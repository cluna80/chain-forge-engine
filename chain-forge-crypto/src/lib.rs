/// chain-forge-crypto
///
/// Crypto-agility layer for QCB Chain and Chain Forge.
///
/// Implements Whitepaper Section 10 — post-quantum security:
///
///   The fix is not simply "use a post-quantum signature algorithm" —
///   algorithm choice alone doesn't survive the next cryptographic break.
///   QCB's constitutional layer (Section 7.3) guarantees the signature
///   scheme CAN be replaced without forking the chain. This crate is the
///   enforcement mechanism for that guarantee.
///
/// Design:
///   - `SignatureScheme` trait: the pluggable interface. Any scheme that
///     implements it can be swapped in at the SchemeRegistry level.
///   - Three concrete schemes: Classical (Ed25519), PQC (ML-DSA/Dilithium),
///     Hybrid (classical + PQC combined). All three are the same trait.
///   - `SchemeRegistry`: which scheme is currently active, what the migration
///     trigger conditions are, and whether a trigger has been detected.
///   - `MigrationTrigger`: the three trigger types from Q16 (NIST update,
///     CRQC demonstration, calendar date).
///   - `SizeReport`: honest accounting of the signature size tradeoff
///     described in Section 10.3.
///
/// Phase 0: all schemes produce/verify deterministic stub bytes.
/// The trait interface is real and tested. Actual crypto (ed25519-dalek
/// for classical, pqcrypto-dilithium for ML-DSA) wires in Phase 1.
///
/// Whitepaper refs: Sections 7.3, 10.1-10.3, Open Question 16.

use serde::{Deserialize, Serialize};

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("signature verification failed for key {key_hint}")]
    VerificationFailed { key_hint: String },

    #[error("scheme {current} does not match required scheme {required}")]
    SchemeMismatch { current: String, required: String },

    #[error("migration not permitted: {reason}")]
    MigrationDenied { reason: String },

    #[error("key generation failed: {0}")]
    KeyGenFailed(String),

    #[error("scheme {0} is not available in Phase 0 (stub only)")]
    NotAvailable(String),

    #[error("internal crypto error: {0}")]
    Internal(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// -- Scheme identifier --------------------------------------------------------

/// Which signature scheme is in use. Matches genesis config values
/// from `chain-forge-core` (`signature_scheme`, `pqc_algorithm`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemeId {
    /// Ed25519 — classical only. Vulnerable to Shor's algorithm.
    /// Used as the Phase 0 baseline.
    Classical,
    /// ML-DSA / CRYSTALS-Dilithium — NIST PQC standard (FIPS 204).
    /// ~2.4KB signatures vs Ed25519's ~64 bytes. See SizeReport.
    MlDsa,
    /// SLH-DSA / SPHINCS+ — NIST PQC standard (FIPS 205).
    /// Largest signatures (~8-50KB) but most conservative security assumptions.
    SlhDsa,
    /// FN-DSA / Falcon — NIST PQC standard (FIPS 206).
    /// ~666 bytes, complex to implement safely. Better size than ML-DSA.
    FnDsa,
    /// Hybrid: classical Ed25519 + ML-DSA combined.
    /// Section 10.3's recommended transition approach.
    /// A signature is only valid if BOTH classical and PQC verify.
    /// Size = Ed25519 size + ML-DSA size ≈ 2.5KB total.
    HybridEd25519MlDsa,
}

impl SchemeId {
    pub fn display_name(&self) -> &str {
        match self {
            Self::Classical          => "Ed25519 (classical)",
            Self::MlDsa              => "ML-DSA / CRYSTALS-Dilithium (NIST FIPS 204)",
            Self::SlhDsa             => "SLH-DSA / SPHINCS+ (NIST FIPS 205)",
            Self::FnDsa              => "FN-DSA / Falcon (NIST FIPS 206)",
            Self::HybridEd25519MlDsa => "Hybrid Ed25519 + ML-DSA",
        }
    }

    /// Is this scheme quantum-resistant (for signatures)?
    /// Section 10.1: Shor's algorithm breaks discrete-log-based schemes.
    pub fn is_quantum_resistant(&self) -> bool {
        match self {
            Self::Classical          => false,
            Self::MlDsa              => true,
            Self::SlhDsa             => true,
            Self::FnDsa              => true,
            Self::HybridEd25519MlDsa => true, // PQC component provides the guarantee
        }
    }

    /// Approximate signature size in bytes (Section 10.3).
    /// These are the real sizes that inform the PQC tradeoff discussion.
    pub fn signature_size_bytes(&self) -> usize {
        match self {
            Self::Classical          => 64,     // Ed25519
            Self::MlDsa              => 3_309,  // pqcrypto dilithium3 detached sig (actual measured)
            Self::SlhDsa             => 17_088, // SLH-DSA-SHAKE-256s (conservative)
            Self::FnDsa              => 666,    // Falcon-512
            Self::HybridEd25519MlDsa => 64 + 3_309, // both combined
        }
    }

    /// Approximate public key size in bytes.
    pub fn public_key_size_bytes(&self) -> usize {
        match self {
            Self::Classical          => 32,
            Self::MlDsa              => 1_952,
            Self::SlhDsa             => 64,
            Self::FnDsa              => 897,
            Self::HybridEd25519MlDsa => 32 + 1_952,
        }
    }

    pub fn from_genesis_strings(signature_scheme: &str, pqc_algorithm: &str) -> Self {
        match (signature_scheme, pqc_algorithm) {
            ("hybrid", "ml-dsa")  => Self::HybridEd25519MlDsa,
            ("pqc-native", "ml-dsa")  => Self::MlDsa,
            ("pqc-native", "shl-dsa") => Self::SlhDsa,
            ("pqc-native", "falcon")  => Self::FnDsa,
            _                         => Self::Classical,
        }
    }
}

// -- Key pair -----------------------------------------------------------------

/// A keypair for one signature scheme.
/// Phase 0: bytes are deterministic stubs (not real crypto).
/// Phase 1+: generated by the actual scheme implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub scheme:      SchemeId,
    pub public_key:  Vec<u8>,
    pub private_key: Vec<u8>,
}

impl KeyPair {
    /// Phase 0 stub: deterministic "keys" from a seed string.
    /// Replace with real key generation in Phase 1.
    pub fn generate_stub(scheme: SchemeId, seed: &str) -> Self {
        let pk_size = scheme.public_key_size_bytes();
        let sk_size = pk_size * 2; // stub: private key is 2× public key size
        let seed_bytes = seed.as_bytes();
        let public_key:  Vec<u8> = (0..pk_size)
            .map(|i| seed_bytes[i % seed_bytes.len()].wrapping_add(i as u8))
            .collect();
        let private_key: Vec<u8> = (0..sk_size)
            .map(|i| seed_bytes[i % seed_bytes.len()].wrapping_add((i as u8).wrapping_add(128)))
            .collect();
        Self { scheme, public_key, private_key }
    }

    pub fn public_key_hex(&self) -> String {
        self.public_key.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// -- Signature ----------------------------------------------------------------

/// A signature produced by a scheme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub scheme: SchemeId,
    pub bytes:  Vec<u8>,
}

impl Signature {
    pub fn size_bytes(&self) -> usize { self.bytes.len() }

    pub fn to_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// -- SignatureScheme trait ----------------------------------------------------

/// The pluggable signature interface.
///
/// This is the constitutional guarantee from Section 7.3: the signature
/// scheme can be replaced without forking the chain, because everything
/// that needs a signature goes through this trait, not a hardcoded algorithm.
///
/// Phase 0: all methods operate on stub bytes (XOR-based, not real crypto).
/// Phase 1+: implementations use real libraries (ed25519-dalek, pqcrypto).
pub trait SignatureScheme: Send + Sync {
    /// Which scheme this is.
    fn scheme_id(&self) -> &SchemeId;

    /// Sign a message. Returns a Signature.
    fn sign(&self, message: &[u8], keypair: &KeyPair) -> CryptoResult<Signature>;

    /// Verify a signature. Returns Ok(()) if valid, Err if not.
    fn verify(
        &self,
        message:    &[u8],
        signature:  &Signature,
        public_key: &[u8],
    ) -> CryptoResult<()>;

    /// Generate a keypair. Phase 0: stub. Phase 1: real keygen.
    fn generate_keypair(&self, seed: &str) -> CryptoResult<KeyPair>;

    /// Size report for this scheme (Section 10.3).
    fn size_report(&self) -> SizeReport;
}

// -- Classical scheme (Ed25519 stub) ------------------------------------------

pub struct ClassicalScheme;

// -- Real Ed25519 implementation (feature = "real-crypto") -------------------

#[cfg(feature = "real-crypto")]
impl SignatureScheme for ClassicalScheme {
    fn scheme_id(&self) -> &SchemeId { &SchemeId::Classical }

    /// Real Ed25519 signing via ed25519-dalek.
    /// The private key bytes are the 32-byte Ed25519 seed.
    fn sign(&self, message: &[u8], keypair: &KeyPair) -> CryptoResult<Signature> {
        use ed25519_dalek::{SigningKey, Signer};

        if keypair.private_key.len() < 32 {
            return Err(CryptoError::KeyGenFailed(
                format!("Ed25519 private key must be >= 32 bytes, got {}",
                    keypair.private_key.len())
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&keypair.private_key[..32]);
        let signing_key = SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(message);

        Ok(Signature {
            scheme: SchemeId::Classical,
            bytes:  sig.to_bytes().to_vec(),
        })
    }

    /// Real Ed25519 verification. A tampered message, signature, or key fails.
    fn verify(&self, message: &[u8], signature: &Signature, public_key: &[u8]) -> CryptoResult<()> {
        use ed25519_dalek::{VerifyingKey, Signature as DalekSig, Verifier};

        if signature.scheme != SchemeId::Classical {
            return Err(CryptoError::SchemeMismatch {
                current:  signature.scheme.display_name().to_string(),
                required: SchemeId::Classical.display_name().to_string(),
            });
        }
        if public_key.len() < 32 {
            return Err(CryptoError::VerificationFailed {
                key_hint: hex_prefix(public_key),
            });
        }
        if signature.bytes.len() != 64 {
            return Err(CryptoError::VerificationFailed {
                key_hint: hex_prefix(public_key),
            });
        }

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&public_key[..32]);
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|_| CryptoError::VerificationFailed {
                key_hint: hex_prefix(public_key),
            })?;

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&signature.bytes[..64]);
        let dalek_sig = DalekSig::from_bytes(&sig_bytes);

        verifying_key.verify(message, &dalek_sig)
            .map_err(|_| CryptoError::VerificationFailed {
                key_hint: hex_prefix(public_key),
            })?;

        tracing::debug!("Ed25519 verify: ok (real crypto)");
        Ok(())
    }

    /// Generate a real Ed25519 keypair. The seed string is hashed to
    /// produce deterministic keys for tests; production callers should
    /// use generate_random() instead.
    fn generate_keypair(&self, seed: &str) -> CryptoResult<KeyPair> {
        use ed25519_dalek::SigningKey;
        use sha2::{Sha256, Digest};

        // Derive a deterministic 32-byte seed from the string
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&hash[..32]);

        let signing_key  = SigningKey::from_bytes(&seed_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(KeyPair {
            scheme:      SchemeId::Classical,
            public_key:  verifying_key.to_bytes().to_vec(),
            private_key: seed_bytes.to_vec(),
        })
    }

    fn size_report(&self) -> SizeReport {
        SizeReport::for_scheme(&SchemeId::Classical)
    }
}

// -- Stub implementation (default, no real-crypto feature) -------------------

#[cfg(not(feature = "real-crypto"))]
impl SignatureScheme for ClassicalScheme {
    fn scheme_id(&self) -> &SchemeId { &SchemeId::Classical }

    fn sign(&self, message: &[u8], keypair: &KeyPair) -> CryptoResult<Signature> {
        // Stub: deterministic bytes from message + PUBLIC key, so verify()
        // can recompute and compare. NOT real crypto.
        Ok(Signature {
            scheme: SchemeId::Classical,
            bytes:  stub_sig_bytes(message, &keypair.public_key, 64),
        })
    }

    fn verify(&self, message: &[u8], signature: &Signature, public_key: &[u8]) -> CryptoResult<()> {
        if signature.scheme != SchemeId::Classical {
            return Err(CryptoError::SchemeMismatch {
                current:  signature.scheme.display_name().to_string(),
                required: SchemeId::Classical.display_name().to_string(),
            });
        }
        let expected = stub_sig_bytes(message, public_key, 64);
        if signature.bytes != expected {
            return Err(CryptoError::VerificationFailed {
                key_hint: hex_prefix(public_key),
            });
        }
        tracing::debug!("classical stub verify: ok (no real-crypto feature)");
        Ok(())
    }

    fn generate_keypair(&self, seed: &str) -> CryptoResult<KeyPair> {
        Ok(KeyPair::generate_stub(SchemeId::Classical, seed))
    }

    fn size_report(&self) -> SizeReport {
        SizeReport::for_scheme(&SchemeId::Classical)
    }
}

impl ClassicalScheme {
    /// Generate a cryptographically random Ed25519 keypair.
    /// Production key generation -- use this, not generate_keypair(seed).
    #[cfg(feature = "real-crypto")]
    pub fn generate_random(&self) -> CryptoResult<KeyPair> {
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        let signing_key   = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Ok(KeyPair {
            scheme:      SchemeId::Classical,
            public_key:  verifying_key.to_bytes().to_vec(),
            private_key: seed.to_vec(),
        })
    }

    /// Whether this build uses real cryptography or stubs.
    pub fn is_real_crypto(&self) -> bool {
        cfg!(feature = "real-crypto")
    }
}

// -- ML-DSA (Dilithium) scheme — real + stub ---------------------------------

pub struct MlDsaScheme;

// -- Real ML-DSA via pqcrypto-dilithium (feature = "real-pqc") ---------------

#[cfg(feature = "real-pqc")]
impl SignatureScheme for MlDsaScheme {
    fn scheme_id(&self) -> &SchemeId { &SchemeId::MlDsa }

    /// Real ML-DSA-65 signing (NIST FIPS 204 / CRYSTALS-Dilithium).
    /// Signature size: 2420 bytes. Public key: 1952 bytes.
    fn sign(&self, message: &[u8], keypair: &KeyPair) -> CryptoResult<Signature> {
        use pqcrypto_dilithium::dilithium3;
        use pqcrypto_traits::sign::{SecretKey as _, DetachedSignature};

        if keypair.private_key.len() < dilithium3::secret_key_bytes() {
            return Err(CryptoError::KeyGenFailed(format!(
                "ML-DSA secret key must be {} bytes, got {}",
                dilithium3::secret_key_bytes(),
                keypair.private_key.len()
            )));
        }

        let sk = dilithium3::SecretKey::from_bytes(
            &keypair.private_key[..dilithium3::secret_key_bytes()]
        ).map_err(|_| CryptoError::KeyGenFailed("invalid ML-DSA secret key".into()))?;

        let sig = dilithium3::detached_sign(message, &sk);
        use pqcrypto_traits::sign::DetachedSignature as DS;
        let sig_bytes: Vec<u8> = <dilithium3::DetachedSignature as DS>::as_bytes(&sig).to_vec();

        Ok(Signature {
            scheme: SchemeId::MlDsa,
            bytes:  sig_bytes,
        })
    }

    fn verify(&self, message: &[u8], signature: &Signature, public_key: &[u8]) -> CryptoResult<()> {
        use pqcrypto_dilithium::dilithium3;
        use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};

        if signature.scheme != SchemeId::MlDsa {
            return Err(CryptoError::SchemeMismatch {
                current:  signature.scheme.display_name().to_string(),
                required: SchemeId::MlDsa.display_name().to_string(),
            });
        }

        let pk = dilithium3::PublicKey::from_bytes(
            &public_key[..dilithium3::public_key_bytes().min(public_key.len())]
        ).map_err(|_| CryptoError::VerificationFailed { key_hint: hex_prefix(public_key) })?;

        let sig = dilithium3::DetachedSignature::from_bytes(&signature.bytes)
            .map_err(|_| CryptoError::VerificationFailed { key_hint: hex_prefix(public_key) })?;

        dilithium3::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| CryptoError::VerificationFailed { key_hint: hex_prefix(public_key) })?;

        tracing::debug!("ML-DSA verify: ok (real pqcrypto)");
        Ok(())
    }

    fn generate_keypair(&self, _seed: &str) -> CryptoResult<KeyPair> {
        use pqcrypto_dilithium::dilithium3;
        use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

        // pqcrypto keygen is randomised; deterministic seeding requires
        // a custom RNG seeded from the string -- use generate_random() in production.
        let (pk, sk) = dilithium3::keypair();
        Ok(KeyPair {
            scheme:      SchemeId::MlDsa,
            public_key:  pk.as_bytes().to_vec(),
            private_key: sk.as_bytes().to_vec(),
        })
    }

    fn size_report(&self) -> SizeReport {
        SizeReport::for_scheme(&SchemeId::MlDsa)
    }
}

// -- Stub ML-DSA (default, no real-pqc feature) --------------------------------

#[cfg(not(feature = "real-pqc"))]
impl SignatureScheme for MlDsaScheme {
    fn scheme_id(&self) -> &SchemeId { &SchemeId::MlDsa }

    fn sign(&self, message: &[u8], keypair: &KeyPair) -> CryptoResult<Signature> {
        Ok(Signature {
            scheme: SchemeId::MlDsa,
            bytes:  stub_sig_bytes(message, &keypair.public_key,
                        SchemeId::MlDsa.signature_size_bytes()),
        })
    }

    fn verify(&self, message: &[u8], signature: &Signature, public_key: &[u8]) -> CryptoResult<()> {
        if signature.scheme != SchemeId::MlDsa {
            return Err(CryptoError::SchemeMismatch {
                current:  signature.scheme.display_name().to_string(),
                required: SchemeId::MlDsa.display_name().to_string(),
            });
        }
        let expected = stub_sig_bytes(message, public_key,
            SchemeId::MlDsa.signature_size_bytes());
        if signature.bytes != expected {
            return Err(CryptoError::VerificationFailed { key_hint: hex_prefix(public_key) });
        }
        tracing::debug!("ML-DSA stub verify: ok (no real-pqc feature)");
        Ok(())
    }

    fn generate_keypair(&self, seed: &str) -> CryptoResult<KeyPair> {
        Ok(KeyPair::generate_stub(SchemeId::MlDsa, seed))
    }

    fn size_report(&self) -> SizeReport {
        SizeReport::for_scheme(&SchemeId::MlDsa)
    }
}

impl MlDsaScheme {
    /// Whether this build uses real ML-DSA or the stub.
    pub fn is_real_pqc(&self) -> bool {
        cfg!(feature = "real-pqc")
    }
}

// -- Hybrid scheme (Ed25519 + ML-DSA) -----------------------------------------

/// The hybrid scheme signs with BOTH classical and PQC algorithms.
/// A signature is only valid if BOTH verify. This provides:
///   - Classical security until a CRQC appears
///   - PQC security against a future CRQC
///   - No single-point-of-failure on either algorithm
/// Cost: signature size = classical + PQC ≈ 2.5KB (Section 10.3).
pub struct HybridScheme {
    classical: ClassicalScheme,
    pqc:       MlDsaScheme,
}

impl HybridScheme {
    pub fn new() -> Self {
        Self { classical: ClassicalScheme, pqc: MlDsaScheme }
    }
}

impl Default for HybridScheme {
    fn default() -> Self { Self::new() }
}

impl SignatureScheme for HybridScheme {
    fn scheme_id(&self) -> &SchemeId { &SchemeId::HybridEd25519MlDsa }

    fn sign(&self, message: &[u8], keypair: &KeyPair) -> CryptoResult<Signature> {
        // Public key split is always 32 bytes (both real and stub Classical
        // schemes report a 32-byte public key -- SchemeId::Classical.public_key_size_bytes()).
        const ED25519_PK: usize = 32;
        // Private key split depends on whether real-crypto is active:
        //   real Ed25519: 32-byte seed
        //   stub Classical: 64 bytes (KeyPair::generate_stub uses 2x pubkey size)
        let ed25519_sk_size = if self.classical.is_real_crypto() { 32 } else { 64 };

        let pk_split = ED25519_PK.min(keypair.public_key.len());
        let sk_split = ed25519_sk_size.min(keypair.private_key.len());

        let classical_kp = KeyPair {
            scheme:      SchemeId::Classical,
            public_key:  keypair.public_key[..pk_split].to_vec(),
            private_key: keypair.private_key[..sk_split].to_vec(),
        };
        let pqc_kp = KeyPair {
            scheme:      SchemeId::MlDsa,
            public_key:  keypair.public_key[pk_split..].to_vec(),
            private_key: keypair.private_key[sk_split..].to_vec(),
        };

        let classical_sig = self.classical.sign(message, &classical_kp)?;
        let pqc_sig       = self.pqc.sign(message, &pqc_kp)?;

        // Concatenate: [classical_sig | pqc_sig]
        let mut combined = classical_sig.bytes;
        combined.extend_from_slice(&pqc_sig.bytes);

        Ok(Signature { scheme: SchemeId::HybridEd25519MlDsa, bytes: combined })
    }

    fn verify(&self, message: &[u8], signature: &Signature, public_key: &[u8]) -> CryptoResult<()> {
        if signature.scheme != SchemeId::HybridEd25519MlDsa {
            return Err(CryptoError::SchemeMismatch {
                current:  signature.scheme.display_name().to_string(),
                required: SchemeId::HybridEd25519MlDsa.display_name().to_string(),
            });
        }

        let expected_size = SchemeId::HybridEd25519MlDsa.signature_size_bytes();
        if signature.bytes.len() != expected_size {
            return Err(CryptoError::VerificationFailed {
                key_hint: hex_prefix(public_key),
            });
        }

        // Split signature back into classical and PQC halves
        let classical_bytes = &signature.bytes[..64];
        let pqc_bytes       = &signature.bytes[64..];

        let classical_sig = Signature { scheme: SchemeId::Classical, bytes: classical_bytes.to_vec() };
        let pqc_sig       = Signature { scheme: SchemeId::MlDsa,     bytes: pqc_bytes.to_vec() };

        let pk_split     = 32.min(public_key.len());
        let classical_pk = &public_key[..pk_split];
        let pqc_pk       = &public_key[pk_split..];

        // BOTH must verify -- that's the security guarantee
        self.classical.verify(message, &classical_sig, classical_pk)?;
        self.pqc.verify(message, &pqc_sig, pqc_pk)?;

        tracing::debug!("hybrid stub verify: classical + ML-DSA both ok (Phase 0)");
        Ok(())
    }

    /// Generate a hybrid keypair: real Ed25519 half + ML-DSA half.
    /// Layout: public_key  = [ed25519_pk (32) | mldsa_pk (1952)]
    ///         private_key = [ed25519_sk (32) | mldsa_sk (...)]
    fn generate_keypair(&self, seed: &str) -> CryptoResult<KeyPair> {
        let classical_kp = self.classical.generate_keypair(&format!("{seed}-ed25519"))?;
        let pqc_kp       = self.pqc.generate_keypair(&format!("{seed}-mldsa"))?;

        let mut public_key = classical_kp.public_key.clone();
        public_key.extend_from_slice(&pqc_kp.public_key);

        let mut private_key = classical_kp.private_key.clone();
        private_key.extend_from_slice(&pqc_kp.private_key);

        Ok(KeyPair {
            scheme: SchemeId::HybridEd25519MlDsa,
            public_key,
            private_key,
        })
    }

    fn size_report(&self) -> SizeReport {
        SizeReport::for_scheme(&SchemeId::HybridEd25519MlDsa)
    }
}

// -- SizeReport ---------------------------------------------------------------

/// Honest accounting of the PQC signature size tradeoff (Section 10.3).
///
/// "There is no PQC option that matches ECDSA's compactness -- adopting
/// post-quantum signatures means accepting this cost somewhere in the
/// stack, not engineering it away." -- Whitepaper Section 10.3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeReport {
    pub scheme:            String,
    pub signature_bytes:   usize,
    pub public_key_bytes:  usize,
    /// Multiplier vs Ed25519 baseline (64 byte sig, 32 byte pk).
    pub sig_size_vs_ed25519: f32,
    pub pk_size_vs_ed25519:  f32,
    /// Impact on a typical 250-byte transaction.
    pub tx_size_bytes:     usize,
    /// Estimated transactions per block at 1MB block limit.
    pub txs_per_mb_block:  usize,
    pub is_quantum_resistant: bool,
    pub notes:             String,
}

impl SizeReport {
    pub fn for_scheme(id: &SchemeId) -> Self {
        let sig = id.signature_size_bytes();
        let pk  = id.public_key_size_bytes();
        let baseline_sig = 64usize;   // Ed25519
        let baseline_pk  = 32usize;
        let tx_overhead  = 250usize;  // tx body without sig/pk
        let tx_size      = tx_overhead + sig + pk;
        let block_1mb    = 1_048_576usize / tx_size.max(1);

        Self {
            scheme:               id.display_name().to_string(),
            signature_bytes:      sig,
            public_key_bytes:     pk,
            sig_size_vs_ed25519:  sig as f32 / baseline_sig as f32,
            pk_size_vs_ed25519:   pk  as f32 / baseline_pk  as f32,
            tx_size_bytes:        tx_size,
            txs_per_mb_block:     block_1mb,
            is_quantum_resistant: id.is_quantum_resistant(),
            notes:                Self::notes_for(id),
        }
    }

    fn notes_for(id: &SchemeId) -> String {
        match id {
            SchemeId::Classical =>
                "Ed25519 baseline. Fast, compact. Vulnerable to Shor's algorithm \
                 once a CRQC of sufficient scale exists. Not acceptable for long-term \
                 use on a chain designed to outlast its founders.".to_string(),
            SchemeId::MlDsa =>
                "NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium). ~38x larger signatures \
                 than Ed25519. Recommended starting point for QCB due to conservative \
                 security assumptions and NIST standardization. Size cost lands on \
                 block throughput and merchant payment latency.".to_string(),
            SchemeId::SlhDsa =>
                "NIST FIPS 205 (SLH-DSA / SPHINCS+). Most conservative security \
                 assumptions (hash-based, not lattice-based). Very large signatures. \
                 Suitable for high-value validator transactions where size cost is \
                 acceptable; not for everyday merchant payments.".to_string(),
            SchemeId::FnDsa =>
                "NIST FIPS 206 (FN-DSA / Falcon). Better size than ML-DSA (~10x \
                 vs Ed25519). Complex to implement safely due to floating-point \
                 arithmetic in signing. Viable alternative once a safe implementation \
                 is available.".to_string(),
            SchemeId::HybridEd25519MlDsa =>
                "Hybrid Ed25519 + ML-DSA. Section 10.3 recommended transition scheme. \
                 Classical security until CRQC appears; PQC security against future \
                 CRQC. Both must verify. Size cost is additive (~3.4KB). \
                 Appropriate for the transition period between launch and full \
                 PQC migration.".to_string(),
        }
    }
}

// -- MigrationTrigger ---------------------------------------------------------

/// The three trigger conditions from Open Question 16.
/// When any trigger fires, the SchemeRegistry initiates migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationTrigger {
    /// NIST publishes guidance that a previously standardized algorithm
    /// is deprecated or broken. Automatic trigger.
    NistGuidanceUpdate { algorithm: String, reason: String },
    /// A cryptographically-relevant quantum computer is demonstrated
    /// publicly, capable of breaking the current scheme in practice.
    CrqcDemonstrated { source: String, estimated_qubit_count: u64 },
    /// A scheduled calendar review of the signature scheme.
    /// QCB's constitutional layer mandates periodic review regardless
    /// of whether external triggers have fired.
    ScheduledReview { review_epoch: u64 },
}

impl MigrationTrigger {
    pub fn is_emergency(&self) -> bool {
        matches!(self, Self::CrqcDemonstrated { .. })
    }

    pub fn description(&self) -> String {
        match self {
            Self::NistGuidanceUpdate { algorithm, reason } =>
                format!("NIST guidance update: {algorithm} deprecated — {reason}"),
            Self::CrqcDemonstrated { source, estimated_qubit_count } =>
                format!("CRQC demonstrated by {source} (~{estimated_qubit_count} qubits)"),
            Self::ScheduledReview { review_epoch } =>
                format!("Scheduled crypto review at epoch {review_epoch}"),
        }
    }
}

// -- SchemeRegistry -----------------------------------------------------------

/// The active signature scheme registry and migration controller.
///
/// This is the on-chain state that enforces the constitutional guarantee:
/// the scheme can be changed, but only through the amendment process
/// (Section 7.3) — not through an ordinary governance vote.
#[derive(Debug, Serialize, Deserialize)]
pub struct SchemeRegistry {
    /// The scheme currently in use for new signatures.
    pub active_scheme:    SchemeId,
    /// The scheme being migrated TO (if migration is in progress).
    pub migration_target: Option<SchemeId>,
    /// Epoch when the current scheme was activated.
    pub activated_epoch:  u64,
    /// Fired triggers that prompted the current migration, if any.
    pub pending_triggers: Vec<MigrationTrigger>,
    /// Whether migration has been constitutionally approved.
    pub migration_approved: bool,
    /// Epoch when migration was constitutionally approved.
    pub approved_epoch:   Option<u64>,
}

impl SchemeRegistry {
    pub fn new(active_scheme: SchemeId, current_epoch: u64) -> Self {
        Self {
            active_scheme,
            migration_target:   None,
            activated_epoch:    current_epoch,
            pending_triggers:   Vec::new(),
            migration_approved: false,
            approved_epoch:     None,
        }
    }

    /// The default for QCB genesis: hybrid scheme (per genesis config).
    pub fn qcb_genesis_default(current_epoch: u64) -> Self {
        Self::new(SchemeId::HybridEd25519MlDsa, current_epoch)
    }

    /// Record a migration trigger (NIST update, CRQC, scheduled review).
    pub fn record_trigger(&mut self, trigger: MigrationTrigger) {
        tracing::warn!(
            trigger = %trigger.description(),
            is_emergency = trigger.is_emergency(),
            "crypto migration trigger fired"
        );
        self.pending_triggers.push(trigger);
    }

    /// Propose a migration to a new scheme.
    /// This does NOT execute the migration -- it sets the target.
    /// Constitutional approval (Section 7.3) is required before execute_migration().
    pub fn propose_migration(&mut self, target: SchemeId) -> CryptoResult<()> {
        if target == self.active_scheme {
            return Err(CryptoError::MigrationDenied {
                reason: "target scheme is already active".to_string(),
            });
        }
        self.migration_target = Some(target.clone());
        self.migration_approved = false;
        tracing::info!(
            from   = %self.active_scheme.display_name(),
            to     = %target.display_name(),
            "crypto migration proposed (awaiting constitutional approval)"
        );
        Ok(())
    }

    /// Constitutional approval of the proposed migration.
    /// In the real chain, this is the output of a successful
    /// supermajority governance vote (Section 7.3).
    /// Phase 0: called directly in tests.
    pub fn approve_migration(&mut self, approval_epoch: u64) -> CryptoResult<()> {
        if self.migration_target.is_none() {
            return Err(CryptoError::MigrationDenied {
                reason: "no migration proposed".to_string(),
            });
        }
        self.migration_approved = true;
        self.approved_epoch = Some(approval_epoch);
        tracing::info!(
            epoch  = approval_epoch,
            target = %self.migration_target.as_ref().unwrap().display_name(),
            "crypto migration constitutionally approved"
        );
        Ok(())
    }

    /// Execute a constitutionally-approved migration.
    /// After this, new keys and signatures use the new scheme.
    /// Existing accounts' public keys remain valid under the old scheme
    /// until they re-sign (forward-compatible, no state invalidation).
    pub fn execute_migration(&mut self, execution_epoch: u64) -> CryptoResult<SchemeId> {
        if !self.migration_approved {
            return Err(CryptoError::MigrationDenied {
                reason: "migration has not been constitutionally approved".to_string(),
            });
        }
        let target = self.migration_target.take()
            .ok_or_else(|| CryptoError::MigrationDenied {
                reason: "no migration target set".to_string(),
            })?;

        let old_scheme = std::mem::replace(&mut self.active_scheme, target.clone());
        self.migration_approved = false;
        self.approved_epoch = None;
        self.activated_epoch = execution_epoch;
        self.pending_triggers.clear();

        tracing::info!(
            from  = %old_scheme.display_name(),
            to    = %target.display_name(),
            epoch = execution_epoch,
            "crypto migration executed -- new scheme active"
        );

        Ok(old_scheme)
    }

    /// Whether a migration is pending (proposed but not yet approved or executed).
    pub fn migration_pending(&self) -> bool {
        self.migration_target.is_some()
    }

    /// Size impact of the active scheme (Section 10.3).
    pub fn size_report(&self) -> SizeReport {
        SizeReport::for_scheme(&self.active_scheme)
    }
}

// -- Helper -------------------------------------------------------------------

/// Phase 0 stub signature bytes: deterministic function of
/// (message, public key, size). Lets verify() recompute and compare,
/// so corrupted signatures fail. NOT cryptographically secure.
fn stub_sig_bytes(message: &[u8], public_key: &[u8], size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| {
            let m = message.get(i % message.len().max(1)).copied().unwrap_or(0);
            let k = public_key.get(i % public_key.len().max(1)).copied().unwrap_or(0);
            m ^ k.rotate_left((i % 8) as u32) ^ (i as u8)
        })
        .collect()
}

fn hex_prefix(bytes: &[u8]) -> String {
    let len = bytes.len().min(8);
    bytes[..len].iter().map(|b| format!("{b:02x}")).collect::<String>() + "..."
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SchemeId tests -------------------------------------------------------

    #[test]
    fn classical_is_not_quantum_resistant() {
        assert!(!SchemeId::Classical.is_quantum_resistant());
    }

    #[test]
    fn pqc_schemes_are_quantum_resistant() {
        assert!(SchemeId::MlDsa.is_quantum_resistant());
        assert!(SchemeId::SlhDsa.is_quantum_resistant());
        assert!(SchemeId::FnDsa.is_quantum_resistant());
        assert!(SchemeId::HybridEd25519MlDsa.is_quantum_resistant());
    }

    #[test]
    fn mldsa_signature_is_much_larger_than_ed25519() {
        let classical = SchemeId::Classical.signature_size_bytes();
        let mldsa     = SchemeId::MlDsa.signature_size_bytes();
        assert!(mldsa > classical * 30,
            "ML-DSA should be >30x larger than Ed25519 (whitepaper Section 10.3)");
    }

    #[test]
    fn hybrid_size_is_sum_of_components() {
        let classical = SchemeId::Classical.signature_size_bytes();
        let mldsa     = SchemeId::MlDsa.signature_size_bytes();
        let hybrid    = SchemeId::HybridEd25519MlDsa.signature_size_bytes();
        assert_eq!(hybrid, classical + mldsa,
            "hybrid signature must be sum of classical + PQC");
    }

    #[test]
    fn genesis_config_maps_to_hybrid() {
        let scheme = SchemeId::from_genesis_strings("hybrid", "ml-dsa");
        assert_eq!(scheme, SchemeId::HybridEd25519MlDsa);
    }

    #[test]
    fn genesis_config_maps_to_mldsa() {
        let scheme = SchemeId::from_genesis_strings("pqc-native", "ml-dsa");
        assert_eq!(scheme, SchemeId::MlDsa);
    }

    // -- Classical scheme tests -----------------------------------------------

    #[test]
    fn classical_sign_and_verify() {
        let scheme = ClassicalScheme;
        let kp     = scheme.generate_keypair("test-seed-alice").unwrap();
        let msg    = b"transfer 1000 ucirfi to bob";

        let sig = scheme.sign(msg, &kp).unwrap();
        assert_eq!(sig.scheme, SchemeId::Classical);
        assert_eq!(sig.bytes.len(), 64);
        assert!(scheme.verify(msg, &sig, &kp.public_key).is_ok());
    }

    #[test]
    fn classical_wrong_scheme_fails_verify() {
        let scheme = ClassicalScheme;
        let kp     = scheme.generate_keypair("seed").unwrap();
        let msg    = b"message";
        let mut sig = scheme.sign(msg, &kp).unwrap();
        sig.scheme = SchemeId::MlDsa; // wrong scheme label
        assert!(scheme.verify(msg, &sig, &kp.public_key).is_err());
    }

    // -- ML-DSA scheme tests --------------------------------------------------

    #[test]
    fn mldsa_sign_and_verify() {
        let scheme = MlDsaScheme;
        let kp     = scheme.generate_keypair("test-seed-validator").unwrap();
        let msg    = b"block_hash_h42";

        let sig = scheme.sign(msg, &kp).unwrap();
        assert_eq!(sig.scheme, SchemeId::MlDsa);
        assert_eq!(sig.bytes.len(), SchemeId::MlDsa.signature_size_bytes(),
            "stub signature must match declared size");
        assert!(scheme.verify(msg, &sig, &kp.public_key).is_ok());
    }

    #[test]
    fn mldsa_signature_size_matches_spec() {
        let scheme = MlDsaScheme;
        let kp = scheme.generate_keypair("s").unwrap();
        let sig = scheme.sign(b"x", &kp).unwrap();
        // pqcrypto dilithium3 detached signature: 3293 bytes
        assert_eq!(sig.bytes.len(), SchemeId::MlDsa.signature_size_bytes(),
            "ML-DSA signature size must match SchemeId constant");
    }

    // -- Hybrid scheme tests --------------------------------------------------

    #[test]
    fn hybrid_sign_and_verify() {
        let scheme = HybridScheme::new();
        let kp     = scheme.generate_keypair("hybrid-validator-1").unwrap();
        let msg    = b"consensus_precommit_h100";

        let sig = scheme.sign(msg, &kp).unwrap();
        assert_eq!(sig.scheme, SchemeId::HybridEd25519MlDsa);
        assert_eq!(sig.bytes.len(), SchemeId::HybridEd25519MlDsa.signature_size_bytes(),
            "hybrid sig = classical (64) + ML-DSA (3293)");
        assert!(scheme.verify(msg, &sig, &kp.public_key).is_ok());
    }

    #[test]
    fn hybrid_both_components_must_verify() {
        let scheme = HybridScheme::new();
        let kp     = scheme.generate_keypair("seed").unwrap();
        let msg    = b"message";
        let mut sig = scheme.sign(msg, &kp).unwrap();

        // Corrupt the PQC half -- verification must fail
        let classical_end = 64;
        sig.bytes[classical_end] ^= 0xFF;
        assert!(scheme.verify(msg, &sig, &kp.public_key).is_err(),
            "corrupted PQC component must fail hybrid verification");
    }

    // -- SizeReport tests -----------------------------------------------------

    #[test]
    fn size_report_ed25519_baseline() {
        let report = SizeReport::for_scheme(&SchemeId::Classical);
        assert_eq!(report.signature_bytes, 64);
        assert_eq!(report.public_key_bytes, 32);
        assert!((report.sig_size_vs_ed25519 - 1.0).abs() < 0.01);
        assert!(!report.is_quantum_resistant);
    }

    #[test]
    fn size_report_mldsa_overhead() {
        let report = SizeReport::for_scheme(&SchemeId::MlDsa);
        assert!(report.sig_size_vs_ed25519 > 30.0,
            "ML-DSA should be >30x overhead vs Ed25519");
        assert!(report.is_quantum_resistant);
        // At 1MB blocks, ML-DSA limits throughput significantly
        let classical_report = SizeReport::for_scheme(&SchemeId::Classical);
        assert!(report.txs_per_mb_block < classical_report.txs_per_mb_block,
            "PQC reduces tx throughput per block");
    }

    #[test]
    fn size_report_documents_tradeoff() {
        // All schemes should have notes describing the tradeoff
        for id in [
            SchemeId::Classical,
            SchemeId::MlDsa,
            SchemeId::HybridEd25519MlDsa,
        ] {
            let report = SizeReport::for_scheme(&id);
            assert!(!report.notes.is_empty(),
                "SizeReport for {id:?} must have notes");
        }
    }

    // -- SchemeRegistry tests -------------------------------------------------

    #[test]
    fn registry_starts_with_hybrid_for_qcb() {
        let registry = SchemeRegistry::qcb_genesis_default(0);
        assert_eq!(registry.active_scheme, SchemeId::HybridEd25519MlDsa);
        assert!(!registry.migration_pending());
    }

    #[test]
    fn migration_requires_constitutional_approval() {
        let mut registry = SchemeRegistry::new(SchemeId::Classical, 0);
        registry.propose_migration(SchemeId::MlDsa).unwrap();

        // Cannot execute without approval
        let result = registry.execute_migration(1);
        assert!(result.is_err(), "migration without approval must fail");
    }

    #[test]
    fn full_migration_lifecycle() {
        let mut registry = SchemeRegistry::new(SchemeId::Classical, 0);

        // 1. A trigger fires (CRQC demonstrated)
        registry.record_trigger(MigrationTrigger::CrqcDemonstrated {
            source:                "research lab".to_string(),
            estimated_qubit_count: 10_000_000,
        });
        assert_eq!(registry.pending_triggers.len(), 1);

        // 2. Migration proposed
        registry.propose_migration(SchemeId::HybridEd25519MlDsa).unwrap();
        assert!(registry.migration_pending());
        assert!(!registry.migration_approved);

        // 3. Constitutional approval (supermajority vote in real chain)
        registry.approve_migration(10).unwrap();
        assert!(registry.migration_approved);

        // 4. Execute migration
        let old_scheme = registry.execute_migration(11).unwrap();
        assert_eq!(old_scheme, SchemeId::Classical);
        assert_eq!(registry.active_scheme, SchemeId::HybridEd25519MlDsa);
        assert!(!registry.migration_pending());
        assert!(registry.pending_triggers.is_empty());
    }

    #[test]
    fn cannot_migrate_to_same_scheme() {
        let mut registry = SchemeRegistry::new(SchemeId::MlDsa, 0);
        let result = registry.propose_migration(SchemeId::MlDsa);
        assert!(result.is_err());
    }

    #[test]
    fn scheduled_review_trigger_is_not_emergency() {
        let trigger = MigrationTrigger::ScheduledReview { review_epoch: 365 };
        assert!(!trigger.is_emergency());
    }

    #[test]
    fn crqc_trigger_is_emergency() {
        let trigger = MigrationTrigger::CrqcDemonstrated {
            source:                "adversary".to_string(),
            estimated_qubit_count: 1_000_000,
        };
        assert!(trigger.is_emergency());
    }

    #[test]
    fn registry_size_report_reflects_active_scheme() {
        let registry = SchemeRegistry::qcb_genesis_default(0);
        let report   = registry.size_report();
        assert_eq!(report.signature_bytes,
            SchemeId::HybridEd25519MlDsa.signature_size_bytes());
        assert!(report.is_quantum_resistant);
    }

    // -- Real crypto tests (feature = "real-crypto") --------------------------

    #[test]
    fn reports_whether_real_crypto_is_active() {
        let scheme = ClassicalScheme;
        // Just confirms the flag is readable; value depends on build features
        let _ = scheme.is_real_crypto();
    }

    #[test]
    fn reports_whether_real_pqc_is_active() {
        let scheme = MlDsaScheme;
        let _ = scheme.is_real_pqc();
    }

    #[cfg(feature = "real-pqc")]
    mod real_pqc {
        use super::*;

        #[test]
        fn mldsa_real_keypair_has_correct_sizes() {
            let scheme = MlDsaScheme;
            let kp = scheme.generate_keypair("test").unwrap();
            assert_eq!(kp.public_key.len(), 1952,
                "ML-DSA-65 public key is 1952 bytes (NIST FIPS 204)");
        }

        #[test]
        fn mldsa_real_roundtrip_verifies() {
            let scheme = MlDsaScheme;
            let kp  = scheme.generate_keypair("validator").unwrap();
            let msg = b"block_precommit_h42";
            let sig = scheme.sign(msg, &kp).unwrap();
            assert!(scheme.verify(msg, &sig, &kp.public_key).is_ok());
        }

        #[test]
        fn mldsa_real_rejects_tampered_message() {
            let scheme = MlDsaScheme;
            let kp  = scheme.generate_keypair("val").unwrap();
            let sig = scheme.sign(b"original", &kp).unwrap();
            assert!(scheme.verify(b"tampered", &sig, &kp.public_key).is_err(),
                "ML-DSA must reject tampered message");
        }
    }

    #[cfg(feature = "real-crypto")]
    mod real_crypto {
        use super::*;

        #[test]
        fn ed25519_keypair_has_correct_sizes() {
            let scheme = ClassicalScheme;
            let kp = scheme.generate_keypair("alice").unwrap();
            assert_eq!(kp.public_key.len(), 32, "Ed25519 public key is 32 bytes");
            assert_eq!(kp.private_key.len(), 32, "Ed25519 seed is 32 bytes");
        }

        #[test]
        fn ed25519_signature_is_64_bytes() {
            let scheme = ClassicalScheme;
            let kp = scheme.generate_keypair("alice").unwrap();
            let sig = scheme.sign(b"transfer 1000 ucirfi", &kp).unwrap();
            assert_eq!(sig.bytes.len(), 64, "Ed25519 signature is 64 bytes");
        }

        #[test]
        fn ed25519_roundtrip_verifies() {
            let scheme = ClassicalScheme;
            let kp  = scheme.generate_keypair("validator-1").unwrap();
            let msg = b"block_h42_precommit";
            let sig = scheme.sign(msg, &kp).unwrap();
            assert!(scheme.verify(msg, &sig, &kp.public_key).is_ok());
        }

        #[test]
        fn ed25519_rejects_tampered_message() {
            let scheme = ClassicalScheme;
            let kp  = scheme.generate_keypair("alice").unwrap();
            let sig = scheme.sign(b"send 100 to bob", &kp).unwrap();
            // Different message must fail -- this is the property a stub cannot provide
            assert!(scheme.verify(b"send 999 to mallory", &sig, &kp.public_key).is_err(),
                "tampered message must fail Ed25519 verification");
        }

        #[test]
        fn ed25519_rejects_tampered_signature() {
            let scheme = ClassicalScheme;
            let kp  = scheme.generate_keypair("alice").unwrap();
            let msg = b"authorize agent";
            let mut sig = scheme.sign(msg, &kp).unwrap();
            sig.bytes[0] ^= 0xFF;
            assert!(scheme.verify(msg, &sig, &kp.public_key).is_err(),
                "tampered signature must fail");
        }

        #[test]
        fn ed25519_rejects_wrong_public_key() {
            let scheme = ClassicalScheme;
            let alice = scheme.generate_keypair("alice").unwrap();
            let bob   = scheme.generate_keypair("bob").unwrap();
            let msg   = b"claim ubi";
            let sig   = scheme.sign(msg, &alice).unwrap();
            // Bob's key must not verify Alice's signature
            assert!(scheme.verify(msg, &sig, &bob.public_key).is_err(),
                "wrong public key must fail verification");
        }

        #[test]
        fn ed25519_keygen_is_deterministic_from_seed() {
            let scheme = ClassicalScheme;
            let a = scheme.generate_keypair("same-seed").unwrap();
            let b = scheme.generate_keypair("same-seed").unwrap();
            assert_eq!(a.public_key, b.public_key,
                "same seed must produce same key (needed for reproducible tests)");
        }

        #[test]
        fn ed25519_different_seeds_give_different_keys() {
            let scheme = ClassicalScheme;
            let a = scheme.generate_keypair("alice").unwrap();
            let b = scheme.generate_keypair("bob").unwrap();
            assert_ne!(a.public_key, b.public_key);
        }

        #[test]
        fn random_keygen_produces_unique_keys() {
            let scheme = ClassicalScheme;
            let a = scheme.generate_random().unwrap();
            let b = scheme.generate_random().unwrap();
            assert_ne!(a.public_key, b.public_key,
                "random keygen must not repeat");
        }

        #[test]
        fn hybrid_with_real_ed25519_roundtrips() {
            let scheme = HybridScheme::new();
            let kp  = scheme.generate_keypair("hybrid-validator").unwrap();
            let msg = b"consensus vote h100";
            let sig = scheme.sign(msg, &kp).unwrap();
            assert!(scheme.verify(msg, &sig, &kp.public_key).is_ok(),
                "hybrid must verify with real Ed25519 half");
        }

        #[test]
        fn hybrid_rejects_tampered_message_via_ed25519_half() {
            let scheme = HybridScheme::new();
            let kp  = scheme.generate_keypair("hybrid-validator").unwrap();
            let sig = scheme.sign(b"original message", &kp).unwrap();
            assert!(scheme.verify(b"tampered message", &sig, &kp.public_key).is_err(),
                "hybrid must reject tampered message");
        }
    }

}
