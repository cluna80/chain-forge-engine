//! chain-forge-wallet — QCB-WALLET-001
//!
//! Post-quantum wallet for QCB Chain.  Implements:
//!
//!   1. ML-DSA-65 key generation (NIST FIPS 204 / CRYSTALS-Dilithium3)
//!   2. Encrypted key file: AES-256-GCM(Argon2id(passphrase))
//!   3. Transaction signing: SHA-256("chain-forge/pq-tx/v1\n" || chain_id || "\n" || body_json) → ML-DSA signature
//!   4. Devnet submission: POST /api/tx with signature bytes
//!   5. Adversarial verification: forge / tamper / replay rejection
//!
//! Key files (`*.wallet.json`) are GITIGNORED — private key seeds
//! never leave the local machine.
//!
//! Whitepaper refs: Sections 7.3, 10.1-10.3, QCB-WALLET-001.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

pub use chain_forge_crypto::{KeyPair, MlDsaScheme, SchemeId, SignatureScheme};
use chain_forge_crypto::mldsa_tx_prehash;  // CS-001-M2: canonical PQ pre-hash helper

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("key file already exists at {0}; refusing to overwrite")]
    KeyFileExists(String),

    #[error("key file not found: {0}")]
    KeyFileNotFound(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed — wrong passphrase or corrupted key file")]
    DecryptionFailed,

    #[error("crypto error: {0}")]
    Crypto(#[from] chain_forge_crypto::CryptoError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decode error: {0}")]
    Hex(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("transaction rejected by node: {0}")]
    TxRejected(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type WalletResult<T> = Result<T, WalletError>;

// ── Key file format ───────────────────────────────────────────────────────────

/// On-disk representation of a wallet key file.
/// The `encrypted_private_key` field is AES-256-GCM encrypted and
/// base64-encoded.  The `private_key` is NEVER stored in plaintext.
///
/// GITIGNORED: `*.wallet.json` — see root .gitignore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletKeyFile {
    /// "ml-dsa-65" — identifies the scheme unambiguously
    pub scheme: String,
    /// QCB bech32 address derived from the ML-DSA public key
    pub address: String,
    /// Hex-encoded ML-DSA-65 public key (1952 bytes uncompressed)
    pub public_key: String,
    /// AES-256-GCM encrypted private key, hex-encoded (see EncryptedBlob)
    pub encrypted_private_key: String,
    /// Argon2id parameters used to derive the AES key from the passphrase
    pub kdf: KdfParams,
    /// Timestamp of creation (Unix seconds)
    pub created_at: u64,
    /// Human label (informational only)
    pub label: String,
}

/// KDF parameters for Argon2id passphrase stretching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm:   String, // "argon2id"
    pub m_cost:      u32,    // memory kibibytes (128 * 1024 = 128 MB)
    pub t_cost:      u32,    // iterations
    pub p_cost:      u32,    // parallelism
    pub salt_hex:    String, // 32-byte random salt, hex-encoded
}

/// AES-256-GCM encrypted blob: nonce + ciphertext + tag.
/// Encoded as `nonce_hex:ciphertext_hex` for clarity in JSON.
struct EncryptedBlob {
    nonce:      [u8; 12],
    ciphertext: Vec<u8>, // includes GCM tag appended by aes-gcm
}

impl EncryptedBlob {
    fn to_hex_string(&self) -> String {
        let nonce_hex: String = self.nonce.iter().map(|b| format!("{b:02x}")).collect();
        let ct_hex:    String = self.ciphertext.iter().map(|b| format!("{b:02x}")).collect();
        format!("{nonce_hex}:{ct_hex}")
    }

    fn from_hex_string(s: &str) -> WalletResult<Self> {
        let (nonce_part, ct_part) = s.split_once(':')
            .ok_or_else(|| WalletError::Hex("encrypted blob missing ':' separator".into()))?;
        let nonce_bytes = hex_decode(nonce_part)?;
        if nonce_bytes.len() != 12 {
            return Err(WalletError::Hex(format!("nonce must be 12 bytes, got {}", nonce_bytes.len())));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);
        Ok(Self { nonce, ciphertext: hex_decode(ct_part)? })
    }
}

// ── Key encryption / decryption ───────────────────────────────────────────────

/// Derive a 32-byte AES key from a passphrase using Argon2id.
fn derive_key(passphrase: &str, params: &KdfParams) -> WalletResult<[u8; 32]> {
    use argon2::{Argon2, Params, Version};

    let salt = hex_decode(&params.salt_hex)?;

    let argon2_params = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(32),
    ).map_err(|e| WalletError::EncryptionFailed(format!("Argon2 params: {e}")))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| WalletError::EncryptionFailed(format!("Argon2 hash: {e}")))?;

    Ok(key)
}

/// Encrypt private key bytes with AES-256-GCM.
fn encrypt_key(key_bytes: &[u8], aes_key: &[u8; 32]) -> WalletResult<EncryptedBlob> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Nonce as AeadNonce}};
    use rand::RngCore;

    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| WalletError::EncryptionFailed(format!("AES init: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = AeadNonce::<Aes256Gcm>::from(nonce_bytes);

    let ciphertext = cipher.encrypt(&nonce, key_bytes)
        .map_err(|e| WalletError::EncryptionFailed(format!("AES-GCM encrypt: {e}")))?;

    Ok(EncryptedBlob { nonce: nonce_bytes, ciphertext })
}

/// Decrypt private key bytes with AES-256-GCM.
fn decrypt_key(blob: &EncryptedBlob, aes_key: &[u8; 32]) -> WalletResult<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Nonce as AeadNonce}};

    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| WalletError::EncryptionFailed(format!("AES init: {e}")))?;

    let nonce = AeadNonce::<Aes256Gcm>::from(blob.nonce);

    cipher.decrypt(&nonce, blob.ciphertext.as_slice())
        .map_err(|_| WalletError::DecryptionFailed)
}

// ── Wallet operations ─────────────────────────────────────────────────────────

/// Generate a new ML-DSA-65 wallet and write the encrypted key file.
///
/// # Arguments
/// * `path`       — output file path (e.g. `keys/alice.wallet.json`)
/// * `label`      — human-readable name for the wallet
/// * `passphrase` — encryption passphrase (never stored)
///
/// # Security
/// The private key is encrypted with AES-256-GCM(Argon2id(passphrase)).
/// The key file is safe to store on disk; the passphrase is required to use it.
/// Never commit `*.wallet.json` to version control.
pub fn generate_wallet(
    path:       &str,
    label:      &str,
    passphrase: &str,
) -> WalletResult<WalletKeyFile> {
    if Path::new(path).exists() {
        return Err(WalletError::KeyFileExists(path.to_string()));
    }

    // Generate ML-DSA-65 key pair
    let scheme = MlDsaScheme;
    let kp = scheme.generate_keypair("random")?; // pqcrypto ignores seed; uses OS RNG

    // Derive address from public key (QCB bech32 prefix)
    let address = derive_address_from_pq_key(&kp.public_key);

    // Argon2id KDF: 128 MB / 3 iterations / 4 threads
    let kdf = KdfParams {
        algorithm: "argon2id".to_string(),
        m_cost:    128 * 1024, // 128 MB
        t_cost:    3,
        p_cost:    4,
        salt_hex:  random_hex(32),
    };

    // Derive AES key and encrypt private key
    let aes_key = derive_key(passphrase, &kdf)?;
    let blob = encrypt_key(&kp.private_key, &aes_key)?;

    let key_file = WalletKeyFile {
        scheme:                "ml-dsa-65".to_string(),
        address:               address.clone(),
        public_key:            hex_encode(&kp.public_key),
        encrypted_private_key: blob.to_hex_string(),
        kdf,
        created_at:            unix_now(),
        label:                 label.to_string(),
    };

    let json = serde_json::to_string_pretty(&key_file)?;
    std::fs::write(path, json)?;

    tracing::info!("wallet generated: address={address} scheme=ml-dsa-65 path={path}");
    Ok(key_file)
}

/// Load and decrypt a wallet key file, returning the raw keypair.
///
/// # Security
/// The private key is only in memory for the duration of this call.
/// Callers must zeroize the returned `KeyPair` when done (future work:
/// use zeroize crate; for Phase 1 this is acceptable).
pub fn load_wallet(path: &str, passphrase: &str) -> WalletResult<(WalletKeyFile, KeyPair)> {
    let json = std::fs::read_to_string(path)
        .map_err(|_| WalletError::KeyFileNotFound(path.to_string()))?;
    let key_file: WalletKeyFile = serde_json::from_str(&json)?;

    let aes_key  = derive_key(passphrase, &key_file.kdf)?;
    let blob     = EncryptedBlob::from_hex_string(&key_file.encrypted_private_key)?;
    let priv_key = decrypt_key(&blob, &aes_key)?;
    let pub_key  = hex_decode(&key_file.public_key)?;

    let kp = KeyPair {
        scheme:      SchemeId::MlDsa,
        public_key:  pub_key,
        private_key: priv_key,
    };

    Ok((key_file, kp))
}

// ── Transaction signing ───────────────────────────────────────────────────────

/// Sign a transaction body JSON string with an ML-DSA key pair.
///
/// The signing message (B4 chain-ID binding) is:
///   SHA-256("chain-forge/pq-tx/v1\n" || chain_id || "\n" || tx_body_json)
///
/// This domain-separated construction binds the signature to the specific chain,
/// preventing cross-chain replay attacks.  The verifier in chain-forge-execution
/// uses the identical construction.
///
/// # Arguments
/// * `tx_body_json` — canonical JSON of the transaction body
/// * `chain_id`     — chain identifier from genesis (e.g. `"testchain"`)
/// * `kp`           — ML-DSA-65 key pair
///
/// # Returns
/// Hex-encoded ML-DSA-65 detached signature (3293 bytes).
pub fn sign_transaction(tx_body_json: &str, chain_id: &str, kp: &KeyPair) -> WalletResult<String> {
    // CS-001-M2: canonical pre-hash — MLDSA_TX_DOMAIN_V1 || chain_id || "\n" || body_json
    let message = mldsa_tx_prehash(chain_id, tx_body_json.as_bytes());
    let scheme = MlDsaScheme;
    let sig = scheme.sign(&message, kp)?;
    Ok(hex_encode(&sig.bytes))
}

// ─── DIS-AUTH-V1 canonical payload ──────────────────────────────────────────
//
// These constants and the builder function must stay byte-for-byte identical
// with the implementation in chain-forge-node::auth.  Both crates implement
// the same algorithm independently to avoid a dependency cycle.
//
// Layout (all integers big-endian):
//   [10]  b"DIS-AUTH-V1"          domain separator (fixed, not length-prefixed)
//   [2]   protocol_version: u16   = 1
//   [2+N] chain_id                u16-length-prefixed UTF-8
//   [2+N] audience (node_id)      u16-length-prefixed UTF-8
//   [2+N] scope                   u16-length-prefixed UTF-8
//   [16]  challenge_id            16 raw bytes (from 32-char hex API field)
//   [8]   issued_at: u64          Unix seconds
//   [8]   expires_at: u64         Unix seconds

const DIS_DOMAIN_SEPARATOR: &[u8] = b"DIS-AUTH-V1";
const DIS_PROTOCOL_VERSION: u16    = 1;
const DIS_MAX_FIELD_LEN: usize     = 255;

/// Build the DIS-AUTH-V1 canonical binary payload from challenge JSON fields.
///
/// Call this with the parsed fields from the QR-code `AuthChallenge` JSON
/// before passing to `sign_challenge_canonical`.
pub fn dis_canonical_payload(
    chain_id:         &str,
    audience:         &str,   // == challenge.node_id
    scope:            &str,
    challenge_id_hex: &str,   // 32 hex chars = 16 bytes
    issued_at:        u64,
    expires_at:       u64,
) -> WalletResult<Vec<u8>> {
    let chain_id_bytes = chain_id.as_bytes();
    let audience_bytes = audience.as_bytes();
    let scope_bytes    = scope.as_bytes();

    if chain_id_bytes.len() > DIS_MAX_FIELD_LEN {
        return Err(WalletError::InvalidInput(
            format!("DIS chain_id too long: {} bytes (max {DIS_MAX_FIELD_LEN})", chain_id_bytes.len())
        ));
    }
    if audience_bytes.len() > DIS_MAX_FIELD_LEN {
        return Err(WalletError::InvalidInput(
            format!("DIS audience too long: {} bytes (max {DIS_MAX_FIELD_LEN})", audience_bytes.len())
        ));
    }
    if scope_bytes.len() > DIS_MAX_FIELD_LEN {
        return Err(WalletError::InvalidInput(
            format!("DIS scope too long: {} bytes (max {DIS_MAX_FIELD_LEN})", scope_bytes.len())
        ));
    }
    if challenge_id_hex.len() != 32 {
        return Err(WalletError::InvalidInput(
            format!("DIS challenge_id must be 32 hex chars, got {}", challenge_id_hex.len())
        ));
    }
    let id_bytes = hex_decode(challenge_id_hex)
        .map_err(|_| WalletError::InvalidInput("DIS challenge_id is not valid hex".into()))?;

    let mut buf = Vec::with_capacity(
        DIS_DOMAIN_SEPARATOR.len() + 2
        + 2 + chain_id_bytes.len()
        + 2 + audience_bytes.len()
        + 2 + scope_bytes.len()
        + 16 + 8 + 8
    );
    buf.extend_from_slice(DIS_DOMAIN_SEPARATOR);
    buf.extend_from_slice(&DIS_PROTOCOL_VERSION.to_be_bytes());
    buf.extend_from_slice(&(chain_id_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(chain_id_bytes);
    buf.extend_from_slice(&(audience_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(audience_bytes);
    buf.extend_from_slice(&(scope_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(scope_bytes);
    buf.extend_from_slice(&id_bytes);
    buf.extend_from_slice(&issued_at.to_be_bytes());
    buf.extend_from_slice(&expires_at.to_be_bytes());
    Ok(buf)
}

/// Sign a DIS-001 authentication challenge with an ML-DSA key pair.
///
/// The wallet receives the `challenge_json` string from the QR code (the full
/// `AuthChallenge` JSON issued by `POST /api/auth/challenge`).  It parses the
/// JSON, builds the DIS-AUTH-V1 canonical binary payload, SHA-256 pre-hashes it
/// (same convention as `sign_transaction`), signs with ML-DSA-65, and returns
/// the tagged signature `"mldsa65:<hex>"`.
///
/// # Authentication flow
/// 1. Node issues `AuthChallenge` via `POST /api/auth/challenge`
/// 2. Node encodes the challenge JSON as a QR code
/// 3. User scans QR code; wallet calls `sign_challenge(challenge_json, &kp)`
/// 4. Wallet POSTs `{ challenge_id, public_key, signature }` to `POST /api/auth/verify`
/// 5. Node verifies signature using the SAME DIS-AUTH-V1 canonical payload and returns
///    `{ status: "verified", address, chain_id }`
///
/// # Signing construction (DIS-specific, documented explicitly)
/// ```text
/// payload  = DIS-AUTH-V1 canonical binary (see dis_canonical_payload)
/// message  = SHA-256(payload)            // explicit SHA-256 pre-hash
/// sig      = ML-DSA-65.sign(message, sk) // standard ML-DSA on the hash
/// output   = "mldsa65:" || hex(sig)
/// ```
///
/// This is NOT standard ML-DSA-65 message signing.  The SHA-256 pre-hash is
/// a DIS-specific construction identical to how transaction bodies are signed.
///
/// # Returns
/// Tagged hex signature: `"mldsa65:<hex_signature_bytes>"`
pub fn sign_challenge(challenge_json: &str, kp: &KeyPair) -> WalletResult<String> {
    use sha2::{Sha256, Digest};

    // Parse the challenge JSON to extract the fields needed for canonical payload.
    let ch: serde_json::Value = serde_json::from_str(challenge_json)
        .map_err(|e| WalletError::InvalidInput(format!("invalid challenge JSON: {e}")))?;

    let challenge_id = ch["challenge_id"].as_str()
        .ok_or_else(|| WalletError::InvalidInput("challenge_id missing".into()))?;
    let issued_at = ch["issued_at"].as_u64()
        .ok_or_else(|| WalletError::InvalidInput("issued_at missing".into()))?;
    let expires_at = ch["expires_at"].as_u64()
        .ok_or_else(|| WalletError::InvalidInput("expires_at missing".into()))?;
    let node_id = ch["node_id"].as_str()
        .ok_or_else(|| WalletError::InvalidInput("node_id missing".into()))?;
    let scope = ch["scope"].as_str()
        .ok_or_else(|| WalletError::InvalidInput("scope missing".into()))?;
    let chain_id = ch["chain_id"].as_str()
        .ok_or_else(|| WalletError::InvalidInput("chain_id missing in challenge — node may be running an older version".into()))?;

    // Build the DIS-AUTH-V1 canonical binary payload.
    // This is the single source of truth for the signed bytes — the node's
    // verify_challenge_signature() builds the same bytes from the stored AuthChallenge.
    let payload = dis_canonical_payload(chain_id, node_id, scope, challenge_id, issued_at, expires_at)?;

    // SHA-256 pre-hash then ML-DSA sign (DIS-specific construction).
    let message: [u8; 32] = Sha256::digest(&payload).into();
    let scheme = MlDsaScheme;
    let sig = scheme.sign(&message, kp)?;

    Ok(format!("mldsa65:{}", hex_encode(&sig.bytes)))
}

/// Verify a transaction signature (used in tests and by the node's tx verifier).
///
/// # Arguments
/// * `tx_body_json` — the transaction body JSON that was signed
/// * `chain_id`     — chain identifier from genesis (e.g. `"testchain"`)
/// * `sig_hex`      — hex-encoded ML-DSA-65 signature
/// * `public_key`   — ML-DSA-65 public key bytes
pub fn verify_transaction(
    tx_body_json: &str,
    chain_id:     &str,
    sig_hex:      &str,
    public_key:   &[u8],
) -> WalletResult<()> {
    use chain_forge_crypto::Signature;

    // CS-001-M2: canonical pre-hash — MLDSA_TX_DOMAIN_V1 || chain_id || "\n" || body_json
    let message = mldsa_tx_prehash(chain_id, tx_body_json.as_bytes());

    let sig_bytes = hex_decode(sig_hex)?;
    let sig = Signature { scheme: SchemeId::MlDsa, bytes: sig_bytes };

    let scheme = MlDsaScheme;
    scheme.verify(&message, &sig, public_key)?;
    Ok(())
}

// ── Devnet tx submission ──────────────────────────────────────────────────────

/// A transaction envelope ready to submit to the node's /api/tx endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedTxEnvelope {
    /// Unique transaction id (caller-generated)
    pub id:        String,
    /// Sender's QCB address
    pub sender:    String,
    /// Monotonically increasing nonce (Unix millis for devnet)
    pub nonce:     u64,
    /// The transaction body (JSON value)
    pub body:      serde_json::Value,
    /// Gas limit in gas units
    pub gas_limit: u64,
    /// ML-DSA-65 signature over SHA-256(body_json), hex-encoded
    pub signature: Vec<String>, // ["mldsa65:<hex>"] — extensible for hybrid
}

impl SignedTxEnvelope {
    /// Build a signed transfer transaction (for devnet testing).
    ///
    /// `chain_id` must match the genesis chain identifier used by the target node.
    pub fn transfer(
        sender:    &str,
        to:        &str,
        amount:    u64,
        denom:     &str,
        chain_id:  &str,
        kp:        &KeyPair,
    ) -> WalletResult<Self> {
        let body = serde_json::json!({
            "type":   "Transfer",
            "to":     to,
            "amount": amount,
            "denom":  denom,
        });
        let body_json = serde_json::to_string(&body)?;
        let sig_hex = sign_transaction(&body_json, chain_id, kp)?;
        let nonce = unix_now_millis();

        Ok(Self {
            id:        format!("wallet-tx-{nonce}"),
            sender:    sender.to_string(),
            nonce,
            body,
            gas_limit: 500_000,
            signature: vec![format!("mldsa65:{sig_hex}")],
        })
    }
}

/// Submit a signed transaction envelope to a QCB node.
///
/// # Arguments
/// * `host` — node hostname or IP (e.g. "127.0.0.1")
/// * `port` — node HTTP API port (e.g. 8080 for Alice devnet)
/// * `tx`   — the signed transaction envelope
///
/// # Returns
/// The raw JSON response body from the node.
pub fn submit_tx(host: &str, port: u16, tx: &SignedTxEnvelope) -> WalletResult<serde_json::Value> {
    let url = format!("http://{host}:{port}/api/tx");
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(tx)
        .map_err(|e| WalletError::Network(format!("{e}")))?;

    let body: serde_json::Value = resp.into_json()
        .map_err(|e| WalletError::Network(format!("response parse: {e}")))?;

    Ok(body)
}

// ── Address derivation ────────────────────────────────────────────────────────

/// Derive a QCB bech32-style address from an ML-DSA (or other PQ) public key.
///
/// **CS-001-H1**: Delegates to `chain_forge_core::Address::from_public_key_schemed`
/// with `AddressScheme::PostQuantum`, which produces:
///   `qcb1pq{hex(SHA3-256(public_key)[..20])}`
///
/// Using SHA-3 (consistent with block/tx hashing) instead of the earlier
/// double-SHA-256 construction.  The `pq` infix is the permanent namespace
/// discriminant — Ed25519 addresses (`qcb1…`) can never collide with ML-DSA
/// addresses (`qcb1pq…`) even if the hash output happened to match.
///
/// **Breaking change from pre-CS-001-H1 devnet**: old addresses used
/// double-SHA-256; new addresses use SHA3-256.  Devnet state is not migrated —
/// regenerate keys and re-derive addresses after this commit.
pub fn derive_address_from_pq_key(public_key: &[u8]) -> String {
    chain_forge_core::Address::from_public_key_schemed(
        public_key,
        "qcb",
        chain_forge_core::HashWidth::Bits256,
        chain_forge_core::AddressScheme::PostQuantum,
    ).as_str().to_string()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> WalletResult<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| WalletError::Hex(format!("at pos {i}: {e}"))))
        .collect()
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex_encode(&buf)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("qcb_wallet_test_{name}.wallet.json"));
        p.to_string_lossy().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    // ── Test 1: Key generation produces correct ML-DSA-65 sizes ──────────────

    #[test]
    fn keygen_produces_correct_sizes() {
        let path = tmp_path("keygen_sizes");
        cleanup(&path);

        let kf = generate_wallet(&path, "test-wallet", "test-passphrase").unwrap();
        let pk = hex_decode(&kf.public_key).unwrap();
        assert_eq!(pk.len(), 1952, "ML-DSA-65 public key is 1952 bytes (NIST FIPS 204)");
        assert_eq!(kf.scheme, "ml-dsa-65");
        assert!(kf.address.starts_with("qcb1pq"), "address must have pq prefix");

        cleanup(&path);
    }

    // ── Test 2: Encrypted key file round-trips correctly ─────────────────────

    #[test]
    fn key_file_roundtrip_correct_passphrase() {
        let path = tmp_path("roundtrip_ok");
        cleanup(&path);

        let kf_orig = generate_wallet(&path, "roundtrip", "correct-passphrase").unwrap();
        let (kf_loaded, _kp) = load_wallet(&path, "correct-passphrase").unwrap();

        assert_eq!(kf_orig.address, kf_loaded.address);
        assert_eq!(kf_orig.public_key, kf_loaded.public_key);

        cleanup(&path);
    }

    // ── Test 3: Wrong passphrase fails decryption ─────────────────────────────

    #[test]
    fn wrong_passphrase_fails() {
        let path = tmp_path("wrong_pass");
        cleanup(&path);

        generate_wallet(&path, "test", "correct-pass").unwrap();
        let result = load_wallet(&path, "wrong-pass");
        assert!(result.is_err(), "wrong passphrase must fail decryption");
        assert!(matches!(result.unwrap_err(), WalletError::DecryptionFailed));

        cleanup(&path);
    }

    // ── Test 4: Transaction sign + verify round-trip ──────────────────────────

    #[test]
    fn sign_verify_roundtrip() {
        let path = tmp_path("sign_verify");
        cleanup(&path);

        let kf = generate_wallet(&path, "signing-test", "pass123").unwrap();
        let (_kf, kp) = load_wallet(&path, "pass123").unwrap();

        let tx_body = r#"{"type":"Transfer","to":"qcb1bob","amount":1000,"denom":"uqrc"}"#;
        let sig_hex = sign_transaction(tx_body, "testchain", &kp).unwrap();
        let pub_key = hex_decode(&kf.public_key).unwrap();

        // Correct verification must succeed
        assert!(verify_transaction(tx_body, "testchain", &sig_hex, &pub_key).is_ok(),
            "valid signature must verify");

        cleanup(&path);
    }

    // ── Test 5: Forged signature is rejected ──────────────────────────────────

    #[test]
    fn forged_signature_rejected() {
        let path = tmp_path("forge");
        cleanup(&path);

        let kf1 = generate_wallet(&path, "alice", "pass-a").unwrap();
        let (_kf1, _kp1) = load_wallet(&path, "pass-a").unwrap();

        // Eve generates her own key pair (different wallet)
        let path2 = tmp_path("forge_eve");
        cleanup(&path2);
        let _kf2 = generate_wallet(&path2, "eve", "pass-e").unwrap();
        let (_kf2, kp2) = load_wallet(&path2, "pass-e").unwrap();

        let tx_body = r#"{"type":"Transfer","to":"qcb1eve","amount":9999,"denom":"uqrc"}"#;
        // Eve signs with her own key — verify against Alice's public key
        let eve_sig = sign_transaction(tx_body, "testchain", &kp2).unwrap();
        let alice_pk = hex_decode(&kf1.public_key).unwrap();

        assert!(verify_transaction(tx_body, "testchain", &eve_sig, &alice_pk).is_err(),
            "signature from wrong key must be rejected");

        cleanup(&path);
        cleanup(&path2);
    }

    // ── Test 6: Tampered message is rejected ──────────────────────────────────

    #[test]
    fn tampered_tx_body_rejected() {
        let path = tmp_path("tamper");
        cleanup(&path);

        let kf = generate_wallet(&path, "alice", "passphrase").unwrap();
        let (_kf, kp) = load_wallet(&path, "passphrase").unwrap();

        let original_tx = r#"{"type":"Transfer","to":"qcb1bob","amount":100,"denom":"uqrc"}"#;
        let tampered_tx = r#"{"type":"Transfer","to":"qcb1eve","amount":100,"denom":"uqrc"}"#;
        let sig_hex = sign_transaction(original_tx, "testchain", &kp).unwrap();
        let pub_key = hex_decode(&kf.public_key).unwrap();

        // Signature of original must not verify against tampered message
        assert!(verify_transaction(tampered_tx, "testchain", &sig_hex, &pub_key).is_err(),
            "tampered tx body must fail signature verification");

        cleanup(&path);
    }

    // ── Test 7: Replayed signature is rejected ────────────────────────────────

    #[test]
    fn replayed_tx_rejected_different_nonce() {
        let path = tmp_path("replay");
        cleanup(&path);

        let kf = generate_wallet(&path, "alice", "passphrase").unwrap();
        let (_kf, kp) = load_wallet(&path, "passphrase").unwrap();
        let pub_key = hex_decode(&kf.public_key).unwrap();

        // Sign tx with nonce=1
        let tx_n1 = r#"{"type":"Transfer","nonce":1,"to":"qcb1bob","amount":100,"denom":"uqrc"}"#;
        let sig_n1 = sign_transaction(tx_n1, "testchain", &kp).unwrap();
        assert!(verify_transaction(tx_n1, "testchain", &sig_n1, &pub_key).is_ok());

        // Replay: try to use nonce=1 signature for nonce=2 tx
        let tx_n2 = r#"{"type":"Transfer","nonce":2,"to":"qcb1bob","amount":100,"denom":"uqrc"}"#;
        assert!(verify_transaction(tx_n2, "testchain", &sig_n1, &pub_key).is_err(),
            "signature from nonce=1 tx must not verify against nonce=2 tx");

        cleanup(&path);
    }

    // ── Test 8: Duplicate key file refused ───────────────────────────────────

    #[test]
    fn refuses_to_overwrite_existing_key_file() {
        let path = tmp_path("overwrite");
        cleanup(&path);

        generate_wallet(&path, "first", "pass1").unwrap();
        let result = generate_wallet(&path, "second", "pass2");
        assert!(matches!(result.unwrap_err(), WalletError::KeyFileExists(_)),
            "must refuse to overwrite an existing key file");

        cleanup(&path);
    }

    // ── Test 9: Address determinism ───────────────────────────────────────────

    #[test]
    fn address_derivation_is_deterministic() {
        let pk = vec![0u8; 1952]; // predictable test input
        let addr1 = derive_address_from_pq_key(&pk);
        let addr2 = derive_address_from_pq_key(&pk);
        assert_eq!(addr1, addr2, "address derivation must be deterministic");
        assert!(addr1.starts_with("qcb1pq"));
    }

    // ── Test 10: SignedTxEnvelope builds correctly ────────────────────────────

    #[test]
    fn signed_tx_envelope_has_mldsa_tag() {
        let path = tmp_path("envelope");
        cleanup(&path);

        let kf = generate_wallet(&path, "test", "passphrase").unwrap();
        let (_kf, kp) = load_wallet(&path, "passphrase").unwrap();

        let env = SignedTxEnvelope::transfer(
            &kf.address, "qcb1bob", 500, "uqrc", "testchain", &kp
        ).unwrap();

        assert_eq!(env.sender, kf.address);
        assert!(!env.signature.is_empty());
        assert!(env.signature[0].starts_with("mldsa65:"),
            "envelope signature must carry mldsa65 scheme tag");

        // Verify the signature in the envelope is valid
        let body_json = serde_json::to_string(&env.body).unwrap();
        let sig_hex = env.signature[0].strip_prefix("mldsa65:").unwrap();
        let pub_key = hex_decode(&kf.public_key).unwrap();
        assert!(verify_transaction(&body_json, "testchain", sig_hex, &pub_key).is_ok(),
            "envelope signature must be valid");

        cleanup(&path);
    }

    // ── Test 11: sign_challenge produces mldsa65-tagged signature ────────────

    #[test]
    fn sign_challenge_produces_tagged_signature() {
        let path = tmp_path("sign_challenge_tag");
        cleanup(&path);

        let _kf = generate_wallet(&path, "auth-test", "passphrase").unwrap();
        let (_kf, kp) = load_wallet(&path, "passphrase").unwrap();

        // DIS-AUTH-V1 challenge JSON — must include chain_id (added in DIS-001-11).
        let challenge_json = r#"{"challenge_id":"abcdef1234567890abcdef1234567890","issued_at":1700000000,"expires_at":1700000060,"node_id":"qcb1alice","scope":"wallet:authenticate","chain_id":"qattice-devnet-1"}"#;

        let sig = sign_challenge(challenge_json, &kp).unwrap();
        assert!(sig.starts_with("mldsa65:"),
            "sign_challenge must produce mldsa65-tagged signature; got: {}", &sig[..16.min(sig.len())]);

        // Hex payload after the tag must be non-empty
        let hex_part = sig.strip_prefix("mldsa65:").unwrap();
        assert!(!hex_part.is_empty(), "signature hex must be non-empty");
        // ML-DSA-65 signatures are ~3309 bytes = 6618 hex chars
        assert!(hex_part.len() > 6000,
            "ML-DSA-65 signature hex should be ~6618 chars, got {}", hex_part.len());

        cleanup(&path);
    }

    // ── Test 12: sign_challenge integration with verify_challenge_signature ───
    //
    // Full DIS-001-11 round-trip: wallet::sign_challenge (DIS-AUTH-V1 canonical payload)
    // must produce a signature that passes the same canonical-payload verification.
    // We replicate the verifier logic here (can't import chain-forge-node — cycle).

    #[test]
    fn sign_challenge_integrates_with_node_verify() {
        use sha2::{Sha256, Digest};
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let path = tmp_path("challenge_integration");
        cleanup(&path);

        let kf = generate_wallet(&path, "alice-auth", "passphrase").unwrap();
        let (_kf, kp) = load_wallet(&path, "passphrase").unwrap();

        // DIS-AUTH-V1 challenge JSON with chain_id (required since DIS-001-11).
        let challenge_json = r#"{"challenge_id":"deadbeef1234567890abcdef12345678","issued_at":1700000000,"expires_at":1700000060,"node_id":"qcb1alice","scope":"wallet:authenticate","chain_id":"qattice-devnet-1"}"#;

        // Sign with wallet (uses DIS-AUTH-V1 canonical payload internally)
        let sig_tagged = sign_challenge(challenge_json, &kp).unwrap();
        assert!(sig_tagged.starts_with("mldsa65:"));

        // Replicate the verifier path: build the same canonical payload and SHA-256 pre-hash.
        let payload = dis_canonical_payload(
            "qattice-devnet-1",
            "qcb1alice",
            "wallet:authenticate",
            "deadbeef1234567890abcdef12345678",
            1700000000,
            1700000060,
        ).expect("canonical_payload must succeed");

        let message: [u8; 32] = Sha256::digest(&payload).into();

        // Verify using the ML-DSA-65 public key from the wallet
        let pk_bytes = hex_decode(&kf.public_key).unwrap();
        assert_eq!(pk_bytes.len(), 1952, "ML-DSA-65 pk must be 1952 bytes");

        let sig_hex = sig_tagged.strip_prefix("mldsa65:").unwrap();
        let sig_bytes = hex_decode(sig_hex).unwrap();

        let sig = chain_forge_crypto::Signature {
            scheme: chain_forge_crypto::SchemeId::MlDsa,
            bytes:  sig_bytes,
        };
        let result = MlDsaScheme.verify(&message, &sig, &pk_bytes);
        assert!(result.is_ok(),
            "wallet sign_challenge (DIS-AUTH-V1) must pass canonical-payload verification: {:?}", result.err());

        cleanup(&path);
    }

    // ── Test 13: sign_challenge requires chain_id field ───────────────────────

    #[test]
    fn sign_challenge_rejects_missing_chain_id() {
        let path = tmp_path("sign_challenge_no_chain");
        cleanup(&path);

        let _kf = generate_wallet(&path, "dis-test", "passphrase").unwrap();
        let (_kf, kp) = load_wallet(&path, "passphrase").unwrap();

        // Old-format challenge JSON without chain_id — must be rejected
        let old_challenge_json = r#"{"challenge_id":"abcdef1234567890abcdef1234567890","issued_at":1700000000,"expires_at":1700000060,"node_id":"qcb1alice","scope":"wallet:authenticate"}"#;

        let result = sign_challenge(old_challenge_json, &kp);
        assert!(result.is_err(),
            "sign_challenge must reject a challenge JSON missing chain_id (version isolation)");
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("chain_id"),
            "error message must mention chain_id; got: {err_str}");

        cleanup(&path);
    }
}
