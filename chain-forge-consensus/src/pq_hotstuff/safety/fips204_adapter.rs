//! Adapter from the safety-state [`ConsensusSigner`] / [`ConsensusVerifier`] traits to the existing FIPS 204 ML-DSA-65
//! backend (`chain-forge-crypto`, feature `fips204-backend`, crate `fips204` 0.5.0). It adds no cryptography of its own: every
//! operation is a call into [`MlDsa65Fips204`], with the FIPS 204 context passed through unchanged.
//!
//! **Keys are in memory only.** Nothing here reads or writes a key file; production validator key storage is out of scope
//! (blocked on the independent review of PR #109). `Fips204Signer` overwrites its secret key when dropped, as a best-effort
//! measure only: copies made elsewhere (the backend's own parsed key object, which it zeroizes on drop, or the operating
//! system's memory) are not under this type's control.
use super::{ConsensusSigner, ConsensusVerifier, SignerError};
use fips204_crypto::fips204_backend::MlDsa65Fips204;

/// An in-memory ML-DSA-65 signing key.
pub struct Fips204Signer {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl Fips204Signer {
    /// FIPS 204 key generation from a 32-byte seed (reproducible; for tests and for restoring a key from its seed).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let kp = MlDsa65Fips204::keygen_from_seed(seed);
        Fips204Signer { public_key: kp.public_key, secret_key: kp.private_key }
    }

    /// A fresh key from the operating-system RNG.
    pub fn generate() -> Result<Self, SignerError> {
        let (mut seed, kp) = MlDsa65Fips204::generate().map_err(|e| SignerError(e.to_string()))?;
        seed.fill(0);
        Ok(Fips204Signer { public_key: kp.public_key, secret_key: kp.private_key })
    }
}

impl ConsensusSigner for Fips204Signer {
    fn public_key(&self) -> &[u8] { &self.public_key }

    /// Hedged signing: fresh randomness from the operating-system RNG for every call.
    fn sign(&mut self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError> {
        MlDsa65Fips204::sign(&self.secret_key, message, context).map_err(|e| SignerError(e.to_string()))
    }
}

impl std::fmt::Debug for Fips204Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fips204Signer").field("public_key_len", &self.public_key.len()).field("secret_key", &"<redacted>").finish()
    }
}

impl Drop for Fips204Signer {
    fn drop(&mut self) {
        self.secret_key.fill(0);
        std::hint::black_box(&self.secret_key); // keep the optimizer from discarding the overwrite
    }
}

/// Verifies against the FIPS 204 backend. Every failure, including a malformed key, a wrong length or an over-long context,
/// is `false`; nothing panics.
pub struct Fips204Verifier;

impl ConsensusVerifier for Fips204Verifier {
    fn verify(&self, public_key: &[u8], context: &[u8], message: &[u8], signature: &[u8]) -> bool {
        MlDsa65Fips204::verify(public_key, message, signature, context).is_ok()
    }
}
