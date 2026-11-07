//! Adapter from the safety-state `ConsensusSigner` / `ConsensusVerifier` traits to the existing FIPS 204 ML-DSA-65 backend
//! (stub: tests-first commit; signing fails and verification rejects until the implementation lands).
use super::{ConsensusSigner, ConsensusVerifier, SignerError};

/// In-memory ML-DSA-65 signing key. Never written to disk by this crate.
#[derive(Debug)]
pub struct Fips204Signer { public_key: Vec<u8> }

impl Fips204Signer {
    pub fn from_seed(_seed: &[u8; 32]) -> Self { Fips204Signer { public_key: Vec::new() } }
    pub fn generate() -> Result<Self, SignerError> { Err(SignerError("unimplemented".into())) }
}

impl ConsensusSigner for Fips204Signer {
    fn public_key(&self) -> &[u8] { &self.public_key }
    fn sign(&mut self, _context: &[u8], _message: &[u8]) -> Result<Vec<u8>, SignerError> { Err(SignerError("unimplemented".into())) }
}

pub struct Fips204Verifier;

impl ConsensusVerifier for Fips204Verifier {
    fn verify(&self, _public_key: &[u8], _context: &[u8], _message: &[u8], _signature: &[u8]) -> bool { false }
}
