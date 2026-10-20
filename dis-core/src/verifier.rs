//! Standalone DIS relying-party verification prototype.
//! Uses real Dilithium3/ML-DSA-65 signatures (no stub backend).
//! In-memory replay storage is suitable for tests, NOT multi-instance production.
//! No issuer credential, recovery, wallet origin-authentication or unlinkability claim.

use std::collections::{HashMap, HashSet};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use crate::{canonical_request, Request, Error as EncodingError};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("invalid request encoding: {0}")]
    Encoding(#[from] EncodingError),
    #[error("RP mismatch")]
    Audience,
    #[error("expired or not yet valid")]
    Time,
    #[error("unknown or consumed challenge")]
    Replay,
    #[error("key or signature invalid")]
    Signature,
    #[error("requested operation not permitted")]
    Unauthorized,
    #[error("invalid challenge parameters")]
    Challenge,
}

/// A local RP decides its own exact resource/action/scope permissions.
/// Authentication and authorization are deliberately separate.
#[derive(Debug, Clone)]
pub struct RpPolicy {
    pub rp_id: String,
    pub rp_origin: String,
    pub policy_id: String,
    pub grants: HashSet<(String, String, String)>, // (resource, action, scope)
}

#[derive(Debug, Clone)]
pub struct HolderProof {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A single-process verifier; each RP has its own instance and replay store.
pub struct RelyingParty {
    policy: RpPolicy,
    pending: HashMap<[u8; 16], Request>,
    enrolled_keys: HashSet<[u8; 32]>,
}

impl RelyingParty {
    pub fn new(policy: RpPolicy) -> Self { Self { policy, pending: HashMap::new(), enrolled_keys: HashSet::new() } }

    /// Local demo enrollment. Production enrollment MUST authenticate the holder\n    /// through an RP-approved bootstrap/credential process; never accept arbitrary\n    /// keys from an unauthenticated public endpoint. Each RP stores its own keys.\n    pub fn enroll_test_key(&mut self, public_key: &[u8]) -> Result<(), VerifyError> {\n        dilithium3::PublicKey::from_bytes(public_key).map_err(|_| VerifyError::Signature)?;\n        self.enrolled_keys.insert(Sha256::digest(public_key).into());\n        Ok(())\n    }\n\n    /// The RP must obtain fresh challenge_id AND nonce from a CSPRNG.
    /// Only register requests issued by this RP, never wallet-supplied requests.
    pub fn issue(&mut self, mut request: Request) -> Result<Request, VerifyError> {
        self.check_audience(&request)?;
        canonical_request(&request)?;
        getrandom::getrandom(&mut request.challenge_id).map_err(|_| VerifyError::Challenge)?;
        getrandom::getrandom(&mut request.nonce).map_err(|_| VerifyError::Challenge)?;
        if self.pending.insert(request.challenge_id, request.clone()).is_some() {
            return Err(VerifyError::Challenge);
        }
        Ok(request)
    }

    fn check_audience(&self, r: &Request) -> Result<(), VerifyError> {
        if r.rp_id != self.policy.rp_id || r.rp_origin != self.policy.rp_origin
            || r.policy_id != self.policy.policy_id { return Err(VerifyError::Audience); }
        Ok(())
    }

    /// Verifies real signature and independently enforces local permissions.
    /// Consume after successful cryptographic verification, even on policy denial,
    /// so one signed request cannot be used to repeatedly probe authorization.
    pub fn verify(&mut self, request: &Request, proof: &HolderProof, now: u64) -> Result<(), VerifyError> {
        self.check_audience(request)?;
        let transcript = canonical_request(request)?;
        if now < request.issued_at || now >= request.expires_at { return Err(VerifyError::Time); }
        let saved = self.pending.get(&request.challenge_id).ok_or(VerifyError::Replay)?;
        if canonical_request(saved)? != transcript { return Err(VerifyError::Challenge); }
        let pk = dilithium3::PublicKey::from_bytes(&proof.public_key).map_err(|_| VerifyError::Signature)?;
        let sig = dilithium3::DetachedSignature::from_bytes(&proof.signature).map_err(|_| VerifyError::Signature)?;
        dilithium3::verify_detached_signature(&sig, &transcript, &pk).map_err(|_| VerifyError::Signature)?;
        self.pending.remove(&request.challenge_id);
        if request.scopes.is_empty() || request.scopes.iter().any(|scope| {
            !self.policy.grants.contains(&(request.resource_id.clone(), request.action.clone(), scope.clone()))
        }) { return Err(VerifyError::Unauthorized); }
        Ok(())
    }
}

/// Demonstration wallet signing only. Production wallet must independently
/// authenticate the RP origin and obtain informed user consent before signing.
pub fn sign_for_test(request: &Request, secret_key: &[u8], public_key: &[u8]) -> Result<HolderProof, VerifyError> {
    let sk = dilithium3::SecretKey::from_bytes(secret_key).map_err(|_| VerifyError::Signature)?;
    let bytes = canonical_request(request)?;
    let sig = dilithium3::detached_sign(&bytes, &sk);
    Ok(HolderProof { public_key: public_key.to_vec(), signature: sig.as_bytes().to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SUITE_ML_DSA_65;

    fn rp(name: &str, resource: &str, action: &str, scope: &str) -> RelyingParty {
        let mut grants = HashSet::new();
        grants.insert((resource.into(), action.into(), scope.into()));
        RelyingParty::new(RpPolicy {
            rp_id: name.into(), rp_origin: format!("https://{name}.example"),
            policy_id: "v1".into(), grants
        })
    }
    fn request(name: &str, resource: &str, action: &str, scope: &str) -> Request {
        Request { suite_id: SUITE_ML_DSA_65, rp_id: name.into(),
            rp_origin: format!("https://{name}.example"),
            challenge_id: [0; 16], nonce: [0; 16],
            issued_at: 1000, expires_at: 1060, resource_id: resource.into(),
            action: action.into(), scopes: vec![scope.into()],
            operation_digest: None, policy_id: "v1".into() }
    }
    #[test]
    fn three_independent_vendors_and_replay() {
        let (pk, sk) = dilithium3::keypair();
        let mut a = rp("game", "game:1", "play", "game:play");
        let mut b = rp("docs", "doc:1", "read", "document:read");
        let mut c = rp("payments", "payment:1", "submit", "payment:submit");
        for (rp, req) in [
            (&mut a, request("game","game:1","play","game:play")),
            (&mut b, request("docs","doc:1","read","document:read")),
            (&mut c, request("payments","payment:1","submit","payment:submit"))
        ] {
            let issued = rp.issue(req).unwrap();
            let proof = sign_for_test(&issued, sk.as_bytes(), pk.as_bytes()).unwrap();
            assert_eq!(rp.verify(&issued, &proof, 1010), Ok(()));
            assert_eq!(rp.verify(&issued, &proof, 1010), Err(VerifyError::Replay));
        }
    }
    #[test]
    fn rejects_cross_vendor_and_modified_action() {
        let (pk, sk) = dilithium3::keypair();
        let mut a = rp("game","game:1","play","game:play");
        let mut b = rp("docs","doc:1","read","document:read");
        a.enroll_test_key(pk.as_bytes()).unwrap();\n        let req = a.issue(request("game","game:1","play","game:play")).unwrap();
        let proof = sign_for_test(&req, sk.as_bytes(), pk.as_bytes()).unwrap();
        assert_eq!(b.verify(&req,&proof,1010),Err(VerifyError::Audience));
        let mut tampered = req.clone();
        tampered.action = "delete".into();
        assert_eq!(a.verify(&tampered,&proof,1010),Err(VerifyError::Challenge));
        assert_eq!(a.verify(&req,&proof,1010),Ok(()));
    }
    #[test]
    fn signature_expiry_and_policy_denial() {
        let (pk, sk) = dilithium3::keypair();
        let mut a = rp("docs","doc:1","read","document:read");
        a.enroll_test_key(pk.as_bytes()).unwrap();\n        let req = a.issue(request("docs","doc:1","delete","document:read")).unwrap();
        let proof = sign_for_test(&req, sk.as_bytes(), pk.as_bytes()).unwrap();
        assert_eq!(a.verify(&req,&proof,1060),Err(VerifyError::Time));
        let mut forged = proof.clone();
        forged.signature[0] ^= 1;
        assert_eq!(a.verify(&req,&forged,1010),Err(VerifyError::Signature));
        assert_eq!(a.verify(&req,&proof,1010),Err(VerifyError::Unauthorized));
        assert_eq!(a.verify(&req,&proof,1010),Err(VerifyError::Replay));
    }
}
