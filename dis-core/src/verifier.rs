//! Standalone DIS relying-party verification prototype.
//! Uses real Dilithium3/ML-DSA-65 signatures (no stub backend).
//! In-memory replay storage is suitable for tests, NOT multi-instance production.
//! No issuer credential, recovery, wallet origin-authentication or unlinkability claim.

use crate::{canonical_request, Error as EncodingError, Request};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

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
    #[error("key has been revoked")]
    Revoked,
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
    revoked_keys: HashSet<[u8; 32]>,
}

impl RelyingParty {
    pub fn new(policy: RpPolicy) -> Self {
        Self {
            policy,
            pending: HashMap::new(),
            enrolled_keys: HashSet::new(),
            revoked_keys: HashSet::new(),
        }
    }

    /// Local demo enrollment. Production enrollment MUST authenticate the holder
    /// through an RP-approved bootstrap/credential process; never accept arbitrary
    /// keys from an unauthenticated public endpoint. Each RP stores its own keys.
    pub fn enroll_test_key(&mut self, public_key: &[u8]) -> Result<(), VerifyError> {
        dilithium3::PublicKey::from_bytes(public_key).map_err(|_| VerifyError::Signature)?;
        self.enrolled_keys.insert(Sha256::digest(public_key).into());
        Ok(())
    }

    /// Revoke a previously enrolled key. Any future verification attempt with
    /// this key returns `VerifyError::Revoked`, even if the proof is cryptographically
    /// valid. The challenge is still consumed so revoked keys cannot be probed.
    pub fn revoke(&mut self, public_key: &[u8]) -> Result<(), VerifyError> {
        dilithium3::PublicKey::from_bytes(public_key).map_err(|_| VerifyError::Signature)?;
        let fp: [u8; 32] = Sha256::digest(public_key).into();
        self.enrolled_keys.remove(&fp);
        self.revoked_keys.insert(fp);
        Ok(())
    }

    /// Atomically revoke `old_public_key` and enroll `new_public_key`.
    /// After this call: proofs signed with the old key are rejected with
    /// `Revoked`; proofs signed with the new key are accepted (subject to
    /// policy). Returns `Err(Signature)` if either key is malformed.
    pub fn rotate_key(
        &mut self,
        old_public_key: &[u8],
        new_public_key: &[u8],
    ) -> Result<(), VerifyError> {
        dilithium3::PublicKey::from_bytes(new_public_key).map_err(|_| VerifyError::Signature)?;
        self.revoke(old_public_key)?;
        let new_fp: [u8; 32] = Sha256::digest(new_public_key).into();
        self.enrolled_keys.insert(new_fp);
        Ok(())
    }

    /// The RP must obtain fresh challenge_id AND nonce from a CSPRNG.
    /// Only register requests issued by this RP, never wallet-supplied requests.
    pub fn issue(&mut self, mut request: Request) -> Result<Request, VerifyError> {
        self.check_audience(&request)?;
        canonical_request(&request)?;
        getrandom::getrandom(&mut request.challenge_id).map_err(|_| VerifyError::Challenge)?;
        getrandom::getrandom(&mut request.nonce).map_err(|_| VerifyError::Challenge)?;
        if self
            .pending
            .insert(request.challenge_id, request.clone())
            .is_some()
        {
            return Err(VerifyError::Challenge);
        }
        Ok(request)
    }

    fn check_audience(&self, r: &Request) -> Result<(), VerifyError> {
        if r.rp_id != self.policy.rp_id
            || r.rp_origin != self.policy.rp_origin
            || r.policy_id != self.policy.policy_id
        {
            return Err(VerifyError::Audience);
        }
        Ok(())
    }

    /// Verifies real signature and independently enforces local permissions.
    /// Consume after successful cryptographic verification, even on policy denial,
    /// so one signed request cannot be used to repeatedly probe authorization.
    pub fn verify(
        &mut self,
        request: &Request,
        proof: &HolderProof,
        now: u64,
    ) -> Result<(), VerifyError> {
        self.check_audience(request)?;
        let transcript = canonical_request(request)?;
        if now < request.issued_at || now >= request.expires_at {
            return Err(VerifyError::Time);
        }
        let saved = self
            .pending
            .get(&request.challenge_id)
            .ok_or(VerifyError::Replay)?;
        if canonical_request(saved)? != transcript {
            return Err(VerifyError::Challenge);
        }
        let pk = dilithium3::PublicKey::from_bytes(&proof.public_key)
            .map_err(|_| VerifyError::Signature)?;
        let sig = dilithium3::DetachedSignature::from_bytes(&proof.signature)
            .map_err(|_| VerifyError::Signature)?;
        dilithium3::verify_detached_signature(&sig, &transcript, &pk)
            .map_err(|_| VerifyError::Signature)?;
        self.pending.remove(&request.challenge_id);
        let key_fingerprint: [u8; 32] = Sha256::digest(&proof.public_key).into();
        if self.revoked_keys.contains(&key_fingerprint) {
            return Err(VerifyError::Revoked);
        }
        if !self.enrolled_keys.contains(&key_fingerprint) {
            return Err(VerifyError::Unauthorized);
        }
        if request.scopes.is_empty()
            || request.scopes.iter().any(|scope| {
                !self.policy.grants.contains(&(
                    request.resource_id.clone(),
                    request.action.clone(),
                    scope.clone(),
                ))
            })
        {
            return Err(VerifyError::Unauthorized);
        }
        Ok(())
    }
}

/// Demonstration wallet signing only. Production wallet must independently
/// authenticate the RP origin and obtain informed user consent before signing.
pub fn sign_for_test(
    request: &Request,
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<HolderProof, VerifyError> {
    let sk = dilithium3::SecretKey::from_bytes(secret_key).map_err(|_| VerifyError::Signature)?;
    let bytes = canonical_request(request)?;
    let sig = dilithium3::detached_sign(&bytes, &sk);
    Ok(HolderProof {
        public_key: public_key.to_vec(),
        signature: sig.as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SUITE_ML_DSA_65;

    fn rp(name: &str, resource: &str, action: &str, scope: &str) -> RelyingParty {
        let mut grants = HashSet::new();
        grants.insert((resource.into(), action.into(), scope.into()));
        RelyingParty::new(RpPolicy {
            rp_id: name.into(),
            rp_origin: format!("https://{name}.example"),
            policy_id: "v1".into(),
            grants,
        })
    }
    fn request(name: &str, resource: &str, action: &str, scope: &str) -> Request {
        Request {
            suite_id: SUITE_ML_DSA_65,
            rp_id: name.into(),
            rp_origin: format!("https://{name}.example"),
            challenge_id: [0; 16],
            nonce: [0; 16],
            issued_at: 1000,
            expires_at: 1060,
            resource_id: resource.into(),
            action: action.into(),
            scopes: vec![scope.into()],
            operation_digest: None,
            policy_id: "v1".into(),
        }
    }
    #[test]
    fn three_independent_vendors_and_replay() {
        let mut a = rp("game", "game:1", "play", "game:play");
        let mut b = rp("docs", "doc:1", "read", "document:read");
        let mut c = rp("payments", "payment:1", "submit", "payment:submit");
        for (rp, req) in [
            (&mut a, request("game", "game:1", "play", "game:play")),
            (&mut b, request("docs", "doc:1", "read", "document:read")),
            (
                &mut c,
                request("payments", "payment:1", "submit", "payment:submit"),
            ),
        ] {
            let (pk, sk) = dilithium3::keypair();
            rp.enroll_test_key(pk.as_bytes()).unwrap();
            let issued = rp.issue(req).unwrap();
            let proof = sign_for_test(&issued, sk.as_bytes(), pk.as_bytes()).unwrap();
            assert_eq!(rp.verify(&issued, &proof, 1010), Ok(()));
            assert_eq!(rp.verify(&issued, &proof, 1010), Err(VerifyError::Replay));
        }
    }
    #[test]
    fn rejects_cross_vendor_and_modified_action() {
        let (pk, sk) = dilithium3::keypair();
        let mut a = rp("game", "game:1", "play", "game:play");
        let mut b = rp("docs", "doc:1", "read", "document:read");
        a.enroll_test_key(pk.as_bytes()).unwrap();
        let req = a
            .issue(request("game", "game:1", "play", "game:play"))
            .unwrap();
        let proof = sign_for_test(&req, sk.as_bytes(), pk.as_bytes()).unwrap();
        assert_eq!(b.verify(&req, &proof, 1010), Err(VerifyError::Audience));
        let mut tampered = req.clone();
        tampered.action = "delete".into();
        assert_eq!(
            a.verify(&tampered, &proof, 1010),
            Err(VerifyError::Challenge)
        );
        assert_eq!(a.verify(&req, &proof, 1010), Ok(()));
    }
    #[test]
    fn unregistered_key_is_denied() {
        let (pk, sk) = dilithium3::keypair();
        let mut a = rp("docs", "doc:1", "read", "document:read");
        let req = a
            .issue(request("docs", "doc:1", "read", "document:read"))
            .unwrap();
        let proof = sign_for_test(&req, sk.as_bytes(), pk.as_bytes()).unwrap();
        assert_eq!(a.verify(&req, &proof, 1010), Err(VerifyError::Unauthorized));
        assert_eq!(a.verify(&req, &proof, 1010), Err(VerifyError::Replay));
    }
    #[test]
    fn revoked_key_is_rejected_and_challenge_consumed() {
        let (pk, sk) = dilithium3::keypair();
        let mut a = rp("docs", "doc:1", "read", "document:read");
        a.enroll_test_key(pk.as_bytes()).unwrap();
        let req = a.issue(request("docs", "doc:1", "read", "document:read")).unwrap();
        let proof = sign_for_test(&req, sk.as_bytes(), pk.as_bytes()).unwrap();
        a.revoke(pk.as_bytes()).unwrap();
        // Revoked key → Revoked; challenge is consumed in the process.
        assert_eq!(a.verify(&req, &proof, 1010), Err(VerifyError::Revoked));
        // Challenge was consumed: a fresh proof with the same challenge is also rejected.
        assert_eq!(a.verify(&req, &proof, 1010), Err(VerifyError::Replay));
    }

    #[test]
    fn proof_signed_before_revocation_is_rejected() {
        // Sign first, then revoke — late-arriving proof is still blocked.
        let (pk, sk) = dilithium3::keypair();
        let mut a = rp("docs", "doc:1", "read", "document:read");
        a.enroll_test_key(pk.as_bytes()).unwrap();
        let req = a.issue(request("docs", "doc:1", "read", "document:read")).unwrap();
        let proof = sign_for_test(&req, sk.as_bytes(), pk.as_bytes()).unwrap();
        a.revoke(pk.as_bytes()).unwrap();
        assert_eq!(a.verify(&req, &proof, 1010), Err(VerifyError::Revoked));
    }

    #[test]
    fn key_rotation_old_rejected_new_accepted() {
        let (old_pk, old_sk) = dilithium3::keypair();
        let (new_pk, new_sk) = dilithium3::keypair();
        let mut a = rp("docs", "doc:1", "read", "document:read");
        a.enroll_test_key(old_pk.as_bytes()).unwrap();

        // Sign a proof with the old key before rotation.
        let req_old = a.issue(request("docs", "doc:1", "read", "document:read")).unwrap();
        let proof_old = sign_for_test(&req_old, old_sk.as_bytes(), old_pk.as_bytes()).unwrap();

        // Rotate: old key revoked, new key enrolled.
        a.rotate_key(old_pk.as_bytes(), new_pk.as_bytes()).unwrap();

        // Old proof → Revoked.
        assert_eq!(a.verify(&req_old, &proof_old, 1010), Err(VerifyError::Revoked));

        // New challenge signed with new key → accepted.
        let req_new = a.issue(request("docs", "doc:1", "read", "document:read")).unwrap();
        let proof_new = sign_for_test(&req_new, new_sk.as_bytes(), new_pk.as_bytes()).unwrap();
        assert_eq!(a.verify(&req_new, &proof_new, 1010), Ok(()));
    }

    #[test]
    fn rotation_of_one_vendor_does_not_affect_others() {
        let (pk_a, sk_a) = dilithium3::keypair();
        let (pk_b, sk_b) = dilithium3::keypair();
        let (pk_c, sk_c) = dilithium3::keypair();
        let (new_pk_a, new_sk_a) = dilithium3::keypair();

        let mut a = rp("game", "game:1", "play", "game:play");
        let mut b = rp("docs", "doc:1", "read", "document:read");
        let mut c = rp("payments", "payment:1", "submit", "payment:submit");
        a.enroll_test_key(pk_a.as_bytes()).unwrap();
        b.enroll_test_key(pk_b.as_bytes()).unwrap();
        c.enroll_test_key(pk_c.as_bytes()).unwrap();

        // Rotate vendor A's key.
        a.rotate_key(pk_a.as_bytes(), new_pk_a.as_bytes()).unwrap();

        // A: old key rejected, new key accepted.
        let req_a_old = a.issue(request("game", "game:1", "play", "game:play")).unwrap();
        let proof_a_old = sign_for_test(&req_a_old, sk_a.as_bytes(), pk_a.as_bytes()).unwrap();
        assert_eq!(a.verify(&req_a_old, &proof_a_old, 1010), Err(VerifyError::Revoked));

        let req_a_new = a.issue(request("game", "game:1", "play", "game:play")).unwrap();
        let proof_a_new = sign_for_test(&req_a_new, new_sk_a.as_bytes(), new_pk_a.as_bytes()).unwrap();
        assert_eq!(a.verify(&req_a_new, &proof_a_new, 1010), Ok(()));

        // B and C: unaffected by A's rotation.
        let req_b = b.issue(request("docs", "doc:1", "read", "document:read")).unwrap();
        let proof_b = sign_for_test(&req_b, sk_b.as_bytes(), pk_b.as_bytes()).unwrap();
        assert_eq!(b.verify(&req_b, &proof_b, 1010), Ok(()));

        let req_c = c.issue(request("payments", "payment:1", "submit", "payment:submit")).unwrap();
        let proof_c = sign_for_test(&req_c, sk_c.as_bytes(), pk_c.as_bytes()).unwrap();
        assert_eq!(c.verify(&req_c, &proof_c, 1010), Ok(()));
    }

    #[test]
    fn signature_expiry_and_policy_denial() {
        let (pk, sk) = dilithium3::keypair();
        let mut a = rp("docs", "doc:1", "read", "document:read");
        a.enroll_test_key(pk.as_bytes()).unwrap();
        let req = a
            .issue(request("docs", "doc:1", "delete", "document:read"))
            .unwrap();
        let proof = sign_for_test(&req, sk.as_bytes(), pk.as_bytes()).unwrap();
        assert_eq!(a.verify(&req, &proof, 1060), Err(VerifyError::Time));
        let mut forged = proof.clone();
        forged.signature[0] ^= 1;
        assert_eq!(a.verify(&req, &forged, 1010), Err(VerifyError::Signature));
        assert_eq!(a.verify(&req, &proof, 1010), Err(VerifyError::Unauthorized));
        assert_eq!(a.verify(&req, &proof, 1010), Err(VerifyError::Replay));
    }
}
