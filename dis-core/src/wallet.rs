//! DIS-KS-002 demo wallet; vendor origins are pretrusted, not discovered.
use crate::verifier::{sign_for_test, HolderProof, VerifyError};
use crate::Request;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use std::collections::HashMap;
struct Key {
    origin: String,
    policy: String,
    pk: Vec<u8>,
    sk: Vec<u8>,
}
#[derive(Default)]
pub struct DemoWallet {
    keys: HashMap<String, Key>,
}
impl DemoWallet {
    pub fn new() -> Self {
        Self::default()
    }
    /// Demo-only enrollment: caller must authenticate vendor metadata externally.
    pub fn provision(
        &mut self,
        id: &str,
        origin: &str,
        policy: &str,
    ) -> Result<Vec<u8>, VerifyError> {
        if id.is_empty() || origin.is_empty() || policy.is_empty() || self.keys.contains_key(id) {
            return Err(VerifyError::Challenge);
        }
        let (pk, sk) = dilithium3::keypair();
        let public = pk.as_bytes().to_vec();
        self.keys.insert(
            id.into(),
            Key {
                origin: origin.into(),
                policy: policy.into(),
                pk: public.clone(),
                sk: sk.as_bytes().to_vec(),
            },
        );
        Ok(public)
    }
    /// Production wallet must independently authenticate origin and obtain consent.
    pub fn sign(
        &self,
        req: &Request,
        expected_resource: &str,
        expected_action: &str,
    ) -> Result<HolderProof, VerifyError> {
        let k = self.keys.get(&req.rp_id).ok_or(VerifyError::Audience)?;
        if req.rp_origin != k.origin
            || req.policy_id != k.policy
            || req.resource_id != expected_resource
            || req.action != expected_action
        {
            return Err(VerifyError::Audience);
        }
        sign_for_test(req, &k.sk, &k.pk)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::{RelyingParty, RpPolicy};
    use crate::SUITE_ML_DSA_65;
    use std::collections::HashSet;
    fn request(id: &str, resource: &str, action: &str, scope: &str) -> Request {
        Request {
            suite_id: SUITE_ML_DSA_65,
            rp_id: id.into(),
            rp_origin: format!("https://{id}.example"),
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
    fn three_vendors_and_replay() {
        let mut wallet = DemoWallet::new();
        let mut distinct_keys = HashSet::new();
        for (id, resource, action, scope) in [
            ("game", "game:1", "play", "game:play"),
            ("docs", "doc:1", "read", "document:read"),
            ("payments", "payment:1", "submit", "payment:submit"),
        ] {
            let origin = format!("https://{id}.example");
            let pk = wallet.provision(id, &origin, "v1").unwrap();
            assert!(distinct_keys.insert(pk.clone()));
            let mut grants = HashSet::new();
            grants.insert((resource.into(), action.into(), scope.into()));
            let mut rp = RelyingParty::new(RpPolicy {
                rp_id: id.into(),
                rp_origin: origin,
                policy_id: "v1".into(),
                grants,
            });
            rp.enroll_test_key(&pk).unwrap();
            let req = rp.issue(request(id, resource, action, scope)).unwrap();
            let proof = wallet.sign(&req, resource, action).unwrap();
            assert_eq!(rp.verify(&req, &proof, 1010), Ok(()));
            assert_eq!(rp.verify(&req, &proof, 1010), Err(VerifyError::Replay));
        }
    }
    #[test]
    fn refuses_spoofed_origin_and_unapproved_action() {
        let mut wallet = DemoWallet::new();
        wallet
            .provision("docs", "https://docs.example", "v1")
            .unwrap();
        let mut req = request("docs", "doc:1", "read", "document:read");
        req.rp_origin = "https://attacker.example".into();
        assert!(matches!(
            wallet.sign(&req, "doc:1", "read"),
            Err(VerifyError::Audience)
        ));
        req.rp_origin = "https://docs.example".into();
        assert!(matches!(
            wallet.sign(&req, "doc:1", "delete"),
            Err(VerifyError::Audience)
        ));
    }
}
