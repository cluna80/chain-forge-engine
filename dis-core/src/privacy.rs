//! DIS-PRIV-001: unlinkability check and disclosure analysis utilities.
//!
//! These utilities make the privacy properties of DIS-KS-V1 explicit and testable.
//! They do NOT provide anonymity or ZK proofs; they document what each RP learns and
//! demonstrate that distinct per-vendor keypairs carry no shared public correlator.

use crate::{verifier::HolderProof, Request};
use sha2::{Digest, Sha256};

/// Everything a relying party learns from a single successfully verified proof.
/// The RP cannot infer ANY field from this struct that relates to the holder's
/// identity, keys, or grants at any other vendor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureInfo {
    /// SHA-256 of the holder's public key at THIS vendor. Vendor-specific;
    /// a different vendor sees a different fingerprint for the same holder.
    pub key_fingerprint: [u8; 32],
    /// Resource the holder is accessing.
    pub resource_id: String,
    /// Action being authorized.
    pub action: String,
    /// Scopes presented in this proof (all were accepted by the RP's policy).
    pub scopes: Vec<String>,
    /// Issuing timestamp (Unix seconds).
    pub issued_at: u64,
}

/// Extract what the RP learns from a verified proof.
/// Call only after `RelyingParty::verify` returns `Ok(())`.
pub fn disclosure_info(request: &Request, proof: &HolderProof) -> DisclosureInfo {
    DisclosureInfo {
        key_fingerprint: Sha256::digest(&proof.public_key).into(),
        resource_id: request.resource_id.clone(),
        action: request.action.clone(),
        scopes: request.scopes.clone(),
        issued_at: request.issued_at,
    }
}

/// Returns `true` if two proofs share the same public key — i.e. the same
/// enrolled key was used for both, allowing the corresponding RPs to correlate
/// the holder if they compared notes.
///
/// In a correctly implemented wallet each vendor gets a distinct keypair, so
/// `are_linkable(proof_a, proof_b)` MUST return `false` for proofs to different
/// vendors. Returning `true` for two proofs to the SAME vendor is expected: the
/// RP already has that key enrolled and can always link its own sessions.
pub fn are_linkable(proof_a: &HolderProof, proof_b: &HolderProof) -> bool {
    proof_a.public_key == proof_b.public_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        verifier::{RelyingParty, RpPolicy, VerifyError},
        wallet::DemoWallet,
        Request, SUITE_ML_DSA_65,
    };
    use std::collections::HashSet;

    fn make_rp(id: &str, resource: &str, action: &str, scope: &str) -> RelyingParty {
        let mut grants = HashSet::new();
        grants.insert((resource.into(), action.into(), scope.into()));
        RelyingParty::new(RpPolicy {
            rp_id: id.into(),
            rp_origin: format!("https://{id}.example"),
            policy_id: "v1".into(),
            grants,
            min_suite_id: SUITE_ML_DSA_65,
        })
    }

    fn make_req(id: &str, resource: &str, action: &str, scope: &str) -> Request {
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

    /// Core unlinkability property: one wallet enrolled at three vendors produces
    /// three distinct public keys — no shared correlator across vendors.
    #[test]
    fn cross_vendor_public_keys_are_distinct() {
        let mut wallet = DemoWallet::new();
        let pk_game = wallet.provision("game", "https://game.example", "v1").unwrap();
        let pk_docs = wallet.provision("docs", "https://docs.example", "v1").unwrap();
        let pk_pay  = wallet.provision("pay",  "https://pay.example",  "v1").unwrap();

        assert_ne!(pk_game, pk_docs, "game and docs share a key — linkable!");
        assert_ne!(pk_docs, pk_pay,  "docs and pay share a key — linkable!");
        assert_ne!(pk_game, pk_pay,  "game and pay share a key — linkable!");
    }

    /// Proofs presented to different vendors carry no shared public material that
    /// would allow the two RPs to identify the same holder by comparing proofs.
    #[test]
    fn cross_vendor_proofs_are_not_linkable() {
        let vendors = [
            ("game",    "game:1",    "play",   "game:play"),
            ("docs",    "doc:1",     "read",   "document:read"),
            ("pay",     "payment:1", "submit", "payment:submit"),
        ];
        let mut wallet = DemoWallet::new();
        let mut rps: Vec<RelyingParty> = Vec::new();

        for (id, resource, action, scope) in vendors {
            let origin = format!("https://{id}.example");
            let pk = wallet.provision(id, &origin, "v1").unwrap();
            let mut rp = make_rp(id, resource, action, scope);
            rp.enroll_test_key(&pk).unwrap();
            rps.push(rp);
        }

        // Collect one proof per vendor.
        let mut proofs: Vec<HolderProof> = Vec::new();
        for (i, (id, resource, action, scope)) in vendors.iter().enumerate() {
            let req = rps[i].issue(make_req(id, resource, action, scope)).unwrap();
            let proof = wallet.sign(&req, resource, action).unwrap();
            assert_eq!(rps[i].verify(&req, &proof, 1010), Ok(()));
            proofs.push(proof);
        }

        // No two cross-vendor proofs share a public key.
        for i in 0..proofs.len() {
            for j in (i + 1)..proofs.len() {
                assert!(
                    !are_linkable(&proofs[i], &proofs[j]),
                    "proofs[{i}] and proofs[{j}] are linkable — same public key leaked"
                );
            }
        }
    }

    /// Two separate proofs to the SAME vendor ARE linkable (expected — the RP has
    /// the key enrolled and can correlate its own sessions by design).
    #[test]
    fn same_vendor_proofs_are_linkable() {
        let mut wallet = DemoWallet::new();
        wallet.provision("docs", "https://docs.example", "v1").unwrap();
        let pk = wallet.provision("docs2", "https://docs.example", "v1");
        // provision rejects a duplicate id but the same key is used for both proofs
        // to "docs"; demonstrate with two requests signed by the same wallet key.
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        let pk_bytes = {
            // re-provision under a throwaway id to get the bytes
            let mut w2 = DemoWallet::new();
            w2.provision("docs", "https://docs.example", "v1").unwrap()
        };
        drop(pk);
        rp.enroll_test_key(&pk_bytes).unwrap();

        // Two requests, both signed by the same key — same-vendor linkability is expected.
        let mut w3 = DemoWallet::new();
        let pk3 = w3.provision("docs", "https://docs.example", "v1").unwrap();
        let mut rp3 = make_rp("docs", "doc:1", "read", "document:read");
        rp3.enroll_test_key(&pk3).unwrap();

        let req1 = rp3.issue(make_req("docs", "doc:1", "read", "document:read")).unwrap();
        let proof1 = w3.sign(&req1, "doc:1", "read").unwrap();
        assert_eq!(rp3.verify(&req1, &proof1, 1010), Ok(()));

        let req2 = rp3.issue(make_req("docs", "doc:1", "read", "document:read")).unwrap();
        let proof2 = w3.sign(&req2, "doc:1", "read").unwrap();
        assert_eq!(rp3.verify(&req2, &proof2, 1010), Ok(()));

        // Same vendor, same key → linkable (RP can correlate its own sessions).
        assert!(are_linkable(&proof1, &proof2));
    }

    /// DisclosureInfo contains no cross-vendor identifier: the key_fingerprint is
    /// vendor-specific and differs across vendors for the same holder.
    #[test]
    fn disclosure_info_contains_no_cross_vendor_identifier() {
        let vendors = [
            ("game", "game:1", "play", "game:play"),
            ("docs", "doc:1",  "read", "document:read"),
        ];
        let mut wallet = DemoWallet::new();
        let mut rps: Vec<RelyingParty> = Vec::new();
        for (id, resource, action, scope) in vendors {
            let origin = format!("https://{id}.example");
            let pk = wallet.provision(id, &origin, "v1").unwrap();
            let mut rp = make_rp(id, resource, action, scope);
            rp.enroll_test_key(&pk).unwrap();
            rps.push(rp);
        }

        let mut infos: Vec<DisclosureInfo> = Vec::new();
        for (i, (id, resource, action, scope)) in vendors.iter().enumerate() {
            let req = rps[i].issue(make_req(id, resource, action, scope)).unwrap();
            let proof = wallet.sign(&req, resource, action).unwrap();
            rps[i].verify(&req, &proof, 1010).unwrap();
            infos.push(disclosure_info(&req, &proof));
        }

        // Different vendors see different key fingerprints — no shared identifier.
        assert_ne!(
            infos[0].key_fingerprint, infos[1].key_fingerprint,
            "cross-vendor key fingerprints must differ"
        );
        // Each vendor sees only its own resource and action.
        assert_ne!(infos[0].resource_id, infos[1].resource_id);
        assert_ne!(infos[0].action, infos[1].action);
    }

    /// A proof for vendor A is structurally rejected by vendor B even with the
    /// same key — the transcript binds rp_id, rp_origin, and policy_id.
    #[test]
    fn cross_vendor_proof_submission_rejected() {
        let mut wallet = DemoWallet::new();
        let pk_game = wallet.provision("game", "https://game.example", "v1").unwrap();
        let pk_docs = wallet.provision("docs", "https://docs.example", "v1").unwrap();
        let mut rp_game = make_rp("game", "game:1", "play", "game:play");
        let mut rp_docs = make_rp("docs", "doc:1", "read", "document:read");
        rp_game.enroll_test_key(&pk_game).unwrap();
        rp_docs.enroll_test_key(&pk_docs).unwrap();

        let req = rp_game.issue(make_req("game", "game:1", "play", "game:play")).unwrap();
        let proof = wallet.sign(&req, "game:1", "play").unwrap();

        // game's proof to docs RP → audience mismatch.
        assert_eq!(
            rp_docs.verify(&req, &proof, 1010),
            Err(VerifyError::Audience)
        );
        // game's RP accepts its own proof.
        assert_eq!(rp_game.verify(&req, &proof, 1010), Ok(()));
    }

    /// Scopes not in the RP's grant are rejected — minimal disclosure is enforced
    /// by the RP, not just by the wallet.
    #[test]
    fn rp_rejects_unauthorized_scope() {
        use crate::verifier::sign_for_test;
        use pqcrypto_dilithium::dilithium3;
        use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

        let (pk, sk) = dilithium3::keypair();
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        rp.enroll_test_key(pk.as_bytes()).unwrap();

        // Request includes an unauthorized scope ("document:admin") in addition to the valid one.
        let mut req = make_req("docs", "doc:1", "read", "document:read");
        req.scopes = vec!["document:admin".into(), "document:read".into()];
        let issued = rp.issue(req).unwrap();
        let proof = sign_for_test(&issued, sk.as_bytes(), pk.as_bytes()).unwrap();

        assert_eq!(rp.verify(&issued, &proof, 1010), Err(VerifyError::Unauthorized));
    }
}
