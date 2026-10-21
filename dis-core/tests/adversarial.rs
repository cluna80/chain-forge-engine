//! DIS-SEC-001: Adversarial validation — every attack scenario must be cleanly
//! rejected with a specific error. No test in this file should ever pass
//! verification; a green run proves the system rejects them all.

use dis_core::{
    canonical_request,
    delegation::{make_delegation, sign_delegation, DelegatedProof, MAX_CHAIN_DEPTH},
    verifier::{HolderProof, RelyingParty, RpPolicy, VerifyError},
    Request, SUITE_ML_DSA_65,
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use std::collections::HashSet;

// ── helpers ──────────────────────────────────────────────────────────────────

fn keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium3::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

fn sign_raw(msg: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
    let sk = dilithium3::SecretKey::from_bytes(sk_bytes).unwrap();
    dilithium3::detached_sign(msg, &sk).as_bytes().to_vec()
}

fn rp(grants: &[(&str, &str, &str)]) -> RelyingParty {
    let mut g = HashSet::new();
    for (r, a, s) in grants {
        g.insert((r.to_string(), a.to_string(), s.to_string()));
    }
    RelyingParty::new(RpPolicy {
        rp_id: "acme".into(),
        rp_origin: "https://acme.example".into(),
        policy_id: "v1".into(),
        grants: g,
        min_suite_id: SUITE_ML_DSA_65,
    })
}

fn base_request() -> Request {
    Request {
        suite_id: SUITE_ML_DSA_65,
        rp_id: "acme".into(),
        rp_origin: "https://acme.example".into(),
        challenge_id: [0; 16],
        nonce: [0; 16],
        issued_at: 1_700_000_000,
        expires_at: 1_700_000_299,
        resource_id: "doc:1".into(),
        action: "read".into(),
        scopes: vec!["doc:read".into()],
        operation_digest: None,
        policy_id: "v1".into(),
    }
}

/// Enroll pk, issue a challenge for `req`, return the issued request.
fn enroll_and_issue(rp: &mut RelyingParty, pk: &[u8], req: Request) -> Request {
    rp.enroll_test_key(pk).unwrap();
    rp.issue(req).unwrap()
}

/// Valid proof for the issued request.
fn valid_proof(req: &Request, pk: &[u8], sk: &[u8]) -> HolderProof {
    let transcript = canonical_request(req).unwrap();
    HolderProof {
        public_key: pk.to_vec(),
        signature: sign_raw(&transcript, sk),
    }
}

const NOW: u64 = 1_700_000_100;

// ── Attack 1: completely forged signature ─────────────────────────────────────

#[test]
fn attack_forged_signature() {
    let (pk, sk) = keypair();
    let (_, attacker_sk) = keypair(); // different secret key
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    let transcript = canonical_request(&req).unwrap();
    let bad_proof = HolderProof {
        public_key: pk.clone(),
        signature: sign_raw(&transcript, &attacker_sk), // signed with wrong sk
    };
    let _ = sk; // legitimate sk unused — attacker doesn't have it
    assert_eq!(rp.verify(&req, &bad_proof, NOW), Err(VerifyError::Signature));
}

// ── Attack 2: bit-flip in signature bytes ─────────────────────────────────────

#[test]
fn attack_signature_bit_flip() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    let mut proof = valid_proof(&req, &pk, &sk);
    proof.signature[100] ^= 0xff;
    assert_eq!(rp.verify(&req, &proof, NOW), Err(VerifyError::Signature));
}

// ── Attack 3: signature over different message (wrong transcript) ─────────────

#[test]
fn attack_signature_over_wrong_message() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    // Sign a different transcript (action changed)
    let mut other_req = req.clone();
    other_req.action = "write".into();
    let other_transcript = canonical_request(&other_req).unwrap();
    let bad_proof = HolderProof {
        public_key: pk.clone(),
        signature: sign_raw(&other_transcript, &sk),
    };
    assert_eq!(rp.verify(&req, &bad_proof, NOW), Err(VerifyError::Signature));
}

// ── Attack 4: replay — present the same challenge twice ───────────────────────

#[test]
fn attack_challenge_replay() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    let proof = valid_proof(&req, &pk, &sk);
    // First verify succeeds
    assert!(rp.verify(&req, &proof, NOW).is_ok());
    // Second attempt with the same challenge is a replay
    assert_eq!(rp.verify(&req, &proof, NOW), Err(VerifyError::Replay));
}

// ── Attack 5: cross-RP challenge replay (present RP-A challenge to RP-B) ──────

#[test]
fn attack_cross_rp_challenge_replay() {
    let (pk, sk) = keypair();
    let mut rp_a = rp(&[("doc:1", "read", "doc:read")]);
    let mut rp_b = {
        let mut g = HashSet::new();
        g.insert(("doc:1".into(), "read".into(), "doc:read".into()));
        RelyingParty::new(RpPolicy {
            rp_id: "beta".into(),
            rp_origin: "https://beta.example".into(),
            policy_id: "v1".into(),
            grants: g,
            min_suite_id: SUITE_ML_DSA_65,
        })
    };
    rp_b.enroll_test_key(&pk).unwrap();

    let mut req_for_a = base_request();
    req_for_a.rp_id = "acme".into();
    req_for_a.rp_origin = "https://acme.example".into();
    let issued_a = enroll_and_issue(&mut rp_a, &pk, req_for_a);
    let proof = valid_proof(&issued_a, &pk, &sk);

    // Audience check on rp_b must reject (wrong rp_id)
    assert_eq!(rp_b.verify(&issued_a, &proof, NOW), Err(VerifyError::Audience));
}

// ── Attack 6: wrong rp_id in request ──────────────────────────────────────────

#[test]
fn attack_wrong_rp_id() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let mut req = base_request();
    req.rp_id = "evil-rp".into();
    rp.enroll_test_key(&pk).unwrap();
    // issue() checks audience before issuing
    let err = rp.issue(req).unwrap_err();
    assert_eq!(err, VerifyError::Audience);
    let _ = sk;
}

// ── Attack 7: wrong rp_origin ──────────────────────────────────────────────────

#[test]
fn attack_wrong_rp_origin() {
    let (pk, _sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let mut req = base_request();
    req.rp_origin = "https://evil.example".into();
    rp.enroll_test_key(&pk).unwrap();
    assert_eq!(rp.issue(req).unwrap_err(), VerifyError::Audience);
}

// ── Attack 8: expired request ─────────────────────────────────────────────────

#[test]
fn attack_expired_request() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    let proof = valid_proof(&req, &pk, &sk);
    let far_future = req.expires_at + 1;
    assert_eq!(rp.verify(&req, &proof, far_future), Err(VerifyError::Time));
}

// ── Attack 9: not-yet-valid request (issued_at in the future) ────────────────

#[test]
fn attack_request_not_yet_valid() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    let proof = valid_proof(&req, &pk, &sk);
    let before_issuance = req.issued_at - 1;
    assert_eq!(rp.verify(&req, &proof, before_issuance), Err(VerifyError::Time));
}

// ── Attack 10: key substitution — swap public key in proof ────────────────────

#[test]
fn attack_key_substitution_in_proof() {
    let (pk, sk) = keypair();
    let (attacker_pk, _) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    // Only legitimate pk is enrolled
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    let transcript = canonical_request(&req).unwrap();
    // Attacker claims legitimate pk but uses their own signature (can't pass)
    let bad_proof = HolderProof {
        public_key: attacker_pk.clone(), // not enrolled
        signature: sign_raw(&transcript, &sk), // valid sig over legitimate transcript
    };
    // sig won't verify with wrong pk → Signature error
    assert_eq!(rp.verify(&req, &bad_proof, NOW), Err(VerifyError::Signature));
}

// ── Attack 11: unenrolled key ─────────────────────────────────────────────────

#[test]
fn attack_unenrolled_key() {
    let (pk, sk) = keypair();
    let (attacker_pk, attacker_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    // Only pk enrolled, attacker has a different keypair
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    let transcript = canonical_request(&req).unwrap();
    let bad_proof = HolderProof {
        public_key: attacker_pk,
        signature: sign_raw(&transcript, &attacker_sk),
    };
    let _ = sk;
    assert_eq!(rp.verify(&req, &bad_proof, NOW), Err(VerifyError::Unauthorized));
}

// ── Attack 12: revoked key ────────────────────────────────────────────────────

#[test]
fn attack_revoked_key() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    rp.enroll_test_key(&pk).unwrap();
    rp.revoke(&pk).unwrap();
    let req = base_request();
    // issue() doesn't block revoked keys; verify() does
    let issued = rp.issue(req).unwrap();
    let proof = valid_proof(&issued, &pk, &sk);
    assert_eq!(rp.verify(&issued, &proof, NOW), Err(VerifyError::Revoked));
}

// ── Attack 13: use old key after rotation ─────────────────────────────────────

#[test]
fn attack_old_key_after_rotation() {
    let (old_pk, old_sk) = keypair();
    let (new_pk, _) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    rp.enroll_test_key(&old_pk).unwrap();
    rp.rotate_key(&old_pk, &new_pk).unwrap();
    let issued = rp.issue(base_request()).unwrap();
    let proof = valid_proof(&issued, &old_pk, &old_sk);
    assert_eq!(rp.verify(&issued, &proof, NOW), Err(VerifyError::Revoked));
}

// ── Attack 14: permission escalation — unauthorized resource ──────────────────

#[test]
fn attack_unauthorized_resource() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]); // only doc:1 allowed
    let mut req = base_request();
    req.resource_id = "doc:99".into(); // not in grants
    req.scopes = vec!["doc:read".into()];
    let issued = enroll_and_issue(&mut rp, &pk, req);
    let proof = valid_proof(&issued, &pk, &sk);
    assert_eq!(rp.verify(&issued, &proof, NOW), Err(VerifyError::Unauthorized));
}

// ── Attack 15: permission escalation — unauthorized action ────────────────────

#[test]
fn attack_unauthorized_action() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]); // only read allowed
    let mut req = base_request();
    req.action = "delete".into();
    req.scopes = vec!["doc:read".into()];
    let issued = enroll_and_issue(&mut rp, &pk, req);
    let proof = valid_proof(&issued, &pk, &sk);
    assert_eq!(rp.verify(&issued, &proof, NOW), Err(VerifyError::Unauthorized));
}

// ── Attack 16: scope injection — extra scope not in grants ────────────────────

#[test]
fn attack_scope_injection() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let mut req = base_request();
    req.scopes = vec!["doc:admin".into(), "doc:read".into()]; // doc:admin not granted
    let issued = enroll_and_issue(&mut rp, &pk, req);
    let proof = valid_proof(&issued, &pk, &sk);
    assert_eq!(rp.verify(&issued, &proof, NOW), Err(VerifyError::Unauthorized));
}

// ── Attack 17: empty scopes ───────────────────────────────────────────────────

#[test]
fn attack_empty_scopes() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let mut req = base_request();
    req.scopes = vec![];
    // canonical_request rejects unsorted/empty scopes? Let's test issue first
    rp.enroll_test_key(&pk).unwrap();
    // issue calls canonical_request internally — empty scopes pass structural check
    // but verify rejects them with Unauthorized
    match rp.issue(req) {
        Err(_) => { /* structural rejection at issue — also fine */ }
        Ok(issued) => {
            let proof = valid_proof(&issued, &pk, &sk);
            assert_eq!(rp.verify(&issued, &proof, NOW), Err(VerifyError::Unauthorized));
        }
    }
}

// ── Attack 18: downgrade suite_id at issue ────────────────────────────────────

#[test]
fn attack_downgrade_at_issue() {
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let mut req = base_request();
    req.suite_id = 0; // below min_suite_id
    rp.enroll_test_key(&keypair().0).unwrap();
    assert_eq!(rp.issue(req).unwrap_err(), VerifyError::DowngradedSuite);
}

// ── Attack 19: tampered request fields after issue ────────────────────────────

#[test]
fn attack_tampered_resource_after_issue() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read"), ("doc:99", "read", "doc:read")]);
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    // Sign the issued (legitimate) transcript
    let proof = valid_proof(&req, &pk, &sk);
    // Tamper the request after signing
    let mut tampered = req.clone();
    tampered.resource_id = "doc:99".into();
    // canonical_request of tampered ≠ saved → Challenge error
    assert_eq!(rp.verify(&tampered, &proof, NOW), Err(VerifyError::Challenge));
}

// ── Attack 20: tampered nonce after issue ─────────────────────────────────────

#[test]
fn attack_tampered_nonce_after_issue() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    let proof = valid_proof(&req, &pk, &sk);
    let mut tampered = req.clone();
    tampered.nonce[0] ^= 0x01;
    assert_eq!(rp.verify(&tampered, &proof, NOW), Err(VerifyError::Challenge));
}

// ── Attack 21: phantom challenge (challenge_id never issued) ──────────────────

#[test]
fn attack_phantom_challenge() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    rp.enroll_test_key(&pk).unwrap();
    // Build a request with a made-up challenge_id, never passed through issue()
    let mut req = base_request();
    req.challenge_id = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let transcript = canonical_request(&req).unwrap();
    let proof = HolderProof { public_key: pk, signature: sign_raw(&transcript, &sk) };
    assert_eq!(rp.verify(&req, &proof, NOW), Err(VerifyError::Replay));
}

// ── Attack 22: delegation — agent exceeds delegated scopes ────────────────────

#[test]
fn attack_delegation_scope_escalation() {
    let (human_pk, human_sk) = keypair();
    let (agent_pk, agent_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read"), ("doc:1", "write", "doc:write")]);
    rp.enroll_test_key(&human_pk).unwrap();

    // Human delegates only "read"
    let link = make_delegation(
        "acme", &human_pk, &human_sk, &agent_pk,
        vec!["doc:read".into()], "doc:1", "read",
        NOW, NOW + 299, None, false,
    ).unwrap();

    // Agent tries to get "write" access
    let mut req = base_request();
    req.action = "write".into();
    req.scopes = vec!["doc:write".into()];
    let issued = rp.issue(req).unwrap();

    let transcript = canonical_request(&issued).unwrap();
    let agent_proof = HolderProof {
        public_key: agent_pk,
        signature: sign_raw(&transcript, &agent_sk),
    };
    let delegated = DelegatedProof { chain: vec![link], agent_proof };
    assert_eq!(
        rp.verify_delegated(&issued, &delegated, NOW),
        Err(VerifyError::DelegationInvalid)
    );
}

// ── Attack 23: delegation — expired delegation link ───────────────────────────

#[test]
fn attack_delegation_expired_link() {
    let (human_pk, human_sk) = keypair();
    let (agent_pk, agent_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    rp.enroll_test_key(&human_pk).unwrap();

    let link = make_delegation(
        "acme", &human_pk, &human_sk, &agent_pk,
        vec!["doc:read".into()], "doc:1", "read",
        1_000, 2_000, // expired well before NOW
        None, false,
    ).unwrap();

    let issued = rp.issue(base_request()).unwrap();
    let transcript = canonical_request(&issued).unwrap();
    let agent_proof = HolderProof {
        public_key: agent_pk,
        signature: sign_raw(&transcript, &agent_sk),
    };
    let delegated = DelegatedProof { chain: vec![link], agent_proof };
    assert_eq!(
        rp.verify_delegated(&issued, &delegated, NOW),
        Err(VerifyError::DelegationInvalid)
    );
}

// ── Attack 24: delegation — chain depth overflow ──────────────────────────────

#[test]
fn attack_delegation_chain_too_deep() {
    let (root_pk, root_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    rp.enroll_test_key(&root_pk).unwrap();

    // Build MAX_CHAIN_DEPTH + 1 links
    let mut chain = Vec::new();
    let mut prev_pk = root_pk.clone();
    let mut prev_sk = root_sk.clone();
    for _ in 0..=MAX_CHAIN_DEPTH {
        let (next_pk, next_sk) = keypair();
        let link = make_delegation(
            "acme", &prev_pk, &prev_sk, &next_pk,
            vec!["doc:read".into()], "doc:1", "read",
            NOW, NOW + 299, None, false,
        ).unwrap();
        chain.push(link);
        prev_pk = next_pk;
        prev_sk = next_sk;
    }

    let issued = rp.issue(base_request()).unwrap();
    let transcript = canonical_request(&issued).unwrap();
    let agent_proof = HolderProof {
        public_key: prev_pk,
        signature: sign_raw(&transcript, &prev_sk),
    };
    let delegated = DelegatedProof { chain, agent_proof };
    assert_eq!(
        rp.verify_delegated(&issued, &delegated, NOW),
        Err(VerifyError::DelegationInvalid)
    );
}

// ── Attack 25: delegation — forged delegation signature ───────────────────────

#[test]
fn attack_delegation_forged_signature() {
    let (human_pk, _human_sk) = keypair();
    let (agent_pk, agent_sk) = keypair();
    let (_, attacker_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    rp.enroll_test_key(&human_pk).unwrap();

    // Build the delegation struct manually, then sign with wrong key
    let mut link = dis_core::delegation::Delegation {
        rp_id: "acme".into(),
        delegator_public_key: human_pk.clone(),
        delegate_public_key: agent_pk.clone(),
        scopes: vec!["doc:read".into()],
        resource_id: "doc:1".into(),
        action: "read".into(),
        issued_at: NOW,
        expires_at: NOW + 299,
        max_uses: None,
        requires_human_approval: false,
        signature: vec![],
    };
    sign_delegation(&mut link, &attacker_sk).unwrap(); // wrong sk

    let issued = rp.issue(base_request()).unwrap();
    let transcript = canonical_request(&issued).unwrap();
    let agent_proof = HolderProof {
        public_key: agent_pk,
        signature: sign_raw(&transcript, &agent_sk),
    };
    let delegated = DelegatedProof { chain: vec![link], agent_proof };
    assert_eq!(
        rp.verify_delegated(&issued, &delegated, NOW),
        Err(VerifyError::DelegationInvalid)
    );
}

// ── Attack 26: delegation — high-risk action without human approval ────────────

#[test]
fn attack_high_risk_no_approval() {
    let (human_pk, human_sk) = keypair();
    let (agent_pk, agent_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    rp.enroll_test_key(&human_pk).unwrap();

    let link = make_delegation(
        "acme", &human_pk, &human_sk, &agent_pk,
        vec!["doc:read".into()], "doc:1", "read",
        NOW, NOW + 299, None,
        true, // requires_human_approval
    ).unwrap();

    let issued = rp.issue(base_request()).unwrap();
    // No approve_challenge() called
    let transcript = canonical_request(&issued).unwrap();
    let agent_proof = HolderProof {
        public_key: agent_pk,
        signature: sign_raw(&transcript, &agent_sk),
    };
    let delegated = DelegatedProof { chain: vec![link], agent_proof };
    assert_eq!(
        rp.verify_delegated(&issued, &delegated, NOW),
        Err(VerifyError::HumanApprovalRequired)
    );
}

// ── Attack 27: delegation — max_uses exhausted ───────────────────────────────

#[test]
fn attack_delegation_uses_exhausted() {
    let (human_pk, human_sk) = keypair();
    let (agent_pk, agent_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    rp.enroll_test_key(&human_pk).unwrap();

    let link = make_delegation(
        "acme", &human_pk, &human_sk, &agent_pk,
        vec!["doc:read".into()], "doc:1", "read",
        NOW, NOW + 299, Some(1), // only 1 use allowed
        false,
    ).unwrap();

    // First use succeeds
    let issued1 = rp.issue(base_request()).unwrap();
    let t1 = canonical_request(&issued1).unwrap();
    let p1 = HolderProof { public_key: agent_pk.clone(), signature: sign_raw(&t1, &agent_sk) };
    let d1 = DelegatedProof { chain: vec![link.clone()], agent_proof: p1 };
    assert!(rp.verify_delegated(&issued1, &d1, NOW).is_ok());

    // Second use must fail
    let issued2 = rp.issue(base_request()).unwrap();
    let t2 = canonical_request(&issued2).unwrap();
    let p2 = HolderProof { public_key: agent_pk.clone(), signature: sign_raw(&t2, &agent_sk) };
    let d2 = DelegatedProof { chain: vec![link], agent_proof: p2 };
    assert_eq!(
        rp.verify_delegated(&issued2, &d2, NOW),
        Err(VerifyError::DelegationUsesExhausted)
    );
}

// ── Attack 28: delegation — agent key enrolled directly as holder ─────────────

#[test]
fn attack_agent_key_enrolled_directly() {
    // An agent key enrolled in enrolled_keys must still not bypass delegation
    // checks — the delegation chain itself must be valid.
    let (human_pk, human_sk) = keypair();
    let (agent_pk, agent_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    rp.enroll_test_key(&human_pk).unwrap();
    // Attacker also enrolls the agent key directly (e.g. via a separate session)
    rp.enroll_test_key(&agent_pk).unwrap();

    // Build delegation claiming human_pk as delegator but sign with human_sk;
    // however claim the delegator_public_key is agent_pk so sig verification fails
    let mut link = dis_core::delegation::Delegation {
        rp_id: "acme".into(),
        delegator_public_key: agent_pk.clone(), // wrong: claims self-delegation
        delegate_public_key: agent_pk.clone(),
        scopes: vec!["doc:read".into()],
        resource_id: "doc:1".into(),
        action: "read".into(),
        issued_at: NOW,
        expires_at: NOW + 299,
        max_uses: None,
        requires_human_approval: false,
        signature: vec![],
    };
    sign_delegation(&mut link, &human_sk).unwrap(); // sig is over delegator=agent_pk body

    let issued = rp.issue(base_request()).unwrap();
    let transcript = canonical_request(&issued).unwrap();
    let agent_proof = HolderProof {
        public_key: agent_pk,
        signature: sign_raw(&transcript, &agent_sk),
    };
    let delegated = DelegatedProof { chain: vec![link], agent_proof };
    // validate_chain checks: chain[0].delegator_public_key must be enrolled human key.
    // agent_pk IS enrolled, so chain[0].delegator = agent_pk passes enrollment check,
    // but sig verification: signed by human_sk over body containing agent_pk → won't verify.
    assert_eq!(
        rp.verify_delegated(&issued, &delegated, NOW),
        Err(VerifyError::DelegationInvalid)
    );
}

// ── Attack 29: delegation — scope widening between chain links ────────────────

#[test]
fn attack_delegation_scope_widening_mid_chain() {
    let (human_pk, human_sk) = keypair();
    let (agent1_pk, agent1_sk) = keypair();
    let (agent2_pk, agent2_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read"), ("doc:1", "write", "doc:write")]);
    rp.enroll_test_key(&human_pk).unwrap();

    // Human → agent1: read only
    let link1 = make_delegation(
        "acme", &human_pk, &human_sk, &agent1_pk,
        vec!["doc:read".into()], "doc:1", "read",
        NOW, NOW + 299, None, false,
    ).unwrap();

    // agent1 → agent2: claims write (wider than read — invalid)
    let link2 = make_delegation(
        "acme", &agent1_pk, &agent1_sk, &agent2_pk,
        vec!["doc:read".into(), "doc:write".into()], "doc:1", "write",
        NOW, NOW + 299, None, false,
    ).unwrap();

    let mut req = base_request();
    req.action = "write".into();
    req.scopes = vec!["doc:write".into()];
    let issued = rp.issue(req).unwrap();
    let transcript = canonical_request(&issued).unwrap();
    let agent_proof = HolderProof {
        public_key: agent2_pk,
        signature: sign_raw(&transcript, &agent2_sk),
    };
    let delegated = DelegatedProof { chain: vec![link1, link2], agent_proof };
    assert_eq!(
        rp.verify_delegated(&issued, &delegated, NOW),
        Err(VerifyError::DelegationInvalid)
    );
}

// ── Attack 30: stolen-device recovery — key revoked, new key works ────────────

#[test]
fn attack_stolen_device_key_revoked_new_enrolled() {
    let (stolen_pk, stolen_sk) = keypair();
    let (new_pk, new_sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);

    // Initial enrollment
    rp.enroll_test_key(&stolen_pk).unwrap();

    // Device stolen: revoke old key, enroll new key
    rp.rotate_key(&stolen_pk, &new_pk).unwrap();

    // Attacker with stolen device tries to use stolen_pk
    let issued = rp.issue(base_request()).unwrap();
    let bad_proof = valid_proof(&issued, &stolen_pk, &stolen_sk);
    assert_eq!(rp.verify(&issued, &bad_proof, NOW), Err(VerifyError::Revoked));

    // Legitimate owner with new key succeeds on a fresh challenge
    let issued2 = rp.issue(base_request()).unwrap();
    let good_proof = valid_proof(&issued2, &new_pk, &new_sk);
    assert!(rp.verify(&issued2, &good_proof, NOW).is_ok());
}

// ── Attack 31: operation_digest mismatch ──────────────────────────────────────

#[test]
fn attack_operation_digest_swap() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let mut req = base_request();
    req.operation_digest = Some([0xaa; 32]);
    let issued = enroll_and_issue(&mut rp, &pk, req);
    let proof = valid_proof(&issued, &pk, &sk);
    // Attacker swaps the operation_digest after signing
    let mut tampered = issued.clone();
    tampered.operation_digest = Some([0xbb; 32]);
    assert_eq!(rp.verify(&tampered, &proof, NOW), Err(VerifyError::Challenge));
}

// ── Attack 32: malformed public key in proof ──────────────────────────────────

#[test]
fn attack_malformed_public_key() {
    let (pk, sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let req = enroll_and_issue(&mut rp, &pk, base_request());
    let mut proof = valid_proof(&req, &pk, &sk);
    // Truncate the public key to make it unparseable
    proof.public_key.truncate(16);
    assert_eq!(rp.verify(&req, &proof, NOW), Err(VerifyError::Signature));
}

// ── Attack 33: policy_id mismatch ─────────────────────────────────────────────

#[test]
fn attack_wrong_policy_id() {
    let (pk, _sk) = keypair();
    let mut rp = rp(&[("doc:1", "read", "doc:read")]);
    let mut req = base_request();
    req.policy_id = "v2-draft".into();
    rp.enroll_test_key(&pk).unwrap();
    assert_eq!(rp.issue(req).unwrap_err(), VerifyError::Audience);
}

// ── Summary: all 33 attacks must never produce Ok(()) on verify ───────────────
//
// If this file ever has a test that passes verification, that is a security bug.
// grep -c "assert_eq!.*Err\|assert!(rp.verify.*is_ok" this file to audit.
