//! Demo: ValidatorSetView workspace boundary + ML-DSA governance votes.
use chain_forge_consensus::{ValidatorInfo, ValidatorSet};
use chain_forge_crypto::{MlDsaScheme, SignatureScheme};
use chain_forge_personhood::{
    governance_vote_signing_bytes, AuthorizedIssuerRegistry, AuthzError, GovernanceVote,
    ValidatorId,
};

fn make_validator_set(count: usize) -> (ValidatorSet, Vec<chain_forge_crypto::KeyPair>) {
    let scheme = MlDsaScheme;
    let mut validators = Vec::with_capacity(count);
    let mut keypairs   = Vec::with_capacity(count);
    for i in 0..count {
        let kp = scheme.generate_keypair(&format!("demo-seed-val-{i:02}")).expect("keygen");
        let cons_id = chain_forge_consensus::ValidatorId(format!("val_{i}"));
        validators.push(ValidatorInfo {
            id: cons_id, voting_power: 1, pop_verified: true,
            public_key: kp.public_key.clone(),
        });
        keypairs.push(kp);
    }
    (ValidatorSet { height: 0, validators }, keypairs)
}

/// Build the same context bytes that propose_change_with_votes uses internally:
/// sorted existing IDs as big-endian u32s, then the new issuer name.
fn propose_ctx(reg: &AuthorizedIssuerRegistry, new_name: &str) -> Vec<u8> {
    let mut ctx = Vec::new();
    let mut ids: Vec<u32> = reg.issuers().keys().copied().collect();
    ids.sort();
    for id in ids {
        ctx.extend_from_slice(&id.to_be_bytes());
    }
    ctx.extend_from_slice(new_name.as_bytes());
    ctx
}

fn signed_vote(idx: usize, keypairs: &[chain_forge_crypto::KeyPair], signing_msg: &[u8]) -> GovernanceVote {
    let kp  = &keypairs[idx];
    let sig = MlDsaScheme.sign(signing_msg, kp).expect("sign").bytes;
    GovernanceVote {
        voter:      ValidatorId(format!("val_{idx}")),
        signature:  sig,
        public_key: kp.public_key.clone(),
    }
}

fn main() {
    let (vs, kps) = make_validator_set(7);
    let quorum = chain_forge_personhood::revocation_quorum_power(&vs);
    println!("Validator set: {} validators, total power = {}, quorum = {}",
        vs.validators.len(), vs.validators.len() as u64, quorum);
    println!();

    let mut reg = AuthorizedIssuerRegistry::new();
    let mut checks_passed = 0usize;

    // 1: 5-of-7 passes — registry empty, context = b"Issuer Alpha"
    let ctx1 = propose_ctx(&reg, "Issuer Alpha");
    let msg1 = governance_vote_signing_bytes(b"propose_change", &ctx1);
    let five: Vec<_> = (0..5).map(|i| signed_vote(i, &kps, &msg1)).collect();
    match reg.propose_change_with_votes("Issuer Alpha", &vs, &five) {
        Ok(id) => { println!("[1] PASS  5-of-7 -> issuer registered (id={id})"); checks_passed += 1; }
        Err(e) => println!("[1] FAIL  {e}"),
    }

    // 2: 3-of-7 fails — registry has {0}, context = 0u32_BE ++ b"Issuer Beta"
    let ctx2 = propose_ctx(&reg, "Issuer Beta");
    let msg2 = governance_vote_signing_bytes(b"propose_change", &ctx2);
    let three: Vec<_> = (0..3).map(|i| signed_vote(i, &kps, &msg2)).collect();
    match reg.propose_change_with_votes("Issuer Beta", &vs, &three) {
        Err(AuthzError::QuorumNotMet { needed, have }) => {
            println!("[2] PASS  3-of-7 rejected (need {needed}, have {have})"); checks_passed += 1;
        }
        other => println!("[2] FAIL  {other:?}"),
    }

    // 3: second issuer — registry still has {0}, context = 0u32_BE ++ b"Issuer Beta"
    let ctx3 = propose_ctx(&reg, "Issuer Beta");
    let msg3 = governance_vote_signing_bytes(b"propose_change", &ctx3);
    let five3: Vec<_> = (0..5).map(|i| signed_vote(i, &kps, &msg3)).collect();
    match reg.propose_change_with_votes("Issuer Beta", &vs, &five3) {
        Ok(id) => { println!("[3] PASS  Second issuer registered (id={id})"); checks_passed += 1; }
        Err(e) => println!("[3] FAIL  {e}"),
    }
    println!("      Registry: {:?}", reg.issuers().keys().collect::<Vec<_>>());
    println!();

    // 4: revoke issuer 0 — context = 0u32_BE
    let msg4 = governance_vote_signing_bytes(b"revoke_immediately", &0u32.to_be_bytes());
    let five4: Vec<_> = (0..5).map(|i| signed_vote(i, &kps, &msg4)).collect();
    match reg.revoke_with_votes(0, &vs, &five4) {
        Ok(()) => { println!("[4] PASS  Issuer 0 revoked"); checks_passed += 1; }
        Err(e) => println!("[4] FAIL  {e}"),
    }

    // 5: revoke nonexistent 99
    let msg5 = governance_vote_signing_bytes(b"revoke_immediately", &99u32.to_be_bytes());
    let five5: Vec<_> = (0..5).map(|i| signed_vote(i, &kps, &msg5)).collect();
    match reg.revoke_with_votes(99, &vs, &five5) {
        Err(AuthzError::IssuerNotFound(id)) => {
            println!("[5] PASS  IssuerNotFound({id})"); checks_passed += 1;
        }
        other => println!("[5] FAIL  {other:?}"),
    }

    // 6: duplicate voter — registry has {1}, context = 1u32_BE ++ b"Issuer Gamma"
    let ctx6 = propose_ctx(&reg, "Issuer Gamma");
    let msg6 = governance_vote_signing_bytes(b"propose_change", &ctx6);
    let v0 = signed_vote(0, &kps, &msg6);
    match reg.propose_change_with_votes("Issuer Gamma", &vs, &[v0.clone(), v0]) {
        Err(AuthzError::DuplicateVoter(id)) => {
            println!("[6] PASS  DuplicateVoter({id})"); checks_passed += 1;
        }
        other => println!("[6] FAIL  {other:?}"),
    }

    // 7: unknown voter — registry has {1}, context = 1u32_BE ++ b"Issuer Delta"
    let outsider_kp = MlDsaScheme.generate_keypair("outsider-seed").unwrap();
    let ctx7 = propose_ctx(&reg, "Issuer Delta");
    let msg7 = governance_vote_signing_bytes(b"propose_change", &ctx7);
    let outsider_sig = MlDsaScheme.sign(&msg7, &outsider_kp).unwrap().bytes;
    let bad_vote = GovernanceVote {
        voter:      ValidatorId("outsider".into()),
        signature:  outsider_sig,
        public_key: outsider_kp.public_key.clone(),
    };
    match reg.propose_change_with_votes("Issuer Delta", &vs, &[bad_vote]) {
        Err(AuthzError::UnknownVoter(id)) => {
            println!("[7] PASS  UnknownVoter({id})"); checks_passed += 1;
        }
        other => println!("[7] FAIL  {other:?}"),
    }

    println!();
    println!("Registry final state: {:?}", reg.issuers());
    println!();
    if checks_passed == 7 {
        println!("All {checks_passed}/7 checks passed");
    } else {
        println!("{checks_passed}/7 checks passed");
        std::process::exit(1);
    }
}