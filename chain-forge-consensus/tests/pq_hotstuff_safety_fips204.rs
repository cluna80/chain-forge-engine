//! The PQ-HotStuff-2 safety store with REAL FIPS 204 ML-DSA-65 (the `fips204` backend in chain-forge-crypto), through the
//! `Fips204Signer` / `Fips204Verifier` adapter. Keys are in memory only. The storage and counter are the same test doubles as
//! tests/pq_hotstuff_safety.rs (they are not trusted mechanisms); only the signature scheme is real here.
//!
//! The contexts are written out as literals below and checked against the crate's constants, so a wrong context in the crate
//! cannot be matched by the same wrong context in these tests.
//! Run: cargo test -p chain-forge-consensus --features pq-hotstuff-fips204 --test pq_hotstuff_safety_fips204
#![cfg(feature = "pq-hotstuff-fips204")]

#[path = "common/pq_safety_doubles.rs"]
mod doubles;

use chain_forge_consensus::pq_hotstuff::safety::*;
use chain_forge_consensus::pq_hotstuff::wire::*;
use fips204_crypto::fips204_backend::MlDsa65Fips204 as Raw;
use doubles::*;

const ALG: AlgId = AlgId::MLDSA65_FIPS204;
const CHAIN: &str = "qattice-pqhs2-dev";
const PROFILE: &str = "qattice-pq-hotstuff-2-v2";
const ID: [u8; 16] = [9; 16];
const CTXS: [(&str, &[u8]); 3] = [("vote", b"qattice/vote/v2"), ("timeout", b"qattice/timeout/v2"), ("proposal", b"qattice/proposal/v2")];

type Store = SafetyStore<MemStorage, TestCounter>;

fn vote(round: u64, b: u8) -> VoteMessage {
    VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 1, round, block_id: [b; 32], parent_id: [0x22; 32], parent_round: round - 1 }
}
fn timeout(round: u64) -> TimeoutMessage { TimeoutMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 1, round, high_qc_round: round - 1 } }
fn proposal(b: u8) -> BlockSigningMessage { BlockSigningMessage { alg_id: ALG, block_id: [b; 32] } }

fn signer(seed: u8) -> Fips204Signer { Fips204Signer::from_seed(&[seed; 32]) }

fn init(signer: &Fips204Signer) -> Store {
    let f = faults();
    let init = FreshInit { protocol_profile: PROFILE, chain_id: CHAIN, public_key: signer.public_key(), instance_id: ID, epoch: 1 };
    SafetyStore::initialize_fresh(MemStorage::new(f.clone()), TestCounter::new(f), &init, &ParticipationEvidence::default()).expect("initialize")
}

fn open(st: &MemStorage, ctr: &TestCounter, pk: &[u8]) -> Result<Store, OpenError> {
    let exp = Expected { protocol_profile: PROFILE, chain_id: CHAIN, public_key: pk };
    SafetyStore::open(st.clone(), ctr.clone(), &exp, &Fips204Verifier, &ParticipationEvidence::default())
}

/// a store with a vote, a timeout and a proposal signed at round 5
fn prior(signer: &mut Fips204Signer) -> Store {
    let mut s = init(signer);
    s.sign_vote(&vote(5, 1), 4, signer).unwrap();
    s.sign_timeout(&timeout(5), signer).unwrap();
    s.sign_proposal(1, 5, &proposal(1), signer).unwrap();
    s
}

#[test]
fn the_crate_contexts_are_exactly_the_approved_strings() {
    assert_eq!(CTX_VOTE, CTXS[0].1);
    assert_eq!(CTX_TIMEOUT, CTXS[1].1);
    assert_eq!(CTX_PROPOSAL, CTXS[2].1);
}

#[test]
fn keys_are_real_ml_dsa_65_sizes_and_come_from_the_seed_deterministically() {
    let a = signer(1);
    let b = signer(1);
    let c = signer(2);
    assert_eq!(a.public_key().len(), 1952);
    assert_eq!(a.public_key(), b.public_key(), "same seed, same key");
    assert_ne!(a.public_key(), c.public_key());
    // the key is a valid FIPS 204 public key: a signature made with the raw backend under it verifies
    let g = Fips204Signer::generate().expect("OS RNG");
    assert_eq!(g.public_key().len(), 1952);
    assert_ne!(g.public_key(), a.public_key());
}

#[test]
fn signatures_through_the_store_are_real_fips_204_signatures_in_the_right_context() {
    let mut s0 = signer(1);
    let pk = s0.public_key().to_vec();
    let mut s = init(&s0);
    let v = s.sign_vote(&vote(3, 7), 2, &mut s0).unwrap();
    let t = s.sign_timeout(&timeout(3), &mut s0).unwrap();
    let p = s.sign_proposal(1, 3, &proposal(7), &mut s0).unwrap();
    for (name, out, ctx) in [("vote", &v, CTXS[0].1), ("timeout", &t, CTXS[1].1), ("proposal", &p, CTXS[2].1)] {
        assert_eq!(out.envelope.signature.len(), 3309, "{name}");
        // verified by the raw backend directly, with the literal approved context
        assert!(Raw::verify(&pk, &out.message, &out.envelope.signature, ctx).is_ok(), "{name} must verify in its own context");
        // and in no other context
        for (other, octx) in CTXS {
            if octx != ctx {
                assert!(Raw::verify(&pk, &out.message, &out.envelope.signature, octx).is_err(), "{name} signature must not verify as {other}");
            }
        }
        // nor under another key, nor over another message
        assert!(Raw::verify(signer(2).public_key(), &out.message, &out.envelope.signature, ctx).is_err(), "{name}: wrong key");
        let mut m2 = out.message.clone();
        *m2.last_mut().unwrap() ^= 1;
        assert!(Raw::verify(&pk, &m2, &out.envelope.signature, ctx).is_err(), "{name}: wrong message");
    }
}

#[test]
fn a_store_reopened_with_the_real_verifier_accepts_real_signatures_and_re_sends_them_byte_for_byte() {
    let mut s0 = signer(1);
    let pk = s0.public_key().to_vec();
    let (st, ctr) = prior(&mut s0).into_parts();
    let mut s = open(&st, &ctr, &pk).expect("real signatures verify on open");
    let before = s.record().last_vote.clone().unwrap();
    let again = s.sign_vote(&vote(5, 1), 4, &mut s0).unwrap();
    assert!(again.resent);
    assert_eq!(again.envelope.encode().unwrap(), before.envelope.encode().unwrap(), "byte-for-byte");
    // a different message for the same round is refused; the real signer is not asked
    assert!(matches!(s.sign_vote(&vote(5, 2), 4, &mut s0).unwrap_err(), SignError::ConflictingMessage { round: 5, .. }));
}

#[test]
fn real_signing_is_hedged_two_signatures_over_one_message_differ_and_both_verify() {
    let mut s0 = signer(1);
    let pk = s0.public_key().to_vec();
    let mut a = init(&s0);
    let mut b = init(&s0);
    let x = a.sign_vote(&vote(3, 7), 2, &mut s0).unwrap();
    let y = b.sign_vote(&vote(3, 7), 2, &mut s0).unwrap();
    assert_eq!(x.message, y.message);
    assert_ne!(x.envelope.signature, y.envelope.signature, "hedged: fresh randomness each time");
    for o in [&x, &y] { assert!(Raw::verify(&pk, &o.message, &o.envelope.signature, CTXS[0].1).is_ok()); }
}

#[test]
fn a_tampered_stored_signature_is_refused_on_open_by_the_real_verifier() {
    let mut s0 = signer(1);
    let pk = s0.public_key().to_vec();
    let (st, ctr) = prior(&mut s0).into_parts();
    for which in ["vote", "timeout", "proposal"] {
        let mut r = decode_record(&st.raw(STATE_FILE).unwrap()).unwrap();
        let item = match which { "vote" => r.last_vote.as_mut(), "timeout" => r.last_timeout.as_mut(), _ => r.last_proposal.as_mut() }.unwrap();
        item.envelope.signature[1000] ^= 1;
        let mut st2 = st.clone();
        st2.set_raw(STATE_FILE, encode_record(&r).unwrap());
        assert_eq!(open(&st2, &ctr, &pk).err().unwrap(), OpenError::BadSignature { kind: match which { "vote" => "vote", "timeout" => "timeout", _ => "proposal" } }, "{which}");
    }
}

#[test]
fn a_garbage_signature_and_a_signature_from_another_key_or_domain_are_refused_on_open() {
    let mut s0 = signer(1);
    let pk = s0.public_key().to_vec();
    let (st, ctr) = prior(&mut s0).into_parts();
    let swap = |f: &dyn Fn(&mut SafetyRecord)| {
        let mut r = decode_record(&st.raw(STATE_FILE).unwrap()).unwrap();
        f(&mut r);
        let mut st2 = st.clone();
        st2.set_raw(STATE_FILE, encode_record(&r).unwrap());
        open(&st2, &ctr, &pk).err().unwrap()
    };
    let garbage: Vec<u8> = (0..3309).map(|i| (i % 251) as u8).collect();
    assert_eq!(swap(&|r| r.last_vote.as_mut().unwrap().envelope.signature = garbage.clone()), OpenError::BadSignature { kind: "vote" });
    // a genuine signature by ANOTHER key over the same message
    let mut other = signer(2);
    let forged = other.sign(CTXS[0].1, &r_msg(&st, "vote")).unwrap();
    assert_eq!(swap(&|r| r.last_vote.as_mut().unwrap().envelope.signature = forged.clone()), OpenError::BadSignature { kind: "vote" });
    // the genuine timeout signature placed on the vote slot (wrong domain)
    assert_eq!(swap(&|r| { let t = r.last_timeout.clone().unwrap(); r.last_vote.as_mut().unwrap().envelope = t.envelope; }), OpenError::BadSignature { kind: "vote" });
}

fn r_msg(st: &MemStorage, which: &str) -> Vec<u8> {
    let r = decode_record(&st.raw(STATE_FILE).unwrap()).unwrap();
    match which { "vote" => r.last_vote.unwrap().message, "timeout" => r.last_timeout.unwrap().message, _ => r.last_proposal.unwrap().message }
}

#[test]
fn the_store_refuses_a_real_signer_whose_key_is_not_the_records_key() {
    let mut s0 = signer(1);
    let mut s = init(&s0);
    let mut other = signer(2);
    assert_eq!(s.sign_vote(&vote(3, 7), 2, &mut other).unwrap_err(), SignError::IdentityMismatch("signer key"));
    s.sign_vote(&vote(3, 7), 2, &mut s0).expect("the right key works");
}

#[test]
fn the_signer_debug_output_never_contains_key_material() {
    let s = signer(1);
    let text = format!("{s:?}");
    assert!(text.contains("redacted"), "{text}");
    assert!(text.len() < 120, "debug output must be short, not a key dump: {text}");
}

#[test]
fn the_verifier_never_panics_on_malformed_input_and_rejects_it() {
    let v = Fips204Verifier;
    let mut s = signer(1);
    // positive control, so that "rejects" below cannot pass just because the verifier rejects everything
    let good = s.sign(b"qattice/vote/v2", b"m").expect("sign");
    assert!(v.verify(s.public_key(), b"qattice/vote/v2", b"m", &good), "a genuine signature must verify");
    assert!(!v.verify(s.public_key(), b"qattice/timeout/v2", b"m", &good), "but not in another context");
    let sig = vec![0u8; 3309];
    assert!(!v.verify(&[], b"qattice/vote/v2", b"m", &sig));
    assert!(!v.verify(&vec![0u8; 1952], b"qattice/vote/v2", b"m", &sig), "an all-zero public key");
    assert!(!v.verify(s.public_key(), b"qattice/vote/v2", b"m", &sig[..3308]));
    assert!(!v.verify(s.public_key(), b"qattice/vote/v2", b"m", &[]));
    assert!(!v.verify(s.public_key(), &vec![b'x'; 256], b"m", &sig), "a context over 255 bytes");
    assert!(!v.verify(s.public_key(), b"qattice/vote/v2", b"m", &sig));
}

#[test]
fn a_crash_at_any_step_with_real_signatures_reopens_and_never_allows_a_second_vote_for_the_round() {
    for crash_before in 0..=5usize {
        let mut s0 = signer(1);
        let pk = s0.public_key().to_vec();
        let mut s = prior(&mut s0);
        // the doubles' fault plan is shared by the store's storage and counter
        let (st0, ctr0) = s.into_parts();
        let plan = st0.faults.clone();
        {
            let mut f = plan.borrow_mut();
            f.ops = 0;
            f.log.clear();
            f.crash_before = Some(crash_before);
        }
        s = open(&st0, &ctr0, &pk).unwrap();
        // `open` does not touch the five commit steps; reset the counter of operations anyway
        plan.borrow_mut().ops = 0;
        let first = s.sign_vote(&vote(6, 1), 5, &mut s0);
        assert_eq!(first.is_ok(), crash_before == 5, "crash before op {crash_before}");
        let (st, ctr) = s.into_parts();
        for (n, o) in st.crash_outcomes(1009).iter().enumerate() {
            let ctx = format!("crash before op {crash_before} / outcome {n}");
            let c = TestCounter::with_value(ctr.value, o.faults.clone());
            let mut s2 = open(o, &c, &pk).unwrap_or_else(|e| panic!("{ctx}: does not reopen: {e}"));
            let durable = s2.record().last_vote.clone().unwrap();
            if durable.round == 6 {
                assert!(matches!(s2.sign_vote(&vote(6, 2), 5, &mut s0).unwrap_err(), SignError::ConflictingMessage { round: 6, .. }), "{ctx}");
                let again = s2.sign_vote(&vote(6, 1), 5, &mut s0).unwrap();
                assert_eq!(again.envelope.encode().unwrap(), durable.envelope.encode().unwrap(), "{ctx}");
                assert!(Raw::verify(&pk, &again.message, &again.envelope.signature, CTXS[0].1).is_ok(), "{ctx}: the re-sent signature is a valid ML-DSA-65 signature");
            } else {
                assert!(first.is_err(), "{ctx}: a signature was returned but is not durable");
                s2.sign_vote(&vote(6, 2), 5, &mut s0).unwrap_or_else(|e| panic!("{ctx}: cannot continue: {e}"));
            }
        }
    }
}
