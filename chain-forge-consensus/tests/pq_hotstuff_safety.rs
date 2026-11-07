//! PQ-HotStuff-2 safety-state persistence (spec section 7, Phase 1 step 1): fail-closed opening, exact message and envelope
//! persistence, crash and fault injection at every step, rollback detection through a trusted counter.
//!
//! The doubles in tests/common/pq_safety_doubles.rs are NOT trusted mechanisms. The golden record digests come from an
//! independent oracle (tests/vectors/gen_pq_hotstuff_safety_vectors.py).
//! Run: cargo test -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_safety
#![cfg(feature = "pq-hotstuff")]

#[path = "common/pq_safety_doubles.rs"]
mod doubles;

use chain_forge_consensus::pq_hotstuff::safety::*;
use chain_forge_consensus::pq_hotstuff::wire::*;
use doubles::*;
use sha3::{Digest, Sha3_256};

const ALG: AlgId = AlgId::MLDSA65_FIPS204;
const CHAIN: &str = "qattice-pqhs2-dev";
const PROFILE: &str = "qattice-pq-hotstuff-2-v2";
const ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

type Store = SafetyStore<MemStorage, TestCounter>;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn digest(b: &[u8]) -> String { hex(&Sha3_256::digest(b)) }

// ---------------------------------------------------------------- messages and requests

fn vote(epoch: u64, round: u64, b: u8) -> VoteMessage {
    VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch, round, block_id: [b; 32], parent_id: [0x22; 32], parent_round: round.saturating_sub(1) }
}
fn timeout(epoch: u64, round: u64, hq: u64) -> TimeoutMessage { TimeoutMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch, round, high_qc_round: hq } }
fn proposal(b: u8) -> BlockSigningMessage { BlockSigningMessage { alg_id: ALG, block_id: [b; 32] } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum K { Vote, Timeout, Proposal }
const ALL_KINDS: [K; 3] = [K::Vote, K::Timeout, K::Proposal];

fn kind(k: K) -> Kind { match k { K::Vote => Kind::Vote, K::Timeout => Kind::Timeout, K::Proposal => Kind::Proposal } }

fn do_sign(store: &mut Store, s: &mut TestSigner, k: K, epoch: u64, round: u64, v: u8) -> Result<Signed, SignError> {
    match k {
        K::Vote => store.sign_vote(&vote(epoch, round, v), round.saturating_sub(1), s),
        K::Timeout => store.sign_timeout(&timeout(epoch, round, v as u64), s),
        K::Proposal => store.sign_proposal(epoch, round, &proposal(v), s),
    }
}

fn message_bytes(k: K, epoch: u64, round: u64, v: u8) -> Vec<u8> {
    match k {
        K::Vote => vote(epoch, round, v).encode().unwrap(),
        K::Timeout => timeout(epoch, round, v as u64).encode().unwrap(),
        K::Proposal => proposal(v).encode().unwrap(),
    }
}

fn slot(rec: &SafetyRecord, k: K) -> Option<&SignedItem> { rec.slot(kind(k)) }

// ---------------------------------------------------------------- the world

struct World { st: MemStorage, ctr: TestCounter, f: Shared, signer: TestSigner, pk: Vec<u8> }

impl World {
    fn new() -> World {
        let f = faults();
        World { st: MemStorage::new(f.clone()), ctr: TestCounter::new(f.clone()), f, signer: TestSigner::new(1), pk: test_public_key(1) }
    }
    fn fresh_init(&self) -> FreshInit<'_> { FreshInit { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &self.pk, instance_id: ID, epoch: 1 } }
    fn init(&self) -> Store {
        Store::initialize_fresh(self.st.clone(), self.ctr.clone(), &self.fresh_init(), &ParticipationEvidence::default()).expect("initialize")
    }
    fn expected(&self) -> Expected<'_> { Expected { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &self.pk } }
    fn open(&self, st: &MemStorage, ctr: &TestCounter) -> Result<Store, OpenError> { self.open_ev(st, ctr, ParticipationEvidence::default()) }
    fn open_ev(&self, st: &MemStorage, ctr: &TestCounter, ev: ParticipationEvidence) -> Result<Store, OpenError> {
        Store::open(st.clone(), ctr.clone(), &self.expected(), &TestVerifier, &ev)
    }
    /// initialized and with a vote, a timeout and a proposal signed at round 5 (epoch 1): Active, counter 4, hvr 5
    fn prior(&mut self) -> Store {
        let mut s = self.init();
        for k in [K::Vote, K::Timeout, K::Proposal] { do_sign(&mut s, &mut self.signer, k, 1, 5, 1).expect("prior signature"); }
        s
    }
    fn reset_plan(&self) { let mut f = self.f.borrow_mut(); f.ops = 0; f.log.clear(); f.crash_before = None; f.fail_at = None; }
}

fn open_err(w: &World, st: &MemStorage, ctr: &TestCounter) -> OpenError { w.open(st, ctr).err().expect("must not open") }

/// The counter state a trusted counter would hold if the state file in `st` were the latest committed record.
fn committed_state(st: &MemStorage) -> CounterState {
    let b = st.raw(STATE_FILE).expect("state file");
    let r = decode_record(&b).expect("decode");
    CounterState { value: r.counter, digest: b[b.len() - 32..].try_into().unwrap() }
}
/// A counter equal to the file (as after a completed commit).
fn counter_at_file(st: &MemStorage, f: Shared) -> TestCounter { TestCounter::with_state(committed_state(st), f) }
/// A counter one behind the file, holding the digest of the file's predecessor (as in the window after the file is durable and
/// before the counter advance).
fn counter_before_file(st: &MemStorage, f: Shared) -> TestCounter {
    let r = decode_record(&st.raw(STATE_FILE).unwrap()).unwrap();
    TestCounter::with_state(CounterState { value: r.counter - 1, digest: r.prev_digest }, f)
}
/// Open as if this (possibly tampered) file were the committed record, to test the content checks on their own.
fn open_err_committed(w: &World, st: &MemStorage) -> OpenError { open_err(w, st, &counter_at_file(st, w.f.clone())) }

// ================================================================ explicit initialization

#[test]
fn initialization_is_explicit_and_the_fresh_state_is_distinguishable() {
    let w = World::new();
    let s = w.init();
    let r = s.record();
    assert_eq!(r.state, State::Fresh);
    assert!(r.hvr.is_none() && r.hqr.is_none() && r.last_vote.is_none() && r.last_timeout.is_none() && r.last_proposal.is_none());
    assert_eq!((r.counter, r.epoch), (1, 1));
    let (st, ctr) = s.into_parts();
    assert_eq!(ctr.value, 1);
    assert!(st.raw(STATE_FILE).is_some() && st.raw(MARKER_FILE).is_some());
    assert_eq!(w.open(&st, &ctr).unwrap().record().state, State::Fresh);
}

#[test]
fn the_first_signature_moves_fresh_to_active_in_the_same_commit() {
    let mut w = World::new();
    let mut s = w.init();
    do_sign(&mut s, &mut w.signer, K::Vote, 1, 1, 7).unwrap();
    assert_eq!(s.record().state, State::Active);
    let (st, ctr) = s.into_parts();
    assert_eq!(w.open(&st, &ctr).unwrap().record().state, State::Active);
}

#[test]
fn open_never_creates_state() {
    let w = World::new();
    let st = MemStorage::new(w.f.clone());
    assert_eq!(open_err(&w, &st, &w.ctr), OpenError::NoState);
    assert!(st.is_empty(), "open must not write anything");
    assert_eq!(w.f.borrow().ops, 0);
}

#[test]
fn initialization_is_refused_when_state_or_a_marker_already_exists() {
    let w = World::new();
    let (st, ctr) = w.init().into_parts();
    let e = Store::initialize_fresh(st.clone(), ctr.clone(), &w.fresh_init(), &ParticipationEvidence::default()).err().unwrap();
    assert_eq!(e, InitError::AlreadyInitialized, "state and marker present");
    let mut marker_only = st.clone();
    marker_only.delete_raw(STATE_FILE);
    let e = Store::initialize_fresh(marker_only, ctr, &w.fresh_init(), &ParticipationEvidence::default()).err().unwrap();
    assert_eq!(e, InitError::AlreadyInitialized, "marker present, state gone");
}

#[test]
fn initialization_is_refused_when_the_trusted_counter_shows_the_identity_was_used() {
    // both files deleted after use: the file side shows nothing, the trusted counter still remembers
    let mut w = World::new();
    let (_, ctr) = w.prior().into_parts();
    assert!(ctr.value > 0);
    let empty = MemStorage::new(w.f.clone());
    let e = Store::initialize_fresh(empty.clone(), ctr.clone(), &w.fresh_init(), &ParticipationEvidence::default()).err().unwrap();
    assert_eq!(e, InitError::CounterNotZero(ctr.value));
    assert!(empty.is_empty());
}

#[test]
fn initialization_is_refused_for_a_counter_at_zero_that_already_holds_a_digest() {
    let w = World::new();
    let c = TestCounter::with_state(CounterState { value: 0, digest: [7; 32] }, w.f.clone());
    let e = Store::initialize_fresh(w.st.clone(), c, &w.fresh_init(), &ParticipationEvidence::default()).err().unwrap();
    assert!(matches!(e, InitError::Counter(_)), "{e:?}");
    assert!(w.st.is_empty(), "nothing may be written");
}

#[test]
fn a_key_that_already_participated_cannot_be_initialized_fresh() {
    let w = World::new();
    let e = Store::initialize_fresh(w.st.clone(), w.ctr.clone(), &w.fresh_init(), &ParticipationEvidence { highest_signed: Some((1, 0)) }).err().unwrap();
    assert_eq!(e, InitError::KeyAlreadyParticipated);
    assert!(w.st.is_empty());
}

#[test]
fn initialization_rejects_a_malformed_identity() {
    let w = World::new();
    let short = vec![1u8; 1951];
    let bad_key = FreshInit { public_key: &short, ..w.fresh_init() };
    assert!(matches!(Store::initialize_fresh(w.st.clone(), w.ctr.clone(), &bad_key, &ParticipationEvidence::default()), Err(InitError::BadIdentity(_))));
    let bad_profile = FreshInit { protocol_profile: "", ..w.fresh_init() };
    assert!(matches!(Store::initialize_fresh(w.st.clone(), w.ctr.clone(), &bad_profile, &ParticipationEvidence::default()), Err(InitError::BadIdentity(_))));
    assert!(w.st.is_empty());
}

// ================================================================ exact persistence and byte-for-byte re-send

#[test]
fn the_exact_canonical_message_and_envelope_are_persisted_for_every_kind() {
    for k in ALL_KINDS {
        let mut w = World::new();
        let mut s = w.init();
        let out = do_sign(&mut s, &mut w.signer, k, 1, 3, 9).unwrap();
        assert!(!out.resent);
        assert_eq!(out.message, message_bytes(k, 1, 3, 9));
        let (st, ctr) = s.into_parts();
        let s2 = w.open(&st, &ctr).unwrap();
        let item = slot(s2.record(), k).expect("slot");
        assert_eq!(item.round, 3);
        assert_eq!(item.message, out.message, "{k:?} message");
        assert_eq!(item.envelope.encode().unwrap(), out.envelope.encode().unwrap(), "{k:?} envelope");
    }
}

#[test]
fn a_restart_re_sends_the_stored_signature_byte_for_byte_and_never_re_signs() {
    for k in ALL_KINDS {
        let mut w = World::new();
        let mut s = w.init();
        let first = do_sign(&mut s, &mut w.signer, k, 1, 3, 9).unwrap();
        let calls = w.signer.calls;
        let (st, ctr) = s.into_parts();
        let mut s2 = w.open(&st, &ctr).unwrap();
        let again = do_sign(&mut s2, &mut w.signer, k, 1, 3, 9).unwrap();
        assert!(again.resent, "{k:?}");
        assert_eq!(again.message, first.message);
        assert_eq!(again.envelope.encode().unwrap(), first.envelope.encode().unwrap(), "{k:?}: byte-for-byte");
        assert_eq!(w.signer.calls, calls, "{k:?}: the signer must not be called for a re-send");
        // and within one session too
        let mut s3 = w.open(&st, &ctr).unwrap();
        let third = do_sign(&mut s3, &mut w.signer, k, 1, 3, 9).unwrap();
        assert_eq!(third.envelope.encode().unwrap(), first.envelope.encode().unwrap());
    }
}

#[test]
fn hedged_signing_really_differs_so_a_re_sign_would_be_visible() {
    let mut w = World::new();
    let mut s = w.init();
    let a = do_sign(&mut s, &mut w.signer, K::Vote, 1, 3, 9).unwrap();
    let mut s2 = w.init_other();
    let b = do_sign(&mut s2, &mut w.signer, K::Vote, 1, 3, 9).unwrap();
    assert_ne!(a.envelope.signature, b.envelope.signature, "the test signer is hedged");
}

impl World {
    fn init_other(&self) -> Store {
        let f = faults();
        Store::initialize_fresh(MemStorage::new(f.clone()), TestCounter::new(f), &self.fresh_init(), &ParticipationEvidence::default()).unwrap()
    }
}

// ================================================================ one message per (kind, round); floors; epochs

#[test]
fn a_different_message_for_a_round_already_signed_is_refused_even_after_a_restart() {
    for k in ALL_KINDS {
        let mut w = World::new();
        let mut s = w.init();
        do_sign(&mut s, &mut w.signer, k, 1, 3, 1).unwrap();
        let calls = w.signer.calls;
        let e = do_sign(&mut s, &mut w.signer, k, 1, 3, 2).unwrap_err();
        assert!(matches!(e, SignError::ConflictingMessage { round: 3, .. }), "{k:?}: {e:?}");
        let (st, ctr) = s.into_parts();
        let mut s2 = w.open(&st, &ctr).unwrap();
        let e = do_sign(&mut s2, &mut w.signer, k, 1, 3, 2).unwrap_err();
        assert!(matches!(e, SignError::ConflictingMessage { round: 3, .. }), "{k:?} after restart: {e:?}");
        assert_eq!(w.signer.calls, calls, "a refused request must not reach the signer");
        assert!(!s2.is_latched(), "a refusal is not a failure");
    }
}

#[test]
fn a_round_below_one_already_signed_is_refused() {
    for k in ALL_KINDS {
        let mut w = World::new();
        let mut s = w.init();
        do_sign(&mut s, &mut w.signer, k, 1, 5, 1).unwrap();
        let e = do_sign(&mut s, &mut w.signer, k, 1, 4, 1).unwrap_err();
        assert!(matches!(e, SignError::RoundBelowSigned { signed: 5, requested: 4, .. }), "{k:?}: {e:?}");
    }
}

#[test]
fn a_vote_then_a_timeout_in_the_same_round_is_allowed_but_not_the_reverse() {
    let mut w = World::new();
    let mut s = w.init();
    do_sign(&mut s, &mut w.signer, K::Vote, 1, 4, 1).unwrap();
    do_sign(&mut s, &mut w.signer, K::Timeout, 1, 4, 1).expect("timeout in the round already voted in");
    let mut w2 = World::new();
    let mut s2 = w2.init();
    do_sign(&mut s2, &mut w2.signer, K::Timeout, 1, 4, 1).unwrap();
    let e = do_sign(&mut s2, &mut w2.signer, K::Vote, 1, 4, 1).unwrap_err();
    assert!(matches!(e, SignError::FloorViolation { kind: "vote", round: 4, floor: 4 }), "{e:?}");
}

#[test]
fn a_timeout_at_a_higher_round_raises_the_floor_for_votes_and_timeouts() {
    let mut w = World::new();
    let mut s = w.init();
    do_sign(&mut s, &mut w.signer, K::Timeout, 1, 9, 1).unwrap();
    assert_eq!(s.record().hvr, Some(9));
    let e = do_sign(&mut s, &mut w.signer, K::Vote, 1, 8, 1).unwrap_err();
    assert!(matches!(e, SignError::FloorViolation { kind: "vote", .. }), "{e:?}");
    let e = do_sign(&mut s, &mut w.signer, K::Timeout, 1, 8, 1).unwrap_err();
    assert!(matches!(e, SignError::RoundBelowSigned { .. } | SignError::FloorViolation { .. }), "{e:?}");
    do_sign(&mut s, &mut w.signer, K::Vote, 1, 10, 1).expect("above the floor");
}

#[test]
fn a_timeout_below_the_round_already_voted_in_is_refused_by_the_floor() {
    let mut w = World::new();
    let mut s = w.init();
    do_sign(&mut s, &mut w.signer, K::Vote, 1, 9, 1).unwrap();
    let e = do_sign(&mut s, &mut w.signer, K::Timeout, 1, 8, 1).unwrap_err();
    assert_eq!(e, SignError::FloorViolation { kind: "timeout", round: 8, floor: 9 });
    do_sign(&mut s, &mut w.signer, K::Timeout, 1, 9, 1).expect("the same round is allowed after a vote");
}

#[test]
fn a_signer_holding_a_different_key_is_refused_without_writing_or_latching() {
    let mut w = World::new();
    let mut s = w.prior();
    let ops = w.f.borrow().ops;
    let mut other = TestSigner::new(2);
    let e = do_sign(&mut s, &mut other, K::Vote, 1, 6, 1).unwrap_err();
    assert_eq!(e, SignError::IdentityMismatch("signer key"));
    assert_eq!(other.calls, 0, "the foreign signer must not be asked to sign");
    assert_eq!(w.f.borrow().ops, ops, "nothing may be written");
    assert!(!s.is_latched());
    do_sign(&mut s, &mut w.signer, K::Vote, 1, 6, 1).expect("the right signer still works");
    // a message for another chain is refused too
    let mut m = vote(1, 7, 1);
    m.chain_id = "other-chain".into();
    assert_eq!(s.sign_vote(&m, 6, &mut w.signer).unwrap_err(), SignError::IdentityMismatch("chain id"));
}

#[test]
fn the_vote_floor_hvr_and_the_lock_hqr_only_move_up() {
    let mut w = World::new();
    let mut s = w.init();
    s.sign_vote(&vote(1, 3, 1), 2, &mut w.signer).unwrap();
    assert_eq!((s.record().hvr, s.record().hqr), (Some(3), Some(2)));
    s.sign_vote(&vote(1, 6, 1), 1, &mut w.signer).unwrap(); // a lower QC round never lowers the lock
    assert_eq!((s.record().hvr, s.record().hqr), (Some(6), Some(2)));
    s.sign_vote(&vote(1, 7, 1), 5, &mut w.signer).unwrap();
    assert_eq!((s.record().hvr, s.record().hqr), (Some(7), Some(5)));
}

#[test]
fn a_lower_epoch_is_refused_and_a_higher_epoch_starts_clean() {
    let mut w = World::new();
    let mut s = w.prior();
    let e = do_sign(&mut s, &mut w.signer, K::Vote, 0, 9, 1).unwrap_err();
    assert_eq!(e, SignError::EpochRegression { record: 1, requested: 0 });
    do_sign(&mut s, &mut w.signer, K::Vote, 2, 1, 1).expect("a new epoch may start at a low round");
    let r = s.record();
    assert_eq!((r.epoch, r.hvr), (2, Some(1)));
    assert!(r.last_timeout.is_none() && r.last_proposal.is_none(), "slots belong to one epoch");
    let (st, ctr) = s.into_parts();
    assert_eq!(w.open(&st, &ctr).unwrap().record().epoch, 2);
}

// ================================================================ failure handling

#[test]
fn a_signer_failure_latches_the_store_and_writes_nothing() {
    let mut w = World::new();
    let mut s = w.prior();
    let before_ops = w.f.borrow().ops;
    w.signer.fail_next = true;
    let e = do_sign(&mut s, &mut w.signer, K::Vote, 1, 6, 1).unwrap_err();
    assert!(matches!(e, SignError::Signer(_)), "{e:?}");
    assert!(s.is_latched());
    assert_eq!(w.f.borrow().ops, before_ops, "nothing may be written when signing fails");
    // latched: even a request that would otherwise be a re-send is refused
    assert_eq!(do_sign(&mut s, &mut w.signer, K::Vote, 1, 5, 1).unwrap_err(), SignError::Latched);
    // a restart reopens at the last committed state
    let (st, ctr) = s.into_parts();
    let s2 = w.open(&st, &ctr).unwrap();
    assert_eq!(s2.record().hvr, Some(5));
}

#[test]
fn a_malformed_signature_from_the_signer_is_refused_and_latches() {
    let mut w = World::new();
    let mut s = w.init();
    w.signer.short_signature = true;
    let e = do_sign(&mut s, &mut w.signer, K::Vote, 1, 3, 1).unwrap_err();
    assert_eq!(e, SignError::BadSignatureLength(3308));
    assert!(s.is_latched());
}

#[test]
fn a_storage_or_counter_failure_at_any_step_latches_the_store() {
    for fail_at in 0..5 {
        let mut w = World::new();
        let mut s = w.prior();
        w.reset_plan();
        w.f.borrow_mut().fail_at = Some(fail_at);
        let e = do_sign(&mut s, &mut w.signer, K::Vote, 1, 6, 1).unwrap_err();
        assert!(matches!(e, SignError::Commit(_)), "fail_at {fail_at}: {e:?}");
        assert!(s.is_latched(), "fail_at {fail_at}");
        assert_eq!(do_sign(&mut s, &mut w.signer, K::Vote, 1, 6, 1).unwrap_err(), SignError::Latched, "fail_at {fail_at}");
        assert_eq!(s.record().hvr, Some(5), "in-memory state must not advance past what is durable");
    }
}

// ================================================================ commit order

#[test]
fn the_commit_order_is_write_sync_rename_sync_dir_then_counter() {
    let mut w = World::new();
    let mut s = w.init();
    {
        let f = w.f.borrow();
        assert_eq!(f.log, ["write_tmp", "sync_file", "rename", "sync_dir", "write_tmp", "sync_file", "rename", "sync_dir", "counter"],
            "initialization: marker (4 steps) then state (4 steps) then the counter");
    }
    w.reset_plan();
    do_sign(&mut s, &mut w.signer, K::Vote, 1, 1, 1).unwrap();
    assert_eq!(w.f.borrow().log, ["write_tmp", "sync_file", "rename", "sync_dir", "counter"]);
    // a re-send is not a commit and writes nothing
    w.reset_plan();
    let again = do_sign(&mut s, &mut w.signer, K::Vote, 1, 1, 1).unwrap();
    assert!(again.resent);
    assert!(w.f.borrow().log.is_empty());
}

// ================================================================ fail closed on open

#[test]
fn a_missing_state_file_with_a_marker_fails_closed_and_creates_nothing() {
    let mut w = World::new();
    let (mut st, ctr) = w.prior().into_parts();
    st.delete_raw(STATE_FILE);
    assert_eq!(open_err(&w, &st, &ctr), OpenError::MarkerWithoutState);
    assert!(st.raw(STATE_FILE).is_none(), "open must not recreate the state");
}

#[test]
fn a_state_file_without_the_marker_fails_closed() {
    let mut w = World::new();
    let (mut st, ctr) = w.prior().into_parts();
    st.delete_raw(MARKER_FILE);
    assert_eq!(open_err(&w, &st, &ctr), OpenError::StateWithoutMarker);
}

#[test]
fn both_files_gone_is_no_state_and_a_fresh_start_is_still_refused_by_the_counter() {
    let mut w = World::new();
    let (mut st, ctr) = w.prior().into_parts();
    st.delete_raw(STATE_FILE);
    st.delete_raw(MARKER_FILE);
    assert_eq!(open_err(&w, &st, &ctr), OpenError::NoState);
    let e = Store::initialize_fresh(st.clone(), ctr.clone(), &w.fresh_init(), &ParticipationEvidence::default()).err().unwrap();
    assert!(matches!(e, InitError::CounterNotZero(_)), "{e:?}");
}

#[test]
fn an_empty_or_truncated_state_file_never_opens_at_any_length() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let good = st.raw(STATE_FILE).unwrap();
    assert!(w.open(&st, &ctr).is_ok());
    for n in 0..good.len() {
        let mut s2 = st.clone();
        s2.set_raw(STATE_FILE, good[..n].to_vec());
        assert!(w.open(&s2, &ctr).is_err(), "a {n}-byte prefix of the {}-byte state file must not open", good.len());
    }
}

#[test]
fn a_single_flipped_bit_at_any_offset_never_opens() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let good = st.raw(STATE_FILE).unwrap();
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        let mut s2 = st.clone();
        s2.set_raw(STATE_FILE, bad);
        assert!(w.open(&s2, &ctr).is_err(), "bit flip at offset {i} must not open");
    }
    // the same for the marker
    let m = st.raw(MARKER_FILE).unwrap();
    for i in 0..m.len() {
        let mut bad = m.clone();
        bad[i] ^= 0x01;
        let mut s2 = st.clone();
        s2.set_raw(MARKER_FILE, bad);
        assert!(w.open(&s2, &ctr).is_err(), "marker bit flip at offset {i} must not open");
    }
}

#[test]
fn trailing_bytes_and_an_unsupported_version_are_refused() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let good = st.raw(STATE_FILE).unwrap();
    let mut s2 = st.clone();
    let mut more = good.clone();
    more.push(0);
    s2.set_raw(STATE_FILE, more);
    assert!(w.open(&s2, &ctr).is_err());
    for bad_version in [1u16, 3] {
        let mut v = good.clone();
        v[4..6].copy_from_slice(&bad_version.to_be_bytes());
        let mut s3 = st.clone();
        s3.set_raw(STATE_FILE, v);
        assert_eq!(open_err(&w, &s3, &ctr), OpenError::VersionUnsupported(bad_version), "version 1 (no prev_digest) and future versions are refused");
    }
    let mut magic = good;
    magic[0] ^= 0xFF;
    let mut s4 = st.clone();
    s4.set_raw(STATE_FILE, magic);
    assert!(w.open(&s4, &ctr).is_err());
}

fn rewrite(st: &MemStorage, f: impl FnOnce(&mut SafetyRecord)) -> MemStorage {
    let mut r = decode_record(&st.raw(STATE_FILE).unwrap()).expect("decode");
    f(&mut r);
    let mut s2 = st.clone();
    s2.set_raw(STATE_FILE, encode_record(&r).expect("encode"));
    s2
}

#[test]
fn a_record_that_belongs_to_another_profile_chain_key_or_instance_is_refused() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    assert_eq!(open_err_committed(&w, &rewrite(&st, |r| r.protocol_profile = "other-profile".into())), OpenError::ProfileMismatch);
    assert_eq!(open_err_committed(&w, &rewrite(&st, |r| r.chain_id = "other-chain".into())), OpenError::ChainMismatch);
    assert_eq!(open_err_committed(&w, &rewrite(&st, |r| r.public_key[0] ^= 1)), OpenError::KeyMismatch);
    assert_eq!(open_err_committed(&w, &rewrite(&st, |r| r.instance_id[0] ^= 1)), OpenError::InstanceMismatch);
    // the caller expecting a different identity is refused too
    let other_pk = test_public_key(2);
    let e = Store::open(st.clone(), ctr.clone(), &Expected { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &other_pk }, &TestVerifier, &ParticipationEvidence::default()).err().unwrap();
    assert_eq!(e, OpenError::KeyMismatch);
    let e = Store::open(st.clone(), ctr.clone(), &Expected { protocol_profile: "other", chain_id: CHAIN, public_key: &w.pk }, &TestVerifier, &ParticipationEvidence::default()).err().unwrap();
    assert_eq!(e, OpenError::ProfileMismatch);
}

#[test]
fn a_marker_that_does_not_match_the_state_is_refused() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let mut m = decode_marker(&st.raw(MARKER_FILE).unwrap()).unwrap();
    m.instance_id[3] ^= 1;
    let mut s2 = st.clone();
    s2.set_raw(MARKER_FILE, encode_marker(&m).unwrap());
    assert_eq!(open_err(&w, &s2, &ctr), OpenError::InstanceMismatch);
    let mut m = decode_marker(&st.raw(MARKER_FILE).unwrap()).unwrap();
    m.public_key[7] ^= 1;
    let mut s3 = st.clone();
    s3.set_raw(MARKER_FILE, encode_marker(&m).unwrap());
    assert!(w.open(&s3, &ctr).is_err());
}

#[test]
fn a_stored_signature_that_does_not_verify_is_refused_even_with_a_valid_checksum() {
    let mut w = World::new();
    let (st, _ctr) = w.prior().into_parts();
    for k in ALL_KINDS {
        let bad = rewrite(&st, |r| {
            let item = match k { K::Vote => r.last_vote.as_mut(), K::Timeout => r.last_timeout.as_mut(), K::Proposal => r.last_proposal.as_mut() }.unwrap();
            item.envelope.signature[100] ^= 1;
        });
        assert_eq!(open_err_committed(&w, &bad), OpenError::BadSignature { kind: kind(k).name() }, "{k:?}");
    }
    // a signature made for another domain does not verify under this one
    let cross = rewrite(&st, |r| {
        let t = r.last_timeout.clone().unwrap();
        r.last_vote.as_mut().unwrap().envelope = t.envelope;
    });
    assert_eq!(open_err_committed(&w, &cross), OpenError::BadSignature { kind: "vote" });
}

#[test]
fn a_stored_message_must_be_canonical_belong_to_this_chain_and_match_its_round() {
    let mut w = World::new();
    let (st, _ctr) = w.prior().into_parts();
    let trailing = rewrite(&st, |r| r.last_vote.as_mut().unwrap().message.push(0));
    assert!(matches!(open_err_committed(&w, &trailing), OpenError::Damaged(_)));
    let wrong_round = rewrite(&st, |r| r.last_vote.as_mut().unwrap().round = 4);
    assert!(matches!(open_err_committed(&w, &wrong_round), OpenError::Damaged(_)));
    let other_chain = rewrite(&st, |r| {
        let mut m = vote(1, 5, 1);
        m.chain_id = "other-chain".into();
        r.last_vote.as_mut().unwrap().message = m.encode().unwrap();
    });
    assert_eq!(open_err_committed(&w, &other_chain), OpenError::ChainMismatch);
    let other_epoch = rewrite(&st, |r| r.last_timeout.as_mut().unwrap().message = timeout(2, 5, 1).encode().unwrap());
    assert!(matches!(open_err_committed(&w, &other_epoch), OpenError::Damaged(_)));
}

#[test]
fn an_internally_inconsistent_record_is_refused() {
    let mut w = World::new();
    let (st, _ctr) = w.prior().into_parts();
    let fresh_with_slot = rewrite(&st, |r| r.state = State::Fresh);
    assert!(matches!(open_err_committed(&w, &fresh_with_slot), OpenError::Damaged(_)), "Fresh must have no signed items");
    let active_empty = rewrite(&st, |r| { r.last_vote = None; r.last_timeout = None; r.last_proposal = None; });
    assert!(matches!(open_err_committed(&w, &active_empty), OpenError::Damaged(_)), "Active must have signed something");
    let low_hvr = rewrite(&st, |r| r.hvr = Some(4));
    assert!(matches!(open_err_committed(&w, &low_hvr), OpenError::Damaged(_)), "hvr below a signed vote round");
    let no_hvr = rewrite(&st, |r| r.hvr = None);
    assert!(matches!(open_err_committed(&w, &no_hvr), OpenError::Damaged(_)));
}

#[test]
fn each_rule_for_a_fresh_record_is_enforced_on_its_own() {
    // The trusted counter is set to 1 and the record's counter to 1 so that the counter rules pass and only the rule under
    // test can reject the record.
    let mut w = World::new();
    let (st, _ctr) = w.prior().into_parts();
    let fresh = |f: &dyn Fn(&mut SafetyRecord)| rewrite(&st, |r| { r.state = State::Fresh; r.counter = 1; f(r) });
    // a fresh record that still carries signed items (each slot on its own)
    assert!(matches!(open_err_committed(&w, &fresh(&|r| { r.last_timeout = None; r.last_proposal = None; r.hvr = None; r.hqr = None; })), OpenError::Damaged(_)), "a vote");
    assert!(matches!(open_err_committed(&w, &fresh(&|r| { r.last_vote = None; r.last_proposal = None; r.hvr = None; r.hqr = None; })), OpenError::Damaged(_)), "a timeout");
    assert!(matches!(open_err_committed(&w, &fresh(&|r| { r.last_vote = None; r.last_timeout = None; r.hvr = None; r.hqr = None; })), OpenError::Damaged(_)), "a proposal");
    // a fresh record with a round floor but nothing signed
    let none = |r: &mut SafetyRecord| { r.last_vote = None; r.last_timeout = None; r.last_proposal = None; };
    assert!(matches!(open_err_committed(&w, &fresh(&|r| { none(r); r.hvr = Some(3); r.hqr = None; })), OpenError::Damaged(_)), "hvr set");
    assert!(matches!(open_err_committed(&w, &fresh(&|r| { none(r); r.hvr = None; r.hqr = Some(3); })), OpenError::Damaged(_)), "hqr set");
    // the clean fresh record at counter 1 is accepted, so the refusals above are the rules and nothing else
    let clean = fresh(&|r| { none(r); r.hvr = None; r.hqr = None; });
    assert!(w.open(&clean, &counter_at_file(&clean, w.f.clone())).is_ok());
    // and a fresh record at the wrong counter is refused even when otherwise clean
    let wrong = rewrite(&st, |r| { r.state = State::Fresh; r.counter = 2; none(r); r.hvr = None; r.hqr = None; });
    assert!(matches!(open_err_committed(&w, &wrong), OpenError::Damaged(_)));
    let _ = &mut w;
}

#[test]
fn a_leftover_temporary_file_is_ignored_and_cleared() {
    let mut w = World::new();
    let (mut st, ctr) = w.prior().into_parts();
    st.set_raw(STATE_TMP, vec![0xAB; 77]);
    let s = w.open(&st, &ctr).expect("the temporary file is never read");
    assert_eq!(s.record().hvr, Some(5));
    let (st2, _) = s.into_parts();
    assert!(st2.raw(STATE_TMP).is_none());
}

// ================================================================ rollback, staleness, the counter

#[test]
fn a_restored_old_backup_is_detected_through_the_trusted_counter() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let backup = st.files(); // the operator's backup, taken at counter 4
    let mut s = w.open(&st, &ctr).unwrap();
    do_sign(&mut s, &mut w.signer, K::Vote, 1, 6, 1).unwrap();
    let (mut st, ctr) = s.into_parts();
    assert_eq!(ctr.value, 5);
    st.restore(backup); // yesterday's files come back; the trusted counter cannot be restored
    assert_eq!(open_err(&w, &st, &ctr), OpenError::Rollback { file_counter: 4, trusted_counter: 5 });
}

#[test]
fn rollback_is_not_detectable_if_the_counter_is_rolled_back_too_so_an_ordinary_file_proves_nothing() {
    // DOCUMENTED LIMIT, asserted so nobody mistakes the file for a rollback defence: with the files AND the counter both
    // restored to the earlier state, the store opens and is stale. Only a counter the attacker cannot roll back helps.
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let backup = st.files();
    let old_state = ctr.state();
    let mut s = w.open(&st, &ctr).unwrap();
    do_sign(&mut s, &mut w.signer, K::Vote, 1, 6, 1).unwrap();
    let (mut st, _) = s.into_parts();
    st.restore(backup);
    let untrusted = TestCounter::with_state(old_state, w.f.clone()); // restored together with the file
    let s2 = w.open(&st, &untrusted).expect("opens: the rollback is invisible without a trusted counter");
    assert_eq!(s2.record().hvr, Some(5), "stale: the vote at round 6 is forgotten");
}

#[test]
fn a_file_one_ahead_of_the_counter_is_the_crash_window_and_completes_the_counter() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let behind = counter_before_file(&st, w.f.clone());
    let s = w.open(&st, &behind).expect("file is one ahead: the crash window between the file and the counter");
    let (_, ctr2) = s.into_parts();
    assert_eq!(ctr2.value, ctr.value, "open completes the counter advance");
}

#[test]
fn a_counter_inconsistent_by_more_than_one_is_refused() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let far_behind = TestCounter::with_value(ctr.value - 2, w.f.clone());
    assert_eq!(open_err(&w, &st, &far_behind), OpenError::CounterInconsistent { file_counter: ctr.value, trusted_counter: ctr.value - 2 });
    let ahead = TestCounter::with_value(ctr.value + 1, w.f.clone());
    assert_eq!(open_err(&w, &st, &ahead), OpenError::Rollback { file_counter: ctr.value, trusted_counter: ctr.value + 1 });
}

#[test]
fn a_record_older_than_the_chain_shows_is_stale_and_a_fresh_one_for_a_participating_key_too() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts(); // hvr 5 in epoch 1, proposal at 5
    let ev = |e, r| ParticipationEvidence { highest_signed: Some((e, r)) };
    assert!(w.open_ev(&st, &ctr, ev(1, 5)).is_ok(), "equal is fine");
    assert!(w.open_ev(&st, &ctr, ev(1, 0)).is_ok());
    assert!(matches!(w.open_ev(&st, &ctr, ev(1, 6)).err().unwrap(), OpenError::StaleAgainstChain { chain: (1, 6), .. }));
    assert!(matches!(w.open_ev(&st, &ctr, ev(2, 0)).err().unwrap(), OpenError::StaleAgainstChain { chain: (2, 0), .. }));
    let (fst, fctr) = w.init().into_parts();
    assert!(w.open_ev(&fst, &fctr, ParticipationEvidence::default()).is_ok());
    assert!(matches!(w.open_ev(&fst, &fctr, ev(1, 0)).err().unwrap(), OpenError::StaleAgainstChain { .. }), "a fresh record cannot be for a key that already participated");
}

// ================================================================ crash and fault enumeration (the core safety property)

/// What a peer would have received: only ever messages the store returned.
#[derive(Default)]
struct Net { sent: Vec<(K, u64, Vec<u8>, Vec<u8>)> }

// Torn-write offsets sampled per crash point (plus 0, 1, len-1, len). The exhaustive every-offset checks are in the
// truncation and bit-flip tests, on the file `open` actually reads; a torn temporary file is never read.
const CRASH_STRIDE: usize = 1009;

#[test]
fn a_crash_or_an_io_error_at_any_step_never_allows_two_messages_for_one_round() {
    for k in ALL_KINDS {
        // modes: Some(crash_before) for 0..=5 (5 = no failure, the process dies right after returning), then I/O errors 0..5
        let mut cases: Vec<(String, Option<usize>, Option<usize>)> = (0..=5).map(|c| (format!("crash before op {c}"), Some(c), None)).collect();
        cases.extend((0..5).map(|f| (format!("I/O error at op {f}"), None, Some(f))));
        for (label, crash_before, fail_at) in cases {
            let mut w = World::new();
            let mut s = w.prior();
            w.reset_plan();
            w.f.borrow_mut().crash_before = crash_before;
            w.f.borrow_mut().fail_at = fail_at;
            let mut net = Net::default();
            let first = do_sign(&mut s, &mut w.signer, k, 1, 6, 1);
            if let Ok(out) = &first { net.sent.push((k, 6, out.message.clone(), out.envelope.encode().unwrap())); }
            let committed = first.is_ok();
            if crash_before == Some(5) { assert!(committed, "{k:?} {label}: with every step done the call succeeds"); } else { assert!(!committed, "{k:?} {label}: a failed step must not return a signature"); }
            let (st, ctr) = s.into_parts();
            let outcomes = st.crash_outcomes(CRASH_STRIDE);
            assert!(!outcomes.is_empty());
            for (n, o) in outcomes.iter().enumerate() {
                let ctx = format!("{k:?} / {label} / outcome {n}");
                let c = ctr.rebind_faults(o.faults.clone());
                // LIVENESS: every state a crash can leave must reopen (a torn or half-renamed file must be impossible)
                let mut s2 = w.open(o, &c).unwrap_or_else(|e| panic!("{ctx}: does not reopen: {e}"));
                let durable = slot(s2.record(), k).cloned().expect("slot");
                let new_msg = message_bytes(k, 1, 6, 1);
                if durable.round == 6 {
                    assert_eq!(durable.message, new_msg, "{ctx}: the durable message is the one signed");
                    // SAFETY: a conflicting message for the same round is refused, the identical one is re-sent verbatim
                    let e = do_sign(&mut s2, &mut w.signer, k, 1, 6, 2).unwrap_err();
                    assert!(matches!(e, SignError::ConflictingMessage { round: 6, .. }), "{ctx}: {e:?}");
                    let again = do_sign(&mut s2, &mut w.signer, k, 1, 6, 1).unwrap();
                    assert!(again.resent, "{ctx}");
                    assert_eq!(again.envelope.encode().unwrap(), durable.envelope.encode().unwrap(), "{ctx}: byte-for-byte");
                } else {
                    assert_eq!(durable.round, 5, "{ctx}: neither old nor new");
                    // NOTHING SENT: the old record is only acceptable if no signature for round 6 ever left the store
                    assert!(net.sent.is_empty(), "{ctx}: a message was sent but is not durable");
                    // LIVENESS: signing a different message for round 6 is allowed, and then it sticks
                    let out = do_sign(&mut s2, &mut w.signer, k, 1, 6, 2).unwrap_or_else(|e| panic!("{ctx}: cannot continue: {e}"));
                    assert!(!out.resent);
                }
                // every message that was sent is durable in every outcome
                for (sk, round, msg, env) in &net.sent {
                    let item = slot(s2.record(), *sk).unwrap();
                    assert!(item.round >= *round && (item.round > *round || (item.message == *msg && item.envelope.encode().unwrap() == *env)), "{ctx}: sent message not durable");
                }
            }
        }
    }
}

#[test]
fn a_crash_while_initializing_never_leaves_signing_state_or_a_state_without_its_marker() {
    for crash_before in 0..=9 {
        let w = World::new();
        w.f.borrow_mut().crash_before = Some(crash_before);
        let r = Store::initialize_fresh(w.st.clone(), w.ctr.clone(), &w.fresh_init(), &ParticipationEvidence::default());
        assert_eq!(r.is_ok(), crash_before == 9, "crash before op {crash_before}");
        let (st, ctr) = match r { Ok(s) => s.into_parts(), Err(_) => (w.st.clone(), w.ctr.clone()) };
        for (n, o) in st.crash_outcomes(CRASH_STRIDE).iter().enumerate() {
            let ctx = format!("crash before op {crash_before} / outcome {n}");
            let c = ctr.rebind_faults(o.faults.clone());
            match w.open(o, &c) {
                Ok(s) => assert_eq!(s.record().state, State::Fresh, "{ctx}: initialization can only ever yield a fresh record"),
                Err(OpenError::NoState) | Err(OpenError::MarkerWithoutState) => {}
                Err(e) => panic!("{ctx}: unexpected {e:?} (a state file must never exist without its marker, and nothing may be torn)"),
            }
            // an interrupted initialization is never silently resumed or doubled
            let again = Store::initialize_fresh(o.clone(), c.clone(), &w.fresh_init(), &ParticipationEvidence::default());
            if w.open(o, &c).is_ok() || o.raw(MARKER_FILE).is_some() { assert_eq!(again.err(), Some(InitError::AlreadyInitialized), "{ctx}"); }
        }
    }
}

// ================================================================ strict compare-and-advance, sessions, recovery (spec 7.1)

type SStore = SafetyStore<MemStorage, SharedCounter>;

fn s_init(w: &World, sc: &SharedCounter) -> SStore {
    SafetyStore::initialize_fresh(w.st.clone(), sc.clone(), &w.fresh_init(), &ParticipationEvidence::default()).expect("initialize")
}
fn s_open(w: &World, st: &MemStorage, sc: &SharedCounter) -> Result<SStore, OpenError> {
    SafetyStore::open(st.clone(), sc.clone(), &w.expected(), &TestVerifier, &ParticipationEvidence::default())
}

#[test]
fn the_test_counter_double_is_strict_compare_and_advance_on_value_and_digest_with_a_fencing_session() {
    let f = faults();
    let mut c = TestCounter::new(f);
    let s1 = c.acquire_session().unwrap();
    let d1 = [1u8; 32];
    assert!(c.advance(&CounterState::INITIAL, d1, &s1).is_ok());
    assert_eq!(c.state(), CounterState { value: 1, digest: d1 });
    assert!(c.advance(&CounterState::INITIAL, d1, &s1).is_err(), "advancing again from the old state must fail: there is no idempotent form");
    assert!(c.advance(&CounterState { value: 2, digest: d1 }, [2; 32], &s1).is_err(), "an expected value ahead of the counter must fail");
    assert!(c.advance(&CounterState { value: 1, digest: [9; 32] }, [2; 32], &s1).is_err(), "the right value with the wrong digest must fail");
    assert_eq!(c.state(), CounterState { value: 1, digest: d1 });
    let s2 = c.acquire_session().unwrap();
    assert!(c.advance(&CounterState { value: 1, digest: d1 }, [2; 32], &s1).is_err(), "a superseded session must fail even with the right expected state");
    assert!(c.advance(&CounterState { value: 1, digest: d1 }, [2; 32], &s2).is_ok());
    assert_eq!(c.state(), CounterState { value: 2, digest: [2; 32] });
}

#[test]
fn every_commit_is_a_compare_and_advance_from_the_records_previous_counter_with_the_stores_session() {
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let mut s = s_init(&w, &sc);
    do_sign_s(&mut s, &mut w.signer, K::Vote, 3).unwrap();
    do_sign_s(&mut s, &mut w.signer, K::Timeout, 3).unwrap();
    do_sign_s(&mut s, &mut w.signer, K::Proposal, 3).unwrap();
    // initialization advanced 0 -> 1, then 1 -> 2, 2 -> 3, 3 -> 4, all with the one session the store acquired
    assert_eq!(sc.calls(), vec![(0, 1), (1, 1), (2, 1), (3, 1)]);
    assert_eq!(sc.value(), 4);
    // a re-send is not a commit and does not touch the counter
    assert!(do_sign_s(&mut s, &mut w.signer, K::Vote, 3).unwrap().resent);
    assert_eq!(sc.calls().len(), 4);
}

fn do_sign_s(s: &mut SStore, signer: &mut TestSigner, k: K, round: u64) -> Result<Signed, SignError> {
    match k {
        K::Vote => s.sign_vote(&vote(1, round, 1), round - 1, signer),
        K::Timeout => s.sign_timeout(&timeout(1, round, 1), signer),
        K::Proposal => s.sign_proposal(1, round, &proposal(1), signer),
    }
}

#[test]
fn a_counter_that_has_moved_fails_the_commit_closed_and_no_signature_is_exposed() {
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let mut s = s_init(&w, &sc);
    sc.set_race_on_next_advance(); // another writer advances the counter first
    let e = do_sign_s(&mut s, &mut w.signer, K::Vote, 3).unwrap_err();
    assert!(matches!(e, SignError::Commit(_)), "{e:?}");
    assert!(s.is_latched());
    // nothing was exposed: the record is unchanged and every later call, even the identical request, is refused
    assert!(s.record().last_vote.is_none() && s.record().hvr.is_none());
    assert_eq!(do_sign_s(&mut s, &mut w.signer, K::Vote, 3).unwrap_err(), SignError::Latched);
    assert_eq!(do_sign_s(&mut s, &mut w.signer, K::Timeout, 4).unwrap_err(), SignError::Latched);
}

#[test]
fn a_superseded_session_cannot_commit_returns_nothing_and_does_not_disturb_the_new_holder() {
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let (st, _) = s_init(&w, &sc).into_parts();
    let mut a = s_open(&w, &st, &sc).expect("A opens"); // acquires a session
    let mut b = s_open(&w, &st, &sc).expect("B opens"); // acquires a later one: A is superseded
    let ea = do_sign_s(&mut a, &mut w.signer, K::Vote, 6).unwrap_err();
    assert!(matches!(ea, SignError::Commit(_)), "the superseded store must not commit: {ea:?}");
    assert!(a.is_latched());
    assert!(a.record().last_vote.is_none(), "and its in-memory state must not advance");
    assert_eq!(do_sign_s(&mut a, &mut w.signer, K::Vote, 6).unwrap_err(), SignError::Latched, "nothing is ever returned by the superseded store");
    // the new holder is unaffected and keeps committing
    let out = do_sign_s(&mut b, &mut w.signer, K::Vote, 6).expect("B commits");
    assert!(!out.resent);
    do_sign_s(&mut b, &mut w.signer, K::Timeout, 6).expect("B commits again");
    assert_eq!(sc.value(), 3);
}

#[test]
fn a_copy_whose_file_is_behind_the_shared_counter_cannot_open() {
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let (st, _) = s_init(&w, &sc).into_parts();
    let mut a = s_open(&w, &st, &sc).unwrap();
    do_sign_s(&mut a, &mut w.signer, K::Vote, 5).unwrap();
    // the clone starts from the snapshot taken before A signed
    assert!(matches!(s_open(&w, &st, &sc).err().unwrap(), OpenError::Rollback { file_counter: 1, trusted_counter: 2 }));
    // and the live store still works
    do_sign_s(&mut a, &mut w.signer, K::Timeout, 5).unwrap();
}

#[test]
fn a_failed_open_does_not_supersede_the_running_store() {
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let (st, _) = s_init(&w, &sc).into_parts();
    let mut a = s_open(&w, &st, &sc).unwrap();
    do_sign_s(&mut a, &mut w.signer, K::Vote, 5).unwrap();
    // a damaged copy, a stale copy and a mismatched copy all fail to open ...
    let mut damaged = st.clone();
    let mut b = damaged.raw(STATE_FILE).unwrap();
    b[10] ^= 1;
    damaged.set_raw(STATE_FILE, b);
    assert!(s_open(&w, &damaged, &sc).is_err());
    assert!(matches!(s_open(&w, &st, &sc).err().unwrap(), OpenError::Rollback { .. }));
    // ... and none of them took the session away from the live store
    do_sign_s(&mut a, &mut w.signer, K::Timeout, 5).expect("the running store is still the one valid writer");
}

#[test]
fn a_counter_bound_to_another_identity_is_refused_at_initialization_and_at_open() {
    let w = World::new();
    let f = w.f.clone();
    let other_key = CounterBinding { public_key: test_public_key(2), instance_id: TEST_INSTANCE };
    let other_instance = CounterBinding { public_key: w.pk.clone(), instance_id: [0xEE; 16] };
    for (name, binding) in [("another key", other_key), ("another instance", other_instance)] {
        let c = TestCounter::bound(CounterState::INITIAL, f.clone(), binding.clone());
        let e = Store::initialize_fresh(MemStorage::new(f.clone()), c, &w.fresh_init(), &ParticipationEvidence::default()).err().unwrap();
        assert_eq!(e, InitError::CounterBindingMismatch, "{name}");
    }
    let (st, ctr) = w.init().into_parts();
    for (name, binding) in [
        ("another key", CounterBinding { public_key: test_public_key(2), instance_id: TEST_INSTANCE }),
        ("another instance", CounterBinding { public_key: w.pk.clone(), instance_id: [0xEE; 16] }),
    ] {
        let c = TestCounter::bound(ctr.state(), f.clone(), binding);
        assert_eq!(w.open(&st, &c).err().unwrap(), OpenError::CounterBindingMismatch, "{name}");
    }
    assert!(w.open(&st, &ctr).is_ok());
}

#[test]
fn a_recovery_advance_gates_the_open_and_a_counter_failure_leaves_no_store() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let behind = counter_before_file(&st, w.f.clone());
    w.reset_plan();
    w.f.borrow_mut().crash_before = Some(0); // the counter is unreachable for the recovery advance
    let e = w.open(&st, &behind).err().expect("no store may exist when the recovery advance fails");
    assert!(matches!(e, OpenError::Counter(_)), "{e:?}");
    w.reset_plan();
    let s = w.open(&st, &behind).expect("once the counter is reachable the same open succeeds");
    assert_eq!(s.into_parts().1.value, ctr.value);
}

#[test]
fn a_recovery_advance_that_loses_a_race_fails_closed() {
    let mut w = World::new();
    let (st, _ctr) = w.prior().into_parts();
    let mut behind = counter_before_file(&st, w.f.clone());
    behind.set_race_on_next_advance(); // another writer advances the counter first
    let e = w.open(&st, &behind).err().expect("must not open");
    assert!(matches!(e, OpenError::Counter(_)), "{e:?}");
}

#[test]
fn a_crash_during_the_recovery_advance_reopens_correctly_in_both_outcomes() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    // outcome 1: the advance did not happen: still one behind -> the same rule applies again
    let behind = counter_before_file(&st, w.f.clone());
    assert_eq!(w.open(&st, &behind).unwrap().into_parts().1.value, ctr.value);
    // outcome 2: the advance happened but the acknowledgement was lost: equal -> normal open, nothing to repeat
    let equal = ctr.rebind_faults(w.f.clone());
    let s = w.open(&st, &equal).unwrap();
    assert_eq!(s.into_parts().1.value, ctr.value);
}

// ================================================================ digest-bound counter commits (spec 7.1.1)
//
// The three regression tests below were written first as `#[ignore]`d tests that failed on the number-only counter (evidence:
// docs/pq-hotstuff-2/phase1-digest-regression-failing-now.txt). They are normal tests now.

/// Two writers on their own disks from one committed record; B (the later session) commits `m_B` for round 6; A, fenced out,
/// tries a different vote for the same round and fails at the counter. Returns (A's disk, the shared counter, m_B, m_A).
fn two_disk_fork(w: &mut World) -> (MemStorage, SharedCounter, Vec<u8>, Vec<u8>) {
    let sc = SharedCounter::new(0, w.f.clone());
    let (st, _) = s_init(w, &sc).into_parts();
    let mut a = s_open(w, &st, &sc).unwrap();
    let mut b = s_open(w, &st, &sc).unwrap();
    let m_b = do_sign_s(&mut b, &mut w.signer, K::Vote, 6).unwrap().message;
    assert!(matches!(a.sign_vote(&vote(1, 6, 2), 5, &mut w.signer).unwrap_err(), SignError::Commit(_)));
    let (a_disk, _) = a.into_parts();
    (a_disk, sc, m_b, vote(1, 6, 2).encode().unwrap())
}

#[test]
fn two_disks_a_fenced_out_writers_restart_is_refused_so_it_can_never_send_a_vote_that_conflicts_with_the_committed_one() {
    let mut w = World::new();
    let (a_disk, sc, m_b, _m_a) = two_disk_fork(&mut w);
    match s_open(&w, &a_disk, &sc) {
        Err(_) => {}
        Ok(a2) => panic!("A reopened holding {:?} although B broadcast a different vote ({} bytes) for the same round",
            a2.record().last_vote.as_ref().map(|v| v.round), m_b.len()),
    }
}

#[test]
fn a_state_file_overwritten_after_the_commit_by_a_fenced_out_writer_is_refused_on_the_new_holders_restart() {
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let (st, _) = s_init(&w, &sc).into_parts();
    let mut a = s_open(&w, &st, &sc).unwrap();
    let mut b = s_open(&w, &st, &sc).unwrap();
    do_sign_s(&mut b, &mut w.signer, K::Vote, 6).unwrap(); // B commits and broadcasts
    assert!(a.sign_vote(&vote(1, 6, 2), 5, &mut w.signer).is_err()); // A is fenced out but its file write happened on its disk
    let (a_disk, _) = a.into_parts();
    let (mut b_disk, _) = b.into_parts();
    // on a shared directory, A's late write lands on top of B's committed file
    b_disk.set_raw(STATE_FILE, a_disk.raw(STATE_FILE).unwrap());
    assert!(s_open(&w, &b_disk, &sc).is_err(), "B must not restart on a record that is not the one it committed");
}

#[test]
fn two_files_one_ahead_the_first_restart_commits_and_the_second_is_refused() {
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let (st, _) = s_init(&w, &sc).into_parts();
    let mut a = s_open(&w, &st, &sc).unwrap();
    let mut b = s_open(&w, &st, &sc).unwrap();
    // B writes its file durably and dies before the counter advance: nothing was returned
    w.reset_plan();
    w.f.borrow_mut().crash_before = Some(4);
    assert!(b.sign_vote(&vote(1, 6, 1), 5, &mut w.signer).is_err());
    // A (fenced out) also writes its file for the same round and fails at the counter: nothing was returned either
    w.reset_plan();
    assert!(a.sign_vote(&vote(1, 6, 2), 5, &mut w.signer).is_err());
    let (a_disk, _) = a.into_parts();
    let (b_disk, _) = b.into_parts();
    w.reset_plan();
    assert_eq!(sc.value(), 1, "the counter never advanced");
    // each disk now holds a valid successor of the committed record; whichever restarts first commits it ...
    let first = s_open(&w, &b_disk, &sc).expect("the first restart commits its successor");
    assert_eq!(sc.value(), 2);
    // ... and the other, whose record is not the committed one, is refused
    assert!(s_open(&w, &a_disk, &sc).is_err(), "the second restart holds a vote that conflicts with the committed one");
    drop(first);
}

#[test]
fn a_process_that_died_after_its_file_was_durable_fails_closed_when_a_competitor_committed_a_different_successor() {
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let (st, _) = s_init(&w, &sc).into_parts();
    // the original process B writes its successor durably and dies before the counter advance: nothing was returned
    let mut b = s_open(&w, &st, &sc).unwrap();
    w.reset_plan();
    w.f.borrow_mut().crash_before = Some(4);
    assert!(b.sign_vote(&vote(1, 6, 1), 5, &mut w.signer).is_err());
    let (b_disk, _) = b.into_parts();
    assert_eq!(sc.value(), 1, "the counter never advanced");
    // a competing validator A, on its own disk at the committed record, commits a DIFFERENT successor and broadcasts it
    w.reset_plan();
    let mut a = s_open(&w, &st, &sc).unwrap();
    let m_a = a.sign_vote(&vote(1, 6, 2), 5, &mut w.signer).expect("A commits").message;
    assert_eq!(sc.value(), 2);
    // B's record is internally valid: it opens when it is treated as the committed one ...
    let valid = counter_at_file(&b_disk, w.f.clone());
    assert!(w.open(&b_disk, &valid).is_ok(), "the record is valid in itself");
    // ... but when B restarts against the real counter, which A advanced, it fails closed
    assert_eq!(s_open(&w, &b_disk, &sc).err().unwrap(), OpenError::Fork { counter: 2 });
    // and A, which broadcast m_A, is unaffected
    assert_eq!(a.record().last_vote.as_ref().unwrap().message, m_a);
}

#[test]
fn the_digest_covers_the_complete_canonical_record() {
    let mut w = World::new();
    let (st, _) = w.prior().into_parts();
    let base = decode_record(&st.raw(STATE_FILE).unwrap()).unwrap();
    let d0 = base.digest().unwrap();
    let bytes = st.raw(STATE_FILE).unwrap();
    assert_eq!(d0[..], bytes[bytes.len() - 32..], "the digest is the sealing checksum of the canonical encoding");
    type Edit = Box<dyn Fn(&mut SafetyRecord)>;
    let edits: Vec<(&str, Edit)> = vec![
        ("prev_digest", Box::new(|r| r.prev_digest[0] ^= 1)),
        ("protocol_profile", Box::new(|r| r.protocol_profile.push('x'))),
        ("chain_id", Box::new(|r| r.chain_id.push('x'))),
        ("public_key", Box::new(|r| r.public_key[7] ^= 1)),
        ("instance_id", Box::new(|r| r.instance_id[0] ^= 1)),
        ("counter", Box::new(|r| r.counter += 1)),
        ("epoch", Box::new(|r| r.epoch += 1)),
        ("hvr", Box::new(|r| r.hvr = r.hvr.map(|h| h + 1))),
        ("hqr", Box::new(|r| r.hqr = r.hqr.map(|h| h + 1))),
        ("state", Box::new(|r| r.state = State::Fresh)),
        ("vote round", Box::new(|r| r.last_vote.as_mut().unwrap().round += 1)),
        ("vote message", Box::new(|r| r.last_vote.as_mut().unwrap().message.push(0))),
        ("vote envelope", Box::new(|r| r.last_vote.as_mut().unwrap().envelope.signature[9] ^= 1)),
        ("timeout message", Box::new(|r| r.last_timeout.as_mut().unwrap().message.push(0))),
        ("timeout envelope", Box::new(|r| r.last_timeout.as_mut().unwrap().envelope.signature[9] ^= 1)),
        ("proposal message", Box::new(|r| r.last_proposal.as_mut().unwrap().message.push(0))),
        ("proposal envelope", Box::new(|r| r.last_proposal.as_mut().unwrap().envelope.signature[9] ^= 1)),
        ("a slot removed", Box::new(|r| r.last_proposal = None)),
    ];
    let mut seen = vec![d0];
    for (name, f) in &edits {
        let mut r = base.clone();
        f(&mut r);
        let d = r.digest().unwrap();
        assert_ne!(d, d0, "changing {name} must change the digest");
        assert!(!seen.contains(&d), "{name}: the digest collides with another variant");
        seen.push(d);
    }
}

#[test]
fn records_form_a_chain_each_prev_digest_is_the_digest_of_the_record_it_replaced() {
    let mut w = World::new();
    let mut s = w.init();
    let r1 = s.record().clone();
    assert_eq!(r1.prev_digest, [0; 32], "the first record has no predecessor");
    do_sign(&mut s, &mut w.signer, K::Vote, 1, 3, 1).unwrap();
    let r2 = s.record().clone();
    assert_eq!(r2.prev_digest, r1.digest().unwrap());
    do_sign(&mut s, &mut w.signer, K::Timeout, 1, 3, 1).unwrap();
    let r3 = s.record().clone();
    assert_eq!(r3.prev_digest, r2.digest().unwrap());
    // and the chain survives a restart
    let (st, ctr) = s.into_parts();
    let mut s2 = w.open(&st, &ctr).unwrap();
    do_sign(&mut s2, &mut w.signer, K::Proposal, 1, 3, 1).unwrap();
    assert_eq!(s2.record().prev_digest, r3.digest().unwrap());
}

#[test]
fn every_commit_advances_from_the_previous_records_digest_to_the_new_records_digest() {
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let mut s = s_init(&w, &sc);
    let d1 = s.record().digest().unwrap();
    do_sign_s(&mut s, &mut w.signer, K::Vote, 3).unwrap();
    let d2 = s.record().digest().unwrap();
    do_sign_s(&mut s, &mut w.signer, K::Timeout, 3).unwrap();
    let d3 = s.record().digest().unwrap();
    assert_eq!(sc.digests(), vec![([0; 32], d1), (d1, d2), (d2, d3)]);
    assert_eq!(sc.state(), CounterState { value: 3, digest: d3 });
}

#[test]
fn a_store_never_adopts_a_counter_state_it_did_not_commit_even_if_the_counter_moved_under_its_own_session() {
    // The commit compares the counter with the state THIS store last committed. If the counter moved by any route (here, outside
    // every session), the commit must fail closed and nothing may be returned; reading the counter fresh and advancing from
    // whatever it shows would silently adopt the foreign state and overwrite it.
    let mut w = World::new();
    let sc = SharedCounter::new(0, w.f.clone());
    let mut s = s_init(&w, &sc);
    do_sign_s(&mut s, &mut w.signer, K::Vote, 3).unwrap();
    sc.move_externally([0xBB; 32]);
    let moved = sc.state();
    let e = do_sign_s(&mut s, &mut w.signer, K::Timeout, 3).unwrap_err();
    assert!(matches!(e, SignError::Commit(_)), "{e:?}");
    assert!(s.is_latched());
    assert_eq!(sc.state(), moved, "the failed commit must not change the counter");
    assert!(s.record().last_timeout.is_none(), "and nothing was returned or recorded");
}

#[test]
fn a_file_at_the_committed_counter_that_is_not_the_committed_record_is_a_fork() {
    let mut w = World::new();
    let (st, ctr) = w.prior().into_parts();
    let f = decode_record(&st.raw(STATE_FILE).unwrap()).unwrap().counter;
    let wrong = TestCounter::with_state(CounterState { value: f, digest: [0xEE; 32] }, ctr.faults.clone());
    assert_eq!(open_err(&w, &st, &wrong), OpenError::Fork { counter: f });
    assert!(w.open(&st, &counter_at_file(&st, w.f.clone())).is_ok(), "with the right digest the same file opens");
}

#[test]
fn a_file_one_ahead_must_be_the_successor_of_the_committed_record() {
    let mut w = World::new();
    let (st, _ctr) = w.prior().into_parts();
    let r = decode_record(&st.raw(STATE_FILE).unwrap()).unwrap();
    let other = TestCounter::with_state(CounterState { value: r.counter - 1, digest: [0xEE; 32] }, w.f.clone());
    assert_eq!(open_err(&w, &st, &other), OpenError::SuccessorOfAnotherRecord { counter: r.counter });
    assert!(w.open(&st, &counter_before_file(&st, w.f.clone())).is_ok(), "with the right predecessor the same file opens");
}

#[test]
fn the_recovery_advance_commits_the_file_digest_from_the_committed_state() {
    let mut w = World::new();
    let (st, _ctr) = w.prior().into_parts();
    let r = decode_record(&st.raw(STATE_FILE).unwrap()).unwrap();
    let file_digest = committed_state(&st).digest;
    let sc = SharedCounter::with_state(CounterState { value: r.counter - 1, digest: r.prev_digest }, w.f.clone());
    s_open(&w, &st, &sc).expect("the successor of the committed record is adopted");
    assert_eq!(sc.digests(), vec![(r.prev_digest, file_digest)]);
    assert_eq!(sc.state(), CounterState { value: r.counter, digest: file_digest });
}

// ================================================================ golden record format (independent oracle)

const FRESH_LEN_DIGEST: (usize, &str) = (2113, "f7201e0f54d327f570b7ed022c4eb34615e4a5918be94c14ad1f0a30e8039cb8");
const ACTIVE_LEN_DIGEST: (usize, &str) = (5581, "d19e50088e275383d8a336d31581598d8eea156a89c5f3a88e3dc7ceba3c73c5");
const MARKER_LEN_DIGEST: (usize, &str) = (2059, "4041fe5645ebd735a964b43c646be4823329ca74bf004dfc30f2acef7c618985");

fn oracle_record(state: State, counter: u64, prev_digest: [u8; 32], hvr: Option<u64>, hqr: Option<u64>, vote_item: Option<SignedItem>) -> SafetyRecord {
    SafetyRecord {
        state, protocol_profile: PROFILE.into(), chain_id: CHAIN.into(), public_key: (0..1952).map(|i| (i % 251) as u8).collect(), instance_id: ID,
        counter, prev_digest, epoch: 1, hvr, hqr, last_vote: vote_item, last_timeout: None, last_proposal: None,
    }
}

#[test]
fn the_record_and_marker_formats_match_the_independent_oracle() {
    let fresh = encode_record(&oracle_record(State::Fresh, 1, [0; 32], None, None, None)).unwrap();
    assert_eq!((fresh.len(), digest(&fresh).as_str()), FRESH_LEN_DIGEST);
    let sig: Vec<u8> = (0..3309).map(|i| ((i * 7) % 251) as u8).collect();
    let item = SignedItem { round: 6, message: vote(1, 6, 0x11).encode().unwrap(), envelope: SignatureEnvelope { alg_id: ALG, signature: sig } };
    let fresh_digest: [u8; 32] = fresh[fresh.len() - 32..].try_into().unwrap();
    assert_eq!(hex(&fresh_digest), "268eef095fd129ac02db9e6855c840e56202826f8dffd1dab0de1971fe037cab", "the digest is the sealing checksum");
    let active = encode_record(&oracle_record(State::Active, 2, fresh_digest, Some(6), Some(5), Some(item))).unwrap();
    assert_eq!((active.len(), digest(&active).as_str()), ACTIVE_LEN_DIGEST);
    let marker = encode_marker(&Marker { protocol_profile: PROFILE.into(), chain_id: CHAIN.into(), public_key: (0..1952).map(|i| (i % 251) as u8).collect(), instance_id: ID }).unwrap();
    assert_eq!((marker.len(), digest(&marker).as_str()), MARKER_LEN_DIGEST);
}

#[test]
fn the_record_codec_round_trips_and_is_deterministic() {
    let mut w = World::new();
    let (st, _) = w.prior().into_parts();
    let bytes = st.raw(STATE_FILE).unwrap();
    let rec = decode_record(&bytes).unwrap();
    assert_eq!(encode_record(&rec).unwrap(), bytes, "decode then encode is the identity");
    assert_eq!(encode_record(&rec).unwrap(), encode_record(&rec).unwrap());
    let m = st.raw(MARKER_FILE).unwrap();
    assert_eq!(encode_marker(&decode_marker(&m).unwrap()).unwrap(), m);
}

fn reseal(mut body: Vec<u8>) -> Vec<u8> {
    let sum = Sha3_256::digest(&body);
    body.extend_from_slice(&sum);
    body
}

#[test]
fn a_correctly_sealed_but_non_canonical_record_is_refused_by_the_strict_decoder() {
    let mut w = World::new();
    let (st, _) = w.prior().into_parts();
    let good = st.raw(STATE_FILE).unwrap();
    assert!(decode_record(&good).is_ok());
    let body = good[..good.len() - 32].to_vec();
    let profile_at = 7;
    let hvr_flag_at = profile_at + 4 + PROFILE.len() + 4 + CHAIN.len() + 4 + 1952 + 16 + 8 + 32 + 8; // after the counter, prev_digest and epoch
    let pk_len_at = profile_at + 4 + PROFILE.len() + 4 + CHAIN.len();
    let case = |name: &str, f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = body.clone();
        f(&mut b);
        assert!(decode_record(&reseal(b)).is_err(), "{name} must be refused even with a valid checksum");
    };
    case("a trailing byte inside the sealed body", &|b| b.push(0));
    case("an unknown state byte", &|b| b[6] = 2);
    case("a NUL inside the profile string", &|b| b[profile_at + 4] = 0);
    case("a profile string longer than 255 bytes", &|b| b[profile_at..profile_at + 4].copy_from_slice(&256u32.to_be_bytes()));
    case("an invalid option flag on hvr", &|b| b[hvr_flag_at] = 2);
    case("a public key of the wrong length", &|b| b[pk_len_at..pk_len_at + 4].copy_from_slice(&1951u32.to_be_bytes()));
    case("invalid UTF-8 in the chain id", &|b| b[profile_at + 4 + PROFILE.len() + 4] = 0xFF);
    // Lengths that are wrong while every byte is consistent with them, so only the length rule can refuse the record.
    let pk_start = pk_len_at + 4;
    let mut short_key = body[..pk_start + 1951].to_vec();
    short_key[pk_len_at..pk_len_at + 4].copy_from_slice(&1951u32.to_be_bytes());
    short_key.extend_from_slice(&body[pk_start + 1952..]);
    assert!(decode_record(&reseal(short_key)).is_err(), "a consistently encoded 1951-byte public key");
    let mut long_key = body[..pk_start + 1952].to_vec();
    long_key[pk_len_at..pk_len_at + 4].copy_from_slice(&1953u32.to_be_bytes());
    long_key.push(0);
    long_key.extend_from_slice(&body[pk_start + 1952..]);
    assert!(decode_record(&reseal(long_key)).is_err(), "a consistently encoded 1953-byte public key");
    let rebuild = |name_len: usize| {
        let mut b = body[..profile_at].to_vec();
        b.extend_from_slice(&(name_len as u32).to_be_bytes());
        b.extend(std::iter::repeat(b'a').take(name_len));
        b.extend_from_slice(&body[profile_at + 4 + PROFILE.len()..]);
        reseal(b)
    };
    assert!(decode_record(&rebuild(255)).is_ok(), "a consistently encoded 255-byte profile is within the limit");
    assert!(decode_record(&rebuild(256)).is_err(), "a consistently encoded 256-byte profile is over the limit");
    // the marker is held to the same standard
    let m = st.raw(MARKER_FILE).unwrap();
    assert!(decode_marker(&m).is_ok());
    let mut mb = m[..m.len() - 32].to_vec();
    mb.push(0);
    assert!(decode_marker(&reseal(mb)).is_err(), "a trailing byte inside the sealed marker");
}

// ================================================================ real filesystem

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("pqhs-safety-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

#[test]
fn fs_sign_reopen_and_re_send_are_byte_identical_on_a_real_directory() {
    let dir = TempDir::new("roundtrip");
    let pk = test_public_key(1);
    let mut signer = TestSigner::new(1);
    let f = faults();
    let init = FreshInit { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &pk, instance_id: ID, epoch: 1 };
    let mut s = SafetyStore::initialize_fresh(FsStorage::new(&dir.0).unwrap(), TestCounter::new(f.clone()), &init, &ParticipationEvidence::default()).unwrap();
    let first = s.sign_vote(&vote(1, 3, 1), 2, &mut signer).unwrap();
    let (_, ctr) = s.into_parts();
    let exp = Expected { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &pk };
    let mut s2 = SafetyStore::open(FsStorage::new(&dir.0).unwrap(), ctr.clone(), &exp, &TestVerifier, &ParticipationEvidence::default()).unwrap();
    let calls = signer.calls;
    let again = s2.sign_vote(&vote(1, 3, 1), 2, &mut signer).unwrap();
    assert!(again.resent);
    assert_eq!(again.envelope.encode().unwrap(), first.envelope.encode().unwrap());
    assert_eq!(signer.calls, calls);
    assert!(s2.sign_vote(&vote(1, 3, 2), 2, &mut signer).is_err());
    let names: std::collections::BTreeSet<String> = std::fs::read_dir(&dir.0).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, [MARKER_FILE.to_string(), STATE_FILE.to_string()].into_iter().collect(), "no temporary files are left behind");
}

#[test]
fn fs_open_on_an_empty_directory_creates_nothing_and_a_damaged_file_fails_closed() {
    let dir = TempDir::new("closed");
    let pk = test_public_key(1);
    let f = faults();
    let exp = Expected { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &pk };
    let e = SafetyStore::open(FsStorage::new(&dir.0).unwrap(), TestCounter::new(f.clone()), &exp, &TestVerifier, &ParticipationEvidence::default()).err().unwrap();
    assert_eq!(e, OpenError::NoState);
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0, "open must not create files");
    let init = FreshInit { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &pk, instance_id: ID, epoch: 1 };
    let s = SafetyStore::initialize_fresh(FsStorage::new(&dir.0).unwrap(), TestCounter::new(f.clone()), &init, &ParticipationEvidence::default()).unwrap();
    let (_, ctr) = s.into_parts();
    let p = dir.0.join(STATE_FILE);
    let mut b = std::fs::read(&p).unwrap();
    let n = b.len();
    b[n / 2] ^= 1;
    std::fs::write(&p, &b).unwrap();
    assert!(SafetyStore::open(FsStorage::new(&dir.0).unwrap(), ctr.clone(), &exp, &TestVerifier, &ParticipationEvidence::default()).is_err());
    b.truncate(n / 3);
    std::fs::write(&p, &b).unwrap();
    assert!(SafetyStore::open(FsStorage::new(&dir.0).unwrap(), ctr, &exp, &TestVerifier, &ParticipationEvidence::default()).is_err());
}

#[test]
fn fs_a_leftover_temporary_file_is_removed_and_names_cannot_escape_the_directory() {
    let dir = TempDir::new("tmp");
    let pk = test_public_key(1);
    let f = faults();
    let init = FreshInit { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &pk, instance_id: ID, epoch: 1 };
    let s = SafetyStore::initialize_fresh(FsStorage::new(&dir.0).unwrap(), TestCounter::new(f), &init, &ParticipationEvidence::default()).unwrap();
    let (_, ctr) = s.into_parts();
    std::fs::write(dir.0.join(STATE_TMP), b"torn").unwrap();
    let exp = Expected { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &pk };
    SafetyStore::open(FsStorage::new(&dir.0).unwrap(), ctr, &exp, &TestVerifier, &ParticipationEvidence::default()).unwrap();
    assert!(!dir.0.join(STATE_TMP).exists());
    let mut fs = FsStorage::new(&dir.0).unwrap();
    for bad in ["", ".", "..", "a/b", "a\\b", "../x", "x\0y"] {
        assert!(fs.write_tmp(bad, b"x").is_err(), "{bad:?}");
        assert!(fs.read(bad).is_err(), "{bad:?}");
    }
    assert!(fs.sync_dir().is_ok());
    assert!(FsStorage::new(dir.0.join("does-not-exist")).is_err());
}
