//! Tendermint locking and voting rules (unit level). The randomized
//! multi-validator safety simulation lives in `sim.rs`.

use super::*;

const CHAIN: &str = "test-chain";

fn validator_set(n: usize) -> ValidatorSet {
    ValidatorSet {
        height: 0,
        validators: (0..n).map(|i| ValidatorInfo {
            id: ValidatorId(format!("val_{i:02}")),
            voting_power: 1,
            pop_verified: true,
            public_key: vec![],
        }).collect(),
    }
}

fn config() -> ConsensusConfig {
    ConsensusConfig {
        variant:              ConsensusVariant::TendermintStyle,
        chain_id:             CHAIN.into(),
        propose_timeout_ms:   3_000,
        prevote_timeout_ms:   1_000,
        precommit_timeout_ms: 1_000,
        block_time_ms:        1_000,
        personhood:           None,
        vca:                  None,
    }
}

/// A started 4-validator engine voting as `me`.
async fn engine_as(me: &str) -> TendermintEngine {
    let mut e = TendermintEngine::new();
    e.init(config(), validator_set(4)).await.unwrap();
    e.set_local_validator(Some(ValidatorId(me.into())));
    e.start();
    drain(&mut e);
    e
}

fn id(v: &str) -> ValidatorId { ValidatorId(v.into()) }

/// Proposer of (height 0, round r) among val_00..val_03.
fn proposer(r: Round) -> String { format!("val_{:02}", r % 4) }

fn block(tag: &str, round: Round, pol_round: Option<Round>) -> BlockProposal {
    let parent = BlockHash("parent_0".into());
    BlockProposal {
        height: 0, round, proposer: id(&proposer(round)),
        block_hash: compute_block_hash(CHAIN, 0, &parent, tag.as_bytes()),
        parent_hash: parent, timestamp_ms: 0, tx_data: tag.as_bytes().to_vec(),
        signature: vec![], pol_round,
    }
}

/// The same block, re-proposed in `round` with proof-of-lock `pol_round`.
fn reproposal(b: &BlockProposal, round: Round, pol_round: Round) -> BlockProposal {
    BlockProposal { round, proposer: id(&proposer(round)), pol_round: Some(pol_round), ..b.clone() }
}

fn vote(t: VoteType, round: Round, who: &str, hash: Option<&BlockHash>) -> Vote {
    Vote { vote_type: t, height: 0, round, validator: id(who), block_hash: hash.cloned(),
           signature: vec![], scheme: Vote::default_scheme() }
}

fn drain(e: &mut TendermintEngine) -> Vec<ConsensusAction> {
    std::iter::from_fn(|| e.next_action()).collect()
}

/// Own votes among `actions`, fed back to the engine as the node does.
async fn cast(e: &mut TendermintEngine, actions: &[ConsensusAction]) -> Vec<Vote> {
    let mut out = vec![];
    for a in actions {
        if let ConsensusAction::CastVote(v) = a {
            e.receive_vote(v.clone()).await.unwrap();
            out.push(v.clone());
        }
    }
    out
}

async fn deliver_votes(e: &mut TendermintEngine, t: VoteType, round: Round, who: &[&str], hash: Option<&BlockHash>) {
    for w in who {
        e.receive_vote(vote(t.clone(), round, w, hash)).await.unwrap();
    }
}

/// `me` locks on `b` in round 0: proposal, own prevote, two peers' prevotes.
/// Tests vote as val_03, which proposes no round before 3.
async fn locked_on(me: &str, b: &BlockProposal) -> TendermintEngine {
    let mut e = engine_as(me).await;
    e.receive_proposal(b.clone()).await.unwrap();
    let a = drain(&mut e);
    cast(&mut e, &a).await;
    let others: Vec<&str> = ["val_00", "val_01", "val_02", "val_03"].into_iter().filter(|v| *v != me).take(2).collect();
    deliver_votes(&mut e, VoteType::Prevote, 0, &others, Some(&b.block_hash)).await;
    let a = drain(&mut e);
    let votes = cast(&mut e, &a).await;
    assert!(votes.iter().any(|v| v.vote_type == VoteType::Precommit && v.block_hash.as_ref() == Some(&b.block_hash)),
        "precondition: {me} precommits (and locks on) the polka block");
    assert_eq!(e.locked, Some((b.block_hash.clone(), 0)));
    e
}

/// Advance `e` (in step precommit) to `round` via the precommit timeout.
async fn advance_to(e: &mut TendermintEngine, round: Round) {
    while e.round < round {
        let r = e.round;
        e.on_step_timeout(TimeoutStep::Precommit, 0, r);
        drain(e);
    }
}

fn prevotes_in(actions: &[ConsensusAction]) -> Vec<Option<BlockHash>> {
    actions.iter().filter_map(|a| match a {
        ConsensusAction::CastVote(v) if is_prevote(&v.vote_type) => Some(v.block_hash.clone()),
        _ => None,
    }).collect()
}

fn precommits_in(actions: &[ConsensusAction]) -> Vec<Option<BlockHash>> {
    actions.iter().filter_map(|a| match a {
        ConsensusAction::CastVote(v) if v.vote_type == VoteType::Precommit => Some(v.block_hash.clone()),
        _ => None,
    }).collect()
}

// ── Precommit only after a polka ──────────────────────────────────────────────

#[tokio::test]
async fn precommits_only_after_a_prevote_polka() {
    let mut e = engine_as("val_03").await;
    let b = block("b", 0, None);
    e.receive_proposal(b.clone()).await.unwrap();
    let a = drain(&mut e);
    assert_eq!(prevotes_in(&a), vec![Some(b.block_hash.clone())], "prevotes the proposal");
    assert!(precommits_in(&a).is_empty(), "no precommit without a polka");
    cast(&mut e, &a).await;

    // Precommits from others (no prevotes) do not make it precommit either.
    deliver_votes(&mut e, VoteType::Precommit, 0, &["val_00", "val_01"], Some(&b.block_hash)).await;
    assert!(precommits_in(&drain(&mut e)).is_empty(), "precommits are not a polka");

    deliver_votes(&mut e, VoteType::Prevote, 0, &["val_00"], Some(&b.block_hash)).await;
    assert!(precommits_in(&drain(&mut e)).is_empty(), "2 of 4 prevotes is not +2/3");
    deliver_votes(&mut e, VoteType::Prevote, 0, &["val_01"], Some(&b.block_hash)).await;
    assert_eq!(precommits_in(&drain(&mut e)), vec![Some(b.block_hash.clone())], "+2/3 prevotes -> precommit");
}

#[tokio::test]
async fn nil_polka_or_prevote_timeout_precommits_nil() {
    let mut e = engine_as("val_03").await;
    e.on_step_timeout(TimeoutStep::Propose, 0, 0);
    let a = drain(&mut e);
    assert_eq!(prevotes_in(&a), vec![None], "no proposal in time -> prevote nil");
    cast(&mut e, &a).await;
    deliver_votes(&mut e, VoteType::Prevote, 0, &["val_00", "val_01"], None).await;
    assert_eq!(precommits_in(&drain(&mut e)), vec![None], "+2/3 nil prevotes -> precommit nil");
}

// ── Locks survive round changes ───────────────────────────────────────────────

#[tokio::test]
async fn lock_is_kept_across_rounds() {
    let b0 = block("b0", 0, None);
    let mut e = locked_on("val_03", &b0).await;
    for round in 1..3 {
        advance_to(&mut e, round).await;
        let fresh = block(&format!("fresh-{round}"), round, None);
        e.receive_proposal(fresh.clone()).await.unwrap();
        assert_eq!(prevotes_in(&drain(&mut e)), vec![None],
            "round {round}: locked on b0, a fresh different proposal gets a nil prevote");
        assert_eq!(e.locked, Some((b0.block_hash.clone(), 0)), "lock unchanged");
        e.on_step_timeout(TimeoutStep::Prevote, 0, round);
        drain(&mut e);
    }
}

#[tokio::test]
async fn locked_validator_prevotes_its_locked_block_when_reproposed() {
    let b0 = block("b0", 0, None);
    let mut e = locked_on("val_03", &b0).await;
    advance_to(&mut e, 1).await;
    // Fresh proposal (no pol_round) of the same value: locked value -> prevote it.
    e.receive_proposal(BlockProposal { round: 1, proposer: id(&proposer(1)), ..b0.clone() }).await.unwrap();
    assert_eq!(prevotes_in(&drain(&mut e)), vec![Some(b0.block_hash.clone())]);
}

// ── Valid later-round unlock evidence ─────────────────────────────────────────

#[tokio::test]
async fn later_round_polka_unlocks_and_permits_progress() {
    let b0 = block("b0", 0, None);
    let b1 = block("b1", 1, None);
    let mut e = locked_on("val_03", &b0).await;
    advance_to(&mut e, 1).await;
    // Round 1: the others prevote b1 (a polka val_02 did not take part in).
    e.receive_proposal(b1.clone()).await.unwrap();
    let a = drain(&mut e);
    assert_eq!(prevotes_in(&a), vec![None], "still locked on b0 in round 1");
    cast(&mut e, &a).await;
    deliver_votes(&mut e, VoteType::Prevote, 1, &["val_00", "val_01", "val_02"], Some(&b1.block_hash)).await;
    drain(&mut e);
    assert_eq!(e.valid, Some((b1.block_hash.clone(), 1)), "polka for b1 observed");
    advance_to(&mut e, 2).await;

    // Round 2: b1 re-proposed with proof-of-lock round 1 >= lock round 0.
    e.receive_proposal(reproposal(&b1, 2, 1)).await.unwrap();
    let a = drain(&mut e);
    assert_eq!(prevotes_in(&a), vec![Some(b1.block_hash.clone())], "valid unlock evidence -> prevote b1");
    cast(&mut e, &a).await;
    deliver_votes(&mut e, VoteType::Prevote, 2, &["val_00", "val_01"], Some(&b1.block_hash)).await;
    let a = drain(&mut e);
    assert_eq!(precommits_in(&a), vec![Some(b1.block_hash.clone())]);
    assert_eq!(e.locked, Some((b1.block_hash.clone(), 2)), "relocked on b1");
    cast(&mut e, &a).await;
    deliver_votes(&mut e, VoteType::Precommit, 2, &["val_00", "val_01"], Some(&b1.block_hash)).await;
    let decided: Vec<_> = drain(&mut e).into_iter().filter_map(|a| match a {
        ConsensusAction::Commit { certificate, .. } => Some(certificate), _ => None }).collect();
    assert_eq!(decided.len(), 1, "progress: b1 decided");
    assert_eq!(decided[0].block_hash, b1.block_hash);
    assert_eq!(decided[0].round, 2);
}

// ── Invalid unlock attempts ───────────────────────────────────────────────────

#[tokio::test]
async fn unlock_without_an_observed_polka_is_rejected() {
    let b0 = block("b0", 0, None);
    let b1 = block("b1", 1, None);
    let mut e = locked_on("val_03", &b0).await;
    advance_to(&mut e, 2).await;
    // Claims a polka in round 1, but only 2 of 4 prevotes were seen there.
    deliver_votes(&mut e, VoteType::Prevote, 1, &["val_00", "val_01"], Some(&b1.block_hash)).await;
    e.receive_proposal(reproposal(&b1, 2, 1)).await.unwrap();
    assert!(prevotes_in(&drain(&mut e)).is_empty(), "no prevote for b1 without the +2/3 proof");
    e.on_step_timeout(TimeoutStep::Propose, 0, 2);
    assert_eq!(prevotes_in(&drain(&mut e)), vec![None], "propose timeout -> nil");
    assert_eq!(e.locked, Some((b0.block_hash.clone(), 0)), "lock unchanged");
}

#[tokio::test]
async fn polka_for_a_different_block_does_not_unlock() {
    let b0 = block("b0", 0, None);
    let b1 = block("b1", 1, None);
    let b2 = block("b2", 1, None);
    let mut e = locked_on("val_03", &b0).await;
    advance_to(&mut e, 2).await;
    // A real polka in round 1 -- but for b2, not the re-proposed b1.
    deliver_votes(&mut e, VoteType::Prevote, 1, &["val_00", "val_01", "val_02"], Some(&b2.block_hash)).await;
    e.receive_proposal(reproposal(&b1, 2, 1)).await.unwrap();
    assert!(prevotes_in(&drain(&mut e)).is_empty(), "the proof must be for the proposed block");
}

#[tokio::test]
async fn proof_older_than_the_lock_does_not_unlock() {
    // Polka for b1 in round 0 (val_03 absent from it); val_03 then locks on
    // b0 in round 1; b1 offered in round 2 with proof round 0 < lock round 1.
    let b1 = block("b1", 0, None);
    let mut e = engine_as("val_03").await;
    deliver_votes(&mut e, VoteType::Prevote, 0, &["val_00", "val_01", "val_02"], Some(&b1.block_hash)).await;
    e.on_step_timeout(TimeoutStep::Propose, 0, 0);
    let a = drain(&mut e);
    cast(&mut e, &a).await;
    drain(&mut e);
    advance_to(&mut e, 1).await;
    let b0 = block("b0", 1, None);
    e.receive_proposal(b0.clone()).await.unwrap();
    let a = drain(&mut e);
    cast(&mut e, &a).await;
    deliver_votes(&mut e, VoteType::Prevote, 1, &["val_00", "val_01"], Some(&b0.block_hash)).await;
    let a = drain(&mut e);
    cast(&mut e, &a).await;
    assert_eq!(e.locked, Some((b0.block_hash.clone(), 1)));
    advance_to(&mut e, 2).await;
    e.receive_proposal(reproposal(&b1, 2, 0)).await.unwrap();
    assert_eq!(prevotes_in(&drain(&mut e)), vec![None], "pol_round 0 < lock round 1 -> nil");
}

#[tokio::test]
async fn malformed_unlock_proposals_are_rejected() {
    let mut e = engine_as("val_03").await;
    let b = block("b", 1, None);
    // pol_round must be strictly below the proposal round.
    assert!(e.receive_proposal(BlockProposal { pol_round: Some(1), ..b.clone() }).await.is_err());
    // The block hash must commit to the contents.
    assert!(e.receive_proposal(BlockProposal { tx_data: b"other".to_vec(), ..b.clone() }).await.is_err());
    // A proposer cannot propose two blocks in one round.
    e.receive_proposal(b.clone()).await.unwrap();
    assert!(e.receive_proposal(block("other", 1, None)).await.is_err());
}

// ── Proposer re-proposes its valid block with the proof round ─────────────────

#[tokio::test]
async fn proposer_reproposes_the_valid_block_with_its_pol_round() {
    // val_01 proposes round 1. It observes a polka for b0 in round 0.
    let b0 = block("b0", 0, None);
    let mut e = engine_as("val_01").await;
    e.receive_proposal(b0.clone()).await.unwrap();
    let a = drain(&mut e);
    cast(&mut e, &a).await;
    deliver_votes(&mut e, VoteType::Prevote, 0, &["val_00", "val_02"], Some(&b0.block_hash)).await;
    let a = drain(&mut e);
    cast(&mut e, &a).await;
    e.on_step_timeout(TimeoutStep::Precommit, 0, 0);
    let a = drain(&mut e);
    let repro: Vec<_> = a.iter().filter_map(|x| match x {
        ConsensusAction::Repropose(p) => Some(p.clone()), _ => None }).collect();
    assert_eq!(repro.len(), 1, "round-1 proposer re-proposes instead of a fresh block: {a:?}");
    assert_eq!(repro[0].block_hash, b0.block_hash);
    assert_eq!(repro[0].pol_round, Some(0));
    assert!(!a.iter().any(|x| matches!(x, ConsensusAction::ProposeNew { .. })));
}

// ── Restart: restored lock state ──────────────────────────────────────────────

#[tokio::test]
async fn restored_lock_state_keeps_the_lock_and_never_resigns() {
    let b0 = block("b0", 0, None);
    let e = locked_on("val_03", &b0).await;
    let saved = e.lock_state().unwrap();
    assert_eq!(saved.own_votes.len(), 2, "prevote + precommit recorded");

    let mut restarted = TendermintEngine::new();
    restarted.init(config(), validator_set(4)).await.unwrap();
    restarted.set_local_validator(Some(id("val_03")));
    restarted.restore_lock_state(saved).unwrap();
    assert_eq!(restarted.locked, Some((b0.block_hash.clone(), 0)));
    restarted.start();
    let a = drain(&mut restarted);
    assert!(prevotes_in(&a).is_empty() && precommits_in(&a).is_empty(),
        "round 0 votes were already signed: never re-emitted: {a:?}");

    // A conflicting round-0 proposal cannot draw a second round-0 prevote.
    restarted.receive_proposal(b0.clone()).await.unwrap();
    assert!(prevotes_in(&drain(&mut restarted)).is_empty());

    advance_to(&mut restarted, 1).await;
    restarted.receive_proposal(block("fresh", 1, None)).await.unwrap();
    assert_eq!(prevotes_in(&drain(&mut restarted)), vec![None], "still locked after restart");
}

#[tokio::test]
async fn tampered_lock_block_is_refused_on_restore() {
    let b0 = block("b0", 0, None);
    let mut saved = locked_on("val_03", &b0).await.lock_state().unwrap();
    saved.blocks[0].tx_data = b"tampered".to_vec();
    let mut e = TendermintEngine::new();
    e.init(config(), validator_set(4)).await.unwrap();
    assert!(e.restore_lock_state(saved).is_err());
}

// ── Decision and certificates ─────────────────────────────────────────────────

#[tokio::test]
async fn decides_only_with_the_block_contents() {
    let mut e = engine_as("val_03").await;
    let b = block("b", 0, None);
    deliver_votes(&mut e, VoteType::Precommit, 0, &["val_00", "val_01", "val_03"], Some(&b.block_hash)).await;
    assert!(!drain(&mut e).iter().any(|a| matches!(a, ConsensusAction::Commit { .. })),
        "no decision for a block whose contents are unknown");
    e.receive_proposal(b.clone()).await.unwrap();
    let commits: Vec<_> = drain(&mut e).into_iter().filter(|a| matches!(a, ConsensusAction::Commit { .. })).collect();
    assert_eq!(commits.len(), 1, "late proposal completes the decision");
}

#[tokio::test]
async fn verify_commit_requires_one_round_and_counts_each_validator_once() {
    let e = engine_as("val_03").await;
    let vs = validator_set(4);
    let h = block("b", 0, None).block_hash;
    let pc = |r, who| vote(VoteType::Precommit, r, who, Some(&h));
    let ok = CommitCertificate { height: 0, round: 0, block_hash: h.clone(),
        precommits: vec![pc(0, "val_00"), pc(0, "val_01"), pc(0, "val_02")] };
    assert!(e.verify_commit(&ok, &vs).is_ok());

    let mixed_rounds = CommitCertificate { precommits: vec![pc(0, "val_00"), pc(0, "val_01"), pc(1, "val_02")], ..ok.clone() };
    assert!(e.verify_commit(&mixed_rounds, &vs).is_err(), "precommits from another round do not count");

    let duplicated = CommitCertificate { precommits: vec![pc(0, "val_00"), pc(0, "val_00"), pc(0, "val_01")], ..ok.clone() };
    assert!(e.verify_commit(&duplicated, &vs).is_err(), "a validator counts once");
}

// ── The canonical fork that locking prevents ──────────────────────────────────

fn decisions(actions: &[ConsensusAction]) -> Vec<BlockHash> {
    actions.iter().filter_map(|a| match a {
        ConsensusAction::Commit { certificate, .. } => Some(certificate.block_hash.clone()), _ => None,
    }).collect()
}

/// n = 4, f = 1. Z = val_00 is Byzantine; A = val_01, B = val_02, C = val_03.
///
/// Round 0: Z proposes X to A and B only. Z's X prevote reaches A and B, so
/// both see a polka, precommit X and lock; C prevotes and precommits nil.
/// Z's X precommit reaches only A, which decides X with {A, B, Z}. B and C
/// time out. In round 3, C proposes a fresh Y. Without the lock, B would
/// prevote Y and {B, C, Z} would form a polka and decide Y: a fork. With the
/// lock, B prevotes nil and Y cannot reach +2/3.
#[tokio::test]
async fn lock_prevents_the_canonical_fork() {
    let (mut a, mut b, mut c) = (engine_as("val_01").await, engine_as("val_02").await, engine_as("val_03").await);
    let x = block("X", 0, None);

    // Round 0.
    a.receive_proposal(x.clone()).await.unwrap();
    b.receive_proposal(x.clone()).await.unwrap();
    let pa = drain(&mut a); cast(&mut a, &pa).await;
    let pb = drain(&mut b); cast(&mut b, &pb).await;
    c.on_step_timeout(TimeoutStep::Propose, 0, 0);
    let pc = drain(&mut c); cast(&mut c, &pc).await;
    deliver_votes(&mut a, VoteType::Prevote, 0, &["val_02", "val_00"], Some(&x.block_hash)).await;
    deliver_votes(&mut b, VoteType::Prevote, 0, &["val_01", "val_00"], Some(&x.block_hash)).await;
    deliver_votes(&mut c, VoteType::Prevote, 0, &["val_01", "val_02"], Some(&x.block_hash)).await; // Z withholds from C
    let ca = drain(&mut a); cast(&mut a, &ca).await;
    let cb = drain(&mut b); cast(&mut b, &cb).await;
    assert_eq!(precommits_in(&ca), vec![Some(x.block_hash.clone())]);
    assert_eq!(precommits_in(&cb), vec![Some(x.block_hash.clone())]);
    c.on_step_timeout(TimeoutStep::Prevote, 0, 0);
    let cc = drain(&mut c); cast(&mut c, &cc).await;
    assert_eq!(precommits_in(&cc), vec![None], "C never saw the polka for X");

    // A decides X with {A, B, Z}.
    deliver_votes(&mut a, VoteType::Precommit, 0, &["val_02", "val_00"], Some(&x.block_hash)).await;
    assert_eq!(decisions(&drain(&mut a)), vec![x.block_hash.clone()], "A decides X");

    // B and C see no X quorum (Z withholds) and time out to round 3.
    deliver_votes(&mut b, VoteType::Precommit, 0, &["val_01"], Some(&x.block_hash)).await;
    deliver_votes(&mut b, VoteType::Precommit, 0, &["val_03"], None).await;
    deliver_votes(&mut c, VoteType::Precommit, 0, &["val_01", "val_02"], Some(&x.block_hash)).await;
    assert!(decisions(&drain(&mut b)).is_empty() && decisions(&drain(&mut c)).is_empty());
    advance_to(&mut b, 3).await;
    advance_to(&mut c, 3).await;

    // Round 3: C proposes a fresh Y.
    let y = block("Y", 3, None);
    b.receive_proposal(y.clone()).await.unwrap();
    c.receive_proposal(y.clone()).await.unwrap();
    let vb = drain(&mut b);
    assert_eq!(prevotes_in(&vb), vec![None], "B is locked on X: it must not prevote Y");
    cast(&mut b, &vb).await;
    let vc = drain(&mut c); cast(&mut c, &vc).await;

    // Even with Z's support, Y gets only {C, Z}.
    deliver_votes(&mut b, VoteType::Prevote, 3, &["val_03", "val_00"], Some(&y.block_hash)).await;
    deliver_votes(&mut c, VoteType::Prevote, 3, &["val_02"], None).await;
    deliver_votes(&mut c, VoteType::Prevote, 3, &["val_00"], Some(&y.block_hash)).await;
    deliver_votes(&mut b, VoteType::Precommit, 3, &["val_00", "val_03"], Some(&y.block_hash)).await;
    deliver_votes(&mut c, VoteType::Precommit, 3, &["val_00"], Some(&y.block_hash)).await;
    let (db, dc) = (drain(&mut b), drain(&mut c));
    assert!(!precommits_in(&db).contains(&Some(y.block_hash.clone())), "B must not precommit Y");
    assert!(!precommits_in(&dc).contains(&Some(y.block_hash.clone())), "C has no polka for Y");
    assert!(decisions(&db).is_empty() && decisions(&dc).is_empty(), "no one may decide Y after A decided X");
}
