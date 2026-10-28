//! Randomized, seeded discrete-event simulation of N validators running the
//! real `TendermintEngine` (model-based safety test).
//!
//! Explores vote ordering, message delays, slow links, staggered startup
//! with lost messages, round changes, crash/restart from persisted lock
//! state, and Byzantine validators that equivocate as proposers and voters.
//!
//! Checked on every run:
//!   - Agreement: no two honest validators decide different blocks at any
//!     height, and no two honest-produced commit certificates conflict.
//!   - No unsafe signing: an honest validator never signs two different
//!     votes for one (height, round, type), across restarts included.
//!   - Termination (within the fault bound, eventual delivery): every honest
//!     validator decides every height.
//!
//! The simulation must also find a fork when the fault bound is exceeded --
//! evidence that it can detect one at all.

use super::*;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

const SIM_CHAIN: &str = "sim-chain";
/// Retransmission period (the node uses the same mechanism).
const REBROADCAST_MS: u64 = 2_000;

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self { Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1) }
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 { if n == 0 { 0 } else { self.next() % n } }
    fn chance(&mut self, pct: u64) -> bool { self.below(100) < pct }
}

#[derive(Clone, Debug)]
enum Msg {
    Proposal(BlockProposal),
    Vote(Vote),
}

#[derive(Clone, Debug)]
enum Kind {
    Start,
    Deliver(Msg),
    /// (step, height, round, incarnation)
    Timeout(TimeoutStep, BlockHeight, Round, u32),
    Crash,
    Restart,
    /// Block sync: fetch committed certificates the validator is missing.
    Sync,
    /// Periodic re-send of this validator's signed votes and own proposals
    /// for the current height (gossipsub delivers each message once).
    Rebroadcast(u32),
}

struct Event { at: u64, seq: u64, to: usize, kind: Kind }
impl PartialEq for Event { fn eq(&self, o: &Self) -> bool { (self.at, self.seq) == (o.at, o.seq) } }
impl Eq for Event {}
impl PartialOrd for Event { fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(o)) } }
impl Ord for Event { fn cmp(&self, o: &Self) -> std::cmp::Ordering { (self.at, self.seq).cmp(&(o.at, o.seq)) } }

#[derive(Clone, Debug)]
pub(super) struct Scenario {
    pub n:            usize,
    pub byzantine:    Vec<usize>,
    pub heights:      u64,
    /// Every message takes 1..=max_delay ms...
    pub max_delay:    u64,
    /// ...plus `slow_extra` ms with probability slow_pct%.
    pub slow_pct:     u64,
    pub slow_extra:   u64,
    /// Validators start at random times in [0, start_spread); messages
    /// reaching a validator that is not running are lost.
    pub start_spread: u64,
    /// Probability (per honest validator) of one crash + restart.
    pub crash_pct:    u64,
    pub max_time:     u64,
    pub adversary:    Adversary,
}

/// What Byzantine validators do with each vote their engine would cast.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Adversary {
    /// Per recipient: a random known block, or nil.
    Random,
    /// Block variant k goes to validators with index % 2 == k; with a single
    /// known block, the other half gets nil.
    SplitBrain,
    /// Per (recipient, vote type): the vote for the proposal, or nothing
    /// (withheld). Different subsets see prevotes and precommits -- the
    /// pattern that makes locks necessary.
    Withhold,
}

impl Scenario {
    fn honest(n: usize) -> Self {
        Scenario { n, byzantine: vec![], heights: 4, max_delay: 400, slow_pct: 10, slow_extra: 4_000,
                   start_spread: 0, crash_pct: 0, max_time: 3_000_000, adversary: Adversary::Random }
    }
}

#[derive(Debug, Default)]
pub(super) struct Outcome {
    /// Per honest validator: height -> decided block.
    pub decisions:   BTreeMap<usize, BTreeMap<BlockHeight, BlockHash>>,
    pub forks:       Vec<String>,
    pub double_signs: Vec<String>,
    pub finished:    bool,
    pub max_round:   Round,
    pub restarts:    usize,
    pub stall:       Vec<String>,
}

struct Node {
    engine:      Option<TendermintEngine>,
    incarnation: u32,
    /// Persisted before every signed vote is sent (models the node).
    saved:       Option<LockState>,
    /// Committed certificates (block store), replayed on restart.
    committed:   Vec<CommitCertificate>,
    done:        bool,
    sync_pending: bool,
    /// Signed votes and own proposals at the current height.
    sent:        Vec<Msg>,
}

fn sim_set(n: usize) -> ValidatorSet {
    ValidatorSet {
        height: 0,
        validators: (0..n).map(|i| ValidatorInfo {
            id: ValidatorId(format!("val_{i:02}")), voting_power: 1, pop_verified: true, public_key: vec![],
        }).collect(),
    }
}

fn sim_config() -> ConsensusConfig {
    ConsensusConfig {
        variant: ConsensusVariant::TendermintStyle, chain_id: SIM_CHAIN.into(),
        propose_timeout_ms: 3_000, prevote_timeout_ms: 1_000, precommit_timeout_ms: 1_000,
        block_time_ms: 1_000, personhood: None, vca: None,
    }
}

fn parent(h: BlockHeight) -> BlockHash { BlockHash(format!("parent_{h}")) }

struct Sim {
    sc:     Scenario,
    rng:    Rng,
    seq:    u64,
    now:    u64,
    queue:  BinaryHeap<Reverse<Event>>,
    nodes:  Vec<Node>,
    out:    Outcome,
    /// Every vote each honest validator signed: (validator, h, r, type) -> block.
    signed: BTreeMap<(usize, BlockHeight, Round, u8), Option<BlockHash>>,
    /// Every certificate an honest validator decided: height -> block.
    certs:  BTreeMap<BlockHeight, BlockHash>,
    /// Byzantine validators: blocks seen per height (to equivocate over).
    seen_blocks: BTreeMap<BlockHeight, Vec<BlockHash>>,
}

impl Sim {
    fn push(&mut self, at: u64, to: usize, kind: Kind) {
        self.seq += 1;
        self.queue.push(Reverse(Event { at, seq: self.seq, to, kind }));
    }

    fn delay(&mut self) -> u64 {
        let mut d = 1 + self.rng.below(self.sc.max_delay);
        if self.rng.chance(self.sc.slow_pct) { d += self.sc.slow_extra; }
        d
    }

    fn send(&mut self, from: usize, to: usize, msg: Msg) {
        if from == to { return; }
        let at = self.now + self.delay();
        self.push(at, to, Kind::Deliver(msg));
    }

    fn broadcast(&mut self, from: usize, msg: Msg) {
        for to in 0..self.sc.n { self.send(from, to, msg.clone()); }
    }

    fn is_byz(&self, i: usize) -> bool { self.sc.byzantine.contains(&i) }

    async fn fresh_engine(&self, i: usize) -> TendermintEngine {
        let mut e = TendermintEngine::new();
        e.init(sim_config(), sim_set(self.sc.n)).await.unwrap();
        e.set_local_validator(Some(ValidatorId(format!("val_{i:02}"))));
        e
    }

    /// Drain node i's actions and carry them out.
    async fn pump(&mut self, i: usize) {
        loop {
            let Some(action) = self.nodes[i].engine.as_mut().and_then(|e| e.next_action()) else { return };
            if self.is_byz(i) { self.byzantine_act(i, action).await; } else { self.honest_act(i, action).await; }
            if self.nodes[i].done { return; }
        }
    }

    async fn honest_act(&mut self, i: usize, action: ConsensusAction) {
        match action {
            ConsensusAction::CastVote(v) => {
                let key = (i, v.height, v.round, type_byte(&v.vote_type));
                if let Some(prev) = self.signed.get(&key) {
                    if *prev != v.block_hash {
                        self.out.double_signs.push(format!(
                            "val_{i:02} signed {:?} and {:?} at h{} r{} type {}", prev, v.block_hash, v.height, v.round, key.3));
                    }
                }
                self.signed.insert(key, v.block_hash.clone());
                // Persist before sending (the node's contract).
                self.nodes[i].saved = self.nodes[i].engine.as_ref().unwrap().lock_state();
                let _ = self.nodes[i].engine.as_mut().unwrap().receive_vote(v.clone()).await;
                self.nodes[i].sent.push(Msg::Vote(v.clone()));
                self.broadcast(i, Msg::Vote(v));
            }
            ConsensusAction::ProposeNew { height, round } => {
                let tx = format!("h{height}-r{round}-val_{i:02}-{}", self.rng.next()).into_bytes();
                let e = self.nodes[i].engine.as_mut().unwrap();
                if let Ok(p) = e.propose(height, round, parent(height), tx).await {
                    self.nodes[i].sent.push(Msg::Proposal(p.clone()));
                    self.broadcast(i, Msg::Proposal(p));
                }
            }
            ConsensusAction::Repropose(p) => {
                self.nodes[i].sent.push(Msg::Proposal(p.clone()));
                self.broadcast(i, Msg::Proposal(p));
            }
            ConsensusAction::ScheduleTimeout { step, height, round, after_ms } => {
                let inc = self.nodes[i].incarnation;
                let at = self.now + after_ms;
                self.push(at, i, Kind::Timeout(step, height, round, inc));
            }
            ConsensusAction::Commit { certificate, proposal } => {
                self.nodes[i].sent.clear();
                let e = self.nodes[i].engine.as_ref().unwrap();
                assert!(e.verify_commit(&certificate, &sim_set(self.sc.n)).is_ok(), "honest cert must verify");
                assert_eq!(proposal.block_hash, certificate.block_hash);
                let h = certificate.height;
                let mine = self.out.decisions.entry(i).or_default();
                mine.insert(h, certificate.block_hash.clone());
                match self.certs.get(&h) {
                    Some(other) if *other != certificate.block_hash => self.out.forks.push(format!(
                        "height {h}: val_{i:02} decided {} (round {}) but {} was decided elsewhere",
                        certificate.block_hash, certificate.round, other)),
                    _ => { self.certs.insert(h, certificate.block_hash.clone()); }
                }
                self.out.max_round = self.out.max_round.max(certificate.round);
                self.nodes[i].committed.push(certificate.clone());
                self.nodes[i].saved = None;
                if h + 1 >= self.sc.heights {
                    self.nodes[i].done = true;
                    return;
                }
                let e = self.nodes[i].engine.as_mut().unwrap();
                e.on_commit(certificate, None).await.unwrap();
            }
        }
    }

    /// Equivocate: every vote goes out with a different block per recipient,
    /// and proposals differ per recipient.
    async fn byzantine_act(&mut self, i: usize, action: ConsensusAction) {
        match action {
            ConsensusAction::CastVote(v) => {
                let mut known = self.seen_blocks.get(&v.height).cloned().unwrap_or_default();
                known.dedup();
                for to in 0..self.sc.n {
                    for t in [VoteType::Prevote, VoteType::Precommit] {
                        let pick = if self.sc.adversary == Adversary::Withhold {
                            if self.rng.chance(50) { continue; } // withheld
                            v.block_hash.clone().or_else(|| known.last().cloned())
                        } else if self.sc.adversary == Adversary::SplitBrain && !known.is_empty() {
                            known.get(to % 2).cloned()
                        } else if known.is_empty() || self.rng.chance(15) {
                            None
                        } else {
                            Some(known[self.rng.below(known.len() as u64) as usize].clone())
                        };
                        let vote = Vote { vote_type: t, block_hash: pick, ..v.clone() };
                        self.send(i, to, Msg::Vote(vote));
                    }
                }
            }
            ConsensusAction::ProposeNew { height, round } => {
                let mut variants = vec![];
                for k in 0..2 {
                    let tx = format!("byz-h{height}-r{round}-v{k}").into_bytes();
                    let parent_hash = parent(height);
                    let block_hash = compute_block_hash(SIM_CHAIN, height, &parent_hash, &tx);
                    variants.push(BlockProposal {
                        height, round, proposer: ValidatorId(format!("val_{i:02}")), block_hash,
                        parent_hash, timestamp_ms: 0, tx_data: tx, signature: vec![], pol_round: None,
                    });
                }
                for p in &variants { self.seen_blocks.entry(height).or_default().push(p.block_hash.clone()); }
                for to in 0..self.sc.n {
                    if self.sc.adversary == Adversary::Withhold {
                        // One block, to a random subset only.
                        if self.rng.chance(50) { self.send(i, to, Msg::Proposal(variants[0].clone())); }
                        continue;
                    }
                    let k = if self.sc.adversary == Adversary::SplitBrain { to % 2 } else { self.rng.below(2) as usize };
                    self.send(i, to, Msg::Proposal(variants[k].clone()));
                }
            }
            ConsensusAction::Repropose(p) => self.broadcast(i, Msg::Proposal(p)),
            ConsensusAction::ScheduleTimeout { step, height, round, after_ms } => {
                let inc = self.nodes[i].incarnation;
                let at = self.now + after_ms;
                self.push(at, i, Kind::Timeout(step, height, round, inc));
            }
            ConsensusAction::Commit { certificate, .. } => {
                let e = self.nodes[i].engine.as_mut().unwrap();
                let _ = e.on_commit(certificate, None).await;
            }
        }
    }

    /// The node requests sync when it sees evidence it is behind (a message
    /// for a later height) or times out while peers have committed further.
    fn maybe_sync(&mut self, i: usize, seen_height: BlockHeight) {
        let Some(e) = self.nodes[i].engine.as_ref() else { return };
        if seen_height <= e.current_height() || self.nodes[i].sync_pending { return; }
        self.nodes[i].sync_pending = true;
        let at = self.now + self.delay();
        self.push(at, i, Kind::Sync);
    }

    fn best_known_height(&self) -> BlockHeight {
        self.nodes.iter().enumerate().filter(|(j, _)| !self.is_byz(*j))
            .map(|(_, n)| n.committed.len() as BlockHeight).max().unwrap_or(0)
    }

    async fn sync(&mut self, i: usize) {
        self.nodes[i].sync_pending = false;
        loop {
            if self.nodes[i].done { return; }
            let Some(h) = self.nodes[i].engine.as_ref().map(|e| e.current_height()) else { return };
            let cert = (0..self.sc.n).filter(|j| !self.is_byz(*j))
                .find_map(|j| self.nodes[j].committed.get(h as usize).cloned());
            let Some(cert) = cert else { break };
            let e = self.nodes[i].engine.as_ref().unwrap();
            assert!(e.verify_commit(&cert, &sim_set(self.sc.n)).is_ok(), "synced cert must verify");
            self.nodes[i].committed.push(cert.clone());
            self.nodes[i].saved = None;
            self.nodes[i].sent.clear();
            self.out.decisions.entry(i).or_default().insert(h, cert.block_hash.clone());
            if h + 1 >= self.sc.heights { self.nodes[i].done = true; return; }
            self.nodes[i].engine.as_mut().unwrap().on_commit(cert, None).await.unwrap();
        }
        self.pump(i).await;
    }

    async fn deliver(&mut self, i: usize, msg: Msg) {
        if self.nodes[i].done { return; }
        let h = match &msg { Msg::Proposal(p) => p.height, Msg::Vote(v) => v.height };
        if !self.is_byz(i) { self.maybe_sync(i, h); }
        let byz = self.sc.byzantine.contains(&i);
        if let (true, Msg::Proposal(p)) = (byz, &msg) {
            self.seen_blocks.entry(p.height).or_default().push(p.block_hash.clone());
        }
        let Some(e) = self.nodes[i].engine.as_mut() else { return }; // not running: lost
        match msg {
            Msg::Proposal(p) => { let _ = e.receive_proposal(p).await; }
            Msg::Vote(v) => { let _ = e.receive_vote(v).await; }
        }
        self.pump(i).await;
    }

    async fn crash(&mut self, i: usize) {
        if self.nodes[i].done || self.nodes[i].engine.is_none() { return; }
        self.nodes[i].engine = None;
        self.nodes[i].incarnation += 1;
    }

    /// Restart from disk: replay committed blocks, restore the persisted
    /// lock state, then start.
    async fn restart(&mut self, i: usize) {
        if self.nodes[i].done || self.nodes[i].engine.is_some() { return; }
        let mut e = self.fresh_engine(i).await;
        for c in self.nodes[i].committed.clone() {
            e.on_commit(c, None).await.unwrap();
        }
        while e.next_action().is_some() {}
        // In-memory send log is lost; the persisted own votes survive.
        self.nodes[i].sent = self.nodes[i].saved.as_ref()
            .map(|s| s.own_votes.iter().cloned().map(Msg::Vote).collect()).unwrap_or_default();
        if let Some(saved) = self.nodes[i].saved.clone() {
            e.restore_lock_state(saved).unwrap();
        }
        e.start();
        self.nodes[i].engine = Some(e);
        self.out.restarts += 1;
        let inc = self.nodes[i].incarnation;
        self.push(self.now + REBROADCAST_MS, i, Kind::Rebroadcast(inc));
        self.pump(i).await;
    }

    async fn run(mut self) -> Outcome {
        for i in 0..self.sc.n {
            let at = self.rng.below(self.sc.start_spread.max(1));
            self.push(at, i, Kind::Start);
            if !self.is_byz(i) && self.rng.chance(self.sc.crash_pct) {
                let crash_at = at + 1_000 + self.rng.below(20_000);
                let down = 500 + self.rng.below(8_000);
                self.push(crash_at, i, Kind::Crash);
                self.push(crash_at + down, i, Kind::Restart);
            }
        }
        let mut steps = 0u64;
        while let Some(Reverse(ev)) = self.queue.pop() {
            steps += 1;
            if ev.at > self.sc.max_time || steps > 5_000_000 { break; }
            self.now = ev.at;
            match ev.kind {
                Kind::Start => {
                    let mut e = self.fresh_engine(ev.to).await;
                    e.start();
                    self.nodes[ev.to].engine = Some(e);
                    let inc = self.nodes[ev.to].incarnation;
                    if !self.is_byz(ev.to) { self.push(self.now + REBROADCAST_MS, ev.to, Kind::Rebroadcast(inc)); }
                    self.pump(ev.to).await;
                }
                Kind::Rebroadcast(inc) => {
                    if self.nodes[ev.to].incarnation != inc || self.nodes[ev.to].done || self.nodes[ev.to].engine.is_none() { continue; }
                    // Re-gossip everything held for this height (own and relayed).
                    let (props, votes) = self.nodes[ev.to].engine.as_ref().unwrap().gossip_messages();
                    for p in props { self.broadcast(ev.to, Msg::Proposal(p)); }
                    for v in votes { self.broadcast(ev.to, Msg::Vote(v)); }
                    self.push(self.now + REBROADCAST_MS, ev.to, Kind::Rebroadcast(inc));
                }
                Kind::Deliver(msg) => self.deliver(ev.to, msg).await,
                Kind::Timeout(step, h, r, inc) => {
                    if self.nodes[ev.to].incarnation != inc || self.nodes[ev.to].done { continue; }
                    if let Some(e) = self.nodes[ev.to].engine.as_mut() {
                        e.on_step_timeout(step, h, r);
                        self.pump(ev.to).await;
                    }
                    if !self.is_byz(ev.to) {
                        let best = self.best_known_height();
                        self.maybe_sync(ev.to, best);
                    }
                }
                Kind::Crash => self.crash(ev.to).await,
                Kind::Restart => self.restart(ev.to).await,
                Kind::Sync => self.sync(ev.to).await,
            }
            if !self.out.forks.is_empty() { break; }
            let all_done = (0..self.sc.n).filter(|i| !self.is_byz(*i)).all(|i| self.nodes[i].done);
            if all_done { self.out.finished = true; break; }
        }
        if !self.out.finished {
            self.out.stall = (0..self.sc.n).map(|i| match &self.nodes[i].engine {
                None => format!("val_{i:02}: down"),
                Some(e) => format!("val_{i:02}{}: done={} h={} r={} step={:?} locked={:?} valid={:?} props={:?} votes={:?} future={} queue_empty={}",
                    if self.is_byz(i) { " (byz)" } else { "" }, self.nodes[i].done, e.height, e.round, e.step,
                    e.locked.as_ref().map(|l| (&l.0 .0[..6], l.1)), e.valid.as_ref().map(|l| (&l.0 .0[..6], l.1)),
                    e.proposals.iter().map(|(r, p)| (*r, p.block_hash.0[..6].to_string(), p.pol_round)).collect::<Vec<_>>(),
                    e.votes.iter().map(|(r, rv)| (*r, rv.prevotes.len(), rv.precommits.len())).collect::<Vec<_>>(),
                    e.future_msgs.len(), self.queue.is_empty()),
            }).collect();
            self.out.stall.push(format!("time={} queue={}", self.now, self.queue.len()));
            for i in 0..self.sc.n {
                if let Some(e) = &self.nodes[i].engine {
                    for r in 0..3u32 {
                        if let Some(rv) = e.votes.get(&r) {
                            let f = |m: &BTreeMap<ValidatorId, Vec<Vote>>| m.iter().flat_map(|(k, vv)| vv.iter().map(move |v| format!("{}:{}", &k.0[4..],
                                v.block_hash.as_ref().map(|h| h.0[..4].to_string()).unwrap_or("nil".into())))).collect::<Vec<_>>().join(",");
                            self.out.stall.push(format!("  val_{i:02} r{r} prevotes[{}] precommits[{}] own={:?}", f(&rv.prevotes), f(&rv.precommits),
                                e.own_votes.iter().filter(|((rr, _), _)| *rr == r).map(|((_, t), v)| (*t, v.block_hash.as_ref().map(|h| h.0[..4].to_string()))).collect::<Vec<_>>()));
                        }
                    }
                    self.out.stall.push(format!("  val_{i:02} sent={}", self.nodes[i].sent.len()));
                }
            }
        }
        self.out
    }
}

pub(super) async fn simulate(sc: Scenario, seed: u64) -> Outcome {
    let nodes = (0..sc.n).map(|_| Node { engine: None, incarnation: 0, saved: None, committed: vec![], done: false, sync_pending: false, sent: vec![] }).collect();
    Sim {
        rng: Rng::new(seed), seq: 0, now: 0, queue: BinaryHeap::new(), nodes,
        out: Outcome::default(), signed: BTreeMap::new(), certs: BTreeMap::new(),
        seen_blocks: BTreeMap::new(), sc,
    }.run().await
}

/// Run `seeds` seeds of a scenario; assert agreement, no double signing and
/// termination. Returns the largest decision round seen (round changes were
/// exercised when > 0).
async fn check(name: &str, sc: Scenario, seeds: std::ops::Range<u64>) -> Round {
    let mut max_round = 0;
    let mut restarts = 0;
    for seed in seeds {
        let out = simulate(sc.clone(), seed).await;
        assert!(out.forks.is_empty(), "{name} seed {seed}: CONFLICTING FINALIZATION {:?}", out.forks);
        assert!(out.double_signs.is_empty(), "{name} seed {seed}: UNSAFE SIGNING {:?}", out.double_signs);
        assert!(out.finished, "{name} seed {seed}: honest validators did not finish {} heights:\n{}",
            sc.heights, out.stall.join("\n"));
        max_round = max_round.max(out.max_round);
        restarts += out.restarts;
    }
    eprintln!("{name}: ok (max decision round {max_round}, restarts {restarts})");
    max_round
}

// ── Scenarios ─────────────────────────────────────────────────────────────────

/// Required test 2 / the live MN-8 failure: five honest validators, staggered
/// startup (messages to a validator not yet running are lost), random and
/// slow links. Must never finalize conflicting blocks.
#[tokio::test]
async fn five_honest_validators_with_staggered_start_never_conflict() {
    let sc = Scenario { start_spread: 8_000, ..Scenario::honest(5) };
    let max_round = check("5 honest, staggered", sc, 0..150).await;
    assert!(max_round > 0, "scenario must exercise round changes");
}

#[tokio::test]
async fn honest_validators_with_slow_links_never_conflict() {
    for n in [4, 7] {
        let sc = Scenario { slow_pct: 25, slow_extra: 6_000, ..Scenario::honest(n) };
        check(&format!("{n} honest, slow links"), sc, 0..80).await;
    }
}

/// Required test 6 at protocol level: validators crash and restart from the
/// persisted lock state; none may sign conflicting votes or fork.
#[tokio::test]
async fn crash_restart_from_persisted_lock_state_never_signs_unsafely() {
    let sc = Scenario { crash_pct: 60, slow_pct: 20, start_spread: 3_000, ..Scenario::honest(4) };
    check("4 honest, crash/restart", sc, 0..150).await;
    let sc = Scenario { crash_pct: 50, slow_pct: 20, ..Scenario::honest(5) };
    check("5 honest, crash/restart", sc, 0..100).await;
}

/// Required test 7: equivocating Byzantine validators within f = floor((n-1)/3).
#[tokio::test]
async fn byzantine_validators_within_the_bound_cannot_cause_conflicting_finalization() {
    for adversary in [Adversary::Random, Adversary::SplitBrain, Adversary::Withhold] {
        for (n, byz) in [(4, vec![0]), (4, vec![3]), (5, vec![1]), (7, vec![0, 4])] {
            let sc = Scenario { byzantine: byz.clone(), start_spread: 2_000, slow_pct: 15, crash_pct: 20,
                                adversary, ..Scenario::honest(n) };
            check(&format!("{n} validators, byzantine {byz:?}, {adversary:?}"), sc, 0..80).await;
        }
    }
}

/// The checker must be able to fail: beyond the bound (2 of 4 Byzantine),
/// equivocation does produce conflicting finalization for some seed.
#[tokio::test]
async fn simulation_detects_forks_beyond_the_fault_bound() {
    let sc = Scenario { byzantine: vec![0, 1], heights: 3, max_time: 60_000, adversary: Adversary::SplitBrain, ..Scenario::honest(4) };
    let mut forked = 0;
    for seed in 0..40 {
        if !simulate(sc.clone(), seed).await.forks.is_empty() { forked += 1; }
    }
    assert!(forked > 0, "2 of 4 coordinated equivocators should be able to fork some run");
    eprintln!("beyond the bound: {forked}/40 runs forked (expected)");
}
