//! Tendermint BFT consensus engine.
//!
//! A direct implementation of Algorithm 1 of Buchman, Kwon & Milosevic,
//! "The latest gossip on BFT consensus" (2018). Line numbers in comments
//! (`L22`, `L36`, ...) refer to that algorithm.
//!
//! Per height a validator keeps `round`, `step`, `locked = (value, round)` and
//! `valid = (value, round)`:
//!
//! - Prevote (L22, L28): prevote a proposal only if not locked, locked on the
//!   same block, or the proposal carries a proof-of-lock round `vr` with a
//!   +2/3 prevote polka the validator has itself observed and its lock is no
//!   newer than `vr`. Otherwise prevote nil.
//! - Precommit (L36): only after observing +2/3 prevotes for the proposal in
//!   the current round; precommitting locks on the block. +2/3 nil prevotes
//!   lead to a nil precommit (L44).
//! - Decide (L49): +2/3 precommits for a block in one round, with the block's
//!   contents known.
//! - Timeouts (L57-L65) and the f+1 round skip (L55) provide liveness.
//!
//! This engine decides every vote its own validator casts and reports it as a
//! `ConsensusAction`. It never emits two votes of the same type in a round.
//! The node signs through a persisted double-sign guard and persists
//! `lock_state()` before broadcasting, so a restart cannot unlock a validator.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use tracing::{debug, info, warn};

use super::*;

// -- Round state ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Step {
    Propose,
    Prevote,
    Precommit,
}

/// Votes for one round of the current height. A validator's votes are kept
/// per distinct block (nil included), so an equivocator's vote counts toward
/// every value it signed, as in Tendermint: two +2/3 sets intersect in more
/// than f, which always includes an honest validator, who never equivocates.
#[derive(Debug, Default)]
struct RoundVotes {
    prevotes:   BTreeMap<ValidatorId, Vec<Vote>>,
    precommits: BTreeMap<ValidatorId, Vec<Vote>>,
}

/// Distinct votes kept per validator, round and type (bounded memory).
const MAX_VOTES_PER_VALIDATOR: usize = 4;

fn power_for(votes: &BTreeMap<ValidatorId, Vec<Vote>>, target: Option<&BlockHash>, vs: &ValidatorSet) -> u64 {
    votes.iter()
        .filter(|(_, vv)| vv.iter().any(|v| v.block_hash.as_ref() == target))
        .map(|(id, _)| vs.power_of(id))
        .sum()
}

fn power_any(votes: &BTreeMap<ValidatorId, Vec<Vote>>, vs: &ValidatorSet) -> u64 {
    votes.keys().map(|id| vs.power_of(id)).sum()
}

impl RoundVotes {
    fn prevote_power(&self, target: Option<&BlockHash>, vs: &ValidatorSet) -> u64 {
        power_for(&self.prevotes, target, vs)
    }
    fn prevote_power_any(&self, vs: &ValidatorSet) -> u64 {
        power_any(&self.prevotes, vs)
    }
    fn precommit_power(&self, target: &BlockHash, vs: &ValidatorSet) -> u64 {
        power_for(&self.precommits, Some(target), vs)
    }
    fn precommit_power_any(&self, vs: &ValidatorSet) -> u64 {
        power_any(&self.precommits, vs)
    }
    /// Power of distinct validators with any vote in this round (L55).
    fn participant_power(&self, vs: &ValidatorSet) -> u64 {
        let ids: BTreeSet<&ValidatorId> = self.prevotes.keys().chain(self.precommits.keys()).collect();
        ids.into_iter().map(|id| vs.power_of(id)).sum()
    }
    fn precommits_for(&self, target: &BlockHash) -> Vec<Vote> {
        self.precommits.values()
            .filter_map(|vv| vv.iter().find(|v| v.block_hash.as_ref() == Some(target)).cloned())
            .collect()
    }
    fn precommit_targets(&self) -> BTreeSet<BlockHash> {
        self.precommits.values().flatten().filter_map(|v| v.block_hash.clone()).collect()
    }
    /// Record `vote`; returns a previously recorded conflicting non-nil vote
    /// (equivocation) if any.
    fn insert(&mut self, vote: Vote) -> Option<Vote> {
        let slot = if is_prevote(&vote.vote_type) { &mut self.prevotes } else { &mut self.precommits };
        let vv = slot.entry(vote.validator.clone()).or_default();
        if vv.iter().any(|v| v.block_hash == vote.block_hash) {
            return None; // duplicate
        }
        let conflict = vote.block_hash.as_ref()
            .and_then(|_| vv.iter().find(|v| v.block_hash.is_some()).cloned());
        if vv.len() < MAX_VOTES_PER_VALIDATOR {
            vv.push(vote);
        }
        conflict
    }
    fn all(&self) -> impl Iterator<Item = &Vote> {
        self.prevotes.values().flatten().chain(self.precommits.values().flatten())
    }
}

/// Votes more than this many rounds ahead of ours are dropped (bounded memory).
const MAX_ROUNDS_AHEAD: Round = 64;
/// Bound on buffered next-height messages.
const MAX_FUTURE_MSGS: usize = 4_096;

#[derive(Debug, Clone)]
enum FutureMsg {
    Proposal(BlockProposal),
    Vote(Vote),
}

// -- Engine ----------------------------------------------------------------------

/// Tendermint-style BFT engine.
pub struct TendermintEngine {
    /// This validator's Ed25519 signing keypair. None for observer nodes.
    #[cfg(feature = "real-crypto")]
    signing_key: Option<KeyPair>,
    /// Chain ID for domain-separating signed messages.
    chain_id:      String,
    config:        Option<ConsensusConfig>,
    validator_set: Option<ValidatorSet>,
    height:        BlockHeight,
    round:         Round,
    step:          Step,
    /// L-state: block this validator is locked on, and the round it locked.
    locked:        Option<(BlockHash, Round)>,
    /// Latest block with an observed +2/3 prevote polka, and its round.
    valid:         Option<(BlockHash, Round)>,
    /// Proposal accepted for each round (from that round's proposer).
    proposals:     BTreeMap<Round, BlockProposal>,
    /// Block contents by hash, any round (commit and re-proposal).
    blocks:        BTreeMap<BlockHash, BlockProposal>,
    votes:         BTreeMap<Round, RoundVotes>,
    /// This node's validator id (None = observer).
    local_id:      Option<ValidatorId>,
    /// Votes this engine has emitted at this height, by (round, type).
    own_votes:     BTreeMap<(Round, u8), Vote>,
    /// "For the first time" latches of L34, L36 and L47.
    prevote_timeout_set:   BTreeSet<Round>,
    polka_handled:         BTreeSet<Round>,
    precommit_timeout_set: BTreeSet<Round>,
    decided:       bool,
    /// Decision reached during the current `receive_*` call (legacy return).
    just_decided:  Option<CommitCertificate>,
    /// `start()` called: emit proposer actions and timeouts.
    started:       bool,
    actions:       VecDeque<ConsensusAction>,
    /// Messages for the next height, replayed after the commit.
    future_msgs:   Vec<FutureMsg>,
    /// Equivocation evidence accumulated by receive_vote().
    /// The node drains this after each vote with `drain_equivocations()`.
    pub pending_equivocations: Vec<EquivocationDetected>,

    /// VCA-derived quorum threshold for the current epoch, used by
    /// `verify_commit`. `None` when VCA is not configured.
    pub(crate) vca_quorum: Option<u64>,
}

/// Evidence of a double-sign detected by the consensus engine.
/// Both votes are from the same validator, same height+round, same phase,
/// but for different block hashes.
#[derive(Debug, Clone)]
pub struct EquivocationDetected {
    pub validator_id:   ValidatorId,
    pub height:         BlockHeight,
    pub round:          Round,
    /// 0 = Prevote, 1 = Precommit (matches vote_signing_bytes encoding).
    pub vote_type_byte: u8,
    pub block_hash_a:   BlockHash,
    pub block_hash_b:   BlockHash,
    /// Raw signature bytes from the first vote (already accepted).
    pub signature_a:    Vec<u8>,
    /// Raw signature bytes from the conflicting vote (just arrived).
    pub signature_b:    Vec<u8>,
}

fn is_prevote(t: &VoteType) -> bool {
    matches!(t, VoteType::Prevote | VoteType::Nil)
}

fn type_byte(t: &VoteType) -> u8 {
    if is_prevote(t) { 0 } else { 1 }
}

impl TendermintEngine {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "real-crypto")]
            signing_key:           None,
            chain_id:              String::new(),
            config:                None,
            validator_set:         None,
            height:                0,
            round:                 0,
            step:                  Step::Propose,
            locked:                None,
            valid:                 None,
            proposals:             BTreeMap::new(),
            blocks:                BTreeMap::new(),
            votes:                 BTreeMap::new(),
            local_id:              None,
            own_votes:             BTreeMap::new(),
            prevote_timeout_set:   BTreeSet::new(),
            polka_handled:         BTreeSet::new(),
            precommit_timeout_set: BTreeSet::new(),
            decided:               false,
            just_decided:          None,
            started:               false,
            actions:               VecDeque::new(),
            future_msgs:           Vec::new(),
            pending_equivocations: Vec::new(),
            vca_quorum:            None,
        }
    }

    /// Drain and return any equivocations detected since the last call.
    pub fn drain_equivocations(&mut self) -> Vec<EquivocationDetected> {
        std::mem::take(&mut self.pending_equivocations)
    }

    /// Set the signing key for this validator. Does nothing without the
    /// real-crypto feature.
    #[cfg(feature = "real-crypto")]
    pub fn set_signing_key(&mut self, key: KeyPair, chain_id: String) {
        self.signing_key = Some(key);
        self.chain_id = chain_id;
    }
    #[cfg(not(feature = "real-crypto"))]
    pub fn set_signing_key(&mut self, _key: (), chain_id: String) {
        self.chain_id = chain_id;
    }

    /// Proposer for (height, round): round-robin over the validator set
    /// sorted by id, rotated by height + round.
    pub(crate) fn proposer_for(&self, height: BlockHeight, round: Round) -> Option<ValidatorId> {
        let vs = self.validator_set.as_ref()?;
        if vs.validators.is_empty() {
            return None;
        }
        let mut sorted: Vec<_> = vs.validators.iter().collect();
        sorted.sort_by_key(|v| &v.id);
        let idx = ((height + round as u64) as usize) % sorted.len();
        Some(sorted[idx].id.clone())
    }

    fn require_config(&self) -> ConsensusResult<&ConsensusConfig> {
        self.config.as_ref().ok_or_else(|| ConsensusError::Internal("engine not initialised".into()))
    }

    fn require_validator_set(&self) -> ConsensusResult<&ValidatorSet> {
        self.validator_set.as_ref().ok_or_else(|| ConsensusError::Internal("validator set not loaded".into()))
    }

    /// +2/3 of total voting power.
    fn quorum(&self) -> u64 {
        self.validator_set.as_ref().map(|vs| vs.quorum_power()).unwrap_or(u64::MAX)
    }

    /// f+1: more than 1/3 of total voting power (any such set holds an honest validator).
    fn skip_threshold(&self) -> u64 {
        let vs = match self.validator_set.as_ref() { Some(vs) => vs, None => return u64::MAX };
        vs.total_power().saturating_sub(vs.quorum_power()) + 1
    }

    fn local_power(&self) -> u64 {
        match (&self.local_id, &self.validator_set) {
            (Some(id), Some(vs)) => vs.power_of(id),
            _ => 0,
        }
    }

    fn timeout_ms(&self, step: TimeoutStep, round: Round) -> u64 {
        let (base, fallback) = match (&self.config, step) {
            (Some(c), TimeoutStep::Propose)   => (c.propose_timeout_ms, 3_000),
            (Some(c), TimeoutStep::Prevote)   => (c.prevote_timeout_ms, 1_000),
            (Some(c), TimeoutStep::Precommit) => (c.precommit_timeout_ms, 1_000),
            (None, _) => (0, 1_000),
        };
        let base = if base == 0 { fallback } else { base };
        // Grows linearly with the round so a slow network eventually fits.
        base + (round as u64) * (base / 2).max(1)
    }

    fn schedule(&mut self, step: TimeoutStep, round: Round) {
        if !self.started { return; }
        let after_ms = self.timeout_ms(step, round);
        self.actions.push_back(ConsensusAction::ScheduleTimeout { step, height: self.height, round, after_ms });
    }

    /// Emit this validator's vote for (current height, `round`), at most once
    /// per (round, type) -- ever, including after a restart (own_votes is
    /// part of the persisted lock state).
    fn emit_vote(&mut self, vote_type: VoteType, round: Round, block_hash: Option<BlockHash>) {
        let Some(id) = self.local_id.clone() else { return };
        if self.local_power() == 0 { return; }
        let key = (round, type_byte(&vote_type));
        if self.own_votes.contains_key(&key) { return; }
        let vote = Vote {
            vote_type, height: self.height, round, validator: id, block_hash,
            signature: vec![], scheme: Vote::default_scheme(),
        };
        self.own_votes.insert(key, vote.clone());
        self.actions.push_back(ConsensusAction::CastVote(vote));
    }

    /// L11 StartRound.
    fn start_round(&mut self, round: Round) {
        self.round = round;
        self.step = Step::Propose;
        if self.started && self.local_power() > 0 && self.proposer_for(self.height, round) == self.local_id {
            match self.valid.clone().and_then(|(h, vr)| self.blocks.get(&h).map(|b| (b.clone(), vr))) {
                // L15: re-propose the valid block with its proof-of-lock round.
                Some((block, vr)) => {
                    let proposal = BlockProposal {
                        round,
                        proposer: self.local_id.clone().unwrap(),
                        pol_round: Some(vr),
                        signature: vec![],
                        ..block
                    };
                    self.proposals.insert(round, proposal.clone());
                    self.actions.push_back(ConsensusAction::Repropose(proposal));
                }
                None => self.actions.push_back(ConsensusAction::ProposeNew { height: self.height, round }),
            }
        }
        self.schedule(TimeoutStep::Propose, round);
    }

    fn round_votes(&self, round: Round) -> Option<&RoundVotes> {
        self.votes.get(&round)
    }

    fn prevote_power(&self, round: Round, target: Option<&BlockHash>) -> u64 {
        match (self.round_votes(round), &self.validator_set) {
            (Some(rv), Some(vs)) => rv.prevote_power(target, vs),
            _ => 0,
        }
    }

    /// Re-evaluate every upon-rule until none fires.
    fn evaluate(&mut self) {
        loop {
            if self.try_decide() { return; }
            if self.try_round_skip() { continue; }
            let mut progressed = self.rule_prevote_on_proposal();
            self.rule_prevote_timeout();
            progressed |= self.rule_polka_lock();
            progressed |= self.rule_polka_nil();
            self.rule_precommit_timeout();
            if !progressed { return; }
        }
    }

    /// L49: +2/3 precommits for a block in some round, contents known.
    fn try_decide(&mut self) -> bool {
        if self.decided { return false; }
        let (Some(vs), quorum) = (self.validator_set.as_ref(), self.quorum()) else { return false };
        let mut decision = None;
        'rounds: for (round, rv) in &self.votes {
            for target in rv.precommit_targets() {
                if rv.precommit_power(&target, vs) >= quorum {
                    if let Some(block) = self.blocks.get(&target) {
                        decision = Some((*round, target.clone(), rv.precommits_for(&target), block.clone()));
                        break 'rounds;
                    }
                }
            }
        }
        let Some((round, block_hash, precommits, block)) = decision else { return false };
        info!(height = self.height, round, block_hash = %block_hash,
              precommit_count = precommits.len(), "precommit quorum reached - committing block");
        let certificate = CommitCertificate { height: self.height, round, block_hash, precommits };
        self.decided = true;
        self.just_decided = Some(certificate.clone());
        self.actions.push_back(ConsensusAction::Commit { certificate, proposal: block });
        true
    }

    /// L55: f+1 voting power already in a later round -> join it.
    fn try_round_skip(&mut self) -> bool {
        let Some(vs) = self.validator_set.as_ref() else { return false };
        let threshold = self.skip_threshold();
        let target = self.votes.range(self.round + 1..)
            .filter(|(_, rv)| rv.participant_power(vs) >= threshold)
            .map(|(r, _)| *r)
            .max();
        match target {
            Some(r) => {
                debug!(height = self.height, from = self.round, to = r, "f+1 votes in a later round: skipping ahead");
                self.start_round(r);
                true
            }
            None => false,
        }
    }

    /// L22 / L28: prevote on the current round's proposal.
    fn rule_prevote_on_proposal(&mut self) -> bool {
        if self.step != Step::Propose { return false; }
        let Some(p) = self.proposals.get(&self.round) else { return false };
        let (hash, pol_round) = (p.block_hash.clone(), p.pol_round);
        let vote = match pol_round {
            // L22: fresh proposal.
            None => match &self.locked {
                None => Some(hash),
                Some((locked, _)) if *locked == hash => Some(hash),
                Some(_) => None,
            },
            // L28: re-proposal; needs the polka in `vr` observed locally.
            Some(vr) => {
                if vr >= self.round || self.prevote_power(vr, Some(&hash)) < self.quorum() {
                    return false; // wait for the proof (or the propose timeout)
                }
                match &self.locked {
                    None => Some(hash),
                    Some((locked, lr)) if *lr <= vr || *locked == hash => Some(hash),
                    Some(_) => None,
                }
            }
        };
        let round = self.round;
        self.emit_vote(VoteType::Prevote, round, vote);
        self.step = Step::Prevote;
        true
    }

    /// L34: +2/3 prevotes of any kind -> schedule the prevote timeout once.
    fn rule_prevote_timeout(&mut self) {
        if self.step != Step::Prevote || self.prevote_timeout_set.contains(&self.round) { return; }
        let any = match (self.round_votes(self.round), &self.validator_set) {
            (Some(rv), Some(vs)) => rv.prevote_power_any(vs),
            _ => 0,
        };
        if any >= self.quorum() {
            self.prevote_timeout_set.insert(self.round);
            self.schedule(TimeoutStep::Prevote, self.round);
        }
    }

    /// L36: proposal + +2/3 prevotes for it in this round -> lock and precommit.
    fn rule_polka_lock(&mut self) -> bool {
        if self.step < Step::Prevote || self.polka_handled.contains(&self.round) { return false; }
        let Some(p) = self.proposals.get(&self.round) else { return false };
        let hash = p.block_hash.clone();
        if self.prevote_power(self.round, Some(&hash)) < self.quorum() { return false; }
        let round = self.round;
        self.polka_handled.insert(round);
        if self.step == Step::Prevote {
            self.locked = Some((hash.clone(), round));
            self.emit_vote(VoteType::Precommit, round, Some(hash.clone()));
            self.step = Step::Precommit;
        }
        self.valid = Some((hash, round));
        true
    }

    /// L44: +2/3 nil prevotes -> precommit nil.
    fn rule_polka_nil(&mut self) -> bool {
        if self.step != Step::Prevote { return false; }
        if self.prevote_power(self.round, None) < self.quorum() { return false; }
        let round = self.round;
        self.emit_vote(VoteType::Precommit, round, None);
        self.step = Step::Precommit;
        true
    }

    /// L47: +2/3 precommits of any kind -> schedule the precommit timeout once.
    fn rule_precommit_timeout(&mut self) {
        if self.precommit_timeout_set.contains(&self.round) { return; }
        let any = match (self.round_votes(self.round), &self.validator_set) {
            (Some(rv), Some(vs)) => rv.precommit_power_any(vs),
            _ => 0,
        };
        if any >= self.quorum() {
            self.precommit_timeout_set.insert(self.round);
            self.schedule(TimeoutStep::Precommit, self.round);
        }
    }

    /// Reset per-height state for `height`, round 0.
    fn reset_height_state(&mut self, height: BlockHeight) {
        self.height = height;
        self.round = 0;
        self.step = Step::Propose;
        self.locked = None;
        self.valid = None;
        self.proposals.clear();
        self.blocks.clear();
        self.votes.clear();
        self.own_votes.clear();
        self.prevote_timeout_set.clear();
        self.polka_handled.clear();
        self.precommit_timeout_set.clear();
        self.decided = false;
        self.just_decided = None;
        // Anything still queued belongs to the previous height.
        self.actions.clear();
        self.future_msgs.retain(|m| match m {
            FutureMsg::Proposal(p) => p.height == height,
            FutureMsg::Vote(v) => v.height == height,
        });
    }

    #[cfg(feature = "real-crypto")]
    fn verify_vote_sig(&self, vote: &Vote) -> ConsensusResult<()> {
        let vs = self.require_validator_set()?;
        let pub_key = vs.public_key_of(&vote.validator);
        if pub_key.is_empty() {
            return Ok(()); // Phase-0 tolerance: no key on file
        }
        let invalid = |reason: String| ConsensusError::InvalidVote {
            validator:  vote.validator.clone(),
            block_hash: vote.block_hash.clone().unwrap_or_else(|| BlockHash("nil".into())),
            reason,
        };
        if vote.signature.is_empty() {
            return Err(invalid("validator has a registered key but vote carries \
                                an empty signature (possible forgery)".into()));
        }
        let msg = vote_signing_bytes(&self.chain_id, &vote.vote_type, vote.height, vote.round, vote.block_hash.as_ref());
        let sig = Signature { scheme: SchemeId::Classical, bytes: vote.signature.clone() };
        ClassicalScheme.verify(&msg, &sig, pub_key).map_err(|e| invalid(format!("invalid signature: {e}")))
    }

    fn record_equivocation(&mut self, existing: &Vote, vote: &Vote) {
        let hash_a = existing.block_hash.clone().unwrap_or_else(|| BlockHash("nil".into()));
        let hash_b = vote.block_hash.clone().unwrap_or_else(|| BlockHash("nil".into()));
        let kind = if is_prevote(&vote.vote_type) { "double-prevote" } else { "double-precommit" };
        warn!(validator = %vote.validator, height = vote.height, round = vote.round,
              hash_a = %hash_a, hash_b = %hash_b, "equivocation detected: {kind} (two real blocks)");
        self.pending_equivocations.push(EquivocationDetected {
            validator_id:   vote.validator.clone(),
            height:         vote.height,
            round:          vote.round,
            vote_type_byte: type_byte(&vote.vote_type),
            block_hash_a:   hash_a,
            block_hash_b:   hash_b,
            signature_a:    existing.signature.clone(),
            signature_b:    vote.signature.clone(),
        });
    }

    fn apply_epoch_set(&mut self, incoming_vs: ValidatorSet) -> ConsensusResult<ValidatorSet> {
        let epoch = self.height;
        if let Some(vca_cfg) = self.config.as_ref().and_then(|c| c.vca.as_ref()) {
            let registry = build_vca_registry_from_validator_set(epoch, &incoming_vs, vca_cfg.weight_config.clone());
            return match compute_adaptive_quorum(&registry, &vca_cfg.quorum_config) {
                Ok(q) => {
                    let mut vs = incoming_vs;
                    apply_vca_weights_to_validator_set(&mut vs, &registry);
                    let q = floored_quorum(Some(q), &vs);
                    self.vca_quorum = Some(q);
                    tracing::info!(epoch, validators = vs.validators.len(), total_weight = vs.total_power(),
                        vca_quorum = q, "VCA-PQ-BFT epoch rotation: weights and adaptive quorum updated");
                    Ok(vs)
                }
                Err(VcaError::EmergencyQuorum) => {
                    tracing::error!(epoch, "VCA epoch rotation: all personhood expired — EmergencyQuorum \
                        (chain requires reconfiguration; keeping old validator set)");
                    Err(ConsensusError::Internal("VCA epoch error: all validators have expired personhood — \
                        emergency reconfiguration required".into()))
                }
                Err(e) => {
                    tracing::error!(epoch, error = %e, "VCA epoch quorum computation failed");
                    Err(ConsensusError::Internal(format!("VCA epoch error: {e}")))
                }
            };
        }
        Ok(match self.config.as_ref().and_then(|c| c.personhood.clone()) {
            Some(pop_cfg) => apply_personhood_cap(incoming_vs, &pop_cfg),
            None => incoming_vs,
        })
    }
    fn handle_proposal(&mut self, proposal: BlockProposal) -> ConsensusResult<()> {
        self.require_validator_set()?;
        if proposal.height == self.height + 1 {
            self.buffer_future(FutureMsg::Proposal(proposal));
            return Ok(());
        }
        if proposal.height != self.height {
            return Err(ConsensusError::StaleMessage(proposal.height, self.height));
        }
        let expected = self.proposer_for(proposal.height, proposal.round)
            .ok_or_else(|| ConsensusError::Internal("empty validator set".into()))?;
        if proposal.proposer != expected {
            return Err(ConsensusError::MalformedProposal(format!(
                "wrong proposer: got {}, expected {}", proposal.proposer, expected)));
        }
        // The block hash is the value voted on: it must commit to the contents.
        let computed = compute_block_hash(&self.chain_id, proposal.height, &proposal.parent_hash, &proposal.tx_data);
        if computed != proposal.block_hash {
            return Err(ConsensusError::MalformedProposal(format!(
                "block_hash {} does not match contents ({computed})", proposal.block_hash)));
        }
        if let Some(vr) = proposal.pol_round {
            if vr >= proposal.round {
                return Err(ConsensusError::MalformedProposal(format!(
                    "pol_round {vr} must be below the proposal round {}", proposal.round)));
            }
        }
        // Fail closed (release gate 1): a proposer with a registered key
        // must sign, over the content including pol_round.
        #[cfg(feature = "real-crypto")]
        {
            let vs = self.require_validator_set()?;
            let pub_key = vs.public_key_of(&proposal.proposer);
            if !pub_key.is_empty() {
                if proposal.signature.is_empty() {
                    return Err(ConsensusError::MalformedProposal(format!(
                        "unsigned proposal from {}, who has a registered key", proposal.proposer)));
                }
                let msg = proposal_signing_bytes(&self.chain_id, proposal.height, proposal.round,
                    &proposal.block_hash, &proposal.parent_hash, proposal.pol_round);
                let sig = Signature { scheme: SchemeId::Classical, bytes: proposal.signature.clone() };
                ClassicalScheme.verify(&msg, &sig, pub_key).map_err(|_|
                    ConsensusError::MalformedProposal(format!("invalid signature from proposer {}", proposal.proposer)))?;
            }
        }
        if let Some(existing) = self.proposals.get(&proposal.round) {
            if existing.block_hash == proposal.block_hash {
                // Our own unsigned copy is replaced by the signed one the
                // node produced, so re-gossip sends a verifiable proposal.
                if existing.signature.is_empty() && !proposal.signature.is_empty()
                    && existing.pol_round == proposal.pol_round
                {
                    self.proposals.insert(proposal.round, proposal);
                }
                return Ok(()); // duplicate
            }
            return Err(ConsensusError::MalformedProposal(format!(
                "proposer {} already proposed {} in round {}", proposal.proposer, existing.block_hash, proposal.round)));
        }
        debug!(height = proposal.height, round = proposal.round, block_hash = %proposal.block_hash,
               pol_round = ?proposal.pol_round, "accepted proposal");
        self.blocks.entry(proposal.block_hash.clone()).or_insert_with(|| proposal.clone());
        self.proposals.insert(proposal.round, proposal);
        self.just_decided = None;
        self.evaluate();
        Ok(())
    }

    fn handle_vote(&mut self, vote: Vote) -> ConsensusResult<Option<CommitCertificate>> {
        let vs = self.require_validator_set()?;
        if vote.height == self.height + 1 {
            self.buffer_future(FutureMsg::Vote(vote));
            return Ok(None);
        }
        if vote.height != self.height {
            return Err(ConsensusError::StaleMessage(vote.height, self.height));
        }
        if vs.power_of(&vote.validator) == 0 {
            return Err(ConsensusError::UnknownValidator(vote.validator.clone()));
        }
        if vote.round > self.round.saturating_add(MAX_ROUNDS_AHEAD) {
            return Err(ConsensusError::Internal(format!(
                "vote for round {} is too far ahead of round {}", vote.round, self.round)));
        }
        #[cfg(feature = "real-crypto")]
        self.verify_vote_sig(&vote)?;

        // Equivocation: two different non-nil blocks, same validator, same
        // (height, round, type). Nil-vs-block is not a double-sign. Both
        // votes are kept and counted per value (see RoundVotes).
        let round = vote.round;
        if let Some(existing) = self.votes.entry(round).or_default().insert(vote.clone()) {
            self.record_equivocation(&existing, &vote);
        }
        self.just_decided = None;
        self.evaluate();
        Ok(self.just_decided.take())
    }

    /// Keep a message for the next height (it arrived while this validator
    /// was still finishing the current one); replayed after `on_commit`.
    fn buffer_future(&mut self, msg: FutureMsg) {
        if self.future_msgs.len() < MAX_FUTURE_MSGS {
            self.future_msgs.push(msg);
        }
    }

    /// Replay buffered messages that belong to the (new) current height.
    fn replay_future(&mut self) {
        let msgs = std::mem::take(&mut self.future_msgs);
        for m in msgs {
            let ok = match m {
                FutureMsg::Proposal(p) => self.handle_proposal(p).map(|_| ()),
                FutureMsg::Vote(v) => self.handle_vote(v).map(|_| ()),
            };
            if let Err(e) = ok { debug!(error = %e, "buffered message rejected at its height"); }
        }
    }

}

impl Default for TendermintEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ConsensusEngine for TendermintEngine {
    fn name(&self) -> &str {
        "Tendermint-style BFT"
    }

    fn variant(&self) -> ConsensusVariant {
        ConsensusVariant::TendermintStyle
    }

    async fn init(&mut self, config: ConsensusConfig, genesis_validators: ValidatorSet) -> ConsensusResult<()> {
        // VCA path: build registry, apply relative weight cap, rewrite
        // voting_power with VCA-derived ConsensusWeight, compute adaptive quorum.
        let vs = if let Some(vca_cfg) = &config.vca {
            let registry = build_vca_registry_from_validator_set(0, &genesis_validators, vca_cfg.weight_config.clone());
            match compute_adaptive_quorum(&registry, &vca_cfg.quorum_config) {
                Ok(q) => {
                    let mut vs = genesis_validators;
                    apply_vca_weights_to_validator_set(&mut vs, &registry);
                    let q = floored_quorum(Some(q), &vs);
                    self.vca_quorum = Some(q);
                    tracing::info!(epoch = 0, validators = vs.validators.len(), total_weight = vs.total_power(),
                        vca_quorum = q, "VCA-PQ-BFT genesis: weights and adaptive quorum set");
                    vs
                }
                Err(VcaError::EmergencyQuorum) => {
                    tracing::error!("genesis VCA registry: all personhood expired — EmergencyQuorum");
                    return Err(ConsensusError::Internal(
                        "VCA genesis error: all validators have expired personhood".into()));
                }
                Err(e) => {
                    tracing::error!(error = %e, "VCA genesis quorum computation failed");
                    return Err(ConsensusError::Internal(format!("VCA genesis error: {e}")));
                }
            }
        } else if let Some(pop_cfg) = &config.personhood {
            apply_personhood_cap(genesis_validators, pop_cfg)
        } else {
            genesis_validators
        };

        if vs.validators.len() < 4 {
            warn!(count = vs.validators.len(),
                "validator set below 4 - BFT safety threshold cannot be met; \
                 this is only acceptable for devnet/single-node testing");
        }
        info!(variant = %self.name(), validators = vs.validators.len(), total_power = vs.total_power(),
              quorum_power = vs.quorum_power(), vca_enabled = config.vca.is_some(), "consensus engine initialised");

        self.chain_id = config.chain_id.clone();
        self.validator_set = Some(vs);
        self.config = Some(config);
        self.reset_height_state(0);
        Ok(())
    }

    fn validator_set(&self) -> &ValidatorSet {
        self.validator_set.as_ref().expect("validator_set() called before init()")
    }

    fn update_validator_set(&mut self, mut vs: ValidatorSet) -> Result<(), ConsensusError> {
        if let Some(pc) = self.config.as_ref().and_then(|c| c.personhood.clone()) {
            vs = apply_personhood_cap(vs, &pc);
        }
        // Unconditional key/verification gate, last.
        vs = gate_voting_power(vs);
        self.validator_set = Some(vs);
        Ok(())
    }

    async fn propose(
        &mut self,
        height: BlockHeight,
        round: Round,
        parent_hash: BlockHash,
        tx_data: Vec<u8>,
    ) -> ConsensusResult<BlockProposal> {
        self.require_config()?;
        self.require_validator_set()?;
        if height != self.height {
            return Err(ConsensusError::StaleMessage(height, self.height));
        }
        if round != self.round || self.step != Step::Propose {
            return Err(ConsensusError::Internal(format!(
                "cannot propose for round {round}: engine is at round {} step {:?}", self.round, self.step)));
        }
        if self.proposals.contains_key(&round) {
            return Err(ConsensusError::Internal(format!("round {round} already has a proposal")));
        }
        let proposer = self.proposer_for(height, round)
            .ok_or_else(|| ConsensusError::Internal("empty validator set".into()))?;
        let block_hash = compute_block_hash(&self.chain_id, height, &parent_hash, &tx_data);
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;

        #[cfg(feature = "real-crypto")]
        let signature = match self.signing_key {
            Some(ref kp) => {
                let bytes = proposal_signing_bytes(&self.chain_id, height, round, &block_hash, &parent_hash, None);
                ClassicalScheme.sign(&bytes, kp).map(|s| s.bytes).unwrap_or_default()
            }
            None => vec![],
        };
        #[cfg(not(feature = "real-crypto"))]
        let signature = vec![];

        let proposal = BlockProposal {
            height, round, proposer, block_hash: block_hash.clone(), parent_hash,
            timestamp_ms, tx_data, signature, pol_round: None,
        };
        debug!(height, round, block_hash = %block_hash, "produced proposal");
        self.proposals.insert(round, proposal.clone());
        self.blocks.entry(block_hash).or_insert_with(|| proposal.clone());
        self.just_decided = None;
        self.evaluate();
        Ok(proposal)
    }

    async fn receive_proposal(&mut self, proposal: BlockProposal) -> ConsensusResult<()> {
        self.handle_proposal(proposal)
    }

    async fn receive_vote(&mut self, vote: Vote) -> ConsensusResult<Option<CommitCertificate>> {
        self.handle_vote(vote)
    }

    async fn on_timeout(&mut self, height: BlockHeight, round: Round) -> ConsensusResult<Vote> {
        // Legacy entry point (node round watchdog). The state machine uses
        // `on_step_timeout`; this jumps straight to round + 1.
        if height != self.height {
            return Err(ConsensusError::Timeout(height, 0));
        }
        warn!(height, round, "round timed out - advancing to round {}", round + 1);
        self.start_round(round + 1);
        self.evaluate();
        Ok(Vote {
            vote_type: VoteType::Nil, height: self.height, round: self.round,
            validator: ValidatorId("self".into()), block_hash: None,
            signature: vec![], scheme: Vote::default_scheme(),
        })
    }

    async fn on_commit(
        &mut self,
        certificate: CommitCertificate,
        new_validator_set: Option<ValidatorSet>,
    ) -> ConsensusResult<()> {
        info!(height = certificate.height, round = certificate.round, block_hash = %certificate.block_hash,
              "block committed - advancing height");
        self.reset_height_state(certificate.height + 1);
        if let Some(incoming_vs) = new_validator_set {
            let vs = self.apply_epoch_set(incoming_vs)?;
            info!(new_height = self.height, new_validator_count = vs.validators.len(),
                  "validator set rotated for new epoch");
            self.validator_set = Some(vs);
        }
        self.start_round(0);
        self.evaluate();
        self.replay_future();
        Ok(())
    }

    fn current_height(&self) -> BlockHeight {
        self.height
    }

    fn current_round(&self) -> Round {
        self.round
    }

    fn verify_commit(&self, certificate: &CommitCertificate, validator_set: &ValidatorSet) -> ConsensusResult<()> {
        // Never below ⌊2·total/3⌋+1 of the set being verified (gate 3).
        let quorum = floored_quorum(self.vca_quorum, validator_set);

        // Only precommits for exactly this (height, round, block) count, and
        // each validator at most once.
        let mut seen = BTreeSet::new();
        let valid_precommits: Vec<&Vote> = certificate.precommits.iter()
            .filter(|v| v.vote_type == VoteType::Precommit
                && v.height == certificate.height
                && v.round == certificate.round
                && v.block_hash.as_ref() == Some(&certificate.block_hash))
            .filter(|v| seen.insert(v.validator.clone()))
            .collect();

        // Fail-closed: a validator with a registered key must have signed.
        #[cfg(feature = "real-crypto")]
        for vote in &valid_precommits {
            let pub_key = validator_set.public_key_of(&vote.validator);
            if pub_key.is_empty() { continue; }
            if vote.signature.is_empty() {
                return Err(ConsensusError::InvalidVote {
                    validator:  vote.validator.clone(),
                    block_hash: certificate.block_hash.clone(),
                    reason:     format!("validator {} has a registered key but precommit in commit \
                                         certificate carries an empty signature (possible forgery)", vote.validator),
                });
            }
            let msg = vote_signing_bytes(&self.chain_id, &vote.vote_type, vote.height, vote.round, vote.block_hash.as_ref());
            let sig = Signature { scheme: SchemeId::Classical, bytes: vote.signature.clone() };
            ClassicalScheme.verify(&msg, &sig, pub_key).map_err(|_| ConsensusError::InvalidVote {
                validator:  vote.validator.clone(),
                block_hash: certificate.block_hash.clone(),
                reason:     format!("invalid precommit signature in commit certificate at height {} round {}",
                                    vote.height, vote.round),
            })?;
        }

        let signed_power: u64 = valid_precommits.iter().map(|v| validator_set.power_of(&v.validator)).sum();
        if signed_power < quorum {
            return Err(ConsensusError::InvalidVote {
                validator:  ValidatorId("(commit)".into()),
                block_hash: certificate.block_hash.clone(),
                reason:     format!("commit certificate has {signed_power} power but quorum requires {quorum}"),
            });
        }
        Ok(())
    }

    fn drain_equivocations(&mut self) -> Vec<EquivocationDetected> {
        std::mem::take(&mut self.pending_equivocations)
    }

    fn reset_to_height(&mut self, height: BlockHeight, validator_set: ValidatorSet) -> ConsensusResult<()> {
        // Restart recovery: resume at `height` (last committed + 1). Lock
        // state for this height, if any, is restored separately by
        // `restore_lock_state` before this validator votes.
        let validator_set = gate_voting_power(validator_set);
        self.validator_set = Some(validator_set);
        self.reset_height_state(height);
        tracing::info!(height, "Tendermint engine fast-forwarded to persisted height");
        Ok(())
    }

    fn drives_own_votes(&self) -> bool {
        true
    }

    fn set_local_validator(&mut self, id: Option<ValidatorId>) {
        self.local_id = id;
    }

    fn start(&mut self) {
        if self.started { return; }
        self.started = true;
        // Re-enter the current round so proposer duty and timeouts are emitted.
        let (round, step) = (self.round, self.step);
        self.start_round(round);
        // start_round resets the step; never move backwards (restored state).
        if step > self.step { self.step = step; }
        self.evaluate();
    }

    fn on_step_timeout(&mut self, step: TimeoutStep, height: BlockHeight, round: Round) {
        if height != self.height || round != self.round { return; }
        match step {
            // L57: no acceptable proposal in time -> prevote nil.
            TimeoutStep::Propose if self.step == Step::Propose => {
                self.emit_vote(VoteType::Prevote, round, None);
                self.step = Step::Prevote;
            }
            // L61: no polka in time -> precommit nil.
            TimeoutStep::Prevote if self.step == Step::Prevote => {
                self.emit_vote(VoteType::Precommit, round, None);
                self.step = Step::Precommit;
            }
            // L65: no decision in time -> next round.
            TimeoutStep::Precommit if !self.decided => self.start_round(round + 1),
            _ => return,
        }
        self.evaluate();
    }

    fn next_action(&mut self) -> Option<ConsensusAction> {
        self.actions.pop_front()
    }

    fn gossip_messages(&self) -> (Vec<BlockProposal>, Vec<Vote>) {
        (self.proposals.values().cloned().collect(),
         self.votes.values().flat_map(|rv| rv.all().cloned()).collect())
    }

    fn lock_state(&self) -> Option<LockState> {
        let mut blocks = vec![];
        for (h, _) in self.locked.iter().chain(self.valid.iter()) {
            if let Some(b) = self.blocks.get(h) {
                if !blocks.iter().any(|x: &BlockProposal| x.block_hash == b.block_hash) {
                    blocks.push(b.clone());
                }
            }
        }
        Some(LockState {
            height:    self.height,
            round:     self.round,
            locked:    self.locked.clone(),
            valid:     self.valid.clone(),
            blocks,
            own_votes: self.own_votes.values().cloned().collect(),
        })
    }

    fn restore_lock_state(&mut self, state: LockState) -> ConsensusResult<()> {
        if state.height != self.height {
            return Ok(()); // a finished height; nothing to restore
        }
        for b in state.blocks {
            let computed = compute_block_hash(&self.chain_id, b.height, &b.parent_hash, &b.tx_data);
            if computed != b.block_hash || b.height != self.height {
                return Err(ConsensusError::Internal(format!(
                    "persisted lock block {} does not match its contents", b.block_hash)));
            }
            self.blocks.insert(b.block_hash.clone(), b);
        }
        self.locked = state.locked;
        self.valid = state.valid;
        for v in state.own_votes {
            if v.height != self.height { continue; }
            // Our own signed votes count in our own tallies too (a restart
            // must not lose the polka our own vote completes).
            self.votes.entry(v.round).or_default().insert(v.clone());
            self.own_votes.insert((v.round, type_byte(&v.vote_type)), v);
        }
        // Resume no earlier than the persisted round, and past any step this
        // validator already voted in.
        self.round = self.round.max(state.round);
        self.step = if self.own_votes.contains_key(&(self.round, 1)) {
            Step::Precommit
        } else if self.own_votes.contains_key(&(self.round, 0)) {
            Step::Prevote
        } else {
            Step::Propose
        };
        info!(height = self.height, round = self.round, locked = ?self.locked.as_ref().map(|l| &l.0),
              own_votes = self.own_votes.len(), "restored consensus lock state");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod sim;
