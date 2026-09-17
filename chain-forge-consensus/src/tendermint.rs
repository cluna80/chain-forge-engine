/// Tendermint-style BFT consensus engine.
///
/// Implements the `ConsensusEngine` trait using a two-phase rotating-proposer
/// protocol: Propose -> Prevote -> Precommit -> Commit.
///
/// This is the first concrete BFT variant in Chain Forge, and the one QCB's
/// testnet runs. Personhood-weighting (Whitepaper Section 3) is applied via
/// `apply_personhood_cap` before any voting math - the algorithm itself is
/// standard Tendermint; personhood is enforced at the validator-set layer.
///
/// What this file implements (Phase 0 - testnet-ready):
///   - Proposer rotation (round-robin by validator index)
///   - Prevote and precommit accumulation
///   - Quorum detection -> CommitCertificate
///   - Round timeout handling (nil votes)
///   - Height advancement on commit
///   - Commit certificate verification (for light clients / sync)
///
/// What is NOT here yet (will be added as the engine matures):
///   - Real signature verification (crypto layer not wired up)
///   - Network I/O (P2P crate handles that)
///   - Persistent state / WAL (needed before mainnet)
///   - Evidence handling for equivocation (Open Question 13)

use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use crate::{
    apply_personhood_cap, BlockHash, BlockHeight, BlockProposal, CommitCertificate,
    ConsensusConfig, ConsensusEngine, ConsensusError, ConsensusResult, ConsensusVariant,
    Round, ValidatorId, ValidatorSet, Vote, VoteType,
};

// -- Internal round state -----------------------------------------------------

/// All votes accumulated for one (height, round) pair.
#[derive(Debug, Default)]
struct RoundVotes {
    prevotes:   BTreeMap<ValidatorId, Vote>,
    precommits: BTreeMap<ValidatorId, Vote>,
}

impl RoundVotes {
    /// Sum of voting power behind prevotes for a specific block hash.
    fn prevote_power(&self, block_hash: &BlockHash, validator_set: &ValidatorSet) -> u64 {
        self.prevotes
            .iter()
            .filter(|(_, v)| v.block_hash.as_ref() == Some(block_hash))
            .map(|(id, _)| validator_set.power_of(id))
            .sum()
    }

    /// Sum of voting power behind precommits for a specific block hash.
    fn precommit_power(&self, block_hash: &BlockHash, validator_set: &ValidatorSet) -> u64 {
        self.precommits
            .iter()
            .filter(|(_, v)| v.block_hash.as_ref() == Some(block_hash))
            .map(|(id, _)| validator_set.power_of(id))
            .sum()
    }

    /// Collect precommit votes for a block into a vec (for CommitCertificate).
    fn precommit_votes_for(&self, block_hash: &BlockHash) -> Vec<Vote> {
        self.precommits
            .values()
            .filter(|v| v.block_hash.as_ref() == Some(block_hash))
            .cloned()
            .collect()
    }
}

// -- Engine -------------------------------------------------------------------

/// Tendermint-style BFT engine.
pub struct TendermintEngine {
    config:         Option<ConsensusConfig>,
    validator_set:  Option<ValidatorSet>,
    height:         BlockHeight,
    round:          Round,
    /// Locked block: the last block we sent a precommit for.
    /// We must prevote for this block (or nil) in future rounds.
    locked_block:   Option<BlockHash>,
    /// Valid block: the latest block we saw 2/3+ prevotes for.
    valid_block:    Option<BlockHash>,
    /// Votes indexed by round.
    votes:          BTreeMap<Round, RoundVotes>,
    /// The proposal we accepted for the current (height, round).
    current_proposal: Option<BlockProposal>,
}

impl TendermintEngine {
    pub fn new() -> Self {
        Self {
            config:           None,
            validator_set:    None,
            height:           0,
            round:            0,
            locked_block:     None,
            valid_block:      None,
            votes:            BTreeMap::new(),
            current_proposal: None,
        }
    }

    /// Determine the proposer for a given (height, round) by round-robin over
    /// the validator set sorted by ValidatorId (deterministic, no external state).
    fn proposer_for(&self, height: BlockHeight, round: Round) -> Option<ValidatorId> {
        let vs = self.validator_set.as_ref()?;
        if vs.validators.is_empty() {
            return None;
        }
        let mut sorted: Vec<_> = vs.validators.iter().collect();
        sorted.sort_by_key(|v| &v.id);
        // Rotate by (height + round) so different heights start with different
        // proposers, and timeouts within a height cycle through the set.
        let idx = ((height + round as u64) as usize) % sorted.len();
        Some(sorted[idx].id.clone())
    }

    /// Check whether a quorum of precommits has formed for any block at the
    /// current round. Returns the winning block hash if so.
    fn check_precommit_quorum(&self) -> Option<BlockHash> {
        let vs = self.validator_set.as_ref()?;
        let round_votes = self.votes.get(&self.round)?;
        let quorum = vs.quorum_power();

        // Collect candidate block hashes from precommits
        let candidates: std::collections::HashSet<_> = round_votes
            .precommits
            .values()
            .filter_map(|v| v.block_hash.as_ref())
            .collect();

        for hash in candidates {
            if round_votes.precommit_power(hash, vs) >= quorum {
                return Some(hash.clone());
            }
        }
        None
    }

    /// Check whether a quorum of prevotes has formed for any block at the
    /// current round. Returns the winning block hash if so.
    fn check_prevote_quorum(&self) -> Option<BlockHash> {
        let vs = self.validator_set.as_ref()?;
        let round_votes = self.votes.get(&self.round)?;
        let quorum = vs.quorum_power();

        let candidates: std::collections::HashSet<_> = round_votes
            .prevotes
            .values()
            .filter_map(|v| v.block_hash.as_ref())
            .collect();

        for hash in candidates {
            if round_votes.prevote_power(hash, vs) >= quorum {
                return Some(hash.clone());
            }
        }
        None
    }

    fn require_config(&self) -> ConsensusResult<&ConsensusConfig> {
        self.config
            .as_ref()
            .ok_or_else(|| ConsensusError::Internal("engine not initialised".into()))
    }

    fn require_validator_set(&self) -> ConsensusResult<&ValidatorSet> {
        self.validator_set
            .as_ref()
            .ok_or_else(|| ConsensusError::Internal("validator set not loaded".into()))
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

    async fn init(
        &mut self,
        config: ConsensusConfig,
        genesis_validators: ValidatorSet,
    ) -> ConsensusResult<()> {
        // Apply personhood cap if configured (QCB mode).
        let vs = if let Some(pop_cfg) = &config.personhood {
            apply_personhood_cap(genesis_validators, pop_cfg)
        } else {
            genesis_validators
        };

        // Sanity check: can we even achieve BFT safety with this set?
        if vs.validators.len() < 4 {
            warn!(
                count = vs.validators.len(),
                "validator set below 4 - BFT safety threshold cannot be met; \
                 this is only acceptable for devnet/single-node testing"
            );
        }

        info!(
            variant    = %self.name(),
            validators = vs.validators.len(),
            total_power = vs.total_power(),
            quorum_power = vs.quorum_power(),
            "consensus engine initialised"
        );

        self.validator_set = Some(vs);
        self.config = Some(config);
        self.height = 0;
        self.round  = 0;
        Ok(())
    }

    fn validator_set(&self) -> &ValidatorSet {
        self.validator_set
            .as_ref()
            .expect("validator_set() called before init()")
    }

    async fn propose(
        &mut self,
        height: BlockHeight,
        round: Round,
        parent_hash: BlockHash,
        tx_data: Vec<u8>,
    ) -> ConsensusResult<BlockProposal> {
        let _cfg = self.require_config()?;
        let _vs  = self.require_validator_set()?;

        if height != self.height {
            return Err(ConsensusError::StaleProposal(height, self.height));
        }

        let proposer = self
            .proposer_for(height, round)
            .ok_or_else(|| ConsensusError::Internal("empty validator set".into()))?;

        // TODO: derive block_hash from tx_data + parent_hash + timestamp via
        // the SHA3 hashing in chain-forge-core once that crate is wired up.
        // For now, use a placeholder that encodes the inputs so tests can
        // distinguish blocks.
        let block_hash = BlockHash(format!(
            "block_h{height}_r{round}_{}", &parent_hash.0[..4.min(parent_hash.0.len())]
        ));

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let proposal = BlockProposal {
            height,
            round,
            proposer,
            block_hash: block_hash.clone(),
            parent_hash,
            timestamp_ms: now_ms,
            tx_data,
            signature: vec![], // TODO: sign with validator key (crypto layer)
        };

        debug!(
            height, round,
            block_hash = %block_hash,
            "produced proposal"
        );

        self.current_proposal = Some(proposal.clone());
        Ok(proposal)
    }

    async fn receive_proposal(
        &mut self,
        proposal: BlockProposal,
    ) -> ConsensusResult<()> {
        let _vs = self.require_validator_set()?;

        if proposal.height != self.height {
            return Err(ConsensusError::StaleProposal(proposal.height, self.height));
        }

        // Verify the proposer is correct for this (height, round).
        let expected_proposer = self
            .proposer_for(proposal.height, proposal.round)
            .ok_or_else(|| ConsensusError::Internal("empty validator set".into()))?;

        if proposal.proposer != expected_proposer {
            return Err(ConsensusError::MalformedProposal(format!(
                "wrong proposer: got {}, expected {}",
                proposal.proposer, expected_proposer
            )));
        }

        // TODO: verify proposer signature once crypto layer is wired up.

        // Locking rule: if we are locked on a block, only accept proposals
        // for that block (or if we see a valid-block polka that unlocks us).
        if let Some(ref locked) = self.locked_block {
            if proposal.block_hash != *locked {
                // In a real implementation we would check for a polka
                // (2/3+ prevotes) for the proposed block, which would allow
                // us to unlock. For now, reject proposals for non-locked blocks
                // when locked. This is conservative but safe.
                return Err(ConsensusError::MalformedProposal(format!(
                    "locked on {locked} but proposal is for {}",
                    proposal.block_hash
                )));
            }
        }

        debug!(
            height = proposal.height,
            round  = proposal.round,
            block_hash = %proposal.block_hash,
            "accepted proposal"
        );

        self.current_proposal = Some(proposal);
        Ok(())
    }

    async fn receive_vote(&mut self, vote: Vote) -> ConsensusResult<Option<CommitCertificate>> {
        let vs = self.require_validator_set()?;

        // Reject votes for wrong height.
        if vote.height != self.height {
            return Err(ConsensusError::StaleProposal(vote.height, self.height));
        }

        // Reject votes from unknown validators.
        if vs.power_of(&vote.validator) == 0 {
            return Err(ConsensusError::UnknownValidator(vote.validator.clone()));
        }

        // TODO: verify vote signature once crypto layer is wired up.

        let round_votes = self.votes.entry(vote.round).or_default();

        match vote.vote_type {
            VoteType::Prevote | VoteType::Nil => {
                // Idempotent: if we already have a prevote from this validator
                // for this round, ignore the duplicate.
                round_votes.prevotes
                    .entry(vote.validator.clone())
                    .or_insert_with(|| vote.clone());

                // Check if we now have 2/3+ prevotes for any block.
                if let Some(valid) = self.check_prevote_quorum() {
                    debug!(
                        height = self.height,
                        round  = self.round,
                        block_hash = %valid,
                        "prevote quorum reached - updating valid_block"
                    );
                    self.valid_block = Some(valid);
                }
            }

            VoteType::Precommit => {
                round_votes.precommits
                    .entry(vote.validator.clone())
                    .or_insert_with(|| vote.clone());

                // Check if we now have 2/3+ precommits for any block.
                if let Some(winning_hash) = self.check_precommit_quorum() {
                    let precommits = round_votes.precommit_votes_for(&winning_hash);

                    info!(
                        height = self.height,
                        round  = self.round,
                        block_hash = %winning_hash,
                        precommit_count = precommits.len(),
                        "precommit quorum reached - committing block"
                    );

                    // Update locked block.
                    self.locked_block = Some(winning_hash.clone());

                    return Ok(Some(CommitCertificate {
                        height: self.height,
                        round: self.round,
                        block_hash: winning_hash,
                        precommits,
                    }));
                }
            }
        }

        Ok(None)
    }

    async fn on_timeout(
        &mut self,
        height: BlockHeight,
        round: Round,
    ) -> ConsensusResult<Vote> {
        if height != self.height {
            return Err(ConsensusError::Timeout(height, 0));
        }

        warn!(
            height, round,
            "round timed out - advancing to round {}",
            round + 1
        );

        self.round = round + 1;
        self.current_proposal = None;

        // Broadcast a nil prevote for the new round to keep liveness.
        Ok(Vote {
            vote_type:  VoteType::Nil,
            height:     self.height,
            round:      self.round,
            validator:  ValidatorId("self".into()), // replaced by node with real ID
            block_hash: None,
            signature:  vec![],
        })
    }

    async fn on_commit(
        &mut self,
        certificate: CommitCertificate,
        new_validator_set: Option<ValidatorSet>,
    ) -> ConsensusResult<()> {
        info!(
            height     = certificate.height,
            round      = certificate.round,
            block_hash = %certificate.block_hash,
            "block committed - advancing height"
        );

        // Advance height, reset round state.
        self.height           = certificate.height + 1;
        self.round            = 0;
        self.current_proposal = None;
        self.valid_block      = None;
        self.votes.clear();

        // Update validator set if the commit triggered an epoch change.
        if let Some(vs) = new_validator_set {
            let vs = if let Some(pop_cfg) = self.config.as_ref().and_then(|c| c.personhood.as_ref()) {
                apply_personhood_cap(vs, pop_cfg)
            } else {
                vs
            };
            info!(
                new_height = self.height,
                new_validator_count = vs.validators.len(),
                "validator set rotated for new epoch"
            );
            self.validator_set = Some(vs);
        }

        Ok(())
    }

    fn current_height(&self) -> BlockHeight {
        self.height
    }

    fn current_round(&self) -> Round {
        self.round
    }

    fn verify_commit(
        &self,
        certificate: &CommitCertificate,
        validator_set: &ValidatorSet,
    ) -> ConsensusResult<()> {
        let quorum = validator_set.quorum_power();

        // Sum the power of all precommit signers.
        let signed_power: u64 = certificate
            .precommits
            .iter()
            .filter(|v| {
                v.vote_type == VoteType::Precommit
                    && v.height == certificate.height
                    && v.block_hash.as_ref() == Some(&certificate.block_hash)
            })
            .map(|v| validator_set.power_of(&v.validator))
            .sum();

        if signed_power < quorum {
            return Err(ConsensusError::InvalidVote {
                validator: ValidatorId("(commit)".into()),
                block_hash: certificate.block_hash.clone(),
                reason: format!(
                    "commit certificate has {signed_power} power but quorum requires {quorum}"
                ),
            });
        }

        // TODO: verify each precommit signature individually once the crypto
        // layer is wired up. For now, power accumulation is the only check.

        Ok(())
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConsensusConfig, ConsensusVariant, ValidatorInfo};

    fn make_engine_and_vs(validator_count: usize) -> (TendermintEngine, ValidatorSet) {
        let vs = ValidatorSet {
            height: 0,
            validators: (0..validator_count)
                .map(|i| ValidatorInfo {
                    id: ValidatorId(format!("val_{i:02}")),
                    voting_power: 1,
                    pop_verified: true,
                })
                .collect(),
        };
        (TendermintEngine::new(), vs)
    }

    fn default_config() -> ConsensusConfig {
        ConsensusConfig {
            variant:             ConsensusVariant::TendermintStyle,
            propose_timeout_ms:  3_000,
            prevote_timeout_ms:  1_000,
            precommit_timeout_ms: 1_000,
            block_time_ms:       5_000,
            personhood:          None,
        }
    }

    #[tokio::test]
    async fn engine_initialises_cleanly() {
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs).await.unwrap();
        assert_eq!(engine.current_height(), 0);
        assert_eq!(engine.current_round(), 0);
        assert_eq!(engine.variant(), ConsensusVariant::TendermintStyle);
    }

    #[tokio::test]
    async fn proposer_rotates_deterministically() {
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs).await.unwrap();

        // With 4 validators sorted by id (val_00..val_03):
        // height=0, round=0 -> idx = (0+0) % 4 = 0 -> val_00
        // height=0, round=1 -> idx = (0+1) % 4 = 1 -> val_01
        let p0 = engine.proposer_for(0, 0).unwrap();
        let p1 = engine.proposer_for(0, 1).unwrap();
        assert_ne!(p0, p1, "proposer should rotate on round advance");
        assert_eq!(p0, engine.proposer_for(0, 0).unwrap(), "deterministic");
    }

    #[tokio::test]
    async fn commit_certificate_on_precommit_quorum() {
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let block_hash = BlockHash("deadbeef_block_0".into());

        // Cast 3 precommits (quorum for 4 validators with power=1 each is 3).
        let mut cert = None;
        for i in 0..3usize {
            let vote = Vote {
                vote_type:  VoteType::Precommit,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("val_{i:02}")),
                block_hash: Some(block_hash.clone()),
                signature:  vec![],
            };
            cert = engine.receive_vote(vote).await.unwrap();
        }

        let cert = cert.expect("quorum should produce a commit certificate");
        assert_eq!(cert.block_hash, block_hash);
        assert_eq!(cert.precommits.len(), 3);
    }

    #[tokio::test]
    async fn no_commit_below_quorum() {
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let block_hash = BlockHash("deadbeef_block_0".into());

        // Only 2 precommits -- below quorum of 3.
        let mut cert = None;
        for i in 0..2usize {
            let vote = Vote {
                vote_type:  VoteType::Precommit,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("val_{i:02}")),
                block_hash: Some(block_hash.clone()),
                signature:  vec![],
            };
            cert = engine.receive_vote(vote).await.unwrap();
        }

        assert!(cert.is_none(), "should not commit below quorum");
    }

    #[tokio::test]
    async fn height_advances_on_commit() {
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let block_hash = BlockHash("deadbeef_block_0".into());
        let cert = CommitCertificate {
            height: 0,
            round: 0,
            block_hash: block_hash.clone(),
            precommits: vec![],
        };

        engine.on_commit(cert, None).await.unwrap();
        assert_eq!(engine.current_height(), 1);
        assert_eq!(engine.current_round(), 0);
    }

    #[tokio::test]
    async fn timeout_advances_round() {
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let nil_vote = engine.on_timeout(0, 0).await.unwrap();
        assert_eq!(engine.current_round(), 1);
        assert_eq!(nil_vote.vote_type, VoteType::Nil);
    }

    #[tokio::test]
    async fn verify_commit_rejects_insufficient_power() {
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let block_hash = BlockHash("deadbeef".into());

        // Only 2 precommits for a 4-validator set (quorum = 3).
        let cert = CommitCertificate {
            height: 0,
            round: 0,
            block_hash: block_hash.clone(),
            precommits: (0..2usize)
                .map(|i| Vote {
                    vote_type:  VoteType::Precommit,
                    height:     0,
                    round:      0,
                    validator:  ValidatorId(format!("val_{i:02}")),
                    block_hash: Some(block_hash.clone()),
                    signature:  vec![],
                })
                .collect(),
        };

        let result = engine.verify_commit(&cert, &vs);
        assert!(result.is_err(), "should reject under-quorum commit");
    }

    #[tokio::test]
    async fn personhood_cap_applied_on_init() {
        use crate::PersonhoodConfig;

        let (mut engine, mut vs) = make_engine_and_vs(4);
        // Give val_00 disproportionate power.
        vs.validators[0].voting_power = 100;

        let mut cfg = default_config();
        cfg.personhood = Some(PersonhoodConfig {
            power_cap: 1,
            reject_expired_pop: false,
            min_verified_pct: 67,
        });

        engine.init(cfg, vs).await.unwrap();

        // After init, val_00 should be capped at 1.
        let capped_power = engine.validator_set().validators[0].voting_power;
        assert_eq!(capped_power, 1, "personhood cap should be applied at init");
    }
}