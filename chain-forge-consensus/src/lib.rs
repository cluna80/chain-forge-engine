/// chain-forge-consensus
///
/// Defines the pluggable consensus interface for Chain Forge. Every BFT
/// variant (Tendermint-style, HotStuff-style, XRPL-inspired) implements
/// the `ConsensusEngine` trait below. QCB's personhood-weighted BFT is one
/// configuration of this interface - it is not a separate codebase.
///
/// Nothing in this crate touches cryptography, P2P, or state directly.
/// Those layers are separate crates. Consensus drives them through the
/// callback types defined here.
///
/// Whitepaper refs: Section 3 (consensus mechanism), Section 7.6 (Chain
/// Forge pluggable design), Open Question 2 (BFT variant selection for QCB).

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

// ── Error type ────────────────────────────────────────────────────────────────

/// All errors the consensus layer can produce.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("not enough validators to meet BFT safety threshold (need ≥ {needed}, have {have})")]
    InsufficientValidators { needed: usize, have: usize },

    #[error("validator {0} is not in the current validator set")]
    UnknownValidator(ValidatorId),

    #[error("proposal for height {0} arrived out of order (current height: {1})")]
    StaleProposal(BlockHeight, BlockHeight),

    #[error("vote from {validator} for block {block_hash} is invalid: {reason}")]
    InvalidVote {
        validator: ValidatorId,
        block_hash: BlockHash,
        reason: String,
    },

    #[error("block proposal is malformed: {0}")]
    MalformedProposal(String),

    #[error("consensus timed out at height {0} after {1}ms")]
    Timeout(BlockHeight, u64),

    #[error("personhood bound exceeded: validator {0} would exceed the per-human power cap")]
    PersonhoodCapExceeded(ValidatorId),

    #[error("internal consensus error: {0}")]
    Internal(String),
}

pub type ConsensusResult<T> = Result<T, ConsensusError>;

// ── Primitive types ───────────────────────────────────────────────────────────

/// Monotonically increasing block height. Genesis = 0.
pub type BlockHeight = u64;

/// Round number within a height. Increments on timeout/nil-vote.
pub type Round = u32;

/// A 32-byte block hash (pre-image is the block's canonical serialisation).
/// Stored as hex string here for readability in JSON; the engine works with
/// raw bytes internally.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockHash(pub String);

impl std::fmt::Display for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0[..8.min(self.0.len())])
    }
}

/// Opaque validator identifier. In QCB this encodes both the consensus key
/// and the PoP-attested human identity; for PoA chains it's just the public
/// key. The consensus layer treats it as an opaque comparable identifier -
/// interpretation is the identity layer's concern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ValidatorId(pub String);

impl std::fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0[..8.min(self.0.len())])
    }
}

// ── Validator set ─────────────────────────────────────────────────────────────

/// A single validator's participation parameters at a given height.
///
/// `voting_power` is a relative weight. For QCB personhood-weighted BFT:
///   - all verified humans have equal base power (e.g. 1)
///   - no single validator may exceed `PersonhoodConfig::power_cap`
/// For plain PoS or PoA, power can vary freely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub id: ValidatorId,

    /// Relative voting power. Consensus safety requires that no Byzantine
    /// subset exceeds 1/3 of total_power across the set.
    pub voting_power: u64,

    /// Whether this validator's identity has been PoP-verified. Used by
    /// the personhood-weighted variant to enforce per-human power caps.
    /// Ignored by PoA and plain-PoS variants.
    pub pop_verified: bool,
}

/// The complete validator set at a given block height.
/// Heights are used as keys because the set may rotate between epochs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub height: BlockHeight,
    pub validators: Vec<ValidatorInfo>,
}

impl ValidatorSet {
    /// Total voting power across all validators.
    pub fn total_power(&self) -> u64 {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    /// Classical BFT safety threshold: 2/3 + 1 of total power.
    /// A commit requires at least this much power in pre-commits.
    pub fn quorum_power(&self) -> u64 {
        let total = self.total_power();
        // ⌊2n/3⌋ + 1  - rounds down then adds 1, matching Tendermint convention.
        (total * 2 / 3) + 1
    }

    /// Power held by a specific validator. Returns 0 if not in the set.
    pub fn power_of(&self, id: &ValidatorId) -> u64 {
        self.validators
            .iter()
            .find(|v| &v.id == id)
            .map(|v| v.voting_power)
            .unwrap_or(0)
    }

    /// True if the given set of votes (validator → power) meets the quorum.
    pub fn has_quorum(&self, votes: &BTreeMap<ValidatorId, u64>) -> bool {
        let voted: u64 = votes.values().sum();
        voted >= self.quorum_power()
    }

    /// Number of Byzantine validators the set can tolerate (floor of n/3 - 1).
    /// A set of 4 validators tolerates 0 Byzantine nodes (4/3 - 1 = 0).
    /// A set of 10 tolerates 2 (10/3 - 1 ≈ 2).
    pub fn byzantine_fault_tolerance(&self) -> usize {
        let n = self.validators.len();
        if n < 4 { 0 } else { n / 3 - 1 }
    }
}

// ── Block proposal ────────────────────────────────────────────────────────────

/// A block proposed by the current round's proposer.
/// The consensus engine validates the proposal's structural integrity;
/// transaction execution validation is the execution layer's concern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposal {
    pub height: BlockHeight,
    pub round: Round,
    pub proposer: ValidatorId,
    pub block_hash: BlockHash,

    /// Hash of the previous committed block. Provides chain linkage.
    pub parent_hash: BlockHash,

    /// Unix timestamp (milliseconds) when the proposer created this proposal.
    pub timestamp_ms: u64,

    /// Opaque transaction payload. The execution layer interprets this;
    /// consensus only cares about the hash commitment above.
    pub tx_data: Vec<u8>,

    /// Proposer's signature over (height ∥ round ∥ block_hash ∥ parent_hash).
    /// Signature scheme is determined by the chain's genesis cryptography config.
    /// Empty during tests / before the crypto layer is wired up.
    pub signature: Vec<u8>,
}

// ── Votes ─────────────────────────────────────────────────────────────────────

/// The three vote types in standard BFT protocols.
/// PREVOTE: "I've seen the proposal and it's valid."
/// PRECOMMIT: "I've seen 2/3+ prevotes for this block."
/// NIL: Timeout - used when a round must advance without a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
    Nil,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: BlockHeight,
    pub round: Round,
    pub validator: ValidatorId,

    /// None for Nil votes (no block to reference).
    pub block_hash: Option<BlockHash>,

    /// Validator's signature over (vote_type ∥ height ∥ round ∥ block_hash).
    /// Empty during tests / before the crypto layer is wired up.
    pub signature: Vec<u8>,
}

// ── Commit certificate ────────────────────────────────────────────────────────

/// Proof that a block was committed: the block hash plus the set of
/// pre-commit votes whose combined power meets quorum.
/// Stored in the block header so any light client can verify finality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitCertificate {
    pub height: BlockHeight,
    pub round: Round,
    pub block_hash: BlockHash,

    /// The pre-commit votes that form the quorum. Must cover ≥ 2/3+1 power.
    pub precommits: Vec<Vote>,
}

// ── Personhood configuration ──────────────────────────────────────────────────

/// Parameters for QCB's personhood-weighted BFT variant.
/// Ignored by PoA and plain-PoS variants.
///
/// Whitepaper Section 3.3: "no single verified human may exercise more than
/// a fixed cap of total validator power, regardless of how much $QCB they
/// stake."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonhoodConfig {
    /// Maximum voting power any single PoP-verified identity may hold.
    /// Expressed as an absolute power units (not a percentage) so the cap
    /// stays fixed while the validator set grows.
    pub power_cap: u64,

    /// Whether to reject proposals from validators whose PoP attestation
    /// has expired or been revoked. If false, they are demoted to power 0
    /// rather than rejected outright (softer liveness behaviour).
    pub reject_expired_pop: bool,

    /// Minimum fraction of the validator set that must be PoP-verified for
    /// the chain to consider itself in a healthy personhood-secured state.
    /// Expressed as a percentage (0–100). Below this, the engine logs a
    /// warning but does not halt - halting is a governance decision, not
    /// a consensus one.
    pub min_verified_pct: u8,
}

impl Default for PersonhoodConfig {
    fn default() -> Self {
        Self {
            power_cap: 1,              // equal weight per human by default
            reject_expired_pop: false, // soft: demote rather than reject
            min_verified_pct: 67,      // warn if < 2/3 of set is PoP-verified
        }
    }
}

// ── Consensus configuration ───────────────────────────────────────────────────

/// Full configuration passed to a consensus engine at chain startup.
/// Populated from the genesis JSON produced by Chain Forge's wizard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Which algorithm variant to instantiate.
    pub variant: ConsensusVariant,

    /// Milliseconds to wait for a proposal before declaring a round timeout.
    pub propose_timeout_ms: u64,

    /// Milliseconds to wait for prevotes before declaring a round timeout.
    pub prevote_timeout_ms: u64,

    /// Milliseconds to wait for precommits before declaring a round timeout.
    pub precommit_timeout_ms: u64,

    /// Target block time. The proposer waits at least this long between
    /// receiving the previous commit and broadcasting the next proposal.
    pub block_time_ms: u64,

    /// QCB personhood parameters. Unused by non-personhood variants.
    pub personhood: Option<PersonhoodConfig>,
}

/// The three BFT variants Chain Forge supports (Whitepaper Section 7.6).
/// QCB uses `TendermintStyle` with `PersonhoodConfig` applied on top.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusVariant {
    /// Two-phase (prevote → precommit) rotating-proposer BFT.
    /// Well-understood safety proofs, instant finality.
    TendermintStyle,

    /// Linear-communication BFT - fewer messages per block at scale.
    /// Higher implementation complexity than Tendermint.
    HotStuffStyle,

    /// Federated Byzantine Agreement with threshold signatures.
    /// XRPL-inspired: no leader rotation, UNL-based safety.
    XrplInspired,
}

impl std::fmt::Display for ConsensusVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TendermintStyle => write!(f, "Tendermint-style BFT"),
            Self::HotStuffStyle   => write!(f, "HotStuff-style BFT"),
            Self::XrplInspired    => write!(f, "XRPL-inspired FBA"),
        }
    }
}

// ── The consensus trait ───────────────────────────────────────────────────────

/// The pluggable consensus interface.
///
/// Every BFT variant implements this trait. The chain node (`chain-forge-node`)
/// holds a `Box<dyn ConsensusEngine>` and calls these methods - it never
/// knows which variant it's running. Swapping algorithms is a config change,
/// not a code change.
///
/// Methods are `async` because real implementations will await network I/O
/// (receiving votes from peers) and timer events (round timeouts).
///
/// # Safety contract
///
/// Implementations MUST guarantee:
///   - Safety: two honest nodes never commit different blocks at the same height.
///   - Liveness: if ≥ 2/3 of voting power is honest and online, the chain
///     eventually commits a block at every height (Whitepaper Open Question 14
///     flags the liveness constraint specific to personhood-bounded sets).
///
/// The trait does NOT enforce these - that's the algorithm's job. Violating
/// either property is a consensus bug, not a trait misuse.
#[async_trait::async_trait]
pub trait ConsensusEngine: Send + Sync {
    /// Human-readable name of this variant (for logs and the Engine Status page).
    fn name(&self) -> &str;

    /// Return the consensus variant enum this engine implements.
    fn variant(&self) -> ConsensusVariant;

    /// Initialise the engine with the genesis validator set and config.
    /// Called once at chain startup, before any blocks are produced.
    async fn init(
        &mut self,
        config: ConsensusConfig,
        genesis_validators: ValidatorSet,
    ) -> ConsensusResult<()>;

    /// Return the current validator set (may change between epochs).
    fn validator_set(&self) -> &ValidatorSet;

    /// Called by the node when it is this validator's turn to propose.
    /// Returns a `BlockProposal` ready to broadcast to peers.
    async fn propose(
        &mut self,
        height: BlockHeight,
        round: Round,
        parent_hash: BlockHash,
        tx_data: Vec<u8>,
    ) -> ConsensusResult<BlockProposal>;

    /// Called when a proposal arrives from a peer.
    /// Returns `Ok(())` if the proposal is structurally valid and should
    /// be voted on; returns `Err` to reject it silently.
    async fn receive_proposal(
        &mut self,
        proposal: BlockProposal,
    ) -> ConsensusResult<()>;

    /// Called when a vote arrives from a peer (prevote, precommit, or nil).
    /// Returns `Some(CommitCertificate)` when the vote completes a quorum,
    /// triggering a commit. Returns `None` if more votes are needed.
    async fn receive_vote(
        &mut self,
        vote: Vote,
    ) -> ConsensusResult<Option<CommitCertificate>>;

    /// Called by the node's timer when a round times out.
    /// The engine should advance to the next round and return a nil vote
    /// ready to broadcast to peers.
    async fn on_timeout(
        &mut self,
        height: BlockHeight,
        round: Round,
    ) -> ConsensusResult<Vote>;

    /// Called after the execution layer has committed a block.
    /// Gives the engine a chance to update its internal state (e.g. rotate
    /// the proposer, advance the height counter, update the validator set
    /// for the new epoch).
    async fn on_commit(
        &mut self,
        certificate: CommitCertificate,
        new_validator_set: Option<ValidatorSet>,
    ) -> ConsensusResult<()>;

    /// Current height the engine is working on.
    fn current_height(&self) -> BlockHeight;

    /// Current round within the current height.
    fn current_round(&self) -> Round;

    /// Verify a commit certificate produced by a peer (used by light clients
    /// and sync). Returns `Ok(())` if the certificate is valid for the given
    /// validator set.
    fn verify_commit(
        &self,
        certificate: &CommitCertificate,
        validator_set: &ValidatorSet,
    ) -> ConsensusResult<()>;
}

// ── Personhood power cap enforcement ─────────────────────────────────────────

/// Applies the personhood power cap from `config` to a raw validator set.
/// Any PoP-verified validator whose `voting_power` exceeds `config.power_cap`
/// is clamped to that cap. Unverified validators are clamped to 0 if
/// `reject_expired_pop` is true, otherwise left unchanged.
///
/// Call this when building the validator set for a new epoch so the cap
/// is enforced at the data layer, not scattered through algorithm code.
pub fn apply_personhood_cap(
    mut validator_set: ValidatorSet,
    config: &PersonhoodConfig,
) -> ValidatorSet {
    for v in &mut validator_set.validators {
        if v.pop_verified {
            if v.voting_power > config.power_cap {
                v.voting_power = config.power_cap;
            }
        } else if config.reject_expired_pop {
            v.voting_power = 0;
        }
    }
    validator_set
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator_set(powers: &[u64]) -> ValidatorSet {
        ValidatorSet {
            height: 0,
            validators: powers
                .iter()
                .enumerate()
                .map(|(i, &p)| ValidatorInfo {
                    id: ValidatorId(format!("val_{i}")),
                    voting_power: p,
                    pop_verified: true,
                })
                .collect(),
        }
    }

    #[test]
    fn quorum_requires_two_thirds_plus_one() {
        // 4 validators of equal power: total = 4, quorum = ⌊8/3⌋+1 = 3
        let vs = make_validator_set(&[1, 1, 1, 1]);
        assert_eq!(vs.total_power(), 4);
        assert_eq!(vs.quorum_power(), 3);
    }

    #[test]
    fn bft_tolerates_one_third_minus_one() {
        // 10 validators: tolerates ⌊10/3⌋ - 1 = 2 Byzantine
        let vs = make_validator_set(&[1; 10]);
        assert_eq!(vs.byzantine_fault_tolerance(), 2);

        // 3 validators: below the 4-node floor, tolerates 0
        let vs_small = make_validator_set(&[1, 1, 1]);
        assert_eq!(vs_small.byzantine_fault_tolerance(), 0);
    }

    #[test]
    fn has_quorum_correctly_sums_votes() {
        let vs = make_validator_set(&[10, 10, 10, 10]); // total=40, quorum=27
        let mut votes = BTreeMap::new();
        votes.insert(ValidatorId("val_0".into()), 10u64);
        votes.insert(ValidatorId("val_1".into()), 10u64);
        assert!(!vs.has_quorum(&votes)); // 20 < 27

        votes.insert(ValidatorId("val_2".into()), 10u64);
        assert!(vs.has_quorum(&votes)); // 30 >= 27
    }

    #[test]
    fn personhood_cap_clamps_excess_power() {
        let vs = make_validator_set(&[5, 1, 3]);
        let config = PersonhoodConfig { power_cap: 2, ..Default::default() };
        let capped = apply_personhood_cap(vs, &config);
        // val_0: 5 → 2, val_1: 1 → 1 (already under cap), val_2: 3 → 2
        assert_eq!(capped.validators[0].voting_power, 2);
        assert_eq!(capped.validators[1].voting_power, 1);
        assert_eq!(capped.validators[2].voting_power, 2);
    }

    #[test]
    fn personhood_cap_zeroes_unverified_when_strict() {
        let mut vs = make_validator_set(&[1, 1, 1]);
        vs.validators[1].pop_verified = false; // middle validator not PoP-verified
        let config = PersonhoodConfig {
            power_cap: 1,
            reject_expired_pop: true,
            min_verified_pct: 67,
        };
        let capped = apply_personhood_cap(vs, &config);
        assert_eq!(capped.validators[1].voting_power, 0); // zeroed
        assert_eq!(capped.validators[0].voting_power, 1); // unchanged
    }
}

pub mod tendermint {
    use super::*;

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

        // Insert the vote first, then drop the borrow before calling
        // check_*_quorum() which needs an immutable borrow of self.
        let vote_round = vote.round;
        {
            let round_votes = self.votes.entry(vote_round).or_default();
            match vote.vote_type {
                VoteType::Prevote | VoteType::Nil => {
                    round_votes.prevotes
                        .entry(vote.validator.clone())
                        .or_insert_with(|| vote.clone());
                }
                VoteType::Precommit => {
                    round_votes.precommits
                        .entry(vote.validator.clone())
                        .or_insert_with(|| vote.clone());
                }
                _ => {}
            }
        } // round_votes borrow ends here

        match vote.vote_type {
            VoteType::Prevote | VoteType::Nil => {
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
                // Check if we now have 2/3+ precommits for any block.
                if let Some(winning_hash) = self.check_precommit_quorum() {
                    // Collect precommits - borrow ends before we mutate self.
                    let precommits = self.votes
                        .get(&vote_round)
                        .map(|rv| rv.precommit_votes_for(&winning_hash))
                        .unwrap_or_default();

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

}
