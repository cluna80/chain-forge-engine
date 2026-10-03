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

#[cfg(feature = "real-crypto")]
use chain_forge_crypto::{ClassicalScheme, KeyPair, Signature, SchemeId, SignatureScheme};

use chain_forge_vca_pq::{
    VcaRegistry, WeightConfig, AdaptiveQuorumConfig,
    ContributionScore, PersonhoodFactor, StakeAmount, IdentityHandle,
    compute_adaptive_quorum, VcaError,
};

// ── Error type ────────────────────────────────────────────────────────────────

/// All errors the consensus layer can produce.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("not enough validators to meet BFT safety threshold (need ≥ {needed}, have {have})")]
    InsufficientValidators { needed: usize, have: usize },

    #[error("validator {0} is not in the current validator set")]
    UnknownValidator(ValidatorId),

    #[error("message for height {0} arrived out of order (current height: {1})")]
    StaleMessage(BlockHeight, BlockHeight),

    #[error("vote from {validator} for block {block_hash} is invalid: {reason}")]
    InvalidVote {
        validator: ValidatorId,
        block_hash: BlockHash,
        reason: String,
    },

    /// Covers three distinct sub-conditions (all currently handled the same way —
    /// log and discard). If future logic needs to branch on cause, split into:
    ///   `WrongProposer`    — wrong proposer for this (height, round); normal in round-change
    ///   `InvalidSignature` — proposer's signature doesn't verify; Byzantine signal
    ///   `LockViolation`    — proposal conflicts with our locked block; safety rule
    /// The `String` payload carries which sub-condition fired for log diagnostics.
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

/// Monotonically increasing block height. Re-exported from chain-forge-core.
pub use chain_forge_core::BlockHeight;

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

/// Opaque validator identifier. Re-exported from chain-forge-core so that
/// boundary crates (chain-forge-personhood, etc.) can hold the same type
/// without depending on this crate.
///
/// In QCB this encodes both the consensus key and the PoP-attested human
/// identity; for PoA chains it's just the public key. The consensus layer
/// treats it as an opaque comparable identifier — interpretation is the
/// identity layer's concern.
/// Opaque validator identifier — re-exported from chain-forge-core.
pub use chain_forge_core::ValidatorId;

// ── Validator set — re-exported from chain-forge-core ────────────────────────
//
// ValidatorInfo, ValidatorSet, and BlockHeight live in chain-forge-core so
// that chain-forge-vca-pq can import them without creating a dependency cycle
// through this crate.  Everything that previously used the local definitions
// continues to work via these re-exports.

/// A single validator's participation parameters. Re-exported from core.
pub use chain_forge_core::ValidatorInfo;

/// The complete validator set at a given block height. Re-exported from core.
pub use chain_forge_core::ValidatorSet;

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

// ── Signing bytes ──────────────────────────────────────────────────────────────────────

/// Bytes a proposer signs for `BlockProposal::signature`.
/// Domain-separated with chain_id to prevent cross-chain replay.
pub fn proposal_signing_bytes(
    chain_id: &str, height: BlockHeight, round: Round,
    block_hash: &BlockHash, parent_hash: &BlockHash,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"CFP|");
    b.extend_from_slice(chain_id.as_bytes());
    b.push(b'|');
    b.extend_from_slice(&height.to_le_bytes());
    b.extend_from_slice(&round.to_le_bytes());
    b.extend_from_slice(block_hash.0.as_bytes());
    b.push(b'|');
    b.extend_from_slice(parent_hash.0.as_bytes());
    b
}

/// Bytes a validator signs for `Vote::signature`.
pub fn vote_signing_bytes(
    chain_id: &str, vote_type: &VoteType, height: BlockHeight, round: Round,
    block_hash: Option<&BlockHash>,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"CFV|");
    b.extend_from_slice(chain_id.as_bytes());
    b.push(b'|');
    b.push(match vote_type { VoteType::Prevote => 0, VoteType::Precommit => 1, VoteType::Nil => 2 });
    b.extend_from_slice(&height.to_le_bytes());
    b.extend_from_slice(&round.to_le_bytes());
    if let Some(bh) = block_hash { b.extend_from_slice(bh.0.as_bytes()); }
    b
}

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

// ── VCA-PQ-BFT integration ────────────────────────────────────────────────────

/// Configuration that wires VCA-PQ-BFT weight computation into the consensus
/// engine. When present on `ConsensusConfig`, the engine:
///
///   1. At each epoch boundary, rebuilds a `VcaRegistry` from the incoming
///      `ValidatorSet`, populating contribution scores and personhood factors
///      from `ValidatorInfo` fields.
///   2. Calls `registry.close_epoch()` to apply the relative weight cap (A4).
///   3. Calls `compute_adaptive_quorum()` to derive the BFT threshold from
///      the verified-personhood fraction (ρ).
///   4. Rewrites each validator's `voting_power` to match the VCA-derived
///      `ConsensusWeight` so all downstream quorum arithmetic uses real
///      personhood-weighted power.
///
/// If `VcaIntegrationConfig` is absent the engine falls back to the legacy
/// `PersonhoodConfig` path (static power_cap + boolean pop_verified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcaIntegrationConfig {
    /// VCA weight computation parameters (contribution scale, personhood
    /// exponent, max_weight_multiplier for the relative cap, etc.).
    pub weight_config: WeightConfig,

    /// Adaptive quorum parameters (base fraction, ρ coverage thresholds,
    /// quorum floor and ceiling).
    pub quorum_config: AdaptiveQuorumConfig,
}

impl Default for VcaIntegrationConfig {
    fn default() -> Self {
        Self {
            weight_config: WeightConfig::default(),
            quorum_config: AdaptiveQuorumConfig::default(),
        }
    }
}

/// Build a fresh `VcaRegistry` for the given epoch from a `ValidatorSet`.
///
/// Each `ValidatorInfo` is mapped to VCA primitives:
///   - `contribution_score` = `voting_power` cast to f64 (legacy field reused
///     as a contribution proxy until the execution layer emits real scores)
///   - `personhood_factor`  = 1.0 if `pop_verified`, else 0.0
///   - `stake`              = 0 (stake does not affect weight — ∂W/∂S = 0)
///   - `identity_handle`    = validator id string
///
/// After population, `close_epoch()` is called to apply the relative weight
/// cap, making it safe to read final weights and call `compute_adaptive_quorum`.
pub fn build_vca_registry_from_validator_set(
    epoch: u64,
    vs: &ValidatorSet,
    weight_config: WeightConfig,
) -> VcaRegistry {
    let mut registry = VcaRegistry::new(epoch, weight_config);

    for v in &vs.validators {
        let contribution = ContributionScore(v.voting_power as f64);
        let personhood   = PersonhoodFactor(if v.pop_verified { 1.0 } else { 0.0 });
        let stake        = StakeAmount(0); // stake irrelevant to weight
        let handle       = IdentityHandle(v.id.0.clone());

        // Errors here are programming errors (registry not yet closed), not
        // runtime failures — log and skip rather than panicking the engine.
        // Public keys are carried on ValidatorInfo.public_key; we pass
        // the classical key from there and leave the PQ slot empty until
        // the PQ migration pipeline is wired in.
        let classical_pubkey = v.public_key.clone();
        let pq_pubkey        = vec![];
        if let Err(e) = registry.upsert(v.id.clone(), handle, contribution, personhood, stake, classical_pubkey, pq_pubkey) {
            tracing::warn!(
                validator = %v.id.0,
                error     = %e,
                "VCA registry upsert skipped during epoch build"
            );
        }
    }

    registry.close_epoch();
    registry
}

/// Apply VCA-derived weights back onto a `ValidatorSet` in place.
///
/// After `close_epoch()`, each validator's `ConsensusWeight` is the
/// authoritative weight. This function overwrites `voting_power` with it so
/// that all downstream quorum arithmetic (prevote tallying, precommit tallying,
/// `verify_commit`) uses the personhood-weighted values.
pub fn apply_vca_weights_to_validator_set(vs: &mut ValidatorSet, registry: &VcaRegistry) {
    for v in &mut vs.validators {
        if let Some(record) = registry.records.get(&v.id) {
            v.voting_power = record.weight.0;
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

    /// The chain's unique identifier. Domain-separates signed messages so
    /// a vote valid on one chain cannot be replayed on another.
    /// Must match the `chain_id` in genesis.json.
    pub chain_id: String,

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

    /// VCA-PQ-BFT integration. When present, overrides the legacy
    /// `personhood` weight computation: `voting_power` is rewritten from
    /// VCA `ConsensusWeight` and the adaptive quorum replaces `quorum_power()`.
    ///
    /// Set this for QCB. Leave `None` for plain PoA / PoS chains that do
    /// not use verifiable-contribution scoring.
    #[serde(default)]
    pub vca: Option<VcaIntegrationConfig>,
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

    /// Replace the validator set (used to backfill public keys after loading key files).
    /// Default is a no-op so existing impls compile without change.
    fn update_validator_set(&mut self, _vs: ValidatorSet) -> Result<(), ConsensusError> { Ok(()) }

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

    /// Drain and return any double-sign evidence accumulated since the last
    /// call. The node calls this after each `receive_vote` and routes the
    /// results to `process_equivocation_evidence`.
    ///
    /// Default impl returns empty — engines that don't track equivocations
    /// (FBA, HotStuff stubs) compile without changes.
    fn drain_equivocations(&mut self) -> Vec<crate::tendermint::EquivocationDetected> {
        Vec::new()
    }
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

// -- FbaEngine (XRPL-inspired Federated Byzantine Agreement) -----------------

/// XRPL-inspired Federated Byzantine Agreement engine.
///
/// FBA differs fundamentally from Tendermint and HotStuff:
///
///   Classical BFT: one global validator set, 2f+1 quorum
///   FBA:           each node defines its own "UNL" (Unique Node List) —
///                  a set of validators it personally trusts. Safety
///                  emerges from UNL overlap between nodes, not from a
///                  single global quorum rule.
///
/// XRPL's design:
///   - No elected leader, no proposer rotation
///   - Every validator independently proposes and votes
///   - A transaction is committed when 80% of a node's UNL agrees
///   - Safety requires ≥ 40% overlap between any two nodes' UNLs
///
/// QCB adaptation:
///   - The UNL is the verified-human validator set (personhood-gated)
///   - The 80% threshold is tunable via FbaConfig
///   - Personhood cap still applies (Section 3.3)
///   - In Phase 0 a single global UNL is used (equivalent to the
///     Tendermint validator set); per-node UNLs are a Phase 1 feature
///
/// Why consider FBA for QCB?
///   - No leader = no proposer rotation = simpler liveness under churn
///   - Natural fit for open, permission-less participation
///   - XRPL has proven the model at scale (millions of tx/day since 2012)
///   - Tradeoff: safety depends on UNL configuration correctness;
///     a badly configured UNL can silently fork the chain
///
/// Whitepaper ref: Section 3 / ConsensusVariant::XrplInspired.
/// Open Question 2: which variant QCB ultimately uses.

/// Configuration specific to the FBA engine.
#[derive(Debug, Clone)]
pub struct FbaConfig {
    /// Fraction of UNL that must agree to commit (XRPL default: 0.80).
    /// Must be > 0.5 for safety. XRPL recommends 0.80.
    pub agreement_threshold: f64,
    /// Minimum UNL size. Below this, the node refuses to participate.
    pub min_unl_size: usize,
}

impl Default for FbaConfig {
    fn default() -> Self {
        Self {
            agreement_threshold: 0.80,
            min_unl_size:        3,
        }
    }
}

/// One round of FBA voting: each validator broadcasts its candidate,
/// collects peer votes, and converges when threshold is met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FbaPhase {
    /// Waiting for proposal / open phase — collecting candidates.
    Open,
    /// Threshold reached for a candidate — committing.
    Committed,
}

pub struct FbaEngine {
    config:      ConsensusConfig,
    fba:         FbaConfig,
    validators:  ValidatorSet,
    height:      BlockHeight,
    round:       Round,
    phase:       FbaPhase,
    /// Votes received this round: block_hash -> (validator -> power).
    votes:       BTreeMap<BlockHash, BTreeMap<ValidatorId, u64>>,
    /// The pending proposal (most-recent received).
    pending:     Option<BlockProposal>,
}

impl FbaEngine {
    pub fn new() -> Self {
        Self {
            config:      ConsensusConfig {
                variant:              ConsensusVariant::XrplInspired,
                chain_id:             String::new(),
                propose_timeout_ms:   4_000,
                prevote_timeout_ms:   1_000,
                precommit_timeout_ms: 1_000,
                block_time_ms:        3_500, // XRPL ~3-5s block time
                personhood:           None,
                vca:                  None,
            },
            fba:         FbaConfig::default(),
            validators:  ValidatorSet { height: 0, validators: vec![] },
            height:      0,
            round:       0,
            phase:       FbaPhase::Open,
            votes:       BTreeMap::new(),
            pending:     None,
        }
    }

    /// Minimum power needed to commit under the FBA threshold.
    fn threshold_power(&self) -> u64 {
        let total = self.validators.total_power() as f64;
        (total * self.fba.agreement_threshold).ceil() as u64
    }

    /// Check whether any candidate has crossed the threshold.
    fn find_committed(&self) -> Option<BlockHash> {
        let threshold = self.threshold_power();
        for (hash, vote_map) in &self.votes {
            let power: u64 = vote_map.values().sum();
            if power >= threshold {
                return Some(hash.clone());
            }
        }
        None
    }

    /// Record a vote for a block hash.
    fn record_vote(&mut self, validator: &ValidatorId, power: u64, hash: &BlockHash) {
        self.votes
            .entry(hash.clone())
            .or_default()
            .entry(validator.clone())
            .or_insert(power);
    }

    /// Build a CommitCertificate for a winning hash.
    fn make_certificate(&self, hash: &BlockHash) -> CommitCertificate {
        let precommits = self.votes.get(hash)
            .map(|vm| vm.keys().map(|id| Vote {
                vote_type:  VoteType::Precommit,
                height:     self.height,
                round:      self.round,
                validator:  id.clone(),
                block_hash: Some(hash.clone()),
                signature:  vec![],
            }).collect())
            .unwrap_or_default();

        CommitCertificate {
            height:     self.height,
            round:      self.round,
            block_hash: hash.clone(),
            precommits,
        }
    }
}

impl Default for FbaEngine {
    fn default() -> Self { Self::new() }
}

#[async_trait::async_trait]
impl ConsensusEngine for FbaEngine {
    fn name(&self) -> &str {
        "XRPL-inspired FBA (Phase 0 — global UNL, 80% threshold)"
    }

    fn variant(&self) -> ConsensusVariant { ConsensusVariant::XrplInspired }

    async fn init(
        &mut self,
        config:     ConsensusConfig,
        mut validators: ValidatorSet,
    ) -> ConsensusResult<()> {
        if let Some(ref pc) = config.personhood {
            validators = apply_personhood_cap(validators, pc);
        }
        if validators.validators.len() < self.fba.min_unl_size {
            return Err(ConsensusError::InsufficientValidators {
                needed: self.fba.min_unl_size,
                have:   validators.validators.len(),
            });
        }
        self.validators = validators;
        self.config     = config;
        self.phase      = FbaPhase::Open;
        tracing::info!(
            variant     = "XRPL-inspired FBA",
            validators  = self.validators.validators.len(),
            total_power = self.validators.total_power(),
            threshold   = self.fba.agreement_threshold,
            threshold_power = self.threshold_power(),
            "FBA consensus engine initialised"
        );
        Ok(())
    }

    fn validator_set(&self) -> &ValidatorSet { &self.validators }
    fn current_height(&self) -> BlockHeight  { self.height }
    fn current_round(&self)  -> Round        { self.round }

    async fn propose(
        &mut self,
        height:      BlockHeight,
        round:       Round,
        parent_hash: BlockHash,
        tx_data:     Vec<u8>,
    ) -> ConsensusResult<BlockProposal> {
        // In FBA every validator proposes independently.
        // Phase 0: the local node produces one canonical proposal.
        let block_hash = BlockHash(format!(
            "fba_h{height}_r{round}_{:08x}",
            tx_data.len() as u32
        ));
        let proposal = BlockProposal {
            height,
            round,
            proposer:   ValidatorId("self".into()),
            block_hash,
            parent_hash,
            timestamp_ms: 0,
            tx_data,
            signature: vec![],
        };
        tracing::debug!(height, round, "FBA: proposal broadcast");
        Ok(proposal)
    }

    async fn receive_proposal(
        &mut self,
        proposal: BlockProposal,
    ) -> ConsensusResult<()> {
        if proposal.height < self.height {
            return Err(ConsensusError::StaleMessage(proposal.height, self.height));
        }
        self.pending = Some(proposal.clone());
        self.phase   = FbaPhase::Open;
        self.votes.clear();
        tracing::debug!(
            height = proposal.height,
            hash   = %proposal.block_hash,
            "FBA: candidate received, open phase"
        );
        Ok(())
    }

    async fn receive_vote(
        &mut self,
        vote: Vote,
    ) -> ConsensusResult<Option<CommitCertificate>> {
        let power = self.validators.power_of(&vote.validator);
        if power == 0 {
            return Err(ConsensusError::UnknownValidator(vote.validator));
        }

        let hash = match &vote.block_hash {
            Some(h) => h.clone(),
            None    => return Ok(None), // nil / timeout vote
        };

        if self.phase == FbaPhase::Committed {
            return Ok(None);
        }

        self.record_vote(&vote.validator, power, &hash);

        if let Some(winning_hash) = self.find_committed() {
            self.phase = FbaPhase::Committed;
            let cert = self.make_certificate(&winning_hash);
            tracing::info!(
                height = cert.height,
                hash   = %cert.block_hash,
                threshold = self.fba.agreement_threshold,
                "FBA: threshold reached -- block committed"
            );
            return Ok(Some(cert));
        }
        Ok(None)
    }

    async fn on_timeout(
        &mut self,
        height: BlockHeight,
        round:  Round,
    ) -> ConsensusResult<Vote> {
        tracing::warn!(height, round, "FBA: round timed out, advancing");
        self.round  = round + 1;
        self.phase  = FbaPhase::Open;
        self.votes.clear();
        self.pending = None;

        Ok(Vote {
            vote_type:  VoteType::Nil,
            height,
            round,
            validator:  ValidatorId("self".into()),
            block_hash: None,
            signature:  vec![],
        })
    }

    async fn on_commit(
        &mut self,
        certificate:       CommitCertificate,
        new_validator_set: Option<ValidatorSet>,
    ) -> ConsensusResult<()> {
        self.height  = certificate.height + 1;
        self.round   = 0;
        self.phase   = FbaPhase::Open;
        self.votes.clear();
        self.pending = None;

        if let Some(mut new_set) = new_validator_set {
            if let Some(ref pc) = self.config.personhood.clone() {
                new_set = apply_personhood_cap(new_set, pc);
            }
            if new_set.validators.len() >= self.fba.min_unl_size {
                self.validators = new_set;
            } else {
                tracing::warn!(
                    "FBA: new validator set too small for UNL ({} < {}); keeping current",
                    new_set.validators.len(), self.fba.min_unl_size
                );
            }
        }

        tracing::info!(height = self.height, "FBA: committed, advancing");
        Ok(())
    }

    fn verify_commit(
        &self,
        certificate:   &CommitCertificate,
        validator_set: &ValidatorSet,
    ) -> ConsensusResult<()> {
        // Count voting power in the certificate
        let power: u64 = certificate.precommits.iter()
            .filter(|v| v.vote_type == VoteType::Precommit)
            .map(|v| validator_set.power_of(&v.validator))
            .sum();

        let total   = validator_set.total_power() as f64;
        let needed  = (total * self.fba.agreement_threshold).ceil() as u64;

        if power < needed {
            return Err(ConsensusError::InvalidVote {
                validator:  ValidatorId("quorum".into()),
                block_hash: certificate.block_hash.clone(),
                reason:     format!(
                    "FBA: insufficient threshold power: {power} < {needed}                      ({:.0}% of {total})",
                    self.fba.agreement_threshold * 100.0
                ),
            });
        }
        Ok(())
    }
}

/// Create a `FbaEngine` and initialise it in one call.
pub async fn new_fba(
    config:     ConsensusConfig,
    validators: ValidatorSet,
) -> ConsensusResult<FbaEngine> {
    let mut engine = FbaEngine::new();
    engine.init(config, validators).await?;
    Ok(engine)
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
                    public_key: vec![],
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
    /// This validator's Ed25519 signing keypair. None for observer nodes.
    #[cfg(feature = "real-crypto")]
    signing_key: Option<KeyPair>,
    /// Chain ID for domain-separating signed messages.
    chain_id: String,
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
    /// Equivocation evidence accumulated by receive_vote().
    /// The node drains this after each vote with `drain_equivocations()`.
    pub pending_equivocations: Vec<EquivocationDetected>,

    /// VCA-derived quorum threshold for the current epoch.
    ///
    /// Computed by `build_vca_registry_from_validator_set` + `compute_adaptive_quorum`
    /// at each epoch boundary. `None` when VCA is not configured or the
    /// registry has not yet been built (genesis state).
    ///
    /// When `Some(q)`, `verify_commit` uses `q` as the quorum threshold instead
    /// of `ValidatorSet::quorum_power()`. This is the primary integration point:
    /// the adaptive quorum derived from verified-personhood fraction ρ replaces
    /// the static 2n/3+1 threshold.
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

impl TendermintEngine {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "real-crypto")]
            signing_key:          None,
            chain_id:             String::new(),
            config:               None,
            validator_set:        None,
            height:               0,
            round:                0,
            locked_block:         None,
            valid_block:          None,
            votes:                BTreeMap::new(),
            current_proposal:     None,
            pending_equivocations: Vec::new(),
            vca_quorum:           None,
        }
    }

    /// Drain and return any equivocations detected since the last call.
    /// The node calls this after processing each vote and forwards any
    /// results to `Node::process_equivocation_evidence`.
    pub fn drain_equivocations(&mut self) -> Vec<EquivocationDetected> {
        std::mem::take(&mut self.pending_equivocations)
    }

    /// Set the signing key for this validator. Called by the node at startup
    /// when a key file is loaded. Does nothing without the real-crypto feature.
    #[cfg(feature = "real-crypto")]
    pub fn set_signing_key(&mut self, key: KeyPair, chain_id: String) {
        self.signing_key = Some(key);
        self.chain_id = chain_id;
    }
    #[cfg(not(feature = "real-crypto"))]
    pub fn set_signing_key(&mut self, _key: (), chain_id: String) {
        self.chain_id = chain_id;
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
        // VCA path: build registry, apply relative weight cap, rewrite
        // voting_power with VCA-derived ConsensusWeight, compute adaptive quorum.
        let vs = if let Some(vca_cfg) = &config.vca {
            let registry = build_vca_registry_from_validator_set(
                0, // genesis epoch
                &genesis_validators,
                vca_cfg.weight_config.clone(),
            );
            match compute_adaptive_quorum(&registry, &vca_cfg.quorum_config) {
                Ok(q) => {
                    self.vca_quorum = Some(q);
                    let mut vs = genesis_validators;
                    apply_vca_weights_to_validator_set(&mut vs, &registry);
                    tracing::info!(
                        epoch        = 0,
                        validators   = vs.validators.len(),
                        total_weight = vs.total_power(),
                        vca_quorum   = q,
                        "VCA-PQ-BFT genesis: weights and adaptive quorum set"
                    );
                    vs
                }
                Err(VcaError::EmergencyQuorum) => {
                    tracing::error!("genesis VCA registry: all personhood expired — EmergencyQuorum");
                    return Err(ConsensusError::Internal(
                        "VCA genesis error: all validators have expired personhood".into()
                    ));
                }
                Err(e) => {
                    tracing::error!(error = %e, "VCA genesis quorum computation failed");
                    return Err(ConsensusError::Internal(format!("VCA genesis error: {e}")));
                }
            }
        } else if let Some(pop_cfg) = &config.personhood {
            // Legacy path: static personhood cap.
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
            variant      = %self.name(),
            validators   = vs.validators.len(),
            total_power  = vs.total_power(),
            quorum_power = vs.quorum_power(),
            vca_enabled  = config.vca.is_some(),
            "consensus engine initialised"
        );

        self.chain_id = config.chain_id.clone();
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

    fn update_validator_set(&mut self, vs: ValidatorSet) -> Result<(), ConsensusError> {
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
        let _cfg = self.require_config()?;
        let _vs  = self.require_validator_set()?;

        if height != self.height {
            return Err(ConsensusError::StaleMessage(height, self.height));
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

        // Sign before moving parent_hash into the struct.
        #[cfg(feature = "real-crypto")]
        let signature = if let Some(ref kp) = self.signing_key {
            let bytes = proposal_signing_bytes(&self.chain_id, height, round, &block_hash, &parent_hash);
            ClassicalScheme.sign(&bytes, kp).map(|s| s.bytes).unwrap_or_default()
        } else { vec![] };
        #[cfg(not(feature = "real-crypto"))]
        let signature = vec![];

        let proposal = BlockProposal {
            height,
            round,
            proposer,
            block_hash: block_hash.clone(),
            parent_hash,
            timestamp_ms: now_ms,
            tx_data,
            signature,
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
            return Err(ConsensusError::StaleMessage(proposal.height, self.height));
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

        // Verify the proposer's signature if we have the crypto feature and
        // the proposal carries a non-empty signature.
        #[cfg(feature = "real-crypto")]
        if !proposal.signature.is_empty() {
            let vs = self.validator_set.as_ref()
                .ok_or_else(|| ConsensusError::Internal("no validator set".into()))?;
            let pub_key = vs.public_key_of(&proposal.proposer);
            if !pub_key.is_empty() {
                let msg = proposal_signing_bytes(
                    &self.chain_id, proposal.height, proposal.round,
                    &proposal.block_hash, &proposal.parent_hash,
                );
                let sig = Signature { scheme: SchemeId::Classical, bytes: proposal.signature.clone() };
                ClassicalScheme.verify(&msg, &sig, pub_key).map_err(|_|
                    ConsensusError::MalformedProposal(format!(
                        "invalid signature from proposer {}", proposal.proposer
                    ))
                )?;
            }
        }

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
            return Err(ConsensusError::StaleMessage(vote.height, self.height));
        }

        // Reject votes from unknown validators.
        if vs.power_of(&vote.validator) == 0 {
            return Err(ConsensusError::UnknownValidator(vote.validator.clone()));
        }

        // Verify the vote's signature if we have the crypto feature.
        #[cfg(feature = "real-crypto")]
        if !vote.signature.is_empty() {
            let vs = self.validator_set.as_ref()
                .ok_or_else(|| ConsensusError::Internal("no validator set".into()))?;
            let pub_key = vs.public_key_of(&vote.validator);
            if !pub_key.is_empty() {
                let msg = vote_signing_bytes(
                    &self.chain_id, &vote.vote_type, vote.height, vote.round,
                    vote.block_hash.as_ref(),
                );
                let sig = Signature { scheme: SchemeId::Classical, bytes: vote.signature.clone() };
                ClassicalScheme.verify(&msg, &sig, pub_key).map_err(|e|
                    ConsensusError::InvalidVote {
                        validator:  vote.validator.clone(),
                        block_hash: vote.block_hash.clone()
                            .unwrap_or_else(|| BlockHash("nil".into())),
                        reason:     format!("invalid signature: {e}"),
                    }
                )?;
            }
        }

        let round_votes = self.votes.entry(vote.round).or_default();

        match vote.vote_type {
            VoteType::Prevote | VoteType::Nil => {
                // Check for equivocation: same validator, same round, different
                // non-nil block hash → double-prevote.
                //
                // A nil prevote followed by a real-block prevote (or vice-versa)
                // is NOT equivocation: it is standard BFT round-change behavior
                // (lock release / polka-nil → new proposal).  Only two different
                // non-nil block hashes at the same (height, round) constitute a
                // double-sign.  KNOWN_ISSUES §2 root cause: the previous check
                // treated nil-vs-real as equivocation, which tombstoned validators
                // that simply changed their vote during the startup gossip race.
                if let Some(existing) = round_votes.prevotes.get(&vote.validator) {
                    let is_equivocation =
                        existing.block_hash.is_some()
                        && vote.block_hash.is_some()
                        && existing.block_hash != vote.block_hash;
                    if is_equivocation {
                        let hash_a = existing.block_hash.clone()
                            .unwrap_or_else(|| BlockHash("nil".into()));
                        let hash_b = vote.block_hash.clone()
                            .unwrap_or_else(|| BlockHash("nil".into()));
                        warn!(
                            validator = %vote.validator,
                            height    = vote.height,
                            round     = vote.round,
                            hash_a    = %hash_a,
                            hash_b    = %hash_b,
                            "equivocation detected: double-prevote (two real blocks)"
                        );
                        self.pending_equivocations.push(EquivocationDetected {
                            validator_id:   vote.validator.clone(),
                            height:         vote.height,
                            round:          vote.round,
                            vote_type_byte: 0,
                            block_hash_a:   hash_a,
                            block_hash_b:   hash_b,
                            signature_a:    existing.signature.clone(),
                            signature_b:    vote.signature.clone(),
                        });
                    }
                }
                // Idempotent: record the first prevote; a second (equivocating)
                // one is noted above but the slot keeps the first for quorum math.
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
                // Check for equivocation: same validator, same round, different
                // non-nil block hash → double-precommit.
                //
                // Nil-vs-real is NOT equivocation (same reasoning as prevote above:
                // standard BFT allows a precommit-nil to be superseded by a real
                // precommit in the same round after a polka is observed).  Only two
                // conflicting real-block precommits constitute a double-sign.
                if let Some(existing) = round_votes.precommits.get(&vote.validator) {
                    let is_equivocation =
                        existing.block_hash.is_some()
                        && vote.block_hash.is_some()
                        && existing.block_hash != vote.block_hash;
                    if is_equivocation {
                        let hash_a = existing.block_hash.clone()
                            .unwrap_or_else(|| BlockHash("nil".into()));
                        let hash_b = vote.block_hash.clone()
                            .unwrap_or_else(|| BlockHash("nil".into()));
                        warn!(
                            validator = %vote.validator,
                            height    = vote.height,
                            round     = vote.round,
                            hash_a    = %hash_a,
                            hash_b    = %hash_b,
                            "equivocation detected: double-precommit (two real blocks)"
                        );
                        self.pending_equivocations.push(EquivocationDetected {
                            validator_id:   vote.validator.clone(),
                            height:         vote.height,
                            round:          vote.round,
                            vote_type_byte: 1,
                            block_hash_a:   hash_a,
                            block_hash_b:   hash_b,
                            signature_a:    existing.signature.clone(),
                            signature_b:    vote.signature.clone(),
                        });
                    }
                }
                round_votes.precommits
                    .entry(vote.validator.clone())
                    .or_insert_with(|| vote.clone());

                // Check if we now have 2/3+ precommits for any block.
                let winning_hash_opt = self.check_precommit_quorum();
                if let Some(winning_hash) = winning_hash_opt {
                    let round_votes2 = self.votes.entry(vote.round).or_default();
                    let precommits = round_votes2.precommit_votes_for(&winning_hash);

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
        // locked_block was missing from this reset -- once set (on reaching
        // precommit quorum for a block), it was never cleared anywhere,
        // meaning a node that committed even one block would permanently
        // reject every future height's proposal forever, since a proposal's
        // block_hash is always specific to its own height and can never
        // match a lock left over from an earlier one. This is what made a
        // 4-node testnet reliably commit exactly ONE block and then stall
        // at every height after that, regardless of peering, gossip, or
        // round-timer behavior -- the lock check in receive_proposal (see
        // "locked on X but proposal is for Y") was correctly doing its job;
        // it just never got told the old lock was no longer relevant. A
        // lock only has meaning within the height it was set in.
        self.locked_block     = None;

        // Update validator set if the commit triggered an epoch change.
        if let Some(incoming_vs) = new_validator_set {
            let epoch = self.height; // new epoch == new height after advancing

            // VCA path: rebuild registry, apply relative weight cap, rewrite
            // voting_power, and compute the new adaptive quorum threshold.
            let vs = if let Some(vca_cfg) = self.config.as_ref().and_then(|c| c.vca.as_ref()) {
                let registry = build_vca_registry_from_validator_set(
                    epoch,
                    &incoming_vs,
                    vca_cfg.weight_config.clone(),
                );
                match compute_adaptive_quorum(&registry, &vca_cfg.quorum_config) {
                    Ok(q) => {
                        self.vca_quorum = Some(q);
                        let mut vs = incoming_vs;
                        apply_vca_weights_to_validator_set(&mut vs, &registry);
                        tracing::info!(
                            epoch        = epoch,
                            validators   = vs.validators.len(),
                            total_weight = vs.total_power(),
                            vca_quorum   = q,
                            "VCA-PQ-BFT epoch rotation: weights and adaptive quorum updated"
                        );
                        vs
                    }
                    Err(VcaError::EmergencyQuorum) => {
                        tracing::error!(
                            epoch = epoch,
                            "VCA epoch rotation: all personhood expired — EmergencyQuorum \
                             (chain requires reconfiguration; keeping old validator set)"
                        );
                        return Err(ConsensusError::Internal(
                            "VCA epoch error: all validators have expired personhood — \
                             emergency reconfiguration required".into()
                        ));
                    }
                    Err(e) => {
                        tracing::error!(epoch = epoch, error = %e, "VCA epoch quorum computation failed");
                        return Err(ConsensusError::Internal(format!("VCA epoch error: {e}")));
                    }
                }
            } else if let Some(pop_cfg) = self.config.as_ref().and_then(|c| c.personhood.as_ref()) {
                // Legacy path: static personhood cap.
                apply_personhood_cap(incoming_vs, &pop_cfg.clone())
            } else {
                incoming_vs
            };

            info!(
                new_height          = self.height,
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
        // VCA-PQ-BFT path: use adaptive quorum derived from verified-personhood
        // fraction ρ instead of the static 2n/3+1 threshold.
        // Falls back to static quorum_power() when VCA is not configured.
        let quorum = self.vca_quorum.unwrap_or_else(|| validator_set.quorum_power());

        // Only consider well-formed precommits: correct type, height, and
        // block hash. Malformed entries are ignored rather than rejected so
        // a certificate with a few garbage entries still verifies if the
        // good entries meet quorum (consistent with Tendermint light-client
        // spec, which says "at least 2/3 must be valid").
        let valid_precommits: Vec<&Vote> = certificate
            .precommits
            .iter()
            .filter(|v| {
                v.vote_type == VoteType::Precommit
                    && v.height == certificate.height
                    && v.block_hash.as_ref() == Some(&certificate.block_hash)
            })
            .collect();

        // -- Phase 1: individual signature verification ----------------------
        // Verify every precommit that carries a non-empty signature.
        // Precommits with empty signatures (Phase 0 / observer nodes) are
        // counted toward power but not cryptographically verified; once all
        // validators sign, every precommit will have a signature.
        #[cfg(feature = "real-crypto")]
        for vote in &valid_precommits {
            if vote.signature.is_empty() { continue; }

            let pub_key = validator_set.public_key_of(&vote.validator);
            if pub_key.is_empty() {
                // No registered key → skip verification for this signer.
                // (New validator that hasn't had its key backfilled yet.)
                continue;
            }

            let msg = vote_signing_bytes(
                &self.chain_id,
                &vote.vote_type,
                vote.height,
                vote.round,
                vote.block_hash.as_ref(),
            );
            let sig = Signature {
                scheme: SchemeId::Classical,
                bytes: vote.signature.clone(),
            };
            ClassicalScheme.verify(&msg, &sig, pub_key).map_err(|_| {
                ConsensusError::InvalidVote {
                    validator:  vote.validator.clone(),
                    block_hash: certificate.block_hash.clone(),
                    reason:     format!(
                        "invalid precommit signature in commit certificate \
                         at height {} round {}",
                        vote.height, vote.round
                    ),
                }
            })?;
        }

        // -- Power accumulation ----------------------------------------------
        // Count power only from the precommits that passed structural checks
        // (and signature checks above where applicable).
        let signed_power: u64 = valid_precommits
            .iter()
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

        Ok(())
    }

    fn drain_equivocations(&mut self) -> Vec<EquivocationDetected> {
        std::mem::take(&mut self.pending_equivocations)
    }
}

// -- HotStuffEngine ----------------------------------------------------------

/// HotStuff-style BFT consensus engine.
///
/// HotStuff (Abraham, Malkhi, Spiegelman 2018) achieves linear message
/// complexity per block by using a three-phase pipelined protocol with a
/// stable rotating leader. Key differences from Tendermint:
///
///   Tendermint:   O(n²) messages per block (all-to-all prevote + precommit)
///   HotStuff:     O(n) messages per block (leader aggregates, fans out)
///
/// The tradeoff: HotStuff requires a trusted threshold signature scheme to
/// aggregate votes efficiently. In Phase 0 (no real crypto), we simulate
/// the aggregation by tracking individual votes -- the safety and liveness
/// properties hold, the communication pattern is simplified.
///
/// Three phases per block:
///   PREPARE:    Leader proposes block extending locked_qc. Validators vote
///               PREPARE if the proposal is safe (extends their lock or is
///               endorsed by a higher-view prepare_qc).
///   PRE-COMMIT: Leader broadcasts PREPARE QC. Validators vote PRE-COMMIT,
///               updating their prepare_qc to this QC.
///   COMMIT:     Leader broadcasts PRE-COMMIT QC. Validators vote COMMIT,
///               locking on the block (locked_qc = PRE-COMMIT QC).
///               On 2f+1 COMMIT votes, block is committed.
///
/// Safety invariant: a validator only votes for block b in PREPARE if
///   b.parent == locked_qc.block_hash  OR  prepare_qc.view > locked_qc.view
/// This ensures two blocks are never committed at the same height.
///
/// View-change: on timeout, validators broadcast a NewView message carrying
/// their highest prepare_qc. The new leader waits for 2f+1 NewView messages,
/// picks the highest-view prepare_qc among them, and proposes the block it
/// extends (or a new block if that QC is nil). This is HotStuff's linear
/// view-change protocol.
///
/// Pipelining: COMMIT for block k happens in the PREPARE phase of block k+2,
/// so the effective latency is one round-trip per block rather than three.
/// This implementation performs non-pipelined three-phase logic per block to
/// keep the code unambiguous; pipelining is a Phase 1 optimisation.
///
/// Personhood weighting: applied identically to TendermintEngine via
/// `apply_personhood_cap()`. The power cap is a QCB-specific constraint
/// layered on top of HotStuff's standard quorum rules.
///
/// VCA integration: when `ConsensusConfig.vca` is set, an adaptive quorum
/// derived from the verified-personhood fraction ρ replaces the static
/// 2n/3+1 threshold, matching the TendermintEngine integration.
///
/// Equivocation detection: the engine tracks one vote per validator per phase.
/// A second conflicting vote from the same validator triggers an
/// EquivocationDetected event, which the node routes to evidence handling.
///
/// Whitepaper ref: Section 3 / ConsensusVariant::HotStuffStyle.
/// Open Question 2: which variant QCB ultimately uses depends on scale.

// ── HotStuff-specific types ──────────────────────────────────────────────────

/// A Quorum Certificate: evidence that 2f+1 validators voted for a specific
/// (view, block) pair in a specific phase. In a real HotStuff implementation
/// this would be a BLS threshold signature; here we carry the individual
/// Vote structs and verify by summing voting power.
#[derive(Debug, Clone)]
pub struct QuorumCertificate {
    /// The consensus view (height * MAX_ROUNDS + round) this QC was formed in.
    pub view:       u64,
    /// Block height.
    pub height:     BlockHeight,
    /// Round within height.
    pub round:      Round,
    /// The block hash this QC certifies.
    pub block_hash: BlockHash,
    /// The votes that form this QC (≥ 2f+1 by voting power).
    pub votes:      Vec<Vote>,
}

impl QuorumCertificate {
    /// Canonical view number: used for ordering QCs across heights and rounds.
    pub fn view(height: BlockHeight, round: Round) -> u64 {
        (height as u64) * 10_000 + (round as u64)
    }

    /// Total voting power represented in this QC.
    pub fn power(&self, vs: &ValidatorSet) -> u64 {
        self.votes.iter().map(|v| vs.power_of(&v.validator)).sum()
    }
}

/// A NewView message sent on timeout.
/// The new leader collects 2f+1 NewView messages and extracts the
/// highest-view prepare_qc to determine the safe proposal.
#[derive(Debug, Clone)]
pub struct HotStuffNewView {
    pub validator:  ValidatorId,
    pub height:     BlockHeight,
    pub new_round:  Round,
    /// The highest prepare_qc this validator holds (None at genesis).
    pub prepare_qc: Option<QuorumCertificate>,
}

/// Which phase of the HotStuff protocol we are in for the current (height, round).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotStuffPhase {
    /// Waiting for the leader's PREPARE message (block proposal).
    WaitingForPrepare,
    /// Collected the proposal; accumulating PREPARE votes.
    CollectingPrepareVotes,
    /// Collected PREPARE QC; accumulating PRE-COMMIT votes.
    CollectingPreCommitVotes,
    /// Collected PRE-COMMIT QC; accumulating COMMIT votes.
    CollectingCommitVotes,
    /// Block committed. Waiting for on_commit() to advance height.
    Committed,
}

/// Per-phase vote accumulator tracking full Vote structs for equivocation
/// detection and QC construction.
#[derive(Debug, Default, Clone)]
struct HsVoteAccum {
    /// One entry per validator. Value = (first vote accepted, power).
    votes: BTreeMap<ValidatorId, (Vote, u64)>,
}

impl HsVoteAccum {
    fn clear(&mut self) { self.votes.clear(); }

    /// Accept a vote. Returns:
    ///   Ok(true)  — first vote from this validator, accepted.
    ///   Ok(false) — duplicate of already-accepted vote, silently dropped.
    ///   Err(equivoc) — conflicting vote (different block_hash): evidence returned.
    fn accept(
        &mut self,
        vote: Vote,
        power: u64,
    ) -> Result<bool, crate::tendermint::EquivocationDetected> {
        use std::collections::btree_map::Entry;
        match self.votes.entry(vote.validator.clone()) {
            Entry::Vacant(e) => {
                e.insert((vote, power));
                Ok(true)
            }
            Entry::Occupied(existing) => {
                let (prev, _) = existing.get();
                if prev.block_hash == vote.block_hash {
                    Ok(false) // exact duplicate
                } else {
                    // Conflicting vote — emit equivocation evidence
                    let vote_type_byte = match vote.vote_type {
                        VoteType::Prevote   => 0,
                        VoteType::Precommit => 1,
                        VoteType::Nil       => 2,
                    };
                    let hash_a = prev.block_hash.clone()
                        .unwrap_or_else(|| BlockHash("nil".into()));
                    let hash_b = vote.block_hash.clone()
                        .unwrap_or_else(|| BlockHash("nil".into()));
                    Err(crate::tendermint::EquivocationDetected {
                        validator_id:   vote.validator.clone(),
                        height:         vote.height,
                        round:          vote.round,
                        vote_type_byte,
                        block_hash_a:   hash_a,
                        block_hash_b:   hash_b,
                        signature_a:    prev.signature.clone(),
                        signature_b:    vote.signature.clone(),
                    })
                }
            }
        }
    }

    /// Total voting power in the accumulator.
    fn power(&self) -> u64 {
        self.votes.values().map(|(_, p)| *p).sum()
    }

    fn has_quorum(&self, quorum: u64) -> bool {
        self.power() >= quorum
    }

    /// Extract a QuorumCertificate once quorum is reached.
    fn to_qc(&self, height: BlockHeight, round: Round, block_hash: BlockHash) -> QuorumCertificate {
        QuorumCertificate {
            view:  QuorumCertificate::view(height, round),
            height,
            round,
            block_hash,
            votes: self.votes.values().map(|(v, _)| v.clone()).collect(),
        }
    }

    /// Extract vote list as CommitCertificate precommits.
    fn to_precommits(&self) -> Vec<Vote> {
        self.votes.values().map(|(v, _)| v.clone()).collect()
    }
}

pub struct HotStuffEngine {
    config:     ConsensusConfig,
    validators: ValidatorSet,
    height:     BlockHeight,
    round:      Round,
    phase:      HotStuffPhase,

    /// Current pending proposal (set on receive_proposal).
    pending:    Option<BlockProposal>,

    /// PREPARE votes for the pending block.
    prepare_votes:   HsVoteAccum,
    /// PRE-COMMIT votes after PREPARE QC formed.
    precommit_votes: HsVoteAccum,
    /// COMMIT votes after PRE-COMMIT QC formed.
    commit_votes:    HsVoteAccum,

    /// PREPARE QC from the most recent round where we observed 2f+1 PREPARE
    /// votes. Used for the safe-block rule: in a new view the leader includes
    /// this QC so replicas can verify the proposal is safe to vote for.
    prepare_qc: Option<QuorumCertificate>,

    /// The QC we are locked on (PRE-COMMIT QC for the most recently locked
    /// block). Safety rule: we only vote PREPARE for b if
    ///   b extends locked_qc.block_hash  OR  prepare_qc.view > locked_qc.view.
    locked_qc: Option<QuorumCertificate>,

    /// NewView messages collected during view-change (keyed by validator).
    new_views: BTreeMap<ValidatorId, HotStuffNewView>,

    /// Equivocation evidence pending draining by the node.
    pending_equivocations: Vec<crate::tendermint::EquivocationDetected>,

    /// VCA-derived quorum threshold (replaces static 2n/3+1 when set).
    vca_quorum: Option<u64>,
}

impl HotStuffEngine {
    pub fn new() -> Self {
        Self {
            config: ConsensusConfig {
                variant:              ConsensusVariant::HotStuffStyle,
                chain_id:             String::new(),
                propose_timeout_ms:   3_000,
                prevote_timeout_ms:   1_000,
                precommit_timeout_ms: 1_000,
                block_time_ms:        1_000,
                personhood:           None,
                vca:                  None,
            },
            validators:            ValidatorSet { height: 0, validators: vec![] },
            height:                0,
            round:                 0,
            phase:                 HotStuffPhase::WaitingForPrepare,
            pending:               None,
            prepare_votes:         HsVoteAccum::default(),
            precommit_votes:       HsVoteAccum::default(),
            commit_votes:          HsVoteAccum::default(),
            prepare_qc:            None,
            locked_qc:             None,
            new_views:             BTreeMap::new(),
            pending_equivocations: Vec::new(),
            vca_quorum:            None,
        }
    }

    /// The current leader (round-robin rotation by height + round).
    pub fn current_leader(&self) -> Option<&ValidatorId> {
        if self.validators.validators.is_empty() { return None; }
        let idx = (self.height as usize + self.round as usize)
            % self.validators.validators.len();
        Some(&self.validators.validators[idx].id)
    }

    /// Active quorum threshold: VCA-derived when set, otherwise 2n/3+1.
    fn quorum(&self) -> u64 {
        self.vca_quorum.unwrap_or_else(|| self.validators.quorum_power())
    }

    /// Safety check for the PREPARE phase (HotStuff Theorem 2).
    ///
    /// Returns true if it is safe to vote PREPARE for a block with the
    /// given `parent_hash`:
    ///   (a) the proposal extends our locked block, OR
    ///   (b) our prepare_qc covers a view higher than our lock's view
    ///       (meaning the network has already moved past our lock).
    fn safe_to_vote(&self, parent_hash: &BlockHash) -> bool {
        match (&self.locked_qc, &self.prepare_qc) {
            (None, _) => true, // no lock yet — always safe
            (Some(lock), _) if &lock.block_hash == parent_hash => true, // extends lock
            (Some(lock), Some(prep)) if prep.view > lock.view => true,  // higher-view QC
            _ => false,
        }
    }

    /// Reset all per-round vote state. Called on phase transitions and view change.
    fn reset_round_state(&mut self) {
        self.pending = None;
        self.prepare_votes.clear();
        self.precommit_votes.clear();
        self.commit_votes.clear();
        self.new_views.clear();
        self.phase = HotStuffPhase::WaitingForPrepare;
    }

    /// Build a CommitCertificate from accumulated COMMIT votes.
    fn make_certificate(&self, block_hash: BlockHash) -> CommitCertificate {
        CommitCertificate {
            height:     self.height,
            round:      self.round,
            block_hash,
            precommits: self.commit_votes.to_precommits(),
        }
    }

    /// Record a NewView message (used during view-change).
    /// Returns true when we've collected 2f+1 NewView messages from distinct
    /// validators, meaning the new leader can safely propose.
    pub fn record_new_view(&mut self, nv: HotStuffNewView) -> bool {
        self.new_views.entry(nv.validator.clone()).or_insert(nv);
        let total_power: u64 = self.new_views.keys()
            .map(|id| self.validators.power_of(id))
            .sum();
        total_power >= self.quorum()
    }

    /// Among all collected NewView messages, find the highest-view prepare_qc.
    /// The new leader uses this to determine the safe block to propose.
    pub fn highest_new_view_qc(&self) -> Option<&QuorumCertificate> {
        self.new_views.values()
            .filter_map(|nv| nv.prepare_qc.as_ref())
            .max_by_key(|qc| qc.view)
    }
}

impl Default for HotStuffEngine {
    fn default() -> Self { Self::new() }
}

#[async_trait::async_trait]
impl ConsensusEngine for HotStuffEngine {
    fn name(&self) -> &str { "HotStuff-style BFT (three-phase, QC-locked)" }
    fn variant(&self) -> ConsensusVariant { ConsensusVariant::HotStuffStyle }

    async fn init(
        &mut self,
        config: ConsensusConfig,
        mut genesis_validators: ValidatorSet,
    ) -> ConsensusResult<()> {
        // Apply personhood cap if configured (Section 3.3)
        if let Some(ref pc) = config.personhood {
            genesis_validators = apply_personhood_cap(genesis_validators, pc);
        }
        if genesis_validators.validators.is_empty() {
            return Err(ConsensusError::InsufficientValidators { needed: 1, have: 0 });
        }

        // VCA path: build registry, apply weights, derive adaptive quorum.
        let vs = if let Some(vca_cfg) = &config.vca {
            let registry = build_vca_registry_from_validator_set(
                0, // genesis epoch
                &genesis_validators,
                vca_cfg.weight_config.clone(),
            );
            match compute_adaptive_quorum(&registry, &vca_cfg.quorum_config) {
                Ok(q) => {
                    self.vca_quorum = Some(q);
                    let mut vs = genesis_validators;
                    apply_vca_weights_to_validator_set(&mut vs, &registry);
                    tracing::info!(
                        epoch        = 0,
                        validators   = vs.validators.len(),
                        total_weight = vs.total_power(),
                        vca_quorum   = q,
                        "HotStuff-VCA genesis: weights and adaptive quorum set"
                    );
                    vs
                }
                Err(e) => {
                    tracing::warn!(error = %e, "HotStuff-VCA quorum computation failed, using static 2f+1");
                    genesis_validators
                }
            }
        } else {
            genesis_validators
        };

        self.validators = vs;
        self.config     = config;
        self.reset_round_state();

        tracing::info!(
            variant      = "HotStuff-style BFT",
            validators   = self.validators.validators.len(),
            total_power  = self.validators.total_power(),
            quorum_power = self.quorum(),
            "HotStuff consensus engine initialised"
        );
        Ok(())
    }

    fn validator_set(&self) -> &ValidatorSet { &self.validators }
    fn current_height(&self) -> BlockHeight  { self.height }
    fn current_round(&self)  -> Round        { self.round  }

    fn update_validator_set(&mut self, mut vs: ValidatorSet) -> Result<(), ConsensusError> {
        if let Some(ref pc) = self.config.personhood.clone() {
            vs = apply_personhood_cap(vs, pc);
        }
        if let Some(vca_cfg) = &self.config.vca.clone() {
            let registry = build_vca_registry_from_validator_set(
                self.height,
                &vs,
                vca_cfg.weight_config.clone(),
            );
            if let Ok(q) = compute_adaptive_quorum(&registry, &vca_cfg.quorum_config) {
                self.vca_quorum = Some(q);
                apply_vca_weights_to_validator_set(&mut vs, &registry);
            }
        }
        self.validators = vs;
        Ok(())
    }

    async fn propose(
        &mut self,
        height:      BlockHeight,
        round:       Round,
        parent_hash: BlockHash,
        tx_data:     Vec<u8>,
    ) -> ConsensusResult<BlockProposal> {
        let proposer = self.current_leader()
            .cloned()
            .unwrap_or_else(|| ValidatorId("solo".into()));

        // If we have a highest NewView QC, propose the block it extends
        // (safe proposal rule). Otherwise use the provided parent_hash.
        let safe_parent = self.highest_new_view_qc()
            .map(|qc| qc.block_hash.clone())
            .unwrap_or(parent_hash);

        let block_hash = BlockHash(format!(
            "hs_h{height}_r{round}_{:08x}",
            tx_data.len() as u32
        ));

        let proposal = BlockProposal {
            height,
            round,
            proposer,
            block_hash,
            parent_hash: safe_parent,
            timestamp_ms: 0,
            tx_data,
            signature: vec![],
        };

        tracing::debug!(
            height, round,
            leader = %proposal.proposer,
            locked_qc = ?self.locked_qc.as_ref().map(|q| &q.block_hash),
            "HotStuff PREPARE: block proposed"
        );
        Ok(proposal)
    }

    async fn receive_proposal(
        &mut self,
        proposal: BlockProposal,
    ) -> ConsensusResult<()> {
        if proposal.height < self.height {
            return Err(ConsensusError::StaleMessage(proposal.height, self.height));
        }

        // Safety rule: only vote PREPARE for b if it is safe per locked_qc.
        if !self.safe_to_vote(&proposal.parent_hash) {
            return Err(ConsensusError::MalformedProposal(format!(
                "LockViolation: proposal at h={} r={} extends {} but we are locked on {}",
                proposal.height, proposal.round, proposal.parent_hash.0,
                self.locked_qc.as_ref().map(|q| q.block_hash.0.as_str()).unwrap_or("none")
            )));
        }

        // Accept: reset phase votes and start collecting PREPARE votes.
        self.prepare_votes.clear();
        self.precommit_votes.clear();
        self.commit_votes.clear();
        self.pending = Some(proposal.clone());
        self.phase   = HotStuffPhase::CollectingPrepareVotes;

        tracing::debug!(
            height = proposal.height,
            round  = proposal.round,
            hash   = %proposal.block_hash,
            "HotStuff: PREPARE phase started"
        );
        Ok(())
    }

    async fn receive_vote(
        &mut self,
        vote: Vote,
    ) -> ConsensusResult<Option<CommitCertificate>> {
        let power = self.validators.power_of(&vote.validator);
        if power == 0 {
            return Err(ConsensusError::UnknownValidator(vote.validator));
        }

        let block_hash = match vote.block_hash.clone() {
            Some(h) => h,
            None    => return Ok(None), // nil vote advances round, handled in on_timeout
        };

        let quorum = self.quorum();

        match self.phase {
            HotStuffPhase::CollectingPrepareVotes => {
                match self.prepare_votes.accept(vote.clone(), power) {
                    Err(ev) => { self.pending_equivocations.push(ev); }
                    Ok(_) => {}
                }
                if self.prepare_votes.has_quorum(quorum) {
                    // Form PREPARE QC and update prepare_qc (safe for higher-view rule).
                    let qc = self.prepare_votes.to_qc(self.height, self.round, block_hash.clone());
                    // Update prepare_qc if this QC is higher-view than what we hold.
                    let update = match &self.prepare_qc {
                        None     => true,
                        Some(pq) => qc.view > pq.view,
                    };
                    if update { self.prepare_qc = Some(qc); }
                    self.phase = HotStuffPhase::CollectingPreCommitVotes;
                    tracing::debug!(
                        height = self.height, round = self.round,
                        "HotStuff: PREPARE QC formed — advancing to PRE-COMMIT"
                    );
                }
            }
            HotStuffPhase::CollectingPreCommitVotes => {
                match self.precommit_votes.accept(vote.clone(), power) {
                    Err(ev) => { self.pending_equivocations.push(ev); }
                    Ok(_) => {}
                }
                if self.precommit_votes.has_quorum(quorum) {
                    // Form PRE-COMMIT QC — this becomes our locked_qc.
                    let qc = self.precommit_votes.to_qc(self.height, self.round, block_hash.clone());
                    // Lock rule: update locked_qc if this QC is higher-view.
                    let update = match &self.locked_qc {
                        None     => true,
                        Some(lq) => qc.view > lq.view,
                    };
                    if update { self.locked_qc = Some(qc); }
                    self.phase = HotStuffPhase::CollectingCommitVotes;
                    tracing::debug!(
                        height = self.height, round = self.round,
                        "HotStuff: PRE-COMMIT QC formed — locked, advancing to COMMIT"
                    );
                }
            }
            HotStuffPhase::CollectingCommitVotes => {
                match self.commit_votes.accept(vote.clone(), power) {
                    Err(ev) => { self.pending_equivocations.push(ev); }
                    Ok(_) => {}
                }
                if self.commit_votes.has_quorum(quorum) {
                    self.phase = HotStuffPhase::Committed;
                    let cert = self.make_certificate(block_hash.clone());
                    tracing::info!(
                        height = cert.height,
                        round  = cert.round,
                        block  = %cert.block_hash,
                        "HotStuff: COMMIT QC formed — block committed"
                    );
                    return Ok(Some(cert));
                }
            }
            HotStuffPhase::WaitingForPrepare | HotStuffPhase::Committed => {
                tracing::debug!(
                    phase = ?self.phase,
                    validator = %vote.validator,
                    "HotStuff: vote in unexpected phase, ignoring"
                );
            }
        }
        Ok(None)
    }

    async fn on_timeout(
        &mut self,
        height: BlockHeight,
        round:  Round,
    ) -> ConsensusResult<Vote> {
        tracing::warn!(height, round, "HotStuff: round timed out — view change");

        // Advance view.
        self.round = round + 1;
        self.reset_round_state();

        // Broadcast NewView so the new leader can determine the safe block.
        // In this Phase 0 implementation the NewView is encoded as a Nil vote;
        // the full NewView type is available for out-of-band use by the node.
        let nil_vote = Vote {
            vote_type:  VoteType::Nil,
            height,
            round,
            validator:  self.current_leader()
                .cloned()
                .unwrap_or_else(|| ValidatorId("self".into())),
            block_hash: None,
            signature:  vec![],
        };
        Ok(nil_vote)
    }

    async fn on_commit(
        &mut self,
        certificate:       CommitCertificate,
        new_validator_set: Option<ValidatorSet>,
    ) -> ConsensusResult<()> {
        self.height    = certificate.height + 1;
        self.round     = 0;
        // Unlock: locked_qc is cleared on successful commit so the next
        // height's proposal is accepted without a stale height lock.
        self.locked_qc = None;
        self.reset_round_state();

        if let Some(new_set) = new_validator_set {
            self.update_validator_set(new_set)
                .map_err(|e| ConsensusError::Internal(e.to_string()))?;
        }

        tracing::info!(
            height = self.height,
            "HotStuff: committed, advancing to next height"
        );
        Ok(())
    }

    fn verify_commit(
        &self,
        certificate:   &CommitCertificate,
        validator_set: &ValidatorSet,
    ) -> ConsensusResult<()> {
        let threshold = self.vca_quorum.unwrap_or_else(|| validator_set.quorum_power());
        let mut power: u64 = 0;
        let mut seen: std::collections::HashSet<&ValidatorId> = Default::default();

        for vote in &certificate.precommits {
            if vote.vote_type != VoteType::Precommit {
                return Err(ConsensusError::InvalidVote {
                    validator:  vote.validator.clone(),
                    block_hash: certificate.block_hash.clone(),
                    reason:     "non-precommit vote in HotStuff commit certificate".into(),
                });
            }
            if vote.block_hash.as_ref() != Some(&certificate.block_hash) {
                return Err(ConsensusError::InvalidVote {
                    validator:  vote.validator.clone(),
                    block_hash: certificate.block_hash.clone(),
                    reason:     format!(
                        "vote block_hash {:?} does not match certificate block_hash {}",
                        vote.block_hash, certificate.block_hash
                    ),
                });
            }
            if !seen.insert(&vote.validator) {
                return Err(ConsensusError::InvalidVote {
                    validator:  vote.validator.clone(),
                    block_hash: certificate.block_hash.clone(),
                    reason:     "duplicate validator in commit certificate".into(),
                });
            }
            power += validator_set.power_of(&vote.validator);
        }

        if power < threshold {
            return Err(ConsensusError::InvalidVote {
                validator:  ValidatorId("quorum".into()),
                block_hash: certificate.block_hash.clone(),
                reason:     format!(
                    "insufficient commit power: {power} < {threshold} (threshold)"
                ),
            });
        }
        Ok(())
    }

    fn drain_equivocations(&mut self) -> Vec<crate::tendermint::EquivocationDetected> {
        std::mem::take(&mut self.pending_equivocations)
    }
}


// -- Engine factory functions -------------------------------------------------

/// Create a HotStuffEngine and initialise it in one call.
pub async fn new_hotstuff(
    config:     ConsensusConfig,
    validators: ValidatorSet,
) -> ConsensusResult<HotStuffEngine> {
    let mut engine = HotStuffEngine::new();
    engine.init(config, validators).await?;
    Ok(engine)
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
                    public_key: vec![],
                })
                .collect(),
        };
        (TendermintEngine::new(), vs)
    }

    fn default_config() -> ConsensusConfig {
        ConsensusConfig {
            variant:             ConsensusVariant::TendermintStyle,
            chain_id:            "test-chain".to_string(),
            propose_timeout_ms:  3_000,
            prevote_timeout_ms:  1_000,
            precommit_timeout_ms: 1_000,
            block_time_ms:       5_000,
            personhood:          None,
            vca:                 None,
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
    async fn locked_block_is_cleared_on_commit_so_next_height_is_accepted() {
        // Regression test for a real bug found live on a 4-node testnet:
        // locked_block was set on reaching precommit quorum but never
        // cleared anywhere, including on_commit. That meant a node which
        // committed even one block would permanently reject every future
        // height's proposal -- forever -- because a proposal's block_hash
        // is always specific to its own height and can never match a lock
        // left over from an earlier one. The network reliably committed
        // exactly one block and then stalled at every height after that.
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        // Reach precommit quorum at height 0 -- this is what sets locked_block.
        let block_hash_0 = BlockHash("deadbeef_block_0".into());
        let mut cert = None;
        for i in 0..3usize {
            let vote = Vote {
                vote_type:  VoteType::Precommit,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("val_{i:02}")),
                block_hash: Some(block_hash_0.clone()),
                signature:  vec![],
            };
            cert = engine.receive_vote(vote).await.unwrap();
        }
        let cert = cert.expect("quorum should produce a commit certificate");

        // Commit it -- this is where locked_block must be cleared.
        engine.on_commit(cert, None).await.unwrap();
        assert_eq!(engine.current_height(), 1);

        // A fresh proposal for the NEW height, with a DIFFERENT block_hash,
        // from height 1's correct deterministic proposer (val_01, since
        // proposer_for rotates by height+round over ids sorted val_00..03).
        let proposal_1 = BlockProposal {
            height:       1,
            round:        0,
            proposer:     ValidatorId("val_01".into()),
            block_hash:   BlockHash("deadbeef_block_1".into()),
            parent_hash:  block_hash_0,
            timestamp_ms: 0,
            tx_data:      vec![],
            signature:    vec![],
        };

        // Before the fix, this failed with:
        //   "block proposal is malformed: locked on block_h0 but proposal is for block_h1"
        engine.receive_proposal(proposal_1).await
            .expect("height 1's proposal must be accepted -- the height-0 lock must not persist");
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
    async fn verify_commit_accepts_empty_signatures() {
        // Phase-0 path: precommits with empty signatures should still count
        // toward power and allow the certificate to pass quorum check.
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let block_hash = BlockHash("empty_sig_test".into());

        // 3 precommits with no signatures -- meets quorum of 3 for 4 validators.
        let cert = CommitCertificate {
            height: 0,
            round: 0,
            block_hash: block_hash.clone(),
            precommits: (0..3usize)
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

        assert!(
            engine.verify_commit(&cert, &vs).is_ok(),
            "empty signatures should pass: they are counted toward power but not crypto-verified"
        );
    }

    /// Tests that a tampered signature causes `verify_commit` to reject the
    /// certificate. Requires the `real-crypto` feature so the signature loop
    /// actually runs (without it the loop is compiled away and any bytes pass).
    #[cfg(feature = "real-crypto")]
    #[tokio::test]
    async fn verify_commit_rejects_tampered_signature() {
        use chain_forge_crypto::{ClassicalScheme, SchemeId, SignatureScheme, Signature};

        let chain_id = "test-chain";
        let block_hash = BlockHash("tamper_test_block".into());

        // Build a 4-validator set with real Ed25519 public keys.
        let kp0 = ClassicalScheme.generate_keypair("seed-val-0").unwrap();
        let kp1 = ClassicalScheme.generate_keypair("seed-val-1").unwrap();
        let kp2 = ClassicalScheme.generate_keypair("seed-val-2").unwrap();
        let keypairs = [&kp0, &kp1, &kp2];

        let vs = ValidatorSet {
            height: 0,
            validators: vec![
                ValidatorInfo { id: ValidatorId("val_00".into()), voting_power: 1,
                    pop_verified: true, public_key: kp0.public_key.clone() },
                ValidatorInfo { id: ValidatorId("val_01".into()), voting_power: 1,
                    pop_verified: true, public_key: kp1.public_key.clone() },
                ValidatorInfo { id: ValidatorId("val_02".into()), voting_power: 1,
                    pop_verified: true, public_key: kp2.public_key.clone() },
                ValidatorInfo { id: ValidatorId("val_03".into()), voting_power: 1,
                    pop_verified: true, public_key: vec![] },
            ],
        };

        let mut engine = TendermintEngine::new();
        let cfg = default_config();
        // Set the chain_id so vote_signing_bytes inside verify_commit uses it.
        engine.set_signing_key(kp0.clone(), chain_id.to_string());
        engine.init(cfg, vs.clone()).await.unwrap();

        // Sign a valid precommit for each of the first 3 validators.
        let make_vote = |i: usize, kp: &chain_forge_crypto::KeyPair| -> Vote {
            let msg = vote_signing_bytes(
                chain_id, &VoteType::Precommit, 0, 0, Some(&block_hash),
            );
            let raw_sig = ClassicalScheme.sign(&msg, kp).unwrap();
            Vote {
                vote_type:  VoteType::Precommit,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("val_{i:02}")),
                block_hash: Some(block_hash.clone()),
                signature:  raw_sig.bytes,
            }
        };

        let good_votes: Vec<Vote> = keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| make_vote(i, kp))
            .collect();

        // A certificate with all good signatures passes.
        let cert_good = CommitCertificate {
            height: 0, round: 0,
            block_hash: block_hash.clone(),
            precommits: good_votes.clone(),
        };
        assert!(
            engine.verify_commit(&cert_good, &vs).is_ok(),
            "certificate with valid signatures must be accepted"
        );

        // Tamper val_01's signature by flipping one byte.
        let mut bad_votes = good_votes.clone();
        bad_votes[1].signature[0] ^= 0xFF;

        let cert_bad = CommitCertificate {
            height: 0, round: 0,
            block_hash: block_hash.clone(),
            precommits: bad_votes,
        };
        let err = engine.verify_commit(&cert_bad, &vs);
        assert!(
            err.is_err(),
            "certificate with a tampered signature must be rejected"
        );
        let err_str = format!("{}", err.unwrap_err());
        assert!(
            err_str.contains("invalid precommit signature"),
            "error message should name the cause: {err_str}"
        );
    }

    // -- Equivocation detection tests -----------------------------------------

    #[tokio::test]
    async fn double_prevote_is_detected_and_drained() {
        // A validator that prevotes for two different blocks in the same
        // height/round must be caught and surfaced via drain_equivocations.
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let block_a = BlockHash("block_alpha".into());
        let block_b = BlockHash("block_beta".into());
        let equivocator = ValidatorId("val_00".into());

        // First prevote for block_a.
        let vote_a = Vote {
            vote_type:  VoteType::Prevote,
            height:     0,
            round:      0,
            validator:  equivocator.clone(),
            block_hash: Some(block_a.clone()),
            signature:  vec![],
        };
        engine.receive_vote(vote_a).await.unwrap();
        assert!(engine.drain_equivocations().is_empty(),
            "no evidence after a single prevote");

        // Second prevote for a different block in the same slot → equivocation.
        let vote_b = Vote {
            vote_type:  VoteType::Prevote,
            height:     0,
            round:      0,
            validator:  equivocator.clone(),
            block_hash: Some(block_b.clone()),
            signature:  vec![],
        };
        engine.receive_vote(vote_b).await.unwrap();

        let evidence = engine.drain_equivocations();
        assert_eq!(evidence.len(), 1, "exactly one equivocation event");
        let ev = &evidence[0];
        assert_eq!(ev.validator_id, equivocator);
        assert_eq!(ev.height, 0);
        assert_eq!(ev.round, 0);
        assert_eq!(ev.vote_type_byte, 0, "prevote type byte = 0");
        // The two conflicting block hashes must both be recorded.
        let hashes = [&ev.block_hash_a, &ev.block_hash_b];
        assert!(hashes.contains(&&block_a), "block_a must appear in evidence");
        assert!(hashes.contains(&&block_b), "block_b must appear in evidence");

        // drain is destructive: a second call returns nothing.
        assert!(engine.drain_equivocations().is_empty(),
            "drain_equivocations must be idempotent/empty after first drain");
    }

    #[tokio::test]
    async fn double_precommit_is_detected_and_drained() {
        // Same as above but for the precommit phase.
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let block_a = BlockHash("commit_alpha".into());
        let block_b = BlockHash("commit_beta".into());
        let equivocator = ValidatorId("val_01".into());

        let vote_a = Vote {
            vote_type:  VoteType::Precommit,
            height:     0,
            round:      0,
            validator:  equivocator.clone(),
            block_hash: Some(block_a.clone()),
            signature:  vec![],
        };
        engine.receive_vote(vote_a).await.unwrap();
        assert!(engine.drain_equivocations().is_empty());

        let vote_b = Vote {
            vote_type:  VoteType::Precommit,
            height:     0,
            round:      0,
            validator:  equivocator.clone(),
            block_hash: Some(block_b.clone()),
            signature:  vec![],
        };
        engine.receive_vote(vote_b).await.unwrap();

        let evidence = engine.drain_equivocations();
        assert_eq!(evidence.len(), 1);
        let ev = &evidence[0];
        assert_eq!(ev.validator_id, equivocator);
        assert_eq!(ev.vote_type_byte, 1, "precommit type byte = 1");
        let hashes = [&ev.block_hash_a, &ev.block_hash_b];
        assert!(hashes.contains(&&block_a));
        assert!(hashes.contains(&&block_b));
    }

    #[tokio::test]
    async fn duplicate_vote_same_block_is_not_equivocation() {
        // A validator re-sending the exact same vote (same block hash) must NOT
        // be flagged as equivocation. Only conflicting block hashes are evidence.
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let block = BlockHash("only_block".into());
        let validator = ValidatorId("val_02".into());

        let vote = Vote {
            vote_type:  VoteType::Precommit,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: Some(block.clone()),
            signature:  vec![],
        };

        engine.receive_vote(vote.clone()).await.unwrap();
        engine.receive_vote(vote).await.unwrap(); // same vote again

        assert!(engine.drain_equivocations().is_empty(),
            "identical vote re-sent must not produce equivocation evidence");
    }

    #[tokio::test]
    async fn nil_vs_real_precommit_is_not_equivocation() {
        // SPEC: A validator equivocates if and only if it casts two conflicting
        // NON-NIL precommits for the same (height, round).  A precommit-nil
        // followed by a precommit-block (or vice-versa) is standard BFT
        // round-change behavior — the validator observed a polka after sending
        // nil, or released a lock.  This is correct protocol and MUST NOT be
        // flagged as equivocation.
        //
        // Regression test: the original code compared block_hash inequality
        // without checking is_some(), treating nil-vs-real as a double-sign.
        // That caused honest validators to be tombstoned at startup (KNOWN_ISSUES §2).
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let validator = ValidatorId("val_00".into());
        let block = BlockHash("real_block".into());

        let nil_vote = Vote {
            vote_type:  VoteType::Precommit,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: None,         // precommit-nil
            signature:  vec![],
        };
        let real_vote = Vote {
            vote_type:  VoteType::Precommit,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: Some(block),  // precommit-block (normal round-change)
            signature:  vec![],
        };

        engine.receive_vote(nil_vote).await.unwrap();
        engine.receive_vote(real_vote).await.unwrap();

        let evidence = engine.drain_equivocations();
        assert!(
            evidence.is_empty(),
            "nil-then-real precommit is normal BFT behavior and must not produce equivocation evidence"
        );
    }

    #[tokio::test]
    async fn nil_vs_real_prevote_is_not_equivocation() {
        // SPEC: A validator equivocates if and only if it casts two conflicting
        // NON-NIL prevotes for the same (height, round).  A prevote-nil followed
        // by a prevote-block is standard polka-nil → new proposal behavior and
        // MUST NOT be flagged as equivocation.
        //
        // Regression test for KNOWN_ISSUES §2 primary cause: the false equivocation
        // detection that tombstoned honest validators during startup gossip warmup.
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let validator = ValidatorId("val_01".into());
        let block = BlockHash("some_block".into());

        let nil_vote = Vote {
            vote_type:  VoteType::Prevote,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: None,
            signature:  vec![],
        };
        let real_vote = Vote {
            vote_type:  VoteType::Prevote,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: Some(block),
            signature:  vec![],
        };

        engine.receive_vote(nil_vote).await.unwrap();
        engine.receive_vote(real_vote).await.unwrap();

        let evidence = engine.drain_equivocations();
        assert!(
            evidence.is_empty(),
            "nil-then-real prevote is normal BFT behavior and must not produce equivocation evidence"
        );
    }

    #[tokio::test]
    async fn two_different_real_precommits_is_equivocation() {
        // SPEC: Two conflicting NON-NIL precommits from the same validator at
        // the same (height, round) IS equivocation — the validator signed two
        // different real blocks, which cannot be explained by legitimate
        // round-change behavior.
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let validator = ValidatorId("val_02".into());
        let block_a = BlockHash("block_A".into());
        let block_b = BlockHash("block_B".into());

        let vote_a = Vote {
            vote_type:  VoteType::Precommit,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: Some(block_a),
            signature:  vec![],
        };
        let vote_b = Vote {
            vote_type:  VoteType::Precommit,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: Some(block_b),
            signature:  vec![],
        };

        engine.receive_vote(vote_a).await.unwrap();
        engine.receive_vote(vote_b).await.unwrap();

        let evidence = engine.drain_equivocations();
        assert_eq!(
            evidence.len(), 1,
            "two conflicting real precommits must produce exactly one equivocation record"
        );
        assert_eq!(evidence[0].validator_id, validator);
    }

    #[tokio::test]
    async fn two_different_real_prevotes_is_equivocation() {
        // SPEC: Two conflicting NON-NIL prevotes from the same validator at
        // the same (height, round) IS equivocation.
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let validator = ValidatorId("val_03".into());
        let block_a = BlockHash("block_X".into());
        let block_b = BlockHash("block_Y".into());

        let vote_a = Vote {
            vote_type:  VoteType::Prevote,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: Some(block_a),
            signature:  vec![],
        };
        let vote_b = Vote {
            vote_type:  VoteType::Prevote,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: Some(block_b),
            signature:  vec![],
        };

        engine.receive_vote(vote_a).await.unwrap();
        engine.receive_vote(vote_b).await.unwrap();

        let evidence = engine.drain_equivocations();
        assert_eq!(
            evidence.len(), 1,
            "two conflicting real prevotes must produce exactly one equivocation record"
        );
        assert_eq!(evidence[0].validator_id, validator);
    }

    #[tokio::test]
    async fn different_round_same_block_is_not_equivocation() {
        // Voting for the same (or different) block in different rounds is
        // legitimate Tendermint protocol — NOT equivocation.
        let (mut engine, vs) = make_engine_and_vs(4);
        engine.init(default_config(), vs.clone()).await.unwrap();

        let validator = ValidatorId("val_02".into());
        let block_a = BlockHash("block_a".into());
        let block_b = BlockHash("block_b".into());

        let vote_round_0 = Vote {
            vote_type:  VoteType::Precommit,
            height:     0,
            round:      0,
            validator:  validator.clone(),
            block_hash: Some(block_a),
            signature:  vec![],
        };
        // Different round — valid protocol re-proposal, not equivocation.
        let vote_round_1 = Vote {
            vote_type:  VoteType::Precommit,
            height:     0,
            round:      1,
            validator:  validator.clone(),
            block_hash: Some(block_b),
            signature:  vec![],
        };

        engine.receive_vote(vote_round_0).await.unwrap();
        engine.receive_vote(vote_round_1).await.unwrap();

        assert!(engine.drain_equivocations().is_empty(),
            "votes in different rounds must not trigger equivocation detection");
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

    // -- FbaEngine tests ------------------------------------------------------

    fn fba_validators(n: u64) -> ValidatorSet {
        ValidatorSet {
            height: 0,
            validators: (1..=n).map(|i| ValidatorInfo {
                id:           ValidatorId(format!("fba_val_{i}")),
                voting_power: 1,
                pop_verified: true,
                    public_key: vec![],
            }).collect(),
        }
    }

    fn fba_config() -> ConsensusConfig {
        ConsensusConfig {
            variant:              ConsensusVariant::XrplInspired,
            chain_id:             "test-chain".to_string(),
            propose_timeout_ms:   4_000,
            prevote_timeout_ms:   1_000,
            precommit_timeout_ms: 1_000,
            block_time_ms:        3_500,
            personhood:           None,
            vca:                  None,
        }
    }

    #[tokio::test]
    async fn fba_initialises_correctly() {
        let mut engine = FbaEngine::new();
        engine.init(fba_config(), fba_validators(4)).await.unwrap();

        assert_eq!(engine.variant(), ConsensusVariant::XrplInspired);
        assert_eq!(engine.current_height(), 0);
        assert_eq!(engine.current_round(), 0);
        assert_eq!(engine.phase, FbaPhase::Open);
        assert_eq!(engine.validator_set().validators.len(), 4);
    }

    #[tokio::test]
    async fn fba_threshold_power_is_80_percent() {
        let mut engine = FbaEngine::new();
        engine.init(fba_config(), fba_validators(5)).await.unwrap();
        // 5 validators, total power 5, 80% threshold = ceil(4.0) = 4
        assert_eq!(engine.threshold_power(), 4);
    }

    #[tokio::test]
    async fn fba_commits_at_threshold() {
        let mut engine = FbaEngine::new();
        engine.init(fba_config(), fba_validators(5)).await.unwrap();
        // threshold = ceil(5 * 0.8) = 4 votes needed

        let parent   = BlockHash("genesis".into());
        let proposal = engine.propose(0, 0, parent, vec![]).await.unwrap();
        engine.receive_proposal(proposal.clone()).await.unwrap();

        // 3 votes -- not yet at threshold (need 4)
        for i in 1..=3 {
            let vote = Vote {
                vote_type:  VoteType::Precommit,
                height:     0, round: 0,
                validator:  ValidatorId(format!("fba_val_{i}")),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
            let result = engine.receive_vote(vote).await.unwrap();
            assert!(result.is_none(), "no commit before 80% threshold");
        }
        assert_eq!(engine.phase, FbaPhase::Open);

        // 4th vote crosses 80% threshold
        let vote4 = Vote {
            vote_type:  VoteType::Precommit,
            height:     0, round: 0,
            validator:  ValidatorId("fba_val_4".into()),
            block_hash: Some(proposal.block_hash.clone()),
            signature:  vec![],
        };
        let cert = engine.receive_vote(vote4).await.unwrap();
        let cert = cert.expect("4th vote must trigger commit");
        assert_eq!(cert.height, 0);
        assert_eq!(cert.block_hash, proposal.block_hash);
        assert_eq!(engine.phase, FbaPhase::Committed);
    }

    #[tokio::test]
    async fn fba_does_not_commit_below_threshold() {
        let mut engine = FbaEngine::new();
        // 5 validators, threshold = 4
        engine.init(fba_config(), fba_validators(5)).await.unwrap();

        let proposal = engine.propose(0, 0, BlockHash("g".into()), vec![]).await.unwrap();
        engine.receive_proposal(proposal.clone()).await.unwrap();

        // Only 3 votes -- below 80%
        for i in 1..=3 {
            let vote = Vote {
                vote_type:  VoteType::Precommit,
                height: 0, round: 0,
                validator:  ValidatorId(format!("fba_val_{i}")),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
            assert!(engine.receive_vote(vote).await.unwrap().is_none());
        }
        assert_eq!(engine.phase, FbaPhase::Open);
    }

    #[tokio::test]
    async fn fba_timeout_advances_round() {
        let mut engine = FbaEngine::new();
        engine.init(fba_config(), fba_validators(4)).await.unwrap();

        let nil_vote = engine.on_timeout(0, 0).await.unwrap();
        assert_eq!(nil_vote.vote_type, VoteType::Nil);
        assert_eq!(engine.current_round(), 1);
        assert_eq!(engine.phase, FbaPhase::Open);
    }

    #[tokio::test]
    async fn fba_on_commit_advances_height() {
        let mut engine = FbaEngine::new();
        engine.init(fba_config(), fba_validators(4)).await.unwrap();

        let cert = CommitCertificate {
            height: 0, round: 0,
            block_hash: BlockHash("fba_h0_r0_00000000".into()),
            precommits: vec![],
        };
        engine.on_commit(cert, None).await.unwrap();

        assert_eq!(engine.current_height(), 1);
        assert_eq!(engine.current_round(), 0);
        assert_eq!(engine.phase, FbaPhase::Open);
    }

    #[tokio::test]
    async fn fba_verify_commit_checks_threshold() {
        let mut engine = FbaEngine::new();
        let validators = fba_validators(5);
        engine.init(fba_config(), validators.clone()).await.unwrap();

        // Valid: 4 of 5 votes (80%)
        let cert_ok = CommitCertificate {
            height: 0, round: 0,
            block_hash: BlockHash("test".into()),
            precommits: (1..=4).map(|i| Vote {
                vote_type:  VoteType::Precommit,
                height: 0, round: 0,
                validator:  ValidatorId(format!("fba_val_{i}")),
                block_hash: Some(BlockHash("test".into())),
                signature:  vec![],
            }).collect(),
        };
        assert!(engine.verify_commit(&cert_ok, &validators).is_ok());

        // Invalid: only 3 of 5 (60% < 80%)
        let cert_bad = CommitCertificate {
            height: 0, round: 0,
            block_hash: BlockHash("test".into()),
            precommits: (1..=3).map(|i| Vote {
                vote_type:  VoteType::Precommit,
                height: 0, round: 0,
                validator:  ValidatorId(format!("fba_val_{i}")),
                block_hash: Some(BlockHash("test".into())),
                signature:  vec![],
            }).collect(),
        };
        assert!(engine.verify_commit(&cert_bad, &validators).is_err());
    }

    #[tokio::test]
    async fn fba_personhood_cap_applied_at_init() {
        let mut engine = FbaEngine::new();
        let mut config = fba_config();
        config.personhood = Some(PersonhoodConfig {
            power_cap:          1,
            reject_expired_pop: false,
            min_verified_pct:   67,
        });

        let validators = ValidatorSet {
            height: 0,
            validators: vec![
                ValidatorInfo { id: ValidatorId("big".into()), voting_power: 10, pop_verified: true, public_key: vec![] },
                ValidatorInfo { id: ValidatorId("v2".into()),  voting_power: 1,  pop_verified: true, public_key: vec![] },
                ValidatorInfo { id: ValidatorId("v3".into()),  voting_power: 1,  pop_verified: true, public_key: vec![] },
            ],
        };
        engine.init(config, validators).await.unwrap();

        let big = engine.validator_set().validators.iter()
            .find(|v| v.id.0 == "big").unwrap();
        assert_eq!(big.voting_power, 1, "FBA: personhood cap should clamp to 1");
    }

    #[tokio::test]
    async fn fba_rejects_unl_too_small() {
        let mut engine = FbaEngine::new();
        // min_unl_size is 3, only provide 2 validators
        let result = engine.init(fba_config(), fba_validators(2)).await;
        assert!(result.is_err(), "FBA must reject UNL below minimum size");
    }

    #[tokio::test]
    async fn fba_all_three_variants_share_trait() {
        // Confirm all three engines satisfy the trait and report correct variant
        let mut t = TendermintEngine::new();
        let mut h = HotStuffEngine::new();
        let mut f = FbaEngine::new();

        let vs = fba_validators(4);
        let cfg_t = ConsensusConfig { variant: ConsensusVariant::TendermintStyle,
            chain_id: "test-chain".to_string(),
            propose_timeout_ms: 1000, prevote_timeout_ms: 1000,
            precommit_timeout_ms: 1000, block_time_ms: 1000, personhood: None, vca: None };
        let cfg_h = ConsensusConfig { variant: ConsensusVariant::HotStuffStyle, ..cfg_t.clone() };
        let cfg_f = ConsensusConfig { variant: ConsensusVariant::XrplInspired,  ..cfg_t.clone() };

        t.init(cfg_t, vs.clone()).await.unwrap();
        h.init(cfg_h, vs.clone()).await.unwrap();
        f.init(cfg_f, vs.clone()).await.unwrap();

        assert_eq!(t.variant(), ConsensusVariant::TendermintStyle);
        assert_eq!(h.variant(), ConsensusVariant::HotStuffStyle);
        assert_eq!(f.variant(), ConsensusVariant::XrplInspired);
    }

    // -- HotStuffEngine tests -------------------------------------------------

    fn hotstuff_validators(n: u64) -> ValidatorSet {
        ValidatorSet {
            height: 0,
            validators: (1..=n).map(|i| ValidatorInfo {
                id:           ValidatorId(format!("hs_val_{i}")),
                voting_power: 1,
                pop_verified: true,
                    public_key: vec![],
            }).collect(),
        }
    }

    fn hotstuff_config() -> ConsensusConfig {
        ConsensusConfig {
            variant:              ConsensusVariant::HotStuffStyle,
            chain_id:             "test-chain".to_string(),
            propose_timeout_ms:   3_000,
            prevote_timeout_ms:   1_000,
            precommit_timeout_ms: 1_000,
            block_time_ms:        1_000,
            personhood:           None,
            vca:                  None,
        }
    }

    #[tokio::test]
    async fn hotstuff_initialises_correctly() {
        let mut engine = HotStuffEngine::new();
        let validators = hotstuff_validators(4);
        engine.init(hotstuff_config(), validators).await.unwrap();

        assert_eq!(engine.variant(), ConsensusVariant::HotStuffStyle);
        assert_eq!(engine.current_height(), 0);
        assert_eq!(engine.current_round(), 0);
        assert_eq!(engine.phase, HotStuffPhase::WaitingForPrepare);
        assert_eq!(engine.validator_set().validators.len(), 4);
    }

    #[tokio::test]
    async fn hotstuff_leader_rotates_by_height() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        let leader0 = engine.current_leader().unwrap().clone();
        engine.height = 1;
        let leader1 = engine.current_leader().unwrap().clone();
        engine.height = 4;
        let leader4 = engine.current_leader().unwrap().clone();

        // Leader at height 4 should wrap back to same as height 0
        assert_eq!(leader0, leader4);
        assert_ne!(leader0, leader1);
    }

    #[tokio::test]
    async fn hotstuff_propose_returns_valid_block() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        let parent = BlockHash("genesis".into());
        let proposal = engine.propose(0, 0, parent.clone(), vec![1, 2, 3]).await.unwrap();

        assert_eq!(proposal.height, 0);
        assert_eq!(proposal.round, 0);
        assert!(proposal.block_hash.0.starts_with("hs_h0_r0_"));
    }

    #[tokio::test]
    async fn hotstuff_three_phases_to_commit() {
        // With 4 validators (quorum = 3), simulate all voting through all 3 phases
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        let parent   = BlockHash("genesis".into());
        let proposal = engine.propose(0, 0, parent, vec![]).await.unwrap();
        engine.receive_proposal(proposal.clone()).await.unwrap();

        assert_eq!(engine.phase, HotStuffPhase::CollectingPrepareVotes);

        // PREPARE phase: 3 votes needed (quorum = 3 of 4)
        for i in 1..=3 {
            let vote = Vote {
                vote_type:  VoteType::Prevote,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("hs_val_{i}")),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
            let result = engine.receive_vote(vote).await.unwrap();
            assert!(result.is_none(), "no commit until COMMIT phase");
        }
        assert_eq!(engine.phase, HotStuffPhase::CollectingPreCommitVotes);

        // PRE-COMMIT phase: 3 votes needed
        for i in 1..=3 {
            let vote = Vote {
                vote_type:  VoteType::Precommit,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("hs_val_{i}")),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
            let result = engine.receive_vote(vote).await.unwrap();
            assert!(result.is_none());
        }
        assert_eq!(engine.phase, HotStuffPhase::CollectingCommitVotes);

        // COMMIT phase: 3rd vote triggers commit
        let mut cert = None;
        for i in 1..=3 {
            let vote = Vote {
                vote_type:  VoteType::Precommit,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("hs_val_{i}")),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
            cert = engine.receive_vote(vote).await.unwrap();
        }

        let cert = cert.expect("commit certificate must be produced");
        assert_eq!(cert.height, 0);
        assert_eq!(cert.block_hash, proposal.block_hash);
        assert_eq!(engine.phase, HotStuffPhase::Committed);
    }

    #[tokio::test]
    async fn hotstuff_timeout_advances_round() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        let nil_vote = engine.on_timeout(0, 0).await.unwrap();

        assert_eq!(nil_vote.vote_type, VoteType::Nil);
        assert_eq!(engine.current_round(), 1);
        assert_eq!(engine.phase, HotStuffPhase::WaitingForPrepare);
    }

    #[tokio::test]
    async fn hotstuff_on_commit_advances_height() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        let cert = CommitCertificate {
            height:     0,
            round:      0,
            block_hash: BlockHash("hs_h0_r0_00000000".into()),
            precommits: vec![],
        };
        engine.on_commit(cert, None).await.unwrap();

        assert_eq!(engine.current_height(), 1);
        assert_eq!(engine.current_round(), 0);
        assert_eq!(engine.phase, HotStuffPhase::WaitingForPrepare);
    }

    #[tokio::test]
    async fn hotstuff_verify_commit_checks_quorum() {
        let mut engine = HotStuffEngine::new();
        let validators = hotstuff_validators(4);
        engine.init(hotstuff_config(), validators.clone()).await.unwrap();

        // Valid: 3 precommits (quorum = 3)
        let cert_valid = CommitCertificate {
            height:     0,
            round:      0,
            block_hash: BlockHash("test".into()),
            precommits: (1..=3).map(|i| Vote {
                vote_type:  VoteType::Precommit,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("hs_val_{i}")),
                block_hash: Some(BlockHash("test".into())),
                signature:  vec![],
            }).collect(),
        };
        assert!(engine.verify_commit(&cert_valid, &validators).is_ok());

        // Invalid: only 2 precommits
        let cert_invalid = CommitCertificate {
            height:     0,
            round:      0,
            block_hash: BlockHash("test".into()),
            precommits: (1..=2).map(|i| Vote {
                vote_type:  VoteType::Precommit,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("hs_val_{i}")),
                block_hash: Some(BlockHash("test".into())),
                signature:  vec![],
            }).collect(),
        };
        assert!(engine.verify_commit(&cert_invalid, &validators).is_err());
    }

    #[tokio::test]
    async fn hotstuff_personhood_cap_applied_at_init() {
        let mut engine = HotStuffEngine::new();
        let mut config = hotstuff_config();
        config.personhood = Some(PersonhoodConfig {
            power_cap:           1,
            reject_expired_pop:  false,
            min_verified_pct:    67,
        });

        // Give one validator too much power
        let validators = ValidatorSet {
            height: 0,
            validators: vec![
                ValidatorInfo { id: ValidatorId("hs_big".into()), voting_power: 10, pop_verified: true, public_key: vec![] },
                ValidatorInfo { id: ValidatorId("hs_v2".into()),  voting_power: 1,  pop_verified: true, public_key: vec![] },
                ValidatorInfo { id: ValidatorId("hs_v3".into()),  voting_power: 1,  pop_verified: true, public_key: vec![] },
                ValidatorInfo { id: ValidatorId("hs_v4".into()),  voting_power: 1,  pop_verified: true, public_key: vec![] },
            ],
        };
        engine.init(config, validators).await.unwrap();

        // The big validator should be capped to power_cap = 1
        let big = engine.validator_set().validators.iter()
            .find(|v| v.id.0 == "hs_big").unwrap();
        assert_eq!(big.voting_power, 1,
            "HotStuff: personhood cap should be applied at init");
    }

    // -- HotStuffEngine: safety-rule, locking, equivocation, verify_commit ----

    /// Drive an engine from proposal → 3 PREPARE votes → 3 PRE-COMMIT votes,
    /// returning (engine, proposal) so callers can continue to COMMIT.
    async fn hotstuff_drive_to_precommit(
        engine: &mut HotStuffEngine,
        height: u64,
        round:  u32,
        parent: &str,
    ) -> BlockProposal {
        let proposal = engine
            .propose(height, round, BlockHash(parent.into()), vec![])
            .await.unwrap();
        engine.receive_proposal(proposal.clone()).await.unwrap();

        // PREPARE votes
        for i in 1..=3 {
            let v = Vote {
                vote_type:  VoteType::Prevote,
                height,
                round,
                validator:  ValidatorId(format!("hs_val_{i}")),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
            engine.receive_vote(v).await.unwrap();
        }
        assert_eq!(engine.phase, HotStuffPhase::CollectingPreCommitVotes);

        // PRE-COMMIT votes
        for i in 1..=3 {
            let v = Vote {
                vote_type:  VoteType::Precommit,
                height,
                round,
                validator:  ValidatorId(format!("hs_val_{i}")),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
            engine.receive_vote(v).await.unwrap();
        }
        assert_eq!(engine.phase, HotStuffPhase::CollectingCommitVotes);
        proposal
    }

    #[tokio::test]
    async fn hotstuff_locked_qc_set_after_precommit_quorum() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        hotstuff_drive_to_precommit(&mut engine, 0, 0, "genesis").await;

        // After PRE-COMMIT quorum, locked_qc must be set.
        assert!(engine.locked_qc.is_some(), "locked_qc should be set after PRE-COMMIT QC");
        let lqc = engine.locked_qc.as_ref().unwrap();
        assert_eq!(lqc.height, 0);
        assert_eq!(lqc.round, 0);
    }

    #[tokio::test]
    async fn hotstuff_locked_qc_cleared_on_commit() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        let proposal = hotstuff_drive_to_precommit(&mut engine, 0, 0, "genesis").await;

        // Reach COMMIT quorum.
        let mut cert = None;
        for i in 1..=3 {
            let v = Vote {
                vote_type:  VoteType::Precommit,
                height:     0,
                round:      0,
                validator:  ValidatorId(format!("hs_val_{i}")),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
            cert = engine.receive_vote(v).await.unwrap();
        }
        let cert = cert.unwrap();

        // on_commit should clear locked_qc so next height starts unlocked.
        engine.on_commit(cert, None).await.unwrap();
        assert!(engine.locked_qc.is_none(), "locked_qc must be cleared after on_commit");
        assert_eq!(engine.height, 1);
        assert_eq!(engine.round, 0);
        assert_eq!(engine.phase, HotStuffPhase::WaitingForPrepare);
    }

    #[tokio::test]
    async fn hotstuff_safety_rule_rejects_non_extending_proposal() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        // Set up a locked_qc manually (simulating having locked on block A).
        engine.locked_qc = Some(QuorumCertificate {
            view:       QuorumCertificate::view(0, 0),
            height:     0,
            round:      0,
            block_hash: BlockHash("block_A".into()),
            votes:      vec![],
        });
        // propose_qc is None (no higher-view QC seen).
        engine.prepare_qc = None;

        // A proposal that does NOT extend block_A and has no higher-view prepare_qc
        // should be rejected.
        let bad_proposal = BlockProposal {
            height:      0,
            round:       1,
            proposer:    ValidatorId("hs_val_1".into()),
            block_hash:  BlockHash("block_B".into()),
            parent_hash: BlockHash("block_X".into()), // NOT block_A
            timestamp_ms: 0,
            tx_data:     vec![],
            signature:   vec![],
        };

        let result = engine.receive_proposal(bad_proposal).await;
        assert!(result.is_err(), "safety rule: must reject proposal that doesn't extend locked_qc");
        match result.unwrap_err() {
            ConsensusError::MalformedProposal(msg) => {
                assert!(msg.contains("LockViolation"), "error message should mention LockViolation");
            }
            other => panic!("expected MalformedProposal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hotstuff_safety_rule_allows_proposal_with_higher_view_prepare_qc() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        // Lock on block_A at view 0.
        engine.locked_qc = Some(QuorumCertificate {
            view:       QuorumCertificate::view(0, 0),
            height:     0,
            round:      0,
            block_hash: BlockHash("block_A".into()),
            votes:      vec![],
        });
        // But we've seen a higher-view prepare_qc at view 1 (endorsing block_B).
        engine.prepare_qc = Some(QuorumCertificate {
            view:       QuorumCertificate::view(0, 1),
            height:     0,
            round:      1,
            block_hash: BlockHash("block_B".into()),
            votes:      vec![],
        });

        // A proposal extending block_B (the higher-view QC's block) should be safe.
        let safe_proposal = BlockProposal {
            height:      0,
            round:       2,
            proposer:    ValidatorId("hs_val_2".into()),
            block_hash:  BlockHash("block_C".into()),
            parent_hash: BlockHash("block_B".into()), // extends block_B
            timestamp_ms: 0,
            tx_data:     vec![],
            signature:   vec![],
        };

        let result = engine.receive_proposal(safe_proposal).await;
        assert!(result.is_ok(), "higher-view prepare_qc unlocks: should accept proposal");
    }

    #[tokio::test]
    async fn hotstuff_equivocation_detected_in_prepare_phase() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        let proposal = engine.propose(0, 0, BlockHash("genesis".into()), vec![]).await.unwrap();
        engine.receive_proposal(proposal.clone()).await.unwrap();
        assert_eq!(engine.phase, HotStuffPhase::CollectingPrepareVotes);

        // First vote for block A.
        let vote_a = Vote {
            vote_type:  VoteType::Prevote,
            height:     0,
            round:      0,
            validator:  ValidatorId("hs_val_1".into()),
            block_hash: Some(proposal.block_hash.clone()),
            signature:  vec![1],
        };
        engine.receive_vote(vote_a).await.unwrap();
        assert!(engine.pending_equivocations.is_empty());

        // Same validator, conflicting block hash.
        let vote_b = Vote {
            vote_type:  VoteType::Prevote,
            height:     0,
            round:      0,
            validator:  ValidatorId("hs_val_1".into()),
            block_hash: Some(BlockHash("other_block".into())),
            signature:  vec![2],
        };
        engine.receive_vote(vote_b).await.unwrap();

        let evs = engine.drain_equivocations();
        assert_eq!(evs.len(), 1, "double-vote should produce one equivocation event");
        assert_eq!(evs[0].validator_id, ValidatorId("hs_val_1".into()));
        assert_eq!(evs[0].height, 0);
        assert_eq!(evs[0].round, 0);

        // drain_equivocations clears the buffer.
        assert!(engine.drain_equivocations().is_empty());
    }

    #[tokio::test]
    async fn hotstuff_verify_commit_rejects_duplicate_validators() {
        let mut engine = HotStuffEngine::new();
        let validators = hotstuff_validators(4);
        engine.init(hotstuff_config(), validators.clone()).await.unwrap();

        // Duplicate validator in the certificate.
        let dup_cert = CommitCertificate {
            height:     0,
            round:      0,
            block_hash: BlockHash("block_0".into()),
            precommits: vec![
                Vote { vote_type: VoteType::Precommit, height: 0, round: 0,
                       validator: ValidatorId("hs_val_1".into()),
                       block_hash: Some(BlockHash("block_0".into())), signature: vec![] },
                Vote { vote_type: VoteType::Precommit, height: 0, round: 0,
                       validator: ValidatorId("hs_val_1".into()), // duplicate!
                       block_hash: Some(BlockHash("block_0".into())), signature: vec![] },
                Vote { vote_type: VoteType::Precommit, height: 0, round: 0,
                       validator: ValidatorId("hs_val_2".into()),
                       block_hash: Some(BlockHash("block_0".into())), signature: vec![] },
            ],
        };
        let result = engine.verify_commit(&dup_cert, &validators);
        assert!(result.is_err(), "verify_commit must reject duplicate validators");
    }

    #[tokio::test]
    async fn hotstuff_verify_commit_rejects_wrong_block_hash_in_vote() {
        let mut engine = HotStuffEngine::new();
        let validators = hotstuff_validators(4);
        engine.init(hotstuff_config(), validators.clone()).await.unwrap();

        // One vote has a mismatched block_hash.
        let bad_cert = CommitCertificate {
            height:     0,
            round:      0,
            block_hash: BlockHash("block_correct".into()),
            precommits: vec![
                Vote { vote_type: VoteType::Precommit, height: 0, round: 0,
                       validator: ValidatorId("hs_val_1".into()),
                       block_hash: Some(BlockHash("block_WRONG".into())), // mismatch
                       signature: vec![] },
                Vote { vote_type: VoteType::Precommit, height: 0, round: 0,
                       validator: ValidatorId("hs_val_2".into()),
                       block_hash: Some(BlockHash("block_correct".into())),
                       signature: vec![] },
            ],
        };
        let result = engine.verify_commit(&bad_cert, &validators);
        assert!(result.is_err(), "verify_commit must reject votes for wrong block hash");
    }

    #[tokio::test]
    async fn hotstuff_new_view_quorum_detection() {
        let mut engine = HotStuffEngine::new();
        engine.init(hotstuff_config(), hotstuff_validators(4)).await.unwrap();

        // Advance round via timeout so engine is in round 1.
        engine.on_timeout(0, 0).await.unwrap();
        assert_eq!(engine.round, 1);

        // Collect NewView messages from 3 of 4 validators (each with power=1;
        // quorum = 3). No prepare_qc yet (genesis).
        for i in 1..=2 {
            let nv = HotStuffNewView {
                validator:  ValidatorId(format!("hs_val_{i}")),
                height:     0,
                new_round:  1,
                prepare_qc: None,
            };
            let reached = engine.record_new_view(nv);
            assert!(!reached, "2 of 4 is not quorum yet");
        }

        let nv3 = HotStuffNewView {
            validator:  ValidatorId("hs_val_3".into()),
            height:     0,
            new_round:  1,
            prepare_qc: None,
        };
        let reached = engine.record_new_view(nv3);
        assert!(reached, "3 of 4 NewView messages should satisfy quorum");

        // highest_new_view_qc is None when all NewViews carry None.
        assert!(engine.highest_new_view_qc().is_none());
    }

    #[tokio::test]
    async fn hotstuff_update_validator_set_applies_personhood_cap() {
        let mut engine = HotStuffEngine::new();
        let mut config = hotstuff_config();
        config.personhood = Some(PersonhoodConfig {
            power_cap:          1,
            reject_expired_pop: false,
            min_verified_pct:   0,
        });
        engine.init(config, hotstuff_validators(4)).await.unwrap();

        // Push a new validator set where one validator has huge power.
        let mut new_vs = hotstuff_validators(4);
        new_vs.validators[0].voting_power = 100;
        new_vs.validators[0].pop_verified = true;

        engine.update_validator_set(new_vs).unwrap();

        // After update, the capped validator should be clamped to 1.
        let capped = engine.validator_set().validators.iter()
            .find(|v| v.id == ValidatorId("hs_val_1".into())).unwrap();
        assert_eq!(capped.voting_power, 1,
            "update_validator_set must apply personhood cap");
    }

}
}

// Re-export the BFT engine types at crate root so callers can import them
// without knowing which sub-module they live in.
pub use tendermint::{TendermintEngine, EquivocationDetected};
pub use tendermint::{HotStuffEngine, HotStuffPhase, QuorumCertificate, HotStuffNewView};
pub use tendermint::new_hotstuff;

/// Compile-time assertion that `chain_forge_consensus::ValidatorId` and
/// `chain_forge_core::ValidatorId` are exactly the same type.
///
/// If this fails to compile, it means the unification was broken — someone
/// introduced a local `ValidatorId` definition in consensus rather than
/// re-exporting from core. That split would cause silent type-mismatch errors
/// at crate boundaries (e.g. in chain-forge-personhood) that are hard to debug.
#[cfg(test)]
mod validator_id_identity {
    fn assert_same_type<T>(_: T) {}

    #[test]
    fn consensus_and_core_validator_id_are_the_same_type() {
        // If ValidatorId were separately defined in consensus and core,
        // this would fail to compile ("mismatched types").
        let core_id = chain_forge_core::ValidatorId("test".into());
        let consensus_id: crate::ValidatorId = core_id; // must compile
        assert_same_type(consensus_id);
    }
}

// ── VCA-PQ-BFT integration tests ─────────────────────────────────────────────
//
// These tests prove that VCA-derived weights flow through the full consensus
// engine path: init() → voting_power rewritten → verify_commit() uses
// the adaptive quorum threshold rather than the static 2n/3+1 value.

#[cfg(test)]
mod vca_integration {
    use super::*;
    use super::tendermint::TendermintEngine;
    use chain_forge_vca_pq::{WeightConfig, AdaptiveQuorumConfig};

    /// Build a 4-validator set where contribution scores are unequal.
    /// alice=4, bob=2, carol=2, dave=1  (pre-VCA voting_power values)
    fn unequal_vs() -> ValidatorSet {
        let names = [("alice", 4u64), ("bob", 2), ("carol", 2), ("dave", 1)];
        ValidatorSet {
            height: 0,
            validators: names.iter().map(|(name, power)| ValidatorInfo {
                id:           ValidatorId(name.to_string()),
                voting_power: *power,
                pop_verified: true,
                public_key:   vec![],
            }).collect(),
        }
    }

    fn vca_config() -> ConsensusConfig {
        ConsensusConfig {
            variant:              ConsensusVariant::TendermintStyle,
            chain_id:             "qcb-devnet".to_string(),
            propose_timeout_ms:   1_000,
            prevote_timeout_ms:   1_000,
            precommit_timeout_ms: 1_000,
            block_time_ms:        1_000,
            personhood:           None,
            vca: Some(VcaIntegrationConfig {
                // tight weight multiplier: relative cap = 1.0 × median (strict BFT mode)
                weight_config: WeightConfig {
                    max_weight_multiplier: 1.0,
                    ..WeightConfig::default()
                },
                quorum_config: AdaptiveQuorumConfig::default(),
            }),
        }
    }

    /// VCA init: voting_power is rewritten to VCA-derived ConsensusWeight.
    ///
    /// VCA weight formula: W = floor(C^0.5 × P × 1000)
    ///   alice: C=4 → W_raw = floor(2000) = 2000
    ///   bob:   C=2 → W_raw = floor(1414) = 1414
    ///   carol: C=2 → W_raw = 1414
    ///   dave:  C=1 → W_raw = 1000
    ///
    /// Sorted: [1000, 1414, 1414, 2000] → median = (1414+1414)/2 = 1414
    /// With max_weight_multiplier=1.0: cap = floor(1414 * 1.0) = 1414
    ///   alice capped: 2000 → 1414
    ///   bob, carol, dave: already ≤ 1414, unchanged
    #[tokio::test]
    async fn vca_init_rewrites_voting_power() {
        let mut engine = TendermintEngine::new();
        let original_vs = unequal_vs();

        // Pre-VCA: alice has 4× dave's voting_power (legacy field).
        assert_eq!(original_vs.power_of(&ValidatorId("alice".into())), 4);
        assert_eq!(original_vs.power_of(&ValidatorId("dave".into())),  1);

        engine.init(vca_config(), original_vs).await
            .expect("VCA init should succeed with all pop_verified validators");

        let vs = engine.validator_set();

        let alice_power = vs.power_of(&ValidatorId("alice".into()));
        let dave_power  = vs.power_of(&ValidatorId("dave".into()));
        let bob_power   = vs.power_of(&ValidatorId("bob".into()));

        // After VCA with multiplier=1.0: alice is capped at the median (1414).
        // Dave and bob are below the median → unchanged.
        assert_eq!(alice_power, 1414,
            "alice (C=4) should be capped to median 1414, got {alice_power}");
        assert_eq!(bob_power, 1414,
            "bob (C=2) VCA weight is 1414 = floor(sqrt(2)*1000), got {bob_power}");
        assert_eq!(dave_power, 1000,
            "dave (C=1) VCA weight is 1000 = floor(sqrt(1)*1000), got {dave_power}");

        // The key result: alice's weight concentration dropped from 4/9 (44%)
        // to 1414/5842 (24%) — below the 1/3 BFT threshold.
        let total = vs.total_power();
        let alice_fraction = alice_power as f64 / total as f64;
        assert!(alice_fraction < 1.0 / 3.0,
            "with multiplier=1.0 alice should be below BFT 1/3 threshold: \
             {alice_power}/{total} = {:.1}%", alice_fraction * 100.0);

        // Verify engine set vca_quorum.
        assert!(engine.vca_quorum.is_some(),
            "vca_quorum should be set after VCA init");

        let vca_q = engine.vca_quorum.unwrap();
        let static_q = vs.quorum_power();
        // With all validators fully pop_verified (ρ=1.0), adaptive quorum
        // equals the classical 2n/3+1 threshold (no upward adjustment at full coverage).
        assert_eq!(vca_q, static_q,
            "at ρ=1.0 (full coverage) adaptive quorum should equal static 2n/3+1: \
             vca={vca_q}, static={static_q}");
    }

    /// VCA uses adaptive quorum in verify_commit instead of static quorum_power().
    #[tokio::test]
    async fn vca_verify_commit_uses_adaptive_quorum() {
        let mut engine = TendermintEngine::new();

        // Mixed set: 3 pop_verified + 1 unverified (ρ = 0.75)
        let vs = ValidatorSet {
            height: 0,
            validators: vec![
                ValidatorInfo { id: ValidatorId("alice".into()), voting_power: 10,
                                pop_verified: true,  public_key: vec![] },
                ValidatorInfo { id: ValidatorId("bob".into()),   voting_power: 10,
                                pop_verified: true,  public_key: vec![] },
                ValidatorInfo { id: ValidatorId("carol".into()), voting_power: 10,
                                pop_verified: true,  public_key: vec![] },
                ValidatorInfo { id: ValidatorId("dave".into()),  voting_power: 10,
                                pop_verified: false, public_key: vec![] },
            ],
        };

        let cfg = ConsensusConfig {
            vca: Some(VcaIntegrationConfig {
                weight_config: WeightConfig::default(),
                quorum_config: AdaptiveQuorumConfig::default(),
            }),
            ..vca_config()
        };

        engine.init(cfg, vs).await.expect("init should succeed");

        // vca_quorum is now set and represents the adaptive threshold.
        assert!(engine.vca_quorum.is_some());
        let vca_q = engine.vca_quorum.unwrap();

        // At ρ=0.75 (3 of 4 verified), quorum may be above the classical floor.
        // The key invariant: quorum_floor ≤ vca_q ≤ total_weight.
        let vs = engine.validator_set();
        let total = vs.total_power();
        assert!(vca_q >= AdaptiveQuorumConfig::default().quorum_floor,
            "adaptive quorum must be at least quorum_floor");
        assert!(vca_q <= total,
            "adaptive quorum cannot exceed total weight: vca_q={vca_q}, total={total}");
    }

    /// Without VCA config, the engine falls back to static quorum_power().
    #[tokio::test]
    async fn no_vca_config_uses_static_quorum() {
        let mut engine = TendermintEngine::new();
        let cfg = ConsensusConfig {
            vca: None,
            ..vca_config()
        };

        engine.init(cfg, unequal_vs()).await.expect("init without VCA should succeed");

        // vca_quorum stays None — verify_commit will use quorum_power().
        assert!(engine.vca_quorum.is_none(),
            "vca_quorum should be None when VCA is not configured");
    }

    /// build_vca_registry_from_validator_set and apply_vca_weights_to_validator_set
    /// are public helpers — verify them directly.
    #[test]
    fn build_registry_and_apply_weights_round_trip() {
        let vs = unequal_vs();
        let weight_cfg = WeightConfig { max_weight_multiplier: 3.0, ..WeightConfig::default() };
        let registry = build_vca_registry_from_validator_set(1, &vs, weight_cfg);

        // Registry should contain all 4 validators.
        assert_eq!(registry.records.len(), 4);

        // After close_epoch(), all weights should be ≥ 0.
        for (id, rec) in &registry.records {
            assert!(rec.weight.0 > 0 || rec.personhood.0 == 0.0,
                "pop_verified validator {id} should have nonzero weight");
        }

        // Apply weights back to a fresh validator set copy.
        let mut vs2 = unequal_vs();
        apply_vca_weights_to_validator_set(&mut vs2, &registry);

        // All validators' voting_power should now match registry records.
        for v in &vs2.validators {
            let record = registry.records.get(&v.id).unwrap();
            assert_eq!(v.voting_power, record.weight.0,
                "apply_vca_weights should set voting_power = VCA weight for {}",
                v.id.0);
        }
    }
}
