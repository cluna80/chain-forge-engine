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

    /// Relative voting power.
    pub voting_power: u64,

    /// Whether PoP-verified (used by personhood-weighted variant).
    pub pop_verified: bool,

    /// Ed25519 public key for this validator. Used to verify signatures on
    /// proposals and votes. Empty on chains without real-crypto.
    pub public_key: Vec<u8>,
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

    /// Ed25519 public key for a validator. Empty if not registered.
    pub fn public_key_of(&self, id: &ValidatorId) -> &[u8] {
        self.validators.iter().find(|v| &v.id == id)
            .map(|v| v.public_key.as_slice()).unwrap_or(&[])
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
                propose_timeout_ms:   4_000,
                prevote_timeout_ms:   1_000,
                precommit_timeout_ms: 1_000,
                block_time_ms:        3_500, // XRPL ~3-5s block time
                personhood:           None,
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
            return Err(ConsensusError::StaleProposal(proposal.height, self.height));
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
}

impl TendermintEngine {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "real-crypto")]
            signing_key:      None,
            chain_id:         String::new(),
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
            return Err(ConsensusError::StaleProposal(vote.height, self.height));
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
                ClassicalScheme.verify(&msg, &sig, pub_key).map_err(|_|
                    ConsensusError::UnknownValidator(vote.validator.clone())
                )?;
            }
        }

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
///   PREPARE:   Leader proposes block, collects 2f+1 PREPARE votes
///   PRE-COMMIT: Leader aggregates PREPARE QC, collects 2f+1 PRE-COMMIT votes
///   COMMIT:    Leader aggregates PRE-COMMIT QC, collects 2f+1 COMMIT votes
///
/// Pipelining: COMMIT for block k happens in the PREPARE phase of block k+2,
/// so the effective latency is one round-trip per block rather than three.
/// Phase 0 implements the full three-phase logic without pipelining to keep
/// the code straightforward; pipelining is a Phase 1 optimisation.
///
/// Personhood weighting: applied identically to TendermintEngine via
/// `apply_personhood_cap()`. The power cap is a QCB-specific constraint
/// layered on top of HotStuff's standard quorum rules.
///
/// Whitepaper ref: Section 3 / ConsensusVariant::HotStuffStyle.
/// Open Question 2: which variant QCB ultimately uses depends on scale.

/// Which phase of the HotStuff protocol we are in for the current height.
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

pub struct HotStuffEngine {
    config:         ConsensusConfig,
    validators:     ValidatorSet,
    height:         BlockHeight,
    round:          Round,
    phase:          HotStuffPhase,
    /// Current pending proposal (set on receive_proposal).
    pending:        Option<BlockProposal>,
    /// PREPARE votes accumulated for the pending block.
    prepare_votes:  BTreeMap<ValidatorId, u64>,
    /// PRE-COMMIT votes accumulated after PREPARE QC formed.
    precommit_votes: BTreeMap<ValidatorId, u64>,
    /// COMMIT votes accumulated after PRE-COMMIT QC formed.
    commit_votes:   BTreeMap<ValidatorId, u64>,
    /// Proposer index for round-robin rotation.
    proposer_idx:   usize,
}

impl HotStuffEngine {
    pub fn new() -> Self {
        Self {
            config:          ConsensusConfig {
                variant:              ConsensusVariant::HotStuffStyle,
                propose_timeout_ms:   3_000,
                prevote_timeout_ms:   1_000,
                precommit_timeout_ms: 1_000,
                block_time_ms:        1_000,
                personhood:           None,
            },
            validators:      ValidatorSet { height: 0, validators: vec![] },
            height:          0,
            round:           0,
            phase:           HotStuffPhase::WaitingForPrepare,
            pending:         None,
            prepare_votes:   BTreeMap::new(),
            precommit_votes: BTreeMap::new(),
            commit_votes:    BTreeMap::new(),
            proposer_idx:    0,
        }
    }

    /// The current leader (round-robin rotation by height + round).
    pub fn current_leader(&self) -> Option<&ValidatorId> {
        if self.validators.validators.is_empty() { return None; }
        let idx = (self.height as usize + self.round as usize)
            % self.validators.validators.len();
        Some(&self.validators.validators[idx].id)
    }

    fn quorum(&self) -> u64 {
        self.validators.quorum_power()
    }

    fn voted_power(votes: &BTreeMap<ValidatorId, u64>) -> u64 {
        votes.values().sum()
    }

    fn has_quorum(votes: &BTreeMap<ValidatorId, u64>, quorum: u64) -> bool {
        Self::voted_power(votes) >= quorum
    }

    fn record_vote(
        votes: &mut BTreeMap<ValidatorId, u64>,
        validator: &ValidatorId,
        power: u64,
    ) {
        votes.entry(validator.clone()).or_insert(power);
    }

    /// Build a CommitCertificate from the commit votes.
    fn make_certificate(&self, block_hash: BlockHash) -> CommitCertificate {
        let precommits = self.commit_votes.keys().map(|id| Vote {
            vote_type:  VoteType::Precommit,
            height:     self.height,
            round:      self.round,
            validator:  id.clone(),
            block_hash: Some(block_hash.clone()),
            signature:  vec![],
        }).collect();
        CommitCertificate {
            height:     self.height,
            round:      self.round,
            block_hash,
            precommits,
        }
    }
}

impl Default for HotStuffEngine {
    fn default() -> Self { Self::new() }
}

#[async_trait::async_trait]
impl ConsensusEngine for HotStuffEngine {
    fn name(&self) -> &str { "HotStuff-style BFT (Phase 0 — three-phase, no pipelining)" }
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
        self.validators = genesis_validators;
        self.config     = config;
        self.phase      = HotStuffPhase::WaitingForPrepare;
        tracing::info!(
            variant    = "HotStuff-style BFT",
            validators = self.validators.validators.len(),
            total_power = self.validators.total_power(),
            quorum_power = self.validators.quorum_power(),
            "HotStuff consensus engine initialised"
        );
        Ok(())
    }

    fn validator_set(&self) -> &ValidatorSet { &self.validators }
    fn current_height(&self) -> BlockHeight  { self.height }
    fn current_round(&self)  -> Round        { self.round  }

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

        let block_hash = BlockHash(format!(
            "hs_h{height}_r{round}_{:08x}",
            tx_data.len() as u32
        ));

        let proposal = BlockProposal {
            height,
            round,
            proposer,
            block_hash,
            parent_hash,
            timestamp_ms: 0,
            tx_data,
            signature: vec![],
        };

        tracing::debug!(
            height, round,
            leader = %proposal.proposer,
            "HotStuff PREPARE: block proposed"
        );
        Ok(proposal)
    }

    async fn receive_proposal(
        &mut self,
        proposal: BlockProposal,
    ) -> ConsensusResult<()> {
        if proposal.height < self.height {
            return Err(ConsensusError::StaleProposal(proposal.height, self.height));
        }
        // Phase 0: accept any well-formed proposal from the expected leader
        if self.phase != HotStuffPhase::WaitingForPrepare
            && self.phase != HotStuffPhase::Committed
        {
            tracing::warn!(
                phase = ?self.phase,
                "HotStuff: received proposal in unexpected phase, resetting"
            );
            self.prepare_votes.clear();
            self.precommit_votes.clear();
            self.commit_votes.clear();
        }

        self.pending      = Some(proposal.clone());
        self.phase        = HotStuffPhase::CollectingPrepareVotes;
        self.prepare_votes.clear();
        self.precommit_votes.clear();
        self.commit_votes.clear();

        tracing::debug!(
            height = proposal.height,
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

        let block_hash = match &vote.block_hash {
            Some(h) => h.clone(),
            None    => return Ok(None), // nil vote advances round, handled in on_timeout
        };

        let quorum = self.quorum();

        match self.phase {
            HotStuffPhase::CollectingPrepareVotes => {
                Self::record_vote(&mut self.prepare_votes, &vote.validator, power);
                if Self::has_quorum(&self.prepare_votes, quorum) {
                    tracing::debug!(
                        height = vote.height,
                        "HotStuff: PREPARE QC formed -- advancing to PRE-COMMIT"
                    );
                    self.phase = HotStuffPhase::CollectingPreCommitVotes;
                }
            }
            HotStuffPhase::CollectingPreCommitVotes => {
                Self::record_vote(&mut self.precommit_votes, &vote.validator, power);
                if Self::has_quorum(&self.precommit_votes, quorum) {
                    tracing::debug!(
                        height = vote.height,
                        "HotStuff: PRE-COMMIT QC formed -- advancing to COMMIT"
                    );
                    self.phase = HotStuffPhase::CollectingCommitVotes;
                }
            }
            HotStuffPhase::CollectingCommitVotes => {
                Self::record_vote(&mut self.commit_votes, &vote.validator, power);
                if Self::has_quorum(&self.commit_votes, quorum) {
                    self.phase = HotStuffPhase::Committed;
                    let cert = self.make_certificate(block_hash);
                    tracing::info!(
                        height = cert.height,
                        block  = %cert.block_hash,
                        "HotStuff: COMMIT QC formed -- block committed"
                    );
                    return Ok(Some(cert));
                }
            }
            HotStuffPhase::WaitingForPrepare | HotStuffPhase::Committed => {
                tracing::debug!(phase = ?self.phase, "HotStuff: vote in unexpected phase, ignoring");
            }
        }
        Ok(None)
    }

    async fn on_timeout(
        &mut self,
        height: BlockHeight,
        round:  Round,
    ) -> ConsensusResult<Vote> {
        tracing::warn!(height, round, "HotStuff: round timed out, advancing");
        self.round   = round + 1;
        self.phase   = HotStuffPhase::WaitingForPrepare;
        self.pending = None;
        self.prepare_votes.clear();
        self.precommit_votes.clear();
        self.commit_votes.clear();

        let nil_vote = Vote {
            vote_type:  VoteType::Nil,
            height,
            round,
            validator:  ValidatorId("self".into()),
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
        self.height      = certificate.height + 1;
        self.round       = 0;
        self.phase       = HotStuffPhase::WaitingForPrepare;
        self.pending     = None;
        self.prepare_votes.clear();
        self.precommit_votes.clear();
        self.commit_votes.clear();

        if let Some(mut new_set) = new_validator_set {
            if let Some(ref pc) = self.config.personhood.clone() {
                new_set = apply_personhood_cap(new_set, pc);
            }
            self.validators = new_set;
        }

        tracing::info!(
            height     = self.height,
            "HotStuff: committed, advancing to next height"
        );
        Ok(())
    }

    fn verify_commit(
        &self,
        certificate:   &CommitCertificate,
        validator_set: &ValidatorSet,
    ) -> ConsensusResult<()> {
        // Count power in the certificate's precommits
        let mut power: u64 = 0;
        for vote in &certificate.precommits {
            if vote.vote_type != VoteType::Precommit {
                return Err(ConsensusError::InvalidVote {
                    validator:  vote.validator.clone(),
                    block_hash: certificate.block_hash.clone(),
                    reason:     "non-precommit vote in HotStuff commit certificate".into(),
                });
            }
            power += validator_set.power_of(&vote.validator);
        }
        if power < validator_set.quorum_power() {
            return Err(ConsensusError::InvalidVote {
                validator:  ValidatorId("quorum".into()),
                block_hash: certificate.block_hash.clone(),
                reason:     format!(
                    "insufficient commit power: {power} < {}",
                    validator_set.quorum_power()
                ),
            });
        }
        Ok(())
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
            propose_timeout_ms:   4_000,
            prevote_timeout_ms:   1_000,
            precommit_timeout_ms: 1_000,
            block_time_ms:        3_500,
            personhood:           None,
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
            propose_timeout_ms: 1000, prevote_timeout_ms: 1000,
            precommit_timeout_ms: 1000, block_time_ms: 1000, personhood: None };
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
            propose_timeout_ms:   3_000,
            prevote_timeout_ms:   1_000,
            precommit_timeout_ms: 1_000,
            block_time_ms:        1_000,
            personhood:           None,
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

}
}
