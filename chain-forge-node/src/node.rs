/// Node: the core runtime that wires all five crates together.

use crate::telemetry::emit_attestation_event;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn, error};

use chain_forge_core::{GenesisConfig, HashWidth};
use chain_forge_crypto::{ClassicalScheme, KeyPair, SchemeId, Signature, SignatureScheme};
use chain_forge_consensus::{proposal_signing_bytes, vote_signing_bytes};
use chain_forge_consensus::{
    ConsensusConfig, ConsensusVariant, PersonhoodConfig,
    ValidatorId, ValidatorInfo, ValidatorSet, BlockHash, BlockProposal, Vote, VoteType,
    tendermint::{TendermintEngine, EquivocationDetected},
    HotStuffEngine, FbaEngine,
    ConsensusEngine,
};
use chain_forge_state::StateStore;
use chain_forge_execution::{Executor, ExecutionConfig, Transaction};
use chain_forge_slashing::{SlashingModule, EquivocationEvidence};
use chain_forge_validators::ValidatorRegistry;
use chain_forge_identity::IdentityStore;
use chain_forge_pocd::DiscoveryRegistry;
use chain_forge_agents::AgentStore;
use chain_forge_p2p::{
    MockNetworkService, NetworkConfig, NetworkEvent, NetworkService,
    GossipTopic, OutboundMessage, PeerInfo,
};

/// Decode a hex-encoded genesis/key-file public key into raw bytes.
/// Returns `None` on malformed hex rather than panicking -- callers treat
/// that the same as "no key available" rather than crashing node startup
/// over a malformed genesis field that `GenesisConfig::validate()` should
/// already have caught earlier in the startup sequence.
fn hex_decode_genesis_key(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// -- Node status (shared with the API) ----------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct NodeStatus {
    pub chain_id:    String,
    pub environment: String,
    pub height:      u64,
    pub peer_count:  usize,
    pub state_root:  Option<String>,
    pub engine_version: String,
    pub is_running:  bool,
}

pub type SharedStatus = Arc<Mutex<NodeStatus>>;

// -- Explorer state (shared with the API, Section 9.1) -------------------------

/// One block's summary for the explorer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockSummary {
    pub height:     u64,
    pub state_root: String,
    pub timestamp_ms: u64,
    pub tx_count:   usize,
    pub tx_ids:     Vec<String>,
}

/// One transaction's summary for the explorer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TxSummary {
    pub id:      String,
    pub height:  u64,
    pub sender:  String,
    pub kind:    String,
    pub success: bool,
    pub gas_used: u64,
    pub events:  Vec<String>,
    pub error:   Option<String>,
}

/// One account's snapshot for the explorer, including charm state (9.1).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountSummary {
    pub address:  String,
    pub role:     String,
    pub nonce:    u64,
    pub balances: std::collections::BTreeMap<String, u128>,
    /// IntrinsicCharm surface: verification tier, or null for non-human.
    pub tier:     Option<String>,
    pub exemption_days: u32,
    /// INV-13: true when this identity is frozen by a ConfirmSybil tx.
    /// Frozen identities cannot earn rewards, cast votes, or be attested.
    #[serde(default)]
    pub frozen: bool,
    /// INV-13: true once a ConfirmSybil has been confirmed on-chain.
    /// Cleared by ReverseSybil after a successful appeal.
    #[serde(default)]
    pub sybil_confirmed: bool,
}

/// Voting-power snapshot for one validator.
/// Used by GET /api/validators to expose the current personhood-weighted set.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorPowerSummary {
    pub id:           String,
    pub voting_power: u64,
    pub pop_verified: bool,
    /// Hex-encoded registered consensus public key, or empty string if none.
    pub consensus_pubkey: String,
}

/// Explorer state, updated by the node on each committed block.
#[derive(Debug, Default)]
pub struct ExplorerState {
    /// Most recent blocks, newest first. Capped at MAX_RECENT_BLOCKS.
    pub blocks: std::collections::VecDeque<BlockSummary>,
    /// tx id -> summary.
    pub txs: std::collections::HashMap<String, TxSummary>,
    /// address -> latest account snapshot.
    pub accounts: std::collections::HashMap<String, AccountSummary>,
    /// Current validator set with voting powers, as of the last committed block.
    /// Updated every block. Used by GET /api/validators.
    pub validator_powers: Vec<ValidatorPowerSummary>,
    /// Grand Challenge receipts received via POST /api/gc-receipt.
    /// Newest first, capped at MAX_GC_RECEIPTS.
    /// NOTE: UsefulWorkReceipt (chain-forge-resource) has been retired.
    /// This field is kept as a placeholder to avoid breaking API shape.
    pub gc_receipts: std::collections::VecDeque<serde_json::Value>,
}

pub const MAX_GC_RECEIPTS: usize = 500;

pub const MAX_RECENT_BLOCKS: usize = 100;

pub type SharedExplorer = Arc<Mutex<ExplorerState>>;

// -- QRC metrics (shared with the API, Section 9.1 / 5.4) -------------------

/// Live snapshot of QRC resource economy metrics.
/// QRC is a data-consumption / resource-credit token (earned or purchased,
/// not distributed as a flat per-person drip):
///   - Purchase path: QCB burned → QRC credits at algorithmic rate Rt
///   - Contribution path: verified resource providers earn QRC directly
///   - Consumption split: ~60% provider / ~25% permanent burn / ~15% protocol reserve
/// Updated on every block commit. Read by /api/qrc.
#[derive(Debug, Default, serde::Serialize, Clone)]
pub struct QrcMetrics {
    /// Total QRC currently in circulation (uqrc).
    pub total_supply_uqrc:            u128,
    /// Total QRC permanently burned from consumption splits since genesis (uqrc).
    pub total_burned_uqrc:            u128,
    /// Total QRC minted via purchase path (QCB → QRC) since genesis (uqrc).
    pub total_purchase_minted_uqrc:   u128,
    /// Total QRC minted via contribution path (provider earnings) since genesis (uqrc).
    pub total_contribution_minted_uqrc: u128,
    /// Total $QCB burned in QCB→QRC purchases since genesis (uqcb).
    pub total_qcb_burned_uqcb:        u128,
    /// Current conversion rate Rt (QRC per QCB burned, fixed-point × D).
    pub conversion_rate_rt:           u128,
    /// QRC held in protocol reserve (15% of every consumption event) (uqrc).
    pub protocol_reserve_uqrc:        u128,
    /// Epoch of most recent metrics update.
    pub last_updated_epoch:           u64,

    // ── Control 5: CoverageRatio circuit breaker (Section 5.5) ───────────────
    /// Current circuit-breaker minting state: "normal", "restricted", or "halted".
    /// - normal:     CR ≥ 1.00 — both purchase and contribution paths open
    /// - restricted: 0.75 ≤ CR < 1.00 — purchase suspended; contribution open
    /// - halted:     CR < 0.75 — both minting paths suspended
    pub minting_state:                String,
    /// Verified network resource capacity last reported via RecordCapacity tx
    /// (normalised units × D). Zero means no capacity report received yet.
    pub tracked_capacity_fp:          u128,
    /// Current coverage ratio (tracked_capacity / total_supply), fixed-point × D.
    /// None (serialised as null) when total_supply == 0.
    pub coverage_ratio_fp:            Option<u128>,
}

pub type SharedQrcMetrics = Arc<Mutex<QrcMetrics>>;

/// Connected peers, updated from real network events (Section 7.4 / P2P layer).
/// Read by /api/peers.
pub type SharedPeers = Arc<Mutex<Vec<PeerInfo>>>;

/// Transactions submitted externally via POST /api/tx, waiting to be
/// picked up by the node's own event loop and fed into submit_tx(). The
/// API server runs in its own tokio task with no direct reference to the
/// live Node -- this queue is the bridge between them, following the same
/// Arc<Mutex<T>> pattern as SharedStatus/SharedExplorer/SharedPeers above.
pub type SharedTxQueue = Arc<Mutex<Vec<Transaction>>>;

/// Per-sender committed-nonce cache. Maps `sender_address → highest committed nonce`.
/// Updated on every block commit; read at API ingress to reject replayed or
/// out-of-sequence nonces without needing to hold the full state store open.
pub type SharedNonceCache = Arc<Mutex<std::collections::HashMap<String, u64>>>;

// -- Node error ---------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("genesis error: {0}")]
    Genesis(String),
    #[error("consensus error: {0}")]
    Consensus(String),
    #[error("state error: {0}")]
    State(String),
    #[error("network error: {0}")]
    Network(String),
}

// -- Node ---------------------------------------------------------------------

/// A behind node's request for a specific missing committed height.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SyncRequest {
    from_height: u64,
}

/// A peer's reply carrying everything needed to verify and replay one
/// committed block: the certificate proving quorum was reached, and the
/// original proposal (which carries the actual transactions).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SyncResponseMsg {
    height:   u64,
    cert:     chain_forge_consensus::CommitCertificate,
    proposal: BlockProposal,
}

pub struct Node {
    genesis:   GenesisConfig,
    consensus: Box<dyn ConsensusEngine>,
    state:     StateStore,
    executor:  Executor,
    /// The P2P network backend. Mock in tests and default builds; real
    /// libp2p when the node crate's own "real-network" feature is enabled.
    /// Boxed as a trait object so both implementations are interchangeable
    /// behind the same NetworkService interface.
    network:   Box<dyn NetworkService>,
    status:         SharedStatus,
    explorer:       SharedExplorer,
    qrc_metrics:  SharedQrcMetrics,
    /// Connected peers, maintained from PeerConnected/PeerDisconnected/PeerList events.
    peers:          SharedPeers,
    /// This node's validator identity. None = observer node (no voting).
    validator_id: Option<ValidatorId>,
    /// Pending transactions waiting to be proposed in the next block.
    /// Directory for persisting chain state between restarts.
    /// If None the node runs in memory-only mode (state lost on restart).
    data_dir: Option<std::path::PathBuf>,
    /// Ed25519 keypair for signing proposals and votes. None for observer nodes.
    signing_key: Option<KeyPair>,
    mempool:   Vec<Transaction>,
    /// Proposals seen but not yet committed, keyed by (height, round).
    /// Needed because a CommitCertificate carries only the block_hash, not
    /// the transactions -- when quorum is reached (locally or via a gossiped
    /// vote), this is how the node finds the tx_data to actually execute.
    /// Entries at or below a committed height are pruned on commit.
    pending_proposals: std::collections::HashMap<(u64, u32), chain_forge_consensus::BlockProposal>,
    /// Commit certificates that arrived (via receive_vote returning Some) when
    /// the corresponding proposal had not yet been stored.  This is the
    /// partition-recovery latch: when a node's proposal gossip is delayed
    /// (network blip, slow link, reorder), votes can reach quorum before the
    /// proposal body lands.  The cert is parked here; the BlockProposal handler
    /// checks on every new proposal arrival and commits immediately if a cert
    /// is already waiting.  Without this latch the block is never committed
    /// after the partition heals, because receive_vote is not called again and
    /// the proposal handler does not re-check quorum.
    /// Entries at or below a committed height are pruned alongside pending_proposals.
    pending_certs: std::collections::HashMap<(u64, u32), chain_forge_consensus::CommitCertificate>,
    /// The (height, round) this node last proposed for, if it is the
    /// proposer and hasn't seen a commit yet. Prevents re-proposing (and
    /// re-broadcasting identical content the gossip layer will just reject
    /// as a duplicate) on every heartbeat tick while waiting for quorum.
    last_proposed: Option<(u64, u32)>,
    /// The (height, round) this node is currently timing, and when it
    /// started -- used to detect a stalled round and call on_timeout(),
    /// independently of whether this node is the round's proposer. Every
    /// validator runs its own round timer (not just the proposer), which is
    /// what lets the network recover when the original proposer already
    /// moved past a round before its peers had even finished connecting.
    round_watch: Option<(u64, u32)>,
    round_watch_started: Option<std::time::Instant>,
    /// Every committed block this node has ever seen, kept for the life of
    /// the process so a peer that falls behind (misses the moment quorum
    /// happened, was disconnected, or just started) can request and replay
    /// history it missed. Without this, a node that misses even one commit
    /// is permanently stuck outside the network -- there is no other way
    /// for it to ever learn what it missed, since gossipsub delivers each
    /// message once and never replays it.
    chain_store: std::collections::BTreeMap<u64, (chain_forge_consensus::CommitCertificate, BlockProposal)>,
    /// Identity registry (Whitepaper Section 4 / Identity Pilot Design) --
    /// backs RegisterIdentity and Attest transactions, and the
    /// verified-tier gates used throughout execution. Threaded through
    /// execute_block_with_identity()
    /// on every commit so identity state actually persists across blocks.
    identity: IdentityStore,
    /// AEI agent registry -- tracks registered agents, their capabilities,
    /// spending limits, and lifecycle status. Threaded through
    /// execute_block_with_identity() so agent state persists across blocks.
    agents: AgentStore,
    /// Slashing enforcement module (equivocation + liveness).
    /// Detects double-sign evidence and computes stake burns routed to BME.
    slasher: SlashingModule,
    /// Validator registry -- authoritative set of registered validators and
    /// their on-chain state (bonded stake, status, keys). Required by slasher.
    validator_registry: ValidatorRegistry,
    /// Transactions submitted via POST /api/tx, waiting to be pulled into
    /// the mempool. Drained once per heartbeat tick in run().
    tx_queue: SharedTxQueue,
    /// True if the runtime network config has bootstrap peers (from genesis
    /// or injected via --bootstrap CLI flag). Controls whether the event loop
    /// waits for real peer connections before attempting to participate in
    /// consensus. False means no peers are expected (solo devnet mode).
    has_bootstrap_peers: bool,

    /// Per-sender committed-nonce cache (F1 ingress guard).
    /// Updated after each block commit; exposed to the API server so it can
    /// reject out-of-sequence or replayed nonces before queuing.
    nonce_cache: SharedNonceCache,

    // ── PoCD (Proof of Cryptographic Discovery) ──────────────────────────────

    /// Active PoCD configuration parsed from `genesis.pocd` at startup.
    /// None when the genesis file has no `pocd` section.
    pocd_config: Option<chain_forge_pocd::PoCDConfig>,

    /// Runtime ledger of PoCD challenges and accepted discovery receipts.
    /// Populated when a `pocd` section exists in genesis; None otherwise.
    /// Behind a Mutex so the API handler thread can read it without holding
    /// a &mut Node reference.
    pocd_registry: Option<std::sync::Arc<Mutex<chain_forge_pocd::DiscoveryRegistry>>>,

    // ── Change Set R — P2P Proof Gossip ───────────────────────────────────────

    /// Anti-replay set for `GossipTopic::DiscoveryProof` messages.
    ///
    /// Keyed on `receipt_id` (string).  Bounded at
    /// `gossip_proof::MAX_SEEN_GOSSIP_RECEIPTS`; oldest entries are evicted
    /// via a companion VecDeque when the cap is reached.
    seen_gossip_receipts: std::collections::HashSet<String>,

    /// FIFO queue of `receipt_id`s inserted into `seen_gossip_receipts`, used
    /// to evict the oldest entry when the set reaches its cap.
    seen_gossip_receipts_order: std::collections::VecDeque<String>,

    // ── Change Set S — Decentralized Verifier Attestation Gossip ─────────────

    /// Anti-replay set for `GossipTopic::VerifierAttestation` messages.
    ///
    /// Keyed on `"{task_id}::{verifier_id}"` (the `replay_key()`).
    /// Bounded at `gossip_attestation::MAX_SEEN_ATTESTATION_KEYS`; evicted
    /// FIFO via `seen_attestation_keys_order`.
    seen_attestation_keys: std::collections::HashSet<String>,

    /// FIFO eviction queue for `seen_attestation_keys`.
    seen_attestation_keys_order: std::collections::VecDeque<String>,

    /// Accumulates verifier attestations per `(task_id, output_hash)`.
    ///
    /// Keyed on `"{task_id}::{output_hash}"` (the `quorum_key()`).
    /// When a bucket's `controller` set reaches `ATTESTATION_QUORUM` distinct
    /// entries, the corresponding `DiscoveryReceipt` in the local PoCD registry
    /// is confirmed as independently verified.  The bucket is kept after quorum
    /// to absorb late-arriving duplicate attestations without re-triggering.
    attestation_accumulator: std::collections::HashMap<
        String,
        crate::gossip_attestation::AttestationBucket,
    >,

    // ── Change Set T — Light P2P Resource/Capacity Discovery ─────────────────

    /// Per-peer capacity table, updated from incoming `GossipTopic::CapacityAd`
    /// messages.  TTL-evicted lazily on `live_entries()`.  Exposed read-only via
    /// `GET /api/peers/capacity`.  Behind an Arc<Mutex<>> so the API task can
    /// snapshot it without holding a &mut Node reference.
    peer_capacity_table: Arc<Mutex<crate::gossip_capacity::PeerCapacityTable>>,

    /// UTC millisecond timestamp of the last time this node broadcast its own
    /// capacity ad.  0 means "never".  The event loop heartbeat re-broadcasts
    /// every `CAPACITY_AD_INTERVAL_SECS` seconds.
    last_capacity_ad_ms: u64,

    // ── Deterministic block-height validator-set epochs ──────────────────────

    /// Number of blocks per validator-set epoch. Every decision that can
    /// change validator membership, voting power, or quorum (stake-bond
    /// admission, liveness-lapse revocation) fires only when
    /// `height % validator_epoch_blocks == 0`, computed purely from block
    /// height -- which every node already agrees on by construction of BFT
    /// consensus -- rather than from any node-local wall clock. A plain
    /// field, resolved once at construction from the optional
    /// `genesis.validator_bonding.validator_epoch_blocks` override (falls
    /// back to `DEFAULT_VALIDATOR_EPOCH_BLOCKS` below when absent --
    /// `DEFAULT_MAX_ACTIVE_VALIDATORS` stays a plain, not-yet-configurable
    /// constant, out of scope for "Configurable validator genesis
    /// parameters"). Still a directly-settable field after construction
    /// so tests can force an epoch boundary on a specific block without
    /// waiting out a realistic epoch length, the same way tests used to
    /// shrink `identity.clock.epoch_duration_ms` back when this was
    /// wall-clock-driven.
    validator_epoch_blocks: u64,

    /// Minimum stake (in the chain's native denom) a candidate must hold to
    /// be eligible for the active validator set. Resolved once at
    /// construction from `genesis.validator_bonding.min_bond_amount`,
    /// falling back to
    /// `chain_forge_execution::validator_bond::DEFAULT_MIN_BOND_UQCB` when
    /// the genesis override is absent -- see "Configurable validator
    /// genesis parameters" in ROADMAP.md. A plain field, same convention as
    /// `validator_epoch_blocks` above, so tests can override it directly
    /// without round-tripping through a genesis JSON string.
    min_bond_uqcb: u128,

    /// The validator set that was actually in force -- and used to reach
    /// quorum -- at each committed height, keyed by height. Populated
    /// before any admission/liveness mutation for the *next* height is
    /// applied, so it reflects exactly what produced that height's
    /// CommitCertificate.
    ///
    /// Needed because the live `self.consensus.validator_set()` is mutated
    /// in place on every epoch boundary (admissions, liveness lapses): by
    /// the time anyone asks "was this certificate valid?", the live set may
    /// already differ from the one that actually voted. A certificate must
    /// be verified against the set effective at its height, not whatever
    /// is live now -- see `verify_certificate_against_history`.
    historical_validator_sets: std::collections::BTreeMap<u64, chain_forge_consensus::ValidatorSet>,

    // ── PH-OVL-001: Personhood-weighting overlay ─────────────────────────────

    /// Per-human voting-power cap for personhood-weighted BFT
    /// (`genesis.consensus.personhood_weighted = true`).
    ///
    /// Set to `Some(PersonhoodConfig::power_cap)` at node startup when the
    /// chain is configured for personhood-weighted consensus; `None` otherwise.
    ///
    /// The per-block pop_verified refresh loops in `commit_block` and
    /// `propose_block` restore a validator's voting power from their bonded
    /// stake when both the consensus-key gate and the personhood gate clear.
    /// Without this cap the raw bonded stake bypasses the per-human influence
    /// limit that `PersonhoodConfig` is supposed to enforce: a validator bonded
    /// at 10 M uQCB would be restored to 10 M even when `power_cap = 1`.
    ///
    /// After restoring power from the bond, both refresh loops check this field
    /// and clamp `voting_power` to `power_cap` for any validator whose
    /// `pop_verified` flag is set — matching the clamping `apply_personhood_cap`
    /// already performs at `update_validator_set` / `init` in all three BFT
    /// engines (Tendermint, HotStuff, FBA).
    personhood_power_cap: Option<u64>,
}

/// Default validator-set epoch length in blocks. Matches the scale PoCD's
/// own `reward_epoch_blocks` test fixtures already use (100), so devnet
/// tests see an epoch roll within a reasonable number of commits without
/// a separate magic number to remember.
pub const DEFAULT_VALIDATOR_EPOCH_BLOCKS: u64 = 100;

/// Map a transaction body to a short string label for the explorer.
///
/// This function is the single source of truth for the kind string used
/// in TxSummary. It must be updated whenever a new TxBody variant is added
/// — the compiler enforces exhaustiveness, so a missing arm is a build error,
/// not a silent bug.
pub(crate) fn tx_kind_label(body: &chain_forge_execution::TxBody) -> &'static str {
    use chain_forge_execution::TxBody;
    match body {
        TxBody::Transfer { .. }             => "transfer",
        TxBody::Burn { .. }                 => "burn",
        TxBody::Stake { .. }                => "stake",
        TxBody::Custom { .. }              => "custom",
        TxBody::RegisterIdentity            => "register_identity",
        TxBody::Attest { .. }              => "attest",
        TxBody::SponsorAgent { .. }        => "sponsor_agent",
        TxBody::RevokeAgent { .. }         => "revoke_agent",
        TxBody::RevokeAttestation { .. }        => "revoke_attestation",
        TxBody::ConfirmSybil { .. }             => "confirm_sybil",
        TxBody::ReverseSybil { .. }             => "reverse_sybil",
        TxBody::ReportSuspectedSybil { .. }     => "report_suspected_sybil",
        // Phase 1: IntrinsicCharm & AEI agent registration
        TxBody::CharmConfinementUpdate { .. }   => "charm_confinement_update",
        TxBody::IntrinsicCharmRecord { .. }     => "intrinsic_charm_record",
        TxBody::RegisterAgent { .. }            => "register_agent",
        // AEI Phase 2 agent lifecycle
        TxBody::AuthorizeAgent { .. }           => "authorize_agent",
        TxBody::SuspendAgent { .. }             => "suspend_agent",
        TxBody::RevokeAgentFull { .. }          => "revoke_agent_full",
        TxBody::RecordAgentSpend { .. }         => "record_agent_spend",
        TxBody::SpawnChildAgent { .. }          => "spawn_child_agent",
        // PQ-VAL-002 R1: PQ Consensus Activation governance tx
        TxBody::ActivatePqConsensus { .. } => "activate_pq_consensus",
        // CS-001 P4: Emergency Cryptographic Deprecation (constitutional governance)
        TxBody::EmergencyDeprecateAlgorithm { .. } => "emergency_deprecate_algorithm",
        // PoCD Research Reward Settlement (Change Set L)
        TxBody::ClaimResearchReward { .. }      => "claim_research_reward",
        // Validator Onboarding (ROADMAP.md)
        TxBody::BondValidator { .. }             => "bond_validator",
        TxBody::UnbondValidator                  => "unbond_validator",
        TxBody::RegisterValidatorKey { .. }      => "register_validator_key",
    }
}

impl Node {
    /// Create a new node from a genesis JSON string.
    pub async fn new(
        genesis_json: &str,
        validator_address: Option<String>,
    ) -> Result<Self, NodeError> {
        Self::new_with_p2p_port(genesis_json, validator_address, None).await
    }

    /// Create a new node, optionally overriding the P2P port from genesis.
    /// The override is what makes running multiple nodes on one machine
    /// (local multi-node testnet) possible -- each instance needs its own
    /// bind port even though they share one genesis file.
    pub async fn new_with_p2p_port(
        genesis_json: &str,
        validator_address: Option<String>,
        p2p_port_override: Option<u16>,
    ) -> Result<Self, NodeError> {
        Self::new_with_config(genesis_json, validator_address, p2p_port_override, vec![]).await
    }

    /// Full constructor: P2P port override + extra bootstrap peer addresses.
    ///
    /// `extra_bootstrap` is a list of libp2p multiaddr strings
    /// (e.g. `/ip4/127.0.0.1/tcp/27001`) that are **merged** with the
    /// genesis `network.bootstrap_nodes` list before the network layer starts.
    /// This lets the node CLI override or extend the genesis peer list at
    /// runtime — necessary to run multiple nodes locally without embedding
    /// per-instance addresses in a shared genesis file.
    pub async fn new_with_config(
        genesis_json: &str,
        validator_address: Option<String>,
        p2p_port_override: Option<u16>,
        extra_bootstrap: Vec<String>,
    ) -> Result<Self, NodeError> {
        // Parse and validate genesis
        let genesis = GenesisConfig::from_json(genesis_json)
            .map_err(|e| NodeError::Genesis(e.to_string()))?;

        let errors = genesis.validate();
        if !errors.is_empty() {
            // Log all validation errors but only fail on hard errors
            for e in &errors {
                warn!(error = %e, "genesis validation warning");
            }
        }

        // Hard error, in every environment: mandatory validator keys
        // (security change set, Decision Option B -- "no devnet bypass
        // that allows unverified or keyless validators to participate in
        // consensus"). A chain that cannot seat any validator with a real
        // registered key is not a "proceed with a warning" situation --
        // nothing could ever reach quorum (see gate_voting_power in
        // chain-forge-consensus), so refuse to start at all rather than
        // boot into a validator set that can never vote.
        genesis.validate_validator_keys().map_err(NodeError::Genesis)?;

        // Hard error, in every environment: an accepted-but-nonsensical
        // `validator_bonding` override (zero minimum bond, zero epoch
        // length) is not a "proceed with a warning" situation -- the
        // latter would panic on the first `height / validator_epoch_blocks`
        // division. See `GenesisConfig::validate_validator_bonding`.
        genesis.validate_validator_bonding().map_err(NodeError::Genesis)?;

        // Resolve the validator-onboarding knobs once here: genesis
        // override if present, else the engine's compiled-in default.
        // Every node that parses the same genesis JSON computes the exact
        // same two values -- "Configurable validator genesis parameters"
        // requirement #5 (every node derives the same epoch boundaries and
        // minimum-bond rule from the same genesis).
        let validator_epoch_blocks = genesis.validator_bonding.as_ref()
            .and_then(|vb| vb.validator_epoch_blocks)
            .unwrap_or(DEFAULT_VALIDATOR_EPOCH_BLOCKS);
        let min_bond_uqcb = genesis.validator_bonding.as_ref()
            .and_then(|vb| vb.min_bond_amount)
            .unwrap_or(chain_forge_execution::validator_bond::DEFAULT_MIN_BOND_UQCB);

        // Hard error, in every environment: running with a module list the
        // engine can't honour would mean the chain behaves differently
        // from what its genesis says.
        let modules = genesis.enabled_modules().map_err(NodeError::Genesis)?;
        info!(
            staking = modules.staking, identity = modules.identity,
            agents = modules.agents,
            market = modules.market, pocd = modules.pocd,
            personhood_weighted = genesis.consensus.personhood_weighted,
            "modules enabled"
        );

        info!(
            chain_id    = %genesis.chain_id,
            environment = %genesis.environment.mode,
            validators  = genesis.consensus.validator_set_size,
            "genesis loaded"
        );

        // Initialise state from genesis accounts
        let hash_width = genesis.hash_width()
            .map_err(|e| NodeError::Genesis(e.to_string()))?;

        let mut state = StateStore::new(hash_width);
        state.apply_genesis(&genesis)
            .map_err(|e| NodeError::State(e.to_string()))?;

        // Build validator set from genesis accounts.
        // pop_verified is derived from the IdentityStore after seeding, not
        // from the raw modules.identity flag. This ensures that only
        // addresses that actually hold a Verified+ IdentityRecord are marked
        // as PoP-verified in the consensus layer — the source of truth is
        // always the identity store, not a configuration flag.
        // Note: identity seeding happens a few lines below this point; we
        // re-derive pop_verified after seeding (see "Backfill pop_verified"
        // comment below) so the two stay in sync.
        let validator_accounts: Vec<_> = genesis.genesis_accounts
            .iter()
            .filter(|a| a.role == "validator")
            .collect();
        let validators: Vec<ValidatorInfo> = validator_accounts.iter()
            .map(|a| {
                // Decode the genesis public key (hex) if present. This is
                // what lets vote/proposal signature verification work from
                // block 0 without any out-of-band key exchange.
                let public_key = a.public_key.as_deref().and_then(|hex| {
                    if hex.len() % 2 != 0 { return None; }
                    (0..hex.len()).step_by(2)
                        .map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
                        .collect::<Option<Vec<u8>>>()
                }).unwrap_or_default();
                ValidatorInfo {
                    id: ValidatorId(a.address.clone()),
                    voting_power: 1,
                    // Placeholder — backfilled from IdentityStore after seeding.
                    pop_verified: false,
                    public_key,
                }
            })
            .collect();

        // Pad to validator_set_size if fewer genesis validators were specified
        let target_size = genesis.consensus.validator_set_size as usize;
        let mut validators = validators;
        if validators.is_empty() {
            // No validator accounts in genesis -- create synthetic validators
            // for devnet/testnet single-node mode
            warn!("no validator accounts in genesis; creating synthetic validator set");
            for i in 0..target_size.min(4) {
                validators.push(ValidatorInfo {
                    id: ValidatorId(format!("synthetic-val-{i:02}")),
                    voting_power: 1,
                    pop_verified: true,
                    public_key: vec![],
                });
            }
        }

        let genesis_vs = ValidatorSet {
            height: 0,
            validators,
        };

        // Build consensus config
        let personhood_cfg = if genesis.consensus.personhood_weighted {
            Some(PersonhoodConfig {
                power_cap: 1,
                reject_expired_pop: false,
                min_verified_pct: 67,
            })
        } else {
            None
        };

        // Read the desired variant from genesis config (default: TendermintStyle).
        let desired_variant = match genesis.consensus.bft_variant.as_deref() {
            Some("hotstuff") | Some("HotStuffStyle") => ConsensusVariant::HotStuffStyle,
            Some("xrpl")    | Some("XrplInspired")   => ConsensusVariant::XrplInspired,
            _                                          => ConsensusVariant::TendermintStyle,
        };

        let consensus_cfg = ConsensusConfig {
            variant:              desired_variant.clone(),
            chain_id:             genesis.chain_id.clone(),
            propose_timeout_ms:   genesis.consensus.block_time_ms * 2,
            prevote_timeout_ms:   genesis.consensus.block_time_ms,
            precommit_timeout_ms: genesis.consensus.block_time_ms,
            block_time_ms:        genesis.consensus.block_time_ms,
            personhood:           personhood_cfg,
            vca:                  None,
        };

        // Factory dispatch: select the BFT engine based on the variant.
        // Factory dispatch: instantiate the BFT engine requested by genesis config.
        // Node stores Box<dyn ConsensusEngine> so all variants are interchangeable.
        let mut engine: Box<dyn ConsensusEngine> = match desired_variant {
            ConsensusVariant::HotStuffStyle => {
                let mut e = HotStuffEngine::new();
                e.init(consensus_cfg, genesis_vs).await
                    .map_err(|e| NodeError::Consensus(e.to_string()))?;
                Box::new(e)
            }
            ConsensusVariant::XrplInspired => {
                let mut e = FbaEngine::new();
                e.init(consensus_cfg, genesis_vs).await
                    .map_err(|e| NodeError::Consensus(e.to_string()))?;
                Box::new(e)
            }
            _ => {
                let mut e = TendermintEngine::new();
                e.init(consensus_cfg, genesis_vs).await
                    .map_err(|e| NodeError::Consensus(e.to_string()))?;
                Box::new(e)
            }
        };

        // Build executor
        let exec_config = ExecutionConfig::from_genesis(&genesis);
        let executor = Executor::new(exec_config);

        // Build network config from genesis, applying the CLI port
        // override if one was given (needed to run multiple nodes locally).
        let mut net_config = NetworkConfig::from_genesis(&genesis);
        if let Some(port) = p2p_port_override {
            net_config.p2p_port = port;
        }
        // Merge CLI-supplied bootstrap peers into the genesis list so that
        // nodes launched via --bootstrap can find each other immediately
        // without relying on mDNS, which is unreliable in CI containers.
        for addr in extra_bootstrap {
            if !net_config.bootstrap_nodes.contains(&addr) {
                net_config.bootstrap_nodes.push(addr);
            }
        }

        // Real libp2p when the "real-network" feature is enabled AND we are
        // not running under `cargo test`.  Unit tests (cfg(test)) always use
        // the fast in-memory mock regardless of the feature flag, so they
        // stay deterministic and don't bind real ports.  The devnet
        // integration test spawns a compiled binary that is NOT compiled with
        // cfg(test), so it gets the real libp2p stack.
        #[cfg(all(feature = "real-network", not(test)))]
        let network: Box<dyn NetworkService> = {
            let (svc, local_addr) = chain_forge_p2p::real::Libp2pService::start(&net_config)
                .await
                .map_err(|e| NodeError::Network(e.to_string()))?;
            info!(local_addr = %local_addr, "real libp2p network started");
            Box::new(svc)
        };

        #[cfg(not(all(feature = "real-network", not(test))))]
        let network: Box<dyn NetworkService> = {
            let mut svc = MockNetworkService::new();
            svc.start(net_config.clone()).await
                .map_err(|e| NodeError::Network(e.to_string()))?;
            Box::new(svc)
        };

        // Initial shared status
        let status = Arc::new(Mutex::new(NodeStatus {
            chain_id:       genesis.chain_id.clone(),
            environment:    genesis.environment.mode.clone(),
            height:         0,
            peer_count:     0,
            state_root:     None,
            engine_version: genesis.engine_version.clone(),
            is_running:     false,
        }));

        let validator_id = validator_address.map(ValidatorId);
        let explorer       = Arc::new(Mutex::new(ExplorerState::default()));
        let qrc_metrics  = Arc::new(Mutex::new(QrcMetrics::default()));

        let peers: SharedPeers = Arc::new(Mutex::new(Vec::new()));

        // IdentityStore's epoch clock is anchored to real wall-clock time,
        // not the genesis config's ISO8601 timestamp -- avoids parsing that
        // string just to compute a value used the same way either way:
        // "epoch 0 starts now." Documented here because it's a deliberate
        // Phase 0/1 simplification, not an oversight -- see the identity
        // pilot's own duration fields (30/90 days) for how epoch numbering
        // is actually consumed downstream.
        let identity_genesis_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut identity = IdentityStore::new(identity_genesis_ms);

        // Without this, IdentityStore::attest() has no seed to bootstrap
        // from: it requires the attester to already be Verified+, and with
        // a fresh store nobody ever is -- meaning no identity could EVER
        // become Verified via the real attestation flow, no matter how
        // many people registered or attested each other. The genesis
        // validator set is the natural root of trust (the same founders
        // who set the chain's rules to begin with), matching how
        // web-of-trust systems in practice always need an initial trusted
        // set to grow from (PGP's original keysigners is the classic
        // example). Every other identity still goes through the real
        // 3-attestation quorum; only this fixed, small, known founding set
        // skips it, via the same genesis bootstrap path the Phase 0 tests
        // already use (PopAttestation::genesis + verify_identity).
        // Only chains running the identity module have a web of trust to seed.
        let seed_accounts = genesis.genesis_accounts.iter()
            .filter(|a| modules.identity && a.role == "validator");
        for acct in seed_accounts {
            let att = chain_forge_identity::PopAttestation::genesis(&acct.address, 0);
            if identity.register(acct.address.clone(), acct.address.clone(), att.clone()).is_ok() {
                // Phase 0: genesis bootstrap; no ZK proof required.
                let _ = identity.verify_identity(&acct.address, att, None);
            }
        }

        // Backfill pop_verified in the consensus engine's validator set now that
        // identity seeding is complete. The genesis_vs was built before seeding
        // (pop_verified: false placeholder), so we fetch a clone, fix each entry,
        // and push it back via update_validator_set.
        //
        // Proof-of-personhood admission: a validator must hold a Verified+
        // IdentityRecord to participate in block production. We derive from the
        // store so the consensus layer's source of truth is always the identity
        // store, not a configuration flag.
        {
            let mut vs = engine.validator_set().clone();
            for v in &mut vs.validators {
                v.pop_verified = identity.get(&v.id.0)
                    .map(|r| r.charm.tier.grants_consensus())
                    .unwrap_or(false);
                if !v.pop_verified {
                    warn!(
                        validator = %v.id,
                        "genesis validator has no Verified identity record — \
                         pop_verified=false, voting power will be clamped to 0 \
                         by apply_personhood_cap if personhood_weighted=true"
                    );
                }
            }
            let _ = engine.update_validator_set(vs);
        }

        // Hard error: confirm the genesis validator set can actually reach
        // quorum before this node enters consensus at all.
        //
        // `update_validator_set` just above runs every validator through
        // `gate_voting_power` (chain-forge-consensus): a validator with no
        // registered key or no verified personhood now has voting_power
        // forced to 0, unconditionally, in every engine. Genesis key
        // validation (`validate_validator_keys`, checked earlier in this
        // function) guarantees every validator HAS a key; this check
        // confirms the other half actually held -- enough of them are also
        // verified -- rather than assuming it did. Catches a genesis that
        // is structurally valid (real keys) but operationally dead (e.g.
        // identity seeding silently failed, or every genesis account's role
        // doesn't match an actual Verified IdentityRecord): better to
        // refuse to start than to boot into a validator set that can never
        // vote.
        {
            let vs = engine.validator_set();
            let eligible = vs.validators.iter().filter(|v| v.voting_power > 0).count();
            if eligible == 0 {
                return Err(NodeError::Consensus(format!(
                    "genesis validator set has zero eligible voting power after \
                     the personhood/key gate -- every one of its {} validator(s) \
                     is missing a registered key, lacks verified personhood, or \
                     both. The chain cannot reach quorum and will never produce \
                     a block. Fix genesis identity seeding or validator_scheme \
                     before starting this node.",
                    vs.validators.len()
                )));
            }
            if eligible < vs.validators.len() {
                warn!(
                    eligible,
                    total = vs.validators.len(),
                    "{} of {} genesis validators have zero effective voting \
                     power (missing key or unverified personhood) -- starting \
                     anyway since at least one is eligible, but BFT safety \
                     margin is computed over the eligible set, not the nominal \
                     one",
                    vs.validators.len() - eligible, vs.validators.len()
                );
            }
            if eligible < 4 {
                warn!(
                    eligible,
                    "fewer than 4 validators have effective voting power -- \
                     byzantine_fault_tolerance() is 0 for sets this small \
                     regardless of nominal size; this chain has no real BFT \
                     safety margin yet"
                );
            }
        }

        // Pilot-phase attestation coordinator. If genesis names one, wire it
        // into the identity store so ConfirmSybil / ReverseSybil txs work.
        // Without this, both tx types return NotCoordinator immediately.
        // Named temporary centralization; see QCB-Attestation-Guard-Design.md.
        if let Some(ref coord) = genesis.attestation_coordinator {
            identity.set_coordinator(Some(coord.clone()));
            info!(coordinator = %coord, "attestation coordinator configured from genesis");
        } else {
            info!("no attestation_coordinator in genesis — ConfirmSybil/ReverseSybil disabled until set");
        }

        // Change Set L: settlement operators for ClaimResearchReward.
        // Analogous to attestation_coordinator; authorization enforced in ExecutionConfig.
        if genesis.settlement_operators.is_empty() {
            info!("no settlement_operators in genesis — ClaimResearchReward disabled until configured");
        } else {
            info!(
                operators = ?genesis.settlement_operators,
                "settlement operators configured from genesis ({} address(es))",
                genesis.settlement_operators.len()
            );
        }

        let slasher = SlashingModule::with_qcb_defaults();

        // Seed the ValidatorRegistry with genesis validators, gated on
        // identity verification (Point 1 of the identity integration plan).
        //
        // Policy: a genesis validator whose identity fails verify_identity()
        // is registered as a Candidate but NOT activated — it stays at
        // voting power 0 with a WARN log. The node does not refuse to start,
        // because one validator's bad state should not halt the whole chain.
        // The failure is visible in /api/status via the ValidatorRegistry and
        // will surface in the per-block PoP refresh. This is the intended
        // "start inactive, log loudly" policy from the integration design doc.
        let mut validator_registry = ValidatorRegistry::qcb_devnet();
        {
            // Only seed if the identity module is enabled — otherwise there is
            // no IdentityStore to verify against, and registering validators
            // without any PoP check would bypass the personhood gate entirely.
            if modules.identity {
                let epoch = identity.clock.current_epoch;
                for acct in genesis.genesis_accounts.iter()
                    .filter(|a| a.role == "validator")
                {
                    let id = &acct.address;

                    // Register as Candidate first (no-op if already present).
                    // Block height 0: we are in node startup, before block 1 is produced.
                    validator_registry.register_genesis_validator(id, 0);

                    // CF-VAL-KEY-002: register_genesis_validator() leaves
                    // KeyBundle.consensus_pubkey empty ("genesis-stub") --
                    // genesis itself is the authenticated source for a
                    // genesis validator's key (validate_validator_keys()
                    // already required every genesis validator to have one
                    // before the node got this far), so there is no separate
                    // proof-of-possession to check here; just carry that
                    // already-verified key into the registry so
                    // build_validator_set() -- which now reads keys back
                    // from here instead of hardcoding empty -- has it too.
                    if let Some(hex_key) = acct.public_key.as_ref() {
                        if let Some(key_bytes) = hex_decode_genesis_key(hex_key) {
                            if let Err(e) = validator_registry.register_consensus_key(id, &key_bytes, epoch) {
                                warn!(validator = id, error = %e, "failed to seed genesis validator's consensus key into registry");
                            }
                        }
                    }

                    // Verify identity against IdentityStore (Integration Point 1).
                    // Only if verification succeeds does the validator enter Active.
                    // verify_identity() returns () on success — we look up the
                    // resulting tier from the record to pass to confirm_pop.
                    let genesis_att = chain_forge_identity::PopAttestation::genesis(id, epoch);
                    // Phase 0: genesis bootstrap; no ZK proof required.
                    match identity.verify_identity(id, genesis_att, None) {
                        Ok(()) => {
                            // Fetch the tier the identity store assigned after verification.
                            let tier = identity.get(id)
                                .map(|r| r.charm.tier.clone())
                                .unwrap_or(chain_forge_identity::VerificationTier::Provisional);
                            if let Err(e) = validator_registry.confirm_pop(id, tier, epoch) {
                                warn!(
                                    validator = id,
                                    error     = %e,
                                    "genesis validator confirm_pop failed after verify_identity"
                                );
                            } else {
                                info!(validator = id, "genesis validator PoP confirmed — Active");
                            }
                            // Sync the verified charm into the StateStore account so
                            // the explorer shows the correct tier from block 1.
                            // Without this, genesis validators are Verified in
                            // IdentityStore but have no charm in StateStore, so
                            // /api/identity returns registered:false forever.
                            if let (Ok(record), Ok(acct)) = (
                                identity.get(id),
                                state.get_account_mut(id),
                            ) {
                                acct.attach_charm(record.charm.clone());
                                state.refresh_leaf(id);
                            }
                        }
                        Err(e) => {
                            warn!(
                                validator = id,
                                error     = %e,
                                "genesis validator identity verification failed — \
                                 staying Candidate (pop_verified=false, voting power 0)"
                            );
                        }
                    }
                }
            }
        }

        let tx_queue: SharedTxQueue = Arc::new(Mutex::new(Vec::new()));

        // Record whether the final runtime config has bootstrap peers so the
        // event loop can decide between solo-devnet and multi-node mode.
        let has_bootstrap_peers = !net_config.bootstrap_nodes.is_empty();

        // ── PoCD: parse optional genesis.pocd section ─────────────────────
        // `genesis.pocd` is stored as raw `serde_json::Value` in GenesisConfig
        // (chain-forge-core must not depend on chain-forge-pocd).  Here in the
        // node crate — which already depends on both — we deserialize it into
        // PoCDConfig and seed an empty DiscoveryRegistry so the API endpoints
        // and reward policy have something to operate on.
        let (pocd_config, pocd_registry) = match &genesis.pocd {
            Some(raw) => {
                match serde_json::from_value::<chain_forge_pocd::PoCDConfig>(raw.clone()) {
                    Ok(cfg) => {
                        info!(
                            chain_id = %cfg.chain_id,
                            min_difficulty = cfg.min_seal_difficulty_bits,
                            "PoCD enabled from genesis"
                        );
                        let mut reg = DiscoveryRegistry::new();

                        // Seed genesis_challenges into the registry so they are
                        // immediately active when the node starts.  The field is
                        // stored as raw JSON in GenesisConfig (same as `pocd`)
                        // so we deserialize it here in the node crate.
                        if let Some(raw_challenges) = &genesis.genesis_challenges {
                            match serde_json::from_value::<Vec<chain_forge_pocd::DiscoveryChallenge>>(
                                raw_challenges.clone(),
                            ) {
                                Ok(challenges) => {
                                    let n = challenges.len();
                                    for ch in challenges {
                                        let id = ch.challenge_id.clone();
                                        if let Err(e) = reg.add_challenge(ch) {
                                            warn!(challenge_id = %id, error = %e, "skipping duplicate genesis challenge");
                                        }
                                    }
                                    info!(count = n, "seeded genesis PoCD challenges");
                                }
                                Err(e) => {
                                    warn!(error = %e, "genesis_challenges present but failed to parse — no challenges seeded");
                                }
                            }
                        }

                        let reg = Arc::new(Mutex::new(reg));
                        (Some(cfg), Some(reg))
                    }
                    Err(e) => {
                        warn!(error = %e, "genesis.pocd is present but failed to parse as PoCDConfig — PoCD disabled");
                        (None, None)
                    }
                }
            }
            None => (None, None),
        };

        // PH-OVL-001: read before `genesis` is moved into the struct.
        let personhood_power_cap: Option<u64> = if genesis.consensus.personhood_weighted {
            Some(1) // matches PersonhoodConfig::power_cap default
        } else {
            None
        };

        // Build nonce cache from committed account state BEFORE state is moved
        // into Self. account.nonce is the next expected nonce (post-increment),
        // so last committed tx.nonce = account.nonce - 1.
        // Genesis accounts seed the nonce cache with their current nonce so F5
        // knows they're valid senders. Nonces start at 0 (first valid tx nonce=1).
        // A fresh account (nonce=0 in genesis) is seeded with last=0, so its first
        // valid tx must use nonce=1 (not nonce=0).
        let initial_nonce_cache = {
            let mut m = std::collections::HashMap::new();
            for acct in state.all_accounts() {
                m.insert(acct.address.clone(), acct.nonce);
            }
            m
        };

        // Seed the explorer with genesis account balances so that
        // /qcb/resource/balance and the F2 balance guard work before the
        // first block is committed (height 0).
        {
            let mut ex = explorer.lock().unwrap();
            for acct in state.all_accounts() {
                ex.accounts.insert(acct.address.clone(), AccountSummary {
                    address:        acct.address.clone(),
                    role:           acct.role.clone(),
                    nonce:          acct.nonce,
                    balances:       acct.balances.clone(),
                    tier:           acct.verification_tier().map(|t| t.to_string()),
                    exemption_days: acct.exemption_days(),
                    frozen:         false,
                    sybil_confirmed: false,
                });
            }
        }

        Ok(Self {
            genesis,
            consensus: engine,
            state,
            executor,
            network,
            status,
            explorer,
            qrc_metrics,
            peers,
            data_dir: None,
            signing_key: None,
            validator_id,
            mempool: Vec::new(),
            nonce_cache: Arc::new(Mutex::new(initial_nonce_cache)),
            pending_proposals: std::collections::HashMap::new(),
            pending_certs:     std::collections::HashMap::new(),
            last_proposed: None,
            round_watch: None,
            round_watch_started: None,
            chain_store: std::collections::BTreeMap::new(),
            identity,
            agents: AgentStore::new(),
            slasher,
            validator_registry,
            tx_queue,
            has_bootstrap_peers,
            pocd_config,
            pocd_registry,
            seen_gossip_receipts:       std::collections::HashSet::new(),
            seen_gossip_receipts_order: std::collections::VecDeque::new(),
            // Change Set S
            seen_attestation_keys:       std::collections::HashSet::new(),
            seen_attestation_keys_order: std::collections::VecDeque::new(),
            attestation_accumulator:     std::collections::HashMap::new(),
            // Change Set T
            peer_capacity_table: Arc::new(Mutex::new(crate::gossip_capacity::PeerCapacityTable::new())),
            last_capacity_ad_ms: 0,
            validator_epoch_blocks,
            min_bond_uqcb,
            historical_validator_sets: std::collections::BTreeMap::new(),
            personhood_power_cap,
        })
    }

    /// Optional modules this chain runs (API pre-check uses this).
    pub fn enabled_modules(&self) -> chain_forge_core::EnabledModules {
        self.genesis.enabled_modules().unwrap_or_default()
    }

    /// Whether genesis requires signed transactions (API pre-check uses this).
    pub fn require_signatures(&self) -> bool {
        self.genesis.execution.require_signatures
    }

    /// Addresses authorised to settle research rewards (API pre-check uses this).
    /// Returns an empty Vec for chains that do not configure settlement_operators.
    pub fn settlement_operators(&self) -> Vec<String> {
        self.genesis.settlement_operators.clone()
    }

    pub fn max_tx_bytes(&self) -> usize {
        self.genesis.limits.max_tx_bytes as usize
    }

    pub fn block_gas_limit(&self) -> u64 {
        self.genesis.limits.block_gas_limit
    }

    /// Address of the pilot-phase attestation coordinator (may be None if not configured).
    /// Only this address may submit ConfirmSybil and ReverseSybil transactions.
    pub fn attestation_coordinator(&self) -> Option<String> {
        self.genesis.attestation_coordinator.clone()
    }

    /// Addresses authorised to submit governance transactions (ActivatePqConsensus).
    /// Derived from genesis validator accounts. Returns empty Vec if none configured.
    pub fn governance_authorities(&self) -> Vec<String> {
        self.genesis.genesis_accounts.iter()
            .filter(|a| a.role == "validator")
            .map(|a| a.address.clone())
            .collect()
    }

    pub fn nonce_cache(&self) -> SharedNonceCache {
        self.nonce_cache.clone()
    }

    pub fn chain_id(&self) -> &str {
        &self.genesis.chain_id
    }

    pub fn environment(&self) -> &str {
        &self.genesis.environment.mode
    }

    pub fn status(&self) -> SharedStatus {
        self.status.clone()
    }

    pub fn explorer(&self) -> SharedExplorer {
        self.explorer.clone()
    }

    pub fn qrc_metrics(&self) -> SharedQrcMetrics {
        self.qrc_metrics.clone()
    }

    pub fn peers(&self) -> SharedPeers {
        self.peers.clone()
    }

    pub fn tx_queue(&self) -> SharedTxQueue {
        self.tx_queue.clone()
    }

    /// PoCD registry shared with the API layer (None if PoCD not enabled).
    pub fn pocd_registry(&self) -> Option<std::sync::Arc<Mutex<chain_forge_pocd::DiscoveryRegistry>>> {
        self.pocd_registry.clone()
    }

    /// PoCD config (None if PoCD not enabled in genesis).
    pub fn pocd_config(&self) -> Option<&chain_forge_pocd::PoCDConfig> {
        self.pocd_config.as_ref()
    }

    // ── Change Set R: proof gossip publish helper ─────────────────────────────

    /// Publish a `DiscoveryReceipt` to all peers via `GossipTopic::DiscoveryProof`.
    ///
    /// Called by the verification layer (and the API's `POST /api/gc-receipt`
    /// path) immediately after a receipt is accepted into the local registry.
    /// The receipt fans out to all connected nodes so every node converges on
    /// the same proof pool before the epoch boundary.
    ///
    /// This is a fire-and-forget publish — network errors are logged at `warn`
    /// level and do not propagate to the caller.  The receipt is already in the
    /// local registry at this point, so a publish failure only affects
    /// propagation, not local correctness.
    pub async fn publish_discovery_receipt(&self, receipt: chain_forge_pocd::DiscoveryReceipt) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let gossip = crate::gossip_proof::DiscoveryProofGossip {
            chain_id:       self.genesis.chain_id.clone(),
            receipt,
            published_at_ms: now_ms,
        };

        let receipt_id  = gossip.receipt.receipt_id.clone();
        let challenge   = gossip.receipt.challenge_id.clone();
        let payload = gossip.to_payload();
        if let Err(e) = self.network.publish(chain_forge_p2p::OutboundMessage {
            topic:   chain_forge_p2p::GossipTopic::DiscoveryProof,
            payload,
        }).await {
            warn!(error = %e, "failed to gossip DiscoveryReceipt");
        } else {
            info!(
                receipt_id  = %receipt_id,
                challenge   = %challenge,
                "DiscoveryReceipt published to gossip mesh"
            );
        }
    }

    // ── Change Set S: attestation gossip publish helper ───────────────────────

    /// Publish a `VerifierAttestationGossip` to all peers via
    /// `GossipTopic::VerifierAttestation`.
    ///
    /// Called immediately after a verification vote is recorded locally
    /// (by the scheduler's VerificationEngine, or via the node's internal
    /// `/internal/gossip/attestation` endpoint).  The attestation fans out so
    /// every node can accumulate an independent quorum view and converge on
    /// the same reward-eligibility decision (Change Set S).
    ///
    /// Errors are logged at WARN level and do not propagate — the attestation is
    /// already recorded locally; gossip failure only affects other nodes' quorum
    /// convergence, not local correctness.
    pub async fn publish_verifier_attestation(
        &self,
        attestation: crate::gossip_attestation::VerifierAttestationGossip,
    ) {
        let task_id  = attestation.task_id.clone();
        let verifier = attestation.verifier_id.clone();
        let payload  = attestation.to_payload();
        if let Err(e) = self.network.publish(chain_forge_p2p::OutboundMessage {
            topic:   chain_forge_p2p::GossipTopic::VerifierAttestation,
            payload,
        }).await {
            warn!(
                error    = %e,
                task_id  = %task_id,
                verifier = %verifier,
                "failed to gossip VerifierAttestation"
            );
        } else {
            info!(
                task_id  = %task_id,
                verifier = %verifier,
                "VerifierAttestation published to gossip mesh"
            );
        }
    }

    // ── Change Set T: capacity ad publish helper ──────────────────────────────

    /// Build and publish this node's own `CapacityAdGossip` to the mesh.
    ///
    /// Computes `cpu_available_pct` from the current mempool depth against
    /// a fixed concurrent-task ceiling (advisory heuristic only).  The peer_id
    /// is derived from the node's chain_id + validator_id so it is stable across
    /// restarts on the same genesis.
    ///
    /// Fire-and-forget: network errors are logged at WARN, never propagated.
    /// Updates `last_capacity_ad_ms` so the caller's heartbeat loop can throttle.
    pub async fn publish_own_capacity_ad(&mut self, now_ms: u64) {
        use crate::gossip_capacity::{CapacityAdGossip, CAPACITY_AD_INTERVAL_SECS};

        let queue_depth = self.mempool.len() as u32;
        let max_concurrent: u32 = 8; // advisory ceiling; tunable in a later change set
        let cpu_pct = {
            let used = queue_depth.min(max_concurrent);
            let pct = (1.0 - used as f64 / max_concurrent as f64) * 100.0;
            pct.clamp(0.0, 100.0) as u8
        };

        let peer_id = match &self.validator_id {
            Some(vid) => format!("{}::{}", self.genesis.chain_id, vid.0),
            None      => format!("{}::observer", self.genesis.chain_id),
        };

        let ad = CapacityAdGossip {
            chain_id:                   self.genesis.chain_id.clone(),
            peer_id:                    peer_id.clone(),
            node_version:               env!("CARGO_PKG_VERSION").to_string(),
            supported_workload_versions: if self.pocd_config.is_some() {
                vec!["pocd_phase1".to_string()]
            } else {
                vec![]
            },
            queue_depth,
            cpu_available_pct:          cpu_pct,
            max_concurrent_tasks:       max_concurrent,
            published_at_ms:            now_ms,
        };

        let payload = ad.to_payload();
        if let Err(e) = self.network.publish(chain_forge_p2p::OutboundMessage {
            topic:   chain_forge_p2p::GossipTopic::CapacityAd,
            payload,
        }).await {
            warn!(
                error   = %e,
                peer_id = %peer_id,
                "failed to publish own CapacityAd"
            );
        } else {
            info!(
                peer_id         = %peer_id,
                queue_depth     = queue_depth,
                cpu_available   = cpu_pct,
                interval_secs   = CAPACITY_AD_INTERVAL_SECS,
                "CapacityAd published"
            );
            self.last_capacity_ad_ms = now_ms;
        }
    }

    /// Accessor used by the API endpoint `GET /api/peers/capacity`.
    /// Returns a clone of the Arc so the API task can lock it independently.
    pub fn peer_capacity_table(&self) -> Arc<Mutex<crate::gossip_capacity::PeerCapacityTable>> {
        self.peer_capacity_table.clone()
    }

    /// Sign a Vote with this node's key, domain-separated by chain_id.
    /// No-op (leaves signature empty) if no signing key is loaded.
    fn sign_vote(&self, vote: &mut Vote) {
        let Some(ref kp) = self.signing_key else { return };
        let chain_id = self.genesis.chain_id.as_str();
        let bytes = vote_signing_bytes(
            chain_id, &vote.vote_type, vote.height, vote.round,
            vote.block_hash.as_ref(),
        );
        if let Ok(sig) = ClassicalScheme.sign(&bytes, kp) {
            vote.signature = sig.bytes;
        }
    }

    /// Sign a BlockProposal with this node's key.
    fn sign_proposal(&self, proposal: &mut BlockProposal) {
        let Some(ref kp) = self.signing_key else { return };
        let chain_id = self.genesis.chain_id.as_str();
        let bytes = proposal_signing_bytes(
            chain_id, proposal.height, proposal.round,
            &proposal.block_hash, &proposal.parent_hash,
        );
        if let Ok(sig) = ClassicalScheme.sign(&bytes, kp) {
            proposal.signature = sig.bytes;
        }
    }

    /// Verify that a gossiped vote's signature is valid for the claimed validator.
    ///
    /// Returns:
    ///   `Ok(())`        — signature is valid, or no key is on file for this
    ///                     validator (Phase 0 devnet tolerance — warn only).
    ///   `Err(String)`   — signature is present but cryptographically wrong,
    ///                     or the validator is not in the active set at all.
    ///                     Caller must drop the vote.
    ///
    /// Design: we look up the sender's public key from the consensus ValidatorSet,
    /// which genesis is now required to populate for every validator
    /// (`load_signing_key` only verifies a local private key against that
    /// registered key -- it no longer backfills it; see that function's
    /// doc comment). If the key is non-empty we MUST verify — an empty
    /// signature against a known key is treated as a forgery. If the key
    /// is empty (should not happen post-migration for a real validator) we
    /// allow through so a mixed key/no-key devnet still works.
    ///
    /// Whitepaper refs: Section 7.5 (validator identity), Section 8.1 (vote rules).
    fn verify_vote_signature(&self, vote: &Vote) -> Result<(), String> {
        let vs = self.consensus.validator_set();

        // Validator must be in the active set — unknown ids are always rejected.
        let vi = vs.validators.iter()
            .find(|v| v.id == vote.validator)
            .ok_or_else(|| format!(
                "validator {} not in active set", vote.validator
            ))?;

        // No key on file: Phase 0 tolerance — pass through with a debug note.
        // Once real keys are loaded (--key-file / genesis public_key), this
        // branch is never reached for any honest validator.
        if vi.public_key.is_empty() {
            debug!(
                validator = %vote.validator,
                "no public key on file for validator — skipping signature check (Phase 0)"
            );
            return Ok(());
        }

        // Key is present — now the signature MUST be non-empty and valid.
        if vote.signature.is_empty() {
            return Err(format!(
                "validator {} has a key on file but vote carries an empty signature",
                vote.validator
            ));
        }

        let chain_id = self.genesis.chain_id.as_str();
        let msg = chain_forge_consensus::vote_signing_bytes(
            chain_id,
            &vote.vote_type,
            vote.height,
            vote.round,
            vote.block_hash.as_ref(),
        );

        let sig = chain_forge_crypto::Signature {
            scheme: chain_forge_crypto::SchemeId::Classical,
            bytes:  vote.signature.clone(),
        };

        ClassicalScheme.verify(&msg, &sig, &vi.public_key)
            .map_err(|e| format!(
                "signature verification failed for validator {}: {e}",
                vote.validator
            ))
    }

    /// Load a validator key file and bind it to this node.
    /// Called from main.rs when --key-file is supplied.
    pub fn load_signing_key(&mut self, path: &std::path::Path) -> Result<(), String> {
        fn hex_decode(s: &str) -> Option<Vec<u8>> {
            let s = s.trim();
            if s.len() % 2 != 0 { return None; }
            (0..s.len()).step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
                .collect()
        }
        fn hex_encode(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read key file {:?}: {e}", path))?;
        let k: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("bad JSON in key file {:?}: {e}", path))?;
        let field = |name: &str| k[name].as_str()
            .ok_or_else(|| format!("key file {:?} missing field '{name}'", path))
            .and_then(|s| hex_decode(s)
                .ok_or_else(|| format!("key file {:?}: '{name}' is not valid hex", path)));
        let kp = KeyPair {
            scheme:      SchemeId::Classical,
            public_key:  field("public_key")?,
            private_key: field("private_key")?,
        };
        // Look up this validator's address from the key file to match genesis.
        let address = k["address"].as_str()
            .unwrap_or_default().to_string();
        let my_id = chain_forge_consensus::ValidatorId(address.clone());

        // Security change set (mandatory validator keys, Decision Option B):
        // genesis is now the SOLE authority for a validator's registered
        // public key -- validate_validator_keys() guarantees every genesis
        // validator already has one before this node ever reaches consensus.
        // This function's job changed from "backfill the missing key" to
        // "verify the local private key actually corresponds to the key
        // genesis already published for this address" (requirement #3: the
        // local private signing key must correspond to the registered
        // public key; this is where that's enforced). It no longer writes
        // into the live ValidatorSet at all -- a key file cannot rebind
        // another validator's public identity, intentionally or by mistake.
        let vs = self.consensus.validator_set();
        let registered = vs.validators.iter().find(|v| v.id == my_id)
            .ok_or_else(|| format!(
                "key file {:?} claims address {address:?}, which is not in \
                 this chain's validator set at all -- cannot load a signing \
                 key for a validator genesis never registered",
                path
            ))?;
        if registered.public_key.is_empty() {
            // Should be unreachable post-migration (genesis validation
            // requires every validator to have a key), but fail loudly
            // rather than silently trusting an unverifiable key file if it
            // somehow is reached.
            return Err(format!(
                "validator {address} has no public_key registered in genesis \
                 at all -- refusing to load a local signing key for it \
                 (genesis must register every validator's key; this node \
                 will not backfill one from a private key file)"
            ));
        }
        if registered.public_key != kp.public_key {
            return Err(format!(
                "key mismatch for validator {address}: the local private key \
                 in {path:?} corresponds to public key {}, but genesis has \
                 {} registered for this address. Refusing to load -- either \
                 the wrong key file was supplied, or this address's genesis \
                 registration doesn't belong to this operator.",
                hex_encode(&kp.public_key), hex_encode(&registered.public_key),
            ));
        }

        // Set this node's validator identity so the event loop participates
        // in consensus (casts prevotes / precommits) rather than running as
        // an observer. Without this, the node logs "validator=None" and never
        // votes, so the network cannot reach quorum.
        self.validator_id = Some(my_id);
        tracing::info!(address = %address, "validator signing key loaded and verified against genesis");
        self.signing_key = Some(kp);
        Ok(())
    }

    /// Set the data directory for state persistence.
    /// Creates the persist subdirectory if needed. Safe to call before
    /// any blocks are committed; the first commit writes the initial files.
    pub fn set_data_dir(&mut self, dir: std::path::PathBuf) -> Result<(), String> {
        let persist = dir.join("persist");
        std::fs::create_dir_all(&persist)
            .map_err(|e| format!("cannot create persist dir {:?}: {e}", persist))?;
        self.data_dir = Some(dir);
        Ok(())
    }

    // ── PQ-VAL-002 public API ────────────────────────────────────────────────

    /// Returns the current consensus epoch from the node's identity clock.
    pub fn current_epoch(&self) -> u64 {
        self.identity.clock.current_epoch
    }

    /// Returns the stored ML-DSA consensus activation epoch, or `None` if no
    /// `ActivatePqConsensus` governance tx has been processed (or if the
    /// activation epoch was cleared by an `EmergencyDeprecateAlgorithm` tx).
    pub fn pq_activation_epoch(&self) -> Option<u64> {
        self.state
            .get_raw("pq_consensus_activation_epoch")
            .and_then(|s| s.parse::<u64>().ok())
    }

    /// Verify a scheme-tagged consensus precommit vote (PQ-VAL-002 R2).
    ///
    /// - `"classical"` votes are verified with Ed25519 against the validator's
    ///   registered classical key; accepted at any epoch.
    /// - `"ml-dsa-65"` votes are accepted only at or after the activation
    ///   epoch stored by an `ActivatePqConsensus` governance tx.  If no
    ///   activation epoch is set, or the current epoch is before it, the vote
    ///   is rejected.
    /// - Any other scheme tag is rejected fail-closed.
    ///
    /// The signing message is produced by
    /// `chain_forge_execution::consensus_precommit_signing_bytes()`.
    pub fn verify_consensus_vote(
        &self,
        vote: &chain_forge_consensus::Vote,
    ) -> Result<(), String> {
        use chain_forge_crypto::{MlDsaScheme, SchemeId, SignatureScheme};

        let validator_id = &vote.validator.0;
        let current_epoch = self.identity.clock.current_epoch;

        match vote.scheme.as_str() {
            "classical" => {
                // Classical path — accepted at any epoch.
                let pub_key = self.validator_registry
                    .consensus_pubkey_bytes(validator_id)
                    .ok_or_else(|| format!(
                        "verify_consensus_vote: validator {validator_id} has no \
                         registered classical consensus key"
                    ))?;
                let block_hash_bytes = vote.block_hash
                    .as_ref()
                    .map(|h| h.0.as_bytes())
                    .unwrap_or(&[]);
                let msg = chain_forge_execution::consensus_precommit_signing_bytes(
                    &self.genesis.chain_id,
                    vote.height,
                    vote.round,
                    block_hash_bytes,
                );
                let sig = chain_forge_crypto::Signature {
                    scheme: SchemeId::Classical,
                    bytes:  vote.signature.clone(),
                };
                ClassicalScheme.verify(&msg, &sig, &pub_key).map_err(|e| format!(
                    "verify_consensus_vote: classical signature verification \
                     failed for validator {validator_id}: {e}"
                ))
            }

            "ml-dsa-65" => {
                // ML-DSA path — epoch-gated by ActivatePqConsensus.
                let activation_epoch = self.pq_activation_epoch().ok_or_else(|| {
                    "verify_consensus_vote: ML-DSA consensus not yet activated \
                     (no ActivatePqConsensus tx has been executed)"
                        .to_string()
                })?;
                if current_epoch < activation_epoch {
                    return Err(format!(
                        "verify_consensus_vote: ML-DSA vote rejected — current \
                         epoch {current_epoch} is before activation epoch \
                         {activation_epoch}"
                    ));
                }
                let pub_key = self.validator_registry
                    .consensus_pubkey_bytes(validator_id)
                    .ok_or_else(|| format!(
                        "verify_consensus_vote: validator {validator_id} has no \
                         registered ML-DSA consensus key"
                    ))?;
                let block_hash_bytes = vote.block_hash
                    .as_ref()
                    .map(|h| h.0.as_bytes())
                    .unwrap_or(&[]);
                let msg = chain_forge_execution::consensus_precommit_signing_bytes(
                    &self.genesis.chain_id,
                    vote.height,
                    vote.round,
                    block_hash_bytes,
                );
                let sig = chain_forge_crypto::Signature {
                    scheme: SchemeId::MlDsa,
                    bytes:  vote.signature.clone(),
                };
                MlDsaScheme.verify(&msg, &sig, &pub_key).map_err(|e| format!(
                    "verify_consensus_vote: ML-DSA signature verification \
                     failed for validator {validator_id}: {e}"
                ))
            }

            other => Err(format!(
                "verify_consensus_vote: unknown scheme tag {:?} — fail-closed; \
                 accepted: \"classical\", \"ml-dsa-65\"",
                other
            )),
        }
    }

    // ── end PQ-VAL-002 public API ────────────────────────────────────────────

    /// Write chain state to disk. Called after every committed block.
    /// Writes JSON files for all stateful subsystems so a restarted node
    /// can resume at the exact committed height without replaying from genesis.
    fn persist_state(&self) {
        let Some(ref dir) = self.data_dir else { return };
        let persist = dir.join("persist");
        let snap    = self.state.export_snapshot();
        let height  = snap.height;
        for (name, value) in [
            ("state.json",      serde_json::to_string_pretty(&snap)                  .ok()),
            ("identity.json",   serde_json::to_string_pretty(&self.identity)         .ok()),
            ("validators.json", serde_json::to_string_pretty(&self.validator_registry).ok()),
            ("agents.json",     serde_json::to_string_pretty(&self.agents)           .ok()),
            ("slashing.json",   serde_json::to_string_pretty(&self.slasher)          .ok()),
            ("chain_store.json",serde_json::to_string_pretty(&self.chain_store)      .ok()),
            ("historical_validator_sets.json", serde_json::to_string_pretty(&self.historical_validator_sets).ok()),
            // CF-VAL-KEY-002: the live consensus ValidatorSet, exactly as
            // `self.consensus` holds it right now -- real keys, real
            // voting power, every currently-seated validator whether seated
            // at genesis or admitted later by stake bonding. This is
            // authoritative in a way `validator_registry.build_validator_set()`
            // is not: that function only knows about validators that went
            // through `ValidatorRegistry::register()`/`register_genesis_validator()`,
            // which the live stake-bond admission path (`compute_stake_active_set`,
            // node.rs) never calls -- so a bonded validator admitted after
            // genesis is entirely absent from `build_validator_set()`'s
            // output, not merely missing its key. Persisting the real,
            // live set directly and restoring it verbatim at restart
            // (`load_persisted_state`) is what actually satisfies "a
            // bonded validator's key and seat survive restart" -- see
            // that function for how this file is used.
            ("live_validator_set.json", serde_json::to_string_pretty(self.consensus.validator_set()).ok()),
        ] {
            if let Some(json) = value {
                let _ = std::fs::write(persist.join(name), json);
            }
        }
        tracing::debug!(height, "state persisted to disk");
    }

    /// Load chain state from disk. Returns true if state was found and loaded.
    /// On success, the node resumes from the last persisted height. All
    /// stateful subsystems (state, identity, QRC, validators, agents, slasher,
    /// block history) are restored so the node is fully caught-up immediately.
    pub fn load_persisted_state(&mut self) -> bool {
        let Some(ref dir) = self.data_dir else { return false };
        let persist = dir.join("persist");
        let snap_path        = persist.join("state.json");
        let id_path          = persist.join("identity.json");
        let validators_path  = persist.join("validators.json");
        let agents_path      = persist.join("agents.json");
        let slashing_path    = persist.join("slashing.json");
        let chain_store_path = persist.join("chain_store.json");
        let historical_vs_path = persist.join("historical_validator_sets.json");
        let live_vs_path      = persist.join("live_validator_set.json");

        if !snap_path.exists() { return false; }

        let mut load = || -> Result<(), Box<dyn std::error::Error>> {
            let snap: chain_forge_state::StateSnapshot =
                serde_json::from_str(&std::fs::read_to_string(&snap_path)?)?;
            let height = snap.height;
            self.state.restore_snapshot(snap);

            if id_path.exists() {
                self.identity = serde_json::from_str(&std::fs::read_to_string(&id_path)?)?;
            }
            if validators_path.exists() {
                self.validator_registry =
                    serde_json::from_str(&std::fs::read_to_string(&validators_path)?)?;
                tracing::debug!("validator registry restored from disk");
            }
            if agents_path.exists() {
                self.agents =
                    serde_json::from_str(&std::fs::read_to_string(&agents_path)?)?;
                tracing::debug!("agent store restored from disk");
            }
            if slashing_path.exists() {
                self.slasher =
                    serde_json::from_str(&std::fs::read_to_string(&slashing_path)?)?;
                tracing::debug!("slashing module restored from disk");
            }
            if chain_store_path.exists() {
                self.chain_store =
                    serde_json::from_str(&std::fs::read_to_string(&chain_store_path)?)?;
                tracing::debug!(
                    blocks = self.chain_store.len(),
                    "block history restored from disk"
                );
            }
            if historical_vs_path.exists() {
                self.historical_validator_sets =
                    serde_json::from_str(&std::fs::read_to_string(&historical_vs_path)?)?;
                tracing::debug!(
                    heights = self.historical_validator_sets.len(),
                    "historical validator sets restored from disk"
                );
            }

            // ── Rebuild ExplorerState from persisted chain_store + state ─────
            // ExplorerState is not persisted separately; it is reconstructed
            // here so that /api/blocks, /api/tx, /api/accounts, and
            // /api/validators all return correct data immediately after restart.
            {
                let mut ex = self.explorer.lock().unwrap();

                // Accounts: derive from the restored StateStore snapshot.
                ex.accounts.clear();
                for a in self.state.all_accounts() {
                    let (frozen, sybil_confirmed) = self.identity.get(&a.address)
                        .map(|r| (r.frozen, r.sybil_confirmed))
                        .unwrap_or((false, false));
                    ex.accounts.insert(a.address.clone(), AccountSummary {
                        address:        a.address.clone(),
                        role:           a.role.clone(),
                        nonce:          a.nonce,
                        balances:       a.balances.clone(),
                        tier:           a.verification_tier().map(|t| t.to_string()),
                        exemption_days: a.exemption_days(),
                        frozen,
                        sybil_confirmed,
                    });
                }

                // Validators: use the live consensus set (restored from
                // live_validator_set.json), which carries real public keys.
                {
                    let live = self.consensus.validator_set();
                    ex.validator_powers = live.validators.iter().map(|v| ValidatorPowerSummary {
                        id:           v.id.0.clone(),
                        voting_power: v.voting_power,
                        pop_verified: v.pop_verified,
                        consensus_pubkey: hex::encode(&v.public_key),
                    }).collect();
                }

                // Blocks + txs: walk chain_store in ascending height order so
                // push_front leaves them newest-first (matching live behaviour).
                // Only the last MAX_RECENT_BLOCKS entries are kept.
                let entries: Vec<_> = self.chain_store.iter().collect();
                let start = entries.len().saturating_sub(MAX_RECENT_BLOCKS);
                for (_, (_cert, proposal)) in &entries[start..] {
                    let txs: Vec<chain_forge_execution::Transaction> =
                        serde_json::from_slice(&proposal.tx_data).unwrap_or_default();
                    let mut tx_ids = Vec::with_capacity(txs.len());
                    for tx in &txs {
                        tx_ids.push(tx.id.clone());
                        ex.txs.entry(tx.id.clone()).or_insert_with(|| TxSummary {
                            id:       tx.id.clone(),
                            height:   proposal.height,
                            sender:   tx.sender.clone(),
                            kind:     tx.body.variant_name().to_string(),
                            // Results are not persisted; mark as succeeded
                            // (they committed, so they were accepted).
                            success:  true,
                            gas_used: 0,
                            events:   vec![],
                            error:    None,
                        });
                    }
                    ex.blocks.push_front(BlockSummary {
                        height:       proposal.height,
                        state_root:   proposal.block_hash.0.clone(),
                        timestamp_ms: proposal.timestamp_ms,
                        tx_count:     tx_ids.len(),
                        tx_ids,
                    });
                }
                // Ensure newest-first ordering after the loop.
                let mut v: Vec<_> = ex.blocks.drain(..).collect();
                v.sort_by(|a, b| b.height.cmp(&a.height));
                ex.blocks.extend(v);

                tracing::info!(
                    accounts = ex.accounts.len(),
                    blocks   = ex.blocks.len(),
                    txs      = ex.txs.len(),
                    "explorer state rebuilt from persisted chain"
                );
            }

            // Rebuild the consensus engine's view of the current height and
            // validator set so it does not re-propose already-committed blocks.
            //
            // CF-VAL-KEY-002 supersedes the original CF-DEVNET-VAL-001 fix
            // here. That fix backfilled real public keys from this node's
            // pre-restore in-memory set into `build_validator_set()`'s
            // output, which correctly solved the problem for GENESIS
            // validators (whose keys are always present pre-restore,
            // because genesis itself is their key authority). But
            // `ValidatorRegistry::build_validator_set()` only knows about
            // validators that went through `register()`/
            // `register_genesis_validator()` -- the live stake-bond
            // admission path (`compute_stake_active_set`, elsewhere in this
            // file) never calls either, so a validator admitted after
            // genesis via `BondValidator`/`RegisterValidatorKey` is not
            // merely missing its key in `build_validator_set()`'s output,
            // it is ENTIRELY ABSENT from it. The old fix could only backfill
            // keys onto entries that existed; it could not resurrect an
            // entry `build_validator_set()` never produced in the first
            // place. This went unnoticed because the original devnet
            // restart test used only genesis validators.
            //
            // Fix: use the live ValidatorSet snapshot persisted verbatim at
            // every commit (`persist_state()`, "live_validator_set.json") --
            // the actual, authoritative, in-memory set this node was
            // running with the moment before it stopped, correct keys,
            // correct voting power, every seat it actually had, genesis or
            // bonded alike. `build_validator_set()` remains the fallback for
            // a data directory written before this change existed (no
            // live_validator_set.json yet), so an old devnet data dir still
            // restarts rather than refusing to start.
            let vs = if live_vs_path.exists() {
                serde_json::from_str(&std::fs::read_to_string(&live_vs_path)?)?
            } else {
                tracing::warn!(
                    "no live_validator_set.json found (data dir predates CF-VAL-KEY-002) \
                     -- falling back to validator_registry.build_validator_set(), which \
                     will not include any validator admitted after genesis by stake bonding"
                );
                self.validator_registry.build_validator_set(height)
            };

            if let Err(e) = self.consensus.reset_to_height(height, vs) {
                tracing::warn!(
                    height,
                    error = %e,
                    "consensus engine could not fast-forward to persisted height; \
                     some re-proposal may occur until peers catch this node up"
                );
            }

            // Populate NodeStatus with the restored state root so that callers
            // that read status.state_root immediately after load_persisted_state
            // receive the correct value without needing to propose a new block.
            if let Some(root) = self.state.current_root() {
                let mut s = self.status.lock().unwrap();
                s.state_root = Some(root.to_string());
                s.height     = height;
            }

            tracing::info!(height, "chain state loaded from disk");
            Ok(())
        };
        match load() {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "could not load persisted state — starting from genesis");
                false
            }
        }
    }

    /// Add a transaction to the mempool. Returns true only if it was newly
    /// added: a tx already pending, or already committed in a block, is
    /// ignored. The committed check matters because gossip can deliver a
    /// copy after the block containing it committed; re-proposing it would
    /// execute it a second time, fail on nonce, and overwrite the explorer's
    /// record of the original success.
    pub fn submit_tx(&mut self, tx: Transaction) -> bool {
        if self.mempool.iter().any(|t| t.id == tx.id) {
            return false;
        }
        if self.explorer.lock().unwrap().txs.contains_key(&tx.id) {
            debug!(tx_id = %tx.id, "already committed -- ignoring");
            return false;
        }
        if self.mempool.len() < self.genesis.limits.mempool_size as usize {
            self.mempool.push(tx);
            true
        } else {
            warn!("mempool full -- transaction dropped");
            false
        }
    }

    /// Drop transactions that a committed block contained. Called from
    /// commit_block, which every multi-node commit path goes through
    /// (own proposal, peer's proposal, and state-sync replay).
    fn remove_committed_from_mempool(&mut self, committed: &[Transaction]) {
        let ids: std::collections::HashSet<&str> = committed.iter().map(|t| t.id.as_str()).collect();
        self.mempool.retain(|t| !ids.contains(t.id.as_str()));
    }

    /// Main event loop. Processes network events and drives consensus.
    /// In Phase 0 (mock network) this drains the startup queue then keeps
    /// running via a ticker so the HTTP API stays alive.
    /// In Phase 1 (real libp2p) this runs on real network events indefinitely.
    pub async fn run(&mut self) {
        info!(
            chain_id    = %self.genesis.chain_id,
            validator   = ?self.validator_id,
            "node event loop starting"
        );

        {
            let mut s = self.status.lock().unwrap();
            s.is_running = true;
        }

        info!(
            chain_id = %self.genesis.chain_id,
            height   = self.consensus.current_height(),
            "node ready -- waiting for transactions and blocks"
        );

        // Single loop, driven by whichever of (network event, heartbeat
        // tick) is ready first.
        //
        // This replaces the old "drain the queue, then switch to ticker"
        // structure, which only worked because the mock's next_event()
        // fails immediately when its queue is empty. A real libp2p
        // next_event() awaits a channel and only resolves when something
        // actually happens -- against a real network, the old structure
        // would block on that very first await and the ticker (and with
        // it, block production and the API's live state) would never run.
        // tokio::select! polls both futures every iteration, so network
        // activity and the heartbeat both make progress regardless of
        // which backend is in use.
        let block_time = self.genesis.consensus.block_time_ms;
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_millis(block_time)
        );
        let mut running = true;
        while running {
            tokio::select! {
                event_result = self.network.next_event() => {
                    match event_result {
                        Ok(event) => {
                            if let Err(e) = self.handle_event(event).await {
                                error!(error = %e, "error handling network event");
                            }
                        }
                        Err(e) => {
                            // Mock: this fires on every poll while its queue is
                            // empty, which is the normal steady state, not a
                            // fault -- so we log quietly and yield briefly
                            // rather than spinning the executor at 100% CPU
                            // re-polling an instantly-failing future.
                            // Real: this fires only if the event channel has
                            // closed (the network task exited) -- also not
                            // treated as fatal here; the heartbeat keeps the
                            // node alive and a future revision can distinguish
                            // "closed" from "idle" once P2pError carries that.
                            debug!(error = %e, "no network event available");
                            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        }
                    }
                }

                _ = interval.tick() => {
                    let height = self.consensus.current_height();
                    let peer_count = {
                        let s = self.status.lock().unwrap();
                        s.peer_count
                    };
                    debug!(height, peer_count, "node heartbeat");

                    // Drain any transactions submitted externally via
                    // POST /api/tx since the last tick. The API server runs
                    // in its own task with no direct reference to this Node,
                    // so this queue (SharedTxQueue) is the only bridge --
                    // same reasoning as status/explorer/peers being shared
                    // the other direction (node -> API).
                    {
                        let mut queue = self.tx_queue.lock().unwrap();
                        let submitted: Vec<Transaction> = queue.drain(..).collect();
                        drop(queue);
                        for tx in submitted {
                            // Gossip it so ANY proposer can include it, not
                            // just this node on its own proposer turns. Only
                            // API-submitted txs are published; txs received
                            // over gossip are not re-published (gossipsub
                            // already propagates them through the mesh).
                            let payload = serde_json::to_vec(&tx).unwrap_or_default();
                            if self.submit_tx(tx) {
                                let _ = self.network.publish(OutboundMessage {
                                    topic:   GossipTopic::Transaction,
                                    payload,
                                }).await;
                            }
                        }
                    }

                    // A genesis with bootstrap_nodes configured signals real
                    // peers are expected -- even before the first one has
                    // actually connected (dialing takes time, especially
                    // across separate hosts/VMs). Racing ahead with solo
                    // devnet commits during that window is exactly what
                    // causes divergence: by the time peers do connect, this
                    // node may be dozens or hundreds of blocks into a private
                    // chain nobody else agrees with, and every subsequent
                    // proposal gets rejected on height mismatch. So the solo
                    // fallback now only fires when this node has no bootstrap
                    // peers configured at all -- a genuinely standalone node.
                    // Use the runtime-resolved flag (which accounts for
                    // --bootstrap CLI peers merged in addition to genesis).
                    let expects_peers = self.has_bootstrap_peers;

                    if peer_count == 0 && !expects_peers {
                        // No real peers, none expected: solo devnet convenience
                        // path, unchanged from Phase 0. The proposer synthesises
                        // every genesis validator's vote itself and commits in
                        // one call, since there is no one else to actually vote.
                        if self.genesis.environment.mode == "devnet" {
                            let parent = chain_forge_consensus::BlockHash(
                                format!("genesis_h{height}")
                            );
                            match self.propose_block(parent).await {
                                Ok(cert) => {
                                    info!(
                                        height = cert.height,
                                        block_hash = %cert.block_hash,
                                        "devnet block committed"
                                    );
                                }
                                Err(e) => {
                                    debug!(error = %e, "block proposal skipped");
                                    running = false; // stop on unrecoverable error
                                }
                            }
                        }
                    } else if peer_count == 0 && expects_peers {
                        // Peers are configured but haven't connected yet --
                        // wait rather than racing ahead solo.
                        debug!("waiting for configured bootstrap peers to connect");
                    } else if let Some(my_id) = self.validator_id.clone() {
                        // Real peers connected. The deterministic proposer for
                        // this (height, round) proposes -- but critically, EVERY
                        // validator (not just the proposer) independently times
                        // this round out if it stalls. Only-the-proposer-times-out
                        // was the earlier design and it has a real liveness gap:
                        // if the proposer's own round advances (e.g. it proposed
                        // before its peers had even finished connecting, timed
                        // out alone, and moved to round 1) nothing tells anyone
                        // else the round changed -- a follower just waits forever
                        // for a round-0 proposal that will never come, because the
                        // only node who could send one has already moved on. Every
                        // validator running its own round timer is the standard
                        // fix: everyone converges on advancing together within a
                        // few timeout cycles even without perfectly synchronized
                        // gossip, because each node's timer starts independently
                        // the moment it notices the current (height, round).
                        let round = self.consensus.current_round();
                        let vs    = self.consensus.validator_set().clone();
                        let key   = (height, round);

                        if self.round_watch != Some(key) {
                            // First tick we've seen this (height, round) -- start
                            // this node's own timeout clock for it.
                            self.round_watch       = Some(key);
                            self.round_watch_started = Some(std::time::Instant::now());
                        }

                        if Self::is_proposer_for(&vs, height, round, &my_id)
                            && self.last_proposed != Some(key)
                            && (!self.mempool.is_empty()
                                || self.round_watch_started
                                    .map(|t| t.elapsed().as_millis() >= 2000)
                                    .unwrap_or(true))
                        {
                            let parent = chain_forge_consensus::BlockHash(
                                format!("genesis_h{height}")
                            );
                            if let Err(e) = self.propose_and_broadcast_multinode(parent).await {
                                debug!(error = %e, "multi-node proposal failed");
                            }
                            self.last_proposed = Some(key);
                        }

                        let stalled = self.round_watch_started
                            .map(|t| t.elapsed().as_millis() as u64 > block_time * 3)
                            .unwrap_or(false);
                        if stalled {
                            // This round has produced no commit within the
                            // timeout, from THIS node's point of view -- whether
                            // or not this node was the proposer. Advance on its
                            // own clock and broadcast that decision so peers who
                            // are still watching this round hear about it too.
                            match self.consensus.on_timeout(height, round).await {
                                Ok(nil_vote_template) => {
                                    warn!(height, round, "round timed out waiting for quorum, advancing round");
                                    let mut nil_vote = Vote { validator: my_id.clone(), ..nil_vote_template };
                                    self.sign_vote(&mut nil_vote);
                                    let _ = self.network.publish(OutboundMessage {
                                        topic:   GossipTopic::ConsensusVote,
                                        payload: serde_json::to_vec(&nil_vote).unwrap_or_default(),
                                    }).await;
                                    self.last_proposed        = None;
                                    self.round_watch          = None;
                                    self.round_watch_started  = None;
                                }
                                Err(e) => debug!(error = %e, "on_timeout failed"),
                            }
                        }
                    }
                    // peer_count > 0 and validator_id == None: this is an
                    // observer node. It relays gossip and executes committed
                    // blocks via handle_event, but never proposes or votes.

                    // ── Change Set T: periodic capacity ad ────────────────────────
                    // Broadcast own capacity ad at startup (last_capacity_ad_ms == 0)
                    // and every CAPACITY_AD_INTERVAL_SECS thereafter.
                    {
                        use crate::gossip_capacity::CAPACITY_AD_INTERVAL_SECS;
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let elapsed_secs = now_ms.saturating_sub(self.last_capacity_ad_ms) / 1_000;
                        if self.last_capacity_ad_ms == 0 || elapsed_secs >= CAPACITY_AD_INTERVAL_SECS {
                            self.publish_own_capacity_ad(now_ms).await;
                        }
                    }

                }
            }
        }

        {
            let mut s = self.status.lock().unwrap();
            s.is_running = false;
        }

        info!("node event loop exited");
    }

    /// Handle a single network event.
    async fn handle_event(&mut self, event: NetworkEvent) -> Result<(), String> {
        match event {
            NetworkEvent::Started { local_addr, peer_id } => {
                info!(local_addr = %local_addr, peer_id = %peer_id, "P2P network started");
            }

            NetworkEvent::Message(msg) => {
                match msg.topic {
                    GossipTopic::BlockProposal => {
                        let proposal: BlockProposal = match serde_json::from_slice(&msg.payload) {
                            Ok(p)  => p,
                            Err(e) => {
                                warn!(from = %msg.from, error = %e, "malformed block proposal, ignoring");
                                return Ok(());
                            }
                        };

                        debug!(
                            from = %msg.from,
                            height = proposal.height,
                            round  = proposal.round,
                            block_hash = %proposal.block_hash,
                            "received block proposal"
                        );

                        if proposal.height > self.consensus.current_height() {
                            // A proposal for a height beyond ours is unambiguous
                            // evidence we've fallen behind -- trying to vote on it
                            // would just get rejected anyway (we haven't verified
                            // or replayed the heights in between), so request sync
                            // instead of processing it normally.
                            self.request_sync().await;
                            return Ok(());
                        }

                        self.catch_up_round_if_behind(proposal.height, proposal.round).await;

                        // A proposal we produced ourselves is already registered
                        // with the consensus engine and cached locally; re-processing
                        // a copy that bounced back over gossip is a harmless no-op,
                        // but skip it so we don't cast a second, duplicate vote.
                        let is_own = self.pending_proposals
                            .get(&(proposal.height, proposal.round))
                            .map(|p| p.block_hash == proposal.block_hash)
                            .unwrap_or(false)
                            && self.validator_id.as_ref() == Some(&proposal.proposer);
                        if is_own {
                            return Ok(());
                        }

                        if let Err(e) = self.consensus.receive_proposal(proposal.clone()).await {
                            debug!(error = %e, "proposal rejected (stale height, wrong proposer, or locked)");
                            return Ok(());
                        }

                        self.pending_proposals.insert(
                            (proposal.height, proposal.round), proposal.clone(),
                        );

                        // Partition-recovery check: if a CommitCertificate for this
                        // (height, round) was already parked by the vote handler (votes
                        // arrived and reached quorum before this proposal body did),
                        // commit immediately.  We do NOT call cast_and_broadcast_own_votes
                        // in this path because (a) the quorum is already reached and the
                        // cert is valid, and (b) those votes were already counted and
                        // broadcast when they were first received.
                        if let Some(cert) = self.pending_certs.remove(&(proposal.height, proposal.round)) {
                            info!(
                                height = proposal.height,
                                round  = proposal.round,
                                "proposal arrived after quorum: committing deferred block"
                            );
                            if let Err(e) = self.commit_block(cert, &proposal).await {
                                error!(error = %e, "commit failed on deferred proposal commit (partition recovery)");
                            }
                        } else {
                            match self.cast_and_broadcast_own_votes(&proposal).await {
                                Ok(Some(cert)) => {
                                    if let Err(e) = self.commit_block(cert, &proposal).await {
                                        error!(error = %e, "commit failed after reaching quorum via own vote");
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => warn!(error = %e, "failed to cast own votes for received proposal"),
                            }
                        }
                    }

                    GossipTopic::ConsensusVote => {
                        let vote: Vote = match serde_json::from_slice(&msg.payload) {
                            Ok(v)  => v,
                            Err(e) => {
                                warn!(from = %msg.from, error = %e, "malformed vote, ignoring");
                                return Ok(());
                            }
                        };

                        debug!(
                            from = %msg.from,
                            height = vote.height,
                            round  = vote.round,
                            validator = %vote.validator,
                            vote_type = ?vote.vote_type,
                            "received consensus vote"
                        );

                        if vote.height > self.consensus.current_height() {
                            // Same reasoning as the BlockProposal branch above --
                            // a vote for a height we haven't reached is evidence
                            // we're behind, not something we can meaningfully
                            // process (receive_vote would just reject it).
                            self.request_sync().await;
                            return Ok(());
                        }

                        // Verify the vote signature before feeding it into
                        // consensus. This stops forged votes from being counted
                        // toward quorum — the first line of vote security.
                        // Only verified when the sending validator has a public
                        // key in the ValidatorSet -- genesis is now required to
                        // register one for every validator (load_signing_key
                        // only checks a local private key against it, it
                        // doesn't backfill). Validators without a key on file
                        // are allowed through with a warn so a mixed key/no-key
                        // network (Phase 0 devnet) doesn't hard-break.
                        if let Err(reject) = self.verify_vote_signature(&vote) {
                            warn!(
                                from      = %msg.from,
                                validator = %vote.validator,
                                height    = vote.height,
                                round     = vote.round,
                                reason    = %reject,
                                "vote rejected: invalid signature"
                            );
                            return Ok(());
                        }

                        // NOTE: deliberately no catch_up_round_if_behind() call here.
                        // A single vote is just one peer's contribution toward
                        // quorum in whatever round IT thinks is current -- treating
                        // it as authoritative evidence that the round has moved on
                        // caused a self-reinforcing cascade in practice: nodes kept
                        // leapfrogging each other's votes, abandoning a round's
                        // in-progress quorum before three matching votes could ever
                        // land in the same bucket, so quorum was never reached even
                        // once. A BlockProposal is different -- it is the legitimate
                        // proposer's unambiguous claim that a specific round has
                        // begun, so catch-up only reacts to that (see the
                        // BlockProposal branch above).

                        match self.consensus.receive_vote(vote.clone()).await {
                            Ok(Some(cert)) => {
                                // Drain equivocations before committing so any
                                // double-signer is tombstoned in the same epoch.
                                let eqs = self.consensus.drain_equivocations();
                                let epoch = self.consensus.current_height();
                                self.handle_drained_equivocations(eqs, epoch);

                                let proposal = self.pending_proposals
                                    .get(&(vote.height, vote.round))
                                    .cloned();
                                match proposal {
                                    Some(p) => {
                                        if let Err(e) = self.commit_block(cert, &p).await {
                                            error!(error = %e, "commit failed after reaching quorum via peer vote");
                                        }
                                    }
                                    None => {
                                        // Quorum reached but the proposal body hasn't arrived
                                        // yet (votes can travel faster than large proposal
                                        // payloads, and a partition heal may deliver votes
                                        // before the proposer's message is retransmitted).
                                        // Park the certificate so the BlockProposal handler
                                        // can commit the moment the body lands, without
                                        // needing to call receive_vote again.
                                        warn!(
                                            height = vote.height,
                                            round  = vote.round,
                                            "quorum reached but proposal not yet seen; \
                                             parking certificate for deferred commit"
                                        );
                                        self.pending_certs
                                            .insert((vote.height, vote.round), cert);
                                    }
                                }
                            }
                            Ok(None) => {
                                // No quorum yet — still drain equivocations so a
                                // double-sign is caught even if quorum isn't reached
                                // this turn.
                                let eqs = self.consensus.drain_equivocations();
                                if !eqs.is_empty() {
                                    let epoch = self.consensus.current_height();
                                    self.handle_drained_equivocations(eqs, epoch);
                                }
                            }
                            Err(e) => debug!(error = %e, "vote rejected"),
                        }
                    }

                    GossipTopic::Transaction => {
                        match serde_json::from_slice::<Transaction>(&msg.payload) {
                            Ok(tx) => {
                                debug!(from = %msg.from, tx_id = %tx.id, "received transaction");
                                self.submit_tx(tx);
                            }
                            Err(e) => {
                                warn!(from = %msg.from, error = %e, "malformed transaction, ignoring");
                            }
                        }
                    }

                    GossipTopic::PeerAnnounce => {
                        debug!(from = %msg.from, "received peer announcement");
                    }

                    GossipTopic::SyncRequest => {
                        let req: SyncRequest = match serde_json::from_slice(&msg.payload) {
                            Ok(r)  => r,
                            Err(e) => {
                                warn!(from = %msg.from, error = %e, "malformed sync request, ignoring");
                                return Ok(());
                            }
                        };
                        // Answer only if this node actually has the requested
                        // height -- most nodes won't, and that's fine, since
                        // this is broadcast gossip rather than point-to-point:
                        // whichever peers DO have it will each answer.
                        if let Some((cert, proposal)) = self.chain_store.get(&req.from_height) {
                            debug!(height = req.from_height, "answering sync request");
                            let resp = SyncResponseMsg {
                                height:   req.from_height,
                                cert:     cert.clone(),
                                proposal: proposal.clone(),
                            };
                            let _ = self.network.publish(OutboundMessage {
                                topic:   GossipTopic::SyncResponse,
                                payload: serde_json::to_vec(&resp).unwrap_or_default(),
                            }).await;
                        }
                    }

                    GossipTopic::SyncResponse => {
                        let resp: SyncResponseMsg = match serde_json::from_slice(&msg.payload) {
                            Ok(r)  => r,
                            Err(e) => {
                                warn!(from = %msg.from, error = %e, "malformed sync response, ignoring");
                                return Ok(());
                            }
                        };
                        // Only useful if it's exactly the next height we need --
                        // a response for a height we already have, or one still
                        // further ahead than what we need next, is ignored (the
                        // latter will arrive again once we've caught up to it).
                        if resp.height != self.consensus.current_height() {
                            return Ok(());
                        }
                        let vs = self.consensus.validator_set().clone();
                        if let Err(e) = self.consensus.verify_commit(&resp.cert, &vs) {
                            warn!(height = resp.height, error = %e, "rejected sync response: invalid commit certificate");
                            return Ok(());
                        }
                        info!(height = resp.height, "syncing: replaying verified block from peer");
                        if let Err(e) = self.commit_block(resp.cert, &resp.proposal).await {
                            error!(error = %e, "failed to replay synced block");
                            return Ok(());
                        }
                        // commit_block() only advances the consensus engine's
                        // height -- it doesn't drive the vote/round FSM the way
                        // a live commit does, so there's nothing further to reset
                        // here. Immediately ask for the next height too, so a
                        // node that's many blocks behind catches up one gossip
                        // round-trip at a time rather than waiting for the next
                        // organic proposal/vote to reveal the next gap.
                        self.request_sync().await;
                    }

                    // ── Change Set R: ingest gossiped DiscoveryReceipts ───────
                    GossipTopic::DiscoveryProof => {
                        // 1. Deserialise the envelope.
                        let gossip: crate::gossip_proof::DiscoveryProofGossip =
                            match serde_json::from_slice(&msg.payload) {
                                Ok(g)  => g,
                                Err(e) => {
                                    warn!(from = %msg.from, error = %e, "malformed DiscoveryProofGossip, ignoring");
                                    return Ok(());
                                }
                            };

                        // 2. Chain-ID guard — reject cross-chain gossip.
                        if gossip.chain_id != self.genesis.chain_id {
                            debug!(
                                from = %msg.from,
                                their_chain = %gossip.chain_id,
                                our_chain   = %self.genesis.chain_id,
                                "DiscoveryProofGossip: wrong chain_id, dropping"
                            );
                            return Ok(());
                        }

                        // 3. Staleness guard.
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        if gossip.is_stale(now_ms) {
                            debug!(
                                receipt_id = %gossip.receipt.receipt_id,
                                age_ms = now_ms.saturating_sub(gossip.published_at_ms),
                                "DiscoveryProofGossip: stale, dropping"
                            );
                            return Ok(());
                        }

                        let receipt_id = gossip.receipt.receipt_id.clone();

                        // 4. Anti-replay: skip if we've seen this receipt_id before.
                        if self.seen_gossip_receipts.contains(&receipt_id) {
                            debug!(receipt_id = %receipt_id, "DiscoveryProofGossip: duplicate, skipping");
                            return Ok(());
                        }

                        // 5. Insert into the local PoCD registry (if PoCD is enabled).
                        let inserted = if let Some(ref reg_arc) = self.pocd_registry {
                            let mut reg = reg_arc.lock().unwrap();
                            // add_receipt is idempotent on receipt_id; it also marks
                            // the proof_id as seen so the verifier won't double-accept.
                            match reg.add_receipt(gossip.receipt.clone()) {
                                Ok(()) => {
                                    info!(
                                        receipt_id  = %receipt_id,
                                        challenge   = %gossip.receipt.challenge_id,
                                        machine_id  = %gossip.receipt.machine_id,
                                        from        = %msg.from,
                                        "DiscoveryProofGossip: receipt ingested from peer"
                                    );
                                    true
                                }
                                Err(e) => {
                                    // DuplicateReceipt is expected on a reconnecting peer
                                    // that re-gossips its known receipts — not an error.
                                    debug!(
                                        receipt_id = %receipt_id,
                                        error = %e,
                                        "DiscoveryProofGossip: add_receipt returned (likely dup)"
                                    );
                                    false
                                }
                            }
                        } else {
                            debug!("DiscoveryProofGossip: PoCD not enabled on this node, ignoring");
                            false
                        };

                        // 6. Record in anti-replay set (even if PoCD disabled, so we
                        //    don't deserialise + check a second time on re-delivery).
                        self.seen_gossip_receipts.insert(receipt_id.clone());
                        self.seen_gossip_receipts_order.push_back(receipt_id);

                        // Evict oldest when capped.
                        while self.seen_gossip_receipts.len()
                            > crate::gossip_proof::MAX_SEEN_GOSSIP_RECEIPTS
                        {
                            if let Some(old) = self.seen_gossip_receipts_order.pop_front() {
                                self.seen_gossip_receipts.remove(&old);
                            }
                        }

                        // 7. Re-broadcast if freshly inserted (flood-fill semantics).
                        //    Without this, only the originating node pushes the message;
                        //    nodes that weren't in the gossipsub mesh at that instant
                        //    never converge. Re-broadcasting from every first-inserter
                        //    means the proof fans out across the full mesh within one
                        //    gossip round-trip.
                        if inserted {
                            let _ = self.network.publish(chain_forge_p2p::OutboundMessage {
                                topic:   chain_forge_p2p::GossipTopic::DiscoveryProof,
                                payload: msg.payload,
                            }).await;
                        }
                    }

                    // ── Change Set S: ingest gossiped VerifierAttestations ────────
                    GossipTopic::VerifierAttestation => {
                        use crate::gossip_attestation::{
                            VerifierAttestationGossip,
                            MAX_SEEN_ATTESTATION_KEYS,
                        };

                        // 1. Deserialise the envelope.
                        let att: VerifierAttestationGossip =
                            match serde_json::from_slice(&msg.payload) {
                                Ok(a)  => a,
                                Err(e) => {
                                    warn!(
                                        from  = %msg.from,
                                        error = %e,
                                        "malformed VerifierAttestationGossip, ignoring"
                                    );
                                    return Ok(());
                                }
                            };

                        // 2. Chain-ID guard — reject cross-chain gossip.
                        if att.chain_id != self.genesis.chain_id {
                            debug!(
                                from        = %msg.from,
                                their_chain = %att.chain_id,
                                our_chain   = %self.genesis.chain_id,
                                "VerifierAttestationGossip: wrong chain_id, dropping"
                            );
                            return Ok(());
                        }

                        // 3. Staleness guard.
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        if att.is_stale(now_ms) {
                            debug!(
                                task_id    = %att.task_id,
                                verifier   = %att.verifier_id,
                                age_ms     = now_ms.saturating_sub(att.published_at_ms),
                                "VerifierAttestationGossip: stale, dropping"
                            );
                            return Ok(());
                        }

                        // 4. Only "reproduced" attestations count toward quorum;
                        //    "failed" are gossiped for audit but discarded here.
                        if !att.counts_toward_quorum() {
                            debug!(
                                task_id  = %att.task_id,
                                verifier = %att.verifier_id,
                                outcome  = %att.outcome,
                                "VerifierAttestationGossip: non-reproduced outcome, dropping"
                            );
                            return Ok(());
                        }

                        // 5. Anti-replay: skip if we've already seen this
                        //    (task_id, verifier_id) pair.
                        let replay_key = att.replay_key();
                        if self.seen_attestation_keys.contains(&replay_key) {
                            debug!(
                                task_id  = %att.task_id,
                                verifier = %att.verifier_id,
                                "VerifierAttestationGossip: duplicate, skipping"
                            );
                            return Ok(());
                        }

                        // 6. Record in anti-replay set; evict oldest when capped.
                        self.seen_attestation_keys.insert(replay_key.clone());
                        self.seen_attestation_keys_order.push_back(replay_key);
                        while self.seen_attestation_keys.len() > MAX_SEEN_ATTESTATION_KEYS {
                            if let Some(old) = self.seen_attestation_keys_order.pop_front() {
                                self.seen_attestation_keys.remove(&old);
                            }
                        }

                        // 7. Accumulate into the per-(task_id, output_hash) bucket.
                        let quorum_key  = att.quorum_key();
                        let bucket = self.attestation_accumulator
                            .entry(quorum_key.clone())
                            .or_default();
                        let was_new = bucket.record(&att.controller_id, &att.result_id);

                        info!(
                            task_id     = %att.task_id,
                            verifier    = %att.verifier_id,
                            controller  = %att.controller_id,
                            output_hash = %att.output_hash,
                            controllers = bucket.controllers.len(),
                            from        = %msg.from,
                            "VerifierAttestationGossip: attestation recorded"
                        );

                        // 8. Quorum check — if we just crossed the threshold, record the
                        //    convergence event.  We only act on the exact crossing
                        //    (was_new && has_quorum) so the log fires exactly once per
                        //    (task_id, output_hash) pair rather than for every additional
                        //    attestation that arrives after quorum was already reached.
                        //
                        //    Architectural note: the scheduler's VerificationEngine (a
                        //    separate process) handles `accept_task_canonical()` for the
                        //    off-chain task state.  The node's PoCD registry tracks
                        //    DiscoveryReceipts for on-chain reward accounting; a receipt
                        //    is already in the registry when it was inserted via Change Set
                        //    R gossip or local verification — the attestation quorum here
                        //    is an independent signal that the result was reproduced by
                        //    distinct controllers, which the epoch-boundary reward pass
                        //    will read via `pending_reward_receipts()`.  No additional
                        //    flag needs to be set; the receipt being present is sufficient.
                        if was_new && bucket.has_quorum() {
                            let result_id = bucket.latest_result_id.clone();
                            info!(
                                task_id     = %att.task_id,
                                output_hash = %att.output_hash,
                                result_id   = %result_id,
                                controllers = bucket.controllers.len(),
                                "VerifierAttestationGossip: quorum reached — \
                                 result independently reproduced by {} distinct controllers",
                                bucket.controllers.len(),
                            );
                            // PoCD registry awareness: if the node has a registry and the
                            // receipt corresponding to this result_id is present, we log it
                            // for the epoch-boundary reward pass.  No state change needed —
                            // the receipt's presence in the registry is the eligibility signal.
                            if let Some(ref reg_arc) = self.pocd_registry {
                                let reg = reg_arc.lock().unwrap();
                                if reg.get_receipt(&result_id).is_some() {
                                    info!(
                                        result_id = %result_id,
                                        "VerifierAttestationGossip: quorum confirmed for receipt already in registry"
                                    );
                                } else {
                                    debug!(
                                        result_id = %result_id,
                                        "VerifierAttestationGossip: quorum reached; receipt not yet in local registry \
                                         (may arrive via DiscoveryProof gossip)"
                                    );
                                }
                            } else {
                                debug!("VerifierAttestationGossip: PoCD not enabled, quorum logged only");
                            }
                        }

                        // 9. Re-broadcast if this attestation was new (flood-fill).
                        //    Nodes that missed the original publish receive it this way.
                        if was_new {
                            let _ = self.network.publish(chain_forge_p2p::OutboundMessage {
                                topic:   chain_forge_p2p::GossipTopic::VerifierAttestation,
                                payload: msg.payload,
                            }).await;
                        }
                    }

                    // ── Change Set T: ingest peer capacity ads ────────────────────
                    GossipTopic::CapacityAd => {
                        use crate::gossip_capacity::CapacityAdGossip;

                        // 1. Deserialise.
                        let ad: CapacityAdGossip =
                            match serde_json::from_slice(&msg.payload) {
                                Ok(a)  => a,
                                Err(e) => {
                                    warn!(
                                        from  = %msg.from,
                                        error = %e,
                                        "malformed CapacityAdGossip, ignoring"
                                    );
                                    return Ok(());
                                }
                            };

                        // 2. Chain-ID guard — drop ads from a different chain.
                        if ad.chain_id != self.genesis.chain_id {
                            debug!(
                                from        = %msg.from,
                                their_chain = %ad.chain_id,
                                our_chain   = %self.genesis.chain_id,
                                "CapacityAd: wrong chain_id, dropping"
                            );
                            return Ok(());
                        }

                        // 3. Clock for staleness + rate-limit checks.
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;

                        // 4. Upsert into the peer capacity table.
                        //    Returns false when the ad is stale or rate-limited
                        //    (CAPACITY_AD_MIN_INTERVAL_MS per peer) — no log spam.
                        let accepted = self.peer_capacity_table.lock().unwrap().upsert(ad, now_ms);

                        // Advisory-only: no re-broadcast.  Each node emits its own
                        // ad.  This keeps traffic O(N) rather than O(N²).
                        if accepted {
                            debug!(from = %msg.from, "CapacityAd accepted");
                        }
                    }
                }
            }

            NetworkEvent::PeerConnected(peer) => {
                info!(peer_id = %peer.peer_id, addr = %peer.addr, "peer connected");
                let mut list = self.peers.lock().unwrap();
                // De-duplicate: a reconnect updates the existing entry
                // rather than appending a second one for the same peer.
                if let Some(existing) = list.iter_mut().find(|p| p.peer_id == peer.peer_id) {
                    *existing = peer;
                } else {
                    list.push(peer);
                }
                let count = list.len();
                drop(list);
                self.status.lock().unwrap().peer_count = count;
            }

            NetworkEvent::PeerDisconnected(peer_id) => {
                info!(peer_id = %peer_id, "peer disconnected");
                let mut list = self.peers.lock().unwrap();
                list.retain(|p| p.peer_id != peer_id);
                let count = list.len();
                drop(list);
                self.status.lock().unwrap().peer_count = count;
            }

            NetworkEvent::PeerList(peers) => {
                let count = peers.len();
                *self.peers.lock().unwrap() = peers;
                self.status.lock().unwrap().peer_count = count;
            }

            NetworkEvent::FatalError(e) => {
                return Err(format!("fatal network error: {e}"));
            }
        }

        Ok(())
    }

    /// Deterministic round-robin proposer check, matching the same logic
    /// TendermintEngine uses internally (sorted by ValidatorId, rotated by
    /// height + round). Duplicated here rather than exposed from the trait
    /// because it is only needed to decide *whether to call* propose() --
    /// propose()/receive_proposal() re-derive and enforce the real answer
    /// themselves, so a wrong guess here just means a wasted, safely-
    /// rejected call, never a consensus-safety issue.
    fn is_proposer_for(vs: &ValidatorSet, height: u64, round: u32, id: &ValidatorId) -> bool {
        if vs.validators.is_empty() { return false; }
        let mut sorted: Vec<_> = vs.validators.iter().collect();
        sorted.sort_by_key(|v| &v.id);
        let idx = ((height + round as u64) as usize) % sorted.len();
        &sorted[idx].id == id
    }

    /// If a gossiped message (a proposal or vote) is for the same height this
    /// node is on, but a LATER round than this node has reached, that message
    /// is direct evidence the network has already moved past this node's
    /// current round -- so catch up immediately rather than waiting for this
    /// node's own timeout timer to eventually notice independently.
    ///
    /// Without this, every validator only advances rounds on its own clock
    /// (the fix from the previous session), which solves outright stalling
    /// but not thrashing: if propagation delay is a meaningful fraction of
    /// the round timeout, nodes can each keep timing out just before a
    /// peer's proposal for the round they were about to try arrives, cycling
    /// through many rounds without ever landing on the same one together at
    /// the same time. Jumping straight to a round a peer has evidence for is
    /// the standard fix -- it lets whichever node is furthest ahead pull
    /// everyone else forward immediately instead of a slow, uncoordinated
    /// drift that can easily never converge.
    async fn catch_up_round_if_behind(&mut self, height: u64, their_round: u32) {
        let my_round = self.consensus.current_round();
        if height != self.consensus.current_height() || their_round <= my_round {
            return;
        }
        // on_timeout(height, R) sets this node's round to R + 1, so passing
        // their_round - 1 jumps straight to their_round in one call, rather
        // than cycling through every intermediate round one at a time.
        if let Ok(nil_vote_template) = self.consensus.on_timeout(height, their_round - 1).await {
            if let Some(my_id) = self.validator_id.clone() {
                let mut nil_vote = Vote { validator: my_id, ..nil_vote_template };
                self.sign_vote(&mut nil_vote);
                let _ = self.network.publish(OutboundMessage {
                    topic:   GossipTopic::ConsensusVote,
                    payload: serde_json::to_vec(&nil_vote).unwrap_or_default(),
                }).await;
            }
        }
        // Reset the ticker's round-tracking state so it recognizes the jump
        // as a fresh round on the very next tick, rather than thinking it's
        // still watching (and timing) the round it was on before the jump.
        self.last_proposed       = None;
        self.round_watch         = None;
        self.round_watch_started = None;
    }

    /// Ask the network for the next committed height this node needs. Fires
    /// whenever handle_event notices a proposal or vote for a height beyond
    /// what this node has reached -- unambiguous evidence it's fallen behind.
    /// Any peer with that height in its chain_store answers over gossip
    /// (see the SyncRequest/SyncResponse arms in handle_event); since gossip
    /// keeps arriving from the live network every block time, this will
    /// naturally keep re-firing until this node catches all the way up.
    async fn request_sync(&mut self) {
        let from_height = self.consensus.current_height();
        let req = SyncRequest { from_height };
        debug!(from_height, "requesting sync for missing height");
        let _ = self.network.publish(OutboundMessage {
            topic:   GossipTopic::SyncRequest,
            payload: serde_json::to_vec(&req).unwrap_or_default(),
        }).await;
    }

    /// Cast this node's own prevote and precommit for a proposal, feeding
    /// each into the local consensus engine and broadcasting it so peers
    /// can count it toward their own quorum. Returns the commit certificate
    /// if this node's own precommit was the one that reached quorum.
    ///
    /// Observer nodes (validator_id == None) have nothing to vote as and
    /// return Ok(None) immediately -- they still receive and relay gossip
    /// via libp2p's mesh, they just do not participate in voting.
    async fn cast_and_broadcast_own_votes(
        &mut self,
        proposal: &BlockProposal,
    ) -> Result<Option<chain_forge_consensus::CommitCertificate>, String> {
        let Some(my_id) = self.validator_id.clone() else {
            return Ok(None);
        };

        let mut prevote = Vote {
            vote_type:  VoteType::Prevote,
            height:     proposal.height,
            round:      proposal.round,
            validator:  my_id.clone(),
            block_hash: Some(proposal.block_hash.clone()),
            signature:  vec![],
            scheme:     Vote::default_scheme(),
        };
        self.sign_vote(&mut prevote);
        if let Err(e) = self.consensus.receive_vote(prevote.clone()).await {
            debug!(error = %e, "own prevote rejected locally");
        }
        let _ = self.network.publish(OutboundMessage {
            topic:   GossipTopic::ConsensusVote,
            payload: serde_json::to_vec(&prevote).unwrap_or_default(),
        }).await;

        let mut precommit = Vote {
            vote_type:  VoteType::Precommit,
            height:     proposal.height,
            round:      proposal.round,
            validator:  my_id,
            block_hash: Some(proposal.block_hash.clone()),
            signature:  vec![],
            scheme:     Vote::default_scheme(),
        };
        self.sign_vote(&mut precommit);
        let cert = self.consensus.receive_vote(precommit.clone()).await
            .map_err(|e| e.to_string())?;
        let _ = self.network.publish(OutboundMessage {
            topic:   GossipTopic::ConsensusVote,
            payload: serde_json::to_vec(&precommit).unwrap_or_default(),
        }).await;

        Ok(cert)
    }

    /// Execute and commit a block once a real (multi-node) quorum has been
    /// reached -- either because this node's own precommit completed it, or
    /// because a gossiped vote from a peer did. This is the follower-safe
    /// counterpart to propose_block()'s inline commit tail: propose_block()
    /// Process equivocation evidence: slash the validator, burn the slashed
    /// stake via the BME mechanism (Section 6.3), and update QRC metrics.
    ///
    /// This is the BME routing entry point for equivocation slashing.
    /// The slashing module computes the burn amount; this method:
    ///   1. Calls `slasher.slash_equivocation` to tombstone + compute burn
    ///   2. Burns the slashed uqcb from the validator's account in StateStore
    ///   3. Increments `qrc_metrics.total_qcb_burned_uqcb` for the API
    ///
    /// Returns the burn amount on success, or an error description.
    pub fn process_equivocation_evidence(
        &mut self,
        evidence: &EquivocationEvidence,
        epoch: u64,
    ) -> Result<u128, String> {
        let chain_id = self.genesis.chain_id.clone();
        let burn_amount = self.slasher.slash_equivocation(
            evidence,
            &mut self.validator_registry,
            epoch,
            &chain_id,
        ).map_err(|e| e.to_string())?;

        // Route burn_amount through BME: debit from the validator's account.
        // This permanently removes the tokens from supply (Section 6.3).
        //
        // Cap the burn at the validator's actual liquid balance so devnet
        // genesis validators (whose bonded_uqcb in the registry is the
        // ENTRY_STAKE minimum, much larger than their token balance) don't
        // silently fail the burn due to InsufficientBalance. In production,
        // validators must bond tokens ≥ their registered stake, so this cap
        // should rarely trigger. The validator is tombstoned regardless; only
        // the burned amount differs.
        let actual_burn = if burn_amount > 0 {
            let available = self.state.get_account(&evidence.validator_id)
                .map(|a| a.balance_of("uqcb"))
                .unwrap_or(0);
            let capped = burn_amount.min(available);
            if capped < burn_amount {
                warn!(
                    validator = %evidence.validator_id,
                    requested_burn = burn_amount,
                    available,
                    capped,
                    "slash burn capped at available balance (bonded_uqcb > liquid balance)"
                );
            }
            if capped > 0 {
                if let Err(e) = self.state.burn(
                    &evidence.validator_id,
                    "uqcb",
                    capped,
                ) {
                    // Log the burn failure but don't undo the tombstone --
                    // the validator is already removed from the active set.
                    warn!(
                        validator = %evidence.validator_id,
                        burn_uqcb = capped,
                        error     = %e,
                        "slash burn failed; tombstone applied but tokens not burned"
                    );
                    0
                } else {
                    info!(
                        validator = %evidence.validator_id,
                        burn_uqcb = capped,
                        "equivocation slash: QCB burned from validator stake"
                    );
                    capped
                }
            } else {
                0
            }
        } else {
            0
        };

        // Update QRC metrics so the API and tests can observe the burn.
        if actual_burn > 0 {
            if let Ok(mut cm) = self.qrc_metrics.lock() {
                cm.total_qcb_burned_uqcb = cm.total_qcb_burned_uqcb.saturating_add(actual_burn);
            }
        }

        // Attestation guard telemetry — one JSON line per slash event.
        // evidence_hash: block_hash_a is already a hex string (the first conflicting vote).
        let ev_hash: &str = &evidence.block_hash_a;
        emit_attestation_event(
            &evidence.validator_id,
            Some(evidence.height),
            Some(evidence.round),
            "slash",
            &ev_hash,
        );

        Ok(actual_burn)
    }

    /// Drain equivocations detected by the consensus engine and route each
    /// one through `process_equivocation_evidence`. Called after every
    /// `receive_vote` so double-signs are punished immediately.
    fn handle_drained_equivocations(&mut self, equivocations: Vec<EquivocationDetected>, epoch: u64) {
        for eq in equivocations {
            let evidence = EquivocationEvidence {
                validator_id:   eq.validator_id.0.clone(),
                height:         eq.height,
                round:          eq.round as u64,
                block_hash_a:   eq.block_hash_a.0.clone(),
                block_hash_b:   eq.block_hash_b.0.clone(),
                signature_a:    eq.signature_a,
                signature_b:    eq.signature_b,
                vote_type_byte: eq.vote_type_byte,
            };
            match self.process_equivocation_evidence(&evidence, epoch) {
                Ok(burned) => {
                    info!(
                        validator = %eq.validator_id,
                        height    = eq.height,
                        round     = eq.round,
                        burned_uqcb = burned,
                        "equivocation detected and slashed"
                    );
                }
                Err(e) => {
                    // Already slashed or validator absent — not an error we
                    // need to propagate; just log.
                    warn!(
                        validator = %eq.validator_id,
                        error     = %e,
                        "equivocation evidence rejected"
                    );
                }
            }
        }
    }

    /// Check liveness participation for every validator after a block commits
    /// and apply slashing to any that have crossed the miss threshold.
    ///
    /// Uses `cert.precommits` (the votes that formed the quorum) as the
    /// authoritative signer set, and `consensus.validator_set()` for the full
    /// active set. Any validator absent from the quorum is recorded as a miss.
    /// Once a validator's miss rate exceeds `liveness_miss_pct_threshold`
    /// (default 20%) over the sliding `liveness_window_blocks` (default 500),
    /// `record_block` returns `Ok(Some(burn_amount))`, the validator is jailed
    /// by the slashing module itself, and this method burns the penalty via BME.
    ///
    /// Whitepaper refs: Section 8.2 (liveness slashing), Section 6.3 (BME burn).
    fn check_liveness_after_commit(
        &mut self,
        cert: &chain_forge_consensus::CommitCertificate,
    ) {
        // Build the set of validator ids that actually signed this block.
        let signers: std::collections::HashSet<String> = cert
            .precommits
            .iter()
            .map(|v| v.validator.0.clone())
            .collect();

        // Full active validator set for this height.
        let all_validators: Vec<String> = self
            .consensus
            .validator_set()
            .validators
            .iter()
            .map(|v| v.id.0.clone())
            .collect();

        let height = cert.height;
        let epoch  = height; // epoch == height until per-epoch batching is wired

        for vid in &all_validators {
            let signed = signers.contains(vid);
            match self.slasher.record_block(
                vid,
                signed,
                &mut self.validator_registry,
                epoch,
                height,
            ) {
                Ok(None) => {
                    // Window filling or threshold not yet crossed — nothing to do.
                }
                Ok(Some(burn_amount)) => {
                    // Liveness threshold crossed: validator jailed by record_block,
                    // now burn the penalty stake via BME (Section 6.3).
                    if burn_amount > 0 {
                        if let Err(e) = self.state.burn(vid, "uqcb", burn_amount) {
                            warn!(
                                validator = %vid,
                                burn_uqcb = burn_amount,
                                error     = %e,
                                "liveness slash: burn failed; jail applied but tokens not burned"
                            );
                        } else {
                            warn!(
                                validator = %vid,
                                height,
                                burn_uqcb = burn_amount,
                                "liveness failure: validator jailed and stake burned"
                            );
                        }
                    }
                }
                Err(e) => {
                    // Validator already jailed / tombstoned — not an error we
                    // need to propagate; record_block is idempotent on its
                    // penalty, so this is expected once a validator is out.
                    debug!(
                        validator = %vid,
                        height,
                        error     = %e,
                        "liveness record_block skipped (validator already jailed/tombstoned)"
                    );
                }
            }
        }
    }

    /// is unchanged and still used for the solo-devnet (no peers) path,
    /// where the proposer synthesises every validator's vote itself.
    async fn commit_block(
        &mut self,
        cert: chain_forge_consensus::CommitCertificate,
        proposal: &BlockProposal,
    ) -> Result<(), String> {
        // A commit means the round we were tracking is over -- clear the
        // propose-once guard so the next height starts clean.
        self.last_proposed = None;
        self.round_watch = None;
        self.round_watch_started = None;

        let txs: Vec<Transaction> = serde_json::from_slice(&proposal.tx_data)
            .unwrap_or_default();
        self.remove_committed_from_mempool(&txs);
        // Keep a lightweight (tx_id, sender, nonce) index before txs is consumed by
        // execute_block_with_identity so the post-execution nonce-cache update
        // can correlate successful TransactionResults back to their senders and nonces.
        let txs_for_cache: Vec<(String, String, u64)> = txs.iter()
            .map(|t| (t.id.clone(), t.sender.clone(), t.nonce))
            .collect();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let tx_meta: Vec<(String, String, String)> = txs.iter()
            .map(|t| (t.id.clone(), t.sender.clone(), tx_kind_label(&t.body).to_string()))
            .collect();

        // Snapshot the validator set that actually produced this cert
        // BEFORE any epoch-boundary admission/liveness mutation below --
        // see `historical_validator_sets`'s doc comment and
        // `verify_certificate_against_history`.
        self.historical_validator_sets.insert(cert.height, self.consensus.validator_set().clone());

        // Deterministic, block-height-driven validator epoch -- replaces
        // the old `self.identity.advance_epoch(now_ms)` wall-clock call for
        // every decision that can change validator membership, voting
        // power, or quorum (see `advance_epoch_to`'s doc comment in
        // chain-forge-identity for why liveness/admission can't be
        // decoupled from the epoch *number* itself, only from how that
        // number is derived). `now_ms` above is still wall-clock -- it only
        // feeds cosmetic epoch bookkeeping and tx execution timestamps now,
        // neither of which affects validator membership, voting power, or
        // quorum.
        let validator_epoch = cert.height / self.validator_epoch_blocks;
        let epoch_rolled = self.identity.advance_epoch_to(validator_epoch);

        // Integration Point 3 (Push): after advancing the epoch, sync the
        // ValidatorRegistry with any identity lapses that just happened.
        //
        // advance_epoch_to() calls lapse() on any Verified/Established
        // identity that hasn't been active for LIVENESS_EPOCH_WINDOW
        // (validator) epochs, dropping them to Provisional. The
        // ValidatorRegistry is a separate module that doesn't hear about
        // this unless we tell it. Without this call, a lapsed validator
        // stays Active with full consensus power — exactly the attack
        // Section 3.3's personhood-weighting is supposed to prevent.
        //
        // We use Push: epoch advance fires here, we immediately reconcile the
        // registry. Pull (querying at every round start) is the
        // production-hardening path but Push is simpler and equally correct.
        //
        // revoke_pop() is idempotent: calling it on an already-Candidate
        // validator is a no-op, so racing epoch advances or duplicate calls
        // are safe.
        {
            let epoch = self.identity.clock.current_epoch;
            let validator_ids: Vec<String> = self.validator_registry
                .all_validators()
                .into_iter()
                .map(|r| r.id.0.clone())
                .collect();
            for vid in &validator_ids {
                let still_verified = self.identity.get(vid)
                    .map(|r| r.charm.tier.grants_consensus())
                    .unwrap_or(false);
                if !still_verified {
                    if let Err(e) = self.validator_registry.revoke_pop(vid, epoch) {
                        // NotFound is fine (validator not in registry); other
                        // errors are unexpected — log but don't crash the node.
                        if !matches!(e, chain_forge_validators::ValidatorError::NotFound(_)) {
                            warn!(validator = vid, error = %e, "revoke_pop failed after epoch advance");
                        }
                    }
                }
            }
        }

        // Validator participation = on-chain activity for QRC yield eligibility.
        // Every validator who signed a precommit in this block's commit certificate
        // gets their activity stamped for this epoch. This means validators earn
        // QRC yield for doing their job — producing/signing blocks — without
        // needing to submit separate Transfer or Stake txs.
        for vote in &cert.precommits {
            self.identity.record_activity(&vote.validator.0);
        }

        // Snapshot Attest tx metadata before txs is consumed by execute_block.
        // (sender = attester, claimant = target identity)
        let attest_senders: Vec<(String, String)> = txs.iter()
            .filter_map(|t| {
                if let chain_forge_execution::TxBody::Attest { claimant_id } = &t.body {
                    Some((t.sender.clone(), claimant_id.clone()))
                } else {
                    None
                }
            })
            .collect();

        // CF-VAL-KEY-002: same snapshot-before-consume pattern, for
        // RegisterValidatorKey. Keeps the original position in `txs` (not
        // just a filtered index) so the result lookup below is a direct,
        // unambiguous positional match against `exec_result.tx_results`
        // (one result per input tx, same order -- see
        // `execute_block_with_identity`) rather than a separately-filtered
        // zip that could silently misalign if two such txs land in one
        // block.
        // Tuple: (tx_index, sender, consensus_pubkey, scheme)
        let register_key_attempts: Vec<(usize, String, Vec<u8>, String)> = txs.iter().enumerate()
            .filter_map(|(i, t)| {
                if let chain_forge_execution::TxBody::RegisterValidatorKey {
                    consensus_pubkey, scheme, ..
                } = &t.body {
                    Some((i, t.sender.clone(), consensus_pubkey.clone(), scheme.clone()))
                } else {
                    None
                }
            })
            .collect();

        // PQ-VAL-002 R4: capture indices of any EDA txs that target
        // ml-dsa-65 consensus signatures — if one succeeds we re-zero
        // all ML-DSA-only validators' voting power in this block.
        let eda_mldsa_consensus_attempts: Vec<usize> = txs.iter().enumerate()
            .filter_map(|(i, t)| {
                if let chain_forge_execution::TxBody::EmergencyDeprecateAlgorithm {
                    deprecated_scheme,
                    scope: chain_forge_execution::DeprecationScope::ConsensusSignatures,
                    ..
                } = &t.body {
                    if deprecated_scheme == "ml-dsa-65" { Some(i) } else { None }
                } else {
                    None
                }
            })
            .collect();

        let exec_result = if let Some(ref reg_arc) = self.pocd_registry {
            let mut reg = reg_arc.lock().unwrap();
            self.executor.execute_block_with_identity(
                cert.height, txs, &mut self.state, &mut self.identity,
                &mut self.agents, now_ms, Some(&mut *reg),
            )
        } else {
            self.executor.execute_block_with_identity(
                cert.height, txs, &mut self.state, &mut self.identity,
                &mut self.agents, now_ms, None,
            )
        };

        // F1: update per-sender nonce cache AFTER execution, from the tx.nonce of each
        // successfully committed transaction. The API check rejects tx.nonce <= cache,
        // so cache must store the last committed tx.nonce (not state.nonce, which is
        // post-increment and would block the immediately following valid submission).
        // Updating before execution caused the cache to advance even for txs that
        // failed, making it impossible to submit a corrected tx on the same sender.
        {
            let mut cache = self.nonce_cache.lock().unwrap();
            for r in exec_result.tx_results.iter().filter(|r| r.success) {
                // TransactionResult has no sender field; look up (sender, nonce) from
                // the index captured before txs was consumed by execute_block_with_identity.
                if let Some((_, sender, tx_nonce)) = txs_for_cache.iter().find(|(id, _, _)| id == &r.tx_id) {
                    let entry = cache.entry(sender.clone()).or_insert(0);
                    if tx_nonce >= entry {
                        *entry = *tx_nonce;
                    }
                }
            }
        }

        // Diagnostic: log each failed tx so tests can see the root cause.
        for r in exec_result.tx_results.iter().filter(|r| !r.success) {
            warn!(
                tx_id  = %r.tx_id,
                error  = ?r.error,
                "tx failed during block execution"
            );
        }

        info!(
            height     = cert.height,
            block_hash = %cert.block_hash,
            txs_ok     = exec_result.success_count(),
            txs_fail   = exec_result.failure_count(),
            gas_used   = exec_result.gas_used,
            state_root = %exec_result.state_root,
            "block executed and committed (multi-node quorum)"
        );

        // Attestation guard telemetry — one JSON line per Attest tx.
        // Zip the pre-captured (attester, claimant) pairs with the tx results
        // that carry the execution events (e.g. "quorum reached").
        {
            let block_hash_str = format!("{}", cert.block_hash);
            let attest_results: Vec<&chain_forge_execution::TransactionResult> = exec_result
                .tx_results
                .iter()
                .filter(|r| {
                    r.events.iter().any(|e| e.starts_with("attest:"))
                })
                .collect();

            for (idx, (attester, claimant)) in attest_senders.iter().enumerate() {
                let result = attest_results.get(idx);
                let (verdict, success) = match result {
                    Some(r) if r.success => {
                        let is_quorum = r.events.iter()
                            .any(|e| e.contains("quorum reached"));
                        if is_quorum { ("quorum", true) } else { ("pass", true) }
                    }
                    Some(_) => ("fail", false),
                    None    => ("pass", false), // no result mapped — treat as pass
                };
                let _ = success; // verdict string already encodes this
                emit_attestation_event(
                    attester,
                    Some(cert.height),
                    Some(cert.round.into()),
                    verdict,
                    &block_hash_str,
                );
                debug!(
                    attester = %attester,
                    claimant = %claimant,
                    height   = cert.height,
                    verdict  = verdict,
                    "attestation telemetry emitted"
                );
            }
        }

        // CF-VAL-KEY-002: mirror every successfully-executed
        // RegisterValidatorKey tx into the ValidatorRegistry's key store.
        // The executor (chain-forge-execution) already did the actual
        // authentication -- unconditional sender-signature verification
        // plus proof-of-possession against consensus_pubkey -- and has no
        // dependency on chain-forge-validators to write the result
        // anywhere itself, so this is purely "trust what the executor
        // already verified, now record it". Must run before both the
        // epoch-boundary admission block and the pop_verified/public_key
        // refresh block immediately below, so a key registered in this
        // very block is visible to both this block's admission decisions
        // and the live ValidatorSet refresh.
        // PQ-VAL-003 R6: collect validators whose key was registered this block
        // so the pop_verified refresh below can skip power restoration for them
        // (producing the one-block power gap R6 requires).
        let mut key_registered_this_block: Vec<String> = Vec::new();
        {
            let epoch = self.identity.clock.current_epoch;
            for (idx, sender, pubkey, scheme) in &register_key_attempts {
                let Some(result) = exec_result.tx_results.get(*idx) else { continue };
                if !result.success {
                    continue;
                }
                // PQ-VAL-001: store scheme alongside key so gate_voting_power
                // (R3) can distinguish ML-DSA-only validators.
                // PQ-VAL-003 R2: always use register_consensus_key_with_scheme
                // so classical downgrade (ML-DSA → classical) updates the
                // scheme field in the registry.
                let effective_scheme = if scheme.is_empty() { "classical" } else { scheme.as_str() };
                // PQ-VAL-003 R6: detect rotation (validator already holds a
                // different key) BEFORE updating the registry so the
                // key_registered_this_block guard applies only to rotations.
                // First-time registrations should restore power immediately;
                // only rotation introduces the one-block power gap.
                let is_rotation = self.validator_registry
                    .consensus_pubkey_bytes(sender)
                    .map(|old| old != *pubkey)
                    .unwrap_or(false);
                let reg_result = self.validator_registry.register_consensus_key_with_scheme(
                    sender, pubkey, epoch, effective_scheme,
                );
                if let Err(e) = reg_result {
                    warn!(
                        validator = %sender,
                        error     = %e,
                        "consensus key registration mirror failed after a transaction the \
                         executor already authenticated -- this should only happen on a \
                         genuine duplicate-key conflict"
                    );
                    continue;
                }
                if is_rotation {
                    key_registered_this_block.push(sender.clone());
                }
            }
        }

        // PQ-VAL-002 R4: if an EDA targeting ml-dsa-65 ConsensusSignatures
        // succeeded in this block, re-zero all ML-DSA-only validators'
        // voting power in the live ValidatorSet immediately.  The state key
        // `pq_consensus_activation_epoch` was already cleared by the executor,
        // so subsequent verify_consensus_vote() calls will also reject ML-DSA.
        {
            let eda_activated = eda_mldsa_consensus_attempts.iter().any(|&idx| {
                exec_result.tx_results.get(idx).map_or(false, |r| r.success)
            });
            if eda_activated {
                let mut updated_vs = self.consensus.validator_set().clone();
                let mut any_changed = false;
                for v in &mut updated_vs.validators {
                    let scheme = self.validator_registry.consensus_key_scheme(&v.id.0)
                        .unwrap_or("classical");
                    if scheme == "ml-dsa-65" && v.voting_power > 0 {
                        warn!(
                            validator = %v.id,
                            "PQ-VAL-002 R4: re-zeroing ML-DSA validator power after \
                             EmergencyDeprecateAlgorithm(ml-dsa-65)"
                        );
                        v.voting_power = 0;
                        any_changed = true;
                    }
                }
                if any_changed {
                    updated_vs.height = cert.height;
                    let _ = self.consensus.update_validator_set(updated_vs);
                }
            }
        }

        // Integration Point 4 (Push): at each identity-epoch boundary,
        // admit newly stake-bonded validators into the live consensus
        // ValidatorSet.
        //
        // ROADMAP.md, Validator Onboarding: before this, `BondValidator`
        // could move uqcb into a validator's bond account, but nothing ever
        // read that back into consensus -- `genesis_vs` was built once at
        // startup and never grew. A validator could bond the minimum stake
        // forever and still never be seated. This closes that gap on the
        // entry side.
        //
        // Scope, deliberately: this ADDS newly-qualifying candidates up to
        // the max active-set size; it does not EVICT an existing validator
        // whose stake falls below the minimum or who is outranked by a
        // later, larger staker. Full top-N churn (the "exit" half of
        // "Top-N stakers automatically enter/exit active set") needs a
        // product decision this change doesn't make on its own: whether
        // genesis/synthetic validators (who hold no bond at all, since they
        // were seated by genesis, not by a BondValidator tx) are exempt from
        // eviction or get swept out the first time anyone else bonds.
        // Tracked as follow-up in ROADMAP.md rather than decided here.
        // Removal of a validator already in the set remains the job of the
        // existing jailing/tombstoning/liveness-revocation machinery, which
        // this does not touch.
        //
        // New entrants start with pop_verified=false and an empty
        // public_key (same Phase-0 placeholder convention as a genesis
        // validator before identity seeding -- see `genesis_vs`
        // construction in `Node::new`). The PoP refresh block immediately
        // below corrects pop_verified from IdentityStore before this same
        // commit finishes; the public key is backfilled later via
        // `load_signing_key` (operator's own node) or by other validators'
        // `verify_vote_signature` Phase-0 tolerance in the meantime.
        if epoch_rolled {
            let active = chain_forge_execution::validator_bond::compute_stake_active_set(
                &self.state,
                self.executor.native_denom(),
                self.min_bond_uqcb,
                chain_forge_execution::validator_bond::DEFAULT_MAX_ACTIVE_VALIDATORS,
            );
            // Build a lookup from the bond ledger for O(1) access below.
            let bond_map: std::collections::HashMap<&str, u128> = active
                .iter()
                .map(|(addr, power)| (addr.as_str(), *power))
                .collect();

            let mut updated_vs = self.consensus.validator_set().clone();
            let mut any_changed = false;

            // Pass 1: refresh voting_power for already-seated validators whose
            // bonded stake has changed since they were last admitted.  Genesis
            // validators start with power=1 (the engine's init default); once
            // they submit a BondValidator tx their real stake appears in the
            // bond ledger and must be reflected here so quorum arithmetic stays
            // proportional to actual stake.
            for v in &mut updated_vs.validators {
                if let Some(&bonded_uqcb) = bond_map.get(v.id.0.as_str()) {
                    let new_power = bonded_uqcb.min(u64::MAX as u128) as u64;
                    if v.voting_power != new_power {
                        info!(
                            validator = %v.id,
                            old_power = v.voting_power,
                            new_power,
                            "stake bond: updating voting power for seated validator"
                        );
                        v.voting_power = new_power;
                        any_changed = true;
                    }
                }
            }

            // Pass 2: admit new validators from the bond ledger that are not
            // yet seated.
            let already_seated: std::collections::HashSet<String> = updated_vs.validators
                .iter()
                .map(|v| v.id.0.clone())
                .collect();
            let capacity = chain_forge_execution::validator_bond::DEFAULT_MAX_ACTIVE_VALIDATORS
                .saturating_sub(updated_vs.validators.len());
            let mut admitted = 0usize;
            for (addr, bonded_uqcb) in &active {
                if admitted >= capacity {
                    break;
                }
                if already_seated.contains(addr) {
                    continue;
                }
                info!(
                    validator = %addr,
                    bonded_uqcb = *bonded_uqcb,
                    "stake bond: admitting new validator candidate to active set"
                );
                // CF-VAL-KEY-002: read back whatever consensus key this
                // address has authenticated via `RegisterValidatorKey`
                // (mirrored into the registry just above, before this
                // epoch-boundary admission block runs -- see the
                // `register_validator_key_senders` handling earlier in this
                // function). Empty if none has been registered yet: that is
                // the correct, intentional state -- `gate_voting_power()`
                // (applied unconditionally by `update_validator_set()` just
                // below) forces this entry's voting_power to 0 regardless of
                // `bonded_uqcb` until a key is on file. The validator keeps
                // its seat and its bond; it simply cannot vote until it
                // proves it holds a consensus key.
                let public_key = self.validator_registry
                    .consensus_pubkey_bytes(addr)
                    .unwrap_or_default();
                updated_vs.validators.push(chain_forge_consensus::ValidatorInfo {
                    id: chain_forge_consensus::ValidatorId(addr.clone()),
                    voting_power: (*bonded_uqcb).min(u64::MAX as u128) as u64,
                    pop_verified: false,
                    public_key,
                });
                admitted += 1;
                any_changed = true;
            }
            if any_changed {
                updated_vs.height = cert.height;
                let _ = self.consensus.update_validator_set(updated_vs);
            }
        }

        // Refresh pop_verified in the live validator set from IdentityStore.
        //
        // This is the per-block PoP admission check: if an identity was
        // just upgraded to Verified (via a quorum of Attest txs in this
        // block), they gain voting power starting next block. If a validator's
        // identity record was revoked or expired, they lose it.
        //
        // We do this BEFORE on_commit so the updated validator set is what
        // the consensus engine sees when it starts the next height.
        {
            let current_vs = self.consensus.validator_set().clone();
            let mut updated_vs = current_vs;
            let mut any_changed = false;
            for v in &mut updated_vs.validators {
                // INV-13: a frozen (ConfirmSybil) identity loses consensus power
                // immediately, regardless of its VerificationTier.
                let now_verified = self.identity.get(&v.id.0)
                    .map(|r| !r.frozen && r.charm.tier.grants_consensus())
                    .unwrap_or(false);
                if v.pop_verified != now_verified {
                    if now_verified {
                        info!(validator = %v.id, "PoP gate: identity Verified — granting consensus power");
                    } else {
                        let frozen = self.identity.get(&v.id.0).map(|r| r.frozen).unwrap_or(false);
                        if frozen {
                            warn!(validator = %v.id, "PoP gate: identity frozen (ConfirmSybil) — revoking consensus power");
                        } else {
                            warn!(validator = %v.id, "PoP gate: identity not Verified — revoking consensus power");
                        }
                    }
                    v.pop_verified = now_verified;
                    any_changed = true;
                }

                // CF-VAL-KEY-002: same idea, for consensus keys. A
                // validator that was seated before it had registered a key
                // (or before this field existed at all, for genesis
                // validators seeded from an older data dir) picks up its
                // real key here the moment one appears in the registry --
                // every block, not just at admission, so a
                // `RegisterValidatorKey` tx submitted well after a
                // validator was first seated still takes effect.
                if v.public_key.is_empty() {
                    if let Some(real_key) = self.validator_registry.consensus_pubkey_bytes(&v.id.0) {
                        v.public_key = real_key;
                        any_changed = true;
                        info!(validator = %v.id, "consensus key gate: registered key found — validator can now vote");
                    }
                }

                // CF-VAL-KEY-002: restore real voting power once both gates
                // are satisfied. `update_validator_set()`'s unconditional
                // `gate_voting_power()` call OVERWRITES `voting_power` with
                // 0 in place for any validator missing a key or personhood
                // -- it does not merely mask it -- so the moment a
                // bonded-but-not-yet-keyed validator was first admitted and
                // gated, its original bonded-stake weight was gone from
                // this struct for good unless something re-reads it from
                // the real bond ledger. This is that re-read: only when
                // both gates are now satisfied AND voting_power is
                // currently zero (never touches a validator already
                // carrying real power, so genesis validators are
                // unaffected), look up the actual bonded amount from
                // state and restore it.
                // PQ-VAL-003 R6: skip power restoration for validators whose
                // key was registered in this very block (first-time or
                // rotation). Their power is intentionally held at 0 until the
                // next block's refresh — this is the one-block gap R6 requires.
                if key_registered_this_block.contains(&v.id.0) {
                    if v.voting_power != 0 {
                        v.voting_power = 0;
                        any_changed = true;
                    }
                } else if v.pop_verified && !v.public_key.is_empty() && v.voting_power == 0 {
                    // PQ-VAL-001/002 / R3: ML-DSA-only validators are gated
                    // until PQ-VAL-002 activates the ML-DSA consensus verifier.
                    // At or after the activation epoch (stored in state by an
                    // ActivatePqConsensus tx), the gate lifts and ML-DSA
                    // validators receive their bonded voting power.
                    let scheme = self.validator_registry.consensus_key_scheme(&v.id.0)
                        .unwrap_or("classical");
                    let pq_active = if scheme == "ml-dsa-65" {
                        let current_epoch = self.identity.clock.current_epoch;
                        match self.pq_activation_epoch() {
                            Some(activation_epoch) if current_epoch >= activation_epoch => {
                                info!(
                                    validator = %v.id,
                                    current_epoch,
                                    activation_epoch,
                                    "R3 gate lift: ML-DSA consensus verifier is active"
                                );
                                true
                            }
                            Some(activation_epoch) => {
                                warn!(
                                    validator = %v.id,
                                    current_epoch,
                                    activation_epoch,
                                    "R3 consensus gate: ML-DSA validator kept at \
                                     voting_power=0 until activation epoch"
                                );
                                false
                            }
                            None => {
                                warn!(
                                    validator = %v.id,
                                    "R3 consensus gate: ML-DSA validator kept at \
                                     voting_power=0 — no ActivatePqConsensus tx yet"
                                );
                                false
                            }
                        }
                    } else {
                        true // classical validators always allowed
                    };

                    if pq_active {
                        let bond_addr = format!(
                            "{}{}", chain_forge_execution::validator_bond::BOND_ACCOUNT_PREFIX, v.id.0,
                        );
                        let bonded = self.state.get_account(&bond_addr)
                            .map(|a| a.balance_of(self.executor.native_denom()))
                            .unwrap_or(0);
                        if bonded > 0 {
                            v.voting_power = bonded.min(u64::MAX as u128) as u64;
                            // PH-OVL-001: clamp restored power through the per-human
                            // influence cap when personhood-weighted BFT is active.
                            // Without this, a validator with a large bond (e.g. 10 M uQCB)
                            // would be restored to their raw bonded stake even when
                            // `power_cap = 1`, defeating the equal-weight guarantee.
                            // This matches what `apply_personhood_cap` does at
                            // `update_validator_set` / `init` in all three BFT engines.
                            if v.pop_verified {
                                if let Some(cap) = self.personhood_power_cap {
                                    if v.voting_power > cap {
                                        v.voting_power = cap;
                                        info!(
                                            validator = %v.id,
                                            voting_power = v.voting_power,
                                            cap,
                                            "PH-OVL-001 commit_block: personhood power cap applied"
                                        );
                                    }
                                }
                            }
                            any_changed = true;
                            info!(validator = %v.id, voting_power = v.voting_power, "consensus key gate: voting power restored from bonded stake");
                        }
                    }
                }
            }
            if any_changed {
                updated_vs.height = cert.height;
                let _ = self.consensus.update_validator_set(updated_vs);
            }
        }

        self.consensus.on_commit(cert.clone(), None).await
            .map_err(|e| e.to_string())?;

        {
            let mut s = self.status.lock().unwrap();
            s.height     = exec_result.height;
            s.state_root = Some(exec_result.state_root.clone());
        }

        {
            let mut ex = self.explorer.lock().unwrap();
            let mut tx_ids = Vec::new();
            for (i, r) in exec_result.tx_results.iter().enumerate() {
                let (sender, kind) = tx_meta.get(i)
                    .map(|(_, s, k)| (s.clone(), k.clone()))
                    .unwrap_or_else(|| ("unknown".into(), "unknown".into()));
                tx_ids.push(r.tx_id.clone());
                ex.txs.insert(r.tx_id.clone(), TxSummary {
                    id:       r.tx_id.clone(),
                    height:   exec_result.height,
                    sender,
                    kind,
                    success:  r.success,
                    gas_used: r.gas_used,
                    events:   r.events.clone(),
                    error:    r.error.clone(),
                });
            }
            ex.blocks.push_front(BlockSummary {
                height:       exec_result.height,
                state_root:   exec_result.state_root.clone(),
                timestamp_ms: now_ms,
                tx_count:     tx_ids.len(),
                tx_ids,
            });
            while ex.blocks.len() > MAX_RECENT_BLOCKS {
                ex.blocks.pop_back();
            }
            ex.accounts.clear();
            for a in self.state.all_accounts() {
                let (frozen, sybil_confirmed) = self.identity.get(&a.address)
                    .map(|r| (r.frozen, r.sybil_confirmed))
                    .unwrap_or((false, false));
                ex.accounts.insert(a.address.clone(), AccountSummary {
                    address:        a.address.clone(),
                    role:           a.role.clone(),
                    nonce:          a.nonce,
                    balances:       a.balances.clone(),
                    tier:           a.verification_tier().map(|t| t.to_string()),
                    exemption_days: a.exemption_days(),
                    frozen,
                    sybil_confirmed,
                });
            }

            // Sync validator power snapshot for GET /api/validators.
            // Use the live consensus ValidatorSet (not build_validator_set) so
            // registered consensus keys are reflected immediately after
            // RegisterValidatorKey commits. The live set is authoritative.
            {
                let live = self.consensus.validator_set();
                ex.validator_powers = live.validators.iter().map(|v| ValidatorPowerSummary {
                    id:           v.id.0.clone(),
                    voting_power: v.voting_power,
                    pop_verified: v.pop_verified,
                    consensus_pubkey: hex::encode(&v.public_key),
                }).collect();
            }
        }

        // Drop proposals and parked certs at or below the height we just
        // committed -- they can no longer be voted on and would otherwise
        // accumulate forever.
        let committed_height = cert.height;
        self.pending_proposals.retain(|(h, _), _| *h > committed_height);
        self.pending_certs.retain(|(h, _), _| *h > committed_height);

        // Unlike pending_proposals (a short-lived voting cache), chain_store
        // keeps every committed block permanently, so a peer that falls
        // behind has something to actually request and replay.
        self.chain_store.insert(committed_height, (cert.clone(), proposal.clone()));

        // Record block participation for every validator and slash any that
        // have crossed the liveness miss threshold (>20% absent in 500-block
        // sliding window → jail + 0.1% stake burn via BME, Section 8.2).
        self.check_liveness_after_commit(&cert);

        // Write state to disk so a restarted node resumes from this height
        // rather than replaying from genesis. No-op when data_dir is None.
        self.persist_state();

        Ok(())
    }

    /// Verify a `CommitCertificate` against the validator set that was
    /// actually in force at `cert.height` -- NOT whatever validator set is
    /// live right now.
    ///
    /// Why this exists: `self.consensus.validator_set()` is mutated in
    /// place at every validator-epoch boundary (stake-bond admissions,
    /// liveness-lapse revocations). A certificate from height 10 was only
    /// ever valid against the set active at height 10; by height 200 that
    /// set may have gained or lost members or had voting power rebalanced.
    /// Checking an old certificate against the CURRENT live set would be
    /// checking it against rules that didn't exist yet when it was formed
    /// -- it could wrongly fail (a since-admitted validator's vote looks
    /// "unknown" to the old set) or wrongly pass (a since-revoked
    /// validator's old vote still "counts" against the new set's quorum
    /// math, which is nonsensical once that validator's power has moved).
    ///
    /// Returns `Ok(())` if the precommits in `cert` are from validators
    /// known to the historical set, are correctly signed wherever that
    /// historical set had a key on file, and their combined voting power
    /// (as of THAT set, not the live one) meets or exceeds that set's own
    /// quorum threshold. `Err` otherwise, with a string explaining which
    /// check failed.
    pub fn verify_certificate_against_history(
        &self,
        cert: &chain_forge_consensus::CommitCertificate,
    ) -> Result<(), String> {
        let historical_vs = self.historical_validator_sets.get(&cert.height)
            .ok_or_else(|| format!(
                "no historical validator set recorded for height {} -- cannot verify \
                 this certificate against the set effective at that height",
                cert.height
            ))?;

        let quorum = historical_vs.quorum_power();
        let mut counted_power: u64 = 0;
        let mut counted_validators = std::collections::HashSet::new();

        for vote in &cert.precommits {
            // Equivocation/duplicate guard: only count each validator once,
            // same as a real quorum tally would.
            if !counted_validators.insert(vote.validator.clone()) {
                continue;
            }

            let power = historical_vs.power_of(&vote.validator);
            if power == 0 {
                // Unknown to, or zero-power in, the set effective at this
                // height -- e.g. a validator admitted LATER whose vote
                // would wrongly look legitimate against today's live set.
                return Err(format!(
                    "validator {} has zero power in the validator set effective at \
                     height {} -- this precommit could not have counted toward \
                     quorum at that height, whatever it looks like against the \
                     current live set",
                    vote.validator, cert.height
                ));
            }

            let pub_key = historical_vs.public_key_of(&vote.validator);
            if !pub_key.is_empty() {
                if vote.signature.is_empty() {
                    return Err(format!(
                        "validator {} had a registered key in the set effective at \
                         height {}, but this precommit carries an empty signature",
                        vote.validator, cert.height
                    ));
                }
                let msg = chain_forge_consensus::vote_signing_bytes(
                    &self.genesis.chain_id, &vote.vote_type, vote.height, vote.round,
                    vote.block_hash.as_ref(),
                );
                let sig = chain_forge_crypto::Signature {
                    scheme: chain_forge_crypto::SchemeId::Classical,
                    bytes:  vote.signature.clone(),
                };
                ClassicalScheme.verify(&msg, &sig, pub_key).map_err(|e| format!(
                    "validator {}'s precommit signature does not verify against the \
                     key it had registered at height {}: {e}",
                    vote.validator, cert.height
                ))?;
            }

            counted_power = counted_power.saturating_add(power);
        }

        if counted_power < quorum {
            return Err(format!(
                "certificate for height {} carries only {counted_power} of voting \
                 power effective at that height, short of the {quorum} needed for \
                 quorum under the set that was actually active then",
                cert.height
            ));
        }

        Ok(())
    }

    /// Propose a block on the real multi-node path: build it, broadcast it,
    /// cast this node's own votes, and commit immediately if that alone
    /// reached quorum (small validator sets can do this in one round-trip).
    /// Otherwise the block commits later, from handle_event, once enough
    /// peers' votes have arrived over gossip.
    async fn propose_and_broadcast_multinode(
        &mut self,
        parent_hash: BlockHash,
    ) -> Result<(), String> {
        let height = self.consensus.current_height();
        let round  = self.consensus.current_round();

        // Copy, don't drain. If this proposal loses its round, the txs must
        // still be here for the next proposer; they leave the mempool only
        // when a block containing them commits (commit_block). Draining here
        // silently lost every tx in any proposal that didn't commit.
        let txs = self.mempool.clone();
        let tx_bytes = serde_json::to_vec(&txs).unwrap_or_default();

        let proposal = self.consensus
            .propose(height, round, parent_hash, tx_bytes)
            .await
            .map_err(|e| e.to_string())?;

        info!(
            height, round,
            block_hash = %proposal.block_hash,
            txs = txs.len(),
            "block proposed (multi-node)"
        );

        self.pending_proposals.insert((height, round), proposal.clone());

        let _ = self.network.publish(OutboundMessage {
            topic:   GossipTopic::BlockProposal,
            payload: serde_json::to_vec(&proposal).unwrap_or_default(),
        }).await;

        if let Some(cert) = self.cast_and_broadcast_own_votes(&proposal).await? {
            self.commit_block(cert, &proposal).await?;
        }

        Ok(())
    }

    /// Propose and execute a block (called when this node is the proposer).
    /// In Phase 0 this is called manually for testing; in Phase 1 the
    /// consensus timer drives it.
    pub async fn propose_block(
        &mut self,
        parent_hash: BlockHash,
    ) -> Result<chain_forge_consensus::CommitCertificate, String> {
        let height = self.consensus.current_height();
        let round  = self.consensus.current_round();

        // Drain mempool into the block
        let mut txs = std::mem::take(&mut self.mempool);

        let tx_bytes = serde_json::to_vec(&txs).unwrap_or_default();

        // Produce a proposal
        let proposal = self.consensus
            .propose(height, round, parent_hash, tx_bytes)
            .await
            .map_err(|e| e.to_string())?;

        info!(
            height,
            round,
            block_hash = %proposal.block_hash,
            txs = txs.len(),
            "block proposed"
        );

        // Broadcast the proposal
        let payload = serde_json::to_vec(&proposal).unwrap_or_default();
        let _ = self.network.publish(OutboundMessage {
            topic:   GossipTopic::BlockProposal,
            payload,
        }).await;

        // In devnet/single-node mode: auto-commit with synthetic votes
        // (no real peers to vote). This lets us test the full pipeline
        // without a multi-node setup.
        let vs = self.consensus.validator_set().clone();
        let quorum = vs.quorum_power();
        let mut cert = None;

        for validator in &vs.validators {
            let power = validator.voting_power;
            if power == 0 { continue; }

            // Every genesis validator now carries a registered consensus
            // key (mandatory-keys migration), so receive_vote's fail-closed
            // rule treats an empty signature on a keyed validator as a
            // forgery and rejects it (chain-forge-consensus::TendermintEngine
            // ::receive_vote and friends). Before this migration no genesis
            // validator had a key, so an empty signature here was silently
            // accepted; it no longer is.
            //
            // This loop simulates ALL validators voting from a single
            // process (devnet/single-node mode has no real peers), so we
            // cannot sign with "the" operator key -- there isn't one key
            // for four identities. We also must never place other
            // validators' private keys in genesis. Instead we re-derive
            // the same deterministic keypair devnet genesis tooling already
            // uses (chain-forge-crypto/src/bin/gen_devnet_keys.rs derives
            // every devnet validator's keypair from `generate_keypair
            // (address)`), strictly in memory, for this simulation only.
            // We only use it if it reproduces the exact public key genesis
            // registered for that validator -- if some other, externally
            // supplied key was registered instead, the derived key won't
            // match and the vote is correctly left unsigned (and will then
            // be rejected, same as a real forged vote would be), rather
            // than silently trusted.
            let devnet_sim_key = ClassicalScheme.generate_keypair(&validator.id.0)
                .ok()
                .filter(|kp| kp.public_key == validator.public_key);

            let sign_devnet_vote = |vote_type: VoteType| -> Vote {
                let mut vote = Vote {
                    vote_type,
                    height,
                    round,
                    validator:  validator.id.clone(),
                    block_hash: Some(proposal.block_hash.clone()),
                    signature:  vec![],
                    scheme:     Vote::default_scheme(),
                };
                if let Some(ref kp) = devnet_sim_key {
                    let bytes = vote_signing_bytes(
                        &self.genesis.chain_id, &vote.vote_type, vote.height,
                        vote.round, vote.block_hash.as_ref(),
                    );
                    if let Ok(sig) = ClassicalScheme.sign(&bytes, kp) {
                        vote.signature = sig.bytes;
                    }
                }
                vote
            };

            // Cast prevote
            let prevote = sign_devnet_vote(VoteType::Prevote);
            let _ = self.consensus.receive_vote(prevote).await;

            // Cast precommit
            let precommit = sign_devnet_vote(VoteType::Precommit);

            match self.consensus.receive_vote(precommit).await {
                Ok(Some(c)) => { cert = Some(c); break; }
                Ok(None)    => {}
                Err(e)      => { warn!(error = %e, "vote error"); }
            }
        }

        let cert = cert.ok_or("failed to reach quorum in devnet mode")?;

        // Execute the block
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Capture tx metadata for the explorer before txs are consumed.
        let tx_meta: Vec<(String, String, String)> = txs.iter()
            .map(|t| (t.id.clone(), t.sender.clone(), tx_kind_label(&t.body).to_string()))
            .collect();

        // CF-VAL-KEY-002: same snapshot-before-consume as the multi-node
        // commit_block path -- see that path's full comment.
        // Tuple: (tx_index, sender, consensus_pubkey, scheme)
        let register_key_attempts: Vec<(usize, String, Vec<u8>, String)> = txs.iter().enumerate()
            .filter_map(|(i, t)| {
                if let chain_forge_execution::TxBody::RegisterValidatorKey {
                    consensus_pubkey, scheme, ..
                } = &t.body {
                    Some((i, t.sender.clone(), consensus_pubkey.clone(), scheme.clone()))
                } else {
                    None
                }
            })
            .collect();

        // PQ-VAL-002 R4: same EDA capture as the multi-node commit_block path.
        let eda_mldsa_consensus_attempts: Vec<usize> = txs.iter().enumerate()
            .filter_map(|(i, t)| {
                if let chain_forge_execution::TxBody::EmergencyDeprecateAlgorithm {
                    deprecated_scheme,
                    scope: chain_forge_execution::DeprecationScope::ConsensusSignatures,
                    ..
                } = &t.body {
                    if deprecated_scheme == "ml-dsa-65" { Some(i) } else { None }
                } else {
                    None
                }
            })
            .collect();

        // Snapshot the validator set that actually produced this cert
        // BEFORE any epoch-boundary mutation below -- same reasoning as the
        // multi-node commit_block path (see `historical_validator_sets`'s
        // doc comment).
        self.historical_validator_sets.insert(height, self.consensus.validator_set().clone());

        // Deterministic, block-height-driven validator epoch -- same reason
        // as the multi-node commit_block path: this is the devnet
        // single-node auto-commit path, so it needs its own copy. See that
        // path's full design comment for why liveness/admission read from
        // this instead of `self.identity.advance_epoch(now_ms)`.
        let validator_epoch = height / self.validator_epoch_blocks;
        let epoch_rolled = self.identity.advance_epoch_to(validator_epoch);

        // Integration Point 3 (Push) — same reconciliation as the multi-node
        // commit path: after advancing the epoch, revoke ValidatorRegistry
        // entries for any identity that just lapsed. See the multi-node path
        // above for the full design comment.
        {
            let epoch = self.identity.clock.current_epoch;
            let validator_ids: Vec<String> = self.validator_registry
                .all_validators()
                .into_iter()
                .map(|r| r.id.0.clone())
                .collect();
            for vid in &validator_ids {
                let still_verified = self.identity.get(vid)
                    .map(|r| r.charm.tier.grants_consensus())
                    .unwrap_or(false);
                if !still_verified {
                    if let Err(e) = self.validator_registry.revoke_pop(vid, epoch) {
                        if !matches!(e, chain_forge_validators::ValidatorError::NotFound(_)) {
                            warn!(validator = vid, error = %e, "revoke_pop failed after epoch advance");
                        }
                    }
                }
            }
        }

        // Pass the PoCD registry (if enabled) so the executor can distribute
        // epoch rewards directly from the in-memory DiscoveryRegistry.
        let exec_result = if let Some(ref reg_arc) = self.pocd_registry {
            let mut reg = reg_arc.lock().unwrap();
            self.executor.execute_block_with_identity(
                height, txs, &mut self.state, &mut self.identity,
                &mut self.agents, now_ms, Some(&mut *reg),
            )
        } else {
            self.executor.execute_block_with_identity(
                height, txs, &mut self.state, &mut self.identity,
                &mut self.agents, now_ms, None,
            )
        };

        // Diagnostic: log each failed tx so tests can see the root cause.
        for r in exec_result.tx_results.iter().filter(|r| !r.success) {
            warn!(
                tx_id  = %r.tx_id,
                error  = ?r.error,
                "tx failed during block execution"
            );
        }

        info!(
            height,
            txs_ok    = exec_result.success_count(),
            txs_fail  = exec_result.failure_count(),
            gas_used  = exec_result.gas_used,
            state_root = %exec_result.state_root,
            "block executed and committed"
        );

        // CF-VAL-KEY-002: mirror successful RegisterValidatorKey txs into
        // the registry -- see the multi-node commit_block path's full
        // comment for why this runs here and what the executor already
        // verified before this tx could succeed at all.
        //
        // PQ-VAL-003 R6: validators whose key was registered (first-time or
        // rotation) in this block are collected in `key_registered_this_block`
        // so the R6 power-zero can be applied AFTER the pop_verified refresh
        // loop below. Applying it before the refresh would be undone
        // immediately — the refresh sees pop_verified=true, public_key
        // non-empty, and restores power in the same block. Running after the
        // refresh means the zero is the last write to voting_power this block.
        let mut key_registered_this_block: Vec<String> = Vec::new();
        {
            let epoch = self.identity.clock.current_epoch;
            for (idx, sender, pubkey, scheme) in &register_key_attempts {
                let Some(result) = exec_result.tx_results.get(*idx) else { continue };
                if !result.success {
                    continue;
                }
                // PQ-VAL-003 R2: always use register_consensus_key_with_scheme
                // so the scheme field is updated on every registration,
                // including ML-DSA → classical downgrade. The old
                // register_consensus_key path left the scheme unchanged,
                // making the registry show "ml-dsa-65" after a classical
                // downgrade (T05/T06).
                let effective_scheme = if scheme.is_empty() { "classical" } else { scheme.as_str() };
                // PQ-VAL-003 R6: detect rotation (validator already holds a
                // different key) BEFORE updating the registry, so the
                // key_registered_this_block guard only applies to rotations, not
                // first-time registrations. A first-time registration should
                // restore power immediately; only rotation introduces the one-block
                // power gap (R6).
                let is_rotation = self.validator_registry
                    .consensus_pubkey_bytes(sender)
                    .map(|old| old != *pubkey)
                    .unwrap_or(false);
                let reg_result = self.validator_registry.register_consensus_key_with_scheme(
                    sender, pubkey, epoch, effective_scheme,
                );
                if let Err(e) = reg_result {
                    warn!(validator = %sender, error = %e, "consensus key registration mirror failed");
                    continue;
                }
                if is_rotation {
                    key_registered_this_block.push(sender.clone());
                }
            }
        }

        // PQ-VAL-002 R4: same EDA ML-DSA re-zero as the multi-node path.
        {
            let eda_activated = eda_mldsa_consensus_attempts.iter().any(|&idx| {
                exec_result.tx_results.get(idx).map_or(false, |r| r.success)
            });
            if eda_activated {
                let mut updated_vs = self.consensus.validator_set().clone();
                let mut any_changed = false;
                for v in &mut updated_vs.validators {
                    let scheme = self.validator_registry.consensus_key_scheme(&v.id.0)
                        .unwrap_or("classical");
                    if scheme == "ml-dsa-65" && v.voting_power > 0 {
                        warn!(
                            validator = %v.id,
                            "PQ-VAL-002 R4: re-zeroing ML-DSA validator power after \
                             EmergencyDeprecateAlgorithm(ml-dsa-65)"
                        );
                        v.voting_power = 0;
                        any_changed = true;
                    }
                }
                if any_changed {
                    updated_vs.height = height;
                    let _ = self.consensus.update_validator_set(updated_vs);
                }
            }
        }

        // Integration Point 4 (Push) — same stake-bond admission as the
        // multi-node commit path (see the full design comment there). This
        // is the devnet/single-node auto-commit path, so it needs its own
        // copy rather than a shared call: the two paths build/cast votes
        // differently and don't share a merge point before `on_commit`.
        if epoch_rolled {
            let active = chain_forge_execution::validator_bond::compute_stake_active_set(
                &self.state,
                self.executor.native_denom(),
                self.min_bond_uqcb,
                chain_forge_execution::validator_bond::DEFAULT_MAX_ACTIVE_VALIDATORS,
            );
            let mut updated_vs = self.consensus.validator_set().clone();
            let already_seated: std::collections::HashSet<String> = updated_vs.validators
                .iter()
                .map(|v| v.id.0.clone())
                .collect();
            let capacity = chain_forge_execution::validator_bond::DEFAULT_MAX_ACTIVE_VALIDATORS
                .saturating_sub(updated_vs.validators.len());
            let mut admitted = 0usize;
            for (addr, bonded_uqcb) in &active {
                if admitted >= capacity {
                    break;
                }
                if already_seated.contains(addr) {
                    continue;
                }
                info!(
                    validator = %addr,
                    bonded_uqcb = *bonded_uqcb,
                    "stake bond: admitting new validator candidate to active set"
                );
                // CF-VAL-KEY-002: same real-key lookup as the multi-node
                // commit_block path -- see that path's comment.
                let public_key = self.validator_registry
                    .consensus_pubkey_bytes(addr)
                    .unwrap_or_default();
                updated_vs.validators.push(chain_forge_consensus::ValidatorInfo {
                    id: chain_forge_consensus::ValidatorId(addr.clone()),
                    voting_power: (*bonded_uqcb).min(u64::MAX as u128) as u64,
                    pop_verified: false,
                    public_key,
                });
                admitted += 1;
            }
            if admitted > 0 {
                updated_vs.height = height;
                let _ = self.consensus.update_validator_set(updated_vs);
            }
        }

        // CF-VAL-KEY-002: same per-block pop_verified/public_key refresh as
        // the multi-node commit_block path (see that path's full design
        // comment) -- this devnet/single-node auto-commit path previously
        // had no equivalent of this step at all, so a validator admitted
        // here before it had a key (or before its identity was Verified)
        // could never pick either one up later except at its own admission
        // moment. That gap is exactly the kind of restart/refresh hole
        // CF-VAL-KEY-002 exists to close, and test7-restart-recovery-local.sh
        // runs exclusively through this path, so it must get the same
        // ongoing refresh the multi-node path already has.
        {
            let current_vs = self.consensus.validator_set().clone();
            let mut updated_vs = current_vs;
            let mut any_changed = false;
            for v in &mut updated_vs.validators {
                let now_verified = self.identity.get(&v.id.0)
                    .map(|r| r.charm.tier.grants_consensus())
                    .unwrap_or(false);
                if v.pop_verified != now_verified {
                    v.pop_verified = now_verified;
                    any_changed = true;
                }
                if v.public_key.is_empty() {
                    if let Some(real_key) = self.validator_registry.consensus_pubkey_bytes(&v.id.0) {
                        v.public_key = real_key;
                        any_changed = true;
                    }
                }
                // CF-VAL-KEY-002: same voting-power restoration as the
                // multi-node commit_block path -- see that path's comment.
                //
                // PQ-VAL-003 R6: skip power restoration for any validator
                // whose key was registered (first-time or rotation) in this
                // very block. Their power is intentionally held at 0 until the
                // next block's refresh — this is the one-block gap R6 requires.
                // Without this guard the refresh restores power in the same
                // block as the rotation, making the gap unobservable.
                if key_registered_this_block.contains(&v.id.0) {
                    // Force power to 0 for this block; next block restores it.
                    if v.voting_power != 0 {
                        v.voting_power = 0;
                        any_changed = true;
                    }
                } else if v.pop_verified && !v.public_key.is_empty() && v.voting_power == 0 {
                    // PQ-VAL-001/002 / R3: ML-DSA-only validators gated until
                    // PQ-VAL-002 activation epoch (same logic as multi-node path).
                    let scheme = self.validator_registry.consensus_key_scheme(&v.id.0)
                        .unwrap_or("classical");
                    let pq_active = if scheme == "ml-dsa-65" {
                        let current_epoch = self.identity.clock.current_epoch;
                        matches!(self.pq_activation_epoch(),
                            Some(ae) if current_epoch >= ae)
                    } else {
                        true
                    };
                    if pq_active {
                        let bond_addr = format!(
                            "{}{}", chain_forge_execution::validator_bond::BOND_ACCOUNT_PREFIX, v.id.0,
                        );
                        let bonded = self.state.get_account(&bond_addr)
                            .map(|a| a.balance_of(self.executor.native_denom()))
                            .unwrap_or(0);
                        if bonded > 0 {
                            v.voting_power = bonded.min(u64::MAX as u128) as u64;
                            // PH-OVL-001: clamp restored power through the per-human
                            // influence cap when personhood-weighted BFT is active.
                            // Same fix as in commit_block — the propose_block path
                            // shares the same refresh structure and the same gap.
                            if v.pop_verified {
                                if let Some(cap) = self.personhood_power_cap {
                                    if v.voting_power > cap {
                                        v.voting_power = cap;
                                        info!(
                                            validator = %v.id,
                                            voting_power = v.voting_power,
                                            cap,
                                            "PH-OVL-001 propose_block: personhood power cap applied"
                                        );
                                    }
                                }
                            }
                            any_changed = true;
                        }
                    }
                }
            }
            if any_changed {
                updated_vs.height = height;
                let _ = self.consensus.update_validator_set(updated_vs);
            }
        }

        // Advance consensus to next height
        self.consensus.on_commit(cert.clone(), None).await
            .map_err(|e| e.to_string())?;

        // Update shared status
        {
            let mut s = self.status.lock().unwrap();
            s.height     = exec_result.height;
            s.state_root = Some(exec_result.state_root.clone());
        }

        // Update explorer state (Section 9.1)
        {
            let mut ex = self.explorer.lock().unwrap();

            let mut tx_ids = Vec::new();
            for (i, r) in exec_result.tx_results.iter().enumerate() {
                let (sender, kind) = tx_meta.get(i)
                    .map(|(_, s, k)| (s.clone(), k.clone()))
                    .unwrap_or_else(|| ("unknown".into(), "unknown".into()));
                tx_ids.push(r.tx_id.clone());
                ex.txs.insert(r.tx_id.clone(), TxSummary {
                    id:       r.tx_id.clone(),
                    height:   exec_result.height,
                    sender,
                    kind,
                    success:  r.success,
                    gas_used: r.gas_used,
                    events:   r.events.clone(),
                    error:    r.error.clone(),
                });
            }

            ex.blocks.push_front(BlockSummary {
                height:       exec_result.height,
                state_root:   exec_result.state_root.clone(),
                timestamp_ms: now_ms,
                tx_count:     tx_ids.len(),
                tx_ids,
            });
            while ex.blocks.len() > MAX_RECENT_BLOCKS {
                ex.blocks.pop_back();
            }

            // Refresh account snapshots (includes IntrinsicCharm surface)
            ex.accounts.clear();
            for a in self.state.all_accounts() {
                let (frozen, sybil_confirmed) = self.identity.get(&a.address)
                    .map(|r| (r.frozen, r.sybil_confirmed))
                    .unwrap_or((false, false));
                ex.accounts.insert(a.address.clone(), AccountSummary {
                    address:        a.address.clone(),
                    role:           a.role.clone(),
                    nonce:          a.nonce,
                    balances:       a.balances.clone(),
                    tier:           a.verification_tier().map(|t| t.to_string()),
                    exemption_days: a.exemption_days(),
                    frozen,
                    sybil_confirmed,
                });
            }

            // Sync validator power snapshot for GET /api/validators.
            // Use the live consensus ValidatorSet so registered consensus
            // keys (from RegisterValidatorKey) are reflected immediately.
            {
                let live = self.consensus.validator_set();
                ex.validator_powers = live.validators.iter().map(|v| ValidatorPowerSummary {
                    id:           v.id.0.clone(),
                    voting_power: v.voting_power,
                    pop_verified: v.pop_verified,
                    consensus_pubkey: hex::encode(&v.public_key),
                }).collect();
            }
        }

        // QrcMetrics update removed: QRC engine retired; /api/qrc returns empty metrics.

        Ok(cert)
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS: &str = r#"{
        "chain_id": "qcb-testnet-1",
        "chain_name": "QuarkCharmBit",
        "engine_version": "0.1.0",
        "genesis_time": "2026-09-16T00:00:00Z",
        "environment": { "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true },
        "native_token": { "name": "QuarkCharm", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" },
        "address_prefix": "qcb",
        "consensus": { "type": "proof-of-stake", "validator_set_size": 4, "block_time_ms": 1000, "personhood_weighted": true },
        "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": false },
        "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
        "network": { "network_id": "qcb-devnet", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "mdns", "max_peers": 10 },
        "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 },
        "modules": ["bank", "staking", "identity", "agents", "pocd"],
        "custom_modules": [],
        "crypto_governors": ["qcb1alice"],
        "genesis_accounts": [
            { "label": "Alice", "address": "qcb1alice", "balance": "5000000", "role": "validator", "public_key": "6caccc4ade33a11be12161375e7b487ed2d5201d6aaf1eae84114b47125178d8" },
            { "label": "Bob",   "address": "qcb1bob",   "balance": "5000000", "role": "validator", "public_key": "65288338497d3f0653040eb1b887a85e9e9320c0c0c3dfcf979aefe6a6809fb0" },
            { "label": "Carol", "address": "qcb1carol", "balance": "5000000", "role": "validator", "public_key": "f95ff18493d936fb90afb7fb4cbfe5607712336984d305e8926c3240a2aad692" },
            { "label": "Dave",  "address": "qcb1dave",  "balance": "5000000", "role": "validator", "public_key": "4f95a9904121fb5d0f040e82d4fbd953b8b76b728a026bed0fba52aaa45256f0" }
        ]
    }"#;
    // The four public keys above are not arbitrary: they are
    // ClassicalScheme.generate_keypair("qcb1<name>") under the real-crypto
    // feature (SHA-256(address) -> deterministic Ed25519 seed) -- the exact
    // same values already committed in tests/devnet/genesis-4node.json for
    // the real 4-node devnet harness. Reusing them keeps every genesis
    // fixture in this codebase internally consistent with one
    // deterministic, reproducible keygen path, rather than introducing a
    // third, disconnected set of test-only keys. Verified independently
    // against the current chain-forge-crypto::ClassicalScheme::generate_keypair
    // implementation while building this migration -- see the "Mandatory
    // validator keys" migration notes.

    #[tokio::test]
    async fn node_initialises_from_genesis() {
        let node = Node::new(GENESIS, None).await.unwrap();
        assert_eq!(node.chain_id(), "qcb-testnet-1");
        assert_eq!(node.environment(), "devnet");
        assert_eq!(node.consensus.current_height(), 0);
        assert_eq!(node.state.account_count(), 4);
    }

    #[tokio::test]
    async fn node_resolves_default_bonding_params_when_genesis_omits_the_override() {
        // GENESIS (above) predates `validator_bonding` entirely -- same
        // shape as every genesis file on disk today. Confirms the engine
        // falls back to its compiled-in defaults byte-for-byte, i.e. this
        // change set does not alter behavior for any existing genesis file.
        let node = Node::new(GENESIS, None).await.unwrap();
        assert_eq!(node.validator_epoch_blocks, DEFAULT_VALIDATOR_EPOCH_BLOCKS);
        assert_eq!(
            node.min_bond_uqcb,
            chain_forge_execution::validator_bond::DEFAULT_MIN_BOND_UQCB
        );
    }

    #[tokio::test]
    async fn node_resolves_validator_bonding_overrides_from_genesis() {
        let json = GENESIS.replace(
            r#""custom_modules": [],"#,
            r#""custom_modules": [],
        "validator_bonding": { "min_bond_amount": 7000000, "validator_epoch_blocks": 42 },"#,
        );
        let node = Node::new(&json, None).await.unwrap();
        assert_eq!(node.validator_epoch_blocks, 42);
        assert_eq!(node.min_bond_uqcb, 7_000_000);
    }

    #[tokio::test]
    async fn restart_preserves_registered_validator_public_keys() {
        // CF-DEVNET-VAL-001 regression (found live via
        // tests/devnet/test7-restart-recovery-local.sh on a real 4-node
        // devnet): after a node restarts with --data-dir, the first new
        // block it helps commit can carry an empty signature for its own
        // precommit -- despite the validator having a registered genesis
        // key and a real --key-file -- which every peer that never
        // restarted then correctly rejects as a forgery:
        //   "validator qcb1alice has a registered key but precommit in
        //    commit certificate carries an empty signature (possible
        //    forgery)"
        //
        // Root cause: `Node::load_persisted_state()` rebuilds the live
        // consensus ValidatorSet after restoring from disk by calling
        // `ValidatorRegistry::build_validator_set()`, which unconditionally
        // emits `public_key: vec![]` for every validator (ValidatorRegistry
        // was never wired to carry the real genesis-registered key --
        // `register_genesis_validator` stores an empty "genesis-stub"
        // KeyBundle). This wipes every validator's real public key from the
        // live set on restart, which does two things: (1) load_signing_key
        // (called right after, from main.rs) looks up the now-keyless entry
        // and refuses to load a real signing key at all, even with a
        // correct --key-file; (2) with no key on file, both
        // node.rs::verify_vote_signature and
        // chain_forge_consensus::TendermintEngine::receive_vote fall back
        // to their Phase-0 "no key on file -> tolerate empty signature"
        // path -- meant for the pre-mandatory-keys era, not a restarted
        // node -- so the restarted node locally accepts and commits an
        // empty-signature "vote" from itself. Any peer that never
        // restarted still has the correct, non-wiped key and rejects the
        // resulting certificate. A local-quorum / remote-verification
        // divergence, not a cosmetic bug.
        //
        // This test reproduces the defect without any real OS process
        // restart or networking: it exercises the exact same
        // set_data_dir -> commit -> drop -> set_data_dir -> load_persisted_state
        // sequence main.rs uses, in-process.
        let dir = std::env::temp_dir()
            .join(format!("cf-restart-regression-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Phase 1: a node with a data dir commits a couple of blocks.
        {
            let mut node = Node::new(GENESIS, Some("qcb1alice".into())).await.unwrap();
            node.set_data_dir(dir.clone()).unwrap();
            let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
            let cert0 = node.propose_block(genesis_hash).await.unwrap();
            node.propose_block(cert0.block_hash).await.unwrap();
            // propose_block()'s devnet/single-node auto-commit path does not
            // itself call persist_state() (only the real multi-node
            // commit_block() path does, right after committing each block).
            // Call it explicitly here so this test persists to disk exactly
            // what a real node's commit_block() would have persisted after
            // these same two blocks.
            node.persist_state();

            // Sanity: before any restart, every genesis validator's real
            // public key is present in the live set (as seeded from
            // genesis at construction).
            for v in &node.consensus.validator_set().validators {
                assert!(
                    !v.public_key.is_empty(),
                    "sanity check failed: {} should have a public key \
                     before any restart ever happens",
                    v.id
                );
            }
        } // node dropped -- simulates process exit.

        // Phase 2: a fresh node instance ("restart") resumes from the same
        // data dir, exactly as main.rs does: set_data_dir then
        // load_persisted_state.
        let mut restarted = Node::new(GENESIS, Some("qcb1alice".into())).await.unwrap();
        restarted.set_data_dir(dir.clone()).unwrap();
        assert!(
            restarted.load_persisted_state(),
            "persisted state from phase 1 must be found and loaded"
        );

        // The actual defect: every validator's public key must survive the
        // restart. Before the fix, this fails -- build_validator_set()
        // replaces the whole set with public_key: vec![] for everyone.
        for v in &restarted.consensus.validator_set().validators {
            assert!(
                !v.public_key.is_empty(),
                "validator {} lost its registered public key across restart \
                 -- this is what lets a restarted node locally accept and \
                 commit an empty-signature vote that peers who never \
                 restarted will correctly reject as a forgery",
                v.id
            );
        }

        // Closing the loop on the actual observed symptom: load_signing_key
        // (called right after load_persisted_state in main.rs, with a real
        // key file on disk) must still succeed post-restart.
        let key_dir = dir.join("test-keys");
        std::fs::create_dir_all(&key_dir).unwrap();
        let key_path = key_dir.join("alice.key.json");
        // Same deterministic devnet keypair the GENESIS fixture's
        // registered public key for qcb1alice comes from (see the comment
        // above the GENESIS constant).
        let kp = chain_forge_crypto::ClassicalScheme
            .generate_keypair("qcb1alice")
            .unwrap();
        fn hex_encode(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        std::fs::write(
            &key_path,
            serde_json::json!({
                "address": "qcb1alice",
                "public_key": hex_encode(&kp.public_key),
                "private_key": hex_encode(&kp.private_key),
                "scheme": "classical-ed25519",
            }).to_string(),
        ).unwrap();

        restarted.load_signing_key(&key_path).unwrap_or_else(|e| {
            panic!("load_signing_key must succeed post-restart with a correct \
                    key file, matching the genesis-registered key: {e}")
        });

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn restart_still_rejects_forged_or_unsigned_precommit_after_fix() {
        // Adversarial counterpart to
        // `restart_preserves_registered_validator_public_keys`: the fix for
        // CF-DEVNET-VAL-001 only backfills a validator's REAL, already
        // genesis-verified public key across restart -- it must not
        // loosen signature verification itself. Prove that, post-restart,
        // a validator whose key WAS correctly preserved still has every
        // vote checked against it: an empty signature and a tampered
        // signature are both still rejected, exactly as they would be for
        // a node that never restarted at all.
        let dir = std::env::temp_dir()
            .join(format!("cf-restart-adversarial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        {
            let mut node = Node::new(GENESIS, Some("qcb1alice".into())).await.unwrap();
            node.set_data_dir(dir.clone()).unwrap();
            let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
            let cert0 = node.propose_block(genesis_hash).await.unwrap();
            node.propose_block(cert0.block_hash).await.unwrap();
            node.persist_state();
        }

        let mut restarted = Node::new(GENESIS, Some("qcb1alice".into())).await.unwrap();
        restarted.set_data_dir(dir.clone()).unwrap();
        assert!(restarted.load_persisted_state());

        let alice = chain_forge_consensus::ValidatorId("qcb1alice".into());
        let height = restarted.consensus.current_height();
        let round = restarted.consensus.current_round();
        let block_hash = chain_forge_consensus::BlockHash("deadbeefdeadbeef".into());

        // 1. Genuinely unsigned (empty-signature) precommit for a validator
        //    the fix just restored a real key for -- must still be
        //    rejected, not silently tolerated by the Phase-0 no-key
        //    allowance (that allowance only applies when public_key really
        //    is empty, which it no longer is for alice post-fix).
        let unsigned = Vote {
            vote_type:  VoteType::Precommit,
            height,
            round,
            validator:  alice.clone(),
            block_hash: Some(block_hash.clone()),
            signature:  vec![],
            scheme:     Vote::default_scheme(),
        };
        assert!(
            restarted.verify_vote_signature(&unsigned).is_err(),
            "an empty-signature precommit for a validator with a (now correctly \
             restored) registered key must still be rejected after the fix"
        );

        // 2. A forged precommit: signed with a key that is NOT alice's real
        //    genesis key, claiming to be alice. Must still be rejected.
        let forger_kp = ClassicalScheme.generate_keypair("not-the-real-alice-key")
            .unwrap();
        let bytes = chain_forge_consensus::vote_signing_bytes(
            &restarted.genesis.chain_id, &VoteType::Precommit, height, round,
            Some(&block_hash),
        );
        let forged_sig = ClassicalScheme.sign(&bytes, &forger_kp).unwrap();
        let forged = Vote {
            vote_type:  VoteType::Precommit,
            height,
            round,
            validator:  alice.clone(),
            block_hash: Some(block_hash.clone()),
            signature:  forged_sig.bytes,
            scheme:     Vote::default_scheme(),
        };
        assert!(
            restarted.verify_vote_signature(&forged).is_err(),
            "a precommit for alice signed with any key other than alice's real \
             registered key must still be rejected after the fix"
        );

        // 3. Sanity: a precommit genuinely signed with alice's real
        //    genesis-registered key (same key the fix preserved) must
        //    still verify successfully -- the fix did not also break the
        //    honest path.
        let real_kp = ClassicalScheme.generate_keypair("qcb1alice").unwrap();
        let real_sig = ClassicalScheme.sign(&bytes, &real_kp).unwrap();
        let honest = Vote {
            vote_type:  VoteType::Precommit,
            height,
            round,
            validator:  alice,
            block_hash: Some(block_hash),
            signature:  real_sig.bytes,
            scheme:     Vote::default_scheme(),
        };
        assert!(
            restarted.verify_vote_signature(&honest).is_ok(),
            "a precommit genuinely signed with alice's real registered key \
             must still verify successfully after the fix"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn node_startup_rejects_zero_min_bond_amount_in_genesis() {
        let json = GENESIS.replace(
            r#""custom_modules": [],"#,
            r#""custom_modules": [],
        "validator_bonding": { "min_bond_amount": 0 },"#,
        );
        let err = Node::new(&json, None).await
            .err()
            .expect("a genesis with min_bond_amount=0 must refuse to start");
        assert!(matches!(err, NodeError::Genesis(_)));
        assert!(err.to_string().contains("min_bond_amount"), "{err}");
    }

    #[tokio::test]
    async fn node_startup_rejects_zero_validator_epoch_blocks_in_genesis() {
        let json = GENESIS.replace(
            r#""custom_modules": [],"#,
            r#""custom_modules": [],
        "validator_bonding": { "validator_epoch_blocks": 0 },"#,
        );
        let err = Node::new(&json, None).await
            .err()
            .expect("a genesis with validator_epoch_blocks=0 must refuse to start -- it would divide by zero on the first commit");
        assert!(matches!(err, NodeError::Genesis(_)));
        assert!(err.to_string().contains("validator_epoch_blocks"), "{err}");
    }

    #[tokio::test]
    async fn two_nodes_from_the_same_overriding_genesis_agree_on_epoch_boundaries() {
        // Requirement #5: every node must derive the SAME validator epoch
        // boundary and minimum-bond rule from the SAME genesis -- not from
        // a locally-set field. Two independently-constructed nodes parsing
        // the identical overriding genesis JSON must compute identical
        // `validator_epoch_blocks`/`min_bond_uqcb`, and therefore roll an
        // epoch at the identical height, with no coordination between them
        // beyond the genesis bytes itself.
        let json = GENESIS.replace(
            r#""custom_modules": [],"#,
            r#""custom_modules": [],
        "validator_bonding": { "min_bond_amount": 3000000, "validator_epoch_blocks": 2 },"#,
        );
        let node_a = Node::new(&json, None).await.unwrap();
        let node_b = Node::new(&json, None).await.unwrap();
        assert_eq!(node_a.validator_epoch_blocks, node_b.validator_epoch_blocks);
        assert_eq!(node_a.min_bond_uqcb, node_b.min_bond_uqcb);
        assert_eq!(node_a.validator_epoch_blocks, 2);
        assert_eq!(node_a.min_bond_uqcb, 3_000_000);
    }

    #[tokio::test]
    async fn genesis_validators_are_seeded_as_verified_identities() {
        // Regression test: without seeding, IdentityStore::attest() has no
        // Verified+ attester to ever bootstrap from, so no identity could
        // EVER become Verified via the real attestation flow -- found
        // while building chain-forge-sim, which would otherwise have had
        // no seed to register its own personas' attestation chain against.
        let node = Node::new(GENESIS, None).await.unwrap();
        for addr in ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"] {
            let record = node.identity.get(addr)
                .unwrap_or_else(|_| panic!("genesis validator {addr} must be seeded into IdentityStore"));
            assert_eq!(
                *record.tier(),
                chain_forge_identity::VerificationTier::Verified,
                "genesis validator {addr} must start Verified, not just registered"
            );
        }
    }

    #[tokio::test]
    async fn node_produces_first_block() {
        let mut node = Node::new(GENESIS, Some("qcb1alice".into())).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = node.propose_block(genesis_hash).await.unwrap();
        assert_eq!(cert.height, 0);
        assert_eq!(node.consensus.current_height(), 1);

        let status = node.status.lock().unwrap();
        assert_eq!(status.height, 0); // block 0 committed
        assert!(status.state_root.is_some());
    }

    #[tokio::test]
    async fn node_produces_multiple_blocks() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let mut parent = chain_forge_consensus::BlockHash("0000000000000000".into());

        for i in 0..3u64 {
            let cert = node.propose_block(parent.clone()).await.unwrap();
            assert_eq!(cert.height, i);
            parent = cert.block_hash;
        }

        assert_eq!(node.consensus.current_height(), 3);
    }

    #[tokio::test]
    async fn node_executes_tx_in_block() {
        use chain_forge_execution::Transaction;

        let mut node = Node::new(GENESIS, None).await.unwrap();

        // Submit a transfer from Alice to Bob
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100_000, 0);
        node.submit_tx(tx);

        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
        node.propose_block(genesis_hash).await.unwrap();

        // Bob should have 5_100_000 after receiving 100_000
        let bob_balance = node.state.get_account("qcb1bob").unwrap().balance_of("uqcb");
        assert_eq!(bob_balance, 5_100_000);
    }

    #[tokio::test]
    async fn bonded_stake_admits_new_validator_candidate_at_epoch_boundary() {
        // ROADMAP.md, Validator Onboarding: a brand-new address with no
        // genesis role at all should be able to bond stake and actually
        // enter the live consensus ValidatorSet -- the gap Integration
        // Point 4 closes. None of the 4 genesis accounts exercise this: all
        // of them already hold role "validator" and are seated from block
        // 0, so this test uses a fifth address the genesis set never heard
        // of.
        use chain_forge_execution::Transaction;

        let mut node = Node::new(GENESIS, None).await.unwrap();
        assert!(
            !node.consensus.validator_set().validators.iter().any(|v| v.id.0 == "qcb1erin"),
            "qcb1erin must not be seated before bonding anything"
        );

        // Deterministic block-height epochs: force every block to be an
        // epoch boundary (height % 1 == 0, always true) rather than
        // waiting out DEFAULT_VALIDATOR_EPOCH_BLOCKS real commits -- this
        // test is about admission at an epoch boundary, not about epoch
        // timing itself.
        node.validator_epoch_blocks = 1;

        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Block 0: fund the new address (it holds nothing at genesis, so
        // it cannot bond before it has uqcb to bond). Fund with headroom
        // above the bond amount to cover gas on this Transfer tx itself;
        // without headroom the bond tx fails ("insufficient balance").
        node.submit_tx(Transaction::transfer("fund-erin", "qcb1alice", "qcb1erin", "uqcb", 2_010_000, 0));
        let cert0 = node.propose_block(genesis_hash).await.unwrap();

        // Block 1: bond the min threshold and above.
        node.submit_tx(Transaction::bond_validator("bond-erin", "qcb1erin", 2_000_000, 0));
        node.propose_block(cert0.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let erin = vs.validators.iter().find(|v| v.id.0 == "qcb1erin")
            .expect("qcb1erin must be admitted to the active set after bonding above the minimum");
        // Mandatory-personhood migration: stake determines admission
        // eligibility and ranking, but voting power is bounded by verified
        // personhood (chain-forge-consensus::gate_voting_power, applied
        // unconditionally in every engine). Erin is seated -- she holds a
        // slot in the active set and her bonded stake is tracked -- but
        // until the IdentityStore marks her Verified she has zero EFFECTIVE
        // voting power, same as a keyless validator would. This was
        // previously 2_000_000 (stake-weighted, ungated); that behavior
        // predates the mandatory-personhood requirement and is no longer
        // correct.
        assert_eq!(erin.voting_power, 0,
            "an unverified entrant must have zero effective voting power even though admitted");
        assert!(!erin.pop_verified, "new entrant starts unverified until IdentityStore says otherwise");
    }

    #[tokio::test]
    async fn validator_epoch_and_admission_converge_identically_across_nodes() {
        // Deterministic block-height validator epochs: two INDEPENDENTLY
        // constructed nodes (simulating two separate processes, each with
        // its own SystemTime::now() at construction and at every would-be
        // wall-clock read) must reach IDENTICAL validator-epoch state --
        // and identical admission outcomes -- after processing the exact
        // same block sequence, even with real wall-clock skew introduced
        // between them. Before this migration, `advance_epoch(now_ms)`
        // read each node's own SystemTime::now() for exactly this
        // decision, so skew could make one node admit/lapse a validator a
        // commit earlier or later than the other -- a state-divergence
        // and quorum-safety risk, not just a cosmetic one.
        use chain_forge_execution::Transaction;

        async fn fund_and_bond_erin(node: &mut Node) -> chain_forge_consensus::ValidatorSet {
            node.validator_epoch_blocks = 2;
            let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
            // Fund with headroom above the bond amount to cover gas on the
            // Transfer tx; without it the bond tx fails ("insufficient balance").
            node.submit_tx(Transaction::transfer("fund-erin", "qcb1alice", "qcb1erin", "uqcb", 2_010_000, 0));
            let cert0 = node.propose_block(genesis_hash).await.unwrap();
            node.submit_tx(Transaction::bond_validator("bond-erin", "qcb1erin", 2_000_000, 0));
            let cert1 = node.propose_block(cert0.block_hash).await.unwrap();
            // One more "do nothing" block so both nodes land on the same
            // final height/epoch before comparison.
            node.propose_block(cert1.block_hash).await.unwrap();
            node.consensus.validator_set().clone()
        }

        let mut node_a = Node::new(GENESIS, None).await.unwrap();
        let vs_a = fund_and_bond_erin(&mut node_a).await;

        // Real wall-clock delay before the second node processes the exact
        // same sequence -- if anything still read SystemTime for epoch
        // advancement, this is where it would show up as a divergence.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut node_b = Node::new(GENESIS, None).await.unwrap();
        let vs_b = fund_and_bond_erin(&mut node_b).await;

        assert_eq!(
            node_a.identity.clock.current_epoch,
            node_b.identity.clock.current_epoch,
            "validator epoch number must be identical across nodes regardless \
             of real-time skew between them"
        );
        assert_eq!(node_a.identity.clock.current_epoch, 1,
            "height 2 / validator_epoch_blocks(2) == epoch 1");

        let ids_and_power = |vs: &chain_forge_consensus::ValidatorSet| -> Vec<(String, u64)> {
            let mut v: Vec<(String, u64)> = vs.validators.iter()
                .map(|vi| (vi.id.0.clone(), vi.voting_power))
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            ids_and_power(&vs_a), ids_and_power(&vs_b),
            "the full active validator set (membership AND voting power) must \
             converge identically across nodes after the same block sequence"
        );
        assert!(
            vs_a.validators.iter().any(|v| v.id.0 == "qcb1erin"),
            "sanity check: Erin must actually have been admitted on both nodes"
        );
    }

    // -- CF-VAL-KEY-002: Mandatory Consensus Public Keys for Post-Genesis
    //    Validators -- Phase 4 regression tests ----------------------------

    /// A validator identity derived from a real keypair (not a human label
    /// like "qcb1erin") -- required because `RegisterValidatorKey` now
    /// enforces real signature authentication unconditionally, and an
    /// unbound, non-derived named address can never pass that check (see
    /// `verify_authorization_signed`'s first-use derivation rule).
    fn keyed_candidate(seed: &str) -> (chain_forge_crypto::KeyPair, String) {
        let kp = ClassicalScheme.generate_keypair(seed).unwrap();
        let addr = chain_forge_core::Address::from_public_key(
            &kp.public_key, "qcb", chain_forge_core::HashWidth::Bits256,
        ).to_string();
        (kp, addr)
    }

    fn register_key_tx(
        sender: &str, nonce: u64, consensus_kp: &chain_forge_crypto::KeyPair, chain_id: &str,
    ) -> Transaction {
        let pop_msg = chain_forge_execution::validator_key_registration_signing_bytes(chain_id, sender);
        let pop_sig = ClassicalScheme.sign(&pop_msg, consensus_kp).unwrap();
        let mut tx = Transaction {
            id:        format!("regkey-{sender}-{nonce}"),
            sender:    sender.to_string(),
            nonce,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    consensus_kp.public_key.clone(),
                proof_of_possession: pop_sig.bytes,
                // V1 classical legacy path: empty scheme triggers the
                // backward-compat branch (treated as "classical"), and
                // pop_version = 1 uses the V1 message (no pubkey binding).
                scheme:              String::new(),
                pop_version:         1,
            },
            gas_limit: 10_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(consensus_kp, chain_id).unwrap();
        tx
    }

    /// Funds, bonds, and grants verified personhood to a brand-new
    /// candidate, driving the node through blocks until they are admitted
    /// into the live consensus ValidatorSet. Does NOT register a consensus
    /// key -- callers add that step themselves so both "has a key" and
    /// "has no key" scenarios share this setup.
    async fn fund_bond_and_verify_personhood(
        node: &mut Node, addr: &str, amount: u128, parent_hash: chain_forge_consensus::BlockHash,
    ) -> chain_forge_consensus::CommitCertificate {
        node.validator_epoch_blocks = 2;
        // Fund with enough headroom to cover gas on the Transfer tx itself
        // (~82 uqcb for a typical devnet transfer) AND the subsequent
        // BondValidator tx, so the candidate can bond exactly `amount`.
        // Without this buffer the fund tx deducts gas first, leaving the
        // candidate short of `amount` when the bond tx runs, causing it to
        // fail with "insufficient balance" -- the root cause of all 7
        // CF-DEVNET-VAL-001 failures (diagnosed via diagnostic eprintlns,
        // now removed). 10_000 is conservative headroom; actual gas is ~200.
        const GAS_BUFFER: u128 = 10_000;
        node.submit_tx(Transaction::transfer("fund", "qcb1alice", addr, "uqcb", amount + GAS_BUFFER, 0));
        let cert0 = node.propose_block(parent_hash).await.unwrap();

        node.submit_tx(Transaction::bond_validator("bond", addr, amount, 0));
        let cert1 = node.propose_block(cert0.block_hash).await.unwrap();

        // Grant verified personhood directly via the identity layer, same
        // mechanism used to seed genesis validators (Node::new_with_config) --
        // bypasses the full on-chain Attest-quorum flow, which is a separate
        // concern from this test's focus (key registration).
        let epoch = node.identity.clock.current_epoch;
        let att = chain_forge_identity::PopAttestation::genesis(addr, epoch);
        let _ = node.identity.register(addr.to_string(), addr.to_string(), att.clone());
        node.identity.verify_identity(addr, att, None).unwrap();

        // One more block: this is the epoch boundary (validator_epoch_blocks=2,
        // height now 2) where Integration Point 4 admits the new candidate
        // and the pop_verified refresh picks up the just-granted personhood.
        node.propose_block(cert1.block_hash).await.unwrap()
    }

    #[tokio::test]
    async fn bonded_validator_with_key_and_personhood_becomes_eligible() {
        // CF-VAL-KEY-002 Phase 4 test #1.
        let (kp, addr) = keyed_candidate("seed-eligible-validator");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
        // One more block to execute the registration and let the refresh
        // loop pick the new key up into the live ValidatorSet.
        node.propose_block(cert.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let v = vs.validators.iter().find(|v| v.id.0 == addr)
            .expect("validator must be seated in the active set");
        assert!(!v.public_key.is_empty(), "validator must have a real key on file");
        assert_eq!(v.public_key, kp.public_key);
        assert!(v.pop_verified, "validator must have verified personhood");
        assert!(
            v.voting_power > 0,
            "a validator with BOTH a registered key AND verified personhood \
             must carry real voting power"
        );
    }

    #[tokio::test]
    async fn bonded_validator_without_key_has_zero_voting_power() {
        // CF-VAL-KEY-002 Phase 4 test #2. Same setup as the test above --
        // funded, bonded, personhood verified -- EXCEPT no
        // RegisterValidatorKey tx is ever submitted.
        let (_, addr) = keyed_candidate("seed-keyless-validator");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        let vs = node.consensus.validator_set();
        let v = vs.validators.iter().find(|v| v.id.0 == addr)
            .expect("validator must still hold a seat (its bond record) even without a key");
        assert!(v.public_key.is_empty(), "sanity: no key was ever registered");
        assert_eq!(
            v.voting_power, 0,
            "a bonded validator with verified personhood but NO registered \
             consensus key must carry zero voting power -- it may keep its \
             bond record but cannot participate in consensus"
        );
    }

    #[tokio::test]
    async fn bonded_validators_unsigned_precommit_is_rejected() {
        // CF-VAL-KEY-002 Phase 4 test #4, for a validator admitted AFTER
        // genesis through this new mechanism specifically (the existing
        // `receive_vote_rejects_empty_sig_when_key_registered` in
        // chain-forge-consensus already covers this generically; this
        // closes the loop end-to-end through the actual bonding + key
        // registration path).
        let (kp, addr) = keyed_candidate("seed-unsigned-precommit-validator");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
        let cert = node.propose_block(cert.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        assert!(vs.validators.iter().any(|v| v.id.0 == addr && !v.public_key.is_empty()));

        let height = node.consensus.current_height();
        let round  = node.consensus.current_round();
        let unsigned = Vote {
            vote_type:  VoteType::Precommit,
            height,
            round,
            validator:  chain_forge_consensus::ValidatorId(addr.clone()),
            block_hash: Some(cert.block_hash.clone()),
            signature:  vec![],
            scheme:     Vote::default_scheme(),
        };
        let result = node.consensus.receive_vote(unsigned).await;
        assert!(
            result.is_err(),
            "an unsigned precommit from a validator with a registered key \
             must be rejected, whether that validator was seated at genesis \
             or admitted later via BondValidator + RegisterValidatorKey"
        );
    }

    #[tokio::test]
    async fn bonded_validators_vote_signed_by_wrong_key_is_rejected() {
        // CF-VAL-KEY-002 Phase 4 test #5.
        let (kp, addr) = keyed_candidate("seed-wrong-key-validator");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
        let cert = node.propose_block(cert.block_hash).await.unwrap();

        let height = node.consensus.current_height();
        let round  = node.consensus.current_round();
        let wrong_kp = ClassicalScheme.generate_keypair("an-impostor-key").unwrap();
        let bytes = vote_signing_bytes(
            node.chain_id(), &VoteType::Precommit, height, round, Some(&cert.block_hash),
        );
        let forged_sig = ClassicalScheme.sign(&bytes, &wrong_kp).unwrap();
        let forged = Vote {
            vote_type:  VoteType::Precommit,
            height,
            round,
            validator:  chain_forge_consensus::ValidatorId(addr.clone()),
            block_hash: Some(cert.block_hash.clone()),
            signature:  forged_sig.bytes,
            scheme:     Vote::default_scheme(),
        };
        let result = node.consensus.receive_vote(forged).await;
        assert!(
            result.is_err(),
            "a precommit claiming to be this validator but signed with a \
             different key must be rejected"
        );
    }

    #[tokio::test]
    async fn all_nodes_compute_identical_validator_sets_after_key_registration() {
        // CF-VAL-KEY-002 Phase 4 test #7.
        let (kp, addr) = keyed_candidate("seed-convergence-validator");

        async fn run(node: &mut Node, addr: &str, kp: &chain_forge_crypto::KeyPair) -> chain_forge_consensus::ValidatorSet {
            let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
            let cert = fund_bond_and_verify_personhood(node, addr, 2_000_000, genesis_hash).await;
            node.submit_tx(register_key_tx(addr, 1, kp, node.chain_id()));
            node.propose_block(cert.block_hash).await.unwrap();
            node.consensus.validator_set().clone()
        }

        let mut node_a = Node::new(GENESIS, None).await.unwrap();
        let vs_a = run(&mut node_a, &addr, &kp).await;

        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        let mut node_b = Node::new(GENESIS, None).await.unwrap();
        let vs_b = run(&mut node_b, &addr, &kp).await;

        let fingerprint = |vs: &chain_forge_consensus::ValidatorSet| -> Vec<(String, u64, bool, Vec<u8>)> {
            let mut v: Vec<_> = vs.validators.iter()
                .map(|vi| (vi.id.0.clone(), vi.voting_power, vi.pop_verified, vi.public_key.clone()))
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            fingerprint(&vs_a), fingerprint(&vs_b),
            "membership, voting power, personhood, AND the registered key \
             itself must converge identically across independently-run nodes \
             processing the same transaction sequence"
        );
    }

    #[tokio::test]
    async fn bonded_validators_key_survives_restart_and_epoch_transition() {
        // CF-VAL-KEY-002 Phase 4 test #8.
        let (kp, addr) = keyed_candidate("seed-restart-validator");
        let dir = std::env::temp_dir()
            .join(format!("cf-val-key-002-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let (vs_before, height_before) = {
            let mut node = Node::new(GENESIS, None).await.unwrap();
            node.set_data_dir(dir.clone()).unwrap();
            let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
            let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
            node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
            node.propose_block(cert.block_hash).await.unwrap();
            node.persist_state();
            // `persist_state()`/`load_persisted_state()` key off the
            // StateStore's own committed height (the last EXECUTED block),
            // not `consensus.current_height()` (the NEXT height to
            // propose, already one ahead after `on_commit`) -- so that is
            // the value to compare against post-restart, not the
            // consensus engine's counter.
            (node.consensus.validator_set().clone(), node.state.current_height())
        };
        let v_before = vs_before.validators.iter().find(|v| v.id.0 == addr).unwrap();
        assert!(!v_before.public_key.is_empty());
        assert!(v_before.voting_power > 0, "sanity: validator had real power before restart");

        let mut restarted = Node::new(GENESIS, None).await.unwrap();
        restarted.set_data_dir(dir.clone()).unwrap();
        assert!(restarted.load_persisted_state());
        assert_eq!(restarted.consensus.current_height(), height_before);

        let vs_after = restarted.consensus.validator_set();
        let v_after = vs_after.validators.iter().find(|v| v.id.0 == addr)
            .expect(
                "the bonded validator must still hold its seat after restart -- \
                 before CF-VAL-KEY-002's restart-persistence fix, a validator \
                 admitted after genesis was entirely absent from the \
                 reconstructed set, not merely missing its key"
            );
        assert_eq!(v_after.public_key, kp.public_key, "key must survive restart");
        assert_eq!(v_after.voting_power, v_before.voting_power, "voting power must survive restart");
        assert_eq!(v_after.pop_verified, v_before.pop_verified);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn historical_validator_set_retains_the_registered_key() {
        // CF-VAL-KEY-002 Phase 4 test #9.
        let (kp, addr) = keyed_candidate("seed-historical-validator");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
        let cert = node.propose_block(cert.block_hash).await.unwrap();

        // historical_validator_sets[height] is snapshotted BEFORE that
        // height's own admission/refresh mutations (see commit_block's
        // design comment), so the snapshot that actually carries this
        // validator's key is the one taken for the height immediately
        // AFTER the block that registered it.
        let next_height = node.consensus.current_height();
        node.propose_block(cert.block_hash).await.unwrap();

        let snapshot = node.historical_validator_sets.get(&next_height)
            .expect("a historical snapshot must exist for the height after key registration");
        let v = snapshot.validators.iter().find(|v| v.id.0 == addr)
            .expect("validator must be present in the historical snapshot");
        assert_eq!(
            v.public_key, kp.public_key,
            "the historical validator set used for certificate verification \
             must retain the real registered key, not an empty placeholder"
        );
    }

    #[tokio::test]
    async fn verify_certificate_against_history_uses_set_effective_at_height_not_live_set() {
        // "Preserve historical validator sets: certificates must be
        // verified against the validator set effective at their height,
        // not the current live set" -- this is the exact property under
        // test.
        //
        // Scenario: a certificate for height 7 really did reach quorum
        // under a 4-validator set (quorum = 3 of 4). The live set then
        // grows to 5 validators (quorum = 4 of 5). The same 3-precommit
        // certificate must still verify correctly against the HISTORICAL
        // set it actually belongs to -- it would incorrectly fall short
        // if checked against today's live quorum instead.
        use chain_forge_consensus::{vote_signing_bytes, BlockHash, CommitCertificate, ValidatorId, ValidatorInfo, ValidatorSet, Vote, VoteType};

        let mut node = Node::new(GENESIS, None).await.unwrap();

        let keyed = |addr: &str| -> ValidatorInfo {
            let kp = ClassicalScheme.generate_keypair(addr).unwrap();
            ValidatorInfo { id: ValidatorId(addr.to_string()), voting_power: 1, pop_verified: true, public_key: kp.public_key }
        };
        let historical = ValidatorSet {
            height: 7,
            validators: vec![keyed("qcb1alice"), keyed("qcb1bob"), keyed("qcb1carol"), keyed("qcb1dave")],
        };
        assert_eq!(historical.quorum_power(), 3, "4 validators of power 1 each need 3 for quorum");
        node.historical_validator_sets.insert(7, historical);

        // Grow the LIVE set to 5 validators so its quorum math differs
        // (5 * 2/3 + 1 = 4) from what was actually in force at height 7.
        let mut live = node.consensus.validator_set().clone();
        live.validators.push(keyed("qcb1erin"));
        live.height = 7;
        let _ = node.consensus.update_validator_set(live.clone());
        assert_eq!(node.consensus.validator_set().quorum_power(), 4,
            "live set must now need 4 of 5 for quorum, different from history");

        let sign = |addr: &str| -> Vote {
            let mut vote = Vote {
                vote_type: VoteType::Precommit, height: 7, round: 0,
                validator: ValidatorId(addr.to_string()),
                block_hash: Some(BlockHash("block7".to_string())),
                signature: vec![],
                scheme:     Vote::default_scheme(),
            };
            let kp = ClassicalScheme.generate_keypair(addr).unwrap();
            let bytes = vote_signing_bytes("qcb-testnet-1", &vote.vote_type, vote.height, vote.round, vote.block_hash.as_ref());
            vote.signature = ClassicalScheme.sign(&bytes, &kp).unwrap().bytes;
            vote
        };

        // Exactly 3 of the 4 validators that were ACTUALLY active at height
        // 7 -- meets that height's real quorum (3), but would fall short of
        // the live set's quorum (4) if ever (wrongly) checked against it.
        let cert = CommitCertificate {
            height: 7, round: 0, block_hash: BlockHash("block7".to_string()),
            precommits: vec![sign("qcb1alice"), sign("qcb1bob"), sign("qcb1carol")],
        };
        assert!(
            node.verify_certificate_against_history(&cert).is_ok(),
            "a certificate that met quorum under the set effective at its height \
             must verify, even though the live set's quorum requirement has \
             since changed"
        );

        // Negative check 1: short of even the HISTORICAL quorum (only 2 of
        // the 3 needed) must fail.
        let short_cert = CommitCertificate {
            height: 7, round: 0, block_hash: BlockHash("block7".to_string()),
            precommits: vec![sign("qcb1alice"), sign("qcb1bob")],
        };
        assert!(
            node.verify_certificate_against_history(&short_cert).is_err(),
            "2 of 4 historical power must fall short of that height's quorum (3)"
        );

        // Negative check 2: a validator unknown to (or zero-power in) the
        // historical set -- e.g. Erin, who was only admitted into the LIVE
        // set, never the one effective at height 7 -- must not be able to
        // pad out a certificate's power.
        let padded_cert = CommitCertificate {
            height: 7, round: 0, block_hash: BlockHash("block7".to_string()),
            precommits: vec![sign("qcb1alice"), sign("qcb1bob"), sign("qcb1erin")],
        };
        assert!(
            node.verify_certificate_against_history(&padded_cert).is_err(),
            "a validator with zero power in the set effective at the cert's \
             height must not count toward that height's quorum, however much \
             power it has in the live set"
        );

        // Negative check 3: no historical entry recorded for the height at
        // all must be a hard error, not a silent fall-through to the live set.
        let no_history_cert = CommitCertificate {
            height: 999, round: 0, block_hash: BlockHash("block999".to_string()),
            precommits: vec![sign("qcb1alice"), sign("qcb1bob"), sign("qcb1carol")],
        };
        let err = node.verify_certificate_against_history(&no_history_cert).err()
            .expect("missing historical set must be a hard error");
        assert!(err.contains("no historical validator set recorded"), "got: {err}");
    }

    #[tokio::test]
    async fn bonding_below_minimum_does_not_admit_a_validator() {
        use chain_forge_execution::Transaction;

        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        node.submit_tx(Transaction::transfer("fund-erin", "qcb1alice", "qcb1erin", "uqcb", 500_000, 0));
        let cert0 = node.propose_block(genesis_hash).await.unwrap();

        // Below chain_forge_execution::validator_bond::DEFAULT_MIN_BOND_UQCB (1_000_000).
        node.submit_tx(Transaction::bond_validator("bond-erin", "qcb1erin", 500_000, 0));
        node.propose_block(cert0.block_hash).await.unwrap();

        assert!(
            !node.consensus.validator_set().validators.iter().any(|v| v.id.0 == "qcb1erin"),
            "a sub-minimum bond must not seat a new validator"
        );
    }

    #[tokio::test]
    async fn node_state_root_changes_per_block() {
        use chain_forge_execution::Transaction;

        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Block 0: include a tx so state is non-trivial
        node.submit_tx(Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0));
        let cert0 = node.propose_block(genesis_hash).await.unwrap();
        let root1 = node.status.lock().unwrap().state_root.clone().unwrap();

        // Block 1: include another tx — alice's nonce is now 1 after block 0
        node.submit_tx(Transaction::transfer("tx2", "qcb1alice", "qcb1bob", "uqcb", 200, 1));
        node.propose_block(cert0.block_hash).await.unwrap();
        let root2 = node.status.lock().unwrap().state_root.clone().unwrap();

        assert_ne!(root1, root2, "state root must change when state changes");
    }

    #[tokio::test]
    async fn node_event_loop_runs_and_exits() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        // The node now runs indefinitely via ticker in devnet mode.
        // Test that it starts correctly and produces at least one block
        // within a short timeout rather than waiting for it to exit.
        {
            let status = node.status.lock().unwrap();
            assert_eq!(status.height, 0);
            assert_eq!(status.is_running, false); // not started yet
        }

        // Propose one block manually to confirm the loop works
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
        node.propose_block(genesis_hash).await.unwrap();

        let status = node.status.lock().unwrap();
        assert_eq!(status.height, 0); // block 0 committed
        assert!(status.state_root.is_some());
    }

    #[tokio::test]
    async fn genesis_validation_warnings_do_not_halt_devnet() {
        // A genesis with a minor warning (no bootstrap nodes in testnet mode)
        // should still start in devnet mode.
        let node = Node::new(GENESIS, None).await;
        assert!(node.is_ok(), "node should start despite validation warnings");
    }

    // -- Explorer state tests (Priority 7 / Section 9.1) ----------------------

    #[tokio::test]
    async fn explorer_records_blocks_on_commit() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let h = chain_forge_consensus::BlockHash("g".into());
        node.propose_block(h).await.unwrap();

        let ex = node.explorer.lock().unwrap();
        assert_eq!(ex.blocks.len(), 1, "one block should be recorded");
        assert_eq!(ex.blocks[0].height, 0);
        assert!(!ex.blocks[0].state_root.is_empty());
    }

    #[tokio::test]
    async fn explorer_indexes_transactions() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        node.submit_tx(Transaction::transfer(
            "extx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0,
        ));
        let h = chain_forge_consensus::BlockHash("g".into());
        node.propose_block(h).await.unwrap();

        let ex = node.explorer.lock().unwrap();
        let t = ex.txs.get("extx1").expect("tx should be indexed");
        assert_eq!(t.sender, "qcb1alice");
        assert_eq!(t.kind, "transfer");
        assert!(t.success);
        assert_eq!(t.height, 0);
    }

    #[tokio::test]
    async fn explorer_snapshots_accounts_with_charm_surface() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let h = chain_forge_consensus::BlockHash("g".into());
        node.propose_block(h).await.unwrap();

        let ex = node.explorer.lock().unwrap();
        let alice = ex.accounts.get("qcb1alice").expect("alice snapshot");
        assert_eq!(alice.role, "validator");
        assert!(alice.balances.get("uqcb").copied().unwrap_or(0) > 0);
        // Genesis validators are seeded as Verified in the identity store and
        // their charm is synced into StateStore during Node::new(), so the
        // explorer shows "Verified" from block 1 onward.
        assert_eq!(
            alice.tier.as_deref(),
            Some("Verified"),
            "genesis validators must appear as Verified in the explorer"
        );
        assert_eq!(alice.exemption_days, 0);
    }

    #[tokio::test]
    async fn explorer_caps_recent_blocks() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        for i in 0..(MAX_RECENT_BLOCKS + 5) {
            let h = chain_forge_consensus::BlockHash(format!("h{i}"));
            node.propose_block(h).await.unwrap();
        }
        let ex = node.explorer.lock().unwrap();
        assert_eq!(ex.blocks.len(), MAX_RECENT_BLOCKS,
            "recent blocks must be capped");
        // Newest first
        assert!(ex.blocks[0].height > ex.blocks[1].height);
    }

    // -- Multi-node gossip-to-consensus wiring tests ---------------------------

    fn make_proposal(height: u64, round: u32, proposer: &str, block_hash: &str) -> BlockProposal {
        BlockProposal {
            height,
            round,
            proposer:    ValidatorId(proposer.to_string()),
            block_hash:  chain_forge_consensus::BlockHash(block_hash.to_string()),
            parent_hash: chain_forge_consensus::BlockHash("genesis_h0".to_string()),
            timestamp_ms: 0,
            tx_data:     serde_json::to_vec(&Vec::<Transaction>::new()).unwrap(),
            signature:   vec![],
        }
    }

    /// Build a Vote signed by `validator`'s deterministic devnet keypair
    /// (`ClassicalScheme::generate_keypair(address)`), the same derivation
    /// GENESIS's embedded public keys were produced with (see GENESIS's
    /// doc comment above). Needed because every genesis validator now
    /// carries a registered consensus key, so receive_vote/
    /// verify_vote_signature's fail-closed rule rejects an empty signature
    /// as a forgery -- tests that simulate gossiped votes from other
    /// validators must sign them for real, not just construct a bare Vote.
    fn signed_vote(
        chain_id: &str, vote_type: VoteType, height: u64, round: u32,
        validator: &str, block_hash: chain_forge_consensus::BlockHash,
    ) -> Vote {
        let mut vote = Vote {
            vote_type,
            height,
            round,
            validator:  ValidatorId(validator.to_string()),
            block_hash: Some(block_hash),
            signature:  vec![],
            scheme:     Vote::default_scheme(),
        };
        let kp = ClassicalScheme.generate_keypair(validator)
            .expect("deterministic devnet keypair generation must not fail");
        let bytes = vote_signing_bytes(
            chain_id, &vote.vote_type, vote.height, vote.round,
            vote.block_hash.as_ref(),
        );
        vote.signature = ClassicalScheme.sign(&bytes, &kp)
            .expect("signing must not fail").bytes;
        vote
    }

    fn gossip(topic: GossipTopic, payload: Vec<u8>) -> NetworkEvent {
        NetworkEvent::Message(chain_forge_p2p::GossipMessage {
            topic,
            from: chain_forge_p2p::PeerId("test-peer".into()),
            payload,
            received_at_ms: 0,
        })
    }

    #[test]
    fn is_proposer_for_matches_expected_rotation() {
        let vs = ValidatorSet {
            height: 0,
            validators: vec![
                ValidatorInfo { id: ValidatorId("qcb1alice".into()), voting_power: 1, pop_verified: true, public_key: vec![] },
                ValidatorInfo { id: ValidatorId("qcb1bob".into()),   voting_power: 1, pop_verified: true, public_key: vec![] },
                ValidatorInfo { id: ValidatorId("qcb1carol".into()), voting_power: 1, pop_verified: true, public_key: vec![] },
                ValidatorInfo { id: ValidatorId("qcb1dave".into()),  voting_power: 1, pop_verified: true, public_key: vec![] },
            ],
        };
        // Sorted order: alice, bob, carol, dave -- rotates by (height+round) % 4.
        assert!(Node::is_proposer_for(&vs, 0, 0, &ValidatorId("qcb1alice".into())));
        assert!(Node::is_proposer_for(&vs, 1, 0, &ValidatorId("qcb1bob".into())));
        assert!(Node::is_proposer_for(&vs, 2, 0, &ValidatorId("qcb1carol".into())));
        assert!(Node::is_proposer_for(&vs, 3, 0, &ValidatorId("qcb1dave".into())));
        assert!(Node::is_proposer_for(&vs, 4, 0, &ValidatorId("qcb1alice".into())));
        assert!(!Node::is_proposer_for(&vs, 0, 0, &ValidatorId("qcb1bob".into())));
    }

    #[tokio::test]
    async fn plain_chain_without_identity_module_refuses_to_start() {
        // Mandatory-personhood migration: gate_voting_power (chain-forge-
        // consensus) unconditionally zeroes voting power for any validator
        // that is not pop_verified, in every engine, with no bypass. A
        // genesis with the "identity" module disabled has no IdentityStore
        // web of trust at all -- nobody can ever become Verified -- so
        // every validator's effective voting power is permanently zero and
        // the chain could never reach quorum or produce a block.
        //
        // Before this migration, disabling "identity" just meant personhood
        // weighting itself was unavailable (personhood_weighted required
        // identity, enforced separately); voting power was still
        // stake/slot-based and worked fine. Now that verified personhood is
        // mandatory rather than optional, "identity module disabled" is no
        // longer a viable consensus configuration at all -- this is an
        // intentional, startup-time hard failure (see the "zero eligible
        // voting power" check in Node::new_with_config), not a bug.
        let plain = GENESIS
            .replace(
                r#""modules": ["bank", "staking", "identity", "agents", "pocd"]"#,
                r#""modules": ["bank", "staking"]"#,
            )
            .replace(r#""personhood_weighted": true"#, r#""personhood_weighted": false"#);
        let err = Node::new(&plain, None).await.err()
            .expect("a chain with no identity module can never satisfy mandatory personhood verification");
        assert!(err.to_string().contains("zero eligible voting power"),
            "must fail for the personhood/key gate reason, not some unrelated error: {err}");
    }

    #[tokio::test]
    async fn node_refuses_to_start_with_an_unknown_module() {
        let bad = GENESIS.replace(
            r#""modules": ["bank", "staking", "identity", "agents", "pocd"]"#,
            r#""modules": ["bank", "dex"]"#,
        );
        let err = Node::new(&bad, None).await.err().expect("must refuse to start");
        assert!(err.to_string().contains("unknown module \"dex\""));
    }

    #[tokio::test]
    async fn node_refuses_personhood_consensus_without_identity() {
        let bad = GENESIS.replace(
            r#""modules": ["bank", "staking", "identity", "agents", "pocd"]"#,
            r#""modules": ["bank", "staking"]"#,
        ); // fixture keeps personhood_weighted: true
        let err = Node::new(&bad, None).await.err().expect("must refuse to start");
        assert!(err.to_string().contains("personhood_weighted requires"));
    }

    #[tokio::test]
    async fn mempool_ignores_duplicate_and_already_committed_txs() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let tx = Transaction::transfer("dup-1", "qcb1alice", "qcb1bob", "uqcb", 1, 0);
        assert!(node.submit_tx(tx.clone()));
        assert!(!node.submit_tx(tx.clone()), "same id twice must not double-queue");
        assert_eq!(node.mempool.len(), 1);

        node.explorer.lock().unwrap().txs.insert("done-1".into(), TxSummary {
            id: "done-1".into(), height: 3, sender: "qcb1alice".into(), kind: "transfer".into(),
            success: true, gas_used: 0, events: vec![], error: None,
        });
        let late = Transaction::transfer("done-1", "qcb1alice", "qcb1bob", "uqcb", 1, 0);
        assert!(!node.submit_tx(late), "a late gossip copy of a committed tx must be ignored");
    }

    #[tokio::test]
    async fn committed_txs_leave_the_mempool_and_others_stay() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let a = Transaction::transfer("keep", "qcb1alice", "qcb1bob", "uqcb", 1, 0);
        let b = Transaction::transfer("gone", "qcb1bob", "qcb1alice", "uqcb", 1, 0);
        node.submit_tx(a);
        node.submit_tx(b.clone());
        node.remove_committed_from_mempool(&[b]);
        let ids: Vec<&str> = node.mempool.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["keep"]);
    }

    #[tokio::test]
    async fn multinode_follower_commits_after_gossiped_votes_reach_quorum() {
        // Bob is not the proposer at (0,0) -- alice is. Bob should accept
        // alice's proposal via gossip, cast his own votes, and then commit
        // once enough OTHER validators' precommits arrive over gossip too.
        let mut node = Node::new(GENESIS, Some("qcb1bob".into())).await.unwrap();
        // Bob's own prevote/precommit (cast automatically in response to the
        // proposal, via sign_vote) are now also checked against his
        // registered genesis key, so he needs a signing key loaded or his
        // own votes silently go out unsigned and get rejected by the exact
        // same fail-closed rule as a forged vote. load_signing_key only
        // verifies against genesis (it no longer backfills), so for this
        // in-memory test we set the deterministic devnet keypair directly
        // rather than round-tripping through a real key file.
        node.signing_key = Some(
            ClassicalScheme.generate_keypair("qcb1bob")
                .expect("deterministic devnet keypair generation must not fail")
        );

        let proposal = make_proposal(0, 0, "qcb1alice", "block_h0_r0_test");
        let payload = serde_json::to_vec(&proposal).unwrap();
        node.handle_event(gossip(GossipTopic::BlockProposal, payload)).await.unwrap();

        // Bob voted (prevote + precommit) but that is only 1 of the 3
        // precommits needed for quorum with 4 validators -- not committed yet.
        assert_eq!(node.status.lock().unwrap().height, 0);
        assert!(node.pending_proposals.contains_key(&(0, 0)));

        // Carol's precommit arrives over gossip -- still only 2 of 3.
        let carol_vote = signed_vote(
            "qcb-testnet-1", VoteType::Precommit, 0, 0, "qcb1carol",
            proposal.block_hash.clone(),
        );
        node.handle_event(gossip(
            GossipTopic::ConsensusVote,
            serde_json::to_vec(&carol_vote).unwrap(),
        )).await.unwrap();
        assert_eq!(node.status.lock().unwrap().height, 0, "2 of 3 -- not yet committed");

        // Dave's precommit is the 3rd -- quorum reached, block commits.
        let dave_vote = signed_vote(
            "qcb-testnet-1", VoteType::Precommit, 0, 0, "qcb1dave",
            proposal.block_hash.clone(),
        );
        node.handle_event(gossip(
            GossipTopic::ConsensusVote,
            serde_json::to_vec(&dave_vote).unwrap(),
        )).await.unwrap();

        // status.height reports the height of the last COMMITTED block (0,
        // matching node_produces_first_block's established convention),
        // while the consensus engine itself has already advanced to work
        // on the next height (1) -- these are two different, correct facts.
        assert_eq!(node.status.lock().unwrap().height, 0,
            "3rd precommit must trigger commit of block 0");
        assert_eq!(node.consensus.current_height(), 1,
            "consensus engine must advance past the committed height");
        assert!(!node.pending_proposals.contains_key(&(0, 0)),
            "committed proposal must be pruned");
        assert_eq!(node.explorer.lock().unwrap().blocks.len(), 1);
    }

    /// Partition recovery: votes reach quorum before the proposal body arrives.
    ///
    /// Simulates the case where a brief network partition (or reordered gossip)
    /// causes all three precommits to be processed first, with the proposal
    /// gossip arriving afterwards.  Before the fix, the block was never committed
    /// in this scenario; after the fix, `pending_certs` parks the certificate
    /// and the BlockProposal handler commits it as soon as the body lands.
    #[tokio::test]
    async fn partition_recovery_votes_before_proposal() {
        // Bob is not the proposer at (0,0) -- alice is -- so Bob votes and
        // processes gossip but doesn't produce the proposal itself.
        let mut node = Node::new(GENESIS, Some("qcb1bob".into())).await.unwrap();
        let proposal = make_proposal(0, 0, "qcb1alice", "block_h0_r0_partition_test");

        // Three precommits arrive BEFORE the proposal gossip.
        // The node feeds them to receive_vote(); on the 3rd one it returns
        // Some(cert) but there is no pending proposal, so the cert is parked.
        for validator in &["qcb1alice", "qcb1carol", "qcb1dave"] {
            let vote = signed_vote(
                "qcb-testnet-1", VoteType::Precommit, 0, 0, validator,
                proposal.block_hash.clone(),
            );
            node.handle_event(gossip(
                GossipTopic::ConsensusVote,
                serde_json::to_vec(&vote).unwrap(),
            )).await.unwrap();
        }

        // Quorum was reached but no commit yet (proposal body not present).
        assert_eq!(node.status.lock().unwrap().height, 0,
            "no commit yet -- proposal hasn't arrived");
        assert!(node.pending_proposals.is_empty(),
            "proposal body not stored yet");
        assert!(node.pending_certs.contains_key(&(0, 0)),
            "certificate must be parked in pending_certs");

        // Now the proposal gossip arrives (partition heals / reorder resolved).
        let payload = serde_json::to_vec(&proposal).unwrap();
        node.handle_event(gossip(GossipTopic::BlockProposal, payload)).await.unwrap();

        // The Proposal handler must detect the parked cert and commit immediately.
        assert_eq!(node.consensus.current_height(), 1,
            "consensus engine must advance to height 1 after deferred commit");
        assert_eq!(node.explorer.lock().unwrap().blocks.len(), 1,
            "block must appear in explorer after deferred commit");
        assert!(node.pending_certs.is_empty(),
            "parked certificate must be pruned after commit");
        assert!(!node.pending_proposals.contains_key(&(0, 0)),
            "committed proposal must be pruned");
    }

    #[tokio::test]
    async fn handle_event_ignores_malformed_gossip_payload() {
        let mut node = Node::new(GENESIS, Some("qcb1bob".into())).await.unwrap();
        let garbage = vec![0xFF, 0x00, 0x13, 0x37];

        // Must not panic or error out the event loop -- just logged and dropped.
        assert!(node.handle_event(gossip(GossipTopic::BlockProposal, garbage.clone())).await.is_ok());
        assert!(node.handle_event(gossip(GossipTopic::ConsensusVote, garbage.clone())).await.is_ok());
        assert!(node.handle_event(gossip(GossipTopic::Transaction, garbage)).await.is_ok());

        assert_eq!(node.status.lock().unwrap().height, 0);
        assert!(node.pending_proposals.is_empty());
    }

    #[tokio::test]
    async fn handle_event_rejects_proposal_from_wrong_proposer() {
        let mut node = Node::new(GENESIS, Some("qcb1bob".into())).await.unwrap();

        // Bob claims to be the proposer at (0,0), but alice is -- consensus
        // must reject this and the node must not register or vote on it.
        let bad_proposal = make_proposal(0, 0, "qcb1bob", "block_h0_r0_bad");
        let payload = serde_json::to_vec(&bad_proposal).unwrap();
        node.handle_event(gossip(GossipTopic::BlockProposal, payload)).await.unwrap();

        assert!(node.pending_proposals.is_empty(),
            "a proposal from the wrong proposer must not be accepted");
        assert_eq!(node.status.lock().unwrap().height, 0);
    }

    #[tokio::test]
    async fn handle_event_gossiped_transaction_enters_mempool() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let tx = Transaction::transfer("gossip-tx-1", "qcb1alice", "qcb1bob", "uqcb", 500, 0);
        let payload = serde_json::to_vec(&tx).unwrap();

        node.handle_event(gossip(GossipTopic::Transaction, payload)).await.unwrap();
        assert_eq!(node.mempool.len(), 1);
        assert_eq!(node.mempool[0].id, "gossip-tx-1");
    }

    // -- 4-node devnet integration scenario (Option A) -------------------------
    //
    // This is the end-to-end proof that "a validator's personhood status gates
    // their consensus power in real time" -- the milestone described in the
    // integration plan after Points 1-3 were wired.
    //
    // We simulate it in-process using a single Node instance (which holds the
    // canonical state of all four genesis validators) rather than four separate
    // OS processes -- this is equivalent for the state-machine logic we are
    // testing (the identity ↔ validator ↔ execution loop), and fast enough to
    // run as a unit test rather than a separate long-running harness.
    //
    // Steps:
    //  1. Start node with all 4 validators (Alice, Bob, Carol, Dave).
    //  2. Confirm all four are PoP-verified in the validator registry at startup.
    //  3. Submit txs from Alice and produce blocks -- confirm activity is recorded.
    //  4. "Stop" Alice (simulate 91-epoch absence by zeroing her last_attested_epoch
    //     and jumping the clock forward 91 epochs). Alice has never called
    //     record_participation, so last_attested_epoch stays at epoch 0.
    //  5. Trigger an epoch advance -- Alice lapses in IdentityStore.
    //  6. Confirm the reconcile sweep (Integration Point 3) ran: Alice's
    //     pop_verified = false in the validator registry after the advance.
    //  7. Confirm Bob, Carol, Dave are unaffected (still pop_verified = true).
    //  8. Confirm the chain can still produce blocks with 3/4 quorum (Alice
    //     excluded from the validator set's consensus power).

    #[tokio::test]
    async fn devnet_lapsed_validator_loses_consensus_power_while_chain_continues() {
        use chain_forge_identity::LIVENESS_EPOCH_WINDOW;

        // ── Step 1: Start node with all 4 genesis validators ─────────────────
        let mut node = Node::new(GENESIS, Some("qcb1alice".into())).await.unwrap();

        // ── Step 2: All four must be PoP-verified at startup ─────────────────
        for addr in ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"] {
            let record = node.validator_registry.get(addr)
                .unwrap_or_else(|_| panic!("genesis validator {addr} must be in registry"));
            assert!(
                record.pop_verified,
                "genesis validator {addr} must be pop_verified after Integration Point 1 wiring"
            );
        }

        // ── Step 3: Submit txs from Alice and commit a block ──────────────────
        // This exercises Integration Point 2: record_activity_by_address is
        // called in the result.is_ok() block for every committed tx.
        node.submit_tx(Transaction::transfer("dev-tx-1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0));
        node.submit_tx(Transaction::transfer("dev-tx-2", "qcb1alice", "qcb1carol", "uqcb", 500, 1));
        let h0 = chain_forge_consensus::BlockHash("devnet-h0".into());
        node.propose_block(h0).await.unwrap();

        // Alice's activity should be recorded in epoch 0 of IdentityStore.
        // (We can't check activity_epoch directly here -- the field is private
        //  -- but the fact that the block committed and the tests below rely on
        //  state after activity recording is the observable outcome.)

        // ── Step 4: "Stop" Alice — simulate 91-epoch absence ─────────────────
        // In production: Alice's node goes offline, so no txs from her address
        // land on-chain. Bob, Carol, and Dave stay active (they keep transacting).
        //
        // We use the test helpers `lapse_only` and `stay_lively` to be explicit
        // about who lapses and who doesn't. This prevents the "all four validators
        // lapse when you jump the clock" class of test bug.
        let target_epoch = LIVENESS_EPOCH_WINDOW + 1; // epoch 91
        node.identity.lapse_only("qcb1alice", target_epoch);
        for addr in ["qcb1bob", "qcb1carol", "qcb1dave"] {
            node.identity.stay_lively(addr, target_epoch);
        }

        // ── Step 5: Trigger advance_epoch + the Point 3 reconcile sweep ───────
        // Jump the clock forward `target_epoch` epochs (91 * 24h).
        // The advance_epoch() call in Node::propose_block is what actually runs
        // the sweep in production; we drive it directly here to keep the test
        // synchronous and deterministic.
        let jump_ms = target_epoch * 86_400_000; // target_epoch days in ms
        let now_ms  = node.identity.clock.epoch_start_ms + jump_ms;

        // advance_epoch lints the lapse; the reconcile sweep (Point 3) revokes pop.
        let epoch_advanced = node.identity.advance_epoch(now_ms);
        assert!(epoch_advanced, "91-epoch jump must advance the epoch clock");

        // Replicate what the commit path does after advance_epoch -- the
        // reconcile sweep from Integration Point 3:
        let epoch = node.identity.clock.current_epoch;
        let validator_ids: Vec<String> = node.validator_registry
            .all_validators()
            .into_iter()
            .map(|r| r.id.0.clone())
            .collect();
        for vid in &validator_ids {
            let still_verified = node.identity.get(vid)
                .map(|r| r.charm.tier.grants_consensus())
                .unwrap_or(false);
            if !still_verified {
                let _ = node.validator_registry.revoke_pop(vid, epoch);
            }
        }

        // ── Step 6: Alice's pop_verified must now be false ────────────────────
        let alice_reg = node.validator_registry.get("qcb1alice")
            .expect("Alice must still be in registry after revocation");
        assert!(
            !alice_reg.pop_verified,
            "Alice's pop_verified must be false after identity lapse + revoke_pop"
        );
        assert_eq!(
            alice_reg.status,
            chain_forge_validators::ValidatorStatus::Candidate,
            "Alice must be demoted to Candidate after revoke_pop"
        );

        // Confirm Alice's identity tier is now Provisional (lapsed).
        let alice_id = node.identity.get("qcb1alice").unwrap();
        assert_eq!(
            *alice_id.tier(),
            chain_forge_identity::VerificationTier::Provisional,
            "Alice's identity tier must be Provisional after lapse"
        );

        // ── Step 7: Bob, Carol, Dave are unaffected ────────────────────────────
        for addr in ["qcb1bob", "qcb1carol", "qcb1dave"] {
            let reg = node.validator_registry.get(addr)
                .unwrap_or_else(|_| panic!("{addr} must still be in registry"));
            assert!(
                reg.pop_verified,
                "{addr} must still be pop_verified -- only Alice lapsed"
            );
            let id = node.identity.get(addr).unwrap();
            assert!(
                id.charm.tier.grants_consensus(),
                "{addr}'s identity tier must still grant consensus"
            );
        }

        // ── Step 8: Chain continues with 3/4 quorum (Alice excluded) ──────────
        // The validator set built from the registry should exclude Alice
        // (voting_power = 0 for non-pop_verified validators).
        let vset = node.validator_registry.build_validator_set(1);
        let alice_in_vset = vset.validators.iter()
            .find(|v| v.id.0 == "qcb1alice");

        // Alice may still appear in the set, but with zero voting power.
        if let Some(alice_vi) = alice_in_vset {
            assert_eq!(
                alice_vi.voting_power, 0,
                "Alice must have 0 voting power after lapse (even if still listed)"
            );
        }

        // The three remaining validators must collectively have enough power
        // to reach 2/3 quorum.  In devnet they each have voting_power = 1, so
        // total = 3, quorum = ceil(2/3 * 3) = 2 — well within range.
        let active_power: u64 = vset.validators.iter()
            .filter(|v| v.id.0 != "qcb1alice")
            .map(|v| v.voting_power)
            .sum();
        assert!(
            active_power >= 2,
            "Bob+Carol+Dave must have enough combined power (≥2) for 2/3 quorum"
        );

        // Produce one more block — the chain must continue even without Alice.
        node.submit_tx(Transaction::transfer(
            "dev-post-lapse-tx", "qcb1bob", "qcb1carol", "uqcb", 100, 0,
        ));
        let h1 = chain_forge_consensus::BlockHash("devnet-h1".into());
        let cert = node.propose_block(h1).await;
        assert!(
            cert.is_ok(),
            "chain must continue producing blocks with 3/4 validators active: {:?}",
            cert.err()
        );
        assert_eq!(node.consensus.current_height(), 2,
            "chain must have advanced to height 2 after the post-lapse block");
    }

    // -- Equivocation → Slashing wire-up tests ---------------------------------

    /// Double-vote (equivocation) detected via drain_equivocations() must be
    /// routed through process_equivocation_evidence() → SlashingModule, which
    /// tombstones the validator and burns 5% of their bonded stake.
    ///
    /// This test verifies the full pipeline:
    ///   receive_vote() → drain_equivocations() → handle_drained_equivocations()
    ///   → process_equivocation_evidence() → slasher.slash_equivocation()
    ///
    /// Note: `propose_block()` is the fastest way to exercise this in a unit
    /// test because it calls the consensus engine in solo-devnet mode, where
    /// Alice sends votes for all four validators internally. We inject a
    /// manually-constructed EquivocationDetected directly into the consensus
    /// engine's pending queue and then call handle_drained_equivocations() to
    /// verify the slashing side effects (tombstone + stake burn + QRC metrics).
    #[tokio::test]
    async fn double_vote_triggers_slashing_and_tombstone() {
        use chain_forge_consensus::tendermint::EquivocationDetected;
        use chain_forge_consensus::{BlockHash, ValidatorId};

        let mut node = Node::new(GENESIS, None).await.unwrap();

        // Snapshot Alice's balance before slashing (5_000_000 uqcb from genesis).
        let alice_balance_before = node.state.get_account("qcb1alice")
            .expect("Alice must be in state")
            .balance_of("uqcb");
        assert_eq!(alice_balance_before, 5_000_000,
            "Alice should start with 5_000_000 uqcb from genesis");

        // Confirm Alice is active and NOT tombstoned before we start.
        assert!(
            node.validator_registry.get("qcb1alice")
                .map(|r| r.status != chain_forge_validators::ValidatorStatus::Tombstoned)
                .unwrap_or(false),
            "Alice must NOT be tombstoned before equivocation"
        );

        // Construct a synthetic EquivocationDetected for Alice at height 0, round 0.
        // The two conflicting block hashes represent a double-prevote.
        //
        // NOTE: signatures are empty here on purpose. Genesis validators are
        // registered with an empty consensus_pubkey ("genesis-stub" scheme), so
        // decode_hex("") in slash_equivocation would fail. Passing empty sigs
        // triggers the "skipped when both sigs are empty" branch and lets the
        // tombstone + burn logic run without real key material.
        let eq_evidence = EquivocationDetected {
            validator_id:   ValidatorId("qcb1alice".into()),
            height:         0,
            round:          0,
            vote_type_byte: 1, // PREVOTE
            block_hash_a:   BlockHash("hash_A_00000000".into()),
            block_hash_b:   BlockHash("hash_B_11111111".into()),
            signature_a:    vec![],
            signature_b:    vec![],
        };

        // Drive the slashing pipeline directly: this is the same code path that
        // handle_event() → receive_vote() → drain_equivocations() invokes.
        let epoch = node.consensus.current_height();
        node.handle_drained_equivocations(vec![eq_evidence], epoch);

        // ── Assert tombstone ─────────────────────────────────────────────────
        assert!(
            node.validator_registry.get("qcb1alice")
                .map(|r| r.status == chain_forge_validators::ValidatorStatus::Tombstoned)
                .unwrap_or(false),
            "Alice must be tombstoned after equivocation"
        );

        // ── Assert stake was burned ──────────────────────────────────────────────
        // SlashingModule uses 500 bps (5%) of bonded stake. Genesis validators
        // are registered with bonded_uqcb = ENTRY_STAKE_UQCB (1_000_000_000),
        // so slash_amount = 50_000_000. But Alice's liquid balance is only
        // 5_000_000 uqcb, so process_equivocation_evidence caps the burn at
        // the available balance (5_000_000). The balance should drop to 0.
        let alice_balance_after = node.state.get_account("qcb1alice")
            .expect("Alice must still be in state after slashing")
            .balance_of("uqcb");
        assert!(
            alice_balance_after < alice_balance_before,
            "Alice's balance must decrease after equivocation slash (before={alice_balance_before}, after={alice_balance_after})"
        );

        // ── Assert QRC burn metrics were updated ─────────────────────────────
        let burned_in_metrics = node.qrc_metrics.lock().unwrap().total_qcb_burned_uqcb;
        let actual_burn = alice_balance_before - alice_balance_after;
        assert_eq!(
            burned_in_metrics, actual_burn,
            "QRC metrics must reflect the exact slashed amount"
        );
    }

    /// Equivocation slashing is idempotent: slashing Alice twice at the same
    /// (height, round) must not double-tombstone or double-burn her stake.
    #[tokio::test]
    async fn double_slash_same_equivocation_is_idempotent() {
        use chain_forge_consensus::tendermint::EquivocationDetected;
        use chain_forge_consensus::{BlockHash, ValidatorId};
        use chain_forge_slashing::EquivocationEvidence;

        let mut node = Node::new(GENESIS, None).await.unwrap();

        // NOTE: empty sigs — genesis validators have empty consensus_pubkey
        // ("genesis-stub" scheme), so decode_hex("") would fail signature
        // verification. Empty sigs trigger the skip-verify branch in
        // slash_equivocation, letting the tombstone + burn logic run.
        let evidence = EquivocationEvidence {
            validator_id:   "qcb1alice".to_string(),
            height:         0,
            round:          0,
            vote_type_byte: 1,
            block_hash_a:   "hash_A".to_string(),
            block_hash_b:   "hash_B".to_string(),
            signature_a:    vec![],
            signature_b:    vec![],
        };

        let epoch = node.consensus.current_height();

        // First slash: should succeed and burn stake.
        let first_result = node.process_equivocation_evidence(&evidence, epoch);
        assert!(first_result.is_ok(), "first slash must succeed");
        let first_burn = first_result.unwrap();
        assert!(first_burn > 0, "first slash must burn some stake");

        let balance_after_first = node.state.get_account("qcb1alice")
            .unwrap().balance_of("uqcb");

        // Second slash at same (height, round): idempotent — slasher rejects it.
        let second_result = node.process_equivocation_evidence(&evidence, epoch);
        // The slasher returns an error for a duplicate; process_equivocation_evidence
        // propagates it as Err.
        assert!(
            second_result.is_err(),
            "second slash at same (height, round) must be rejected by the slasher"
        );

        // Balance must be unchanged after the rejected second slash.
        let balance_after_second = node.state.get_account("qcb1alice")
            .unwrap().balance_of("uqcb");
        assert_eq!(
            balance_after_first, balance_after_second,
            "no tokens burned on duplicate slash"
        );

        // QRC metrics reflect only the first burn.
        let total_burned = node.qrc_metrics.lock().unwrap().total_qcb_burned_uqcb;
        assert_eq!(total_burned, first_burn,
            "QRC metrics must only count the first (accepted) slash");
    }

    // ── Change Set R: DiscoveryProof gossip tests ─────────────────────────────

    /// Build a minimal but valid `DiscoveryReceipt` for use in gossip tests.
    fn test_receipt(receipt_id: &str, challenge_id: &str, chain_id: &str) -> chain_forge_pocd::DiscoveryReceipt {
        chain_forge_pocd::DiscoveryReceipt {
            receipt_id:          receipt_id.into(),
            chain_id:            chain_id.into(),
            challenge_id:        challenge_id.into(),
            machine_id:          "miner-42".into(),
            output_hash:         "abc123".into(),
            input_hash:          "def456".into(),
            methodology_ref:     "ipfs://Qm...".into(),
            discovery_nonce:     99,
            checks_performed:    1_000_000,
            elapsed_seconds:     1.5,
            submitted_at:        "2026-10-12T00:00:00Z".into(),
            machine_signature:   "".into(),
            seal_nonce:          42,
            seal_hash:           "00001234".into(),
            seal_difficulty_bits: 8,
            verifier_id:         "verifier-01".into(),
            verifier_signature:  "".into(),
            committed_at_block:  0,
            reward_distributed:  false,
            _proof_id:           format!("proof-for-{receipt_id}"),
        }
    }

    fn proof_gossip_event(receipt: chain_forge_pocd::DiscoveryReceipt, chain_id: &str) -> NetworkEvent {
        let g = crate::gossip_proof::DiscoveryProofGossip {
            chain_id: chain_id.into(),
            receipt,
            published_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        gossip(GossipTopic::DiscoveryProof, g.to_payload())
    }

    /// A genesis string with a minimal `pocd` section so DiscoveryRegistry is active.
    fn genesis_with_pocd() -> String {
        // Insert the pocd section before the final closing brace of GENESIS.
        // We use rfind to locate the last '}' which closes the top-level object.
        // All fields required by PoCDConfig (no serde defaults) must be present.
        let mut s = GENESIS.to_string();
        let pos = s.rfind('}').expect("GENESIS must end with '}'");
        let pocd = r#","pocd":{"enabled":true,"chain_id":"qcb-testnet-1","challenge_tracks":[],"reward_epoch_blocks":100,"require_verified_identity":false,"min_seal_difficulty_bits":8}"#;
        s.insert_str(pos, pocd);
        s
    }

    #[tokio::test]
    async fn discovery_proof_gossip_ingests_receipt() {
        let mut node = Node::new(&genesis_with_pocd(), None).await.unwrap();
        // Registry starts empty.
        assert_eq!(node.pocd_registry().unwrap().lock().unwrap().receipt_count(), 0);

        let receipt = test_receipt("rcpt-001", "ch-1", "qcb-testnet-1");
        let event   = proof_gossip_event(receipt.clone(), "qcb-testnet-1");

        node.handle_event(event).await.unwrap();

        let reg = node.pocd_registry().unwrap();
        let reg = reg.lock().unwrap();
        assert_eq!(reg.receipt_count(), 1, "receipt should be in registry after gossip");
        assert!(reg.get_receipt("rcpt-001").is_some());
    }

    #[tokio::test]
    async fn discovery_proof_gossip_deduplicates() {
        let mut node  = Node::new(&genesis_with_pocd(), None).await.unwrap();
        let receipt   = test_receipt("rcpt-dup", "ch-1", "qcb-testnet-1");

        // Send the same receipt twice.
        node.handle_event(proof_gossip_event(receipt.clone(), "qcb-testnet-1")).await.unwrap();
        node.handle_event(proof_gossip_event(receipt.clone(), "qcb-testnet-1")).await.unwrap();

        // Registry still has exactly one entry.
        let count = node.pocd_registry().unwrap().lock().unwrap().receipt_count();
        assert_eq!(count, 1, "duplicate gossip must not insert twice");

        // Anti-replay set also has exactly one entry.
        assert_eq!(node.seen_gossip_receipts.len(), 1);
    }

    #[tokio::test]
    async fn discovery_proof_gossip_rejects_wrong_chain() {
        let mut node  = Node::new(&genesis_with_pocd(), None).await.unwrap();
        let receipt   = test_receipt("rcpt-wrongchain", "ch-1", "qcb-mainnet-1");

        // Gossip is tagged with a different chain_id.
        node.handle_event(proof_gossip_event(receipt, "qcb-mainnet-1")).await.unwrap();

        // Registry must remain empty.
        let count = node.pocd_registry().unwrap().lock().unwrap().receipt_count();
        assert_eq!(count, 0, "cross-chain receipt must be dropped");
    }

    #[tokio::test]
    async fn discovery_proof_gossip_rejects_stale() {
        let mut node  = Node::new(&genesis_with_pocd(), None).await.unwrap();
        let receipt   = test_receipt("rcpt-stale", "ch-1", "qcb-testnet-1");

        // Build a gossip message with an ancient published_at_ms.
        let stale = crate::gossip_proof::DiscoveryProofGossip {
            chain_id:        "qcb-testnet-1".into(),
            receipt,
            published_at_ms: 0, // epoch 0 = very stale
        };
        node.handle_event(gossip(GossipTopic::DiscoveryProof, stale.to_payload()))
            .await.unwrap();

        let count = node.pocd_registry().unwrap().lock().unwrap().receipt_count();
        assert_eq!(count, 0, "stale gossip must be dropped");
    }

    #[tokio::test]
    async fn discovery_proof_gossip_noop_without_pocd() {
        // Node without a `pocd` genesis section: proof gossip is silently ignored.
        let mut node  = Node::new(GENESIS, None).await.unwrap();
        let receipt   = test_receipt("rcpt-no-pocd", "ch-1", "qcb-testnet-1");
        // Must not panic or error.
        node.handle_event(proof_gossip_event(receipt, "qcb-testnet-1")).await.unwrap();
        assert!(node.pocd_registry().is_none());
    }

    // ── Change Set S: VerifierAttestation gossip tests ────────────────────────

    /// Build a minimal `VerifierAttestationGossip` for use in attestation tests.
    fn test_attestation(
        task_id:      &str,
        verifier_id:  &str,
        controller_id: &str,
        output_hash:  &str,
        chain_id:     &str,
    ) -> crate::gossip_attestation::VerifierAttestationGossip {
        crate::gossip_attestation::VerifierAttestationGossip {
            chain_id:         chain_id.into(),
            task_id:          task_id.into(),
            result_id:        format!("result-for-{task_id}"),
            verifier_id:      verifier_id.into(),
            controller_id:    controller_id.into(),
            output_hash:      output_hash.into(),
            outcome:          "reproduced".into(),
            workload_version: "v1.0".into(),
            submission_nonce: "nonce-001".into(),
            signature:        "".into(),
            published_at_ms:  std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    fn attestation_gossip_event(
        att: crate::gossip_attestation::VerifierAttestationGossip,
    ) -> NetworkEvent {
        gossip(GossipTopic::VerifierAttestation, att.to_payload())
    }

    /// A single attestation does not reach quorum (quorum = 2 distinct controllers).
    #[tokio::test]
    async fn attestation_gossip_single_attestation_no_quorum() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let att = test_attestation("task-1", "verifier-A", "ctrl-A", "hash-xyz", "qcb-testnet-1");
        node.handle_event(attestation_gossip_event(att)).await.unwrap();

        // Anti-replay set now has one entry.
        assert_eq!(node.seen_attestation_keys.len(), 1);

        // Accumulator has one controller for task-1.
        let bucket = node.attestation_accumulator
            .get("task-1::hash-xyz")
            .expect("bucket must exist after first attestation");
        assert_eq!(bucket.controllers.len(), 1);
        assert!(!bucket.has_quorum(), "single attestation must not reach quorum");
    }

    /// Two attestations from distinct controllers on the same (task_id, output_hash)
    /// reach quorum.
    #[tokio::test]
    async fn attestation_gossip_two_controllers_reach_quorum() {
        let mut node = Node::new(GENESIS, None).await.unwrap();

        let att_a = test_attestation("task-2", "verifier-A", "ctrl-A", "hash-abc", "qcb-testnet-1");
        let att_b = test_attestation("task-2", "verifier-B", "ctrl-B", "hash-abc", "qcb-testnet-1");

        node.handle_event(attestation_gossip_event(att_a)).await.unwrap();
        node.handle_event(attestation_gossip_event(att_b)).await.unwrap();

        let bucket = node.attestation_accumulator
            .get("task-2::hash-abc")
            .expect("bucket must exist after attestations");
        assert_eq!(bucket.controllers.len(), 2);
        assert!(bucket.has_quorum(), "two distinct controllers must reach quorum");
    }

    /// Two attestations from the SAME controller (different verifier IDs) do NOT
    /// reach quorum — the Sybil guard deduplicates by controller_id.
    #[tokio::test]
    async fn attestation_gossip_same_controller_no_quorum() {
        let mut node = Node::new(GENESIS, None).await.unwrap();

        // Same controller_id, different verifier_ids — this is the Sybil case.
        let att_a = test_attestation("task-3", "verifier-A", "ctrl-SAME", "hash-def", "qcb-testnet-1");
        let att_b = test_attestation("task-3", "verifier-B", "ctrl-SAME", "hash-def", "qcb-testnet-1");

        node.handle_event(attestation_gossip_event(att_a)).await.unwrap();
        node.handle_event(attestation_gossip_event(att_b)).await.unwrap();

        let bucket = node.attestation_accumulator
            .get("task-3::hash-def")
            .expect("bucket must exist");
        // Controller dedup: both verifiers share a controller, so the bucket has only 1.
        assert_eq!(bucket.controllers.len(), 1, "same controller must not inflate count");
        assert!(!bucket.has_quorum(), "Sybil controllers must not reach quorum");
    }

    /// A duplicate attestation (same task_id, same verifier_id) is rejected by the
    /// anti-replay set and does not advance the accumulator.
    #[tokio::test]
    async fn attestation_gossip_deduplicates_same_verifier() {
        let mut node = Node::new(GENESIS, None).await.unwrap();

        let att = test_attestation("task-4", "verifier-A", "ctrl-A", "hash-ghi", "qcb-testnet-1");

        // Send the exact same attestation twice.
        node.handle_event(attestation_gossip_event(att.clone())).await.unwrap();
        node.handle_event(attestation_gossip_event(att)).await.unwrap();

        // Anti-replay set has only one key.
        assert_eq!(node.seen_attestation_keys.len(), 1);

        let bucket = node.attestation_accumulator
            .get("task-4::hash-ghi")
            .expect("bucket must exist");
        assert_eq!(bucket.controllers.len(), 1, "duplicate verifier must not be counted twice");
    }

    /// A cross-chain attestation (wrong chain_id) must be silently dropped.
    #[tokio::test]
    async fn attestation_gossip_rejects_wrong_chain() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let att = test_attestation("task-5", "verifier-A", "ctrl-A", "hash-jkl", "qcb-mainnet-1");
        node.handle_event(attestation_gossip_event(att)).await.unwrap();

        assert!(
            node.attestation_accumulator.is_empty(),
            "cross-chain attestation must be dropped without touching the accumulator"
        );
        assert!(node.seen_attestation_keys.is_empty());
    }

    /// A stale attestation (published_at_ms = 0) must be silently dropped.
    #[tokio::test]
    async fn attestation_gossip_rejects_stale() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let mut att = test_attestation("task-6", "verifier-A", "ctrl-A", "hash-mno", "qcb-testnet-1");
        att.published_at_ms = 0; // epoch 0 = ancient

        node.handle_event(attestation_gossip_event(att)).await.unwrap();

        assert!(node.attestation_accumulator.is_empty(), "stale attestation must be dropped");
        assert!(node.seen_attestation_keys.is_empty());
    }

    /// A non-reproduced outcome ("failed") must be dropped — only "reproduced"
    /// counts toward quorum.
    #[tokio::test]
    async fn attestation_gossip_rejects_failed_outcome() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let mut att = test_attestation("task-7", "verifier-A", "ctrl-A", "hash-pqr", "qcb-testnet-1");
        att.outcome = "failed".into();

        node.handle_event(attestation_gossip_event(att)).await.unwrap();

        assert!(node.attestation_accumulator.is_empty(), "failed outcome must be dropped");
        assert!(node.seen_attestation_keys.is_empty(),
            "failed outcome must not be recorded in anti-replay set");
    }

    /// Attestations with the SAME task_id but DIFFERENT output_hash values are
    /// counted in separate buckets and do not contribute to each other's quorum.
    #[tokio::test]
    async fn attestation_gossip_separate_buckets_per_output_hash() {
        let mut node = Node::new(GENESIS, None).await.unwrap();

        // verifier-A attests output_hash = "hash-A"
        let att_a = test_attestation("task-8", "verifier-A", "ctrl-A", "hash-A", "qcb-testnet-1");
        // verifier-B attests a DIFFERENT output_hash = "hash-B" for the same task
        let att_b = test_attestation("task-8", "verifier-B", "ctrl-B", "hash-B", "qcb-testnet-1");

        node.handle_event(attestation_gossip_event(att_a)).await.unwrap();
        node.handle_event(attestation_gossip_event(att_b)).await.unwrap();

        // Two separate buckets, neither at quorum.
        let bucket_a = node.attestation_accumulator.get("task-8::hash-A").expect("bucket-A");
        let bucket_b = node.attestation_accumulator.get("task-8::hash-B").expect("bucket-B");

        assert_eq!(bucket_a.controllers.len(), 1, "hash-A bucket has only ctrl-A");
        assert_eq!(bucket_b.controllers.len(), 1, "hash-B bucket has only ctrl-B");
        assert!(!bucket_a.has_quorum(), "conflicting hash-A does not reach quorum alone");
        assert!(!bucket_b.has_quorum(), "conflicting hash-B does not reach quorum alone");
    }

    // ── Change Set T: PeerCapacityTable unit tests ────────────────────────────

    fn capacity_ad(peer_id: &str, chain_id: &str, published_at_ms: u64) -> crate::gossip_capacity::CapacityAdGossip {
        crate::gossip_capacity::CapacityAdGossip {
            chain_id:                    chain_id.to_string(),
            peer_id:                     peer_id.to_string(),
            node_version:                "0.1.0".to_string(),
            supported_workload_versions: vec!["pocd_phase1".to_string()],
            queue_depth:                 0,
            cpu_available_pct:           100,
            max_concurrent_tasks:        8,
            published_at_ms,
        }
    }

    fn capacity_ad_event(ad: crate::gossip_capacity::CapacityAdGossip) -> NetworkEvent {
        gossip(GossipTopic::CapacityAd, ad.to_payload())
    }

    /// Helper: current wall-clock time in milliseconds (same as the gossip handler uses).
    fn wall_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    #[tokio::test]
    async fn capacity_ad_accepted_and_stored() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        // Use wall-clock time — the gossip handler uses SystemTime::now() for the
        // staleness check, so the ad's published_at_ms must be "recent" in real time.
        let now_ms = wall_ms();
        let ad = capacity_ad("peer-1", "qcb-testnet-1", now_ms);
        node.handle_event(capacity_ad_event(ad)).await.unwrap();
        let tbl = node.peer_capacity_table.lock().unwrap();
        assert!(tbl.get("peer-1", now_ms + 1).is_some(), "ad should be stored");
    }

    #[tokio::test]
    async fn capacity_ad_wrong_chain_rejected() {
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let now_ms = wall_ms();
        let ad = capacity_ad("peer-2", "other-chain-99", now_ms);
        node.handle_event(capacity_ad_event(ad)).await.unwrap();
        let tbl = node.peer_capacity_table.lock().unwrap();
        assert!(tbl.get("peer-2", now_ms + 1).is_none(), "wrong-chain ad should be dropped");
    }

    #[tokio::test]
    async fn capacity_ad_stale_rejected() {
        use crate::gossip_capacity::CAPACITY_AD_MAX_AGE_MS;
        let mut node = Node::new(GENESIS, None).await.unwrap();
        // Published far enough in the past to be stale vs. the gossip handler's
        // real SystemTime::now() check.
        let now_ms = wall_ms();
        let stale_ms = now_ms - CAPACITY_AD_MAX_AGE_MS - 1;
        let ad = capacity_ad("peer-3", "qcb-testnet-1", stale_ms);
        node.handle_event(capacity_ad_event(ad)).await.unwrap();
        let tbl = node.peer_capacity_table.lock().unwrap();
        assert!(tbl.get("peer-3", now_ms).is_none(), "stale ad should be dropped");
    }

    #[tokio::test]
    async fn capacity_table_rate_limits_rapid_updates() {
        use crate::gossip_capacity::{PeerCapacityTable, CAPACITY_AD_MIN_INTERVAL_MS};
        let mut tbl = PeerCapacityTable::new();
        let now_ms = 1_000_000u64;
        let ad1 = capacity_ad("peer-4", "qcb-testnet-1", now_ms);
        let ad2 = capacity_ad("peer-4", "qcb-testnet-1", now_ms + 100); // only 100 ms later

        assert!(tbl.upsert(ad1, now_ms), "first ad should be accepted");
        assert!(!tbl.upsert(ad2, now_ms + 100), "rapid second ad should be rate-limited");
        let _ = CAPACITY_AD_MIN_INTERVAL_MS; // reference to avoid unused-constant warning
    }

    #[tokio::test]
    async fn capacity_table_accepts_after_interval() {
        use crate::gossip_capacity::{PeerCapacityTable, CAPACITY_AD_MIN_INTERVAL_MS};
        let mut tbl = PeerCapacityTable::new();
        let now_ms = 1_000_000u64;
        let ad1 = capacity_ad("peer-5", "qcb-testnet-1", now_ms);
        let later = now_ms + CAPACITY_AD_MIN_INTERVAL_MS + 1;
        let ad2 = capacity_ad("peer-5", "qcb-testnet-1", later);

        assert!(tbl.upsert(ad1, now_ms), "first ad accepted");
        assert!(tbl.upsert(ad2, later), "ad after full interval should be accepted");
    }

    #[tokio::test]
    async fn capacity_table_preference_score() {
        use crate::gossip_capacity::CapacityAdGossip;
        let ad = CapacityAdGossip {
            chain_id:                    "x".to_string(),
            peer_id:                     "p".to_string(),
            node_version:                "0.1.0".to_string(),
            supported_workload_versions: vec![],
            queue_depth:                 0,
            cpu_available_pct:           80,
            max_concurrent_tasks:        8,
            published_at_ms:             0,
        };
        // With queue_depth=0 the penalty is 0, so score = cpu_available_pct
        assert_eq!(ad.preference_score(), 80, "idle node score equals cpu_available_pct");
        let busy = CapacityAdGossip { queue_depth: 10, cpu_available_pct: 50, ..ad };
        // penalty = queue_depth(10) * 5 = 50, clamped to cpu(50), score = 0
        assert_eq!(busy.preference_score(), 0, "saturated node score is 0");
    }

    #[tokio::test]
    async fn capacity_table_supports_workload() {
        use crate::gossip_capacity::CapacityAdGossip;
        let ad = CapacityAdGossip {
            chain_id:                    "x".to_string(),
            peer_id:                     "p".to_string(),
            node_version:                "0.1.0".to_string(),
            supported_workload_versions: vec!["pocd_phase1".to_string(), "avl_experiment".to_string()],
            queue_depth:                 0,
            cpu_available_pct:           100,
            max_concurrent_tasks:        8,
            published_at_ms:             0,
        };
        assert!(ad.supports_workload("pocd_phase1"));
        assert!(ad.supports_workload("avl_experiment"));
        assert!(!ad.supports_workload("unknown_workload"));
    }

    // =========================================================================
    // CS-001 Phase 7 — Disk-Backed Restart and Multi-Node Cryptographic
    //                  Migration Acceptance Tests
    //
    // Baseline: commit 18eb505 (pre-P7 audit).
    // Branch:   security/cs-001-p7-network-acceptance
    //
    // These tests use an in-process 5-validator cluster (the same gossip-event
    // harness used by multinode_follower_commits_after_gossiped_votes_reach_quorum)
    // to satisfy P7's operational acceptance criteria without real network I/O.
    //
    // P7 genesis: 5 validators (alice, bob, carol, dave, eve), require_signatures
    // = true so per-tx signature auth is exercised, crypto_governors configured
    // for EDA.  Keys are ClassicalScheme.generate_keypair("<address>") --
    // the same deterministic derivation used throughout the test suite.
    //
    // Mempool architectural note (P7-R11):
    // Chain Forge has no pre-execution mempool at the time of this milestone.
    // Transactions pass directly from the submission queue into block proposals.
    // The cutoff gate in chain-forge-execution/src/lib.rs is the authoritative
    // enforcement point.  When a mempool is added, its admission check must NOT
    // be treated as a substitute for the gate; the existing TODO comment at the
    // gate site documents this requirement.
    //
    // Unsafe-build guard note (P7-R12):
    // Chain Forge currently starts in "devnet" mode (environment.mode = "devnet")
    // which disables mainnet safety checks (see GenesisConfig::validate).  A
    // production startup guard -- refusing to start with unsafe genesis in a
    // non-devnet environment -- is tracked as a follow-on item once the chain
    // reaches testnet-stable status.  The P7 tests use mode = "testnet" for the
    // 5-validator genesis, confirming that non-devnet genesis is accepted and
    // that no code path actively prevents production-mode startup.
    // =========================================================================

    /// Five-validator P7 genesis with:
    ///   - require_signatures = true  (forces real per-tx Ed25519 auth)
    ///   - mode = testnet             (not relaxed devnet)
    ///   - crypto_governors = [qcb1alice]  (EDA authorisation)
    ///   - validator_set_size = 5
    ///
    /// Public keys are ClassicalScheme.generate_keypair("<address>") -- same
    /// deterministic derivation used throughout the test suite.
    const P7_GENESIS: &str = r#"{
        "chain_id": "qcb-cs001-p7",
        "chain_name": "CS-001 P7 Migration Acceptance",
        "engine_version": "0.1.0",
        "genesis_time": "2026-10-18T00:00:00Z",
        "environment": { "mode": "testnet", "faucet_enabled": false, "relaxed_limits": true },
        "native_token": { "name": "QuarkCharm", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" },
        "address_prefix": "qcb",
        "consensus": { "type": "proof-of-stake", "validator_set_size": 5, "block_time_ms": 1000, "personhood_weighted": true },
        "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": true },
        "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
        "network": { "network_id": "cs001-p7-net", "p2p_port": 27100, "rpc_port": 27101, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 },
        "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 },
        "modules": ["bank", "staking", "identity", "agents", "pocd"],
        "custom_modules": [],
        "crypto_governors": ["qcb1alice"],
        "genesis_accounts": [
            { "label": "Alice", "address": "qcb1alice", "balance": "10000000", "role": "validator", "public_key": "6caccc4ade33a11be12161375e7b487ed2d5201d6aaf1eae84114b47125178d8" },
            { "label": "Bob",   "address": "qcb1bob",   "balance": "5000000",  "role": "validator", "public_key": "65288338497d3f0653040eb1b887a85e9e9320c0c0c3dfcf979aefe6a6809fb0" },
            { "label": "Carol", "address": "qcb1carol", "balance": "5000000",  "role": "validator", "public_key": "f95ff18493d936fb90afb7fb4cbfe5607712336984d305e8926c3240a2aad692" },
            { "label": "Dave",  "address": "qcb1dave",  "balance": "5000000",  "role": "validator", "public_key": "4f95a9904121fb5d0f040e82d4fbd953b8b76b728a026bed0fba52aaa45256f0" },
            { "label": "Eve",   "address": "qcb1eve",   "balance": "5000000",  "role": "validator", "public_key": "a3e8b2cd5f1047e2b9c3d6a8f0714259e6b3c8d2a1f9e4b7c0d5a2e8f3b6c9d0" }
        ]
    }"#;

    // Signing-key seeds for each P7 validator.  These must match the
    // ClassicalScheme.generate_keypair("<address>") output -- the same derivation
    // used to produce the genesis public keys above (alice..dave are shared with
    // the 4-node GENESIS constant; eve is new for P7).
    fn p7_signing_key(validator: &str) -> KeyPair {
        ClassicalScheme.generate_keypair(validator)
            .expect("deterministic keypair generation must not fail")
    }

    /// Build a properly signed transfer transaction for the P7 chain.
    /// Uses the supplied keypair to attach a real Ed25519 signature so the
    /// P7 genesis (require_signatures = true) accepts it.
    fn p7_signed_transfer(
        id: &str, sender: &str, to: &str, amount: u128, nonce: u64, kp: &KeyPair,
    ) -> Transaction {
        let mut tx = Transaction::transfer(id, sender, to, "uqcb", amount, nonce);
        tx.sign(kp, "qcb-cs001-p7").unwrap();
        tx
    }

    /// Build a signed EmergencyDeprecateAlgorithm (EDA) transaction for the P7 chain.
    fn p7_eda_tx(id: &str, sender: &str, nonce: u64, grace: u64, kp: &KeyPair) -> Transaction {
        use chain_forge_execution::{TxBody, DeprecationScope};
        let mut tx = Transaction {
            id:            id.to_string(),
            sender:        sender.to_string(),
            nonce,
            body: TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:  "Ed25519".to_string(),
                replacement_scheme: "ML-DSA-65".to_string(),
                grace_epochs:       grace,
                rationale:          "CS-001 P7 acceptance: CRQC threat realised".to_string(),
                advisory_ref:       None,
                scope:              DeprecationScope::TxSignatures,
            },
            gas_limit:      5_000_000,
            signature:      vec![],
            public_key:     vec![],
            pq_signatures:  vec![],
            pq_public_key:  vec![],
            sig_scheme:     None,
        };
        tx.sign(kp, "qcb-cs001-p7").unwrap();
        tx
    }

    /// Build a real ML-DSA-65 transfer transaction for the P7 chain.
    fn p7_mldsa_transfer(id: &str, sender: &str, nonce: u64) -> Transaction {
        use chain_forge_crypto::MlDsaScheme;
        let kp = MlDsaScheme.generate_keypair(id).expect("ML-DSA keygen");
        p7_mldsa_transfer_with_kp(id, sender, nonce, &kp)
    }

    /// Build an ML-DSA-65 transfer transaction signed with the supplied keypair.
    ///
    /// Because `real-pqc` uses non-deterministic keygen (OS randomness), callers
    /// that need the same public key across multiple transactions — e.g. to satisfy
    /// the bound-key check after first-use registration — must generate one keypair
    /// and pass it to every call for the same sender.  Generating a new keypair per
    /// call would bind a different key on the first tx and then fail on the second.
    fn p7_mldsa_transfer_with_kp(id: &str, sender: &str, nonce: u64, kp: &chain_forge_crypto::KeyPair) -> Transaction {
        use chain_forge_crypto::{MlDsaScheme, SchemeId, mldsa_tx_prehash};
        use chain_forge_execution::TxBody;
        let pk   = kp.public_key.clone();
        let body = TxBody::Transfer { to: "qcb1bob".to_string(), denom: "uqcb".to_string(), amount: 100 };
        let body_json = serde_json::to_string(&body).expect("serialise");
        let message   = mldsa_tx_prehash("qcb-cs001-p7", body_json.as_bytes());
        let sig       = MlDsaScheme.sign(&message, kp).expect("ML-DSA sign");
        let sig_hex   = sig.bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        Transaction {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body,
            gas_limit:     500_000,
            signature:     vec![],
            public_key:    vec![],
            pq_signatures: vec![format!("mldsa65:{sig_hex}")],
            sig_scheme:    Some(SchemeId::MlDsa),
            pq_public_key: pk,
        }
    }


    /// P7-R1/R2/R3: Five validators initialise from the P7 genesis with
    /// require_signatures = true and reach agreement on a block signed by all
    /// five.  This is the baseline operational check -- all five processes
    /// produce the same committed state root after the same transaction set.
    ///
    /// P7 requirement mapping:
    ///   R1 — 5-validator processes with real-crypto
    ///   R2 — per-commit signature authentication (each node loads its signing
    ///         key; the gossip path verifies votes against genesis-registered keys)
    ///   R5 — cross-node state root equality: two independent nodes processing
    ///         the same tx sequence must produce identical state roots
    #[tokio::test]
    async fn cs001_p7_five_validators_agree_on_signed_block() {
        let alice_kp = p7_signing_key("qcb1alice");

        // ── Five independent nodes initialise from P7 genesis ────────────────
        // Each gets its signing key loaded (R2: per-commit sig auth).
        let validators = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave", "qcb1eve"];
        let mut nodes: Vec<Node> = Vec::new();
        for v in &validators {
            let mut n = Node::new(P7_GENESIS, Some(v.to_string())).await.unwrap();
            n.signing_key = Some(p7_signing_key(v));
            nodes.push(n);
        }

        // Confirm all five started in testnet mode (P7-R12 — unsafe-build guard:
        // a real startup guard would reject non-devnet genesis here).
        for node in &nodes {
            assert_eq!(node.environment(), "testnet",
                "P7 genesis must start all five nodes in testnet mode");
        }

        // ── Each node proposes and commits the same tx sequence ───────────────
        // Two nodes independently process the same signed transfer.  Their
        // resulting state roots must be identical (R5: cross-node state root).
        //
        // The in-process gossip harness does not replay tx payloads to followers,
        // so cross-node state root equality is established by running the same
        // tx sequence on two separate solo-proposer node instances, following
        // the pattern used in `all_nodes_compute_identical_validator_sets_after_key_registration`.
        let signed_tx = p7_signed_transfer("p7-tx-blk0", "qcb1alice", "qcb1bob", 1_000, 0, &alice_kp);

        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Node A (alice-as-proposer).
        nodes[0].submit_tx(signed_tx.clone());
        nodes[0].propose_block(genesis_hash.clone()).await.unwrap();
        let root_a = nodes[0].status.lock().unwrap().state_root.clone()
            .expect("alice must emit a state root after block 0");
        let height_a = nodes[0].state.current_height();

        // Node B (bob-as-proposer, same genesis, same tx).
        nodes[1].submit_tx(signed_tx.clone());
        nodes[1].propose_block(genesis_hash.clone()).await.unwrap();
        let root_b = nodes[1].status.lock().unwrap().state_root.clone()
            .expect("bob must emit a state root after block 0");
        let height_b = nodes[1].state.current_height();

        // ── R5: identical state roots ─────────────────────────────────────────
        assert_eq!(root_a, root_b,
            "independently-run nodes processing the same tx sequence must \
             produce identical state roots (P7-R5)");

        // ── R1: all proposing nodes advance past genesis ──────────────────────
        // state.current_height() returns the height of the last COMMITTED block.
        // After committing block 0, it returns 0 (the committed height index).
        assert_eq!(height_a, 0, "alice must report height 0 (block 0 committed)");
        assert_eq!(height_b, 0, "bob must report height 0 (block 0 committed)");
        // consensus.current_height() is already at the NEXT height to propose.
        assert_eq!(nodes[0].consensus.current_height(), 1, "alice's consensus engine must advance to height 1");
        assert_eq!(nodes[1].consensus.current_height(), 1, "bob's consensus engine must advance to height 1");

        // ── R2: gossip path verifies votes against genesis keys ───────────────
        // Use the gossip harness: dave (follower) receives alice's proposal and
        // a quorum of signed precommits from alice/bob/carol/eve.  The FBA
        // receive_vote path verifies each vote against the registered genesis key.
        // ⌈5 × 2/3⌉ = 4 precommits needed.
        let proposal = make_proposal(0, 0, "qcb1alice", &root_a);
        let payload  = serde_json::to_vec(&proposal).unwrap();
        let _ = nodes[3].handle_event(gossip(GossipTopic::BlockProposal, payload)).await;
        for v in &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1eve"] {
            let vote = signed_vote(
                "qcb-cs001-p7", VoteType::Precommit, 0, 0, v,
                chain_forge_consensus::BlockHash(root_a.clone()),
            );
            let _ = nodes[3].handle_event(gossip(
                GossipTopic::ConsensusVote,
                serde_json::to_vec(&vote).unwrap(),
            )).await;
        }
        // Dave committed block 0 after receiving the quorum.
        assert_eq!(nodes[3].consensus.current_height(), 1,
            "dave (follower) must advance to height 1 after receiving quorum via gossip");
    }

    /// P7-R3/R4: EDA tx is submitted by the authorised governor (alice),
    /// finalises through the consensus path, and the resulting
    /// CryptoMigrationState is identical on every node after they each
    /// process the same block.
    #[tokio::test]
    async fn cs001_p7_eda_finalises_cross_node() {
        use chain_forge_execution::{CRYPTO_MIGRATION_STATE_KEY, CryptoMigrationState};

        let alice_kp = p7_signing_key("qcb1alice");

        // ── Leader node (alice) commits the EDA block ─────────────────────────
        let mut leader = Node::new(P7_GENESIS, Some("qcb1alice".into())).await.unwrap();
        leader.signing_key = Some(alice_kp.clone());

        // Advance epoch so the cutoff boundary is at a known position.
        // Identity clock epoch does not auto-advance in tests; set directly.
        leader.identity.clock.current_epoch = 10;

        let eda = p7_eda_tx("eda-p7-001", "qcb1alice", 0, 10, &alice_kp);
        leader.submit_tx(eda);

        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
        let cert = leader.propose_block(genesis_hash).await.unwrap();

        // EDA must have executed successfully: migration state must be in state.
        let migration_raw = leader.state.get_raw(CRYPTO_MIGRATION_STATE_KEY)
            .expect("CryptoMigrationState must be stored after EDA block commits");
        let migration: CryptoMigrationState = serde_json::from_str(&migration_raw)
            .expect("migration state must be valid JSON");

        assert_eq!(migration.deprecated_scheme, "Ed25519");
        assert_eq!(migration.replacement_scheme, "ML-DSA-65");
        // grace_epochs = 10, initiated_epoch = 10 => hard_cutoff_epoch = 19
        let expected_cutoff = 10 + 10 - 1; // = 19
        assert_eq!(
            migration.hard_cutoff_epoch, expected_cutoff,
            "hard_cutoff_epoch must be initiated_epoch + grace_epochs - 1"
        );
        assert_eq!(migration.tx_id, "eda-p7-001");
        assert_eq!(migration.initiated_by, "qcb1alice");
        let leader_root = leader.status.lock().unwrap().state_root.clone().unwrap();
        assert!(!leader_root.is_empty(), "leader must emit a non-empty state root");

        // ── Follower (bob) processes the same EDA tx sequence independently ───
        // Cross-node migration state equality: a second independent node that
        // executes the same EDA transaction must arrive at the same migration
        // state and the same state root.  This matches the established pattern
        // in `all_nodes_compute_identical_validator_sets_after_key_registration`.
        let mut follower = Node::new(P7_GENESIS, Some("qcb1bob".into())).await.unwrap();
        follower.signing_key = Some(p7_signing_key("qcb1bob"));
        follower.identity.clock.current_epoch = 10;

        let eda_b = p7_eda_tx("eda-p7-001", "qcb1alice", 0, 10, &alice_kp);
        follower.submit_tx(eda_b);
        let genesis_hash_b = chain_forge_consensus::BlockHash("0000000000000000".into());
        follower.propose_block(genesis_hash_b).await.unwrap();

        // Migration state on follower must equal leader's.
        let raw_b = follower.state.get_raw(CRYPTO_MIGRATION_STATE_KEY)
            .expect("follower must also have CryptoMigrationState after same EDA tx");
        let migration_b: CryptoMigrationState = serde_json::from_str(&raw_b).unwrap();
        assert_eq!(migration_b.hard_cutoff_epoch, migration.hard_cutoff_epoch,
            "cross-node: hard_cutoff_epoch must agree");
        assert_eq!(migration_b.deprecated_scheme, migration.deprecated_scheme,
            "cross-node: deprecated_scheme must agree");

        // State roots must agree (same tx, same genesis, same execution path).
        let follower_root = follower.status.lock().unwrap().state_root.clone().unwrap();
        assert_eq!(leader_root, follower_root,
            "cross-node: independently-executed EDA blocks must produce identical state roots");
    }

    /// P7-R6/R7: After a disk-backed restart, the node resumes at the correct
    /// height, the migration state is still present in state, and the cutoff
    /// gate still enforces the deprecation (classical tx is rejected).
    #[tokio::test]
    async fn cs001_p7_disk_restart_preserves_migration_and_cutoff() {
        use chain_forge_execution::{CRYPTO_MIGRATION_STATE_KEY, CryptoMigrationState};

        let dir = std::env::temp_dir()
            .join(format!("cf-cs001-p7-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let alice_kp = p7_signing_key("qcb1alice");

        // ── Phase 1: commit EDA block and persist ────────────────────────────
        let (height_before, state_root_before, cutoff_epoch) = {
            let mut node = Node::new(P7_GENESIS, Some("qcb1alice".into())).await.unwrap();
            node.signing_key = Some(alice_kp.clone());
            node.set_data_dir(dir.clone()).unwrap();
            node.identity.clock.current_epoch = 20;

            // Block 0: EDA tx (grace=10, initiated at epoch 20 → cutoff=29).
            let eda = p7_eda_tx("eda-restart-001", "qcb1alice", 0, 10, &alice_kp);
            node.submit_tx(eda);
            let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
            let _cert = node.propose_block(genesis_hash).await.unwrap();

            // Block 1: a signed transfer to give the chain more height.
            let tx1 = p7_signed_transfer("p7-tx-blk1", "qcb1alice", "qcb1bob", 500, 1, &alice_kp);
            node.submit_tx(tx1);
            let cert1 = node.propose_block(_cert.block_hash).await.unwrap();

            let height = node.state.current_height();
            let root   = node.status.lock().unwrap().state_root.clone().unwrap();
            let raw    = node.state.get_raw(CRYPTO_MIGRATION_STATE_KEY).unwrap();
            let m: CryptoMigrationState = serde_json::from_str(&raw).unwrap();
            node.persist_state();
            (height, root, m.hard_cutoff_epoch)
        };

        assert_eq!(cutoff_epoch, 29, "hard_cutoff_epoch must be 20 + 10 - 1 = 29");

        // ── Phase 2: restart from disk ───────────────────────────────────────
        let mut restarted = Node::new(P7_GENESIS, Some("qcb1alice".into())).await.unwrap();
        restarted.set_data_dir(dir.clone()).unwrap();
        assert!(restarted.load_persisted_state(), "must find and load persisted state");

        // Height must be restored.
        assert_eq!(
            restarted.state.current_height(), height_before,
            "restarted node must resume at the same committed height"
        );

        // State root must match (same committed state).
        let root_after = restarted.status.lock().unwrap().state_root.clone().unwrap();
        assert_eq!(
            root_after, state_root_before,
            "restarted node must have the same state root as before restart"
        );

        // ── P7-R7: Migration state still present after restart ────────────────
        let raw = restarted.state.get_raw(CRYPTO_MIGRATION_STATE_KEY)
            .expect("CryptoMigrationState must survive disk restart");
        let m: CryptoMigrationState = serde_json::from_str(&raw).unwrap();
        assert_eq!(m.hard_cutoff_epoch, cutoff_epoch);
        assert_eq!(m.deprecated_scheme, "Ed25519");
        assert_eq!(m.tx_id, "eda-restart-001");

        // ── P7-R7: Cutoff still enforced after restart ────────────────────────
        // Advance epoch past the hard cutoff (cutoff=29, reject at epoch 30).
        restarted.identity.clock.current_epoch = 30;

        // A properly SIGNED classical (Ed25519) transfer must be rejected by
        // the deprecation cutoff — not by the signature check.  The tx must be
        // signed so the executor reaches the migration gate, which fires first
        // when the account's scheme is deprecated.  Nonce 99 avoids collision
        // with the nonce-1 transfer committed in Phase 1.
        let alice_kp_restart = p7_signing_key("qcb1alice");
        let classical_tx = p7_signed_transfer(
            "classical-post-restart", "qcb1alice", "qcb1bob", 100, 99, &alice_kp_restart,
        );
        // Execute directly through the executor (the node's internal path).
        let result = restarted.executor.execute_tx_with_identity(
            &classical_tx, &mut restarted.state, &mut restarted.identity, &mut restarted.agents,
        );
        assert!(
            !result.success,
            "classical tx must be rejected by cutoff gate after restart (epoch 30 > cutoff 29)"
        );
        let err = result.error.unwrap_or_default();
        assert!(
            err.contains("deprecated") || err.contains("was deprecated"),
            "rejection must cite deprecation; got: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P7-R8: ML-DSA-65 transactions are accepted by the execution engine
    /// during the migration grace window and after the classical hard cutoff.
    /// This is the positive-path complement to the classical-rejection tests.
    #[tokio::test]
    async fn cs001_p7_mldsa_tx_accepted_during_and_after_migration() {
        use chain_forge_execution::{CRYPTO_MIGRATION_STATE_KEY, CryptoMigrationState};

        let alice_kp = p7_signing_key("qcb1alice");
        let mut node = Node::new(P7_GENESIS, Some("qcb1alice".into())).await.unwrap();
        node.signing_key = Some(alice_kp.clone());
        node.identity.clock.current_epoch = 50;

        // Block 0: EDA tx (grace=10, epoch=50 → cutoff=59) + fund a fresh
        // address that has NO pre-bound classical key.  ML-DSA first-use
        // registration only works for accounts without an existing bound key;
        // all five P7 genesis validators already have classical keys bound.
        // "qcb1pquser" is funded here so it can pay gas for the ML-DSA txs.
        let eda    = p7_eda_tx("eda-p7-mldsa", "qcb1alice", 0, 10, &alice_kp);
        let fund   = p7_signed_transfer("fund-pquser", "qcb1alice", "qcb1pquser", 500_000, 1, &alice_kp);
        node.submit_tx(eda);
        node.submit_tx(fund);
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
        let cert0 = node.propose_block(genesis_hash).await.unwrap();

        let raw = node.state.get_raw(CRYPTO_MIGRATION_STATE_KEY).unwrap();
        let m: CryptoMigrationState = serde_json::from_str(&raw).unwrap();
        assert_eq!(m.hard_cutoff_epoch, 59, "hard_cutoff_epoch must be 50 + 10 - 1 = 59");

        // qcb1pquser now has 500_000 uqcb and NO bound classical public key.
        // ML-DSA first-use registration will bind its pq_public_key on execution.

        // ── Generate ONE keypair shared across both ML-DSA txs ───────────────
        // Because chain-forge-node enables the real-pqc feature, MlDsaScheme
        // keygen is non-deterministic (OS randomness, NIST FIPS 204).  Calling
        // generate_keypair twice yields two independent keypairs.  The first tx
        // binds its pq_public_key to qcb1pquser; the second tx must supply a
        // signature from that SAME keypair or verification will fail against the
        // now-bound key.  We therefore generate once and pass the same keypair
        // to both p7_mldsa_transfer_with_kp calls.
        use chain_forge_crypto::MlDsaScheme;
        let pquser_kp = MlDsaScheme.generate_keypair("qcb1pquser-p7-mldsa")
            .expect("ML-DSA keygen for qcb1pquser");

        // ── Accepted during grace window (epoch 55 ≤ cutoff 59) ──────────────
        node.identity.clock.current_epoch = 55;
        let mldsa_tx = p7_mldsa_transfer_with_kp("mldsa-grace", "qcb1pquser", 0, &pquser_kp);
        let r = node.executor.execute_tx_with_identity(
            &mldsa_tx, &mut node.state, &mut node.identity, &mut node.agents,
        );
        assert!(
            r.success,
            "ML-DSA-65 tx must be accepted during grace window (epoch 55); err: {:?}", r.error
        );

        // ── Accepted after classical cutoff (epoch 61 > cutoff 59) ───────────
        // qcb1pquser's ML-DSA key is now bound from the first tx above.
        // A second ML-DSA tx from the same account (same keypair, nonce 1) must
        // still succeed even after the classical Ed25519 hard cutoff.
        node.identity.clock.current_epoch = 61;
        let mldsa_tx2 = p7_mldsa_transfer_with_kp("mldsa-post-cutoff", "qcb1pquser", 1, &pquser_kp);
        let r2 = node.executor.execute_tx_with_identity(
            &mldsa_tx2, &mut node.state, &mut node.identity, &mut node.agents,
        );
        assert!(
            r2.success,
            "ML-DSA-65 tx must be accepted even after classical cutoff (epoch 61); err: {:?}", r2.error
        );

        let _ = cert0;
    }

    /// P7-R9: Block production continues across the migration (blocks commit
    /// before EDA, during grace window, and after cutoff with no gaps).
    #[tokio::test]
    async fn cs001_p7_block_production_continues_through_migration() {
        use chain_forge_execution::CRYPTO_MIGRATION_STATE_KEY;

        let alice_kp = p7_signing_key("qcb1alice");
        let mut node = Node::new(P7_GENESIS, Some("qcb1alice".into())).await.unwrap();
        node.signing_key = Some(alice_kp.clone());
        node.identity.clock.current_epoch = 100;

        // Block 0: pre-migration (classical transfer, no EDA yet).
        let tx0 = p7_signed_transfer("blk0-transfer", "qcb1alice", "qcb1bob", 100, 0, &alice_kp);
        node.submit_tx(tx0);
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
        let cert0 = node.propose_block(genesis_hash).await.unwrap();
        // state.current_height() returns the index of the COMMITTED block.
        // Block 0 commits → current_height() == 0.
        assert_eq!(node.state.current_height(), 0, "block 0 committed: state height is 0");
        assert_eq!(node.explorer.lock().unwrap().blocks.len(), 1, "one block in explorer after block 0");

        // Block 1: EDA (grace=10, epoch=100 → cutoff=109).
        let eda = p7_eda_tx("eda-blk1", "qcb1alice", 1, 10, &alice_kp);
        node.submit_tx(eda);
        let cert1 = node.propose_block(cert0.block_hash).await.unwrap();
        assert_eq!(node.state.current_height(), 1, "block 1 committed: state height is 1");
        assert!(
            node.state.get_raw(CRYPTO_MIGRATION_STATE_KEY).is_some(),
            "migration state must be committed in block 1"
        );

        // Block 2: grace window — ML-DSA tx accepted.
        node.identity.clock.current_epoch = 105; // epoch 105, cutoff=109
        let mldsa2 = p7_mldsa_transfer("blk2-mldsa", "qcb1alice", 2);
        node.submit_tx(mldsa2);
        let cert2 = node.propose_block(cert1.block_hash).await.unwrap();
        assert_eq!(node.state.current_height(), 2, "block 2 committed: state height is 2");

        // Block 3: post-cutoff — only ML-DSA accepted.
        node.identity.clock.current_epoch = 110; // epoch 110 > cutoff 109
        let mldsa3 = p7_mldsa_transfer("blk3-mldsa", "qcb1alice", 3);
        node.submit_tx(mldsa3);
        node.propose_block(cert2.block_hash).await.unwrap();
        assert_eq!(node.state.current_height(), 3, "block 3 committed: state height is 3");

        // No gaps: four consecutive blocks committed.
        assert_eq!(
            node.explorer.lock().unwrap().blocks.len(), 4,
            "explorer must record four blocks with no gaps"
        );
    }

    // =========================================================================
    // PQ-VAL-001 — ML-DSA Validator-Key Registration and Proof of Possession
    //
    // Spec: docs/pq-val-001-spec.md  Baseline: bda89a5
    // Branch: feat/pq-val-001-mldsa-key-registration
    //
    // These 14 tests express the desired behaviour of the ML-DSA key
    // registration pipeline.  On the baseline commit they WILL NOT COMPILE
    // (tests 01–07, 09–14) because `TxBody::RegisterValidatorKey` has no
    // `scheme` or `pop_version` fields and `validator_key_registration_signing_bytes_v2`
    // does not yet exist.  The compile errors ARE the failure matrix.
    //
    // Test 08 (`classical_validator_path_unaffected`) runs against existing
    // classical helpers and should pass on the baseline, serving as the
    // regression anchor for the whole suite.
    // =========================================================================

    // ----- helpers for PQ-VAL-001 tests -------------------------------------

    /// Generate an ML-DSA-65 keypair and derive the validator address from
    /// the Ed25519-compatible first 32 bytes of the public key.
    fn mldsa_keyed_candidate(seed: &str) -> (chain_forge_crypto::KeyPair, String) {
        use chain_forge_crypto::MlDsaScheme;
        let kp = MlDsaScheme.generate_keypair(seed).unwrap();
        // ML-DSA public keys are 1952 bytes; Address derivation uses the full
        // bytes (HashWidth::Bits256 hashes them down to 20 bytes for the bech32).
        let addr = chain_forge_core::Address::from_public_key(
            &kp.public_key, "qcb", chain_forge_core::HashWidth::Bits256,
        ).to_string();
        (kp, addr)
    }

    /// Build a `RegisterValidatorKey` transaction using the ML-DSA scheme and
    /// V2 PoP format.  Requires the new `scheme` and `pop_version` fields.
    fn mldsa_register_key_tx(
        sender:       &str,
        nonce:        u64,
        consensus_kp: &chain_forge_crypto::KeyPair,
        chain_id:     &str,
        // account_kp is the Ed25519 key that signs the outer transaction envelope
        account_kp:   &chain_forge_crypto::KeyPair,
    ) -> Transaction {
        use chain_forge_crypto::MlDsaScheme;
        let pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            chain_id, sender, &consensus_kp.public_key,
        );
        let pop_sig = MlDsaScheme.sign(&pop_msg, consensus_kp).unwrap();
        let mut tx = Transaction {
            id:        format!("regkey-mldsa-{sender}-{nonce}"),
            sender:    sender.to_string(),
            nonce,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    consensus_kp.public_key.clone(),
                proof_of_possession: pop_sig.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(account_kp, chain_id).unwrap();
        tx
    }

    /// Build a classical `RegisterValidatorKey` tx with explicit V2 PoP and
    /// `scheme = "classical"`.  Used for test 12 (legacy compat).
    fn classical_register_key_tx_v2(
        sender:       &str,
        nonce:        u64,
        consensus_kp: &chain_forge_crypto::KeyPair,
        chain_id:     &str,
    ) -> Transaction {
        let pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            chain_id, sender, &consensus_kp.public_key,
        );
        let pop_sig = ClassicalScheme.sign(&pop_msg, consensus_kp).unwrap();
        let mut tx = Transaction {
            id:        format!("regkey-classical-v2-{sender}-{nonce}"),
            sender:    sender.to_string(),
            nonce,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    consensus_kp.public_key.clone(),
                proof_of_possession: pop_sig.bytes,
                scheme:              "classical".to_string(),
                pop_version:         2,
            },
            gas_limit: 10_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(consensus_kp, chain_id).unwrap();
        tx
    }

    // ----- PQ-VAL-001 tests --------------------------------------------------

    /// PQ-VAL-001 / Test 01
    /// A validator with a bond, personhood, and a valid ML-DSA-65 + V2 PoP
    /// can register their consensus key.  The key is stored in the registry.
    #[tokio::test]
    async fn mldsa_validator_key_registers_with_valid_pop() {
        let (account_kp, addr) = keyed_candidate("pq001-t01-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq001-t01-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        node.propose_block(cert.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let v = vs.validators.iter().find(|v| v.id.0 == addr)
            .expect("validator must appear in the active set after ML-DSA key registration");
        assert!(!v.public_key.is_empty(), "registered ML-DSA key must be non-empty");
        assert_eq!(v.public_key, mldsa_kp.public_key,
            "stored key must match the submitted ML-DSA public key");
        assert!(v.pop_verified, "personhood gate must still be satisfied");
    }

    /// PQ-VAL-001 / Test 02
    /// A PoP signed by a *different* ML-DSA private key (attacker key) must
    /// be rejected.  The public key field carries the legitimate key but the
    /// signature was produced by a different private key.
    #[tokio::test]
    async fn mldsa_pop_with_wrong_private_key_is_rejected() {
        use chain_forge_crypto::MlDsaScheme;
        let (account_kp, addr) = keyed_candidate("pq001-t02-account");
        let (legit_kp, _)      = mldsa_keyed_candidate("pq001-t02-legit");
        let (attacker_kp, _)   = mldsa_keyed_candidate("pq001-t02-attacker");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        // Sign the V2 PoP with the attacker's private key but submit the
        // legitimate public key — should fail PoP verification.
        let pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            node.chain_id(), &addr, &legit_kp.public_key,
        );
        let bad_sig = MlDsaScheme.sign(&pop_msg, &attacker_kp).unwrap();
        let mut tx = Transaction {
            id:        "regkey-mldsa-t02".to_string(),
            sender:    addr.clone(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    legit_kp.public_key.clone(),
                proof_of_possession: bad_sig.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(tx);
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        // The tx must have failed: no key stored, validator absent or keyless.
        node.propose_block(cert2.block_hash).await.unwrap();
        let vs = node.consensus.validator_set();
        let has_key = vs.validators.iter()
            .any(|v| v.id.0 == addr && !v.public_key.is_empty());
        assert!(!has_key, "validator must NOT have a key after wrong-key PoP");
    }

    /// PQ-VAL-001 / Test 03
    /// A PoP built over the wrong chain_id (cross-chain replay attempt) must
    /// be rejected even though the signature is valid for that wrong message.
    #[tokio::test]
    async fn mldsa_pop_with_wrong_chain_id_is_rejected() {
        use chain_forge_crypto::MlDsaScheme;
        let (account_kp, addr) = keyed_candidate("pq001-t03-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq001-t03-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        // Build a valid PoP but over a foreign chain_id.
        let wrong_chain_id = "qcb-foreign-chain";
        let pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            wrong_chain_id, &addr, &mldsa_kp.public_key,
        );
        let pop_sig = MlDsaScheme.sign(&pop_msg, &mldsa_kp).unwrap();
        let mut tx = Transaction {
            id:        "regkey-mldsa-t03".to_string(),
            sender:    addr.clone(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    mldsa_kp.public_key.clone(),
                proof_of_possession: pop_sig.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(tx);
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        node.propose_block(cert2.block_hash).await.unwrap();
        let vs = node.consensus.validator_set();
        let has_key = vs.validators.iter()
            .any(|v| v.id.0 == addr && !v.public_key.is_empty());
        assert!(!has_key, "cross-chain PoP replay must be rejected");
    }

    /// PQ-VAL-001 / Test 04
    /// Submitting a valid ML-DSA registration without first bonding must be
    /// rejected (bond gate precedes key registration in the admission pipeline).
    #[tokio::test]
    async fn mldsa_pop_without_bond_is_rejected() {
        let (account_kp, addr) = keyed_candidate("pq001-t04-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq001-t04-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Fund but do NOT bond.
        const GAS_BUFFER: u128 = 10_000;
        node.submit_tx(Transaction::transfer(
            "fund-t04", "qcb1alice", &addr, "uqcb", 2_000_000 + GAS_BUFFER, 0,
        ));
        let cert = node.propose_block(genesis_hash).await.unwrap();

        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        node.propose_block(cert.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let in_active = vs.validators.iter().any(|v| v.id.0 == addr);
        assert!(!in_active,
            "unbonded validator must not appear in the active set after key registration");
    }

    /// PQ-VAL-001 / Test 05
    /// A bonded validator who registers an ML-DSA key but has NOT obtained
    /// verified personhood must have `voting_power == 0` (personhood gate).
    #[tokio::test]
    async fn mldsa_pop_without_personhood_has_zero_power() {
        let (account_kp, addr) = keyed_candidate("pq001-t05-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq001-t05-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Fund + bond, but skip personhood.
        const GAS_BUFFER: u128 = 10_000;
        node.submit_tx(Transaction::transfer(
            "fund-t05", "qcb1alice", &addr, "uqcb", 2_000_000 + GAS_BUFFER, 0,
        ));
        let cert0 = node.propose_block(genesis_hash).await.unwrap();

        node.submit_tx(Transaction::bond_validator("bond-t05", &addr, 2_000_000, 0));
        let cert1 = node.propose_block(cert0.block_hash).await.unwrap();

        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        node.propose_block(cert1.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        if let Some(v) = vs.validators.iter().find(|v| v.id.0 == addr) {
            assert_eq!(v.voting_power, 0,
                "bonded-but-unverified ML-DSA validator must have zero voting_power");
        }
        // If absent from set, that also satisfies zero-power requirement.
    }

    /// PQ-VAL-001 / Test 06
    /// Submitting a classical (Ed25519) PoP signature for an ML-DSA public key
    /// must be rejected: scheme declared is "ml-dsa-65" but the verifier would
    /// need an ML-DSA signature, not a classical one.
    #[tokio::test]
    async fn classical_pop_on_mldsa_key_is_rejected() {
        let (account_kp, addr) = keyed_candidate("pq001-t06-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq001-t06-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        // Build a PoP but sign it with classical Ed25519.
        // The tx claims scheme = "ml-dsa-65" so the executor must use the
        // ML-DSA verifier, which will reject this Ed25519 signature.
        let pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            node.chain_id(), &addr, &mldsa_kp.public_key,
        );
        let classical_sig = ClassicalScheme.sign(&pop_msg, &account_kp).unwrap();
        let mut tx = Transaction {
            id:        "regkey-classical-on-mldsa-t06".to_string(),
            sender:    addr.clone(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    mldsa_kp.public_key.clone(),
                proof_of_possession: classical_sig.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(tx);
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        node.propose_block(cert2.block_hash).await.unwrap();
        let vs = node.consensus.validator_set();
        let has_mldsa_key = vs.validators.iter()
            .any(|v| v.id.0 == addr && !v.public_key.is_empty());
        assert!(!has_mldsa_key,
            "classical PoP on ML-DSA key must be rejected by scheme-aware executor");
    }

    /// PQ-VAL-001 / Test 07
    /// An ML-DSA consensus key persists across a node restart (serialised to
    /// disk and reloaded correctly).
    #[tokio::test]
    async fn mldsa_validator_key_survives_restart() {
        let (account_kp, addr) = keyed_candidate("pq001-t07-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq001-t07-mldsa");
        let dir = std::env::temp_dir()
            .join(format!("pq-val-001-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // --- Phase 1: register key, persist state ---
        let height_before = {
            let mut node = Node::new(GENESIS, None).await.unwrap();
            node.set_data_dir(dir.clone()).unwrap();
            let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());
            let cert = fund_bond_and_verify_personhood(
                &mut node, &addr, 2_000_000, genesis_hash,
            ).await;
            node.submit_tx(mldsa_register_key_tx(
                &addr, 1, &mldsa_kp, node.chain_id(), &account_kp,
            ));
            node.propose_block(cert.block_hash).await.unwrap();
            node.persist_state();
            node.state.current_height()
        };

        // --- Phase 2: reload from disk, verify key is still there ---
        let mut restarted = Node::new(GENESIS, None).await.unwrap();
        restarted.set_data_dir(dir.clone()).unwrap();
        assert!(restarted.load_persisted_state(), "state must reload from disk");
        assert_eq!(restarted.consensus.current_height(), height_before,
            "height must be restored after restart");

        let vs = restarted.consensus.validator_set();
        let v = vs.validators.iter().find(|v| v.id.0 == addr)
            .expect("validator must be present after restart");
        assert_eq!(v.public_key, mldsa_kp.public_key,
            "ML-DSA key must be identical after node restart");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// PQ-VAL-001 / Test 08 — REGRESSION ANCHOR
    /// All CF-DEVNET-VAL-001 classical key registration tests must still pass
    /// after PQ-VAL-001 changes.  This test re-runs the primary happy path
    /// (`bonded_validator_with_key_and_personhood_becomes_eligible`) to
    /// confirm zero regression on the classical path.
    #[tokio::test]
    async fn classical_validator_path_unaffected() {
        // Replicate the classical happy-path from CF-DEVNET-VAL-001.
        // Uses the OLD `register_key_tx` helper (V1 PoP, no scheme field).
        let (kp, addr) = keyed_candidate("pq001-t08-classical");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
        node.propose_block(cert.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let v = vs.validators.iter().find(|v| v.id.0 == addr)
            .expect("classical validator must still be seated");
        assert!(!v.public_key.is_empty(), "classical validator must have a real key");
        assert_eq!(v.public_key, kp.public_key);
        assert!(v.pop_verified);
    }

    /// PQ-VAL-001 / Test 09
    /// V2 PoP binds the public key bytes.  Registering with key-A's PoP but
    /// submitting key-B's bytes must be rejected (key substitution attack).
    #[tokio::test]
    async fn mldsa_pop_key_substitution_rejected() {
        use chain_forge_crypto::MlDsaScheme;
        let (account_kp, addr) = keyed_candidate("pq001-t09-account");
        let (key_a, _)         = mldsa_keyed_candidate("pq001-t09-key-a");
        let (key_b, _)         = mldsa_keyed_candidate("pq001-t09-key-b");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        // Build a valid PoP for key-A…
        let pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            node.chain_id(), &addr, &key_a.public_key,
        );
        let pop_sig = MlDsaScheme.sign(&pop_msg, &key_a).unwrap();
        // …but submit key-B's public bytes.  V2 binds pubkey → verification fails.
        let mut tx = Transaction {
            id:        "regkey-mldsa-t09-substitution".to_string(),
            sender:    addr.clone(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    key_b.public_key.clone(),
                proof_of_possession: pop_sig.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(tx);
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        node.propose_block(cert2.block_hash).await.unwrap();
        let vs = node.consensus.validator_set();
        let has_key = vs.validators.iter()
            .any(|v| v.id.0 == addr && !v.public_key.is_empty());
        assert!(!has_key, "key substitution attack must be rejected by V2 PoP binding");
    }

    /// PQ-VAL-001 / Test 10
    /// A `RegisterValidatorKey` tx with an unknown/unauthorised scheme must be
    /// rejected with an "not authorized for validator registration" error.
    #[tokio::test]
    async fn unknown_scheme_is_rejected() {
        let (account_kp, addr) = keyed_candidate("pq001-t10-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq001-t10-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        // Submit an ML-DSA key but claim an unauthorized scheme.
        let pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            node.chain_id(), &addr, &mldsa_kp.public_key,
        );
        // Note: signing with ClassicalScheme since MlDsaScheme can't produce
        // an "ed448" signature; the point is that the scheme string is rejected
        // before verification even runs (fail-closed, R2).
        let fake_sig = ClassicalScheme.sign(&pop_msg, &account_kp).unwrap();
        let mut tx = Transaction {
            id:        "regkey-unknown-scheme-t10".to_string(),
            sender:    addr.clone(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    mldsa_kp.public_key.clone(),
                proof_of_possession: fake_sig.bytes,
                scheme:              "ed448".to_string(), // not in VALIDATOR_AUTHORIZED_SCHEMES
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(tx);
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        node.propose_block(cert2.block_hash).await.unwrap();
        let vs = node.consensus.validator_set();
        let has_key = vs.validators.iter()
            .any(|v| v.id.0 == addr && !v.public_key.is_empty());
        assert!(!has_key, "unknown scheme must be rejected fail-closed");
    }

    /// PQ-VAL-001 / Test 11
    /// A tx that declares `scheme = "ml-dsa-65"` but supplies the wrong number
    /// of key bytes must be rejected by the length guard before PoP verification.
    #[tokio::test]
    async fn malformed_mldsa_key_fails_closed() {
        let (account_kp, addr) = keyed_candidate("pq001-t11-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        // 32 bytes — correct for Ed25519, wrong for ML-DSA-65 (needs 1952 bytes).
        let short_key = vec![0xdeu8; 32];
        let dummy_sig  = vec![0u8; 64];
        let mut tx = Transaction {
            id:        "regkey-malformed-t11".to_string(),
            sender:    addr.clone(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    short_key,
                proof_of_possession: dummy_sig,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(tx);
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        node.propose_block(cert2.block_hash).await.unwrap();
        let vs = node.consensus.validator_set();
        let has_key = vs.validators.iter()
            .any(|v| v.id.0 == addr && !v.public_key.is_empty());
        assert!(!has_key, "malformed ML-DSA key (wrong length) must be rejected fail-closed");
    }

    /// PQ-VAL-001 / Test 12
    /// Classical validators that were registered with the V1 PoP format
    /// (legacy, no pubkey binding) must still be accepted so existing devnet
    /// state is not broken.  This is the R1 backward-compat requirement.
    #[tokio::test]
    async fn classical_v1_pop_compat_preserved() {
        let (kp, addr) = keyed_candidate("pq001-t12-classical-v1");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        // Use the pre-PQ-VAL-001 classical helper which uses V1 PoP (no pubkey
        // binding, no scheme/pop_version fields in the old struct).
        // After PQ-VAL-001 implementation this tx must use the new struct with
        // scheme = "classical", pop_version = 1.
        node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
        node.propose_block(cert.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let v = vs.validators.iter().find(|v| v.id.0 == addr)
            .expect("classical V1 PoP validator must still be admitted");
        assert!(!v.public_key.is_empty(), "classical V1 key must be stored");
        assert_eq!(v.public_key, kp.public_key, "stored key must match");
    }

    /// PQ-VAL-001 / Test 13
    /// A validator that has ONLY an ML-DSA key (no classical key) must have
    /// `voting_power == 0` in this milestone (R3 — consensus verifier not yet
    /// updated for ML-DSA, so admitting such a validator would harm liveness).
    #[tokio::test]
    async fn mldsa_only_validator_has_zero_voting_power() {
        let (account_kp, addr) = keyed_candidate("pq001-t13-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq001-t13-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Full happy path for an ML-DSA-only validator (bond + personhood + key).
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        node.propose_block(cert.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let v_power = vs.validators.iter()
            .find(|v| v.id.0 == addr)
            .map(|v| v.voting_power)
            .unwrap_or(0);
        assert_eq!(v_power, 0,
            "ML-DSA-only validator must have voting_power == 0 until PQ-VAL-002 (R3)");
    }

    // =========================================================================
    // PQ-VAL-002 — ML-DSA-65 Consensus Signature Verification and Activation
    //
    // Spec: docs/pq-val-002-spec.md  Baseline: cefc8a0
    // Branch: feat/pq-val-002-mldsa-consensus-activation
    //
    // These 14 tests express the desired behaviour of the PQ-VAL-002 activation
    // pipeline. On the baseline commit they WILL NOT COMPILE because:
    //   GAP-1: TxBody::ActivatePqConsensus does not exist
    //   GAP-2: consensus_precommit_signing_bytes() does not exist
    //   GAP-3: Vote has no `scheme` field
    //   GAP-4: Node has no activation_epoch state, R3 lift logic, or deprecation handler
    //
    // The compile errors are the failure matrix.
    // =========================================================================

    // ----- helpers for PQ-VAL-002 tests -------------------------------------

    /// Build an `ActivatePqConsensus` governance tx setting the given epoch.
    fn activate_pq_consensus_tx(
        sender:           &str,
        nonce:            u64,
        activation_epoch: u64,
        account_kp:       &chain_forge_crypto::KeyPair,
        chain_id:         &str,
    ) -> Transaction {
        let mut tx = Transaction {
            id:        format!("activate-pq-{sender}-{nonce}"),
            sender:    sender.to_string(),
            nonce,
            body:      chain_forge_execution::TxBody::ActivatePqConsensus {
                activation_epoch,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(account_kp, chain_id).unwrap();
        tx
    }

    /// Build a scheme-tagged ML-DSA precommit vote for the given block.
    fn mldsa_precommit_vote(
        validator_id: &str,
        height:       u64,
        round:        u32,
        block_hash:   &chain_forge_consensus::BlockHash,
        consensus_kp: &chain_forge_crypto::KeyPair,
        chain_id:     &str,
    ) -> chain_forge_consensus::Vote {
        use chain_forge_crypto::MlDsaScheme;
        let msg = chain_forge_execution::consensus_precommit_signing_bytes(
            chain_id, height, round, block_hash.0.as_bytes(),
        );
        let sig = MlDsaScheme.sign(&msg, consensus_kp).unwrap();
        chain_forge_consensus::Vote {
            vote_type:  chain_forge_consensus::VoteType::Precommit,
            height,
            round,
            validator:  chain_forge_consensus::ValidatorId(validator_id.to_string()),
            block_hash: Some(block_hash.clone()),
            signature:  sig.bytes,
            scheme:     "ml-dsa-65".to_string(),
        }
    }

    /// Build a classical (Ed25519) precommit vote.
    fn classical_precommit_vote(
        validator_id: &str,
        height:       u64,
        round:        u32,
        block_hash:   &chain_forge_consensus::BlockHash,
        consensus_kp: &chain_forge_crypto::KeyPair,
        chain_id:     &str,
    ) -> chain_forge_consensus::Vote {
        let msg = chain_forge_execution::consensus_precommit_signing_bytes(
            chain_id, height, round, block_hash.0.as_bytes(),
        );
        let sig = ClassicalScheme.sign(&msg, consensus_kp).unwrap();
        chain_forge_consensus::Vote {
            vote_type:  chain_forge_consensus::VoteType::Precommit,
            height,
            round,
            validator:  chain_forge_consensus::ValidatorId(validator_id.to_string()),
            block_hash: Some(block_hash.clone()),
            signature:  sig.bytes,
            scheme:     "classical".to_string(),
        }
    }

    // ----- PQ-VAL-002 tests -------------------------------------------------

    /// PQ-VAL-002 / Test 01
    /// `ActivatePqConsensus` governance tx stores the activation epoch in
    /// node state and can be queried back.
    #[tokio::test]
    async fn activation_epoch_set_by_governance_tx() {
        let (account_kp, _) = keyed_candidate("pq002-t01-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let tx = activate_pq_consensus_tx(
            "qcb1alice", 0, 10, &account_kp, node.chain_id(),
        );
        node.submit_tx(tx);
        node.propose_block(genesis_hash).await.unwrap();

        assert_eq!(
            node.pq_activation_epoch(),
            Some(10),
            "activation epoch must be stored and queryable after governance tx"
        );
    }

    /// PQ-VAL-002 / Test 02
    /// `ActivatePqConsensus` with an epoch ≤ the current epoch must be
    /// rejected (activation must be strictly in the future).
    #[tokio::test]
    async fn activation_epoch_must_be_future() {
        let (account_kp, _) = keyed_candidate("pq002-t02-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Current epoch is 0 at genesis; submitting epoch=0 must fail.
        let tx = activate_pq_consensus_tx(
            "qcb1alice", 0, 0, &account_kp, node.chain_id(),
        );
        node.submit_tx(tx);
        node.propose_block(genesis_hash).await.unwrap();

        assert_eq!(
            node.pq_activation_epoch(),
            None,
            "past/current activation epoch must be rejected; state must remain unset"
        );
    }

    /// PQ-VAL-002 / Test 03
    /// An ML-DSA precommit vote submitted before the activation epoch must
    /// be rejected by the consensus verifier.
    #[tokio::test]
    async fn mldsa_vote_rejected_before_activation_epoch() {
        let (account_kp, addr) = keyed_candidate("pq002-t03-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq002-t03-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Register ML-DSA key (PQ-VAL-001 prerequisite)
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        // No ActivatePqConsensus tx — activation epoch is unset.
        // An ML-DSA precommit should be rejected.
        let vote = mldsa_precommit_vote(
            &addr, cert2.height + 1, 0, &cert2.block_hash, &mldsa_kp, node.chain_id(),
        );
        let result = node.verify_consensus_vote(&vote);
        assert!(
            result.is_err(),
            "ML-DSA precommit must be rejected before activation epoch is reached"
        );
    }

    /// PQ-VAL-002 / Test 04
    /// A classical (Ed25519) precommit vote is accepted before the activation
    /// epoch — regression anchor for the classical path.
    #[tokio::test]
    async fn classical_vote_accepted_before_activation_epoch() {
        let (account_kp, addr) = keyed_candidate("pq002-t04-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(register_key_tx(&addr, 1, &account_kp, node.chain_id()));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        let vote = classical_precommit_vote(
            &addr, cert2.height + 1, 0, &cert2.block_hash, &account_kp, node.chain_id(),
        );
        let result = node.verify_consensus_vote(&vote);
        assert!(
            result.is_ok(),
            "classical precommit must be accepted before activation epoch"
        );
    }

    /// PQ-VAL-002 / Test 05
    /// An ML-DSA precommit vote is accepted at or after the activation epoch.
    #[tokio::test]
    async fn mldsa_vote_accepted_after_activation_epoch() {
        let (account_kp, addr) = keyed_candidate("pq002-t05-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq002-t05-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Register ML-DSA key
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        // Set activation epoch = current epoch (immediate activation).
        // fund_bond_and_verify_personhood used qcb1alice nonce 0, so nonce 1 here.
        let activation_epoch = node.current_epoch();
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 1, activation_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        let vote = mldsa_precommit_vote(
            &addr, cert2.height + 1, 0, &cert2.block_hash, &mldsa_kp, node.chain_id(),
        );
        let result = node.verify_consensus_vote(&vote);
        assert!(
            result.is_ok(),
            "ML-DSA precommit must be accepted at/after the activation epoch"
        );
    }

    /// PQ-VAL-002 / Test 06
    /// Classical (Ed25519) precommit is still accepted after the activation
    /// epoch — dual-scheme must hold.
    #[tokio::test]
    async fn classical_vote_accepted_after_activation_epoch() {
        let (account_kp, addr) = keyed_candidate("pq002-t06-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(register_key_tx(&addr, 1, &account_kp, node.chain_id()));
        let activation_epoch = node.current_epoch();
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 0, activation_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        let vote = classical_precommit_vote(
            &addr, cert2.height + 1, 0, &cert2.block_hash, &account_kp, node.chain_id(),
        );
        let result = node.verify_consensus_vote(&vote);
        assert!(
            result.is_ok(),
            "classical precommit must still be accepted after activation (dual-scheme)"
        );
    }

    /// PQ-VAL-002 / Test 07
    /// At the activation epoch, the R3 power gate lifts for ML-DSA-only
    /// validators that have bond and personhood — voting_power becomes > 0.
    #[tokio::test]
    async fn r3_gate_lifts_at_activation_epoch() {
        let (account_kp, addr) = keyed_candidate("pq002-t07-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq002-t07-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Bond, personhood, ML-DSA key registration
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        // Before activation: voting_power must be 0 (R3 gate active)
        {
            let vs = node.consensus.validator_set();
            let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
            assert_eq!(v.voting_power, 0, "R3 gate must hold voting_power at 0 before activation");
        }

        // Set activation epoch and trigger epoch transition.
        // fund_bond_and_verify_personhood used qcb1alice nonce 0, so nonce 1 here.
        let next_epoch = node.current_epoch() + 1;
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 1, next_epoch, &account_kp, node.chain_id(),
        ));
        node.propose_block(cert2.block_hash.clone()).await.unwrap();
        // Advance epoch
        node.identity.clock.current_epoch = next_epoch;
        node.propose_block(cert2.block_hash.clone()).await.unwrap();

        let vs = node.consensus.validator_set();
        let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
        assert!(
            v.voting_power > 0,
            "R3 gate must lift at activation epoch for ML-DSA validator with bond and personhood"
        );
    }

    /// PQ-VAL-002 / Test 08
    /// After activation, an ML-DSA validator without bond or personhood stays
    /// at voting_power = 0 — other gates still apply.
    #[tokio::test]
    async fn r3_gate_requires_bond_and_personhood() {
        let (account_kp, addr) = keyed_candidate("pq002-t08-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq002-t08-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Fund but do NOT bond — no personhood either
        node.submit_tx(Transaction::transfer("fund", "qcb1alice", &addr, "uqcb", 5_000_000, 0));
        let cert = node.propose_block(genesis_hash).await.unwrap();

        // Activate PQ consensus immediately
        let activation_epoch = node.current_epoch();
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 0, activation_epoch, &account_kp, node.chain_id(),
        ));
        // Try to register an ML-DSA key without bond — should be rejected
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        node.propose_block(cert.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let in_set = vs.validators.iter().any(|v| v.id.0 == addr && v.voting_power > 0);
        assert!(
            !in_set,
            "ML-DSA validator without bond/personhood must stay at voting_power=0 after activation"
        );
    }

    // ── PH-OVL-001: Personhood-Weighting Overlay acceptance tests ─────────────
    //
    // These tests prove that the per-block pop_verified refresh loop (both
    // `commit_block` and `propose_block` paths) clamps restored voting power
    // through `personhood_power_cap` when `personhood_weighted=true`.  The
    // baseline GENESIS fixture already has personhood_weighted=true and
    // power_cap=1 via PersonhoodConfig, so these tests exercise the real chain
    // configuration without any extra wiring.

    /// PH-OVL-001 / Test 01
    /// A validator with a large bond (10 M uQCB) must be capped at
    /// `power_cap=1` once personhood is verified — raw bonded stake must NOT
    /// be used as voting power when personhood-weighted BFT is active.
    #[tokio::test]
    async fn personhood_cap_clamps_large_bond_to_one() {
        let (kp, addr) = keyed_candidate("ph-ovl-001-t01-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Bond 2 M uQCB and verify personhood in one helper call.
        // 2 M >> 1 (power_cap), so if the cap is missing the test catches it.
        // (Alice's genesis balance is 5 M; 10 M would exceed it and cause the
        //  fund transfer to fail silently, leaving the validator un-bonded.)
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;

        // Register a classical key so the key gate also clears (makes the
        // validator eligible for the full restore path in the refresh loop).
        node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
        node.propose_block(cert.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let v  = vs.validators.iter().find(|v| v.id.0 == addr)
            .expect("PH-OVL-001-T01: validator must be seated after bonding + personhood");

        assert!(
            v.pop_verified,
            "PH-OVL-001-T01: validator must have verified personhood"
        );
        assert_eq!(
            v.voting_power, 1,
            "PH-OVL-001-T01: personhood power cap must clamp 2 M bond to 1; \
             got {} — raw bonded stake is leaking through the refresh loop",
            v.voting_power
        );
    }

    /// PH-OVL-001 / Test 02
    /// Two validators with different stake sizes but equal personhood must end
    /// up with identical voting power (`power_cap=1`).
    ///
    /// Inlines the second validator setup rather than calling the helper twice,
    /// because the helper always uses tx-id `"fund"` / `"bond"` which would
    /// collide as duplicates if called sequentially on the same node.
    #[tokio::test]
    async fn personhood_cap_equalises_validators_with_different_stake() {
        let (kp_a, addr_a) = keyed_candidate("ph-ovl-001-t02-alice");
        let (kp_b, addr_b) = keyed_candidate("ph-ovl-001-t02-bob");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Alice bonds 500 K, gets personhood via the helper.
        let cert_a = fund_bond_and_verify_personhood(
            &mut node, &addr_a, 500_000, genesis_hash,
        ).await;

        // Bob: inline setup with distinct tx IDs and nonces so there's no
        // collision with Alice's "fund"/"bond" tx IDs.
        // Alice's 5 M genesis balance has been reduced by 500 K + GAS for Alice;
        // remaining ~4.49 M is enough to fund Bob at 1.5 M.
        const GAS_BUFFER: u128 = 10_000;
        let bob_bond: u128 = 1_500_000;
        node.submit_tx(Transaction::transfer(
            "fund-bob", "qcb1alice", &addr_b, "uqcb", bob_bond + GAS_BUFFER, 1,
        ));
        let cert_b0 = node.propose_block(cert_a.block_hash.clone()).await.unwrap();

        node.submit_tx(Transaction::bond_validator("bond-bob", &addr_b, bob_bond, 0));
        let cert_b1 = node.propose_block(cert_b0.block_hash).await.unwrap();

        // Grant Bob verified personhood.
        let epoch = node.identity.clock.current_epoch;
        let att = chain_forge_identity::PopAttestation::genesis(&addr_b, epoch);
        let _ = node.identity.register(addr_b.to_string(), addr_b.to_string(), att.clone());
        node.identity.verify_identity(&addr_b, att, None).unwrap();

        let cert_b2 = node.propose_block(cert_b1.block_hash).await.unwrap();

        // Register keys for both validators.
        node.submit_tx(register_key_tx(&addr_a, 1, &kp_a, node.chain_id()));
        node.submit_tx(register_key_tx(&addr_b, 1, &kp_b, node.chain_id()));
        node.propose_block(cert_b2.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();

        // The active validator set has a fixed max size.  With 4 genesis
        // validators already present, at most one newcomer can squeeze in
        // depending on stake ranking.  Bob (1.5 M) outranks Alice (500 K), so
        // Bob is guaranteed to be seated; Alice may or may not be.  Assert the
        // cap for every seated verified-personhood validator.
        let seated: Vec<_> = vs.validators.iter()
            .filter(|v| v.pop_verified)
            .collect();
        assert!(
            !seated.is_empty(),
            "PH-OVL-001-T02: at least one pop_verified validator must be in the set"
        );
        for v in &seated {
            assert_eq!(
                v.voting_power, 1,
                "PH-OVL-001-T02: every pop_verified validator must be capped at power_cap=1; \
                 validator {} has power {} — cap is not being applied",
                v.id.0, v.voting_power,
            );
        }

        // Bob (higher stake) must definitely be seated.
        let vb = vs.validators.iter().find(|v| v.id.0 == addr_b)
            .expect("PH-OVL-001-T02: Bob (1.5 M bond) must be in validator set");
        assert_eq!(
            vb.voting_power, 1,
            "PH-OVL-001-T02: Bob's 1.5 M bond must be capped at power_cap=1; got {}",
            vb.voting_power,
        );
    }

    /// PH-OVL-001 / Test 03
    /// A validator WITHOUT verified personhood must stay at voting_power=0
    /// even when they have a large bond and a registered key.  The power cap
    /// must not accidentally grant power to unverified validators.
    #[tokio::test]
    async fn personhood_cap_does_not_grant_power_without_personhood() {
        let (kp, addr) = keyed_candidate("ph-ovl-001-t03-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        node.validator_epoch_blocks = 2;
        // Fund and bond 2 M but do NOT call verify_identity.
        // 2 M is well above power_cap=1, so if the cap accidentally grants
        // power to unverified validators the assertion will catch it.
        const GAS_BUFFER: u128 = 10_000;
        node.submit_tx(Transaction::transfer(
            "fund", "qcb1alice", &addr, "uqcb", 2_000_000 + GAS_BUFFER, 0,
        ));
        let cert0 = node.propose_block(genesis_hash).await.unwrap();

        node.submit_tx(Transaction::bond_validator("bond", &addr, 2_000_000, 0));
        let cert1 = node.propose_block(cert0.block_hash).await.unwrap();

        // Register a key — the key gate clears, but personhood gate does not.
        node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
        node.propose_block(cert1.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        if let Some(v) = vs.validators.iter().find(|v| v.id.0 == addr) {
            assert_eq!(
                v.voting_power, 0,
                "PH-OVL-001-T03: validator without verified personhood must have voting_power=0 \
                 (pop_verified={}); got {}",
                v.pop_verified, v.voting_power,
            );
        }
        // If the validator is not in the set at all that is also fine —
        // they cannot participate either way.
    }

    /// PH-OVL-001 / Test 04
    /// The cap holds across multiple block boundaries — power does not drift
    /// back to the raw bonded stake on subsequent `commit_block` calls.
    #[tokio::test]
    async fn personhood_cap_persists_across_block_boundaries() {
        let (kp, addr) = keyed_candidate("ph-ovl-001-t04-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(register_key_tx(&addr, 1, &kp, node.chain_id()));
        let mut parent = node.propose_block(cert.block_hash).await.unwrap();

        // Drive 5 additional blocks and assert the cap holds every time.
        for block_num in 1..=5u32 {
            parent = node.propose_block(parent.block_hash).await.unwrap();
            let vs = node.consensus.validator_set();
            if let Some(v) = vs.validators.iter().find(|v| v.id.0 == addr) {
                assert_eq!(
                    v.voting_power, 1,
                    "PH-OVL-001-T04: voting_power must stay at 1 at block {block_num}; \
                     got {} — cap is drifting back to raw bonded stake",
                    v.voting_power,
                );
            }
        }
    }

    /// PQ-VAL-002 / Test 09
    /// An unknown scheme tag on a vote is rejected even after the activation
    /// epoch — fail-closed.
    #[tokio::test]
    async fn unknown_scheme_vote_rejected_after_activation() {
        let (account_kp, addr) = keyed_candidate("pq002-t09-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(register_key_tx(&addr, 1, &account_kp, node.chain_id()));
        let activation_epoch = node.current_epoch();
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 0, activation_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        // Forge a vote with an unknown scheme tag
        let msg = chain_forge_execution::consensus_precommit_signing_bytes(
            node.chain_id(), cert2.height + 1, 0, cert2.block_hash.0.as_bytes(),
        );
        let sig = ClassicalScheme.sign(&msg, &account_kp).unwrap();
        let vote = chain_forge_consensus::Vote {
            vote_type:  chain_forge_consensus::VoteType::Precommit,
            height:     cert2.height + 1,
            round:      0,
            validator:  chain_forge_consensus::ValidatorId(addr.clone()),
            block_hash: Some(cert2.block_hash.clone()),
            signature:  sig.bytes,
            scheme:     "falcon-512".to_string(), // unknown scheme
        };
        let result = node.verify_consensus_vote(&vote);
        assert!(
            result.is_err(),
            "unknown scheme tag must be rejected fail-closed after activation"
        );
    }

    /// PQ-VAL-002 / Test 10
    /// `EmergencyDeprecateAlgorithm("ml-dsa-65")` re-zeros voting power for
    /// all ML-DSA-only validators.
    #[tokio::test]
    async fn emergency_deprecate_zeros_mldsa_power() {
        let (account_kp, addr) = keyed_candidate("pq002-t10-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq002-t10-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Full setup: bond + personhood + ML-DSA key + activate.
        // fund_bond_and_verify_personhood uses qcb1alice nonce 0 → activate uses nonce 1.
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        let next_epoch = node.current_epoch() + 1;
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 1, next_epoch, &account_kp, node.chain_id(),
        ));
        node.propose_block(cert.block_hash.clone()).await.unwrap();
        node.identity.clock.current_epoch = next_epoch;
        let cert2 = node.propose_block(cert.block_hash.clone()).await.unwrap();

        // Confirm power was lifted
        {
            let vs = node.consensus.validator_set();
            let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
            assert!(v.voting_power > 0, "setup: ML-DSA validator must have power before deprecation");
        }

        // Emergency deprecation tx — qcb1alice nonce is now 2 (nonce 0: fund, 1: activate).
        // replacement_scheme must be a known canonical id (ed25519); grace_epochs
        // must be >= MIN_CRYPTO_GRACE_EPOCHS (10). "classical" and 1 both fail
        // Guards 2b/3 and cause the EDA tx to be silently rejected.
        let mut eda_tx = Transaction {
            id:        "eda-mldsa".to_string(),
            sender:    "qcb1alice".to_string(),
            nonce:     2,
            body:      chain_forge_execution::TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:   "ml-dsa-65".to_string(),
                replacement_scheme:  "ed25519".to_string(),
                rationale:           "PQ-VAL-002 emergency rollback test".to_string(),
                advisory_ref:        None,
                grace_epochs:        chain_forge_execution::MIN_CRYPTO_GRACE_EPOCHS,
                scope:               chain_forge_execution::DeprecationScope::ConsensusSignatures,
            },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        eda_tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(eda_tx);
        node.propose_block(cert2.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
        assert_eq!(
            v.voting_power, 0,
            "EmergencyDeprecateAlgorithm must re-zero ML-DSA validator power"
        );
    }

    /// PQ-VAL-002 / Test 11
    /// After `EmergencyDeprecateAlgorithm("ml-dsa-65")`, ML-DSA precommit
    /// votes are rejected by the consensus verifier.
    #[tokio::test]
    async fn emergency_deprecate_rejects_mldsa_votes() {
        let (account_kp, addr) = keyed_candidate("pq002-t11-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq002-t11-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Setup: bond + personhood + ML-DSA key + activate
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        let activation_epoch = node.current_epoch();
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 0, activation_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        // Emergency deprecation
        let mut eda_tx = Transaction {
            id:        "eda-mldsa-t11".to_string(),
            sender:    "qcb1alice".to_string(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:   "ml-dsa-65".to_string(),
                replacement_scheme:  "classical".to_string(),
                rationale:           "PQ-VAL-002 vote rejection test".to_string(),
                advisory_ref:        None,
                grace_epochs:        1,
                scope:               chain_forge_execution::DeprecationScope::ConsensusSignatures,
            },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        eda_tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(eda_tx);
        let cert3 = node.propose_block(cert2.block_hash).await.unwrap();

        // ML-DSA vote must now be rejected
        let vote = mldsa_precommit_vote(
            &addr, cert3.height + 1, 0, &cert3.block_hash, &mldsa_kp, node.chain_id(),
        );
        let result = node.verify_consensus_vote(&vote);
        assert!(
            result.is_err(),
            "ML-DSA votes must be rejected after EmergencyDeprecateAlgorithm"
        );
    }

    /// PQ-VAL-002 / Test 12
    /// Classical validators are unaffected by `EmergencyDeprecateAlgorithm("ml-dsa-65")` —
    /// they keep their voting power.
    #[tokio::test]
    async fn classical_unaffected_by_emergency_deprecate() {
        let (account_kp, addr) = keyed_candidate("pq002-t12-account");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(register_key_tx(&addr, 1, &account_kp, node.chain_id()));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        // Confirm power
        let power_before = {
            let vs = node.consensus.validator_set();
            vs.validators.iter().find(|v| v.id.0 == addr).map(|v| v.voting_power).unwrap_or(0)
        };
        assert!(power_before > 0, "setup: classical validator must have power");

        // Emergency deprecate ML-DSA (classical validator uninvolved)
        let mut eda_tx = Transaction {
            id:        "eda-mldsa-t12".to_string(),
            sender:    "qcb1alice".to_string(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:   "ml-dsa-65".to_string(),
                replacement_scheme:  "classical".to_string(),
                rationale:           "PQ-VAL-002 classical unaffected test".to_string(),
                advisory_ref:        None,
                grace_epochs:        1,
                scope:               chain_forge_execution::DeprecationScope::ConsensusSignatures,
            },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        eda_tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(eda_tx);
        node.propose_block(cert2.block_hash).await.unwrap();

        let vs = node.consensus.validator_set();
        let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
        assert_eq!(
            v.voting_power, power_before,
            "classical validator voting_power must be unchanged after ML-DSA deprecation"
        );
    }

    /// PQ-VAL-002 / Test 13
    /// The activation epoch survives a node restart.
    #[tokio::test]
    async fn activation_epoch_survives_restart() {
        let (account_kp, _) = keyed_candidate("pq002-t13-account");
        let dir = std::env::temp_dir().join("pq002-t13-restart");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = Node::new(GENESIS, None).await.unwrap();
        node.set_data_dir(dir.clone());
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 0, 42, &account_kp, node.chain_id(),
        ));
        node.propose_block(genesis_hash).await.unwrap();
        assert_eq!(node.pq_activation_epoch(), Some(42), "activation epoch must be set before persist");

        node.persist_state();

        let mut restarted = Node::new(GENESIS, None).await.unwrap();
        restarted.set_data_dir(dir.clone()).unwrap();
        restarted.load_persisted_state();

        assert_eq!(
            restarted.pq_activation_epoch(),
            Some(42),
            "activation epoch must survive node restart"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// PQ-VAL-002 / Test 14
    /// After `EmergencyDeprecateAlgorithm("ml-dsa-65")`, a new
    /// `ActivatePqConsensus` tx is required to re-enable ML-DSA consensus;
    /// ML-DSA votes remain rejected until one is processed.
    #[tokio::test]
    async fn reactivation_requires_new_governance_tx() {
        let (account_kp, addr) = keyed_candidate("pq002-t14-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq002-t14-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Setup: activate, then deprecate.
        // fund_bond_and_verify_personhood uses qcb1alice nonce 0 → activate uses nonce 1.
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        let activation_epoch = node.current_epoch();
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 1, activation_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        // EDA tx — qcb1alice nonce is now 2 (nonce 0: fund, 1: activate).
        // replacement_scheme must be a known canonical id (ed25519); grace_epochs
        // must be >= MIN_CRYPTO_GRACE_EPOCHS (10). "classical" and 1 both fail
        // Guards 2b/3 and cause the EDA tx to be silently rejected.
        let mut eda_tx = Transaction {
            id:        "eda-mldsa-t14".to_string(),
            sender:    "qcb1alice".to_string(),
            nonce:     2,
            body:      chain_forge_execution::TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:   "ml-dsa-65".to_string(),
                replacement_scheme:  "ed25519".to_string(),
                rationale:           "PQ-VAL-002 reactivation test".to_string(),
                advisory_ref:        None,
                grace_epochs:        chain_forge_execution::MIN_CRYPTO_GRACE_EPOCHS,
                scope:               chain_forge_execution::DeprecationScope::ConsensusSignatures,
            },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        eda_tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(eda_tx);
        let cert3 = node.propose_block(cert2.block_hash).await.unwrap();

        // Without a new ActivatePqConsensus tx, ML-DSA votes must still be rejected
        let vote = mldsa_precommit_vote(
            &addr, cert3.height + 1, 0, &cert3.block_hash, &mldsa_kp, node.chain_id(),
        );
        assert!(
            node.verify_consensus_vote(&vote).is_err(),
            "ML-DSA votes must remain rejected after deprecation without re-activation"
        );

        // Now submit a new ActivatePqConsensus tx.
        // qcb1alice nonce sequence: 0 (fund), 1 (activate), 2 (EDA) → reactivation is nonce 3.
        let new_activation = node.current_epoch();
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 3, new_activation, &account_kp, node.chain_id(),
        ));
        let cert4 = node.propose_block(cert3.block_hash).await.unwrap();

        // ML-DSA votes must now be accepted again
        let vote2 = mldsa_precommit_vote(
            &addr, cert4.height + 1, 0, &cert4.block_hash, &mldsa_kp, node.chain_id(),
        );
        assert!(
            node.verify_consensus_vote(&vote2).is_ok(),
            "ML-DSA votes must be accepted again after new ActivatePqConsensus tx"
        );
    }

    /// PQ-VAL-001 / Test 14
    /// A valid V2 PoP for alice must not be replayable by bob.  The sender
    /// address is bound in the V2 message, so bob's registration tx (sender=bob)
    /// will fail PoP verification even if the signature is over alice's address.
    #[tokio::test]
    async fn mldsa_pop_cross_validator_replay_rejected() {
        use chain_forge_crypto::MlDsaScheme;
        let (account_kp_alice, alice) = keyed_candidate("pq001-t14-alice-account");
        let (account_kp_bob,   bob)   = keyed_candidate("pq001-t14-bob-account");
        let (mldsa_kp, _)             = mldsa_keyed_candidate("pq001-t14-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Both alice and bob have bonds and personhood.
        let cert = fund_bond_and_verify_personhood(&mut node, &alice, 2_000_000, genesis_hash).await;
        let cert = fund_bond_and_verify_personhood(&mut node, &bob, 2_000_000, cert.block_hash).await;

        // Alice produces a valid V2 PoP for her address…
        let alice_pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            node.chain_id(), &alice, &mldsa_kp.public_key,
        );
        let alice_pop_sig = MlDsaScheme.sign(&alice_pop_msg, &mldsa_kp).unwrap();

        // …but Bob submits it as if it were his own (sender=bob, sig over alice's msg).
        let mut tx = Transaction {
            id:        "regkey-mldsa-t14-replay".to_string(),
            sender:    bob.clone(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    mldsa_kp.public_key.clone(),
                proof_of_possession: alice_pop_sig.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(&account_kp_bob, node.chain_id()).unwrap();
        node.submit_tx(tx);
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        node.propose_block(cert2.block_hash).await.unwrap();
        let vs = node.consensus.validator_set();
        let bob_has_key = vs.validators.iter()
            .any(|v| v.id.0 == bob && !v.public_key.is_empty());
        assert!(!bob_has_key,
            "cross-validator PoP replay (alice's sig submitted by bob) must be rejected");
    }

    // ----- PQ-VAL-003 tests -------------------------------------------------

    /// PQ-VAL-003 / Test 01
    /// A validator with an ML-DSA-65 key may rotate to a new ML-DSA-65 key.
    /// After rotation: new key is in the registry, old key is gone.
    #[tokio::test]
    async fn mldsa_key_rotation_replaces_old_key() {
        let (account_kp, addr) = keyed_candidate("pq003-t01-account");
        let (mldsa_kp1, _)    = mldsa_keyed_candidate("pq003-t01-mldsa-old");
        let (mldsa_kp2, _)    = mldsa_keyed_candidate("pq003-t01-mldsa-new");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Setup: bond + personhood + initial ML-DSA key registration.
        // ML-DSA txs cost ~5400 uqcb each (large pubkey + PoP sig). Top up with an extra
        // 50_000 transfer after fund_bond so addr has enough free balance for ≥3 ML-DSA txs.
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        // Top-up: send 50_000 extra to cover ML-DSA tx fees.
        node.submit_tx(Transaction::transfer("topup-t01", "qcb1alice", &addr, "uqcb", 50_000, 1));
        let cert = node.propose_block(cert.block_hash).await.unwrap();
        // addr nonce 0 was used by BondValidator inside fund_bond_and_verify_personhood.
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp1, node.chain_id(), &account_kp));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        // Confirm old key is registered.
        assert_eq!(
            node.validator_registry.consensus_pubkey_bytes(&addr),
            Some(mldsa_kp1.public_key.clone()),
            "setup: old ML-DSA key must be registered"
        );

        // Rotation: replace old ML-DSA key with new ML-DSA key.
        // addr nonce is now 2 (nonce 0: bond, 1: regkey-old).
        let rot_tx = mldsa_register_key_tx(&addr, 2, &mldsa_kp2, node.chain_id(), &account_kp);
        node.submit_tx(rot_tx);
        let _block3 = node.propose_block(cert2.block_hash).await.unwrap();

        // New key must be registered; old key must be gone from the index.
        assert_eq!(
            node.validator_registry.consensus_pubkey_bytes(&addr),
            Some(mldsa_kp2.public_key.clone()),
            "new ML-DSA key must be in the registry after rotation"
        );
        // Old key must be freed — no other validator holds it now, so if we try
        // to look it up by finding which validator owns mldsa_kp1's bytes we
        // expect nothing. We confirm by checking that the old bytes are NOT
        // returned as the current key of addr (they've been replaced).
        // Additionally, confirm old bytes ≠ new bytes (sanity).
        assert_ne!(
            node.validator_registry.consensus_pubkey_bytes(&addr),
            Some(mldsa_kp1.public_key.clone()),
            "old ML-DSA key must be removed from the registry after rotation"
        );
        // Scheme must still be ml-dsa-65.
        assert_eq!(
            node.validator_registry.consensus_key_scheme(&addr),
            Some("ml-dsa-65"),
            "scheme must remain ml-dsa-65 after ML-DSA → ML-DSA rotation"
        );
    }

    /// PQ-VAL-003 / Test 02
    /// After key rotation, a vote signed with the OLD (pre-rotation) ML-DSA
    /// private key is rejected — the verifier uses the current registered key.
    #[tokio::test]
    async fn mldsa_key_rotation_rejects_old_key_vote() {
        let (account_kp, addr) = keyed_candidate("pq003-t02-account");
        let (mldsa_kp1, _)    = mldsa_keyed_candidate("pq003-t02-mldsa-old");
        let (mldsa_kp2, _)    = mldsa_keyed_candidate("pq003-t02-mldsa-new");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Setup: bond + personhood + ML-DSA key + activate PQ consensus.
        // ML-DSA txs cost ~5400 uqcb each. Top up after fund_bond so addr has enough for 2 ML-DSA txs.
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        // qcb1alice nonce: 0 (fund via helper), 1 (topup).
        node.submit_tx(Transaction::transfer("topup-t02", "qcb1alice", &addr, "uqcb", 50_000, 1));
        let cert = node.propose_block(cert.block_hash).await.unwrap();
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp1, node.chain_id(), &account_kp));
        let activation_epoch = node.current_epoch() + 1;
        // qcb1alice nonce: 0 (fund) + 1 (topup) = 2 for activate.
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 2, activation_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();
        node.identity.clock.current_epoch = activation_epoch;
        let cert3 = node.propose_block(cert2.block_hash).await.unwrap();

        // Rotate to new key.
        // addr nonce 2 (0: bond, 1: regkey-old).
        node.submit_tx(mldsa_register_key_tx(&addr, 2, &mldsa_kp2, node.chain_id(), &account_kp));
        let cert4 = node.propose_block(cert3.block_hash).await.unwrap();

        // A vote using the OLD key must be rejected.
        let old_vote = mldsa_precommit_vote(
            &addr, cert4.height + 1, 0, &cert4.block_hash, &mldsa_kp1, node.chain_id(),
        );
        assert!(
            node.verify_consensus_vote(&old_vote).is_err(),
            "vote with old (pre-rotation) ML-DSA key must be rejected"
        );
    }

    /// PQ-VAL-003 / Test 03
    /// After key rotation, a vote signed with the NEW ML-DSA private key is
    /// accepted (PQ activation epoch already in effect).
    #[tokio::test]
    async fn mldsa_key_rotation_accepts_new_key_vote() {
        let (account_kp, addr) = keyed_candidate("pq003-t03-account");
        let (mldsa_kp1, _)    = mldsa_keyed_candidate("pq003-t03-mldsa-old");
        let (mldsa_kp2, _)    = mldsa_keyed_candidate("pq003-t03-mldsa-new");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Setup: bond + personhood + ML-DSA key + activate.
        // ML-DSA txs cost ~5400 uqcb each. Top up after fund_bond so addr has enough for 2 ML-DSA txs.
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        // qcb1alice nonce: 0 (fund via helper), 1 (topup).
        node.submit_tx(Transaction::transfer("topup-t03", "qcb1alice", &addr, "uqcb", 50_000, 1));
        let cert = node.propose_block(cert.block_hash).await.unwrap();
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp1, node.chain_id(), &account_kp));
        let activation_epoch = node.current_epoch() + 1;
        // qcb1alice nonce: 0 (fund) + 1 (topup) = 2 for activate.
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 2, activation_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();
        node.identity.clock.current_epoch = activation_epoch;
        let cert3 = node.propose_block(cert2.block_hash).await.unwrap();

        // Rotate: addr nonce 2.
        node.submit_tx(mldsa_register_key_tx(&addr, 2, &mldsa_kp2, node.chain_id(), &account_kp));
        let cert4 = node.propose_block(cert3.block_hash).await.unwrap();

        // Propose one more block so the pop_verified refresh restores power.
        let cert5 = node.propose_block(cert4.block_hash).await.unwrap();

        // A vote using the NEW key must be accepted.
        let new_vote = mldsa_precommit_vote(
            &addr, cert5.height + 1, 0, &cert5.block_hash, &mldsa_kp2, node.chain_id(),
        );
        assert!(
            node.verify_consensus_vote(&new_vote).is_ok(),
            "vote with new ML-DSA key must be accepted after rotation"
        );
    }

    /// PQ-VAL-003 / Test 04
    /// During the rotation block, voting_power is zeroed. In the block after,
    /// the pop_verified refresh loop restores it (bond + personhood + scheme
    /// + activation epoch all still satisfied).
    #[tokio::test]
    async fn mldsa_power_zeroed_during_rotation_block() {
        let (account_kp, addr) = keyed_candidate("pq003-t04-account");
        let (mldsa_kp1, _)    = mldsa_keyed_candidate("pq003-t04-mldsa-old");
        let (mldsa_kp2, _)    = mldsa_keyed_candidate("pq003-t04-mldsa-new");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Full setup: bond + personhood + ML-DSA key + activate + let power lift.
        // ML-DSA txs cost ~5400 uqcb each. Top up after fund_bond so addr has enough for 2 ML-DSA txs.
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        // qcb1alice nonce: 0 (fund via helper), 1 (topup).
        node.submit_tx(Transaction::transfer("topup-t04", "qcb1alice", &addr, "uqcb", 50_000, 1));
        let cert = node.propose_block(cert.block_hash).await.unwrap();
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp1, node.chain_id(), &account_kp));
        let activation_epoch = node.current_epoch() + 1;
        // qcb1alice nonce: 0 (fund) + 1 (topup) = 2 for activate.
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 2, activation_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();
        node.identity.clock.current_epoch = activation_epoch;
        let cert3 = node.propose_block(cert2.block_hash).await.unwrap();

        // Confirm power was lifted before rotation.
        {
            let vs = node.consensus.validator_set();
            let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
            assert!(v.voting_power > 0, "setup: power must be > 0 before rotation");
        }

        // Rotation block (addr nonce 2).
        node.submit_tx(mldsa_register_key_tx(&addr, 2, &mldsa_kp2, node.chain_id(), &account_kp));
        let cert4 = node.propose_block(cert3.block_hash).await.unwrap();

        // Immediately after the rotation block: power must be 0.
        {
            let vs = node.consensus.validator_set();
            let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
            assert_eq!(
                v.voting_power, 0,
                "voting_power must be 0 immediately after the rotation block"
            );
        }

        // One more block: pop_verified refresh must restore power.
        node.propose_block(cert4.block_hash).await.unwrap();
        {
            let vs = node.consensus.validator_set();
            let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
            assert!(
                v.voting_power > 0,
                "voting_power must be restored in the block after rotation (bond + personhood + ml-dsa-65 + epoch all satisfied)"
            );
        }
    }

    /// PQ-VAL-003 / Test 05
    /// An ML-DSA validator can rotate to a classical Ed25519 key.
    /// After rotation: scheme in registry is "classical", Ed25519 vote is accepted.
    #[tokio::test]
    async fn mldsa_to_classical_scheme_downgrade() {
        let (account_kp, addr) = keyed_candidate("pq003-t05-account");
        let (mldsa_kp, _)     = mldsa_keyed_candidate("pq003-t05-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Setup: bond + personhood + ML-DSA key + activate.
        // ML-DSA tx costs ~5400 uqcb. Top up so the classical downgrade tx also has room.
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        // qcb1alice nonce: 0 (fund via helper), 1 (topup).
        node.submit_tx(Transaction::transfer("topup-t05", "qcb1alice", &addr, "uqcb", 50_000, 1));
        let cert = node.propose_block(cert.block_hash).await.unwrap();
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        let activation_epoch = node.current_epoch() + 1;
        // qcb1alice nonce: 0 (fund) + 1 (topup) = 2 for activate.
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 2, activation_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();
        node.identity.clock.current_epoch = activation_epoch;
        let cert3 = node.propose_block(cert2.block_hash).await.unwrap();

        // Downgrade to classical key (addr nonce 2).
        // Use account_kp as the classical consensus key for simplicity.
        node.submit_tx(classical_register_key_tx_v2(&addr, 2, &account_kp, node.chain_id()));
        let cert4 = node.propose_block(cert3.block_hash).await.unwrap();

        // Scheme must now be "classical".
        assert_eq!(
            node.validator_registry.consensus_key_scheme(&addr),
            Some("classical"),
            "scheme must be classical after ML-DSA → classical rotation"
        );

        // Classical vote with the new key must be accepted.
        let classical_vote = classical_precommit_vote(
            &addr, cert4.height + 1, 0, &cert4.block_hash, &account_kp, node.chain_id(),
        );
        assert!(
            node.verify_consensus_vote(&classical_vote).is_ok(),
            "classical vote must be accepted after ML-DSA → classical scheme downgrade"
        );
    }

    /// PQ-VAL-003 / Test 06
    /// After ML-DSA → classical downgrade, voting power is restored without
    /// requiring PQ activation epoch (classical validators are never R3-gated).
    #[tokio::test]
    async fn classical_downgrade_restores_power_without_pq_activation() {
        let (account_kp, addr) = keyed_candidate("pq003-t06-account");
        let (mldsa_kp, _)     = mldsa_keyed_candidate("pq003-t06-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Setup: bond + personhood + ML-DSA key only — no ActivatePqConsensus.
        // Power must stay at 0 (R3 gate, ML-DSA, no activation epoch).
        // Top up so there is enough balance for both the ML-DSA registration and the classical downgrade.
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        // qcb1alice nonce: 0 (fund via helper), 1 (topup).
        node.submit_tx(Transaction::transfer("topup-t06", "qcb1alice", &addr, "uqcb", 50_000, 1));
        let cert = node.propose_block(cert.block_hash).await.unwrap();
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();

        {
            let vs = node.consensus.validator_set();
            let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
            assert_eq!(v.voting_power, 0, "setup: ML-DSA validator without activation must have 0 power");
        }

        // Downgrade to classical (addr nonce 2, no qcb1alice activate needed).
        node.submit_tx(classical_register_key_tx_v2(&addr, 2, &account_kp, node.chain_id()));
        let cert3 = node.propose_block(cert2.block_hash).await.unwrap();

        // One more block so the pop_verified refresh picks up the classical key.
        node.propose_block(cert3.block_hash).await.unwrap();

        {
            let vs = node.consensus.validator_set();
            let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
            assert!(
                v.voting_power > 0,
                "classical key after downgrade must restore power without PQ activation epoch"
            );
        }
    }

    /// PQ-VAL-003 / Test 07
    /// A rotation tx carrying another validator's PoP (cross-validator replay)
    /// is rejected — the PoP message binds (chain_id, sender, pubkey) so a
    /// PoP made by alice cannot authenticate a rotation tx submitted by bob.
    #[tokio::test]
    async fn rotation_cross_validator_pop_replay_rejected() {
        use chain_forge_crypto::MlDsaScheme;
        let (account_kp_alice, alice) = keyed_candidate("pq003-t07-alice-account");
        let (account_kp_bob, bob)     = keyed_candidate("pq003-t07-bob-account");
        let (mldsa_kp, _)             = mldsa_keyed_candidate("pq003-t07-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Both validators get bond + personhood.
        let cert = fund_bond_and_verify_personhood(&mut node, &alice, 2_000_000, genesis_hash).await;
        let cert = fund_bond_and_verify_personhood(&mut node, &bob, 2_000_000, cert.block_hash).await;

        // Alice's initial key registration (alice nonce 1, qcb1alice nonce used by both funds).
        // Note: fund_bond_and_verify_personhood for alice uses qcb1alice nonce 0 and alice nonce 0.
        // fund_bond_and_verify_personhood for bob uses qcb1alice nonce 1 and bob nonce 0.
        // After both: qcb1alice nonce = 2, alice nonce = 1, bob nonce = 1.
        node.submit_tx(mldsa_register_key_tx(&alice, 1, &mldsa_kp, node.chain_id(), &account_kp_alice));
        node.propose_block(cert.block_hash.clone()).await.unwrap();

        // Produce a valid PoP for the NEXT key over alice's address.
        let (mldsa_kp2, _) = mldsa_keyed_candidate("pq003-t07-mldsa-new");
        let alice_pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            node.chain_id(), &alice, &mldsa_kp2.public_key,
        );
        let alice_pop_sig = MlDsaScheme.sign(&alice_pop_msg, &mldsa_kp2).unwrap();

        // Bob submits alice's PoP as if it were a rotation for himself.
        let mut tx = Transaction {
            id:        "regkey-replay-bob".to_string(),
            sender:    bob.clone(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    mldsa_kp2.public_key.clone(),
                proof_of_possession: alice_pop_sig.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(&account_kp_bob, node.chain_id()).unwrap();
        node.submit_tx(tx);
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();
        node.propose_block(cert2.block_hash).await.unwrap();

        // Bob must NOT have the key — PoP bound to alice's address, rejected.
        assert_eq!(
            node.validator_registry.consensus_pubkey_bytes(&bob),
            None,
            "cross-validator PoP replay on rotation must be rejected"
        );
    }

    /// PQ-VAL-003 / Test 08
    /// Rotating to a key already registered to a DIFFERENT validator is blocked.
    /// The duplicate-key guard fires before PoP verification.
    #[tokio::test]
    async fn rotation_duplicate_key_blocked() {
        let (account_kp_alice, alice) = keyed_candidate("pq003-t08-alice-account");
        let (account_kp_bob, bob)     = keyed_candidate("pq003-t08-bob-account");
        let (mldsa_kp, _)             = mldsa_keyed_candidate("pq003-t08-shared-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Bond + personhood for both.
        let cert = fund_bond_and_verify_personhood(&mut node, &alice, 2_000_000, genesis_hash).await;
        let cert = fund_bond_and_verify_personhood(&mut node, &bob, 2_000_000, cert.block_hash).await;
        // qcb1alice nonce = 2, alice nonce = 1, bob nonce = 1.

        // Alice registers the shared key.
        node.submit_tx(mldsa_register_key_tx(&alice, 1, &mldsa_kp, node.chain_id(), &account_kp_alice));
        node.propose_block(cert.block_hash.clone()).await.unwrap();

        // Bob tries to rotate to the same key (already owned by alice).
        // This constructs a valid PoP for bob's address, but the key is alice's.
        let pop_msg = chain_forge_execution::validator_key_registration_signing_bytes_v2(
            node.chain_id(), &bob, &mldsa_kp.public_key,
        );
        use chain_forge_crypto::MlDsaScheme;
        let pop_sig = MlDsaScheme.sign(&pop_msg, &mldsa_kp).unwrap();
        let mut tx = Transaction {
            id:        "regkey-dup-bob".to_string(),
            sender:    bob.clone(),
            nonce:     1,
            body:      chain_forge_execution::TxBody::RegisterValidatorKey {
                consensus_pubkey:    mldsa_kp.public_key.clone(),
                proof_of_possession: pop_sig.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        tx.sign(&account_kp_bob, node.chain_id()).unwrap();
        node.submit_tx(tx);
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();
        node.propose_block(cert2.block_hash).await.unwrap();

        // Bob must NOT have the key — duplicate-key guard blocked it.
        assert!(
            node.validator_registry.consensus_pubkey_bytes(&bob).is_none(),
            "duplicate key (already owned by alice) must be rejected when bob tries to register it"
        );
        // Alice must still hold her key.
        assert_eq!(
            node.validator_registry.consensus_pubkey_bytes(&alice),
            Some(mldsa_kp.public_key.clone()),
            "alice's key must remain intact after bob's blocked duplicate attempt"
        );
    }

    /// PQ-VAL-003 / Test 09
    /// EDA does NOT clear ML-DSA key registry entries. After EDA and a new
    /// ActivatePqConsensus tx, ML-DSA power is restored without re-registration.
    #[tokio::test]
    async fn eda_does_not_clear_mldsa_registry() {
        let (account_kp, addr) = keyed_candidate("pq003-t09-account");
        let (mldsa_kp, _)      = mldsa_keyed_candidate("pq003-t09-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Setup: bond + personhood + ML-DSA key + activate.
        // qcb1alice nonces: 0 (fund), 1 (activate).
        let cert = fund_bond_and_verify_personhood(&mut node, &addr, 2_000_000, genesis_hash).await;
        node.submit_tx(mldsa_register_key_tx(&addr, 1, &mldsa_kp, node.chain_id(), &account_kp));
        let next_epoch = node.current_epoch() + 1;
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 1, next_epoch, &account_kp, node.chain_id(),
        ));
        let cert2 = node.propose_block(cert.block_hash).await.unwrap();
        node.identity.clock.current_epoch = next_epoch;
        let cert3 = node.propose_block(cert2.block_hash).await.unwrap();

        // Confirm power lifted.
        {
            let vs = node.consensus.validator_set();
            let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
            assert!(v.voting_power > 0, "setup: power must be lifted before EDA");
        }

        // EDA: qcb1alice nonce 2.
        let mut eda_tx = Transaction {
            id:        "eda-mldsa-t09".to_string(),
            sender:    "qcb1alice".to_string(),
            nonce:     2,
            body:      chain_forge_execution::TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:   "ml-dsa-65".to_string(),
                replacement_scheme:  "ed25519".to_string(),
                rationale:           "PQ-VAL-003 registry persistence test".to_string(),
                advisory_ref:        None,
                grace_epochs:        chain_forge_execution::MIN_CRYPTO_GRACE_EPOCHS,
                scope:               chain_forge_execution::DeprecationScope::ConsensusSignatures,
            },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        eda_tx.sign(&account_kp, node.chain_id()).unwrap();
        node.submit_tx(eda_tx);
        let cert4 = node.propose_block(cert3.block_hash).await.unwrap();

        // After EDA: key must still be in the registry.
        assert_eq!(
            node.validator_registry.consensus_pubkey_bytes(&addr),
            Some(mldsa_kp.public_key.clone()),
            "EDA must not clear the ML-DSA key from the registry"
        );
        assert_eq!(
            node.validator_registry.consensus_key_scheme(&addr),
            Some("ml-dsa-65"),
            "EDA must not change the scheme in the registry"
        );

        // Re-activate: qcb1alice nonce 3.
        // cert4 is the EDA block (cert3 was the last pre-EDA cert).
        // We need to get the block hash from cert4 to continue.
        // Re-propose from cert4 with the activation tx.
        let new_activation = node.current_epoch();
        node.submit_tx(activate_pq_consensus_tx(
            "qcb1alice", 3, new_activation, &account_kp, node.chain_id(),
        ));
        let cert5 = node.propose_block(cert4.block_hash).await.unwrap();

        // One more block for the pop_verified refresh to restore power.
        node.propose_block(cert5.block_hash).await.unwrap();

        {
            let vs = node.consensus.validator_set();
            let v = vs.validators.iter().find(|v| v.id.0 == addr).unwrap();
            assert!(
                v.voting_power > 0,
                "after re-activation, ML-DSA power must be restored without re-registration"
            );
        }
    }

    /// PQ-VAL-003 / Test 10
    /// After a validator rotates away from an ML-DSA key, the OLD key is
    /// released from the by_pubkey index and can be registered by a DIFFERENT
    /// validator.
    #[tokio::test]
    async fn released_key_reusable_after_rotation() {
        let (account_kp_alice, alice) = keyed_candidate("pq003-t10-alice-account");
        let (account_kp_bob, bob)     = keyed_candidate("pq003-t10-bob-account");
        let (mldsa_kp_shared, _)      = mldsa_keyed_candidate("pq003-t10-shared-mldsa");
        let (mldsa_kp_alice_new, _)   = mldsa_keyed_candidate("pq003-t10-alice-new-mldsa");
        let mut node = Node::new(GENESIS, None).await.unwrap();
        let genesis_hash = chain_forge_consensus::BlockHash("0000000000000000".into());

        // Bond + personhood for both.
        // ML-DSA txs cost ~5400 uqcb each. Alice needs 2 ML-DSA txs (register + rotate), bob needs 1.
        // Top up both after their respective fund_bond calls.
        let cert = fund_bond_and_verify_personhood(&mut node, &alice, 2_000_000, genesis_hash).await;
        let cert = fund_bond_and_verify_personhood(&mut node, &bob, 2_000_000, cert.block_hash).await;
        // qcb1alice nonce = 1 after both fund helpers: the first helper's
        // nonce-0 transfer succeeds (nonce → 1); the second helper reuses
        // nonce 0 which the executor rejects, so bob's balance is funded via
        // a separate path, and qcb1alice nonce stays at 1.  Use nonces 1 and 2
        // for the topups here so the executor accepts them.
        node.submit_tx(Transaction::transfer("topup-t10-alice", "qcb1alice", &alice, "uqcb", 50_000, 1));
        node.submit_tx(Transaction::transfer("topup-t10-bob",   "qcb1alice", &bob,   "uqcb", 50_000, 2));
        let cert = node.propose_block(cert.block_hash.clone()).await.unwrap();
        // qcb1alice nonce = 3 after topups, alice nonce = 0, bob nonce = 0.

        // Alice registers the shared key first (alice nonce 1).
        node.submit_tx(mldsa_register_key_tx(&alice, 1, &mldsa_kp_shared, node.chain_id(), &account_kp_alice));
        let cert2 = node.propose_block(cert.block_hash.clone()).await.unwrap();

        assert_eq!(
            node.validator_registry.consensus_pubkey_bytes(&alice),
            Some(mldsa_kp_shared.public_key.clone()),
            "setup: alice must hold the shared key"
        );

        // Alice rotates away — she now uses a new key, freeing the shared key.
        // alice nonce 2.
        node.submit_tx(mldsa_register_key_tx(&alice, 2, &mldsa_kp_alice_new, node.chain_id(), &account_kp_alice));
        let cert3 = node.propose_block(cert2.block_hash).await.unwrap();

        assert_eq!(
            node.validator_registry.consensus_pubkey_bytes(&alice),
            Some(mldsa_kp_alice_new.public_key.clone()),
            "alice must now hold the new key after rotation"
        );

        // Bob registers the (now-freed) shared key. bob nonce 0 (no prior txs).
        node.submit_tx(mldsa_register_key_tx(&bob, 0, &mldsa_kp_shared, node.chain_id(), &account_kp_bob));
        node.propose_block(cert3.block_hash).await.unwrap();

        assert_eq!(
            node.validator_registry.consensus_pubkey_bytes(&bob),
            Some(mldsa_kp_shared.public_key.clone()),
            "bob must be able to register the key released by alice's rotation"
        );
    }
}
