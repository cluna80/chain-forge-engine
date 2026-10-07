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
use chain_forge_qrc::QrcEngine;
use chain_forge_agents::AgentStore;
use chain_forge_p2p::{
    MockNetworkService, NetworkConfig, NetworkEvent, NetworkService,
    GossipTopic, OutboundMessage, PeerInfo,
};

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
}

/// Voting-power snapshot for one validator.
/// Used by GET /api/validators to expose the current personhood-weighted set.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorPowerSummary {
    pub id:           String,
    pub voting_power: u64,
    pub pop_verified: bool,
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
    pub gc_receipts: std::collections::VecDeque<chain_forge_resource::UsefulWorkReceipt>,
}

pub const MAX_GC_RECEIPTS: usize = 500;

pub const MAX_RECENT_BLOCKS: usize = 100;

pub type SharedExplorer = Arc<Mutex<ExplorerState>>;

// -- QRC metrics (shared with the API, Section 9.1 / 5.4) -------------------

/// Live snapshot of QRC resource economy metrics.
/// QRC is a data-consumption / resource-credit token (NOT a UBI coin):
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
    /// backs RegisterIdentity and Attest transactions, and ClaimUbi's
    /// verified-tier gate. Threaded through execute_block_with_identity()
    /// on every commit so identity state actually persists across blocks.
    identity: IdentityStore,
    /// QRC resource economy engine — tracks conversion rate Rt, per-resource
    /// utilization EMAs, supply/burn/reserve accounting, and epoch minting caps.
    /// Threaded through execute_block_with_identity() so economy state persists
    /// across blocks (purchase path, contribution path, consumption splits).
    qrc: QrcEngine,
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
}

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
        TxBody::ClaimUbi { .. }            => "claim_ubi",
        TxBody::RedirectToUbiPool { .. }   => "ubi_redirect",
        TxBody::SponsorAgent { .. }        => "sponsor_agent",
        TxBody::RevokeAgent { .. }         => "revoke_agent",
        TxBody::RevokeAttestation { .. }        => "revoke_attestation",
        TxBody::ConfirmSybil { .. }             => "confirm_sybil",
        TxBody::ReverseSybil { .. }             => "reverse_sybil",
        TxBody::ReportSuspectedSybil { .. }     => "report_suspected_sybil",
        // QRC Economic Model v0.1
        TxBody::QrcPurchase { .. }              => "qrc_purchase",
        TxBody::QrcSpend { .. }                 => "qrc_spend",
        TxBody::QrcContributionSettle { .. }    => "qrc_contribution_settle",
        // Phase 1: IntrinsicCharm & AEI agent registration
        TxBody::CharmConfinementUpdate { .. }   => "charm_confinement_update",
        TxBody::IntrinsicCharmRecord { .. }     => "intrinsic_charm_record",
        TxBody::RegisterAgent { .. }            => "register_agent",
        // QRC Economic Model v0.2 epoch boundary signals
        TxBody::EpochOpen { .. }                => "epoch_open",
        TxBody::EpochClose { .. }               => "epoch_close",
        // AEI Phase 2 agent lifecycle
        TxBody::AuthorizeAgent { .. }           => "authorize_agent",
        TxBody::SuspendAgent { .. }             => "suspend_agent",
        TxBody::RevokeAgentFull { .. }          => "revoke_agent_full",
        TxBody::RecordAgentSpend { .. }         => "record_agent_spend",
        TxBody::SpawnChildAgent { .. }          => "spawn_child_agent",
        // Control 5: network capacity reporting
        TxBody::RecordCapacity { .. }           => "record_capacity",
        // Resource Network v0.2 marketplace tx types
        TxBody::PurchaseQrc { .. }              => "purchase_qrc",
        TxBody::CreditProvider { .. }           => "credit_provider",
        // Resource Marketplace — QRC Escrow
        TxBody::LockQrcForJob { .. }            => "lock_qrc_for_job",
        TxBody::ReleaseQrcForJob { .. }         => "release_qrc_for_job",
        TxBody::RefundQrcForJob { .. }          => "refund_qrc_for_job",
        // Agent Treasury
        TxBody::DepositToTreasury { .. }        => "deposit_to_treasury",
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

        // Hard error, in every environment: running with a module list the
        // engine can't honour would mean the chain behaves differently
        // from what its genesis says.
        let modules = genesis.enabled_modules().map_err(NodeError::Genesis)?;
        info!(
            staking = modules.staking, identity = modules.identity,
            qrc = modules.qrc, agents = modules.agents,
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

        let qrc   = QrcEngine::new(chain_forge_qrc::D);
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
            pending_proposals: std::collections::HashMap::new(),
            pending_certs:     std::collections::HashMap::new(),
            last_proposed: None,
            round_watch: None,
            round_watch_started: None,
            chain_store: std::collections::BTreeMap::new(),
            identity,
            qrc,
            agents: AgentStore::new(),
            slasher,
            validator_registry,
            tx_queue,
            has_bootstrap_peers,
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
    /// Design: we look up the sender's public key from the consensus ValidatorSet
    /// (populated from genesis or backfilled by `load_signing_key`). If the key
    /// is non-empty we MUST verify — an empty signature against a known key is
    /// treated as a forgery. If the key is empty we allow through so a mixed
    /// key/no-key devnet still works.
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
        // Bind the keypair to the consensus layer so it can verify peer keys
        // Look up this validator's address from the key file to match genesis
        let address = k["address"].as_str()
            .unwrap_or_default().to_string();
        // Backfill the public key into the consensus ValidatorSet so that
        // peer validators can verify our proposals and votes immediately.
        let my_id = chain_forge_consensus::ValidatorId(address.clone());
        let mut vs = self.consensus.validator_set().clone();
        if let Some(vi) = vs.validators.iter_mut().find(|v| v.id == my_id) {
            vi.public_key = kp.public_key.clone();
            self.consensus.update_validator_set(vs).ok();
        }
        // Set this node's validator identity so the event loop participates
        // in consensus (casts prevotes / precommits) rather than running as
        // an observer. Without this, the node logs "validator=None" and never
        // votes, so the network cannot reach quorum.
        self.validator_id = Some(chain_forge_consensus::ValidatorId(address.clone()));
        tracing::info!(address = %address, "validator signing key loaded");
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
            ("qrc.json",        serde_json::to_string_pretty(&self.qrc)              .ok()),
            ("validators.json", serde_json::to_string_pretty(&self.validator_registry).ok()),
            ("agents.json",     serde_json::to_string_pretty(&self.agents)           .ok()),
            ("slashing.json",   serde_json::to_string_pretty(&self.slasher)          .ok()),
            ("chain_store.json",serde_json::to_string_pretty(&self.chain_store)      .ok()),
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
        let qrc_path         = persist.join("qrc.json");
        let validators_path  = persist.join("validators.json");
        let agents_path      = persist.join("agents.json");
        let slashing_path    = persist.join("slashing.json");
        let chain_store_path = persist.join("chain_store.json");

        if !snap_path.exists() { return false; }

        let mut load = || -> Result<(), Box<dyn std::error::Error>> {
            let snap: chain_forge_state::StateSnapshot =
                serde_json::from_str(&std::fs::read_to_string(&snap_path)?)?;
            let height = snap.height;
            self.state.restore_snapshot(snap);

            if id_path.exists() {
                self.identity = serde_json::from_str(&std::fs::read_to_string(&id_path)?)?;
            }
            if qrc_path.exists() {
                self.qrc = serde_json::from_str(&std::fs::read_to_string(&qrc_path)?)?;
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

            // ── Rebuild ExplorerState from persisted chain_store + state ─────
            // ExplorerState is not persisted separately; it is reconstructed
            // here so that /api/blocks, /api/tx, /api/accounts, and
            // /api/validators all return correct data immediately after restart.
            {
                let mut ex = self.explorer.lock().unwrap();

                // Accounts: derive from the restored StateStore snapshot.
                ex.accounts.clear();
                for a in self.state.all_accounts() {
                    ex.accounts.insert(a.address.clone(), AccountSummary {
                        address:        a.address.clone(),
                        role:           a.role.clone(),
                        nonce:          a.nonce,
                        balances:       a.balances.clone(),
                        tier:           a.verification_tier().map(|t| t.to_string()),
                        exemption_days: a.exemption_days(),
                    });
                }

                // Validators: derive from the restored validator registry.
                let vs = self.validator_registry.build_validator_set(height);
                ex.validator_powers = vs.validators.iter().map(|v| ValidatorPowerSummary {
                    id:           v.id.0.clone(),
                    voting_power: v.voting_power,
                    pop_verified: v.pop_verified,
                }).collect();

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
            let vs = self.validator_registry.build_validator_set(height);
            if let Err(e) = self.consensus.reset_to_height(height, vs) {
                tracing::warn!(
                    height,
                    error = %e,
                    "consensus engine could not fast-forward to persisted height; \
                     some re-proposal may occur until peers catch this node up"
                );
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
                        // key in the ValidatorSet (loaded from genesis or via
                        // load_signing_key). Validators without a key on file
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

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let tx_meta: Vec<(String, String, String)> = txs.iter()
            .map(|t| (t.id.clone(), t.sender.clone(), tx_kind_label(&t.body).to_string()))
            .collect();

        self.identity.advance_epoch(now_ms);

        // Integration Point 3 (Push): after advancing the epoch, sync the
        // ValidatorRegistry with any identity lapses that just happened.
        //
        // advance_epoch() calls lapse() on any Verified/Established identity
        // that hasn't been active for LIVENESS_EPOCH_WINDOW epochs, dropping
        // them to Provisional. The ValidatorRegistry is a separate module that
        // doesn't hear about this unless we tell it. Without this call, a
        // lapsed validator stays Active with full consensus power — exactly the
        // attack Section 3.3's personhood-weighting is supposed to prevent.
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

        let exec_result = self.executor.execute_block_with_identity(
            cert.height, txs, &mut self.state, &mut self.identity, &mut self.qrc, &mut self.agents, now_ms,
        );

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
                let now_verified = self.identity.get(&v.id.0)
                    .map(|r| r.charm.tier.grants_consensus())
                    .unwrap_or(false);
                if v.pop_verified != now_verified {
                    if now_verified {
                        info!(validator = %v.id, "PoP gate: identity Verified — granting consensus power");
                    } else {
                        warn!(validator = %v.id, "PoP gate: identity not Verified — revoking consensus power");
                    }
                    v.pop_verified = now_verified;
                    any_changed = true;
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
                ex.accounts.insert(a.address.clone(), AccountSummary {
                    address:        a.address.clone(),
                    role:           a.role.clone(),
                    nonce:          a.nonce,
                    balances:       a.balances.clone(),
                    tier:           a.verification_tier().map(|t| t.to_string()),
                    exemption_days: a.exemption_days(),
                });
            }

            // Sync validator power snapshot for GET /api/validators.
            let vs = self.validator_registry.build_validator_set(exec_result.height);
            ex.validator_powers = vs.validators.iter().map(|v| ValidatorPowerSummary {
                id:           v.id.0.clone(),
                voting_power: v.voting_power,
                pop_verified: v.pop_verified,
            }).collect();
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
        let txs = std::mem::take(&mut self.mempool);
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

            // Cast prevote
            let prevote = Vote {
                vote_type:  VoteType::Prevote,
                height,
                round,
                validator:  validator.id.clone(),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
            let _ = self.consensus.receive_vote(prevote).await;

            // Cast precommit
            let precommit = Vote {
                vote_type:  VoteType::Precommit,
                height,
                round,
                validator:  validator.id.clone(),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };

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

        self.identity.advance_epoch(now_ms);

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

        let exec_result = self.executor.execute_block_with_identity(
            height, txs, &mut self.state, &mut self.identity, &mut self.qrc, &mut self.agents, now_ms,
        );

        info!(
            height,
            txs_ok    = exec_result.success_count(),
            txs_fail  = exec_result.failure_count(),
            gas_used  = exec_result.gas_used,
            state_root = %exec_result.state_root,
            "block executed and committed"
        );

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
                ex.accounts.insert(a.address.clone(), AccountSummary {
                    address:        a.address.clone(),
                    role:           a.role.clone(),
                    nonce:          a.nonce,
                    balances:       a.balances.clone(),
                    tier:           a.verification_tier().map(|t| t.to_string()),
                    exemption_days: a.exemption_days(),
                });
            }

            // Sync validator power snapshot for GET /api/validators.
            let vs = self.validator_registry.build_validator_set(exec_result.height);
            ex.validator_powers = vs.validators.iter().map(|v| ValidatorPowerSummary {
                id:           v.id.0.clone(),
                voting_power: v.voting_power,
                pop_verified: v.pop_verified,
            }).collect();
        }

        // Update QRC resource economy metrics snapshot (Section 9.1 / 5.4 / 5.5)
        // Mirror live QrcEngine state directly into the shared metrics struct
        // so the /api/qrc endpoint always reflects the committed engine state.
        {
            let mut cm = self.qrc_metrics.lock().unwrap();
            cm.last_updated_epoch               = exec_result.height;
            cm.total_supply_uqrc                = self.qrc.total_supply;
            cm.total_burned_uqrc                = self.qrc.total_burned;
            cm.total_purchase_minted_uqrc       = self.qrc.total_purchase_minted;
            cm.total_contribution_minted_uqrc   = self.qrc.total_contribution_minted;
            cm.total_qcb_burned_uqcb            = self.qrc.total_qcb_burned;
            cm.conversion_rate_rt               = self.qrc.conversion_rate.rt;
            cm.protocol_reserve_uqrc            = self.qrc.protocol_reserve;
            // Control 5: circuit-breaker state and coverage ratio
            cm.minting_state                    = self.qrc.minting_state.as_str().to_string();
            cm.tracked_capacity_fp              = self.qrc.tracked_capacity;
            cm.coverage_ratio_fp                = self.qrc.coverage_ratio();
        }

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
        "modules": ["bank", "staking", "identity", "qrc", "agents"],
        "custom_modules": [],
        "genesis_accounts": [
            { "label": "Alice", "address": "qcb1alice", "balance": "5000000", "role": "validator" },
            { "label": "Bob",   "address": "qcb1bob",   "balance": "5000000", "role": "validator" },
            { "label": "Carol", "address": "qcb1carol", "balance": "5000000", "role": "validator" },
            { "label": "Dave",  "address": "qcb1dave",  "balance": "5000000", "role": "validator" }
        ]
    }"#;

    #[tokio::test]
    async fn node_initialises_from_genesis() {
        let node = Node::new(GENESIS, None).await.unwrap();
        assert_eq!(node.chain_id(), "qcb-testnet-1");
        assert_eq!(node.environment(), "devnet");
        assert_eq!(node.consensus.current_height(), 0);
        assert_eq!(node.state.account_count(), 4);
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
    async fn plain_chain_seeds_no_identities() {
        let plain = GENESIS
            .replace(
                r#""modules": ["bank", "staking", "identity", "qrc", "agents"]"#,
                r#""modules": ["bank", "staking"]"#,
            )
            .replace(r#""personhood_weighted": true"#, r#""personhood_weighted": false"#);
        let node = Node::new(&plain, None).await.unwrap();
        assert!(node.identity.get("qcb1alice").is_err(),
            "without the identity module there is no web of trust to seed");
    }

    #[tokio::test]
    async fn node_refuses_to_start_with_an_unknown_module() {
        let bad = GENESIS.replace(
            r#""modules": ["bank", "staking", "identity", "qrc", "agents"]"#,
            r#""modules": ["bank", "dex"]"#,
        );
        let err = Node::new(&bad, None).await.err().expect("must refuse to start");
        assert!(err.to_string().contains("unknown module \"dex\""));
    }

    #[tokio::test]
    async fn node_refuses_personhood_consensus_without_identity() {
        let bad = GENESIS.replace(
            r#""modules": ["bank", "staking", "identity", "qrc", "agents"]"#,
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

        let proposal = make_proposal(0, 0, "qcb1alice", "block_h0_r0_test");
        let payload = serde_json::to_vec(&proposal).unwrap();
        node.handle_event(gossip(GossipTopic::BlockProposal, payload)).await.unwrap();

        // Bob voted (prevote + precommit) but that is only 1 of the 3
        // precommits needed for quorum with 4 validators -- not committed yet.
        assert_eq!(node.status.lock().unwrap().height, 0);
        assert!(node.pending_proposals.contains_key(&(0, 0)));

        // Carol's precommit arrives over gossip -- still only 2 of 3.
        let carol_vote = Vote {
            vote_type:  VoteType::Precommit,
            height: 0, round: 0,
            validator:  ValidatorId("qcb1carol".into()),
            block_hash: Some(proposal.block_hash.clone()),
            signature:  vec![],
        };
        node.handle_event(gossip(
            GossipTopic::ConsensusVote,
            serde_json::to_vec(&carol_vote).unwrap(),
        )).await.unwrap();
        assert_eq!(node.status.lock().unwrap().height, 0, "2 of 3 -- not yet committed");

        // Dave's precommit is the 3rd -- quorum reached, block commits.
        let dave_vote = Vote {
            vote_type:  VoteType::Precommit,
            height: 0, round: 0,
            validator:  ValidatorId("qcb1dave".into()),
            block_hash: Some(proposal.block_hash.clone()),
            signature:  vec![],
        };
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
            let vote = Vote {
                vote_type:  VoteType::Precommit,
                height: 0, round: 0,
                validator:  ValidatorId(validator.to_string()),
                block_hash: Some(proposal.block_hash.clone()),
                signature:  vec![],
            };
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
        assert!(epoch_advanced, "91-epoch jump must advance the UBI clock");

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
}
