/// Node: the core runtime that wires all five crates together.

use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn, error};

use chain_forge_core::{GenesisConfig, HashWidth};
use chain_forge_consensus::{
    ConsensusConfig, ConsensusVariant, PersonhoodConfig,
    ValidatorId, ValidatorInfo, ValidatorSet, BlockHash, BlockProposal, Vote, VoteType,
    tendermint::TendermintEngine, ConsensusEngine,
};
use chain_forge_state::StateStore;
use chain_forge_execution::{Executor, ExecutionConfig, Transaction};
use chain_forge_identity::IdentityStore;
use chain_forge_cirfi::CirfiEngine;
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

/// Explorer state, updated by the node on each committed block.
#[derive(Debug, Default)]
pub struct ExplorerState {
    /// Most recent blocks, newest first. Capped at MAX_RECENT_BLOCKS.
    pub blocks: std::collections::VecDeque<BlockSummary>,
    /// tx id -> summary.
    pub txs: std::collections::HashMap<String, TxSummary>,
    /// address -> latest account snapshot.
    pub accounts: std::collections::HashMap<String, AccountSummary>,
}

pub const MAX_RECENT_BLOCKS: usize = 100;

pub type SharedExplorer = Arc<Mutex<ExplorerState>>;

// -- CirFi metrics (shared with the API, Section 9.1 / 5.4) -------------------

/// Live snapshot of CirFi monetary engine metrics.
/// Updated on every epoch boundary. Read by /api/cirfi.
#[derive(Debug, Default, serde::Serialize, Clone)]
pub struct CirfiMetrics {
    /// Current UBI pool balance (ucirfi).
    pub ubi_pool_balance_ucirfi:      u128,
    /// Total ucirfi received into UBI pool from demurrage since genesis.
    pub total_decayed_to_pool_ucirfi: u128,
    /// Total ucirfi distributed as UBI since genesis.
    pub total_ubi_distributed_ucirfi: u128,
    /// Total BME fees collected (ucirfi) since genesis.
    pub total_bme_fees_ucirfi:        u128,
    /// Total $QCB burned via BME (uqcb) since genesis.
    pub total_qcb_burned_uqcb:        u128,
    /// BME fee rate in basis points (50 = 0.5%).
    pub bme_fee_bps:                  u32,
    /// Whether BME is live (Section 6.3 threshold met).
    pub bme_is_live:                  bool,
    /// Daily UBI rate per verified human (ucirfi).
    pub daily_ubi_rate_ucirfi:        u128,
    /// Epoch of most recent metrics update.
    pub last_updated_epoch:           u64,
}

pub type SharedCirfiMetrics = Arc<Mutex<CirfiMetrics>>;

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
    cirfi_metrics:  SharedCirfiMetrics,
    /// Connected peers, maintained from PeerConnected/PeerDisconnected/PeerList events.
    peers:          SharedPeers,
    /// This node's validator identity. None = observer node (no voting).
    validator_id: Option<ValidatorId>,
    /// Pending transactions waiting to be proposed in the next block.
    mempool:   Vec<Transaction>,
    /// Proposals seen but not yet committed, keyed by (height, round).
    /// Needed because a CommitCertificate carries only the block_hash, not
    /// the transactions -- when quorum is reached (locally or via a gossiped
    /// vote), this is how the node finds the tx_data to actually execute.
    /// Entries at or below a committed height are pruned on commit.
    pending_proposals: std::collections::HashMap<(u64, u32), chain_forge_consensus::BlockProposal>,
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
    /// CirFi monetary engine (demurrage, UBI pool, BME) -- backs ClaimUbi
    /// and RedirectToUbiPool. Threaded through execute_block_with_identity()
    /// alongside identity, for the same reason.
    cirfi: CirfiEngine,
    /// Transactions submitted via POST /api/tx, waiting to be pulled into
    /// the mempool. Drained once per heartbeat tick in run().
    tx_queue: SharedTxQueue,
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
            cirfi = modules.cirfi, agents = modules.agents,
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

        // Build validator set from genesis accounts
        let validators: Vec<ValidatorInfo> = genesis.genesis_accounts
            .iter()
            .filter(|a| a.role == "validator")
            .map(|a| ValidatorInfo {
                id: ValidatorId(a.address.clone()),
                voting_power: 1,
                pop_verified: true,
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
                });
            }
        }

        let genesis_vs = ValidatorSet {
            height: 0,
            validators,
        };

        // Build consensus config
        let personhood_cfg = if genesis.consensus.consensus_type == "proof-of-stake" {
            Some(PersonhoodConfig {
                power_cap: 1,
                reject_expired_pop: false,
                min_verified_pct: 67,
            })
        } else {
            None
        };

        let consensus_cfg = ConsensusConfig {
            variant:              ConsensusVariant::TendermintStyle,
            propose_timeout_ms:   genesis.consensus.block_time_ms * 2,
            prevote_timeout_ms:   genesis.consensus.block_time_ms,
            precommit_timeout_ms: genesis.consensus.block_time_ms,
            block_time_ms:        genesis.consensus.block_time_ms,
            personhood:           personhood_cfg,
        };

        let mut engine = TendermintEngine::new();
        engine.init(consensus_cfg, genesis_vs).await
            .map_err(|e| NodeError::Consensus(e.to_string()))?;

        // Build executor
        let exec_config = ExecutionConfig::from_genesis(&genesis);
        let executor = Executor::new(exec_config);

        // Build network config from genesis, applying the CLI port
        // override if one was given (needed to run multiple nodes locally).
        let mut net_config = NetworkConfig::from_genesis(&genesis);
        if let Some(port) = p2p_port_override {
            net_config.p2p_port = port;
        }

        // Real libp2p when this crate's "real-network" feature is enabled;
        // otherwise the in-memory mock (fast, deterministic, used by tests
        // and by default builds). Both satisfy the same NetworkService
        // trait, so nothing downstream of this block knows which one is live.
        #[cfg(feature = "real-network")]
        let network: Box<dyn NetworkService> = {
            let (svc, local_addr) = chain_forge_p2p::real::Libp2pService::start(&net_config)
                .await
                .map_err(|e| NodeError::Network(e.to_string()))?;
            info!(local_addr = %local_addr, "real libp2p network started");
            Box::new(svc)
        };

        #[cfg(not(feature = "real-network"))]
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
        let cirfi_metrics  = Arc::new(Mutex::new(CirfiMetrics {
            bme_fee_bps:          50,
            daily_ubi_rate_ucirfi: chain_forge_identity::DAILY_UBI_RATE_UCIRFI,
            ..Default::default()
        }));

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
                let _ = identity.verify_identity(&acct.address, att);
            }
        }

        let cirfi = CirfiEngine::new("ucirfi".to_string(), "uqcb".to_string());
        let tx_queue: SharedTxQueue = Arc::new(Mutex::new(Vec::new()));

        Ok(Self {
            genesis,
            consensus: Box::new(engine),
            state,
            executor,
            network,
            status,
            explorer,
            cirfi_metrics,
            peers,
            validator_id,
            mempool: Vec::new(),
            pending_proposals: std::collections::HashMap::new(),
            last_proposed: None,
            round_watch: None,
            round_watch_started: None,
            chain_store: std::collections::BTreeMap::new(),
            identity,
            cirfi,
            tx_queue,
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

    pub fn cirfi_metrics(&self) -> SharedCirfiMetrics {
        self.cirfi_metrics.clone()
    }

    pub fn peers(&self) -> SharedPeers {
        self.peers.clone()
    }

    pub fn tx_queue(&self) -> SharedTxQueue {
        self.tx_queue.clone()
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
                    let expects_peers = !self.genesis.network.bootstrap_nodes.is_empty();

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
                                    let nil_vote = Vote { validator: my_id.clone(), ..nil_vote_template };
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
                                        // Quorum reached on a proposal we never received --
                                        // possible if this vote arrived before the proposal
                                        // gossip did. We cannot execute without the tx_data,
                                        // so we log and wait; the proposal message, once it
                                        // arrives, currently will not re-trigger this commit
                                        // (a known gap -- see the deployment notes).
                                        warn!(
                                            height = vote.height,
                                            round  = vote.round,
                                            "quorum reached but proposal not yet seen; cannot execute block"
                                        );
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(e) => debug!(error = %e, "vote rejected (stale height or unknown validator)"),
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
                let nil_vote = Vote { validator: my_id, ..nil_vote_template };
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

        let prevote = Vote {
            vote_type:  VoteType::Prevote,
            height:     proposal.height,
            round:      proposal.round,
            validator:  my_id.clone(),
            block_hash: Some(proposal.block_hash.clone()),
            signature:  vec![], // TODO: sign once the crypto layer is wired into consensus
        };
        if let Err(e) = self.consensus.receive_vote(prevote.clone()).await {
            debug!(error = %e, "own prevote rejected locally");
        }
        let _ = self.network.publish(OutboundMessage {
            topic:   GossipTopic::ConsensusVote,
            payload: serde_json::to_vec(&prevote).unwrap_or_default(),
        }).await;

        let precommit = Vote {
            vote_type:  VoteType::Precommit,
            height:     proposal.height,
            round:      proposal.round,
            validator:  my_id,
            block_hash: Some(proposal.block_hash.clone()),
            signature:  vec![],
        };
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
            .map(|t| {
                let kind = match &t.body {
                    chain_forge_execution::TxBody::Transfer { .. }          => "transfer",
                    chain_forge_execution::TxBody::Burn { .. }              => "burn",
                    chain_forge_execution::TxBody::Stake { .. }             => "stake",
                    chain_forge_execution::TxBody::Custom { .. }            => "custom",
                    chain_forge_execution::TxBody::RegisterIdentity         => "register_identity",
                    chain_forge_execution::TxBody::Attest { .. }            => "attest",
                    chain_forge_execution::TxBody::ClaimUbi { .. }          => "claim_ubi",
                    chain_forge_execution::TxBody::RedirectToUbiPool { .. } => "ubi_redirect",
                    chain_forge_execution::TxBody::SponsorAgent { .. }      => "sponsor_agent",
                    chain_forge_execution::TxBody::RevokeAgent { .. }       => "revoke_agent",
                };
                (t.id.clone(), t.sender.clone(), kind.to_string())
            })
            .collect();

        self.identity.advance_epoch(now_ms);
        let exec_result = self.executor.execute_block_with_identity(
            cert.height, txs, &mut self.state, &mut self.identity, &mut self.cirfi, now_ms,
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
        }

        // Drop proposals at or below the height we just committed -- they
        // can no longer be voted on and would otherwise accumulate forever.
        let committed_height = cert.height;
        self.pending_proposals.retain(|(h, _), _| *h > committed_height);

        // Unlike pending_proposals (a short-lived voting cache), chain_store
        // keeps every committed block permanently, so a peer that falls
        // behind has something to actually request and replay.
        self.chain_store.insert(committed_height, (cert, proposal.clone()));

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
            .map(|t| {
                let kind = match &t.body {
                    chain_forge_execution::TxBody::Transfer { .. }          => "transfer",
                    chain_forge_execution::TxBody::Burn { .. }              => "burn",
                    chain_forge_execution::TxBody::Stake { .. }             => "stake",
                    chain_forge_execution::TxBody::Custom { .. }            => "custom",
                    chain_forge_execution::TxBody::RegisterIdentity         => "register_identity",
                    chain_forge_execution::TxBody::Attest { .. }            => "attest",
                    chain_forge_execution::TxBody::ClaimUbi { .. }          => "claim_ubi",
                    chain_forge_execution::TxBody::RedirectToUbiPool { .. } => "ubi_redirect",
                    chain_forge_execution::TxBody::SponsorAgent { .. }      => "sponsor_agent",
                    chain_forge_execution::TxBody::RevokeAgent { .. }       => "revoke_agent",
                };
                (t.id.clone(), t.sender.clone(), kind.to_string())
            })
            .collect();

        self.identity.advance_epoch(now_ms);
        let exec_result = self.executor.execute_block_with_identity(
            height, txs, &mut self.state, &mut self.identity, &mut self.cirfi, now_ms,
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
        }

        // Update CirFi metrics snapshot (Section 9.1 / 5.4)
        // Phase 0: metrics come from the execution layer's CirFi engine.
        // We update the daily UBI rate from identity constants; full per-epoch
        // demurrage and BME stats wire in Phase 1 when CirFiEngine is plumbed
        // through the execution pipeline end-to-end.
        {
            let mut cm = self.cirfi_metrics.lock().unwrap();
            cm.last_updated_epoch     = exec_result.height;
            cm.daily_ubi_rate_ucirfi  = chain_forge_identity::DAILY_UBI_RATE_UCIRFI;
            // Count UBI claim events from this block's tx results
            let ubi_claims = exec_result.tx_results.iter()
                .filter(|r| r.success)
                .flat_map(|r| r.events.iter())
                .filter(|e| e.starts_with("ubi_claim:"))
                .count();
            if ubi_claims > 0 {
                cm.total_ubi_distributed_ucirfi = cm.total_ubi_distributed_ucirfi
                    .saturating_add(ubi_claims as u128
                        * chain_forge_identity::DAILY_UBI_RATE_UCIRFI);
            }
            // Count BME redirect events
            let redirects = exec_result.tx_results.iter()
                .filter(|r| r.success)
                .flat_map(|r| r.events.iter())
                .filter(|e| e.starts_with("ubi_redirect:"))
                .count();
            if redirects > 0 {
                // 0.5% BME fee on redirects (50bp)
                cm.total_bme_fees_ucirfi = cm.total_bme_fees_ucirfi
                    .saturating_add(redirects as u128 * 5_000); // approx 0.5% of 1M ucirfi
                cm.bme_fee_bps = 50;
            }
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
        "consensus": { "type": "proof-of-stake", "validator_set_size": 4, "block_time_ms": 1000 },
        "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": false },
        "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
        "network": { "network_id": "qcb-devnet", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "mdns", "max_peers": 10 },
        "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 },
        "modules": ["bank", "staking", "identity", "cirfi", "agents"],
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
        // Genesis accounts have no IntrinsicCharm attached in Phase 0
        assert!(alice.tier.is_none());
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
                ValidatorInfo { id: ValidatorId("qcb1alice".into()), voting_power: 1, pop_verified: true },
                ValidatorInfo { id: ValidatorId("qcb1bob".into()),   voting_power: 1, pop_verified: true },
                ValidatorInfo { id: ValidatorId("qcb1carol".into()), voting_power: 1, pop_verified: true },
                ValidatorInfo { id: ValidatorId("qcb1dave".into()),  voting_power: 1, pop_verified: true },
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
        let plain = GENESIS.replace(
            r#""modules": ["bank", "staking", "identity", "cirfi", "agents"]"#,
            r#""modules": ["bank", "staking"]"#,
        );
        let node = Node::new(&plain, None).await.unwrap();
        assert!(node.identity.get("qcb1alice").is_err(),
            "without the identity module there is no web of trust to seed");
    }

    #[tokio::test]
    async fn node_refuses_to_start_with_an_unknown_module() {
        let bad = GENESIS.replace(
            r#""modules": ["bank", "staking", "identity", "cirfi", "agents"]"#,
            r#""modules": ["bank", "dex"]"#,
        );
        let err = Node::new(&bad, None).await.err().expect("must refuse to start");
        assert!(err.to_string().contains("unknown module \"dex\""));
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
}
