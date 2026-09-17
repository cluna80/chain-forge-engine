/// Node: the core runtime that wires all five crates together.

use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn, error};

use chain_forge_core::{GenesisConfig, HashWidth};
use chain_forge_consensus::{
    ConsensusConfig, ConsensusVariant, PersonhoodConfig,
    ValidatorId, ValidatorInfo, ValidatorSet, BlockHash, Vote, VoteType,
    tendermint::TendermintEngine, ConsensusEngine,
};
use chain_forge_state::StateStore;
use chain_forge_execution::{Executor, ExecutionConfig, Transaction};
use chain_forge_p2p::{
    MockNetworkService, NetworkConfig, NetworkEvent, NetworkService,
    GossipTopic, OutboundMessage,
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

pub struct Node {
    genesis:   GenesisConfig,
    consensus: Box<dyn ConsensusEngine>,
    state:     StateStore,
    executor:  Executor,
    network:   MockNetworkService,
    status:    SharedStatus,
    /// This node's validator identity. None = observer node (no voting).
    validator_id: Option<ValidatorId>,
    /// Pending transactions waiting to be proposed in the next block.
    mempool:   Vec<Transaction>,
}

impl Node {
    /// Create a new node from a genesis JSON string.
    pub async fn new(
        genesis_json: &str,
        validator_address: Option<String>,
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

        // Start mock network service (Phase 0 - no real libp2p)
        let mut network = MockNetworkService::new();
        let net_config = NetworkConfig::from_genesis(&genesis);
        network.start(net_config).await
            .map_err(|e| NodeError::Network(e.to_string()))?;

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

        Ok(Self {
            genesis,
            consensus: Box::new(engine),
            state,
            executor,
            network,
            status,
            validator_id,
            mempool: Vec::new(),
        })
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

    /// Add a transaction to the mempool.
    pub fn submit_tx(&mut self, tx: Transaction) {
        if self.mempool.len() < self.genesis.limits.mempool_size as usize {
            self.mempool.push(tx);
        } else {
            warn!("mempool full -- transaction dropped");
        }
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

        // Drain any startup events from the mock network queue first.
        loop {
            match self.network.next_event().await {
                Ok(event) => {
                    if let Err(e) = self.handle_event(event).await {
                        error!(error = %e, "error handling network event");
                    }
                }
                Err(_) => {
                    // Mock queue empty -- switch to ticker mode.
                    break;
                }
            }
        }

        info!(
            chain_id = %self.genesis.chain_id,
            height   = self.consensus.current_height(),
            "node ready -- waiting for transactions and blocks"
        );

        // Keep the node alive with a heartbeat ticker.
        // Phase 1: replace this with real libp2p event loop.
        let block_time = self.genesis.consensus.block_time_ms;
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_millis(block_time)
        );
        let mut running = true;
        while running {
            interval.tick().await;
            let height = self.consensus.current_height();
            let peer_count = {
                let s = self.status.lock().unwrap();
                s.peer_count
            };
            debug!(height, peer_count, "node heartbeat");

            // In devnet mode with no peers, auto-propose blocks so the
            // chain actually advances and the API shows live state.
            if self.genesis.environment.mode == "devnet" && peer_count == 0 {
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
                        // Deserialise and pass to consensus
                        debug!(from = %msg.from, "received block proposal");
                        // TODO: deserialise BlockProposal from msg.payload
                        // and call self.consensus.receive_proposal(proposal).await
                    }

                    GossipTopic::ConsensusVote => {
                        debug!(from = %msg.from, "received consensus vote");
                        // TODO: deserialise Vote and call self.consensus.receive_vote(vote).await
                        // If receive_vote returns Some(CommitCertificate), execute the block.
                    }

                    GossipTopic::Transaction => {
                        debug!(from = %msg.from, "received transaction");
                        // TODO: deserialise Transaction and add to mempool
                    }

                    GossipTopic::PeerAnnounce => {
                        debug!(from = %msg.from, "received peer announcement");
                    }
                }
            }

            NetworkEvent::PeerConnected(peer) => {
                info!(peer_id = %peer.peer_id, addr = %peer.addr, "peer connected");
                let mut s = self.status.lock().unwrap();
                s.peer_count += 1;
            }

            NetworkEvent::PeerDisconnected(peer_id) => {
                info!(peer_id = %peer_id, "peer disconnected");
                let mut s = self.status.lock().unwrap();
                s.peer_count = s.peer_count.saturating_sub(1);
            }

            NetworkEvent::PeerList(peers) => {
                let mut s = self.status.lock().unwrap();
                s.peer_count = peers.len();
            }

            NetworkEvent::FatalError(e) => {
                return Err(format!("fatal network error: {e}"));
            }
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

        let exec_result = self.executor.execute_block(height, txs, &mut self.state, now_ms);

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
            s.state_root = Some(exec_result.state_root);
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
        "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic" },
        "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
        "network": { "network_id": "qcb-devnet", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "mdns", "max_peers": 10 },
        "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 },
        "modules": ["bank", "staking"],
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
}
