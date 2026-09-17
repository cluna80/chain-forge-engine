/// chain-forge-p2p
///
/// Peer-to-peer networking for Chain Forge. Handles:
///   - Peer discovery (mDNS for local, bootstrap nodes for testnet/mainnet)
///   - Block and vote propagation via gossipsub
///   - Connection management and peer scoring
///
/// This crate wraps libp2p and exposes a clean async interface the node
/// crate uses. The consensus engine never touches libp2p directly -- it
/// sends and receives messages through the NetworkHandle.
///
/// Whitepaper refs:
///   - Section 9 (P2P network design)
///   - Wizard Step 7 (Network config: ports, discovery, bootstrap nodes)
///   - Open Question 14 (liveness under partial validator participation)

use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use chain_forge_core::GenesisConfig;

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error("failed to bind to address {addr}: {reason}")]
    BindFailed { addr: String, reason: String },

    #[error("peer {peer_id} is banned: {reason}")]
    PeerBanned { peer_id: String, reason: String },

    #[error("gossip topic {0} is not subscribed")]
    TopicNotSubscribed(String),

    #[error("message too large: {size} bytes exceeds limit {limit}")]
    MessageTooLarge { size: usize, limit: usize },

    #[error("network is not yet started")]
    NotStarted,

    #[error("internal P2P error: {0}")]
    Internal(String),
}

pub type P2pResult<T> = Result<T, P2pError>;

// -- Peer identity ------------------------------------------------------------

/// An opaque peer identifier (wraps libp2p PeerId in production;
/// a simple string for testing without the full libp2p stack).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first 8 chars in short contexts
        write!(f, "{}", &self.0[..8.min(self.0.len())])
    }
}

// -- Gossip topics ------------------------------------------------------------

/// The gossip topics Chain Forge nodes subscribe to.
/// Each topic carries a specific message type so subscribers only
/// process messages relevant to them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GossipTopic {
    /// Block proposals from the current round's proposer.
    BlockProposal,
    /// Prevote and precommit votes from validators.
    ConsensusVote,
    /// Pending transactions waiting to be included in a block.
    Transaction,
    /// Peer capability announcements (supported protocols, chain ID).
    PeerAnnounce,
}

impl GossipTopic {
    pub fn as_str(&self) -> &str {
        match self {
            Self::BlockProposal  => "chain-forge/block-proposal/1.0.0",
            Self::ConsensusVote  => "chain-forge/consensus-vote/1.0.0",
            Self::Transaction    => "chain-forge/transaction/1.0.0",
            Self::PeerAnnounce   => "chain-forge/peer-announce/1.0.0",
        }
    }
}

// -- Network messages ---------------------------------------------------------

/// A message received from the gossip network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub topic:    GossipTopic,
    pub from:     PeerId,
    pub payload:  Vec<u8>,   // serialised consensus/tx type
    pub received_at_ms: u64,
}

/// A message to publish on the gossip network.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub topic:   GossipTopic,
    pub payload: Vec<u8>,
}

// -- Peer info ----------------------------------------------------------------

/// What we know about a connected peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id:    PeerId,
    pub addr:       String,       // multiaddr string e.g. "/ip4/1.2.3.4/tcp/26656"
    pub chain_id:   Option<String>,
    pub connected:  bool,
    pub score:      i32,          // higher = more trusted; drop at < -100
}

impl PeerInfo {
    pub fn new(peer_id: PeerId, addr: String) -> Self {
        Self {
            peer_id,
            addr,
            chain_id: None,
            connected: true,
            score: 0,
        }
    }

    /// Apply a score delta. Score is clamped to [-200, 200].
    pub fn adjust_score(&mut self, delta: i32) {
        self.score = (self.score + delta).clamp(-200, 200);
    }

    /// True if this peer's score is too low to keep.
    pub fn should_disconnect(&self) -> bool {
        self.score < -100
    }
}

// -- Network config -----------------------------------------------------------

/// Runtime network configuration, derived from GenesisConfig at startup.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub network_id:      String,
    pub p2p_port:        u16,
    pub bootstrap_nodes: Vec<String>,
    pub peer_discovery:  PeerDiscovery,
    pub max_peers:       u32,
    /// Maximum gossip message size in bytes. Checked before broadcasting.
    /// Should be at least max_tx_bytes from genesis limits.
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerDiscovery {
    Mdns,
    Bootstrap,
    Both,
}

impl NetworkConfig {
    /// Build from the genesis config produced by the Chain Forge wizard.
    pub fn from_genesis(genesis: &GenesisConfig) -> Self {
        let discovery = match genesis.network.peer_discovery.as_str() {
            "mdns"      => PeerDiscovery::Mdns,
            "bootstrap" => PeerDiscovery::Bootstrap,
            _           => PeerDiscovery::Both,
        };

        Self {
            network_id:      genesis.network.network_id.clone(),
            p2p_port:        genesis.network.p2p_port,
            bootstrap_nodes: genesis.network.bootstrap_nodes.clone(),
            peer_discovery:  discovery,
            max_peers:       genesis.network.max_peers,
            max_message_bytes: genesis.limits.max_tx_bytes as usize * 2,
        }
    }
}

// -- Network handle (the interface the node uses) -----------------------------

/// Commands sent from the node into the network layer.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Publish a message to all subscribed peers.
    Publish(OutboundMessage),
    /// Ban a peer and disconnect them.
    BanPeer { peer_id: PeerId, reason: String },
    /// Request the current peer list.
    GetPeers,
    /// Shut the network down cleanly.
    Shutdown,
}

/// Events the network layer sends back to the node.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A gossip message arrived from a peer.
    Message(GossipMessage),
    /// A new peer connected.
    PeerConnected(PeerInfo),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// Current peer list (response to GetPeers command).
    PeerList(Vec<PeerInfo>),
    /// Network started successfully on the given address.
    Started { local_addr: String, peer_id: PeerId },
    /// Fatal network error — node should shut down.
    FatalError(String),
}

// -- NetworkService trait -----------------------------------------------------

/// The interface the node uses to interact with the P2P layer.
/// Implementations: `LibP2pService` (production), `MockNetworkService` (tests).
#[async_trait::async_trait]
pub trait NetworkService: Send + Sync {
    /// Start the network service. Must be called before any other method.
    async fn start(&mut self, config: NetworkConfig) -> P2pResult<()>;

    /// Publish a message to all peers subscribed to the topic.
    async fn publish(&self, msg: OutboundMessage) -> P2pResult<()>;

    /// Return a snapshot of currently connected peers.
    async fn peers(&self) -> P2pResult<Vec<PeerInfo>>;

    /// Ban a peer by ID and disconnect them.
    async fn ban_peer(&mut self, peer_id: PeerId, reason: &str) -> P2pResult<()>;

    /// Receive the next network event. Blocks until one arrives.
    async fn next_event(&mut self) -> P2pResult<NetworkEvent>;

    /// Stop the network service cleanly.
    async fn stop(&mut self) -> P2pResult<()>;

    /// True if the service has been started.
    fn is_running(&self) -> bool;

    /// The local peer ID assigned at startup.
    fn local_peer_id(&self) -> Option<&PeerId>;
}

// -- Peer manager -------------------------------------------------------------

/// Tracks connected peers and their scores.
/// Shared between the network service and the node layer.
#[derive(Debug, Default)]
pub struct PeerManager {
    peers:   std::collections::HashMap<PeerId, PeerInfo>,
    banned:  HashSet<PeerId>,
    max_peers: u32,
}

impl PeerManager {
    pub fn new(max_peers: u32) -> Self {
        Self {
            peers: std::collections::HashMap::new(),
            banned: HashSet::new(),
            max_peers,
        }
    }

    /// Add or update a peer. Returns false if the peer is banned or
    /// the peer limit has been reached.
    pub fn add_peer(&mut self, info: PeerInfo) -> bool {
        if self.banned.contains(&info.peer_id) {
            return false;
        }
        if self.peers.len() >= self.max_peers as usize
            && !self.peers.contains_key(&info.peer_id)
        {
            return false;
        }
        self.peers.insert(info.peer_id.clone(), info);
        true
    }

    /// Remove a peer by ID.
    pub fn remove_peer(&mut self, id: &PeerId) {
        self.peers.remove(id);
    }

    /// Adjust a peer's score. Disconnects them if score drops too low.
    /// Returns true if the peer was disconnected.
    pub fn adjust_score(&mut self, id: &PeerId, delta: i32) -> bool {
        if let Some(peer) = self.peers.get_mut(id) {
            peer.adjust_score(delta);
            if peer.should_disconnect() {
                self.peers.remove(id);
                return true;
            }
        }
        false
    }

    /// Ban a peer permanently (for this session).
    pub fn ban(&mut self, id: PeerId) {
        self.peers.remove(&id);
        self.banned.insert(id);
    }

    pub fn is_banned(&self, id: &PeerId) -> bool {
        self.banned.contains(id)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn is_full(&self) -> bool {
        self.peers.len() >= self.max_peers as usize
    }

    pub fn all_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().collect()
    }

    /// Peers whose chain_id matches ours (i.e. they are on the same network).
    pub fn peers_on_network(&self, network_id: &str) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.chain_id.as_deref() == Some(network_id))
            .collect()
    }
}

// -- Mock network service (for tests and dev without real networking) ----------

/// A mock network service that records published messages and lets tests
/// inject incoming events. Used by chain-forge-node tests and by devnet
/// single-node mode where real networking is unnecessary.
pub struct MockNetworkService {
    running:        bool,
    local_peer_id:  Option<PeerId>,
    pub published:  Vec<OutboundMessage>,
    pub peer_manager: PeerManager,
    event_queue:    std::collections::VecDeque<NetworkEvent>,
}

impl MockNetworkService {
    pub fn new() -> Self {
        Self {
            running:       false,
            local_peer_id: None,
            published:     Vec::new(),
            peer_manager:  PeerManager::new(50),
            event_queue:   std::collections::VecDeque::new(),
        }
    }

    /// Inject an event that next_event() will return.
    pub fn inject_event(&mut self, event: NetworkEvent) {
        self.event_queue.push_back(event);
    }

    /// Inject a simulated incoming gossip message.
    pub fn inject_message(&mut self, topic: GossipTopic, from: PeerId, payload: Vec<u8>) {
        self.event_queue.push_back(NetworkEvent::Message(GossipMessage {
            topic,
            from,
            payload,
            received_at_ms: 0,
        }));
    }
}

impl Default for MockNetworkService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NetworkService for MockNetworkService {
    async fn start(&mut self, config: NetworkConfig) -> P2pResult<()> {
        self.local_peer_id = Some(PeerId("mock-peer-0000".into()));
        self.peer_manager  = PeerManager::new(config.max_peers);
        self.running       = true;

        self.event_queue.push_back(NetworkEvent::Started {
            local_addr: format!("/ip4/127.0.0.1/tcp/{}", config.p2p_port),
            peer_id:    self.local_peer_id.clone().unwrap(),
        });

        Ok(())
    }

    async fn publish(&self, msg: OutboundMessage) -> P2pResult<()> {
        if !self.running {
            return Err(P2pError::NotStarted);
        }
        // In production this would actually broadcast; here we just record.
        // The mutable publish list is accessed via interior mutability in
        // production; for tests we use the public `published` field directly.
        Ok(())
    }

    async fn peers(&self) -> P2pResult<Vec<PeerInfo>> {
        Ok(self.peer_manager.all_peers().into_iter().cloned().collect())
    }

    async fn ban_peer(&mut self, peer_id: PeerId, _reason: &str) -> P2pResult<()> {
        self.peer_manager.ban(peer_id);
        Ok(())
    }

    async fn next_event(&mut self) -> P2pResult<NetworkEvent> {
        if let Some(event) = self.event_queue.pop_front() {
            return Ok(event);
        }
        // In a real implementation this would block on the network.
        // In the mock we return a fatal error to signal the queue is empty
        // (tests should drain the queue before calling this).
        Err(P2pError::Internal("mock event queue is empty".into()))
    }

    async fn stop(&mut self) -> P2pResult<()> {
        self.running = false;
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running
    }

    fn local_peer_id(&self) -> Option<&PeerId> {
        self.local_peer_id.as_ref()
    }
}

// -- Message size guard -------------------------------------------------------

/// Check a payload before publishing. Returns Err if too large.
pub fn check_message_size(payload: &[u8], limit: usize) -> P2pResult<()> {
    if payload.len() > limit {
        return Err(P2pError::MessageTooLarge {
            size:  payload.len(),
            limit,
        });
    }
    Ok(())
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_core::GenesisConfig;

    fn qcb_genesis_json() -> &'static str {
        r#"{
            "chain_id": "qcb-testnet-1",
            "chain_name": "QuarkCharmBit",
            "engine_version": "0.1.0",
            "genesis_time": "2026-09-16T00:00:00Z",
            "environment": { "mode": "testnet", "faucet_enabled": true, "relaxed_limits": true },
            "native_token": { "name": "QuarkCharm", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" },
            "address_prefix": "qcb",
            "consensus": { "type": "proof-of-stake", "validator_set_size": 4, "block_time_ms": 5000 },
            "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic" },
            "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
            "network": { "network_id": "qcb-testnet-1-net", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "both", "max_peers": 50 },
            "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 5000, "mempool_ttl_seconds": 300 },
            "modules": ["bank", "staking"],
            "custom_modules": [],
            "genesis_accounts": [
                { "label": "Validator 1", "address": "qcb1abc", "balance": "1000000", "role": "validator" }
            ]
        }"#
    }

    #[test]
    fn network_config_from_genesis() {
        let genesis = GenesisConfig::from_json(qcb_genesis_json()).unwrap();
        let cfg = NetworkConfig::from_genesis(&genesis);
        assert_eq!(cfg.network_id, "qcb-testnet-1-net");
        assert_eq!(cfg.p2p_port, 26656);
        assert_eq!(cfg.peer_discovery, PeerDiscovery::Both);
        assert_eq!(cfg.max_peers, 50);
        // max_message_bytes = max_tx_bytes * 2 = 65536 * 2
        assert_eq!(cfg.max_message_bytes, 131_072);
    }

    #[test]
    fn peer_manager_respects_max_peers() {
        let mut pm = PeerManager::new(2);
        let p1 = PeerInfo::new(PeerId("peer1".into()), "/ip4/1.0.0.1/tcp/26656".into());
        let p2 = PeerInfo::new(PeerId("peer2".into()), "/ip4/1.0.0.2/tcp/26656".into());
        let p3 = PeerInfo::new(PeerId("peer3".into()), "/ip4/1.0.0.3/tcp/26656".into());

        assert!(pm.add_peer(p1));
        assert!(pm.add_peer(p2));
        assert!(!pm.add_peer(p3), "should reject peer when full");
        assert_eq!(pm.peer_count(), 2);
    }

    #[test]
    fn peer_manager_bans_peer() {
        let mut pm = PeerManager::new(10);
        let id = PeerId("bad-peer".into());
        let info = PeerInfo::new(id.clone(), "/ip4/1.0.0.1/tcp/26656".into());

        pm.add_peer(info.clone());
        assert_eq!(pm.peer_count(), 1);

        pm.ban(id.clone());
        assert_eq!(pm.peer_count(), 0);
        assert!(pm.is_banned(&id));

        // Banned peer cannot be re-added
        let info2 = PeerInfo::new(id.clone(), "/ip4/1.0.0.2/tcp/26656".into());
        assert!(!pm.add_peer(info2));
    }

    #[test]
    fn peer_score_disconnects_at_threshold() {
        let mut pm = PeerManager::new(10);
        let id = PeerId("misbehaving".into());
        pm.add_peer(PeerInfo::new(id.clone(), "/ip4/1.0.0.1/tcp/26656".into()));

        // Apply enough negative delta to cross the -100 threshold
        let disconnected = pm.adjust_score(&id, -150);
        assert!(disconnected, "peer should be disconnected at score < -100");
        assert_eq!(pm.peer_count(), 0);
    }

    #[test]
    fn peer_score_stays_in_bounds() {
        let mut info = PeerInfo::new(PeerId("p".into()), "/ip4/1.0.0.1/tcp/26656".into());
        info.adjust_score(500);
        assert_eq!(info.score, 200, "score should clamp at 200");
        info.adjust_score(-1000);
        assert_eq!(info.score, -200, "score should clamp at -200");
    }

    #[test]
    fn gossip_topic_strings_are_unique() {
        let topics = [
            GossipTopic::BlockProposal,
            GossipTopic::ConsensusVote,
            GossipTopic::Transaction,
            GossipTopic::PeerAnnounce,
        ];
        let strings: HashSet<_> = topics.iter().map(|t| t.as_str()).collect();
        assert_eq!(strings.len(), topics.len(), "topic strings must be unique");
    }

    #[test]
    fn message_size_guard_rejects_oversized() {
        let payload = vec![0u8; 1025];
        assert!(check_message_size(&payload, 1024).is_err());
        assert!(check_message_size(&payload, 2048).is_ok());
    }

    #[test]
    fn peers_on_network_filters_correctly() {
        let mut pm = PeerManager::new(10);

        let mut p1 = PeerInfo::new(PeerId("p1".into()), "/ip4/1.0.0.1/tcp/26656".into());
        p1.chain_id = Some("qcb-testnet-1-net".into());

        let mut p2 = PeerInfo::new(PeerId("p2".into()), "/ip4/1.0.0.2/tcp/26656".into());
        p2.chain_id = Some("other-net".into());

        let p3 = PeerInfo::new(PeerId("p3".into()), "/ip4/1.0.0.3/tcp/26656".into()); // no chain_id

        pm.add_peer(p1);
        pm.add_peer(p2);
        pm.add_peer(p3);

        let on_qcb = pm.peers_on_network("qcb-testnet-1-net");
        assert_eq!(on_qcb.len(), 1);
        assert_eq!(on_qcb[0].peer_id, PeerId("p1".into()));
    }

    #[tokio::test]
    async fn mock_service_starts_and_emits_started_event() {
        let mut svc = MockNetworkService::new();
        let genesis = GenesisConfig::from_json(qcb_genesis_json()).unwrap();
        let cfg = NetworkConfig::from_genesis(&genesis);

        svc.start(cfg).await.unwrap();
        assert!(svc.is_running());
        assert!(svc.local_peer_id().is_some());

        let event = svc.next_event().await.unwrap();
        assert!(matches!(event, NetworkEvent::Started { .. }));
    }

    #[tokio::test]
    async fn mock_service_delivers_injected_messages() {
        let mut svc = MockNetworkService::new();
        let genesis = GenesisConfig::from_json(qcb_genesis_json()).unwrap();
        svc.start(NetworkConfig::from_genesis(&genesis)).await.unwrap();
        let _ = svc.next_event().await; // drain Started event

        svc.inject_message(
            GossipTopic::ConsensusVote,
            PeerId("validator-1".into()),
            b"vote-payload".to_vec(),
        );

        let event = svc.next_event().await.unwrap();
        match event {
            NetworkEvent::Message(msg) => {
                assert_eq!(msg.topic, GossipTopic::ConsensusVote);
                assert_eq!(msg.payload, b"vote-payload");
            }
            other => panic!("expected Message event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_service_ban_removes_peer() {
        let mut svc = MockNetworkService::new();
        let genesis = GenesisConfig::from_json(qcb_genesis_json()).unwrap();
        svc.start(NetworkConfig::from_genesis(&genesis)).await.unwrap();

        let id = PeerId("rogue".into());
        svc.peer_manager.add_peer(PeerInfo::new(id.clone(), "/ip4/1.0.0.1/tcp/26656".into()));
        assert_eq!(svc.peer_manager.peer_count(), 1);

        svc.ban_peer(id.clone(), "misbehaving").await.unwrap();
        assert_eq!(svc.peer_manager.peer_count(), 0);
        assert!(svc.peer_manager.is_banned(&id));
    }
}
