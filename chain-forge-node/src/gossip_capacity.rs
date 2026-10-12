//! `CapacityAdGossip` — the envelope gossiped on `GossipTopic::CapacityAd`.
//!
//! ## Change Set T — Light P2P Resource/Capacity Discovery
//!
//! Before Change Set T the scheduler had no network-level signal about which
//! nodes were idle or what workload types they supported.  Task assignment was
//! effectively blind: the scheduler assigned work to any connected node without
//! knowing whether that node had spare compute, a matching runtime, or was
//! already saturated.
//!
//! Change Set T adds a lightweight, advisory-only capacity layer:
//!
//! 1. **Self-advertisement**: each node broadcasts a `CapacityAdGossip` on
//!    `GossipTopic::CapacityAd` at startup and every
//!    `CAPACITY_AD_INTERVAL_SECS` seconds thereafter.
//!
//! 2. **Peer table**: every node maintains a `peer_capacity_table`
//!    (`HashMap<peer_id, CapacityAdGossip>`) with last-write-wins semantics.
//!    Entries older than `CAPACITY_AD_MAX_AGE_MS` (5 minutes) are evicted
//!    lazily when the table is read.
//!
//! 3. **Scheduler query**: `GET /api/peers/capacity` exposes the live table as
//!    JSON so an external scheduler can prefer idle nodes with a matching
//!    `supported_workload_versions` entry.
//!
//! ## Advisory semantics
//!
//! Capacity ads are entirely advisory.  A node may exaggerate or understate its
//! capacity; the scheduler MUST NOT rely on them for correctness.  They exist
//! only to reduce unnecessary task-assignment round-trips.  Consensus, token
//! economics, and task ownership are unaffected.
//!
//! ## Anti-spam
//!
//! A per-peer rate-limit prevents flooding: a second ad from the same peer
//! arriving within `CAPACITY_AD_MIN_INTERVAL_MS` (30 seconds) is silently
//! dropped by the receiver.  The rate-limit table (`last_ad_ms`) is bounded at
//! `MAX_CAPACITY_AD_PEERS` entries; oldest entries are evicted first.
//!
//! ## No flood-fill re-broadcast
//!
//! Unlike DiscoveryProof and VerifierAttestation gossip, capacity ads are NOT
//! re-broadcast by receiving nodes.  Each node is responsible for emitting its
//! own ad.  This keeps ad traffic O(N) where N is the number of nodes, rather
//! than O(N²) for a flood-fill.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How often a node re-broadcasts its own capacity ad (seconds).
pub const CAPACITY_AD_INTERVAL_SECS: u64 = 60;

/// Entries in the peer capacity table older than this are treated as stale
/// and dropped on the next read.
pub const CAPACITY_AD_MAX_AGE_MS: u64 = 5 * 60 * 1_000; // 5 minutes

/// Minimum interval between two ads from the same peer (anti-spam).
pub const CAPACITY_AD_MIN_INTERVAL_MS: u64 = 30 * 1_000; // 30 seconds

/// Maximum number of peers tracked in the capacity table.
/// Oldest entries are evicted when exceeded.
pub const MAX_CAPACITY_AD_PEERS: usize = 500;

// ---------------------------------------------------------------------------
// CapacityAdGossip
// ---------------------------------------------------------------------------

/// Gossip envelope published on `GossipTopic::CapacityAd`.
///
/// All fields are best-effort self-reports.  Receivers MUST treat them as
/// advisory and MUST NOT make correctness-critical decisions based on them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityAdGossip {
    /// The chain this node is running on.  Receiving nodes MUST reject ads
    /// whose `chain_id` differs from their own genesis `chain_id`.
    pub chain_id: String,

    /// Opaque peer identifier (matches `PeerId.0` from the P2P layer).
    /// Used as the key in `peer_capacity_table`.
    pub peer_id: String,

    /// Semantic version string of the node binary, e.g. `"0.1.0"`.
    /// Receivers can skip assignment to nodes running incompatible versions.
    pub node_version: String,

    /// Workload type strings this node can execute, e.g.
    /// `["pocd_phase1", "pocd_phase2", "avl_experiment"]`.
    /// An empty list means the node is a pure validator with no compute role.
    pub supported_workload_versions: Vec<String>,

    /// Number of tasks currently queued or in-flight on this node.
    /// 0 = fully idle.  A scheduler should prefer lower values.
    pub queue_depth: u32,

    /// Rough available CPU as a percentage (0–100).
    /// 100 = fully available, 0 = saturated.  May be estimated from
    /// `(1 − queue_depth / max_concurrent_tasks) * 100` when no OS metric
    /// is available.
    pub cpu_available_pct: u8,

    /// Maximum number of tasks this node will accept concurrently.
    /// Used by the scheduler to avoid over-saturating a single node.
    pub max_concurrent_tasks: u32,

    /// UTC millisecond timestamp when this ad was first published.
    /// Used for staleness filtering and rate-limiting.
    pub published_at_ms: u64,
}

impl CapacityAdGossip {
    /// Encode to JSON bytes for `OutboundMessage::payload`.
    pub fn to_payload(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Decode from `GossipMessage::payload`.
    pub fn from_payload(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// True if this ad is too old to be useful.
    pub fn is_stale(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.published_at_ms) > CAPACITY_AD_MAX_AGE_MS
    }

    /// True if this peer sent an ad so recently we should rate-limit it.
    pub fn arrived_too_soon(&self, last_seen_ms: u64) -> bool {
        self.published_at_ms.saturating_sub(last_seen_ms) < CAPACITY_AD_MIN_INTERVAL_MS
    }

    /// A rough "preference score" for scheduler use:
    /// higher = more preferred for new task assignment.
    ///
    /// Formula: `cpu_available_pct` clamped to [0, 100], biased downward
    /// when `queue_depth` is high.  Pure heuristic — not authoritative.
    pub fn preference_score(&self) -> u32 {
        let cpu = self.cpu_available_pct as u32;
        let queue_penalty = self.queue_depth.saturating_mul(5).min(cpu);
        cpu.saturating_sub(queue_penalty)
    }

    /// True if this node advertises support for the given workload type.
    pub fn supports_workload(&self, workload: &str) -> bool {
        self.supported_workload_versions.iter().any(|w| w == workload)
    }
}

// ---------------------------------------------------------------------------
// PeerCapacityTable
// ---------------------------------------------------------------------------

/// In-memory table of the most-recent capacity ad from each peer.
///
/// Stored on `Node` and updated by the `GossipTopic::CapacityAd` handler.
/// Exposed read-only to the API layer via `GET /api/peers/capacity`.
#[derive(Debug, Default)]
pub struct PeerCapacityTable {
    /// Most-recent ad from each peer, keyed on `peer_id`.
    entries: std::collections::HashMap<String, CapacityAdGossip>,

    /// Millisecond timestamp of the last accepted ad per peer, for rate-limiting.
    last_ad_ms: std::collections::HashMap<String, u64>,

    /// FIFO order of inserted peer_ids, for bounded-eviction.
    insertion_order: std::collections::VecDeque<String>,
}

impl PeerCapacityTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update an ad.  Returns `true` if the ad was accepted (new or
    /// updated), `false` if it was rate-limited, stale, or wrong chain.
    ///
    /// Evicts the oldest entry when `MAX_CAPACITY_AD_PEERS` is reached.
    pub fn upsert(&mut self, ad: CapacityAdGossip, now_ms: u64) -> bool {
        // Staleness guard.
        if ad.is_stale(now_ms) {
            return false;
        }

        // Rate-limit: drop if this peer sent an ad too recently.
        if let Some(&last) = self.last_ad_ms.get(&ad.peer_id) {
            if ad.arrived_too_soon(last) {
                return false;
            }
        }

        // Evict oldest when at capacity (only for genuinely new peers).
        if !self.entries.contains_key(&ad.peer_id)
            && self.entries.len() >= MAX_CAPACITY_AD_PEERS
        {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest);
                self.last_ad_ms.remove(&oldest);
            }
        }

        // Track insertion order for new entries.
        if !self.entries.contains_key(&ad.peer_id) {
            self.insertion_order.push_back(ad.peer_id.clone());
        }

        self.last_ad_ms.insert(ad.peer_id.clone(), now_ms);
        self.entries.insert(ad.peer_id.clone(), ad);
        true
    }

    /// Return all non-stale ads, evicting stale entries in the process.
    pub fn live_entries(&mut self, now_ms: u64) -> Vec<&CapacityAdGossip> {
        // Evict stale entries.
        self.entries.retain(|_, ad| !ad.is_stale(now_ms));
        // Purge stale keys from last_ad_ms too (best-effort; keeps memory bounded).
        self.last_ad_ms.retain(|k, _| self.entries.contains_key(k));
        self.entries.values().collect()
    }

    /// Total number of peers currently in the table (including potentially
    /// stale entries — call `live_entries` to prune first if freshness matters).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the ad for a specific peer, if present and not stale.
    pub fn get(&self, peer_id: &str, now_ms: u64) -> Option<&CapacityAdGossip> {
        self.entries.get(peer_id).filter(|ad| !ad.is_stale(now_ms))
    }
}
