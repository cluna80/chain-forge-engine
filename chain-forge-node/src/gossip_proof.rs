//! `DiscoveryProofGossip` — the envelope gossiped on `GossipTopic::DiscoveryProof`.
//!
//! ## Change Set R — P2P Proof Gossip
//!
//! When a node's scheduler accepts and verifies a miner's result it promotes
//! that result to a `DiscoveryReceipt`.  Before Change Set R each node held
//! its receipts privately, so reward accounting at epoch boundaries was only
//! as complete as what that one node happened to see.  Change Set R fixes this:
//! every node that accepts a receipt immediately gossips it on
//! `GossipTopic::DiscoveryProof`.  Every other node ingests the gossip,
//! deduplicates by `receipt_id`, and inserts the receipt into its local
//! `DiscoveryRegistry`.  At the epoch boundary every node has the same receipt
//! pool and reaches the same reward totals.
//!
//! ## Anti-replay
//!
//! The receiving node checks `DiscoveryRegistry::proof_seen(receipt_id)` before
//! inserting.  The registry's `proof_seen` set is keyed on the proof_id, and
//! `add_receipt` automatically marks the proof_id seen.  We additionally track
//! `receipt_id` directly in `Node::seen_gossip_receipts` (a bounded `HashSet`)
//! so we can skip deserialising the body on duplicates.
//!
//! ## Message format
//!
//! A single JSON-serialised `DiscoveryProofGossip` struct.  The struct carries
//! the full `DiscoveryReceipt` so any node can immediately insert it into its
//! registry without re-verifying (the verifier signature on the receipt itself
//! is the proof of validity — see Change Set P).

use serde::{Deserialize, Serialize};
use chain_forge_pocd::DiscoveryReceipt;

/// Envelope published on `GossipTopic::DiscoveryProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryProofGossip {
    /// The chain this receipt was issued on.  Receiving nodes MUST reject
    /// messages whose `chain_id` differs from their own genesis chain_id.
    pub chain_id: String,

    /// The accepted receipt, including the verifier signature (Change Set P).
    pub receipt: DiscoveryReceipt,

    /// Millisecond UTC timestamp when this gossip was first published.
    /// Used for staleness filtering: nodes reject messages older than
    /// `PROOF_GOSSIP_MAX_AGE_MS` so the mesh is not flooded with ancient proofs
    /// from nodes that restart after a long downtime.
    pub published_at_ms: u64,
}

/// Gossip messages older than this are silently dropped.
pub const PROOF_GOSSIP_MAX_AGE_MS: u64 = 5 * 60 * 1_000; // 5 minutes

/// How many receipt IDs we track in the anti-replay set before evicting the
/// oldest entries (LRU-style cap).  At ~100 receipts/epoch this holds many
/// epochs of history.
pub const MAX_SEEN_GOSSIP_RECEIPTS: usize = 10_000;

impl DiscoveryProofGossip {
    /// Encode to JSON bytes for `OutboundMessage::payload`.
    pub fn to_payload(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Decode from `GossipMessage::payload`.
    pub fn from_payload(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// True if this message is too old to be useful.
    pub fn is_stale(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.published_at_ms) > PROOF_GOSSIP_MAX_AGE_MS
    }
}
