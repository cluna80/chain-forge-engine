//! `PoCDConfig` — per-blockchain activation and tuning for the PoCD protocol.
//!
//! This is the only place where chain-specific parameters enter PoCD.
//! The rest of the crate is QCB-agnostic.

use serde::{Deserialize, Serialize};

use super::challenge::ChallengeTrack;

/// Top-level configuration that a blockchain passes to the PoCD module.
///
/// Stored in genesis or chain config; not hardcoded anywhere in this crate.
///
/// ## Example (QCB Chain)
/// ```json
/// {
///   "enabled": true,
///   "chain_id": "qcb-devnet-1",
///   "challenge_tracks": ["Cryptography", "ComputationalEfficiency"],
///   "reward_epoch_blocks": 720,
///   "require_verified_identity": true
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCDConfig {
    /// Whether PoCD mining is active on this blockchain.
    pub enabled: bool,

    /// The chain this config belongs to.  Every receipt, proof, and reward
    /// claim is cryptographically bound to this ID to prevent cross-chain
    /// replay attacks.
    pub chain_id: String,

    /// Which research tracks are open for submission on this chain.
    /// An empty list with `enabled: true` is valid but will produce no
    /// receipts — useful as a staging step before tracks are activated.
    pub challenge_tracks: Vec<ChallengeTrack>,

    /// How many blocks form one reward epoch.  At the end of each epoch
    /// the chain's `RewardPolicy` implementation is called with the set of
    /// accepted receipts to distribute rewards.
    pub reward_epoch_blocks: u64,

    /// When true, the `DiscoveryVerifier` must confirm that the submitting
    /// machine traces to a verified human identity before a receipt is accepted.
    /// Chains without on-chain identity can set this to false.
    pub require_verified_identity: bool,

    /// Minimum seal difficulty (leading zero bits) required for ANY track on
    /// this chain.  Individual tracks may set a higher value; they may not set
    /// a lower one.
    pub min_seal_difficulty_bits: u32,
}

impl PoCDConfig {
    /// Disabled config — PoCD is completely off.  Safe default for chains
    /// that do not want the mining module.
    pub fn disabled(chain_id: impl Into<String>) -> Self {
        Self {
            enabled: false,
            chain_id: chain_id.into(),
            challenge_tracks: vec![],
            reward_epoch_blocks: 0,
            require_verified_identity: false,
            min_seal_difficulty_bits: 0,
        }
    }

    /// Returns `true` if the given track is active on this chain.
    pub fn track_active(&self, track: &ChallengeTrack) -> bool {
        self.enabled && self.challenge_tracks.contains(track)
    }

    /// Effective difficulty for a track — the higher of the chain minimum
    /// and the track's own declared minimum.
    pub fn effective_difficulty(&self, track_min: u32) -> u32 {
        track_min.max(self.min_seal_difficulty_bits)
    }
}
