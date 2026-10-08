//! `DiscoveryChallenge` — a mathematical mining task any PoCD-enabled chain
//! can activate.
//!
//! A challenge is the unit of scientific work.  Each active challenge has:
//!   - A unique ID (chain-scoped, format: `{chain_id}::{track}::{slug}`)
//!   - A track that classifies the kind of computation
//!   - Verifiable criteria: what counts as a valid result
//!   - A seal difficulty that must meet the chain's minimum
//!
//! Challenges are proposed and activated through the chain's governance
//! system; this crate defines the data shapes only.

use serde::{Deserialize, Serialize};

/// Research area a challenge belongs to.
///
/// Chains configure which tracks they accept in `PoCDConfig::challenge_tracks`.
/// New variants can be added here; existing chains ignore unrecognised ones
/// via `serde(other)` on the receiving side.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ChallengeTrack {
    /// Finding new post-quantum candidates, analysing parameter weaknesses.
    Cryptography,
    /// ZK circuit optimisation, proof system improvements.
    Privacy,
    /// Algorithm speedups for hashing, proof generation, state-trie ops.
    ComputationalEfficiency,
    /// Formally specified open problems with objective pass/fail criteria.
    Mathematics,
    /// Lattice QCD, many-body quantum, cosmological simulations.
    PhysicsAndOpenScience,
    /// Protocol telemetry analysis, capacity/demand modelling.
    AiAssistedDiscovery,
    /// Catch-all for future tracks.  Chains MUST NOT issue rewards for
    /// `Custom` receipts without explicit governance activation.
    Custom(String),
}

/// Current lifecycle state of a challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeStatus {
    /// Proposed but not yet governance-approved.
    Pending,
    /// Governance-approved; machines may submit proofs.
    Active,
    /// Paused; no new submissions accepted, but prior receipts are still valid.
    Suspended,
    /// Search space exhausted or governance-retired; permanently closed.
    Closed,
}

/// A single PoCD mining task.
///
/// All IDs are scoped to the chain via `chain_id` — a receipt for
/// `challenge_id = "qcb-devnet-1::Cryptography::ecdlp-256"` is invalid on
/// `chain-b-mainnet-1` even if it carries a valid seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryChallenge {
    /// Globally unique: `"{chain_id}::{track_slug}::{problem_slug}"`.
    pub challenge_id: String,

    /// The chain this challenge is scoped to.  Embedded in every proof and
    /// receipt to prevent cross-chain replay.
    pub chain_id: String,

    /// Which research track this challenge belongs to.
    pub track: ChallengeTrack,

    /// Human-readable name ("ECDLP-256 discrete log search").
    pub name: String,

    /// What constitutes a valid result.  Free-form; interpretable by the
    /// `DiscoveryVerifier` for this track.  May be a hash of a formal spec
    /// document, a reference to an IPFS CID, or an inline description for
    /// simpler challenges.
    pub verification_criteria: String,

    /// Number of leading zero *bits* required in `seal_hash`.
    /// Must be >= `PoCDConfig::min_seal_difficulty_bits` for this chain.
    pub seal_difficulty_bits: u32,

    /// Optional: expected total search space size.  Only set when the
    /// space is mathematically finite and measurable.  Used by the public
    /// discovery dashboard; `None` suppresses completion-percentage display.
    pub search_space_size: Option<u128>,

    /// Block height at which this challenge was activated (None = pending).
    pub activated_at_block: Option<u64>,

    pub status: ChallengeStatus,
}

impl DiscoveryChallenge {
    /// Construct the canonical challenge ID from its components.
    pub fn make_id(chain_id: &str, track_slug: &str, problem_slug: &str) -> String {
        format!("{chain_id}::{track_slug}::{problem_slug}")
    }

    /// True when the challenge is currently accepting new proof submissions.
    pub fn is_accepting_submissions(&self) -> bool {
        self.status == ChallengeStatus::Active
    }
}
