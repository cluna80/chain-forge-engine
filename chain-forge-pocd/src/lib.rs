//! # chain-forge-pocd
//!
//! **Proof of Cryptographic Discovery** — a chain-agnostic, reusable mining
//! protocol for blockchains built with Chain Forge.
//!
//! PoCD replaces the traditional proof-of-work "wasted" hash race with
//! meaningful computational contributions to open scientific and mathematical
//! challenges.  Miners earn rewards by finding solutions; results are
//! independently verified and permanently recorded on-chain.
//!
//! ## Architecture
//!
//! ```text
//!  ┌────────────────────────────────────────────────────────────────────┐
//!  │  chain-forge-pocd  (this crate — chain-agnostic)                  │
//!  │                                                                    │
//!  │  PoCDConfig ──► DiscoveryChallenge ──► DiscoveryProof             │
//!  │       │                                      │                     │
//!  │       ▼                                      ▼                     │
//!  │  DiscoveryRegistry  ◄──── DiscoveryVerifier ─── DiscoveryReceipt  │
//!  │       │                          │                                 │
//!  │       ▼                          ▼                                 │
//!  │  RewardPolicy::compute_rewards()  ──► RewardGrant[]               │
//!  └────────────────────────────────────────────────────────────────────┘
//!                  ▲
//!                  │  implements traits / builds config
//!  ┌───────────────┴────────────────────────────────────────────────────┐
//!  │  QCB Chain (or any Chain Forge blockchain)                         │
//!  │  - QcbRewardPolicy implements RewardPolicy (pays in uQRC)         │
//!  │  - QcbVerifier implements DiscoveryVerifier                       │
//!  │  - Wires PoCDConfig from genesis / chain config                   │
//!  └────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Crate features
//!
//! This crate has no optional features yet.  Everything is always compiled.
//!
//! ## Cross-chain replay prevention
//!
//! Every `challenge_id` has the format `"{chain_id}::{track}::{slug}"`.
//! The `chain_id` bytes are mixed into every seal hash, so a valid proof on
//! `qcb-devnet-1` cannot be replayed on `qcb-mainnet-1` even if the seal
//! nonce and output hash are identical.  The `DiscoveryReceipt` additionally
//! carries `chain_id` as a top-level field and `is_for_chain()` checks both.

pub mod error;
pub mod types;

// ── Convenient re-exports ─────────────────────────────────────────────────

pub use error::PoCDError;

pub use types::challenge::{ChallengeStatus, ChallengeTrack, DiscoveryChallenge};
pub use types::config::PoCDConfig;
pub use types::proof::{
    compute_seal_hash, find_seal_nonce, meets_difficulty, DiscoveryProof,
};
pub use types::receipt::DiscoveryReceipt;
pub use types::registry::DiscoveryRegistry;
pub use types::reward::{FlatRewardPolicy, NullRewardPolicy, RewardGrant, RewardPolicy};
pub use types::worker::{
    build_proof, build_receipt, DiscoveryVerifier, DiscoveryWorker, VerificationOutcome,
    WorkResult,
};

// ── Change Set C: Research Microtask Decomposition ────────────────────────────
pub use types::microtask::{
    decompose_objective, DecompositionConfig, MicrotaskCommitment, MicrotaskRegistry,
    MicrotaskStatus, ObjectiveStatus, ResearchMicrotask, ResearchObjective, WorkloadClass,
};
