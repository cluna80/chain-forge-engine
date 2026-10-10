//! # chain-forge-verifier
//!
//! **QCB Discovery Engine — Independent Result Verification** (Change Set F)
//!
//! Provides the HTTP verification service that accepts independent
//! reproduction attempts from miner nodes and transitions confirmed results
//! from `submitted` → `accepted`.
//!
//! ## Architecture
//!
//! ```text
//!  chain-forge-scheduler  (Change Set E)
//!       │  submit_result() → task status = 'submitted'
//!       ▼
//!  chain-forge-verifier  (this crate)
//!       ├── VerificationEngine   — submit_verification / list_submitted
//!       ├── api / router         — axum 0.7 HTTP layer
//!       └── VerifierError        — typed error enum
//! ```
//!
//! ## Verification protocol
//!
//! 1. After a task is `submitted` (via the scheduler), independent miner(s)
//!    call `POST /verifier/tasks/{task_id}/verify` with their own reproduction
//!    of the result.
//! 2. The engine validates:
//!    * `outcome` is one of `reproduced`, `diverged`, `inconclusive`.
//!    * `verifier_id` ≠ original `miner_id` (no self-verification).
//!    * The verifier has not already submitted for this result.
//!    * The task is still in `submitted` status.
//! 3. The verification record is inserted.
//! 4. The engine counts `'reproduced'` verifications for the result.
//! 5. If the count ≥ `verification_quorum` (per-objective, default 2), the
//!    task is transitioned to `'accepted'` and the response carries
//!    `{ "accepted": true }`.
//!
//! ## Quorum rules
//!
//! * Only `'reproduced'` outcomes advance the quorum counter.
//! * `'diverged'` and `'inconclusive'` are stored for provenance but do not
//!   contribute to acceptance.
//!
//! ## Consensus separation
//!
//! `'accepted'` is the highest status this service writes.  On-chain rewards
//! (`DiscoveryReceipt` in `chain-forge-pocd`) require an independent on-chain
//! commitment that is never written by this crate.

pub mod api;
pub mod engine;
pub mod error;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use api::{router, AppState};
pub use engine::VerificationEngine;
pub use error::VerifierError;

#[cfg(test)]
mod tests;
