//! # chain-forge-intelligence
//!
//! **QCB Discovery Engine — Research Intelligence & AI Analysis** (Change Set G)
//!
//! Sits above the verifier layer and answers: *"what does the accepted research
//! data actually mean?"*
//!
//! ## Architecture
//!
//! ```text
//!  chain-forge-verifier  (Change Set F)
//!       │  accept_task() → task status = 'accepted'
//!       ▼
//!  chain-forge-intelligence  (this crate)
//!       ├── AnalysisEngine     — generate_report / detect_anomalies
//!       ├── AnomalyDetector    — hash collisions, divergence storms,
//!       │                        low agreement, stall detection
//!       ├── ObjectiveReport    — structured output (serialisable JSON)
//!       ├── api / router       — axum 0.7 HTTP layer
//!       └── IntelligenceError  — typed error enum
//! ```
//!
//! ## Report contents
//!
//! An `ObjectiveReport` includes:
//! * Task-completion progress (counts by status, completion rate)
//! * Verifier statistics (reproduced / diverged counts, mean agreement rate)
//! * Per-miner contribution breakdown (sorted by accepted results)
//! * High-confidence findings (confidence ≥ 0.7)
//! * All detected anomalies
//!
//! Reports are persisted to `research_intelligence_reports` (migration 009)
//! so subsequent `GET /intelligence/objectives/:id/report` calls return the
//! cached result without re-running analysis.
//!
//! ## Anomaly types
//!
//! | Anomaly | Trigger |
//! |---|---|
//! | `HashCollision` | ≥2 distinct miners submitted the same `content_hash` for a task |
//! | `DivergenceStorm` | `diverged_count > reproduced_count` for a result |
//! | `LowVerifierAgreement` | Mean verifier agreement < 0.5 (configurable) |
//! | `StallDetected` | Tasks exist but none have been accepted yet |
//!
//! ## Consensus separation
//!
//! This crate is read-only with respect to task and result status.  Nothing
//! here calls `accept_task()` or modifies the task state machine.  Anomaly
//! detection is advisory only — all decisions remain with human operators.

pub mod anomaly;
pub mod api;
pub mod engine;
pub mod error;
pub mod report;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use api::{router, AppState};
pub use engine::AnalysisEngine;
pub use error::IntelligenceError;
pub use report::{Anomaly, AnomalyConfig, MinerContribution, ObjectiveReport};

#[cfg(test)]
mod tests;
