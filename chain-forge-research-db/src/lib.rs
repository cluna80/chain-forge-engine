//! # chain-forge-research-db
//!
//! **QCB Discovery Engine — Persistent Research Memory** (Change Set D)
//!
//! Provides durable PostgreSQL storage for research objectives, microtasks,
//! experimental results, verification records, findings, and supporting
//! artifacts produced by the QCB mining network.
//!
//! ## Architecture
//!
//! ```text
//!  chain-forge-pocd (consensus-safe, no DB dependency)
//!       │
//!       │  ResearchObjective / ResearchMicrotask / MicrotaskCommitment
//!       ▼
//!  chain-forge-research-db  (this crate)
//!       │
//!       ├── ResearchDb trait  (async, object-safe)
//!       │        │
//!       │        └── PgResearchDb  (PostgreSQL via sqlx)
//!       │
//!       ├── models  (DB row types + insert DTOs)
//!       ├── bridge  (From<&PocdType> for NewDto converters)
//!       └── migrations/  (001..006 SQL files, embedded via sqlx::migrate!)
//! ```
//!
//! ## Consensus separation (IMPORTANT)
//!
//! This crate is NOT on the consensus critical path.  Reward eligibility,
//! double-payment protection, and accepted-commitment enforcement remain
//! exclusively in `chain-forge-pocd::MicrotaskRegistry` (in-memory) and
//! on-chain via `DiscoveryReceipt`.
//!
//! A database outage must never prevent the chain from reaching consensus.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use chain_forge_research_db::{PgResearchDb, ResearchDb};
//! use chain_forge_research_db::models::NewObjective;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let db = PgResearchDb::connect("postgres://…").await?;
//!     let obj = db.insert_objective(NewObjective { … }).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Change Set E preview
//!
//! Change Set E (Continuous Scheduling) will add a scheduler layer that reads
//! `objectives_with_pending_work()` on startup and distributes available tasks
//! to registered miners.  The `ResearchDb` trait surface is stable; Change Set E
//! only adds callers, not new trait methods.

pub mod bridge;
pub mod db;
pub mod error;
pub mod mem_db;
pub mod models;
pub mod pg;

// ── Convenient re-exports ─────────────────────────────────────────────────────

pub use db::{ResearchDb, TaskProvenance};
pub use error::ResearchDbError;
pub use models::{
    ExperimentResultRow, NewExperimentResult, NewObjective, NewResearchArtifact,
    NewResearchFinding, NewTask, NewVerificationRecord, ObjectiveRow, ResearchArtifactRow,
    ResearchFindingRow, TaskRow, VerificationRecordRow,
};
pub use mem_db::MemResearchDb;
pub use pg::PgResearchDb;

#[cfg(test)]
mod tests;
