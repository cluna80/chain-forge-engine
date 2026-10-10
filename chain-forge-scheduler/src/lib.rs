//! # chain-forge-scheduler
//!
//! **QCB Discovery Engine — Continuous Research Scheduling** (Change Set E)
//!
//! Provides the HTTP scheduling service that continuously distributes
//! available research microtasks to registered miners and durably persists
//! their results.
//!
//! ## Architecture
//!
//! ```text
//!  chain-forge-pocd (consensus-safe, no DB dependency)
//!       │
//!       │  ResearchObjective decomposed → tasks inserted into research_tasks
//!       ▼
//!  chain-forge-research-db  (PostgreSQL persistence)
//!       │
//!       ▼
//!  chain-forge-scheduler  (this crate)
//!       ├── ResearchScheduler     — assign_task / submit_result / expire loop
//!       ├── MinerRegistry         — in-memory miner directory
//!       ├── api / router          — axum 0.7 HTTP layer
//!       └── SchedulerError        — typed error enum
//! ```
//!
//! ## Lease protocol
//!
//! 1. A miner calls `GET /scheduler/miners/{miner_id}/task` and receives a
//!    `TaskAssignmentResponse` containing `lease_generation` and
//!    `lease_expires_at`.
//! 2. The miner must submit results before `lease_expires_at` via
//!    `POST /scheduler/tasks/{task_id}/result`, including `submitted_generation`.
//! 3. The scheduler validates:
//!    * `miner_id` == `task.assigned_to`
//!    * `submitted_generation` == `task.lease_generation`
//!    * `lease_expires_at > now`
//!    Any mismatch → `409 Conflict` (`LeaseSuperseded`) — submission dropped.
//! 4. A background ticker calls `expire_stale_leases` every N seconds,
//!    returning timed-out tasks to `'available'`.
//!
//! ## Consensus separation
//!
//! The scheduler is NOT on the consensus critical path.  A database or
//! scheduler outage must never prevent the chain from reaching consensus.
//! Reward eligibility, double-payment protection, and accepted-commitment
//! enforcement remain exclusively in `chain-forge-pocd::MicrotaskRegistry`
//! (in-memory) and on-chain via `DiscoveryReceipt`.
//!
//! `submit_result` transitions a task to `'submitted'`, NOT `'accepted'`.
//! Independent verification (Change Set F) is required before rewards can
//! be issued.

pub mod api;
pub mod error;
pub mod miner;
pub mod scheduler;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use api::{router, AppState};
pub use error::SchedulerError;
pub use miner::{MinerInfo, MinerRegistry};
pub use scheduler::ResearchScheduler;

#[cfg(test)]
mod tests;
