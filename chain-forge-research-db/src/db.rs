//! `ResearchDb` — async trait abstracting all persistence operations.
//!
//! The trait is the stable API surface.  The `PgResearchDb` struct is the
//! PostgreSQL implementation.  Future implementations (in-memory for tests,
//! SQLite for single-node devnet) only need to satisfy this trait.
//!
//! # Consensus separation
//!
//! This trait intentionally does NOT expose reward grant, treasury, or
//! double-payment guard operations.  Those remain exclusively in
//! `MicrotaskRegistry` (in-memory) and on-chain (DiscoveryReceipt).
//! A database outage must never prevent the chain from reaching consensus.

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::ResearchDbError;
use crate::models::*;

// ── Trait ─────────────────────────────────────────────────────────────────────

/// All persistence operations for the QCB Discovery Engine.
///
/// All methods are `async` and return `Result<_, ResearchDbError>`.
/// Implementations must be `Send + Sync` so they can be shared across
/// async tasks (e.g. stored in `Arc<dyn ResearchDb>`).
#[async_trait]
pub trait ResearchDb: Send + Sync {
    // ── objectives ──────────────────────────────────────────────────────────

    /// Persist a new research objective.
    /// Returns `ResearchDbError::Duplicate` if `objective_id` already exists.
    async fn insert_objective(&self, obj: NewObjective) -> Result<ObjectiveRow, ResearchDbError>;

    /// Fetch an objective by ID.  Returns `None` if not found.
    async fn get_objective(&self, objective_id: &str) -> Result<Option<ObjectiveRow>, ResearchDbError>;

    /// List all objectives for a challenge, ordered by created_at.
    async fn list_objectives_for_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Vec<ObjectiveRow>, ResearchDbError>;

    /// Update objective status (e.g. 'active' → 'completed').
    async fn update_objective_status(
        &self,
        objective_id: &str,
        status: &str,
    ) -> Result<(), ResearchDbError>;

    // ── tasks ───────────────────────────────────────────────────────────────

    /// Persist a batch of tasks for an objective.
    /// Skips tasks whose `task_id` already exists (idempotent upsert).
    async fn upsert_tasks(&self, tasks: Vec<NewTask>) -> Result<usize, ResearchDbError>;

    /// Fetch a task by ID.
    async fn get_task(&self, task_id: &str) -> Result<Option<TaskRow>, ResearchDbError>;

    /// List all tasks for an objective, ordered by range_start.
    async fn list_tasks_for_objective(
        &self,
        objective_id: &str,
    ) -> Result<Vec<TaskRow>, ResearchDbError>;

    /// List tasks with a given status for an objective.
    async fn list_tasks_by_status(
        &self,
        objective_id: &str,
        status: &str,
    ) -> Result<Vec<TaskRow>, ResearchDbError>;

    /// Update task status and optional fields.
    async fn update_task_status(
        &self,
        task_id:            &str,
        status:             &str,
        assigned_to:        Option<&str>,
        settled_receipt_id: Option<&str>,
    ) -> Result<(), ResearchDbError>;

    // ── experiment results ──────────────────────────────────────────────────

    /// Insert an experiment result.
    ///
    /// Returns `ResearchDbError::DuplicateResult` when an identical
    /// (task_id, miner_id, content_hash) triplet already exists.
    ///
    /// Intentional replication — same task, different miner, different
    /// content_hash — is permitted.
    async fn insert_result(
        &self,
        result: NewExperimentResult,
    ) -> Result<ExperimentResultRow, ResearchDbError>;

    /// Fetch a result by UUID.
    async fn get_result(&self, result_id: Uuid) -> Result<Option<ExperimentResultRow>, ResearchDbError>;

    /// List all results for a task (supports replication review).
    async fn list_results_for_task(
        &self,
        task_id: &str,
    ) -> Result<Vec<ExperimentResultRow>, ResearchDbError>;

    /// List all results submitted by a miner across all tasks.
    async fn list_results_for_miner(
        &self,
        miner_id: &str,
    ) -> Result<Vec<ExperimentResultRow>, ResearchDbError>;

    /// Update result status (e.g. 'submitted' → 'independently_verified').
    async fn update_result_status(
        &self,
        result_id: Uuid,
        status: &str,
    ) -> Result<(), ResearchDbError>;

    /// Check whether a content_hash has already been submitted for a task
    /// by the same miner (deduplication probe).
    async fn result_exists(
        &self,
        task_id:      &str,
        miner_id:     &str,
        content_hash: &str,
    ) -> Result<bool, ResearchDbError>;

    // ── verification records ────────────────────────────────────────────────

    /// Insert a verification record.
    ///
    /// Returns `ResearchDbError::SelfVerification` when `verifier_id`
    /// matches the original result's `miner_id`.
    async fn insert_verification(
        &self,
        record: NewVerificationRecord,
    ) -> Result<VerificationRecordRow, ResearchDbError>;

    /// List verification records for a result.
    async fn list_verifications_for_result(
        &self,
        result_id: Uuid,
    ) -> Result<Vec<VerificationRecordRow>, ResearchDbError>;

    // ── research findings ───────────────────────────────────────────────────

    /// Insert a research finding (positive or negative).
    async fn insert_finding(
        &self,
        finding: NewResearchFinding,
    ) -> Result<ResearchFindingRow, ResearchDbError>;

    /// List findings for an objective, ordered by found_at desc.
    async fn list_findings_for_objective(
        &self,
        objective_id: &str,
    ) -> Result<Vec<ResearchFindingRow>, ResearchDbError>;

    // ── research artifacts ──────────────────────────────────────────────────

    /// Insert a research artifact.
    async fn insert_artifact(
        &self,
        artifact: NewResearchArtifact,
    ) -> Result<ResearchArtifactRow, ResearchDbError>;

    /// Fetch an artifact by ID.
    async fn get_artifact(&self, artifact_id: Uuid) -> Result<Option<ResearchArtifactRow>, ResearchDbError>;

    // ── provenance ──────────────────────────────────────────────────────────

    /// Return the full provenance chain for a task:
    /// objective → task → results → verifications → findings → artifacts.
    async fn task_provenance(&self, task_id: &str) -> Result<TaskProvenance, ResearchDbError>;

    // ── recovery ────────────────────────────────────────────────────────────

    /// Return objective IDs where at least one task remains 'available' or 'assigned'.
    /// Used during service restart to reconstruct the scheduling queue.
    async fn objectives_with_pending_work(&self) -> Result<Vec<String>, ResearchDbError>;

    /// Count accepted tasks for an objective.
    async fn count_accepted_tasks(&self, objective_id: &str) -> Result<u64, ResearchDbError>;

    /// Total task count for an objective.
    async fn count_tasks(&self, objective_id: &str) -> Result<u64, ResearchDbError>;
}

// ── Provenance DTO ─────────────────────────────────────────────────────────────

/// Full provenance chain for a single microtask.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskProvenance {
    pub objective:     ObjectiveRow,
    pub task:          TaskRow,
    pub results:       Vec<ExperimentResultRow>,
    pub verifications: Vec<VerificationRecordRow>,
    pub findings:      Vec<ResearchFindingRow>,
    pub artifacts:     Vec<ResearchArtifactRow>,
}

use serde::{Deserialize, Serialize};
