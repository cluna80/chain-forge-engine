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
use chrono::{DateTime, Utc};
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

    /// List all results for an objective regardless of status (submitted,
    /// accepted, etc.).  Used by the analyzer to read results from an
    /// in-memory scheduler that has no independent-verification step.
    async fn list_results_for_objective(
        &self,
        objective_id: &str,
        limit:        usize,
        offset:       usize,
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

    // ── scheduling (Change Set E) ────────────────────────────────────────────

    /// Atomically assign the next available task for the given objective and
    /// workload class to a miner, returning the full `TaskRow` (including the
    /// new `lease_generation` the miner must present on submission).
    ///
    /// `exclude_miner` — when `Some`, skip any task whose `phase1_miner_id`
    /// matches this value.  Used by the scheduler to enforce the two-phase
    /// different-miner rule: a miner that completed phase-1 of a task cannot
    /// be assigned the resulting phase-2 task.
    ///
    /// Returns `None` when no eligible task exists.
    async fn assign_task(
        &self,
        objective_id:     &str,
        workload_class:   &str,
        miner_id:         &str,
        lease_expires_at: DateTime<Utc>,
        exclude_miner:    Option<&str>,
    ) -> Result<Option<TaskRow>, ResearchDbError>;

    // ── two-phase cascade (Change Set J) ────────────────────────────────────

    /// Spawn a phase-2 task derived from a completed phase-1 result.
    ///
    /// Called by the scheduler immediately after a phase-1 result is
    /// submitted.  The new task:
    /// - has `phase = 2`
    /// - uses `parent_hash` (hex-encoded phase-1 winning hash) as its seed
    ///   (the bytes of the hash XOR-folded into an i64)
    /// - records `phase1_miner_id` so the scheduler can block that miner
    ///   from picking up the derived task
    ///
    /// Returns the newly created `TaskRow`.  If a phase-2 task already exists
    /// for this parent task (idempotent replay), returns the existing row.
    async fn spawn_phase2_task(
        &self,
        parent_task_id:  &str,
        parent_hash:     &str,
        phase1_miner_id: &str,
        range_per_task:  u64,
    ) -> Result<TaskRow, ResearchDbError>;

    /// Transition a task from `'assigned'` to `'submitted'`.
    ///
    /// The **caller** (i.e. `ResearchScheduler`) is responsible for
    /// validating that `miner_id` matches `assigned_to` AND that
    /// `submitted_generation` equals the stored `lease_generation` BEFORE
    /// calling this method.  A generation mismatch at the scheduler layer
    /// returns `SchedulerError::LeaseSuperseded`; this method is called only
    /// after those checks pass.
    ///
    /// Clears `lease_expires_at` and `assigned_to` as part of the transition.
    async fn submit_task_result(
        &self,
        task_id:  &str,
        miner_id: &str,
    ) -> Result<(), ResearchDbError>;

    /// Bulk-return all `'assigned'` tasks whose `lease_expires_at < now` back
    /// to `'available'`.
    ///
    /// `lease_generation` is intentionally NOT reset — the next `assign_task()`
    /// call increments it, ensuring evicted miners' old generation values can
    /// never match any future assignment.
    ///
    /// Returns the number of rows that were returned to `'available'`.
    async fn expire_stale_leases(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, ResearchDbError>;

    // ── recovery ────────────────────────────────────────────────────────────

    /// Return objective IDs where at least one task remains 'available' or 'assigned'.
    /// Used during service restart to reconstruct the scheduling queue.
    async fn objectives_with_pending_work(&self) -> Result<Vec<String>, ResearchDbError>;

    /// Count accepted tasks for an objective.
    async fn count_accepted_tasks(&self, objective_id: &str) -> Result<u64, ResearchDbError>;

    /// Total task count for an objective.
    async fn count_tasks(&self, objective_id: &str) -> Result<u64, ResearchDbError>;

    // ── verification (Change Set F) ──────────────────────────────────────────

    /// Return the `verification_quorum` for an objective.
    ///
    /// This is the minimum number of independent `'reproduced'` verifications
    /// required before a submitted result may be accepted.
    async fn get_verification_quorum(
        &self,
        objective_id: &str,
    ) -> Result<u32, ResearchDbError>;

    /// Count the number of independent `'reproduced'` verifications for a
    /// given result.
    ///
    /// Only verifications with `outcome = 'reproduced'` are counted.
    /// Self-verifications are blocked at insert time (by the DB constraint and
    /// `insert_verification`), so this count is always independent reproductions.
    async fn count_reproduced_verifications(
        &self,
        result_id: Uuid,
    ) -> Result<u64, ResearchDbError>;

    /// Transition a task from `'submitted'` to `'accepted'`, and mark the
    /// associated result as `'accepted'`.
    ///
    /// Called by `VerificationEngine` once the reproduced-verification count
    /// meets or exceeds the objective's `verification_quorum`.
    ///
    /// This is the ONLY path by which a task reaches `'accepted'`.  No
    /// other code should directly flip a task or result to `accepted`.
    async fn accept_task(
        &self,
        task_id:   &str,
        result_id: Uuid,
    ) -> Result<(), ResearchDbError>;

    /// List all tasks for an objective that are in `'submitted'` status
    /// (i.e. awaiting independent verification).
    async fn list_submitted_tasks(
        &self,
        objective_id: &str,
    ) -> Result<Vec<TaskRow>, ResearchDbError>;

    // ── intelligence (Change Set G) ──────────────────────────────────────────

    /// Return all accepted results for an objective, each with its full
    /// verification records.
    ///
    /// Used by `AnalysisEngine` to compute the objective report.  Only results
    /// with `result_status = 'accepted'` are returned; results still in
    /// `'submitted'` or `'pending'` status are excluded.
    async fn get_accepted_results_for_objective(
        &self,
        objective_id: &str,
    ) -> Result<Vec<ExperimentResultRow>, ResearchDbError>;

    /// Return aggregate statistics for an objective in a single query.
    ///
    /// Implementations should compute all counts atomically (e.g. via
    /// `SELECT … GROUP BY` or CTEs) so there is no time-of-check vs.
    /// time-of-use inconsistency between the individual counters.
    async fn get_objective_stats(
        &self,
        objective_id: &str,
    ) -> Result<ObjectiveStats, ResearchDbError>;

    /// List findings for an objective whose `confidence >= min_confidence`.
    ///
    /// Findings with `confidence = NULL` are excluded.
    /// Results are ordered by `confidence DESC, found_at DESC`.
    async fn list_findings_with_confidence(
        &self,
        objective_id:   &str,
        min_confidence: f64,
    ) -> Result<Vec<ResearchFindingRow>, ResearchDbError>;

    /// Upsert an intelligence report for an objective.
    ///
    /// If a report already exists for the objective, it is replaced in place
    /// (the `report_body`, `generated_at`, and `schema_version` are updated).
    async fn upsert_intelligence_report(
        &self,
        report: NewIntelligenceReport,
    ) -> Result<IntelligenceReportRow, ResearchDbError>;

    /// Fetch the most recently generated intelligence report for an objective.
    ///
    /// Returns `None` if no report has been generated yet.
    async fn get_intelligence_report(
        &self,
        objective_id: &str,
    ) -> Result<Option<IntelligenceReportRow>, ResearchDbError>;
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
