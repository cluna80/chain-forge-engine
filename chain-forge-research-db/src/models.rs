//! Row types that map 1-to-1 with the database schema.
//!
//! These are distinct from the in-memory types in `chain-forge-pocd`
//! so the schema can evolve independently without touching consensus code.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ── research_objectives ───────────────────────────────────────────────────────

/// Database row for `research_objectives`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ObjectiveRow {
    pub objective_id:         String,
    pub challenge_id:         String,
    pub slug:                 String,
    pub track:                String,
    pub algorithm_version:    String,
    pub range_start:          i64,
    pub range_end:            i64,
    pub workload_class:       String,
    pub status:               String,
    pub verification_spec:    serde_json::Value,
    /// Minimum number of independent `'reproduced'` verifications required
    /// before a submitted result may transition to `'accepted'`.
    /// Added in migration 008 (Change Set F). Default: 2.
    pub verification_quorum:  i32,
    pub created_at:           DateTime<Utc>,
    pub updated_at:           DateTime<Utc>,
}

// ── research_tasks ────────────────────────────────────────────────────────────

/// Database row for `research_tasks`.
///
/// Three fields were added in migration 007 (Change Set E) to support
/// the atomic lease protocol used by `chain-forge-scheduler`:
///
/// * `lease_expires_at`  — wall-clock deadline; `None` when not assigned.
/// * `lease_generation`  — monotonic counter; incremented by every `assign_task()`.
///   A miner's submission must carry the exact generation it received.
/// * `attempt_count`     — total number of assignments ever issued for this task.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TaskRow {
    pub task_id:            String,
    pub objective_id:       String,
    pub range_start:        i64,
    pub range_end:          i64,
    pub workload_class:     String,
    pub input_seed:         i64,
    pub status:             String,
    pub assigned_to:        Option<String>,
    pub settled_receipt_id: Option<String>,
    // ── lease fields (migration 007) ────────────────────────────────────────
    /// Wall-clock expiry of the current assignment lease.  `None` when
    /// `status` is `'available'` or `'submitted'`.
    pub lease_expires_at:   Option<DateTime<Utc>>,
    /// Monotonically increasing assignment counter.  Never reset, only
    /// incremented.  Miners must present this value when submitting results.
    pub lease_generation:   i64,
    /// Total number of times `assign_task()` has fired for this task.
    pub attempt_count:      i32,
    // ────────────────────────────────────────────────────────────────────────
    pub created_at:         DateTime<Utc>,
    pub updated_at:         DateTime<Utc>,
}

// ── experiment_results ────────────────────────────────────────────────────────

/// Database row for `experiment_results`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ExperimentResultRow {
    pub result_id:          Uuid,
    pub task_id:            String,
    pub receipt_id:         String,
    pub miner_id:           String,
    pub content_hash:       String,
    pub result_status:      String,
    pub result_payload:     serde_json::Value,
    pub algorithm_version:  String,
    pub workload_version:   String,
    pub seal_nonce:         Option<i64>,
    pub submitted_at:       DateTime<Utc>,
    pub updated_at:         DateTime<Utc>,
}

// ── verification_records ──────────────────────────────────────────────────────

/// Database row for `verification_records`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VerificationRecordRow {
    pub verification_id:        Uuid,
    pub result_id:              Uuid,
    pub task_id:                String,
    pub verifier_id:            String,
    pub outcome:                String,
    pub verifier_content_hash:  String,
    pub notes:                  Option<String>,
    pub verifier_receipt_id:    Option<String>,
    pub verified_at:            DateTime<Utc>,
}

// ── research_findings ─────────────────────────────────────────────────────────

/// Database row for `research_findings`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ResearchFindingRow {
    pub finding_id:             Uuid,
    pub objective_id:           String,
    pub task_id:                Option<String>,
    pub finding_type:           String,
    pub summary:                String,
    pub confidence:             Option<f64>,
    pub evidence_refs:          serde_json::Value,
    pub applied_to_objective:   bool,
    pub found_at:               DateTime<Utc>,
    pub updated_at:             DateTime<Utc>,
}

// ── research_artifacts ────────────────────────────────────────────────────────

/// Database row for `research_artifacts`.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ResearchArtifactRow {
    pub artifact_id:            Uuid,
    pub result_id:              Option<Uuid>,
    pub finding_id:             Option<Uuid>,
    pub artifact_type:          String,
    pub label:                  String,
    pub content_hash:           String,
    pub size_bytes:             i64,
    pub storage_uri:            String,
    pub supersedes_artifact_id: Option<Uuid>,
    pub created_at:             DateTime<Utc>,
}

// ── Input DTOs (used when inserting new rows) ─────────────────────────────────

/// Input for inserting a new objective.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewObjective {
    pub objective_id:        String,
    pub challenge_id:        String,
    pub slug:                String,
    pub track:               String,
    pub algorithm_version:   String,
    pub range_start:         u64,
    pub range_end:           u64,
    pub workload_class:      String,
    pub verification_spec:   serde_json::Value,
    /// Required reproduced-verification quorum before a result is accepted.
    /// Defaults to 2 when not supplied (matches the DB column default).
    #[serde(default = "default_verification_quorum")]
    pub verification_quorum: u32,
}

fn default_verification_quorum() -> u32 { 2 }

/// Input for inserting a new task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewTask {
    pub task_id:        String,
    pub objective_id:   String,
    pub range_start:    u64,
    pub range_end:      u64,
    pub workload_class: String,
    pub input_seed:     u64,
}

/// Input for inserting a new experiment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewExperimentResult {
    pub task_id:            String,
    pub receipt_id:         String,
    pub miner_id:           String,
    pub content_hash:       String,
    pub result_payload:     serde_json::Value,
    pub algorithm_version:  String,
    pub workload_version:   String,
    pub seal_nonce:         Option<u64>,
}

/// Input for inserting a verification record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewVerificationRecord {
    pub result_id:              Uuid,
    pub task_id:                String,
    pub verifier_id:            String,
    pub outcome:                String,
    pub verifier_content_hash:  String,
    pub notes:                  Option<String>,
    pub verifier_receipt_id:    Option<String>,
}

/// Input for inserting a research finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewResearchFinding {
    pub objective_id:   String,
    pub task_id:        Option<String>,
    pub finding_type:   String,
    pub summary:        String,
    pub confidence:     Option<f64>,
    pub evidence_refs:  serde_json::Value,
}

// ── intelligence (Change Set G) ───────────────────────────────────────────────

/// Aggregate statistics for a single research objective.
///
/// Returned by `ResearchDb::get_objective_stats`.  All counts are computed
/// in a single query so callers pay one round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectiveStats {
    pub objective_id:       String,
    /// Total task count for the objective.
    pub total_tasks:        u64,
    /// Tasks still in `'available'` status.
    pub available_tasks:    u64,
    /// Tasks currently `'assigned'` to a miner.
    pub assigned_tasks:     u64,
    /// Tasks that have been submitted and are awaiting verification.
    pub submitted_tasks:    u64,
    /// Tasks that have reached `'accepted'` after quorum verification.
    pub accepted_tasks:     u64,
    /// Unique miners that have submitted at least one result.
    pub unique_miners:      u64,
    /// Total submitted result rows (may exceed `accepted_tasks` due to
    /// replication and rejected duplicates).
    pub total_results:      u64,
    /// Number of `'reproduced'` verification records across all results.
    pub reproduced_count:   u64,
    /// Number of `'diverged'` verification records across all results.
    pub diverged_count:     u64,
    /// Fraction of tasks that have been accepted (0.0–1.0).
    /// `None` when `total_tasks == 0`.
    pub completion_rate:    Option<f64>,
    /// Mean fraction of verifications that returned `'reproduced'` per result,
    /// across results that have at least one verification.
    /// `None` when no verifications exist yet.
    pub verifier_agreement: Option<f64>,
}

/// A persisted intelligence report for one objective.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct IntelligenceReportRow {
    pub report_id:      uuid::Uuid,
    pub objective_id:   String,
    /// Full `ObjectiveReport` JSON (as stored in the DB).
    pub report_body:    serde_json::Value,
    pub generated_at:   DateTime<Utc>,
    pub schema_version: i32,
}

/// Input for upserting an intelligence report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewIntelligenceReport {
    pub objective_id:   String,
    pub report_body:    serde_json::Value,
    pub schema_version: i32,
}

/// Input for inserting a research artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewResearchArtifact {
    pub result_id:              Option<Uuid>,
    pub finding_id:             Option<Uuid>,
    pub artifact_type:          String,
    pub label:                  String,
    pub content_hash:           String,
    pub size_bytes:             u64,
    pub storage_uri:            String,
    pub supersedes_artifact_id: Option<Uuid>,
}
