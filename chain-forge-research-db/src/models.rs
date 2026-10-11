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
    pub verification_quorum:  i32,
    pub created_at:           DateTime<Utc>,
    pub updated_at:           DateTime<Utc>,
}

// ── research_tasks ────────────────────────────────────────────────────────────

/// Database row for `research_tasks`.
///
/// **Two-phase cascade fields (Change Set J)**:
///
/// * `phase`       — `1` = initial SHA-256 preimage search; `2` = second-hop
///   search seeded by the phase-1 winner's hash.  Phase-2 tasks are created
///   dynamically by the scheduler when a phase-1 result is accepted.
/// * `parent_hash` — for phase-2 tasks, the hex-encoded winning hash from
///   phase-1 that becomes the seed of this task.  `None` for phase-1 tasks.
/// * `phase1_miner_id` — for phase-2 tasks, the miner that completed phase-1.
///   The scheduler will never assign a phase-2 task to the same miner,
///   ensuring two independent machines contribute to every full discovery.
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
    pub lease_expires_at:   Option<DateTime<Utc>>,
    pub lease_generation:   i64,
    pub attempt_count:      i32,
    // ── two-phase cascade fields (Change Set J) ─────────────────────────────
    /// Which phase of the cascade this task belongs to.  Always 1 or 2.
    pub phase:              i32,
    /// For phase-2 tasks: hex-encoded SHA-256 output from the phase-1 winner
    /// that seeds this task's search.  `None` for phase-1 tasks.
    pub parent_hash:        Option<String>,
    /// For phase-2 tasks: the miner_id that completed the parent phase-1 task.
    /// The scheduler uses this to enforce the different-miner rule.
    pub phase1_miner_id:    Option<String>,
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
    #[serde(default = "default_verification_quorum")]
    pub verification_quorum: u32,
}

fn default_verification_quorum() -> u32 { 2 }

/// Input for inserting a new task.
///
/// Phase-1 tasks (seeded by `qcb-seed`) leave `parent_hash` and
/// `phase1_miner_id` as `None`.  Phase-2 tasks are created by the scheduler
/// and always supply both fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewTask {
    pub task_id:            String,
    pub objective_id:       String,
    pub range_start:        u64,
    pub range_end:          u64,
    pub workload_class:     String,
    pub input_seed:         u64,
    /// 1 = phase-1 (default), 2 = phase-2 spawned by scheduler.
    #[serde(default = "default_phase")]
    pub phase:              u32,
    /// Phase-2 only: hex-encoded winning hash from the phase-1 task.
    pub parent_hash:        Option<String>,
    /// Phase-2 only: miner_id that completed the phase-1 task.
    /// The scheduler blocks this miner from being assigned the phase-2 task.
    pub phase1_miner_id:    Option<String>,
}

fn default_phase() -> u32 { 1 }

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectiveStats {
    pub objective_id:       String,
    pub total_tasks:        u64,
    pub available_tasks:    u64,
    pub assigned_tasks:     u64,
    pub submitted_tasks:    u64,
    pub accepted_tasks:     u64,
    pub unique_miners:      u64,
    pub total_results:      u64,
    pub reproduced_count:   u64,
    pub diverged_count:     u64,
    pub completion_rate:    Option<f64>,
    pub verifier_agreement: Option<f64>,
}

/// A persisted intelligence report for one objective.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct IntelligenceReportRow {
    pub report_id:      uuid::Uuid,
    pub objective_id:   String,
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
