//! Row types that map 1-to-1 with the database schema.
//!
//! These are distinct from the in-memory types in `chain-forge-pocd`
//! so the schema can evolve independently without touching consensus code.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ── TaskKind ──────────────────────────────────────────────────────────────────

/// Discriminates between PoCD (proof-of-coordinated-difficulty) work and
/// Change Set K research experiments.  Stored as a string in the database
/// so the column is readable without joins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// Phase-1 of the SHA-256 preimage cascade (the original PoCD work).
    PoCDPhase1,
    /// Phase-2 of the SHA-256 preimage cascade (different-miner enforcement).
    PoCDPhase2,
    /// Change Set K: avalanche-analysis experiment.
    /// The miner computes SHA-256(seed) and SHA-256(flip(seed, bit_index)),
    /// XORs the outputs, counts the Hamming distance, and submits the full
    /// 32-byte XOR vector so the analyzer can build the flip-frequency matrix.
    AvalancheExperiment,
    /// Cross-machine replication sample: same computation as AvalancheExperiment
    /// but must be performed by a *different* miner than the one that completed
    /// the original task.  `phase1_miner_id` carries the original miner_id for
    /// the scheduler's exclude_miner filter.
    AvalancheReplication,
}

impl TaskKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskKind::PoCDPhase1          => "pocd_phase1",
            TaskKind::PoCDPhase2          => "pocd_phase2",
            TaskKind::AvalancheExperiment => "avalanche_experiment",
            TaskKind::AvalancheReplication=> "avalanche_replication",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pocd_phase1"           => Some(TaskKind::PoCDPhase1),
            "pocd_phase2"           => Some(TaskKind::PoCDPhase2),
            "avalanche_experiment"  => Some(TaskKind::AvalancheExperiment),
            "avalanche_replication" => Some(TaskKind::AvalancheReplication),
            _ => None,
        }
    }

    /// Returns true for the two avalanche kinds (same computation,
    /// different provenance label).
    pub fn is_avalanche(&self) -> bool {
        matches!(self, TaskKind::AvalancheExperiment | TaskKind::AvalancheReplication)
    }
}

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
///
/// **Avalanche experiment fields (Change Set K)**:
///
/// * `task_kind`   — discriminates between PoCD phases and avalanche experiment/
///   replication kinds.  Stored as a human-readable string.
/// * `avl_seed_index` — for avalanche tasks: which of the 10 canonical seeds
///   (0..9) this task uses.  The actual 32-byte seed is derived as
///   `SHA-256("qcb-avalanche-v1" || objective_id || seed_index_le64)`.
/// * `avl_bit_index`  — for avalanche tasks: which input bit (0..255) is
///   flipped for this experiment.
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
    /// Reused for avalanche_replication tasks: the original miner that must be
    /// excluded from the replication assignment.
    pub phase1_miner_id:    Option<String>,
    // ── task kind + avalanche fields (Change Set K) ──────────────────────────
    /// Discriminator string; see `TaskKind`.  Defaults to `"pocd_phase1"` for
    /// backwards-compatible rows that pre-date Change Set K.
    pub task_kind:          String,
    /// Avalanche only: index of the canonical seed (0..9).
    pub avl_seed_index:     Option<i32>,
    /// Avalanche only: input bit position to flip (0..255).
    pub avl_bit_index:      Option<i32>,
    // ────────────────────────────────────────────────────────────────────────
    pub created_at:         DateTime<Utc>,
    pub updated_at:         DateTime<Utc>,
}

impl TaskRow {
    /// Parse the `task_kind` string into a `TaskKind` enum value.
    /// Falls back to `PoCDPhase1` for legacy rows.
    pub fn kind(&self) -> TaskKind {
        TaskKind::from_str(&self.task_kind).unwrap_or(TaskKind::PoCDPhase1)
    }
}

// ── experiment_results ────────────────────────────────────────────────────────

/// Database row for `experiment_results`.
///
/// **Avalanche result fields (Change Set K)**:
///
/// * `avl_original_hash` — hex-encoded SHA-256(canonical_seed) — the 32-byte
///   hash of the unmodified seed.
/// * `avl_flipped_hash`  — hex-encoded SHA-256(flip(canonical_seed, bit_index)).
/// * `avl_xor_diff`      — hex-encoded 32-byte XOR of the two hashes.  Storing
///   the full vector (not just the count) allows the analyzer to build the
///   per-output-bit flip-frequency matrix.
/// * `avl_hamming_dist`  — `popcount(xor_diff)`, i.e. the number of output bits
///   that changed.  Redundant with `avl_xor_diff` but denormalized for fast
///   aggregate queries.
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
    // ── avalanche result fields (Change Set K) ───────────────────────────────
    /// Avalanche only: hex-encoded SHA-256(canonical_seed) — 64 hex chars.
    pub avl_original_hash:  Option<String>,
    /// Avalanche only: hex-encoded SHA-256(flip(seed, bit_index)) — 64 hex chars.
    pub avl_flipped_hash:   Option<String>,
    /// Avalanche only: hex-encoded XOR of the two 32-byte hashes — 64 hex chars.
    pub avl_xor_diff:       Option<String>,
    /// Avalanche only: Hamming distance between original and flipped hash
    /// (= popcount of xor_diff); 0..=256.
    pub avl_hamming_dist:   Option<i32>,
    // ── task identity fields (joined from research_tasks) ────────────────────
    /// Task kind discriminator: "avalanche_experiment" | "avalanche_replication"
    /// | "pocd_phase1" | "pocd_phase2".
    /// Populated from the parent task row by list_results_for_objective.
    #[serde(default = "default_task_kind")]
    pub task_kind:          String,
    /// Avalanche only: which of the 10 canonical seeds (0..9).
    /// Populated from the parent task row by list_results_for_objective.
    pub avl_seed_index:     Option<i32>,
    /// Avalanche only: which input bit position is flipped (0..255).
    /// Populated from the parent task row by list_results_for_objective.
    pub avl_bit_index:      Option<i32>,
    // ─────────────────────────────────────────────────────────────────────────
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
///
/// Avalanche tasks (Change Set K) set `task_kind` to `"avalanche_experiment"`
/// or `"avalanche_replication"` and supply `avl_seed_index` + `avl_bit_index`.
/// The miner ignores `range_start`/`range_end` for these kinds; use 0/0.
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
    /// Also used by avalanche_replication tasks for the same exclude purpose.
    pub phase1_miner_id:    Option<String>,
    // ── Change Set K ─────────────────────────────────────────────────────────
    /// Task kind string; see `TaskKind`.  Defaults to `"pocd_phase1"`.
    #[serde(default = "default_task_kind")]
    pub task_kind:          String,
    /// Avalanche only: canonical seed index (0..9).
    pub avl_seed_index:     Option<u32>,
    /// Avalanche only: input bit index to flip (0..255).
    pub avl_bit_index:      Option<u32>,
}

fn default_phase() -> u32 { 1 }
fn default_task_kind() -> String { "pocd_phase1".to_string() }

/// Input for inserting a new experiment result.
///
/// Avalanche tasks (Change Set K) populate the four `avl_*` fields.
/// PoCD tasks leave them as `None`.
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
    // ── Change Set K ─────────────────────────────────────────────────────────
    /// Avalanche only: hex-encoded SHA-256(canonical_seed).
    pub avl_original_hash:  Option<String>,
    /// Avalanche only: hex-encoded SHA-256(flip(seed, bit_index)).
    pub avl_flipped_hash:   Option<String>,
    /// Avalanche only: hex-encoded XOR of the two hashes (32 bytes = 64 hex chars).
    pub avl_xor_diff:       Option<String>,
    /// Avalanche only: popcount(xor_diff) — Hamming distance, 0..=256.
    pub avl_hamming_dist:   Option<u32>,
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
