//! `ObjectiveReport` — the primary output of the intelligence engine.
//!
//! A report is a structured, serialisable summary of everything the system
//! knows about a research objective: task-completion progress, verifier
//! agreement, miner contributions, finding confidence distribution, and any
//! flagged anomalies.
//!
//! Reports are versioned (`schema_version`) so the DB-persisted JSON can be
//! migrated if the shape changes.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Anomaly types ─────────────────────────────────────────────────────────────

/// A suspicious pattern detected during analysis.
///
/// Anomalies are advisory only — they never block consensus or modify task
/// status.  They are surfaced for human review via the intelligence API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Anomaly {
    /// Two or more miners submitted the same `content_hash` for the same task.
    ///
    /// In a legitimate distributed computation, different miners should rarely
    /// produce bitwise-identical output — collisions across miners may indicate
    /// result copying or coordinated pre-computation.
    HashCollision {
        task_id:      String,
        content_hash: String,
        /// Miners that submitted this hash.
        miner_ids:    Vec<String>,
    },

    /// A result has more `'diverged'` verifications than `'reproduced'` ones,
    /// suggesting the result may be incorrect.
    DivergenceStorm {
        result_id:       Uuid,
        task_id:         String,
        miner_id:        String,
        reproduced_count: u64,
        diverged_count:   u64,
    },

    /// The mean verifier-agreement rate for the objective has fallen below the
    /// warning threshold (default: 0.5).
    LowVerifierAgreement {
        objective_id:       String,
        verifier_agreement: f64,
        threshold:          f64,
    },

    /// An objective has been stalled at the same completion rate for too long
    /// (i.e., no tasks transitioned to `'accepted'` recently).
    ///
    /// Currently computed as: `available_tasks + assigned_tasks > 0` AND
    /// `accepted_tasks == 0` (no accepted work at all despite tasks existing).
    StallDetected {
        objective_id:    String,
        total_tasks:     u64,
        accepted_tasks:  u64,
        available_tasks: u64,
        assigned_tasks:  u64,
    },
}

// ── Miner contribution ────────────────────────────────────────────────────────

/// Per-miner statistics within an objective.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerContribution {
    pub miner_id:        String,
    /// Number of results submitted (accepted + others).
    pub results_submitted: u64,
    /// Number of those results that reached `'accepted'` status.
    pub results_accepted:  u64,
    /// Acceptance rate for this miner (0.0–1.0).  `None` if no results.
    pub acceptance_rate:   Option<f64>,
}

// ── Finding summary ───────────────────────────────────────────────────────────

/// Lightweight summary of a finding for inclusion in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub finding_id:   Uuid,
    pub finding_type: String,
    pub summary:      String,
    pub confidence:   Option<f64>,
    pub found_at:     DateTime<Utc>,
}

// ── ObjectiveReport ───────────────────────────────────────────────────────────

/// The complete intelligence report for one research objective.
///
/// Serialised as JSON and stored in `research_intelligence_reports.report_body`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectiveReport {
    /// Schema version — increment when the shape changes.
    pub schema_version:     u32,
    pub objective_id:       String,
    pub challenge_id:       String,
    pub slug:               String,
    pub track:              String,
    pub algorithm_version:  String,
    pub generated_at:       DateTime<Utc>,

    // ── Progress ──────────────────────────────────────────────────────────────
    pub total_tasks:        u64,
    pub available_tasks:    u64,
    pub assigned_tasks:     u64,
    pub submitted_tasks:    u64,
    pub accepted_tasks:     u64,
    /// Fraction of tasks that have been accepted (0.0–1.0).
    /// `None` when there are no tasks.
    pub completion_rate:    Option<f64>,

    // ── Verification ─────────────────────────────────────────────────────────
    pub total_results:      u64,
    pub unique_miners:      u64,
    pub reproduced_count:   u64,
    pub diverged_count:     u64,
    /// Mean fraction of `'reproduced'` verifications per result.
    /// `None` when no verifications exist yet.
    pub verifier_agreement: Option<f64>,

    // ── Miner breakdown ───────────────────────────────────────────────────────
    /// Per-miner contribution stats, ordered by `results_accepted DESC`.
    pub miner_contributions: Vec<MinerContribution>,

    // ── Findings ──────────────────────────────────────────────────────────────
    /// High-confidence findings (confidence ≥ 0.7), newest first.
    pub high_confidence_findings: Vec<FindingSummary>,
    /// Total finding count (all confidence levels, including NULL).
    pub total_findings:           u64,

    // ── Anomalies ─────────────────────────────────────────────────────────────
    pub anomalies: Vec<Anomaly>,
}

// ── Anomaly detection thresholds ─────────────────────────────────────────────

/// Configuration knobs for anomaly detection.
///
/// All fields have sensible defaults.
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// Mean verifier-agreement below this triggers `LowVerifierAgreement`.
    /// Default: 0.5
    pub low_agreement_threshold: f64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            low_agreement_threshold: 0.5,
        }
    }
}

// ── Miner contribution builder (helper) ─────────────────────────────────────

/// Build per-miner contribution stats from a flat list of results.
pub fn build_miner_contributions(
    results: &[chain_forge_research_db::models::ExperimentResultRow],
) -> Vec<MinerContribution> {
    let mut by_miner: HashMap<String, (u64, u64)> = HashMap::new(); // (submitted, accepted)
    for r in results {
        let entry = by_miner.entry(r.miner_id.clone()).or_default();
        entry.0 += 1;
        if r.result_status == "accepted" {
            entry.1 += 1;
        }
    }
    let mut contributions: Vec<MinerContribution> = by_miner
        .into_iter()
        .map(|(miner_id, (submitted, accepted))| {
            let acceptance_rate = if submitted == 0 {
                None
            } else {
                Some(accepted as f64 / submitted as f64)
            };
            MinerContribution {
                miner_id,
                results_submitted: submitted,
                results_accepted:  accepted,
                acceptance_rate,
            }
        })
        .collect();
    // Order by accepted DESC, then submitted DESC
    contributions.sort_by(|a, b| {
        b.results_accepted
            .cmp(&a.results_accepted)
            .then_with(|| b.results_submitted.cmp(&a.results_submitted))
    });
    contributions
}
