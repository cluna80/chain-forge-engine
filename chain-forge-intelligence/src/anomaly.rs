//! `AnomalyDetector` — identifies suspicious patterns in accepted research data.
//!
//! All detection is purely statistical and advisory.  Nothing here modifies
//! task or result status; anomalies are surfaced for human review only.

use std::collections::HashMap;

use uuid::Uuid;

use chain_forge_research_db::models::{ExperimentResultRow, ObjectiveStats, VerificationRecordRow};

use crate::report::{Anomaly, AnomalyConfig};

/// Detects anomalies from accepted results and their verification records.
pub struct AnomalyDetector {
    pub config: AnomalyConfig,
}

impl AnomalyDetector {
    pub fn new(config: AnomalyConfig) -> Self {
        Self { config }
    }

    /// Run all detectors and return a de-duplicated list of anomalies.
    ///
    /// `results` — all results for the objective (not just accepted ones),
    ///             so hash-collision detection covers the full submission set.
    /// `verifications` — all verification records for results in `results`.
    /// `stats` — pre-computed objective-level stats (from `get_objective_stats`).
    pub fn detect(
        &self,
        results:       &[ExperimentResultRow],
        verifications: &[VerificationRecordRow],
        stats:         &ObjectiveStats,
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        self.detect_hash_collisions(results, &mut anomalies);
        self.detect_divergence_storms(results, verifications, &mut anomalies);
        self.detect_low_agreement(stats, &mut anomalies);
        self.detect_stall(stats, &mut anomalies);

        anomalies
    }

    // ── Hash collision ────────────────────────────────────────────────────────

    /// Flag tasks where multiple distinct miners submitted the same content_hash.
    fn detect_hash_collisions(
        &self,
        results: &[ExperimentResultRow],
        out: &mut Vec<Anomaly>,
    ) {
        // Group by (task_id, content_hash) → Vec<miner_id>
        let mut map: HashMap<(String, String), Vec<String>> = HashMap::new();
        for r in results {
            map.entry((r.task_id.clone(), r.content_hash.clone()))
                .or_default()
                .push(r.miner_id.clone());
        }
        for ((task_id, content_hash), mut miner_ids) in map {
            // Deduplicate miner list — same miner can submit multiple results
            miner_ids.sort();
            miner_ids.dedup();
            if miner_ids.len() >= 2 {
                out.push(Anomaly::HashCollision {
                    task_id,
                    content_hash,
                    miner_ids,
                });
            }
        }
        // Stable order for deterministic tests
        out.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    }

    // ── Divergence storm ──────────────────────────────────────────────────────

    /// Flag results where diverged verifications outnumber reproduced ones.
    fn detect_divergence_storms(
        &self,
        results:       &[ExperimentResultRow],
        verifications: &[VerificationRecordRow],
        out: &mut Vec<Anomaly>,
    ) {
        // Build verification index keyed by result_id
        let mut ver_index: HashMap<Uuid, (u64, u64)> = HashMap::new(); // (reproduced, diverged)
        for v in verifications {
            let entry = ver_index.entry(v.result_id).or_default();
            match v.outcome.as_str() {
                "reproduced" => entry.0 += 1,
                "diverged"   => entry.1 += 1,
                _            => {}
            }
        }
        for r in results {
            if let Some(&(reproduced, diverged)) = ver_index.get(&r.result_id) {
                if diverged > reproduced {
                    out.push(Anomaly::DivergenceStorm {
                        result_id:        r.result_id,
                        task_id:          r.task_id.clone(),
                        miner_id:         r.miner_id.clone(),
                        reproduced_count: reproduced,
                        diverged_count:   diverged,
                    });
                }
            }
        }
    }

    // ── Low verifier agreement ────────────────────────────────────────────────

    fn detect_low_agreement(
        &self,
        stats: &ObjectiveStats,
        out:   &mut Vec<Anomaly>,
    ) {
        if let Some(agreement) = stats.verifier_agreement {
            if agreement < self.config.low_agreement_threshold {
                out.push(Anomaly::LowVerifierAgreement {
                    objective_id:       stats.objective_id.clone(),
                    verifier_agreement: agreement,
                    threshold:          self.config.low_agreement_threshold,
                });
            }
        }
    }

    // ── Stall detection ───────────────────────────────────────────────────────

    /// Flag objectives that have tasks but no accepted results yet.
    fn detect_stall(
        &self,
        stats: &ObjectiveStats,
        out:   &mut Vec<Anomaly>,
    ) {
        let has_pending = stats.available_tasks + stats.assigned_tasks > 0;
        if has_pending && stats.accepted_tasks == 0 && stats.total_tasks > 0 {
            out.push(Anomaly::StallDetected {
                objective_id:    stats.objective_id.clone(),
                total_tasks:     stats.total_tasks,
                accepted_tasks:  stats.accepted_tasks,
                available_tasks: stats.available_tasks,
                assigned_tasks:  stats.assigned_tasks,
            });
        }
    }
}
