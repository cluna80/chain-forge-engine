//! `AnalysisEngine` — orchestrates report generation and anomaly detection.
//!
//! The engine holds an `Arc<dyn ResearchDb>` and provides two high-level
//! operations:
//!
//! 1. `generate_report(objective_id)` — compute a full `ObjectiveReport` and
//!    persist it via `upsert_intelligence_report`.  Returns the fresh report.
//! 2. `get_report(objective_id)` — fetch the most recently persisted report
//!    without re-running analysis.
//! 3. `detect_anomalies(objective_id)` — run anomaly detection on the current
//!    DB state without persisting a full report.

use std::sync::Arc;

use chrono::Utc;

use chain_forge_research_db::{
    ResearchDb,
    models::{
        ExperimentResultRow, NewIntelligenceReport,
        VerificationRecordRow,
    },
};

use crate::anomaly::AnomalyDetector;
use crate::error::{IntelligenceError, IntelligenceResult};
use crate::report::{
    AnomalyConfig, FindingSummary, ObjectiveReport, build_miner_contributions,
};

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct AnalysisEngine {
    pub(crate) db:     Arc<dyn ResearchDb>,
    pub(crate) config: AnomalyConfig,
}

impl AnalysisEngine {
    pub fn new(db: Arc<dyn ResearchDb>) -> Self {
        Self {
            db,
            config: AnomalyConfig::default(),
        }
    }

    pub fn with_config(db: Arc<dyn ResearchDb>, config: AnomalyConfig) -> Self {
        Self { db, config }
    }

    // ── generate_report ───────────────────────────────────────────────────────

    /// Compute a full `ObjectiveReport`, persist it to the DB, and return it.
    pub async fn generate_report(
        &self,
        objective_id: &str,
    ) -> IntelligenceResult<ObjectiveReport> {
        // Verify objective exists and fetch metadata
        let obj = self
            .db
            .get_objective(objective_id)
            .await?
            .ok_or_else(|| IntelligenceError::ObjectiveNotFound(objective_id.to_string()))?;

        // Aggregate stats (one round-trip)
        let stats = self.db.get_objective_stats(objective_id).await?;

        // All results for the objective (all statuses, for anomaly detection)
        let all_results = self.db.get_accepted_results_for_objective(objective_id).await?;

        // Also fetch ALL results (not just accepted) for collision/divergence detection.
        // We reuse list_tasks_for_objective + list_results_for_task to gather them.
        let all_tasks = self.db.list_tasks_for_objective(objective_id).await?;
        let mut full_results: Vec<ExperimentResultRow> = Vec::new();
        let mut all_verifications: Vec<VerificationRecordRow> = Vec::new();
        for task in &all_tasks {
            let task_results = self.db.list_results_for_task(&task.task_id).await?;
            for r in &task_results {
                let vrs = self.db.list_verifications_for_result(r.result_id).await?;
                all_verifications.extend(vrs);
            }
            full_results.extend(task_results);
        }

        // Miner contributions (from full result set)
        let miner_contributions = build_miner_contributions(&full_results);

        // High-confidence findings (confidence >= 0.7)
        let high_conf_findings = self
            .db
            .list_findings_with_confidence(objective_id, 0.7)
            .await?;
        let total_findings = self
            .db
            .list_findings_for_objective(objective_id)
            .await?
            .len() as u64;

        let high_confidence_findings: Vec<FindingSummary> = high_conf_findings
            .into_iter()
            .map(|f| FindingSummary {
                finding_id:   f.finding_id,
                finding_type: f.finding_type,
                summary:      f.summary,
                confidence:   f.confidence,
                found_at:     f.found_at,
            })
            .collect();

        // Anomaly detection
        let detector = AnomalyDetector::new(self.config.clone());
        let anomalies = detector.detect(&full_results, &all_verifications, &stats);

        let report = ObjectiveReport {
            schema_version: 1,
            objective_id:   obj.objective_id.clone(),
            challenge_id:   obj.challenge_id.clone(),
            slug:           obj.slug.clone(),
            track:          obj.track.clone(),
            algorithm_version: obj.algorithm_version.clone(),
            generated_at:   Utc::now(),

            total_tasks:     stats.total_tasks,
            available_tasks: stats.available_tasks,
            assigned_tasks:  stats.assigned_tasks,
            submitted_tasks: stats.submitted_tasks,
            accepted_tasks:  stats.accepted_tasks,
            completion_rate: stats.completion_rate,

            total_results:      stats.total_results,
            unique_miners:      stats.unique_miners,
            reproduced_count:   stats.reproduced_count,
            diverged_count:     stats.diverged_count,
            verifier_agreement: stats.verifier_agreement,

            miner_contributions,
            high_confidence_findings,
            total_findings,
            anomalies,
        };

        // Persist the report
        let body = serde_json::to_value(&report).map_err(|e| {
            IntelligenceError::Db(chain_forge_research_db::ResearchDbError::Other(
                format!("failed to serialise report: {e}"),
            ))
        })?;
        self.db
            .upsert_intelligence_report(NewIntelligenceReport {
                objective_id:   objective_id.to_string(),
                report_body:    body,
                schema_version: 1,
            })
            .await?;

        Ok(report)
    }

    // ── get_report ────────────────────────────────────────────────────────────

    /// Fetch the most recently persisted report without re-running analysis.
    pub async fn get_report(
        &self,
        objective_id: &str,
    ) -> IntelligenceResult<ObjectiveReport> {
        let row = self
            .db
            .get_intelligence_report(objective_id)
            .await?
            .ok_or_else(|| IntelligenceError::ReportNotFound(objective_id.to_string()))?;

        let report: ObjectiveReport =
            serde_json::from_value(row.report_body).map_err(|e| {
                IntelligenceError::Db(chain_forge_research_db::ResearchDbError::Other(
                    format!("failed to deserialise report: {e}"),
                ))
            })?;
        Ok(report)
    }

    // ── detect_anomalies ─────────────────────────────────────────────────────

    /// Run anomaly detection against current DB state without persisting a report.
    pub async fn detect_anomalies(
        &self,
        objective_id: &str,
    ) -> IntelligenceResult<Vec<crate::report::Anomaly>> {
        // Verify objective exists
        self.db
            .get_objective(objective_id)
            .await?
            .ok_or_else(|| IntelligenceError::ObjectiveNotFound(objective_id.to_string()))?;

        let stats = self.db.get_objective_stats(objective_id).await?;

        let all_tasks = self.db.list_tasks_for_objective(objective_id).await?;
        let mut full_results: Vec<ExperimentResultRow> = Vec::new();
        let mut all_verifications: Vec<VerificationRecordRow> = Vec::new();
        for task in &all_tasks {
            let task_results = self.db.list_results_for_task(&task.task_id).await?;
            for r in &task_results {
                let vrs = self.db.list_verifications_for_result(r.result_id).await?;
                all_verifications.extend(vrs);
            }
            full_results.extend(task_results);
        }

        let detector = AnomalyDetector::new(self.config.clone());
        Ok(detector.detect(&full_results, &all_verifications, &stats))
    }

    // ── list_submitted_tasks (delegation) ────────────────────────────────────

    pub async fn list_submitted_tasks(
        &self,
        objective_id: &str,
    ) -> IntelligenceResult<Vec<chain_forge_research_db::models::TaskRow>> {
        Ok(self.db.list_submitted_tasks(objective_id).await?)
    }
}
