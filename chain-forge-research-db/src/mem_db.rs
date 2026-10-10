//! In-memory `ResearchDb` implementation for unit tests.
//!
//! Uses the exact same `ResearchDb` trait as `PgResearchDb`, so all
//! application logic tests run without a live PostgreSQL instance.
//!
//! This is NOT for production use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use crate::db::{ResearchDb, TaskProvenance};
use crate::error::ResearchDbError;
use crate::models::*;

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct MemState {
    objectives:     HashMap<String, ObjectiveRow>,
    tasks:          HashMap<String, TaskRow>,
    results:        HashMap<Uuid, ExperimentResultRow>,
    verifications:  HashMap<Uuid, VerificationRecordRow>,
    findings:       HashMap<Uuid, ResearchFindingRow>,
    artifacts:      HashMap<Uuid, ResearchArtifactRow>,
}

/// In-memory test double for `ResearchDb`.
#[derive(Clone, Default)]
pub struct MemResearchDb {
    state: Arc<Mutex<MemState>>,
}

impl MemResearchDb {
    pub fn new() -> Self {
        Self::default()
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn now() -> chrono::DateTime<Utc> {
    Utc::now()
}

// ── impl ──────────────────────────────────────────────────────────────────────

#[async_trait]
impl ResearchDb for MemResearchDb {
    async fn insert_objective(&self, obj: NewObjective) -> Result<ObjectiveRow, ResearchDbError> {
        let mut s = self.state.lock().unwrap();
        if s.objectives.contains_key(&obj.objective_id) {
            return Err(ResearchDbError::Duplicate(format!(
                "objective_id={}",
                obj.objective_id
            )));
        }
        let row = ObjectiveRow {
            objective_id:      obj.objective_id.clone(),
            challenge_id:      obj.challenge_id,
            slug:              obj.slug,
            track:             obj.track,
            algorithm_version: obj.algorithm_version,
            range_start:       obj.range_start as i64,
            range_end:         obj.range_end as i64,
            workload_class:    obj.workload_class,
            status:            "active".to_string(),
            verification_spec: obj.verification_spec,
            created_at:        now(),
            updated_at:        now(),
        };
        s.objectives.insert(obj.objective_id, row.clone());
        Ok(row)
    }

    async fn get_objective(&self, objective_id: &str) -> Result<Option<ObjectiveRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        Ok(s.objectives.get(objective_id).cloned())
    }

    async fn list_objectives_for_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Vec<ObjectiveRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut rows: Vec<_> = s
            .objectives
            .values()
            .filter(|o| o.challenge_id == challenge_id)
            .cloned()
            .collect();
        rows.sort_by_key(|o| o.created_at);
        Ok(rows)
    }

    async fn update_objective_status(
        &self,
        objective_id: &str,
        status: &str,
    ) -> Result<(), ResearchDbError> {
        let mut s = self.state.lock().unwrap();
        let row = s.objectives.get_mut(objective_id).ok_or_else(|| {
            ResearchDbError::NotFound(format!("objective_id={objective_id}"))
        })?;
        row.status = status.to_string();
        row.updated_at = now();
        Ok(())
    }

    async fn upsert_tasks(&self, tasks: Vec<NewTask>) -> Result<usize, ResearchDbError> {
        let mut s = self.state.lock().unwrap();
        let mut inserted = 0usize;
        for t in tasks {
            if s.tasks.contains_key(&t.task_id) {
                continue; // idempotent skip
            }
            let row = TaskRow {
                task_id:            t.task_id.clone(),
                objective_id:       t.objective_id,
                range_start:        t.range_start as i64,
                range_end:          t.range_end as i64,
                workload_class:     t.workload_class,
                input_seed:         t.input_seed as i64,
                status:             "available".to_string(),
                assigned_to:        None,
                settled_receipt_id: None,
                created_at:         now(),
                updated_at:         now(),
            };
            s.tasks.insert(t.task_id, row);
            inserted += 1;
        }
        Ok(inserted)
    }

    async fn get_task(&self, task_id: &str) -> Result<Option<TaskRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        Ok(s.tasks.get(task_id).cloned())
    }

    async fn list_tasks_for_objective(
        &self,
        objective_id: &str,
    ) -> Result<Vec<TaskRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut rows: Vec<_> = s
            .tasks
            .values()
            .filter(|t| t.objective_id == objective_id)
            .cloned()
            .collect();
        rows.sort_by_key(|t| t.range_start);
        Ok(rows)
    }

    async fn list_tasks_by_status(
        &self,
        objective_id: &str,
        status: &str,
    ) -> Result<Vec<TaskRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut rows: Vec<_> = s
            .tasks
            .values()
            .filter(|t| t.objective_id == objective_id && t.status == status)
            .cloned()
            .collect();
        rows.sort_by_key(|t| t.range_start);
        Ok(rows)
    }

    async fn update_task_status(
        &self,
        task_id:            &str,
        status:             &str,
        assigned_to:        Option<&str>,
        settled_receipt_id: Option<&str>,
    ) -> Result<(), ResearchDbError> {
        let mut s = self.state.lock().unwrap();
        let row = s
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ResearchDbError::NotFound(format!("task_id={task_id}")))?;
        row.status = status.to_string();
        if let Some(a) = assigned_to {
            row.assigned_to = Some(a.to_string());
        }
        if let Some(r) = settled_receipt_id {
            row.settled_receipt_id = Some(r.to_string());
        }
        row.updated_at = now();
        Ok(())
    }

    async fn insert_result(
        &self,
        r: NewExperimentResult,
    ) -> Result<ExperimentResultRow, ResearchDbError> {
        let mut s = self.state.lock().unwrap();
        // Dedup check
        let exists = s.results.values().any(|row| {
            row.task_id      == r.task_id
                && row.miner_id  == r.miner_id
                && row.content_hash == r.content_hash
        });
        if exists {
            return Err(ResearchDbError::DuplicateResult {
                task_id:      r.task_id,
                miner_id:     r.miner_id,
                content_hash: r.content_hash,
            });
        }
        let id = Uuid::new_v4();
        let row = ExperimentResultRow {
            result_id:         id,
            task_id:           r.task_id,
            receipt_id:        r.receipt_id,
            miner_id:          r.miner_id,
            content_hash:      r.content_hash,
            result_status:     "submitted".to_string(),
            result_payload:    r.result_payload,
            algorithm_version: r.algorithm_version,
            workload_version:  r.workload_version,
            seal_nonce:        r.seal_nonce.map(|n| n as i64),
            submitted_at:      now(),
            updated_at:        now(),
        };
        s.results.insert(id, row.clone());
        Ok(row)
    }

    async fn get_result(&self, result_id: Uuid) -> Result<Option<ExperimentResultRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        Ok(s.results.get(&result_id).cloned())
    }

    async fn list_results_for_task(
        &self,
        task_id: &str,
    ) -> Result<Vec<ExperimentResultRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut rows: Vec<_> = s
            .results
            .values()
            .filter(|r| r.task_id == task_id)
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.submitted_at);
        Ok(rows)
    }

    async fn list_results_for_miner(
        &self,
        miner_id: &str,
    ) -> Result<Vec<ExperimentResultRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut rows: Vec<_> = s
            .results
            .values()
            .filter(|r| r.miner_id == miner_id)
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.submitted_at);
        Ok(rows)
    }

    async fn update_result_status(
        &self,
        result_id: Uuid,
        status: &str,
    ) -> Result<(), ResearchDbError> {
        let mut s = self.state.lock().unwrap();
        let row = s
            .results
            .get_mut(&result_id)
            .ok_or_else(|| ResearchDbError::NotFound(format!("result_id={result_id}")))?;
        row.result_status = status.to_string();
        row.updated_at = now();
        Ok(())
    }

    async fn result_exists(
        &self,
        task_id:      &str,
        miner_id:     &str,
        content_hash: &str,
    ) -> Result<bool, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let found = s.results.values().any(|r| {
            r.task_id == task_id && r.miner_id == miner_id && r.content_hash == content_hash
        });
        Ok(found)
    }

    async fn insert_verification(
        &self,
        v: NewVerificationRecord,
    ) -> Result<VerificationRecordRow, ResearchDbError> {
        // Self-verification check
        let original_miner = {
            let s = self.state.lock().unwrap();
            s.results
                .get(&v.result_id)
                .ok_or_else(|| {
                    ResearchDbError::NotFound(format!("result_id={}", v.result_id))
                })?
                .miner_id
                .clone()
        };
        if original_miner == v.verifier_id {
            return Err(ResearchDbError::SelfVerification(v.verifier_id.clone()));
        }

        let id = Uuid::new_v4();
        let row = VerificationRecordRow {
            verification_id:       id,
            result_id:             v.result_id,
            task_id:               v.task_id,
            verifier_id:           v.verifier_id,
            outcome:               v.outcome,
            verifier_content_hash: v.verifier_content_hash,
            notes:                 v.notes,
            verifier_receipt_id:   v.verifier_receipt_id,
            verified_at:           now(),
        };
        let mut s = self.state.lock().unwrap();
        s.verifications.insert(id, row.clone());
        Ok(row)
    }

    async fn list_verifications_for_result(
        &self,
        result_id: Uuid,
    ) -> Result<Vec<VerificationRecordRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut rows: Vec<_> = s
            .verifications
            .values()
            .filter(|v| v.result_id == result_id)
            .cloned()
            .collect();
        rows.sort_by_key(|v| v.verified_at);
        Ok(rows)
    }

    async fn insert_finding(
        &self,
        f: NewResearchFinding,
    ) -> Result<ResearchFindingRow, ResearchDbError> {
        let id = Uuid::new_v4();
        let row = ResearchFindingRow {
            finding_id:           id,
            objective_id:         f.objective_id,
            task_id:              f.task_id,
            finding_type:         f.finding_type,
            summary:              f.summary,
            confidence:           f.confidence,
            evidence_refs:        f.evidence_refs,
            applied_to_objective: false,
            found_at:             now(),
            updated_at:           now(),
        };
        let mut s = self.state.lock().unwrap();
        s.findings.insert(id, row.clone());
        Ok(row)
    }

    async fn list_findings_for_objective(
        &self,
        objective_id: &str,
    ) -> Result<Vec<ResearchFindingRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut rows: Vec<_> = s
            .findings
            .values()
            .filter(|f| f.objective_id == objective_id)
            .cloned()
            .collect();
        rows.sort_by_key(|f| std::cmp::Reverse(f.found_at));
        Ok(rows)
    }

    async fn insert_artifact(
        &self,
        a: NewResearchArtifact,
    ) -> Result<ResearchArtifactRow, ResearchDbError> {
        let id = Uuid::new_v4();
        let row = ResearchArtifactRow {
            artifact_id:            id,
            result_id:              a.result_id,
            finding_id:             a.finding_id,
            artifact_type:          a.artifact_type,
            label:                  a.label,
            content_hash:           a.content_hash,
            size_bytes:             a.size_bytes as i64,
            storage_uri:            a.storage_uri,
            supersedes_artifact_id: a.supersedes_artifact_id,
            created_at:             now(),
        };
        let mut s = self.state.lock().unwrap();
        s.artifacts.insert(id, row.clone());
        Ok(row)
    }

    async fn get_artifact(&self, artifact_id: Uuid) -> Result<Option<ResearchArtifactRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        Ok(s.artifacts.get(&artifact_id).cloned())
    }

    async fn task_provenance(&self, task_id: &str) -> Result<TaskProvenance, ResearchDbError> {
        let task = self
            .get_task(task_id)
            .await?
            .ok_or_else(|| ResearchDbError::NotFound(format!("task_id={task_id}")))?;

        let objective = self
            .get_objective(&task.objective_id.clone())
            .await?
            .ok_or_else(|| {
                ResearchDbError::NotFound(format!(
                    "objective_id={} (parent of task {})",
                    task.objective_id, task_id
                ))
            })?;

        let results = self.list_results_for_task(task_id).await?;

        let mut verifications = Vec::new();
        for r in &results {
            let mut v = self.list_verifications_for_result(r.result_id).await?;
            verifications.append(&mut v);
        }

        let findings = {
            let s = self.state.lock().unwrap();
            let mut rows: Vec<_> = s
                .findings
                .values()
                .filter(|f| f.task_id.as_deref() == Some(task_id))
                .cloned()
                .collect();
            rows.sort_by_key(|f| std::cmp::Reverse(f.found_at));
            rows
        };

        let artifacts = {
            let s = self.state.lock().unwrap();
            results
                .iter()
                .flat_map(|r| {
                    s.artifacts
                        .values()
                        .filter(|a| a.result_id == Some(r.result_id))
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .collect()
        };

        Ok(TaskProvenance {
            objective,
            task,
            results,
            verifications,
            findings,
            artifacts,
        })
    }

    async fn objectives_with_pending_work(&self) -> Result<Vec<String>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut ids: Vec<String> = s
            .tasks
            .values()
            .filter(|t| t.status == "available" || t.status == "assigned")
            .map(|t| t.objective_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        ids.sort();
        Ok(ids)
    }

    async fn count_accepted_tasks(&self, objective_id: &str) -> Result<u64, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let count = s
            .tasks
            .values()
            .filter(|t| t.objective_id == objective_id && t.status == "accepted")
            .count();
        Ok(count as u64)
    }

    async fn count_tasks(&self, objective_id: &str) -> Result<u64, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let count = s
            .tasks
            .values()
            .filter(|t| t.objective_id == objective_id)
            .count();
        Ok(count as u64)
    }
}

