//! In-memory `ResearchDb` implementation for unit tests.
//!
//! Uses the exact same `ResearchDb` trait as `PgResearchDb`, so all
//! application logic tests run without a live PostgreSQL instance.
//!
//! This is NOT for production use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::{ResearchDb, TaskProvenance};
use crate::error::ResearchDbError;
use crate::models::*;

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct MemState {
    objectives:             HashMap<String, ObjectiveRow>,
    tasks:                  HashMap<String, TaskRow>,
    results:                HashMap<Uuid, ExperimentResultRow>,
    verifications:          HashMap<Uuid, VerificationRecordRow>,
    findings:               HashMap<Uuid, ResearchFindingRow>,
    artifacts:              HashMap<Uuid, ResearchArtifactRow>,
    intelligence_reports:   HashMap<Uuid, IntelligenceReportRow>,
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
            objective_id:        obj.objective_id.clone(),
            challenge_id:        obj.challenge_id,
            slug:                obj.slug,
            track:               obj.track,
            algorithm_version:   obj.algorithm_version,
            range_start:         obj.range_start as i64,
            range_end:           obj.range_end as i64,
            workload_class:      obj.workload_class,
            status:              "active".to_string(),
            verification_spec:   obj.verification_spec,
            verification_quorum: obj.verification_quorum as i32,
            created_at:          now(),
            updated_at:          now(),
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
                lease_expires_at:   None,
                lease_generation:   0,
                attempt_count:      0,
                phase:              t.phase as i32,
                parent_hash:        t.parent_hash,
                phase1_miner_id:    t.phase1_miner_id,
                task_kind:          t.task_kind,
                avl_seed_index:     t.avl_seed_index.map(|v| v as i32),
                avl_bit_index:      t.avl_bit_index.map(|v| v as i32),
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
            avl_original_hash: r.avl_original_hash,
            avl_flipped_hash:  r.avl_flipped_hash,
            avl_xor_diff:      r.avl_xor_diff,
            avl_hamming_dist:  r.avl_hamming_dist.map(|v| v as i32),
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

    // ── scheduling (Change Set E) ────────────────────────────────────────────

    async fn assign_task(
        &self,
        objective_id:     &str,
        workload_class:   &str,
        miner_id:         &str,
        lease_expires_at: DateTime<Utc>,
        exclude_miner:    Option<&str>,
    ) -> Result<Option<TaskRow>, ResearchDbError> {
        let mut s = self.state.lock().unwrap();

        // Find the available task with the smallest range_start.
        // Skip tasks whose phase1_miner_id matches exclude_miner (two-phase rule).
        let task_id = s
            .tasks
            .values()
            .filter(|t| {
                t.objective_id   == objective_id
                    && t.workload_class == workload_class
                    && t.status         == "available"
                    && exclude_miner.map_or(true, |em| {
                        t.phase1_miner_id.as_deref() != Some(em)
                    })
            })
            .min_by_key(|t| t.range_start)
            .map(|t| t.task_id.clone());

        let task_id = match task_id {
            Some(id) => id,
            None     => return Ok(None),
        };

        let row = s.tasks.get_mut(&task_id).unwrap();
        row.status           = "assigned".to_string();
        row.assigned_to      = Some(miner_id.to_string());
        row.lease_expires_at = Some(lease_expires_at);
        row.lease_generation += 1;
        row.attempt_count    += 1;
        row.updated_at        = now();

        Ok(Some(row.clone()))
    }

    async fn submit_task_result(
        &self,
        task_id:  &str,
        miner_id: &str,
    ) -> Result<(), ResearchDbError> {
        let mut s = self.state.lock().unwrap();
        let row = s
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ResearchDbError::NotFound(format!("task_id={task_id}")))?;

        if row.status != "assigned" || row.assigned_to.as_deref() != Some(miner_id) {
            return Err(ResearchDbError::NotFound(format!(
                "task_id={task_id} assigned_to={miner_id} status=assigned"
            )));
        }

        row.status           = "submitted".to_string();
        row.lease_expires_at = None;
        // assigned_to intentionally kept so provenance is preserved.
        row.updated_at       = now();
        Ok(())
    }

    async fn expire_stale_leases(
        &self,
        now_ts: DateTime<Utc>,
    ) -> Result<u64, ResearchDbError> {
        let mut s = self.state.lock().unwrap();
        let mut count = 0u64;

        for row in s.tasks.values_mut() {
            if row.status != "assigned" {
                continue;
            }
            let expired = row
                .lease_expires_at
                .map(|exp| exp < now_ts)
                .unwrap_or(false);
            if expired {
                row.status           = "available".to_string();
                row.assigned_to      = None;
                row.lease_expires_at = None;
                // lease_generation is intentionally NOT reset.
                row.updated_at       = now();
                count += 1;
            }
        }

        Ok(count)
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

    // ── verification (Change Set F) ──────────────────────────────────────────

    async fn get_verification_quorum(
        &self,
        objective_id: &str,
    ) -> Result<u32, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let quorum = s
            .objectives
            .get(objective_id)
            .ok_or_else(|| ResearchDbError::NotFound(format!("objective_id={objective_id}")))?
            .verification_quorum;
        Ok(quorum as u32)
    }

    async fn count_reproduced_verifications(
        &self,
        result_id: Uuid,
    ) -> Result<u64, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let count = s
            .verifications
            .values()
            .filter(|v| v.result_id == result_id && v.outcome == "reproduced")
            .count();
        Ok(count as u64)
    }

    async fn accept_task(
        &self,
        task_id:   &str,
        result_id: Uuid,
    ) -> Result<(), ResearchDbError> {
        let mut s = self.state.lock().unwrap();

        // Transition task: submitted → accepted
        let task = s
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ResearchDbError::NotFound(format!("task_id={task_id}")))?;
        if task.status != "submitted" {
            return Err(ResearchDbError::NotFound(format!(
                "task_id={task_id} is not in 'submitted' status (got '{}')",
                task.status
            )));
        }
        task.status     = "accepted".to_string();
        task.updated_at = now();

        // Transition result: submitted → accepted
        let result = s
            .results
            .get_mut(&result_id)
            .ok_or_else(|| ResearchDbError::NotFound(format!("result_id={result_id}")))?;
        result.result_status = "accepted".to_string();
        result.updated_at    = now();

        Ok(())
    }

    async fn list_submitted_tasks(
        &self,
        objective_id: &str,
    ) -> Result<Vec<TaskRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut rows: Vec<_> = s
            .tasks
            .values()
            .filter(|t| t.objective_id == objective_id && t.status == "submitted")
            .cloned()
            .collect();
        rows.sort_by_key(|t| t.updated_at);
        Ok(rows)
    }

    // ── intelligence (Change Set G) ──────────────────────────────────────────

    async fn get_accepted_results_for_objective(
        &self,
        objective_id: &str,
    ) -> Result<Vec<ExperimentResultRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        // Collect task_ids that belong to this objective
        let task_ids: std::collections::HashSet<&str> = s
            .tasks
            .values()
            .filter(|t| t.objective_id == objective_id)
            .map(|t| t.task_id.as_str())
            .collect();

        let mut rows: Vec<_> = s
            .results
            .values()
            .filter(|r| {
                task_ids.contains(r.task_id.as_str()) && r.result_status == "accepted"
            })
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.submitted_at);
        Ok(rows)
    }

    async fn get_objective_stats(
        &self,
        objective_id: &str,
    ) -> Result<ObjectiveStats, ResearchDbError> {
        let s = self.state.lock().unwrap();

        // Verify the objective exists
        if !s.objectives.contains_key(objective_id) {
            return Err(ResearchDbError::NotFound(format!(
                "objective_id={}",
                objective_id
            )));
        }

        // Task counts by status
        let tasks_for_obj: Vec<&TaskRow> = s
            .tasks
            .values()
            .filter(|t| t.objective_id == objective_id)
            .collect();

        let total_tasks    = tasks_for_obj.len() as u64;
        let available_tasks = tasks_for_obj.iter().filter(|t| t.status == "available").count() as u64;
        let assigned_tasks  = tasks_for_obj.iter().filter(|t| t.status == "assigned").count()  as u64;
        let submitted_tasks = tasks_for_obj.iter().filter(|t| t.status == "submitted").count() as u64;
        let accepted_tasks  = tasks_for_obj.iter().filter(|t| t.status == "accepted").count()  as u64;

        // Collect task_ids for result/verification queries
        let task_ids: std::collections::HashSet<&str> = tasks_for_obj
            .iter()
            .map(|t| t.task_id.as_str())
            .collect();

        // Result stats
        let results_for_obj: Vec<&ExperimentResultRow> = s
            .results
            .values()
            .filter(|r| task_ids.contains(r.task_id.as_str()))
            .collect();

        let total_results  = results_for_obj.len() as u64;
        let unique_miners  = results_for_obj
            .iter()
            .map(|r| r.miner_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len() as u64;

        let result_ids: std::collections::HashSet<Uuid> = results_for_obj
            .iter()
            .map(|r| r.result_id)
            .collect();

        // Verification stats
        let verifications_for_obj: Vec<&VerificationRecordRow> = s
            .verifications
            .values()
            .filter(|v| result_ids.contains(&v.result_id))
            .collect();

        let reproduced_count = verifications_for_obj.iter().filter(|v| v.outcome == "reproduced").count() as u64;
        let diverged_count   = verifications_for_obj.iter().filter(|v| v.outcome == "diverged").count()   as u64;

        let completion_rate = if total_tasks == 0 {
            None
        } else {
            Some(accepted_tasks as f64 / total_tasks as f64)
        };

        // verifier_agreement: per result, fraction of verifications that are
        // 'reproduced'; average across results that have >= 1 verification.
        let mut agreement_sum   = 0.0_f64;
        let mut agreement_count = 0_u64;
        for result in &results_for_obj {
            let v_for_result: Vec<_> = verifications_for_obj
                .iter()
                .filter(|v| v.result_id == result.result_id)
                .collect();
            if !v_for_result.is_empty() {
                let reproduced = v_for_result.iter().filter(|v| v.outcome == "reproduced").count();
                agreement_sum   += reproduced as f64 / v_for_result.len() as f64;
                agreement_count += 1;
            }
        }
        let verifier_agreement = if agreement_count == 0 {
            None
        } else {
            Some(agreement_sum / agreement_count as f64)
        };

        Ok(ObjectiveStats {
            objective_id:    objective_id.to_string(),
            total_tasks,
            available_tasks,
            assigned_tasks,
            submitted_tasks,
            accepted_tasks,
            unique_miners,
            total_results,
            reproduced_count,
            diverged_count,
            completion_rate,
            verifier_agreement,
        })
    }

    async fn list_findings_with_confidence(
        &self,
        objective_id:   &str,
        min_confidence: f64,
    ) -> Result<Vec<ResearchFindingRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let mut rows: Vec<_> = s
            .findings
            .values()
            .filter(|f| {
                f.objective_id == objective_id
                    && f.confidence.map_or(false, |c| c >= min_confidence)
            })
            .cloned()
            .collect();
        // Order by confidence DESC, then found_at DESC
        rows.sort_by(|a, b| {
            let ca = a.confidence.unwrap_or(0.0);
            let cb = b.confidence.unwrap_or(0.0);
            cb.partial_cmp(&ca)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.found_at.cmp(&a.found_at))
        });
        Ok(rows)
    }

    async fn upsert_intelligence_report(
        &self,
        report: NewIntelligenceReport,
    ) -> Result<IntelligenceReportRow, ResearchDbError> {
        let mut s = self.state.lock().unwrap();
        // Find existing report for this objective if any
        let existing_id = s
            .intelligence_reports
            .values()
            .find(|r| r.objective_id == report.objective_id)
            .map(|r| r.report_id);

        let row = IntelligenceReportRow {
            report_id:      existing_id.unwrap_or_else(Uuid::new_v4),
            objective_id:   report.objective_id.clone(),
            report_body:    report.report_body,
            generated_at:   now(),
            schema_version: report.schema_version,
        };
        s.intelligence_reports.insert(row.report_id, row.clone());
        Ok(row)
    }

    async fn get_intelligence_report(
        &self,
        objective_id: &str,
    ) -> Result<Option<IntelligenceReportRow>, ResearchDbError> {
        let s = self.state.lock().unwrap();
        let row = s
            .intelligence_reports
            .values()
            .find(|r| r.objective_id == objective_id)
            .cloned();
        Ok(row)
    }

    // ── two-phase cascade (Change Set J) ────────────────────────────────────

    async fn spawn_phase2_task(
        &self,
        parent_task_id:  &str,
        parent_hash:     &str,
        phase1_miner_id: &str,
        range_per_task:  u64,
    ) -> Result<TaskRow, ResearchDbError> {
        let (objective_id, workload_class) = {
            let s = self.state.lock().unwrap();
            let parent = s
                .tasks
                .get(parent_task_id)
                .ok_or_else(|| ResearchDbError::NotFound(format!("parent_task_id={parent_task_id}")))?;
            (parent.objective_id.clone(), parent.workload_class.clone())
        };

        // Idempotency: if a phase-2 task already exists for this parent, return it.
        {
            let s = self.state.lock().unwrap();
            if let Some(existing) = s.tasks.values().find(|t| {
                t.objective_id == objective_id
                    && t.phase == 2
                    && t.parent_hash.as_deref() == Some(parent_hash)
            }) {
                return Ok(existing.clone());
            }
        }

        // Derive a deterministic i64 seed from the parent hash bytes.
        // Take the first 8 bytes of the hash (decoded from hex) and read as LE i64.
        let hash_bytes = hex::decode(&parent_hash[..parent_hash.len().min(16)])
            .unwrap_or_else(|_| vec![0u8; 8]);
        let mut seed_bytes = [0u8; 8];
        let copy_len = hash_bytes.len().min(8);
        seed_bytes[..copy_len].copy_from_slice(&hash_bytes[..copy_len]);
        let input_seed = i64::from_le_bytes(seed_bytes);

        let task_id = format!("phase2-{parent_task_id}");

        let row = TaskRow {
            task_id:            task_id.clone(),
            objective_id,
            range_start:        0,
            range_end:          range_per_task as i64,
            workload_class,
            input_seed,
            status:             "available".to_string(),
            assigned_to:        None,
            settled_receipt_id: None,
            lease_expires_at:   None,
            lease_generation:   0,
            attempt_count:      0,
            phase:              2,
            parent_hash:        Some(parent_hash.to_string()),
            phase1_miner_id:    Some(phase1_miner_id.to_string()),
            task_kind:          "pocd_phase2".to_string(),
            avl_seed_index:     None,
            avl_bit_index:      None,
            created_at:         now(),
            updated_at:         now(),
        };

        let mut s = self.state.lock().unwrap();
        s.tasks.insert(task_id, row.clone());
        Ok(row)
    }
}

