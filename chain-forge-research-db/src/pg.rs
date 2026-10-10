//! PostgreSQL implementation of `ResearchDb`.
//!
//! Uses `sqlx` with a `PgPool` (connection pool).  Migrations are embedded
//! and run automatically on `PgResearchDb::connect()`.
//!
//! # Thread safety
//!
//! `PgPool` is internally `Arc`-wrapped and `Clone`; `PgResearchDb` is
//! `Send + Sync` and safe to share across async tasks as `Arc<PgResearchDb>`.

use async_trait::async_trait;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::{debug, info};
use uuid::Uuid;

use crate::db::{ResearchDb, TaskProvenance};
use crate::error::ResearchDbError;
use crate::models::*;

/// PostgreSQL-backed research persistence.
pub struct PgResearchDb {
    pool: PgPool,
}

impl PgResearchDb {
    /// Connect to PostgreSQL and run any pending migrations.
    ///
    /// `database_url` must be a valid `postgres://…` connection string.
    pub async fn connect(database_url: &str) -> Result<Self, ResearchDbError> {
        info!("connecting to research database");
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        info!("running research database migrations");
        sqlx::migrate!("./migrations").run(&pool).await?;
        info!("research database ready");

        Ok(Self { pool })
    }

    /// Expose the underlying pool (for tests or direct queries).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl ResearchDb for PgResearchDb {
    // ── objectives ──────────────────────────────────────────────────────────

    async fn insert_objective(&self, obj: NewObjective) -> Result<ObjectiveRow, ResearchDbError> {
        debug!(objective_id = %obj.objective_id, "inserting objective");
        let row = sqlx::query_as::<_, ObjectiveRow>(
            r#"
            INSERT INTO research_objectives
                (objective_id, challenge_id, slug, track, algorithm_version,
                 range_start, range_end, workload_class, verification_spec)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(&obj.objective_id)
        .bind(&obj.challenge_id)
        .bind(&obj.slug)
        .bind(&obj.track)
        .bind(&obj.algorithm_version)
        .bind(obj.range_start as i64)
        .bind(obj.range_end as i64)
        .bind(&obj.workload_class)
        .bind(&obj.verification_spec)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                ResearchDbError::Duplicate(format!("objective_id={}", obj.objective_id))
            } else {
                ResearchDbError::Sqlx(e)
            }
        })?;
        Ok(row)
    }

    async fn get_objective(&self, objective_id: &str) -> Result<Option<ObjectiveRow>, ResearchDbError> {
        let row = sqlx::query_as::<_, ObjectiveRow>(
            "SELECT * FROM research_objectives WHERE objective_id = $1",
        )
        .bind(objective_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list_objectives_for_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Vec<ObjectiveRow>, ResearchDbError> {
        let rows = sqlx::query_as::<_, ObjectiveRow>(
            "SELECT * FROM research_objectives WHERE challenge_id = $1 ORDER BY created_at",
        )
        .bind(challenge_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn update_objective_status(
        &self,
        objective_id: &str,
        status: &str,
    ) -> Result<(), ResearchDbError> {
        let affected = sqlx::query(
            "UPDATE research_objectives SET status = $1 WHERE objective_id = $2",
        )
        .bind(status)
        .bind(objective_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(ResearchDbError::NotFound(format!(
                "objective_id={objective_id}"
            )));
        }
        Ok(())
    }

    // ── tasks ───────────────────────────────────────────────────────────────

    async fn upsert_tasks(&self, tasks: Vec<NewTask>) -> Result<usize, ResearchDbError> {
        if tasks.is_empty() {
            return Ok(0);
        }

        let mut tx = self.pool.begin().await?;
        let mut inserted = 0usize;

        for t in &tasks {
            let affected = sqlx::query(
                r#"
                INSERT INTO research_tasks
                    (task_id, objective_id, range_start, range_end,
                     workload_class, input_seed)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (task_id) DO NOTHING
                "#,
            )
            .bind(&t.task_id)
            .bind(&t.objective_id)
            .bind(t.range_start as i64)
            .bind(t.range_end as i64)
            .bind(&t.workload_class)
            .bind(t.input_seed as i64)
            .execute(&mut *tx)
            .await?
            .rows_affected();

            inserted += affected as usize;
        }

        tx.commit().await?;
        debug!(inserted, "upsert_tasks complete");
        Ok(inserted)
    }

    async fn get_task(&self, task_id: &str) -> Result<Option<TaskRow>, ResearchDbError> {
        let row = sqlx::query_as::<_, TaskRow>(
            "SELECT * FROM research_tasks WHERE task_id = $1",
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list_tasks_for_objective(
        &self,
        objective_id: &str,
    ) -> Result<Vec<TaskRow>, ResearchDbError> {
        let rows = sqlx::query_as::<_, TaskRow>(
            "SELECT * FROM research_tasks WHERE objective_id = $1 ORDER BY range_start",
        )
        .bind(objective_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn list_tasks_by_status(
        &self,
        objective_id: &str,
        status: &str,
    ) -> Result<Vec<TaskRow>, ResearchDbError> {
        let rows = sqlx::query_as::<_, TaskRow>(
            "SELECT * FROM research_tasks WHERE objective_id = $1 AND status = $2 ORDER BY range_start",
        )
        .bind(objective_id)
        .bind(status)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn update_task_status(
        &self,
        task_id:            &str,
        status:             &str,
        assigned_to:        Option<&str>,
        settled_receipt_id: Option<&str>,
    ) -> Result<(), ResearchDbError> {
        let affected = sqlx::query(
            r#"
            UPDATE research_tasks
            SET status             = $1,
                assigned_to        = COALESCE($2, assigned_to),
                settled_receipt_id = COALESCE($3, settled_receipt_id)
            WHERE task_id = $4
            "#,
        )
        .bind(status)
        .bind(assigned_to)
        .bind(settled_receipt_id)
        .bind(task_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(ResearchDbError::NotFound(format!("task_id={task_id}")));
        }
        Ok(())
    }

    // ── experiment results ──────────────────────────────────────────────────

    async fn insert_result(
        &self,
        r: NewExperimentResult,
    ) -> Result<ExperimentResultRow, ResearchDbError> {
        debug!(task_id = %r.task_id, miner_id = %r.miner_id, "inserting experiment result");
        let row = sqlx::query_as::<_, ExperimentResultRow>(
            r#"
            INSERT INTO experiment_results
                (task_id, receipt_id, miner_id, content_hash,
                 result_payload, algorithm_version, workload_version, seal_nonce)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(&r.task_id)
        .bind(&r.receipt_id)
        .bind(&r.miner_id)
        .bind(&r.content_hash)
        .bind(&r.result_payload)
        .bind(&r.algorithm_version)
        .bind(&r.workload_version)
        .bind(r.seal_nonce.map(|n| n as i64))
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                ResearchDbError::DuplicateResult {
                    task_id:      r.task_id.clone(),
                    miner_id:     r.miner_id.clone(),
                    content_hash: r.content_hash.clone(),
                }
            } else {
                ResearchDbError::Sqlx(e)
            }
        })?;
        Ok(row)
    }

    async fn get_result(&self, result_id: Uuid) -> Result<Option<ExperimentResultRow>, ResearchDbError> {
        let row = sqlx::query_as::<_, ExperimentResultRow>(
            "SELECT * FROM experiment_results WHERE result_id = $1",
        )
        .bind(result_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list_results_for_task(
        &self,
        task_id: &str,
    ) -> Result<Vec<ExperimentResultRow>, ResearchDbError> {
        let rows = sqlx::query_as::<_, ExperimentResultRow>(
            "SELECT * FROM experiment_results WHERE task_id = $1 ORDER BY submitted_at",
        )
        .bind(task_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn list_results_for_miner(
        &self,
        miner_id: &str,
    ) -> Result<Vec<ExperimentResultRow>, ResearchDbError> {
        let rows = sqlx::query_as::<_, ExperimentResultRow>(
            "SELECT * FROM experiment_results WHERE miner_id = $1 ORDER BY submitted_at",
        )
        .bind(miner_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn update_result_status(
        &self,
        result_id: Uuid,
        status: &str,
    ) -> Result<(), ResearchDbError> {
        let affected = sqlx::query(
            "UPDATE experiment_results SET result_status = $1 WHERE result_id = $2",
        )
        .bind(status)
        .bind(result_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(ResearchDbError::NotFound(format!("result_id={result_id}")));
        }
        Ok(())
    }

    async fn result_exists(
        &self,
        task_id:      &str,
        miner_id:     &str,
        content_hash: &str,
    ) -> Result<bool, ResearchDbError> {
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM experiment_results
                WHERE task_id = $1 AND miner_id = $2 AND content_hash = $3
            )
            "#,
        )
        .bind(task_id)
        .bind(miner_id)
        .bind(content_hash)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists)
    }

    // ── verification records ────────────────────────────────────────────────

    async fn insert_verification(
        &self,
        v: NewVerificationRecord,
    ) -> Result<VerificationRecordRow, ResearchDbError> {
        // Enforce self-verification ban at the application layer
        // (the DB constraint also catches it, but we provide a better error here).
        let original = self
            .get_result(v.result_id)
            .await?
            .ok_or_else(|| ResearchDbError::NotFound(format!("result_id={}", v.result_id)))?;

        if original.miner_id == v.verifier_id {
            return Err(ResearchDbError::SelfVerification(v.verifier_id.clone()));
        }

        let row = sqlx::query_as::<_, VerificationRecordRow>(
            r#"
            INSERT INTO verification_records
                (result_id, task_id, verifier_id, outcome,
                 verifier_content_hash, notes, verifier_receipt_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(v.result_id)
        .bind(&v.task_id)
        .bind(&v.verifier_id)
        .bind(&v.outcome)
        .bind(&v.verifier_content_hash)
        .bind(&v.notes)
        .bind(&v.verifier_receipt_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list_verifications_for_result(
        &self,
        result_id: Uuid,
    ) -> Result<Vec<VerificationRecordRow>, ResearchDbError> {
        let rows = sqlx::query_as::<_, VerificationRecordRow>(
            "SELECT * FROM verification_records WHERE result_id = $1 ORDER BY verified_at",
        )
        .bind(result_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // ── research findings ───────────────────────────────────────────────────

    async fn insert_finding(
        &self,
        f: NewResearchFinding,
    ) -> Result<ResearchFindingRow, ResearchDbError> {
        let row = sqlx::query_as::<_, ResearchFindingRow>(
            r#"
            INSERT INTO research_findings
                (objective_id, task_id, finding_type, summary,
                 confidence, evidence_refs)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(&f.objective_id)
        .bind(&f.task_id)
        .bind(&f.finding_type)
        .bind(&f.summary)
        .bind(f.confidence)
        .bind(&f.evidence_refs)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list_findings_for_objective(
        &self,
        objective_id: &str,
    ) -> Result<Vec<ResearchFindingRow>, ResearchDbError> {
        let rows = sqlx::query_as::<_, ResearchFindingRow>(
            "SELECT * FROM research_findings WHERE objective_id = $1 ORDER BY found_at DESC",
        )
        .bind(objective_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // ── research artifacts ──────────────────────────────────────────────────

    async fn insert_artifact(
        &self,
        a: NewResearchArtifact,
    ) -> Result<ResearchArtifactRow, ResearchDbError> {
        let row = sqlx::query_as::<_, ResearchArtifactRow>(
            r#"
            INSERT INTO research_artifacts
                (result_id, finding_id, artifact_type, label,
                 content_hash, size_bytes, storage_uri, supersedes_artifact_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(a.result_id)
        .bind(a.finding_id)
        .bind(&a.artifact_type)
        .bind(&a.label)
        .bind(&a.content_hash)
        .bind(a.size_bytes as i64)
        .bind(&a.storage_uri)
        .bind(a.supersedes_artifact_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    async fn get_artifact(&self, artifact_id: Uuid) -> Result<Option<ResearchArtifactRow>, ResearchDbError> {
        let row = sqlx::query_as::<_, ResearchArtifactRow>(
            "SELECT * FROM research_artifacts WHERE artifact_id = $1",
        )
        .bind(artifact_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    // ── provenance ──────────────────────────────────────────────────────────

    async fn task_provenance(&self, task_id: &str) -> Result<TaskProvenance, ResearchDbError> {
        let task = self
            .get_task(task_id)
            .await?
            .ok_or_else(|| ResearchDbError::NotFound(format!("task_id={task_id}")))?;

        let objective = self
            .get_objective(&task.objective_id)
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

        let findings = sqlx::query_as::<_, ResearchFindingRow>(
            "SELECT * FROM research_findings WHERE task_id = $1 ORDER BY found_at DESC",
        )
        .bind(task_id)
        .fetch_all(&self.pool)
        .await?;

        let mut artifacts = Vec::new();
        for r in &results {
            let mut a = sqlx::query_as::<_, ResearchArtifactRow>(
                "SELECT * FROM research_artifacts WHERE result_id = $1 ORDER BY created_at",
            )
            .bind(r.result_id)
            .fetch_all(&self.pool)
            .await?;
            artifacts.append(&mut a);
        }

        Ok(TaskProvenance {
            objective,
            task,
            results,
            verifications,
            findings,
            artifacts,
        })
    }

    // ── recovery ────────────────────────────────────────────────────────────

    async fn objectives_with_pending_work(&self) -> Result<Vec<String>, ResearchDbError> {
        let ids: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT objective_id
            FROM research_tasks
            WHERE status IN ('available', 'assigned')
            ORDER BY objective_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(ids)
    }

    async fn count_accepted_tasks(&self, objective_id: &str) -> Result<u64, ResearchDbError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM research_tasks WHERE objective_id = $1 AND status = 'accepted'",
        )
        .bind(objective_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count as u64)
    }

    async fn count_tasks(&self, objective_id: &str) -> Result<u64, ResearchDbError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM research_tasks WHERE objective_id = $1",
        )
        .bind(objective_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count as u64)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn is_unique_violation(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = e {
        // PostgreSQL unique-violation SQLSTATE code = 23505
        return db_err.code().map(|c| c == "23505").unwrap_or(false);
    }
    false
}
