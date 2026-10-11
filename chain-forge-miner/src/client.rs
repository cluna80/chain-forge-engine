//! HTTP client for the QCB scheduler API.

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::MinerError;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A task assignment returned by the scheduler.
#[derive(Debug, Deserialize)]
pub struct TaskAssignment {
    pub task_id:          String,
    pub objective_id:     String,
    pub range_start:      i64,
    pub range_end:        i64,
    pub workload_class:   String,
    pub input_seed:       i64,
    pub lease_expires_at: DateTime<Utc>,
    pub lease_generation: i64,
}

/// The result payload sent to the scheduler.
#[derive(Debug, Serialize)]
pub struct NewResult {
    pub task_id:           String,
    pub miner_id:          String,
    pub content_hash:      String,
    pub result_payload:    Value,
    pub algorithm_version: String,
    pub workload_version:  String,
    pub seal_nonce:        Option<u64>,
}

/// Body for POST /scheduler/tasks/:id/result
#[derive(Serialize)]
struct SubmitResultBody {
    miner_id:             String,
    submitted_generation: i64,
    result:               SubmitResultInner,
}

#[derive(Serialize)]
struct SubmitResultInner {
    task_id:           String,
    receipt_id:        String,
    miner_id:          String,
    content_hash:      String,
    result_payload:    Value,
    algorithm_version: String,
    workload_version:  String,
    seal_nonce:        Option<u64>,
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Thin async wrapper around the scheduler's HTTP API.
pub struct SchedulerClient {
    http:     Client,
    base_url: String,
}

impl SchedulerClient {
    pub fn new(base_url: &str) -> Result<Self, MinerError> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| MinerError::Http(e.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    // ── Register ──────────────────────────────────────────────────────────────

    /// POST /scheduler/miners/register
    pub async fn register(
        &self,
        miner_id:      &str,
        workload_class: &str,
    ) -> Result<(), MinerError> {
        let url = format!("{}/scheduler/miners/register", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({
                "miner_id":      miner_id,
                "workload_class": workload_class,
            }))
            .send()
            .await
            .map_err(|e| MinerError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(MinerError::Scheduler(format!(
                "register failed: HTTP {status} — {body}"
            )));
        }
        Ok(())
    }

    // ── Poll for task ─────────────────────────────────────────────────────────

    /// GET /scheduler/miners/:miner_id/task?objective_id=...&workload_class=...
    ///
    /// Returns `None` when the scheduler has no task available (HTTP 204).
    pub async fn get_task(
        &self,
        miner_id:      &str,
        objective_id:  &str,
        workload_class: &str,
    ) -> Result<Option<TaskAssignment>, MinerError> {
        let url = format!(
            "{}/scheduler/miners/{}/task",
            self.base_url,
            urlencoding::encode(miner_id)
        );
        let resp = self
            .http
            .get(&url)
            .query(&[
                ("objective_id", objective_id),
                ("workload_class", workload_class),
            ])
            .send()
            .await
            .map_err(|e| MinerError::Http(e.to_string()))?;

        match resp.status().as_u16() {
            204 => return Ok(None),
            200 => {}
            code => {
                let body = resp.text().await.unwrap_or_default();
                return Err(MinerError::Scheduler(format!(
                    "get_task: HTTP {code} — {body}"
                )));
            }
        }

        let assignment: TaskAssignment = resp
            .json()
            .await
            .map_err(|e| MinerError::Deserialize(e.to_string()))?;
        Ok(Some(assignment))
    }

    // ── Submit result ─────────────────────────────────────────────────────────

    /// POST /scheduler/tasks/:task_id/result
    pub async fn submit_result(
        &self,
        task_id:              &str,
        miner_id:             &str,
        submitted_generation: i64,
        result:               NewResult,
    ) -> Result<(), MinerError> {
        let url = format!(
            "{}/scheduler/tasks/{}/result",
            self.base_url,
            urlencoding::encode(task_id)
        );

        let body = SubmitResultBody {
            miner_id: miner_id.to_string(),
            submitted_generation,
            result: SubmitResultInner {
                task_id:           result.task_id,
                receipt_id:        Uuid::new_v4().to_string(),
                miner_id:          result.miner_id,
                content_hash:      result.content_hash,
                result_payload:    result.result_payload,
                algorithm_version: result.algorithm_version,
                workload_version:  result.workload_version,
                seal_nonce:        result.seal_nonce,
            },
        };

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| MinerError::Http(e.to_string()))?;

        match resp.status().as_u16() {
            204 => Ok(()),
            409 => {
                let msg = resp.text().await.unwrap_or_default();
                Err(MinerError::LeaseSuperseded(msg))
            }
            410 => {
                let msg = resp.text().await.unwrap_or_default();
                Err(MinerError::LeaseExpired(msg))
            }
            403 => {
                let msg = resp.text().await.unwrap_or_default();
                Err(MinerError::Forbidden(msg))
            }
            code => {
                let body = resp.text().await.unwrap_or_default();
                Err(MinerError::Scheduler(format!(
                    "submit_result: HTTP {code} — {body}"
                )))
            }
        }
    }
}
