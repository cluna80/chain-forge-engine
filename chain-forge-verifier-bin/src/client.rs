//! HTTP client for the QCB scheduler API (verifier-side).
//!
//! Covers:
//!   GET  /scheduler/objectives/{id}/results  — list submitted results
//!   POST /scheduler/tasks/{id}/verify        — submit a verification record

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Result row from the scheduler ─────────────────────────────────────────────

/// A single experiment result row returned by the scheduler's results listing.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SubmittedResult {
    pub result_id:     String,
    pub task_id:       String,
    pub miner_id:      String,
    pub content_hash:  String,
    pub result_status: String,
    pub result_payload: Value,
    /// Task kind (joined from the task row): "pocd_phase1" | "pocd_phase2" |
    /// "avalanche_experiment" | "avalanche_replication".
    #[serde(default = "default_task_kind")]
    pub task_kind:     String,
    /// Phase-2 only: hex-encoded SHA-256 output from the phase-1 winner.
    /// Joined from the task row by the scheduler's results endpoint.
    pub parent_hash:   Option<String>,
}

fn default_task_kind() -> String { "pocd_phase1".to_string() }

// ── Verify response ───────────────────────────────────────────────────────────

/// Response body from `POST /scheduler/tasks/{task_id}/verify`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct VerifyResponse {
    pub verification_id:  String,
    pub reproduced_count: u64,
    pub quorum_required:  u32,
    pub quorum_reached:   bool,
    pub status:           String,
}

// ── Outcome enum ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum VerifyOutcome {
    Reproduced,
    Rejected,
    Inconclusive,
}

impl VerifyOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reproduced   => "reproduced",
            Self::Rejected     => "rejected",
            Self::Inconclusive => "inconclusive",
        }
    }
}

// ── Verify request body ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct VerifyRequest<'a> {
    result_id:              &'a str,
    verifier_id:            &'a str,
    outcome:                &'a str,
    verifier_content_hash:  &'a str,
    notes:                  Option<&'a str>,
    verifier_receipt_id:    Option<&'a str>,
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Thin async wrapper around the scheduler's HTTP API.
pub struct SchedulerClient {
    http:     Client,
    base_url: String,
}

impl SchedulerClient {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    // ── List submitted results ────────────────────────────────────────────────

    /// GET /scheduler/objectives/{objective_id}/results
    ///
    /// Returns only results with `result_status = "submitted"`.
    pub async fn list_submitted_results(
        &self,
        objective_id: &str,
        limit:        usize,
    ) -> anyhow::Result<Vec<SubmittedResult>> {
        let url = format!(
            "{}/scheduler/objectives/{}/results",
            self.base_url,
            urlencoding::encode(objective_id),
        );
        let resp = self
            .http
            .get(&url)
            .query(&[("limit", limit.to_string())])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("list_results: HTTP {status} — {body}");
        }

        let all: Vec<SubmittedResult> = resp.json().await?;
        // Filter to submitted only; accepted/superseded/pending are not our job
        Ok(all.into_iter().filter(|r| r.result_status == "submitted").collect())
    }

    // ── Submit verification ───────────────────────────────────────────────────

    /// POST /scheduler/tasks/{task_id}/verify
    pub async fn verify(
        &self,
        task_id:      &str,
        result_id:    &str,
        verifier_id:  &str,
        outcome:      VerifyOutcome,
        content_hash: &str,
    ) -> anyhow::Result<VerifyResponse> {
        let url = format!(
            "{}/scheduler/tasks/{}/verify",
            self.base_url,
            urlencoding::encode(task_id),
        );

        let body = VerifyRequest {
            result_id,
            verifier_id,
            outcome:               outcome.as_str(),
            verifier_content_hash: content_hash,
            notes:                 None,
            verifier_receipt_id:   None,
        };

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        if status.as_u16() == 201 {
            let vr: VerifyResponse = serde_json::from_str(&body_text)
                .map_err(|e| anyhow::anyhow!("deserialize VerifyResponse: {e} — body: {body_text}"))?;
            return Ok(vr);
        }

        // Surface the error body so callers can detect self_verification, etc.
        anyhow::bail!("verify: HTTP {status} — {body_text}")
    }
}
