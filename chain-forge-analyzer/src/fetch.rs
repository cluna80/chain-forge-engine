//! HTTP client for fetching results from the QCB scheduler.

use reqwest::Client;
use serde::Deserialize;

// ── Types returned by the scheduler ──────────────────────────────────────────

/// A settled experiment result as returned by GET /scheduler/objectives/:id/results
#[derive(Debug, Deserialize, Clone)]
pub struct SettledResult {
    /// Task ID (e.g. "avl-<obj>-s00-b000")
    pub task_id:          String,
    /// Which miner submitted this result
    pub miner_id:         String,
    /// Task kind: "avalanche_experiment" | "avalanche_replication" | "pocd_phase1" | "pocd_phase2"
    #[serde(default = "default_task_kind")]
    pub task_kind:        String,
    /// Seed index (0..9) — present for avalanche results
    pub avl_seed_index:   Option<u32>,
    /// Bit index (0..255) — present for avalanche results
    pub avl_bit_index:    Option<u32>,
    /// SHA-256(canonical_seed) — hex, 64 chars
    pub avl_original_hash: Option<String>,
    /// SHA-256(flip(canonical_seed, bit_index)) — hex, 64 chars
    pub avl_flipped_hash:  Option<String>,
    /// XOR of both hashes — hex, 64 chars (256-bit vector)
    pub avl_xor_diff:      Option<String>,
    /// popcount(xor_diff) — number of output bits changed
    pub avl_hamming_dist:  Option<u32>,
    /// SHA-256(original_hash_bytes || flipped_hash_bytes) — dedup key
    pub content_hash:     String,
    /// Receiving timestamp
    pub submitted_at:     Option<String>,
}

fn default_task_kind() -> String { "avalanche_experiment".to_string() }

// ── Client ────────────────────────────────────────────────────────────────────

pub struct SchedulerClient {
    http:     Client,
    base_url: String,
}

impl SchedulerClient {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// GET /scheduler/objectives/:objective_id/results
    ///
    /// Returns all settled experiment results for the objective.
    /// The scheduler paginates with `?limit=1000&offset=N`; we follow until
    /// we get an empty page.
    pub async fn fetch_results(
        &self,
        objective_id: &str,
    ) -> anyhow::Result<Vec<SettledResult>> {
        let mut all: Vec<SettledResult> = Vec::new();
        let mut offset = 0usize;
        let limit = 1000usize;

        loop {
            let url = format!(
                "{}/scheduler/objectives/{}/results",
                self.base_url,
                urlencoding::encode(objective_id),
            );
            let resp = self
                .http
                .get(&url)
                .query(&[
                    ("limit",  limit.to_string().as_str()),
                    ("offset", offset.to_string().as_str()),
                ])
                .send()
                .await?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body   = resp.text().await.unwrap_or_default();
                anyhow::bail!("fetch_results: HTTP {status} — {body}");
            }

            let page: Vec<SettledResult> = resp.json().await?;
            let page_len = page.len();
            all.extend(page);

            if page_len < limit {
                break; // last page
            }
            offset += limit;
        }

        Ok(all)
    }
}
