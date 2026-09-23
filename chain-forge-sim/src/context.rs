//! SimContext -- the live HTTP client every persona uses to talk to a real
//! running chain-forge-node. Uses raw tokio TCP so this crate needs no
//! HTTP-client dependency beyond what the workspace already provides.
//! The node speaks plain HTTP/1.1 over TCP, so hand-writing requests is
//! straightforward and dependency-free.

use anyhow::{anyhow, Context, Result};
use chain_forge_execution::Transaction;
use serde::Deserialize;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// What happened to a submitted transaction, once we could find out.
#[derive(Debug, Clone)]
pub enum TxOutcome {
    /// Accepted into the queue but not yet confirmed by the time we gave
    /// up polling.
    Queued,
    /// The node processed it -- success or failure, either way this is
    /// the real, live-committed outcome.
    Confirmed { success: bool, events: Vec<String>, error: Option<String> },
    /// POST /api/tx itself was rejected (malformed JSON, etc.) before
    /// ever being queued.
    RejectedAtSubmission { message: String },
}

/// A single (persona, action, outcome) entry, recorded for the report.
#[derive(Debug, Clone)]
pub struct TxLogEntry {
    pub persona_id: String,
    pub tx_id:      String,
    pub kind:        String,
    pub outcome:     TxOutcome,
}

/// Minimal local shape of GET /api/accounts/{address}.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountView {
    pub address:        String,
    pub role:           Option<String>,
    pub nonce:          u64,
    pub balances:       HashMap<String, u128>,
    pub tier:           Option<String>,
    pub exemption_days: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct TxSubmitResponse {
    status:  String,
    tx_id:   Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TxSummaryResponse {
    success: bool,
    events:  Vec<String>,
    error:   Option<String>,
}

pub struct SimContext {
    host:      String,   // e.g. "10.0.0.90"
    port:      u16,
    nonces:    HashMap<String, u64>,
    pub epoch_log: Vec<TxLogEntry>,
}

/// Minimal synchronous HTTP/1.1 GET over tokio TCP. Returns the response
/// body as a String, or an error if the connection failed or the response
/// had no body.
async fn http_get(host: &str, port: u16, path: &str) -> Result<(u16, String)> {
    let mut stream = TcpStream::connect((host, port)).await
        .with_context(|| format!("TCP connect to {host}:{port} failed"))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let raw = String::from_utf8_lossy(&buf).to_string();

    let status_code = raw.split_whitespace().nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);
    let body = raw.find("\r\n\r\n")
        .map(|i| raw[i + 4..].to_string())
        .unwrap_or_default();
    Ok((status_code, body))
}

/// Minimal HTTP/1.1 POST over tokio TCP with a JSON body.
async fn http_post_json(host: &str, port: u16, path: &str, body: &str) -> Result<(u16, String)> {
    let mut stream = TcpStream::connect((host, port)).await
        .with_context(|| format!("TCP connect to {host}:{port} failed"))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let raw = String::from_utf8_lossy(&buf).to_string();

    let status_code = raw.split_whitespace().nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);
    let body_out = raw.find("\r\n\r\n")
        .map(|i| raw[i + 4..].to_string())
        .unwrap_or_default();
    Ok((status_code, body_out))
}

impl SimContext {
    /// `base_url` should be like "http://10.0.0.90:8080" or "http://localhost:8080".
    pub fn new(base_url: String) -> Self {
        let (host, port) = parse_base_url(&base_url);
        Self { host, port, nonces: HashMap::new(), epoch_log: Vec::new() }
    }

    pub fn next_nonce(&mut self, sender: &str) -> u64 {
        let n = self.nonces.entry(sender.to_string()).or_insert(0);
        let current = *n;
        *n += 1;
        current
    }

    pub async fn submit_tx(
        &mut self,
        persona_id: &str,
        kind: &str,
        tx: Transaction,
    ) -> Result<TxOutcome> {
        let tx_id = tx.id.clone();
        let body = serde_json::to_string(&tx).context("failed to serialise transaction")?;

        let (status, resp_body) = http_post_json(&self.host, self.port, "/api/tx", &body).await?;

        let outcome = if status == 200 {
            let parsed: TxSubmitResponse = serde_json::from_str(&resp_body)
                .context("POST /api/tx returned unexpected JSON shape")?;
            if parsed.status == "queued" {
                self.poll_for_confirmation(&tx_id, 6, std::time::Duration::from_millis(500)).await
            } else {
                TxOutcome::RejectedAtSubmission {
                    message: parsed.message.unwrap_or_else(|| "unknown rejection".into()),
                }
            }
        } else {
            TxOutcome::RejectedAtSubmission {
                message: format!("HTTP {status}: {resp_body}"),
            }
        };

        self.epoch_log.push(TxLogEntry {
            persona_id: persona_id.to_string(), tx_id, kind: kind.to_string(),
            outcome: outcome.clone(),
        });
        Ok(outcome)
    }

    async fn poll_for_confirmation(
        &self,
        tx_id: &str,
        max_attempts: u32,
        interval: std::time::Duration,
    ) -> TxOutcome {
        let path = format!("/api/tx/{tx_id}");
        for _ in 0..max_attempts {
            if let Ok((status, body)) = http_get(&self.host, self.port, &path).await {
                if status == 200 {
                    if let Ok(s) = serde_json::from_str::<TxSummaryResponse>(&body) {
                        return TxOutcome::Confirmed {
                            success: s.success,
                            events:  s.events,
                            error:   s.error,
                        };
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
        TxOutcome::Queued
    }

    pub async fn submit_raw_malformed(&mut self, persona_id: &str, body: &str) -> Result<u16> {
        let (status, _) = http_post_json(&self.host, self.port, "/api/tx", body).await?;
        self.epoch_log.push(TxLogEntry {
            persona_id: persona_id.to_string(),
            tx_id:      "malformed-raw".to_string(),
            kind:       "malformed_raw".to_string(),
            outcome:    TxOutcome::RejectedAtSubmission { message: format!("HTTP {status}") },
        });
        Ok(status)
    }

    pub async fn get_account(&self, address: &str) -> Result<Option<AccountView>> {
        let path = format!("/api/accounts/{address}");
        let (status, body) = http_get(&self.host, self.port, &path).await?;
        if status == 404 { return Ok(None); }
        if status != 200 {
            return Err(anyhow!("GET /api/accounts/{address} returned HTTP {status}"));
        }
        let account: AccountView = serde_json::from_str(&body)
            .context("GET /api/accounts returned unexpected JSON shape")?;
        Ok(Some(account))
    }

    pub fn drain_epoch_log(&mut self) -> Vec<TxLogEntry> {
        std::mem::take(&mut self.epoch_log)
    }
}

fn parse_base_url(url: &str) -> (String, u16) {
    let url = url.trim_start_matches("http://").trim_start_matches("https://");
    if let Some((host, port_str)) = url.split_once(':') {
        let port = port_str.parse::<u16>().unwrap_or(8080);
        (host.to_string(), port)
    } else {
        (url.to_string(), 8080)
    }
}
