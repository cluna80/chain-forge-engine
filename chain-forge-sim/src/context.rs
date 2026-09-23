//! SimContext -- the live HTTP client every persona uses to talk to a real
//! running chain-forge-node. Uses raw tokio TCP so this crate needs no
//! HTTP-client dependency beyond what the workspace already provides.
//! The node speaks plain HTTP/1.1 over TCP, so hand-writing requests is
//! straightforward and dependency-free.

use anyhow::{anyhow, Context, Result};
use chain_forge_core::{Address, HashWidth};
use chain_forge_crypto::{ClassicalScheme, KeyPair, SchemeId};
use chain_forge_execution::{Transaction, TxBody};
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
    /// Signing keys by on-chain address: generated for sim-* personas,
    /// loaded from key files for named genesis accounts (seed attesters).
    keys:      HashMap<String, KeyPair>,
    /// Persona label (e.g. "sim-alice") -> its key-derived address.
    labels:    HashMap<String, String>,
    /// Fetched from /api/status in init(); every signature commits to it.
    chain_id:  String,
    /// Unique per run, prefixed to every transaction id, so rerunning
    /// against a live chain never polls a previous run's tx summary.
    run_tag:   String,
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
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

    // Use byte length (not char count) for Content-Length -- they differ
    // for any non-ASCII character, and getting this wrong causes the node's
    // HTTP parser to see a truncated or malformed body.
    let body_bytes = body.as_bytes();
    let headers = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    // One write: headers and body together, so they usually travel in the
    // same TCP segment. (The node no longer depends on this -- it reads
    // until Content-Length is satisfied -- but there's no reason to split.)
    let mut request = headers.into_bytes();
    request.extend_from_slice(body_bytes);
    stream.write_all(&request).await?;

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
        let run_tag = format!("run{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
        Self {
            host, port,
            nonces: HashMap::new(),
            epoch_log: Vec::new(),
            keys: HashMap::new(),
            labels: HashMap::new(),
            chain_id: String::new(),
            run_tag,
        }
    }

    /// Fetch chain_id from the node and load any key files (*.key.json)
    /// from `keys_dir` -- needed for named genesis accounts like qcb1alice,
    /// whose addresses aren't derived from keys. Must run before any epoch.
    pub async fn init(&mut self, keys_dir: Option<&std::path::Path>) -> Result<()> {
        let (status, body) = http_get(&self.host, self.port, "/api/status").await
            .context("could not reach node /api/status")?;
        if status != 200 {
            return Err(anyhow!("/api/status returned HTTP {status}"));
        }
        let v: serde_json::Value = serde_json::from_str(&body).context("/api/status not JSON")?;
        self.chain_id = v["chain_id"].as_str()
            .ok_or_else(|| anyhow!("/api/status has no chain_id"))?.to_string();

        if let Some(dir) = keys_dir {
            for entry in std::fs::read_dir(dir).with_context(|| format!("cannot read keys dir {dir:?}"))? {
                let path = entry?.path();
                if !path.to_string_lossy().ends_with(".key.json") { continue; }
                let k: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)
                    .with_context(|| format!("bad key file {path:?}"))?;
                let field = |name: &str| k[name].as_str().map(str::to_string)
                    .ok_or_else(|| anyhow!("{path:?} missing {name}"));
                let address = field("address")?;
                let kp = KeyPair {
                    scheme:      SchemeId::Classical,
                    public_key:  decode_hex(&field("public_key")?).ok_or_else(|| anyhow!("{path:?}: bad public_key hex"))?,
                    private_key: decode_hex(&field("private_key")?).ok_or_else(|| anyhow!("{path:?}: bad private_key hex"))?,
                };
                tracing::info!(%address, "loaded key file");
                self.keys.insert(address, kp);
            }
        }
        Ok(())
    }

    pub fn chain_id(&self) -> &str { &self.chain_id }

    /// Prefix a transaction id with this run's tag.
    pub fn tag(&self, id: &str) -> String { format!("{}-{id}", self.run_tag) }

    /// The on-chain address for a label, creating a keypair the first time
    /// a sim-* label is seen. Anything else (qcb1alice, a raw address)
    /// passes through unchanged.
    pub fn resolve(&mut self, label: &str) -> String {
        if let Some(addr) = self.labels.get(label) {
            return addr.clone();
        }
        if !label.starts_with("sim-") {
            return label.to_string();
        }
        let kp = ClassicalScheme.generate_random().expect("ed25519 keygen");
        let addr = Address::from_public_key(&kp.public_key, "qcb", HashWidth::Bits256)
            .as_str().to_string();
        self.labels.insert(label.to_string(), addr.clone());
        self.keys.insert(addr.clone(), kp);
        addr
    }

    /// Non-creating lookup, for read-only paths (expectation checks).
    pub fn address_of(&self, label: &str) -> String {
        self.labels.get(label).cloned().unwrap_or_else(|| label.to_string())
    }

    /// The keypair controlling a label or address, if the sim holds it.
    pub fn keypair_for(&self, label: &str) -> Option<KeyPair> {
        self.keys.get(&self.address_of(label)).cloned()
    }

    /// Fetch the current on-chain nonce for an address and sync the local
    /// counter to it. Call this once per address before the first
    /// transaction, especially for pre-existing accounts (like genesis
    /// validator addresses used as seed attesters) whose on-chain nonce
    /// may already be ahead of 0.
    pub async fn sync_nonce(&mut self, label: &str) -> Result<()> {
        let address = self.resolve(label);
        if let Ok(Some(acct)) = self.get_account(&address).await {
            self.nonces.insert(address, acct.nonce);
        }
        Ok(())
    }

    pub fn next_nonce(&mut self, label: &str) -> u64 {
        let address = self.resolve(label);
        let n = self.nonces.entry(address).or_insert(0);
        let current = *n;
        *n += 1;
        current
    }

    /// Translate labels to addresses, tag the id, sign with the sender's
    /// key (if the sim holds it), then submit. Personas use this for
    /// every normal transaction.
    pub async fn submit_tx(
        &mut self,
        persona_id: &str,
        kind: &str,
        mut tx: Transaction,
    ) -> Result<TxOutcome> {
        tx.sender = self.resolve(&tx.sender);
        match &mut tx.body {
            TxBody::Attest { claimant_id }         => *claimant_id = self.resolve(claimant_id),
            TxBody::ClaimUbi { identity_id }       => *identity_id = self.resolve(identity_id),
            TxBody::Transfer { to, .. }            => *to = self.resolve(to),
            TxBody::SponsorAgent { agent_address } => *agent_address = self.resolve(agent_address),
            TxBody::RevokeAgent { agent_address }  => *agent_address = self.resolve(agent_address),
            _ => {}
        }
        tx.id = self.tag(&tx.id);
        if let Some(kp) = self.keys.get(&tx.sender) {
            tx.sign(kp, &self.chain_id).map_err(|e| anyhow!("signing failed: {e}"))?;
        }
        self.submit_prepared(persona_id, kind, tx).await
    }

    /// Submit exactly as given: no label translation, no id tag, no
    /// signing. Fault-injection personas use this to send unsigned,
    /// forged or tampered transactions (they tag ids themselves).
    pub async fn submit_prepared(
        &mut self,
        persona_id: &str,
        kind: &str,
        tx: Transaction,
    ) -> Result<TxOutcome> {
        let tx_id = tx.id.clone();
        let body = serde_json::to_string(&tx).context("failed to serialise transaction")?;

        // Retry on connection reset (os error 10054) -- the node uses
        // Connection: close and Windows TCP sometimes resets the connection
        // before the response is fully received. Two attempts is enough.
        let (status, resp_body) = {
            let mut result = http_post_json(&self.host, self.port, "/api/tx", &body).await;
            if result.is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                result = http_post_json(&self.host, self.port, "/api/tx", &body).await;
            }
            result?
        };

        let outcome = if status == 200 {
            let parsed: TxSubmitResponse = serde_json::from_str(&resp_body)
                .context("POST /api/tx returned unexpected JSON shape")?;
            if parsed.status == "queued" {
                self.poll_for_confirmation(&tx_id, 16, std::time::Duration::from_secs(1)).await
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
        for attempt in 0..max_attempts {
            // Give the node a moment before the first poll -- it needs to
            // actually commit the block containing this tx first.
            tokio::time::sleep(interval).await;
            match http_get(&self.host, self.port, &path).await {
                Ok((200, body)) => {
                    if let Ok(s) = serde_json::from_str::<TxSummaryResponse>(&body) {
                        return TxOutcome::Confirmed {
                            success: s.success,
                            events:  s.events,
                            error:   s.error,
                        };
                    }
                }
                Ok((404, _)) => {
                    // Not committed yet -- keep polling.
                }
                Ok((status, body)) => {
                    tracing::debug!(tx_id, attempt, status, "unexpected poll status: {body}");
                }
                Err(e) => {
                    // Connection reset (os error 10054) and similar transient
                    // errors -- the node closed the TCP connection after the
                    // previous response (Connection: close), which is normal.
                    // Just retry rather than propagating as a persona error.
                    tracing::debug!(tx_id, attempt, error = %e, "poll connection error, retrying");
                }
            }
        }
        TxOutcome::Queued
    }

    pub async fn submit_raw_malformed(&mut self, persona_id: &str, body: &str) -> Result<u16> {
        let (status, _) = {
            let mut result = http_post_json(&self.host, self.port, "/api/tx", body).await;
            if result.is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                result = http_post_json(&self.host, self.port, "/api/tx", body).await;
            }
            result?
        };
        self.epoch_log.push(TxLogEntry {
            persona_id: persona_id.to_string(),
            tx_id:      "malformed-raw".to_string(),
            kind:       "malformed_raw".to_string(),
            outcome:    TxOutcome::RejectedAtSubmission { message: format!("HTTP {status}") },
        });
        Ok(status)
    }

    pub async fn get_account(&self, label: &str) -> Result<Option<AccountView>> {
        let address = self.address_of(label);
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

    /// Wait until a given address has a confirmed on-chain account,
    /// polling until it appears or the attempt budget runs out.
    /// Used to stall the sim before proceeding past epoch 0 when
    /// registrations are slow to commit.
    pub async fn wait_for_account(
        &self,
        address: &str,
        max_attempts: u32,
        interval: std::time::Duration,
    ) -> bool {
        for _ in 0..max_attempts {
            if let Ok(Some(_)) = self.get_account(address).await {
                return true;
            }
            tokio::time::sleep(interval).await;
        }
        false
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
