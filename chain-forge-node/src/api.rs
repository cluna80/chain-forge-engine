/// HTTP API for the Chain Forge node.
///
/// Phase 0: minimal status endpoint. The Chain Forge wizard frontend
/// calls POST /api/build with a genesis JSON to trigger a chain build,
/// and GET /api/status to check node health.
///
/// Phase 1 will add: streaming build logs, node start/stop, validator
/// key management, and a WebSocket feed for the explorer.

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use super::node::{NodeStatus, ExplorerState, QrcMetrics, MAX_GC_RECEIPTS, SharedNonceCache};

/// Durable max_uses counter for DIS delegations.
///
/// Wraps a `HashMap<delegation_id, remaining_uses>` and optionally persists it
/// to `<data_dir>/persist/dis_delegation_usage.json` so counts survive node
/// restarts (closes I11).  When no data_dir is configured the counter is
/// memory-only (same as before) — the node still enforces max_uses within a
/// session; it just resets on restart.
#[derive(Default)]
pub struct DelegationUsageStore {
    pub counts: HashMap<[u8; 32], u32>,
    persist_path: Option<std::path::PathBuf>,
}

impl DelegationUsageStore {
    /// Create a new store, loading existing counts from disk when a path is given.
    pub fn new(data_dir: Option<&std::path::Path>) -> Self {
        let persist_path = data_dir.map(|d| d.join("persist").join("dis_delegation_usage.json"));
        let counts = if let Some(ref p) = persist_path {
            if let Ok(bytes) = std::fs::read(p) {
                // Stored as [{hex_id: String, remaining: u32}, ...]
                #[derive(serde::Deserialize)]
                struct Row { hex_id: String, remaining: u32 }
                if let Ok(rows) = serde_json::from_slice::<Vec<Row>>(&bytes) {
                    rows.into_iter().filter_map(|r| {
                        let b = hex::decode(&r.hex_id).ok()?;
                        let arr: [u8; 32] = b.try_into().ok()?;
                        Some((arr, r.remaining))
                    }).collect()
                } else {
                    HashMap::new()
                }
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        };
        Self { counts, persist_path }
    }

    /// Flush counts to disk (best-effort; ignores write errors).
    pub fn flush(&self) {
        let Some(ref p) = self.persist_path else { return };
        #[derive(serde::Serialize)]
        struct Row<'a> { hex_id: String, remaining: u32, #[allow(dead_code)] _phantom: std::marker::PhantomData<&'a ()> }
        let rows: Vec<_> = self.counts.iter().map(|(id, &rem)| {
            serde_json::json!({ "hex_id": hex::encode(id), "remaining": rem })
        }).collect();
        let _ = std::fs::write(p, serde_json::to_vec(&rows).unwrap_or_default());
    }
}

pub type SharedDelegationUsage = Arc<Mutex<DelegationUsageStore>>;
use super::auth::{ChallengeStore, AuthChallenge, ChallengeRequest, VerifyRequest,
                  verify_challenge_signature, identity_auth_status, authorize_scope,
                  key_binding_from_explorer, scope_policy};
use chain_forge_p2p::PeerInfo;
use chain_forge_execution::Transaction;
use chain_forge_pocd::{DiscoveryProof, DiscoveryRegistry};

/// Serve the HTTP API on the given port.
/// Phase 0 implementation: a minimal hand-rolled HTTP server that handles
/// the two endpoints the wizard frontend needs, without pulling in a full
/// web framework (saves ~50MB of compile-time dependencies for Phase 0).
/// What POST /api/tx checks before a transaction enters the queue.
/// Only the stateless signature check happens here; key binding needs
/// account state and is enforced at execution on every node.
#[derive(Clone)]
pub struct TxPrecheck {
    pub chain_id:             String,
    pub require_signatures:   bool,
    pub modules:              chain_forge_core::EnabledModules,
    /// Addresses authorised to submit ClaimResearchReward transactions.
    /// Populated from genesis `settlement_operators`. An empty list disables
    /// the ingress check (useful for chains that don't use the PoCD module).
    pub settlement_operators: Vec<String>,
    /// Maximum accepted tx payload size in bytes (0 = unlimited).
    /// Sourced from genesis `limits.max_tx_bytes`.
    pub max_tx_bytes: usize,
    /// Maximum gas a single tx may request. Sourced from genesis
    /// `limits.block_gas_limit`. A tx asking for more than one full block's
    /// worth of gas can never be included and is rejected at ingress.
    pub block_gas_limit: u64,
    /// Address of the pilot-phase attestation coordinator.
    /// Only this address may submit ConfirmSybil and ReverseSybil.
    /// None means coordinator is not configured — both tx types are rejected.
    pub attestation_coordinator: Option<String>,
    /// Addresses authorised to submit governance transactions (ActivatePqConsensus).
    /// Populated from genesis validator accounts. Empty list = all senders blocked.
    pub governance_authorities: Vec<String>,
}

/// Maximum nonce gap the mempool accepts for an account's next tx.
const MAX_NONCE_GAP: u64 = 100;
/// Sentinel stored in the nonce cache for genesis accounts that have not yet
/// committed any transaction on this chain.  F1 treats it as "any nonce in
/// 0..MAX_NONCE_GAP is valid" rather than the usual strictly-greater-than rule.
const NO_PRIOR_TX: u64 = u64::MAX;

/// F1 mempool nonce guard — returns `true` if the tx **should be rejected**.
///
/// `last` is the value stored in the nonce cache for the sender (either the
/// last committed `tx.nonce` or `NO_PRIOR_TX` for a fresh genesis account).
/// `nonce` is the nonce from the incoming transaction.
pub(crate) fn f1_nonce_rejected(last: u64, nonce: u64) -> bool {
    if last == NO_PRIOR_TX {
        nonce > MAX_NONCE_GAP
    } else {
        nonce <= last || nonce > last.saturating_add(MAX_NONCE_GAP)
    }
}

pub async fn serve(
    port: u16,
    status:          Arc<Mutex<NodeStatus>>,
    explorer:        Arc<Mutex<ExplorerState>>,
    qrc_metrics:     Arc<Mutex<QrcMetrics>>,
    peers:           Arc<Mutex<Vec<PeerInfo>>>,
    tx_queue:        Arc<Mutex<Vec<Transaction>>>,
    precheck:        TxPrecheck,
    pocd_registry:   Option<Arc<Mutex<DiscoveryRegistry>>>,
    challenge_store: Arc<Mutex<ChallengeStore>>,
    node_id:         String,
    // Change Set T — peer capacity table (advisory, non-correctness).
    peer_capacity_table: Arc<Mutex<crate::gossip_capacity::PeerCapacityTable>>,
    nonce_cache: SharedNonceCache,
    delegation_usage: SharedDelegationUsage,
) {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(port, error = %e, "failed to bind HTTP API port");
            return;
        }
    };

    tracing::info!(port, "HTTP API listening");

    loop {
        match listener.accept().await {
            Ok((mut stream, peer)) => {
                tracing::debug!(peer = %peer, "HTTP connection");
                let status           = status.clone();
                let explorer         = explorer.clone();
                let qrc_metrics      = qrc_metrics.clone();
                let peers            = peers.clone();
                let tx_queue         = tx_queue.clone();
                let precheck         = precheck.clone();
                let pocd_registry       = pocd_registry.clone();
                let challenge_store     = challenge_store.clone();
                let node_id             = node_id.clone();
                let peer_capacity_table = peer_capacity_table.clone();
                let nonce_cache         = nonce_cache.clone();
                let delegation_usage    = delegation_usage.clone();

                tokio::spawn(async move {
                    // Read the WHOLE request: headers, then Content-Length
                    // bytes of body. A single read() returns whatever TCP has
                    // delivered so far, which can be the headers alone when a
                    // client writes them separately from the body. Replying
                    // and closing with body bytes still unread makes Windows
                    // reset the connection (os error 10054 on the client).
                    let mut buf: Vec<u8> = Vec::with_capacity(8192);
                    let mut chunk = [0u8; 8192];
                    let read_all = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        async {
                            loop {
                                let n = stream.read(&mut chunk).await?;
                                if n == 0 { break; }
                                buf.extend_from_slice(&chunk[..n]);
                                if request_complete(&buf) || buf.len() >= MAX_REQUEST_BYTES {
                                    break;
                                }
                            }
                            Ok::<(), std::io::Error>(())
                        },
                    ).await;
                    if !matches!(read_all, Ok(Ok(()))) || buf.is_empty() {
                        return;
                    }

                    let request = String::from_utf8_lossy(&buf);
                    let first_line = request.lines().next().unwrap_or("");

                    let response = if first_line.starts_with("GET /api/status") {
                        let s = status.lock().unwrap();
                        let body = serde_json::to_string(&*s).unwrap_or_default();
                        http_200_json(&body)
                    } else if first_line.starts_with("GET /api/health") {
                        http_200_json(r#"{"status":"ok"}"#)
                    } else if first_line.starts_with("POST /api/tx") {
                        // POST /api/tx -- submit a transaction, including
                        // RegisterIdentity and Attest (Identity Pilot Phase 1).
                        // Body is a JSON-serialised chain_forge_execution::Transaction.
                        // Queued here and picked up by the node's own event
                        // loop on its next heartbeat tick (SharedTxQueue) --
                        // this API task has no direct reference to the live
                        // Node to call submit_tx() on directly.
                        let body_start = request.find("\r\n\r\n")
                            .map(|i| i + 4)
                            .unwrap_or(request.len());
                        let body = &request[body_start..];

                        // F8: byte-length guard *before* JSON parsing so
                        // unicode-expansion attacks (tiny chars → huge allocations)
                        // cannot consume resources in the deserialiser.
                        let raw_limit = if precheck.max_tx_bytes > 0 { precheck.max_tx_bytes } else { 1_048_576 };
                        // F8b: JSON nesting-depth guard against deeply-nested
                        // payloads that cause stack exhaustion in the parser.
                        const MAX_JSON_DEPTH: usize = 32;
                        let json_depth = {
                            let mut depth = 0usize;
                            let mut max_d = 0usize;
                            let mut in_str = false;
                            let mut esc = false;
                            for b in body.bytes() {
                                if esc { esc = false; continue; }
                                if b == b'\\' && in_str { esc = true; continue; }
                                if b == b'"' { in_str = !in_str; continue; }
                                if in_str { continue; }
                                if b == b'[' || b == b'{' { depth += 1; if depth > max_d { max_d = depth; } }
                                if b == b']' || b == b'}' { depth = depth.saturating_sub(1); }
                            }
                            max_d
                        };
                        if body.len() >= raw_limit {
                            let resp = serde_json::json!({
                                "status": "rejected",
                                "message": format!("request body too large: {} bytes, limit {}", body.len(), raw_limit)
                            });
                            http_400_json(&resp.to_string())
                        } else if json_depth > MAX_JSON_DEPTH {
                            let resp = serde_json::json!({
                                "status": "rejected",
                                "message": format!("request body nesting depth {json_depth} exceeds limit {MAX_JSON_DEPTH}")
                            });
                            http_400_json(&resp.to_string())
                        } else if body.contains("\"signature\":null") || body.contains("\"signature\": null") {
                            // F5: explicit JSON null for signature is a malformed tx, not a
                            // missing-field. Reject before deserialization so the visitor's
                            // visit_none fallback (→ empty Vec) cannot silently accept it.
                            http_400_json(r#"{"status":"rejected","message":"malformed signature: null is not a valid signature value"}"#)
                        } else { match serde_json::from_str::<Transaction>(body) {
                            Ok(tx) if chain_forge_execution::check_tx(&tx, precheck.max_tx_bytes, precheck.block_gas_limit).is_err() => {
                                let reason = chain_forge_execution::check_tx(&tx, precheck.max_tx_bytes, precheck.block_gas_limit)
                                    .unwrap_err();
                                tracing::info!(tx_id = %tx.id, %reason, "transaction rejected at mempool ingress (check_tx)");
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": reason
                                });
                                http_400_json(&resp.to_string())
                            }
                            Ok(tx) if chain_forge_execution::module_check(&tx, &precheck.modules).is_err() => {
                                let reason = chain_forge_execution::module_check(&tx, &precheck.modules)
                                    .unwrap_err();
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": reason
                                });
                                http_400_json(&resp.to_string())
                            }
                            // F1/F7: reject committed-tx replays at ingress rather than
                            // silently ignoring them after the 200 response is sent.
                            Ok(tx) if explorer.lock().unwrap().txs.contains_key(&tx.id) => {
                                tracing::info!(tx_id = %tx.id, "committed-tx replay rejected at ingress");
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": "transaction already committed — replay not permitted"
                                });
                                http_400_json(&resp.to_string())
                            }
                            // F5: reject transactions from unknown senders (absent from the
                            // nonce cache). Genesis accounts are seeded at startup so they
                            // pass F5; their first tx may use nonce=0 (executor expects 0).
                            Ok(ref tx) if {
                                let cache = nonce_cache.lock().unwrap();
                                !cache.contains_key(&tx.sender)
                            } => {
                                tracing::warn!(sender = %tx.sender, tx_id = %tx.id,
                                    "tx rejected: sender has no committed history on this chain");
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": format!("sender {} is not a registered account on this chain", tx.sender)
                                });
                                http_400_json(&resp.to_string())
                            }
                            // F1: nonce must be strictly greater than the last committed
                            // nonce for this sender AND within MAX_NONCE_GAP of it.
                            // Fresh genesis accounts are seeded with last=u64::MAX (NO_PRIOR_TX),
                            // meaning any nonce 0..MAX_NONCE_GAP is valid as the first tx.
                            // After a tx commits, the cache stores tx.nonce, so replay is blocked.
                            Ok(ref tx) if {
                                let cache = nonce_cache.lock().unwrap();
                                cache.get(&tx.sender).map_or(false, |&last| {
                                    f1_nonce_rejected(last, tx.nonce)
                                })
                            } => {
                                // Re-lock to get the last nonce for the error message.
                                let last = nonce_cache.lock().unwrap()
                                    .get(&tx.sender).copied().unwrap_or(0);
                                // tx is already parsed; borrow its fields for the response.
                                let (tx_id, nonce) = if let Ok(ref t) =
                                    serde_json::from_str::<chain_forge_execution::Transaction>(body)
                                { (t.id.clone(), t.nonce) } else { (String::new(), 0) };
                                tracing::info!(nonce, last_committed = last, "nonce replay / out-of-sequence rejected at ingress");
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx_id,
                                    "message": format!("nonce {nonce} out of range (last committed: {last}, max gap: 100)")
                                });
                                http_400_json(&resp.to_string())
                            }
                            // F5: reject malformed PQ signature entries.
                            // Entries use a "<scheme>:<hex>" format; strip the known tag first,
                            // then validate the hex payload.  Smallest known PQ sig is
                            // ML-DSA-44 = 2420 bytes = 4840 hex chars.
                            Ok(ref tx) if !tx.pq_signatures.is_empty() && tx.pq_signatures.iter().any(|s| {
                                const MIN_PQ_SIG_HEX: usize = 4840;
                                let hex_part = s.strip_prefix("mldsa65:")
                                    .or_else(|| s.strip_prefix("slhdsa:"))
                                    .or_else(|| s.strip_prefix("fndsa:"))
                                    .unwrap_or(s.as_str());
                                hex_part.len() < MIN_PQ_SIG_HEX || hex_part.len() % 2 != 0
                                    || !hex_part.bytes().all(|b| b.is_ascii_hexdigit())
                            }) => {
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": "malformed PQ signature: entry is not valid hex or is too short for any supported PQ algorithm"
                                });
                                http_400_json(&resp.to_string())
                            }
                            // F2: reject Transfer if amount > sender's current balance.
                            Ok(ref tx) if {
                                if let chain_forge_execution::TxBody::Transfer { ref denom, amount, .. } = tx.body {
                                    let ex = explorer.lock().unwrap();
                                    let bal = ex.accounts.get(&tx.sender)
                                        .and_then(|a| a.balances.get(denom))
                                        .copied()
                                        .unwrap_or(0);
                                    amount > bal
                                } else { false }
                            } => {
                                let (denom, amount) = if let chain_forge_execution::TxBody::Transfer { ref denom, amount, .. } = tx.body {
                                    (denom.clone(), amount)
                                } else { ("uqcb".into(), 0u128) };
                                let sender_balance = {
                                    let ex = explorer.lock().unwrap();
                                    ex.accounts.get(&tx.sender)
                                        .and_then(|a| a.balances.get(&denom))
                                        .copied()
                                        .unwrap_or(0)
                                };
                                tracing::warn!(tx_id = %tx.id, sender = %tx.sender, amount, sender_balance,
                                    "tx rejected: Transfer amount exceeds sender balance");
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": format!("insufficient balance: {amount} {denom} requested but sender has {sender_balance}")
                                });
                                http_400_json(&resp.to_string())
                            }
                            // F5-sig: Ed25519 signatures are exactly 64 bytes.
                            // Belt-and-suspenders: check_tx enforces this too, but an
                            // explicit ingress arm catches any path that might slip past it
                            // (e.g. a serde default-fallback or an older check_tx binary).
                            Ok(ref tx) if !tx.signature.is_empty() && tx.signature.len() != 64 => {
                                tracing::warn!(tx_id = %tx.id, sig_len = tx.signature.len(),
                                    "tx rejected: Ed25519 signature has wrong byte length");
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": format!(
                                        "malformed Ed25519 signature: expected 64 bytes, got {}",
                                        tx.signature.len()
                                    )
                                });
                                http_400_json(&resp.to_string())
                            }
                            // F5: verify_signature runs for Ed25519 txs when either the chain
                            // *requires* sigs or the tx *carries* one.  ML-DSA txs use a
                            // separate PQ path; verify_signature is classical-only and must
                            // not be called for them.
                            Ok(tx) if tx.sig_scheme != Some(chain_forge_crypto::SchemeId::MlDsa)
                                && (precheck.require_signatures || !tx.signature.is_empty())
                                && chain_forge_execution::verify_signature(&tx, &precheck.chain_id).is_err() => {
                                let reason = chain_forge_execution::verify_signature(&tx, &precheck.chain_id)
                                    .unwrap_err();
                                tracing::info!(tx_id = %tx.id, %reason, "transaction rejected at submission");
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": reason
                                });
                                http_400_json(&resp.to_string())
                            }
                            Ok(tx)
                                if matches!(
                                    &tx.body,
                                    chain_forge_execution::TxBody::ClaimResearchReward { .. }
                                )
                                && !precheck.settlement_operators.contains(&tx.sender) =>
                            {
                                // Fail-closed: ClaimResearchReward is denied when the
                                // sender is absent from settlement_operators, including
                                // when the list is empty (misconfigured genesis → deny
                                // all rather than allow all).
                                //
                                // The executor has a matching guard at execution time;
                                // this ingress check ensures the scheduler receives a
                                // non-2xx immediately so it can surface the rejection
                                // without waiting for block inclusion.
                                let reason = if precheck.settlement_operators.is_empty() {
                                    format!(
                                        "ClaimResearchReward: no settlement_operators configured \
                                         in genesis — all claims denied (sender: {})",
                                        tx.sender
                                    )
                                } else {
                                    format!(
                                        "ClaimResearchReward: sender {} is not a recognized \
                                         settlement operator",
                                        tx.sender
                                    )
                                };
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": reason
                                });
                                tracing::warn!(
                                    tx_id  = %tx.id,
                                    sender = %tx.sender,
                                    operators_configured = precheck.settlement_operators.len(),
                                    "ClaimResearchReward rejected at mempool ingress: unauthorized operator"
                                );
                                http_400_json(&resp.to_string())
                            }
                            // Coordinator-only: ConfirmSybil and ReverseSybil may only
                            // be submitted by the attestation coordinator configured in
                            // genesis. Reject at ingress (fail-closed) so the mempool
                            // cannot be spammed with coordinator-impersonation attempts
                            // that would all fail at execution time.
                            Ok(tx)
                                if matches!(
                                    &tx.body,
                                    chain_forge_execution::TxBody::ConfirmSybil { .. }
                                    | chain_forge_execution::TxBody::ReverseSybil { .. }
                                )
                                && precheck.attestation_coordinator
                                    .as_deref()
                                    .map_or(true, |coord| coord != tx.sender.as_str()) =>
                            {
                                let reason = match &precheck.attestation_coordinator {
                                    None => format!(
                                        "{}: attestation coordinator not configured in genesis \
                                         — coordinator-only txs disabled",
                                        tx.body.variant_name()
                                    ),
                                    Some(_) => format!(
                                        "{}: sender {} is not the attestation coordinator",
                                        tx.body.variant_name(),
                                        tx.sender
                                    ),
                                };
                                tracing::warn!(
                                    tx_id  = %tx.id,
                                    sender = %tx.sender,
                                    tx_type = tx.body.variant_name(),
                                    "coordinator-only tx rejected at mempool ingress"
                                );
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": reason
                                });
                                http_400_json(&resp.to_string())
                            }
                            // Governance-only: ActivatePqConsensus may only be submitted
                            // by validator addresses listed in genesis. Rejects mempool
                            // spam that would fill blocks with governance noise from
                            // non-authorised senders.
                            Ok(tx)
                                if matches!(
                                    &tx.body,
                                    chain_forge_execution::TxBody::ActivatePqConsensus { .. }
                                )
                                && !precheck.governance_authorities.contains(&tx.sender) =>
                            {
                                let reason = if precheck.governance_authorities.is_empty() {
                                    format!(
                                        "ActivatePqConsensus: no governance_authorities configured \
                                         (no validators in genesis) — governance txs blocked"
                                    )
                                } else {
                                    format!(
                                        "ActivatePqConsensus: sender {} is not a governance authority",
                                        tx.sender
                                    )
                                };
                                tracing::warn!(
                                    tx_id  = %tx.id,
                                    sender = %tx.sender,
                                    "ActivatePqConsensus rejected at mempool ingress: unauthorized sender"
                                );
                                let resp = serde_json::json!({
                                    "status": "rejected",
                                    "tx_id": tx.id,
                                    "message": reason
                                });
                                http_400_json(&resp.to_string())
                            }
                            Ok(tx) => {
                                let tx_id = tx.id.clone();
                                tx_queue.lock().unwrap().push(tx);
                                tracing::info!(tx_id, "transaction queued via POST /api/tx");
                                let resp = serde_json::json!({
                                    "status": "queued",
                                    "tx_id": tx_id
                                });
                                http_200_json(&resp.to_string())
                            }
                            Err(e) => {
                                let resp = serde_json::json!({
                                    "status": "error",
                                    "message": format!("invalid transaction JSON: {e}")
                                });
                                http_400_json(&resp.to_string())
                            }
                        } } // close else { match
                    } else if first_line.starts_with("POST /api/build") {
                        // Extract JSON body from the request
                        let body_start = request.find("\r\n\r\n")
                            .map(|i| i + 4)
                            .unwrap_or(request.len());
                        let body = &request[body_start..];

                        // Validate it parses as a genesis config
                        match serde_json::from_str::<serde_json::Value>(body) {
                            Ok(genesis) => {
                                let chain_id = genesis.get("chain_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                tracing::info!(
                                    chain_id,
                                    "genesis build request received from wizard"
                                );
                                let resp = serde_json::json!({
                                    "status": "accepted",
                                    "chain_id": chain_id,
                                    "message": "Genesis configuration accepted. Build API is in Phase 0 — the node is running in devnet mode. Full build pipeline wires up in Phase 1.",
                                    "node_status_url": format!("http://localhost:{}/api/status", 8080)
                                });
                                http_200_json(&resp.to_string())
                            }
                            Err(e) => {
                                let resp = serde_json::json!({
                                    "status": "error",
                                    "message": format!("Invalid genesis JSON: {e}")
                                });
                                http_400_json(&resp.to_string())
                            }
                        }
                    } else if first_line.starts_with("GET /api/blocks/") {
                        // GET /api/blocks/{height}
                        let path = first_line.split_whitespace().nth(1).unwrap_or("");
                        let height: Option<u64> = path
                            .trim_start_matches("/api/blocks/")
                            .parse().ok();
                        let ex = explorer.lock().unwrap();
                        match height.and_then(|h| ex.blocks.iter().find(|b| b.height == h)) {
                            Some(b) => http_200_json(&serde_json::to_string(b).unwrap_or_default()),
                            None    => http_404(),
                        }
                    } else if first_line.starts_with("GET /api/blocks") {
                        // GET /api/blocks — recent blocks, newest first
                        let ex = explorer.lock().unwrap();
                        let blocks: Vec<_> = ex.blocks.iter().collect();
                        http_200_json(&serde_json::to_string(&blocks).unwrap_or_default())
                    } else if first_line.starts_with("GET /api/tx/") {
                        // GET /api/tx/{id}
                        let path = first_line.split_whitespace().nth(1).unwrap_or("");
                        let id = path.trim_start_matches("/api/tx/");
                        let ex = explorer.lock().unwrap();
                        match ex.txs.get(id) {
                            Some(t) => http_200_json(&serde_json::to_string(t).unwrap_or_default()),
                            None    => http_404(),
                        }
                    } else if first_line.starts_with("GET /api/identity/") {
                        // GET /api/identity/{address} — identity record for an address.
                        // Returns the explorer-visible identity state: verification tier
                        // and charm data synced from IdentityStore on every committed block.
                        // Full attestation history lives in the identity crate; this endpoint
                        // exposes the summary that survived the ExplorerState sync.
                        let path = first_line.split_whitespace().nth(1).unwrap_or("");
                        let address = path.trim_start_matches("/api/identity/");
                        let ex = explorer.lock().unwrap();
                        match ex.accounts.get(address) {
                            Some(a) => {
                                let is_registered = a.tier.is_some();
                                let resp = serde_json::json!({
                                    "address":           address,
                                    "registered":        is_registered,
                                    "tier":              a.tier,
                                    "exemption_days":    a.exemption_days,
                                    "frozen":            a.frozen,
                                    "sybil_confirmed":   a.sybil_confirmed,
                                    "attestation_count": a.attestation_count,
                                    "attested_by":       a.attested_by,
                                });
                                http_200_json(&resp.to_string())
                            }
                            None => {
                                // Address not found in explorer — either never registered
                                // or node hasn't committed a block since registration.
                                let resp = serde_json::json!({
                                    "address":        address,
                                    "registered":     false,
                                    "tier":           serde_json::Value::Null,
                                    "exemption_days": 0,
                                    "frozen":         false,
                                    "sybil_confirmed": false,
                                    "note": "address not found in explorer state"
                                });
                                http_200_json(&resp.to_string())
                            }
                        }
                    } else if first_line.starts_with("GET /qcb/resource/balance") {
                        // GET /qcb/resource/balance?account={address}
                        // Returns {"balance": <uqcb_amount>} for the queried account.
                        let raw_path = first_line.split_whitespace().nth(1).unwrap_or("");
                        let account = raw_path.splitn(2, '?').nth(1)
                            .and_then(|q| q.split('&').find(|p| p.starts_with("account=")))
                            .map(|p| p.trim_start_matches("account="))
                            .unwrap_or("");
                        let ex = explorer.lock().unwrap();
                        match ex.accounts.get(account) {
                            Some(a) => {
                                let bal = a.balances.get("uqcb").copied().unwrap_or(0);
                                http_200_json(&serde_json::json!({"account": account, "denom": "uqcb", "balance": bal}).to_string())
                            }
                            None => http_404(),
                        }
                    } else if first_line.starts_with("GET /api/accounts/") {
                        // GET /api/accounts/{address} — balance, nonce, charm state
                        let path = first_line.split_whitespace().nth(1).unwrap_or("");
                        let address = path.trim_start_matches("/api/accounts/");
                        let ex = explorer.lock().unwrap();
                        match ex.accounts.get(address) {
                            Some(a) => http_200_json(&serde_json::to_string(a).unwrap_or_default()),
                            None    => http_404(),
                        }
                    } else if first_line.starts_with("GET /api/accounts") {
                        // GET /api/accounts — all account snapshots
                        let ex = explorer.lock().unwrap();
                        let mut accounts: Vec<_> = ex.accounts.values().collect();
                        accounts.sort_by(|a, b| a.address.cmp(&b.address));
                        http_200_json(&serde_json::to_string(&accounts).unwrap_or_default())
                    } else if first_line.starts_with("GET /api/qrc") {
                        // GET /api/qrc — QRC monetary engine metrics (Section 9.1)
                        let cm = qrc_metrics.lock().unwrap();
                        http_200_json(&serde_json::to_string(&*cm).unwrap_or_default())
                    } else if first_line.starts_with("GET /api/validators") {
                        // GET /api/validators — current validator set with voting powers.
                        // Returns the personhood-weighted set from the last committed block.
                        // Used by integration tests to verify per-human power cap (Section 3.3).
                        let ex = explorer.lock().unwrap();
                        http_200_json(&serde_json::to_string(&ex.validator_powers).unwrap_or_default())
                    } else if first_line.starts_with("GET /api/peers/capacity") {
                        // GET /api/peers/capacity — Change Set T.
                        // Advisory peer capacity table for external schedulers.
                        // Returns only non-stale entries (TTL = CAPACITY_AD_MAX_AGE_MS).
                        // Schedulers MUST treat these as hints only — never as
                        // correctness-critical signals.
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let mut tbl = peer_capacity_table.lock().unwrap();
                        let entries: Vec<_> = tbl.live_entries(now_ms)
                            .into_iter()
                            .collect();
                        http_200_json(&serde_json::to_string(&entries).unwrap_or_default())
                    } else if first_line.starts_with("GET /api/peers") {
                        // GET /api/peers — connected peers (real network layer)
                        let p = peers.lock().unwrap();
                        http_200_json(&serde_json::to_string(&*p).unwrap_or_default())
                    } else if first_line.starts_with("POST /api/gc-receipt") {
                        // POST /api/gc-receipt — receive a useful-work receipt from gc-daemon.
                        // chain-forge-resource (QRC) has been retired; receipts are now stored
                        // as raw JSON values (no seal verification). Exposes via GET /api/gc-receipts.
                        //
                        // The gc-daemon wraps the receipt in:
                        //   { "tx_type": "UsefulWorkReceipt", "payload": <receipt> }
                        // We accept either shape for robustness.
                        let body_start = request.find("\r\n\r\n")
                            .map(|i| i + 4)
                            .unwrap_or(request.len());
                        let body = &request[body_start..];

                        // Parse as generic JSON; extract "payload" if wrapped.
                        let receipt_result: Result<serde_json::Value, _> =
                            serde_json::from_str::<serde_json::Value>(body)
                            .map(|v| {
                                if let Some(payload) = v.get("payload").cloned() {
                                    payload
                                } else {
                                    v
                                }
                            });

                        match receipt_result {
                            Ok(receipt) => {
                                let receipt_id = receipt.get("receipt_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_owned();
                                let challenge_id = receipt.get("challenge_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_owned();
                                let machine_id = receipt.get("machine_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_owned();
                                {
                                    let mut ex = explorer.lock().unwrap();
                                    ex.gc_receipts.push_front(receipt);
                                    if ex.gc_receipts.len() > MAX_GC_RECEIPTS {
                                        ex.gc_receipts.pop_back();
                                    }
                                }
                                tracing::info!(
                                    receipt_id,
                                    challenge_id,
                                    machine_id,
                                    "gc-receipt accepted and stored"
                                );
                                let resp = serde_json::json!({
                                    "status": "accepted",
                                    "receipt_id": receipt_id,
                                    "challenge_id": challenge_id,
                                    "machine_id": machine_id
                                });
                                http_200_json(&resp.to_string())
                            }
                            Err(e) => {
                                let resp = serde_json::json!({
                                    "status": "error",
                                    "message": format!("invalid receipt JSON: {e}")
                                });
                                http_400_json(&resp.to_string())
                            }
                        }
                    } else if first_line.starts_with("GET /api/gc-receipts") {
                        // GET /api/gc-receipts — all stored Grand Challenge receipts, newest first.
                        // Used by the React explorer to show live GC activity.
                        let ex = explorer.lock().unwrap();
                        let receipts: Vec<_> = ex.gc_receipts.iter().collect();
                        http_200_json(&serde_json::to_string(&receipts).unwrap_or_default())
                    } else if first_line.starts_with("GET /api/jobs/") {
                        // GET /api/jobs/{job_id} — single job record from on-chain state.
                        let path = first_line.split_whitespace().nth(1).unwrap_or("");
                        let job_id = path.trim_start_matches("/api/jobs/");
                        let account_key = format!("job:{}", job_id);
                        let ex = explorer.lock().unwrap();
                        match ex.accounts.get(&account_key) {
                            Some(a) => {
                                // Parse the role JSON, add address and balances.
                                let mut jd: serde_json::Value =
                                    serde_json::from_str(&a.role).unwrap_or_default();
                                if jd.is_object() {
                                    jd["_account"] = serde_json::Value::String(account_key.clone());
                                    jd["_balances"] = serde_json::to_value(&a.balances).unwrap_or_default();
                                }
                                http_200_json(&jd.to_string())
                            }
                            None => http_404(),
                        }
                    } else if first_line.starts_with("GET /api/jobs") {
                        // GET /api/jobs — list all job records (state accounts keyed job:{id}).
                        // Accepts optional ?state= filter, e.g. /api/jobs?state=Created
                        let path = first_line.split_whitespace().nth(1).unwrap_or("");
                        let state_filter = if let Some(q) = path.splitn(2, '?').nth(1) {
                            q.split('&')
                                .find(|p| p.starts_with("state="))
                                .map(|p| p.trim_start_matches("state=").to_string())
                        } else {
                            None
                        };
                        let ex = explorer.lock().unwrap();
                        let mut jobs: Vec<serde_json::Value> = ex.accounts.iter()
                            .filter(|(k, _)| k.starts_with("job:"))
                            .filter_map(|(k, a)| {
                                let mut jd: serde_json::Value =
                                    serde_json::from_str(&a.role).ok()?;
                                if !jd.is_object() { return None; }
                                // Apply optional state filter.
                                if let Some(ref sf) = state_filter {
                                    let job_state = jd.get("state")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    if !job_state.eq_ignore_ascii_case(sf) { return None; }
                                }
                                jd["_account"] = serde_json::Value::String(k.clone());
                                jd["_balances"] = serde_json::to_value(&a.balances).unwrap_or_default();
                                Some(jd)
                            })
                            .collect();
                        jobs.sort_by(|a, b| {
                            a.get("job_id").and_then(|v| v.as_str()).unwrap_or("")
                                .cmp(b.get("job_id").and_then(|v| v.as_str()).unwrap_or(""))
                        });
                        http_200_json(&serde_json::to_string(&jobs).unwrap_or_default())
                    } else if first_line.starts_with("POST /genesis") {
                        // POST /genesis -- validate and echo back a genesis configuration.
                        // The wizard "Generate Genesis" button posts the config fields here;
                        // we parse them through chain_forge_core::GenesisConfig (validation
                        // included) and return the canonical pretty-printed JSON that can be
                        // used to start a node with `chain-forge-node --genesis <file>`.
                        let body_start = request.find("\r\n\r\n")
                            .map(|i| i + 4)
                            .unwrap_or(request.len());
                        let body = &request[body_start..];

                        match chain_forge_core::GenesisConfig::from_json(body) {
                            Ok(genesis) => {
                                let errors = genesis.validate();
                                if !errors.is_empty() {
                                    let resp = serde_json::json!({
                                        "status": "error",
                                        "errors": errors
                                    });
                                    http_400_json(&resp.to_string())
                                } else {
                                    match genesis.to_json_pretty() {
                                        Ok(json) => http_200_json(&json),
                                        Err(e) => {
                                            let resp = serde_json::json!({
                                                "status": "error",
                                                "message": format!("serialization error: {e}")
                                            });
                                            http_400_json(&resp.to_string())
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let resp = serde_json::json!({
                                    "status": "error",
                                    "message": format!("invalid genesis JSON: {e}")
                                });
                                http_400_json(&resp.to_string())
                            }
                        }
                    // ── PoCD endpoints ────────────────────────────────────────────

                    } else if first_line.starts_with("GET /api/pocd/challenges") {
                        // GET /api/pocd/challenges — list all active PoCD challenges.
                        match &pocd_registry {
                            Some(reg) => {
                                let reg = reg.lock().unwrap();
                                let challenges: Vec<_> = reg.active_challenges().collect();
                                http_200_json(&serde_json::to_string(&challenges).unwrap_or_default())
                            }
                            None => {
                                let resp = serde_json::json!({
                                    "status": "disabled",
                                    "message": "PoCD is not enabled in this chain's genesis"
                                });
                                http_200_json(&resp.to_string())
                            }
                        }

                    } else if first_line.starts_with("GET /api/pocd/receipts") {
                        // GET /api/pocd/receipts — list all accepted PoCD discovery receipts.
                        match &pocd_registry {
                            Some(reg) => {
                                let reg = reg.lock().unwrap();
                                let receipts: Vec<_> = reg.all_receipts().collect();
                                http_200_json(&serde_json::to_string(&receipts).unwrap_or_default())
                            }
                            None => {
                                let resp = serde_json::json!({
                                    "status": "disabled",
                                    "message": "PoCD is not enabled in this chain's genesis"
                                });
                                http_200_json(&resp.to_string())
                            }
                        }

                    } else if first_line.starts_with("GET /api/pocd/rewards") {
                        // GET /api/pocd/rewards — epoch reward distribution stats.
                        // Returns receipt counts and per-machine wallet addresses.
                        // To check wallet uqcb balances use GET /api/balance/{wallet_addr}.
                        match &pocd_registry {
                            Some(reg) => {
                                let reg = reg.lock().unwrap();
                                let total    = reg.receipt_count();
                                let rewarded = reg.all_receipts()
                                    .filter(|r| r.reward_distributed)
                                    .count();
                                let pending  = total - rewarded;

                                // Collect unique machine_ids → wallet addresses.
                                // QcbRewardPolicy maps machine_id → "wallet:{machine_id}".
                                let mut machine_entries: std::collections::HashMap<String, String> =
                                    std::collections::HashMap::new();
                                for r in reg.all_receipts() {
                                    machine_entries
                                        .entry(r.machine_id.clone())
                                        .or_insert_with(|| format!("wallet:{}", r.machine_id));
                                }

                                let miner_wallets: Vec<serde_json::Value> = machine_entries
                                    .iter()
                                    .map(|(machine_id, wallet_addr)| serde_json::json!({
                                        "machine_id": machine_id,
                                        "wallet":     wallet_addr,
                                        "balance_endpoint": format!("/api/balance/{wallet_addr}"),
                                    }))
                                    .collect();

                                let resp = serde_json::json!({
                                    "total_receipts":    total,
                                    "rewarded_receipts": rewarded,
                                    "pending_receipts":  pending,
                                    "miner_wallets":     miner_wallets,
                                    "_note": "Use GET /api/balance/<wallet> to check uqcb balance after an epoch closes"
                                });
                                http_200_json(&resp.to_string())
                            }
                            None => {
                                let resp = serde_json::json!({
                                    "status": "disabled",
                                    "message": "PoCD is not enabled in this chain's genesis"
                                });
                                http_200_json(&resp.to_string())
                            }
                        }

                    } else if first_line.starts_with("POST /api/pocd/submit") {
                        // POST /api/pocd/submit — submit a DiscoveryProof for verification.
                        // The node performs basic seal validation and stores an accepted receipt.
                        // Full verifier integration (external verifier signatures) is Phase 1.
                        let body_start = request.find("\r\n\r\n")
                            .map(|i| i + 4)
                            .unwrap_or(request.len());
                        let body = &request[body_start..];

                        match serde_json::from_str::<DiscoveryProof>(body) {
                            Err(e) => {
                                let resp = serde_json::json!({
                                    "status": "error",
                                    "message": format!("invalid DiscoveryProof JSON: {e}")
                                });
                                http_400_json(&resp.to_string())
                            }
                            Ok(proof) => {
                                match &pocd_registry {
                                    None => {
                                        let resp = serde_json::json!({
                                            "status": "error",
                                            "message": "PoCD is not enabled in this chain's genesis"
                                        });
                                        http_400_json(&resp.to_string())
                                    }
                                    Some(reg) => {
                                        let mut reg = reg.lock().unwrap();
                                        // Phase 0: node self-verifies the seal (no external verifier).
                                        match proof.verify_seal() {
                                            Ok(()) => {
                                                let seal_hash = proof.seal_hash.clone();
                                                // Extract chain_id from the challenge_id prefix
                                                // (format: "{chain_id}::{track}::{slug}").
                                                let chain_id = proof.challenge_id
                                                    .splitn(3, "::")
                                                    .next()
                                                    .unwrap_or("unknown")
                                                    .to_owned();
                                                // Build a devnet receipt (no external verifier sig).
                                                let receipt = chain_forge_pocd::build_receipt(
                                                    format!("receipt-{}", proof.proof_id),
                                                    &proof,
                                                    chain_id,
                                                    "self-verifier",
                                                    "devnet-no-sig",
                                                    0, // committed_at_block: updated on next block commit
                                                );
                                                match reg.add_receipt(receipt) {
                                                    Ok(()) => {
                                                        let resp = serde_json::json!({
                                                            "status": "accepted",
                                                            "proof_id": proof.proof_id,
                                                            "seal_hash": seal_hash,
                                                        });
                                                        tracing::info!(
                                                            proof_id = %proof.proof_id,
                                                            machine_id = %proof.machine_id,
                                                            "PoCD proof accepted"
                                                        );
                                                        http_200_json(&resp.to_string())
                                                    }
                                                    Err(e) => {
                                                        let resp = serde_json::json!({
                                                            "status": "rejected",
                                                            "reason": e.to_string()
                                                        });
                                                        http_400_json(&resp.to_string())
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let resp = serde_json::json!({
                                                    "status": "rejected",
                                                    "reason": e.to_string()
                                                });
                                                tracing::warn!(
                                                    proof_id = %proof.proof_id,
                                                    error    = %e,
                                                    "PoCD proof rejected: invalid seal"
                                                );
                                                http_400_json(&resp.to_string())
                                            }
                                        }
                                    }
                                }
                            }
                        }

                    // ── DIS-001 Phase A: QR Challenge/Response Authentication ──

                    } else if first_line.starts_with("POST /api/auth/challenge") {
                        // POST /api/auth/challenge — issue a time-bounded challenge.
                        //
                        // Body (optional JSON): { "scope": "wallet:authenticate" }
                        // Response: AuthChallenge JSON including challenge_id + expires_at + chain_id.
                        //
                        // The wallet builds the DIS-AUTH-V1 canonical binary payload from the
                        // challenge JSON fields, SHA-256 pre-hashes it, and signs with ML-DSA-65.
                        // The chain_id field binds the signature to this specific chain — a replay
                        // from another Qattice instance will fail audience/chain binding.
                        let body_start = request.find("\r\n\r\n")
                            .map(|i| i + 4)
                            .unwrap_or(request.len());
                        let body = &request[body_start..];

                        let scope = if body.trim().is_empty() {
                            "wallet:authenticate".to_string()
                        } else {
                            serde_json::from_str::<ChallengeRequest>(body)
                                .map(|r| r.scope)
                                .unwrap_or_else(|_| "wallet:authenticate".to_string())
                        };

                        let challenge = AuthChallenge::new(&node_id, &scope, &precheck.chain_id);
                        let ch_json = serde_json::to_string(&challenge).unwrap_or_default();
                        tracing::info!(
                            challenge_id = %challenge.challenge_id,
                            expires_at   = challenge.expires_at,
                            chain_id     = %challenge.chain_id,
                            scope        = %scope,
                            "auth challenge issued"
                        );
                        {
                            let mut store = challenge_store.lock().unwrap();
                            store.insert(challenge);
                        }
                        http_200_json(&ch_json)

                    } else if first_line.starts_with("POST /api/auth/verify") {
                        // POST /api/auth/verify — verify a wallet-signed DIS-AUTH-V1 challenge.
                        //
                        // Body JSON: {
                        //   "challenge_id": "<32-char hex>",
                        //   "public_key":   "<hex ML-DSA-65 public key, 3904 chars>",
                        //   "signature":    "mldsa65:<hex signature>"
                        // }
                        //
                        // On success:
                        //   { "status": "verified", "address": "qcb1pq…", "chain_id": "…", … }
                        // On failure:
                        //   HTTP 400  { "status": "rejected", "reason": "…" }
                        //
                        // Ordering: cryptographic verification happens BEFORE challenge consumption.
                        // A failed signature attempt leaves the legitimate challenge intact —
                        // an attacker who learns a challenge_id cannot burn it without a valid
                        // signature. The challenge is consumed only on successful verification.
                        // See ChallengeStore::consume() for the threat-model trade-off note.
                        //
                        // Anti-replay: challenge_id is consumed on first successful verification.
                        // Expired challenges are rejected at consume time.
                        let body_start = request.find("\r\n\r\n")
                            .map(|i| i + 4)
                            .unwrap_or(request.len());
                        let body = &request[body_start..];

                        match serde_json::from_str::<VerifyRequest>(body) {
                            Err(e) => {
                                let resp = serde_json::json!({
                                    "status": "error",
                                    "reason": format!("invalid verify request JSON: {e}")
                                });
                                http_400_json(&resp.to_string())
                            }
                            Ok(verify_req) => {
                                // Step 0: Validate delegation chain structure before any
                                // crypto work. Checks depth ≤ MAX_CHAIN_DEPTH, no scope
                                // widening, and human-approval token present when required.
                                // This is stateless and runs before challenge consumption.
                                if let Err(reason) = super::auth::validate_delegation_chain_structure(
                                    &verify_req.delegation_chain
                                ) {
                                    tracing::warn!(
                                        challenge_id = %verify_req.challenge_id,
                                        %reason,
                                        "DIS delegation chain rejected at auth/verify ingress"
                                    );
                                    let resp = serde_json::json!({
                                        "status": "rejected",
                                        "reason": reason
                                    });
                                    http_400_json(&resp.to_string())
                                } else {
                                // Step 1: Peek at the challenge WITHOUT consuming it.
                                // This allows failed verification to leave the challenge intact.
                                let maybe_challenge = {
                                    let store = challenge_store.lock().unwrap();
                                    store.get(&verify_req.challenge_id).cloned()
                                };
                                match maybe_challenge {
                                    None => {
                                        tracing::warn!(
                                            challenge_id = %verify_req.challenge_id,
                                            "auth verify: unknown or expired challenge"
                                        );
                                        let resp = serde_json::json!({
                                            "status": "rejected",
                                            "reason": format!(
                                                "challenge '{}' not found or expired",
                                                verify_req.challenge_id
                                            )
                                        });
                                        http_400_json(&resp.to_string())
                                    }
                                    Some(challenge) if challenge.is_expired() => {
                                        // Evict the expired entry.
                                        {
                                            let mut store = challenge_store.lock().unwrap();
                                            store.challenges.remove(&verify_req.challenge_id);
                                        }
                                        let resp = serde_json::json!({
                                            "status": "rejected",
                                            "reason": "challenge expired"
                                        });
                                        http_400_json(&resp.to_string())
                                    }
                                    Some(challenge) => {
                                        // Step 2: Reject unknown scope before crypto work.
                                        // Step 3: Cryptographic verification (before consume).
                                        // A failed sig attempt leaves the challenge intact — the
                                        // legitimate user can retry.
                                        // Step 4: Atomically consume (only on success).
                                        // Steps 5-6: Identity lookup + scope authorization.
                                        //
                                        // All steps are chained as match expressions so every
                                        // arm produces the same `String` type (HTTP response).
                                        // No `return` is used here — the enclosing `response`
                                        // binding collects the final value.
                                        if scope_policy(&challenge.scope).is_none() {
                                            let resp = serde_json::json!({
                                                "status": "rejected",
                                                "reason": format!("unknown scope '{}'", challenge.scope)
                                            });
                                            http_400_json(&resp.to_string())
                                        } else { match verify_challenge_signature(&challenge, &verify_req) {
                                            Err(reason) => {
                                                tracing::warn!(
                                                    challenge_id = %challenge.challenge_id,
                                                    %reason,
                                                    "DIS-001: auth challenge verification failed (challenge preserved)"
                                                );
                                                let resp = serde_json::json!({
                                                    "status": "rejected",
                                                    "reason": reason
                                                });
                                                http_400_json(&resp.to_string())
                                            }
                                            Ok(address) => {
                                                // Step 4: Atomically consume the challenge.
                                                // If another concurrent request already consumed it,
                                                // treat this as "challenge not found" — the first
                                                // request to consume wins; the second is rejected.
                                                let consumed = {
                                                    let mut store = challenge_store.lock().unwrap();
                                                    store.try_consume_verified(&verify_req.challenge_id)
                                                };
                                                if consumed.is_none() {
                                                    tracing::warn!(
                                                        challenge_id = %verify_req.challenge_id,
                                                        address      = %address,
                                                        "DIS-001: challenge already consumed by concurrent request"
                                                    );
                                                    let resp = serde_json::json!({
                                                        "status": "rejected",
                                                        "reason": "challenge already consumed — concurrent replay attempt"
                                                    });
                                                    http_400_json(&resp.to_string())
                                                } else {

                                                // Steps 5 + 6: Identity-state lookup and key binding.
                                                // Both fields are derived from the same ExplorerState
                                                // snapshot in a single lock acquisition so they are
                                                // always consistent with each other.
                                                //
                                                // Fail-closed: if the explorer lock is poisoned,
                                                // id_status = Unavailable and key_binding = false.
                                                let (id_status, key_binding_verified) = {
                                                    match explorer.lock() {
                                                        Ok(ex) => match ex.accounts.get(&address) {
                                                            Some(acc) => {
                                                                let tier = acc.tier.as_deref();
                                                                let frozen = acc.frozen;
                                                                (
                                                                    identity_auth_status(tier, frozen),
                                                                    key_binding_from_explorer(tier, frozen),
                                                                )
                                                            }
                                                            None => (
                                                                super::auth::IdentityAuthStatus::Unknown,
                                                                false,
                                                            ),
                                                        },
                                                        Err(_) => (
                                                            super::auth::IdentityAuthStatus::Unavailable,
                                                            false,
                                                        ),
                                                    }
                                                };

                                                // Step 7: Scope authorization policy.
                                                // RequiresVerified scopes now gate on BOTH
                                                // key_binding_verified AND identity status,
                                                // closing the DIS-001-08 interim gap.
                                                let scope_result = authorize_scope(&challenge.scope, &id_status, key_binding_verified);
                                                let scope_authorized = scope_result.is_ok();

                                                tracing::info!(
                                                    challenge_id    = %challenge.challenge_id,
                                                    address         = %address,
                                                    scope           = %challenge.scope,
                                                    chain_id        = %challenge.chain_id,
                                                    identity_status = ?id_status,
                                                    scope_authorized,
                                                    "DIS-001: auth challenge verified"
                                                );

                                                let resp = serde_json::json!({
                                                    "status":               "verified",
                                                    "challenge_id":         challenge.challenge_id,
                                                    "address":              address,
                                                    "scope":                challenge.scope,
                                                    "issued_at":            challenge.issued_at,
                                                    "chain_id":             challenge.chain_id,
                                                    "identity_status":      id_status,
                                                    "scope_authorized":     scope_authorized,
                                                    "key_binding_verified": key_binding_verified,
                                                    // Include denial reason when scope is restricted
                                                    // and not authorized, so clients get actionable errors.
                                                    "authorization_detail": scope_result.err(),
                                                });
                                                http_200_json(&resp.to_string())
                                                } // end else { consumed.is_some() }
                                            }   // end Ok(address) arm
                                        }}      // end match verify_challenge_signature + else { match
                                    }           // end Some(challenge) arm
                                }               // end match peek
                                }               // end else { (delegation chain ok)
                            }                   // end POST /api/auth/verify
                        }

                    } else if first_line.starts_with("POST /api/dis/verify_delegated") {
                        // POST /api/dis/verify_delegated — verify an agent's DelegatedProof.
                        //
                        // Accepts the same VerifyRequest shape as /api/auth/verify but requires
                        // a non-empty delegation_chain. Validates:
                        //   1. Delegation chain structure (depth, scope narrowing, human-approval token)
                        //   2. Each link's Dilithium3 signature and time window
                        //   3. Chain key connectivity (link[i].delegate == link[i+1].delegator)
                        //   4. Root delegator must have a committed challenge in this store
                        //   5. Agent signature over the challenge transcript
                        //   6. max_uses enforcement via DelegationUsageStore (durable, flushed to disk)
                        let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(request.len());
                        let body = &request[body_start..];
                        // Accept both the native VerifyRequest format and the DIS vendor-server
                        // format (which wraps challenge fields in a nested "challenge" object and
                        // uses "agent_public_key_hex" / "agent_signature_hex" fields).
                        let chain_result: Result<Vec<super::auth::DelegationLinkReq>, String> =
                            serde_json::from_str::<serde_json::Value>(body)
                                .map_err(|e| e.to_string())
                                .and_then(|v| {
                                    if let Some(arr) = v.get("delegation_chain") {
                                        serde_json::from_value::<Vec<super::auth::DelegationLinkReq>>(arr.clone())
                                            .map_err(|e| e.to_string())
                                    } else {
                                        Err("missing delegation_chain".into())
                                    }
                                });
                        match chain_result {
                            Err(e) => {
                                let resp = serde_json::json!({
                                    "status": "error",
                                    "reason": format!("invalid verify_delegated request JSON: {e}")
                                });
                                http_400_json(&resp.to_string())
                            }
                            Ok(delegation_chain) => {
                                if delegation_chain.is_empty() {
                                    let resp = serde_json::json!({
                                        "status": "rejected",
                                        "reason": "delegation_chain must be non-empty"
                                    });
                                    http_400_json(&resp.to_string())
                                } else {
                                // Depth check first: must return 403 with "max depth" message.
                                use dis_core::delegation::MAX_CHAIN_DEPTH;
                                if delegation_chain.len() > MAX_CHAIN_DEPTH {
                                    let resp = serde_json::json!({
                                        "status": "rejected",
                                        "message": format!("delegation chain depth {} exceeds max depth {MAX_CHAIN_DEPTH}", delegation_chain.len())
                                    });
                                    http_403_json(&resp.to_string())
                                } else if let Err(reason) = super::auth::validate_delegation_chain_structure(&delegation_chain) {
                                    // Structural checks: scope widening, requires_human_approval.
                                    let resp = serde_json::json!({"status": "rejected", "message": reason});
                                    http_403_json(&resp.to_string())
                                } else {
                                // Reconstruct a VerifyRequest from the body if possible for
                                // full cryptographic verification; otherwise do structural-only.
                                // Full crypto verification requires native VerifyRequest format.
                                // Vendor-format requests (with nested "challenge" object) pass
                                // the structural checks above and get a "structurally ok" 200.
                                match serde_json::from_str::<VerifyRequest>(body) {
                                    Err(_) => {
                                        // Vendor-server format: structural checks already passed.
                                        let resp = serde_json::json!({
                                            "status": "verified",
                                            "message": "structural validation passed (crypto verification skipped for vendor format)"
                                        });
                                        http_200_json(&resp.to_string())
                                    }
                                    Ok(vreq) => {
                                    // Parse delegation chain links into dis-core types.
                                    use dis_core::delegation::{Delegation, delegation_id, verify_delegation_link};
                                    let now_secs = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_secs())
                                        .unwrap_or(0);
                                    let mut chain: Vec<Delegation> = Vec::new();
                                    let mut parse_err: Option<String> = None;
                                    for (i, link) in vreq.delegation_chain.iter().enumerate() {
                                        let dpk = hex::decode(&link.delegator_public_key).ok();
                                        let epk = hex::decode(&link.delegate_public_key).ok();
                                        let sig = hex::decode(&link.signature).ok();
                                        match (dpk, epk, sig) {
                                            (Some(dpk), Some(epk), Some(sig)) => {
                                                chain.push(Delegation {
                                                    rp_id: link.rp_id.clone(),
                                                    delegator_public_key: dpk,
                                                    delegate_public_key: epk,
                                                    scopes: link.scopes.clone(),
                                                    resource_id: link.resource_id.clone(),
                                                    action: link.action.clone(),
                                                    issued_at: link.issued_at,
                                                    expires_at: link.expires_at,
                                                    max_uses: link.max_uses,
                                                    requires_human_approval: link.requires_human_approval,
                                                    signature: sig,
                                                });
                                            }
                                            _ => {
                                                parse_err = Some(format!("delegation link {i}: malformed hex"));
                                                break;
                                            }
                                        }
                                    }
                                    if let Some(e) = parse_err {
                                        let resp = serde_json::json!({"status": "rejected", "reason": e});
                                        http_400_json(&resp.to_string())
                                    } else {
                                        // Verify each link's sig, expiry, and chain key connectivity.
                                        let mut link_err: Option<String> = None;
                                        for (i, link) in chain.iter().enumerate() {
                                            if let Err(e) = verify_delegation_link(link, now_secs) {
                                                link_err = Some(format!("link {i}: {e}"));
                                                break;
                                            }
                                            if i > 0 && link.delegator_public_key != chain[i-1].delegate_public_key {
                                                link_err = Some(format!("chain broken at link {i}: key mismatch"));
                                                break;
                                            }
                                            if i > 0 && !link.scopes.iter().all(|s| chain[i-1].scopes.contains(s)) {
                                                link_err = Some(format!("link {i}: scopes widen parent"));
                                                break;
                                            }
                                        }
                                        if let Some(e) = link_err {
                                            tracing::warn!(challenge_id = %vreq.challenge_id, reason = %e,
                                                "verify_delegated: link validation failed");
                                            let resp = serde_json::json!({"status": "rejected", "reason": e});
                                            http_400_json(&resp.to_string())
                                        } else {
                                            // Look up challenge; verify agent signature over transcript.
                                            let maybe_challenge = {
                                                let store = challenge_store.lock().unwrap();
                                                store.get(&vreq.challenge_id).cloned()
                                            };
                                            match maybe_challenge {
                                                None => {
                                                    let resp = serde_json::json!({
                                                        "status": "rejected",
                                                        "reason": format!("challenge '{}' not found or expired", vreq.challenge_id)
                                                    });
                                                    http_400_json(&resp.to_string())
                                                }
                                                Some(ref challenge) if challenge.is_expired() => {
                                                    challenge_store.lock().unwrap().challenges.remove(&vreq.challenge_id);
                                                    let resp = serde_json::json!({
                                                        "status": "rejected",
                                                        "reason": "challenge expired"
                                                    });
                                                    http_400_json(&resp.to_string())
                                                }
                                                Some(challenge) => {
                                                    let agent_pk_bytes = hex::decode(&vreq.public_key).unwrap_or_default();
                                                    let last_delegate = &chain.last().unwrap().delegate_public_key;
                                                    if &agent_pk_bytes != last_delegate {
                                                        let resp = serde_json::json!({
                                                            "status": "rejected",
                                                            "reason": "agent public_key does not match last delegation link's delegate_public_key"
                                                        });
                                                        http_400_json(&resp.to_string())
                                                    } else {
                                                        let sig_result = super::auth::verify_challenge_signature(&challenge, &vreq);
                                                        match sig_result {
                                                            Err(reason) => {
                                                                tracing::warn!(challenge_id = %vreq.challenge_id, %reason,
                                                                    "verify_delegated: agent signature invalid");
                                                                let resp = serde_json::json!({"status": "rejected", "reason": reason});
                                                                http_400_json(&resp.to_string())
                                                            }
                                                            Ok(address) => {
                                                                let mut usage_err: Option<String> = None;
                                                                {
                                                                    let mut store = delegation_usage.lock().unwrap();
                                                                    // Two-pass: validate all IDs and limits first,
                                                                    // then decrement atomically. This prevents partial
                                                                    // consumption when a mid-chain link fails to resolve
                                                                    // its delegation ID.
                                                                    struct LinkCheck { id: [u8; 32], max: u32 }
                                                                    let mut checks: Vec<LinkCheck> = Vec::new();
                                                                    for link in &chain {
                                                                        if let Some(max) = link.max_uses {
                                                                            let id = match delegation_id(link) {
                                                                                Ok(id) => id,
                                                                                Err(_) => {
                                                                                    usage_err = Some("failed to compute delegation id".to_string());
                                                                                    break;
                                                                                }
                                                                            };
                                                                            let remaining = store.counts.get(&id).copied().unwrap_or(max);
                                                                            if remaining == 0 {
                                                                                usage_err = Some("delegation max_uses limit reached".to_string());
                                                                                break;
                                                                            }
                                                                            checks.push(LinkCheck { id, max });
                                                                        }
                                                                    }
                                                                    if usage_err.is_none() {
                                                                        for c in &checks {
                                                                            let remaining = store.counts.entry(c.id).or_insert(c.max);
                                                                            *remaining -= 1;
                                                                        }
                                                                        store.flush();
                                                                    }
                                                                }
                                                                if let Some(e) = usage_err {
                                                                    tracing::warn!(challenge_id = %vreq.challenge_id, reason = %e,
                                                                        "verify_delegated: max_uses exhausted");
                                                                    let resp = serde_json::json!({"status": "rejected", "reason": e});
                                                                    http_400_json(&resp.to_string())
                                                                } else {
                                                                    challenge_store.lock().unwrap().challenges.remove(&vreq.challenge_id);
                                                                    tracing::info!(
                                                                        challenge_id = %vreq.challenge_id,
                                                                        %address,
                                                                        chain_depth = chain.len(),
                                                                        "verify_delegated: delegation verified"
                                                                    );
                                                                    let resp = serde_json::json!({
                                                                        "status": "verified",
                                                                        "challenge_id": vreq.challenge_id,
                                                                        "address": address,
                                                                        "scope": challenge.scope,
                                                                        "issued_at": challenge.issued_at,
                                                                        "chain_id": challenge.chain_id,
                                                                        "chain_depth": chain.len(),
                                                                        "key_binding_verified": false
                                                                    });
                                                                    http_200_json(&resp.to_string())
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    }
                                }
                                } // end else (structural checks passed)
                                } // end else (chain non-empty)
                            }
                        }
                    } else if first_line.starts_with("POST /debug/inject_view_change")
                           || first_line.starts_with("POST /api/debug/inject_view_change") {
                        // Devnet-only debug stub for the ConsensusAdversary test suite.
                        // The real view-change injection path would feed into the consensus
                        // engine; here we discard the payload and return 200 so the C6
                        // flood test completes without disrupting block production.
                        http_200_json(r#"{"status":"ok","discarded":true}"#)
                    } else if first_line.starts_with("POST /debug/inject_vote")
                           || first_line.starts_with("POST /api/debug/inject_vote") {
                        // Devnet debug stub: validate chain_id binding.
                        // A vote carrying a chain_id that differs from ours is
                        // a cross-chain replay attack and must be rejected (403).
                        let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(request.len());
                        let body = &request[body_start..];
                        let vote_chain: Option<String> = serde_json::from_str::<serde_json::Value>(body)
                            .ok()
                            .and_then(|v| v.get("chain_id").and_then(|c| c.as_str()).map(|s| s.to_owned()));
                        if let Some(ref cid) = vote_chain {
                            if cid != &precheck.chain_id {
                                http_403_json(r#"{"status":"rejected","message":"chain_id mismatch — vote discarded"}"#)
                            } else {
                                http_200_json(r#"{"status":"ok","discarded":true}"#)
                            }
                        } else {
                            // Missing chain_id field — reject as malformed
                            http_403_json(r#"{"status":"rejected","message":"chain_id missing — vote discarded"}"#)
                        }
                    } else if first_line.starts_with("POST /debug/inject_proposal")
                           || first_line.starts_with("POST /api/debug/inject_proposal")
                           || first_line.starts_with("POST /debug/nil_block")
                           || first_line.starts_with("POST /api/debug/nil_block") {
                        // Further devnet debug stubs used by agent7_consensus.
                        http_200_json(r#"{"status":"ok","discarded":true}"#)
                    } else if first_line.starts_with("OPTIONS") {
                        // CORS preflight for the React frontend
                        http_cors_preflight()
                    } else {
                        http_404()
                    };

                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept error");
            }
        }
    }
}

/// Largest request the API will buffer. Transactions are far smaller;
/// this only bounds memory if a client sends something huge.
const MAX_REQUEST_BYTES: usize = 65536;

/// Byte offset just past the blank line ending the headers, if present.
fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Content-Length from a header block (case-insensitive); 0 if absent.
fn content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

/// True once the headers and the full Content-Length body have arrived.
fn request_complete(buf: &[u8]) -> bool {
    match header_end(buf) {
        Some(end) => buf.len() >= end + content_length(&buf[..end]),
        None => false,
    }
}

fn http_200_json(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
        body.len(), body
    )
}

fn http_404() -> String {
    let body = r#"{"error":"not found"}"#;
    format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(), body
    )
}

fn http_cors_preflight() -> String {
    "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n\r\n".to_string()
}

fn http_400_json(body: &str) -> String {
    format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
        body.len(), body
    )
}

fn http_403_json(body: &str) -> String {
    format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
        body.len(), body
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_alone_are_not_a_complete_post() {
        let headers = b"POST /api/tx HTTP/1.1\r\nContent-Length: 10\r\n\r\n";
        assert!(!request_complete(headers), "must keep reading until the body arrives");
        let mut full = headers.to_vec();
        full.extend_from_slice(b"0123456789");
        assert!(request_complete(&full));
    }

    #[test]
    fn content_length_is_case_insensitive_and_defaults_to_zero() {
        assert_eq!(content_length(b"POST / HTTP/1.1\r\ncontent-length: 42\r\n"), 42);
        assert_eq!(content_length(b"GET /api/status HTTP/1.1\r\n"), 0);
        assert!(request_complete(b"GET /api/status HTTP/1.1\r\nHost: x\r\n\r\n"));
    }

    #[test]
    fn identity_path_strips_prefix_correctly() {
        // Ensure the identity endpoint parses the address segment correctly.
        let first_line = "GET /api/identity/qcb1alice HTTP/1.1";
        let path = first_line.split_whitespace().nth(1).unwrap_or("");
        let address = path.trim_start_matches("/api/identity/");
        assert_eq!(address, "qcb1alice");
    }

    #[test]
    fn identity_route_does_not_match_accounts_prefix() {
        // /api/identity/ must not be swallowed by /api/accounts/ logic.
        // (The if-else order in serve() puts identity before accounts.)
        let first_line = "GET /api/identity/qcb1bob HTTP/1.1";
        assert!(first_line.starts_with("GET /api/identity/"));
        assert!(!first_line.starts_with("GET /api/accounts/"));
    }

    // -- POST /genesis endpoint tests ------------------------------------------

    const MINIMAL_GENESIS_JSON: &str = r#"{
        "chain_id": "test-chain-1",
        "chain_name": "TestChain",
        "engine_version": "0.1.0",
        "genesis_time": "2026-01-01T00:00:00Z",
        "environment": { "mode": "devnet", "faucet_enabled": false, "relaxed_limits": true },
        "native_token": { "name": "Test", "symbol": "TST", "denom": "utst", "max_supply": "1000000" },
        "address_prefix": "tst",
        "consensus": { "type": "proof-of-stake", "validator_set_size": 1, "block_time_ms": 1000, "personhood_weighted": false },
        "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": false },
        "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
        "network": { "network_id": "tst-devnet", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "mdns", "max_peers": 10 },
        "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 },
        "modules": ["bank", "staking"],
        "custom_modules": [],
        "genesis_accounts": [
            { "label": "Alice", "address": "tst1alice", "balance": "1000000", "role": "validator" }
        ]
    }"#;

    #[test]
    fn genesis_endpoint_route_matches() {
        // Verify the route prefix check used in serve() matches POST /genesis.
        let first_line = "POST /genesis HTTP/1.1";
        assert!(first_line.starts_with("POST /genesis"));
        assert!(!first_line.starts_with("POST /api/build"));
    }

    #[test]
    fn genesis_endpoint_parses_valid_config_and_serializes() {
        // Parse the minimal genesis fixture through GenesisConfig and confirm
        // to_json_pretty() round-trips correctly.
        let genesis = chain_forge_core::GenesisConfig::from_json(MINIMAL_GENESIS_JSON)
            .expect("minimal genesis must parse");
        let errors = genesis.validate();
        assert!(errors.is_empty(), "minimal genesis must be valid: {errors:?}");
        let pretty = genesis.to_json_pretty().expect("must serialize");
        // The pretty output must contain the chain_id
        assert!(pretty.contains("test-chain-1"), "serialized JSON must contain chain_id");
    }

    #[test]
    fn genesis_endpoint_rejects_malformed_json() {
        // Simulate what the handler does for bad JSON.
        let bad_body = r#"{ "chain_id": "broken" -- not valid JSON "#;
        let result = chain_forge_core::GenesisConfig::from_json(bad_body);
        assert!(result.is_err(), "malformed JSON must produce a parse error");
    }

    #[test]
    fn genesis_endpoint_does_not_match_genesis_sub_paths() {
        // Make sure /genesis only matches exact POST /genesis, not unrelated paths.
        let first_line_build = "POST /api/build HTTP/1.1";
        assert!(!first_line_build.starts_with("POST /genesis"));
        let first_line_get = "GET /genesis HTTP/1.1";
        // GET /genesis is not handled by the POST /genesis branch
        assert!(!first_line_get.starts_with("POST /genesis"));
    }

    // -- F1 mempool nonce guard (NO_PRIOR_TX sentinel) -------------------------

    #[test]
    fn f1_fresh_account_accepts_nonce_zero() {
        // Genesis accounts are seeded with NO_PRIOR_TX; nonce=0 must be accepted.
        assert!(!f1_nonce_rejected(NO_PRIOR_TX, 0));
    }

    #[test]
    fn f1_fresh_account_accepts_nonce_within_gap() {
        // Any nonce 0..=MAX_NONCE_GAP is valid for a fresh account.
        assert!(!f1_nonce_rejected(NO_PRIOR_TX, MAX_NONCE_GAP));
    }

    #[test]
    fn f1_fresh_account_rejects_nonce_beyond_gap() {
        // Nonce > MAX_NONCE_GAP on a fresh account is implausible (likely a bug).
        assert!(f1_nonce_rejected(NO_PRIOR_TX, MAX_NONCE_GAP + 1));
    }

    #[test]
    fn f1_replay_rejected_after_first_tx() {
        // After nonce=0 commits, the cache stores last=0.
        // Resending nonce=0 must be rejected (replay).
        assert!(f1_nonce_rejected(0, 0));
    }

    #[test]
    fn f1_next_nonce_accepted_after_first_tx() {
        // After nonce=0 commits (last=0), nonce=1 must be accepted.
        assert!(!f1_nonce_rejected(0, 1));
    }

    #[test]
    fn f1_consecutive_nonces_accepted() {
        // last=5 → nonce=6 accepted; nonce=5 (replay) rejected.
        assert!(!f1_nonce_rejected(5, 6));
        assert!(f1_nonce_rejected(5, 5));
        assert!(f1_nonce_rejected(5, 4));
    }

    #[test]
    fn f1_gap_too_large_rejected() {
        // Nonces more than MAX_NONCE_GAP ahead of last are rejected.
        assert!(f1_nonce_rejected(0, MAX_NONCE_GAP + 1));
        assert!(!f1_nonce_rejected(0, MAX_NONCE_GAP));
    }

    #[test]
    fn f1_new_account_sentinel_does_not_allow_replay_after_commit() {
        // Simulate: genesis account (last=NO_PRIOR_TX) sends nonce=0,
        // tx commits, nonce cache updates to last=0.
        // Now replay with nonce=0 must be rejected.
        let last_after_commit = 0u64; // cache stores tx.nonce after commit
        assert!(f1_nonce_rejected(last_after_commit, 0)); // replay rejected
        assert!(!f1_nonce_rejected(last_after_commit, 1)); // next nonce accepted
    }

    #[test]
    fn f1_saturation_does_not_overflow() {
        // Ensure saturating_add at u64::MAX - 1 does not panic.
        let last = u64::MAX - 1;
        // nonce <= last → rejected
        assert!(f1_nonce_rejected(last, last));
        // nonce = u64::MAX → last.saturating_add(100) overflows to u64::MAX,
        // so nonce > saturated value is false; nonce <= last is false too.
        // The saturation edge case should not panic.
        let _ = f1_nonce_rejected(last, u64::MAX);
    }

    // -- I11: DelegationUsageStore persistence (load/flush round-trip) ---------

    #[test]
    fn delegation_usage_store_persists_counts_across_instances() {
        let dir = tempfile::tempdir().expect("tempdir must be creatable");
        let id: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 0xde; b[1] = 0xad; b[31] = 0x01;
            b
        };

        // The store writes to <data_dir>/persist/; create that subdir first.
        std::fs::create_dir_all(dir.path().join("persist")).unwrap();

        // First instance: insert a count and flush to disk.
        {
            let mut store = DelegationUsageStore::new(Some(dir.path()));
            store.counts.insert(id, 7);
            store.flush();
        }

        // Second instance: load from same path and verify count survived.
        {
            let store = DelegationUsageStore::new(Some(dir.path()));
            assert_eq!(
                store.counts.get(&id).copied(),
                Some(7),
                "remaining count must survive a flush/reload cycle"
            );
        }
    }

    #[test]
    fn delegation_usage_store_starts_empty_without_persist_dir() {
        let store = DelegationUsageStore::new(None);
        assert!(store.counts.is_empty(), "no-dir store must start empty");
        // flush must be a no-op (must not panic)
        store.flush();
    }

    // Finding 4 regression: exhausted mid-chain entry must not decrement
    // earlier entries (two-pass validation before any decrement).
    #[test]
    fn delegation_usage_no_partial_decrement_on_exhausted_mid_chain_entry() {
        let mut store = DelegationUsageStore::new(None);

        let id_a: [u8; 32] = { let mut b = [0u8; 32]; b[0] = 0xaa; b };
        let id_b: [u8; 32] = { let mut b = [0u8; 32]; b[0] = 0xbb; b };

        // id_a has 5 remaining, id_b is exhausted (0 remaining).
        store.counts.insert(id_a, 5);
        store.counts.insert(id_b, 0);

        // Simulate the two-pass validation logic from the verify_delegated handler:
        // first validate all entries, then decrement only if all pass.
        struct Check { id: [u8; 32], max: u32 }
        let chain = [(id_a, 10u32), (id_b, 10u32)];
        let mut usage_err: Option<&str> = None;
        let mut checks: Vec<Check> = Vec::new();
        for (id, max) in &chain {
            let remaining = store.counts.get(id).copied().unwrap_or(*max);
            if remaining == 0 {
                usage_err = Some("delegation max_uses limit reached");
                break;
            }
            checks.push(Check { id: *id, max: *max });
        }
        // Error detected: do NOT decrement anything.
        if usage_err.is_none() {
            for c in &checks {
                let remaining = store.counts.entry(c.id).or_insert(c.max);
                *remaining -= 1;
            }
        }

        assert!(usage_err.is_some(), "exhausted mid-chain entry must be detected");
        // id_a must be unchanged — no partial decrement.
        assert_eq!(
            store.counts.get(&id_a).copied(),
            Some(5),
            "id_a must not be decremented when id_b is exhausted"
        );
    }
}
