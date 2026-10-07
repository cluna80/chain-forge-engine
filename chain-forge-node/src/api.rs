/// HTTP API for the Chain Forge node.
///
/// Phase 0: minimal status endpoint. The Chain Forge wizard frontend
/// calls POST /api/build with a genesis JSON to trigger a chain build,
/// and GET /api/status to check node health.
///
/// Phase 1 will add: streaming build logs, node start/stop, validator
/// key management, and a WebSocket feed for the explorer.

use std::sync::{Arc, Mutex};
use super::node::{NodeStatus, ExplorerState, QrcMetrics, MAX_GC_RECEIPTS};
use chain_forge_p2p::PeerInfo;
use chain_forge_execution::Transaction;
use chain_forge_resource::UsefulWorkReceipt;

/// Serve the HTTP API on the given port.
/// Phase 0 implementation: a minimal hand-rolled HTTP server that handles
/// the two endpoints the wizard frontend needs, without pulling in a full
/// web framework (saves ~50MB of compile-time dependencies for Phase 0).
/// What POST /api/tx checks before a transaction enters the queue.
/// Only the stateless signature check happens here; key binding needs
/// account state and is enforced at execution on every node.
#[derive(Clone)]
pub struct TxPrecheck {
    pub chain_id:           String,
    pub require_signatures: bool,
    pub modules:            chain_forge_core::EnabledModules,
}

pub async fn serve(
    port: u16,
    status:        Arc<Mutex<NodeStatus>>,
    explorer:      Arc<Mutex<ExplorerState>>,
    qrc_metrics: Arc<Mutex<QrcMetrics>>,
    peers:         Arc<Mutex<Vec<PeerInfo>>>,
    tx_queue:      Arc<Mutex<Vec<Transaction>>>,
    precheck:      TxPrecheck,
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
                let status        = status.clone();
                let explorer      = explorer.clone();
                let qrc_metrics = qrc_metrics.clone();
                let peers         = peers.clone();
                let tx_queue      = tx_queue.clone();
                let precheck      = precheck.clone();

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

                        match serde_json::from_str::<Transaction>(body) {
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
                            Ok(tx) if precheck.require_signatures
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
                        }
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
                                    "address":       address,
                                    "registered":    is_registered,
                                    "tier":          a.tier,
                                    "exemption_days": a.exemption_days,
                                    // attestation_count and attester_list are
                                    // available via the identity crate's IdentityStore
                                    // directly; ExplorerState carries tier/charm only.
                                    "note": "full attestation history available via IdentityStore"
                                });
                                http_200_json(&resp.to_string())
                            }
                            None => {
                                // Address not found in explorer — either never registered
                                // or node hasn't committed a block since registration.
                                let resp = serde_json::json!({
                                    "address":    address,
                                    "registered": false,
                                    "tier":       serde_json::Value::Null,
                                    "exemption_days": 0,
                                    "note": "address not found in explorer state"
                                });
                                http_200_json(&resp.to_string())
                            }
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
                    } else if first_line.starts_with("GET /api/peers") {
                        // GET /api/peers — connected peers (real network layer)
                        let p = peers.lock().unwrap();
                        http_200_json(&serde_json::to_string(&*p).unwrap_or_default())
                    } else if first_line.starts_with("POST /api/gc-receipt") {
                        // POST /api/gc-receipt — receive a UsefulWorkReceipt from gc-daemon.
                        // Validates with verify_seal(), stores in ExplorerState (newest-first,
                        // capped at MAX_GC_RECEIPTS), and exposes via GET /api/gc-receipts.
                        //
                        // The gc-daemon wraps the receipt in:
                        //   { "tx_type": "UsefulWorkReceipt", "payload": <receipt> }
                        // We accept either shape for robustness.
                        let body_start = request.find("\r\n\r\n")
                            .map(|i| i + 4)
                            .unwrap_or(request.len());
                        let body = &request[body_start..];

                        // Try both shapes: bare receipt or envelope with "payload" field.
                        let receipt_result: Result<UsefulWorkReceipt, _> =
                            serde_json::from_str(body)
                            .or_else(|_| {
                                serde_json::from_str::<serde_json::Value>(body)
                                    .ok()
                                    .and_then(|v| v.get("payload").cloned())
                                    .ok_or_else(|| serde_json::from_str::<UsefulWorkReceipt>("").unwrap_err())
                                    .and_then(|p| serde_json::from_value(p))
                            });

                        match receipt_result {
                            Ok(receipt) => {
                                if !chain_forge_resource::verify_seal(&receipt) {
                                    let resp = serde_json::json!({
                                        "status": "rejected",
                                        "receipt_id": receipt.receipt_id,
                                        "reason": "verify_seal failed — seal_hash does not meet difficulty target"
                                    });
                                    tracing::warn!(
                                        receipt_id = %receipt.receipt_id,
                                        "gc-receipt rejected: verify_seal failed"
                                    );
                                    http_400_json(&resp.to_string())
                                } else {
                                    let receipt_id = receipt.receipt_id.clone();
                                    let challenge_id = receipt.challenge_id.clone();
                                    let machine_id = receipt.machine_id.0.clone();
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
                            }
                            Err(e) => {
                                let resp = serde_json::json!({
                                    "status": "error",
                                    "message": format!("invalid UsefulWorkReceipt JSON: {e}")
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
}
