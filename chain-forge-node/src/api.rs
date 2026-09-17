/// HTTP API for the Chain Forge node.
///
/// Phase 0: minimal status endpoint. The Chain Forge wizard frontend
/// calls POST /api/build with a genesis JSON to trigger a chain build,
/// and GET /api/status to check node health.
///
/// Phase 1 will add: streaming build logs, node start/stop, validator
/// key management, and a WebSocket feed for the explorer.

use std::sync::{Arc, Mutex};
use super::node::NodeStatus;

/// Serve the HTTP API on the given port.
/// Phase 0 implementation: a minimal hand-rolled HTTP server that handles
/// the two endpoints the wizard frontend needs, without pulling in a full
/// web framework (saves ~50MB of compile-time dependencies for Phase 0).
pub async fn serve(port: u16, status: Arc<Mutex<NodeStatus>>) {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = format!("127.0.0.1:{port}");
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
                let status = status.clone();

                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = match stream.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };

                    let request = String::from_utf8_lossy(&buf[..n]);
                    let first_line = request.lines().next().unwrap_or("");

                    let response = if first_line.starts_with("GET /api/status") {
                        let s = status.lock().unwrap();
                        let body = serde_json::to_string(&*s).unwrap_or_default();
                        http_200_json(&body)
                    } else if first_line.starts_with("GET /api/health") {
                        http_200_json(r#"{"status":"ok"}"#)
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
