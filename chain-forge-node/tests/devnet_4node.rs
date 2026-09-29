//! 4-node devnet integration test.
//!
//! Spawns four `chain-forge-node` processes (Alice, Bob, Carol, Dave) against
//! `tests/devnet/genesis-4node.json`, then polls each node's `/api/status`
//! endpoint until all four report `height >= TARGET_HEIGHT` or the test times out.
//!
//! This is the first end-to-end proof that the real libp2p gossip layer works —
//! real TCP connections, real mDNS peer discovery, real proposal/vote/commit
//! round-trips across separate OS processes.
//!
//! Run:
//!   cargo test --test devnet_4node -- --nocapture
//!
//! The test is skipped (not failed) in environments where the binary isn't built
//! yet, so it never breaks a `cargo test --workspace` that hasn't run `cargo build`
//! first.  The `--ignored` flag is NOT used — the test is always attempted if the
//! binary exists.
//!
//! Environment variables:
//!   DEVNET_TIMEOUT_SECS   — seconds to wait (default: 60)
//!   DEVNET_TARGET_HEIGHT  — height all nodes must reach (default: 3)

use std::{
    collections::HashMap,
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// Validators in the 4-node genesis.
const VALIDATORS: &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
/// HTTP API ports — one per node, well away from common ports.
const API_PORTS: &[u16] = &[18080, 18081, 18082, 18083];
/// P2P ports — each node binds a distinct one.
const P2P_PORTS: &[u16] = &[27000, 27001, 27002, 27003];

/// Target chain height all four nodes must reach.
const DEFAULT_TARGET_HEIGHT: u64 = 3;
/// Seconds to wait before declaring the test failed.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

// ── Helpers ------------------------------------------------------------------

fn repo_root() -> PathBuf {
    // This file lives at <repo>/chain-forge-node/tests/devnet_4node.rs.
    // `CARGO_MANIFEST_DIR` is <repo>/chain-forge-node.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().to_path_buf()
}

fn node_binary() -> PathBuf {
    // `cargo test` sets CARGO_TARGET_DIR or we fall back to the default.
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    // Check debug first (most common for `cargo test`), then release.
    let debug   = target.join("debug").join("chain-forge-node");
    let release = target.join("release").join("chain-forge-node");
    if release.exists() { release } else { debug }
}

fn genesis_path() -> PathBuf {
    repo_root().join("tests").join("devnet").join("genesis-4node.json")
}

/// Wait up to `timeout` for a TCP port on 127.0.0.1 to accept connections.
fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// GET /api/status and parse `height` out of the JSON response.
/// Returns None if the request fails or the field is missing.
fn poll_height(api_port: u16) -> Option<u64> {
    let _url = format!("http://127.0.0.1:{api_port}/api/status");
    // Use a hand-rolled GET so we don't need reqwest/ureq in the test binary.
    use std::io::{BufRead, Write};
    let mut stream = TcpStream::connect(format!("127.0.0.1:{api_port}")).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    let request = format!(
        "GET /api/status HTTP/1.0\r\nHost: 127.0.0.1:{api_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;

    let mut body = String::new();
    let reader = std::io::BufReader::new(stream);
    let mut past_headers = false;
    for line in reader.lines() {
        let line = line.ok()?;
        if past_headers {
            body.push_str(&line);
        } else if line.is_empty() {
            past_headers = true;
        }
    }

    // Parse `"height":<number>` — good enough without pulling in serde.
    body.split("\"height\":")
        .nth(1)
        .and_then(|s| s.split([',', '}']).next())
        .and_then(|s| s.trim().parse().ok())
}

/// Ensure a port is free before we try to bind it.
fn port_is_free(port: u16) -> bool {
    TcpStream::connect(format!("127.0.0.1:{port}")).is_err()
}

// ── RAII process guard -------------------------------------------------------

struct NodeProcess {
    validator: &'static str,
    child: Child,
    api_port: u16,
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        // Best-effort SIGTERM, then SIGKILL.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── The test -----------------------------------------------------------------

#[test]
fn devnet_4node_reaches_target_height() {
    let bin = node_binary();
    if !bin.exists() {
        println!(
            "SKIP: node binary not found at {bin:?}. \
             Run `cargo build --bin chain-forge-node` first."
        );
        return;
    }

    let genesis = genesis_path();
    assert!(
        genesis.exists(),
        "genesis file not found: {genesis:?}"
    );

    // Check all ports are free — if not, a previous run leaked processes.
    for port in API_PORTS.iter().chain(P2P_PORTS.iter()) {
        assert!(
            port_is_free(*port),
            "port {port} is already in use — kill any stray node processes first"
        );
    }

    let timeout = Duration::from_secs(
        std::env::var("DEVNET_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS),
    );
    let target_height: u64 = std::env::var("DEVNET_TARGET_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TARGET_HEIGHT);

    println!(
        "\n── 4-node devnet integration test ──────────────────────────────────\n\
           binary:        {bin:?}\n\
           genesis:       {genesis:?}\n\
           target_height: {target_height}\n\
           timeout:       {timeout:?}\n"
    );

    // ── Spawn 4 nodes --------------------------------------------------------
    let log_dir = std::env::temp_dir().join("qcb-devnet-4node");
    std::fs::create_dir_all(&log_dir).unwrap();

    let mut nodes: Vec<NodeProcess> = Vec::new();

    for (i, &validator) in VALIDATORS.iter().enumerate() {
        let api_port = API_PORTS[i];
        let p2p_port = P2P_PORTS[i];
        let log_path = log_dir.join(format!("{validator}.log"));
        let log_file = std::fs::File::create(&log_path)
            .unwrap_or_else(|e| panic!("cannot create log {log_path:?}: {e}"));

        println!("   Starting {validator}  api=:{api_port}  p2p=:{p2p_port}  log={log_path:?}");

        let child = Command::new(&bin)
            .args([
                "--genesis",   genesis.to_str().unwrap(),
                "--validator", validator,
                "--api-port",  &api_port.to_string(),
                "--p2p-port",  &p2p_port.to_string(),
            ])
            .stdout(log_file.try_clone().unwrap())
            .stderr(log_file)
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {validator}: {e}"));

        nodes.push(NodeProcess { validator, child, api_port });
    }

    // ── Wait for API ports to bind -------------------------------------------
    println!("\n   Waiting for API ports to bind...");
    for node in &nodes {
        assert!(
            wait_for_port(node.api_port, Duration::from_secs(15)),
            "{} API port :{} never opened",
            node.validator, node.api_port
        );
        println!("   {} API is up on :{}", node.validator, node.api_port);
    }
    println!();

    // ── Poll until all nodes reach target_height ------------------------------
    println!("   Polling /api/status (target: height >= {target_height})...\n");

    let start = Instant::now();
    let mut heights: HashMap<&str, u64> = HashMap::new();

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            // Print final state and fail.
            println!("\nTIMEOUT after {elapsed:.1?}");
            for node in &nodes {
                let h = heights.get(node.validator).copied().unwrap_or(0);
                println!("   {}  height={h}  (need {target_height})", node.validator);
            }

            // Dump last lines of logs for diagnosis.
            for node in &nodes {
                let log_path = log_dir.join(format!("{}.log", node.validator));
                println!("\n── {} log (last 30 lines) ─────────────────────────────", node.validator);
                if let Ok(content) = std::fs::read_to_string(&log_path) {
                    let lines: Vec<_> = content.lines().collect();
                    let start_line = lines.len().saturating_sub(30);
                    for line in &lines[start_line..] {
                        println!("{line}");
                    }
                }
            }

            panic!(
                "4-node devnet did not reach height {target_height} within {timeout:?}"
            );
        }

        // Check each node.
        let mut all_reached = true;
        let mut status = String::new();

        for node in &mut nodes {
            // Detect crashed node.
            if let Ok(Some(exit)) = node.child.try_wait().map_err(|_| ()) {
                // Re-check — if it exited with success it may have been a
                // deliberate shutdown; otherwise it's a crash.
                panic!(
                    "{} exited unexpectedly with status: {exit}",
                    node.validator
                );
            }

            let h = poll_height(node.api_port).unwrap_or(0);
            heights.insert(node.validator, h);

            status.push_str(&format!("  {}={h}", node.validator));
            if h < target_height {
                all_reached = false;
            }
        }

        print!("\r   [{:>4.1}s]{status}   ", elapsed.as_secs_f32());
        std::io::Write::flush(&mut std::io::stdout()).ok();

        if all_reached {
            println!(
                "\n\n── All 4 nodes reached height {target_height} in {:.1?} ─────────────",
                start.elapsed()
            );
            for node in &nodes {
                println!("   {}  height={}", node.validator, heights[node.validator]);
            }
            println!();
            return; // PASS — NodeProcess::drop() kills the children.
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}
