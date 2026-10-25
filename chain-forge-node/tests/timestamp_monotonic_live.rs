//! P0-7 — Block Timestamp Monotonicity Regression Test
//!
//! Proves that every block committed to the chain has a strictly increasing
//! `timestamp_ms` as reported by `/api/blocks`, regardless of which node
//! proposed the block or any clock drift between proposers.
//!
//! ## What is tested
//!
//! **P0-7 — No timestamp regression across proposers:**
//!   1. Spin up a 4-node devnet (standard genesis-mldsa.json).
//!   2. Wait for ≥ 6 committed blocks to accumulate.
//!   3. Fetch `/api/blocks` from all 4 nodes.
//!   4. Assert that within each node's block list, every block's `timestamp_ms`
//!      is strictly greater than the previous block's `timestamp_ms`.
//!   5. Assert that all nodes agree on the same timestamps for the same heights.
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test timestamp_monotonic_live -- --nocapture
//! ```

use std::{
    collections::HashMap,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// ── Port allocation ───────────────────────────────────────────────────────────

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("free_port: bind failed")
        .local_addr()
        .expect("free_port: local_addr")
        .port()
}

struct DevnetPorts {
    alice_api: u16, alice_p2p: u16,
    bob_api:   u16, bob_p2p:   u16,
    carol_api: u16, carol_p2p: u16,
    dave_api:  u16, dave_p2p:  u16,
}

impl DevnetPorts {
    fn new() -> Self {
        Self {
            alice_api: free_port(), alice_p2p: free_port(),
            bob_api:   free_port(), bob_p2p:   free_port(),
            carol_api: free_port(), carol_p2p: free_port(),
            dave_api:  free_port(), dave_p2p:  free_port(),
        }
    }
    fn all_api(&self) -> [u16; 4] {
        [self.alice_api, self.bob_api, self.carol_api, self.dave_api]
    }
}

// ── File / path helpers ───────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().to_path_buf()
}

fn node_binary() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let debug   = target.join("debug").join(&exe);
    let release = target.join("release").join(&exe);
    match (debug.metadata().and_then(|m| m.modified()),
           release.metadata().and_then(|m| m.modified())) {
        (Ok(dt), Ok(rt)) => if dt >= rt { debug } else { release },
        (Ok(_),  Err(_)) => debug,
        (Err(_), Ok(_))  => release,
        _                => debug,
    }
}

fn genesis_path() -> PathBuf {
    repo_root().join("tests").join("devnet").join("genesis-mldsa.json")
}

fn key_file(label: &str) -> PathBuf {
    repo_root().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json"))
}

fn skip_if_no_binary() -> bool {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("SKIP: node binary not found at {bin:?}. Run `cargo build -p chain-forge-node` first.");
        return true;
    }
    false
}

// ── Node lifecycle ────────────────────────────────────────────────────────────

struct NodeHandle {
    name:    String,
    process: Child,
    log_dir: PathBuf,
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn spawn_node(
    name:     &str,
    api_port: u16,
    p2p_port: u16,
    log_dir:  &PathBuf,
    peers:    &[u16],
    key_file: Option<PathBuf>,
) -> NodeHandle {
    let log_path = log_dir.join(format!("{name}.log"));
    let log_file = std::fs::File::create(&log_path)
        .expect("create log file");

    let bootstrap: Vec<String> = peers.iter()
        .map(|&p| format!("/ip4/127.0.0.1/tcp/{p}"))
        .collect();

    let mut cmd = Command::new(node_binary());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator").arg(name)
       .arg("--api-port").arg(api_port.to_string())
       .arg("--p2p-port").arg(p2p_port.to_string());
    for addr in &bootstrap {
        cmd.arg("--bootstrap").arg(addr);
    }
    if let Some(kf) = key_file {
        cmd.arg("--key-file").arg(kf);
    }
    cmd.stdout(log_file.try_clone().unwrap())
       .stderr(log_file)
       .stdin(Stdio::null());

    let process = cmd.spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {name}: {e}"));
    NodeHandle { name: name.to_string(), process, log_dir: log_dir.clone() }
}

fn spawn_devnet(ports: &DevnetPorts, log_dir: &PathBuf) -> Vec<NodeHandle> {
    let kf = |label: &str| Some(key_file(label));
    vec![
        spawn_node("qcb1alice", ports.alice_api, ports.alice_p2p, log_dir,
                   &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p], kf("alice")),
        spawn_node("qcb1bob",   ports.bob_api,   ports.bob_p2p,   log_dir,
                   &[ports.alice_p2p, ports.carol_p2p, ports.dave_p2p], kf("bob")),
        spawn_node("qcb1carol", ports.carol_api, ports.carol_p2p, log_dir,
                   &[ports.alice_p2p, ports.bob_p2p, ports.dave_p2p], kf("carol")),
        spawn_node("qcb1dave",  ports.dave_api,  ports.dave_p2p,  log_dir,
                   &[ports.alice_p2p, ports.bob_p2p, ports.carol_p2p], kf("dave")),
    ]
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_raw(port: u16, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().unwrap(), Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(1500))).ok()?;

    let request = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    Some(buf.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let body = http_raw(port, path)?;
    serde_json::from_str(&body).ok()
}

fn height_of(port: u16) -> u64 {
    api_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        ).is_ok() { return true; }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn wait_all_apis(ports: &[u16], labels: &[&str], timeout: Duration) -> bool {
    for (&port, &label) in ports.iter().zip(labels.iter()) {
        if !wait_for_port(port, timeout) {
            eprintln!("   TIMEOUT waiting for {label} API on :{port}");
            return false;
        }
        eprintln!("   {label} API up on :{port}");
    }
    true
}

fn poll_height(ports: &[u16], target: u64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let heights: Vec<u64> = ports.iter().map(|&p| height_of(p)).collect();
        let elapsed = Instant::now().saturating_duration_since(deadline - timeout);
        print!("\r   [{:.1}s] ", elapsed.as_secs_f32());
        for (i, &h) in heights.iter().enumerate() { print!("node{}={}  ", i, h); }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        if heights.iter().all(|&h| h >= target) { println!(); return true; }
        if Instant::now() >= deadline { println!(); return false; }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── Helpers for reading /api/blocks ──────────────────────────────────────────

/// Returns a vec of (height, timestamp_ms) sorted by height ascending.
fn blocks_of(port: u16) -> Vec<(u64, u64)> {
    let v = api_get(port, "/api/blocks").unwrap_or(serde_json::Value::Array(vec![]));
    let arr = v.as_array().cloned().unwrap_or_default();
    let mut pairs: Vec<(u64, u64)> = arr.iter().filter_map(|b| {
        let h = b["height"].as_u64()?;
        let t = b["timestamp_ms"].as_u64()?;
        Some((h, t))
    }).collect();
    pairs.sort_by_key(|(h, _)| *h);
    pairs
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[test]
fn p0_7_timestamp_monotonic() {
    if skip_if_no_binary() { return; }

    let log_dir = tempfile::tempdir().expect("tempdir").into_path();
    let ports   = DevnetPorts::new();
    let labels  = ["alice", "bob", "carol", "dave"];

    eprintln!("\n── P0-7: block timestamp monotonicity ──────────────────────────────");

    let _nodes = spawn_devnet(&ports, &log_dir);
    let all_api = ports.all_api();

    assert!(
        wait_all_apis(&all_api, &labels, Duration::from_secs(30)),
        "P0-7: node APIs did not come up in time"
    );

    // Wait for at least 6 committed blocks on all nodes.
    const TARGET_HEIGHT: u64 = 6;
    assert!(
        poll_height(&all_api, TARGET_HEIGHT, Duration::from_secs(90)),
        "P0-7: nodes did not reach height {TARGET_HEIGHT} in time"
    );

    // Extra settle time to let all nodes sync their explorer state.
    std::thread::sleep(Duration::from_secs(3));

    eprintln!("   All nodes at height ≥ {TARGET_HEIGHT}. Checking timestamp monotonicity…");

    // ── Assert monotonicity on each node ──────────────────────────────────────
    let mut all_passed = true;
    let mut node_blocks: Vec<Vec<(u64, u64)>> = Vec::new();

    for (i, (&port, &label)) in all_api.iter().zip(labels.iter()).enumerate() {
        let blocks = blocks_of(port);
        eprintln!("   {label} /api/blocks ({} entries):", blocks.len());
        for &(h, ts) in &blocks {
            eprintln!("      height={h}  timestamp_ms={ts}");
        }

        // Need at least TARGET_HEIGHT blocks to have a meaningful check.
        if blocks.len() < TARGET_HEIGHT as usize {
            eprintln!("   FAIL: {label} only returned {} blocks (want ≥ {TARGET_HEIGHT})",
                      blocks.len());
            all_passed = false;
            node_blocks.push(blocks);
            continue;
        }

        // Strict monotonicity: each block's timestamp must be > previous.
        let mut prev_ts: Option<u64> = None;
        for &(height, ts) in &blocks {
            if let Some(p) = prev_ts {
                if ts <= p {
                    eprintln!("   FAIL [{label}]: height={height} timestamp_ms={ts} \
                               is NOT > previous timestamp_ms={p}  ← regression");
                    all_passed = false;
                }
            }
            prev_ts = Some(ts);
        }
        if prev_ts.is_some() && all_passed {
            eprintln!("   OK [{label}]: timestamps strictly increasing across {} blocks",
                      blocks.len());
        }
        node_blocks.push(blocks);
        let _ = i;
    }

    // ── Assert cross-node agreement on timestamps ─────────────────────────────
    // Build a map height → timestamp from the first node's data, then check all
    // other nodes agree for every height they share.
    if !node_blocks.is_empty() {
        let reference: HashMap<u64, u64> = node_blocks[0].iter().cloned().collect();
        for (i, blocks) in node_blocks.iter().enumerate().skip(1) {
            for &(h, ts) in blocks {
                if let Some(&ref_ts) = reference.get(&h) {
                    if ts != ref_ts {
                        eprintln!(
                            "   FAIL: node{i} has height={h} timestamp_ms={ts} \
                             but node0 has {ref_ts}  ← nodes disagree"
                        );
                        all_passed = false;
                    }
                }
            }
        }
        if all_passed {
            eprintln!("   OK: all nodes agree on timestamps for shared heights");
        }
    }

    assert!(all_passed, "P0-7 FAIL: timestamp monotonicity or cross-node agreement violated");
    eprintln!("── P0-7 PASS ────────────────────────────────────────────────────────\n");
}
