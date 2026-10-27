//! H0-5 — Execution atomicity, multi-node acceptance test (Phase 0.5).
//!
//! Live counterpart of the `h0_atomicity_fee_conservation` unit tests in
//! chain-forge-execution. Covers the H0-5 acceptance criteria that need real
//! nodes:
//!
//!   H5-1  Included-but-failed tx: a transfer exceeding the sender's balance is
//!         included, charges exactly its fee, consumes exactly one nonce, and
//!         moves no funds.
//!   H5-2  Replay: the failed tx's nonce cannot be used again and a replay
//!         attempt charges nothing.
//!   H5-3  Rejected tx: a tx with a future nonce changes nothing and pays no
//!         fee.
//!   H5-4  Cross-node determinism: all four nodes report the same state root
//!         for the same block height and the same post-sequence balances,
//!         nonces and treasury balances.
//!   H5-5  Restart persistence: after ALL four nodes are killed and restarted
//!         from their data directories, the block root at that height and the
//!         sender's balance and nonce are unchanged on every node (no partial
//!         mutation reappears from disk), and the chain keeps producing blocks.
//!
//! ## Genesis
//!
//! Uses `tests/devnet/genesis-fee-settle.json` (unsigned txs allowed, four
//! validators, funded `qcb1user1`). Ports 18280-18283 / 27200-27203 so it can
//! never collide with `fee_settle_live`.
//!
//! ## Run (Windows/MINGW64)
//!
//! ```
//! cargo build -p chain-forge-node && \
//! cargo test -p chain-forge-node --test h0_5_atomicity_live -- --nocapture
//! ```

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_core::GenesisConfig;
use chain_forge_execution::{ExecutionConfig, Transaction, TxBody};

// ── Constants ─────────────────────────────────────────────────────────────────

const DENOM:     &str = "uqcb";
const SENDER:    &str = "qcb1user1";
const RECIPIENT: &str = "qcb1alice";
const VALIDATORS: &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
const API_PORTS: &[u16] = &[18280, 18281, 18282, 18283];
const P2P_PORTS: &[u16] = &[27200, 27201, 27202, 27203];
const TIMEOUT_SECS: u64 = 90;

// ── Paths and harness (same as fee_settle_live) ───────────────────────────────

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
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests").join("devnet").join("genesis-fee-settle.json")
}

fn key_path(short_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests").join("devnet").join("keys")
        .join(format!("{short_name}.key.json"))
}

// ── Network helpers ───────────────────────────────────────────────────────────

fn port_is_free(port: u16) -> bool {
    TcpStream::connect(format!("127.0.0.1:{port}")).is_err()
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() { return true; }
        if Instant::now() >= deadline { return false; }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(1_000))).ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1)?).ok()
}

fn api_post_tx(port: u16, tx_json: &str) -> Option<serde_json::Value> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(2_000))).ok()?;
    let body = tx_json.as_bytes();
    let req = format!(
        "POST /api/tx HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    stream.write_all(body).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1)?).ok()
}

fn height_of(port: u16) -> u64 {
    api_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

/// Return the uqcb balance of `addr` as seen by node at `port`.
fn balance_of(port: u16, addr: &str) -> u128 {
    api_get(port, &format!("/api/accounts/{addr}"))
        .and_then(|v| {
            v["balances"]["uqcb"]
                .as_str()
                .and_then(|s| s.parse::<u128>().ok())
                .or_else(|| v["balances"]["uqcb"].as_u64().map(|n| n as u128))
        })
        .unwrap_or(0)
}

/// Poll all `ports` until every node reaches `target_height` or timeout.
fn wait_for_height(ports: &[u16], target: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let heights: Vec<u64> = ports.iter().map(|&p| height_of(p)).collect();
        let all_reached = heights.iter().all(|&h| h >= target);
        print!("\r   waiting for height {target}: {:?}  ", heights);
        std::io::Write::flush(&mut std::io::stdout()).ok();
        if all_reached { println!(); return; }
        if Instant::now() >= deadline {
            panic!(
                "height {target} not reached within {timeout:?}; heights={heights:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

// ── RAII process guard ────────────────────────────────────────────────────────

struct NodeProc {
    label:    &'static str,
    child:    Child,
    api_port: u16,
    log_path: PathBuf,
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Spawn helpers ─────────────────────────────────────────────────────────────

fn spawn_node(
    bin:        &PathBuf,
    genesis:    &PathBuf,
    log_dir:    &PathBuf,
    idx:        usize,
    data_dir:   Option<&PathBuf>,
    bootstraps: &[String],
) -> NodeProc {
    let validator  = VALIDATORS[idx];
    let api_port   = API_PORTS[idx];
    let p2p_port   = P2P_PORTS[idx];
    let short_name = validator.strip_prefix("qcb1").unwrap_or(validator);
    let key_file   = key_path(short_name);
    let log_path   = log_dir.join(format!("{validator}.log"));
    let log_file   = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(&log_path)
        .unwrap_or_else(|e| panic!("log open failed {log_path:?}: {e}"));

    let mut cmd = Command::new(bin);
    cmd.args([
        "--genesis",   genesis.to_str().unwrap(),
        "--validator", validator,
        "--key-file",  key_file.to_str().unwrap(),
        "--api-port",  &api_port.to_string(),
        "--p2p-port",  &p2p_port.to_string(),
    ]);
    if let Some(d) = data_dir {
        cmd.args(["--data-dir", d.to_str().unwrap()]);
    }
    for b in bootstraps {
        cmd.args(["--bootstrap", b]);
    }
    cmd.stdout(log_file.try_clone().unwrap())
       .stderr(log_file)
       .stdin(Stdio::null());

    let child = cmd.spawn()
        .unwrap_or_else(|e| panic!("spawn {validator} failed: {e}"));

    NodeProc { label: validator, child, api_port, log_path }
}

/// Strip ANSI escape sequences from a string.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ESC [ ... m  — consume until 'm'
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for nc in chars.by_ref() {
                    if nc == 'm' { break; }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Read a node's libp2p peer ID from its log file by polling until the
/// `local_peer_id=<ID>` field appears (ANSI codes stripped).
fn read_peer_id_from_log(log_path: &PathBuf, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(content) = std::fs::read_to_string(log_path) {
            for raw_line in content.lines() {
                let line = strip_ansi(raw_line);
                // Line contains: local_peer_id=12D3KooW...
                if let Some(pos) = line.find("local_peer_id=") {
                    let after = &line[pos + "local_peer_id=".len()..];
                    // The peer ID ends at whitespace or end-of-line.
                    let id: String = after.chars()
                        .take_while(|c| !c.is_whitespace())
                        .collect();
                    if !id.is_empty() { return id; }
                }
            }
        }
        if Instant::now() >= deadline {
            panic!("peer ID never appeared in log {log_path:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_all(
    bin:     &PathBuf,
    genesis: &PathBuf,
    log_dir: &PathBuf,
    data_dirs: Option<&[PathBuf]>,
) -> Vec<NodeProc> {
    let mut nodes = Vec::new();

    // Start Alice (index 0) first, without a bootstrap peer.
    {
        let dd = data_dirs.map(|dirs| &dirs[0]);
        nodes.push(spawn_node(bin, genesis, log_dir, 0, dd, &[]));
    }
    assert!(
        wait_for_port(nodes[0].api_port, Duration::from_secs(15)),
        "{} API port :{} never opened", nodes[0].label, nodes[0].api_port
    );
    println!("   {} up on :{}", nodes[0].label, nodes[0].api_port);

    // Read Alice's libp2p peer ID so we can bootstrap the others against her.
    let alice_peer_id = read_peer_id_from_log(
        &nodes[0].log_path,
        Duration::from_secs(10),
    );
    let alice_bootstrap = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{}", P2P_PORTS[0], alice_peer_id
    );
    println!("   Alice peer ID: {alice_peer_id}");
    println!("   Bootstrap addr: {alice_bootstrap}");

    // Start remaining nodes, each bootstrapping against Alice.
    for i in 1..VALIDATORS.len() {
        let dd = data_dirs.map(|dirs| &dirs[i]);
        nodes.push(spawn_node(bin, genesis, log_dir, i, dd, &[alice_bootstrap.clone()]));
        assert!(
            wait_for_port(nodes[i].api_port, Duration::from_secs(15)),
            "{} API port :{} never opened", nodes[i].label, nodes[i].api_port
        );
        println!("   {} up on :{}", nodes[i].label, nodes[i].api_port);
    }
    nodes
}

fn print_tail(log_path: &PathBuf, lines: usize) {
    if let Ok(content) = std::fs::read_to_string(log_path) {
        let all: Vec<_> = content.lines().collect();
        let start = all.len().saturating_sub(lines);
        for line in &all[start..] { println!("{line}"); }
    }
}

// ── H0-5 helpers ──────────────────────────────────────────────────────────────

fn account_nonce(port: u16, addr: &str) -> u64 {
    api_get(port, &format!("/api/accounts/{addr}"))
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(0)
}

/// State root recorded for block `height` on the node at `port`.
fn block_root(port: u16, height: u64) -> Option<String> {
    api_get(port, &format!("/api/blocks/{height}"))
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
}

fn transfer(id: &str, nonce: u64, amount: u128) -> Transaction {
    Transaction {
        id: id.into(), sender: SENDER.into(), nonce,
        body: TxBody::Transfer { to: RECIPIENT.into(), denom: DENOM.into(), amount },
        gas_limit: 1_000_000,
        signature: vec![], public_key: vec![], pq_signatures: vec![],
        sig_scheme: None, pq_public_key: vec![],
    }
}

/// Fee the chain charges for `tx`, computed from the same genesis the nodes run.
fn fee_for(cfg: &ExecutionConfig, tx: &Transaction) -> u128 {
    cfg.gas_model.calculate_gas(tx) as u128
}

fn submit(port: u16, tx: &Transaction) -> serde_json::Value {
    api_post_tx(port, &serde_json::to_string(tx).unwrap())
        .unwrap_or_else(|| panic!("POST /api/tx for {} failed (network)", tx.id))
}

fn failing_amount_fails(tx: &Transaction, balance: u128, fee: u128) -> bool {
    match &tx.body {
        TxBody::Transfer { amount, .. } => *amount <= balance && *amount > balance - fee,
        _ => false,
    }
}

/// Wait until every node reports `addr` at `nonce` or higher.
fn wait_for_nonce(ports: &[u16], addr: &str, nonce: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let seen: Vec<u64> = ports.iter().map(|&p| account_nonce(p, addr)).collect();
        if seen.iter().all(|&n| n >= nonce) { return; }
        assert!(Instant::now() < deadline,
            "{addr} never reached nonce {nonce} on all nodes: {seen:?}");
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Every node must report the same value; returns it.
fn agreed<T: PartialEq + std::fmt::Debug + Clone>(what: &str, vals: Vec<T>) -> T {
    for (i, v) in vals.iter().enumerate().skip(1) {
        assert_eq!(v, &vals[0], "H5-4 FAILED: {what} differs on {}: {vals:?}", VALIDATORS[i]);
    }
    vals[0].clone()
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn h0_5_execution_atomicity_multi_node() {
    let bin = node_binary();
    assert!(bin.exists(),
        "HARD FAIL: node binary not found at {bin:?}. Run `cargo build -p chain-forge-node` first.");
    let genesis = genesis_path();
    let cfg = ExecutionConfig::from_genesis(
        &GenesisConfig::from_json(&std::fs::read_to_string(&genesis).unwrap()).unwrap());
    for name in ["alice", "bob", "carol", "dave"] {
        assert!(key_path(name).exists(), "key file not found: {:?}", key_path(name));
    }
    for port in API_PORTS.iter().chain(P2P_PORTS.iter()) {
        assert!(port_is_free(*port), "port {port} is in use — kill stray processes first");
    }

    let timeout = Duration::from_secs(TIMEOUT_SECS);
    let log_dir = std::env::temp_dir().join("qcb-h05-atomicity-test");
    let data_root = std::env::temp_dir().join("qcb-h05-atomicity-data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&data_root);
    std::fs::create_dir_all(&log_dir).unwrap();
    let data_dirs: Vec<PathBuf> = VALIDATORS.iter().map(|v| data_root.join(v)).collect();
    for d in &data_dirs { std::fs::create_dir_all(d).unwrap(); }
    let ports: Vec<u16> = API_PORTS.to_vec();
    let run = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);

    println!("\n── H0-5 execution atomicity (4 nodes) ──────────────────────────────");
    println!("   logs: {log_dir:?}");
    let mut nodes = spawn_all(&bin, &genesis, &log_dir, Some(&data_dirs));
    wait_for_height(&ports, 2, timeout);

    let n0 = agreed("starting nonce", ports.iter().map(|&p| account_nonce(p, SENDER)).collect());
    let b0 = agreed("starting balance", ports.iter().map(|&p| balance_of(p, SENDER)).collect());
    assert!(b0 > 0, "{SENDER} has no balance in this genesis");
    println!("   {SENDER}: nonce={n0} balance={b0}");

    // ── H5-1: included-but-failed ──────────────────────────────────────────────
    // POST /api/tx rejects a transfer larger than the sender's balance, so use
    // one that passes that check (amount <= balance) but fails in execution:
    // the fee is debited first, leaving less than `amount`.
    let fail_id = format!("h05-fail-{run}");
    let fee_estimate = fee_for(&cfg, &transfer(&fail_id, n0, b0));
    let failing = transfer(&fail_id, n0, b0 - fee_estimate + 1);
    let fee_fail = fee_for(&cfg, &failing);
    assert!(failing_amount_fails(&failing, b0, fee_fail), "fixture: transfer must fail after the fee");
    println!("   failing transfer (nonce {n0}, fee {fee_fail}): {}", submit(ports[0], &failing));
    wait_for_nonce(&ports, SENDER, n0 + 1, timeout);
    for (i, &p) in ports.iter().enumerate() {
        assert_eq!(account_nonce(p, SENDER), n0 + 1,
            "H5-1 FAILED on {}: a failed tx must consume exactly one nonce", VALIDATORS[i]);
        assert_eq!(balance_of(p, SENDER), b0 - fee_fail,
            "H5-1 FAILED on {}: a failed tx must charge exactly its fee and move no funds", VALIDATORS[i]);
    }
    println!("   H5-1 PASS — failed tx charged {fee_fail}, consumed nonce {n0}, moved nothing");

    // ── H5-2 / H5-3: replay of the failed nonce, a valid tx, a future nonce ────
    let replay = transfer(&format!("h05-replay-{run}"), n0, 1);
    println!("   replay of nonce {n0}: {}", submit(ports[1], &replay));
    let ok = transfer(&format!("h05-ok-{run}"), n0 + 1, 1_000);
    let fee_ok = fee_for(&cfg, &ok);
    println!("   valid transfer (nonce {}): {}", n0 + 1, submit(ports[0], &ok));
    let future = transfer(&format!("h05-future-{run}"), n0 + 40, 1);
    println!("   future-nonce tx (nonce {}): {}", n0 + 40, submit(ports[2], &future));
    wait_for_nonce(&ports, SENDER, n0 + 2, timeout);

    // Give any queued rejected txs time to reach a block, then pin a height.
    let pin = ports.iter().map(|&p| height_of(p)).max().unwrap() + 3;
    wait_for_height(&ports, pin, timeout);

    let expected_balance = b0 - fee_fail - fee_ok - 1_000;
    for (i, &p) in ports.iter().enumerate() {
        assert_eq!(account_nonce(p, SENDER), n0 + 2,
            "H5-2/H5-3 FAILED on {}: only the failed and the valid tx may consume nonces", VALIDATORS[i]);
        assert_eq!(balance_of(p, SENDER), expected_balance,
            "H5-2/H5-3 FAILED on {}: replayed or rejected txs must not be charged", VALIDATORS[i]);
    }
    println!("   H5-2 PASS — replay of nonce {n0} charged nothing");
    println!("   H5-3 PASS — future-nonce tx changed nothing");

    // ── H5-4: cross-node determinism at a pinned height ───────────────────────
    let root_at_pin = agreed(&format!("state root at height {pin}"),
        ports.iter().map(|&p| block_root(p, pin)).collect());
    assert!(root_at_pin.is_some(), "no state root recorded for height {pin}");
    for addr in [SENDER, RECIPIENT, "treasury:fees", "treasury:validator-pool", "treasury:network"] {
        agreed(&format!("{addr} balance"), ports.iter().map(|&p| balance_of(p, addr)).collect());
    }
    println!("   H5-4 PASS — all nodes agree; root@{pin}={}", root_at_pin.as_deref().unwrap());

    // ── H5-5: kill all four nodes, restart from disk ──────────────────────────
    let height_before = ports.iter().map(|&p| height_of(p)).max().unwrap();
    println!("   killing all nodes at height ~{height_before}");
    drop(std::mem::take(&mut nodes));
    std::thread::sleep(Duration::from_secs(2));
    // Fresh log files: spawn_all reads Alice's libp2p peer ID from her log, and
    // peer IDs change on restart, so the pre-restart log would give a stale ID.
    let restart_log_dir = log_dir.join("restart");
    std::fs::create_dir_all(&restart_log_dir).unwrap();
    let restarted = spawn_all(&bin, &genesis, &restart_log_dir, Some(&data_dirs));
    wait_for_height(&ports, height_before + 2, timeout);

    for (i, &p) in ports.iter().enumerate() {
        assert_eq!(block_root(p, pin), root_at_pin,
            "H5-5 FAILED on {}: block {pin} root changed across restart", VALIDATORS[i]);
        assert_eq!(account_nonce(p, SENDER), n0 + 2,
            "H5-5 FAILED on {}: sender nonce changed across restart", VALIDATORS[i]);
        assert_eq!(balance_of(p, SENDER), expected_balance,
            "H5-5 FAILED on {}: sender balance changed across restart", VALIDATORS[i]);
    }
    println!("   H5-5 PASS — restart preserved root@{pin}, nonce and balance; chain resumed");

    if std::env::var("H05_PRINT_LOGS").is_ok() {
        for n in &restarted { print_tail(&n.log_path, 20); }
    }
    println!("\n   H0-5 live: H5-1..H5-5 passed");
}
