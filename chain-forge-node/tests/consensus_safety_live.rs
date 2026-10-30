//! Consensus safety, multi-node live test (Tendermint state machine).
//!
//! Regression for the conflicting finalization observed live: with honest
//! nodes started at different times, height 1 was finalized as one block on
//! some nodes and a different one on others (both empty, so state roots
//! matched and only block hashes revealed it).
//!
//! Each run starts four validators and one observer in random order with
//! random gaps (messages sent before a node is up are lost), then kills and
//! restarts one validator from its data dir mid-run. Every node, observer
//! included, must report the same block hash at every height.
//!
//! ## Run (Windows/MINGW64)
//!
//! ```
//! cargo build -p chain-forge-node && \
//! cargo test -p chain-forge-node --test consensus_safety_live -- --nocapture
//! ```
//!
//! `CONSENSUS_SAFETY_RUNS` (default 3) sets the number of runs.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const NAMES:     &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave", "observer"];
const API_PORTS: &[u16]  = &[18480, 18481, 18482, 18483, 18484];
const P2P_PORTS: &[u16]  = &[27400, 27401, 27402, 27403, 27404];
const TARGET_HEIGHT: u64 = 12;
const TIMEOUT_SECS:  u64 = 180;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn node_binary() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR").map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let debug   = target.join("debug").join(&exe);
    let release = target.join("release").join(&exe);
    match (debug.metadata().and_then(|m| m.modified()), release.metadata().and_then(|m| m.modified())) {
        (Ok(dt), Ok(rt)) => if dt >= rt { debug } else { release },
        (Ok(_),  Err(_)) => debug,
        (Err(_), Ok(_))  => release,
        _                => debug,
    }
}

#[path = "common/consensus_keys.rs"]
mod consensus_keys;

fn genesis_path() -> PathBuf {
    consensus_keys::genesis(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("devnet").join("genesis-fee-settle.json"))
}

fn key_path(name: &str) -> PathBuf {
    let short = name.strip_prefix("qcb1").unwrap_or(name);
    consensus_keys::validator_key(short,
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("devnet").join("keys").join(format!("{short}.key.json")))
}

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
    let mut stream = TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(2_000))).ok()?;
    stream.write_all(format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").as_bytes()).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1)?).ok()
}

fn height_of(port: u16) -> u64 {
    api_get(port, "/api/status").and_then(|v| v["height"].as_u64()).unwrap_or(0)
}

fn block_hash_at(port: u16, height: u64) -> Option<String> {
    api_get(port, &format!("/api/blocks/{height}")).and_then(|v| v["block_hash"].as_str().map(str::to_string))
}

fn wait_for_height(target: u64, timeout: Duration, nodes: &[Option<NodeProc>]) {
    let deadline = Instant::now() + timeout;
    loop {
        let heights: Vec<u64> = API_PORTS.iter().map(|&p| height_of(p)).collect();
        print!("\r   waiting for height {target}: {heights:?}  ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        if heights.iter().all(|&h| h >= target) { println!(); return; }
        if Instant::now() >= deadline {
            println!();
            for n in nodes.iter().flatten() { print_tail(&n.log_path, 25); }
            panic!("height {target} not reached within {timeout:?}; heights={heights:?}");
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

struct NodeProc {
    child:    Child,
    log_path: PathBuf,
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(bin: &PathBuf, idx: usize, log_dir: &PathBuf, data_dir: &PathBuf, bootstraps: &[String]) -> NodeProc {
    let log_path = log_dir.join(format!("{}.log", NAMES[idx]));
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).unwrap();
    let mut cmd = Command::new(bin);
    cmd.args([
        "--genesis",  genesis_path().to_str().unwrap(),
        "--api-port", &API_PORTS[idx].to_string(),
        "--p2p-port", &P2P_PORTS[idx].to_string(),
        "--data-dir", data_dir.to_str().unwrap(),
    ]);
    if idx < 4 {
        cmd.args(["--validator", NAMES[idx], "--key-file", key_path(NAMES[idx]).to_str().unwrap()]);
    }
    for b in bootstraps { cmd.args(["--bootstrap", b]); }
    cmd.stdout(log_file.try_clone().unwrap()).stderr(log_file).stdin(Stdio::null());
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {} failed: {e}", NAMES[idx]));
    assert!(wait_for_port(API_PORTS[idx], Duration::from_secs(20)), "{} API never opened", NAMES[idx]);
    NodeProc { child, log_path }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for nc in chars.by_ref() { if nc == 'm' { break; } }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn peer_id(log_path: &PathBuf) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(content) = std::fs::read_to_string(log_path) {
            if let Some(line) = content.lines().map(strip_ansi).find(|l| l.contains("local_peer_id=")) {
                let after = &line[line.find("local_peer_id=").unwrap() + "local_peer_id=".len()..];
                return after.chars().take_while(|c| !c.is_whitespace()).collect();
            }
        }
        assert!(Instant::now() < deadline, "peer ID never appeared in {log_path:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn print_tail(log_path: &PathBuf, lines: usize) {
    if let Ok(content) = std::fs::read_to_string(log_path) {
        let all: Vec<_> = content.lines().collect();
        println!("── tail of {log_path:?} ──");
        for line in &all[all.len().saturating_sub(lines)..] { println!("{}", strip_ansi(line)); }
    }
}

/// Small deterministic PRNG (per-run seed printed for reproduction).
struct Rng(u64);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17;
        self.0 % n.max(1)
    }
}

/// Every node must report the same block hash at every height 1..=upto.
fn assert_agreement(run: u32, upto: u64) {
    for h in 1..=upto {
        let seen: Vec<Option<String>> = API_PORTS.iter().map(|&p| block_hash_at(p, h)).collect();
        assert!(seen.iter().all(Option::is_some), "run {run}: block {h} missing on some node: {seen:?}");
        for (i, b) in seen.iter().enumerate().skip(1) {
            assert_eq!(b, &seen[0], "run {run}: CONFLICTING FINALIZATION at height {h}: {} {b:?} vs {} {:?}",
                       NAMES[i], NAMES[0], seen[0]);
        }
    }
}

#[test]
fn honest_nodes_with_staggered_start_and_restart_never_finalize_conflicting_blocks() {
    let bin = node_binary();
    assert!(bin.exists(), "HARD FAIL: node binary not found at {bin:?}. Run `cargo build -p chain-forge-node` first.");
    for port in API_PORTS.iter().chain(P2P_PORTS.iter()) {
        assert!(port_is_free(*port), "port {port} is in use — kill stray processes first");
    }
    let runs: u32 = std::env::var("CONSENSUS_SAFETY_RUNS").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    let timeout = Duration::from_secs(TIMEOUT_SECS);

    for run in 0..runs {
        let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 | 1;
        let mut rng = Rng(seed);
        println!("\n── consensus safety run {run} (seed {seed}) ─────────────────────────");
        let log_dir  = std::env::temp_dir().join(format!("qcb-consensus-safety-{run}"));
        let data_root = std::env::temp_dir().join(format!("qcb-consensus-safety-data-{run}"));
        let _ = std::fs::remove_dir_all(&log_dir);
        let _ = std::fs::remove_dir_all(&data_root);
        std::fs::create_dir_all(&log_dir).unwrap();
        let data: Vec<PathBuf> = NAMES.iter().map(|n| data_root.join(n)).collect();
        for d in &data { std::fs::create_dir_all(d).unwrap(); }

        // Alice first (bootstrap node), then the others in random order with
        // random gaps of up to 4 s.
        let mut nodes: Vec<Option<NodeProc>> = (0..NAMES.len()).map(|_| None).collect();
        nodes[0] = Some(spawn(&bin, 0, &log_dir, &data[0], &[]));
        let bootstrap = vec![format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", P2P_PORTS[0], peer_id(&nodes[0].as_ref().unwrap().log_path))];
        let mut order: Vec<usize> = (1..NAMES.len()).collect();
        for i in (1..order.len()).rev() { order.swap(i, rng.below(i as u64 + 1) as usize); }
        for idx in order {
            std::thread::sleep(Duration::from_millis(rng.below(4_000)));
            nodes[idx] = Some(spawn(&bin, idx, &log_dir, &data[idx], &bootstrap));
            println!("   started {}", NAMES[idx]);
        }

        wait_for_height(TARGET_HEIGHT / 2, timeout, &nodes);

        // Crash one validator (not the bootstrap node) and restart it from disk.
        let victim = 1 + rng.below(3) as usize;
        println!("   crashing {} and restarting it from its data dir", NAMES[victim]);
        nodes[victim] = None;
        std::thread::sleep(Duration::from_millis(500 + rng.below(3_000)));
        nodes[victim] = Some(spawn(&bin, victim, &log_dir, &data[victim], &bootstrap));

        wait_for_height(TARGET_HEIGHT, timeout, &nodes);
        assert_agreement(run, TARGET_HEIGHT);
        println!("   run {run}: all 5 nodes agree on block hashes 1..={TARGET_HEIGHT}");
        drop(nodes);
        std::thread::sleep(Duration::from_secs(1));
    }
}
