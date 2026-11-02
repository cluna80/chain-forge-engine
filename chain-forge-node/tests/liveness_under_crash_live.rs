//! Consensus liveness under permanent validator crash (live integration test).
//!
//! Regression for the bug where the seed node's round timers were gated on
//! `has_bootstrap_peers`. With that guard in place, the seed node (started
//! without --bootstrap) only reacted to incoming messages and could never
//! advance a round on its own. When one of the other three validators died,
//! the two survivors could not form the quorum of 3 needed for BFT progress,
//! and the chain stalled permanently at the height where the crashed node was
//! next proposer — despite 3-of-4 validators being alive.
//!
//! ## What this test checks
//!
//! 1. All four validators start and reach height 4 (verifies basic liveness).
//! 2. Dave is killed permanently (SIGKILL / TerminateProcess on Windows).
//! 3. Alice, Bob and Carol advance the chain to height ≥ CONTINUE_THROUGH_HEIGHT
//!    within the deadline — proving the surviving 3-of-4 form quorum and keep
//!    committing blocks through Dave's proposer turns.
//!
//! ## Run (Windows / MINGW64)
//!
//! ```
//! cargo build -p chain-forge-node && \
//! cargo test -p chain-forge-node --test liveness_under_crash_live -- --nocapture
//! ```

use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// ── Fixed port ranges (no collision with other live tests) ────────────────────
const ALICE_API: u16 = 18700;
const BOB_API:   u16 = 18701;
const CAROL_API: u16 = 18702;
const DAVE_API:  u16 = 18703;

const ALICE_P2P: u16 = 27700;
const BOB_P2P:   u16 = 27701;
const CAROL_P2P: u16 = 27702;
const DAVE_P2P:  u16 = 27703;

const KILL_AT_HEIGHT:           u64 = 5;
const CONTINUE_THROUGH_HEIGHT:  u64 = 20;
const TIMEOUT_SECS:             u64 = 180;
const POLL_MS:                  u64 = 300;

// ── Paths ─────────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn node_bin() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR").map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let debug   = target.join("debug").join(&exe);
    let release = target.join("release").join(&exe);
    match (
        debug.metadata().and_then(|m| m.modified()),
        release.metadata().and_then(|m| m.modified()),
    ) {
        (Ok(dt), Ok(rt)) => if dt >= rt { debug } else { release },
        (Ok(_), Err(_))  => debug,
        (Err(_), Ok(_))  => release,
        _                => debug,
    }
}

fn genesis_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests").join("devnet").join("genesis-liveness-crash.json")
}

fn key_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests").join("devnet").join("keys").join(format!("{name}.key.json"))
}

fn devnet_dirs() -> PathBuf {
    repo_root().join("target").join("test-devnet-liveness-crash")
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    use std::io::{Read, Write};
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    let body = buf.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(body).ok()
}

fn height_of(port: u16) -> u64 {
    http_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

// ── Node spawning ─────────────────────────────────────────────────────────────

fn spawn_node(
    label: &str,
    validator_id: &str,
    api_port: u16,
    p2p_port: u16,
    bootstrap: Option<&str>,
    dirs: &PathBuf,
) -> Child {
    let data_dir = dirs.join(label);
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let short_name = validator_id.strip_prefix("qcb1").unwrap_or(validator_id);
    let kf = key_path(short_name);

    let log_path = dirs.join(format!("{label}.log"));
    let log_file = std::fs::OpenOptions::new()
        .create(true).write(true).truncate(true)
        .open(&log_path)
        .unwrap_or_else(|e| panic!("open log {}: {e}", log_path.display()));

    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator").arg(validator_id)
       .arg("--key-file").arg(&kf)
       .arg("--api-port").arg(api_port.to_string())
       .arg("--p2p-port").arg(p2p_port.to_string())
       .arg("--data-dir").arg(&data_dir)
       .stdout(log_file.try_clone().unwrap())
       .stderr(log_file)
       .stdin(Stdio::null());
    if let Some(bs) = bootstrap {
        cmd.arg("--bootstrap").arg(bs);
    }
    cmd.spawn().unwrap_or_else(|e| panic!("spawn {label}: {e}"))
}

fn wait_api_ready(port: u16, deadline: Instant) {
    loop {
        assert!(Instant::now() < deadline, "timeout waiting for API on port {port}");
        if http_get(port, "/api/status").is_some() { return; }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_height(ports: &[u16], target: u64, deadline: Instant) {
    loop {
        assert!(
            Instant::now() < deadline,
            "timeout waiting for height {target} on {ports:?}"
        );
        if ports.iter().all(|&p| height_of(p) >= target) { return; }
        std::thread::sleep(Duration::from_millis(POLL_MS));
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[test]
fn liveness_survives_permanent_validator_crash() {
    let deadline = Instant::now() + Duration::from_secs(TIMEOUT_SECS);
    let dirs = devnet_dirs();
    let _ = std::fs::remove_dir_all(&dirs);
    std::fs::create_dir_all(&dirs).unwrap();

    // ── Start Alice first (seed / bootstrap node) ─────────────────────────────
    let alice = spawn_node("alice", "qcb1alice", ALICE_API, ALICE_P2P, None, &dirs);
    wait_api_ready(ALICE_API, deadline);

    // Read Alice's peer ID from the API to build a valid bootstrap multiaddr.
    // The full base58 ID is required — Display shows only 8 chars.
    let alice_peer_id = {
        let mut peer_id = None;
        let wait_until = Instant::now() + Duration::from_secs(10);
        while peer_id.is_none() && Instant::now() < wait_until {
            peer_id = http_get(ALICE_API, "/api/status")
                .and_then(|v| v["local_peer_id"].as_str().map(|s| s.to_string()));
            if peer_id.is_none() {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        peer_id.expect("Alice's local_peer_id must be set after P2P starts")
    };
    let bootstrap_addr = format!("/ip4/127.0.0.1/tcp/{ALICE_P2P}/p2p/{alice_peer_id}");

    // ── Start Bob, Carol, Dave ────────────────────────────────────────────────
    let bob   = spawn_node("bob",   "qcb1bob",   BOB_API,   BOB_P2P,   Some(&bootstrap_addr), &dirs);
    let carol = spawn_node("carol", "qcb1carol", CAROL_API, CAROL_P2P, Some(&bootstrap_addr), &dirs);
    let mut dave  = spawn_node("dave",  "qcb1dave",  DAVE_API,  DAVE_P2P,  Some(&bootstrap_addr), &dirs);

    for (name, port) in [("bob", BOB_API), ("carol", CAROL_API), ("dave", DAVE_API)] {
        println!("[startup] waiting for {name}…");
        wait_api_ready(port, deadline);
        println!("[startup] {name} ready.");
    }

    // ── L-01: all four reach height KILL_AT_HEIGHT (basic liveness) ──────────
    println!("[L-01] waiting for all four nodes to reach height {KILL_AT_HEIGHT}…");
    wait_for_height(
        &[ALICE_API, BOB_API, CAROL_API, DAVE_API],
        KILL_AT_HEIGHT,
        deadline,
    );
    println!("[L-01] PASS — all four validators reached height {KILL_AT_HEIGHT}.");

    // ── L-02: kill Dave permanently ───────────────────────────────────────────
    println!("[L-02] killing Dave (permanent crash)…");
    dave.kill().expect("kill dave");
    let _ = dave.wait();
    println!("[L-02] Dave is down. Surviving: Alice, Bob, Carol (3-of-4, quorum = 3).");

    // ── L-03: surviving nodes advance chain through Dave's proposer turns ─────
    // With the round-timer bug, the chain would stall here permanently.
    // With the fix, Alice runs her own round timers and can propose/timeout
    // independently, so the three survivors keep committing blocks.
    println!("[L-03] waiting for Alice+Bob+Carol to reach height {CONTINUE_THROUGH_HEIGHT}…");
    wait_for_height(
        &[ALICE_API, BOB_API, CAROL_API],
        CONTINUE_THROUGH_HEIGHT,
        deadline,
    );
    let heights: Vec<u64> = [ALICE_API, BOB_API, CAROL_API]
        .iter().map(|&p| height_of(p)).collect();
    println!("[L-03] PASS — surviving validators at heights {heights:?}.");

    // Cleanup
    for mut node in [alice, bob, carol] { // Child::kill/wait require &mut self
        let _ = node.kill();
        let _ = node.wait();
    }
}
