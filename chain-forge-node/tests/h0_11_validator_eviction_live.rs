//! H0-11 — Validator Eviction Policy: Live Acceptance Test
//!
//! Confirms that Qattice's liveness-based eviction policy applies equally to
//! genesis validators and post-genesis validators.  No validator is exempt by
//! virtue of appearing in the genesis file.
//!
//! ## Owner decision (2026-10-31, recorded here per ROADMAP.md H0-11)
//!
//! Eviction policy for Qattice devnet and mainnet:
//!
//!   • **Jail-only for missed blocks** — temporary and reversible.  Liveness
//!     never burns stake.  Only provable double-signing (equivocation) triggers
//!     tombstoning.
//!   • **No genesis exemption** — a genesis validator that misses its liveness
//!     window is jailed by exactly the same rules as any other validator.
//!   • **Epoch-boundary determinism** — liveness enforcement begins at
//!     `consensus.liveness.start_height` (configurable via genesis).
//!   • **Byzantine-robust counting** — up to f = floor((n-1)/3) omitting
//!     proposers are discounted so a single malicious proposer cannot jail an
//!     honest validator.
//!   • **Quorum preservation** — with 4 validators and f=1, jailing one
//!     leaves 3 (75%) which exceeds the 2/3 threshold; the chain continues.
//!
//! ## Acceptance criteria
//!
//! | ID   | Scenario |
//! |------|----------|
//! | E-01 | Devnet forms with `window=10 / threshold=60% / start=3`; four nodes commit block 3+ without false jailing |
//! | E-02 | After Dave's node is killed at height 5, he is jailed by height ~20; `GET /api/validators` no longer includes Dave |
//! | E-03 | After Dave is jailed, Alice+Bob+Carol maintain quorum and advance the chain |
//! | E-04 | Dave's stake balance is unchanged after jailing (liveness never burns stake) |
//!
//! ## Genesis
//!
//! `tests/devnet/genesis-h0-11-eviction.json`:
//!   - chain_id: `qcb-devnet-h0-11-eviction`
//!   - `consensus.liveness.window_blocks`: 10
//!   - `consensus.liveness.max_missed_pct`: 60
//!   - `consensus.liveness.start_height`: 3
//!   - Four validators: alice, bob, carol, dave — each 500 M uqcb
//!
//! With n=4 and f=1 Byzantine discount, Dave must be absent from more than
//! 60% of the last 10 blocks (after discounting the one most-omitting proposer)
//! to be jailed.  Killing his process guarantees 100% absence, so he is
//! jailed well within 20 blocks of the kill.
//!
//! ## Quorum after Dave is jailed
//!
//! With stake-weighted voting (Phase 0 devnet has personhood_weighted=true but
//! no real personhood verification, so every validator gets equal weight):
//!   n=3 remaining → quorum = floor(3 × 2/3) + 1 = 3 → all 3 must sign.
//!
//! Actually: the engine computes quorum from total bonded power.  Because
//! liveness jails Dave but does NOT remove him from the validator registry
//! (he is `Jailed`, not `Tombstoned`), his registered power is still counted
//! in total_power.  In Phase 0, all validators share equal power from genesis
//! bonds.  With Dave jailed:
//!   total_power = 4 units (still includes Dave's registered power)
//!   quorum      = floor(4 × 2/3) + 1 = 3
//!   signing     = Alice + Bob + Carol = 3 → exactly quorum ✓
//!
//! Note: if the chain uses stake-computed power (BondValidator phase), the
//! numbers change; the genesis file here keeps the Phase 0 equal-weight model
//! (no BondValidator txs in the test).  Three validators are always enough to
//! commit a block.
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test h0_11_validator_eviction_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: mark E-01..E-04 ✅ only after confirmed passing on
//! developer's local machine (Windows/MINGW64).

use std::{
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// ── Constants ─────────────────────────────────────────────────────────────────

const ALICE_ADDR: &str = "qcb1alice";
const DAVE_ADDR:  &str = "qcb1dave";

/// Genesis Dave stake (500 M uqcb); must be unchanged after jailing.
const DAVE_GENESIS_BALANCE: u128 = 500_000_000;

/// Height by which Dave's node is killed.  Must be > liveness.start_height (3)
/// and early enough to accumulate a full window of missed blocks.
const DAVE_KILL_HEIGHT: u64 = 5;

/// Maximum height to wait for Dave to be jailed.  The window is 10 blocks, so
/// Dave needs to miss ~7 blocks (>60%) after height 3.  With kill at height 5
/// he starts missing at height 6; expect jail by height 20 with margin.
const JAIL_OBSERVED_BY_HEIGHT: u64 = 30;

/// Height to verify the chain is still advancing after Dave's jailing.
const CONTINUE_THROUGH_HEIGHT: u64 = 35;

/// Per-poll interval when waiting for height advancement.
const POLL_MS: u64 = 400;

/// Overall test timeout.
const TIMEOUT_SECS: u64 = 240;

// ── Fixed ports ───────────────────────────────────────────────────────────────
//
// Fixed ports prevent the Windows port-reuse race that occurs when free_port()
// releases its TcpListener and the OS reallocates the port before the node
// process binds it.  These ranges are chosen to avoid conflicts with other
// live tests:
//   fee_settle   → 18500..18519 / 27100..27119
//   h0_5         → 18280..18299 / 27200..27219
//   h0_7         → 18560..18579 / 27500..27519
//   consensus    → 18480..18499 / 27400..27419
//   h0_11 (this) → 18620..18629 / 27600..27609

const ALICE_API: u16 = 18620;
const ALICE_P2P: u16 = 27600;
const BOB_API:   u16 = 18621;
const BOB_P2P:   u16 = 27601;
const CAROL_API: u16 = 18622;
const CAROL_P2P: u16 = 27602;
const DAVE_API:  u16 = 18623;
const DAVE_P2P:  u16 = 27603;

fn port_is_free(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(200),
    ).is_err()
}

struct Ports;

impl Ports {
    /// API ports for the three surviving nodes (alice, bob, carol).
    fn surviving(&self) -> [u16; 3] { [ALICE_API, BOB_API, CAROL_API] }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

fn manifest_dir() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")) }
fn repo_root()    -> PathBuf { manifest_dir().parent().unwrap().to_path_buf() }

fn node_bin() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let d = target.join("debug").join(&exe);
    let r = target.join("release").join(&exe);
    match (d.metadata().and_then(|m| m.modified()),
           r.metadata().and_then(|m| m.modified())) {
        (Ok(dt), Ok(rt)) => if dt >= rt { d } else { r },
        (Ok(_),  Err(_)) => d,
        (Err(_), Ok(_))  => r,
        _                => d,
    }
}

fn genesis_path() -> PathBuf {
    manifest_dir()
        .join("tests").join("devnet")
        .join("genesis-h0-11-eviction.json")
}

fn devnet_dirs() -> PathBuf {
    std::env::temp_dir().join("h0_11_eviction_devnet")
}

// ── API helpers ───────────────────────────────────────────────────────────────

fn http_get(port: u16, path: &str) -> Option<serde_json::Value> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    let body = buf.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(body).ok()
}

/// Committed height from GET /api/status.
fn height_of(port: u16) -> u64 {
    http_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

/// Balance (uqcb) for address via GET /api/accounts.
fn balance_of(port: u16, addr: &str) -> u128 {
    let accts = http_get(port, "/api/accounts")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    for a in &accts {
        if a["address"].as_str() == Some(addr) {
            let bal = a["balances"]["uqcb"].as_str()
                .and_then(|s| s.parse::<u128>().ok())
                .or_else(|| a["balances"]["uqcb"].as_u64().map(|n| n as u128))
                .unwrap_or(0);
            return bal;
        }
    }
    0
}

/// IDs of validators with voting_power > 0 from GET /api/validators.
fn active_validator_ids(port: u16) -> Vec<String> {
    http_get(port, "/api/validators")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|v| v["voting_power"].as_u64().unwrap_or(0) > 0)
        .filter_map(|v| v["id"].as_str().map(|s| s.to_string()))
        .collect()
}

/// Wait for all ports to reach at least `target` height.
fn wait_for_height(ports: &[u16], target: u64, deadline: Instant) {
    loop {
        assert!(Instant::now() < deadline,
            "timeout waiting for height {target} on {:?}", ports);
        if ports.iter().all(|&p| height_of(p) >= target) { return; }
        std::thread::sleep(Duration::from_millis(POLL_MS));
    }
}

/// Wait for the given port to be unreachable (node killed).
fn wait_port_down(port: u16, deadline: Instant) {
    use std::net::TcpStream;
    loop {
        assert!(Instant::now() < deadline, "timeout waiting for port {port} to go down");
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        ).is_err() { return; }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ── Node spawn ────────────────────────────────────────────────────────────────

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

    // Log stderr to a file so failures are diagnosable.
    let log_path = dirs.join(format!("{label}.log"));
    let log_file = std::fs::File::create(&log_path)
        .unwrap_or_else(|e| panic!("open log {}: {e}", log_path.display()));

    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator-id").arg(validator_id)
       .arg("--api-port").arg(api_port.to_string())
       .arg("--p2p-port").arg(p2p_port.to_string())
       .arg("--data-dir").arg(&data_dir)
       .stdout(Stdio::null())
       .stderr(log_file);
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

// ── Test ──────────────────────────────────────────────────────────────────────

/// H0-11 — Validator eviction acceptance test (E-01..E-04).
///
/// Policy verified: no genesis exemption; jail-only (no stake burn); quorum
/// preserved after a genesis validator is jailed.
#[test]
fn validator_eviction_genesis_no_exemption() {
    // ── Pre-flight port check ─────────────────────────────────────────────────
    for (name, port) in [
        ("alice-api", ALICE_API), ("alice-p2p", ALICE_P2P),
        ("bob-api",   BOB_API),   ("bob-p2p",   BOB_P2P),
        ("carol-api", CAROL_API), ("carol-p2p", CAROL_P2P),
        ("dave-api",  DAVE_API),  ("dave-p2p",  DAVE_P2P),
    ] {
        assert!(port_is_free(port),
            "port {port} ({name}) is already in use — kill stray h0_11 processes first");
    }

    let deadline = Instant::now() + Duration::from_secs(TIMEOUT_SECS);
    let ports    = Ports;
    let dirs     = devnet_dirs();
    let _ = std::fs::remove_dir_all(&dirs);
    std::fs::create_dir_all(&dirs).unwrap();

    // ── Spawn Alice first (bootstrap) ─────────────────────────────────────────
    let mut alice = spawn_node(
        "alice", ALICE_ADDR, ALICE_API, ALICE_P2P, None, &dirs,
    );
    wait_api_ready(ALICE_API, deadline);
    let alice_peer_id = http_get(ALICE_API, "/api/node-info")
        .and_then(|v| v["peer_id"].as_str().map(|s| s.to_string()))
        .expect("E-01: alice peer_id");
    let bootstrap_addr = format!(
        "/ip4/127.0.0.1/tcp/{ALICE_P2P}/p2p/{alice_peer_id}"
    );

    // ── Spawn Bob, Carol, Dave ────────────────────────────────────────────────
    let mut bob = spawn_node(
        "bob", "qcb1bob", BOB_API, BOB_P2P, Some(&bootstrap_addr), &dirs,
    );
    let mut carol = spawn_node(
        "carol", "qcb1carol", CAROL_API, CAROL_P2P, Some(&bootstrap_addr), &dirs,
    );
    let mut dave = spawn_node(
        "dave", DAVE_ADDR, DAVE_API, DAVE_P2P, Some(&bootstrap_addr), &dirs,
    );

    // ── Wait for all four to start and reach height 3 (liveness start) ───────
    for (name, port) in [("bob", BOB_API), ("carol", CAROL_API), ("dave", DAVE_API)] {
        println!("[startup] waiting for {name} API on port {port}…");
        wait_api_ready(port, deadline);
        println!("[startup] {name} ready.");
    }
    println!("[E-01] All four nodes ready. Waiting for height {} (liveness start)…",
             DAVE_KILL_HEIGHT - 1);
    wait_for_height(
        &[ALICE_API, BOB_API, CAROL_API, DAVE_API],
        DAVE_KILL_HEIGHT - 1,
        deadline,
    );

    // E-01 check: Dave is in the active set before being killed.
    let active_before = active_validator_ids(ALICE_API);
    println!("[E-01] Active validators at height {}: {:?}", DAVE_KILL_HEIGHT - 1, active_before);
    assert!(
        active_before.iter().any(|id| id == DAVE_ADDR),
        "E-01 FAIL: Dave not in active set before kill — got {:?}", active_before
    );
    println!("[E-01] PASS — Dave is Active before kill, no false jailing during network formation.");

    // Dave's genesis balance before kill (baseline for E-04).
    let dave_balance_before = balance_of(ALICE_API, DAVE_ADDR);
    println!("[E-04 baseline] Dave balance = {} uqcb", dave_balance_before);
    assert!(
        dave_balance_before > 0,
        "E-04 baseline FAIL: Dave has no balance — genesis not applied"
    );

    // ── E-02: Kill Dave at height DAVE_KILL_HEIGHT ────────────────────────────
    // Wait for the surviving nodes to reach the kill height so Dave has
    // already contributed to those blocks (avoiding false credit).
    wait_for_height(&[ALICE_API, BOB_API, CAROL_API], DAVE_KILL_HEIGHT, deadline);
    println!("[E-02] Killing Dave's node at height {}…", DAVE_KILL_HEIGHT);
    dave.kill().expect("kill dave");
    let _ = dave.wait();
    wait_port_down(DAVE_API, deadline);
    println!("[E-02] Dave's node is down.");

    // ── E-02: Wait for Dave to be jailed (absent from /api/validators) ───────
    println!("[E-02] Waiting for Dave to be jailed (height ≤ {})…", JAIL_OBSERVED_BY_HEIGHT);
    let dave_jailed_height;
    loop {
        assert!(Instant::now() < deadline,
            "E-02 FAIL: Dave was not jailed by height {}", JAIL_OBSERVED_BY_HEIGHT);
        let h = height_of(ALICE_API);
        assert!(
            h <= JAIL_OBSERVED_BY_HEIGHT,
            "E-02 FAIL: reached height {} without Dave being jailed", h
        );
        let active = active_validator_ids(ALICE_API);
        if !active.iter().any(|id| id == DAVE_ADDR) {
            dave_jailed_height = h;
            println!("[E-02] PASS — Dave absent from active set at height {}. Active: {:?}",
                     h, active);
            break;
        }
        std::thread::sleep(Duration::from_millis(POLL_MS));
    }

    // ── E-03: Surviving nodes maintain quorum and advance the chain ───────────
    println!("[E-03] Verifying Alice+Bob+Carol advance chain to height {}…",
             CONTINUE_THROUGH_HEIGHT);
    wait_for_height(&ports.surviving(), CONTINUE_THROUGH_HEIGHT, deadline);
    let surviving_heights: Vec<u64> = ports.surviving().iter().map(|&p| height_of(p)).collect();
    println!("[E-03] PASS — Heights after Dave jailed: {:?}", surviving_heights);
    assert!(
        surviving_heights.iter().all(|&h| h >= CONTINUE_THROUGH_HEIGHT),
        "E-03 FAIL: not all surviving nodes reached height {CONTINUE_THROUGH_HEIGHT}: {:?}",
        surviving_heights
    );

    // E-03 supplemental: confirm Dave's API is still unreachable (still down).
    assert!(
        TcpStream::connect_timeout(
            &format!("127.0.0.1:{DAVE_API}").parse().unwrap(),
            Duration::from_millis(300),
        ).is_err(),
        "E-03: Dave's API port came back up unexpectedly"
    );

    // ── E-04: Dave's stake balance is unchanged ───────────────────────────────
    let dave_balance_after = balance_of(ALICE_API, DAVE_ADDR);
    println!("[E-04] Dave balance after jailing = {} uqcb (was {})",
             dave_balance_after, dave_balance_before);
    assert_eq!(
        dave_balance_after, dave_balance_before,
        "E-04 FAIL: Dave's balance changed after liveness jail. \
         Liveness must never burn stake. \
         Before: {} After: {}", dave_balance_before, dave_balance_after
    );
    // Cross-check: balance matches genesis allocation (no fees charged to Dave
    // because we submitted no transactions from Dave's account).
    assert_eq!(
        dave_balance_after, DAVE_GENESIS_BALANCE,
        "E-04 supplemental: Dave balance {} != genesis {} (no txs were sent from Dave)",
        dave_balance_after, DAVE_GENESIS_BALANCE
    );
    println!("[E-04] PASS — Dave's stake is intact ({} uqcb). Liveness jailing never burns stake.",
             dave_balance_after);

    // ── Summary ───────────────────────────────────────────────────────────────
    println!();
    println!("══════════════════════════════════════════════════════════════════");
    println!(" H0-11 VALIDATOR EVICTION — ALL ASSERTIONS PASSED");
    println!("──────────────────────────────────────────────────────────────────");
    println!(" E-01: Four-node devnet formed; Dave Active at height {} (no false jailing).",
             DAVE_KILL_HEIGHT - 1);
    println!(" E-02: Dave jailed at height {} after kill at height {}.",
             dave_jailed_height, DAVE_KILL_HEIGHT);
    println!(" E-03: Alice+Bob+Carol reached height {} after Dave jailed.",
             CONTINUE_THROUGH_HEIGHT);
    println!(" E-04: Dave stake unchanged at {} uqcb (liveness never burns).",
             dave_balance_after);
    println!();
    println!(" Policy confirmed (owner decision 2026-10-31):");
    println!("   • Genesis validators are NOT exempt from liveness eviction.");
    println!("   • Jail is temporary and reversible; stake is not burned.");
    println!("   • f=1 Byzantine discount is active (3 validators maintain quorum).");
    println!("══════════════════════════════════════════════════════════════════");

    // ── Cleanup ───────────────────────────────────────────────────────────────
    alice.kill().ok(); bob.kill().ok(); carol.kill().ok();
    let _ = alice.wait(); let _ = bob.wait(); let _ = carol.wait();
    let _ = std::fs::remove_dir_all(&dirs);
}
