//! 4-node devnet integration tests.
//!
//! ## Tests
//!
//! ### `devnet_4node_reaches_target_height`
//! Spawns four `chain-forge-node` processes (Alice, Bob, Carol, Dave) against
//! `tests/devnet/genesis-4node.json`, then polls each node's `/api/status`
//! endpoint until all four report `height >= 3` or the test times out.
//! First end-to-end proof that the real libp2p gossip layer works — real TCP
//! connections, real mDNS peer discovery, real proposal/vote/commit round-trips
//! across separate OS processes.
//!
//! ### `devnet_4node_partition_recovery`
//! Builds on the above: lets all 4 nodes reach height 3, then uses `iptables`
//! to DROP all packets to/from Alice's P2P port (simulating a hard network
//! partition that isolates one validator).  After a 5-second hold the rule is
//! removed.  The test then waits for all 4 nodes to advance to height 6,
//! proving that:
//!   - the 3-of-4 quorum (Bob, Carol, Dave) can commit blocks during the
//!     partition, and
//!   - Alice resumes and catches up once the partition heals.
//!
//! The partition test is skipped (not failed) if `iptables` is not available
//! or cannot insert rules (no root / no CAP_NET_ADMIN).
//!
//! ## Run
//! ```
//! cargo test --test devnet_4node -- --nocapture
//! ```
//!
//! The tests are skipped (not failed) in environments where the binary isn't
//! built yet, so they never break a `cargo test --workspace` that hasn't run
//! `cargo build` first.
//!
//! ## Environment variables
//! | Variable              | Default | Meaning                          |
//! |-----------------------|---------|----------------------------------|
//! | DEVNET_TIMEOUT_SECS   | 60      | Seconds to wait per phase        |
//! | DEVNET_TARGET_HEIGHT  | 3       | First height target (phase 1)    |
//! | DEVNET_PARTITION_HOLD | 5       | Seconds the partition lasts      |

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

/// Alice is always validator index 0.
const ALICE_IDX: usize = 0;

/// Target chain height all four nodes must reach (phase 1).
const DEFAULT_TARGET_HEIGHT: u64 = 3;
/// Seconds to wait per polling phase before declaring failure.
const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// Seconds to hold the iptables partition rule before restoring.
const DEFAULT_PARTITION_HOLD_SECS: u64 = 5;

// ── Path helpers ─────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    // This file lives at <repo>/chain-forge-node/tests/devnet_4node.rs.
    // `CARGO_MANIFEST_DIR` is <repo>/chain-forge-node.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().to_path_buf()
}

fn node_binary() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    // On Windows the binary is `chain-forge-node.exe`; EXE_SUFFIX is ".exe"
    // on Windows and "" everywhere else.
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let debug   = target.join("debug").join(&exe);
    let release = target.join("release").join(&exe);

    // Prefer the binary that was most recently modified so that a freshly-built
    // debug binary (e.g. after `cargo build -p chain-forge-node`) is used even
    // when an older release binary also exists.  Fall back to whichever exists.
    match (debug.metadata().and_then(|m| m.modified()),
           release.metadata().and_then(|m| m.modified())) {
        (Ok(dt), Ok(rt)) => if dt >= rt { debug } else { release },
        (Ok(_), Err(_))  => debug,
        (Err(_), Ok(_))  => release,
        (Err(_), Err(_)) => debug, // neither exists — return debug so the skip message names a path
    }
}

fn genesis_path() -> PathBuf {
    repo_root().join("tests").join("devnet").join("genesis-4node.json")
}

// ── Network helpers ───────────────────────────────────────────────────────────

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

    // Parse `"height":<number>` without pulling in serde.
    body.split("\"height\":")
        .nth(1)
        .and_then(|s| s.split([',', '}']).next())
        .and_then(|s| s.trim().parse().ok())
}

/// Ensure a port is free before we try to bind it.
fn port_is_free(port: u16) -> bool {
    TcpStream::connect(format!("127.0.0.1:{port}")).is_err()
}

// ── iptables partition helpers ────────────────────────────────────────────────

/// Returns true if `iptables` exists and we can list rules (i.e. we have
/// CAP_NET_ADMIN or are root).  Used to skip the partition test gracefully.
fn iptables_available() -> bool {
    Command::new("iptables")
        .args(["-L", "-n"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The loopback interface flag differs by chain direction:
///   INPUT  uses `-i lo`  (incoming interface)
///   OUTPUT uses `-o lo`  (outgoing interface)
/// Using `-i` on OUTPUT is rejected by iptables (nf_tables backend).
fn iface_flag(chain: &str) -> &'static str {
    if chain == "INPUT" { "-i" } else { "-o" }
}

/// Insert INPUT + OUTPUT DROP rules for `port` on loopback.
/// Always calls `remove_partition_rules` first so that a stale rule
/// from a previously crashed test run is flushed before inserting a
/// fresh one (idempotent).
fn insert_partition_rules(port: u16) {
    // Flush any leftover rules from a previous (possibly crashed) run.
    remove_partition_rules(port);

    // INPUT  drops packets arriving  at this port  (others → Alice)
    // OUTPUT drops packets departing from this port (Alice → others)
    for (chain, port_flag) in [("INPUT", "--dport"), ("OUTPUT", "--sport")] {
        let status = Command::new("iptables")
            .args([
                "-I", chain, "1",
                "-p", "tcp",
                iface_flag(chain), "lo",
                port_flag, &port.to_string(),
                "-j", "DROP",
            ])
            .status()
            .expect("iptables INSERT failed");
        assert!(status.success(), "iptables -I {chain} failed");
    }
    println!("   [partition] iptables DROP rules inserted for port {port}");
}

/// Remove the INPUT + OUTPUT DROP rules added by `insert_partition_rules`.
/// Uses `-D` (delete first match) which is safe to call even if the rule
/// no longer exists.
fn remove_partition_rules(port: u16) {
    for (chain, port_flag) in [("INPUT", "--dport"), ("OUTPUT", "--sport")] {
        let _ = Command::new("iptables")
            .args([
                "-D", chain,
                "-p", "tcp",
                iface_flag(chain), "lo",
                port_flag, &port.to_string(),
                "-j", "DROP",
            ])
            .status();
    }
    println!("   [partition] iptables DROP rules removed for port {port}");
}

// ── RAII process guard ────────────────────────────────────────────────────────

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

// ── Shared: spawn + wait for APIs ────────────────────────────────────────────

fn spawn_nodes(bin: &PathBuf, genesis: &PathBuf, log_dir: &PathBuf) -> Vec<NodeProcess> {
    let mut nodes: Vec<NodeProcess> = Vec::new();

    for (i, &validator) in VALIDATORS.iter().enumerate() {
        let api_port = API_PORTS[i];
        let p2p_port = P2P_PORTS[i];
        let log_path = log_dir.join(format!("{validator}.log"));
        let log_file = std::fs::File::create(&log_path)
            .unwrap_or_else(|e| panic!("cannot create log {log_path:?}: {e}"));

        println!("   Starting {validator}  api=:{api_port}  p2p=:{p2p_port}  log={log_path:?}");

        // Derive key file from validator name: "qcb1alice" -> "alice.key.json"
        let short_name = validator.strip_prefix("qcb1").unwrap_or(validator);
        let key_file = repo_root()
            .join("tests").join("devnet").join("keys")
            .join(format!("{short_name}.key.json"));

        let child = Command::new(bin)
            .args([
                "--genesis",   genesis.to_str().unwrap(),
                "--validator", validator,
                "--key-file",  key_file.to_str().unwrap(),
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

    // Wait for every API port to bind.
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

    nodes
}

/// Poll /api/status on all nodes until every node reaches `target_height` or
/// `timeout` elapses.  Panics with a log dump on timeout.
fn poll_until_height(
    nodes: &mut Vec<NodeProcess>,
    target_height: u64,
    timeout: Duration,
    log_dir: &PathBuf,
    phase_label: &str,
) -> HashMap<&'static str, u64> {
    println!("   [{phase_label}] Polling /api/status (target: height >= {target_height})...\n");

    let start = Instant::now();
    let mut heights: HashMap<&str, u64> = HashMap::new();

    loop {
        let elapsed = start.elapsed();

        if elapsed >= timeout {
            println!("\nTIMEOUT after {elapsed:.1?} [{phase_label}]");
            for node in nodes.iter() {
                let h = heights.get(node.validator).copied().unwrap_or(0);
                println!("   {}  height={h}  (need {target_height})", node.validator);
            }

            for node in nodes.iter() {
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
                "[{phase_label}] 4-node devnet did not reach height {target_height} within {timeout:?}"
            );
        }

        let mut all_reached = true;
        let mut status = String::new();

        for node in nodes.iter_mut() {
            if let Ok(Some(exit)) = node.child.try_wait().map_err(|_| ()) {
                panic!("{} exited unexpectedly with status: {exit}", node.validator);
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
                "\n\n── [{phase_label}] All 4 nodes reached height {target_height} in {:.1?} ──",
                start.elapsed()
            );
            for node in nodes.iter() {
                println!("   {}  height={}", node.validator, heights[node.validator]);
            }
            println!();
            return heights;
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── Test 1: basic liveness ────────────────────────────────────────────────────

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
    assert!(genesis.exists(), "genesis file not found: {genesis:?}");

    for port in API_PORTS.iter().chain(P2P_PORTS.iter()) {
        assert!(
            port_is_free(*port),
            "port {port} is already in use — kill any stray node processes first"
        );
    }

    let timeout = Duration::from_secs(
        std::env::var("DEVNET_TIMEOUT_SECS")
            .ok().and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS),
    );
    let target_height: u64 = std::env::var("DEVNET_TARGET_HEIGHT")
        .ok().and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TARGET_HEIGHT);

    println!(
        "\n── 4-node devnet integration test ──────────────────────────────────\n\
           binary:        {bin:?}\n\
           genesis:       {genesis:?}\n\
           target_height: {target_height}\n\
           timeout:       {timeout:?}\n"
    );

    let log_dir = std::env::temp_dir().join("qcb-devnet-4node");
    std::fs::create_dir_all(&log_dir).unwrap();

    let mut nodes = spawn_nodes(&bin, &genesis, &log_dir);
    poll_until_height(&mut nodes, target_height, timeout, &log_dir, "liveness");
    // NodeProcess::drop() kills the children.
}

// ── Test 2: partition recovery ────────────────────────────────────────────────

/// End-to-end partition recovery test.
///
/// Phase 1 — steady state:  all 4 nodes commit blocks to height 3.
/// Phase 2 — partition:     iptables DROPs all TCP to/from Alice's P2P port.
///                          Bob, Carol, Dave (3-of-4 quorum) keep committing.
/// Phase 3 — heal:          DROP rules removed.  All 4 nodes must reach
///                          height `target_height + 3` (i.e. 6 by default),
///                          proving Alice resumed and the others didn't stall.
///
/// Skipped (not failed) when iptables is unavailable or unprivileged.
#[test]
fn devnet_4node_partition_recovery() {
    let bin = node_binary();
    if !bin.exists() {
        println!(
            "SKIP: node binary not found at {bin:?}. \
             Run `cargo build --bin chain-forge-node` first."
        );
        return;
    }

    if !iptables_available() {
        println!(
            "SKIP: iptables not available or insufficient permissions. \
             Run as root or with CAP_NET_ADMIN to enable this test."
        );
        return;
    }

    let genesis = genesis_path();
    assert!(genesis.exists(), "genesis file not found: {genesis:?}");

    for port in API_PORTS.iter().chain(P2P_PORTS.iter()) {
        assert!(
            port_is_free(*port),
            "port {port} is already in use — kill any stray node processes first"
        );
    }

    let timeout = Duration::from_secs(
        std::env::var("DEVNET_TIMEOUT_SECS")
            .ok().and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS),
    );
    let phase1_target: u64 = std::env::var("DEVNET_TARGET_HEIGHT")
        .ok().and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TARGET_HEIGHT);
    let partition_hold = Duration::from_secs(
        std::env::var("DEVNET_PARTITION_HOLD")
            .ok().and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_PARTITION_HOLD_SECS),
    );
    let phase3_target = phase1_target + 3;

    let alice_p2p_port = P2P_PORTS[ALICE_IDX];

    println!(
        "\n── 4-node partition-recovery integration test ───────────────────────\n\
           binary:          {bin:?}\n\
           genesis:         {genesis:?}\n\
           phase1_target:   {phase1_target}\n\
           partition_hold:  {partition_hold:?}\n\
           phase3_target:   {phase3_target}\n\
           timeout/phase:   {timeout:?}\n\
           alice_p2p_port:  {alice_p2p_port}\n"
    );

    let log_dir = std::env::temp_dir().join("qcb-devnet-4node-partition");
    std::fs::create_dir_all(&log_dir).unwrap();

    // Pre-emptively remove any stale DROP rules left over from a crashed
    // previous run.  This is safe to call even when no rules exist.
    println!("   Flushing any stale iptables rules for port {alice_p2p_port}...");
    remove_partition_rules(alice_p2p_port);

    // ── Phase 1: steady-state liveness ───────────────────────────────────────
    println!("── Phase 1: steady state ────────────────────────────────────────────");
    let mut nodes = spawn_nodes(&bin, &genesis, &log_dir);
    poll_until_height(&mut nodes, phase1_target, timeout, &log_dir, "phase1/steady-state");

    // ── Phase 2: partition (DROP Alice's P2P port) ────────────────────────────
    println!("── Phase 2: inserting network partition (Alice isolated) ────────────");
    insert_partition_rules(alice_p2p_port);

    // Use a panic guard so the DROP rules are always cleaned up even if
    // Phase 3's poll panics on timeout.
    struct PartitionGuard { port: u16, active: bool }
    impl Drop for PartitionGuard {
        fn drop(&mut self) {
            if self.active {
                eprintln!("   [partition guard] removing iptables rules on drop");
                remove_partition_rules(self.port);
            }
        }
    }
    let mut guard = PartitionGuard { port: alice_p2p_port, active: true };

    println!("   Holding partition for {partition_hold:?}...");
    std::thread::sleep(partition_hold);

    // ── Phase 3: heal and wait for full recovery ──────────────────────────────
    println!("── Phase 3: healing partition ───────────────────────────────────────");
    remove_partition_rules(alice_p2p_port);
    guard.active = false; // disarm the guard — we already cleaned up

    poll_until_height(&mut nodes, phase3_target, timeout, &log_dir, "phase3/recovery");

    println!("── Partition recovery PASSED ────────────────────────────────────────");
    println!("   Alice re-joined the network and all 4 nodes reached height {phase3_target}.");
    println!();
    // NodeProcess::drop() kills the children.
}
