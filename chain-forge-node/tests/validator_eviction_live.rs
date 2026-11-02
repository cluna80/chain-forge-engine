//! H0-11 — Validator Eviction (live acceptance test)
//!
//! Acceptance criteria:
//!
//! EV-01 — UnbondValidator evicts from active set at next epoch boundary.
//!          Eve bonds, gains admission, then unbonds.  At the next epoch
//!          boundary she must disappear from GET /api/validators.
//!
//! EV-02 — No outbid-eviction.  When Eve joins with a smaller bond than the
//!          genesis validators, Alice/Bob/Carol/Dave remain in the active set.
//!          Confirmed again after Eve's eviction: existing validators are
//!          unaffected.
//!
//! EV-03 — State root consistent across all 4 nodes after the eviction
//!          epoch boundary.
//!
//! ## Policy (ROADMAP H0-11, recorded 2026-11-01)
//!
//! * Eviction is deterministic at epoch boundaries.
//! * Eviction is NOT triggered by outbidding (consensus is personhood-weighted,
//!   not stake-weighted).
//! * Sustained failure (liveness / equivocation) → suspension or eviction.
//! * Genesis validators are NOT permanently exempt.
//! * Synthetic bootstrap validators retire under an explicit transition policy.
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test validator_eviction_live -- --nocapture
//! ```

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
use chain_forge_execution::{Transaction, TxBody};

const CHAIN_ID:    &str = "qcb-devnet-val-evict";
const ALICE_ADDR:  &str = "qcb1alice";
const EVE_ADDR:    &str = "qcb1eve";
/// Eve's bond: above min (1_000_000 uqcb) but well below genesis validators.
const EVE_BOND:    u64  = 2_000_000;
/// Phase-0b bond for each genesis validator (leaves room for fee buffer).
const GENESIS_BOND: u64 = 490_000_000;

// ── Port helpers ──────────────────────────────────────────────────────────────

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Ports {
    alice_api: u16, alice_p2p: u16,
    bob_api:   u16, bob_p2p:   u16,
    carol_api: u16, carol_p2p: u16,
    dave_api:  u16, dave_p2p:  u16,
}
impl Ports {
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

// ── Binary / paths ────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn node_bin() -> PathBuf {
    // Always use the debug binary — the eviction test uses the standard
    // genesis (no insecure-dev-quorum) so this is just about freshness.
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    target.join("debug").join(exe)
}

fn genesis_path() -> PathBuf {
    repo_root().join("tests").join("devnet").join("genesis-val-evict.json")
}

fn key_file(label: &str) -> PathBuf {
    repo_root().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json"))
}

// ── Node lifecycle ────────────────────────────────────────────────────────────

struct NodeHandle {
    _proc: Child,
}
impl Drop for NodeHandle {
    fn drop(&mut self) {
        let _ = self._proc.kill();
        let _ = self._proc.wait();
    }
}

fn spawn_node(
    name: &str, api: u16, p2p: u16,
    log_dir: &PathBuf, data_dir: &PathBuf, peers: &[u16],
) -> NodeHandle {
    std::fs::create_dir_all(data_dir).unwrap();
    let log = std::fs::File::create(log_dir.join(format!("{name}.log"))).unwrap();
    let bootstrap: Vec<String> = peers.iter().map(|&p| format!("/ip4/127.0.0.1/tcp/{p}")).collect();
    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator").arg(name)
       .arg("--api-port").arg(api.to_string())
       .arg("--p2p-port").arg(p2p.to_string())
       .arg("--data-dir").arg(data_dir)
       .arg("--key-file").arg(key_file(name.strip_prefix("qcb1").unwrap_or(name)));
    for addr in &bootstrap { cmd.arg("--bootstrap").arg(addr); }
    cmd.stdout(log.try_clone().unwrap()).stderr(log).stdin(Stdio::null());
    NodeHandle { _proc: cmd.spawn().unwrap_or_else(|e| panic!("spawn {name}: {e}")) }
}

fn spawn_devnet(ports: &Ports, log_dir: &PathBuf) -> Vec<NodeHandle> {
    let names = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
    let peers_list = [
        vec![ports.bob_p2p, ports.carol_p2p, ports.dave_p2p],
        vec![ports.alice_p2p, ports.carol_p2p, ports.dave_p2p],
        vec![ports.alice_p2p, ports.bob_p2p, ports.dave_p2p],
        vec![ports.alice_p2p, ports.bob_p2p, ports.carol_p2p],
    ];
    let api_ports  = [ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api];
    let p2p_ports  = [ports.alice_p2p, ports.bob_p2p, ports.carol_p2p, ports.dave_p2p];
    names.iter().enumerate().map(|(i, &name)| {
        let data_dir = log_dir.join(format!("data-{}", name.strip_prefix("qcb1").unwrap_or(name)));
        spawn_node(name, api_ports[i], p2p_ports[i], log_dir, &data_dir, &peers_list[i])
    }).collect()
}

/// Read the last `n` lines of a log file for diagnostic output.
fn tail_log(log_dir: &PathBuf, name: &str, n: usize) -> String {
    let path = log_dir.join(format!("{name}.log"));
    std::fs::read_to_string(&path)
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(n);
            lines[start..].join("\n")
        })
        .unwrap_or_else(|_| format!("<log not found: {path:?}>"))
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_get(port: u16, path: &str) -> Option<serde_json::Value> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut s = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(500),
    ).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;
    write!(s, "GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1).unwrap_or("")).ok()
}

fn http_post(port: u16, path: &str, body: &str) -> Option<serde_json::Value> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut s = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(500),
    ).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;
    let req = format!(
        "POST {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1).unwrap_or("")).ok()
}

fn height(port: u16) -> u64 {
    http_get(port, "/api/status").and_then(|v| v["height"].as_u64()).unwrap_or(0)
}

fn state_root(port: u16) -> String {
    http_get(port, "/api/status")
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn poll_ready(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(100),
        ).is_ok() { return true; }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn wait_for_height(port: u16, target: u64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if height(port) >= target { return true; }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

fn nonce(port: u16, addr: &str) -> u64 {
    http_get(port, &format!("/api/account/{addr}"))
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(0)
}

fn submit_and_wait(port: u16, tx: &Transaction, timeout: Duration) -> serde_json::Value {
    let body = serde_json::to_string(tx).unwrap();
    let resp = http_post(port, "/api/tx", &body).unwrap_or_default();
    let id = tx.id.clone();
    assert_eq!(resp["status"].as_str().unwrap_or(""), "queued",
               "tx {id} not queued: {resp}");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(r) = http_get(port, &format!("/api/tx/{id}")) {
            if r["success"].as_bool().is_some() { return r; }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("tx {id} never landed (height={})", height(port));
}

/// Returns the current validator set from GET /api/validators.
fn validators(port: u16) -> Vec<serde_json::Value> {
    http_get(port, "/api/validators")
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

fn is_in_set(port: u16, addr: &str) -> bool {
    validators(port).iter().any(|v| v["id"].as_str() == Some(addr))
}

fn voting_power(port: u16, addr: &str) -> u64 {
    validators(port).iter()
        .find(|v| v["id"].as_str() == Some(addr))
        .and_then(|v| v["voting_power"].as_u64())
        .unwrap_or(0)
}

// ── Tx builders ───────────────────────────────────────────────────────────────

fn bond_tx(sender: &str, nonce_val: u64, amount: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(sender).unwrap();
    let mut tx = Transaction::bond_validator(
        &format!("bond-{sender}-{nonce_val}"), sender, amount as u128, nonce_val,
    );
    if let TxBody::BondValidator { ref mut owner_identity_id, .. } = tx.body {
        *owner_identity_id = Some(sender.to_string());
    }
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

fn unbond_tx(sender: &str, nonce_val: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(sender).unwrap();
    let mut tx = Transaction::unbond_validator(
        &format!("unbond-{sender}-{nonce_val}"), sender, nonce_val,
    );
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

fn register_identity_tx(sender: &str, nonce_val: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(sender).unwrap();
    let mut tx = Transaction::register_identity(
        &format!("reg-{sender}-{nonce_val}"), sender, nonce_val,
    );
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

fn attest_tx(attester: &str, attester_nonce: u64, claimant: &str) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(attester).unwrap();
    let mut tx = Transaction::attest(
        &format!("attest-{attester}-for-{claimant}-{attester_nonce}"),
        attester, claimant, attester_nonce,
    );
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn validator_eviction_live() {
    let bin = node_bin();
    if !bin.exists() {
        eprintln!("SKIP: binary not found at {bin:?}. Run `cargo build -p chain-forge-node`.");
        return;
    }

    let ports  = Ports::new();
    let run_id = format!("val-evict-{}", ports.alice_api);
    let tmp    = std::env::temp_dir().join(format!("qcb-{run_id}"));
    std::fs::create_dir_all(&tmp).unwrap();

    println!("\n── Validator Eviction (H0-11) ──────────────────────────────────────");
    println!("   chain_id={CHAIN_ID}  alice_api={}", ports.alice_api);

    // ── Start 4-node devnet ───────────────────────────────────────────────────
    let _nodes = spawn_devnet(&ports, &tmp);
    let all_api = ports.all_api();
    let node_names = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
    for (i, &p) in all_api.iter().enumerate() {
        assert!(poll_ready(p, Duration::from_secs(30)),
                "node{i} ({}) API did not come up on :{p}\n--- last 40 log lines ---\n{}\n---",
                node_names[i], tail_log(&tmp, node_names[i], 40));
    }
    // Poll all 4 nodes; require all of them to reach height 3 (same as validator_key_live).
    // Give 60 s — Windows under concurrent test load can be slow to form consensus.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let hs: Vec<u64> = all_api.iter().map(|&p| height(p)).collect();
        print!("\r   heights: alice={} bob={} carol={} dave={}   ",
               hs[0], hs[1], hs[2], hs[3]);
        let _ = std::io::Write::flush(&mut std::io::stdout());
        if hs.iter().all(|&h| h >= 3) { println!(); break; }
        if Instant::now() >= deadline {
            println!();
            for (i, name) in node_names.iter().enumerate() {
                eprintln!("--- {} log tail ---\n{}", name, tail_log(&tmp, name, 40));
            }
            panic!("devnet did not reach height 3 within 60s (heights: alice={} bob={} carol={} dave={})",
                   hs[0], hs[1], hs[2], hs[3]);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("   Devnet ready at height {}.", height(ports.alice_api));

    // ── Phase 0b: genesis validators bond so quorum stays correct ────────────
    // Each genesis validator bonds 490_000_000 uqcb; this gives them real
    // voting power proportional to stake so Eve's small bond can't skew quorum.
    let genesis_addrs = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
    let genesis_ports = [ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api];
    // Track the nonce each genesis validator has consumed; starts at 0 (genesis state).
    let mut genesis_nonces = [0u64; 4];
    for (i, (addr, &p)) in genesis_addrs.iter().zip(genesis_ports.iter()).enumerate() {
        let n = nonce(p, addr);
        let r = submit_and_wait(p, &bond_tx(addr, n, GENESIS_BOND), Duration::from_secs(20));
        assert!(r["success"].as_bool().unwrap_or(false),
                "Phase-0b bond for {addr} failed: {r}");
        genesis_nonces[i] = n + 1; // next nonce for this validator after the bond tx
    }
    println!("   Phase-0b bonds complete.");

    // Wait for epoch boundary so genesis bonds take effect.
    let h_epoch1 = height(ports.alice_api) + 6; // 5-block epoch + 1
    assert!(wait_for_height(ports.alice_api, h_epoch1, Duration::from_secs(30)),
            "epoch 1 not reached");
    println!("   Epoch 1 boundary passed at height {}.", height(ports.alice_api));

    // Verify all 4 genesis validators are in the active set with power > 0.
    for addr in &genesis_addrs {
        let vp = voting_power(ports.alice_api, addr);
        assert!(vp > 0, "{addr} has voting_power=0 after Phase-0b bond");
    }
    println!("   All 4 genesis validators active.");

    // ── Eve's identity bootstrap ──────────────────────────────────────────────
    // Eve needs Verified personhood to get pop_verified=true and real voting power.
    let reg = register_identity_tx(EVE_ADDR, 0);
    let r = submit_and_wait(ports.alice_api, &reg, Duration::from_secs(20));
    assert!(r["success"].as_bool().unwrap_or(false), "Eve RegisterIdentity failed: {r}");

    // Alice, Bob, Carol attest Eve (3 attestations → Verified).
    // Use the tracked nonces (each already sent 1 Bond tx in Phase-0b).
    for (i, (attester, &p)) in genesis_addrs[..3].iter().zip(genesis_ports[..3].iter()).enumerate() {
        let n = genesis_nonces[i];
        let tx = attest_tx(attester, n, EVE_ADDR);
        let r = submit_and_wait(p, &tx, Duration::from_secs(20));
        assert!(r["success"].as_bool().unwrap_or(false),
                "{attester} Attest for Eve failed: {r}");
        genesis_nonces[i] += 1;
    }
    println!("   Eve identity: Verified.");

    // ── EV-02 setup: Eve bonds (smaller than genesis validators) ─────────────
    // Eve's RegisterIdentity consumed nonce 0; track nonces explicitly.
    let eve_n0 = 1u64;
    let r = submit_and_wait(ports.alice_api, &bond_tx(EVE_ADDR, eve_n0, EVE_BOND),
                            Duration::from_secs(20));
    assert!(r["success"].as_bool().unwrap_or(false), "Eve BondValidator failed: {r}");
    println!("   Eve bonded {} uqcb.", EVE_BOND);

    // Wait for epoch boundary where Eve is admitted.
    let h_eve_admit = height(ports.alice_api) + 6;
    assert!(wait_for_height(ports.alice_api, h_eve_admit, Duration::from_secs(30)),
            "Eve admission epoch not reached");
    println!("   Eve admission epoch boundary at height {}.", height(ports.alice_api));

    // EV-02: Genesis validators are still in the active set (not outbid-evicted).
    for addr in &genesis_addrs {
        assert!(is_in_set(ports.alice_api, addr),
                "EV-02 FAIL: {addr} was evicted when Eve joined (outbid-eviction must not happen)");
    }
    // Eve should now be in the set with voting_power > 0.
    assert!(is_in_set(ports.alice_api, EVE_ADDR),
            "Eve not admitted to active set after bonding");
    let eve_vp = voting_power(ports.alice_api, EVE_ADDR);
    assert!(eve_vp > 0, "Eve voting_power=0 after admission (pop_verified may not have fired)");
    println!("   ✓ EV-02: genesis validators unaffected by Eve's admission (voting_power={eve_vp}).");

    // ── EV-01: Eve unbonds → evicted at next epoch boundary ──────────────────
    let eve_n1 = eve_n0 + 1;
    let r = submit_and_wait(ports.alice_api, &unbond_tx(EVE_ADDR, eve_n1),
                            Duration::from_secs(20));
    assert!(r["success"].as_bool().unwrap_or(false), "Eve UnbondValidator failed: {r}");
    println!("   Eve unbonded. Waiting for eviction epoch boundary...");

    // Wait for the next epoch boundary (Pass 3 fires here).
    let h_evict = height(ports.alice_api) + 6;
    assert!(wait_for_height(ports.alice_api, h_evict, Duration::from_secs(30)),
            "eviction epoch not reached");
    println!("   Eviction epoch boundary at height {}.", height(ports.alice_api));

    // EV-01: Eve must be gone from all 4 nodes.
    for (i, &p) in all_api.iter().enumerate() {
        assert!(!is_in_set(p, EVE_ADDR),
                "EV-01 FAIL: Eve still in active set on node{i} (port {p}) after unbonding");
    }
    println!("   ✓ EV-01: Eve evicted from all 4 nodes after unbonding.");

    // EV-02 (re-confirmed): Genesis validators still present after Eve's eviction.
    for addr in &genesis_addrs {
        assert!(is_in_set(ports.alice_api, addr),
                "EV-02 FAIL: {addr} missing after Eve's eviction");
        let vp = voting_power(ports.alice_api, addr);
        assert!(vp > 0, "EV-02 FAIL: {addr} has voting_power=0 after eviction epoch");
    }
    println!("   ✓ EV-02: genesis validators unaffected by Eve's eviction.");

    // ── EV-03: State root consistent across all 4 nodes ──────────────────────
    let roots: Vec<String> = all_api.iter().map(|&p| state_root(p)).collect();
    let r0 = &roots[0];
    assert!(!r0.is_empty(), "state root must not be empty");
    for (i, r) in roots.iter().enumerate() {
        assert_eq!(r, r0, "EV-03 FAIL: node{i} state root {r} != node0 {r0}");
    }
    println!("   ✓ EV-03: state root consistent: {r0}");

    println!("\n── Summary ──────────────────────────────────────────────────────────");
    println!("   ✓ EV-01: UnbondValidator → evicted from active set at epoch boundary");
    println!("   ✓ EV-02: Existing validators not evicted when Eve joined or left");
    println!("   ✓ EV-03: State root consistent across all 4 nodes after eviction");
    println!("   state root: {r0}");
    println!("────────────────────────────────────────────────────────────────────");
}
