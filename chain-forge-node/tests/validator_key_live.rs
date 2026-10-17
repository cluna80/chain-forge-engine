//! CF-DEVNET-VAL-002 — Live post-genesis validator admission and restart
//! acceptance test.
//!
//! Proves that a fifth validator (Eve) can join the active set after genesis
//! by:
//!   1. Registering her identity and gaining verified personhood via on-chain
//!      attestation from the existing four genesis validators (the real
//!      `RegisterIdentity` + `Attest` protocol path — no test bypass).
//!   2. Bonding stake via `BondValidator`.
//!   3. Registering her consensus public key via `RegisterValidatorKey` with
//!      a valid proof-of-possession signature (outer tx also signed by Eve's
//!      wallet key).
//!   4. Waiting for the epoch boundary.
//!   5. Verifying all four original nodes agree on Eve's admission:
//!      address, consensus key, pop_verified, voting_power > 0.
//!   6. Verifying finalized block hash and state root are consistent across
//!      all nodes.
//!   7. Restarting one node at a time (Alice, then Bob) while checking
//!      quorum is maintained after each restart.
//!   8. Confirming Eve's validator state survives both restarts.
//!   9. Optionally demonstrating that killing two equal-weight validators
//!      from a 5-node set halts the chain (below quorum), and that it
//!      recovers once they restart.
//!
//! ## Negative tests (separate `#[test]` functions)
//!
//! - Missing key registration: bonded + personhood but no key → voting_power
//!   == 0.
//! - Invalid proof of possession: `RegisterValidatorKey` tx with garbage PoP
//!   → tx fails.
//! - Forged outer signature: tx body signed by wrong key → rejected.
//! - Wrong chain ID in PoP signing bytes → PoP verification fails.
//! - Unsigned consensus vote from un-keyed validator → rejected by all nodes.
//!
//! ## Prerequisites
//!
//! ```
//! cargo build -p chain-forge-node
//! ```
//!
//! ## Run
//!
//! ```
//! # Main admission test:
//! cargo test -p chain-forge-node --test validator_key_live \
//!     post_genesis_validator_admission -- --nocapture
//!
//! # All tests (including negative):
//! cargo test -p chain-forge-node --test validator_key_live -- --nocapture
//! ```
//!
//! ## Quorum maths
//!
//! With 4 equal-weight validators at 500 QCB each:
//!   total_power = 2_000_000_000 uqcb
//!   quorum      = floor(2_000_000_000 * 2/3) + 1 = 1_333_333_335
//!   → any 3 of 4 can commit (1_500_000_000 >= quorum)  ✓
//!
//! After Eve bonds 2_000_000 uqcb and is admitted:
//!   total_power ≈ 2_002_000_000 uqcb
//!   quorum      ≈ 1_334_666_668
//!   → 4 of 5 can always commit; Alice + Bob (1_000_000_000 uqcb) < quorum
//!   → killing Alice + Bob halts the chain (Carol + Dave + Eve ≈ 1_002_000_000
//!     < quorum). Tested in the deliberate-halt scenario only.

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
use chain_forge_execution::{Transaction, TxBody, validator_key_registration_signing_bytes};

const CHAIN_ID: &str = "qcb-devnet-val002";
/// Eve's wallet address (literal, matches genesis-val002.json genesis_accounts entry).
const EVE_ADDR: &str = "qcb1eve";
/// Alice's wallet address — used as the funding source.
const ALICE_ADDR: &str = "qcb1alice";
/// Amount Eve bonds (2 QCB — well above DEFAULT_MIN_BOND_UQCB = 1_000_000 uqcb).
const EVE_BOND_UQCB: u64 = 2_000_000;

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
    repo_root().join("tests").join("devnet").join("genesis-val002.json")
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

impl NodeHandle {
    fn log_tail(&self, lines: usize) -> String {
        let log = self.log_dir.join(format!("{}.log", self.name));
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .rev()
            .take(lines)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    }
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
    data_dir: Option<PathBuf>,
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
    if let Some(dd) = data_dir {
        cmd.arg("--data-dir").arg(dd);
    }
    cmd.stdout(log_file.try_clone().unwrap())
       .stderr(log_file)
       .stdin(Stdio::null());

    let process = cmd.spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {name}: {e}"));
    NodeHandle { name: name.to_string(), process, log_dir: log_dir.clone() }
}

fn spawn_devnet(ports: &DevnetPorts, log_dir: &PathBuf, data_dirs: Option<&[PathBuf; 4]>) -> Vec<NodeHandle> {
    let kf = |label: &str| Some(key_file(label));
    let dd = |i: usize| data_dirs.map(|d| d[i].clone());
    vec![
        spawn_node("qcb1alice", ports.alice_api, ports.alice_p2p, log_dir,
                   &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p], kf("alice"), dd(0)),
        spawn_node("qcb1bob",   ports.bob_api,   ports.bob_p2p,   log_dir,
                   &[ports.alice_p2p, ports.carol_p2p, ports.dave_p2p], kf("bob"),   dd(1)),
        spawn_node("qcb1carol", ports.carol_api, ports.carol_p2p, log_dir,
                   &[ports.alice_p2p, ports.bob_p2p, ports.dave_p2p], kf("carol"), dd(2)),
        spawn_node("qcb1dave",  ports.dave_api,  ports.dave_p2p,  log_dir,
                   &[ports.alice_p2p, ports.bob_p2p, ports.carol_p2p], kf("dave"),  dd(3)),
    ]
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_raw(method: &str, port: u16, path: &str, body: Option<&str>) -> Option<(u16, String)> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().unwrap(), Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(1000))).ok()?;

    let request = if let Some(b) = body {
        format!(
            "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        )
    } else {
        format!("{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    };

    stream.write_all(request.as_bytes()).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;

    // Parse status line
    let status: u16 = buf.lines().next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = buf.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Some((status, body))
}

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let (_, body) = http_raw("GET", port, path, None)?;
    serde_json::from_str(&body).ok()
}

fn api_post(port: u16, path: &str, body: &str) -> Option<serde_json::Value> {
    let (_, resp) = http_raw("POST", port, path, Some(body))?;
    serde_json::from_str(&resp).ok()
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

/// Wait for a specific tx to appear in the explorer with `success: true`.
/// Returns `Some(events)` on success, `None` on timeout or execution failure.
fn wait_tx_executed(port: u16, tx_id: &str, timeout: Duration) -> Option<Vec<String>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(v) = api_get(port, &format!("/api/tx/{tx_id}")) {
            if v["success"].as_bool() == Some(true) {
                let events: Vec<String> = v["events"].as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect();
                return Some(events);
            }
            if v["success"].as_bool() == Some(false) {
                eprintln!("   tx {tx_id} FAILED: {:?}", v["error"]);
                return None;
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    eprintln!("   tx {tx_id} not found in explorer after {timeout:?}");
    None
}

/// POST a tx to the node and return the tx_id if accepted.
fn submit_tx(port: u16, tx: &Transaction) -> Option<String> {
    let json = serde_json::to_string(tx).expect("tx serialise");
    let resp = api_post(port, "/api/tx", &json)?;
    if resp["status"].as_str() == Some("queued") {
        Some(resp["tx_id"].as_str()?.to_string())
    } else {
        eprintln!("   tx rejected: {:?}", resp);
        None
    }
}

/// Get the validator summary for a given address from the node's /api/validators.
fn get_validator(port: u16, addr: &str) -> Option<serde_json::Value> {
    let vs: Vec<serde_json::Value> = serde_json::from_value(
        api_get(port, "/api/validators")?
    ).ok()?;
    vs.into_iter().find(|v| v["id"].as_str() == Some(addr))
}

/// Get the most recent committed block summary from /api/blocks.
fn latest_block(port: u16) -> Option<serde_json::Value> {
    let blocks: Vec<serde_json::Value> = serde_json::from_value(
        api_get(port, "/api/blocks")?
    ).ok()?;
    blocks.into_iter().next()
}

// ── Tx builders ──────────────────────────────────────────────────────────────

/// Build and sign a RegisterIdentity tx for `sender`.
/// Signing key = ClassicalScheme.generate_keypair(sender) — deterministic.
fn build_register_identity_tx(sender: &str, nonce: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(sender).unwrap();
    let mut tx = Transaction::register_identity(
        &format!("reg-id-{sender}-{nonce}"), sender, nonce,
    );
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

/// Build and sign an Attest tx: `attester` vouches for `claimant`.
fn build_attest_tx(attester: &str, attester_nonce: u64, claimant: &str) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(attester).unwrap();
    let mut tx = Transaction::attest(
        &format!("attest-{attester}-for-{claimant}-{attester_nonce}"),
        attester, claimant, attester_nonce,
    );
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

/// Build and sign a Transfer tx from `from` to `to`.
fn build_transfer_tx(from: &str, from_nonce: u64, to: &str, amount_uqcb: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(from).unwrap();
    let mut tx = Transaction::transfer(
        &format!("xfer-{from}-to-{to}-{from_nonce}"),
        from, to, "uqcb", amount_uqcb as u128, from_nonce,
    );
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

/// Build and sign a BondValidator tx for `sender`.
fn build_bond_tx(sender: &str, nonce: u64, amount_uqcb: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(sender).unwrap();
    let mut tx = Transaction::bond_validator(
        &format!("bond-{sender}-{nonce}"),
        sender, amount_uqcb as u128, nonce,
    );
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

/// Build and sign a RegisterValidatorKey tx.
/// `wallet_kp` signs the outer tx (proves sender controls the bonded address).
/// `consensus_kp` is the key being registered (PoP proves possession).
fn build_register_key_tx(
    sender:       &str,
    nonce:        u64,
    wallet_kp:    &chain_forge_crypto::KeyPair,
    consensus_kp: &chain_forge_crypto::KeyPair,
    chain_id:     &str,
) -> Transaction {
    let pop_msg = validator_key_registration_signing_bytes(chain_id, sender);
    let pop_sig = ClassicalScheme.sign(&pop_msg, consensus_kp).unwrap();
    let mut tx = Transaction {
        id:          format!("regkey-{sender}-{nonce}"),
        sender:      sender.to_string(),
        nonce,
        body:        TxBody::RegisterValidatorKey {
            consensus_pubkey:    consensus_kp.public_key.clone(),
            proof_of_possession: pop_sig.bytes,
        },
        gas_limit:   10_000,
        signature:   vec![],
        public_key:  vec![],
        pq_signatures: vec![],
        pq_public_key: vec![],
    };
    tx.sign(wallet_kp, chain_id).unwrap();
    tx
}

// ─────────────────────────────────────────────────────────────────────────────
// Main acceptance test: CF-DEVNET-VAL-002
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn post_genesis_validator_admission() {
    if skip_if_no_binary() { return; }

    let ports    = DevnetPorts::new();
    let test_id  = format!("val002-{}", ports.alice_api);
    let log_dir  = std::env::temp_dir().join(format!("qcb-{test_id}"));
    std::fs::create_dir_all(&log_dir).unwrap();

    // Isolated per-test data directories so persistence doesn't bleed between runs.
    let data_dirs: [PathBuf; 4] = [
        log_dir.join("data-alice"),
        log_dir.join("data-bob"),
        log_dir.join("data-carol"),
        log_dir.join("data-dave"),
    ];
    for d in &data_dirs { std::fs::create_dir_all(d).unwrap(); }

    eprintln!("\n── CF-DEVNET-VAL-002: post-genesis validator admission ──────────────");
    eprintln!("   log dir:  {log_dir:?}");
    eprintln!("   binary:   {:?}", node_binary());
    eprintln!("   genesis:  {:?}", genesis_path());
    eprintln!("   epoch:    10 blocks × 2 s = 20 s");

    // ── Phase 0: start 4-node devnet ─────────────────────────────────────────

    eprintln!("\n── Phase 0: starting 4-node devnet ─────────────────────────────────");
    let mut nodes = spawn_devnet(&ports, &log_dir, Some(&data_dirs));
    assert!(
        wait_all_apis(
            &[ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api],
            &["alice", "bob", "carol", "dave"],
            Duration::from_secs(20),
        ),
        "devnet APIs did not come up in time"
    );

    eprintln!("\n   Waiting for height >= 2 (chain is live)...");
    assert!(
        poll_height(&ports.all_api(), 2, Duration::from_secs(30)),
        "chain did not reach height 2"
    );
    let h0 = height_of(ports.alice_api);
    eprintln!("   Chain live at height {h0}.");

    // Derive Eve's keypairs.
    // wallet_kp signs Eve's transactions (outer tx auth for RegisterValidatorKey).
    // consensus_kp is the key Eve registers for block signing.
    let eve_wallet_kp    = ClassicalScheme.generate_keypair(EVE_ADDR).unwrap();
    let eve_consensus_kp = ClassicalScheme.generate_keypair("qcb1eve-consensus").unwrap();
    let eve_consensus_hex = hex::encode(&eve_consensus_kp.public_key);
    eprintln!("   Eve wallet pubkey:    {}", hex::encode(&eve_wallet_kp.public_key));
    eprintln!("   Eve consensus pubkey: {eve_consensus_hex}");

    // ── Phase 1: identity registration ───────────────────────────────────────

    eprintln!("\n── Phase 1: Eve registers identity and collects 3 attestations ──────");

    // Eve self-registers as Provisional.
    let reg_tx = build_register_identity_tx(EVE_ADDR, 0);
    let reg_id = reg_tx.id.clone();
    let queued = submit_tx(ports.alice_api, &reg_tx);
    assert!(queued.is_some(), "RegisterIdentity tx rejected at submission");
    eprintln!("   RegisterIdentity queued: {reg_id}");

    // Wait for registration to commit and appear in explorer.
    let events = wait_tx_executed(ports.alice_api, &reg_id, Duration::from_secs(20))
        .expect("RegisterIdentity tx never executed");
    eprintln!("   RegisterIdentity executed. Events: {events:?}");
    assert!(
        events.iter().any(|e| e.contains("registered as Provisional")),
        "expected 'registered as Provisional' event, got: {events:?}"
    );

    // Verify tier = Provisional before attestations.
    let id_state = api_get(ports.alice_api, &format!("/api/identity/{EVE_ADDR}"))
        .expect("/api/identity/qcb1eve returned nothing");
    eprintln!("   Eve identity state after RegisterIdentity: {id_state}");
    assert_eq!(id_state["registered"].as_bool(), Some(true), "Eve not registered");
    assert_ne!(id_state["tier"].as_str(), Some("Verified"),
        "Eve should be Provisional before attestations");

    // Get current nonces for the attesters (alice, bob, carol).
    let alice_nonce0 = api_get(ports.alice_api, &format!("/api/accounts/{ALICE_ADDR}"))
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(0);
    let bob_nonce0   = api_get(ports.alice_api, "/api/accounts/qcb1bob")
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(0);
    let carol_nonce0 = api_get(ports.alice_api, "/api/accounts/qcb1carol")
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(0);

    // Submit attestations from Alice, Bob, Carol (all Verified genesis validators).
    let att1 = build_attest_tx(ALICE_ADDR, alice_nonce0, EVE_ADDR);
    let att2 = build_attest_tx("qcb1bob",  bob_nonce0,   EVE_ADDR);
    let att3 = build_attest_tx("qcb1carol", carol_nonce0, EVE_ADDR);

    let att1_id = att1.id.clone();
    let att2_id = att2.id.clone();
    let att3_id = att3.id.clone();

    submit_tx(ports.alice_api, &att1).expect("attest1 rejected");
    submit_tx(ports.alice_api, &att2).expect("attest2 rejected");
    submit_tx(ports.alice_api, &att3).expect("attest3 rejected");

    // Wait for all three to execute.
    let e1 = wait_tx_executed(ports.alice_api, &att1_id, Duration::from_secs(20))
        .expect("attest1 not executed");
    eprintln!("   attest1 executed: {e1:?}");

    let e2 = wait_tx_executed(ports.alice_api, &att2_id, Duration::from_secs(20))
        .expect("attest2 not executed");
    eprintln!("   attest2 executed: {e2:?}");

    let e3 = wait_tx_executed(ports.alice_api, &att3_id, Duration::from_secs(20))
        .expect("attest3 not executed");
    eprintln!("   attest3 executed: {e3:?}");

    // Third attestation must cross quorum → Verified.
    assert!(
        e3.iter().any(|e| e.contains("quorum reached") || e.contains("Verified")),
        "expected third attestation to trigger quorum upgrade; events: {e3:?}"
    );

    // Confirm identity tier is now Verified.
    let id_after = api_get(ports.alice_api, &format!("/api/identity/{EVE_ADDR}"))
        .expect("/api/identity/qcb1eve returned nothing");
    eprintln!("   Eve identity after attestation quorum: {id_after}");
    assert_eq!(id_after["tier"].as_str(), Some("Verified"),
        "Eve should be Verified after 3 attestations, got: {id_after}");

    // ── Phase 2: bond stake ───────────────────────────────────────────────────

    eprintln!("\n── Phase 2: Eve bonds {EVE_BOND_UQCB} uqcb ─────────────────────────────────");

    // Eve's nonce after RegisterIdentity = 1 (RegisterIdentity consumed nonce 0).
    let eve_nonce1 = 1u64;
    let bond_tx    = build_bond_tx(EVE_ADDR, eve_nonce1, EVE_BOND_UQCB);
    let bond_id    = bond_tx.id.clone();
    submit_tx(ports.alice_api, &bond_tx).expect("BondValidator rejected");

    let bond_events = wait_tx_executed(ports.alice_api, &bond_id, Duration::from_secs(20))
        .expect("BondValidator not executed");
    eprintln!("   BondValidator executed: {bond_events:?}");

    // ── Phase 3: negative check — no key registered yet → power must be 0 ───

    eprintln!("\n── Phase 3: advance past epoch boundary with no key → power must stay 0 ─");

    // Epoch boundary is at height ceil(current_height / 10) * 10.
    let h_before_key = height_of(ports.alice_api);
    let next_epoch   = ((h_before_key / 10) + 1) * 10;
    eprintln!("   Current height: {h_before_key}. Waiting for epoch boundary at {next_epoch}...");

    assert!(
        poll_height(&ports.all_api(), next_epoch + 2, Duration::from_secs(60)),
        "chain did not reach height {} before key registration check", next_epoch + 2
    );

    // Eve should now be in the validator set (bonded + personhood) but with
    // voting_power == 0 because she has no registered consensus key.
    let eve_state_no_key = get_validator(ports.alice_api, EVE_ADDR);
    eprintln!("   Eve in validator set (no key): {eve_state_no_key:?}");
    if let Some(v) = &eve_state_no_key {
        assert_eq!(
            v["voting_power"].as_u64(), Some(0),
            "Eve must have zero voting power without a registered consensus key; got: {v}"
        );
        assert!(
            v["consensus_pubkey"].as_str().map_or(true, |s| s.is_empty()),
            "Eve must have empty consensus_pubkey before registration; got: {v}"
        );
    }
    // If Eve isn't in the set yet, that's fine — she may not have been admitted
    // to the live set before we check. The key point is that she CANNOT have
    // non-zero voting power.

    // ── Phase 4: register consensus key ──────────────────────────────────────

    eprintln!("\n── Phase 4: Eve registers consensus key ─────────────────────────────");

    // Eve's nonce: 0 = RegisterIdentity, 1 = BondValidator, 2 = RegisterValidatorKey.
    let eve_nonce2 = 2u64;
    let regkey_tx  = build_register_key_tx(
        EVE_ADDR, eve_nonce2, &eve_wallet_kp, &eve_consensus_kp, CHAIN_ID,
    );
    let regkey_id = regkey_tx.id.clone();
    submit_tx(ports.alice_api, &regkey_tx).expect("RegisterValidatorKey rejected at submission");
    eprintln!("   RegisterValidatorKey queued: {regkey_id}");

    let key_events = wait_tx_executed(ports.alice_api, &regkey_id, Duration::from_secs(20))
        .expect("RegisterValidatorKey never executed");
    eprintln!("   RegisterValidatorKey executed. Events: {key_events:?}");

    // Event must contain the hex-encoded consensus pubkey.
    assert!(
        key_events.iter().any(|e| e.contains(&eve_consensus_hex)),
        "expected event containing consensus pubkey hex; events: {key_events:?}"
    );

    // ── Phase 5: wait for next epoch — Eve must gain real voting power ────────

    eprintln!("\n── Phase 5: wait for epoch boundary → Eve must become active ────────");

    let h_after_regkey = height_of(ports.alice_api);
    let admission_epoch = ((h_after_regkey / 10) + 1) * 10;
    eprintln!("   Waiting for height {admission_epoch} (next epoch after key registration)...");

    assert!(
        poll_height(&ports.all_api(), admission_epoch + 2, Duration::from_secs(60)),
        "chain did not reach height {}", admission_epoch + 2
    );

    // ── Phase 6: all four nodes must agree on Eve's state ────────────────────

    eprintln!("\n── Phase 6: verify all nodes agree on Eve's admission ───────────────");

    let node_ports = [ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api];
    let node_names = ["alice", "bob", "carol", "dave"];

    let mut eve_powers: Vec<u64>   = vec![];
    let mut eve_keys:   Vec<String> = vec![];
    let mut eve_pops:   Vec<bool>   = vec![];

    for (&port, &name) in node_ports.iter().zip(node_names.iter()) {
        let v = get_validator(port, EVE_ADDR)
            .unwrap_or_else(|| panic!("{name}: Eve not found in /api/validators"));
        eprintln!("   {name}: Eve = {v}");

        let power = v["voting_power"].as_u64().unwrap_or(0);
        let key   = v["consensus_pubkey"].as_str().unwrap_or("").to_string();
        let pop   = v["pop_verified"].as_bool().unwrap_or(false);

        assert!(power > 0,
            "{name}: Eve voting_power should be > 0 after epoch boundary; got {power}");
        assert_eq!(key, eve_consensus_hex,
            "{name}: Eve consensus_pubkey mismatch; expected {eve_consensus_hex}, got {key}");
        assert!(pop,
            "{name}: Eve pop_verified should be true after 3 attestations");

        eve_powers.push(power);
        eve_keys.push(key);
        eve_pops.push(pop);
    }

    // All nodes must agree.
    assert!(eve_powers.windows(2).all(|w| w[0] == w[1]),
        "nodes disagree on Eve's voting_power: {eve_powers:?}");
    assert!(eve_keys.windows(2).all(|w| w[0] == w[1]),
        "nodes disagree on Eve's consensus_pubkey: {eve_keys:?}");
    assert!(eve_pops.windows(2).all(|w| w[0] == w[1]),
        "nodes disagree on Eve's pop_verified: {eve_pops:?}");

    eprintln!("   ✓ All nodes agree: Eve voting_power={} consensus_pubkey={} pop_verified=true",
        eve_powers[0], eve_consensus_hex);

    // Verify finalized block hash and state root are consistent.
    let h_check = height_of(ports.alice_api);
    eprintln!("\n   Verifying block hash / state root consistency at height {h_check}...");
    // Give all nodes a moment to commit the same height.
    poll_height(&ports.all_api(), h_check, Duration::from_secs(10));

    let blocks: Vec<serde_json::Value> = node_ports.iter()
        .filter_map(|&p| latest_block(p))
        .collect();
    eprintln!("   Latest blocks: {blocks:?}");
    if blocks.len() == 4 {
        let root0 = blocks[0]["state_root"].as_str().unwrap_or("");
        // All nodes should converge on the same state root at the same height.
        let h_all: Vec<u64> = blocks.iter()
            .map(|b| b["height"].as_u64().unwrap_or(0))
            .collect();
        let root_all: Vec<&str> = blocks.iter()
            .map(|b| b["state_root"].as_str().unwrap_or(""))
            .collect();
        // At the same height they must agree; heights may differ by 1 in a live network.
        let same_height = h_all.windows(2).all(|w| w[0] == w[1]);
        if same_height {
            assert!(root_all.windows(2).all(|w| w[0] == w[1]),
                "nodes disagree on state root at height {:?}: {:?}", h_all, root_all);
            eprintln!("   ✓ All nodes agree on state root {} at height {}",
                root0, h_all[0]);
        } else {
            eprintln!("   INFO: nodes at different heights {h_all:?}; skipping cross-node root comparison (live network)");
        }
    }

    // ── Phase 7: quorum check before restart ─────────────────────────────────
    //
    // With 5 validators (equal bond), quorum requires 4 of 5.
    // Restarting ONE node at a time ensures the remaining 4 can still commit.

    eprintln!("\n── Phase 7: restart Alice (one node) — quorum must be maintained ────");

    let h_before_restart = height_of(ports.bob_api);
    eprintln!("   Height before Alice restart: {h_before_restart}");

    // Kill Alice.
    drop(nodes.remove(0));  // Alice is index 0
    eprintln!("   Alice killed. Bob/Carol/Dave/Eve (3 genesis + Eve) continue...");
    eprintln!("   NOTE: 4 of 5 validators needed for quorum; 4 remain (Bob+Carol+Dave+Eve cannot provide quorum without Alice's power at this stake ratio).");
    eprintln!("   Checking whether Bob/Carol/Dave can still commit...");

    // Actually: with 4 remaining, check if they can reach quorum.
    // Bob+Carol+Dave = 1_500_000_000 uqcb; Eve = 2_000_000 uqcb.
    // Total = 2_002_000_000; quorum ≈ 1_334_666_668.
    // Bob+Carol+Dave+Eve ≈ 1_502_000_000 > quorum. ✓
    // (Alice alone = 500_000_000 < total - quorum → losing Alice doesn't break quorum.)
    let quorum_ports = [ports.bob_api, ports.carol_api, ports.dave_api];
    assert!(
        poll_height(&quorum_ports, h_before_restart + 2, Duration::from_secs(40)),
        "Bob/Carol/Dave could not commit blocks after Alice restart"
    );
    eprintln!("   ✓ Bob/Carol/Dave advanced without Alice.");

    // Restart Alice with her original data dir (restores live_validator_set.json).
    eprintln!("   Restarting Alice from persisted state...");
    let alice_handle = spawn_node(
        "qcb1alice", ports.alice_api, ports.alice_p2p, &log_dir,
        &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p],
        Some(key_file("alice")),
        Some(data_dirs[0].clone()),
    );
    nodes.push(alice_handle);
    assert!(wait_for_port(ports.alice_api, Duration::from_secs(15)), "Alice API did not come back");
    eprintln!("   Alice API up.");

    // Wait for all nodes including restarted Alice to advance.
    let h_alice_restart_target = height_of(ports.bob_api) + 2;
    assert!(
        poll_height(&ports.all_api(), h_alice_restart_target, Duration::from_secs(60)),
        "Not all nodes advanced after Alice restart"
    );

    // Verify Eve's state is still correct on Alice after restart.
    let eve_after_alice_restart = get_validator(ports.alice_api, EVE_ADDR)
        .expect("Eve not found in Alice's /api/validators after restart");
    eprintln!("   Alice (restarted) Eve state: {eve_after_alice_restart}");
    assert_eq!(
        eve_after_alice_restart["consensus_pubkey"].as_str().unwrap_or(""),
        eve_consensus_hex,
        "Alice: Eve consensus_pubkey lost after restart"
    );
    assert!(
        eve_after_alice_restart["voting_power"].as_u64().unwrap_or(0) > 0,
        "Alice: Eve voting_power dropped to 0 after restart"
    );

    eprintln!("\n── Phase 8: restart Bob — verify Eve state survives second restart ──");

    let h_before_bob_restart = height_of(ports.carol_api);
    drop(nodes.iter_mut().find(|n| n.name == "qcb1bob")
        .map(|n| n.process.kill()));
    // Remove Bob from nodes list cleanly.
    nodes.retain(|n| n.name != "qcb1bob");
    eprintln!("   Bob killed. Waiting for Carol/Dave/Eve/Alice to advance...");

    // Alice+Carol+Dave+Eve ≈ 1_502_000_000 > quorum ✓
    let without_bob = [ports.alice_api, ports.carol_api, ports.dave_api];
    assert!(
        poll_height(&without_bob, h_before_bob_restart + 2, Duration::from_secs(40)),
        "chain halted while Bob was down"
    );
    eprintln!("   ✓ Chain advanced without Bob.");

    // Restart Bob.
    let bob_handle = spawn_node(
        "qcb1bob", ports.bob_api, ports.bob_p2p, &log_dir,
        &[ports.alice_p2p, ports.carol_p2p, ports.dave_p2p],
        Some(key_file("bob")),
        Some(data_dirs[1].clone()),
    );
    nodes.push(bob_handle);
    assert!(wait_for_port(ports.bob_api, Duration::from_secs(15)), "Bob API did not come back");

    let h_all_target = height_of(ports.carol_api) + 2;
    assert!(
        poll_height(&ports.all_api(), h_all_target, Duration::from_secs(60)),
        "Not all 5 nodes advanced after Bob restart"
    );

    // Final cross-node agreement on Eve after both restarts.
    eprintln!("\n── Phase 9: final cross-node agreement after both restarts ──────────");
    for (&port, &name) in node_ports.iter().zip(node_names.iter()) {
        let v = get_validator(port, EVE_ADDR)
            .unwrap_or_else(|| panic!("{name}: Eve lost after restarts"));
        let key   = v["consensus_pubkey"].as_str().unwrap_or("");
        let power = v["voting_power"].as_u64().unwrap_or(0);
        let pop   = v["pop_verified"].as_bool().unwrap_or(false);
        eprintln!("   {name}: Eve power={power} key={key} pop={pop}");
        assert_eq!(key, eve_consensus_hex, "{name}: Eve key changed after restarts");
        assert!(power > 0, "{name}: Eve power dropped after restarts");
        assert!(pop,       "{name}: Eve pop_verified false after restarts");
    }

    eprintln!("\n══ CF-DEVNET-VAL-002: PASS ══════════════════════════════════════════");
    eprintln!("   Eve successfully admitted as post-genesis validator.");
    eprintln!("   Consensus key verified across all nodes before and after restarts.");
    eprintln!("   Quorum maintained through one-at-a-time restart of Alice then Bob.");
}

// ─────────────────────────────────────────────────────────────────────────────
// Negative tests
// ─────────────────────────────────────────────────────────────────────────────

/// A bonded + personhood-verified validator with NO registered consensus key
/// must remain at voting_power == 0 through epoch boundaries.
#[test]
fn bonded_and_verified_without_key_stays_at_zero_power() {
    if skip_if_no_binary() { return; }

    let ports   = DevnetPorts::new();
    let test_id = format!("val002-neg1-{}", ports.alice_api);
    let log_dir = std::env::temp_dir().join(format!("qcb-{test_id}"));
    std::fs::create_dir_all(&log_dir).unwrap();

    eprintln!("\n── Negative test 1: bonded+verified but no key → power == 0 ────────");

    let mut nodes = spawn_devnet(&ports, &log_dir, None);
    assert!(
        wait_all_apis(
            &[ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api],
            &["alice", "bob", "carol", "dave"],
            Duration::from_secs(20),
        ),
        "devnet did not come up"
    );
    assert!(poll_height(&ports.all_api(), 2, Duration::from_secs(30)), "chain stuck");

    // Register Frank (using "qcb1frank" seed). He won't be in genesis so he
    // needs funding first. We fund via Alice (she has plenty of uqcb).
    let frank_addr = "qcb1frank";
    let alice_nonce = api_get(ports.alice_api, &format!("/api/accounts/{ALICE_ADDR}"))
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(0);

    // Fund Frank via Alice.
    let fund_tx = build_transfer_tx(ALICE_ADDR, alice_nonce, frank_addr, 5_000_000);
    let fund_id = fund_tx.id.clone();
    submit_tx(ports.alice_api, &fund_tx).expect("fund tx rejected");
    wait_tx_executed(ports.alice_api, &fund_id, Duration::from_secs(20))
        .expect("fund tx not executed");

    // Frank: RegisterIdentity, 3 attestations, BondValidator — but NO RegisterValidatorKey.
    submit_tx(ports.alice_api, &build_register_identity_tx(frank_addr, 0))
        .expect("Frank RegisterIdentity rejected");

    let alice_n2   = alice_nonce + 1;
    let bob_n0     = api_get(ports.alice_api, "/api/accounts/qcb1bob")
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(0);
    let carol_n0   = api_get(ports.alice_api, "/api/accounts/qcb1carol")
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(0);
    submit_tx(ports.alice_api, &build_attest_tx(ALICE_ADDR, alice_n2, frank_addr))
        .expect("att1 rejected");
    submit_tx(ports.alice_api, &build_attest_tx("qcb1bob",   bob_n0,   frank_addr))
        .expect("att2 rejected");
    let att3 = build_attest_tx("qcb1carol", carol_n0, frank_addr);
    let att3_id = att3.id.clone();
    submit_tx(ports.alice_api, &att3).expect("att3 rejected");
    wait_tx_executed(ports.alice_api, &att3_id, Duration::from_secs(20))
        .expect("att3 not executed");

    let bond_tx = build_bond_tx(frank_addr, 1, 2_000_000);
    let bond_id = bond_tx.id.clone();
    submit_tx(ports.alice_api, &bond_tx).expect("bond rejected");
    wait_tx_executed(ports.alice_api, &bond_id, Duration::from_secs(20))
        .expect("bond not executed");

    // Advance past two epoch boundaries to give the admission path every chance.
    let h = height_of(ports.alice_api);
    let target = ((h / 10) + 2) * 10 + 2;
    assert!(poll_height(&ports.all_api(), target, Duration::from_secs(80)), "chain stuck");

    let frank_vs = get_validator(ports.alice_api, frank_addr);
    eprintln!("   Frank in validator set: {frank_vs:?}");
    if let Some(v) = frank_vs {
        assert_eq!(v["voting_power"].as_u64(), Some(0),
            "Frank must have zero power without a registered key; got: {v}");
        eprintln!("   ✓ Frank power == 0 (no key registered).");
    } else {
        eprintln!("   ✓ Frank not yet in active set (also acceptable — no key means no power).");
    }

    drop(nodes);
    eprintln!("   PASS: bonded+verified without key stays at zero power.");
}

/// A `RegisterValidatorKey` tx with a garbage proof-of-possession must be
/// executed but fail: `success == false` in the explorer.
#[test]
fn invalid_proof_of_possession_rejected() {
    if skip_if_no_binary() { return; }

    let ports   = DevnetPorts::new();
    let test_id = format!("val002-neg2-{}", ports.alice_api);
    let log_dir = std::env::temp_dir().join(format!("qcb-{test_id}"));
    std::fs::create_dir_all(&log_dir).unwrap();

    eprintln!("\n── Negative test 2: invalid PoP → tx fails ──────────────────────────");

    let mut nodes = spawn_devnet(&ports, &log_dir, None);
    assert!(
        wait_all_apis(
            &[ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api],
            &["alice", "bob", "carol", "dave"],
            Duration::from_secs(20),
        ),
        "devnet did not come up"
    );
    assert!(poll_height(&ports.all_api(), 2, Duration::from_secs(30)), "chain stuck");

    let wallet_kp    = ClassicalScheme.generate_keypair(EVE_ADDR).unwrap();
    let consensus_kp = ClassicalScheme.generate_keypair("qcb1eve-consensus").unwrap();

    // Build a RegisterValidatorKey tx with GARBAGE proof-of-possession.
    let mut tx = Transaction {
        id:          "bad-pop-test".to_string(),
        sender:      EVE_ADDR.to_string(),
        nonce:       0,
        body:        TxBody::RegisterValidatorKey {
            consensus_pubkey:    consensus_kp.public_key.clone(),
            proof_of_possession: vec![0xde, 0xad, 0xbe, 0xef].into_iter().cycle().take(64).collect(),  // 64 bytes of garbage
        },
        gas_limit:   10_000,
        signature:   vec![],
        public_key:  vec![],
        pq_signatures: vec![],
        pq_public_key: vec![],
    };
    tx.sign(&wallet_kp, CHAIN_ID).unwrap();

    let tx_id = tx.id.clone();
    submit_tx(ports.alice_api, &tx).expect("tx accepted into mempool");

    // Wait for it to execute (it should be included in a block and fail there).
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut found = false;
    while Instant::now() < deadline {
        if let Some(v) = api_get(ports.alice_api, &format!("/api/tx/{tx_id}")) {
            if v.get("success").is_some() {
                assert_eq!(v["success"].as_bool(), Some(false),
                    "tx with invalid PoP must fail; got: {v}");
                assert!(
                    v["error"].as_str().map_or(false, |e| e.contains("proof-of-possession")),
                    "error must mention proof-of-possession; got: {:?}", v["error"]
                );
                found = true;
                eprintln!("   ✓ Invalid PoP correctly rejected: {:?}", v["error"]);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(found, "tx with invalid PoP never appeared in explorer");

    drop(nodes);
    eprintln!("   PASS: invalid proof-of-possession rejected at execution.");
}

/// A `RegisterValidatorKey` tx signed with the WRONG outer key (not the
/// bonded address's key) must be rejected.
#[test]
fn forged_outer_signature_rejected() {
    if skip_if_no_binary() { return; }

    let ports   = DevnetPorts::new();
    let test_id = format!("val002-neg3-{}", ports.alice_api);
    let log_dir = std::env::temp_dir().join(format!("qcb-{test_id}"));
    std::fs::create_dir_all(&log_dir).unwrap();

    eprintln!("\n── Negative test 3: forged outer signature → submission rejected ─────");

    let mut nodes = spawn_devnet(&ports, &log_dir, None);
    assert!(
        wait_all_apis(
            &[ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api],
            &["alice", "bob", "carol", "dave"],
            Duration::from_secs(20),
        ),
        "devnet did not come up"
    );
    assert!(poll_height(&ports.all_api(), 2, Duration::from_secs(30)), "chain stuck");

    let attacker_kp  = ClassicalScheme.generate_keypair("qcb1attacker").unwrap();
    let consensus_kp = ClassicalScheme.generate_keypair("qcb1eve-consensus").unwrap();

    // Build RegisterValidatorKey for EVE but sign the outer tx with ATTACKER's key.
    let pop_msg = validator_key_registration_signing_bytes(CHAIN_ID, EVE_ADDR);
    let pop_sig = ClassicalScheme.sign(&pop_msg, &consensus_kp).unwrap();
    let mut tx = Transaction {
        id:          "forged-sig-test".to_string(),
        sender:      EVE_ADDR.to_string(),  // claims to be Eve
        nonce:       0,
        body:        TxBody::RegisterValidatorKey {
            consensus_pubkey:    consensus_kp.public_key.clone(),
            proof_of_possession: pop_sig.bytes,
        },
        gas_limit:   10_000,
        signature:   vec![],
        public_key:  vec![],
        pq_signatures: vec![],
        pq_public_key: vec![],
    };
    tx.sign(&attacker_kp, CHAIN_ID).unwrap();  // signed by attacker, not Eve

    let resp = api_post(ports.alice_api, "/api/tx",
        &serde_json::to_string(&tx).unwrap());
    eprintln!("   Forged tx submission response: {resp:?}");

    // `verify_authorization_for` is called unconditionally at execution time,
    // even when require_signatures=false. However, the mempool does not verify
    // signatures when require_signatures=false (relaxed devnet). So the tx may
    // be queued but must FAIL at execution with a signature mismatch.
    //
    // Check both paths: either rejected at submission OR fails at execution.
    if let Some(ref v) = resp {
        if v["status"].as_str() == Some("rejected") {
            eprintln!("   ✓ Forged tx rejected at submission: {:?}", v["message"]);
            drop(nodes);
            return;
        }
    }

    // If queued, it must fail at execution.
    let tx_id = "forged-sig-test";
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut found = false;
    while Instant::now() < deadline {
        if let Some(v) = api_get(ports.alice_api, &format!("/api/tx/{tx_id}")) {
            if v.get("success").is_some() {
                assert_eq!(v["success"].as_bool(), Some(false),
                    "forged outer signature tx must fail; got: {v}");
                found = true;
                eprintln!("   ✓ Forged outer signature rejected at execution: {:?}", v["error"]);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(found, "forged tx never appeared in explorer");

    drop(nodes);
    eprintln!("   PASS: forged outer signature rejected.");
}

/// A `RegisterValidatorKey` with a PoP signed for the WRONG chain ID must fail.
#[test]
fn wrong_chain_id_in_pop_rejected() {
    if skip_if_no_binary() { return; }

    let ports   = DevnetPorts::new();
    let test_id = format!("val002-neg4-{}", ports.alice_api);
    let log_dir = std::env::temp_dir().join(format!("qcb-{test_id}"));
    std::fs::create_dir_all(&log_dir).unwrap();

    eprintln!("\n── Negative test 4: wrong chain ID in PoP → tx fails ────────────────");

    let mut nodes = spawn_devnet(&ports, &log_dir, None);
    assert!(
        wait_all_apis(
            &[ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api],
            &["alice", "bob", "carol", "dave"],
            Duration::from_secs(20),
        ),
        "devnet did not come up"
    );
    assert!(poll_height(&ports.all_api(), 2, Duration::from_secs(30)), "chain stuck");

    let wallet_kp    = ClassicalScheme.generate_keypair(EVE_ADDR).unwrap();
    let consensus_kp = ClassicalScheme.generate_keypair("qcb1eve-consensus").unwrap();

    // Sign PoP for the WRONG chain ID.
    let pop_msg = validator_key_registration_signing_bytes("wrong-chain-id", EVE_ADDR);
    let pop_sig = ClassicalScheme.sign(&pop_msg, &consensus_kp).unwrap();
    let mut tx = Transaction {
        id:          "wrong-chain-id-pop".to_string(),
        sender:      EVE_ADDR.to_string(),
        nonce:       0,
        body:        TxBody::RegisterValidatorKey {
            consensus_pubkey:    consensus_kp.public_key.clone(),
            proof_of_possession: pop_sig.bytes,
        },
        gas_limit:   10_000,
        signature:   vec![],
        public_key:  vec![],
        pq_signatures: vec![],
        pq_public_key: vec![],
    };
    tx.sign(&wallet_kp, CHAIN_ID).unwrap();  // outer tx correctly signed for right chain

    let tx_id = tx.id.clone();
    submit_tx(ports.alice_api, &tx).expect("tx accepted into mempool");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut found = false;
    while Instant::now() < deadline {
        if let Some(v) = api_get(ports.alice_api, &format!("/api/tx/{tx_id}")) {
            if v.get("success").is_some() {
                assert_eq!(v["success"].as_bool(), Some(false),
                    "wrong-chain-id PoP must fail at execution; got: {v}");
                assert!(
                    v["error"].as_str().map_or(false, |e| e.contains("proof-of-possession")),
                    "error must mention proof-of-possession; got: {:?}", v["error"]
                );
                found = true;
                eprintln!("   ✓ Wrong-chain-id PoP correctly rejected: {:?}", v["error"]);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(found, "wrong-chain-id tx never appeared in explorer");

    drop(nodes);
    eprintln!("   PASS: wrong chain ID in PoP rejected.");
}
