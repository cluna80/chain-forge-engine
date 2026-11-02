//! H0-12 — Governance Quorum Integration Test
//!
//! Verifies the three-protection model (participation quorum, approval
//! threshold, absolute minimum voter count) using a live 4-node devnet.
//!
//! ## Acceptance criteria
//!
//! | ID    | Scenario |
//! |-------|----------|
//! | GQ-01 | Ordinary proposal, 0 voters → fails quorum |
//! | GQ-02 | Ordinary proposal, 1 voter yes → passes (quorum=1 of 11) |
//! | GQ-03 | Constitutional proposal, 9 voters → fails abs_min (need 10) |
//! | GQ-04 | Constitutional, 11 voters ≥67% yes → passes |
//! | GQ-05 | Quorum met but approval below threshold → fails approval |
//! | GQ-06 | ActivateChange before voting period ends → rejected |
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node --features insecure-dev-quorum
//! cargo test -p chain-forge-node --test governance_quorum_live --features insecure-dev-quorum -- --nocapture
//! ```
//!
//! Per CLAUDE.md: mark GQ-01 through GQ-06 ✅ only after confirmed passing on
//! the developer's local machine (Windows/MINGW64).

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::json;

// ── Constants ─────────────────────────────────────────────────────────────────

const CHAIN_ID: &str = "qcb-devnet-gov-quorum";
const COORDINATOR: &str = "qcb1alice";

const PROPOSER: &str = "qcb1proposer";
const VOTERS: &[&str] = &[
    "qcb1voter1", "qcb1voter2", "qcb1voter3", "qcb1voter4", "qcb1voter5",
    "qcb1voter6", "qcb1voter7", "qcb1voter8", "qcb1voter9", "qcb1voter10",
];

const FIXTURE_PROPOSER: &str = "dis003d-pilot";
const FIXTURE_VOTERS: &[&str] = &[
    "dis003d-guardian1", "dis003d-guardian2", "dis003d-guardian3",
    "dis003d-new-key-f01", "dis003d-new-key-f02", "dis003d-new-key-f03",
    "dis003d-new-key-f04", "dis003d-new-key-f05", "dis003d-new-key-f06",
    "dis003d-new-key-f07",
];

// ── Port helpers ──────────────────────────────────────────────────────────────

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("free_port bind")
        .local_addr().expect("local_addr").port()
}

struct Ports {
    alice: u16, alice_p2p: u16,
    bob:   u16, bob_p2p:   u16,
    carol: u16, carol_p2p: u16,
    dave:  u16, dave_p2p:  u16,
}
impl Ports {
    fn new() -> Self {
        Self {
            alice: free_port(), alice_p2p: free_port(),
            bob:   free_port(), bob_p2p:   free_port(),
            carol: free_port(), carol_p2p: free_port(),
            dave:  free_port(), dave_p2p:  free_port(),
        }
    }
    fn all(&self) -> [u16; 4] { [self.alice, self.bob, self.carol, self.dave] }
}

// ── Path helpers ───────────────────────────────────────────────────────────────

fn manifest_dir() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")) }
fn repo_root()    -> PathBuf { manifest_dir().parent().unwrap().to_path_buf() }

fn node_bin() -> PathBuf {
    // Always use the debug binary — this test requires --features insecure-dev-quorum
    // which is only compiled into the debug build.  A release binary (built without
    // that feature) will reject the low attestation_quorum in the test genesis and
    // silently crash before writing any logs.
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    target.join("debug").join(exe)
}

fn genesis_path() -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("genesis-gov-quorum.json")
}

fn key_file(label: &str) -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json"))
}

fn devnet_dirs() -> PathBuf {
    // Use a per-process-ID directory so each test run is always isolated,
    // even if a previous run's node processes are still holding file locks
    // (common on Windows when the test panics before Drop kills children).
    use std::sync::OnceLock;
    static DIR: OnceLock<std::path::PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        std::env::temp_dir().join(format!("gov_quorum_devnet_{}", std::process::id()))
    }).clone()
}

// ── Node lifecycle ─────────────────────────────────────────────────────────────

struct NodeHandle { #[allow(dead_code)] name: String, process: Child }
impl Drop for NodeHandle { fn drop(&mut self) { let _ = self.process.kill(); } }

fn spawn_node(name: &str, api: u16, p2p: u16, log_dir: &PathBuf,
              peers: &[u16], key_path: Option<PathBuf>) -> NodeHandle {
    let log_file = std::fs::File::create(log_dir.join(format!("{name}.log")))
        .expect("create log");
    let data_dir = devnet_dirs().join("data").join(name);
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator").arg(name)
       .arg("--api-port").arg(api.to_string())
       .arg("--p2p-port").arg(p2p.to_string())
       .arg("--data-dir").arg(&data_dir);
    for &p in peers { cmd.arg("--bootstrap").arg(format!("/ip4/127.0.0.1/tcp/{p}")); }
    if let Some(kf) = key_path { cmd.arg("--key-file").arg(kf); }
    cmd.stdout(log_file.try_clone().unwrap()).stderr(log_file).stdin(Stdio::null());

    let process = cmd.spawn().unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    NodeHandle { name: name.to_string(), process }
}

fn spawn_devnet(ports: &Ports) -> [NodeHandle; 4] {
    let base    = devnet_dirs();
    let log_dir = base.join("logs");
    std::fs::create_dir_all(&log_dir).expect("create log dir");

    let kf = |label: &str| -> Option<PathBuf> {
        let p = key_file(label); if p.exists() { Some(p) } else { None }
    };
    [
        spawn_node("qcb1alice", ports.alice, ports.alice_p2p, &log_dir,
            &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p], kf("alice")),
        spawn_node("qcb1bob",   ports.bob,   ports.bob_p2p,   &log_dir,
            &[ports.alice_p2p, ports.carol_p2p, ports.dave_p2p], kf("bob")),
        spawn_node("qcb1carol", ports.carol, ports.carol_p2p, &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.dave_p2p], kf("carol")),
        spawn_node("qcb1dave",  ports.dave,  ports.dave_p2p,  &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.carol_p2p], kf("dave")),
    ]
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

fn http_raw(method: &str, port: u16, path: &str, body: Option<&str>) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(15_000))).ok()?;
    let req = if let Some(b) = body {
        format!("{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
    } else {
        format!("{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    };
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    let status = buf.lines().next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok()).unwrap_or(0);
    Some((status, buf.split("\r\n\r\n").nth(1).unwrap_or("").to_string()))
}

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let (_, b) = http_raw("GET", port, path, None)?;
    serde_json::from_str(&b).ok()
}

fn api_post(port: u16, path: &str, body: &str) -> (u16, serde_json::Value) {
    match http_raw("POST", port, path, Some(body)) {
        Some((s, r)) => (s, serde_json::from_str(&r).unwrap_or(serde_json::Value::Null)),
        None         => (0, serde_json::Value::Null),
    }
}

fn poll_ready(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if api_get(port, "/api/status").is_some() { return true; }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn submit_tx_json(port: u16, body: &str) -> serde_json::Value {
    api_post(port, "/api/tx", body).1
}

fn wait_tx(port: u16, tx_id: &str, timeout: Duration) -> Option<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(v) = api_get(port, &format!("/api/tx/{tx_id}")) {
            let is_not_found = v["error"].as_str().map_or(false, |e| e.contains("not found"));
            if !is_not_found && (v.get("success").is_some() || v.get("error").is_some()) {
                return Some(v);
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    None
}

fn current_height(port: u16) -> u64 {
    api_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

fn current_nonce(port: u16, addr: &str) -> u64 {
    api_get(port, &format!("/api/accounts/{addr}"))
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(0)
}

fn wait_for_height(port: u16, target: u64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if current_height(port) >= target { return true; }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

fn state_root(port: u16) -> String {
    api_get(port, "/api/status")
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn skip_if_no_binary() -> bool {
    let bin = node_bin();
    if !bin.exists() {
        eprintln!("SKIP: binary not found at {}", bin.display());
        return true;
    }
    false
}

// ── Tx helpers (unsigned — require_signatures: false in genesis) ─────────────

fn unsigned_tx(id: &str, sender: &str, nonce: u64, body: serde_json::Value, gas: u64) -> String {
    json!({
        "id":         id,
        "sender":     sender,
        "nonce":      nonce,
        "body":       body,
        "gas_limit":  gas,
        "signature":  [],
        "public_key": []
    }).to_string()
}

fn submit_and_wait(port: u16, id: &str, sender: &str, nonce: u64,
                   body: serde_json::Value, gas: u64,
                   timeout: Duration) -> serde_json::Value {
    let tx = unsigned_tx(id, sender, nonce, body, gas);
    let sub = submit_tx_json(port, &tx);
    let status = sub["status"].as_str().unwrap_or("");
    eprintln!("[submit_and_wait] id={id} sender={sender} nonce={nonce} status={status} sub={sub}");
    assert!(
        status == "queued" || status == "ok",
        "tx {id} not queued — got: {sub}"
    );
    wait_tx(port, id, timeout)
        .unwrap_or_else(|| panic!("tx {id} never landed (height={})", current_height(port)))
}

// ── Governance JSON helpers ───────────────────────────────────────────────────

fn ordinary_kind_json() -> String {
    serde_json::to_string(&serde_json::json!({
        "QrcParameter": {
            "parameter": "decay_rate",
            "current_value": "0.01",
            "proposed_value": "0.02"
        }
    })).unwrap()
}

fn constitutional_kind_json() -> String {
    serde_json::to_string(&serde_json::json!({
        "Constitutional": {
            "description": "Add veto override clause",
            "affected_section": "Section 7.3"
        }
    })).unwrap()
}

// ── Bootstrap: register and attest all user accounts ─────────────────────────

fn bootstrap_identities(port: u16) {
    let all_addrs: Vec<(&str, &str)> = {
        let mut v: Vec<(&str, &str)> = vec![(PROPOSER, FIXTURE_PROPOSER)];
        for (addr, fixture) in VOTERS.iter().zip(FIXTURE_VOTERS.iter()) {
            v.push((addr, fixture));
        }
        v
    };

    // EPOCH_REG_CAP = 10 (hardcoded in chain-forge-identity).
    // With validator_epoch_blocks=1 each block is a new epoch, so we submit
    // at most 10 registrations per block and wait for the block to commit
    // before sending the next batch.
    println!("[bootstrap] RegisterIdentity for {} accounts (batched by epoch cap=10)",
             all_addrs.len());
    let mut global_offset = 0usize;
    for batch in all_addrs.chunks(10) {
        let mut batch_ids = Vec::new();
        let h_before = current_height(port);
        for (i, (addr, _)) in batch.iter().enumerate() {
            let nonce = current_nonce(port, addr);
            let id = format!("reg-{}-{addr}", global_offset + i);
            let tx = unsigned_tx(&id, addr, nonce,
                json!("RegisterIdentity"), 200_000);
            let resp = submit_tx_json(port, &tx);
            let status = resp["status"].as_str().unwrap_or("");
            assert!(
                status == "queued" || status == "ok",
                "RegisterIdentity for {addr} not queued: {resp}"
            );
            batch_ids.push(id);
        }
        global_offset += batch.len();

        // Wait for this batch to commit before the next batch (next epoch).
        for id in &batch_ids {
            let r = wait_tx(port, id, Duration::from_secs(30))
                .unwrap_or_else(|| panic!("{id} never landed"));
            assert!(
                r["success"].as_bool().unwrap_or(false),
                "RegisterIdentity {id} failed: {r}"
            );
        }
        // Ensure the chain advances to the next epoch before the next batch.
        if global_offset < all_addrs.len() {
            assert!(
                wait_for_height(port, h_before + 1, Duration::from_secs(15)),
                "chain did not advance for next registration epoch"
            );
        }
    }
    println!("[bootstrap] All RegisterIdentity committed.");

    // Alice (genesis validator, auto-Verified) attests each user.
    // With attestation_quorum=1, one attest makes them Verified.
    // Each attest must commit before the next is sent because the node's
    // mempool validates nonces against committed state (no pending-nonce
    // tracking), so submitting nonce N+1 while nonce N is still pending
    // causes a nonce mismatch rejection.
    println!("[bootstrap] Attesting {} accounts via {COORDINATOR} (one at a time)", all_addrs.len());
    for (addr, _) in &all_addrs {
        let alice_nonce = current_nonce(port, COORDINATOR);
        let id = format!("attest-{addr}");
        let r = submit_and_wait(
            port, &id, COORDINATOR, alice_nonce,
            json!({ "Attest": { "claimant_id": addr } }), 100_000,
            Duration::from_secs(30),
        );
        assert!(
            r["success"].as_bool().unwrap_or(false),
            "Attest {id} failed: {r}"
        );
    }
    println!("[bootstrap] All accounts now Verified.");
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn governance_quorum_live() {
    if skip_if_no_binary() { return; }

    let ports = Ports::new();
    println!("\n── Governance Quorum (H0-12) ──────────────────────────────────────");
    println!("   chain_id={CHAIN_ID}  alice_api={}", ports.alice);

    let _nodes = spawn_devnet(&ports);
    let port = ports.alice;

    // Wait for all nodes to be ready.
    for (name, p) in [("alice", ports.alice), ("bob", ports.bob),
                       ("carol", ports.carol), ("dave", ports.dave)] {
        assert!(poll_ready(p, Duration::from_secs(30)),
                "{name} API did not come up");
    }

    // Wait for height 3 (gossip mesh stable).
    assert!(
        wait_for_height(port, 3, Duration::from_secs(30)),
        "chain did not reach height 3"
    );
    println!("   Devnet ready at height {}.", current_height(port));

    // Bootstrap: register and attest all 11 user accounts.
    bootstrap_identities(port);

    // Extra block to propagate identity state to all nodes.
    let h_after_bootstrap = current_height(port) + 2;
    assert!(
        wait_for_height(port, h_after_bootstrap, Duration::from_secs(30)),
        "chain did not advance after bootstrap"
    );
    println!("   Identity bootstrap complete at height {}.", current_height(port));

    // Nonce tracker: all governance txs go through alice's API.
    // Each account's nonce is fetched fresh before each tx to avoid races.

    // ── Submit all 6 proposals in a single burst ──────────────────────────────
    // With validator_epoch_blocks=1, all proposals get the same
    // voting_end_epoch so we only need to wait ONE voting period.

    let _proposer_nonce_base = current_nonce(port, PROPOSER);

    // Proposals are submitted sequentially. Each proposal must commit before the
    // next is sent because the proposer's nonce must match committed state.
    // Use a fresh current_nonce() before each proposal to be safe against any
    // timing edge cases.

    // GQ-01: ordinary, 0 voters
    let p1_resp = submit_and_wait(
        port, "gov-p01", PROPOSER, current_nonce(port, PROPOSER),
        json!({ "ProposeChange": { "kind_json": ordinary_kind_json() } }), 1_000_000,
        Duration::from_secs(45),
    );
    assert!(p1_resp["success"].as_bool().unwrap_or(false),
        "GQ-01: proposal submission failed: {p1_resp}");
    println!("   GQ-01 proposal submitted (id=1).");

    // GQ-02: ordinary, 1 voter yes
    let p2_resp = submit_and_wait(
        port, "gov-p02", PROPOSER, current_nonce(port, PROPOSER),
        json!({ "ProposeChange": { "kind_json": ordinary_kind_json() } }), 1_000_000,
        Duration::from_secs(45),
    );
    assert!(p2_resp["success"].as_bool().unwrap_or(false),
        "GQ-02: proposal submission failed: {p2_resp}");
    println!("   GQ-02 proposal submitted (id=2).");

    // GQ-03: constitutional, 9 voters (fails abs_min)
    let p3_resp = submit_and_wait(
        port, "gov-p03", PROPOSER, current_nonce(port, PROPOSER),
        json!({ "ProposeChange": { "kind_json": constitutional_kind_json() } }), 1_000_000,
        Duration::from_secs(45),
    );
    assert!(p3_resp["success"].as_bool().unwrap_or(false),
        "GQ-03: proposal submission failed: {p3_resp}");
    println!("   GQ-03 proposal submitted (id=3).");

    // GQ-04: constitutional, 11 voters ≥67% yes
    let p4_resp = submit_and_wait(
        port, "gov-p04", PROPOSER, current_nonce(port, PROPOSER),
        json!({ "ProposeChange": { "kind_json": constitutional_kind_json() } }), 1_000_000,
        Duration::from_secs(45),
    );
    assert!(p4_resp["success"].as_bool().unwrap_or(false),
        "GQ-04: proposal submission failed: {p4_resp}");
    println!("   GQ-04 proposal submitted (id=4).");

    // GQ-05: ordinary, quorum met but approval below threshold (0 yes, 1 no)
    let p5_resp = submit_and_wait(
        port, "gov-p05", PROPOSER, current_nonce(port, PROPOSER),
        json!({ "ProposeChange": { "kind_json": ordinary_kind_json() } }), 1_000_000,
        Duration::from_secs(45),
    );
    assert!(p5_resp["success"].as_bool().unwrap_or(false),
        "GQ-05: proposal submission failed: {p5_resp}");
    println!("   GQ-05 proposal submitted (id=5).");

    // GQ-06: ordinary (will be activated early — before voting ends)
    let p6_resp = submit_and_wait(
        port, "gov-p06", PROPOSER, current_nonce(port, PROPOSER),
        json!({ "ProposeChange": { "kind_json": ordinary_kind_json() } }), 1_000_000,
        Duration::from_secs(45),
    );
    assert!(p6_resp["success"].as_bool().unwrap_or(false),
        "GQ-06: proposal submission failed: {p6_resp}");
    println!("   GQ-06 proposal submitted (id=6).");

    // ── GQ-06: Attempt early activation (must fail) ───────────────────────────
    // All 6 proposals were just submitted. Voting period hasn't ended yet.
    let alice_nonce_gq06 = current_nonce(port, COORDINATOR);
    let gq06_early = submit_and_wait(
        port, "gov-act-early", COORDINATOR, alice_nonce_gq06,
        json!({ "ActivateChange": { "proposal_id": 6u64 } }), 500_000,
        Duration::from_secs(20),
    );
    assert!(
        !gq06_early["success"].as_bool().unwrap_or(true),
        "GQ-06: early activation must fail, but got: {gq06_early}"
    );
    let gq06_err = gq06_early["error"].as_str().unwrap_or("");
    assert!(
        gq06_err.contains("VotingActive") || gq06_err.contains("voting") || gq06_err.contains("active"),
        "GQ-06: expected VotingActive error, got: {gq06_early}"
    );
    println!("   ✓ GQ-06 early activation rejected: {gq06_err}");

    // ── Cast votes ────────────────────────────────────────────────────────────

    // GQ-02: voter1 votes yes on proposal 2.
    let v1_nonce = current_nonce(port, VOTERS[0]);
    let gq02_vote = submit_and_wait(
        port, "gov-v02-1", VOTERS[0], v1_nonce,
        json!({ "VoteOnProposal": { "proposal_id": 2u64, "choice": "yes" } }), 500_000,
        Duration::from_secs(20),
    );
    assert!(gq02_vote["success"].as_bool().unwrap_or(false),
        "GQ-02: vote failed: {gq02_vote}");
    println!("   GQ-02: voter1 voted yes.");

    // GQ-03: voters 1..9 vote yes on proposal 3 in parallel.
    // Each voter has an independent nonce so concurrent submission is safe.
    {
        let handles: Vec<_> = (0..9usize).map(|i| {
            let voter = VOTERS[i].to_owned();
            let vid   = format!("gov-v03-{i}");
            std::thread::spawn(move || -> serde_json::Value {
                let vn = current_nonce(port, &voter);
                submit_and_wait(port, &vid, &voter, vn,
                    json!({ "VoteOnProposal": { "proposal_id": 3u64, "choice": "yes" } }),
                    500_000, Duration::from_secs(30))
            })
        }).collect();
        for (i, h) in handles.into_iter().enumerate() {
            let r = h.join().expect("GQ-03 vote thread panicked");
            assert!(r["success"].as_bool().unwrap_or(false),
                "GQ-03: vote {i} failed: {r}");
        }
    }
    println!("   GQ-03: 9 voters voted yes.");

    // GQ-04: proposer + all 10 voters vote in parallel (8 yes, 3 no = 72.7% > 67%).
    {
        let all_gov_voters: Vec<String> = {
            let mut v = vec![PROPOSER.to_owned()];
            v.extend(VOTERS.iter().map(|s| s.to_string()));
            v
        };
        let handles: Vec<_> = all_gov_voters.into_iter().enumerate().map(|(i, addr)| {
            let choice = if i < 8 { "yes" } else { "no" };
            let vid = format!("gov-v04-{i}");
            std::thread::spawn(move || -> (usize, String, serde_json::Value) {
                let vn = current_nonce(port, &addr);
                let r = submit_and_wait(port, &vid, &addr, vn,
                    json!({ "VoteOnProposal": { "proposal_id": 4u64, "choice": choice } }),
                    500_000, Duration::from_secs(30));
                (i, addr, r)
            })
        }).collect();
        for h in handles {
            let (i, addr, r) = h.join().expect("GQ-04 vote thread panicked");
            assert!(r["success"].as_bool().unwrap_or(false),
                "GQ-04: vote {i} ({addr}) failed: {r}");
        }
    }
    println!("   GQ-04: 11 voters voted (8 yes, 3 no).");

    // GQ-05: voter1 votes no on proposal 5 (quorum met but 0% approval).
    // voter1's nonce is now after their GQ-02 + GQ-03 + GQ-04 votes.
    let v1_nonce2 = current_nonce(port, VOTERS[0]);
    let gq05_vote = submit_and_wait(
        port, "gov-v05-1", VOTERS[0], v1_nonce2,
        json!({ "VoteOnProposal": { "proposal_id": 5u64, "choice": "no" } }), 500_000,
        Duration::from_secs(20),
    );
    assert!(gq05_vote["success"].as_bool().unwrap_or(false),
        "GQ-05: vote failed: {gq05_vote}");
    println!("   GQ-05: voter1 voted no.");

    // ── Wait for voting periods to expire ────────────────────────────────────
    // voting_period_epochs=14, validator_epoch_blocks=1 → wait 15 more blocks.
    let h_vote_end = current_height(port) + 16;
    println!("   Waiting for height {h_vote_end} (voting period close)...");
    assert!(
        wait_for_height(port, h_vote_end, Duration::from_secs(90)),
        "chain did not reach height {h_vote_end} within 90s"
    );
    println!("   Voting periods closed at height {}.", current_height(port));

    // ── Activate all proposals ────────────────────────────────────────────────

    let mut act_nonce = current_nonce(port, COORDINATOR);

    // GQ-01: ordinary, 0 voters → must fail (quorum not met).
    let gq01_act = submit_and_wait(
        port, "gov-act-01", COORDINATOR, act_nonce,
        json!({ "ActivateChange": { "proposal_id": 1u64 } }), 500_000,
        Duration::from_secs(20),
    );
    act_nonce += 1;
    assert!(
        !gq01_act["success"].as_bool().unwrap_or(true),
        "GQ-01: activation must fail (no voters), got: {gq01_act}"
    );
    let err01 = gq01_act["error"].as_str().unwrap_or("");
    assert!(
        err01.contains("quorum") || err01.contains("Quorum"),
        "GQ-01: expected quorum failure, got: {gq01_act}"
    );
    println!("   ✓ GQ-01 failed quorum as expected: {err01}");

    // GQ-02: ordinary, 1 voter yes → must succeed (PassedOrdinary).
    let gq02_act = submit_and_wait(
        port, "gov-act-02", COORDINATOR, act_nonce,
        json!({ "ActivateChange": { "proposal_id": 2u64 } }), 500_000,
        Duration::from_secs(20),
    );
    act_nonce += 1;
    assert!(
        gq02_act["success"].as_bool().unwrap_or(false),
        "GQ-02: activation must succeed, got: {gq02_act}"
    );
    let events02 = gq02_act["events"].as_array()
        .map(|e| e.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    let passed02 = events02.iter().any(|e| e.contains("Passed") || e.contains("activate_change"));
    assert!(passed02, "GQ-02: expected Passed in events, got: {gq02_act}");
    println!("   ✓ GQ-02 passed ordinary as expected.");

    // GQ-03: constitutional, 9 voters → must fail (abs_min=10).
    let gq03_act = submit_and_wait(
        port, "gov-act-03", COORDINATOR, act_nonce,
        json!({ "ActivateChange": { "proposal_id": 3u64 } }), 500_000,
        Duration::from_secs(20),
    );
    act_nonce += 1;
    assert!(
        !gq03_act["success"].as_bool().unwrap_or(true),
        "GQ-03: activation must fail (abs_min), got: {gq03_act}"
    );
    let err03 = gq03_act["error"].as_str().unwrap_or("");
    assert!(
        err03.contains("absolute minimum") || err03.contains("abs") || err03.contains("minimum"),
        "GQ-03: expected abs_min failure, got: {gq03_act}"
    );
    println!("   ✓ GQ-03 failed abs_min as expected: {err03}");

    // GQ-04: constitutional, 11 voters ≥67% yes → must succeed (PassedConstitutional).
    let gq04_act = submit_and_wait(
        port, "gov-act-04", COORDINATOR, act_nonce,
        json!({ "ActivateChange": { "proposal_id": 4u64 } }), 500_000,
        Duration::from_secs(20),
    );
    act_nonce += 1;
    assert!(
        gq04_act["success"].as_bool().unwrap_or(false),
        "GQ-04: activation must succeed (constitutional), got: {gq04_act}"
    );
    println!("   ✓ GQ-04 passed constitutional as expected.");

    // GQ-05: ordinary, 1 voter no → must fail (0% approval < 51%).
    let gq05_act = submit_and_wait(
        port, "gov-act-05", COORDINATOR, act_nonce,
        json!({ "ActivateChange": { "proposal_id": 5u64 } }), 500_000,
        Duration::from_secs(20),
    );
    act_nonce += 1;
    assert!(
        !gq05_act["success"].as_bool().unwrap_or(true),
        "GQ-05: activation must fail (approval threshold), got: {gq05_act}"
    );
    let err05 = gq05_act["error"].as_str().unwrap_or("");
    assert!(
        err05.contains("approval") || err05.contains("Approval"),
        "GQ-05: expected approval failure, got: {gq05_act}"
    );
    println!("   ✓ GQ-05 failed approval as expected: {err05}");

    // GQ-06: activate after voting period with 0 votes → fails quorum
    // (the early activation already confirmed the VotingActive rejection above).
    // Now confirm the proposal also fails quorum when activated after period.
    let gq06_late = submit_and_wait(
        port, "gov-act-06-late", COORDINATOR, act_nonce,
        json!({ "ActivateChange": { "proposal_id": 6u64 } }), 500_000,
        Duration::from_secs(20),
    );
    assert!(
        !gq06_late["success"].as_bool().unwrap_or(true),
        "GQ-06: late activation must fail (0 voters = quorum fail), got: {gq06_late}"
    );
    println!("   ✓ GQ-06 late activation failed as expected (early rejection already confirmed).");

    // ── Verify state root is consistent across all 4 nodes ───────────────────
    let roots: Vec<String> = ports.all().iter().map(|&p| state_root(p)).collect();
    let r0 = &roots[0];
    assert!(
        !r0.is_empty(),
        "state root must not be empty"
    );
    for (i, r) in roots.iter().enumerate() {
        assert_eq!(r, r0,
            "node {i} state root {r:?} diverged from node 0 {r0:?}");
    }

    println!();
    println!("── Summary ──────────────────────────────────────────────────────────");
    println!("   ✓ GQ-01: ordinary, 0 voters → quorum failure");
    println!("   ✓ GQ-02: ordinary, 1 voter yes → passed (ordinary)");
    println!("   ✓ GQ-03: constitutional, 9 voters → abs_min failure");
    println!("   ✓ GQ-04: constitutional, 11 voters 72.7% yes → passed");
    println!("   ✓ GQ-05: ordinary, 1 voter no → approval threshold failure");
    println!("   ✓ GQ-06: early activation → VotingActive rejection");
    println!("   state root: {r0}");
    println!("────────────────────────────────────────────────────────────────────");
}
