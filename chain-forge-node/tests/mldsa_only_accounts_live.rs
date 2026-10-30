//! ML-DSA-only user accounts on the upgraded-devnet genesis.
//!
//! `tests/devnet/genesis-4node-mldsa.json` sets `cryptography.signature_scheme
//! = "pqc-native"`: every user transaction must be ML-DSA-65 signed, whatever
//! `require_signatures` says (the template has it `false`). One rule
//! (`check_account_signature_policy`) is applied at API admission, gossip
//! intake and execution, so no entry point accepts what another refuses.
//!
//! | ID   | Check |
//! |------|-------|
//! | A-01 | An Ed25519-signed tx is refused at the API (400, with the reason) by every node |
//! | A-02 | An untagged (legacy-envelope) Ed25519 tx is refused the same way |
//! | A-03 | An unsigned tx is refused, although `require_signatures` is false |
//! | A-04 | A valid ML-DSA-65 tx commits; all 4 nodes agree on the state root |
//! | A-05 | None of the refused txs was ever executed on any node |
//!
//! ## Run
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test mldsa_only_accounts_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: ✅ only after it passes on Windows (MINGW64).

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{ClassicalScheme, MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash};
use chain_forge_execution::Transaction;

const CHAIN_ID:  &str = "qcb-devnet-4node-mldsa";
const USER_ADDR: &str = "qcb1user";
const SEED_USER: &str = "mldsa-only-accounts-user-seed-000000000000000000000001";

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
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let d = target.join("debug").join(&exe);
    let r = target.join("release").join(&exe);
    match (d.metadata().and_then(|m| m.modified()),
           r.metadata().and_then(|m| m.modified())) {
        (Ok(dt), Ok(rt)) => if dt >= rt { d } else { r },
        (Ok(_), Err(_))  => d,
        (Err(_), Ok(_))  => r,
        _                => d,
    }
}

/// `tests/devnet/genesis-4node-mldsa.json` (the upgraded-devnet template)
/// unchanged, plus one funded user account for the test.
fn genesis_path() -> PathBuf {
    let template = repo_root().join("tests").join("devnet").join("genesis-4node-mldsa.json");
    let mut g: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(template).unwrap()).unwrap();
    assert_eq!(g["cryptography"]["signature_scheme"], "pqc-native", "the template must be ML-DSA-only");
    g["genesis_accounts"].as_array_mut().unwrap().push(serde_json::json!({
        "label": "User", "address": USER_ADDR, "balance": "50000000", "role": "user"
    }));
    let out = devnet_dirs().join("genesis.json");
    std::fs::create_dir_all(devnet_dirs()).unwrap();
    if !out.exists() {
        let tmp = out.with_extension("tmp");
        std::fs::write(&tmp, g.to_string()).unwrap();
        std::fs::rename(&tmp, &out).unwrap();
    }
    out
}

fn key_file(label: &str) -> PathBuf {
    repo_root().join("tests").join("devnet").join("keys").join("mldsa").join(format!("{label}.key.json"))
}

fn devnet_dirs() -> PathBuf {
    std::env::temp_dir().join(format!("mldsa_only_accounts_live_{}", std::process::id()))
}

// ── Node lifecycle ─────────────────────────────────────────────────────────────

struct NodeHandle { #[allow(dead_code)] name: String, process: Child }
impl Drop for NodeHandle { fn drop(&mut self) { let _ = self.process.kill(); } }

fn spawn_node(name: &str, api: u16, p2p: u16, log_dir: &PathBuf,
              peers: &[u16], key_file_path: Option<PathBuf>) -> NodeHandle {
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
    if let Some(kf) = key_file_path { cmd.arg("--key-file").arg(kf); }
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

fn submit_tx(port: u16, json: &str) -> serde_json::Value {
    api_post(port, "/api/tx", json).1
}

fn wait_tx_result(port: u16, tx_id: &str, timeout: Duration) -> Option<serde_json::Value> {
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

fn account_of(port: u16, addr: &str) -> Option<serde_json::Value> {
    api_get(port, &format!("/api/accounts/{addr}"))
}

fn state_root(port: u16) -> String {
    api_get(port, "/api/status")
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn current_nonce(port: u16, addr: &str) -> u64 {
    account_of(port, addr)
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(0)
}

fn sig_to_hex(sig: &chain_forge_crypto::Signature) -> String {
    sig.bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn current_height(port: u16) -> u64 {
    api_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

// ── Tx builders ───────────────────────────────────────────────────────────────

fn tx_json(tx: &Transaction) -> String { serde_json::to_string(tx).expect("tx json") }

fn transfer(id: &str, nonce: u64) -> Transaction {
    let mut tx = Transaction::transfer(id, USER_ADDR, "qcb1bob", "uqcb", 1_000, nonce);
    tx.gas_limit = 200_000;
    tx
}

fn mldsa_transfer(id: &str, nonce: u64) -> Transaction {
    let kp = MlDsaScheme.generate_keypair(SEED_USER).expect("keygen");
    let mut tx = transfer(id, nonce);
    let body_json = serde_json::to_string(&tx.body).expect("body");
    let sig = MlDsaScheme.sign(&mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes()), &kp).expect("sign");
    tx.pq_signatures = vec![format!("mldsa65:{}", sig_to_hex(&sig))];
    tx.sig_scheme = Some(SchemeId::MlDsa);
    tx.pq_public_key = kp.public_key.clone();
    tx
}

#[test]
fn ml_dsa_only_accounts_refuse_ed25519_and_unsigned_at_every_node() {
    let _ = std::fs::remove_dir_all(devnet_dirs());
    let ports = Ports::new();
    let _nodes = spawn_devnet(&ports);
    for p in ports.all() {
        assert!(poll_ready(p, Duration::from_secs(30)), "node on :{p} not ready");
    }

    let ed_kp = ClassicalScheme.generate_keypair("mldsa-only-accounts-ed25519").unwrap();
    let mut ed = transfer("acct-ed25519", 0);
    ed.sign(&ed_kp, CHAIN_ID).unwrap();
    let mut ed_untagged = transfer("acct-ed25519-untagged", 0);
    ed_untagged.sign(&ed_kp, CHAIN_ID).unwrap();
    ed_untagged.sig_scheme = None;
    let unsigned = transfer("acct-unsigned", 0);

    // A-01..A-03: refused at every node's API with the policy reason.
    for (id, tx, what) in [("A-01", &ed, "ed25519-signed"), ("A-02", &ed_untagged, "ed25519-signed"), ("A-03", &unsigned, "unsigned")] {
        for p in ports.all() {
            let (status, body) = api_post(p, "/api/tx", &tx_json(tx));
            assert_eq!(status, 400, "{id}: node :{p} must refuse it: {body}");
            let msg = body["message"].as_str().unwrap_or("");
            assert!(msg.contains(what) && msg.contains("ML-DSA-65"), "{id}: reason must name the policy: {msg}");
        }
        println!("✓ {id}: {} refused by all 4 nodes", tx.id);
    }

    // A-04: a valid ML-DSA-65 tx commits on every node.
    let pq = mldsa_transfer("acct-mldsa", 0);
    let resp = submit_tx(ports.alice, &tx_json(&pq));
    assert_eq!(resp["status"], "queued", "A-04: {resp}");
    let r = wait_tx_result(ports.alice, "acct-mldsa", Duration::from_secs(60)).expect("A-04: result");
    assert!(r["success"].as_bool().unwrap_or(false), "A-04: ML-DSA tx must succeed: {r}");
    let h = r["height"].as_u64().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let roots: Vec<String> = ports.all().iter().map(|&p| state_root(p)).collect();
        let heights: Vec<u64> = ports.all().iter().map(|&p| current_height(p)).collect();
        if heights.iter().all(|&x| x == heights[0] && x >= h) && roots.iter().all(|r| !r.is_empty() && *r == roots[0]) {
            break;
        }
        assert!(Instant::now() < deadline, "A-04: nodes disagree: {roots:?} at {heights:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    for p in ports.all() {
        assert_eq!(current_nonce(p, USER_ADDR), 1, "A-04: node :{p} must have executed the ML-DSA tx");
    }
    println!("✓ A-04: ML-DSA tx committed at height {h}; all 4 nodes agree");

    // A-05: the refused txs were never executed anywhere.
    for p in ports.all() {
        for id in ["acct-ed25519", "acct-ed25519-untagged", "acct-unsigned"] {
            let v = api_get(p, &format!("/api/tx/{id}")).unwrap_or(serde_json::Value::Null);
            assert!(v.get("success").is_none(), "A-05: {id} has a result on :{p}: {v}");
        }
    }
    println!("✓ A-05: no refused tx was executed on any node");
    let _ = std::fs::remove_dir_all(devnet_dirs());
}
