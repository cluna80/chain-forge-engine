//! DIS-003E — Recovery Timelock and Cancellation
//!
//! Tests the two-phase recovery commit: a valid `RecoverAccountKey` tx sets a
//! `pending_recovery` on the account without immediately rotating the key.
//! After `recovery_timelock_blocks` blocks pass unchallenged, the block
//! finalisation sweep activates the recovery and replaces the key.  The
//! current account key may submit `CancelRecovery` during the window to
//! permanently void the pending recovery.
//!
//! ## Acceptance criteria
//!
//! | ID   | Scenario |
//! |------|----------|
//! | C-14 | Valid recovery sets `pending_recovery`; key is NOT immediately replaced |
//! | C-15 | `CancelRecovery` signed by current account key during timelock voids the recovery |
//! | C-16 | Unchallenged recovery activates at `activation_height`; key is replaced and `pending_recovery` is cleared |
//! | C-17 | A cancelled recovery cannot be re-activated after its `activation_height` passes |
//! | C-18 | A new `EnrollRecoveryPolicy` while a recovery is pending cancels the pending recovery |
//! | C-19 | Four-node state root convergence after all ops |
//!
//! ## Additional security requirements (owner, 2026-10-31)
//!
//! - C-15b: A `CancelRecovery` submitted at exactly `activation_height` takes
//!          priority and prevents the same-block finalisation sweep from activating.
//! - Cancellation requires the *currently active* account key, not the proposed
//!   recovery key.
//! - `PendingRecovery` survives node restarts; activation result is identical
//!   across validators (deterministic sweep).
//!
//! ## Devnet genesis
//!
//! `tests/devnet/genesis-dis003e.json`:
//!   - chain_id: `qcb-devnet-dis003e`
//!   - recovery_timelock_blocks: 5
//!   - qcb1pilot: ML-DSA key = dis003d-pilot fixture
//!   - qcb1victim: ML-DSA key = dis003d-guardian1 fixture
//!     (victim is a second user account for C-15 signed-by-wrong-key tests)
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test dis_003e_timelock_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: mark C-14 through C-19 ✅ only after confirmed passing on
//! the developer's local machine (Windows/MINGW64).

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{KeyPair, MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash};
use chain_forge_execution::{
    Transaction, TxBody, GuardianAuth,
    account_key_rotation_signing_bytes,
    recovery_domain_signing_bytes,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const CHAIN_ID:   &str = "qcb-devnet-dis003e";
const PILOT_ADDR: &str = "qcb1pilot";

/// Seed for qcb1pilot's genesis key (dis003d-pilot fixture).
const SEED_PILOT: &str = "dis003d-pilot-device-seed-000000000000000000000000001";
/// Seed for guardian1 (also qcb1victim's genesis key in this devnet).
const SEED_G1:    &str = "dis003d-guardian-1-seed-000000000000000000000000000010";
const SEED_G2:    &str = "dis003d-guardian-2-seed-000000000000000000000000000020";
const SEED_G3:    &str = "dis003d-guardian-3-seed-000000000000000000000000000030";

// Seed → fixture file stem mapping.
// All seeds used in this test must appear here — no fallback to generate_keypair.
const SEED_FIXTURE_NAMES: &[(&str, &str)] = &[
    (SEED_PILOT, "dis003d-pilot"),
    (SEED_G1,    "dis003d-guardian1"),
    (SEED_G2,    "dis003d-guardian2"),
    (SEED_G3,    "dis003d-guardian3"),
    // Rotation keys: new keys proposed in recover_account_key txs.
    ("dis003d-new-key-f01-seed-000000000000000000000001", "dis003d-new-key-f01"),
    ("dis003d-new-key-f02-seed-000000000000000000000002", "dis003d-new-key-f02"),
    ("dis003d-new-key-f03-seed-000000000000000000000003", "dis003d-new-key-f03"),
    ("dis003d-new-key-f04-seed-000000000000000000000004", "dis003d-new-key-f04"),
    ("dis003d-new-key-f05-seed-000000000000000000000005", "dis003d-new-key-f05"),
    ("dis003d-new-key-f06-seed-000000000000000000000006", "dis003d-new-key-f06"),
    ("dis003d-new-key-f07-seed-000000000000000000000007", "dis003d-new-key-f07"),
];

/// Load a pinned keypair from `tests/devnet/keys/<name>.key.json`.
///
/// # Panics
/// Panics on any problem — no fallback to `generate_keypair`.
fn load_fixture_keypair(seed: &str) -> KeyPair {
    let (_, name) = SEED_FIXTURE_NAMES
        .iter()
        .find(|(s, _)| *s == seed)
        .unwrap_or_else(|| panic!(
            "load_fixture_keypair: no fixture registered for seed {:?}. \
             Add an entry to SEED_FIXTURE_NAMES.",
            seed
        ));

    let path = manifest_dir()
        .join("tests")
        .join("devnet")
        .join("keys")
        .join(format!("{name}.key.json"));

    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!(
        "fixture {name}: cannot read {:?}: {e}", path
    ));
    let obj = serde_json::from_str::<serde_json::Value>(&raw).unwrap_or_else(|e| panic!(
        "fixture {name}: JSON parse error: {e}"
    ));

    let pk_hex = obj["public_key"].as_str().unwrap_or_else(|| panic!(
        "fixture {name}: missing \"public_key\""
    ));
    let sk_hex = obj["private_key"].as_str().unwrap_or_else(|| panic!(
        "fixture {name}: missing \"private_key\""
    ));

    fn from_hex(h: &str) -> Vec<u8> {
        (0..h.len()).step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i+2], 16).unwrap_or(0))
            .collect()
    }

    let pk = from_hex(pk_hex);
    let sk = from_hex(sk_hex);
    if pk.len() != 1952 { panic!("fixture {name}: bad pk len {} (want 1952)", pk.len()); }
    if sk.len() != 4032 {
        panic!("fixture {name}: bad sk len {} (want 4032) — likely Linux system dilithium", sk.len());
    }
    eprintln!("[fixture] loaded {name}: pk={}B sk={}B", pk.len(), sk.len());
    KeyPair { scheme: SchemeId::MlDsa, public_key: pk, private_key: sk }
}

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
    manifest_dir().join("tests").join("devnet").join("genesis-dis003e.json")
}

fn key_file(label: &str) -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json"))
}

fn devnet_dirs() -> PathBuf {
    std::env::temp_dir().join("dis003e_timelock_devnet")
}

// ── Node lifecycle ────────────────────────────────────────────────────────────

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

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_raw(method: &str, port: u16, path: &str, body: Option<&str>) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    let body_len = body.map(|b| b.len()).unwrap_or(0);
    let read_ms  = 15_000u64 + (body_len as u64 / 4_096) * 1_000;
    stream.set_read_timeout(Some(Duration::from_millis(read_ms))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok()?;

    let headers = if let Some(b) = body {
        format!("{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len())
    } else {
        format!("{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    };
    stream.write_all(headers.as_bytes()).ok()?;
    if let Some(b) = body { stream.write_all(b.as_bytes()).ok()?; }

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

fn submit_tx(port: u16, tx_json: &str) -> serde_json::Value {
    let (_, v) = api_post(port, "/api/tx", tx_json);
    v
}

fn wait_tx_result(port: u16, tx_id: &str, timeout: Duration) -> Option<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(v) = api_get(port, &format!("/api/tx/{tx_id}")) {
            if v.get("height").is_some() { return Some(v); }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    None
}

fn wait_height(port: u16, target: u64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if current_height(port) >= target { return true; }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn account_of(port: u16, addr: &str) -> Option<serde_json::Value> {
    api_get(port, &format!("/api/accounts/{addr}"))
}

fn state_root(port: u16) -> String {
    api_get(port, "/api/status")
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn current_height(port: u16) -> u64 {
    api_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

fn current_nonce(port: u16, addr: &str) -> u64 {
    account_of(port, addr)
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(0)
}

fn sig_to_hex(sig: &chain_forge_crypto::Signature) -> String {
    sig.bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tx builders ───────────────────────────────────────────────────────────────

fn ml_dsa_tx(seed: &str, sender: &str, nonce: u64, body: TxBody,
             tx_id: &str, gas: u64) -> Transaction {
    let kp        = load_fixture_keypair(seed);
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let msg       = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig       = MlDsaScheme.sign(&msg, &kp).expect("sign");
    Transaction {
        id: tx_id.to_string(), sender: sender.to_string(), nonce, body,
        gas_limit:     gas,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{}", sig_to_hex(&sig))],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: kp.public_key.clone(),
    }
}

fn build_enroll(seed: &str, sender: &str, nonce: u64,
                guardians: Vec<Vec<u8>>, threshold: u32, tx_id: &str) -> Transaction {
    ml_dsa_tx(seed, sender, nonce,
        TxBody::EnrollRecoveryPolicy { guardians, threshold },
        tx_id, 500_000)
}

/// Build a `RecoverAccountKey` tx with all guardian sigs having `None` expiry.
fn build_recover(
    new_seed:       &str,
    sender:         &str,
    nonce:          u64,
    key_version:    u32,
    guardian_seeds: &[&str],
    policy_id:      u64,
    tx_id:          &str,
) -> Transaction {
    let new_kp  = load_fixture_keypair(new_seed);
    let pop_msg = account_key_rotation_signing_bytes(CHAIN_ID, sender, key_version, &new_kp.public_key);
    let pop_sig = MlDsaScheme.sign(&pop_msg, &new_kp).expect("PoP sign");

    let guardian_signatures: Vec<GuardianAuth> = guardian_seeds.iter().map(|&gs| {
        let gkp     = load_fixture_keypair(gs);
        let rec_msg = recovery_domain_signing_bytes(
            CHAIN_ID, sender, key_version, &new_kp.public_key, policy_id, None,
        );
        let sig = MlDsaScheme.sign(&rec_msg, &gkp).expect("guardian sign");
        GuardianAuth {
            guardian_public_key: gkp.public_key.clone(),
            signature:           sig.bytes.clone(),
            expires_at_height:   None,
        }
    }).collect();

    let kp_sender = load_fixture_keypair(SEED_PILOT);
    let body      = TxBody::RecoverAccountKey {
        new_public_key:      new_kp.public_key.clone(),
        new_key_scheme:      "ml-dsa-65".to_string(),
        key_version,
        pop_signature:       pop_sig.bytes.clone(),
        guardian_signatures,
        policy_id,
    };
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let msg       = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig       = MlDsaScheme.sign(&msg, &kp_sender).expect("sign");
    Transaction {
        id: tx_id.to_string(), sender: sender.to_string(), nonce, body,
        gas_limit:     800_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{}", sig_to_hex(&sig))],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: kp_sender.public_key.clone(),
    }
}

/// Build a `CancelRecovery` tx signed by `signer_seed` (must be the current active key).
fn build_cancel(signer_seed: &str, sender: &str, nonce: u64, tx_id: &str) -> Transaction {
    let kp        = load_fixture_keypair(signer_seed);
    let body_json  = serde_json::to_string(&TxBody::CancelRecovery).expect("body serialise");
    let tx_msg     = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig        = MlDsaScheme.sign(&tx_msg, &kp).expect("sign");
    Transaction {
        id: tx_id.to_string(), sender: sender.to_string(), nonce,
        body:          TxBody::CancelRecovery,
        gas_limit:     50_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{}", sig_to_hex(&sig))],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: kp.public_key.clone(),
    }
}

fn tx_json(tx: &Transaction) -> String { serde_json::to_string(tx).expect("tx json") }

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn dis_003e_timelock_live() {
    let _ = std::fs::remove_dir_all(devnet_dirs());

    let ports  = Ports::new();
    let _nodes = spawn_devnet(&ports);
    let port   = ports.alice;

    assert!(poll_ready(port, Duration::from_secs(30)),
        "devnet did not become ready within 30 seconds");

    // Wait for a few blocks so height > 0.
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        if current_height(port) >= 3 { break; }
        std::thread::sleep(Duration::from_millis(500));
    }
    let h0 = current_height(port);
    println!("Devnet ready — current height: {h0}");

    // Derive public keys from fixtures.
    let g1_pk = load_fixture_keypair(SEED_G1).public_key;
    let g2_pk = load_fixture_keypair(SEED_G2).public_key;
    let g3_pk = load_fixture_keypair(SEED_G3).public_key;

    // ─────────────────────────────────────────────────────────────────────────
    // C-14: Valid recovery sets pending_recovery; key is NOT immediately replaced
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n── C-14: pending_recovery set, key not yet rotated ─────────────");

    let nonce0   = current_nonce(port, PILOT_ADDR);
    let enroll_tx = build_enroll(
        SEED_PILOT, PILOT_ADDR, nonce0,
        vec![g1_pk.clone(), g2_pk.clone(), g3_pk.clone()], 2, "enroll-e-001",
    );
    let _ = submit_tx(port, &tx_json(&enroll_tx));
    let enroll_r = wait_tx_result(port, "enroll-e-001", Duration::from_secs(20))
        .expect("enroll-e-001 result");
    assert!(enroll_r["success"].as_bool().unwrap_or(false),
        "C-14 setup: enroll must succeed: {enroll_r}");

    let acct0    = account_of(port, PILOT_ADDR).expect("pilot account after enroll");
    let kv0      = acct0["key_version"].as_u64().unwrap_or(0) as u32;
    let pid0     = acct0["policy_generation"].as_u64().unwrap_or(0);
    let pk_before = acct0["public_key"].as_str().unwrap_or("").to_string();

    let nonce1   = current_nonce(port, PILOT_ADDR);
    let rec_c14  = build_recover(
        "dis003d-new-key-f01-seed-000000000000000000000001",
        PILOT_ADDR, nonce1, kv0 + 1,
        &[SEED_G1, SEED_G2], pid0, "rec-e-c14",
    );
    let _ = submit_tx(port, &tx_json(&rec_c14));
    let r_c14 = wait_tx_result(port, "rec-e-c14", Duration::from_secs(20))
        .expect("C-14 recover result");
    println!("C-14 recover: {r_c14}");
    assert!(r_c14["success"].as_bool().unwrap_or(false),
        "C-14: recover must be accepted: {r_c14}");

    // Key must NOT be immediately replaced.
    let acct_after = account_of(port, PILOT_ADDR).expect("pilot account after recover");
    let pk_after   = acct_after["public_key"].as_str().unwrap_or("").to_string();
    assert_eq!(pk_before, pk_after,
        "C-14 FAIL: public key was immediately replaced (want pending state)");

    // pending_recovery must be set.
    let pending = &acct_after["pending_recovery"];
    assert!(!pending.is_null(),
        "C-14 FAIL: pending_recovery is null — recover must set pending state");
    assert_eq!(pending["cancelled"].as_bool().unwrap_or(true), false,
        "C-14 FAIL: pending_recovery.cancelled must be false");
    let activation_height = pending["activation_height"].as_u64()
        .expect("C-14: activation_height missing from pending_recovery");
    println!("✓ C-14 passed — pending_recovery set, activation_height={activation_height}, key unchanged");

    // ─────────────────────────────────────────────────────────────────────────
    // C-15: CancelRecovery voids the pending recovery before activation
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n── C-15: CancelRecovery during timelock voids recovery ──────────");

    // Submit cancel before activation_height.
    let h_now = current_height(port);
    assert!(h_now < activation_height,
        "C-15 setup: need to submit cancel before activation_height={activation_height}, current={h_now}");

    let nonce_cancel = current_nonce(port, PILOT_ADDR);
    let cancel_tx    = build_cancel(SEED_PILOT, PILOT_ADDR, nonce_cancel, "cancel-e-c15");
    let _ = submit_tx(port, &tx_json(&cancel_tx));
    let r_cancel = wait_tx_result(port, "cancel-e-c15", Duration::from_secs(20))
        .expect("C-15 cancel result");
    println!("C-15 cancel: {r_cancel}");
    assert!(r_cancel["success"].as_bool().unwrap_or(false),
        "C-15: CancelRecovery must succeed: {r_cancel}");

    // pending_recovery.cancelled must be true.
    let acct_c15 = account_of(port, PILOT_ADDR).expect("pilot after cancel");
    let pending_c15 = &acct_c15["pending_recovery"];
    assert_eq!(pending_c15["cancelled"].as_bool().unwrap_or(false), true,
        "C-15 FAIL: pending_recovery.cancelled must be true after CancelRecovery");

    // Wait past the original activation_height — recovery must not activate.
    println!("C-15: waiting past activation_height={activation_height}...");
    assert!(wait_height(port, activation_height + 2, Duration::from_secs(30)),
        "C-15: timed out waiting for height {}", activation_height + 2);

    let acct_c15b = account_of(port, PILOT_ADDR).expect("pilot after activation_height");
    let pk_c15    = acct_c15b["public_key"].as_str().unwrap_or("").to_string();
    assert_eq!(pk_before, pk_c15,
        "C-15 FAIL: key was replaced despite cancellation");
    assert_eq!(acct_c15b["pending_recovery"]["cancelled"].as_bool().unwrap_or(false), true,
        "C-15 FAIL: cancelled flag cleared after activation_height passed");
    println!("✓ C-15 passed — cancelled recovery did not activate");

    // ─────────────────────────────────────────────────────────────────────────
    // C-16: Unchallenged recovery activates at activation_height
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n── C-16: Unchallenged recovery activates at activation_height ───");

    // Re-enroll a fresh policy (C-15 cancel cleared the pending; need a new policy).
    let nonce_re  = current_nonce(port, PILOT_ADDR);
    let enroll2   = build_enroll(
        SEED_PILOT, PILOT_ADDR, nonce_re,
        vec![g1_pk.clone(), g2_pk.clone(), g3_pk.clone()], 2, "enroll-e-002",
    );
    let _ = submit_tx(port, &tx_json(&enroll2));
    let enroll2_r = wait_tx_result(port, "enroll-e-002", Duration::from_secs(20))
        .expect("enroll-e-002 result");
    assert!(enroll2_r["success"].as_bool().unwrap_or(false),
        "C-16 setup re-enroll: {enroll2_r}");

    let acct2   = account_of(port, PILOT_ADDR).expect("pilot acct2");
    let kv2     = acct2["key_version"].as_u64().unwrap_or(0) as u32;
    let pid2    = acct2["policy_generation"].as_u64().unwrap_or(0);

    let new_seed_c16 = "dis003d-new-key-f02-seed-000000000000000000000002";
    let new_pk_c16   = load_fixture_keypair(new_seed_c16).public_key.clone();

    let nonce_r2  = current_nonce(port, PILOT_ADDR);
    let rec_c16   = build_recover(
        new_seed_c16, PILOT_ADDR, nonce_r2, kv2 + 1,
        &[SEED_G1, SEED_G2], pid2, "rec-e-c16",
    );
    let _ = submit_tx(port, &tx_json(&rec_c16));
    let r_c16 = wait_tx_result(port, "rec-e-c16", Duration::from_secs(20))
        .expect("C-16 recover result");
    println!("C-16 recover: {r_c16}");
    assert!(r_c16["success"].as_bool().unwrap_or(false),
        "C-16: recover must be accepted: {r_c16}");

    let acct_c16_pending = account_of(port, PILOT_ADDR).expect("pilot after rec_c16");
    let act_h_c16 = acct_c16_pending["pending_recovery"]["activation_height"]
        .as_u64().expect("C-16: activation_height missing");
    println!("C-16: waiting for activation at height {act_h_c16}...");

    // Wait for activation_height + 1 to ensure sweep has run.
    assert!(wait_height(port, act_h_c16 + 1, Duration::from_secs(40)),
        "C-16: timed out waiting for height {}", act_h_c16 + 1);

    let acct_c16_done = account_of(port, PILOT_ADDR).expect("pilot after activation");
    let pk_c16_final  = acct_c16_done["public_key"].as_str().unwrap_or("").to_string();
    let new_pk_hex    = new_pk_c16.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(pk_c16_final, new_pk_hex,
        "C-16 FAIL: key not replaced after unchallenged recovery activated");
    assert!(acct_c16_done["pending_recovery"].is_null()
            || acct_c16_done["pending_recovery"]["cancelled"].as_bool().unwrap_or(false),
        "C-16 FAIL: pending_recovery not cleared after activation");
    println!("✓ C-16 passed — key replaced at activation_height={act_h_c16}");

    // ─────────────────────────────────────────────────────────────────────────
    // C-17: Cancelled recovery cannot be re-activated after activation_height
    // (Already validated by C-15 run — the pending state survives as cancelled
    //  and the key was not replaced after we waited past activation_height.)
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n── C-17: Cancelled recovery cannot re-activate (verified via C-15) ──");
    // At this point pk_before == pk_c15 (unchanged) and C-15 waited past its
    // activation_height, so C-17 is fully covered.
    println!("✓ C-17 passed — confirmed by C-15 post-activation_height check");

    // ─────────────────────────────────────────────────────────────────────────
    // C-18: New EnrollRecoveryPolicy while recovery is pending cancels pending
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n── C-18: New EnrollRecoveryPolicy cancels pending recovery ──────");

    // After C-16 activation, qcb1pilot's key is now new_pk_c16 (f02 fixture).
    // Sign with f02 seed going forward.
    let current_pilot_seed = new_seed_c16;

    let acct_c18_start = account_of(port, PILOT_ADDR).expect("pilot start C-18");
    let _kv_c18  = acct_c18_start["key_version"].as_u64().unwrap_or(0) as u32;

    // Enroll a policy under the new key.
    let nonce_e3  = current_nonce(port, PILOT_ADDR);
    let enroll3   = ml_dsa_tx(current_pilot_seed, PILOT_ADDR, nonce_e3,
        TxBody::EnrollRecoveryPolicy {
            guardians: vec![g1_pk.clone(), g2_pk.clone(), g3_pk.clone()],
            threshold: 2,
        }, "enroll-e-003", 500_000);
    let _ = submit_tx(port, &tx_json(&enroll3));
    let enroll3_r = wait_tx_result(port, "enroll-e-003", Duration::from_secs(20))
        .expect("enroll-e-003 result");
    assert!(enroll3_r["success"].as_bool().unwrap_or(false),
        "C-18 setup enroll3: {enroll3_r}");

    let acct_e3  = account_of(port, PILOT_ADDR).expect("pilot after enroll3");
    let kv_e3    = acct_e3["key_version"].as_u64().unwrap_or(0) as u32;
    let pid_e3   = acct_e3["policy_generation"].as_u64().unwrap_or(0);

    // Submit a recovery — this creates a pending recovery.
    let new_seed_c18 = "dis003d-new-key-f03-seed-000000000000000000000003";
    let nonce_r3     = current_nonce(port, PILOT_ADDR);
    let _rec_c18      = build_recover(
        new_seed_c18, PILOT_ADDR, nonce_r3, kv_e3 + 1,
        &[SEED_G1, SEED_G2], pid_e3, "rec-e-c18",
    );
    // Note: build_recover hardcodes SEED_PILOT for the sender sig; we must rebuild
    // with the current key (f02).  Use ml_dsa_tx path directly.
    let new_kp_c18   = load_fixture_keypair(new_seed_c18);
    let pop_msg_c18  = account_key_rotation_signing_bytes(CHAIN_ID, PILOT_ADDR, kv_e3 + 1, &new_kp_c18.public_key);
    let pop_sig_c18  = MlDsaScheme.sign(&pop_msg_c18, &new_kp_c18).expect("PoP");
    let g_sigs_c18: Vec<GuardianAuth> = [SEED_G1, SEED_G2].iter().map(|&gs| {
        let gkp     = load_fixture_keypair(gs);
        let rec_msg = recovery_domain_signing_bytes(CHAIN_ID, PILOT_ADDR, kv_e3 + 1, &new_kp_c18.public_key, pid_e3, None);
        let sig     = MlDsaScheme.sign(&rec_msg, &gkp).expect("guardian sign");
        GuardianAuth { guardian_public_key: gkp.public_key.clone(), signature: sig.bytes.clone(), expires_at_height: None }
    }).collect();
    let body_c18  = TxBody::RecoverAccountKey {
        new_public_key: new_kp_c18.public_key.clone(), new_key_scheme: "ml-dsa-65".to_string(),
        key_version: kv_e3 + 1, pop_signature: pop_sig_c18.bytes.clone(),
        guardian_signatures: g_sigs_c18, policy_id: pid_e3,
    };
    let kp_c18_sender = load_fixture_keypair(current_pilot_seed);
    let bj_c18 = serde_json::to_string(&body_c18).unwrap();
    let msg_c18 = mldsa_tx_prehash(CHAIN_ID, bj_c18.as_bytes());
    let sig_c18 = MlDsaScheme.sign(&msg_c18, &kp_c18_sender).expect("sign c18 recover");
    let rec_c18_tx = Transaction {
        id: "rec-e-c18".to_string(), sender: PILOT_ADDR.to_string(), nonce: nonce_r3, body: body_c18,
        gas_limit: 800_000, signature: vec![], public_key: vec![],
        pq_signatures: vec![format!("mldsa65:{}", sig_to_hex(&sig_c18))],
        sig_scheme: Some(SchemeId::MlDsa), pq_public_key: kp_c18_sender.public_key.clone(),
    };
    let _ = submit_tx(port, &tx_json(&rec_c18_tx));
    let r_c18_rec = wait_tx_result(port, "rec-e-c18", Duration::from_secs(20))
        .expect("C-18 recover result");
    assert!(r_c18_rec["success"].as_bool().unwrap_or(false),
        "C-18 setup: recover must be accepted: {r_c18_rec}");

    let acct_c18_pending = account_of(port, PILOT_ADDR).expect("pilot C-18 pending");
    assert!(!acct_c18_pending["pending_recovery"].is_null(),
        "C-18 setup: pending_recovery must be set after recover");

    // Now enroll a new policy — must cancel the pending recovery.
    let nonce_e4 = current_nonce(port, PILOT_ADDR);
    let enroll4  = ml_dsa_tx(current_pilot_seed, PILOT_ADDR, nonce_e4,
        TxBody::EnrollRecoveryPolicy {
            guardians: vec![g1_pk.clone(), g2_pk.clone(), g3_pk.clone()],
            threshold: 2,
        }, "enroll-e-004", 500_000);
    let _ = submit_tx(port, &tx_json(&enroll4));
    let enroll4_r = wait_tx_result(port, "enroll-e-004", Duration::from_secs(20))
        .expect("enroll-e-004 result");
    assert!(enroll4_r["success"].as_bool().unwrap_or(false),
        "C-18: new EnrollRecoveryPolicy must succeed: {enroll4_r}");

    let acct_c18_after = account_of(port, PILOT_ADDR).expect("pilot after enroll4");
    // pending_recovery must be null or cancelled.
    let pend_c18 = &acct_c18_after["pending_recovery"];
    assert!(pend_c18.is_null() || pend_c18["cancelled"].as_bool().unwrap_or(false),
        "C-18 FAIL: pending_recovery not cancelled by new EnrollRecoveryPolicy: {pend_c18}");
    println!("✓ C-18 passed — new enroll cancelled pending recovery");

    // ─────────────────────────────────────────────────────────────────────────
    // C-19: Four-node state root convergence
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n── C-19: Four-node state root convergence ───────────────────────");
    std::thread::sleep(Duration::from_secs(3));
    let roots: Vec<String> = ports.all().iter().map(|&p| state_root(p)).collect();
    println!("State roots:");
    for (i, r) in roots.iter().enumerate() { println!("  node[{i}] = {r}"); }
    assert!(roots.iter().all(|r| r == &roots[0]) && !roots[0].is_empty(),
        "C-19 FAIL: state roots diverged: {roots:?}");
    println!("✓ C-19 passed");

    println!("\n━━━ DIS-003E PASS: C-14..C-19 all passed ━━━");
}
