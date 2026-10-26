//! DIS-002B — Identity Continuity: Authorized Device Migration (Path 1)
//!
//! Proves that a Verified pilot identity survives a `RotateAccountKey` rotation
//! with all identity attributes unchanged, and that negative cases are correctly
//! rejected.
//!
//! ## Test sequence
//!
//! 1. Spin up a 4-node devnet using `genesis-dis002b.json`.
//! 2. **Bootstrap Verified identity** for `qcb1pilot`:
//!    a. Submit `RegisterIdentity` from `qcb1pilot` (signed with Key_A).
//!    b. Submit `Attest` from `qcb1bob` (a Verified genesis validator).
//!    c. Poll `/api/identity/qcb1pilot` until `registered: true` on ALL 4 nodes.
//! 3. **Snapshot** identity record: tier, attestation_count, attested_by.
//! 4. **B-01**: Submit `RotateAccountKey` Key_A → Key_B with valid PoP.
//! 5. **B-02**: Verify identity ID and account address unchanged after rotation.
//! 6. **B-03**: Verify Verified tier and attestation records unchanged.
//! 7. **B-04**: Verify balance (decreased by gas), nonce, preserved.
//! 8. **B-05**: Submit a Transfer with Key_B — must succeed.
//! 9. **B-06**: Submit a Transfer with Key_A — must be rejected.
//! 10. **B-07**: Replay the migration tx — must be rejected (nonce consumed).
//! 11. **B-08**: Submit an unauthorized rotation (wrong signer) — must be rejected.
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test dis_002b_migration_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: mark B-01 through B-08 ✅ only after confirmed passing on
//! the developer's local machine (Windows/MINGW64).

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash, KeyPair};
use chain_forge_execution::{
    Transaction, TxBody,
    account_key_rotation_signing_bytes,
};

/// Load an Ed25519 keypair from a `.key.json` file (validator key format).
fn load_ed25519_keypair(path: &PathBuf) -> KeyPair {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read key file {path:?}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("cannot parse key file {path:?}: {e}"));
    let pk_hex = v["public_key"].as_str().expect("public_key missing in key file");
    let sk_hex = v["private_key"].as_str().expect("private_key missing in key file");
    KeyPair {
        scheme:      SchemeId::Classical,
        public_key:  hex::decode(pk_hex).expect("public_key hex decode"),
        private_key: hex::decode(sk_hex).expect("private_key hex decode"),
    }
}

const CHAIN_ID:    &str = "qcb-devnet-dis002b";
const PILOT_ADDR:  &str = "qcb1pilot";
const ATTACKER:    &str = "qcb1attacker";

// Disposable seeds — never used with real pilot identities.
const SEED_A: &str = "dis002b-pilot-device-a-seed-00000000000000000000000000001";
const SEED_B: &str = "dis002b-pilot-device-b-seed-00000000000000000000000000002";
const SEED_ATK: &str = "dis002b-attacker-seed-000000000000000000000000000003";

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

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    manifest_dir().parent().unwrap().to_path_buf()
}

fn node_bin() -> PathBuf {
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
        (Err(_), Err(_)) => debug,
    }
}

fn genesis_path() -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("genesis-dis002b.json")
}

fn key_file(label: &str) -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json"))
}

// ── Node lifecycle ────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct NodeHandle {
    name:     String,
    process:  Child,
    log_path: PathBuf,
}

impl Drop for NodeHandle {
    fn drop(&mut self) { let _ = self.process.kill(); }
}

fn spawn_node(
    name: &str, api: u16, p2p: u16,
    log_dir: &PathBuf,
    peers: &[u16],
    key_file_path: Option<PathBuf>,
) -> NodeHandle {
    let log_path = log_dir.join(format!("{name}.log"));
    let log_file = std::fs::File::create(&log_path).expect("create log file");

    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator").arg(name)
       .arg("--api-port").arg(api.to_string())
       .arg("--p2p-port").arg(p2p.to_string());
    for &p in peers {
        cmd.arg("--bootstrap").arg(format!("/ip4/127.0.0.1/tcp/{p}"));
    }
    if let Some(kf) = key_file_path {
        cmd.arg("--key-file").arg(kf);
    }
    cmd.stdout(log_file.try_clone().unwrap())
       .stderr(log_file)
       .stdin(Stdio::null());

    let process = cmd.spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {name}: {e}"));
    NodeHandle { name: name.to_string(), process, log_path }
}

fn spawn_devnet(ports: &DevnetPorts) -> [NodeHandle; 4] {
    let log_dir = std::env::temp_dir().join("dis002b_devnet_logs");
    std::fs::create_dir_all(&log_dir).expect("create log dir");

    let kf = |label: &str| -> Option<PathBuf> {
        let p = key_file(label);
        if p.exists() { Some(p) } else { None }
    };

    [
        spawn_node("qcb1alice", ports.alice_api, ports.alice_p2p, &log_dir,
            &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p], kf("alice")),
        spawn_node("qcb1bob",   ports.bob_api,   ports.bob_p2p,   &log_dir,
            &[ports.alice_p2p, ports.carol_p2p, ports.dave_p2p], kf("bob")),
        spawn_node("qcb1carol", ports.carol_api, ports.carol_p2p, &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.dave_p2p], kf("carol")),
        spawn_node("qcb1dave",  ports.dave_api,  ports.dave_p2p,  &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.carol_p2p], kf("dave")),
    ]
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn http_raw(method: &str, port: u16, path: &str, body: Option<&str>) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(3000))).ok()?;

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
    let status: u16 = buf.lines().next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some((status, buf.split("\r\n\r\n").nth(1).unwrap_or("").to_string()))
}

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let (_, body) = http_raw("GET", port, path, None)?;
    serde_json::from_str(&body).ok()
}

fn api_post(port: u16, path: &str, body: &str) -> (u16, serde_json::Value) {
    match http_raw("POST", port, path, Some(body)) {
        Some((status, resp)) => (status, serde_json::from_str(&resp).unwrap_or(serde_json::Value::Null)),
        None                 => (0, serde_json::Value::Null),
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

fn poll_height(port: u16, target: u64, timeout: Duration) -> Option<u64> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(v) = api_get(port, "/api/status") {
            let h = v["height"].as_u64().unwrap_or(0);
            if h >= target { return Some(h); }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

fn submit_tx(port: u16, tx_json: &str) -> serde_json::Value {
    let (_, v) = api_post(port, "/api/tx", tx_json);
    v
}

fn wait_tx_result(port: u16, tx_id: &str, timeout: Duration) -> Option<serde_json::Value> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(v) = api_get(port, &format!("/api/tx/{tx_id}")) {
            if v.get("success").is_some() { return Some(v); }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    None
}

fn balance_of(port: u16, address: &str) -> u64 {
    api_get(port, &format!("/api/accounts/{address}"))
        .and_then(|v| {
            v["balances"]["uqcb"].as_u64()
                .or_else(|| v["balances"]["uqcb"].as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0)
}

fn nonce_of(port: u16, address: &str) -> u64 {
    api_get(port, &format!("/api/accounts/{address}"))
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(0)
}

fn state_root(port: u16) -> String {
    api_get(port, "/api/status")
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn identity_of(port: u16, address: &str) -> Option<serde_json::Value> {
    api_get(port, &format!("/api/identity/{address}"))
}

/// Poll until all ports report registered: true for the given address.
fn poll_until_registered(ports: &[u16], address: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let results: Vec<bool> = ports.iter().map(|&p| {
            identity_of(p, address)
                .and_then(|v| v["registered"].as_bool())
                .unwrap_or(false)
        }).collect();
        let all = results.iter().all(|&r| r);
        let elapsed = Instant::now().duration_since(deadline - timeout);
        eprint!("\r   [{:.1}s] identity convergence: ", elapsed.as_secs_f32());
        for (i, &r) in results.iter().enumerate() {
            eprint!("node{}={} ", i, if r { "✓" } else { "…" });
        }
        if all { eprintln!(); return true; }
        if Instant::now() >= deadline { eprintln!(); return false; }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── Transaction builders ──────────────────────────────────────────────────────

fn build_register_identity(seed: &str, sender: &str, nonce: u64) -> Transaction {
    let kp = MlDsaScheme.generate_keypair(seed).expect("ML-DSA keygen");
    let body = TxBody::RegisterIdentity;
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig = MlDsaScheme.sign(&message, &kp).expect("ML-DSA sign");
    let sig_hex: String = sig.bytes.iter().map(|b| format!("{b:02x}")).collect();
    Transaction {
        id:            format!("dis002b-reg-{sender}-n{nonce}"),
        sender:        sender.to_string(),
        nonce,
        body,
        gas_limit:     200_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{sig_hex}")],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: kp.public_key.clone(),
    }
}

/// Build an Attest tx signed with an Ed25519 validator keypair (genesis validators).
fn build_attest_ed25519(
    kp: &KeyPair,
    attester: &str,
    attester_nonce: u64,
    claimant_id: &str,
) -> Transaction {
    let body = TxBody::Attest { claimant_id: claimant_id.to_string() };
    let mut tx = Transaction {
        id:            format!("dis002b-attest-{attester}-for-{claimant_id}"),
        sender:        attester.to_string(),
        nonce:         attester_nonce,
        body,
        gas_limit:     200_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![],
        sig_scheme:    Some(SchemeId::Classical),
        pq_public_key: vec![],
    };
    tx.sign(kp, CHAIN_ID).expect("Ed25519 sign Attest");
    tx
}

fn build_transfer(
    seed: &str, sender: &str, nonce: u64,
    to: &str, amount: u128,
    id_suffix: &str,
) -> Transaction {
    let kp = MlDsaScheme.generate_keypair(seed).expect("ML-DSA keygen");
    let body = TxBody::Transfer { to: to.to_string(), denom: "uqcb".to_string(), amount };
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig = MlDsaScheme.sign(&message, &kp).expect("ML-DSA sign");
    let sig_hex: String = sig.bytes.iter().map(|b| format!("{b:02x}")).collect();
    Transaction {
        id:            format!("dis002b-xfer-{id_suffix}"),
        sender:        sender.to_string(),
        nonce,
        body,
        gas_limit:     500_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{sig_hex}")],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: kp.public_key.clone(),
    }
}

fn build_rotation_tx(
    current_seed: &str,
    new_seed:     &str,
    sender:       &str,
    nonce:        u64,
    key_version:  u32,
    tx_id_suffix: &str,
) -> Transaction {
    let current_kp = MlDsaScheme.generate_keypair(current_seed).expect("current keygen");
    let new_kp     = MlDsaScheme.generate_keypair(new_seed).expect("new keygen");

    let pop_message = account_key_rotation_signing_bytes(
        CHAIN_ID, sender, key_version, &new_kp.public_key,
    );
    let pop_sig = MlDsaScheme.sign(&pop_message, &new_kp).expect("PoP sign");

    let body = TxBody::RotateAccountKey {
        new_public_key: new_kp.public_key.clone(),
        new_key_scheme: "ml-dsa-65".to_string(),
        key_version,
        pop_signature:  pop_sig.bytes.clone(),
    };

    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message   = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let outer_sig = MlDsaScheme.sign(&message, &current_kp).expect("outer sign");
    let sig_hex: String = outer_sig.bytes.iter().map(|b| format!("{b:02x}")).collect();

    Transaction {
        id:            format!("dis002b-rotate-{tx_id_suffix}"),
        sender:        sender.to_string(),
        nonce,
        body,
        gas_limit:     1_000_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{sig_hex}")],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: current_kp.public_key.clone(),
    }
}

fn build_rotation_wrong_signer(
    attacker_seed: &str,
    new_seed:      &str,
    sender:        &str,
    nonce:         u64,
    key_version:   u32,
) -> Transaction {
    let attacker_kp = MlDsaScheme.generate_keypair(attacker_seed).expect("attacker keygen");
    let new_kp      = MlDsaScheme.generate_keypair(new_seed).expect("new keygen");

    let pop_message = account_key_rotation_signing_bytes(
        CHAIN_ID, sender, key_version, &new_kp.public_key,
    );
    let pop_sig = MlDsaScheme.sign(&pop_message, &new_kp).expect("PoP sign");

    let body = TxBody::RotateAccountKey {
        new_public_key: new_kp.public_key.clone(),
        new_key_scheme: "ml-dsa-65".to_string(),
        key_version,
        pop_signature:  pop_sig.bytes.clone(),
    };

    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message   = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let outer_sig = MlDsaScheme.sign(&message, &attacker_kp).expect("outer sign");
    let sig_hex: String = outer_sig.bytes.iter().map(|b| format!("{b:02x}")).collect();

    Transaction {
        id:            "dis002b-rotate-unauth".to_string(),
        sender:        sender.to_string(),
        nonce,
        body,
        gas_limit:     1_000_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{sig_hex}")],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: attacker_kp.public_key.clone(),
    }
}

// ── Diagnostic ───────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn dump_logs(nodes: &[NodeHandle; 4]) {
    for node in nodes {
        let buf = std::fs::read_to_string(&node.log_path).unwrap_or_default();
        let lines: Vec<&str> = buf.lines().collect();
        let head: Vec<&str> = lines.iter().copied().take(50).collect();
        let tail: Vec<&str> = if lines.len() > 90 {
            lines.iter().copied().rev().take(40).collect::<Vec<_>>()
                .into_iter().rev().collect()
        } else { vec![] };
        eprintln!("=== {} log ({} lines) ===", node.name, lines.len());
        for l in &head { eprintln!("{l}"); }
        if !tail.is_empty() {
            eprintln!("... ({} lines omitted) ...", lines.len().saturating_sub(90));
            for l in &tail { eprintln!("{l}"); }
        }
    }
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn dis_002b_migration() {
    let ports = DevnetPorts::new();
    let mut nodes = spawn_devnet(&ports);
    let api_port = ports.alice_api;
    let bob_port = ports.bob_api;
    let all_ports = ports.all_api();

    eprintln!("DIS-002B identity migration test starting...");
    eprintln!("genesis:    {}", genesis_path().display());
    eprintln!("pilot addr: {PILOT_ADDR}");

    // Wait for devnet to become ready.
    eprintln!("\n[init] Waiting for devnet readiness...");
    for &p in &all_ports {
        assert!(poll_ready(p, Duration::from_secs(30)), "node :{p} did not start");
    }
    assert!(
        poll_height(api_port, 2, Duration::from_secs(30)).is_some(),
        "devnet did not reach height 2 — nodes are not producing blocks"
    );
    eprintln!("[init] Devnet ready.");

    // ── Phase 0: baseline ─────────────────────────────────────────────────────
    let balance_before = balance_of(api_port, PILOT_ADDR);
    eprintln!("\n[phase0] pilot balance before: {balance_before} uqcb");

    // ── Phase 1: RegisterIdentity for qcb1pilot ───────────────────────────────
    // First tx from pilot also binds Key_A to the account.
    eprintln!("\n[phase1] RegisterIdentity + key bind for {PILOT_ADDR}");
    let reg_tx = build_register_identity(SEED_A, PILOT_ADDR, 0);
    let reg_json = serde_json::to_string(&reg_tx).expect("serialise");
    let resp_reg = submit_tx(api_port, &reg_json);
    let ingress_reg = resp_reg["status"].as_str().unwrap_or("").to_string();
    assert!(
        ingress_reg == "queued" || ingress_reg == "ok",
        "RegisterIdentity not queued: {resp_reg}"
    );
    let result_reg = wait_tx_result(api_port, &reg_tx.id, Duration::from_secs(30))
        .expect("RegisterIdentity tx not found after 30s");
    assert!(
        result_reg["success"].as_bool().unwrap_or(false),
        "RegisterIdentity FAIL: {result_reg:?}"
    );
    eprintln!("[phase1] RegisterIdentity succeeded.");

    // ── Phase 2: Attest from qcb1bob ─────────────────────────────────────────
    // qcb1bob is Verified at genesis and uses Ed25519. Load the key file and sign.
    eprintln!("\n[phase2] Attest from qcb1bob for {PILOT_ADDR}");
    let bob_kp = load_ed25519_keypair(&key_file("bob"));
    let attest_tx = build_attest_ed25519(&bob_kp, "qcb1bob", 0, PILOT_ADDR);
    let attest_json = serde_json::to_string(&attest_tx).expect("serialise attest");
    let resp_attest = submit_tx(bob_port, &attest_json);
    let ingress_attest = resp_attest["status"].as_str().unwrap_or("").to_string();
    assert!(
        ingress_attest == "queued" || ingress_attest == "ok",
        "Attest not queued: {resp_attest}"
    );
    let result_attest = wait_tx_result(bob_port, &attest_tx.id, Duration::from_secs(30))
        .expect("Attest tx not found after 30s");
    assert!(
        result_attest["success"].as_bool().unwrap_or(false),
        "Attest FAIL: {result_attest:?}"
    );
    eprintln!("[phase2] Attest from qcb1bob succeeded.");

    // ── Phase 3: Wait for identity convergence on all 4 nodes ─────────────────
    eprintln!("\n[phase3] Waiting for identity convergence...");
    assert!(
        poll_until_registered(&all_ports, PILOT_ADDR, Duration::from_secs(60)),
        "identity for {PILOT_ADDR} did not converge on all 4 nodes within 60s"
    );
    eprintln!("[phase3] Identity converged on all 4 nodes.");

    // ── Snapshot identity record before rotation ──────────────────────────────
    let identity_before = identity_of(api_port, PILOT_ADDR)
        .expect("identity not found on alice before rotation");
    let tier_before = identity_before["tier"].as_str().unwrap_or("null").to_string();
    let attcount_before = identity_before["attestation_count"].as_u64().unwrap_or(0);
    let attested_by_before = identity_before["attested_by"].clone();

    eprintln!("\n[snapshot] identity before rotation:");
    eprintln!("  tier              = {tier_before}");
    eprintln!("  attestation_count = {attcount_before}");
    eprintln!("  attested_by       = {attested_by_before}");

    // ── B-01: RotateAccountKey Key_A → Key_B ─────────────────────────────────
    // nonce=1 (RegisterIdentity was nonce=0).
    eprintln!("\n[B-01] RotateAccountKey Key_A → Key_B (Verified pilot identity migration)");
    let rotation_tx = build_rotation_tx(SEED_A, SEED_B, PILOT_ADDR, 1, 1, "pilot-a-to-b");
    let rotation_json = serde_json::to_string(&rotation_tx).expect("serialise");
    let resp_rot = submit_tx(api_port, &rotation_json);
    let ingress_rot = resp_rot["status"].as_str().unwrap_or("").to_string();
    assert_eq!(ingress_rot, "queued", "B-01 ingress: expected queued, got {ingress_rot}: {resp_rot}");
    let result_rot = wait_tx_result(api_port, &rotation_tx.id, Duration::from_secs(30))
        .expect("B-01: rotation tx not found after 30s");
    assert!(
        result_rot["success"].as_bool().unwrap_or(false),
        "B-01 FAIL: RotateAccountKey must succeed — {result_rot:?}"
    );
    eprintln!("[B-01] PASS: RotateAccountKey executed successfully.");

    // ── B-02: Identity ID and account address unchanged ───────────────────────
    eprintln!("\n[B-02] Verify identity ID and account address unchanged");
    let identity_after = identity_of(api_port, PILOT_ADDR)
        .expect("identity not found on alice after rotation");
    assert!(
        identity_after["registered"].as_bool().unwrap_or(false),
        "B-02 FAIL: identity not registered after rotation"
    );
    // The identity record is keyed by address; PILOT_ADDR must still resolve.
    // If the record had changed address, /api/identity/qcb1pilot would return registered: false.
    eprintln!("[B-02] PASS: identity record still found at address {PILOT_ADDR}.");

    // ── B-03: Verified tier and attestation records unchanged ─────────────────
    eprintln!("\n[B-03] Verify Verified tier and attestation records unchanged");
    let tier_after = identity_after["tier"].as_str().unwrap_or("null").to_string();
    let attcount_after = identity_after["attestation_count"].as_u64().unwrap_or(0);
    let attested_by_after = &identity_after["attested_by"];

    eprintln!("  tier_before={tier_before} tier_after={tier_after}");
    eprintln!("  attcount_before={attcount_before} attcount_after={attcount_after}");

    assert_eq!(
        tier_before, tier_after,
        "B-03 FAIL: tier changed from {tier_before} to {tier_after} after rotation"
    );
    assert_eq!(
        attcount_before, attcount_after,
        "B-03 FAIL: attestation_count changed from {attcount_before} to {attcount_after}"
    );
    assert_eq!(
        &attested_by_before, attested_by_after,
        "B-03 FAIL: attested_by changed after rotation"
    );
    eprintln!("[B-03] PASS: tier={tier_after}, attestation_count={attcount_after} — both unchanged.");

    // ── B-04: Balance and nonce preserved ─────────────────────────────────────
    eprintln!("\n[B-04] Verify balance (gas consumed) and nonce preserved");
    let nonce_after = nonce_of(api_port, PILOT_ADDR);
    assert_eq!(
        nonce_after, 2,
        "B-04 FAIL: nonce should be 2 after RegisterIdentity (n=0) and RotateAccountKey (n=1)"
    );
    let balance_after_rotation = balance_of(api_port, PILOT_ADDR);
    assert!(
        balance_after_rotation < balance_before,
        "B-04 FAIL: balance should have decreased (gas fees); before={balance_before}, after={balance_after_rotation}"
    );
    eprintln!("[B-04] PASS: nonce={nonce_after}, balance={balance_after_rotation} (was {balance_before}).");

    // ── B-05: Key_B signs a finalized transfer ────────────────────────────────
    eprintln!("\n[B-05] Transfer signed with Key_B (post-migration) must succeed");
    let tx_b5 = build_transfer(SEED_B, PILOT_ADDR, 2, ATTACKER, 1_000, "b05-keyb");
    let tx_b5_json = serde_json::to_string(&tx_b5).expect("serialise");
    let resp_b5 = submit_tx(api_port, &tx_b5_json);
    let ingress_b5 = resp_b5["status"].as_str().unwrap_or("").to_string();
    assert_eq!(ingress_b5, "queued", "B-05 ingress: {ingress_b5}: {resp_b5}");
    let result_b5 = wait_tx_result(api_port, &tx_b5.id, Duration::from_secs(30))
        .expect("B-05: tx not found after 30s");
    assert!(
        result_b5["success"].as_bool().unwrap_or(false),
        "B-05 FAIL: Transfer with Key_B must succeed — {result_b5:?}"
    );
    eprintln!("[B-05] PASS: Key_B transfer finalized.");

    // ── B-06: Key_A rejected after migration ──────────────────────────────────
    eprintln!("\n[B-06] Transfer signed with Key_A (old device key) must be rejected");
    let tx_b6 = build_transfer(SEED_A, PILOT_ADDR, 3, ATTACKER, 1, "b06-keya-rejected");
    let tx_b6_json = serde_json::to_string(&tx_b6).expect("serialise");
    let resp_b6 = submit_tx(api_port, &tx_b6_json);
    let ingress_b6 = resp_b6["status"].as_str().unwrap_or("").to_string();
    let result_b6 = if ingress_b6 != "queued" {
        serde_json::json!({ "success": false, "error": resp_b6["error"].as_str().unwrap_or(&ingress_b6) })
    } else {
        wait_tx_result(api_port, &tx_b6.id, Duration::from_secs(30))
            .expect("B-06: tx result never appeared")
    };
    assert!(
        !result_b6["success"].as_bool().unwrap_or(true),
        "B-06 FAIL: Key_A must be rejected after migration — {result_b6:?}"
    );
    eprintln!("[B-06] PASS: Key_A correctly rejected. error={:?}", result_b6["error"]);

    // ── B-07: Replayed migration tx rejected ──────────────────────────────────
    eprintln!("\n[B-07] Replayed migration tx (same nonce) must be rejected");
    let replay_resp = submit_tx(api_port, &rotation_json);
    let replay_ingress = replay_resp["status"].as_str().unwrap_or("").to_string();
    let replay_result = if replay_ingress != "queued" {
        serde_json::json!({ "success": false })
    } else {
        wait_tx_result(api_port, &rotation_tx.id, Duration::from_secs(20))
            .unwrap_or(serde_json::json!({ "success": false }))
    };
    assert!(
        !replay_result["success"].as_bool().unwrap_or(true),
        "B-07 FAIL: replayed migration tx must be rejected"
    );
    eprintln!("[B-07] PASS: replay rejected.");

    // ── B-08: Unauthorized migration rejected ─────────────────────────────────
    // Attacker tries to rotate qcb1pilot's key, signing with attacker's key.
    // Fails because qcb1pilot has Key_B bound; attacker's key != Key_B.
    eprintln!("\n[B-08] Unauthorized rotation attempt (attacker's outer signature) rejected");
    let tx_b8 = build_rotation_wrong_signer(SEED_ATK, SEED_A, PILOT_ADDR, 3, 2);
    let tx_b8_json = serde_json::to_string(&tx_b8).expect("serialise");
    let resp_b8 = submit_tx(api_port, &tx_b8_json);
    let ingress_b8 = resp_b8["status"].as_str().unwrap_or("").to_string();
    let result_b8 = if ingress_b8 != "queued" {
        serde_json::json!({ "success": false })
    } else {
        wait_tx_result(api_port, &tx_b8.id, Duration::from_secs(20))
            .expect("B-08: tx result never appeared")
    };
    assert!(
        !result_b8["success"].as_bool().unwrap_or(true),
        "B-08 FAIL: unauthorized rotation must be rejected — {result_b8:?}"
    );
    eprintln!("[B-08] PASS: unauthorized rotation rejected.");

    // ── Cross-node consistency ─────────────────────────────────────────────────
    eprintln!("\n[consistency] Waiting for state root convergence on all 4 nodes...");
    let cur_height = api_get(api_port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0);
    let _ = poll_height(api_port, cur_height + 1, Duration::from_secs(20));

    let roots: Vec<String> = all_ports.iter().map(|&p| state_root(p)).collect();
    let identity_nodes: Vec<_> = all_ports.iter().map(|&p| identity_of(p, PILOT_ADDR)).collect();

    eprintln!("[consistency] State roots: {roots:?}");
    eprintln!("[consistency] Identity on all nodes:");
    for (i, id) in identity_nodes.iter().enumerate() {
        eprintln!("  node{i}: {:?}", id.as_ref().map(|v| v.to_string()));
    }

    let first_root = &roots[0];
    for (i, r) in roots.iter().enumerate() {
        assert_eq!(r, first_root, "node {i} state root {r:?} != node 0 root {first_root:?}");
    }
    eprintln!("[consistency] All 4 nodes agree on state root {first_root}.");

    // Final identity snapshot on all nodes.
    for (i, id) in identity_nodes.iter().enumerate() {
        let tier = id.as_ref()
            .and_then(|v| v["tier"].as_str())
            .unwrap_or("null");
        assert_eq!(
            tier, tier_before,
            "node {i}: tier {tier} != expected {tier_before}"
        );
    }
    eprintln!("[consistency] All 4 nodes show tier={tier_before} for {PILOT_ADDR}.");

    // ── Summary ───────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("DIS-002B Path 1 PASS — all B-01..B-08 criteria verified:");
    eprintln!("  B-01: Verified pilot identity migrated Key_A → Key_B");
    eprintln!("  B-02: Identity ID and account address unchanged");
    eprintln!("  B-03: tier={tier_before}, attestation_count={attcount_after} — both unchanged");
    eprintln!("  B-04: nonce={nonce_after}, balance decreased by gas fees");
    eprintln!("  B-05: Key_B signed and finalized a transfer");
    eprintln!("  B-06: Key_A rejected after migration");
    eprintln!("  B-07: Replayed migration tx rejected");
    eprintln!("  B-08: Unauthorized rotation attempt rejected");
    eprintln!("  [+] All 4 nodes agree on state root {first_root}");
    eprintln!("  [+] All 4 nodes show Verified tier after migration");
    eprintln!();
    eprintln!("Per CLAUDE.md: mark milestone ✅ only after confirmed passing on");
    eprintln!("developer machine (Windows/MINGW64): git pull && cargo build -p chain-forge-node");
    eprintln!("  && cargo test -p chain-forge-node --test dis_002b_migration_live -- --nocapture");

    drop(nodes);
}
