//! DIS-002B — Identity Continuity: Lost-Device Recovery (Path 2)
//!
//! Proves that a Verified pilot identity can recover access via enrolled
//! threshold-guardian policy when the original signing key is lost.
//!
//! ## Acceptance criteria
//!
//! | ID   | Criterion |
//! |------|-----------|
//! | B-09 | Lost-device recovery succeeds with valid enrolled policy and threshold met |
//! | B-10 | Recovery with insufficient guardian sigs is rejected |
//! | B-11 | Recovery with forged guardian sigs is rejected |
//! | B-12 | Rotation and recovery survive node restart (state persists to disk) |
//! | B-13 | Four nodes agree on identity, key version, and state root after recovery |
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test dis_002b_recovery_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: mark B-09 through B-13 ✅ only after confirmed passing on
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
    Transaction, TxBody, GuardianAuth,
    account_key_rotation_signing_bytes,
    recovery_domain_signing_bytes,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const CHAIN_ID:    &str = "qcb-devnet-dis002b";
const PILOT_ADDR:  &str = "qcb1pilot";
const ATTACKER:    &str = "qcb1attacker";

// Pilot's initial key (will be "lost").
const SEED_A: &str = "dis002b-pilot-device-a-seed-00000000000000000000000000001";
// Pilot's recovery key (new device).
const SEED_REC: &str = "dis002b-pilot-recovery-seed-00000000000000000000000000099";
// Three independent guardians.
const SEED_G1: &str = "dis002b-guardian-1-seed-000000000000000000000000000010";
const SEED_G2: &str = "dis002b-guardian-2-seed-000000000000000000000000000020";
const SEED_G3: &str = "dis002b-guardian-3-seed-000000000000000000000000000030";
// Attacker seed (for forged sig test).
const SEED_ATK: &str = "dis002b-attacker-seed-000000000000000000000000000003";

// ── Port allocation ────────────────────────────────────────────────────────────

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

// ── File / path helpers ────────────────────────────────────────────────────────

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

fn load_ed25519_keypair(path: &PathBuf) -> KeyPair {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read key file {path:?}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("cannot parse key file {path:?}: {e}"));
    let pk_hex = v["public_key"].as_str().expect("public_key missing");
    let sk_hex = v["private_key"].as_str().expect("private_key missing");
    KeyPair {
        scheme:      SchemeId::Classical,
        public_key:  hex::decode(pk_hex).expect("pk hex decode"),
        private_key: hex::decode(sk_hex).expect("sk hex decode"),
    }
}

// ── Node lifecycle ─────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct NodeHandle {
    name:     String,
    process:  Child,
    log_path: PathBuf,
}

impl Drop for NodeHandle {
    fn drop(&mut self) { let _ = self.process.kill(); }
}

fn devnet_dirs() -> PathBuf {
    std::env::temp_dir().join("dis002b_recovery_devnet")
}

fn spawn_node(
    name: &str, api: u16, p2p: u16,
    log_dir: &PathBuf,
    peers: &[u16],
    key_file_path: Option<PathBuf>,
    data_dir: Option<PathBuf>,
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
    if let Some(dd) = data_dir {
        std::fs::create_dir_all(&dd).expect("create data dir");
        cmd.arg("--data-dir").arg(dd);
    }
    cmd.stdout(log_file.try_clone().unwrap())
       .stderr(log_file)
       .stdin(Stdio::null());

    let process = cmd.spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {name}: {e}"));
    NodeHandle { name: name.to_string(), process, log_path }
}

fn spawn_devnet(ports: &DevnetPorts) -> [NodeHandle; 4] {
    let base  = devnet_dirs();
    let log_dir = base.join("logs");
    std::fs::create_dir_all(&log_dir).expect("create log dir");

    let kf = |label: &str| -> Option<PathBuf> {
        let p = key_file(label);
        if p.exists() { Some(p) } else { None }
    };
    let dd = |name: &str| -> Option<PathBuf> { Some(base.join("data").join(name)) };

    [
        spawn_node("qcb1alice", ports.alice_api, ports.alice_p2p, &log_dir,
            &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p], kf("alice"), dd("qcb1alice")),
        spawn_node("qcb1bob",   ports.bob_api,   ports.bob_p2p,   &log_dir,
            &[ports.alice_p2p, ports.carol_p2p, ports.dave_p2p], kf("bob"), dd("qcb1bob")),
        spawn_node("qcb1carol", ports.carol_api, ports.carol_p2p, &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.dave_p2p], kf("carol"), dd("qcb1carol")),
        spawn_node("qcb1dave",  ports.dave_api,  ports.dave_p2p,  &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.carol_p2p], kf("dave"), dd("qcb1dave")),
    ]
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

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

fn state_root(port: u16) -> String {
    api_get(port, "/api/status")
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn identity_of(port: u16, address: &str) -> Option<serde_json::Value> {
    api_get(port, &format!("/api/identity/{address}"))
}

fn account_of(port: u16, address: &str) -> Option<serde_json::Value> {
    api_get(port, &format!("/api/accounts/{address}"))
}

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

// ── Helpers ────────────────────────────────────────────────────────────────────

fn sig_to_hex(sig: &chain_forge_crypto::Signature) -> String {
    sig.bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Transaction builders ───────────────────────────────────────────────────────

/// Build any ML-DSA-signed transaction.
fn ml_dsa_tx(
    seed: &str,
    sender: &str,
    nonce: u64,
    body: TxBody,
    tx_id: &str,
    gas_limit: u64,
) -> Transaction {
    let kp = MlDsaScheme.generate_keypair(seed).expect("ML-DSA keygen");
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let msg = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig = MlDsaScheme.sign(&msg, &kp).expect("ML-DSA sign");
    Transaction {
        id:            tx_id.to_string(),
        sender:        sender.to_string(),
        nonce,
        body,
        gas_limit,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{}", sig_to_hex(&sig))],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: kp.public_key.clone(),
    }
}

fn build_register_identity(seed: &str, sender: &str, nonce: u64, tx_id: &str) -> Transaction {
    ml_dsa_tx(seed, sender, nonce, TxBody::RegisterIdentity, tx_id, 200_000)
}

fn build_attest_ed25519(kp: &KeyPair, attester: &str, nonce: u64, claimant_id: &str) -> Transaction {
    let body = TxBody::Attest { claimant_id: claimant_id.to_string() };
    let mut tx = Transaction {
        id:            format!("rec-attest-{attester}-for-{claimant_id}"),
        sender:        attester.to_string(),
        nonce,
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

/// Build EnrollRecoveryPolicy signed by the account's current ML-DSA key.
fn build_enroll_policy(
    seed: &str,
    sender: &str,
    nonce: u64,
    guardians: Vec<Vec<u8>>,
    threshold: u32,
    tx_id: &str,
) -> Transaction {
    let body = TxBody::EnrollRecoveryPolicy { guardians, threshold };
    ml_dsa_tx(seed, sender, nonce, body, tx_id, 500_000)
}

/// Build RecoverAccountKey. The tx carries no outer signing key — authentication
/// is entirely via guardian signatures and PoP from the new key.
fn build_recover_account_key(
    new_seed: &str,
    sender: &str,
    nonce: u64,
    key_version: u32,
    guardian_seeds: &[&str],
    tx_id: &str,
    policy_id: u64,
) -> Transaction {
    let new_kp = MlDsaScheme.generate_keypair(new_seed).expect("new key keygen");

    let pop_msg = account_key_rotation_signing_bytes(
        CHAIN_ID, sender, key_version, &new_kp.public_key,
    );
    let pop_sig = MlDsaScheme.sign(&pop_msg, &new_kp).expect("PoP sign");

    let rec_msg = recovery_domain_signing_bytes(
        CHAIN_ID, sender, key_version, &new_kp.public_key,
    );

    let guardian_signatures: Vec<GuardianAuth> = guardian_seeds.iter().map(|&gs| {
        let gkp = MlDsaScheme.generate_keypair(gs).expect("guardian keygen");
        let sig = MlDsaScheme.sign(&rec_msg, &gkp).expect("guardian sign");
        GuardianAuth {
            guardian_public_key: gkp.public_key.clone(),
            signature:           sig.bytes.clone(),
        }
    }).collect();

    Transaction {
        id:            tx_id.to_string(),
        sender:        sender.to_string(),
        nonce,
        body: TxBody::RecoverAccountKey {
            new_public_key:      new_kp.public_key.clone(),
            new_key_scheme:      "ml-dsa-65".to_string(),
            key_version,
            pop_signature:       pop_sig.bytes.clone(),
            guardian_signatures,
            policy_id,
        },
        gas_limit:     2_000_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![],
        // Tag as MlDsa so the ingress Ed25519-sig check skips this tx.
        // RecoverAccountKey authentication is via guardian sigs in the body,
        // not via the outer tx signature; verify_authorization() returns Ok(())
        // for this variant unconditionally.
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: new_kp.public_key.clone(),
    }
}

/// Build a Transfer signed by a new ML-DSA key (post-recovery).
fn build_transfer_with_seed(
    seed: &str,
    sender: &str,
    nonce: u64,
    to: &str,
    amount: u128,
    tx_id: &str,
) -> Transaction {
    let body = TxBody::Transfer { to: to.to_string(), denom: "uqcb".to_string(), amount };
    ml_dsa_tx(seed, sender, nonce, body, tx_id, 500_000)
}

// ── Main test ──────────────────────────────────────────────────────────────────

#[test]
fn dis_002b_recovery() {
    // Clean data dirs so each run starts from genesis (prevents stale persist
    // from a previous run causing double-spend or nonce mismatches).
    let _ = std::fs::remove_dir_all(devnet_dirs());

    let ports = DevnetPorts::new();
    eprintln!("\n=== DIS-002B Path 2: Lost-Device Recovery ===");
    eprintln!("    alice_api={} bob_api={} carol_api={} dave_api={}",
        ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api);

    let nodes = spawn_devnet(&ports);
    let all_api = ports.all_api();

    for (i, &p) in all_api.iter().enumerate() {
        assert!(poll_ready(p, Duration::from_secs(20)),
            "node {i} not ready after 20s");
    }
    eprintln!("  [+] all 4 nodes ready");

    // ── Phase 1: Bootstrap a Verified identity for qcb1pilot ──────────────────

    eprintln!("\n--- Phase 1: Bootstrap Verified identity for {PILOT_ADDR} ---");

    let reg_tx = build_register_identity(SEED_A, PILOT_ADDR, 0, "rec-reg-identity-001");
    let reg_json = serde_json::to_string(&reg_tx).unwrap();
    let reg_res = submit_tx(ports.alice_api, &reg_json);
    eprintln!("  RegisterIdentity: {:?}", reg_res);

    let bob_kp = load_ed25519_keypair(&key_file("bob"));
    let attest_tx = build_attest_ed25519(&bob_kp, "qcb1bob", 0, PILOT_ADDR);
    let attest_json = serde_json::to_string(&attest_tx).unwrap();
    let attest_res = submit_tx(ports.bob_api, &attest_json);
    eprintln!("  Attest(bob→pilot): {:?}", attest_res);

    assert!(
        poll_until_registered(&all_api, PILOT_ADDR, Duration::from_secs(30)),
        "qcb1pilot not registered on all nodes after 30s"
    );

    // ── Phase 2: Enroll recovery policy (nonce=1 because RegisterIdentity=0) ──

    eprintln!("\n--- Phase 2: EnrollRecoveryPolicy ---");

    let g1_kp = MlDsaScheme.generate_keypair(SEED_G1).expect("g1 keygen");
    let g2_kp = MlDsaScheme.generate_keypair(SEED_G2).expect("g2 keygen");
    let g3_kp = MlDsaScheme.generate_keypair(SEED_G3).expect("g3 keygen");

    let guardians = vec![
        g1_kp.public_key.clone(),
        g2_kp.public_key.clone(),
        g3_kp.public_key.clone(),
    ];

    let enroll_tx = build_enroll_policy(
        SEED_A, PILOT_ADDR, 1, guardians.clone(), 2, "rec-enroll-001",
    );
    let enroll_json = serde_json::to_string(&enroll_tx).unwrap();
    let _ = submit_tx(ports.alice_api, &enroll_json);
    let enroll_result = wait_tx_result(ports.alice_api, "rec-enroll-001", Duration::from_secs(15))
        .expect("enroll tx not settled in 15s");
    eprintln!("  Enroll result: {:?}", enroll_result);
    assert!(
        enroll_result["success"].as_bool().unwrap_or(false),
        "EnrollRecoveryPolicy should succeed: {:?}", enroll_result
    );
    eprintln!("  [+] recovery policy enrolled (threshold=2/3)");

    // Snapshot tier right before recovery so B-13 can verify it is unchanged.
    let id_before = identity_of(ports.alice_api, PILOT_ADDR)
        .expect("identity_of qcb1pilot before recovery");
    let tier_before       = id_before["tier"].as_str().unwrap_or("").to_string();
    let attest_count_before = id_before["attestation_count"].as_u64().unwrap_or(0);
    eprintln!("  Pre-recovery snapshot: tier={tier_before} attest_count={attest_count_before}");

    // ── B-09: Recovery with valid policy and threshold met (2-of-3) ───────────

    eprintln!("\n--- B-09: RecoverAccountKey (valid, 2-of-3 guardians) ---");

    // nonce=2 (0=register, 1=enroll), key_version=1 (current=0, rotating to 1).
    // policy_id=1: this is the first enrollment on this account (policy_generation=1).
    let recover_tx = build_recover_account_key(
        SEED_REC, PILOT_ADDR, 2, 1,
        &[SEED_G1, SEED_G2],
        "rec-recover-001",
        1,
    );
    let recover_json = serde_json::to_string(&recover_tx).unwrap();
    let _ = submit_tx(ports.alice_api, &recover_json);
    let recover_result = wait_tx_result(ports.alice_api, "rec-recover-001", Duration::from_secs(15))
        .expect("recovery tx not settled in 15s");
    eprintln!("  Recovery result: {:?}", recover_result);
    assert!(
        recover_result["success"].as_bool().unwrap_or(false),
        "B-09: RecoverAccountKey should succeed: {:?}", recover_result
    );

    let acct_after = account_of(ports.alice_api, PILOT_ADDR).unwrap_or_default();
    let kv_after = acct_after["key_version"].as_u64().unwrap_or(0);
    assert_eq!(kv_after, 1, "B-09: key_version should be 1 after recovery");
    eprintln!("  [+] B-09 PASS: recovery succeeded, key_version={kv_after}");

    // Verify new key works.
    let transfer_tx = build_transfer_with_seed(
        SEED_REC, PILOT_ADDR, 3, ATTACKER, 1_000_000, "rec-transfer-post-001",
    );
    let transfer_json = serde_json::to_string(&transfer_tx).unwrap();
    let _ = submit_tx(ports.alice_api, &transfer_json);
    let tr_result = wait_tx_result(ports.alice_api, "rec-transfer-post-001", Duration::from_secs(10))
        .expect("post-recovery transfer not settled");
    assert!(
        tr_result["success"].as_bool().unwrap_or(false),
        "B-09: post-recovery Transfer should succeed: {:?}", tr_result
    );
    eprintln!("  [+] B-09 PASS: new key works for transfers");

    // ── B-10: Recovery rejected with insufficient guardian sigs (1-of-3) ──────

    eprintln!("\n--- B-10: RecoverAccountKey (insufficient sigs — only 1-of-3) ---");

    // Re-enroll a policy with the new key (SEED_REC, nonce=4).
    let re_enroll_tx = build_enroll_policy(
        SEED_REC, PILOT_ADDR, 4,
        vec![g1_kp.public_key.clone(), g2_kp.public_key.clone(), g3_kp.public_key.clone()],
        2, "rec-enroll-002",
    );
    let re_enroll_json = serde_json::to_string(&re_enroll_tx).unwrap();
    let _ = submit_tx(ports.alice_api, &re_enroll_json);
    let re_enroll_result = wait_tx_result(ports.alice_api, "rec-enroll-002", Duration::from_secs(15))
        .expect("re-enroll not settled");
    assert!(
        re_enroll_result["success"].as_bool().unwrap_or(false),
        "re-enroll for B-10 should succeed: {:?}", re_enroll_result
    );
    eprintln!("  Re-enrolled policy at key_version=1");

    // Try recovery with only 1 guardian (below threshold=2) — must fail.
    // policy_id=2: second enrollment (policy_generation increments on each EnrollRecoveryPolicy).
    let insufficient_tx = build_recover_account_key(
        "dis002b-new-key-b10-seed-000000000000000000000000000",
        PILOT_ADDR, 5, 2,
        &[SEED_G1],
        "rec-recover-b10-fail",
        2,
    );
    let insufficient_json = serde_json::to_string(&insufficient_tx).unwrap();
    let _ = submit_tx(ports.alice_api, &insufficient_json);
    let insufficient_result = wait_tx_result(ports.alice_api, "rec-recover-b10-fail", Duration::from_secs(10))
        .expect("B-10 tx not settled");
    assert!(
        !insufficient_result["success"].as_bool().unwrap_or(true),
        "B-10: recovery with 1-of-3 sigs should be rejected: {:?}", insufficient_result
    );
    eprintln!("  [+] B-10 PASS: insufficient sigs correctly rejected");

    // ── B-11: Recovery rejected with forged guardian sigs ─────────────────────

    eprintln!("\n--- B-11: RecoverAccountKey (forged guardian sigs) ---");

    // Attacker signs with their own key (not enrolled as a guardian).
    let atk_kp = MlDsaScheme.generate_keypair(SEED_ATK).expect("atk keygen");
    let new_kp_b11 = MlDsaScheme.generate_keypair("dis002b-new-key-b11-seed-0000000000000")
        .expect("b11 new key");
    let rec_msg_b11 = recovery_domain_signing_bytes(CHAIN_ID, PILOT_ADDR, 2, &new_kp_b11.public_key);
    let atk_sig1 = MlDsaScheme.sign(&rec_msg_b11, &atk_kp).expect("atk sign");
    let atk_sig2 = MlDsaScheme.sign(&rec_msg_b11, &atk_kp).expect("atk sign 2");
    let pop_msg_b11 = account_key_rotation_signing_bytes(
        CHAIN_ID, PILOT_ADDR, 2, &new_kp_b11.public_key,
    );
    let pop_b11 = MlDsaScheme.sign(&pop_msg_b11, &new_kp_b11).expect("PoP b11");

    // Both guardian entries use the attacker's pk — which is not in the enrolled policy.
    let forged_guardian_sigs = vec![
        GuardianAuth { guardian_public_key: atk_kp.public_key.clone(), signature: atk_sig1.bytes.clone() },
        GuardianAuth { guardian_public_key: atk_kp.public_key.clone(), signature: atk_sig2.bytes.clone() },
    ];
    let forged_tx = Transaction {
        id:            "rec-recover-b11-forged".to_string(),
        sender:        PILOT_ADDR.to_string(),
        nonce:         5,
        body: TxBody::RecoverAccountKey {
            new_public_key:      new_kp_b11.public_key.clone(),
            new_key_scheme:      "ml-dsa-65".to_string(),
            key_version:         2,
            pop_signature:       pop_b11.bytes.clone(),
            guardian_signatures: forged_guardian_sigs,
            policy_id:           2,
        },
        gas_limit:     2_000_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: new_kp_b11.public_key.clone(),
    };
    let forged_json = serde_json::to_string(&forged_tx).unwrap();
    let _ = submit_tx(ports.alice_api, &forged_json);
    let forged_result = wait_tx_result(ports.alice_api, "rec-recover-b11-forged", Duration::from_secs(10))
        .expect("B-11 tx not settled");
    assert!(
        !forged_result["success"].as_bool().unwrap_or(true),
        "B-11: forged guardian sigs should be rejected: {:?}", forged_result
    );
    eprintln!("  [+] B-11 PASS: forged guardian sigs correctly rejected");

    // ── B-12: Restart all nodes and verify state persists ─────────────────────

    eprintln!("\n--- B-12: Node restart (state persistence) ---");

    drop(nodes);
    std::thread::sleep(Duration::from_millis(500));

    let base = devnet_dirs();
    let log_dir = base.join("logs");
    let kf = |label: &str| -> Option<PathBuf> {
        let p = key_file(label);
        if p.exists() { Some(p) } else { None }
    };
    let dd = |name: &str| -> Option<PathBuf> { Some(base.join("data").join(name)) };
    let nodes_restarted = [
        spawn_node("qcb1alice", ports.alice_api, ports.alice_p2p, &log_dir,
            &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p], kf("alice"), dd("qcb1alice")),
        spawn_node("qcb1bob",   ports.bob_api,   ports.bob_p2p,   &log_dir,
            &[ports.alice_p2p, ports.carol_p2p, ports.dave_p2p], kf("bob"), dd("qcb1bob")),
        spawn_node("qcb1carol", ports.carol_api, ports.carol_p2p, &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.dave_p2p], kf("carol"), dd("qcb1carol")),
        spawn_node("qcb1dave",  ports.dave_api,  ports.dave_p2p,  &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.carol_p2p], kf("dave"), dd("qcb1dave")),
    ];

    for (i, &p) in all_api.iter().enumerate() {
        assert!(poll_ready(p, Duration::from_secs(30)),
            "node {i} not ready after restart");
    }
    eprintln!("  [+] all nodes back online");
    std::thread::sleep(Duration::from_secs(3));

    let acct_after_restart = account_of(ports.alice_api, PILOT_ADDR).unwrap_or_default();
    let kv_after_restart = acct_after_restart["key_version"].as_u64().unwrap_or(0);
    assert_eq!(kv_after_restart, 1,
        "B-12: key_version should still be 1 after restart, got {kv_after_restart}");

    // Confirm new key still works after restart (nonce=5 was used by b10 attempt; use 6).
    let nonce_after_restart = account_of(ports.alice_api, PILOT_ADDR)
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(6);
    let transfer_restart = build_transfer_with_seed(
        SEED_REC, PILOT_ADDR, nonce_after_restart, ATTACKER, 500_000, "rec-transfer-restart",
    );
    let tr_restart_json = serde_json::to_string(&transfer_restart).unwrap();
    let _ = submit_tx(ports.alice_api, &tr_restart_json);
    let tr_restart_result = wait_tx_result(ports.alice_api, "rec-transfer-restart", Duration::from_secs(15))
        .expect("post-restart transfer not settled");
    assert!(
        tr_restart_result["success"].as_bool().unwrap_or(false),
        "B-12: post-restart transfer should succeed: {:?}", tr_restart_result
    );
    eprintln!("  [+] B-12 PASS: state persisted, new key still works (key_version={kv_after_restart})");

    // ── B-13: All four nodes agree on identity, key version, and state root ───

    eprintln!("\n--- B-13: Cross-node convergence ---");

    std::thread::sleep(Duration::from_secs(2));

    let roots: Vec<String> = all_api.iter().map(|&p| state_root(p)).collect();
    eprintln!("  state roots:");
    for (i, r) in roots.iter().enumerate() { eprintln!("    node{i}: {r}"); }

    let root_ref = &roots[0];
    for (i, r) in roots.iter().enumerate() {
        assert_eq!(r, root_ref, "B-13: node{i} state root differs from node0");
    }

    let kv_values: Vec<u64> = all_api.iter().map(|&p| {
        account_of(p, PILOT_ADDR)
            .and_then(|v| v["key_version"].as_u64())
            .unwrap_or(0)
    }).collect();
    eprintln!("  key_versions: {:?}", kv_values);
    for (i, &kv) in kv_values.iter().enumerate() {
        assert_eq!(kv, 1, "B-13: node{i} key_version={kv}, expected 1");
    }

    // Qattice's stable identity anchor is the account address (derived from
    // the initial public key; invariant across key rotation and recovery).
    // The /api/identity/ response does not expose a separate identity_id field,
    // so we assert that all four nodes return the expected stable address.
    let addr_values: Vec<String> = all_api.iter().map(|&p| {
        identity_of(p, PILOT_ADDR)
            .and_then(|v| v["address"].as_str().map(str::to_string))
            .expect("B-13: identity address missing from /api/identity/ response")
    }).collect();
    eprintln!("  addresses: {:?}", addr_values);
    for (i, addr) in addr_values.iter().enumerate() {
        assert_eq!(addr, PILOT_ADDR,
            "B-13: node{i} identity address mismatch after recovery");
    }

    let tier_values: Vec<String> = all_api.iter().map(|&p| {
        identity_of(p, PILOT_ADDR)
            .and_then(|v| v["tier"].as_str().map(str::to_string))
            .unwrap_or_default()
    }).collect();
    eprintln!("  tiers: {:?}", tier_values);
    for (i, t) in tier_values.iter().enumerate() {
        assert_eq!(t, &tier_before,
            "B-13: node{i} tier changed after recovery (expected {tier_before}, got {t})");
    }

    eprintln!("  [+] B-13 PASS: all 4 nodes agree on identity, key_version=1, tier={tier_before}");
    eprintln!("\n=== DIS-002B Path 2: ALL CHECKS PASSED ===");
    eprintln!("  state_root: {}", roots[0]);
    eprintln!(
        "  identity preserved: tier={} attest_count={}",
        tier_before, attest_count_before
    );

    drop(nodes_restarted);
}
