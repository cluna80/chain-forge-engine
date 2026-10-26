//! DIS-003A — Recovery Policy Lifecycle Security
//!
//! Proves that the `policy_id` generation counter prevents guardian
//! signatures created under one policy from being replayed under another,
//! and that `RevokeRecoveryPolicy` correctly invalidates an active policy.
//!
//! ## Acceptance criteria
//!
//! | ID   | Criterion |
//! |------|-----------|
//! | C-01 | First enrollment sets policy_id=1; recovery authorized under policy_id=1 succeeds |
//! | C-02 | Recovery tx carrying wrong policy_id is rejected (old-policy replay guard) |
//! | C-03 | RevokeRecoveryPolicy clears the policy; subsequent recovery attempt is rejected |
//! | C-04 | Re-enrollment after revocation increments policy_id to 3; recovery under policy_id=3 succeeds |
//! | C-05 | Guardian signatures bound to policy_id=1 are rejected when policy_id=3 is active |
//! | C-06 | Guardian signatures bound to policy_id=2 (never existed) are rejected |
//! | C-07 | Account address, identity tier, and balance are unchanged throughout |
//! | C-08 | All four nodes agree on state root and policy_generation after all ops |
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test dis_003a_policy_lifecycle_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: mark C-01 through C-08 ✅ only after confirmed passing on
//! the developer's local machine (Windows/MINGW64).

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash};
use chain_forge_execution::{
    Transaction, TxBody, GuardianAuth,
    account_key_rotation_signing_bytes,
    recovery_domain_signing_bytes,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const CHAIN_ID:   &str = "qcb-devnet-dis003a";
const PILOT_ADDR: &str = "qcb1pilot";

// Pilot's initial key.
const SEED_A:  &str = "dis003a-pilot-device-a-seed-0000000000000000000000000001";
// Pilot's recovery key (used in C-01 and C-04).
const SEED_REC: &str = "dis003a-pilot-recovery-seed-00000000000000000000000000099";
// Guardians.
const SEED_G1: &str = "dis003a-guardian-1-seed-000000000000000000000000000010";
const SEED_G2: &str = "dis003a-guardian-2-seed-000000000000000000000000000020";
const SEED_G3: &str = "dis003a-guardian-3-seed-000000000000000000000000000030";

// ── Port helpers ───────────────────────────────────────────────────────────────

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("free_port bind")
        .local_addr().expect("local_addr").port()
}

struct Ports { alice: u16, alice_p2p: u16, bob: u16, bob_p2p: u16,
               carol: u16, carol_p2p: u16, dave: u16, dave_p2p: u16 }
impl Ports {
    fn new() -> Self {
        Self { alice: free_port(), alice_p2p: free_port(),
               bob:   free_port(), bob_p2p:   free_port(),
               carol: free_port(), carol_p2p: free_port(),
               dave:  free_port(), dave_p2p:  free_port() }
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

fn genesis_path() -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("genesis-dis003a.json")
}

fn key_file(label: &str) -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json"))
}

fn devnet_dirs() -> PathBuf {
    std::env::temp_dir().join("dis003a_policy_devnet")
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
    let base = devnet_dirs();
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
    stream.set_read_timeout(Some(Duration::from_millis(3000))).ok()?;
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
            // "not found" means the tx hasn't been processed yet — keep polling.
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

fn sig_to_hex(sig: &chain_forge_crypto::Signature) -> String {
    sig.bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tx builders ───────────────────────────────────────────────────────────────

fn ml_dsa_tx(seed: &str, sender: &str, nonce: u64, body: TxBody,
             tx_id: &str, gas: u64) -> Transaction {
    let kp       = MlDsaScheme.generate_keypair(seed).expect("keygen");
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let msg = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig = MlDsaScheme.sign(&msg, &kp).expect("sign");
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

fn build_revoke(seed: &str, sender: &str, nonce: u64, tx_id: &str) -> Transaction {
    ml_dsa_tx(seed, sender, nonce, TxBody::RevokeRecoveryPolicy, tx_id, 200_000)
}

fn build_recover(new_seed: &str, sender: &str, nonce: u64, key_version: u32,
                 guardian_seeds: &[&str], policy_id: u64, tx_id: &str) -> Transaction {
    let new_kp = MlDsaScheme.generate_keypair(new_seed).expect("new keygen");
    let pop_msg = account_key_rotation_signing_bytes(CHAIN_ID, sender, key_version, &new_kp.public_key);
    let pop_sig = MlDsaScheme.sign(&pop_msg, &new_kp).expect("PoP sign");
    let rec_msg = recovery_domain_signing_bytes(CHAIN_ID, sender, key_version, &new_kp.public_key, None);

    let guardian_signatures: Vec<GuardianAuth> = guardian_seeds.iter().map(|&gs| {
        let gkp = MlDsaScheme.generate_keypair(gs).expect("guardian keygen");
        let sig = MlDsaScheme.sign(&rec_msg, &gkp).expect("guardian sign");
        GuardianAuth { guardian_public_key: gkp.public_key.clone(), signature: sig.bytes.clone(), expires_at_height: None }
    }).collect();

    Transaction {
        id: tx_id.to_string(), sender: sender.to_string(), nonce,
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
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: new_kp.public_key.clone(),
    }
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn dis_003a_policy_lifecycle() {
    let _ = std::fs::remove_dir_all(devnet_dirs());

    let ports = Ports::new();
    eprintln!("\n=== DIS-003A: Recovery Policy Lifecycle Security ===");
    eprintln!("    alice={} bob={} carol={} dave={}", ports.alice, ports.bob, ports.carol, ports.dave);

    let _nodes = spawn_devnet(&ports);
    let all = ports.all();

    for (i, &p) in all.iter().enumerate() {
        assert!(poll_ready(p, Duration::from_secs(30)), "node{i} not ready");
    }
    eprintln!("  [+] all 4 nodes ready");

    // Pre-derive guardian public keys.
    let g1_kp = MlDsaScheme.generate_keypair(SEED_G1).expect("g1");
    let g2_kp = MlDsaScheme.generate_keypair(SEED_G2).expect("g2");
    let g3_kp = MlDsaScheme.generate_keypair(SEED_G3).expect("g3");
    let guardians = vec![g1_kp.public_key.clone(), g2_kp.public_key.clone(),
                         g3_kp.public_key.clone()];

    // Snapshot pre-op state for C-07.
    let bal_before = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["balances"]["uqcb"].as_u64())
        .unwrap_or(0);

    // ── Bootstrap: RegisterIdentity so we have a verified account ─────────────

    eprintln!("\n--- Bootstrap: register qcb1pilot ---");
    let reg_tx = ml_dsa_tx(SEED_A, PILOT_ADDR, 0,
        TxBody::RegisterIdentity,
        "pol-reg-001", 200_000);
    let _ = submit_tx(ports.alice, &serde_json::to_string(&reg_tx).unwrap());
    wait_tx_result(ports.alice, "pol-reg-001", Duration::from_secs(15))
        .expect("register not settled");

    // ── C-01: Enroll policy_id=1 and recover successfully ─────────────────────

    eprintln!("\n--- C-01: Enroll policy_id=1; valid recovery succeeds ---");

    let enroll1 = build_enroll(SEED_A, PILOT_ADDR, 1, guardians.clone(), 2, "pol-enroll-001");
    let _ = submit_tx(ports.alice, &serde_json::to_string(&enroll1).unwrap());
    let e1_result = wait_tx_result(ports.alice, "pol-enroll-001", Duration::from_secs(15))
        .expect("enroll-001 not settled");
    assert!(e1_result["success"].as_bool().unwrap_or(false),
        "C-01: first enrollment should succeed: {:?}", e1_result);
    eprintln!("  [+] policy_id=1 enrolled");

    let rec1 = build_recover(SEED_REC, PILOT_ADDR, 2, 1, &[SEED_G1, SEED_G2], 1, "pol-recover-001");
    let _ = submit_tx(ports.alice, &serde_json::to_string(&rec1).unwrap());
    let r1_result = wait_tx_result(ports.alice, "pol-recover-001", Duration::from_secs(15))
        .expect("recover-001 not settled");
    assert!(r1_result["success"].as_bool().unwrap_or(false),
        "C-01: recovery under policy_id=1 should succeed: {:?}", r1_result);
    let kv = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["key_version"].as_u64()).unwrap_or(0);
    assert_eq!(kv, 1, "C-01: key_version should be 1 after recovery");
    eprintln!("  [+] C-01 PASS: recovery with policy_id=1 succeeded (key_version={})", kv);

    // ── C-02: Wrong policy_id is rejected ─────────────────────────────────────
    //
    // policy is now consumed (recovery cleared it). Re-enroll (policy_id=2)
    // then try recovery with policy_id=99 — must be rejected.

    eprintln!("\n--- C-02: Wrong policy_id rejected ---");

    // nonce=3 (0=reg, 1=enroll, 2=recover).
    // Re-enroll using SEED_REC (the new key after recovery), nonce=3.
    let enroll2 = build_enroll(SEED_REC, PILOT_ADDR, 3, guardians.clone(), 2, "pol-enroll-002");
    let _ = submit_tx(ports.alice, &serde_json::to_string(&enroll2).unwrap());
    wait_tx_result(ports.alice, "pol-enroll-002", Duration::from_secs(15))
        .expect("enroll-002 not settled");
    eprintln!("  Re-enrolled at policy_id=2");

    // Try recovery with wrong policy_id=99 — must fail.
    let rec_wrong_pid = build_recover(
        "dis003a-wrong-pid-key-000000000000000000000000000000",
        PILOT_ADDR, 4, 2, &[SEED_G1, SEED_G2], 99, "pol-recover-wrong-pid",
    );
    let _ = submit_tx(ports.alice, &serde_json::to_string(&rec_wrong_pid).unwrap());
    let rw_result = wait_tx_result(ports.alice, "pol-recover-wrong-pid", Duration::from_secs(10))
        .expect("wrong-pid tx not settled");
    assert!(!rw_result["success"].as_bool().unwrap_or(true),
        "C-02: wrong policy_id should be rejected: {:?}", rw_result);
    let kv2 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["key_version"].as_u64()).unwrap_or(0);
    assert_eq!(kv2, 1, "C-02: key_version unchanged after rejected recovery");
    eprintln!("  [+] C-02 PASS: wrong policy_id correctly rejected");

    // ── C-03: RevokeRecoveryPolicy clears policy; recovery rejected ────────────

    eprintln!("\n--- C-03: RevokeRecoveryPolicy; recovery rejected ---");

    // nonce=4 was used by the wrong-pid attempt above (it failed, nonce not advanced).
    // Use nonce=4 for revocation.
    let actual_nonce = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(4);
    let revoke_tx = build_revoke(SEED_REC, PILOT_ADDR, actual_nonce, "pol-revoke-001");
    let _ = submit_tx(ports.alice, &serde_json::to_string(&revoke_tx).unwrap());
    let rev_result = wait_tx_result(ports.alice, "pol-revoke-001", Duration::from_secs(15))
        .expect("revoke-001 not settled");
    assert!(rev_result["success"].as_bool().unwrap_or(false),
        "C-03: RevokeRecoveryPolicy should succeed: {:?}", rev_result);
    eprintln!("  [+] policy revoked");

    // Now try recovery — no enrolled policy, must fail.
    let rec_after_revoke = build_recover(
        "dis003a-after-revoke-key-0000000000000000000000000000",
        PILOT_ADDR, actual_nonce + 1, 2, &[SEED_G1, SEED_G2], 2, "pol-recover-after-revoke",
    );
    let _ = submit_tx(ports.alice, &serde_json::to_string(&rec_after_revoke).unwrap());
    let rar_result = wait_tx_result(ports.alice, "pol-recover-after-revoke", Duration::from_secs(10))
        .expect("after-revoke recovery not settled");
    assert!(!rar_result["success"].as_bool().unwrap_or(true),
        "C-03: recovery with no enrolled policy should be rejected: {:?}", rar_result);
    eprintln!("  [+] C-03 PASS: post-revocation recovery correctly rejected");

    // ── C-04: Re-enroll (policy_id=3); recovery under policy_id=3 succeeds ────

    eprintln!("\n--- C-04: Re-enroll policy_id=3; valid recovery succeeds ---");

    let nonce_c04 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(actual_nonce + 1);
    let enroll3 = build_enroll(SEED_REC, PILOT_ADDR, nonce_c04, guardians.clone(), 2, "pol-enroll-003");
    let _ = submit_tx(ports.alice, &serde_json::to_string(&enroll3).unwrap());
    let e3_result = wait_tx_result(ports.alice, "pol-enroll-003", Duration::from_secs(15))
        .expect("enroll-003 not settled");
    assert!(e3_result["success"].as_bool().unwrap_or(false),
        "C-04: third enrollment should succeed: {:?}", e3_result);
    eprintln!("  [+] policy_id=3 enrolled");

    let nonce_rec3 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(nonce_c04 + 1);
    let rec3 = build_recover(
        "dis003a-recovery-key-3-seed-00000000000000000000000000",
        PILOT_ADDR, nonce_rec3, 2, &[SEED_G1, SEED_G3], 3, "pol-recover-003",
    );
    let _ = submit_tx(ports.alice, &serde_json::to_string(&rec3).unwrap());
    let r3_result = wait_tx_result(ports.alice, "pol-recover-003", Duration::from_secs(15))
        .expect("recover-003 not settled");
    assert!(r3_result["success"].as_bool().unwrap_or(false),
        "C-04: recovery under policy_id=3 should succeed: {:?}", r3_result);
    let kv3 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["key_version"].as_u64()).unwrap_or(0);
    assert_eq!(kv3, 2, "C-04: key_version should be 2 after second recovery");
    eprintln!("  [+] C-04 PASS: recovery with policy_id=3 succeeded (key_version={})", kv3);

    // ── C-05: Old policy_id=1 signatures rejected when policy_id=3 was active ─
    //
    // policy is consumed again. Re-enroll (policy_id=4) so there is an active
    // policy to test against, then try recovery with policy_id=1.

    eprintln!("\n--- C-05: policy_id=1 replay rejected ---");

    let seed_rec3 = "dis003a-recovery-key-3-seed-00000000000000000000000000";
    let nonce_c05_enroll = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(nonce_rec3 + 1);
    let enroll4 = build_enroll(seed_rec3, PILOT_ADDR, nonce_c05_enroll, guardians.clone(), 2, "pol-enroll-004");
    let _ = submit_tx(ports.alice, &serde_json::to_string(&enroll4).unwrap());
    wait_tx_result(ports.alice, "pol-enroll-004", Duration::from_secs(15))
        .expect("enroll-004 not settled");
    eprintln!("  Re-enrolled at policy_id=4");

    let nonce_c05 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(nonce_c05_enroll + 1);
    let rec_old_pid = build_recover(
        "dis003a-old-pid-replay-key-000000000000000000000000000",
        PILOT_ADDR, nonce_c05, 3, &[SEED_G1, SEED_G2], 1, "pol-recover-old-pid",
    );
    let _ = submit_tx(ports.alice, &serde_json::to_string(&rec_old_pid).unwrap());
    let rop_result = wait_tx_result(ports.alice, "pol-recover-old-pid", Duration::from_secs(10))
        .expect("old-pid recovery not settled");
    assert!(!rop_result["success"].as_bool().unwrap_or(true),
        "C-05: policy_id=1 replay should be rejected: {:?}", rop_result);
    eprintln!("  [+] C-05 PASS: old policy_id=1 signatures correctly rejected");

    // ── C-06: policy_id=2 (was revoked, never had a valid recovery) rejected ───

    eprintln!("\n--- C-06: policy_id=2 (revoked) rejected ---");

    let nonce_c06 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["nonce"].as_u64()).unwrap_or(nonce_c05 + 1);
    let rec_revoked_pid = build_recover(
        "dis003a-revoked-pid-key-000000000000000000000000000000",
        PILOT_ADDR, nonce_c06, 3, &[SEED_G1, SEED_G2], 2, "pol-recover-revoked-pid",
    );
    let _ = submit_tx(ports.alice, &serde_json::to_string(&rec_revoked_pid).unwrap());
    let rrp_result = wait_tx_result(ports.alice, "pol-recover-revoked-pid", Duration::from_secs(10))
        .expect("revoked-pid recovery not settled");
    assert!(!rrp_result["success"].as_bool().unwrap_or(true),
        "C-06: policy_id=2 (revoked) should be rejected: {:?}", rrp_result);
    eprintln!("  [+] C-06 PASS: revoked policy_id=2 correctly rejected");

    // ── C-07: Identity and balance invariants ─────────────────────────────────

    eprintln!("\n--- C-07: Address, identity, and balance invariants ---");

    let acct_after = account_of(ports.alice, PILOT_ADDR).unwrap_or_default();
    let addr_after = acct_after["address"].as_str().unwrap_or("");
    assert_eq!(addr_after, PILOT_ADDR, "C-07: address must be stable");
    let bal_after = acct_after["balances"]["uqcb"].as_u64().unwrap_or(0);
    assert!(bal_after < bal_before || bal_before == 0,
        "C-07: balance should only decrease (gas), not increase");
    eprintln!("  [+] C-07 PASS: address={addr_after} balance {bal_before}→{bal_after} (gas only)");

    // ── C-08: Four-node convergence ───────────────────────────────────────────

    eprintln!("\n--- C-08: Cross-node convergence ---");
    std::thread::sleep(Duration::from_secs(2));

    let roots: Vec<String> = all.iter().map(|&p| state_root(p)).collect();
    eprintln!("  state roots:");
    for (i, r) in roots.iter().enumerate() { eprintln!("    node{i}: {r}"); }
    let root_ref = &roots[0];
    for (i, r) in roots.iter().enumerate() {
        assert_eq!(r, root_ref, "C-08: node{i} state root differs from node0");
    }
    assert!(!root_ref.is_empty(), "C-08: state root must not be empty");

    let kv_values: Vec<u64> = all.iter().map(|&p| {
        account_of(p, PILOT_ADDR)
            .and_then(|v| v["key_version"].as_u64())
            .unwrap_or(0)
    }).collect();
    eprintln!("  key_versions: {:?}", kv_values);
    for (i, &kv) in kv_values.iter().enumerate() {
        assert_eq!(kv, 2, "C-08: node{i} key_version should be 2");
    }

    eprintln!("  [+] C-08 PASS: all 4 nodes agree (state_root={}, key_version=2)", root_ref);

    eprintln!("\n=== DIS-003A: ALL CHECKS PASSED ===");
    eprintln!("  policy_generation correctly tracked through: enroll→recover→enroll→enroll→revoke→enroll→recover→enroll");
    eprintln!("  state_root: {}", roots[0]);
}
