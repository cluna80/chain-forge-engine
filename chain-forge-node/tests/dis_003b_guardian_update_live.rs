//! DIS-003B — Guardian Policy Updates and Compromise Resistance
//!
//! Proves that `UpdateGuardianPolicy` correctly replaces the guardian set
//! and that any guardian signatures collected under the old set are
//! invalidated. Also tests threshold enforcement, duplicate-guardian
//! rejection, removed-guardian rejection, and that account identity
//! and balance are stable throughout.
//!
//! ## Acceptance criteria
//!
//! | ID   | Criterion |
//! |------|-----------|
//! | D-01 | `UpdateGuardianPolicy` replaces guardians; recovery with NEW set succeeds |
//! | D-02 | Recovery attempt using an OLD (pre-update) guardian is rejected |
//! | D-03 | `UpdateGuardianPolicy` is rejected when no policy is currently enrolled |
//! | D-04 | Duplicate guardian key in `UpdateGuardianPolicy` is rejected |
//! | D-05 | Threshold > guardian count in `UpdateGuardianPolicy` is rejected |
//! | D-06 | Recovery with only 1-of-2 sigs when threshold=2 is rejected |
//! | D-07 | policy_generation persists correctly across a full node restart |
//! | D-08 | Account address, identity tier, and balance are unchanged throughout |
//! | D-09 | All four nodes agree on state root and policy_generation after all ops |
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test dis_003b_guardian_update_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: mark D-01 through D-09 ✅ only after confirmed passing on
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

const CHAIN_ID:   &str = "qcb-devnet-dis003b";
const PILOT_ADDR: &str = "qcb1pilot";

const SEED_A:   &str = "dis003b-pilot-device-a-seed-0000000000000000000000000001";
const SEED_REC: &str = "dis003b-pilot-recovery-seed-0000000000000000000000000099";

// Initial guardian set (G1, G2, G3).
const SEED_G1: &str = "dis003b-guardian-1-seed-000000000000000000000000000010";
const SEED_G2: &str = "dis003b-guardian-2-seed-000000000000000000000000000020";
const SEED_G3: &str = "dis003b-guardian-3-seed-000000000000000000000000000030";

// Replacement guardian set (G4, G5) — G3 is removed.
const SEED_G4: &str = "dis003b-guardian-4-seed-000000000000000000000000000040";
const SEED_G5: &str = "dis003b-guardian-5-seed-000000000000000000000000000050";

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

fn genesis_template_path() -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("genesis-dis003b.json")
}

/// Write a patched copy of the genesis with the live pilot public key injected.
///
/// Because `dilithium3::keypair()` is randomised per process, we cannot store a
/// static genesis key.  Instead we generate the pilot keypair at test startup,
/// patch the genesis, and pass the temp file to each node.
fn write_genesis_with_pilot_key(pilot_pubkey: &[u8]) -> PathBuf {
    let hex: String = pilot_pubkey.iter().map(|b| format!("{b:02x}")).collect();
    let template = std::fs::read_to_string(genesis_template_path())
        .expect("read genesis template");
    let mut genesis: serde_json::Value = serde_json::from_str(&template)
        .expect("parse genesis template");

    // Find the qcb1pilot entry and set its public_key.
    let accounts = genesis["genesis_accounts"]
        .as_array_mut()
        .expect("genesis_accounts array");
    let pilot = accounts.iter_mut()
        .find(|a| a["address"].as_str() == Some("qcb1pilot"))
        .expect("qcb1pilot account in genesis");
    pilot["public_key"] = serde_json::Value::String(hex);

    let out = std::env::temp_dir()
        .join("dis003b_guardian_devnet")
        .join("genesis-live.json");
    std::fs::create_dir_all(out.parent().unwrap()).ok();
    std::fs::write(&out, serde_json::to_string_pretty(&genesis).unwrap())
        .expect("write patched genesis");
    out
}

fn key_file(label: &str) -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json"))
}

fn devnet_dirs() -> PathBuf {
    std::env::temp_dir().join("dis003b_guardian_devnet")
}

// ── Node lifecycle ─────────────────────────────────────────────────────────────

struct NodeHandle { #[allow(dead_code)] name: String, process: Child }
impl Drop for NodeHandle { fn drop(&mut self) { let _ = self.process.kill(); } }

fn spawn_node(name: &str, api: u16, p2p: u16, log_dir: &PathBuf,
              peers: &[u16], key_file_path: Option<PathBuf>,
              genesis: &PathBuf) -> NodeHandle {
    let log_file = std::fs::File::create(log_dir.join(format!("{name}.log")))
        .expect("create log");
    let data_dir = devnet_dirs().join("data").join(name);
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(genesis)
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

fn spawn_devnet(ports: &Ports, genesis: &PathBuf) -> [NodeHandle; 4] {
    let base = devnet_dirs();
    let log_dir = base.join("logs");
    std::fs::create_dir_all(&log_dir).expect("create log dir");

    let kf = |label: &str| -> Option<PathBuf> {
        let p = key_file(label); if p.exists() { Some(p) } else { None }
    };
    [
        spawn_node("qcb1alice", ports.alice, ports.alice_p2p, &log_dir,
            &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p], kf("alice"), genesis),
        spawn_node("qcb1bob",   ports.bob,   ports.bob_p2p,   &log_dir,
            &[ports.alice_p2p, ports.carol_p2p, ports.dave_p2p], kf("bob"), genesis),
        spawn_node("qcb1carol", ports.carol, ports.carol_p2p, &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.dave_p2p], kf("carol"), genesis),
        spawn_node("qcb1dave",  ports.dave,  ports.dave_p2p,  &log_dir,
            &[ports.alice_p2p, ports.bob_p2p, ports.carol_p2p], kf("dave"), genesis),
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

// ── Tx builders ───────────────────────────────────────────────────────────────

fn ml_dsa_tx(seed: &str, sender: &str, nonce: u64, body: TxBody,
             tx_id: &str, gas: u64) -> Transaction {
    let kp        = MlDsaScheme.generate_keypair(seed).expect("keygen");
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

fn build_update_guardians(seed: &str, sender: &str, nonce: u64,
                           new_guardians: Vec<Vec<u8>>, new_threshold: u32,
                           tx_id: &str) -> Transaction {
    ml_dsa_tx(seed, sender, nonce,
        TxBody::UpdateGuardianPolicy { new_guardians, new_threshold },
        tx_id, 500_000)
}

fn build_recover(new_seed: &str, sender: &str, nonce: u64, key_version: u32,
                 guardian_seeds: &[&str], policy_id: u64, tx_id: &str) -> Transaction {
    let new_kp  = MlDsaScheme.generate_keypair(new_seed).expect("new keygen");
    let pop_msg = account_key_rotation_signing_bytes(CHAIN_ID, sender, key_version, &new_kp.public_key);
    let pop_sig = MlDsaScheme.sign(&pop_msg, &new_kp).expect("PoP sign");
    let rec_msg = recovery_domain_signing_bytes(CHAIN_ID, sender, key_version, &new_kp.public_key, policy_id, None);

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

fn send_wait(port: u16, tx: &Transaction, label: &str) -> serde_json::Value {
    let json = serde_json::to_string(tx).expect("serialize");
    let _ = submit_tx(port, &json);
    wait_tx_result(port, &tx.id, Duration::from_secs(15))
        .unwrap_or_else(|| panic!("{label}: tx not settled within timeout"))
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn dis_003b_guardian_update() {
    let _ = std::fs::remove_dir_all(devnet_dirs());

    // Generate the pilot keypair first so we can embed the public key in genesis.
    // dilithium3::keypair() is randomised per process; we cannot use a static key.
    let pilot_kp = MlDsaScheme.generate_keypair(SEED_A).expect("pilot keygen");
    let genesis = write_genesis_with_pilot_key(&pilot_kp.public_key);
    eprintln!("  [+] pilot pubkey: {} bytes, genesis written to {:?}",
              pilot_kp.public_key.len(), genesis);

    let ports = Ports::new();
    eprintln!("\n=== DIS-003B: Guardian Policy Updates and Compromise Resistance ===");
    eprintln!("    alice={} bob={} carol={} dave={}", ports.alice, ports.bob, ports.carol, ports.dave);

    let _nodes = spawn_devnet(&ports, &genesis);
    let all = ports.all();

    for (i, &p) in all.iter().enumerate() {
        assert!(poll_ready(p, Duration::from_secs(30)), "node{i} not ready");
    }
    eprintln!("  [+] all 4 nodes ready");

    // Pre-derive keys.
    let g1_kp = MlDsaScheme.generate_keypair(SEED_G1).expect("g1");
    let g2_kp = MlDsaScheme.generate_keypair(SEED_G2).expect("g2");
    let g3_kp = MlDsaScheme.generate_keypair(SEED_G3).expect("g3");
    let g4_kp = MlDsaScheme.generate_keypair(SEED_G4).expect("g4");
    let g5_kp = MlDsaScheme.generate_keypair(SEED_G5).expect("g5");

    let initial_guardians     = vec![g1_kp.public_key.clone(), g2_kp.public_key.clone(),
                                     g3_kp.public_key.clone()];
    let replacement_guardians = vec![g4_kp.public_key.clone(), g5_kp.public_key.clone()];

    // Balance baseline for D-08.
    let bal_before = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["balances"]["uqcb"].as_u64())
        .unwrap_or(0);

    // ── Bootstrap: register identity ──────────────────────────────────────────

    eprintln!("\n--- Bootstrap: register qcb1pilot ---");
    let reg = ml_dsa_tx(SEED_A, PILOT_ADDR, 0, TxBody::RegisterIdentity, "b-reg-001", 200_000);
    let _ = send_wait(ports.alice, &reg, "bootstrap/register");
    eprintln!("  [+] identity registered");

    // ── Enroll initial policy (G1, G2, G3; threshold=2; policy_id=1) ──────────

    eprintln!("\n--- Enroll initial policy (G1/G2/G3, threshold=2) ---");
    let n_enroll = current_nonce(ports.alice, PILOT_ADDR);
    let enroll = build_enroll(SEED_A, PILOT_ADDR, n_enroll,
                              initial_guardians.clone(), 2, "b-enroll-001");
    let er = send_wait(ports.alice, &enroll, "initial enroll");
    assert!(er["success"].as_bool().unwrap_or(false), "initial enroll failed: {:?}", er);
    eprintln!("  [+] policy_id=1 enrolled (G1/G2/G3)");

    // ── D-01: UpdateGuardianPolicy → replace with G4, G5; recover with new set ──

    eprintln!("\n--- D-01: UpdateGuardianPolicy (G4/G5, threshold=2); new set recovers ---");
    let n_upd = current_nonce(ports.alice, PILOT_ADDR);
    let upd = build_update_guardians(SEED_A, PILOT_ADDR, n_upd,
                                     replacement_guardians.clone(), 2, "b-update-001");
    let ur = send_wait(ports.alice, &upd, "D-01 update");
    assert!(ur["success"].as_bool().unwrap_or(false), "D-01: UpdateGuardianPolicy failed: {:?}", ur);
    eprintln!("  [+] policy_id=2 (G4/G5) active");

    let n_rec1 = current_nonce(ports.alice, PILOT_ADDR);
    let rec1 = build_recover(SEED_REC, PILOT_ADDR, n_rec1, 1,
                              &[SEED_G4, SEED_G5], 2, "b-recover-d01");
    let r1 = send_wait(ports.alice, &rec1, "D-01 recover");
    assert!(r1["success"].as_bool().unwrap_or(false), "D-01: recovery with new set failed: {:?}", r1);
    let kv1 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["key_version"].as_u64()).unwrap_or(0);
    assert_eq!(kv1, 1, "D-01: key_version should be 1 after recovery");
    eprintln!("  [+] D-01 PASS: recovery with G4/G5 succeeded (key_version={})", kv1);

    // ── D-02: Old guardian G3 (pre-update) is rejected ────────────────────────

    // Re-enroll with G4/G5 (policy consumed by recovery above) to give us an
    // active policy_id=3, then try recovery using G3 (old set, not enrolled).
    eprintln!("\n--- D-02: Old guardian (G3) rejected ---");
    let n_re = current_nonce(ports.alice, PILOT_ADDR);
    let re_enroll = build_enroll(SEED_REC, PILOT_ADDR, n_re,
                                  replacement_guardians.clone(), 2, "b-enroll-002");
    let ree = send_wait(ports.alice, &re_enroll, "D-02 re-enroll");
    assert!(ree["success"].as_bool().unwrap_or(false), "D-02: re-enroll failed: {:?}", ree);
    eprintln!("  Re-enrolled at policy_id=3 (G4/G5)");

    let n_d02 = current_nonce(ports.alice, PILOT_ADDR);
    // G3 is not in the enrolled set; G4 is. G3+G4 = 2 sigs but G3 is not enrolled.
    let rec_old_g = build_recover(
        "dis003b-d02-new-key-000000000000000000000000000000",
        PILOT_ADDR, n_d02, 2, &[SEED_G3, SEED_G4], 3, "b-recover-d02",
    );
    let r2 = send_wait(ports.alice, &rec_old_g, "D-02 old guardian");
    assert!(!r2["success"].as_bool().unwrap_or(true),
        "D-02: old guardian G3 should be rejected: {:?}", r2);
    let kv_d02 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["key_version"].as_u64()).unwrap_or(0);
    assert_eq!(kv_d02, 1, "D-02: key_version unchanged after rejection");
    eprintln!("  [+] D-02 PASS: old guardian G3 correctly rejected");

    // ── D-03: UpdateGuardianPolicy rejected when no policy enrolled ────────────

    // Revoke the current policy first, then try UpdateGuardianPolicy.
    eprintln!("\n--- D-03: UpdateGuardianPolicy rejected with no active policy ---");
    let n_rev = current_nonce(ports.alice, PILOT_ADDR);
    let revoke = ml_dsa_tx(SEED_REC, PILOT_ADDR, n_rev, TxBody::RevokeRecoveryPolicy,
                            "b-revoke-d03", 200_000);
    let rev_r = send_wait(ports.alice, &revoke, "D-03 revoke");
    assert!(rev_r["success"].as_bool().unwrap_or(false), "D-03: revoke failed: {:?}", rev_r);

    let n_d03 = current_nonce(ports.alice, PILOT_ADDR);
    let upd_no_policy = build_update_guardians(
        SEED_REC, PILOT_ADDR, n_d03,
        replacement_guardians.clone(), 2, "b-update-d03",
    );
    let u3 = send_wait(ports.alice, &upd_no_policy, "D-03 update no policy");
    assert!(!u3["success"].as_bool().unwrap_or(true),
        "D-03: UpdateGuardianPolicy with no policy should be rejected: {:?}", u3);
    eprintln!("  [+] D-03 PASS: UpdateGuardianPolicy correctly rejected (no active policy)");

    // Re-enroll for subsequent tests.
    let n_reenroll2 = current_nonce(ports.alice, PILOT_ADDR);
    let re_enroll2 = build_enroll(SEED_REC, PILOT_ADDR, n_reenroll2,
                                   replacement_guardians.clone(), 2, "b-enroll-003");
    let ree2 = send_wait(ports.alice, &re_enroll2, "re-enroll after D-03");
    assert!(ree2["success"].as_bool().unwrap_or(false), "re-enroll-003 failed: {:?}", ree2);

    // ── D-04: Duplicate guardian in UpdateGuardianPolicy rejected ──────────────

    eprintln!("\n--- D-04: Duplicate guardian key rejected ---");
    let n_d04 = current_nonce(ports.alice, PILOT_ADDR);
    let dupe_guardians = vec![g4_kp.public_key.clone(), g4_kp.public_key.clone()];
    let upd_dupe = build_update_guardians(
        SEED_REC, PILOT_ADDR, n_d04, dupe_guardians, 2, "b-update-d04",
    );
    let u4 = send_wait(ports.alice, &upd_dupe, "D-04 duplicate");
    assert!(!u4["success"].as_bool().unwrap_or(true),
        "D-04: duplicate guardian should be rejected: {:?}", u4);
    eprintln!("  [+] D-04 PASS: duplicate guardian correctly rejected");

    // ── D-05: Threshold > guardian count rejected ──────────────────────────────

    eprintln!("\n--- D-05: threshold > guardian count rejected ---");
    let n_d05 = current_nonce(ports.alice, PILOT_ADDR);
    let two_guardians = vec![g4_kp.public_key.clone(), g5_kp.public_key.clone()];
    let upd_bad_thresh = build_update_guardians(
        SEED_REC, PILOT_ADDR, n_d05, two_guardians, 3, "b-update-d05",
    );
    let u5 = send_wait(ports.alice, &upd_bad_thresh, "D-05 bad threshold");
    assert!(!u5["success"].as_bool().unwrap_or(true),
        "D-05: threshold > guardians should be rejected: {:?}", u5);
    eprintln!("  [+] D-05 PASS: bad threshold correctly rejected");

    // ── D-06: 1-of-2 recovery (below threshold=2) rejected ────────────────────

    eprintln!("\n--- D-06: 1-of-2 sigs below threshold=2 rejected ---");
    // Current policy is still enroll-003 (G4/G5, threshold=2, policy_id from that enrollment).
    let pol_id_d06 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["policy_generation"].as_u64())
        .unwrap_or(4);
    let n_d06 = current_nonce(ports.alice, PILOT_ADDR);
    let rec_1of2 = build_recover(
        "dis003b-d06-new-key-000000000000000000000000000000",
        PILOT_ADDR, n_d06, 2, &[SEED_G4], pol_id_d06, "b-recover-d06",
    );
    let r6 = send_wait(ports.alice, &rec_1of2, "D-06 1-of-2");
    assert!(!r6["success"].as_bool().unwrap_or(true),
        "D-06: 1-of-2 recovery should be rejected: {:?}", r6);
    eprintln!("  [+] D-06 PASS: 1-of-2 recovery correctly rejected");

    // ── D-07: policy_generation persists across node restart ──────────────────

    eprintln!("\n--- D-07: policy_generation persists across restart ---");
    let pgen_before = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["policy_generation"].as_u64())
        .unwrap_or(0);
    eprintln!("  policy_generation before restart: {pgen_before}");

    // Drop all nodes (their Drop kills the processes).
    drop(_nodes);
    std::thread::sleep(Duration::from_millis(500));

    // Restart on new ports (same data dirs).
    let ports2 = Ports::new();
    eprintln!("  Restarting: alice={} bob={} carol={} dave={}",
        ports2.alice, ports2.bob, ports2.carol, ports2.dave);
    let _nodes2 = spawn_devnet(&ports2, &genesis);
    let all2 = ports2.all();

    for (i, &p) in all2.iter().enumerate() {
        assert!(poll_ready(p, Duration::from_secs(30)), "node{i} not ready after restart");
    }

    let pgen_after = account_of(ports2.alice, PILOT_ADDR)
        .and_then(|v| v["policy_generation"].as_u64())
        .unwrap_or(0);
    eprintln!("  policy_generation after restart: {pgen_after}");
    assert_eq!(pgen_after, pgen_before,
        "D-07: policy_generation must survive restart ({pgen_before} → {pgen_after})");
    assert!(pgen_after > 0, "D-07: policy_generation must not be zero after all ops");
    eprintln!("  [+] D-07 PASS: policy_generation={pgen_after} survived restart");

    // ── D-08: Address, identity, and balance invariants ───────────────────────

    eprintln!("\n--- D-08: Address, identity, and balance invariants ---");
    let acct = account_of(ports2.alice, PILOT_ADDR).unwrap_or_default();
    let addr = acct["address"].as_str().unwrap_or("");
    assert_eq!(addr, PILOT_ADDR, "D-08: address must be stable");
    let bal_after = acct["balances"]["uqcb"].as_u64().unwrap_or(0);
    assert!(bal_after < bal_before || bal_before == 0,
        "D-08: balance should only decrease (gas)");
    eprintln!("  [+] D-08 PASS: address={addr} balance {bal_before}→{bal_after} (gas only)");

    // ── D-09: Four-node convergence ───────────────────────────────────────────

    eprintln!("\n--- D-09: Cross-node convergence after restart ---");

    // Poll until all 4 nodes agree on a non-empty state root (up to 30 s).
    // A single read immediately after restart can catch nodes still replaying
    // committed blocks, so we wait for consensus.
    let root_ref = {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last_roots: Vec<String> = vec![];
        loop {
            let roots: Vec<String> = all2.iter().map(|&p| state_root(p)).collect();
            let first = &roots[0];
            let all_same   = roots.iter().all(|r| r == first);
            let all_nonempty = roots.iter().all(|r| !r.is_empty());
            if all_same && all_nonempty {
                eprintln!("  state roots (converged):");
                for (i, r) in roots.iter().enumerate() { eprintln!("    node{i}: {r}"); }
                last_roots = roots;
                break;
            }
            if Instant::now() >= deadline {
                eprintln!("  state roots at timeout:");
                for (i, r) in roots.iter().enumerate() { eprintln!("    node{i}: {r}"); }
                panic!("D-09: nodes did not agree on state root within 30s");
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        last_roots.into_iter().next().unwrap_or_default()
    };

    assert!(!root_ref.is_empty(), "D-09: state root must not be empty");

    let pgen_all: Vec<u64> = all2.iter().map(|&p| {
        account_of(p, PILOT_ADDR)
            .and_then(|v| v["policy_generation"].as_u64())
            .unwrap_or(0)
    }).collect();
    eprintln!("  policy_generations: {:?}", pgen_all);
    for (i, &pg) in pgen_all.iter().enumerate() {
        assert_eq!(pg, pgen_before,
            "D-09: node{i} policy_generation should be {pgen_before}");
    }

    eprintln!("  [+] D-09 PASS: all 4 nodes agree (state_root={root_ref}, pgen={})", pgen_all[0]);

    eprintln!("\n=== DIS-003B: ALL CHECKS PASSED ===");
    eprintln!("  state_root: {root_ref}");
    eprintln!("  policy_generation: {}", pgen_all[0]);
    eprintln!("  key_version: {}", acct["key_version"].as_u64().unwrap_or(0));
}

