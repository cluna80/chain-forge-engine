//! DIS-003C — Cross-chain and Cross-account Replay Attack Coverage
//!
//! Adversarial tests proving that `RecoverAccountKey` guardian signatures are
//! bound to a specific (chain_id, account, key_version, new_public_key) tuple
//! and cannot be replayed in any other context.
//!
//! No new transaction types are introduced; this phase is purely adversarial
//! verification of the signing-domain enforcement already present in the
//! recovery executor.
//!
//! ## Acceptance criteria
//!
//! | ID   | Adversarial scenario |
//! |------|----------------------|
//! | E-01 | Guardian sigs created for chain_id=X are rejected on chain_id=Y |
//! | E-02 | Guardian sigs created for account A are rejected for account B |
//! | E-03 | Guardian sigs created for key_version=N are rejected at key_version=N+1 |
//! | E-04 | Guardian sigs bound to new_pk_A are rejected when new_pk_B is presented |
//! | E-05 | PoP signed by new_pk_A is rejected when new_pk_B is presented |
//! | E-06 | Valid sigs for a legitimate recovery ARE accepted (positive control) |
//! | E-07 | Cross-account replay: sigs for account B cannot unlock account A |
//! | E-08 | All four nodes agree on state root after all adversarial ops |
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test dis_003c_replay_attack_live -- --nocapture
//! ```
//!
//! Per CLAUDE.md: mark E-01 through E-08 ✅ only after confirmed passing on
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

/// The actual chain_id the devnet runs on.
const CHAIN_ID:   &str = "qcb-devnet-dis003c";
/// A different chain_id — used for E-01 cross-chain replay.
const CHAIN_ID_X: &str = "qcb-mainnet-fake-000000000000000";

const PILOT_ADDR:   &str = "qcb1pilot";
const VICTIM_ADDR:  &str = "qcb1victim";  // second account for E-02 / E-07

const SEED_PILOT:  &str = "dis003c-pilot-device-seed-000000000000000000000000001";
const SEED_VICTIM: &str = "dis003c-victim-device-seed-00000000000000000000000002";

const SEED_G1: &str = "dis003c-guardian-1-seed-000000000000000000000000000010";
const SEED_G2: &str = "dis003c-guardian-2-seed-000000000000000000000000000020";

/// New key for the legitimate recovery (E-06).
const SEED_NEW_GOOD: &str = "dis003c-new-good-key-00000000000000000000000000099";
/// A different new key (used as the "wrong pk" in E-04/E-05).
const SEED_NEW_BAD:  &str = "dis003c-new-bad-key-000000000000000000000000000088";

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
    manifest_dir().join("tests").join("devnet").join("genesis-dis003c.json")
}

fn key_file(label: &str) -> PathBuf {
    manifest_dir().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json"))
}

fn devnet_dirs() -> PathBuf {
    std::env::temp_dir().join("dis003c_replay_devnet")
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

/// Build an enroll tx signed by `seed`.
fn build_enroll(seed: &str, sender: &str, nonce: u64,
                guardians: Vec<Vec<u8>>, threshold: u32, tx_id: &str) -> Transaction {
    ml_dsa_tx(seed, sender, nonce,
        TxBody::EnrollRecoveryPolicy { guardians, threshold },
        tx_id, 500_000)
}

/// Build a recovery tx with full control over each signing domain.
/// `guardian_chain_id` / `guardian_account` / `guardian_kv` / `guardian_new_pk`
/// are the values the guardians *actually* signed — they may differ from the
/// tx fields to simulate replay attacks.
#[allow(clippy::too_many_arguments)]
fn build_recover_custom(
    // New-key material presented in the tx.
    new_seed:       &str,
    // PoP domain — what the new key actually signs.
    pop_chain_id:   &str,
    pop_account:    &str,
    pop_kv:         u32,
    // Guardian domain — what guardians actually signed.
    g_chain_id:     &str,
    g_account:      &str,
    g_kv:           u32,
    g_new_pk_seed:  &str,   // seed whose pk the guardians signed
    // Tx metadata.
    tx_sender:      &str,
    tx_nonce:       u64,
    tx_kv:          u32,
    guardian_seeds: &[&str],
    policy_id:      u64,
    tx_id:          &str,
) -> Transaction {
    let new_kp      = MlDsaScheme.generate_keypair(new_seed).expect("new keygen");
    let g_pk_kp     = MlDsaScheme.generate_keypair(g_new_pk_seed).expect("g_pk keygen");

    // PoP: new key signs pop_chain_id / pop_account / pop_kv / new_kp.pk
    let pop_msg = account_key_rotation_signing_bytes(pop_chain_id, pop_account, pop_kv, &new_kp.public_key);
    let pop_sig = MlDsaScheme.sign(&pop_msg, &new_kp).expect("PoP sign");

    // Guardians sign g_chain_id / g_account / g_kv / g_pk_kp.pk
    let rec_msg = recovery_domain_signing_bytes(g_chain_id, g_account, g_kv, &g_pk_kp.public_key);
    let guardian_signatures: Vec<GuardianAuth> = guardian_seeds.iter().map(|&gs| {
        let gkp = MlDsaScheme.generate_keypair(gs).expect("guardian keygen");
        let sig = MlDsaScheme.sign(&rec_msg, &gkp).expect("guardian sign");
        GuardianAuth { guardian_public_key: gkp.public_key.clone(), signature: sig.bytes.clone() }
    }).collect();

    Transaction {
        id: tx_id.to_string(), sender: tx_sender.to_string(), nonce: tx_nonce,
        body: TxBody::RecoverAccountKey {
            new_public_key:     new_kp.public_key.clone(),
            new_key_scheme:     "ml-dsa-65".to_string(),
            key_version:        tx_kv,
            pop_signature:      pop_sig.bytes.clone(),
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

/// Convenience: build a fully-correct recovery tx (positive control, E-06).
fn build_recover_valid(
    new_seed: &str, sender: &str, nonce: u64, kv: u32,
    guardian_seeds: &[&str], policy_id: u64, tx_id: &str,
) -> Transaction {
    build_recover_custom(
        new_seed,
        CHAIN_ID, sender, kv,   // correct PoP domain
        CHAIN_ID, sender, kv, new_seed,  // guardians sign correct domain + same pk
        sender, nonce, kv,
        guardian_seeds, policy_id, tx_id,
    )
}

fn send_wait(port: u16, tx: &Transaction, label: &str) -> serde_json::Value {
    let json = serde_json::to_string(tx).expect("serialize");
    let _ = submit_tx(port, &json);
    wait_tx_result(port, &tx.id, Duration::from_secs(15))
        .unwrap_or_else(|| panic!("{label}: tx not settled within timeout"))
}

// ── Setup helpers ──────────────────────────────────────────────────────────────

/// Register identity, enroll policy, return policy_id.
fn setup_account(port: u16, addr: &str, device_seed: &str,
                 g1_pk: Vec<u8>, g2_pk: Vec<u8>,
                 reg_id: &str, enroll_id: &str) -> u64 {
    let n0  = current_nonce(port, addr);
    let reg = ml_dsa_tx(device_seed, addr, n0, TxBody::RegisterIdentity, reg_id, 200_000);
    let _   = send_wait(port, &reg, reg_id);

    let n1     = current_nonce(port, addr);
    let enroll = build_enroll(device_seed, addr, n1, vec![g1_pk, g2_pk], 2, enroll_id);
    let er     = send_wait(port, &enroll, enroll_id);
    assert!(er["success"].as_bool().unwrap_or(false), "{enroll_id} failed: {:?}", er);

    account_of(port, addr)
        .and_then(|v| v["policy_generation"].as_u64())
        .unwrap_or(1)
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn dis_003c_replay_attacks() {
    let _ = std::fs::remove_dir_all(devnet_dirs());

    let ports = Ports::new();
    eprintln!("\n=== DIS-003C: Cross-chain and Cross-account Replay Attack Coverage ===");
    eprintln!("    alice={} bob={} carol={} dave={}", ports.alice, ports.bob, ports.carol, ports.dave);

    let _nodes = spawn_devnet(&ports);
    let all    = ports.all();

    for (i, &p) in all.iter().enumerate() {
        assert!(poll_ready(p, Duration::from_secs(30)), "node{i} not ready");
    }
    eprintln!("  [+] all 4 nodes ready");

    // Pre-derive guardian keys.
    let g1_kp = MlDsaScheme.generate_keypair(SEED_G1).expect("g1");
    let g2_kp = MlDsaScheme.generate_keypair(SEED_G2).expect("g2");

    // ── Setup: register + enroll policy for pilot and victim ──────────────────

    eprintln!("\n--- Setup: register and enroll pilot and victim ---");
    let pilot_pid = setup_account(
        ports.alice, PILOT_ADDR, SEED_PILOT,
        g1_kp.public_key.clone(), g2_kp.public_key.clone(),
        "c-reg-pilot", "c-enroll-pilot",
    );
    eprintln!("  qcb1pilot  policy_id={pilot_pid}");

    let victim_pid = setup_account(
        ports.alice, VICTIM_ADDR, SEED_VICTIM,
        g1_kp.public_key.clone(), g2_kp.public_key.clone(),
        "c-reg-victim", "c-enroll-victim",
    );
    eprintln!("  qcb1victim policy_id={victim_pid}");

    // ── E-01: Cross-chain replay — guardians signed CHAIN_ID_X, not CHAIN_ID ──

    eprintln!("\n--- E-01: Cross-chain replay rejected ---");
    let n_e01  = current_nonce(ports.alice, PILOT_ADDR);
    let rec_e01 = build_recover_custom(
        SEED_NEW_GOOD,
        CHAIN_ID, PILOT_ADDR, 1,         // PoP correct
        CHAIN_ID_X, PILOT_ADDR, 1, SEED_NEW_GOOD, // guardians signed wrong chain
        PILOT_ADDR, n_e01, 1,
        &[SEED_G1, SEED_G2], pilot_pid, "c-recover-e01",
    );
    let r_e01 = send_wait(ports.alice, &rec_e01, "E-01");
    assert!(!r_e01["success"].as_bool().unwrap_or(true),
        "E-01: cross-chain replay should be rejected: {:?}", r_e01);
    let kv_e01 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["key_version"].as_u64()).unwrap_or(0);
    assert_eq!(kv_e01, 0, "E-01: key_version unchanged");
    eprintln!("  [+] E-01 PASS: cross-chain replay correctly rejected (key_version={})", kv_e01);

    // ── E-02: Cross-account — guardians signed for victim, used on pilot ───────

    eprintln!("\n--- E-02: Cross-account replay rejected ---");
    let n_e02  = current_nonce(ports.alice, PILOT_ADDR);
    let rec_e02 = build_recover_custom(
        SEED_NEW_GOOD,
        CHAIN_ID, PILOT_ADDR, 1,           // PoP: pilot
        CHAIN_ID, VICTIM_ADDR, 1, SEED_NEW_GOOD, // guardians signed for victim
        PILOT_ADDR, n_e02, 1,
        &[SEED_G1, SEED_G2], pilot_pid, "c-recover-e02",
    );
    let r_e02 = send_wait(ports.alice, &rec_e02, "E-02");
    assert!(!r_e02["success"].as_bool().unwrap_or(true),
        "E-02: cross-account replay should be rejected: {:?}", r_e02);
    let kv_e02 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["key_version"].as_u64()).unwrap_or(0);
    assert_eq!(kv_e02, 0, "E-02: key_version unchanged");
    eprintln!("  [+] E-02 PASS: cross-account replay correctly rejected");

    // ── E-03: Wrong key_version — guardians signed kv=0, tx claims kv=1 ────────

    eprintln!("\n--- E-03: Wrong key_version in guardian sigs rejected ---");
    let n_e03  = current_nonce(ports.alice, PILOT_ADDR);
    let rec_e03 = build_recover_custom(
        SEED_NEW_GOOD,
        CHAIN_ID, PILOT_ADDR, 1,           // PoP: correct kv=1
        CHAIN_ID, PILOT_ADDR, 0, SEED_NEW_GOOD, // guardians signed kv=0 (stale)
        PILOT_ADDR, n_e03, 1,
        &[SEED_G1, SEED_G2], pilot_pid, "c-recover-e03",
    );
    let r_e03 = send_wait(ports.alice, &rec_e03, "E-03");
    assert!(!r_e03["success"].as_bool().unwrap_or(true),
        "E-03: wrong key_version in guardian sigs should be rejected: {:?}", r_e03);
    eprintln!("  [+] E-03 PASS: stale key_version in guardian sigs correctly rejected");

    // ── E-04: Wrong new_pk — guardians signed new_pk_BAD, tx presents new_pk_GOOD ─

    eprintln!("\n--- E-04: Guardians signed wrong new_pk rejected ---");
    let n_e04  = current_nonce(ports.alice, PILOT_ADDR);
    let rec_e04 = build_recover_custom(
        SEED_NEW_GOOD,
        CHAIN_ID, PILOT_ADDR, 1,            // PoP: new_pk_GOOD
        CHAIN_ID, PILOT_ADDR, 1, SEED_NEW_BAD, // guardians signed new_pk_BAD
        PILOT_ADDR, n_e04, 1,
        &[SEED_G1, SEED_G2], pilot_pid, "c-recover-e04",
    );
    let r_e04 = send_wait(ports.alice, &rec_e04, "E-04");
    assert!(!r_e04["success"].as_bool().unwrap_or(true),
        "E-04: guardians signing wrong new_pk should be rejected: {:?}", r_e04);
    eprintln!("  [+] E-04 PASS: wrong new_pk in guardian sigs correctly rejected");

    // ── E-05: Wrong PoP — PoP signed for wrong pk (new_pk_BAD presents, PoP for BAD)
    //
    // Guardians sign correctly for new_pk_BAD, PoP is over new_pk_BAD, but the
    // tx presents new_pk_BAD as the new key. This is internally consistent but
    // the PoP verifies against the presented pk (new_pk_BAD) — the tx should
    // succeed only if the guardian set and policy match.
    //
    // More useful E-05 variant: PoP signed by a *different* key than new_public_key.
    // new_pk_GOOD is presented, but PoP is produced by new_pk_BAD.

    eprintln!("\n--- E-05: PoP signed by wrong key rejected ---");
    {
        let new_kp_good = MlDsaScheme.generate_keypair(SEED_NEW_GOOD).expect("good key");
        let new_kp_bad  = MlDsaScheme.generate_keypair(SEED_NEW_BAD).expect("bad key");

        // PoP: bad key signs for good key's pk (cross-key PoP forgery attempt)
        let pop_msg = account_key_rotation_signing_bytes(
            CHAIN_ID, PILOT_ADDR, 1, &new_kp_good.public_key);
        let pop_sig_by_bad = MlDsaScheme.sign(&pop_msg, &new_kp_bad).expect("bad PoP sign");

        // Guardians sign correctly for new_kp_good.
        let rec_msg = recovery_domain_signing_bytes(
            CHAIN_ID, PILOT_ADDR, 1, &new_kp_good.public_key);
        let guardian_signatures: Vec<GuardianAuth> = [SEED_G1, SEED_G2].iter().map(|&gs| {
            let gkp = MlDsaScheme.generate_keypair(gs).expect("guardian keygen");
            let sig = MlDsaScheme.sign(&rec_msg, &gkp).expect("guardian sign");
            GuardianAuth { guardian_public_key: gkp.public_key.clone(), signature: sig.bytes.clone() }
        }).collect();

        let n_e05 = current_nonce(ports.alice, PILOT_ADDR);
        let tx_e05 = Transaction {
            id: "c-recover-e05".to_string(),
            sender: PILOT_ADDR.to_string(),
            nonce: n_e05,
            body: TxBody::RecoverAccountKey {
                new_public_key:     new_kp_good.public_key.clone(),
                new_key_scheme:     "ml-dsa-65".to_string(),
                key_version:        1,
                pop_signature:      pop_sig_by_bad.bytes.clone(),  // wrong key's sig
                guardian_signatures,
                policy_id: pilot_pid,
            },
            gas_limit:     2_000_000,
            signature:     vec![],
            public_key:    vec![],
            pq_signatures: vec![],
            sig_scheme:    Some(SchemeId::MlDsa),
            pq_public_key: new_kp_good.public_key.clone(),
        };
        let json = serde_json::to_string(&tx_e05).expect("serialize");
        let _ = submit_tx(ports.alice, &json);
        let r_e05 = wait_tx_result(ports.alice, "c-recover-e05", Duration::from_secs(10))
            .unwrap_or_default();
        assert!(!r_e05["success"].as_bool().unwrap_or(true),
            "E-05: wrong PoP key should be rejected: {:?}", r_e05);
        eprintln!("  [+] E-05 PASS: PoP signed by wrong key correctly rejected");
    }

    // ── E-06: Positive control — valid recovery succeeds ──────────────────────

    eprintln!("\n--- E-06: Valid recovery (positive control) ---");
    let n_e06 = current_nonce(ports.alice, PILOT_ADDR);
    let rec_valid = build_recover_valid(
        SEED_NEW_GOOD, PILOT_ADDR, n_e06, 1,
        &[SEED_G1, SEED_G2], pilot_pid, "c-recover-e06",
    );
    let r_e06 = send_wait(ports.alice, &rec_valid, "E-06");
    assert!(r_e06["success"].as_bool().unwrap_or(false),
        "E-06: valid recovery should succeed: {:?}", r_e06);
    let kv_e06 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["key_version"].as_u64()).unwrap_or(0);
    assert_eq!(kv_e06, 1, "E-06: key_version should be 1 after recovery");
    eprintln!("  [+] E-06 PASS: valid recovery succeeded (key_version={})", kv_e06);

    // ── E-07: Cross-account replay — sigs for victim cannot unlock pilot ────────
    //
    // Re-enroll pilot (policy consumed by E-06), then attempt recovery of pilot
    // using sigs that were correctly generated for victim's account.
    //
    // Even though the guardian set, threshold, and policy_generation structure
    // are identical between the two accounts, the account-address binding in the
    // signing domain must prevent the cross-account substitution.

    eprintln!("\n--- E-07: Cross-account replay (victim's sigs on pilot) rejected ---");
    let n_re = current_nonce(ports.alice, PILOT_ADDR);
    let re_enroll = build_enroll(
        SEED_NEW_GOOD, PILOT_ADDR, n_re,
        vec![g1_kp.public_key.clone(), g2_kp.public_key.clone()],
        2, "c-re-enroll-pilot",
    );
    let ree = send_wait(ports.alice, &re_enroll, "E-07 re-enroll");
    assert!(ree["success"].as_bool().unwrap_or(false), "E-07: re-enroll failed: {:?}", ree);
    let pilot_pid2 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["policy_generation"].as_u64())
        .unwrap_or(2);
    eprintln!("  pilot re-enrolled at policy_id={pilot_pid2}");

    // Build a tx targeting pilot but with guardian sigs created for victim.
    let n_e07  = current_nonce(ports.alice, PILOT_ADDR);
    let victim_kv = account_of(ports.alice, VICTIM_ADDR)
        .and_then(|v| v["key_version"].as_u64())
        .unwrap_or(0) as u32;
    let rec_e07 = build_recover_custom(
        "dis003c-e07-new-key-00000000000000000000000000000",
        CHAIN_ID, PILOT_ADDR, 1,                  // PoP: pilot
        CHAIN_ID, VICTIM_ADDR, victim_kv + 1, "dis003c-e07-new-key-00000000000000000000000000000",
        PILOT_ADDR, n_e07, 1,
        &[SEED_G1, SEED_G2], pilot_pid2, "c-recover-e07",
    );
    let r_e07 = send_wait(ports.alice, &rec_e07, "E-07");
    assert!(!r_e07["success"].as_bool().unwrap_or(true),
        "E-07: victim sigs on pilot should be rejected: {:?}", r_e07);
    let kv_e07 = account_of(ports.alice, PILOT_ADDR)
        .and_then(|v| v["key_version"].as_u64()).unwrap_or(0);
    assert_eq!(kv_e07, 1, "E-07: pilot key_version unchanged after cross-account replay");
    eprintln!("  [+] E-07 PASS: cross-account replay (victim→pilot) correctly rejected");

    // ── E-08: Four-node convergence ───────────────────────────────────────────

    eprintln!("\n--- E-08: Cross-node convergence ---");
    std::thread::sleep(Duration::from_secs(2));

    let roots: Vec<String> = all.iter().map(|&p| state_root(p)).collect();
    eprintln!("  state roots:");
    for (i, r) in roots.iter().enumerate() { eprintln!("    node{i}: {r}"); }
    let root_ref = &roots[0];
    for (i, r) in roots.iter().enumerate() {
        assert_eq!(r, root_ref, "E-08: node{i} state root differs from node0");
    }
    assert!(!root_ref.is_empty(), "E-08: state root must not be empty");

    let kv_all: Vec<u64> = all.iter().map(|&p| {
        account_of(p, PILOT_ADDR)
            .and_then(|v| v["key_version"].as_u64())
            .unwrap_or(0)
    }).collect();
    eprintln!("  pilot key_versions: {:?}", kv_all);
    for (i, &kv) in kv_all.iter().enumerate() {
        assert_eq!(kv, 1, "E-08: node{i} pilot key_version should be 1");
    }

    eprintln!("  [+] E-08 PASS: all 4 nodes agree (state_root={}, pilot_kv=1)", root_ref);

    eprintln!("\n=== DIS-003C: ALL CHECKS PASSED ===");
    eprintln!("  state_root: {root_ref}");
    eprintln!("  Signing domain binds: chain_id ✓  account ✓  key_version ✓  new_pk ✓  pop ✓");
}
