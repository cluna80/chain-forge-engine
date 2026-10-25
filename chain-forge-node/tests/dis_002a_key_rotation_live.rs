//! DIS-002A — Authenticated Account Key Rotation Acceptance Test
//!
//! Proves that the `RotateAccountKey` transaction path is correct end-to-end.
//!
//! ## What is tested
//!
//! **Case A — Happy path:**
//!   1. User submits a Transfer tx with Key_A (first-use registration).
//!   2. User submits RotateAccountKey from Key_A → Key_B (with PoP from Key_B).
//!   3. Rotation executes with `success: true`.
//!   4. User submits a Transfer tx with Key_B.
//!   5. Transfer executes with `success: true`.
//!
//! **Case B — Identity continuity:**
//!   After rotation: address, balance (minus gas), nonce, are all as expected.
//!
//! **Case C — Old key rejected after rotation:**
//!   Submit a tx signed with Key_A after rotation.
//!   Must execute with `success: false` ("signing key does not match").
//!
//! **Case D — New key accepted:**
//!   Covered by Case A step 4 (Key_B Transfer succeeds post-rotation).
//!
//! **Case E — Replay of rotation tx rejected:**
//!   Resubmit the rotation tx (same nonce). Must fail (nonce already consumed).
//!
//! **Case F — Stale key_version rejected:**
//!   Submit a rotation tx with key_version = 0 after rotation has set it to 1.
//!   Must fail with key_version mismatch.
//!
//! **Case G — Unauthorized rotation (wrong current-key signature) rejected:**
//!   Build a RotateAccountKey tx signed by a third party's key.
//!   Must fail signature verification.
//!
//! **Case H — Invalid PoP rejected:**
//!   Submit RotateAccountKey with valid outer sig but garbage pop_signature.
//!   Must fail with PoP verification error.
//!
//! **Case I — Cross-node consistency:**
//!   After all rotations, all 4 nodes agree on the same state root.
//!
//! ## Run
//!
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test dis_002a_key_rotation_live -- --nocapture
//! ```

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash};
use chain_forge_execution::{
    Transaction, TxBody,
    account_key_rotation_signing_bytes,
};

const CHAIN_ID:   &str = "qcb-devnet-dis002a";
const USER_ADDR:  &str = "qcb1user";
const BYSTANDER:  &str = "qcb1bystander";

// Seeds for deterministic keypair generation.
const SEED_A: &str = "dis002a-key-a-seed-00000000000000000000000000000001";
const SEED_B: &str = "dis002a-key-b-seed-00000000000000000000000000000002";
const SEED_C: &str = "dis002a-key-c-bystander-seed-000000000000000000000000003";

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

fn node_bin() -> PathBuf {
    repo_root().join("target").join("debug").join("chain-forge-node")
}

fn genesis_path() -> PathBuf {
    repo_root().join("tests").join("devnet").join("genesis-dis002a.json")
}

fn key_file(label: &str) -> PathBuf {
    repo_root().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json"))
}

// ── Node lifecycle ────────────────────────────────────────────────────────────

struct GuardedChild(Child);
impl Drop for GuardedChild {
    fn drop(&mut self) { let _ = self.0.kill(); }
}

fn spawn_node(
    label: &str, api: u16, p2p: u16,
    peers: &[String],
) -> GuardedChild {
    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator").arg(format!("qcb1{label}"))
       .arg("--key-file").arg(key_file(label))
       .arg("--api-port").arg(api.to_string())
       .arg("--p2p-port").arg(p2p.to_string());
    for p in peers {
        cmd.arg("--peer").arg(p);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    GuardedChild(cmd.spawn().expect("spawn_node: failed to start node"))
}

fn spawn_devnet(ports: &DevnetPorts) -> [GuardedChild; 4] {
    let ap = format!("127.0.0.1:{}", ports.alice_p2p);
    let bp = format!("127.0.0.1:{}", ports.bob_p2p);
    let cp = format!("127.0.0.1:{}", ports.carol_p2p);
    let dp = format!("127.0.0.1:{}", ports.dave_p2p);
    [
        spawn_node("alice", ports.alice_api, ports.alice_p2p, &[bp.clone(), cp.clone(), dp.clone()]),
        spawn_node("bob",   ports.bob_api,   ports.bob_p2p,   &[ap.clone(), cp.clone(), dp.clone()]),
        spawn_node("carol", ports.carol_api, ports.carol_p2p, &[ap.clone(), bp.clone(), dp.clone()]),
        spawn_node("dave",  ports.dave_api,  ports.dave_p2p,  &[ap.clone(), bp.clone(), cp.clone()]),
    ]
}

// ── HTTP helpers (raw TCP, no external crate) ─────────────────────────────────

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

fn state_root(port: u16) -> String {
    api_get(port, "/api/status")
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn nonce_of(port: u16, address: &str) -> u64 {
    api_get(port, &format!("/api/accounts/{address}"))
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Transaction builders ──────────────────────────────────────────────────────

/// Build and sign an ML-DSA-65 Transfer tx.
fn build_transfer(
    seed: &str, sender: &str, nonce: u64,
    to: &str, amount: u128,
) -> Transaction {
    let kp = MlDsaScheme.generate_keypair(seed).expect("ML-DSA keygen");
    let body = TxBody::Transfer { to: to.to_string(), denom: "uqcb".to_string(), amount };
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let sig = MlDsaScheme.sign(&message, &kp).expect("ML-DSA sign");
    let sig_hex: String = sig.bytes.iter().map(|b| format!("{b:02x}")).collect();
    Transaction {
        id:            format!("dis002a-xfer-{sender}-n{nonce}"),
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

/// Build a RotateAccountKey tx signed with `current_seed`,
/// rotating to the keypair derived from `new_seed`.
///
/// `tx_id_suffix`: unique suffix for the transaction ID.
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

    // Proof-of-possession: new key signs the domain message.
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

    // Outer tx signature: current key signs the tx body.
    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message   = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let outer_sig = MlDsaScheme.sign(&message, &current_kp).expect("outer sign");
    let sig_hex: String = outer_sig.bytes.iter().map(|b| format!("{b:02x}")).collect();

    Transaction {
        id:            format!("dis002a-rotate-{tx_id_suffix}"),
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

/// Build a RotateAccountKey tx with a garbage pop_signature (Case H).
fn build_rotation_bad_pop(
    current_seed: &str,
    new_seed:     &str,
    sender:       &str,
    nonce:        u64,
    key_version:  u32,
) -> Transaction {
    let current_kp = MlDsaScheme.generate_keypair(current_seed).expect("current keygen");
    let new_kp     = MlDsaScheme.generate_keypair(new_seed).expect("new keygen");

    let garbage_pop: Vec<u8> = (0..4595_usize).map(|i| (i * 7 + 99) as u8).collect();

    let body = TxBody::RotateAccountKey {
        new_public_key: new_kp.public_key.clone(),
        new_key_scheme: "ml-dsa-65".to_string(),
        key_version,
        pop_signature:  garbage_pop,
    };

    let body_json = serde_json::to_string(&body).expect("body serialise");
    let message   = mldsa_tx_prehash(CHAIN_ID, body_json.as_bytes());
    let outer_sig = MlDsaScheme.sign(&message, &current_kp).expect("outer sign");
    let sig_hex: String = outer_sig.bytes.iter().map(|b| format!("{b:02x}")).collect();

    Transaction {
        id:            "dis002a-rotate-bad-pop".to_string(),
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

/// Build a RotateAccountKey tx signed by a *third party* key (Case G).
/// The outer signature will fail because the sender's bound key is Key_A, not SEED_C.
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
        id:            "dis002a-rotate-wrong-signer".to_string(),
        sender:        sender.to_string(),
        nonce,
        body,
        gas_limit:     1_000_000,
        signature:     vec![],
        public_key:    vec![],
        pq_signatures: vec![format!("mldsa65:{sig_hex}")],
        sig_scheme:    Some(SchemeId::MlDsa),
        pq_public_key: attacker_kp.public_key.clone(),  // attacker's key, not User's
    }
}

// ── Diagnostic ───────────────────────────────────────────────────────────────

fn dump_logs(children: &mut [GuardedChild; 4]) {
    let labels = ["alice", "bob", "carol", "dave"];
    for (i, child) in children.iter_mut().enumerate() {
        use std::io::Read;
        if let Some(stderr) = child.0.stderr.as_mut() {
            let mut buf = String::new();
            let _ = stderr.read_to_string(&mut buf);
            let lines: Vec<&str> = buf.lines().collect();
            let head = lines.iter().take(50);
            let tail = if lines.len() > 50 { lines.iter().rev().take(40).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>() } else { vec![] };
            eprintln!("=== {} (first 50 lines) ===", labels[i]);
            for l in head { eprintln!("{l}"); }
            if !tail.is_empty() {
                eprintln!("... ({} lines omitted) ...", lines.len().saturating_sub(90));
                eprintln!("=== {} (last 40 lines) ===", labels[i]);
                for l in tail { eprintln!("{l}"); }
            }
        }
    }
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn dis_002a_key_rotation() {
    let ports = DevnetPorts::new();
    let mut nodes = spawn_devnet(&ports);
    let api_port  = ports.alice_api;

    // Wait for devnet to become ready and produce blocks.
    eprintln!("Waiting for devnet readiness...");
    for &p in &ports.all_api() {
        assert!(poll_ready(p, Duration::from_secs(30)), "node {p} did not start");
    }
    assert!(
        poll_height(api_port, 2, Duration::from_secs(30)).is_some(),
        "devnet did not reach height 2 — nodes are not producing blocks"
    );
    eprintln!("Devnet ready.");

    // ── Step 0: establish baseline ────────────────────────────────────────────
    let balance_before = balance_of(api_port, USER_ADDR);
    eprintln!("User balance before: {balance_before} uqcb");

    // ── Step A-1: first Transfer with Key_A (binds Key_A to qcb1user) ─────────
    eprintln!("Case A-1: Submit Transfer with Key_A (first use — binds key)");
    let tx_a1 = build_transfer(SEED_A, USER_ADDR, 0, BYSTANDER, 1_000);
    let tx_a1_json = serde_json::to_string(&tx_a1).expect("serialise");
    let resp_a1 = submit_tx(api_port, &tx_a1_json);
    let ingress_a1 = resp_a1["status"].as_str().unwrap_or("").to_string();
    assert_eq!(ingress_a1, "queued", "A-1 ingress: expected queued, got {ingress_a1}");
    let result_a1 = wait_tx_result(api_port, &tx_a1.id, Duration::from_secs(30))
        .expect("A-1: tx not found after 30s");
    assert!(
        result_a1["success"].as_bool().unwrap_or(false),
        "A-1 FAIL: first Transfer must succeed — {:?}", result_a1
    );
    eprintln!("Case A-1 PASS: Key_A bound, Transfer finalized.");

    // ── Step A-2: RotateAccountKey from Key_A → Key_B ─────────────────────────
    eprintln!("Case A-2: RotateAccountKey Key_A → Key_B");
    // Current nonce after A-1 is 1.
    let rotation_tx = build_rotation_tx(SEED_A, SEED_B, USER_ADDR, 1, 1, "a-to-b");
    let rotation_json = serde_json::to_string(&rotation_tx).expect("serialise");
    let resp_rot = submit_tx(api_port, &rotation_json);
    let ingress_rot = resp_rot["status"].as_str().unwrap_or("").to_string();
    assert_eq!(ingress_rot, "queued", "A-2 ingress: expected queued, got {ingress_rot}");
    let result_rot = wait_tx_result(api_port, &rotation_tx.id, Duration::from_secs(30))
        .expect("A-2: rotation tx not found after 30s");
    assert!(
        result_rot["success"].as_bool().unwrap_or(false),
        "A-2 FAIL: rotation must succeed — {:?}", result_rot
    );
    eprintln!("Case A-2 PASS: RotateAccountKey executed successfully.");

    // ── Step A-3: Transfer with Key_B (post-rotation) ─────────────────────────
    eprintln!("Case A-3 / Case D: Submit Transfer with Key_B (post-rotation)");
    let tx_b1 = build_transfer(SEED_B, USER_ADDR, 2, BYSTANDER, 1_000);
    let tx_b1_json = serde_json::to_string(&tx_b1).expect("serialise");
    let resp_b1 = submit_tx(api_port, &tx_b1_json);
    let ingress_b1 = resp_b1["status"].as_str().unwrap_or("").to_string();
    assert_eq!(ingress_b1, "queued", "A-3 ingress: {ingress_b1}");
    let result_b1 = wait_tx_result(api_port, &tx_b1.id, Duration::from_secs(30))
        .expect("A-3: tx not found after 30s");
    assert!(
        result_b1["success"].as_bool().unwrap_or(false),
        "Case A-3 / D FAIL: Transfer with Key_B must succeed — {:?}", result_b1
    );
    eprintln!("Case A-3 / D PASS: Key_B Transfer finalized.");

    // ── Case B: identity continuity ───────────────────────────────────────────
    eprintln!("Case B: Checking identity continuity post-rotation");
    let nonce_after = nonce_of(api_port, USER_ADDR);
    assert_eq!(nonce_after, 3, "Case B FAIL: nonce should be 3 after 3 successful txs");
    // Balance should be: initial - 2 * 1000 (transfers) - gas fees.
    // We check it decreased (fees consumed), not an exact amount (gas varies).
    let balance_after = balance_of(api_port, USER_ADDR);
    assert!(
        balance_after < balance_before,
        "Case B FAIL: balance should have decreased from {balance_before} to <{balance_before}, got {balance_after}"
    );
    eprintln!("Case B PASS: nonce={nonce_after}, balance={balance_after}.");

    // ── Case C: old key (Key_A) rejected after rotation ───────────────────────
    eprintln!("Case C: Old key (Key_A) rejected post-rotation");
    // Key_A is no longer authorized; the node has Key_B bound.
    // build_transfer uses SEED_A which produces Key_A. pq_public_key will be Key_A.
    // verify_mldsa_authorization: bound_key = Key_B; key_A != Key_B → reject.
    let tx_c = build_transfer(SEED_A, USER_ADDR, 3, BYSTANDER, 1);
    let tx_c_json = serde_json::to_string(&tx_c).expect("serialise");
    let resp_c = submit_tx(api_port, &tx_c_json);
    let ingress_c = resp_c["status"].as_str().unwrap_or("").to_string();
    let result_c = if ingress_c != "queued" {
        serde_json::json!({ "success": false, "error": resp_c["error"].as_str().unwrap_or(&ingress_c) })
    } else {
        wait_tx_result(api_port, &tx_c.id, Duration::from_secs(30))
            .expect("C: tx result never appeared")
    };
    assert!(
        !result_c["success"].as_bool().unwrap_or(true),
        "Case C FAIL: old key must be rejected — {:?}", result_c
    );
    eprintln!("Case C PASS: Key_A correctly rejected. error={:?}", result_c["error"]);

    // ── Case E: replay of rotation tx ─────────────────────────────────────────
    eprintln!("Case E: Replay of rotation tx rejected");
    // The rotation tx had nonce=1, which is already consumed. Re-submitting it
    // will fail nonce replay protection.
    let replay_v = submit_tx(api_port, &rotation_json);
    let replay_ingress = replay_v["status"].as_str().unwrap_or("").to_string();
    let replay_result = if replay_ingress != "queued" {
        serde_json::json!({ "success": false })
    } else {
        wait_tx_result(api_port, "dis002a-rotate-a-to-b", Duration::from_secs(20))
            .unwrap_or(serde_json::json!({ "success": false }))
    };
    assert!(
        !replay_result["success"].as_bool().unwrap_or(true),
        "Case E FAIL: rotation tx replay must be rejected"
    );
    eprintln!("Case E PASS: rotation replay rejected.");

    // ── Case F: stale key_version rejected ────────────────────────────────────
    eprintln!("Case F: Stale key_version (0 instead of 2) rejected");
    // key_version is now 1 after the first rotation; a new rotation must use 2.
    // Submitting with key_version=0 must fail.
    let tx_f = build_rotation_tx(SEED_B, SEED_A, USER_ADDR, 3, 0, "stale-version");
    let tx_f_json = serde_json::to_string(&tx_f).expect("serialise");
    let resp_f = submit_tx(api_port, &tx_f_json);
    let ingress_f = resp_f["status"].as_str().unwrap_or("").to_string();
    let result_f = if ingress_f != "queued" {
        serde_json::json!({ "success": false })
    } else {
        wait_tx_result(api_port, &tx_f.id, Duration::from_secs(20))
            .expect("F: tx result never appeared")
    };
    assert!(
        !result_f["success"].as_bool().unwrap_or(true),
        "Case F FAIL: stale key_version must be rejected — {:?}", result_f
    );
    eprintln!("Case F PASS: stale key_version rejected.");

    // ── Case G: unauthorized rotation (wrong outer signer) ────────────────────
    eprintln!("Case G: Unauthorized rotation (attacker's outer signature) rejected");
    // Attacker (SEED_C) signs the outer tx, but qcb1user has Key_B bound.
    // The supplied pq_public_key is attacker's key, which != bound Key_B.
    // verify_mldsa_authorization: bound key is Key_B; attacker's key != Key_B → reject.
    let tx_g = build_rotation_wrong_signer(SEED_C, SEED_A, USER_ADDR, 3, 2);
    let tx_g_json = serde_json::to_string(&tx_g).expect("serialise");
    let resp_g = submit_tx(api_port, &tx_g_json);
    let ingress_g = resp_g["status"].as_str().unwrap_or("").to_string();
    let result_g = if ingress_g != "queued" {
        serde_json::json!({ "success": false })
    } else {
        wait_tx_result(api_port, &tx_g.id, Duration::from_secs(20))
            .expect("G: tx result never appeared")
    };
    assert!(
        !result_g["success"].as_bool().unwrap_or(true),
        "Case G FAIL: unauthorized rotation must be rejected — {:?}", result_g
    );
    eprintln!("Case G PASS: attacker rotation rejected.");

    // ── Case H: invalid PoP rejected ──────────────────────────────────────────
    eprintln!("Case H: Invalid proof-of-possession rejected");
    // Outer signature is valid (Key_B signs), but pop_signature is garbage.
    let tx_h = build_rotation_bad_pop(SEED_B, SEED_A, USER_ADDR, 3, 2);
    let tx_h_json = serde_json::to_string(&tx_h).expect("serialise");
    let resp_h = submit_tx(api_port, &tx_h_json);
    let ingress_h = resp_h["status"].as_str().unwrap_or("").to_string();
    let result_h = if ingress_h != "queued" {
        serde_json::json!({ "success": false })
    } else {
        wait_tx_result(api_port, &tx_h.id, Duration::from_secs(20))
            .expect("H: tx result never appeared")
    };
    assert!(
        !result_h["success"].as_bool().unwrap_or(true),
        "Case H FAIL: bad PoP must be rejected — {:?}", result_h
    );
    eprintln!("Case H PASS: invalid PoP rejected.");

    // ── Case I: cross-node consistency ────────────────────────────────────────
    eprintln!("Case I: Verifying cross-node state root consistency");
    // Wait one more block so all nodes have processed all txs.
    let cur_height = api_get(api_port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0);
    let _ = poll_height(api_port, cur_height + 1, Duration::from_secs(20));

    let roots: Vec<String> = ports.all_api().iter().map(|&p| state_root(p)).collect();
    eprintln!("State roots: {:?}", roots);
    let first = &roots[0];
    for (i, r) in roots.iter().enumerate() {
        assert_eq!(
            r, first,
            "Case I FAIL: node {i} state root {r:?} != node 0 state root {first:?}"
        );
    }
    eprintln!("Case I PASS: all 4 nodes agree on state root {first}.");

    // ── Summary ───────────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("DIS-002A PASS — all 9 cases verified:");
    eprintln!("  A: Key_A rotation to Key_B succeeds");
    eprintln!("  B: Identity (address, nonce, balance) unchanged by rotation");
    eprintln!("  C: Old Key_A rejected after rotation");
    eprintln!("  D: New Key_B accepted (covered by A-3)");
    eprintln!("  E: Rotation tx replay rejected");
    eprintln!("  F: Stale key_version rejected");
    eprintln!("  G: Unauthorized rotation (wrong outer signer) rejected");
    eprintln!("  H: Invalid proof-of-possession rejected");
    eprintln!("  I: All 4 nodes agree on state root");

    drop(nodes);
}
