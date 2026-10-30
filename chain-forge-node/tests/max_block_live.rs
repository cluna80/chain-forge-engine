//! Maximum-size transactions vs. block size, mempool, execution and gossip.
//!
//! A 4-node devnet (DIS-003D genesis: `max_tx_bytes` 262144, `max_block_bytes`
//! 1048576) receives a burst of maximum-size ML-DSA recovery transactions
//! (10 guardians, ~221 KB each): one valid recovery followed by copies that
//! fail at execution. Together they are far more than one block can hold.
//!
//! Before the block-size fix every proposal carried the whole mempool. A
//! proposal's tx bytes are re-encoded as a JSON number array (~3.6x), so this
//! burst made the proposal larger than the 16 MB gossip limit: no validator
//! received it and the chain stopped finalizing.
//!
//! | ID   | Check |
//! |------|-------|
//! | M-01 | Every tx in the burst gets a committed result (success or error) |
//! | M-02 | The valid 10-guardian recovery succeeds |
//! | M-03 | The burst is spread over several blocks, none above max_block_bytes worth of txs |
//! | M-04 | All 4 nodes agree on every block hash and on the final state root |
//! | M-05 | The chain keeps finalizing after the burst |
//!
//! ## Run
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test max_block_live -- --nocapture
//! CF_CONSENSUS_KEYS=mldsa cargo test -p chain-forge-node --test max_block_live -- --nocapture
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

use chain_forge_crypto::{MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash};
use chain_forge_execution::{
    Transaction, TxBody, GuardianAuth,
    account_key_rotation_signing_bytes,
    recovery_domain_signing_bytes,
};

#[path = "common/consensus_keys.rs"]
mod consensus_keys;

const CHAIN_ID:   &str = "qcb-devnet-dis003d";
const PILOT_ADDR: &str = "qcb1pilot";
const SEED_PILOT: &str = "dis003d-pilot-device-seed-000000000000000000000000001";
const GUARDIANS:  usize = 10;
/// Copies after the valid recovery. 25 x ~221 KB is ~5.5 MB of txs: about
/// six blocks' worth, and a ~20 MB proposal if put in one block.
const COPIES:     usize = 24;

fn guardian_seed(i: usize) -> String { format!("max-block-guardian-{i:02}-seed-0000000000000000000000") }

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
    consensus_keys::genesis(&manifest_dir().join("tests").join("devnet").join("genesis-dis003d.json"))
}

fn key_file(label: &str) -> PathBuf {
    consensus_keys::validator_key(label, manifest_dir().join("tests").join("devnet").join("keys")
        .join(format!("{label}.key.json")))
}

fn devnet_dirs() -> PathBuf {
    std::env::temp_dir().join(format!("max_block_live_{}", std::process::id()))
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

/// Build a recovery tx where all guardians sign with `expires_at_height`.
fn build_recover(
    new_seed:    &str,
    sender:      &str,
    nonce:       u64,
    key_version: u32,
    guardian_seeds:    &[&str],
    expires_per_guardian: &[Option<u64>],  // same length as guardian_seeds
    policy_id:   u64,
    tx_id:       &str,
) -> Transaction {
    assert_eq!(guardian_seeds.len(), expires_per_guardian.len(),
        "guardian_seeds and expires_per_guardian must have equal length");

    let new_kp  = MlDsaScheme.generate_keypair(new_seed).expect("new keygen");
    let pop_msg = account_key_rotation_signing_bytes(CHAIN_ID, sender, key_version, &new_kp.public_key);
    let pop_sig = MlDsaScheme.sign(&pop_msg, &new_kp).expect("PoP sign");

    let guardian_signatures: Vec<GuardianAuth> = guardian_seeds.iter()
        .zip(expires_per_guardian.iter())
        .map(|(&gs, &exp)| {
            let gkp     = MlDsaScheme.generate_keypair(gs).expect("guardian keygen");
            let rec_msg = recovery_domain_signing_bytes(
                CHAIN_ID, sender, key_version, &new_kp.public_key, policy_id, exp,
            );
            let sig = MlDsaScheme.sign(&rec_msg, &gkp).expect("guardian sign");
            GuardianAuth {
                guardian_public_key: gkp.public_key.clone(),
                signature:           sig.bytes.clone(),
                expires_at_height:   exp,
            }
        }).collect();

    let kp_sender = MlDsaScheme.generate_keypair(SEED_PILOT).expect("sender keygen");
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

fn tx_json(tx: &Transaction) -> String { serde_json::to_string(tx).expect("tx json") }

fn block(port: u16, h: u64) -> Option<serde_json::Value> { api_get(port, &format!("/api/blocks/{h}")) }

#[test]
fn max_size_recoveries_spread_over_blocks_and_finalize() {
    let _ = std::fs::remove_dir_all(devnet_dirs());
    let ports = Ports::new();
    let _nodes = spawn_devnet(&ports);
    let port = ports.alice;
    for p in ports.all() {
        assert!(poll_ready(p, Duration::from_secs(30)), "node on :{p} not ready");
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while current_height(port) < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(300));
    }

    // Enroll a 10-of-10 recovery policy.
    let seeds: Vec<String> = (0..GUARDIANS).map(guardian_seed).collect();
    let guardian_pks: Vec<Vec<u8>> = seeds.iter()
        .map(|s| MlDsaScheme.generate_keypair(s).expect("guardian keygen").public_key)
        .collect();
    let enroll = build_enroll(SEED_PILOT, PILOT_ADDR, current_nonce(port, PILOT_ADDR),
        guardian_pks, GUARDIANS as u32, "max-enroll");
    submit_tx(port, &tx_json(&enroll));
    let r = wait_tx_result(port, "max-enroll", Duration::from_secs(30)).expect("enroll result");
    assert!(r["success"].as_bool().unwrap_or(false), "enroll must succeed: {r}");
    let acct = account_of(port, PILOT_ADDR).expect("pilot account");
    let policy_id = acct["policy_generation"].as_u64().unwrap_or(0);
    let kv = acct["key_version"].as_u64().unwrap_or(0) as u32;

    // The valid recovery, then copies with later nonces.
    let nonce = current_nonce(port, PILOT_ADDR);
    let seed_refs: Vec<&str> = seeds.iter().map(String::as_str).collect();
    let expiry = vec![None; GUARDIANS];
    let base = build_recover("max-block-new-key-seed-00000000000000000000000001",
        PILOT_ADDR, nonce, kv + 1, &seed_refs, &expiry, policy_id, "max-rec-0");
    let size = tx_json(&base).len();
    println!("10-guardian recovery tx: {size} bytes");
    assert!(size > 200_000, "expected a maximum-size recovery, got {size} bytes");

    let h_start = current_height(port);
    let ids: Vec<String> = (0..=COPIES).map(|i| format!("max-rec-{i}")).collect();
    for (i, id) in ids.iter().enumerate() {
        let mut tx = base.clone();
        tx.id = id.clone();
        tx.nonce = nonce + i as u64;
        let resp = submit_tx(port, &tx_json(&tx));
        assert_eq!(resp["status"], "queued", "{id} must be admitted: {resp}");
    }
    println!("submitted {} txs (~{:.1} MB) at height {h_start}", ids.len(), (size * ids.len()) as f64 / 1e6);

    // M-01 / M-02
    let mut last_height = 0;
    for id in &ids {
        let r = wait_tx_result(port, id, Duration::from_secs(180))
            .unwrap_or_else(|| panic!("M-01: {id} never committed (chain stalled?) at height {}", current_height(port)));
        last_height = last_height.max(r["height"].as_u64().unwrap_or(0));
        if id == "max-rec-0" {
            assert!(r["success"].as_bool().unwrap_or(false), "M-02: the valid recovery must succeed: {r}");
        }
    }
    println!("✓ M-01/M-02: all {} txs committed by height {last_height}", ids.len());

    // M-03: several blocks, none holding more tx bytes than max_block_bytes.
    let max_block_bytes = 1_048_576usize;
    let mut blocks_used = 0;
    for h in h_start..=last_height {
        let b = block(port, h).unwrap_or_else(|| panic!("block {h} missing"));
        let n = b["tx_count"].as_u64().unwrap_or(0) as usize;
        if n > 0 { blocks_used += 1; }
        assert!(n * size <= max_block_bytes, "M-03: block {h} holds {n} txs of {size} bytes");
    }
    assert!(blocks_used >= 2, "M-03: the burst must be spread over several blocks, used {blocks_used}");
    println!("✓ M-03: burst spread over {blocks_used} blocks");

    // M-05: the chain keeps finalizing afterwards.
    let target = last_height + 3;
    let deadline = Instant::now() + Duration::from_secs(60);
    while ports.all().iter().any(|&p| current_height(p) < target) {
        assert!(Instant::now() < deadline, "M-05: not all nodes reached height {target}: {:?}",
            ports.all().map(current_height));
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("✓ M-05: all nodes reached height {target}");

    // M-04: identical blocks on every node.
    for h in h_start..=target {
        let hashes: Vec<String> = ports.all().iter()
            .map(|&p| block(p, h).and_then(|b| b["block_hash"].as_str().map(str::to_string)).unwrap_or_default())
            .collect();
        assert!(hashes.iter().all(|x| !x.is_empty() && *x == hashes[0]), "M-04: block {h} differs: {hashes:?}");
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let roots: Vec<String> = ports.all().iter().map(|&p| state_root(p)).collect();
        let heights: Vec<u64> = ports.all().iter().map(|&p| current_height(p)).collect();
        if heights.iter().all(|&h| h == heights[0]) && roots.iter().all(|r| !r.is_empty() && *r == roots[0]) {
            break;
        }
        assert!(Instant::now() < deadline, "M-04: state roots differ: {roots:?} at {heights:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("✓ M-04: all 4 nodes agree on blocks {h_start}..={target} and the state root");
    let _ = std::fs::remove_dir_all(devnet_dirs());
}
