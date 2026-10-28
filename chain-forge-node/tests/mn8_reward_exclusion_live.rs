//! MN-8 — Reward exclusion after personhood revocation, multi-node.
//!
//! A post-genesis validator (Eve) is admitted through the real protocol path,
//! runs her own voting node, and earns an exact epoch-reward share. Her
//! personhood is then revoked and the next epoch close pays her nothing while
//! the genesis validators split the pool exactly. Every value is read from all
//! five nodes and must agree.
//!
//!   MN8-1  Eve becomes Verified (RegisterIdentity + three Attest), bonds, and
//!          registers her consensus key with a real proof of possession.
//!   MN8-2  At the next epoch boundary every node seats Eve with voting power,
//!          pop_verified and her registered key.
//!   MN8-3  Eve's node restarts with her key (a node can only load a signing
//!          key for an address already in its validator set) and votes.
//!   MN8-4  Positive control: after a full epoch of participation, the closing
//!          block pays each of the five validators exactly pool / 5; the
//!          remainder stays in the pool.
//!   MN8-5  Alice revokes her attestation: Eve drops to Provisional. The next
//!          close pays Eve nothing and each genesis validator exactly
//!          pool / 4; Eve loses voting power on every node.
//!   MN8-6  All five nodes agree on the state root at a pinned height.
//!
//! ## Genesis
//!
//! `tests/devnet/genesis-mn8.json`: the fee-settle genesis (personhood-weighted,
//! unsigned txs allowed except key registration) with a 10-block epoch and
//! Eve's wallet key bound. Ports 18380-18384 / 27300-27304.
//!
//! ## Run (Windows/MINGW64)
//!
//! ```
//! cargo build -p chain-forge-node && \
//! cargo test -p chain-forge-node --test mn8_reward_exclusion_live -- --nocapture
//! ```

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
use chain_forge_execution::{validator_key_registration_signing_bytes, Transaction, TxBody};

// ── Constants ─────────────────────────────────────────────────────────────────

const CHAIN_ID: &str = "qcb-devnet-mn8";
const DENOM:    &str = "uqcb";
const EVE:      &str = "qcb1eve";
const USER:     &str = "qcb1user1";
const POOL:     &str = "treasury:validator-pool";
/// Node order: four genesis validators, then Eve.
const NAMES:     &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave", "qcb1eve"];
const API_PORTS: &[u16] = &[18380, 18381, 18382, 18383, 18384];
const P2P_PORTS: &[u16] = &[27300, 27301, 27302, 27303, 27304];
const EPOCH: u64 = 10; // genesis validator_bonding.validator_epoch_blocks
const EVE_BOND_UQCB: u128 = 2_000_000;
const TIMEOUT_SECS: u64 = 120;

// ── Paths ─────────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn node_binary() -> PathBuf {
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
        _                => debug,
    }
}

fn genesis_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("devnet").join("genesis-mn8.json")
}

fn key_path(short_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests").join("devnet").join("keys")
        .join(format!("{short_name}.key.json"))
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

fn port_is_free(port: u16) -> bool {
    TcpStream::connect(format!("127.0.0.1:{port}")).is_err()
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() { return true; }
        if Instant::now() >= deadline { return false; }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn http(port: u16, request: String, body: &[u8]) -> Option<serde_json::Value> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(2_000))).ok()?;
    stream.write_all(request.as_bytes()).ok()?;
    stream.write_all(body).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1)?).ok()
}

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    http(port, format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"), &[])
}

fn api_post_tx(port: u16, tx_json: &str) -> Option<serde_json::Value> {
    let body = tx_json.as_bytes();
    http(port, format!(
        "POST /api/tx HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()), body)
}

fn height_of(port: u16) -> u64 {
    api_get(port, "/api/status").and_then(|v| v["height"].as_u64()).unwrap_or(0)
}

fn max_height(ports: &[u16]) -> u64 {
    ports.iter().map(|&p| height_of(p)).max().unwrap_or(0)
}

fn balance_of(port: u16, addr: &str) -> u128 {
    api_get(port, &format!("/api/accounts/{addr}"))
        .and_then(|v| {
            v["balances"][DENOM].as_str().and_then(|s| s.parse::<u128>().ok())
                .or_else(|| v["balances"][DENOM].as_u64().map(u128::from))
        })
        .unwrap_or(0)
}

fn account_nonce(port: u16, addr: &str) -> u64 {
    api_get(port, &format!("/api/accounts/{addr}")).and_then(|v| v["nonce"].as_u64()).unwrap_or(0)
}

fn identity_of(port: u16, addr: &str) -> serde_json::Value {
    api_get(port, &format!("/api/identity/{addr}")).unwrap_or(serde_json::Value::Null)
}

/// (voting_power, pop_verified, consensus_pubkey) of `addr` in /api/validators.
fn validator_of(port: u16, addr: &str) -> Option<(u64, bool, String)> {
    let vs: Vec<serde_json::Value> = serde_json::from_value(api_get(port, "/api/validators")?).ok()?;
    let v = vs.into_iter().find(|v| v["id"].as_str() == Some(addr))?;
    Some((
        v["voting_power"].as_u64().unwrap_or(0),
        v["pop_verified"].as_bool().unwrap_or(false),
        v["consensus_pubkey"].as_str().unwrap_or("").to_string(),
    ))
}

fn block_root(port: u16, height: u64) -> Option<String> {
    api_get(port, &format!("/api/blocks/{height}"))
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
}

/// Read a value from every node; all must agree. Returns it.
fn agreed_on<T: PartialEq + std::fmt::Debug + Clone>(ports: &[u16], what: &str, read: impl Fn(u16) -> T) -> T {
    let vals: Vec<T> = ports.iter().map(|&p| read(p)).collect();
    for (i, v) in vals.iter().enumerate().skip(1) {
        assert_eq!(v, &vals[0], "{what} differs on {}: {vals:?}", NAMES[i]);
    }
    vals[0].clone()
}

fn wait_for_height(ports: &[u16], target: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let heights: Vec<u64> = ports.iter().map(|&p| height_of(p)).collect();
        print!("\r   waiting for height {target}: {heights:?}  ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        if heights.iter().all(|&h| h >= target) { println!(); return; }
        assert!(Instant::now() < deadline, "height {target} not reached within {timeout:?}; heights={heights:?}");
        std::thread::sleep(Duration::from_millis(300));
    }
}

// ── Transactions ──────────────────────────────────────────────────────────────

fn submit(port: u16, tx: &Transaction) {
    let resp = api_post_tx(port, &serde_json::to_string(tx).unwrap())
        .unwrap_or_else(|| panic!("POST /api/tx for {} failed (network)", tx.id));
    let st = resp["status"].as_str().unwrap_or("unknown");
    assert!(st == "queued" || st == "ok", "{} rejected at ingress: {resp}", tx.id);
}

/// Wait until tx `id` is committed on every node with success and an
/// identical outcome everywhere. Returns its events.
fn confirm_success(ports: &[u16], id: &str, timeout: Duration) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    let outcomes: Vec<serde_json::Value> = loop {
        let seen: Vec<Option<serde_json::Value>> = ports.iter()
            .map(|&p| api_get(p, &format!("/api/tx/{id}")).filter(|v| v["id"] == id))
            .collect();
        if seen.iter().all(Option::is_some) { break seen.into_iter().map(Option::unwrap).collect(); }
        assert!(Instant::now() < deadline, "tx {id} not committed on every node: {seen:?}");
        std::thread::sleep(Duration::from_millis(300));
    };
    for (i, o) in outcomes.iter().enumerate() {
        assert_eq!(o["success"], true, "tx {id} failed on {}: {}", NAMES[i], o["error"]);
        assert_eq!(o, &outcomes[0], "tx {id} outcome differs on {}", NAMES[i]);
    }
    outcomes[0]["events"].as_array().into_iter().flatten()
        .filter_map(|e| e.as_str().map(str::to_string)).collect()
}

fn unsigned(id: String, sender: &str, nonce: u64, body: TxBody) -> Transaction {
    Transaction {
        id, sender: sender.into(), nonce, body, gas_limit: 200_000,
        signature: vec![], public_key: vec![], pq_signatures: vec![],
        sig_scheme: None, pq_public_key: vec![],
    }
}

// ── Nodes ─────────────────────────────────────────────────────────────────────

struct NodeProc {
    child:    Child,
    log_path: PathBuf,
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn node `idx`. `validator` = (address, key file); `None` runs an observer.
fn spawn(
    bin: &PathBuf, genesis: &PathBuf, log_dir: &PathBuf, idx: usize,
    validator: Option<(&str, PathBuf)>, data_dir: &PathBuf, bootstraps: &[String],
) -> NodeProc {
    let log_path = log_dir.join(format!("{}.log", NAMES[idx]));
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)
        .unwrap_or_else(|e| panic!("log open failed {log_path:?}: {e}"));
    let mut cmd = Command::new(bin);
    cmd.args([
        "--genesis",  genesis.to_str().unwrap(),
        "--api-port", &API_PORTS[idx].to_string(),
        "--p2p-port", &P2P_PORTS[idx].to_string(),
        "--data-dir", data_dir.to_str().unwrap(),
    ]);
    if let Some((addr, key)) = validator {
        cmd.args(["--validator", addr, "--key-file", key.to_str().unwrap()]);
    }
    for b in bootstraps { cmd.args(["--bootstrap", b]); }
    cmd.stdout(log_file.try_clone().unwrap()).stderr(log_file).stdin(Stdio::null());
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {} failed: {e}", NAMES[idx]));
    assert!(wait_for_port(API_PORTS[idx], Duration::from_secs(20)),
        "{} API port :{} never opened", NAMES[idx], API_PORTS[idx]);
    println!("   {} up on :{}", NAMES[idx], API_PORTS[idx]);
    NodeProc { child, log_path }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for nc in chars.by_ref() { if nc == 'm' { break; } }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Wait until `needle` appears in the (ANSI-stripped) log; returns the line.
fn wait_for_log(log_path: &PathBuf, needle: &str, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(content) = std::fs::read_to_string(log_path) {
            if let Some(line) = content.lines().map(strip_ansi).find(|l| l.contains(needle)) {
                return Some(line);
            }
        }
        if Instant::now() >= deadline { return None; }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read_peer_id(log_path: &PathBuf) -> String {
    let line = wait_for_log(log_path, "local_peer_id=", Duration::from_secs(15))
        .unwrap_or_else(|| panic!("peer ID never appeared in log {log_path:?}"));
    let after = &line[line.find("local_peer_id=").unwrap() + "local_peer_id=".len()..];
    after.chars().take_while(|c| !c.is_whitespace()).collect()
}

fn print_tail(log_path: &PathBuf, lines: usize) {
    if let Ok(content) = std::fs::read_to_string(log_path) {
        let all: Vec<_> = content.lines().collect();
        println!("── tail of {log_path:?} ──");
        for line in &all[all.len().saturating_sub(lines)..] { println!("{}", strip_ansi(line)); }
    }
}

// ── Epoch-close measurement ───────────────────────────────────────────────────

struct Close {
    height:     u64,
    pool:       u128,
    gains:      Vec<u128>,
    pool_after: u128,
}

/// Measure the next epoch close that `setup` fully precedes. Waits for the
/// second block of the next epoch, runs `setup` (which may commit txs), then
/// snapshots the pool and every payee's balance on all nodes. The snapshot
/// must predate the close: no txs are submitted between it and the close, so
/// the only balance changes across the closing block are the reward sweep.
fn measure_close(
    ports: &[u16], payees: &[&str], timeout: Duration, label: &str, setup: impl FnOnce(),
) -> Close {
    let start = (max_height(ports) / EPOCH + 1) * EPOCH + 1;
    wait_for_height(ports, start, timeout);
    let close = (start / EPOCH + 1) * EPOCH;
    setup();

    let snapshot = || -> (u128, Vec<u128>) {
        let pool = agreed_on(ports, &format!("{label}: pool"), |p| balance_of(p, POOL));
        let bals = payees.iter()
            .map(|a| agreed_on(ports, &format!("{label}: {a} balance"), |p| balance_of(p, a)))
            .collect();
        (pool, bals)
    };
    let (pool, before) = snapshot();
    let h = max_height(ports);
    assert!(h < close,
        "{label}: setup ran past the epoch close at height {close} (now {h}); \
         the snapshot would not isolate the reward sweep");

    wait_for_height(ports, close + 1, timeout);
    let (pool_after, after) = snapshot();
    let gains = after.iter().zip(&before).enumerate()
        .map(|(i, (a, b))| a.checked_sub(*b)
            .unwrap_or_else(|| panic!("{label}: {} lost funds across the close ({b} -> {a})", payees[i])))
        .collect();
    Close { height: close, pool, gains, pool_after }
}

// ── Main test ─────────────────────────────────────────────────────────────────

#[test]
fn mn8_revoked_validator_is_excluded_from_epoch_rewards() {
    let bin = node_binary();
    assert!(bin.exists(),
        "HARD FAIL: node binary not found at {bin:?}. Run `cargo build -p chain-forge-node` first.");
    let genesis = genesis_path();
    for name in ["alice", "bob", "carol", "dave"] {
        assert!(key_path(name).exists(), "key file not found: {:?}", key_path(name));
    }
    for port in API_PORTS.iter().chain(P2P_PORTS.iter()) {
        assert!(port_is_free(*port), "port {port} is in use — kill stray processes first");
    }

    // Eve's wallet key must be the one genesis binds to her account (her
    // RegisterValidatorKey is always signature-checked).
    let wallet = ClassicalScheme.generate_keypair(EVE).unwrap();
    let genesis_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&genesis).unwrap()).unwrap();
    let bound = genesis_json["genesis_accounts"].as_array().unwrap().iter()
        .find(|a| a["address"] == EVE).unwrap()["public_key"].as_str().unwrap().to_string();
    assert_eq!(hex::encode(&wallet.public_key), bound,
        "genesis-mn8.json must bind Eve's wallet key (generate_keypair(\"{EVE}\"))");
    let consensus = ClassicalScheme.generate_keypair("qcb1eve-consensus").unwrap();
    let consensus_hex = hex::encode(&consensus.public_key);

    let timeout  = Duration::from_secs(TIMEOUT_SECS);
    let log_dir  = std::env::temp_dir().join("qcb-mn8-test");
    let data_root = std::env::temp_dir().join("qcb-mn8-data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&data_root);
    std::fs::create_dir_all(&log_dir).unwrap();
    let data_dirs: Vec<PathBuf> = NAMES.iter().map(|n| data_root.join(n)).collect();
    for d in &data_dirs { std::fs::create_dir_all(d).unwrap(); }
    let eve_key = log_dir.join("eve.key.json");
    std::fs::write(&eve_key, serde_json::json!({
        "address": EVE,
        "private_key": hex::encode(&consensus.private_key),
        "public_key": consensus_hex,
        "scheme": "classical-ed25519",
    }).to_string()).unwrap();
    let run = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);
    let ports: Vec<u16> = API_PORTS.to_vec();
    let genesis_ports = &ports[..4];

    println!("\n── MN-8 reward exclusion after personhood revocation (5 nodes) ─────");
    println!("   logs: {log_dir:?}");

    // ── Boot: four validators + Eve as an observer ────────────────────────────
    let key_of = |i: usize| Some((NAMES[i], key_path(NAMES[i].strip_prefix("qcb1").unwrap())));
    let mut nodes = vec![spawn(&bin, &genesis, &log_dir, 0, key_of(0), &data_dirs[0], &[])];
    let bootstrap = vec![format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", P2P_PORTS[0], read_peer_id(&nodes[0].log_path))];
    for i in 1..4 {
        nodes.push(spawn(&bin, &genesis, &log_dir, i, key_of(i), &data_dirs[i], &bootstrap));
    }
    let mut eve_node = spawn(&bin, &genesis, &log_dir, 4, None, &data_dirs[4], &bootstrap);
    wait_for_height(&ports, 2, timeout);

    // ── MN8-1: Eve becomes Verified, bonds, registers her consensus key ──────
    println!("── MN8-1: identity, bond, consensus key ──");
    let eve_nonce = account_nonce(ports[0], EVE);
    let mut reg = Transaction::register_identity(&format!("mn8-reg-{run}"), EVE, eve_nonce);
    reg.sign(&wallet, CHAIN_ID).unwrap();
    submit(ports[0], &reg);
    confirm_success(&ports, &reg.id, timeout);

    let atts: Vec<Transaction> = ["qcb1alice", "qcb1bob", "qcb1carol"].iter()
        .map(|a| Transaction::attest(&format!("mn8-att-{a}-{run}"), a, EVE, account_nonce(ports[0], a)))
        .collect();
    for t in &atts { submit(ports[0], t); }
    for t in &atts { confirm_success(&ports, &t.id, timeout); }
    assert_eq!(agreed_on(&ports, "eve tier", |p| identity_of(p, EVE)["tier"].as_str().map(str::to_string)).as_deref(),
        Some("Verified"), "MN8-1: Eve must be Verified after three attestations");

    let mut bond = unsigned(format!("mn8-bond-{run}"), EVE, eve_nonce + 1,
        // The owner binding ties the seat to Eve's personhood; without it a
        // post-genesis validator is fail-closed to zero power.
        TxBody::BondValidator { amount: EVE_BOND_UQCB, owner_identity_id: Some(EVE.into()) });
    bond.sign(&wallet, CHAIN_ID).unwrap();
    submit(ports[0], &bond);
    confirm_success(&ports, &bond.id, timeout);

    let pop = ClassicalScheme.sign(&validator_key_registration_signing_bytes(CHAIN_ID, EVE), &consensus).unwrap();
    let mut regkey = unsigned(format!("mn8-regkey-{run}"), EVE, eve_nonce + 2, TxBody::RegisterValidatorKey {
        consensus_pubkey: consensus.public_key.clone(),
        proof_of_possession: pop.bytes,
        scheme: String::new(),
        pop_version: 1,
    });
    regkey.sign(&wallet, CHAIN_ID).unwrap();
    submit(ports[0], &regkey);
    let events = confirm_success(&ports, &regkey.id, timeout);
    assert!(events.iter().any(|e| e.contains(&consensus_hex)), "MN8-1: key event missing: {events:?}");
    println!("   MN8-1 PASS — Eve Verified, bonded {EVE_BOND_UQCB}, key {consensus_hex}");

    // ── MN8-2: seated at the next epoch boundary ─────────────────────────────
    let boundary = (max_height(&ports) / EPOCH + 1) * EPOCH;
    wait_for_height(&ports, boundary + 1, timeout);
    let (power, pop_ok, key) = agreed_on(genesis_ports, "eve validator entry", |p| validator_of(p, EVE))
        .expect("MN8-2: Eve not in /api/validators after the epoch boundary");
    assert!(power > 0 && pop_ok && key == consensus_hex,
        "MN8-2: Eve must be seated with power, pop_verified and her key: ({power}, {pop_ok}, {key})");
    println!("   MN8-2 PASS — Eve seated at height {boundary}: power={power}");

    // ── MN8-3: Eve's node restarts as a voting validator ─────────────────────
    drop(eve_node);
    std::thread::sleep(Duration::from_secs(1));
    eve_node = spawn(&bin, &genesis, &log_dir, 4, Some((EVE, eve_key.clone())), &data_dirs[4], &bootstrap);
    if wait_for_log(&eve_node.log_path, "validator signing key loaded", Duration::from_secs(20)).is_none() {
        print_tail(&eve_node.log_path, 40);
        panic!("MN8-3: Eve's node did not load her signing key");
    }
    let voting_from = max_height(&ports) + 2;
    wait_for_height(&ports, voting_from, timeout);
    println!("   MN8-3 PASS — Eve voting from about height {voting_from}");

    // ── MN8-4: positive control — Eve earns an exact share ───────────────────
    // Skip to the first epoch Eve participates in fully, then measure its close.
    let full_epoch_start = (voting_from / EPOCH + 1) * EPOCH;
    wait_for_height(&ports, full_epoch_start, timeout);
    let five: Vec<&str> = NAMES.to_vec();
    let fee_tx = unsigned(format!("mn8-fee-{run}"), USER, account_nonce(ports[0], USER),
        TxBody::Transfer { to: "qcb1sink".into(), denom: DENOM.into(), amount: 1_000 });
    let c = measure_close(&ports, &five, timeout, "MN8-4", || {
        submit(ports[0], &fee_tx);
        confirm_success(&ports, &fee_tx.id, timeout);
    });
    let share = c.pool / 5;
    println!("   close@{}: pool={} gains={:?}", c.height, c.pool, c.gains);
    assert!(share > 0, "MN8-4: pool {} too small to measure", c.pool);
    if c.gains != vec![share; 5] {
        print_tail(&eve_node.log_path, 40);
        panic!("MN8-4 FAILED: every validator, Eve included, must earn exactly pool/5 = {share}; gains={:?}", c.gains);
    }
    assert_eq!(c.pool_after, c.pool - 5 * share, "MN8-4: remainder must stay in the pool");
    println!("   MN8-4 PASS — five validators each earned exactly {share}");

    // ── MN8-5: revoke Eve's personhood — excluded at the next close ──────────
    let revoke = unsigned(format!("mn8-revoke-{run}"), "qcb1alice", account_nonce(ports[0], "qcb1alice"),
        TxBody::RevokeAttestation { attested_id: EVE.into() });
    let fee_tx2 = unsigned(format!("mn8-fee2-{run}"), USER, account_nonce(ports[0], USER),
        TxBody::Transfer { to: "qcb1sink".into(), denom: DENOM.into(), amount: 1_000 });
    let c = measure_close(&ports, &five, timeout, "MN8-5", || {
        submit(ports[0], &revoke);
        submit(ports[0], &fee_tx2);
        confirm_success(&ports, &revoke.id, timeout);
        confirm_success(&ports, &fee_tx2.id, timeout);
        assert_eq!(
            agreed_on(&ports, "eve tier", |p| identity_of(p, EVE)["tier"].as_str().map(str::to_string)).as_deref(),
            Some("Provisional"), "MN8-5: Eve must drop to Provisional");
    });
    let share = c.pool / 4;
    println!("   close@{}: pool={} gains={:?}", c.height, c.pool, c.gains);
    assert!(share > 0, "MN8-5: pool {} too small to measure", c.pool);
    assert_eq!(c.gains[4], 0, "MN8-5 FAILED: Eve must earn nothing after revocation");
    assert_eq!(c.gains[..4], vec![share; 4],
        "MN8-5 FAILED: each genesis validator must earn exactly pool/4 = {share}");
    assert_eq!(c.pool_after, c.pool - 4 * share, "MN8-5: remainder must stay in the pool");
    let (power, pop_ok, _) = agreed_on(genesis_ports, "eve validator entry", |p| validator_of(p, EVE))
        .unwrap_or((0, false, String::new()));
    assert!(power == 0 && !pop_ok, "MN8-5: Eve must lose voting power: power={power} pop_verified={pop_ok}");
    println!("   MN8-5 PASS — Eve excluded; genesis validators each earned exactly {share}");

    // ── MN8-6: all five nodes agree on a pinned root ─────────────────────────
    let pin = max_height(&ports) + 1;
    wait_for_height(&ports, pin, timeout);
    let root = agreed_on(&ports, &format!("state root at height {pin}"), |p| block_root(p, pin));
    assert!(root.is_some(), "MN8-6: no state root recorded for height {pin}");
    println!("   MN8-6 PASS — root@{pin}={}", root.unwrap());

    if std::env::var("MN8_PRINT_LOGS").is_ok() {
        for n in nodes.iter().chain(std::iter::once(&eve_node)) { print_tail(&n.log_path, 20); }
    }
    println!("\n   MN-8 live: MN8-1..MN8-6 passed");
}
