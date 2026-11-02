//! H0-7 — Supply conservation and fee accounting (Phase 0.5 acceptance test).
//!
//! Verifies that every block preserves the fundamental supply invariants:
//!
//!   S_h+1 = S_h + M_h - B_h
//!
//! where M_h is authorized issuance and B_h is total authorized burning at
//! height h.  Fee redistribution is a transfer — not issuance — so it must not
//! change total supply.  The fee-allocation invariant is:
//!
//!   F_h = V_h + T_h + B_fee,h
//!
//! where F_h is collected fees, V_h is the validator-pool allocation, T_h is
//! the treasury:network allocation, and B_fee,h is the fee-burn share.
//!
//! ## Accounting model (as-implemented)
//!
//! * Fees are debited from sender to `fee_collector` ("treasury:fees") per tx.
//! * At block close, `distribute_block_fees_from` splits *only that block's
//!   fees_collected* (not the collector's total balance) using BPS:
//!     - 7 000 BPS → treasury:validator-pool  (integer floor)
//!     - 2 000 BPS → treasury:network         (integer floor, + remainder)
//!     - 1 000 BPS → burned from treasury:fees (removes from supply)
//! * Remainder from floor division accrues to treasury:network (not validators).
//! * `state.burn()` debits the account balance permanently — no separate
//!   supply counter; total supply = Σ balances["uqcb"] across all accounts.
//! * A `TxBody::Burn` tx debits the *sender's* balance (BME mechanism).
//!
//! ## Acceptance criteria
//!
//! | Case | Invariant                                                              |
//! |------|------------------------------------------------------------------------|
//! | S-01 | Fee-bearing block: fees redistribute without creating or losing uqcb   |
//! |      | except for the explicit burn share, which reduces total supply exactly  |
//! | S-02 | Genesis-supply audit: sum of all account balances equals expected total |
//! | S-03 | Explicit Burn tx (BME): supply decreases by exactly the burned amount   |
//! | S-04 | Combined fee + burn: both invariants hold simultaneously               |
//! | S-05 | Four-node convergence and crash-restart persistence                     |
//! | S-06 | Arithmetic overflow / invalid burn rejected without partial state change|
//!
//! ## Ports
//!
//! API 18560-18563 / P2P 27500-27503 — clear of all other live tests.
//!
//! ## Run (Windows/MINGW64)
//!
//! ```
//! cargo build -p chain-forge-node && \
//! cargo test -p chain-forge-node --test h0_7_supply_conservation_live -- --nocapture
//! ```

#![allow(dead_code)]

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_execution::{FeeDistribution, Transaction, TxBody};

// ── Constants ──────────────────────────────────────────────────────────────────

const DENOM:     &str = "uqcb";
/// Sender for fee-bearing txs.  Funded at 10 000 000 uqcb in genesis.
const USER1:     &str = "qcb1user1";
/// A second funded account (for transfers).
const EVE:       &str = "qcb1eve";
/// Recipient for transfers — not funded in genesis (auto-created on receive).
const RECIPIENT: &str = "qcb1recipient7";

const VALIDATORS: &[&str] = &["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
const API_PORTS: &[u16]   = &[18560, 18561, 18562, 18563];
const P2P_PORTS: &[u16]   = &[27500, 27501, 27502, 27503];
const TIMEOUT_SECS: u64   = 120;

// Treasury addresses defined by the execution layer.
const FEE_COLLECTOR:    &str = "treasury:fees";
const VALIDATOR_POOL:   &str = "treasury:validator-pool";
const TREASURY_NETWORK: &str = "treasury:network";

// Expected genesis total supply (sum of all genesis_accounts balances).
// Validators: 4 × 500_000_000; user1: 10_000_000; eve: 20_000_000.
const GENESIS_TOTAL_SUPPLY: u128 = 4 * 500_000_000 + 10_000_000 + 20_000_000;

// ── Paths ──────────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().to_path_buf()
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

#[path = "common/consensus_keys.rs"]
mod consensus_keys;

fn genesis_path() -> PathBuf {
    // Reuse genesis-fee-settle.json: four validators, funded user1 and eve,
    // fee_distribution_bps 7000/2000/1000, require_signatures=false.
    consensus_keys::genesis(&PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests").join("devnet").join("genesis-fee-settle.json"))
}

fn key_path(short_name: &str) -> PathBuf {
    consensus_keys::validator_key(short_name, PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests").join("devnet").join("keys")
        .join(format!("{short_name}.key.json")))
}

// ── Network helpers ────────────────────────────────────────────────────────────

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

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(2_000))).ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1)?).ok()
}

fn api_post_tx(port: u16, tx_json: &str) -> Option<serde_json::Value> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(2_000))).ok()?;
    let body = tx_json.as_bytes();
    let req = format!(
        "POST /api/tx HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    stream.write_all(body).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1)?).ok()
}

fn height_of(port: u16) -> u64 {
    api_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

fn balance_of(port: u16, addr: &str) -> u128 {
    api_get(port, &format!("/api/accounts/{addr}"))
        .and_then(|v| {
            v["balances"]["uqcb"]
                .as_str()
                .and_then(|s| s.parse::<u128>().ok())
                .or_else(|| v["balances"]["uqcb"].as_u64().map(|n| n as u128))
        })
        .unwrap_or(0)
}

fn account_nonce(port: u16, addr: &str) -> u64 {
    api_get(port, &format!("/api/accounts/{addr}"))
        .and_then(|v| v["nonce"].as_u64())
        .unwrap_or(0)
}

/// Sum of all uqcb balances across every account the node knows about.
/// Uses GET /api/accounts (returns all account snapshots as a JSON array).
fn total_supply(port: u16) -> u128 {
    let accounts = api_get(port, "/api/accounts")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    accounts.iter().map(|a| {
        a["balances"]["uqcb"]
            .as_str()
            .and_then(|s| s.parse::<u128>().ok())
            .or_else(|| a["balances"]["uqcb"].as_u64().map(|n| n as u128))
            .unwrap_or(0)
    }).sum()
}

fn block_root(port: u16, height: u64) -> Option<String> {
    api_get(port, &format!("/api/blocks/{height}"))
        .and_then(|v| v["state_root"].as_str().map(str::to_string))
}

fn block_hash_at(port: u16, height: u64) -> Option<String> {
    api_get(port, &format!("/api/blocks/{height}"))
        .and_then(|v| v["block_hash"].as_str().map(str::to_string))
}

fn wait_for_height(ports: &[u16], target: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let heights: Vec<u64> = ports.iter().map(|&p| height_of(p)).collect();
        let all_reached = heights.iter().all(|&h| h >= target);
        print!("\r   waiting for height {target}: {:?}  ", heights);
        std::io::Write::flush(&mut std::io::stdout()).ok();
        if all_reached { println!(); return; }
        if Instant::now() >= deadline {
            panic!("height {target} not reached within {timeout:?}; heights={heights:?}");
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn wait_for_nonce(ports: &[u16], addr: &str, nonce: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let seen: Vec<u64> = ports.iter().map(|&p| account_nonce(p, addr)).collect();
        if seen.iter().all(|&n| n >= nonce) { return; }
        assert!(Instant::now() < deadline,
            "{addr} never reached nonce {nonce} on all nodes: {seen:?}");
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Assert all nodes agree on `what` and return the common value.
fn agreed<T: PartialEq + std::fmt::Debug + Clone>(what: &str, vals: Vec<T>) -> T {
    for (i, v) in vals.iter().enumerate().skip(1) {
        assert_eq!(v, &vals[0],
            "S-05 determinism FAILED: {what} differs on {}: {vals:?}", VALIDATORS[i]);
    }
    vals[0].clone()
}

fn agreed_block_hashes(ports: &[u16], upto: u64) -> Vec<String> {
    (1..=upto).map(|h| {
        let seen: Vec<Option<String>> = ports.iter().map(|&p| block_hash_at(p, h)).collect();
        assert!(seen[0].is_some(), "no block hash for height {h}");
        for (i, b) in seen.iter().enumerate().skip(1) {
            assert_eq!(b, &seen[0],
                "conflicting block hash at height {h} on {}: {seen:?}", VALIDATORS[i]);
        }
        seen[0].clone().unwrap()
    }).collect()
}

// ── Transaction builders ───────────────────────────────────────────────────────

fn make_transfer(id: &str, sender: &str, nonce: u64, to: &str, amount: u128) -> Transaction {
    Transaction {
        id: id.into(), sender: sender.into(), nonce,
        body: TxBody::Transfer { to: to.into(), denom: DENOM.into(), amount },
        gas_limit: 1_000_000,
        signature: vec![], public_key: vec![], pq_signatures: vec![],
        sig_scheme: None, pq_public_key: vec![],
    }
}

fn make_burn(id: &str, sender: &str, nonce: u64, amount: u128) -> Transaction {
    Transaction {
        id: id.into(), sender: sender.into(), nonce,
        body: TxBody::Burn { denom: DENOM.into(), amount },
        gas_limit: 1_000_000,
        signature: vec![], public_key: vec![], pq_signatures: vec![],
        sig_scheme: None, pq_public_key: vec![],
    }
}

fn submit(port: u16, tx: &Transaction) -> serde_json::Value {
    api_post_tx(port, &serde_json::to_string(tx).unwrap())
        .unwrap_or_else(|| panic!("POST /api/tx for {} failed", tx.id))
}

// ── RAII node guard ────────────────────────────────────────────────────────────

struct NodeProc {
    label:    &'static str,
    child:    Child,
    api_port: u16,
    log_path: PathBuf,
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── Spawn helpers ──────────────────────────────────────────────────────────────

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for nc in chars.by_ref() { if nc == 'm' { break; } }
            }
        } else { out.push(c); }
    }
    out
}

fn read_peer_id_from_log(log_path: &PathBuf, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(content) = std::fs::read_to_string(log_path) {
            for raw_line in content.lines() {
                let line = strip_ansi(raw_line);
                if let Some(pos) = line.find("local_peer_id=") {
                    let after = &line[pos + "local_peer_id=".len()..];
                    let id: String = after.chars().take_while(|c| !c.is_whitespace()).collect();
                    if !id.is_empty() { return id; }
                }
            }
        }
        if Instant::now() >= deadline { panic!("peer ID never appeared in {log_path:?}"); }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_node(
    bin:        &PathBuf,
    genesis:    &PathBuf,
    log_dir:    &PathBuf,
    idx:        usize,
    data_dir:   Option<&PathBuf>,
    bootstraps: &[String],
) -> NodeProc {
    let validator  = VALIDATORS[idx];
    let api_port   = API_PORTS[idx];
    let p2p_port   = P2P_PORTS[idx];
    let short_name = validator.strip_prefix("qcb1").unwrap_or(validator);
    let key_file   = key_path(short_name);
    let log_path   = log_dir.join(format!("{validator}.log"));
    let log_file   = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open(&log_path)
        .unwrap_or_else(|e| panic!("log open {log_path:?}: {e}"));

    let mut cmd = Command::new(bin);
    cmd.args([
        "--genesis",   genesis.to_str().unwrap(),
        "--validator", validator,
        "--key-file",  key_file.to_str().unwrap(),
        "--api-port",  &api_port.to_string(),
        "--p2p-port",  &p2p_port.to_string(),
    ]);
    if let Some(d) = data_dir { cmd.args(["--data-dir", d.to_str().unwrap()]); }
    for b in bootstraps { cmd.args(["--bootstrap", b]); }
    cmd.stdout(log_file.try_clone().unwrap())
       .stderr(log_file)
       .stdin(Stdio::null());

    let child = cmd.spawn()
        .unwrap_or_else(|e| panic!("spawn {validator}: {e}"));
    NodeProc { label: validator, child, api_port, log_path }
}

fn spawn_all(
    bin:       &PathBuf,
    genesis:   &PathBuf,
    log_dir:   &PathBuf,
    data_dirs: Option<&[PathBuf]>,
) -> Vec<NodeProc> {
    let mut nodes = Vec::new();
    {
        let dd = data_dirs.map(|dirs| &dirs[0]);
        nodes.push(spawn_node(bin, genesis, log_dir, 0, dd, &[]));
    }
    assert!(wait_for_port(nodes[0].api_port, Duration::from_secs(15)),
        "{} API port :{} never opened", nodes[0].label, nodes[0].api_port);
    println!("   {} up on :{}", nodes[0].label, nodes[0].api_port);

    let alice_peer_id = read_peer_id_from_log(&nodes[0].log_path, Duration::from_secs(10));
    let alice_bootstrap = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", P2P_PORTS[0], alice_peer_id);
    println!("   Alice peer ID: {alice_peer_id}");
    println!("   Bootstrap addr: {alice_bootstrap}");

    for i in 1..VALIDATORS.len() {
        let dd = data_dirs.map(|dirs| &dirs[i]);
        nodes.push(spawn_node(bin, genesis, log_dir, i, dd, &[alice_bootstrap.clone()]));
        assert!(wait_for_port(nodes[i].api_port, Duration::from_secs(15)),
            "{} API port :{} never opened", nodes[i].label, nodes[i].api_port);
        println!("   {} up on :{}", nodes[i].label, nodes[i].api_port);
    }
    nodes
}

// ── Supply accounting helper ───────────────────────────────────────────────────

/// Apply the same integer BPS split used by `FeeDistribution::split()`.
/// 70% → validator, 20% + remainder → treasury:network, 10% → burn.
fn expected_split(fees: u64, dist: &FeeDistribution) -> (u64, u64, u64) {
    dist.split(fees)  // returns (validator_share, treasury_share, burn_share)
}

// ── Main test ──────────────────────────────────────────────────────────────────

#[test]
fn h0_7_supply_conservation_multi_node() {
    let bin = node_binary();
    assert!(bin.exists(),
        "HARD FAIL: node binary not found at {bin:?}. Run `cargo build -p chain-forge-node` first.");
    let genesis = genesis_path();
    // FeeDistribution from genesis (validates BPS sum = 10 000).
    let dist = {
        use chain_forge_core::GenesisConfig;
        FeeDistribution::from_genesis(
            &GenesisConfig::from_json(&std::fs::read_to_string(&genesis).unwrap()).unwrap()
        ).expect("FeeDistribution from genesis")
    };
    for name in ["alice", "bob", "carol", "dave"] {
        assert!(key_path(name).exists(), "key file missing: {:?}", key_path(name));
    }
    for port in API_PORTS.iter().chain(P2P_PORTS.iter()) {
        assert!(port_is_free(*port), "port {port} in use — kill stray processes first");
    }

    let timeout   = Duration::from_secs(TIMEOUT_SECS);
    let log_dir   = std::env::temp_dir().join("qcb-h07-supply-test");
    let data_root = std::env::temp_dir().join("qcb-h07-supply-data");
    let _ = std::fs::remove_dir_all(&log_dir);
    let _ = std::fs::remove_dir_all(&data_root);
    std::fs::create_dir_all(&log_dir).unwrap();
    let data_dirs: Vec<PathBuf> = VALIDATORS.iter().map(|v| data_root.join(v)).collect();
    for d in &data_dirs { std::fs::create_dir_all(d).unwrap(); }
    let ports: Vec<u16> = API_PORTS.to_vec();
    let run = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0);

    println!("\n── H0-7 supply conservation (4 nodes) ──────────────────────────────");
    println!("   logs: {log_dir:?}");
    let mut nodes = spawn_all(&bin, &genesis, &log_dir, Some(&data_dirs));
    wait_for_height(&ports, 2, timeout);

    // ── S-02: Genesis supply audit ────────────────────────────────────────────
    println!("\n── S-02: Genesis supply audit ───────────────────────────────────────");
    let supply_at_genesis = agreed("genesis total supply",
        ports.iter().map(|&p| total_supply(p)).collect());
    assert_eq!(supply_at_genesis, GENESIS_TOTAL_SUPPLY,
        "S-02 FAIL: genesis supply {supply_at_genesis} ≠ expected {GENESIS_TOTAL_SUPPLY}");
    println!("✓ S-02 passed — genesis total supply = {supply_at_genesis} uqcb");

    // ── S-01: Fee-bearing block conserves supply correctly ────────────────────
    // Strategy: measure the ACTUAL fee from the sender's balance delta, not from
    // the gas model (which may not match the on-chain fee exactly).
    // Actual fee = (sender_bal_before - sender_bal_after) - transfer_amount.
    // Then split the actual fee to derive the exact expected vault changes.
    println!("\n── S-01: Fee-bearing transfer — supply accounting ───────────────────");
    let n1 = account_nonce(ports[0], USER1);
    let user1_bal_before_s01 = balance_of(ports[0], USER1);
    let supply_before_s01    = agreed("supply before S-01",
        ports.iter().map(|&p| total_supply(p)).collect());
    let vpool_before_s01 = balance_of(ports[0], VALIDATOR_POOL);
    let tnet_before_s01  = balance_of(ports[0], TREASURY_NETWORK);

    let transfer_amount_s01: u128 = 1_000;
    let s01_tx   = make_transfer(&format!("h07-s01-{run}"), USER1, n1, RECIPIENT, transfer_amount_s01);
    let s01_resp = submit(ports[0], &s01_tx);
    println!("   S-01 transfer: {s01_resp}");
    wait_for_nonce(&ports, USER1, n1 + 1, timeout);

    // Pin at current height + 1 so the block containing the tx is fully committed.
    let pin_s01 = ports.iter().map(|&p| height_of(p)).max().unwrap() + 1;
    wait_for_height(&ports, pin_s01, timeout);

    let user1_bal_after_s01  = balance_of(ports[0], USER1);
    let supply_after_s01     = agreed("supply after S-01",
        ports.iter().map(|&p| total_supply(p)).collect());
    let vpool_after_s01  = balance_of(ports[0], VALIDATOR_POOL);
    let tnet_after_s01   = balance_of(ports[0], TREASURY_NETWORK);

    // Actual fee charged (on-chain, not estimated).
    let user1_debited_s01 = user1_bal_before_s01.saturating_sub(user1_bal_after_s01);
    assert!(user1_debited_s01 >= transfer_amount_s01,
        "S-01 FAIL: USER1 debited only {user1_debited_s01} but sent {transfer_amount_s01}");
    let actual_fee_s01 = user1_debited_s01 - transfer_amount_s01;
    let (vshare_s01, tshare_s01, bshare_s01) = expected_split(actual_fee_s01 as u64, &dist);
    println!("   actual_fee={actual_fee_s01} → validator={vshare_s01} treasury={tshare_s01} burn={bshare_s01}");

    // Conservation check: split must reconstruct the actual fee exactly.
    assert_eq!(vshare_s01 as u128 + tshare_s01 as u128 + bshare_s01 as u128, actual_fee_s01,
        "S-01 FAIL: fee split arithmetic violated: \
        {vshare_s01}+{tshare_s01}+{bshare_s01} ≠ {actual_fee_s01}");

    // Vault changes must match split exactly.
    let vpool_increase_s01 = vpool_after_s01.saturating_sub(vpool_before_s01);
    let tnet_increase_s01  = tnet_after_s01.saturating_sub(tnet_before_s01);
    assert_eq!(vpool_increase_s01, vshare_s01 as u128,
        "S-01 FAIL: validator-pool increased by {vpool_increase_s01}, expected exactly {vshare_s01}");
    assert_eq!(tnet_increase_s01, tshare_s01 as u128,
        "S-01 FAIL: treasury:network increased by {tnet_increase_s01}, expected exactly {tshare_s01}");

    // Supply decreased by exactly the burn share (transfer moves funds, fee redistributes, burn destroys).
    let supply_decrease_s01 = supply_before_s01.saturating_sub(supply_after_s01);
    assert_eq!(supply_decrease_s01, bshare_s01 as u128,
        "S-01 FAIL: supply decreased by {supply_decrease_s01}, expected exactly burn_share={bshare_s01}");

    println!("✓ S-01 passed — fee={actual_fee_s01}: validator+={vshare_s01} treasury+={tshare_s01} \
        supply−={bshare_s01}; all exact");

    // ── S-03: Explicit Burn tx (BME) decreases supply exactly ────────────────
    // Measure actual fee from sender's balance delta; separate from burn_amount.
    println!("\n── S-03: Explicit TxBody::Burn — supply decreases by burned amount ──");
    let n2 = account_nonce(ports[0], USER1);
    let user1_bal_before_s03 = balance_of(ports[0], USER1);
    let supply_before_s03    = agreed("supply before S-03",
        ports.iter().map(|&p| total_supply(p)).collect());

    let burn_amount: u128 = 100_000;
    let s03_tx   = make_burn(&format!("h07-s03-{run}"), USER1, n2, burn_amount);
    let s03_resp = submit(ports[0], &s03_tx);
    println!("   S-03 burn: {s03_resp}");
    wait_for_nonce(&ports, USER1, n2 + 1, timeout);
    let pin_s03 = ports.iter().map(|&p| height_of(p)).max().unwrap() + 1;
    wait_for_height(&ports, pin_s03, timeout);

    let user1_bal_after_s03 = balance_of(ports[0], USER1);
    let supply_after_s03    = agreed("supply after S-03",
        ports.iter().map(|&p| total_supply(p)).collect());

    let user1_debited_s03 = user1_bal_before_s03.saturating_sub(user1_bal_after_s03);
    assert!(user1_debited_s03 >= burn_amount,
        "S-03 FAIL: USER1 debited {user1_debited_s03} but burn_amount={burn_amount}");
    let actual_fee_s03 = user1_debited_s03 - burn_amount;
    let (_, _, bshare_s03) = expected_split(actual_fee_s03 as u64, &dist);
    println!("   burn_amount={burn_amount}, actual_fee={actual_fee_s03}, fee_burn_share={bshare_s03}");

    // Supply must have decreased by exactly burn_amount (BME body) + bshare_s03 (fee burn).
    let expected_decrease_s03 = burn_amount + bshare_s03 as u128;
    let actual_decrease_s03   = supply_before_s03.saturating_sub(supply_after_s03);
    assert_eq!(actual_decrease_s03, expected_decrease_s03,
        "S-03 FAIL: supply decreased by {actual_decrease_s03}, \
        expected exactly {expected_decrease_s03} (burn_tx={burn_amount} + fee_burn={bshare_s03})");

    println!("✓ S-03 passed — supply −{actual_decrease_s03} = burn_tx({burn_amount}) + fee_burn({bshare_s03}), exact");

    // ── S-04: Combined — fee + burn in same block ─────────────────────────────
    // Use balance deltas to derive actual fees; verify both invariants simultaneously.
    println!("\n── S-04: Combined fee + explicit burn in same block ─────────────────");
    let n3_user1 = account_nonce(ports[0], USER1);
    let n3_eve   = account_nonce(ports[0], EVE);
    let user1_bal_before_s04 = balance_of(ports[0], USER1);
    let eve_bal_before_s04   = balance_of(ports[0], EVE);
    let supply_before_s04    = agreed("supply before S-04",
        ports.iter().map(|&p| total_supply(p)).collect());

    let s04_xfer_amount: u128 = 500;
    let s04_burn_amount: u128 = 50_000;
    let s04_xfer  = make_transfer(&format!("h07-s04a-{run}"), USER1, n3_user1, RECIPIENT, s04_xfer_amount);
    let s04_bburn = make_burn(&format!("h07-s04b-{run}"), EVE, n3_eve, s04_burn_amount);

    submit(ports[0], &s04_xfer);
    submit(ports[1], &s04_bburn);
    wait_for_nonce(&ports, USER1, n3_user1 + 1, timeout);
    wait_for_nonce(&ports, EVE, n3_eve + 1, timeout);
    let pin_s04 = ports.iter().map(|&p| height_of(p)).max().unwrap() + 1;
    wait_for_height(&ports, pin_s04, timeout);

    let user1_bal_after_s04 = balance_of(ports[0], USER1);
    let eve_bal_after_s04   = balance_of(ports[0], EVE);
    let supply_after_s04    = agreed("supply after S-04",
        ports.iter().map(|&p| total_supply(p)).collect());

    let xfer_fee = user1_bal_before_s04.saturating_sub(user1_bal_after_s04)
        .saturating_sub(s04_xfer_amount);
    let burn_fee = eve_bal_before_s04.saturating_sub(eve_bal_after_s04)
        .saturating_sub(s04_burn_amount);
    let (_, _, xfee_burn) = expected_split(xfer_fee as u64, &dist);
    let (_, _, bfee_burn) = expected_split(burn_fee as u64, &dist);

    // Total supply decrease = explicit burn + both fee burn shares.
    let expected_s04 = s04_burn_amount + xfee_burn as u128 + bfee_burn as u128;
    let actual_s04   = supply_before_s04.saturating_sub(supply_after_s04);
    assert_eq!(actual_s04, expected_s04,
        "S-04 FAIL: supply decreased by {actual_s04}, \
        expected {expected_s04} (burn_tx={s04_burn_amount} + fee_burns={xfee_burn}+{bfee_burn})");

    println!("✓ S-04 passed — combined supply −{actual_s04} = burn({s04_burn_amount})+fee_burns({xfee_burn}+{bfee_burn}), exact");

    // ── S-06: Overflow / invalid burn rejected ────────────────────────────────
    println!("\n── S-06: Invalid burn rejected — no partial state change ────────────");
    let n4 = account_nonce(ports[0], USER1);
    let bal_before_s06    = balance_of(ports[0], USER1);
    let supply_before_s06 = total_supply(ports[0]);

    // Attempt to burn far more than the sender holds.  The tx must be included
    // (consuming the nonce) but the burn body must not apply — only the fee is
    // charged.  This mirrors the H5-1 "included-but-failed" pattern.
    let over_amount = bal_before_s06 + 1_000_000_000_000;
    let s06_tx   = make_burn(&format!("h07-s06-{run}"), USER1, n4, over_amount);
    let s06_resp = submit(ports[0], &s06_tx);
    println!("   S-06 overflow burn: {s06_resp}");
    wait_for_nonce(&ports, USER1, n4 + 1, timeout);
    let pin_s06 = ports.iter().map(|&p| height_of(p)).max().unwrap() + 1;
    wait_for_height(&ports, pin_s06, timeout);

    let bal_after_s06    = balance_of(ports[0], USER1);
    let supply_after_s06 = total_supply(ports[0]);

    // The over-burn body must not have applied.
    // Sender's balance must NOT have dropped by over_amount.
    assert!(bal_after_s06 > 0 || bal_before_s06 == 0,
        "S-06 FAIL: sender balance wiped; over-burn applied");
    let sender_decrease_s06 = bal_before_s06.saturating_sub(bal_after_s06);
    assert!(sender_decrease_s06 < over_amount,
        "S-06 FAIL: sender lost {sender_decrease_s06} ≈ over_amount={over_amount}; burn body applied");

    // Supply must have decreased by at most the fee-burn share of the actual fee,
    // never by the over_amount.
    let actual_fee_s06  = sender_decrease_s06;  // upper bound: nonce was consumed, fee charged
    let (_, _, max_bshare_s06) = expected_split(actual_fee_s06 as u64, &dist);
    let supply_decrease_s06 = supply_before_s06.saturating_sub(supply_after_s06);
    assert!(supply_decrease_s06 <= max_bshare_s06 as u128,
        "S-06 FAIL: supply decreased by {supply_decrease_s06} but max fee-burn is {max_bshare_s06}; \
        over-burn body must not have applied");

    println!("✓ S-06 passed — over-burn rejected; sender lost {sender_decrease_s06} (fee only), \
        supply −{supply_decrease_s06} ≤ fee_burn={max_bshare_s06}");

    // ── S-05: Four-node convergence + crash-restart ───────────────────────────
    println!("\n── S-05: Four-node convergence and crash-restart persistence ─────────");
    let pin_final = ports.iter().map(|&p| height_of(p)).max().unwrap() + 2;
    wait_for_height(&ports, pin_final, timeout);

    let root_final = agreed("final state root",
        ports.iter().map(|&p| block_root(p, pin_final)).collect());
    assert!(root_final.is_some(), "no state root for height {pin_final}");

    let supply_final = agreed("final total supply",
        ports.iter().map(|&p| total_supply(p)).collect());
    let hashes_final = agreed_block_hashes(&ports, pin_final);

    println!("   State roots:");
    for (i, &p) in ports.iter().enumerate() {
        println!("     node[{i}] = {}", block_root(p, pin_final).unwrap_or_default());
    }

    // Crash-restart all four nodes.
    let height_before_restart = ports.iter().map(|&p| height_of(p)).max().unwrap();
    println!("   killing all nodes at height ~{height_before_restart}");
    drop(std::mem::take(&mut nodes));
    std::thread::sleep(Duration::from_secs(2));

    let restart_log_dir = log_dir.join("restart");
    std::fs::create_dir_all(&restart_log_dir).unwrap();
    let restarted = spawn_all(&bin, &genesis, &restart_log_dir, Some(&data_dirs));
    wait_for_height(&ports, height_before_restart + 2, timeout);

    // Verify state root, supply, and block hashes are preserved.
    for (i, &p) in ports.iter().enumerate() {
        assert_eq!(block_root(p, pin_final), root_final,
            "S-05 FAIL on {}: root@{pin_final} changed across restart", VALIDATORS[i]);
    }
    let supply_after_restart = agreed("supply after restart",
        ports.iter().map(|&p| total_supply(p)).collect());
    assert_eq!(supply_after_restart, supply_final,
        "S-05 FAIL: total supply changed across restart: \
        before={supply_final} after={supply_after_restart}");
    assert_eq!(agreed_block_hashes(&ports, pin_final), hashes_final,
        "S-05 FAIL: finalized block hashes changed across restart");

    println!("✓ S-05 passed — 4-node state roots converge, supply consistent, restart preserved");
    println!("   final supply = {supply_final} uqcb");
    println!("   supply reduction from genesis = {} uqcb (authorized burns only)",
        GENESIS_TOTAL_SUPPLY.saturating_sub(supply_final));

    drop(restarted);
    println!("\n━━━ H0-7 PASS: S-01..S-06 all passed ━━━");
}
