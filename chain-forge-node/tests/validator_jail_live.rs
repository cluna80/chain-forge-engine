//! H0-11B Phase 1 — Jail enforcement under real consensus (live acceptance test)
//!
//! Four real node processes. Dave is killed after the chain is healthy; the
//! existing liveness policy (committed `last_commit` evidence, 100-block window,
//! 20% threshold, genesis `consensus.liveness`) jails him. This test checks what
//! that jail *does* to consensus:
//!
//! JL-01  four healthy validators finalize blocks; none is jailed
//! JL-02  Dave's absence shows up as missed duties in the liveness window,
//!        and the same view is reached on every live node
//! JL-03  Dave becomes Jailed; jail record is epoch-based (10 epochs) and agreed
//! JL-04  Dave keeps his seat until the next epoch boundary (sampled, exact)
//! JL-05  Dave is removed from the committee at that boundary, on every node
//! JL-06  the remaining three keep FINALIZING after the transition (a tx lands),
//!        with identical state roots
//! JL-07  Dave's bond is unchanged (no slashing)
//! JL-08  restarting a node preserves the jail record and the committee
//! JL-09  the jail period expiring does NOT reinstate Dave, who is back online,
//!        caught up (replayed the chain, same state root) and healthy
//!
//! This does NOT prove the 20% policy is safe against false positives: the
//! evidence is the proposer's `last_commit`, which can omit a live validator's
//! late precommit. It shows the policy's consequences are enforced, not that
//! its threshold is right. Automatic suspension stays off for production
//! genesis files until that is resolved.
//!
//! Removing Dave leaves a 3-validator committee (f = 0): it needs all three.
//! JL-08 restarts one of them, which halts the chain until it returns; the test
//! records that and does not assert on it.
//!
//! Runtime: roughly 8-10 minutes (the genesis minimum liveness window is 100
//! blocks at 2 s/block, then a 10-epoch jail at 5 blocks/epoch).
//!
//! ## Run
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test validator_jail_live -- --nocapture
//! ```

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
use chain_forge_execution::{Transaction, TxBody};

const CHAIN_ID:      &str = "qcb-devnet-val-jail";
const DAVE:          &str = "qcb1dave";
const EPOCH_BLOCKS:  u64  = 5;
const JAIL_EPOCHS:   u64  = 10;
const GENESIS_BOND:  u64  = 490_000_000;
const LIVE_NODES:    [&str; 3] = ["qcb1alice", "qcb1bob", "qcb1carol"];

// ── Paths and processes ───────────────────────────────────────────────────────

/// Ports below the OS ephemeral range (Linux 32768+, Windows 49152+): the other nodes' outgoing
/// connections draw from the ephemeral range, and a node restarted on its old API port can find it taken.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = 20_000 + (std::process::id() % 8_000) as u16;
    loop {
        let p = start + NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(p < 32_000, "no free port found");
        if TcpListener::bind(("127.0.0.1", p)).is_ok() { return p; }
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn node_bin() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    target.join("debug").join(exe)
}

fn genesis_path() -> PathBuf {
    repo_root().join("tests").join("devnet").join("genesis-val-jail.json")
}

fn key_file(label: &str) -> PathBuf {
    repo_root().join("tests").join("devnet").join("keys").join(format!("{label}.key.json"))
}

struct NodeHandle { proc: Child }
impl NodeHandle {
    fn alive(&mut self) -> bool { matches!(self.proc.try_wait(), Ok(None)) }
}
impl Drop for NodeHandle {
    fn drop(&mut self) {
        let _ = self.proc.kill();
        let _ = self.proc.wait();
    }
}

#[derive(Clone)]
struct Spec { name: &'static str, api: u16, p2p: u16, peers: Vec<u16> }

fn spawn(spec: &Spec, log_dir: &PathBuf) -> NodeHandle {
    let data_dir = log_dir.join(format!("data-{}", spec.name.trim_start_matches("qcb1")));
    std::fs::create_dir_all(&data_dir).unwrap();
    let log_path = log_dir.join(format!("{}.log", spec.name));
    if log_path.exists() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let _ = std::fs::rename(&log_path, log_dir.join(format!("{}.prev-{stamp}.log", spec.name)));
    }
    let log = std::fs::File::create(&log_path).unwrap();
    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator").arg(spec.name)
       .arg("--api-port").arg(spec.api.to_string())
       .arg("--p2p-port").arg(spec.p2p.to_string())
       .arg("--data-dir").arg(&data_dir)
       .arg("--key-file").arg(key_file(spec.name.trim_start_matches("qcb1")));
    for p in &spec.peers { cmd.arg("--bootstrap").arg(format!("/ip4/127.0.0.1/tcp/{p}")); }
    // Storage format 2 test switch (default OFF): CF_TEST_STORAGE_V2=1 runs this test on the experimental v2 layout.
    if std::env::var_os("CF_TEST_STORAGE_V2").is_some() { cmd.arg("--storage-v2-experimental"); }
    cmd.stdout(log.try_clone().unwrap()).stderr(log).stdin(Stdio::null());
    NodeHandle { proc: cmd.spawn().unwrap_or_else(|e| panic!("spawn {}: {e}", spec.name)) }
}

fn tail_log(log_dir: &PathBuf, name: &str, n: usize) -> String {
    std::fs::read_to_string(log_dir.join(format!("{name}.log")))
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            lines[lines.len().saturating_sub(n)..].join("\n")
        })
        .unwrap_or_else(|_| "<no log>".into())
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

fn http(method: &str, port: u16, path: &str, body: &str) -> Option<serde_json::Value> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(500)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len());
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1).unwrap_or("")).ok()
}
fn get(port: u16, path: &str) -> Option<serde_json::Value> { http("GET", port, path, "") }

fn height(port: u16) -> u64 {
    get(port, "/api/status").and_then(|v| v["height"].as_u64()).unwrap_or(0)
}

fn state_view(port: u16) -> Option<(u64, String)> {
    let v = get(port, "/api/status")?;
    Some((v["height"].as_u64()?, v["state_root"].as_str()?.to_string()))
}

fn port_open(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(100)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() { return true; }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn nonce(port: u16, addr: &str) -> u64 {
    get(port, &format!("/api/accounts/{addr}")).and_then(|v| v["nonce"].as_u64()).unwrap_or(0)
}

fn submit_and_wait(port: u16, tx: &Transaction, timeout: Duration) -> serde_json::Value {
    let resp = http("POST", port, "/api/tx", &serde_json::to_string(tx).unwrap()).unwrap_or_default();
    assert_eq!(resp["status"].as_str().unwrap_or(""), "queued", "tx {} not queued: {resp}", tx.id);
    let id = tx.id.clone();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(r) = get(port, &format!("/api/tx/{id}")) {
            if r["success"].as_bool().is_some() { return r; }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("tx {id} never landed (height={})", height(port));
}

/// Sorted ids of the live consensus committee, from GET /api/validators.
fn committee(port: u16) -> Vec<String> {
    let mut ids: Vec<String> = get(port, "/api/validators")
        .and_then(|v| v.as_array().cloned()).unwrap_or_default()
        .iter().filter_map(|v| v["id"].as_str().map(str::to_string)).collect();
    ids.sort();
    ids
}

fn voting_power(port: u16, id: &str) -> u64 {
    get(port, "/api/validators").and_then(|v| v.as_array().cloned()).unwrap_or_default()
        .iter().find(|v| v["id"].as_str() == Some(id))
        .and_then(|v| v["voting_power"].as_u64()).unwrap_or(0)
}

/// Registry-side status of `id` from GET /api/validators/status.
fn status_of(port: u16, id: &str) -> Option<serde_json::Value> {
    get(port, "/api/validators/status")?.as_array()?.iter()
        .find(|v| v["id"].as_str() == Some(id)).cloned()
}

fn is_jailed(port: u16, id: &str) -> bool {
    status_of(port, id).map_or(false, |s| s["status"].as_str() == Some("Jailed"))
}

/// Wait until every port reports the same height AND state root; panics if two
/// nodes report different roots at the same height.
fn agree(ports: &[u16], timeout: Duration) -> (u64, String) {
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        let views: Vec<Option<(u64, String)>> = ports.iter().map(|&p| state_view(p)).collect();
        if views.iter().all(Option::is_some) {
            let views: Vec<(u64, String)> = views.into_iter().map(Option::unwrap).collect();
            last = format!("{views:?}");
            if views.iter().all(|v| v.0 == views[0].0) {
                if views.iter().all(|v| v.1 == views[0].1) { return views[0].clone(); }
                std::thread::sleep(Duration::from_millis(300));
                let again: Vec<Option<(u64, String)>> = ports.iter().map(|&p| state_view(p)).collect();
                if again.iter().all(|v| v.as_ref().map(|x| x.0) == Some(views[0].0)) {
                    let roots: Vec<String> = again.iter().map(|v| v.as_ref().unwrap().1.clone()).collect();
                    assert!(roots.iter().all(|r| *r == roots[0]),
                            "STATE ROOT DIVERGENCE at height {}: {roots:?}", views[0].0);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("nodes never reached the same height and state root within {timeout:?}; last views: {last}");
}

// ── Evidence helpers independent of the HTTP API ──────────────────────────────

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            while let Some(&n) = chars.peek() { chars.next(); if n == 'm' { break; } }
        } else {
            out.push(c);
        }
    }
    out
}

/// (height, round) for every block the node's CURRENT log says it proposed.
fn proposals_logged(log_dir: &PathBuf, name: &str) -> Vec<(u64, u32)> {
    let text = std::fs::read_to_string(log_dir.join(format!("{name}.log"))).unwrap_or_default();
    strip_ansi(&text).lines()
        .filter(|l| l.contains("block proposed (multi-node)"))
        .filter_map(|l| {
            let num = |key: &str| l.split(key).nth(1)
                .map(|r| r.chars().take_while(char::is_ascii_digit).collect::<String>());
            Some((num("height=")?.parse().ok()?, num("round=")?.parse().ok()?))
        })
        .collect()
}

/// The committee the node itself wrote to disk after its last commit.
///
/// Since #48 a node persists atomic generations: `CURRENT` names the committed
/// generation and the committee is `snapshots/<gen>/live_validator_set.json`
/// (not `persist/live_validator_set.json`, the pre-H0-3 layout). A running node
/// can commit and prune between reading `CURRENT` and reading the file, so the
/// pair is retried a few times; a stopped node (the case JL-08 checks) is stable.
fn persisted_committee(log_dir: &PathBuf, name: &str) -> Vec<String> {
    let data = log_dir.join(format!("data-{}", name.trim_start_matches("qcb1")));
    let mut last_err = String::new();
    for _ in 0..8 {
        let attempt = (|| -> Result<serde_json::Value, String> {
            let gen = std::fs::read_to_string(data.join("CURRENT"))
                .map_err(|e| format!("cannot read CURRENT in {data:?}: {e}"))?;
            let p = data.join("snapshots").join(gen.trim()).join("live_validator_set.json");
            let text = std::fs::read_to_string(&p).map_err(|e| format!("cannot read {p:?}: {e}"))?;
            serde_json::from_str(&text).map_err(|e| format!("cannot parse {p:?}: {e}"))
        })();
        match attempt {
            Ok(v) => {
                let mut ids: Vec<String> = v["validators"].as_array().unwrap().iter()
                    .map(|x| x["id"].as_str().unwrap().to_string()).collect();
                ids.sort();
                return ids;
            }
            Err(e) => { last_err = e; std::thread::sleep(Duration::from_millis(250)); }
        }
    }
    panic!("persisted committee of {name}: {last_err}");
}

/// True once the node started with this log reports its API listening on `port`. Panics if its bind
/// failed (a foreign listener on the port would otherwise satisfy a plain connect check).
fn api_listening(log_dir: &PathBuf, name: &str, port: u16, timeout: Duration) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        let text = strip_ansi(&std::fs::read_to_string(log_dir.join(format!("{name}.log"))).unwrap_or_default());
        assert!(!text.contains("failed to bind HTTP API"),
            "{name}: its API could not bind port {port}\n{}", tail_log(log_dir, name, 20));
        if text.contains(&format!("HTTP API listening port={port}")) { return true; }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

// ── Tx builders ───────────────────────────────────────────────────────────────

fn bond_tx(sender: &str, nonce_val: u64, amount: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(sender).unwrap();
    let mut tx = Transaction::bond_validator(
        &format!("bond-{sender}-{nonce_val}"), sender, amount as u128, nonce_val);
    if let TxBody::BondValidator { ref mut owner_identity_id, .. } = tx.body {
        *owner_identity_id = Some(sender.to_string());
    }
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

fn transfer_tx(sender: &str, to: &str, nonce_val: u64) -> Transaction {
    let kp = ClassicalScheme.generate_keypair(sender).unwrap();
    let mut tx = Transaction::transfer(
        &format!("xfer-{sender}-{nonce_val}"), sender, to, "uqcb", 1_000, nonce_val);
    tx.sign(&kp, CHAIN_ID).unwrap();
    tx
}

// ── The test ──────────────────────────────────────────────────────────────────

#[test]
fn validator_jail_live() {
    let bin = node_bin();
    if !bin.exists() {
        eprintln!("SKIP: binary not found at {bin:?}. Run `cargo build -p chain-forge-node`.");
        return;
    }
    let t0 = Instant::now();
    let say = |m: String| println!("[{:>4}s] {m}", t0.elapsed().as_secs());

    let ports: Vec<(u16, u16)> = (0..4).map(|_| (free_port(), free_port())).collect();
    let names = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
    let specs: Vec<Spec> = (0..4).map(|i| Spec {
        name: names[i], api: ports[i].0, p2p: ports[i].1,
        peers: (0..4).filter(|&j| j != i).map(|j| ports[j].1).collect(),
    }).collect();
    let api: Vec<u16> = specs.iter().map(|s| s.api).collect();
    let (alice, bob, carol, dave) = (api[0], api[1], api[2], api[3]);
    let live_api = [alice, bob, carol];

    let tmp = std::env::temp_dir().join(format!("qcb-val-jail-{alice}"));
    std::fs::create_dir_all(&tmp).unwrap();
    println!("\n── Validator Jail (H0-11B phase 1) ─────────────────────────────────");
    println!("   chain_id={CHAIN_ID} logs={tmp:?}");

    let mut nodes: Vec<Option<NodeHandle>> = specs.iter().map(|s| Some(spawn(s, &tmp))).collect();
    for (i, s) in specs.iter().enumerate() {
        assert!(port_open(s.api, Duration::from_secs(30)),
                "{} API did not come up\n--- log ---\n{}", s.name, tail_log(&tmp, s.name, 40));
        let _ = i;
    }
    assert!(wait_until(Duration::from_secs(60), || api.iter().all(|&p| height(p) >= 3)),
            "devnet did not reach height 3");
    say(format!("devnet up at height {}", height(alice)));

    // ── Bond all four so jailing has a real bond to leave untouched ──────────
    for (i, n) in names.iter().enumerate() {
        let r = submit_and_wait(api[i], &bond_tx(n, nonce(api[i], n), GENESIS_BOND), Duration::from_secs(30));
        assert!(r["success"].as_bool().unwrap_or(false), "bond for {n} failed: {r}");
    }
    let h = height(alice);
    assert!(wait_until(Duration::from_secs(60), || height(alice) >= h + EPOCH_BLOCKS + 1), "no epoch after bonds");
    for n in names { assert!(voting_power(alice, n) > 0, "{n} has no voting power after bond"); }
    say("all four bonded and seated with voting power".into());

    // ── JL-01: healthy network, nobody jailed ────────────────────────────────
    assert!(wait_until(Duration::from_secs(120), || api.iter().all(|&p| height(p) >= 30)),
            "healthy devnet did not pass height 30");
    for n in names {
        let s = status_of(alice, n).unwrap_or_else(|| panic!("{n} missing from status"));
        assert_eq!(s["status"].as_str(), Some("Active"), "JL-01: {n} not Active: {s}");
    }
    assert_eq!(committee(alice).len(), 4, "JL-01: committee must have four seats");
    let (h_ok, root_ok) = agree(&api, Duration::from_secs(30));
    say(format!("✓ JL-01: four validators finalizing, none jailed (height {h_ok}, root {})", &root_ok[..12]));

    // ── Kill Dave ────────────────────────────────────────────────────────────
    let dave_bond = status_of(alice, DAVE).unwrap()["bonded_uqcb"].as_u64().unwrap();
    assert_eq!(dave_bond, GENESIS_BOND, "Dave's registry bond should equal his ledger bond");
    drop(nodes[3].take());
    let h_kill = height(alice);
    say(format!("killed Dave at height {h_kill}; bond {dave_bond}"));

    // ── JL-02/03: absence accumulates in the window, then Dave is jailed ─────
    let mut max_missed = 0u32;
    let mut last_print = Instant::now();
    let jailed_ok = wait_until(Duration::from_secs(600), || {
        if let Some(s) = status_of(alice, DAVE) {
            max_missed = max_missed.max(s["liveness_missed_pct"].as_u64().unwrap_or(0) as u32);
            if last_print.elapsed() > Duration::from_secs(15) {
                say(format!("  height {} dave: status={} window={} missed={}%",
                    height(alice), s["status"], s["liveness_observed"], s["liveness_missed_pct"]));
                last_print = Instant::now();
            }
        }
        is_jailed(alice, DAVE)
    });
    if !jailed_ok {
        for n in &LIVE_NODES { eprintln!("--- {n} ---\n{}", tail_log(&tmp, n, 30)); }
        panic!("JL-03: Dave was never jailed (max missed seen {max_missed}%)");
    }
    let h_jailed_seen = height(alice);
    let seated_at_first_sight = committee(alice).iter().any(|i| i == DAVE);
    let rec = status_of(alice, DAVE).unwrap();
    assert!(max_missed > 0, "JL-02: the window never showed Dave missing duties");
    say(format!("✓ JL-02: Dave's absence reached the liveness window (peak {max_missed}% before jailing)"));

    let jailed_epoch = rec["jailed_epoch"].as_u64().expect("jail record has an epoch");
    let unjail_after = rec["unjail_after"].as_u64().expect("jail record has an expiry");
    assert_eq!(rec["jail_count"].as_u64(), Some(1));
    assert_eq!(unjail_after - jailed_epoch, JAIL_EPOCHS, "JL-03: jail must last {JAIL_EPOCHS} epochs: {rec}");
    assert!(h_jailed_seen / EPOCH_BLOCKS <= jailed_epoch + 1 && jailed_epoch <= h_jailed_seen / EPOCH_BLOCKS,
            "JL-03: jailed_epoch {jailed_epoch} must be the validator epoch (height {h_jailed_seen} / {EPOCH_BLOCKS}), \
             not a block height");
    for p in [bob, carol] {
        assert!(wait_until(Duration::from_secs(30), || is_jailed(p, DAVE)), "JL-03: a live node never jailed Dave");
        let r = status_of(p, DAVE).unwrap();
        assert_eq!((r["jailed_epoch"].clone(), r["unjail_after"].clone()), (rec["jailed_epoch"].clone(), rec["unjail_after"].clone()),
                   "JL-03: nodes disagree on the jail record");
    }
    for n in LIVE_NODES {
        assert_eq!(status_of(alice, n).unwrap()["status"].as_str(), Some("Active"), "{n} was wrongly jailed");
    }
    say(format!("✓ JL-03: Dave Jailed at epoch {jailed_epoch}, expires epoch {unjail_after}; all live nodes agree"));

    // ── JL-04/05: seat kept until the boundary, gone at it ───────────────────
    let boundary = (jailed_epoch + 1) * EPOCH_BLOCKS;
    let mut saw_seated_before = false;
    let started = Instant::now();
    loop {
        let h_before = height(alice);
        let seated = committee(alice).iter().any(|i| i == DAVE);
        let h_after = height(alice);
        if h_after < boundary {
            assert!(seated, "JL-04: Dave lost his seat at height {h_after}, before the boundary {boundary}");
            saw_seated_before = true;
        }
        if h_before > boundary {
            assert!(!seated, "JL-05: Dave still seated at height {h_before}, past the boundary {boundary}");
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(120), "JL-05: boundary {boundary} never passed");
        std::thread::sleep(Duration::from_millis(150));
    }
    if seated_at_first_sight && h_jailed_seen < boundary {
        assert!(saw_seated_before, "JL-04: never observed Dave seated between jail and boundary");
    }
    say(format!("✓ JL-04: Dave kept his seat until the boundary at height {boundary}"));
    for p in live_api {
        assert!(wait_until(Duration::from_secs(30), || committee(p) == ["qcb1alice", "qcb1bob", "qcb1carol"]),
                "JL-05: a live node still seats Dave: {:?}", committee(p));
    }
    say("✓ JL-05: Dave removed from the committee on alice, bob and carol".into());

    // ── JL-06: the remaining three still FINALIZE after the transition ───────
    let h_after_transition = height(alice);
    assert!(wait_until(Duration::from_secs(90), || live_api.iter().all(|&p| height(p) >= h_after_transition + 10)),
            "JL-06: the three-validator committee stopped finalizing blocks");
    let xfer = transfer_tx("qcb1carol", "qcb1eve", nonce(carol, "qcb1carol"));
    let r = submit_and_wait(carol, &xfer, Duration::from_secs(60));
    assert!(r["success"].as_bool().unwrap_or(false), "JL-06: a tx must finalize under the new committee: {r}");
    let (h6, root6) = agree(&live_api, Duration::from_secs(60));
    assert!(h6 > boundary + 5, "JL-06: agreement must be on a post-transition block (h={h6}, boundary={boundary})");
    say(format!("✓ JL-06: three-validator committee finalizing (height {h6} > boundary {boundary}); tx landed; root {}", &root6[..12]));

    // ── JL-07: bond untouched ────────────────────────────────────────────────
    for p in live_api {
        let s = status_of(p, DAVE).unwrap();
        assert_eq!(s["bonded_uqcb"].as_u64(), Some(dave_bond), "JL-07: bond changed: {s}");
        assert_eq!(s["status"].as_str(), Some("Jailed"));
    }
    say(format!("✓ JL-07: Dave's bond is still {dave_bond} uqcb (jailed, not slashed)"));

    // ── Bring Dave back, healthy: he must replay the chain and stay out ──────
    nodes[3] = Some(spawn(&specs[3], &tmp));
    assert!(api_listening(&tmp, DAVE, dave, Duration::from_secs(30)), "Dave did not restart\n{}", tail_log(&tmp, DAVE, 40));
    assert!(wait_until(Duration::from_secs(240), || height(dave) + 3 >= height(alice)),
            "Dave never caught up (dave {} vs alice {})\n{}", height(dave), height(alice), tail_log(&tmp, DAVE, 40));
    let (h_all, _) = agree(&api, Duration::from_secs(90));
    assert!(is_jailed(dave, DAVE), "Dave's own replay did not derive Jailed");
    say(format!("  Dave back online and replayed to height {h_all}; his own state says Jailed, roots agree on all four"));

    // ── JL-08: restart a committee member ────────────────────────────────────
    let before = status_of(bob, DAVE).unwrap();
    drop(nodes[1].take());
    let h_down = height(alice);
    std::thread::sleep(Duration::from_secs(8));
    let advanced_without_bob = height(alice) > h_down + 1;
    say(format!("  bob down: chain {} (3-validator committee needs all three)",
        if advanced_without_bob { "STILL ADVANCED" } else { "halted, as expected for f=0" }));
    nodes[1] = Some(spawn(&specs[1], &tmp));
    assert!(api_listening(&tmp, "qcb1bob", bob, Duration::from_secs(30)), "bob did not restart\n{}", tail_log(&tmp, "qcb1bob", 40));
    assert!(wait_until(Duration::from_secs(60), || is_jailed(bob, DAVE)),
            "JL-08: bob forgot Dave's jail across a restart\n{}", tail_log(&tmp, "qcb1bob", 40));
    let after = status_of(bob, DAVE).unwrap();
    for k in ["jailed_epoch", "unjail_after", "jail_count", "bonded_uqcb"] {
        assert_eq!(before[k], after[k], "JL-08: {k} changed across restart");
    }
    assert_eq!(committee(bob), ["qcb1alice", "qcb1bob", "qcb1carol"], "JL-08: committee changed across restart");
    assert!(wait_until(Duration::from_secs(120), || height(alice) >= h_down + 6),
            "JL-08: chain did not resume after bob returned");
    let (h8, _) = agree(&api, Duration::from_secs(90));

    // Four independent views of the committee must agree after the restart:
    //  1. GET /api/validators          (asserted above, on bob)
    //  2. the file bob persisted        (below)
    //  3. GET /api/validators/status    (Dave Jailed, asserted above)
    //  4. the consensus ENGINE itself: who it lets propose which (height, round).
    let three = ["qcb1alice", "qcb1bob", "qcb1carol"];
    assert!(wait_until(Duration::from_secs(120), || height(alice) >= h8 + 9), "JL-08: chain stalled after resuming");
    assert_eq!(persisted_committee(&tmp, "qcb1bob"), three, "JL-08: bob's persisted committee");
    for &p in &api { assert_eq!(committee(p), three, "JL-08: API committee on port {p}"); }
    let mut engine_checked = std::collections::BTreeSet::new();
    for n in LIVE_NODES {
        for (h, r) in proposals_logged(&tmp, n) {
            if h <= h_down + 1 { continue; }
            let expected = three[((h + r as u64) % 3) as usize];
            assert_eq!(n, expected,
                "JL-08: {n} proposed height {h} round {r}, but a 3-seat engine assigns that to {expected} \
                 (the engine still holds a different committee)");
            engine_checked.insert(h);
        }
    }
    assert!(engine_checked.len() >= 4,
        "JL-08: only {} post-restart proposals in the logs; cannot infer the engine's committee",
        engine_checked.len());
    say(format!("✓ JL-08: bob restarted; engine rotation ({} proposals), persisted file, /api/validators and \
        /api/validators/status all agree on the 3-seat committee with Dave Jailed; chain resumed (height {h8})",
        engine_checked.len()));

    // ── JL-09: expiry is not reinstatement ───────────────────────────────────
    let expiry_height = (unjail_after + 2) * EPOCH_BLOCKS;
    say(format!("  waiting for height {expiry_height} (jail expires at epoch {unjail_after}); Dave is online"));
    assert!(wait_until(Duration::from_secs(400), || height(alice) >= expiry_height), "JL-09: epoch {unjail_after} never passed");
    assert!(nodes[3].as_mut().unwrap().alive(), "Dave's process must still be running");
    for &p in &api {
        let s = status_of(p, DAVE).unwrap();
        assert_eq!(s["jail_expired"].as_bool(), Some(true), "JL-09: jail should be expired: {s}");
        assert_eq!(s["status"].as_str(), Some("Jailed"), "JL-09: expiry must not reinstate: {s}");
        assert!(!committee(p).iter().any(|i| i == DAVE), "JL-09: Dave regained a seat on expiry");
    }
    let (h9, root9) = agree(&api, Duration::from_secs(60));
    say(format!("✓ JL-09: jail expired, Dave online and caught up, still Jailed and unseated (height {h9}, root {})", &root9[..12]));

    println!("\n── Summary ──────────────────────────────────────────────────────────");
    println!("   ✓ JL-01..JL-09 passed on the existing 20% / 100-block liveness policy.");
    println!("   NOT established: that this policy cannot jail a live validator (last_commit can");
    println!("   omit late precommits). Do not enable automatic suspension on that basis.");
    println!("   elapsed: {}s   logs: {tmp:?}", t0.elapsed().as_secs());
    println!("────────────────────────────────────────────────────────────────────");
}
