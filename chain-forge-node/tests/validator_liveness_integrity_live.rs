//! H0-11B evidence integrity (live layer): do HEALTHY validators get recorded as
//! missing duties on a real network, and do all nodes agree on that record?
//!
//! FP-01  Healthy four-node network, idle then under transaction load, across a
//!        full 100-block liveness window each: nobody is jailed. The highest
//!        miss percentage any healthy validator showed is REPORTED (it is the
//!        measured false-positive input for the policy in
//!        `chain-forge-slashing/tests/liveness_false_positive.rs`).
//! FP-06  At several heights, all four nodes serve an identical
//!        GET /api/validators/status (status, bond, jail record AND liveness
//!        window of every validator), and identical state roots.
//!
//! The load phase matters: with an empty mempool a proposer idles ~2 s before
//! proposing, which also gives late precommits ~2 s to arrive; with traffic it
//! proposes as soon as COMMIT_GATHER_MS (1 s) has passed.
//!
//! This is a LOOPBACK measurement: precommit latency here is microseconds to a
//! few milliseconds, so it bounds the policy's behaviour on a good network, not
//! on a WAN. Delay-injected measurement is a separate decision (see
//! KNOWN_ISSUES §8). Nothing here changes the threshold or enables suspension.
//!
//! Runtime: roughly 8-9 minutes.
//!
//! ## Run
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test validator_liveness_integrity_live -- --nocapture
//! ```

use std::{
    collections::BTreeMap,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{atomic::{AtomicBool, Ordering}, Arc},
    time::{Duration, Instant},
};

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
use chain_forge_execution::{Transaction, TxBody};

const CHAIN_ID:     &str = "qcb-devnet-val-jail";
const GENESIS_BOND: u64  = 490_000_000;
const NAMES: [&str; 4]   = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];

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
fn repo_root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf() }
fn node_bin() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|_| repo_root().join("target"));
    target.join("debug").join(format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX))
}
fn devnet(file: &str) -> PathBuf { repo_root().join("tests").join("devnet").join(file) }

struct NodeHandle(Child);
impl Drop for NodeHandle { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

fn spawn(name: &str, api: u16, p2p: u16, peers: &[u16], dir: &PathBuf) -> NodeHandle {
    let data = dir.join(format!("data-{}", name.trim_start_matches("qcb1")));
    std::fs::create_dir_all(&data).unwrap();
    let log = std::fs::File::create(dir.join(format!("{name}.log"))).unwrap();
    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(devnet("genesis-val-jail.json"))
       .arg("--validator").arg(name)
       .arg("--api-port").arg(api.to_string())
       .arg("--p2p-port").arg(p2p.to_string())
       .arg("--data-dir").arg(&data)
       .arg("--key-file").arg(devnet("keys").join(format!("{}.key.json", name.trim_start_matches("qcb1"))));
    for p in peers { cmd.arg("--bootstrap").arg(format!("/ip4/127.0.0.1/tcp/{p}")); }
    cmd.stdout(log.try_clone().unwrap()).stderr(log).stdin(Stdio::null());
    NodeHandle(cmd.spawn().unwrap_or_else(|e| panic!("spawn {name}: {e}")))
}

fn http(method: &str, port: u16, path: &str, body: &str) -> Option<serde_json::Value> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(500)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;
    let req = format!("{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1).unwrap_or("")).ok()
}
fn get(port: u16, path: &str) -> Option<serde_json::Value> { http("GET", port, path, "") }
fn height(port: u16) -> u64 { get(port, "/api/status").and_then(|v| v["height"].as_u64()).unwrap_or(0) }
fn nonce(port: u16, addr: &str) -> u64 { get(port, &format!("/api/accounts/{addr}")).and_then(|v| v["nonce"].as_u64()).unwrap_or(0) }

fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end { if f() { return true; } std::thread::sleep(Duration::from_millis(250)); }
    false
}

fn signed_tx(mut tx: Transaction, who: &str) -> Transaction {
    tx.sign(&ClassicalScheme.generate_keypair(who).unwrap(), CHAIN_ID).unwrap();
    tx
}

fn bond_tx(who: &str, n: u64) -> Transaction {
    let mut tx = Transaction::bond_validator(&format!("bond-{who}-{n}"), who, GENESIS_BOND as u128, n);
    if let TxBody::BondValidator { ref mut owner_identity_id, .. } = tx.body { *owner_identity_id = Some(who.to_string()); }
    signed_tx(tx, who)
}

fn submit_and_wait(port: u16, tx: &Transaction) -> serde_json::Value {
    let r = http("POST", port, "/api/tx", &serde_json::to_string(tx).unwrap()).unwrap_or_default();
    assert_eq!(r["status"].as_str(), Some("queued"), "tx {} not queued: {r}", tx.id);
    let end = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end {
        if let Some(v) = get(port, &format!("/api/tx/{}", tx.id)) { if v["success"].as_bool().is_some() { return v; } }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("tx {} never landed", tx.id);
}

/// A status snapshot that did not straddle a commit: (height, status array as text).
fn stable_status(port: u16) -> Option<(u64, String)> {
    let h1 = height(port);
    let body = get(port, "/api/validators/status")?;
    let h2 = height(port);
    (h1 == h2).then(|| (h1, body.to_string()))
}

/// FP-06: all four nodes serve the same validator status and state root at one height.
fn assert_nodes_agree(api: &[u16]) -> u64 {
    for _ in 0..40 {
        let snaps: Vec<Option<(u64, String)>> = api.iter().map(|&p| stable_status(p)).collect();
        if snaps.iter().all(Option::is_some) {
            let snaps: Vec<(u64, String)> = snaps.into_iter().map(Option::unwrap).collect();
            if snaps.iter().all(|s| s.0 == snaps[0].0) {
                let roots: Vec<Option<String>> = api.iter()
                    .map(|&p| get(p, "/api/status").and_then(|v| v["state_root"].as_str().map(str::to_string))).collect();
                let h_after: Vec<u64> = api.iter().map(|&p| height(p)).collect();
                if h_after.iter().all(|&h| h == snaps[0].0) {
                    for (i, s) in snaps.iter().enumerate() {
                        assert_eq!(s.1, snaps[0].1, "FP-06: node {i} validator status differs at height {}", s.0);
                        assert_eq!(roots[i], roots[0], "FP-06: node {i} state root differs at height {}", s.0);
                    }
                    return snaps[0].0;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("FP-06: could not take a same-height snapshot of all four nodes");
}

#[derive(Default, Clone)]
struct Seen { max_missed_pct: u64, window: u64 }

#[test]
fn validator_liveness_integrity_live() {
    if !node_bin().exists() { eprintln!("SKIP: node binary missing; run `cargo build -p chain-forge-node`"); return; }
    let t0 = Instant::now();
    let say = |m: String| println!("[{:>4}s] {m}", t0.elapsed().as_secs());

    let ports: Vec<(u16, u16)> = (0..4).map(|_| (free_port(), free_port())).collect();
    let api: Vec<u16> = ports.iter().map(|p| p.0).collect();
    let tmp = std::env::temp_dir().join(format!("qcb-liveness-integrity-{}", api[0]));
    std::fs::create_dir_all(&tmp).unwrap();
    println!("\n── Liveness evidence integrity (H0-11B FP-01 / FP-06) ──────────────");
    println!("   logs: {tmp:?}");

    let _nodes: Vec<NodeHandle> = (0..4).map(|i| {
        let peers: Vec<u16> = (0..4).filter(|&j| j != i).map(|j| ports[j].1).collect();
        spawn(NAMES[i], ports[i].0, ports[i].1, &peers, &tmp)
    }).collect();
    assert!(wait_until(Duration::from_secs(90), || api.iter().all(|&p| height(p) >= 3)), "devnet did not start");

    for (i, who) in NAMES.iter().enumerate() {
        let r = submit_and_wait(api[i], &bond_tx(who, nonce(api[i], who)));
        assert!(r["success"].as_bool().unwrap_or(false), "bond for {who} failed: {r}");
    }
    let h = height(api[0]);
    assert!(wait_until(Duration::from_secs(60), || height(api[0]) >= h + 6), "no epoch after bonds");
    say("four validators bonded and seated".into());

    // Sample all four validators' liveness windows from node 0, flag any jail.
    let mut seen: BTreeMap<&str, Seen> = NAMES.iter().map(|n| (*n, Seen::default())).collect();
    let mut sample = |seen: &mut BTreeMap<&str, Seen>| {
        let arr = get(api[0], "/api/validators/status").and_then(|v| v.as_array().cloned()).unwrap_or_default();
        for v in arr {
            let id = v["id"].as_str().unwrap_or("");
            if let Some(s) = seen.get_mut(id) {
                assert_eq!(v["status"].as_str(), Some("Active"), "FP-01: healthy validator {id} left Active: {v}");
                s.max_missed_pct = s.max_missed_pct.max(v["liveness_missed_pct"].as_u64().unwrap_or(0));
                s.window = v["liveness_observed"].as_u64().unwrap_or(0);
            }
        }
    };
    let report = |label: &str, seen: &BTreeMap<&str, Seen>| {
        for (id, s) in seen {
            println!("         {label:<6} {id:<10} window={:<3} max plain miss over the phase = {}%", s.window, s.max_missed_pct);
        }
    };

    // ── Phase 1: idle network (empty mempool: proposers idle ~2 s per block) ──
    let start1 = height(api[0]);
    let t1 = Instant::now();
    let mut agreements = 0;
    let mut next_agree = start1 + 25;
    assert!(wait_until(Duration::from_secs(420), || {
        sample(&mut seen);
        let h = height(api[0]);
        if h >= next_agree { assert_nodes_agree(&api); agreements += 1; next_agree = h + 25; }
        h >= 128 && seen.values().all(|s| s.window >= 100)
    }), "FP-01: phase 1 did not fill every liveness window");
    let blocks1 = height(api[0]) - start1;
    say(format!("✓ FP-01 idle: {blocks1} blocks in {}s ({:.1}s/block), full 100-block windows, nobody jailed",
        t1.elapsed().as_secs(), t1.elapsed().as_secs_f64() / blocks1 as f64));
    report("idle", &seen);
    let idle_max = seen.values().map(|s| s.max_missed_pct).max().unwrap();

    // ── Phase 2: sustained transaction load (proposers do not idle) ───────────
    let stop = Arc::new(AtomicBool::new(false));
    let sender_nonce = nonce(api[2], "qcb1carol");
    let load = {
        let stop = stop.clone();
        let port = api[2];
        std::thread::spawn(move || {
            let mut n = sender_nonce;
            let mut sent = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let tx = signed_tx(Transaction::transfer(&format!("load-{n}"), "qcb1carol", "qcb1eve", "uqcb", 1, n), "qcb1carol");
                if http("POST", port, "/api/tx", &serde_json::to_string(&tx).unwrap())
                    .map_or(false, |r| r["status"].as_str() == Some("queued")) { n += 1; sent += 1; }
                std::thread::sleep(Duration::from_millis(350));
            }
            sent
        })
    };
    for s in seen.values_mut() { s.max_missed_pct = 0; }
    let start2 = height(api[0]);
    let t2 = Instant::now();
    let ok = wait_until(Duration::from_secs(480), || {
        sample(&mut seen);
        let h = height(api[0]);
        if h >= next_agree { assert_nodes_agree(&api); agreements += 1; next_agree = h + 25; }
        h >= start2 + 105
    });
    stop.store(true, Ordering::Relaxed);
    let sent = load.join().unwrap();
    assert!(ok, "FP-01: loaded phase did not complete");
    let blocks2 = height(api[0]) - start2;
    say(format!("✓ FP-01 loaded: {blocks2} blocks in {}s ({:.1}s/block), {sent} txs sent, nobody jailed",
        t2.elapsed().as_secs(), t2.elapsed().as_secs_f64() / blocks2 as f64));
    report("loaded", &seen);
    let load_max = seen.values().map(|s| s.max_missed_pct).max().unwrap();

    let h_final = assert_nodes_agree(&api);
    assert!(agreements >= 4, "FP-06: only {agreements} mid-run agreement checks");
    say(format!("✓ FP-06: {} same-height agreement checks (validator status incl. liveness windows + state root), final at height {h_final}", agreements + 1));

    println!("\n── Summary ──────────────────────────────────────────────────────────");
    println!("   Healthy validators, loopback: worst plain miss over a window = {idle_max}% idle, {load_max}% under load (threshold 20%).");
    println!("   This bounds behaviour on a good network only; it says nothing about WAN delay.");
    println!("   elapsed: {}s   logs: {tmp:?}", t0.elapsed().as_secs());
    println!("────────────────────────────────────────────────────────────────────");
}
