//! H0-11B evidence integrity (delay layer): where is a late-but-live validator's
//! precommit lost on the way to the liveness record?
//!
//! Four real nodes. Dave is healthy and precommits on time, but his precommits
//! are made to ARRIVE LATE at the other nodes (receiver-side delay, controlled
//! at run time through a file; cargo feature `fault-injection`, see
//! `src/fault.rs`). For each delay, and for every block in the scenario, the
//! test traces Dave's precommit through five stages:
//!
//!   1 sent       Dave logged signing and publishing it
//!   2 received   the proposer of the NEXT block logged its first sight of it
//!   3 in time    it was handed to consensus before that proposer built the
//!                next block (proposal timestamp)
//!   4 included   it is in the next block's committed `last_commit` (API)
//!   5 counted    Dave's liveness window recorded a miss exactly when it was
//!                not included (window counters from the status route)
//!
//! Hard assertions: stage 5 always equals "not included" (the liveness
//! accounting faithfully reflects committed evidence); no delay and a short
//! delay are never omitted; a delay far beyond the collection window almost
//! always is. The in-between delays are MEASURED and printed, not asserted:
//! they locate the cliff.
//!
//! The liveness window here is 1,000 blocks with a 90% threshold so Dave cannot
//! be jailed mid-experiment; this test measures evidence, not suspension.
//!
//! Two experiments share this file:
//!   `validator_precommit_delay_live`         idle chain (empty mempool)
//!   `validator_precommit_delay_loaded_live`  sustained multi-sender load; also
//!       records mempool occupancy at each proposal, txs per block, block
//!       interval and commit-to-proposal time, proves the chain really was
//!       loaded, attributes every omission to the evidence cutoff, and checks
//!       all four nodes agree on committed evidence and liveness state.
//!
//! Requires a node binary built with the feature:
//! ```
//! cargo build -p chain-forge-node --features fault-injection
//! cargo test  -p chain-forge-node --features fault-injection --test validator_precommit_delay_live -- --nocapture
//! ```
//! Runtime: roughly 7-8 minutes per experiment. `CF_DELAY_TEST_DELAYS=0,1500`
//! (comma-separated ms) overrides the delays for a quick probe.

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{atomic::{AtomicBool, Ordering}, Arc},
    time::{Duration, Instant},
};

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
use chain_forge_execution::{Transaction, TxBody};

const CHAIN_ID:     &str = "qcb-devnet-val-delay";
const GENESIS_BOND: u64  = 490_000_000;
const NAMES: [&str; 4]   = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
const DAVE: &str = "qcb1dave";
const BLOCKS_PER_SCENARIO: u64 = 18;
const IDLE_DELAYS_MS: [u64; 7] = [0, 500, 900, 1500, 2200, 3000, 4500];
// The trailing 0 is a control: it must look like the first 0, or the chain drifted.
const LOADED_DELAYS_MS: [u64; 8] = [0, 500, 900, 1200, 1500, 2200, 3000, 0];

/// Ports below the OS ephemeral range: outgoing connections made by the
/// other nodes while they start can otherwise grab a port picked here.
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

fn spawn(name: &str, api: u16, p2p: u16, peers: &[u16], dir: &PathBuf, control: &PathBuf) -> NodeHandle {
    let data = dir.join(format!("data-{}", name.trim_start_matches("qcb1")));
    std::fs::create_dir_all(&data).unwrap();
    let log = std::fs::File::create(dir.join(format!("{name}.log"))).unwrap();
    let mut cmd = Command::new(node_bin());
    cmd.arg("--genesis").arg(devnet("genesis-val-delay.json"))
       .arg("--validator").arg(name)
       .arg("--api-port").arg(api.to_string())
       .arg("--p2p-port").arg(p2p.to_string())
       .arg("--data-dir").arg(&data)
       .arg("--key-file").arg(devnet("keys").join(format!("{}.key.json", name.trim_start_matches("qcb1"))));
    for p in peers { cmd.arg("--bootstrap").arg(format!("/ip4/127.0.0.1/tcp/{p}")); }
    // info for everything; the fault-injection trace target is info too.
    cmd.env("CF_FAULT_CONTROL_FILE", control).env("RUST_LOG", "info");
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
    while Instant::now() < end { if f() { return true; } std::thread::sleep(Duration::from_millis(200)); }
    false
}

fn bond_tx(who: &str, n: u64) -> Transaction {
    let mut tx = Transaction::bond_validator(&format!("bond-{who}-{n}"), who, GENESIS_BOND as u128, n);
    if let TxBody::BondValidator { ref mut owner_identity_id, .. } = tx.body { *owner_identity_id = Some(who.to_string()); }
    tx.sign(&ClassicalScheme.generate_keypair(who).unwrap(), CHAIN_ID).unwrap();
    tx
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

/// Dave's liveness counters at a height that did not move while reading.
fn dave_window(port: u16) -> (u64, u64, u64) {
    for _ in 0..50 {
        let h1 = height(port);
        let s = get(port, "/api/validators/status").and_then(|v| v.as_array().cloned()).unwrap_or_default();
        let h2 = height(port);
        if h1 == h2 {
            if let Some(d) = s.iter().find(|v| v["id"].as_str() == Some(DAVE)) {
                return (h1, d["liveness_observed"].as_u64().unwrap(), d["liveness_missed"].as_u64().unwrap());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("no stable liveness snapshot");
}

// ── Log trace parsing ─────────────────────────────────────────────────────────

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' { while let Some(&n) = it.peek() { it.next(); if n == 'm' { break; } } } else { out.push(c); }
    }
    out
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// "2026-11-02T02:53:05.124292Z" -> epoch milliseconds.
fn epoch_ms(ts: &str) -> Option<u64> {
    let (date, time) = ts.trim_end_matches('Z').split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, dd) = (d.next()??, d.next()??, d.next()??);
    let mut t = time.split(':');
    let (h, mi) = (t.next()?.parse::<f64>().ok()?, t.next()?.parse::<f64>().ok()?);
    let s = t.next()?.parse::<f64>().ok()?;
    Some(((days_from_civil(y, m, dd) as f64 * 86_400.0 + h * 3600.0 + mi * 60.0 + s) * 1000.0) as u64)
}

#[derive(Clone, Debug, Default)]
struct Ev { ts_ms: u64, kind: &'static str, validator: String, height: u64, round: u64,
            mempool: u64, since_commit_ms: u64, evidence: u64, included_txs: u64 }

fn trace(dir: &PathBuf, node: &str) -> Vec<Ev> {
    let text = strip_ansi(&std::fs::read_to_string(dir.join(format!("{node}.log"))).unwrap_or_default());
    let field = |l: &str, k: &str| l.split(k).nth(1).map(|r| r.chars().take_while(|c| !c.is_whitespace()).collect::<String>());
    let num = |l: &str, k: &str| field(l, k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    text.lines().filter_map(|l| {
        let kind = ["sent precommit", "recv precommit", "defer precommit", "deliver precommit", "propose context"].into_iter()
            .find(|k| l.contains(k))?;
        Some(Ev {
            ts_ms: epoch_ms(l.split_whitespace().next()?)?,
            kind: match kind { "sent precommit" => "sent", "recv precommit" => "recv", "defer precommit" => "defer",
                               "deliver precommit" => "deliver", _ => "propose" },
            validator: field(l, "validator=").unwrap_or_else(|| node.to_string()),
            height: field(l, "height=")?.parse().ok()?,
            round: num(l, "round="),
            mempool: num(l, "mempool="),
            since_commit_ms: num(l, "since_commit_ms="),
            evidence: num(l, "evidence_precommits="),
            included_txs: num(l, "included_txs="),
        })
    }).collect()
}

fn median(v: &mut Vec<i64>) -> i64 { v.sort(); v.get(v.len() / 2).copied().unwrap_or(0) }

/// Four nodes serve identical validator status (incl. liveness windows) and
/// state root at one height.
fn stable_status(port: u16) -> Option<(u64, String)> {
    let h1 = height(port);
    let body = get(port, "/api/validators/status")?;
    let h2 = height(port);
    (h1 == h2).then(|| (h1, body.to_string()))
}

fn assert_nodes_agree(api: &[u16]) {
    for _ in 0..60 {
        let snaps: Vec<Option<(u64, String)>> = api.iter().map(|&p| stable_status(p)).collect();
        if snaps.iter().all(Option::is_some) {
            let snaps: Vec<(u64, String)> = snaps.into_iter().map(Option::unwrap).collect();
            if snaps.iter().all(|s| s.0 == snaps[0].0) {
                let roots: Vec<Option<String>> = api.iter()
                    .map(|&p| get(p, "/api/status").and_then(|v| v["state_root"].as_str().map(str::to_string))).collect();
                if api.iter().all(|&p| height(p) == snaps[0].0) {
                    for (i, sn) in snaps.iter().enumerate() {
                        assert_eq!(sn.1, snaps[0].1, "node {i} validator status/liveness window differs at height {}", sn.0);
                        assert_eq!(roots[i], roots[0], "node {i} state root differs at height {}", sn.0);
                    }
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("could not take a same-height snapshot of all four nodes");
}

/// Committed evidence for blocks h0..=h1 is identical on every node.
fn assert_evidence_agrees(api: &[u16], h0: u64, h1: u64) {
    for hh in h0..=h1 {
        let views: Vec<String> = api.iter().map(|&p| {
            let b = get(p, &format!("/api/blocks/{hh}")).unwrap_or_else(|| panic!("node on port {p} does not serve block {hh}"));
            format!("{}|{}|{}|{}", b["block_hash"], b["proposer"], b["round"], b["last_commit_signers"])
        }).collect();
        assert!(views.iter().all(|v| *v == views[0]), "nodes disagree on committed evidence at block {hh}: {views:?}");
    }
}

// Small on purpose: persist_state rewrites the whole chain store every commit (KNOWN_ISSUES §9),
// so a heavy load slows the chain during the run and makes the scenarios incomparable.
const LOAD_ACCOUNTS: usize = 8;

fn load_addr(k: usize) -> String { format!("qcb1ld{k:02}") }

/// Pipelined nonces fail under gossip (a proposer can see tx 53 without 29..52 and
/// execution then rejects it, wedging the sender), so the load uses MANY accounts
/// that each keep exactly one transaction in flight. This funds them first.
fn fund_load_accounts(api: &[u16]) {
    let funders = [("qcb1alice", api[0]), ("qcb1bob", api[1]), ("qcb1carol", api[2]), ("qcb1dave", api[3])];
    let mut k = 0;
    while k < LOAD_ACCOUNTS {
        let mut ids = vec![];
        for (who, port) in funders.iter() {
            if k >= LOAD_ACCOUNTS { break; }
            let mut tx = Transaction::transfer(&format!("fund-{k}"), who, &load_addr(k), "uqcb", 5_000_000, nonce(*port, who));
            tx.sign(&ClassicalScheme.generate_keypair(who).unwrap(), CHAIN_ID).unwrap();
            let r = http("POST", *port, "/api/tx", &serde_json::to_string(&tx).unwrap()).unwrap_or_default();
            assert_eq!(r["status"].as_str(), Some("queued"), "funding tx {k} not queued: {r}");
            ids.push((*port, tx.id.clone()));
            k += 1;
        }
        for (port, id) in ids {
            let end = Instant::now() + Duration::from_secs(40);
            loop {
                let r = get(port, &format!("/api/tx/{id}")).unwrap_or_default();
                if r["success"].as_bool() == Some(true) { break; }
                assert!(r["success"].as_bool() != Some(false), "funding tx {id} failed: {r}");
                assert!(Instant::now() < end, "funding tx {id} never landed");
                std::thread::sleep(Duration::from_millis(300));
            }
        }
    }
}

/// Sustained load: LOAD_ACCOUNTS accounts, one transaction in flight each.
fn start_load(api: Vec<u16>) -> (Arc<AtomicBool>, std::thread::JoinHandle<u64>) {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let handle = std::thread::spawn(move || {
        let mut sent: Vec<Option<(u64, Instant)>> = vec![None; LOAD_ACCOUNTS];
        let mut queued = 0u64;
        while !flag.load(Ordering::Relaxed) {
            for k in 0..LOAD_ACCOUNTS {
                if flag.load(Ordering::Relaxed) { break; }
                let (addr, port) = (load_addr(k), api[k % 4]);
                let committed = nonce(port, &addr);
                let due = match sent[k] {
                    None => true,
                    Some((n, at)) => committed > n || at.elapsed() > Duration::from_secs(8),
                };
                if !due { continue; }
                let mut tx = Transaction::transfer(&format!("ld-{addr}-{committed}"), &addr, "qcb1alice", "uqcb", 1, committed);
                tx.sign(&ClassicalScheme.generate_keypair(&addr).unwrap(), CHAIN_ID).unwrap();
                let ok = http("POST", port, "/api/tx", &serde_json::to_string(&tx).unwrap())
                    .map_or(false, |r| r["status"].as_str() == Some("queued"));
                if ok { sent[k] = Some((committed, Instant::now())); queued += 1; }
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        queued
    });
    (stop, handle)
}

struct Row {
    delay: u64, blocks: u64, own: u64, sent: u64, received: u64, in_time: u64, included: u64,
    counted: u64, omitted: u64, unattributed: Vec<String>, anomalies: Vec<String>,
    margin: i64, mempool: i64, txs_per_block: i64, since_commit: i64, interval: i64,
    loaded_proposals: u64, proposals_seen: u64, txs_committed: u64,
}

fn delays_for(default: &[u64]) -> Vec<u64> {
    std::env::var("CF_DELAY_TEST_DELAYS").ok()
        .map(|v| v.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .filter(|v: &Vec<u64>| !v.is_empty())
        .unwrap_or_else(|| default.to_vec())
}

fn run(loaded: bool) {
    if !node_bin().exists() { eprintln!("SKIP: node binary missing"); return; }
    let delays = delays_for(if loaded { &LOADED_DELAYS_MS } else { &IDLE_DELAYS_MS });
    let t0 = Instant::now();
    let say = |m: String| println!("[{:>4}s] {m}", t0.elapsed().as_secs());

    let ports: Vec<(u16, u16)> = (0..4).map(|_| (free_port(), free_port())).collect();
    let api: Vec<u16> = ports.iter().map(|p| p.0).collect();
    let tmp = std::env::temp_dir().join(format!("qcb-precommit-delay-{}-{}", if loaded { "loaded" } else { "idle" }, api[0]));
    std::fs::create_dir_all(&tmp).unwrap();
    let control = tmp.join("fault-control.txt");
    std::fs::write(&control, "off").unwrap();
    println!("\n── Late-precommit evidence trace, {} chain (H0-11B) ───────────────", if loaded { "LOADED" } else { "idle" });
    println!("   logs: {tmp:?}");

    let _nodes: Vec<NodeHandle> = (0..4).map(|i| {
        let peers: Vec<u16> = (0..4).filter(|&j| j != i).map(|j| ports[j].1).collect();
        spawn(NAMES[i], ports[i].0, ports[i].1, &peers, &tmp, &control)
    }).collect();
    assert!(wait_until(Duration::from_secs(90), || api.iter().all(|&p| height(p) >= 3)), "devnet did not start");
    std::thread::sleep(Duration::from_secs(1));
    let active = (0..4).all(|i| {
        std::fs::read_to_string(tmp.join(format!("{}.log", NAMES[i]))).map_or(false, |t| t.contains("fault injection ACTIVE"))
    });
    assert!(active, "this node binary was built WITHOUT the fault-injection feature.\n\
        Run: cargo build -p chain-forge-node --features fault-injection");

    for (i, who) in NAMES.iter().enumerate() {
        let r = submit_and_wait(api[i], &bond_tx(who, nonce(api[i], who)));
        assert!(r["success"].as_bool().unwrap_or(false), "bond for {who} failed: {r}");
    }
    let h = height(api[0]);
    assert!(wait_until(Duration::from_secs(60), || height(api[0]) >= h + 12), "chain stalled after bonds");
    say("four validators bonded; fault injection active on all four nodes".into());

    if loaded {
        fund_load_accounts(&api);
        say(format!("{LOAD_ACCOUNTS} load accounts funded"));
    }
    let load = if loaded { Some(start_load(api.clone())) } else { None };
    if loaded {
        // Prove the load is real BEFORE measuring: committed txs must be flowing.
        let h_start = height(api[0]);
        assert!(wait_until(Duration::from_secs(120), || height(api[0]) >= h_start + 8), "chain stalled under load");
        let committed: u64 = (h_start + 1..=height(api[0])).filter_map(|b| get(api[0], &format!("/api/blocks/{b}")))
            .map(|b| b["tx_count"].as_u64().unwrap_or(0)).sum();
        assert!(committed >= 40, "the load generator is not producing committed transactions (only {committed} in 8 blocks); \
            this run would have measured an idle chain");
        say(format!("load verified: {committed} txs committed in the last 8 blocks"));
    }

    let mut rows: Vec<Row> = vec![];
    for &delay in &delays {
        std::fs::write(&control, if delay == 0 { "off".to_string() } else { format!("{DAVE} {delay}") }).unwrap();
        std::thread::sleep(Duration::from_secs(7));
        let (h0, obs0, miss0) = dave_window(api[0]);
        assert!(wait_until(Duration::from_secs(300), || height(api[0]) >= h0 + BLOCKS_PER_SCENARIO), "chain stalled at delay {delay} ms");
        let (h1, obs1, miss1) = dave_window(api[0]);
        std::thread::sleep(Duration::from_millis(500));

        let dave_trace = trace(&tmp, DAVE);
        let node_traces: Vec<(&str, Vec<Ev>)> = NAMES.iter().map(|n| (*n, trace(&tmp, n))).collect();
        let mut row = Row { delay, blocks: h1 - h0, own: 0, sent: 0, received: 0, in_time: 0, included: 0, counted: miss1 - miss0, omitted: 0,
            unattributed: vec![], anomalies: vec![], margin: 0, mempool: 0, txs_per_block: 0, since_commit: 0, interval: 0,
            loaded_proposals: 0, proposals_seen: 0, txs_committed: 0 };
        let (mut margins, mut mempools, mut txs, mut since, mut intervals) = (vec![], vec![], vec![], vec![], vec![]);
        let mut prev_ts: Option<u64> = None;
        for hh in h0..h1 {
            let blk = get(api[0], &format!("/api/blocks/{}", hh + 1)).unwrap_or_else(|| panic!("block {} not served", hh + 1));
            let proposer = blk["proposer"].as_str().unwrap().to_string();
            let round = blk["round"].as_u64().unwrap_or(0);
            let signers: Vec<String> = blk["last_commit_signers"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
            let included = signers.iter().any(|x| x == DAVE);
            let propose_ms = blk["timestamp_ms"].as_u64().unwrap();
            row.txs_committed += blk["tx_count"].as_u64().unwrap_or(0);
            txs.push(blk["tx_count"].as_u64().unwrap_or(0) as i64);
            if let Some(p) = prev_ts { intervals.push(propose_ms as i64 - p as i64); }
            prev_ts = Some(propose_ms);
            if included { row.included += 1 } else { row.omitted += 1 }
            if dave_trace.iter().any(|e| e.kind == "sent" && e.height == hh) { row.sent += 1 }

            let evs = &node_traces.iter().find(|(n, _)| *n == proposer).unwrap().1;
            if let Some(c) = evs.iter().find(|e| e.kind == "propose" && e.height == hh + 1 && e.round == round) {
                row.proposals_seen += 1;
                if c.mempool > 0 { row.loaded_proposals += 1 }
                mempools.push(c.mempool as i64);
                since.push(c.since_commit_ms as i64);
            }
            if proposer == DAVE { row.own += 1; continue; }

            let recv = evs.iter().find(|e| e.kind == "recv" && e.validator == DAVE && e.height == hh);
            let deliver = evs.iter().find(|e| e.kind == "deliver" && e.validator == DAVE && e.height == hh);
            // Arrival at consensus: the logged delivery, or (if the delayed delivery is not
            // yet in the log at read time) first sight plus the injected delay.
            let arrival = deliver.map(|d| d.ts_ms).or(recv.map(|r| r.ts_ms + delay));
            if recv.is_some() { row.received += 1 }
            let in_time = arrival.map_or(false, |a| a <= propose_ms);
            if in_time { row.in_time += 1 }
            if let Some(a) = arrival { margins.push(propose_ms as i64 - a as i64); }
            if !included && !(recv.is_some() && !in_time) {
                row.unattributed.push(format!("h{hh}: omitted but recv={} in_time={in_time} (proposer {proposer})", recv.is_some()));
            }
            if included && !in_time {
                row.anomalies.push(format!("h{hh}: included although arrival {:?} > propose {propose_ms} (proposer {proposer})", arrival));
            }
        }
        row.margin = median(&mut margins);
        row.mempool = median(&mut mempools);
        row.txs_per_block = median(&mut txs);
        row.since_commit = median(&mut since);
        row.interval = median(&mut intervals);

        assert_eq!(obs1 - obs0, row.blocks, "liveness window must observe one block per height");
        assert_evidence_agrees(&api, h0, h1);
        assert_nodes_agree(&api);
        say(format!("delay {:>4} ms: {}/{} in committed evidence, window recorded {} miss(es), median mempool at proposal {}",
            delay, row.included, row.blocks, row.counted, row.mempool));
        rows.push(row);
    }
    std::fs::write(&control, "off").unwrap();
    let queued = load.map(|(stop, h)| { stop.store(true, Ordering::Relaxed); h.join().unwrap() });

    println!("\n── Per-stage counts for Dave's precommit ({} chain) ─────────────────", if loaded { "LOADED" } else { "idle" });
    println!("   Blocks Dave proposed himself ('own') are excluded from stages 2-3.");
    println!("   delay  blocks own | 1 sent 2 recv 3 in-time 4 included 5 counted | omitted unattrib | margin  | mempool txs/blk commit->propose interval");
    for r in &rows {
        println!("   {:>4}ms {:>5} {:>3} | {:>6} {:>6} {:>9} {:>10} {:>9} | {:>7} {:>8} | {:>5}ms | {:>7} {:>7} {:>9}ms {:>8}ms",
            r.delay, r.blocks, r.own, r.sent, r.received, r.in_time, r.included, r.counted, r.omitted, r.unattributed.len(),
            r.margin, r.mempool, r.txs_per_block, r.since_commit, r.interval);
    }
    if let Some(q) = queued { println!("   load: {q} transactions queued by {LOAD_ACCOUNTS} accounts (one in flight each)"); }
    for r in &rows {
        for a in r.anomalies.iter().take(2) { println!("   note (delay {} ms): {a}", r.delay); }
    }

    for r in &rows {
        assert_eq!(r.counted, r.omitted, "stage 5: the window must record a miss exactly when Dave is absent from committed evidence (delay {} ms)", r.delay);
        assert_eq!(r.sent, r.blocks, "stage 1: Dave must send a precommit for every block (delay {} ms)", r.delay);
        assert!(r.unattributed.is_empty(), "measurement integrity: omissions not explained by the evidence cutoff at delay {} ms: {:?}", r.delay, r.unattributed);
        if loaded {
            assert!(r.proposals_seen * 10 >= (r.blocks) * 9, "could not observe the proposer context for {}/{} blocks (delay {} ms)", r.proposals_seen, r.blocks, r.delay);
            assert!(r.loaded_proposals * 4 >= r.proposals_seen * 3,
                "the chain was not loaded at delay {} ms: mempool non-empty at only {}/{} proposals", r.delay, r.loaded_proposals, r.proposals_seen);
        }
    }
    if loaded {
        let base = rows[0].interval.max(1);
        for r in &rows {
            assert!(r.interval * 2 <= base * 3 + 600,
                "the chain slowed during the experiment (median block interval {} ms at delay {} ms vs {} ms at the start); \
                 scenarios are not comparable", r.interval, r.delay, rows[0].interval);
        }
        let (first, ctl) = (&rows[0], rows.last().unwrap());
        println!("   control: delay 0 at start omitted {} of {}, at end {} of {} (block interval {} ms -> {} ms)",
            first.omitted, first.blocks - first.own, ctl.omitted, ctl.blocks - ctl.own, first.interval, ctl.interval);
    }
    if !loaded {
        assert_eq!(rows[0].omitted, 0, "no delay: never omitted");
        assert_eq!(rows[1].omitted, 0, "500 ms is inside the collection window: never omitted");
        let last = rows.last().unwrap();
        let networked = last.blocks - last.own;
        assert!(last.omitted * 10 >= networked * 9, "a 4.5 s delay should be omitted from >= 90% of networked blocks, got {}/{}", last.omitted, networked);
    }
    let dave = get(api[0], "/api/validators/status").and_then(|v| v.as_array().cloned()).unwrap()
        .into_iter().find(|v| v["id"].as_str() == Some(DAVE)).unwrap();
    assert_eq!(dave["status"].as_str(), Some("Active"), "Dave must not be jailed during the experiment");

    let cliff = rows.iter().find(|r| r.omitted * 2 >= r.blocks - r.own).map(|r| r.delay);
    println!("\n── Summary ──────────────────────────────────────────────────────────");
    println!("   Dave precommitted on time every block; only its ARRIVAL was delayed.");
    println!("   First delay at which >= half of his networked precommits were omitted: {}",
        cliff.map_or("none in the tested range".to_string(), |d| format!("{d} ms")));
    println!("   Chain: {}.", if loaded { "sustained load (mempool non-empty at >= 75% of proposals in every scenario)" } else { "idle (empty mempool)" });
    println!("   elapsed: {}s   logs: {tmp:?}", t0.elapsed().as_secs());
    println!("────────────────────────────────────────────────────────────────────");
}

#[test]
fn validator_precommit_delay_live() { run(false); }

#[test]
fn validator_precommit_delay_loaded_live() { run(true); }
