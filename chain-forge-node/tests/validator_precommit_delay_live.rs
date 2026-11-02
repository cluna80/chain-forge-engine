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
//! Requires a node binary built with the feature:
//! ```
//! cargo build -p chain-forge-node --features fault-injection
//! cargo test  -p chain-forge-node --test validator_precommit_delay_live -- --nocapture
//! ```
//! Runtime: roughly 7-8 minutes.

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
use chain_forge_execution::{Transaction, TxBody};

const CHAIN_ID:     &str = "qcb-devnet-val-delay";
const GENESIS_BOND: u64  = 490_000_000;
const NAMES: [&str; 4]   = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];
const DAVE: &str = "qcb1dave";
const BLOCKS_PER_SCENARIO: u64 = 18;
const DELAYS_MS: [u64; 7] = [0, 500, 900, 1500, 2200, 3000, 4500];

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

#[derive(Clone, Debug)]
struct Ev { ts_ms: u64, kind: &'static str, validator: String, height: u64 }

fn trace(dir: &PathBuf, node: &str) -> Vec<Ev> {
    let text = strip_ansi(&std::fs::read_to_string(dir.join(format!("{node}.log"))).unwrap_or_default());
    let field = |l: &str, k: &str| l.split(k).nth(1).map(|r| r.chars().take_while(|c| !c.is_whitespace()).collect::<String>());
    text.lines().filter(|l| l.contains("cf_fault")).filter_map(|l| {
        let kind = ["sent precommit", "recv precommit", "defer precommit", "deliver precommit"].into_iter()
            .find(|k| l.contains(k))?;
        Some(Ev {
            ts_ms: epoch_ms(l.split_whitespace().next()?)?,
            kind: match kind { "sent precommit" => "sent", "recv precommit" => "recv", "defer precommit" => "defer", _ => "deliver" },
            validator: field(l, "validator=").unwrap_or_else(|| node.to_string()),
            height: field(l, "height=")?.parse().ok()?,
        })
    }).collect()
}

struct Row { delay: u64, blocks: u64, sent: u64, received: u64, in_time: u64, included: u64, omitted: u64, counted: u64, mismatches: Vec<String>, median_margin: i64 }

#[test]
fn validator_precommit_delay_live() {
    if !node_bin().exists() { eprintln!("SKIP: node binary missing"); return; }
    let t0 = Instant::now();
    let say = |m: String| println!("[{:>4}s] {m}", t0.elapsed().as_secs());

    let ports: Vec<(u16, u16)> = (0..4).map(|_| (free_port(), free_port())).collect();
    let api: Vec<u16> = ports.iter().map(|p| p.0).collect();
    let tmp = std::env::temp_dir().join(format!("qcb-precommit-delay-{}", api[0]));
    std::fs::create_dir_all(&tmp).unwrap();
    let control = tmp.join("fault-control.txt");
    std::fs::write(&control, "off").unwrap();
    println!("\n── Late-precommit evidence trace (H0-11B) ──────────────────────────");
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

    let mut rows: Vec<Row> = vec![];
    for &delay in &DELAYS_MS {
        std::fs::write(&control, if delay == 0 { "off".to_string() } else { format!("{DAVE} {delay}") }).unwrap();
        std::thread::sleep(Duration::from_secs(7)); // let in-flight deferred votes drain
        let (h0, obs0, miss0) = dave_window(api[0]);
        assert!(wait_until(Duration::from_secs(240), || height(api[0]) >= h0 + BLOCKS_PER_SCENARIO), "chain stalled at delay {delay} ms");
        let (h1, obs1, miss1) = dave_window(api[0]);
        std::thread::sleep(Duration::from_millis(500));

        // Stage data for evidence of blocks h0..h1-1 (published in blocks h0+1..h1).
        let dave_trace = trace(&tmp, DAVE);
        let node_traces: Vec<(&str, Vec<Ev>)> = NAMES.iter().map(|n| (*n, trace(&tmp, n))).collect();
        let mut row = Row { delay, blocks: h1 - h0, sent: 0, received: 0, in_time: 0, included: 0, omitted: 0, counted: miss1 - miss0,
                            mismatches: vec![], median_margin: 0 };
        let mut margins = vec![];
        for hh in h0..h1 {
            let blk = get(api[0], &format!("/api/blocks/{}", hh + 1)).unwrap_or_else(|| panic!("block {} not served", hh + 1));
            let proposer = blk["proposer"].as_str().unwrap().to_string();
            let signers: Vec<String> = blk["last_commit_signers"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
            let included = signers.iter().any(|s| s == DAVE);
            let propose_ms = blk["timestamp_ms"].as_u64().unwrap();
            if included { row.included += 1 } else { row.omitted += 1 }
            let sent = dave_trace.iter().any(|e| e.kind == "sent" && e.height == hh);
            if sent { row.sent += 1 }
            if proposer == DAVE { row.in_time += 1; row.received += 1; continue; } // his own precommit needs no network path
            let evs = &node_traces.iter().find(|(n, _)| *n == proposer).unwrap().1;
            let recv = evs.iter().find(|e| e.kind == "recv" && e.validator == DAVE && e.height == hh);
            let arrival = evs.iter().find(|e| e.kind == "deliver" && e.validator == DAVE && e.height == hh).or(recv);
            if recv.is_some() { row.received += 1 }
            let in_time = arrival.map_or(false, |a| a.ts_ms <= propose_ms);
            if in_time { row.in_time += 1 }
            if let Some(a) = arrival { margins.push(propose_ms as i64 - a.ts_ms as i64); }
            if in_time != included {
                row.mismatches.push(format!("h{hh}: proposer {proposer} arrival {:?} propose {propose_ms} included {included}", arrival.map(|a| a.ts_ms)));
            }
        }
        margins.sort();
        row.median_margin = margins.get(margins.len() / 2).copied().unwrap_or(0);
        assert_eq!(obs1 - obs0, row.blocks, "liveness window must observe one block per height");
        say(format!("delay {:>4} ms: {}/{} in committed evidence, window recorded {} miss(es)", delay, row.included, row.blocks, row.counted));
        rows.push(row);
    }
    std::fs::write(&control, "off").unwrap();

    println!("\n── Per-stage counts for Dave's precommit (per block, healthy validator) ─");
    println!("   delay   blocks  1 sent  2 received  3 in time  4 included  5 counted-as-miss  omitted   median margin (propose - arrival)");
    for r in &rows {
        println!("   {:>4}ms  {:>5}  {:>6}  {:>10}  {:>9}  {:>10}  {:>17}  {:>7}   {:>6} ms",
            r.delay, r.blocks, r.sent, r.received, r.in_time, r.included, r.counted, r.omitted, r.median_margin);
    }
    for r in &rows {
        if !r.mismatches.is_empty() {
            println!("   note: delay {} ms: {} block(s) where 'in time' (by log clocks) disagreed with 'included': {:?}", r.delay, r.mismatches.len(), &r.mismatches[..r.mismatches.len().min(3)]);
        }
    }

    for r in &rows {
        assert_eq!(r.counted, r.omitted, "stage 5: the liveness window must record a miss exactly when Dave is absent from committed evidence (delay {} ms)", r.delay);
        assert_eq!(r.sent, r.blocks, "stage 1: Dave must sign and send a precommit for every block (delay {} ms)", r.delay);
    }
    assert_eq!(rows[0].omitted, 0, "no delay: never omitted");
    assert_eq!(rows[1].omitted, 0, "500 ms is inside the collection window: never omitted");
    let last = rows.last().unwrap();
    assert!(last.omitted * 10 >= last.blocks * 9, "a 4.5 s delay should be omitted from >= 90% of blocks, got {}/{}", last.omitted, last.blocks);
    let dave = get(api[0], "/api/validators/status").and_then(|v| v.as_array().cloned()).unwrap()
        .into_iter().find(|v| v["id"].as_str() == Some(DAVE)).unwrap();
    assert_eq!(dave["status"].as_str(), Some("Active"), "Dave must not be jailed during the experiment");

    let cliff = rows.iter().find(|r| r.omitted * 2 >= r.blocks).map(|r| r.delay);
    println!("\n── Summary ──────────────────────────────────────────────────────────");
    println!("   Dave precommitted on time every block; only its ARRIVAL was delayed.");
    println!("   Delay at which >= half of his precommits were omitted from committed evidence: {}",
        cliff.map_or("none in the tested range".to_string(), |d| format!("{d} ms")));
    println!("   Idle chain (empty mempool); light traffic does not change this (see KNOWN_ISSUES §8).");
    println!("   elapsed: {}s   logs: {tmp:?}", t0.elapsed().as_secs());
    println!("────────────────────────────────────────────────────────────────────");
}
