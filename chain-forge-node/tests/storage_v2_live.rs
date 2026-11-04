//! PERSIST-001 P-02b PR 2 — storage format 2: live four-node crash and restart acceptance (EXPERIMENTAL).
//!
//! Four real node processes. The `v2_*` tests start every node with `--storage-v2-experimental` (default OFF); the `v1_*`
//! tests run the SAME scenarios on the default (production) storage with no flag, for the three boundaries v1 has.
//!
//! V2L-1  a node ABORTS at each v2 commit boundary (after the block-log append, after the validator-history append,
//!        after the generation files, after the manifest, after CURRENT): the process dies with no cleanup; on
//!        restart it logs the selected format, resumes at the committed height (the previous block before CURRENT,
//!        the new block after it), catches up, and all four state roots agree. The exclusive lock is free again.
//! V2L-2  SIGKILL of a different node at several heights (5, 15, 30): restart, catch-up, root agreement each time;
//!        a second process on a running node's data directory is refused (OS lock) and exits.
//! No node log may report equivocation; every node log names the storage format it selected.
//!
//! Needs a node built WITH the fault-injection feature (the crash points are env-driven, off otherwise).
//! ## Run
//! ```
//! cargo build -p chain-forge-node --features fault-injection
//! cargo test -p chain-forge-node --test storage_v2_live -- --nocapture --test-threads=1
//! ```

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
use chain_forge_execution::Transaction;
use std::{
    io::{BufRead, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn repo_root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf() }
fn node_bin() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|_| repo_root().join("target"));
    target.join("debug").join(format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX))
}
fn genesis() -> PathBuf { repo_root().join("tests/devnet/genesis-val-evict.json") }
fn key(name: &str) -> PathBuf { repo_root().join("tests/devnet/keys").join(format!("{name}.key.json")) }

/// Ports below the OS ephemeral range (see validator_jail_live).
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

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").as_bytes()).ok()?;
    let (mut body, mut past) = (String::new(), false);
    for line in std::io::BufReader::new(s).lines() {
        let line = line.ok()?;
        if past { body.push_str(&line); } else if line.is_empty() { past = true; }
    }
    serde_json::from_str(&body).ok()
}
fn height(port: u16) -> Option<u64> { api_get(port, "/api/status")?.get("height")?.as_u64() }
fn wait_port(port: u16, t: Duration) -> bool {
    let d = Instant::now() + t;
    while Instant::now() < d { if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() { return true; } std::thread::sleep(Duration::from_millis(100)); }
    false
}
fn wait_heights(ports: &[u16], target: u64, t: Duration) -> bool {
    let d = Instant::now() + t;
    while Instant::now() < d {
        if ports.iter().all(|&p| height(p).unwrap_or(0) >= target) { return true; }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}
const CHAIN_ID: &str = "qcb-devnet-val-evict";

fn post_tx(port: u16, tx: &Transaction) -> bool {
    let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{port}")) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let body = serde_json::to_string(tx).unwrap();
    let req = format!("POST /api/tx HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    if s.write_all(req.as_bytes()).is_err() { return false; }
    let mut buf = String::new();
    let _ = std::io::Read::read_to_string(&mut s, &mut buf);
    buf.contains("queued")
}

/// Sends one signed transfer (alice -> bob) per ~700 ms to `port` until dropped, so blocks carry transactions and
/// the state root keeps changing (agreement on an unchanging root would prove little).
struct Feeder { stop: std::sync::Arc<std::sync::atomic::AtomicBool>, h: Option<std::thread::JoinHandle<u64>> }
impl Feeder {
    fn start(port: u16) -> Feeder {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s2 = stop.clone();
        let h = std::thread::spawn(move || {
            let kp = ClassicalScheme.generate_keypair("qcb1alice").unwrap();
            let mut sent = 0u64;
            while !s2.load(std::sync::atomic::Ordering::Relaxed) {
                let nonce = api_get(port, "/api/accounts/qcb1alice").and_then(|v| v["nonce"].as_u64()).unwrap_or(0);
                let mut tx = Transaction::transfer(&format!("v2l-{nonce}-{sent}"), "qcb1alice", "qcb1bob", "uqcb", 1_000, nonce);
                tx.sign(&kp, CHAIN_ID).unwrap();
                if post_tx(port, &tx) { sent += 1; }
                std::thread::sleep(Duration::from_millis(700));
            }
            sent
        });
        Feeder { stop, h: Some(h) }
    }
    fn finish(mut self) -> u64 { self.stop.store(true, std::sync::atomic::Ordering::Relaxed); self.h.take().unwrap().join().unwrap() }
}
impl Drop for Feeder { fn drop(&mut self) { self.stop.store(true, std::sync::atomic::Ordering::Relaxed); } }

fn strip_ansi(t: &str) -> String {
    let (mut out, mut esc) = (String::new(), false);
    for c in t.chars() { if c == '\x1b' { esc = true; continue; } if esc { if c == 'm' { esc = false; } continue; } out.push(c); }
    out
}
fn read_log(p: &PathBuf) -> String { strip_ansi(&std::fs::read_to_string(p).unwrap_or_default()) }

struct Node { name: &'static str, child: Option<Child>, api: u16, p2p: u16, data: PathBuf, log: PathBuf, peers: Vec<u16> }
impl Drop for Node { fn drop(&mut self) { if let Some(c) = self.child.as_mut() { let _ = c.kill(); let _ = c.wait(); } } }
impl Node {
    fn kill9(&mut self) { if let Some(mut c) = self.child.take() { let _ = c.kill(); let _ = c.wait(); } }
}

thread_local! { static V2: std::cell::Cell<bool> = const { std::cell::Cell::new(true) }; }
fn is_v2() -> bool { V2.with(|v| v.get()) }
fn fmt_line() -> &'static str { if is_v2() { "storage format: v2" } else { "storage format: v1 (default)" } }

fn spawn(name: &'static str, data: &PathBuf, log: &PathBuf, p2p: u16, peers: &[u16], envs: &[(&str, &str)]) -> Node {
    std::fs::create_dir_all(data).unwrap();
    let api = free_port();
    let f = std::fs::File::create(log).unwrap();
    let mut cmd = Command::new(node_bin());
    cmd.args(["--genesis", genesis().to_str().unwrap(), "--validator", &format!("qcb1{name}"),
              "--key-file", key(name).to_str().unwrap(), "--data-dir", data.to_str().unwrap(),
              "--api-port", &api.to_string(), "--p2p-port", &p2p.to_string()]);
    if is_v2() { cmd.arg("--storage-v2-experimental"); }
    for q in peers { cmd.args(["--bootstrap", &format!("/ip4/127.0.0.1/tcp/{q}")]); }
    for (k, v) in envs { cmd.env(k, v); }
    let child = cmd.stdout(f.try_clone().unwrap()).stderr(f).stdin(Stdio::null()).spawn().unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    Node { name, child: Some(child), api, p2p, data: data.clone(), log: log.clone(), peers: peers.to_vec() }
}

fn dump(n: &Node) { let t = read_log(&n.log); let l: Vec<&str> = t.lines().collect(); eprintln!("── {} log (last 40) ──", n.name); for x in &l[l.len().saturating_sub(40)..] { eprintln!("{x}"); } }

/// Alice, Bob, Carol, Dave in a full mesh; `dave_env` is applied to Dave only. Returns the nodes and their p2p ports.
fn start_cluster(base: &PathBuf, dave_env: &[(&str, &str)]) -> (Vec<Node>, Vec<u16>) {
    let _ = std::fs::remove_dir_all(base);
    let logs = base.join("logs"); std::fs::create_dir_all(&logs).unwrap();
    let p2p: Vec<u16> = (0..4).map(|_| free_port()).collect();
    let names = ["alice", "bob", "carol", "dave"];
    let mut nodes = vec![];
    for i in 0..4 {
        let peers: Vec<u16> = (0..4).filter(|&j| j != i).map(|j| p2p[j]).collect();
        let env: &[(&str, &str)] = if i == 3 { dave_env } else { &[] };
        nodes.push(spawn(names[i], &base.join(names[i]), &logs.join(format!("{}.log", names[i])), p2p[i], &peers, env));
    }
    for n in &nodes { assert!(wait_port(n.api, Duration::from_secs(30)), "{} API never opened", n.name); }
    (nodes, p2p)
}

/// All listed nodes serve the same state root for the block at the lowest common height.
fn assert_roots_agree(nodes: &[&Node], what: &str) {
    let ports: Vec<u16> = nodes.iter().map(|n| n.api).collect();
    let h = ports.iter().map(|&p| height(p).unwrap_or(0)).min().unwrap();
    assert!(h > 0, "{what}: no common height");
    let roots: Vec<String> = ports.iter().map(|&p| api_get(p, &format!("/api/blocks/{h}")).and_then(|j| j["state_root"].as_str().map(str::to_string)).unwrap_or_default()).collect();
    println!("   {what}: roots at h={h}: {}", roots.iter().map(|r| r.chars().take(10).collect::<String>()).collect::<Vec<_>>().join(" "));
    assert!(roots.iter().all(|r| !r.is_empty()), "{what}: a node returned no state root at h={h}: {roots:?}");
    assert!(roots.iter().all(|r| r == &roots[0]), "{what}: state roots DIVERGE at h={h}: {roots:?}");
}

fn resumed_height(log: &PathBuf) -> Option<u64> {
    read_log(log).lines().filter(|l| l.contains("resumed from persisted state")).last()
        .and_then(|l| l.split("height=").nth(1)).and_then(|r| r.split_whitespace().next()).and_then(|h| h.parse().ok())
}

fn no_equivocation(nodes: &[&Node]) {
    for n in nodes {
        let t = read_log(&n.log).to_lowercase();
        // a node may log that it REFUSED to sign (guard); it must never report an equivocation
        let bad: Vec<&str> = t.lines().filter(|l| l.contains("equivocation") && !l.contains("refus")).collect();
        assert!(bad.is_empty(), "{}: equivocation reported: {:?}", n.name, &bad[..bad.len().min(3)]);
    }
}

const CRASH_AT: u64 = 6;

/// V2L-1
#[test]
fn v2_a_node_aborted_at_each_commit_boundary_recovers_and_converges() { boundary_crashes(true) }

/// The same scenario on the DEFAULT storage (v1), for the boundaries its commit has (generation files, manifest, `CURRENT`).
#[test]
fn v1_a_node_aborted_at_each_commit_boundary_recovers_and_converges() { boundary_crashes(false) }

fn boundary_crashes(v2: bool) {
    V2.with(|c| c.set(v2));
    let points: &[&str] = if v2 { &["block_log_appended", "hvs_log_appended", "gen_files_written", "manifest_written", "current_written"] }
                          else { &["gen_files_written", "manifest_written", "current_written"] };
    for &point in points {
        println!("\n── V2L-1: Dave aborts at {point} while committing height {CRASH_AT} ──");
        let base = std::env::temp_dir().join(format!("cf-{}l1-{}-{point}", if v2 { "v2" } else { "v1" }, std::process::id()));
        let (mut nodes, p2p) = start_cluster(&base, &[("CF_FAULT_V2_CRASH_POINT", point), ("CF_FAULT_V2_CRASH_HEIGHT", &CRASH_AT.to_string())]);
        let feeder = Feeder::start(nodes[0].api);
        // Dave dies by himself
        let d = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(s) = nodes[3].child.as_mut().unwrap().try_wait().unwrap() { break s; }
            if Instant::now() > d { for n in &nodes { dump(n); } panic!("Dave did not abort at {point} (was the node built with --features fault-injection?)"); }
            std::thread::sleep(Duration::from_millis(200));
        };
        nodes[3].child = None;
        assert!(!status.success(), "{point}: Dave must have been aborted, got {status:?}");
        assert!(read_log(&nodes[3].log).contains(&format!("crashing the process at {point}")), "{point}: Dave's log does not show the injected crash");
        // the format was selected and logged
        for n in &nodes { assert!(read_log(&n.log).contains(fmt_line()), "{}: log does not name the storage format", n.name); }
        // survivors keep finalizing (3 of 4)
        let surv: Vec<u16> = nodes[..3].iter().map(|n| n.api).collect();
        assert!(wait_heights(&surv, CRASH_AT + 4, Duration::from_secs(90)), "{point}: survivors did not advance without Dave");
        // restart Dave on the SAME data directory, no crash env
        let mut dave = spawn("dave", &nodes[3].data.clone(), &nodes[3].log.with_file_name("dave2.log"), nodes[3].p2p, &nodes[3].peers.clone(), &[]);
        let _ = &p2p;
        assert!(wait_port(dave.api, Duration::from_secs(30)), "{point}: restarted Dave's API never opened (lock or recovery failure)");
        std::thread::sleep(Duration::from_secs(1));
        let log = read_log(&dave.log);
        assert!(log.contains(fmt_line()), "{point}: restarted Dave did not log the storage format");
        assert!(log.contains("resumed from persisted state") && !log.contains("starting from genesis"), "{point}: Dave did not resume from persisted state\n{log}");
        let want = if point == "current_written" { CRASH_AT } else { CRASH_AT - 1 };
        let got = resumed_height(&dave.log).expect("resumed height in log");
        println!("   {point}: Dave resumed at height {got} (expected {want})");
        assert_eq!(got, want, "{point}: Dave resumed at the wrong committed height");
        // Dave had already signed his precommit for height 6 (the guard is durable before the vote leaves the node).
        // Before CURRENT the committed state is height 5, so the guard is ahead and he must abstain; after CURRENT it is not.
        let abstains = log.contains("abstaining from signing");
        assert_eq!(abstains, point != "current_written", "{point}: abstention on restart (guard ahead of state) was {abstains}");
        // catches up and agrees
        let target = height(nodes[0].api).unwrap();
        assert!(wait_heights(&[dave.api], target, Duration::from_secs(120)), "{point}: Dave did not catch up to {target}");
        let all = [&nodes[0], &nodes[1], &nodes[2], &dave];
        assert!(wait_heights(&all.iter().map(|n| n.api).collect::<Vec<_>>(), target, Duration::from_secs(60)));
        assert_roots_agree(&all, point);
        no_equivocation(&all);
        let sent = feeder.finish();
        assert!(sent >= 5, "{point}: only {sent} transactions were accepted: the state would not have moved");
        let acc = api_get(nodes[0].api, "/api/accounts/qcb1alice").and_then(|v| v["nonce"].as_u64()).unwrap_or(0);
        assert!(acc >= 5, "{point}: alice's nonce is {acc}: transactions did not commit");
        dave.kill9();
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// V2L-2
#[test]
fn v2_sigkill_restart_at_multiple_heights_and_the_directory_lock() { sigkill_rounds(true) }

/// The same SIGKILL scenario on the DEFAULT storage (v1; there is no directory lock to test).
#[test]
fn v1_sigkill_restart_at_multiple_heights() { sigkill_rounds(false) }

fn sigkill_rounds(v2: bool) {
    V2.with(|c| c.set(v2));
    let base = std::env::temp_dir().join(format!("cf-{}l2-{}", if v2 { "v2" } else { "v1" }, std::process::id()));
    let (mut nodes, _p2p) = start_cluster(&base, &[]);
    let feeder = Feeder::start(nodes[0].api);
    let mut last_root = String::new();
    let all_ports = |ns: &Vec<Node>| ns.iter().map(|n| n.api).collect::<Vec<u16>>();
    for (round, (target, victim)) in [(5u64, 3usize), (15, 2), (30, 1)].into_iter().enumerate() {
        let name = nodes[victim].name;
        println!("\n── V2L-2 round {round}: wait h>={target}, SIGKILL {name} ──");
        assert!(wait_heights(&all_ports(&nodes), target, Duration::from_secs(240)), "round {round}: cluster did not reach {target}");
        let at_kill = height(nodes[0].api).unwrap();
        nodes[victim].kill9();
        let surv: Vec<u16> = nodes.iter().enumerate().filter(|(i, n)| *i != victim && n.child.is_some()).map(|(_, n)| n.api).collect();
        assert!(wait_heights(&surv, at_kill + 3, Duration::from_secs(90)), "round {round}: survivors did not advance without {name}");
        let (data, log) = (nodes[victim].data.clone(), nodes[victim].log.with_file_name(format!("{name}-r{round}.log")));
        let (own_p2p, peers) = (nodes[victim].p2p, nodes[victim].peers.clone());
        let mut back = spawn(name, &data, &log, own_p2p, &peers, &[]);
        assert!(wait_port(back.api, Duration::from_secs(30)), "round {round}: restarted {name} API never opened");
        std::thread::sleep(Duration::from_secs(1));
        let text = read_log(&back.log);
        assert!(text.contains(fmt_line()) && text.contains("resumed from persisted state") && !text.contains("starting from genesis"),
                "round {round}: {name} did not resume on v2\n{text}");
        println!("   {name} resumed at height {:?} (killed at ~{at_kill})", resumed_height(&back.log));
        let target_h = height(nodes[0].api).unwrap();
        assert!(wait_heights(&[back.api], target_h, Duration::from_secs(120)), "round {round}: {name} did not catch up");
        // the OS lock: a SECOND process on this running node's directory is refused
        if v2 {
            let mut second = spawn(name, &data, &log.with_file_name(format!("{name}-r{round}-dup.log")), free_port(), &peers, &[]);
            let d = Instant::now() + Duration::from_secs(30);
            let code = loop { if let Some(s) = second.child.as_mut().unwrap().try_wait().unwrap() { break s; } assert!(Instant::now() < d, "round {round}: a second process on a locked directory kept running"); std::thread::sleep(Duration::from_millis(200)); };
            second.child = None;
            assert!(!code.success(), "round {round}: duplicate process must exit non-zero");
            assert!(read_log(&second.log).contains("cannot use the data directory in storage v2"), "round {round}: duplicate refused for the wrong reason");
        }
        nodes[victim] = back;
        let refs: Vec<&Node> = nodes.iter().collect();
        assert!(wait_heights(&all_ports(&nodes), target_h, Duration::from_secs(60)));
        assert_roots_agree(&refs, &format!("round {round}"));
        let h = refs.iter().map(|n| height(n.api).unwrap_or(0)).min().unwrap();
        let root = api_get(nodes[0].api, &format!("/api/blocks/{h}")).and_then(|j| j["state_root"].as_str().map(str::to_string)).unwrap_or_default();
        assert_ne!(root, last_root, "round {round}: the state root did not change since the previous round (no transactions committing?)");
        last_root = root;
    }
    let sent = feeder.finish();
    assert!(sent >= 20, "only {sent} transactions accepted over the run");
    let refs: Vec<&Node> = nodes.iter().collect();
    no_equivocation(&refs);
    let _ = std::fs::remove_dir_all(&base);
}

/// H0-3b PR B: the signing-guard windows. Dave's process is aborted right after the guard recording a VOTE (resp. a PROPOSAL)
/// is durable, before the message is sent. After the restart: the guard on disk still holds what was authorised, the node
/// resumes from the verified committed state (abstaining while the guard is ahead of it), the chain converges, and no node
/// reports an equivocation.
#[test]
fn v2_a_node_aborted_after_its_signing_guard_write_restarts_without_conflicting_signatures() { guard_window_crashes(true) }
#[test]
fn v1_a_node_aborted_after_its_signing_guard_write_restarts_without_conflicting_signatures() { guard_window_crashes(false) }

fn guard_window_crashes(v2: bool) {
    V2.with(|c| c.set(v2));
    for point in ["vote_guard_written", "proposal_guard_written"] {
        println!("\n── V2L-3: Dave aborts at {point} (v2={v2}) ──");
        let base = std::env::temp_dir().join(format!("cf-{}l3-{}-{point}", if v2 { "v2" } else { "v1" }, std::process::id()));
        let (mut nodes, _p2p) = start_cluster(&base, &[("CF_FAULT_V2_CRASH_POINT", point), ("CF_FAULT_V2_CRASH_HEIGHT", "6")]);
        let feeder = Feeder::start(nodes[0].api);
        let d = Instant::now() + Duration::from_secs(180);
        let status = loop {
            if let Some(s) = nodes[3].child.as_mut().unwrap().try_wait().unwrap() { break s; }
            if Instant::now() > d { for n in &nodes { dump(n); } panic!("Dave did not abort at {point} (was the node built with --features fault-injection?)"); }
            std::thread::sleep(Duration::from_millis(200));
        };
        nodes[3].child = None;
        assert!(!status.success(), "{point}: Dave must have been aborted, got {status:?}");
        let crash_log = read_log(&nodes[3].log);
        let at_h: u64 = crash_log.lines().filter(|l| l.contains(&format!("crashing the process at {point} at height")))
            .filter_map(|l| l.rsplit("height ").next()).filter_map(|h| h.trim().parse().ok()).next()
            .unwrap_or_else(|| panic!("{point}: the crash height is not in Dave's log"));
        println!("   {point}: aborted while signing at height {at_h}");
        // the guard that was made durable BEFORE the message left the node
        let guard: serde_json::Value = serde_json::from_slice(&std::fs::read(nodes[3].data.join("persist").join("consensus_signing.json")).expect("guard file exists")).unwrap();
        if point == "vote_guard_written" {
            assert!(guard["last"][0].as_u64().map_or(false, |h| h == at_h), "{point}: the guard records the vote at height {at_h}: {}", guard["last"]);
        } else {
            assert_eq!(guard["proposal"]["height"].as_u64(), Some(at_h), "{point}: the guard records the proposal at height {at_h}");
        }
        let surv: Vec<u16> = nodes[..3].iter().map(|n| n.api).collect();
        assert!(wait_heights(&surv, at_h + 3, Duration::from_secs(120)), "{point}: survivors did not advance without Dave");
        let mut dave = spawn("dave", &nodes[3].data.clone(), &nodes[3].log.with_file_name("dave2.log"), nodes[3].p2p, &nodes[3].peers.clone(), &[]);
        assert!(wait_port(dave.api, Duration::from_secs(30)), "{point}: restarted Dave's API never opened");
        std::thread::sleep(Duration::from_secs(1));
        let log = read_log(&dave.log);
        assert!(log.contains(fmt_line()) && log.contains("resumed from persisted state") && !log.contains("starting from genesis"), "{point}: Dave did not resume\n{log}");
        let got = resumed_height(&dave.log).expect("resumed height in the log");
        println!("   {point}: Dave resumed at height {got}");
        assert!(got == at_h || got + 1 == at_h, "{point}: resumed at {got}, signing was at {at_h}");
        if point == "vote_guard_written" {
            // a vote at at_h was authorised; the committed state is behind it => the node must abstain, not re-decide
            assert_eq!(got + 1, at_h, "{point}: the block was not committed");
            assert!(log.contains("abstaining from signing"), "{point}: the restarted node must abstain while its guard is ahead of its state");
        }
        let target = height(nodes[0].api).unwrap();
        assert!(wait_heights(&[dave.api], target, Duration::from_secs(120)), "{point}: Dave did not catch up to {target}");
        let all = [&nodes[0], &nodes[1], &nodes[2], &dave];
        assert!(wait_heights(&all.iter().map(|n| n.api).collect::<Vec<_>>(), target, Duration::from_secs(60)));
        assert_roots_agree(&all, point);
        let sent = feeder.finish();
        assert!(sent >= 5, "{point}: only {sent} transactions were accepted");
        no_equivocation(&all);
        dave.kill9();
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// A node asked to use a data directory that cannot be used must STOP (it used to warn and run memory-only on the default
/// storage, where a restarted validator would then sign with no signing guard and no committed state).
#[test]
fn v1_a_node_with_an_unusable_data_dir_refuses_to_start() { unusable_data_dir(false) }
#[test]
fn v2_a_node_with_an_unusable_data_dir_refuses_to_start() { unusable_data_dir(true) }

fn unusable_data_dir(v2: bool) {
    let base = std::env::temp_dir().join(format!("cf-baddir-{}-{}", if v2 { "v2" } else { "v1" }, std::process::id()));
    let _ = std::fs::remove_dir_all(&base); std::fs::create_dir_all(&base).unwrap();
    let blocker = base.join("a-file"); std::fs::write(&blocker, b"x").unwrap();
    let data = blocker.join("data");                       // a directory "inside" a file: cannot be created
    let log = base.join("node.log");
    let f = std::fs::File::create(&log).unwrap();
    let mut cmd = Command::new(node_bin());
    cmd.args(["--genesis", genesis().to_str().unwrap(), "--validator", "qcb1alice", "--key-file", key("alice").to_str().unwrap(),
              "--data-dir", data.to_str().unwrap(), "--api-port", &free_port().to_string(), "--p2p-port", &free_port().to_string()]);
    if v2 { cmd.arg("--storage-v2-experimental"); }
    let mut child = cmd.stdout(f.try_clone().unwrap()).stderr(f).stdin(Stdio::null()).spawn().unwrap();
    let d = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() { break s; }
        if Instant::now() > d { let _ = child.kill(); panic!("the node kept running with an unusable data directory:\n{}", read_log(&log)); }
        std::thread::sleep(Duration::from_millis(200));
    };
    let text = read_log(&log);
    assert!(!status.success(), "must exit non-zero, got {status:?}");
    assert!(text.contains("FATAL") && !text.contains("running memory-only"), "the log must say FATAL and must not fall back to memory-only:\n{text}");
    let _ = std::fs::remove_dir_all(&base);
}
