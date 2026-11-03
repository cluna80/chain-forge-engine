//! PERSIST-001 P-02b PR 2 — storage format 2: live four-node crash and restart acceptance (EXPERIMENTAL).
//!
//! Four real node processes, every one started with `--storage-v2-experimental` (default OFF).
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
fn genesis() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/devnet/genesis-4node-crash.json") }
fn key(name: &str) -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/devnet/keys").join(format!("{name}.key.json")) }

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
fn strip_ansi(t: &str) -> String {
    let (mut out, mut esc) = (String::new(), false);
    for c in t.chars() { if c == '\x1b' { esc = true; continue; } if esc { if c == 'm' { esc = false; } continue; } out.push(c); }
    out
}
fn read_log(p: &PathBuf) -> String { strip_ansi(&std::fs::read_to_string(p).unwrap_or_default()) }

struct Node { name: &'static str, child: Option<Child>, api: u16, p2p: u16, data: PathBuf, log: PathBuf }
impl Drop for Node { fn drop(&mut self) { if let Some(c) = self.child.as_mut() { let _ = c.kill(); let _ = c.wait(); } } }
impl Node {
    fn kill9(&mut self) { if let Some(mut c) = self.child.take() { let _ = c.kill(); let _ = c.wait(); } }
}

fn spawn(name: &'static str, data: &PathBuf, log: &PathBuf, bootstrap: Option<&str>, envs: &[(&str, &str)]) -> Node {
    std::fs::create_dir_all(data).unwrap();
    let (api, p2p) = (free_port(), free_port());
    let f = std::fs::File::create(log).unwrap();
    let mut cmd = Command::new(node_bin());
    cmd.args(["--genesis", genesis().to_str().unwrap(), "--validator", &format!("qcb1{name}"),
              "--key-file", key(name).to_str().unwrap(), "--data-dir", data.to_str().unwrap(),
              "--api-port", &api.to_string(), "--p2p-port", &p2p.to_string(), "--storage-v2-experimental"]);
    match bootstrap { Some(b) => { cmd.args(["--bootstrap", b]); } None => { cmd.arg("--expect-peers"); } }
    for (k, v) in envs { cmd.env(k, v); }
    let child = cmd.stdout(f.try_clone().unwrap()).stderr(f).stdin(Stdio::null()).spawn().unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    Node { name, child: Some(child), api, p2p, data: data.clone(), log: log.clone() }
}

fn peer_id(log: &PathBuf, t: Duration) -> String {
    let d = Instant::now() + t;
    loop {
        if let Some(id) = read_log(log).lines().filter(|l| l.contains("P2P listening")).find_map(|l| l.split("peer=").nth(1))
            .map(|r| r.split_whitespace().next().unwrap_or("").to_string()).filter(|i| i.starts_with("12D3")) { return id; }
        assert!(Instant::now() < d, "no libp2p peer id in {log:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn dump(n: &Node) { let t = read_log(&n.log); let l: Vec<&str> = t.lines().collect(); eprintln!("── {} log (last 40) ──", n.name); for x in &l[l.len().saturating_sub(40)..] { eprintln!("{x}"); } }

/// Alice (anchor), Bob, Carol, Dave; `dave_env` is applied to Dave only.
fn start_cluster(base: &PathBuf, dave_env: &[(&str, &str)]) -> (Vec<Node>, String) {
    let _ = std::fs::remove_dir_all(base);
    let logs = base.join("logs"); std::fs::create_dir_all(&logs).unwrap();
    let alice = spawn("alice", &base.join("alice"), &logs.join("alice.log"), None, &[]);
    assert!(wait_port(alice.api, Duration::from_secs(30)), "alice API never opened");
    let boot = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", alice.p2p, peer_id(&alice.log, Duration::from_secs(20)));
    let bob = spawn("bob", &base.join("bob"), &logs.join("bob.log"), Some(&boot), &[]);
    let carol = spawn("carol", &base.join("carol"), &logs.join("carol.log"), Some(&boot), &[]);
    let dave = spawn("dave", &base.join("dave"), &logs.join("dave.log"), Some(&boot), dave_env);
    for n in [&bob, &carol, &dave] { assert!(wait_port(n.api, Duration::from_secs(30)), "{} API never opened", n.name); }
    (vec![alice, bob, carol, dave], boot)
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
fn v2_a_node_aborted_at_each_commit_boundary_recovers_and_converges() {
    for point in ["block_log_appended", "hvs_log_appended", "gen_files_written", "manifest_written", "current_written"] {
        println!("\n── V2L-1: Dave aborts at {point} while committing height {CRASH_AT} ──");
        let base = std::env::temp_dir().join(format!("cf-v2l1-{}-{point}", std::process::id()));
        let (mut nodes, boot) = start_cluster(&base, &[("CF_FAULT_V2_CRASH_POINT", point), ("CF_FAULT_V2_CRASH_HEIGHT", &CRASH_AT.to_string())]);
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
        for n in &nodes { assert!(read_log(&n.log).contains("storage format: v2"), "{}: log does not name the storage format", n.name); }
        // survivors keep finalizing (3 of 4)
        let surv: Vec<u16> = nodes[..3].iter().map(|n| n.api).collect();
        assert!(wait_heights(&surv, CRASH_AT + 4, Duration::from_secs(90)), "{point}: survivors did not advance without Dave");
        // restart Dave on the SAME data directory, no crash env
        let mut dave = spawn("dave", &nodes[3].data.clone(), &nodes[3].log.with_file_name("dave2.log"), Some(&boot), &[]);
        assert!(wait_port(dave.api, Duration::from_secs(30)), "{point}: restarted Dave's API never opened (lock or recovery failure)");
        std::thread::sleep(Duration::from_secs(1));
        let log = read_log(&dave.log);
        assert!(log.contains("storage format: v2"), "{point}: restarted Dave did not log the storage format");
        assert!(log.contains("resumed from persisted state") && !log.contains("starting from genesis"), "{point}: Dave did not resume from persisted state\n{log}");
        let want = if point == "current_written" { CRASH_AT } else { CRASH_AT - 1 };
        let got = resumed_height(&dave.log).expect("resumed height in log");
        println!("   {point}: Dave resumed at height {got} (expected {want})");
        assert_eq!(got, want, "{point}: Dave resumed at the wrong committed height");
        // catches up and agrees
        let target = height(nodes[0].api).unwrap();
        assert!(wait_heights(&[dave.api], target, Duration::from_secs(120)), "{point}: Dave did not catch up to {target}");
        let all = [&nodes[0], &nodes[1], &nodes[2], &dave];
        assert!(wait_heights(&all.iter().map(|n| n.api).collect::<Vec<_>>(), target, Duration::from_secs(60)));
        assert_roots_agree(&all, point);
        no_equivocation(&all);
        dave.kill9();
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// V2L-2
#[test]
fn v2_sigkill_restart_at_multiple_heights_and_the_directory_lock() {
    let base = std::env::temp_dir().join(format!("cf-v2l2-{}", std::process::id()));
    let (mut nodes, boot) = start_cluster(&base, &[]);
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
        let mut back = spawn(name, &data, &log, Some(&boot), &[]);
        assert!(wait_port(back.api, Duration::from_secs(30)), "round {round}: restarted {name} API never opened");
        std::thread::sleep(Duration::from_secs(1));
        let text = read_log(&back.log);
        assert!(text.contains("storage format: v2") && text.contains("resumed from persisted state") && !text.contains("starting from genesis"),
                "round {round}: {name} did not resume on v2\n{text}");
        println!("   {name} resumed at height {:?} (killed at ~{at_kill})", resumed_height(&back.log));
        let target_h = height(nodes[0].api).unwrap();
        assert!(wait_heights(&[back.api], target_h, Duration::from_secs(120)), "round {round}: {name} did not catch up");
        // the OS lock: a SECOND process on this running node's directory is refused
        let mut second = spawn(name, &data, &log.with_file_name(format!("{name}-r{round}-dup.log")), Some(&boot), &[]);
        let d = Instant::now() + Duration::from_secs(30);
        let code = loop { if let Some(s) = second.child.as_mut().unwrap().try_wait().unwrap() { break s; } assert!(Instant::now() < d, "round {round}: a second process on a locked directory kept running"); std::thread::sleep(Duration::from_millis(200)); };
        second.child = None;
        assert!(!code.success(), "round {round}: duplicate process must exit non-zero");
        assert!(read_log(&second.log).contains("cannot use the data directory in storage v2"), "round {round}: duplicate refused for the wrong reason");
        nodes[victim] = back;
        let refs: Vec<&Node> = nodes.iter().collect();
        assert!(wait_heights(&all_ports(&nodes), target_h, Duration::from_secs(60)));
        assert_roots_agree(&refs, &format!("round {round}"));
    }
    let refs: Vec<&Node> = nodes.iter().collect();
    no_equivocation(&refs);
    let _ = std::fs::remove_dir_all(&base);
}
