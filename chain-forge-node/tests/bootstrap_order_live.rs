//! Four real nodes started in the WORST order must still connect and produce blocks, three times in a row.
//!
//! Seed-node topology (as the Explorer scripts and a real testnet use): bob, carol and dave list ONLY alice as `--bootstrap`; alice lists
//! none. Dave, carol and bob start first, alice 1 s after each other start. Before the bootstrap-retry fix each node dialled its
//! bootstrap peer once, at startup; alice was not listening yet, so dave/carol/bob never connected: the APIs answered, `peer_count`
//! stayed 0 and no block was produced. (If every node lists every other node, the last node to start dials the others and the
//! network forms by itself, which is why an all-to-all bootstrap list cannot reproduce the stall.) Uses the unchanged `tests/devnet/genesis-4node-mldsa.json`
//! and the public test validator keys.
//!
//! ## Run
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test bootstrap_order_live -- --nocapture
//! ```
//! Per CLAUDE.md: marked done only after it passes on Windows (MINGW64).

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn repo_root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf() }
fn node_bin() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = ["debug", "release"].iter()
        .filter_map(|p| { let f = target.join(p).join(&exe); f.metadata().and_then(|m| m.modified()).ok().map(|t| (t, f)) }).collect();
    found.sort();
    found.pop().map(|x| x.1).unwrap_or_else(|| panic!("chain-forge-node is not built; run: cargo build -p chain-forge-node"))
}
fn free_port() -> u16 { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }

fn api_status(port: u16) -> Option<serde_json::Value> {
    let mut s = TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_millis(500)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(5_000))).ok()?;
    s.write_all(b"GET /api/status HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    serde_json::from_str(buf.split("\r\n\r\n").nth(1)?).ok()
}

struct Net { nodes: Vec<Child>, dir: PathBuf }
impl Drop for Net { fn drop(&mut self) { for n in &mut self.nodes { let _ = n.kill(); let _ = n.wait(); } let _ = std::fs::remove_dir_all(&self.dir); } }

/// Start order is `order` (indexes into alice, bob, carol, dave); `gap` between starts.
fn start(trial: u32, order: &[usize], gap: Duration) -> (Net, [u16; 4]) {
    let names = ["alice", "bob", "carol", "dave"];
    let dir = std::env::temp_dir().join(format!("bootstrap-order-live-{}-{trial}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("logs")).unwrap();
    let api = [free_port(), free_port(), free_port(), free_port()];
    let p2p = [free_port(), free_port(), free_port(), free_port()];
    let mut net = Net { nodes: vec![], dir: dir.clone() };
    for (k, &i) in order.iter().enumerate() {
        let data = dir.join("data").join(names[i]);
        std::fs::create_dir_all(&data).unwrap();
        let log = std::fs::File::create(dir.join("logs").join(format!("{}.log", names[i]))).unwrap();
        let mut cmd = Command::new(node_bin());
        cmd.arg("--genesis").arg(repo_root().join("tests/devnet/genesis-4node-mldsa.json"))
            .arg("--validator").arg(format!("qcb1{}", names[i]))
            .arg("--api-port").arg(api[i].to_string()).arg("--p2p-port").arg(p2p[i].to_string()).arg("--data-dir").arg(&data)
            .arg("--key-file").arg(repo_root().join("tests/devnet/keys/mldsa").join(format!("{}.key.json", names[i])));
        if i != 0 { cmd.arg("--bootstrap").arg(format!("/ip4/127.0.0.1/tcp/{}", p2p[0])); }
        cmd.stdout(log.try_clone().unwrap()).stderr(log).stdin(Stdio::null());
        net.nodes.push(cmd.spawn().unwrap_or_else(|e| panic!("spawn {}: {e}", names[i])));
        if k + 1 < order.len() { std::thread::sleep(gap); }
    }
    (net, api)
}

fn tail(net: &Net) -> String {
    ["alice", "bob", "carol", "dave"].iter().map(|n| {
        let t = std::fs::read_to_string(net.dir.join("logs").join(format!("{n}.log"))).unwrap_or_default();
        format!("--- {n}\n{}", t.lines().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n"))
    }).collect::<Vec<_>>().join("\n")
}

#[test]
fn four_nodes_started_in_the_worst_order_still_connect_and_produce_blocks_three_times_in_a_row() {
    for trial in 1..=3 {
        // dave, carol, bob first; alice last (and 3 s after the others).
        let (net, api) = start(trial, &[3, 2, 1, 0], Duration::from_millis(1_000));
        let t0 = Instant::now();
        let deadline = Duration::from_secs(90);
        let verdict = loop {
            let st: Vec<serde_json::Value> = api.iter().map(|&p| api_status(p).unwrap_or(serde_json::Value::Null)).collect();
            let peers: Vec<u64> = st.iter().map(|s| s["peer_count"].as_u64().unwrap_or(0)).collect();
            let hs: Vec<u64> = st.iter().map(|s| s["height"].as_u64().unwrap_or(0)).collect();
            let roots: Vec<String> = st.iter().map(|s| s["state_root"].as_str().unwrap_or("").to_string()).collect();
            if peers.iter().all(|&p| p > 0) && hs.iter().all(|&h| h >= 2 && h == hs[0]) && roots.iter().all(|r| !r.is_empty() && *r == roots[0]) {
                break Ok((t0.elapsed(), peers, hs[0]));
            }
            if t0.elapsed() > deadline { break Err(format!("peers {peers:?} heights {hs:?}")); }
            std::thread::sleep(Duration::from_millis(500));
        };
        match verdict {
            Ok((t, peers, h)) => println!("trial {trial}: connected in {:.1}s, peers {peers:?}, height {h}, state roots agree", t.as_secs_f32()),
            Err(why) => panic!("trial {trial}: the nodes did not connect and produce blocks within {}s ({why})\n{}", deadline.as_secs(), tail(&net)),
        }
    }
}
