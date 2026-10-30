//! DIS-001-13: Live Authentication Acceptance Test
//!
//! Spins up the real 4-node devnet and exercises DIS auth end-to-end across real
//! process boundaries, covering the full key-binding and scope-authorization matrix.
//!
//! ## What is tested
//!
//! Two fresh ML-DSA-65 keypairs are generated in-process.  Wallet A is registered
//! and promoted to Verified; Wallet B is registered but never attested (Provisional).
//!
//! Step 1 — RegisterIdentity for Wallet A.
//! Step 2 — Promote Wallet A to Verified via quorum attestation (bob + carol + dave).
//! Step 3 — Issue a `identity:attest` (RequiresVerified) challenge.
//! Step 4 — Wallet A signs; verify returns key_binding_verified=true, scope_authorized=true.
//! Step 5 — Wallet B (Provisional) signs same scope; verify returns scope_authorized=false.
//! Step 6 — Freeze Wallet A (ConfirmSybil); verify returns
//!           key_binding_verified=true, scope_authorized=false (orthogonality invariant).
//! Step 6.5 — ReverseSybil Wallet A; verify returns scope_authorized=true again.
//! Step 7 — Node restart; repeat Step-4 checks — ExplorerState rebuilds correctly.
//! Step 8 — Permissionless scope (`wallet:authenticate`) succeeds for both wallets.
//!
//! ## What counts as passing
//!
//! All assertions inspect the JSON fields `key_binding_verified`, `scope_authorized`,
//! and `identity_status` in the verify response — not just the HTTP status code.
//!
//! ## Run
//! ```
//! cargo build -p chain-forge-node
//! cargo test -p chain-forge-node --test dis_auth_live -- --nocapture
//! ```

use std::{
    io::{Read, Write as IoWrite},
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use chain_forge_crypto::{MlDsaScheme, SignatureScheme};
use chain_forge_wallet::{derive_address_from_pq_key, sign_challenge};

// ── Port helpers ──────────────────────────────────────────────────────────────

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("free_port: bind failed")
        .local_addr()
        .expect("free_port: local_addr failed")
        .port()
}

struct DevnetPorts {
    alice_api:  u16,
    bob_api:    u16,
    carol_api:  u16,
    dave_api:   u16,
    alice_p2p:  u16,
    bob_p2p:    u16,
    carol_p2p:  u16,
    dave_p2p:   u16,
}

impl DevnetPorts {
    fn new() -> Self {
        Self {
            alice_api:  free_port(),
            bob_api:    free_port(),
            carol_api:  free_port(),
            dave_api:   free_port(),
            alice_p2p:  free_port(),
            bob_p2p:    free_port(),
            carol_p2p:  free_port(),
            dave_p2p:   free_port(),
        }
    }
    fn all_api_ports(&self) -> [u16; 4] {
        [self.alice_api, self.bob_api, self.carol_api, self.dave_api]
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn node_binary() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root().join("target"));
    let exe = format!("chain-forge-node{}", std::env::consts::EXE_SUFFIX);
    let debug   = target.join("debug").join(&exe);
    let release = target.join("release").join(&exe);
    match (
        debug.metadata().and_then(|m| m.modified()),
        release.metadata().and_then(|m| m.modified()),
    ) {
        (Ok(dt), Ok(rt)) => if dt >= rt { debug } else { release },
        (Ok(_), Err(_))  => debug,
        (Err(_), Ok(_))  => release,
        (Err(_), Err(_)) => debug,
    }
}

fn genesis_path() -> PathBuf {
    repo_root().join("tests").join("devnet").join("genesis-4node.json")
}

// ── Node spawn / teardown ─────────────────────────────────────────────────────

struct NodeHandle {
    _name:   &'static str,
    process: Child,
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn spawn_node(
    name:     &'static str,
    api_port: u16,
    p2p_port: u16,
    log_dir:  &std::path::Path,
    peers:    &[u16],
) -> NodeHandle {
    let log_path = log_dir.join(format!("{name}.log"));
    let log_file = std::fs::File::create(&log_path).expect("create log file");

    let bootstrap: Vec<String> = peers
        .iter()
        .map(|&p| format!("/ip4/127.0.0.1/tcp/{p}"))
        .collect();

    let short_name = name.strip_prefix("qcb1").unwrap_or(name);
    let key_file = repo_root()
        .join("tests").join("devnet").join("keys")
        .join(format!("{short_name}.key.json"));

    let mut cmd = Command::new(node_binary());
    cmd.arg("--genesis").arg(genesis_path())
       .arg("--validator").arg(name)
       .arg("--key-file").arg(&key_file)
       .arg("--api-port").arg(api_port.to_string())
       .arg("--p2p-port").arg(p2p_port.to_string());
    for addr in &bootstrap {
        cmd.arg("--bootstrap").arg(addr);
    }
    cmd.stdout(log_file.try_clone().unwrap())
       .stderr(log_file)
       .stdin(Stdio::null());

    let process = cmd.spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {name}: {e}"));
    NodeHandle { _name: name, process }
}

fn spawn_devnet(ports: &DevnetPorts, log_dir: &std::path::Path) -> Vec<NodeHandle> {
    vec![
        spawn_node("qcb1alice", ports.alice_api, ports.alice_p2p, log_dir,
                   &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p]),
        spawn_node("qcb1bob",   ports.bob_api,   ports.bob_p2p,   log_dir,
                   &[ports.alice_p2p, ports.carol_p2p, ports.dave_p2p]),
        spawn_node("qcb1carol", ports.carol_api, ports.carol_p2p, log_dir,
                   &[ports.alice_p2p, ports.bob_p2p, ports.dave_p2p]),
        spawn_node("qcb1dave",  ports.dave_api,  ports.dave_p2p,  log_dir,
                   &[ports.alice_p2p, ports.bob_p2p, ports.carol_p2p]),
    ]
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn api_get(port: u16, path: &str) -> Option<serde_json::Value> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_millis(200),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(500))).ok()?;

    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;

    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    let body = buf.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(body).ok()
}

fn api_post_tx(port: u16, tx_json: &str) -> Option<serde_json::Value> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;

    let body = tx_json.as_bytes();
    let req = format!(
        "POST /api/tx HTTP/1.0\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    stream.write_all(body).ok()?;

    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    let resp_body = buf.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(resp_body).ok()
}

/// POST to /api/auth/challenge; returns the full challenge JSON value.
fn api_post_challenge(port: u16, scope: &str) -> Option<serde_json::Value> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;

    let body_str = serde_json::json!({ "scope": scope }).to_string();
    let body = body_str.as_bytes();
    let req = format!(
        "POST /api/auth/challenge HTTP/1.0\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    stream.write_all(body).ok()?;

    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    let resp_body = buf.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(resp_body).ok()
}

/// POST to /api/auth/verify; returns the full verify response JSON value.
fn api_post_verify(
    port:           u16,
    challenge_id:   &str,
    public_key_hex: &str,
    signature:      &str,
) -> Option<serde_json::Value> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_millis(500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(3000))).ok()?;

    let body_str = serde_json::json!({
        "challenge_id": challenge_id,
        "public_key":   public_key_hex,
        "signature":    signature,
    }).to_string();
    let body = body_str.as_bytes();
    let req = format!(
        "POST /api/auth/verify HTTP/1.0\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    stream.write_all(body).ok()?;

    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    let resp_body = buf.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(resp_body).ok()
}

fn height_of(port: u16) -> u64 {
    api_get(port, "/api/status")
        .and_then(|v| v["height"].as_u64())
        .unwrap_or(0)
}

fn identity_of(port: u16, address: &str) -> Option<serde_json::Value> {
    api_get(port, &format!("/api/identity/{address}"))
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        ).is_ok() { return true; }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn poll_until_height(ports: &[u16], target: u64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let heights: Vec<u64> = ports.iter().map(|&p| height_of(p)).collect();
        let all = heights.iter().all(|&h| h >= target);
        let elapsed = Instant::now().duration_since(deadline - timeout);
        print!("\r   [{:.1}s] ", elapsed.as_secs_f32());
        for (i, &h) in heights.iter().enumerate() { print!("node{}={}  ", i, h); }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        if all { println!(); return true; }
        if Instant::now() >= deadline { println!(); return false; }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn poll_until_registered(ports: &[u16], address: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let results: Vec<bool> = ports.iter().map(|&p| {
            identity_of(p, address)
                .and_then(|v| v["registered"].as_bool())
                .unwrap_or(false)
        }).collect();
        let all = results.iter().all(|&r| r);
        let elapsed = Instant::now().duration_since(deadline - timeout);
        print!("\r   [{:.1}s] registered convergence: ", elapsed.as_secs_f32());
        for (i, &r) in results.iter().enumerate() {
            print!("node{}={} ", i, if r { "✓" } else { "…" });
        }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        if all { println!(); return true; }
        if Instant::now() >= deadline { println!(); return false; }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn poll_until_tier(ports: &[u16], address: &str, expected_tier: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let results: Vec<Option<String>> = ports.iter().map(|&p| {
            identity_of(p, address)
                .and_then(|v| v["tier"].as_str().map(String::from))
        }).collect();
        let all = results.iter().all(|r| r.as_deref() == Some(expected_tier));
        let elapsed = Instant::now().duration_since(deadline - timeout);
        print!("\r   [{:.1}s] tier convergence (want {expected_tier}): ", elapsed.as_secs_f32());
        for (i, r) in results.iter().enumerate() {
            print!("node{}={} ", i, r.as_deref().unwrap_or("?"));
        }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        if all { println!(); return true; }
        if Instant::now() >= deadline { println!(); return false; }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn poll_until_frozen(ports: &[u16], address: &str, expected: bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let results: Vec<Option<bool>> = ports.iter().map(|&p| {
            identity_of(p, address)
                .and_then(|v| v["frozen"].as_bool())
        }).collect();
        let all = results.iter().all(|r| *r == Some(expected));
        let elapsed = Instant::now().duration_since(deadline - timeout);
        print!("\r   [{:.1}s] frozen convergence (want {expected}): ", elapsed.as_secs_f32());
        for (i, r) in results.iter().enumerate() {
            print!("node{}={} ", i, r.map(|b| b.to_string()).unwrap_or("?".into()));
        }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        if all { println!(); return true; }
        if Instant::now() >= deadline { println!(); return false; }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn tempdir(prefix: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let dir = std::env::temp_dir().join(format!("{prefix}-{ts}"));
    std::fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

fn skip_if_no_binary() -> bool {
    let bin = node_binary();
    if !bin.exists() {
        println!("SKIP: node binary not found at {bin:?}. Run `cargo build -p chain-forge-node` first.");
        return true;
    }
    false
}

// ── Auth helper: sign a fresh challenge and post verify, returning full JSON ──

fn auth_round(
    port:           u16,
    scope:          &str,
    pub_key_hex:    &str,
    kp:             &chain_forge_crypto::KeyPair,
    label:          &str,
) -> serde_json::Value {
    let challenge = api_post_challenge(port, scope)
        .unwrap_or_else(|| panic!("{label}: POST /api/auth/challenge failed"));
    println!("   {label}: challenge issued — id={}", &challenge["challenge_id"]);

    let challenge_json = serde_json::to_string(&challenge).unwrap();
    let signature = sign_challenge(&challenge_json, kp)
        .unwrap_or_else(|e| panic!("{label}: sign_challenge failed: {e}"));

    let challenge_id = challenge["challenge_id"].as_str()
        .unwrap_or_else(|| panic!("{label}: challenge_id missing"));

    let resp = api_post_verify(port, challenge_id, pub_key_hex, &signature)
        .unwrap_or_else(|| panic!("{label}: POST /api/auth/verify failed"));
    println!("   {label}: verify response = {resp}");
    resp
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// DIS-001-13: live authentication acceptance test.
///
/// End-to-end proof that key-binding, scope-authorization, freeze semantics,
/// and node restart all work correctly against a real 4-node devnet.
#[tokio::test]
async fn dis_auth_live() {
    if skip_if_no_binary() { return; }

    let ports   = DevnetPorts::new();
    let log_dir = tempdir("qcb-dis-auth");

    println!("\n── DIS-001-13 live authentication acceptance test ───────────────────");
    println!("   log dir: {}", log_dir.display());
    println!("   alice_api={} bob_api={} carol_api={} dave_api={}",
             ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api);

    // ── Generate two fresh ML-DSA-65 keypairs in-process ──────────────────
    let scheme = MlDsaScheme;

    let kp_a = scheme.generate_random()
        .expect("keypair A generation failed");
    let addr_a = derive_address_from_pq_key(&kp_a.public_key);
    let pub_a  = kp_a.public_key_hex();

    let kp_b = scheme.generate_random()
        .expect("keypair B generation failed");
    let addr_b = derive_address_from_pq_key(&kp_b.public_key);
    let pub_b  = kp_b.public_key_hex();

    println!("   wallet A : {addr_a}");
    println!("   wallet B : {addr_b}");

    // ── Spawn devnet ───────────────────────────────────────────────────────
    let mut nodes = spawn_devnet(&ports, &log_dir);

    println!("   Waiting for API ports...");
    for (name, port) in [("alice", ports.alice_api), ("bob", ports.bob_api),
                          ("carol", ports.carol_api), ("dave", ports.dave_api)] {
        assert!(
            wait_for_port(port, Duration::from_secs(30)),
            "{name} API (:{port}) did not come up within 30s"
        );
    }
    println!("   All API ports up.");

    // Wait for block 1 so all nodes are ready
    let all_ports = ports.all_api_ports();
    assert!(
        poll_until_height(&all_ports, 1, Duration::from_secs(30)),
        "devnet did not reach height 1 within 30s"
    );

    // ── Fund wallets A and B from the genesis-funded qcb1alice account ───
    // ML-DSA-derived addresses start with 0 uqcb; they need gas to execute
    // RegisterIdentity (gas cost = 92 uqcb).  Transfer 10_000 uqcb to each
    // so all subsequent txs from those addresses have plenty of gas headroom.
    println!("\n── Pre-fund: Transfer gas from qcb1alice to wallet A and B ────────");
    let fund_a = serde_json::json!({
        "id":         format!("fund-{addr_a}"),
        "sender":     "qcb1alice",
        "nonce":      0u64,
        "body":       { "Transfer": { "to": addr_a, "denom": "uqcb", "amount": 10_000u64 } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.alice_api, &fund_a.to_string())
        .expect("fund wallet A: no response");
    println!("   Fund A: {r}");
    assert!(
        r["status"].as_str().unwrap_or("") == "queued" || r["status"].as_str().unwrap_or("") == "ok",
        "fund wallet A not queued: {r}"
    );

    // Wait for Fund A to settle (alice nonce must reach 1) before submitting
    // Fund B so nonces are strictly sequential across blocks.
    {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let nonce: u64 = api_get(ports.alice_api, "/api/accounts/qcb1alice")
                .and_then(|v| v["nonce"].as_u64())
                .unwrap_or(0);
            if nonce >= 1 { break; }
            assert!(Instant::now() < deadline, "fund wallet A did not settle within 30s");
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    let fund_b = serde_json::json!({
        "id":         format!("fund-{addr_b}"),
        "sender":     "qcb1alice",
        "nonce":      1u64,
        "body":       { "Transfer": { "to": addr_b, "denom": "uqcb", "amount": 10_000u64 } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.alice_api, &fund_b.to_string())
        .expect("fund wallet B: no response");
    println!("   Fund B: {r}");
    assert!(
        r["status"].as_str().unwrap_or("") == "queued" || r["status"].as_str().unwrap_or("") == "ok",
        "fund wallet B not queued: {r}"
    );

    // Wait for Fund B to settle (alice nonce must reach 2).
    {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let nonce: u64 = api_get(ports.alice_api, "/api/accounts/qcb1alice")
                .and_then(|v| v["nonce"].as_u64())
                .unwrap_or(0);
            if nonce >= 2 { break; }
            assert!(Instant::now() < deadline, "fund txs did not settle within 30s (alice nonce={nonce})");
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    println!("   ✓ Wallets A and B funded.");

    // ── Step 1: RegisterIdentity for Wallet A and Wallet B ────────────────
    println!("\n── Step 1: RegisterIdentity ────────────────────────────────────────");

    // Register Wallet A (no signature required — devnet genesis has require_signatures:false).
    // The sender IS the address (SHA3-256 of pubkey), which establishes key binding.
    // public_key field in the tx is not used for DIS key binding — the auth challenge
    // verify POST sends the real public_key_hex for signature verification.
    let reg_a = serde_json::json!({
        "id":         format!("reg-{addr_a}"),
        "sender":     addr_a,
        "nonce":      0u64,
        "body":       "RegisterIdentity",
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.alice_api, &reg_a.to_string())
        .expect("RegisterIdentity A: no response");
    println!("   Wallet A register: {r}");
    let s = r["status"].as_str().unwrap_or("unknown");
    assert!(
        s == "queued" || s == "ok",
        "RegisterIdentity A not queued: {r}"
    );

    // Register Wallet B
    let reg_b = serde_json::json!({
        "id":         format!("reg-{addr_b}"),
        "sender":     addr_b,
        "nonce":      0u64,
        "body":       "RegisterIdentity",
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.bob_api, &reg_b.to_string())
        .expect("RegisterIdentity B: no response");
    println!("   Wallet B register: {r}");
    let s = r["status"].as_str().unwrap_or("unknown");
    assert!(
        s == "queued" || s == "ok",
        "RegisterIdentity B not queued: {r}"
    );

    // Poll until Wallet A's registration propagates to all nodes
    assert!(
        poll_until_registered(&all_ports, &addr_a, Duration::from_secs(30)),
        "Wallet A did not register on all nodes within 30s"
    );
    println!("   ✓ Wallet A registered on all nodes");

    // ── Step 2: Promote Wallet A to Verified via attestation quorum ───────
    println!("\n── Step 2: Attest Wallet A → Verified ──────────────────────────────");

    // bob attests A
    let attest_bob = serde_json::json!({
        "id":         format!("attest-bob-{addr_a}"),
        "sender":     "qcb1bob",
        "nonce":      0u64,
        "body":       { "Attest": { "claimant_id": addr_a } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.bob_api, &attest_bob.to_string())
        .expect("Attest bob: no response");
    println!("   bob attest: {r}");

    // carol attests A (second attestation)
    let attest_carol = serde_json::json!({
        "id":         format!("attest-carol-{addr_a}"),
        "sender":     "qcb1carol",
        "nonce":      0u64,
        "body":       { "Attest": { "claimant_id": addr_a } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.carol_api, &attest_carol.to_string())
        .expect("Attest carol: no response");
    println!("   carol attest: {r}");

    // dave attests A (third attestation → ATTESTATION_QUORUM=3 → Verified)
    let attest_dave = serde_json::json!({
        "id":         format!("attest-dave-{addr_a}"),
        "sender":     "qcb1dave",
        "nonce":      0u64,
        "body":       { "Attest": { "claimant_id": addr_a } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.dave_api, &attest_dave.to_string())
        .expect("Attest dave: no response");
    println!("   dave attest: {r}");

    // Poll until tier=Verified on all nodes
    assert!(
        poll_until_tier(&all_ports, &addr_a, "Verified", Duration::from_secs(30)),
        "Wallet A did not reach Verified tier on all nodes within 30s"
    );
    println!("   ✓ Wallet A is Verified on all nodes");

    // ── Step 3 & 4: Restricted scope auth succeeds for Wallet A ──────────
    println!("\n── Step 4: Restricted scope auth — Wallet A (Verified) ─────────────");

    let resp = auth_round(
        ports.alice_api,
        "identity:attest",
        &pub_a,
        &kp_a,
        "WalletA/identity:attest",
    );
    assert_eq!(resp["status"].as_str(), Some("verified"),
        "Step 4: expected status=verified, got {resp}");
    assert_eq!(resp["key_binding_verified"].as_bool(), Some(true),
        "Step 4: expected key_binding_verified=true, got {resp}");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(true),
        "Step 4: expected scope_authorized=true, got {resp}");
    println!("   ✓ Step 4 passed: Verified wallet has key_binding + scope_authorized");

    // ── Step 5: Restricted scope auth denied for Wallet B (Provisional) ──
    println!("\n── Step 5: Restricted scope auth — Wallet B (Provisional) ──────────");

    let resp = auth_round(
        ports.alice_api,
        "identity:attest",
        &pub_b,
        &kp_b,
        "WalletB/identity:attest",
    );
    // Signature is valid but identity is not Verified → scope denied
    assert_eq!(resp["status"].as_str(), Some("verified"),
        "Step 5: expected status=verified (sig check passed), got {resp}");
    // Wallet B was registered so it has a binding at Provisional — but key_binding
    // requires Verified or Established per DIS-001-12 spec.
    assert_eq!(resp["key_binding_verified"].as_bool(), Some(false),
        "Step 5: expected key_binding_verified=false for Provisional, got {resp}");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(false),
        "Step 5: expected scope_authorized=false for Provisional wallet, got {resp}");
    println!("   ✓ Step 5 passed: Provisional wallet denied restricted scope");

    // ── Step 6: Freeze Wallet A → key_binding retains, scope denied ──────
    println!("\n── Step 6: Freeze Wallet A (ConfirmSybil) ───────────────────────────");

    let confirm_sybil = serde_json::json!({
        "id":         format!("sybil-{addr_a}"),
        "sender":     "qcb1alice",
        "nonce":      2u64,   // alice nonces 0+1 used by the fund txs above
        "body":       { "ConfirmSybil": { "sybil_id": addr_a } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.alice_api, &confirm_sybil.to_string())
        .expect("ConfirmSybil: no response");
    println!("   ConfirmSybil: {r}");

    // Poll until frozen=true on all nodes
    assert!(
        poll_until_frozen(&all_ports, &addr_a, true, Duration::from_secs(30)),
        "Wallet A did not become frozen on all nodes within 30s"
    );
    println!("   ✓ Wallet A is frozen");

    let resp = auth_round(
        ports.alice_api,
        "identity:attest",
        &pub_a,
        &kp_a,
        "WalletA-frozen/identity:attest",
    );
    // Orthogonality invariant: frozen Verified retains key_binding but loses scope_authorized
    assert_eq!(resp["key_binding_verified"].as_bool(), Some(true),
        "Step 6: frozen Verified must retain key_binding_verified=true, got {resp}");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(false),
        "Step 6: frozen account must have scope_authorized=false, got {resp}");
    println!("   ✓ Step 6 passed: frozen wallet retains binding but loses scope_authorized (orthogonality)");

    // ── Step 6.5: ReverseSybil → restricted auth restored ─────────────────
    println!("\n── Step 6.5: ReverseSybil Wallet A ──────────────────────────────────");

    let reverse_sybil = serde_json::json!({
        "id":         format!("unsybil-{addr_a}"),
        "sender":     "qcb1alice",
        "nonce":      3u64,   // alice nonces: 0+1 fund, 2 ConfirmSybil, 3 ReverseSybil
        "body":       { "ReverseSybil": { "sybil_id": addr_a } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.alice_api, &reverse_sybil.to_string())
        .expect("ReverseSybil: no response");
    println!("   ReverseSybil: {r}");

    assert!(
        poll_until_frozen(&all_ports, &addr_a, false, Duration::from_secs(30)),
        "Wallet A did not become unfrozen on all nodes within 30s"
    );
    println!("   ✓ Wallet A unfrozen");

    let resp = auth_round(
        ports.alice_api,
        "identity:attest",
        &pub_a,
        &kp_a,
        "WalletA-unfrozen/identity:attest",
    );
    assert_eq!(resp["key_binding_verified"].as_bool(), Some(true),
        "Step 6.5: unfrozen Verified must have key_binding_verified=true, got {resp}");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(true),
        "Step 6.5: unfrozen Verified must have scope_authorized=true again, got {resp}");
    println!("   ✓ Step 6.5 passed: restricted auth restored after ReverseSybil");

    // ── Step 7: Node restart — ExplorerState rebuilds correctly ───────────
    println!("\n── Step 7: Restart alice node ────────────────────────────────────────");

    // Kill alice node only and respawn it (same ports)
    drop(nodes.remove(0)); // index 0 = alice
    std::thread::sleep(Duration::from_millis(500)); // brief pause for port release

    nodes.insert(0, spawn_node(
        "qcb1alice",
        ports.alice_api,
        ports.alice_p2p,
        &log_dir,
        &[ports.bob_p2p, ports.carol_p2p, ports.dave_p2p],
    ));

    assert!(
        wait_for_port(ports.alice_api, Duration::from_secs(30)),
        "alice API did not come back up within 30s after restart"
    );

    // Wait for alice to sync to at least current height (bob as reference)
    let bob_h = height_of(ports.bob_api);
    assert!(
        poll_until_height(&[ports.alice_api], bob_h, Duration::from_secs(30)),
        "alice did not catch up to height {bob_h} within 30s after restart"
    );
    println!("   ✓ alice restarted and synced to height {bob_h}");

    // Post-restart auth for Wallet A — ExplorerState must reconstruct from IdentityStore
    let resp = auth_round(
        ports.alice_api,
        "identity:attest",
        &pub_a,
        &kp_a,
        "WalletA-post-restart/identity:attest",
    );
    assert_eq!(resp["key_binding_verified"].as_bool(), Some(true),
        "Step 7: post-restart key_binding_verified must be true, got {resp}");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(true),
        "Step 7: post-restart scope_authorized must be true, got {resp}");
    println!("   ✓ Step 7 passed: ExplorerState rebuilt correctly after restart");

    // ── Step 8: Permissionless scope succeeds for both wallets ───────────
    println!("\n── Step 8: Permissionless scope (`wallet:authenticate`) ─────────────");

    // Wallet A
    let resp = auth_round(
        ports.alice_api,
        "wallet:authenticate",
        &pub_a,
        &kp_a,
        "WalletA/wallet:authenticate",
    );
    assert_eq!(resp["status"].as_str(), Some("verified"),
        "Step 8 wallet A: expected status=verified, got {resp}");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(true),
        "Step 8 wallet A: permissionless scope must be authorized, got {resp}");

    // Wallet B (Provisional — still gets permissionless scope)
    let resp = auth_round(
        ports.alice_api,
        "wallet:authenticate",
        &pub_b,
        &kp_b,
        "WalletB/wallet:authenticate",
    );
    assert_eq!(resp["status"].as_str(), Some("verified"),
        "Step 8 wallet B: expected status=verified, got {resp}");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(true),
        "Step 8 wallet B: permissionless scope must be authorized even for Provisional, got {resp}");

    println!("   ✓ Step 8 passed: permissionless scope authorized for both wallets");

    println!("\n── DIS-001-13 PASSED ────────────────────────────────────────────────");
    println!("   All 8 steps verified against live 4-node devnet.");
}

/// A04 — Revocation Propagation Live Devnet Test (QPC-CONS-001 Phase C)
///
/// Confirms that revoking an attestation that drops a Verified identity below
/// ATTESTATION_QUORUM (3) correctly downgrades it back to Provisional on ALL
/// nodes end-to-end.  This is the PR #10 merge blocker.
///
/// Flow:
///   1. Register Wallet C
///   2. Bob, Carol, Dave each attest → tier=Verified
///   3. Bob revokes his attestation (RevokeAttestation) → count drops to 2 < 3
///   4. Assert tier=Provisional on all 4 nodes
///   5. Assert scope_authorized=false for identity:attest (RequiresVerified)
///   6. Re-attest Bob → count back to 3 → assert tier=Verified again
#[tokio::test]
async fn a04_revocation_propagation() {
    if skip_if_no_binary() { return; }

    let ports   = DevnetPorts::new();
    let log_dir = tempdir("qcb-a04-revocation");

    println!("\n── A04 Revocation Propagation live devnet test ──────────────────────");
    println!("   log dir: {}", log_dir.display());
    println!("   alice_api={} bob_api={} carol_api={} dave_api={}",
             ports.alice_api, ports.bob_api, ports.carol_api, ports.dave_api);

    let scheme = MlDsaScheme;
    let kp_c   = SignatureScheme::generate_keypair(&scheme, "random")
        .expect("keypair C generation failed");
    let addr_c = derive_address_from_pq_key(&kp_c.public_key);
    let pub_c  = kp_c.public_key_hex();
    println!("   wallet C : {addr_c}");

    let _nodes = spawn_devnet(&ports, &log_dir);
    let all_ports = ports.all_api_ports();

    println!("   Waiting for API ports...");
    for (name, port) in [("alice", ports.alice_api), ("bob", ports.bob_api),
                          ("carol", ports.carol_api), ("dave", ports.dave_api)] {
        assert!(
            wait_for_port(port, Duration::from_secs(30)),
            "{name} API (:{port}) did not come up within 30s"
        );
    }
    assert!(
        poll_until_height(&all_ports, 1, Duration::from_secs(30)),
        "devnet did not reach height 1 within 30s"
    );

    // ── Fund Wallet C for gas ──────────────────────────────────────────────
    let fund_c = serde_json::json!({
        "id":         format!("fund-{addr_c}"),
        "sender":     "qcb1alice",
        "nonce":      0u64,
        "body":       { "Transfer": { "to": addr_c, "denom": "uqcb", "amount": 10_000u64 } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.alice_api, &fund_c.to_string()).expect("fund C: no response");
    println!("   Fund C: {r}");
    {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let nonce: u64 = api_get(ports.alice_api, "/api/accounts/qcb1alice")
                .and_then(|v| v["nonce"].as_u64()).unwrap_or(0);
            if nonce >= 1 { break; }
            assert!(Instant::now() < deadline, "fund C did not settle within 30s");
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    // ── Step 1: RegisterIdentity for Wallet C ─────────────────────────────
    println!("\n── Step 1: RegisterIdentity for Wallet C ────────────────────────────");
    let reg_c = serde_json::json!({
        "id":         format!("reg-{addr_c}"),
        "sender":     addr_c,
        "nonce":      0u64,
        "body":       "RegisterIdentity",
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.alice_api, &reg_c.to_string()).expect("RegisterIdentity C: no response");
    println!("   Register C: {r}");
    assert!(
        poll_until_registered(&all_ports, &addr_c, Duration::from_secs(30)),
        "Wallet C did not register on all nodes within 30s"
    );
    println!("   ✓ Wallet C registered");

    // ── Step 2: Bob + Carol + Dave attest → Verified ──────────────────────
    println!("\n── Step 2: Three attestations → Verified ────────────────────────────");
    for (attester_addr, attester_port, label) in [
        ("qcb1bob",   ports.bob_api,   "bob"),
        ("qcb1carol", ports.carol_api, "carol"),
        ("qcb1dave",  ports.dave_api,  "dave"),
    ] {
        let attest = serde_json::json!({
            "id":         format!("attest-{label}-{addr_c}"),
            "sender":     attester_addr,
            "nonce":      0u64,
            "body":       { "Attest": { "claimant_id": addr_c } },
            "gas_limit":  100_000u64,
            "signature":  [],
            "public_key": []
        });
        let r = api_post_tx(attester_port, &attest.to_string())
            .unwrap_or_else(|| panic!("Attest {label}: no response"));
        println!("   attest {label}: {r}");
    }

    assert!(
        poll_until_tier(&all_ports, &addr_c, "Verified", Duration::from_secs(30)),
        "Wallet C did not reach Verified tier on all nodes within 30s"
    );
    println!("   ✓ Wallet C is Verified on all nodes");

    // Confirm scope_authorized=true while Verified
    let resp = auth_round(ports.alice_api, "identity:attest", &pub_c, &kp_c,
                          "WalletC-verified/identity:attest");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(true),
        "Step 2: Verified wallet must have scope_authorized=true, got {resp}");
    println!("   ✓ scope_authorized=true for Verified wallet");

    // ── Step 3: Bob revokes → count drops to 2 → Provisional ─────────────
    println!("\n── Step 3: Bob revokes attestation → tier drops to Provisional ──────");
    let revoke_bob = serde_json::json!({
        "id":         format!("revoke-bob-{addr_c}"),
        "sender":     "qcb1bob",
        "nonce":      1u64,   // bob used nonce 0 for Attest
        "body":       { "RevokeAttestation": { "attested_id": addr_c } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.bob_api, &revoke_bob.to_string())
        .expect("RevokeAttestation bob: no response");
    println!("   RevokeAttestation bob: {r}");

    // ── Step 4: Assert tier=Provisional on all 4 nodes ───────────────────
    println!("\n── Step 4: Assert tier=Provisional on all nodes ─────────────────────");
    assert!(
        poll_until_tier(&all_ports, &addr_c, "Provisional", Duration::from_secs(30)),
        "Wallet C did not downgrade to Provisional tier on all nodes within 30s \
         after attestation count dropped below quorum"
    );
    println!("   ✓ Wallet C is Provisional on all nodes — revocation propagation confirmed");

    // ── Step 5: Scope denied after downgrade ─────────────────────────────
    println!("\n── Step 5: Assert scope_authorized=false after downgrade ────────────");
    let resp = auth_round(ports.alice_api, "identity:attest", &pub_c, &kp_c,
                          "WalletC-downgraded/identity:attest");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(false),
        "Step 5: downgraded-to-Provisional wallet must have scope_authorized=false, got {resp}");
    println!("   ✓ scope_authorized=false after revocation downgrade");

    // ── Step 6: Alice attests → back to Verified (bob is on cooldown) ────
    // Bob is subject to REVOCATION_COOLDOWN_EPOCHS and cannot immediately
    // re-attest.  Use alice (a Verified genesis validator who has not yet
    // attested Wallet C) as the 4th attester to bring the count back to 3.
    println!("\n── Step 6: Alice attests Wallet C → back to Verified ────────────────");
    let attest_alice = serde_json::json!({
        "id":         format!("reattest-alice-{addr_c}"),
        "sender":     "qcb1alice",
        "nonce":      1u64,   // alice nonce 0 used for Fund C
        "body":       { "Attest": { "claimant_id": addr_c } },
        "gas_limit":  100_000u64,
        "signature":  [],
        "public_key": []
    });
    let r = api_post_tx(ports.alice_api, &attest_alice.to_string())
        .expect("Re-attest alice: no response");
    println!("   Re-attest alice: {r}");

    assert!(
        poll_until_tier(&all_ports, &addr_c, "Verified", Duration::from_secs(30)),
        "Wallet C did not recover to Verified after alice re-attestation within 30s \
         (alice is the 4th attester; bob is on REVOCATION_COOLDOWN_EPOCHS)"
    );
    println!("   ✓ Wallet C recovered to Verified (alice as 4th attester)");

    let resp = auth_round(ports.alice_api, "identity:attest", &pub_c, &kp_c,
                          "WalletC-recovered/identity:attest");
    assert_eq!(resp["scope_authorized"].as_bool(), Some(true),
        "Step 6: re-verified wallet must have scope_authorized=true, got {resp}");
    println!("   ✓ scope_authorized=true restored after re-attestation");

    println!("\n── A04 PASSED ───────────────────────────────────────────────────────");
    println!("   Revocation propagation confirmed: attestation count below quorum");
    println!("   correctly downgrades Verified → Provisional on all 4 nodes.");
    println!("   Recovery via a fresh attester (alice) restores Verified tier.");
    println!("   Note: REVOCATION_COOLDOWN_EPOCHS=1 applies to the revoking attester (bob).");
}
