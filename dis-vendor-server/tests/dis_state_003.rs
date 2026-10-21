//! DIS-STATE-003 acceptance tests: multi-instance and distributed-state security.
//!
//! Each test starts two independent `dis-vendor-server` processes that share a
//! fresh PostgreSQL database. The servers reach Postgres through an in-test
//! TCP proxy so a database outage can be simulated per test.
//!
//! Environment:
//!   DIS_TEST_DATABASE_URL  admin connection, default postgres://postgres:postgres@127.0.0.1:5432/postgres
//!   DIS_PG_RESTART_CMD     shell command that restarts the real Postgres server
//!                          (e.g. "service postgresql restart"). Without it the
//!                          DB-restart test falls back to severing all connections.

use dis_core::{canonical_request, Request};
use futures::future::join_all;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, Connection, PgConnection, PgPool};
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, task::AbortHandle};

/// Tests share one Postgres server (and one may restart it), so run serially.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const TTL: i64 = 299;

fn admin_url() -> String {
    std::env::var("DIS_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432/postgres".into())
}
fn hex(b: &[u8]) -> String { b.iter().map(|b| format!("{b:02x}")).collect() }
fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n]; getrandom::getrandom(&mut b).unwrap(); hex(&b)
}
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

// ---------------------------------------------------------------- DB proxy

/// TCP proxy between the servers and Postgres; `set_up(false)` simulates an outage.
struct DbProxy {
    port: u16,
    up: Arc<AtomicBool>,
    conns: Arc<Mutex<Vec<AbortHandle>>>,
    accept: AbortHandle,
}

impl DbProxy {
    async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let up = Arc::new(AtomicBool::new(true));
        let conns: Arc<Mutex<Vec<AbortHandle>>> = Arc::default();
        let (up2, conns2) = (up.clone(), conns.clone());
        let accept = tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else { continue };
                if !up2.load(Ordering::SeqCst) { drop(client); continue; }
                let h = tokio::spawn(async move {
                    if let Ok(mut server) = tokio::net::TcpStream::connect(upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
                conns2.lock().unwrap().push(h.abort_handle());
            }
        }).abort_handle();
        DbProxy { port, up, conns, accept }
    }
    fn set_up(&self, up: bool) {
        self.up.store(up, Ordering::SeqCst);
        if !up { for c in self.conns.lock().unwrap().drain(..) { c.abort(); } }
    }
}
impl Drop for DbProxy {
    fn drop(&mut self) { self.accept.abort(); self.set_up(false); }
}

// ---------------------------------------------------------------- servers

struct Server { child: Child, base: String, port: u16, db_url: String }

impl Server {
    async fn start(db_url: &str) -> Self { Self::start_on(db_url, free_port()).await }
    async fn start_on(db_url: &str, port: u16) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_dis-vendor-server"))
            .env("DATABASE_URL", db_url)
            .env("PORT", port.to_string())
            .env("DIS_DB_ACQUIRE_TIMEOUT_MS", "1500")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn().expect("spawn dis-vendor-server");
        let s = Server { child, base: format!("http://127.0.0.1:{port}"), port, db_url: db_url.into() };
        s.wait_healthy(Duration::from_secs(30)).await;
        s
    }
    async fn wait_healthy(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(r) = http().get(format!("{}/health", self.base)).send().await {
                if r.status().is_success() { return; }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server {} not healthy within {timeout:?}", self.base);
    }
    /// SIGKILL — no graceful shutdown, no chance to flush anything.
    fn crash(&mut self) { self.child.kill().unwrap(); self.child.wait().unwrap(); }
    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let r = http().post(format!("{}{path}", self.base)).json(&body).send().await.unwrap();
        let code = r.status().as_u16();
        (code, r.json().await.unwrap_or(Value::Null))
    }
}
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().timeout(Duration::from_secs(20)).build().unwrap()
}

// ---------------------------------------------------------------- cluster

struct Cluster { a: Server, b: Server, proxy: DbProxy, db: PgPool, vendor: String }

impl Cluster {
    /// Fresh database, proxy, two server instances, one registered vendor.
    async fn start() -> Self {
        let admin = admin_url();
        let mut conn = PgConnection::connect(&admin).await.expect("connect to admin Postgres");
        let db_name = format!("dis003_{}", rand_hex(6));
        sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&mut conn).await.unwrap();
        let base = admin.rsplit_once('/').unwrap().0.to_string();
        let direct = format!("{base}/{db_name}");
        let upstream: SocketAddr = {
            let hostport = base.rsplit_once('@').map(|x| x.1).unwrap_or(&base).trim_start_matches("postgres://");
            let hostport = hostport.replace("localhost", "127.0.0.1");
            let addr = tokio::net::lookup_host(&hostport).await.unwrap().next().unwrap(); addr
        };
        let proxy = DbProxy::start(upstream).await;
        let via_proxy = format!("{}@127.0.0.1:{}/{db_name}",
            base.rsplit_once('@').unwrap().0, proxy.port);
        let a = Server::start(&via_proxy).await;
        let b = Server::start(&via_proxy).await;
        let db = PgPoolOptions::new().max_connections(5).connect(&direct).await.unwrap();
        let vendor = format!("vendor{}", rand_hex(4));
        let (_, r) = a.post("/vendor/register", json!({"vendor_id":vendor,"rp_origin":"https://docs.example",
            "allowed_resources":["doc:1"],"allowed_actions":["read"],"api_key":"k"})).await;
        assert_eq!(r["status"], "registered", "{r}");
        Cluster { a, b, proxy, db, vendor }
    }
}

struct Wallet { id: String, pk: Vec<u8>, sk: Vec<u8> }

impl Wallet {
    async fn enroll(s: &Server) -> Self {
        let (pk, sk) = dilithium3::keypair();
        let w = Wallet { id: format!("wallet-{}", rand_hex(4)), pk: pk.as_bytes().to_vec(), sk: sk.as_bytes().to_vec() };
        let (_, r) = s.post("/enroll/challenge", json!({"wallet_id":w.id})).await;
        let nonce = r["nonce"].as_str().unwrap().to_string();
        let sig = dilithium3::detached_sign(nonce.as_bytes(), &sk);
        let (_, r) = s.post("/enroll", json!({"wallet_id":w.id,"public_key_hex":hex(&w.pk),
            "nonce_signature_hex":hex(sig.as_bytes())})).await;
        assert_eq!(r["status"], "enrolled", "{r}");
        w
    }
    fn sign(&self, ch: &Value) -> Vec<u8> { sign_with(&self.sk, ch) }
}

fn to_request(ch: &Value) -> Request {
    let bytes16 = |v: &Value| -> [u8; 16] {
        let b: Vec<u8> = v.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect();
        b.try_into().unwrap()
    };
    Request {
        suite_id: ch["suite_id"].as_u64().unwrap() as u16,
        rp_id: ch["rp_id"].as_str().unwrap().into(),
        rp_origin: ch["rp_origin"].as_str().unwrap().into(),
        challenge_id: bytes16(&ch["challenge_id"]), nonce: bytes16(&ch["nonce"]),
        issued_at: ch["issued_at"].as_u64().unwrap(), expires_at: ch["expires_at"].as_u64().unwrap(),
        resource_id: ch["resource_id"].as_str().unwrap().into(),
        action: ch["action"].as_str().unwrap().into(),
        scopes: ch["scopes"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().into()).collect(),
        operation_digest: None,
        policy_id: ch["policy_id"].as_str().unwrap().into(),
    }
}
fn sign_with(sk: &[u8], ch: &Value) -> Vec<u8> {
    let sk = dilithium3::SecretKey::from_bytes(sk).unwrap();
    dilithium3::detached_sign(&canonical_request(&to_request(ch)).unwrap(), &sk).as_bytes().to_vec()
}
fn challenge_key(vendor: &str, ch: &Value) -> String {
    format!("dis:v1:challenge:{vendor}:{}", hex(&to_request(ch).challenge_id))
}

impl Cluster {
    async fn challenge(&self, s: &Server, w: &Wallet) -> Value {
        let (_, r) = s.post("/challenge", json!({"wallet_id":w.id,"vendor_id":self.vendor,
            "resource_id":"doc:1","action":"read"})).await;
        assert_eq!(r["status"], "ok", "{r}");
        r["challenge"].clone()
    }
    fn proof(&self, w: &Wallet, ch: &Value, sig: &[u8]) -> Value {
        json!({"wallet_id":w.id,"vendor_id":self.vendor,"challenge":ch,
               "public_key_hex":hex(&w.pk),"signature_hex":hex(sig)})
    }
    async fn consumed_at(&self, ch: &Value) -> Option<i64> {
        sqlx::query_scalar("SELECT consumed_at FROM challenges WHERE challenge_key=$1")
            .bind(challenge_key(&self.vendor, ch)).fetch_one(&self.db).await.unwrap()
    }
}

fn status(r: &Value) -> &str { r["status"].as_str().unwrap_or("") }
fn message(r: &Value) -> &str { r["message"].as_str().unwrap_or("") }

// ---------------------------------------------------------------- tests

/// State is shared: issue on A, verify on B; replay on A rejected.
/// Challenge keys are namespaced and the DB TTL equals the server window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_01_two_instances_share_one_store() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let w = Wallet::enroll(&c.b).await;
    let ch = c.challenge(&c.a, &w).await;

    let key = challenge_key(&c.vendor, &ch);
    let (issued, expires): (i64, i64) = sqlx::query_as(
        "SELECT issued_at, expires_at FROM challenges WHERE challenge_key=$1")
        .bind(&key).fetch_one(&c.db).await.unwrap();
    assert!(key.starts_with(&format!("dis:v1:challenge:{}:", c.vendor)));
    assert_eq!(expires - issued, TTL, "DB TTL must equal server window");
    assert_eq!(ch["expires_at"].as_i64().unwrap() - ch["issued_at"].as_i64().unwrap(), TTL);
    assert_eq!((issued, expires), (ch["issued_at"].as_i64().unwrap(), ch["expires_at"].as_i64().unwrap()));

    let proof = c.proof(&w, &ch, &w.sign(&ch));
    let (_, r) = c.b.post("/verify", proof.clone()).await;
    assert_eq!(status(&r), "verified", "{r}");
    let (_, r) = c.a.post("/verify", proof).await;
    assert_eq!(status(&r), "rejected", "{r}");
    assert!(message(&r).starts_with("Replay"), "{r}");
}

/// The same valid proof submitted 24× concurrently across both instances is accepted exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_02_concurrent_proof_accepted_exactly_once() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let w = Wallet::enroll(&c.a).await;
    for round in 0..3 {
        let ch = c.challenge(if round % 2 == 0 { &c.a } else { &c.b }, &w).await;
        let proof = c.proof(&w, &ch, &w.sign(&ch));
        let results = join_all((0..24).map(|i| {
            let s = if i % 2 == 0 { &c.a } else { &c.b };
            s.post("/verify", proof.clone())
        })).await;
        let accepted = results.iter().filter(|(_, r)| status(r) == "verified").count();
        let replays = results.iter().filter(|(_, r)| status(r) == "rejected" && message(r).starts_with("Replay")).count();
        assert_eq!(accepted, 1, "round {round}: {results:?}");
        assert_eq!(replays, 23, "round {round}: {results:?}");
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM verified_sessions WHERE challenge_key=$1")
            .bind(challenge_key(&c.vendor, &ch)).fetch_one(&c.db).await.unwrap();
        assert_eq!(sessions, 1);
    }
}

/// Revocation on A is enforced by B — for challenges issued before and after the revocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_03_revocation_on_one_instance_enforced_by_other() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let w = Wallet::enroll(&c.a).await;
    let ch = c.challenge(&c.b, &w).await;
    let (_, r) = c.b.post("/verify", c.proof(&w, &ch, &w.sign(&ch))).await;
    assert_eq!(status(&r), "verified", "{r}");

    let pending = c.challenge(&c.b, &w).await; // issued before revocation
    let (_, r) = c.a.post("/admin/revoke", json!({"wallet_id":w.id})).await;
    assert_eq!(status(&r), "revoked", "{r}");

    let (_, r) = c.b.post("/verify", c.proof(&w, &pending, &w.sign(&pending))).await;
    assert_eq!(status(&r), "rejected", "{r}");
    assert!(message(&r).contains("revoked"), "{r}");
    assert_eq!(c.consumed_at(&pending).await, None);

    let after = c.challenge(&c.a, &w).await; // issued after revocation
    for s in [&c.a, &c.b] {
        let (_, r) = s.post("/verify", c.proof(&w, &after, &w.sign(&after))).await;
        assert!(message(&r).contains("revoked"), "{r}");
    }
}

/// Forged proofs (bad signature, wrong key, tampered request) never consume the legitimate challenge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_04_forged_proof_cannot_consume_challenge() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let w = Wallet::enroll(&c.a).await;
    let ch = c.challenge(&c.a, &w).await;
    let good = w.sign(&ch);

    let mut flipped = good.clone();
    flipped[100] ^= 0x01;
    let (_, attacker_sk) = dilithium3::keypair();
    let wrong_key = sign_with(attacker_sk.as_bytes(), &ch);
    let mut tampered_ch = ch.clone();
    tampered_ch["action"] = json!("write");
    let tampered_sig = w.sign(&tampered_ch);

    let attempts = [
        c.proof(&w, &ch, &flipped),
        c.proof(&w, &ch, &wrong_key),
        c.proof(&w, &ch, &vec![0u8; good.len()]),
        c.proof(&w, &tampered_ch, &tampered_sig),
    ];
    for (i, forged) in attempts.into_iter().enumerate() {
        for s in [&c.a, &c.b] {
            let (_, r) = s.post("/verify", forged.clone()).await;
            assert_ne!(status(&r), "verified", "attempt {i}: {r}");
        }
    }
    // Concurrent burst of forgeries racing each other.
    let burst = join_all((0..16).map(|i| {
        let mut sig = good.clone(); sig[i * 7 % good.len()] ^= 0x80;
        let s = if i % 2 == 0 { &c.a } else { &c.b };
        s.post("/verify", c.proof(&w, &ch, &sig))
    })).await;
    assert!(burst.iter().all(|(_, r)| status(r) != "verified"));

    assert_eq!(c.consumed_at(&ch).await, None, "forged proof consumed the challenge");
    let (_, r) = c.b.post("/verify", c.proof(&w, &ch, &good)).await;
    assert_eq!(status(&r), "verified", "legitimate proof must still succeed: {r}");
}

/// SIGKILL of an instance after consumption cannot resurrect the challenge on any instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_05_server_crash_cannot_restore_consumed_challenge() {
    let _g = SERIAL.lock().await;
    let mut c = Cluster::start().await;
    let w = Wallet::enroll(&c.a).await;
    let ch = c.challenge(&c.a, &w).await;
    let proof = c.proof(&w, &ch, &w.sign(&ch));
    let (_, r) = c.a.post("/verify", proof.clone()).await;
    assert_eq!(status(&r), "verified", "{r}");
    let consumed = c.consumed_at(&ch).await;
    assert!(consumed.is_some());

    c.a.crash();
    let (_, r) = c.b.post("/verify", proof.clone()).await;
    assert!(message(&r).starts_with("Replay"), "B after A crash: {r}");

    let (url, port) = (c.a.db_url.clone(), c.a.port);
    c.a = Server::start_on(&url, port).await;
    for s in [&c.a, &c.b] {
        let (_, r) = s.post("/verify", proof.clone()).await;
        assert!(message(&r).starts_with("Replay"), "after restart: {r}");
    }
    assert_eq!(c.consumed_at(&ch).await, consumed);
}

/// DB outage: every state-dependent endpoint fails closed (503, never "verified");
/// after recovery the untouched challenge still works exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_06_db_outage_fails_closed() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let w = Wallet::enroll(&c.a).await;
    let ch = c.challenge(&c.a, &w).await;
    let proof = c.proof(&w, &ch, &w.sign(&ch));

    c.proxy.set_up(false);
    for s in [&c.a, &c.b] {
        let (code, r) = s.post("/verify", proof.clone()).await;
        assert_eq!(code, 503, "{r}");
        assert_ne!(status(&r), "verified", "{r}");
        let (code, _) = s.post("/challenge", json!({"wallet_id":w.id,"vendor_id":c.vendor,
            "resource_id":"doc:1","action":"read"})).await;
        assert_eq!(code, 503);
        let (code, _) = s.post("/admin/revoke", json!({"wallet_id":w.id})).await;
        assert_eq!(code, 503);
        let h = http().get(format!("{}/health", s.base)).send().await.unwrap();
        assert_eq!(h.status().as_u16(), 503);
    }
    // Concurrent burst during the outage: still nothing granted.
    let burst = join_all((0..10).map(|i| (if i % 2 == 0 { &c.a } else { &c.b }).post("/verify", proof.clone()))).await;
    assert!(burst.iter().all(|(code, r)| *code == 503 && status(r) != "verified"), "{burst:?}");

    c.proxy.set_up(true);
    c.a.wait_healthy(Duration::from_secs(15)).await;
    c.b.wait_healthy(Duration::from_secs(15)).await;
    assert_eq!(c.consumed_at(&ch).await, None, "outage must not consume");
    let (_, r) = c.b.post("/verify", proof.clone()).await;
    assert_eq!(status(&r), "verified", "{r}");
    let (_, r) = c.a.post("/verify", proof).await;
    assert!(message(&r).starts_with("Replay"), "{r}");
}

/// Postgres restart preserves replay protection and revocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_07_db_restart_preserves_guarantees() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let w1 = Wallet::enroll(&c.a).await;
    let w2 = Wallet::enroll(&c.b).await;
    let ch1 = c.challenge(&c.a, &w1).await;
    let p1 = c.proof(&w1, &ch1, &w1.sign(&ch1));
    let (_, r) = c.a.post("/verify", p1.clone()).await;
    assert_eq!(status(&r), "verified", "{r}");
    let ch2 = c.challenge(&c.b, &w2).await;
    let p2 = c.proof(&w2, &ch2, &w2.sign(&ch2));
    let (_, r) = c.b.post("/admin/revoke", json!({"wallet_id":w2.id})).await;
    assert_eq!(status(&r), "revoked");

    match std::env::var("DIS_PG_RESTART_CMD") {
        Ok(cmd) => {
            eprintln!("restarting Postgres: {cmd}");
            let st = Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
            assert!(st.success(), "restart command failed");
        }
        Err(_) => {
            eprintln!("DIS_PG_RESTART_CMD unset — simulating restart by severing all DB connections");
            c.proxy.set_up(false);
            tokio::time::sleep(Duration::from_secs(1)).await;
            c.proxy.set_up(true);
        }
    }
    c.a.wait_healthy(Duration::from_secs(30)).await;
    c.b.wait_healthy(Duration::from_secs(30)).await;

    for s in [&c.a, &c.b] {
        let (_, r) = s.post("/verify", p1.clone()).await;
        assert!(message(&r).starts_with("Replay"), "replay after DB restart: {r}");
        let (_, r) = s.post("/verify", p2.clone()).await;
        assert!(message(&r).contains("revoked"), "revocation after DB restart: {r}");
    }
    let w3 = Wallet::enroll(&c.b).await;
    let ch3 = c.challenge(&c.b, &w3).await;
    let (_, r) = c.a.post("/verify", c.proof(&w3, &ch3, &w3.sign(&ch3))).await;
    assert_eq!(status(&r), "verified", "service must recover: {r}");
}

/// Ordering rule: verification and revocation serialize on the wallet's key row.
///  (a) a verification that reaches the lock while a revocation is in flight
///      waits, then sees the committed revocation and is rejected;
///  (b) a revocation waits for an in-flight verification to commit;
///  (c) under a concurrent race, every verify that starts after /admin/revoke
///      has returned is rejected, and every grant is recorded exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_08_concurrent_revocation_and_verification_ordering() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;

    // (a) revocation in flight (holding the key-row lock) blocks verification.
    let w = Wallet::enroll(&c.a).await;
    let ch = c.challenge(&c.a, &w).await;
    let proof = c.proof(&w, &ch, &w.sign(&ch));
    let mut tx = c.db.begin().await.unwrap();
    let key_id: String = sqlx::query_scalar("SELECT key_id FROM enrolled_keys WHERE wallet_id=$1 FOR UPDATE")
        .bind(&w.id).fetch_one(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO revocations (key_id,wallet_id,revoked_at) VALUES ($1,$2,0)")
        .bind(&key_id).bind(&w.id).execute(&mut *tx).await.unwrap();
    let b = &c.b;
    let pending = tokio::spawn({ let base = b.base.clone(); let p = proof.clone();
        async move { http().post(format!("{base}/verify")).json(&p).send().await.unwrap().json::<Value>().await.unwrap() } });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!pending.is_finished(), "verification must wait for the in-flight revocation");
    tx.commit().await.unwrap();
    let r = pending.await.unwrap();
    assert_eq!(status(&r), "rejected", "{r}");
    assert!(message(&r).contains("revoked"), "{r}");
    assert_eq!(c.consumed_at(&ch).await, None);

    // (b) verification in flight (holding FOR SHARE) blocks revocation.
    let w = Wallet::enroll(&c.a).await;
    let mut tx = c.db.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM enrolled_keys WHERE wallet_id=$1 FOR SHARE").bind(&w.id).execute(&mut *tx).await.unwrap();
    let pending = tokio::spawn({ let base = c.a.base.clone(); let id = w.id.clone();
        async move { http().post(format!("{base}/admin/revoke")).json(&json!({"wallet_id":id})).send().await.unwrap().json::<Value>().await.unwrap() } });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!pending.is_finished(), "revocation must wait for the in-flight verification");
    tx.commit().await.unwrap();
    assert_eq!(status(&pending.await.unwrap()), "revoked");

    // (c) race: 40 independent valid proofs vs one revocation, across both instances.
    let w = Wallet::enroll(&c.a).await;
    let mut proofs = Vec::new();
    let mut late = Vec::new();
    for i in 0..4 {
        let ch = c.challenge(if i % 2 == 0 { &c.a } else { &c.b }, &w).await;
        late.push(c.proof(&w, &ch, &w.sign(&ch)));
    }
    for i in 0..40 {
        let ch = c.challenge(if i % 2 == 0 { &c.a } else { &c.b }, &w).await;
        proofs.push(c.proof(&w, &ch, &w.sign(&ch)));
    }
    let revoked_at: Arc<Mutex<Option<Instant>>> = Arc::default();
    let revoke = { let rv = revoked_at.clone(); let base = c.b.base.clone(); let id = w.id.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let r: Value = http().post(format!("{base}/admin/revoke")).json(&json!({"wallet_id":id}))
                .send().await.unwrap().json().await.unwrap();
            *rv.lock().unwrap() = Some(Instant::now());
            r
        } };
    let verifies = join_all(proofs.into_iter().enumerate().map(|(i, p)| {
        let base = if i % 2 == 0 { c.a.base.clone() } else { c.b.base.clone() };
        async move {
            tokio::time::sleep(Duration::from_millis(i as u64 * 3)).await;
            let started = Instant::now();
            let r: Value = http().post(format!("{base}/verify")).json(&p).send().await.unwrap().json().await.unwrap();
            (started, r)
        }
    }));
    let (rv, results) = tokio::join!(revoke, verifies);
    assert_eq!(status(&rv), "revoked");
    let revoked_at = revoked_at.lock().unwrap().unwrap();
    let mut granted = 0;
    for (started, r) in &results {
        match status(r) {
            "verified" => {
                granted += 1;
                assert!(*started < revoked_at, "verification started after revocation returned was granted: {r}");
            }
            "rejected" => assert!(message(r).contains("revoked"), "unexpected rejection: {r}"),
            _ => panic!("unexpected response: {r}"),
        }
    }
    let after = results.iter().filter(|(s, _)| *s > revoked_at).count();
    // Proofs for challenges issued before the revocation, submitted after it returned.
    for (i, p) in late.into_iter().enumerate() {
        let (_, r) = (if i % 2 == 0 { &c.a } else { &c.b }).post("/verify", p).await;
        assert!(message(&r).contains("revoked"), "post-revocation verify must be rejected: {r}");
    }
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM verified_sessions WHERE wallet_id=$1")
        .bind(&w.id).fetch_one(&c.db).await.unwrap();
    assert_eq!(sessions, granted as i64, "every grant recorded exactly once");
    eprintln!("race: {granted} granted before revocation, {} rejected ({after} started after revoke returned)",
        results.len() - granted);
}

/// The DB row's expiry window is what is enforced: an expired challenge is
/// rejected and left unconsumed, even with a valid signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_09_expiry_enforced_from_db_window() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let w = Wallet::enroll(&c.a).await;
    let ch = c.challenge(&c.a, &w).await;
    sqlx::query("UPDATE challenges SET issued_at=issued_at-1000, expires_at=expires_at-1000 WHERE challenge_key=$1")
        .bind(challenge_key(&c.vendor, &ch)).execute(&c.db).await.unwrap();
    let (_, r) = c.b.post("/verify", c.proof(&w, &ch, &w.sign(&ch))).await;
    assert!(message(&r).starts_with("Time"), "{r}");
    assert_eq!(c.consumed_at(&ch).await, None);
    let bad = sqlx::query("UPDATE challenges SET expires_at=expires_at+1000 WHERE challenge_key=$1")
        .bind(challenge_key(&c.vendor, &ch)).execute(&c.db).await;
    assert!(bad.is_err(), "TTL CHECK constraint must reject a window != server TTL");
}
