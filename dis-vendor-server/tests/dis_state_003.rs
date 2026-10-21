//! DIS-STATE-003 / DIS-SEC-004 acceptance tests.
//!
//! Each test starts two independent `dis-vendor-server` processes that share a
//! fresh PostgreSQL database. The servers reach Postgres through an in-test
//! TCP proxy so a database outage can be simulated per test.
//! A tiny in-process HTTP server plays the role of vendor origins (well-known
//! endpoint) so origin-ownership verification can be tested without the network.
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
use sha2::{Digest, Sha256};
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
const ADMIN_KEY: &str = "test-admin-key-0123456789abcdef0123456789";
const REGISTRATION_KEY: &str = "test-registration-key-0123456789abcdef0123456789";

// ---------------------------------------------------------------- origin mock

/// A tiny HTTP server that responds to `GET /.well-known/dis-vendor-registration`
/// with the currently configured ownership token (or 404 when cleared).
/// Each mock represents one rp_origin; tests set the token for the current
/// registration attempt and clear it to simulate "nothing published".
struct OriginMock {
    port: u16,
    /// `None` → 404; `Some(s)` → 200 with body `s`.
    token: Arc<Mutex<Option<String>>>,
    _handle: AbortHandle,
}

fn sha256_hex_test(b: &[u8]) -> String {
    let h: [u8; 32] = Sha256::digest(b).into();
    h.iter().map(|b| format!("{b:02x}")).collect()
}

impl OriginMock {
    async fn start() -> Self {
        let token: Arc<Mutex<Option<String>>> = Arc::default();
        let token2 = token.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        use axum::{routing::get as aGet, Router as ARouter};
        let app = ARouter::new()
            .route("/.well-known/dis-vendor-registration", aGet(move || {
                let token = token2.clone();
                async move {
                    match token.lock().unwrap().clone() {
                        Some(t) => (axum::http::StatusCode::OK, t),
                        None    => (axum::http::StatusCode::NOT_FOUND, String::new()),
                    }
                }
            }));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        }).abort_handle();
        OriginMock { port, token, _handle: handle }
    }

    /// Compute and publish the ownership token for this vendor + registration_token.
    /// Returns the token string (sha256("{vendor_id}:{registration_token}")).
    fn set_token(&self, vendor_id: &str, registration_token: &str) -> String {
        let t = sha256_hex_test(format!("{vendor_id}:{registration_token}").as_bytes());
        *self.token.lock().unwrap() = Some(t.clone());
        t
    }

    /// Remove the token (simulates "nothing published at the well-known path").
    fn clear(&self) { *self.token.lock().unwrap() = None; }

    /// Convenience: set_token is the common case; keep the old name as an alias.
    fn register(&self, vendor_id: &str, registration_token: &str) -> String {
        self.set_token(vendor_id, registration_token)
    }

    /// The rp_origin this mock represents (HTTP because tests don't need TLS).
    fn origin(&self) -> String { format!("http://127.0.0.1:{}", self.port) }
}

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
            .env("DIS_ADMIN_API_KEY", ADMIN_KEY)
            .env("DIS_VENDOR_REGISTRATION_KEY", REGISTRATION_KEY)
            // Allow HTTP origins so tests can use OriginMock (plain HTTP on localhost).
            // Both flags are required together; neither must appear in production.
            .env("DIS_ALLOW_HTTP_ORIGINS", "1")
            .env("DIS_TEST_MODE", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn().expect("spawn dis-vendor-server");
        let s = Server { child, base: format!("http://127.0.0.1:{port}"), port, db_url: db_url.into() };
        s.wait_healthy(Duration::from_secs(30)).await;
        s
    }

    /// Start a server in production mode (no DIS_ALLOW_HTTP_ORIGINS).
    /// Used by SSRF adversarial tests that need the strict validation path.
    async fn start_prod_mode(db_url: &str) -> Self {
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_dis-vendor-server"))
            .env("DATABASE_URL", db_url)
            .env("PORT", port.to_string())
            .env("DIS_DB_ACQUIRE_TIMEOUT_MS", "1500")
            .env("DIS_ADMIN_API_KEY", ADMIN_KEY)
            .env("DIS_VENDOR_REGISTRATION_KEY", REGISTRATION_KEY)
            // DIS_ALLOW_HTTP_ORIGINS intentionally NOT set → production SSRF checks active.
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
        let mut rq = http().post(format!("{}{path}", self.base)).json(&body);
        if path.starts_with("/admin/") { rq = rq.bearer_auth(ADMIN_KEY); }
        let r = rq.send().await.unwrap();
        let code = r.status().as_u16();
        (code, r.json().await.unwrap_or(Value::Null))
    }
    async fn post_with_reg_key(&self, path: &str, body: Value) -> (u16, Value) {
        let r = http().post(format!("{}{path}", self.base)).json(&body)
            .bearer_auth(REGISTRATION_KEY).send().await.unwrap();
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

struct Cluster {
    a: Server, b: Server, proxy: DbProxy, db: PgPool, vendor: String,
    /// Mock HTTP server that answers well-known requests for the test vendor.
    _mock: OriginMock,
}

impl Cluster {
    /// Fresh database, proxy, two server instances, one registered vendor.
    async fn start() -> Self {
        let mock = OriginMock::start().await;
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
        let reg_token = rand_hex(32);
        mock.register(&vendor, &reg_token);
        let (_, r) = a.post_with_reg_key("/vendor/register",
            json!({"vendor_id":vendor,"rp_origin":mock.origin(),
                   "allowed_resources":["doc:1"],"allowed_actions":["read"],
                   "api_key":"k","registration_token":reg_token})).await;
        assert_eq!(r["status"], "registered", "{r}");
        Cluster { a, b, proxy, db, vendor, _mock: mock }
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
        async move { http().post(format!("{base}/admin/revoke")).bearer_auth(ADMIN_KEY).json(&json!({"wallet_id":id})).send().await.unwrap().json::<Value>().await.unwrap() } });
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
            let r: Value = http().post(format!("{base}/admin/revoke")).bearer_auth(ADMIN_KEY).json(&json!({"wallet_id":id}))
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

/// Admin endpoints reject missing or wrong credentials on every instance and
/// leave state untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_10_admin_endpoints_require_authentication() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let w = Wallet::enroll(&c.a).await;
    for s in [&c.a, &c.b] {
        for token in [None, Some("wrong"), Some(&ADMIN_KEY[..ADMIN_KEY.len() - 1])] {
            for (path, body) in [("/admin/revoke", json!({"wallet_id":w.id})), ("/admin/reset", json!({}))] {
                let mut rq = http().post(format!("{}{path}", s.base)).json(&body);
                if let Some(t) = token { rq = rq.bearer_auth(t); }
                let r = rq.send().await.unwrap();
                assert_eq!(r.status().as_u16(), 401, "{path} with {token:?}");
            }
        }
    }
    let revoked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM revocations").fetch_one(&c.db).await.unwrap();
    assert_eq!(revoked, 0);
    let ch = c.challenge(&c.b, &w).await; // reset did not run either
    let (_, r) = c.a.post("/verify", c.proof(&w, &ch, &w.sign(&ch))).await;
    assert_eq!(status(&r), "verified", "{r}");
}

/// Enrollment nonces are bounded in time and single-use.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s3_11_enrollment_nonce_expires_and_is_single_use() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let (pk, sk) = dilithium3::keypair();
    let id = format!("wallet-{}", rand_hex(4));
    let (_, r) = c.a.post("/enroll/challenge", json!({"wallet_id":id})).await;
    let nonce = r["nonce"].as_str().unwrap().to_string();
    sqlx::query("UPDATE enroll_nonces SET expires_at = expires_at - 1000 WHERE wallet_id=$1")
        .bind(&id).execute(&c.db).await.unwrap();
    let body = json!({"wallet_id":id,"public_key_hex":hex(pk.as_bytes()),
        "nonce_signature_hex":hex(dilithium3::detached_sign(nonce.as_bytes(), &sk).as_bytes())});
    let (_, r) = c.b.post("/enroll", body.clone()).await;
    assert!(message(&r).contains("expired"), "{r}");
    let (_, r) = c.b.post("/enroll", body).await;
    assert!(message(&r).contains("no enroll challenge"), "expired nonce must be deleted: {r}");

    let (_, r) = c.a.post("/enroll/challenge", json!({"wallet_id":id})).await;
    let nonce = r["nonce"].as_str().unwrap().to_string();
    let body = json!({"wallet_id":id,"public_key_hex":hex(pk.as_bytes()),
        "nonce_signature_hex":hex(dilithium3::detached_sign(nonce.as_bytes(), &sk).as_bytes())});
    let (_, r) = c.b.post("/enroll", body.clone()).await;
    assert_eq!(status(&r), "enrolled", "{r}");
    let (_, r) = c.a.post("/enroll", body).await;
    assert_eq!(status(&r), "error", "nonce reuse must fail: {r}");
}

// ================================================================ DIS-SEC-004

/// Registration requires the registration key; missing or wrong key → 401/403.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_01_vendor_register_requires_registration_key() {
    let _g = SERIAL.lock().await;
    let mock = OriginMock::start().await;
    let admin = admin_url();
    let mut conn = PgConnection::connect(&admin).await.unwrap();
    let db_name = format!("dis003_{}", rand_hex(6));
    sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&mut conn).await.unwrap();
    let base = admin.rsplit_once('/').unwrap().0.to_string();
    let direct = format!("{base}/{db_name}");
    let db = PgPoolOptions::new().max_connections(2).connect(&direct).await.unwrap();
    let via = format!("{}@127.0.0.1:5432/{db_name}", base.rsplit_once('@').unwrap().0);
    let s = Server::start(&via).await;

    let vendor = format!("vendor{}", rand_hex(4));
    let reg_token = rand_hex(32);
    mock.register(&vendor, &reg_token);
    let body = json!({"vendor_id":vendor,"rp_origin":mock.origin(),
        "allowed_resources":["doc:1"],"allowed_actions":["read"],
        "api_key":"k","registration_token":reg_token});

    // No token → 403 (endpoint disabled message) or 401
    let r = http().post(format!("{}/vendor/register", s.base)).json(&body).send().await.unwrap();
    assert!(r.status().as_u16() >= 401, "no token: {}", r.status());
    // Wrong token → 401
    let r = http().post(format!("{}/vendor/register", s.base)).json(&body)
        .bearer_auth("wrong-token-0123456789abcdef0123456789").send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    // Truncated token → 401
    let r = http().post(format!("{}/vendor/register", s.base)).json(&body)
        .bearer_auth(&REGISTRATION_KEY[..REGISTRATION_KEY.len()-1]).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 401);
    // Vendor must not have been created.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors").fetch_one(&db).await.unwrap();
    assert_eq!(count, 0);
    // Correct key succeeds.
    let (code, r) = s.post_with_reg_key("/vendor/register", body).await;
    assert_eq!(code, 200);
    assert_eq!(status(&r), "registered", "{r}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors").fetch_one(&db).await.unwrap();
    assert_eq!(count, 1);
}

/// Origin ownership verification: the server fetches the well-known token.
/// A missing, wrong, or tampered token causes the registration to fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_02_origin_ownership_verified_before_registration() {
    let _g = SERIAL.lock().await;
    let mock = OriginMock::start().await;
    let admin = admin_url();
    let mut conn = PgConnection::connect(&admin).await.unwrap();
    let db_name = format!("dis003_{}", rand_hex(6));
    sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&mut conn).await.unwrap();
    let base = admin.rsplit_once('/').unwrap().0.to_string();
    let direct = format!("{base}/{db_name}");
    let db = PgPoolOptions::new().max_connections(2).connect(&direct).await.unwrap();
    let via = format!("{}@127.0.0.1:5432/{db_name}", base.rsplit_once('@').unwrap().0);
    let s = Server::start(&via).await;

    let vendor = format!("vendor{}", rand_hex(4));
    let reg_token = rand_hex(32);

    // (a) well-known endpoint serves nothing (mock not yet primed) → rejected
    let body = json!({"vendor_id":vendor,"rp_origin":mock.origin(),
        "allowed_resources":["doc:1"],"allowed_actions":["read"],
        "api_key":"k","registration_token":reg_token});
    let (code, r) = s.post_with_reg_key("/vendor/register", body.clone()).await;
    assert_eq!(code, 403, "unprimed mock: {r}");
    assert!(message(&r).contains("origin ownership"), "{r}");

    // (b) well-known endpoint serves the wrong token (for a different vendor) → rejected
    // set_token for "other-vendor" publishes SHA-256("other-vendor:…"), which will
    // not match the server's expected SHA-256("{vendor}:{reg_token}").
    mock.set_token("other-vendor", &rand_hex(32));
    let (code, r) = s.post_with_reg_key("/vendor/register", body.clone()).await;
    assert_eq!(code, 403, "wrong token: {r}");

    // (c) well-known endpoint serves the right token → accepted
    mock.register(&vendor, &reg_token);
    let (code, r) = s.post_with_reg_key("/vendor/register", body.clone()).await;
    assert_eq!(code, 200);
    assert_eq!(status(&r), "registered", "{r}");
    let verified: Option<i64> = sqlx::query_scalar("SELECT origin_verified_at FROM vendors WHERE vendor_id=$1")
        .bind(&vendor).fetch_one(&db).await.unwrap();
    assert!(verified.is_some(), "origin_verified_at must be set");

    // (d) replay of the same vendor_id → rejected (already registered)
    let (_, r) = s.post_with_reg_key("/vendor/register", body).await;
    assert_eq!(status(&r), "error");
    assert!(message(&r).contains("already"), "{r}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors").fetch_one(&db).await.unwrap();
    assert_eq!(count, 1);
}

/// A vendor_id registered by one vendor cannot be claimed by a different rp_origin.
/// Tests both squatting (taking an existing ID) and cross-origin confusion.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_03_vendor_identity_takeover_prevented() {
    let _g = SERIAL.lock().await;
    // Two origin mocks = two independent vendors trying to claim the same vendor_id.
    let mock_a = OriginMock::start().await;
    let mock_b = OriginMock::start().await;
    let admin = admin_url();
    let mut conn = PgConnection::connect(&admin).await.unwrap();
    let db_name = format!("dis003_{}", rand_hex(6));
    sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&mut conn).await.unwrap();
    let base = admin.rsplit_once('/').unwrap().0.to_string();
    let direct = format!("{base}/{db_name}");
    let db = PgPoolOptions::new().max_connections(2).connect(&direct).await.unwrap();
    let via = format!("{}@127.0.0.1:5432/{db_name}", base.rsplit_once('@').unwrap().0);
    let s = Server::start(&via).await;

    let vendor_id = format!("vendor{}", rand_hex(4));

    // Legitimate owner registers vendor_id at mock_a.
    let reg_token_a = rand_hex(32);
    mock_a.register(&vendor_id, &reg_token_a);
    let (code, r) = s.post_with_reg_key("/vendor/register", json!({
        "vendor_id":vendor_id,"rp_origin":mock_a.origin(),
        "allowed_resources":["doc:1"],"allowed_actions":["read"],
        "api_key":"k","registration_token":reg_token_a})).await;
    assert_eq!(code, 200); assert_eq!(status(&r), "registered");

    // Attacker at mock_b tries to claim the same vendor_id → rejected (already exists).
    let reg_token_b = rand_hex(32);
    mock_b.register(&vendor_id, &reg_token_b);
    let (code, r) = s.post_with_reg_key("/vendor/register", json!({
        "vendor_id":vendor_id,"rp_origin":mock_b.origin(),
        "allowed_resources":["doc:1"],"allowed_actions":["read"],
        "api_key":"k","registration_token":reg_token_b})).await;
    assert!(message(&r).contains("already"), "squatting attempt should fail: {r}");

    // The stored rp_origin is still mock_a's.
    let stored_origin: String = sqlx::query_scalar("SELECT rp_origin FROM vendors WHERE vendor_id=$1")
        .bind(&vendor_id).fetch_one(&db).await.unwrap();
    assert_eq!(stored_origin, mock_a.origin());

    // Attacker at mock_a tries to register their own vendor_id using mock_a
    // but presents the registration_token meant for vendor_id → token mismatch.
    let attacker_id = format!("vendor{}", rand_hex(4));
    // mock_a still serves the token for vendor_id, not attacker_id.
    let (code, r) = s.post_with_reg_key("/vendor/register", json!({
        "vendor_id":attacker_id,"rp_origin":mock_a.origin(),
        "allowed_resources":["doc:1"],"allowed_actions":["read"],
        "api_key":"k","registration_token":reg_token_a})).await;
    assert_eq!(code, 403, "cross-token confusion should fail: {r}");
    assert!(message(&r).contains("origin ownership"), "{r}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors").fetch_one(&db).await.unwrap();
    assert_eq!(count, 1, "only the legitimate vendor should be registered");
}

/// An unreachable rp_origin is rejected, not silently accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_04_unreachable_origin_rejected() {
    let _g = SERIAL.lock().await;
    let admin = admin_url();
    let mut conn = PgConnection::connect(&admin).await.unwrap();
    let db_name = format!("dis003_{}", rand_hex(6));
    sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&mut conn).await.unwrap();
    let base = admin.rsplit_once('/').unwrap().0.to_string();
    let direct = format!("{base}/{db_name}");
    let db = PgPoolOptions::new().max_connections(2).connect(&direct).await.unwrap();
    let via = format!("{}@127.0.0.1:5432/{db_name}", base.rsplit_once('@').unwrap().0);
    let s = Server::start(&via).await;

    let vendor = format!("vendor{}", rand_hex(4));
    let reg_token = rand_hex(32);
    // A port that has no listener → connection refused → rejected.
    let dead_origin = format!("http://127.0.0.1:{}", free_port());
    let (code, r) = s.post_with_reg_key("/vendor/register", json!({
        "vendor_id":vendor,"rp_origin":dead_origin,
        "allowed_resources":["doc:1"],"allowed_actions":["read"],
        "api_key":"k","registration_token":reg_token})).await;
    assert_eq!(code, 403, "{r}");
    assert!(message(&r).contains("origin ownership"), "{r}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors").fetch_one(&db).await.unwrap();
    assert_eq!(count, 0, "dead origin must not create a vendor row");
}

/// A vendor registered without origin verification (direct DB insert, simulating
/// a migration from an older schema) cannot issue challenges.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_05_unverified_vendor_cannot_issue_challenges() {
    let _g = SERIAL.lock().await;
    let c = Cluster::start().await;
    let w = Wallet::enroll(&c.a).await;
    // Inject a vendor row without origin_verified_at (simulates old-schema row).
    let bad_vendor = format!("badvendor{}", rand_hex(4));
    sqlx::query("INSERT INTO vendors (vendor_id,rp_origin,allowed_resources,allowed_actions,api_key_hash) VALUES ($1,$2,$3,$4,$5)")
        .bind(&bad_vendor).bind("https://bad.example")
        .bind(r#"["doc:1"]"#).bind(r#"["read"]"#).bind("hash")
        .execute(&c.db).await.unwrap();
    let (_, r) = c.a.post("/challenge", json!({"wallet_id":w.id,"vendor_id":bad_vendor,
        "resource_id":"doc:1","action":"read"})).await;
    assert_eq!(status(&r), "error");
    assert!(message(&r).contains("origin not verified"), "{r}");
    let (_, r) = c.b.post("/challenge", json!({"wallet_id":w.id,"vendor_id":bad_vendor,
        "resource_id":"doc:1","action":"read"})).await;
    assert_eq!(status(&r), "error");
    assert!(message(&r).contains("origin not verified"), "{r}");
}

// ================================================================ DIS-SEC-005 SSRF tests

/// In production mode (no DIS_ALLOW_HTTP_ORIGINS), rp_origin values that resolve
/// to internal/private/loopback IPs or that use the HTTP scheme are rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_06_ssrf_internal_addresses_rejected_in_prod_mode() {
    let _g = SERIAL.lock().await;
    let admin = admin_url();
    let mut conn = PgConnection::connect(&admin).await.unwrap();
    let db_name = format!("dis003_{}", rand_hex(6));
    sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&mut conn).await.unwrap();
    let base = admin.rsplit_once('/').unwrap().0.to_string();
    let direct = format!("{base}/{db_name}");
    let db = PgPoolOptions::new().max_connections(2).connect(&direct).await.unwrap();
    let via = format!("{}@127.0.0.1:5432/{db_name}", base.rsplit_once('@').unwrap().0);
    // Start server WITHOUT DIS_ALLOW_HTTP_ORIGINS → production SSRF checks active.
    let s = Server::start_prod_mode(&via).await;
    let vendor = format!("vendor{}", rand_hex(4));
    let reg_token = rand_hex(32);

    let bad_origins: &[&str] = &[
        // HTTP scheme (not HTTPS) — rejected by scheme check.
        "http://127.0.0.1:8080",
        // Loopback IPv4 literal.
        "https://127.0.0.1",
        // Loopback IPv6 literal.
        "https://[::1]",
        // Private RFC1918 ranges.
        "https://10.0.0.1",
        "https://172.16.0.1",
        "https://192.168.1.1",
        // Link-local.
        "https://169.254.169.254",
        // CGNAT.
        "https://100.64.0.1",
        // Unspecified.
        "https://0.0.0.0",
        // localhost resolves to 127.0.0.1 — rejected by DNS check.
        "https://localhost",
    ];

    for origin in bad_origins {
        let (code, r) = s.post_with_reg_key("/vendor/register", json!({
            "vendor_id": vendor,
            "rp_origin": origin,
            "allowed_resources": ["doc:1"],
            "allowed_actions": ["read"],
            "api_key": "k",
            "registration_token": reg_token
        })).await;
        assert!(
            code == 403 || code == 400,
            "expected 403/400 for SSRF origin {origin}: got {code} — {r}"
        );
        let msg = message(&r);
        assert!(
            msg.contains("origin ownership") || msg.contains("HTTPS") || msg.contains("non-public")
                || msg.contains("valid URL") || msg.contains("credentials") || msg.contains("path"),
            "unexpected error message for {origin}: {msg}"
        );
    }

    // No vendor row should have been created.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors").fetch_one(&db).await.unwrap();
    assert_eq!(count, 0, "no vendor row must be created via internal-IP origins");
}

/// Redirects from the well-known endpoint are not followed.
/// An origin mock that returns a 302 redirect to a different (possibly internal)
/// URL must not allow registration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_07_redirect_from_well_known_blocked() {
    let _g = SERIAL.lock().await;
    let admin = admin_url();
    let mut conn = PgConnection::connect(&admin).await.unwrap();
    let db_name = format!("dis003_{}", rand_hex(6));
    sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&mut conn).await.unwrap();
    let base = admin.rsplit_once('/').unwrap().0.to_string();
    let direct = format!("{base}/{db_name}");
    let db = PgPoolOptions::new().max_connections(2).connect(&direct).await.unwrap();
    let via = format!("{}@127.0.0.1:5432/{db_name}", base.rsplit_once('@').unwrap().0);

    // Build a redirect mock: always responds with 302 to the real token location.
    let token_store: Arc<Mutex<Option<String>>> = Arc::default();
    let token_clone = token_store.clone();
    let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_port = redirect_listener.local_addr().unwrap().port();
    // A second listener that serves the actual token.
    let token_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_port = token_listener.local_addr().unwrap().port();
    let token_clone2 = token_store.clone();
    use axum::{routing::get as aGet, Router as ARouter};

    let token_app = ARouter::new()
        .route("/.well-known/dis-vendor-registration", aGet(move || {
            let t = token_clone2.clone();
            async move {
                match t.lock().unwrap().clone() {
                    Some(s) => (axum::http::StatusCode::OK, s),
                    None => (axum::http::StatusCode::NOT_FOUND, String::new()),
                }
            }
        }));
    let token_base = format!("http://127.0.0.1:{token_port}");
    tokio::spawn(async move { axum::serve(token_listener, token_app).await.ok(); });

    let token_base_c = token_base.clone();
    let redirect_app = ARouter::new()
        .route("/.well-known/dis-vendor-registration", aGet(move || {
            let dest = format!("{token_base_c}/.well-known/dis-vendor-registration");
            let _ = token_clone.clone(); // keep alive
            async move {
                (
                    axum::http::StatusCode::FOUND,
                    [(axum::http::header::LOCATION, dest)],
                    "",
                )
            }
        }));
    tokio::spawn(async move { axum::serve(redirect_listener, redirect_app).await.ok(); });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Start in test mode so HTTP origins pass the scheme check (we're testing redirect blocking).
    let s = Server::start(&via).await;
    let vendor = format!("vendor{}", rand_hex(4));
    let reg_token = rand_hex(32);
    let expected = sha256_hex_test(format!("{vendor}:{reg_token}").as_bytes());
    *token_store.lock().unwrap() = Some(expected);

    // The registration origin points at the redirect mock, not the token server.
    let redirect_origin = format!("http://127.0.0.1:{redirect_port}");
    let (code, r) = s.post_with_reg_key("/vendor/register", json!({
        "vendor_id": vendor,
        "rp_origin": redirect_origin,
        "allowed_resources": ["doc:1"],
        "allowed_actions": ["read"],
        "api_key": "k",
        "registration_token": reg_token
    })).await;
    // Redirect not followed → the redirect response body is empty/302 text,
    // not the ownership token → rejected.
    assert_eq!(code, 403, "redirect should not be followed: {r}");
    assert!(message(&r).contains("origin ownership"), "{r}");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors").fetch_one(&db).await.unwrap();
    assert_eq!(count, 0, "redirect must not allow registration");
}

/// Malformed rp_origin values (bad scheme, credentials, path, query, fragment)
/// are rejected by URL validation before any network request is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_08_malformed_origin_url_rejected() {
    let _g = SERIAL.lock().await;
    let admin = admin_url();
    let mut conn = PgConnection::connect(&admin).await.unwrap();
    let db_name = format!("dis003_{}", rand_hex(6));
    sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&mut conn).await.unwrap();
    let base = admin.rsplit_once('/').unwrap().0.to_string();
    let direct = format!("{base}/{db_name}");
    let db = PgPoolOptions::new().max_connections(2).connect(&direct).await.unwrap();
    let via = format!("{}@127.0.0.1:5432/{db_name}", base.rsplit_once('@').unwrap().0);
    // Production mode: enforces HTTPS.
    let s = Server::start_prod_mode(&via).await;
    let vendor = format!("vendor{}", rand_hex(4));
    let reg_token = rand_hex(32);

    let bad_urls: &[(&str, &str)] = &[
        // Not a URL at all.
        ("not-a-url", "valid URL"),
        // FTP scheme.
        ("ftp://example.com", "scheme"),
        // Embedded credentials.
        ("https://user:pass@example.com", "credentials"),
        // Path component.
        ("https://example.com/path", "path"),
        // Query component.
        ("https://example.com?q=1", "query"),
        // Fragment.
        ("https://example.com#frag", "fragment"),
        // Empty host — url crate rejects it as unparseable.
        ("https://", "valid URL"),
        // HTTP without allow flag.
        ("http://example.com", "HTTPS"),
    ];

    for (origin, expected_substr) in bad_urls {
        let (code, r) = s.post_with_reg_key("/vendor/register", json!({
            "vendor_id": vendor,
            "rp_origin": origin,
            "allowed_resources": ["doc:1"],
            "allowed_actions": ["read"],
            "api_key": "k",
            "registration_token": reg_token
        })).await;
        assert!(
            code == 403 || code == 400,
            "expected 403/400 for {origin}: got {code} — {r}"
        );
        let msg = message(&r);
        assert!(
            msg.contains(expected_substr),
            "for origin {origin}: expected message containing {expected_substr:?}, got: {msg}"
        );
    }

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors").fetch_one(&db).await.unwrap();
    assert_eq!(count, 0, "no vendor row must be created for malformed origins");
}

/// Verifies that the `resolve_to_addrs` pinning mechanism works as expected:
/// a reqwest client with pinned addresses connects to the target even when the
/// URL hostname does not exist in the OS DNS resolver, while an unpinned client
/// fails for the same hostname.
///
/// # What this test does and does not prove
///
/// **What it proves**: reqwest's `resolve_to_addrs` overrides OS DNS lookup
/// entirely for the pinned hostname.  The production code in
/// `verify_origin_ownership` uses the same mechanism: after `validate_origin_ips`
/// returns validated `Vec<SocketAddr>`, the per-request client is built with
/// `resolve_to_addrs(hostname, &validated_addrs)`.  Consequently the actual HTTP
/// connection goes to one of the pre-checked IPs, not to whatever the OS resolver
/// would return at the time of the connection attempt.
///
/// **What it does not prove**: it does not simulate an adversary operating a
/// real DNS server that changes its A-record answers between two live queries.
/// That scenario requires external DNS infrastructure and is out of scope for
/// an in-process integration test.  The invariant this test exercises — that
/// `resolve_to_addrs` routes the request without consulting the OS resolver —
/// is the property that closes the rebinding window in production.
///
/// The companion unit test `ssrf_tests::pinned_client_uses_pre_validated_address`
/// in `src/main.rs` exercises the same property at the library level.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_09_pinned_client_bypasses_os_dns_resolver() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use axum::{routing::get as aGet, Router as ARouter};

    // Start a mock that returns a known ownership token body.
    const TOKEN_BODY: &str = "rebind-test-token-placeholder";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mock_handle = tokio::spawn(async move {
        let app = ARouter::new().route(
            "/.well-known/dis-vendor-registration",
            aGet(|| async { TOKEN_BODY }),
        );
        axum::serve(listener, app).await.ok();
    });

    let mock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    // ── Case 1: pinned client reaches the mock via a .invalid hostname ────────
    //
    // The .invalid TLD is IANA-reserved and never delegates; "fake-dis-pin.invalid"
    // cannot appear in any real DNS tree.  Building a client with resolve_to_addrs
    // pinned to mock_addr routes the request directly to the mock, bypassing the
    // OS resolver entirely.  This is exactly what verify_origin_ownership does in
    // production after validate_origin_ips returns validated addresses.
    let pinned = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs("fake-dis-pin.invalid", &[mock_addr])
        .build()
        .expect("build pinned client");

    let well_known = format!("http://fake-dis-pin.invalid:{port}/.well-known/dis-vendor-registration");
    let resp = pinned.get(&well_known).send().await
        .expect("pinned client must route to the mock server");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.text().await.unwrap().trim(), TOKEN_BODY);

    // ── Case 2: unpinned client fails for the same .invalid hostname ──────────
    //
    // Without resolve_to_addrs, reqwest falls back to the OS DNS resolver, which
    // returns NXDOMAIN for .invalid → connection error.  This confirms the pinned
    // path above is genuinely bypassing the OS resolver, not accidentally succeeding
    // because .invalid happens to resolve on this machine.
    let unpinned = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build unpinned client");
    assert!(
        unpinned.get(&well_known).send().await.is_err(),
        "unpinned client must fail to resolve fake-dis-pin.invalid"
    );

    mock_handle.abort();
}
