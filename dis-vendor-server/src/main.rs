use axum::{
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use axum_extra::{
    headers::{Authorization, authorization::Bearer},
    TypedHeader,
};
use dis_core::{
    verifier::{HolderProof, RelyingParty, RpPolicy},
    canonical_request, Request, SUITE_ML_DSA_65,
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tower_http::cors::{AllowOrigin, CorsLayer};

const SESSIONS_API_KEY: &str = "dis-sessions-key-change-in-production";

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    rps: Arc<Mutex<HashMap<String, RelyingParty>>>,
}

#[derive(Deserialize)]
struct RegisterVendorRequest {
    vendor_id: String, rp_origin: String,
    allowed_resources: Vec<String>, allowed_actions: Vec<String>, api_key: String,
}
#[derive(Deserialize)]
struct EnrollChallengeRequest { wallet_id: String }
#[derive(Deserialize)]
struct EnrollRequest { wallet_id: String, public_key_hex: String, nonce_signature_hex: String }
#[derive(Deserialize)]
struct ChallengeRequest { wallet_id: String, vendor_id: String, resource_id: String, action: String }
#[derive(Serialize, Deserialize, Clone)]
struct ChallengeResponse {
    challenge_id: Vec<u8>, nonce: Vec<u8>, issued_at: u64, expires_at: u64,
    resource_id: String, action: String, scopes: Vec<String>, policy_id: String,
    rp_id: String, rp_origin: String, suite_id: u16,
}
#[derive(Deserialize)]
struct VerifyRequest {
    wallet_id: String, vendor_id: String, challenge: ChallengeResponse,
    public_key_hex: String, signature_hex: String,
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).ok()).collect()
}
fn hex_encode(b: &[u8]) -> String { b.iter().map(|b| format!("{:02x}", b)).collect() }
fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}
fn sha256_hex(s: &str) -> String { hex_encode(&Sha256::digest(s.as_bytes())) }
fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n]; getrandom::getrandom(&mut b).unwrap(); hex_encode(&b)
}

fn make_rp(vendor_id: &str, rp_origin: &str, resources: &[String], actions: &[String]) -> RelyingParty {
    let mut grants = HashSet::new();
    for res in resources { for act in actions {
        let scope = match act.as_str() {
            "read" => "document:read", "write" => "document:write",
            "submit" => "payment:submit", _ => "document:read",
        };
        grants.insert((res.clone(), act.clone(), scope.to_string()));
    }}
    RelyingParty::new(RpPolicy { rp_id: vendor_id.into(), rp_origin: rp_origin.into(), policy_id: "v1".into(), grants })
}

fn init_db(conn: &Connection) {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS vendors (
            vendor_id TEXT PRIMARY KEY, rp_origin TEXT NOT NULL,
            allowed_resources TEXT NOT NULL, allowed_actions TEXT NOT NULL, api_key_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS enrolled_keys (
            wallet_id TEXT PRIMARY KEY, public_key_hex TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS enroll_nonces (
            wallet_id TEXT PRIMARY KEY, nonce TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS consumed_challenges (
            challenge_id_hex TEXT PRIMARY KEY, consumed_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS verified_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wallet_id TEXT NOT NULL, vendor_id TEXT NOT NULL,
            resource_id TEXT NOT NULL, action TEXT NOT NULL, verified_at TEXT NOT NULL
        );
    ").unwrap();
}

fn rebuild_rps(conn: &Connection) -> HashMap<String, RelyingParty> {
    let mut rps = HashMap::new();
    let mut stmt = conn.prepare(
        "SELECT vendor_id, rp_origin, allowed_resources, allowed_actions FROM vendors"
    ).unwrap();
    let vendors: Vec<(String,String,String,String)> = stmt.query_map([], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    }).unwrap().filter_map(|r| r.ok()).collect();

    let mut kstmt = conn.prepare("SELECT public_key_hex FROM enrolled_keys").unwrap();
    let keys: Vec<String> = kstmt.query_map([], |r| r.get(0))
        .unwrap().filter_map(|r| r.ok()).collect();

    for (vid, origin, res_json, act_json) in &vendors {
        let resources: Vec<String> = serde_json::from_str(res_json).unwrap_or_default();
        let actions: Vec<String> = serde_json::from_str(act_json).unwrap_or_default();
        let mut rp = make_rp(vid, origin, &resources, &actions);
        for pk_hex in &keys {
            if let Some(pk_bytes) = hex_decode(pk_hex) { let _ = rp.enroll_test_key(&pk_bytes); }
        }
        rps.insert(vid.clone(), rp);
    }
    rps
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok","server":"DIS Vendor Server","version":"0.3.0","security":"DIS-STATE-001","persistence":"SQLite"}))
}

async fn reset(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.db.lock().unwrap();
    db.execute_batch("DELETE FROM vendors; DELETE FROM enrolled_keys; DELETE FROM enroll_nonces; DELETE FROM consumed_challenges; DELETE FROM verified_sessions;").unwrap();
    *state.rps.lock().unwrap() = HashMap::new();
    Json(serde_json::json!({"status":"reset","message":"Server state cleared"}))
}

async fn register_vendor(State(state): State<AppState>, Json(req): Json<RegisterVendorRequest>) -> Json<serde_json::Value> {
    if req.vendor_id.is_empty() || req.rp_origin.is_empty() || req.api_key.is_empty() {
        return Json(serde_json::json!({"status":"error","message":"missing required fields"}));
    }
    let db = state.db.lock().unwrap();
    let exists: bool = db.query_row("SELECT 1 FROM vendors WHERE vendor_id=?1", params![req.vendor_id], |_| Ok(true)).unwrap_or(false);
    if exists { return Json(serde_json::json!({"status":"error","message":"vendor already registered"})); }
    let res_json = serde_json::to_string(&req.allowed_resources).unwrap();
    let act_json = serde_json::to_string(&req.allowed_actions).unwrap();
    db.execute("INSERT INTO vendors (vendor_id,rp_origin,allowed_resources,allowed_actions,api_key_hash) VALUES (?1,?2,?3,?4,?5)",
        params![req.vendor_id, req.rp_origin, res_json, act_json, sha256_hex(&req.api_key)]).unwrap();

    let keys: Vec<String> = {
        let mut s = db.prepare("SELECT public_key_hex FROM enrolled_keys").unwrap();
        s.query_map([], |r| r.get(0)).unwrap().filter_map(|r| r.ok()).collect()
    };
    drop(db);

    let mut rp = make_rp(&req.vendor_id, &req.rp_origin, &req.allowed_resources, &req.allowed_actions);
    for pk_hex in &keys {
        if let Some(pk_bytes) = hex_decode(pk_hex) { let _ = rp.enroll_test_key(&pk_bytes); }
    }
    state.rps.lock().unwrap().insert(req.vendor_id.clone(), rp);
    Json(serde_json::json!({"status":"registered","vendor_id":req.vendor_id,"rp_origin":req.rp_origin,"message":"Vendor registered and persisted."}))
}

async fn enroll_challenge(State(state): State<AppState>, Json(req): Json<EnrollChallengeRequest>) -> Json<serde_json::Value> {
    let nonce = random_hex(32);
    state.db.lock().unwrap().execute("INSERT OR REPLACE INTO enroll_nonces (wallet_id,nonce) VALUES (?1,?2)", params![req.wallet_id, nonce.clone()]).unwrap();
    Json(serde_json::json!({"status":"ok","wallet_id":req.wallet_id,"nonce":nonce}))
}

async fn enroll(State(state): State<AppState>, Json(req): Json<EnrollRequest>) -> Json<serde_json::Value> {
    let pk_bytes = match hex_decode(&req.public_key_hex) { Some(b) => b, None => return Json(serde_json::json!({"status":"error","message":"invalid public key hex"})) };
    let sig_bytes = match hex_decode(&req.nonce_signature_hex) { Some(b) => b, None => return Json(serde_json::json!({"status":"error","message":"invalid signature hex"})) };
    let db = state.db.lock().unwrap();
    let nonce: Option<String> = db.query_row("SELECT nonce FROM enroll_nonces WHERE wallet_id=?1", params![req.wallet_id], |r| r.get(0)).ok();
    let nonce = match nonce { Some(n) => n, None => return Json(serde_json::json!({"status":"error","message":"no enroll challenge found — call /enroll/challenge first"})) };
    let pk = match dilithium3::PublicKey::from_bytes(&pk_bytes) { Ok(k) => k, Err(_) => return Json(serde_json::json!({"status":"error","message":"invalid public key"})) };
    let sig = match dilithium3::DetachedSignature::from_bytes(&sig_bytes) { Ok(s) => s, Err(_) => return Json(serde_json::json!({"status":"error","message":"invalid signature"})) };
    if dilithium3::verify_detached_signature(&sig, nonce.as_bytes(), &pk).is_err() {
        return Json(serde_json::json!({"status":"error","message":"key ownership proof failed"}));
    }
    let exists: bool = db.query_row("SELECT 1 FROM enrolled_keys WHERE wallet_id=?1", params![req.wallet_id], |_| Ok(true)).unwrap_or(false);
    if exists { return Json(serde_json::json!({"status":"error","message":"wallet already enrolled — key replacement not permitted"})); }
    db.execute("DELETE FROM enroll_nonces WHERE wallet_id=?1", params![req.wallet_id]).unwrap();
    db.execute("INSERT INTO enrolled_keys (wallet_id,public_key_hex) VALUES (?1,?2)", params![req.wallet_id, req.public_key_hex]).unwrap();
    drop(db);
    for rp in state.rps.lock().unwrap().values_mut() { let _ = rp.enroll_test_key(&pk_bytes); }
    Json(serde_json::json!({"status":"enrolled","wallet_id":req.wallet_id,"message":"Key ownership verified. Wallet enrolled and persisted."}))
}

async fn challenge(State(state): State<AppState>, Json(req): Json<ChallengeRequest>) -> Json<serde_json::Value> {
    let db = state.db.lock().unwrap();
    let enrolled: bool = db.query_row("SELECT 1 FROM enrolled_keys WHERE wallet_id=?1", params![req.wallet_id], |_| Ok(true)).unwrap_or(false);
    if !enrolled { return Json(serde_json::json!({"status":"error","message":"wallet not enrolled"})); }
    let vendor: Option<(String,String,String)> = db.query_row(
        "SELECT rp_origin,allowed_resources,allowed_actions FROM vendors WHERE vendor_id=?1",
        params![req.vendor_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok();
    let (rp_origin, res_json, act_json) = match vendor { Some(v) => v, None => return Json(serde_json::json!({"status":"error","message":"vendor not registered"})) };
    drop(db);
    let resources: Vec<String> = serde_json::from_str(&res_json).unwrap_or_default();
    let actions: Vec<String> = serde_json::from_str(&act_json).unwrap_or_default();
    if !resources.iter().any(|r| r == &req.resource_id || r == "*") {
        return Json(serde_json::json!({"status":"error","message":"resource not authorized for this vendor"}));
    }
    if !actions.contains(&req.action) { return Json(serde_json::json!({"status":"error","message":"action not authorized for this vendor"})); }
    let now = now_secs();
    let scope = match req.action.as_str() { "read"=>"document:read","write"=>"document:write","submit"=>"payment:submit",_=>"document:read" };
    let template = Request { suite_id: SUITE_ML_DSA_65, rp_id: req.vendor_id.clone(), rp_origin: rp_origin.clone(),
        challenge_id: [0;16], nonce: [0;16], issued_at: now, expires_at: now+299,
        resource_id: req.resource_id.clone(), action: req.action.clone(),
        scopes: vec![scope.into()], operation_digest: None, policy_id: "v1".into() };
    let mut rps = state.rps.lock().unwrap();
    let rp = match rps.get_mut(&req.vendor_id) { Some(r) => r, None => return Json(serde_json::json!({"status":"error","message":"vendor RP not initialized"})) };
    match rp.issue(template) {
        Ok(issued) => Json(serde_json::json!({"status":"ok","challenge":{"challenge_id":issued.challenge_id.to_vec(),"nonce":issued.nonce.to_vec(),"issued_at":issued.issued_at,"expires_at":issued.expires_at,"resource_id":issued.resource_id,"action":issued.action,"scopes":issued.scopes,"policy_id":issued.policy_id,"rp_id":issued.rp_id,"rp_origin":issued.rp_origin,"suite_id":issued.suite_id}})),
        Err(e) => Json(serde_json::json!({"status":"error","message":format!("{:?}",e)})),
    }
}

async fn verify(State(state): State<AppState>, Json(req): Json<VerifyRequest>) -> Json<serde_json::Value> {
    let pk_bytes = match hex_decode(&req.public_key_hex) { Some(b) => b, None => return Json(serde_json::json!({"status":"error","message":"invalid public key hex"})) };
    let sig_bytes = match hex_decode(&req.signature_hex) { Some(b) => b, None => return Json(serde_json::json!({"status":"error","message":"invalid signature hex"})) };
    let db = state.db.lock().unwrap();
    let stored_pk: Option<String> = db.query_row("SELECT public_key_hex FROM enrolled_keys WHERE wallet_id=?1", params![req.wallet_id], |r| r.get(0)).ok();
    match &stored_pk {
        None => return Json(serde_json::json!({"status":"error","message":"wallet not enrolled"})),
        Some(pk) if *pk != req.public_key_hex => return Json(serde_json::json!({"status":"error","message":"public key does not match enrolled key"})),
        _ => {}
    }
    let c = &req.challenge;
    let mut challenge_id = [0u8;16]; let mut nonce = [0u8;16];
    for (i,b) in c.challenge_id.iter().take(16).enumerate() { challenge_id[i] = *b as u8; }
    for (i,b) in c.nonce.iter().take(16).enumerate() { nonce[i] = *b as u8; }
    let cid_hex = hex_encode(&challenge_id);
    // Atomic replay prevention
    let inserted = db.execute("INSERT OR IGNORE INTO consumed_challenges (challenge_id_hex,consumed_at) VALUES (?1,?2)", params![cid_hex, now_secs() as i64]).unwrap();
    if inserted == 0 { return Json(serde_json::json!({"status":"rejected","message":"Replay"})); }
    drop(db);
    let request = Request { suite_id: c.suite_id, rp_id: c.rp_id.clone(), rp_origin: c.rp_origin.clone(),
        challenge_id, nonce, issued_at: c.issued_at, expires_at: c.expires_at,
        resource_id: c.resource_id.clone(), action: c.action.clone(),
        scopes: c.scopes.clone(), operation_digest: None, policy_id: c.policy_id.clone() };
    let proof = HolderProof { public_key: pk_bytes, signature: sig_bytes };
    let now = now_secs();
    let mut rps = state.rps.lock().unwrap();
    let rp = match rps.get_mut(&req.vendor_id) { Some(r) => r, None => return Json(serde_json::json!({"status":"error","message":"vendor not registered"})) };
    match rp.verify(&request, &proof, now) {
        Ok(_) => {
            drop(rps);
            state.db.lock().unwrap().execute(
                "INSERT INTO verified_sessions (wallet_id,vendor_id,resource_id,action,verified_at) VALUES (?1,?2,?3,?4,?5)",
                params![req.wallet_id, req.vendor_id, c.resource_id, c.action, chrono::Utc::now().to_rfc3339()]).unwrap();
            Json(serde_json::json!({"status":"verified","message":"DIS proof accepted — access granted","wallet_id":req.wallet_id,"vendor_id":req.vendor_id,"resource_id":c.resource_id,"action":c.action}))
        }
        Err(e) => Json(serde_json::json!({"status":"rejected","message":format!("{:?}",e)})),
    }
}

async fn sessions(State(state): State<AppState>, auth: Option<TypedHeader<Authorization<Bearer>>>) -> (StatusCode, Json<serde_json::Value>) {
    match auth {
        Some(TypedHeader(Authorization(bearer))) if bearer.token() == SESSIONS_API_KEY => {
            let db = state.db.lock().unwrap();
            let mut s = db.prepare("SELECT wallet_id,vendor_id,resource_id,action,verified_at FROM verified_sessions ORDER BY id DESC LIMIT 100").unwrap();
            let sessions: Vec<serde_json::Value> = s.query_map([], |r| Ok(serde_json::json!({"wallet_id":r.get::<_,String>(0)?,"vendor_id":r.get::<_,String>(1)?,"resource_id":r.get::<_,String>(2)?,"action":r.get::<_,String>(3)?,"verified_at":r.get::<_,String>(4)?}))).unwrap().filter_map(|r| r.ok()).collect();
            let mut ew = db.prepare("SELECT wallet_id FROM enrolled_keys").unwrap();
            let wallets: Vec<String> = ew.query_map([], |r| r.get(0)).unwrap().filter_map(|r| r.ok()).collect();
            let mut vw = db.prepare("SELECT vendor_id FROM vendors").unwrap();
            let vendors: Vec<String> = vw.query_map([], |r| r.get(0)).unwrap().filter_map(|r| r.ok()).collect();
            (StatusCode::OK, Json(serde_json::json!({"verified_sessions":sessions,"count":sessions.len(),"enrolled_wallets":wallets,"registered_vendors":vendors})))
        }
        _ => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"status":"error","message":"Authorization: Bearer <api-key> required"}))),
    }
}

#[tokio::main]
async fn main() {
    let db_path = std::env::var("DIS_DB").unwrap_or("dis_state.db".into());
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;").unwrap();
    init_db(&conn);
    let rps = rebuild_rps(&conn);
    let rp_count = rps.len();
    let key_count: i64 = conn.query_row("SELECT COUNT(*) FROM enrolled_keys", [], |r| r.get(0)).unwrap_or(0);
    let state = AppState { db: Arc::new(Mutex::new(conn)), rps: Arc::new(Mutex::new(rps)) };
    let allowed_origins = std::env::var("ALLOWED_ORIGINS").unwrap_or_else(|_| "http://localhost:3000".into());
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin: &HeaderValue, _| {
            allowed_origins.split(',').any(|o| o.trim() == origin.to_str().unwrap_or(""))
        }))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any);
    let app: Router = Router::new()
        .route("/health", get(health))
        .route("/admin/reset", post(reset))
        .route("/vendor/register", post(register_vendor))
        .route("/enroll/challenge", post(enroll_challenge))
        .route("/enroll", post(enroll))
        .route("/challenge", post(challenge))
        .route("/verify", post(verify))
        .route("/sessions", get(sessions))
        .with_state(state)
        .layer(cors);
    let port = std::env::var("PORT").unwrap_or("3000".into());
    let addr = format!("0.0.0.0:{port}");
    println!("DIS Vendor Server v0.3.0 (DIS-STATE-001) on {addr}");
    println!("DB: {db_path} — {rp_count} vendor(s), {key_count} key(s) restored");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
