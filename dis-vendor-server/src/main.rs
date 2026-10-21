//! DIS vendor server — DIS-STATE-003.
//!
//! All security state (vendors, enrolled keys, issued/consumed challenges,
//! revocations, sessions) lives in one shared PostgreSQL database, so any
//! number of instances can serve the same vendors. Instances hold no
//! security state in memory.
//!
//! Verification order (see `verify_inner`):
//!   1. read-only pre-checks: enrolled key, revocation, issued challenge
//!   2. ML-DSA-65 signature over the server-stored transcript — before any write
//!   3. one transaction: lock key row (FOR SHARE) + challenge row (FOR UPDATE),
//!      re-check revocation, expiry and replay, consume, record session, commit
//! Any database error denies access (fail closed).
//!
//! Revocation/verification ordering rule: both lock the wallet's
//! `enrolled_keys` row (revoke: FOR UPDATE, verify: FOR SHARE), so they
//! serialize on it. A verification that commits before the revocation commits
//! is honoured; once a revocation has committed (i.e. before /admin/revoke
//! responds) no verification on any instance can commit.

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
use dis_core::{canonical_request, Request, SUITE_ML_DSA_65};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};

const SESSIONS_API_KEY: &str = "dis-sessions-key-change-in-production";
/// Server-enforced challenge lifetime. Must match the `challenge_ttl` CHECK
/// constraint in migrations/0001_dis_state_003.sql.
const CHALLENGE_TTL_SECS: i64 = 299;
/// Lifetime of an /enroll/challenge nonce.
const ENROLL_NONCE_TTL_SECS: i64 = 300;
const POLICY_ID: &str = "v1";
const DB_NOW: &str = "EXTRACT(EPOCH FROM clock_timestamp())::BIGINT";

#[derive(Clone)]
struct AppState {
    db: PgPool,
    /// SHA-256 of DIS_ADMIN_API_KEY; None disables the admin endpoints.
    admin_key_hash: Option<[u8; 32]>,
}

type Resp = (StatusCode, Json<Value>);
type BearerAuth = Option<TypedHeader<Authorization<Bearer>>>;

/// Admin endpoints require `Authorization: Bearer <DIS_ADMIN_API_KEY>`.
/// Digests are compared in constant time.
fn require_admin(state: &AppState, auth: &BearerAuth) -> Result<(), Resp> {
    let Some(expected) = state.admin_key_hash else {
        return Err((StatusCode::FORBIDDEN, Json(json!({"status":"error","message":"admin API disabled — set DIS_ADMIN_API_KEY"}))));
    };
    let presented: [u8; 32] = match auth {
        Some(TypedHeader(Authorization(bearer))) => Sha256::digest(bearer.token().as_bytes()).into(),
        None => [0u8; 32],
    };
    let diff = expected.iter().zip(presented.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if auth.is_none() || diff != 0 {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"status":"error","message":"Authorization: Bearer <admin-key> required"}))));
    }
    Ok(())
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
#[derive(Deserialize)]
struct RevokeRequest { wallet_id: String, reason: Option<String> }

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect()
}
fn hex_encode(b: &[u8]) -> String { b.iter().map(|b| format!("{:02x}", b)).collect() }
fn sha256_hex(b: &[u8]) -> String { hex_encode(&Sha256::digest(b)) }
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N]; getrandom::getrandom(&mut b).expect("CSPRNG unavailable"); b
}
fn challenge_key(vendor_id: &str, challenge_id_hex: &str) -> String {
    format!("dis:v1:challenge:{vendor_id}:{challenge_id_hex}")
}
fn scope_for(action: &str) -> &'static str {
    match action { "read" => "document:read", "write" => "document:write", "submit" => "payment:submit", _ => "document:read" }
}
fn vendor_permits(res_json: &str, act_json: &str, resource: &str, action: &str) -> bool {
    let resources: Vec<String> = serde_json::from_str(res_json).unwrap_or_default();
    let actions: Vec<String> = serde_json::from_str(act_json).unwrap_or_default();
    resources.iter().any(|r| r == resource || r == "*") && actions.iter().any(|a| a == action)
}

fn ok(v: Value) -> Resp { (StatusCode::OK, Json(v)) }
fn error(msg: &str) -> Resp { ok(json!({"status":"error","message":msg})) }
fn rejected(msg: &str) -> Resp { ok(json!({"status":"rejected","message":msg})) }

/// Fail closed: any state-store error becomes a denial, never a grant.
fn finish(r: Result<Resp, sqlx::Error>) -> Resp {
    r.unwrap_or_else(|e| {
        eprintln!("[dis] state store error, failing closed: {e}");
        (StatusCode::SERVICE_UNAVAILABLE,
         Json(json!({"status":"error","message":"state store unavailable — access denied (fail closed)"})))
    })
}

async fn health(State(state): State<AppState>) -> Resp {
    let db_up = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    let body = json!({"status": if db_up {"ok"} else {"degraded"}, "server":"DIS Vendor Server","version":"0.4.0",
        "security":"DIS-STATE-003","persistence":"PostgreSQL","db": if db_up {"up"} else {"down"}});
    (if db_up { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }, Json(body))
}

async fn reset(State(state): State<AppState>, auth: BearerAuth) -> Resp {
    if let Err(denied) = require_admin(&state, &auth) { return denied; }
    // Revocations are intentionally preserved across resets.
    finish(async {
        sqlx::query("TRUNCATE verified_sessions, challenges, enroll_nonces, enrolled_keys, vendors")
            .execute(&state.db).await?;
        Ok(ok(json!({"status":"reset","message":"Server state cleared"})))
    }.await)
}

async fn register_vendor(State(state): State<AppState>, Json(req): Json<RegisterVendorRequest>) -> Resp {
    if req.vendor_id.is_empty() || req.rp_origin.is_empty() || req.api_key.is_empty() {
        return error("missing required fields");
    }
    // ':' is the challenge-key namespace separator.
    if req.vendor_id.contains(':') { return error("vendor_id must not contain ':'"); }
    finish(async {
        let res_json = serde_json::to_string(&req.allowed_resources).unwrap();
        let act_json = serde_json::to_string(&req.allowed_actions).unwrap();
        let inserted = sqlx::query(
            "INSERT INTO vendors (vendor_id,rp_origin,allowed_resources,allowed_actions,api_key_hash)
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT (vendor_id) DO NOTHING")
            .bind(&req.vendor_id).bind(&req.rp_origin).bind(res_json).bind(act_json)
            .bind(sha256_hex(req.api_key.as_bytes()))
            .execute(&state.db).await?.rows_affected();
        if inserted == 0 { return Ok(error("vendor already registered")); }
        Ok(ok(json!({"status":"registered","vendor_id":req.vendor_id,"rp_origin":req.rp_origin,"message":"Vendor registered and persisted."})))
    }.await)
}

async fn enroll_challenge(State(state): State<AppState>, Json(req): Json<EnrollChallengeRequest>) -> Resp {
    finish(async {
        let nonce = hex_encode(&random_bytes::<32>());
        let expires_at: i64 = sqlx::query_scalar(&format!(
            "INSERT INTO enroll_nonces (wallet_id,nonce,expires_at) VALUES ($1,$2,{DB_NOW}+$3)
             ON CONFLICT (wallet_id) DO UPDATE SET nonce = EXCLUDED.nonce, expires_at = EXCLUDED.expires_at
             RETURNING expires_at"))
            .bind(&req.wallet_id).bind(&nonce).bind(ENROLL_NONCE_TTL_SECS).fetch_one(&state.db).await?;
        Ok(ok(json!({"status":"ok","wallet_id":req.wallet_id,"nonce":nonce,"expires_at":expires_at})))
    }.await)
}

async fn enroll(State(state): State<AppState>, Json(req): Json<EnrollRequest>) -> Resp {
    let Some(pk_bytes) = hex_decode(&req.public_key_hex) else { return error("invalid public key hex") };
    let Some(sig_bytes) = hex_decode(&req.nonce_signature_hex) else { return error("invalid signature hex") };
    finish(async {
        let mut tx = state.db.begin().await?;
        let row: Option<(String, bool)> = sqlx::query_as(&format!(
            "SELECT nonce, expires_at <= {DB_NOW} FROM enroll_nonces WHERE wallet_id=$1 FOR UPDATE"))
            .bind(&req.wallet_id).fetch_optional(&mut *tx).await?;
        let Some((nonce, expired)) = row else { return Ok(error("no enroll challenge found — call /enroll/challenge first")) };
        if expired {
            sqlx::query("DELETE FROM enroll_nonces WHERE wallet_id=$1").bind(&req.wallet_id).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(error("enroll challenge expired — call /enroll/challenge again"));
        }
        let Ok(pk) = dilithium3::PublicKey::from_bytes(&pk_bytes) else { return Ok(error("invalid public key")) };
        let Ok(sig) = dilithium3::DetachedSignature::from_bytes(&sig_bytes) else { return Ok(error("invalid signature")) };
        if dilithium3::verify_detached_signature(&sig, nonce.as_bytes(), &pk).is_err() {
            return Ok(error("key ownership proof failed"));
        }
        sqlx::query("DELETE FROM enroll_nonces WHERE wallet_id=$1").bind(&req.wallet_id).execute(&mut *tx).await?;
        let inserted = sqlx::query("INSERT INTO enrolled_keys (wallet_id,public_key_hex,key_id) VALUES ($1,$2,$3)
                                    ON CONFLICT DO NOTHING")
            .bind(&req.wallet_id).bind(req.public_key_hex.to_lowercase()).bind(sha256_hex(&pk_bytes))
            .execute(&mut *tx).await?.rows_affected();
        if inserted == 0 { return Ok(error("wallet already enrolled — key replacement not permitted")); }
        tx.commit().await?;
        Ok(ok(json!({"status":"enrolled","wallet_id":req.wallet_id,"message":"Key ownership verified. Wallet enrolled and persisted."})))
    }.await)
}

async fn challenge(State(state): State<AppState>, Json(req): Json<ChallengeRequest>) -> Resp {
    finish(async {
        let db = &state.db;
        let enrolled = sqlx::query("SELECT 1 FROM enrolled_keys WHERE wallet_id=$1")
            .bind(&req.wallet_id).fetch_optional(db).await?.is_some();
        if !enrolled { return Ok(error("wallet not enrolled")); }
        let vendor = sqlx::query("SELECT rp_origin,allowed_resources,allowed_actions FROM vendors WHERE vendor_id=$1")
            .bind(&req.vendor_id).fetch_optional(db).await?;
        let Some(vendor) = vendor else { return Ok(error("vendor not registered")) };
        let (rp_origin, res_json, act_json): (String, String, String) = (vendor.get(0), vendor.get(1), vendor.get(2));
        let resources: Vec<String> = serde_json::from_str(&res_json).unwrap_or_default();
        if !resources.iter().any(|r| r == &req.resource_id || r == "*") {
            return Ok(error("resource not authorized for this vendor"));
        }
        if !vendor_permits(&res_json, &act_json, &req.resource_id, &req.action) {
            return Ok(error("action not authorized for this vendor"));
        }
        // The database clock is the single time authority for all instances.
        let now: i64 = sqlx::query_scalar(&format!("SELECT {DB_NOW}")).fetch_one(db).await?;
        let issued = Request {
            suite_id: SUITE_ML_DSA_65, rp_id: req.vendor_id.clone(), rp_origin,
            challenge_id: random_bytes::<16>(), nonce: random_bytes::<16>(),
            issued_at: now as u64, expires_at: (now + CHALLENGE_TTL_SECS) as u64,
            resource_id: req.resource_id.clone(), action: req.action.clone(),
            scopes: vec![scope_for(&req.action).into()], operation_digest: None, policy_id: POLICY_ID.into(),
        };
        let transcript = match canonical_request(&issued) {
            Ok(t) => t,
            Err(e) => return Ok(error(&format!("{e:?}"))),
        };
        let cid_hex = hex_encode(&issued.challenge_id);
        sqlx::query("INSERT INTO challenges (challenge_key,challenge_id,vendor_id,wallet_id,transcript,issued_at,expires_at)
                     VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(challenge_key(&req.vendor_id, &cid_hex)).bind(&cid_hex).bind(&req.vendor_id)
            .bind(&req.wallet_id).bind(&transcript).bind(now).bind(now + CHALLENGE_TTL_SECS)
            .execute(db).await?;
        Ok(ok(json!({"status":"ok","challenge":{"challenge_id":issued.challenge_id.to_vec(),"nonce":issued.nonce.to_vec(),
            "issued_at":issued.issued_at,"expires_at":issued.expires_at,"resource_id":issued.resource_id,"action":issued.action,
            "scopes":issued.scopes,"policy_id":issued.policy_id,"rp_id":issued.rp_id,"rp_origin":issued.rp_origin,"suite_id":issued.suite_id}})))
    }.await)
}

async fn verify(State(state): State<AppState>, Json(req): Json<VerifyRequest>) -> Resp {
    finish(verify_inner(&state.db, req).await)
}

async fn verify_inner(db: &PgPool, req: VerifyRequest) -> Result<Resp, sqlx::Error> {
    let Some(pk_bytes) = hex_decode(&req.public_key_hex) else { return Ok(error("invalid public key hex")) };
    let Some(sig_bytes) = hex_decode(&req.signature_hex) else { return Ok(error("invalid signature hex")) };
    let c = &req.challenge;
    let (Ok(challenge_id), Ok(nonce)) = (<[u8; 16]>::try_from(c.challenge_id.as_slice()), <[u8; 16]>::try_from(c.nonce.as_slice()))
        else { return Ok(rejected("malformed challenge")) };
    let submitted = Request { suite_id: c.suite_id, rp_id: c.rp_id.clone(), rp_origin: c.rp_origin.clone(),
        challenge_id, nonce, issued_at: c.issued_at, expires_at: c.expires_at,
        resource_id: c.resource_id.clone(), action: c.action.clone(),
        scopes: c.scopes.clone(), operation_digest: None, policy_id: c.policy_id.clone() };
    let Ok(submitted_transcript) = canonical_request(&submitted) else { return Ok(rejected("malformed challenge")) };
    let key = challenge_key(&req.vendor_id, &hex_encode(&challenge_id));

    // --- Phase 1: read-only pre-checks (no state is modified) ---
    let stored_pk: Option<(String, String)> = sqlx::query_as("SELECT public_key_hex, key_id FROM enrolled_keys WHERE wallet_id=$1")
        .bind(&req.wallet_id).fetch_optional(db).await?;
    let Some((stored_pk, key_id)) = stored_pk else { return Ok(error("wallet not enrolled")) };
    if stored_pk != req.public_key_hex.to_lowercase() { return Ok(error("public key does not match enrolled key")); }
    if sqlx::query("SELECT 1 FROM revocations WHERE key_id=$1").bind(&key_id).fetch_optional(db).await?.is_some() {
        return Ok(rejected("wallet key has been revoked"));
    }
    let row: Option<(Vec<u8>, String)> = sqlx::query_as("SELECT transcript, wallet_id FROM challenges WHERE challenge_key=$1")
        .bind(&key).fetch_optional(db).await?;
    let Some((transcript, challenge_wallet)) = row else { return Ok(rejected("Replay: unknown challenge")) };
    if challenge_wallet != req.wallet_id { return Ok(rejected("challenge was issued to a different wallet")); }
    if transcript != submitted_transcript { return Ok(rejected("Challenge: submitted request does not match issued challenge")); }

    // --- Phase 2: ML-DSA-65 signature over the server-stored transcript, before any write ---
    let (Ok(pk), Ok(sig)) = (dilithium3::PublicKey::from_bytes(&pk_bytes), dilithium3::DetachedSignature::from_bytes(&sig_bytes))
        else { return Ok(rejected("Signature: malformed key or signature")) };
    if dilithium3::verify_detached_signature(&sig, &transcript, &pk).is_err() {
        return Ok(rejected("Signature: invalid ML-DSA-65 signature"));
    }

    // --- Phase 3: one atomic transaction: revocation check + consume ---
    // Dropping `tx` without commit (early return or `?`) rolls back.
    let mut tx = db.begin().await?;
    // Serialize against /admin/revoke, which holds FOR UPDATE on this row.
    let still_enrolled = sqlx::query("SELECT 1 FROM enrolled_keys WHERE wallet_id=$1 AND key_id=$2 FOR SHARE")
        .bind(&req.wallet_id).bind(&key_id).fetch_optional(&mut *tx).await?.is_some();
    if !still_enrolled { return Ok(error("wallet not enrolled")); }
    let ch = sqlx::query(&format!(
        "SELECT consumed_at, issued_at, expires_at, {DB_NOW} AS now FROM challenges WHERE challenge_key=$1 FOR UPDATE"))
        .bind(&key).fetch_optional(&mut *tx).await?;
    let Some(ch) = ch else { return Ok(rejected("Replay: unknown challenge")) };
    let (consumed_at, issued_at, expires_at, now): (Option<i64>, i64, i64, i64) =
        (ch.try_get(0)?, ch.try_get(1)?, ch.try_get(2)?, ch.try_get(3)?);
    if consumed_at.is_some() { return Ok(rejected("Replay")); }
    if now < issued_at || now >= expires_at { return Ok(rejected("Time: challenge expired or not yet valid")); }
    // Statement runs after the key-row lock is held, so it sees any revocation
    // that committed before this verification could proceed.
    if sqlx::query("SELECT 1 FROM revocations WHERE key_id=$1").bind(&key_id).fetch_optional(&mut *tx).await?.is_some() {
        return Ok(rejected("wallet key has been revoked"));
    }
    sqlx::query("UPDATE challenges SET consumed_at=$2 WHERE challenge_key=$1 AND consumed_at IS NULL")
        .bind(&key).bind(now).execute(&mut *tx).await?;
    // Authorization is independent of authentication. A cryptographically valid
    // proof consumes its challenge even if denied, so it cannot be used to probe.
    let vendor: Option<(String, String)> = sqlx::query_as("SELECT allowed_resources, allowed_actions FROM vendors WHERE vendor_id=$1")
        .bind(&req.vendor_id).fetch_optional(&mut *tx).await?;
    let permitted = vendor.is_some_and(|(r, a)| vendor_permits(&r, &a, &c.resource_id, &c.action))
        && c.scopes == [scope_for(&c.action)];
    if !permitted {
        tx.commit().await?;
        return Ok(rejected("Unauthorized"));
    }
    sqlx::query("INSERT INTO verified_sessions (wallet_id,vendor_id,resource_id,action,challenge_key) VALUES ($1,$2,$3,$4,$5)")
        .bind(&req.wallet_id).bind(&req.vendor_id).bind(&c.resource_id).bind(&c.action).bind(&key)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(ok(json!({"status":"verified","message":"DIS proof accepted — access granted","wallet_id":req.wallet_id,
        "vendor_id":req.vendor_id,"resource_id":c.resource_id,"action":c.action})))
}

async fn revoke(State(state): State<AppState>, auth: BearerAuth, Json(req): Json<RevokeRequest>) -> Resp {
    if let Err(denied) = require_admin(&state, &auth) { return denied; }
    finish(async {
        let mut tx = state.db.begin().await?;
        // Exclusive lock on the key row: waits for in-flight verifications of
        // this key to finish, and blocks new ones until the revocation commits.
        let key_id: Option<String> = sqlx::query_scalar("SELECT key_id FROM enrolled_keys WHERE wallet_id=$1 FOR UPDATE")
            .bind(&req.wallet_id).fetch_optional(&mut *tx).await?;
        let Some(key_id) = key_id else { return Ok(error("wallet not enrolled")) };
        let reason = req.reason.clone().unwrap_or_else(|| "revoked by admin".into());
        sqlx::query(&format!("INSERT INTO revocations (key_id,wallet_id,revoked_at,reason) VALUES ($1,$2,{DB_NOW},$3)
                              ON CONFLICT (key_id) DO NOTHING"))
            .bind(&key_id).bind(&req.wallet_id).bind(reason).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(ok(json!({"status":"revoked","wallet_id":req.wallet_id,"key_id":key_id,"message":"Key revoked and persisted."})))
    }.await)
}

async fn sessions(State(state): State<AppState>, auth: Option<TypedHeader<Authorization<Bearer>>>) -> Resp {
    match auth {
        Some(TypedHeader(Authorization(bearer))) if bearer.token() == SESSIONS_API_KEY => finish(async {
            let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
                "SELECT wallet_id,vendor_id,resource_id,action,to_char(verified_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
                 FROM verified_sessions ORDER BY id DESC LIMIT 100").fetch_all(&state.db).await?;
            let sessions: Vec<Value> = rows.into_iter().map(|(w, v, r, a, t)|
                json!({"wallet_id":w,"vendor_id":v,"resource_id":r,"action":a,"verified_at":t})).collect();
            let wallets: Vec<String> = sqlx::query_scalar("SELECT wallet_id FROM enrolled_keys").fetch_all(&state.db).await?;
            let vendors: Vec<String> = sqlx::query_scalar("SELECT vendor_id FROM vendors").fetch_all(&state.db).await?;
            Ok(ok(json!({"verified_sessions":sessions,"count":sessions.len(),"enrolled_wallets":wallets,"registered_vendors":vendors})))
        }.await),
        _ => (StatusCode::UNAUTHORIZED, Json(json!({"status":"error","message":"Authorization: Bearer <api-key> required"}))),
    }
}

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set (e.g. postgres://user:pass@localhost/dis)");
    let acquire_timeout = std::env::var("DIS_DB_ACQUIRE_TIMEOUT_MS").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(3000);
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_millis(acquire_timeout))
        .test_before_acquire(true)
        .connect(&database_url).await
        .expect("cannot connect to PostgreSQL — refusing to start");
    sqlx::migrate!("./migrations").run(&pool).await.expect("database migration failed");
    let vendor_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vendors").fetch_one(&pool).await.unwrap_or(0);
    let key_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM enrolled_keys").fetch_one(&pool).await.unwrap_or(0);
    let admin_key_hash = match std::env::var("DIS_ADMIN_API_KEY") {
        Ok(k) if k.len() >= 32 => Some(Sha256::digest(k.as_bytes()).into()),
        Ok(_) => panic!("DIS_ADMIN_API_KEY must be at least 32 characters"),
        Err(_) => { eprintln!("DIS_ADMIN_API_KEY not set — /admin/* endpoints disabled"); None }
    };
    let state = AppState { db: pool, admin_key_hash };
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
        .route("/admin/revoke", post(revoke))
        .with_state(state)
        .layer(cors);
    let port = std::env::var("PORT").unwrap_or("3000".into());
    let addr = format!("0.0.0.0:{port}");
    println!("DIS Vendor Server v0.4.0 (DIS-STATE-003) on {addr}");
    println!("DB: PostgreSQL — {vendor_count} vendor(s), {key_count} key(s) in shared store");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
