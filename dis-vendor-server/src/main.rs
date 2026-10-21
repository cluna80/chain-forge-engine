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
    canonical_request,
    verifier::{HolderProof, RelyingParty, RpPolicy, VerifyError},
    Request, SUITE_ML_DSA_65,
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tower_http::cors::{AllowOrigin, CorsLayer};

// ── Config ────────────────────────────────────────────────────────────────────

const SESSIONS_API_KEY: &str = "dis-sessions-key-change-in-production";

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<VendorState>>,
}

struct VendorState {
    rps: HashMap<String, RelyingParty>,
    enrolled_keys: HashMap<String, Vec<u8>>,
    enroll_nonces: HashMap<String, String>, // wallet_id -> nonce
    verified_sessions: Vec<VerifiedSession>,
    vendor_registry: HashMap<String, VendorRegistration>,
}

#[derive(Clone, Serialize)]
struct VerifiedSession {
    wallet_id: String,
    vendor_id: String,
    resource_id: String,
    action: String,
    verified_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct VendorRegistration {
    vendor_id: String,
    rp_origin: String,
    allowed_resources: Vec<String>,
    allowed_actions: Vec<String>,
    api_key_hash: String, // SHA256 of vendor API key
}

// ── Request/Response types ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterVendorRequest {
    vendor_id: String,
    rp_origin: String,
    allowed_resources: Vec<String>,
    allowed_actions: Vec<String>,
    api_key: String,
}

#[derive(Deserialize)]
struct EnrollChallengeRequest {
    wallet_id: String,
}

#[derive(Deserialize)]
struct EnrollRequest {
    wallet_id: String,
    public_key_hex: String,
    nonce_signature_hex: String, // proves ownership of the key
}

#[derive(Deserialize)]
struct ChallengeRequest {
    wallet_id: String,
    vendor_id: String,
    resource_id: String,
    action: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct ChallengeResponse {
    challenge_id: Vec<u8>,
    nonce: Vec<u8>,
    issued_at: u64,
    expires_at: u64,
    resource_id: String,
    action: String,
    scopes: Vec<String>,
    policy_id: String,
    rp_id: String,
    rp_origin: String,
    suite_id: u16,
}

#[derive(Deserialize)]
struct VerifyRequest {
    wallet_id: String,
    vendor_id: String,
    challenge: ChallengeResponse,
    public_key_hex: String,
    signature_hex: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sha256_hex(input: &str) -> String {
    hex_encode(&Sha256::digest(input.as_bytes()))
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap();
    hex_encode(&bytes)
}

fn make_rp_for(vendor_id: &str, rp_origin: &str, resources: &[String], actions: &[String]) -> RelyingParty {
    let mut grants = HashSet::new();
    for resource in resources {
        for action in actions {
            let scope = match action.as_str() {
                "read" => "document:read",
                "write" => "document:write",
                "submit" => "payment:submit",
                _ => "document:read",
            };
            grants.insert((resource.clone(), action.clone(), scope.to_string()));
        }
    }
    RelyingParty::new(RpPolicy {
        rp_id: vendor_id.to_string(),
        rp_origin: rp_origin.to_string(),
        policy_id: "v1".into(),
        grants,
    })
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn reset(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut s = state.inner.lock().unwrap();
    s.rps.clear();
    s.enrolled_keys.clear();
    s.enroll_nonces.clear();
    s.verified_sessions.clear();
    s.vendor_registry.clear();
    Json(serde_json::json!({"status": "reset", "message": "Server state cleared"}))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "server": "DIS Vendor Server",
        "version": "0.2.0",
        "security": "DIS-SEC-002"
    }))
}

// Fix #3: Vendors register with their own identity
async fn register_vendor(
    State(state): State<AppState>,
    Json(req): Json<RegisterVendorRequest>,
) -> Json<serde_json::Value> {
    if req.vendor_id.is_empty() || req.rp_origin.is_empty() || req.api_key.is_empty() {
        return Json(serde_json::json!({"status":"error","message":"missing required fields"}));
    }

    let mut s = state.inner.lock().unwrap();

    if s.vendor_registry.contains_key(&req.vendor_id) {
        return Json(serde_json::json!({"status":"error","message":"vendor already registered"}));
    }

    let mut rp = make_rp_for(&req.vendor_id, &req.rp_origin, &req.allowed_resources, &req.allowed_actions);

    // Enroll any already-registered wallet keys into this new vendor RP
    for pk_bytes in s.enrolled_keys.values() {
        let _ = rp.enroll_test_key(pk_bytes);
    }

    s.rps.insert(req.vendor_id.clone(), rp);

    s.vendor_registry.insert(req.vendor_id.clone(), VendorRegistration {
        vendor_id: req.vendor_id.clone(),
        rp_origin: req.rp_origin.clone(),
        allowed_resources: req.allowed_resources,
        allowed_actions: req.allowed_actions,
        api_key_hash: sha256_hex(&req.api_key),
    });

    Json(serde_json::json!({
        "status": "registered",
        "vendor_id": req.vendor_id,
        "rp_origin": req.rp_origin,
        "message": "Vendor registered. Wallets can now enroll and authenticate."
    }))
}

// Fix #1a: Issue enroll challenge (nonce)
async fn enroll_challenge(
    State(state): State<AppState>,
    Json(req): Json<EnrollChallengeRequest>,
) -> Json<serde_json::Value> {
    let nonce = random_nonce();
    let mut s = state.inner.lock().unwrap();
    s.enroll_nonces.insert(req.wallet_id.clone(), nonce.clone());
    Json(serde_json::json!({
        "status": "ok",
        "wallet_id": req.wallet_id,
        "nonce": nonce,
        "message": "Sign this nonce with your ML-DSA key to prove ownership"
    }))
}

// Fix #1b: Authenticated enrollment — verify key ownership
async fn enroll(
    State(state): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> Json<serde_json::Value> {
    let pk_bytes = match hex_decode(&req.public_key_hex) {
        Some(b) => b,
        None => return Json(serde_json::json!({"status":"error","message":"invalid public key hex"})),
    };
    let sig_bytes = match hex_decode(&req.nonce_signature_hex) {
        Some(b) => b,
        None => return Json(serde_json::json!({"status":"error","message":"invalid signature hex"})),
    };

    let mut s = state.inner.lock().unwrap();

    // Check nonce exists
    let nonce = match s.enroll_nonces.get(&req.wallet_id) {
        Some(n) => n.clone(),
        None => return Json(serde_json::json!({
            "status": "error",
            "message": "no enroll challenge found — call /enroll/challenge first"
        })),
    };

    // Verify signature over nonce proves key ownership
    let pk = match dilithium3::PublicKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return Json(serde_json::json!({"status":"error","message":"invalid public key"})),
    };
    let sig = match dilithium3::DetachedSignature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return Json(serde_json::json!({"status":"error","message":"invalid signature"})),
    };

    if dilithium3::verify_detached_signature(&sig, nonce.as_bytes(), &pk).is_err() {
        return Json(serde_json::json!({
            "status": "error",
            "message": "key ownership proof failed — signature does not match nonce"
        }));
    }

    // Ownership proven — remove nonce
    s.enroll_nonces.remove(&req.wallet_id);

    // Fix: block key replacement — once enrolled, key is permanent
    if s.enrolled_keys.contains_key(&req.wallet_id) {
        return Json(serde_json::json!({
            "status": "error",
            "message": "wallet already enrolled — key replacement not permitted"
        }));
    }

    // Enroll key into ALL vendor RPs so verify() works
    for rp in s.rps.values_mut() {
        let _ = rp.enroll_test_key(&pk_bytes);
    }

    s.enrolled_keys.insert(req.wallet_id.clone(), pk_bytes);

    Json(serde_json::json!({
        "status": "enrolled",
        "wallet_id": req.wallet_id,
        "message": "Key ownership verified. Wallet enrolled."
    }))
}

async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Json<serde_json::Value> {
    let mut s = state.inner.lock().unwrap();

    if !s.enrolled_keys.contains_key(&req.wallet_id) {
        return Json(serde_json::json!({
            "status": "error",
            "message": "wallet not enrolled"
        }));
    }

    let vendor = match s.vendor_registry.get(&req.vendor_id) {
        Some(v) => v.clone(),
        None => return Json(serde_json::json!({
            "status": "error",
            "message": "vendor not registered — call /vendor/register first"
        })),
    };

    // Fix #5: Check resource/action against vendor-specific grants
    if !vendor.allowed_resources.iter().any(|r| r == &req.resource_id || r == "*") {
        return Json(serde_json::json!({"status":"error","message":"resource not authorized for this vendor"}));
    }
    if !vendor.allowed_actions.contains(&req.action) {
        return Json(serde_json::json!({"status":"error","message":"action not authorized for this vendor"}));
    }

    let now = now_secs();
    let scope = match req.action.as_str() {
        "read" => "document:read",
        "write" => "document:write",
        "submit" => "payment:submit",
        _ => "document:read",
    };

    let template = Request {
        suite_id: SUITE_ML_DSA_65,
        rp_id: req.vendor_id.clone(),
        rp_origin: vendor.rp_origin.clone(),
        challenge_id: [0; 16],
        nonce: [0; 16],
        issued_at: now,
        expires_at: now + 299,
        resource_id: req.resource_id.clone(),
        action: req.action.clone(),
        scopes: vec![scope.into()],
        operation_digest: None,
        policy_id: "v1".into(),
    };

    let rp = match s.rps.get_mut(&req.vendor_id) {
        Some(r) => r,
        None => return Json(serde_json::json!({"status":"error","message":"vendor RP not found — re-register vendor"})),
    };

    match rp.issue(template) {
        Ok(issued) => Json(serde_json::json!({
            "status": "ok",
            "challenge": {
                "challenge_id": issued.challenge_id.to_vec(),
                "nonce": issued.nonce.to_vec(),
                "issued_at": issued.issued_at,
                "expires_at": issued.expires_at,
                "resource_id": issued.resource_id,
                "action": issued.action,
                "scopes": issued.scopes,
                "policy_id": issued.policy_id,
                "rp_id": issued.rp_id,
                "rp_origin": issued.rp_origin,
                "suite_id": issued.suite_id
            }
        })),
        Err(e) => Json(serde_json::json!({"status":"error","message":format!("{:?}",e)})),
    }
}

async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Json<serde_json::Value> {
    let pk_bytes = match hex_decode(&req.public_key_hex) {
        Some(b) => b,
        None => return Json(serde_json::json!({"status":"error","message":"invalid public key hex"})),
    };
    let sig_bytes = match hex_decode(&req.signature_hex) {
        Some(b) => b,
        None => return Json(serde_json::json!({"status":"error","message":"invalid signature hex"})),
    };

    // Verify enrolled key matches submitted key
    let s_lock = state.inner.lock().unwrap();
    match s_lock.enrolled_keys.get(&req.wallet_id) {
        Some(enrolled_pk) if enrolled_pk != &pk_bytes => {
            return Json(serde_json::json!({
                "status": "error",
                "message": "public key does not match enrolled key"
            }));
        }
        None => return Json(serde_json::json!({"status":"error","message":"wallet not enrolled"})),
        _ => {}
    }
    drop(s_lock);

    let c = &req.challenge;
    let mut challenge_id = [0u8; 16];
    let mut nonce = [0u8; 16];
    for (i, b) in c.challenge_id.iter().take(16).enumerate() { challenge_id[i] = *b as u8; }
    for (i, b) in c.nonce.iter().take(16).enumerate() { nonce[i] = *b as u8; }

    let request = Request {
        suite_id: c.suite_id,
        rp_id: c.rp_id.clone(),
        rp_origin: c.rp_origin.clone(),
        challenge_id,
        nonce,
        issued_at: c.issued_at,
        expires_at: c.expires_at,
        resource_id: c.resource_id.clone(),
        action: c.action.clone(),
        scopes: c.scopes.clone(),
        operation_digest: None,
        policy_id: c.policy_id.clone(),
    };

    let proof = HolderProof { public_key: pk_bytes, signature: sig_bytes };
    let now = now_secs();
    let mut s = state.inner.lock().unwrap();

    let rp = match s.rps.get_mut(&req.vendor_id) {
        Some(r) => r,
        None => return Json(serde_json::json!({"status":"error","message":"vendor not registered"})),
    };

    match rp.verify(&request, &proof, now) {
        Ok(_) => {
            s.verified_sessions.push(VerifiedSession {
                wallet_id: req.wallet_id.clone(),
                vendor_id: req.vendor_id.clone(),
                resource_id: c.resource_id.clone(),
                action: c.action.clone(),
                verified_at: chrono::Utc::now().to_rfc3339(),
            });
            Json(serde_json::json!({
                "status": "verified",
                "message": "DIS proof accepted — access granted",
                "wallet_id": req.wallet_id,
                "vendor_id": req.vendor_id,
                "resource_id": c.resource_id,
                "action": c.action,
            }))
        }
        Err(e) => Json(serde_json::json!({"status":"rejected","message":format!("{:?}",e)})),
    }
}

// Fix #2: Protected /sessions endpoint
async fn sessions(
    State(state): State<AppState>,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match auth {
        Some(TypedHeader(Authorization(bearer))) if bearer.token() == SESSIONS_API_KEY => {
            let s = state.inner.lock().unwrap();
            (StatusCode::OK, Json(serde_json::json!({
                "verified_sessions": s.verified_sessions,
                "count": s.verified_sessions.len(),
                "enrolled_wallets": s.enrolled_keys.keys().collect::<Vec<_>>(),
                "registered_vendors": s.vendor_registry.keys().collect::<Vec<_>>()
            })))
        }
        _ => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "status": "error",
            "message": "Authorization: Bearer <api-key> required"
        }))),
    }
}

#[tokio::main]
async fn main() {
    let state = AppState {
        inner: Arc::new(Mutex::new(VendorState {
            rps: HashMap::new(),
            enrolled_keys: HashMap::new(),
            enroll_nonces: HashMap::new(),
            verified_sessions: Vec::new(),
            vendor_registry: HashMap::new(),
        })),
    };

    // Fix #4: Tighter CORS
    let allowed_origins = std::env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
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
    println!("🚀 DIS Vendor Server v0.2.0 (DIS-SEC-002) running on {addr}");
    println!("   POST /vendor/register   — register a vendor with its own identity");
    println!("   POST /enroll/challenge  — get nonce to prove key ownership");
    println!("   POST /enroll            — authenticated enrollment with ownership proof");
    println!("   POST /challenge         — issue a DIS challenge");
    println!("   POST /verify            — verify a DIS proof");
    println!("   GET  /sessions          — list sessions (requires API key)");
    println!("   GET  /health            — server status");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
