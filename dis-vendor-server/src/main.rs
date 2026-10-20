use axum::{
    extract::State,
    http::{HeaderValue, Method},
    response::Json,
    routing::{get, post},
    Router,
};
use dis_core::{
    canonical_request,
    verifier::{RelyingParty, RpPolicy, VerifyError},
    Request, SUITE_ML_DSA_65,
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tower_http::cors::CorsLayer;

// ── State ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<VendorState>>,
}

struct VendorState {
    rps: HashMap<String, RelyingParty>,      // wallet_id -> RP
    enrolled_keys: HashMap<String, Vec<u8>>, // wallet_id -> public_key
    verified_sessions: Vec<VerifiedSession>,
}

#[derive(Clone, Serialize)]
struct VerifiedSession {
    wallet_id: String,
    resource_id: String,
    action: String,
    verified_at: String,
}

// ── Request / Response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct EnrollRequest {
    wallet_id: String,
    public_key_hex: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    status: String,
    wallet_id: String,
}

#[derive(Deserialize)]
struct ChallengeRequest {
    wallet_id: String,
    resource_id: String,
    action: String,
}

#[derive(Serialize, Deserialize)]
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
    challenge: ChallengeResponse,
    public_key_hex: String,
    signature_hex: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    status: String,
    message: String,
    wallet_id: Option<String>,
    resource_id: Option<String>,
    action: Option<String>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
        .collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn make_rp_for(rp_id: &str, rp_origin: &str) -> RelyingParty {
    let mut grants = HashSet::new();
    for resource in &["document:001", "payment:001", "profile:001"] {
        for (action, scope) in &[
            ("read", "document:read"),
            ("write", "document:write"),
            ("submit", "payment:submit"),
            ("read", "profile:read"),
        ] {
            grants.insert((resource.to_string(), action.to_string(), scope.to_string()));
        }
    }
    RelyingParty::new(RpPolicy {
        rp_id: rp_id.to_string(),
        rp_origin: rp_origin.to_string(),
        policy_id: "v1".into(),
        grants,
    })
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "server": "DIS Vendor Server",
        "version": "0.1.0",
        "rp_id": "dis-vendor",
        "rp_origin": "https://dis-vendor.example.com"
    }))
}

async fn enroll(
    State(state): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> Json<serde_json::Value> {
    let pk_bytes = match hex_decode(&req.public_key_hex) {
        Some(b) => b,
        None => return Json(serde_json::json!({"status":"error","message":"invalid public key hex"})),
    };

    let mut s = state.inner.lock().unwrap();

    // Create per-wallet RP if not exists
    let wallet_origin = format!("https://{}.example.com", req.wallet_id);
    let wallet_id_clone = req.wallet_id.clone();
    let rp = s.rps.entry(req.wallet_id.clone())
        .or_insert_with(|| make_rp_for(&wallet_id_clone, &wallet_origin));

    match rp.enroll_test_key(&pk_bytes) {
        Ok(_) => {
            s.enrolled_keys.insert(req.wallet_id.clone(), pk_bytes);
            Json(serde_json::json!({
                "status": "enrolled",
                "wallet_id": req.wallet_id,
                "message": "Public key enrolled. You can now request challenges."
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("{:?}", e)
        })),
    }
}

async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Json<serde_json::Value> {
    let mut s = state.inner.lock().unwrap();

    // Check wallet is enrolled
    if !s.enrolled_keys.contains_key(&req.wallet_id) {
        return Json(serde_json::json!({
            "status": "error",
            "message": "wallet not enrolled — call /enroll first"
        }));
    }
    let rp_id = req.wallet_id.clone();
    let rp_origin = format!("https://{}.example.com", rp_id);
    let rp_id_clone = rp_id.clone();
    let rp_origin_clone = rp_origin.clone();

    let now = now_secs();
    let scope = match req.action.as_str() {
        "read" => "document:read",
        "write" => "document:write",
        "submit" => "payment:submit",
        _ => "document:read",
    };

    let template = Request {
        suite_id: SUITE_ML_DSA_65,
        rp_id: rp_id.clone(),
        rp_origin: rp_origin.clone(),
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

    let rp = s.rps.entry(req.wallet_id.clone())
        .or_insert_with(|| make_rp_for(&rp_id_clone, &rp_origin_clone));
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
        Err(e) => Json(serde_json::json!({
            "status": "error",
            "message": format!("{:?}", e)
        })),
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

    let proof = dis_core::verifier::HolderProof {
        public_key: pk_bytes,
        signature: sig_bytes,
    };

    let now = now_secs();
    let mut s = state.inner.lock().unwrap();
    let wallet_id = req.wallet_id.clone();
    let rp = match s.rps.get_mut(&wallet_id) {
        Some(r) => r,
        None => return Json(serde_json::json!({"status":"error","message":"wallet not enrolled"})),
    };
    match rp.verify(&request, &proof, now) {
        Ok(_) => {
            let session = VerifiedSession {
                wallet_id: req.wallet_id.clone(),
                resource_id: c.resource_id.clone(),
                action: c.action.clone(),
                verified_at: chrono::Utc::now().to_rfc3339(),
            };
            s.verified_sessions.push(session);
            Json(serde_json::json!({
                "status": "verified",
                "message": "DIS proof accepted — access granted",
                "wallet_id": req.wallet_id,
                "resource_id": c.resource_id,
                "action": c.action,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "status": "rejected",
            "message": format!("{:?}", e)
        })),
    }
}

async fn sessions(State(state): State<AppState>) -> Json<serde_json::Value> {
    let s = state.inner.lock().unwrap();
    Json(serde_json::json!({
        "verified_sessions": s.verified_sessions,
        "count": s.verified_sessions.len(),
        "enrolled_wallets": s.enrolled_keys.keys().collect::<Vec<_>>()
    }))
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let state = AppState {
        inner: Arc::new(Mutex::new(VendorState {
            rps: HashMap::new(),
            enrolled_keys: HashMap::new(),
            verified_sessions: Vec::new(),
        })),
    };

    let cors = CorsLayer::new()
        .allow_origin("*".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/enroll", post(enroll))
        .route("/challenge", post(challenge))
        .route("/verify", post(verify))
        .route("/sessions", get(sessions))
        .with_state(state)
        .layer(cors);

    let port = std::env::var("PORT").unwrap_or("3000".into());
    let addr = format!("0.0.0.0:{port}");
    println!("🚀 DIS Vendor Server running on {addr}");
    println!("   POST /enroll    — register a wallet public key");
    println!("   POST /challenge — issue a DIS challenge");
    println!("   POST /verify    — verify a DIS proof");
    println!("   GET  /sessions  — list verified sessions");
    println!("   GET  /health    — server status");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
