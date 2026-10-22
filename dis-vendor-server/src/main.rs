//! DIS vendor server — DIS-SEC-005 gap closures (challenge purge, token single-use, SQLite removal).
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
//!
//! SSRF protection (see `validate_origin_url`, `validate_origin_ips`,
//! `verify_origin_ownership`):
//! Production mode enforces HTTPS, validates URL structure (no path/query/
//! fragment/userinfo), blocks internal/private/loopback IPs, disables HTTP
//! redirects, and closes the DNS rebinding window by pinning the pre-validated
//! IP addresses into a per-request reqwest client (`resolve_to_addrs`).
//! `DIS_ALLOW_HTTP_ORIGINS=1` (test-only) skips these checks; starting the
//! server with this flag requires `DIS_TEST_MODE=1` to also be set (two-key
//! acknowledgment), making accidental production enablement nearly impossible.
//! Both flags must never appear in production deployments.
//! The origin-verification HTTP client never uses proxy env vars (`no_proxy()`).

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
    delegation::{delegation_id, verify_delegation_link, MAX_CHAIN_DEPTH, Delegation},
    Request, SUITE_ML_DSA_65,
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{net::{IpAddr, SocketAddr}, time::Duration};
use tower_http::cors::{AllowOrigin, CorsLayer};
use url::Url;
// reqwest is used only for origin verification; pulled in via dev-deps too.
use reqwest::Client as HttpClient;

const SESSIONS_API_KEY: &str = "dis-sessions-key-change-in-production";
/// Server-enforced challenge lifetime. Must match the `challenge_ttl` CHECK
/// constraint in migrations/0001_dis_state_003.sql.
const CHALLENGE_TTL_SECS: i64 = 299;
/// Lifetime of an /enroll/challenge nonce.
const ENROLL_NONCE_TTL_SECS: i64 = 300;
const POLICY_ID: &str = "v1";
const DB_NOW: &str = "EXTRACT(EPOCH FROM clock_timestamp())::BIGINT";
/// How often the background purge task runs.
const CHALLENGE_PURGE_INTERVAL_SECS: u64 = 600;
/// Consumed challenges are kept for this many seconds after consumption before
/// being purged (allows post-hoc audit of recent sessions).
const CHALLENGE_PURGE_GRACE_SECS: i64 = 3600;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    /// SHA-256 of DIS_ADMIN_API_KEY; None disables the admin endpoints.
    admin_key_hash: Option<[u8; 32]>,
    /// SHA-256 of DIS_VENDOR_REGISTRATION_KEY; None disables /vendor/register.
    registration_key_hash: Option<[u8; 32]>,
    /// HTTP client used to verify vendor RP origin ownership.
    http: HttpClient,
    /// When true, HTTP origins are accepted and internal IPs are not blocked.
    /// Set only via DIS_ALLOW_HTTP_ORIGINS=1 + DIS_TEST_MODE=1 for integration tests.
    allow_http_origins: bool,
}

type Resp = (StatusCode, Json<Value>);
type BearerAuth = Option<TypedHeader<Authorization<Bearer>>>;

/// Compares a bearer token against a stored SHA-256 hash in constant time.
/// Returns `Ok(())` only when the token is present and matches.
fn require_key(expected: Option<[u8; 32]>, auth: &BearerAuth, disabled_msg: &str, required_msg: &str) -> Result<(), Resp> {
    let Some(expected) = expected else {
        return Err((StatusCode::FORBIDDEN, Json(json!({"status":"error","message":disabled_msg}))));
    };
    let presented: [u8; 32] = match auth {
        Some(TypedHeader(Authorization(bearer))) => Sha256::digest(bearer.token().as_bytes()).into(),
        None => [0u8; 32],
    };
    let diff = expected.iter().zip(presented.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if auth.is_none() || diff != 0 {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"status":"error","message":required_msg}))));
    }
    Ok(())
}

fn require_admin(state: &AppState, auth: &BearerAuth) -> Result<(), Resp> {
    require_key(state.admin_key_hash, auth,
        "admin API disabled — set DIS_ADMIN_API_KEY",
        "Authorization: Bearer <admin-key> required")
}

fn require_registration_key(state: &AppState, auth: &BearerAuth) -> Result<(), Resp> {
    require_key(state.registration_key_hash, auth,
        "vendor registration disabled — set DIS_VENDOR_REGISTRATION_KEY",
        "Authorization: Bearer <registration-key> required")
}

/// Well-known path where the vendor must publish its ownership token.
const WELL_KNOWN_PATH: &str = "/.well-known/dis-vendor-registration";
/// Maximum response body length accepted from the well-known endpoint.
const WELL_KNOWN_MAX_BYTES: usize = 4096;
/// Timeout for the outbound origin-verification request.
const ORIGIN_VERIFY_TIMEOUT_MS: u64 = 5000;

/// Validate that `rp_origin` is a well-formed origin suitable for a production
/// vendor registration.  A well-formed origin:
///   - parses as a URL with scheme https (or http when `allow_http` is set)
///   - has a non-empty host that is not an IP literal in production
///   - has no path component beyond "/" (i.e. no path/query/fragment/userinfo)
///   - has no embedded credentials (userinfo)
fn validate_origin_url(rp_origin: &str, allow_http: bool) -> Result<Url, &'static str> {
    let parsed = Url::parse(rp_origin).map_err(|_| "rp_origin is not a valid URL")?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_http => {}
        "http" => return Err("rp_origin must use HTTPS in production"),
        _ => return Err("rp_origin scheme must be https"),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("rp_origin must not contain credentials");
    }
    if parsed.host_str().unwrap_or("").is_empty() {
        return Err("rp_origin must have a non-empty host");
    }
    // No path beyond "/", no query, no fragment.
    let path = parsed.path();
    if path != "/" && !path.is_empty() {
        return Err("rp_origin must not have a path component");
    }
    if parsed.query().is_some() {
        return Err("rp_origin must not have a query component");
    }
    if parsed.fragment().is_some() {
        return Err("rp_origin must not have a fragment component");
    }
    Ok(parsed)
}

/// Returns true if `addr` is a non-public address that should not be reachable
/// from a vendor registration request.
fn is_internal_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()         // 127.0.0.0/8
            || v4.is_private()       // 10/8, 172.16/12, 192.168/16
            || v4.is_link_local()    // 169.254.0.0/16
            || v4.is_multicast()     // 224.0.0.0/4
            || v4.is_broadcast()     // 255.255.255.255
            || v4.is_unspecified()   // 0.0.0.0
            // CGNAT 100.64.0.0/10
            || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
            // Reserved/documentation ranges
            || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()         // ::1
            || v6.is_multicast()
            || v6.is_unspecified()   // ::
            // IPv4-mapped: ::ffff:0:0/96 — check the embedded v4 address
            || v6.to_ipv4_mapped().map(|v4| is_internal_ip(IpAddr::V4(v4))).unwrap_or(false)
        }
    }
}

/// Resolve `hostname` and verify that none of the DNS answers are internal IPs.
///
/// Returns the validated socket addresses so the caller can build a pinned
/// reqwest client that connects directly to one of these addresses instead of
/// re-resolving the hostname.  This closes the DNS rebinding window: an attacker
/// who changes the DNS record after validation cannot redirect the actual HTTP
/// connection to an internal destination.
async fn validate_origin_ips(hostname: &str, port: u16) -> Result<Vec<SocketAddr>, &'static str> {
    let hostport = format!("{hostname}:{port}");
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&hostport).await
        .map_err(|_| "could not resolve rp_origin hostname")?
        .collect();
    if addrs.is_empty() {
        return Err("rp_origin hostname resolved to no addresses");
    }
    for sa in &addrs {
        if is_internal_ip(sa.ip()) {
            return Err("rp_origin resolves to a non-public IP address");
        }
    }
    Ok(addrs)
}

/// Verify that the caller controls `rp_origin` by fetching
/// `{rp_origin}/.well-known/dis-vendor-registration` and checking that
/// the response body contains the expected ownership token.
///
/// The ownership token is `SHA-256("{vendor_id}:{registration_token}")`,
/// hex-encoded. The vendor pre-publishes it at the well-known URL before
/// calling `/vendor/register`; the server verifies it here.
///
/// This binds the vendor identity to a specific origin: a registration
/// token for `vendor-a` cannot be used to register `vendor-b` at the
/// same origin, and a token from a different origin cannot claim
/// `vendor-a`'s identity.
///
/// SSRF protections applied before any outbound request (when `allow_http` is false):
///   - scheme must be https
///   - URL structure validated (no path/query/fragment/credentials)
///   - DNS-resolved addresses must all be public (no loopback/private/link-local/etc.)
///   - Validated IPs are pinned into a per-request client via `resolve_to_addrs`,
///     so the actual connection uses the pre-checked addresses — not a fresh DNS
///     lookup — closing the DNS rebinding window.
///   - HTTP redirects are disabled on every client built here.
async fn verify_origin_ownership(
    http: &HttpClient,
    rp_origin: &str,
    vendor_id: &str,
    registration_token: &str,
    allow_http: bool,
) -> Result<(), &'static str> {
    // Validate URL structure before making any network request.
    let parsed = validate_origin_url(rp_origin, allow_http)?;
    let hostname = parsed.host_str().unwrap_or("").to_string();

    // Determine which client to use for the outbound GET.
    //
    // Production path (allow_http == false):
    //   IP literals → check directly, use the shared client.
    //   Hostnames   → resolve, validate, build a per-request pinned client.
    //                 The pinned client's `resolve_to_addrs` map means reqwest
    //                 will connect to one of the pre-validated IPs instead of
    //                 re-invoking the OS DNS resolver.  A rebinding attacker
    //                 who changes the DNS record after `validate_origin_ips`
    //                 returns cannot redirect the connection to a private address.
    //
    // Test path (allow_http == true):
    //   Origins are IP literals (127.0.0.1:PORT); no DNS to rebind; shared client.
    let pinned: Option<HttpClient>;
    if !allow_http {
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            // Numeric IP literal — validate directly, no DNS involved.
            if is_internal_ip(ip) {
                return Err("rp_origin must not be a non-public IP address");
            }
            pinned = None;
        } else {
            let port = parsed.port().unwrap_or(443);
            let validated_addrs = validate_origin_ips(&hostname, port).await?;
            // Build a one-shot client pinned to the validated addresses.
            // `.no_proxy()` prevents proxy env vars from redirecting this
            // request through an unintended proxy that could reach internal
            // services the IP validation just blocked.
            pinned = Some(
                HttpClient::builder()
                    .timeout(Duration::from_millis(ORIGIN_VERIFY_TIMEOUT_MS))
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .resolve_to_addrs(&hostname, &validated_addrs)
                    .build()
                    .map_err(|_| "failed to build pinned HTTP client")?,
            );
        }
    } else {
        pinned = None;
    }
    let effective_client = pinned.as_ref().unwrap_or(http);

    // Compute what the well-known endpoint must return.
    let expected = sha256_hex(format!("{vendor_id}:{registration_token}").as_bytes());
    // Construct the well-known URL from the validated parsed origin only, not
    // from the raw rp_origin string, to avoid any parsing inconsistency.
    let well_known_url = {
        let mut u = parsed.clone();
        u.set_path(WELL_KNOWN_PATH);
        String::from(u)
    };
    let resp = effective_client
        .get(&well_known_url)
        .timeout(Duration::from_millis(ORIGIN_VERIFY_TIMEOUT_MS))
        .send().await
        .map_err(|_| "could not reach rp_origin well-known endpoint")?;
    if !resp.status().is_success() {
        return Err("rp_origin well-known endpoint returned non-200");
    }
    let body = resp.bytes().await.map_err(|_| "could not read well-known response")?;
    if body.len() > WELL_KNOWN_MAX_BYTES {
        return Err("well-known response too large");
    }
    let body_str = std::str::from_utf8(&body)
        .map_err(|_| "well-known response is not valid UTF-8")?
        .trim();
    if body_str != expected {
        return Err("well-known token does not match expected value");
    }
    Ok(())
}

/// Unit tests for the SSRF protection layer.
#[cfg(test)]
mod ssrf_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── validate_origin_url ──────────────────────────────────────────────────

    #[test]
    fn origin_url_https_bare_accepted() {
        assert!(validate_origin_url("https://example.com", false).is_ok());
        assert!(validate_origin_url("https://example.com:8443", false).is_ok());
    }

    #[test]
    fn origin_url_http_rejected_in_prod() {
        assert!(validate_origin_url("http://example.com", false).is_err());
    }

    #[test]
    fn origin_url_http_accepted_in_test_mode() {
        assert!(validate_origin_url("http://127.0.0.1:8080", true).is_ok());
    }

    #[test]
    fn origin_url_ftp_rejected() {
        assert!(validate_origin_url("ftp://example.com", false).is_err());
    }

    #[test]
    fn origin_url_credentials_rejected() {
        assert!(validate_origin_url("https://user:pass@example.com", false).is_err());
    }

    #[test]
    fn origin_url_path_rejected() {
        assert!(validate_origin_url("https://example.com/path", false).is_err());
    }

    #[test]
    fn origin_url_query_rejected() {
        assert!(validate_origin_url("https://example.com?q=1", false).is_err());
    }

    #[test]
    fn origin_url_fragment_rejected() {
        assert!(validate_origin_url("https://example.com#f", false).is_err());
    }

    // ── is_internal_ip ───────────────────────────────────────────────────────

    #[test]
    fn loopback_ipv4_is_internal() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255))));
    }

    #[test]
    fn private_rfc1918_is_internal() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn link_local_is_internal() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
    }

    #[test]
    fn cgnat_is_internal() {
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_internal_ip(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
        // 100.128.0.0 is outside CGNAT.
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0))));
    }

    #[test]
    fn loopback_ipv6_is_internal() {
        assert!(is_internal_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn ipv4_mapped_private_is_internal() {
        // ::ffff:192.168.1.1
        let mapped: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_internal_ip(IpAddr::V6(mapped)));
    }

    #[test]
    fn public_ipv4_is_not_internal() {
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_internal_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    // ── DNS pinning mechanism ─────────────────────────────────────────────────

    /// Verifies that a reqwest client built with `resolve_to_addrs` routes
    /// requests to the pinned address without consulting the OS DNS resolver.
    ///
    /// This exercises the mechanism used by `verify_origin_ownership`: after
    /// `validate_origin_ips` returns validated `Vec<SocketAddr>`, a per-request
    /// client is built with `resolve_to_addrs(hostname, &validated_addrs)` so
    /// the actual HTTP connection uses those pre-checked IPs.  The OS resolver
    /// is bypassed for that connection, so a DNS change between the pre-flight
    /// check and the outbound GET has no effect on which address is reached.
    ///
    /// Note: this test does not simulate an adversary changing live DNS answers
    /// between two real queries; it verifies the mechanism that makes such an
    /// attack ineffective (bypassing the OS resolver entirely for the connection).
    #[tokio::test]
    async fn pinned_client_uses_pre_validated_address() {
        use axum::{routing::get as aGet, Router as ARouter};
        use tokio::net::TcpListener;

        // Start a mock server that returns a known body.
        const BODY: &str = "pinning-works";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let app = ARouter::new().route(
                "/.well-known/dis-vendor-registration",
                aGet(|| async { BODY }),
            );
            axum::serve(listener, app).await.ok();
        });

        let mock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        // Build a client pinned to the mock's address under a fake hostname.
        // "fake-dis-pin.invalid" is guaranteed to never exist in real DNS
        // (IANA reserves the .invalid TLD for exactly this purpose).
        let pinned = HttpClient::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs("fake-dis-pin.invalid", &[mock_addr])
            .build()
            .unwrap();

        // Request via the fake hostname → reaches the mock through pinning.
        let url = format!("http://fake-dis-pin.invalid:{port}/.well-known/dis-vendor-registration");
        let resp = pinned.get(&url).send().await
            .expect("pinned client must reach the mock server");
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.text().await.unwrap().trim(), BODY);

        // An unpinned client fails because the hostname does not exist in DNS.
        let unpinned = HttpClient::builder()
            .timeout(Duration::from_millis(500))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let err = unpinned.get(&url).send().await;
        assert!(err.is_err(), "unpinned client must fail for a .invalid hostname");

        handle.abort();
    }
}

#[derive(Deserialize)]
struct RegisterVendorRequest {
    vendor_id: String,
    rp_origin: String,
    allowed_resources: Vec<String>,
    allowed_actions: Vec<String>,
    /// Per-vendor API key (stored as SHA-256; used for /sessions auth scoping in future).
    api_key: String,
    /// One-time registration token.  The vendor must pre-publish
    /// `SHA-256("{vendor_id}:{registration_token}")` at
    /// `{rp_origin}/.well-known/dis-vendor-registration`.
    registration_token: String,
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
/// Security rejections always return 403 so callers cannot mistake a denied
/// authorization for success by checking only the HTTP status code.
fn rejected(msg: &str) -> Resp { (StatusCode::FORBIDDEN, Json(json!({"status":"rejected","message":msg}))) }

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

async fn register_vendor(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(req): Json<RegisterVendorRequest>,
) -> Resp {
    if let Err(denied) = require_registration_key(&state, &auth) { return denied; }
    if req.vendor_id.is_empty() || req.rp_origin.is_empty()
        || req.api_key.is_empty() || req.registration_token.is_empty() {
        return error("missing required fields");
    }
    // ':' is the challenge-key namespace separator.
    if req.vendor_id.contains(':') { return error("vendor_id must not contain ':'"); }
    if req.registration_token.len() < 32 {
        return error("registration_token must be at least 32 characters");
    }
    // Verify the vendor controls its declared rp_origin before writing anything.
    if let Err(msg) = verify_origin_ownership(&state.http, &req.rp_origin, &req.vendor_id, &req.registration_token, state.allow_http_origins).await {
        return (StatusCode::FORBIDDEN, Json(json!({"status":"error","message":format!("origin ownership verification failed: {msg}")})));
    }
    finish(async {
        let token_hash = sha256_hex(req.registration_token.as_bytes());
        let res_json = serde_json::to_string(&req.allowed_resources).unwrap();
        let act_json = serde_json::to_string(&req.allowed_actions).unwrap();
        // Atomically: mark the token used AND insert the vendor row.
        // Either both succeed or neither does (transaction).
        let mut tx = state.db.begin().await?;
        // Claim the token. ON CONFLICT DO NOTHING; rows_affected == 0 means already used.
        let token_inserted = sqlx::query(&format!(
            "INSERT INTO used_registration_tokens (token_hash,vendor_id,used_at)
             VALUES ($1,$2,{DB_NOW}) ON CONFLICT (token_hash) DO NOTHING"))
            .bind(&token_hash).bind(&req.vendor_id)
            .execute(&mut *tx).await?.rows_affected();
        if token_inserted == 0 {
            tx.rollback().await.ok();
            return Ok(error("registration token already used"));
        }
        let vendor_inserted = sqlx::query(&format!(
            "INSERT INTO vendors (vendor_id,rp_origin,allowed_resources,allowed_actions,api_key_hash,registration_token_hash,origin_verified_at)
             VALUES ($1,$2,$3,$4,$5,$6,{DB_NOW}) ON CONFLICT (vendor_id) DO NOTHING"))
            .bind(&req.vendor_id).bind(&req.rp_origin).bind(res_json).bind(act_json)
            .bind(sha256_hex(req.api_key.as_bytes()))
            .bind(&token_hash)
            .execute(&mut *tx).await?.rows_affected();
        if vendor_inserted == 0 {
            tx.rollback().await.ok();
            return Ok(error("vendor already registered"));
        }
        tx.commit().await?;
        Ok(ok(json!({"status":"registered","vendor_id":req.vendor_id,"rp_origin":req.rp_origin,
            "message":"Vendor registered: origin ownership verified and identity persisted."})))
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
        let vendor = sqlx::query("SELECT rp_origin,allowed_resources,allowed_actions,origin_verified_at FROM vendors WHERE vendor_id=$1")
            .bind(&req.vendor_id).fetch_optional(db).await?;
        let Some(vendor) = vendor else { return Ok(error("vendor not registered")) };
        let (rp_origin, res_json, act_json, verified_at): (String, String, String, Option<i64>) =
            (vendor.get(0), vendor.get(1), vendor.get(2), vendor.get(3));
        if verified_at.is_none() {
            return Ok(error("vendor origin not verified — registration incomplete"));
        }
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

// ── /api/dis/verify_delegated ─────────────────────────────────────────────────
// DIS-I11: verifies a DelegatedProof against the DB.
//
// Request shape mirrors /verify: the client supplies the same ChallengeResponse
// blob issued by /challenge (wallet_id, vendor_id, challenge), plus:
//   - delegation_chain: ordered list of signed Delegation links (JSON)
//   - agent_public_key_hex: hex ML-DSA-65 key of the acting agent
//   - agent_signature_hex: hex ML-DSA-65 sig of the server-stored transcript
//
// Verification order:
//   1. Root holder enrolled & not revoked (DB read)
//   2. Each delegation link: sig valid, not expired, chain keys connected,
//      scopes narrow (never widen), depth ≤ MAX_CHAIN_DEPTH
//   3. Agent key == last link's delegate_public_key
//   4. Agent sig valid over server-stored transcript (same bytes as /verify)
//   5. DB transaction: for each link with max_uses, SELECT FOR UPDATE + check
//      used_count < max_uses, increment — fail closed if limit reached
//
// No in-memory state; all security-relevant checks are against the DB.

#[derive(Deserialize)]
struct DelegationLinkJson {
    rp_id: String,
    delegator_public_key: String,  // hex
    delegate_public_key: String,   // hex
    scopes: Vec<String>,
    resource_id: String,
    action: String,
    issued_at: u64,
    expires_at: u64,
    max_uses: Option<u32>,
    requires_human_approval: bool,
    signature: String,             // hex Dilithium3 detached sig
}

#[derive(Deserialize)]
struct VerifyDelegatedRequest {
    wallet_id: String,
    vendor_id: String,
    challenge: ChallengeResponse,
    delegation_chain: Vec<DelegationLinkJson>,
    agent_public_key_hex: String,
    agent_signature_hex: String,
}

async fn verify_delegated(State(state): State<AppState>, Json(req): Json<VerifyDelegatedRequest>) -> Resp {
    finish(verify_delegated_inner(&state.db, req).await)
}

async fn verify_delegated_inner(db: &PgPool, req: VerifyDelegatedRequest) -> Result<Resp, sqlx::Error> {
    let c = &req.challenge;
    let now_secs: i64 = sqlx::query_scalar(&format!("SELECT {DB_NOW}")).fetch_one(db).await?;
    let now = now_secs as u64;

    // Parse chain.
    if req.delegation_chain.is_empty() || req.delegation_chain.len() > MAX_CHAIN_DEPTH {
        return Ok(rejected("delegation chain empty or exceeds max depth"));
    }
    let mut chain: Vec<Delegation> = Vec::with_capacity(req.delegation_chain.len());
    for link in &req.delegation_chain {
        let (Some(dpk), Some(epk), Some(sig)) = (
            hex_decode(&link.delegator_public_key),
            hex_decode(&link.delegate_public_key),
            hex_decode(&link.signature),
        ) else {
            return Ok(rejected("delegation link: malformed hex in keys or signature"));
        };
        chain.push(Delegation {
            rp_id: link.rp_id.clone(),
            delegator_public_key: dpk,
            delegate_public_key: epk,
            scopes: link.scopes.clone(),
            resource_id: link.resource_id.clone(),
            action: link.action.clone(),
            issued_at: link.issued_at,
            expires_at: link.expires_at,
            max_uses: link.max_uses,
            requires_human_approval: link.requires_human_approval,
            signature: sig,
        });
    }

    // Phase 1: root holder enrolled, not revoked, and belongs to req.wallet_id.
    let root_fp = sha256_hex(&chain[0].delegator_public_key);
    if sqlx::query("SELECT 1 FROM revocations WHERE key_id=$1").bind(&root_fp)
        .fetch_optional(db).await?.is_some() {
        return Ok(rejected("root delegator key has been revoked"));
    }
    let enrolled_wallet: Option<String> = sqlx::query_scalar(
        "SELECT wallet_id FROM enrolled_keys WHERE key_id=$1").bind(&root_fp)
        .fetch_optional(db).await?;
    match enrolled_wallet {
        None => return Ok(rejected("root delegator key is not enrolled")),
        Some(ref w) if w != &req.wallet_id =>
            return Ok(rejected("root delegator key is enrolled under a different wallet")),
        _ => {}
    }

    // Phase 2: each delegation link sig + expiry; chain key connectivity; scope narrowing;
    // rp_id must match the authenticated vendor for every link.
    for (i, link) in chain.iter().enumerate() {
        if link.rp_id != c.rp_id {
            return Ok(rejected(&format!(
                "delegation link {i} rp_id ({}) does not match vendor ({})",
                link.rp_id, c.rp_id)));
        }
        if let Err(e) = verify_delegation_link(link, now) {
            return Ok(rejected(&format!("delegation link {i} invalid: {e}")));
        }
        if i > 0 {
            let prev = &chain[i - 1];
            if link.delegator_public_key != prev.delegate_public_key {
                return Ok(rejected(&format!("delegation chain broken at link {i}: key mismatch")));
            }
            if !link.scopes.iter().all(|s| prev.scopes.contains(s)) {
                return Ok(rejected(&format!("delegation chain link {i}: child scopes widen parent")));
            }
        }
    }

    // Phase 2b: last delegation link must authorize the resource, action, and scopes
    // the challenge was issued for.  Without this check an agent could present a
    // delegation for doc:1/read against a challenge for doc:secret/delete.
    let last = chain.last().unwrap();
    if last.resource_id != c.resource_id {
        return Ok(rejected(&format!(
            "delegation resource ({}) does not match challenge resource ({})",
            last.resource_id, c.resource_id)));
    }
    if last.action != c.action {
        return Ok(rejected(&format!(
            "delegation action ({}) does not match challenge action ({})",
            last.action, c.action)));
    }
    for scope in &c.scopes {
        if !last.scopes.contains(scope) {
            return Ok(rejected(&format!(
                "challenge scope ({scope}) is not covered by the delegation")));
        }
    }

    // Phase 3: agent key == last link's delegate.
    let Some(agent_pk_bytes) = hex_decode(&req.agent_public_key_hex) else {
        return Ok(rejected("agent_public_key_hex: invalid hex"));
    };
    if agent_pk_bytes != chain.last().unwrap().delegate_public_key {
        return Ok(rejected("agent key does not match last delegation link's delegate"));
    }

    // Phase 4: agent sig over server-stored transcript (same bytes /verify uses).
    let (Ok(challenge_id), Ok(nonce)) = (
        <[u8; 16]>::try_from(c.challenge_id.as_slice()),
        <[u8; 16]>::try_from(c.nonce.as_slice()),
    ) else {
        return Ok(rejected("malformed challenge"));
    };
    let submitted = Request {
        suite_id: c.suite_id, rp_id: c.rp_id.clone(), rp_origin: c.rp_origin.clone(),
        challenge_id, nonce, issued_at: c.issued_at, expires_at: c.expires_at,
        resource_id: c.resource_id.clone(), action: c.action.clone(),
        scopes: c.scopes.clone(), operation_digest: None, policy_id: c.policy_id.clone(),
    };
    let Ok(submitted_transcript) = canonical_request(&submitted) else {
        return Ok(rejected("malformed challenge fields"));
    };
    let challenge_key_str = challenge_key(&req.vendor_id, &hex_encode(&challenge_id));
    let stored_row = sqlx::query(
        "SELECT transcript, wallet_id, consumed_at FROM challenges WHERE challenge_key=$1")
        .bind(&challenge_key_str).fetch_optional(db).await?;
    let Some(row) = stored_row else {
        return Ok(rejected("Replay: unknown or expired challenge"));
    };
    let (stored_transcript, challenge_wallet, consumed_at): (Vec<u8>, String, Option<i64>) =
        (row.try_get(0)?, row.try_get(1)?, row.try_get(2)?);
    if consumed_at.is_some() {
        return Ok(rejected("Replay: challenge already consumed"));
    }
    if challenge_wallet != req.wallet_id {
        return Ok(rejected("Challenge: issued to a different wallet"));
    }
    if stored_transcript != submitted_transcript {
        return Ok(rejected("Challenge: submitted fields do not match issued challenge"));
    }
    let Some(agent_sig_bytes) = hex_decode(&req.agent_signature_hex) else {
        return Ok(rejected("agent_signature_hex: invalid hex"));
    };
    let (Ok(agent_pk), Ok(agent_sig)) = (
        dilithium3::PublicKey::from_bytes(&agent_pk_bytes),
        dilithium3::DetachedSignature::from_bytes(&agent_sig_bytes),
    ) else {
        return Ok(rejected("agent key or signature malformed"));
    };
    if dilithium3::verify_detached_signature(&agent_sig, &stored_transcript, &agent_pk).is_err() {
        return Ok(rejected("agent signature invalid"));
    }

    // Phase 5 (DIS-I11): atomic max_uses enforcement.
    // Each link with max_uses gets a SELECT FOR UPDATE + check + increment in one
    // transaction. Any limit hit rolls back the whole transaction (no partial increments).
    let mut tx = db.begin().await?;
    for link in &chain {
        let Some(max) = link.max_uses else { continue };
        let del_id: Vec<u8> = match delegation_id(link) {
            Ok(id) => id.to_vec(),
            Err(_) => return Ok(rejected("internal: failed to compute delegation id")),
        };
        sqlx::query(
            "INSERT INTO delegation_usage (delegation_id, max_uses, used_count)
             VALUES ($1, $2, 0) ON CONFLICT (delegation_id) DO NOTHING")
            .bind(&del_id).bind(max as i32).execute(&mut *tx).await?;
        let row = sqlx::query(
            "SELECT used_count, max_uses FROM delegation_usage WHERE delegation_id=$1 FOR UPDATE")
            .bind(&del_id).fetch_one(&mut *tx).await?;
        let (used, cap): (i32, i32) = (row.try_get(0)?, row.try_get(1)?);
        if used >= cap {
            tx.rollback().await?;
            return Ok(rejected(&format!(
                "delegation max_uses ({cap}) exhausted ({used} uses already recorded)")));
        }
        sqlx::query(
            "UPDATE delegation_usage SET used_count = used_count + 1 WHERE delegation_id=$1")
            .bind(&del_id).execute(&mut *tx).await?;
    }
    // Mark challenge consumed (same as /verify) so it cannot be replayed.
    sqlx::query(
        "UPDATE challenges SET consumed_at=$2 WHERE challenge_key=$1 AND consumed_at IS NULL")
        .bind(&challenge_key_str).bind(now_secs).execute(&mut *tx).await?;
    tx.commit().await?;

    Ok(ok(json!({
        "status": "verified",
        "message": "delegated proof accepted",
        "wallet_id": req.wallet_id,
        "vendor_id": req.vendor_id,
        "resource_id": c.resource_id,
        "action": c.action,
    })))
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
    let registration_key_hash = match std::env::var("DIS_VENDOR_REGISTRATION_KEY") {
        Ok(k) if k.len() >= 32 => Some(Sha256::digest(k.as_bytes()).into()),
        Ok(_) => panic!("DIS_VENDOR_REGISTRATION_KEY must be at least 32 characters"),
        Err(_) => { eprintln!("DIS_VENDOR_REGISTRATION_KEY not set — /vendor/register disabled"); None }
    };
    let allow_http_origins = std::env::var("DIS_ALLOW_HTTP_ORIGINS").map(|v| v == "1").unwrap_or(false);
    if allow_http_origins {
        // Two-key acknowledgment: DIS_TEST_MODE=1 must also be set.
        // Requiring a second independent flag makes it nearly impossible to
        // accidentally enable this bypass in a production deployment — an operator
        // would need to deliberately set both test-only variables.  A legitimate
        // production host that happens to use a local PostgreSQL instance would
        // still be protected because neither flag belongs in any production manifest
        // or secrets store.
        let test_mode = std::env::var("DIS_TEST_MODE").map(|v| v == "1").unwrap_or(false);
        if !test_mode {
            panic!(
                "DIS_ALLOW_HTTP_ORIGINS=1 requires DIS_TEST_MODE=1 to also be set. \
                 Both are test-only flags that must never be present in production. \
                 Set DIS_TEST_MODE=1 only in integration-test environments."
            );
        }
        eprintln!("WARNING: DIS_ALLOW_HTTP_ORIGINS=1 + DIS_TEST_MODE=1 — \
                   HTTP origins and internal IPs allowed. \
                   Test mode only — never set these in production.");
    }
    let http = HttpClient::builder()
        .timeout(Duration::from_millis(ORIGIN_VERIFY_TIMEOUT_MS + 500))
        // Disable redirects: a redirect could steer the verification request to
        // an internal endpoint after the SSRF pre-checks have passed.
        .redirect(reqwest::redirect::Policy::none())
        // Never route origin-verification requests through a proxy: a misconfigured
        // or attacker-controlled proxy could forward the request to internal services,
        // bypassing the IP validation checks above.
        .no_proxy()
        .build().expect("failed to build HTTP client");
    let state = AppState { db: pool, admin_key_hash, registration_key_hash, http, allow_http_origins };

    // Background task: purge expired/consumed challenge rows to keep the table
    // bounded. Consumed rows are retained for CHALLENGE_PURGE_GRACE_SECS after
    // consumption for audit purposes; purely expired (never-consumed) rows are
    // removed immediately once past their TTL.
    {
        let purge_pool = state.db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                Duration::from_secs(CHALLENGE_PURGE_INTERVAL_SECS)
            );
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                let result = sqlx::query(&format!(
                    "DELETE FROM challenges WHERE
                       (consumed_at IS NOT NULL
                        AND consumed_at < {DB_NOW} - $1)
                    OR (consumed_at IS NULL
                        AND expires_at < {DB_NOW})"))
                    .bind(CHALLENGE_PURGE_GRACE_SECS)
                    .execute(&purge_pool).await;
                match result {
                    Ok(r) if r.rows_affected() > 0 =>
                        eprintln!("challenge purge: removed {} row(s)", r.rows_affected()),
                    Err(e) =>
                        eprintln!("challenge purge error: {e}"),
                    _ => {}
                }
            }
        });
    }

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
        .route("/api/dis/verify_delegated", post(verify_delegated))
        .route("/sessions", get(sessions))
        .route("/admin/revoke", post(revoke))
        .with_state(state)
        .layer(cors);
    let port = std::env::var("PORT").unwrap_or("3000".into());
    let addr = format!("0.0.0.0:{port}");
    println!("DIS Vendor Server v0.6.0 (DIS-SEC-005 gaps) on {addr}");
    println!("DB: PostgreSQL — {vendor_count} vendor(s), {key_count} key(s) in shared store");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
