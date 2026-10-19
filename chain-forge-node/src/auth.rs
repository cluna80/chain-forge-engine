/// DIS-001 Phase A — QR Challenge/Response Authentication
///
/// This module implements the node-side of the QCB Digital Identity Stone
/// authentication protocol. The QR code displayed to the user contains a
/// challenge issued by this endpoint; the wallet signs it locally with
/// ML-DSA and submits the signature to /api/auth/verify.
///
/// Security properties:
/// - Challenges are time-bounded: expire after AUTH_CHALLENGE_TTL_SECS
/// - Anti-replay: each challenge is consumed on first successful verification
/// - Key never transmitted: wallet sends only its public key + signature
/// - No central authority: any node can issue and verify challenges
/// - Domain-separated canonical signing payload (DIS-AUTH-V1 binary format)
/// - Version isolation: V1 binary payloads are never accepted as legacy JSON
///
/// Phase A scope: challenge issuance + ML-DSA-65 signature verification.
/// Phase B (ZK layer) will add selective disclosure so verifiers learn
/// only what the user authorises, without seeing which identity signed.
///
/// # DIS-AUTH-V1 canonical payload layout
///
/// All integers big-endian. Variable-length fields u16-length-prefixed (max 255 bytes).
/// Challenge ID is always 16 raw bytes (128-bit CSPRNG), represented as 32 hex chars
/// at the API boundary.
///
/// ```text
/// [10]  domain separator:  b"DIS-AUTH-V1"   (fixed, not length-prefixed)
/// [2]   protocol_version:  u16 = 1
/// [2+N] chain_id:          u16 || UTF-8 bytes
/// [2+N] audience (node_id):u16 || UTF-8 bytes
/// [2+N] scope:             u16 || UTF-8 bytes
/// [16]  challenge_id:      16 raw bytes (decoded from 32-char hex API representation)
/// [8]   issued_at:         u64 Unix seconds
/// [8]   expires_at:        u64 Unix seconds
/// ```
///
/// The wallet SHA-256 pre-hashes this canonical payload before ML-DSA signing,
/// matching the existing sign_transaction convention.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};
use serde::{Deserialize, Serialize};

/// Challenges expire after 60 seconds (Phase A devnet default).
/// Phase E security testing will evaluate shorter windows (10–30s) vs.
/// UX tradeoffs on slow networks.
pub const AUTH_CHALLENGE_TTL_SECS: u64 = 60;

/// Maximum pending challenges stored per node before old ones are pruned.
/// Prevents memory exhaustion from challenge-flood attacks.
pub const MAX_PENDING_CHALLENGES: usize = 1024;

/// DIS-AUTH-V1 domain separator (10 bytes, fixed prefix, not length-prefixed).
pub const DIS_DOMAIN_SEPARATOR: &[u8] = b"DIS-AUTH-V1";

/// DIS-AUTH-V1 protocol version embedded in the canonical payload.
pub const DIS_PROTOCOL_VERSION: u16 = 1;

/// Maximum byte length for variable-length fields in the canonical payload.
/// Enforced on both encode and decode paths.
pub const DIS_MAX_FIELD_LEN: usize = 255;

/// A time-bounded authentication challenge issued by the node.
///
/// `challenge_id` is 16 CSPRNG bytes encoded as a 32-char lowercase hex string.
/// The `chain_id` is included so signatures are domain-separated per chain —
/// a replay from another Qattice chain or testnet is rejected by audience binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// 16 CSPRNG bytes as 32-char lowercase hex.
    pub challenge_id: String,
    /// Unix timestamp (seconds) when challenge was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) after which the challenge is invalid.
    pub expires_at: u64,
    /// Node identifier (validator address of the issuing node).
    pub node_id: String,
    /// Human-readable scope (e.g. "wallet:authenticate", "identity:attest").
    pub scope: String,
    /// Chain identifier from genesis — included in canonical signed payload
    /// so cross-chain replay is impossible.
    pub chain_id: String,
}

impl AuthChallenge {
    /// Create a new challenge for the given node and chain, expiring at now + TTL.
    pub fn new(node_id: &str, scope: &str, chain_id: &str) -> Self {
        let now = unix_now();
        let id = generate_challenge_id();
        Self {
            challenge_id: id,
            issued_at:    now,
            expires_at:   now + AUTH_CHALLENGE_TTL_SECS,
            node_id:      node_id.to_string(),
            scope:        scope.to_string(),
            chain_id:     chain_id.to_string(),
        }
    }

    /// Create a challenge with explicit timestamps (test helper).
    #[cfg(test)]
    pub fn new_at(node_id: &str, scope: &str, chain_id: &str, issued_at: u64, expires_at: u64) -> Self {
        Self {
            challenge_id: generate_challenge_id(),
            issued_at,
            expires_at,
            node_id:   node_id.to_string(),
            scope:     scope.to_string(),
            chain_id:  chain_id.to_string(),
        }
    }

    pub fn is_expired(&self) -> bool {
        unix_now() >= self.expires_at
    }

    /// Build the canonical DIS-AUTH-V1 binary payload that the wallet signs.
    ///
    /// Layout (all integers big-endian):
    /// - 10 bytes: b"DIS-AUTH-V1" (domain separator)
    /// - 2 bytes:  protocol version (u16 = 1)
    /// - 2+N:      chain_id (u16 length + UTF-8)
    /// - 2+N:      node_id / audience (u16 length + UTF-8)
    /// - 2+N:      scope (u16 length + UTF-8)
    /// - 16 bytes: challenge_id decoded from 32-char hex
    /// - 8 bytes:  issued_at (u64)
    /// - 8 bytes:  expires_at (u64)
    ///
    /// Returns `Err` if any field exceeds `DIS_MAX_FIELD_LEN` bytes or the
    /// challenge_id is not valid 32-char hex (16 bytes).
    pub fn canonical_payload(&self) -> Result<Vec<u8>, String> {
        canonical_payload(
            DIS_PROTOCOL_VERSION,
            &self.chain_id,
            &self.node_id,
            &self.scope,
            &self.challenge_id,
            self.issued_at,
            self.expires_at,
        )
    }
}

/// Build a DIS-AUTH-V1 canonical payload from explicit fields.
///
/// Separated from `AuthChallenge::canonical_payload` so the wallet crate can
/// call this without needing the full `AuthChallenge` type — just the JSON
/// fields it parsed from the QR code.
pub fn canonical_payload(
    protocol_version: u16,
    chain_id:         &str,
    audience:         &str,
    scope:            &str,
    challenge_id_hex: &str,
    issued_at:        u64,
    expires_at:       u64,
) -> Result<Vec<u8>, String> {
    // Validate field lengths before encoding
    let chain_id_bytes = chain_id.as_bytes();
    let audience_bytes = audience.as_bytes();
    let scope_bytes    = scope.as_bytes();

    if chain_id_bytes.len() > DIS_MAX_FIELD_LEN {
        return Err(format!("chain_id too long: {} bytes (max {DIS_MAX_FIELD_LEN})", chain_id_bytes.len()));
    }
    if audience_bytes.len() > DIS_MAX_FIELD_LEN {
        return Err(format!("audience too long: {} bytes (max {DIS_MAX_FIELD_LEN})", audience_bytes.len()));
    }
    if scope_bytes.len() > DIS_MAX_FIELD_LEN {
        return Err(format!("scope too long: {} bytes (max {DIS_MAX_FIELD_LEN})", scope_bytes.len()));
    }

    // Decode challenge_id hex → 16 raw bytes
    if challenge_id_hex.len() != 32 {
        return Err(format!(
            "challenge_id must be 32 hex chars (16 bytes), got {} chars",
            challenge_id_hex.len()
        ));
    }
    let id_bytes = hex::decode(challenge_id_hex)
        .map_err(|e| format!("challenge_id is not valid hex: {e}"))?;
    if id_bytes.len() != 16 {
        return Err(format!("challenge_id decoded to {} bytes, expected 16", id_bytes.len()));
    }

    let mut buf = Vec::with_capacity(
        DIS_DOMAIN_SEPARATOR.len()   // 10
        + 2                          // version
        + 2 + chain_id_bytes.len()   // chain_id
        + 2 + audience_bytes.len()   // audience
        + 2 + scope_bytes.len()      // scope
        + 16                         // challenge_id
        + 8                          // issued_at
        + 8                          // expires_at
    );

    // Domain separator — fixed, not length-prefixed
    buf.extend_from_slice(DIS_DOMAIN_SEPARATOR);
    // Protocol version
    buf.extend_from_slice(&protocol_version.to_be_bytes());
    // chain_id
    buf.extend_from_slice(&(chain_id_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(chain_id_bytes);
    // audience
    buf.extend_from_slice(&(audience_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(audience_bytes);
    // scope
    buf.extend_from_slice(&(scope_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(scope_bytes);
    // challenge_id raw bytes
    buf.extend_from_slice(&id_bytes);
    // issued_at / expires_at
    buf.extend_from_slice(&issued_at.to_be_bytes());
    buf.extend_from_slice(&expires_at.to_be_bytes());

    Ok(buf)
}

/// Request body for POST /api/auth/challenge
#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    /// Scope hint from the client (e.g. "wallet:authenticate", "identity:attest").
    /// Phase A treats all scopes identically at the crypto layer; authorization
    /// policy is enforced by the verify endpoint.
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String { "wallet:authenticate".to_string() }

/// Request body for POST /api/auth/verify
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The challenge_id from the ChallengeRequest response (32 hex chars).
    pub challenge_id: String,
    /// ML-DSA-65 public key (hex, 1952 bytes = 3904 hex chars).
    pub public_key: String,
    /// ML-DSA-65 signature over SHA-256(canonical_payload()),
    /// tagged "mldsa65:<hex>" (same convention as SignedTxEnvelope).
    pub signature: String,
}

/// Result of a successful verification
#[derive(Debug, Serialize)]
pub struct VerifySuccess {
    pub status: String,
    pub challenge_id: String,
    /// QCB address derived from the verified public key (qcb1pq…)
    pub address: String,
    /// Scope that was requested when the challenge was issued
    pub scope: String,
    /// Unix timestamp of the issued challenge
    pub issued_at: u64,
    /// Chain the challenge was issued on
    pub chain_id: String,
}

/// In-memory store for pending challenges.
/// Backed by a `HashMap<challenge_id, AuthChallenge>` inside an `Arc<Mutex<>>`.
#[derive(Debug, Default)]
pub struct ChallengeStore {
    pub challenges: HashMap<String, AuthChallenge>,
}

impl ChallengeStore {
    pub fn new() -> Self { Self::default() }

    /// Insert a new challenge, evicting expired entries first.
    /// If the store is at capacity after eviction, drops the oldest entry.
    pub fn insert(&mut self, ch: AuthChallenge) {
        // Evict expired entries first
        self.challenges.retain(|_, v| !v.is_expired());

        // If still at cap, drop the oldest by issued_at
        if self.challenges.len() >= MAX_PENDING_CHALLENGES {
            if let Some(oldest_id) = self.challenges
                .values()
                .min_by_key(|c| c.issued_at)
                .map(|c| c.challenge_id.clone())
            {
                self.challenges.remove(&oldest_id);
            }
        }

        self.challenges.insert(ch.challenge_id.clone(), ch);
    }

    /// Consume a challenge by ID (returns None if unknown or expired).
    ///
    /// **Ordering note (DIS threat model):** Challenges are consumed AFTER
    /// successful signature verification (see `verify_challenge_signature`).
    /// This prevents an attacker who learns a challenge_id from burning
    /// a legitimate user's pending challenge via a failed verify attempt.
    /// The trade-off: two concurrent valid verifications of the same challenge
    /// are possible in a narrow window; the second verify call will find the
    /// challenge already gone and be treated as "unknown challenge".
    /// This is acceptable for Phase A devnet (no session tokens issued).
    pub fn consume(&mut self, id: &str) -> Option<AuthChallenge> {
        let ch = self.challenges.remove(id)?;
        if ch.is_expired() { return None; }
        Some(ch)
    }

    /// Peek at a challenge without consuming it (for verify-before-consume ordering).
    pub fn get(&self, id: &str) -> Option<&AuthChallenge> {
        self.challenges.get(id)
    }

    /// Evict all expired challenges (call periodically to bound memory).
    pub fn evict_expired(&mut self) {
        self.challenges.retain(|_, v| !v.is_expired());
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a 16-byte CSPRNG challenge ID, returned as 32 lowercase hex chars.
///
/// Uses `getrandom::getrandom` (OS entropy: `/dev/urandom` on Linux).
/// Panics only if the OS PRNG is completely unavailable — not a recoverable
/// condition for a blockchain node.
fn generate_challenge_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .expect("OS CSPRNG unavailable — cannot generate challenge ID");
    hex::encode(bytes)
}

// ─── ML-DSA-65 signature verification ───────────────────────────────────────

/// Verify an ML-DSA-65 signature over a challenge's DIS-AUTH-V1 canonical payload.
///
/// **Ordering:** Cryptographic verification happens BEFORE the challenge is
/// consumed from the store. This means a failed verification attempt leaves
/// the legitimate challenge intact. The caller is responsible for consuming
/// the challenge only on `Ok`.
///
/// The signature field must be tagged "mldsa65:<hex>". The public key is
/// untagged hex. Audience binding is enforced: the challenge's `chain_id`
/// and `node_id` must match what was issued by this node (caller's responsibility
/// to pass the correct challenge object from the store).
///
/// Returns `Ok(address)` on success, where address is the `qcb1pq…` address
/// derived from the provided public key.
pub fn verify_challenge_signature(
    challenge: &AuthChallenge,
    req:       &VerifyRequest,
) -> Result<String, String> {
    use chain_forge_crypto::{MlDsaScheme, SignatureScheme, Signature, SchemeId};

    // 1. Decode public key
    let pk_bytes = hex::decode(&req.public_key)
        .map_err(|e| format!("invalid public key hex: {e}"))?;

    if pk_bytes.len() != 1952 {
        return Err(format!(
            "ML-DSA-65 public key must be 1952 bytes, got {}",
            pk_bytes.len()
        ));
    }

    // 2. Parse signature: strip "mldsa65:" prefix
    let sig_hex = req.signature
        .strip_prefix("mldsa65:")
        .ok_or_else(|| "signature must be tagged 'mldsa65:<hex>'".to_string())?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| format!("invalid signature hex: {e}"))?;

    // 3. Build the DIS-AUTH-V1 canonical payload (same as what wallet signed).
    //    This is the single source of truth for the signed bytes; both wallet
    //    and verifier call the same `canonical_payload()` function.
    let payload = challenge.canonical_payload()
        .map_err(|e| format!("failed to build canonical payload: {e}"))?;

    // 4. SHA-256 pre-hash (same convention as sign_transaction).
    let message = {
        use sha2::{Sha256, Digest};
        Sha256::digest(&payload).to_vec()
    };

    // 5. Verify using MlDsaScheme (same path as chain-forge-execution).
    let sig = Signature {
        scheme: SchemeId::MlDsa,
        bytes:  sig_bytes,
    };
    MlDsaScheme.verify(&message, &sig, &pk_bytes)
        .map_err(|e| format!("ML-DSA-65 verification failed: {e}"))?;

    // 6. Derive address from the verified public key (qcb1pq… namespace).
    let address = pq_address_from_key(&pk_bytes);

    Ok(address)
}

/// Derive a QCB post-quantum address from an ML-DSA-65 public key.
///
/// Format: `qcb1pq{hex(SHA3-256(key)[..20])}`.
/// Must match `chain-forge-wallet::derive_address_from_pq_key`.
fn pq_address_from_key(public_key: &[u8]) -> String {
    use chain_forge_core::{Address, AddressScheme, HashWidth};
    Address::from_public_key_schemed(public_key, "qcb", HashWidth::Bits256, AddressScheme::PostQuantum)
        .as_str()
        .to_string()
}

// ─── unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHAIN: &str = "qattice-devnet-1";
    const TEST_NODE:  &str = "qcb1alice";
    const TEST_SCOPE: &str = "wallet:authenticate";

    fn make_challenge() -> AuthChallenge {
        AuthChallenge::new(TEST_NODE, TEST_SCOPE, TEST_CHAIN)
    }

    // ── DIS-001-01: challenge issuance ───────────────────────────────────

    #[test]
    fn challenge_has_correct_ttl() {
        let ch = make_challenge();
        let now = unix_now();
        assert!(ch.expires_at >= now + AUTH_CHALLENGE_TTL_SECS - 1);
        assert!(ch.expires_at <= now + AUTH_CHALLENGE_TTL_SECS + 1);
        assert!(!ch.is_expired());
    }

    #[test]
    fn challenge_id_is_32_hex_chars() {
        let ch = make_challenge();
        assert_eq!(ch.challenge_id.len(), 32,
            "challenge_id must be 32 hex chars (16 bytes)");
        assert!(ch.challenge_id.chars().all(|c| c.is_ascii_hexdigit()),
            "challenge_id must be lowercase hex");
    }

    #[test]
    fn two_challenges_have_different_ids() {
        let c1 = make_challenge();
        let c2 = make_challenge();
        assert_ne!(c1.challenge_id, c2.challenge_id,
            "CSPRNG must produce distinct challenge IDs");
    }

    #[test]
    fn challenge_includes_chain_id() {
        let ch = make_challenge();
        assert_eq!(ch.chain_id, TEST_CHAIN);
    }

    // ── DIS-001-02: expiry ───────────────────────────────────────────────

    #[test]
    fn expired_challenge_rejected_by_consume() {
        let mut store = ChallengeStore::new();
        // Construct an already-expired challenge
        let now = unix_now();
        let ch = AuthChallenge::new_at(TEST_NODE, TEST_SCOPE, TEST_CHAIN, now - 70, now - 10);
        assert!(ch.is_expired(), "challenge must be expired");
        let id = ch.challenge_id.clone();
        // Insert bypasses expiry check
        store.challenges.insert(id.clone(), ch);
        // consume() must detect expiry and return None
        let result = store.consume(&id);
        assert!(result.is_none(), "expired challenge must be rejected by consume()");
    }

    #[test]
    fn is_expired_false_for_future_expiry() {
        let now = unix_now();
        let ch = AuthChallenge::new_at(TEST_NODE, TEST_SCOPE, TEST_CHAIN, now, now + 60);
        assert!(!ch.is_expired());
    }

    // ── DIS-001-06: anti-replay (consume-on-success) ─────────────────────

    #[test]
    fn store_consume_returns_none_for_unknown_id() {
        let mut store = ChallengeStore::new();
        assert!(store.consume("nonexistent").is_none());
    }

    #[test]
    fn store_consume_removes_challenge_preventing_replay() {
        let mut store = ChallengeStore::new();
        let ch = make_challenge();
        let id = ch.challenge_id.clone();
        store.insert(ch);
        assert!(store.consume(&id).is_some(), "first consume must succeed");
        assert!(store.consume(&id).is_none(), "second consume must fail (anti-replay)");
    }

    // ── DIS-001-10: challenge-flood / eviction ───────────────────────────

    #[test]
    fn store_evicts_at_capacity() {
        let mut store = ChallengeStore::new();
        for _ in 0..MAX_PENDING_CHALLENGES {
            store.insert(make_challenge());
        }
        assert!(store.challenges.len() <= MAX_PENDING_CHALLENGES);
        store.insert(make_challenge());
        assert!(store.challenges.len() <= MAX_PENDING_CHALLENGES,
            "store must not exceed MAX_PENDING_CHALLENGES after overflow insert");
    }

    // ── DIS-001-09: scope round-trip ─────────────────────────────────────

    #[test]
    fn non_default_scope_round_trips_in_canonical_payload() {
        let ch = AuthChallenge::new(TEST_NODE, "identity:attest", TEST_CHAIN);
        assert_eq!(ch.scope, "identity:attest");
        let payload = ch.canonical_payload().expect("canonical_payload must succeed");
        // Verify the scope bytes appear in the payload (not a full parse, but ensures inclusion)
        let scope_bytes = b"identity:attest";
        assert!(
            payload.windows(scope_bytes.len()).any(|w| w == scope_bytes),
            "scope must be present in canonical payload"
        );
    }

    #[test]
    fn challenge_request_defaults_scope() {
        let req: ChallengeRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(req.scope, "wallet:authenticate");
    }

    // ── DIS-001-11: canonical DIS-AUTH-V1 payload ────────────────────────

    #[test]
    fn canonical_payload_starts_with_domain_separator() {
        let ch = make_challenge();
        let payload = ch.canonical_payload().expect("canonical_payload must succeed");
        assert!(payload.starts_with(DIS_DOMAIN_SEPARATOR),
            "payload must start with DIS-AUTH-V1 domain separator");
    }

    #[test]
    fn canonical_payload_contains_protocol_version_1() {
        let ch = make_challenge();
        let payload = ch.canonical_payload().unwrap();
        let ver_offset = DIS_DOMAIN_SEPARATOR.len();
        let ver = u16::from_be_bytes([payload[ver_offset], payload[ver_offset + 1]]);
        assert_eq!(ver, DIS_PROTOCOL_VERSION, "protocol version must be 1");
    }

    #[test]
    fn canonical_payload_is_deterministic() {
        // Same AuthChallenge must produce identical bytes every call
        let ch = make_challenge();
        let p1 = ch.canonical_payload().unwrap();
        let p2 = ch.canonical_payload().unwrap();
        assert_eq!(p1, p2, "canonical_payload must be deterministic");
    }

    #[test]
    fn canonical_payload_differs_by_chain_id() {
        let now = unix_now();
        // Use same challenge_id to isolate chain_id effect
        let base_id = generate_challenge_id();
        let mut ch1 = AuthChallenge::new_at(TEST_NODE, TEST_SCOPE, "chain-A", now, now + 60);
        ch1.challenge_id = base_id.clone();
        let mut ch2 = AuthChallenge::new_at(TEST_NODE, TEST_SCOPE, "chain-B", now, now + 60);
        ch2.challenge_id = base_id;

        let p1 = ch1.canonical_payload().unwrap();
        let p2 = ch2.canonical_payload().unwrap();
        assert_ne!(p1, p2,
            "different chain_id must produce different canonical payloads (cross-chain replay prevention)");
    }

    #[test]
    fn canonical_payload_differs_by_audience() {
        let now = unix_now();
        let base_id = generate_challenge_id();
        let mut ch1 = AuthChallenge::new_at("node-A", TEST_SCOPE, TEST_CHAIN, now, now + 60);
        ch1.challenge_id = base_id.clone();
        let mut ch2 = AuthChallenge::new_at("node-B", TEST_SCOPE, TEST_CHAIN, now, now + 60);
        ch2.challenge_id = base_id;

        let p1 = ch1.canonical_payload().unwrap();
        let p2 = ch2.canonical_payload().unwrap();
        assert_ne!(p1, p2,
            "different audience must produce different canonical payloads (cross-node replay prevention)");
    }

    #[test]
    fn canonical_payload_differs_by_scope() {
        let now = unix_now();
        let base_id = generate_challenge_id();
        let mut ch1 = AuthChallenge::new_at(TEST_NODE, "wallet:authenticate", TEST_CHAIN, now, now + 60);
        ch1.challenge_id = base_id.clone();
        let mut ch2 = AuthChallenge::new_at(TEST_NODE, "identity:attest", TEST_CHAIN, now, now + 60);
        ch2.challenge_id = base_id;

        let p1 = ch1.canonical_payload().unwrap();
        let p2 = ch2.canonical_payload().unwrap();
        assert_ne!(p1, p2,
            "different scope must produce different canonical payloads");
    }

    #[test]
    fn canonical_payload_rejects_oversized_field() {
        let long_chain = "x".repeat(DIS_MAX_FIELD_LEN + 1);
        let result = canonical_payload(
            DIS_PROTOCOL_VERSION,
            &long_chain,
            TEST_NODE,
            TEST_SCOPE,
            &generate_challenge_id(),
            0, 60,
        );
        assert!(result.is_err(), "oversized chain_id must be rejected");
        assert!(result.unwrap_err().contains("chain_id too long"));
    }

    #[test]
    fn canonical_payload_rejects_invalid_challenge_id_hex() {
        let result = canonical_payload(
            DIS_PROTOCOL_VERSION,
            TEST_CHAIN,
            TEST_NODE,
            TEST_SCOPE,
            "not-hex-at-all!!!!!!!!!!!!!!!!",
            0, 60,
        );
        assert!(result.is_err(), "invalid hex challenge_id must be rejected");
    }

    #[test]
    fn canonical_payload_rejects_wrong_length_challenge_id() {
        // 30 chars = 15 bytes, not 16
        let result = canonical_payload(
            DIS_PROTOCOL_VERSION,
            TEST_CHAIN,
            TEST_NODE,
            TEST_SCOPE,
            "aabbccddeeff001122334455667788",   // 30 chars
            0, 60,
        );
        assert!(result.is_err(), "wrong-length challenge_id must be rejected");
    }

    // ── DIS-001-04/05/04: signature verification ────────────────────────

    fn sign_canonical(payload: &[u8], kp: &chain_forge_crypto::KeyPair) -> String {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};
        use sha2::{Sha256, Digest};
        let message = Sha256::digest(payload).to_vec();
        let sig = MlDsaScheme.sign(&message, kp).expect("signing");
        format!("mldsa65:{}", hex::encode(&sig.bytes))
    }

    #[test]
    fn verify_request_rejects_untagged_signature() {
        let ch = make_challenge();
        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   "aa".repeat(1952),
            signature:    "deadbeef".to_string(),
        };
        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tagged 'mldsa65:"));
    }

    #[test]
    fn verify_request_rejects_wrong_pk_length() {
        let ch = make_challenge();
        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   "deadbeef".to_string(),
            signature:    "mldsa65:aabb".to_string(),
        };
        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("1952 bytes"));
    }

    /// DIS-001-03: full round-trip — real ML-DSA-65 keypair signs canonical payload.
    #[test]
    fn full_roundtrip_sign_and_verify_challenge() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let kp = MlDsaScheme.generate_keypair("test-roundtrip").expect("keygen");
        let pk_hex = hex::encode(&kp.public_key);

        let ch = make_challenge();
        let payload = ch.canonical_payload().expect("canonical_payload");
        let sig_tagged = sign_canonical(&payload, &kp);

        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   pk_hex,
            signature:    sig_tagged,
        };

        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_ok(), "full roundtrip must succeed: {:?}", result);

        let address = result.unwrap();
        assert!(address.starts_with("qcb1pq"), "unexpected address prefix: {address}");
    }

    /// DIS-001-04: forged signature must be rejected.
    #[test]
    fn forged_signature_rejected() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let kp = MlDsaScheme.generate_keypair("test-forge").expect("keygen");
        let pk_hex = hex::encode(&kp.public_key);
        let ch = make_challenge();

        let forged_bytes = vec![0xDE_u8; 3309];
        let forged_sig = format!("mldsa65:{}", hex::encode(&forged_bytes));

        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   pk_hex,
            signature:    forged_sig,
        };
        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_err(), "forged signature must be rejected");
    }

    /// DIS-001-05: wrong-key signature must be rejected.
    #[test]
    fn wrong_key_rejected() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let kp1 = MlDsaScheme.generate_keypair("test-key1").expect("keygen1");
        let kp2 = MlDsaScheme.generate_keypair("test-key2").expect("keygen2");
        let pk1_hex = hex::encode(&kp1.public_key);

        let ch = make_challenge();
        let payload = ch.canonical_payload().unwrap();
        let sig_tagged = sign_canonical(&payload, &kp2);

        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   pk1_hex,
            signature:    sig_tagged,
        };
        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_err(), "wrong-key signature must be rejected");
    }

    /// DIS-001-11: cross-chain replay — signature for chain-A must be rejected on chain-B.
    #[test]
    fn cross_chain_replay_rejected() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let kp = MlDsaScheme.generate_keypair("replay-test").expect("keygen");
        let pk_hex = hex::encode(&kp.public_key);
        let now = unix_now();
        let base_id = generate_challenge_id();

        // Sign for chain-A
        let mut ch_a = AuthChallenge::new_at(TEST_NODE, TEST_SCOPE, "chain-A", now, now + 60);
        ch_a.challenge_id = base_id.clone();
        let payload_a = ch_a.canonical_payload().unwrap();
        let sig = sign_canonical(&payload_a, &kp);

        // Try to verify that same signature against chain-B's version of the challenge
        let mut ch_b = AuthChallenge::new_at(TEST_NODE, TEST_SCOPE, "chain-B", now, now + 60);
        ch_b.challenge_id = base_id;

        let req = VerifyRequest {
            challenge_id: ch_b.challenge_id.clone(),
            public_key:   pk_hex,
            signature:    sig,
        };
        let result = verify_challenge_signature(&ch_b, &req);
        assert!(result.is_err(),
            "cross-chain replay must be rejected: signature for chain-A must not verify on chain-B");
    }

    /// DIS-001-11: wrong-audience replay — signature for node-A must be rejected on node-B.
    #[test]
    fn wrong_audience_rejected() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let kp = MlDsaScheme.generate_keypair("audience-test").expect("keygen");
        let pk_hex = hex::encode(&kp.public_key);
        let now = unix_now();
        let base_id = generate_challenge_id();

        // Sign for node-A
        let mut ch_a = AuthChallenge::new_at("node-A", TEST_SCOPE, TEST_CHAIN, now, now + 60);
        ch_a.challenge_id = base_id.clone();
        let payload_a = ch_a.canonical_payload().unwrap();
        let sig = sign_canonical(&payload_a, &kp);

        // Try to verify on node-B
        let mut ch_b = AuthChallenge::new_at("node-B", TEST_SCOPE, TEST_CHAIN, now, now + 60);
        ch_b.challenge_id = base_id;

        let req = VerifyRequest {
            challenge_id: ch_b.challenge_id.clone(),
            public_key:   pk_hex,
            signature:    sig,
        };
        let result = verify_challenge_signature(&ch_b, &req);
        assert!(result.is_err(),
            "wrong-audience replay must be rejected: signature for node-A must not verify on node-B");
    }

    /// DIS-001-11: wrong-scope replay — signature for scope-A must be rejected under scope-B.
    #[test]
    fn wrong_scope_rejected() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let kp = MlDsaScheme.generate_keypair("scope-test").expect("keygen");
        let pk_hex = hex::encode(&kp.public_key);
        let now = unix_now();
        let base_id = generate_challenge_id();

        let mut ch_auth = AuthChallenge::new_at(TEST_NODE, "wallet:authenticate", TEST_CHAIN, now, now + 60);
        ch_auth.challenge_id = base_id.clone();
        let payload = ch_auth.canonical_payload().unwrap();
        let sig = sign_canonical(&payload, &kp);

        // Same challenge_id, different scope — the verifier's challenge has "identity:attest"
        let mut ch_attest = AuthChallenge::new_at(TEST_NODE, "identity:attest", TEST_CHAIN, now, now + 60);
        ch_attest.challenge_id = base_id;

        let req = VerifyRequest {
            challenge_id: ch_attest.challenge_id.clone(),
            public_key:   pk_hex,
            signature:    sig,
        };
        let result = verify_challenge_signature(&ch_attest, &req);
        assert!(result.is_err(),
            "wrong-scope replay must be rejected: wallet:authenticate sig must not verify as identity:attest");
    }

    /// DIS-001-11: a legacy JSON signing payload must not verify as a V1 canonical payload.
    #[test]
    fn legacy_json_payload_does_not_verify_as_v1() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};
        use sha2::{Sha256, Digest};

        let kp = MlDsaScheme.generate_keypair("version-test").expect("keygen");
        let pk_hex = hex::encode(&kp.public_key);

        let ch = make_challenge();

        // Sign using old JSON path (serde_json::to_string of the whole struct)
        let legacy_json = serde_json::to_string(&ch).expect("json");
        let legacy_message = Sha256::digest(legacy_json.as_bytes()).to_vec();
        let legacy_sig = MlDsaScheme.sign(&legacy_message, &kp).expect("sign");
        let legacy_tagged = format!("mldsa65:{}", hex::encode(&legacy_sig.bytes));

        // Verify must use the V1 canonical payload — JSON sig must not pass
        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   pk_hex,
            signature:    legacy_tagged,
        };
        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_err(),
            "legacy JSON signature must not pass V1 canonical verification (version isolation)");
    }
}
