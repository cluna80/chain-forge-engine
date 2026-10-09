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
///
/// Phase A scope: challenge issuance + ML-DSA-65 signature verification.
/// Phase B (ZK layer) will add selective disclosure so verifiers learn
/// only what the user authorises, without seeing which identity signed.

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

/// A time-bounded authentication challenge issued by the node.
///
/// The challenge_id is opaque to the wallet; the wallet signs the full
/// `ChallengePayload` (id + issued_at + expires_at + node_id) so the
/// signature covers the temporal and node context, not just a random nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Unique challenge identifier (UUID-like hex string, 32 chars)
    pub challenge_id: String,
    /// Unix timestamp (seconds) when challenge was issued
    pub issued_at: u64,
    /// Unix timestamp (seconds) after which the challenge is invalid
    pub expires_at: u64,
    /// Node identifier (validator address of the issuing node)
    pub node_id: String,
    /// Human-readable scope hint (e.g. "qcb-auth", "wallet-login")
    pub scope: String,
}

impl AuthChallenge {
    /// Create a new challenge expiring at now + TTL.
    pub fn new(node_id: &str, scope: &str) -> Self {
        let now = unix_now();
        let id = generate_challenge_id(now);
        Self {
            challenge_id: id,
            issued_at:    now,
            expires_at:   now + AUTH_CHALLENGE_TTL_SECS,
            node_id:      node_id.to_string(),
            scope:        scope.to_string(),
        }
    }

    pub fn is_expired(&self) -> bool {
        unix_now() >= self.expires_at
    }

    /// The canonical bytes the wallet must sign (deterministic JSON of the
    /// challenge fields, no whitespace). This is SHA-256-pre-hashed by the
    /// wallet's sign_challenge() exactly as sign_transaction hashes tx bodies.
    pub fn signing_payload(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Request body for POST /api/auth/challenge
#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    /// Scope hint from the client: "qcb-auth", "wallet-login", etc.
    /// Arbitrary string; Phase A treats all scopes identically.
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String { "qcb-auth".to_string() }

/// Request body for POST /api/auth/verify
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The challenge_id from the ChallengeRequest response
    pub challenge_id: String,
    /// ML-DSA-65 public key (hex, 1952 bytes = 3904 hex chars)
    pub public_key: String,
    /// ML-DSA-65 signature over SHA-256(challenge.signing_payload()),
    /// tagged "mldsa65:<hex>" (same convention as SignedTxEnvelope)
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
}

/// In-memory store for pending challenges.
/// Backed by a `HashMap<challenge_id, AuthChallenge>` inside an `Arc<Mutex<>>`.
/// The store is threaded through the API server task like the tx_queue.
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
    /// Consumed challenges cannot be replayed.
    pub fn consume(&mut self, id: &str) -> Option<AuthChallenge> {
        // Remove-and-check to consume atomically
        let ch = self.challenges.remove(id)?;
        if ch.is_expired() { return None; }
        Some(ch)
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

/// Deterministic-enough challenge ID: hex(sha256(now_ms || counter)).
/// Not a UUID but opaque enough for Phase A devnet; Phase E will review.
fn generate_challenge_id(seed: u64) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let input = format!("{seed}:{count}");

    // SHA-256 of "timestamp:counter" → take first 16 bytes as hex (32 chars)
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(&hash[..16])
}

// ─── ML-DSA-65 signature verification ───────────────────────────────────────

/// Verify an ML-DSA-65 signature over a challenge's signing payload.
///
/// The signature field must be tagged "mldsa65:<hex>" (same convention as
/// signed transactions). The public key is provided raw (untagged hex).
///
/// Returns Ok(address) on success, where address is the qcb1pq… address
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

    // 3. Reconstruct the signing payload (same as what wallet signed)
    //    Wallet: SHA-256(payload_json) then ML-DSA-sign(hash_bytes)
    let payload = challenge.signing_payload();
    let message = {
        use sha2::{Sha256, Digest};
        Sha256::digest(payload.as_bytes()).to_vec()
    };

    // 4. Verify using MlDsaScheme (same path as chain-forge-execution)
    let sig = Signature {
        scheme: SchemeId::MlDsa,
        bytes:  sig_bytes,
    };
    MlDsaScheme.verify(&message, &sig, &pk_bytes)
        .map_err(|e| format!("ML-DSA-65 verification failed: {e}"))?;

    // 5. Derive address from the verified public key (qcb1pq… namespace)
    let address = pq_address_from_key(&pk_bytes);

    Ok(address)
}

/// Derive a QCB post-quantum address from an ML-DSA-65 public key.
/// Format: "qcb1pq" + hex(SHA-256(SHA-256(public_key))[..20])
/// Matches the derivation in chain-forge-wallet::derive_address_from_pq_key.
fn pq_address_from_key(public_key: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let h1 = Sha256::digest(public_key);
    let h2 = Sha256::digest(h1);
    format!("qcb1pq{}", hex::encode(&h2[..20]))
}

// ─── unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_has_correct_ttl() {
        let ch = AuthChallenge::new("qcb1alice", "qcb-auth");
        let now = unix_now();
        assert!(ch.expires_at >= now + AUTH_CHALLENGE_TTL_SECS - 1);
        assert!(ch.expires_at <= now + AUTH_CHALLENGE_TTL_SECS + 1);
        assert!(!ch.is_expired());
    }

    #[test]
    fn challenge_id_is_32_hex_chars() {
        let ch = AuthChallenge::new("qcb1alice", "qcb-auth");
        assert_eq!(ch.challenge_id.len(), 32);
        assert!(ch.challenge_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn two_challenges_have_different_ids() {
        let c1 = AuthChallenge::new("node", "auth");
        let c2 = AuthChallenge::new("node", "auth");
        assert_ne!(c1.challenge_id, c2.challenge_id);
    }

    #[test]
    fn store_consume_returns_none_for_unknown_id() {
        let mut store = ChallengeStore::new();
        assert!(store.consume("nonexistent").is_none());
    }

    #[test]
    fn store_consume_removes_challenge_preventing_replay() {
        let mut store = ChallengeStore::new();
        let ch = AuthChallenge::new("node", "auth");
        let id = ch.challenge_id.clone();
        store.insert(ch);
        // First consume succeeds
        assert!(store.consume(&id).is_some());
        // Second consume fails (anti-replay)
        assert!(store.consume(&id).is_none());
    }

    #[test]
    fn store_evicts_at_capacity() {
        let mut store = ChallengeStore::new();
        // Fill to max
        for _ in 0..MAX_PENDING_CHALLENGES {
            store.insert(AuthChallenge::new("node", "auth"));
        }
        assert!(store.challenges.len() <= MAX_PENDING_CHALLENGES);
        // Add one more — should still be at or below cap
        store.insert(AuthChallenge::new("node", "auth"));
        assert!(store.challenges.len() <= MAX_PENDING_CHALLENGES);
    }

    #[test]
    fn signing_payload_is_valid_json() {
        let ch = AuthChallenge::new("qcb1test", "qcb-auth");
        let payload = ch.signing_payload();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["challenge_id"].as_str().unwrap(), ch.challenge_id);
        assert_eq!(parsed["scope"].as_str().unwrap(), "qcb-auth");
    }

    #[test]
    fn challenge_request_defaults_scope() {
        let req: ChallengeRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(req.scope, "qcb-auth");
    }

    #[test]
    fn verify_request_rejects_untagged_signature() {
        let ch = AuthChallenge::new("node", "auth");
        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   "aa".repeat(1952),
            signature:    "deadbeef".to_string(), // missing mldsa65: prefix
        };
        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tagged 'mldsa65:"));
    }

    #[test]
    fn verify_request_rejects_wrong_pk_length() {
        let ch = AuthChallenge::new("node", "auth");
        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   "deadbeef".to_string(), // too short
            signature:    "mldsa65:aabb".to_string(),
        };
        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("1952 bytes"));
    }

    /// Sign a challenge payload with an ML-DSA keypair (test helper).
    /// Matches the path chain-forge-wallet::sign_challenge will use:
    /// SHA-256(payload_json) → ML-DSA-sign(hash_bytes)
    fn sign_challenge_payload(
        payload: &str,
        kp: &chain_forge_crypto::KeyPair,
    ) -> String {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};
        use sha2::{Sha256, Digest};
        let message = Sha256::digest(payload.as_bytes()).to_vec();
        let sig = MlDsaScheme.sign(&message, kp).expect("signing");
        format!("mldsa65:{}", hex::encode(&sig.bytes))
    }

    /// Full round-trip: generate a real ML-DSA-65 keypair, sign a challenge,
    /// verify it — confirms the auth flow works end-to-end.
    #[test]
    fn full_roundtrip_sign_and_verify_challenge() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let kp = MlDsaScheme.generate_keypair("test-roundtrip").expect("keygen");
        let pk_hex = hex::encode(&kp.public_key);

        let ch = AuthChallenge::new("qcb1alice", "qcb-auth");
        let payload = ch.signing_payload();
        let sig_tagged = sign_challenge_payload(&payload, &kp);

        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   pk_hex,
            signature:    sig_tagged,
        };

        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_ok(), "verification failed: {:?}", result);

        let address = result.unwrap();
        assert!(address.starts_with("qcb1pq"), "unexpected address prefix: {address}");
    }

    /// Forged signature must be rejected.
    #[test]
    fn forged_signature_rejected() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let kp = MlDsaScheme.generate_keypair("test-forge").expect("keygen");
        let pk_hex = hex::encode(&kp.public_key);

        let ch = AuthChallenge::new("node", "auth");

        // Forge a signature (random bytes at correct length)
        let forged_bytes = vec![0xDE_u8; 3309];
        let forged_sig = format!("mldsa65:{}", hex::encode(&forged_bytes));

        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   pk_hex,
            signature:    forged_sig,
        };
        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_err(), "forged signature should be rejected");
    }

    /// Wrong-key signature must be rejected.
    #[test]
    fn wrong_key_rejected() {
        use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

        let kp1 = MlDsaScheme.generate_keypair("test-key1").expect("keygen1");
        let kp2 = MlDsaScheme.generate_keypair("test-key2").expect("keygen2");
        let pk1_hex = hex::encode(&kp1.public_key);

        let ch = AuthChallenge::new("node", "auth");
        let payload = ch.signing_payload();

        // Sign with kp2 but verify against kp1's public key
        let sig_tagged = sign_challenge_payload(&payload, &kp2);

        let req = VerifyRequest {
            challenge_id: ch.challenge_id.clone(),
            public_key:   pk1_hex,
            signature:    sig_tagged,
        };
        let result = verify_challenge_signature(&ch, &req);
        assert!(result.is_err(), "wrong-key signature should be rejected");
    }
}
