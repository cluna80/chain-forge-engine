// SPDX-License-Identifier: MIT

//! FeeSponsor cryptographic primitives for FS-01 (cryptographic infrastructure only).
//!
//! This module implements SponsorAccount, SponsorPolicy, SponsorAuthorization,
//! canonical unsigned tx hashing (canonical_body_hash()), ML-DSA domain-separated
//! verification helpers, and unit tests for signature validity, tampering,
//! replay-domain separation, malformed signatures, and deterministic
//! serialization. It intentionally does not implement any persistent state
//! changes, fee charging, or consumed-auth tracking — those are out of scope
//! for FS-01.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use chain_forge_crypto::{SignatureScheme, MlDsaScheme, Signature, SchemeId};

/// Sponsor identifier (reused existing primitive pattern).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SponsorId(pub String);

/// Sponsor account (in-memory representation only; persistent storage deferred
/// to FS-02).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SponsorAccount {
    pub sponsor_id: SponsorId,
    /// Public key bytes (ML-DSA public key expected by convention).
    pub public_key: Vec<u8>,
    /// Policy describing limits and allowed scopes.
    pub policy: SponsorPolicy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SponsorPolicy {
    pub per_tx_max_fee_uqcb: u128,
    pub epoch_budget_uqcb: u128,
}

/// 128-bit single-use authorization id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthId(pub [u8; 16]);

/// SponsorAuthorization structure signed by sponsor's ML-DSA key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SponsorAuthorization {
    pub auth_id: AuthId,
    pub sponsor_id: SponsorId,
    pub tx_body_hash: [u8; 32],
    pub max_fee_uqcb: u128,
    pub issued_at_block: u64,
    pub expires_at_block: u64,
    pub signature: String, // mldsa65:<hex>
}

/// Compute the canonical serialization of an unsigned transaction body.
/// For FS-01 we define a minimal canonicalization used in tests: JSON with
/// sorted object keys and no extra whitespace. In the real engine this must
/// match the canonical serialization used by the executor.
pub fn canonical_serialize_body<T: Serialize>(body: &T) -> Vec<u8> {
    // serde_json does not guarantee key order; use serde_json::to_value +
    // sorting when object.
    let v = serde_json::to_value(body).expect("serialize body");
    let sorted = sort_json_value(&v);
    serde_json::to_vec(&sorted).expect("to_vec")
}

fn sort_json_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut obj = serde_json::Map::new();
            for k in keys {
                obj.insert(k.clone(), sort_json_value(&map[&k]));
            }
            serde_json::Value::Object(obj)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_value).collect())
        }
        other => other.clone(),
    }
}

/// Compute the canonical body hash: SHA256(canonical_serialize_body(body)).
pub fn canonical_body_hash<T: Serialize>(body: &T) -> [u8; 32] {
    let bytes = canonical_serialize_body(body);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let res = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res[..]);
    out
}

/// Build the ML-DSA signing message for SponsorAuthorization verification.
/// Domain separator: "qcb/sponsor-auth/v1\n" || chain_id || "\n" || hex(tx_body_hash)
pub fn sponsor_signing_message(chain_id: &str, tx_body_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"qcb/sponsor-auth/v1\n");
    m.extend_from_slice(chain_id.as_bytes());
    m.extend_from_slice(b"\n");
    m.extend_from_slice(hex::encode(tx_body_hash).as_bytes());
    m
}

/// Verify an ML-DSA sponsor signature (expects signature tag "mldsa65:<hex>").
/// The public_key param is raw public key bytes for ML-DSA.
pub fn verify_sponsor_signature(
    public_key: &[u8],
    chain_id: &str,
    tx_body_hash: &[u8; 32],
    signature_tagged: &str,
) -> Result<(), String> {
    if !signature_tagged.starts_with("mldsa65:") {
        return Err("signature tag must be mldsa65:".to_string());
    }
    let hexed = signature_tagged.trim_start_matches("mldsa65:");
    let sig_bytes = hex::decode(hexed).map_err(|e| format!("sig hex decode: {e}"))?;

    // Build message
    let msg = sponsor_signing_message(chain_id, tx_body_hash);

    let sig = Signature { scheme: SchemeId::MlDsa, bytes: sig_bytes };

    MlDsaScheme.verify(&msg, &sig, public_key)
        .map_err(|e| format!("ml-dsa verify error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

    #[derive(Serialize)]
    struct DummyBody {
        a: u64,
        b: String,
    }

    fn make_keypair(label: &str) -> chain_forge_crypto::KeyPair {
        MlDsaScheme.generate_keypair(label).expect("keygen")
    }

    fn sign_sponsor_auth(
        kp: &chain_forge_crypto::KeyPair,
        chain_id: &str,
        body_hash: &[u8; 32],
    ) -> String {
        let msg = sponsor_signing_message(chain_id, body_hash);
        let sig = MlDsaScheme.sign(&msg, kp).expect("sign");
        format!("mldsa65:{}", hex::encode(&sig.bytes))
    }

    #[test]
    fn canonical_hash_deterministic() {
        let b1 = DummyBody { a: 1, b: "x".into() };
        let b2 = DummyBody { b: "x".into(), a: 1 };
        let h1 = canonical_body_hash(&b1);
        let h2 = canonical_body_hash(&b2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn valid_sponsor_signature_verifies() {
        let kp = make_keypair("sponsor-01");
        let body = DummyBody { a: 42, b: "ok".into() };
        let h = canonical_body_hash(&body);
        let tag = sign_sponsor_auth(&kp, "qcb-testnet-1", &h);
        assert!(verify_sponsor_signature(&kp.public_key, "qcb-testnet-1", &h, &tag).is_ok());
    }

    #[test]
    fn tampered_body_rejected() {
        let kp = make_keypair("sponsor-02");
        let body = DummyBody { a: 2, b: "foo".into() };
        let h = canonical_body_hash(&body);
        let tag = sign_sponsor_auth(&kp, "qcb-testnet-1", &h);

        // tamper: compute different hash
        let body2 = DummyBody { a: 3, b: "foo".into() };
        let h2 = canonical_body_hash(&body2);

        let res = verify_sponsor_signature(&kp.public_key, "qcb-testnet-1", &h2, &tag);
        assert!(res.is_err());
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let kp = make_keypair("sponsor-03");
        let body = DummyBody { a: 7, b: "z".into() };
        let h = canonical_body_hash(&body);
        let tag = sign_sponsor_auth(&kp, "qcb-testnet-1", &h);

        let res = verify_sponsor_signature(&kp.public_key, "qcb-mainnet-1", &h, &tag);
        assert!(res.is_err());
    }

    #[test]
    fn malformed_signature_rejected() {
        let kp = make_keypair("sponsor-04");
        let body = DummyBody { a: 8, b: "m".into() };
        let h = canonical_body_hash(&body);
        let bad = "mldsa65:deadbeef"; // too short
        let res = verify_sponsor_signature(&kp.public_key, "qcb-testnet-1", &h, bad);
        assert!(res.is_err());
    }

    #[test]
    fn deterministic_serialization_matches_expected() {
        let body = DummyBody { a: 100, b: "abc".into() };
        let v = canonical_serialize_body(&body);
        // ensure keys sorted and no spaces
        let s = String::from_utf8(v).unwrap();
        assert_eq!(s, "{\"a\":100,\"b\":\"abc\"}");
    }
}
