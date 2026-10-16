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
//!
//! See `docs/FeeSponsor.md` for the full design.
//!
//! `store` (FS-02) adds persistent SponsorAccount storage, single-use
//! auth_id replay tracking, and revocation on top of these primitives.

pub mod store;

use chain_forge_crypto::{MlDsaScheme, SchemeId, Signature, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// Pre-funded balance available to pay fees on users' behalf.
    pub balance_uqcb: u128,
    /// Policy describing limits and allowed scopes.
    pub policy: SponsorPolicy,
    /// Set by an immediate `revoke()`, or by `revoke_before_block()` to the
    /// batch-revocation cutoff. Any SponsorAuthorization with
    /// `issued_at_block <= revoked_until_block` is rejected (docs/FeeSponsor.md
    /// "Revocation semantics").
    pub revoked_until_block: Option<u64>,
    /// uqcb spent so far in the current epoch; reset by `advance_epoch()`.
    pub epoch_spent_uqcb: u128,
}

impl SponsorAccount {
    pub fn new(sponsor_id: SponsorId, public_key: Vec<u8>, policy: SponsorPolicy) -> Self {
        Self {
            sponsor_id,
            public_key,
            balance_uqcb: 0,
            policy,
            revoked_until_block: None,
            epoch_spent_uqcb: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SponsorPolicy {
    pub per_tx_max_fee_uqcb: u128,
    pub epoch_budget_uqcb: u128,
}

/// 128-bit single-use authorization id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
///
/// This intentionally mirrors `chain_forge_execution::verify_mldsa_authorization`'s
/// `body_json = serde_json::to_string(&tx.body)` convention (plain
/// `serde_json`, no key re-sorting): `#[derive(Serialize)]` on a fixed-schema
/// Rust struct/enum always emits fields in declaration order regardless of
/// platform or build, so this is already deterministic across nodes compiled
/// from the same source -- the same property the executor's tx-signing path
/// already relies on. Using a *different* canonicalization here (e.g.
/// sorting object keys) would make `tx_body_hash` diverge from the hash the
/// executor actually binds signatures to once FS-02 wires this against the
/// real `Transaction`/`TxBody` types, recreating the "circular hash" problem
/// `docs/FeeSponsor.md` section 2 warns about. Keep this function and
/// `verify_mldsa_authorization`'s `body_json` construction in sync.
pub fn canonical_serialize_body<T: Serialize>(body: &T) -> Vec<u8> {
    serde_json::to_vec(body).expect("transaction body always serialises")
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
///
/// Domain separator (matches `docs/FeeSponsor.md`'s execution flow step 3):
///   "qcb/sponsor-auth/v1\n" || chain_id || "\n" || hex(tx_body_hash) || "\n"
///     || hex(auth_id) || "\n" || sponsor_id || "\n" || max_fee_uqcb || "\n"
///     || issued_at_block || "\n" || expires_at_block
///
/// Every field the node checks when validating a SponsorAuthorization is
/// bound into the signed message -- not just `tx_body_hash` -- so a sponsor
/// signature cannot be replayed against a tampered `max_fee_uqcb`,
/// `expires_at_block`, `issued_at_block`, `auth_id`, or `sponsor_id`.
pub fn sponsor_signing_message(
    chain_id: &str,
    tx_body_hash: &[u8; 32],
    auth_id: &AuthId,
    sponsor_id: &SponsorId,
    max_fee_uqcb: u128,
    issued_at_block: u64,
    expires_at_block: u64,
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"qcb/sponsor-auth/v1\n");
    m.extend_from_slice(chain_id.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(hex::encode(tx_body_hash).as_bytes());
    m.push(b'\n');
    m.extend_from_slice(hex::encode(auth_id.0).as_bytes());
    m.push(b'\n');
    m.extend_from_slice(sponsor_id.0.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(max_fee_uqcb.to_string().as_bytes());
    m.push(b'\n');
    m.extend_from_slice(issued_at_block.to_string().as_bytes());
    m.push(b'\n');
    m.extend_from_slice(expires_at_block.to_string().as_bytes());
    m
}

/// Build the signing message for a `SponsorAuthorization` struct directly.
pub fn signing_message_for(auth: &SponsorAuthorization, chain_id: &str) -> Vec<u8> {
    sponsor_signing_message(
        chain_id,
        &auth.tx_body_hash,
        &auth.auth_id,
        &auth.sponsor_id,
        auth.max_fee_uqcb,
        auth.issued_at_block,
        auth.expires_at_block,
    )
}

/// Verify an ML-DSA sponsor signature (expects signature tag "mldsa65:<hex>").
/// The public_key param is raw public key bytes for ML-DSA.
#[allow(clippy::too_many_arguments)]
pub fn verify_sponsor_signature(
    public_key: &[u8],
    chain_id: &str,
    tx_body_hash: &[u8; 32],
    auth_id: &AuthId,
    sponsor_id: &SponsorId,
    max_fee_uqcb: u128,
    issued_at_block: u64,
    expires_at_block: u64,
    signature_tagged: &str,
) -> Result<(), String> {
    if !signature_tagged.starts_with("mldsa65:") {
        return Err("signature tag must be mldsa65:".to_string());
    }
    let hexed = signature_tagged.trim_start_matches("mldsa65:");
    let sig_bytes = hex::decode(hexed).map_err(|e| format!("sig hex decode: {e}"))?;

    let msg = sponsor_signing_message(
        chain_id,
        tx_body_hash,
        auth_id,
        sponsor_id,
        max_fee_uqcb,
        issued_at_block,
        expires_at_block,
    );

    let sig = Signature {
        scheme: SchemeId::MlDsa,
        bytes: sig_bytes,
    };

    MlDsaScheme
        .verify(&msg, &sig, public_key)
        .map_err(|e| format!("ml-dsa verify error: {e}"))
}

/// Verify a `SponsorAuthorization`'s signature against its own fields.
pub fn verify_sponsor_authorization(
    public_key: &[u8],
    chain_id: &str,
    auth: &SponsorAuthorization,
) -> Result<(), String> {
    verify_sponsor_signature(
        public_key,
        chain_id,
        &auth.tx_body_hash,
        &auth.auth_id,
        &auth.sponsor_id,
        auth.max_fee_uqcb,
        auth.issued_at_block,
        auth.expires_at_block,
        &auth.signature,
    )
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

    fn make_auth(body_hash: [u8; 32]) -> SponsorAuthorization {
        SponsorAuthorization {
            auth_id: AuthId([7u8; 16]),
            sponsor_id: SponsorId("sponsor-acme".to_string()),
            tx_body_hash: body_hash,
            max_fee_uqcb: 1_000,
            issued_at_block: 100,
            expires_at_block: 200,
            signature: String::new(),
        }
    }

    fn sign_auth(
        kp: &chain_forge_crypto::KeyPair,
        chain_id: &str,
        auth: &SponsorAuthorization,
    ) -> String {
        let msg = signing_message_for(auth, chain_id);
        let sig = MlDsaScheme.sign(&msg, kp).expect("sign");
        format!("mldsa65:{}", hex::encode(&sig.bytes))
    }

    #[test]
    fn canonical_hash_matches_executor_body_json_convention() {
        // Same field order as declared -> same bytes -> same hash. This is
        // the property verify_mldsa_authorization's body_json relies on.
        let b1 = DummyBody {
            a: 1,
            b: "x".into(),
        };
        let b2 = DummyBody {
            a: 1,
            b: "x".into(),
        };
        assert_eq!(canonical_body_hash(&b1), canonical_body_hash(&b2));
    }

    #[test]
    fn valid_sponsor_signature_verifies() {
        let kp = make_keypair("sponsor-01");
        let body = DummyBody {
            a: 42,
            b: "ok".into(),
        };
        let h = canonical_body_hash(&body);
        let mut auth = make_auth(h);
        auth.signature = sign_auth(&kp, "qcb-testnet-1", &auth);
        assert!(verify_sponsor_authorization(&kp.public_key, "qcb-testnet-1", &auth).is_ok());
    }

    #[test]
    fn tampered_body_hash_rejected() {
        let kp = make_keypair("sponsor-02");
        let body = DummyBody {
            a: 2,
            b: "foo".into(),
        };
        let h = canonical_body_hash(&body);
        let mut auth = make_auth(h);
        auth.signature = sign_auth(&kp, "qcb-testnet-1", &auth);

        // tamper: swap in a different tx_body_hash after signing
        let body2 = DummyBody {
            a: 3,
            b: "foo".into(),
        };
        auth.tx_body_hash = canonical_body_hash(&body2);

        assert!(verify_sponsor_authorization(&kp.public_key, "qcb-testnet-1", &auth).is_err());
    }

    #[test]
    fn tampered_max_fee_rejected() {
        // The signed message must bind max_fee_uqcb, not just tx_body_hash --
        // otherwise a signed authorization could be replayed with a higher
        // sponsor-covered fee than the sponsor actually agreed to.
        let kp = make_keypair("sponsor-02b");
        let body = DummyBody {
            a: 2,
            b: "foo".into(),
        };
        let h = canonical_body_hash(&body);
        let mut auth = make_auth(h);
        auth.signature = sign_auth(&kp, "qcb-testnet-1", &auth);

        auth.max_fee_uqcb = 999_999;

        assert!(verify_sponsor_authorization(&kp.public_key, "qcb-testnet-1", &auth).is_err());
    }

    #[test]
    fn tampered_expiry_rejected() {
        // Similarly, expires_at_block/issued_at_block must be bound so an
        // auth can't be stretched past the window the sponsor actually signed.
        let kp = make_keypair("sponsor-02c");
        let body = DummyBody {
            a: 2,
            b: "foo".into(),
        };
        let h = canonical_body_hash(&body);
        let mut auth = make_auth(h);
        auth.signature = sign_auth(&kp, "qcb-testnet-1", &auth);

        auth.expires_at_block = 999_999;

        assert!(verify_sponsor_authorization(&kp.public_key, "qcb-testnet-1", &auth).is_err());
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let kp = make_keypair("sponsor-03");
        let body = DummyBody {
            a: 7,
            b: "z".into(),
        };
        let h = canonical_body_hash(&body);
        let mut auth = make_auth(h);
        auth.signature = sign_auth(&kp, "qcb-testnet-1", &auth);

        assert!(verify_sponsor_authorization(&kp.public_key, "qcb-mainnet-1", &auth).is_err());
    }

    #[test]
    fn malformed_signature_rejected() {
        let kp = make_keypair("sponsor-04");
        let body = DummyBody {
            a: 8,
            b: "m".into(),
        };
        let h = canonical_body_hash(&body);
        let mut auth = make_auth(h);
        auth.signature = "mldsa65:deadbeef".to_string(); // too short

        assert!(verify_sponsor_authorization(&kp.public_key, "qcb-testnet-1", &auth).is_err());
    }

    #[test]
    fn deterministic_serialization_matches_expected() {
        let body = DummyBody {
            a: 100,
            b: "abc".into(),
        };
        let v = canonical_serialize_body(&body);
        let s = String::from_utf8(v).unwrap();
        assert_eq!(s, "{\"a\":100,\"b\":\"abc\"}");
    }
}
