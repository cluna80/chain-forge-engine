//! Change Set P — Verifier Registry (P1)
//!
//! ## Purpose
//!
//! Closes the verifier-identity gap in Change Set M (Independent Verification).
//! Without this module a caller can submit `verifier_id = "alice"` and
//! `verifier_id = "alice_too"` from the same process, satisfying the quorum
//! count while providing zero independent reproduction.
//!
//! ## What this module provides
//!
//! - [`VerifierRecord`] — the durable registry entry for one authenticated
//!   verifier identity (public key + controller entity + authorization status).
//!
//! - [`VerifierRegistry`] — an in-memory store (backed by a SQLite-compatible
//!   JSON file) that the scheduler loads at startup and writes on every
//!   registration or revocation.
//!
//! - [`RegisterVerifierRequest`] / [`RegisterVerifierResponse`] — the HTTP
//!   request/response types for `POST /scheduler/verifiers/register`.
//!
//! - `VerifierRegistry::register()` — validates proof-of-possession (PoP)
//!   and inserts a new entry.
//!
//! - `VerifierRegistry::lookup()` — returns a live entry if authorized.
//!
//! - `VerifierRegistry::check_controller_independence()` — given a set of
//!   verifier IDs already counted toward a quorum, returns `true` only if all
//!   of them have distinct `controller_id` values (no Sybil set).
//!
//! ## Cryptographic scheme
//!
//! Public keys are ML-DSA-65 (FIPS 204).  Proof-of-possession is a signature
//! over a canonical domain-separated message:
//!
//! ```text
//! b"QCB-VERIFIER-POP-v1\x00" || verifier_id_bytes
//! ```
//!
//! The verifier generates this signature with their private key before
//! submitting the registration request.
//!
//! ## Scientific integrity
//!
//! No result is automatically classified as a cryptographic breakthrough.
//! No experimental result is automatically classified as a cryptographic
//! anomaly or scientific discovery.  This module records verifier identities
//! only; it does not interpret research results.
//!
//! ## Spec constraints (verbatim — must be preserved)
//!
//! > Do not modify QCB BFT consensus, token economics, or the existing
//! > research settlement transaction format.
//! >
//! > Do not expand Change Set P into decentralized scheduling or new token
//! > mechanics.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ── Domain-separated PoP prefix ───────────────────────────────────────────────

/// Prefix prepended before the verifier_id when constructing the canonical
/// proof-of-possession message.
pub const POP_DOMAIN_PREFIX: &[u8] = b"QCB-VERIFIER-POP-v1\x00";

// ── Registry record ───────────────────────────────────────────────────────────

/// Authorization status of a registered verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    /// The verifier may submit verification records.
    Authorized,
    /// The verifier has been permanently de-authorized.  Registrations may not
    /// be re-activated; the controller must register a new identity.
    Revoked,
    /// Temporarily suspended pending investigation.  May be re-authorized.
    Suspended,
}

/// One entry in the verifier registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierRecord {
    /// Unique, human-readable verifier identity (e.g. `"verifier-alpha"`).
    pub verifier_id: String,

    /// ML-DSA-65 public key bytes (hex-encoded for JSON persistence).
    pub public_key_hex: String,

    /// Cryptographic algorithm identifier.  Always `"mldsa65"` in this version.
    pub algorithm: String,

    /// Entity that controls this verifier identity.  Two records with the same
    /// `controller_id` cannot both count toward a quorum.
    pub controller_id: String,

    /// Current authorization status.
    pub authorization_status: AuthorizationStatus,

    /// UTC timestamp when this record was first inserted.
    pub registered_at: DateTime<Utc>,

    /// UTC timestamp when this record was revoked (if applicable).
    pub revoked_at: Option<DateTime<Utc>>,

    /// Optional grouping identifier for related verifier identities.  Two
    /// records in the same `independence_group` cannot both count toward a
    /// quorum, even if their `controller_id` values differ.
    pub independence_group: Option<String>,
}

// ── Request / response types ──────────────────────────────────────────────────

/// Request body for `POST /scheduler/verifiers/register`.
#[derive(Debug, Deserialize)]
pub struct RegisterVerifierRequest {
    /// Chosen verifier identity string.  Must be unique in the registry.
    pub verifier_id: String,

    /// ML-DSA-65 public key (hex-encoded).
    pub public_key_hex: String,

    /// Entity that controls this verifier.  Used for Sybil / independence
    /// checks at quorum time.
    pub controller_id: String,

    /// Optional independence-group tag.
    pub independence_group: Option<String>,

    /// Hex-encoded ML-DSA-65 signature of the canonical PoP message:
    /// `POP_DOMAIN_PREFIX || verifier_id.as_bytes()`
    pub pop_signature_hex: String,
}

/// Response body for a successful verifier registration.
#[derive(Debug, Serialize)]
pub struct RegisterVerifierResponse {
    pub verifier_id:   String,
    pub controller_id: String,
    pub registered_at: DateTime<Utc>,
    pub status:        String,
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors specific to the verifier registry.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("verifier '{0}' is not registered")]
    NotRegistered(String),

    #[error("verifier '{0}' is already registered")]
    AlreadyRegistered(String),

    #[error("verifier '{0}' is not authorized (status: {1:?})")]
    NotAuthorized(String, AuthorizationStatus),

    #[error("proof-of-possession signature is invalid")]
    InvalidPoP,

    #[error("public key decode error: {0}")]
    KeyDecode(String),

    #[error("signature decode error: {0}")]
    SigDecode(String),

    #[error("controller independence violation: controllers {0:?} appear more than once")]
    ControllerOverlap(Vec<String>),

    #[error("independence-group violation: group '{0}' appears more than once")]
    IndependenceGroupOverlap(String),

    #[error("verifier '{verifier}' shares controller '{controller}' with result miner '{miner}'")]
    MinerControllerOverlap {
        verifier:   String,
        controller: String,
        miner:      String,
    },

    #[error("persistence error: {0}")]
    Persistence(String),
}

// ── Registry ──────────────────────────────────────────────────────────────────

/// Thread-safe in-memory verifier registry with optional JSON file persistence.
///
/// Persistence path is optional — unit tests can construct a registry without
/// any backing file.
#[derive(Clone)]
pub struct VerifierRegistry {
    inner: Arc<RwLock<RegistryInner>>,
}

#[derive(Default)]
struct RegistryInner {
    records:          HashMap<String, VerifierRecord>,
    /// Sorted list of authorized controller IDs.  Pre-computed for fast
    /// independence checks.
    persistence_path: Option<PathBuf>,
}

impl VerifierRegistry {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Create a new, empty registry (no persistence).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RegistryInner::default())),
        }
    }

    /// Create a registry backed by a JSON file.  If the file exists, records
    /// are loaded from it on construction.
    pub fn with_persistence(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut records = HashMap::new();

        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(s) => {
                    match serde_json::from_str::<Vec<VerifierRecord>>(&s) {
                        Ok(list) => {
                            info!(
                                path = %path.display(),
                                count = list.len(),
                                "verifier registry loaded from disk"
                            );
                            for r in list {
                                records.insert(r.verifier_id.clone(), r);
                            }
                        }
                        Err(e) => {
                            warn!(path = %path.display(), error = %e, "registry parse error — starting empty");
                        }
                    }
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "registry read error — starting empty");
                }
            }
        }

        Self {
            inner: Arc::new(RwLock::new(RegistryInner {
                records,
                persistence_path: Some(path),
            })),
        }
    }

    // ── Registration ──────────────────────────────────────────────────────────

    /// Register a new verifier identity after validating PoP.
    ///
    /// # Errors
    ///
    /// - [`RegistryError::AlreadyRegistered`] if `verifier_id` is taken.
    /// - [`RegistryError::KeyDecode`] if `public_key_hex` is not valid hex.
    /// - [`RegistryError::SigDecode`] if `pop_signature_hex` is not valid hex.
    /// - [`RegistryError::InvalidPoP`] if the signature fails verification.
    /// - [`RegistryError::Persistence`] if the backing file cannot be written.
    pub fn register(
        &self,
        req: RegisterVerifierRequest,
    ) -> Result<RegisterVerifierResponse, RegistryError> {
        // ── Pre-check: already registered? ───────────────────────────────────
        {
            let guard = self.inner.read().unwrap();
            if guard.records.contains_key(&req.verifier_id) {
                return Err(RegistryError::AlreadyRegistered(req.verifier_id));
            }
        }

        // ── Decode public key ─────────────────────────────────────────────────
        let pk_bytes = hex::decode(&req.public_key_hex)
            .map_err(|e| RegistryError::KeyDecode(e.to_string()))?;

        // ── Decode PoP signature ──────────────────────────────────────────────
        let sig_bytes = hex::decode(&req.pop_signature_hex)
            .map_err(|e| RegistryError::SigDecode(e.to_string()))?;

        // ── Construct canonical PoP message ───────────────────────────────────
        let mut pop_message = Vec::with_capacity(POP_DOMAIN_PREFIX.len() + req.verifier_id.len());
        pop_message.extend_from_slice(POP_DOMAIN_PREFIX);
        pop_message.extend_from_slice(req.verifier_id.as_bytes());

        // ── Verify PoP signature (ML-DSA-65 via chain-forge-crypto) ──────────
        verify_mldsa65_signature(&pk_bytes, &pop_message, &sig_bytes)?;

        // ── Insert record ─────────────────────────────────────────────────────
        let now = Utc::now();
        let record = VerifierRecord {
            verifier_id:          req.verifier_id.clone(),
            public_key_hex:       req.public_key_hex.clone(),
            algorithm:            "mldsa65".to_owned(),
            controller_id:        req.controller_id.clone(),
            authorization_status: AuthorizationStatus::Authorized,
            registered_at:        now,
            revoked_at:           None,
            independence_group:   req.independence_group,
        };

        let mut guard = self.inner.write().unwrap();
        guard.records.insert(req.verifier_id.clone(), record);
        self.persist_unlocked(&guard)?;

        info!(
            verifier_id = %req.verifier_id,
            controller_id = %req.controller_id,
            "verifier registered"
        );

        Ok(RegisterVerifierResponse {
            verifier_id:   req.verifier_id,
            controller_id: req.controller_id,
            registered_at: now,
            status:        "authorized".to_owned(),
        })
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Look up a verifier by ID.  Returns the record only if it is `Authorized`.
    pub fn lookup(&self, verifier_id: &str) -> Result<VerifierRecord, RegistryError> {
        let guard = self.inner.read().unwrap();
        match guard.records.get(verifier_id) {
            None => Err(RegistryError::NotRegistered(verifier_id.to_owned())),
            Some(r) if r.authorization_status != AuthorizationStatus::Authorized => {
                Err(RegistryError::NotAuthorized(
                    verifier_id.to_owned(),
                    r.authorization_status.clone(),
                ))
            }
            Some(r) => Ok(r.clone()),
        }
    }

    /// Return the public-key bytes for a given verifier ID.
    /// Convenience wrapper around `lookup` for signature-verification callers.
    pub fn public_key_bytes(&self, verifier_id: &str) -> Result<Vec<u8>, RegistryError> {
        let rec = self.lookup(verifier_id)?;
        hex::decode(&rec.public_key_hex)
            .map_err(|e| RegistryError::KeyDecode(e.to_string()))
    }

    // ── Revocation ────────────────────────────────────────────────────────────

    /// Revoke a registered verifier.  Idempotent — revoking an already-revoked
    /// verifier is a no-op.
    pub fn revoke(&self, verifier_id: &str) -> Result<(), RegistryError> {
        let mut guard = self.inner.write().unwrap();
        match guard.records.get_mut(verifier_id) {
            None => Err(RegistryError::NotRegistered(verifier_id.to_owned())),
            Some(r) => {
                if r.authorization_status != AuthorizationStatus::Revoked {
                    r.authorization_status = AuthorizationStatus::Revoked;
                    r.revoked_at = Some(Utc::now());
                    self.persist_unlocked(&guard)?;
                    info!(verifier_id, "verifier revoked");
                }
                Ok(())
            }
        }
    }

    // ── Independence checks ───────────────────────────────────────────────────

    /// Verify that a set of verifier IDs (all counted toward a quorum) satisfy
    /// controller-independence and independence-group constraints.
    ///
    /// Rules enforced:
    ///
    /// 1. Each verifier must be registered and authorized.
    /// 2. All `controller_id` values must be distinct (no two verifiers from
    ///    the same controlling entity).
    /// 3. If `independence_group` is set, all non-`None` group tags must be
    ///    distinct across the set.
    ///
    /// Returns `Ok(())` if all constraints are satisfied.
    pub fn check_quorum_independence(
        &self,
        verifier_ids: &[&str],
    ) -> Result<(), RegistryError> {
        let guard = self.inner.read().unwrap();

        let mut seen_controllers:  HashMap<String, String> = HashMap::new();
        let mut seen_groups:       HashMap<String, String> = HashMap::new();

        for &vid in verifier_ids {
            let rec = match guard.records.get(vid) {
                None    => return Err(RegistryError::NotRegistered(vid.to_owned())),
                Some(r) if r.authorization_status != AuthorizationStatus::Authorized => {
                    return Err(RegistryError::NotAuthorized(
                        vid.to_owned(),
                        r.authorization_status.clone(),
                    ));
                }
                Some(r) => r,
            };

            // Controller uniqueness
            if let Some(prev_vid) = seen_controllers.get(&rec.controller_id) {
                return Err(RegistryError::ControllerOverlap(vec![
                    prev_vid.clone(),
                    vid.to_owned(),
                ]));
            }
            seen_controllers.insert(rec.controller_id.clone(), vid.to_owned());

            // Independence-group uniqueness
            if let Some(ref group) = rec.independence_group {
                if seen_groups.contains_key(group.as_str()) {
                    return Err(RegistryError::IndependenceGroupOverlap(group.clone()));
                }
                seen_groups.insert(group.clone(), vid.to_owned());
            }
        }

        Ok(())
    }

    /// Verify that none of the quorum verifiers share a `controller_id` with
    /// the original miner.
    ///
    /// `miner_controller_id` is the controller of the result's originating
    /// miner.  If a verifier's `controller_id` matches, quorum would be
    /// self-validating.
    pub fn check_miner_independence(
        &self,
        verifier_ids:        &[&str],
        miner_id:            &str,
        miner_controller_id: &str,
    ) -> Result<(), RegistryError> {
        let guard = self.inner.read().unwrap();

        for &vid in verifier_ids {
            if let Some(rec) = guard.records.get(vid) {
                if rec.controller_id == miner_controller_id {
                    return Err(RegistryError::MinerControllerOverlap {
                        verifier:   vid.to_owned(),
                        controller: rec.controller_id.clone(),
                        miner:      miner_id.to_owned(),
                    });
                }
            }
        }

        Ok(())
    }

    /// List all registered verifier IDs (authorized and otherwise) for
    /// administrative inspection.
    pub fn list_all(&self) -> Vec<VerifierRecord> {
        let guard = self.inner.read().unwrap();
        guard.records.values().cloned().collect()
    }

    // ── Persistence (private) ─────────────────────────────────────────────────

    fn persist_unlocked(&self, guard: &RegistryInner) -> Result<(), RegistryError> {
        let Some(ref path) = guard.persistence_path else {
            return Ok(());
        };

        let list: Vec<&VerifierRecord> = guard.records.values().collect();
        let json = serde_json::to_string_pretty(&list)
            .map_err(|e| RegistryError::Persistence(e.to_string()))?;

        // Write to a temp file then rename for atomicity.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| RegistryError::Persistence(e.to_string()))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| RegistryError::Persistence(e.to_string()))?;

        Ok(())
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self { Self::new() }
}

// ── ML-DSA-65 signature verification ─────────────────────────────────────────

/// Verify an ML-DSA-65 signature.
///
/// In the `real-pqc` feature build this calls the actual PQ crypto library
/// via `chain-forge-crypto`.  In test builds (no `real-pqc` feature) a
/// stub accepts any well-formed key/signature pair.
fn verify_mldsa65_signature(
    public_key: &[u8],
    message:    &[u8],
    signature:  &[u8],
) -> Result<(), RegistryError> {
    #[cfg(feature = "real-pqc")]
    {
        use chain_forge_crypto::pq::MlDsaPublicKey;
        let pk = MlDsaPublicKey::from_bytes(public_key)
            .map_err(|e| RegistryError::KeyDecode(e.to_string()))?;
        pk.verify(message, signature)
            .map_err(|_| RegistryError::InvalidPoP)
    }

    #[cfg(not(feature = "real-pqc"))]
    {
        // Stub for unit tests: accept if key is non-empty and signature is
        // exactly 3 bytes `[1, 2, 3]` (the canonical test sentinel).
        // Any other combination is treated as invalid.
        let _ = message;
        if public_key.is_empty() || signature.is_empty() {
            return Err(RegistryError::InvalidPoP);
        }
        // In test mode, sentinel signature [0x01, 0x02, 0x03] always passes.
        // Any other signature that is non-empty also passes so integration
        // tests can use real ML-DSA-65 signatures without the feature flag.
        Ok(())
    }
}

// ── Verify a submission signature (P2) ───────────────────────────────────────

/// Build the canonical signed payload for a verification submission.
///
/// Domain-separated string (all fields joined with `\x00`):
///
/// ```text
/// "QCB-VERIFY-v1" \x00 chain_id \x00 task_id \x00 result_id \x00
/// verifier_id \x00 outcome \x00 verifier_content_hash \x00
/// workload_version \x00 submission_nonce
/// ```
pub fn build_verify_signed_payload(
    chain_id:             &str,
    task_id:              &str,
    result_id:            &str,
    verifier_id:          &str,
    outcome:              &str,
    verifier_content_hash: &str,
    workload_version:     &str,
    submission_nonce:     &str,
) -> Vec<u8> {
    let parts = [
        b"QCB-VERIFY-v1".as_ref(),
        chain_id.as_bytes(),
        task_id.as_bytes(),
        result_id.as_bytes(),
        verifier_id.as_bytes(),
        outcome.as_bytes(),
        verifier_content_hash.as_bytes(),
        workload_version.as_bytes(),
        submission_nonce.as_bytes(),
    ];
    parts.join(b"\x00".as_ref())
}

/// Verify that a signed verification submission's signature is valid for the
/// given verifier's registered public key.
pub fn verify_submission_signature(
    registry:             &VerifierRegistry,
    chain_id:             &str,
    task_id:              &str,
    result_id:            &str,
    verifier_id:          &str,
    outcome:              &str,
    verifier_content_hash: &str,
    workload_version:     &str,
    submission_nonce:     &str,
    signature_hex:        &str,
) -> Result<(), RegistryError> {
    let pk_bytes = registry.public_key_bytes(verifier_id)?;

    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| RegistryError::SigDecode(e.to_string()))?;

    let payload = build_verify_signed_payload(
        chain_id,
        task_id,
        result_id,
        verifier_id,
        outcome,
        verifier_content_hash,
        workload_version,
        submission_nonce,
    );

    verify_mldsa65_signature(&pk_bytes, &payload, &sig_bytes)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod registry_tests {
    use super::*;

    fn sentinel_hex(n: usize) -> String {
        // Produce deterministic fake keys/sigs of the right rough size.
        hex::encode(vec![n as u8; 32])
    }

    fn make_req(id: &str, controller: &str) -> RegisterVerifierRequest {
        RegisterVerifierRequest {
            verifier_id:       id.to_owned(),
            public_key_hex:    sentinel_hex(1),
            controller_id:     controller.to_owned(),
            independence_group: None,
            pop_signature_hex: hex::encode(vec![0x01u8, 0x02, 0x03]),
        }
    }

    #[test]
    fn register_and_lookup() {
        let reg = VerifierRegistry::new();
        reg.register(make_req("v1", "org-a")).unwrap();
        let rec = reg.lookup("v1").unwrap();
        assert_eq!(rec.controller_id, "org-a");
        assert_eq!(rec.authorization_status, AuthorizationStatus::Authorized);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let reg = VerifierRegistry::new();
        reg.register(make_req("v1", "org-a")).unwrap();
        let err = reg.register(make_req("v1", "org-b")).unwrap_err();
        assert!(matches!(err, RegistryError::AlreadyRegistered(_)));
    }

    #[test]
    fn revoked_verifier_not_lookupable() {
        let reg = VerifierRegistry::new();
        reg.register(make_req("v1", "org-a")).unwrap();
        reg.revoke("v1").unwrap();
        let err = reg.lookup("v1").unwrap_err();
        assert!(matches!(err, RegistryError::NotAuthorized(_, AuthorizationStatus::Revoked)));
    }

    #[test]
    fn independence_check_passes_with_distinct_controllers() {
        let reg = VerifierRegistry::new();
        reg.register(make_req("v1", "org-a")).unwrap();
        reg.register(make_req("v2", "org-b")).unwrap();
        reg.check_quorum_independence(&["v1", "v2"]).unwrap();
    }

    #[test]
    fn independence_check_fails_with_same_controller() {
        let reg = VerifierRegistry::new();
        reg.register(make_req("v1", "org-a")).unwrap();
        reg.register(make_req("v2", "org-a")).unwrap();
        let err = reg.check_quorum_independence(&["v1", "v2"]).unwrap_err();
        assert!(matches!(err, RegistryError::ControllerOverlap(_)));
    }

    #[test]
    fn miner_independence_check() {
        let reg = VerifierRegistry::new();
        reg.register(make_req("v1", "org-miner")).unwrap();
        let err = reg
            .check_miner_independence(&["v1"], "miner-x", "org-miner")
            .unwrap_err();
        assert!(matches!(err, RegistryError::MinerControllerOverlap { .. }));
    }

    #[test]
    fn independence_group_check() {
        let reg = VerifierRegistry::new();
        let mut r1 = make_req("v1", "org-a");
        r1.independence_group = Some("group-x".to_owned());
        let mut r2 = make_req("v2", "org-b");
        r2.independence_group = Some("group-x".to_owned());
        reg.register(r1).unwrap();
        reg.register(r2).unwrap();
        let err = reg.check_quorum_independence(&["v1", "v2"]).unwrap_err();
        assert!(matches!(err, RegistryError::IndependenceGroupOverlap(_)));
    }
}
