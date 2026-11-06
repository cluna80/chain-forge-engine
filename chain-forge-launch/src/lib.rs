//! Qattice launch-manifest verification (owner decisions 2026-11-05).
//!
//! Public Alpha is identified by an explicit, version-controlled launch manifest, not by a new environment mode. This crate is
//! the deployment gate: a genesis is deployable as the public alpha only if
//!   * it carries `commitment_profile: "qattice-v2"` (omitted or changed is refused, even if the manifest is re-pinned),
//!   * it is ML-DSA-only (`pqc-native` + `ml-dsa`, validator scheme `ml-dsa-65`),
//!   * it is exactly the genesis the manifest pins (chain id, environment mode, genesis hash).
//! The manifest itself cannot weaken those requirements, and must name `signing-v2` among the release-build features.
//! Historical genesis files are never touched: this crate only reads.

use chain_forge_core::{compute_genesis_hash, GenesisConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const NETWORK: &str = "qattice-public-alpha";
pub const REQUIRED_PROFILE: &str = "qattice-v2";
pub const REQUIRED_SIGNATURE_SCHEME: &str = "pqc-native";
pub const REQUIRED_PQC_ALGORITHM: &str = "ml-dsa";
pub const REQUIRED_VALIDATOR_SCHEME: &str = "ml-dsa-65";
pub const REQUIRED_BUILD_FEATURE: &str = "signing-v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Violation {
    pub code: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub network: String,
    pub chain_id: String,
    pub genesis_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    network: String,
    chain_id: String,
    environment_mode: String,
    genesis_hash: String,
    required_commitment_profile: String,
    required_signature_scheme: String,
    required_pqc_algorithm: String,
    required_validator_scheme: String,
    release_build_features: Vec<String>,
}

fn v(code: &'static str, detail: impl Into<String>) -> Violation { Violation { code, detail: detail.into() } }

fn is_lower_hex_64(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) }

/// Check `genesis_json` against the launch `manifest_json`. Collects every violation (it does not stop at the first).
pub fn verify(manifest_json: &str, genesis_json: &str) -> Result<Report, Vec<Violation>> {
    let mut bad: Vec<Violation> = vec![];

    // -- manifest ------------------------------------------------------------------------------------------------------
    let manifest: Option<Manifest> = match serde_json::from_str::<Manifest>(manifest_json) {
        Ok(m) => Some(m),
        Err(e) => { bad.push(v("PA_MANIFEST_INVALID", format!("manifest is not a valid v1 launch manifest: {e}"))); None }
    };
    if let Some(m) = &manifest {
        if m.schema_version != 1 { bad.push(v("PA_MANIFEST_SCHEMA", format!("schema_version {} is not supported (expected 1)", m.schema_version))); }
        if m.network != NETWORK { bad.push(v("PA_MANIFEST_NETWORK", format!("network {:?} is not {NETWORK:?}", m.network))); }
        if !is_lower_hex_64(&m.genesis_hash) { bad.push(v("PA_MANIFEST_HASH_FORMAT", "genesis_hash must be 64 lowercase hex characters")); }
        for (name, have, want) in [
            ("required_commitment_profile", &m.required_commitment_profile, REQUIRED_PROFILE),
            ("required_signature_scheme", &m.required_signature_scheme, REQUIRED_SIGNATURE_SCHEME),
            ("required_pqc_algorithm", &m.required_pqc_algorithm, REQUIRED_PQC_ALGORITHM),
            ("required_validator_scheme", &m.required_validator_scheme, REQUIRED_VALIDATOR_SCHEME),
        ] {
            if have != want { bad.push(v("PA_MANIFEST_WEAKENED", format!("{name} is {have:?}; the public alpha requires {want:?} and a manifest cannot change it"))); }
        }
        if !m.release_build_features.iter().any(|f| f == REQUIRED_BUILD_FEATURE) {
            bad.push(v("PA_MANIFEST_BUILD_FEATURES", format!("release_build_features must include {REQUIRED_BUILD_FEATURE:?}")));
        }
    }

    // -- genesis: the commitment profile, read from the raw JSON so that "omitted" and "changed" are told apart -----------
    let raw: Option<Value> = match serde_json::from_str::<Value>(genesis_json) {
        Ok(r) if r.is_object() => Some(r),
        Ok(_) => { bad.push(v("PA_GENESIS_INVALID", "genesis is not a JSON object")); None }
        Err(e) => { bad.push(v("PA_GENESIS_INVALID", format!("genesis is not valid JSON: {e}"))); None }
    };
    let mut profile_flagged = false;
    if let Some(r) = &raw {
        match r.get("commitment_profile") {
            None => { bad.push(v("PA_PROFILE_MISSING", "genesis has no commitment_profile; the public alpha requires \"qattice-v2\" (a missing field means legacy)")); profile_flagged = true; }
            Some(Value::String(s)) if s == REQUIRED_PROFILE => {}
            Some(other) => { bad.push(v("PA_PROFILE_INVALID", format!("commitment_profile is {other}; the public alpha requires exactly \"qattice-v2\""))); profile_flagged = true; }
        }
    }

    // -- genesis: the typed checks -----------------------------------------------------------------------------------------
    let mut report = None;
    if raw.is_some() {
        match GenesisConfig::from_json(genesis_json) {
            Err(e) => {
                let msg = e.to_string();
                // A bad profile value already has its own precise code; do not bury it under a generic parse error.
                if !(profile_flagged && msg.contains("commitment_profile")) {
                    bad.push(v("PA_GENESIS_INVALID", format!("genesis does not parse: {msg}")));
                }
            }
            Ok(g) => {
                let c = &g.cryptography;
                if c.signature_scheme != REQUIRED_SIGNATURE_SCHEME || c.pqc_algorithm.as_deref() != Some(REQUIRED_PQC_ALGORITHM) {
                    bad.push(v("PA_CRYPTO_NOT_MLDSA", format!(
                        "cryptography must be ML-DSA-only (signature_scheme {REQUIRED_SIGNATURE_SCHEME:?}, pqc_algorithm {REQUIRED_PQC_ALGORITHM:?}); got {:?} / {:?}",
                        c.signature_scheme, c.pqc_algorithm)));
                }
                if c.validator_scheme != REQUIRED_VALIDATOR_SCHEME {
                    bad.push(v("PA_VALIDATOR_SCHEME", format!("validator_scheme must be {REQUIRED_VALIDATOR_SCHEME:?}; got {:?}", c.validator_scheme)));
                }
                let hash = compute_genesis_hash(&g);
                if let Some(m) = &manifest {
                    if g.chain_id != m.chain_id { bad.push(v("PA_CHAIN_ID_MISMATCH", format!("genesis chain_id {:?} != manifest {:?}", g.chain_id, m.chain_id))); }
                    if g.environment.mode != m.environment_mode { bad.push(v("PA_MODE_MISMATCH", format!("genesis environment.mode {:?} != manifest {:?}", g.environment.mode, m.environment_mode))); }
                    if hash != m.genesis_hash { bad.push(v("PA_GENESIS_HASH_MISMATCH", format!("genesis hash {hash} != manifest {}", m.genesis_hash))); }
                    report = Some(Report { network: m.network.clone(), chain_id: g.chain_id.clone(), genesis_hash: hash });
                }
            }
        }
    }

    if bad.is_empty() { Ok(report.expect("a fully valid manifest and genesis produce a report")) } else { Err(bad) }
}
