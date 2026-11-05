//! Qattice launch-manifest verification. SCAFFOLD (tests first): `verify` accepts everything.

use serde::Serialize;

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

/// Check `genesis_json` against the launch `manifest_json`. Collects every violation.
pub fn verify(_manifest_json: &str, _genesis_json: &str) -> Result<Report, Vec<Violation>> {
    Ok(Report { network: String::new(), chain_id: String::new(), genesis_hash: String::new() })
}
