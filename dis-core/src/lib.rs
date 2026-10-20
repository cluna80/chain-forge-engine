//! DIS-KS-V1: vendor-independent canonical request transcript (prototype).
//!
//! No blockchain dependencies. This crate does NOT sign, verify, issue credentials,
//! enforce permissions, or claim privacy/continuity. The binary transcript is
//! an experimental versioned profile pending external review and golden vectors.
//! Existing Qattice DIS-AUTH-V1 is intentionally unchanged.

pub mod verifier;

use sha2::{Digest, Sha256};

pub const DOMAIN: &[u8] = b"DIS-KS-V1\0";
pub const SUITE_ML_DSA_65: u16 = 1;
const MAX_FIELD: usize = 4096;
const MAX_TTL: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub suite_id: u16,
    pub rp_id: String,
    pub rp_origin: String,
    pub challenge_id: [u8; 16],
    pub nonce: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
    pub resource_id: String,
    pub action: String,
    pub scopes: Vec<String>,
    /// SHA-256 of the canonical exact business operation; required by RP
    /// policy for financial or other transaction-specific authorization.
    pub operation_digest: Option<[u8; 32]>,
    pub policy_id: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unsupported signature suite")]
    UnsupportedSuite,
    #[error("invalid time window")]
    InvalidTime,
    #[error("invalid or oversized field")]
    InvalidField,
    #[error("scopes must be strictly sorted and unique")]
    NonCanonicalScopes,
}

fn field(out: &mut Vec<u8>, value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > MAX_FIELD || value.contains('\0') {
        return Err(Error::InvalidField);
    }
    let n = u16::try_from(value.len()).map_err(|_| Error::InvalidField)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Unambiguous length-prefixed canonical bytes for the proposed KS-V1 request.
/// The wallet MUST authenticate rp_origin independently; a string in a QR
/// challenge is never sufficient to establish origin identity.
pub fn canonical_request(r: &Request) -> Result<Vec<u8>, Error> {
    if r.suite_id != SUITE_ML_DSA_65 { return Err(Error::UnsupportedSuite); }
    if r.expires_at <= r.issued_at || r.expires_at - r.issued_at > MAX_TTL {
        return Err(Error::InvalidTime);
    }
    if r.scopes.len() > 64 { return Err(Error::InvalidField); }
    if r.scopes.windows(2).any(|p| p[0] >= p[1]) {
        return Err(Error::NonCanonicalScopes);
    }
    let mut out = Vec::new();
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&r.suite_id.to_be_bytes());
    field(&mut out, &r.rp_id)?;
    field(&mut out, &r.rp_origin)?;
    out.extend_from_slice(&r.challenge_id);
    out.extend_from_slice(&r.nonce);
    out.extend_from_slice(&r.issued_at.to_be_bytes());
    out.extend_from_slice(&r.expires_at.to_be_bytes());
    field(&mut out, &r.resource_id)?;
    field(&mut out, &r.action)?;
    out.extend_from_slice(&(r.scopes.len() as u16).to_be_bytes());
    for scope in &r.scopes { field(&mut out, scope)?; }
    match r.operation_digest {
        Some(d) => { out.push(1); out.extend_from_slice(&d); }
        None => out.push(0),
    }
    field(&mut out, &r.policy_id)?;
    Ok(out)
}

/// Digest for diagnostics and future golden vectors, NOT a signature.
/// No security guarantee follows from computing this digest alone.
pub fn request_digest(r: &Request) -> Result<[u8; 32], Error> {
    Ok(Sha256::digest(canonical_request(r)?).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> Request {
        Request {
            suite_id: SUITE_ML_DSA_65,
            rp_id: "vendor-a".into(),
            rp_origin: "https://vendor-a.example".into(),
            challenge_id: [1; 16], nonce: [2; 16],
            issued_at: 1000, expires_at: 1060,
            resource_id: "document:123".into(),
            action: "read".into(),
            scopes: vec!["document:read".into()],
            operation_digest: None,
            policy_id: "policy-v1".into(),
        }
    }
    #[test]
    fn deterministic_and_domain_separated() {
        let r = example();
        assert_eq!(canonical_request(&r).unwrap(), canonical_request(&r).unwrap());
        assert!(canonical_request(&r).unwrap().starts_with(DOMAIN));
    }
    #[test]
    fn vendor_and_action_binding() {
        let r = example();
        let baseline = request_digest(&r).unwrap();
        let mut changed = r.clone();
        changed.rp_id = "vendor-b".into();
        assert_ne!(baseline, request_digest(&changed).unwrap());
        changed = r.clone();
        changed.action = "delete".into();
        assert_ne!(baseline, request_digest(&changed).unwrap());
        changed = r.clone();
        changed.operation_digest = Some([3; 32]);
        assert_ne!(baseline, request_digest(&changed).unwrap());
    }
    #[test]
    fn rejects_invalid_time_and_suite() {
        let mut r = example();
        r.expires_at = r.issued_at;
        assert_eq!(canonical_request(&r), Err(Error::InvalidTime));
        r = example();
        r.suite_id = 0;
        assert_eq!(canonical_request(&r), Err(Error::UnsupportedSuite));
    }
    #[test]
    fn rejects_noncanonical_scopes_and_fields() {
        let mut r = example();
        r.scopes = vec!["b".into(), "a".into()];
        assert_eq!(canonical_request(&r), Err(Error::NonCanonicalScopes));
        r = example();
        r.rp_id = "".into();
        assert_eq!(canonical_request(&r), Err(Error::InvalidField));
    }
}
