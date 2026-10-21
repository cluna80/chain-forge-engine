//! Vendor (relying party) SDK — ergonomic wrapper around `RelyingParty`.

use crate::{Grant, SdkError};
use dis_core::{
    delegation::DelegatedProof,
    verifier::{HolderProof, RelyingParty, RpPolicy},
    Request, SUITE_ML_DSA_65,
};
use std::collections::HashSet;

/// Configuration for a vendor SDK instance.
#[derive(Debug, Clone)]
pub struct VendorConfig {
    pub rp_id: String,
    pub rp_origin: String,
    pub policy_id: String,
    pub grants: Vec<Grant>,
    /// Reject any request with suite_id below this value. Use `SUITE_ML_DSA_65`
    /// for current deployments; raise when migrating to a stronger suite.
    pub min_suite_id: u16,
}

impl VendorConfig {
    pub fn new(rp_id: impl Into<String>, rp_origin: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            rp_origin: rp_origin.into(),
            policy_id: "v1".into(),
            grants: vec![],
            min_suite_id: SUITE_ML_DSA_65,
        }
    }

    pub fn with_policy(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = policy_id.into();
        self
    }

    pub fn with_grant(mut self, resource: impl Into<String>, action: impl Into<String>, scope: impl Into<String>) -> Self {
        self.grants.push(Grant::new(resource, action, scope));
        self
    }

    pub fn with_min_suite(mut self, min_suite_id: u16) -> Self {
        self.min_suite_id = min_suite_id;
        self
    }
}

/// Vendor (relying party) SDK.
///
/// Each vendor has its own `VendorSdk` instance with its own enrolled keys,
/// pending challenges, and policy. Instances are NOT thread-safe; wrap in a
/// `Mutex` for concurrent use.
pub struct VendorSdk {
    rp: RelyingParty,
}

impl VendorSdk {
    /// Create a new vendor SDK from a `VendorConfig`.
    pub fn new(config: VendorConfig) -> Self {
        let mut grants = HashSet::new();
        for g in config.grants {
            grants.insert((g.resource, g.action, g.scope));
        }
        Self {
            rp: RelyingParty::new(RpPolicy {
                rp_id: config.rp_id,
                rp_origin: config.rp_origin,
                policy_id: config.policy_id,
                grants,
                min_suite_id: config.min_suite_id,
            }),
        }
    }

    /// Enroll a holder's public key (demo/test enrollment).
    /// Production enrollment requires an RP-approved bootstrap process.
    pub fn enroll_key(&mut self, public_key: &[u8]) -> Result<(), SdkError> {
        Ok(self.rp.enroll_test_key(public_key)?)
    }

    /// Revoke a previously enrolled key.
    pub fn revoke_key(&mut self, public_key: &[u8]) -> Result<(), SdkError> {
        Ok(self.rp.revoke(public_key)?)
    }

    /// Atomically revoke `old_key` and enroll `new_key` (key rotation).
    pub fn rotate_key(&mut self, old_key: &[u8], new_key: &[u8]) -> Result<(), SdkError> {
        Ok(self.rp.rotate_key(old_key, new_key)?)
    }

    /// Issue a fresh challenge for a holder request. The returned `Request` has
    /// `challenge_id` and `nonce` filled by a CSPRNG; the wallet must sign this
    /// exact struct and return a `HolderProof`.
    pub fn issue_challenge(&mut self, request: Request) -> Result<Request, SdkError> {
        Ok(self.rp.issue(request)?)
    }

    /// Verify a holder proof for the issued challenge.
    pub fn verify(&mut self, request: &Request, proof: &HolderProof, now_unix_secs: u64) -> Result<(), SdkError> {
        Ok(self.rp.verify(request, proof, now_unix_secs)?)
    }

    /// Verify a delegated (agent) proof for the issued challenge.
    pub fn verify_delegated(
        &mut self,
        request: &Request,
        proof: &DelegatedProof,
        now_unix_secs: u64,
    ) -> Result<(), SdkError> {
        Ok(self.rp.verify_delegated(request, proof, now_unix_secs)?)
    }

    /// Approve a high-risk challenge (call before `verify_delegated` when the
    /// delegation's `requires_human_approval` flag is set).
    pub fn approve_challenge(&mut self, challenge_id: [u8; 16]) {
        self.rp.approve_challenge(challenge_id);
    }

    /// Build a `Request` template for this vendor.
    pub fn request(
        &self,
        resource: impl Into<String>,
        action: impl Into<String>,
        scopes: Vec<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Request {
        Request {
            suite_id: SUITE_ML_DSA_65,
            rp_id: self.rp_id().into(),
            rp_origin: self.rp_origin().into(),
            challenge_id: [0; 16], // filled by issue_challenge
            nonce: [0; 16],        // filled by issue_challenge
            issued_at,
            expires_at,
            resource_id: resource.into(),
            action: action.into(),
            scopes,
            operation_digest: None,
            policy_id: self.policy_id().into(),
        }
    }

    pub fn rp_id(&self) -> &str { &self.rp.policy().rp_id }
    pub fn rp_origin(&self) -> &str { &self.rp.policy().rp_origin }
    pub fn policy_id(&self) -> &str { &self.rp.policy().policy_id }
}
