//! DIS-AGENT-001: scoped, expiring, revocable capability delegation.
//!
//! A human holder signs a `Delegation` granting an agent a strict subset of their
//! RP-granted capabilities for a specific resource and action. Chains of up to
//! `MAX_CHAIN_DEPTH` are validated; scopes may only narrow at each link.
//!
//! Machine/agent credentials never imply human uniqueness (QPC). An enrolled agent
//! key is NOT an enrollment of a human identity; the RP's enrolled_keys set is for
//! human holders only; agent keys appear only in delegation chains.

use crate::{Error as EncodingError, Request};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha2::{Digest, Sha256};

pub const DELEGATION_DOMAIN: &[u8] = b"DIS-DEL-V1\0";
pub const MAX_CHAIN_DEPTH: usize = 4;

/// A single link in a delegation chain.
///
/// `signature` is a Dilithium3 detached signature by `delegator_public_key` over
/// `canonical_delegation_body(self)` — the same struct with `signature` empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// Must match the verifying RP's `rp_id`.
    pub rp_id: String,
    /// ML-DSA-65 public key of the party granting this delegation.
    /// For the root link this must be enrolled at the RP.
    pub delegator_public_key: Vec<u8>,
    /// ML-DSA-65 public key of the party receiving this delegation (the agent).
    pub delegate_public_key: Vec<u8>,
    /// Scopes granted — must be ⊆ delegator's own scopes (or RP grants for root).
    pub scopes: Vec<String>,
    pub resource_id: String,
    pub action: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// If Some(n), this delegation may be used at most n times.
    pub max_uses: Option<u32>,
    /// If true, the RP must see an explicit human-approval signal for the
    /// challenge before accepting a proof from this delegation chain.
    pub requires_human_approval: bool,
    /// Delegator's Dilithium3 signature over `canonical_delegation_body`.
    pub signature: Vec<u8>,
}

/// A holder proof produced by an agent acting under a delegation chain.
#[derive(Debug, Clone)]
pub struct DelegatedProof {
    /// Ordered chain: chain[0].delegator_public_key is the human holder (enrolled at RP).
    /// chain[i].delegate_public_key == chain[i+1].delegator_public_key.
    /// chain.last().delegate_public_key is the signing agent.
    pub chain: Vec<Delegation>,
    /// Agent's ML-DSA signature over `canonical_request(request)`.
    pub agent_proof: crate::verifier::HolderProof,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DelegationError {
    #[error("invalid request or delegation encoding: {0}")]
    Encoding(#[from] EncodingError),
    #[error("delegation chain is empty or exceeds max depth")]
    InvalidChain,
    #[error("delegation signature invalid")]
    DelegationChainInvalid,
    #[error("delegation has expired or not yet valid")]
    DelegationExpired,
    #[error("agent claims scopes not granted by delegation chain")]
    DelegationScopeExceeded,
    #[error("this action requires explicit human approval")]
    HumanApprovalRequired,
    #[error("delegation max_uses limit reached")]
    UsesExhausted,
}

fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn write_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn write_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), DelegationError> {
    let n = u16::try_from(b.len())
        .map_err(|_| DelegationError::Encoding(EncodingError::InvalidField))?;
    write_u16(out, n);
    out.extend_from_slice(b);
    Ok(())
}
fn write_str(out: &mut Vec<u8>, s: &str) -> Result<(), DelegationError> {
    write_bytes(out, s.as_bytes())
}

/// Canonical bytes signed by the delegator (excludes the `signature` field).
pub fn canonical_delegation_body(d: &Delegation) -> Result<Vec<u8>, DelegationError> {
    let mut out = Vec::new();
    out.extend_from_slice(DELEGATION_DOMAIN);
    write_str(&mut out, &d.rp_id)?;
    write_bytes(&mut out, &d.delegator_public_key)?;
    write_bytes(&mut out, &d.delegate_public_key)?;
    write_u16(
        &mut out,
        u16::try_from(d.scopes.len())
            .map_err(|_| DelegationError::Encoding(EncodingError::InvalidField))?,
    );
    for scope in &d.scopes {
        write_str(&mut out, scope)?;
    }
    write_str(&mut out, &d.resource_id)?;
    write_str(&mut out, &d.action)?;
    write_u64(&mut out, d.issued_at);
    write_u64(&mut out, d.expires_at);
    match d.max_uses {
        Some(n) => {
            out.push(1);
            write_u32(&mut out, n);
        }
        None => {
            out.push(0);
        }
    }
    out.push(d.requires_human_approval as u8);
    Ok(out)
}

/// Sign a delegation with the delegator's secret key.
pub fn sign_delegation(
    d: &mut Delegation,
    delegator_secret_key: &[u8],
) -> Result<(), DelegationError> {
    let sk = dilithium3::SecretKey::from_bytes(delegator_secret_key)
        .map_err(|_| DelegationError::DelegationChainInvalid)?;
    let body = canonical_delegation_body(d)?;
    d.signature = dilithium3::detached_sign(&body, &sk).as_bytes().to_vec();
    Ok(())
}

/// Verify one delegation link's signature and time window.
pub fn verify_delegation_link(d: &Delegation, now: u64) -> Result<(), DelegationError> {
    if d.expires_at <= d.issued_at || now >= d.expires_at {
        return Err(DelegationError::DelegationExpired);
    }
    let pk = dilithium3::PublicKey::from_bytes(&d.delegator_public_key)
        .map_err(|_| DelegationError::DelegationChainInvalid)?;
    let sig = dilithium3::DetachedSignature::from_bytes(&d.signature)
        .map_err(|_| DelegationError::DelegationChainInvalid)?;
    let body = canonical_delegation_body(d)?;
    dilithium3::verify_detached_signature(&sig, &body, &pk)
        .map_err(|_| DelegationError::DelegationChainInvalid)?;
    Ok(())
}

/// SHA-256 of `canonical_delegation_body` — used as the delegation's stable id
/// for max_uses tracking.
pub fn delegation_id(d: &Delegation) -> Result<[u8; 32], DelegationError> {
    Ok(Sha256::digest(canonical_delegation_body(d)?).into())
}

/// Create and sign a delegation in one call (test/demo helper).
#[allow(clippy::too_many_arguments)]
pub fn make_delegation(
    rp_id: &str,
    delegator_pk: &[u8],
    delegator_sk: &[u8],
    delegate_pk: &[u8],
    scopes: Vec<String>,
    resource_id: &str,
    action: &str,
    issued_at: u64,
    expires_at: u64,
    max_uses: Option<u32>,
    requires_human_approval: bool,
) -> Result<Delegation, DelegationError> {
    let mut d = Delegation {
        rp_id: rp_id.into(),
        delegator_public_key: delegator_pk.to_vec(),
        delegate_public_key: delegate_pk.to_vec(),
        scopes,
        resource_id: resource_id.into(),
        action: action.into(),
        issued_at,
        expires_at,
        max_uses,
        requires_human_approval,
        signature: vec![],
    };
    sign_delegation(&mut d, delegator_sk)?;
    Ok(d)
}

/// Validate that `request.scopes` is a subset of `allowed`.
pub fn scopes_within(request_scopes: &[String], allowed: &[String]) -> bool {
    request_scopes.iter().all(|s| allowed.contains(s))
}

/// Validate a full delegation chain against a request, given the root delegator's
/// enrolled grants for `(resource, action)`. Returns whether any link requires
/// human approval.
///
/// Does NOT check max_uses or RP enrollment — that is the caller's responsibility.
pub fn validate_chain(
    chain: &[Delegation],
    request: &Request,
    root_grants: &std::collections::HashSet<(String, String, String)>,
    now: u64,
) -> Result<bool, DelegationError> {
    if chain.is_empty() || chain.len() > MAX_CHAIN_DEPTH {
        return Err(DelegationError::InvalidChain);
    }

    // Compute the effective scopes the root delegator is allowed: those in their grants
    // for this (resource, action) pair.
    let root_scopes: Vec<String> = root_grants
        .iter()
        .filter(|(r, a, _)| r == &request.resource_id && a == &request.action)
        .map(|(_, _, s)| s.clone())
        .collect();

    let mut parent_scopes: &[String] = &root_scopes;
    let mut requires_human_approval = false;
    let mut temp: Vec<String>; // holds scopes for each link

    for (i, link) in chain.iter().enumerate() {
        // Structural checks.
        if link.rp_id != request.rp_id {
            return Err(DelegationError::DelegationChainInvalid);
        }
        if link.resource_id != request.resource_id || link.action != request.action {
            return Err(DelegationError::DelegationChainInvalid);
        }
        // Chain connectivity.
        if i > 0 && chain[i - 1].delegate_public_key != link.delegator_public_key {
            return Err(DelegationError::DelegationChainInvalid);
        }
        // Scopes narrow or stay equal.
        if !scopes_within(&link.scopes, parent_scopes) {
            return Err(DelegationError::DelegationScopeExceeded);
        }
        // Signature and expiry.
        verify_delegation_link(link, now)?;

        if link.requires_human_approval {
            requires_human_approval = true;
        }
        temp = link.scopes.clone();
        parent_scopes = &temp; // safe: temp lives for this iteration, then we reborrow
                               // (actually we can't reborrow temp across iterations without the borrow checker complaining;
                               //  restructure with an owned Vec)
        let _ = parent_scopes; // suppress unused
        parent_scopes = &chain[i].scopes; // borrow from the slice which has 'chain lifetime
    }

    // Final: request scopes must be ⊆ last link's scopes.
    if !scopes_within(&request.scopes, &chain.last().unwrap().scopes) {
        return Err(DelegationError::DelegationScopeExceeded);
    }
    // Final: agent proof key must match last delegate.
    // (caller verifies this separately since we don't have the HolderProof here)

    Ok(requires_human_approval)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        delegation::DelegatedProof,
        verifier::{sign_for_test, RelyingParty, RpPolicy, VerifyError},
        Request, SUITE_ML_DSA_65,
    };
    use pqcrypto_dilithium::dilithium3;
    use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
    use std::collections::HashSet;

    fn make_rp(id: &str, resource: &str, action: &str, scope: &str) -> RelyingParty {
        let mut grants = HashSet::new();
        grants.insert((resource.into(), action.into(), scope.into()));
        RelyingParty::new(RpPolicy {
            rp_id: id.into(),
            rp_origin: format!("https://{id}.example"),
            policy_id: "v1".into(),
            grants,
            min_suite_id: SUITE_ML_DSA_65,
        })
    }

    fn make_req(id: &str, resource: &str, action: &str, scope: &str) -> Request {
        Request {
            suite_id: SUITE_ML_DSA_65,
            rp_id: id.into(),
            rp_origin: format!("https://{id}.example"),
            challenge_id: [0; 16],
            nonce: [0; 16],
            issued_at: 1000,
            expires_at: 1060,
            resource_id: resource.into(),
            action: action.into(),
            scopes: vec![scope.into()],
            operation_digest: None,
            policy_id: "v1".into(),
        }
    }

    fn issued_req(
        rp: &mut RelyingParty,
        id: &str,
        resource: &str,
        action: &str,
        scope: &str,
    ) -> Request {
        rp.issue(make_req(id, resource, action, scope)).unwrap()
    }

    /// Basic happy path: human delegates to agent, agent signs, RP accepts.
    #[test]
    fn agent_can_act_within_delegated_scopes() {
        let (human_pk, human_sk) = dilithium3::keypair();
        let (agent_pk, agent_sk) = dilithium3::keypair();
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        rp.enroll_test_key(human_pk.as_bytes()).unwrap();

        let del = make_delegation(
            "docs",
            human_pk.as_bytes(),
            human_sk.as_bytes(),
            agent_pk.as_bytes(),
            vec!["document:read".into()],
            "doc:1",
            "read",
            900,
            2000,
            None,
            false,
        )
        .unwrap();

        let req = issued_req(&mut rp, "docs", "doc:1", "read", "document:read");
        let agent_proof = sign_for_test(&req, agent_sk.as_bytes(), agent_pk.as_bytes()).unwrap();
        let delegated = DelegatedProof {
            chain: vec![del],
            agent_proof,
        };

        assert_eq!(rp.verify_delegated(&req, &delegated, 1010), Ok(()));
    }

    /// Agent is not in enrolled_keys — direct verify must reject it.
    #[test]
    fn agent_key_not_enrolled_directly() {
        let (human_pk, human_sk) = dilithium3::keypair();
        let (agent_pk, agent_sk) = dilithium3::keypair();
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        rp.enroll_test_key(human_pk.as_bytes()).unwrap();

        let req = issued_req(&mut rp, "docs", "doc:1", "read", "document:read");
        let proof = sign_for_test(&req, agent_sk.as_bytes(), agent_pk.as_bytes()).unwrap();
        // Direct verify must reject the agent key (not enrolled).
        assert_eq!(
            rp.verify(&req, &proof, 1010),
            Err(VerifyError::Unauthorized)
        );
    }

    /// Scope not in delegation is rejected.
    #[test]
    fn agent_cannot_exceed_delegated_scopes() {
        let (human_pk, human_sk) = dilithium3::keypair();
        let (agent_pk, agent_sk) = dilithium3::keypair();
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        rp.enroll_test_key(human_pk.as_bytes()).unwrap();

        // Delegation only grants document:read; request asks for document:admin.
        let del = make_delegation(
            "docs",
            human_pk.as_bytes(),
            human_sk.as_bytes(),
            agent_pk.as_bytes(),
            vec!["document:read".into()],
            "doc:1",
            "read",
            900,
            2000,
            None,
            false,
        )
        .unwrap();

        let mut req = make_req("docs", "doc:1", "read", "document:read");
        req.scopes = vec!["document:admin".into()];
        let req = rp.issue(req).unwrap();
        let agent_proof = sign_for_test(&req, agent_sk.as_bytes(), agent_pk.as_bytes()).unwrap();
        let delegated = DelegatedProof {
            chain: vec![del],
            agent_proof,
        };

        assert_eq!(
            rp.verify_delegated(&req, &delegated, 1010),
            Err(VerifyError::Unauthorized)
        );
    }

    /// Expired delegation is rejected.
    #[test]
    fn expired_delegation_rejected() {
        let (human_pk, human_sk) = dilithium3::keypair();
        let (agent_pk, agent_sk) = dilithium3::keypair();
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        rp.enroll_test_key(human_pk.as_bytes()).unwrap();

        let del = make_delegation(
            "docs",
            human_pk.as_bytes(),
            human_sk.as_bytes(),
            agent_pk.as_bytes(),
            vec!["document:read".into()],
            "doc:1",
            "read",
            900,
            1000, // expires_at == issued_at for request → already expired
            None,
            false,
        )
        .unwrap();

        let req = issued_req(&mut rp, "docs", "doc:1", "read", "document:read");
        let agent_proof = sign_for_test(&req, agent_sk.as_bytes(), agent_pk.as_bytes()).unwrap();
        let delegated = DelegatedProof {
            chain: vec![del],
            agent_proof,
        };

        // now=1010 > delegation.expires_at=1000 → expired
        assert_eq!(
            rp.verify_delegated(&req, &delegated, 1010),
            Err(VerifyError::DelegationInvalid)
        );
    }

    /// Two-level chain: human → agent → subagent.
    #[test]
    fn two_level_delegation_chain() {
        let (human_pk, human_sk) = dilithium3::keypair();
        let (agent_pk, agent_sk) = dilithium3::keypair();
        let (sub_pk, sub_sk) = dilithium3::keypair();
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        rp.enroll_test_key(human_pk.as_bytes()).unwrap();

        let del1 = make_delegation(
            "docs",
            human_pk.as_bytes(),
            human_sk.as_bytes(),
            agent_pk.as_bytes(),
            vec!["document:read".into()],
            "doc:1",
            "read",
            900,
            2000,
            None,
            false,
        )
        .unwrap();
        let del2 = make_delegation(
            "docs",
            agent_pk.as_bytes(),
            agent_sk.as_bytes(),
            sub_pk.as_bytes(),
            vec!["document:read".into()],
            "doc:1",
            "read",
            900,
            2000,
            None,
            false,
        )
        .unwrap();

        let req = issued_req(&mut rp, "docs", "doc:1", "read", "document:read");
        let sub_proof = sign_for_test(&req, sub_sk.as_bytes(), sub_pk.as_bytes()).unwrap();
        let delegated = DelegatedProof {
            chain: vec![del1, del2],
            agent_proof: sub_proof,
        };

        assert_eq!(rp.verify_delegated(&req, &delegated, 1010), Ok(()));
    }

    /// Sub-delegation that tries to widen scopes beyond what the parent granted is rejected.
    #[test]
    fn chain_cannot_widen_scopes() {
        let (human_pk, human_sk) = dilithium3::keypair();
        let (agent_pk, agent_sk) = dilithium3::keypair();
        let (sub_pk, _sub_sk) = dilithium3::keypair();
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        rp.enroll_test_key(human_pk.as_bytes()).unwrap();

        // Agent gets document:read only.
        let del1 = make_delegation(
            "docs",
            human_pk.as_bytes(),
            human_sk.as_bytes(),
            agent_pk.as_bytes(),
            vec!["document:read".into()],
            "doc:1",
            "read",
            900,
            2000,
            None,
            false,
        )
        .unwrap();
        // Agent tries to grant document:admin — wider than what it has.
        let del2 = make_delegation(
            "docs",
            agent_pk.as_bytes(),
            agent_sk.as_bytes(),
            sub_pk.as_bytes(),
            vec!["document:admin".into()], // not in del1.scopes
            "doc:1",
            "read",
            900,
            2000,
            None,
            false,
        )
        .unwrap();

        let req = issued_req(&mut rp, "docs", "doc:1", "read", "document:read");
        let sub_proof = sign_for_test(&req, _sub_sk.as_bytes(), sub_pk.as_bytes()).unwrap();
        let delegated = DelegatedProof {
            chain: vec![del1, del2],
            agent_proof: sub_proof,
        };

        assert_eq!(
            rp.verify_delegated(&req, &delegated, 1010),
            Err(VerifyError::Unauthorized)
        );
    }

    /// High-risk action: delegation requires human approval; without it, rejected.
    #[test]
    fn high_risk_action_requires_human_approval() {
        let (human_pk, human_sk) = dilithium3::keypair();
        let (agent_pk, agent_sk) = dilithium3::keypair();
        let mut rp = make_rp("pay", "payment:1", "submit", "payment:submit");
        rp.enroll_test_key(human_pk.as_bytes()).unwrap();

        let del = make_delegation(
            "pay",
            human_pk.as_bytes(),
            human_sk.as_bytes(),
            agent_pk.as_bytes(),
            vec!["payment:submit".into()],
            "payment:1",
            "submit",
            900,
            2000,
            None,
            true, // requires_human_approval
        )
        .unwrap();

        let req = issued_req(&mut rp, "pay", "payment:1", "submit", "payment:submit");
        let agent_proof = sign_for_test(&req, agent_sk.as_bytes(), agent_pk.as_bytes()).unwrap();
        let delegated = DelegatedProof {
            chain: vec![del.clone()],
            agent_proof: agent_proof.clone(),
        };

        // Without approval: rejected.
        assert_eq!(
            rp.verify_delegated(&req, &delegated, 1010),
            Err(VerifyError::HumanApprovalRequired)
        );

        // Issue a fresh challenge and approve it.
        let req2 = issued_req(&mut rp, "pay", "payment:1", "submit", "payment:submit");
        rp.approve_challenge(req2.challenge_id);
        let agent_proof2 = sign_for_test(&req2, agent_sk.as_bytes(), agent_pk.as_bytes()).unwrap();
        let delegated2 = DelegatedProof {
            chain: vec![del],
            agent_proof: agent_proof2,
        };
        assert_eq!(rp.verify_delegated(&req2, &delegated2, 1010), Ok(()));
    }

    /// max_uses=1: first use succeeds, second use is rejected.
    #[test]
    fn max_uses_enforcement() {
        let (human_pk, human_sk) = dilithium3::keypair();
        let (agent_pk, agent_sk) = dilithium3::keypair();
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        rp.enroll_test_key(human_pk.as_bytes()).unwrap();

        let del = make_delegation(
            "docs",
            human_pk.as_bytes(),
            human_sk.as_bytes(),
            agent_pk.as_bytes(),
            vec!["document:read".into()],
            "doc:1",
            "read",
            900,
            2000,
            Some(1), // max_uses = 1
            false,
        )
        .unwrap();

        // First use: ok.
        let req1 = issued_req(&mut rp, "docs", "doc:1", "read", "document:read");
        let proof1 = sign_for_test(&req1, agent_sk.as_bytes(), agent_pk.as_bytes()).unwrap();
        assert_eq!(
            rp.verify_delegated(
                &req1,
                &DelegatedProof {
                    chain: vec![del.clone()],
                    agent_proof: proof1
                },
                1010
            ),
            Ok(())
        );

        // Second use: exhausted.
        let req2 = issued_req(&mut rp, "docs", "doc:1", "read", "document:read");
        let proof2 = sign_for_test(&req2, agent_sk.as_bytes(), agent_pk.as_bytes()).unwrap();
        assert_eq!(
            rp.verify_delegated(
                &req2,
                &DelegatedProof {
                    chain: vec![del],
                    agent_proof: proof2
                },
                1010
            ),
            Err(VerifyError::DelegationUsesExhausted)
        );
    }

    /// Revoked root delegator key blocks delegated proof.
    #[test]
    fn revoked_delegator_blocks_delegation() {
        let (human_pk, human_sk) = dilithium3::keypair();
        let (agent_pk, agent_sk) = dilithium3::keypair();
        let mut rp = make_rp("docs", "doc:1", "read", "document:read");
        rp.enroll_test_key(human_pk.as_bytes()).unwrap();

        let del = make_delegation(
            "docs",
            human_pk.as_bytes(),
            human_sk.as_bytes(),
            agent_pk.as_bytes(),
            vec!["document:read".into()],
            "doc:1",
            "read",
            900,
            2000,
            None,
            false,
        )
        .unwrap();

        rp.revoke(human_pk.as_bytes()).unwrap();

        let req = issued_req(&mut rp, "docs", "doc:1", "read", "document:read");
        let agent_proof = sign_for_test(&req, agent_sk.as_bytes(), agent_pk.as_bytes()).unwrap();
        let delegated = DelegatedProof {
            chain: vec![del],
            agent_proof,
        };

        assert_eq!(
            rp.verify_delegated(&req, &delegated, 1010),
            Err(VerifyError::Revoked)
        );
    }
}
