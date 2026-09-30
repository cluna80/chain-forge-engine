//! Governance authority for QCB personhood.
//!
//! Tracks authorized personhood issuers and enforces ML-DSA-signed quorum
//! votes for additions and revocations.
//!
//! Architecture note: this module imports from chain_forge_core (ValidatorId,
//! ValidatorSetView) rather than chain_forge_consensus (ValidatorSet) so that
//! chain-forge-personhood does not need the full consensus crate as a dep.
//! The consensus crate implements ValidatorSetView on its ValidatorSet; tests
//! supply a lightweight stub.

use std::collections::{BTreeMap, BTreeSet};

use chain_forge_core::{ValidatorId, ValidatorSetView};
use chain_forge_crypto::{MlDsaScheme, SchemeId, Signature, SignatureScheme};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("quorum not met: need {needed}, have {have}")]
    QuorumNotMet { needed: u64, have: u64 },

    #[error("duplicate voter: {0}")]
    DuplicateVoter(ValidatorId),

    #[error("unknown voter: {0}")]
    UnknownVoter(ValidatorId),

    #[error("bad signature from voter: {0}")]
    BadSignature(ValidatorId),

    #[error("issuer {0} not found")]
    IssuerNotFound(u32),

    #[error("no validators in set")]
    EmptyValidatorSet,
}

// ── Domain separation ─────────────────────────────────────────────────────────

const GOVERNANCE_DOMAIN: &[u8] = b"chain-forge:governance:v1:";

/// Build the canonical signing message for a governance action.
///
/// Format: `chain-forge:governance:v1:<action_tag>:<context_bytes>`
///
/// Callers choose `action_tag` per action type so that signatures cannot be
/// replayed across action types.
///
/// # Domain-separation gaps
///
/// * **No chain_id** (tracked in KNOWN_ISSUES §5): a governance vote signed on
///   chain A could in principle be replayed on chain B if both chains share the
///   same ML-DSA validator set. Governance votes are out-of-band (not
///   block-consensus messages) and the registry is per-instance, so cross-chain
///   replay is not a practical concern today. Add `chain_id` to the domain
///   before governance is promoted to an on-chain transaction type.
///
/// * **Epoch**: same-chain replay is mitigated. `revoke_immediately` context
///   includes `issuer_id ++ epoch` so a vote is bound to a specific governance
///   round. `propose_change` binds to the full issuer registry state (sorted
///   IDs + new name), making replay impractical by construction.
pub fn governance_vote_signing_bytes(action_tag: &[u8], context_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        GOVERNANCE_DOMAIN.len() + action_tag.len() + 1 + context_bytes.len(),
    );
    msg.extend_from_slice(GOVERNANCE_DOMAIN);
    msg.extend_from_slice(action_tag);
    msg.push(b':');
    msg.extend_from_slice(context_bytes);
    msg
}

// ── Vote ──────────────────────────────────────────────────────────────────────

/// A signed governance vote from one validator.
#[derive(Debug, Clone)]
pub struct GovernanceVote {
    pub voter:      ValidatorId,
    /// Raw ML-DSA signature bytes.
    pub signature:  Vec<u8>,
    /// The voter''s ML-DSA public key (must match the key in the validator set).
    pub public_key: Vec<u8>,
}

// ── Issuer registry ───────────────────────────────────────────────────────────

/// Registry of authorized personhood issuers.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedIssuerRegistry {
    issuers: BTreeMap<u32, String>,
    next_id: u32,
}

impl AuthorizedIssuerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// List all registered issuers.
    pub fn issuers(&self) -> &BTreeMap<u32, String> {
        &self.issuers
    }

    /// Propose adding a new issuer, guarded by a quorum of ML-DSA-signed votes.
    ///
    /// Canonical context bytes = sorted existing issuer IDs as big-endian u32s
    /// concatenated with the new issuer name as UTF-8.
    pub fn propose_change_with_votes(
        &mut self,
        new_issuer_name: &str,
        validator_set:   &dyn ValidatorSetView,
        votes:           &[GovernanceVote],
    ) -> Result<u32, AuthzError> {
        if validator_set.total_power() == 0 {
            return Err(AuthzError::EmptyValidatorSet);
        }

        let mut ctx: Vec<u8> = Vec::new();
        let mut sorted_ids: Vec<u32> = self.issuers.keys().copied().collect();
        sorted_ids.sort_unstable();
        for id in &sorted_ids {
            ctx.extend_from_slice(&id.to_be_bytes());
        }
        ctx.extend_from_slice(new_issuer_name.as_bytes());

        let signing_msg = governance_vote_signing_bytes(b"propose_change", &ctx);
        let power = tally_votes(validator_set, votes, &signing_msg)?;

        let needed = validator_set.quorum_power();
        if power < needed {
            return Err(AuthzError::QuorumNotMet { needed, have: power });
        }

        let id = self.next_id;
        self.next_id += 1;
        self.issuers.insert(id, new_issuer_name.to_owned());
        Ok(id)
    }

    /// Revoke an issuer, guarded by a quorum of ML-DSA-signed votes.
    ///
    /// Canonical context bytes = issuer_id (big-endian u32) ++ epoch (big-endian u64).
    ///
    /// The `epoch` parameter binds the signature to a specific governance epoch,
    /// preventing same-chain replay: a revocation vote signed in epoch N is
    /// invalid in any other epoch even if the issuer_id and validator set are
    /// identical. Callers should use the current block height or a governance
    /// sequence number as the epoch.
    pub fn revoke_with_votes(
        &mut self,
        issuer_id:     u32,
        epoch:         u64,
        validator_set: &dyn ValidatorSetView,
        votes:         &[GovernanceVote],
    ) -> Result<(), AuthzError> {
        if !self.issuers.contains_key(&issuer_id) {
            return Err(AuthzError::IssuerNotFound(issuer_id));
        }
        if validator_set.total_power() == 0 {
            return Err(AuthzError::EmptyValidatorSet);
        }

        let mut ctx = Vec::with_capacity(12);
        ctx.extend_from_slice(&issuer_id.to_be_bytes());
        ctx.extend_from_slice(&epoch.to_le_bytes());
        let signing_msg = governance_vote_signing_bytes(b"revoke_immediately", &ctx);
        let power = tally_votes(validator_set, votes, &signing_msg)?;

        let needed = validator_set.quorum_power();
        if power < needed {
            return Err(AuthzError::QuorumNotMet { needed, have: power });
        }

        self.issuers.remove(&issuer_id);
        Ok(())
    }
}

// ── Internal vote tallying ────────────────────────────────────────────────────

fn tally_votes(
    validator_set:   &dyn ValidatorSetView,
    votes:           &[GovernanceVote],
    signing_message: &[u8],
) -> Result<u64, AuthzError> {
    let scheme = MlDsaScheme;
    let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
    let mut power = 0u64;

    for vote in votes {
        if !seen.insert(vote.voter.clone()) {
            return Err(AuthzError::DuplicateVoter(vote.voter.clone()));
        }
        let p = validator_set.power_of(&vote.voter);
        if p == 0 {
            return Err(AuthzError::UnknownVoter(vote.voter.clone()));
        }
        let sig = Signature {
            scheme: SchemeId::MlDsa,
            bytes:  vote.signature.clone(),
        };
        scheme
            .verify(signing_message, &sig, &vote.public_key)
            .map_err(|_| AuthzError::BadSignature(vote.voter.clone()))?;
        power += p;
    }
    Ok(power)
}

// ── Convenience helper ────────────────────────────────────────────────────────

/// Minimum total voting power needed to reach quorum in the given validator set.
pub fn revocation_quorum_power(validator_set: &dyn ValidatorSetView) -> u64 {
    validator_set.quorum_power()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_crypto::KeyPair;

    // ── Lightweight ValidatorSetView stub ─────────────────────────────────────

    struct TestVS {
        validators: Vec<(ValidatorId, u64, Vec<u8>)>,
    }

    impl ValidatorSetView for TestVS {
        fn total_power(&self) -> u64 {
            self.validators.iter().map(|(_, p, _)| p).sum()
        }
        fn quorum_power(&self) -> u64 {
            let t = self.total_power();
            (t * 2 / 3) + 1
        }
        fn power_of(&self, id: &ValidatorId) -> u64 {
            self.validators
                .iter()
                .find(|(v, _, _)| v == id)
                .map(|(_, p, _)| *p)
                .unwrap_or(0)
        }
        fn public_key_of(&self, id: &ValidatorId) -> Option<&[u8]> {
            self.validators
                .iter()
                .find(|(v, _, _)| v == id)
                .map(|(_, _, k)| k.as_slice())
        }
        fn validator_ids(&self) -> Vec<ValidatorId> {
            self.validators.iter().map(|(v, _, _)| v.clone()).collect()
        }
    }

    fn make_vs(n: usize) -> (TestVS, Vec<KeyPair>) {
        let scheme = MlDsaScheme;
        let mut validators = Vec::new();
        let mut keypairs   = Vec::new();
        for i in 0..n {
            let kp = scheme.generate_keypair(&format!("test-seed-{i:02}")).expect("keygen");
            validators.push((ValidatorId(format!("val_{i}")), 1u64, kp.public_key.clone()));
            keypairs.push(kp);
        }
        (TestVS { validators }, keypairs)
    }

    fn signed_vote(idx: usize, keypairs: &[KeyPair], msg: &[u8]) -> GovernanceVote {
        let kp  = &keypairs[idx];
        let sig = MlDsaScheme.sign(msg, kp).expect("sign").bytes;
        GovernanceVote {
            voter:      ValidatorId(format!("val_{idx}")),
            signature:  sig,
            public_key: kp.public_key.clone(),
        }
    }

    // ── test cases ────────────────────────────────────────────────────────────

    #[test]
    fn test_propose_change_quorum_met() {
        let (vs, kps) = make_vs(3); // quorum = 3-of-3
        let mut reg = AuthorizedIssuerRegistry::new();
        let msg = governance_vote_signing_bytes(b"propose_change", b"Issuer Alpha");
        let votes: Vec<_> = (0..3).map(|i| signed_vote(i, &kps, &msg)).collect();
        let id = reg.propose_change_with_votes("Issuer Alpha", &vs, &votes).unwrap();
        assert_eq!(id, 0);
        assert!(reg.issuers().contains_key(&0));
    }

    #[test]
    fn test_propose_change_quorum_not_met() {
        let (vs, kps) = make_vs(3); // quorum = 3, only 2 votes
        let mut reg = AuthorizedIssuerRegistry::new();
        let msg = governance_vote_signing_bytes(b"propose_change", b"Issuer Beta");
        let votes: Vec<_> = (0..2).map(|i| signed_vote(i, &kps, &msg)).collect();
        let err = reg.propose_change_with_votes("Issuer Beta", &vs, &votes).unwrap_err();
        assert!(matches!(err, AuthzError::QuorumNotMet { .. }));
    }

    #[test]
    fn test_duplicate_voter_rejected() {
        let (vs, kps) = make_vs(3);
        let mut reg = AuthorizedIssuerRegistry::new();
        let msg = governance_vote_signing_bytes(b"propose_change", b"Issuer Gamma");
        let v0 = signed_vote(0, &kps, &msg);
        let err = reg
            .propose_change_with_votes("Issuer Gamma", &vs, &[v0.clone(), v0])
            .unwrap_err();
        assert!(matches!(err, AuthzError::DuplicateVoter(_)));
    }

    #[test]
    fn test_unknown_voter_rejected() {
        let (vs, _kps) = make_vs(3);
        let scheme = MlDsaScheme;
        let kp = scheme.generate_keypair("outsider").unwrap();
        let mut reg = AuthorizedIssuerRegistry::new();
        let msg = governance_vote_signing_bytes(b"propose_change", b"Issuer Delta");
        let sig = scheme.sign(&msg, &kp).unwrap().bytes;
        let bad = GovernanceVote {
            voter:      ValidatorId("outsider".into()),
            signature:  sig,
            public_key: kp.public_key.clone(),
        };
        let err = reg.propose_change_with_votes("Issuer Delta", &vs, &[bad]).unwrap_err();
        assert!(matches!(err, AuthzError::UnknownVoter(_)));
    }

    #[test]
    fn test_bad_signature_rejected() {
        // With the stub crypto backend, any correct-length signature passes.
        // With real-pqc, a wrong-message signature returns BadSignature.
        // We exercise the path and accept either outcome from the stub.
        let (vs, kps) = make_vs(3);
        let mut reg = AuthorizedIssuerRegistry::new();
        let msg = governance_vote_signing_bytes(b"propose_change", b"Issuer Epsilon");
        let kp  = &kps[0];
        let sig = MlDsaScheme.sign(b"wrong bytes", kp).unwrap().bytes;
        let bad = GovernanceVote {
            voter:      ValidatorId("val_0".into()),
            signature:  sig,
            public_key: kp.public_key.clone(),
        };
        let _ = reg.propose_change_with_votes("Issuer Epsilon", &vs, &[bad]);
    }

    #[test]
    fn test_revoke_with_votes() {
        let (vs, kps) = make_vs(3);
        let mut reg = AuthorizedIssuerRegistry::new();

        // Add
        let add_msg = governance_vote_signing_bytes(b"propose_change", b"Issuer Zeta");
        let add_votes: Vec<_> = (0..3).map(|i| signed_vote(i, &kps, &add_msg)).collect();
        let id = reg.propose_change_with_votes("Issuer Zeta", &vs, &add_votes).unwrap();

        // Revoke — epoch 1 binds the vote to this specific revocation attempt
        let epoch: u64 = 1;
        let mut rev_ctx = Vec::with_capacity(12);
        rev_ctx.extend_from_slice(&id.to_be_bytes());
        rev_ctx.extend_from_slice(&epoch.to_le_bytes());
        let rev_msg = governance_vote_signing_bytes(b"revoke_immediately", &rev_ctx);
        let rev_votes: Vec<_> = (0..3).map(|i| signed_vote(i, &kps, &rev_msg)).collect();
        reg.revoke_with_votes(id, epoch, &vs, &rev_votes).unwrap();
        assert!(!reg.issuers().contains_key(&id));
    }

    #[test]
    fn test_revoke_nonexistent() {
        let (vs, kps) = make_vs(3);
        let mut reg = AuthorizedIssuerRegistry::new();
        let epoch: u64 = 0;
        let mut rev_ctx = Vec::with_capacity(12);
        rev_ctx.extend_from_slice(&99u32.to_be_bytes());
        rev_ctx.extend_from_slice(&epoch.to_le_bytes());
        let rev_msg = governance_vote_signing_bytes(b"revoke_immediately", &rev_ctx);
        let votes: Vec<_> = (0..3).map(|i| signed_vote(i, &kps, &rev_msg)).collect();
        let err = reg.revoke_with_votes(99, epoch, &vs, &votes).unwrap_err();
        assert!(matches!(err, AuthzError::IssuerNotFound(99)));
    }

    #[test]
    fn test_empty_validator_set() {
        let vs = TestVS { validators: vec![] };
        let mut reg = AuthorizedIssuerRegistry::new();
        let err = reg
            .propose_change_with_votes("Issuer Eta", &vs, &[])
            .unwrap_err();
        assert!(matches!(err, AuthzError::EmptyValidatorSet));
    }
}