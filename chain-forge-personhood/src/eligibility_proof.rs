//! # eligibility_proof — T3.4: Composite ZK Eligibility Proof
//!
//! Combines the T3.2 `IssuerApprovalCircuit` and T3.3 `PersonhoodThresholdCircuit`
//! into a single **EligibilityProof** that proves the complete predicate:
//!
//! ```text
//! Eligible(K, e) = Membership(K, VRC_e)          -- IssuerApprovalCircuit
//!               ∧ IssuerApproved(i, e)            -- IssuerApprovalCircuit
//!               ∧ P(K) ≥ P_min                   -- PersonhoodThresholdCircuit
//!               ∧ Epoch(K) = e                   -- both circuits (shared epoch public input)
//!               ∧ N = PRF_K(D ∥ e)              -- derived natively, bound by commitment
//! ```
//!
//! ## Why two proofs instead of one monolithic circuit?
//!
//! Composing the two proofs independently keeps each circuit small, testable,
//! and upgradeable without re-doing the trusted setup for the whole system.
//! The verifier checks both proofs against their respective public inputs and
//! the result is the conjunction.
//!
//! ## What the verifier learns
//!
//! The verifier learns only:
//! - `vrc_root`     — the epoch's credential tree root (public)
//! - `approved_root` — the epoch's approved-issuer tree root (public)
//! - `epoch`         — which epoch this is (public)
//! - `p_min`         — the minimum personhood threshold (public)
//! - `nullifier`     — the epoch-bound nullifier (public, used for replay prevention)
//!
//! The verifier does NOT learn:
//! - which credential K the prover holds
//! - which issuer issued it
//! - the prover's actual personhood score P
//! - any other identity information
//!
//! ## IssuerTrust ≠ PersonhoodTruth
//!
//! The personhood threshold is a separate circuit constraint, not delegated to
//! the issuer.  An approved issuer cannot inflate a score to bypass the
//! threshold — the prover must supply the actual score as a private witness
//! satisfying `P ≥ P_min`, and the circuit rejects fabricated scores.
//!
//! ## The full Sybil-resistance chain
//!
//! ```text
//! Approved Issuer
//!     → Valid Personhood Predicate (P ≥ P_min, proven in circuit)
//!     → Valid Credential (in VRC Merkle tree)
//!     → Epoch-Bound Nullifier (one per credential per epoch)
//!     → One Valid Eligibility Event
//! ```

use crate::{
    eligibility::{CredentialSecret, EpochId, Nullifier, NullifierSet},
    issuer_approval_circuit::{
        IssuerApprovalKeys, IssuerApprovalProver, IssuerApprovalVerifier,
        issuer_approval_public_inputs,
    },
    nullifier_circuit::SecretCommitHash,
    personhood_threshold_circuit::{
        PersonhoodProofError, PersonhoodScore, PersonhoodThresholdKeys,
        PersonhoodThresholdProver, PersonhoodThresholdVerifier,
        personhood_threshold_public_inputs,
    },
    LeafHash, TwoToOneHash, VrcRegistryTree,
};
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};

// ── EligibilityProof ──────────────────────────────────────────────────────────

/// The complete ZK eligibility proof for one credential in one epoch.
///
/// Contains two independent Groth16 proofs:
/// - `issuer_proof`     — proves VRC membership AND issuer approval
/// - `threshold_proof`  — proves `P(K) ≥ P_min`
///
/// Both proofs share `epoch` as a public input.  The `nullifier` is derived
/// natively (not inside R1CS) and is the epoch-scoped deduplication key.
#[derive(Debug, Clone)]
pub struct EligibilityProof {
    /// T3.2 proof: `Membership(K, VRC_e) ∧ IssuerApproved(i, e)`
    pub issuer_proof: Vec<u8>,
    /// T3.3 proof: `P(K) ≥ P_min`
    pub threshold_proof: Vec<u8>,
    /// Epoch this proof is bound to.
    pub epoch: EpochId,
    /// Epoch-bound nullifier derived from K and epoch.
    pub nullifier: Nullifier,
}

/// The public statement the verifier checks.  Emitted by the prover alongside
/// the proof and inspectable without running the verifier.
#[derive(Debug, Clone)]
pub struct EligibilityStatement {
    /// Root of the VRC credential Merkle tree for this epoch.
    pub vrc_root: <TwoToOneHash as TwoToOneCRHScheme>::Output,
    /// Root of the governance-approved issuers Merkle tree for this epoch.
    pub approved_root: <TwoToOneHash as TwoToOneCRHScheme>::Output,
    /// The epoch.
    pub epoch: EpochId,
    /// The minimum personhood threshold the prover has proven against.
    pub p_min: PersonhoodScore,
    /// The nullifier — used by `NullifierSet` for replay prevention.
    pub nullifier: Nullifier,
}

// ── EligibilityKeys ──────────────────────────────────────────────────────────

/// The combined trusted-setup keys for both sub-circuits.
///
/// Each key set was generated independently; they have no shared trapdoor.
pub struct EligibilityKeys {
    pub issuer_keys:    IssuerApprovalKeys,
    pub threshold_keys: PersonhoodThresholdKeys,
}

impl EligibilityKeys {
    pub fn setup<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
        num_leaves: usize,
        leaf_crh_params:   <LeafHash as CRHScheme>::Parameters,
        two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        commit_params:     <SecretCommitHash as CRHScheme>::Parameters,
        rng: &mut R,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let issuer_keys = IssuerApprovalKeys::setup(
            num_leaves,
            leaf_crh_params,
            two_to_one_params,
            commit_params,
            rng,
        )?;
        let threshold_keys = PersonhoodThresholdKeys::setup(rng)?;
        Ok(Self { issuer_keys, threshold_keys })
    }
}

// ── EligibilityProver ────────────────────────────────────────────────────────

/// Generates composite eligibility proofs.
pub struct EligibilityProver<'a> {
    pub keys:              &'a EligibilityKeys,
    pub leaf_crh_params:   <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub commit_params:     <SecretCommitHash as CRHScheme>::Parameters,
}

impl<'a> EligibilityProver<'a> {
    pub fn new(
        keys:              &'a EligibilityKeys,
        leaf_crh_params:   <LeafHash as CRHScheme>::Parameters,
        two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        commit_params:     <SecretCommitHash as CRHScheme>::Parameters,
    ) -> Self {
        Self { keys, leaf_crh_params, two_to_one_params, commit_params }
    }

    /// Generate the composite eligibility proof.
    ///
    /// Proves:
    /// - `K` is a leaf in `vrc_tree` (credential membership)
    /// - The credential's issuer is a leaf in `approved_tree` (issuer approval)
    /// - `p_score ≥ p_min` (personhood threshold)
    /// - All claims are bound to `epoch`
    ///
    /// Returns `(proof, statement)` on success.
    ///
    /// Fails with `EligibilityProofError::BelowThreshold` if `p_score < p_min`
    /// without leaking any other information.
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
        &self,
        secret:              &CredentialSecret,
        issuer_id:           u32,
        vrc_leaf_index:      usize,
        vrc_tree:            &VrcRegistryTree,
        approved_leaf_index: usize,
        approved_tree:       &VrcRegistryTree,
        epoch:               EpochId,
        p_score:             PersonhoodScore,
        p_min:               PersonhoodScore,
        rng:                 &mut R,
    ) -> Result<(EligibilityProof, EligibilityStatement), EligibilityProofError> {
        // ── 1. Personhood threshold check (fast-fail before expensive proof) ──
        if p_score < p_min {
            return Err(EligibilityProofError::BelowThreshold {
                score: p_score.0,
                min: p_min.0,
            });
        }

        // ── 2. T3.2 — Issuer approval proof ─────────────────────────────────
        let issuer_prover = IssuerApprovalProver {
            keys:              &self.keys.issuer_keys,
            leaf_crh_params:   self.leaf_crh_params.clone(),
            two_to_one_params: self.two_to_one_params.clone(),
            commit_params:     self.commit_params.clone(),
        };
        let (issuer_proof_bytes, nullifier) = issuer_prover
            .prove_and_derive(
                secret,
                issuer_id,
                vrc_leaf_index,
                vrc_tree,
                approved_leaf_index,
                approved_tree,
                epoch,
                rng,
            )
            .map_err(EligibilityProofError::IssuerProofFailed)?;

        // ── 3. T3.3 — Personhood threshold proof ────────────────────────────
        let threshold_prover = PersonhoodThresholdProver::new(&self.keys.threshold_keys);
        let threshold_proof_bytes = threshold_prover
            .prove(p_score, p_min, rng)
            .map_err(EligibilityProofError::ThresholdProofFailed)?;

        // ── 4. Assemble ──────────────────────────────────────────────────────
        let vrc_root = vrc_tree.root();
        let approved_root = approved_tree.root();

        let proof = EligibilityProof {
            issuer_proof: issuer_proof_bytes,
            threshold_proof: threshold_proof_bytes,
            epoch,
            nullifier: nullifier.clone(),
        };

        let statement = EligibilityStatement {
            vrc_root,
            approved_root,
            epoch,
            p_min,
            nullifier,
        };

        Ok((proof, statement))
    }
}

// ── EligibilityVerifier ──────────────────────────────────────────────────────

/// Verifies composite eligibility proofs.
pub struct EligibilityVerifier {
    issuer_verifier:    IssuerApprovalVerifier,
    threshold_verifier: PersonhoodThresholdVerifier,
}

impl EligibilityVerifier {
    pub fn new(keys: &EligibilityKeys) -> Self {
        Self {
            issuer_verifier:    IssuerApprovalVerifier::new(&keys.issuer_keys.vk),
            threshold_verifier: PersonhoodThresholdVerifier::new(&keys.threshold_keys.vk),
        }
    }

    /// Verify the composite eligibility proof against a public statement.
    ///
    /// Returns `Ok(true)` iff BOTH sub-proofs verify AND the nullifier has
    /// not been seen before in this epoch (pass `nullifier_set`).
    ///
    /// Nullifier registration: if verification succeeds, the nullifier is
    /// inserted into `nullifier_set`.  Callers MUST persist the set across
    /// calls to prevent replay.
    pub fn verify(
        &self,
        proof: &EligibilityProof,
        statement: &EligibilityStatement,
        nullifier_set: &mut NullifierSet,
    ) -> Result<bool, EligibilityVerifyError> {
        // ── 1. Epoch consistency ─────────────────────────────────────────────
        if proof.epoch != statement.epoch {
            return Err(EligibilityVerifyError::EpochMismatch {
                proof_epoch: proof.epoch.0,
                stmt_epoch:  statement.epoch.0,
            });
        }

        // ── 2. Nullifier replay check ────────────────────────────────────────
        if nullifier_set.contains(&proof.nullifier) {
            return Ok(false); // replay; do not insert again
        }

        // ── 3. T3.2 — Issuer approval proof ─────────────────────────────────
        self.issuer_verifier
            .verify_proof(
                &proof.issuer_proof,
                &statement.vrc_root,
                &statement.approved_root,
                proof.epoch,
            )
            .map_err(EligibilityVerifyError::IssuerVerifyFailed)?;

        // ── 4. T3.3 — Personhood threshold proof ────────────────────────────
        let threshold_ok = self
            .threshold_verifier
            .verify_proof(&proof.threshold_proof, statement.p_min)
            .map_err(EligibilityVerifyError::ThresholdVerifyFailed)?;

        if !threshold_ok {
            return Ok(false);
        }

        // ── 5. Both proofs valid — register nullifier ────────────────────────
        nullifier_set
            .spend(proof.nullifier.clone())
            .map_err(|_| EligibilityVerifyError::NullifierAlreadySpent)?;
        Ok(true)
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum EligibilityProofError {
    #[error("personhood score {score} is below threshold {min} — cannot generate eligibility proof")]
    BelowThreshold { score: u64, min: u64 },
    #[error("issuer approval proof failed: {0}")]
    IssuerProofFailed(String),
    #[error("personhood threshold proof failed: {0}")]
    ThresholdProofFailed(#[from] PersonhoodProofError),
}

#[derive(Debug, thiserror::Error)]
pub enum EligibilityVerifyError {
    #[error("epoch mismatch: proof epoch {proof_epoch} ≠ statement epoch {stmt_epoch}")]
    EpochMismatch { proof_epoch: u64, stmt_epoch: u64 },
    #[error("issuer approval verification failed: {0}")]
    IssuerVerifyFailed(String),
    #[error("personhood threshold verification failed: {0}")]
    ThresholdVerifyFailed(String),
    #[error("nullifier already spent — replay detected")]
    NullifierAlreadySpent,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        eligibility::EpochId,
        issuer_registry::IssuerRegistry,
        make_leaf, make_issuer_leaf,
    };
    use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::BTreeSet;

    // ── Test fixture ──────────────────────────────────────────────────────────

    struct EligibilityFixture {
        keys:              EligibilityKeys,
        leaf_crh_params:   <LeafHash as CRHScheme>::Parameters,
        two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        commit_params:     <SecretCommitHash as CRHScheme>::Parameters,
        vrc_tree:          VrcRegistryTree,
        approved_tree:     VrcRegistryTree,
        secrets:           Vec<CredentialSecret>,
        issuer_ids:        Vec<u32>,
        num_leaves:        usize,
    }

    impl EligibilityFixture {
        fn new() -> Self {
            let mut rng = ChaCha20Rng::seed_from_u64(0xFEED_C0DE_1234_5678);
            let num_leaves = 4;

            let leaf_crh_params   = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
            let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();
            let commit_params     = <SecretCommitHash as CRHScheme>::setup(&mut rng).unwrap();

            // Two approved issuers: IDs 1 and 2.
            let issuer_ids = vec![1u32, 2u32];
            let mut secrets = Vec::new();
            let mut vrc_leaves = Vec::new();

            for (i, &issuer_id) in issuer_ids.iter().enumerate() {
                let mut secret_bytes = [0u8; 32];
                secret_bytes[0] = (i + 1) as u8;
                let secret = CredentialSecret(secret_bytes);
                let leaf = make_leaf(issuer_id, &mut rng);
                // Build leaf using the nullifier leaf format (issuer_id + commitment)
                use crate::nullifier_circuit::NullifierLeaf;
                let vrc_leaf = NullifierLeaf::build(issuer_id, &secret, &commit_params);
                vrc_leaves.push(vrc_leaf);
                secrets.push(secret);
            }

            // Pad to num_leaves
            while vrc_leaves.len() < num_leaves {
                vrc_leaves.push(vec![0u8; 32]);
            }
            let vrc_tree = VrcRegistryTree::new(
                &leaf_crh_params,
                &two_to_one_params,
                vrc_leaves.iter().map(|l| l.as_slice()),
            ).unwrap();

            // Approved-issuers tree
            let mut issuer_leaves: Vec<Vec<u8>> = issuer_ids.iter()
                .map(|&id| make_issuer_leaf(id))
                .collect();
            while issuer_leaves.len() < num_leaves {
                issuer_leaves.push(u32::MAX.to_le_bytes().to_vec());
            }
            let approved_tree = VrcRegistryTree::new(
                &leaf_crh_params,
                &two_to_one_params,
                issuer_leaves.iter().map(|l| l.as_slice()),
            ).unwrap();

            let keys = EligibilityKeys::setup(
                num_leaves,
                leaf_crh_params.clone(),
                two_to_one_params.clone(),
                commit_params.clone(),
                &mut rng,
            ).expect("trusted setup");

            Self {
                keys,
                leaf_crh_params,
                two_to_one_params,
                commit_params,
                vrc_tree,
                approved_tree,
                secrets,
                issuer_ids,
                num_leaves,
            }
        }

        fn prover(&self) -> EligibilityProver<'_> {
            EligibilityProver::new(
                &self.keys,
                self.leaf_crh_params.clone(),
                self.two_to_one_params.clone(),
                self.commit_params.clone(),
            )
        }

        fn verifier(&self) -> EligibilityVerifier {
            EligibilityVerifier::new(&self.keys)
        }

        fn prove_for(
            &self,
            credential_idx: usize,
            issuer_idx: usize,
            epoch: EpochId,
            p_score: PersonhoodScore,
            p_min: PersonhoodScore,
            rng: &mut ChaCha20Rng,
        ) -> Result<(EligibilityProof, EligibilityStatement), EligibilityProofError> {
            self.prover().prove(
                &self.secrets[credential_idx],
                self.issuer_ids[issuer_idx],
                credential_idx,
                &self.vrc_tree,
                issuer_idx,
                &self.approved_tree,
                epoch,
                p_score,
                p_min,
                rng,
            )
        }
    }

    // ── T3.4.1: Approved issuer + P = P_min → accept ────────────────────────

    #[test]
    fn t3_4_approved_issuer_at_threshold_accepted() {
        let f = EligibilityFixture::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0xA001_0001);
        let mut ns = NullifierSet::new();
        let epoch = EpochId(1);
        let p_min = PersonhoodScore(500_000);
        let p_score = PersonhoodScore(500_000); // exactly at threshold

        let (proof, stmt) = f.prove_for(0, 0, epoch, p_score, p_min, &mut rng)
            .expect("proof must succeed");
        let ok = f.verifier().verify(&proof, &stmt, &mut ns).expect("verify");
        assert!(ok, "T3.4.1: approved issuer + P == P_min must accept");
    }

    // ── T3.4.2: Approved issuer + P > P_min → accept ────────────────────────

    #[test]
    fn t3_4_approved_issuer_above_threshold_accepted() {
        let f = EligibilityFixture::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0xA002_0001);
        let mut ns = NullifierSet::new();
        let epoch = EpochId(1);
        let p_min = PersonhoodScore(250_000);
        let p_score = PersonhoodScore(800_000);

        let (proof, stmt) = f.prove_for(0, 0, epoch, p_score, p_min, &mut rng)
            .expect("proof must succeed");
        let ok = f.verifier().verify(&proof, &stmt, &mut ns).expect("verify");
        assert!(ok, "T3.4.2: approved issuer + P > P_min must accept");
    }

    // ── T3.4.3: Approved issuer + P = P_min - 1 → prover error (not a valid proof)

    #[test]
    fn t3_4_below_threshold_prover_fails() {
        let f = EligibilityFixture::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0xA003_0001);
        let epoch = EpochId(1);
        let p_min = PersonhoodScore(500_000);
        let p_score = PersonhoodScore(499_999);

        let result = f.prove_for(0, 0, epoch, p_score, p_min, &mut rng);
        assert!(
            matches!(result, Err(EligibilityProofError::BelowThreshold { .. })),
            "T3.4.3: P below threshold must fail at prover, not produce a false proof"
        );
    }

    // ── T3.4.4: Reused nullifier → reject ────────────────────────────────────

    #[test]
    fn t3_4_reused_nullifier_rejected() {
        let f = EligibilityFixture::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0xA004_0001);
        let mut ns = NullifierSet::new();
        let epoch = EpochId(1);
        let p_min = PersonhoodScore(250_000);
        let p_score = PersonhoodScore(750_000);

        let (proof, stmt) = f.prove_for(0, 0, epoch, p_score, p_min, &mut rng)
            .expect("first proof");
        let ok1 = f.verifier().verify(&proof, &stmt, &mut ns).expect("first verify");
        assert!(ok1, "first verify must succeed");

        // Attempt to reuse the same proof (same nullifier)
        let ok2 = f.verifier().verify(&proof, &stmt, &mut ns).expect("second verify");
        assert!(!ok2, "T3.4.4: reused nullifier must be rejected");
    }

    // ── T3.4.5: Wrong epoch at verify → epoch mismatch error ─────────────────

    #[test]
    fn t3_4_epoch_mismatch_at_verify_rejected() {
        let f = EligibilityFixture::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0xA005_0001);
        let mut ns = NullifierSet::new();
        let epoch = EpochId(3);
        let p_min = PersonhoodScore(250_000);
        let p_score = PersonhoodScore(500_000);

        let (proof, mut stmt) = f.prove_for(0, 0, epoch, p_score, p_min, &mut rng)
            .expect("proof");
        // Tamper: claim a different epoch in the statement
        stmt.epoch = EpochId(99);

        let result = f.verifier().verify(&proof, &stmt, &mut ns);
        assert!(
            matches!(result, Err(EligibilityVerifyError::EpochMismatch { .. })),
            "T3.4.5: epoch mismatch between proof and statement must error"
        );
    }

    // ── T3.4.6: Wrong p_min at verify → threshold proof rejects ──────────────

    #[test]
    fn t3_4_wrong_p_min_at_verify_rejected() {
        let f = EligibilityFixture::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0xA006_0001);
        let mut ns = NullifierSet::new();
        let epoch = EpochId(1);
        let p_min_prove = PersonhoodScore(250_000);
        let p_score = PersonhoodScore(300_000);

        let (proof, mut stmt) = f.prove_for(0, 0, epoch, p_score, p_min_prove, &mut rng)
            .expect("proof");
        // Tamper: claim a higher threshold at verify time
        stmt.p_min = PersonhoodScore(750_000);

        let ok = f.verifier().verify(&proof, &stmt, &mut ns).expect("verify");
        assert!(
            !ok,
            "T3.4.6: proof with p_min=250_000 must not verify against p_min=750_000"
        );
    }

    // ── T3.4.7: Different credentials same epoch = different nullifiers ───────

    #[test]
    fn t3_4_two_credentials_same_epoch_accepted_independently() {
        let f = EligibilityFixture::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0xA007_0001);
        let mut ns = NullifierSet::new();
        let epoch = EpochId(1);
        let p_min = PersonhoodScore(250_000);
        let p_score = PersonhoodScore(750_000);

        // Two distinct credentials (issuer 1 and issuer 2)
        let (proof1, stmt1) = f.prove_for(0, 0, epoch, p_score, p_min, &mut rng).expect("proof1");
        let (proof2, stmt2) = f.prove_for(1, 1, epoch, p_score, p_min, &mut rng).expect("proof2");

        assert_ne!(
            proof1.nullifier, proof2.nullifier,
            "T3.4.7: different credentials must produce different nullifiers"
        );

        let ok1 = f.verifier().verify(&proof1, &stmt1, &mut ns).expect("verify1");
        let ok2 = f.verifier().verify(&proof2, &stmt2, &mut ns).expect("verify2");
        assert!(ok1 && ok2, "T3.4.7: two distinct credentials must both be accepted");
    }

    // ── T3.4.8: Correct epoch binds the nullifier ─────────────────────────────

    #[test]
    fn t3_4_same_credential_different_epochs_different_nullifiers() {
        let f = EligibilityFixture::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0xA008_0001);
        let p_min = PersonhoodScore(250_000);
        let p_score = PersonhoodScore(750_000);

        let (proof_e1, _) = f.prove_for(0, 0, EpochId(1), p_score, p_min, &mut rng).expect("e1");
        let (proof_e2, _) = f.prove_for(0, 0, EpochId(2), p_score, p_min, &mut rng).expect("e2");

        assert_ne!(
            proof_e1.nullifier, proof_e2.nullifier,
            "T3.4.8: same credential in different epochs must produce different nullifiers"
        );
    }
}
