//! # personhood_threshold_circuit — T3.3: Groth16 PersonhoodThresholdCircuit
//!
//! Proves **`P(K) ≥ P_min`** inside the R1CS without revealing `P(K)`.
//!
//! ## The security gap this closes
//!
//! Prior to this circuit, the personhood gate was a runtime assertion inside
//! `EligibilityRegistry::activate()`:
//!
//! ```text
//! if cred.personhood_factor < self.config.p_min {
//!     return Err(EligibilityError::BelowMinimum { … });
//! }
//! ```
//!
//! That check is invisible to the verifier.  A dishonest node could skip it.
//! This circuit moves the predicate into the Groth16 proof so the verifier
//! can confirm `P ≥ P_min` was enforced — without learning `P`.
//!
//! ## Fixed-point encoding
//!
//! Personhood scores are encoded as integers in `[0, D]` where
//! `D = 1_000_000` (consistent with the CIRFI Protocol Spec §1).  A score of
//! 1.0 (fully-verified) encodes as `1_000_000`; a score of 0.25 encodes as
//! `250_000`.
//!
//! This keeps all arithmetic inside the BLS12-381 scalar field (`Fr`), which
//! has a modulus far above 1_000_000, so range checks are trivially sound.
//!
//! ## Circuit structure
//!
//! ```text
//! Public inputs:  [p_min_fixed (Fr)]
//! Private witness: [p_fixed (Fr)]
//!
//! Constraints:
//!   1. p_fixed ≥ p_min_fixed   (via FpVar::enforce_cmp)
//!   2. p_fixed ∈ [0, D]        (via FpVar::enforce_cmp with zero and D_var)
//! ```
//!
//! The score `p_fixed` is kept private.  The public input `p_min_fixed` is the
//! threshold the whole network agreed to enforce this epoch.
//!
//! ## Composite eligibility
//!
//! This circuit is designed to be composed with `IssuerApprovalCircuit` into
//! the `EligibilityProof` in the T3.4 `eligibility_proof.rs` module, which
//! proves the complete predicate:
//!
//! ```text
//! Eligible(K, e) = Membership(K, VRC_e)
//!               ∧ IssuerApproved(i, e)
//!               ∧ P(K) ≥ P_min
//!               ∧ Epoch(K) = e
//!               ∧ N = PRF_K(D ∥ e)
//! ```
//!
//! ## IssuerTrust ≠ PersonhoodTruth
//!
//! The circuit keeps issuer approval and personhood threshold as separate
//! constraints.  A compromised approved issuer cannot bypass the threshold
//! by issuing a credential with an inflated score — the score witness is
//! bound inside the proof, not trusted from the issuer.  (In T3.4 the
//! credential commitment binds `P`; here we prove the predicate on that
//! committed `P`.)

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey,
};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use std::cmp::Ordering;

/// Fixed-point denominator: score 1.0 = 1_000_000.
pub const PERSONHOOD_D: u64 = 1_000_000;

/// A personhood score encoded as a fixed-point integer in `[0, PERSONHOOD_D]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PersonhoodScore(pub u64);

impl PersonhoodScore {
    /// Encode an `f64` score in `[0.0, 1.0]` as fixed-point.
    /// Panics if out of range — call sites should validate first.
    pub fn from_f64(v: f64) -> Self {
        assert!((0.0..=1.0).contains(&v), "personhood score must be in [0.0, 1.0]");
        PersonhoodScore((v * PERSONHOOD_D as f64).round() as u64)
    }

    pub fn as_fr(self) -> Fr {
        Fr::from(self.0)
    }
}

// ── Circuit ─────────────────────────────────────────────────────────────────

/// R1CS circuit proving `P ≥ P_min` without revealing `P`.
///
/// Public inputs  : `[p_min_fixed]`  — the minimum threshold as a fixed-point u64 in `[0, D]`
/// Private witness: `[p_fixed]`      — the actual score, kept private
#[derive(Clone)]
pub struct PersonhoodThresholdCircuit {
    /// Public: the minimum threshold this epoch (encoded as `[0, PERSONHOOD_D]`).
    pub p_min: PersonhoodScore,
    /// Private: the actual personhood score.  `None` during trusted setup.
    pub p_score: Option<PersonhoodScore>,
}

impl ConstraintSynthesizer<Fr> for PersonhoodThresholdCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── 1. Public input: p_min ────────────────────────────────────────────
        let p_min_var = FpVar::<Fr>::new_input(
            ark_relations::ns!(cs, "p_min"),
            || Ok(self.p_min.as_fr()),
        )?;

        // ── 2. Private witness: p_score ───────────────────────────────────────
        let p_score_val = self
            .p_score
            .ok_or(SynthesisError::AssignmentMissing)?
            .as_fr();
        let p_var = FpVar::<Fr>::new_witness(
            ark_relations::ns!(cs, "p_score"),
            || Ok(p_score_val),
        )?;

        // ── 3. Constraint: p_score ∈ [0, PERSONHOOD_D] ───────────────────────
        // p_score ≥ 0: FpVar represents field elements; negative values
        // would wrap around the field modulus and fail the upper bound check.
        // Enforce 0 ≤ p_score by checking p_score ≥ 0 (trivially true for
        // non-negative encoding) and p_score ≤ D.
        let zero_var = FpVar::<Fr>::new_constant(
            ark_relations::ns!(cs, "zero"),
            Fr::from(0u64),
        )?;
        let d_var = FpVar::<Fr>::new_constant(
            ark_relations::ns!(cs, "d"),
            Fr::from(PERSONHOOD_D),
        )?;

        // p_score ≥ 0 (i.e., p_score > 0 OR p_score == 0)
        p_var.enforce_cmp(&zero_var, Ordering::Greater, /*or equal*/ true)?;
        // p_score ≤ D
        d_var.enforce_cmp(&p_var, Ordering::Greater, /*or equal*/ true)?;

        // ── 4. Constraint: p_score ≥ p_min ───────────────────────────────────
        // This is the core predicate.  enforce_cmp checks the comparison and
        // fails constraint satisfaction if p_var < p_min_var.
        p_var.enforce_cmp(&p_min_var, Ordering::Greater, /*or equal*/ true)?;

        Ok(())
    }
}

// ── Public input encoding ────────────────────────────────────────────────────

/// Encode the public inputs for `PersonhoodThresholdCircuit` as `Vec<Fr>`.
pub fn personhood_threshold_public_inputs(p_min: PersonhoodScore) -> Vec<Fr> {
    vec![p_min.as_fr()]
}

// ── Keys ────────────────────────────────────────────────────────────────────

/// Proving and verifying keys for `PersonhoodThresholdCircuit`.
pub struct PersonhoodThresholdKeys {
    pub pk: ProvingKey<Bls12_381>,
    pub vk: VerifyingKey<Bls12_381>,
}

impl PersonhoodThresholdKeys {
    /// Generate a new trusted setup.  `p_min` is used only as a dummy during
    /// setup; the actual threshold is a public input at prove/verify time.
    pub fn setup<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
        rng: &mut R,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let dummy_circuit = PersonhoodThresholdCircuit {
            p_min:   PersonhoodScore(0),
            p_score: Some(PersonhoodScore(0)),
        };
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, rng)
            .map_err(|e| format!("trusted setup failed: {e}"))?;
        Ok(Self { pk, vk })
    }

    pub fn vk_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.vk.serialize_uncompressed(&mut buf).expect("vk serialize");
        buf
    }
}

// ── Prover ──────────────────────────────────────────────────────────────────

/// Generates Groth16 proofs that `p_score ≥ p_min`.
pub struct PersonhoodThresholdProver<'a> {
    pub keys: &'a PersonhoodThresholdKeys,
}

impl<'a> PersonhoodThresholdProver<'a> {
    pub fn new(keys: &'a PersonhoodThresholdKeys) -> Self {
        Self { keys }
    }

    /// Prove that `p_score ≥ p_min`.
    ///
    /// Returns an error if `p_score < p_min` — the constraint system cannot
    /// be satisfied, so the prover fails rather than producing a false proof.
    pub fn prove<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
        &self,
        p_score: PersonhoodScore,
        p_min: PersonhoodScore,
        rng: &mut R,
    ) -> Result<Vec<u8>, PersonhoodProofError> {
        if p_score < p_min {
            return Err(PersonhoodProofError::BelowThreshold {
                score: p_score.0,
                min: p_min.0,
            });
        }
        if p_score.0 > PERSONHOOD_D {
            return Err(PersonhoodProofError::ScoreOutOfRange(p_score.0));
        }

        let circuit = PersonhoodThresholdCircuit {
            p_min,
            p_score: Some(p_score),
        };

        let proof = Groth16::<Bls12_381>::prove(&self.keys.pk, circuit, rng)
            .map_err(|e| PersonhoodProofError::ProvingFailed(e.to_string()))?;

        let mut proof_bytes = Vec::new();
        proof
            .serialize_uncompressed(&mut proof_bytes)
            .map_err(|e| PersonhoodProofError::ProvingFailed(e.to_string()))?;
        Ok(proof_bytes)
    }
}

// ── Verifier ─────────────────────────────────────────────────────────────────

/// Verifies Groth16 proofs for `PersonhoodThresholdCircuit`.
pub struct PersonhoodThresholdVerifier {
    pvk: PreparedVerifyingKey<Bls12_381>,
}

impl PersonhoodThresholdVerifier {
    pub fn new(vk: &VerifyingKey<Bls12_381>) -> Self {
        Self {
            pvk: prepare_verifying_key(vk),
        }
    }

    pub fn from_vk_bytes(bytes: &[u8]) -> Result<Self, String> {
        let vk = VerifyingKey::<Bls12_381>::deserialize_uncompressed(bytes)
            .map_err(|e| format!("vk deserialize: {e}"))?;
        Ok(Self::new(&vk))
    }

    /// Verify that the proof asserts `P ≥ p_min`.
    ///
    /// The verifier learns only `p_min` — not the prover's actual score.
    pub fn verify_proof(
        &self,
        proof_bytes: &[u8],
        p_min: PersonhoodScore,
    ) -> Result<bool, String> {
        let proof =
            ark_groth16::Proof::<Bls12_381>::deserialize_uncompressed(proof_bytes)
                .map_err(|e| format!("proof deserialize: {e}"))?;
        let public_inputs = personhood_threshold_public_inputs(p_min);
        Groth16::<Bls12_381>::verify_with_processed_vk(&self.pvk, &public_inputs, &proof)
            .map_err(|e| format!("groth16 verify: {e}"))
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PersonhoodProofError {
    #[error("personhood score {score} is below threshold {min} — cannot produce a valid proof")]
    BelowThreshold { score: u64, min: u64 },
    #[error("personhood score {0} exceeds PERSONHOOD_D={}", PERSONHOOD_D)]
    ScoreOutOfRange(u64),
    #[error("proving failed: {0}")]
    ProvingFailed(String),
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;

    // ── Constraint-system satisfaction tests (no trusted setup needed) ────────

    fn check_constraints(p_score: u64, p_min: u64) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = PersonhoodThresholdCircuit {
            p_min:   PersonhoodScore(p_min),
            p_score: Some(PersonhoodScore(p_score)),
        };
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn t3_3_score_equals_p_min_satisfies() {
        assert!(
            check_constraints(500_000, 500_000),
            "P == P_min must satisfy: equality is accepted"
        );
    }

    #[test]
    fn t3_3_score_above_p_min_satisfies() {
        assert!(
            check_constraints(750_000, 500_000),
            "P > P_min must satisfy"
        );
    }

    #[test]
    fn t3_3_score_below_p_min_fails() {
        assert!(
            !check_constraints(499_999, 500_000),
            "P < P_min must NOT satisfy: threshold not met"
        );
    }

    #[test]
    fn t3_3_full_score_satisfies_any_threshold() {
        for p_min in [0, 250_000, 500_000, 750_000, 999_999, 1_000_000] {
            assert!(
                check_constraints(PERSONHOOD_D, p_min),
                "full score must pass any threshold"
            );
        }
    }

    #[test]
    fn t3_3_zero_threshold_accepts_any_score() {
        for score in [0, 1, 250_000, 500_000, 1_000_000] {
            assert!(
                check_constraints(score, 0),
                "zero threshold must accept any score"
            );
        }
    }

    #[test]
    fn t3_3_score_exceeds_d_fails() {
        // D+1 should fail the upper-bound constraint.
        assert!(
            !check_constraints(PERSONHOOD_D + 1, 0),
            "score > D must NOT satisfy: out of range"
        );
    }

    #[test]
    fn t3_3_boundary_one_below_fails() {
        assert!(
            !check_constraints(249_999, 250_000),
            "one below threshold must fail"
        );
    }

    // ── Public-input encoding ────────────────────────────────────────────────

    #[test]
    fn t3_3_public_inputs_length() {
        let inputs = personhood_threshold_public_inputs(PersonhoodScore(500_000));
        assert_eq!(
            inputs.len(),
            1,
            "PersonhoodThresholdCircuit must have exactly 1 public input (p_min)"
        );
    }

    // ── Full Groth16 round-trip ───────────────────────────────────────────────

    struct ThresholdFixture {
        keys: PersonhoodThresholdKeys,
    }

    impl ThresholdFixture {
        fn new() -> Self {
            let mut rng = ChaCha20Rng::seed_from_u64(0xC0DE_1337_ABCD_EF01);
            let keys = PersonhoodThresholdKeys::setup(&mut rng).expect("trusted setup");
            Self { keys }
        }

        fn prover(&self) -> PersonhoodThresholdProver<'_> {
            PersonhoodThresholdProver::new(&self.keys)
        }

        fn verifier(&self) -> PersonhoodThresholdVerifier {
            PersonhoodThresholdVerifier::new(&self.keys.vk)
        }
    }

    #[test]
    fn t3_3_groth16_score_at_threshold_accepted() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x0001_A001);
        let f = ThresholdFixture::new();
        let p_min = PersonhoodScore(500_000);
        let p_score = PersonhoodScore(500_000); // exactly at threshold

        let proof_bytes = f.prover().prove(p_score, p_min, &mut rng).expect("prove");
        let ok = f.verifier().verify_proof(&proof_bytes, p_min).expect("verify");
        assert!(ok, "proof for P == P_min must verify");
    }

    #[test]
    fn t3_3_groth16_score_above_threshold_accepted() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x0002_A002);
        let f = ThresholdFixture::new();
        let p_min = PersonhoodScore(250_000);
        let p_score = PersonhoodScore(800_000);

        let proof_bytes = f.prover().prove(p_score, p_min, &mut rng).expect("prove");
        let ok = f.verifier().verify_proof(&proof_bytes, p_min).expect("verify");
        assert!(ok, "proof for P > P_min must verify");
    }

    #[test]
    fn t3_3_groth16_score_below_threshold_prover_errors() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x0003_A003);
        let f = ThresholdFixture::new();
        let p_min = PersonhoodScore(500_000);
        let p_score = PersonhoodScore(499_999);

        let result = f.prover().prove(p_score, p_min, &mut rng);
        assert!(
            matches!(result, Err(PersonhoodProofError::BelowThreshold { .. })),
            "prover must return BelowThreshold error, not a malformed proof"
        );
    }

    #[test]
    fn t3_3_groth16_wrong_p_min_at_verify_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x0004_A004);
        let f = ThresholdFixture::new();
        let p_min_prove = PersonhoodScore(250_000);
        let p_score = PersonhoodScore(300_000);

        // Prove with a low threshold
        let proof_bytes = f
            .prover()
            .prove(p_score, p_min_prove, &mut rng)
            .expect("prove");

        // Try to verify against a HIGHER threshold — the public input won't match
        let p_min_verify = PersonhoodScore(750_000);
        let ok = f
            .verifier()
            .verify_proof(&proof_bytes, p_min_verify)
            .expect("verify call");
        assert!(
            !ok,
            "T3.3: proof produced with p_min=250_000 must not verify against p_min=750_000"
        );
    }

    #[test]
    fn t3_3_groth16_full_score_any_threshold() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x0005_A005);
        let f = ThresholdFixture::new();
        let p_score = PersonhoodScore(PERSONHOOD_D);

        for p_min_val in [0u64, 250_000, 500_000, 750_000, 1_000_000] {
            let p_min = PersonhoodScore(p_min_val);
            let proof_bytes = f.prover().prove(p_score, p_min, &mut rng).expect("prove");
            let ok = f.verifier().verify_proof(&proof_bytes, p_min).expect("verify");
            assert!(ok, "full score must verify against p_min={p_min_val}");
        }
    }

    // ── Adversarial boundary: IssuerTrust ≠ PersonhoodTruth ─────────────────

    #[test]
    fn t3_3_issuer_approval_cannot_skip_threshold() {
        // Simulate: an attacker holds an approved-issuer credential but their
        // personhood score is P=0.  They try to prove P ≥ P_min with P_min=1.
        // The prover MUST fail — issuer approval alone is not enough.
        let mut rng = ChaCha20Rng::seed_from_u64(0x0006_A006);
        let f = ThresholdFixture::new();
        let p_score = PersonhoodScore(0);
        let p_min = PersonhoodScore(1);

        let result = f.prover().prove(p_score, p_min, &mut rng);
        assert!(
            matches!(result, Err(PersonhoodProofError::BelowThreshold { .. })),
            "P=0 with p_min=1 must fail even if issuer is approved"
        );
    }

    #[test]
    fn t3_3_from_f64_encoding_correct() {
        let s = PersonhoodScore::from_f64(0.5);
        assert_eq!(s.0, 500_000, "0.5 * D must encode as 500_000");
        let s = PersonhoodScore::from_f64(1.0);
        assert_eq!(s.0, 1_000_000);
        let s = PersonhoodScore::from_f64(0.0);
        assert_eq!(s.0, 0);
        let s = PersonhoodScore::from_f64(0.25);
        assert_eq!(s.0, 250_000);
    }
}
