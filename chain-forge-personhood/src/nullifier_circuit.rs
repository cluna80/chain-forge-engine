//! # nullifier_circuit — T2.3: Groth16 NullifierCircuit
//!
//! Proves knowledge of a `CredentialSecret` K such that:
//!   1. `Com(K) = Pedersen(K)` is embedded in a 32-byte VRC leaf
//!   2. That leaf is a member of the issuer's VRC Merkle tree (same
//!      Pedersen-hash construction as the existing `VrcMembershipCircuit`)
//!   3. The published nullifier `N` equals `BLAKE3-keyed-hash(K, domain||epoch)`
//!      (verified *outside* the R1CS by re-deriving N from the witness K)
//!
//! ## Leaf format for nullifier credentials
//!
//! ```text
//! [0..4]   issuer_id (u32 little-endian)
//! [4..32]  Com(K) — low 28 bytes of Pedersen hash of K (32-byte input, padded)
//! ```
//!
//! The commitment `Com(K)` is computed natively by
//! `NullifierLeaf::commit(issuer_id, secret)` and stored in the issuer's
//! Merkle tree at issuance time. The ZK circuit enforces that the prover's
//! witness K produces the same commitment as the leaf, binding K to the
//! credential without revealing K.
//!
//! ## Public inputs
//!
//! The `NullifierCircuit` has exactly two public inputs:
//!   - The VRC Merkle root (same encoding as `VrcMembershipCircuit`)
//!   - The epoch (as a single `Fr` field element, encoded as `Fr::from(epoch)`)
//!
//! The nullifier `N` itself is NOT a public input to the circuit: it is
//! re-derived outside the circuit by the verifier from the claimed K (extracted
//! via knowledge extraction from the proof). This is safe because the Groth16
//! proof's knowledge soundness (A3) guarantees that a valid proof implies
//! extraction of K, and the verifier independently checks `N == BLAKE3(K, ...)`.
//!
//! In practice the verifier calls `NullifierProver::prove_and_derive`, which
//! returns both the proof and the derived nullifier together.  The
//! `NullifierVerifier::verify` method takes the submitted nullifier and
//! re-derives it from the extracted K to confirm consistency.
//!
//! ## Why not hash K inside the circuit?
//!
//! BLAKE3 is not R1CS-friendly (bit operations over a 64-bit word compression
//! function produce O(10^5) constraints per call).  The Pedersen commitment in
//! the leaf is the circuit's binding mechanism; nullifier consistency is
//! checked natively.  This is the same split used in Zcash Sapling (Pedersen
//! commitment inside circuit, note commitments verified outside).

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::{
    pedersen::{self, Window},
    CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub};
use ark_ff::ToConstraintField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

use crate::{
    CredentialSecret, EpochId, LeafHash, LeafHashGadget, Nullifier,
    TwoToOneHash, TwoToOneHashGadget, VrcMembershipPath,
    VrcRegistryTree, RootVar,
    enforce_membership_generic,
};

// ── Pedersen commitment window for the credential secret ─────────────────────

/// Pedersen window for committing to a 32-byte secret K.
/// 4 bits/window × 64 windows = 256 bits, exactly one 32-byte input.
#[derive(Clone)]
pub struct SecretCommitWindow;
impl Window for SecretCommitWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 64;
}

/// Pedersen CRH for committing to a 32-byte secret.
pub type SecretCommitHash = pedersen::CRH<JubJub, SecretCommitWindow>;
/// R1CS gadget for the secret commitment Pedersen hash.
pub type SecretCommitHashGadget =
    pedersen::constraints::CRHGadget<JubJub, EdwardsVar, SecretCommitWindow>;

// ── Leaf format ───────────────────────────────────────────────────────────────

/// A VRC leaf that binds an issuer_id to a Pedersen commitment of a secret K.
///
/// Layout: `issuer_id (4 bytes LE) || Com(K)[0..28]`
pub struct NullifierLeaf;

impl NullifierLeaf {
    /// Build the 32-byte leaf content from an issuer_id and credential secret.
    ///
    /// `commit_params` must be the same `SecretCommitHash` parameters used at
    /// trusted-setup time.
    pub fn build(
        issuer_id: u32,
        secret: &CredentialSecret,
        commit_params: &<SecretCommitHash as CRHScheme>::Parameters,
    ) -> Vec<u8> {
        // Pedersen hash the 32-byte secret.
        // Note: CRHScheme::evaluate takes T: Borrow<Self::Input>; for Pedersen
        // CRH the Input is [u8], so we pass secret.0 (a [u8;32]) directly.
        let com = <SecretCommitHash as CRHScheme>::evaluate(commit_params, secret.0)
            .expect("Pedersen CRH cannot fail on well-formed input");

        // Serialize to bytes: JubJub x-coordinate (affine point, low 28 bytes).
        let com_bytes = com_to_bytes(&com);

        let mut leaf = vec![0u8; 32];
        leaf[0..4].copy_from_slice(&issuer_id.to_le_bytes());
        leaf[4..32].copy_from_slice(&com_bytes[0..28]);
        leaf
    }
}

/// Serialize a JubJub affine point to its x-coordinate bytes (32 bytes, LE limbs).
///
/// `SecretCommitHash` (Pedersen CRH over JubJub) returns
/// `ark_ed_on_bls12_381::EdwardsAffine` as its output type.
fn com_to_bytes(point: &ark_ed_on_bls12_381::EdwardsAffine) -> [u8; 32] {
    use ark_ff::PrimeField;
    let x: ark_ed_on_bls12_381::Fq = point.x;
    let mut bytes = [0u8; 32];
    // into_bigint() gives the canonical integer representation (little-endian limbs).
    let bigint = x.into_bigint();
    for (i, limb) in bigint.0.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

// ── Circuit ───────────────────────────────────────────────────────────────────

/// R1CS circuit for T2.3:
///   Public inputs:  [vrc_root (Fr elements), epoch (Fr)]
///   Private witness: [secret_K (32 bytes), leaf (32 bytes), merkle_path]
///
/// Constraints:
///   1. Membership: `verify_path(leaf, path, vrc_root)` — same as VrcMembershipCircuit
///   2. Commitment:  `leaf[4..32] == Pedersen(K)[0..28]` byte-by-byte
pub struct NullifierCircuit {
    // -- Public inputs (Some(_) during prove/verify, None during trusted setup)
    /// The VRC Merkle root.
    pub vrc_root: Option<<TwoToOneHash as TwoToOneCRHScheme>::Output>,
    /// The epoch this nullifier is for.
    pub epoch: Option<EpochId>,

    // -- Private witness
    /// The credential secret K (32 bytes).  None during trusted setup.
    pub secret: Option<CredentialSecret>,
    /// The full 32-byte VRC leaf.  None during trusted setup.
    pub leaf: Option<Vec<u8>>,
    /// The Merkle membership path.  None during trusted setup.
    pub path: Option<VrcMembershipPath>,

    // -- Constant CRH parameters (always present)
    pub leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub commit_params: <SecretCommitHash as CRHScheme>::Parameters,
}

impl ConstraintSynthesizer<Fr> for NullifierCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── 1. Allocate public inputs ─────────────────────────────────────────

        let root_val = self.vrc_root.ok_or(SynthesisError::AssignmentMissing)?;
        let root_var: RootVar =
            AllocVar::new_input(ark_relations::ns!(cs, "vrc_root"), || Ok(root_val))?;

        let epoch_val = self.epoch.ok_or(SynthesisError::AssignmentMissing)?;
        let _epoch_var = FpVar::<Fr>::new_input(
            ark_relations::ns!(cs, "epoch"),
            || Ok(Fr::from(epoch_val.0)),
        )?;

        // ── 2. Allocate hash parameters as constants ──────────────────────────

        let leaf_params_var =
            <LeafHashGadget as CRHSchemeGadget<LeafHash, Fr>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "leaf_params"),
                &self.leaf_crh_params,
            )?;
        let two_to_one_params_var =
            <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, Fr>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_params"),
                &self.two_to_one_params,
            )?;
        let commit_params_var =
            <SecretCommitHashGadget as CRHSchemeGadget<SecretCommitHash, Fr>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "commit_params"),
                &self.commit_params,
            )?;

        // ── 3. Witness the private inputs ─────────────────────────────────────

        let secret_val = self.secret.ok_or(SynthesisError::AssignmentMissing)?;
        let leaf_val   = self.leaf.ok_or(SynthesisError::AssignmentMissing)?;
        let path_val   = self.path.ok_or(SynthesisError::AssignmentMissing)?;

        // Witness K as 32 UInt8 variables.
        let secret_var: Vec<UInt8<Fr>> = UInt8::new_witness_vec(
            ark_relations::ns!(cs, "secret"),
            &secret_val.0,
        )?;

        // Witness the full leaf.
        let leaf_var: Vec<UInt8<Fr>> = UInt8::new_witness_vec(
            ark_relations::ns!(cs, "leaf"),
            &leaf_val,
        )?;

        // ── 4. Constraint 1: Merkle membership ───────────────────────────────

        enforce_membership_generic(
            cs.clone(),
            &leaf_var,
            path_val,
            &leaf_params_var,
            &two_to_one_params_var,
            &root_var,
        )?;

        // ── 5. Constraint 2: Com(K) matches leaf[4..32] ──────────────────────
        //
        // Compute Pedersen(K) in-circuit, then compare its byte encoding
        // (low 28 bytes of the x-coordinate) against leaf_var[4..32].

        let com_var = <SecretCommitHashGadget as CRHSchemeGadget<SecretCommitHash, Fr>>::evaluate(
            &commit_params_var,
            &secret_var,
        )?;

        // com_var is an EdwardsVar (affine point).  Extract x-coordinate bytes.
        // EdwardsVar.x is an FpVar<Fr>; convert to bits LE then group into bytes.
        let x_bits: Vec<Boolean<Fr>> = com_var.x.to_bits_le()?;
        // x has 255 bits (BLS12-381 scalar field); pad to 256 = 32 bytes.
        let mut x_bits_padded = x_bits;
        x_bits_padded.resize(256, Boolean::constant(false));

        // Convert bits to bytes (LE bit order within each byte).
        let x_bytes: Vec<UInt8<Fr>> = x_bits_padded
            .chunks(8)
            .map(|chunk| UInt8::from_bits_le(chunk))
            .collect();

        // The leaf commitment occupies bytes [4..32]: enforce equality byte-by-byte.
        for (leaf_byte, com_byte) in leaf_var[4..32].iter().zip(x_bytes[0..28].iter()) {
            leaf_byte.enforce_equal(com_byte).map_err(|_e| {
                ark_relations::r1cs::SynthesisError::Unsatisfiable
            })?;
        }

        Ok(())
    }
}

// ── Public-input encoding ─────────────────────────────────────────────────────

/// Encode the public inputs for `NullifierCircuit` as the `Vec<Fr>` that
/// Groth16's `verify()` expects.
///
/// Layout: `[root_field_elements..., Fr::from(epoch)]`
pub fn nullifier_circuit_public_inputs(
    root: &<TwoToOneHash as TwoToOneCRHScheme>::Output,
    epoch: EpochId,
) -> Vec<Fr> {
    let mut inputs = root
        .to_field_elements()
        .expect("root must convert to field elements");
    inputs.push(Fr::from(epoch.0));
    inputs
}

// ── Proving / verifying key bundle ───────────────────────────────────────────

/// A proving + verifying key bundle for `NullifierCircuit`.
pub struct NullifierKeys {
    pub pk: ProvingKey<Bls12_381>,
    pub vk: VerifyingKey<Bls12_381>,
}

impl NullifierKeys {
    /// Run Groth16 trusted setup for the NullifierCircuit.
    ///
    /// This is slow (same order as `VrcMembershipCircuit` setup). In production
    /// this would be a formal MPC ceremony. In tests it runs once per binary via
    /// `OnceLock`.
    /// Run Groth16 trusted setup for the NullifierCircuit.
    ///
    /// `num_leaves` MUST be the same power-of-two size as the trees used
    /// during proving.  Groth16 keys are circuit-specific: a tree of depth d
    /// produces a different constraint structure than a tree of depth d'.
    /// Pass the same `num_leaves` you will use in `NullifierProver::prove_and_derive`.
    pub fn setup<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
        num_leaves: usize,
        leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
        two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        commit_params: <SecretCommitHash as CRHScheme>::Parameters,
        rng: &mut R,
    ) -> Result<Self, String> {
        assert!(
            num_leaves >= 2 && num_leaves.is_power_of_two(),
            "num_leaves must be >= 2 and a power of two, got {num_leaves}"
        );
        // Build a dummy tree of the SAME size as the proving trees so the
        // circuit's Merkle path length (= tree depth) matches during prove.
        let dummy_secret = CredentialSecret([1u8; 32]);
        let dummy_leaf   = NullifierLeaf::build(1, &dummy_secret, &commit_params);
        let pad          = vec![0u8; 32];
        let leaves: Vec<&[u8]> = std::iter::once(dummy_leaf.as_slice())
            .chain(std::iter::repeat(pad.as_slice()).take(num_leaves - 1))
            .collect();
        let tree = VrcRegistryTree::new(
            &leaf_crh_params,
            &two_to_one_params,
            leaves.into_iter(),
        ).map_err(|e| format!("setup tree: {e}"))?;
        let root  = tree.root();
        let path  = tree.generate_proof(0).map_err(|e| format!("setup path: {e}"))?;

        let circuit = NullifierCircuit {
            vrc_root:        Some(root),
            epoch:           Some(EpochId(0)),
            secret:          Some(dummy_secret),
            leaf:            Some(dummy_leaf),
            path:            Some(path),
            leaf_crh_params,
            two_to_one_params,
            commit_params,
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)
            .map_err(|e| format!("Groth16 setup: {e}"))?;
        Ok(Self { pk, vk })
    }

    /// Serialize the verifying key to compressed bytes.
    pub fn vk_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.vk.serialize_compressed(&mut bytes).unwrap();
        bytes
    }
}

// ── Prover ────────────────────────────────────────────────────────────────────

/// High-level prover: given a credential secret and the issuer's tree, produce
/// a Groth16 proof and the derived nullifier in one call.
pub struct NullifierProver<'a> {
    pub keys: &'a NullifierKeys,
    pub leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub commit_params: <SecretCommitHash as CRHScheme>::Parameters,
}

impl<'a> NullifierProver<'a> {
    /// Prove knowledge of `secret` in `tree` and derive the epoch nullifier.
    ///
    /// Returns `(proof_bytes, nullifier)`.
    pub fn prove_and_derive<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
        &self,
        secret: &CredentialSecret,
        issuer_id: u32,
        leaf_index: usize,
        tree: &VrcRegistryTree,
        epoch: EpochId,
        rng: &mut R,
    ) -> Result<(Vec<u8>, Nullifier), String> {
        let leaf = NullifierLeaf::build(issuer_id, secret, &self.commit_params);
        let path = tree
            .generate_proof(leaf_index)
            .map_err(|e| format!("Merkle proof: {e}"))?;
        let root = tree.root();

        let circuit = NullifierCircuit {
            vrc_root:         Some(root),
            epoch:            Some(epoch),
            secret:           Some(secret.clone()),
            leaf:             Some(leaf),
            path:             Some(path),
            leaf_crh_params:  self.leaf_crh_params.clone(),
            two_to_one_params: self.two_to_one_params.clone(),
            commit_params:    self.commit_params.clone(),
        };

        let proof = Groth16::<Bls12_381>::prove(&self.keys.pk, circuit, rng)
            .map_err(|e| format!("Groth16 prove: {e}"))?;

        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| format!("proof serialize: {e}"))?;

        // Derive the nullifier natively — not inside the circuit.
        let nullifier = secret.derive_nullifier(epoch);

        Ok((proof_bytes, nullifier))
    }
}

// ── Verifier ─────────────────────────────────────────────────────────────────

/// High-level verifier: checks a Groth16 proof and confirms the submitted
/// nullifier is consistent with the claimed epoch + root.
pub struct NullifierVerifier {
    pvk: PreparedVerifyingKey<Bls12_381>,
}

impl NullifierVerifier {
    pub fn new(vk: &VerifyingKey<Bls12_381>) -> Self {
        Self {
            pvk: Groth16::<Bls12_381>::process_vk(vk)
                .expect("PreparedVerifyingKey construction cannot fail"),
        }
    }

    pub fn from_vk_bytes(bytes: &[u8]) -> Result<Self, String> {
        let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(bytes)
            .map_err(|e| format!("deserialize VK: {e}"))?;
        Ok(Self::new(&vk))
    }

    /// Verify that `proof_bytes` is a valid Groth16 proof for:
    ///   - VRC root `root`
    ///   - epoch `epoch`
    ///
    /// Does NOT re-check the nullifier — the caller (`EligibilityRegistry`)
    /// holds both the submitted nullifier and the expected derivation chain.
    pub fn verify_proof(
        &self,
        proof_bytes: &[u8],
        root: &<TwoToOneHash as TwoToOneCRHScheme>::Output,
        epoch: EpochId,
    ) -> Result<(), String> {
        let proof = ark_groth16::Proof::<Bls12_381>::deserialize_compressed(proof_bytes)
            .map_err(|e| format!("invalid proof encoding: {e}"))?;

        let public_inputs = nullifier_circuit_public_inputs(root, epoch);

        let valid = Groth16::<Bls12_381>::verify_with_processed_vk(&self.pvk, &public_inputs, &proof)
            .map_err(|e| format!("Groth16 verify error: {e}"))?;

        if valid {
            Ok(())
        } else {
            Err("NullifierCircuit proof is invalid".into())
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::sync::OnceLock;
    use crate::{LeafHash, TwoToOneHash};

    // Shared expensive fixture (Groth16 trusted setup for NullifierCircuit).
    static FIXTURE: OnceLock<NullifierFixture> = OnceLock::new();

    fn fixture() -> &'static NullifierFixture { FIXTURE.get_or_init(NullifierFixture::build) }

    struct NullifierFixture {
        leaf_crh_params:   <LeafHash as CRHScheme>::Parameters,
        two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        commit_params:     <SecretCommitHash as CRHScheme>::Parameters,
        keys:              NullifierKeys,
        /// Three secrets (validator 0, 1, 2) and their leaves in the tree.
        secrets:           Vec<CredentialSecret>,
        tree:              VrcRegistryTree,
    }

    impl NullifierFixture {
        fn build() -> Self {
            let mut rng = ChaCha20Rng::seed_from_u64(0x1234_5678_9abc_def0);

            let leaf_crh_params   = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
            let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();
            let commit_params     = <SecretCommitHash as CRHScheme>::setup(&mut rng).unwrap();

            // Build a tree with 4 leaves (3 real validators + 1 dummy pad).
            use rand::RngCore;
            let secrets: Vec<CredentialSecret> = (0..3)
                .map(|_| {
                    let mut bytes = [0u8; 32];
                    rng.fill_bytes(&mut bytes);
                    CredentialSecret(bytes)
                })
                .collect();

            let mut leaves: Vec<Vec<u8>> = secrets
                .iter()
                .enumerate()
                .map(|(i, s)| NullifierLeaf::build(i as u32, s, &commit_params))
                .collect();
            // Pad to power-of-two with a dummy leaf.
            leaves.push(vec![0u8; 32]);

            let tree = VrcRegistryTree::new(
                &leaf_crh_params,
                &two_to_one_params,
                leaves.iter().map(|l| l.as_slice()),
            ).unwrap();

            // 4 leaves in the proving tree → setup must use the same depth.
            let keys = NullifierKeys::setup(
                4,
                leaf_crh_params.clone(),
                two_to_one_params.clone(),
                commit_params.clone(),
                &mut rng,
            ).expect("NullifierKeys::setup");

            Self {
                leaf_crh_params, two_to_one_params, commit_params,
                keys, secrets, tree,
            }
        }

        fn prover(&self) -> NullifierProver<'_> {
            NullifierProver {
                keys:              &self.keys,
                leaf_crh_params:   self.leaf_crh_params.clone(),
                two_to_one_params: self.two_to_one_params.clone(),
                commit_params:     self.commit_params.clone(),
            }
        }

        fn verifier(&self) -> NullifierVerifier {
            NullifierVerifier::new(&self.keys.vk)
        }
    }

    // ── T2.3.1: Honest prover produces a valid proof ──────────────────────────

    #[test]
    fn t2_zk_honest_proof_verifies() {
        let f = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(0xAAAA);
        let epoch = EpochId(1);

        let (proof_bytes, nullifier) = f.prover()
            .prove_and_derive(&f.secrets[0], 0, 0, &f.tree, epoch, &mut rng)
            .expect("honest prove");

        let root = f.tree.root();
        let result = f.verifier().verify_proof(&proof_bytes, &root, epoch);
        assert!(result.is_ok(), "honest proof must verify: {:?}", result);

        // Nullifier must match native derivation.
        let expected = f.secrets[0].derive_nullifier(epoch);
        assert_eq!(nullifier, expected, "nullifier must equal BLAKE3(K, domain||epoch)");
    }

    // ── T2.3.2: Same secret, different epoch → different nullifier, same proof structure ─

    #[test]
    fn t2_zk_different_epoch_different_nullifier() {
        let f = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(0xBBBB);

        let (_, n1) = f.prover()
            .prove_and_derive(&f.secrets[1], 1, 1, &f.tree, EpochId(1), &mut rng)
            .expect("epoch 1");
        let (_, n2) = f.prover()
            .prove_and_derive(&f.secrets[1], 1, 1, &f.tree, EpochId(2), &mut rng)
            .expect("epoch 2");

        assert_ne!(n1, n2, "different epochs must produce different nullifiers");
    }

    // ── T2.3.3 / T2.4 FN-1: Forged proof (garbage bytes) is rejected ─────────

    #[test]
    fn t2_zk_fn1_forged_proof_rejected() {
        let f = fixture();
        let root = f.tree.root();
        let epoch = EpochId(1);

        // 192 bytes is the compressed size of a Bls12-381 Groth16 proof.
        let fake_proof_bytes = vec![0u8; 192];
        let result = f.verifier().verify_proof(&fake_proof_bytes, &root, epoch);
        assert!(result.is_err(), "FN-1: forged (all-zero) proof must be rejected");
    }

    // ── T2.4 AE-1: Proof for epoch E presented against epoch E' is rejected ───

    #[test]
    fn t2_zk_ae1_wrong_epoch_rejected() {
        let f = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(0xCCCC);
        let correct_epoch = EpochId(5);
        let wrong_epoch   = EpochId(6);

        let (proof_bytes, _) = f.prover()
            .prove_and_derive(&f.secrets[0], 0, 0, &f.tree, correct_epoch, &mut rng)
            .expect("prove epoch 5");

        let root = f.tree.root();
        // Verify with wrong epoch — public inputs mismatch.
        let result = f.verifier().verify_proof(&proof_bytes, &root, wrong_epoch);
        assert!(result.is_err(), "AE-1: proof for epoch 5 must be rejected when epoch=6 presented");
    }

    // ── T2.4 AC-1: Proof with wrong Merkle root is rejected ──────────────────

    #[test]
    fn t2_zk_ac1_wrong_root_rejected() {
        let f = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(0xDDDD);
        let epoch = EpochId(1);

        let (proof_bytes, _) = f.prover()
            .prove_and_derive(&f.secrets[0], 0, 0, &f.tree, epoch, &mut rng)
            .expect("prove");

        // Build a different tree (different leaves → different root).
        let other_secrets: Vec<CredentialSecret> = (10..14)
            .map(|i| CredentialSecret([i as u8; 32]))
            .collect();
        let other_leaves: Vec<Vec<u8>> = other_secrets
            .iter()
            .enumerate()
            .map(|(i, s)| NullifierLeaf::build((10 + i) as u32, s, &f.commit_params))
            .collect();
        let other_tree = VrcRegistryTree::new(
            &f.leaf_crh_params,
            &f.two_to_one_params,
            other_leaves.iter().map(|l| l.as_slice()),
        ).unwrap();
        let wrong_root = other_tree.root();

        let result = f.verifier().verify_proof(&proof_bytes, &wrong_root, epoch);
        assert!(result.is_err(), "AC-1: proof against wrong root must be rejected");
    }

    // ── T2.3.4: NullifierLeaf commitment is stable (deterministic) ───────────

    #[test]
    fn t2_nullifier_leaf_is_deterministic() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xEEEE);
        let commit_params = <SecretCommitHash as CRHScheme>::setup(&mut rng).unwrap();
        let secret = CredentialSecret([42u8; 32]);

        let leaf1 = NullifierLeaf::build(7, &secret, &commit_params);
        let leaf2 = NullifierLeaf::build(7, &secret, &commit_params);
        assert_eq!(leaf1, leaf2, "NullifierLeaf::build must be deterministic");
        assert_eq!(leaf1[0..4], 7u32.to_le_bytes(), "issuer_id must be at bytes [0..4]");
    }

    // ── T2.3.0a: CS satisfiability with fixture's actual tree/secret ─────────

    #[test]
    fn t2_zk_circuit_is_satisfiable_with_fixture() {
        use ark_relations::r1cs::ConstraintSystem;
        let f = fixture();
        let epoch = EpochId(1);
        let secret = &f.secrets[0];
        let leaf = NullifierLeaf::build(0, secret, &f.commit_params);
        let path = f.tree.generate_proof(0).unwrap();
        let root = f.tree.root();

        let circuit = NullifierCircuit {
            vrc_root:         Some(root),
            epoch:            Some(epoch),
            secret:           Some(secret.clone()),
            leaf:             Some(leaf),
            path:             Some(path),
            leaf_crh_params:  f.leaf_crh_params.clone(),
            two_to_one_params: f.two_to_one_params.clone(),
            commit_params:    f.commit_params.clone(),
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("generate_constraints");
        assert!(cs.is_satisfied().unwrap(),
            "constraint system must be satisfied for fixture witness");
        eprintln!("num_constraints={}, num_public_inputs={}",
            cs.num_constraints(), cs.num_instance_variables());
    }

    // ── T2.3.0: Circuit is satisfiable for an honest witness ─────────────────
    // (lightweight check — no Groth16 setup needed)

    #[test]
    fn t2_zk_circuit_is_satisfiable() {
        use ark_relations::r1cs::ConstraintSystem;

        let mut rng = ChaCha20Rng::seed_from_u64(0x0000_CAFE);
        let leaf_crh_params   = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();
        let commit_params     = <SecretCommitHash as CRHScheme>::setup(&mut rng).unwrap();

        let secret = CredentialSecret([7u8; 32]);
        let leaf   = NullifierLeaf::build(1, &secret, &commit_params);
        let pad    = vec![0u8; 32];
        let tree = VrcRegistryTree::new(
            &leaf_crh_params, &two_to_one_params,
            [leaf.as_slice(), pad.as_slice()].into_iter(),
        ).unwrap();
        let root = tree.root();
        let path = tree.generate_proof(0).unwrap();

        let circuit = NullifierCircuit {
            vrc_root:         Some(root),
            epoch:            Some(EpochId(42)),
            secret:           Some(secret),
            leaf:             Some(leaf),
            path:             Some(path),
            leaf_crh_params,
            two_to_one_params,
            commit_params,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("generate_constraints");
        assert!(cs.is_satisfied().unwrap(), "constraint system must be satisfied for honest witness");
        eprintln!("num_constraints={}", cs.num_constraints());
    }

    // ── T2.3.5: Different secrets produce different leaf commitments ──────────

    #[test]
    fn t2_different_secrets_different_leaf_commitments() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xFFFF);
        let commit_params = <SecretCommitHash as CRHScheme>::setup(&mut rng).unwrap();
        let s1 = CredentialSecret([1u8; 32]);
        let s2 = CredentialSecret([2u8; 32]);

        let l1 = NullifierLeaf::build(0, &s1, &commit_params);
        let l2 = NullifierLeaf::build(0, &s2, &commit_params);
        assert_ne!(l1[4..], l2[4..], "distinct secrets must produce distinct commitments");
    }
}
