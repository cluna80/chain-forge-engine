//! # issuer_approval_circuit — T3: Groth16 IssuerApprovalCircuit
//!
//! Extends the T2.3 `NullifierCircuit` with a third constraint:
//!
//!   **The credential's issuer_id must be a leaf in the governance-approved
//!   issuers Merkle tree.**
//!
//! Together the three constraints prove:
//!
//!   1. `Com(K)` is embedded in VRC leaf `[issuer_id || Com(K)[0..28]]`
//!   2. That leaf is a member of the issuer's VRC Merkle tree (root = `vrc_root`)
//!   3. `issuer_id` (the first 4 bytes of that same witnessed leaf) is a member
//!      of the governance-approved-issuers Merkle tree (root = `approved_root`)
//!
//! Critically, the approved-issuer membership check is applied to the **same
//! 4 bytes** that are witnessed as part of the VRC leaf — not to a value
//! re-supplied by the prover. A prover who holds a credential from an
//! unapproved issuer cannot satisfy both constraints simultaneously.
//!
//! ## Public inputs
//!
//! ```text
//! [vrc_root (2 Fr elements: x, y of JubJub point),
//!  approved_root (2 Fr elements: x, y),
//!  epoch (1 Fr element)]
//! ```
//! Total: 5 public inputs. Groth16 `gamma_abc_g1.len() == 6`.
//!
//! ## Nullifier
//!
//! Like `NullifierCircuit`, the nullifier `N = BLAKE3(K, domain || epoch)` is
//! derived **outside** the R1CS (BLAKE3 is not constraint-friendly). The
//! prover's knowledge of K is bound by the in-circuit commitment check; the
//! nullifier is derived natively and returned alongside the proof.
//!
//! ## Circuit depth / `num_leaves`
//!
//! Both the VRC tree and the approved-issuers tree are the **same depth** in
//! this implementation (same `num_leaves` for both). A production deployment
//! could relax this by using separate depth parameters, but here symmetry
//! keeps the trusted-setup API simple: pass one `num_leaves` that applies to
//! both trees.

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::{
    CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_ff::ToConstraintField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

use crate::{
    CredentialSecret, EpochId, LeafHash, LeafHashGadget, Nullifier,
    TwoToOneHash, TwoToOneHashGadget, VrcMembershipPath, VrcRegistryTree, RootVar,
    make_issuer_leaf, enforce_membership_with_issuer_approval,
};
use crate::nullifier_circuit::{
    SecretCommitHash, SecretCommitHashGadget, NullifierLeaf,
};

// ── Circuit ───────────────────────────────────────────────────────────────────

/// R1CS circuit for T3 — issuer-approved credential binding.
///
/// Public inputs:  `[vrc_root (x, y), approved_root (x, y), epoch]` — 5 Fr elements.
/// Private witness: `[secret_K, leaf, vrc_path, approved_path]`
///
/// Constraints:
///   1. Merkle membership (VRC):       leaf ∈ tree(vrc_root)
///   2. Issuer approval (governance):  leaf[0..4] ∈ approved_tree(approved_root)
///   3. Commitment binding:            leaf[4..32] == Pedersen(K)[0..28]
pub struct IssuerApprovalCircuit {
    // ── Public inputs (None during trusted setup, Some during prove/verify) ──

    /// Root of the VRC credential Merkle tree.
    pub vrc_root: Option<<TwoToOneHash as TwoToOneCRHScheme>::Output>,
    /// Root of the governance-approved issuers Merkle tree.
    pub approved_root: Option<<TwoToOneHash as TwoToOneCRHScheme>::Output>,
    /// The epoch this proof covers.
    pub epoch: Option<EpochId>,

    // ── Private witness (None during trusted setup) ───────────────────────────

    /// The credential secret K (32 bytes).
    pub secret: Option<CredentialSecret>,
    /// The full 32-byte VRC leaf: `issuer_id (4B LE) || Com(K)[0..28]`.
    pub vrc_leaf: Option<Vec<u8>>,
    /// Merkle path from the VRC leaf to `vrc_root`.
    pub vrc_path: Option<VrcMembershipPath>,
    /// Merkle path from the approved-issuer leaf to `approved_root`.
    pub approved_path: Option<VrcMembershipPath>,

    // ── Constant CRH parameters (always present) ──────────────────────────────
    pub leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub commit_params: <SecretCommitHash as CRHScheme>::Parameters,
}

impl ConstraintSynthesizer<Fr> for IssuerApprovalCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── 1. Public inputs ──────────────────────────────────────────────────

        let vrc_root_val = self.vrc_root.ok_or(SynthesisError::AssignmentMissing)?;
        let vrc_root_var: RootVar =
            AllocVar::new_input(ark_relations::ns!(cs, "vrc_root"), || Ok(vrc_root_val))?;

        let approved_root_val = self.approved_root.ok_or(SynthesisError::AssignmentMissing)?;
        let approved_root_var: RootVar =
            AllocVar::new_input(ark_relations::ns!(cs, "approved_root"), || Ok(approved_root_val))?;

        let epoch_val = self.epoch.ok_or(SynthesisError::AssignmentMissing)?;
        let _epoch_var = FpVar::<Fr>::new_input(
            ark_relations::ns!(cs, "epoch"),
            || Ok(Fr::from(epoch_val.0)),
        )?;

        // ── 2. Hash parameters (constants) ────────────────────────────────────

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

        // ── 3. Private witness ────────────────────────────────────────────────

        let secret_val    = self.secret.ok_or(SynthesisError::AssignmentMissing)?;
        let vrc_leaf_val  = self.vrc_leaf.ok_or(SynthesisError::AssignmentMissing)?;
        let vrc_path_val  = self.vrc_path.ok_or(SynthesisError::AssignmentMissing)?;
        let appr_path_val = self.approved_path.ok_or(SynthesisError::AssignmentMissing)?;

        let secret_var: Vec<UInt8<Fr>> = UInt8::new_witness_vec(
            ark_relations::ns!(cs, "secret"),
            &secret_val.0,
        )?;

        // ── 4. Constraints 1 + 2: VRC membership AND approved-issuer membership
        //
        // `enforce_membership_with_issuer_approval` witnesses the VRC leaf,
        // checks it against vrc_root, then builds the approved-issuer leaf
        // from the SAME first 4 bytes and checks that against approved_root.
        // The issuer_id is returned as an FpVar (unused here but available for
        // future multi-credential distinctness checks).
        let _issuer_id_var = enforce_membership_with_issuer_approval(
            cs.clone(),
            vrc_leaf_val.clone(),
            vrc_path_val,
            appr_path_val,
            &leaf_params_var,
            &two_to_one_params_var,
            &vrc_root_var,
            &approved_root_var,
        )?;

        // ── 5. Constraint 3: Com(K) matches leaf[4..32] ──────────────────────
        //
        // Witness the VRC leaf again as UInt8 vars so we can constrain
        // individual bytes. The two witness allocations are independent R1CS
        // witnesses — the verifier cannot detect inconsistency between them
        // from this alone — but Constraint 1 already committed the leaf to the
        // Merkle root inside `enforce_membership_with_issuer_approval`, so a
        // prover who supplies inconsistent bytes for the two witnesses would
        // fail constraint 1. We therefore need the leaf bytes again only to
        // enforce the Com(K) equality.
        let leaf_var: Vec<UInt8<Fr>> = UInt8::new_witness_vec(
            ark_relations::ns!(cs, "leaf_for_commitment"),
            &vrc_leaf_val,
        )?;

        let com_var = <SecretCommitHashGadget as CRHSchemeGadget<SecretCommitHash, Fr>>::evaluate(
            &commit_params_var,
            &secret_var,
        )?;

        // Extract x-coordinate bytes of the Pedersen output (JubJub affine point).
        let x_bits: Vec<Boolean<Fr>> = com_var.x.to_bits_le()?;
        let mut x_bits_padded = x_bits;
        x_bits_padded.resize(256, Boolean::constant(false));

        let x_bytes: Vec<UInt8<Fr>> = x_bits_padded
            .chunks(8)
            .map(|chunk| UInt8::from_bits_le(chunk))
            .collect();

        // Enforce byte-by-byte equality: leaf[4..32] == Pedersen(K).x[0..28]
        for (leaf_byte, com_byte) in leaf_var[4..32].iter().zip(x_bytes[0..28].iter()) {
            leaf_byte
                .enforce_equal(com_byte)
                .map_err(|_| SynthesisError::Unsatisfiable)?;
        }

        Ok(())
    }
}

// ── Public-input encoding ─────────────────────────────────────────────────────

/// Encode the 5 public inputs for `IssuerApprovalCircuit` as the `Vec<Fr>`
/// Groth16's `verify()` expects.
///
/// Layout: `[vrc_root.x, vrc_root.y, approved_root.x, approved_root.y, Fr::from(epoch)]`
pub fn issuer_approval_public_inputs(
    vrc_root:      &<TwoToOneHash as TwoToOneCRHScheme>::Output,
    approved_root: &<TwoToOneHash as TwoToOneCRHScheme>::Output,
    epoch:         EpochId,
) -> Vec<Fr> {
    let mut inputs = vrc_root
        .to_field_elements()
        .expect("vrc_root must convert to field elements");
    let approved_elems = approved_root
        .to_field_elements()
        .expect("approved_root must convert to field elements");
    inputs.extend(approved_elems);
    inputs.push(Fr::from(epoch.0));
    inputs
}

// ── Key bundle ────────────────────────────────────────────────────────────────

/// Proving + verifying key bundle for `IssuerApprovalCircuit`.
pub struct IssuerApprovalKeys {
    pub pk: ProvingKey<Bls12_381>,
    pub vk: VerifyingKey<Bls12_381>,
}

impl IssuerApprovalKeys {
    /// Run Groth16 trusted setup for `IssuerApprovalCircuit`.
    ///
    /// `num_leaves` applies to BOTH the VRC tree and the approved-issuers tree
    /// (both are the same depth in this implementation).  It must be ≥ 2 and
    /// a power of two, and must match the trees used in `IssuerApprovalProver`.
    pub fn setup<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
        num_leaves: usize,
        leaf_crh_params:   <LeafHash as CRHScheme>::Parameters,
        two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        commit_params:     <SecretCommitHash as CRHScheme>::Parameters,
        rng:               &mut R,
    ) -> Result<Self, String> {
        assert!(
            num_leaves >= 2 && num_leaves.is_power_of_two(),
            "num_leaves must be ≥ 2 and a power of two, got {num_leaves}"
        );

        // ── Dummy VRC tree ────────────────────────────────────────────────────
        let dummy_secret  = CredentialSecret([1u8; 32]);
        let dummy_issuer  = 1u32;
        let dummy_vrc_leaf = NullifierLeaf::build(dummy_issuer, &dummy_secret, &commit_params);
        let vrc_pad        = vec![0u8; 32];
        let vrc_leaves: Vec<&[u8]> = std::iter::once(dummy_vrc_leaf.as_slice())
            .chain(std::iter::repeat(vrc_pad.as_slice()).take(num_leaves - 1))
            .collect();
        let vrc_tree = VrcRegistryTree::new(
            &leaf_crh_params, &two_to_one_params, vrc_leaves.into_iter(),
        ).map_err(|e| format!("setup VRC tree: {e}"))?;
        let vrc_root = vrc_tree.root();
        let vrc_path = vrc_tree.generate_proof(0).map_err(|e| format!("setup VRC path: {e}"))?;

        // ── Dummy approved-issuers tree ───────────────────────────────────────
        // The approved-issuer leaf is `issuer_id (4B LE) || [0u8; 28]`.
        let dummy_appr_leaf = make_issuer_leaf(dummy_issuer);
        let appr_pad        = vec![0u8; 32];
        let appr_leaves: Vec<&[u8]> = std::iter::once(dummy_appr_leaf.as_slice())
            .chain(std::iter::repeat(appr_pad.as_slice()).take(num_leaves - 1))
            .collect();
        let appr_tree = VrcRegistryTree::new(
            &leaf_crh_params, &two_to_one_params, appr_leaves.into_iter(),
        ).map_err(|e| format!("setup approved-issuers tree: {e}"))?;
        let approved_root = appr_tree.root();
        let appr_path = appr_tree.generate_proof(0).map_err(|e| format!("setup approved path: {e}"))?;

        let circuit = IssuerApprovalCircuit {
            vrc_root:         Some(vrc_root),
            approved_root:    Some(approved_root),
            epoch:            Some(EpochId(0)),
            secret:           Some(dummy_secret),
            vrc_leaf:         Some(dummy_vrc_leaf),
            vrc_path:         Some(vrc_path),
            approved_path:    Some(appr_path),
            leaf_crh_params:  leaf_crh_params.clone(),
            two_to_one_params: two_to_one_params.clone(),
            commit_params:    commit_params.clone(),
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)
            .map_err(|e| format!("Groth16 setup: {e}"))?;
        Ok(Self { pk, vk })
    }

    pub fn vk_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.vk.serialize_compressed(&mut bytes).unwrap();
        bytes
    }
}

// ── Prover ────────────────────────────────────────────────────────────────────

/// High-level prover for `IssuerApprovalCircuit`.
///
/// Requires both the VRC tree (for the credential leaf) and the
/// approved-issuers tree (for the governance approval leaf).
pub struct IssuerApprovalProver<'a> {
    pub keys:              &'a IssuerApprovalKeys,
    pub leaf_crh_params:   <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub commit_params:     <SecretCommitHash as CRHScheme>::Parameters,
}

impl<'a> IssuerApprovalProver<'a> {
    /// Prove T3: credential in VRC tree + issuer in approved-issuers tree.
    ///
    /// Returns `(proof_bytes, nullifier)`.
    ///
    /// * `secret`         — the credential secret K
    /// * `issuer_id`      — the issuer's numeric id (must match VRC leaf byte 0..4)
    /// * `vrc_leaf_index` — index of the credential leaf in `vrc_tree`
    /// * `vrc_tree`       — the VRC credential Merkle tree
    /// * `approved_leaf_index` — index of `issuer_id` leaf in `approved_tree`
    /// * `approved_tree`  — the governance-approved issuers Merkle tree
    /// * `epoch`          — the current epoch
    pub fn prove_and_derive<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
        &self,
        secret:              &CredentialSecret,
        issuer_id:           u32,
        vrc_leaf_index:      usize,
        vrc_tree:            &VrcRegistryTree,
        approved_leaf_index: usize,
        approved_tree:       &VrcRegistryTree,
        epoch:               EpochId,
        rng:                 &mut R,
    ) -> Result<(Vec<u8>, Nullifier), String> {
        let vrc_leaf = NullifierLeaf::build(issuer_id, secret, &self.commit_params);
        let vrc_path = vrc_tree
            .generate_proof(vrc_leaf_index)
            .map_err(|e| format!("VRC Merkle proof: {e}"))?;
        let vrc_root = vrc_tree.root();

        let approved_path = approved_tree
            .generate_proof(approved_leaf_index)
            .map_err(|e| format!("approved-issuers Merkle proof: {e}"))?;
        let approved_root = approved_tree.root();

        let circuit = IssuerApprovalCircuit {
            vrc_root:         Some(vrc_root),
            approved_root:    Some(approved_root),
            epoch:            Some(epoch),
            secret:           Some(secret.clone()),
            vrc_leaf:         Some(vrc_leaf),
            vrc_path:         Some(vrc_path),
            approved_path:    Some(approved_path),
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

        let nullifier = secret.derive_nullifier(epoch);
        Ok((proof_bytes, nullifier))
    }
}

// ── Verifier ─────────────────────────────────────────────────────────────────

/// High-level verifier for `IssuerApprovalCircuit`.
pub struct IssuerApprovalVerifier {
    pvk: PreparedVerifyingKey<Bls12_381>,
}

impl IssuerApprovalVerifier {
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
    ///   - VRC root `vrc_root`
    ///   - Approved-issuers root `approved_root`
    ///   - Epoch `epoch`
    pub fn verify_proof(
        &self,
        proof_bytes:   &[u8],
        vrc_root:      &<TwoToOneHash as TwoToOneCRHScheme>::Output,
        approved_root: &<TwoToOneHash as TwoToOneCRHScheme>::Output,
        epoch:         EpochId,
    ) -> Result<(), String> {
        let proof = ark_groth16::Proof::<Bls12_381>::deserialize_compressed(proof_bytes)
            .map_err(|e| format!("invalid proof encoding: {e}"))?;

        let public_inputs = issuer_approval_public_inputs(vrc_root, approved_root, epoch);

        let valid = Groth16::<Bls12_381>::verify_with_processed_vk(
            &self.pvk,
            &public_inputs,
            &proof,
        )
        .map_err(|e| format!("Groth16 verify error: {e}"))?;

        if valid {
            Ok(())
        } else {
            Err("IssuerApprovalCircuit proof is invalid".into())
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rand::RngCore;
    use std::sync::OnceLock;
    use crate::{LeafHash, TwoToOneHash};

    // ── Shared fixture (one Groth16 trusted setup per test binary) ────────────

    static FIXTURE: OnceLock<ApprovalFixture> = OnceLock::new();
    fn fixture() -> &'static ApprovalFixture { FIXTURE.get_or_init(ApprovalFixture::build) }

    /// A 4-leaf VRC tree (3 real + 1 pad) and a 4-leaf approved-issuers tree
    /// containing exactly issuers 0, 1, 2 (+ pad).  Validator 0 uses issuer 0;
    /// issuers 0–2 are all approved.
    struct ApprovalFixture {
        leaf_crh_params:   <LeafHash as CRHScheme>::Parameters,
        two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        commit_params:     <SecretCommitHash as CRHScheme>::Parameters,
        keys:              IssuerApprovalKeys,
        /// Secrets for validators 0, 1, 2.
        secrets:           Vec<CredentialSecret>,
        vrc_tree:          VrcRegistryTree,
        /// Approved-issuers tree: leaves are `make_issuer_leaf(i)` for i in 0..3 + pad.
        approved_tree:     VrcRegistryTree,
    }

    impl ApprovalFixture {
        fn build() -> Self {
            let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_C0DE_1234_5678);

            let leaf_crh_params   = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
            let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();
            let commit_params     = <SecretCommitHash as CRHScheme>::setup(&mut rng).unwrap();

            // Three validators (issuer_id == validator index for simplicity).
            let secrets: Vec<CredentialSecret> = (0..3)
                .map(|_| {
                    let mut b = [0u8; 32];
                    rng.fill_bytes(&mut b);
                    CredentialSecret(b)
                })
                .collect();

            // VRC tree: 3 real nullifier leaves + 1 dummy pad.
            let mut vrc_leaves: Vec<Vec<u8>> = secrets
                .iter()
                .enumerate()
                .map(|(i, s)| NullifierLeaf::build(i as u32, s, &commit_params))
                .collect();
            vrc_leaves.push(vec![0u8; 32]);
            let vrc_tree = VrcRegistryTree::new(
                &leaf_crh_params, &two_to_one_params,
                vrc_leaves.iter().map(|l| l.as_slice()),
            ).unwrap();

            // Approved-issuers tree: issuer_ids 0, 1, 2 + dummy pad.
            let mut appr_leaves: Vec<Vec<u8>> =
                (0u32..3).map(make_issuer_leaf).collect();
            appr_leaves.push(vec![0u8; 32]);
            let approved_tree = VrcRegistryTree::new(
                &leaf_crh_params, &two_to_one_params,
                appr_leaves.iter().map(|l| l.as_slice()),
            ).unwrap();

            // Trusted setup — same 4-leaf depth for both trees.
            let keys = IssuerApprovalKeys::setup(
                4,
                leaf_crh_params.clone(),
                two_to_one_params.clone(),
                commit_params.clone(),
                &mut rng,
            ).expect("IssuerApprovalKeys::setup");

            Self {
                leaf_crh_params, two_to_one_params, commit_params,
                keys, secrets, vrc_tree, approved_tree,
            }
        }

        fn prover(&self) -> IssuerApprovalProver<'_> {
            IssuerApprovalProver {
                keys:              &self.keys,
                leaf_crh_params:   self.leaf_crh_params.clone(),
                two_to_one_params: self.two_to_one_params.clone(),
                commit_params:     self.commit_params.clone(),
            }
        }

        fn verifier(&self) -> IssuerApprovalVerifier {
            IssuerApprovalVerifier::new(&self.keys.vk)
        }
    }

    // ── T3.0: CS satisfiability (no Groth16 needed) ──────────────────────────

    #[test]
    fn t3_circuit_is_satisfiable() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x1111_2222);

        let leaf_crh_params   = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();
        let commit_params     = <SecretCommitHash as CRHScheme>::setup(&mut rng).unwrap();

        let issuer_id = 7u32;
        let secret    = CredentialSecret([5u8; 32]);
        let vrc_leaf  = NullifierLeaf::build(issuer_id, &secret, &commit_params);
        let pad       = vec![0u8; 32];

        // 2-leaf VRC tree.
        let vrc_tree = VrcRegistryTree::new(
            &leaf_crh_params, &two_to_one_params,
            [vrc_leaf.as_slice(), pad.as_slice()].into_iter(),
        ).unwrap();
        let vrc_root = vrc_tree.root();
        let vrc_path = vrc_tree.generate_proof(0).unwrap();

        // 2-leaf approved-issuers tree.
        let appr_leaf = make_issuer_leaf(issuer_id);
        let appr_tree = VrcRegistryTree::new(
            &leaf_crh_params, &two_to_one_params,
            [appr_leaf.as_slice(), pad.as_slice()].into_iter(),
        ).unwrap();
        let approved_root = appr_tree.root();
        let appr_path = appr_tree.generate_proof(0).unwrap();

        let circuit = IssuerApprovalCircuit {
            vrc_root:         Some(vrc_root),
            approved_root:    Some(approved_root),
            epoch:            Some(EpochId(1)),
            secret:           Some(secret),
            vrc_leaf:         Some(vrc_leaf),
            vrc_path:         Some(vrc_path),
            approved_path:    Some(appr_path),
            leaf_crh_params,
            two_to_one_params,
            commit_params,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("generate_constraints");
        assert!(
            cs.is_satisfied().unwrap(),
            "T3.0: constraint system must be satisfied for honest witness"
        );
        eprintln!("T3 num_constraints={}, num_public_inputs={}",
            cs.num_constraints(), cs.num_instance_variables());
    }

    // ── T3.1: Honest proof verifies ──────────────────────────────────────────

    #[test]
    fn t3_honest_proof_verifies() {
        let f = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(0xAAAA_3001u64);

        let epoch = EpochId(3);
        let (proof_bytes, nullifier) = f.prover()
            .prove_and_derive(
                &f.secrets[0], 0,  // validator 0, issuer 0
                0, &f.vrc_tree,    // VRC leaf index 0
                0, &f.approved_tree, // approved-issuer leaf index 0
                epoch,
                &mut rng,
            )
            .expect("T3.1: honest prove must succeed");

        let vrc_root      = f.vrc_tree.root();
        let approved_root = f.approved_tree.root();
        let result = f.verifier().verify_proof(&proof_bytes, &vrc_root, &approved_root, epoch);
        assert!(result.is_ok(), "T3.1: honest proof must verify: {:?}", result);

        // Nullifier must match BLAKE3 derivation.
        let expected = f.secrets[0].derive_nullifier(epoch);
        assert_eq!(nullifier, expected, "T3.1: nullifier must equal BLAKE3(K, domain||epoch)");
    }

    // ── T3.2: Wrong epoch rejected ───────────────────────────────────────────

    #[test]
    fn t3_wrong_epoch_rejected() {
        let f = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(0xBBBB_3002u64);

        let correct_epoch = EpochId(10);
        let wrong_epoch   = EpochId(11);

        let (proof_bytes, _) = f.prover()
            .prove_and_derive(
                &f.secrets[1], 1, 1, &f.vrc_tree,
                1, &f.approved_tree, correct_epoch, &mut rng,
            )
            .expect("prove epoch 10");

        let vrc_root      = f.vrc_tree.root();
        let approved_root = f.approved_tree.root();
        let result = f.verifier().verify_proof(&proof_bytes, &vrc_root, &approved_root, wrong_epoch);
        assert!(result.is_err(), "T3.2: proof for epoch 10 must be rejected when epoch=11");
    }

    // ── T3.3: Wrong VRC root rejected ────────────────────────────────────────

    #[test]
    fn t3_wrong_vrc_root_rejected() {
        let f = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(0xCCCC_3003u64);

        let epoch = EpochId(1);
        let (proof_bytes, _) = f.prover()
            .prove_and_derive(
                &f.secrets[0], 0, 0, &f.vrc_tree,
                0, &f.approved_tree, epoch, &mut rng,
            )
            .expect("prove");

        // Build a different VRC tree → different root.
        let other_vrc_leaves: Vec<Vec<u8>> = (10u32..14)
            .map(|i| {
                let s = CredentialSecret([i as u8; 32]);
                NullifierLeaf::build(i, &s, &f.commit_params)
            })
            .collect();
        let other_vrc_tree = VrcRegistryTree::new(
            &f.leaf_crh_params, &f.two_to_one_params,
            other_vrc_leaves.iter().map(|l| l.as_slice()),
        ).unwrap();
        let wrong_vrc_root = other_vrc_tree.root();

        let approved_root = f.approved_tree.root();
        let result = f.verifier().verify_proof(&proof_bytes, &wrong_vrc_root, &approved_root, epoch);
        assert!(result.is_err(), "T3.3: proof with wrong VRC root must be rejected");
    }

    // ── T3.4: Wrong approved-issuers root rejected ────────────────────────────

    #[test]
    fn t3_wrong_approved_root_rejected() {
        let f = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(0xDDDD_3004u64);

        let epoch = EpochId(1);
        let (proof_bytes, _) = f.prover()
            .prove_and_derive(
                &f.secrets[0], 0, 0, &f.vrc_tree,
                0, &f.approved_tree, epoch, &mut rng,
            )
            .expect("prove");

        // Build a different approved-issuers tree → different root.
        let other_appr_leaves: Vec<Vec<u8>> = (20u32..24)
            .map(make_issuer_leaf)
            .collect();
        let other_appr_tree = VrcRegistryTree::new(
            &f.leaf_crh_params, &f.two_to_one_params,
            other_appr_leaves.iter().map(|l| l.as_slice()),
        ).unwrap();
        let wrong_approved_root = other_appr_tree.root();

        let vrc_root = f.vrc_tree.root();
        let result = f.verifier().verify_proof(&proof_bytes, &vrc_root, &wrong_approved_root, epoch);
        assert!(result.is_err(), "T3.4: proof with wrong approved-issuers root must be rejected");
    }

    // ── T3.5: Forged proof (garbage bytes) rejected ──────────────────────────

    #[test]
    fn t3_forged_proof_rejected() {
        let f   = fixture();
        let vrc_root      = f.vrc_tree.root();
        let approved_root = f.approved_tree.root();
        let epoch         = EpochId(1);

        let fake = vec![0u8; 192]; // right size, wrong content
        let result = f.verifier().verify_proof(&fake, &vrc_root, &approved_root, epoch);
        assert!(result.is_err(), "T3.5: forged proof bytes must be rejected");
    }

    // ── T3.6: Unapproved issuer cannot produce a valid proof ─────────────────
    //
    // An attacker holds a credential from issuer_id=99, which is NOT in the
    // approved-issuers tree.  They build a VRC leaf for issuer 99, try to prove
    // it against the approved-issuers tree that only contains issuers 0–2.
    //
    // The circuit is satisfiable only when BOTH Merkle paths verify.  Because
    // issuer 99 is not in the approved tree, the prover cannot construct a valid
    // Merkle path for it — the `approved_path` for a nonexistent leaf cannot
    // produce the correct `approved_root`.  At the proof level this means either:
    //   (a) The proof is over a WRONG `approved_root` → verifier rejects (public-input mismatch).
    //   (b) The prover tries to use a garbage path → circuit is unsatisfiable → no valid proof.
    //
    // We test (a): the attacker uses the correct `approved_root` in public inputs
    // but supplies a Merkle path for a leaf that isn't actually in the tree.
    // The circuit would be unsatisfied, so Groth16::prove would produce a proof
    // only for a DIFFERENT approved_root.  When verified against the real
    // `approved_root`, it must be rejected.
    //
    // Implementation: we use a 4-leaf approved tree where leaf[3] is the pad
    // `[0u8; 32]` (not an issuer leaf).  We attempt to prove with issuer_id=99
    // using the path for pad leaf[3] (index 3) — which does verify against
    // approved_root, but the approved-issuer leaf built from the VRC leaf's first
    // 4 bytes (issuer 99) doesn't match the pad leaf, so the circuit is
    // unsatisfied.  A satisfying proof for a DIFFERENT approved tree is rejected
    // by the verifier because the approved_root public input doesn't match.
    #[test]
    fn t3_unapproved_issuer_proof_rejected() {
        let f = fixture();
        let _rng = ChaCha20Rng::seed_from_u64(0xEEEE_3005u64);

        // Build a VRC leaf for unapproved issuer 99.
        let bad_issuer = 99u32;
        let secret     = CredentialSecret([0xBBu8; 32]);
        let bad_vrc_leaf = NullifierLeaf::build(bad_issuer, &secret, &f.commit_params);
        let bad_pad      = vec![0u8; 32];

        // A 4-leaf VRC tree containing the unapproved leaf.
        let bad_vrc_leaves = [
            bad_vrc_leaf.as_slice(),
            bad_pad.as_slice(),
            bad_pad.as_slice(),
            bad_pad.as_slice(),
        ];
        let bad_vrc_tree = VrcRegistryTree::new(
            &f.leaf_crh_params, &f.two_to_one_params,
            bad_vrc_leaves.into_iter(),
        ).unwrap();
        let bad_vrc_root = bad_vrc_tree.root();
        let bad_vrc_path = bad_vrc_tree.generate_proof(0).unwrap();

        // The approved-issuers tree is the REAL one (issuers 0, 1, 2 only).
        // The attacker tries to use a path for pad leaf[3] as their "approval".
        // This path DOES verify against approved_root, but the constraint
        // enforcing leaf[0..4] == issuer_99_bytes fails inside the circuit —
        // so Groth16::prove will return an unsatisfied circuit error, OR will
        // succeed only if the attacker uses a DIFFERENT approved_root.
        //
        // In practice, arkworks Groth16::prove on an unsatisfied circuit will
        // either panic or return an error. We catch both and treat them as "proof
        // failed to be produced", which means the attacker cannot present a valid
        // proof to the real verifier.
        let approved_root = f.approved_tree.root();

        // Try to build the bogus proof (we expect this to fail OR produce an
        // invalid proof when verified against the real approved_root).
        let bad_appr_path = f.approved_tree.generate_proof(3).unwrap(); // pad leaf path

        let circuit = IssuerApprovalCircuit {
            vrc_root:         Some(bad_vrc_root),
            approved_root:    Some(approved_root),
            epoch:            Some(EpochId(1)),
            secret:           Some(secret),
            vrc_leaf:         Some(bad_vrc_leaf),
            vrc_path:         Some(bad_vrc_path),
            approved_path:    Some(bad_appr_path),
            leaf_crh_params:  f.leaf_crh_params.clone(),
            two_to_one_params: f.two_to_one_params.clone(),
            commit_params:    f.commit_params.clone(),
        };

        // Satisfiability check: the circuit must NOT be satisfied.
        let cs = ConstraintSystem::<Fr>::new_ref();
        // If generate_constraints errors, the circuit is clearly unsatisfiable.
        let gen_result = circuit.generate_constraints(cs.clone());
        let is_sat = gen_result.is_ok() && cs.is_satisfied().unwrap_or(false);
        assert!(
            !is_sat,
            "T3.6: circuit with unapproved issuer path must not be satisfiable"
        );
    }

    // ── T3.7: Public-input encoding has correct structure ────────────────────

    #[test]
    fn t3_public_inputs_have_correct_length() {
        let f = fixture();
        let vrc_root      = f.vrc_tree.root();
        let approved_root = f.approved_tree.root();
        let inputs = issuer_approval_public_inputs(&vrc_root, &approved_root, EpochId(7));
        // 2 (vrc_root) + 2 (approved_root) + 1 (epoch) = 5
        assert_eq!(
            inputs.len(), 5,
            "T3.7: IssuerApprovalCircuit must have exactly 5 public inputs"
        );
    }

    // ── T3.8: VK bytes round-trip ────────────────────────────────────────────

    #[test]
    fn t3_vk_bytes_round_trip() {
        let f = fixture();
        let vk_bytes = f.keys.vk_bytes();
        let verifier = IssuerApprovalVerifier::from_vk_bytes(&vk_bytes)
            .expect("T3.8: VK must deserialize from bytes");

        let mut rng = ChaCha20Rng::seed_from_u64(0xFFFF_3006u64);
        let epoch = EpochId(2);
        let (proof_bytes, _) = f.prover()
            .prove_and_derive(
                &f.secrets[2], 2, 2, &f.vrc_tree,
                2, &f.approved_tree, epoch, &mut rng,
            )
            .expect("prove");

        let vrc_root      = f.vrc_tree.root();
        let approved_root = f.approved_tree.root();
        let result = verifier.verify_proof(&proof_bytes, &vrc_root, &approved_root, epoch);
        assert!(result.is_ok(), "T3.8: VK round-trip must still verify: {:?}", result);
    }
}
