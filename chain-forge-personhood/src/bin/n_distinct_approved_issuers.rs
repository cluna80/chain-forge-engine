//! Closes the issuer-validity gap in `n_distinct_issuers`: that circuit only
//! proved the issuer_id fields embedded in your credentials were pairwise
//! distinct — it never checked those issuer_ids were actually on any
//! approved list. A credential from a rogue, revoked, or never-approved
//! issuer would sail through as long as it merely existed in the VRC
//! registry tree.
//!
//! This circuit adds a SECOND registry — a Merkle tree of approved
//! issuer_id values — and requires, for each of the N claimed credentials,
//! an independent membership proof that its issuer_id is in that approved
//! set, bound via equality to the issuer_id extracted from the credential
//! itself. Both registries reuse the same Pedersen/Merkle machinery from
//! the lib; only the leaf content differs (32-byte VRC commitments vs.
//! bare 4-byte issuer_id values), which the generic membership helper
//! doesn't care about.

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_groth16::Groth16;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

use chain_forge_personhood::{
    enforce_membership_and_extract_issuer, make_leaf, root_to_public_inputs, LeafHash,
    LeafHashGadget, RootVar, TwoToOneHash, TwoToOneHashGadget, VrcMembershipPath,
    VrcRegistryTree,
};

const N: usize = 3;

/// One claimed credential: the VRC leaf/path (proves "I hold a registered
/// credential") plus the raw issuer_id bytes/path (proves "and its issuer is
/// on the approved list").
type Credential = (Vec<u8>, VrcMembershipPath, Vec<u8>, VrcMembershipPath);

struct NDistinctApprovedIssuersCircuit {
    vrc_root: Option<<TwoToOneHash as TwoToOneCRHScheme>::Output>,
    issuer_root: Option<<TwoToOneHash as TwoToOneCRHScheme>::Output>,
    credentials: Option<[Credential; N]>,
    leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl ConstraintSynthesizer<Fr> for NDistinctApprovedIssuersCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let vrc_root_val = self.vrc_root.ok_or(SynthesisError::AssignmentMissing)?;
        let vrc_root_var: RootVar =
            AllocVar::new_input(ark_relations::ns!(cs, "vrc_root"), || Ok(vrc_root_val))?;

        let issuer_root_val = self.issuer_root.ok_or(SynthesisError::AssignmentMissing)?;
        let issuer_root_var: RootVar =
            AllocVar::new_input(ark_relations::ns!(cs, "issuer_root"), || Ok(issuer_root_val))?;

        // Both registries share the same hash parameters — allocated once.
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

        let credentials = self.credentials.ok_or(SynthesisError::AssignmentMissing)?;

        let mut issuer_ids: Vec<FpVar<Fr>> = Vec::with_capacity(N);
        for (vrc_leaf, vrc_path, issuer_bytes, issuer_path) in credentials {
            // Leg 1: "I hold this registered VRC credential."
            let issuer_from_vrc = enforce_membership_and_extract_issuer(
                cs.clone(),
                vrc_leaf,
                vrc_path,
                &leaf_params_var,
                &two_to_one_params_var,
                &vrc_root_var,
            )?;

            // Leg 2: "...and its issuer_id is on the approved list." The
            // issuer registry's leaves ARE the raw 4-byte issuer_id, so
            // membership + extraction on the whole leaf gives back the same
            // value in field-element form.
            let issuer_from_registry = enforce_membership_and_extract_issuer(
                cs.clone(),
                issuer_bytes,
                issuer_path,
                &leaf_params_var,
                &two_to_one_params_var,
                &issuer_root_var,
            )?;

            // Bind the two: the issuer_id claimed inside the credential must
            // be the SAME issuer_id whose approval was just proven — without
            // this, the two membership checks would be proving two unrelated
            // facts instead of one coherent claim.
            issuer_from_vrc.enforce_equal(&issuer_from_registry)?;

            issuer_ids.push(issuer_from_vrc);
        }

        // Pairwise distinctness, same as the previous composition.
        for i in 0..N {
            for j in (i + 1)..N {
                issuer_ids[i].enforce_not_equal(&issuer_ids[j])?;
            }
        }

        Ok(())
    }
}

fn main() {
    println!("=== QCB: N-distinct APPROVED issuers ZK proof (N = {N}) ===\n");

    let mut rng = ChaCha20Rng::seed_from_u64(20260926);

    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // ── VRC credential registry (16 entries, power of two) ────────────────────
    // Index 8 is a real, registered credential — but issued under issuer 99,
    // who (see below) is NOT on the approved-issuer list. That's the exact
    // scenario the old circuit couldn't catch: a genuine credential from a
    // rogue/unapproved issuer.
    let issuer_plan: [u32; 16] = [1, 2, 3, 4, 5, 6, 7, 7, 99, 9, 10, 11, 12, 13, 14, 15];
    let vrc_secrets: Vec<Vec<u8>> = issuer_plan.iter().map(|&id| make_leaf(id, &mut rng)).collect();
    let vrc_tree = VrcRegistryTree::new(
        &leaf_crh_params,
        &two_to_one_params,
        vrc_secrets.iter().map(|s| s.as_slice()),
    )
    .unwrap();
    let vrc_root = vrc_tree.root();
    println!("VRC credential registry built: {} credentials.", vrc_secrets.len());

    // ── Approved-issuer allowlist (8 entries, power of two) ────────────────────
    // Issuer 99 is deliberately absent — it has a real credential in the VRC
    // tree above, but it is not (or no longer) an approved issuer.
    let approved_issuers: [u32; 8] = [1, 2, 3, 4, 5, 6, 10, 11];
    let issuer_leaves: Vec<Vec<u8>> =
        approved_issuers.iter().map(|id| id.to_le_bytes().to_vec()).collect();
    let issuer_tree = VrcRegistryTree::new(
        &leaf_crh_params,
        &two_to_one_params,
        issuer_leaves.iter().map(|s| s.as_slice()),
    )
    .unwrap();
    let issuer_root = issuer_tree.root();
    println!(
        "Approved-issuer registry built: {:?} (issuer 99 is deliberately NOT on this list).\n",
        approved_issuers
    );

    let build_credential = |vrc_idx: usize, approved_idx: usize| -> Credential {
        (
            vrc_secrets[vrc_idx].clone(),
            vrc_tree.generate_proof(vrc_idx).unwrap(),
            issuer_leaves[approved_idx].clone(),
            issuer_tree.generate_proof(approved_idx).unwrap(),
        )
    };

    // ── Honest prover: issuers 1, 3, 5 (indices 0, 2, 4) — all approved ────────
    let honest_credentials: [Credential; N] = [
        build_credential(0, 0), // issuer 1 -> approved_issuers[0] = 1
        build_credential(2, 2), // issuer 3 -> approved_issuers[2] = 3
        build_credential(4, 4), // issuer 5 -> approved_issuers[4] = 5
    ];
    println!("Honest prover claims credentials from issuers 1, 3, 5 (all approved).");

    let setup_circuit = NDistinctApprovedIssuersCircuit {
        vrc_root: Some(vrc_root),
        issuer_root: Some(issuer_root),
        credentials: Some(honest_credentials.clone()),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };

    let t0 = Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();
    println!("\nTrusted setup complete in {:?}", t0.elapsed());

    let prove_circuit = NDistinctApprovedIssuersCircuit {
        vrc_root: Some(vrc_root),
        issuer_root: Some(issuer_root),
        credentials: Some(honest_credentials),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };

    let t1 = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, prove_circuit, &mut rng).unwrap();
    println!("Proof generated in {:?}", t1.elapsed());

    let mut proof_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes).unwrap();
    println!("Proof size: {} bytes", proof_bytes.len());

    let mut public_inputs = root_to_public_inputs(&vrc_root);
    public_inputs.extend(root_to_public_inputs(&issuer_root));

    let t2 = Instant::now();
    let valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof).unwrap();
    println!("Verification took {:?}", t2.elapsed());
    println!("\nHonest proof (3 approved, distinct issuers) valid: {valid}");
    assert!(valid, "honest proof with approved issuers must verify");

    // ── Rogue-issuer cheat: swap in the issuer-99 credential (real VRC, ────────
    // unapproved issuer), faking its approval leg with a mismatched path.
    println!("\nDishonest prover swaps in the issuer-99 credential (index 8 in the VRC tree).");
    println!("Issuer 99 has no real path in the approved-issuer tree, so the prover fabricates");
    println!("one by reusing approved_issuers[0]'s path with issuer 99's bytes.");

    let fabricated_issuer_leg = (
        99u32.to_le_bytes().to_vec(),          // claims to be issuer 99...
        issuer_tree.generate_proof(0).unwrap(), // ...but reuses issuer 1's real path
    );
    let rogue_credentials: [Credential; N] = [
        (
            vrc_secrets[8].clone(),
            vrc_tree.generate_proof(8).unwrap(),
            fabricated_issuer_leg.0,
            fabricated_issuer_leg.1,
        ),
        build_credential(2, 2), // issuer 3, still legitimately approved
        build_credential(4, 4), // issuer 5, still legitimately approved
    ];
    let rogue_circuit = NDistinctApprovedIssuersCircuit {
        vrc_root: Some(vrc_root),
        issuer_root: Some(issuer_root),
        credentials: Some(rogue_credentials),
        leaf_crh_params,
        two_to_one_params,
    };

    // The VRC-membership leg for issuer 99 is genuinely valid (it really is a
    // registered credential), so this doesn't hit the inverse-of-zero failure
    // from the duplicate-issuer test. The fabricated approval-path leg simply
    // produces a false membership bit — an ordinary unsatisfied constraint,
    // so prove() succeeds but the resulting proof must fail verification.
    let rogue_proof = Groth16::<Bls12_381>::prove(&pk, rogue_circuit, &mut rng).unwrap();
    let rogue_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &rogue_proof).unwrap_or(false);
    println!(
        "\nRogue-issuer proof verification: {}",
        if rogue_valid { "INCORRECTLY passed (BUG)" } else { "correctly rejected" }
    );
    assert!(!rogue_valid, "a credential from an unapproved issuer must never verify");

    println!("\n=== All checks passed. Issuer-validity gap is closed. ===");
}
