//! "I hold VRC credentials from ≥3 distinct issuers, all registered in the
//! on-chain VRC registry" — without revealing which credentials, which
//! issuers, or any nonce.
//!
//! Composition of the single-membership circuit: run N (=3) independent
//! Merkle-membership checks against the SAME public root, then add a
//! pairwise distinctness constraint over the issuer_id extracted from each.
//! One Groth16 proof covers all of it — the verifier still only sees the
//! root and a constant-size proof.

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

struct NDistinctIssuersCircuit {
    root: Option<<TwoToOneHash as TwoToOneCRHScheme>::Output>,
    /// N (leaf, path) pairs — one per claimed credential.
    credentials: Option<[(Vec<u8>, VrcMembershipPath); N]>,
    leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl ConstraintSynthesizer<Fr> for NDistinctIssuersCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root_val = self.root.ok_or(SynthesisError::AssignmentMissing)?;
        let root_var: RootVar =
            AllocVar::new_input(ark_relations::ns!(cs, "root"), || Ok(root_val))?;

        // Allocated once, shared across all N membership checks below.
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

        // Each credential must independently be a member of the SAME
        // registry root, and each one yields its issuer_id as a witness.
        let mut issuer_ids: Vec<FpVar<Fr>> = Vec::with_capacity(N);
        for (leaf, path) in credentials {
            let issuer_id = enforce_membership_and_extract_issuer(
                cs.clone(),
                leaf,
                path,
                &leaf_params_var,
                &two_to_one_params_var,
                &root_var,
            )?;
            issuer_ids.push(issuer_id);
        }

        // Pairwise distinctness: for every pair (i, j), issuer_ids[i] != issuer_ids[j].
        // This is the whole point of the circuit — without it, one issuer's
        // credential reused three times would satisfy "3 memberships" but
        // must NOT satisfy "3 distinct issuers".
        for i in 0..N {
            for j in (i + 1)..N {
                issuer_ids[i].enforce_not_equal(&issuer_ids[j])?;
            }
        }

        Ok(())
    }
}

fn main() {
    println!("=== QCB: N-distinct-issuers ZK proof (N = {N}) ===\n");

    let mut rng = ChaCha20Rng::seed_from_u64(20260926);

    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // Build a registry of 16 VRCs from a mix of issuers (arkworks' Merkle
    // tree requires a power-of-two leaf count). Issuer 7 appears twice (two
    // different credentials, same issuer), which is exactly the case the
    // distinctness constraint has to catch.
    let issuer_plan: [u32; 16] = [1, 2, 3, 4, 5, 6, 7, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let vrc_secrets: Vec<Vec<u8>> = issuer_plan.iter().map(|&id| make_leaf(id, &mut rng)).collect();

    let tree = VrcRegistryTree::new(
        &leaf_crh_params,
        &two_to_one_params,
        vrc_secrets.iter().map(|s| s.as_slice()),
    )
    .unwrap();
    let root = tree.root();
    println!("VRC registry built: {} credentials from {} issuer slots.", vrc_secrets.len(), issuer_plan.len());

    // ── Honest prover: indices 0, 2, 4 → issuers 1, 3, 5 (all distinct) ────────
    let honest_indices = [0usize, 2, 4];
    let honest_credentials: [(Vec<u8>, VrcMembershipPath); N] = honest_indices.map(|idx| {
        (vrc_secrets[idx].clone(), tree.generate_proof(idx).unwrap())
    });
    println!(
        "Honest prover claims credentials at indices {:?} (issuers {:?}).",
        honest_indices,
        honest_indices.map(|i| issuer_plan[i])
    );

    let setup_circuit = NDistinctIssuersCircuit {
        root: Some(root),
        credentials: Some(honest_credentials.clone()),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };

    let t0 = Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();
    println!("\nTrusted setup complete in {:?}", t0.elapsed());

    let prove_circuit = NDistinctIssuersCircuit {
        root: Some(root),
        credentials: Some(honest_credentials),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };

    let t1 = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, prove_circuit, &mut rng).unwrap();
    println!("Proof generated in {:?}", t1.elapsed());

    let mut proof_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes).unwrap();
    println!("Proof size: {} bytes (same constant size as a single-membership proof)", proof_bytes.len());

    let public_inputs = root_to_public_inputs(&root);

    let t2 = Instant::now();
    let valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof).unwrap();
    println!("Verification took {:?}", t2.elapsed());
    println!("\nHonest proof (3 distinct issuers) valid: {valid}");
    assert!(valid, "honest 3-distinct-issuer proof must verify");

    // ── Dishonest prover: indices 6, 7, 4 → issuers 7, 7, 5 (issuer 7 reused) ──
    let cheat_indices = [6usize, 7, 4];
    println!(
        "\nDishonest prover claims credentials at indices {:?} (issuers {:?}) — issuer 7 reused.",
        cheat_indices,
        cheat_indices.map(|i| issuer_plan[i])
    );
    let cheat_credentials: [(Vec<u8>, VrcMembershipPath); N] = cheat_indices.map(|idx| {
        (vrc_secrets[idx].clone(), tree.generate_proof(idx).unwrap())
    });
    let cheat_circuit = NDistinctIssuersCircuit {
        root: Some(root),
        credentials: Some(cheat_credentials),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };
    // Unlike Tier 1's tamper test, this failure shows up EARLIER than
    // verification. `enforce_not_equal` on two equal field elements requires
    // witnessing the inverse of their difference — and the inverse of zero
    // doesn't exist. A dishonest prover literally cannot compute that
    // witness, so `prove()` itself fails; there's no proof to even attempt
    // to verify. That's a stronger guarantee than "wait for verify() to
    // catch it" — the cheat is caught at the earliest possible point.
    match Groth16::<Bls12_381>::prove(&pk, cheat_circuit, &mut rng) {
        Err(e) => {
            println!(
                "Dishonest proof (issuer 7 used twice): prove() itself failed ({e:?}) — \
                 the required distinctness witness (an inverse of zero) doesn't exist."
            );
        }
        Ok(cheat_proof) => {
            // Some circuit/library versions might instead defer the failure
            // to verification (e.g. if a fallback witness of 0 is used for a
            // missing inverse). Handle that path too, for robustness.
            let cheat_valid =
                Groth16::<Bls12_381>::verify(&vk, &public_inputs, &cheat_proof).unwrap_or(false);
            println!(
                "Dishonest proof (issuer 7 used twice) verification: {}",
                if cheat_valid { "INCORRECTLY passed (BUG)" } else { "correctly rejected" }
            );
            assert!(!cheat_valid, "reusing the same issuer twice must never verify");
        }
    }

    println!("\n=== All checks passed. N-distinct-issuers composition works end-to-end. ===");
}
