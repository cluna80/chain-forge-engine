//! Demonstrates the issuer-registry governance path: routine (epoch-delayed,
//! grace-windowed) rotation vs. emergency (immediate, grace-window-purging)
//! revocation — and grounds it with one real Groth16 proof so the state
//! machine isn't tested in isolation from the actual cryptography it gates.

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_groth16::Groth16;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeSet;

use chain_forge_personhood::{
    enforce_membership_and_extract_issuer, root_to_public_inputs, IssuerRegistry, LeafHash,
    LeafHashGadget, RootVar, TwoToOneHash, TwoToOneHashGadget, VrcMembershipPath, VrcRegistryTree,
};

/// A minimal one-credential circuit just to demonstrate that a real proof,
/// built against a real registry root, keeps or loses validity exactly as
/// `IssuerRegistry::is_valid_root` predicts as that root ages through the
/// governance state machine.
struct IssuerMembershipCircuit {
    root: Option<<TwoToOneHash as TwoToOneCRHScheme>::Output>,
    issuer_bytes: Option<Vec<u8>>,
    path: Option<VrcMembershipPath>,
    leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl ConstraintSynthesizer<Fr> for IssuerMembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root_val = self.root.ok_or(SynthesisError::AssignmentMissing)?;
        let root_var: RootVar = AllocVar::new_input(ark_relations::ns!(cs, "root"), || Ok(root_val))?;

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

        let _issuer_id = enforce_membership_and_extract_issuer(
            cs,
            self.issuer_bytes.ok_or(SynthesisError::AssignmentMissing)?,
            self.path.ok_or(SynthesisError::AssignmentMissing)?,
            &leaf_params_var,
            &two_to_one_params_var,
            &root_var,
        )?;
        Ok(())
    }
}

fn build_tree_for(
    issuers: &BTreeSet<u32>,
    leaf_crh_params: &<LeafHash as CRHScheme>::Parameters,
    two_to_one_params: &<TwoToOneHash as TwoToOneCRHScheme>::Parameters,
) -> VrcRegistryTree {
    const PADDING_SENTINEL: u32 = u32::MAX;
    let mut leaves: Vec<Vec<u8>> = issuers.iter().map(|id| id.to_le_bytes().to_vec()).collect();
    let mut padded_len = leaves.len().max(2);
    while padded_len & (padded_len - 1) != 0 {
        padded_len += 1;
    }
    while leaves.len() < padded_len {
        leaves.push(PADDING_SENTINEL.to_le_bytes().to_vec());
    }
    VrcRegistryTree::new(leaf_crh_params, two_to_one_params, leaves.iter().map(|l| l.as_slice())).unwrap()
}

fn main() {
    println!("=== QCB: Issuer registry governance path ===\n");
    let mut rng = ChaCha20Rng::seed_from_u64(20260926);

    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    let initial_issuers: BTreeSet<u32> = [1, 2, 3, 4, 5, 6, 10, 11].into_iter().collect();
    let mut registry = IssuerRegistry::new(
        initial_issuers.clone(),
        /* activation_delay */ 3,
        /* grace_window */ 2,
        leaf_crh_params.clone(),
        two_to_one_params.clone(),
    );
    println!(
        "Registry initialised at height 0 with issuers {:?} (activation_delay=3, grace_window=2).",
        initial_issuers
    );

    // ── Ground it with one real proof: issuer 6 proves membership at height 0 ─
    let genesis_tree = build_tree_for(&initial_issuers, &leaf_crh_params, &two_to_one_params);
    let genesis_root = registry.current.root;
    let issuer6_bytes = 6u32.to_le_bytes().to_vec();
    let issuer6_index = initial_issuers.iter().position(|&id| id == 6).unwrap();
    let issuer6_path = genesis_tree.generate_proof(issuer6_index).unwrap();

    let setup_circuit = IssuerMembershipCircuit {
        root: Some(genesis_root),
        issuer_bytes: Some(issuer6_bytes.clone()),
        path: Some(issuer6_path.clone()),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();
    let prove_circuit = IssuerMembershipCircuit {
        root: Some(genesis_root),
        issuer_bytes: Some(issuer6_bytes),
        path: Some(issuer6_path),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };
    let proof_at_genesis = Groth16::<Bls12_381>::prove(&pk, prove_circuit, &mut rng).unwrap();
    let genesis_public_inputs = root_to_public_inputs(&genesis_root);
    let genesis_valid =
        Groth16::<Bls12_381>::verify(&vk, &genesis_public_inputs, &proof_at_genesis).unwrap();
    println!("Real proof of issuer 6's membership at height 0: valid = {genesis_valid}\n");
    assert!(genesis_valid);

    // ── Scenario A: routine addition (issuer 20), grace-window tolerance ──────
    println!("--- Scenario A: routine addition of issuer 20 ---");
    let mut with_20 = registry.current.approved_issuers.clone();
    with_20.insert(20);
    let activation = registry.propose_change(with_20).unwrap();
    println!("Proposed adding issuer 20 at height 0 -> activates at height {activation}.");

    for h in 1..=activation {
        registry.advance_height(h);
        let genesis_status = registry.is_valid_root(&genesis_root);
        let label = match genesis_status {
            Some(snap) if std::ptr::eq(snap, &registry.current) => "VALID (current)",
            Some(_) => "VALID (grace window / history)",
            None => "EXPIRED (outside grace window)",
        };
        println!(
            "  height {h}: current root is {}; genesis-height root (issuer 6's proof) is {label}",
            if h < activation { "still the original" } else { "the NEW root (issuer 20 added)" },
        );
    }
    assert!(
        registry.is_valid_root(&genesis_root).is_some(),
        "genesis root must still be valid immediately after rotation (grace window)"
    );
    // Our proof from height 0 still verifies against genesis_root regardless
    // of anything the registry does — Groth16 proofs don't expire on their
    // own. What CAN change is whether a verifier's registry still calls that
    // root acceptable, which is exactly what is_valid_root tracks.
    let still_valid = Groth16::<Bls12_381>::verify(&vk, &genesis_public_inputs, &proof_at_genesis).unwrap();
    println!("Original proof still cryptographically valid: {still_valid} (as always — proofs don't expire; acceptance policy does)\n");

    // The grace window here is a COUNT of recent rotations, not an elapsed-
    // height decay — advancing height alone with no new proposal doesn't
    // touch history at all. To actually push the genesis snapshot out, we
    // need MORE rotations than the window can hold (grace_window=2), not
    // more time. Two more routine changes push it out on the third.
    println!("Pushing two more routine rotations through (grace_window=2) to age genesis out...");
    for extra_issuer in [21u32, 22u32] {
        let mut next_set = registry.current.approved_issuers.clone();
        next_set.insert(extra_issuer);
        let h_before = registry.height;
        let act = registry.propose_change(next_set).unwrap();
        for h in (h_before + 1)..=act {
            registry.advance_height(h);
        }
        let still_there = registry.is_valid_root(&genesis_root).is_some();
        println!(
            "  after adding issuer {extra_issuer} (history now holds {} snapshot(s)): genesis root is {}",
            registry.history.len(),
            if still_there { "still VALID" } else { "EXPIRED" }
        );
    }
    let expired_status = registry.is_valid_root(&genesis_root);
    assert!(
        expired_status.is_none(),
        "genesis root must expire once pushed out of the count-bounded grace window"
    );

    // ── Scenario B: emergency revocation overrides the grace window ───────────
    println!("\n--- Scenario B: emergency revocation of issuer 6 ---");
    println!("Current approved set: {:?}", registry.current.approved_issuers);

    // First, do ANOTHER routine rotation so there's a fresh, still-within-
    // window historical snapshot that includes issuer 6 - to prove revocation
    // purges it even though it hasn't aged out yet.
    let mut without_11 = registry.current.approved_issuers.clone();
    without_11.remove(&11);
    let h_before_revoke = registry.height;
    let activation2 = registry.propose_change(without_11).unwrap();
    for h in (h_before_revoke + 1)..=activation2 {
        registry.advance_height(h);
    }
    let root_with_issuer6 = registry
        .history
        .front()
        .expect("just-superseded snapshot should be in history")
        .root;
    println!(
        "Rotated again (dropped issuer 11). Snapshot from height {} — which still includes \
         issuer 6 — sits in the grace window: {}",
        registry.history.front().unwrap().height,
        if registry.is_valid_root(&root_with_issuer6).is_some() { "VALID (as expected, still fresh)" } else { "unexpectedly invalid" }
    );
    assert!(registry.is_valid_root(&root_with_issuer6).is_some());

    // Now revoke issuer 6 immediately.
    registry.revoke_immediately(6).unwrap();
    println!("Issuer 6 revoked immediately. Current approved set: {:?}", registry.current.approved_issuers);

    let purged_status = registry.is_valid_root(&root_with_issuer6);
    println!(
        "That same still-fresh grace-window snapshot (which included issuer 6) is now: {}",
        if purged_status.is_some() { "INCORRECTLY still valid (BUG)" } else { "PURGED — revocation overrode the grace window, as required" }
    );
    assert!(
        purged_status.is_none(),
        "revocation must purge every historical root that included the revoked issuer, \
         regardless of how recently it was superseded"
    );

    println!("\n=== All checks passed. Routine rotation tolerates in-flight proofs; ===");
    println!("=== emergency revocation cuts through that same tolerance instantly. ===");
}
