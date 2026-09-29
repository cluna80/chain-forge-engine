//! Tier 1, step 1: "I hold a valid VRC" — single membership proof.
//! (Refactored to use the shared `chain_forge_personhood` lib; behavior unchanged from
//! the original standalone version.)

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

use chain_forge_personhood::{
    make_leaf, root_to_public_inputs, LeafHash, TwoToOneHash,
    VrcRegistryTree, VrcMembershipCircuit,
};

fn main() {
    println!("=== QCB Tier 1: VRC membership ZK proof (Groth16 over BLS12-381) ===\n");

    let mut rng = ChaCha20Rng::seed_from_u64(20260926);

    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    let vrc_secrets: Vec<Vec<u8>> = (0u32..8).map(|i| make_leaf(i, &mut rng)).collect();

    let tree = VrcRegistryTree::new(
        &leaf_crh_params,
        &two_to_one_params,
        vrc_secrets.iter().map(|s| s.as_slice()),
    )
    .unwrap();
    let root = tree.root();
    println!("VRC registry built: {} credentials, root committed on-chain.", vrc_secrets.len());

    let my_index = 3;
    let my_leaf = vrc_secrets[my_index].clone();
    let my_path = tree.generate_proof(my_index).unwrap();

    assert!(my_path
        .verify(&leaf_crh_params, &two_to_one_params, &root, my_leaf.as_slice())
        .unwrap());
    println!("Local membership check passed (not yet zero-knowledge).\n");

    let setup_circuit = VrcMembershipCircuit {
        root: Some(root),
        leaf: Some(my_leaf.clone()),
        path: Some(my_path.clone()),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };

    let t0 = Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();
    println!("Trusted setup complete in {:?}", t0.elapsed());

    let prove_circuit = VrcMembershipCircuit {
        root: Some(root),
        leaf: Some(my_leaf.clone()),
        path: Some(my_path.clone()),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };

    let t1 = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, prove_circuit, &mut rng).unwrap();
    println!("Proof generated in {:?}", t1.elapsed());

    let mut proof_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes).unwrap();
    println!("Proof size: {} bytes", proof_bytes.len());

    let public_inputs = root_to_public_inputs(&root);

    let t2 = Instant::now();
    let valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof).unwrap();
    println!("Verification took {:?}", t2.elapsed());
    println!("\nProof valid: {valid}");
    assert!(valid, "proof must verify");

    // Negative test 1: tampered credential must fail verification (not proving).
    let mut forged_leaf = my_leaf.clone();
    forged_leaf[5] ^= 0xFF;
    let forged_circuit = VrcMembershipCircuit {
        root: Some(root),
        leaf: Some(forged_leaf),
        path: Some(my_path),
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_params: two_to_one_params.clone(),
    };
    let forged_proof = Groth16::<Bls12_381>::prove(&pk, forged_circuit, &mut rng).unwrap();
    let forged_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &forged_proof).unwrap_or(false);
    println!(
        "\nForged-credential proof verification: {}",
        if forged_valid { "INCORRECTLY passed (BUG)" } else { "correctly rejected" }
    );
    assert!(!forged_valid, "a forged credential must never verify");

    // Negative test 2: valid credential proved against an unrelated root must fail.
    let other_secrets: Vec<Vec<u8>> = (100u32..108).map(|i| make_leaf(i, &mut rng)).collect();
    let other_tree = VrcRegistryTree::new(
        &leaf_crh_params,
        &two_to_one_params,
        other_secrets.iter().map(|s| s.as_slice()),
    )
    .unwrap();
    let wrong_root_inputs = root_to_public_inputs(&other_tree.root());
    let wrong_root_valid = Groth16::<Bls12_381>::verify(&vk, &wrong_root_inputs, &proof).unwrap_or(false);
    println!(
        "Valid proof checked against a DIFFERENT registry root: {}",
        if wrong_root_valid { "INCORRECTLY passed (BUG)" } else { "correctly rejected" }
    );
    assert!(!wrong_root_valid, "a proof must not verify against an unrelated root");

    println!("\n=== All checks passed. ===");
}
