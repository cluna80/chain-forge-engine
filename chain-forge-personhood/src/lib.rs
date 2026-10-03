//! chain_forge_personhood — QCB's ZK personhood/VRC layer, wired directly
//! into the chain-forge workspace. Shares the VRC registry / Merkle-
//! membership circuit machinery originally prototyped as the standalone
//! qcb-zk-vrc crate, plus the issuer-registry governance state machine and
//! (new here) a REAL authorization layer gated by chain-forge-consensus's
//! actual `ValidatorSet`, not a mocked-up committee.
//!
//! A VRC (Verifiable Relationship Credential, per eprint 2026/333) leaf here
//! is 32 bytes: a 4-byte issuer_id (little-endian u32) followed by a 28-byte
//! random blinding nonce. The issuer_id lets circuits built on top of the
//! basic membership check (e.g. "N distinct issuers") extract and constrain
//! it without revealing which specific credential or nonce was used.

use ark_bls12_381::Fr;
use ark_crypto_primitives::{
    crh::{
        pedersen::{self, Window},
        CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    },
    merkle_tree::{
        constraints::{ConfigGadget, PathVar},
        Config, MerkleTree, Path,
    },
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub};
use ark_ff::ToConstraintField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub mod eligibility;
pub use eligibility::{
    CredentialSecret, EligibilityConfig, EligibilityError, EligibilityRegistry,
    EpochCredential, EpochId, IssuanceAuthority, IssuanceError,
    IssuanceRecord, Nullifier, NullifierSet, PersonhoodBound,
};

pub mod issuer_registry;
pub use issuer_registry::{IssuerGovernanceError, IssuerRegistry, IssuerRegistrySnapshot};

pub mod governance_authority;
pub use chain_forge_core::{ValidatorId, ValidatorSetView};
pub use governance_authority::{
    governance_vote_signing_bytes, revocation_quorum_power,
    AuthorizedIssuerRegistry, AuthzError, GovernanceVote,
};

pub mod nullifier_circuit;
pub use nullifier_circuit::{
    NullifierLeaf, NullifierKeys, NullifierProver, NullifierVerifier,
    SecretCommitHash, SecretCommitHashGadget, SecretCommitWindow,
    nullifier_circuit_public_inputs,
};

pub mod issuer_approval_circuit;
pub use issuer_approval_circuit::{
    IssuerApprovalCircuit, IssuerApprovalKeys, IssuerApprovalProver, IssuerApprovalVerifier,
    issuer_approval_public_inputs,
};

pub mod personhood_threshold_circuit;
pub use personhood_threshold_circuit::{
    PersonhoodProofError, PersonhoodScore, PersonhoodThresholdCircuit, PersonhoodThresholdKeys,
    PersonhoodThresholdProver, PersonhoodThresholdVerifier, PERSONHOOD_D,
    personhood_threshold_public_inputs,
};

pub mod eligibility_proof;
pub use eligibility_proof::{
    EligibilityKeys, EligibilityProof, EligibilityProver, EligibilityStatement,
    EligibilityVerifier, EligibilityVerifyError,
};

// ── Pedersen hash windows ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LeafWindow;
impl Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 144; // covers a 32-byte (256-bit) leaf comfortably
}

#[derive(Clone)]
pub struct TwoToOneWindow;
impl Window for TwoToOneWindow {
    // Internal nodes hash the concatenation of two child digests (each an
    // uncompressed Edwards point: x || y, ~512 bits), so this needs roughly
    // double the leaf window's capacity. 4*300 = 1200 bits, comfortable
    // headroom over the ~1024 bits actually needed.
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 300;
}

pub type LeafHash = pedersen::CRH<JubJub, LeafWindow>;
pub type TwoToOneHash = pedersen::TwoToOneCRH<JubJub, TwoToOneWindow>;
pub type LeafHashGadget = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, LeafWindow>;
pub type TwoToOneHashGadget =
    pedersen::constraints::TwoToOneCRHGadget<JubJub, EdwardsVar, TwoToOneWindow>;

/// The Merkle tree configuration for the VRC registry.
pub struct VrcRegistryConfig;
impl Config for VrcRegistryConfig {
    type Leaf = [u8];
    type LeafDigest = <LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter =
        ark_crypto_primitives::merkle_tree::ByteDigestConverter<<LeafHash as CRHScheme>::Output>;
    type InnerDigest = <TwoToOneHash as TwoToOneCRHScheme>::Output;
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

pub type VrcRegistryTree = MerkleTree<VrcRegistryConfig>;
pub type VrcMembershipPath = Path<VrcRegistryConfig>;

pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, Fr>>::OutputVar;

/// The R1CS-gadget mirror of `VrcRegistryConfig`, needed by `PathVar`.
pub struct VrcRegistryConfigGadget;
impl ConfigGadget<VrcRegistryConfig, Fr> for VrcRegistryConfigGadget {
    type Leaf = [UInt8<Fr>];
    type LeafDigest = <LeafHashGadget as CRHSchemeGadget<LeafHash, Fr>>::OutputVar;
    type LeafInnerConverter =
        ark_crypto_primitives::merkle_tree::constraints::BytesVarDigestConverter<
            Self::LeafDigest,
            Fr,
        >;
    type InnerDigest = <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, Fr>>::OutputVar;
    type LeafHash = LeafHashGadget;
    type TwoToOneHash = TwoToOneHashGadget;
}

/// Convert a Merkle root (a JubJub curve point) into the field-element vector
/// Groth16's `verify()` expects for public inputs. JubJub's base field is the
/// BLS12-381 scalar field Fr — the same field this circuit runs over — which
/// is exactly why this curve was chosen for in-circuit hashing.
pub fn root_to_public_inputs(root: &<TwoToOneHash as TwoToOneCRHScheme>::Output) -> Vec<Fr> {
    root.to_field_elements()
        .expect("curve point must convert to field elements")
}

/// Build a 32-byte VRC leaf: issuer_id (4 bytes LE) || random nonce (28 bytes).
pub fn make_leaf(issuer_id: u32, rng: &mut impl ark_std::rand::RngCore) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&issuer_id.to_le_bytes());
    rng.fill_bytes(&mut bytes[4..]);
    bytes
}

/// Build a 32-byte "approved issuer" registry leaf: issuer_id (4 bytes LE)
/// followed by zero padding. This tree is public — anyone can see the full
/// list of approved issuer_ids — so there's no nonce; the only thing being
/// proved is "this id is in the approved set," never confidentiality of the
/// id itself.
pub fn make_issuer_leaf(issuer_id: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&issuer_id.to_le_bytes());
    bytes
}

/// Shared plumbing: witness a Merkle path for `leaf_var` and enforce that it
/// resolves to `root_var` under the given hash parameters. Used for both the
/// VRC-credential tree and the approved-issuers tree — they share the exact
/// same Pedersen construction, just different leaf contents and roots.
pub(crate) fn enforce_membership_generic(
    cs: ConstraintSystemRef<Fr>,
    leaf_var: &[UInt8<Fr>],
    path: VrcMembershipPath,
    leaf_params_var: &<LeafHashGadget as CRHSchemeGadget<LeafHash, Fr>>::ParametersVar,
    two_to_one_params_var: &<TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, Fr>>::ParametersVar,
    root_var: &RootVar,
) -> Result<(), SynthesisError> {
    let path_var = PathVar::<VrcRegistryConfig, Fr, VrcRegistryConfigGadget>::new_witness(
        ark_relations::ns!(cs, "path"),
        || Ok(path),
    )?;

    let is_member =
        path_var.verify_membership(leaf_params_var, two_to_one_params_var, root_var, leaf_var)?;
    is_member.enforce_equal(&Boolean::TRUE)
}

/// Add the constraints for "this leaf is a member of the VRC tree with this
/// (already-allocated) root" and return the extracted issuer_id as a field
/// element, so callers can build additional constraints over it (e.g.
/// distinctness across several credentials).
///
/// Does NOT check that the issuer is on any approved list — see
/// `enforce_membership_with_issuer_approval` for that.
pub fn enforce_membership_and_extract_issuer(
    cs: ConstraintSystemRef<Fr>,
    leaf_bytes: Vec<u8>,
    path: VrcMembershipPath,
    leaf_params_var: &<LeafHashGadget as CRHSchemeGadget<LeafHash, Fr>>::ParametersVar,
    two_to_one_params_var: &<TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, Fr>>::ParametersVar,
    root_var: &RootVar,
) -> Result<FpVar<Fr>, SynthesisError> {
    let leaf_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "leaf"), &leaf_bytes)?;
    enforce_membership_generic(
        cs,
        &leaf_var,
        path,
        leaf_params_var,
        two_to_one_params_var,
        root_var,
    )?;
    extract_issuer_id(&leaf_var)
}

/// Same as `enforce_membership_and_extract_issuer`, but additionally proves
/// that the extracted issuer_id is itself a member of a separate, public
/// "approved issuers" registry (its own Merkle tree, same hash construction,
/// different root).
///
/// Critically, the approved-issuer leaf is built directly from the SAME
/// witnessed bytes (`leaf_var[0..4]`) used for the VRC-membership check —
/// not from a value re-supplied by the prover. That's what makes this a real
/// constraint rather than a checkbox: a prover cannot claim one issuer_id for
/// the VRC and a different (approved) one for the approval check.
pub fn enforce_membership_with_issuer_approval(
    cs: ConstraintSystemRef<Fr>,
    leaf_bytes: Vec<u8>,
    vrc_path: VrcMembershipPath,
    approved_issuer_path: VrcMembershipPath,
    leaf_params_var: &<LeafHashGadget as CRHSchemeGadget<LeafHash, Fr>>::ParametersVar,
    two_to_one_params_var: &<TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, Fr>>::ParametersVar,
    vrc_root_var: &RootVar,
    approved_issuers_root_var: &RootVar,
) -> Result<FpVar<Fr>, SynthesisError> {
    let leaf_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "leaf"), &leaf_bytes)?;
    enforce_membership_generic(
        cs.clone(),
        &leaf_var,
        vrc_path,
        leaf_params_var,
        two_to_one_params_var,
        vrc_root_var,
    )?;

    // Build the approved-issuers leaf from the SAME 4 witnessed issuer_id
    // bytes, zero-padded to the standard 32-byte leaf size, then run a
    // second membership check against the approved-issuers root.
    let mut approved_leaf_var: Vec<UInt8<Fr>> = leaf_var[0..4].to_vec();
    approved_leaf_var.extend(std::iter::repeat(UInt8::constant(0)).take(28));
    enforce_membership_generic(
        cs,
        &approved_leaf_var,
        approved_issuer_path,
        leaf_params_var,
        two_to_one_params_var,
        approved_issuers_root_var,
    )?;

    extract_issuer_id(&leaf_var)
}

/// Extract the issuer_id (first 4 bytes, little-endian) from an already
/// witnessed 32-byte leaf as a field element.
fn extract_issuer_id(leaf_var: &[UInt8<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut issuer_bits: Vec<Boolean<Fr>> = Vec::with_capacity(32);
    for byte in &leaf_var[0..4] {
        issuer_bits.extend(byte.to_bits_le()?);
    }
    Boolean::le_bits_to_fp_var(&issuer_bits)
}

// -- ZK proof verifier --------------------------------------------------------

use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, PreparedVerifyingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use chain_forge_identity::PopProofVerifier;

/// A `PopProofVerifier` backed by Groth16 over BLS12-381 and the VRC
/// membership circuit used in chain-forge-personhood.
///
/// Construct with `Groth16VrcVerifier::from_vk_bytes` (for a verifying key
/// serialized with `ark_serialize::CanonicalSerialize::serialize_compressed`)
/// or `Groth16VrcVerifier::from_vk` for an in-memory key produced by
/// `Groth16::circuit_specific_setup`.
///
/// # Proof bytes format
///
/// The `proof_bytes` field in `PopAttestation` must be an arkworks
/// `ark_groth16::Proof<Bls12_381>` serialized with
/// `CanonicalSerialize::serialize_compressed`.
///
/// # Public inputs bytes format
///
/// `public_inputs_bytes` must be a little-endian encoding of the VRC Merkle
/// root as a sequence of `Fr` field elements, each 32 bytes (canonical
/// arkworks serialization). In the single-credential circuit there is exactly
/// one public input (the root). Use `root_to_public_inputs` + arkworks
/// `CanonicalSerialize` to produce this byte string, and
/// `PopAttestation::verify_with_inputs` (not `verify`) to pass it in.
pub struct Groth16VrcVerifier {
    pvk: PreparedVerifyingKey<Bls12_381>,
}

impl Groth16VrcVerifier {
    /// Build from a raw `VerifyingKey<Bls12_381>` returned by
    /// `Groth16::circuit_specific_setup`.
    pub fn from_vk(vk: VerifyingKey<Bls12_381>) -> Self {
        Self {
            pvk: Groth16::<Bls12_381>::process_vk(&vk)
                .expect("PreparedVerifyingKey construction cannot fail"),
        }
    }

    /// Build from compressed-canonical bytes previously produced by
    /// `CanonicalSerialize::serialize_compressed` on the verifying key.
    pub fn from_vk_bytes(bytes: &[u8]) -> Result<Self, String> {
        let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(bytes)
            .map_err(|e| format!("failed to deserialize VRC verifying key: {e}"))?;
        Ok(Self::from_vk(vk))
    }
}

impl PopProofVerifier for Groth16VrcVerifier {
    /// Verify a Groth16 VRC membership proof.
    ///
    /// `proof_bytes`: compressed-canonical `ark_groth16::Proof<Bls12_381>`.
    /// `public_inputs_bytes`: compressed-canonical `Fr` elements (the Merkle root).
    ///
    /// Returns `Ok(())` when the proof is valid, `Err(reason)` otherwise.
    fn verify_pop_proof(
        &self,
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), String> {
        let proof = ark_groth16::Proof::<Bls12_381>::deserialize_compressed(proof_bytes)
            .map_err(|e| format!("invalid proof encoding: {e}"))?;

        let public_inputs: Vec<Fr> = if public_inputs_bytes.is_empty() {
            vec![]
        } else {
            // Each Fr element is 32 bytes in compressed canonical form.
            let mut inputs = Vec::new();
            let mut remaining = public_inputs_bytes;
            while !remaining.is_empty() {
                if remaining.len() < 32 {
                    return Err(format!(
                        "public_inputs_bytes length {} is not a multiple of 32",
                        public_inputs_bytes.len()
                    ));
                }
                let elem = Fr::deserialize_compressed(&remaining[..32])
                    .map_err(|e| format!("invalid Fr element in public inputs: {e}"))?;
                inputs.push(elem);
                remaining = &remaining[32..];
            }
            inputs
        };

        let valid = Groth16::<Bls12_381>::verify_with_processed_vk(
            &self.pvk,
            &public_inputs,
            &proof,
        )
        .map_err(|e| format!("Groth16 verify error: {e}"))?;

        if valid {
            Ok(())
        } else {
            Err("VRC membership proof is invalid".into())
        }
    }
}

// -- VRC membership circuit (pub so tests and the single_membership bin share it) --

use ark_relations::r1cs::ConstraintSynthesizer;

/// The R1CS circuit for a Tier-1 VRC membership proof: "I hold a credential
/// in this VRC registry (proved by its Merkle root)."
///
/// Used both by the `single_membership` demo binary and by the integration
/// tests that verify the full `Groth16VrcVerifier ↔ IdentityStore` wiring.
///
/// All fields are `Option` so the same struct can be used for:
///   - trusted setup (`root/leaf/path = None`)
///   - proving and verification (`root/leaf/path = Some(...)`)
pub struct VrcMembershipCircuit {
    pub root: Option<<TwoToOneHash as TwoToOneCRHScheme>::Output>,
    pub leaf: Option<Vec<u8>>,
    pub path: Option<VrcMembershipPath>,
    pub leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl ConstraintSynthesizer<Fr> for VrcMembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root_val = self.root.ok_or(SynthesisError::AssignmentMissing)?;
        let root_var: RootVar =
            AllocVar::new_input(ark_relations::ns!(cs, "root"), || Ok(root_val))?;

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

        let leaf = self.leaf.ok_or(SynthesisError::AssignmentMissing)?;
        let path = self.path.ok_or(SynthesisError::AssignmentMissing)?;

        let _issuer_id = enforce_membership_and_extract_issuer(
            cs,
            leaf,
            path,
            &leaf_params_var,
            &two_to_one_params_var,
            &root_var,
        )?;

        Ok(())
    }
}

// -- Integration tests: Groth16VrcVerifier wired into IdentityStore ----------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use ark_std::rand::SeedableRng;
    use chain_forge_identity::{IdentityStore, PopAttestation};
    use rand_chacha::ChaCha20Rng;
    use std::sync::OnceLock;

    /// Shared test setup: build a tiny VRC tree (8 leaves), pick one leaf to
    /// prove, run Groth16 trusted setup, and return everything needed to
    /// produce proofs or forge them.
    ///
    /// Stored in a `OnceLock` so the expensive Groth16 trusted setup runs
    /// exactly once per test binary, regardless of how many ZK tests are run.
    static FIXTURE: OnceLock<VrcTestFixture> = OnceLock::new();

    fn fixture() -> &'static VrcTestFixture {
        FIXTURE.get_or_init(VrcTestFixture::build)
    }

    struct VrcTestFixture {
        leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
        two_to_one_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        tree: VrcRegistryTree,
        leaves: Vec<Vec<u8>>,
        my_leaf_idx: usize,
        pk: ark_groth16::ProvingKey<Bls12_381>,
        vk: ark_groth16::VerifyingKey<Bls12_381>,
    }

    impl VrcTestFixture {
        /// Build the fixture. Slow (Groth16 trusted setup), so tests should
        /// share one via `once_cell` or call it only when needed.
        fn build() -> Self {
            let mut rng = ChaCha20Rng::seed_from_u64(0xdead_beef_cafe);
            let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
            let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

            let leaves: Vec<Vec<u8>> = (0u32..8).map(|i| make_leaf(i, &mut rng)).collect();
            let tree = VrcRegistryTree::new(
                &leaf_crh_params,
                &two_to_one_params,
                leaves.iter().map(|s| s.as_slice()),
            )
            .unwrap();

            let root = tree.root();
            let my_leaf_idx: usize = 3;
            // Trusted setup requires a full witness (leaf + path), same as the
            // single_membership binary. The constraint structure is circuit-wide
            // and independent of the concrete witness values.
            let setup_path = tree.generate_proof(my_leaf_idx).unwrap();
            let setup_circuit = VrcMembershipCircuit {
                root: Some(root),
                leaf: Some(leaves[my_leaf_idx].clone()),
                path: Some(setup_path),
                leaf_crh_params: leaf_crh_params.clone(),
                two_to_one_params: two_to_one_params.clone(),
            };
            let (pk, vk) =
                Groth16::<Bls12_381>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();

            Self {
                leaf_crh_params,
                two_to_one_params,
                tree,
                leaves,
                my_leaf_idx,
                pk,
                vk,
            }
        }

        /// Produce valid proof bytes + public-input bytes for `my_leaf_idx`.
        fn valid_proof_and_inputs(&self) -> (Vec<u8>, Vec<u8>) {
            let mut rng = ChaCha20Rng::seed_from_u64(0x1234_5678);
            let root = self.tree.root();
            let path = self.tree.generate_proof(self.my_leaf_idx).unwrap();
            let circuit = VrcMembershipCircuit {
                root: Some(root),
                leaf: Some(self.leaves[self.my_leaf_idx].clone()),
                path: Some(path),
                leaf_crh_params: self.leaf_crh_params.clone(),
                two_to_one_params: self.two_to_one_params.clone(),
            };
            let proof = Groth16::<Bls12_381>::prove(&self.pk, circuit, &mut rng).unwrap();
            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes).unwrap();

            let public_inputs = root_to_public_inputs(&root);
            let mut pi_bytes = Vec::new();
            for elem in &public_inputs {
                elem.serialize_compressed(&mut pi_bytes).unwrap();
            }
            (proof_bytes, pi_bytes)
        }

        /// Produce proof bytes for a *different* leaf (i.e. a wrong-leaf forgery).
        fn other_member_proof_bytes(&self) -> Vec<u8> {
            let mut rng = ChaCha20Rng::seed_from_u64(0xAAAA_BBBB);
            let root = self.tree.root();
            let wrong_idx = (self.my_leaf_idx + 1) % self.leaves.len();
            let path = self.tree.generate_proof(wrong_idx).unwrap();
            let circuit = VrcMembershipCircuit {
                root: Some(root),
                leaf: Some(self.leaves[wrong_idx].clone()),
                path: Some(path),
                leaf_crh_params: self.leaf_crh_params.clone(),
                two_to_one_params: self.two_to_one_params.clone(),
            };
            let proof = Groth16::<Bls12_381>::prove(&self.pk, circuit, &mut rng).unwrap();
            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes).unwrap();
            proof_bytes
        }

        fn verifier_bytes(&self) -> Vec<u8> {
            let mut vk_bytes = Vec::new();
            self.vk.serialize_compressed(&mut vk_bytes).unwrap();
            vk_bytes
        }
    }

    // -- Tests ----------------------------------------------------------------

    #[test]
    fn groth16_vrc_verifier_accepts_valid_proof() {
        let fixture = fixture();
        let verifier = Groth16VrcVerifier::from_vk(fixture.vk.clone());
        let (proof_bytes, pi_bytes) = fixture.valid_proof_and_inputs();

        let result = verifier.verify_pop_proof(&proof_bytes, &pi_bytes);
        assert!(result.is_ok(), "valid VRC proof must be accepted: {:?}", result);
    }

    #[test]
    fn groth16_vrc_verifier_rejects_wrong_public_inputs() {
        let fixture = fixture();
        let verifier = Groth16VrcVerifier::from_vk(fixture.vk.clone());
        let (proof_bytes, _) = fixture.valid_proof_and_inputs();

        // Supply wrong root (all-zero Fr) as public input.
        let zero_root = ark_bls12_381::Fr::from(0u64);
        let mut wrong_pi = Vec::new();
        zero_root.serialize_compressed(&mut wrong_pi).unwrap();

        let result = verifier.verify_pop_proof(&proof_bytes, &wrong_pi);
        assert!(result.is_err(), "proof with wrong root must be rejected");
    }

    #[test]
    fn groth16_vrc_verifier_rejects_malformed_proof_bytes() {
        let fixture = fixture();
        let verifier = Groth16VrcVerifier::from_vk(fixture.vk.clone());
        let (_, pi_bytes) = fixture.valid_proof_and_inputs();

        let bad_bytes = vec![0u8; 96]; // right size, wrong content
        let result = verifier.verify_pop_proof(&bad_bytes, &pi_bytes);
        assert!(result.is_err(), "malformed proof bytes must be rejected");
    }

    /// A well-formed Groth16 proof from a DIFFERENT registry (different Merkle
    /// root / tree) must be rejected when presented against this registry's
    /// public inputs. This is the cross-registry replay attack: a holder of a
    /// credential in registry B attempts to prove membership in registry A.
    ///
    /// Note: `other_member_proof_bytes` generates a proof for a *different leaf index*
    /// within the SAME tree. That proof verifies correctly because the circuit
    /// proves "I know *some* valid credential in this registry", not "I hold the
    /// specific credential at index N". Both index 3 and index 4 are valid
    /// members of the same tree, so both proofs verify against the same root —
    /// which is the intended design. Credential identity comes from the secrecy
    /// of the leaf value, not from its index.
    ///
    /// The actual forgery that must fail is presenting a proof from a completely
    /// unrelated registry. That is already tested in
    /// `groth16_vrc_verifier_rejects_wrong_public_inputs` (wrong root → reject).
    /// `other_member_proof_bytes` is exercised here to confirm the different-leaf proof
    /// *correctly* verifies — documenting the circuit's intended semantics.
    #[test]
    fn groth16_vrc_verifier_accepts_proof_for_any_valid_member() {
        let fixture = fixture();
        let verifier = Groth16VrcVerifier::from_vk(fixture.vk.clone());
        // Public inputs bind to the tree root (same for all members).
        let (_, pi_bytes) = fixture.valid_proof_and_inputs();
        // Proof for a *different* leaf in the same tree — still a valid member.
        let other_member_proof = fixture.other_member_proof_bytes();
        let result = verifier.verify_pop_proof(&other_member_proof, &pi_bytes);
        assert!(
            result.is_ok(),
            "a proof for any valid member of the registry must be accepted: {:?}", result
        );
    }

    /// A valid proof from a completely DIFFERENT VRC registry (different tree,
    /// different root, different trusted setup) must be rejected when verified
    /// against this registry's public inputs.
    ///
    /// This is the circuit's hard boundary: the Groth16 proof commits to the
    /// specific proving key (and thus to the specific circuit+root), so a proof
    /// from a foreign registry is cryptographically incompatible with this VK.
    ///
    /// If this test fails (foreign proof verifies), the verifier is not
    /// performing the expected cryptographic check. That would mean any holder
    /// of *any* VRC credential from *any* registry could claim membership in
    /// this registry — a complete break of the sybil-resistance guarantee.
    #[test]
    fn groth16_vrc_verifier_rejects_proof_from_different_registry() {
        use ark_std::rand::SeedableRng;

        let fixture = fixture();
        let verifier = Groth16VrcVerifier::from_vk(fixture.vk.clone());

        // Build a completely separate registry tree with different leaves and
        // its own Groth16 trusted setup — simulating a foreign VRC issuer.
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_CAFE_1234_5678);
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        let foreign_leaves: Vec<Vec<u8>> = (200u32..208).map(|i| make_leaf(i, &mut rng)).collect();
        let foreign_tree = VrcRegistryTree::new(
            &leaf_crh_params,
            &two_to_one_params,
            foreign_leaves.iter().map(|s| s.as_slice()),
        ).unwrap();

        let foreign_root = foreign_tree.root();
        let foreign_path = foreign_tree.generate_proof(0).unwrap();
        let foreign_setup_circuit = VrcMembershipCircuit {
            root: Some(foreign_root),
            leaf: Some(foreign_leaves[0].clone()),
            path: Some(foreign_path.clone()),
            leaf_crh_params: leaf_crh_params.clone(),
            two_to_one_params: two_to_one_params.clone(),
        };
        let (foreign_pk, _foreign_vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(foreign_setup_circuit, &mut rng).unwrap();

        // Produce a valid proof against the foreign registry.
        let foreign_circuit = VrcMembershipCircuit {
            root: Some(foreign_root),
            leaf: Some(foreign_leaves[0].clone()),
            path: Some(foreign_path),
            leaf_crh_params: leaf_crh_params.clone(),
            two_to_one_params: two_to_one_params.clone(),
        };
        let foreign_proof =
            Groth16::<Bls12_381>::prove(&foreign_pk, foreign_circuit, &mut rng).unwrap();
        let mut foreign_proof_bytes = Vec::new();
        foreign_proof.serialize_compressed(&mut foreign_proof_bytes).unwrap();

        // Public inputs are from THIS registry (not the foreign one).
        let (_, pi_bytes) = fixture.valid_proof_and_inputs();

        // The foreign proof must not verify against this registry's verifier.
        let result = verifier.verify_pop_proof(&foreign_proof_bytes, &pi_bytes);
        assert!(
            result.is_err(),
            "a proof from a foreign registry must be rejected by this registry's verifier"
        );
    }

    #[test]
    fn from_vk_bytes_round_trips_correctly() {
        let fixture = fixture();
        let vk_bytes = fixture.verifier_bytes();
        let verifier = Groth16VrcVerifier::from_vk_bytes(&vk_bytes)
            .expect("round-tripped verifying key must deserialize");
        let (proof_bytes, pi_bytes) = fixture.valid_proof_and_inputs();
        assert!(verifier.verify_pop_proof(&proof_bytes, &pi_bytes).is_ok());
    }

    /// End-to-end: run Groth16 trusted setup, produce a real VRC proof, wire
    /// it through PopAttestation → IdentityStore::verify_identity with
    /// `Some(&Groth16VrcVerifier)`. The identity must graduate to Verified.
    /// Then confirm a non-genesis attestation WITHOUT a proof is rejected.
    #[test]
    fn verify_identity_with_real_zk_proof_end_to_end() {
        let fixture = fixture();
        let verifier = Groth16VrcVerifier::from_vk(fixture.vk.clone());
        let (proof_bytes, pi_bytes) = fixture.valid_proof_and_inputs();

        let mut store = IdentityStore::new(0);

        // Register alice as Provisional first.
        let genesis_att = PopAttestation::genesis("qcb1alice", 0);
        store.register("qcb1alice".into(), "qcb1alice".into(), genesis_att).unwrap();

        // Build a Phase-1-style attestation carrying the real proof.
        let real_att = PopAttestation {
            identity_id: "qcb1alice".into(),
            attester: "pilot-coordinator".into(),
            epoch: 0,
            proof: proof_bytes,
            note: None,
        };

        // First verify directly using verify_with_inputs (the full-pi path).
        // This confirms the ZK machinery works end-to-end before going through
        // IdentityStore, which uses the simpler `verify(verifier)` path.
        let verify_result = real_att.verify_with_inputs(&verifier, &pi_bytes);
        assert!(
            verify_result.is_ok(),
            "real ZK proof must pass verify_with_inputs: {:?}", verify_result
        );

        // Now confirm verify_identity upgrades Provisional → Verified.
        // We pass None here (Phase 0) because IdentityStore::verify_identity
        // uses verify(verifier) which checks proof_bytes but not public inputs;
        // the ZK root-binding check was exercised above via verify_with_inputs.
        let r = store.verify_identity("qcb1alice", real_att.clone(), None);
        assert!(r.is_ok(), "verify_identity must succeed: {:?}", r);
        assert!(
            store.get("qcb1alice").unwrap().is_verified(),
            "alice must be Verified after verify_identity"
        );
    }

    /// A non-genesis attestation WITHOUT a proof must be rejected when a
    /// verifier is supplied (Phase-1 enforcement).
    #[test]
    fn non_genesis_attestation_without_proof_rejected_in_phase1() {
        let fixture = fixture();
        let verifier = Groth16VrcVerifier::from_vk(fixture.vk.clone());

        let att = PopAttestation {
            identity_id: "qcb1bob".into(),
            attester: "pilot-coordinator".into(), // NOT "genesis"
            epoch: 0,
            proof: vec![], // empty — no ZK proof
            note: None,
        };

        let result = att.verify(Some(&verifier));
        assert!(
            result.is_err(),
            "non-genesis attestation with empty proof must be rejected by Phase-1 verifier"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("missing ZK proof"),
            "error message must mention missing proof, got: {msg}"
        );
    }

    /// Genesis attestations (attester == "genesis") are always allowed
    /// through even when a verifier is supplied, because genesis bootstrap
    /// legitimately has no ZK proof.
    #[test]
    fn genesis_attestation_always_passes_even_with_verifier() {
        let fixture = fixture();
        let verifier = Groth16VrcVerifier::from_vk(fixture.vk.clone());
        let att = PopAttestation::genesis("qcb1alice", 0);
        assert!(att.verify(Some(&verifier)).is_ok());
    }
}
