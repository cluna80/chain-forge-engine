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

pub mod issuer_registry;
pub use issuer_registry::{IssuerGovernanceError, IssuerRegistry, IssuerRegistrySnapshot};

pub mod governance_authority;
pub use chain_forge_core::{ValidatorId, ValidatorSetView};
pub use governance_authority::{
    governance_vote_signing_bytes, revocation_quorum_power,
    AuthorizedIssuerRegistry, AuthzError, GovernanceVote,
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
fn enforce_membership_generic(
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
