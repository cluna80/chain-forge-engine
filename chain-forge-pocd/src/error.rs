//! `PoCDError` — all error variants produced by the `chain-forge-pocd` crate.

use thiserror::Error;

/// Errors that can arise while validating or processing PoCD artefacts.
#[derive(Debug, Error)]
pub enum PoCDError {
    // ── Seal / proof errors ───────────────────────────────────────────────

    /// The `seal_hash` field does not match the recomputed value.
    #[error("invalid seal: {reason}")]
    InvalidSeal { reason: String },

    /// The seal hash does not have the required number of leading zero bits.
    #[error("insufficient seal difficulty: required {required} bits, got {got}")]
    InsufficientDifficulty { required: u32, got: u32 },

    // ── Challenge errors ──────────────────────────────────────────────────

    /// The referenced challenge is not known to this chain's registry.
    #[error("unknown challenge: {challenge_id}")]
    UnknownChallenge { challenge_id: String },

    /// The challenge exists but is not currently accepting submissions.
    #[error("challenge not active: {challenge_id} (status: {status})")]
    ChallengeNotActive { challenge_id: String, status: String },

    /// The proof's `seal_difficulty_bits` is below the challenge (or chain) minimum.
    #[error("difficulty below minimum: proof declares {declared}, chain requires {required}")]
    DifficultyBelowMinimum { declared: u32, required: u32 },

    // ── Cross-chain / identity errors ─────────────────────────────────────

    /// The receipt was issued on a different chain.
    #[error("cross-chain receipt: receipt chain_id={receipt_chain_id}, running chain={running_chain_id}")]
    CrossChainReceipt {
        receipt_chain_id: String,
        running_chain_id: String,
    },

    /// The `challenge_id` prefix does not match the declared `chain_id`.
    #[error("chain_id/challenge_id mismatch: challenge_id={challenge_id}, chain_id={chain_id}")]
    ChainIdMismatch { challenge_id: String, chain_id: String },

    /// Identity verification required but not provided.
    #[error("identity verification required for machine {machine_id}")]
    IdentityRequired { machine_id: String },

    /// Machine signature verification failed.
    #[error("invalid machine signature for proof {proof_id}: {reason}")]
    InvalidMachineSignature { proof_id: String, reason: String },

    /// Verifier signature verification failed.
    #[error("invalid verifier signature for receipt {receipt_id}: {reason}")]
    InvalidVerifierSignature { receipt_id: String, reason: String },

    // ── Registry errors ───────────────────────────────────────────────────

    /// A proof with the same ID has already been accepted.
    #[error("duplicate proof: {proof_id}")]
    DuplicateProof { proof_id: String },

    /// A receipt with the same ID already exists in the registry.
    #[error("duplicate receipt: {receipt_id}")]
    DuplicateReceipt { receipt_id: String },

    // ── Reward errors ─────────────────────────────────────────────────────

    /// Rewards have already been distributed for this receipt.
    #[error("rewards already distributed for receipt {receipt_id}")]
    RewardAlreadyDistributed { receipt_id: String },

    /// The `RewardPolicy` implementation returned an error.
    #[error("reward policy error: {0}")]
    RewardPolicyError(String),

    // ── Track errors ──────────────────────────────────────────────────────

    /// The challenge's research track is not enabled on this chain.
    #[error("track not enabled on this chain: {track}")]
    TrackNotEnabled { track: String },

    // ── Generic ───────────────────────────────────────────────────────────

    /// Catch-all for errors that don't fit above (e.g. from integrating crates).
    #[error("pocd error: {0}")]
    Other(String),
}
