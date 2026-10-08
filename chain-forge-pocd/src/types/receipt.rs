//! `DiscoveryReceipt` — an accepted and verified proof, ready for reward
//! accounting.
//!
//! A receipt is produced by the `DiscoveryVerifier` after it:
//!   1. Confirms the seal is valid (see `DiscoveryProof::verify_seal`)
//!   2. Confirms the result is scientifically correct for the challenge
//!   3. Optionally confirms the submitting machine's identity
//!
//! Receipts are the unit of account for `RewardPolicy`: at the end of each
//! epoch the chain calls `RewardPolicy::compute_rewards` with all accepted
//! receipts from that epoch.
//!
//! ## Cross-chain isolation
//! `chain_id` is embedded in both `challenge_id` and as a top-level field.
//! A receipt produced on `qcb-devnet-1` is INVALID on any other chain — the
//! verifier MUST reject receipts whose `chain_id` does not match the running
//! chain's config.

use serde::{Deserialize, Serialize};

/// An accepted and independently-verified discovery contribution.
///
/// Fields are a strict superset of `DiscoveryProof`; everything needed for
/// reward computation and the public discovery dashboard is here in one struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryReceipt {
    /// Unique receipt ID (chain-assigned).
    pub receipt_id: String,

    /// Chain this receipt was issued on.  Cross-chain replay guard at the
    /// receipt level (complements the chain prefix in `challenge_id`).
    pub chain_id: String,

    /// The challenge that was solved / contributed to.
    pub challenge_id: String,

    /// Machine that submitted the proof.
    pub machine_id: String,

    /// SHA-256 hash of the output / discovery (hex) — copied from the proof.
    pub output_hash: String,

    /// SHA-256 hash of the input / parameter bundle (hex).
    pub input_hash: String,

    /// Content-addressable reference to the methodology document.
    pub methodology_ref: String,

    /// Domain discovery nonce (the found candidate value, if applicable).
    pub discovery_nonce: u64,

    /// Number of iterations performed.
    pub checks_performed: u64,

    pub elapsed_seconds: f64,

    /// UTC timestamp of proof submission.
    pub submitted_at: String,

    /// Machine's signature (base64) — carried through from the proof.
    pub machine_signature: String,

    // ── Seal fields (for re-verification and dashboard display) ───────────
    pub seal_nonce:          u64,
    pub seal_hash:           String,
    pub seal_difficulty_bits: u32,

    // ── Verification ──────────────────────────────────────────────────────
    /// ID of the verifier machine / node that validated the result.
    pub verifier_id: String,

    /// Verifier's Ed25519 signature over the receipt fields (base64).
    pub verifier_signature: String,

    /// Block height at which this receipt was committed on-chain.
    pub committed_at_block: u64,

    // ── Reward accounting ─────────────────────────────────────────────────
    /// Whether the chain's `RewardPolicy` has already distributed rewards
    /// for this receipt.  Prevents double-payment across epoch boundaries.
    pub reward_distributed: bool,

    /// The `proof_id` of the proof this receipt was issued for.  Stored so
    /// the `DiscoveryRegistry` can mark the proof as seen even after the
    /// original proof struct is no longer in scope.
    pub _proof_id: String,
}

impl DiscoveryReceipt {
    /// True when this receipt was issued for the given chain.
    pub fn is_for_chain(&self, chain_id: &str) -> bool {
        self.chain_id == chain_id
            && self.challenge_id.starts_with(&format!("{chain_id}::"))
    }

    /// The proof ID this receipt was produced from.
    pub fn proof_id_ref(&self) -> &str {
        &self._proof_id
    }
}
