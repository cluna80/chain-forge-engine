//! `RewardPolicy` — the trait every PoCD-enabled chain must implement to
//! distribute mining rewards.
//!
//! The crate itself has zero knowledge of token economics.  Chains wire in
//! their own `RewardPolicy` implementation and the epoch runner calls it at
//! the end of each epoch with the set of pending receipts.
//!
//! ## Example flow
//! ```text
//! epoch ends at block 1440
//! registry.pending_reward_receipts(721, 1440) → [r1, r2, r3]
//! policy.compute_rewards([r1, r2, r3])        → [RewardGrant { … }, …]
//! chain applies grants → marks receipts reward_distributed = true
//! ```

use crate::error::PoCDError;
use crate::types::receipt::DiscoveryReceipt;

/// A single reward grant produced by the `RewardPolicy`.
///
/// The chain's token layer converts these into actual balance transfers.
/// Amounts are in the chain's native base denomination (e.g. uQRC for QCB);
/// the field is typed as `u64` to stay chain-agnostic.
#[derive(Debug, Clone)]
pub struct RewardGrant {
    /// The receipt this grant is for.
    pub receipt_id: String,

    /// The machine that should receive the reward.
    pub machine_id: String,

    /// The wallet / account address that should receive the reward.
    /// Typically derived from `machine_id` by the policy or the chain's
    /// identity layer.
    pub recipient_wallet: String,

    /// Amount in the chain's native base denomination.
    pub amount: u64,

    /// Human-readable reason / breakdown (for auditing).
    pub notes: String,
}

/// How a chain distributes rewards for accepted PoCD receipts.
///
/// Implement this trait and pass the implementation to the chain's PoCD
/// module.  The `compute_rewards` method is called once per epoch with all
/// receipts whose `reward_distributed` flag is `false` and whose
/// `committed_at_block` falls within the epoch window.
///
/// The implementor MUST NOT mutate the registry or emit token transfers
/// directly; it returns a list of `RewardGrant`s and the chain runtime
/// applies them and marks receipts distributed.
pub trait RewardPolicy: Send + Sync {
    /// Compute reward grants for a batch of accepted receipts.
    ///
    /// * `receipts` — slice of receipts awaiting reward distribution;
    ///   all have `reward_distributed == false`.
    /// * Returns a `Vec<RewardGrant>` — one or more grants per receipt is
    ///   allowed (e.g. to split rewards between machine and verifier).
    ///
    /// Returning `Ok(vec![])` for a receipt means no reward is issued for
    /// it this epoch.  The caller will still mark it as distributed.
    fn compute_rewards(
        &self,
        receipts: &[&DiscoveryReceipt],
    ) -> Result<Vec<RewardGrant>, PoCDError>;

    /// Human-readable name of this policy implementation (for logging).
    fn policy_name(&self) -> &str;
}

// ── Convenience implementations ───────────────────────────────────────────

/// A no-op policy that issues no rewards.
///
/// Useful for testing or for chains that want PoCD participation tracked
/// without token rewards.
pub struct NullRewardPolicy;

impl RewardPolicy for NullRewardPolicy {
    fn compute_rewards(
        &self,
        _receipts: &[&DiscoveryReceipt],
    ) -> Result<Vec<RewardGrant>, PoCDError> {
        Ok(vec![])
    }

    fn policy_name(&self) -> &str {
        "NullRewardPolicy"
    }
}

/// A flat fixed-amount policy: every accepted receipt earns exactly
/// `amount_per_receipt` tokens paid to `recipient_wallet`.
///
/// Useful for devnets and early testing where all that matters is that the
/// reward pipeline fires.
pub struct FlatRewardPolicy {
    /// Amount per receipt in the chain's native base denomination.
    pub amount_per_receipt: u64,
}

impl RewardPolicy for FlatRewardPolicy {
    fn compute_rewards(
        &self,
        receipts: &[&DiscoveryReceipt],
    ) -> Result<Vec<RewardGrant>, PoCDError> {
        Ok(receipts
            .iter()
            .map(|r| RewardGrant {
                receipt_id:       r.receipt_id.clone(),
                machine_id:       r.machine_id.clone(),
                recipient_wallet: r.machine_id.clone(), // chain maps machine → wallet
                amount:           self.amount_per_receipt,
                notes:            format!(
                    "flat reward {} for receipt {}",
                    self.amount_per_receipt, r.receipt_id
                ),
            })
            .collect())
    }

    fn policy_name(&self) -> &str {
        "FlatRewardPolicy"
    }
}
