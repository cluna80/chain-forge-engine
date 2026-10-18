//! `QcbResearchRewardPolicy` — PoCD research-contribution reward policy.
//!
//! Moved here from `chain-forge-qrc` when the QRC token engine was retired.
//! This policy pays Change Set K/L *scientific experiment* results in **uqcb**
//! (micro-QCB, the native token) at flat per-result rates.  It has no QRC
//! dependencies and belongs with the scheduler that uses it.
//!
//! ## Separation from the old `QcbRewardPolicy`
//!
//! The former `chain_forge_qrc::QcbRewardPolicy` paid PoCD proof-of-work
//! receipts in uQRC using a difficulty-scaled formula.
//! `QcbResearchRewardPolicy` pays avalanche-experiment and replication task
//! results in uqcb at flat per-result rates.
//!
//! ## Budget enforcement
//!
//! `compute_reward` returns `BudgetExhausted` when the proposed payment would
//! push the total disbursed for the objective past `objective_budget_uqcb`.
//!
//! ## Scientific constraints (preserved from Change Set K/L spec)
//!
//! "No result is automatically classified as a cryptographic breakthrough."
//! "No experimental result is automatically classified as a cryptographic
//!  anomaly or scientific discovery."
//! "Do not introduce AI inference, new token economics, or automatic
//!  scientific discovery claims."

use chain_forge_research_db::models::{NewResearchRewardClaim, RewardKind};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Policy version string for `QcbResearchRewardPolicy`.
pub const RESEARCH_POLICY_VERSION: &str = "QcbResearchRewardPolicy-v1";

/// Reward policy for PoCD research contributions, denominated in uqcb.
pub struct QcbResearchRewardPolicy {
    /// Flat reward per accepted primary result (avalanche_experiment), in uqcb.
    pub primary_rate_uqcb:     u64,

    /// Flat reward per accepted replication result (avalanche_replication), in uqcb.
    pub replication_rate_uqcb: u64,

    /// Maximum total uqcb to pay out across all claims for one objective.
    pub objective_budget_uqcb: u64,

    /// On-chain address from which uqcb rewards are sourced.
    pub treasury_address:      String,
}

/// Result of `compute_reward` when budget allows.
#[derive(Debug)]
pub struct ResearchRewardOutput {
    /// Ready-to-persist claim DTO.
    pub claim: NewResearchRewardClaim,
    /// Amount computed (mirrors `claim.amount_uqcb`).
    pub amount_uqcb: u64,
}

/// Error returned when `compute_reward` cannot produce a valid claim.
#[derive(Debug, thiserror::Error)]
pub enum ResearchRewardError {
    #[error("objective budget exhausted: budget={budget_uqcb} disbursed={disbursed_uqcb} requested={requested_uqcb}")]
    BudgetExhausted {
        budget_uqcb:    u64,
        disbursed_uqcb: u64,
        requested_uqcb: u64,
    },

    #[error("zero-amount claim rejected for task {task_id}: rate for {reward_kind:?} is 0")]
    ZeroAmount {
        task_id:     String,
        reward_kind: RewardKind,
    },
}

impl QcbResearchRewardPolicy {
    /// Devnet defaults: 5 QCB primary, 2 QCB replication, 5000 QCB budget.
    pub fn default_for_devnet(treasury_address: impl Into<String>) -> Self {
        Self {
            primary_rate_uqcb:     5_000_000,      // 5 QCB
            replication_rate_uqcb: 2_000_000,      // 2 QCB
            objective_budget_uqcb: 5_000_000_000,  // 5000 QCB
            treasury_address:      treasury_address.into(),
        }
    }

    /// Compute the reward for a single verified research result.
    ///
    /// # Scientific constraints
    ///
    /// This method does NOT examine result content.  It does not classify
    /// results as discoveries, anomalies, or breakthroughs.  The amount is
    /// determined solely by the flat rate table and `reward_kind`.
    pub fn compute_reward(
        &self,
        chain_id:          &str,
        objective_id:      &str,
        task_id:           &str,
        result_id:         Uuid,
        contribution_hash: &str,
        recipient:         &str,
        reward_kind:       RewardKind,
        disbursed_so_far:  u64,
    ) -> Result<ResearchRewardOutput, ResearchRewardError> {
        // 1. Look up the flat rate for this reward kind.
        let amount_uqcb = match &reward_kind {
            RewardKind::Primary     => self.primary_rate_uqcb,
            RewardKind::Replication => self.replication_rate_uqcb,
        };

        // Guard: misconfiguration check.
        if amount_uqcb == 0 {
            return Err(ResearchRewardError::ZeroAmount {
                task_id:     task_id.to_owned(),
                reward_kind,
            });
        }

        // 2. Budget enforcement.
        let next_total = disbursed_so_far.saturating_add(amount_uqcb);
        if next_total > self.objective_budget_uqcb {
            return Err(ResearchRewardError::BudgetExhausted {
                budget_uqcb:    self.objective_budget_uqcb,
                disbursed_uqcb: disbursed_so_far,
                requested_uqcb: amount_uqcb,
            });
        }

        // 3. Derive deterministic claim_id.
        //    hex( SHA-256( "qcb-claim-v1\x00" || chain_id || "\x00"
        //                   || objective_id || "\x00" || task_id || "\x00"
        //                   || reward_kind_str ) )
        let reward_kind_str = reward_kind.as_str();
        let mut hasher = Sha256::new();
        hasher.update(b"qcb-claim-v1\x00");
        hasher.update(chain_id.as_bytes());
        hasher.update(b"\x00");
        hasher.update(objective_id.as_bytes());
        hasher.update(b"\x00");
        hasher.update(task_id.as_bytes());
        hasher.update(b"\x00");
        hasher.update(reward_kind_str.as_bytes());
        let claim_id = hex::encode(hasher.finalize());

        tracing::info!(
            claim_id       = %claim_id,
            objective_id   = %objective_id,
            task_id        = %task_id,
            result_id      = %result_id,
            recipient      = %recipient,
            reward_kind    = %reward_kind_str,
            amount_uqcb    = amount_uqcb,
            budget_uqcb    = self.objective_budget_uqcb,
            disbursed      = disbursed_so_far,
            "QcbResearchRewardPolicy: computed research reward"
        );

        let claim = NewResearchRewardClaim {
            claim_id:          claim_id.clone(),
            objective_id:      objective_id.to_owned(),
            task_id:           task_id.to_owned(),
            result_id,
            contribution_hash: contribution_hash.to_owned(),
            recipient:         recipient.to_owned(),
            amount_uqcb,
            policy_version:    RESEARCH_POLICY_VERSION.to_owned(),
            reward_kind:       reward_kind_str.to_owned(),
        };

        Ok(ResearchRewardOutput { claim, amount_uqcb })
    }

    /// The policy version identifier.
    pub fn policy_version(&self) -> &str {
        RESEARCH_POLICY_VERSION
    }
}
