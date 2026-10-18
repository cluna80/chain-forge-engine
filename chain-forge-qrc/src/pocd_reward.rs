//! `QcbRewardPolicy` — PoCD reward distribution in uQRC.
//!
//! This module implements the `chain_forge_pocd::RewardPolicy` trait for
//! QCB Chain.  At the end of each PoCD epoch the chain calls
//! `compute_rewards` with the set of accepted receipts; this policy returns
//! `RewardGrant`s denominated in **uQRC** (micro-QRC, the base denomination).
//!
//! ## Reward formula (v0 — flat per-receipt)
//!
//! ```text
//! reward_uqrc = BASE_REWARD_UQRC
//!             × difficulty_multiplier(seal_difficulty_bits)
//!             × track_multiplier(challenge_track)
//! ```
//!
//! ### Difficulty multiplier
//! Each additional 4 bits of difficulty doubles the expected search time, so
//! the multiplier grows exponentially in 4-bit increments:
//! ```text
//! difficulty_multiplier = 2^((seal_difficulty_bits - MIN_DIFFICULTY) / 4)
//! ```
//! (Capped at `MAX_DIFFICULTY_MULTIPLIER` to protect the reward pool.)
//!
//! ### Track multiplier
//! Chains with scarce expertise tracks apply a premium to attract miners.
//! The QCB defaults below can be overridden at construction time.
//!
//! ## Reward cap
//! Total rewards per epoch are capped at `epoch_pool_uqrc` passed at
//! construction.  When the calculated total exceeds the pool, grants are
//! scaled down pro-rata.
//!
//! ## Treasury account
//! Rewards are *sourced* from `pocd_treasury` — the address the chain's
//! governance funds with uQRC for PoCD payouts.  The chain's execution layer
//! must debit that account and credit each `recipient_wallet`.  This module
//! only computes the amounts; it never touches balances directly.

use chain_forge_pocd::{
    ChallengeTrack, DiscoveryReceipt, PoCDError, RewardGrant, RewardPolicy,
};

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum seal difficulty assumed by the multiplier formula.
/// Below this the multiplier stays at 1×.
const MIN_DIFFICULTY: u32 = 16;

/// Maximum difficulty multiplier (caps exponential blowup).
const MAX_DIFFICULTY_MULTIPLIER: u64 = 256;

/// Default base reward: 1 QRC = 1_000_000 uQRC.
pub const DEFAULT_BASE_REWARD_UQRC: u64 = 1_000_000;

/// Default epoch pool: 720 × base reward (one epoch ≈ 720 blocks ≈ 1 hour on QCB).
pub const DEFAULT_EPOCH_POOL_UQRC: u64 = 720 * DEFAULT_BASE_REWARD_UQRC;

// ── Track multipliers ─────────────────────────────────────────────────────

/// Per-track reward multiplier × 100 (integer math; divide by 100 at use).
/// Example: 150 → 1.5×, 100 → 1×, 200 → 2×.
fn default_track_multiplier_x100(track: &ChallengeTrack) -> u64 {
    match track {
        ChallengeTrack::Mathematics              => 300, // rare expertise
        ChallengeTrack::Cryptography             => 250,
        ChallengeTrack::PhysicsAndOpenScience    => 200,
        ChallengeTrack::Privacy                  => 175,
        ChallengeTrack::ComputationalEfficiency  => 150,
        ChallengeTrack::AiAssistedDiscovery      => 120,
        ChallengeTrack::Custom(_)                => 100,
    }
}

// ── QcbRewardPolicy ───────────────────────────────────────────────────────

/// QCB Chain's PoCD reward policy — pays in uQRC, sourced from a designated
/// PoCD treasury account.
pub struct QcbRewardPolicy {
    /// Base reward per receipt (uQRC) before multipliers.
    pub base_reward_uqrc: u64,

    /// Maximum total uQRC to distribute in a single epoch.
    pub epoch_pool_uqrc: u64,

    /// The on-chain address from which rewards are paid.
    /// Governance must keep this account funded.
    pub pocd_treasury: String,
}

impl QcbRewardPolicy {
    /// Create with QCB defaults.
    pub fn default_for_devnet(pocd_treasury: impl Into<String>) -> Self {
        Self {
            base_reward_uqrc: DEFAULT_BASE_REWARD_UQRC,
            epoch_pool_uqrc:  DEFAULT_EPOCH_POOL_UQRC,
            pocd_treasury:    pocd_treasury.into(),
        }
    }

    /// Compute the reward for a single receipt before pro-rata scaling.
    fn raw_reward(&self, receipt: &DiscoveryReceipt) -> u64 {
        // Difficulty multiplier: 2^((bits - MIN) / 4), capped.
        let diff_bonus = receipt.seal_difficulty_bits.saturating_sub(MIN_DIFFICULTY);
        let diff_mult  = (1u64 << (diff_bonus / 4)).min(MAX_DIFFICULTY_MULTIPLIER);

        // Track multiplier.
        // Parse the track from the challenge_id slug (e.g. "qcb-devnet-1::Cryptography::…")
        let track_mult = track_from_challenge_id(&receipt.challenge_id)
            .map(|t| default_track_multiplier_x100(&t))
            .unwrap_or(100);

        self.base_reward_uqrc
            .saturating_mul(diff_mult)
            .saturating_mul(track_mult)
            / 100
    }
}

impl RewardPolicy for QcbRewardPolicy {
    fn compute_rewards(
        &self,
        receipts: &[&DiscoveryReceipt],
    ) -> Result<Vec<RewardGrant>, PoCDError> {
        if receipts.is_empty() {
            return Ok(vec![]);
        }

        // 1. Calculate raw rewards.
        let raws: Vec<u64> = receipts.iter().map(|r| self.raw_reward(r)).collect();
        let total_raw: u64 = raws.iter().sum();

        // 2. Scale down pro-rata if total exceeds epoch pool.
        let grants: Vec<RewardGrant> = receipts
            .iter()
            .zip(raws.iter())
            .map(|(r, &raw)| {
                let amount = if total_raw <= self.epoch_pool_uqrc {
                    raw
                } else {
                    // Pro-rata: amount = raw × pool / total_raw
                    (raw as u128)
                        .saturating_mul(self.epoch_pool_uqrc as u128)
                        .checked_div(total_raw as u128)
                        .unwrap_or(0) as u64
                };

                RewardGrant {
                    receipt_id:      r.receipt_id.clone(),
                    machine_id:      r.machine_id.clone(),
                    recipient_wallet: machine_to_wallet(&r.machine_id),
                    amount,
                    notes: format!(
                        "QCB PoCD reward: {} uQRC for receipt {} (difficulty={}bits, raw={})",
                        amount, r.receipt_id, r.seal_difficulty_bits, raw
                    ),
                }
            })
            .filter(|g| g.amount > 0)
            .collect();

        tracing::info!(
            receipts   = receipts.len(),
            total_raw  = total_raw,
            pool       = self.epoch_pool_uqrc,
            grants     = grants.len(),
            "QcbRewardPolicy: computed PoCD rewards"
        );

        Ok(grants)
    }

    fn policy_name(&self) -> &str {
        "QcbRewardPolicy-v0"
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Derive the wallet address from a machine_id.
///
/// QCB convention: machines register as `machine:{id}` on-chain; the wallet
/// that receives their PoCD rewards is `machine:{id}`.  The execution layer
/// knows to look up that account's beneficiary wallet.  For devnet simplicity
/// the machine_id IS the wallet.
fn machine_to_wallet(machine_id: &str) -> String {
    machine_id.to_owned()
}

/// Parse the `ChallengeTrack` from a `challenge_id` of the form
/// `{chain_id}::{TrackName}::{slug}`.  Returns `None` on any parse failure.
fn track_from_challenge_id(challenge_id: &str) -> Option<ChallengeTrack> {
    let mut parts = challenge_id.splitn(3, "::");
    let _chain = parts.next()?;
    let track  = parts.next()?;
    match track {
        "Cryptography"            => Some(ChallengeTrack::Cryptography),
        "Privacy"                 => Some(ChallengeTrack::Privacy),
        "ComputationalEfficiency" => Some(ChallengeTrack::ComputationalEfficiency),
        "Mathematics"             => Some(ChallengeTrack::Mathematics),
        "PhysicsAndOpenScience"   => Some(ChallengeTrack::PhysicsAndOpenScience),
        "AiAssistedDiscovery"     => Some(ChallengeTrack::AiAssistedDiscovery),
        other                     => Some(ChallengeTrack::Custom(other.to_owned())),
    }
}

// ── QcbResearchRewardPolicy (Change Set L) ────────────────────────────────
//
// Reward policy for PoCD **research contributions** (avalanche experiments and
// replications in Change Set K/L).  This is DISTINCT from `QcbRewardPolicy`
// above, which pays in uQRC and is difficulty-multiplier-based.
//
// This policy:
//   - pays in **uqcb** (micro-QCB, native token) — NOT uQRC
//   - uses flat per-result rates: `primary_rate_uqcb` and `replication_rate_uqcb`
//   - enforces a per-objective budget cap (`objective_budget_uqcb`)
//   - never infers scientific significance — amounts are determined solely by
//     `RewardKind` and the flat rate table
//   - returns a `NewResearchRewardClaim` DTO ready for persistence and settlement
//
// Scientific integrity constraints (preserved verbatim from Change Set K/L spec):
//   "No result is automatically classified as a cryptographic breakthrough."
//   "No experimental result is automatically classified as a cryptographic anomaly
//    or scientific discovery."
//   "Do not introduce AI inference, new token economics, or automatic scientific
//    discovery claims."

use chain_forge_core::{ChainHash, HashWidth};
use chain_forge_research_db::models::{NewResearchRewardClaim, RewardKind};
use uuid::Uuid;

/// Policy version string for `QcbResearchRewardPolicy`.
pub const RESEARCH_POLICY_VERSION: &str = "QcbResearchRewardPolicy-v1";

/// Reward policy for PoCD research contributions, denominated in uqcb.
///
/// ## Separation from `QcbRewardPolicy`
///
/// `QcbRewardPolicy` pays PoCD *proof-of-work* receipts in uQRC using a
/// difficulty-scaled formula.  `QcbResearchRewardPolicy` pays Change Set K/L
/// *scientific experiment* results (avalanche_experiment and
/// avalanche_replication task kinds) in uqcb at flat per-result rates.
///
/// ## Budget enforcement
///
/// `compute_reward` will return `None` when the proposed payment would push the
/// total disbursed for the objective past `objective_budget_uqcb`.  The caller
/// (settlement operator) is responsible for tracking `disbursed_so_far` by
/// querying the research DB.
///
/// ## Recipient binding
///
/// The `recipient` argument must be the authenticated wallet address of the
/// miner that produced the canonical result.  `compute_reward` copies it
/// verbatim into the claim — no substitution is possible at policy level.
///
/// ## Claim-ID determinism
///
/// The returned `claim_id` is deterministic:
/// ```text
/// hex( SHA-256( "qcb-claim-v1\x00" || chain_id || "\x00"
///               || objective_id || "\x00" || task_id || "\x00"
///               || reward_kind_str ) )
/// ```
/// This makes settlement re-submission after a crash idempotent.
pub struct QcbResearchRewardPolicy {
    /// Flat reward per accepted primary result (avalanche_experiment), in uqcb.
    pub primary_rate_uqcb:     u64,

    /// Flat reward per accepted replication result (avalanche_replication), in uqcb.
    pub replication_rate_uqcb: u64,

    /// Maximum total uqcb to pay out across all claims for one objective.
    /// Prevents runaway payouts if the scheduler creates more tasks than budgeted.
    pub objective_budget_uqcb: u64,

    /// On-chain address from which uqcb rewards are sourced
    /// (e.g. `"treasury:pocd-research"`).  Governance must keep it funded.
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
            primary_rate_uqcb:     5_000_000,  // 5 QCB
            replication_rate_uqcb: 2_000_000,  // 2 QCB
            objective_budget_uqcb: 5_000_000_000, // 5000 QCB
            treasury_address:      treasury_address.into(),
        }
    }

    /// Compute the reward for a single verified research result.
    ///
    /// # Arguments
    ///
    /// * `chain_id`         — chain identifier (e.g. `"qcb-devnet-1"`), used
    ///                        in deterministic claim-ID derivation and chain-ID binding.
    /// * `objective_id`     — parent objective.
    /// * `task_id`          — the specific task this result belongs to.
    /// * `result_id`        — UUID of the canonical `experiment_results` row.
    /// * `contribution_hash`— content hash of the canonical result (denormalized).
    /// * `recipient`        — authenticated wallet address of the result's miner.
    ///                        Must match the DIS-authenticated machine owner;
    ///                        the caller is responsible for that check.
    /// * `reward_kind`      — `Primary` (avalanche_experiment) or
    ///                        `Replication` (avalanche_replication).
    /// * `disbursed_so_far` — sum of `amount_uqcb` already finalized for this
    ///                        objective, queried from `list_reward_claims_for_objective`.
    ///
    /// # Errors
    ///
    /// Returns `BudgetExhausted` if the payment would exceed `objective_budget_uqcb`.
    /// Returns `ZeroAmount` if the rate for the given `RewardKind` is zero
    /// (misconfiguration guard).
    ///
    /// # Scientific constraints
    ///
    /// This method does NOT examine result content.  It does not classify results
    /// as discoveries, anomalies, or breakthroughs.  The amount is determined
    /// solely by the flat rate table and `reward_kind`.
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

        // Guard: misconfiguration check (zero rate → reject rather than paying nothing).
        if amount_uqcb == 0 {
            return Err(ResearchRewardError::ZeroAmount {
                task_id:     task_id.to_owned(),
                reward_kind,
            });
        }

        // 2. Budget enforcement: reject if paying would exceed the objective cap.
        let next_total = disbursed_so_far.saturating_add(amount_uqcb);
        if next_total > self.objective_budget_uqcb {
            return Err(ResearchRewardError::BudgetExhausted {
                budget_uqcb:    self.objective_budget_uqcb,
                disbursed_uqcb: disbursed_so_far,
                requested_uqcb: amount_uqcb,
            });
        }

        // 3. Derive deterministic claim_id via ChainHash (SHA-3-256).
        //    CS-001-L1: routes through ChainHash instead of raw sha2 so the
        //    hash algorithm is upgraded in one place.
        //    Format: hex( SHA3-256( "qcb-claim-v1\x00" || chain_id || "\x00"
        //                           || objective_id || "\x00" || task_id || "\x00"
        //                           || reward_kind_str ) )
        //    NOTE: devnet only — a mainnet deployment would need a claim_id
        //    migration if switching from the prior SHA-256 derivation.
        let reward_kind_str = reward_kind.as_str();
        let mut preimage = Vec::with_capacity(
            13 + chain_id.len() + 1 + objective_id.len() + 1
               + task_id.len() + 1 + reward_kind_str.len(),
        );
        preimage.extend_from_slice(b"qcb-claim-v1\x00");
        preimage.extend_from_slice(chain_id.as_bytes());
        preimage.push(b'\x00');
        preimage.extend_from_slice(objective_id.as_bytes());
        preimage.push(b'\x00');
        preimage.extend_from_slice(task_id.as_bytes());
        preimage.push(b'\x00');
        preimage.extend_from_slice(reward_kind_str.as_bytes());
        let claim_id = ChainHash::digest(&preimage, HashWidth::Bits256).to_hex();

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
            claim_id:           claim_id.clone(),
            objective_id:       objective_id.to_owned(),
            task_id:            task_id.to_owned(),
            result_id,
            contribution_hash:  contribution_hash.to_owned(),
            recipient:          recipient.to_owned(),
            amount_uqcb,
            policy_version:     RESEARCH_POLICY_VERSION.to_owned(),
            reward_kind:        reward_kind_str.to_owned(),
        };

        Ok(ResearchRewardOutput { claim, amount_uqcb })
    }

    /// The policy version identifier.
    pub fn policy_version(&self) -> &str {
        RESEARCH_POLICY_VERSION
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_pocd::DiscoveryReceipt;

    fn dummy_receipt(id: &str, difficulty_bits: u32, challenge_id: &str) -> DiscoveryReceipt {
        DiscoveryReceipt {
            receipt_id:           id.to_owned(),
            chain_id:             "qcb-devnet-1".to_owned(),
            challenge_id:         challenge_id.to_owned(),
            machine_id:           "qcb1miner".to_owned(),
            output_hash:          "deadbeef".to_owned(),
            input_hash:           "cafebabe".to_owned(),
            methodology_ref:      "ipfs://Qm…".to_owned(),
            discovery_nonce:      42,
            checks_performed:     1_000_000,
            elapsed_seconds:      3.7,
            submitted_at:         "2026-10-08T00:00:00Z".to_owned(),
            machine_signature:    "sig".to_owned(),
            seal_nonce:           0,
            seal_hash:            "0000…".to_owned(),
            seal_difficulty_bits: difficulty_bits,
            verifier_id:          "verifier-1".to_owned(),
            verifier_signature:   "vsig".to_owned(),
            committed_at_block:   100,
            reward_distributed:   false,
            _proof_id:            format!("proof-{id}"),
        }
    }

    #[test]
    fn single_receipt_gets_base_reward_at_min_difficulty() {
        let policy = QcbRewardPolicy::default_for_devnet("treasury:pocd");
        let r = dummy_receipt("r1", MIN_DIFFICULTY, "qcb-devnet-1::Cryptography::test");
        let grants = policy.compute_rewards(&[&r]).unwrap();
        assert_eq!(grants.len(), 1);
        // difficulty_mult = 1, track Cryptography = 2.5×
        let expected = DEFAULT_BASE_REWARD_UQRC * 1 * 250 / 100;
        assert_eq!(grants[0].amount, expected,
            "expected {expected} uQRC, got {}", grants[0].amount);
    }

    #[test]
    fn higher_difficulty_multiplies_reward() {
        let policy = QcbRewardPolicy::default_for_devnet("treasury:pocd");
        let r_low  = dummy_receipt("low",  MIN_DIFFICULTY,      "qcb-devnet-1::Mathematics::easy");
        let r_high = dummy_receipt("high", MIN_DIFFICULTY + 8,  "qcb-devnet-1::Mathematics::hard");
        let grants_low  = policy.compute_rewards(&[&r_low]).unwrap();
        let grants_high = policy.compute_rewards(&[&r_high]).unwrap();
        // +8 bits → 2^2 = 4× difficulty multiplier
        assert_eq!(grants_high[0].amount, grants_low[0].amount * 4,
            "8 extra bits should give 4× reward");
    }

    #[test]
    fn pro_rata_scaling_when_pool_exceeded() {
        // Two equal receipts whose raw total exceeds the pool.
        let base = 1_000_000u64;
        let pool = base; // pool = 1 receipt worth
        let policy = QcbRewardPolicy {
            base_reward_uqrc: base,
            epoch_pool_uqrc:  pool,
            pocd_treasury:    "treasury:pocd".into(),
        };
        // Use Custom track (1×) and MIN_DIFFICULTY (1×) so raw == base.
        let r1 = dummy_receipt("r1", MIN_DIFFICULTY, "qcb-devnet-1::Custom::t");
        let r2 = dummy_receipt("r2", MIN_DIFFICULTY, "qcb-devnet-1::Custom::t");
        let grants = policy.compute_rewards(&[&r1, &r2]).unwrap();
        let total: u64 = grants.iter().map(|g| g.amount).sum();
        assert!(total <= pool, "total {total} should not exceed pool {pool}");
        assert_eq!(grants[0].amount, grants[1].amount, "equal work → equal share");
    }

    #[test]
    fn empty_receipts_returns_empty_grants() {
        let policy = QcbRewardPolicy::default_for_devnet("treasury:pocd");
        let grants = policy.compute_rewards(&[]).unwrap();
        assert!(grants.is_empty());
    }

    #[test]
    fn track_parser_handles_known_and_custom() {
        assert!(matches!(
            track_from_challenge_id("qcb::Cryptography::foo"),
            Some(ChallengeTrack::Cryptography)
        ));
        assert!(matches!(
            track_from_challenge_id("qcb::Mathematics::rsa"),
            Some(ChallengeTrack::Mathematics)
        ));
        assert!(matches!(
            track_from_challenge_id("qcb::BrandNew::x"),
            Some(ChallengeTrack::Custom(_))
        ));
        assert!(track_from_challenge_id("no-separator").is_none());
    }

    // ── QcbResearchRewardPolicy tests ─────────────────────────────────────

    fn dummy_result_id() -> uuid::Uuid {
        uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    #[test]
    fn primary_rate_applied_for_primary_kind() {
        let policy = QcbResearchRewardPolicy::default_for_devnet("treasury:pocd-research");
        let out = policy.compute_reward(
            "qcb-devnet-1",
            "obj-1",
            "task-1",
            dummy_result_id(),
            "deadbeef",
            "qcb1miner",
            RewardKind::Primary,
            0, // no prior disbursements
        ).unwrap();
        assert_eq!(out.amount_uqcb, 5_000_000,
            "primary rate should be 5 QCB = 5_000_000 uqcb");
        assert_eq!(out.claim.policy_version, RESEARCH_POLICY_VERSION);
        assert_eq!(out.claim.reward_kind, "primary");
        assert_eq!(out.claim.recipient, "qcb1miner");
    }

    #[test]
    fn replication_rate_applied_for_replication_kind() {
        let policy = QcbResearchRewardPolicy::default_for_devnet("treasury:pocd-research");
        let out = policy.compute_reward(
            "qcb-devnet-1",
            "obj-1",
            "task-1",
            dummy_result_id(),
            "cafebabe",
            "qcb1replicator",
            RewardKind::Replication,
            0,
        ).unwrap();
        assert_eq!(out.amount_uqcb, 2_000_000,
            "replication rate should be 2 QCB = 2_000_000 uqcb");
        assert_eq!(out.claim.reward_kind, "replication");
    }

    #[test]
    fn deterministic_claim_id_is_stable() {
        let policy = QcbResearchRewardPolicy::default_for_devnet("t");
        let out1 = policy.compute_reward(
            "qcb-devnet-1", "obj-abc", "task-xyz", dummy_result_id(),
            "hash", "wallet", RewardKind::Primary, 0,
        ).unwrap();
        let out2 = policy.compute_reward(
            "qcb-devnet-1", "obj-abc", "task-xyz", dummy_result_id(),
            "hash", "wallet", RewardKind::Primary, 0,
        ).unwrap();
        assert_eq!(out1.claim.claim_id, out2.claim.claim_id,
            "claim_id must be deterministic given the same inputs");
    }

    #[test]
    fn claim_id_differs_for_different_reward_kinds() {
        let policy = QcbResearchRewardPolicy::default_for_devnet("t");
        let primary = policy.compute_reward(
            "qcb-devnet-1", "obj-abc", "task-xyz", dummy_result_id(),
            "hash", "wallet", RewardKind::Primary, 0,
        ).unwrap();
        let replication = policy.compute_reward(
            "qcb-devnet-1", "obj-abc", "task-xyz", dummy_result_id(),
            "hash", "wallet", RewardKind::Replication, 0,
        ).unwrap();
        assert_ne!(primary.claim.claim_id, replication.claim.claim_id,
            "different reward kinds must produce different claim IDs");
    }

    #[test]
    fn budget_exhausted_when_disbursed_plus_rate_exceeds_cap() {
        let policy = QcbResearchRewardPolicy {
            primary_rate_uqcb:     5_000_000,
            replication_rate_uqcb: 2_000_000,
            objective_budget_uqcb: 7_000_000, // room for 1 primary + 1 replication only
            treasury_address:      "t".into(),
        };
        // First primary is fine.
        let _ = policy.compute_reward(
            "qcb-devnet-1", "obj-1", "t-1", dummy_result_id(),
            "h", "w", RewardKind::Primary, 0,
        ).unwrap();
        // After disbursing 5_000_000 (primary), 2_000_000 replication is also fine.
        let _ = policy.compute_reward(
            "qcb-devnet-1", "obj-1", "t-2", dummy_result_id(),
            "h", "w", RewardKind::Replication, 5_000_000,
        ).unwrap();
        // After 7_000_000 disbursed, any further claim hits the budget.
        let err = policy.compute_reward(
            "qcb-devnet-1", "obj-1", "t-3", dummy_result_id(),
            "h", "w", RewardKind::Replication, 7_000_000,
        ).unwrap_err();
        assert!(matches!(err, ResearchRewardError::BudgetExhausted { .. }),
            "expected BudgetExhausted, got: {err:?}");
    }

    #[test]
    fn zero_rate_returns_zero_amount_error() {
        let policy = QcbResearchRewardPolicy {
            primary_rate_uqcb:     0, // misconfiguration
            replication_rate_uqcb: 2_000_000,
            objective_budget_uqcb: 1_000_000_000,
            treasury_address:      "t".into(),
        };
        let err = policy.compute_reward(
            "qcb-devnet-1", "obj-1", "task-1", dummy_result_id(),
            "h", "w", RewardKind::Primary, 0,
        ).unwrap_err();
        assert!(matches!(err, ResearchRewardError::ZeroAmount { .. }),
            "zero primary_rate_uqcb must be rejected");
    }

    #[test]
    fn policy_version_is_v1() {
        let policy = QcbResearchRewardPolicy::default_for_devnet("t");
        assert_eq!(policy.policy_version(), "QcbResearchRewardPolicy-v1");
    }
}
