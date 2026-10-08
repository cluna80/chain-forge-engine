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
}
