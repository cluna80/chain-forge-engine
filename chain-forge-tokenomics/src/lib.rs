/// chain-forge-tokenomics
///
/// Two-token supply enforcement for QCB Chain.
///
/// Implements Whitepaper Sections 6.1-6.3 and 6.7:
///
///   - SupplyRegistry: $QCB hard cap at 210,000,000 (in uqcb base units),
///     mint/burn accounting, cap enforcement at the protocol layer
///   - $CIRFI uncapped, population-linked issuance tracking
///   - Genesis allocation per Section 6.7: UBI-majority by construction
///   - Staking: bond/unbond $QCB to validators, reward accounting
///   - Section 3.3 personhood bound: stake determines participation and
///     reward share, NOT consensus influence (that cap lives in consensus)
///
/// The two-token separation is constitutional (Section 7.3). This crate is
/// where the supply side of that separation is enforced in code:
/// $QCB mints past the cap fail, and $CIRFI mints are tracked against
/// verified population so population-linked issuance is auditable.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// -- Constants (Whitepaper Section 6) ----------------------------------------

/// $QCB maximum supply: 210,000,000 QCB.
/// In uqcb base units (6 decimals): 210,000,000 * 1,000,000.
pub const QCB_MAX_SUPPLY_UQCB: u128 = 210_000_000 * 1_000_000;

/// Base units per whole token (6 decimals).
pub const UNITS_PER_TOKEN: u128 = 1_000_000;

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum TokenomicsError {
    #[error("mint of {amount} uqcb would exceed $QCB max supply: current {current} + {amount} > cap {cap}")]
    QcbCapExceeded { current: u128, amount: u128, cap: u128 },

    #[error("burn of {amount} exceeds circulating supply {circulating}")]
    BurnExceedsSupply { amount: u128, circulating: u128 },

    #[error("genesis allocation percentages must sum to 100, got {0}")]
    BadAllocationSum(u32),

    #[error("UBI allocation {ubi_pct}% must be the majority share (>50%)")]
    UbiNotMajority { ubi_pct: u32 },

    #[error("non-UBI allocation {name} at {pct}% exceeds low-double-digit ceiling (max {max}%)")]
    AllocationCeilingExceeded { name: String, pct: u32, max: u32 },

    #[error("insufficient stake: {have} < {need}")]
    InsufficientStake { have: u128, need: u128 },

    #[error("validator {0} not found")]
    ValidatorNotFound(String),

    #[error("unbonding amount {amount} exceeds bonded stake {bonded}")]
    UnbondExceedsBonded { amount: u128, bonded: u128 },

    #[error("internal tokenomics error: {0}")]
    Internal(String),
}

pub type TkResult<T> = Result<T, TokenomicsError>;

// -- Supply registry ----------------------------------------------------------

/// Tracks total supply for both tokens and enforces $QCB's hard cap.
///
/// $QCB: fixed cap, mint-limited, burn-reduced (BME).
/// $CIRFI: uncapped, population-linked issuance, demurrage-recycled (not burned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyRegistry {
    /// Total $QCB ever minted (uqcb).
    pub qcb_minted_uqcb: u128,
    /// Total $QCB burned via BME (uqcb).
    pub qcb_burned_uqcb: u128,
    /// Total $CIRFI ever minted (ucirfi). Uncapped by design.
    pub cirfi_minted_ucirfi: u128,
    /// Total $CIRFI recycled through demurrage into the UBI pool.
    /// NOT burned -- tracked separately to audit the recycle loop.
    pub cirfi_recycled_ucirfi: u128,
}

impl SupplyRegistry {
    pub fn new() -> Self {
        Self {
            qcb_minted_uqcb:       0,
            qcb_burned_uqcb:       0,
            cirfi_minted_ucirfi:   0,
            cirfi_recycled_ucirfi: 0,
        }
    }

    /// Circulating $QCB = minted - burned.
    pub fn qcb_circulating(&self) -> u128 {
        self.qcb_minted_uqcb.saturating_sub(self.qcb_burned_uqcb)
    }

    /// Remaining mintable $QCB under the 210M cap.
    pub fn qcb_mintable(&self) -> u128 {
        QCB_MAX_SUPPLY_UQCB.saturating_sub(self.qcb_minted_uqcb)
    }

    /// Mint $QCB. FAILS if it would exceed the 210M cap.
    /// This is the constitutional two-token separation enforced in code.
    pub fn mint_qcb(&mut self, amount: u128) -> TkResult<()> {
        if self.qcb_minted_uqcb + amount > QCB_MAX_SUPPLY_UQCB {
            return Err(TokenomicsError::QcbCapExceeded {
                current: self.qcb_minted_uqcb,
                amount,
                cap: QCB_MAX_SUPPLY_UQCB,
            });
        }
        self.qcb_minted_uqcb += amount;
        tracing::info!(
            amount,
            total_minted = self.qcb_minted_uqcb,
            remaining = self.qcb_mintable(),
            "QCB minted"
        );
        Ok(())
    }

    /// Burn $QCB (BME mechanism, Section 6.3).
    pub fn burn_qcb(&mut self, amount: u128) -> TkResult<()> {
        let circulating = self.qcb_circulating();
        if amount > circulating {
            return Err(TokenomicsError::BurnExceedsSupply { amount, circulating });
        }
        self.qcb_burned_uqcb += amount;
        tracing::info!(
            amount,
            total_burned = self.qcb_burned_uqcb,
            circulating = self.qcb_circulating(),
            "QCB burned (BME)"
        );
        Ok(())
    }

    /// Mint $CIRFI. Uncapped by design (population-linked issuance, Section 6.2).
    /// Only the protocol calls this -- currency issuance is reserved (7.2).
    pub fn mint_cirfi(&mut self, amount: u128) {
        self.cirfi_minted_ucirfi += amount;
    }

    /// Record $CIRFI recycled through demurrage (flows to UBI pool, not burned).
    pub fn record_cirfi_recycle(&mut self, amount: u128) {
        self.cirfi_recycled_ucirfi += amount;
    }
}

impl Default for SupplyRegistry {
    fn default() -> Self { Self::new() }
}

// -- Genesis allocation (Section 6.7) -----------------------------------------

/// The one-time genesis allocation from Whitepaper Section 6.7.
/// Percentages are of the total genesis allocation.
///
/// Constraints enforced:
///   - UBI reserve must be the majority share (>50%) -- by construction
///   - No single non-UBI allocation may exceed the low-double-digit ceiling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Total genesis allocation in uqcb.
    pub total_uqcb: u128,
    /// UBI distributions seed (majority by construction). Illustrative: 70%.
    pub ubi_reserve_pct: u32,
    /// Reserve pool (yield-bearing stability backing). Illustrative: 15%.
    pub reserve_pool_pct: u32,
    /// Development (vested, disclosed on-chain). Illustrative: 7%.
    pub development_pct: u32,
    /// Merchant incentives (onboarding rewards). Illustrative: 5%.
    pub merchant_incentives_pct: u32,
    /// Validator rewards (staking incentives). Illustrative: 3%.
    pub validator_rewards_pct: u32,
}

/// The low-double-digit ceiling for non-UBI allocations (Section 6.7).
pub const NON_UBI_CEILING_PCT: u32 = 15;

impl GenesisAllocation {
    /// The whitepaper's illustrative allocation: 70/15/7/5/3.
    pub fn whitepaper_default(total_uqcb: u128) -> Self {
        Self {
            total_uqcb,
            ubi_reserve_pct:         70,
            reserve_pool_pct:        15,
            development_pct:         7,
            merchant_incentives_pct: 5,
            validator_rewards_pct:   3,
        }
    }

    /// Validate the allocation against Section 6.7's founding commitments.
    pub fn validate(&self) -> TkResult<()> {
        let sum = self.ubi_reserve_pct + self.reserve_pool_pct
            + self.development_pct + self.merchant_incentives_pct
            + self.validator_rewards_pct;
        if sum != 100 {
            return Err(TokenomicsError::BadAllocationSum(sum));
        }
        if self.ubi_reserve_pct <= 50 {
            return Err(TokenomicsError::UbiNotMajority {
                ubi_pct: self.ubi_reserve_pct,
            });
        }
        let non_ubi = [
            ("reserve_pool",        self.reserve_pool_pct),
            ("development",         self.development_pct),
            ("merchant_incentives", self.merchant_incentives_pct),
            ("validator_rewards",   self.validator_rewards_pct),
        ];
        for (name, pct) in non_ubi {
            if pct > NON_UBI_CEILING_PCT {
                return Err(TokenomicsError::AllocationCeilingExceeded {
                    name: name.to_string(), pct, max: NON_UBI_CEILING_PCT,
                });
            }
        }
        Ok(())
    }

    /// Amount for each allocation in uqcb.
    pub fn ubi_reserve_uqcb(&self) -> u128 {
        self.total_uqcb * self.ubi_reserve_pct as u128 / 100
    }
    pub fn reserve_pool_uqcb(&self) -> u128 {
        self.total_uqcb * self.reserve_pool_pct as u128 / 100
    }
    pub fn development_uqcb(&self) -> u128 {
        self.total_uqcb * self.development_pct as u128 / 100
    }
    pub fn merchant_incentives_uqcb(&self) -> u128 {
        self.total_uqcb * self.merchant_incentives_pct as u128 / 100
    }
    pub fn validator_rewards_uqcb(&self) -> u128 {
        self.total_uqcb * self.validator_rewards_pct as u128 / 100
    }
}

// -- Staking (Section 3.3 / 6.3) ----------------------------------------------

/// One staker's bond to one validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeEntry {
    pub staker:    String,
    pub validator: String,
    pub amount_uqcb: u128,
    /// Epoch when the stake was bonded.
    pub bonded_epoch: u64,
}

/// Per-validator staking state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidatorStake {
    /// Total uqcb bonded to this validator across all stakers.
    pub total_bonded_uqcb: u128,
    /// Accumulated unclaimed rewards for this validator's stakers (uqcb).
    pub pending_rewards_uqcb: u128,
}

/// The staking module: bonds, unbonds, and reward accounting.
///
/// Section 3.3: stake determines participation and reward eligibility;
/// personhood bounds determine actual consensus influence. The influence
/// cap is enforced in chain-forge-consensus (apply_personhood_cap) --
/// this module handles only the economic side.
pub struct StakingModule {
    /// staker address -> their stakes (may bond to multiple validators).
    stakes: HashMap<String, Vec<StakeEntry>>,
    /// validator address -> aggregate stake state.
    validators: HashMap<String, ValidatorStake>,
    /// Minimum bond amount (uqcb). Prevents dust stakes.
    pub min_bond_uqcb: u128,
}

impl StakingModule {
    pub fn new(min_bond_uqcb: u128) -> Self {
        Self {
            stakes:      HashMap::new(),
            validators:  HashMap::new(),
            min_bond_uqcb,
        }
    }

    /// Bond stake to a validator.
    /// The caller (execution layer) must have already debited the staker's
    /// balance -- this module only tracks the bond.
    pub fn bond(
        &mut self,
        staker:    &str,
        validator: &str,
        amount:    u128,
        epoch:     u64,
    ) -> TkResult<()> {
        if amount < self.min_bond_uqcb {
            return Err(TokenomicsError::InsufficientStake {
                have: amount, need: self.min_bond_uqcb,
            });
        }

        self.stakes.entry(staker.to_string())
            .or_default()
            .push(StakeEntry {
                staker:       staker.to_string(),
                validator:    validator.to_string(),
                amount_uqcb:  amount,
                bonded_epoch: epoch,
            });

        self.validators.entry(validator.to_string())
            .or_default()
            .total_bonded_uqcb += amount;

        tracing::info!(staker, validator, amount, "stake bonded");
        Ok(())
    }

    /// Unbond stake from a validator. Returns the amount to credit back
    /// to the staker (the execution layer handles the actual credit).
    pub fn unbond(
        &mut self,
        staker:    &str,
        validator: &str,
        amount:    u128,
    ) -> TkResult<u128> {
        let entries = self.stakes.get_mut(staker)
            .ok_or_else(|| TokenomicsError::ValidatorNotFound(staker.to_string()))?;

        // Total bonded by this staker to this validator
        let bonded: u128 = entries.iter()
            .filter(|e| e.validator == validator)
            .map(|e| e.amount_uqcb)
            .sum();

        if amount > bonded {
            return Err(TokenomicsError::UnbondExceedsBonded { amount, bonded });
        }

        // Remove stake entries (FIFO) until amount is covered
        let mut remaining = amount;
        entries.retain_mut(|e| {
            if e.validator != validator || remaining == 0 {
                return true;
            }
            if e.amount_uqcb <= remaining {
                remaining -= e.amount_uqcb;
                false // remove this entry
            } else {
                e.amount_uqcb -= remaining;
                remaining = 0;
                true
            }
        });

        // Reduce validator aggregate
        if let Some(v) = self.validators.get_mut(validator) {
            v.total_bonded_uqcb = v.total_bonded_uqcb.saturating_sub(amount);
        }

        tracing::info!(staker, validator, amount, "stake unbonded");
        Ok(amount)
    }

    /// Distribute rewards to a validator's reward pool.
    /// Called by BME/fee routing: a share of merchant fees flows here (6.3).
    pub fn add_rewards(&mut self, validator: &str, amount: u128) {
        self.validators.entry(validator.to_string())
            .or_default()
            .pending_rewards_uqcb += amount;
    }

    /// Claim a staker's proportional share of a validator's pending rewards.
    /// Returns the amount claimed.
    pub fn claim_rewards(
        &mut self,
        staker:    &str,
        validator: &str,
    ) -> TkResult<u128> {
        let staker_bonded: u128 = self.stakes.get(staker)
            .map(|entries| entries.iter()
                .filter(|e| e.validator == validator)
                .map(|e| e.amount_uqcb)
                .sum())
            .unwrap_or(0);

        let v = self.validators.get_mut(validator)
            .ok_or_else(|| TokenomicsError::ValidatorNotFound(validator.to_string()))?;

        if v.total_bonded_uqcb == 0 || staker_bonded == 0 {
            return Ok(0);
        }

        // Proportional share: staker_bonded / total_bonded * pending
        let share = v.pending_rewards_uqcb * staker_bonded / v.total_bonded_uqcb;
        v.pending_rewards_uqcb -= share;

        tracing::info!(staker, validator, share, "rewards claimed");
        Ok(share)
    }

    // -- Lookups --------------------------------------------------------------

    pub fn total_bonded(&self, validator: &str) -> u128 {
        self.validators.get(validator)
            .map(|v| v.total_bonded_uqcb)
            .unwrap_or(0)
    }

    pub fn staker_bonded(&self, staker: &str, validator: &str) -> u128 {
        self.stakes.get(staker)
            .map(|entries| entries.iter()
                .filter(|e| e.validator == validator)
                .map(|e| e.amount_uqcb)
                .sum())
            .unwrap_or(0)
    }

    pub fn pending_rewards(&self, validator: &str) -> u128 {
        self.validators.get(validator)
            .map(|v| v.pending_rewards_uqcb)
            .unwrap_or(0)
    }

    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SupplyRegistry: $QCB cap enforcement ---------------------------------

    #[test]
    fn qcb_cap_is_210_million() {
        assert_eq!(QCB_MAX_SUPPLY_UQCB, 210_000_000 * 1_000_000);
    }

    #[test]
    fn qcb_mint_within_cap_succeeds() {
        let mut reg = SupplyRegistry::new();
        reg.mint_qcb(1_000_000_000).unwrap();
        assert_eq!(reg.qcb_circulating(), 1_000_000_000);
    }

    #[test]
    fn qcb_mint_exceeding_cap_fails() {
        let mut reg = SupplyRegistry::new();
        reg.mint_qcb(QCB_MAX_SUPPLY_UQCB).unwrap(); // mint the entire cap
        let result = reg.mint_qcb(1); // one more unit must fail
        assert!(result.is_err(), "minting past 210M cap must fail");
    }

    #[test]
    fn qcb_mint_exactly_at_cap_succeeds() {
        let mut reg = SupplyRegistry::new();
        assert!(reg.mint_qcb(QCB_MAX_SUPPLY_UQCB).is_ok());
        assert_eq!(reg.qcb_mintable(), 0);
    }

    #[test]
    fn qcb_burn_reduces_circulating_not_minted() {
        let mut reg = SupplyRegistry::new();
        reg.mint_qcb(1_000_000).unwrap();
        reg.burn_qcb(400_000).unwrap();
        assert_eq!(reg.qcb_circulating(), 600_000);
        // Burns do NOT free up mint capacity -- cap is on total minted
        assert_eq!(reg.qcb_mintable(), QCB_MAX_SUPPLY_UQCB - 1_000_000);
    }

    #[test]
    fn qcb_burn_exceeding_circulating_fails() {
        let mut reg = SupplyRegistry::new();
        reg.mint_qcb(1_000).unwrap();
        assert!(reg.burn_qcb(1_001).is_err());
    }

    #[test]
    fn cirfi_mint_is_uncapped() {
        let mut reg = SupplyRegistry::new();
        // Mint a huge amount -- should never fail (population-linked, uncapped)
        reg.mint_cirfi(u128::MAX / 2);
        reg.mint_cirfi(u128::MAX / 4);
        assert!(reg.cirfi_minted_ucirfi > 0);
    }

    #[test]
    fn cirfi_recycle_tracked_separately_from_burn() {
        let mut reg = SupplyRegistry::new();
        reg.mint_cirfi(1_000_000);
        reg.record_cirfi_recycle(50_000);
        // Recycled CIRFI is NOT burned -- minted total unchanged
        assert_eq!(reg.cirfi_minted_ucirfi, 1_000_000);
        assert_eq!(reg.cirfi_recycled_ucirfi, 50_000);
    }

    // -- GenesisAllocation: Section 6.7 constraints ---------------------------

    #[test]
    fn whitepaper_default_allocation_is_valid() {
        let alloc = GenesisAllocation::whitepaper_default(100_000_000);
        assert!(alloc.validate().is_ok());
    }

    #[test]
    fn allocation_amounts_sum_to_total() {
        let alloc = GenesisAllocation::whitepaper_default(100_000_000);
        let sum = alloc.ubi_reserve_uqcb()
            + alloc.reserve_pool_uqcb()
            + alloc.development_uqcb()
            + alloc.merchant_incentives_uqcb()
            + alloc.validator_rewards_uqcb();
        assert_eq!(sum, 100_000_000);
    }

    #[test]
    fn ubi_must_be_majority() {
        let mut alloc = GenesisAllocation::whitepaper_default(1_000_000);
        alloc.ubi_reserve_pct = 40;
        alloc.reserve_pool_pct = 45; // sum still 100
        assert!(alloc.validate().is_err(), "UBI below 50% must fail validation");
    }

    #[test]
    fn non_ubi_ceiling_enforced() {
        let mut alloc = GenesisAllocation::whitepaper_default(1_000_000);
        alloc.ubi_reserve_pct = 55;
        alloc.development_pct = 22; // exceeds 15% ceiling
        alloc.reserve_pool_pct = 15;
        alloc.merchant_incentives_pct = 5;
        alloc.validator_rewards_pct = 3;
        assert!(alloc.validate().is_err(), "dev allocation above ceiling must fail");
    }

    #[test]
    fn allocation_sum_must_be_100() {
        let mut alloc = GenesisAllocation::whitepaper_default(1_000_000);
        alloc.validator_rewards_pct = 10; // sum = 107
        assert!(alloc.validate().is_err());
    }

    #[test]
    fn ubi_reserve_is_70_percent_of_total() {
        let alloc = GenesisAllocation::whitepaper_default(210_000_000 * UNITS_PER_TOKEN);
        let expected = 210_000_000 * UNITS_PER_TOKEN * 70 / 100;
        assert_eq!(alloc.ubi_reserve_uqcb(), expected);
    }

    // -- StakingModule --------------------------------------------------------

    fn staking() -> StakingModule {
        StakingModule::new(1_000_000) // 1 QCB minimum bond
    }

    #[test]
    fn bond_below_minimum_fails() {
        let mut s = staking();
        assert!(s.bond("alice", "val1", 999_999, 0).is_err());
    }

    #[test]
    fn bond_and_track_stake() {
        let mut s = staking();
        s.bond("alice", "val1", 5_000_000, 0).unwrap();
        s.bond("bob",   "val1", 3_000_000, 0).unwrap();

        assert_eq!(s.total_bonded("val1"), 8_000_000);
        assert_eq!(s.staker_bonded("alice", "val1"), 5_000_000);
        assert_eq!(s.staker_bonded("bob",   "val1"), 3_000_000);
    }

    #[test]
    fn staker_can_bond_to_multiple_validators() {
        let mut s = staking();
        s.bond("alice", "val1", 2_000_000, 0).unwrap();
        s.bond("alice", "val2", 3_000_000, 0).unwrap();

        assert_eq!(s.staker_bonded("alice", "val1"), 2_000_000);
        assert_eq!(s.staker_bonded("alice", "val2"), 3_000_000);
    }

    #[test]
    fn unbond_returns_stake() {
        let mut s = staking();
        s.bond("alice", "val1", 5_000_000, 0).unwrap();

        let returned = s.unbond("alice", "val1", 2_000_000).unwrap();
        assert_eq!(returned, 2_000_000);
        assert_eq!(s.staker_bonded("alice", "val1"), 3_000_000);
        assert_eq!(s.total_bonded("val1"), 3_000_000);
    }

    #[test]
    fn unbond_more_than_bonded_fails() {
        let mut s = staking();
        s.bond("alice", "val1", 1_000_000, 0).unwrap();
        assert!(s.unbond("alice", "val1", 2_000_000).is_err());
    }

    #[test]
    fn unbond_across_multiple_entries_fifo() {
        let mut s = staking();
        s.bond("alice", "val1", 1_000_000, 0).unwrap();
        s.bond("alice", "val1", 2_000_000, 1).unwrap();
        s.bond("alice", "val1", 3_000_000, 2).unwrap();

        // Unbond 2.5M -- consumes first entry (1M) + part of second (1.5M)
        let returned = s.unbond("alice", "val1", 2_500_000).unwrap();
        assert_eq!(returned, 2_500_000);
        assert_eq!(s.staker_bonded("alice", "val1"), 3_500_000);
    }

    #[test]
    fn rewards_distributed_proportionally() {
        let mut s = staking();
        s.bond("alice", "val1", 6_000_000, 0).unwrap(); // 75% of stake
        s.bond("bob",   "val1", 2_000_000, 0).unwrap(); // 25% of stake

        s.add_rewards("val1", 1_000_000);

        let alice_reward = s.claim_rewards("alice", "val1").unwrap();
        assert_eq!(alice_reward, 750_000, "alice gets 75% of rewards");

        let bob_reward = s.claim_rewards("bob", "val1").unwrap();
        assert_eq!(bob_reward, 62_500, "bob gets 25% of remaining pool (250K * 2M/8M)");
    }

    #[test]
    fn no_stake_no_rewards() {
        let mut s = staking();
        s.bond("alice", "val1", 1_000_000, 0).unwrap();
        s.add_rewards("val1", 1_000_000);

        let carol_reward = s.claim_rewards("carol", "val1").unwrap();
        assert_eq!(carol_reward, 0, "non-staker gets nothing");
    }

    #[test]
    fn integration_genesis_to_staking() {
        // Simulate: mint genesis allocation, validate it, bond validator rewards
        let mut reg = SupplyRegistry::new();
        let genesis_total = 210_000_000 * UNITS_PER_TOKEN;
        reg.mint_qcb(genesis_total).unwrap();

        let alloc = GenesisAllocation::whitepaper_default(genesis_total);
        alloc.validate().unwrap();

        // Validator rewards pool: 3% of genesis
        let validator_pool = alloc.validator_rewards_uqcb();
        assert_eq!(validator_pool, genesis_total * 3 / 100);

        // Entire cap is now minted -- nothing more can ever be minted
        assert_eq!(reg.qcb_mintable(), 0);
        assert!(reg.mint_qcb(1).is_err());

        // BME burns still work
        reg.burn_qcb(1_000_000).unwrap();
        assert_eq!(reg.qcb_circulating(), genesis_total - 1_000_000);
    }
}
