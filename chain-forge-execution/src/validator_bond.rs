// SPDX-License-Identifier: MIT

//! Validator Onboarding — Permissionless Entry via Stake Bond.
//!
//! Implements the `BondValidator` / `UnbondValidator` tx types and the
//! stake-ranking logic from `ROADMAP.md`'s "Validator Onboarding —
//! Permissionless Entry via Stake Bond" section: anyone who bonds the
//! minimum uqcb can become a validator candidate; no whitelist, no
//! committee approval. Existing slashing (liveness + equivocation) is the
//! Sybil defense -- bonding itself does not vet who may bond.
//!
//! This module is self-contained (same shape as `feesponsor::store`,
//! `chain_forge_agents::AgentStore`): it owns the bonding bookkeeping, and
//! the executor mirrors its decisions onto `StateStore` (the bonded uqcb
//! actually moves to a `treasury:validator-bonds` account, same convention
//! as `DepositToTreasury`).
//!
//! Scope note: this module implements bonding, unbonding-with-cooldown, and
//! the stake-ranked active-set computation (`active_set()`). It does NOT
//! wire that computed active set into the live consensus engine's
//! `ValidatorSet` at epoch boundaries -- today, `chain-forge-node` builds
//! `ValidatorSet` once from genesis and never recomputes it (see
//! `chain-forge-node/src/node.rs`, `genesis_vs`). Swapping the consensus
//! engine's live validator set at each epoch boundary from
//! `ValidatorBondStore::active_set()` is the remaining integration work,
//! tracked in `ROADMAP.md`.

use std::collections::HashMap;

/// Deterministic virtual account holding all currently-bonded stake.
/// Same convention as `treasury:{agent_id}` / `treasury:pocd-research` --
/// never held by any private key, only moved by this module's logic.
pub const VALIDATOR_BOND_TREASURY: &str = "treasury:validator-bonds";

/// Minimum total bonded uqcb a validator candidate must hold to be eligible
/// for the active set (ROADMAP "Minimum bond threshold" -- low enough for
/// individual participation, high enough to make Sybil attacks expensive).
/// A genesis-config knob is a natural follow-up; hardcoded here for FS-01-style
/// first slice, same as FeeSponsor's DEFAULT_EXPIRY_WINDOW_BLOCKS.
pub const DEFAULT_MIN_BOND_UQCB: u128 = 1_000_000;

/// BFT doesn't scale to thousands of validators (ROADMAP "Maximum active
/// validator set size"); cap the ranked active set here.
pub const DEFAULT_MAX_ACTIVE_VALIDATORS: usize = 150;

/// Epochs a validator's stake remains locked (and slashable) after
/// `UnbondValidator`, before it can be swept back to the owner's balance.
pub const DEFAULT_UNBONDING_COOLDOWN_EPOCHS: u64 = 21;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BondError {
    #[error("validator {0:?} has no bonded stake")]
    NotBonded(String),
    #[error("validator {0:?} already has an unbonding request in progress (unlocks at epoch {1})")]
    UnbondAlreadyInProgress(String, u64),
    #[error("nothing to sweep for validator {0:?}: no matured unbonding entry")]
    NothingToSweep(String),
}

/// A validator's stake still locked by an in-flight `UnbondValidator`
/// request. Remains slashable until `unlock_epoch` (ROADMAP "Unbonding
/// cooldown enforcement... slashable during cooldown") -- this module
/// tracks the lock; wiring it into the slashing crate's view of
/// slashable balance is a follow-up alongside the consensus-set wiring
/// noted in the module doc comment above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbondingEntry {
    pub amount_uqcb: u128,
    pub unlock_epoch: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BondRecord {
    /// Currently bonded and counted toward active-set ranking.
    pub bonded_uqcb: u128,
    /// Set by `UnbondValidator`; cleared once `sweep_matured()` releases it.
    pub unbonding: Option<UnbondingEntry>,
}

/// In-memory validator bonding registry.
#[derive(Debug, Clone, Default)]
pub struct ValidatorBondStore {
    records: HashMap<String, BondRecord>,
}

impl ValidatorBondStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, validator: &str) -> Option<&BondRecord> {
        self.records.get(validator)
    }

    /// `BondValidator` — increase `validator`'s bonded stake. Any amount is
    /// accepted (incremental bonding is allowed); whether the resulting
    /// total clears `min_bond` only matters for `active_set()` eligibility,
    /// checked at ranking time rather than at bond time, so a validator
    /// can bond in installments before reaching the threshold.
    pub fn bond(&mut self, validator: &str, amount_uqcb: u128) {
        let rec = self.records.entry(validator.to_string()).or_default();
        rec.bonded_uqcb = rec.bonded_uqcb.saturating_add(amount_uqcb);
    }

    /// `UnbondValidator` — move the validator's entire currently-bonded
    /// stake into a cooldown lock. Stops counting toward `active_set()`
    /// immediately (ROADMAP: "Stake-ranked validator set... top-N stakers
    /// automatically enter/exit"); funds are not released to the owner
    /// until `sweep_matured()` after `unlock_epoch`. Only one unbonding
    /// request may be in flight at a time -- this prevents "slash-and-run"
    /// by never letting a validator queue multiple overlapping cooldowns
    /// to confuse which funds are actually locked when.
    pub fn start_unbond(
        &mut self,
        validator: &str,
        current_epoch: u64,
        cooldown_epochs: u64,
    ) -> Result<u128, BondError> {
        let rec = self
            .records
            .get_mut(validator)
            .ok_or_else(|| BondError::NotBonded(validator.to_string()))?;

        if let Some(existing) = &rec.unbonding {
            return Err(BondError::UnbondAlreadyInProgress(
                validator.to_string(),
                existing.unlock_epoch,
            ));
        }
        if rec.bonded_uqcb == 0 {
            return Err(BondError::NotBonded(validator.to_string()));
        }

        let amount = rec.bonded_uqcb;
        rec.bonded_uqcb = 0;
        rec.unbonding = Some(UnbondingEntry {
            amount_uqcb: amount,
            unlock_epoch: current_epoch.saturating_add(cooldown_epochs),
        });
        Ok(amount)
    }

    /// If `validator` has a matured (cooldown-expired) unbonding entry,
    /// clear it and return the amount to release back to the owner's
    /// account balance. The caller (the executor) is responsible for
    /// actually crediting that amount -- this store only tracks the
    /// bonding bookkeeping, not StateStore balances.
    pub fn sweep_matured(&mut self, validator: &str, current_epoch: u64) -> Option<u128> {
        let rec = self.records.get_mut(validator)?;
        let entry = rec.unbonding.as_ref()?;
        if current_epoch < entry.unlock_epoch {
            return None;
        }
        let amount = entry.amount_uqcb;
        rec.unbonding = None;
        Some(amount)
    }

    /// Same as `sweep_matured`, but returns an error distinguishing "not
    /// bonded at all" from "nothing matured yet" -- useful for the tx
    /// handler to decide what event/error message to emit.
    pub fn try_sweep_matured(
        &mut self,
        validator: &str,
        current_epoch: u64,
    ) -> Result<u128, BondError> {
        match self.records.get(validator) {
            None => Err(BondError::NotBonded(validator.to_string())),
            Some(rec) if rec.unbonding.is_none() => {
                Err(BondError::NothingToSweep(validator.to_string()))
            }
            Some(_) => self
                .sweep_matured(validator, current_epoch)
                .ok_or_else(|| BondError::NothingToSweep(validator.to_string())),
        }
    }

    /// Stake-ranked active set: the top `max_size` validators by
    /// `bonded_uqcb`, excluding anyone below `min_bond_uqcb` or currently
    /// fully unbonding (bonded_uqcb == 0). Ties broken by validator address
    /// for determinism across nodes (BTreeMap iteration order is not
    /// guaranteed to match insertion, and HashMap iteration order is
    /// explicitly randomized per-process, so this sort must be total and
    /// must not depend on map iteration order alone).
    pub fn active_set(&self, max_size: usize, min_bond_uqcb: u128) -> Vec<(String, u128)> {
        let mut candidates: Vec<(String, u128)> = self
            .records
            .iter()
            .filter(|(_, rec)| rec.bonded_uqcb >= min_bond_uqcb)
            .map(|(addr, rec)| (addr.clone(), rec.bonded_uqcb))
            .collect();

        // Descending by stake, then ascending by address for a total,
        // deterministic order every node computes identically.
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        candidates.truncate(max_size);
        candidates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incremental_bonding_accumulates() {
        let mut store = ValidatorBondStore::new();
        store.bond("qcb1alice", 500_000);
        store.bond("qcb1alice", 600_000);
        assert_eq!(store.get("qcb1alice").unwrap().bonded_uqcb, 1_100_000);
    }

    #[test]
    fn below_min_bond_excluded_from_active_set() {
        let mut store = ValidatorBondStore::new();
        store.bond("qcb1alice", 500_000); // below 1_000_000 default min
        store.bond("qcb1bob", 2_000_000);
        let active = store.active_set(DEFAULT_MAX_ACTIVE_VALIDATORS, DEFAULT_MIN_BOND_UQCB);
        assert_eq!(active, vec![("qcb1bob".to_string(), 2_000_000)]);
    }

    #[test]
    fn active_set_ranked_by_stake_desc_then_address_asc() {
        let mut store = ValidatorBondStore::new();
        store.bond("qcb1charlie", 5_000_000);
        store.bond("qcb1alice", 5_000_000); // tie with charlie -- address breaks it
        store.bond("qcb1bob", 9_000_000);
        let active = store.active_set(10, DEFAULT_MIN_BOND_UQCB);
        assert_eq!(
            active,
            vec![
                ("qcb1bob".to_string(), 9_000_000),
                ("qcb1alice".to_string(), 5_000_000),
                ("qcb1charlie".to_string(), 5_000_000),
            ]
        );
    }

    #[test]
    fn active_set_capped_at_max_size() {
        let mut store = ValidatorBondStore::new();
        for i in 0..10 {
            store.bond(&format!("qcb1val{i:02}"), DEFAULT_MIN_BOND_UQCB + i as u128);
        }
        let active = store.active_set(3, DEFAULT_MIN_BOND_UQCB);
        assert_eq!(active.len(), 3);
        // Highest stakes first: val09, val08, val07.
        assert_eq!(active[0].0, "qcb1val09");
        assert_eq!(active[2].0, "qcb1val07");
    }

    #[test]
    fn unbonding_removes_from_active_set_immediately() {
        let mut store = ValidatorBondStore::new();
        store.bond("qcb1alice", 5_000_000);
        store
            .start_unbond("qcb1alice", 100, DEFAULT_UNBONDING_COOLDOWN_EPOCHS)
            .unwrap();
        assert_eq!(store.get("qcb1alice").unwrap().bonded_uqcb, 0);
        assert_eq!(store.active_set(10, DEFAULT_MIN_BOND_UQCB), vec![]);
    }

    #[test]
    fn unbonding_without_a_bond_rejected() {
        let mut store = ValidatorBondStore::new();
        let err = store
            .start_unbond("qcb1nobody", 0, DEFAULT_UNBONDING_COOLDOWN_EPOCHS)
            .unwrap_err();
        assert_eq!(err, BondError::NotBonded("qcb1nobody".to_string()));
    }

    #[test]
    fn double_unbond_rejected_prevents_slash_and_run_confusion() {
        let mut store = ValidatorBondStore::new();
        store.bond("qcb1alice", 5_000_000);
        store
            .start_unbond("qcb1alice", 100, DEFAULT_UNBONDING_COOLDOWN_EPOCHS)
            .unwrap();
        // A second unbond attempt while one is already cooling down is
        // rejected explicitly -- not silently queued as a second,
        // independent cooldown entry (which would make it ambiguous which
        // funds are locked until when).
        let err = store
            .start_unbond("qcb1alice", 101, DEFAULT_UNBONDING_COOLDOWN_EPOCHS)
            .unwrap_err();
        assert_eq!(
            err,
            BondError::UnbondAlreadyInProgress(
                "qcb1alice".to_string(),
                100 + DEFAULT_UNBONDING_COOLDOWN_EPOCHS
            )
        );
    }

    #[test]
    fn sweep_before_cooldown_elapses_returns_none() {
        let mut store = ValidatorBondStore::new();
        store.bond("qcb1alice", 5_000_000);
        store.start_unbond("qcb1alice", 100, 21).unwrap();
        // Still within the cooldown window.
        assert_eq!(store.sweep_matured("qcb1alice", 110), None);
    }

    #[test]
    fn sweep_after_cooldown_elapses_releases_funds_once() {
        let mut store = ValidatorBondStore::new();
        store.bond("qcb1alice", 5_000_000);
        store.start_unbond("qcb1alice", 100, 21).unwrap();
        assert_eq!(store.sweep_matured("qcb1alice", 121), Some(5_000_000));
        // Already swept -- nothing left to release a second time.
        assert_eq!(store.sweep_matured("qcb1alice", 200), None);
    }

    #[test]
    fn try_sweep_matured_distinguishes_not_bonded_from_nothing_matured() {
        let mut store = ValidatorBondStore::new();
        let err = store.try_sweep_matured("qcb1nobody", 0).unwrap_err();
        assert_eq!(err, BondError::NotBonded("qcb1nobody".to_string()));

        store.bond("qcb1alice", 5_000_000);
        let err = store.try_sweep_matured("qcb1alice", 0).unwrap_err();
        assert_eq!(err, BondError::NothingToSweep("qcb1alice".to_string()));
    }

    #[test]
    fn rebonding_after_full_unbond_starts_a_fresh_record() {
        // A validator who fully unbonds, waits out cooldown, and bonds
        // again should be treated as a normal new bond -- not blocked by
        // stale unbonding state.
        let mut store = ValidatorBondStore::new();
        store.bond("qcb1alice", 5_000_000);
        store.start_unbond("qcb1alice", 100, 21).unwrap();
        store.sweep_matured("qcb1alice", 121);
        store.bond("qcb1alice", 2_000_000);
        assert_eq!(store.get("qcb1alice").unwrap().bonded_uqcb, 2_000_000);
        assert!(store.get("qcb1alice").unwrap().unbonding.is_none());
        // And can unbond again normally.
        assert!(store.start_unbond("qcb1alice", 121, 21).is_ok());
    }
}
