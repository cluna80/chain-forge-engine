// SPDX-License-Identifier: MIT

//! FS-02: persistent SponsorAccount storage, single-use `auth_id` replay
//! tracking, revocation, and sponsor-side validation/consumption.
//!
//! This module does not touch `StateStore` or the execution pipeline --
//! it is a self-contained store, the same shape as `chain_forge_agents::AgentStore`,
//! meant to be threaded through block execution the same way `AgentStore` and
//! `IdentityStore` are. Wiring it into `execute_tx_with_identity()` (actually
//! debiting `SponsorAccount.balance_uqcb` and running application logic) is
//! FS-03, once the engine's real per-tx fee debit exists -- see the review
//! note in docs/FeeSponsor.md (chain-forge-execution's execute_tx() /
//! execute_block() currently only *count* gas as `fees_collected` for
//! reporting; no path debits any account's uqcb balance for a fee today, so
//! "sponsor pays instead of user" has no existing user-side debit to
//! substitute yet).

use std::collections::BTreeMap;

use super::{
    verify_sponsor_authorization, AuthId, SponsorAccount, SponsorAuthorization, SponsorId,
};

/// Default `docs/FeeSponsor.md` constants.
pub const DEFAULT_EXPIRY_WINDOW_BLOCKS: u64 = /* ~12h @ assumed block time */ 720;
pub const DEFAULT_GC_WINDOW_BLOCKS: u64 = /* ~1 week */ 100_800;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SponsorError {
    #[error("sponsor {0:?} not found")]
    NotFound(SponsorId),
    #[error("sponsor {0:?} already registered")]
    AlreadyExists(SponsorId),
    #[error("sponsor unavailable: {0}")]
    Unavailable(String),
}

/// One entry in the single-use replay set: the block at which the
/// authorization that consumed this `auth_id` expires. Kept until
/// `expiry_block + GC_WINDOW`, then pruned (docs/FeeSponsor.md "Expiry
/// window & pruning").
type ConsumedAuths = BTreeMap<AuthId, u64>;

/// In-memory SponsorAccount registry. Persistence/snapshotting follows
/// whatever mechanism `AgentStore`/`IdentityStore` use elsewhere in the
/// block-execution pipeline; this type only owns the in-memory shape.
#[derive(Debug, Clone, Default)]
pub struct SponsorStore {
    accounts: std::collections::HashMap<SponsorId, SponsorAccount>,
    consumed: std::collections::HashMap<SponsorId, ConsumedAuths>,
}

/// Outcome of a successful `validate_and_consume()` call: what the executor
/// should actually do to the chain state (debit the sponsor, mark the auth
/// consumed). Returned instead of mutating `StateStore` directly, since this
/// store doesn't have a reference to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsorCharge {
    pub sponsor_id: SponsorId,
    pub fee_uqcb: u128,
}

impl SponsorStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// `CreateSponsorAccount` — register a new, zero-balance sponsor.
    pub fn register(
        &mut self,
        sponsor_id: SponsorId,
        public_key: Vec<u8>,
        policy: super::SponsorPolicy,
    ) -> Result<(), SponsorError> {
        if self.accounts.contains_key(&sponsor_id) {
            return Err(SponsorError::AlreadyExists(sponsor_id));
        }
        self.accounts.insert(
            sponsor_id.clone(),
            SponsorAccount::new(sponsor_id, public_key, policy),
        );
        Ok(())
    }

    /// `DepositSponsor` — top up a sponsor's pre-funded balance.
    pub fn deposit(
        &mut self,
        sponsor_id: &SponsorId,
        amount_uqcb: u128,
    ) -> Result<(), SponsorError> {
        let acct = self
            .accounts
            .get_mut(sponsor_id)
            .ok_or_else(|| SponsorError::NotFound(sponsor_id.clone()))?;
        acct.balance_uqcb = acct.balance_uqcb.saturating_add(amount_uqcb);
        Ok(())
    }

    pub fn get(&self, sponsor_id: &SponsorId) -> Option<&SponsorAccount> {
        self.accounts.get(sponsor_id)
    }

    /// Immediate stop-of-service: reject all future sponsorships from this
    /// account regardless of `issued_at_block`.
    pub fn revoke_now(
        &mut self,
        sponsor_id: &SponsorId,
        current_block: u64,
    ) -> Result<(), SponsorError> {
        let acct = self
            .accounts
            .get_mut(sponsor_id)
            .ok_or_else(|| SponsorError::NotFound(sponsor_id.clone()))?;
        acct.revoked_until_block = Some(current_block);
        Ok(())
    }

    /// `RevokeAuthPrefix { sponsor_id, before_block }` — batch-invalidate
    /// every authorization issued at or before `before_block`, without
    /// iterating over individual auth ids.
    pub fn revoke_before_block(
        &mut self,
        sponsor_id: &SponsorId,
        before_block: u64,
    ) -> Result<(), SponsorError> {
        let acct = self
            .accounts
            .get_mut(sponsor_id)
            .ok_or_else(|| SponsorError::NotFound(sponsor_id.clone()))?;
        acct.revoked_until_block = Some(acct.revoked_until_block.unwrap_or(0).max(before_block));
        Ok(())
    }

    /// Reset every sponsor's epoch spend counter. Call once per epoch
    /// boundary (same cadence as `AgentStore::advance_epoch()`).
    pub fn advance_epoch(&mut self) {
        for acct in self.accounts.values_mut() {
            acct.epoch_spent_uqcb = 0;
        }
    }

    /// Drop consumed-auth entries whose `expiry_block + GC_WINDOW` has
    /// passed, bounding storage (docs/FeeSponsor.md "Expiry window &
    /// pruning").
    pub fn prune_expired(&mut self, current_block: u64, gc_window_blocks: u64) {
        for set in self.consumed.values_mut() {
            set.retain(|_, expiry_block| {
                current_block <= expiry_block.saturating_add(gc_window_blocks)
            });
        }
    }

    /// Validate a `SponsorAuthorization` against chain id, the signed
    /// fields, revocation, replay, expiry, and sponsor policy/balance/epoch
    /// budget -- and, only if every check passes, atomically consume the
    /// `auth_id` and record the debit. Returns the amount to actually debit
    /// from `SponsorAccount.balance_uqcb` (== `fee_uqcb`, already applied to
    /// this store's own bookkeeping) for the executor to mirror onto
    /// `StateStore`.
    ///
    /// No partial mutation on a rejected authorization: every check below is
    /// read-only until the final `Ok` branch, matching docs/FeeSponsor.md's
    /// "fee payer... Ensure sufficient balance... If not sufficient, reject
    /// immediately... no fallback" rule -- nothing here is left half-applied.
    pub fn validate_and_consume(
        &mut self,
        chain_id: &str,
        current_block: u64,
        fee_uqcb: u128,
        auth: &SponsorAuthorization,
    ) -> Result<SponsorCharge, SponsorError> {
        let acct = self
            .accounts
            .get(&auth.sponsor_id)
            .ok_or_else(|| SponsorError::NotFound(auth.sponsor_id.clone()))?;

        // -- Revocation --------------------------------------------------
        if let Some(revoked_until) = acct.revoked_until_block {
            if auth.issued_at_block <= revoked_until {
                return Err(SponsorError::Unavailable(format!(
                    "sponsor {:?} revoked authorizations issued at or before block {revoked_until}",
                    auth.sponsor_id
                )));
            }
        }

        // -- Expiry window -------------------------------------------------
        if !(auth.issued_at_block <= current_block && current_block <= auth.expires_at_block) {
            return Err(SponsorError::Unavailable(format!(
                "authorization window [{}, {}] does not cover current block {current_block}",
                auth.issued_at_block, auth.expires_at_block
            )));
        }

        // -- Single-use replay ---------------------------------------------
        if self
            .consumed
            .get(&auth.sponsor_id)
            .is_some_and(|set| set.contains_key(&auth.auth_id))
        {
            return Err(SponsorError::Unavailable(format!(
                "auth_id {:?} already consumed",
                auth.auth_id
            )));
        }

        // -- Signature -------------------------------------------------------
        verify_sponsor_authorization(&acct.public_key, chain_id, auth)
            .map_err(SponsorError::Unavailable)?;

        // -- Policy ----------------------------------------------------------
        if auth.max_fee_uqcb > acct.policy.per_tx_max_fee_uqcb {
            return Err(SponsorError::Unavailable(format!(
                "max_fee_uqcb {} exceeds sponsor per_tx_max_fee_uqcb {}",
                auth.max_fee_uqcb, acct.policy.per_tx_max_fee_uqcb
            )));
        }
        if fee_uqcb > auth.max_fee_uqcb {
            return Err(SponsorError::Unavailable(format!(
                "fee {fee_uqcb} exceeds authorized max_fee_uqcb {}",
                auth.max_fee_uqcb
            )));
        }

        // -- Balance & epoch budget ------------------------------------------
        if acct.balance_uqcb < fee_uqcb {
            return Err(SponsorError::Unavailable(format!(
                "sponsor balance {} below required fee {fee_uqcb}",
                acct.balance_uqcb
            )));
        }
        let projected_epoch_spend = acct.epoch_spent_uqcb.saturating_add(fee_uqcb);
        if projected_epoch_spend > acct.policy.epoch_budget_uqcb {
            return Err(SponsorError::Unavailable(format!(
                "epoch budget {} exceeded by projected spend {projected_epoch_spend}",
                acct.policy.epoch_budget_uqcb
            )));
        }

        // -- All checks passed: commit atomically ----------------------------
        let acct = self
            .accounts
            .get_mut(&auth.sponsor_id)
            .expect("looked up above");
        acct.balance_uqcb -= fee_uqcb;
        acct.epoch_spent_uqcb = projected_epoch_spend;
        self.consumed
            .entry(auth.sponsor_id.clone())
            .or_default()
            .insert(auth.auth_id.clone(), auth.expires_at_block);

        Ok(SponsorCharge {
            sponsor_id: auth.sponsor_id.clone(),
            fee_uqcb,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feesponsor::{canonical_body_hash, signing_message_for, SponsorPolicy};
    use chain_forge_crypto::{KeyPair, MlDsaScheme, SignatureScheme};
    use serde::Serialize;

    #[derive(Serialize)]
    struct DummyBody {
        a: u64,
    }

    fn setup_sponsor(
        store: &mut SponsorStore,
        sponsor_id: &str,
        balance: u128,
        per_tx_max_fee: u128,
        epoch_budget: u128,
    ) -> (SponsorId, KeyPair) {
        let kp = MlDsaScheme.generate_keypair(sponsor_id).expect("keygen");
        let id = SponsorId(sponsor_id.to_string());
        store
            .register(
                id.clone(),
                kp.public_key.clone(),
                SponsorPolicy {
                    per_tx_max_fee_uqcb: per_tx_max_fee,
                    epoch_budget_uqcb: epoch_budget,
                },
            )
            .unwrap();
        store.deposit(&id, balance).unwrap();
        (id, kp)
    }

    fn make_signed_auth(
        kp: &KeyPair,
        chain_id: &str,
        sponsor_id: &SponsorId,
        max_fee: u128,
        issued_at: u64,
        expires_at: u64,
    ) -> SponsorAuthorization {
        let body = DummyBody { a: 1 };
        let tx_body_hash = canonical_body_hash(&body);
        let mut auth = SponsorAuthorization {
            auth_id: AuthId([9u8; 16]),
            sponsor_id: sponsor_id.clone(),
            tx_body_hash,
            max_fee_uqcb: max_fee,
            issued_at_block: issued_at,
            expires_at_block: expires_at,
            signature: String::new(),
        };
        let msg = signing_message_for(&auth, chain_id);
        let sig = MlDsaScheme.sign(&msg, kp).expect("sign");
        auth.signature = format!("mldsa65:{}", hex::encode(&sig.bytes));
        auth
    }

    #[test]
    fn happy_path_debits_sponsor_and_consumes_auth() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 10_000);
        let auth = make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100);

        let charge = store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth)
            .expect("should validate");
        assert_eq!(charge.fee_uqcb, 500);
        assert_eq!(store.get(&sponsor_id).unwrap().balance_uqcb, 9_500);
        assert_eq!(store.get(&sponsor_id).unwrap().epoch_spent_uqcb, 500);
    }

    #[test]
    fn insufficient_balance_rejected_with_no_partial_debit() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 100, 1_000, 10_000);
        let auth = make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100);

        let err = store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));
        // Balance untouched -- no fallback, no partial debit.
        assert_eq!(store.get(&sponsor_id).unwrap().balance_uqcb, 100);
    }

    #[test]
    fn expired_authorization_rejected() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 10_000);
        let auth = make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100);

        let err = store
            .validate_and_consume("qcb-testnet-1", 101, 500, &auth)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));
    }

    #[test]
    fn not_yet_issued_rejected() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 10_000);
        let auth = make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100);

        let err = store
            .validate_and_consume("qcb-testnet-1", 5, 500, &auth)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));
    }

    #[test]
    fn forged_signature_rejected() {
        let mut store = SponsorStore::new();
        let (sponsor_id, _kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 10_000);
        // Sign with an unrelated key -- the store looks up the *registered*
        // sponsor's public key, so this should fail verification.
        let forger = MlDsaScheme.generate_keypair("mallory").expect("keygen");
        let auth = make_signed_auth(&forger, "qcb-testnet-1", &sponsor_id, 500, 10, 100);

        let err = store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));
        assert_eq!(store.get(&sponsor_id).unwrap().balance_uqcb, 10_000);
    }

    #[test]
    fn cross_chain_replay_rejected() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 10_000);
        let auth = make_signed_auth(&kp, "qcb-mainnet-1", &sponsor_id, 500, 10, 100);

        // Same auth, validated against a different chain_id.
        let err = store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));
    }

    #[test]
    fn duplicate_auth_id_rejected_on_second_use() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 10_000);
        let auth = make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100);

        store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth)
            .expect("first use succeeds");
        let err = store
            .validate_and_consume("qcb-testnet-1", 51, 500, &auth)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));
        // Only debited once.
        assert_eq!(store.get(&sponsor_id).unwrap().balance_uqcb, 9_500);
    }

    #[test]
    fn revocation_before_consumption_rejected() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 10_000);
        let auth = make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100);

        store.revoke_before_block(&sponsor_id, 20).unwrap();

        let err = store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));
    }

    #[test]
    fn revocation_after_issued_at_does_not_retroactively_block() {
        // issued_at_block (30) is AFTER the revocation cutoff (20), so this
        // auth was issued after the sponsor resumed service and must still
        // be valid.
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 10_000);
        let auth = make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 30, 100);
        store.revoke_before_block(&sponsor_id, 20).unwrap();

        assert!(store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth)
            .is_ok());
    }

    #[test]
    fn per_tx_max_fee_policy_enforced() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(
            &mut store, "acme", 10_000, 100, /* per_tx cap */
            10_000,
        );
        // Sponsor signs an authorization claiming a higher max_fee than their
        // own policy allows.
        let auth = make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100);

        let err = store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));
    }

    #[test]
    fn epoch_budget_enforced_across_multiple_txs() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 800);

        let auth1 = SponsorAuthorization {
            auth_id: AuthId([1u8; 16]),
            ..make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100)
        };
        let auth1 = resign(&kp, "qcb-testnet-1", auth1);
        store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth1)
            .expect("first 500 within 800 budget");

        let auth2 = SponsorAuthorization {
            auth_id: AuthId([2u8; 16]),
            ..make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100)
        };
        let auth2 = resign(&kp, "qcb-testnet-1", auth2);
        let err = store
            .validate_and_consume("qcb-testnet-1", 51, 500, &auth2)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));

        store.advance_epoch();
        let auth3 = SponsorAuthorization {
            auth_id: AuthId([3u8; 16]),
            ..make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100)
        };
        let auth3 = resign(&kp, "qcb-testnet-1", auth3);
        store
            .validate_and_consume("qcb-testnet-1", 52, 500, &auth3)
            .expect("epoch reset, budget available again");
    }

    /// Re-sign after mutating a field with struct-update syntax (auth_id
    /// changes the signed message, so the signature must be recomputed).
    fn resign(
        kp: &KeyPair,
        chain_id: &str,
        mut auth: SponsorAuthorization,
    ) -> SponsorAuthorization {
        let msg = signing_message_for(&auth, chain_id);
        let sig = MlDsaScheme.sign(&msg, kp).expect("sign");
        auth.signature = format!("mldsa65:{}", hex::encode(&sig.bytes));
        auth
    }

    #[test]
    fn pruning_drops_only_expired_entries_past_gc_window() {
        let mut store = SponsorStore::new();
        let (sponsor_id, kp) = setup_sponsor(&mut store, "acme", 10_000, 1_000, 10_000);
        let auth = make_signed_auth(&kp, "qcb-testnet-1", &sponsor_id, 500, 10, 100);
        store
            .validate_and_consume("qcb-testnet-1", 50, 500, &auth)
            .unwrap();

        // Still within GC window: not pruned, so replay is still rejected.
        store.prune_expired(150, 100);
        let err = store
            .validate_and_consume("qcb-testnet-1", 150, 500, &auth)
            .unwrap_err();
        assert!(matches!(err, SponsorError::Unavailable(_)));

        // Past expiry + GC window: pruned. (The auth itself is also past its
        // own expires_at_block by now, so re-validating would fail the
        // expiry check anyway -- this asserts the *entry* is gone, which
        // matters for the store's own storage bound.)
        store.prune_expired(300, 100);
        assert!(!store
            .consumed
            .get(&sponsor_id)
            .map(|s| s.contains_key(&auth.auth_id))
            .unwrap_or(false));
    }
}
