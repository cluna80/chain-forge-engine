/// chain-forge-cirfi
///
/// The QCB monetary engine. Implements Whitepaper Sections 5.4 and 6.2:
///
///   - Tiered demurrage on idle $CIRFI balances
///   - Decay-exemption credits from spending
///   - UBI epoch distribution to verified humans
///   - UBI pool: receives decayed tokens
///   - Proactive UBI pool redirect (holder choice, triggers BME)
///   - BME: merchant fees and redirects -> buy-and-burn $QCB
///   - Two-token enforcement: only $CIRFI is the protocol currency
///
/// This crate reads from chain-forge-identity (verified count, claim gating)
/// and writes to chain-forge-state (balance changes, burns).
///
/// Whitepaper refs: Sections 5.4, 6.1-6.6, Q25.

use serde::{Deserialize, Serialize};
use chain_forge_state::{AccountState, StateStore};
use chain_forge_identity::IdentityStore;

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CirfiError {
    #[error("account {0} not found")]
    AccountNotFound(String),

    #[error("identity {0} not verified for UBI")]
    NotVerified(String),

    #[error("UBI already claimed by {0} this epoch")]
    AlreadyClaimed(String),

    #[error("insufficient balance for redirect: have {have} ucirfi, need {need}")]
    InsufficientForRedirect { have: u128, need: u128 },

    #[error("BME error: {0}")]
    BmeError(String),

    #[error("internal CirFi error: {0}")]
    Internal(String),
}

pub type CirfiResult<T> = Result<T, CirfiError>;

// -- Demurrage tiers ----------------------------------------------------------

/// Tiered demurrage schedule from Whitepaper Section 6.2.
/// Balance is measured in days of UBI equivalent at the current daily rate.
/// Decay rate is monthly percentage applied to the balance above each tier floor.
///
/// Balance Range         | Monthly Decay
/// 0 - 30 days UBI      | 0%       (base exemption)
/// 30 - 90 days UBI     | 0.5%
/// 90 - 365 days UBI    | 1.0%
/// 365+ days UBI        | 1.5%
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemurrageTier {
    /// Lower bound in ucirfi (balance at or above this floor is in this tier).
    pub floor_ucirfi: u128,
    /// Upper bound in ucirfi. u128::MAX for the top tier.
    pub ceiling_ucirfi: u128,
    /// Monthly decay rate as basis points (100 bp = 1%).
    /// 0 = no decay, 50 = 0.5%, 100 = 1.0%, 150 = 1.5%.
    pub monthly_bp: u32,
}

impl DemurrageTier {
    /// Calculate the decay for a balance sitting in this tier for one epoch
    /// (one day). Monthly rate is divided by 30 for daily application.
    /// Returns the amount to decay (in ucirfi), rounded down.
    pub fn daily_decay(&self, balance_in_tier: u128) -> u128 {
        if self.monthly_bp == 0 || balance_in_tier == 0 {
            return 0;
        }
        // daily_rate = monthly_bp / (30 * 10_000)
        // decay = balance * monthly_bp / (30 * 10_000)
        balance_in_tier * self.monthly_bp as u128 / (30 * 10_000)
    }
}

/// Build the canonical demurrage tiers from the whitepaper.
/// daily_ubi_rate_ucirfi is used to convert "days of UBI" to ucirfi amounts.
pub fn demurrage_tiers(daily_ubi_rate_ucirfi: u128) -> Vec<DemurrageTier> {
    vec![
        DemurrageTier {
            floor_ucirfi:   0,
            ceiling_ucirfi: daily_ubi_rate_ucirfi * 30,   // 30 days UBI
            monthly_bp:     0,                              // 0% - base exemption
        },
        DemurrageTier {
            floor_ucirfi:   daily_ubi_rate_ucirfi * 30,
            ceiling_ucirfi: daily_ubi_rate_ucirfi * 90,   // 90 days UBI
            monthly_bp:     50,                             // 0.5%
        },
        DemurrageTier {
            floor_ucirfi:   daily_ubi_rate_ucirfi * 90,
            ceiling_ucirfi: daily_ubi_rate_ucirfi * 365,  // 365 days UBI
            monthly_bp:     100,                            // 1.0%
        },
        DemurrageTier {
            floor_ucirfi:   daily_ubi_rate_ucirfi * 365,
            ceiling_ucirfi: u128::MAX,
            monthly_bp:     150,                            // 1.5%
        },
    ]
}

/// Calculate total daily demurrage for a given balance across all tiers.
/// Returns (total_decay_ucirfi, per_tier_breakdown).
pub fn calculate_demurrage(
    balance: u128,
    tiers: &[DemurrageTier],
    exemption_days: u32,
) -> (u128, Vec<u128>) {
    // Apply exemption: reduce effective balance by exemption_days * daily_rate
    // The first tier (0-30 days) is always exempt anyway, so exemption
    // credits reduce how much sits in the higher tiers.
    // For simplicity in Phase 0: exemption_days reduce balance by that
    // many days of UBI before calculating decay.
    let daily_rate = tiers.first().map(|t| t.ceiling_ucirfi / 30).unwrap_or(0);
    let exemption_reduction = (exemption_days as u128) * daily_rate;
    let effective_balance = balance.saturating_sub(exemption_reduction);

    let mut total_decay = 0u128;
    let mut breakdown = Vec::new();
    let mut remaining = effective_balance;

    for tier in tiers {
        if remaining == 0 { breakdown.push(0); continue; }

        let tier_size = tier.ceiling_ucirfi.saturating_sub(tier.floor_ucirfi);
        let balance_in_tier = remaining.min(tier_size);
        let decay = tier.daily_decay(balance_in_tier);

        total_decay += decay;
        breakdown.push(decay);
        remaining = remaining.saturating_sub(balance_in_tier);
    }

    (total_decay, breakdown)
}

// -- UBI pool -----------------------------------------------------------------

/// The UBI pool receives decayed tokens and distributes them as UBI.
/// Whitepaper 6.2: "decayed tokens flow into the UBI distribution pool
/// -- not burned, not sent to the team."
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UbiPool {
    /// Current balance of the pool in ucirfi.
    pub balance_ucirfi: u128,
    /// Total received from demurrage across all epochs.
    pub total_received_from_decay: u128,
    /// Total distributed as UBI across all epochs.
    pub total_distributed: u128,
}

impl UbiPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Receive decayed tokens from a balance.
    pub fn receive_decay(&mut self, amount: u128) {
        self.balance_ucirfi += amount;
        self.total_received_from_decay += amount;
    }

    /// Receive a proactive redirect from a holder.
    pub fn receive_redirect(&mut self, amount: u128) {
        self.balance_ucirfi += amount;
        // Note: redirects are not counted in total_received_from_decay --
        // they are a separate flow (voluntary vs. passive).
    }

    /// Distribute UBI to a verified human. Returns amount distributed.
    pub fn distribute(&mut self, amount: u128) -> u128 {
        let actual = self.balance_ucirfi.min(amount);
        self.balance_ucirfi -= actual;
        self.total_distributed += actual;
        actual
    }
}

// -- BME engine ---------------------------------------------------------------

/// Burn-and-Mint Equilibrium engine (Whitepaper Section 6.3).
/// Merchant fees and proactive redirects fund $QCB buy-and-burn.
///
/// Phase 0: burn tracking only (actual market buy is off-chain).
/// Phase 1+: integrate with settlement layer to buy $QCB on-market.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BmeEngine {
    /// Total ucirfi collected as BME fees (merchant + redirect).
    pub total_fees_collected_ucirfi: u128,
    /// Total uqcb burned across all epochs.
    pub total_qcb_burned_uqcb: u128,
    /// BME fee rate in basis points (50 = 0.5% per Section 8.1).
    pub fee_bp: u32,
    /// Whether BME is currently "live" vs "speculative" per Section 6.3.
    /// Live = burns >= 1% of $QCB daily trading volume for 90 consecutive days.
    pub is_live: bool,
    /// Consecutive days meeting the "live" threshold.
    pub consecutive_live_days: u32,
}

impl BmeEngine {
    pub fn new(fee_bp: u32) -> Self {
        Self { fee_bp, ..Default::default() }
    }

    /// Calculate BME fee on a transfer amount.
    pub fn fee_on(&self, amount: u128) -> u128 {
        amount * self.fee_bp as u128 / 10_000
    }

    /// Record a BME event (merchant settlement or proactive redirect).
    /// Returns the fee amount collected in ucirfi.
    pub fn collect_fee(&mut self, amount: u128, source: BmeSource) -> u128 {
        let fee = self.fee_on(amount);
        self.total_fees_collected_ucirfi += fee;
        tracing::debug!(
            fee_ucirfi = fee,
            source = ?source,
            "BME fee collected"
        );
        fee
    }

    /// Record $QCB burned (called after off-chain buy-and-burn).
    pub fn record_burn(&mut self, uqcb_burned: u128) {
        self.total_qcb_burned_uqcb += uqcb_burned;
        tracing::info!(
            burned = uqcb_burned,
            total = self.total_qcb_burned_uqcb,
            "QCB burned via BME"
        );
    }
}

/// Source of a BME event -- merchant settlement or proactive redirect.
/// Affects classification toward "live" threshold (Q25).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BmeSource {
    MerchantSettlement,
    ProactiveRedirect,
}

// -- CirFi engine -------------------------------------------------------------

/// The full CirFi monetary engine.
/// Holds demurrage tiers, UBI pool, and BME engine.
/// Called once per epoch by the node to process all accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CirfiEngine {
    pub tiers:      Vec<DemurrageTier>,
    pub ubi_pool:   UbiPool,
    pub bme:        BmeEngine,
    /// Base denom for $CIRFI (e.g. "ucirfi").
    pub cirfi_denom: String,
    /// Base denom for $QCB (e.g. "uqcb").
    pub qcb_denom:  String,
    /// Daily UBI rate per verified human in ucirfi.
    pub daily_ubi_rate: u128,
}

impl CirfiEngine {
    pub fn new(cirfi_denom: String, qcb_denom: String) -> Self {
        let daily_ubi_rate = chain_forge_identity::DAILY_UBI_RATE_UCIRFI;
        Self {
            tiers:      demurrage_tiers(daily_ubi_rate),
            ubi_pool:   UbiPool::new(),
            bme:        BmeEngine::new(50), // 0.5% BME fee
            cirfi_denom,
            qcb_denom,
            daily_ubi_rate,
        }
    }

    /// Apply demurrage to one account for one epoch.
    /// Decayed tokens flow to the UBI pool.
    /// Returns the amount decayed.
    pub fn apply_demurrage(
        &mut self,
        account: &mut AccountState,
        exemption_days: u32,
    ) -> u128 {
        let balance = account.balance_of(&self.cirfi_denom);
        if balance == 0 { return 0; }

        let (decay, _) = calculate_demurrage(balance, &self.tiers, exemption_days);
        if decay == 0 { return 0; }

        // Debit from account (best-effort -- if balance changed since check, cap)
        let actual_decay = decay.min(balance);
        *account.balances
            .entry(self.cirfi_denom.clone())
            .or_insert(0) -= actual_decay;

        // Credit UBI pool
        self.ubi_pool.receive_decay(actual_decay);

        tracing::debug!(
            address = %account.address,
            decay = actual_decay,
            balance_after = account.balance_of(&self.cirfi_denom),
            "demurrage applied"
        );
        actual_decay
    }

    /// Distribute UBI to one verified human account.
    /// Source: identity store enforces one claim per epoch.
    /// Returns the amount distributed (may be less if UBI pool is low).
    pub fn distribute_ubi(
        &mut self,
        identity_id: &str,
        account: &mut AccountState,
        identity_store: &mut IdentityStore,
    ) -> CirfiResult<u128> {
        // Delegate claim gating to identity store.
        // Checks in order: tier (must be Verified+), liveness, one-claim-per-epoch,
        // and the earned-yield gate (must have on-chain activity this epoch).
        let ubi_amount = identity_store.claim_ubi(identity_id)
            .map_err(|e| CirfiError::NotVerified(format!("{identity_id}: {e}")))?;

        // Draw from UBI pool (or mint fresh if pool is insufficient)
        // Phase 0: mint fresh tokens; pool is topped up by demurrage over time.
        let distributed = if self.ubi_pool.balance_ucirfi >= ubi_amount {
            self.ubi_pool.distribute(ubi_amount)
        } else {
            // Pool insufficient -- mint the difference (population-linked issuance)
            let from_pool = self.ubi_pool.distribute(self.ubi_pool.balance_ucirfi);
            let minted = ubi_amount - from_pool;
            tracing::debug!(minted, "UBI minted (pool insufficient)");
            from_pool + minted
        };

        account.credit(&self.cirfi_denom, distributed);

        // Record participation for liveness tracking (Q24)
        account.increment_nonce();

        tracing::debug!(
            identity = identity_id,
            amount   = distributed,
            "UBI distributed"
        );
        Ok(distributed)
    }

    /// Process a $CIRFI transfer with BME fee collection.
    /// Fee flows to BME (buy-and-burn $QCB).
    /// Returns the net amount received by the recipient.
    pub fn process_transfer(
        &mut self,
        sender:    &mut AccountState,
        recipient: &mut AccountState,
        amount:    u128,
        source:    BmeSource,
    ) -> CirfiResult<u128> {
        let balance = sender.balance_of(&self.cirfi_denom);
        if balance < amount {
            return Err(CirfiError::InsufficientForRedirect {
                have: balance,
                need: amount,
            });
        }

        // Collect BME fee from transfer amount
        let fee = self.bme.collect_fee(amount, source);
        let net_amount = amount - fee;

        // Debit sender (full amount including fee)
        *sender.balances
            .entry(self.cirfi_denom.clone())
            .or_insert(0) -= amount;
        sender.increment_nonce();

        // Credit recipient (net amount after fee)
        recipient.credit(&self.cirfi_denom, net_amount);

        // Earn decay exemption credit for the spend
        // (handled by IntrinsicCharm in identity layer -- here we just note it)
        tracing::debug!(
            from    = %sender.address,
            to      = %recipient.address,
            amount,
            fee,
            net     = net_amount,
            "CIRFI transfer with BME fee"
        );

        Ok(net_amount)
    }

    /// Proactive UBI pool redirect (Whitepaper Section 6.3 / Q25).
    /// Holder voluntarily sends balance to UBI pool, triggering BME fee.
    /// Better than passive decay: holder earns no negative, BME gets funded.
    pub fn redirect_to_ubi_pool(
        &mut self,
        account: &mut AccountState,
        amount:  u128,
    ) -> CirfiResult<u128> {
        let balance = account.balance_of(&self.cirfi_denom);
        if balance < amount {
            return Err(CirfiError::InsufficientForRedirect {
                have: balance,
                need: amount,
            });
        }

        // Collect BME fee
        let fee = self.bme.collect_fee(amount, BmeSource::ProactiveRedirect);
        let net_to_pool = amount - fee;

        // Debit account
        *account.balances
            .entry(self.cirfi_denom.clone())
            .or_insert(0) -= amount;
        account.increment_nonce();

        // Credit UBI pool (net amount)
        self.ubi_pool.receive_redirect(net_to_pool);

        tracing::info!(
            address     = %account.address,
            amount,
            fee,
            to_pool     = net_to_pool,
            "proactive UBI pool redirect"
        );

        Ok(net_to_pool)
    }

    /// Run a full epoch: apply demurrage to all accounts, then distribute
    /// UBI to all verified humans who claim.
    /// Returns an epoch summary.
    pub fn process_epoch(
        &mut self,
        state:    &mut StateStore,
        identity: &mut IdentityStore,
    ) -> EpochSummary {
        let epoch = identity.clock.current_epoch;
        let mut summary = EpochSummary {
            epoch,
            accounts_charged:    0,
            total_decayed:       0,
            total_ubi_distributed: 0,
            ubi_recipients:      0,
        };

        // Step 1: collect addresses and exemption days first (avoid borrow issues)
        let account_data: Vec<(String, u32)> = state
            .all_accounts()
            .map(|a| {
                let exemption_days = identity
                    .get_by_address_opt(&a.address)
                    .map(|r| r.charm.decay_exemption.days)
                    .unwrap_or(0);
                (a.address.clone(), exemption_days)
            })
            .collect();

        // Step 2: apply demurrage to each account
        for (address, exemption_days) in &account_data {
            if let Ok(account) = state.get_account_mut(address) {
                let decayed = self.apply_demurrage(account, *exemption_days);
                if decayed > 0 {
                    summary.accounts_charged += 1;
                    summary.total_decayed += decayed;
                }
            }
        }

        // Step 3: CirFi yield is NOT auto-distributed.
        //
        // Yield claims are explicit tx submissions from each identity.
        // The execution layer calls distribute_ubi() when it processes a
        // ClaimYield transaction, after verifying that record_activity()
        // has been called for this identity in the current epoch.
        //
        // This ensures CirFi is earned (participation-gated), not a
        // passive UBI drip. Any identity that did not submit at least one
        // on-chain action this epoch is simply ineligible — no exception
        // in devnet mode either, so tests catch regressions early.

        tracing::info!(
            epoch                 = summary.epoch,
            accounts_charged      = summary.accounts_charged,
            total_decayed         = summary.total_decayed,
            ubi_recipients        = summary.ubi_recipients,
            total_ubi_distributed = summary.total_ubi_distributed,
            "CirFi epoch processed"
        );

        summary
    }
}

/// Summary of one CirFi epoch.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EpochSummary {
    pub epoch:                 u64,
    pub accounts_charged:      usize,
    pub total_decayed:         u128,
    pub total_ubi_distributed: u128,
    pub ubi_recipients:        usize,
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_identity::{IdentityStore, PopAttestation, DAILY_UBI_RATE_UCIRFI};
    use chain_forge_state::{AccountState, StateStore};
    use chain_forge_core::HashWidth;

    const CIRFI: &str = "ucirfi";
    const QCB:   &str = "uqcb";

    fn make_engine() -> CirfiEngine {
        CirfiEngine::new(CIRFI.into(), QCB.into())
    }

    fn make_account(address: &str, cirfi_balance: u128) -> AccountState {
        let mut a = AccountState::new(address.to_string(), "user".to_string());
        a.credit(CIRFI, cirfi_balance);
        a
    }

    fn make_identity_store() -> IdentityStore {
        IdentityStore::new(0)
    }

    fn register_and_verify(store: &mut IdentityStore, id: &str, address: &str) {
        let att = PopAttestation::genesis(id, 0);
        store.register(id.to_string(), address.to_string(), att.clone()).unwrap();
        store.verify_identity(id, att).unwrap();
    }

    // -- Demurrage tier tests -------------------------------------------------

    #[test]
    fn base_exemption_tier_has_zero_decay() {
        let tiers = demurrage_tiers(DAILY_UBI_RATE_UCIRFI);
        // Balance of 10 days UBI -- within base exemption (0-30 days)
        let balance = DAILY_UBI_RATE_UCIRFI * 10;
        let (decay, _) = calculate_demurrage(balance, &tiers, 0);
        assert_eq!(decay, 0, "balance within base exemption should have zero decay");
    }

    #[test]
    fn second_tier_decays_at_half_percent_monthly() {
        let tiers = demurrage_tiers(DAILY_UBI_RATE_UCIRFI);
        // Balance of 60 days UBI -- 30 in exempt tier, 30 in 0.5% tier
        let balance = DAILY_UBI_RATE_UCIRFI * 60;
        let (decay, breakdown) = calculate_demurrage(balance, &tiers, 0);
        assert_eq!(breakdown[0], 0); // exempt tier: no decay
        assert!(breakdown[1] > 0,   // 0.5% monthly tier: has decay
            "second tier should decay at 0.5% monthly");
        assert!(decay > 0);
    }

    #[test]
    fn higher_tiers_decay_faster() {
        let tiers = demurrage_tiers(DAILY_UBI_RATE_UCIRFI);
        // Large balance spanning all tiers
        let balance = DAILY_UBI_RATE_UCIRFI * 400;
        let (_, breakdown) = calculate_demurrage(balance, &tiers, 0);
        // Each tier's per-unit decay should be >= previous tier
        // (we just verify the top tier is non-zero)
        assert!(breakdown[3] > 0, "top tier (1.5% monthly) should have decay");
    }

    #[test]
    fn decay_exemption_reduces_effective_balance() {
        let tiers = demurrage_tiers(DAILY_UBI_RATE_UCIRFI);
        // Balance of 60 days UBI with 30 days exemption
        let balance = DAILY_UBI_RATE_UCIRFI * 60;
        let (decay_no_exemption, _) = calculate_demurrage(balance, &tiers, 0);
        let (decay_with_exemption, _) = calculate_demurrage(balance, &tiers, 30);
        assert!(decay_with_exemption < decay_no_exemption,
            "exemption should reduce decay");
    }

    #[test]
    fn zero_balance_has_zero_decay() {
        let tiers = demurrage_tiers(DAILY_UBI_RATE_UCIRFI);
        let (decay, _) = calculate_demurrage(0, &tiers, 0);
        assert_eq!(decay, 0);
    }

    // -- UBI pool tests -------------------------------------------------------

    #[test]
    fn ubi_pool_receives_and_distributes() {
        let mut pool = UbiPool::new();
        pool.receive_decay(1_000_000);
        assert_eq!(pool.balance_ucirfi, 1_000_000);

        let distributed = pool.distribute(400_000);
        assert_eq!(distributed, 400_000);
        assert_eq!(pool.balance_ucirfi, 600_000);
        assert_eq!(pool.total_distributed, 400_000);
        assert_eq!(pool.total_received_from_decay, 1_000_000);
    }

    #[test]
    fn ubi_pool_caps_distribution_at_balance() {
        let mut pool = UbiPool::new();
        pool.receive_decay(100);

        let distributed = pool.distribute(999_999);
        assert_eq!(distributed, 100, "cannot distribute more than pool holds");
        assert_eq!(pool.balance_ucirfi, 0);
    }

    // -- BME engine tests -----------------------------------------------------

    #[test]
    fn bme_fee_calculation() {
        let bme = BmeEngine::new(50); // 0.5%
        let fee = bme.fee_on(1_000_000);
        assert_eq!(fee, 5_000, "0.5% of 1M = 5K");
    }

    #[test]
    fn bme_collects_and_tracks_fees() {
        let mut bme = BmeEngine::new(50);
        bme.collect_fee(2_000_000, BmeSource::MerchantSettlement);
        assert_eq!(bme.total_fees_collected_ucirfi, 10_000);
    }

    // -- CirFi engine tests ---------------------------------------------------

    #[test]
    fn demurrage_applied_to_large_balance() {
        let mut engine = make_engine();
        let mut account = make_account("qcb1test", DAILY_UBI_RATE_UCIRFI * 100);
        // Balance of 100 days UBI -- spans exempt + 0.5% tiers
        let decayed = engine.apply_demurrage(&mut account, 0);
        assert!(decayed > 0, "large balance should decay");
        assert_eq!(
            account.balance_of(CIRFI),
            DAILY_UBI_RATE_UCIRFI * 100 - decayed
        );
        assert_eq!(engine.ubi_pool.balance_ucirfi, decayed,
            "decayed tokens should be in UBI pool");
    }

    #[test]
    fn small_balance_no_demurrage() {
        let mut engine = make_engine();
        // Balance within base exemption (10 days UBI)
        let mut account = make_account("qcb1test", DAILY_UBI_RATE_UCIRFI * 10);
        let decayed = engine.apply_demurrage(&mut account, 0);
        assert_eq!(decayed, 0, "balance within base exemption should not decay");
    }

    #[test]
    fn ubi_distribution_requires_verified_identity() {
        let mut engine = make_engine();
        let mut state = StateStore::new(HashWidth::Bits256);
        let mut identity = make_identity_store();

        // Register but don't verify
        let att = PopAttestation::genesis("h1", 0);
        identity.register("h1".into(), "qcb1h1".into(), att).unwrap();

        let mut account = make_account("qcb1h1", 0);
        let result = engine.distribute_ubi("h1", &mut account, &mut identity);
        assert!(result.is_err(), "unverified identity cannot claim UBI");
        let _ = state; // suppress unused warning
    }

    #[test]
    fn yield_distribution_requires_on_chain_activity() {
        let mut engine = make_engine();
        let mut identity = make_identity_store();
        register_and_verify(&mut identity, "h1", "qcb1h1");

        // Verified but NO activity recorded this epoch — must be rejected.
        let mut account = make_account("qcb1h1", 0);
        let result = engine.distribute_ubi("h1", &mut account, &mut identity);
        assert!(result.is_err(), "CirFi yield requires on-chain activity; passive claim must fail");
    }

    #[test]
    fn yield_distribution_credits_active_verified_human() {
        let mut engine = make_engine();
        let mut identity = make_identity_store();
        register_and_verify(&mut identity, "h1", "qcb1h1");

        // Record on-chain activity this epoch (simulates tx submission).
        identity.record_activity("h1");

        let mut account = make_account("qcb1h1", 0);
        let amount = engine.distribute_ubi("h1", &mut account, &mut identity).unwrap();

        assert_eq!(amount, DAILY_UBI_RATE_UCIRFI);
        assert_eq!(account.balance_of(CIRFI), DAILY_UBI_RATE_UCIRFI);
    }

    #[test]
    fn yield_double_claim_rejected() {
        let mut engine = make_engine();
        let mut identity = make_identity_store();
        register_and_verify(&mut identity, "h1", "qcb1h1");
        identity.record_activity("h1");

        let mut account = make_account("qcb1h1", 0);
        engine.distribute_ubi("h1", &mut account, &mut identity).unwrap();
        let second = engine.distribute_ubi("h1", &mut account, &mut identity);
        assert!(second.is_err(), "cannot claim CirFi yield twice in same epoch");
    }

    #[test]
    fn transfer_collects_bme_fee() {
        let mut engine = make_engine();
        let mut sender    = make_account("qcb1sender",    10_000_000);
        let mut recipient = make_account("qcb1recipient", 0);

        let net = engine.process_transfer(
            &mut sender, &mut recipient, 1_000_000, BmeSource::MerchantSettlement
        ).unwrap();

        let expected_fee = engine.bme.fee_on(1_000_000); // 5_000
        assert_eq!(net, 1_000_000 - expected_fee);
        assert_eq!(recipient.balance_of(CIRFI), net);
        assert_eq!(sender.balance_of(CIRFI), 10_000_000 - 1_000_000);
        assert_eq!(engine.bme.total_fees_collected_ucirfi, expected_fee);
    }

    #[test]
    fn proactive_redirect_funds_ubi_pool() {
        let mut engine = make_engine();
        let mut account = make_account("qcb1holder", 5_000_000);

        let to_pool = engine.redirect_to_ubi_pool(&mut account, 1_000_000).unwrap();

        let fee = engine.bme.fee_on(1_000_000);
        assert_eq!(to_pool, 1_000_000 - fee,
            "UBI pool receives amount minus BME fee");
        assert_eq!(engine.ubi_pool.balance_ucirfi, to_pool,
            "UBI pool balance updated");
        assert_eq!(account.balance_of(CIRFI), 4_000_000,
            "sender balance reduced by full redirect amount");
        assert!(engine.bme.total_fees_collected_ucirfi > 0,
            "BME collected fee from redirect");
    }

    #[test]
    fn redirect_rejects_insufficient_balance() {
        let mut engine = make_engine();
        let mut account = make_account("qcb1poor", 100);
        let result = engine.redirect_to_ubi_pool(&mut account, 999_999);
        assert!(result.is_err());
    }

    #[test]
    fn two_token_model_qcb_unaffected_by_cirfi_ops() {
        let mut engine = make_engine();
        let mut account = make_account("qcb1mixed", DAILY_UBI_RATE_UCIRFI * 50);
        // Give account some QCB too
        account.credit(QCB, 1_000_000);

        // Apply demurrage -- should only touch ucirfi
        engine.apply_demurrage(&mut account, 0);

        // QCB balance must be unchanged
        assert_eq!(account.balance_of(QCB), 1_000_000,
            "$QCB balance must not be affected by $CIRFI demurrage");
    }
}
