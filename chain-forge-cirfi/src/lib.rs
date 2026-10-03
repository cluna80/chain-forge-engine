//! # chain-forge-cirfi
//!
//! The QCB resource economy. Implements the CIRFI Economic Model v0.1.
//!
//! ## What $CIRFI is
//!
//! $CIRFI is a **resource consumption token**, not a UBI token.
//! It is the unit of account for all network resource usage:
//! compute, storage, ZK proving, bandwidth, oracle data, AI inference,
//! and external verification.
//!
//! ## Two minting paths (fully independent)
//!
//! 1. **Purchase path**: QCB is permanently burned → CIRFI resource credits
//!    are created at the algorithmic rate `Rt`. Rate adjusts with network load.
//! 2. **Contribution path**: Verified resource providers earn CIRFI minted
//!    directly when the VCA system confirms delivery. No QCB is involved.
//!
//! There is **no CIRFI → QCB conversion**. This is a constitutional constraint.
//!
//! ## Consumption split
//!
//! When CIRFI is consumed by an operation it splits:
//!   ~60% → provider compensation
//!   ~25% → permanent CIRFI burn (deflationary pressure)
//!   ~15% → protocol reserve
//!
//! ## Demand loop
//!
//! Network usage grows → CIRFI demand rises → more QCB burned to obtain CIRFI
//! → QCB supply contracts → QCB scarcity increases.
//!
//! ## Core supply equation
//!
//! M(t+1) = Mt + [Qt * Rt] + [sum Ei,t] - Bt - Pt
//!
//! Where Qt*Rt is the purchase-path mint, sum Ei,t is the contribution-path
//! mint, Bt is the burn from consumption, and Pt is the protocol reserve take.
//!
//! ## What this module does NOT include
//!
//! - The old UBI/demurrage model (superseded by CIRFI Economic Model v0.1)
//! - ZK proof of contribution verification (VCA layer, see chain-forge-personhood)
//! - Cross-resource arbitrage constraints (deferred, Section 11)
//! - Delegated budget mechanics (deferred, Section 11)
//! - Bootstrap sequence (deferred, Section 11)

pub mod capacity_report;
pub use capacity_report::{
    AggregationMethod, CapacityEvidence, CapacityPhase, CapacityReport,
    CapacityReportState, ResourceCapacityRecord, ResourceType,
};

pub mod contribution_settlement;
pub use contribution_settlement::{
    kind_to_resource_type, resource_type_to_kind, settle, EpochSettlement,
    SettlementError, SettlementMode, SettlementRecord,
};

use std::collections::BTreeMap;
use thiserror::Error;

// ── Fixed-point denominator ───────────────────────────────────────────────────

/// Fixed-point denominator. All rates, fractions and weights are expressed
/// as integers where the real value = integer / D.
/// E.g. a 70% target is stored as 700_000.
pub const D: u128 = 1_000_000;

// ── Protocol constants ────────────────────────────────────────────────────────

/// Target utilization per resource type (70%). When U-bar == U*, Rt == R0.
pub const U_STAR: u128 = 700_000; // 0.70 × D

/// EMA smoothing coefficient (10%). One block's spike decays over ~10 windows.
pub const ALPHA: u128 = 100_000; // 0.10 × D

/// Consumption split: provider share (60%).
pub const PROVIDER_SHARE: u128 = 600_000;

/// Consumption split: permanent burn share (25%).
pub const BURN_SHARE: u128 = 250_000;

/// Consumption split: protocol reserve share (15%).
pub const RESERVE_SHARE: u128 = 150_000;

// PROVIDER_SHARE + BURN_SHARE + RESERVE_SHARE must equal D. Verified by test.

/// Hard floor on Rt: prevents CIRFI from becoming free during low demand.
/// TBD via economic simulation; placeholder = 0.1 × R0.
pub const R_MIN_FRACTION: u128 = 100_000; // 0.10 × D (10% of R0)

/// Hard ceiling on Rt: prevents CIRFI from becoming unaffordable.
/// TBD via economic simulation; placeholder = 10 × R0.
pub const R_MAX_FRACTION: u128 = 10_000_000; // 10.0 × D (1000% of R0)

/// Congestion sensitivity exponent γ (gamma). Higher = faster price response.
/// TBD via simulation. Placeholder = 2.0 (quadratic response).
pub const GAMMA_NUM: u128 = 2; // integer — used in integer exponentiation

// ── ResourceKind ─────────────────────────────────────────────────────────────

/// All network resource types that CIRFI prices.
/// Extended resource types (oracle data, AI inference, external verification)
/// are listed here for completeness but share the `Compute` billing tier
/// until per-type weights are calibrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceKind {
    Compute,
    Storage,
    ZkProving,
    Bandwidth,
    OracleData,
    AiInference,
    ExternalVerification,
}

impl ResourceKind {
    pub fn all() -> &'static [ResourceKind] {
        &[
            ResourceKind::Compute,
            ResourceKind::Storage,
            ResourceKind::ZkProving,
            ResourceKind::Bandwidth,
            ResourceKind::OracleData,
            ResourceKind::AiInference,
            ResourceKind::ExternalVerification,
        ]
    }

    /// Base CIRFI cost for one normalized unit of this resource (× D).
    /// These are illustrative placeholders — must be calibrated by simulation.
    pub fn base_cost_per_unit(self) -> u128 {
        match self {
            ResourceKind::Compute              =>   1_000, // 0.001 CIRFI/CU
            ResourceKind::Storage              =>     100, // 0.0001 CIRFI/byte·epoch
            ResourceKind::ZkProving            =>  10_000, // 0.01 CIRFI/proof-second
            ResourceKind::Bandwidth            =>     500, // 0.0005 CIRFI/kB
            ResourceKind::OracleData           =>   5_000, // 0.005 CIRFI/query
            ResourceKind::AiInference          =>  50_000, // 0.05 CIRFI/inference
            ResourceKind::ExternalVerification => 100_000, // 0.1 CIRFI/verification
        }
    }
}

// ── ResourceUtilization ───────────────────────────────────────────────────────

/// Tracks demand and capacity for one resource type in one window,
/// and carries the EMA-smoothed utilization across windows.
#[derive(Debug, Clone)]
pub struct ResourceUtilization {
    /// Resource type.
    pub kind: ResourceKind,
    /// Raw utilization in this window: demand / capacity (fixed-point × D).
    /// 0 if no capacity was reported.
    pub u_raw: u128,
    /// EMA-smoothed utilization (U-bar). Updated each window via ALPHA.
    pub u_bar: u128,
    /// Congestion ratio: U-bar / U* (fixed-point × D).
    pub congestion: u128,
    /// Demand units consumed this window.
    pub demand_units: u128,
    /// Capacity units available this window (from CapacityReport).
    pub capacity_units: u128,
}

impl ResourceUtilization {
    /// Create a new tracker seeded at the target utilization (no congestion).
    pub fn new(kind: ResourceKind) -> Self {
        Self {
            kind,
            u_raw:          U_STAR,
            u_bar:          U_STAR,
            congestion:     D,      // U* / U* = 1.0 × D
            demand_units:   0,
            capacity_units: 0,
        }
    }

    /// Record demand and capacity for this window, then update the EMA.
    pub fn record_window(&mut self, demand_units: u128, capacity_units: u128) {
        self.demand_units   = demand_units;
        self.capacity_units = capacity_units;

        // U(r,t) = demand / capacity. Cap at 1.0 to avoid over-100% congestion
        // signals gaming the formula. If no capacity, treat as 100% utilization.
        self.u_raw = if capacity_units == 0 {
            D // 100% — treat as fully congested
        } else {
            (demand_units.saturating_mul(D) / capacity_units).min(D)
        };

        // U-bar(r,t) = alpha * U(r,t) + (1 - alpha) * U-bar(r,t-1)
        // All in fixed-point: multiply before dividing.
        let alpha_contrib     = ALPHA.saturating_mul(self.u_raw) / D;
        let prev_contrib      = (D - ALPHA).saturating_mul(self.u_bar) / D;
        self.u_bar            = alpha_contrib + prev_contrib;

        // C(r,t) = U-bar / U*
        self.congestion = self.u_bar.saturating_mul(D) / U_STAR;
    }

    /// The congestion multiplier for CIRFI pricing.
    /// congestion > 1.0 × D means above-target → operations cost more.
    pub fn congestion_multiplier(&self) -> u128 {
        self.congestion
    }

    /// CIRFI cost for `units` of this resource in the current window.
    /// cost = base_cost_per_unit * congestion_multiplier * units / D
    pub fn cost_for(&self, units: u128) -> u128 {
        let base  = self.kind.base_cost_per_unit();
        let adj   = base.saturating_mul(self.congestion_multiplier()) / D;
        adj.saturating_mul(units)
    }
}

// ── ConversionRate ────────────────────────────────────────────────────────────

/// Algorithmic QCB → CIRFI conversion rate state.
///
/// Rt = R0 * (U* / U-bar_aggregate)^gamma
/// Clamped to [Rmin, Rmax].
///
/// When utilization is below target, Rt > R0 (more CIRFI per QCB burned —
/// cheaper to acquire capacity). When above target, Rt < R0 (CIRFI is scarce).
#[derive(Debug, Clone)]
pub struct ConversionRate {
    /// Base rate R0: CIRFI units minted per QCB burned at target utilization.
    /// Fixed-point × D. E.g. 1_000_000 = 1.0 CIRFI per QCB.
    pub r0: u128,
    /// Current rate Rt (fixed-point × D).
    pub rt: u128,
    /// Hard floor Rmin (fixed-point × D).
    pub r_min: u128,
    /// Hard ceiling Rmax (fixed-point × D).
    pub r_max: u128,
}

impl ConversionRate {
    pub fn new(r0: u128) -> Self {
        let r_min = r0.saturating_mul(R_MIN_FRACTION) / D;
        let r_max = r0.saturating_mul(R_MAX_FRACTION) / D;
        Self { r0, rt: r0, r_min, r_max }
    }

    /// Recompute Rt from aggregate smoothed utilization.
    ///
    /// Formula: Rt = R0 * (U* / U-bar)^gamma, clamped to [Rmin, Rmax].
    ///
    /// `u_bar_aggregate` is the demand-weighted average U-bar across all
    /// resource types (or a simple average for v0).
    pub fn update(&mut self, u_bar_aggregate: u128) {
        if u_bar_aggregate == 0 {
            // No utilization data → use Rmax (generous, network is empty).
            self.rt = self.r_max;
            return;
        }

        // ratio = U* / U-bar (fixed-point).
        // If U-bar < U* → ratio > 1 → Rt > R0 (more CIRFI per QCB).
        // If U-bar > U* → ratio < 1 → Rt < R0 (less CIRFI per QCB).
        let ratio = U_STAR.saturating_mul(D) / u_bar_aggregate;

        // Rt = R0 * ratio^gamma.
        // Integer exponentiation: ratio is fixed-point × D.
        // ratio^2 = ratio * ratio / D (keeping fixed-point).
        let ratio_pow = integer_pow_fp(ratio, GAMMA_NUM);
        let rt_raw    = self.r0.saturating_mul(ratio_pow) / D;

        self.rt = rt_raw.clamp(self.r_min, self.r_max);
    }

    /// CIRFI minted for `qcb_burned` QCB at the current rate.
    /// cirfi_minted = qcb_burned * Rt / D
    pub fn cirfi_for_qcb(&self, qcb_burned: u128) -> u128 {
        qcb_burned.saturating_mul(self.rt) / D
    }
}

/// Fixed-point integer exponentiation: base^exp where base is fixed-point (× D).
/// Returns base^exp as fixed-point (× D).
/// Uses repeated multiplication, keeping fixed-point scale.
fn integer_pow_fp(base: u128, exp: u128) -> u128 {
    if exp == 0 { return D; }
    let mut result = D; // 1.0 in fixed-point
    let mut b = base;
    let mut e = exp;
    // Binary exponentiation
    while e > 0 {
        if e & 1 == 1 {
            result = result.saturating_mul(b) / D;
        }
        b = b.saturating_mul(b) / D;
        e >>= 1;
    }
    result
}

// ── ConsumptionSplit ──────────────────────────────────────────────────────────

/// Result of splitting a CIRFI consumption event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumptionSplit {
    /// CIRFI routed to providers who served this operation.
    pub to_providers: u128,
    /// CIRFI permanently burned.
    pub burned: u128,
    /// CIRFI added to protocol reserve.
    pub to_reserve: u128,
}

impl ConsumptionSplit {
    /// Total consumed (sum of all three destinations).
    pub fn total(&self) -> u128 {
        self.to_providers + self.burned + self.to_reserve
    }
}

/// Split `amount` of CIRFI according to the 60/25/15 consumption split.
/// Rounding remainder goes to providers (minimizes burn/reserve drift).
pub fn split_consumption(amount: u128) -> ConsumptionSplit {
    let to_providers = amount.saturating_mul(PROVIDER_SHARE) / D;
    let burned       = amount.saturating_mul(BURN_SHARE) / D;
    let to_reserve   = amount.saturating_mul(RESERVE_SHARE) / D;
    // Remainder (from rounding) goes to providers
    let assigned     = to_providers + burned + to_reserve;
    let remainder    = amount.saturating_sub(assigned);
    ConsumptionSplit {
        to_providers: to_providers + remainder,
        burned,
        to_reserve,
    }
}

// ── ProviderEarning ───────────────────────────────────────────────────────────

/// Contribution-path earning formula for one provider in one window.
///
/// E(i,t) = sum_r [ w(r) * C(i,r,t) * BaseCost(r) * CongestionMultiplier(r,t) ]
///
/// `contributions` maps resource kind → verified contribution units (from VCA).
/// `utilization` carries the current congestion state per resource.
///
/// Returns CIRFI minted for this provider (fixed-point units).
pub fn provider_earning(
    contributions: &BTreeMap<ResourceKind, u128>,
    utilization:   &BTreeMap<ResourceKind, ResourceUtilization>,
    resource_weight: &BTreeMap<ResourceKind, u128>,
) -> u128 {
    contributions.iter().map(|(kind, &units)| {
        if units == 0 { return 0u128; }

        let base_cost = kind.base_cost_per_unit();

        // CongestionMultiplier from current utilization state.
        let congestion = utilization
            .get(kind)
            .map(|u| u.congestion_multiplier())
            .unwrap_or(D); // 1.0 if no state tracked yet

        // Resource weight (protocol-set, defaults to D if unset).
        let weight = resource_weight
            .get(kind)
            .copied()
            .unwrap_or(D);

        // E(i,r,t) = weight * contribution * base_cost * congestion / D^2
        // (two D divisions: weight/D and congestion/D)
        let per_unit = base_cost.saturating_mul(congestion) / D;
        let weighted  = weight.saturating_mul(per_unit) / D;
        weighted.saturating_mul(units)
    }).sum()
}

// ── OperationCost ─────────────────────────────────────────────────────────────

/// A single operation's resource breakdown.
#[derive(Debug, Clone)]
pub struct OperationCost {
    /// Resource requirements: kind → units consumed.
    pub resources: BTreeMap<ResourceKind, u128>,
}

impl OperationCost {
    pub fn new() -> Self {
        Self { resources: BTreeMap::new() }
    }

    pub fn add(mut self, kind: ResourceKind, units: u128) -> Self {
        *self.resources.entry(kind).or_insert(0) += units;
        self
    }
}

impl Default for OperationCost {
    fn default() -> Self { Self::new() }
}

// ── CirfiEngine ───────────────────────────────────────────────────────────────

/// The full CIRFI resource economy engine.
///
/// Tracks per-resource utilization, the conversion rate, cumulative supply
/// metrics, and applies the economic formulas from CIRFI Economic Model v0.1.
#[derive(Debug, Clone)]
pub struct CirfiEngine {
    // -- Per-resource utilization state --
    pub utilization: BTreeMap<ResourceKind, ResourceUtilization>,

    // -- Resource weights (per-resource earning weights w(r), fixed-point × D) --
    pub resource_weights: BTreeMap<ResourceKind, u128>,

    // -- Conversion rate state --
    pub conversion_rate: ConversionRate,

    // -- Supply metrics --
    /// Total CIRFI in circulation (Mt).
    pub total_supply: u128,
    /// CIRFI minted via purchase path (sum of Qt*Rt over all windows).
    pub total_purchase_minted: u128,
    /// CIRFI minted via contribution path (sum of Ei,t over all windows).
    pub total_contribution_minted: u128,
    /// CIRFI permanently burned from consumption splits.
    pub total_burned: u128,
    /// CIRFI in protocol reserve.
    pub protocol_reserve: u128,
    /// QCB burned across all purchase conversions.
    pub total_qcb_burned: u128,

    // -- Window tracking --
    pub current_window: u64,
}

impl CirfiEngine {
    /// Create a new engine with the given base conversion rate R0.
    /// `r0` is fixed-point × D: how many CIRFI units are minted per QCB
    /// burned at target utilization.
    pub fn new(r0: u128) -> Self {
        let mut utilization = BTreeMap::new();
        let mut resource_weights = BTreeMap::new();

        for &kind in ResourceKind::all() {
            utilization.insert(kind, ResourceUtilization::new(kind));
            // Default weight = 1.0 (D) for all resources until calibrated.
            resource_weights.insert(kind, D);
        }

        Self {
            utilization,
            resource_weights,
            conversion_rate: ConversionRate::new(r0),
            total_supply:               0,
            total_purchase_minted:      0,
            total_contribution_minted:  0,
            total_burned:               0,
            protocol_reserve:           0,
            total_qcb_burned:           0,
            current_window:             0,
        }
    }

    // ── Purchase path ─────────────────────────────────────────────────────────

    /// Burn `qcb_amount` QCB and mint CIRFI at the current rate Rt.
    ///
    /// Returns `(cirfi_minted, rt_used)`.
    ///
    /// Security: the no-CIRFI-to-QCB constraint is enforced at the protocol
    /// level; this function only handles the QCB → CIRFI direction.
    pub fn purchase_cirfi(&mut self, qcb_amount: u128) -> (u128, u128) {
        let cirfi_minted = self.conversion_rate.cirfi_for_qcb(qcb_amount);
        let rt_used      = self.conversion_rate.rt;

        self.total_qcb_burned          += qcb_amount;
        self.total_supply              += cirfi_minted;
        self.total_purchase_minted     += cirfi_minted;

        tracing::info!(
            qcb_burned   = qcb_amount,
            cirfi_minted,
            rt           = rt_used,
            window       = self.current_window,
            "CIRFI purchase: QCB burned → CIRFI minted"
        );

        (cirfi_minted, rt_used)
    }

    // ── Contribution path ─────────────────────────────────────────────────────

    /// Credit contribution-earned CIRFI to a verified provider.
    ///
    /// `contributions` maps resource kind → verified units (from VCA/CapacityReport).
    /// Returns CIRFI minted for this provider.
    pub fn credit_provider_earning(
        &mut self,
        provider_id: &[u8; 32],
        contributions: &BTreeMap<ResourceKind, u128>,
    ) -> u128 {
        let earned = provider_earning(
            contributions,
            &self.utilization,
            &self.resource_weights,
        );

        if earned > 0 {
            self.total_supply                 += earned;
            self.total_contribution_minted    += earned;

            tracing::debug!(
                provider  = hex::encode(provider_id),
                earned,
                window    = self.current_window,
                "CIRFI contribution mint"
            );
        }

        earned
    }

    // ── Consumption ───────────────────────────────────────────────────────────

    /// Consume CIRFI for an operation and apply the 60/25/15 split.
    ///
    /// `amount` is the total CIRFI cost of the operation.
    /// Returns the `ConsumptionSplit` (providers/burn/reserve amounts).
    ///
    /// Caller is responsible for:
    /// 1. Verifying the consumer's CIRFI balance >= amount.
    /// 2. Debiting the consumer's balance.
    /// 3. Distributing `split.to_providers` to the serving providers.
    pub fn consume(&mut self, amount: u128) -> ConsumptionSplit {
        let split = split_consumption(amount);

        // Apply burn and reserve to engine state.
        // Provider share is distributed by caller (they know which providers served).
        self.total_supply    = self.total_supply.saturating_sub(split.burned);
        self.total_burned    += split.burned;
        self.protocol_reserve += split.to_reserve;

        tracing::debug!(
            consumed     = amount,
            to_providers = split.to_providers,
            burned       = split.burned,
            to_reserve   = split.to_reserve,
            window       = self.current_window,
            "CIRFI consumed"
        );

        split
    }

    /// Compute the CIRFI cost for an operation given its resource breakdown.
    ///
    /// `cost = sum_r [ base_cost(r) * congestion_multiplier(r) * units(r) ]`
    pub fn operation_cost(&self, op: &OperationCost) -> u128 {
        op.resources.iter().map(|(kind, &units)| {
            self.utilization
                .get(kind)
                .map(|u| u.cost_for(units))
                .unwrap_or_else(|| {
                    // No utilization state: use base cost at no congestion.
                    kind.base_cost_per_unit().saturating_mul(units)
                })
        }).sum()
    }

    // ── Window boundary ───────────────────────────────────────────────────────

    /// Advance to the next window, updating utilization EMA and conversion rate.
    ///
    /// `demand_by_resource` — actual demand units consumed per resource this window.
    /// `capacity_by_resource` — available capacity per resource (from CapacityReport).
    ///
    /// Call this at each epoch/window boundary before processing the next window's
    /// transactions.
    pub fn advance_window(
        &mut self,
        demand_by_resource:   &BTreeMap<ResourceKind, u128>,
        capacity_by_resource: &BTreeMap<ResourceKind, u128>,
    ) {
        self.current_window += 1;

        // Update per-resource utilization.
        for (&kind, u) in self.utilization.iter_mut() {
            let demand   = demand_by_resource.get(&kind).copied().unwrap_or(0);
            let capacity = capacity_by_resource.get(&kind).copied().unwrap_or(0);
            u.record_window(demand, capacity);
        }

        // Aggregate U-bar: simple average across all resource types.
        // TODO: weight by resource importance for a better aggregate signal.
        let u_bars: Vec<u128> = self.utilization.values().map(|u| u.u_bar).collect();
        let u_bar_agg = if u_bars.is_empty() {
            U_STAR
        } else {
            u_bars.iter().sum::<u128>() / u_bars.len() as u128
        };

        // Update conversion rate.
        self.conversion_rate.update(u_bar_agg);

        tracing::info!(
            window       = self.current_window,
            u_bar_agg,
            rt           = self.conversion_rate.rt,
            total_supply = self.total_supply,
            total_burned = self.total_burned,
            "CIRFI window advanced"
        );
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Current conversion rate Rt (fixed-point × D).
    pub fn rt(&self) -> u128 { self.conversion_rate.rt }

    /// Current congestion multiplier for a resource type.
    pub fn congestion_of(&self, kind: ResourceKind) -> u128 {
        self.utilization.get(&kind).map(|u| u.congestion).unwrap_or(D)
    }

    /// Window summary for logging / explorer.
    pub fn window_summary(&self) -> WindowSummary {
        WindowSummary {
            window:                    self.current_window,
            rt:                        self.conversion_rate.rt,
            total_supply:              self.total_supply,
            total_purchase_minted:     self.total_purchase_minted,
            total_contribution_minted: self.total_contribution_minted,
            total_burned:              self.total_burned,
            protocol_reserve:          self.protocol_reserve,
            total_qcb_burned:          self.total_qcb_burned,
            congestion_by_resource: self.utilization.iter()
                .map(|(&k, u)| (k, u.congestion))
                .collect(),
        }
    }
}

// ── WindowSummary ─────────────────────────────────────────────────────────────

/// Snapshot of engine state at a window boundary.
#[derive(Debug, Clone)]
pub struct WindowSummary {
    pub window:                    u64,
    pub rt:                        u128,
    pub total_supply:              u128,
    pub total_purchase_minted:     u128,
    pub total_contribution_minted: u128,
    pub total_burned:              u128,
    pub protocol_reserve:          u128,
    pub total_qcb_burned:          u128,
    pub congestion_by_resource:    BTreeMap<ResourceKind, u128>,
}

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CirfiError {
    #[error("insufficient CIRFI balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    #[error("no CIRFI-to-QCB conversion path exists (constitutional constraint)")]
    NoReverseConversion,

    #[error("resource kind {0:?} not tracked")]
    UnknownResource(ResourceKind),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type CirfiResult<T> = Result<T, CirfiError>;

// ── External dependency shim ──────────────────────────────────────────────────

/// Minimal hex encoding for provider ID logging (no extra dep).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> CirfiEngine {
        // R0 = 1.0 × D: 1 CIRFI minted per QCB burned at target utilization.
        CirfiEngine::new(D)
    }

    // ── Protocol invariants ───────────────────────────────────────────────────

    #[test]
    fn consumption_split_sums_to_d() {
        let sum = PROVIDER_SHARE + BURN_SHARE + RESERVE_SHARE;
        assert_eq!(sum, D, "consumption split must sum to D");
    }

    #[test]
    fn split_consumption_no_leakage() {
        let amount = 1_234_567_u128;
        let split  = split_consumption(amount);
        assert_eq!(split.total(), amount, "consumption split must account for all CIRFI");
    }

    #[test]
    fn split_consumption_proportions() {
        let amount = 1_000_000_u128; // exactly D
        let split  = split_consumption(amount);
        assert_eq!(split.to_providers, 600_000, "60% to providers");
        assert_eq!(split.burned,       250_000, "25% burned");
        assert_eq!(split.to_reserve,   150_000, "15% to reserve");
    }

    // ── Purchase path ─────────────────────────────────────────────────────────

    #[test]
    fn purchase_at_target_utilization_uses_r0() {
        let mut e = engine();
        // U-bar == U* by default → Rt == R0 == D
        let (cirfi, rt) = e.purchase_cirfi(D); // burn 1 QCB (×D)
        assert_eq!(rt, D, "Rt should equal R0 at target utilization");
        assert_eq!(cirfi, D, "1 QCB → 1 CIRFI at R0 = 1.0");
        assert_eq!(e.total_supply, D);
        assert_eq!(e.total_qcb_burned, D);
    }

    #[test]
    fn purchase_burns_qcb_and_mints_cirfi() {
        let mut e = engine();
        let (minted, _) = e.purchase_cirfi(2 * D);
        assert_eq!(e.total_qcb_burned, 2 * D);
        assert_eq!(e.total_supply, minted);
        assert_eq!(e.total_purchase_minted, minted);
    }

    // ── Utilization and EMA ───────────────────────────────────────────────────

    #[test]
    fn ema_decays_spike_over_windows() {
        let mut u = ResourceUtilization::new(ResourceKind::Compute);
        // One window at 100% utilization.
        u.record_window(D, D);
        let spike_u_bar = u.u_bar;
        // 10 windows at 0% (no demand).
        for _ in 0..10 {
            u.record_window(0, D);
        }
        assert!(u.u_bar < spike_u_bar,
            "EMA should decay toward 0 after spike clears");
        // After 10 windows of 0 demand, u_bar should be well below the spike.
        assert!(u.u_bar < D / 2,
            "EMA should be below 50% utilization after 10 quiet windows");
    }

    #[test]
    fn utilization_capped_at_100_percent() {
        let mut u = ResourceUtilization::new(ResourceKind::Compute);
        // Demand > capacity is unusual but must not overflow.
        u.record_window(100 * D, D);
        assert_eq!(u.u_raw, D, "raw utilization capped at 100%");
    }

    #[test]
    fn zero_capacity_treated_as_full_congestion() {
        let mut u = ResourceUtilization::new(ResourceKind::Compute);
        u.record_window(1_000, 0); // demand but no capacity reported
        assert_eq!(u.u_raw, D, "no capacity → 100% congestion");
    }

    // ── Conversion rate ───────────────────────────────────────────────────────

    #[test]
    fn rt_equals_r0_at_target_utilization() {
        let mut rate = ConversionRate::new(D);
        rate.update(U_STAR);
        assert_eq!(rate.rt, D, "Rt = R0 when U-bar = U*");
    }

    #[test]
    fn rt_above_r0_when_underutilized() {
        let mut rate = ConversionRate::new(D);
        // U-bar = 35% (below 70% target → cheaper to acquire CIRFI)
        rate.update(350_000);
        assert!(rate.rt > D, "Rt > R0 when network is underutilized");
    }

    #[test]
    fn rt_below_r0_when_congested() {
        let mut rate = ConversionRate::new(D);
        // U-bar = 90% (above 70% target → CIRFI is scarcer)
        rate.update(900_000);
        assert!(rate.rt < D, "Rt < R0 when network is congested");
    }

    #[test]
    fn rt_clamped_to_rmin_at_extreme_congestion() {
        let mut rate = ConversionRate::new(D);
        rate.update(D); // 100% utilization
        assert!(rate.rt >= rate.r_min, "Rt must not go below Rmin");
    }

    #[test]
    fn rt_clamped_to_rmax_at_zero_utilization() {
        let mut rate = ConversionRate::new(D);
        rate.update(1); // near-zero utilization → rate would explode
        assert!(rate.rt <= rate.r_max, "Rt must not exceed Rmax");
    }

    // ── Operation pricing ─────────────────────────────────────────────────────

    #[test]
    fn operation_cost_scales_with_congestion() {
        let mut e = engine();

        // Force high congestion on Compute: 90% demand.
        {
            let u = e.utilization.get_mut(&ResourceKind::Compute).unwrap();
            u.record_window(900_000, D); // 90% utilization
        }

        let op = OperationCost::new().add(ResourceKind::Compute, D);
        let cost_congested = e.operation_cost(&op);

        // Reset to target utilization.
        {
            let u = e.utilization.get_mut(&ResourceKind::Compute).unwrap();
            u.record_window(700_000, D);
        }
        let cost_normal = e.operation_cost(&op);

        assert!(cost_congested > cost_normal,
            "congested operations should cost more CIRFI");
    }

    #[test]
    fn zk_proving_costs_more_than_state_read() {
        let e = engine();
        let read_op = OperationCost::new().add(ResourceKind::Storage, D);
        let zk_op   = OperationCost::new().add(ResourceKind::ZkProving, D);

        let read_cost = e.operation_cost(&read_op);
        let zk_cost   = e.operation_cost(&zk_op);

        assert!(zk_cost > read_cost,
            "ZK proving should cost more than a state read at equal utilization");
    }

    // ── Provider earning ──────────────────────────────────────────────────────

    #[test]
    fn provider_earns_more_when_resource_is_scarce() {
        let mut e = engine();

        // Low congestion on Compute.
        {
            let u = e.utilization.get_mut(&ResourceKind::Compute).unwrap();
            u.record_window(300_000, D); // 30% utilization
        }
        let mut contributions = BTreeMap::new();
        contributions.insert(ResourceKind::Compute, D);
        let earning_low = provider_earning(
            &contributions, &e.utilization, &e.resource_weights
        );

        // High congestion on Compute.
        {
            let u = e.utilization.get_mut(&ResourceKind::Compute).unwrap();
            u.record_window(900_000, D); // 90% utilization
        }
        let earning_high = provider_earning(
            &contributions, &e.utilization, &e.resource_weights
        );

        assert!(earning_high > earning_low,
            "providers earn more when their resource is congested/scarce");
    }

    #[test]
    fn zero_contribution_earns_zero() {
        let e = engine();
        let contributions = BTreeMap::new();
        let earned = provider_earning(
            &contributions, &e.utilization, &e.resource_weights
        );
        assert_eq!(earned, 0);
    }

    #[test]
    fn credit_provider_earning_updates_supply() {
        let mut e = engine();
        let provider = [1u8; 32];
        let mut contributions = BTreeMap::new();
        contributions.insert(ResourceKind::Compute, D);

        let earned = e.credit_provider_earning(&provider, &contributions);
        assert_eq!(e.total_supply, earned);
        assert_eq!(e.total_contribution_minted, earned);
    }

    // ── Consumption ───────────────────────────────────────────────────────────

    #[test]
    fn consume_reduces_supply_by_burn_share() {
        let mut e = engine();
        // First mint some CIRFI.
        let (minted, _) = e.purchase_cirfi(10 * D);
        let supply_before = e.total_supply;

        let split = e.consume(D); // consume 1 CIRFI (×D)
        assert_eq!(e.total_burned, split.burned);
        assert_eq!(e.protocol_reserve, split.to_reserve);
        // Supply reduced by burned amount only (providers take the rest off-chain).
        assert_eq!(e.total_supply, supply_before - split.burned);
        let _ = minted;
    }

    // ── Window advance ────────────────────────────────────────────────────────

    #[test]
    fn advance_window_updates_conversion_rate() {
        let mut e  = engine();
        let rt_0   = e.rt();

        // Advance with high demand on all resources → congestion → Rt drops.
        let demand   : BTreeMap<ResourceKind, u128> =
            ResourceKind::all().iter().map(|&k| (k, 900_000u128)).collect();
        let capacity : BTreeMap<ResourceKind, u128> =
            ResourceKind::all().iter().map(|&k| (k, D)).collect();
        e.advance_window(&demand, &capacity);

        assert_ne!(e.rt(), rt_0, "advance_window should update Rt");
        assert!(e.rt() <= rt_0,
            "high utilization should lower or maintain Rt");
    }

    #[test]
    fn advance_window_increments_counter() {
        let mut e = engine();
        assert_eq!(e.current_window, 0);
        let empty: BTreeMap<ResourceKind, u128> = BTreeMap::new();
        e.advance_window(&empty, &empty);
        assert_eq!(e.current_window, 1);
    }

    // ── Full loop ─────────────────────────────────────────────────────────────

    #[test]
    fn demand_loop_qcb_burns_grow_with_usage() {
        let mut e = engine();
        let empty: BTreeMap<ResourceKind, u128> = BTreeMap::new();

        // Low usage window: burn 1 QCB.
        let low_demand: BTreeMap<_, _> =
            ResourceKind::all().iter().map(|&k| (k, 100_000u128)).collect();
        let capacity: BTreeMap<_, _> =
            ResourceKind::all().iter().map(|&k| (k, D)).collect();
        e.advance_window(&low_demand, &capacity);
        let (minted_low, rt_low) = e.purchase_cirfi(D);

        // Reset engine (manual) and simulate high usage.
        let mut e2 = engine();
        let high_demand: BTreeMap<_, _> =
            ResourceKind::all().iter().map(|&k| (k, 950_000u128)).collect();
        e2.advance_window(&high_demand, &capacity);
        let (_minted_high, rt_high) = e2.purchase_cirfi(D);

        // At high usage Rt is lower (fewer CIRFI per QCB → scarcer).
        assert!(rt_high <= rt_low,
            "high-demand network should yield fewer CIRFI per QCB burned");
        let _ = (minted_low, empty);
    }

    #[test]
    fn supply_equation_components_tracked_independently() {
        let mut e = engine();
        let provider = [0u8; 32];

        // Purchase path.
        let (purchase_minted, _) = e.purchase_cirfi(5 * D);

        // Contribution path.
        let mut contributions = BTreeMap::new();
        contributions.insert(ResourceKind::ZkProving, D);
        let contrib_minted = e.credit_provider_earning(&provider, &contributions);

        // Consume some.
        let split = e.consume(D);

        assert_eq!(e.total_purchase_minted, purchase_minted);
        assert_eq!(e.total_contribution_minted, contrib_minted);
        assert_eq!(e.total_burned, split.burned);
        // Supply = purchase_minted + contrib_minted - burned.
        assert_eq!(
            e.total_supply,
            purchase_minted + contrib_minted - split.burned
        );
    }

    #[test]
    fn integer_pow_fp_at_zero_exponent_is_one() {
        assert_eq!(integer_pow_fp(D, 0), D);
    }

    #[test]
    fn integer_pow_fp_at_one_exponent_is_base() {
        assert_eq!(integer_pow_fp(2 * D, 1), 2 * D);
    }

    #[test]
    fn integer_pow_fp_squares_correctly() {
        // (2.0)^2 = 4.0 in fixed-point
        let result = integer_pow_fp(2 * D, 2);
        assert_eq!(result, 4 * D);
    }
}
