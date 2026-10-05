//! # chain-forge-qrc
//!
//! The QCB resource economy. Implements the QRC Economic Model v0.1.
//!
//! ## What $QRC is
//!
//! $QRC is a **resource consumption token**, not a UBI token.
//! It is the unit of account for all network resource usage:
//! compute, storage, ZK proving, bandwidth, oracle data, AI inference,
//! and external verification.
//!
//! ## Two minting paths (fully independent)
//!
//! 1. **Purchase path**: QCB is permanently burned → QRC resource credits
//!    are created at the algorithmic rate `Rt`. Rate adjusts with network load.
//! 2. **Contribution path**: Verified resource providers earn QRC minted
//!    directly when the VCA system confirms delivery. No QCB is involved.
//!
//! There is **no QRC → QCB conversion**. This is a constitutional constraint.
//!
//! ## Consumption split
//!
//! When QRC is consumed by an operation it splits:
//!   ~60% → provider compensation
//!   ~25% → permanent QRC burn (deflationary pressure)
//!   ~15% → protocol reserve
//!
//! ## Demand loop
//!
//! Network usage grows → QRC demand rises → more QCB burned to obtain QRC
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
//! - Demurrage / time-value decay (deliberately excluded — QRC is a pure resource
//!   consumption credit; idle credits do not decay)
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

/// Hard floor on Rt: prevents QRC from becoming free during low demand.
/// TBD via economic simulation; placeholder = 0.1 × R0.
pub const R_MIN_FRACTION: u128 = 100_000; // 0.10 × D (10% of R0)

/// Hard ceiling on Rt: prevents QRC from becoming unaffordable.
/// TBD via economic simulation; placeholder = 10 × R0.
pub const R_MAX_FRACTION: u128 = 10_000_000; // 10.0 × D (1000% of R0)

/// Congestion sensitivity exponent γ (gamma). Higher = faster price response.
/// TBD via simulation. Placeholder = 2.0 (quadratic response).
pub const GAMMA_NUM: u128 = 2; // integer — used in integer exponentiation

// ── Epoch accounting constants (QRC Economic Model v0.2) ─────────────────────

/// Maximum QRC that may be issued (purchase + contribution combined) per verified
/// identity per epoch. Acts as the epoch-level supply cap, scaling with the
/// verified population so minting pressure tracks real network participants.
/// Unit: micro-QRC (fixed-point × D). Placeholder — calibrate via simulation.
pub const EPOCH_ISSUANCE_CAP_PER_VERIFIED: u128 = 10_000_000; // 10 QRC per verified per epoch

/// Fraction of `protocol_reserve` seeded into `epoch_reserve_balance` at EpochOpen.
/// Fixed-point × D. 100_000 = 10% of the reserve.
pub const EPOCH_RESERVE_SEED_RATE: u128 = 100_000; // 10% of protocol_reserve

// ── ResourceKind ─────────────────────────────────────────────────────────────

/// All network resource types that QRC prices.
/// Extended resource types (oracle data, AI inference, external verification)
/// are listed here for completeness but share the `Compute` billing tier
/// until per-type weights are calibrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
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

    /// Base QRC cost for one normalized unit of this resource (× D).
    /// These are illustrative placeholders — must be calibrated by simulation.
    pub fn base_cost_per_unit(self) -> u128 {
        match self {
            ResourceKind::Compute              =>   1_000, // 0.001 QRC/CU
            ResourceKind::Storage              =>     100, // 0.0001 QRC/byte·epoch
            ResourceKind::ZkProving            =>  10_000, // 0.01 QRC/proof-second
            ResourceKind::Bandwidth            =>     500, // 0.0005 QRC/kB
            ResourceKind::OracleData           =>   5_000, // 0.005 QRC/query
            ResourceKind::AiInference          =>  50_000, // 0.05 QRC/inference
            ResourceKind::ExternalVerification => 100_000, // 0.1 QRC/verification
        }
    }
}

// ── ResourceUtilization ───────────────────────────────────────────────────────

/// Tracks demand and capacity for one resource type in one window,
/// and carries the EMA-smoothed utilization across windows.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

    /// The congestion multiplier for QRC pricing.
    /// congestion > 1.0 × D means above-target → operations cost more.
    pub fn congestion_multiplier(&self) -> u128 {
        self.congestion
    }

    /// QRC cost for `units` of this resource in the current window.
    /// cost = base_cost_per_unit * congestion_multiplier * units / D
    pub fn cost_for(&self, units: u128) -> u128 {
        let base  = self.kind.base_cost_per_unit();
        let adj   = base.saturating_mul(self.congestion_multiplier()) / D;
        adj.saturating_mul(units)
    }
}

// ── ConversionRate ────────────────────────────────────────────────────────────

/// Algorithmic QCB → QRC conversion rate state.
///
/// Rt = R0 * (U* / U-bar_aggregate)^gamma
/// Clamped to [Rmin, Rmax].
///
/// When utilization is below target, Rt > R0 (more QRC per QCB burned —
/// cheaper to acquire capacity). When above target, Rt < R0 (QRC is scarce).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConversionRate {
    /// Base rate R0: QRC units minted per QCB burned at target utilization.
    /// Fixed-point × D. E.g. 1_000_000 = 1.0 QRC per QCB.
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
        // If U-bar < U* → ratio > 1 → Rt > R0 (more QRC per QCB).
        // If U-bar > U* → ratio < 1 → Rt < R0 (less QRC per QCB).
        let ratio = U_STAR.saturating_mul(D) / u_bar_aggregate;

        // Rt = R0 * ratio^gamma.
        // Integer exponentiation: ratio is fixed-point × D.
        // ratio^2 = ratio * ratio / D (keeping fixed-point).
        let ratio_pow = integer_pow_fp(ratio, GAMMA_NUM);
        let rt_raw    = self.r0.saturating_mul(ratio_pow) / D;

        self.rt = rt_raw.clamp(self.r_min, self.r_max);
    }

    /// QRC minted for `qcb_burned` QCB at the current rate.
    /// qrc_minted = qcb_burned * Rt / D
    pub fn qrc_for_qcb(&self, qcb_burned: u128) -> u128 {
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

/// Result of splitting a QRC consumption event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumptionSplit {
    /// QRC routed to providers who served this operation.
    pub to_providers: u128,
    /// QRC permanently burned.
    pub burned: u128,
    /// QRC added to protocol reserve.
    pub to_reserve: u128,
}

impl ConsumptionSplit {
    /// Total consumed (sum of all three destinations).
    pub fn total(&self) -> u128 {
        self.to_providers + self.burned + self.to_reserve
    }
}

/// Split `amount` of QRC according to the 60/25/15 consumption split.
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
/// Returns QRC minted for this provider (fixed-point units).
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

// ── Control 5: CoverageRatio circuit breaker ─────────────────────────────────

/// CoverageRatio threshold below which minting halts entirely (both paths).
/// CR_halt = 0.75 (fixed-point × D).
pub const CR_HALT: u128 = 750_000; // 0.75 × D

/// CoverageRatio threshold above which normal operation resumes.
/// CR_resume = 1.00 (fixed-point × D). Hysteresis gap: 0.25.
pub const CR_RESUME: u128 = 1_000_000; // 1.00 × D

/// Three-state minting circuit breaker for the CoverageRatio control.
///
/// State transitions (CR = capacity / qrc_outstanding, fixed-point × D):
/// ```text
/// NORMAL     → RESTRICTED : CR drops below CR_resume  (1.00)
/// RESTRICTED → HALTED     : CR drops below CR_halt    (0.75)
/// HALTED     → RESTRICTED : CR rises to   CR_halt     (0.75)
/// RESTRICTED → NORMAL     : CR rises to   CR_resume   (1.00)
/// ```
/// The hysteresis gap (CR_halt … CR_resume) prevents oscillation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MintingState {
    /// CR ≥ CR_resume: both purchase and contribution paths open.
    Normal,
    /// CR_halt ≤ CR < CR_resume: purchase (conversion) path suspended;
    /// contribution path remains open so providers can keep earning.
    Restricted,
    /// CR < CR_halt: both minting paths suspended until capacity recovers.
    Halted,
}

impl MintingState {
    /// Whether the purchase (QCB → QRC) conversion path is currently permitted.
    pub fn purchase_allowed(self) -> bool {
        self == MintingState::Normal
    }

    /// Whether the contribution earn path is currently permitted.
    pub fn contribution_allowed(self) -> bool {
        self != MintingState::Halted
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MintingState::Normal     => "normal",
            MintingState::Restricted => "restricted",
            MintingState::Halted     => "halted",
        }
    }
}

impl Default for MintingState {
    fn default() -> Self { MintingState::Normal }
}

// ── QrcEngine ───────────────────────────────────────────────────────────────

/// The full QRC resource economy engine.
///
/// Tracks per-resource utilization, the conversion rate, cumulative supply
/// metrics, and applies the economic formulas from QRC Economic Model v0.1.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QrcEngine {
    // -- Per-resource utilization state --
    pub utilization: BTreeMap<ResourceKind, ResourceUtilization>,

    // -- Resource weights (per-resource earning weights w(r), fixed-point × D) --
    pub resource_weights: BTreeMap<ResourceKind, u128>,

    // -- Conversion rate state --
    pub conversion_rate: ConversionRate,

    // -- Supply metrics --
    /// Total QRC in circulation (Mt).
    pub total_supply: u128,
    /// QRC minted via purchase path (sum of Qt*Rt over all windows).
    pub total_purchase_minted: u128,
    /// QRC minted via contribution path (sum of Ei,t over all windows).
    pub total_contribution_minted: u128,
    /// QRC permanently burned from consumption splits.
    pub total_burned: u128,
    /// QRC in protocol reserve.
    pub protocol_reserve: u128,
    /// QCB burned across all purchase conversions.
    pub total_qcb_burned: u128,

    // -- Window tracking --
    pub current_window: u64,

    // ── Epoch accounting (QRC Economic Model v0.2) ────────────────────────────

    /// The epoch currently open. 0 = no epoch open yet.
    pub current_epoch: u64,

    /// Whether an epoch is currently open (between EpochOpen and EpochClose).
    pub epoch_open: bool,

    /// Supply cap for the current epoch: maximum QRC that may be minted
    /// (purchase + contribution paths combined) during this epoch.
    /// Computed at EpochOpen as: `verified_count * EPOCH_ISSUANCE_CAP_PER_VERIFIED`.
    pub epoch_supply_cap: u128,

    /// QRC minted so far in the current epoch (purchase + contribution).
    /// Checked against `epoch_supply_cap` on every mint.
    pub epoch_minted: u128,

    /// Epoch reserve balance: QRC swept into the epoch reserve at EpochOpen
    /// (seeded from `protocol_reserve`), disbursed to providers, excess swept
    /// back at EpochClose.
    pub epoch_reserve_balance: u128,

    /// Per-epoch provider reward accumulator: total QRC earned by contribution-
    /// path providers during this epoch. Finalized at EpochClose.
    pub epoch_provider_rewards: u128,

    // ── Control 5: CoverageRatio circuit breaker (QRC Economic Model v0.2) ─────

    /// Current state of the minting circuit breaker.
    pub minting_state: MintingState,

    /// On-chain tracked network resource capacity (VCA-attested).
    /// Updated via `record_capacity()`. Units: normalized capacity units × D.
    pub tracked_capacity: u128,

    /// QRC outstanding = total_supply (alias kept for semantic clarity in CR formula).
    /// CR_t = tracked_capacity / total_supply (when total_supply > 0).
    // Note: this is derived, not stored separately — use `coverage_ratio()`.
    // Placeholder field for future state migration if needed.
    pub _cb_reserved: u128,
}

impl QrcEngine {
    /// Create a new engine with the given base conversion rate R0.
    /// `r0` is fixed-point × D: how many QRC units are minted per QCB
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
            // Epoch accounting (v0.2)
            current_epoch:              0,
            epoch_open:                 false,
            epoch_supply_cap:           0,
            epoch_minted:               0,
            epoch_reserve_balance:      0,
            epoch_provider_rewards:     0,
            // Control 5: circuit breaker
            minting_state:              MintingState::Normal,
            tracked_capacity:           0,
            _cb_reserved:               0,
        }
    }

    // ── Purchase path ─────────────────────────────────────────────────────────

    /// Burn `qcb_amount` QCB and mint QRC at the current rate Rt.
    ///
    /// Returns `(qrc_minted, rt_used)`.
    ///
    /// When an epoch is open, minting is capped at `epoch_supply_cap -
    /// epoch_minted`. If the full mint would exceed the cap, it is silently
    /// truncated — the caller receives fewer QRC credits than requested.
    /// Block producers must honour slippage guards (`min_qrc_out`) to protect
    /// buyers in this case.
    ///
    /// Security: the no-QRC-to-QCB constraint is enforced at the protocol
    /// level; this function only handles the QCB → QRC direction.
    pub fn purchase_qrc(&mut self, qcb_amount: u128) -> (u128, u128) {
        // Control 5: purchase path blocked when RESTRICTED or HALTED.
        if !self.minting_state.purchase_allowed() {
            tracing::warn!(
                state        = self.minting_state.as_str(),
                qcb_amount,
                "QRC purchase blocked by CoverageRatio circuit breaker"
            );
            // Return (0, current_rt) — no QRC minted, QCB not burned.
            return (0, self.conversion_rate.rt);
        }

        let qrc_raw  = self.conversion_rate.qrc_for_qcb(qcb_amount);
        let rt_used  = self.conversion_rate.rt;

        // Cap at epoch supply ceiling when an epoch is active.
        let qrc_minted = if self.epoch_open && self.epoch_supply_cap > 0 {
            let headroom = self.epoch_supply_cap.saturating_sub(self.epoch_minted);
            let capped   = qrc_raw.min(headroom);
            if capped < qrc_raw {
                tracing::warn!(
                    requested = qrc_raw,
                    capped,
                    epoch = self.current_epoch,
                    "QRC purchase capped by epoch supply ceiling"
                );
            }
            capped
        } else {
            qrc_raw
        };

        self.total_qcb_burned          += qcb_amount;
        self.total_supply              += qrc_minted;
        self.total_purchase_minted     += qrc_minted;
        if self.epoch_open { self.epoch_minted += qrc_minted; }

        tracing::info!(
            qcb_burned   = qcb_amount,
            qrc_minted,
            rt           = rt_used,
            window       = self.current_window,
            epoch        = self.current_epoch,
            "QRC purchase: QCB burned → QRC minted"
        );

        (qrc_minted, rt_used)
    }

    // ── Contribution path ─────────────────────────────────────────────────────

    /// Credit contribution-earned QRC to a verified provider.
    ///
    /// `contributions` maps resource kind → verified units (from VCA/CapacityReport).
    /// Returns QRC minted for this provider.
    pub fn credit_provider_earning(
        &mut self,
        provider_id: &[u8; 32],
        contributions: &BTreeMap<ResourceKind, u128>,
    ) -> u128 {
        // Control 5: contribution earn path blocked only when HALTED.
        // RESTRICTED still allows providers to earn (capacity providers are
        // the mechanism for increasing CR back toward NORMAL).
        if !self.minting_state.contribution_allowed() {
            tracing::warn!(
                provider  = hex::encode(provider_id),
                state     = self.minting_state.as_str(),
                "QRC contribution blocked by CoverageRatio circuit breaker (HALTED)"
            );
            return 0;
        }

        let earned = provider_earning(
            contributions,
            &self.utilization,
            &self.resource_weights,
        );

        // Cap at epoch supply ceiling when an epoch is active.
        let minted = if self.epoch_open && self.epoch_supply_cap > 0 {
            let headroom = self.epoch_supply_cap.saturating_sub(self.epoch_minted);
            earned.min(headroom)
        } else {
            earned
        };

        if minted > 0 {
            self.total_supply                 += minted;
            self.total_contribution_minted    += minted;
            if self.epoch_open {
                self.epoch_minted             += minted;
                self.epoch_provider_rewards   += minted;
            }

            tracing::debug!(
                provider  = hex::encode(provider_id),
                earned    = minted,
                window    = self.current_window,
                epoch     = self.current_epoch,
                "QRC contribution mint"
            );
        }

        minted
    }

    // ── Consumption ───────────────────────────────────────────────────────────

    /// Consume QRC for an operation and apply the 60/25/15 split.
    ///
    /// `amount` is the total QRC cost of the operation.
    /// Returns the `ConsumptionSplit` (providers/burn/reserve amounts).
    ///
    /// Caller is responsible for:
    /// 1. Verifying the consumer's QRC balance >= amount.
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
            "QRC consumed"
        );

        split
    }

    /// Compute the QRC cost for an operation given its resource breakdown.
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
            "QRC window advanced"
        );
    }

    // ── Control 5: CoverageRatio circuit breaker ──────────────────────────────

    /// Record VCA-attested network capacity for Control 5.
    ///
    /// Call this whenever a `CapacityReport` is finalised and accepted on-chain.
    /// `capacity` is the network's total verified resource capacity in normalised
    /// units (× D). After recording, `update_circuit_breaker()` is called
    /// automatically to apply any state transition.
    pub fn record_capacity(&mut self, capacity: u128) {
        self.tracked_capacity = capacity;
        self.update_circuit_breaker();
    }

    /// Compute the current CoverageRatio (CR_t).
    ///
    /// CR_t = tracked_capacity / total_supply  (both × D, result × D)
    ///
    /// Returns `None` when `total_supply == 0` (no QRC outstanding;
    /// the network is trivially solvent — treat as NORMAL).
    pub fn coverage_ratio(&self) -> Option<u128> {
        if self.total_supply == 0 {
            return None; // Trivially solvent.
        }
        // Fixed-point division: (capacity × D) / supply
        Some(self.tracked_capacity.saturating_mul(D) / self.total_supply)
    }

    /// Apply the three-state hysteresis transition based on the current CR.
    ///
    /// Transition table (CR = coverage_ratio()):
    /// - None (supply == 0)  → NORMAL
    /// - CR ≥ CR_resume      → NORMAL
    /// - CR_halt ≤ CR < CR_resume
    ///   - from NORMAL       → RESTRICTED
    ///   - from RESTRICTED   → stays RESTRICTED  (hysteresis)
    ///   - from HALTED       → RESTRICTED         (recovering)
    /// - CR < CR_halt        → HALTED
    ///
    /// Emits a structured JSON event to stdout on every state change.
    pub fn update_circuit_breaker(&mut self) {
        let cr_opt = self.coverage_ratio();

        let next_state = match cr_opt {
            None => MintingState::Normal, // No supply outstanding — fully solvent.
            Some(cr) => {
                if cr >= CR_RESUME {
                    MintingState::Normal
                } else if cr >= CR_HALT {
                    // In the hysteresis band: can only go to/stay at RESTRICTED.
                    // (Never jump from HALTED directly to NORMAL.)
                    MintingState::Restricted
                } else {
                    MintingState::Halted
                }
            }
        };

        if next_state != self.minting_state {
            let prev = self.minting_state;
            self.minting_state = next_state;

            // Emit structured telemetry.
            let cr_display = cr_opt.unwrap_or(u128::MAX);
            println!(
                "{{\"event\":\"circuit_breaker\",\"prev_state\":\"{}\",\"new_state\":\"{}\",\
                 \"coverage_ratio_fp\":{},\"tracked_capacity\":{},\"qrc_outstanding\":{}}}",
                prev.as_str(),
                next_state.as_str(),
                cr_display,
                self.tracked_capacity,
                self.total_supply,
            );
        }
    }

    // ── Epoch boundary (QRC Economic Model v0.2) ──────────────────────────────

    /// Open a new epoch.
    ///
    /// # Parameters
    /// - `epoch` — the epoch number being opened (must be current_epoch + 1,
    ///   or 1 on first open; calling EpochOpen twice without EpochClose is an error).
    /// - `verified_count` — number of verified identities at epoch start,
    ///   used to compute the epoch supply cap.
    ///
    /// # Effects
    /// - Sets `current_epoch = epoch`.
    /// - Computes `epoch_supply_cap = verified_count * EPOCH_ISSUANCE_CAP_PER_VERIFIED`.
    /// - Seeds `epoch_reserve_balance` from `protocol_reserve`
    ///   (up to `EPOCH_RESERVE_SEED_RATE` fraction of the reserve).
    /// - Resets `epoch_minted`, `epoch_provider_rewards` to 0.
    /// - Calls `advance_window` with zero demand/capacity to update utilization EMA.
    ///
    /// Returns `Err` if an epoch is already open.
    pub fn open_epoch(
        &mut self,
        epoch:          u64,
        verified_count: u64,
    ) -> QrcResult<EpochSummary> {
        if self.epoch_open {
            return Err(QrcError::EpochAlreadyOpen(self.current_epoch));
        }

        // Compute epoch supply cap from the verified population size.
        // EPOCH_ISSUANCE_CAP_PER_VERIFIED is in micro-QRC (× D).
        let supply_cap = (verified_count as u128)
            .saturating_mul(EPOCH_ISSUANCE_CAP_PER_VERIFIED);

        // Seed epoch reserve from protocol_reserve (up to the seed rate).
        let seed = self.protocol_reserve
            .saturating_mul(EPOCH_RESERVE_SEED_RATE) / D;
        self.protocol_reserve          = self.protocol_reserve.saturating_sub(seed);
        self.epoch_reserve_balance     = seed;

        // Reset per-epoch accumulators.
        self.epoch_minted              = 0;
        self.epoch_provider_rewards    = 0;
        self.current_epoch             = epoch;
        self.epoch_supply_cap          = supply_cap;
        self.epoch_open                = true;

        // Advance the utilization window (zero demand = startup signal).
        let empty = BTreeMap::new();
        self.advance_window(&empty, &empty);

        tracing::info!(
            epoch,
            verified_count,
            supply_cap,
            epoch_reserve_seeded = seed,
            "QRC epoch opened"
        );

        Ok(self.epoch_summary())
    }

    /// Close the current epoch.
    ///
    /// # Effects
    /// - Finalizes provider reward totals.
    /// - Sweeps unused `epoch_reserve_balance` back into `protocol_reserve`.
    /// - Marks `epoch_open = false`.
    ///
    /// Returns `Err` if no epoch is currently open.
    pub fn close_epoch(&mut self) -> QrcResult<EpochSummary> {
        if !self.epoch_open {
            return Err(QrcError::NoEpochOpen);
        }

        // Sweep unspent epoch reserve back to protocol reserve.
        self.protocol_reserve              += self.epoch_reserve_balance;
        let swept                           = self.epoch_reserve_balance;
        self.epoch_reserve_balance         = 0;

        let summary = self.epoch_summary();
        self.epoch_open = false;

        tracing::info!(
            epoch          = self.current_epoch,
            minted         = summary.epoch_minted,
            provider_rewards = summary.provider_rewards,
            reserve_swept  = swept,
            total_supply   = self.total_supply,
            "QRC epoch closed"
        );

        Ok(summary)
    }

    /// Snapshot of the current epoch's accounting state.
    pub fn epoch_summary(&self) -> EpochSummary {
        EpochSummary {
            epoch:            self.current_epoch,
            epoch_open:       self.epoch_open,
            supply_cap:       self.epoch_supply_cap,
            epoch_minted:     self.epoch_minted,
            provider_rewards: self.epoch_provider_rewards,
            reserve_balance:  self.epoch_reserve_balance,
            total_supply:     self.total_supply,
            total_burned:     self.total_burned,
        }
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

// ── EpochSummary ──────────────────────────────────────────────────────────────

/// Snapshot of epoch accounting state, returned by `open_epoch`, `close_epoch`,
/// and `epoch_summary`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSummary {
    /// Epoch number.
    pub epoch: u64,
    /// Whether the epoch is currently open.
    pub epoch_open: bool,
    /// Maximum QRC that may be minted this epoch (purchase + contribution).
    pub supply_cap: u128,
    /// QRC minted so far (or total at close) in this epoch.
    pub epoch_minted: u128,
    /// QRC earned by contribution-path providers this epoch.
    pub provider_rewards: u128,
    /// Unspent epoch reserve balance (0 after close — swept to protocol_reserve).
    pub reserve_balance: u128,
    /// Total QRC in circulation at snapshot time.
    pub total_supply: u128,
    /// Cumulative QRC permanently burned at snapshot time.
    pub total_burned: u128,
}

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum QrcError {
    #[error("insufficient QRC balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    #[error("no QRC-to-QCB conversion path exists (constitutional constraint)")]
    NoReverseConversion,

    #[error("resource kind {0:?} not tracked")]
    UnknownResource(ResourceKind),

    #[error("epoch {0} is already open — close it before opening a new one")]
    EpochAlreadyOpen(u64),

    #[error("no epoch is currently open")]
    NoEpochOpen,

    #[error("internal error: {0}")]
    Internal(String),
}

pub type QrcResult<T> = Result<T, QrcError>;

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

    fn engine() -> QrcEngine {
        // R0 = 1.0 × D: 1 QRC minted per QCB burned at target utilization.
        QrcEngine::new(D)
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
        assert_eq!(split.total(), amount, "consumption split must account for all QRC");
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
        let (qrc, rt) = e.purchase_qrc(D); // burn 1 QCB (×D)
        assert_eq!(rt, D, "Rt should equal R0 at target utilization");
        assert_eq!(qrc, D, "1 QCB → 1 QRC at R0 = 1.0");
        assert_eq!(e.total_supply, D);
        assert_eq!(e.total_qcb_burned, D);
    }

    #[test]
    fn purchase_burns_qcb_and_mints_qrc() {
        let mut e = engine();
        let (minted, _) = e.purchase_qrc(2 * D);
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
        // U-bar = 35% (below 70% target → cheaper to acquire QRC)
        rate.update(350_000);
        assert!(rate.rt > D, "Rt > R0 when network is underutilized");
    }

    #[test]
    fn rt_below_r0_when_congested() {
        let mut rate = ConversionRate::new(D);
        // U-bar = 90% (above 70% target → QRC is scarcer)
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
            "congested operations should cost more QRC");
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
        // First mint some QRC.
        let (minted, _) = e.purchase_qrc(10 * D);
        let supply_before = e.total_supply;

        let split = e.consume(D); // consume 1 QRC (×D)
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
        let (minted_low, rt_low) = e.purchase_qrc(D);

        // Reset engine (manual) and simulate high usage.
        let mut e2 = engine();
        let high_demand: BTreeMap<_, _> =
            ResourceKind::all().iter().map(|&k| (k, 950_000u128)).collect();
        e2.advance_window(&high_demand, &capacity);
        let (_minted_high, rt_high) = e2.purchase_qrc(D);

        // At high usage Rt is lower (fewer QRC per QCB → scarcer).
        assert!(rt_high <= rt_low,
            "high-demand network should yield fewer QRC per QCB burned");
        let _ = (minted_low, empty);
    }

    #[test]
    fn supply_equation_components_tracked_independently() {
        let mut e = engine();
        let provider = [0u8; 32];

        // Purchase path.
        let (purchase_minted, _) = e.purchase_qrc(5 * D);

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

    // ── Epoch boundary (v0.2) ─────────────────────────────────────────────────

    #[test]
    fn open_epoch_sets_supply_cap_from_verified_count() {
        let mut e = engine();
        let summary = e.open_epoch(1, 100).unwrap();
        assert_eq!(summary.epoch, 1);
        assert!(summary.epoch_open);
        assert_eq!(summary.supply_cap, 100 * EPOCH_ISSUANCE_CAP_PER_VERIFIED);
        assert_eq!(summary.epoch_minted, 0);
        assert_eq!(summary.provider_rewards, 0);
    }

    #[test]
    fn open_epoch_seeds_reserve_from_protocol_reserve() {
        let mut e = engine();
        // Seed the protocol reserve first via consumption.
        e.purchase_qrc(100 * D);
        e.consume(50 * D); // 15% → reserve = 7.5 * D
        let reserve_before = e.protocol_reserve;
        assert!(reserve_before > 0, "protocol_reserve should be non-zero after consumption");

        e.open_epoch(1, 10).unwrap();

        let expected_seed = reserve_before.saturating_mul(EPOCH_RESERVE_SEED_RATE) / D;
        assert_eq!(e.epoch_reserve_balance, expected_seed);
        assert_eq!(e.protocol_reserve, reserve_before - expected_seed);
    }

    #[test]
    fn double_open_epoch_returns_error() {
        let mut e = engine();
        e.open_epoch(1, 100).unwrap();
        let err = e.open_epoch(2, 100).unwrap_err();
        assert!(
            matches!(err, QrcError::EpochAlreadyOpen(1)),
            "opening a second epoch without closing should fail"
        );
    }

    #[test]
    fn close_without_open_returns_error() {
        let mut e = engine();
        let err = e.close_epoch().unwrap_err();
        assert!(matches!(err, QrcError::NoEpochOpen));
    }

    #[test]
    fn close_epoch_sweeps_reserve_back() {
        let mut e = engine();
        // Give the engine some reserve so open_epoch seeds something.
        e.purchase_qrc(100 * D);
        e.consume(100 * D);
        let reserve_before_open = e.protocol_reserve;

        e.open_epoch(1, 10).unwrap();
        let seeded = e.epoch_reserve_balance;
        assert!(seeded > 0);

        let summary = e.close_epoch().unwrap();

        // Reserve fully swept back (no disbursements in this test).
        assert_eq!(summary.reserve_balance, 0);
        assert_eq!(e.epoch_reserve_balance, 0);
        assert_eq!(e.protocol_reserve, reserve_before_open);
    }

    #[test]
    fn close_epoch_marks_epoch_closed() {
        let mut e = engine();
        e.open_epoch(1, 50).unwrap();
        assert!(e.epoch_open);
        e.close_epoch().unwrap();
        assert!(!e.epoch_open);
    }

    #[test]
    fn open_close_open_is_valid() {
        let mut e = engine();
        e.open_epoch(1, 50).unwrap();
        e.close_epoch().unwrap();
        // Should succeed — previous epoch is closed.
        let summary = e.open_epoch(2, 60).unwrap();
        assert_eq!(summary.epoch, 2);
        assert_eq!(summary.supply_cap, 60 * EPOCH_ISSUANCE_CAP_PER_VERIFIED);
    }

    #[test]
    fn epoch_supply_cap_limits_purchase_minting() {
        let mut e = engine();
        // Open epoch with only 1 verified person → tiny supply cap.
        e.open_epoch(1, 1).unwrap();
        let cap = e.epoch_supply_cap;
        assert!(cap > 0);

        // Attempt to mint 10× the cap.
        let (minted, _) = e.purchase_qrc(10 * cap);

        // Minted must not exceed the cap.
        assert!(
            minted <= cap,
            "purchase minting must not exceed epoch supply cap: minted={minted}, cap={cap}"
        );
        assert_eq!(e.epoch_minted, minted);
    }

    #[test]
    fn epoch_supply_cap_limits_contribution_minting() {
        let mut e = engine();
        e.open_epoch(1, 1).unwrap();
        let cap = e.epoch_supply_cap;

        // Force high Compute congestion so one D-unit contribution earns a lot.
        {
            let u = e.utilization.get_mut(&ResourceKind::Compute).unwrap();
            u.record_window(D, D); // 100% utilization → high earnings
        }

        let provider = [2u8; 32];
        let mut contributions = BTreeMap::new();
        // Contribute enormous Compute units — earnings should still be capped.
        contributions.insert(ResourceKind::Compute, 1_000_000 * D);
        let earned = e.credit_provider_earning(&provider, &contributions);

        assert!(
            earned <= cap,
            "contribution minting must not exceed epoch supply cap: earned={earned}, cap={cap}"
        );
    }

    #[test]
    fn epoch_summary_reflects_provider_rewards() {
        let mut e = engine();
        e.open_epoch(1, 1000).unwrap();

        let provider = [3u8; 32];
        let mut contributions = BTreeMap::new();
        contributions.insert(ResourceKind::Compute, D);
        let earned = e.credit_provider_earning(&provider, &contributions);

        let summary = e.epoch_summary();
        assert_eq!(summary.provider_rewards, earned);
        assert_eq!(summary.epoch_minted, earned);
    }

    // ── Control 5: CoverageRatio circuit breaker ──────────────────────────────

    /// Helper: build an engine with `total_supply` already set.
    fn engine_with_supply(supply: u128) -> QrcEngine {
        let mut e = engine();
        // Directly set supply (bypass purchase logic for test setup).
        e.total_supply = supply;
        e
    }

    #[test]
    fn coverage_ratio_none_when_no_supply() {
        let e = engine();
        assert_eq!(e.total_supply, 0);
        assert!(e.coverage_ratio().is_none(), "CR should be None when no QRC outstanding");
        assert_eq!(e.minting_state, MintingState::Normal, "no supply → trivially Normal");
    }

    #[test]
    fn coverage_ratio_calculation_correct() {
        // capacity = 1.5 × D, supply = 1.0 × D  →  CR = 1.5 × D
        let mut e = engine_with_supply(D);
        e.tracked_capacity = 3 * D / 2; // 1.5 × D
        let cr = e.coverage_ratio().expect("supply > 0");
        assert_eq!(cr, 3 * D / 2, "CR = capacity/supply should be 1.5×D");
    }

    #[test]
    fn normal_state_when_cr_above_resume() {
        // Start with supply=D, set capacity to 2×D → CR = 2.0 > CR_resume(1.0).
        let mut e = engine_with_supply(D);
        e.record_capacity(2 * D);
        assert_eq!(e.minting_state, MintingState::Normal);
    }

    #[test]
    fn restricted_state_when_cr_in_hysteresis_band() {
        // CR = 0.90 × D: above CR_halt(0.75) but below CR_resume(1.00).
        let mut e = engine_with_supply(D); // supply = D
        e.record_capacity(900_000);        // capacity = 0.9 × D  →  CR = 0.9 × D
        assert_eq!(
            e.minting_state,
            MintingState::Restricted,
            "CR in [CR_halt, CR_resume) should be RESTRICTED"
        );
    }

    #[test]
    fn halted_state_when_cr_below_halt() {
        // CR = 0.50 × D: below CR_halt(0.75).
        let mut e = engine_with_supply(D);
        e.record_capacity(500_000); // 0.5 × D → CR = 0.5 × D
        assert_eq!(
            e.minting_state,
            MintingState::Halted,
            "CR below CR_halt should be HALTED"
        );
    }

    #[test]
    fn purchase_blocked_in_restricted_state() {
        let mut e = engine_with_supply(D);
        e.record_capacity(900_000); // → RESTRICTED
        assert_eq!(e.minting_state, MintingState::Restricted);

        let supply_before = e.total_supply;
        let (minted, _) = e.purchase_qrc(100 * D);
        assert_eq!(minted, 0, "purchase must be blocked in RESTRICTED state");
        assert_eq!(e.total_supply, supply_before, "total_supply must not change");
        assert_eq!(e.total_qcb_burned, 0, "QCB must not be burned");
    }

    #[test]
    fn purchase_blocked_in_halted_state() {
        let mut e = engine_with_supply(D);
        e.record_capacity(500_000); // → HALTED
        assert_eq!(e.minting_state, MintingState::Halted);

        let (minted, _) = e.purchase_qrc(100 * D);
        assert_eq!(minted, 0, "purchase must be blocked in HALTED state");
    }

    #[test]
    fn contribution_allowed_in_restricted_state() {
        let mut e = engine_with_supply(D);
        e.record_capacity(900_000); // → RESTRICTED
        assert_eq!(e.minting_state, MintingState::Restricted);

        let provider = [7u8; 32];
        let mut contributions = BTreeMap::new();
        contributions.insert(ResourceKind::Compute, D);
        // Providers should still earn even when purchase is suspended.
        // (Earning increases capacity indirectly and helps recover CR.)
        let earned = e.credit_provider_earning(&provider, &contributions);
        // Non-zero earnings confirm contribution path is open.
        assert!(earned > 0, "contribution must be allowed in RESTRICTED state; got {earned}");
    }

    #[test]
    fn contribution_blocked_in_halted_state() {
        let mut e = engine_with_supply(D);
        e.record_capacity(500_000); // → HALTED
        assert_eq!(e.minting_state, MintingState::Halted);

        let provider = [8u8; 32];
        let mut contributions = BTreeMap::new();
        contributions.insert(ResourceKind::Compute, D);
        let earned = e.credit_provider_earning(&provider, &contributions);
        assert_eq!(earned, 0, "contribution must be blocked in HALTED state");
    }

    #[test]
    fn hysteresis_prevents_oscillation() {
        // Start Normal; drop CR into hysteresis band → RESTRICTED.
        // A second record_capacity in the same band should stay RESTRICTED (not flip).
        let mut e = engine_with_supply(D);
        e.record_capacity(2 * D); // Normal (CR = 2.0)
        assert_eq!(e.minting_state, MintingState::Normal);

        e.record_capacity(900_000); // CR = 0.9 → RESTRICTED
        assert_eq!(e.minting_state, MintingState::Restricted);

        // Update capacity slightly within the band — must stay RESTRICTED.
        e.record_capacity(950_000); // CR = 0.95 — still below CR_resume
        assert_eq!(
            e.minting_state,
            MintingState::Restricted,
            "must stay RESTRICTED inside the hysteresis band"
        );
    }

    #[test]
    fn recovery_path_normal_to_restricted_to_halted_to_normal() {
        let mut e = engine_with_supply(D);

        // 1. Normal
        e.record_capacity(2 * D);
        assert_eq!(e.minting_state, MintingState::Normal);

        // 2. Decline → Restricted
        e.record_capacity(900_000);
        assert_eq!(e.minting_state, MintingState::Restricted);

        // 3. Further decline → Halted
        e.record_capacity(500_000);
        assert_eq!(e.minting_state, MintingState::Halted);

        // 4. Partial recovery → lands in Restricted (not Normal — hysteresis)
        e.record_capacity(900_000); // CR = 0.9 — in hysteresis band
        assert_eq!(e.minting_state, MintingState::Restricted,
            "recovery from HALTED should land in RESTRICTED, not NORMAL");

        // 5. Full recovery → Normal
        e.record_capacity(D); // CR = 1.0 == CR_resume → Normal
        assert_eq!(e.minting_state, MintingState::Normal);
    }

    #[test]
    fn normal_operation_purchase_and_contribution_both_open() {
        let mut e = engine(); // supply=0, trivially Normal
        // Mint some supply via purchase first (CR guard passes when supply=0).
        let (minted, _) = e.purchase_qrc(D);
        assert!(minted > 0, "purchase must succeed when Normal and supply=0");

        // Now set capacity well above outstanding → stays Normal.
        e.record_capacity(5 * e.total_supply);
        assert_eq!(e.minting_state, MintingState::Normal);

        let provider = [9u8; 32];
        let mut contributions = BTreeMap::new();
        contributions.insert(ResourceKind::Compute, D);
        let earned = e.credit_provider_earning(&provider, &contributions);
        assert!(earned > 0, "contribution must succeed when Normal");
    }
}
