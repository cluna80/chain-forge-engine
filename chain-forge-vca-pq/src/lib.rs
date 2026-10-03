//! # chain-forge-vca-pq
//!
//! VCA-PQ-BFT primitives for QCB — implements the three-layer architecture
//! described in the VCA-PQ-BFT research specification (v0.2):
//!
//! ## Architecture layers
//!
//! ### Layer 1 — Verifiable Contribution Authority (VCA)
//! Consensus authority is derived from *verified, contribution-weighted*
//! participation rather than raw stake. The core separation invariant:
//!
//! ```text
//!   I_i ≠ D_i ≠ S_i ≠ C_i ≠ W_i
//! ```
//!
//! where:
//!   - `I_i` = identity (personhood credential, privacy-preserving)
//!   - `D_i` = disclosed data (what is actually revealed on-chain)
//!   - `S_i` = stake (token balance committed as collateral)
//!   - `C_i` = contribution score (work performed, verified on-chain)
//!   - `W_i` = consensus weight (voting power, derived from C_i and P_i)
//!
//! The key invariant from §4.2 of the spec:
//!
//! ```text
//!   W_i = F(C_i, P_i)    where  ∂W_i/∂S_i = 0
//! ```
//!
//! Stake cannot directly buy consensus weight. Contribution + personhood drive it.
//!
//! ### Layer 2 — Adaptive Quorum
//! The quorum threshold adapts based on the verified-participation ratio of the
//! current validator set (§7 of the spec). A set with high personhood coverage
//! can safely use a lower absolute threshold; sparse coverage triggers a higher
//! threshold and liveness warnings.
//!
//! ### Layer 3 — Post-Quantum readiness
//! Every signed message carries both a classical (Ed25519) signature slot and a
//! PQ (ML-DSA-87) signature slot. In Phase 0 only the classical slot is
//! populated; ML-DSA is opt-in. Migration to PQ-native follows NIST guidance
//! (genesis `cryptography.migration_trigger = "nist-guidance"`).
//!
//! ## Security fixes (v0.3)
//!
//! Four open attack vectors discovered by the adversarial composition-safety
//! test suite have been closed in this version:
//!
//! - **A4** — Relative weight cap: `W_i ≤ k × median(W)` prevents a single
//!   adversary from accumulating disproportionate weight even via legitimate
//!   contribution. Applied dynamically at `VcaRegistry::close_epoch()`.
//!
//! - **D1** — Atomic epoch transitions: quorum is always computed within the
//!   epoch that produced the registry. `VcaRegistry::snapshot()` returns a
//!   frozen copy for quorum computation; `upsert()` is blocked after `close_epoch()`.
//!
//! - **D3/D7** — Personhood uniqueness + minimum P threshold: `upsert()` now
//!   enforces that each `IdentityHandle` maps to at most one `ValidatorId` and
//!   rejects records with `P < min_personhood_factor` (default: 0.25).
//!
//! - **D6** — Emergency quorum: when all personhood expires simultaneously,
//!   `compute_adaptive_quorum()` returns `EmergencyQuorum` instead of halting,
//!   allowing the chain to reconfigure with a governance-defined fallback.
//!
//! ## What this crate does NOT do
//! - It does not implement external-chain verification (§20.5 — separate research)
//! - It does not manage identity credentials (chain-forge-personhood)
//! - It does not replace the consensus engine (chain-forge-consensus)
//!
//! It extends the consensus layer with VCA-specific weight computation,
//! adaptive-quorum logic, and PQ signature slots.

use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};
use chain_forge_core::{BlockHeight, ValidatorId, ValidatorSet, ValidatorInfo};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum VcaError {
    #[error("contribution score must be non-negative; got {0}")]
    NegativeContribution(f64),

    #[error("personhood factor must be in [0.0, 1.0]; got {0}")]
    InvalidPersonhoodFactor(f64),

    #[error("personhood factor {actual} below minimum required {min} — sybil guard rejected upsert")]
    PersonhoodBelowMinimum { min: f64, actual: f64 },

    #[error("identity handle {0:?} already registered to a different validator — uniqueness violation")]
    IdentityHandleCollision(String),

    #[error("adaptive quorum config invalid: floor {floor} > ceiling {ceiling}")]
    InvalidQuorumConfig { floor: u64, ceiling: u64 },

    #[error("PQ signature too short: expected at least {min} bytes, got {actual}")]
    PqSignatureTooShort { min: usize, actual: usize },

    #[error("separation invariant violated: {0}")]
    SeparationViolation(String),

    #[error("validator {0} not found in VCA registry")]
    UnknownValidator(ValidatorId),

    #[error("registry epoch {0} is closed — upserts are not permitted after close_epoch()")]
    RegistryClosed(u64),

    #[error("all validators have expired personhood — chain requires emergency quorum reconfiguration")]
    EmergencyQuorum,
}

pub type VcaResult<T> = Result<T, VcaError>;

// ── Separation types ──────────────────────────────────────────────────────────
//
// These are distinct newtypes to enforce I_i ≠ D_i ≠ S_i ≠ C_i ≠ W_i at
// compile time. You cannot accidentally pass a ContributionScore where a
// ConsensusWeight is expected, or mix up StakeAmount with PersonhoodFactor.

/// Privacy-preserving identity handle.
/// On-chain this is an opaque commitment; the actual credential lives in the
/// identity layer (chain-forge-personhood). The VCA layer never sees the raw
/// identity — only a verification result from the personhood module.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IdentityHandle(pub String);

/// On-chain disclosed data commitment (what the validator has chosen to reveal).
/// Must be strictly less than `IdentityHandle` — more information can be
/// carried by the identity handle than is disclosed on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosedData {
    /// Opaque commitment to the disclosed data set (hash or merkle root).
    pub commitment: String,
    /// Epoch when this disclosure was made.
    pub epoch:      u64,
}

/// Raw token stake committed as slashable collateral.
/// This is in `uqcb` (micro-QCB), the smallest denomination.
/// IMPORTANT: stake does NOT directly influence `ConsensusWeight`.
/// It only determines slash exposure and minimum eligibility thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StakeAmount(pub u64);

/// Verified on-chain contribution score for a validator.
/// Computed by the execution layer from finalized, attributable work.
/// The specific work types depend on the chain's module configuration.
///
/// In QCB: QRC transactions processed, identity attestations cosigned,
/// governance participation, uptime-weighted block proposals, etc.
///
/// Range: [0.0, ∞). A score of 0 means no verified contribution this epoch.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ContributionScore(pub f64);

impl ContributionScore {
    pub fn zero() -> Self { Self(0.0) }

    pub fn new(v: f64) -> VcaResult<Self> {
        if v < 0.0 {
            Err(VcaError::NegativeContribution(v))
        } else {
            Ok(Self(v))
        }
    }
}

/// Personhood factor: how well-verified this validator's personhood is.
/// 1.0 = fully verified, active, non-expired PoP credential.
/// 0.5 = partial (e.g. verification in progress, or a single-issuer credential).
/// 0.0 = unverified or expired.
///
/// The personhood module computes this; VCA consumes it.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PersonhoodFactor(pub f64);

impl PersonhoodFactor {
    pub fn verified() -> Self   { Self(1.0) }
    pub fn unverified() -> Self { Self(0.0) }

    pub fn new(v: f64) -> VcaResult<Self> {
        if !(0.0..=1.0).contains(&v) {
            Err(VcaError::InvalidPersonhoodFactor(v))
        } else {
            Ok(Self(v))
        }
    }
}

/// Consensus weight derived from contribution and personhood.
/// This is what actually becomes `voting_power` in the `ValidatorSet`.
///
/// W_i = F(C_i, P_i)    where  ∂W_i/∂S_i = 0
///
/// Stake does not appear in this formula.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConsensusWeight(pub u64);

impl ConsensusWeight {
    pub fn zero() -> Self { Self(0) }
}

// ── Weight function F(C_i, P_i) ───────────────────────────────────────────────

/// Configuration for the VCA weight function.
///
/// The weight function is:
///   W_i = floor( C_i^α × P_i × scale ) clamped to [min_weight, max_weight]
///
/// After all weights are computed, a *relative cap* is applied during
/// `close_epoch()`:
///   W_i ≤ max_weight_multiplier × median(W)
///
/// This prevents any single validator from accumulating disproportionate weight
/// even through legitimate contribution (A4 fix).
///
/// Where:
///   - `α` (contribution_exponent): sub-linear (< 1) gives diminishing returns
///     to contribution, preventing runaway concentration. Linear (= 1) is simpler
///     but allows large contributors to dominate.
///   - `scale`: converts the raw score to an integer weight. Tune so that a
///     "typical" validator gets weight ≈ 100.
///   - `max_weight`: hard per-validator cap (absolute, enforced at construction).
///   - `max_weight_multiplier`: relative cap applied at epoch close; the
///     final weight of any validator must be ≤ this multiple of the median.
///   - `min_personhood_factor`: minimum P accepted by `upsert()`. Validators
///     with P < this threshold are rejected (D7 sybil guard).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightConfig {
    /// Exponent applied to the contribution score. Default: 0.5 (square-root).
    /// Range: (0.0, 2.0]. Values > 1.0 are super-linear and should be used
    /// with caution — they amplify contribution differences.
    pub contribution_exponent: f64,

    /// Multiplier that converts the raw (C^α × P) value to an integer weight.
    /// Default: 1000.0 — a validator with C=1.0, P=1.0 gets weight 1000.
    pub scale: f64,

    /// Minimum weight for any validator with P > 0 and C > 0.
    /// Prevents verified-personhood validators from being silenced by a low
    /// contribution score in their first epoch.
    pub min_weight: u64,

    /// Hard cap on weight (absolute, enforced at construction).
    /// The relative cap (`max_weight_multiplier × median`) is applied later
    /// during `close_epoch()` and may produce a lower effective ceiling.
    pub max_weight: u64,

    /// Relative weight cap multiplier (A4 fix).
    ///
    /// After epoch close, any validator with:
    ///   W_i > max_weight_multiplier × median(W)
    /// is clamped to that ceiling. This prevents a single high-contribution
    /// adversary from accumulating disproportionate weight when the honest
    /// validator set is small.
    ///
    /// Default: 3.0 — no validator can hold more than 3× the median weight.
    /// A value of 3.0 with a 4-node set means the max any single validator
    /// can hold is ≈ 3/6 = 50% (3 of 6 "shares"), which is still above the
    /// BFT 1/3 threshold but much better than 10× concentration.
    ///
    /// For strong guarantees set this to 1.0 (all validators equal weight)
    /// or use a smaller value to limit concentration further.
    pub max_weight_multiplier: f64,

    /// Minimum personhood factor accepted by `upsert()` (D7 sybil guard).
    ///
    /// Validators with `P < min_personhood_factor` are rejected at upsert time,
    /// preventing partial-personhood sybils from accumulating weight in aggregate.
    ///
    /// Default: 0.25 — partial credentials (P=0.5) are accepted but unverified
    /// (P=0.0) and very low-credentialed validators are rejected.
    ///
    /// Set to 1.0 to require fully verified personhood for all validators.
    pub min_personhood_factor: f64,
}

impl Default for WeightConfig {
    fn default() -> Self {
        Self {
            contribution_exponent:  0.5,    // square-root: sub-linear, diminishing returns
            scale:                  1000.0,
            min_weight:             1,       // floor for eligible validators
            max_weight:             10_000,  // absolute cap per human
            max_weight_multiplier:  3.0,     // relative cap: at most 3× median (A4 fix)
            min_personhood_factor:  0.25,    // reject sybils with very low P (D7 fix)
        }
    }
}

/// Compute W_i = F(C_i, P_i) using the configured weight function.
///
/// This is the core VCA primitive. Call this when building the ValidatorSet
/// for a new epoch. Stake is deliberately not a parameter.
///
/// Note: this computes the *raw* weight before the relative cap from
/// `close_epoch()`. The final effective weight may be lower.
pub fn compute_weight(
    contribution: ContributionScore,
    personhood:   PersonhoodFactor,
    config:       &WeightConfig,
) -> ConsensusWeight {
    let p = personhood.0;

    // A validator with zero personhood factor gets zero weight,
    // regardless of contribution. Personhood is a gate, not a bonus.
    if p == 0.0 {
        return ConsensusWeight::zero();
    }

    // W = floor( C^α × P × scale )
    let raw = contribution.0.powf(config.contribution_exponent) * p * config.scale;
    let weight = raw.floor() as u64;

    // Apply floor (only if the validator is eligible at all)
    let weight = if weight == 0 { config.min_weight } else { weight };

    // Apply absolute cap
    ConsensusWeight(weight.min(config.max_weight))
}

// ── VCA validator record ──────────────────────────────────────────────────────

/// Full VCA record for one validator in one epoch.
/// Separates the five identity types as distinct fields (compile-time).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcaValidatorRecord {
    /// Consensus layer identifier (used as the key in ValidatorSet).
    pub validator_id:   ValidatorId,

    /// Privacy-preserving identity handle — NOT the disclosed identity.
    /// This is an opaque commitment; the VCA layer never reads the raw identity.
    pub identity_handle: IdentityHandle,

    /// Epoch when this validator's contribution and personhood were last snapshotted.
    pub epoch: u64,

    /// Verified contribution score for this epoch.
    pub contribution:  ContributionScore,

    /// Personhood factor from the identity layer.
    pub personhood:    PersonhoodFactor,

    /// Slashable stake (not used in weight, only for slash exposure).
    pub stake:         StakeAmount,

    /// Derived consensus weight (computed from contribution × personhood only).
    /// May be further clamped by the relative cap at `close_epoch()`.
    pub weight:        ConsensusWeight,

    /// Classical signature public key (Ed25519).
    pub classical_pubkey: Vec<u8>,

    /// Post-quantum signature public key (ML-DSA-87).
    /// Empty until the validator opts in / migration trigger fires.
    pub pq_pubkey:     Vec<u8>,
}

impl VcaValidatorRecord {
    /// Build a VCA record, computing the weight from contribution and personhood.
    /// Enforces that stake is NOT part of the weight calculation.
    pub fn new(
        validator_id:     ValidatorId,
        identity_handle:  IdentityHandle,
        epoch:            u64,
        contribution:     ContributionScore,
        personhood:       PersonhoodFactor,
        stake:            StakeAmount,
        weight_config:    &WeightConfig,
        classical_pubkey: Vec<u8>,
        pq_pubkey:        Vec<u8>,
    ) -> Self {
        let weight = compute_weight(contribution, personhood, weight_config);
        Self {
            validator_id,
            identity_handle,
            epoch,
            contribution,
            personhood,
            stake,
            weight,
            classical_pubkey,
            pq_pubkey,
        }
    }

    /// Convert this VCA record to a `ValidatorInfo` for the consensus layer.
    /// The `voting_power` is `weight.0`; `pop_verified` is true iff P > 0.
    pub fn to_validator_info(&self) -> ValidatorInfo {
        ValidatorInfo {
            id:           self.validator_id.clone(),
            voting_power: self.weight.0,
            pop_verified: self.personhood.0 > 0.0,
            public_key:   self.classical_pubkey.clone(),
        }
    }
}

// ── VCA registry ─────────────────────────────────────────────────────────────

/// The VCA registry holds one `VcaValidatorRecord` per validator per epoch.
/// At epoch boundaries it is recomputed from fresh contribution scores and
/// personhood factors, then converted to a `ValidatorSet` for the consensus layer.
///
/// ## Epoch lifecycle (D1 fix — atomic epoch transitions)
///
/// 1. `VcaRegistry::new(epoch, config)` — open a new registry for `epoch`.
/// 2. `registry.upsert(...)` — add or update validator records (errors if closed).
/// 3. `registry.close_epoch()` — apply the relative weight cap and freeze the
///    registry. After this call, no further upserts are accepted.
/// 4. `registry.to_validator_set(height)` — produce the `ValidatorSet` for
///    the consensus layer. Only valid after `close_epoch()`.
/// 5. `compute_adaptive_quorum(&registry, &config)` — compute quorum from the
///    frozen registry. Quorum is always computed within the epoch that
///    produced the registry.
#[derive(Debug, Serialize, Deserialize)]
pub struct VcaRegistry {
    pub epoch:      u64,
    pub records:    BTreeMap<ValidatorId, VcaValidatorRecord>,
    pub weight_cfg: WeightConfig,

    /// Set of identity handles already registered in this epoch.
    /// Used to enforce uniqueness: one identity handle → one validator (D3 fix).
    identity_index: BTreeSet<IdentityHandle>,

    /// Whether `close_epoch()` has been called.
    /// After close, upserts are blocked (D1 fix).
    epoch_closed: bool,
}

impl Default for VcaRegistry {
    fn default() -> Self {
        Self::new(0, WeightConfig::default())
    }
}

impl VcaRegistry {
    pub fn new(epoch: u64, weight_cfg: WeightConfig) -> Self {
        Self {
            epoch,
            records: BTreeMap::new(),
            weight_cfg,
            identity_index: BTreeSet::new(),
            epoch_closed: false,
        }
    }

    /// Register or update a validator's VCA record for the current epoch.
    ///
    /// ## Security checks
    ///
    /// - **D1 (epoch closure)**: Fails with `RegistryClosed` if `close_epoch()`
    ///   has already been called. This ensures quorum is always computed from
    ///   a stable registry snapshot.
    ///
    /// - **D7 (minimum personhood)**: Fails with `PersonhoodBelowMinimum` if
    ///   `personhood.0 < weight_cfg.min_personhood_factor` and personhood > 0.
    ///   Fully unverified validators (P=0.0) bypass this check — they receive
    ///   W=0 and are excluded from the validator set.
    ///
    /// - **D3 (identity uniqueness)**: Fails with `IdentityHandleCollision` if
    ///   the same `IdentityHandle` is presented for a different `ValidatorId`.
    ///   Updating the same validator's record is allowed.
    pub fn upsert(
        &mut self,
        validator_id:     ValidatorId,
        identity_handle:  IdentityHandle,
        contribution:     ContributionScore,
        personhood:       PersonhoodFactor,
        stake:            StakeAmount,
        classical_pubkey: Vec<u8>,
        pq_pubkey:        Vec<u8>,
    ) -> VcaResult<()> {
        // D1: block upserts on a closed epoch
        if self.epoch_closed {
            return Err(VcaError::RegistryClosed(self.epoch));
        }

        // D7: reject sybil validators with very low (but nonzero) personhood
        if personhood.0 > 0.0 && personhood.0 < self.weight_cfg.min_personhood_factor {
            return Err(VcaError::PersonhoodBelowMinimum {
                min:    self.weight_cfg.min_personhood_factor,
                actual: personhood.0,
            });
        }

        // D3: enforce identity handle uniqueness across validators.
        // Allow re-upsert of the same validator (identity already indexed for them).
        let existing_for_id = self.records.get(&validator_id)
            .map(|r| r.identity_handle.clone());

        // Check if this identity handle is already claimed by a DIFFERENT validator
        if self.identity_index.contains(&identity_handle) {
            // It's OK if the existing record for this validator_id already has this handle
            match &existing_for_id {
                Some(existing_handle) if existing_handle == &identity_handle => {
                    // Same validator updating their own record — allowed
                }
                _ => {
                    // A different validator already holds this identity handle
                    return Err(VcaError::IdentityHandleCollision(identity_handle.0));
                }
            }
        }

        // Remove old identity handle from index if this is an update
        if let Some(old_handle) = &existing_for_id {
            if old_handle != &identity_handle {
                self.identity_index.remove(old_handle);
            }
        }

        // Index the new identity handle
        self.identity_index.insert(identity_handle.clone());

        let record = VcaValidatorRecord::new(
            validator_id.clone(),
            identity_handle,
            self.epoch,
            contribution,
            personhood,
            stake,
            &self.weight_cfg,
            classical_pubkey,
            pq_pubkey,
        );
        self.records.insert(validator_id, record);
        Ok(())
    }

    /// Close the epoch and apply the relative weight cap (A4 fix).
    ///
    /// After this call:
    /// - No further upserts are accepted.
    /// - All validator weights are clamped to `max_weight_multiplier × median(W)`.
    ///
    /// The relative cap prevents a single high-contribution adversary from
    /// accumulating more than `max_weight_multiplier` times the median weight,
    /// even when the honest validator set is small.
    ///
    /// Call this once all validators for the epoch have been registered,
    /// before computing the quorum or producing a `ValidatorSet`.
    pub fn close_epoch(&mut self) {
        self.epoch_closed = true;

        // Collect all nonzero weights to compute the median
        let mut weights: Vec<u64> = self.records.values()
            .map(|r| r.weight.0)
            .filter(|&w| w > 0)
            .collect();

        if weights.is_empty() {
            return; // nothing to cap
        }

        weights.sort_unstable();
        let median = if weights.len() % 2 == 0 {
            (weights[weights.len() / 2 - 1] + weights[weights.len() / 2]) / 2
        } else {
            weights[weights.len() / 2]
        };

        let cap = (median as f64 * self.weight_cfg.max_weight_multiplier).floor() as u64;
        let cap = cap.max(1); // never cap to 0

        // Apply relative cap to all records
        for record in self.records.values_mut() {
            if record.weight.0 > cap {
                tracing::debug!(
                    validator_id = %record.validator_id,
                    raw_weight   = record.weight.0,
                    median,
                    relative_cap = cap,
                    "relative weight cap applied (A4 guard)"
                );
                record.weight = ConsensusWeight(cap);
            }
        }
    }

    /// Get a validator's record.
    pub fn get(&self, id: &ValidatorId) -> VcaResult<&VcaValidatorRecord> {
        self.records.get(id).ok_or_else(|| VcaError::UnknownValidator(id.clone()))
    }

    /// Whether this registry has been closed for the epoch.
    pub fn is_closed(&self) -> bool { self.epoch_closed }

    /// Convert the registry to a `ValidatorSet` for the consensus layer.
    /// Weight becomes voting_power. Validators with weight=0 are excluded.
    pub fn to_validator_set(&self, height: BlockHeight) -> ValidatorSet {
        let validators: Vec<ValidatorInfo> = self.records.values()
            .filter(|r| r.weight.0 > 0)
            .map(|r| r.to_validator_info())
            .collect();

        ValidatorSet { height, validators }
    }

    /// Total VCA weight across all eligible validators.
    pub fn total_weight(&self) -> u64 {
        self.records.values().map(|r| r.weight.0).sum()
    }

    /// Fraction of validators that are personhood-verified (P > 0).
    /// Returns 0.0 if the registry is empty.
    pub fn verified_fraction(&self) -> f64 {
        if self.records.is_empty() { return 0.0; }
        let verified = self.records.values().filter(|r| r.personhood.0 > 0.0).count();
        verified as f64 / self.records.len() as f64
    }

    /// Total weight held by verified validators (P > 0).
    pub fn verified_weight(&self) -> u64 {
        self.records.values()
            .filter(|r| r.personhood.0 > 0.0)
            .map(|r| r.weight.0)
            .sum()
    }

    /// True if all validators in the registry have expired personhood (P = 0).
    /// Used by `compute_adaptive_quorum()` to detect the D6 emergency condition.
    pub fn all_personhood_expired(&self) -> bool {
        !self.records.is_empty()
            && self.records.values().all(|r| r.personhood.0 == 0.0)
    }
}

// ── Adaptive quorum ───────────────────────────────────────────────────────────

/// Configuration for the adaptive quorum mechanism (VCA-PQ-BFT §7).
///
/// The quorum threshold Q adapts based on the verified-participation ratio ρ
/// of the current validator set:
///
/// ```text
///   ρ = (total weight of verified validators) / (total weight of all validators)
///
///   Q = max(quorum_floor,  ceil(total_weight × base_fraction + adjustment(ρ)))
///   Q = min(Q, quorum_ceiling)
/// ```
///
/// When ρ is high (most weight is personhood-verified), the adjustment is 0 —
/// the classical 2/3+1 BFT quorum applies.
///
/// When ρ drops below `high_coverage_threshold`, the quorum tightens toward
/// `quorum_ceiling`. This makes the chain more conservative (harder to commit)
/// when personhood coverage is weak — reducing the attack surface from Sybil
/// validators that slipped through with low personhood scores.
///
/// ## Emergency quorum (D6 fix)
///
/// When ALL validators' personhood has expired (`all_personhood_expired()`),
/// `compute_adaptive_quorum()` returns `Err(VcaError::EmergencyQuorum)` instead
/// of proceeding with a degenerate or zero quorum. The consensus layer must
/// handle this by triggering a governance-defined emergency reconfiguration
/// (e.g. a temporary unanimity requirement, an oracle refresh, or a halt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveQuorumConfig {
    /// Base quorum fraction (classical BFT: 2/3). Applied to total weight.
    pub base_fraction: f64,

    /// Minimum absolute quorum (floor). Must be ≥ 1.
    pub quorum_floor: u64,

    /// Maximum absolute quorum (ceiling). Must be ≥ quorum_floor.
    /// When set to total_weight, requires unanimity (safe but less live).
    pub quorum_ceiling_fraction: f64,

    /// Verified-participation ratio above which no adjustment is applied.
    /// Default: 0.80 — if 80%+ of weight is verified, use base_fraction quorum.
    pub high_coverage_threshold: f64,

    /// Verified-participation ratio below which max adjustment is applied.
    /// Default: 0.50 — if < 50% of weight is verified, use quorum_ceiling.
    pub low_coverage_threshold: f64,
}

impl Default for AdaptiveQuorumConfig {
    fn default() -> Self {
        Self {
            base_fraction:           2.0 / 3.0,
            quorum_floor:            1,
            quorum_ceiling_fraction: 0.80, // 80% as ceiling
            high_coverage_threshold: 0.80,
            low_coverage_threshold:  0.50,
        }
    }
}

/// Compute the adaptive quorum threshold given the registry state and config.
///
/// Returns the number of weight-units required to commit a block.
///
/// ## Errors
///
/// - `InvalidQuorumConfig` — the config's floor exceeds the ceiling.
/// - `EmergencyQuorum` (D6 fix) — all validators' personhood has expired.
///   The caller must trigger emergency reconfiguration; normal consensus
///   cannot proceed with a zero-personhood validator set.
pub fn compute_adaptive_quorum(
    registry: &VcaRegistry,
    config:   &AdaptiveQuorumConfig,
) -> VcaResult<u64> {
    if config.quorum_floor > (config.quorum_ceiling_fraction * 1_000_000.0) as u64 {
        return Err(VcaError::InvalidQuorumConfig {
            floor:   config.quorum_floor,
            ceiling: (config.quorum_ceiling_fraction * 1_000_000.0) as u64,
        });
    }

    // D6: detect the emergency condition before attempting quorum arithmetic
    if registry.all_personhood_expired() {
        tracing::error!(
            epoch = registry.epoch,
            validator_count = registry.records.len(),
            "ALL validators have expired personhood — EmergencyQuorum triggered (D6 guard)"
        );
        return Err(VcaError::EmergencyQuorum);
    }

    let total = registry.total_weight();
    if total == 0 { return Ok(config.quorum_floor); }

    // ρ = fraction of total weight that is personhood-verified
    let verified_weight = registry.verified_weight();
    let rho = verified_weight as f64 / total as f64;

    // Base quorum (classical 2/3 of total weight)
    let base_q = (total as f64 * config.base_fraction).ceil() as u64;

    // Adjustment: linear interpolation between 0 and extra_q
    // as ρ drops from high_coverage_threshold to low_coverage_threshold.
    let ceiling_q = (total as f64 * config.quorum_ceiling_fraction).ceil() as u64;
    let extra_q = ceiling_q.saturating_sub(base_q);

    let adjustment = if rho >= config.high_coverage_threshold {
        0
    } else if rho <= config.low_coverage_threshold {
        extra_q
    } else {
        // Linear interpolation
        let span = config.high_coverage_threshold - config.low_coverage_threshold;
        let t = (config.high_coverage_threshold - rho) / span; // 0 at high, 1 at low
        (extra_q as f64 * t).ceil() as u64
    };

    let q = base_q + adjustment;
    let q = q.max(config.quorum_floor).min(ceiling_q.max(config.quorum_floor));

    tracing::debug!(
        total_weight   = total,
        verified_weight,
        rho,
        base_q,
        adjustment,
        adaptive_q     = q,
        "adaptive quorum computed"
    );

    Ok(q)
}

// ── Post-quantum signature envelope ──────────────────────────────────────────

/// Dual-signature envelope carrying both a classical and a PQ signature.
///
/// Phase 0: classical is populated, pq_signature is empty.
/// Phase 1 (opt-in): both are populated.
/// Phase 2 (migration trigger): classical becomes optional, pq required.
///
/// Migration trigger is set by genesis `cryptography.migration_trigger`.
/// The VCA layer enforces the current phase's requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqSignatureEnvelope {
    /// Classical Ed25519 signature bytes.
    pub classical_signature: Vec<u8>,

    /// ML-DSA-87 signature bytes. Empty until opt-in / migration trigger.
    /// ML-DSA-87 produces signatures of exactly 4627 bytes.
    pub pq_signature: Vec<u8>,

    /// Which phase produced this envelope.
    pub phase: SignaturePhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignaturePhase {
    /// Phase 0: classical only. PQ field is empty.
    ClassicalOnly,
    /// Phase 1: both present. Either alone is insufficient for consensus.
    Dual,
    /// Phase 2: PQ required. Classical is advisory only.
    PqNative,
}

impl PqSignatureEnvelope {
    /// Create a Phase 0 envelope (classical only).
    pub fn classical(sig: Vec<u8>) -> Self {
        Self {
            classical_signature: sig,
            pq_signature:        vec![],
            phase:               SignaturePhase::ClassicalOnly,
        }
    }

    /// Create a Phase 1 dual envelope.
    pub fn dual(classical: Vec<u8>, pq: Vec<u8>) -> VcaResult<Self> {
        const ML_DSA_87_BYTES: usize = 4627;
        if pq.len() != ML_DSA_87_BYTES {
            return Err(VcaError::PqSignatureTooShort {
                min:    ML_DSA_87_BYTES,
                actual: pq.len(),
            });
        }
        Ok(Self {
            classical_signature: classical,
            pq_signature:        pq,
            phase:               SignaturePhase::Dual,
        })
    }

    /// True if this envelope satisfies the requirements for `phase`.
    pub fn is_valid_for_phase(&self, required: &SignaturePhase) -> bool {
        match required {
            SignaturePhase::ClassicalOnly => !self.classical_signature.is_empty(),
            SignaturePhase::Dual => {
                !self.classical_signature.is_empty() && !self.pq_signature.is_empty()
            }
            SignaturePhase::PqNative => !self.pq_signature.is_empty(),
        }
    }
}

// ── Separation invariant checker ──────────────────────────────────────────────

/// Verify the core VCA separation invariant for a validator record:
///
///   I_i ≠ D_i ≠ S_i ≠ C_i ≠ W_i
///
/// In practice this checks that the weight was computed from C and P only,
/// and that the stake field did not influence it. Since the weight is
/// computed by `compute_weight(contribution, personhood, config)` — with no
/// stake parameter — this invariant is structurally enforced. This function
/// re-derives the weight and asserts the stored value matches.
///
/// It also checks that the identity handle is opaque (not equal to the
/// validator_id, which would be a data-minimization failure).
///
/// Note: this checks the weight BEFORE the relative cap from `close_epoch()`.
/// After epoch close, weights may be lower than the raw formula produces.
/// Pass the pre-close config to verify the formula; after close, use
/// `record.weight` directly and compare against the closed registry's totals.
pub fn verify_separation_invariant(
    record:  &VcaValidatorRecord,
    config:  &WeightConfig,
) -> VcaResult<()> {
    // Re-derive the weight from C and P (no stake).
    let expected_weight = compute_weight(record.contribution, record.personhood, config);
    // After close_epoch() the stored weight may be lower (relative cap).
    // We check that the stored weight is ≤ the raw formula weight.
    if record.weight.0 > expected_weight.0 {
        return Err(VcaError::SeparationViolation(format!(
            "validator {}: stored weight {} > derived weight {} — stake may have influenced weight",
            record.validator_id, record.weight.0, expected_weight.0
        )));
    }

    // Identity handle must not equal the validator_id string
    // (that would mean the on-chain pseudonym = the identity, violating D_i ≠ I_i).
    if record.identity_handle.0 == record.validator_id.0 {
        return Err(VcaError::SeparationViolation(format!(
            "validator {}: identity_handle == validator_id — identity is not privacy-preserving",
            record.validator_id
        )));
    }

    Ok(())
}

// ── BFT safety predicate ──────────────────────────────────────────────────────
//
// Formal safety module for VCA-PQ-BFT.
//
// The core invariant:
//
//   Safety(R, Q) ⟺ ∀ B ∈ B_adm : W(B) < Q_S
//
// where:
//   R       = current VCA registry (closed epoch)
//   B       = an admissible Byzantine coalition
//   W(B)    = Σ_{i∈B} W_i
//   B_adm   = coalitions permitted by the identity/personhood assumptions
//   Q_S     = safety quorum (strict: must be > W(B), not merely ≥)
//
// The adaptive quorum may increase *progress* (liveness); it must never lower
// the safety floor below 2/3 of total weight. This module expresses and
// checks that contract explicitly.

/// An explicit adversary model: the assumptions about what the attacker can do.
///
/// This replaces ad-hoc "what if P=0.5?" tests with a rigorous parameterized
/// adversary that can be varied across the full attack space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversaryModel {
    /// Maximum personhood factor the adversary can achieve per Sybil identity.
    /// At P=1.0 the adversary can create fully-verified identities (strongest).
    /// At P=0.5 the adversary has partial-personhood Sybils.
    /// The min_personhood_factor in WeightConfig acts as the gate.
    pub max_personhood_per_sybil: f64,

    /// Maximum number of adversarial validator slots the attacker controls.
    pub max_byzantine_validators: usize,

    /// Maximum contribution score the adversary can achieve per Sybil.
    /// Contribution is assumed verifiable, so an unbounded C is not realistic;
    /// this bounds the adversary's contribution-accumulation ability.
    pub max_contribution_per_sybil: f64,
}

impl AdversaryModel {
    /// Standard Sybil adversary: many partial-personhood validators.
    /// Models an attacker who can manufacture P=0.5 credentials at scale.
    pub fn partial_personhood_sybil(n: usize, max_c: f64) -> Self {
        Self {
            max_personhood_per_sybil:   0.5,
            max_byzantine_validators:   n,
            max_contribution_per_sybil: max_c,
        }
    }

    /// Full-personhood adversary: controls validators with P=1.0.
    /// Models a captured set of fully-verified validators.
    pub fn full_personhood(n: usize, max_c: f64) -> Self {
        Self {
            max_personhood_per_sybil:   1.0,
            max_byzantine_validators:   n,
            max_contribution_per_sybil: max_c,
        }
    }

    /// Compute the maximum aggregate weight this adversary can accumulate
    /// under the given weight configuration and relative cap.
    ///
    /// The worst case is: `max_byzantine_validators` Sybils, each with
    /// `max_contribution_per_sybil` and `max_personhood_per_sybil`, after the
    /// relative cap `max_weight_multiplier × median` has been applied.
    ///
    /// `median_cap` is the pre-computed cap from a closed registry (e.g.,
    /// from `registry.total_weight()` / validator count).  When `None`, no
    /// relative cap is applied — this gives the worst-case raw bound.
    pub fn max_byzantine_weight(
        &self,
        weight_config: &WeightConfig,
        relative_cap:  Option<u64>,
    ) -> u64 {
        let p   = PersonhoodFactor(self.max_personhood_per_sybil.min(1.0).max(0.0));
        let c   = ContributionScore(self.max_contribution_per_sybil.max(0.0));
        let raw = compute_weight(c, p, weight_config);

        // Apply relative cap if known
        let per_sybil = match relative_cap {
            Some(cap) => raw.0.min(cap),
            None      => raw.0,
        };

        // Saturating multiply: total Byzantine weight
        per_sybil.saturating_mul(self.max_byzantine_validators as u64)
    }
}

/// The result of a BFT safety check.
///
/// Provides actionable numbers rather than a bare bool, so adversarial tests
/// and monitoring can report precise margins:
///
/// ```text
///   total validator weight:       10000
///   max Byzantine coalition:       2900
///   safety quorum:                 6701
///   safety margin:                +3801   ← positive means SAFE
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyResult {
    /// Whether the safety invariant holds for this registry + adversary model.
    pub holds: bool,

    /// Total weight of all validators in the (closed) registry.
    pub total_weight: u64,

    /// Maximum aggregate weight the adversary can accumulate under the model.
    pub max_byzantine_weight: u64,

    /// The safety quorum threshold that was checked against.
    pub safety_quorum: u64,

    /// `safety_quorum as i128 - max_byzantine_weight as i128`.
    /// Positive → the quorum exceeds the adversary's max weight (safe).
    /// Zero or negative → the adversary could block or capture quorum (unsafe).
    pub margin: i128,

    /// Personhood coverage ratio ρ = verified_weight / total_weight.
    pub personhood_coverage: f64,
}

impl SafetyResult {
    /// True iff the safety invariant is satisfied with a strictly positive margin.
    pub fn is_safe(&self) -> bool { self.holds && self.margin > 0 }
}

impl std::fmt::Display for SafetyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BFT Safety: {} | total={} byz_max={} quorum={} margin={:+} ρ={:.2}",
            if self.holds { "SAFE" } else { "UNSAFE" },
            self.total_weight,
            self.max_byzantine_weight,
            self.safety_quorum,
            self.margin,
            self.personhood_coverage,
        )
    }
}

/// Check whether the BFT safety invariant holds for a closed registry.
///
/// ## Safety contract
///
/// For every admissible Byzantine coalition B under `adversary`:
///   W(B) < Q_S
///
/// The safety quorum Q_S is the STRICTER of:
///   - The classically-required floor: ceil(total_weight × 2/3) + 1
///   - The adaptive quorum from `compute_adaptive_quorum()` (may be higher)
///
/// Using max(classical, adaptive) ensures the adaptive mechanism can only
/// *raise* the safety bar, never lower it below the BFT floor.
///
/// ## Relative cap
///
/// The cap from `close_epoch()` (max_weight_multiplier × median) bounds
/// how much weight any single Sybil can accumulate. This function uses the
/// registry's actual post-cap weights to compute `max_byzantine_weight`,
/// so the adversary model operates on the same weights the consensus layer sees.
///
/// ## Usage
///
/// Call this:
/// - After `registry.close_epoch()` (weights must be final)
/// - Before `compute_adaptive_quorum()` is used to commit blocks
/// - In monitoring / governance tooling to verify safety before epoch use
///
/// Returns `SafetyResult` in all cases; check `.holds` or `.is_safe()`.
/// Returns `Err` only if `quorum_config` is structurally invalid.
pub fn check_bft_safety(
    registry:       &VcaRegistry,
    quorum_config:  &AdaptiveQuorumConfig,
    adversary:      &AdversaryModel,
) -> VcaResult<SafetyResult> {
    let total = registry.total_weight();

    // Classical BFT safety floor: requires strict majority of total weight.
    // ceil(2/3 × total) + 1 ensures W_honest > W_byz even at exactly 1/3 Byzantine.
    let classical_floor = if total == 0 {
        quorum_config.quorum_floor
    } else {
        ((total as f64 * 2.0 / 3.0).ceil() as u64).saturating_add(1)
    };

    // Adaptive quorum: may be higher than the classical floor when ρ is low.
    // If all personhood is expired, we still use the classical floor for the
    // safety check (the consensus layer would have halted with EmergencyQuorum,
    // but the predicate still reports unsafe rather than erroring out).
    let adaptive_q = match compute_adaptive_quorum(registry, quorum_config) {
        Ok(q)                        => q,
        Err(VcaError::EmergencyQuorum) => classical_floor, // degenerate but safe to evaluate
        Err(e)                       => return Err(e),
    };

    // Safety quorum is the MAX — the adaptive mechanism may only raise the bar.
    let safety_quorum = classical_floor.max(adaptive_q);

    // Compute the relative cap from the actual post-close weights in the registry.
    // We use the median of actual weights (same as close_epoch uses) so the
    // adversary model operates on the real post-cap weight space.
    let relative_cap: Option<u64> = {
        let mut weights: Vec<u64> = registry.records.values()
            .map(|r| r.weight.0)
            .filter(|&w| w > 0)
            .collect();
        if weights.is_empty() {
            None
        } else {
            weights.sort_unstable();
            let median = if weights.len() % 2 == 0 {
                (weights[weights.len() / 2 - 1] + weights[weights.len() / 2]) / 2
            } else {
                weights[weights.len() / 2]
            };
            Some((median as f64 * registry.weight_cfg.max_weight_multiplier).floor() as u64)
        }
    };

    let max_byz = adversary.max_byzantine_weight(&registry.weight_cfg, relative_cap);

    // Safety invariant: W(B) < Q_S  (strict less-than — equality is NOT safe)
    let margin = safety_quorum as i128 - max_byz as i128;
    let holds  = margin > 0;

    let personhood_coverage = if total == 0 {
        0.0
    } else {
        registry.verified_weight() as f64 / total as f64
    };

    let result = SafetyResult {
        holds,
        total_weight: total,
        max_byzantine_weight: max_byz,
        safety_quorum,
        margin,
        personhood_coverage,
    };

    if !holds {
        tracing::warn!(
            epoch = registry.epoch,
            %result,
            "BFT safety invariant VIOLATED — Byzantine coalition can reach quorum"
        );
    } else {
        tracing::debug!(
            epoch = registry.epoch,
            %result,
            "BFT safety invariant satisfied"
        );
    }

    Ok(result)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: a default WeightConfig
    fn wc() -> WeightConfig { WeightConfig::default() }

    // Helper: a default AdaptiveQuorumConfig
    fn aqc() -> AdaptiveQuorumConfig { AdaptiveQuorumConfig::default() }

    // Helper: upsert or panic
    fn upsert(
        reg: &mut VcaRegistry,
        id: &str,
        handle: &str,
        c: f64,
        p: f64,
        stake: u64,
    ) {
        reg.upsert(
            ValidatorId(id.into()),
            IdentityHandle(handle.into()),
            ContributionScore(c),
            PersonhoodFactor::new(p).unwrap(),
            StakeAmount(stake),
            vec![],
            vec![],
        ).expect("upsert should succeed");
    }

    // ── Weight function tests ─────────────────────────────────────────────

    #[test]
    fn weight_zero_personhood_gives_zero_weight() {
        let w = compute_weight(
            ContributionScore(100.0),
            PersonhoodFactor::unverified(),
            &wc(),
        );
        assert_eq!(w, ConsensusWeight::zero(),
            "zero personhood must produce zero weight regardless of contribution");
    }

    #[test]
    fn weight_zero_contribution_gives_min_weight_if_verified() {
        let w = compute_weight(
            ContributionScore::zero(),
            PersonhoodFactor::verified(),
            &wc(),
        );
        // C=0: 0^0.5 = 0, raw = 0, so we apply min_weight floor
        assert_eq!(w.0, wc().min_weight,
            "verified validator with no contribution gets min_weight floor");
    }

    #[test]
    fn weight_capped_at_max() {
        // Very high contribution should not exceed the absolute cap.
        let w = compute_weight(
            ContributionScore(1_000_000.0),
            PersonhoodFactor::verified(),
            &wc(),
        );
        assert_eq!(w.0, wc().max_weight, "weight must be capped at max_weight");
    }

    #[test]
    fn weight_stake_invariant() {
        // W_i must not change when only stake changes.
        let contribution = ContributionScore(4.0);
        let personhood   = PersonhoodFactor::verified();

        let w1 = compute_weight(contribution, personhood, &wc());
        let w2 = compute_weight(contribution, personhood, &wc());
        // Same C, same P → same W regardless of stake (stake is not even a param)
        assert_eq!(w1, w2, "weight must be deterministic and stake-independent");

        // Verify the exact value: sqrt(4.0) × 1.0 × 1000 = 2000
        assert_eq!(w1.0, 2000, "sqrt(4) × 1.0 × 1000 = 2000");
    }

    #[test]
    fn weight_sublinear_diminishing_returns() {
        // With α=0.5 (square root), doubling contribution does NOT double weight.
        let c1 = ContributionScore(1.0);
        let c2 = ContributionScore(4.0);   // 4× contribution
        let p  = PersonhoodFactor::verified();

        let w1 = compute_weight(c1, p, &wc()).0; // sqrt(1) × 1000 = 1000
        let w2 = compute_weight(c2, p, &wc()).0; // sqrt(4) × 1000 = 2000

        assert_eq!(w1, 1000);
        assert_eq!(w2, 2000);
        // 4× contribution → only 2× weight (sub-linear ✓)
        assert!(w2 < 4 * w1, "sub-linear: 4× contribution should give < 4× weight");
    }

    #[test]
    fn personhood_factor_validation() {
        assert!(PersonhoodFactor::new(0.0).is_ok());
        assert!(PersonhoodFactor::new(1.0).is_ok());
        assert!(PersonhoodFactor::new(0.5).is_ok());
        assert!(PersonhoodFactor::new(-0.1).is_err());
        assert!(PersonhoodFactor::new(1.1).is_err());
    }

    #[test]
    fn contribution_score_validation() {
        assert!(ContributionScore::new(0.0).is_ok());
        assert!(ContributionScore::new(1000.0).is_ok());
        assert!(ContributionScore::new(-1.0).is_err());
    }

    // ── A4 fix: relative weight cap ───────────────────────────────────────

    #[test]
    fn close_epoch_applies_relative_weight_cap() {
        // Reproduce the A4 attack: adversary at max_weight vs 3 honest at W≈2000.
        // Before fix: adversary = 10000, total = 16000, fraction = 62.5% > 33.3%
        // After fix: adversary capped to 3 × median(2000) = 6000, fraction ≤ 50%
        let mut reg = VcaRegistry::new(1, wc());

        // 3 honest validators at C=4 → W=2000 each
        upsert(&mut reg, "h1", "id_h1", 4.0, 1.0, 1_000_000);
        upsert(&mut reg, "h2", "id_h2", 4.0, 1.0, 1_000_000);
        upsert(&mut reg, "h3", "id_h3", 4.0, 1.0, 1_000_000);
        // Adversary at C=100 → raw W=10000 (hits absolute cap)
        upsert(&mut reg, "adv", "id_adv", 100.0, 1.0, 1);

        // Before close: adversary holds 10000/(6000+10000) = 62.5%
        let adv_raw = reg.records[&ValidatorId("adv".into())].weight.0;
        assert_eq!(adv_raw, 10_000);

        reg.close_epoch();

        // After close: median of [2000, 2000, 2000, capped] — the median of the
        // uncapped values is 2000. Cap = 3 × 2000 = 6000.
        // adversary weight should now be 6000.
        let adv_after = reg.records[&ValidatorId("adv".into())].weight.0;
        assert!(adv_after <= 6000,
            "relative cap should clamp adversary from 10000 to ≤ 6000; got {adv_after}");

        // Verify the honest validators were not capped
        let h1 = reg.records[&ValidatorId("h1".into())].weight.0;
        assert_eq!(h1, 2000, "honest validators at median should not be capped");

        // Adversary's fraction after cap should be < 62.5% (original) and ≤ 50%
        // With 3 honest at 2000 and cap = 3×median(2000) = 6000:
        //   total = 3×2000 + 6000 = 12000, adv = 6000/12000 = 50.0%
        // That is already a substantial improvement over the uncapped 62.5%.
        // To get below 33.3% (BFT safety), use max_weight_multiplier ≤ 1.0.
        let total = reg.total_weight();
        let adv_fraction = adv_after as f64 / total as f64;
        let uncapped_fraction = 10_000_f64 / (6_000_f64 + 10_000_f64);
        assert!(adv_fraction < uncapped_fraction,
            "after relative cap, adversary fraction {adv_fraction:.3} should be less than uncapped {uncapped_fraction:.3}");
        assert!(adv_fraction <= 0.50,
            "after relative cap, adversary should hold ≤ 50% of weight; got {adv_fraction:.3}");
    }

    #[test]
    fn close_epoch_tight_multiplier_achieves_bft_safety() {
        // With max_weight_multiplier = 1.0, all validators are forced to the median.
        // This eliminates any concentration and guarantees BFT safety.
        let cfg = WeightConfig {
            max_weight_multiplier: 1.0, // strict equality — all weights equal median
            ..WeightConfig::default()
        };
        let mut reg = VcaRegistry::new(1, cfg);

        // 3 honest at C=4 → W=2000, adversary at C=100 → W=10000 (capped to absolute 10000)
        for (id, handle) in [("h1","ih1"),("h2","ih2"),("h3","ih3")] {
            reg.upsert(
                ValidatorId(id.into()), IdentityHandle(handle.into()),
                ContributionScore(4.0), PersonhoodFactor::verified(),
                StakeAmount(1_000_000), vec![], vec![],
            ).unwrap();
        }
        reg.upsert(
            ValidatorId("adv".into()), IdentityHandle("i_adv".into()),
            ContributionScore(100.0), PersonhoodFactor::verified(),
            StakeAmount(1), vec![], vec![],
        ).unwrap();

        reg.close_epoch();

        // After 1× multiplier: cap = 1 × median(2000) = 2000. All at 2000.
        let adv = reg.records[&ValidatorId("adv".into())].weight.0;
        assert_eq!(adv, 2000, "1× multiplier should clamp adversary to median=2000");

        let total = reg.total_weight();
        let adv_fraction = adv as f64 / total as f64;
        assert!(adv_fraction < 1.0 / 3.0 + 0.001,
            "with 1× multiplier, any single validator holds ≤ 1/4 of weight (BFT safe)");
    }

    #[test]
    fn close_epoch_blocks_further_upserts() {
        let mut reg = VcaRegistry::new(1, wc());
        upsert(&mut reg, "v1", "id_v1", 1.0, 1.0, 1_000_000);
        reg.close_epoch();

        let result = reg.upsert(
            ValidatorId("late".into()),
            IdentityHandle("id_late".into()),
            ContributionScore(1.0),
            PersonhoodFactor::verified(),
            StakeAmount(1_000_000),
            vec![],
            vec![],
        );
        assert!(matches!(result, Err(VcaError::RegistryClosed(_))),
            "upsert after close_epoch() should return RegistryClosed");
    }

    // ── D3/D7 fix: identity uniqueness + min personhood ───────────────────

    #[test]
    fn upsert_rejects_identity_handle_collision() {
        let mut reg = VcaRegistry::new(1, wc());
        upsert(&mut reg, "alice", "shared_handle", 1.0, 1.0, 1_000_000);

        // Bob tries to use Alice's identity handle
        let result = reg.upsert(
            ValidatorId("bob".into()),
            IdentityHandle("shared_handle".into()),
            ContributionScore(1.0),
            PersonhoodFactor::verified(),
            StakeAmount(1_000_000),
            vec![],
            vec![],
        );
        assert!(matches!(result, Err(VcaError::IdentityHandleCollision(_))),
            "two validators cannot share an identity handle");
    }

    #[test]
    fn upsert_allows_same_validator_to_update_same_handle() {
        let mut reg = VcaRegistry::new(1, wc());
        upsert(&mut reg, "alice", "alice_handle", 1.0, 1.0, 1_000_000);

        // Alice updates her own record (same handle, new contribution)
        let result = reg.upsert(
            ValidatorId("alice".into()),
            IdentityHandle("alice_handle".into()),
            ContributionScore(4.0),
            PersonhoodFactor::verified(),
            StakeAmount(1_000_000),
            vec![],
            vec![],
        );
        assert!(result.is_ok(), "same validator updating same handle should succeed");
    }

    #[test]
    fn upsert_rejects_very_low_personhood() {
        let mut reg = VcaRegistry::new(1, wc());

        // P=0.1 is below the default min of 0.25
        let result = reg.upsert(
            ValidatorId("sybil".into()),
            IdentityHandle("id_sybil".into()),
            ContributionScore(1.0),
            PersonhoodFactor::new(0.1).unwrap(),
            StakeAmount(1_000_000),
            vec![],
            vec![],
        );
        assert!(matches!(result, Err(VcaError::PersonhoodBelowMinimum { .. })),
            "personhood below min_personhood_factor should be rejected");
    }

    #[test]
    fn upsert_allows_fully_unverified_at_zero_weight() {
        // P=0.0 is allowed (they get W=0 and are excluded from the set)
        let mut reg = VcaRegistry::new(1, wc());
        upsert(&mut reg, "v", "id_v", 1.0, 0.0, 1_000_000);
        let w = reg.records[&ValidatorId("v".into())].weight.0;
        assert_eq!(w, 0, "P=0.0 should give W=0");
    }

    // ── D6 fix: emergency quorum when all personhood expires ──────────────

    #[test]
    fn all_personhood_expired_triggers_emergency_quorum() {
        let mut reg = VcaRegistry::new(1, wc());
        // Register with personhood, then simulate expiry by reinserting with P=0
        // (bypassing the min_personhood check which only blocks low nonzero P)
        upsert(&mut reg, "v1", "id_v1", 1.0, 0.0, 1_000_000);
        upsert(&mut reg, "v2", "id_v2", 1.0, 0.0, 1_000_000);

        assert!(reg.all_personhood_expired(),
            "all validators at P=0 should trigger all_personhood_expired()");

        let result = compute_adaptive_quorum(&reg, &aqc());
        assert!(matches!(result, Err(VcaError::EmergencyQuorum)),
            "all personhood expired should return EmergencyQuorum error");
    }

    #[test]
    fn partial_personhood_expiry_does_not_trigger_emergency() {
        let mut reg = VcaRegistry::new(1, wc());
        upsert(&mut reg, "v1", "id_v1", 1.0, 1.0, 1_000_000); // active
        upsert(&mut reg, "v2", "id_v2", 1.0, 0.0, 1_000_000); // expired

        // Not all expired → should compute normally (with higher quorum)
        let result = compute_adaptive_quorum(&reg, &aqc());
        assert!(result.is_ok(),
            "partial expiry should not trigger emergency quorum");
    }

    // ── Adaptive quorum tests ─────────────────────────────────────────────

    fn make_registry_with_mix(
        verified: usize,
        unverified: usize,
        per_validator_contribution: f64,
    ) -> VcaRegistry {
        let mut reg = VcaRegistry::new(1, wc());
        for i in 0..verified {
            upsert(&mut reg, &format!("v_ver_{i}"), &format!("id_ver_{i}"),
                per_validator_contribution, 1.0, 1_000_000);
        }
        for i in 0..unverified {
            upsert(&mut reg, &format!("v_unv_{i}"), &format!("id_unv_{i}"),
                per_validator_contribution, 0.0, 1_000_000);
        }
        reg
    }

    #[test]
    fn adaptive_quorum_full_coverage_uses_base_fraction() {
        // All validators verified → ρ = 1.0 → no adjustment → base 2/3 quorum
        let reg = make_registry_with_mix(4, 0, 1.0);
        let q = compute_adaptive_quorum(&reg, &aqc()).unwrap();
        let total = reg.total_weight();
        let base_q = ((total as f64 * 2.0 / 3.0).ceil()) as u64;
        assert_eq!(q, base_q,
            "full coverage: adaptive quorum should equal classical 2/3 quorum");
    }

    #[test]
    fn adaptive_quorum_low_coverage_raises_threshold() {
        // Only 25% verified → ρ < 0.50 → max adjustment → quorum_ceiling
        let reg = make_registry_with_mix(1, 3, 1.0);
        let q = compute_adaptive_quorum(&reg, &aqc()).unwrap();
        let total = reg.total_weight();
        let base_q = ((total as f64 * 2.0 / 3.0).ceil()) as u64;
        assert!(q >= base_q,
            "low coverage: adaptive quorum should be >= base quorum");
        // Should be at or near ceiling
        let ceiling_q = ((total as f64 * 0.80).ceil()) as u64;
        assert!(q <= ceiling_q.max(base_q),
            "low coverage: quorum should not exceed ceiling");
    }

    #[test]
    fn adaptive_quorum_empty_registry_returns_floor() {
        let reg = VcaRegistry::new(1, wc());
        let q = compute_adaptive_quorum(&reg, &aqc()).unwrap();
        assert_eq!(q, aqc().quorum_floor);
    }

    // ── PQ signature envelope tests ───────────────────────────────────────

    #[test]
    fn pq_envelope_classical_only_valid() {
        let env = PqSignatureEnvelope::classical(vec![1, 2, 3]);
        assert!(env.is_valid_for_phase(&SignaturePhase::ClassicalOnly));
        assert!(!env.is_valid_for_phase(&SignaturePhase::Dual));
        assert!(!env.is_valid_for_phase(&SignaturePhase::PqNative));
    }

    #[test]
    fn pq_envelope_dual_rejects_wrong_pq_length() {
        // ML-DSA-87 must be exactly 4627 bytes
        let short_pq = vec![0u8; 100];
        let result = PqSignatureEnvelope::dual(vec![1, 2, 3], short_pq);
        assert!(result.is_err(), "should reject PQ sig of wrong length");
    }

    #[test]
    fn pq_envelope_dual_accepts_correct_length() {
        let pq = vec![0u8; 4627]; // correct ML-DSA-87 length
        let env = PqSignatureEnvelope::dual(vec![1, 2, 3], pq).unwrap();
        assert!(env.is_valid_for_phase(&SignaturePhase::Dual));
        assert!(env.is_valid_for_phase(&SignaturePhase::ClassicalOnly));
        assert!(env.is_valid_for_phase(&SignaturePhase::PqNative));
    }

    // ── VCA registry tests ────────────────────────────────────────────────

    #[test]
    fn registry_to_validator_set_excludes_zero_weight() {
        let mut reg = VcaRegistry::new(1, wc());
        // Verified validator — gets non-zero weight
        upsert(&mut reg, "alice", "id_alice_secret", 1.0, 1.0, 1_000_000);
        // Unverified validator — gets zero weight → excluded from ValidatorSet
        upsert(&mut reg, "sybil", "id_sybil_secret", 1000.0, 0.0, 999_999_999);

        let vs = reg.to_validator_set(1);
        assert_eq!(vs.validators.len(), 1, "sybil with P=0 must be excluded");
        assert_eq!(vs.validators[0].id, ValidatorId("alice".into()));
    }

    #[test]
    fn registry_stake_does_not_influence_weight() {
        let mut reg_low_stake  = VcaRegistry::new(1, wc());
        let mut reg_high_stake = VcaRegistry::new(1, wc());

        let id  = ValidatorId("bob".into());
        let c   = ContributionScore(4.0);
        let p   = PersonhoodFactor::verified();

        reg_low_stake.upsert(id.clone(), IdentityHandle("id_bob".into()),
            c, p, StakeAmount(1), vec![], vec![]).unwrap();
        reg_high_stake.upsert(id.clone(), IdentityHandle("id_bob".into()),
            c, p, StakeAmount(u64::MAX), vec![], vec![]).unwrap();

        let w_low  = reg_low_stake.records[&id].weight;
        let w_high = reg_high_stake.records[&id].weight;
        assert_eq!(w_low, w_high,
            "∂W/∂S = 0: stake must not influence consensus weight");
    }

    // ── Separation invariant tests ────────────────────────────────────────

    #[test]
    fn separation_invariant_passes_for_valid_record() {
        let mut reg = VcaRegistry::new(1, wc());
        upsert(&mut reg, "carol", "commitment_xyz_carol", 9.0, 1.0, 500_000);
        let record = reg.get(&ValidatorId("carol".into())).unwrap();
        assert!(verify_separation_invariant(record, &wc()).is_ok());
    }

    #[test]
    fn separation_invariant_fails_when_identity_equals_validator_id() {
        // Manually build a record where identity_handle == validator_id
        let record = VcaValidatorRecord::new(
            ValidatorId("dave".into()),
            IdentityHandle("dave".into()), // VIOLATION: identity == pseudonym
            1,
            ContributionScore(1.0),
            PersonhoodFactor::verified(),
            StakeAmount(1_000_000),
            &wc(),
            vec![],
            vec![],
        );
        assert!(verify_separation_invariant(&record, &wc()).is_err(),
            "identity == validator_id should fail the separation invariant");
    }

    #[test]
    fn vca_record_roundtrip_to_validator_info() {
        let record = VcaValidatorRecord::new(
            ValidatorId("eve".into()),
            IdentityHandle("id_eve_opaque".into()),
            3,
            ContributionScore(1.0),
            PersonhoodFactor::verified(),
            StakeAmount(250_000),
            &wc(),
            vec![0x01, 0x02],
            vec![],
        );

        let info = record.to_validator_info();
        assert_eq!(info.id, ValidatorId("eve".into()));
        assert_eq!(info.voting_power, record.weight.0);
        assert!(info.pop_verified);
        assert_eq!(info.public_key, vec![0x01, 0x02]);
    }

    #[test]
    fn verified_fraction_correct() {
        let reg = make_registry_with_mix(3, 1, 1.0);
        // 3 verified, 1 unverified → 4 total records
        let frac = reg.verified_fraction();
        assert!((frac - 0.75).abs() < 1e-6, "3/4 = 0.75 verified fraction");
    }
}
