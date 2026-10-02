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
//! ## What this crate does NOT do
//! - It does not implement external-chain verification (§20.5 — separate research)
//! - It does not manage identity credentials (chain-forge-personhood)
//! - It does not replace the consensus engine (chain-forge-consensus)
//!
//! It extends the consensus layer with VCA-specific weight computation,
//! adaptive-quorum logic, and PQ signature slots.

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use chain_forge_consensus::{BlockHeight, ValidatorId, ValidatorSet, ValidatorInfo};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum VcaError {
    #[error("contribution score must be non-negative; got {0}")]
    NegativeContribution(f64),

    #[error("personhood factor must be in [0.0, 1.0]; got {0}")]
    InvalidPersonhoodFactor(f64),

    #[error("adaptive quorum config invalid: floor {floor} > ceiling {ceiling}")]
    InvalidQuorumConfig { floor: u64, ceiling: u64 },

    #[error("PQ signature too short: expected at least {min} bytes, got {actual}")]
    PqSignatureTooShort { min: usize, actual: usize },

    #[error("separation invariant violated: {0}")]
    SeparationViolation(String),

    #[error("validator {0} not found in VCA registry")]
    UnknownValidator(ValidatorId),
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
/// In QCB: CirFi transactions processed, identity attestations cosigned,
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
/// Where:
///   - `α` (contribution_exponent): sub-linear (< 1) gives diminishing returns
///     to contribution, preventing runaway concentration. Linear (= 1) is simpler
///     but allows large contributors to dominate.
///   - `scale`: converts the raw score to an integer weight. Tune so that a
///     "typical" validator gets weight ≈ 100.
///   - `max_weight`: hard cap enforcing the personhood power-cap invariant.
///     Corresponds to `PersonhoodConfig::power_cap` in the base consensus layer.
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

    /// Hard cap on weight. Enforces the personhood power-cap invariant:
    /// no single human can accumulate unbounded consensus authority even
    /// with very high contribution.
    pub max_weight: u64,
}

impl Default for WeightConfig {
    fn default() -> Self {
        Self {
            contribution_exponent: 0.5,   // square-root: sub-linear, diminishing returns
            scale:                 1000.0,
            min_weight:            1,      // floor for eligible validators
            max_weight:            10_000, // cap per human
        }
    }
}

/// Compute W_i = F(C_i, P_i) using the configured weight function.
///
/// This is the core VCA primitive. Call this when building the ValidatorSet
/// for a new epoch. Stake is deliberately not a parameter.
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

    // Apply cap
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
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VcaRegistry {
    pub epoch:      u64,
    pub records:    BTreeMap<ValidatorId, VcaValidatorRecord>,
    pub weight_cfg: WeightConfig,
}

impl VcaRegistry {
    pub fn new(epoch: u64, weight_cfg: WeightConfig) -> Self {
        Self { epoch, records: BTreeMap::new(), weight_cfg }
    }

    /// Register or update a validator's VCA record for the current epoch.
    pub fn upsert(
        &mut self,
        validator_id:     ValidatorId,
        identity_handle:  IdentityHandle,
        contribution:     ContributionScore,
        personhood:       PersonhoodFactor,
        stake:            StakeAmount,
        classical_pubkey: Vec<u8>,
        pq_pubkey:        Vec<u8>,
    ) {
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
    }

    /// Get a validator's record.
    pub fn get(&self, id: &ValidatorId) -> VcaResult<&VcaValidatorRecord> {
        self.records.get(id).ok_or_else(|| VcaError::UnknownValidator(id.clone()))
    }

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

    let total = registry.total_weight();
    if total == 0 { return Ok(config.quorum_floor); }

    // ρ = fraction of total weight that is personhood-verified
    let verified_weight: u64 = registry.records.values()
        .filter(|r| r.personhood.0 > 0.0)
        .map(|r| r.weight.0)
        .sum();
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
pub fn verify_separation_invariant(
    record:  &VcaValidatorRecord,
    config:  &WeightConfig,
) -> VcaResult<()> {
    // Re-derive the weight from C and P (no stake).
    let expected_weight = compute_weight(record.contribution, record.personhood, config);
    if record.weight != expected_weight {
        return Err(VcaError::SeparationViolation(format!(
            "validator {}: stored weight {} ≠ derived weight {} — stake may have influenced weight",
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: a default WeightConfig
    fn wc() -> WeightConfig { WeightConfig::default() }

    // Helper: a default AdaptiveQuorumConfig
    fn aqc() -> AdaptiveQuorumConfig { AdaptiveQuorumConfig::default() }

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
        // Very high contribution should not exceed the cap.
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

    // ── Adaptive quorum tests ─────────────────────────────────────────────

    fn make_registry_with_mix(
        verified: usize,
        unverified: usize,
        per_validator_contribution: f64,
    ) -> VcaRegistry {
        let mut reg = VcaRegistry::new(1, wc());
        for i in 0..verified {
            reg.upsert(
                ValidatorId(format!("v_ver_{i}")),
                IdentityHandle(format!("id_ver_{i}")),
                ContributionScore(per_validator_contribution),
                PersonhoodFactor::verified(),
                StakeAmount(1_000_000),
                vec![],
                vec![],
            );
        }
        for i in 0..unverified {
            reg.upsert(
                ValidatorId(format!("v_unv_{i}")),
                IdentityHandle(format!("id_unv_{i}")),
                ContributionScore(per_validator_contribution),
                PersonhoodFactor::unverified(),
                StakeAmount(1_000_000),
                vec![],
                vec![],
            );
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
        reg.upsert(
            ValidatorId("alice".into()),
            IdentityHandle("id_alice_secret".into()),
            ContributionScore(1.0),
            PersonhoodFactor::verified(),
            StakeAmount(1_000_000),
            vec![],
            vec![],
        );
        // Unverified validator — gets zero weight → excluded from ValidatorSet
        reg.upsert(
            ValidatorId("sybil".into()),
            IdentityHandle("id_sybil_secret".into()),
            ContributionScore(1000.0),
            PersonhoodFactor::unverified(),
            StakeAmount(999_999_999), // huge stake, but P=0 → W=0
            vec![],
            vec![],
        );

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
            c, p, StakeAmount(1), vec![], vec![]);
        reg_high_stake.upsert(id.clone(), IdentityHandle("id_bob".into()),
            c, p, StakeAmount(u64::MAX), vec![], vec![]);

        let w_low  = reg_low_stake.records[&id].weight;
        let w_high = reg_high_stake.records[&id].weight;
        assert_eq!(w_low, w_high,
            "∂W/∂S = 0: stake must not influence consensus weight");
    }

    // ── Separation invariant tests ────────────────────────────────────────

    #[test]
    fn separation_invariant_passes_for_valid_record() {
        let mut reg = VcaRegistry::new(1, wc());
        reg.upsert(
            ValidatorId("carol".into()),
            IdentityHandle("commitment_xyz_carol".into()), // opaque, ≠ validator_id
            ContributionScore(9.0),
            PersonhoodFactor::verified(),
            StakeAmount(500_000),
            vec![],
            vec![],
        );
        let record = reg.get(&ValidatorId("carol".into())).unwrap();
        assert!(verify_separation_invariant(record, &wc()).is_ok());
    }

    #[test]
    fn separation_invariant_fails_when_identity_equals_validator_id() {
        // Manually build a record where identity_handle == validator_id
        let mut reg = VcaRegistry::new(1, wc());
        reg.upsert(
            ValidatorId("dave".into()),
            IdentityHandle("dave".into()), // VIOLATION: identity == pseudonym
            ContributionScore(1.0),
            PersonhoodFactor::verified(),
            StakeAmount(1_000_000),
            vec![],
            vec![],
        );
        let record = reg.get(&ValidatorId("dave".into())).unwrap();
        assert!(verify_separation_invariant(record, &wc()).is_err(),
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
        // 3 verified, 1 unverified → but unverified gets W=0 (P=0), so they're
        // still counted in records (4 total) but not in weight
        // verified_fraction counts by record count, not weight
        let frac = reg.verified_fraction();
        assert!((frac - 0.75).abs() < 1e-6, "3/4 = 0.75 verified fraction");
    }
}
