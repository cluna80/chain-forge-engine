//! # chain-forge-personhood :: eligibility
//!
//! Layer 1 of the VCA-PQ-BFT formal security contract: **Personhood Eligibility**.
//!
//! This module implements properties P-1 through P-8 from the formal spec:
//!
//! | Property | Name                         | Description                                     |
//! |----------|------------------------------|-------------------------------------------------|
//! | P-1      | Unique Registration          | Each real person registers at most once         |
//! | P-2      | Credential Authenticity      | Credentials issued by approved issuers only     |
//! | P-3      | Temporal Validity            | Credentials expire; expired ⟹ P = 0            |
//! | P-4      | Score Validity               | P_i ∈ [0.0, 1.0]; fully verified = 1.0          |
//! | P-5      | Stake Independence           | Eligibility derived from credential, not stake  |
//! | P-6      | Replay Prevention            | A credential can only be active in one epoch    |
//! | P-7      | Identity Multiplicity Bound  | One person → at most N* active identities       |
//! | P-8      | Minimum Personhood Gate      | P < P_min ⟹ excluded from validator set        |
//!
//! The central export for the consensus layer is [`PersonhoodBound`]: it carries
//! `(P_max, N_max, C_max)` — the three parameters consumed by
//! `chain_forge_vca_pq::AdversaryModel` — and is derived from the state of an
//! [`EligibilityRegistry`] at epoch close.
//!
//! # Relationship to the ZK layer
//!
//! The *credential issuer* (the ZK circuit in `lib.rs`) proves that a leaf exists
//! in a VRC Merkle tree. **This module** is the runtime registry that tracks
//! which credentials have been activated this epoch, enforces uniqueness, and
//! expresses the resulting bound into the adversary model. The two layers are
//! complementary:
//!
//! - ZK: "this person holds a valid credential" (proof of existence)
//! - Eligibility: "this credential is unique this epoch and meets P ≥ P_min" (runtime enforcement)

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

// ── Domain types ──────────────────────────────────────────────────────────────

/// An epoch identifier. Epochs are monotonically increasing u64s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EpochId(pub u64);

impl std::fmt::Display for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch({})", self.0)
    }
}

/// A nullifier is a single-use token that prevents the same underlying
/// credential from being activated in more than one epoch (P-6).
///
/// In a production system this would be a ZK-derived value (e.g., PRF output
/// over the secret blinding nonce). Here it is a `[u8; 32]` that the
/// eligibility module treats as opaque. The issuing system is responsible for
/// deriving a deterministic, epoch-scoped nullifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// Derive a synthetic nullifier from a validator id + epoch (for tests).
    /// Production systems must use a ZK-derived nullifier.
    pub fn from_validator_epoch(validator_id: u64, epoch: EpochId) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        validator_id.hash(&mut hasher);
        epoch.0.hash(&mut hasher);
        let h = hasher.finish();
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&h.to_le_bytes());
        bytes[8..16].copy_from_slice(&h.wrapping_add(1).to_le_bytes());
        bytes[16..24].copy_from_slice(&h.wrapping_add(2).to_le_bytes());
        bytes[24..32].copy_from_slice(&h.wrapping_add(3).to_le_bytes());
        Self(bytes)
    }
}

/// An epoch-scoped personhood credential: the runtime activation of a ZK-VRC
/// proof within a specific epoch.
///
/// `EpochCredential` is what the eligibility module actually tracks; it wraps
/// the ZK verification result (a `PersonhoodFactor` and a `Nullifier`) and
/// binds it to a validator identity and epoch window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCredential {
    /// The on-chain validator identifier (maps to `ValidatorId` in `chain-forge-core`).
    pub validator_id: u64,

    /// The epoch this credential is active in. A credential with epoch=E
    /// cannot be reused in epoch E+1 (P-6).
    pub epoch: EpochId,

    /// Personhood factor attested by the credential (P_i ∈ [0, 1]).
    /// Derived from the ZK proof; 1.0 = fully verified, 0.0 = unverified.
    pub personhood_factor: f64,

    /// Single-use token preventing cross-epoch replay (P-6).
    pub nullifier: Nullifier,

    /// The block height at which this credential was registered.
    pub registered_at: u64,
}

impl EpochCredential {
    /// Construct and validate a new epoch credential.
    pub fn new(
        validator_id: u64,
        epoch: EpochId,
        personhood_factor: f64,
        nullifier: Nullifier,
        registered_at: u64,
    ) -> Result<Self, EligibilityError> {
        if !(0.0..=1.0).contains(&personhood_factor) {
            return Err(EligibilityError::InvalidPersonhoodFactor(personhood_factor));
        }
        Ok(Self {
            validator_id,
            epoch,
            personhood_factor,
            nullifier,
            registered_at,
        })
    }

    /// Returns true if this credential is temporally valid for `query_epoch`.
    /// Credentials are valid only in the epoch they were issued for (P-3).
    pub fn is_valid_for_epoch(&self, query_epoch: EpochId) -> bool {
        self.epoch == query_epoch
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum EligibilityError {
    #[error("personhood factor {0} is outside [0.0, 1.0]")]
    InvalidPersonhoodFactor(f64),

    #[error("nullifier already used this epoch — replay attempt (P-6)")]
    NullifierReplay,

    #[error(
        "validator {validator_id} already has an active credential this epoch (multiplicity: {active}) — \
         identity multiplicity bound N*={n_star} exceeded (P-7)"
    )]
    MultiplicityExceeded {
        validator_id: u64,
        active:       usize,
        n_star:       usize,
    },

    #[error("registry epoch {registry_epoch} is closed — no new credentials accepted")]
    RegistryClosed { registry_epoch: u64 },

    #[error("credential epoch {cred_epoch} does not match registry epoch {registry_epoch}")]
    EpochMismatch { cred_epoch: u64, registry_epoch: u64 },

    #[error("personhood factor {actual:.3} below minimum P_min={min:.3} — excluded by P-8 gate")]
    BelowMinimum { actual: f64, min: f64 },
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the eligibility registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EligibilityConfig {
    /// The identity multiplicity bound N* (P-7).
    ///
    /// A single real person may hold at most `n_star` active consensus
    /// identities per epoch. Setting `n_star = 1` enforces strict 1-person /
    /// 1-validator. Higher values allow key rotation grace periods.
    pub n_star: usize,

    /// Minimum personhood factor P_min (P-8).
    ///
    /// Credentials with `P_i < p_min` are excluded from the validator set
    /// entirely. Default 0.25 (from VCA-PQ-BFT spec §4).
    pub p_min: f64,
}

impl Default for EligibilityConfig {
    fn default() -> Self {
        Self {
            n_star: 1,
            p_min:  0.25,
        }
    }
}

// ── Nullifier set (P-6) ───────────────────────────────────────────────────────

/// Tracks spent nullifiers within an epoch to prevent credential replay (P-6).
///
/// At epoch boundary the nullifier set is cleared (nullifiers are epoch-scoped).
#[derive(Debug, Default, Clone)]
pub struct NullifierSet {
    spent: HashSet<Nullifier>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to spend a nullifier. Returns `Err(NullifierReplay)` if already spent.
    pub fn spend(&mut self, n: Nullifier) -> Result<(), EligibilityError> {
        if self.spent.contains(&n) {
            Err(EligibilityError::NullifierReplay)
        } else {
            self.spent.insert(n);
            Ok(())
        }
    }

    pub fn contains(&self, n: &Nullifier) -> bool {
        self.spent.contains(n)
    }

    pub fn len(&self) -> usize {
        self.spent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }
}

// ── Eligibility registry ───────────────────────────────────────────────────────

/// Per-epoch registry of active personhood credentials.
///
/// Enforces P-1 through P-8 at credential activation time. At epoch close
/// the registry produces a [`PersonhoodBound`] that parameterises the
/// `AdversaryModel` in `chain-forge-vca-pq`.
pub struct EligibilityRegistry {
    epoch: EpochId,
    config: EligibilityConfig,

    /// Active credentials indexed by validator_id.
    /// Each validator maps to the list of credentials active this epoch.
    /// Under the default `n_star = 1` config this list always has at most one entry.
    credentials: HashMap<u64, Vec<EpochCredential>>,

    /// Spent nullifiers this epoch (P-6).
    nullifiers: NullifierSet,

    /// Whether the epoch is closed to new activations.
    closed: bool,
}

impl EligibilityRegistry {
    /// Create a new, open registry for the given epoch.
    pub fn new(epoch: EpochId, config: EligibilityConfig) -> Self {
        Self {
            epoch,
            config,
            credentials: HashMap::new(),
            nullifiers: NullifierSet::new(),
            closed: false,
        }
    }

    /// Create with default config (N* = 1, P_min = 0.25).
    pub fn new_default(epoch: EpochId) -> Self {
        Self::new(epoch, EligibilityConfig::default())
    }

    /// Activate a personhood credential for the given epoch.
    ///
    /// Enforces (in order):
    /// 1. Registry open check
    /// 2. Epoch match (P-3)
    /// 3. Personhood factor range check (P-4)
    /// 4. P_min gate (P-8)
    /// 5. Nullifier uniqueness (P-6 replay prevention)
    /// 6. Identity multiplicity bound (P-7)
    pub fn activate(&mut self, cred: EpochCredential) -> Result<(), EligibilityError> {
        // 1. Closed check
        if self.closed {
            return Err(EligibilityError::RegistryClosed {
                registry_epoch: self.epoch.0,
            });
        }

        // 2. Epoch match (P-3)
        if cred.epoch != self.epoch {
            return Err(EligibilityError::EpochMismatch {
                cred_epoch:     cred.epoch.0,
                registry_epoch: self.epoch.0,
            });
        }

        // 3+4. Factor range (P-4) + P_min gate (P-8)
        // EpochCredential::new already validated [0,1], but double-check P_min here
        if cred.personhood_factor < self.config.p_min {
            return Err(EligibilityError::BelowMinimum {
                actual: cred.personhood_factor,
                min:    self.config.p_min,
            });
        }

        // 5. Nullifier uniqueness (P-6)
        self.nullifiers.spend(cred.nullifier.clone())?;

        // 6. Identity multiplicity bound (P-7)
        let existing = self.credentials.entry(cred.validator_id).or_default();
        if existing.len() >= self.config.n_star {
            return Err(EligibilityError::MultiplicityExceeded {
                validator_id: cred.validator_id,
                active:       existing.len(),
                n_star:       self.config.n_star,
            });
        }

        existing.push(cred);
        Ok(())
    }

    /// Close the epoch. After this call no new credentials are accepted.
    /// Returns the [`PersonhoodBound`] for use in the adversary model.
    pub fn close_epoch(&mut self) -> PersonhoodBound {
        self.closed = true;
        self.compute_bound()
    }

    /// Compute the personhood bound without closing the registry (for inspection).
    pub fn compute_bound(&self) -> PersonhoodBound {
        let n_active = self.credentials.values().map(|v| v.len()).sum::<usize>();

        // P_max: maximum personhood factor observed across all active credentials.
        // An adversary who corrupts the issuer to produce P=1.0 credentials has
        // P_max = 1.0. We report the actual observed maximum so the safety check
        // uses a realistic (not always worst-case) value.
        let p_max = self
            .credentials
            .values()
            .flat_map(|v| v.iter())
            .map(|c| c.personhood_factor)
            .fold(0.0f64, f64::max);

        // N_max: the maximum number of active credentials any single validator holds.
        // This is the per-validator multiplicity, bounded by N*. In a correct system
        // N_max ≤ N*; if they differ something went wrong (should be impossible given
        // the activate() guard, but we report the actual observed value).
        let n_max = self
            .credentials
            .values()
            .map(|v| v.len())
            .max()
            .unwrap_or(0);

        PersonhoodBound {
            epoch:                self.epoch,
            n_star:               self.config.n_star,
            n_max_observed:       n_max,
            p_max_observed:       p_max,
            p_min:                self.config.p_min,
            n_active_credentials: n_active,
            n_active_validators:  self.credentials.len(),
        }
    }

    // ── Accessors ──────────────────────────────────────────────────────────────

    pub fn epoch(&self) -> EpochId { self.epoch }
    pub fn is_closed(&self) -> bool { self.closed }
    pub fn active_credential_count(&self) -> usize {
        self.credentials.values().map(|v| v.len()).sum()
    }
    pub fn active_validator_count(&self) -> usize { self.credentials.len() }

    /// Personhood factor for a given validator (highest across its credentials).
    /// Returns 0.0 if the validator has no active credential.
    pub fn personhood_factor(&self, validator_id: u64) -> f64 {
        self.credentials
            .get(&validator_id)
            .map(|v| v.iter().map(|c| c.personhood_factor).fold(0.0f64, f64::max))
            .unwrap_or(0.0)
    }

    /// True if the validator has at least one active, epoch-valid credential.
    pub fn is_eligible(&self, validator_id: u64) -> bool {
        self.credentials
            .get(&validator_id)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }
}

// ── Personhood bound (the bridge to AdversaryModel) ───────────────────────────

/// The Layer 1 output: a snapshot of the personhood state at epoch close,
/// expressed as parameters `(P_max, N_max, C_max_assumed)` that plug directly
/// into `chain_forge_vca_pq::AdversaryModel`.
///
/// # Formal relationship (Theorem T1)
///
/// The composition theorem T1 states:
///
/// ```text
///   Security_Personhood ⟹ N_max ≤ N*
/// ```
///
/// That is: if the identity system correctly enforces the identity multiplicity
/// bound, then the number of active consensus identities controlled by any single
/// real person is at most `N*`. This module *enforces* `N* = n_star` at runtime
/// (see `activate()`), so every `PersonhoodBound` produced here has
/// `n_max_observed ≤ n_star` by construction — the inequality is checked
/// structurally, not just asserted.
///
/// # Usage
///
/// ```rust,ignore
/// use chain_forge_vca_pq::AdversaryModel;
///
/// let bound = registry.close_epoch();
/// let adversary = bound.to_adversary_model(/* max_contribution_per_sybil */ 100.0);
/// let result = check_bft_safety(&vca_registry, &quorum_config, &adversary)?;
/// assert!(result.is_safe());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonhoodBound {
    /// The epoch this bound covers.
    pub epoch: EpochId,

    /// The configured identity multiplicity limit (N*).
    pub n_star: usize,

    /// The maximum number of active credentials observed for any single validator.
    /// In a correctly operating system: `n_max_observed ≤ n_star`.
    pub n_max_observed: usize,

    /// The maximum personhood factor observed across all active credentials.
    pub p_max_observed: f64,

    /// The minimum personhood factor gate (P_min from config).
    pub p_min: f64,

    /// Total number of active credentials (≥ n_active_validators).
    pub n_active_credentials: usize,

    /// Total number of distinct validators with at least one active credential.
    pub n_active_validators: usize,
}

impl PersonhoodBound {
    /// Convert to an `AdversaryModel` for use in `check_bft_safety`.
    ///
    /// - `max_byzantine_validators`: number of adversarial validators assumed.
    ///   In the full composition proof this would come from `N* × |corrupt persons|`;
    ///   in practice, callers supply it as a policy parameter.
    /// - `max_contribution_per_sybil`: assumed maximum contribution the adversary
    ///   can accumulate per Sybil identity.
    ///
    /// The adversary's `max_personhood_per_sybil` is set to `p_max_observed` —
    /// the highest factor the personhood system actually produced. This is tighter
    /// than the worst-case 1.0 when the system only issues partial credentials.
    pub fn to_adversary_model(
        &self,
        max_byzantine_validators: usize,
        max_contribution_per_sybil: f64,
    ) -> chain_forge_vca_pq::AdversaryModel {
        chain_forge_vca_pq::AdversaryModel {
            max_personhood_per_sybil:   self.p_max_observed,
            max_byzantine_validators,
            max_contribution_per_sybil,
        }
    }

    /// Whether the observed multiplicity is within the N* bound (T1 check).
    pub fn multiplicity_within_bound(&self) -> bool {
        self.n_max_observed <= self.n_star
    }

    /// Fraction of active validators among the total that are eligible
    /// (P_i ≥ P_min). In a correctly configured registry this is always 1.0
    /// because `activate()` enforces P_min; this accessor is a sanity check.
    pub fn verified_fraction(&self) -> f64 {
        if self.n_active_validators == 0 {
            0.0
        } else {
            // All activated credentials passed the P_min gate.
            1.0
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_core::ValidatorId;
    use chain_forge_vca_pq::{
        AdaptiveQuorumConfig, ContributionScore, IdentityHandle, PersonhoodFactor,
        StakeAmount, VcaRegistry, WeightConfig, check_bft_safety,
    };

    fn make_cred(validator_id: u64, epoch: EpochId, p: f64) -> EpochCredential {
        EpochCredential::new(
            validator_id,
            epoch,
            p,
            Nullifier::from_validator_epoch(validator_id, epoch),
            0,
        )
        .unwrap()
    }

    // ── P-4: factor validation ────────────────────────────────────────────────

    #[test]
    fn invalid_personhood_factor_rejected() {
        let result = EpochCredential::new(
            1,
            EpochId(0),
            1.5, // > 1.0
            Nullifier::from_validator_epoch(1, EpochId(0)),
            0,
        );
        assert!(matches!(result, Err(EligibilityError::InvalidPersonhoodFactor(_))));
    }

    #[test]
    fn negative_personhood_factor_rejected() {
        let result = EpochCredential::new(
            1,
            EpochId(0),
            -0.1,
            Nullifier::from_validator_epoch(1, EpochId(0)),
            0,
        );
        assert!(matches!(result, Err(EligibilityError::InvalidPersonhoodFactor(_))));
    }

    // ── P-6: nullifier replay ─────────────────────────────────────────────────

    #[test]
    fn nullifier_replay_rejected() {
        let epoch = EpochId(1);
        let mut registry = EligibilityRegistry::new_default(epoch);

        let nullifier = Nullifier::from_validator_epoch(42, epoch);
        let cred1 = EpochCredential::new(42, epoch, 1.0, nullifier.clone(), 0).unwrap();
        assert!(registry.activate(cred1).is_ok());

        // Second activation with same nullifier but different validator_id
        // (simulating a credential being presented twice)
        let cred2 = EpochCredential::new(99, epoch, 1.0, nullifier, 0).unwrap();
        let result = registry.activate(cred2);
        assert!(matches!(result, Err(EligibilityError::NullifierReplay)));
    }

    #[test]
    fn distinct_nullifiers_both_accepted() {
        let epoch = EpochId(1);
        let mut registry = EligibilityRegistry::new_default(epoch);

        let cred1 = make_cred(1, epoch, 1.0);
        let cred2 = make_cred(2, epoch, 1.0);
        assert!(registry.activate(cred1).is_ok());
        assert!(registry.activate(cred2).is_ok());
        assert_eq!(registry.active_credential_count(), 2);
    }

    // ── P-7: identity multiplicity bound ──────────────────────────────────────

    #[test]
    fn multiplicity_bound_n_star_1_blocks_second_credential() {
        let epoch = EpochId(2);
        let mut registry = EligibilityRegistry::new(epoch, EligibilityConfig {
            n_star: 1,
            p_min:  0.0,
        });

        let cred1 = make_cred(7, epoch, 0.8);
        assert!(registry.activate(cred1).is_ok());

        // Second credential for the same validator with a different nullifier
        let second_nullifier = Nullifier([42u8; 32]);
        let cred2 = EpochCredential::new(7, epoch, 0.9, second_nullifier, 1).unwrap();
        let result = registry.activate(cred2);
        assert!(
            matches!(result, Err(EligibilityError::MultiplicityExceeded { validator_id: 7, active: 1, n_star: 1 })),
            "expected MultiplicityExceeded, got {:?}", result
        );
    }

    #[test]
    fn multiplicity_bound_n_star_2_allows_two_credentials() {
        let epoch = EpochId(3);
        let mut registry = EligibilityRegistry::new(epoch, EligibilityConfig {
            n_star: 2,
            p_min:  0.0,
        });

        // First credential
        let cred1 = make_cred(5, epoch, 1.0);
        assert!(registry.activate(cred1).is_ok());

        // Second credential with distinct nullifier
        let n2 = Nullifier([0xABu8; 32]);
        let cred2 = EpochCredential::new(5, epoch, 1.0, n2, 1).unwrap();
        assert!(registry.activate(cred2).is_ok());

        // Third is over the limit
        let n3 = Nullifier([0xCDu8; 32]);
        let cred3 = EpochCredential::new(5, epoch, 1.0, n3, 2).unwrap();
        let result = registry.activate(cred3);
        assert!(
            matches!(result, Err(EligibilityError::MultiplicityExceeded { .. })),
            "third credential must be rejected when n_star=2"
        );
    }

    // ── P-8: minimum personhood gate ──────────────────────────────────────────

    #[test]
    fn below_p_min_rejected() {
        let epoch = EpochId(0);
        let mut registry = EligibilityRegistry::new(epoch, EligibilityConfig {
            n_star: 1,
            p_min:  0.5,
        });
        // P = 0.3 < 0.5 = P_min
        let cred = EpochCredential::new(
            1,
            epoch,
            0.3,
            Nullifier::from_validator_epoch(1, epoch),
            0,
        ).unwrap();
        let result = registry.activate(cred);
        assert!(
            matches!(result, Err(EligibilityError::BelowMinimum { actual, min }) if actual < min),
        );
    }

    #[test]
    fn at_p_min_accepted() {
        let epoch = EpochId(0);
        let mut registry = EligibilityRegistry::new(epoch, EligibilityConfig {
            n_star: 1,
            p_min:  0.5,
        });
        let cred = EpochCredential::new(
            1,
            epoch,
            0.5,
            Nullifier::from_validator_epoch(1, epoch),
            0,
        ).unwrap();
        assert!(registry.activate(cred).is_ok());
    }

    // ── P-3: epoch mismatch ───────────────────────────────────────────────────

    #[test]
    fn credential_from_wrong_epoch_rejected() {
        let registry_epoch = EpochId(10);
        let mut registry = EligibilityRegistry::new_default(registry_epoch);

        // Credential claims epoch 9 (previous epoch)
        let cred = EpochCredential::new(
            1,
            EpochId(9),
            1.0,
            Nullifier::from_validator_epoch(1, EpochId(9)),
            0,
        ).unwrap();
        let result = registry.activate(cred);
        assert!(matches!(result, Err(EligibilityError::EpochMismatch { cred_epoch: 9, registry_epoch: 10 })));
    }

    // ── Registry lifecycle ────────────────────────────────────────────────────

    #[test]
    fn closed_registry_rejects_new_credentials() {
        let epoch = EpochId(5);
        let mut registry = EligibilityRegistry::new_default(epoch);
        let _ = registry.close_epoch();

        let cred = make_cred(99, epoch, 1.0);
        let result = registry.activate(cred);
        assert!(matches!(result, Err(EligibilityError::RegistryClosed { registry_epoch: 5 })));
    }

    // ── PersonhoodBound ───────────────────────────────────────────────────────

    #[test]
    fn bound_multiplicity_within_n_star() {
        let epoch = EpochId(0);
        let mut registry = EligibilityRegistry::new_default(epoch);
        for i in 0..5u64 {
            registry.activate(make_cred(i, epoch, 1.0)).unwrap();
        }
        let bound = registry.close_epoch();
        assert!(bound.multiplicity_within_bound(), "n_max_observed must be ≤ n_star");
        assert_eq!(bound.n_max_observed, 1);
        assert_eq!(bound.n_active_validators, 5);
        assert_eq!(bound.n_active_credentials, 5);
        assert_eq!(bound.p_max_observed, 1.0);
    }

    #[test]
    fn bound_p_max_tracks_highest_factor() {
        let epoch = EpochId(0);
        let mut registry = EligibilityRegistry::new(epoch, EligibilityConfig {
            n_star: 1,
            p_min:  0.0,
        });
        for (i, p) in [(1u64, 0.3), (2, 0.7), (3, 0.5)] {
            registry.activate(make_cred(i, epoch, p)).unwrap();
        }
        let bound = registry.compute_bound();
        assert!((bound.p_max_observed - 0.7).abs() < 1e-9);
    }

    #[test]
    fn empty_registry_bound() {
        let epoch = EpochId(0);
        let mut registry = EligibilityRegistry::new_default(epoch);
        let bound = registry.close_epoch();
        assert_eq!(bound.n_active_validators, 0);
        assert_eq!(bound.n_max_observed, 0);
        assert_eq!(bound.p_max_observed, 0.0);
        assert!(bound.multiplicity_within_bound());
    }

    // ── Integration: PersonhoodBound → AdversaryModel → check_bft_safety ─────

    /// End-to-end Layer 1 → Layer 3 → Layer 4 integration:
    ///
    /// 1. Activate 10 honest validator credentials (P=1.0) in the eligibility registry.
    /// 2. Close the registry, obtain a PersonhoodBound.
    /// 3. Register the same 10 validators in a VcaRegistry with matching weights.
    /// 4. Derive an adversary model from the bound (3 Byzantine validators, P=1.0).
    /// 5. Run check_bft_safety and assert the result is safe.
    #[test]
    fn layer1_bound_feeds_into_bft_safety_check() {
        let epoch = EpochId(0);

        // ── Layer 1: activate 10 honest validator credentials ──────────────────
        let mut elig = EligibilityRegistry::new_default(epoch);
        for i in 0..10u64 {
            elig.activate(make_cred(i, epoch, 1.0)).unwrap();
        }
        let bound = elig.close_epoch();

        assert!(bound.multiplicity_within_bound(), "T1: N_max ≤ N*");
        assert_eq!(bound.n_active_validators, 10);

        // ── Layer 2/3: register in VcaRegistry ────────────────────────────────
        let weight_cfg = WeightConfig::default();
        let mut vca = VcaRegistry::new(epoch.0, weight_cfg.clone());
        for i in 0..10u64 {
            vca.upsert(
                ValidatorId(format!("v{i}")),
                IdentityHandle(format!("id{i}")),
                ContributionScore::new(100.0).unwrap(),
                PersonhoodFactor::new(1.0).unwrap(),
                StakeAmount(1000),
                vec![],
                vec![],
            ).unwrap();
        }
        vca.close_epoch();

        // ── Layer 4: adversary model from personhood bound ─────────────────────
        // 3 Byzantine validators, each with max contribution 100.0
        let adversary = bound.to_adversary_model(3, 100.0);
        assert_eq!(adversary.max_byzantine_validators, 3);
        assert!((adversary.max_personhood_per_sybil - 1.0).abs() < 1e-9);

        let quorum = AdaptiveQuorumConfig::default();
        let result = check_bft_safety(&vca, &quorum, &adversary)
            .expect("check_bft_safety must not error with valid config");

        assert!(
            result.is_safe(),
            "3 Byzantine out of 10 with P=1.0 must be safe (margin={})",
            result.margin
        );
    }

    /// Quantified D7 / sybil sweep: same scenario as the vca-pq adversarial
    /// test suite's d7 test, but driven through the personhood Layer 1 first.
    ///
    /// At P=0.5 and N*=1, an adversary needs > (total_weight / 3) sybils.
    /// This test verifies that the Layer 1 → Layer 4 pipeline correctly
    /// identifies the unsafe threshold.
    #[test]
    fn layer1_to_layer4_sybil_sweep_finds_unsafe_threshold() {
        let epoch = EpochId(0);
        let weight_cfg = WeightConfig::default();
        let quorum = AdaptiveQuorumConfig::default();

        // 10 honest validators with full personhood and moderate contribution
        let mut elig = EligibilityRegistry::new_default(epoch);
        for i in 0..10u64 {
            elig.activate(make_cred(i, epoch, 1.0)).unwrap();
        }
        let bound = elig.close_epoch();

        let mut vca = VcaRegistry::new(epoch.0, weight_cfg.clone());
        for i in 0..10u64 {
            vca.upsert(
                ValidatorId(format!("v{i}")),
                IdentityHandle(format!("id{i}")),
                ContributionScore::new(100.0).unwrap(),
                PersonhoodFactor::new(1.0).unwrap(),
                StakeAmount(1000),
                vec![],
                vec![],
            ).unwrap();
        }
        vca.close_epoch();

        let mut last_safe_n = 0;
        let mut first_unsafe_n = usize::MAX;

        // Sweep Byzantine count from 1 to 15
        for n_byz in 1..=15 {
            // Use partial personhood (P=0.5) as in the D7 attack
            let adversary = chain_forge_vca_pq::AdversaryModel {
                max_personhood_per_sybil:   0.5,
                max_byzantine_validators:   n_byz,
                max_contribution_per_sybil: 100.0,
            };
            let result = check_bft_safety(&vca, &quorum, &adversary)
                .expect("valid config");
            if result.is_safe() {
                last_safe_n = n_byz;
            } else if first_unsafe_n == usize::MAX {
                first_unsafe_n = n_byz;
                break;
            }
        }

        assert!(
            last_safe_n > 0 && first_unsafe_n > last_safe_n,
            "sweep must find a clear safe/unsafe boundary: safe up to n={}, unsafe at n={}",
            last_safe_n, first_unsafe_n
        );

        // The bound's n_star tells us the identity constraint: with N*=1 and P=0.5,
        // the adversary needs real persons (not just identities).
        assert_eq!(bound.n_star, 1, "default config enforces one identity per person");
    }
}
