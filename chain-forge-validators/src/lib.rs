/// chain-forge-validators
///
/// Validator registration and key management for QCB Chain.
///
/// This is the module that makes the whitepaper's central claim testable:
/// "validator voting power is weighted by verified personhood, not stake."
///
/// The workflow:
///   1. A verified human submits a RegistrationRequest (keys + commission + stake)
///   2. ValidatorRegistry records them as a Candidate
///   3. When their PoP identity is confirmed, they enter the ActiveSet
///   4. The consensus engine receives a ValidatorSet derived from the ActiveSet
///   5. apply_personhood_cap() enforces the power ceiling per human (Section 3.3)
///
/// Lifecycle:
///   Candidate → Active → (Jailed) → Active | Tombstoned
///
/// Key design: stake determines reward eligibility and participation;
/// personhood determines actual consensus influence. These are separated
/// by design (Section 3.3). A whale can bond more QCB for yield but cannot
/// convert that into disproportionate block production power.
///
/// Whitepaper refs: Sections 3, 3.3, 6.3, Q6 (slashing), Q14 (liveness).

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use chain_forge_consensus::{ValidatorId, ValidatorInfo, ValidatorSet, PersonhoodConfig};
use chain_forge_identity::VerificationTier;

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ValidatorError {
    #[error("validator {0} not found")]
    NotFound(String),

    #[error("validator {0} already registered")]
    AlreadyRegistered(String),

    #[error("insufficient stake: have {have} uqcb, need {need} uqcb")]
    InsufficientStake { have: u128, need: u128 },

    #[error("validator {0} is tombstoned and cannot re-register")]
    Tombstoned(String),

    #[error("validator {0} is jailed: {reason}")]
    Jailed { id: String, reason: String },

    #[error("commission rate {rate} exceeds maximum {max}")]
    CommissionTooHigh { rate: u32, max: u32 },

    #[error("commission change too soon: must wait {wait_epochs} more epochs")]
    CommissionChangeTooSoon { wait_epochs: u64 },

    #[error("key bundle invalid: {0}")]
    InvalidKeyBundle(String),

    #[error("internal validator error: {0}")]
    Internal(String),
}

pub type ValResult<T> = Result<T, ValidatorError>;

// -- StakeTier ----------------------------------------------------------------

/// Minimum bond tiers for validator participation (Section 3.3 / tokenomics).
///
/// These thresholds gate *participation and yield*, not consensus influence.
/// A human with the minimum stake has the same voting power as one with
/// maximum stake — the power cap is applied after tier qualification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeTier {
    /// Minimum stake — can participate as a validator candidate.
    /// 1,000 QCB = 1_000_000_000 uqcb (6 decimals).
    Entry,
    /// Standard stake — higher reward share.
    /// 10,000 QCB.
    Standard,
    /// Full stake — maximum reward share, governance weight.
    /// 100,000 QCB.
    Full,
}

/// Minimum bond in uqcb for each tier.
pub const ENTRY_STAKE_UQCB:    u128 = 1_000     * 1_000_000;
pub const STANDARD_STAKE_UQCB: u128 = 10_000    * 1_000_000;
pub const FULL_STAKE_UQCB:     u128 = 100_000   * 1_000_000;

impl StakeTier {
    pub fn from_bonded(uqcb: u128) -> Option<Self> {
        if uqcb >= FULL_STAKE_UQCB {
            Some(Self::Full)
        } else if uqcb >= STANDARD_STAKE_UQCB {
            Some(Self::Standard)
        } else if uqcb >= ENTRY_STAKE_UQCB {
            Some(Self::Entry)
        } else {
            None
        }
    }

    pub fn minimum_uqcb(&self) -> u128 {
        match self {
            Self::Entry    => ENTRY_STAKE_UQCB,
            Self::Standard => STANDARD_STAKE_UQCB,
            Self::Full     => FULL_STAKE_UQCB,
        }
    }

    /// Reward multiplier relative to Entry (basis points, 10000 = 1x).
    pub fn reward_multiplier_bps(&self) -> u64 {
        match self {
            Self::Entry    => 10_000,  // 1.0×
            Self::Standard => 12_500,  // 1.25×
            Self::Full     => 15_000,  // 1.5×
        }
    }
}

// -- ValidatorStatus ----------------------------------------------------------

/// Lifecycle state of a registered validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Registered, stake bonded, but not yet PoP-verified.
    /// Voting power = 0 in the active set.
    Candidate,
    /// PoP-verified, in the active consensus set.
    Active,
    /// Temporarily removed from the active set.
    /// Cause recorded in JailRecord. Can be unjailed after penalty.
    Jailed,
    /// Permanently removed. Cannot re-register.
    /// Reserved for double-signing (equivocation).
    Tombstoned,
}

impl std::fmt::Display for ValidatorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Candidate  => write!(f, "Candidate"),
            Self::Active     => write!(f, "Active"),
            Self::Jailed     => write!(f, "Jailed"),
            Self::Tombstoned => write!(f, "Tombstoned"),
        }
    }
}

// -- KeyBundle ----------------------------------------------------------------

/// The set of cryptographic keys a validator must register.
///
/// Separation of concerns:
///   - consensus_pubkey: signs block proposals and votes (hot key, online)
///   - account_address:  receives staking rewards (can be cold)
///   - pqc_pubkey:       optional post-quantum key (Section 10, Phase 1+)
///
/// In Phase 0 these are hex-encoded stub keys. The SchemeRegistry
/// (chain-forge-crypto) governs which scheme is active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    /// Public key used for signing consensus messages.
    /// Hex-encoded. 32 bytes for Ed25519, 1952 for ML-DSA, 1984 for hybrid.
    pub consensus_pubkey: String,
    /// The validator's reward address (bech32 qcb1...).
    pub account_address:  String,
    /// Optional PQC public key. Required once the SchemeRegistry
    /// migrates to a PQC-only scheme (Section 10.3 / Q16).
    pub pqc_pubkey:       Option<String>,
    /// Which signature scheme this key bundle uses.
    pub scheme:           String,
}

impl KeyBundle {
    pub fn new_ed25519(consensus_pubkey: &str, account_address: &str) -> Self {
        Self {
            consensus_pubkey: consensus_pubkey.to_string(),
            account_address:  account_address.to_string(),
            pqc_pubkey:       None,
            scheme:           "Ed25519".to_string(),
        }
    }

    pub fn new_hybrid(
        consensus_pubkey: &str,
        account_address:  &str,
        pqc_pubkey:       &str,
    ) -> Self {
        Self {
            consensus_pubkey: consensus_pubkey.to_string(),
            account_address:  account_address.to_string(),
            pqc_pubkey:       Some(pqc_pubkey.to_string()),
            scheme:           "HybridEd25519MlDsa".to_string(),
        }
    }

    pub fn validate(&self) -> ValResult<()> {
        if self.consensus_pubkey.is_empty() {
            return Err(ValidatorError::InvalidKeyBundle(
                "consensus_pubkey is empty".into()
            ));
        }
        if !self.account_address.starts_with("qcb1") {
            return Err(ValidatorError::InvalidKeyBundle(format!(
                "account_address must start with qcb1, got '{}'",
                self.account_address
            )));
        }
        Ok(())
    }
}

// -- Commission ---------------------------------------------------------------

/// Validator commission configuration.
///
/// Commission is the fraction of delegator rewards the validator keeps.
/// Bounded by MAX_COMMISSION_RATE_BPS and subject to a change delay
/// to protect delegators from sudden increases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commission {
    /// Current rate in basis points (100 bps = 1%). Max 2000 (20%).
    pub rate_bps: u32,
    /// Max rate this validator will ever charge (declared at registration,
    /// cannot be increased — only the current rate can change within it).
    pub max_rate_bps: u32,
    /// Epoch of the most recent rate change.
    pub last_changed_epoch: u64,
}

/// Maximum commission rate: 20%.
pub const MAX_COMMISSION_RATE_BPS: u32 = 2_000;
/// Minimum epochs between commission rate changes (protects delegators).
pub const COMMISSION_CHANGE_DELAY_EPOCHS: u64 = 7;

impl Commission {
    pub fn new(rate_bps: u32, max_rate_bps: u32) -> ValResult<Self> {
        if max_rate_bps > MAX_COMMISSION_RATE_BPS {
            return Err(ValidatorError::CommissionTooHigh {
                rate: max_rate_bps,
                max:  MAX_COMMISSION_RATE_BPS,
            });
        }
        if rate_bps > max_rate_bps {
            return Err(ValidatorError::CommissionTooHigh {
                rate: rate_bps,
                max:  max_rate_bps,
            });
        }
        Ok(Self { rate_bps, max_rate_bps, last_changed_epoch: 0 })
    }

    pub fn update_rate(&mut self, new_rate_bps: u32, epoch: u64) -> ValResult<()> {
        if new_rate_bps > self.max_rate_bps {
            return Err(ValidatorError::CommissionTooHigh {
                rate: new_rate_bps,
                max:  self.max_rate_bps,
            });
        }
        let elapsed = epoch.saturating_sub(self.last_changed_epoch);
        if elapsed < COMMISSION_CHANGE_DELAY_EPOCHS {
            return Err(ValidatorError::CommissionChangeTooSoon {
                wait_epochs: COMMISSION_CHANGE_DELAY_EPOCHS - elapsed,
            });
        }
        self.rate_bps          = new_rate_bps;
        self.last_changed_epoch = epoch;
        Ok(())
    }
}

// -- JailRecord ---------------------------------------------------------------

/// Why a validator was jailed and for how long.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailRecord {
    pub reason:       String,
    pub jailed_epoch: u64,
    /// Earliest epoch at which unjailing is permitted.
    pub unjail_after: u64,
    /// Number of times this validator has been jailed.
    pub jail_count:   u32,
}

// -- ValidatorRecord ----------------------------------------------------------

/// Full on-chain state for one registered validator.
///
/// This is the AEI equivalent for validators: the authoritative record
/// of who a validator is, what they've staked, what their current status
/// is, and what their personhood verification says.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRecord {
    /// Unique validator ID (matches consensus ValidatorId).
    pub id:               ValidatorId,
    /// Cryptographic keys registered by this validator.
    pub keys:             KeyBundle,
    /// Commission configuration.
    pub commission:       Commission,
    /// Total bonded stake in uqcb.
    pub bonded_uqcb:      u128,
    /// Stake tier derived from bonded amount.
    pub stake_tier:       Option<StakeTier>,
    /// Current lifecycle status.
    pub status:           ValidatorStatus,
    /// Whether the identity layer has confirmed this validator as human.
    /// This gates entry into the active set and voting power assignment.
    pub pop_verified:     bool,
    /// Verification tier from chain-forge-identity.
    pub verification_tier: Option<VerificationTier>,
    /// Epoch of registration.
    pub registered_epoch: u64,
    /// Epoch of last status change.
    pub last_status_epoch: u64,
    /// Blocks proposed by this validator (for performance tracking).
    pub blocks_proposed:  u64,
    /// Blocks missed in recent window (for liveness tracking, Q14).
    pub blocks_missed:    u64,
    /// Jail history (slashing prerequisite, Q6).
    pub jail_records:     Vec<JailRecord>,
    /// Human-readable moniker (display name).
    pub moniker:          String,
    /// Optional website or contact URI.
    pub website:          Option<String>,
}

impl ValidatorRecord {
    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Active
    }

    pub fn is_eligible_for_active_set(&self) -> bool {
        self.pop_verified
            && self.status == ValidatorStatus::Candidate
            && self.stake_tier.is_some()
    }

    /// Voting power to assign in the consensus ValidatorSet.
    /// Non-verified validators get 0 power regardless of stake.
    pub fn consensus_power(&self) -> u64 {
        if self.pop_verified && self.status == ValidatorStatus::Active {
            1 // Equal per-human weight; apply_personhood_cap handles the ceiling
        } else {
            0
        }
    }

    /// Activate this validator (Candidate -> Active).
    pub fn activate(&mut self, epoch: u64) {
        self.status            = ValidatorStatus::Active;
        self.last_status_epoch = epoch;
        tracing::info!(
            id     = %self.id,
            moniker = %self.moniker,
            stake  = self.bonded_uqcb,
            "validator activated"
        );
    }

    /// Jail this validator.
    pub fn jail(&mut self, reason: &str, epoch: u64, jail_duration_epochs: u64) {
        self.jail_records.push(JailRecord {
            reason:       reason.to_string(),
            jailed_epoch: epoch,
            unjail_after: epoch + jail_duration_epochs,
            jail_count:   self.jail_records.len() as u32 + 1,
        });
        self.status            = ValidatorStatus::Jailed;
        self.last_status_epoch = epoch;
        tracing::warn!(id = %self.id, reason, "validator jailed");
    }

    /// Unjail (return to Candidate; must re-verify to become Active again).
    pub fn unjail(&mut self, epoch: u64) -> ValResult<()> {
        if self.status != ValidatorStatus::Jailed {
            return Err(ValidatorError::Internal(
                format!("{} is not jailed", self.id)
            ));
        }
        if let Some(last) = self.jail_records.last() {
            if epoch < last.unjail_after {
                return Err(ValidatorError::Jailed {
                    id:     self.id.0.clone(),
                    reason: format!(
                        "cannot unjail until epoch {} (currently {})",
                        last.unjail_after, epoch
                    ),
                });
            }
        }
        self.status            = ValidatorStatus::Candidate;
        self.last_status_epoch = epoch;
        tracing::info!(id = %self.id, "validator unjailed -> Candidate");
        Ok(())
    }

    /// Tombstone permanently (double-sign equivocation).
    pub fn tombstone(&mut self, epoch: u64) {
        self.status            = ValidatorStatus::Tombstoned;
        self.last_status_epoch = epoch;
        tracing::error!(id = %self.id, "validator tombstoned (equivocation)");
    }
}

// -- RegistrationRequest ------------------------------------------------------

/// What a candidate submits to register as a validator.
pub struct RegistrationRequest {
    /// Desired validator ID (must be unique).
    pub id:           ValidatorId,
    /// Human-readable name.
    pub moniker:      String,
    /// Cryptographic keys.
    pub keys:         KeyBundle,
    /// Commission configuration.
    pub commission:   Commission,
    /// Initial bonded stake in uqcb.
    pub bonded_uqcb:  u128,
    /// Optional website.
    pub website:      Option<String>,
}

// -- ValidatorRegistry --------------------------------------------------------

/// The authoritative registry of all validators on QCB Chain.
///
/// This is the on-chain module that bridges:
///   - chain-forge-identity (who is a verified human?)
///   - chain-forge-tokenomics (how much is staked?)
///   - chain-forge-consensus (who is in the active ValidatorSet?)
///
/// The registry enforces QCB's core separation:
///   stake → reward share + tier
///   personhood → voting power (via consensus ValidatorSet)
pub struct ValidatorRegistry {
    validators:   HashMap<String, ValidatorRecord>,
    /// Index: consensus pubkey -> validator ID.
    by_pubkey:    HashMap<String, String>,
    /// Index: account address -> validator ID.
    by_address:   HashMap<String, String>,
    /// Minimum stake required to register.
    min_stake_uqcb: u128,
    /// PersonhoodConfig applied when building the ValidatorSet.
    personhood_config: PersonhoodConfig,
    /// Minimum liveness window: if missed_blocks / recent_blocks > this,
    /// the validator is a candidate for jailing (Q14).
    pub liveness_threshold: f64,
    /// How long a jailed validator must wait before unjailing (epochs).
    pub jail_duration_epochs: u64,
}

impl ValidatorRegistry {
    pub fn new(min_stake_uqcb: u128, personhood_config: PersonhoodConfig) -> Self {
        Self {
            validators:          HashMap::new(),
            by_pubkey:           HashMap::new(),
            by_address:          HashMap::new(),
            min_stake_uqcb,
            personhood_config,
            liveness_threshold:  0.05, // >5% missed blocks triggers jail warning
            jail_duration_epochs: 10,
        }
    }

    /// Default configuration for QCB Chain devnet.
    pub fn qcb_devnet() -> Self {
        Self::new(
            ENTRY_STAKE_UQCB,
            PersonhoodConfig {
                power_cap:          1,
                reject_expired_pop: true,
                min_verified_pct:   67,
            },
        )
    }

    // -- Registration ---------------------------------------------------------

    /// Register a new validator candidate.
    pub fn register(&mut self, req: RegistrationRequest, epoch: u64) -> ValResult<()> {
        let id_str = req.id.0.clone();

        if let Some(existing) = self.validators.get(&id_str) {
            if existing.status == ValidatorStatus::Tombstoned {
                return Err(ValidatorError::Tombstoned(id_str));
            }
            return Err(ValidatorError::AlreadyRegistered(id_str));
        }

        if req.bonded_uqcb < self.min_stake_uqcb {
            return Err(ValidatorError::InsufficientStake {
                have: req.bonded_uqcb,
                need: self.min_stake_uqcb,
            });
        }

        req.keys.validate()?;

        // Duplicate key check
        if self.by_pubkey.contains_key(&req.keys.consensus_pubkey) {
            return Err(ValidatorError::InvalidKeyBundle(
                "consensus_pubkey already registered to another validator".into()
            ));
        }

        let stake_tier = StakeTier::from_bonded(req.bonded_uqcb);

        let record = ValidatorRecord {
            id:                req.id.clone(),
            keys:              req.keys.clone(),
            commission:        req.commission,
            bonded_uqcb:       req.bonded_uqcb,
            stake_tier,
            status:            ValidatorStatus::Candidate,
            pop_verified:      false,
            verification_tier: None,
            registered_epoch:  epoch,
            last_status_epoch: epoch,
            blocks_proposed:   0,
            blocks_missed:     0,
            jail_records:      Vec::new(),
            moniker:           req.moniker,
            website:           req.website,
        };

        self.by_pubkey.insert(req.keys.consensus_pubkey, id_str.clone());
        self.by_address.insert(req.keys.account_address, id_str.clone());
        self.validators.insert(id_str.clone(), record);

        tracing::info!(
            id    = %req.id,
            stake = req.bonded_uqcb,
            epoch,
            "validator candidate registered"
        );
        Ok(())
    }

    /// Register a genesis validator without the full stake/key requirements.
    ///
    /// Genesis validators are the founding set whose identity was established
    /// during chain genesis. They don't yet hold real cryptographic key bundles
    /// (those are added as validators come online) and they receive their stake
    /// from the genesis state rather than a bonding transaction, so the normal
    /// registration path — which enforces stake threshold and key validity —
    /// would block them. This method inserts a minimal Candidate record so
    /// `confirm_pop` can activate them once their identity is verified.
    ///
    /// No-ops if the validator is already registered (idempotent, safe to call
    /// from genesis seeding loops that may run more than once).
    pub fn register_genesis_validator(&mut self, id: &str) {
        if self.validators.contains_key(id) {
            return; // already registered, no-op
        }
        let validator_id = ValidatorId(id.to_string());
        let record = ValidatorRecord {
            id:                validator_id.clone(),
            keys:              KeyBundle {
                consensus_pubkey: String::new(),
                account_address:  id.to_string(),
                pqc_pubkey:       None,
                scheme:           "genesis-stub".to_string(),
            },
            commission:        Commission {
                rate_bps:           0,
                max_rate_bps:       2000,
                last_changed_epoch: 0,
            },
            bonded_uqcb:       self.min_stake_uqcb, // treated as genesis-funded
            stake_tier:        StakeTier::from_bonded(self.min_stake_uqcb),
            status:            ValidatorStatus::Candidate,
            pop_verified:      false,
            verification_tier: None,
            registered_epoch:  0,
            last_status_epoch: 0,
            blocks_proposed:   0,
            blocks_missed:     0,
            jail_records:      Vec::new(),
            moniker:           id.to_string(),
            website:           None,
        };
        self.validators.insert(id.to_string(), record);
        tracing::info!(id, "genesis validator registered as Candidate");
    }

    // -- PoP verification gate ------------------------------------------------

    /// Called by the identity layer when a validator's PoP is confirmed.
    /// This is the personhood gate (Section 3): without this call the
    /// validator stays in Candidate with 0 voting power.
    pub fn confirm_pop(
        &mut self,
        validator_id:      &str,
        verification_tier: VerificationTier,
        epoch:             u64,
    ) -> ValResult<()> {
        let record = self.validators.get_mut(validator_id)
            .ok_or_else(|| ValidatorError::NotFound(validator_id.to_string()))?;

        record.pop_verified      = true;
        record.verification_tier = Some(verification_tier.clone());

        // Automatically activate if they are a Candidate with sufficient stake
        if record.is_eligible_for_active_set() {
            record.activate(epoch);
        }

        tracing::info!(
            id    = validator_id,
            tier  = ?verification_tier,
            "validator PoP confirmed"
        );
        Ok(())
    }

    /// Called when a validator's PoP lapses (liveness failure in identity layer).
    /// Their consensus power drops to 0; they become Candidate again.
    pub fn revoke_pop(&mut self, validator_id: &str, epoch: u64) -> ValResult<()> {
        let record = self.validators.get_mut(validator_id)
            .ok_or_else(|| ValidatorError::NotFound(validator_id.to_string()))?;

        record.pop_verified      = false;
        record.verification_tier = None;

        if record.status == ValidatorStatus::Active {
            record.status            = ValidatorStatus::Candidate;
            record.last_status_epoch = epoch;
            tracing::warn!(id = validator_id, "validator PoP lapsed -> Candidate");
        }
        Ok(())
    }

    // -- Stake management -----------------------------------------------------

    /// Update a validator's bonded stake (called by the execution layer).
    pub fn update_stake(&mut self, validator_id: &str, new_bonded: u128) -> ValResult<()> {
        let record = self.validators.get_mut(validator_id)
            .ok_or_else(|| ValidatorError::NotFound(validator_id.to_string()))?;

        record.bonded_uqcb  = new_bonded;
        record.stake_tier   = StakeTier::from_bonded(new_bonded);

        // If stake dropped below minimum, move back to Candidate
        if new_bonded < self.min_stake_uqcb && record.status == ValidatorStatus::Active {
            record.status = ValidatorStatus::Candidate;
            tracing::warn!(
                id = validator_id,
                stake = new_bonded,
                min   = self.min_stake_uqcb,
                "validator stake below minimum -> Candidate"
            );
        }
        Ok(())
    }

    // -- Commission management ------------------------------------------------

    pub fn update_commission(
        &mut self,
        validator_id:  &str,
        new_rate_bps:  u32,
        epoch:         u64,
    ) -> ValResult<()> {
        let record = self.validators.get_mut(validator_id)
            .ok_or_else(|| ValidatorError::NotFound(validator_id.to_string()))?;
        record.commission.update_rate(new_rate_bps, epoch)
    }

    // -- Jailing and tombstoning ----------------------------------------------

    pub fn jail(
        &mut self,
        validator_id: &str,
        reason:       &str,
        epoch:        u64,
    ) -> ValResult<()> {
        let record = self.validators.get_mut(validator_id)
            .ok_or_else(|| ValidatorError::NotFound(validator_id.to_string()))?;
        if record.status == ValidatorStatus::Tombstoned {
            return Ok(()); // already gone
        }
        record.jail(reason, epoch, self.jail_duration_epochs);
        Ok(())
    }

    pub fn unjail(&mut self, validator_id: &str, epoch: u64) -> ValResult<()> {
        let record = self.validators.get_mut(validator_id)
            .ok_or_else(|| ValidatorError::NotFound(validator_id.to_string()))?;
        record.unjail(epoch)
    }

    pub fn tombstone(&mut self, validator_id: &str, epoch: u64) -> ValResult<()> {
        let record = self.validators.get_mut(validator_id)
            .ok_or_else(|| ValidatorError::NotFound(validator_id.to_string()))?;
        record.tombstone(epoch);
        Ok(())
    }

    // -- Liveness tracking ----------------------------------------------------

    /// Record block production outcome for a validator.
    pub fn record_block(&mut self, validator_id: &str, proposed: bool) {
        if let Some(record) = self.validators.get_mut(validator_id) {
            if proposed {
                record.blocks_proposed += 1;
            } else {
                record.blocks_missed += 1;
            }
        }
    }

    /// Check if a validator's liveness is below threshold and should be warned.
    /// Returns the missed fraction (0.0..1.0) for the validator.
    pub fn liveness_score(&self, validator_id: &str) -> Option<f64> {
        let record = self.validators.get(validator_id)?;
        let total = record.blocks_proposed + record.blocks_missed;
        if total == 0 { return Some(0.0); }
        Some(record.blocks_missed as f64 / total as f64)
    }

    // -- Active set and ValidatorSet building ---------------------------------

    /// Build the consensus ValidatorSet from the current active validators.
    /// This is called by the node on every epoch boundary to update consensus.
    ///
    /// Key: only pop_verified Active validators appear with non-zero power.
    /// Candidates, Jailed, and Tombstoned validators are excluded.
    /// apply_personhood_cap() is applied to enforce the power ceiling.
    pub fn build_validator_set(&self, height: u64) -> ValidatorSet {
        use chain_forge_consensus::apply_personhood_cap;

        let validators: Vec<ValidatorInfo> = self.validators.values()
            .filter(|r| r.status == ValidatorStatus::Active && r.pop_verified)
            .map(|r| ValidatorInfo {
                id:           r.id.clone(),
                voting_power: r.consensus_power(),
                pop_verified: r.pop_verified,
            public_key: vec![],
            })
            .collect();

        let mut vs = ValidatorSet { height, validators };
        vs = apply_personhood_cap(vs, &self.personhood_config);
        vs
    }

    /// All active validators (for display / API).
    pub fn active_validators(&self) -> Vec<&ValidatorRecord> {
        self.validators.values()
            .filter(|r| r.status == ValidatorStatus::Active)
            .collect()
    }

    /// All registered validators regardless of status.
    pub fn all_validators(&self) -> Vec<&ValidatorRecord> {
        self.validators.values().collect()
    }

    pub fn get(&self, validator_id: &str) -> ValResult<&ValidatorRecord> {
        self.validators.get(validator_id)
            .ok_or_else(|| ValidatorError::NotFound(validator_id.to_string()))
    }

    pub fn get_by_pubkey(&self, pubkey: &str) -> Option<&ValidatorRecord> {
        self.by_pubkey.get(pubkey)
            .and_then(|id| self.validators.get(id))
    }

    pub fn total_registered(&self) -> usize { self.validators.len() }
    pub fn total_active(&self) -> usize {
        self.validators.values()
            .filter(|r| r.status == ValidatorStatus::Active)
            .count()
    }
    pub fn total_candidates(&self) -> usize {
        self.validators.values()
            .filter(|r| r.status == ValidatorStatus::Candidate)
            .count()
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ValidatorRegistry {
        ValidatorRegistry::qcb_devnet()
    }

    fn req(id: &str, addr: &str, stake: u128) -> RegistrationRequest {
        RegistrationRequest {
            id:          ValidatorId(id.to_string()),
            moniker:     format!("Validator {id}"),
            keys:        KeyBundle::new_ed25519(
                             &format!("pubkey_{id}"),
                             addr,
                         ),
            commission:  Commission::new(500, 2_000).unwrap(), // 5% rate, 20% max
            bonded_uqcb: stake,
            website:     None,
        }
    }

    // -- StakeTier tests ------------------------------------------------------

    #[test]
    fn stake_tiers_derived_from_bonded() {
        assert_eq!(StakeTier::from_bonded(0), None);
        assert_eq!(StakeTier::from_bonded(ENTRY_STAKE_UQCB - 1), None);
        assert_eq!(StakeTier::from_bonded(ENTRY_STAKE_UQCB), Some(StakeTier::Entry));
        assert_eq!(StakeTier::from_bonded(STANDARD_STAKE_UQCB), Some(StakeTier::Standard));
        assert_eq!(StakeTier::from_bonded(FULL_STAKE_UQCB), Some(StakeTier::Full));
    }

    #[test]
    fn full_tier_has_highest_reward_multiplier() {
        assert!(StakeTier::Full.reward_multiplier_bps() > StakeTier::Standard.reward_multiplier_bps());
        assert!(StakeTier::Standard.reward_multiplier_bps() > StakeTier::Entry.reward_multiplier_bps());
    }

    // -- Commission tests -----------------------------------------------------

    #[test]
    fn commission_rejects_rate_above_max() {
        assert!(Commission::new(500, 3_000).is_err()); // max exceeds 20%
        assert!(Commission::new(2_500, 2_000).is_err()); // rate > max
    }

    #[test]
    fn commission_change_requires_delay() {
        let mut c = Commission::new(500, 2_000).unwrap();
        c.last_changed_epoch = 0;
        assert!(c.update_rate(600, 3).is_err()); // only 3 epochs elapsed, need 7
        assert!(c.update_rate(600, 7).is_ok());  // exactly 7 epochs
    }

    #[test]
    fn commission_cannot_exceed_declared_max() {
        let mut c = Commission::new(500, 1_000).unwrap();
        c.last_changed_epoch = 0;
        assert!(c.update_rate(1_500, 10).is_err()); // 15% > 10% max
        assert!(c.update_rate(1_000, 10).is_ok());  // exactly at max
    }

    // -- KeyBundle tests ------------------------------------------------------

    #[test]
    fn key_bundle_requires_qcb1_prefix() {
        let bad = KeyBundle::new_ed25519("pk_abc", "cosmos1xyz");
        assert!(bad.validate().is_err());
    }

    #[test]
    fn key_bundle_rejects_empty_pubkey() {
        let bad = KeyBundle::new_ed25519("", "qcb1alice");
        assert!(bad.validate().is_err());
    }

    #[test]
    fn hybrid_key_bundle_records_pqc_key() {
        let kb = KeyBundle::new_hybrid("ed_pk", "qcb1alice", "mldsa_pk");
        assert_eq!(kb.scheme, "HybridEd25519MlDsa");
        assert!(kb.pqc_pubkey.is_some());
        assert!(kb.validate().is_ok());
    }

    // -- Registration tests ---------------------------------------------------

    #[test]
    fn register_candidate_with_entry_stake() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();

        assert_eq!(reg.total_registered(), 1);
        assert_eq!(reg.total_candidates(), 1);
        assert_eq!(reg.total_active(), 0); // no PoP yet

        let r = reg.get("val1").unwrap();
        assert_eq!(r.status, ValidatorStatus::Candidate);
        assert!(!r.pop_verified);
        assert_eq!(r.stake_tier, Some(StakeTier::Entry));
        assert_eq!(r.consensus_power(), 0); // no power without PoP
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        assert!(reg.register(req("val1", "qcb1val1b", ENTRY_STAKE_UQCB), 0).is_err());
    }

    #[test]
    fn duplicate_consensus_key_rejected() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();

        // Different ID but same pubkey
        let mut req2 = req("val2", "qcb1val2", ENTRY_STAKE_UQCB);
        req2.keys.consensus_pubkey = "pubkey_val1".into(); // duplicate
        assert!(reg.register(req2, 0).is_err());
    }

    #[test]
    fn insufficient_stake_rejected() {
        let mut reg = registry();
        let result = reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB - 1), 0);
        assert!(result.is_err());
    }

    // -- PoP verification gate tests ------------------------------------------

    #[test]
    fn pop_confirmation_activates_candidate() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        assert_eq!(reg.total_active(), 0);

        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();

        assert_eq!(reg.total_active(), 1);
        assert_eq!(reg.total_candidates(), 0);
        let r = reg.get("val1").unwrap();
        assert!(r.pop_verified);
        assert_eq!(r.status, ValidatorStatus::Active);
        assert_eq!(r.consensus_power(), 1);
    }

    #[test]
    fn pop_revocation_demotes_to_candidate() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();
        assert_eq!(reg.total_active(), 1);

        reg.revoke_pop("val1", 5).unwrap();
        assert_eq!(reg.total_active(), 0);
        assert_eq!(reg.get("val1").unwrap().status, ValidatorStatus::Candidate);
        assert_eq!(reg.get("val1").unwrap().consensus_power(), 0);
    }

    // -- ValidatorSet building ------------------------------------------------

    #[test]
    fn validator_set_excludes_candidates() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.register(req("val2", "qcb1val2", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();
        // val2 stays Candidate

        let vs = reg.build_validator_set(1);
        assert_eq!(vs.validators.len(), 1);
        assert_eq!(vs.validators[0].id.0, "val1");
    }

    #[test]
    fn validator_set_applies_personhood_cap() {
        let mut reg = ValidatorRegistry::new(
            ENTRY_STAKE_UQCB,
            PersonhoodConfig {
                power_cap:          1,
                reject_expired_pop: false,
                min_verified_pct:   0,
            },
        );
        // Register 3 validators with varying stake -- all should get power = 1
        for (id, addr, stake) in [
            ("v1", "qcb1v1", FULL_STAKE_UQCB),    // 100k QCB
            ("v2", "qcb1v2", STANDARD_STAKE_UQCB), // 10k QCB
            ("v3", "qcb1v3", ENTRY_STAKE_UQCB),    // 1k QCB
        ] {
            reg.register(req(id, addr, stake), 0).unwrap();
            reg.confirm_pop(id, VerificationTier::Verified, 1).unwrap();
        }
        let vs = reg.build_validator_set(1);
        assert_eq!(vs.validators.len(), 3);
        // All three have power = 1 regardless of stake (personhood cap)
        for v in &vs.validators {
            assert_eq!(v.voting_power, 1,
                "stake must not grant extra voting power: {}",
                v.id.0);
        }
    }

    // -- Jailing and tombstoning ----------------------------------------------

    #[test]
    fn jailed_validator_excluded_from_active_set() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();
        assert_eq!(reg.total_active(), 1);

        reg.jail("val1", "missed blocks", 5).unwrap();
        assert_eq!(reg.total_active(), 0);
        assert_eq!(reg.get("val1").unwrap().status, ValidatorStatus::Jailed);
    }

    #[test]
    fn unjail_before_delay_fails() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();
        reg.jail("val1", "test", 5).unwrap(); // jailed at epoch 5

        assert!(reg.unjail("val1", 6).is_err()); // too soon (need epoch 15)
        assert!(reg.unjail("val1", 15).is_ok()); // ok
    }

    #[test]
    fn tombstoned_validator_cannot_reregister() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();
        reg.tombstone("val1", 10).unwrap();

        let result = reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 11);
        assert!(result.is_err(), "tombstoned validators cannot re-register");
    }

    // -- Liveness tracking ----------------------------------------------------

    #[test]
    fn liveness_score_tracks_missed_blocks() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();

        // 8 proposed, 2 missed -> 20% miss rate
        for _ in 0..8 { reg.record_block("val1", true); }
        for _ in 0..2 { reg.record_block("val1", false); }

        let score = reg.liveness_score("val1").unwrap();
        assert!((score - 0.20).abs() < 0.001,
            "expected 20% miss rate, got {score:.2}");
    }

    #[test]
    fn stake_update_demotes_if_below_minimum() {
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();
        assert_eq!(reg.total_active(), 1);

        reg.update_stake("val1", ENTRY_STAKE_UQCB - 1).unwrap();
        assert_eq!(reg.get("val1").unwrap().status, ValidatorStatus::Candidate,
            "dropping below minimum stake must demote to Candidate");
    }

    #[test]
    fn multiple_validators_correct_active_count() {
        let mut reg = registry();
        for i in 1..=5 {
            reg.register(req(&format!("v{i}"), &format!("qcb1v{i}"),
                ENTRY_STAKE_UQCB), 0).unwrap();
        }
        // Only confirm 3
        for i in 1..=3 {
            reg.confirm_pop(&format!("v{i}"),
                VerificationTier::Verified, 1).unwrap();
        }
        assert_eq!(reg.total_active(), 3);
        assert_eq!(reg.total_candidates(), 2);

        let vs = reg.build_validator_set(1);
        assert_eq!(vs.validators.len(), 3);
    }
}
