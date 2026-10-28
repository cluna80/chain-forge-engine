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

    #[error("verification tier {tier} does not grant consensus for validator {id}")]
    IneligibleTier { id: String, tier: String },
}

pub type ValResult<T> = Result<T, ValidatorError>;

/// Minimal hex helpers -- `KeyBundle.consensus_pubkey` is stored hex-encoded
/// (see its doc comment), and CF-VAL-KEY-002's key registration needs to
/// convert between that and the raw bytes `chain_forge_consensus::ValidatorInfo`
/// and the crypto scheme actually operate on. No external hex dependency is
/// pulled in for two tiny, allocation-free functions.
fn hex_encode_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

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
    /// Monotonically increasing sequence number assigned at registration time.
    /// Used as a stable tiebreaker when two validators share the same
    /// `registered_epoch` (e.g. both registered at epoch 0): lower sequence =
    /// registered first → gets priority for the per-human power cap.
    pub registration_seq: u64,
    /// Epoch of last status change.
    pub last_status_epoch: u64,
    /// Blocks proposed by this validator (cumulative lifetime).
    pub blocks_proposed:  u64,
    /// Blocks missed in recent window (cumulative lifetime, for liveness tracking, Q14).
    pub blocks_missed:    u64,
    /// Blocks signed in the current epoch (reset at each epoch boundary).
    #[serde(default)]
    pub epoch_blocks_signed: u64,
    /// Epoch in which epoch_blocks_signed was last reset.
    #[serde(default)]
    pub epoch_counter_epoch: u64,
    /// Jail history (slashing prerequisite, Q6).
    pub jail_records:     Vec<JailRecord>,
    /// Human-readable moniker (display name).
    pub moniker:          String,
    /// Optional website or contact URI.
    pub website:          Option<String>,
    /// The identity address of the *human* who controls this validator.
    ///
    /// This is the personhood-weighting link (Section 3.3): a single verified
    /// human may operate multiple validator addresses (e.g., for redundancy or
    /// stake partitioning), but their combined voting power may not exceed
    /// `PersonhoodConfig::power_cap`. Without this field, `apply_personhood_cap`
    /// operates per-`ValidatorInfo` entry and a multi-validator human bypasses
    /// the cap by registering two entries.
    ///
    /// When `None`, the validator is treated as its own owner (`id.0` is used
    /// as the owner key). This preserves backward compatibility for genesis
    /// validators and the existing test suite.
    pub owner_identity_id: Option<String>,
    /// True only for validators registered by `register_genesis_validator()`.
    /// Cannot be set through any post-genesis transaction path. Used by the
    /// per-block PoP refresh in node.rs to distinguish genesis validators
    /// (which check their own identity) from post-genesis validators (which
    /// must have an authenticated owner binding via StateStore).
    #[serde(default)]
    pub is_genesis: bool,
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
    /// A stored verification tier that does not satisfy `grants_consensus()`
    /// also produces zero power — defense-in-depth against stale state.
    pub fn consensus_power(&self) -> u64 {
        let tier_eligible = self.verification_tier
            .as_ref()
            .map(|t| t.grants_consensus())
            .unwrap_or(false);
        if self.pop_verified && self.status == ValidatorStatus::Active && tier_eligible {
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
    /// The identity address of the controlling human (Section 3.3).
    /// When `None`, defaults to the validator's own `id` at set-build time.
    pub owner_identity_id: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistry {
    validators:   HashMap<String, ValidatorRecord>,
    /// Index: consensus pubkey -> validator ID.
    by_pubkey:    HashMap<String, String>,
    /// Index: account address -> validator ID.
    by_address:   HashMap<String, String>,
    /// Index: owner_identity_id -> list of validator IDs controlled by that human.
    /// Key is the effective owner key: `owner_identity_id` when set, `id.0` otherwise.
    /// Used by `build_validator_set` to enforce the per-human power cap (Section 3.3).
    validators_by_human: HashMap<String, Vec<String>>,
    /// Minimum stake required to register.
    min_stake_uqcb: u128,
    /// PersonhoodConfig applied when building the ValidatorSet.
    personhood_config: PersonhoodConfig,
    /// Minimum liveness window: if missed_blocks / recent_blocks > this,
    /// the validator is a candidate for jailing (Q14).
    pub liveness_threshold: f64,
    /// How long a jailed validator must wait before unjailing (epochs).
    pub jail_duration_epochs: u64,
    /// Monotonically increasing counter for registration order.
    /// Incremented on every successful `register()` or `register_genesis()` call.
    next_registration_seq: u64,
}

impl ValidatorRegistry {
    pub fn new(min_stake_uqcb: u128, personhood_config: PersonhoodConfig) -> Self {
        Self {
            validators:             HashMap::new(),
            by_pubkey:              HashMap::new(),
            by_address:             HashMap::new(),
            validators_by_human:    HashMap::new(),
            min_stake_uqcb,
            personhood_config,
            liveness_threshold:     0.05, // >5% missed blocks triggers jail warning
            jail_duration_epochs:   10,
            next_registration_seq:  0,
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

        let seq = self.next_registration_seq;
        self.next_registration_seq += 1;

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
            registration_seq:  seq,
            last_status_epoch: epoch,
            blocks_proposed:   0,
            blocks_missed:     0,
            epoch_blocks_signed: 0,
            epoch_counter_epoch: 0,
            jail_records:      Vec::new(),
            moniker:           req.moniker,
            website:           req.website,
            owner_identity_id: req.owner_identity_id.clone(),
            is_genesis:        false,
        };

        // Maintain per-human index for personhood cap enforcement.
        let owner_key = req.owner_identity_id.clone().unwrap_or_else(|| id_str.clone());
        self.validators_by_human
            .entry(owner_key)
            .or_default()
            .push(id_str.clone());

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
    ///
    /// # Safety / Misuse
    ///
    /// This method bypasses the stake and key requirements that `register()` enforces.
    /// It **must only be called before block 1 is produced** (i.e., during node startup
    /// from `Node::new_with_p2p_port` or equivalent genesis-initialization paths).
    ///
    /// The method panics at runtime if `highest_committed_block` > 0, so misuse from
    /// a running chain is caught immediately rather than silently. Pass the node's
    /// current committed block height so this invariant can be enforced.
    pub fn register_genesis_validator(&mut self, id: &str, highest_committed_block: u64) {
        assert_eq!(
            highest_committed_block, 0,
            "register_genesis_validator called after genesis (block {}): \
             this is a validator-creation backdoor — call it only during node startup \
             before block 1 is produced",
            highest_committed_block
        );
        if self.validators.contains_key(id) {
            return; // already registered, no-op
        }
        let validator_id = ValidatorId(id.to_string());
        let seq = self.next_registration_seq;
        self.next_registration_seq += 1;
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
            registration_seq:  seq,
            last_status_epoch: 0,
            blocks_proposed:   0,
            blocks_missed:     0,
            epoch_blocks_signed: 0,
            epoch_counter_epoch: 0,
            jail_records:      Vec::new(),
            moniker:           id.to_string(),
            website:           None,
            owner_identity_id: None, // genesis validators own themselves
            is_genesis:        true,
        };
        // Genesis validators own themselves (owner_identity_id = None → key = id).
        self.validators_by_human
            .entry(id.to_string())
            .or_default()
            .push(id.to_string());

        self.validators.insert(id.to_string(), record);
        tracing::info!(id, "genesis validator registered as Candidate");
    }

    /// Register a validator that arrived via the stake-bond admission path
    /// (`compute_stake_active_set`).  Unlike `register_genesis_validator` this
    /// may be called at any block height; unlike `register()` it does not
    /// require a pre-registered consensus key.  The validator starts as
    /// Candidate with `pop_verified=false`; `confirm_pop` / the pop_verified
    /// refresh in `propose_block` promote it once its identity is verified.
    ///
    /// This is a no-op if the validator is already registered (idempotent, same
    /// as `register_genesis_validator`).
    pub fn register_bonded_validator(
        &mut self,
        id: &str,
        bonded_uqcb: u128,
        owner_identity_id: Option<String>,
        epoch: u64,
    ) {
        if self.validators.contains_key(id) {
            return;
        }
        let validator_id = ValidatorId(id.to_string());
        let seq = self.next_registration_seq;
        self.next_registration_seq += 1;
        let record = ValidatorRecord {
            id:                validator_id.clone(),
            keys:              KeyBundle {
                consensus_pubkey: String::new(),
                account_address:  id.to_string(),
                pqc_pubkey:       None,
                scheme:           "bond-stub".to_string(),
            },
            commission:        Commission {
                rate_bps:           0,
                max_rate_bps:       2000,
                last_changed_epoch: epoch,
            },
            bonded_uqcb:       bonded_uqcb.min(u64::MAX as u128) as u128,
            stake_tier:        StakeTier::from_bonded(bonded_uqcb),
            status:            ValidatorStatus::Candidate,
            pop_verified:      false,
            verification_tier: None,
            registered_epoch:  epoch,
            registration_seq:  seq,
            last_status_epoch: epoch,
            blocks_proposed:   0,
            blocks_missed:     0,
            epoch_blocks_signed: 0,
            epoch_counter_epoch: 0,
            jail_records:      Vec::new(),
            moniker:           id.to_string(),
            website:           None,
            owner_identity_id: owner_identity_id.clone(),
            is_genesis:        false,
        };
        let human_key = owner_identity_id.as_deref().unwrap_or(id).to_string();
        self.validators_by_human
            .entry(human_key)
            .or_default()
            .push(id.to_string());
        self.validators.insert(id.to_string(), record);
        tracing::info!(id, epoch, "bonded validator registered as Candidate");
    }

    /// Register (or rotate) the authenticated consensus public key for a
    /// validator address — CF-VAL-KEY-002.
    ///
    /// This is deliberately narrow: unlike `register()`, it does not touch
    /// stake, commission, or lifecycle status. Those remain the job of
    /// `BondValidator`/`compute_stake_active_set()` (stake) and
    /// `confirm_pop()`/identity (personhood) respectively -- this method
    /// maintains exactly one thing: the authenticated binding from a
    /// validator identity to the consensus public key it has proven it
    /// controls.
    ///
    /// The caller (chain-forge-node, after executing a `RegisterValidatorKey`
    /// transaction) is responsible for having already verified that:
    ///   1. The transaction's sender signature authenticates `validator_id`
    ///      (so only that validator's own account can call this for itself --
    ///      this is what makes a replacement "authorized": nobody else's
    ///      transaction can reach this method for an address they don't
    ///      control).
    ///   2. A proof-of-possession signature over `consensus_pubkey` verified
    ///      against `consensus_pubkey` itself (so the registrant actually
    ///      holds the new key's private half, not merely its public bytes --
    ///      this is what makes registering a forged/stolen key impossible).
    ///
    /// This method itself only enforces the one invariant it is positioned
    /// to enforce: no two validators may ever share a registered consensus
    /// key (duplicate-key protection via the `by_pubkey` index, same rule
    /// `register()` already applies for first-time registration).
    ///
    /// If `validator_id` has no existing record (the common case today,
    /// since the live stake-bond admission path in `chain-forge-node`
    /// doesn't call `register()`), a minimal `Candidate` record is created
    /// so the key has somewhere to live; `bonded_uqcb`/status are left at
    /// their defaults because this method has no visibility into (and must
    /// not duplicate) the StateStore-backed bonding ledger that is the real
    /// source of truth for stake.
    pub fn register_consensus_key(
        &mut self,
        validator_id:      &str,
        consensus_pubkey:  &[u8],
        epoch:             u64,
    ) -> ValResult<()> {
        if consensus_pubkey.is_empty() {
            return Err(ValidatorError::InvalidKeyBundle(
                "consensus_pubkey must not be empty".into()
            ));
        }
        let hex_key = hex_encode_bytes(consensus_pubkey);

        // Duplicate-key protection: the same consensus key may not be
        // registered for two different validator identities.
        if let Some(existing_owner) = self.by_pubkey.get(&hex_key) {
            if existing_owner != validator_id {
                return Err(ValidatorError::InvalidKeyBundle(format!(
                    "consensus_pubkey already registered to validator {existing_owner} \
                     -- cannot also register it to {validator_id}"
                )));
            }
            // Re-registering the exact same key for the same validator
            // (e.g. a retried tx) is a harmless no-op past this point.
        }

        match self.validators.get_mut(validator_id) {
            Some(record) => {
                // Rotating an existing key: drop the old by_pubkey entry
                // first so it doesn't linger and block re-use, then bind
                // the new one.
                let old_key = record.keys.consensus_pubkey.clone();
                if !old_key.is_empty() && old_key != hex_key {
                    self.by_pubkey.remove(&old_key);
                }
                record.keys.consensus_pubkey = hex_key.clone();
            }
            None => {
                let seq = self.next_registration_seq;
                self.next_registration_seq += 1;
                let record = ValidatorRecord {
                    id:                ValidatorId(validator_id.to_string()),
                    keys:              KeyBundle {
                        consensus_pubkey: hex_key.clone(),
                        account_address:  validator_id.to_string(),
                        pqc_pubkey:       None,
                        scheme:           "Ed25519".to_string(),
                    },
                    commission:        Commission {
                        rate_bps:           0,
                        max_rate_bps:       MAX_COMMISSION_RATE_BPS,
                        last_changed_epoch: epoch,
                    },
                    // Stake lives in StateStore (validator-bond:<addr>), not
                    // here -- this registry entry exists only to carry the
                    // authenticated key. 0/None here does not mean "has no
                    // stake"; it means "this registry doesn't track stake
                    // for bond-admitted validators".
                    bonded_uqcb:       0,
                    stake_tier:        None,
                    status:            ValidatorStatus::Candidate,
                    pop_verified:      false,
                    verification_tier: None,
                    registered_epoch:  epoch,
                    registration_seq:  seq,
                    last_status_epoch: epoch,
                    blocks_proposed:   0,
                    blocks_missed:     0,
            epoch_blocks_signed: 0,
            epoch_counter_epoch: 0,
                    jail_records:      Vec::new(),
                    moniker:           validator_id.to_string(),
                    website:           None,
                    owner_identity_id: None,
                    is_genesis:        false,
                };
                self.validators_by_human
                    .entry(validator_id.to_string())
                    .or_default()
                    .push(validator_id.to_string());
                self.validators.insert(validator_id.to_string(), record);
            }
        }

        self.by_pubkey.insert(hex_key, validator_id.to_string());
        tracing::info!(id = validator_id, "consensus key registered");
        Ok(())
    }

    /// PQ-VAL-001: Register a consensus key with an explicit scheme string.
    /// Updates `KeyBundle.scheme` so callers can later query it for R3 gating.
    /// Falls through to `register_consensus_key` for all other logic.
    pub fn register_consensus_key_with_scheme(
        &mut self,
        validator_id:     &str,
        consensus_pubkey: &[u8],
        epoch:            u64,
        scheme:           &str,
    ) -> ValResult<()> {
        self.register_consensus_key(validator_id, consensus_pubkey, epoch)?;
        // register_consensus_key succeeded; now update the scheme field.
        if let Some(rec) = self.validators.get_mut(validator_id) {
            rec.keys.scheme = scheme.to_string();
        }
        Ok(())
    }

    /// PQ-VAL-001 / R3: Return the registered consensus key scheme for a
    /// validator, or `None` if the validator is unknown or has no key.
    /// Used by node.rs to gate voting_power for ML-DSA-only validators.
    pub fn consensus_key_scheme(&self, validator_id: &str) -> Option<&str> {
        let rec = self.validators.get(validator_id)?;
        if rec.keys.consensus_pubkey.is_empty() {
            return None;
        }
        Some(rec.keys.scheme.as_str())
    }

    /// Look up a validator's registered consensus public key, hex-decoded
    /// back to raw bytes. `None` if the validator is unknown or has no key
    /// registered yet.
    pub fn consensus_pubkey_bytes(&self, validator_id: &str) -> Option<Vec<u8>> {
        let rec = self.validators.get(validator_id)?;
        if rec.keys.consensus_pubkey.is_empty() {
            return None;
        }
        hex_decode_bytes(&rec.keys.consensus_pubkey)
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
        if !verification_tier.grants_consensus() {
            return Err(ValidatorError::IneligibleTier {
                id:   validator_id.to_string(),
                tier: format!("{verification_tier:?}"),
            });
        }

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
    ///
    /// # Intentional design: lapsing is not a slashing offense
    ///
    /// `revoke_pop` demotes the validator to Candidate with zero voting power.
    /// It does NOT jail them, does NOT slash their stake, and does NOT record a
    /// `JailRecord`. This is a deliberate choice from Section 3.3 of the whitepaper:
    /// personhood-weighting is a bound on influence, not a punishment for inactivity.
    ///
    /// Slashing is reserved for equivocation and consensus-level liveness failures
    /// (evidence-based offenses handled by the slashing module). A validator who
    /// goes offline and lets their identity lapse is simply inactive — they stop
    /// accruing rewards and lose their seat in the active set, but their stake is
    /// not penalized. They re-enter the active set by re-verifying their identity
    /// and having `confirm_pop` called again, via the same path as any other
    /// Candidate-to-Active transition.
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

    /// Record that a validator signed a precommit in the current epoch.
    /// `current_epoch` is passed so stale counters are reset on first call.
    pub fn record_precommit(&mut self, validator_id: &str, current_epoch: u64) {
        if let Some(record) = self.validators.get_mut(validator_id) {
            if record.epoch_counter_epoch != current_epoch {
                record.epoch_blocks_signed = 0;
                record.epoch_counter_epoch = current_epoch;
            }
            record.epoch_blocks_signed += 1;
        }
    }

    /// Determine which validators are eligible for epoch rewards and
    /// distribute the validator pool equally among them.
    ///
    /// Eligibility (all must hold):
    /// - `Active` status, `pop_verified=true`, nonzero `consensus_power()`
    /// - Not jailed (no active jail record)
    /// - `epoch_blocks_signed / validator_epoch_blocks >= participation_threshold_pct / 100`
    /// - Owner identity unique per human (one share per human owner)
    ///
    /// Distribution:
    /// - Pool amount split equally among eligible count (integer floor).
    /// - Remainder stays in `treasury:validator-pool` for the next epoch.
    /// - Zero eligible validators → no distribution, pool untouched.
    ///
    /// Returns the list of (validator_id, reward_amount) pairs that were credited.
    pub fn eligible_validators_for_epoch_reward(
        &self,
        current_epoch:            u64,
        validator_epoch_blocks:   u64,
        participation_threshold:  u8, // 0–100 (percentage, e.g. 95)
    ) -> Vec<String> {
        use std::collections::HashMap;

        // Collect candidates: one per human owner, best participation wins.
        // Map: owner_key → (validator_id, signed_blocks)
        let mut best_per_human: HashMap<String, (String, u64)> = HashMap::new();

        for (id, record) in &self.validators {
            if !record.pop_verified { continue; }
            if record.status != ValidatorStatus::Active { continue; }
            if record.consensus_power() == 0 { continue; }
            // Jailed: any jail record where unjail_after epoch hasn't passed.
            if record.jail_records.iter().any(|j| j.unjail_after >= current_epoch) { continue; }

            // Epoch participation check.
            let signed = if record.epoch_counter_epoch == current_epoch {
                record.epoch_blocks_signed
            } else {
                0
            };
            if validator_epoch_blocks > 0 {
                let pct = (signed * 100) / validator_epoch_blocks;
                if pct < participation_threshold as u64 { continue; }
            }

            // Per-human dedup: keep the one with the highest signed count.
            let owner_key = record.owner_identity_id.clone()
                .unwrap_or_else(|| id.clone());
            let entry = best_per_human.entry(owner_key).or_insert((id.clone(), 0));
            if signed > entry.1 {
                *entry = (id.clone(), signed);
            }
        }

        best_per_human.into_values().map(|(id, _)| id).collect()
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
        // Collect all active, PoP-verified validators whose stored tier
        // grants consensus. The tier check is defense-in-depth: consensus_power()
        // already returns 0 for ineligible tiers, but filtering here ensures
        // ineligible validators are fully absent from the set, not just zero-powered.
        let candidates: Vec<&ValidatorRecord> = self.validators.values()
            .filter(|r| {
                r.status == ValidatorStatus::Active
                    && r.pop_verified
                    && r.verification_tier
                        .as_ref()
                        .map(|t| t.grants_consensus())
                        .unwrap_or(false)
            })
            .collect();

        // Per-human power budget: tracks how much of power_cap this human has
        // already consumed across their registered validators, oldest-first.
        // "Oldest-first" is approximated by registration epoch; in a tie, any
        // ordering is acceptable — the cap is what matters, not which validator
        // is chosen.
        let power_cap = self.personhood_config.power_cap;
        let mut human_power_used: HashMap<String, u64> = HashMap::new();

        let validators: Vec<ValidatorInfo> = {
            // Sort by (registered_epoch, registration_seq) so the first-registered
            // validator for a given human always gets priority for the per-human
            // power cap, even when two validators share the same epoch (e.g. both
            // registered at epoch 0 during testing or genesis).
            let mut sorted = candidates;
            sorted.sort_by_key(|r| (r.registered_epoch, r.registration_seq));

            sorted.iter().map(|r| {
                // Effective owner key: explicit owner_identity_id or fall back to id.
                let owner = r.owner_identity_id.as_deref().unwrap_or(r.id.0.as_str());
                let used  = human_power_used.entry(owner.to_string()).or_insert(0);
                let base  = r.consensus_power(); // 1 for verified Active, 0 otherwise

                // How much of the human's power cap remains?
                let remaining = power_cap.saturating_sub(*used);
                let granted   = base.min(remaining);

                *used += granted;

                if granted < base {
                    tracing::info!(
                        validator = %r.id,
                        owner,
                        human_power_used = *used,
                        power_cap,
                        "per-human power cap applied: validator granted {} of {} requested power",
                        granted, base,
                    );
                }

                // CF-VAL-KEY-002: read back the authenticated consensus key
                // this validator actually has on file (via
                // `register_consensus_key`/the genesis seeding path), rather
                // than the previous hardcoded `vec![]`. If none is
                // registered yet, this stays empty -- `gate_voting_power()`
                // (applied by every consensus engine's `update_validator_set`)
                // then forces `voting_power` to 0 for this entry regardless
                // of what `granted` says here, so an unkeyed validator can
                // never carry real consensus weight.
                let public_key = hex_decode_bytes(&r.keys.consensus_pubkey)
                    .unwrap_or_default();

                ValidatorInfo {
                    id:           r.id.clone(),
                    voting_power: granted,
                    pop_verified: r.pop_verified,
                    public_key,
                }
            }).collect()
        };

        ValidatorSet { height, validators }
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
            id:               ValidatorId(id.to_string()),
            moniker:          format!("Validator {id}"),
            keys:             KeyBundle::new_ed25519(&format!("pubkey_{id}"), addr),
            commission:       Commission::new(500, 2_000).unwrap(), // 5% rate, 20% max
            bonded_uqcb:      stake,
            website:          None,
            owner_identity_id: None,
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

    // -- State-machine coherence: revoke/confirm cycle ------------------------
    //
    // These tests answer the question: "does a lapsed+re-verified validator land
    // in the same functional state as a fresh validator after confirm_pop?"
    //
    // The answer is: consensus-critical fields (pop_verified, status,
    // verification_tier, consensus_power) converge completely. Historical fields
    // (blocks_proposed, blocks_missed, last_status_epoch) do NOT reset — these
    // are intentional scars: the chain keeps history of what a validator did.
    // The jail_records intentionally DO remain empty on lapse (not a slashing
    // offense), and this must remain true to preserve the lapse-vs-slash
    // distinction from Section 3.3 of the whitepaper.

    #[test]
    fn lapse_does_not_record_a_slash() {
        // A validator that lapses (identity goes offline) must not accumulate a
        // JailRecord. Lapsing is an inactivity event, not a punishable offense.
        // Slashing is reserved for equivocation and consensus liveness failures.
        let mut reg = registry();
        reg.register_genesis_validator("alice", 0);
        reg.confirm_pop("alice", VerificationTier::Verified, 0).unwrap();

        // Simulate two lapse/re-verify cycles
        reg.revoke_pop("alice", 5).unwrap();
        reg.confirm_pop("alice", VerificationTier::Verified, 6).unwrap();
        reg.revoke_pop("alice", 10).unwrap();
        reg.confirm_pop("alice", VerificationTier::Verified, 11).unwrap();

        let record = reg.get("alice").unwrap();
        assert!(
            record.jail_records.is_empty(),
            "revoke_pop must never write a JailRecord — lapse is not a slashing offense \
             (Section 3.3: personhood-weighting is a bound on influence, not a punishment)"
        );
    }

    #[test]
    fn revoke_confirm_cycle_produces_same_consensus_state_as_fresh_validator() {
        // The critical question: does a lapsed-then-re-verified validator re-enter
        // the active set identically to a validator who was never lapsed?
        //
        // Fields checked here are the "consensus-critical" ones — the fields that
        // the consensus layer and the validator set builder actually use when
        // deciding who counts toward quorum:
        //   - pop_verified
        //   - status
        //   - verification_tier
        //   - consensus_power()
        //
        // Historical fields (blocks_proposed, blocks_missed, last_status_epoch)
        // intentionally differ: the chain keeps a scar. That's fine — those fields
        // are not used to gate entry into the active set.
        let mut reg = registry();

        // Path A: fresh validator, never lapsed.
        reg.register_genesis_validator("fresh", 0);
        reg.confirm_pop("fresh", VerificationTier::Verified, 0).unwrap();

        // Path B: validator that was Active, then lapsed, then re-verified.
        reg.register_genesis_validator("lapsed", 0);
        reg.confirm_pop("lapsed", VerificationTier::Verified, 0).unwrap();
        // Simulate lapse at epoch 5 (identity went offline)
        reg.revoke_pop("lapsed", 5).unwrap();
        // Re-verify at epoch 10 (came back online, identity re-verified)
        reg.confirm_pop("lapsed", VerificationTier::Verified, 10).unwrap();

        let fresh  = reg.get("fresh").unwrap();
        let lapsed = reg.get("lapsed").unwrap();

        // Consensus-critical fields must converge.
        assert_eq!(
            fresh.pop_verified, lapsed.pop_verified,
            "pop_verified must converge after re-verification"
        );
        assert_eq!(
            fresh.status, lapsed.status,
            "status must converge after re-verification (both Active)"
        );
        assert_eq!(
            fresh.verification_tier, lapsed.verification_tier,
            "verification_tier must converge after re-verification"
        );
        assert_eq!(
            fresh.consensus_power(), lapsed.consensus_power(),
            "consensus_power() must converge — lapsed validator re-enters with full weight"
        );
        assert!(lapsed.pop_verified, "lapsed validator must be pop_verified after re-confirmation");
        assert_eq!(lapsed.status, ValidatorStatus::Active, "lapsed validator must be Active after re-confirmation");
        assert_eq!(lapsed.consensus_power(), 1, "lapsed validator must have consensus power 1 after re-confirmation");

        // No jail was recorded (lapse is not a slash).
        assert!(lapsed.jail_records.is_empty(),
            "jail_records must be empty — lapse is not a slashing offense");

        // Historical fields intentionally differ (this is the "scar"):
        // lapsed.last_status_epoch != fresh.last_status_epoch (epoch 10 vs epoch 0)
        // -- not checked because the difference is intentional.
        // lapsed.blocks_proposed / blocks_missed may differ -- also intentional.
        // These differences do NOT affect quorum eligibility.
    }

    #[test]
    fn reactivation_path_is_identical_for_failed_startup_and_lapsed_validator() {
        // Both a validator whose verify_identity failed at startup (Candidate,
        // never pop_verified) and a validator who was Active and then lapsed
        // (Candidate, pop_verified revoked) should re-activate via the SAME call:
        //   confirm_pop(id, tier, epoch)
        // This test proves there is no separate "resurrection" path needed.
        let mut reg = registry();

        // Path A: failed startup — register_genesis_validator ran but confirm_pop
        // was never called (verify_identity failed, stayed Candidate).
        reg.register_genesis_validator("failed-startup", 0);
        // Note: no confirm_pop here — this is the "stayed Candidate" case.

        // Path B: was Active, lapsed, now back as Candidate.
        reg.register_genesis_validator("was-active", 0);
        reg.confirm_pop("was-active", VerificationTier::Verified, 0).unwrap();
        reg.revoke_pop("was-active", 5).unwrap();
        // Now "was-active" is also Candidate with pop_verified=false.

        // Both should be Candidate with pop_verified=false before re-verify.
        for id in ["failed-startup", "was-active"] {
            let r = reg.get(id).unwrap();
            assert_eq!(r.status, ValidatorStatus::Candidate, "{id}: expected Candidate");
            assert!(!r.pop_verified, "{id}: expected pop_verified = false");
            assert_eq!(r.consensus_power(), 0, "{id}: expected 0 consensus power");
        }

        // Re-activate BOTH through the SAME confirm_pop call.
        reg.confirm_pop("failed-startup", VerificationTier::Verified, 10).unwrap();
        reg.confirm_pop("was-active",     VerificationTier::Verified, 10).unwrap();

        // Both must now be Active with identical consensus-critical state.
        for id in ["failed-startup", "was-active"] {
            let r = reg.get(id).unwrap();
            assert_eq!(r.status, ValidatorStatus::Active, "{id}: must be Active after confirm_pop");
            assert!(r.pop_verified, "{id}: must be pop_verified after confirm_pop");
            assert_eq!(r.consensus_power(), 1, "{id}: must have consensus_power 1 after confirm_pop");
        }
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

    // -- Personhood-weighting: per-human cap (Section 3.3) --------------------

    fn req_with_owner(id: &str, addr: &str, stake: u128, owner: &str) -> RegistrationRequest {
        RegistrationRequest {
            id:               ValidatorId(id.to_string()),
            moniker:          format!("Validator {id}"),
            keys:             KeyBundle::new_ed25519(&format!("pubkey_{id}"), addr),
            commission:       Commission::new(500, 2_000).unwrap(),
            bonded_uqcb:      stake,
            website:          None,
            owner_identity_id: Some(owner.to_string()),
        }
    }

    /// **The Section 3.3 test**: one human, two validators, one with 10× the stake.
    /// The second validator must receive 0 voting power — the human's cap of 1
    /// is fully consumed by the first (lower-registered-epoch) validator.
    ///
    /// This is the whitepaper's core claim: stake does not compound voting influence
    /// beyond the per-human cap, regardless of how many validator addresses a human
    /// controls.
    #[test]
    fn two_validators_same_human_combined_power_capped() {
        let mut reg = ValidatorRegistry::new(
            ENTRY_STAKE_UQCB,
            PersonhoodConfig {
                power_cap:          1,   // max 1 unit of power per human
                reject_expired_pop: false,
                min_verified_pct:   0,
            },
        );

        // Human "qcb1human1" registers two validators.
        // val_small: entry stake (1k QCB), registered first.
        // val_large: 10× stake (10k QCB), registered second.
        // Under Section 3.3 the 10× stake MUST NOT grant extra influence.
        reg.register(req_with_owner("val_small", "qcb1val_small",
            ENTRY_STAKE_UQCB, "qcb1human1"), 0).unwrap();
        reg.register(req_with_owner("val_large", "qcb1val_large",
            STANDARD_STAKE_UQCB, "qcb1human1"), 0).unwrap();

        reg.confirm_pop("val_small", VerificationTier::Verified, 1).unwrap();
        reg.confirm_pop("val_large", VerificationTier::Verified, 1).unwrap();

        let vs = reg.build_validator_set(1);
        assert_eq!(vs.validators.len(), 2, "both validators should appear in the set");

        let power_small = vs.validators.iter()
            .find(|v| v.id.0 == "val_small").map(|v| v.voting_power).unwrap();
        let power_large = vs.validators.iter()
            .find(|v| v.id.0 == "val_large").map(|v| v.voting_power).unwrap();

        // Combined power must not exceed the per-human cap.
        assert_eq!(
            power_small + power_large, 1,
            "combined voting power for one human must equal power_cap=1 (not 2): \
             small={power_small}, large={power_large}"
        );

        // The first-registered validator (val_small) gets the allocation.
        assert_eq!(power_small, 1,
            "val_small (first-registered) must receive the full power cap");
        assert_eq!(power_large, 0,
            "val_large (second-registered, 10× stake) must receive 0 power \
             — stake does not compound influence beyond the per-human cap (Section 3.3)");
    }

    /// Two *different* humans, two validators — each should get their full cap.
    /// This confirms the cap is per-human, not global.
    #[test]
    fn two_validators_different_humans_each_get_full_cap() {
        let mut reg = ValidatorRegistry::new(
            ENTRY_STAKE_UQCB,
            PersonhoodConfig {
                power_cap:          1,
                reject_expired_pop: false,
                min_verified_pct:   0,
            },
        );

        reg.register(req_with_owner("val_a", "qcb1val_a",
            ENTRY_STAKE_UQCB, "qcb1human_a"), 0).unwrap();
        reg.register(req_with_owner("val_b", "qcb1val_b",
            ENTRY_STAKE_UQCB, "qcb1human_b"), 0).unwrap();

        reg.confirm_pop("val_a", VerificationTier::Verified, 1).unwrap();
        reg.confirm_pop("val_b", VerificationTier::Verified, 1).unwrap();

        let vs = reg.build_validator_set(1);
        for v in &vs.validators {
            assert_eq!(v.voting_power, 1,
                "each distinct human must receive the full power cap: {}",
                v.id.0);
        }
        assert_eq!(vs.total_power(), 2,
            "total power must equal number of distinct verified humans");
    }

    /// Three validators sharing one owner identity (edge case: cap=1 means only
    /// the first gets any power, regardless of stake).
    #[test]
    fn three_validators_one_human_only_first_gets_power() {
        let mut reg = ValidatorRegistry::new(
            ENTRY_STAKE_UQCB,
            PersonhoodConfig {
                power_cap:          1,
                reject_expired_pop: false,
                min_verified_pct:   0,
            },
        );

        for (id, addr, epoch) in [
            ("v1", "qcb1v1", 0u64),
            ("v2", "qcb1v2", 1u64),
            ("v3", "qcb1v3", 2u64),
        ] {
            reg.register(req_with_owner(id, addr, ENTRY_STAKE_UQCB, "qcb1human_x"), epoch).unwrap();
            reg.confirm_pop(id, VerificationTier::Verified, epoch + 1).unwrap();
        }

        let vs = reg.build_validator_set(3);
        let total: u64 = vs.validators.iter().map(|v| v.voting_power).sum();
        assert_eq!(total, 1,
            "three validators, one human, power_cap=1 → total must be 1");
    }

    /// Validators without an explicit owner_identity_id default to owning themselves.
    /// Existing tests should be unaffected.
    #[test]
    fn validators_without_owner_id_default_to_self_owned() {
        let mut reg = ValidatorRegistry::new(
            ENTRY_STAKE_UQCB,
            PersonhoodConfig {
                power_cap:          1,
                reject_expired_pop: false,
                min_verified_pct:   0,
            },
        );

        // Use the existing `req()` helper — owner_identity_id is None.
        for (id, addr) in [("a", "qcb1a"), ("b", "qcb1b"), ("c", "qcb1c")] {
            reg.register(req(id, addr, ENTRY_STAKE_UQCB), 0).unwrap();
            reg.confirm_pop(id, VerificationTier::Verified, 1).unwrap();
        }

        let vs = reg.build_validator_set(1);
        for v in &vs.validators {
            assert_eq!(v.voting_power, 1,
                "self-owned validator must get full cap: {}", v.id.0);
        }
        assert_eq!(vs.total_power(), 3);
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

    // -- CF-VAL-KEY-002: register_consensus_key ------------------------------

    #[test]
    fn register_consensus_key_creates_minimal_record_for_an_unknown_validator() {
        // The live stake-bond admission path (chain-forge-node) never calls
        // `register()`, so this is the common case: the first thing the
        // registry ever hears about a bonded validator is its key.
        let mut reg = registry();
        reg.register_consensus_key("qcb1newval", b"real-consensus-key-bytes", 3).unwrap();

        let rec = reg.get("qcb1newval").unwrap();
        assert_eq!(
            rec.keys.consensus_pubkey,
            hex_encode_bytes(b"real-consensus-key-bytes"),
        );
        assert_eq!(reg.consensus_pubkey_bytes("qcb1newval"), Some(b"real-consensus-key-bytes".to_vec()));
    }

    #[test]
    fn register_consensus_key_rejects_empty_key() {
        let mut reg = registry();
        let err = reg.register_consensus_key("qcb1newval", &[], 0).unwrap_err();
        assert!(matches!(err, ValidatorError::InvalidKeyBundle(_)));
    }

    #[test]
    fn register_consensus_key_rejects_registering_another_validators_key() {
        // CF-VAL-KEY-002 Phase 4 test #6: "An unauthorized key replacement
        // is rejected." The same consensus key cannot be bound to two
        // different validator identities -- this is the registry-level
        // half of that guarantee (the tx-level half is that nobody but
        // `sender` can even reach this method for `sender`'s own id, since
        // the executor authenticates the transaction's sender first).
        let mut reg = registry();
        reg.register_consensus_key("qcb1alice", b"alices-real-key", 0).unwrap();

        let err = reg.register_consensus_key("qcb1mallory", b"alices-real-key", 0).unwrap_err();
        assert!(matches!(err, ValidatorError::InvalidKeyBundle(_)));

        // Alice's own binding is untouched by the rejected attempt.
        assert_eq!(
            reg.consensus_pubkey_bytes("qcb1alice"),
            Some(b"alices-real-key".to_vec())
        );
        // Mallory never got a record created for her at all.
        assert!(reg.get("qcb1mallory").is_err());
    }

    #[test]
    fn register_consensus_key_allows_authorized_rotation_by_the_same_validator() {
        // "Reject unauthorized key replacement" implies an *authorized*
        // replacement (the validator rotating its own key) must still work.
        let mut reg = registry();
        reg.register_consensus_key("qcb1alice", b"old-key", 0).unwrap();
        reg.register_consensus_key("qcb1alice", b"new-key", 5).unwrap();

        assert_eq!(reg.consensus_pubkey_bytes("qcb1alice"), Some(b"new-key".to_vec()));
        // The old key is freed from the duplicate-key index, not left
        // dangling to block its own validator's next rotation or anyone
        // else's legitimate (new) use of that exact byte string.
        assert!(reg.get_by_pubkey(&hex_encode_bytes(b"old-key")).is_none());
    }

    #[test]
    fn build_validator_set_reads_back_the_registered_consensus_key() {
        // Closes the actual CF-VAL-KEY-002 gap: build_validator_set() used
        // to hardcode public_key: vec![] for every validator regardless of
        // what was registered. Now it must read the real key back.
        let mut reg = registry();
        reg.register(req("v1", "qcb1v1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.register_consensus_key("v1", b"v1-real-key", 0).unwrap();
        reg.confirm_pop("v1", VerificationTier::Verified, 0).unwrap();

        let vs = reg.build_validator_set(1);
        let v1 = vs.validators.iter().find(|v| v.id.0 == "v1").unwrap();
        assert_eq!(v1.public_key, b"v1-real-key".to_vec());
    }

    #[test]
    fn build_validator_set_leaves_public_key_empty_when_none_registered() {
        let mut reg = registry();
        reg.register(req("v1", "qcb1v1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("v1", VerificationTier::Verified, 0).unwrap();

        let vs = reg.build_validator_set(1);
        let v1 = vs.validators.iter().find(|v| v.id.0 == "v1").unwrap();
        assert!(v1.public_key.is_empty());
    }

    // -- Epoch-boundary revocation invariant tests ----------------------------
    //
    // Protocol invariant (Section 3.3 / QPC-CONS-001):
    //   At epoch advance, any validator whose owner identity tier no longer
    //   grants_consensus() MUST have pop_verified = false and status = Candidate
    //   in the ValidatorRegistry, and MUST NOT appear with non-zero voting power
    //   in the validator set used by the consensus engine.
    //
    // The epoch-boundary window (between identity lapse and the next epoch
    // advance) is intentional: it bounds the delay at one epoch but does not
    // eliminate it. These tests confirm the boundary semantics are correct and
    // that the window is closed as soon as epoch_advance fires.

    #[test]
    fn epoch_boundary_revocation_removes_consensus_power() {
        // A validator that was Active+pop_verified MUST lose all voting power
        // as soon as revoke_pop() is called (simulating the epoch-advance sweep).
        // This is the core invariant: no lapsed validator may contribute to quorum.
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();

        // Pre-condition: validator is in the active set with non-zero power.
        let vs_before = reg.build_validator_set(1);
        let power_before = vs_before.validators.iter()
            .find(|v| v.id.0 == "val1")
            .map(|v| v.voting_power)
            .unwrap_or(0);
        assert!(power_before > 0,
            "pre-condition: validator must have non-zero power before epoch-boundary revocation");

        // Epoch advance fires: identity tier no longer grants consensus.
        reg.revoke_pop("val1", 2).unwrap();

        // Post-condition: validator must not appear in the active set with power.
        let vs_after = reg.build_validator_set(2);
        let power_after = vs_after.validators.iter()
            .find(|v| v.id.0 == "val1")
            .map(|v| v.voting_power)
            .unwrap_or(0);
        assert_eq!(power_after, 0,
            "epoch-boundary invariant violated: lapsed validator must have zero consensus power \
             immediately after revoke_pop (epoch-advance window is closed)");

        let record = reg.get("val1").unwrap();
        assert!(!record.pop_verified,
            "pop_verified must be false after epoch-boundary revocation");
        assert_eq!(record.status, ValidatorStatus::Candidate,
            "status must be Candidate after epoch-boundary revocation");
    }

    #[test]
    fn epoch_boundary_revocation_affects_only_lapsed_validator() {
        // When one validator lapses at epoch advance, other validators with
        // valid identity must retain their full consensus power. The sweep is
        // per-validator, not a global reset.
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.register(req("val2", "qcb1val2", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();
        reg.confirm_pop("val2", VerificationTier::Verified, 1).unwrap();

        // Only val1 lapses at epoch 2 (identity no longer grants_consensus).
        reg.revoke_pop("val1", 2).unwrap();

        let vs = reg.build_validator_set(2);

        let power_val1 = vs.validators.iter()
            .find(|v| v.id.0 == "val1")
            .map(|v| v.voting_power)
            .unwrap_or(0);
        let power_val2 = vs.validators.iter()
            .find(|v| v.id.0 == "val2")
            .map(|v| v.voting_power)
            .unwrap_or(0);

        assert_eq!(power_val1, 0,
            "lapsed validator val1 must have zero power after epoch-boundary revocation");
        assert!(power_val2 > 0,
            "valid validator val2 must retain non-zero power after a different validator lapses; \
             epoch-boundary sweep must not affect validators whose identity is still eligible");
    }

    #[test]
    fn revoke_pop_is_idempotent_across_multiple_epoch_advances() {
        // revoke_pop() is called once per eligible validator per epoch advance.
        // If the sweep fires twice (concurrent epoch advances, duplicate calls),
        // the second call must be a no-op — it must not corrupt the record or
        // return an error that would abort the sweep loop.
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();

        // First revoke at epoch 2 — simulates normal epoch-advance sweep.
        reg.revoke_pop("val1", 2).unwrap();
        let record_after_first = reg.get("val1").unwrap().clone();

        // Second revoke at epoch 3 — simulates duplicate call or racing advance.
        let result = reg.revoke_pop("val1", 3);
        assert!(result.is_ok(),
            "revoke_pop must be idempotent: a second call on an already-Candidate \
             validator must not return an error; got: {:?}", result.err());

        let record_after_second = reg.get("val1").unwrap();
        assert_eq!(record_after_second.pop_verified, record_after_first.pop_verified,
            "pop_verified must be unchanged after idempotent revoke_pop");
        assert_eq!(record_after_second.status, record_after_first.status,
            "status must be unchanged after idempotent revoke_pop");
        assert_eq!(record_after_second.consensus_power(), 0,
            "consensus power must remain zero after idempotent revoke_pop");
    }

    #[test]
    fn validator_reenter_consensus_after_identity_restored() {
        // After an epoch-boundary revocation, a validator whose owner re-attains
        // a consensus-eligible identity tier must be able to re-enter the active
        // set via confirm_pop. The re-entry must restore full consensus power and
        // must not leave any residue from the lapse that would reduce power.
        let mut reg = registry();
        reg.register(req("val1", "qcb1val1", ENTRY_STAKE_UQCB), 0).unwrap();
        reg.confirm_pop("val1", VerificationTier::Verified, 1).unwrap();

        // Epoch 2: identity lapses, epoch-boundary sweep fires.
        reg.revoke_pop("val1", 2).unwrap();
        assert_eq!(reg.get("val1").unwrap().consensus_power(), 0,
            "pre-condition for re-entry test: power must be zero after revocation");

        // Epoch 3: owner re-verifies identity, confirm_pop fires.
        reg.confirm_pop("val1", VerificationTier::Verified, 3).unwrap();

        let record = reg.get("val1").unwrap();
        assert!(record.pop_verified,
            "pop_verified must be true after identity is restored via confirm_pop");
        assert_eq!(record.status, ValidatorStatus::Active,
            "status must be Active after identity is restored via confirm_pop");
        assert!(record.consensus_power() > 0,
            "consensus power must be restored after identity re-verification; \
             a validator whose owner re-attains eligibility must re-enter the active set");

        // The restored validator must appear with non-zero power in the validator set.
        let vs = reg.build_validator_set(3);
        let power = vs.validators.iter()
            .find(|v| v.id.0 == "val1")
            .map(|v| v.voting_power)
            .unwrap_or(0);
        assert!(power > 0,
            "epoch-boundary re-entry invariant: validator set must reflect restored \
             consensus power after confirm_pop (power={})", power);

        // Jail records must remain empty — lapse+re-verify is not a slashing event.
        assert!(record.jail_records.is_empty(),
            "jail_records must remain empty after lapse+re-verify cycle: \
             lapse is an inactivity event, not a punishable offense (Section 3.3)");
    }

    // -- Registry eligibility enforcement tests ------------------------------
    //
    // These tests cover the defense-in-depth guard added to the registry:
    //   confirm_pop() rejects tiers that do not satisfy grants_consensus().
    //   consensus_power() returns 0 when the stored tier is ineligible.
    //   build_validator_set() excludes ineligible-tier validators entirely.
    //
    // These guarantees hold even if the node sweep were to call confirm_pop
    // with a stale or downgraded tier — the registry refuses the call at the
    // boundary rather than requiring the sweep to self-correct.

    fn make_reg_single(id: &str) -> ValidatorRegistry {
        let mut reg = registry();
        reg.register_genesis_validator(id, 0);
        reg
    }

    #[test]
    fn confirm_pop_rejects_provisional_tier() {
        let mut reg = make_reg_single("v1");
        let err = reg.confirm_pop("v1", VerificationTier::Provisional, 1)
            .expect_err("confirm_pop must reject VerificationTier::Provisional");
        assert!(
            matches!(err, ValidatorError::IneligibleTier { .. }),
            "expected IneligibleTier, got {err:?}"
        );
        // Validator must remain in its prior state: not pop_verified, not Active.
        let r = reg.get("v1").unwrap();
        assert!(!r.pop_verified, "pop_verified must stay false after rejected confirm_pop");
        assert_eq!(r.consensus_power(), 0, "consensus_power must remain 0");
    }

    #[test]
    fn consensus_power_zero_for_ineligible_tier_via_direct_field_write() {
        // Documents the defense-in-depth in consensus_power(): even if a record
        // somehow ends up with pop_verified=true and an ineligible tier (e.g. via
        // deserialization of corrupt state), consensus_power() returns 0.
        let mut reg = make_reg_single("v1");

        // Bypass confirm_pop and corrupt the record directly (simulates bad state).
        {
            let record = reg.validators.get_mut("v1").unwrap();
            record.pop_verified      = true;
            record.verification_tier = Some(VerificationTier::Provisional);
            record.status            = ValidatorStatus::Active;
        }

        let r = reg.get("v1").unwrap();
        assert_eq!(
            r.consensus_power(), 0,
            "consensus_power must return 0 for Active+pop_verified validator \
             whose stored tier is Provisional (ineligible)"
        );
    }

    #[test]
    fn build_validator_set_excludes_ineligible_tier_validator() {
        // Even with pop_verified=true and Active status, a validator with an
        // ineligible tier must not appear in the built validator set.
        let mut reg = registry();
        reg.register_genesis_validator("eligible",   0);
        reg.register_genesis_validator("ineligible", 0);

        reg.confirm_pop("eligible", VerificationTier::Verified, 1).unwrap();

        // Corrupt the ineligible validator's record directly.
        {
            let record = reg.validators.get_mut("ineligible").unwrap();
            record.pop_verified      = true;
            record.verification_tier = Some(VerificationTier::Provisional);
            record.status            = ValidatorStatus::Active;
        }

        let vs = reg.build_validator_set(1);
        assert!(
            vs.validators.iter().all(|v| v.id.0 != "ineligible"),
            "build_validator_set must exclude the ineligible-tier validator entirely"
        );
        let eligible_power = vs.validators.iter()
            .find(|v| v.id.0 == "eligible")
            .map(|v| v.voting_power)
            .unwrap_or(0);
        assert!(eligible_power > 0, "eligible Verified validator must have non-zero power");
    }

    #[test]
    fn confirm_pop_verified_tier_still_works_after_eligibility_guard() {
        // Regression: adding the eligibility guard must not break the normal path.
        let mut reg = make_reg_single("v1");
        reg.confirm_pop("v1", VerificationTier::Verified, 1).unwrap();
        let r = reg.get("v1").unwrap();
        assert!(r.pop_verified);
        assert_eq!(r.consensus_power(), 1);
    }

    // ── FS-03 epoch-reward acceptance tests ────────────────────────────────────

    /// Build a registry with `n` active, pop_verified validators.
    /// Each validator signs `signed` out of `epoch_blocks` in epoch 1.
    /// Returns (registry, vec of validator ids).
    fn make_active_validators(n: usize, signed: u64, epoch_blocks: u64) -> (ValidatorRegistry, Vec<String>) {
        let mut reg = registry();
        let ids: Vec<String> = (0..n).map(|i| format!("v{i}")).collect();
        for id in &ids {
            reg.register_genesis_validator(id, 0);
            reg.confirm_pop(id, VerificationTier::Verified, 1).unwrap();
            // Simulate precommits in epoch 1.
            for _ in 0..signed {
                reg.record_precommit(id, 1);
            }
        }
        // Confirm all are Active after confirm_pop.
        for id in &ids {
            assert_eq!(reg.get(id).unwrap().status, ValidatorStatus::Active);
        }
        (reg, ids)
    }

    #[test]
    fn fs03_epoch_all_eligible_at_full_participation() {
        let epoch_blocks: u64 = 100;
        let (reg, ids) = make_active_validators(4, epoch_blocks, epoch_blocks);
        let eligible = reg.eligible_validators_for_epoch_reward(1, epoch_blocks, 95);
        assert_eq!(eligible.len(), 4, "all 4 fully-participating validators must be eligible");
        let mut sorted = eligible.clone();
        sorted.sort();
        let mut expected: Vec<_> = ids.clone();
        expected.sort();
        assert_eq!(sorted, expected, "eligible set must match the registered validators");
    }

    #[test]
    fn fs03_epoch_below_threshold_excluded() {
        let epoch_blocks: u64 = 100;
        // v0..v2 sign 95/100 (exactly at threshold), v3 signs only 50/100.
        let (mut reg, _) = make_active_validators(3, 95, epoch_blocks);
        reg.register_genesis_validator("v3", 0);
        reg.confirm_pop("v3", VerificationTier::Verified, 1).unwrap();
        for _ in 0..50 { reg.record_precommit("v3", 1); }

        let eligible = reg.eligible_validators_for_epoch_reward(1, epoch_blocks, 95);
        assert_eq!(eligible.len(), 3, "v3 at 50% must be excluded (threshold 95%)");
        assert!(!eligible.contains(&"v3".to_string()), "v3 must not appear in eligible list");
    }

    #[test]
    fn fs03_epoch_zero_eligible_when_none_participate() {
        let epoch_blocks: u64 = 100;
        // Register two validators but never call record_precommit — 0% participation.
        let mut reg = registry();
        for id in ["v0", "v1"] {
            reg.register_genesis_validator(id, 0);
            reg.confirm_pop(id, VerificationTier::Verified, 1).unwrap();
        }
        let eligible = reg.eligible_validators_for_epoch_reward(1, epoch_blocks, 95);
        assert!(eligible.is_empty(),
            "zero eligible validators must produce empty list, not panic or partial list");
    }

    #[test]
    fn fs03_epoch_per_human_dedup_one_share_per_human() {
        // Two validators with the same owner_identity_id represent the same human.
        // Only the one with higher participation should appear in the eligible list.
        let epoch_blocks: u64 = 100;
        let mut reg = registry();

        // Register two validators under the same owner using the full registration path.
        let mut req_high = req("v_high", "qcb1high", ENTRY_STAKE_UQCB);
        req_high.owner_identity_id = Some("human1".to_string());
        let mut req_low  = req("v_low",  "qcb1low",  ENTRY_STAKE_UQCB);
        req_low.owner_identity_id  = Some("human1".to_string());

        reg.register(req_high, 0).unwrap();
        reg.register(req_low,  0).unwrap();
        reg.confirm_pop("v_high", VerificationTier::Verified, 1).unwrap();
        reg.confirm_pop("v_low",  VerificationTier::Verified, 1).unwrap();

        // v_high signs 98 blocks, v_low signs 96 blocks (both above 95% threshold).
        for _ in 0..98 { reg.record_precommit("v_high", 1); }
        for _ in 0..96 { reg.record_precommit("v_low",  1); }

        let eligible = reg.eligible_validators_for_epoch_reward(1, epoch_blocks, 95);
        assert_eq!(eligible.len(), 1, "one human must get exactly one reward share");
        assert_eq!(eligible[0], "v_high",
            "the node with higher participation (v_high=98) must win the dedup");
    }

    /// Two validators of one human with equal participation: every node must
    /// pick the same one. Each registry gets its own HashMap hash seed, so
    /// iteration-order tie-breaks differ between registries (and nodes).
    #[test]
    fn fs03_epoch_per_human_tie_is_broken_identically_on_every_node() {
        let epoch_blocks: u64 = 100;
        let picks: std::collections::BTreeSet<Vec<String>> = (0..32).map(|_| {
            let mut reg = registry();
            for (id, addr) in [("v_a", "qcb1a"), ("v_b", "qcb1b"), ("v_c", "qcb1c")] {
                let mut r = req(id, addr, ENTRY_STAKE_UQCB);
                r.owner_identity_id = Some("human1".to_string());
                reg.register(r, 0).unwrap();
                reg.confirm_pop(id, VerificationTier::Verified, 1).unwrap();
                for _ in 0..epoch_blocks { reg.record_precommit(id, 1); }
            }
            reg.eligible_validators_for_epoch_reward(1, epoch_blocks, 95)
        }).collect();
        assert_eq!(picks.len(), 1, "tie-break must not depend on hash order: {picks:?}");
        assert_eq!(picks.into_iter().next().unwrap(), vec!["v_a".to_string()],
            "ties go to the lowest validator id");
    }

    #[test]
    fn fs03_epoch_boundary_uses_completed_epoch_counters() {
        // This test verifies that epoch N's participation counters are read
        // BEFORE record_precommit resets them for epoch N+1.
        //
        // Correct ordering: reward eligibility is checked at epoch close for
        // epoch N.  If the node calls record_precommit with epoch N+1 BEFORE
        // calling eligible_validators_for_epoch_reward, the counters reset to 0
        // and no validator appears eligible (off-by-one epoch bug).
        let epoch_blocks: u64 = 100;
        let (mut reg, ids) = make_active_validators(2, epoch_blocks, epoch_blocks);

        // At epoch close of epoch 1, query BEFORE advancing to epoch 2.
        let eligible_epoch1 = reg.eligible_validators_for_epoch_reward(1, epoch_blocks, 95);
        assert_eq!(eligible_epoch1.len(), 2, "both validators eligible at epoch 1 close");

        // Simulate epoch 2 starting: record_precommit with epoch=2 resets counters.
        reg.record_precommit(&ids[0], 2);
        reg.record_precommit(&ids[1], 2);

        // Now query for epoch 1 again — counters are epoch 2, so epoch 1 query
        // returns 0 signed (counters reset).  This documents the invariant:
        // always query eligible_validators_for_epoch_reward(N, ...) BEFORE
        // issuing record_precommit calls for epoch N+1.
        let eligible_after_reset = reg.eligible_validators_for_epoch_reward(1, epoch_blocks, 95);
        assert!(eligible_after_reset.is_empty(),
            "after epoch counters reset for epoch 2, epoch 1 query must return empty — \
             reward distribution MUST precede record_precommit for the new epoch");

        // But epoch 2 query works (only 1 block signed so far — below 95%):
        let eligible_epoch2_partial = reg.eligible_validators_for_epoch_reward(2, epoch_blocks, 95);
        assert!(eligible_epoch2_partial.is_empty(),
            "epoch 2 with only 1 signed block (< 95% of 100) must have no eligible validators");
    }

    #[test]
    fn fs03_epoch_not_eligible_when_not_pop_verified() {
        let epoch_blocks: u64 = 100;
        let mut reg = registry();
        reg.register_genesis_validator("v_unverified", 0);
        // Do NOT call confirm_pop — pop_verified stays false.
        for _ in 0..100 { reg.record_precommit("v_unverified", 1); }

        let eligible = reg.eligible_validators_for_epoch_reward(1, epoch_blocks, 95);
        assert!(eligible.is_empty(),
            "validator without personhood verification must not receive epoch rewards");
    }
}
