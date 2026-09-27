/// chain-forge-slashing
///
/// Slashing enforcement for QCB Chain.
///
/// Implements the two slashing conditions from Q6 and Q14:
///
/// 1. EQUIVOCATION (double-signing)
///    A validator signs two conflicting blocks at the same (height, round).
///    This is Byzantine behavior — deliberate deception of the network.
///    Detection: the consensus layer observes two valid signatures from the
///    same validator for conflicting blocks at the same height/round.
///    Penalty: tombstone (permanent removal) + 5% stake slash (default).
///    The stake slash is burned via BME (Section 6.3), not redistributed.
///
/// 2. LIVENESS (downtime)
///    A validator misses more than the liveness threshold of blocks in a
///    sliding observation window. This is passive failure.
///    Detection: the block production tracker counts signed vs missed blocks.
///    Penalty: jail (temporary removal) + 0.1% stake slash (default).
///
/// Slash proceeds are burned, not redistributed. Redistributing to accusers
/// creates an incentive to manufacture evidence of slashing, which is
/// especially dangerous in a personhood-weighted system where identity
/// manipulations are the primary attack surface.
///
/// The SlashingModule:
///   - Holds the configurable slash rates
///   - Records evidence of equivocation (prevents double-slash)
///   - Computes the slash amount from bonded stake
///   - Calls the ValidatorRegistry to apply status changes
///   - Returns the amount to burn (caller routes to BME)
///   - Tracks the full slash history for audit
///
/// Whitepaper refs: Q6 (slashing), Q14 (liveness), Section 3.3, Section 6.3.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use chain_forge_validators::{ValidatorRegistry, ENTRY_STAKE_UQCB};
use chain_forge_consensus::ValidatorId;

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SlashError {
    #[error("validator {0} not found in registry")]
    ValidatorNotFound(String),

    #[error("equivocation already recorded for validator {0} at height {1} round {2}")]
    EquivocationAlreadyRecorded(String, u64, u64),

    #[error("validator {0} is already tombstoned")]
    AlreadyTombstoned(String),

    #[error("slash amount {amount} exceeds bonded stake {bonded}")]
    SlashExceedsBonded { amount: u128, bonded: u128 },

    #[error("registry error: {0}")]
    Registry(String),

    #[error("invalid equivocation evidence: {0}")]
    InvalidEvidence(String),

    #[error("internal slashing error: {0}")]
    Internal(String),
}

// -- Hex decode (stdlib-only, no external deps) --------------------------------

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at {i}: {e}")))
        .collect()
}

pub type SlashResult<T> = Result<T, SlashError>;

// -- SlashReason --------------------------------------------------------------

/// Why a validator was slashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashReason {
    /// Signed two conflicting blocks at the same height and round.
    /// Byzantine — permanent removal.
    Equivocation {
        height: u64,
        round:  u64,
    },
    /// Missed more than the liveness threshold of blocks.
    /// Passive failure — temporary jail.
    LivenessFailure {
        missed_pct: u32, // percentage of blocks missed (0-100)
        window:     u64, // observation window in blocks
    },
}

impl SlashReason {
    pub fn display(&self) -> String {
        match self {
            Self::Equivocation { height, round } =>
                format!("equivocation at height {height} round {round}"),
            Self::LivenessFailure { missed_pct, window } =>
                format!("liveness failure: missed {missed_pct}% of last {window} blocks"),
        }
    }

    pub fn is_byzantine(&self) -> bool {
        matches!(self, Self::Equivocation { .. })
    }
}

// -- SlashRecord --------------------------------------------------------------

/// An immutable audit record of one slashing event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashRecord {
    pub validator_id:   String,
    pub reason:         SlashReason,
    pub epoch:          u64,
    pub bonded_before:  u128,
    /// Amount slashed in uqcb. Burned via BME.
    pub slashed_uqcb:   u128,
    pub bonded_after:   u128,
    /// Whether the validator was tombstoned (equivocation) or jailed (liveness).
    pub tombstoned:     bool,
}

// -- EquivocationEvidence -----------------------------------------------------

/// Cryptographic evidence of double-signing.
///
/// In Phase 0 this is a struct with the two conflicting block hashes.
/// In Phase 1+ it carries the actual signatures for on-chain verification.
///
/// `vote_type_byte` encodes which vote phase both conflicting votes came from:
///   0 = Prevote, 1 = Precommit  (matches `vote_signing_bytes` encoding)
/// Both votes must be from the same phase (a double-prevote or
/// double-precommit) — a mixed-phase pair is not evidence of equivocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub validator_id:   String,
    pub height:         u64,
    pub round:          u64,
    /// The two conflicting block hashes signed by this validator.
    pub block_hash_a:   String,
    pub block_hash_b:   String,
    /// Signatures (Phase 0: empty, Phase 1: real sig bytes).
    pub signature_a:    Vec<u8>,
    pub signature_b:    Vec<u8>,
    /// Vote type both sigs cover: 0 = Prevote, 1 = Precommit.
    /// Ignored when signatures are empty (Phase 0 fast-path).
    pub vote_type_byte: u8,
}

// -- LivenessWindow -----------------------------------------------------------

/// Sliding window block production tracker for liveness monitoring.
///
/// Each validator has one window. On every block, the node calls
/// `record_block()`. Once the window fills, `missed_pct()` can be
/// checked against `SlashingConfig::liveness_miss_pct_threshold`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessWindow {
    /// Ring buffer: true = proposed, false = missed.
    pub window:   Vec<bool>,
    pub size:     usize,
    pub position: usize,
    pub filled:   bool,
}

impl LivenessWindow {
    pub fn new(size: usize) -> Self {
        Self {
            window:   vec![false; size],
            size,
            position: 0,
            filled:   false,
        }
    }

    /// Record a block outcome for this validator.
    pub fn record(&mut self, proposed: bool) {
        self.window[self.position] = proposed;
        self.position = (self.position + 1) % self.size;
        if self.position == 0 { self.filled = true; }
    }

    /// Number of blocks observed (up to window size).
    pub fn observed(&self) -> usize {
        if self.filled { self.size } else { self.position }
    }

    /// Fraction of blocks missed (0.0 to 1.0).
    pub fn missed_fraction(&self) -> f64 {
        let n = self.observed();
        if n == 0 { return 0.0; }
        let missed = self.window[..n].iter().filter(|&&b| !b).count();
        missed as f64 / n as f64
    }

    /// Percentage of blocks missed (0-100).
    pub fn missed_pct(&self) -> u32 {
        (self.missed_fraction() * 100.0).round() as u32
    }
}

// -- SlashingConfig -----------------------------------------------------------

/// Configurable slash rates and liveness parameters.
/// These are ordinary-governance-adjustable (Section 6.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Fraction of bonded stake slashed for equivocation (basis points).
    /// Default: 500 bps = 5%. Burned via BME.
    pub equivocation_slash_bps: u32,
    /// Fraction of bonded stake slashed for liveness failure (basis points).
    /// Default: 10 bps = 0.1%. Much lighter than equivocation.
    pub liveness_slash_bps: u32,
    /// Fraction of blocks a validator may miss before liveness slash.
    /// Default: 20% — missing more than 1 in 5 blocks triggers liveness slash.
    pub liveness_miss_pct_threshold: u32,
    /// Size of the liveness observation window in blocks.
    /// Default: 500 blocks (~8 minutes at 1s blocks).
    pub liveness_window_blocks: usize,
    /// Minimum stake after slash. Prevents slashing below minimum registration.
    /// Set to 0 to allow full slash.
    pub min_remaining_stake: u128,
}

impl SlashingConfig {
    pub fn qcb_default() -> Self {
        Self {
            equivocation_slash_bps:      500,    // 5%
            liveness_slash_bps:          10,     // 0.1%
            liveness_miss_pct_threshold: 20,     // >20% missed triggers slash
            liveness_window_blocks:      500,
            min_remaining_stake:         0, // no floor -- slash the full computed amount
        }
    }

    /// Compute the slash amount in uqcb from bonded stake and rate.
    pub fn slash_amount(&self, bonded: u128, bps: u32) -> u128 {
        let amount = bonded * bps as u128 / 10_000;
        // Never slash below min_remaining_stake
        let max_slash = bonded.saturating_sub(self.min_remaining_stake);
        amount.min(max_slash)
    }

    pub fn equivocation_slash_amount(&self, bonded: u128) -> u128 {
        self.slash_amount(bonded, self.equivocation_slash_bps)
    }

    pub fn liveness_slash_amount(&self, bonded: u128) -> u128 {
        self.slash_amount(bonded, self.liveness_slash_bps)
    }
}

// -- SlashingModule -----------------------------------------------------------

/// The slashing enforcement module.
///
/// Sits between the consensus/block-production layer (which detects violations)
/// and the ValidatorRegistry (which applies status changes).
/// Returns the amount to burn — the node routes this to the BME engine.
pub struct SlashingModule {
    config:   SlashingConfig,
    history:  Vec<SlashRecord>,
    /// Set of (validator_id, height, round) already slashed for equivocation.
    /// Prevents double-slash of the same event.
    equivocation_set: HashSet<(String, u64, u64)>,
    /// Liveness windows per validator.
    liveness_windows: HashMap<String, LivenessWindow>,
    /// Total uqcb slashed across all events (for audit/BME accounting).
    pub total_slashed_uqcb: u128,
    /// Total uqcb slashed for equivocation specifically.
    pub equivocation_slashed_uqcb: u128,
    /// Total uqcb slashed for liveness failures.
    pub liveness_slashed_uqcb: u128,
}

impl SlashingModule {
    pub fn new(config: SlashingConfig) -> Self {
        Self {
            config,
            history:              Vec::new(),
            equivocation_set:     HashSet::new(),
            liveness_windows:     HashMap::new(),
            total_slashed_uqcb:   0,
            equivocation_slashed_uqcb: 0,
            liveness_slashed_uqcb: 0,
        }
    }

    pub fn with_qcb_defaults() -> Self {
        Self::new(SlashingConfig::qcb_default())
    }

    // -- Equivocation ---------------------------------------------------------

    /// Verify equivocation evidence cryptographically.
    ///
    /// Domain-separated with `CFV|` prefix (chain_id + height + round).
    /// Called only when at least one signature is non-empty (Phase 1+).
    /// Phase 0 fast-path: both sigs empty → skip (trusted internal detector).
    ///
    /// Compile with `real-crypto` feature to enable ML-DSA verification;
    /// without it the stub rejects any non-empty signature (safe default).
    #[cfg_attr(not(feature = "real-crypto"), allow(unused_variables))]
    fn verify_evidence(
        chain_id: &str,
        evidence: &EquivocationEvidence,
        _pub_key: &[u8],
        _pub_key_b: &[u8],
    ) -> SlashResult<()> {
        #[cfg(not(feature = "real-crypto"))]
        {
            // Stub: non-empty sigs are always invalid until real-crypto is wired.
            if !evidence.signature_a.is_empty() || !evidence.signature_b.is_empty() {
                return Err(SlashError::InvalidEvidence(
                    "real-crypto feature required to verify signatures".to_string(),
                ));
            }
            return Ok(());
        }
        #[cfg(feature = "real-crypto")]
        {
            use chain_forge_crypto::{ClassicalScheme, SignatureScheme};
            // Reconstruct the exact bytes the consensus engine signed via
            // vote_signing_bytes(): b"CFV|" + chain_id + b"|" + type_byte +
            // height_le + round_le + block_hash_bytes.
            // Both votes are from the same phase (same vote_type_byte) but
            // different block hashes, which is the definition of equivocation.
            let build_msg = |block_hash: &str| -> Vec<u8> {
                let mut b = Vec::new();
                b.extend_from_slice(b"CFV|");
                b.extend_from_slice(chain_id.as_bytes());
                b.push(b'|');
                b.push(evidence.vote_type_byte);
                b.extend_from_slice(&evidence.height.to_le_bytes());
                b.extend_from_slice(&evidence.round.to_le_bytes());
                b.extend_from_slice(block_hash.as_bytes());
                b
            };
            let msg_a = build_msg(&evidence.block_hash_a);
            let msg_b = build_msg(&evidence.block_hash_b);
            let sig_a = chain_forge_crypto::Signature::from_bytes(&evidence.signature_a)
                .map_err(|e| SlashError::InvalidEvidence(format!("sig_a: {e}")))?;
            let sig_b = chain_forge_crypto::Signature::from_bytes(&evidence.signature_b)
                .map_err(|e| SlashError::InvalidEvidence(format!("sig_b: {e}")))?;
            ClassicalScheme.verify(&msg_a, &sig_a, _pub_key)
                .map_err(|e| SlashError::InvalidEvidence(format!("sig_a invalid: {e}")))?;
            ClassicalScheme.verify(&msg_b, &sig_b, _pub_key_b)
                .map_err(|e| SlashError::InvalidEvidence(format!("sig_b invalid: {e}")))?;
            Ok(())
        }
    }

    /// Process equivocation evidence and slash the validator.
    ///
    /// Tombstones the validator (permanent removal) and slashes their stake.
    /// Returns the amount to burn via BME.
    ///
    /// Phase 0 fast-path: both `signature_a` and `signature_b` empty →
    /// skip cryptographic verification (trusted internal equivocation detector).
    /// Phase 1+: non-empty signatures are verified against the validator's
    /// consensus public key before any state change occurs.
    pub fn slash_equivocation(
        &mut self,
        evidence:  &EquivocationEvidence,
        registry:  &mut ValidatorRegistry,
        epoch:     u64,
        chain_id:  &str,
    ) -> SlashResult<u128> {
        let key = (
            evidence.validator_id.clone(),
            evidence.height,
            evidence.round,
        );

        // Idempotent: write the key BEFORE fallible registry lookup so replay
        // attacks are blocked even when the validator is transiently absent.
        if self.equivocation_set.contains(&key) {
            return Err(SlashError::EquivocationAlreadyRecorded(
                evidence.validator_id.clone(),
                evidence.height,
                evidence.round,
            ));
        }
        self.equivocation_set.insert(key.clone());

        let record = registry.get(&evidence.validator_id)
            .map_err(|_| SlashError::ValidatorNotFound(evidence.validator_id.clone()))?;

        if record.status == chain_forge_validators::ValidatorStatus::Tombstoned {
            return Err(SlashError::AlreadyTombstoned(evidence.validator_id.clone()));
        }

        // Phase 1 signature verification (skipped when both sigs are empty)
        if !evidence.signature_a.is_empty() || !evidence.signature_b.is_empty() {
            let pub_key = decode_hex(&record.keys.consensus_pubkey)
                .map_err(|e| SlashError::InvalidEvidence(
                    format!("bad consensus_pubkey hex: {e}")
                ))?;
            Self::verify_evidence(chain_id, evidence, &pub_key, &pub_key)?;
        }

        let bonded_before = record.bonded_uqcb;
        let slash_amount  = self.config.equivocation_slash_amount(bonded_before);
        let bonded_after  = bonded_before.saturating_sub(slash_amount);

        // Apply to registry
        registry.update_stake(&evidence.validator_id, bonded_after)
            .map_err(|e| SlashError::Registry(e.to_string()))?;
        registry.tombstone(&evidence.validator_id, epoch)
            .map_err(|e| SlashError::Registry(e.to_string()))?;
        self.total_slashed_uqcb         += slash_amount;
        self.equivocation_slashed_uqcb  += slash_amount;

        let slash_rec = SlashRecord {
            validator_id:  evidence.validator_id.clone(),
            reason:        SlashReason::Equivocation {
                height: evidence.height,
                round:  evidence.round,
            },
            epoch,
            bonded_before,
            slashed_uqcb:  slash_amount,
            bonded_after,
            tombstoned:    true,
        };
        self.history.push(slash_rec);

        tracing::warn!(
            validator = %evidence.validator_id,
            height    = evidence.height,
            round     = evidence.round,
            slashed   = slash_amount,
            "equivocation detected — validator tombstoned"
        );

        Ok(slash_amount) // caller routes to BME burn
    }

    // -- Liveness -------------------------------------------------------------

    /// Record a block outcome for a validator's liveness window.
    /// Returns Some(slash_amount_to_burn) if liveness threshold is exceeded.
    pub fn record_block(
        &mut self,
        validator_id: &str,
        proposed:     bool,
        registry:     &mut ValidatorRegistry,
        epoch:        u64,
    ) -> SlashResult<Option<u128>> {
        let window_size = self.config.liveness_window_blocks;
        let window = self.liveness_windows
            .entry(validator_id.to_string())
            .or_insert_with(|| LivenessWindow::new(window_size));

        window.record(proposed);

        // Only check after the window fills for the first time
        if !window.filled { return Ok(None); }

        let missed_pct = window.missed_pct();
        if missed_pct <= self.config.liveness_miss_pct_threshold { return Ok(None); }

        // Liveness threshold exceeded — slash and jail
        let record = match registry.get(validator_id) {
            Ok(r) => r,
            Err(_) => return Ok(None), // validator may have been removed
        };

        // Don't re-jail an already-jailed or tombstoned validator
        if record.status != chain_forge_validators::ValidatorStatus::Active {
            return Ok(None);
        }

        let bonded_before = record.bonded_uqcb;
        let slash_amount  = self.config.liveness_slash_amount(bonded_before);
        let bonded_after  = bonded_before.saturating_sub(slash_amount);

        registry.update_stake(validator_id, bonded_after)
            .map_err(|e| SlashError::Registry(e.to_string()))?;
        registry.jail(validator_id, "liveness failure", epoch)
            .map_err(|e| SlashError::Registry(e.to_string()))?;

        // Reset the window after slashing so the validator isn't
        // immediately re-slashed when they come back online
        self.liveness_windows.insert(
            validator_id.to_string(),
            LivenessWindow::new(window_size),
        );

        self.total_slashed_uqcb    += slash_amount;
        self.liveness_slashed_uqcb += slash_amount;

        self.history.push(SlashRecord {
            validator_id:  validator_id.to_string(),
            reason:        SlashReason::LivenessFailure {
                missed_pct,
                window: window_size as u64,
            },
            epoch,
            bonded_before,
            slashed_uqcb:  slash_amount,
            bonded_after,
            tombstoned:    false,
        });

        tracing::warn!(
            validator   = validator_id,
            missed_pct,
            slashed     = slash_amount,
            "liveness failure — validator jailed"
        );

        Ok(Some(slash_amount))
    }

    // -- History and lookups --------------------------------------------------

    pub fn slash_history(&self) -> &[SlashRecord] {
        &self.history
    }

    pub fn history_for(&self, validator_id: &str) -> Vec<&SlashRecord> {
        self.history.iter()
            .filter(|r| r.validator_id == validator_id)
            .collect()
    }

    pub fn liveness_window(&self, validator_id: &str) -> Option<&LivenessWindow> {
        self.liveness_windows.get(validator_id)
    }

    pub fn config(&self) -> &SlashingConfig {
        &self.config
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_validators::{
        ValidatorRegistry, RegistrationRequest, KeyBundle,
        Commission, ValidatorStatus, ENTRY_STAKE_UQCB, FULL_STAKE_UQCB,
    };
    use chain_forge_consensus::ValidatorId;
    use chain_forge_identity::VerificationTier;

    // -- Test helpers ---------------------------------------------------------

    fn registry_with_validator(id: &str, stake: u128) -> ValidatorRegistry {
        let mut reg = ValidatorRegistry::qcb_devnet();
        let req = RegistrationRequest {
            id:          ValidatorId(id.to_string()),
            moniker:     format!("Validator {id}"),
            keys:        KeyBundle::new_ed25519(
                             &format!("pk_{id}"),
                             &format!("qcb1{id}"),
                         ),
            commission:  Commission::new(500, 2_000).unwrap(),
            bonded_uqcb: stake,
            website:     None,
        };
        reg.register(req, 0).unwrap();
        reg.confirm_pop(id, VerificationTier::Verified, 1).unwrap();
        reg
    }

    fn evidence(id: &str, height: u64, round: u64) -> EquivocationEvidence {
        EquivocationEvidence {
            validator_id:   id.to_string(),
            height,
            round,
            block_hash_a:   format!("hash_a_h{height}"),
            block_hash_b:   format!("hash_b_h{height}"),
            signature_a:    vec![],
            signature_b:    vec![],
            vote_type_byte: 0, // Prevote (Phase 0 fast-path; sigs empty)
        }
    }

    // -- SlashingConfig tests -------------------------------------------------

    #[test]
    fn equivocation_slash_rate_is_5_percent() {
        let cfg = SlashingConfig::qcb_default();
        assert_eq!(cfg.equivocation_slash_bps, 500);
        let slash = cfg.equivocation_slash_amount(10_000_000);
        assert_eq!(slash, 500_000); // 5% of 10 QCB
    }

    #[test]
    fn liveness_slash_rate_is_point_1_percent() {
        let cfg = SlashingConfig::qcb_default();
        assert_eq!(cfg.liveness_slash_bps, 10);
        let slash = cfg.liveness_slash_amount(10_000_000);
        assert_eq!(slash, 10_000); // 0.1% of 10 QCB
    }

    #[test]
    fn slash_cannot_drop_below_minimum_remaining() {
        // With min_remaining_stake = 0 (default), the full computed slash applies.
        // To test the floor, use a custom config with a floor set.
        let cfg = SlashingConfig {
            equivocation_slash_bps:      500,
            liveness_slash_bps:          10,
            liveness_miss_pct_threshold: 20,
            liveness_window_blocks:      500,
            min_remaining_stake:         ENTRY_STAKE_UQCB, // floor at 1k QCB
        };
        // bonded = just 1M above the floor
        let bonded = ENTRY_STAKE_UQCB + 1_000_000;
        let slash  = cfg.equivocation_slash_amount(bonded);
        // 5% of bonded = 50,050,000 but max_slash = bonded - floor = 1,000,000
        assert_eq!(slash, 1_000_000);
        assert!(bonded - slash >= ENTRY_STAKE_UQCB);
    }

    #[test]
    fn slash_full_stake_capped_at_max_slash() {
        let cfg = SlashingConfig::qcb_default();
        let bonded = FULL_STAKE_UQCB; // 100,000 QCB
        let slash  = cfg.equivocation_slash_amount(bonded);
        // 5% of 100,000 QCB = 5,000 QCB; min_remaining = 1,000 QCB
        // max_slash = 99,000 QCB; actual = 5,000 QCB (below cap)
        assert_eq!(slash, FULL_STAKE_UQCB * 500 / 10_000);
    }

    // -- LivenessWindow tests -------------------------------------------------

    #[test]
    fn liveness_window_starts_unfilled() {
        let w = LivenessWindow::new(10);
        assert!(!w.filled);
        assert_eq!(w.observed(), 0);
        assert_eq!(w.missed_fraction(), 0.0);
    }

    #[test]
    fn liveness_window_tracks_missed_blocks() {
        let mut w = LivenessWindow::new(10);
        for _ in 0..8 { w.record(true);  }
        for _ in 0..2 { w.record(false); }
        assert!(w.filled);
        assert_eq!(w.missed_pct(), 20);
    }

    #[test]
    fn liveness_window_rings_correctly() {
        let mut w = LivenessWindow::new(5);
        // Fill with 5 misses
        for _ in 0..5 { w.record(false); }
        assert_eq!(w.missed_pct(), 100);
        // Overwrite with 5 proposals
        for _ in 0..5 { w.record(true); }
        assert_eq!(w.missed_pct(), 0);
    }

    #[test]
    fn all_proposed_is_zero_miss_rate() {
        let mut w = LivenessWindow::new(100);
        for _ in 0..100 { w.record(true); }
        assert_eq!(w.missed_fraction(), 0.0);
    }

    // -- Equivocation slashing ------------------------------------------------

    #[test]
    fn equivocation_tombstones_and_slashes() {
        let mut reg     = registry_with_validator("val1", FULL_STAKE_UQCB);
        let mut slasher = SlashingModule::with_qcb_defaults();

        let ev = evidence("val1", 10, 0);
        let burned = slasher.slash_equivocation(&ev, &mut reg, 5, "test-chain").unwrap();

        assert!(burned > 0, "some stake must be burned");
        let rec = reg.get("val1").unwrap();
        assert_eq!(rec.status, ValidatorStatus::Tombstoned);
        assert_eq!(rec.bonded_uqcb, FULL_STAKE_UQCB - burned);
        assert_eq!(slasher.total_slashed_uqcb, burned);
        assert_eq!(slasher.equivocation_slashed_uqcb, burned);
    }

    #[test]
    fn equivocation_evidence_cannot_be_processed_twice() {
        let mut reg     = registry_with_validator("val1", FULL_STAKE_UQCB);
        let mut slasher = SlashingModule::with_qcb_defaults();

        let ev = evidence("val1", 10, 0);
        slasher.slash_equivocation(&ev, &mut reg, 5, "test-chain").unwrap();

        let result = slasher.slash_equivocation(&ev, &mut reg, 5, "test-chain");
        assert!(result.is_err(), "same evidence must not be processed twice");
    }

    #[test]
    fn equivocation_at_different_heights_are_independent() {
        let mut reg     = registry_with_validator("val1", FULL_STAKE_UQCB);
        let mut slasher = SlashingModule::with_qcb_defaults();

        // A validator equivocating at height 10 and 11 are two separate events
        // (once tombstoned after first, second should return AlreadyTombstoned)
        slasher.slash_equivocation(&evidence("val1", 10, 0), &mut reg, 5, "test-chain").unwrap();
        let result = slasher.slash_equivocation(&evidence("val1", 11, 0), &mut reg, 5, "test-chain");
        assert!(result.is_err(), "tombstoned validator cannot be slashed again");
    }

    #[test]
    fn slash_history_recorded() {
        let mut reg     = registry_with_validator("val1", FULL_STAKE_UQCB);
        let mut slasher = SlashingModule::with_qcb_defaults();

        slasher.slash_equivocation(&evidence("val1", 5, 0), &mut reg, 10, "test-chain").unwrap();
        let history = slasher.history_for("val1");
        assert_eq!(history.len(), 1);
        assert!(history[0].tombstoned);
        assert!(matches!(history[0].reason, SlashReason::Equivocation { height: 5, round: 0 }));
    }

    // -- Liveness slashing ----------------------------------------------------

    #[test]
    fn liveness_slash_triggers_after_threshold() {
        let mut reg = registry_with_validator("val1", FULL_STAKE_UQCB);
        // Use a small window (10 blocks) and low threshold (20%) for a fast test
        let mut slasher = SlashingModule::new(SlashingConfig {
            equivocation_slash_bps:      500,
            liveness_slash_bps:          10,
            liveness_miss_pct_threshold: 20,
            liveness_window_blocks:      10,
            min_remaining_stake:         0,
        });

        // Fill window: 8 proposed + 2 missed = 20% -- at threshold, not triggered
        for _ in 0..8 { slasher.record_block("val1", true,  &mut reg, 0).unwrap(); }
        for _ in 0..2 { slasher.record_block("val1", false, &mut reg, 0).unwrap(); }
        assert_eq!(reg.get("val1").unwrap().status, ValidatorStatus::Active,
            "exactly at threshold should not trigger");

        // One more miss replaces a 'true': 7 proposed + 3 missed = 30% > 20% -> triggers
        slasher.record_block("val1", false, &mut reg, 0).unwrap();
        assert_eq!(reg.get("val1").unwrap().status, ValidatorStatus::Jailed,
            "exceeding threshold must jail");
        assert!(slasher.liveness_slashed_uqcb > 0);
    }

    #[test]
    fn liveness_window_resets_after_slash() {
        let mut reg = registry_with_validator("val1", FULL_STAKE_UQCB);
        let mut slasher = SlashingModule::new(SlashingConfig {
            equivocation_slash_bps:      500,
            liveness_slash_bps:          10,
            liveness_miss_pct_threshold: 20,
            liveness_window_blocks:      10,
            min_remaining_stake:         0,
        });

        // Fill window and exceed threshold to trigger slash
        for _ in 0..8 { slasher.record_block("val1", true,  &mut reg, 0).unwrap(); }
        for _ in 0..3 { slasher.record_block("val1", false, &mut reg, 0).unwrap(); }

        // Window should have reset after the slash
        let window = slasher.liveness_window("val1").unwrap();
        assert!(!window.filled, "window must reset after liveness slash");
    }

    #[test]
    fn already_jailed_validator_not_re_slashed() {
        let mut reg     = registry_with_validator("val1", FULL_STAKE_UQCB);
        let mut slasher = SlashingModule::with_qcb_defaults();

        // Jail via equivocation first
        slasher.slash_equivocation(&evidence("val1", 1, 0), &mut reg, 1, "test-chain").unwrap();
        // (now tombstoned, not jailed, but similar test: inactive validator)
        let slash_count_before = slasher.total_slashed_uqcb;

        // Block records for a tombstoned validator should be silently ignored
        for _ in 0..501 { slasher.record_block("val1", false, &mut reg, 2).unwrap(); }
        assert_eq!(slasher.total_slashed_uqcb, slash_count_before,
            "inactive validator must not be slashed again via liveness");
    }

    #[test]
    fn slash_amounts_accumulate_correctly() {
        let mut reg     = registry_with_validator("val1", FULL_STAKE_UQCB);
        let mut reg2    = registry_with_validator("val2", FULL_STAKE_UQCB);
        let mut slasher = SlashingModule::with_qcb_defaults();

        let burned1 = slasher.slash_equivocation(&evidence("val1", 1, 0), &mut reg,  5, "test-chain").unwrap();
        let burned2 = slasher.slash_equivocation(&evidence("val2", 2, 0), &mut reg2, 5, "test-chain").unwrap();

        assert_eq!(slasher.total_slashed_uqcb, burned1 + burned2);
        assert_eq!(slasher.history().len(), 2);
    }

    #[test]
    fn fake_evidence_with_non_empty_signatures_is_rejected() {
        // A validator with a 32-byte all-zero pubkey (valid even-length hex)
        let mut reg     = registry_with_validator("val1", FULL_STAKE_UQCB);
        // Override the consensus pubkey to a valid 64-char hex (32 zero bytes)
        // by re-registering is not easy, so we test via the decode_hex path:
        // build evidence with forged non-empty sigs
        let fake_evidence = EquivocationEvidence {
            validator_id:   "val1".to_string(),
            height:         42,
            round:          0,
            block_hash_a:   "deadblock".to_string(),
            block_hash_b:   "cafeblock".to_string(),
            signature_a:    vec![0xde, 0xad, 0xbe, 0xef],
            signature_b:    vec![0xca, 0xfe, 0xba, 0xbe],
            vote_type_byte: 1, // Precommit
        };
        let mut slasher = SlashingModule::with_qcb_defaults();
        // Without real-crypto, any non-empty sig → InvalidEvidence
        let result = slasher.slash_equivocation(&fake_evidence, &mut reg, 5, "test-chain");
        // Could be InvalidEvidence (bad hex pubkey) or InvalidEvidence (stub sig check)
        // Either way must NOT be Ok
        assert!(
            matches!(result, Err(SlashError::InvalidEvidence(..))),
            "forged sigs must be rejected; got: {result:?}",
        );
        // Validator must remain Active — no state change on failed evidence
        let rec = reg.get("val1").unwrap();
        assert_eq!(rec.status, ValidatorStatus::Active,
            "validator status must be unchanged after rejected evidence");
        assert_eq!(rec.bonded_uqcb, FULL_STAKE_UQCB,
            "stake must be unchanged after rejected evidence");
    }

    #[test]
    fn liveness_slash_is_much_smaller_than_equivocation() {
        let cfg = SlashingConfig::qcb_default();
        let bonded = FULL_STAKE_UQCB;
        let liveness_slash   = cfg.liveness_slash_amount(bonded);
        let equivocation_slash = cfg.equivocation_slash_amount(bonded);
        // liveness = 0.1%, equivocation = 5% -- ratio is exactly 50x
        // assert strictly less with 49x to avoid floating-point equality edge
        assert!(liveness_slash * 49 < equivocation_slash,
            "liveness penalty must be much lighter than equivocation penalty");
    }
}

// extra accessor for tests
impl SlashingModule {
    pub fn history(&self) -> &[SlashRecord] { &self.history }
}
