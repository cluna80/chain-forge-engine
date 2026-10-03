/// chain-forge-identity
///
/// Protocol-level proof-of-personhood for QCB Chain.
///
/// This crate implements Whitepaper Section 4 and the identity
/// components of Sections 5.1 (Charm Confinement) and 5.2
/// (Intrinsic Charm). It is the single dependency that gates:
///   - Consensus power weighting (Section 3.3)
///   - UBI claim eligibility (Section 6.2)
///   - Governance vote rights (Section 6.6)
///   - Charmed Agent sponsorship (Section 5.3)
///   - Sponsored Contract deployment (Section 7.2)
///
/// Phase 0 status: VerificationTier, IdentityRecord, IdentityStore,
/// UBI epoch clock, liveness enforcement, and IntrinsicCharm are all
/// real and tested. The actual PoP proof (web-of-trust graph +
/// live-challenge ceremony) is stubbed -- the interface is defined so
/// the consensus and execution layers can depend on it now; the
/// cryptographic proof is filled in during the identity pilot (Section 4).
///
/// Whitepaper refs: Sections 3.3, 4, 4.5, 5.1, 5.2, 6.2, 6.6, Q24.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity {0} not found")]
    NotFound(String),

    #[error("identity {0} already exists")]
    AlreadyExists(String),

    #[error("identity {0} is not verified (tier: {1:?})")]
    NotVerified(String, VerificationTier),

    #[error("identity {0} has lapsed (last active epoch: {1}, current: {2})")]
    Lapsed(String, u64, u64),

    #[error("UBI already claimed by {0} in epoch {1}")]
    AlreadyClaimed(String, u64),

    #[error("agent {0} is not authorized by sponsor {1}")]
    UnauthorizedAgent(String, String),

    #[error("verification proof is invalid: {0}")]
    InvalidProof(String),

    #[error("identity {0} cannot attest for itself")]
    SelfAttestation(String),

    #[error("attester {0} is not Verified -- only Verified or Established identities can vouch for a new claimant")]
    AttesterNotVerified(String),

    #[error("attester {0} has already vouched for this claimant")]
    AlreadyAttested(String),

    #[error("attester {0} has reached the maximum attestations allowed this epoch")]
    AttestationRateLimitExceeded(String),

    #[error("attester {0} has reached the rolling-window attestation cap ({1} active attestations in the past {2} epochs)")]
    AttestationCapExceeded(String, u32, u64),

    #[error("identity {0} is already past Provisional -- no further attestations needed")]
    AlreadyVerified(String),

    #[error("no active attestation from {0} for {1}")]
    AttestationNotFound(String, String),

    #[error("attestation from {0} for {1} is already revoked")]
    AttestationAlreadyRevoked(String, String),

    #[error("attestation from {0} for {1} is penalized and cannot be revoked; use reverse_sybil to undo the confirmation first")]
    AttestationAlreadyPenalized(String, String),

    // -- Phase C errors -------------------------------------------------------

    #[error("coordinator not configured; call set_coordinator before confirm_sybil / reverse_sybil")]
    CoordinatorNotSet,

    #[error("caller {0} is not the configured coordinator")]
    NotCoordinator(String),

    #[error("identity {0} is not registered")]
    IdentityNotFound(String),

    #[error("identity {0} has already been confirmed as a sybil")]
    AlreadyConfirmedSybil(String),

    #[error("sybil confirmation for identity {0} not found; cannot reverse")]
    SybilConfirmationNotFound(String),

    // -- Phase D errors -------------------------------------------------------

    #[error("attester {0} has not attested identity {1} and cannot report it as a suspected sybil")]
    CannotReportWithoutAttestation(String, String),

    #[error("attester {0} has already reported identity {1} as a suspected sybil")]
    AlreadyReported(String, String),

    #[error("internal identity error: {0}")]
    Internal(String),
}

pub type IdResult<T> = Result<T, IdentityError>;

// -- Verification tier --------------------------------------------------------

/// The graduated identity lifecycle from Whitepaper Section 4.
/// Graduated from Section 4.5's "identity is the door" framing:
/// more participation -> higher tier -> more rights.
///
/// Provisional:   registered but not yet verified. Can receive $QRC
///                at a reduced rate once pilot allows it. Cannot vote,
///                cannot sponsor agents, cannot validate.
/// Verified:      passed PoP verification. Full UBI, governance, consensus.
/// Established:   Verified + sustained liveness over multiple epochs.
///                Future: higher governance weight, lower demurrage tier.
///                Phase 0: treated identically to Verified.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerificationTier {
    Provisional,
    Verified,
    Established,
}

impl VerificationTier {
    /// Whether this tier grants full UBI (1,000 $QRC/day per Section 6.2).
    pub fn grants_full_ubi(&self) -> bool {
        matches!(self, Self::Verified | Self::Established)
    }

    /// Whether this tier grants consensus participation (Section 3).
    pub fn grants_consensus(&self) -> bool {
        matches!(self, Self::Verified | Self::Established)
    }

    /// Whether this tier grants governance votes (Section 6.6).
    pub fn grants_governance(&self) -> bool {
        matches!(self, Self::Verified | Self::Established)
    }

    /// Whether this tier can sponsor Charmed Agents (Section 5.3).
    pub fn can_sponsor_agents(&self) -> bool {
        matches!(self, Self::Verified | Self::Established)
    }

    /// Voting power multiplier for consensus (Section 3.3).
    /// Phase 0: Provisional = 0, Verified = 1, Established = 1.
    /// Phase 2+: Established may get a higher cap.
    pub fn consensus_power(&self) -> u64 {
        match self {
            Self::Provisional  => 0,
            Self::Verified     => 1,
            Self::Established  => 1,
        }
    }
}

impl std::fmt::Display for VerificationTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provisional  => write!(f, "Provisional"),
            Self::Verified     => write!(f, "Verified"),
            Self::Established  => write!(f, "Established"),
        }
    }
}

// -- PoP proof verifier -------------------------------------------------------

/// Pluggable verifier for the cryptographic proof inside a `PopAttestation`.
///
/// Phase 0: the identity layer doesn't verify the proof at all (the
/// `PopAttestation::verify` stub accepts any non-empty attester). Phase 1:
/// callers inject a `PopProofVerifier` into `IdentityStore::verify_identity`
/// so the real ZK proof is checked without coupling this crate to the
/// heavyweight `chain-forge-personhood` / arkworks dependency tree.
///
/// The expected contract for a real (Phase 1+) implementation:
///   - `proof_bytes`: serialized Groth16 proof (arkworks canonical encoding).
///   - `public_inputs_bytes`: serialized public inputs for the circuit
///     (e.g. the VRC Merkle root as a BLS12-381 Fr element).
/// Returns `Ok(())` if the proof is valid, or `Err(reason)` if it is not.
///
/// The Genesis / Phase 0 stub (`NoOpVerifier`) always returns `Ok(())` and
/// is the default used when no real verifier is supplied.
pub trait PopProofVerifier: Send + Sync {
    fn verify_pop_proof(
        &self,
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), String>;
}

/// Phase 0 no-op: every attestation passes. Used during genesis bootstrap
/// and in all tests that are not specifically testing proof verification.
///
/// This is the type that `IdentityStore::verify_identity` uses by default
/// when the caller passes `None` as the verifier. When the identity pilot
/// moves to Phase 1, callers pass `Some(&Groth16VrcVerifier { ... })`.
pub struct NoOpVerifier;

impl PopProofVerifier for NoOpVerifier {
    fn verify_pop_proof(&self, _proof_bytes: &[u8], _public_inputs: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

// -- PoP attestation ----------------------------------------------------------

/// A proof-of-personhood attestation.
///
/// Phase 0: the proof field is a placeholder string. In production
/// this will be a ZK proof or threshold signature from the
/// web-of-trust + live-challenge ceremony (Whitepaper Section 4).
///
/// The attester is the node or ceremony coordinator that issued
/// the attestation. In the web-of-trust model this is a set of
/// existing Verified humans who vouch for the new claimant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopAttestation {
    /// The identity being attested.
    pub identity_id: String,
    /// Who issued this attestation (ceremony coordinator / web-of-trust peers).
    /// Phase 0: "genesis" for bootstrap identities.
    pub attester:    String,
    /// The epoch in which the attestation was issued.
    pub epoch:       u64,
    /// Cryptographic proof. Phase 0: empty vec (stub).
    /// Phase 1+: ZK proof bytes from live-challenge ceremony.
    pub proof:       Vec<u8>,
    /// Human-readable note. Phase 0 only -- removed in production.
    pub note:        Option<String>,
}

impl PopAttestation {
    /// Phase 0 genesis attestation -- no real proof required.
    pub fn genesis(identity_id: &str, epoch: u64) -> Self {
        Self {
            identity_id: identity_id.to_string(),
            attester:    "genesis".to_string(),
            epoch,
            proof:       vec![],
            note:        Some("genesis bootstrap attestation -- Phase 0 only".to_string()),
        }
    }

    /// Verify the attestation, optionally checking the embedded ZK proof.
    ///
    /// * `verifier = None`  — Phase 0 (no-op): structural checks only.
    ///   Accepts any attestation with a non-empty identity_id and attester.
    ///   Used at genesis and in all Phase 0 tests.
    ///
    /// * `verifier = Some(v)` — Phase 1+: after the structural checks, calls
    ///   `v.verify_pop_proof(&self.proof, &[])` (public inputs are passed as
    ///   empty here; real callers that have public inputs — e.g. a VRC root —
    ///   should use `verify_with_inputs`).
    pub fn verify(&self, verifier: Option<&dyn PopProofVerifier>) -> IdResult<()> {
        if self.identity_id.is_empty() {
            return Err(IdentityError::InvalidProof("empty identity_id".into()));
        }
        if self.attester.is_empty() {
            return Err(IdentityError::InvalidProof("empty attester".into()));
        }
        // Phase 0: structural checks only — no ZK proof needed.
        // Phase 1+: verify the embedded proof against the supplied verifier.
        if let Some(v) = verifier {
            if !self.proof.is_empty() {
                v.verify_pop_proof(&self.proof, &[])
                    .map_err(IdentityError::InvalidProof)?;
            }
            // A real Phase 1 attestation MUST carry a proof; a genesis
            // attestation legitimately has an empty proof vec. If the caller
            // passed a verifier and the proof is empty, only genesis
            // attestations (attester == "genesis") are allowed through.
            // Everything else is rejected to prevent a proof-stripping attack.
            else if self.attester != "genesis" {
                return Err(IdentityError::InvalidProof(
                    "non-genesis attestation missing ZK proof (Phase 1 enforcement)".into(),
                ));
            }
        }
        Ok(())
    }

    /// Same as `verify`, but passes `public_inputs_bytes` to the verifier
    /// for circuits whose public inputs are not embedded in the proof itself
    /// (e.g. the VRC Merkle root supplied separately by the identity pilot
    /// ceremony coordinator).
    pub fn verify_with_inputs(
        &self,
        verifier: &dyn PopProofVerifier,
        public_inputs_bytes: &[u8],
    ) -> IdResult<()> {
        if self.identity_id.is_empty() {
            return Err(IdentityError::InvalidProof("empty identity_id".into()));
        }
        if self.attester.is_empty() {
            return Err(IdentityError::InvalidProof("empty attester".into()));
        }
        if self.proof.is_empty() && self.attester != "genesis" {
            return Err(IdentityError::InvalidProof(
                "non-genesis attestation missing ZK proof".into(),
            ));
        }
        if !self.proof.is_empty() {
            verifier
                .verify_pop_proof(&self.proof, public_inputs_bytes)
                .map_err(IdentityError::InvalidProof)?;
        }
        Ok(())
    }
}

// -- Web-of-trust quorum -------------------------------------------------------

/// Minimum number of distinct Verified-or-Established attesters a
/// Provisional identity needs before it graduates to Verified.
/// Whitepaper Section 4 / Identity Pilot Design Section 3.1: "provisional
/// target: 3 attestations." Provisional here means governance-adjustable,
/// not fixed at the protocol layer -- Section 6.6 governs QRC-adjacent
/// parameters like this one the same way it governs decay rates.
pub const ATTESTATION_QUORUM: usize = 3;

/// Maximum number of distinct claimants one identity can vouch for within
/// a single epoch. Named in the Identity Pilot Design (Section 3.1) as a
/// parameter to finalize before Phase 1; bounds how much damage a single
/// compromised or malicious Verified identity can do by rapidly vouching
/// for a cohort of fake claimants. Provisional value, governance-adjustable.
pub const MAX_ATTESTATIONS_PER_EPOCH: u32 = 5;

/// Hard cap on outbound attestations per rolling window (Phase B / guard 2).
///
/// An attester may have at most this many ACTIVE (non-revoked) attestations
/// within the past ATTESTATION_CAP_WINDOW_EPOCHS epochs at any point in time.
/// Revoked attestations do not count — revocation frees the slot (design Q1).
///
/// Pilot value: 3. Governance-tunable. The cap is enforced on the derived
/// count from attestation_records, not from a separate ring buffer — at pilot
/// scale this is acceptable; add a ring buffer index if count grows past ~50k.
pub const ATTESTATION_CAP_PER_WINDOW: u32 = 3;

/// Rolling window size in epochs for the attestation cap (Phase B).
///
/// An attestation made more than this many epochs ago does not count against
/// the cap. Pilot value: 90 epochs (≈ 90 days if one epoch = one day).
pub const ATTESTATION_CAP_WINDOW_EPOCHS: u64 = 90;

// -- Phase D constants --------------------------------------------------------

/// Standard CS penalty rate for attesters of a confirmed sybil, in basis points.
///
/// 12000 bps = 120% (100% clawback of CS earned + 20% deterrent).
/// Pilot value per QCB-Attestation-Guard-Design.md §3: "100% earned back
/// + 20% as a deterrent signal." Governance-tunable.
///
/// The actual deduction is: cs_earned_from_attestation * ATTEST_PENALTY_RATE_BPS / 10000.
/// With 12000 bps on X CS earned: attester loses 1.2 * X (net -20% deterrent).
pub const ATTEST_PENALTY_RATE_BPS: u32 = 12_000;

/// Flat revocation cost in basis points of CS earned from that attestation.
///
/// 1000 bps = 10%. Pilot value per QCB-Attestation-Guard-Design.md §4:
/// "A small, flat CS deduction on revocation (initially: 10% of CS earned
/// from that attestation), regardless of reason or timing."
///
/// Governance-tunable. Applied by the execution layer using the
/// `RevocationCost` value returned by `revoke_attestation()`.
pub const REVOCATION_COST_BPS: u32 = 1_000;

/// Penalty reduction for attesters who self-reported before coordinator
/// confirmation, in basis points of the STANDARD penalty.
///
/// 5000 bps = 50% reduction. Pilot value: attester who flagged a sybil
/// before the coordinator's `confirm_sybil` call pays half the normal penalty.
/// Governance-tunable.
pub const SELF_REPORT_PENALTY_REDUCTION_BPS: u32 = 5_000;

/// Carries the CS deduction signal from `revoke_attestation` to the
/// execution layer. The identity crate does not own CS arithmetic —
/// it signals what happened; the execution layer applies the deduction.
///
/// `cost_bps`: the basis-points rate to apply against the CS earned
/// from this attestation. At pilot launch this is always REVOCATION_COST_BPS
/// (10%); governance can tune it without a code change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationCost {
    /// The attester whose CS should be debited.
    pub attester_id: String,
    /// The attested identity whose attestation was revoked.
    pub attested_id: String,
    /// Rate in basis points (1 bps = 0.01%) to apply against the CS earned
    /// from this attestation. 1000 = 10%.
    pub cost_bps: u32,
}

/// A self-report event: an attester pre-emptively flags an identity they
/// vouched for as a suspected sybil, before the coordinator acts.
///
/// If the coordinator subsequently confirms the sybil, the self-reporting
/// attester's penalty is reduced by SELF_REPORT_PENALTY_REDUCTION_BPS.
/// If the identity is never confirmed, the report has no effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SybilReport {
    /// The attester who filed the report.
    pub attester_id: String,
    /// The suspected sybil identity.
    pub suspected_id: String,
    /// The epoch in which the report was filed.
    pub report_epoch: u64,
}

/// Tracks which distinct identities have vouched for a Provisional
/// claimant so far, on the way to reaching ATTESTATION_QUORUM.
///
/// Kept as a Vec rather than a HashSet so serialization order is
/// deterministic (matters for state-root determinism across nodes,
/// same reasoning as the rest of this codebase's state layer).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestationLedger {
    pub attesters: Vec<String>,
}

impl AttestationLedger {
    pub fn has_attested(&self, attester_id: &str) -> bool {
        self.attesters.iter().any(|a| a == attester_id)
    }

    /// Records a new distinct attester. No-ops (does not duplicate) if
    /// this attester has already vouched -- callers should still treat a
    /// repeat as an error via IdentityStore::attest's own dedupe check;
    /// this method itself just guarantees the invariant either way.
    fn add(&mut self, attester_id: String) {
        if !self.has_attested(&attester_id) {
            self.attesters.push(attester_id);
        }
    }

    pub fn count(&self) -> usize {
        self.attesters.len()
    }
}

/// What happened as a result of a single attest() call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationOutcome {
    /// Recorded, but the claimant has not yet reached quorum.
    Recorded { attester_count: usize, quorum: usize },
    /// This attestation was the one that crossed the quorum threshold --
    /// the claimant has just been upgraded Provisional -> Verified.
    QuorumReachedVerified,
}

// -- Attestation records (Phase A: guard data model) --------------------------

/// The lifecycle status of one outbound attestation made by an attester.
///
/// Transitions:
///   Active -> Revoked   (attester calls revoke_attestation)
///   Active -> Penalized (coordinator calls confirm_sybil — Phase C)
///   Penalized -> Active (coordinator calls reverse_sybil — Phase C)
///
/// Revoked is terminal: a revoked attestation cannot be re-activated or
/// penalized after revocation. If a sybil is confirmed after an attester
/// revokes their attestation, the attester paid the revocation cost but
/// does not pay the sybil penalty (revocation was the exit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationStatus {
    /// The attestation is active and the attester is exposed to sybil risk.
    Active,
    /// The attester voluntarily revoked this attestation (paid the flat cost).
    /// A slot is freed in the rolling-window cap budget (design decision Q1).
    Revoked,
    /// The attested identity was confirmed as a sybil; the CS penalty has been
    /// applied to the attester. Set by confirm_sybil (Phase C coordinator call).
    Penalized,
}

/// The full on-chain record for one attestation event.
///
/// One record per (attester_id, attested_id) pair. Written by `attest()` and
/// updated by `revoke_attestation()` (Phase A) and `confirm_sybil()` /
/// `reverse_sybil()` (Phase C). This record is the source of truth for penalty
/// lookup and the rolling-window cap's slot tracking.
///
/// Phase A: populated by attest(), read by attestations_by_attester().
/// Phase B: attester_cap_slots on IdentityStore reads these to enforce the cap.
/// Phase C: confirm_sybil() / reverse_sybil() walk these records by attested_id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRecord {
    /// The identity who gave the attestation.
    pub attester_id: String,
    /// The identity who received the attestation.
    pub attested_id: String,
    /// The epoch in which the attestation was made.
    pub epoch: u64,
    /// Current status of this attestation.
    pub status: AttestationStatus,
    /// The epoch in which this attestation was revoked, if applicable.
    pub revocation_epoch: Option<u64>,
    /// Whether a CS penalty has been applied to the attester for this
    /// attestation. Set true by confirm_sybil, set false by reverse_sybil.
    /// False by default; true only in Penalized state.
    pub penalty_applied: bool,
}

impl AttestationRecord {
    pub fn new(attester_id: String, attested_id: String, epoch: u64) -> Self {
        Self {
            attester_id,
            attested_id,
            epoch,
            status: AttestationStatus::Active,
            revocation_epoch: None,
            penalty_applied: false,
        }
    }

    pub fn is_active(&self) -> bool {
        self.status == AttestationStatus::Active
    }
}

/// Canonical key for `IdentityStore::attestation_records`.
///
/// Uses a null-byte separator so serde_json can serialize the HashMap as a
/// valid JSON object (JSON object keys must be strings; tuple keys fail).
/// Identity IDs are address strings and cannot contain null bytes.
fn attestation_record_key(attester_id: &str, attested_id: &str) -> String {
    format!("{}\x00{}", attester_id, attested_id)
}

// -- Sybil confirmation log (Phase C) -----------------------------------------

/// An immutable log entry created when the coordinator confirms a sybil.
///
/// Written by `confirm_sybil`, read by `reverse_sybil`. The log is the
/// audit trail for CS penalties: it records who was penalized and why, so
/// that reversals can undo exactly the right penalties and no others.
///
/// Phase D: the log also records which attesters self-reported before
/// confirmation (and therefore qualify for the reduced penalty rate).
///
/// The `reversed` flag is set true by `reverse_sybil`; the entry is kept
/// rather than deleted so the reversal itself is auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SybilConfirmationLog {
    /// The identity confirmed as a sybil.
    pub sybil_id: String,
    /// The coordinator who issued the confirmation.
    pub coordinator_id: String,
    /// The epoch in which the confirmation was issued.
    pub confirmed_epoch: u64,
    /// Per-attester penalty records for attesters whose records were penalized
    /// (Active → Penalized). Revoked attestations are NOT included.
    pub penalized_attesters: Vec<PenaltyRecord>,
    /// Whether this confirmation has been reversed by `reverse_sybil`.
    pub reversed: bool,
    /// If reversed: the epoch in which it was reversed.
    pub reversal_epoch: Option<u64>,
}

/// One attester's penalty entry within a `SybilConfirmationLog`.
///
/// Phase D: records whether the attester self-reported before the
/// coordinator confirmation, which determines their effective penalty rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyRecord {
    /// The attester whose CS is to be penalized.
    pub attester_id: String,
    /// Effective penalty rate in basis points.
    ///
    /// For attesters who did NOT self-report: ATTEST_PENALTY_RATE_BPS (120%).
    /// For attesters who self-reported before confirmation:
    ///   ATTEST_PENALTY_RATE_BPS * (1 - SELF_REPORT_PENALTY_REDUCTION_BPS/10000)
    ///   = 120% * 50% = 60%.
    /// Governance-tunable; the rate is computed at confirmation time and
    /// recorded here so reversals don't need to recompute it.
    pub penalty_bps: u32,
    /// Whether this attester filed a self-report before coordinator confirmation.
    pub self_reported: bool,
}

// -- Decay exemption credits --------------------------------------------------

/// Tracks how many days of demurrage exemption an identity has earned
/// through spending (Whitepaper Section 6.2: "every valid spend earns
/// 1 day of decay exemption, stackable, capped at 30 days").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecayExemption {
    /// Accumulated exemption days. Capped at MAX_EXEMPTION_DAYS.
    pub days: u32,
    /// Epoch in which the last exemption was earned.
    pub last_earned_epoch: u64,
}

pub const MAX_EXEMPTION_DAYS: u32 = 30;

impl DecayExemption {
    pub fn new() -> Self {
        Self { days: 0, last_earned_epoch: 0 }
    }

    /// Record a valid spend -- earns 1 day of exemption.
    pub fn record_spend(&mut self, epoch: u64) {
        if self.days < MAX_EXEMPTION_DAYS {
            self.days += 1;
        }
        self.last_earned_epoch = epoch;
    }

    /// Consume exemption days for demurrage calculation.
    /// Returns how many days were actually consumed (may be less than requested).
    pub fn consume(&mut self, days: u32) -> u32 {
        let consumed = self.days.min(days);
        self.days -= consumed;
        consumed
    }

    pub fn has_exemption(&self) -> bool {
        self.days > 0
    }
}

impl Default for DecayExemption {
    fn default() -> Self { Self::new() }
}

// -- IntrinsicCharm -----------------------------------------------------------

/// Properties intrinsic to an identity -- they travel with it across
/// the chain rather than being externally assigned (Whitepaper 5.2).
///
/// This is the "Intrinsic Charm" module: PoP tier, decay-exemption
/// credits, and verification metadata are encoded as intrinsic
/// properties of each identity, not as external permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntrinsicCharm {
    /// Current verification tier.
    pub tier: VerificationTier,
    /// Decay-exemption credits earned through spending.
    pub decay_exemption: DecayExemption,
    /// The epoch in which this identity was first verified.
    pub verified_since_epoch: Option<u64>,
    /// The epoch of the most recent PoP re-attestation.
    pub last_attested_epoch: u64,
    /// Number of consecutive epochs with at least one participation event.
    /// Used to graduate from Verified -> Established (Q24).
    pub consecutive_active_epochs: u32,
}

impl IntrinsicCharm {
    pub fn provisional(current_epoch: u64) -> Self {
        Self {
            tier: VerificationTier::Provisional,
            decay_exemption: DecayExemption::new(),
            verified_since_epoch: None,
            last_attested_epoch: current_epoch,
            consecutive_active_epochs: 0,
        }
    }

    /// Upgrade to Verified after a successful PoP attestation.
    pub fn verify(&mut self, epoch: u64) {
        self.tier = VerificationTier::Verified;
        self.verified_since_epoch = Some(epoch);
        self.last_attested_epoch = epoch;
    }

    /// Record a participation event (UBI claim, vote, or transfer).
    /// Increments consecutive_active_epochs and may graduate to Established.
    pub fn record_participation(&mut self, epoch: u64) {
        self.last_attested_epoch = epoch;
        self.consecutive_active_epochs += 1;

        // Graduate to Established after 30 consecutive active epochs
        // (approximately 1 month if epochs are daily). Open Question 24.
        if self.tier == VerificationTier::Verified
            && self.consecutive_active_epochs >= 30
        {
            self.tier = VerificationTier::Established;
            tracing::info!(
                epoch,
                consecutive = self.consecutive_active_epochs,
                "identity graduated to Established"
            );
        }
    }

    /// Check liveness: has this identity participated recently enough?
    /// Whitepaper Q24: identity must participate at least once per
    /// LIVENESS_EPOCH_WINDOW epochs to remain active.
    pub fn is_lively(&self, current_epoch: u64) -> bool {
        current_epoch.saturating_sub(self.last_attested_epoch) <= LIVENESS_EPOCH_WINDOW
    }

    /// Downgrade a lapsed identity to Provisional.
    pub fn lapse(&mut self) {
        tracing::warn!(
            tier = %self.tier,
            "identity lapsed -- downgraded to Provisional"
        );
        self.tier = VerificationTier::Provisional;
        self.consecutive_active_epochs = 0;
    }
}

/// Number of epochs an identity can be inactive before lapsing.
/// Provisional: 90 days of grace (Q24 -- exact value TBD by pilot).
pub const LIVENESS_EPOCH_WINDOW: u64 = 90;

// -- Identity record ----------------------------------------------------------

/// The full on-chain state for one verified human.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    /// Unique identifier -- in QCB this is the account address.
    pub id: String,
    /// The account address this identity controls.
    pub address: String,
    /// Intrinsic charm: tier, exemptions, liveness data.
    pub charm: IntrinsicCharm,
    /// The attestation that created or last renewed this record.
    pub attestation: PopAttestation,
    /// Whether this identity has claimed QRC yield in the current epoch.
    pub claimed_this_epoch: bool,
    /// Total QRC yield claimed across all epochs (in uqrc base units).
    pub total_ubi_claimed: u128,
    /// The last epoch in which this identity performed on-chain activity
    /// (sent a tx, validated a block, processed a merchant settlement).
    /// QRC yield requires activity in the current epoch — this is the
    /// earned-yield gate. None = never active.
    pub last_active_epoch: Option<u64>,
    /// Agents sponsored by this identity (agent address -> authorized).
    pub sponsored_agents: Vec<String>,
    /// Distinct Verified+ identities who have vouched for THIS identity
    /// while it was Provisional, on the way to ATTESTATION_QUORUM.
    pub attestation_ledger: AttestationLedger,
    /// The epoch this identity last gave an attestation to someone else --
    /// used to reset attestations_given_count when a new epoch begins.
    pub attestations_given_epoch: u64,
    /// How many distinct claimants this identity has vouched for so far
    /// in attestations_given_epoch. Reset to 0 whenever the epoch advances.
    pub attestations_given_count: u32,
}

impl IdentityRecord {
    pub fn new(
        id: String,
        address: String,
        attestation: PopAttestation,
        current_epoch: u64,
    ) -> Self {
        Self {
            id,
            address,
            charm: IntrinsicCharm::provisional(current_epoch),
            attestation,
            claimed_this_epoch: false,
            total_ubi_claimed: 0,
            last_active_epoch: None,
            sponsored_agents: Vec::new(),
            attestation_ledger: AttestationLedger::default(),
            attestations_given_epoch: 0,
            attestations_given_count: 0,
        }
    }

    /// Verify this identity (upgrade Provisional -> Verified).
    ///
    /// Pass `verifier = Some(v)` to enforce ZK proof validation (Phase 1+),
    /// or `None` to skip proof checking (Phase 0 genesis bootstrap).
    pub fn verify(
        &mut self,
        attestation: PopAttestation,
        verifier: Option<&dyn PopProofVerifier>,
    ) -> IdResult<()> {
        attestation.verify(verifier)?;
        let epoch = attestation.epoch;
        self.charm.verify(epoch);
        self.attestation = attestation;
        Ok(())
    }

    pub fn is_verified(&self) -> bool {
        self.charm.tier.grants_full_ubi()
    }

    pub fn tier(&self) -> &VerificationTier {
        &self.charm.tier
    }

    /// Sponsor a Charmed Agent (Section 5.3).
    pub fn sponsor_agent(&mut self, agent_address: &str) -> IdResult<()> {
        if !self.charm.tier.can_sponsor_agents() {
            return Err(IdentityError::NotVerified(
                self.id.clone(),
                self.charm.tier.clone(),
            ));
        }
        if !self.sponsored_agents.contains(&agent_address.to_string()) {
            self.sponsored_agents.push(agent_address.to_string());
        }
        Ok(())
    }

    /// Revoke a sponsored agent.
    pub fn revoke_agent(&mut self, agent_address: &str) {
        self.sponsored_agents.retain(|a| a != agent_address);
    }

    pub fn has_sponsored(&self, agent_address: &str) -> bool {
        self.sponsored_agents.contains(&agent_address.to_string())
    }
}

// -- UBI epoch clock ----------------------------------------------------------

/// Tracks the current UBI epoch and manages claim windows.
///
/// One epoch = one day (86,400 seconds) in production.
/// Phase 0: epoch advances manually for testing.
/// Daily UBI rate: 1,000 $QRC per verified human (Whitepaper 6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiClock {
    pub current_epoch:    u64,
    pub epoch_start_ms:   u64,
    pub epoch_duration_ms: u64,
    /// Total $QRC distributed across all epochs.
    pub total_distributed: u128,
}

/// Daily UBI rate per verified human in base uqrc units.
/// 1,000 $QRC = 1,000,000,000 uqrc (assuming 6 decimal places).
pub const DAILY_UBI_RATE_UQRC: u128 = 1_000_000_000;

impl UbiClock {
    pub fn new(genesis_time_ms: u64) -> Self {
        Self {
            current_epoch:     0,
            epoch_start_ms:    genesis_time_ms,
            epoch_duration_ms: 86_400_000, // 24 hours
            total_distributed: 0,
        }
    }

    /// For testing: create a clock with short epochs.
    pub fn with_epoch_duration_ms(genesis_time_ms: u64, duration_ms: u64) -> Self {
        Self {
            current_epoch:     0,
            epoch_start_ms:    genesis_time_ms,
            epoch_duration_ms: duration_ms,
            total_distributed: 0,
        }
    }

    /// Advance to the next epoch. Returns true if the epoch actually advanced.
    pub fn try_advance(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.epoch_start_ms);
        if elapsed >= self.epoch_duration_ms {
            let epochs_passed = elapsed / self.epoch_duration_ms;
            self.current_epoch += epochs_passed;
            self.epoch_start_ms += epochs_passed * self.epoch_duration_ms;
            tracing::info!(epoch = self.current_epoch, "UBI epoch advanced");
            true
        } else {
            false
        }
    }

    /// Calculate UBI for one verified human for one epoch.
    pub fn ubi_per_epoch() -> u128 {
        DAILY_UBI_RATE_UQRC
    }

    /// Total UBI to distribute to all verified humans this epoch.
    pub fn total_ubi_for_epoch(&self, verified_count: usize) -> u128 {
        Self::ubi_per_epoch() * verified_count as u128
    }
}

// -- Identity store -----------------------------------------------------------

/// The canonical registry of all identity records on QCB.
///
/// CharmConfinement (Section 5.1) is enforced here:
///   - One UBI claim per verified identity per epoch
///   - Agent sponsorship bounded by identity tier
///   - Liveness enforcement gates continued rights
///
/// Phase A additions (attestation guard data model):
///   - `attestation_records`: the per-pair record of every attestation event,
///     used as the source of truth for penalty lookup (Phase C) and cap slot
///     tracking (Phase B).
///   - `coordinator_id`: the pilot-phase coordinator key. None until set;
///     required for confirm_sybil / reverse_sybil (Phase C). Named here as
///     a pilot-phase temporary centralization — see design doc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStore {
    records:  HashMap<String, IdentityRecord>,
    /// Index: address -> identity_id for fast lookup by account address.
    by_address: HashMap<String, String>,
    pub clock: UbiClock,
    /// Phase A: per-pair attestation records for penalty and cap tracking.
    ///
    /// Key order: (attester_id, attested_id). This choice is a named trade-off:
    ///
    ///   - attestations_by_attester(attester_id): full scan. O(n) over all records
    ///     where n = total attestation count across all attesters. This is the
    ///     Phase B query (cap enforcement) and it happens on every new attestation.
    ///
    ///   - attestations_for_identity(attested_id): full scan. O(n) over the same
    ///     set. This is the Phase C query (penalty walk on sybil confirmation) and
    ///     it is infrequent (only on coordinator confirm_sybil).
    ///
    /// Neither key order gives efficient lookup on both axes in a single HashMap.
    /// A second reverse index (attested_id → Vec<attester_id>) would make one
    /// query O(1) but adds write complexity and a consistency surface.
    ///
    /// PILOT ASSUMPTION: at pilot scale (hundreds to low thousands of total
    /// attestations), full scans are acceptable. If total attestation count
    /// exceeds ~50,000, add a reverse index:
    ///   `attestations_by_attested: HashMap<String, Vec<String>>`
    /// pointing from attested_id to the list of attester_ids.
    /// This assumption must be revisited before production scale.
    ///
    /// KEY FORMAT: `"{attester_id}\x00{attested_id}"` — null byte separator.
    /// The null byte cannot appear in identity IDs (which are address strings),
    /// so there is no collision risk. This format is chosen over a tuple key
    /// because serde_json cannot serialize HashMap<(String,String), _> to valid
    /// JSON (tuple keys become JSON arrays, which are illegal as object keys).
    /// See `attestation_record_key()` for the canonical constructor.
    pub(crate) attestation_records: HashMap<String, AttestationRecord>,
    /// Phase C (pilot-phase centralization): the coordinator identity ID.
    /// None = coordinator not yet configured; Some(id) = coordinator is active.
    /// Required for confirm_sybil and reverse_sybil calls.
    /// This is a named temporary centralization — see QCB-Attestation-Guard-Design.md,
    /// "Pilot-Phase Centralization" section. Migrates to on-chain governance post-pilot.
    pub coordinator_id: Option<String>,
    /// Phase C: audit log of sybil confirmations and their reversals.
    ///
    /// Key: sybil identity ID. One entry per confirmed sybil. Reversed entries
    /// are kept (reversed=true) for auditability. This map is append-only from
    /// the coordinator's perspective; entries are never deleted.
    pub(crate) sybil_confirmations: HashMap<String, SybilConfirmationLog>,
    /// Phase D: pending self-reports from attesters who suspect an identity
    /// they vouched for is a sybil, submitted before coordinator confirmation.
    ///
    /// Key: suspected identity ID → list of reports from attesters.
    /// Cleared (entry removed) when `confirm_sybil` is called and the reports
    /// are consumed into the confirmation log's `PenaltyRecord.self_reported` fields.
    /// Entries are also preserved if the coordinator reverses and re-confirms.
    pub(crate) pending_sybil_reports: HashMap<String, Vec<SybilReport>>,
}

impl IdentityStore {
    pub fn new(genesis_time_ms: u64) -> Self {
        Self {
            records:    HashMap::new(),
            by_address: HashMap::new(),
            clock:      UbiClock::new(genesis_time_ms),
            attestation_records: HashMap::new(),
            coordinator_id: None,
            sybil_confirmations: HashMap::new(),
            pending_sybil_reports: HashMap::new(),
        }
    }

    /// For testing: create a store with short epoch duration.
    pub fn with_epoch_ms(genesis_time_ms: u64, epoch_duration_ms: u64) -> Self {
        Self {
            records:    HashMap::new(),
            by_address: HashMap::new(),
            clock:      UbiClock::with_epoch_duration_ms(genesis_time_ms, epoch_duration_ms),
            attestation_records: HashMap::new(),
            coordinator_id: None,
            sybil_confirmations: HashMap::new(),
            pending_sybil_reports: HashMap::new(),
        }
    }

    // -- Registration and verification ----------------------------------------

    /// Register a new Provisional identity.
    pub fn register(
        &mut self,
        id: String,
        address: String,
        attestation: PopAttestation,
    ) -> IdResult<()> {
        if self.records.contains_key(&id) {
            return Err(IdentityError::AlreadyExists(id));
        }
        // Registration creates a Provisional identity; no ZK proof is
        // required at registration time (structural checks only).
        attestation.verify(None)?;
        let epoch = self.clock.current_epoch;
        let record = IdentityRecord::new(id.clone(), address.clone(), attestation, epoch);
        self.by_address.insert(address, id.clone());
        self.records.insert(id, record);
        Ok(())
    }

    /// Verify a Provisional identity (upgrade to Verified).
    ///
    /// * `verifier = None`  — Phase 0 (genesis / tests): no ZK proof required.
    ///   The attestation's structural checks (non-empty identity_id, attester)
    ///   are still enforced.
    ///
    /// * `verifier = Some(v)` — Phase 1+: the embedded `attestation.proof`
    ///   is passed to `v.verify_pop_proof(...)`. Non-genesis attestations
    ///   without a proof are rejected. Use `PopAttestation::verify_with_inputs`
    ///   directly when the VRC root must be supplied as a separate public input.
    pub fn verify_identity(
        &mut self,
        id: &str,
        attestation: PopAttestation,
        verifier: Option<&dyn PopProofVerifier>,
    ) -> IdResult<()> {
        let record = self.records.get_mut(id)
            .ok_or_else(|| IdentityError::NotFound(id.to_string()))?;
        record.verify(attestation, verifier)?;
        tracing::info!(id, "identity verified (Provisional -> Verified)");
        Ok(())
    }

    /// Record a web-of-trust attestation: `attester_id` vouches that
    /// `claimant_id` is a unique human. This is the real Phase 1 mechanism
    /// named in Whitepaper Section 4 and specified in the Identity Pilot
    /// Design (Section 3.1) -- distinct from verify_identity() above, which
    /// remains the Phase 0 genesis bootstrap path (a single attestation
    /// immediately upgrades a genesis identity, since there is no existing
    /// Verified population yet to draw attesters from at genesis).
    ///
    /// Enforces, in order:
    /// - an identity cannot attest for itself
    /// - the attester must already be Verified or Established -- a
    ///   Provisional identity cannot vouch for anyone, which is what
    ///   prevents two Provisional (possibly synthetic) identities from
    ///   bootstrapping each other into Verified status
    /// - the claimant must currently be Provisional (already-Verified
    ///   identities don't need more attestations)
    /// - the attester can only vouch for a given claimant once (repeat
    ///   attestations from the same attester don't inflate the count)
    /// - the attester is rate-limited to ATTESTATION_CAP_PER_WINDOW
    ///   active attestations in a rolling ATTESTATION_CAP_WINDOW_EPOCHS window;
    ///   revoked attestations free their slot back
    ///
    /// Once the claimant's distinct-attester count reaches
    /// ATTESTATION_QUORUM, the claimant is upgraded to Verified as a
    /// side effect of this call.
    pub fn attest(
        &mut self,
        claimant_id: &str,
        attester_id: &str,
    ) -> IdResult<AttestationOutcome> {
        if claimant_id == attester_id {
            return Err(IdentityError::SelfAttestation(attester_id.to_string()));
        }

        let attester_tier = self.records.get(attester_id)
            .ok_or_else(|| IdentityError::NotFound(attester_id.to_string()))?
            .tier()
            .clone();
        if !attester_tier.grants_full_ubi() {
            return Err(IdentityError::AttesterNotVerified(attester_id.to_string()));
        }

        {
            let claimant = self.records.get(claimant_id)
                .ok_or_else(|| IdentityError::NotFound(claimant_id.to_string()))?;
            if !matches!(claimant.tier(), VerificationTier::Provisional) {
                return Err(IdentityError::AlreadyVerified(claimant_id.to_string()));
            }
            if claimant.attestation_ledger.has_attested(attester_id) {
                return Err(IdentityError::AlreadyAttested(attester_id.to_string()));
            }
        }

        let epoch = self.clock.current_epoch;

        // Phase B: rolling-window cap enforcement.
        // Count active attestations from this attester in the last
        // ATTESTATION_CAP_WINDOW_EPOCHS epochs. Derived from attestation_records
        // so it stays consistent with revocations without a separate buffer.
        let window_start = epoch.saturating_sub(ATTESTATION_CAP_WINDOW_EPOCHS);
        let active_in_window = self.attestations_by_attester(attester_id)
            .iter()
            .filter(|r| r.is_active() && r.epoch >= window_start)
            .count() as u32;

        if active_in_window >= ATTESTATION_CAP_PER_WINDOW {
            return Err(IdentityError::AttestationCapExceeded(
                attester_id.to_string(),
                active_in_window,
                ATTESTATION_CAP_WINDOW_EPOCHS,
            ));
        }

        let claimant = self.records.get_mut(claimant_id).unwrap();
        claimant.attestation_ledger.add(attester_id.to_string());
        let count = claimant.attestation_ledger.count();

        // Phase A: write the attestation record. This is the source of truth
        // for Phase B (cap slot tracking) and Phase C (penalty lookup).
        let record = AttestationRecord::new(
            attester_id.to_string(),
            claimant_id.to_string(),
            epoch,
        );
        self.attestation_records.insert(
            attestation_record_key(attester_id, claimant_id),
            record,
        );

        if count >= ATTESTATION_QUORUM {
            claimant.charm.verify(epoch);
            tracing::info!(
                claimant_id, attester_count = count,
                "identity verified via web-of-trust quorum (Provisional -> Verified)"
            );
            Ok(AttestationOutcome::QuorumReachedVerified)
        } else {
            Ok(AttestationOutcome::Recorded { attester_count: count, quorum: ATTESTATION_QUORUM })
        }
    }

    /// Revoke a previously-given attestation.
    ///
    /// Phase A: updates the `AttestationRecord` status to `Revoked` and records
    /// the revocation epoch. The rolling-window cap slot is freed automatically
    /// because Phase B's cap count excludes Revoked records.
    ///
    /// Phase D: returns a `RevocationCost` that the execution layer uses to
    /// apply the flat CS deduction (REVOCATION_COST_BPS = 10% of CS earned
    /// from this attestation). The identity crate does not own CS arithmetic;
    /// `RevocationCost` is the signal, not the deduction itself.
    ///
    /// Design decision Q1: revocation frees the rolling-window cap slot.
    /// An honest attester who discovers a mistake is not penalized by a
    /// permanently reduced future budget on top of the CS cost.
    ///
    /// Returns `Err(AttestationNotFound)` if no active attestation from
    /// `attester_id` for `attested_id` exists. Returns
    /// `Err(AttestationAlreadyRevoked)` if already revoked.
    pub fn revoke_attestation(
        &mut self,
        attester_id: &str,
        attested_id: &str,
    ) -> IdResult<RevocationCost> {
        let key = attestation_record_key(attester_id, attested_id);
        let epoch = self.clock.current_epoch;

        let rec = self.attestation_records.get_mut(&key)
            .ok_or_else(|| IdentityError::AttestationNotFound(
                attester_id.to_string(),
                attested_id.to_string(),
            ))?;

        match rec.status {
            AttestationStatus::Revoked => {
                return Err(IdentityError::AttestationAlreadyRevoked(
                    attester_id.to_string(),
                    attested_id.to_string(),
                ));
            }
            AttestationStatus::Penalized => {
                // A penalized attestation means the CS penalty has already been
                // applied by confirm_sybil. Revocation at this point would remove
                // the ledger entry without undoing the penalty — a confusing state.
                // The correct sequence is: coordinator calls reverse_sybil first
                // (which clears Penalized → Active and credits back the CS), then
                // the attester can revoke normally. This error makes that explicit
                // rather than silently allowing a Penalized → Revoked transition
                // that leaves penalty_applied=true on a "revoked" record.
                return Err(IdentityError::AttestationAlreadyPenalized(
                    attester_id.to_string(),
                    attested_id.to_string(),
                ));
            }
            AttestationStatus::Active => {
                rec.status = AttestationStatus::Revoked;
                rec.revocation_epoch = Some(epoch);
            }
        }

        // Remove this attester's contribution from the attested identity's
        // ledger and CS contribution. The identity is not marked as sybil —
        // only a coordinator confirm_sybil does that (Phase C).
        if let Some(identity) = self.records.get_mut(attested_id) {
            identity.attestation_ledger.attesters.retain(|a| a != attester_id);
            // If removing this attestation drops the count below quorum AND
            // the identity is currently Verified solely because of this
            // quorum, it should be re-evaluated. For Phase A, we flag it
            // in the record only — full tier re-evaluation is Phase C scope.
            // (An identity that was verified through other paths, such as
            // verify_identity(), is not affected by attestation revocation.)
        }

        tracing::info!(
            attester_id, attested_id, epoch,
            "attestation revoked"
        );
        Ok(RevocationCost {
            attester_id: attester_id.to_string(),
            attested_id: attested_id.to_string(),
            cost_bps: REVOCATION_COST_BPS,
        })
    }

    /// Return all attestation records where `attester_id` is the attester.
    ///
    /// Phase A query method. Used by the coordinator dashboard (Phase E) and
    /// by Phase B cap enforcement to count active attestations in the rolling window.
    pub fn attestations_by_attester(&self, attester_id: &str) -> Vec<&AttestationRecord> {
        self.attestation_records.values()
            .filter(|r| r.attester_id == attester_id)
            .collect()
    }

    /// Return all attestation records where `attested_id` is the attested identity.
    ///
    /// Phase C uses this to walk all attesters who vouched for a confirmed sybil,
    /// applying CS penalties to each active attester.
    pub fn attestations_for_identity(&self, attested_id: &str) -> Vec<&AttestationRecord> {
        self.attestation_records.values()
            .filter(|r| r.attested_id == attested_id)
            .collect()
    }

    // -- UBI claim gating (Charm Confinement) ---------------------------------

    /// Claim UBI for a verified identity.
    /// Enforces: one claim per epoch, verified tier, liveness.
    /// Returns the amount of uqrc to credit to the account.
    pub fn claim_ubi(&mut self, id: &str) -> IdResult<u128> {
        let epoch = self.clock.current_epoch;
        let record = self.records.get_mut(id)
            .ok_or_else(|| IdentityError::NotFound(id.to_string()))?;

        // Tier check
        if !record.charm.tier.grants_full_ubi() {
            return Err(IdentityError::NotVerified(
                id.to_string(),
                record.charm.tier.clone(),
            ));
        }

        // Liveness check (Q24)
        if !record.charm.is_lively(epoch) {
            return Err(IdentityError::Lapsed(
                id.to_string(),
                record.charm.last_attested_epoch,
                epoch,
            ));
        }

        // Charm Confinement: one claim per epoch (Section 5.1)
        if record.claimed_this_epoch {
            return Err(IdentityError::AlreadyClaimed(id.to_string(), epoch));
        }

        // Earned-yield gate: QRC is NOT a UBI drip — it must be earned.
        // The identity must have performed at least one on-chain action this
        // epoch (tx submission, validator participation, merchant settlement).
        // record_activity() / record_activity_by_address() are called by the
        // execution layer whenever such an event occurs.
        let active_this_epoch = record.last_active_epoch == Some(epoch);
        if !active_this_epoch {
            return Err(IdentityError::NotVerified(
                id.to_string(),
                record.charm.tier.clone(),
            ));
        }

        let amount = UbiClock::ubi_per_epoch();
        record.claimed_this_epoch = true;
        record.total_ubi_claimed += amount;
        record.charm.record_participation(epoch);
        self.clock.total_distributed += amount;

        tracing::debug!(id, epoch, amount_uqrc = amount, "QRC yield claimed");
        Ok(amount)
    }

    /// Record on-chain activity for an identity, enabling QRC yield claim
    /// for this epoch. Called by the execution layer whenever a verified
    /// identity submits a tx, participates as a validator, or processes a
    /// merchant settlement. No-op if the identity is not found.
    pub fn record_activity(&mut self, id: &str) {
        let epoch = self.clock.current_epoch;
        if let Some(record) = self.records.get_mut(id) {
            record.last_active_epoch = Some(epoch);
            tracing::debug!(id, epoch, "on-chain activity recorded for QRC yield eligibility");
        }
    }

    /// Same as record_activity but looks up by wallet address rather than
    /// identity id. Used by the execution layer which knows addresses, not ids.
    pub fn record_activity_by_address(&mut self, address: &str) {
        let epoch = self.clock.current_epoch;
        // find the record whose address matches
        for record in self.records.values_mut() {
            if record.address == address {
                record.last_active_epoch = Some(epoch);
                tracing::debug!(address, epoch, "on-chain activity recorded for QRC yield eligibility");
                return;
            }
        }
    }

    /// Advance the UBI epoch. Resets claim flags for all identities.
    /// Also enforces liveness -- lapsed identities are downgraded.
    pub fn advance_epoch(&mut self, now_ms: u64) -> bool {
        if !self.clock.try_advance(now_ms) {
            return false;
        }
        let current = self.clock.current_epoch;

        // Reset claim flags and enforce liveness for all identities
        for record in self.records.values_mut() {
            record.claimed_this_epoch = false;

            // Liveness enforcement (Q24): downgrade if inactive too long
            if record.charm.tier != VerificationTier::Provisional
                && !record.charm.is_lively(current)
            {
                record.charm.lapse();
            }
        }

        tracing::info!(epoch = current, "UBI epoch advanced, claim flags reset");
        true
    }

    // -- Agent sponsorship ----------------------------------------------------

    /// Authorize an agent under a verified human sponsor.
    pub fn sponsor_agent(
        &mut self,
        sponsor_id: &str,
        agent_address: &str,
    ) -> IdResult<()> {
        let record = self.records.get_mut(sponsor_id)
            .ok_or_else(|| IdentityError::NotFound(sponsor_id.to_string()))?;
        record.sponsor_agent(agent_address)?;
        tracing::info!(sponsor = sponsor_id, agent = agent_address, "agent sponsored");
        Ok(())
    }

    /// Check if an agent is authorized by a specific sponsor.
    pub fn is_agent_authorized(&self, agent_address: &str, sponsor_id: &str) -> bool {
        self.records.get(sponsor_id)
            .map(|r| r.has_sponsored(agent_address))
            .unwrap_or(false)
    }

    /// Find the sponsor of an agent (any sponsor).
    pub fn find_agent_sponsor(&self, agent_address: &str) -> Option<&str> {
        self.records.values()
            .find(|r| r.has_sponsored(agent_address))
            .map(|r| r.id.as_str())
    }

    // -- Lookups --------------------------------------------------------------

    pub fn get(&self, id: &str) -> IdResult<&IdentityRecord> {
        self.records.get(id)
            .ok_or_else(|| IdentityError::NotFound(id.to_string()))
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut IdentityRecord> {
        self.records.get_mut(id)
    }

    pub fn get_by_address(&self, address: &str) -> IdResult<&IdentityRecord> {
        let id = self.by_address.get(address)
            .ok_or_else(|| IdentityError::NotFound(address.to_string()))?;
        self.get(id)
    }

    pub fn is_verified(&self, id: &str) -> bool {
        self.records.get(id)
            .map(|r| r.is_verified())
            .unwrap_or(false)
    }

    pub fn verified_count(&self) -> usize {
        self.records.values()
            .filter(|r| r.charm.tier.grants_full_ubi())
            .count()
    }

    pub fn total_registered(&self) -> usize {
        self.records.len()
    }

    /// All verified identity IDs -- used by consensus to build validator set.
    /// Optional get by address (returns None instead of Err).
    pub fn get_by_address_opt(&self, address: &str) -> Option<&IdentityRecord> {
        self.by_address.get(address)
            .and_then(|id| self.records.get(id))
    }

    pub fn verified_identity_ids(&self) -> Vec<String> {
        self.records.values()
            .filter(|r| r.charm.tier.grants_consensus())
            .map(|r| r.id.clone())
            .collect()
    }

    // -- Test helpers ---------------------------------------------------------
    //
    // These methods manipulate internal epoch state and are intended for use
    // in integration tests that need to control who lapses across a clock jump.
    // They are `pub` so downstream crates (chain-forge-node's tests) can reach
    // them; the names make their test-only intent clear.

    /// Make exactly one identity appear to have been inactive long enough to
    /// lapse when `advance_epoch` is next called, without touching any other
    /// identity. Use this in epoch-manipulation tests to be explicit about
    /// who lapses — prevents the "all validators lapse when you jump the clock"
    /// class of test bugs.
    ///
    /// Sets `last_attested_epoch` to 0 for `id` only. Call this before any
    /// clock jump; identities you want to stay lively should have a
    /// `last_attested_epoch` within `LIVENESS_EPOCH_WINDOW` of the target epoch.
    pub fn lapse_only(&mut self, id: &str, _target_epoch: u64) {
        if let Some(record) = self.records.get_mut(id) {
            record.charm.last_attested_epoch = 0;
        }
    }

    /// Keep `id` lively through a clock jump to `target_epoch`. Sets
    /// `last_attested_epoch` to a value within `LIVENESS_EPOCH_WINDOW` of
    /// `target_epoch` (specifically, `target_epoch - LIVENESS_EPOCH_WINDOW / 2`).
    ///
    /// Use alongside `lapse_only` to be explicit about which identities survive
    /// an epoch jump and which do not.
    pub fn stay_lively(&mut self, id: &str, target_epoch: u64) {
        if let Some(record) = self.records.get_mut(id) {
            // Pick a recent-enough epoch that the identity remains lively.
            record.charm.last_attested_epoch =
                target_epoch.saturating_sub(LIVENESS_EPOCH_WINDOW / 2);
        }
    }

    // -- Phase C: coordinator role and sybil confirmation ---------------------

    /// Configure the pilot-phase coordinator identity.
    ///
    /// The coordinator is the only entity authorized to call `confirm_sybil`
    /// and `reverse_sybil`. This is a named temporary centralization; see the
    /// QCB-Attestation-Guard-Design.md "Pilot-Phase Centralization" section.
    ///
    /// Can be called multiple times to rotate the coordinator key.
    /// Passing `None` disables the coordinator role (no sybil confirmations
    /// possible until a new coordinator is set).
    pub fn set_coordinator(&mut self, coordinator_id: Option<String>) {
        self.coordinator_id = coordinator_id;
    }

    /// Confirm an identity as a sybil (coordinator-only).
    ///
    /// Effects:
    /// - All ACTIVE attestation records for `sybil_id` are marked `Penalized`
    ///   and `penalty_applied = true`. Revoked records are untouched — the
    ///   attester already paid the revocation cost and exited cleanly.
    /// - A `SybilConfirmationLog` entry is written with the list of penalized
    ///   attesters, for use by `reverse_sybil`.
    /// - Returns the list of attester IDs that were penalized, so the
    ///   execution layer can apply the CS deduction to each.
    ///
    /// Errors:
    /// - `CoordinatorNotSet`: no coordinator configured.
    /// - `NotCoordinator`: caller is not the configured coordinator.
    /// - `IdentityNotFound`: `sybil_id` is not registered.
    /// - `AlreadyConfirmedSybil`: already confirmed and not yet reversed.
    pub fn confirm_sybil(
        &mut self,
        caller_id: &str,
        sybil_id: &str,
    ) -> IdResult<Vec<String>> {
        // Auth: only the coordinator can confirm sybils.
        let coord = self.coordinator_id.clone()
            .ok_or(IdentityError::CoordinatorNotSet)?;
        if caller_id != coord {
            return Err(IdentityError::NotCoordinator(caller_id.to_string()));
        }

        // The sybil identity must be registered.
        if !self.records.contains_key(sybil_id) {
            return Err(IdentityError::IdentityNotFound(sybil_id.to_string()));
        }

        // Idempotency: cannot re-confirm an already-confirmed sybil.
        if let Some(log) = self.sybil_confirmations.get(sybil_id) {
            if !log.reversed {
                return Err(IdentityError::AlreadyConfirmedSybil(sybil_id.to_string()));
            }
        }

        let epoch = self.clock.current_epoch;

        // Collect any pending self-reports for this identity (Phase D).
        // These are attesters who flagged this identity as suspected before
        // the coordinator acted — they receive the reduced penalty rate.
        let self_reporters: std::collections::HashSet<String> = self
            .pending_sybil_reports
            .remove(sybil_id)
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.attester_id)
            .collect();

        // Walk all attestation records for this identity. Penalize active
        // ones; skip revoked ones (attester already paid their exit cost).
        let mut penalty_records: Vec<PenaltyRecord> = Vec::new();
        for record in self.attestation_records.values_mut() {
            if record.attested_id == sybil_id && record.status == AttestationStatus::Active {
                record.status = AttestationStatus::Penalized;
                record.penalty_applied = true;

                let self_reported = self_reporters.contains(&record.attester_id);
                // Reduced rate for self-reporters: standard * (1 - reduction)
                // E.g. 12000 * (1 - 5000/10000) = 12000 * 50% = 6000 bps (60%)
                let penalty_bps = if self_reported {
                    ATTEST_PENALTY_RATE_BPS
                        * (10_000 - SELF_REPORT_PENALTY_REDUCTION_BPS)
                        / 10_000
                } else {
                    ATTEST_PENALTY_RATE_BPS
                };

                penalty_records.push(PenaltyRecord {
                    attester_id: record.attester_id.clone(),
                    penalty_bps,
                    self_reported,
                });
            }
        }

        // Collect attester IDs for the return value (execution layer applies CS deductions).
        let penalized_ids: Vec<String> = penalty_records.iter()
            .map(|pr| pr.attester_id.clone())
            .collect();

        // Write the confirmation log entry.
        self.sybil_confirmations.insert(
            sybil_id.to_string(),
            SybilConfirmationLog {
                sybil_id: sybil_id.to_string(),
                coordinator_id: coord,
                confirmed_epoch: epoch,
                penalized_attesters: penalty_records,
                reversed: false,
                reversal_epoch: None,
            },
        );

        tracing::info!(
            sybil_id,
            coordinator = caller_id,
            epoch,
            penalized_count = penalized_ids.len(),
            "sybil confirmed; attesters penalized"
        );

        Ok(penalized_ids)
    }

    /// File a self-report: `attester_id` flags an identity they vouched for
    /// as a suspected sybil before the coordinator acts (Phase D).
    ///
    /// If the coordinator subsequently calls `confirm_sybil` for this identity,
    /// this attester's CS penalty is reduced by SELF_REPORT_PENALTY_REDUCTION_BPS
    /// (50% of the standard rate). If the identity is never confirmed, the report
    /// has no effect.
    ///
    /// Requirements:
    /// - The attester must have an active (non-revoked, non-penalized) attestation
    ///   for `suspected_id`. An attester who has already revoked their attestation
    ///   has no exposure and cannot file a report.
    /// - The attester may not file a duplicate report for the same suspected identity.
    ///
    /// Returns `Ok(())` if the report was accepted.
    pub fn report_suspected_sybil(
        &mut self,
        attester_id: &str,
        suspected_id: &str,
    ) -> IdResult<()> {
        // The attester must have an active attestation for this identity.
        let key = attestation_record_key(attester_id, suspected_id);
        let record = self.attestation_records.get(&key)
            .ok_or_else(|| IdentityError::CannotReportWithoutAttestation(
                attester_id.to_string(),
                suspected_id.to_string(),
            ))?;
        if !record.is_active() {
            return Err(IdentityError::CannotReportWithoutAttestation(
                attester_id.to_string(),
                suspected_id.to_string(),
            ));
        }

        // Reject duplicate reports from the same attester for the same identity.
        let reports = self.pending_sybil_reports
            .entry(suspected_id.to_string())
            .or_insert_with(Vec::new);
        if reports.iter().any(|r| r.attester_id == attester_id) {
            return Err(IdentityError::AlreadyReported(
                attester_id.to_string(),
                suspected_id.to_string(),
            ));
        }

        let epoch = self.clock.current_epoch;
        reports.push(SybilReport {
            attester_id: attester_id.to_string(),
            suspected_id: suspected_id.to_string(),
            report_epoch: epoch,
        });

        tracing::info!(
            attester_id, suspected_id, epoch,
            "self-report filed; attester will receive penalty reduction if identity is confirmed as sybil"
        );
        Ok(())
    }

    /// Reverse a sybil confirmation (coordinator-only).
    ///
    /// Effects:
    /// - All `Penalized` attestation records that were penalized in the
    ///   original `confirm_sybil` call are restored to `Active` with
    ///   `penalty_applied = false`.
    /// - The `SybilConfirmationLog` entry is marked `reversed = true`.
    /// - Returns the list of attester IDs whose penalties were reversed,
    ///   so the execution layer can credit the CS back.
    ///
    /// Errors:
    /// - `CoordinatorNotSet`: no coordinator configured.
    /// - `NotCoordinator`: caller is not the configured coordinator.
    /// - `SybilConfirmationNotFound`: no confirmation exists for `sybil_id`,
    ///   or the confirmation has already been reversed.
    pub fn reverse_sybil(
        &mut self,
        caller_id: &str,
        sybil_id: &str,
    ) -> IdResult<Vec<String>> {
        // Auth: only the coordinator can reverse.
        let coord = self.coordinator_id.clone()
            .ok_or(IdentityError::CoordinatorNotSet)?;
        if caller_id != coord {
            return Err(IdentityError::NotCoordinator(caller_id.to_string()));
        }

        let epoch = self.clock.current_epoch;

        // Find the confirmation log; fail if it doesn't exist or is already reversed.
        let penalized_attesters = {
            let log = self.sybil_confirmations.get_mut(sybil_id)
                .filter(|l| !l.reversed)
                .ok_or_else(|| IdentityError::SybilConfirmationNotFound(sybil_id.to_string()))?;
            log.reversed = true;
            log.reversal_epoch = Some(epoch);
            log.penalized_attesters.clone()
        };

        // Restore each penalized record back to Active.
        // penalized_attesters is Vec<PenaltyRecord>; extract the attester IDs.
        let attester_ids: Vec<String> = penalized_attesters.iter()
            .map(|pr| pr.attester_id.clone())
            .collect();

        for attester_id in &attester_ids {
            let key = attestation_record_key(attester_id, sybil_id);
            if let Some(record) = self.attestation_records.get_mut(&key) {
                if record.status == AttestationStatus::Penalized {
                    record.status = AttestationStatus::Active;
                    record.penalty_applied = false;
                }
            }
        }

        tracing::info!(
            sybil_id,
            coordinator = caller_id,
            epoch,
            restored_count = attester_ids.len(),
            "sybil confirmation reversed; attester penalties cleared"
        );

        Ok(attester_ids)
    }

    /// Look up the sybil confirmation log for an identity (read-only).
    pub fn sybil_confirmation(&self, identity_id: &str) -> Option<&SybilConfirmationLog> {
        self.sybil_confirmations.get(identity_id)
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> IdentityStore {
        IdentityStore::new(0)
    }

    fn genesis_attestation(id: &str) -> PopAttestation {
        PopAttestation::genesis(id, 0)
    }

    fn register_and_verify(store: &mut IdentityStore, id: &str, address: &str) {
        store.register(
            id.to_string(),
            address.to_string(),
            genesis_attestation(id),
        ).unwrap();
        store.verify_identity(id, genesis_attestation(id), None).unwrap();
    }

    // -- VerificationTier tests -----------------------------------------------

    #[test]
    fn provisional_grants_no_rights() {
        let tier = VerificationTier::Provisional;
        assert!(!tier.grants_full_ubi());
        assert!(!tier.grants_consensus());
        assert!(!tier.grants_governance());
        assert!(!tier.can_sponsor_agents());
        assert_eq!(tier.consensus_power(), 0);
    }

    #[test]
    fn verified_grants_all_rights() {
        let tier = VerificationTier::Verified;
        assert!(tier.grants_full_ubi());
        assert!(tier.grants_consensus());
        assert!(tier.grants_governance());
        assert!(tier.can_sponsor_agents());
        assert_eq!(tier.consensus_power(), 1);
    }

    #[test]
    fn tier_ordering_is_correct() {
        assert!(VerificationTier::Provisional < VerificationTier::Verified);
        assert!(VerificationTier::Verified < VerificationTier::Established);
    }

    // -- DecayExemption tests -------------------------------------------------

    #[test]
    fn decay_exemption_caps_at_30_days() {
        let mut ex = DecayExemption::new();
        for epoch in 0..50 {
            ex.record_spend(epoch);
        }
        assert_eq!(ex.days, MAX_EXEMPTION_DAYS);
    }

    #[test]
    fn decay_exemption_consume_partial() {
        let mut ex = DecayExemption::new();
        ex.record_spend(0);
        ex.record_spend(1);
        ex.record_spend(2); // 3 days

        let consumed = ex.consume(2);
        assert_eq!(consumed, 2);
        assert_eq!(ex.days, 1);
    }

    #[test]
    fn decay_exemption_consume_clamps_to_available() {
        let mut ex = DecayExemption::new();
        ex.record_spend(0); // 1 day

        let consumed = ex.consume(10); // ask for 10, only 1 available
        assert_eq!(consumed, 1);
        assert_eq!(ex.days, 0);
    }

    // -- IntrinsicCharm tests -------------------------------------------------

    #[test]
    fn intrinsic_charm_provisional_at_creation() {
        let charm = IntrinsicCharm::provisional(0);
        assert_eq!(charm.tier, VerificationTier::Provisional);
        assert!(!charm.decay_exemption.has_exemption());
    }

    #[test]
    fn intrinsic_charm_verify_upgrades_tier() {
        let mut charm = IntrinsicCharm::provisional(0);
        charm.verify(1);
        assert_eq!(charm.tier, VerificationTier::Verified);
        assert_eq!(charm.verified_since_epoch, Some(1));
    }

    #[test]
    fn intrinsic_charm_graduates_to_established() {
        let mut charm = IntrinsicCharm::provisional(0);
        charm.verify(0);
        for epoch in 0..30 {
            charm.record_participation(epoch);
        }
        assert_eq!(charm.tier, VerificationTier::Established);
    }

    #[test]
    fn intrinsic_charm_liveness_window() {
        let mut charm = IntrinsicCharm::provisional(0);
        charm.verify(0);
        charm.last_attested_epoch = 0;

        assert!(charm.is_lively(LIVENESS_EPOCH_WINDOW));
        assert!(!charm.is_lively(LIVENESS_EPOCH_WINDOW + 1));
    }

    #[test]
    fn intrinsic_charm_lapse_downgrades() {
        let mut charm = IntrinsicCharm::provisional(0);
        charm.verify(0);
        charm.consecutive_active_epochs = 10;
        charm.lapse();
        assert_eq!(charm.tier, VerificationTier::Provisional);
        assert_eq!(charm.consecutive_active_epochs, 0);
    }

    // -- IdentityStore tests --------------------------------------------------

    #[test]
    fn register_and_verify_identity() {
        let mut store = make_store();
        register_and_verify(&mut store, "human1", "qcb1human1");

        let record = store.get("human1").unwrap();
        assert!(record.is_verified());
        assert_eq!(record.tier(), &VerificationTier::Verified);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut store = make_store();
        store.register("h1".into(), "qcb1h1".into(), genesis_attestation("h1")).unwrap();
        let result = store.register("h1".into(), "qcb1h1b".into(), genesis_attestation("h1"));
        assert!(result.is_err());
    }

    #[test]
    fn provisional_cannot_claim_ubi() {
        let mut store = make_store();
        store.register("h1".into(), "qcb1h1".into(), genesis_attestation("h1")).unwrap();
        // Not verified yet -- should fail
        let result = store.claim_ubi("h1");
        assert!(result.is_err());
    }

    #[test]
    fn verified_but_inactive_cannot_claim_yield() {
        let mut store = make_store();
        register_and_verify(&mut store, "h1", "qcb1h1");

        // Verified but no on-chain activity recorded — must fail.
        let result = store.claim_ubi("h1");
        assert!(result.is_err(), "QRC yield requires on-chain activity; passive claim must fail");
    }

    #[test]
    fn active_verified_identity_claims_yield() {
        let mut store = make_store();
        register_and_verify(&mut store, "h1", "qcb1h1");

        // Record activity (simulates tx submission).
        store.record_activity("h1");

        let amount = store.claim_ubi("h1").unwrap();
        assert_eq!(amount, DAILY_UBI_RATE_UQRC);
    }

    #[test]
    fn charm_confinement_one_claim_per_epoch() {
        let mut store = make_store();
        register_and_verify(&mut store, "h1", "qcb1h1");
        store.record_activity("h1");

        store.claim_ubi("h1").unwrap();
        let second = store.claim_ubi("h1");
        assert!(second.is_err(), "should not allow second claim in same epoch");
    }

    #[test]
    fn epoch_advance_resets_claim_flags() {
        let mut store = IdentityStore::with_epoch_ms(0, 1000);
        register_and_verify(&mut store, "h1", "qcb1h1");

        store.record_activity("h1");
        store.claim_ubi("h1").unwrap();
        store.advance_epoch(1001); // advance past 1 epoch duration

        // Must record activity again in the new epoch before claiming.
        store.record_activity("h1");
        let result = store.claim_ubi("h1");
        assert!(result.is_ok(), "should allow claim in new epoch after activity");
    }

    #[test]
    fn liveness_enforcement_lapses_inactive_identity() {
        let mut store = IdentityStore::with_epoch_ms(0, 1000);
        register_and_verify(&mut store, "h1", "qcb1h1");

        // Advance past the liveness window without any participation
        for i in 1..=(LIVENESS_EPOCH_WINDOW + 2) {
            store.advance_epoch(i * 1000);
        }

        // Identity should have lapsed to Provisional
        let record = store.get("h1").unwrap();
        assert_eq!(record.tier(), &VerificationTier::Provisional);
    }

    #[test]
    fn agent_sponsorship_requires_verified_tier() {
        let mut store = make_store();
        // Register but don't verify
        store.register("h1".into(), "qcb1h1".into(), genesis_attestation("h1")).unwrap();

        let result = store.sponsor_agent("h1", "qcb1agent1");
        assert!(result.is_err(), "provisional identity cannot sponsor agents");
    }

    #[test]
    fn verified_identity_can_sponsor_agent() {
        let mut store = make_store();
        register_and_verify(&mut store, "h1", "qcb1h1");

        store.sponsor_agent("h1", "qcb1agent1").unwrap();
        assert!(store.is_agent_authorized("qcb1agent1", "h1"));
        assert_eq!(store.find_agent_sponsor("qcb1agent1"), Some("h1"));
    }

    #[test]
    fn lookup_by_address() {
        let mut store = make_store();
        register_and_verify(&mut store, "h1", "qcb1h1");

        let record = store.get_by_address("qcb1h1").unwrap();
        assert_eq!(record.id, "h1");
    }

    #[test]
    fn verified_count_tracks_correctly() {
        let mut store = make_store();
        assert_eq!(store.verified_count(), 0);

        register_and_verify(&mut store, "h1", "qcb1h1");
        register_and_verify(&mut store, "h2", "qcb1h2");
        store.register("h3".into(), "qcb1h3".into(), genesis_attestation("h3")).unwrap(); // provisional only

        assert_eq!(store.verified_count(), 2);
        assert_eq!(store.total_registered(), 3);
    }

    #[test]
    fn ubi_clock_advances_on_time() {
        let mut clock = UbiClock::with_epoch_duration_ms(0, 1000);
        assert_eq!(clock.current_epoch, 0);

        let advanced = clock.try_advance(1001);
        assert!(advanced);
        assert_eq!(clock.current_epoch, 1);

        let not_advanced = clock.try_advance(1500);
        assert!(!not_advanced);
        assert_eq!(clock.current_epoch, 1);
    }

    #[test]
    fn total_ubi_accumulates() {
        let mut store = make_store();
        register_and_verify(&mut store, "h1", "qcb1h1");
        register_and_verify(&mut store, "h2", "qcb1h2");

        store.record_activity("h1");
        store.record_activity("h2");

        store.claim_ubi("h1").unwrap();
        store.claim_ubi("h2").unwrap();

        assert_eq!(store.clock.total_distributed, DAILY_UBI_RATE_UQRC * 2);
    }

    // -- Web-of-trust quorum (Phase 1 identity pilot mechanism) ----------------

    fn register_provisional(store: &mut IdentityStore, id: &str, address: &str) {
        store.register(id.to_string(), address.to_string(), genesis_attestation(id)).unwrap();
    }

    #[test]
    fn quorum_upgrades_claimant_after_three_distinct_attestations() {
        let mut store = make_store();
        register_and_verify(&mut store, "a1", "qcb1a1");
        register_and_verify(&mut store, "a2", "qcb1a2");
        register_and_verify(&mut store, "a3", "qcb1a3");
        register_provisional(&mut store, "newbie", "qcb1newbie");

        assert_eq!(*store.get("newbie").unwrap().tier(), VerificationTier::Provisional);

        let r1 = store.attest("newbie", "a1").unwrap();
        assert_eq!(r1, AttestationOutcome::Recorded { attester_count: 1, quorum: ATTESTATION_QUORUM });
        assert_eq!(*store.get("newbie").unwrap().tier(), VerificationTier::Provisional);

        let r2 = store.attest("newbie", "a2").unwrap();
        assert_eq!(r2, AttestationOutcome::Recorded { attester_count: 2, quorum: ATTESTATION_QUORUM });
        assert_eq!(*store.get("newbie").unwrap().tier(), VerificationTier::Provisional);

        let r3 = store.attest("newbie", "a3").unwrap();
        assert_eq!(r3, AttestationOutcome::QuorumReachedVerified);
        assert_eq!(*store.get("newbie").unwrap().tier(), VerificationTier::Verified);
    }

    #[test]
    fn below_quorum_attestations_leave_claimant_provisional() {
        let mut store = make_store();
        register_and_verify(&mut store, "a1", "qcb1a1");
        register_and_verify(&mut store, "a2", "qcb1a2");
        register_provisional(&mut store, "newbie", "qcb1newbie");

        store.attest("newbie", "a1").unwrap();
        store.attest("newbie", "a2").unwrap();

        assert_eq!(*store.get("newbie").unwrap().tier(), VerificationTier::Provisional,
            "2 attestations must not reach a quorum of 3");
    }

    #[test]
    fn duplicate_attestation_from_same_attester_rejected() {
        let mut store = make_store();
        register_and_verify(&mut store, "a1", "qcb1a1");
        register_provisional(&mut store, "newbie", "qcb1newbie");

        store.attest("newbie", "a1").unwrap();
        let result = store.attest("newbie", "a1");

        assert!(matches!(result, Err(IdentityError::AlreadyAttested(_))),
            "the same attester vouching twice must not inflate the count");
    }

    #[test]
    fn self_attestation_rejected() {
        let mut store = make_store();
        register_and_verify(&mut store, "a1", "qcb1a1");

        let result = store.attest("a1", "a1");
        assert!(matches!(result, Err(IdentityError::SelfAttestation(_))));
    }

    #[test]
    fn provisional_identity_cannot_vouch_for_others() {
        let mut store = make_store();
        register_provisional(&mut store, "p1", "qcb1p1");
        register_provisional(&mut store, "p2", "qcb1p2");

        // Two Provisional identities cannot bootstrap each other into
        // Verified status -- this is the specific attack the pilot design
        // names as the web-of-trust base layer's core sybil resistance.
        let result = store.attest("p2", "p1");
        assert!(matches!(result, Err(IdentityError::AttesterNotVerified(_))));
    }

    #[test]
    fn already_verified_claimant_rejects_further_attestations() {
        let mut store = make_store();
        register_and_verify(&mut store, "a1", "qcb1a1");
        register_and_verify(&mut store, "human", "qcb1human"); // already Verified via genesis path

        let result = store.attest("human", "a1");
        assert!(matches!(result, Err(IdentityError::AlreadyVerified(_))));
    }

    #[test]
    fn attestation_rate_limit_enforced_per_epoch() {
        // Phase B: rolling-window cap (ATTESTATION_CAP_PER_WINDOW = 3) is the
        // binding rate limit. ATTESTATION_CAP_PER_WINDOW distinct claimants succeed...
        let mut store = make_store();
        register_and_verify(&mut store, "attester", "qcb1attester");

        for i in 0..ATTESTATION_CAP_PER_WINDOW {
            let id = format!("claimant{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }

        // ...the next one within the same rolling window is rejected.
        register_provisional(&mut store, "one_too_many", "qcb1one_too_many");
        let result = store.attest("one_too_many", "attester");
        assert!(matches!(result, Err(IdentityError::AttestationCapExceeded(_, _, _))));
    }

    #[test]
    fn attestation_rate_limit_resets_next_epoch() {
        // Phase B: the cap resets after ATTESTATION_CAP_WINDOW_EPOCHS (90),
        // not after a single epoch. Advance past the full window to free the budget.
        let mut store = IdentityStore::with_epoch_ms(0, 1);
        register_and_verify(&mut store, "attester", "qcb1attester");

        for i in 0..ATTESTATION_CAP_PER_WINDOW {
            let id = format!("claimant{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }

        register_provisional(&mut store, "blocked_in_window", "qcb1blocked");
        assert!(store.attest("blocked_in_window", "attester").is_err());

        // Advance past the full window so all attestations age out.
        let target_ms = (ATTESTATION_CAP_WINDOW_EPOCHS + 1) as u64;
        store.stay_lively("attester", target_ms);
        store.advance_epoch(target_ms);

        register_provisional(&mut store, "allowed_after_window", "qcb1allowed");
        let result = store.attest("allowed_after_window", "attester");
        assert!(result.is_ok(), "rolling cap must free after window passes, got {:?}", result);
    }

    #[test]
    fn rejected_attestation_does_not_consume_rate_limit_budget() {
        let mut store = make_store();
        register_and_verify(&mut store, "attester", "qcb1attester");
        register_provisional(&mut store, "newbie", "qcb1newbie");

        // A self-attestation attempt and a not-found attempt should both
        // fail WITHOUT spending any of the attester's rolling-window budget.
        let _ = store.attest("attester", "attester"); // self-attestation, rejected
        let _ = store.attest("does_not_exist", "attester"); // NotFound, rejected

        // The attester should still have their full budget -- prove it by
        // successfully using all ATTESTATION_CAP_PER_WINDOW slots afterward.
        for i in 0..ATTESTATION_CAP_PER_WINDOW {
            let id = format!("claimant{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }
    }

    // -- Phase A: attestation record data model --------------------------------

    #[test]
    fn attest_writes_attestation_record() {
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");

        store.attest("bob", "alice").unwrap();

        let records = store.attestations_by_attester("alice");
        assert_eq!(records.len(), 1);
        let rec = records[0];
        assert_eq!(rec.attester_id, "alice");
        assert_eq!(rec.attested_id, "bob");
        assert_eq!(rec.status, AttestationStatus::Active);
        assert!(rec.revocation_epoch.is_none());
        assert!(!rec.penalty_applied);
    }

    #[test]
    fn attestations_by_attester_returns_all_records_for_attester() {
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");
        register_provisional(&mut store, "carol", "qcb1carol");

        store.attest("bob", "alice").unwrap();
        store.attest("carol", "alice").unwrap();

        let records = store.attestations_by_attester("alice");
        assert_eq!(records.len(), 2);

        let mut attested: Vec<_> = records.iter().map(|r| r.attested_id.as_str()).collect();
        attested.sort();
        assert_eq!(attested, vec!["bob", "carol"]);
    }

    #[test]
    fn attestations_for_identity_returns_all_attesters() {
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_and_verify(&mut store, "dave", "qcb1dave");
        register_provisional(&mut store, "bob", "qcb1bob");

        store.attest("bob", "alice").unwrap();
        store.attest("bob", "dave").unwrap();

        let for_bob = store.attestations_for_identity("bob");
        assert_eq!(for_bob.len(), 2);

        let mut attesters: Vec<_> = for_bob.iter().map(|r| r.attester_id.as_str()).collect();
        attesters.sort();
        assert_eq!(attesters, vec!["alice", "dave"]);
    }

    #[test]
    fn revoke_attestation_marks_record_revoked() {
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");

        store.attest("bob", "alice").unwrap();
        store.revoke_attestation("alice", "bob").unwrap();

        let records = store.attestations_by_attester("alice");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, AttestationStatus::Revoked);
        assert_eq!(records[0].revocation_epoch, Some(0)); // epoch 0 in tests
    }

    #[test]
    fn revoke_nonexistent_attestation_returns_error() {
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");

        // alice never attested bob, so revocation should fail
        let result = store.revoke_attestation("alice", "bob");
        assert!(
            matches!(result, Err(IdentityError::AttestationNotFound(..))),
            "expected AttestationNotFound, got {:?}", result
        );
    }

    #[test]
    fn revoke_already_revoked_attestation_returns_error() {
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");

        store.attest("bob", "alice").unwrap();
        store.revoke_attestation("alice", "bob").unwrap();

        // Second revocation of the same attestation must fail
        let result = store.revoke_attestation("alice", "bob");
        assert!(
            matches!(result, Err(IdentityError::AttestationAlreadyRevoked(..))),
            "expected AttestationAlreadyRevoked, got {:?}", result
        );
    }

    #[test]
    fn revocation_removes_attester_from_ledger() {
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");

        store.attest("bob", "alice").unwrap();
        assert_eq!(store.get("bob").unwrap().attestation_ledger.count(), 1);

        store.revoke_attestation("alice", "bob").unwrap();

        // Alice's contribution is removed from bob's attestation ledger
        assert_eq!(store.get("bob").unwrap().attestation_ledger.count(), 0,
            "revoking should remove the attester from the ledger");
    }

    #[test]
    fn failed_attest_does_not_write_attestation_record() {
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");

        // Self-attestation fails -- should not write a record
        let _ = store.attest("alice", "alice");
        assert!(store.attestations_by_attester("alice").is_empty(),
            "failed attest must not write an attestation record");

        // Not-found fails -- should not write a record
        let _ = store.attest("does_not_exist", "alice");
        assert!(store.attestations_by_attester("does_not_exist").is_empty());
    }

    #[test]
    fn attestation_record_epoch_matches_store_epoch() {
        let mut store = IdentityStore::with_epoch_ms(0, 1000);
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");

        // Advance to epoch 3
        store.advance_epoch(1001);
        store.advance_epoch(2002);
        store.advance_epoch(3003);

        store.attest("bob", "alice").unwrap();

        let records = store.attestations_by_attester("alice");
        assert_eq!(records[0].epoch, 3, "attestation epoch must match the store's current epoch");
    }

    #[test]
    fn revoke_penalized_attestation_returns_error() {
        // A Penalized record means confirm_sybil has already applied a CS penalty.
        // Revocation at that point is blocked — the attester must have the coordinator
        // call reverse_sybil first (Phase C). This test exercises the error path;
        // Phase C will test the full confirm → reverse → revoke sequence.
        //
        // We manufacture a Penalized record directly since confirm_sybil is Phase C.
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");

        store.attest("bob", "alice").unwrap();

        // Manually set the record to Penalized (simulating what confirm_sybil will do)
        let key = attestation_record_key("alice", "bob");
        store.attestation_records.get_mut(&key).unwrap().status = AttestationStatus::Penalized;
        store.attestation_records.get_mut(&key).unwrap().penalty_applied = true;

        let result = store.revoke_attestation("alice", "bob");
        assert!(
            matches!(result, Err(IdentityError::AttestationAlreadyPenalized(..))),
            "revoking a penalized attestation must return AttestationAlreadyPenalized, got {:?}", result
        );
    }

    // -- Phase B: rolling-window cap enforcement --------------------------------

    #[test]
    fn rolling_window_cap_blocks_fourth_attestation() {
        // An attester is allowed ATTESTATION_CAP_PER_WINDOW (3) active
        // attestations in a rolling window; the fourth must be rejected.
        let mut store = make_store();
        register_and_verify(&mut store, "attester", "qcb1attester");

        for i in 0..ATTESTATION_CAP_PER_WINDOW {
            let id = format!("claimant{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }

        register_provisional(&mut store, "blocked", "qcb1blocked");
        let result = store.attest("blocked", "attester");
        assert!(
            matches!(result, Err(IdentityError::AttestationCapExceeded(..))),
            "fourth attestation in window must be rejected by the cap, got {:?}", result
        );
    }

    #[test]
    fn rolling_window_cap_does_not_count_revoked_attestations() {
        // Design decision Q1: revocation frees the slot. After revoking one
        // attestation from a full budget, the attester can make a new one.
        let mut store = make_store();
        register_and_verify(&mut store, "attester", "qcb1attester");

        // Fill the cap
        for i in 0..ATTESTATION_CAP_PER_WINDOW {
            let id = format!("claimant{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }

        // Revoke one — this should free a slot
        store.revoke_attestation("attester", "claimant0").unwrap();

        // Now a new attestation should be allowed
        register_provisional(&mut store, "new_claimant", "qcb1new");
        let result = store.attest("new_claimant", "attester");
        assert!(
            result.is_ok(),
            "after revoking one attestation the cap slot must be freed, got {:?}", result
        );
    }

    #[test]
    fn rolling_window_cap_does_not_count_old_attestations() {
        // Attestations older than ATTESTATION_CAP_WINDOW_EPOCHS do not count
        // against the cap. After the window passes, the attester's budget resets.
        // Use 1-epoch-duration store and advance past the window.
        let mut store = IdentityStore::with_epoch_ms(0, 1);
        register_and_verify(&mut store, "attester", "qcb1attester");

        // Fill the cap at epoch 0
        for i in 0..ATTESTATION_CAP_PER_WINDOW {
            let id = format!("claimant{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }

        // Advance past the window: current epoch = CAP_WINDOW + 1, so all
        // attestations from epoch 0 are now outside the [window_start, now] range.
        // Keep the attester lively so liveness enforcement doesn't downgrade them.
        let target_ms = (ATTESTATION_CAP_WINDOW_EPOCHS + 1) as u64;
        store.stay_lively("attester", target_ms);
        store.advance_epoch(target_ms);

        // A new attestation should now be allowed — old ones expired out of window
        register_provisional(&mut store, "fresh", "qcb1fresh");
        let result = store.attest("fresh", "attester");
        assert!(
            result.is_ok(),
            "attestations older than the window must not count against the cap, got {:?}", result
        );
    }

    #[test]
    fn rolling_window_cap_counts_only_active_attestations_in_window() {
        // A mix: some active in window, some revoked, some old. Only active
        // in-window ones consume the budget.
        let mut store = IdentityStore::with_epoch_ms(0, 1);
        register_and_verify(&mut store, "attester", "qcb1attester");

        // Attest two at epoch 0, then advance past the window for one of them
        register_provisional(&mut store, "old", "qcb1old");
        store.attest("old", "attester").unwrap();            // epoch 0 — will be old

        register_provisional(&mut store, "revoked", "qcb1revoked");
        store.attest("revoked", "attester").unwrap();        // epoch 0 — will be revoked

        // Advance past window; "old" is now expired.
        // Keep the attester lively so liveness enforcement doesn't downgrade them.
        let mid_ms = (ATTESTATION_CAP_WINDOW_EPOCHS + 1) as u64;
        store.stay_lively("attester", mid_ms);
        store.advance_epoch(mid_ms);
        store.revoke_attestation("attester", "revoked").unwrap(); // revoked at epoch > 0

        // Now attest two more in the new window (epochs > window_start)
        for i in 0..2 {
            let id = format!("fresh{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }

        // Budget: 2 active in window (fresh0, fresh1). One more is allowed.
        register_provisional(&mut store, "third_fresh", "qcb1third");
        let result = store.attest("third_fresh", "attester");
        assert!(result.is_ok(), "expected cap budget available, got {:?}", result);

        // Fourth in the current window should be blocked
        register_provisional(&mut store, "fourth_fresh", "qcb1fourth");
        let blocked = store.attest("fourth_fresh", "attester");
        assert!(
            matches!(blocked, Err(IdentityError::AttestationCapExceeded(..))),
            "fourth in-window active attestation must be blocked, got {:?}", blocked
        );
    }

    #[test]
    fn identity_store_with_attestation_records_survives_json_roundtrip() {
        // Guard against regression: IdentityStore is serialized as JSON by the
        // node (identity.json snapshot). A HashMap<(String,String), _> key fails
        // JSON serialization (tuple keys become arrays, which JSON rejects as
        // object keys). This test ensures the string-keyed map survives a
        // serde_json roundtrip so node restarts don't lose attestation history.
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");
        store.attest("bob", "alice").unwrap();

        let json = serde_json::to_string(&store)
            .expect("IdentityStore must serialize to JSON without error");
        let restored: IdentityStore = serde_json::from_str(&json)
            .expect("IdentityStore must deserialize from JSON without error");

        let records = restored.attestations_by_attester("alice");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].attester_id, "alice");
        assert_eq!(records[0].attested_id, "bob");
        assert_eq!(records[0].status, AttestationStatus::Active);
    }

    #[test]
    fn attestation_record_epoch_is_fixed_across_revocation() {
        // Phase B relies on record.epoch staying fixed (the epoch the attestation
        // was made) so it can correctly compute whether the attestation falls within
        // the 90-day rolling window at cap-check time. Revocation must not mutate
        // the epoch field — only revocation_epoch is set.
        let mut store = IdentityStore::with_epoch_ms(0, 1000);
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");

        // Attest at epoch 2
        store.advance_epoch(1001);
        store.advance_epoch(2002);
        store.attest("bob", "alice").unwrap();
        let attest_epoch = store.attestations_by_attester("alice")[0].epoch;
        assert_eq!(attest_epoch, 2);

        // Advance clock and revoke at epoch 5
        store.advance_epoch(3003);
        store.advance_epoch(4004);
        store.advance_epoch(5005);
        store.revoke_attestation("alice", "bob").unwrap();

        let records = store.attestations_by_attester("alice");
        assert_eq!(records[0].epoch, 2,
            "revocation must not change record.epoch — it stays as the attestation epoch");
        assert_eq!(records[0].revocation_epoch, Some(5),
            "revocation_epoch must record when the revocation happened");
    }

    // -- Phase C: coordinator role and sybil confirmation ---------------------

    #[test]
    fn confirm_sybil_requires_coordinator_set() {
        // confirm_sybil must fail when no coordinator is configured.
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();

        let result = store.confirm_sybil("alice", "sybil");
        assert!(
            matches!(result, Err(IdentityError::CoordinatorNotSet)),
            "expected CoordinatorNotSet, got {:?}", result
        );
    }

    #[test]
    fn confirm_sybil_rejects_non_coordinator_caller() {
        // Only the configured coordinator can confirm a sybil.
        let mut store = make_store();
        store.set_coordinator(Some("coordinator".to_string()));
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();

        let result = store.confirm_sybil("alice", "sybil"); // alice is not coordinator
        assert!(
            matches!(result, Err(IdentityError::NotCoordinator(_))),
            "expected NotCoordinator, got {:?}", result
        );
    }

    #[test]
    fn confirm_sybil_penalizes_active_attesters() {
        // confirm_sybil marks all active attestation records for the sybil
        // as Penalized and returns the list of penalized attesters.
        let mut store = make_store();
        store.set_coordinator(Some("coordinator".to_string()));

        // Three attesters vouch for the sybil
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_and_verify(&mut store, "bob", "qcb1bob");
        register_and_verify(&mut store, "carol", "qcb1carol");
        register_provisional(&mut store, "sybil", "qcb1sybil");

        store.attest("sybil", "alice").unwrap();
        store.attest("sybil", "bob").unwrap();
        store.attest("sybil", "carol").unwrap();

        let penalized = store.confirm_sybil("coordinator", "sybil").unwrap();
        assert_eq!(penalized.len(), 3, "all three attesters must be penalized");

        // Every attested record for the sybil is now Penalized
        let records = store.attestations_for_identity("sybil");
        assert_eq!(records.len(), 3);
        for rec in records {
            assert_eq!(
                rec.status, AttestationStatus::Penalized,
                "record for attester {} must be Penalized", rec.attester_id
            );
            assert!(rec.penalty_applied, "penalty_applied must be true");
        }

        // Confirmation log is written
        let log = store.sybil_confirmation("sybil").expect("log must exist");
        assert_eq!(log.sybil_id, "sybil");
        assert!(!log.reversed);
        assert_eq!(log.penalized_attesters.len(), 3);
    }

    #[test]
    fn confirm_sybil_skips_revoked_attestations() {
        // An attester who revoked before sybil confirmation pays only the
        // revocation cost — they are NOT included in the penalized list.
        let mut store = make_store();
        store.set_coordinator(Some("coordinator".to_string()));

        register_and_verify(&mut store, "alice", "qcb1alice");
        register_and_verify(&mut store, "bob", "qcb1bob");
        register_provisional(&mut store, "sybil", "qcb1sybil");

        store.attest("sybil", "alice").unwrap();
        store.attest("sybil", "bob").unwrap();

        // Bob revokes before the coordinator acts
        store.revoke_attestation("bob", "sybil").unwrap();

        let penalized = store.confirm_sybil("coordinator", "sybil").unwrap();
        assert_eq!(penalized, vec!["alice".to_string()],
            "only alice (active attester) must be penalized; bob revoked cleanly");

        // Alice's record is Penalized; bob's is still Revoked
        let alice_rec = store.attestation_records
            .get(&attestation_record_key("alice", "sybil"))
            .expect("alice's record must exist");
        assert_eq!(alice_rec.status, AttestationStatus::Penalized);

        let bob_rec = store.attestation_records
            .get(&attestation_record_key("bob", "sybil"))
            .expect("bob's record must exist");
        assert_eq!(bob_rec.status, AttestationStatus::Revoked,
            "bob's revoked record must remain Revoked, not be retroactively penalized");
    }

    #[test]
    fn reverse_sybil_restores_penalized_records() {
        // reverse_sybil undoes confirm_sybil: records return to Active,
        // penalty_applied resets to false, reversal is logged.
        let mut store = make_store();
        store.set_coordinator(Some("coordinator".to_string()));

        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();

        store.confirm_sybil("coordinator", "sybil").unwrap();

        // Verify penalized state
        let rec = store.attestation_records
            .get(&attestation_record_key("alice", "sybil"))
            .unwrap();
        assert_eq!(rec.status, AttestationStatus::Penalized);

        // Reverse
        let restored = store.reverse_sybil("coordinator", "sybil").unwrap();
        assert_eq!(restored, vec!["alice".to_string()]);

        // Record is back to Active
        let rec = store.attestation_records
            .get(&attestation_record_key("alice", "sybil"))
            .unwrap();
        assert_eq!(rec.status, AttestationStatus::Active,
            "record must be Active after reversal");
        assert!(!rec.penalty_applied,
            "penalty_applied must be false after reversal");

        // Log records the reversal
        let log = store.sybil_confirmation("sybil").unwrap();
        assert!(log.reversed, "log must be marked reversed");
        assert!(log.reversal_epoch.is_some());
    }

    #[test]
    fn reverse_sybil_allows_reconfirmation() {
        // After a reversal, the coordinator can confirm the same identity again.
        // The second confirmation starts fresh and penalizes the current Active records.
        let mut store = make_store();
        store.set_coordinator(Some("coordinator".to_string()));

        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();

        store.confirm_sybil("coordinator", "sybil").unwrap();
        store.reverse_sybil("coordinator", "sybil").unwrap();

        // Can confirm again after reversal
        let penalized = store.confirm_sybil("coordinator", "sybil");
        assert!(penalized.is_ok(), "re-confirmation after reversal must succeed");
    }

    #[test]
    fn identity_store_with_sybil_confirmations_survives_json_roundtrip() {
        // sybil_confirmations must survive serde_json serialization so node
        // state snapshots don't lose confirmation history across restarts.
        let mut store = make_store();
        store.set_coordinator(Some("coordinator".to_string()));

        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();
        store.confirm_sybil("coordinator", "sybil").unwrap();

        let json = serde_json::to_string(&store).expect("serialize must succeed");
        let restored: IdentityStore = serde_json::from_str(&json).expect("deserialize must succeed");

        let log = restored.sybil_confirmation("sybil").expect("log must survive roundtrip");
        assert_eq!(log.sybil_id, "sybil");
        assert_eq!(log.coordinator_id, "coordinator");
        assert_eq!(log.penalized_attesters.len(), 1);
        assert_eq!(log.penalized_attesters[0].attester_id, "alice");
        assert_eq!(log.penalized_attesters[0].penalty_bps, ATTEST_PENALTY_RATE_BPS);
        assert!(!log.penalized_attesters[0].self_reported);
        assert!(!log.reversed);
    }

    // -- Phase D: revocation cost and self-report exemption -------------------

    #[test]
    fn revocation_returns_cost_signal() {
        // revoke_attestation returns a RevocationCost carrying the attester,
        // attested identity, and the basis-points rate. The identity crate
        // signals; the execution layer applies the CS deduction.
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "bob", "qcb1bob");
        store.attest("bob", "alice").unwrap();

        let cost = store.revoke_attestation("alice", "bob").unwrap();
        assert_eq!(cost.attester_id, "alice");
        assert_eq!(cost.attested_id, "bob");
        assert_eq!(cost.cost_bps, REVOCATION_COST_BPS,
            "revocation cost must be REVOCATION_COST_BPS ({})", REVOCATION_COST_BPS);
    }

    #[test]
    fn self_report_before_confirmation_reduces_penalty() {
        // An attester who self-reports before the coordinator confirms the sybil
        // receives a 50% reduction on the standard penalty rate.
        // Standard: ATTEST_PENALTY_RATE_BPS = 12000 (120%)
        // Reduced:  12000 * (1 - 5000/10000) = 12000 * 50% = 6000 bps (60%)
        let mut store = make_store();
        store.set_coordinator(Some("coordinator".to_string()));

        register_and_verify(&mut store, "alice", "qcb1alice");
        register_and_verify(&mut store, "bob", "qcb1bob");
        register_provisional(&mut store, "sybil", "qcb1sybil");

        store.attest("sybil", "alice").unwrap();
        store.attest("sybil", "bob").unwrap();

        // Alice self-reports before the coordinator acts.
        store.report_suspected_sybil("alice", "sybil").unwrap();

        let penalized = store.confirm_sybil("coordinator", "sybil").unwrap();
        assert_eq!(penalized.len(), 2, "both attesters must be penalized");

        let log = store.sybil_confirmation("sybil").unwrap();
        let alice_rec = log.penalized_attesters.iter().find(|pr| pr.attester_id == "alice")
            .expect("alice must be in the penalty log");
        let bob_rec = log.penalized_attesters.iter().find(|pr| pr.attester_id == "bob")
            .expect("bob must be in the penalty log");

        // Alice self-reported: reduced rate
        let expected_reduced = ATTEST_PENALTY_RATE_BPS
            * (10_000 - SELF_REPORT_PENALTY_REDUCTION_BPS)
            / 10_000;
        assert_eq!(alice_rec.penalty_bps, expected_reduced,
            "self-reporter must get reduced penalty ({}), got {}",
            expected_reduced, alice_rec.penalty_bps);
        assert!(alice_rec.self_reported, "alice must be marked as self_reported=true");

        // Bob did not self-report: full rate
        assert_eq!(bob_rec.penalty_bps, ATTEST_PENALTY_RATE_BPS,
            "non-reporter must get the full penalty rate");
        assert!(!bob_rec.self_reported, "bob must be marked as self_reported=false");
    }

    #[test]
    fn self_report_requires_active_attestation() {
        // An attester must have an active attestation for the suspected identity
        // to file a self-report. Revoked attestation = no exposure = no report.
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();

        // Alice revokes before trying to report
        store.revoke_attestation("alice", "sybil").unwrap();

        let result = store.report_suspected_sybil("alice", "sybil");
        assert!(
            matches!(result, Err(IdentityError::CannotReportWithoutAttestation(..))),
            "revoked attester must not be allowed to self-report, got {:?}", result
        );
    }

    #[test]
    fn self_report_without_any_attestation_rejected() {
        // An identity that never attested the suspected sybil cannot file a report.
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_and_verify(&mut store, "outsider", "qcb1outsider");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();

        // outsider never attested sybil
        let result = store.report_suspected_sybil("outsider", "sybil");
        assert!(
            matches!(result, Err(IdentityError::CannotReportWithoutAttestation(..))),
            "non-attester must not be allowed to self-report, got {:?}", result
        );
    }

    #[test]
    fn duplicate_self_report_rejected() {
        // An attester may not file more than one report for the same suspected identity.
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();

        store.report_suspected_sybil("alice", "sybil").unwrap();

        let result = store.report_suspected_sybil("alice", "sybil");
        assert!(
            matches!(result, Err(IdentityError::AlreadyReported(..))),
            "duplicate report must be rejected, got {:?}", result
        );
    }

    #[test]
    fn non_self_reporter_gets_full_penalty() {
        // An attester who did not self-report gets ATTEST_PENALTY_RATE_BPS, not reduced.
        let mut store = make_store();
        store.set_coordinator(Some("coordinator".to_string()));
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();

        // No self-report filed; confirm directly.
        store.confirm_sybil("coordinator", "sybil").unwrap();

        let log = store.sybil_confirmation("sybil").unwrap();
        assert_eq!(log.penalized_attesters.len(), 1);
        let pr = &log.penalized_attesters[0];
        assert_eq!(pr.attester_id, "alice");
        assert_eq!(pr.penalty_bps, ATTEST_PENALTY_RATE_BPS,
            "non-reporter must receive the full penalty");
        assert!(!pr.self_reported);
    }

    #[test]
    fn pending_sybil_reports_survive_json_roundtrip() {
        // pending_sybil_reports is part of IdentityStore state and must survive
        // JSON serialization so node restarts don't lose pending reports.
        let mut store = make_store();
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();
        store.report_suspected_sybil("alice", "sybil").unwrap();

        let json = serde_json::to_string(&store).expect("serialize must succeed");
        let restored: IdentityStore = serde_json::from_str(&json).expect("deserialize must succeed");

        let reports = restored.pending_sybil_reports.get("sybil")
            .expect("pending reports must survive roundtrip");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].attester_id, "alice");
        assert_eq!(reports[0].suspected_id, "sybil");
    }

    #[test]
    fn pending_reports_consumed_on_sybil_confirmation() {
        // After confirm_sybil, pending_sybil_reports for that identity must be
        // cleared (reports are consumed into the log, not kept as pending).
        let mut store = make_store();
        store.set_coordinator(Some("coordinator".to_string()));
        register_and_verify(&mut store, "alice", "qcb1alice");
        register_provisional(&mut store, "sybil", "qcb1sybil");
        store.attest("sybil", "alice").unwrap();
        store.report_suspected_sybil("alice", "sybil").unwrap();

        store.confirm_sybil("coordinator", "sybil").unwrap();

        // Pending reports for "sybil" must be gone (entry removed, not empty vec)
        assert!(
            store.pending_sybil_reports.get("sybil").is_none(),
            "pending reports must be cleared after sybil confirmation"
        );
    }
}
