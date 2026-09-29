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

    #[error("identity {0} is already past Provisional -- no further attestations needed")]
    AlreadyVerified(String),

    #[error("internal identity error: {0}")]
    Internal(String),
}

pub type IdResult<T> = Result<T, IdentityError>;

// -- Verification tier --------------------------------------------------------

/// The graduated identity lifecycle from Whitepaper Section 4.
/// Graduated from Section 4.5's "identity is the door" framing:
/// more participation -> higher tier -> more rights.
///
/// Provisional:   registered but not yet verified. Can receive $CIRFI
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
    /// Whether this tier grants full UBI (1,000 $CIRFI/day per Section 6.2).
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
/// not fixed at the protocol layer -- Section 6.6 governs CirFi-adjacent
/// parameters like this one the same way it governs decay rates.
pub const ATTESTATION_QUORUM: usize = 3;

/// Maximum number of distinct claimants one identity can vouch for within
/// a single epoch. Named in the Identity Pilot Design (Section 3.1) as a
/// parameter to finalize before Phase 1; bounds how much damage a single
/// compromised or malicious Verified identity can do by rapidly vouching
/// for a cohort of fake claimants. Provisional value, governance-adjustable.
pub const MAX_ATTESTATIONS_PER_EPOCH: u32 = 5;

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
    /// Whether this identity has claimed CirFi yield in the current epoch.
    pub claimed_this_epoch: bool,
    /// Total CirFi yield claimed across all epochs (in ucirfi base units).
    pub total_ubi_claimed: u128,
    /// The last epoch in which this identity performed on-chain activity
    /// (sent a tx, validated a block, processed a merchant settlement).
    /// CirFi yield requires activity in the current epoch — this is the
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
/// Daily UBI rate: 1,000 $CIRFI per verified human (Whitepaper 6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiClock {
    pub current_epoch:    u64,
    pub epoch_start_ms:   u64,
    pub epoch_duration_ms: u64,
    /// Total $CIRFI distributed across all epochs.
    pub total_distributed: u128,
}

/// Daily UBI rate per verified human in base ucirfi units.
/// 1,000 $CIRFI = 1,000,000,000 ucirfi (assuming 6 decimal places).
pub const DAILY_UBI_RATE_UCIRFI: u128 = 1_000_000_000;

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
        DAILY_UBI_RATE_UCIRFI
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStore {
    records:  HashMap<String, IdentityRecord>,
    /// Index: address -> identity_id for fast lookup by account address.
    by_address: HashMap<String, String>,
    pub clock: UbiClock,
}

impl IdentityStore {
    pub fn new(genesis_time_ms: u64) -> Self {
        Self {
            records:    HashMap::new(),
            by_address: HashMap::new(),
            clock:      UbiClock::new(genesis_time_ms),
        }
    }

    /// For testing: create a store with short epoch duration.
    pub fn with_epoch_ms(genesis_time_ms: u64, epoch_duration_ms: u64) -> Self {
        Self {
            records:    HashMap::new(),
            by_address: HashMap::new(),
            clock:      UbiClock::with_epoch_duration_ms(genesis_time_ms, epoch_duration_ms),
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
    /// - the attester is rate-limited to MAX_ATTESTATIONS_PER_EPOCH
    ///   distinct claimants per epoch, resetting each time the epoch
    ///   advances
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

        // Rate limit, tracked on the attester's own record. Reset the
        // window here rather than in advance_epoch(), so an attester who
        // never vouches for anyone doesn't need per-epoch upkeep -- the
        // window resets lazily, the first time they attest in a new epoch.
        {
            let attester_record = self.records.get_mut(attester_id).unwrap();
            if attester_record.attestations_given_epoch != epoch {
                attester_record.attestations_given_epoch = epoch;
                attester_record.attestations_given_count = 0;
            }
            if attester_record.attestations_given_count >= MAX_ATTESTATIONS_PER_EPOCH {
                return Err(IdentityError::AttestationRateLimitExceeded(attester_id.to_string()));
            }
            attester_record.attestations_given_count += 1;
        }

        let claimant = self.records.get_mut(claimant_id).unwrap();
        claimant.attestation_ledger.add(attester_id.to_string());
        let count = claimant.attestation_ledger.count();

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

    // -- UBI claim gating (Charm Confinement) ---------------------------------

    /// Claim UBI for a verified identity.
    /// Enforces: one claim per epoch, verified tier, liveness.
    /// Returns the amount of ucirfi to credit to the account.
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

        // Earned-yield gate: CirFi is NOT a UBI drip — it must be earned.
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

        tracing::debug!(id, epoch, amount_ucirfi = amount, "CirFi yield claimed");
        Ok(amount)
    }

    /// Record on-chain activity for an identity, enabling CirFi yield claim
    /// for this epoch. Called by the execution layer whenever a verified
    /// identity submits a tx, participates as a validator, or processes a
    /// merchant settlement. No-op if the identity is not found.
    pub fn record_activity(&mut self, id: &str) {
        let epoch = self.clock.current_epoch;
        if let Some(record) = self.records.get_mut(id) {
            record.last_active_epoch = Some(epoch);
            tracing::debug!(id, epoch, "on-chain activity recorded for CirFi yield eligibility");
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
                tracing::debug!(address, epoch, "on-chain activity recorded for CirFi yield eligibility");
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
        assert!(result.is_err(), "CirFi yield requires on-chain activity; passive claim must fail");
    }

    #[test]
    fn active_verified_identity_claims_yield() {
        let mut store = make_store();
        register_and_verify(&mut store, "h1", "qcb1h1");

        // Record activity (simulates tx submission).
        store.record_activity("h1");

        let amount = store.claim_ubi("h1").unwrap();
        assert_eq!(amount, DAILY_UBI_RATE_UCIRFI);
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

        assert_eq!(store.clock.total_distributed, DAILY_UBI_RATE_UCIRFI * 2);
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
        let mut store = make_store();
        register_and_verify(&mut store, "attester", "qcb1attester");

        // MAX_ATTESTATIONS_PER_EPOCH distinct claimants succeed...
        for i in 0..MAX_ATTESTATIONS_PER_EPOCH {
            let id = format!("claimant{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }

        // ...the next one in the SAME epoch is rejected.
        register_provisional(&mut store, "one_too_many", "qcb1one_too_many");
        let result = store.attest("one_too_many", "attester");
        assert!(matches!(result, Err(IdentityError::AttestationRateLimitExceeded(_))));
    }

    #[test]
    fn attestation_rate_limit_resets_next_epoch() {
        let mut store = IdentityStore::with_epoch_ms(0, 1000);
        register_and_verify(&mut store, "attester", "qcb1attester");

        for i in 0..MAX_ATTESTATIONS_PER_EPOCH {
            let id = format!("claimant{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }

        register_provisional(&mut store, "blocked_this_epoch", "qcb1blocked");
        assert!(store.attest("blocked_this_epoch", "attester").is_err());

        // Advance to a new epoch -- the rate limit window resets.
        store.advance_epoch(1500);
        register_provisional(&mut store, "allowed_next_epoch", "qcb1allowed");
        let result = store.attest("allowed_next_epoch", "attester");
        assert!(result.is_ok(), "rate limit must reset once a new epoch begins");
    }

    #[test]
    fn rejected_attestation_does_not_consume_rate_limit_budget() {
        let mut store = make_store();
        register_and_verify(&mut store, "attester", "qcb1attester");
        register_provisional(&mut store, "newbie", "qcb1newbie");

        // A self-attestation attempt and a not-found attempt should both
        // fail WITHOUT spending any of the attester's per-epoch budget.
        let _ = store.attest("attester", "attester"); // self-attestation, rejected
        let _ = store.attest("does_not_exist", "attester"); // NotFound, rejected

        // The attester should still have their full budget -- prove it by
        // successfully using all MAX_ATTESTATIONS_PER_EPOCH slots afterward.
        for i in 0..MAX_ATTESTATIONS_PER_EPOCH {
            let id = format!("claimant{i}");
            register_provisional(&mut store, &id, &format!("qcb1{id}"));
            store.attest(&id, "attester").unwrap();
        }
    }
}
