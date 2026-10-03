//! # capacity_report — CapacityEvidence_v0 State Machine
//!
//! Implements the CapacityReport sub-protocol specified in
//! `qrc_sim/CapacityReport-SubProtocol-v0.1.md`.
//!
//! ## What this module provides
//!
//! 1. **Types**: `CapacityEvidence`, `CapacityReport`, `ResourceType`,
//!    `CapacityPhase`, and their supporting structures.
//! 2. **State machine**: `CapacityReportState` — drives the
//!    `COLLECTING → FINALIZING → FINALIZED | CARRY_FORWARD` lifecycle.
//! 3. **Aggregation**: median-based Byzantine-robust aggregation of evidence
//!    claims (§5.1), multi-resource weighted sum (§5.2), carry-forward (§5.3).
//! 4. **Submission validation**: all 8 validity rules from §3.2, enforced
//!    deterministically so all validators reach identical conclusions.
//! 5. **Slashing stubs**: collateral tracking and slash application (§7.1).
//!
//! ## What this module does NOT provide
//!
//! - VCA credential verification (separate protocol)
//! - Actual challenge-response proof verification for v0 proof types —
//!   v0 proofs are structurally validated only; semantic validation is v1.
//! - BFT countersignature collection (handled by the consensus layer).
//! - Economic calibration of CU weights.
//!
//! ## Fixed-point arithmetic
//!
//! All capacity values use D = 1_000_000 as denominator, consistent with the
//! QRC spec. An integer value `x` represents `x / D` in real units.
//! All arithmetic is integer; no floating point enters consensus-critical paths.

use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;

// ── Constants (§8) ────────────────────────────────────────────────────────────

/// Fixed-point denominator, inherited from QRC spec. CONSTITUTIONAL.
pub const D: u128 = 1_000_000;

/// Minimum evidence items required for a valid (non-carry-forward) report.
/// 3 is the minimum for an honest median with 1 Byzantine provider.
pub const MIN_PROVIDER_QUORUM: usize = 3;

/// Maximum single-provider capacity claim (fixed-point). Prevents one provider
/// from dominating the median.
pub const MAX_SINGLE_PROVIDER_CLAIM: u128 = 10_000_000_000_000; // 10^13 CU × D

/// Blocks before epoch boundary at which the Evidence Collection Window closes.
pub const ECW_CLOSE_OFFSET: u64 = 10;

/// Blocks before epoch boundary at which the CapacityReport must be on-chain.
pub const REPORT_DEADLINE_OFFSET: u64 = 5;

/// Maximum epochs before a carry-forward triggers a protocol warning.
pub const MAX_CARRY_FORWARD_EPOCHS: u64 = 3;

/// Fraction of staked collateral slashed on successful challenge (fixed-point).
pub const SLASH_FRACTION: u128 = 200_000; // 20%

/// Blocks after CapacityReport finalization during which challenges are accepted.
pub const CHALLENGE_WINDOW_BLOCKS: u64 = 100;

/// Blocks for validator adjudication of a challenge.
pub const ADJUDICATION_WINDOW: u64 = 50;

/// Epochs collateral is locked after a submission.
pub const COLLATERAL_LOCK_EPOCHS: u64 = 4;

/// Single-epoch capacity change threshold above which a warning is emitted.
pub const CAPACITY_STEP_WARN_THRESHOLD: u128 = 200_000; // 20% fixed-point

/// Resource weight: Compute (60%).
pub const WEIGHT_COMPUTE: u128 = 600_000;
/// Resource weight: Storage (15%).
pub const WEIGHT_STORAGE: u128 = 150_000;
/// Resource weight: ZkProving (25%).
pub const WEIGHT_ZK_PROVING: u128 = 250_000;

// Weights must sum to D. Verified by test `weights_sum_to_d`.

/// Domain separator for challenge nonce derivation.
pub const DOMAIN_SEP_CAPACITY: &[u8] = b"CAPACITY_EVIDENCE_NONCE_V0";

// ── ResourceType ─────────────────────────────────────────────────────────────

/// Enumerated resource categories. Additional types require a protocol upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceType {
    /// General-purpose compute in normalized FLOP-equivalents.
    Compute,
    /// Persistent storage in bytes.
    Storage,
    /// ZK proof generation in normalized proof-seconds.
    ZkProving,
}

impl ResourceType {
    /// Return the governance-set weight for this resource type (fixed-point × D).
    pub fn weight(self) -> u128 {
        match self {
            ResourceType::Compute   => WEIGHT_COMPUTE,
            ResourceType::Storage   => WEIGHT_STORAGE,
            ResourceType::ZkProving => WEIGHT_ZK_PROVING,
        }
    }

    /// All resource types, in canonical order.
    pub fn all() -> &'static [ResourceType] {
        &[ResourceType::Compute, ResourceType::Storage, ResourceType::ZkProving]
    }
}

// ── v0 Proof types (§2.1) ────────────────────────────────────────────────────

/// Compute benchmark proof (v0). Time-gates fabrication; does NOT verify
/// correct execution. v1 will require a ZK proof of correct execution.
#[derive(Debug, Clone)]
pub struct ComputeProofV0 {
    /// Normalized operations completed.
    pub benchmark_result: u64,
    /// Canonical circuit ID (4 bytes).
    pub benchmark_circuit: [u8; 4],
    /// Wall-clock time in milliseconds.
    pub elapsed_ms: u32,
}

/// Storage proof (v0). Sector sampling driven by challenge_nonce.
#[derive(Debug, Clone)]
pub struct StorageProofV0 {
    /// Merkle root of challenge-sampled stored data.
    pub merkle_root: [u8; 32],
    /// Number of sectors sampled.
    pub sample_count: u32,
}

/// ZK proving capacity proof (v0). Proves over the canonical test circuit.
#[derive(Debug, Clone)]
pub struct ZkProvingProofV0 {
    /// Serialized proof bytes over the canonical test circuit.
    pub proof_bytes: Vec<u8>,
    /// Must match chain-published circuit ID.
    pub circuit_id: [u8; 4],
}

/// Resource-type-specific capacity proof. v0 proofs are structurally validated
/// only; semantic validation (cryptographic binding) is deferred to v1.
#[derive(Debug, Clone)]
pub enum CapacityProof {
    Compute(ComputeProofV0),
    Storage(StorageProofV0),
    ZkProving(ZkProvingProofV0),
}

impl CapacityProof {
    /// Return the resource type this proof corresponds to.
    pub fn resource_type(&self) -> ResourceType {
        match self {
            CapacityProof::Compute(_)   => ResourceType::Compute,
            CapacityProof::Storage(_)   => ResourceType::Storage,
            CapacityProof::ZkProving(_) => ResourceType::ZkProving,
        }
    }

    /// Structural validity check for v0. Returns Err if the proof is
    /// structurally malformed (e.g., wrong resource type for the claim).
    /// Semantic correctness (cryptographic verification) is v1.
    pub fn validate_v0(&self, resource_type: ResourceType) -> Result<(), EvidenceError> {
        if self.resource_type() != resource_type {
            return Err(EvidenceError::ProofResourceTypeMismatch {
                expected: resource_type,
                got: self.resource_type(),
            });
        }
        match self {
            CapacityProof::Storage(p) => {
                if p.sample_count == 0 {
                    return Err(EvidenceError::ProofInvalid(
                        "StorageProofV0: sample_count must be > 0".into(),
                    ));
                }
            }
            CapacityProof::ZkProving(p) => {
                if p.proof_bytes.is_empty() {
                    return Err(EvidenceError::ProofInvalid(
                        "ZkProvingProofV0: proof_bytes must not be empty".into(),
                    ));
                }
            }
            CapacityProof::Compute(_) => {} // no structural constraints at v0
        }
        Ok(())
    }
}

// ── CapacityEvidence (§2) ────────────────────────────────────────────────────

/// A VCA credential (opaque bytes at this layer; verified by the VCA protocol).
#[derive(Debug, Clone)]
pub struct VcaCredential(pub Vec<u8>);

/// A provider's public key (opaque bytes; signature verification is done by the
/// caller using the chain's crypto layer).
pub type ProviderId = [u8; 32];

/// A provider's signature over an evidence item (opaque bytes).
pub type Signature = [u8; 64];

/// A signed, epoch-scoped claim by a registered provider asserting that it can
/// service `capacity_claim` CU of `resource_type`.
#[derive(Debug, Clone)]
pub struct CapacityEvidence {
    // Identity
    pub provider_id:     ProviderId,
    pub vca_credential:  VcaCredential,

    // Resource claim
    pub resource_type:   ResourceType,
    /// Claimed CU, fixed-point (× D). 1,000 CU → 1_000 * D = 1_000_000_000.
    pub capacity_claim:  u128,

    // Liveness and freshness
    pub epoch:           u64,
    /// H(epoch_e || finalized_block_hash_{e-1} || DOMAIN_SEP_CAPACITY)
    pub challenge_nonce: [u8; 32],
    /// H(nonce || capacity_proof_data)
    pub response_hash:   [u8; 32],

    // Challenge-response proof
    pub proof:           CapacityProof,

    // Signature over all fields above
    pub signature:       Signature,
}

// ── CapacityReport (§6.1) ────────────────────────────────────────────────────

/// Per-resource-type record in a CapacityReport.
#[derive(Debug, Clone)]
pub struct ResourceCapacityRecord {
    /// Aggregated capacity for this resource type (fixed-point × D).
    pub capacity:       u128,
    /// Number of evidence items used.
    pub evidence_count: u32,
    /// Whether MIN_PROVIDER_QUORUM was met.
    pub quorum_met:     bool,
    /// True if this is a carry-forward value (quorum not met or no submissions).
    pub carry_forward:  bool,
}

/// Aggregation method tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregationMethod {
    MedianV0,
}

/// The authoritative per-resource-type capacity value for an epoch.
/// Valid only when countersigned by ≥ 2/3 of validators by weight.
/// (Countersignature collection is handled by the consensus layer;
/// this struct holds the signatures once collected.)
#[derive(Debug, Clone)]
pub struct CapacityReport {
    pub epoch:                u64,
    pub resource_reports:     BTreeMap<ResourceType, ResourceCapacityRecord>,
    /// The weighted sum `capacity_e` consumed by the QRC epoch boundary.
    pub capacity_total:       u128,
    /// Merkle root of sorted evidence per resource type (for dispute anchoring).
    pub evidence_roots:       BTreeMap<ResourceType, [u8; 32]>,
    pub aggregation_method:   AggregationMethod,
    /// `(provider_id, signature)` pairs from countersigning validators.
    pub validator_signatures: Vec<(ProviderId, Signature)>,
}

// ── State machine (§11) ──────────────────────────────────────────────────────

/// Phase of the CapacityReport state machine for one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityPhase {
    /// ECW open — evidence submissions accepted.
    Collecting,
    /// ECW closed — aggregation in progress.
    Finalizing,
    /// CapacityReport countersigned and on-chain.
    Finalized,
    /// No valid report; using `capacity_{e-1}`.
    CarryForward,
}

/// Protocol-level events emitted by the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityEvent {
    /// Emitted when ECW closes and evidence is committed.
    EcwClosed {
        epoch:             u64,
        evidence_counts:   BTreeMap<ResourceType, usize>,
    },
    /// Emitted when the CapacityReport is fully aggregated (before countersig).
    ReportAggregated {
        epoch:          u64,
        capacity_total: u128,
    },
    /// Emitted when the CapacityReport is finalized with valid countersig quorum.
    ReportFinalized {
        epoch:          u64,
        capacity_total: u128,
    },
    /// Emitted when no valid report is available by the deadline.
    CarryForwardActivated {
        epoch:         u64,
        prior_capacity: u128,
    },
    /// Emitted when a single-epoch capacity step exceeds CAPACITY_STEP_WARN_THRESHOLD.
    CapacityStepWarning {
        epoch:       u64,
        prior:       u128,
        current:     u128,
        change_frac: u128, // fixed-point fraction of prior
    },
    /// Emitted when carry-forward has been active for MAX_CARRY_FORWARD_EPOCHS.
    StaleCapacityWarning {
        epoch:              u64,
        carry_forward_since: u64,
    },
    /// Emitted when a provider is slashed.
    ProviderSlashed {
        provider_id:    ProviderId,
        slash_amount:   u128,
        reason:         String,
    },
}

/// Full state for one epoch's capacity report lifecycle.
#[derive(Debug, Clone)]
pub struct CapacityReportState {
    pub epoch:         u64,
    pub phase:         CapacityPhase,

    /// Evidence collected per resource type.
    evidence_set: BTreeMap<ResourceType, Vec<CapacityEvidence>>,

    /// Tracks which (provider_id, resource_type) pairs have already submitted
    /// this epoch (prevents duplicates per §3.2 rule 6).
    submitted: HashSet<(ProviderId, ResourceType)>,

    /// Merkle roots committed at ECW_close (placeholder: SHA-256 of sorted
    /// evidence hashes; a real impl uses the chain's Merkle tree).
    pub evidence_roots: BTreeMap<ResourceType, [u8; 32]>,

    /// The aggregated report (available once phase ≥ Finalizing).
    pub report: Option<CapacityReport>,

    /// The challenge nonce issued by the chain for this epoch.
    pub challenge_nonce: [u8; 32],

    /// Block height of the epoch start.
    pub epoch_start_height: u64,

    /// Block height of the epoch boundary.
    pub epoch_boundary_height: u64,

    /// Provider collateral (fixed-point × D). In a full implementation this
    /// comes from on-chain state; here it is tracked locally for testing.
    collateral: HashMap<ProviderId, u128>,

    /// Epochs since last genuine (non-carry-forward) report per resource type.
    carry_forward_since: BTreeMap<ResourceType, u64>,

    /// Previous epoch's capacity per resource type (for carry-forward).
    prior_capacity: BTreeMap<ResourceType, u128>,

    /// Events emitted during state transitions.
    pub events: Vec<CapacityEvent>,
}

impl CapacityReportState {
    /// Create a new state for epoch `e`.
    ///
    /// `prior_capacity` — capacity values from epoch `e-1` for carry-forward.
    /// `challenge_nonce` — the chain-derived nonce for this epoch.
    /// `epoch_boundary_height` — block height of the upcoming epoch boundary.
    pub fn new(
        epoch: u64,
        prior_capacity: BTreeMap<ResourceType, u128>,
        challenge_nonce: [u8; 32],
        epoch_start_height: u64,
        epoch_boundary_height: u64,
    ) -> Self {
        let carry_forward_since = ResourceType::all()
            .iter()
            .map(|&r| (r, 0u64))
            .collect();
        Self {
            epoch,
            phase: CapacityPhase::Collecting,
            evidence_set: BTreeMap::new(),
            submitted: HashSet::new(),
            evidence_roots: BTreeMap::new(),
            report: None,
            challenge_nonce,
            epoch_start_height,
            epoch_boundary_height,
            collateral: HashMap::new(),
            carry_forward_since,
            prior_capacity,
            events: Vec::new(),
        }
    }

    /// Derive the block height at which the ECW closes.
    pub fn ecw_close_height(&self) -> u64 {
        self.epoch_boundary_height.saturating_sub(ECW_CLOSE_OFFSET)
    }

    /// Derive the block height by which the report must be on-chain.
    pub fn report_deadline_height(&self) -> u64 {
        self.epoch_boundary_height.saturating_sub(REPORT_DEADLINE_OFFSET)
    }

    // ── Provider registration ────────────────────────────────────────────────

    /// Register a provider's collateral. In production this comes from on-chain
    /// staked balance; here it is set directly for testing.
    pub fn register_provider(&mut self, provider_id: ProviderId, collateral: u128) {
        self.collateral.insert(provider_id, collateral);
    }

    /// Returns true if the provider is registered (has collateral stake on file).
    pub fn is_registered(&self, provider_id: &ProviderId) -> bool {
        self.collateral.contains_key(provider_id)
    }

    // ── Evidence submission (§3) ─────────────────────────────────────────────

    /// Submit a `CapacityEvidence` item. Enforces all 8 validity rules from §3.2.
    ///
    /// `current_height` — the chain block height at submission time.
    /// `verify_sig`     — caller-supplied signature verifier (avoids pulling a
    ///                    crypto dep into this module). Returns `true` if valid.
    pub fn submit_evidence(
        &mut self,
        evidence: CapacityEvidence,
        current_height: u64,
        verify_sig: impl Fn(&ProviderId, &[u8; 64]) -> bool,
    ) -> Result<(), EvidenceError> {
        // Rule 1: epoch matches
        if evidence.epoch != self.epoch {
            return Err(EvidenceError::WrongEpoch {
                expected: self.epoch,
                got: evidence.epoch,
            });
        }

        // Rule 2: ECW still open
        if current_height >= self.ecw_close_height() {
            return Err(EvidenceError::EcwClosed {
                closed_at: self.ecw_close_height(),
                current:   current_height,
            });
        }

        // Phase guard — must be Collecting
        if self.phase != CapacityPhase::Collecting {
            return Err(EvidenceError::EcwClosed {
                closed_at: self.ecw_close_height(),
                current:   current_height,
            });
        }

        // Rule 3: registered provider
        if !self.is_registered(&evidence.provider_id) {
            return Err(EvidenceError::ProviderNotRegistered(evidence.provider_id));
        }

        // Rule 4: signature valid
        if !verify_sig(&evidence.provider_id, &evidence.signature) {
            return Err(EvidenceError::InvalidSignature(evidence.provider_id));
        }

        // Rule 5: challenge nonce matches
        if evidence.challenge_nonce != self.challenge_nonce {
            return Err(EvidenceError::WrongChallengeNonce);
        }

        // Rule 6: no duplicate from (provider, resource_type) this epoch
        let key = (evidence.provider_id, evidence.resource_type);
        if self.submitted.contains(&key) {
            return Err(EvidenceError::DuplicateSubmission {
                provider_id:   evidence.provider_id,
                resource_type: evidence.resource_type,
            });
        }

        // Rule 7: proof structurally valid (v0: structural only)
        evidence.proof.validate_v0(evidence.resource_type)?;

        // Rule 8: capacity claim within single-provider cap
        if evidence.capacity_claim > MAX_SINGLE_PROVIDER_CLAIM {
            return Err(EvidenceError::ClaimExceedsCap {
                claim: evidence.capacity_claim,
                cap:   MAX_SINGLE_PROVIDER_CLAIM,
            });
        }

        // All rules passed — accept the evidence
        self.submitted.insert(key);
        self.evidence_set
            .entry(evidence.resource_type)
            .or_default()
            .push(evidence);

        Ok(())
    }

    // ── ECW close (§4) ───────────────────────────────────────────────────────

    /// Transition from COLLECTING → FINALIZING at `ECW_close_e`.
    ///
    /// Commits the evidence Merkle roots and emits `EcwClosed`.
    /// Must be called at `current_height == ecw_close_height()`.
    pub fn close_ecw(&mut self, current_height: u64) -> Result<(), TransitionError> {
        if self.phase != CapacityPhase::Collecting {
            return Err(TransitionError::WrongPhase {
                expected: CapacityPhase::Collecting,
                got:      self.phase,
            });
        }
        if current_height < self.ecw_close_height() {
            return Err(TransitionError::TooEarly {
                action:  "close_ecw",
                allowed_at: self.ecw_close_height(),
                current: current_height,
            });
        }

        // Commit evidence roots (placeholder hash: sorted provider_id XOR fold)
        let mut counts = BTreeMap::new();
        for &rt in ResourceType::all() {
            let items = self.evidence_set.get(&rt).map(|v| v.len()).unwrap_or(0);
            counts.insert(rt, items);
            let root = compute_evidence_root(self.evidence_set.get(&rt).map(|v| v.as_slice()).unwrap_or(&[]));
            self.evidence_roots.insert(rt, root);
        }

        self.phase = CapacityPhase::Finalizing;
        self.events.push(CapacityEvent::EcwClosed {
            epoch:           self.epoch,
            evidence_counts: counts,
        });
        Ok(())
    }

    // ── Aggregation (§5) ─────────────────────────────────────────────────────

    /// Run aggregation and build the CapacityReport. Must be called after
    /// `close_ecw()` and before the report deadline.
    ///
    /// Sets `self.report` and transitions phase to FINALIZING (waiting for
    /// validator countersignatures). Emits `ReportAggregated`.
    pub fn aggregate(&mut self) -> Result<&CapacityReport, TransitionError> {
        if self.phase != CapacityPhase::Finalizing {
            return Err(TransitionError::WrongPhase {
                expected: CapacityPhase::Finalizing,
                got:      self.phase,
            });
        }

        let mut resource_reports = BTreeMap::new();
        let mut capacity_total: u128 = 0;

        for &rt in ResourceType::all() {
            let items = self.evidence_set.get(&rt).map(|v| v.as_slice()).unwrap_or(&[]);
            let prior = *self.prior_capacity.get(&rt).unwrap_or(&0);

            let (capacity, evidence_count, quorum_met, carry_forward) =
                aggregate_resource(items, prior);

            if carry_forward {
                let since = self.carry_forward_since.get(&rt).copied().unwrap_or(0);
                let since = if since == 0 { self.epoch } else { since };
                *self.carry_forward_since.entry(rt).or_insert(since) = since;
                if self.epoch.saturating_sub(since) >= MAX_CARRY_FORWARD_EPOCHS {
                    self.events.push(CapacityEvent::StaleCapacityWarning {
                        epoch:               self.epoch,
                        carry_forward_since: since,
                    });
                }
            } else {
                self.carry_forward_since.insert(rt, 0);
            }

            // Step-change warning
            if prior > 0 {
                let diff = if capacity > prior { capacity - prior } else { prior - capacity };
                let frac = diff.saturating_mul(D) / prior;
                if frac > CAPACITY_STEP_WARN_THRESHOLD {
                    self.events.push(CapacityEvent::CapacityStepWarning {
                        epoch:       self.epoch,
                        prior,
                        current:     capacity,
                        change_frac: frac,
                    });
                }
            }

            // Weighted contribution to capacity_total:
            // weight_r * capacity_e_r / D
            capacity_total += rt.weight().saturating_mul(capacity) / D;

            resource_reports.insert(rt, ResourceCapacityRecord {
                capacity,
                evidence_count: evidence_count as u32,
                quorum_met,
                carry_forward,
            });
        }

        let report = CapacityReport {
            epoch:                self.epoch,
            resource_reports,
            capacity_total,
            evidence_roots:       self.evidence_roots.clone(),
            aggregation_method:   AggregationMethod::MedianV0,
            validator_signatures: Vec::new(),
        };

        self.events.push(CapacityEvent::ReportAggregated {
            epoch:          self.epoch,
            capacity_total: report.capacity_total,
        });

        self.report = Some(report);
        Ok(self.report.as_ref().unwrap())
    }

    // ── Countersignature (§6.2) ──────────────────────────────────────────────

    /// Accept a validator countersignature for the pending CapacityReport.
    ///
    /// `total_validator_weight` — sum of all validators' weights.
    /// `validator_weight`       — weight of the signing validator.
    ///
    /// When the 2/3 threshold is crossed, transitions to FINALIZED and emits
    /// `ReportFinalized`.
    pub fn add_validator_signature(
        &mut self,
        validator_id: ProviderId,
        signature: Signature,
        validator_weight: u64,
        total_validator_weight: u64,
    ) -> Result<bool, TransitionError> {
        if self.phase != CapacityPhase::Finalizing {
            return Err(TransitionError::WrongPhase {
                expected: CapacityPhase::Finalizing,
                got:      self.phase,
            });
        }
        let report = self.report.as_mut().ok_or(TransitionError::ReportNotReady)?;

        // Deduplicate
        if report.validator_signatures.iter().any(|(id, _)| id == &validator_id) {
            return Ok(false); // already signed; not an error
        }

        report.validator_signatures.push((validator_id, signature));

        // Check 2/3 threshold
        let signed_weight: u64 = report.validator_signatures.len() as u64 * validator_weight;
        let threshold = (total_validator_weight * 2).div_ceil(3);
        if signed_weight > threshold {
            let capacity_total = report.capacity_total;
            self.phase = CapacityPhase::Finalized;
            self.events.push(CapacityEvent::ReportFinalized {
                epoch:          self.epoch,
                capacity_total,
            });
            return Ok(true);
        }
        Ok(false)
    }

    // ── Deadline / carry-forward (§5.3, §9) ─────────────────────────────────

    /// Called at `REPORT_DEADLINE_e` if the report is not yet FINALIZED.
    /// Transitions to CARRY_FORWARD and emits `CarryForwardActivated`.
    pub fn activate_carry_forward(&mut self, current_height: u64) -> Result<(), TransitionError> {
        if self.phase == CapacityPhase::Finalized {
            return Err(TransitionError::AlreadyFinalized);
        }
        if self.phase == CapacityPhase::CarryForward {
            return Ok(()); // idempotent
        }
        if current_height < self.report_deadline_height() {
            return Err(TransitionError::TooEarly {
                action:     "carry_forward",
                allowed_at: self.report_deadline_height(),
                current:    current_height,
            });
        }

        let prior_capacity = self.prior_capacity.values().sum::<u128>();
        self.phase = CapacityPhase::CarryForward;
        self.events.push(CapacityEvent::CarryForwardActivated {
            epoch:          self.epoch,
            prior_capacity,
        });
        Ok(())
    }

    /// The `capacity_e` value to hand to the QRC epoch boundary sequence.
    ///
    /// Returns the aggregated report's `capacity_total` if a report exists
    /// (FINALIZING or FINALIZED), or the weighted sum of prior-epoch values if
    /// CARRY_FORWARD or not yet aggregated (COLLECTING / no report).
    ///
    /// Note: countersignature is required before `capacity_e` has on-chain
    /// authority. Call this after `add_validator_signature` reaches the 2/3
    /// threshold for the canonical value; calling it from FINALIZING gives the
    /// provisional value (same number, awaiting countersigs).
    pub fn capacity_e(&self) -> u128 {
        match &self.report {
            // Aggregated (FINALIZING or FINALIZED): use the computed total.
            Some(r) if matches!(
                self.phase,
                CapacityPhase::Finalizing | CapacityPhase::Finalized
            ) => r.capacity_total,
            _ => {
                // Carry-forward or not yet aggregated: weighted sum of prior capacities.
                ResourceType::all()
                    .iter()
                    .map(|&rt| {
                        let c = self.prior_capacity.get(&rt).copied().unwrap_or(0);
                        rt.weight().saturating_mul(c) / D
                    })
                    .sum()
            }
        }
    }

    // ── Slashing (§7.1) ──────────────────────────────────────────────────────

    /// Apply a slash to a provider's collateral.
    ///
    /// In production, `collateral` comes from on-chain staked balance.
    /// Here it is tracked locally for testing.
    ///
    /// Returns `(slash_amount, remaining_collateral)`.
    pub fn slash_provider(
        &mut self,
        provider_id: &ProviderId,
        reason: String,
    ) -> Result<(u128, u128), SlashError> {
        let collateral = self
            .collateral
            .get_mut(provider_id)
            .ok_or(SlashError::ProviderNotFound(*provider_id))?;

        let slash_amount = collateral.saturating_mul(SLASH_FRACTION) / D;
        *collateral = collateral.saturating_sub(slash_amount);
        let remaining = *collateral;

        self.events.push(CapacityEvent::ProviderSlashed {
            provider_id: *provider_id,
            slash_amount,
            reason,
        });
        Ok((slash_amount, remaining))
    }

    /// Read a provider's current collateral balance.
    pub fn provider_collateral(&self, provider_id: &ProviderId) -> Option<u128> {
        self.collateral.get(provider_id).copied()
    }

    /// All evidence items for a given resource type.
    pub fn evidence_for(&self, rt: ResourceType) -> &[CapacityEvidence] {
        self.evidence_set.get(&rt).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

// ── Aggregation logic (§5.1, §5.2) ───────────────────────────────────────────

/// Aggregate a slice of evidence items for one resource type.
///
/// Returns `(capacity, evidence_count, quorum_met, carry_forward)`.
fn aggregate_resource(
    items: &[CapacityEvidence],
    prior_capacity: u128,
) -> (u128, usize, bool, bool) {
    let n = items.len();

    if n < MIN_PROVIDER_QUORUM {
        // Quorum not met → carry-forward
        return (prior_capacity, n, false, true);
    }

    let mut claims: Vec<u128> = items.iter().map(|e| e.capacity_claim).collect();
    claims.sort_unstable();

    let capacity = if n % 2 == 1 {
        claims[n / 2]
    } else {
        let lo = claims[n / 2 - 1];
        let hi = claims[n / 2];
        (lo + hi) / 2 // integer division; rounds down per spec
    };

    (capacity, n, true, false)
}

/// Compute a placeholder evidence root (XOR-fold of provider IDs, sorted).
/// A production implementation uses the chain's Merkle tree.
fn compute_evidence_root(items: &[CapacityEvidence]) -> [u8; 32] {
    let mut ids: Vec<[u8; 32]> = items.iter().map(|e| e.provider_id).collect();
    ids.sort_unstable();
    let mut root = [0u8; 32];
    for id in ids {
        for (r, b) in root.iter_mut().zip(id.iter()) {
            *r ^= b;
        }
    }
    root
}

// ── Challenge nonce derivation (§3.3) ────────────────────────────────────────

/// Derive the challenge nonce for epoch `e`.
///
/// `prev_block_hash` — hash of the last finalized block in epoch `e-1`.
///
/// Uses a simple SHA-256-like XOR fold (placeholder; production uses the
/// chain's hash function).
pub fn derive_challenge_nonce(epoch: u64, prev_block_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    // Mix epoch bytes
    let epoch_bytes = epoch.to_le_bytes();
    for (i, b) in epoch_bytes.iter().enumerate() {
        buf[i] ^= b;
    }
    // Mix previous block hash
    for (i, b) in prev_block_hash.iter().enumerate() {
        buf[i % 32] ^= b;
    }
    // Mix domain separator
    for (i, b) in DOMAIN_SEP_CAPACITY.iter().enumerate() {
        buf[i % 32] ^= b;
    }
    buf
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("wrong epoch: expected {expected}, got {got}")]
    WrongEpoch { expected: u64, got: u64 },

    #[error("ECW closed at height {closed_at}; submission at height {current} rejected")]
    EcwClosed { closed_at: u64, current: u64 },

    #[error("provider {0:?} is not registered")]
    ProviderNotRegistered(ProviderId),

    #[error("invalid signature from provider {0:?}")]
    InvalidSignature(ProviderId),

    #[error("challenge nonce mismatch")]
    WrongChallengeNonce,

    #[error("duplicate submission from provider {provider_id:?} for {resource_type:?} this epoch")]
    DuplicateSubmission {
        provider_id:   ProviderId,
        resource_type: ResourceType,
    },

    #[error("proof resource type mismatch: expected {expected:?}, got {got:?}")]
    ProofResourceTypeMismatch {
        expected: ResourceType,
        got:      ResourceType,
    },

    #[error("proof structurally invalid: {0}")]
    ProofInvalid(String),

    #[error("capacity claim {claim} exceeds single-provider cap {cap}")]
    ClaimExceedsCap { claim: u128, cap: u128 },
}

#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("wrong phase: expected {expected:?}, got {got:?}")]
    WrongPhase { expected: CapacityPhase, got: CapacityPhase },

    #[error("action '{action}' not allowed until height {allowed_at}; current height {current}")]
    TooEarly { action: &'static str, allowed_at: u64, current: u64 },

    #[error("report not yet aggregated")]
    ReportNotReady,

    #[error("report is already finalized")]
    AlreadyFinalized,
}

#[derive(Debug, Error)]
pub enum SlashError {
    #[error("provider {0:?} not found in collateral registry")]
    ProviderNotFound(ProviderId),
}

// ── Tests (§12 — all 11 spec scenarios) ───────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ─────────────────────────────────────────────────────────

    const COLLATERAL: u128 = 1_000 * D; // 1,000 CU of collateral

    fn provider(n: u8) -> ProviderId {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn nonce() -> [u8; 32] {
        [0xAB; 32]
    }

    fn sig() -> Signature {
        [0u8; 64]
    }

    /// Signature verifier that always accepts (for unit testing).
    fn always_accept(_id: &ProviderId, _sig: &Signature) -> bool { true }

    /// Signature verifier that always rejects.
    fn always_reject(_id: &ProviderId, _sig: &Signature) -> bool { false }

    fn make_evidence(
        provider_n: u8,
        resource_type: ResourceType,
        capacity_claim: u128,
        epoch: u64,
    ) -> CapacityEvidence {
        let proof = match resource_type {
            ResourceType::Compute => CapacityProof::Compute(ComputeProofV0 {
                benchmark_result: 1_000_000,
                benchmark_circuit: [0u8; 4],
                elapsed_ms: 500,
            }),
            ResourceType::Storage => CapacityProof::Storage(StorageProofV0 {
                merkle_root: [0u8; 32],
                sample_count: 100,
            }),
            ResourceType::ZkProving => CapacityProof::ZkProving(ZkProvingProofV0 {
                proof_bytes: vec![0u8; 128],
                circuit_id: [0u8; 4],
            }),
        };
        CapacityEvidence {
            provider_id:     provider(provider_n),
            vca_credential:  VcaCredential(vec![provider_n]),
            resource_type,
            capacity_claim,
            epoch,
            challenge_nonce: nonce(),
            response_hash:   [0u8; 32],
            proof,
            signature:       sig(),
        }
    }

    /// Build a default state: epoch=1, boundary=100, prior=0 for all resources.
    fn default_state() -> CapacityReportState {
        let prior: BTreeMap<ResourceType, u128> = ResourceType::all()
            .iter()
            .map(|&r| (r, 0u128))
            .collect();
        CapacityReportState::new(1, prior, nonce(), 0, 100)
    }

    fn register_n_providers(state: &mut CapacityReportState, n: u8) {
        for i in 1..=n {
            state.register_provider(provider(i), COLLATERAL);
        }
    }

    /// Submit evidence for `n_providers` with the given claim, then close ECW
    /// and aggregate. Returns the report's capacity_total.
    fn run_to_report(
        n_providers: u8,
        resource_type: ResourceType,
        claim: u128,
    ) -> (CapacityReportState, u128) {
        let mut state = default_state();
        register_n_providers(&mut state, n_providers);
        for i in 1..=n_providers {
            state
                .submit_evidence(
                    make_evidence(i, resource_type, claim, 1),
                    /* current_height */ 5,
                    always_accept,
                )
                .unwrap();
        }
        state.close_ecw(90).unwrap(); // at ecw_close = 100 - 10 = 90
        state.aggregate().unwrap();
        let total = state.capacity_e();
        (state, total)
    }

    // ── Weights sanity ────────────────────────────────────────────────────────

    #[test]
    fn weights_sum_to_d() {
        let sum: u128 = ResourceType::all().iter().map(|r| r.weight()).sum();
        assert_eq!(sum, D, "resource weights must sum to D");
    }

    // ── T1: All providers honest, quorum met ──────────────────────────────────

    #[test]
    fn t1_all_honest_quorum_met() {
        // 5 providers all claiming 1,000 CU (= 1_000 * D)
        let claim = 1_000 * D;
        let (_state, total) = run_to_report(5, ResourceType::Compute, claim);
        // capacity_e_r = median(claim × 5) = claim
        // capacity_total = weight_Compute * claim / D = 600_000 * 1_000_000_000 / 1_000_000 = 600_000_000
        assert!(total > 0, "T1: capacity must be nonzero when quorum met");
        // Compute contributes 60% of claim
        let expected_compute_contrib = WEIGHT_COMPUTE.saturating_mul(claim) / D;
        assert_eq!(total, expected_compute_contrib, "T1: capacity_total must equal weighted compute claim");
    }

    // ── T2: 1 Byzantine provider (of 5), inflated claim ──────────────────────

    #[test]
    fn t2_one_byzantine_of_five_median_unaffected() {
        let honest_claim = 1_000 * D;
        let inflated_claim = 1_000_000 * D; // 1000× honest

        let mut state = default_state();
        register_n_providers(&mut state, 5);

        // 4 honest + 1 Byzantine
        for i in 1..=4 {
            state
                .submit_evidence(make_evidence(i, ResourceType::Compute, honest_claim, 1), 5, always_accept)
                .unwrap();
        }
        state
            .submit_evidence(make_evidence(5, ResourceType::Compute, inflated_claim, 1), 5, always_accept)
            .unwrap();

        state.close_ecw(90).unwrap();
        state.aggregate().unwrap();

        let report = state.report.as_ref().unwrap();
        let rec = &report.resource_reports[&ResourceType::Compute];

        // Sorted claims: [honest×4, inflated]. Median (5 items) = claims[2] = honest_claim.
        assert_eq!(rec.capacity, honest_claim, "T2: 1 Byzantine of 5 — median must equal honest claim");
        assert!(rec.quorum_met, "T2: quorum must be met");
        assert!(!rec.carry_forward, "T2: carry_forward must be false");
    }

    // ── T3: 2 Byzantine providers (of 5), inflated claims ────────────────────

    #[test]
    fn t3_two_byzantine_of_five_median_within_honest_range() {
        let honest_claim = 1_000 * D;
        let inflated_claim = 9_999 * D;

        let mut state = default_state();
        register_n_providers(&mut state, 5);

        for i in 1..=3 {
            state
                .submit_evidence(make_evidence(i, ResourceType::Compute, honest_claim, 1), 5, always_accept)
                .unwrap();
        }
        for i in 4..=5 {
            state
                .submit_evidence(make_evidence(i, ResourceType::Compute, inflated_claim, 1), 5, always_accept)
                .unwrap();
        }

        state.close_ecw(90).unwrap();
        state.aggregate().unwrap();

        let report = state.report.as_ref().unwrap();
        let rec = &report.resource_reports[&ResourceType::Compute];

        // Sorted: [honest, honest, honest, inflated, inflated]. Median = honest_claim.
        assert_eq!(rec.capacity, honest_claim, "T3: 2 Byzantine of 5 — median must equal honest claim");
    }

    // ── T4: Majority Byzantine (3 of 5) ──────────────────────────────────────

    #[test]
    fn t4_majority_byzantine_median_dominated() {
        // Demonstrates the attack; motivates MIN_PROVIDER_QUORUM > 3 in production.
        let honest_claim = 1_000 * D;
        let inflated_claim = 9_999_999 * D;

        let mut state = default_state();
        register_n_providers(&mut state, 5);

        for i in 1..=2 {
            state
                .submit_evidence(make_evidence(i, ResourceType::Compute, honest_claim, 1), 5, always_accept)
                .unwrap();
        }
        for i in 3..=5 {
            state
                .submit_evidence(make_evidence(i, ResourceType::Compute, inflated_claim, 1), 5, always_accept)
                .unwrap();
        }

        state.close_ecw(90).unwrap();
        state.aggregate().unwrap();

        let report = state.report.as_ref().unwrap();
        let rec = &report.resource_reports[&ResourceType::Compute];

        // Sorted: [honest, honest, inflated, inflated, inflated]. Median = inflated_claim.
        assert_eq!(rec.capacity, inflated_claim,
            "T4: majority Byzantine dominates median — attack succeeds (expected by spec)");
    }

    // ── T5: Zero submissions → CARRY_FORWARD ─────────────────────────────────

    #[test]
    fn t5_zero_submissions_carry_forward() {
        let prior_compute = 500 * D;
        let mut prior = BTreeMap::new();
        prior.insert(ResourceType::Compute, prior_compute);
        prior.insert(ResourceType::Storage, 0);
        prior.insert(ResourceType::ZkProving, 0);

        let mut state = CapacityReportState::new(2, prior, nonce(), 0, 100);
        // No providers registered, no submissions.
        state.close_ecw(90).unwrap();
        state.aggregate().unwrap();

        let report = state.report.as_ref().unwrap();
        let rec = &report.resource_reports[&ResourceType::Compute];

        assert!(rec.carry_forward, "T5: zero submissions must yield carry_forward");
        assert_eq!(rec.capacity, prior_compute, "T5: carried-forward capacity must equal prior");
        assert!(!rec.quorum_met, "T5: quorum must not be met");
    }

    // ── T6: Below quorum → CARRY_FORWARD ─────────────────────────────────────

    #[test]
    fn t6_below_quorum_carry_forward() {
        let prior_compute = 300 * D;
        let mut prior = BTreeMap::new();
        prior.insert(ResourceType::Compute, prior_compute);
        prior.insert(ResourceType::Storage, 0);
        prior.insert(ResourceType::ZkProving, 0);

        let mut state = CapacityReportState::new(2, prior, nonce(), 0, 100);
        // Only 2 providers — below MIN_PROVIDER_QUORUM=3.
        register_n_providers(&mut state, 2);
        for i in 1..=2 {
            state
                .submit_evidence(make_evidence(i, ResourceType::Compute, 1_000 * D, 2), 5, always_accept)
                .unwrap();
        }

        state.close_ecw(90).unwrap();
        state.aggregate().unwrap();

        let report = state.report.as_ref().unwrap();
        let rec = &report.resource_reports[&ResourceType::Compute];

        assert!(rec.carry_forward, "T6: below-quorum must yield carry_forward");
        assert_eq!(rec.capacity, prior_compute, "T6: carried-forward capacity must equal prior");
    }

    // ── T7: Large provider exits (50% capacity drop) ──────────────────────────

    #[test]
    fn t7_large_provider_exit_step_warning() {
        let prior_compute = 10_000 * D;
        let mut prior = BTreeMap::new();
        prior.insert(ResourceType::Compute, prior_compute);
        prior.insert(ResourceType::Storage, 0);
        prior.insert(ResourceType::ZkProving, 0);

        let mut state = CapacityReportState::new(2, prior, nonce(), 0, 100);
        register_n_providers(&mut state, 3);

        // Providers claim ~50% of prior capacity
        for i in 1..=3 {
            state
                .submit_evidence(
                    make_evidence(i, ResourceType::Compute, 5_000 * D, 2),
                    5,
                    always_accept,
                )
                .unwrap();
        }

        state.close_ecw(90).unwrap();
        state.aggregate().unwrap();

        // A 50% drop (>20% threshold) must emit CapacityStepWarning
        let has_warning = state.events.iter().any(|e| {
            matches!(e, CapacityEvent::CapacityStepWarning { .. })
        });
        assert!(has_warning, "T7: 50% capacity drop must emit CapacityStepWarning");
    }

    // ── T8: Duplicate submission rejected ────────────────────────────────────

    #[test]
    fn t8_duplicate_submission_rejected() {
        let mut state = default_state();
        state.register_provider(provider(1), COLLATERAL);

        let ev = make_evidence(1, ResourceType::Compute, 1_000 * D, 1);
        state.submit_evidence(ev.clone(), 5, always_accept).unwrap();

        let result = state.submit_evidence(ev, 5, always_accept);
        assert!(
            matches!(result, Err(EvidenceError::DuplicateSubmission { .. })),
            "T8: second submission from same provider+resource_type must be rejected"
        );
    }

    // ── T9: Submission after ECW_close rejected ───────────────────────────────

    #[test]
    fn t9_submission_after_ecw_close_rejected() {
        let mut state = default_state();
        state.register_provider(provider(1), COLLATERAL);

        // ecw_close_height = 100 - 10 = 90; submit at height 90 (== closed)
        let result = state.submit_evidence(
            make_evidence(1, ResourceType::Compute, 1_000 * D, 1),
            90, // at ecw_close, not before it
            always_accept,
        );
        assert!(
            matches!(result, Err(EvidenceError::EcwClosed { .. })),
            "T9: submission at ECW_close height must be rejected"
        );

        // Also test height > ecw_close
        let result2 = state.submit_evidence(
            make_evidence(1, ResourceType::Compute, 1_000 * D, 1),
            95,
            always_accept,
        );
        assert!(
            matches!(result2, Err(EvidenceError::EcwClosed { .. })),
            "T9: submission after ECW_close must be rejected"
        );
    }

    // ── T10: Report not countersigned by deadline → CARRY_FORWARD ────────────

    #[test]
    fn t10_report_not_countersigned_carry_forward() {
        let prior_compute = 800 * D;
        let mut prior = BTreeMap::new();
        prior.insert(ResourceType::Compute, prior_compute);
        prior.insert(ResourceType::Storage, 0);
        prior.insert(ResourceType::ZkProving, 0);

        let mut state = CapacityReportState::new(2, prior.clone(), nonce(), 0, 100);
        register_n_providers(&mut state, 3);
        for i in 1..=3 {
            state
                .submit_evidence(make_evidence(i, ResourceType::Compute, 1_000 * D, 2), 5, always_accept)
                .unwrap();
        }
        state.close_ecw(90).unwrap();
        state.aggregate().unwrap();

        // Deadline passes without countersignature
        state.activate_carry_forward(95).unwrap(); // report_deadline = 100-5=95

        assert_eq!(state.phase, CapacityPhase::CarryForward, "T10: phase must be CARRY_FORWARD");
        let has_cf_event = state.events.iter().any(|e| {
            matches!(e, CapacityEvent::CarryForwardActivated { .. })
        });
        assert!(has_cf_event, "T10: CarryForwardActivated event must be emitted");
    }

    // ── T11: Successful ChallengeCapacityEvidence → slash ────────────────────

    #[test]
    fn t11_successful_challenge_slashes_provider() {
        let mut state = default_state();
        state.register_provider(provider(1), COLLATERAL);

        let (slash_amount, remaining) = state
            .slash_provider(
                &provider(1),
                "fabricated capacity evidence".into(),
            )
            .unwrap();

        let expected_slash = COLLATERAL.saturating_mul(SLASH_FRACTION) / D; // 20%
        assert_eq!(slash_amount, expected_slash, "T11: slash amount must be 20% of collateral");
        assert_eq!(remaining, COLLATERAL - slash_amount, "T11: remaining collateral must be reduced");

        let has_slash_event = state.events.iter().any(|e| {
            matches!(e, CapacityEvent::ProviderSlashed { .. })
        });
        assert!(has_slash_event, "T11: ProviderSlashed event must be emitted");
    }

    // ── Additional validity rule tests ────────────────────────────────────────

    #[test]
    fn wrong_epoch_rejected() {
        let mut state = default_state(); // epoch=1
        state.register_provider(provider(1), COLLATERAL);
        let ev = make_evidence(1, ResourceType::Compute, 1_000 * D, 2); // wrong epoch
        let result = state.submit_evidence(ev, 5, always_accept);
        assert!(matches!(result, Err(EvidenceError::WrongEpoch { .. })));
    }

    #[test]
    fn unregistered_provider_rejected() {
        let mut state = default_state();
        // provider(1) NOT registered
        let ev = make_evidence(1, ResourceType::Compute, 1_000 * D, 1);
        let result = state.submit_evidence(ev, 5, always_accept);
        assert!(matches!(result, Err(EvidenceError::ProviderNotRegistered(_))));
    }

    #[test]
    fn invalid_signature_rejected() {
        let mut state = default_state();
        state.register_provider(provider(1), COLLATERAL);
        let ev = make_evidence(1, ResourceType::Compute, 1_000 * D, 1);
        let result = state.submit_evidence(ev, 5, always_reject);
        assert!(matches!(result, Err(EvidenceError::InvalidSignature(_))));
    }

    #[test]
    fn wrong_challenge_nonce_rejected() {
        let mut state = default_state();
        state.register_provider(provider(1), COLLATERAL);
        let mut ev = make_evidence(1, ResourceType::Compute, 1_000 * D, 1);
        ev.challenge_nonce = [0xFF; 32]; // wrong nonce
        let result = state.submit_evidence(ev, 5, always_accept);
        assert!(matches!(result, Err(EvidenceError::WrongChallengeNonce)));
    }

    #[test]
    fn claim_exceeds_cap_rejected() {
        let mut state = default_state();
        state.register_provider(provider(1), COLLATERAL);
        let ev = make_evidence(1, ResourceType::Compute, MAX_SINGLE_PROVIDER_CLAIM + 1, 1);
        let result = state.submit_evidence(ev, 5, always_accept);
        assert!(matches!(result, Err(EvidenceError::ClaimExceedsCap { .. })));
    }

    #[test]
    fn median_odd_n() {
        // 3 honest providers: claims 100, 200, 300. Median = 200.
        let prior = BTreeMap::new();
        let mut state = CapacityReportState::new(1, prior, nonce(), 0, 100);
        for i in 1..=3 {
            state.register_provider(provider(i), COLLATERAL);
        }
        state.submit_evidence(make_evidence(1, ResourceType::Compute, 100 * D, 1), 5, always_accept).unwrap();
        state.submit_evidence(make_evidence(2, ResourceType::Compute, 200 * D, 1), 5, always_accept).unwrap();
        state.submit_evidence(make_evidence(3, ResourceType::Compute, 300 * D, 1), 5, always_accept).unwrap();
        state.close_ecw(90).unwrap();
        state.aggregate().unwrap();
        let rec = &state.report.as_ref().unwrap().resource_reports[&ResourceType::Compute];
        assert_eq!(rec.capacity, 200 * D, "odd-N median: must be middle value");
    }

    #[test]
    fn median_even_n() {
        // 4 providers: claims 100, 200, 300, 400. Median = (200+300)/2 = 250.
        let prior = BTreeMap::new();
        let mut state = CapacityReportState::new(1, prior, nonce(), 0, 100);
        for i in 1..=4 {
            state.register_provider(provider(i), COLLATERAL);
        }
        let claims = [100u128, 200, 300, 400];
        for (i, &c) in claims.iter().enumerate() {
            state.submit_evidence(
                make_evidence((i + 1) as u8, ResourceType::Compute, c * D, 1),
                5, always_accept,
            ).unwrap();
        }
        state.close_ecw(90).unwrap();
        state.aggregate().unwrap();
        let rec = &state.report.as_ref().unwrap().resource_reports[&ResourceType::Compute];
        assert_eq!(rec.capacity, 250 * D, "even-N median: must be (lo+hi)/2");
    }

    #[test]
    fn finalization_requires_2_3_threshold() {
        let (mut state, _) = run_to_report(3, ResourceType::Compute, 1_000 * D);
        // Uniform validator weight = 1; total = 3; threshold = ceil(3*2/3) = 2+1 = 3
        // First signature: not yet finalized
        let done = state.add_validator_signature(provider(10), sig(), 1, 3).unwrap();
        assert!(!done, "one of three signatures is not enough");
        assert_eq!(state.phase, CapacityPhase::Finalizing);

        // Second signature: still not finalized (signed_weight=2, threshold=3 → 2 > 2 is false)
        // (threshold = ceil(3*2/3) = 2; but condition is signed_weight > threshold, so 2 > 2 = false)
        let done = state.add_validator_signature(provider(11), sig(), 1, 3).unwrap();
        assert!(!done, "two of three signatures is not enough (need strictly more than 2/3)");

        // Third signature: finalized
        let done = state.add_validator_signature(provider(12), sig(), 1, 3).unwrap();
        assert!(done, "three of three signatures must finalize the report");
        assert_eq!(state.phase, CapacityPhase::Finalized);
    }

    #[test]
    fn derive_challenge_nonce_deterministic() {
        let h = [0xBE; 32];
        let n1 = derive_challenge_nonce(5, &h);
        let n2 = derive_challenge_nonce(5, &h);
        assert_eq!(n1, n2, "nonce derivation must be deterministic");
        let n3 = derive_challenge_nonce(6, &h);
        assert_ne!(n1, n3, "different epochs must produce different nonces");
    }
}
