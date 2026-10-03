//! # contribution_settlement — Finalized CapacityReport → QRC minting
//!
//! This module bridges the `CapacityEvidence_v0` state machine (`capacity_report`)
//! and the QRC resource economy engine (`QrcEngine`), completing the
//! contribution minting path described in QRC Economic Model v0.1 §4.2.
//!
//! ## Flow
//!
//! ```text
//! CapacityReportState (Finalized / Finalizing)
//!   │
//!   │  per-provider CapacityEvidence { provider_id, resource_type, capacity_claim }
//!   │  ───────────────── C(i,r,t) ─────────────────────────────────────────────►
//!   │
//!   └─► ContributionSettlement::settle()
//!         │
//!         │  maps ResourceType → ResourceKind (capacity_report subset)
//!         │  calls QrcEngine::credit_provider_earning() per provider
//!         │
//!         └─► Vec<SettlementRecord>  (audit trail for the epoch)
//! ```
//!
//! ## ResourceType → ResourceKind mapping
//!
//! `capacity_report::ResourceType` covers the three capacity-provable resource
//! types (Compute, Storage, ZkProving). `ResourceKind` in the QRC engine covers
//! seven types including Bandwidth, OracleData, AiInference, and
//! ExternalVerification — these are consumption-priced but not yet
//! capacity-reportable.  The mapping is 1-to-1 for the three overlapping types;
//! the other four kinds are excluded from contribution earning until the
//! CapacityReport sub-protocol is extended to cover them.
//!
//! ## When to call `settle()`
//!
//! Call once per epoch at the epoch boundary, immediately after the
//! CapacityReport reaches `Finalized` (or `Finalizing` if you want provisional
//! payouts — see `SettlementMode`). The engine's window must already have been
//! advanced with the epoch's demand/capacity data before calling `settle()`.
//!
//! ## Security invariants
//!
//! - Only evidence from a `Finalized` or `Finalizing` phase is accepted.
//! - Carry-forward evidence is NOT used for contribution earnings: only evidence
//!   submitted and aggregated *this epoch* qualifies (`carry_forward == false`
//!   per resource).
//! - Each provider is settled exactly once per (epoch, resource_type) pair.
//! - QRC is minted by `QrcEngine` which applies the full earning formula
//!   including per-resource weights and congestion multipliers.

use std::collections::BTreeMap;

use crate::{
    capacity_report::{CapacityPhase, CapacityReportState, ResourceType},
    QrcEngine, ResourceKind,
};

// ── ResourceType → ResourceKind bridge ───────────────────────────────────────

/// Map a `capacity_report::ResourceType` to the corresponding `ResourceKind`
/// in the QRC engine.
///
/// Returns `None` for resource types not yet supported by the engine
/// (none at present, but kept as an extension point).
pub fn resource_type_to_kind(rt: ResourceType) -> Option<ResourceKind> {
    match rt {
        ResourceType::Compute   => Some(ResourceKind::Compute),
        ResourceType::Storage   => Some(ResourceKind::Storage),
        ResourceType::ZkProving => Some(ResourceKind::ZkProving),
    }
}

/// Map a `ResourceKind` back to the corresponding `ResourceType` if one exists.
/// Returns `None` for engine-only kinds (Bandwidth, OracleData, AiInference,
/// ExternalVerification) that are not yet capacity-reportable.
pub fn kind_to_resource_type(kind: ResourceKind) -> Option<ResourceType> {
    match kind {
        ResourceKind::Compute   => Some(ResourceType::Compute),
        ResourceKind::Storage   => Some(ResourceType::Storage),
        ResourceKind::ZkProving => Some(ResourceType::ZkProving),
        ResourceKind::Bandwidth
        | ResourceKind::OracleData
        | ResourceKind::AiInference
        | ResourceKind::ExternalVerification => None,
    }
}

// ── SettlementMode ────────────────────────────────────────────────────────────

/// Controls when contribution QRC minting is triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementMode {
    /// Mint only after the CapacityReport has been fully countersigned
    /// (`CapacityPhase::Finalized`). Authoritative; no provisional payouts.
    Authoritative,
    /// Mint as soon as the report is aggregated (`CapacityPhase::Finalizing`),
    /// before all countersignatures arrive. Faster payouts but provisional.
    /// If the report is subsequently invalidated, a reconciliation pass is
    /// needed (deferred to v1).
    Provisional,
}

// ── SettlementRecord ──────────────────────────────────────────────────────────

/// Audit record for one provider's QRC earning in one epoch.
#[derive(Debug, Clone)]
pub struct SettlementRecord {
    /// Provider that earned QRC.
    pub provider_id: [u8; 32],
    /// Epoch this record covers.
    pub epoch: u64,
    /// Per-resource contribution units used in the earning formula.
    /// Maps `ResourceKind` → verified `C(i,r,t)` from the CapacityReport.
    pub contributions: BTreeMap<ResourceKind, u128>,
    /// QRC minted for this provider.
    pub qrc_minted: u128,
    /// Whether this was a provisional payout (Finalizing phase).
    pub provisional: bool,
}

// ── ContributionSettlement ────────────────────────────────────────────────────

/// Result of one epoch's contribution settlement.
#[derive(Debug, Clone)]
pub struct EpochSettlement {
    pub epoch: u64,
    /// Individual provider records.
    pub records: Vec<SettlementRecord>,
    /// Total QRC minted this epoch via the contribution path.
    pub total_minted: u128,
    /// Number of providers settled.
    pub provider_count: usize,
    /// Number of resource types skipped because their CapacityReport record
    /// was a carry-forward (no fresh evidence to pay out on).
    pub carry_forward_skips: usize,
    /// Whether the settlement was provisional (Finalizing phase).
    pub provisional: bool,
}

/// Errors that prevent settlement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettlementError {
    #[error("CapacityReport not yet aggregated (phase: {phase:?})")]
    NotYetAggregated { phase: CapacityPhase },
    #[error("SettlementMode::Authoritative requires Finalized phase; got {phase:?}")]
    NotAuthoritative { phase: CapacityPhase },
    #[error("CapacityReport is missing (state machine in unexpected state)")]
    MissingReport,
}

/// Settle contribution-path QRC for all providers that submitted valid
/// evidence in the given `CapacityReportState`.
///
/// # Arguments
///
/// * `capacity_state` — the epoch's capacity report state machine, which must
///   be in `Finalizing` or `Finalized` phase.
/// * `engine` — the `QrcEngine` to mint into.  Its utilization must already
///   reflect the current epoch's demand/capacity (i.e., `advance_window` was
///   called before `settle()`).
/// * `mode` — whether to require `Finalized` or accept `Finalizing`.
///
/// # Returns
///
/// An [`EpochSettlement`] summarising all provider payouts, or a
/// [`SettlementError`] if the state machine is not ready.
pub fn settle(
    capacity_state: &CapacityReportState,
    engine: &mut QrcEngine,
    mode: SettlementMode,
) -> Result<EpochSettlement, SettlementError> {
    // Phase guard
    match capacity_state.phase {
        CapacityPhase::Finalized => {} // always OK
        CapacityPhase::Finalizing => {
            if mode == SettlementMode::Authoritative {
                return Err(SettlementError::NotAuthoritative {
                    phase: capacity_state.phase,
                });
            }
        }
        other => {
            return Err(SettlementError::NotYetAggregated { phase: other });
        }
    }

    let report = capacity_state.report.as_ref().ok_or(SettlementError::MissingReport)?;
    let provisional = capacity_state.phase == CapacityPhase::Finalizing;
    let epoch = capacity_state.epoch;

    // Determine which resource types have genuine (non-carry-forward) evidence.
    // Carry-forward records do not trigger contribution payouts.
    let mut eligible_resources: BTreeMap<ResourceType, bool> = BTreeMap::new();
    for (&rt, record) in &report.resource_reports {
        eligible_resources.insert(rt, !record.carry_forward);
    }

    let mut carry_forward_skips = 0usize;

    // Build a map: provider_id → BTreeMap<ResourceKind, capacity_claim>
    // by iterating over all eligible resource types and their evidence.
    let mut provider_contributions: BTreeMap<[u8; 32], BTreeMap<ResourceKind, u128>> =
        BTreeMap::new();

    for &rt in ResourceType::all() {
        let genuine = *eligible_resources.get(&rt).unwrap_or(&false);
        if !genuine {
            carry_forward_skips += 1;
            tracing::debug!(
                epoch,
                resource = ?rt,
                "carry-forward resource: skipping contribution payout"
            );
            continue;
        }

        let kind = match resource_type_to_kind(rt) {
            Some(k) => k,
            None => continue, // no engine mapping (future-proofing)
        };

        for evidence in capacity_state.evidence_for(rt) {
            provider_contributions
                .entry(evidence.provider_id)
                .or_default()
                .insert(kind, evidence.capacity_claim);
        }
    }

    // Settle each provider.
    let mut records = Vec::with_capacity(provider_contributions.len());
    let mut total_minted = 0u128;

    for (provider_id, contributions) in &provider_contributions {
        let qrc_minted = engine.credit_provider_earning(provider_id, contributions);

        tracing::info!(
            epoch,
            provider  = hex::encode(provider_id),
            qrc_minted,
            provisional,
            resources = contributions.len(),
            "contribution-path QRC settled"
        );

        total_minted += qrc_minted;
        records.push(SettlementRecord {
            provider_id: *provider_id,
            epoch,
            contributions: contributions.clone(),
            qrc_minted,
            provisional,
        });
    }

    Ok(EpochSettlement {
        epoch,
        records,
        total_minted,
        provider_count: provider_contributions.len(),
        carry_forward_skips,
        provisional,
    })
}

// ── Private helpers ───────────────────────────────────────────────────────────

mod hex {
    pub fn encode(bytes: &[u8; 32]) -> String {
        bytes.iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>() + "…"
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capacity_report::{
            CapacityEvidence, CapacityPhase, CapacityProof, CapacityReportState,
            ComputeProofV0, ResourceType, StorageProofV0, VcaCredential, ZkProvingProofV0,
        },
        QrcEngine, D,
    };
    use std::collections::BTreeMap;

    // ── Test helpers ──────────────────────────────────────────────────────────

    const R0: u128 = D; // 1.0 × D = 1 QRC per QCB at target utilization

    fn always_valid_sig(_id: &[u8; 32], _sig: &[u8; 64]) -> bool { true }

    fn make_nonce(seed: u8) -> [u8; 32] {
        let mut n = [0u8; 32];
        // Derive from seed using the capacity_report domain separator logic
        for (i, b) in crate::capacity_report::DOMAIN_SEP_CAPACITY.iter().enumerate() {
            if i < 32 { n[i] = b ^ seed; }
        }
        n
    }

    fn make_provider(id: u8) -> [u8; 32] {
        let mut p = [0u8; 32];
        p[0] = id;
        p
    }

    fn make_sig() -> [u8; 64] { [0u8; 64] }

    fn make_evidence(
        provider: u8,
        rt: ResourceType,
        claim: u128,
        epoch: u64,
        nonce: [u8; 32],
    ) -> CapacityEvidence {
        let proof = match rt {
            ResourceType::Compute => CapacityProof::Compute(ComputeProofV0 {
                benchmark_result:  1_000_000,
                benchmark_circuit: [1, 2, 3, 4],
                elapsed_ms:        100,
            }),
            ResourceType::Storage => CapacityProof::Storage(StorageProofV0 {
                merkle_root:  [0u8; 32],
                sample_count: 8,
            }),
            ResourceType::ZkProving => CapacityProof::ZkProving(ZkProvingProofV0 {
                proof_bytes: vec![1, 2, 3],
                circuit_id:  [0u8; 4],
            }),
        };
        CapacityEvidence {
            provider_id:     make_provider(provider),
            vca_credential:  VcaCredential(vec![provider]),
            resource_type:   rt,
            capacity_claim:  claim,
            epoch,
            challenge_nonce: nonce,
            response_hash:   [0u8; 32],
            proof,
            signature:       make_sig(),
        }
    }

    /// Build a CapacityReportState with `n` providers, run it through to
    /// Finalizing, and return it.
    fn make_finalizing_state(n_providers: u8, epoch: u64) -> CapacityReportState {
        let nonce      = make_nonce(1);
        let mut state  = CapacityReportState::new(
            epoch,
            BTreeMap::new(),
            nonce,
            0,
            100,
        );

        for id in 0..n_providers {
            state.register_provider(make_provider(id), 1_000 * D);
        }

        let ecw_close = state.ecw_close_height();
        for id in 0..n_providers {
            for &rt in ResourceType::all() {
                let claim = (id as u128 + 1) * D * 1_000; // 1000, 2000, … CU × D
                state.submit_evidence(
                    make_evidence(id, rt, claim, epoch, nonce),
                    ecw_close - 1,
                    always_valid_sig,
                ).unwrap();
            }
        }

        state.close_ecw(ecw_close).unwrap();
        state.aggregate().unwrap();
        state
    }

    // ── T1: basic settle — mints QRC for all providers ─────────────────────

    #[test]
    fn t1_settle_mints_qrc_for_all_providers() {
        let n = 4u8;
        let state  = make_finalizing_state(n, 1);
        let mut engine = QrcEngine::new(R0);

        let result = settle(&state, &mut engine, SettlementMode::Provisional).unwrap();

        assert_eq!(result.epoch, 1);
        assert_eq!(result.provider_count, n as usize);
        assert!(result.total_minted > 0, "should have minted QRC");
        assert_eq!(result.records.len(), n as usize);
        assert!(result.provisional);

        // All providers got > 0 QRC
        for r in &result.records {
            assert!(r.qrc_minted > 0, "provider {:?} got 0 QRC", &r.provider_id[0]);
        }
    }

    // ── T2: authoritative mode requires Finalized phase ───────────────────────

    #[test]
    fn t2_authoritative_mode_rejected_in_finalizing() {
        let state      = make_finalizing_state(4, 1);
        let mut engine = QrcEngine::new(R0);

        let err = settle(&state, &mut engine, SettlementMode::Authoritative).unwrap_err();
        assert!(
            matches!(err, SettlementError::NotAuthoritative { phase: CapacityPhase::Finalizing }),
            "unexpected error: {:?}", err
        );
    }

    // ── T3: collecting phase → not yet aggregated error ───────────────────────

    #[test]
    fn t3_collecting_phase_returns_not_yet_aggregated() {
        let nonce      = make_nonce(1);
        let state      = CapacityReportState::new(1, BTreeMap::new(), nonce, 0, 100);
        let mut engine = QrcEngine::new(R0);

        let err = settle(&state, &mut engine, SettlementMode::Provisional).unwrap_err();
        assert!(
            matches!(err, SettlementError::NotYetAggregated { phase: CapacityPhase::Collecting }),
            "unexpected error: {:?}", err
        );
    }

    // ── T4: total minted equals sum of individual records ────────────────────

    #[test]
    fn t4_total_minted_equals_sum_of_records() {
        let state      = make_finalizing_state(5, 2);
        let mut engine = QrcEngine::new(R0);
        let result     = settle(&state, &mut engine, SettlementMode::Provisional).unwrap();

        let sum: u128 = result.records.iter().map(|r| r.qrc_minted).sum();
        assert_eq!(result.total_minted, sum);
    }

    // ── T5: engine supply increases by total minted ───────────────────────────

    #[test]
    fn t5_engine_supply_increases_by_total_minted() {
        let state          = make_finalizing_state(4, 1);
        let mut engine     = QrcEngine::new(R0);
        let before_supply  = engine.total_supply;

        let result = settle(&state, &mut engine, SettlementMode::Provisional).unwrap();

        assert_eq!(
            engine.total_supply,
            before_supply + result.total_minted
        );
        assert_eq!(
            engine.total_contribution_minted,
            result.total_minted
        );
    }

    // ── T6: larger capacity claim → larger earning ────────────────────────────

    #[test]
    fn t6_higher_claim_earns_more_qrc() {
        let epoch       = 1u64;
        let nonce       = make_nonce(2);
        let mut state   = CapacityReportState::new(epoch, BTreeMap::new(), nonce, 0, 100);

        // 4 providers so quorum is met. provider[3] has 5× the claim of provider[0].
        for id in 0u8..4 {
            state.register_provider(make_provider(id), 1_000 * D);
        }
        let ecw = state.ecw_close_height();

        // All provide Compute only; provider 3 claims 5× more than provider 0.
        let claims: [u128; 4] = [D * 100, D * 200, D * 300, D * 500];
        for (id, &claim) in claims.iter().enumerate() {
            state.submit_evidence(
                make_evidence(id as u8, ResourceType::Compute, claim, epoch, nonce),
                ecw - 1,
                always_valid_sig,
            ).unwrap();
        }
        state.close_ecw(ecw).unwrap();
        state.aggregate().unwrap();

        let mut engine = QrcEngine::new(R0);
        let result = settle(&state, &mut engine, SettlementMode::Provisional).unwrap();

        // Find earnings for provider 0 (smallest) and provider 3 (largest).
        let earn_small = result.records.iter()
            .find(|r| r.provider_id[0] == 0).unwrap().qrc_minted;
        let earn_large = result.records.iter()
            .find(|r| r.provider_id[0] == 3).unwrap().qrc_minted;

        assert!(
            earn_large > earn_small,
            "provider with 5× claim should earn more QRC (got {} vs {})",
            earn_large, earn_small
        );
    }

    // ── T7: contributions map resource_type → resource_kind correctly ─────────

    #[test]
    fn t7_contributions_use_correct_resource_kind() {
        let state      = make_finalizing_state(4, 1);
        let mut engine = QrcEngine::new(R0);
        let result     = settle(&state, &mut engine, SettlementMode::Provisional).unwrap();

        for record in &result.records {
            // All three CapacityReport resource types should be present.
            assert!(record.contributions.contains_key(&ResourceKind::Compute));
            assert!(record.contributions.contains_key(&ResourceKind::Storage));
            assert!(record.contributions.contains_key(&ResourceKind::ZkProving));

            // Engine-only kinds must NOT be present (not capacity-reportable yet).
            assert!(!record.contributions.contains_key(&ResourceKind::Bandwidth));
            assert!(!record.contributions.contains_key(&ResourceKind::OracleData));
            assert!(!record.contributions.contains_key(&ResourceKind::AiInference));
            assert!(!record.contributions.contains_key(&ResourceKind::ExternalVerification));
        }
    }

    // ── T8: carry-forward resource types are skipped ──────────────────────────

    #[test]
    fn t8_carry_forward_resources_are_skipped() {
        // Only 1 provider — quorum (3) not met → carry-forward for all resources.
        let epoch      = 1u64;
        let nonce      = make_nonce(3);
        let mut state  = CapacityReportState::new(epoch, BTreeMap::new(), nonce, 0, 100);
        state.register_provider(make_provider(0), 1_000 * D);

        let ecw = state.ecw_close_height();
        state.submit_evidence(
            make_evidence(0, ResourceType::Compute, D * 100, epoch, nonce),
            ecw - 1,
            always_valid_sig,
        ).unwrap();
        state.close_ecw(ecw).unwrap();
        state.aggregate().unwrap(); // transitions to Finalizing with all carry-forward

        let mut engine = QrcEngine::new(R0);
        let result = settle(&state, &mut engine, SettlementMode::Provisional).unwrap();

        // No providers settled (all resources are carry-forward; no fresh evidence).
        assert_eq!(result.total_minted, 0, "carry-forward resources must not trigger QRC minting");
        assert_eq!(result.provider_count, 0);
        assert_eq!(result.carry_forward_skips, 3, "all 3 resource types should be skipped");
    }

    // ── T9: resource_type_to_kind / kind_to_resource_type round-trips ─────────

    #[test]
    fn t9_resource_kind_mapping_round_trips() {
        for &rt in ResourceType::all() {
            let kind = resource_type_to_kind(rt).expect("all ResourceTypes should map to a ResourceKind");
            let back = kind_to_resource_type(kind).expect("mapped kind should round-trip back");
            assert_eq!(back, rt);
        }
    }

    #[test]
    fn t9b_engine_only_kinds_have_no_resource_type() {
        let engine_only = [
            ResourceKind::Bandwidth,
            ResourceKind::OracleData,
            ResourceKind::AiInference,
            ResourceKind::ExternalVerification,
        ];
        for kind in engine_only {
            assert!(
                kind_to_resource_type(kind).is_none(),
                "{:?} should not map to a ResourceType", kind
            );
        }
    }

    // ── T10: zero providers → zero minted, zero records ───────────────────────

    #[test]
    fn t10_no_evidence_means_zero_minted() {
        let nonce     = make_nonce(4);
        let mut state = CapacityReportState::new(1, BTreeMap::new(), nonce, 0, 100);
        // Register enough providers so aggregate doesn't carry-forward due to registration,
        // but don't submit evidence so quorum fails and carry-forward fires.
        for id in 0u8..4 {
            state.register_provider(make_provider(id), D * 1_000);
        }
        let ecw = state.ecw_close_height();
        state.close_ecw(ecw).unwrap();
        state.aggregate().unwrap();

        let mut engine = QrcEngine::new(R0);
        let result = settle(&state, &mut engine, SettlementMode::Provisional).unwrap();

        assert_eq!(result.total_minted, 0);
        assert_eq!(result.records.len(), 0);
        assert_eq!(engine.total_contribution_minted, 0);
    }
}
