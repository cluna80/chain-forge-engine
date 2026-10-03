# CapacityReport Sub-Protocol Specification v0.1

**Status**: Draft — prerequisite for CIRFI Rust implementation  
**Depends on**: CIRFI-Protocol-Spec-v0.1.md (commit `1473a7d`)  
**Answers**: CIRFI-Protocol-Spec §8.1 Open Question (CRITICAL)

---

## 0. Purpose and Scope

The CIRFI State Validity Invariant is:

```
outstanding_e * CR_min_fixed <= capacity_e * D
```

`capacity_e` is consensus-critical state. If two validators disagree on
`capacity_e`, they may reach different conclusions about whether the same
`QcbToCirfi` transaction is valid. That is a consensus fork, not an
economic error.

This specification defines the **CapacityReport sub-protocol**: the
peer-level protocol to CIRFI issuance that establishes `capacity_e` as a
deterministic, Byzantine-resistant, auditable value agreed upon by all
validators before the CIRFI epoch boundary runs.

### What this spec does NOT do

This spec does not define:
- VCA contribution verification (separate protocol)
- CIRFI issuance or consumption (see CIRFI-Protocol-Spec)
- Validator set management (see chain consensus layer)
- Economic calibration of CU/ucirfi ratio (see §8.2 of CIRFI spec)

### Required claim separation

```
┌────────────────────────────────────────────────────┐
│  VCA verifies contribution                         │
│    (did this provider do work in the past?)        │
└──────────────────────────┬─────────────────────────┘
                           │ necessary but not sufficient
┌──────────────────────────▼─────────────────────────┐
│  CapacityEvidence verifies resource availability   │
│    (are resources available to service claims now?)│
└──────────────────────────┬─────────────────────────┘
                           │ aggregated and finalized by
┌──────────────────────────▼─────────────────────────┐
│  Consensus verifies the CapacityReport             │
│    (is this the canonical capacity_e all agree on?)│
└────────────────────────────────────────────────────┘
```

These are three distinct claims. A provider who performed past work (VCA)
may not have current capacity (CapacityEvidence). Validator agreement on a
CapacityReport (Consensus) is meaningless if the underlying evidence is
fabricated.

---

## 1. Definitions

**CapacityUnit (CU)**: The atomic unit of resource capacity. One CU
represents one standardized unit of a given `ResourceType`.

**ResourceType**: An enumerated resource category. Initial set:
- `Compute` — general-purpose compute (in normalized FLOP-equivalents)
- `Storage` — persistent storage (in bytes)
- `ZkProving` — ZK proof generation (in normalized proof-seconds)

Additional resource types require a protocol upgrade.

**CapacityEvidence**: A signed, epoch-scoped claim by a registered
provider asserting that it can service a stated number of CU for a given
`ResourceType`. Evidence is the raw material; it is not authoritative until
aggregated.

**CapacityReport**: The authoritative per-resource-type capacity value for
an epoch, derived by deterministic aggregation of finalized evidence and
countersigned by ≥ 2/3 of the validator set by weight.

**Registered Provider**: A protocol participant holding:
1. A valid VCA credential issued by the chain's VCA protocol
2. A staked collateral deposit ≥ `MIN_PROVIDER_STAKE` (see §6)

Registration is required to submit CapacityEvidence. Unregistered
submissions MUST be rejected.

**Evidence Collection Window**: The period `[epoch_start_e, ECW_close_e]`
during which CapacityEvidence for epoch `e` is accepted. The window closes
`ECW_CLOSE_OFFSET` blocks before the epoch boundary.

**Evidence Set**: The set of all valid, non-duplicate CapacityEvidence
items finalized before `ECW_close_e`. This set is the input to aggregation.

---

## 2. CapacityEvidence Structure

```
CapacityEvidence = {
    // Identity
    provider_id:        PublicKey,          // VCA credential key
    vca_credential:     VcaCredential,      // current epoch VCA proof
    
    // Resource claim
    resource_type:      ResourceType,
    capacity_claim:     u128,               // claimed CU, fixed-point (× D)
    
    // Liveness and freshness
    epoch:              u64,                // must equal current epoch
    challenge_nonce:    [u8; 32],           // issued by chain for this epoch
    response_hash:      [u8; 32],           // H(nonce || capacity_proof_data)
    
    // Challenge-response proof (resource-type specific)
    proof:              CapacityProof,      // see §2.1
    
    // Signature
    signature:          Signature,          // over all fields above
}
```

`capacity_claim` is expressed as fixed-point with denominator D = 1_000_000
(consistent with CIRFI spec §1). An evidence item claiming 1,000 CU of
Compute is encoded as `capacity_claim = 1_000 * D = 1_000_000_000`.

### 2.1 CapacityProof (resource-type specific)

The proof format is per-`ResourceType`. Initial v0 proofs are intentionally
minimal; they will be tightened in subsequent versions.

#### 2.1.1 ComputeProof_v0

```
ComputeProof_v0 = {
    benchmark_result:  u64,    // normalized operations completed
    benchmark_circuit: [u8; 4], // canonical circuit ID
    elapsed_ms:        u32,    // wall-clock time
    // Note: v0 does not verify the computation — it time-gates it.
    // A provider cannot complete the canonical benchmark faster than
    // it takes to run it, setting a soft lower bound on fabrication cost.
    // V1 will require a ZK proof of correct execution.
}
```

#### 2.1.2 StorageProof_v0

```
StorageProof_v0 = {
    merkle_root:  [u8; 32],  // root of challenge-sampled stored data
    sample_count: u32,       // number of sectors sampled
    // Sector sampling is driven by challenge_nonce so cannot be precomputed.
}
```

#### 2.1.3 ZkProvingProof_v0

```
ZkProvingProof_v0 = {
    proof_bytes:    Vec<u8>,  // a proof over the canonical test circuit
    circuit_id:     [u8; 4],  // must match chain-published circuit
    // The proving time is measured by the proof's public inputs.
    // Claimed ZK capacity must be ≤ (epoch_duration / proving_time) × safety_margin.
}
```

---

## 3. Evidence Submission

### 3.1 Submission transaction type

```
SubmitCapacityEvidence {
    evidence: CapacityEvidence,
}
```

### 3.2 Submission validity rules

A `SubmitCapacityEvidence` transaction is valid if and only if:

1. `evidence.epoch == current_epoch_e`
2. `current_block_height < ECW_close_e` (evidence window still open)
3. `is_registered_provider(evidence.provider_id)` — holds valid VCA credential + stake
4. `verify_signature(evidence.provider_id, evidence.signature)` — signature valid
5. `evidence.challenge_nonce == chain_challenge_nonce_e` — nonce issued this epoch
6. `!evidence_already_submitted(evidence.provider_id, evidence.resource_type, evidence.epoch)` — no duplicate
7. `verify_capacity_proof(evidence.proof, evidence.resource_type, evidence.capacity_claim)` — proof valid
8. `evidence.capacity_claim <= MAX_SINGLE_PROVIDER_CLAIM` (per §6)

Rejection of any condition MUST produce a deterministic, logged error.
Validators MUST agree on which evidence items are valid; validity rules are
fully deterministic given the current chain state.

### 3.3 Challenge nonce issuance

At the start of each epoch `e`, the chain derives:

```
challenge_nonce_e = H(epoch_e || finalized_block_hash_{e-1} || DOMAIN_SEP_CAPACITY)
```

where `DOMAIN_SEP_CAPACITY = b"CAPACITY_EVIDENCE_NONCE_V0"`.

This is deterministic and unpredictable to providers until the epoch begins,
preventing precomputed proofs.

---

## 4. Evidence Set Finalization

At block height `ECW_close_e` (= epoch boundary − ECW_CLOSE_OFFSET blocks):

1. The evidence collection window closes. No further submissions are accepted.
2. All valid, non-duplicate evidence items received before this height form
   the **finalized evidence set** `E_e_r` for each resource type `r`.
3. `E_e_r` is committed on-chain as a Merkle root: `evidence_root_e_r = MerkleRoot(sort_by_provider_id(E_e_r))`.
4. This commitment is the on-chain anchor for post-hoc dispute resolution (§7).

The finalization is deterministic: all validators who have processed the same
transactions will compute identical `evidence_root_e_r`.

---

## 5. Aggregation

### 5.1 Aggregation function

Given finalized evidence set `E_e_r = { ev_1, ev_2, ..., ev_N }`:

```
// Step 1: extract capacity claims
claims = [ev_i.capacity_claim for ev_i in E_e_r]
sorted_claims = sort_ascending(claims)

// Step 2: median aggregation (Byzantine-robust)
if len(sorted_claims) == 0:
    capacity_e_r = capacity_{e-1}_r   // carry-forward (see §5.3)
elif len(sorted_claims) % 2 == 1:
    capacity_e_r = sorted_claims[ len/2 ]
else:
    lo = sorted_claims[ len/2 - 1 ]
    hi = sorted_claims[ len/2 ]
    capacity_e_r = (lo + hi) / 2      // integer division; rounds down

// Step 3: quorum check
if len(E_e_r) < MIN_PROVIDER_QUORUM:
    capacity_e_r = capacity_{e-1}_r   // carry-forward: quorum not met
```

**Rationale for median**: With N evidence items, a coalition of at most
`floor((N-1)/2)` dishonest providers cannot move the median above the lowest
honest claim. The median is the strongest single-statistic aggregation
against a minority adversary. Summation would be strictly dominated by a
Sybil attack; weighted-average requires stake-weighting infrastructure not
yet specified.

### 5.2 Multi-resource aggregation

The total `capacity_e` is a weighted sum over resource types:

```
capacity_e = Σ_r ( weight_r * capacity_e_r ) / D
```

where `weight_r` values are chain parameters (see §6). The weights express
relative economic value per CU across resource types.

**Note**: Incorrect weights allow cheap resources to dominate `capacity_e`.
Weight calibration is an economic decision requiring separate governance;
initial weights are provided in §6 as conservative starting values.

### 5.3 Carry-forward policy

If no valid report is available for resource type `r` in epoch `e`
(quorum not met, no submissions, or ECW closed with no valid evidence):

```
capacity_e_r = capacity_{e-1}_r
```

Carry-forward continues indefinitely. However, if `capacity_e_r` has not
been updated for `MAX_CARRY_FORWARD_EPOCHS` consecutive epochs, the chain
MUST emit a protocol warning event. Implementations SHOULD alert operators.

Carry-forward does NOT reduce capacity. Actual capacity may have declined.
The circuit breaker (CIRFI-Protocol-Spec §7.3) is the backstop: if
outstanding grows relative to stale carried-forward capacity, CR falls and
the Availability Guard fires.

---

## 6. CapacityReport Construction and Countersignature

### 6.1 Report structure

```
CapacityReport_e = {
    epoch:            u64,
    resource_reports: Map<ResourceType, ResourceCapacityRecord>,
    capacity_total:   u128,                  // = capacity_e (weighted sum)
    evidence_roots:   Map<ResourceType, [u8; 32]>,  // per-resource Merkle roots
    aggregation_method: AggregationMethod,   // = Median_v0
    validator_signatures: Vec<(PublicKey, Signature)>,
}

ResourceCapacityRecord = {
    capacity:      u128,    // capacity_e_r
    evidence_count: u32,    // |E_e_r|
    quorum_met:    bool,
    carry_forward: bool,    // true if this is a carry-forward value
}
```

### 6.2 Countersignature requirement

A `CapacityReport_e` is **valid** if and only if:

```
Σ_{ i in validator_signatures } weight(validator_i)
    > (2/3) * Σ_{ all validators } weight(validator)
```

This is the standard BFT threshold. All validators MUST:
1. Independently compute `capacity_e` from the finalized evidence set
2. Verify that the proposed `CapacityReport_e.capacity_total` matches their
   own computation
3. Sign if and only if the values match

A validator MUST NOT countersign a CapacityReport whose `capacity_total`
differs from its own computation, even if 2/3 of other validators have
already signed.

### 6.3 Report finalization timing

The `CapacityReport_e` is finalized as part of the CIRFI epoch boundary
sequence, Step 2 ("ACCEPT_CAPACITY_REPORT"). It must be available on-chain
before the epoch boundary block is finalized.

Timeline within epoch `e`:

```
epoch_start_e
    │
    ├── [ECW open] — challenge_nonce_e published
    │
    ├── ... providers submit CapacityEvidence ...
    │
    ├── ECW_close_e (= boundary − ECW_CLOSE_OFFSET blocks)
    │      evidence_root_e_r committed
    │      validators begin aggregation
    │
    ├── REPORT_DEADLINE_e (= boundary − REPORT_DEADLINE_OFFSET blocks)
    │      CapacityReport_e must be countersigned and on-chain by this block
    │
    └── epoch_boundary_e
           CIRFI epoch boundary sequence runs (uses finalized capacity_e)
```

---

## 7. Slashing and Dispute Resolution

### 7.1 Sybil-capacity defense: collateral slashing

The primary defense against fabricated capacity claims is economic:

**Registration requirement**: A provider MUST stake `MIN_PROVIDER_STAKE`
collateral before submitting CapacityEvidence. Collateral is locked for
`COLLATERAL_LOCK_EPOCHS` after each submission.

**Challenge mechanism**: Any protocol participant may submit a
`ChallengeCapacityEvidence` transaction within `CHALLENGE_WINDOW_BLOCKS`
of a finalized CapacityReport, identifying a specific evidence item they
believe is fabricated.

```
ChallengeCapacityEvidence = {
    evidence_id:    (provider_id, resource_type, epoch),
    challenge_type: ChallengeType,
    proof_of_false: ChallengeProof,
}
```

If the challenge succeeds (adjudicated by validators within `ADJUDICATION_WINDOW`):
- Provider's staked collateral is slashed by `SLASH_FRACTION` (see §8)
- Slashed collateral is distributed: 50% to challenger, 50% burned
- The challenged evidence item is retroactively excluded and `capacity_e_r`
  is recomputed. If recomputation changes the capacity-invariant decision for
  any finalized CIRFI transaction in that epoch, those transactions are
  flagged for governance review (the state transition cannot be reversed; the
  slash is the economic penalty)

### 7.2 Dispute evidence anchor

Because `evidence_root_e_r` is committed on-chain at `ECW_close_e` (§4),
any evidence item can be proven to have been included or excluded from the
final set using a Merkle proof against that root. This is the on-chain
anchor for post-hoc disputes.

A provider who claims to have submitted valid evidence that was wrongly
excluded can prove this by presenting the evidence and a Merkle proof of
its inclusion in the committed root. A validator who claims it never
received an evidence item can be shown the root commitment that proves the
item was finalized.

### 7.3 Single-epoch capacity step protection

A sudden provider exit (Scenario 3 in v3 simulation: CR → 0.027) can cause
a step discontinuity in `capacity_e`. No smoothing mechanism is specified
at this time; the Availability Guard circuit breaker (CR_halt = 0.75) is
the primary protection.

However, implementations SHOULD emit a warning event whenever:

```
|capacity_e - capacity_{e-1}| / capacity_{e-1} > CAPACITY_STEP_WARN_THRESHOLD
```

This provides an operator signal without blocking consensus. Protocol-level
smoothing (e.g., a cap on single-epoch capacity changes) is deferred to v0.2.

---

## 8. Parameters

All parameters are network-configurable via governance. Initial values
are calibration estimates; the v3 simulation did not sweep them.

```
// Fixed-point denominator (inherited from CIRFI spec)
D = 1_000_000                           // [CONSTITUTIONAL]

// Provider registration
MIN_PROVIDER_STAKE        = TBD_QCB     // minimum staked QCB to register
                                        // must be set before mainnet

// Evidence collection
ECW_CLOSE_OFFSET          = 10          // blocks before boundary ECW closes
REPORT_DEADLINE_OFFSET    = 5           // blocks before boundary report due
MAX_SINGLE_PROVIDER_CLAIM = 10_000_000_000_000  // 10^13 CU fixed-point cap
                                        // prevents one provider dominating median

// Quorum
MIN_PROVIDER_QUORUM       = 3           // minimum evidence items for valid report
                                        // (3 = minimum for honest median with 1 Byzantine)

// Carry-forward
MAX_CARRY_FORWARD_EPOCHS  = 3           // warning threshold; no hard stop

// Multi-resource weights (initial)
weight_Compute            = 600_000     // 60% [fixed-point × D]
weight_Storage            = 150_000     // 15%
weight_ZkProving          = 250_000     // 25%
// Must sum to D = 1_000_000

// Slashing
CHALLENGE_WINDOW_BLOCKS   = 100         // blocks after CapacityReport finalization
ADJUDICATION_WINDOW       = 50          // blocks for validator adjudication
SLASH_FRACTION            = 200_000     // 20% of staked collateral [fixed-point × D]
COLLATERAL_LOCK_EPOCHS    = 4           // lock period after submission

// Step warning
CAPACITY_STEP_WARN_THRESHOLD = 200_000  // 20% single-epoch change [fixed-point × D]
```

---

## 9. Relationship to CIRFI Epoch Boundary

The CIRFI epoch boundary sequence (CIRFI-Protocol-Spec §4) assumes a finalized
`capacity_e` is available at Step 2. This sub-protocol provides that value.

The integration contract is:

```
// From CapacityReport sub-protocol → CIRFI issuance protocol
capacity_e: u128 = finalized_CapacityReport_e.capacity_total
```

If no valid CapacityReport is finalized by `REPORT_DEADLINE_e`:

```
capacity_e = capacity_{e-1}   // carry-forward (sub-protocol handles this)
```

The CIRFI epoch boundary sequence proceeds regardless. A missing report does
not halt consensus — it uses the last known capacity. The Availability Guard
will fire if outstanding has grown relative to stale capacity.

---

## 10. Open Questions (v0.2 targets)

### 10.1 Stake-weighted aggregation

Median aggregation (§5.1) is Byzantine-robust but treats a large provider
and a small provider identically. A stake-weighted median or stake-weighted
average would align economic weight with reporting authority. Requires:
- Definition of provider stake as a weight
- Handling of stake changes mid-epoch
- Analysis of whether stake-weighting improves or worsens Sybil resistance

### 10.2 v1 proof types

`ComputeProof_v0`, `StorageProof_v0`, and `ZkProvingProof_v0` are
intentionally minimal. v1 should require:
- Compute: ZK proof of correct execution of canonical benchmark
- Storage: Proof-of-Spacetime (continuous availability, not point-in-time)
- ZkProving: Recursive proof-of-proof-generation

### 10.3 Protocol-level capacity smoothing

Single-epoch step discontinuities (§7.3) are currently handled only by the
circuit breaker. A per-epoch capacity change cap (e.g., max 20% decrease per
epoch) would bound the discontinuity but would also allow gradual fraudulent
inflation over many epochs. The tradeoff requires analysis.

### 10.4 Challenge adjudication mechanism

The `ChallengeCapacityEvidence` mechanism (§7.1) specifies slashing
outcomes but defers the adjudication mechanism — how validators determine
whether the challenge succeeds — to a follow-on spec. This is a significant
gap: without adjudication rules, the slashing mechanism cannot be implemented.

### 10.5 Multi-resource capacity attacks

A provider may have genuine capacity in one resource type but fabricated
capacity in another. The current spec requires a VCA credential for all
submissions but does not require the credential to be resource-type-specific.
Resource-type specialization of VCA credentials may be needed.

---

## 11. State Machine Sketch

```
CapacityReportState_e = {
    evidence_set:    Map<ResourceType, Vec<CapacityEvidence>>,
    evidence_root:   Map<ResourceType, [u8; 32]>,   // committed at ECW_close
    capacity_report: Option<CapacityReport_e>,
    phase:           CapacityPhase,
}

CapacityPhase = 
    | COLLECTING   // ECW open; evidence submissions accepted
    | FINALIZING   // ECW closed; aggregation in progress
    | FINALIZED    // CapacityReport countersigned and on-chain
    | CARRY_FORWARD // No valid report; using capacity_{e-1}

Transitions:
    COLLECTING → FINALIZING     (at ECW_close_e)
    FINALIZING → FINALIZED      (on CapacityReport_e valid countersignature)
    FINALIZING → CARRY_FORWARD  (at REPORT_DEADLINE_e if no FINALIZED)
    FINALIZED  → COLLECTING     (at epoch_boundary_e, for next epoch)
    CARRY_FORWARD → COLLECTING  (at epoch_boundary_e)
```

---

## 12. Test Scenarios

Before implementing this sub-protocol in Rust, the following scenarios MUST
be tested against the spec (extending the CIRFI v3 test vectors):

| # | Scenario | Expected outcome |
|---|----------|-----------------|
| T1 | All providers honest, quorum met | CapacityReport finalized, capacity_e = median |
| T2 | 1 Byzantine provider (of 5), inflated claim | Median unaffected; report valid |
| T3 | 2 Byzantine providers (of 5), inflated claim | Median shifted but within honest range; report valid |
| T4 | Majority Byzantine (3 of 5) | Median dominated by adversary; attack succeeds — motivates MIN_PROVIDER_QUORUM > 3 |
| T5 | Zero submissions | CARRY_FORWARD; capacity_e = capacity_{e-1} |
| T6 | Submissions below MIN_PROVIDER_QUORUM | CARRY_FORWARD |
| T7 | Large provider exits (50% capacity drop) | CAPACITY_STEP_WARN event; carry-forward or new report; Availability Guard fires if CR drops below CR_halt |
| T8 | Duplicate submission from same provider | Second submission rejected; first counted |
| T9 | Submission after ECW_close | Rejected deterministically by all validators |
| T10 | Report not countersigned by deadline | CARRY_FORWARD; no halt |
| T11 | Successful ChallengeCapacityEvidence | Slash applied; capacity_e_r recomputed |

---

*CapacityReport-SubProtocol-v0.1 — closes CIRFI-Protocol-Spec §8.1 Open Question*  
*Next: implement CapacityEvidence_v0 state machine in Chain Forge; v0.2 adds stake-weighted aggregation and v1 proof types*
