# QRC Resource Economy — Protocol Specification v0.1

**Status:** Draft — normative  
**Date:** 2026-10-03  
**Supersedes:** Section 6.10 of QCB-Chain-Whitepaper-v2.md (explanatory)  
**Evidence base:** qrc_stress_test_v3.py (commit bb3d2d4), 15-scenario sweep + CR floor sweep + recovery test  

---

This document is the normative specification for the QRC Resource Economy protocol layer. It defines the state machine, transaction types, epoch boundary operations, invariants, and consensus rules that a correct Rust implementation must satisfy. It is not an explanation of the economic rationale — that lives in the whitepaper. Every statement here is either a definition, a MUST constraint, or a SHOULD recommendation. Simulation results are cited as the empirical basis for parameter choices, not as proofs of safety.

---

## 1. Notation and Fixed-Point Representation

All arithmetic in consensus-critical operations MUST use integer fixed-point arithmetic. Floating-point is prohibited in any computation whose result determines state validity or transaction acceptance.

**Precision constant:** `D = 1_000_000` (10^6)

All quantities that conceptually range over [0, ∞) are represented as non-negative integers in their smallest unit:

| Symbol | Unit | Meaning |
|--------|------|---------|
| `capacity` | capacity-units (CU) | 1 CU = 1/D of one QRC-equivalent resource unit |
| `outstanding` | uqrc | 1 uqrc = 10^-6 QRC |
| `qcb_burned` | uqcb | 1 uqcb = 10^-6 QCB |
| `conversion_volume` | uqcb | cumulative QCB burned this epoch |
| `epoch_cap` | uqcb | maximum QCB convertible per epoch |

**Coverage ratio** is derived, never stored:

```
CR_e  =  (capacity_e * D) / outstanding_e       [integer division]
```

**Coverage invariant** (integer form, avoids division):

```
outstanding_e * CR_min_fixed <= capacity_e * D
```

where `CR_min_fixed = CR_min * D` expressed as an integer (e.g., CR_min = 0.75 → CR_min_fixed = 750_000).

**Why derived, not stored:** storing CR as a third field creates a consistency hazard — three values that can disagree if any one update is applied without the others. Storing only `capacity` and `outstanding` and deriving CR at check time eliminates this class of state corruption.

---

## 2. Protocol State

The QRC economic state for epoch `e` is the tuple:

```
State_e = (
    capacity_e,          // u128: attested resource capacity in CU
    outstanding_e,       // u128: outstanding QRC liability in uqrc
    conversion_volume_e, // u128: QCB converted to QRC this epoch, in uqcb
    earn_volume_e,       // u128: QRC issued via contribution this epoch, in uqrc
    consumption_volume_e,// u128: QRC consumed this epoch, in uqrc
    burn_volume_e,       // u128: QRC permanently destroyed this epoch, in uqrc
    mode_e,              // MintMode: NORMAL | HALTED
    epoch_cap_e,         // u128: L_e for this epoch, in uqcb
    ema_utilization_e,   // u128: smoothed utilization in fixed-point [0, D]
)
```

`mode_e` governs which issuance paths are open:

| `mode_e` | `QcbToQrc` | `ContributionToQrc` |
|----------|--------------|----------------------|
| `NORMAL` | allowed | allowed |
| `HALTED` | rejected | rejected |

**Note on the simulation's RESTRICTED state:** The v3 simulation distinguished three states (NORMAL / RESTRICTED / HALTED) where RESTRICTED suspended conversion but allowed contribution earn. This specification collapses to two states (NORMAL / HALTED) for the initial implementation, because the two-tier hysteresis is fully captured by the (CR_halt, CR_resume) pair without requiring a third mode. The behavior is equivalent: when CR_halt ≤ CR < CR_resume, the system stays HALTED (contribution earn suspended) even though capacity has partially recovered. This is the conservative choice. If simulation evidence supports reopening the contribution path before full CR_resume, a three-state mode can be added in a later revision without changing the invariant.

---

## 3. Capacity Report

The authoritative source of `capacity_e` is a **CapacityReport** finalized at each epoch boundary.

```
CapacityReport = {
    epoch:        u64,
    resource:     ResourceType,
    capacity:     u128,      // in CU for this resource type
    evidence:     Vec<CapacityEvidence>,
    contributors: Vec<ContributorId>,
    attestation:  ValidatorSignatureSet,
}
```

**ResourceType** covers the types the simulation modeled:

```rust
enum ResourceType {
    Compute,
    Storage,
    Bandwidth,
    ZkProving,
    Oracle,
    AiInference,
}
```

**Total epoch capacity** is the weighted sum across resource types:

```
capacity_e = sum_r( weight_r * capacity_e_r )
```

where `weight_r` is a governance-adjustable per-resource weight and `capacity_e_r` is the attested capacity for resource type `r`. Weights are expressed in fixed-point with denominator D and MUST sum to D.

**CapacityEvidence** is intentionally left open in v0.1. The following constraints are normative:

- Evidence MUST be submitted by an entity with a valid VCA (Verifiable Contribution Attestation) credential.
- A CapacityReport is valid only if its `attestation` carries signatures from a quorum of validators (threshold: > 2/3 of current validator set by weight).
- A CapacityReport that is not finalized by the epoch boundary MUST cause `capacity_e` to carry over from `capacity_{e-1}`. This is safe because a stale (conservative) capacity estimate causes CR to be lower, which is the safe direction — it risks triggering the circuit breaker earlier rather than later.
- **The capacity measurement adversarial model is an open question (see Section 8).** Providers can misreport capacity. VCA attestation is a necessary but not sufficient condition for an adversary-resistant capacity measurement. This specification names the gap; it does not close it.

---

## 4. Epoch Boundary Transition

The epoch boundary transition is strictly ordered. No QRC issuance or conversion transactions are processed while the transition is in progress. The transition MUST be deterministic across all validators — identical inputs MUST produce identical outputs.

**Epoch boundary sequence for epoch `e → e+1`:**

```
1.  FINALIZE_ACCOUNTING
    - Close consumption_volume_e and burn_volume_e
    - Apply burn: outstanding_{e+1} = outstanding_e - burn_volume_e

2.  ACCEPT_CAPACITY_REPORT
    - Finalize CapacityReport for epoch e+1
    - If no valid CapacityReport: capacity_{e+1} = capacity_e (carry-forward)

3.  COMPUTE_OUTSTANDING
    - outstanding_{e+1} (from step 1) is now finalized

4.  EVALUATE_COVERAGE
    - Derive CR_e using finalized capacity_{e+1} and outstanding_{e+1}
    - CR comparison uses integer form: no division performed here
      cr_check = capacity_{e+1} * D   vs   outstanding_{e+1} * CR_halt_fixed
      cr_resume_check = capacity_{e+1} * D  vs  outstanding_{e+1} * CR_resume_fixed

5.  EVALUATE_CIRCUIT_BREAKER
    mode_{e+1} = match (cr_check, cr_resume_check, mode_e) {
        // CR < CR_halt: always HALTED
        cr_check < outstanding_{e+1} * CR_halt_fixed  =>  HALTED,
        // CR >= CR_resume: always NORMAL
        cr_resume_check >= outstanding_{e+1} * CR_resume_fixed  =>  NORMAL,
        // CR_halt <= CR < CR_resume: hysteresis — keep current mode
        _  =>  mode_e,
    }

6.  COMPUTE_EPOCH_CAP
    epoch_cap_{e+1} = beta_cap * capacity_{e+1} + lambda_cap * demand_proxy_{e+1}
    (adaptive cap; see Section 5.2)

7.  RESET_EPOCH_COUNTERS
    conversion_volume_{e+1} = 0
    earn_volume_{e+1} = 0
    consumption_volume_{e+1} = 0

8.  UPDATE_EMA_UTILIZATION
    ema_utilization_{e+1} =
        alpha * utilization_e + (1 - alpha) * ema_utilization_e
    (utilization_e is total QRC consumed / total resource capacity this epoch)

9.  OPEN_EPOCH_{e+1}
    - State_{e+1} is now complete and valid
    - Issuance transactions for epoch e+1 may now be processed
```

**Key timing constraint:** A `QcbToQrc` or `ContributionToQrc` transaction submitted during epoch `e` uses **epoch `e`'s already-finalized parameters** (mode_e, epoch_cap_e, rate_e). It MUST NOT be held in a queue and re-evaluated under epoch `e+1` parameters unless it was submitted after the epoch boundary and therefore belongs to `e+1`.

**Rejected transactions are rejected, not queued:** A `QcbToQrc` transaction that arrives when `conversion_volume_e >= epoch_cap_e` MUST be rejected with a definitive error. It MUST NOT be queued for execution in the next epoch. The submitter resubmits if they wish to try again.

---

## 5. Transaction Types

### 5.1 `QcbToQrc` (QCB Conversion)

Burns QCB and mints QRC at the current epoch conversion rate. This is the discretionary issuance path.

**Authorization requirements (all MUST hold; any failure → reject):**

```
1. valid_signature(tx.sender)
2. balance_qcb(tx.sender) >= tx.qcb_amount
3. mode_e == NORMAL
4. conversion_volume_e + tx.qcb_amount <= epoch_cap_e
5. tx.qcb_amount >= MIN_CONVERSION   // dust prevention, governance-set
6. qrc_out = floor(tx.qcb_amount * rate_e / D)
7. (outstanding_e + qrc_out) * CR_min_fixed <= capacity_e * D  // coverage check
```

**State updates on acceptance:**

```
qcb_supply         -= tx.qcb_amount
outstanding_e      += qrc_out
qrc_balance(tx.sender) += qrc_out
conversion_volume_e += tx.qcb_amount
```

**Conversion rate:**

```
rate_e = clamp(
    R0 * (U_star_fixed / ema_utilization_e)^gamma / D^(gamma-1),
    R_min_fixed,
    R_max_fixed
)
```

All values fixed-point with denominator D. Exponentiation uses integer approximation (see Section 6).

### 5.2 `ContributionToQrc` (Contribution Earn)

Issues QRC to a provider in proportion to their attested contribution. This is the non-discretionary issuance path — it compensates work already done.

**Authorization requirements (all MUST hold; any failure → reject):**

```
1. mode_e == NORMAL    // HALTED blocks both paths; see Section 2 note
2. valid_vca_proof(tx.contribution_proof, tx.epoch)
3. tx.epoch == current_epoch_e
4. !already_claimed(tx.contributor_id, tx.epoch)
5. qrc_out = compute_earn(tx.contribution_proof)
   // earn formula: governance-set, VCA-measured, per-resource-type
6. (outstanding_e + qrc_out) * CR_min_fixed <= capacity_e * D  // coverage check
```

**State updates on acceptance:**

```
outstanding_e      += qrc_out
qrc_balance(tx.contributor) += qrc_out
earn_volume_e      += qrc_out
mark_claimed(tx.contributor_id, tx.epoch)
```

**Separation of attack surfaces:** `QcbToQrc` attacks come from the conversion path (dump QCB at low utilization; epoch cap is the defense). `ContributionToQrc` attacks come from the VCA path (Sybil farming; VCA attestation and the self-defeating burn dynamic are the defenses). These must remain separate transaction types so their authorization checks and rate limits can evolve independently.

### 5.3 `ConsumeQrc` (Resource Consumption)

Burns QRC to claim resource services from providers.

**Authorization requirements:**

```
1. valid_signature(tx.sender)
2. qrc_balance(tx.sender) >= tx.qrc_amount
3. valid_resource_request(tx.resource_type, tx.amount)
```

**State updates on acceptance:**

```
burned = floor(tx.qrc_amount * p_burn_fixed / D)
paid_to_provider = tx.qrc_amount - burned

qrc_balance(tx.sender)   -= tx.qrc_amount
outstanding_e              -= burned          // permanent destruction
burn_volume_e              += burned
consumption_volume_e       += tx.qrc_amount
// provider payment routing: separate settlement
```

**Note:** `ConsumeQrc` MUST NOT be blocked by `mode_e`. Consumption reduces `outstanding`, which improves CR. Blocking consumption during HALTED would prevent the natural recovery path.

---

## 6. Protocol Parameters

All parameters are governance-adjustable via the ordinary $QRC governance process (Whitepaper §6.6) unless marked [CONSTITUTIONAL].

| Parameter | Symbol | Starting value | Unit | Notes |
|-----------|--------|---------------|------|-------|
| Precision constant | D | 1_000_000 | - | [CONSTITUTIONAL — changing D requires all stored values to be migrated] |
| CR halt threshold | CR_halt_fixed | 750_000 | fixed-point, denom D | Reject: 1_000_000 (see §6.1) |
| CR resume threshold | CR_resume_fixed | 1_000_000 | fixed-point, denom D | Must be > CR_halt_fixed |
| Min coverage ratio | CR_min_fixed | 750_000 | fixed-point, denom D | Consensus-rejection floor |
| Max conversion rate | R_max_fixed | 2_000_000 | fixed-point, denom D | = 2.0 × D |
| Min conversion rate | R_min_fixed | 500_000 | fixed-point, denom D | = 0.5 × D |
| Rate sensitivity | gamma | 3/2 | rational | Use integer arithmetic: (U*/U)^(3/2) |
| EMA smoothing | alpha_fixed | 100_000 | fixed-point, denom D | = 0.10 × D |
| Target utilization | U_star_fixed | 700_000 | fixed-point, denom D | = 0.70 × D |
| Adaptive cap beta | beta_cap_fixed | 1_000 | fixed-point, denom D | = 0.001 × D |
| Adaptive cap lambda | lambda_cap_fixed | 500 | fixed-point, denom D | = 0.0005 × D |
| Consumption burn rate | p_burn_fixed | 250_000 | fixed-point, denom D | = 0.25 × D |
| Provider share | p_prov_fixed | 600_000 | fixed-point, denom D | = 0.60 × D |
| Reserve share | p_res_fixed | 150_000 | fixed-point, denom D | = 0.15 × D |
| Dust minimum | MIN_CONVERSION | TBD | uqcb | Open question |

**Derivation of starting values:** All values above are simulation-derived from the v3 stress test (commit bb3d2d4). They are starting values for implementation and further testing, not globally optimal constants. The column "Starting value" means: use this until governance has real on-chain data to justify a revision.

### 6.1 Why CR_halt = 1.00 was rejected

The recovery test (T=400, capacity collapses to 20% of baseline at epoch 100, recovers to 100% by epoch 300) produced the following results:

| CR_halt / CR_resume | Minting resumes at |
|--------------------|--------------------|
| 0.50 / 0.75 | epoch 234 |
| 0.75 / 1.00 | epoch 262 |
| 1.00 / 1.25 | never (within T=400) |

CR_halt = 1.00 is rejected because the system cannot recover from realistic capacity-shock scenarios within a reasonable time horizon. CR_halt = 0.75 provides adequate solvency protection while preserving the ability to resume minting after capacity recovers.

### 6.2 Exponentiation in fixed-point

The rate formula requires `(U_star / U_bar)^1.5`. In integer fixed-point:

```
// gamma = 3/2: compute x^(3/2) = x * sqrt(x)
// where x = (U_star_fixed * D) / ema_utilization_e  (ratio in fixed-point)
// Use integer square root; result is approximate but deterministic

fn rate_fixed(U_star: u128, U_bar: u128, R0: u128, D: u128) -> u128 {
    let ratio = U_star.saturating_mul(D) / U_bar.max(1);
    let ratio_sq = ratio.saturating_mul(ratio) / D;
    let ratio_32 = isqrt(ratio_sq.saturating_mul(D));  // fixed-point sqrt
    let raw = R0.saturating_mul(ratio_32) / D;
    raw.clamp(R_min_fixed, R_max_fixed)
}
```

The specific integer square root algorithm is an implementation decision. It MUST be identical across all validators (same algorithm, same rounding behavior). This MUST be specified in the Rust implementation and tested with known inputs before deployment.

---

## 7. Invariants and Consensus Validity

### 7.1 State Validity Invariant

At every epoch boundary, the following MUST hold:

```
outstanding_e * CR_min_fixed <= capacity_e * D
```

If this is false after applying the epoch boundary transition, the epoch boundary is invalid and MUST be rejected by all correct validators.

### 7.2 Transaction Validity Rule

Before any QRC-minting transaction is accepted, the node MUST verify:

```
(outstanding_e + qrc_out) * CR_min_fixed <= capacity_e * D
```

If false, the transaction MUST be rejected regardless of all other authorization conditions. This check is the ultimate guard — it fires even when the circuit breaker is NORMAL and the epoch cap has not been reached.

**Three enforcement layers (defense in depth):**

```
Layer 1 — Availability Guard (§7.3)
  Condition:  CR < CR_halt  (i.e., outstanding * CR_halt_fixed > capacity * D)
  Action:     mode_e = HALTED; all minting transactions rejected at dispatch
  Scope:      issuance-wide; coarse fast-path rejection

Layer 2 — Transaction Validity Rule (this section)
  Condition:  (outstanding + qrc_out) * CR_min_fixed > capacity * D
  Action:     individual mint rejected at state-update time
  Scope:      per-transaction; fires even when mode_e == NORMAL
  Catches:    any mint that would individually violate the invariant
              even when aggregate CR is above CR_halt

Layer 3 — State Validity Invariant (§7.1)
  Condition:  outstanding_e * CR_min_fixed > capacity_e * D
  Action:     entire epoch state rejected by validators
  Scope:      epoch-level; the consensus-enforced floor
  Catches:    any epoch state that violated the invariant regardless of
              how it got there (implementation bug, replay, corruption)
```

This vocabulary — Availability Guard, Transaction Validity Rule, State Validity Invariant — SHOULD be used consistently in the Rust implementation, code review, and security audit documentation so that each enforcement point is independently identifiable and testable.

### 7.3 Availability Guard

The Availability Guard is set at the epoch boundary (Step 5 of §4) and determines `mode_{e+1}`:

```
if outstanding_{e+1} * CR_halt_fixed > capacity_{e+1} * D:
    mode_{e+1} = HALTED
elif capacity_{e+1} * D >= outstanding_{e+1} * CR_resume_fixed:
    mode_{e+1} = NORMAL
else:
    mode_{e+1} = mode_e          // hysteresis: preserve current mode
```

When `mode_e == HALTED`, the node MUST reject all `QcbToQrc` and `ContributionToQrc` transactions at dispatch, before reaching the Transaction Validity Rule check. This is a fast-path — it avoids performing the per-mint coverage calculation for every rejected transaction during a halt period.

The Availability Guard does NOT halt `ConsumeQrc` transactions. Consumption reduces `outstanding`, which improves CR. Blocking consumption during HALTED would extend the halt by preventing the natural recovery path.

### 7.4 Epoch counter monotonicity

```
epoch_{e+1} == epoch_e + 1
```

No epoch may be skipped. Epoch numbering is global and chain-ordered.

### 7.5 Conversion counter reset

```
conversion_volume_e == 0  at the start of every epoch
```

The counter MUST be reset before any transactions in the new epoch are processed (Step 7 of the epoch boundary sequence).

### 7.6 HALTED semantics

When `mode_e == HALTED`:

- `QcbToQrc` transactions MUST be rejected (Availability Guard)
- `ContributionToQrc` transactions MUST be rejected (Availability Guard)
- `ConsumeQrc` transactions MUST NOT be affected
- Transfers of existing QRC balances MUST NOT be affected
- Consensus participation MUST NOT be affected
- Validator rewards MUST NOT be affected

**The Availability Guard is issuance-local, not chain-global.**

---

## 8. Open Questions

These questions MUST be resolved before the Rust implementation can be considered complete. They are listed in approximate dependency order.

### 8.1 Capacity evidence adversarial model (CRITICAL — prerequisite for BFT correctness)

This is the most important unresolved question in the specification. Its resolution is a prerequisite for the QRC economic state to participate in Byzantine fault tolerance — not just for economic accuracy, but for consensus correctness.

**Why this is consensus-critical, not just economic:**

Capacity has been tied directly into the State Validity Invariant:

```
outstanding_e * CR_min_fixed <= capacity_e * D
```

This means `capacity_e` is no longer merely an economic parameter. It is consensus-critical state. If validator A sees `capacity_e = 10,000` while validator B sees `capacity_e = 6,000`, they reach different conclusions about whether the same `QcbToQrc` transaction is valid. That is a potential consensus fork, not merely an inaccurate price. The capacity evidence model must therefore provide the same determinism guarantee as any other consensus-critical input.

**The required separation of claims:**

Three distinct claims must not be conflated:

```
VCA verifies contribution
    ↓ (necessary but not sufficient for)
CapacityEvidence verifies resource availability
    ↓ (aggregated and signed by)
Consensus verifies the resulting CapacityReport
```

VCA proves that a contributor performed work. CapacityEvidence proves that resources are available to service future claims. These are different claims: a provider who did work in the past may not have capacity available now. Consensus then establishes that the CapacityReport derived from that evidence is the canonical value all validators agree on. Each arrow in this chain requires its own trust model.

**The ten questions this model must answer:**

1. **What constitutes CapacityEvidence?**
   For each ResourceType, what is the minimal proof that a claimed capacity unit actually exists? For compute: a benchmark result with a signed nonce? For storage: a proof-of-space challenge-response? For ZK proving: a timing attestation on a canonical circuit? Evidence requirements will differ per resource type and must be specified individually.

2. **Who can submit CapacityEvidence?**
   Must a submitter hold a VCA credential? Must they be a registered provider with staked collateral? The submission identity determines the adversarial surface — a permissionless submission model allows Sybil providers; a staked-collateral model introduces capital requirements that may exclude small providers.

3. **How is contribution tied to the claimed resource?**
   A provider who earned QRC through contribution (ContributionToQrc) has demonstrated past work. Does that work automatically constitute CapacityEvidence? The safer model is: past work proves past contribution; present capacity requires a present proof. The spec should not assume they're the same.

4. **How are multiple reports aggregated?**
   If N providers each submit a CapacityReport for the same resource type, what is `capacity_e_r`? Options: sum (optimistic — assumes all reports are honest), median (Byzantine-robust — a minority of dishonest reporters cannot dominate), weighted average (stake-weighted — aligns reporting honesty with economic stake). The choice determines the adversarial tolerance of the aggregation.

5. **What happens when reports conflict?**
   If provider A claims 10,000 CU of compute and provider B disputes it, what is the resolution mechanism? Is there a challenge period before `capacity_e` is finalized? Who adjudicates? What evidence is required for a successful challenge? The spec currently states capacity carries over from the previous epoch if no valid report is received — this needs a conflict case too.

6. **What quorum is required?**
   The spec currently states a CapacityReport requires `> 2/3` of validators by weight to countersign. This is the standard BFT threshold and is correct for validator agreement, but it does not answer: what fraction of the registered provider set must contribute evidence for the report to be valid? A CapacityReport signed by 2/3 of validators but based on evidence from a single provider is formally valid but economically dangerous.

7. **What prevents a provider from claiming nonexistent capacity?**
   The Sybil-capacity attack: create many provider identities, each claiming moderate capacity, aggregate to large apparent `capacity_e`, enabling large `outstanding` without real resources. Defenses include: staked collateral (slashed if capacity is challenged and found false), challenge-response proofs that cannot be faked without real resources, and rate limits on capacity claims per identity. This attack vector is not addressed in the current spec.

8. **What happens when capacity disappears between reports?**
   Provider exodus (Scenario 3 in the v3 simulation) caused CR → 0.027 despite the circuit breaker. The simulation modeled this as a smooth decline. The real risk is a step discontinuity: a large provider exits between epoch boundaries, `capacity_{e+1}` drops sharply, and the Availability Guard fires before any mitigation is possible. The spec should define: what is the maximum permitted single-epoch capacity change? Is there a smoothing mechanism? Or is the circuit breaker the only protection?

9. **How do capacity changes become deterministic across validators?**
   Capacity evidence may be submitted during an epoch from multiple sources at different times. Validators must agree on which evidence is included in `capacity_e`. The epoch boundary sequence (§4, Step 2) specifies a deadline: evidence not finalized by the boundary is excluded. But the mechanism for achieving agreement on the evidence set itself — before it is aggregated — must be specified. This is likely a separate consensus sub-protocol (evidence collection → evidence set finalization → CapacityReport aggregation → validator countersignature).

10. **What cryptographic evidence survives a dispute?**
    If a provider later claims they were wrongly excluded from a CapacityReport, or a validator claims it signed a CapacityReport it never received, what on-chain record resolves the dispute? Evidence commitments should be anchored on-chain before the epoch boundary so that post-hoc disputes have a ground truth to appeal to.

**Working recommendation for the next engineering phase:**

Before implementing `QcbToQrc` or `ContributionToQrc` in Chain Forge, specify the capacity evidence model as a separate sub-protocol with its own state machine, transaction types, and consensus rules. Treat it as a peer to the QRC issuance protocol, not as a detail inside it. The QRC invariant is only as strong as the evidence model that feeds `capacity_e`.

Until this is resolved, `capacity_e` is a trust assumption with a validator-signature wrapper, not a protocol guarantee. The invariant holds under honest validators; it does not hold under a Byzantine-validator + malicious-provider coalition.

**Minimum viable evidence model for initial implementation:**

A simplified model sufficient to start testing the state machine without closing all ten questions:

```
CapacityEvidence_v0 = {
    provider_id:   ValidVCA credential (existing mechanism)
    resource_type: ResourceType
    capacity_claim: u128 (in CU)
    challenge_nonce: [u8; 32]  // signed by provider, prevents replay
    validator_set_epoch: u64   // evidence is epoch-scoped
}

CapacityReport_v0 aggregation:
    capacity_e_r = median( capacity_claim_i for all valid evidence_i )
    valid = len(evidence) >= MIN_PROVIDER_QUORUM
             && validator_signatures >= 2/3 of validator set
```

This is Byzantine-resistant in aggregation (median), requires VCA credentials (existing protection against anonymous providers), but does not answer questions 7–10. It is labeled v0 to signal that it is a starting point for testing, not the final adversarial model.

### 8.2 CU↔uqrc unit alignment

The specification states `capacity_e * D` and `outstanding_e * CR_min_fixed` must be comparable. This requires that 1 QRC-equivalent CU represents the same "amount of resource" as 1 uqrc represents "outstanding claims." The exact mapping — how many CU is one QRC "worth" at genesis — must be defined before the protocol can compute a meaningful CR.

Concretely: if capacity_e = 1_000_000_000_000 CU and outstanding_e = 1_000_000_000_000 uqrc, CR = 1.0. That only means something if the units are commensurable. The genesis calibration of CU/uqrc is an economic decision, not just an engineering one.

### 8.3 Multi-resource capacity aggregation

The per-resource weights `weight_r` determine how compute capacity, storage capacity, and ZK proving capacity are combined into a single `capacity_e` scalar. Wrong weights allow a provider to shift the network's apparent capacity by adding cheap resources (bandwidth) while real scarce resources (ZK proving) are depleted.

The weight-setting mechanism, and who can propose weight changes, needs specification before multi-resource capacity is implemented.

### 8.4 Contribution earn formula

`compute_earn(contribution_proof)` is referenced in §5.2 but not specified. The formula maps a VCA-attested contribution measurement to a uqrc amount. This formula determines:
- How much QRC providers earn per unit of real work
- Whether the earn rate can be gamed (over-reporting small contributions)
- The equilibrium between total earn issuance and consumption burn

The simulation used a simplified model. The real formula needs to be defined per ResourceType and tested against the sybil-farming scenario before implementation.

### 8.5 Dust minimum `MIN_CONVERSION`

The minimum QCB amount for a `QcbToQrc` transaction needs to be set. Too low: spam; too high: excludes small conversions. Depends on the final QCB/QRC exchange rate regime.

### 8.6 Demand proxy for adaptive epoch cap

The adaptive cap formula uses `demand_proxy_e`:

```
epoch_cap_e = beta_cap * capacity_e + lambda_cap * demand_proxy_e
```

The simulation used `consumption_volume_e` as the demand proxy. On-chain, this creates a one-epoch lag (you're using last epoch's consumption to set this epoch's cap). Whether a one-epoch lag is acceptable, or whether the demand proxy needs to be forward-estimated, is unresolved.

### 8.7 Reserve pool routing

`ConsumeQrc` splits the consumed QRC into `burned` (p_burn) and `paid_to_provider` (p_prov). The remaining fraction (p_res) goes to a reserve pool. The reserve pool's governance, withdrawal conditions, and whether the reserve accumulates in QRC or is converted to QCB, are not specified here.

---

## 9. Test Vectors

The 15 simulation scenarios in `qrc_stress_test_v3.py` (commit bb3d2d4) are the canonical economic test vectors. The Rust implementation MUST produce state transitions consistent with the simulation's outputs for each scenario, modulo fixed-point rounding differences.

The following scenarios are the minimum required for implementation sign-off:

| Scenario | What it validates |
|----------|------------------|
| Sc.1 Nominal | Correct base-case state progression |
| Sc.5 Adversarial dump + CB | Epoch cap blocks conversion; CR remains ≥ 0.99 |
| Sc.6 Adversarial dump, no CB | Epoch cap alone contains CR; supply +5.9% acceptable |
| Sc.7 Sybil farming | Self-defeating at high U; CR remains ≥ 0.99 |
| Sc.3 Provider exodus | Circuit breaker fires; minting suspends; CR collapse documented |
| Sc.4 Crash + recovery | CR recovers to > 0.50; minting resumes after recovery |
| Recovery test (CR_halt=0.75) | Minting resumes by epoch 262 after 20% capacity floor |
| Recovery test (CR_halt=1.00) | Minting does NOT resume within 400 epochs — rejected threshold |

Zero invariant violations (no tick where minting was allowed while CR < 0.10) MUST hold across all scenarios.

---

## 10. Formal State Machine Summary

The full QRC resource economy is the state machine:

```
S_{e+1} = T(S_e, I_e, R_e)
```

where:

- `S_e` = `State_e` as defined in Section 2
- `I_e` = the set of finalized transactions in epoch `e`
- `R_e` = the finalized `CapacityReport` for epoch `e`
- `T` = the epoch boundary transition defined in Section 4, applied to `S_e` after processing all transactions in `I_e`

**The core safety property:**

```
∀ e:  outstanding_e * CR_min_fixed  ≤  capacity_e * D
```

This is the property that the simulation verified holds across all 15 scenarios (zero violations). The Rust implementation MUST enforce it as a consensus rule, not merely as a best-effort check.

**The design intent:** `T` is deterministic. Given identical `(S_e, I_e, R_e)`, every correct validator produces identical `S_{e+1}`. The capacity evidence model (Open Question 8.1) is where non-determinism can enter: if validators disagree about `R_e`, they disagree about `S_{e+1}`. Closing Open Question 8.1 is therefore a prerequisite for Byzantine fault tolerance of the capacity measurement itself.

---

*This specification is versioned. Changes to any normative MUST constraint, parameter starting value, or open question resolution require a version bump and a commit to the chain-forge-engine repository.*
