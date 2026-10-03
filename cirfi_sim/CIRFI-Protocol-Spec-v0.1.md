# CIRFI Resource Economy — Protocol Specification v0.1

**Status:** Draft — normative  
**Date:** 2026-10-03  
**Supersedes:** Section 6.10 of QCB-Chain-Whitepaper-v2.md (explanatory)  
**Evidence base:** cirfi_stress_test_v3.py (commit bb3d2d4), 15-scenario sweep + CR floor sweep + recovery test  

---

This document is the normative specification for the CIRFI Resource Economy protocol layer. It defines the state machine, transaction types, epoch boundary operations, invariants, and consensus rules that a correct Rust implementation must satisfy. It is not an explanation of the economic rationale — that lives in the whitepaper. Every statement here is either a definition, a MUST constraint, or a SHOULD recommendation. Simulation results are cited as the empirical basis for parameter choices, not as proofs of safety.

---

## 1. Notation and Fixed-Point Representation

All arithmetic in consensus-critical operations MUST use integer fixed-point arithmetic. Floating-point is prohibited in any computation whose result determines state validity or transaction acceptance.

**Precision constant:** `D = 1_000_000` (10^6)

All quantities that conceptually range over [0, ∞) are represented as non-negative integers in their smallest unit:

| Symbol | Unit | Meaning |
|--------|------|---------|
| `capacity` | capacity-units (CU) | 1 CU = 1/D of one CIRFI-equivalent resource unit |
| `outstanding` | ucirfi | 1 ucirfi = 10^-6 CIRFI |
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

The CIRFI economic state for epoch `e` is the tuple:

```
State_e = (
    capacity_e,          // u128: attested resource capacity in CU
    outstanding_e,       // u128: outstanding CIRFI liability in ucirfi
    conversion_volume_e, // u128: QCB converted to CIRFI this epoch, in uqcb
    earn_volume_e,       // u128: CIRFI issued via contribution this epoch, in ucirfi
    consumption_volume_e,// u128: CIRFI consumed this epoch, in ucirfi
    burn_volume_e,       // u128: CIRFI permanently destroyed this epoch, in ucirfi
    mode_e,              // MintMode: NORMAL | HALTED
    epoch_cap_e,         // u128: L_e for this epoch, in uqcb
    ema_utilization_e,   // u128: smoothed utilization in fixed-point [0, D]
)
```

`mode_e` governs which issuance paths are open:

| `mode_e` | `QcbToCirfi` | `ContributionToCirfi` |
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

The epoch boundary transition is strictly ordered. No CIRFI issuance or conversion transactions are processed while the transition is in progress. The transition MUST be deterministic across all validators — identical inputs MUST produce identical outputs.

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
    (utilization_e is total CIRFI consumed / total resource capacity this epoch)

9.  OPEN_EPOCH_{e+1}
    - State_{e+1} is now complete and valid
    - Issuance transactions for epoch e+1 may now be processed
```

**Key timing constraint:** A `QcbToCirfi` or `ContributionToCirfi` transaction submitted during epoch `e` uses **epoch `e`'s already-finalized parameters** (mode_e, epoch_cap_e, rate_e). It MUST NOT be held in a queue and re-evaluated under epoch `e+1` parameters unless it was submitted after the epoch boundary and therefore belongs to `e+1`.

**Rejected transactions are rejected, not queued:** A `QcbToCirfi` transaction that arrives when `conversion_volume_e >= epoch_cap_e` MUST be rejected with a definitive error. It MUST NOT be queued for execution in the next epoch. The submitter resubmits if they wish to try again.

---

## 5. Transaction Types

### 5.1 `QcbToCirfi` (QCB Conversion)

Burns QCB and mints CIRFI at the current epoch conversion rate. This is the discretionary issuance path.

**Authorization requirements (all MUST hold; any failure → reject):**

```
1. valid_signature(tx.sender)
2. balance_qcb(tx.sender) >= tx.qcb_amount
3. mode_e == NORMAL
4. conversion_volume_e + tx.qcb_amount <= epoch_cap_e
5. tx.qcb_amount >= MIN_CONVERSION   // dust prevention, governance-set
6. cirfi_out = floor(tx.qcb_amount * rate_e / D)
7. (outstanding_e + cirfi_out) * CR_min_fixed <= capacity_e * D  // coverage check
```

**State updates on acceptance:**

```
qcb_supply         -= tx.qcb_amount
outstanding_e      += cirfi_out
cirfi_balance(tx.sender) += cirfi_out
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

### 5.2 `ContributionToCirfi` (Contribution Earn)

Issues CIRFI to a provider in proportion to their attested contribution. This is the non-discretionary issuance path — it compensates work already done.

**Authorization requirements (all MUST hold; any failure → reject):**

```
1. mode_e == NORMAL    // HALTED blocks both paths; see Section 2 note
2. valid_vca_proof(tx.contribution_proof, tx.epoch)
3. tx.epoch == current_epoch_e
4. !already_claimed(tx.contributor_id, tx.epoch)
5. cirfi_out = compute_earn(tx.contribution_proof)
   // earn formula: governance-set, VCA-measured, per-resource-type
6. (outstanding_e + cirfi_out) * CR_min_fixed <= capacity_e * D  // coverage check
```

**State updates on acceptance:**

```
outstanding_e      += cirfi_out
cirfi_balance(tx.contributor) += cirfi_out
earn_volume_e      += cirfi_out
mark_claimed(tx.contributor_id, tx.epoch)
```

**Separation of attack surfaces:** `QcbToCirfi` attacks come from the conversion path (dump QCB at low utilization; epoch cap is the defense). `ContributionToCirfi` attacks come from the VCA path (Sybil farming; VCA attestation and the self-defeating burn dynamic are the defenses). These must remain separate transaction types so their authorization checks and rate limits can evolve independently.

### 5.3 `ConsumeCirfi` (Resource Consumption)

Burns CIRFI to claim resource services from providers.

**Authorization requirements:**

```
1. valid_signature(tx.sender)
2. cirfi_balance(tx.sender) >= tx.cirfi_amount
3. valid_resource_request(tx.resource_type, tx.amount)
```

**State updates on acceptance:**

```
burned = floor(tx.cirfi_amount * p_burn_fixed / D)
paid_to_provider = tx.cirfi_amount - burned

cirfi_balance(tx.sender)   -= tx.cirfi_amount
outstanding_e              -= burned          // permanent destruction
burn_volume_e              += burned
consumption_volume_e       += tx.cirfi_amount
// provider payment routing: separate settlement
```

**Note:** `ConsumeCirfi` MUST NOT be blocked by `mode_e`. Consumption reduces `outstanding`, which improves CR. Blocking consumption during HALTED would prevent the natural recovery path.

---

## 6. Protocol Parameters

All parameters are governance-adjustable via the ordinary $CIRFI governance process (Whitepaper §6.6) unless marked [CONSTITUTIONAL].

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

### 7.1 Coverage invariant

At every epoch boundary, the following MUST hold:

```
outstanding_e * CR_min_fixed <= capacity_e * D
```

If this is false after applying the epoch boundary transition, the epoch boundary is invalid and MUST be rejected by all correct validators.

### 7.2 Per-mint coverage check

Before any CIRFI-minting transaction is accepted, the node MUST verify:

```
(outstanding_e + cirfi_out) * CR_min_fixed <= capacity_e * D
```

If false, the transaction MUST be rejected regardless of all other authorization conditions. This check is the ultimate guard — it fires even when the circuit breaker is NORMAL and the epoch cap has not been reached.

**Two-layer protection:**

```
Layer 1: Circuit breaker (mode_e)
  → coarse: rejects all minting when CR < CR_halt
  → implemented at transaction dispatch

Layer 2: Coverage invariant check (§7.2)
  → fine: rejects any individual mint that would push CR below CR_min
  → implemented at state-update time
  → fires even when mode_e == NORMAL
```

The circuit breaker is a fast-path rejection. The coverage invariant is the consensus-enforceable guarantee.

### 7.3 Epoch counter monotonicity

```
epoch_{e+1} == epoch_e + 1
```

No epoch may be skipped. Epoch numbering is global and chain-ordered.

### 7.4 Conversion counter reset

```
conversion_volume_e == 0  at the start of every epoch
```

The counter MUST be reset before any transactions in the new epoch are processed (Step 7 of the epoch boundary sequence).

### 7.5 HALTED semantics

When `mode_e == HALTED`:

- `QcbToCirfi` transactions MUST be rejected
- `ContributionToCirfi` transactions MUST be rejected
- `ConsumeCirfi` transactions MUST NOT be affected
- Transfers of existing CIRFI balances MUST NOT be affected
- Consensus participation MUST NOT be affected
- Validator rewards MUST NOT be affected

**The circuit breaker is issuance-local, not chain-global.**

---

## 8. Open Questions

These questions MUST be resolved before the Rust implementation can be considered complete. They are listed in approximate dependency order.

### 8.1 Capacity evidence adversarial model (CRITICAL)

The most important unresolved question. VCA attestation is a necessary condition for capacity reports, but not a sufficient one against a well-resourced adversary. The specification must define:

- What constitutes admissible CapacityEvidence for each ResourceType
- What fraction of validators must countersign a CapacityReport for it to be valid
- What happens when providers submit inflated capacity reports (detection, slashing, cooldown)
- Whether capacity can be challenged by other participants after the epoch boundary
- The minimum sample size for a statistically valid capacity estimate

Until this is resolved, `capacity_e` is a trust assumption, not a protocol guarantee.

### 8.2 CU↔ucirfi unit alignment

The specification states `capacity_e * D` and `outstanding_e * CR_min_fixed` must be comparable. This requires that 1 CIRFI-equivalent CU represents the same "amount of resource" as 1 ucirfi represents "outstanding claims." The exact mapping — how many CU is one CIRFI "worth" at genesis — must be defined before the protocol can compute a meaningful CR.

Concretely: if capacity_e = 1_000_000_000_000 CU and outstanding_e = 1_000_000_000_000 ucirfi, CR = 1.0. That only means something if the units are commensurable. The genesis calibration of CU/ucirfi is an economic decision, not just an engineering one.

### 8.3 Multi-resource capacity aggregation

The per-resource weights `weight_r` determine how compute capacity, storage capacity, and ZK proving capacity are combined into a single `capacity_e` scalar. Wrong weights allow a provider to shift the network's apparent capacity by adding cheap resources (bandwidth) while real scarce resources (ZK proving) are depleted.

The weight-setting mechanism, and who can propose weight changes, needs specification before multi-resource capacity is implemented.

### 8.4 Contribution earn formula

`compute_earn(contribution_proof)` is referenced in §5.2 but not specified. The formula maps a VCA-attested contribution measurement to a ucirfi amount. This formula determines:
- How much CIRFI providers earn per unit of real work
- Whether the earn rate can be gamed (over-reporting small contributions)
- The equilibrium between total earn issuance and consumption burn

The simulation used a simplified model. The real formula needs to be defined per ResourceType and tested against the sybil-farming scenario before implementation.

### 8.5 Dust minimum `MIN_CONVERSION`

The minimum QCB amount for a `QcbToCirfi` transaction needs to be set. Too low: spam; too high: excludes small conversions. Depends on the final QCB/CIRFI exchange rate regime.

### 8.6 Demand proxy for adaptive epoch cap

The adaptive cap formula uses `demand_proxy_e`:

```
epoch_cap_e = beta_cap * capacity_e + lambda_cap * demand_proxy_e
```

The simulation used `consumption_volume_e` as the demand proxy. On-chain, this creates a one-epoch lag (you're using last epoch's consumption to set this epoch's cap). Whether a one-epoch lag is acceptable, or whether the demand proxy needs to be forward-estimated, is unresolved.

### 8.7 Reserve pool routing

`ConsumeCirfi` splits the consumed CIRFI into `burned` (p_burn) and `paid_to_provider` (p_prov). The remaining fraction (p_res) goes to a reserve pool. The reserve pool's governance, withdrawal conditions, and whether the reserve accumulates in CIRFI or is converted to QCB, are not specified here.

---

## 9. Test Vectors

The 15 simulation scenarios in `cirfi_stress_test_v3.py` (commit bb3d2d4) are the canonical economic test vectors. The Rust implementation MUST produce state transitions consistent with the simulation's outputs for each scenario, modulo fixed-point rounding differences.

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

The full CIRFI resource economy is the state machine:

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
