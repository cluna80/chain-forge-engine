# QCB Single-Token Economic Engine — Architecture Audit

**Milestone:** Phase 1 — QCB Single-Token Economic Engine  
**Date:** 2026-10-10  
**Basis:** `QCB-Chain-Whitepaper-v2.md` (fully reviewed)  
**Scope:** Identify every code site that assumes QRC is the active resource currency; define the migration plan, economic invariants, and phased implementation checklist.

---

## 1. Executive Summary

The whitepaper adopted a single-token model in October 2026 (§6.2–§6.5): **$QCB** is the sole protocol token; **uQCB** is its micro-denomination (1 QCB = 1,000,000 uQCB); the QRC two-token prototype is preserved in `chain-forge-qrc` as a reference crate and is not active on-chain.

The good news: the on-chain state layer already uses `uqcb` as its native denom. Genesis accounts are denominated in `uqcb`. The PoCD (Grand Challenge) reward path that has been tested and confirmed working (`treasury:pocd` → miner wallets) correctly uses `uqcb`. The consensus, identity, and slashing modules are token-agnostic.

The problem: the **resource marketplace** (escrow, job lifecycle, agent spending) uses `uqrc` as its internal accounting denom throughout the execution layer. The `LockQrcForJob`, `ReleaseQrcForJob`, `RefundQrcForJob`, and `DepositToTreasury` handlers all credit/debit `"uqrc"`. The `QrcPurchase` step — which burns `uqcb` and mints a separate `uqrc` balance — is the structural remnant of the two-token model.

Migration to single-token means: **eliminate the burn-to-mint QRC purchase step; use `uqcb` end-to-end for resource escrow**. The job lifecycle structure (LockQrcForJob → CreateJob → AcceptJob → CompleteJob → VerifyJob) is reusable as-is; only the currency denomination changes.

---

## 2. What "Single-Token" Means in Code

| Concept | Old (QRC model) | New (QCB single-token) |
|---|---|---|
| Consumer buys resource credits | Burns `uqcb` → mints `uqrc` via `QrcPurchase` | No purchase step — consumer holds `uqcb` directly |
| Escrow denom | `uqrc` / `locked_uqrc` | `uqcb` / `locked_uqcb` |
| Provider payment denom | `uqrc` | `uqcb` |
| Treasury (agent funding) denom | `uqrc` | `uqcb` |
| PoCD reward denom | `uqrc` (old EpochClose path) / `uqcb` (active path) | `uqcb` (already correct on active path) |
| Consumption burn | `p_burn = 0.25` of QRC (SUSPENDED) | Suspended — not implemented in this milestone |
| Supply invariant | 210M QCB cap tracked in `chain-forge-tokenomics` | Same cap; no new minting in resource path |

---

## 3. Full Module Audit

### 3.1 `chain-forge-execution/src/lib.rs` — THE PRIMARY CHANGE TARGET

This is the only file that needs substantive code changes for the resource-marketplace migration. Everything else is either already correct, legacy-only, or test scaffolding.

#### 3.1.1 `QrcPurchase` transaction type (lines ~218–222, ~2325–2400)

**Status:** Active on-chain. Must be frozen/deprecated for Phase 1.

The `QrcPurchase` handler:
- Debits `uqcb` from sender (correct — debit already uses `uqcb`)
- Credits `uqrc` to sender via `QrcEngine::qrc_for_qcb()` — **this `uqrc` credit has no on-chain utility in the single-token model**

**Decision required (unresolved):** How should existing `uqrc` balances be handled?  
Options: (a) leave them — they're inert since nothing spends `uqrc` in the new path; (b) burn them at genesis of the new genesis — not applicable to a running chain; (c) provide a `ConvertUqrcToUqcb` migration tx. Since the devnet is a test environment, option (a) is acceptable for Phase 1 (existing `uqrc` balances are stranded but harmless).

**Phase 1 action:** Do not remove `QrcPurchase` from `TxBody` (preserve legacy tests). Add a new `TxBody::BuyResourceCredits` is NOT needed — skip this step entirely in the new lifecycle. Document that calling `QrcPurchase` produces inert `uqrc` credits.

#### 3.1.2 `LockQrcForJob` handler (lines ~3300–3415)

**Status:** Active on-chain. The only code change in resource settlement path.

Current logic:
1. Checks `treasury:agent_id` balance of `"uqrc"` or falls back to sender's `"uqrc"`
2. Debits `"uqrc"` from treasury/sender
3. Credits `"locked_uqrc"` AND `"uqrc"` to `escrow:{escrow_id}` (the recent bug fix)

**Required change:** Replace `"uqrc"` → `"uqcb"` and `"locked_uqrc"` → `"locked_uqcb"` throughout this handler. The per-job limit check (`per_job_limit_uqrc`) field name in `AgentRecord` should also be renamed to `per_job_limit_uqcb` — but this is a struct rename; defer to avoid breaking existing records.

**Unresolved design decision:** The whitepaper suspends `p_burn` but does not finalize what fraction (if any) of the escrowed amount is protocol-burned at settlement vs. fully released to provider. The current code releases `PAYMENT_AMOUNT` to provider and leaves `ESCROW_AMOUNT - PAYMENT_AMOUNT` stranded in escrow. This residual is `QCB-ECON-001` — **do not invent percentages the whitepaper has not finalized**. Keep the existing two-amount structure (provider_amount + residual) and document it as pending.

#### 3.1.3 `ReleaseQrcForJob` handler (lines ~3460–3510)

**Status:** Active on-chain. Simple denom rename.

Currently debits `"uqrc"` from escrow and credits `"uqrc"` to provider wallet.

**Required change:** Replace `"uqrc"` → `"uqcb"` in both operations. No structural change.

#### 3.1.4 `RefundQrcForJob` handler (lines ~3530–3570)

**Status:** Active on-chain. Simple denom rename.

Currently debits `"uqrc"` from escrow and credits `"uqrc"` to requester wallet.

**Required change:** Replace `"uqrc"` → `"uqcb"` in both operations. No structural change.

#### 3.1.5 `VerifyJob` handler (lines ~3540–3560, uses `"uqrc"`)

**Status:** Active on-chain. Uses the inline settlement path.

Currently debits `"uqrc"` from escrow and credits `"uqrc"` to provider.

**Required change:** Replace `"uqrc"` → `"uqcb"` in both operations. Also rename `"locked_uqrc"` → `"locked_uqcb"` in the pre-settlement check.

#### 3.1.6 `DepositToTreasury` handler (lines ~3300–3400)

**Status:** Active on-chain.

Currently transfers `"uqrc"` from sender to `treasury:{agent_id}`.

**Required change:** Replace `"uqrc"` → `"uqcb"`. The `per_job_limit_uqrc` field in the tx body can stay as-is for now (it's a numeric field name, not a denom).

#### 3.1.7 `EpochClose` PoCD reward path (lines ~2749–2862)

**Status:** THIS IS THE LEGACY PATH — uses `"uqrc"` for treasury debit and miner credit.

There are **two distinct PoCD reward paths** in `chain-forge-execution/src/lib.rs`:

- **Legacy path** (lines ~2749–2862): Inside the `EpochClose` tx handler. Reads `treasury:pocd` balance as `"uqrc"`, credits miners with `"uqrc"`. **This path is not active on the devnet** — the devnet uses the second path below.
- **Active path** (lines ~4564–4622): Inside the `SubmitUsefulWork` / epoch boundary handler. Reads `treasury:pocd` balance as `"uqcb"`, credits miners with `"uqcb"`. **This is the confirmed-working path** (3-miner test, 2026-10-09).

**Phase 1 action:** Leave both paths in place. Add a code comment to the legacy `EpochClose` path noting it uses `"uqrc"` and is superseded by the active path. No functional change needed — the active path is already correct.

#### 3.1.8 `QrcSpend`, `QrcContributionSettle`, `EpochOpen`, `CoverageRatioReport` (lines ~2400–2600)

**Status:** These handlers operate on `"uqrc"` balances and invoke `QrcEngine`. They are **not called by any active devnet test** — they are legacy QRC prototype paths.

**Phase 1 action:** Preserve in place. Add `#[allow(dead_code)]` comments if compiler warns. Do not remove.

#### 3.1.9 `AgentQrcSpend` / `RecordAgentSpend` (lines ~3171–3200)

**Status:** Tracks agent spending in `uqrc`. Not used by active resource lifecycle.

**Phase 1 action:** Preserve. Rename field to `uqcb` in a later phase when agent spending is wired up.

#### 3.1.10 Module routing — `"qrc"` module tag (lines ~1888–1931)

The execution layer routes transactions to modules by a string tag. Several `TxBody` variants are tagged `"qrc"`:

```rust
TxBody::QrcPurchase { .. } => Some("qrc"),
TxBody::LockQrcForJob { .. } => Some("qrc"),
// etc.
```

And the module is enabled if genesis includes `"qrc"` in the modules array.

**Phase 1 action:** Keep `"qrc"` as the module tag for the resource marketplace. The tag is just a string; renaming it to `"resource"` is desirable eventually but is a cosmetic refactor, not a blocking issue. The genesis already has `"qrc"` in the modules list and this gate is what enables the resource handlers.

---

### 3.2 `chain-forge-node/src/api.rs`

- `GET /api/qrc` endpoint: returns `QrcMetrics` (conversion rate, coverage ratio, etc.) from the `QrcEngine` — legacy endpoint, not needed by active devnet tests. Preserve; mark as legacy in a comment.
- `GET /api/accounts/{address}`: returns raw `balances` map from state. No change needed — once handlers write `uqcb`, clients will see `uqcb` in balance responses.
- `GET /api/jobs/{job_id}`: queries job state. No change needed.

---

### 3.3 `chain-forge-qrc/` crate

**Status:** Reference/prototype. Not active on-chain. The execution layer imports it for:
- `QrcEngine` (dynamic conversion rate, coverage ratio)
- `ResourceKind` enum (used in `QrcSpend`, `PurchaseResourceJob`, `CreditResourceNode` body types)
- `CapacityEvidence` type
- `QcbRewardPolicy` (used in the **active** PoCD path at line ~4571)

**Critical:** `QcbRewardPolicy` in `chain-forge-qrc/src/pocd_reward.rs` is used by the active devnet PoCD reward path. It is NOT legacy. The crate must stay as a dependency.

**Phase 1 action:** Leave crate untouched. Its presence as a Cargo dependency is required for `QcbRewardPolicy`. The `QrcEngine` logic in this crate is dormant (no active tx invokes it).

---

### 3.4 `chain-forge-tokenomics/src/lib.rs`

- `QCB_MAX_SUPPLY_UQCB = 210_000_000 * 1_000_000` — correct and matches whitepaper
- `SupplyRegistry::mint_qcb`, `burn_qcb` — correct cap enforcement exists
- `mint_qrc` / `qrc_minted_uqrc` / `qrc_recycled_uqrc` fields — legacy, unused by active paths

**Phase 1 action:** No changes. The supply cap constant is correct.

---

### 3.5 `chain-forge-state/src/lib.rs`

- `GenesisState` seeds balances using `genesis.native_token.denom` = `"uqcb"` — **correct**
- `AccountState::credit/debit` accept arbitrary denom strings — **correct, denom-agnostic**
- `StateImpl::burn` records burns with denom — **correct**

**Phase 1 action:** No changes needed.

---

### 3.6 Genesis files

#### `tests/devnet/genesis-3node.json` and `genesis-3node.json`

- `native_token.denom = "uqcb"` ✅
- `native_token.max_supply = "210000000"` ✅
- `modules: [..., "qrc", ...]` — needed to enable resource handlers ✅
- `treasury:pocd` balance in `uqcb` ✅
- Genesis accounts denominated in `uqcb` ✅

**Gap:** There is no `treasury:resource` account in genesis. Under the single-token model, the whitepaper describes a genesis allocation of ~70% to the "resource economy seed." This is not yet reflected in the devnet genesis. For Phase 1 (devnet only), the existing per-user balances serve as the test funding pool — a genesis `treasury:resource` account is a Phase 2/mainnet concern.

**Phase 1 action:** No changes to genesis files needed for devnet migration.

---

### 3.7 Python test scripts

| Script | QRC references | Impact |
|---|---|---|
| `scripts/phase0_job_test.py` | Uses `QrcPurchase`, `"uqrc"` balances, `per_job_limit_uqrc` | Must be updated to new lifecycle (QCB path) or preserved as QRC-prototype smoke test |
| `scripts/phase0_settlement_invariants.py` | Uses `QrcPurchase`, `"uqrc"` escrow denom | Must be updated once handlers switch to `uqcb` |
| `scripts/phase0_negative_release_test.py` | Uses `"uqrc"` | Update |
| `scripts/phase0_negative_refund_test.py` | Uses `"uqrc"` | Update |
| `scripts/phase0_acceptance_test.py` | Uses `QrcPurchase`, `LockQrcForJob` | Update |
| `scripts/pocd_miner.py` | Uses `uqcb` for reward checks | ✅ Already correct |
| `scripts/phase1_contribution_test.py` | Uses `uqcb` | ✅ Already correct |
| `scripts/phase1_wallet_test.py` | Uses `uqcb` | ✅ Already correct |
| `scripts/phase1_dis001_test.py` | No balance ops | ✅ No change |
| `scripts/carol_resource_node.py` | Submits `AcceptJob`/`CompleteJob` — no denom | ✅ No change |

**Phase 1 action for test scripts:** The strategic recommendation says to "pause the old QRC settlement-invariants test." For Phase 1, preserve all existing scripts as-is. Write new QCB-native versions after the execution handlers are updated.

---

### 3.8 `chain-forge-agents/`, `chain-forge-resource/`, `chain-forge-sim/`

- `chain-forge-agents`: References `per_epoch_uqrc`, `lifetime_limit_uqrc`, `max_balance_uqrc` in struct field names. These are struct fields, not on-chain denoms — they hold numeric values. Low priority rename; no on-chain breakage.
- `chain-forge-resource`: Types for `Job`, `Escrow`, `Machine`, `Receipt` — denom-agnostic structs. No changes needed.
- `chain-forge-sim`: QRC simulation scripts. Preserve as reference. Not active on-chain.

---

## 4. Economic Invariants for Phase 1

These are the invariants the new integration test suite must verify, per the whitepaper (§6.2, §6.7) and the strategic recommendation.

### INV-001: Fixed Supply — Genesis Total

```
sum(all genesis account balances in uqcb) == 210,000,000 * 1,000,000
```

**Status:** Not yet enforced by a test. Genesis has Alice(500M) + Bob(500M) + Dave(500M) + Carol(500M) + treasury:pocd(50B) — clearly a devnet subsidy, not the 210M mainnet cap. Devnet genesis is explicitly a test environment; this invariant applies to mainnet genesis only.

**Phase 1 action:** Document this distinction. Create a test helper that validates the sum for any genesis file where `max_supply` is the binding constraint.

### INV-002: Resource Settlement Conservation

```
uqcb_consumer_delta + uqcb_provider_delta + uqcb_escrow_residual == 0
```

Where:
- `uqcb_consumer_delta` = -(ESCROW_AMOUNT) [consumer pays escrow at LockQrcForJob]  
- `uqcb_provider_delta` = +(PAYMENT_AMOUNT) [provider receives at VerifyJob/ReleaseQrcForJob]  
- `uqcb_escrow_residual` = +(ESCROW_AMOUNT - PAYMENT_AMOUNT) [stranded in escrow account, pending QCB-ECON-001]

**Note:** The residual is NOT burned in Phase 1. Conservation identity must account for the stranded amount.

### INV-003: No New Minting in Resource Path

```
treasury:pocd.balance_after_resource_job == treasury:pocd.balance_before_resource_job
total_uqcb_in_accounts(before_job) == total_uqcb_in_accounts(after_job)
```

Resource jobs must not increase total `uqcb` supply. The only `uqcb` minting path is `SubmitUsefulWork` → epoch close → `treasury:pocd` debit → miner wallet credit. That path transfers from an existing funded treasury, it does not mint.

### INV-004: PoCD Treasury Solvency

```
treasury:pocd.balance >= sum(all miner rewards paid in epoch)
```

The treasury must never go negative. The active PoCD path (lines 4583/4604/4622) checks this with `if treasury_balance >= amt` before crediting.

**Status:** Verified working by the 3-miner test (2026-10-09). Treasury debited exactly the sum of miner credits.

### INV-005: Cross-Node Consistency (3-Node)

After gossip propagation, all three nodes (Alice :8080, Bob :8081, Dave :8082) must agree on:
- Consumer's `uqcb` balance
- Provider's `uqcb` balance  
- Escrow account's `uqcb` + `locked_uqcb` balances
- Job state (Settled)

### INV-006: Duplicate Settlement Rejection

A second `VerifyJob` (or `ReleaseQrcForJob`) on an already-settled escrow must be rejected. The provider's balance must not increase a second time.

**Status:** The VerifyJob handler checks job state before releasing escrow. Needs a dedicated test.

---

## 5. Unresolved Economic Design Decisions

Per the strategic recommendation: **do not begin implementation until these are resolved.**

### UED-001: Escrow/Revenue Split (QCB-ECON-001)

**Blocker for:** Setting the `PAYMENT_AMOUNT` vs. `ESCROW_AMOUNT` split correctly.

The whitepaper explicitly suspends `p_burn = 0.25` (Control 4, §6.10) because burning from provider payment is economically wrong. The residual `ESCROW_AMOUNT - PAYMENT_AMOUNT` (100,000 uQRC in current tests) is currently stranded in the escrow account with no defined destination.

**Options not yet decided:**
- Option A: 100% released to provider (no protocol fee in Phase 1)
- Option B: Residual burned permanently (supply contraction)
- Option C: Residual routed to a protocol treasury (fee capture)
- Option D: Consumer-side burn at job submission (not provider-side), enabling provider to receive 100%

**Recommendation:** For Phase 1 devnet testing only, use Option A (100% to provider) to demonstrate end-to-end conservation cleanly. **This must not be presented as the final fee split.** The whitepaper reserves this decision for the escrow/revenue-policy redesign.

### UED-002: uQCB as Sole Resource Denom vs. Separate Escrow Token

The whitepaper (§6.8 footnote, §6.5) states: "uQCB should ordinarily be implemented as the smallest accounting unit of QCB, rather than as a second independently issued asset."

**Current state:** The execution layer uses `"uqrc"` as an escrow denom separate from `"uqcb"`. Migrating to `"uqcb"` makes escrow balances directly visible in the account's main balance — which is simpler but means a consumer's "available" balance mixes locked-for-job and free balances unless the `locked_uqcb` sub-denom is preserved.

**Decision:** Keep the `locked_uqcb` sub-denom pattern (analogous to `locked_uqrc`) for the escrow account. The escrow account's `uqcb` balance equals the consumer's claim; `locked_uqcb` is the tracking field for `VerifyJob`. This is the minimal change preserving the existing two-field structure.

### UED-003: Per-epoch uQCB Issuance Rate and Contribution Pool Size

Open Question 26a in the whitepaper: the per-epoch uQCB issuance rate, total contribution pool, and drawdown schedule are not specified.

**Current devnet:** `treasury:pocd` seeded with 50,000,000,000 uqcb (50,000 QCB). This is a devnet constant, not a mainnet commitment.

**Phase 1 action:** Keep the devnet constant. Do not implement the contribution pool drawdown schedule — that is Phase 2+.

---

## 6. Proposed Module Changes

This is the minimal change set for Phase 1. All changes are in `chain-forge-execution/src/lib.rs` unless noted.

### Change Set A — Resource Escrow Denom Migration (CORE)

**Files:** `chain-forge-execution/src/lib.rs`

1. `LockQrcForJob` handler:
   - Change `balance_of("uqrc")` → `balance_of("uqcb")` (treasury and sender balance checks)
   - Change `debit("uqrc", ...)` → `debit("uqcb", ...)`
   - Change `credit("locked_uqrc", ...)` → `credit("locked_uqcb", ...)`
   - Change `credit("uqrc", ...)` → `credit("uqcb", ...)` (escrow account)
   - Change `"insufficient uqrc"` error messages → `"insufficient uqcb"`

2. `ReleaseQrcForJob` handler:
   - Change `balance_of("uqrc")` → `balance_of("uqcb")` (escrow balance check)
   - Change `debit("uqrc", ...)` → `debit("uqcb", ...)`
   - Change `credit("uqrc", ...)` → `credit("uqcb", ...)` (provider wallet)

3. `RefundQrcForJob` handler:
   - Change `balance_of("uqrc")` → `balance_of("uqcb")` (escrow balance check)
   - Change `debit("uqrc", ...)` → `debit("uqcb", ...)`
   - Change `credit("uqrc", ...)` → `credit("uqcb", ...)` (requester wallet)

4. `VerifyJob` handler (inline settlement path):
   - Change `balance_of("locked_uqrc")` → `balance_of("locked_uqcb")`
   - Change `debit("locked_uqrc", ...)` → `debit("locked_uqcb", ...)`
   - Change `balance_of("uqrc")` → `balance_of("uqcb")` (escrow)
   - Change `debit("uqrc", ...)` → `debit("uqcb", ...)`
   - Change `credit("uqrc", ...)` → `credit("uqcb", ...)` (provider wallet)

5. `DepositToTreasury` handler:
   - Change `balance_of("uqrc")` → `balance_of("uqcb")` (sender balance check)
   - Change `debit("uqrc", ...)` → `debit("uqcb", ...)`
   - Change `credit("uqrc", ...)` → `credit("uqcb", ...)` (treasury account)

### Change Set B — New QCB Resource Job Lifecycle (Phase 1 Test Only)

**Files:** `scripts/phase0_qcb_job_test.py` (new file)

Write a new test that exercises the QCB-native lifecycle:
- No `QrcPurchase` step — Alice funds the job from her genesis `uqcb` balance
- `DepositToTreasury` with `uqcb`
- `LockQrcForJob` with `uqcb` escrow
- Full `CreateJob → AcceptJob → CompleteJob → VerifyJob` lifecycle
- Verify balances in `uqcb`
- Verify economic invariants INV-002 through INV-006

The existing `phase0_job_test.py` is preserved as-is (QRC legacy prototype).

### Change Set C — Documentation

1. Add `QCB-ECON-001` comment block to `LockQrcForJob` handler noting that the `PAYMENT_AMOUNT < ESCROW_AMOUNT` residual is pending policy finalization.
2. Add `// LEGACY: uses uqrc — superseded by active path at line XXXX` comment to the `EpochClose` PoCD distribution block.
3. Update `chain-forge-execution/src/lib.rs` module-level doc comment to reflect single-token architecture.

### What NOT to Change (Phase 1)

- **Consensus, P2P, cryptography** — untouched
- **`chain-forge-qrc` crate** — preserved as-is (required for `QcbRewardPolicy`)
- **`QrcPurchase`, `QrcSpend`, `QrcContributionSettle`, `EpochOpen`, `EpochClose` tx types** — preserved as legacy in `TxBody` enum; existing tests continue to pass
- **`chain-forge-tokenomics`** — no changes
- **`chain-forge-state`** — no changes
- **Genesis files** — no changes
- **Identity, personhood, slashing modules** — no changes
- **Any existing passing test** — all Phase 0 tests must remain green

---

## 7. Phased Implementation Checklist

### Phase 1 — Single-Token Resource Settlement (This Milestone)

**Prerequisite:** Resolve UED-001 (escrow residual destination) at the level needed for devnet testing. Recommendation: use 100% provider payment (no fee) for Phase 1 test clarity.

- [ ] **P1-1** Apply Change Set A to `chain-forge-execution/src/lib.rs` — replace `"uqrc"`/`"locked_uqrc"` with `"uqcb"`/`"locked_uqcb"` in the five handlers above
- [ ] **P1-2** Verify existing Phase 0 tests still pass (no regression in QRC legacy path)
- [ ] **P1-3** Verify devnet nodes start with updated binary and reach consensus
- [ ] **P1-4** Write `scripts/phase0_qcb_job_test.py` — full QCB-native lifecycle test (Change Set B)
- [ ] **P1-5** Run new test on 3-node devnet; confirm INV-002 (conservation), INV-005 (cross-node)
- [ ] **P1-6** Add Change Set C documentation comments
- [ ] **P1-7** Add code comments to legacy `EpochClose` PoCD path noting it uses `uqrc`
- [ ] **P1-8** Update `docs/QCB-Single-Token-Migration-Audit.md` with any findings from implementation

### Phase 2 — Economic Conservation Integration Tests

- [ ] **P2-1** Write `scripts/phase1_qcb_settlement_invariants.py` as QCB-native successor to `phase0_settlement_invariants.py`
  - INV-002: resource settlement conservation
  - INV-003: no new minting in resource path
  - INV-004: PoCD treasury solvency (already passing)
  - INV-005: cross-node consistency after gossip
  - INV-006: duplicate settlement rejection
- [ ] **P2-2** Run SI suite on 3-node devnet; all invariants green
- [ ] **P2-3** Resolve UED-001 formally — pick fee destination policy and encode as a named constant in the handler

### Phase 3 — PoCD + Resource Path Integration

- [ ] **P3-1** Verify the PoCD reward path (active, `uqcb`) works concurrently with resource jobs
- [ ] **P3-2** Verify `treasury:pocd` debit matches miner wallet credits (INV-004) while a resource job is in-flight
- [ ] **P3-3** Confirm no interference between `gc_receipt` reward accounting and escrow accounting

### Phase 4 — Adversarial Tests

- [ ] **P4-1** Forged escrow ID (ghost escrow) rejected by `ReleaseQrcForJob`/`RefundQrcForJob`/`VerifyJob`
- [ ] **P4-2** Over-amount release rejected
- [ ] **P4-3** Wrong-sender release rejected
- [ ] **P4-4** Duplicate settlement rejected (INV-006)
- [ ] **P4-5** Replay after SIGKILL+restart rejected (existing DIS-001 Phase B, extended for `uqcb` path)

### Phase 5 — Genesis-to-Mainnet Supply Invariant

- [ ] **P5-1** Define mainnet genesis with proper 210M QCB allocation structure (§6.7 allocations)
- [ ] **P5-2** Write supply-sum invariant test (INV-001) for mainnet genesis file
- [ ] **P5-3** Implement `treasury:resource-seed` genesis account with §6.7 ~70% resource economy allocation
- [ ] **P5-4** Wire `SupplyRegistry::mint_qcb` / `burn_qcb` into the active resource path once burn policy is finalized (QCB-ECON-001)

---

## 8. What Is Implemented vs. What Are Whitepaper Proposals

| Feature | Status |
|---|---|
| `uqcb` as native denom in state layer | ✅ Implemented |
| 210M QCB cap constant | ✅ Implemented (`chain-forge-tokenomics`) |
| Genesis funded in `uqcb` | ✅ Implemented |
| PoCD reward path (`treasury:pocd` → miner wallets in `uqcb`) | ✅ Implemented and tested |
| Resource job lifecycle (5-step state machine) | ✅ Implemented (currently in `uqrc`) |
| Escrow conservation (provider payment + residual = escrow amount) | ✅ Implemented (currently in `uqrc`) |
| **Resource escrow in `uqcb`** | ❌ Phase 1 target |
| **No `QrcPurchase` step in new lifecycle** | ❌ Phase 1 target |
| Protocol fee routing (QCB-ECON-001) | ❌ Whitepaper proposal — pending escrow/revenue-split redesign |
| Consumption burn (`p_burn`) | ❌ Whitepaper proposal — **SUSPENDED** as of October 2026 |
| CoverageRatio circuit breaker (resource path) | ❌ Whitepaper proposal — not wired to resource handlers |
| Dynamic conversion rate (Controls 1/2) | ❌ Whitepaper proposal — implemented in `chain-forge-qrc` but not active |
| Mainnet genesis allocations (§6.7 percentages) | ❌ Whitepaper proposal — devnet uses test balances |
| 8-year locked distribution schedule (§6.9) | ❌ Whitepaper proposal — future phase |
| Grand Challenge contribution pool schedule (OQ-26a) | ❌ Whitepaper proposal — unresolved |
| Permissioned EVM layer | ❌ Whitepaper proposal — Phase 5+ |
| Personhood-weighted BFT overlay | ❌ Whitepaper proposal — Phase 1 (consensus layer) |

---

## 9. Implementation Start Condition

**Do not begin Change Set A until the following is decided:**

1. **UED-001 (escrow residual):** For Phase 1, confirm that 100% provider payment (no protocol fee) is acceptable as a devnet-only placeholder, with `QCB-ECON-001` explicitly documented as pending. If a fee destination is required now, pick Option B (burn to `/dev/null` — simplest accounting) or Option C (route to `treasury:protocol`).

2. **UED-002 (locked_uqcb sub-denom):** Confirm keeping the two-field escrow pattern (`uqcb` + `locked_uqcb`) rather than collapsing to a single field. This document recommends keeping it.

Once those two decisions are confirmed, Change Set A is a mechanical find-and-replace across five handler blocks — approximately 30 lines of code changed, with the existing test suite verifying no regression.

---

*Audit prepared by Claude Sonnet 4.6 — chain-forge-engine, 2026-10-10*
