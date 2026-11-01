# Phase 0.5 — Protocol Foundation Hardening: Closure Matrix

> **Purpose:** Authoritative tracking document for Phase 0.5 milestone closure.
> Each row maps one H0 milestone to its implementation evidence, acceptance
> tests, Windows verification result, integration status, remaining gap, and
> current closure decision.
>
> **Three standing rules:**
> 1. Windows-confirmed ≠ merged. Both fields are preserved independently.
> 2. Merged ≠ accepted. Every milestone must satisfy its own acceptance criteria
>    even after merge — an untested merge does not close a milestone.
> 3. Evidence must be verifiable. Unverified or unlocated SHAs are marked
>    **[unverified]** rather than inferred.
>
> **Last updated:** 2026-10-31
> **Branch:** `docs/phase-0-5-closure-matrix`
> **Do not change milestone statuses in this file without a corresponding
> Windows acceptance result. Do not merge implementation PRs based solely on
> this document.**

---

## Closure decision key

| Symbol | Meaning |
|--------|---------|
| ✅ CLOSED | Windows-confirmed, merged or merge-ready with accepted evidence |
| ⏳ PENDING VERIFICATION | Implementation complete; Windows run not yet confirmed |
| 🔲 OPEN | Implementation gap, design decision outstanding, or untested |
| ⚠️ PARTIAL | Subset of acceptance criteria confirmed; remainder outstanding |

---

## H0-1 — Consensus Safety

**Requirement:** Full Tendermint prevote / precommit / lock / unlock safety;
persisted double-sign guard; block-hash verification; agreement under validator
failures within the stated fault model.

| Field | Detail |
|-------|--------|
| **Implementation PR** | #17 (deterministic participation, committed `last_commit`, liveness jails, genesis liveness policy), #18 (Tendermint prevote/precommit/lock/unlock, persisted double-sign guard, block-hash verification) |
| **Key commits** | `integration/phase-0-5-candidate` branch; individual SHAs not extracted — see PR #17 and PR #18 on GitHub |
| **Acceptance tests** | `chain-forge-node/tests/consensus_safety_live.rs` (3 cases: normal finality, crash/restart, proposal rejection); `chain-forge-node/tests/devnet_4node.rs` |
| **Windows verification** | ✅ **PASS 2026-10-28** — consensus 91/91, node 231/231, devnet, restart, `consensus_safety_live` 3/3 (PR #18) |
| **Integration status** | ⚠️ **Awaiting merge** — Windows-confirmed on `integration/phase-0-5-candidate`; not yet on `main` |
| **Remaining gap** | Merge of #17 then #18 in dependency order; no new engineering required |
| **Closure decision** | ⏳ PENDING MERGE — engineering complete, evidence exists |

---

## H0-2 — State Determinism

**Requirement:** All validators compute identical state roots for every block;
divergence is impossible under normal operation and Byzantine-tolerant under
the fault model.

| Field | Detail |
|-------|--------|
| **Implementation PR** | #17 (deterministic participation from committed `last_commit`; prior local-certificate divergence path identified and fixed), #24 (ML-DSA-65 consensus keys on Tendermint devnet) |
| **Key commits** | `integration/phase-0-5-candidate`; ML-DSA devnet confirmed `node 253/253` (PR #24) |
| **Acceptance tests** | `chain-forge-node/tests/devnet_4node.rs` (block-hash + state-root agreement); `chain-forge-node/tests/consensus_safety_live.rs`; `chain-forge-node/tests/mldsa_tx_live.rs` (P0-3..P0-6) |
| **Windows verification** | ✅ **PASS 2026-10-28** — ML-DSA devnet_4node liveness with block-hash + state-root agreement; ML-DSA `consensus_safety_live` 3/3 with crash/restart (PR #24) |
| **Integration status** | ⚠️ **Awaiting merge** — Windows-confirmed on `integration/phase-0-5-candidate`; not on `main` |
| **Remaining gap** | Merge of #17, #18, #24 in order; no new engineering required |
| **Closure decision** | ⏳ PENDING MERGE — engineering complete, evidence exists |

> **Note on prior divergence:** The local-certificate participation path (where each
> node assembled commit certificates independently) was identified as a latent
> state-divergence source (discovered 2026-10-27, documented in ROADMAP
> `FS-03-MN-001`). PR #17 replaces it with participation from committed
> `last_commit` data. This fix is a prerequisite for H0-2 closure.

---

## H0-3 — Crash Recovery

**Requirement:** Node state is consistent with the canonical chain after an
unclean shutdown at any block height; node never silently restarts from genesis.

| Field | Detail |
|-------|--------|
| **Implementation PR** | #41 (generation-based atomic state persistence; signing-guard path fix) |
| **Key commits** | `367b060` (C-01 single-node), `bd1818e` (C-07 four-node SIGKILL), `ab5feac` (F1–F4 security fixes), `6f98800` (F5 signing-guard path) |
| **Acceptance tests** | `chain-forge-node/tests/h0_3_crash_recovery_live.rs` — C-01..C-07 (12 cases); security findings F1–F5 |
| **Windows verification** | ✅ **PASS 2026-10-31 (BossKing / MINGW64)** — 12/12 tests, 11.53 s; all five security findings F1–F5 resolved |
| **Integration status** | ✅ **Merged to `main`** — `2dcc8ad` merge commit |
| **Remaining gap** | None |
| **Closure decision** | ✅ **CLOSED** |

---

## H0-4 — Nonce / Replay Protection

**Requirement:** Nonce wrap-around (u64::MAX) and duplicate transactions across
blocks are rejected with zero partial state change.

| Field | Detail |
|-------|--------|
| **Implementation PR** | None (standalone PR); logic lives in `chain-forge-execution/src/lib.rs` `check_tx` path |
| **Key commits** | Nonce guard at line 2331–2334 of `chain-forge-execution/src/lib.rs` (u64::MAX rejection); replay rejection via nonce-must-equal-account-nonce check in executor |
| **Acceptance tests** | Unit tests in `chain-forge-execution/src/lib.rs` (lines 7845–7852: `nonce=u64::MAX` rejected, `gas=u64::MAX` rejected). **No dedicated live integration test for cross-block replay boundary or u64::MAX wrap.** |
| **Windows verification** | ⚠️ **NOT RUN as standalone** — nonce unit tests pass in sandbox as part of `cargo test -p chain-forge-execution`; no BossKing run for boundary cases |
| **Integration status** | Implementation on `main`; no dedicated PR |
| **Remaining gap** | Missing: (1) live integration test asserting that a tx with nonce N succeeds, then an identical tx with nonce N is rejected in a subsequent block on all 4 nodes; (2) u64::MAX boundary test in a live devnet context; (3) Windows confirmation of a dedicated nonce-boundary acceptance suite |
| **Closure decision** | 🔲 **OPEN** — implementation exists but acceptance criteria not met |

---

## H0-5 — Execution Rollback

**Requirement:** A tx that fails mid-execution or runs out of gas applies zero
state changes — full rollback, not partial. Verified end-to-end on a 4-node
devnet.

| Field | Detail |
|-------|--------|
| **Implementation PR** | Atomicity lives in `chain-forge-execution` state-snapshot/restore path; no standalone PR number in ROADMAP |
| **Key commits** | `chain-forge-execution/src/lib.rs` — per-tx state checkpoint and restore; unit tests `h0_atomicity_fee_conservation` |
| **Acceptance tests** | `chain-forge-node/tests/h0_5_atomicity_live.rs` — H5-1 (failed tx charges fee, moves nothing), H5-2 (replay of failed nonce rejected), H5-3 (future-nonce tx rejected), H5-4 (cross-node root agreement), H5-5 (restart preserves atomicity guarantees) |
| **Windows verification** | 🔲 **NOT RUN** — test file exists and compiles; no BossKing confirmation recorded |
| **Integration status** | Test file on `main`; implementation on `main` |
| **Remaining gap** | BossKing run: `cargo test -p chain-forge-node --test h0_5_atomicity_live -- --nocapture` |
| **Closure decision** | 🔲 **OPEN** — engineering likely complete; Windows acceptance run required |

> **Audit note (2026-10-31):** H0-5 is the highest-priority open milestone for BIZ-PRE-1.
> The test file covers all five required cases. A single BossKing run is the only
> remaining gate. Recommend scheduling immediately after H0-10 BossKing run.

---

## H0-6 — Key Binding Race

**Requirement:** Two transactions in the same block cannot both successfully
bind a key to the same account. The second bind attempt must be rejected with
zero state change.

| Field | Detail |
|-------|--------|
| **Implementation PR** | None dedicated; guard in `bind_key_if_unbound` (`chain-forge-execution/src/lib.rs` line 2438) — `if acct.public_key.is_none()` prevents double-bind within a block via committed state |
| **Key commits** | `chain-forge-execution/src/lib.rs` `bind_key_if_unbound` function |
| **Acceptance tests** | **None.** No test asserts that two same-block txs from the same account, both carrying a public key, result in exactly one successful bind and one rejection. `mldsa_only_accounts_live.rs` tests sequential binding but not same-block racing. |
| **Windows verification** | 🔲 **NOT RUN** — no dedicated test exists to run |
| **Integration status** | Guard implementation on `main` |
| **Remaining gap** | (1) Write a live test submitting two txs in the same block from an unbound account with different keys; assert the first binds, the second is rejected; assert state root agreement across all 4 nodes; (2) Windows confirmation |
| **Closure decision** | 🔲 **OPEN** — guard exists but acceptance criterion (explicit same-block race test) not met |

---

## H0-7 — Supply Invariant

**Requirement:** No tx sequence increases total uQCB supply;
`treasury + burn + validator_rewards = fees_collected` per block, verified
end-to-end on a multi-node devnet.

| Field | Detail |
|-------|--------|
| **Implementation PR** | Fee conservation unit tests exist in `chain-forge-execution`; live fee distribution confirmed in FS-03 (fee_settle_live MN-1..MN-6). No standalone H0-7 live test. |
| **Key commits** | Fee split at `chain-forge-execution/src/lib.rs` `distribute_block_fees`; supply accounting via `StateStore::burn()`; unit test `h0_atomicity_fee_conservation` |
| **Acceptance tests** | Unit: 7 accounting acceptance tests in `chain-forge-execution` (conservation, remainder rule, double-settlement prevention, failed-tx fee charge, burn supply accounting). Live: **no dedicated H0-7 live test asserting `treasury + burn + validator_rewards = fees_collected` per block across all nodes** |
| **Windows verification** | ⚠️ **PARTIAL** — `fee_settle_live` MN-1..MN-6 Windows-confirmed 2026-10-24; MN-7/MN-8 require revalidation; no per-block supply invariant live test run |
| **Integration status** | Implementation and unit tests on `main`; `fee_settle_live` on `main` |
| **Remaining gap** | Write a live test that reads `total_supply`, `treasury:fees`, burn counter, and `treasury:validator-pool` at each block boundary and asserts the conservation equation. Windows confirmation required. |
| **Closure decision** | 🔲 **OPEN** — per-block conservation invariant not live-verified |

---

## H0-8 — Genesis-Hash Peer Verification

**Requirement:** A peer must prove matching genesis hash (not just chain_id) to
be trusted; a tx signed on chain A is rejected on chain B.

| Field | Detail |
|-------|--------|
| **Implementation PR** | Standalone; merged directly to `main` |
| **Key commits** | `616bf0e` (genesis-hash wired through libp2p identify handshake), `d6343bc`, `f85fbcb`, `d72513c`, `0ff15b3` |
| **Acceptance tests** | `chain-forge-node/tests/h0_8_genesis_peer_verification_live.rs` — G-01..G-07 |
| **Windows verification** | ✅ **PASS 2026-10-31 (BossKing / MINGW64)** — G-01..G-07 passing |
| **Integration status** | ✅ **Merged to `main`** — `2dcc8ad` merge commit |
| **Remaining gap** | None |
| **Closure decision** | ✅ **CLOSED** |

---

## H0-9 — DIS-003D Test Harness Repair

**Requirement:** `dis_003d_expiry_live` passes locally on Windows/MINGW64;
large ML-DSA recovery transactions (~77 KB) are reliably submitted and
confirmed.

| Field | Detail |
|-------|--------|
| **Implementation PR** | `security/h0-9-recovery-tx-size` branch; merged to `main` |
| **Key commits** | `c2e0a6b` (migrate keypair calls to `load_fixture_keypair`), `9f1a33c`, `6de1331`, `bbb997c`, `0dfa880`, `22592ec`, `022e8e4`, `cd205ce`, `8ec1ff8`, `6e94671` |
| **Acceptance tests** | `chain-forge-node/tests/dis_003d_expiry_live.rs` — F-00..F-08 (9 cases) |
| **Windows verification** | ✅ **PASS 2026-10-31 (BossKing / MINGW64)** — F-00..F-08 all passed, 38.77 s |
| **Integration status** | ✅ **Merged to `main`** |
| **Remaining gap** | None |
| **Closure decision** | ✅ **CLOSED** |

---

## H0-10 — DIS-003E Recovery Timelock and Cancellation

**Requirement:** Two-phase key recovery with configurable timelock;
`CancelRecovery` during timelock prevents activation; pending state survives
node restarts; production genesis requires nonzero timelock.

| Field | Detail |
|-------|--------|
| **Implementation PR** | `security/h0-10-recovery-timelock` (pushed 2026-10-31; PR not yet opened) |
| **Key commits** | `93e4909` (PendingRecovery struct), `85bedbb` (GenesisExecution fields), `87771c3` (execution: CancelRecovery, sweep, two-phase commit), `3a0a1c3` (node.rs match arm), `dcf0940` (dev genesis allow_zero), `ec71c1b` (test file + genesis-dis003e.json) |
| **Acceptance tests** | `chain-forge-node/tests/dis_003e_timelock_live.rs` — C-14..C-19 (6 cases: timelock pending, cancel prevents activation, re-recovery after cancel, key replacement at activation, EnrollRecoveryPolicy auto-cancel, 4-node state root convergence) |
| **Windows verification** | 🔲 **NOT RUN** — compile-verified clean in sandbox (2026-10-31); BossKing run required |
| **Integration status** | Development branch `security/h0-10-recovery-timelock`; not merged |
| **Remaining gap** | BossKing run: `git pull origin security/h0-10-recovery-timelock && cargo build -p chain-forge-node && cargo test -p chain-forge-node --test dis_003e_timelock_live -- --nocapture` |
| **Closure decision** | ⏳ PENDING VERIFICATION |

---

## H0-11 — Validator Eviction

**Requirement:** Product decision on eviction policy recorded; decision
implemented; deterministic epoch-boundary eviction tested.

| Field | Detail |
|-------|--------|
| **Implementation PR** | None — awaiting product decision |
| **Key commits** | None — bonding code in `chain-forge-validators` defers eviction explicitly |
| **Acceptance tests** | None |
| **Windows verification** | 🔲 **NOT RUN** — nothing to run |
| **Integration status** | Not started |
| **Remaining gap** | (1) Owner records eviction policy decision in ROADMAP; (2) implementation; (3) failing tests first; (4) Windows confirmation |
| **Closure decision** | 🔲 **OPEN — awaiting product decision** |

> **Proposed policy (2026-10-31, owner — not yet approved):**
> Genesis validators receive no permanent exemption from eviction once
> permissionless validator admission is activated. They compete under the same
> personhood, reliability, and eligibility rules as all later validators.
> Eviction occurs at epoch boundaries (deterministic); mid-epoch removal is not
> used. This proposal must be explicitly approved before implementation begins.

---

## H0-12 — Governance Quorum

**Requirement:** `>3%` turnout for ordinary votes, `>6%` for constitutional
changes — implemented, wired to the `VoteOnProposal` execution path, and
adversarially tested.

| Field | Detail |
|-------|--------|
| **Implementation PR** | None dedicated to the execution-path wiring |
| **Key commits** | `chain-forge-governance/src/lib.rs` — quorum calculation, `GovernanceTier` (Ordinary vs Constitutional), vote tallying, double-vote rejection, abstention counting. Defaults: 4% ordinary, 7% constitutional (both exceed ROADMAP floors). |
| **Acceptance tests** | Unit tests in `chain-forge-governance` crate. **No `VoteOnProposal`, `ProposeChange`, or `ActivateChange` tx variants exist in `chain-forge-execution/src/lib.rs`.** No live integration test. |
| **Windows verification** | 🔲 **NOT RUN** — governance module unit tests pass in sandbox; no execution-path wiring exists to test |
| **Integration status** | Governance module (`chain-forge-governance`) on `main`; execution-path wiring **not started** |
| **Remaining gap** | (1) Add `ProposeChange`, `VoteOnProposal`, `ActivateChange` to `TxBody` in `chain-forge-execution`; (2) wire quorum check from `chain-forge-governance` into the executor; (3) adversarial live tests (below-quorum rejection, double-vote, constitutional threshold); (4) Windows confirmation |
| **Closure decision** | 🔲 **OPEN** — module exists but execution integration and live tests are absent |

---

## Summary table

| Milestone | Description | Closure decision | Windows | Merged |
|-----------|-------------|-----------------|---------|--------|
| H0-1 | Consensus safety | ⏳ Pending merge | ✅ 2026-10-28 | ⏳ Awaiting |
| H0-2 | State determinism | ⏳ Pending merge | ✅ 2026-10-28 | ⏳ Awaiting |
| H0-3 | Crash recovery | ✅ **CLOSED** | ✅ 2026-10-31 | ✅ Merged |
| H0-4 | Nonce / replay | 🔲 Open | 🔲 Not run | N/A |
| H0-5 | Execution rollback | 🔲 Open | 🔲 Not run | N/A |
| H0-6 | Key binding race | 🔲 Open | 🔲 Not run | N/A |
| H0-7 | Supply invariant | 🔲 Open | 🔲 Not run | N/A |
| H0-8 | Genesis-hash peer verification | ✅ **CLOSED** | ✅ 2026-10-31 | ✅ Merged |
| H0-9 | DIS-003D harness repair | ✅ **CLOSED** | ✅ 2026-10-31 | ✅ Merged |
| H0-10 | DIS-003E recovery timelock | ⏳ Pending verification | 🔲 Not run | 🔲 Not merged |
| H0-11 | Validator eviction | 🔲 Open — awaiting decision | 🔲 Not run | N/A |
| H0-12 | Governance quorum | 🔲 Open | 🔲 Not run | N/A |

**Closed: 3 of 12.  Pending verification / merge: 3 of 12.  Open: 6 of 12.**

---

## Recommended next actions

Actions are ordered by dependency and BIZ-PRE gate criticality. Do not skip
steps or merge out of order.

### Immediate (no new engineering required)

1. **H0-10 BossKing run** — pull `security/h0-10-recovery-timelock`, build,
   run `dis_003e_timelock_live`. Closes H0-10 and BIZ-PRE-2 (with DIS-003D
   already closed).
   ```
   git pull origin security/h0-10-recovery-timelock
   cargo build -p chain-forge-node
   cargo test -p chain-forge-node --test dis_003e_timelock_live -- --nocapture
   ```

2. **H0-5 BossKing run** — test file already on `main`, implementation already
   on `main`.
   ```
   cargo build -p chain-forge-node
   cargo test -p chain-forge-node --test h0_5_atomicity_live -- --nocapture
   ```

3. **Merge integration candidate** — once owner reviews PRs #17→#20→#21→#22→#23
   in the approved dependency order. Closes H0-1 and H0-2 on `main`.
   Do not batch-merge; resolve conflicts per PR and verify after each merge.

### Short-term (focused test authoring, no architecture change)

4. **H0-7 live test** — read `total_supply` + treasury + burn at each block
   boundary; assert conservation equation. BossKing run after.

5. **H0-4 live boundary test** — assert cross-block nonce replay is rejected
   on all 4 nodes; assert u64::MAX nonce rejected. BossKing run after.

6. **H0-6 same-block race test** — submit two txs in the same block from an
   unbound account; assert exactly one bind succeeds. BossKing run after.

### Medium-term (requires design then implementation)

7. **H0-11 eviction policy** — approve or revise proposed policy; write failing
   tests; implement deterministic epoch-boundary eviction; BossKing run.

8. **H0-12 governance wiring** — add `ProposeChange`/`VoteOnProposal`/
   `ActivateChange` to `TxBody`; wire `chain-forge-governance` quorum check
   into executor; adversarial live tests; BossKing run.

---

## Merge order for integration candidate

Per ROADMAP and owner instruction, PRs must merge in dependency order.
PR #31 (`integration/phase-0-5-candidate` snapshot) is a reference point,
not a direct merge target. Merge the constituent PRs individually:

```
#17 → #18 → #20 → #21 → #22 → #23 → #24 → (others as resolved)
```

Verify the resulting `main` compiles and all live tests pass on BossKing
after each PR lands before proceeding to the next.

---

*This document is a source-and-ROADMAP inventory. It does not change any
milestone status in ROADMAP.md and does not authorize any PR merge.
Evidence marked [unverified] requires a human to confirm the commit SHA or
test result against the repository before it can be treated as accepted.*
