# Phase 0 Closeout Audit Report

**Baseline commit:** `318be979d0c6902f5b913ef447ec57931bdf863c`  
**Branch:** `main`  
**Date:** 2026-10-31  
**Auditor:** Claude Sonnet 4.6 (Claude-Session: https://claude.ai/code/session_01EkHNSdbE6jTxmmHjvqMKZW)  
**Owner review required:** Yes — see §P0-1 (two-machine gap) and §Release Gate before closing

> **This document is an evidence report, not a declaration of completion.**
> Each milestone is ✅ only when implementation AND a passing acceptance test
> both exist on the current `main`. Where evidence is prior-commit only, the
> commit SHA is noted and the status reflects whether the evidence still
> applies to current `main`.
>
> **Tag policy:** The existing `v0.1.0-phase0` tag (commit `e269374`,
> 2026-10-25) is preserved untouched as a historical marker. The closeout
> tag for this validated baseline is `v0.1.0-phase0-closeout` — created only
> after all nine milestones have current evidence and the owner approves.

---

## Exit-Criteria Matrix

| # | Criterion | Status | Gap |
|---|-----------|--------|-----|
| P0-1 | Clean genesis launches across **independent machines** | ⚠️ Partial | Two-machine ML-DSA devnet not yet run (see §P0-1) |
| P0-2 | All four DIS pilot identities remain Verified after restart | ✅ | — |
| P0-3 | ML-DSA-65-signed tx accepted and finalized across 4 nodes | ✅ | — |
| P0-4 | Invalid signatures rejected | ✅ | — |
| P0-5 | Replayed transactions rejected | ✅ | — |
| P0-6 | Incorrect nonces rejected | ✅ | — |
| P0-7 | Timestamp monotonicity regression-tested | ✅ | — |
| P0-8 | Consensus safety and finality under current config | ✅ | Partition test is sandbox-only (no iptables on Windows) |
| P0-9 | PoCD proof submission and reward settlement verified | ✅ | Application layer; trusted-operator model explicit |

**Overall gate:** ⚠️ **P0-1 two-machine gap must be closed before tagging `v0.1.0-phase0-closeout`.**

---

## P0-1 — Clean Genesis Across Independent Machines

**Criterion:** Genesis launches successfully across independent machines; block
production begins, finality is reached, and state-root agreement holds
across all validators.

**Implementation:** `chain-forge-node` binary; `tests/devnet/genesis-4node-mldsa.json`
(ML-DSA devnet, the supported devnet since PR #36); `scripts/start-machine1.sh` /
`scripts/start-carol.sh`; validator keys under `tests/devnet/keys/mldsa/`.

**Prior evidence (pre-ML-DSA, same-machine):** 4-node devnet with
`genesis-4node.json` (Ed25519) started, reached block 5, all validators
active — confirmed multiple sessions, multiple ROADMAP entries.

**Prior evidence (ML-DSA, same-machine):** `devnet_4node_reaches_target_height`
— passes in-process (sandbox) and was Windows-confirmed for block-hash +
state-root agreement as part of PR #24.

**Gap — two-machine ML-DSA run not yet performed:**
The locked plan (Step 4) explicitly requires a two-machine run on the
ML-DSA devnet. `scripts/start-machine1.sh` and `scripts/start-carol.sh`
currently reference `genesis-4node.json` (Ed25519), not the ML-DSA genesis.
The scripts must be updated to use `genesis-4node-mldsa.json` and the
ML-DSA key set before the two-machine test can be run.

**Required action before closing P0-1:**
1. Update `scripts/start-machine1.sh` and `scripts/start-carol.sh` to use
   `genesis-4node-mldsa.json` and `tests/devnet/keys/mldsa/`.
2. Run on two machines (BossKing + a second machine), verify:
   - Block production starts within 30 s.
   - Finality reached at height ≥ 5.
   - State-root agreement across all 4 validators confirmed via `/api/status`.
3. Record machine hostnames, height reached, state root hash, and timestamp.
4. Commit evidence to `ROADMAP.md` P0-1 row.

**Status:** ⚠️ Partial — same-machine ML-DSA evidence exists; two-machine
run is the remaining gap.

---

## P0-2 — DIS Pilot Identities Verified After Restart

**Criterion:** All four pilot DIS identities (BossKing, Laptop, Phone,
King-OptiPlex-990) remain at Verified tier after a full node restart.

**Implementation:** `chain-forge-identity` identity store; `chain-forge-node`
restart-recovery path (`live_validator_set.json`); DIS genesis seeding via
`PopAttestation::genesis` + `verify_identity`.

**Evidence:**
- Manual devnet run, 2026-10-25: all four pilot identities confirmed Verified
  via wallet re-fetch after node restart.
- `dis_auth_live` (PR #40, 2026-10-31, Windows/MINGW64, 8-step end-to-end):
  RegisterIdentity → fund → Attest sequence succeeds on 4-node devnet.
  Test commit: `aeb6428`.
- `dis_003b_guardian_update_live` D-01–D-09 (PR #40, 2026-10-31,
  Windows/MINGW64, 37.88 s): `policy_generation=4` survives 4-node full
  restart; convergence state root confirmed across nodes. Test commit:
  `44dd826`.
- `attestation_live::attestation_guard_live` + `attestation_coordinator_gate`
  (PR #40, 2026-10-31, Windows/MINGW64, 25.46 s): identity registration
  propagates to all 4 nodes before attestation; duplicate-attest guard
  (`AlreadyAttested`) confirmed. Test commits: `32c8519`, `9dc0df9`.

**Limitations:** Automated Verified-tier verification is via `dis_auth_live`
and `attestation_live`; the four named pilot devices are a manual-devnet
result. No automated test boots the devnet and queries the pilot addresses
by name.

**Status:** ✅

---

## P0-3 — ML-DSA-65 Transaction Accepted and Finalized

**Criterion:** An ML-DSA-65-signed transaction is accepted by all nodes,
executed successfully, and its effects (balance change) are visible on all 4
nodes.

**Implementation:** `chain-forge-execution` ML-DSA-65 signature verification;
`chain-forge-node` ingress admission; `mldsa_tx_live` acceptance test.

**Evidence:** `mldsa_tx_live` (commit `b46de7c`): `qcb1sender` ML-DSA-65
Transfer queued, executed `success: true` at height 3, receiver balance
confirmed on 4/4 nodes via `/api/account`. Three ingress bugs found and
fixed during this test (wire-format size check, F5 hex guard, classical
signature guard). Windows-confirmed as part of PR #24.

**Status:** ✅

---

## P0-4 — Invalid Signatures Rejected

**Criterion:** A transaction with a malformed or invalid ML-DSA-65 signature
is rejected before execution or fails at execution with a verification error.

**Implementation:** `check_account_signature_policy` (PR #35); ML-DSA
signature verification in `chain-forge-execution`; API-level rejection for
wrong-scheme signatures.

**Evidence:** `mldsa_tx_live` P0-4 case: 3309-byte garbage ML-DSA-65
signature rejected at submission or fails execution. `mldsa_only_accounts_live`
A-01..A-09 (PR #35, 2026-10-30, Windows/MINGW64, node 270/270): Ed25519-signed
and unsigned user txs refused on `pqc-native` genesis at API admission,
gossip intake, and execution — one function (`check_account_signature_policy`)
applied at all three gates.

**Status:** ✅

---

## P0-5 — Replayed Transactions Rejected

**Criterion:** A previously-committed transaction (same tx ID / nonce)
re-submitted to the network is rejected with a replay or nonce error.

**Implementation:** `commit_set` replay guard in `chain-forge-node`; nonce
monotonicity enforcement in `chain-forge-execution`.

**Evidence:** `mldsa_tx_live` P0-5 case: nonce-0 tx resubmitted after
commit → rejected with nonce/replay error. Windows-confirmed (PR #24).
`dis_003b_guardian_update_live` D-01: replay-attack case confirmed
(PR #40, 2026-10-31). `dis_003c_replay_attack_live` covers the full
replay-attack surface for DIS operations.

**Status:** ✅

---

## P0-6 — Incorrect Nonces Rejected

**Criterion:** A transaction with a nonce that does not match the sender's
current account nonce is rejected.

**Implementation:** Nonce check in `execute_tx_with_identity_inner`
(line ~3094, `chain-forge-execution/src/lib.rs`).

**Evidence:** `mldsa_tx_live` P0-6 case: nonce-999 tx (expected 1)
rejected with nonce mismatch. Windows-confirmed (PR #24).

**Status:** ✅

---

## P0-7 — Timestamp Monotonicity

**Criterion:** The `timestamp_ms` field of committed blocks is strictly
monotonically increasing; the fix has a regression test.

**Implementation:** Both commit paths in `node.rs` use
`proposal.timestamp_ms.max(last + 1)`; `last_committed_timestamp_ms` field
enforces strict monotonicity after each commit.

**Evidence:** `timestamp_monotonic_live` regression test (commit `0b0a611`):
runs against a live 4-node devnet, submits rapid transactions, asserts each
block's timestamp strictly exceeds the previous. Windows-confirmed.

**Status:** ✅

---

## P0-8 — Consensus Safety and Finality

**Criterion:** Consensus safety and finality hold under the current validator
configuration, including under crash-restart, network partition, and
equivocation scenarios.

**Implementation:** Full Tendermint prevote/precommit/lock/unlock; persisted
double-sign guard; block-hash verification and agreement; VCA quorum floor
(PR #22, ≥ ⌊2·total/3⌋+1 on all engines); proposal authentication with
`pol_round` coverage (PR #21).

**Evidence:**
- `consensus_safety_live` 3/3 (crash/restart, partition, equivocation) —
  Windows-confirmed (PRs #18, #21, #22).
- `adversarial_gossip` 3/3 — Windows-confirmed.
- ML-DSA devnet: `devnet_4node_reaches_target_height` with block-hash +
  state-root agreement — Windows-confirmed (PR #24).
- MN-8 reward-exclusion test 6/6 — Windows-confirmed (PR #21).
- Partition tolerance test: iptables DROP, 5 s isolation, recovery —
  **sandbox only** (no iptables on Windows; Linux sandbox pass confirmed).

**Limitation:** Eclipse attacks, long-range partitions (> 30 s), Sybil peer
connections, and cross-machine adversarial network scenarios are not covered.
These are Phase 0.5 prerequisites for a public testnet.

**Status:** ✅ (partition recovery: Linux/sandbox only)

---

## P0-9 — PoCD Proof Submission and Reward Settlement

**Criterion:** PoCD proof submission and reward settlement work correctly on
the current `main` codebase across all defined acceptance cases.

**Classification:** Application layer (owner decision, ROADMAP §Step 4 note).
The PoCD settlement mechanism uses a trusted-operator model; the chain
enforces operator identity, replay prevention, and treasury solvency but not
research correctness. This is an explicit Phase 0 design choice
(see `docs/PHASE0-SECURITY-ASSUMPTIONS.md` §1).

**Implementation:** `ClaimResearchReward` tx body; `TreasuryStore`; `EscrowStore`;
replay guard via `commit_set`; `pocd_reward_live` 7-case acceptance test.

**Evidence:** `pocd_reward_live` (Windows-confirmed, PR #30):
- **A** — Valid claim settles from treasury.
- **B** — Replay of same claim rejected.
- **C** — Unauthorized operator rejected.
- **D** — Insolvent treasury rejected.
- **E** — Concurrent claims from two operators both settle correctly.
- **F** — Unknown `objective_id`/`task_id` accepted by trusted operator
  (operator-asserted metadata; by design).
- **G** — Settlement state persists across block boundary.

All 7 cases pass. H0-5 nonce semantics verified for PoCD tx path (PR #30).

**Status:** ✅

---

## Additional Milestones Confirmed (Phase 0 Security Layer)

These were not in the original P0-1..P0-9 table but are required for the
Phase 0 security baseline:

| Milestone | Evidence | Commit / PR |
|-----------|----------|-------------|
| ML-DSA-only user accounts (`pqc-native` genesis) | `mldsa_only_accounts_live` A-01..A-09; Windows-confirmed 2026-10-30 | PR #35 |
| ML-DSA account ownership (address-to-key binding) | `mldsa_only_accounts_live` A-01..A-09 + live devnet; Windows-confirmed 2026-10-30 | PR #39 |
| ML-DSA-65 consensus keys on Tendermint devnet | `consensus_safety_live` 3/3 + `devnet_4node`; Windows-confirmed | PR #24 |
| Ed25519 fallback devnet retired | ML-DSA devnet is the supported devnet; Ed25519 genesis files remain as test fixtures | PR #36 |
| DIS-003B guardian policy updates (D-01–D-09) | `dis_003b_guardian_update_live` 9/9; Windows/MINGW64 confirmed 2026-10-31, 37.88 s | PR #40 |
| Identity registration + attestation guard | `attestation_live` 2/2; Windows/MINGW64 confirmed 2026-10-31, 25.46 s | PR #40 |
| DIS auth (wallet registration + transfer) | `dis_auth_live` 8-step; Windows/MINGW64 confirmed 2026-10-31 | PR #40 |

---

## Known Failing Tests on `main` (2026-10-31)

| Test | Status | Note |
|------|--------|------|
| `validator_key_live::post_genesis_validator_admission` | ⚠️ Failing (2 cases) | Pre-existing failure on `main`; not caused by PR #39–40 stack |
| `chain-forge-intelligence` (compile) | ⚠️ Does not compile | Pre-existing; separate crate, out of scope for Phase 0 |

These failures do not block P0-1..P0-9, but must be resolved or explicitly
deferred before the `v0.1.0-phase0-closeout` tag is placed.

---

## Unit Test Counts (Sandbox, `main` at `318be97`)

**Build status:** `cargo build --workspace` exits 0 with one dead_code warning
in `chain-forge-verifier` (pre-existing, not a failure). The `chain-forge-intelligence`
crate does not compile due to missing struct fields in its internal test module
(`NewTask`, `NewExperimentResult`) — this is a pre-existing failure documented
in ROADMAP §Known failing tests. All other crates build cleanly.

Unit tests (`cargo test --workspace --lib --exclude chain-forge-intelligence`)
running in sandbox at time of writing. Prior confirmed counts from `main` at
`966a130` (2026-10-19) with expected deltas from PRs #24, #35, #39, #40:

| Crate | Count (confirmed `966a130`) | Notes |
|-------|----------------------------|-------|
| `chain-forge-core` | 27 | No changes since |
| `chain-forge-identity` | 65 | No changes since |
| `chain-forge-consensus` | 67 | No changes since |
| `chain-forge-execution` | 106 | Minor warnings only since |
| `chain-forge-validators` | 35 | No changes since |
| `chain-forge-node` | 270 (post PR #35) | +0 since PR #40 (test files only) |
| `adversarial_gossip` | 3 | No changes since |
| `chain-forge-intelligence` | ⚠️ Does not compile | Pre-existing; out of scope for Phase 0 |

Owner's local run should confirm counts match or exceed these baselines.

---

## Preserved Historical Artifacts

| Artifact | Description |
|----------|-------------|
| Tag `v0.1.0-phase0` | Commit `e269374` (2026-10-25) — original Phase 0 completion marker; **do not move or delete** |
| Branch `devnet-legacy-2026-10` | Legacy pilot devnet (`genesis-4node.json`, `qcb-testnet-4node`); untouched |
| `tests/devnet/keys/` (Ed25519) | Classical-compatibility test fixtures; remain as test data |
| `docs/PHASE0-SECURITY-ASSUMPTIONS.md` | Explicit Phase 0 security boundaries; reviewed and current |

---

## Phase 0 → Phase 0.5 Transition Gate

Phase 0.5 work does **not** begin until:

1. **P0-1 two-machine gap closed:** Two-machine ML-DSA devnet run completed,
   evidence recorded in `ROADMAP.md` P0-1 row.
2. **`validator_key_live::post_genesis_validator_admission` resolved or
   explicitly deferred** with an owner decision.
3. **Owner reviews and approves** this document and the `v0.1.0-phase0-closeout`
   tag placement.

Once all three are satisfied, tag `v0.1.0-phase0-closeout` at current `main`
HEAD and open Phase 0.5 work.

---

## Phase 0.5 Blockers (for reference)

The following are the next milestones after Phase 0 closes:

- **H0-3** — Atomic state persistence; fail safely, never restart from genesis silently.
- **H0-8** — Genesis-hash peer check; cross-chain block-replay rejection test.
- **H0-10** — Recovery timelock and cancellation.
- **H0-11** — Validator eviction policy (pending owner decision).
- **H0-12** — Governance proposals and votes with quorum.
- **P2P reconnection** — Nodes reconnect to bootstrap peers after network interruption; Linux partition test.

---

*Generated 2026-10-31 by Claude Sonnet 4.6.*  
*Claude-Session: https://claude.ai/code/session_01EkHNSdbE6jTxmmHjvqMKZW*
