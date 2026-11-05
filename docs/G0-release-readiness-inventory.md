# G0 release-readiness inventory — Qattice Public Testnet Alpha (DRAFT, read-only)

Base: `origin/main` @ `b09df3b`. Documentation only: no production, genesis, state-root, cryptographic-format or Chain Forge change. Not merged. Companion to draft PR #88 (release plan).

## 0. Method and limits (read first)

- **What was done:** read `ROADMAP.md` (Phase 0.5 table, status log), `KNOWN_ISSUES.md`, the open-PR list, the `chain-forge-node/tests` live-suite names and selected source (API surface, mempool admission). Status below is **as recorded in those documents**, cross-checked against merged PRs.
- **What was NOT done:** I did not re-run any suite for this inventory, did not independently re-verify any roadmap ✅ other than E1–E5 and the O8 tests (which I ran and the owner re-ran on Windows), and did not review the code behind the older ✅ rows. A roadmap ✅ here means "the repo records Windows evidence", not "re-checked today".
- **Severity and disposition are proposals** for owner decision. "Decision owner" is who must decide; engineering owner is not assigned anywhere in the repo.
- Platform column: **L** = Linux sandbox evidence recorded, **W** = Windows (BossKing/MINGW64) evidence recorded.
- Nothing here marks a gate passed. G0 itself (candidate commit, dependency matrix, chain ID, token supply, release owner) is **not yet done**; see §5.

## 1. Summary

| Bucket | Count | Items |
|---|---|---|
| Phase 0.5 items with recorded Windows evidence | 8 | H0-1, H0-2, H0-5, H0-7, H0-8, H0-9, H0-10, H0-12 (+ H0-3b complete, H0-3 ◐ with documented limits) |
| Phase 0.5 items partially done | 3 | H0-11 (A and B-phase-1 done; B-policy design only), H0-3 (◐, limits recorded), H0-11C (roadmap 🔲; see §3) |
| Phase 0.5 items not started / no evidence | 4 | **P2P automatic reconnection**, **H0-4 nonce/replay**, **H0-6 key-binding race**, **H0-11D bootstrap retirement** |
| Security fixes designed or investigated but **not implemented** | 3 | ACCT-LEAF-1 (leaf v2), STATE-COMMIT-2 (E1–E5 fixes), executor-level O8 bounds |
| Open known issues that touch public exposure | 4 | §10 nonce-cache cap, §5 governance preimage chain_id, §8 mis-jail, §9 per-block persistence growth |
| Public-infrastructure items (G4) | 6 | explorer, faucet, hardened public RPC, wallet/CLI path, status page, install guide: **none confirmed complete** |

**Bottom line (evidence-based):** there is a working, Windows-confirmed 4-node ML-DSA devnet with persistence hardening, genesis-hash peer checks, recovery timelock and governance quorum. What stands between that and a public alpha is mostly **(a)** the authenticated-state work (E1–E5, nothing fixed yet), **(b)** P2P reconnection, **(c)** two replay/ingress issues (H0-4 / §10), **(d)** hardening the public API surface, and **(e)** the not-yet-built public services and soak/external-operator gates. No public-launch security blocker has been *closed* by this inventory.

## 2. Blocker ledger — consensus, state and persistence

Disposition key: **BLOCKER** (must pass before inviting outsiders), **REQUIRED** (needed before public RPC/faucet, not before a closed cohort), **DISCLOSE** (ship with a published limitation, owner-approved), **N/A**.

| ID | Item | Sev. (proposed) | Implementation status | Test evidence recorded | L / W | Depends on | Decision owner | Alpha disposition |
|---|---|---|---|---|---|---|---|---|
| H0-1 | Consensus safety (no conflicting finals, f=1) | Critical | Done | committed participation evidence tests | L, **W** 2026-10-30 | – | – | Done; re-run on release candidate (G3) |
| H0-2 | State determinism across nodes | Critical | Done | identical roots after same tx sequence | L, **W** 2026-10-30 | – | – | Done; re-run on RC |
| H0-3 | Crash recovery | Critical | Merged `467b1ae` (#48); ◐ | P-02a gaps closed (L1–L5, G, F, R, D) | L, **W** (power-loss untested; one unexplained C-01 anomaly P02A-W1) | – | Owner | **DISCLOSE** power-loss limitation (owner already decided: documented limitation) |
| H0-3b / PERSIST-001 | Crash-safe persistence | Critical | **Complete** (owner 2026-11-04); storage v2 default **off** | manifest sweep (#70), unit 398/0, `storage_v2_live` 8, H0-3 live 12/12 | L, **W** at `5d84dba`/`b38bc0c` | – | – | Done for v1. **Restore authenticates files by hash only** (E2/E3); see STATE-COMMIT-2 |
| H0-4 | Nonce wrap/replay across blocks, zero partial state | High | **🔲 not started** per roadmap | none recorded | – | related to §10 | Owner | **BLOCKER** pending a test or a documented basis that it is covered (execution enforces nonces; §10 notes ingress check is off) |
| H0-5 | Execution rollback / atomicity | Critical | Done (#15) | failed txs leave no state change | L, **W** 2026-10-30/31 | – | – | Done |
| H0-6 | Key-binding race (two txs binding one key) | High | **🔲 not started** per roadmap | none recorded | – | – | Owner | **BLOCKER or documented waiver** |
| H0-7 | Supply conservation | Critical | Done | invariant tests | L, **W** 2026-10-30 | – | – | Done |
| H0-8 | Genesis-hash peer check + cross-chain replay | Critical | Done | G-01..G-07 | L, **W** `616bf0e` 2026-10-31 | – | – | Done. Gap: `adversarial_gossip` test does not compile (§6); GUARD-ID-1 (signing guard not bound to chain id) open, informational |
| H0-9 | Large-tx harness | Medium | Done | `dis_003d_expiry_live` | **W** 2026-10-30 | – | – | Done |
| H0-10 | Recovery timelock/cancel (DIS-003E) | High | Done (#45) | C-14..C-19, 4-node roots converge | L, **W** 2026-11-01 | – | – | Done |
| H0-11A | Eviction when bond < minimum | High | Done (#54) | `validator_eviction_live` EV-01..03 | L, **W** 2026-11-02/03 | – | – | Done |
| H0-11B | Liveness suspension | High | **Phase 1 only** (jail enforcement, epoch accounting). Policy is **design only**; automatic suspension disabled in production genesis | `validator_jail_live` JL-01..09, `precommit_delay_live`, FP-01/06 | L, **W** 2026-11-02/03 | persistence timing measured on real hardware (owner); #60 design memo open | Owner (numeric choices) | **DISCLOSE**: no automatic suspension in alpha; confirm genesis keeps it off. §8 mis-jail risk stays |
| H0-11C | Equivocation evidence + penalty | High | Roadmap says 🔲. Source has evidence/slashing paths (committed-evidence application, `SlashingModule`); **not reconciled against the H0-11C wording** | slashing tests exist; no H0-11C-labelled evidence | – | – | Owner | **Needs reconciliation** (do the existing paths meet H0-11C?) before disposition |
| H0-11D | Bootstrap retirement | Medium | 🔲 | none | – | personhood credential flow | Owner | **DISCLOSE**: genesis validators remain in alpha; alpha operators are a known cohort |
| H0-12 | Governance quorum | High | Done (#52, #53) | GQ-01..06, root identical on 4 nodes | L, **W** 2026-11-02 | needs `insecure-dev-quorum` feature for the test genesis | – | Done. **Release build must be default features**: a default build refuses the low-quorum test genesis (as designed) |
| P2P-RECON | Automatic reconnection + partition recovery | **High** | **Not implemented** (ROADMAP: bootstrap peers dialed once, failures silent) | none; one ML-DSA stall after a ~99-min machine suspend was the trigger | – | – | Owner | **BLOCKER** (G1/G5: external nodes drop and stay dropped) |
| ML-DSA | ML-DSA-65 consensus + ML-DSA-only user accounts | Critical | Done (#24, #35) | devnet_4node root agreement, consensus_safety_live 3/3 incl. crash/restart, `mldsa_tx_live`, `mldsa_only_accounts_live` | L, **W** | – | – | Done; re-run on RC |
| ACCT-LEAF-1 | Account leaf omits key_version, pending_recovery, guardian keys, role, charm | High | **Design + vectors only**: #82, #84 (draft, unmerged); no Rust | Python reference suite (31 tests); not a Rust test | Python on L; W optional | Q-decisions; STATE-COMMIT-2 | Owner | **BLOCKER (Phase 0.5 mainnet gate, owner)**: for the alpha, decide fresh-v2 profile (in principle chosen) |
| SC2-E1 | Account tier mirror stale after lapse | Medium (integrity) | Reproduced, **unfixed** | `sc2a_e1` (ignored, fails by design) | L, **W** | v2 profile / R1 | Owner (Q2) | **BLOCKER or DISCLOSE** (no authorization bypass found: nothing reads `acct.charm`) |
| SC2-E2/E3 | Tampered `validators.json` / `identity.json` accepted on restore, root unchanged | High (local-write adversary; consensus power) | Reproduced, **unfixed** | `sc2a_e2`, `sc2a_e3` | L, **W** | R2 authority tree / R4 | Owner (Q1–Q4) | **BLOCKER** for outside operators (they control their own data dirs) unless owner accepts disclosure |
| SC2-E4 | Agent index trusted from disk | Medium | Reproduced, **unfixed** | `sc2a_e4` | L, **W** | R4 | Owner | REQUIRED |
| SC2-E5 | No executor-level address/denom limit | Medium | **Partly mitigated**: mempool + genesis bounds merged (#87); executor still accepts over-bound values from another node's block | `o8_*` pass; `sc2a_e5` ignored/fails | L, **W** (full node suite 399/0) | profile / activation decision | Owner (Q5) | REQUIRED: executor-level enforcement under the v2 profile |
| SC2-CLAIM | `claim:{id}` accounts store a JSON record in `role` (> 64 B), conflicts with O8 `role ≤ 64` | Medium (blocks v2 encoder) | Found by this audit; **unresolved** | read + arithmetic; not run | – | Q5 | Owner | **BLOCKER for the v2 encoder** |

## 3. Blocker ledger — known issues relevant to a public network

| ID | Issue | Sev. (proposed) | Status | Disposition |
|---|---|---|---|---|
| KI §10 | API nonce cache stuck at the `NO_PRIOR_TX` sentinel: each account capped at ~101 API-submitted txs for its lifetime; ingress replay check effectively off | **High for a public alpha** (faucet users and testers hit the cap; execution still enforces nonces so funds are not endangered per the doc) | **OPEN**, not fixed, fix sketched in the doc | **BLOCKER** for G4/G5 usability; fix with tests first |
| KI §5 | Governance vote preimage has no `chain_id` (cross-chain replay) | Medium–High | **OPEN — "must fix before governance moves on-chain"** | **BLOCKER if** governance txs are enabled in the alpha; otherwise confirm the governance tx kinds are disabled/unreachable in the alpha genesis (not verified here) |
| KI §8 | Jailing can mis-jail a healthy but merely-late validator | Medium | OPEN; automatic suspension must stay disabled in production genesis | **DISCLOSE** + verify alpha genesis disables it |
| KI §9 | Per-block persistence cost grows with chain length (v1 default) | Medium (affects the 7-day soak) | OPEN for v1; addressed in storage v2 (default off) | **Measure in G6**; do not flip the default without owner decision |
| KI §6 | `adversarial_gossip` integration test does not compile | Medium (test hygiene; covers peer-gossip adversaries) | OPEN | REQUIRED before G3 (restores a negative-test suite) |
| KI §13 / EVICT-ROOT-1 | History-dependent roots after deletions; eviction test prints a non-constant root | Low–Medium | OPEN; documentation corrected, no code defect found | Owner decision (§13) before the RC freeze |
| KI GOV-Q1 | Governance quorum follow-ups (wording, zero population, float in decision) | Low–Medium | OPEN, follow-up | REQUIRED if governance is enabled |
| KI GUARD-ID-1 | Signing guard not bound to chain/genesis id | Low (informational) | OPEN | DISCLOSE |
| NODE-TOKIO-1 | Node panicked in tokio's time driver once | – | **FIXED** (#72, tokio 1.54.1); `panic = "abort"` question still open | Owner decision |
| API bind | Whether a node whose API fails to bind should exit | Low | Open decision | REQUIRED for operator guide |
| CI | CI covers only `dis-core` (the green check says nothing about node/state/core) | Process risk | Known limit in ROADMAP | REQUIRED: a minimum CI on node/state/core before external operators build from source |

## 4. Public-surface and infrastructure inventory (G4) — source reading only

| Item | Finding | Disposition |
|---|---|---|
| API bind address | `api.rs` binds `0.0.0.0:{port}` | REQUIRED: public RPC must sit behind an allowlisting proxy; validator nodes should not expose the API |
| Endpoints on the same listener | Read: `/api/status`, `/api/health`, `/api/blocks`, `/api/tx/{id}`, `/api/accounts`, `/api/identity`, `/api/validators`, `/api/peers`. Write/admin-like: `POST /api/tx`, `POST /api/build`, `POST /genesis`, `POST /api/gc-receipt`, `POST /api/pocd/submit`, `POST /api/auth/*`, `POST /api/dis/verify_delegated`, and **`POST /debug/inject_view_change` / `inject_vote` ("devnet-only stubs")**. I found no `cfg(feature)` gate on the debug stubs in `api.rs` by grep; not verified further | **BLOCKER for G4**: separate a public read+submit surface from admin/debug endpoints, or compile the debug stubs out of the release build. Needs a follow-up read to confirm |
| Explorer | `ExplorerState` is node-local and rebuilt on restart from `chain_store` + state; there is no separate explorer UI in this repo | REQUIRED (G4): build or reuse one; non-consensus |
| Faucet | Genesis templates carry `faucet_enabled`; **no faucet service found** | REQUIRED (G4): rate-limited faucet with its own key; subject to §10 cap |
| Wallet/CLI path | `chain-forge-node` has a tx CLI; wallet ML-DSA signing is draft **PR #63** (open, not draft-flagged); Android wallet #12 open | REQUIRED: one documented, tested path to create a wallet and submit an ML-DSA tx |
| Status page, node install guide, operator runbook | None recorded | REQUIRED (G4/G5) |
| Release build | Default features (no `insecure-dev-quorum`) | Record in G0 dependency matrix |
| Security contact / disclaimer | None recorded | REQUIRED (G7) |

## 5. G0 items still to produce (none exist yet)

Candidate commit, Rust toolchain and dependency matrix, chain ID and genesis, **test-token supply** and faucet policy, consensus engine and crypto suite pin (Tendermint + ML-DSA-65 per CLAUDE.md), ports, a threat model for outside operators, a named release owner, and a Linux + Windows baseline run on the candidate (the 24-suite sweep and the Phase 0 closeout write-up are open per ROADMAP; `PHASE-0-CLOSEOUT.md` covers P0-1 only).

## 6. Minimum critical path to a security-gated public alpha (proposed)

Order is by dependency; items marked ∥ can run in parallel.

1. **Owner decisions** (no engineering cost): confirm Q1–Q3; answer Q4–Q8, O9–O11; decide H0-4/H0-6 handling, H0-11C reconciliation, governance enabled/disabled in alpha, §13.
2. **Authenticated state (G2):** SC2-C vectors + Python encoder → SC2-D restore re-derivation → ACCT-LEAF-1 Rust encoder + R2 authority tree under the fresh-v2 profile → executor-level O8 bounds under that profile. Resolve the `claim:` role conflict first.
3. **Replay/ingress (G1):** §10 nonce-cache fix (tests first); H0-4 and H0-6 tests or documented waivers; §5 resolved or governance proven unreachable.
4. **P2P reconnection + Linux partition/rejoin test** (G1/G3).
5. **Public API surface** separated from admin/debug endpoints; minimum CI on node/state/core ∥.
6. **Release candidate:** fix §6 (`adversarial_gossip`), run the full live sweep on Linux and Windows, freeze (G3).
7. ∥ **Public services** on isolated infrastructure: explorer, faucet, RPC proxy, status page, operator guide, wallet path (G4).
8. **External operators** (G5), then **7-day soak** with measured finality (G6; the < 3 s figure stays an unmeasured goal), then owner go/no-go (G7).

## 7. What this inventory does not establish

It does not show that any open item is safe to defer; it does not check the code behind older ✅ rows; it does not estimate effort or dates (no data); it does not decide the numeric bounds, the activation profile or any owner decision. Items marked "Needs reconciliation" or "not verified" are exactly that.
