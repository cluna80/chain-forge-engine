# H0-11B — Liveness evidence, quorum protection and reinstatement: design memo

**Status (2026-11-03): DESIGN ONLY, DRAFT for owner review.** Nothing in this memo is implemented or enabled. **Automatic validator suspension stays disabled in production genesis.** No change to the evidence rule is implemented without separate owner approval. H0-11B and BIZ-PRE-5 stay open.
**Depends on:** `docs/persist-001-p02-design.md` (section 16: the per-block persistence cost confounds every loaded-chain timing number below). **Related:** KNOWN_ISSUES §8 (measurements), §9 (cost), NODE-TOKIO-1 (runtime panic), ROADMAP rows H0-11, H0-11B, BIZ-PRE-5.

---

## 1. Scope

In scope: (a) what counts as evidence that a validator did its duty; (b) how a late-but-live validator is protected from being jailed; (c) a quorum-protection rule for the epoch transition that applies a jail; (d) how a jailed validator is reinstated. Out of scope: equivocation (H0-11C), bootstrap-validator retirement (H0-11D), choosing the numeric threshold, and any implementation.

## 2. What the code does today (facts)

All references are to `main` `385431f`.

**Evidence.** After a block commits, the proposer of the *next* block collects precommits for it and puts the certificate into the next block's payload as `last_commit` (`node.rs`, `last_commit_evidence`). It waits until it has a precommit from every validator with voting power, or `COMMIT_GATHER_MS = 1000` ms, whichever comes first (`last_commit_ready`). A precommit that arrives after the commit but **before the next proposal is built** is added (`absorb_late_precommit`: same height, round and block hash, valid signature and power against the validator set effective at that height). A precommit that arrives after the proposal is built **counts as a miss**.

**Accounting.** When a block carrying `last_commit` commits, `check_liveness_after_commit` records, for every validator in the historical set at the evidence's height, "signed" or "missed". Each validator has a `LivenessWindow` ring buffer that also records *which proposer's evidence* produced each observation. `robust_missed_pct(f)` excludes every observation produced by the `f = floor((n-1)/3)` proposers that omitted that validator most often (deterministic tie-break on proposer id), so up to f malicious proposers cannot jail an honest validator alone.

**Policy.** Once a window is full and `robust_missed_pct` exceeds the threshold, the validator is jailed (status `Jailed`, stake untouched; liveness never burns). **Production defaults are a 500-block window and a 50% threshold, with start height 20** (`chain-forge-core`: `DEFAULT_LIVENESS_*`). **The live tests use a genesis override of 100 blocks and 20%.** Every "20%" figure in KNOWN_ISSUES §8 and below is that test override, not the production default.

**Enforcement.** The committee changes only at the epoch boundary (`commit_block`, Pass 4): a jailed validator is removed from the live set, its bond untouched. The only protection today is that **if enforcing would leave no committee at all, the whole transition is deferred.** A transition that leaves 3 of 4 seats (f = 0) is allowed: `validator_jail_live` JL-08 shows a 3-seat committee halts if any one of the three stops.

**Reinstatement.** Jail expiry makes a validator *eligible to ask for reinstatement* (`jail_expired`) and never reseats it. `unjail` returns it to `Candidate`. **There is no reinstatement transaction and no probation.** `JailRecord` already carries `jail_count`.

## 3. What the measurements show, and what they do not

Windows, merged `main`, two runs of the same test and load: `b9f1e7e` (2026-11-02) and `385431f` (2026-11-03) (KNOWN_ISSUES §8; only Dave's precommit *arrival* is delayed, he signs on time):

| Chain | First omissions | Half of his networked precommits omitted |
| --- | --- | --- |
| idle | 2200 ms (5/18 in run 1, 1/18 in run 2) | 3000 ms (both runs) |
| loaded (16 accounts) | 500 ms: 2/14 = 14% (both runs). **900 ms: 4/14 = 29% in run 1, 1/14 = 7% in run 2, not stable** | 1200 ms (7/14 in run 1, 9/14 in run 2) |

Healthy validators on a loopback devnet: worst plain miss 0% idle and loaded (integrity test, 652 s).

**These numbers are confounded and not repeatable at the 900 ms point.** During the loaded runs the block interval drifted **1.9×** (1071 to 2077 ms) in run 1 and **1.6×** (1269 to 2080 ms) in run 2 from per-block persistence cost, and the delay-0 control at the end omitted 3 of 11 (run 1) and 2 of 10 (run 2) precommits with no added delay. The transition from harmless to mostly omitted lies between about 900 and 1200 ms, but its exact position varies run to run. So the loaded miss rates mix (1) arrival lateness against the proposer's collection window and (2) the cost that stretches the interval and moves that window. **No threshold may be chosen from them until PERSIST-001 P-02b has been measured** (persistence memo, section 16). The tests also cannot say what a WAN does.

## 4. The problem

Absence from `last_commit` is treated as "offline", but it can also mean:
1. **late but live**: the precommit arrived after the proposer stopped waiting (the case measured above);
2. **omitted by the proposer** (mitigated by the f-proposer exclusion, which covers only f proposers);
3. **a slow chain**, where the collection window is short relative to block time (section 3).

A rule that jails on (1) or (3) punishes a validator that is doing its job. The ROADMAP records that the policy is *not* established safe against jailing a live validator.

## 5. Requirements (from owner directions, 2026-11-01..02)

- **R1 admissible evidence:** exactly what counts as proof of participation.
- **R2 attestation:** who attests that the evidence was received in time.
- **R3 binding:** evidence is bound to height, round and block hash.
- **R4 grace window:** how long after a block late evidence is still accepted.
- **R5 conflicting or missing evidence:** a defined, deterministic outcome.
- **R6 agreement:** every honest node reaches the same liveness decision from the same chain.
- **R7:** a validator that was offline during height h and signs a precommit for h *afterwards* must **not** be counted as having been present.
- **R8:** measure actual duties, not merely inclusion in a proposer's certificate.
- **R9:** requalification must demonstrate recovery.
- **R10:** quorum protection is one deterministic epoch transition covering suspension and replacement admission, independent of bonded QCB.
- **R11:** tests first, and no automatic suspension until all of the above are tested.

## 6. Late-participation evidence (Option A: grace across blocks)

**The core difficulty.** A precommit signature is valid forever; it carries no time. A rule that accepts a valid late signature (R1 only) fails R7, because it cannot tell "arrived 2 s late" from "signed an hour later by a validator that was down". Timeliness has to come from something the chain agrees on.

**A1 — proposer includes a late valid precommit for height h in any block up to h+G** (bounded count and age, like equivocation evidence: 16 items per block, 1000-block age). Simple, deterministic and self-verifying (reuses the single-vote path of `absorb_late_precommit`). **Fails R7**: nothing proves timeliness.

**A2 — A1 plus receipt attestations.** The late precommit is accepted only with co-signed attestations from at least f+1 validators ("I received v's precommit for (h, r, hash) before I committed height h+k"), so at least one honest validator vouches for timeliness. The attester's height is bound by its own consensus votes. **Meets R2, R3, R5 (conflicting attestations resolve deterministically by a fixed rule, to be specified), R7.** Costs: a new signed message type, extra block bytes, more evidence processing on the commit path, and a dependency on the attesters being timely themselves.

**A3 — presence evidence.** A validator counts as present at height h if a valid signed consensus message from it appears in the committed evidence of any block in h..h+G. A validator that is signing at h+1 was live around h. This is cheap and needs no new message, but it only helps with *sporadic* lateness. A validator that is chronically later than the collection window (the measured case) is absent from every certificate and gets no relief.

**Recommendation (for the owner to decide):** A2 for requirement R7, with A3 as a cheap first filter, and **a decision on the collection window itself**: the loaded measurements show the 1000 ms window is the binding constraint, and lengthening it trades block latency for evidence completeness. **Open: whether to measure arrival with a protocol-level clock at all**; this memo assumes not (non-deterministic across nodes, R6).

**Rule shape (for later).** The liveness input for block h becomes "present in the certificate, **or** covered by an admissible late-evidence item for h", evaluated when block h+G commits, so every node decides from committed data only (R6). The grace window G, the attestation threshold and the age limit are parameters in genesis, with bounds validated at startup like the existing `liveness` block.

## 7. Quorum protection (one deterministic transition)

**Today.** Pass 4 removes every jailed validator unless that empties the set. Example: jailing Dave in a 4-seat set leaves 3 seats (f = 0).

**Proposed rule.** The epoch transition computes the new committee as a single deterministic function of (committee at the boundary, jailed set, eligible bonded and personhood-verified candidates), in the order *jail enforcement, then replacement admission, then a check*:
1. Q1: the resulting committee must satisfy `n' >= N_MIN` (proposed `N_MIN = 4`, so f' >= 1), unless the genesis committee was smaller.
2. Q2: if it does not, the transition applies as many jails as the rule permits **in a deterministic order** (for example by jail epoch, then validator id) and leaves the rest *jailed but still seated* with their power unchanged and a persisted deferral marker, so every node agrees which validators are in that state.
3. Q3: deferred enforcement is re-evaluated at every epoch boundary.
4. Q4: replacement admission uses personhood and ordinary bonding only. **Independent of the QCB amount**: it must not let stake outbid a seated validator.

**Open decisions:** `N_MIN`; whether a jailed-but-seated validator may sign and count toward quorum during deferral (proposed: yes, since it is still seated and unslashed, and removing it is the very thing the rule refuses); and how a long deferral is surfaced to operators.

## 8. Reinstatement

Proposed: an explicit `ResumeValidator` transaction, valid only after jail expiry, that moves the validator to a **probation** state (no voting power, observed by the same evidence rule as section 6) and, after **N** consecutive observed blocks of participation, seats it at the next epoch boundary through the same admission step. **R9: expiry alone never reseats.** Repeated jailing escalates the jail duration using the existing `jail_count`. Open: N, the probation measurement, and whether probation counts toward the committee-size check in section 7 (proposed: no).

## 9. Test plan (tests first; each fails against current code where it demonstrates a gap)

1. Deterministic unit tests of the evidence rule over fixed certificate and late-evidence sequences, including a proposer that omits (f and f+1 proposers).
2. **R7 test:** a validator offline during h that signs for h afterwards is **not** counted present; an attested late precommit is.
3. **Agreement test (R6):** the same chain, replayed on four in-process nodes, produces identical liveness windows and the same jail height, including after a restart.
4. Quorum-protection transition tests: 4 seats with one jailed and a bonded candidate available (replacement restores n' = 4); no candidate (deferral, Q2 ordering); two jails at once.
5. Reinstatement: expiry does not reseat; probation requires N observed blocks; a relapse escalates the jail.
6. The existing `liveness_false_positive`, `late_precommit` and `validator_liveness_integrity_live` suites stay green as regression tests.
7. **After P-02b:** repeat `validator_precommit_delay_loaded_live` with the same load and compare the drift ratio (1.9× and 1.6× above) and the delay-0 control, then decide the thresholds.
8. Windows runs of every live test, per the project rule.

## 9a. Sequencing and dependencies

P-02b first (it changes the timing everything here depends on), then a threshold decision, then tests-first implementation. New on-chain evidence needs a storage format bump (persistence memo, D5) and a migration from the generation layout. NODE-TOKIO-1 is separate but interacts with section 7: a chain at f = 0 stops when any one validator crashes.

## 10. Open decisions for the owner

| # | Decision |
| --- | --- |
| B1 | Late-evidence scheme: A1 / A2 / A3 / combination (recommended A2 + A3) |
| B2 | Grace window G, attestation threshold, age limit |
| B3 | Collection window (currently 1000 ms): change it, or keep it and rely on grace |
| B4 | `N_MIN` for section 7; behaviour of jailed-but-seated validators during deferral |
| B5 | Reinstatement: N, probation measurement, escalation schedule |
| B6 | The jail threshold and window for production (defaults today: 50% over 500 blocks), chosen only after P-02b |
| B7 | Whether any of this needs an on-chain parameter vote (H0-12 governance) |

## 11. What is explicitly not claimed

That any section-6 scheme is sufficient against a coordinated majority; that the measured delays predict WAN behaviour; that the loaded numbers are stable (they are confounded); or that the current 20% / 100-block test policy is safe. The jail test's own summary line says the same: *"NOT established: that this policy cannot jail a live validator."*
