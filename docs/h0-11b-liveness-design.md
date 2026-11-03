# H0-11B — Liveness evidence, quorum protection and reinstatement: design memo

**Status (2026-11-03): DESIGN ONLY. Owner decisions B1–B7 recorded in section 10; sections 6a–6b (A2 specification and Byzantine-resistance argument), 12 (unresolved security questions) and 13 (acceptance tests) added for owner review.** Nothing in this memo is implemented or enabled. **Automatic validator suspension stays disabled in production genesis.** No change to the evidence rule is implemented without separate owner approval. H0-11B and BIZ-PRE-5 stay open.
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

## 6a. A2 specification: authenticated receipt attestations (owner decision B1)

**No shared wall clock (owner, 2026-11-03).** Nothing below uses a timestamp. "Timely" is defined only by protocol events: *the attester had not yet committed height h+k*. Local clocks are never an input to a decision.

**Statement.** An attester `a` (a validator in the committee at height h, with voting power) signs, with its ML-DSA consensus key and a dedicated domain-separation tag, the canonical bytes of
`Receipt{ chain_id, genesis_hash, epoch, h, r, block_hash, v, sig_digest, k_a }`
where `v` is the validator being vouched for, `sig_digest = SHA-256(v's precommit signature bytes)` (so the statement names exactly one signature, not "some precommit"), and `k_a` is the attester's own last-committed height when it first held that signature (`k_a >= h`). An honest attester signs it only if it holds a *verified* precommit from `v` for `(h, r, block_hash)` and its last-committed height was exactly `k_a` at first receipt. Items are batched: one attestation signs the Merkle root of a list of `(h, v, sig_digest)` leaves, to bound ML-DSA signature bytes (3,309 per signature).

**Carriage.** A proposer includes `LateEvidence{ precommit, attestations }` items in the block payload, bounded per block (default proposal: 16 items) and by age: included in a block at height `h' ∈ [h+1, h+G]`.

**Deterministic verification (every node, from committed data only).** An item for `(h, v)` is *admissible* iff all of:
1. `h` is within `[H' − G, H' − 1]` for the including block's height `H'`, and the block at `h` is the committed block (its hash equals `block_hash`);
2. `v` is in the committee recorded for height `h` (`historical_validator_sets`), and `precommit` is a valid signature by `v` over `(chain_id, h, r, block_hash)`; `sig_digest` matches it;
3. the attestations are from **distinct** members of the committee at `h`, each a valid signature over its Merkle root, with a valid Merkle path to the leaf for `(h, v, sig_digest)`, with `k_a ∈ [h, H'−1]` (an attester cannot have held it from a future height);
4. the attesting voting power is **strictly greater than one third of the total power of the committee at h** (this is the "f+1" condition expressed in power, so at least one honest attester is among them);
5. no other item for `(h, v)` was admitted in an earlier block (first admissible item wins; later duplicates are ignored, deterministically).
Then `(h, v)` is credited as *present*. **Evaluation point:** the liveness window entry for `(h, v)` is finalised when block `h+G` commits, from the certificate in block `h+1` plus all admissible items in blocks `h+1..h+G`. (R6: a function of committed blocks only.)

**A3 as the initial filter.** `(h, v)` is credited without any attestation when `v`'s signature on a consensus message at height `h` appears in the certificate of block `h+1` (the existing path), or in the committed evidence of any block in `h+1..h+G` (A3). Attestations are required only for the validators still uncredited, so a healthy chain pays nothing.

**Why an f+1 count alone is not enough, and what is added here.** A bare count proves that more than f validators *said* they received a signature. It does not (a) bind the claim to one specific signature, (b) bind it to the chain, epoch and height (replay), (c) bind the attester to a protocol position, (d) stop the same attester contributing to several conflicting claims, or (e) say how the claim relates to the passage of protocol time. The statement above fixes (a)–(c): the signed bytes include `sig_digest`, the domain tag, `chain_id`, `genesis_hash`, `epoch` and `k_a`. (d): attester power is counted once per `(h, v)`, and an attester that signs two different `sig_digest` values for the same `(h, r, v)` has produced equivocation-like evidence (a v that signs two precommits for the same height and round is already an equivocator; attestations of both are inadmissible). (e) is the residual limitation stated in section 12 (Q1).

## 6b. Byzantine-resistance argument (assumption: fewer than one third of total power is Byzantine; signatures are existentially unforgeable)

- **C1, no forgery of presence.** To credit `(h, v)`, an item needs a valid signature by `v` (unforgeable), and attesting power above one third, which cannot come from Byzantine validators alone, so **at least one honest attester signed**. An honest attester signs only for a signature it received and verified. So a credit exists only if `v` really produced a valid precommit for `(h, r, block_hash)` and an honest validator held it at a height `k_a` in `[h, h+G−1]`.
- **C2, no false absence from a few omitting proposers.** An item is admissible in *any* of `G` consecutive blocks, so a Byzantine proposer cannot suppress it unless every proposer in the window is Byzantine. With deterministic round-robin and fewer than a third of seats Byzantine, `G >= f+1` consecutive proposers contain an honest one. (For stake- or personhood-weighted proposer selection the guarantee is probabilistic; see Q4.)
- **C3, agreement.** Admissibility and finalisation are pure functions of committed blocks `<= h+G` and the recorded committee at `h`. Nodes that replay the same chain reach the same liveness window and the same jail height, including after restart (test A2-T6).
- **C4, no inflation by attesters alone.** Byzantine attesters cannot raise `v` from absent to present: they are below one third and the honest ones will not attest to a signature they never received.
- **What is *not* shown:** that a credited validator was online *when height h was decided*. C1 only places the signature in an honest validator's hands within `G` blocks. See Q1.

## 7. Quorum protection (one deterministic transition)

**Today.** Pass 4 removes every jailed validator unless that empties the set. Example: jailing Dave in a 4-seat set leaves 3 seats (f = 0).

**Proposed rule.** The epoch transition computes the new committee as a single deterministic function of (committee at the boundary, jailed set, eligible bonded and personhood-verified candidates), in the order *jail enforcement, then replacement admission, then a check*:
1. Q1: the resulting committee must satisfy `n' >= N_MIN` (proposed `N_MIN = 4`, so f' >= 1), unless the genesis committee was smaller.
2. Q2: if it does not, the transition applies as many jails as the rule permits **in a deterministic order** (for example by jail epoch, then validator id) and leaves the rest *jailed but still seated* with their power unchanged and a persisted deferral marker, so every node agrees which validators are in that state.
3. Q3: deferred enforcement is re-evaluated at every epoch boundary.
4. Q4: replacement admission uses personhood and ordinary bonding only. **Independent of the QCB amount**: it must not let stake outbid a seated validator.

**Owner decision B4 (2026-11-03):** the voting committee must be at least four members (`N_MIN = 4`) and quorum safety is preserved. A jailed-but-seated validator keeps *voting eligibility* during deferral, but **is never counted as having voted unless a valid vote from it is actually present**: the quorum check, the liveness accounting and every evidence rule use signed votes only, never the seat. Prolonged deferrals are surfaced to operators (a persisted deferral counter, a log line every epoch and an API field). Consequence recorded as Q5: a deferred, genuinely offline validator still sits in the quorum denominator.

**Previously open:** `N_MIN`; whether a jailed-but-seated validator may sign and count toward quorum during deferral (proposed: yes, since it is still seated and unslashed, and removing it is the very thing the rule refuses); and how a long deferral is surfaced to operators.

## 8. Reinstatement

Proposed: an explicit `ResumeValidator` transaction, valid only after jail expiry, that moves the validator to a **probation** state (no voting power, observed by the same evidence rule as section 6) and, after **N** consecutive observed blocks of participation, seats it at the next epoch boundary through the same admission step. **R9: expiry alone never reseats.** Repeated jailing escalates the jail duration using the existing `jail_count`. **Owner decision B5 (2026-11-03):** an explicit `ResumeValidator` authorization is required; the validator goes through probation and must demonstrate reliability before being reseated; probationary validators do **not** count toward `N_MIN`. **N is determined later** (after the evidence rule and P-02b measurements).

## 9. Test plan (tests first; each fails against current code where it demonstrates a gap)

1. Deterministic unit tests of the evidence rule over fixed certificate and late-evidence sequences, including a proposer that omits (f and f+1 proposers).
2. **R7 test:** a validator offline during h that signs for h afterwards is **not** counted present; an attested late precommit is.
3. **Agreement test (R6):** the same chain, replayed on four in-process nodes, produces identical liveness windows and the same jail height, including after a restart.
4. Quorum-protection transition tests: 4 seats with one jailed and a bonded candidate available (replacement restores n' = 4); no candidate (deferral, Q2 ordering); two jails at once.
5. Reinstatement: expiry does not reseat; probation requires N observed blocks; a relapse escalates the jail.
6. The existing `liveness_false_positive`, `late_precommit` and `validator_liveness_integrity_live` suites stay green as regression tests.
7. **After P-02b:** repeat `validator_precommit_delay_loaded_live` with the same load and compare the drift ratio (1.9× and 1.6× above) and the delay-0 control, then decide the thresholds.
8. Windows runs of every live test, per the project rule.
9. A2 tests are listed in section 13.

## 9a. Sequencing and dependencies

P-02b first (it changes the timing everything here depends on), then a threshold decision, then tests-first implementation. New on-chain evidence needs a storage format bump (persistence memo, D5) and a migration from the generation layout. NODE-TOKIO-1 is separate but interacts with section 7: a chain at f = 0 stops when any one validator crashes.

## 10. Owner decisions (2026-11-03)

| # | Decision (as given by the owner) | Effect on this memo |
| --- | --- | --- |
| B1 | Design A2 authenticated receipt attestations, with A3 certificate evidence as an initial filter. An f+1 threshold alone does not prove timely participation; provide a Byzantine-resistance argument and a deterministic verification specification. | Sections 6a, 6b. Open limits in section 12 (Q1–Q4). |
| B2 | Grace-window and evidence parameters are genesis-configurable with validated bounds. Numerical defaults wait for P-02b measurements. | `G`, per-block item cap, age limit, power threshold are genesis fields (validated at startup like the `liveness` block); **no numbers chosen**. Constraint recorded: `G >= f+1` for round-robin (C2). |
| B3 | Retain `COMMIT_GATHER_MS = 1000` for now. | Unchanged. |
| B4 | Minimum four-member voting committee; quorum safety preserved; jailed-but-seated validators keep voting eligibility but are never counted as having voted without a valid vote; surface prolonged deferrals. | Section 7. |
| B5 | Explicit `ResumeValidator`, probation, demonstrated reliability before reseating; probation does not count toward `N_MIN`; N later. | Section 8. |
| B6 | Defer production liveness thresholds until persistence measurements exist. | No threshold in this memo. |
| B7 | Genesis-only configuration for the initial release; defer on-chain governance changes. | No H0-12 governance parameter for this. |

**Clock assumption (owner):** no shared protocol-level wall clock. Receipt evidence must be cryptographically authenticated and tied to verifiable protocol events; local timestamps alone are insufficient.

**Restrictions still in force:** no consensus-policy implementation; no merges without separate authorization; automatic suspension stays disabled in production; H0-11B, H0-3b and BIZ-PRE-5 stay open.

## 11. What is explicitly not claimed

That any section-6 scheme is sufficient against a coordinated majority; that the measured delays predict WAN behaviour; that the loaded numbers are stable (they are confounded); or that the current 20% / 100-block test policy is safe. The jail test's own summary line says the same: *"NOT established: that this policy cannot jail a live validator."*

## 12. Unresolved security questions (for owner and reviewer)

- **Q1, what "timely" means without a clock.** A2 proves that an honest validator held a valid signature for height `h` while at height `k_a <= h+G−1`. A validator that was *down* during `h` can still sign a precommit for the (public, committed) block `h` after it returns and have it attested within `G` blocks. So presence is credited at granularity `G` blocks, and requirement R7 ("offline during h, signs for h afterwards, must not be counted") holds **only for outages longer than `G` blocks**. Options: keep and state it; add the attester statement "held before I cast my precommit at height `k_a`" (rejects most backfilling, but also rejects the measured case, where the delayed precommit arrives after other nodes have already committed); or require `v` to have a timely consensus message within the window (A3 only, which cannot help a chronically late validator). **Decision needed.**
- **Q2, backfill farming.** A validator could stay mostly offline and pay for presence by signing historical precommits cheaply within `G`. Are caps, rate limits per validator, or "presence by attestation counts at most X of the window" required?
- **Q3, attestation size and work.** ML-DSA-65 signatures are 3,309 bytes. At an f+1 power threshold on a 100-member committee that is >100 KB per unbatched item. Batching by Merkle root is proposed; the verification cost on the commit path and the cap (16) are untested.
- **Q4, proposer selection.** The omission argument (C2) assumes round-robin. For any weighted or randomised selection, `G` needs a probabilistic bound.
- **Q5, deferral and the quorum denominator.** A deferred jailed validator that is truly offline still counts in the quorum denominator, so deferral can lower liveness while protecting `n' >= 4`. Decide the rule for an *eventual* forced removal, if any, and an operator alarm.
- **Q6, equivocating or double-attested precommits.** Rule (d) above makes both attestations inadmissible; confirm that no honest attester can be tricked into attesting two signatures and that equivocation evidence for `v` is then produced (H0-11C interaction).
- **Q7, replay and format.** New block payload fields change the block format and the persistence format (persistence memo D5): migration and the genesis-hash implications need a decision.
- **Q8, attester incentive and honesty.** Honest attesters sign only on real receipt; there is no reward or penalty. Is the absence of an incentive acceptable at G blocks of latency?

## 13. Proposed acceptance tests (all tests first; each marked "fails today" must fail against current code)

| ID | Test | Expectation |
| --- | --- | --- |
| A2-T1 | Deterministic unit: fixed certificates plus items | Admissibility truth table for rules 1–5 (wrong height, wrong chain/epoch, non-member, duplicate attester, power exactly one third, just above one third, `k_a` out of range, future-height claim). |
| A2-T2 | Forgery | No admissible item exists without `v`'s real signature; attester signatures from `<= f` Byzantine validators never reach the threshold (fails today: no mechanism). |
| A2-T3 | Replay | The same item rejected on another chain, epoch or height (domain-separation bytes). |
| A2-T4 | R7 boundary | Validator offline for `G+1` blocks and signing historical precommits afterwards is **not** credited; offline for fewer than `G` blocks is credited (states the Q1 limit explicitly). |
| A2-T5 | Proposer omission | `f` consecutive Byzantine proposers omitting the item still leave it admissible via an honest proposer within `G`. |
| A2-T6 | Agreement | Replay the same chain on four in-process nodes and after a restart: identical windows and jail height. |
| A2-T7 | Conflict | Two different `sig_digest` for one `(h, r, v)` are both inadmissible and produce equivocation evidence. |
| A2-T8 | Size and cost | Per-block verification time and bytes at 4, 21, 100 validators with the cap set; recorded on Windows. |
| A2-T9 | Live | Re-run `validator_precommit_delay_loaded_live` at 500, 900, 1200, 1500 ms with A2 enabled in a test genesis: late-but-live Dave credited, never jailed; an offline Dave jailed. Windows run required before any ✅. |
| QP-T1..3 | Quorum protection | 4 seats with one jail and a candidate; no candidate (deferral, deterministic order); two jails at once. A jailed-but-seated validator with no vote is never counted as having voted. |
| RS-T1..3 | Reinstatement | Expiry alone never reseats; probation does not count toward `N_MIN`; relapse escalates `jail_count`. |
| REG | Regression | `liveness_false_positive`, `late_precommit`, `validator_liveness_integrity_live` stay green. |
