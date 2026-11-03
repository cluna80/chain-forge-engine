# PERSIST-001 P-02b — Per-block persistence cost: measurement plan, options and acceptance criteria

**Status (2026-11-03, revised after owner decisions): DESIGN ONLY, DRAFT for owner review.** Documentation only. No code, no consensus-policy change, no format change is made by this document. Implementation needs separate approval. H0-3b stays open. Authorised by the owner on 2026-11-03 ("documentation-only design in parallel; define performance measurements and acceptance criteria while preserving crash durability, state-root consistency and signing-guard safety").

**Builds on:** `docs/persist-001-p02-design.md` (D1, §8.1, §16), KNOWN_ISSUES §9, the P-02a implementation (`chain-forge-node/src/persistence.rs`, `persist_state` in `node.rs`). **Feeds:** `docs/h0-11b-liveness-design.md` (B6: no liveness threshold until this is measured).

---

## 1. The problem, from the code (facts on `main` `385431f`)

`persist_state()` runs on the consensus event loop at the end of every `commit_block`. Each call:
1. serialises **all eight** components with `to_string_pretty`: `state.json`, `identity.json`, `validators.json`, `agents.json`, `slashing.json`, `chain_store.json`, `historical_validator_sets.json`, `live_validator_set.json`;
2. creates a new `snapshots/gen-N` directory and writes each file with temp + fsync + rename (`write_atomic_bytes`), SHA-256-hashing each;
3. fsyncs the generation directory, writes `manifest.json`, fsyncs again, fsyncs `snapshots/`, then replaces `CURRENT`, then removes generation N−2.

`chain_store.json` holds every block and grows with height, so **per-block cost is O(chain length)** and the total cost over a chain is quadratic. Measured before P-02a (KNOWN_ISSUES §9): 27 MB by height ~190; commit interval ~1.2 s growing to 7.8 s by height 175–200 under load; an idle chain stayed ~2.4 s per block. P-02a added more fsyncs per block (directory fsyncs, manifest, `CURRENT`) and the cost has **not been re-measured since**. On Windows the loaded delay test saw interval drift 1.9× (run 1) and 1.6× (run 2) over only ~14 measured blocks (KNOWN_ISSUES §8).

Existing instrument: the ignored test `persist001_profile_commit_path` (in-process 4-validator commit path; prints commit ms, `chain_store.json` size, serialise and write times, compact-serialise time, an atomic-write probe and a full `persist_state()` call).

## 2. Invariants every option must preserve (hard requirements)

- **I1 crash durability.** After any crash the node restores the last fully committed state or fails closed. No silent fallback to genesis, no partially applied state. (P-02 memo §1, §6.)
- **I2 state-root consistency.** The restored state's root equals the manifest's `state_root` and the committed block's root; the STATE-PERF golden roots (#46) must not change; the genesis hash check (`compute_genesis_hash`) is unchanged.
- **I3 signing-guard safety (D1, §8.1).** The signing guard is durable before any signature leaves the node; no vote or proposal for height *h+1* is produced until the state for height *h* is durable **unless the owner revisits D1 explicitly**; the guard may be newer than state, never older than an emitted signature; guard ahead of state means abstain, not sign (existing rule); guard with no state at height > 0 is fatal.
- **I4 deterministic content.** Bytes written for the same state are identical across runs and platforms (the manifest hashes them).
- **I5 migration.** A data directory written by P-02a (`format_version = 1`, `snapshots/gen-N`) loads after the change, or is migrated by a specified, tested step. Any format change bumps `FORMAT_VERSION`.
- **I6 no new unguarded state.** The proposal-signing gap (named follow-on gap, memo §14) is not made worse.

## 3. Measurement plan (before choosing anything)

All numbers are reported, none invented. Machine and OS are named in every result (Windows BossKing is the reference; sandbox numbers are labelled sandbox).

| ID | What | How | Output |
| --- | --- | --- | --- |
| M0 | **Baseline on current `main`** (the missing re-measure after P-02a) | `persist001_profile_commit_path` at heights 25, 50, 100, 200, 300, 450, 600 with 10 transfers per block; also with `CF_PERSIST_PROFILE_NODISK=1` to isolate `persist_state` from the rest of the commit path | Table: commit ms, `chain_store.json` MB, serialise ms, write ms, `persist_state()` ms, bytes per block |
| M1 | Per-phase breakdown inside `write_snapshot` | Temporary timing around: serialise, per-file write+fsync, hashing, directory fsyncs, manifest, `CURRENT`, prune. One build, Windows and Linux | ms per phase at heights 50 / 200 / 500, so we know whether fsync count or byte volume dominates |
| M2 | Which files grow | Print the size of each of the eight files at the same heights | Table; expectation to confirm: only `chain_store.json` grows materially |
| M3 | Commit interval under live load | Existing `validator_precommit_delay_loaded_live` setup (16 throttled accounts) extended to a longer run, sampling the median interval at heights ~50, ~150, ~250 | Interval per height band; the drift ratio (1.9× and 1.6× recorded so far) |
| M4 | Delay-0 control | The closing 0 ms row of the same test | Omissions of Dave's precommit with no injected delay (3 of 11, then 2 of 10 so far) |
| M5 | Cost of fsync alone | Write N empty files with and without fsync on Windows/NTFS and Linux (reuses the `fsync_probe`) | Fixed cost per fsync; separates the constant from the O(chain) term |
| M6 | Restart time | Time `load_persisted_state` at heights 50 / 200 / 500 | Needed for any journal-and-replay option |

### 3a. M0 baseline plan (revised; runs first, before any prototype code)

**Question M0 answers:** on current `main`, what is the persistence cost per block, how does it grow, and are the provisional targets (1.25×, p95 50 ms, p99 100 ms, 20,000 blocks) realistic on the test hardware, including the fixed cost of the fsyncs P-02a already added?

1. **Fixed commit, fixed hardware.** Record the commit hash, OS, CPU, disk type, antivirus exclusions (Avast hazard, KNOWN_ISSUES), and `CARGO_INCREMENTAL=0`. Reference machine: BossKing (Windows/MINGW64). The sandbox is a second, labelled data set.
2. **Instrumentation only.** Use `persist001_profile_commit_path`, extended with a per-call latency vector and the M1 phase timings behind `#[cfg(test)]`; no production code change. Latency is recorded per block (not averaged), so p50/p95/p99 and the maximum can be computed.
3. **Two modes.** (a) the in-process 4-validator commit path (fast, can reach 20,000 blocks), with `CF_PERSIST_PROFILE_NODISK=1` as the control; (b) a live 4-node run at a throttled load for a shorter, labelled number of blocks, because the in-process path excludes networking and the consensus loop's other work.
4. **Heights sampled:** 25, 50, 100, 200, 300, 450, 600, 1,000, 2,500, 5,000, 10,000, 20,000, with `chain_store.json` size recorded at each.
5. **Report:** per-height p50/p95/p99/max of `persist_state()`, the growth ratio against the P1 definition, the per-phase split (M1), the fsync-only floor (M5), and wall-clock time to reach 20,000 blocks.
6. **Feasibility rule.** If M5 shows the fixed cost of the current number of fsyncs per block already exceeds the p95 target, then the target is unreachable *without reducing fsync count* and the report says so with the number; the proposal is then to revise the target or the number of syncs, not to hide the cost.
7. **Stop point.** M0 results go to the owner. The prototype below is not started until they are reviewed.

M0 has **not** been run yet in this session. Nothing in this document is a measurement.

M0 is the gating item: **no option is chosen before M0 and M1 exist on Windows.** If M1 shows the fixed fsync count dominates rather than chain size, Option 1 below will not be enough, and the choice changes.

## 4. Options

**Option 1, cheap constant factors.** Compact JSON instead of pretty JSON; reuse buffers; skip rewriting the seven small files when their bytes are unchanged (keep the previous generation's files by hard link or by referencing them from the manifest). Does *not* remove the O(chain) term. Risk: low. Expected to help only the constant.

**Option 2, split `chain_store` into an append-only block log plus a small mutable snapshot (recommended first implementation, subject to M0/M1).** Blocks are immutable once committed. Store them in segment files, append each new block (O(block) bytes), fsync the segment. The generation's `chain_store` entry becomes a small descriptor: segment list, per-segment length and SHA-256, and the tail hash. The manifest still binds everything to `state_root` and the file hashes. Per-block cost becomes O(block size + small files), independent of height. Risks: new torn-tail cases (a partially appended block); a format bump and migration from P-02a (I5); the `chain_store` readers (`/blocks` APIs, light-client proofs) must read from segments.

**Option 3, off-loop serialisation and writing with a durability barrier.** A writer thread owns the disk; the consensus loop hands it an immutable snapshot of what changed and continues. The barrier required by D1/§8.1 is kept: the node does not sign for *h+1* until the writer reports height *h* durable. This overlaps the write with the one-second collection window and proposal propagation, so it hides cost without reducing it, and it cannot help if persistence takes longer than the gap before the next vote. It also adds a failure mode (writer thread panic or error) that must stop signing. Complements Option 2; alone it is not sufficient.

**Option 4, write-ahead journal plus periodic checkpoint.** Append one record per block (executed delta and block) to a journal; write a full generation every K blocks. Cheapest per block, most complex: needs deterministic replay (STATE-PERF roots are the guardrail), torn-tail rules, and a K-dependent restart time (M6). Larger change; defer unless Option 2 is insufficient.

**Not proposed:** weakening D1 (voting before the previous height is durable) to buy speed. If the owner wants that, it is a separate, explicit decision with its own double-sign analysis (§8.1 item 4 already shows what the guard covers).

## 4a. Option 2 prototype: append-only block log (owner approved 2026-11-03 for benchmarking and crash-safety evaluation only)

**Authorisation boundary.** A prototype for benchmarking and crash-safety evaluation is approved. **Production storage-format migration is NOT authorised.** The prototype must not change the format `main` writes; it runs behind a test-only path or feature flag and a separate data directory, and cannot open a production directory. D1 (durable state before the next height is voted or proposed) is retained **without relaxation**.

**Record format.** One record per committed block, in segment files `blocklog/seg-<first_height>.log`.
`magic(4) | format_version(1) | height(8, LE) | payload_len(8, LE) | payload | prev_hash(32) | record_hash(32)`
where `payload` is the canonical block bytes already used by the state (bytes, not pretty JSON), `prev_hash` is the previous record's `record_hash`, and `record_hash = SHA-256(magic .. prev_hash)` over everything before it. The chain of hashes makes truncation, reordering and a middle-segment change detectable. The first record's `prev_hash` is the genesis hash.

**Integrity.** A record is valid only if magic, version, length bounds, height continuity (`height == previous + 1`) and `record_hash` all check. A short read at the tail is a torn write; any other failure is corruption.

**Commit point and torn-write recovery.** Per block: append the record, `fsync` the segment, then write the (small) snapshot generation whose manifest records `{log_tail_height, log_tail_hash, segment list with lengths}`. The manifest remains the commit point, as today.
- Crash after the append, before the manifest: the log has a block *beyond* the manifest's tail. On restart the tail beyond the manifest is **discarded** (truncated), and the node restores the manifest's height (same as P-02a roll-back).
- Crash mid-append (torn record): the incomplete record is beyond the manifest tail, so it is truncated, never trusted.
- A record **within** the manifest's tail that fails validation is fatal (never repaired, never fall back to genesis).
- Truncation is permitted only when the manifest proves the damaged region is beyond the committed tail; otherwise fatal.

**Replay.** State is not rebuilt from the log in the prototype: the snapshot still holds state, and the log holds blocks. Replay (re-executing blocks from a checkpoint) is evaluated separately as Option 4 and must match the STATE-PERF golden roots byte for byte before it is considered.

**Checkpointing.** The snapshot generation is the checkpoint. The prototype keeps today's N and N−1 generations; each manifest binds the log tail. Whether a checkpoint every K blocks (instead of every block) is allowed is evaluated against D1 and is **not** assumed.

**Compaction.** The prototype does not delete blocks. Compaction and pruning (validators and sync nodes may need old blocks) are design questions only; any pruning must not make a recorded `prev_hash` chain unverifiable from the retained anchor.

**Migration (design only; not authorised to run on production).** `FORMAT_VERSION` 1 (`chain_store.json` per generation) to 2 (log plus descriptor) as a one-way, atomic, hash-verified step: write the log from `chain_store.json`, verify the tail hash and `state_root`, write a v2 generation, flip `CURRENT`, keep the v1 generation until the next successful commit. Downgrade is refused with a clear error. This is specified so it can be reviewed, not executed.

**Signing-guard consistency.** Unchanged and required: the guard is written durably before a signature leaves the node; no signature for *h+1* until the log record, the snapshot generation and the manifest for *h* are all durable (D1); the guard may be newer than the log tail (abstain, existing rule) and never older than an emitted signature; a guard at height > 0 with no log and no snapshot is fatal. The log adds one new failure mode: a log tail that is *ahead* of the manifest. It is truncated to the manifest and never used to move the node forward.

### Prototype acceptance criteria (benchmarking and crash safety only)

1. **Cost:** per-block write is O(block size), measured by bytes written per block (PB-T2) at heights 50 / 1,000 / 20,000 and by latency p95/p99 against the provisional targets.
2. **Equivalence:** the block sequence read back from the log equals the sequence the in-memory chain holds; the restored `state_root` equals the manifest's equals the live root.
3. **Torn writes:** PB-T3 to PB-T6 pass for every byte offset of a record (truncate at each offset of the last record) and for a corrupt byte in each record field.
4. **Guard interplay:** PB-T7 passes; no run produces a conflicting signature or a silent genesis start (hard zero).
5. **Determinism:** identical bytes for identical blocks on Windows and Linux (PB-T10).
6. **Sustained run:** at least 20,000 committed blocks with identical state roots across honest nodes (P5, P6).
7. **No production reach:** the prototype refuses to open a production data directory and does not alter `FORMAT_VERSION` written by `main`.

## 5. Recommended path (for the owner to decide)

1. Run M0–M2 (and M5) on Windows and in the sandbox. Report. No code changes beyond timing instrumentation behind `#[cfg(test)]`.
2. If `chain_store` growth dominates (expected): Option 2 for the log, Option 1 compaction for the small files; Option 3 only if M1 shows the remaining fsync cost still erodes the gather window.
3. Every option is tests-first (section 7) and lands as its own PR, not combined with H0-11B or the deletion-root correction (§13 in KNOWN_ISSUES).

## 6. Acceptance criteria

**Performance. Provisional owner targets (2026-11-03), to be validated by M0 before any implementation; if M0 shows them unrealistic on the test hardware, the evidence and a proposed revision are reported first:**
- **P1 growth.** Commit-interval growth ratio **<= 1.25×** (interval in the last band over the first band, same load, heights ~50 / ~150 / ~250 and the end of the sustained run).
- **P3 latency.** Persistence latency (the whole `persist_state()` call as seen by the commit path) **p95 <= 50 ms and p99 <= 100 ms**.
- **P5 sustained load.** A sustained-load measurement of **at least 20,000 committed blocks**, with P1 and P3 evaluated over the run.
- **P6 agreement.** Identical state roots across honest nodes at every sampled height of that run.
- **P2 loaded delay test.** Re-run `validator_precommit_delay_loaded_live` before and after with identical load; compare the drift ratio and the delay-0 control. Baselines: 1.9× / 1.6× and 3 of 11 / 2 of 10 omitted. Reported, not a pass/fail number.
- **P4 restart time** reported at heights 50 / 200 / 500 / 20,000 (no unbounded regression; a bound is proposed after M0).
- **Zero** silent genesis fallback and **zero** conflicting signatures in all recovery tests (also under S4).

**Safety (all must pass; none is relaxed for performance):**
- **S1** the P-02 torn-file matrix and the P-02a crash-injection tests (L, G, A, F, R, D) pass unchanged, on Windows.
- **S2** new crash-injection tests for each new write step (below), including the tail of a log segment.
- **S3** restored root equals the manifest root equals the live root; STATE-PERF golden roots unchanged; `compute_genesis_hash` unchanged.
- **S4** signing-guard ordering tests: guard durable before the signature leaves the node; no signature for *h+1* before *h* durable; guard-ahead-of-state abstains; guard-without-state fatal.
- **S5** a P-02a data directory loads (or migrates) and a downgrade attempt is refused with a clear error.
- **S6** Windows (BossKing) run of every test above before any ✅, per the project rule.

## 7. Tests to write first (each should fail against current code where it demonstrates the gap)

| ID | Test | Expectation |
| --- | --- | --- |
| PB-T1 | Per-block persistence time at heights 50 / 200 / 500 (ignored profile test) | Today grows with height (fails the flatness bound once the owner sets it) |
| PB-T2 | Bytes written per block | Today O(chain); target O(block) |
| PB-T3 | Crash after appending block *h* to the log, before the manifest | Restart restores *h−1* and fails closed on a truncated tail; no half block visible |
| PB-T4 | Crash after the manifest, before `CURRENT` | Restart restores the previous generation (existing behaviour, re-asserted for the log) |
| PB-T5 | Corrupt one byte in a middle segment | Fatal, never repaired silently |
| PB-T6 | Torn tail of the last segment | Truncated to the last complete record only when the manifest proves it is beyond the committed height; otherwise fatal |
| PB-T7 | Signing guard at *h*, state at *h−1* | Abstain (existing rule) and no conflicting signature |
| PB-T8 | Writer error or panic (Option 3) | The node stops signing and exits non-zero; never continues voting with undurable state |
| PB-T9 | Migration from a P-02a directory | State root identical before and after; second start is a no-op |
| PB-T10 | Determinism: same blocks, two runs, Windows and Linux | Identical segment and descriptor bytes |

## 8. Unresolved questions for the owner

1. **Targets: decided provisionally (2026-11-03)** (section 6); to be confirmed or revised after M0.
2. **Option 2:** approved as a prototype for benchmarking and crash safety only; production migration not authorised.
3. **D1: retained without relaxation** (owner, 2026-11-03).
4. **Retention.** How many blocks must stay fast to read after segmenting (relevant to `/blocks` and sync)? Is pruning old segments ever allowed on a validator?
5. **Windows power-loss.** Directory fsync via `FILE_FLAG_BACKUP_SEMANTICS` + `FlushFileBuffers` is still unverified for power loss (memo §15). A log makes this matter more, because the tail is written every block.
6. **Retry policy.** Still a separate Windows-validated decision (memo §14); this design assumes none.
7. **NODE-TOKIO-1** (a tokio time-driver assertion that killed one node once) is separate, but any writer thread added by Option 3 must not widen it.

## 9. Not claimed

That any option will meet a target that has not been measured; that sandbox numbers predict Windows; that the loaded-delay results will improve by a particular amount (the 900 ms point already varies between identical runs); or that crash durability under power loss on Windows is verified.

## 10. M0 results — Linux sandbox, debug build (2026-11-03)

**These are debug-build, Linux-sandbox measurements. They are not release-build numbers and not Windows (BossKing) numbers.** Both are still to be measured.

**Pinned configuration.** Code: `main` `385431f` plus the `cfg(test)` instrumentation commit `b02b895` (branch `perf/p02b-m0`; the production write path is unchanged in non-test builds). Hardware: sandbox VM, Linux 6.18, 4-core Intel Xeon 2.8 GHz, 15 GB RAM, virtio disk. Profile: `dev` (unoptimized + debuginfo). Workload: in-process 4-validator commit path, 10 transfers per block; node 0 persists (disk run) and nodes 1–3 execute the same proposals with no disk; live state roots compared on every block. No networking: commit time is not a real block interval. Tests: `persist001_m0_baseline`, `persist001_m5_fsync_floor`.

**Disk-backed run: 681 blocks** (stopped by its 45-minute cap, not by a failure).

| Heights | Persist p50 | p95 | p99 | max | State persisted per block |
| --- | --- | --- | --- | --- | --- |
| 0–50 | 227 ms | 435 ms | 490 ms | 490 ms | 5.0 MB |
| 50–100 | 706 ms | 865 ms | 939 ms | 939 ms | 9.9 MB |
| 100–200 | 1,314 ms | 1,744 ms | 1,789 ms | 1,795 ms | 19.9 MB |
| 200–300 | 2,269 ms | 2,718 ms | 2,734 ms | 3,643 ms | 29.9 MB |
| 300–400 | 3,097 ms | 3,597 ms | 3,638 ms | 3,654 ms | 39.9 MB |
| 400–500 | 4,104 ms | 4,691 ms | 5,468 ms | 5,782 ms | 49.8 MB |
| 500–681 (late heights) | **5,457 ms** | **6,359 ms** | **6,784 ms** | 7,152 ms | **67.9 MB** at the final window |

- **Commit-interval growth: 9.7×** (667 ms around height 50 to 6,451 ms at the end).
- **Phase split** (median of the last 50 blocks): serialisation ≈ 2,009 ms; file write + fsync + hashing ≈ 4,061 ms; pruning the old generation ≈ 32 ms; `export_snapshot` 0.01 ms; state root 0.25 ms; manifest, `CURRENT` and the three directory fsyncs 0.2–0.8 ms each. The cost is the whole-chain rewrite, not the fsync sequence or manifest.
- **State-root agreement:** the four nodes agreed on every block of the measured run (0 disagreements).
- **Against the provisional targets:** growth ≤ 1.25× (measured 9.7×) and persistence p95 ≤ 50 ms / p99 ≤ 100 ms (measured 6,359 / 6,784 ms at late heights) are missed by large margins. The 20,000-block run **could not be reached** with the current design in this sandbox.

**M5 fsync-only floor** (real `write_snapshot`, eight 1 KB files, 2,000 calls): p50 6.9 ms, **p95 10.1 ms**, p99 12.5 ms, max 171 ms. Phases (p50): files write+fsync+hash 3.9 ms, prune 1.1 ms, `CURRENT` 0.7 ms, manifest 0.5 ms, directory fsyncs 0.14–0.22 ms. With state size removed, the current number of fsyncs fits inside the 50 ms p95 target on this disk; Windows may differ.

**No-disk control** (same workload, persistence off): commit p50 203–205 ms flat from height 0 to over 3,000, p99 ≤ 266 ms, all four nodes' roots agreeing on every block. **Final: 6,453 blocks in 5,400 s (stopped by the 90-minute cap, not 20,000).** Commit p50 203 / 203 / 198 / 186 ms over heights 0–1,000 / 1,000–3,000 / 3,000–5,000 / 5,000–6,453 (p99 251 / 263 / 256 / 233 ms, max 335 ms): **no growth**. All four nodes' roots agreed on every block.

**Not measured.** A release build; a live 4-node run with networking; Windows. Debug-build serialisation is likely overstated relative to release.

## 11. Option 2 prototype v1 — first benchmark (Linux sandbox, **debug build**, exploratory; 2026-11-03)

**Owner position (2026-11-03): the prototype and its 20,000-block run are not essential for closing Phase 0.5; they answer whether the append-only log is a viable fix.** Branch `proto/p02b-blocklog` (v1 `225e6f4`, v2 `4af285e`); not merged, not wired into the node, production `persist_state` untouched. Same hardware, workload and debug profile as M0 §10, but **one** executing node (not four), so state-root agreement is not re-demonstrated here; the prototype does not touch consensus.

**v1 moved only `chain_store` into the block log.** Run: 4,229 blocks (stopped by the 50-minute cap; **the 20,000-block target was not reached**).

| Heights | Persist p50 | p95 | p99 | max | Bytes written per block |
| --- | --- | --- | --- | --- | --- |
| 0–100 | 26 ms | 38 ms | 50 ms | 126 ms | 0.30 MB |
| 500–1,000 | 188 ms | 265 ms | 312 ms | 354 ms | 2.5 MB |
| 1,000–2,000 | 365 ms | 490 ms | 536 ms | 587 ms | 5.0 MB |
| 2,000–3,000 | 579 ms | 704 ms | 785 ms | 1,021 ms | 7.4 MB |
| 3,000–4,000 | 802 ms | 919 ms | 974 ms | 1,245 ms | 9.9 MB |
| 4,000–4,229 | 923 ms | 998 ms | 1,041 ms | 1,079 ms | 10.5 MB |

- **The log itself is flat:** the append plus fsync of one block stayed at about 3.6 ms p50 from the first block to the last. Cost per block of the log is O(block), as designed.
- **v1 still misses the targets and still grows** (p95 998 ms at height ~4,200 versus the 50 ms target). Cause found by this run: **`historical_validator_sets.json` also grows by about 2.4 KB per block** (one validator set per height, 7.6 MB by height ~3,100) and v1 still rewrote it whole in every generation. Serialising the small files (p50 316 ms) and writing them (snapshot p50 592 ms) are now the cost. M0 §10's "only `chain_store.json` grows" expectation (M2) was wrong; the design in §4a did not account for it.
- **Compared with M0 at similar heights:** at ~500 blocks M0 persisted in 4,100–5,500 ms writing about 50 MB; v1 took 188–265 ms writing 2.5 MB. The improvement is large (about 20×) but not the flat curve required.
- **Log size on disk:** 109.8 MB for 4,229 blocks (about 26 KB per block, compact JSON).
- **Recovery and replay costs at 4,229 blocks (debug):** hash-chain verification only 6.4 s; replay plus deserialise plus byte-compare with memory 22.3 s; `recover` (open, verify, truncate to the checkpoint) 6.7 s. Restart cost is O(chain) in this prototype; checkpointing or an index would be needed to bound it.
- **Prototype v2** (`4af285e`) logs `historical_validator_sets` in a second append-only log. It compiles and its round-trip test passes; **its benchmark has not been run**, and a release build and the 20,000-block run have not been run either.

**Crash-safety tests (all pass, 14):** golden record bytes; append/replay across segments; identical bytes for identical inputs; height gap rejected; torn last record beyond the committed tail truncated at every byte offset; torn record inside the committed region fatal; a flipped byte in each position of a committed record fatal (recovery and replay); log ahead of the checkpoint truncated including later segments; empty new segment after a crash in roll removed; missing or mismatched committed tail fatal (last segment, middle segment, wrong hash, wrong anchor); nothing committed removes everything; `create` refuses an existing log; plus one end-to-end test on real blocks (D1 postcondition: the committed descriptor equals the log tail when persistence returns; log-ahead crash recovers to the checkpoint, never forward). **Not tested:** power-loss durability, Windows, signing-guard interplay beyond the D1 postcondition, state re-execution replay, migration.

## 12. Remaining risks (prototype)
1. Every file in a generation must be audited for growth with height; at least `historical_validator_sets.json` grows linearly (M2 should be re-run per file at several heights, not assumed).
2. Restart and replay cost is O(chain) (§11), so checkpointing/pruning needs a design.
3. Cross-platform determinism is tested only on Linux; Windows has not been run.
4. A second log (v2) doubles the number of commit-boundary files, so D1 ordering and recovery cases must be re-derived and tested for two logs.
5. Production-size blocks, real networking, release-build timing and a 20,000-block run remain unmeasured.
