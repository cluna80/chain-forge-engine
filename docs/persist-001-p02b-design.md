# PERSIST-001 P-02b — Per-block persistence cost: measurement plan, options and acceptance criteria

**Status (2026-11-03): DESIGN ONLY, DRAFT for owner review.** Documentation only. No code, no consensus-policy change, no format change is made by this document. Implementation needs separate approval. H0-3b stays open. Authorised by the owner on 2026-11-03 ("documentation-only design in parallel; define performance measurements and acceptance criteria while preserving crash durability, state-root consistency and signing-guard safety").

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

M0 is the gating item: **no option is chosen before M0 and M1 exist on Windows.** If M1 shows the fixed fsync count dominates rather than chain size, Option 1 below will not be enough, and the choice changes.

## 4. Options

**Option 1, cheap constant factors.** Compact JSON instead of pretty JSON; reuse buffers; skip rewriting the seven small files when their bytes are unchanged (keep the previous generation's files by hard link or by referencing them from the manifest). Does *not* remove the O(chain) term. Risk: low. Expected to help only the constant.

**Option 2, split `chain_store` into an append-only block log plus a small mutable snapshot (recommended first implementation, subject to M0/M1).** Blocks are immutable once committed. Store them in segment files, append each new block (O(block) bytes), fsync the segment. The generation's `chain_store` entry becomes a small descriptor: segment list, per-segment length and SHA-256, and the tail hash. The manifest still binds everything to `state_root` and the file hashes. Per-block cost becomes O(block size + small files), independent of height. Risks: new torn-tail cases (a partially appended block); a format bump and migration from P-02a (I5); the `chain_store` readers (`/blocks` APIs, light-client proofs) must read from segments.

**Option 3, off-loop serialisation and writing with a durability barrier.** A writer thread owns the disk; the consensus loop hands it an immutable snapshot of what changed and continues. The barrier required by D1/§8.1 is kept: the node does not sign for *h+1* until the writer reports height *h* durable. This overlaps the write with the one-second collection window and proposal propagation, so it hides cost without reducing it, and it cannot help if persistence takes longer than the gap before the next vote. It also adds a failure mode (writer thread panic or error) that must stop signing. Complements Option 2; alone it is not sufficient.

**Option 4, write-ahead journal plus periodic checkpoint.** Append one record per block (executed delta and block) to a journal; write a full generation every K blocks. Cheapest per block, most complex: needs deterministic replay (STATE-PERF roots are the guardrail), torn-tail rules, and a K-dependent restart time (M6). Larger change; defer unless Option 2 is insufficient.

**Not proposed:** weakening D1 (voting before the previous height is durable) to buy speed. If the owner wants that, it is a separate, explicit decision with its own double-sign analysis (§8.1 item 4 already shows what the guard covers).

## 5. Recommended path (for the owner to decide)

1. Run M0–M2 (and M5) on Windows and in the sandbox. Report. No code changes beyond timing instrumentation behind `#[cfg(test)]`.
2. If `chain_store` growth dominates (expected): Option 2 for the log, Option 1 compaction for the small files; Option 3 only if M1 shows the remaining fsync cost still erodes the gather window.
3. Every option is tests-first (section 7) and lands as its own PR, not combined with H0-11B or the deletion-root correction (§13 in KNOWN_ISSUES).

## 6. Acceptance criteria

**Performance (the numeric targets are the owner's; this document reports and compares, it does not invent a pass/fail number):**
- **P1 growth.** Commit interval under the fixed load of M3 at heights ~50, ~150, ~250 and the ratio of the last to the first. Target to be set by the owner (a ratio near 1 is the goal).
- **P2 loaded delay test.** Re-run `validator_precommit_delay_loaded_live` before and after with identical load; compare the drift ratio and the delay-0 control. Both runs' numbers (1.9× / 1.6×; 3 of 11 / 2 of 10) are the baseline.
- **P3 per-block persistence time** at heights 50 / 200 / 500, flat within a bound the owner sets.
- **P4 restart time** reported at heights 50 / 200 / 500 (not allowed to regress unboundedly).

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

1. **Targets.** What ratio and absolute per-block time count as a pass (P1, P3)?
2. **Does the owner accept Option 2's format bump** (and its read-side changes to block APIs), or prefer Option 4 for the longer term?
3. **Is D1 to stay exactly as written** (no vote for *h+1* before *h* is durable), given that it caps what Option 3 can hide?
4. **Retention.** How many blocks must stay fast to read after segmenting (relevant to `/blocks` and sync)? Is pruning old segments ever allowed on a validator?
5. **Windows power-loss.** Directory fsync via `FILE_FLAG_BACKUP_SEMANTICS` + `FlushFileBuffers` is still unverified for power loss (memo §15). A log makes this matter more, because the tail is written every block.
6. **Retry policy.** Still a separate Windows-validated decision (memo §14); this design assumes none.
7. **NODE-TOKIO-1** (a tokio time-driver assertion that killed one node once) is separate, but any writer thread added by Option 3 must not widen it.

## 9. Not claimed

That any option will meet a target that has not been measured; that sandbox numbers predict Windows; that the loaded-delay results will improve by a particular amount (the 900 ms point already varies between identical runs); or that crash durability under power loss on Windows is verified.
