# PERSIST-001 P-02b — Production integration design and minimal safety acceptance plan

**Status (2026-11-03): DESIGN ONLY, for owner approval.** Documentation only. No production integration, no migration, no merge and no further benchmark is authorised by this document or by the instruction that requested it. H0-3b, H0-11B and BIZ-PRE-5 stay open. Nothing here is verified on Windows.

**Evidence base (experimental, accepted as such by the owner):** `docs/persist-001-p02b-design.md` §10–§13: M0 baseline (current design: p95 6.4 s at height ~600, 9.7× interval growth), prototype v2 (release: 20,001 blocks, p50 11.0 / p95 17.2 / p99 22.8 ms, max 2,395 ms, about 58 KB written per block; debug: 12,045 blocks, p95 30.3 ms). Prototype code: branch `proto/p02b-blocklog` (`ddfe570`), module `chain-forge-node/src/blocklog.rs` and test-only harness in `node.rs`. **Linux sandbox only; the prototype is not wired into the node.**

**Related:** `docs/persist-001-p02-design.md` (D1, §8.1, §14 named follow-on gap, §15), `docs/h0-11b-liveness-design.md` (liveness evidence interacts with fsync stalls, §8 here).

---

## 1. What exists today (facts from `main` `385431f`)

- **One commit boundary per block** (P-02a, PR #48): `persist_state()` serialises eight files, writes them into `snapshots/gen-N` (temp + fsync + rename each), fsyncs the generation directory, writes `manifest.json` last (format_version 1, chain_id, genesis_hash, state_root, per-file SHA-256 and size), fsyncs, fsyncs `snapshots/`, replaces `CURRENT`, and prunes N−2. `commit_block` calls it **synchronously on the consensus loop**; a failure is **fatal** (the node halts consensus, `node.rs` "FATAL: snapshot write failed after commit").
- **Loader** (`load_persisted_state`): `Fresh` / `Restored` / `Fatal`; never silently falls back to genesis; the manifest must carry a supported `format_version` (today exactly 1; any other value, or none, is `IncompatibleManifest` and "start with a clean data directory"), the node's `chain_id` and `genesis_hash`, and the restored root must equal the manifest `state_root`.
- **Signing guard** (`persist/consensus_signing.json`, outside the generations): written durably *before* a vote leaves the node; a guard at height > 0 with no state is `Fatal`; a guard ahead of state makes the node **abstain** (`signing_abstain_until`) until the state catches up. Proposal signing is **not** guarded (named follow-on gap, persistence memo §14; separate item).
- **D1 (owner, retained without relaxation):** no vote or proposal for height *h+1* before the state for *h* is durable.
- **Legacy migration** from pre-H0-3b data exists and is strict (`persist/legacy-pre-h0-3/`). It is the only precedent for a format change.

## 2. Target layout (format_version 2) — design

```
<data_dir>/
  persist/consensus_signing.json            (unchanged location and semantics)
  blocklog/seg-<first_height>.log           (append-only, hash-chained; prototype record format)
  hvslog/seg-<first_height>.log             (validator-set history, same record format)
  snapshots/gen-N/{state,identity,validators,agents,slashing,live_validator_set}.json
  snapshots/gen-N/storage_descriptor.json   (names both log tails: height + record hash; segment sizes)
  snapshots/gen-N/manifest.json             (format_version 2; lists the descriptor and small files with SHA-256)
  snapshots/CURRENT
```

**Integrity argument (why one manifest still commits everything).** The manifest hashes the descriptor and the six small files; the descriptor names each log's tail `(height, record_hash)`; every record's hash covers the previous record's hash, so the tail hash transitively commits to every earlier byte of the log. `state_root` still binds the live state. Anything in a log beyond the manifest's tail is **uncommitted by definition** and is discarded at startup, never used to move the node forward.

**Record format** (as prototyped): `magic "CFBL" | version(1) | height(8 LE) | len(8 LE) | payload | prev_hash(32) | record_hash(32)`, `record_hash = SHA-256(everything before it)`, first `prev_hash` = a value derived from the genesis hash. `payload` is compact serialisation of the block `(CommitCertificate, BlockProposal)` or `(height, ValidatorSet)`.

**Open item (owner decision):** payload serialisation. The prototype used compact `serde_json`, deterministic for the types tested on Linux only. Production needs a canonical, versioned encoding that is byte-identical on Windows and Linux; a golden-bytes test must pin it before integration.

## 3. The commit boundary (ordering; D1-compatible)

For block *h*, `commit_block` performs, in this order, on the consensus loop:
1. Serialise the six small files (they do not grow with height).
2. **Append block *h* to the block log and fsync the segment** (fsync the directory when a segment is created).
3. **Append the validator set for *h* to the history log and fsync.**
4. Write the generation: small files, `storage_descriptor.json` (tails of both logs after steps 2–3), then the manifest last, with the existing directory fsyncs, then `CURRENT`.
5. Only now may the node vote or propose at *h+1* (D1). `recheck_signing_abstention` runs as today.

A crash between any two steps leaves the previous generation as the committed state. Steps 2–3 make the logs *ahead of* the manifest by at most one block; recovery removes that block (below). Two logs can only disagree with each other by that same one block.

## 4. Startup recovery (design; every row has a test in §9)

Order: (a) classify the directory (fresh / v1 / v2 / mixed) from `CURRENT`, the manifests and the log directories **before reading anything else**; (b) validate the committed generation exactly as today (identity, hashes, state root); (c) read the descriptor; (d) recover both logs against it; (e) load the signing guard and apply the existing rules.

| Condition at startup | Result |
| --- | --- |
| No `CURRENT`, no logs, no guard above height 0 | `Fresh` (as today) |
| `CURRENT` valid, both log tails equal the descriptor | `Restored` |
| A log is **ahead** of the descriptor (whole records, a torn record, trailing bytes, a newly created empty segment) | Truncate to the descriptor tail, fsync, then `Restored`; log a warning with the number of bytes and blocks discarded |
| A log is **behind** the descriptor, a committed record is damaged, a middle segment is missing, a tail hash differs, the anchor is wrong | `Fatal`, never repaired, never fall back to genesis |
| The two log tails disagree with each other beyond the one-block crash window, or with the descriptor's heights | `Fatal` |
| Descriptor missing, unreadable, or its hash not in the manifest | `Fatal` |
| Logs present but `CURRENT` absent, or `CURRENT` names a v1 generation while v2 logs exist (or the reverse) | `Fatal` ("mixed formats"), no automatic choice |
| Guard exists at height > 0 and there is no valid committed state | `Fatal` (existing rule) |
| Guard height ahead of the restored height (including by the one block that recovery just removed) | `Restored`, **abstain** until the state reaches the guard height (existing rule); see §5 |

## 5. Signing guard and conflicting signatures

- The guard keeps its location, its format and its "durable before the signature leaves" rule. The integration **must not** add a second guard or move it into a generation.
- **Rolled-back block.** If step 2–3 completed for block *h*, the node never voted at *h+1* (D1), so recovery that discards *h* cannot create a signature conflict at *h+1*. Votes the node cast **at height *h*** (before committing it) are in the guard; after recovery the node is at *h−1* and the guard shows *h*: it abstains or re-votes the same value, never a different one (existing rule, memo §8.1 item 4; the test in §9, G-3, pins it for the two-log layout).
- **Proposal signing** is unguarded today (named gap). The integration does not change that and does not close it; it must not make it worse (e.g. no new signed artefact written before the guard). Closing it stays a separate approved item and is listed as a precondition for **closing H0-3b**, not for the integration PRs.
- **Single writer.** Two processes opening the same data directory would write two logs and two guards. The design adds an OS-level exclusive lock file for the data directory, taken before anything is read and held until exit; failing to take it is `Fatal`. (This is not in the code today; owner to confirm.)

## 6. Format detection, versioning and explicit migration

**Detection.** `format_version` stays in the manifest; the loader accepts exactly the versions it implements. A v2 node reading a v1 directory, or the reverse, is `IncompatibleManifest` with a message naming the migration command. **There is no silent, in-place or automatic migration, ever.**

**New nodes.** A flag chooses the format for a *fresh* data directory only. Default `1` until the owner approves the switch; the flag has no effect on an existing directory.

**Explicit migration (design only; not authorised to run).** An offline command, e.g. `chain-forge-node migrate-storage --from-v1 <dir> --to <new-dir>`, run by the operator with the node stopped:
1. Take the data-directory lock; refuse if a node is running.
2. **Read-only on the source.** Never writes to, renames or deletes anything in the v1 directory.
3. Load the v1 committed generation with the full v1 verification (identity, hashes, state root).
4. Write the v2 directory *elsewhere*: build both logs from `chain_store.json` and `historical_validator_sets.json`, write the six small files, descriptor and manifest, and `CURRENT` last.
5. **Verify before declaring success:** re-open the new directory with the v2 loader; compare the replayed blocks and sets byte-for-byte with the source; compare the state root and height; print both tails.
6. **Signing guard:** copy `consensus_signing.json` byte-for-byte to the new directory (a guard must never be lost or reset), verify equality, and print its height. The source guard is left in place.
7. **Cut-over is the operator's act**, by pointing the node at the new directory. The old directory is kept untouched for rollback; the migration prints a warning that running *both* directories with the same validator key can double-sign, and the v1 directory is marked with a `MIGRATED-DO-NOT-RUN` file only by the operator's explicit follow-up command (not automatically).
8. Downgrade is not supported: v1 nodes refuse a v2 directory; rollback means returning to the untouched v1 directory, with the signing-guard caveat above.

**Protecting existing validator data.** Read-only source, new directory, explicit verification, guard copied not moved, lock file, no in-place mutation, no automatic cut-over. Backup guidance is part of the operator documentation (not code).

## 7. Compatibility with other work

`state_root` and the STATE-PERF golden roots are untouched (the logs hold blocks and validator sets, not tree nodes). `compute_genesis_hash` is untouched. The H0-3 legacy migration path is kept and runs *before* any v1→v2 step.

## 8. Fsync stalls (multi-second pauses) — detection and handling without weakening consensus safety

**Observed:** isolated bursts of 2–5 consecutive blocks with 0.15–3.0 s persistence in both prototype runs (release max 2,395 ms; debug 3,019 ms), unrelated to height, probably VM or host I/O contention. Not reproduced in isolation; cause unconfirmed.

**What a stall means.** Persistence runs on the consensus loop, so a stall delays that node's next vote or proposal and makes it late to the proposer's 1,000 ms gather window. Under D1 this is **a liveness cost for that validator, not a safety risk**: nothing is signed until the state is durable.

**Rules (design):**
1. **Never skip, shorten or reorder durability to recover time.** D1 and the ordering in §3 hold regardless of how slow the disk is. There is no "persist later" mode.
2. **A slow fsync is not an error; an fsync error is.** Errors stay fatal (existing behaviour). A stall is surfaced, not converted into a failure.
3. **Measure every commit:** record the persistence duration and the per-step times (the prototype already measures them) as node metrics, and log a warning above a configurable threshold (proposed 250 ms) and an error above a second threshold (proposed 1,000 ms, the gather window). Provisional numbers; the owner decides.
4. **Operator alert, non-punitive:** an alert when N commits in a window exceed the threshold ("storage is slow"), on the same footing as the tier-O alerts in the H0-11B memo. It must not cause any consensus-state change (no jail, slash, removal or voting-power change).
5. **Stall and liveness evidence:** a validator whose own disk stalls will have its precommits arrive late; under the H0-11B tiering that is tier O (ambiguous), which never jails. This is a reason the O rule exists; the two documents are consistent and the H0-11B thresholds stay provisional until measured on real hardware.
6. **Watchdog (optional, owner decision):** if a single persistence call exceeds a hard limit (proposed 30 s), the node logs a critical error and exits rather than hang while peers time it out. Exiting is safe (state is the last committed generation); it is not a consensus action.
7. **Off-loop writer (Option 3 in the design memo) is not proposed for Phase 0.5.** It would hide cost but add a thread, an error path and a new failure mode, and the measured release p99 (22.8 ms) does not need it. Revisit only if Windows measurements show stalls that matter.

## 9. Minimal safety-focused acceptance plan (everything below is required before H0-3b can close; none has been run on Windows)

**A. Unit and crash-injection tests (Linux sandbox and Windows, `cargo test`)**
- **L-1..L-13** the existing 13 log tests (golden record bytes, torn tail at every offset, corrupt byte in every field, missing/mismatched tail, anchor, segment roll).
- **R-1..R-9** the recovery table of §4, one test per row on a real node (including log ahead by one block, torn record in each log, history log behind, descriptor missing, mixed formats, wrong chain or genesis).
- **G-1** guard durable before the signature leaves (existing P-02a tests re-run on the two-log layout).
- **G-2** no signature for *h+1* before the manifest for *h* is durable (ordering assertion at each of the five steps of §3, with fault injection that stops the node between steps).
- **G-3** guard at *h*, state recovered to *h−1* after the two-log truncation: abstain, no conflicting signature (hard zero).
- **G-4** a guard with no state is `Fatal` in v2 directories too.
- **F-1** format detection: v1 node on a v2 directory and v2 node on a v1 directory refuse with the migration message; a mixed directory refuses.
- **M-1..M-6** migration: source untouched (hash the whole source tree before and after); verification catches a deliberately corrupted output; guard copied identically; migrated node restarts and continues; re-running on the output is refused; interrupted migration leaves no half-written target that a node could start from.
- **D-1** golden serialisation bytes for a fixed block and set, identical on Windows and Linux.
- **S-1** stall handling: injected 3 s fsync delay: node stays correct (no signature before durable), emits the warning and error metrics, and does not change consensus state.
- **Mutation checks** on the recovery and ordering code (disable truncation, disable the descriptor check, reorder steps 2–4) must each make at least one test fail.

**B. Live-node tests (Windows BossKing, per the project rule)**
- **W-1** the four existing H0-11 live tests re-run on a v2 data directory (eviction, jail, integrity, loaded delay) with identical results to the v1 baseline.
- **W-2** kill -9 / hard process kill of one validator at random commit steps (including mid-append) in a 4-node run, 50 repetitions: restart, rejoin, no conflicting signatures, identical state roots across nodes.
- **W-3** restart of every node at heights 100 / 1,000 / 5,000 with the restart time recorded.
- **W-4** persistence p50/p95/p99/max at the same loads as M0 and the prototype, on Windows, with the stall counters.
- **W-5** power-loss durability remains **unverified** by any software test; it needs a documented manual procedure or hardware test and an explicit owner decision about whether H0-3b closes without it (the existing "Windows directory fsync is unverified for power loss" caveat).

**C. Closing H0-3b additionally requires** (outside the integration PRs): the unguarded-proposal-signing gap closed or explicitly accepted by the owner, the retry-policy decision, `--reset-data` (D3), and a Windows-confirmed run of A and B. **This design does not close H0-3b.**

## 10. What can be deferred without violating Phase 0.5 safety requirements

| Improvement | Why deferral is safe | Condition |
| --- | --- | --- |
| Faster restart and replay (checkpoint, index, lazy loading of history). Measured restart: 2.8 s at 20,001 blocks (release), 19.6 s at 12,045 (debug) | Restart cost affects availability after a crash, not safety; both are bounded and linear | Document the linear growth; revisit when restart exceeds an owner-set bound |
| Log compaction and pruning | No safety function; disk grows about 26 KB per block | Document the growth (about 520 MB per 20,000 blocks); never delete a block still inside the retained hash chain |
| Loading the full validator-set history at startup | Same as restart cost | Keep the full load until a measured need appears |
| An off-loop writer thread | Not needed at the measured percentiles; adds a failure mode | Revisit after Windows stall data |
| Binary (non-JSON) record payloads | A size and speed optimisation only | The canonical-bytes decision (D-1) is **not** deferrable |
| Deletion-root correction (§13 in KNOWN_ISSUES), API bind failure | Separate items | Not combined with this change |

**Not deferrable:** the ordering of §3, the recovery table of §4, the guard rules of §5, the lock file, explicit migration with a read-only source, the canonical serialisation pin, the stall metrics, and the Windows tests in §9.

## 11. Proposed PR sequence (for owner approval; none authorised)

1. `blocklog.rs` plus its unit tests, **unwired** (no behaviour change; the prototype module reviewed and hardened; golden bytes pinned).
2. v2 persistence behind a default-off flag, **fresh data directories only**, with the recovery, guard and format-detection tests.
3. The offline migration command with its tests, read-only on the source.
4. Windows runs (A and B), results recorded; owner decides on the default.
Each is its own PR, merged only on explicit authorisation, none combined with H0-11B, the deletion-root correction or the API startup change.

## 12. Decisions needed from the owner

1. Approve the layout, ordering and recovery table (§2–§4), or require changes.
2. Canonical payload encoding for the logs (the prototype's compact JSON versus a binary encoding), pinned by golden bytes on both platforms.
3. Data-directory lock file (§5): accept.
4. Thresholds in §8 (250 ms warn, 1,000 ms error, 30 s hard limit): provisional numbers, or none yet.
5. Whether H0-3b may close without a power-loss test (W-5).
6. Whether the default for fresh directories flips to v2 after the Windows runs, and when.

## 13. Not claimed

That the prototype is production-ready; that Windows behaves like the Linux sandbox; that the disk stalls are understood; that power-loss durability holds; that any acceptance test above has been written or run for the integrated layout (only the prototype's 13 log tests, the two-log recovery test and the v1 round-trip exist, on Linux); or that closing the unguarded proposal-signing gap is part of this design.
