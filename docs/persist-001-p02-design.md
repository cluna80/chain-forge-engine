# PERSIST-001 P-02 — Crash-safe incremental persistence: design memo

**Status:** DESIGN ONLY. No storage change is authorised. Authored 2026-11-02 for owner review.
**Closes (when implemented and Windows-confirmed):** H0-3b. **Also addresses:** KNOWN_ISSUES §9 (cost) and §11 (torn files).
**Not in scope:** §13 (history-dependent roots after deletions), the API bind-failure change, consensus policy (H0-11B).

---

## 1. The recovery invariant this design must satisfy

At startup the node classifies its data directory into exactly one of four states and acts as follows.

| Class | Meaning | Required action |
| --- | --- | --- |
| **NEW** | Provably a fresh node: no manifest, no persisted component file, no journal, no signing guard. | Initialise from genesis. The only path that may. |
| **COMMITTED** | A manifest names height *h*, and every component it names is present and matches its recorded checksum. | Load height *h*. Verify the restored root equals the manifest root. |
| **TORN** | A write was interrupted before its commit record became durable (staging directory or journal tail with no valid commit). A previous committed generation exists. | Discard the incomplete write, load the previous committed generation, log what was discarded. Deterministic. Not an error. |
| **CORRUPT** | Anything else: a manifest that names a missing or mismatched component, an unparseable committed file, a damaged record with valid data after it, a manifest with no valid fallback, or node-identity evidence (signing guard) with no chain state. | **Refuse to start**: non-zero exit and an error naming the file, the expected and actual checksum or parse error, and the height. Never fall back to genesis. |

Rule: **silent fallback from corrupted storage to genesis is not a recovery path.** A deliberate reset is an explicit operator action (§8, D3), never automatic.

## 2. What the code does today (facts, with sources)

All references are to `chain-forge-node/src/node.rs` on `feat/h0-11-validator-eviction` unless noted.

1. `persist_state()` (l.2141) runs at the end of every `commit_block` (l.4983), on the consensus loop. It serialises eight files with `to_string_pretty` — `state.json`, `identity.json`, `validators.json`, `agents.json`, `slashing.json`, `chain_store.json`, `historical_validator_sets.json`, `live_validator_set.json` — and writes each with `std::fs::write` (truncate then write). No temp file, no fsync, no rename. `let _ =` discards write errors and `.ok()` discards serialisation errors.
2. Only `consensus_signing.json` uses `write_atomic` (l.147: temp, `sync_all`, rename). The directory is not fsynced.
3. `load_persisted_state()` (l.2203) returns `false` if `state.json` does not exist. Every other component is read only `if path.exists()`, so a **missing** `identity.json`, `validators.json`, `agents.json`, `slashing.json`, `chain_store.json` or `historical_validator_sets.json` is skipped silently and the node proceeds with genesis defaults for that component.
4. The load runs as one closure that **mutates `self` as it goes** (`restore_snapshot` first, then each component). A parse error partway leaves a node holding restored state plus genesis defaults, and the function returns `false`.
5. `main.rs` (l.196-199) treats `false` as "no persisted state found — starting from genesis" and carries on. There is no distinction between a new node and a damaged one.
6. `reset_to_height` failure is only a `warn!` ("some re-proposal may occur").
7. `restore_sign_guard` (l.5353): an **unreadable** `consensus_signing.json` panics (fail-closed), but a **missing** one is silently ignored (`let Ok(text) = ... else return`). So the guard is fail-closed on corruption and fail-open on absence.
8. `StateStore::restore_snapshot` rebuilds the Merkle tree from account and metadata content in one batch; `export_snapshot` carries `root_hash`. The restored root can therefore be compared with the recorded one.

**Measured baseline (KNOWN_ISSUES §9, §11):**
- Cost: `chain_store.json` reached 27 MB by height ~190 under load; commit interval grew from ~1.2 s to 7.8 s. Every block rewrites the whole history.
- Torn files (audit `persist001_audit_torn_files`, reproduced on Linux and Windows): `state.json`, `chain_store.json` truncated or emptied, and `slashing.json`, `identity.json`, `live_validator_set.json` truncated, all **fall back to genesis** (height 0). `validators.json` missing loads at height 11 with a registry rebuilt from genesis (silently inconsistent).

## 3. Design principles

1. One **commit record** defines what "committed" means. Component files are never trusted on their own.
2. A reader sees height *h* complete or the previous committed height complete, never a mix.
3. Every failure mode is classified (§1); nothing is "best effort".
4. Derived data (explorer state, `bond_owner_bindings`) is rebuilt on load and never persisted.
5. Persistence failures are errors the node surfaces. A write error must not be discarded.
6. No change to consensus-critical encodings. Block, state-root and snapshot formats are unchanged.

## 4. Options considered

**Option 1 — Atomic generations with a manifest (P-02a).** For each commit, write every component of height *h* into `persist/gen-<h>.tmp/`, fsync each file, fsync the directory, write `MANIFEST` (format version, chain id, genesis hash, height, state root, per-file SHA-256 and length) with `write_atomic`, rename the directory to `gen-<h>`, update a `CURRENT` pointer atomically, fsync the parent. Keep the last *K* generations (default 2) and delete older ones only after the new one is durable.
- Fixes: atomicity, torn files, missing-component silence, genesis fallback. Reuses the existing `write_atomic` idea.
- Does **not** fix cost (§9): still rewrites everything each block, and briefly needs ~2× disk.

**Option 2 — Append-only journal plus periodic checkpoints (P-02b, the target).** `chain_store` (the part that grows) becomes an append-only journal: length-prefixed, CRC-protected records, one per block, fsynced at the commit boundary. The small, bounded components (`state`, `identity`, `validators`, `agents`, `slashing`, `historical_validator_sets`, `live_validator_set`) are checkpointed every *N* blocks as Option 1 generations. Recovery = newest valid checkpoint, then replay journal records up to the last fully valid one.
- A bad or short record at the **tail** is a torn append: truncate it (rollback of the partial write).
- A bad record with valid records **after** it is CORRUPT: refuse.
- Replay either re-executes the journalled blocks through the existing deterministic executor (no extra format) or journals per-block state deltas. Re-execution is simpler and reuses a path the node already exercises when syncing from peers; its cost is bounded by *N*. The delta alternative needs a persisted tree WAL — `NodeStore` has a `wal` field, but **whether it is durable or usable for this is unverified** and must be checked before this option is committed to.
- Fixes cost and atomicity. Larger change; needs the replay path to be exactly deterministic.

**Option 3 — Embedded transactional store (SQLite WAL or similar).** Gives atomic commits and torn-write recovery off the shelf. Rejected for now: new native dependency, and this project has already seen Windows linker and antivirus friction with native build artefacts. Revisit only if Options 1–2 prove hard.

**Recommendation.** Ship **P-02a** first as the H0-3b fix: it is small, changes no payload formats, and closes the correctness defect. Then **P-02b** for the cost problem, on top of the same manifest and classifier. Do not combine them.

## 5. The durable commit boundary

Per block (P-02a):

1. Serialise all components in memory (errors are fatal to this commit and surfaced, not ignored).
2. Write each into `gen-<h>.tmp/`; `fsync` each file.
3. `fsync` the staging directory.
4. Write `MANIFEST.tmp`, `fsync`, rename to `gen-<h>.tmp/MANIFEST`.
5. Rename `gen-<h>.tmp` → `gen-<h>`; `fsync` `persist/`.   **← durable commit point for height *h***
6. Atomically update `CURRENT`; fsync. Prune generations older than *K*.

A crash before step 5 leaves a `.tmp` directory: class TORN, roll back to the previous generation. A crash after step 5 leaves a complete generation: COMMITTED.

**Interaction with voting (decision D1).** A node that crashes between executing block *h* and step 5 restarts at *h−1* and catches up from peers. That is safe for liveness. For double-signing it relies on the signing guard, which is already written atomically **before** a vote is sent. So the state may lag the guard but must never be ahead of it. Whether to fsync the manifest *before* voting on height *h+1* (stronger, slower) or after (current ordering, group commit possible) is an owner decision.

**Signing guard.** Keep `consensus_signing.json` outside generations (it must be written before votes). Change the load rule: guard present with no chain state, or chain state present with no guard, is CORRUPT unless the data directory is classified NEW. This closes the "fail-open on absence" gap in item 7 above.

## 6. Torn-file recovery: required behaviour

Each row becomes a test (§9). "Refuse" means non-zero exit with the explicit error of §1.

| Damage | Today | Required |
| --- | --- | --- |
| Crash mid-write of generation *h* (staging dir, no manifest) | partial files loaded or genesis | Roll back to the previous generation; log it |
| Any component of the current generation truncated, emptied or unparseable | genesis (height 0) | Refuse; name file and checksum |
| Any component missing | skipped silently (or genesis) | Refuse |
| Checksum mismatch, files otherwise valid | not detected | Refuse |
| `MANIFEST` damaged, a previous valid generation exists | n/a | Treat as TORN only if the newest generation is the staging one; a damaged **committed** manifest is CORRUPT |
| `CURRENT` points to a missing generation | n/a | Refuse |
| Restored root ≠ manifest root | not checked | Refuse |
| Signing guard present, no chain state | genesis | Refuse |
| Empty or absent data directory | genesis | Genesis (NEW) |
| Unknown future `format_version` | n/a | Refuse (no downgrade) |

## 7. Migration from existing data directories

- Detect **legacy** layout: `persist/state.json` present, no `MANIFEST`.
- First start of the new binary validates the legacy set strictly: all eight files parse, the restored root equals the recorded `root_hash`, the chain store's last height equals the snapshot height. If valid, write generation `gen-<h>` from it with a `MANIFEST`, and move (not delete) the legacy files to `persist/legacy-<timestamp>/`. If invalid, classify CORRUPT and refuse; do not guess.
- One known legitimate legacy gap: a data directory that predates CF-VAL-KEY-002 has no `live_validator_set.json` (the code already tolerates it with a warning). Migration may allow exactly that case, recorded in the migration log.
- **Downgrade hazard.** The previous binary reading the new layout finds no `state.json` and would silently start from genesis. Mitigation: the new layout writes a `persist/README-FORMAT-V2` marker and the release notes state "no downgrade"; confirm in review that no operator tooling relies on the old file names.
- Rollback path: legacy files are retained until the second successful generation is committed.

## 8. Decisions needed from the owner

- **D1.** Per-block fsync before voting on the next height, or after (and optionally group commit)?
- **D2.** Generations retained, *K* (proposal: 2).
- **D3.** Deliberate reset: an explicit CLI flag (proposed name `--reset-data`), refused unless the directory is explicitly named, that archives rather than deletes the old data.
- **D4.** Is an embedded database (Option 3) acceptable as a future dependency?
- **D5.** No-downgrade policy confirmed?
- **D6.** Is "signing guard present, chain state absent" fatal (proposed) or an operator-confirmed condition?

## 9. Test plan (written first, against the current code where they demonstrate the defect)

1. **Torn-file matrix** (extends `persist001_audit_torn_files`): every file of §6, one at a time; assert refusal or rollback exactly as tabulated. These currently show the defect and must flip.
2. **Crash injection at every step boundary** of §5 via the existing `fault-injection` feature (a hook between each fsync and rename); kill and restart; assert class TORN or COMMITTED and that height is *h−1* or *h*, never anything else.
3. **Restart consistency under load:** `kill -9` a validator at random heights; after restart its state root at height *h* must equal its peers' at *h*, and the chain must resume. Windows and Linux.
4. **Model-based property test:** random sequences of commit, crash-point and restart against a reference model of "last committed generation".
5. **Classifier tests:** NEW, COMMITTED, TORN, CORRUPT, and the guard/chain combinations (D6).
6. **Migration tests:** a legacy directory (valid, torn, missing optional file) migrates, or refuses, as §7 states; round trip preserves the root.
7. **Windows specifics:** directory flush uses a handle opened with `FILE_FLAG_BACKUP_SEMANTICS`; `rename` over an existing file; bounded retry with an explicit error on transient sharing violations (antivirus, as seen with LNK1104 and the Avast block). This must be validated on Windows before ✅ (CLAUDE.md policy).
8. **Cost:** repeat the §9 loaded-chain measurement; commit interval must stay flat to chain length for P-02b.

## 10. Risks and dependencies

- **§13.** Verifying "restored root = manifest root" assumes the rebuilt tree reproduces the live root. §13 says a root can depend on deletion history, and the only production deletion is `rollback_checkpoint`. Until §13 is decided, the verification must tolerate or avoid snapshots taken after a rollback, or the manifest must record a root computed the same way as the restore path.
- **H0-11B / jail.** `validators.json`, `historical_validator_sets.json` and `live_validator_set.json` must be part of the same generation as `state.json`; the earlier restart defect (committee shown after reload) came from these drifting apart.
- **Re-execution determinism (P-02b).** Replay must be exactly deterministic across platforms; the STATE-PERF golden roots and node golden-root test are the guardrail.
- **Disk.** Option 1 transiently holds ~2× the data; pruning must follow the commit point only.

## 11. Acceptance criteria to close H0-3b

1. Torn-file matrix of §6 passes: no scenario reaches genesis from a non-NEW directory.
2. Crash injection at every §5 boundary recovers to *h−1* or *h*.
3. Restart-under-load consistency passes on Windows (BossKing) and Linux.
4. Migration of an existing devnet data directory succeeds, or refuses with the explicit error.
5. `KNOWN_ISSUES` §9 and §11 updated with results; ROADMAP H0-3b marked ✅ only after the developer's local Windows confirmation.

## 12. Not verified yet (check before implementation)

- Whether `NodeStore`'s `wal` is persisted or usable for delta journalling.
- Directory-fsync behaviour on Windows through the standard library.
- Whether any tooling or test reads the legacy `persist/*.json` file names directly.
