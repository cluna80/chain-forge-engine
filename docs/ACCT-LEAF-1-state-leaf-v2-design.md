# ACCT-LEAF-1 — Versioned account-state leaf (v2): design specification

**Status: DESIGN, owner-reviewed 2026-11-04 (Option A approved in principle). Nothing in this document is implemented.** No production code, genesis, signing, state-root or persisted-format change is made by this document or by the PRs that carry it. Baseline: Qattice `main` `baf7345`.
**Normative byte-level encoding: `docs/state-leaf-v2/ENCODING.md` (PR-A), with golden vectors and an independent Python reference encoder.** Where this document and ENCODING.md differ on a byte, ENCODING.md wins; this document keeps the rationale, the compatibility strategy, the tests and the plan.

## 0. Owner decisions (2026-11-04) and where each is applied
| # | Decision | Applied in |
|---|---|---|
| O1 | New commitments use the `qattice/state/...` domain family; existing signing domains and the legacy v1 encoding are not renamed | ENCODING.md section 3 |
| O2 | Hybrid encoding: scalar fields inline, larger variable-length substructures committed by domain-separated SHA3-256 | section 3 here; ENCODING.md sections 5 and 6 |
| O3 | Fresh v2 genesis / devnet regeneration first; v1 histories preserved; height-gated migration is a separately gated design, not a requirement for the initial mainnet implementation | section 4 here; ENCODING.md section 10 |
| O4 | The optional escrow commitment stays while the field exists; no escrow deletion and no QRC cleanup in this milestone | tag `0C` |
| O5 | `role` and every `IntrinsicCharm` field are committed, in addition to complete recovery, key-version and balance coverage | tags `03`, `04`, `0B` |
| O6 | Prefer additive manifest metadata; first specify and test old-binary fail-closed behavior; propose a format-version bump if compatibility cannot be demonstrated | section 4.5; ENCODING.md section 11 |
| O7 | A separate read-only STATE-COMMIT-2 investigation (identity, agents, validator sets, liveness, slashing) before production encoder work | section 9; plan item 0 |

## 0.1 The nine clarifications and where they are answered
| # | Clarification | Answer |
|---|---|---|
| 1 | Domain-prefix bytes and hash inputs | ENCODING.md section 3: `SHA3-256(U8(len(domain)) || domain || body)`, four exact ASCII domains |
| 2 | Leaf magic, version and field tags | section 5: magic `00 51 41 4C 45 41 46 00`, version `02`, explicit `U32` body length, tags `01..0C` strictly ascending |
| 3 | Integer widths, optionals, enum values | section 2: fixed-width big-endian; optional leaf fields by tag presence; `tier_code` 0..3 |
| 4 | Nested structs, optional charm values, guardian order | section 6: fixed field orders, `OPT_U64` for `verified_since_epoch`, guardians in stored order |
| 5 | Bounds and malformed-input rejection | section 7: bounds table, 18 stable error codes, 51 negative vectors |
| 6 | Leaf value versus the tree's own hashing | section 4: the leaf is the pre-image of `SHA3-256(0x02 || leaf)`; verified against Rust-pinned roots |
| 7 | Historical v1 roots stay verifiable | section 9: frozen v1 encoder, selection by chain parameter, cross-checked against the eight-account Rust corpus |
| 8 | Can mainnet v2-from-genesis avoid the height-gated migration implementation? | **Yes**: section 10 lists exactly what is and is not needed |
| 9 | Substructure upgrade rules | section 8: the leaf version is a commitment PROFILE; any substructure domain or body change is a new profile governed by an explicit parameter / activation contract |

## 0.2 Finding from writing the vectors
The first draft of the layout was not prefix-free: because optional fields are omitted, a leaf cut at a field boundary decoded as a valid shorter account. The vector test `test_every_proper_prefix_of_every_leaf_is_rejected` exposed it. The layout now carries an explicit `U32` body length, and trailing or missing bytes are rejected with stable codes.


## 1. What the state root covers today (VERIFIED)

- `StateStore` keeps `accounts` (`HashMap<address, AccountState>`) and `metadata` (`HashMap<String,String>`) and **one Jellyfish Merkle Tree** (SHA3-256). The block's `state_root` is `StateStore::current_root()`.
- Tree entries are exactly two kinds:
  1. **Accounts**: key = the address string, value = `AccountState::to_leaf_bytes()`.
  2. **Metadata**: key = `"meta:" + key`, value = the raw string bytes (`set_raw`). Users today: `gov:module` (the governance module as JSON of `GovernanceModule { config, proposals: BTreeMap, next_id }`, deterministic: no `HashMap`), `crypto_migration:active`, the validator owner-binding keys (`validator-owner:*` and the binding key). Validator bonds (`validator-bond:` prefix) and research claim records (`claim:` prefix) are ordinary accounts, not metadata.
- The node persists eight files per generation (`SNAPSHOT_FILES`): `state.json`, `identity.json`, `validators.json`, `agents.json`, `slashing.json`, `chain_store.json`, `historical_validator_sets.json`, `live_validator_set.json`. Restore verifies the recomputed state root against the manifest's `state_root` (test family `r*`, `r5_*`). Only `state.json` feeds the tree.
- There is **no account-proof API** today (the tree exposes `upsert`, `remove`, `root_hex`; no proof generation). Proof generation is therefore a design constraint for v2, not a compatibility constraint.

Current leaf (v1) is the text `address|nonce|tier|denom=bal|...` plus, only when present, `pk=<hex>`, `escrow=<json>`, `recovery=t{threshold}/{n_guardians}/{enrolled_at_key_version}/pid{policy_id}`, `pgen={n}`.

## 2. Field-by-field commitment coverage (the matrix)

`AccountState` after S1: generic fields plus `ext: AccountExtFields`.

| # | Field (type) | In v1 leaf? | Other authenticated commitment | Effect on execution / security if omitted | v2 encoding |
|---|---|---|---|---|---|
| 1 | `address: String` | yes (text) and as the tree key | key | none | length-prefixed UTF-8 (inline) |
| 2 | `balances: BTreeMap<String,u128>` | yes, as `denom=amount` text | none | ownership of funds | inline, count + sorted (len, denom, 16-byte BE amount). **v1 is not self-delimiting** (see 2.1) |
| 3 | `nonce: u64` | yes | none | replay protection | inline, 8-byte BE |
| 4 | `role: String` | **no** | none | **drives validator selection**: the node picks genesis validators by `a.role == "validator"` (node.rs startup / epoch paths). It changes only at genesis in practice, but it is authorization-relevant | inline, length-prefixed UTF-8 |
| 5 | `charm.tier` (`VerificationTier`) | yes (text) | none | gates identity-dependent transactions and consensus eligibility | inside the charm commitment, and also exposed inline as a 1-byte tier (cheap lookups without the preimage) |
| 6 | rest of `charm: IntrinsicCharm` (`decay_exemption{days,last_earned_epoch}`, `verified_since_epoch`, `last_attested_epoch`, `consecutive_active_epochs`, `verified_via_wot`) | **no** | none for the account copy | not read by execution/node logic today (the one `verified_via_wot` use is on the `IdentityStore` record, not the account), so informational now; still account state that would matter if used | hashed substructure (`charm_hash`) |
| 7 | `public_key: Option<Vec<u8>>` | yes (`pk=` hex) | none | which key controls the account | inline, flag + length-prefixed raw bytes (no hex) |
| 8 | `ext.escrow: Option<EscrowBinding>` | yes (`escrow=` JSON) | none | dormant resource-market binding. **QRC/market is retired; the field may be deleted by the QRC cleanup** | hashed substructure (`escrow_hash`) only while the field exists |
| 9 | `ext.key_version: u32` | **no** | none | gates `RotateAccountKey` (must be current + 1) and is bound into rotation / recovery signatures | inline, 4-byte BE |
| 10 | `ext.recovery_policy: Option<RecoveryPolicy{guardians: Vec<Vec<u8>>, threshold, enrolled_at_key_version, policy_id}>` | **partly** (threshold, guardian COUNT, enrolled_at_key_version, policy_id) | none | **the guardian public keys are the recovery authority and are not committed** | hashed substructure (`recovery_policy_hash`) over the complete canonical policy including every guardian key in order |
| 11 | `ext.policy_generation: u64` | yes, only when > 0 | none | replay protection of guardian signatures across re-enrolments | inline, 8-byte BE (always present) |
| 12 | `ext.pending_recovery: Option<PendingRecovery{new_public_key, new_key_scheme, key_version, submitted_at_height, activation_height, policy_id, cancelled}>` | **no** | none (submitting clears `recovery_policy`, which moves the root indirectly; the record itself, and `CancelRecovery`'s `cancelled = true`, move nothing) | decides which key the block-end sweep installs and when | hashed substructure (`pending_recovery_hash`) over the complete canonical record |

### 2.1 Findings in the v1 encoding itself (hardening, independent of the missing fields)
1. Not injective in principle: parts are joined with `|` and `=` without escaping or lengths, so a balance map `{"a":1,"b":2}` and a single denom named `a=1|b` with amount 2 produce the same bytes. Denoms originate from genesis/config (a user can only move a denom the sender already holds), so this is low risk in practice, but v2 must be injective by construction.
2. `escrow` is embedded as a JSON string; JSON object key order and number formatting then become consensus-critical. v2 uses no JSON inside consensus bytes.
3. Hex of the public key doubles its size and adds no information.

### 2.2 What is outside the tree entirely (task 7; see section 9)
The `IdentityStore` (attestation ledger, sybil logs, penalties, records, epoch clock), the `AgentStore`, `validators.json`, `slashing.json`, `live_validator_set.json` and `historical_validator_sets.json` are persisted but are **not** in the tree. Only the account copy of the tier is.

## 3. The v2 leaf format

Goals: complete (every row of section 2 that influences execution or authorization), injective, deterministic across platforms, domain-separated, versioned, compact, extensible without breaking old proofs.

### 3.1 to 3.3 Primitives, layout and hashed substructures: see ENCODING.md
Summary only. Fixed-width big-endian integers, length-prefixed UTF-8 strings, sorted maps, no JSON; leaf = `MAGIC(8) || 02 || BODY_LEN(U32) || FIELD*` with `FIELD = TAG(U8) || VALUE`, tags `01` address, `02` nonce, `03` role, `04` tier, `05` balances, `06` public key (optional), `07` key_version, `08` policy_generation, `09` recovery_policy_hash, `0A` pending_recovery_hash, `0B` charm_hash, `0C` escrow_hash (the four hashes optional), in strictly ascending tag order. The hashed substructures are `SHA3-256(U8(len(domain)) || domain || body)` over the fixed-order bodies in ENCODING.md section 6 (guardian keys in stored order, the complete pending record, every charm field, the escrow strings). Account proofs, hashed-versus-inline trade-offs and upgrade rules follow.

### 3.4 Inline versus hashed (comparison, task 4)
| | Complete inline encoding | Hybrid (recommended): scalars inline, large/variable substructures hashed |
|---|---|---|
| Leaf size | with a 3-guardian ML-DSA policy about 6 KB, plus about 2 KB for a pending recovery; every account with recovery state pays it in the tree and in every proof | about 150 to 250 bytes for any account |
| Account proof | a proof carries the whole leaf; large for recovery accounts | a proof carries the small leaf; a verifier who needs guardians or a pending record asks for that preimage and checks it against the 32-byte hash in the proven leaf (selective disclosure) |
| Correctness | simplest to reason about | needs the substructure encodings to be canonical (specified in 3.3) |
| Upgrades | adding a field to a substructure changes the leaf layout and version | adding a field to a substructure changes only that substructure's domain version; the leaf layout stays |
| Light-client friendliness | poor | good |
| Risk | storage / bandwidth growth with guardian count (max guardians is bounded by `MAX_GUARDIANS`) | one more hashing step; must keep preimages available to nodes that serve proofs |
Recommendation: hybrid. The hash covers everything, so the commitment is complete either way; the difference is proof size and upgrade surface.

### 3.5 Account proofs (future-proofing, task 4)
There is no proof API today. v2 does not add one, but the layout supports it: JMT inclusion proof for key = address -> leaf bytes -> optional substructure preimages. A proof of non-existence of a pending recovery is the leaf's `opt` flag being `0x00`.

## 4. Versioning, activation and compatibility

### 4.1 Leaf version as chain parameter
`state_leaf_version` (1 or 2) and, for chains that change versions, `state_leaf_v2_activation_height`. Both belong to the genesis `consensus`/`execution` section (they are consensus parameters, hashed into the genesis hash like the rest of the genesis). An absent field means version 1 for the whole chain, so **every existing genesis and its genesis hash is unchanged** (the S0 baseline of 28 genesis hashes must stay identical).

### 4.2 Fresh mainnet
Mainnet genesis sets `state_leaf_version = 2` from block 0. No migration, no activation height, no v1 code on the mainnet path (v1 stays in the codebase for historical/devnet verification). Because mainnet is a fresh all-ML-DSA genesis, this is the cheapest moment to change the leaf.

### 4.3 Existing devnets (owner decision O3: regenerate first; the height-gated path is a separately gated design)
1. **Regenerate** the devnet with a v2 genesis (devnets are disposable; `devnet-legacy-2026-10` is already preserved as history). No code beyond section 4.2.
2. **Height-gated activation (DEFERRED, separately gated design; not required for the initial mainnet implementation, see ENCODING.md section 10)** for a devnet that must keep its history: `state_leaf_v2_activation_height = H`. Blocks below H use v1 leaves and v1 roots (historical roots unchanged). In block H, after all transactions, the DIS sweep and fee distribution, and **before** the root is computed, every account is re-leafed under v2 in one deterministic pass (cost O(accounts); metadata leaves are unchanged). Block H's root is the first v2 root. Every later block touches leaves with v2 only.
3. **Do not activate** (stay v1). Valid for chains that never go to mainnet.

### 4.4 Coordination and rollback
- All validators must run a v2-capable binary before H; a node without v2 computes a different root at H, which is a consensus failure (safe: it halts or forks off, it does not accept a wrong root). Choose H at least N blocks after the release; announce it.
- Rollback: before H nothing changed. After H, going back requires a v1-capable binary and a snapshot taken before H; there is no in-place downgrade. The re-leafing is reversible deterministically, but only as another coordinated change. Keep a verified backup and a pre-H snapshot.

### 4.5 Persistence, snapshots, storage v2, restart integrity
- The manifest gains `state_leaf_version` (serde default 1 when absent). Restore recomputes the root with the recorded version and compares to `state_root`; it also checks that the version agrees with `leaf_version_at(height)` derived from the genesis parameters (else refuse). A tampered `pending_recovery`, guardian key or `key_version` in `state.json` now changes the recomputed root and is rejected; today it is not.
- An older binary reading a newer manifest ignores the unknown field, recomputes v1, mismatches and refuses to start (fail-closed). A newer binary reading an older manifest treats it as v1. **Evidence for O6 (verified now):** `SnapshotManifest` has no `deny_unknown_fields`; the existing tests `r1_*` and `r5_*` (a root that does not match the restored state is fatal) and `f1_*` / `f2_*` (explicit format-version refusals) pass on `main`. The old-binary message would be the generic root mismatch; if a clear 'unsupported leaf version' message is required, bump `FORMAT_VERSION`. The four tests that must pass before choosing are listed in ENCODING.md section 11 (PR-E).
- storage v2 (experimental, default-off): block-log records carry the root as an opaque string (no format change); the generation descriptor gains the same `state_leaf_version` field. `FORMAT_VERSION` is not bumped for an additive manifest field; if the owner prefers a bump, v1/v2 refusal rules apply as for the existing format checks.
- **Historical state roots**: block headers are not rewritten. Verification of an old block uses `leaf_version_at(height)`. Both encoders therefore live in the codebase side by side, selected by version, never by guessing from the bytes (the MAGIC prefix is a consistency check only).

## 5. Tests, written BEFORE implementation (acceptance criteria)

T1 **Exhaustive field mutation.** The v2 encoder destructures `AccountState` and every nested struct without `..` (a compile-time guard: adding a field breaks the build until the encoding is updated). A table-driven test mutates each field individually (including each guardian key, `cancelled`, `activation_height`, `key_version`, `role`, every charm field) and asserts the leaf and the root change; its negative twin asserts that fields declared non-committed (none expected) do not.
T2 **Canonical determinism and golden vectors.** Published byte-level vectors (hex) for a set of accounts (empty, balances only, with key, with recovery policy, with pending, with charm, all fields, many denoms, non-ASCII strings). An **independent reference encoder written in Python** (not derived from the Rust) must produce identical bytes; the Rust test and a script both check the same vector file. Same vectors run on Linux and Windows (BossKing).
T3 **Injectivity / negative cases.** Denoms containing `|`, `=`, NUL, very long strings; balances `{"a":1,"b":2}` versus `{"a=1|b":2}` give different leaves under v2 (and the same under v1: documented regression test for the legacy encoder). Non-ascending maps and over-long lengths are rejected by the decoder / validator.
T4 **Order independence.** Insert accounts in many orders (including reversed and shuffled) and assert identical roots; shuffle `HashMap` iteration inputs.
T5 **Tamper detection on restore.** Write a snapshot, alter in `state.json` each of: `pending_recovery.new_public_key`, `activation_height`, `cancelled`, a guardian key, `key_version`, `role`; assert restore refuses (v2) and (documented) accepts under v1.
T6 **Recovery lifecycle commitments.** Drive the full lifecycle through the executor (enroll, update guardians, submit recovery, cancel, re-enroll cancelling a pending one, rotate, sweep activation) and assert after every step that the root changed whenever any committed field changed, including `CancelRecovery` (which changes only `cancelled`) and the sweep clearing `pending_recovery`.
T7 **Historical roots under their original version.** The existing S0 baseline (28 genesis hashes), the account-leaf corpus and the S2 execution corpus must stay byte-identical when the chain parameter is v1; new v2 corpora are recorded separately and deliberately.
T8 **Activation.** A 4-node live devnet crossing H: blocks below H have v1 roots equal to a v1-only reference run; block H onward v2; all nodes agree; a node restarted across H restores correctly; a snapshot taken before and after H each restores with the right version; a v1-only binary stops at H (fail-closed). Linux and Windows.
T9 **Cross-platform parity.** T2 and T8 on BossKing; no floating point, no locale-dependent formatting, no `usize` in consensus bytes.
T10 **Performance bound.** Re-leafing 100k and 1M accounts: record time and memory; the activation block must still fit the block time budget (or be spread across blocks if it does not; see risk R5).

## 6. Implementation plan: independently reviewable PRs (none authorized yet)
0. **STATE-COMMIT-2 (O7), read-only, before PR-C:** classify identity, agents, validator sets, liveness and slashing state as authoritative / derived / node-local and decide what must be committed (section 9). No code.
1. **PR-A (docs and vectors only; opened for review):** `docs/state-leaf-v2/` with the normative ENCODING.md, 19 positive and 51 negative golden vectors, the frozen v1 vectors, an independent Python reference encoder and 31 self-tests. No Rust change, no state-root change, no baseline replaced.
2. **PR-B:** extract the v1 encoder behind a `LeafVersion` abstraction (`to_leaf_bytes_v1`), no behavior change; the existing corpora and the S0 baseline prove it. Add the exhaustive-destructuring guard test for v1.
3. **PR-C:** the v2 encoder and the substructure encoders with T1 to T4; unused by consensus (selected only in tests).
4. **PR-D:** chain parameters `state_leaf_version` / `state_leaf_v2_activation_height` (default v1), `StateStore` plumbing (`leaf_version_at(height)`), genesis validation and hashing rules; T7 must show all current genesis hashes unchanged.
5. **PR-E:** persistence: manifest `state_leaf_version`, restore verification, storage v2 descriptor; T5.
6. **PR-F (DEFERRED, optional):** the height-gated activation pass at block H. NOT required for a mainnet that starts on v2 (ENCODING.md section 10); proceeds only if the owner approves a separate activation design. T8 applies only if PR-F is built.
7. **PR-G:** mainnet and devnet genesis templates default to v2; deliberate re-recording of the v2 corpora; ROADMAP / KNOWN_ISSUES (ACCT-LEAF-1 closure criteria).
Each PR: tests first, Linux and BossKing results, mutation checks on the new code, no unrelated changes.

## 7. Risks
R1 Existing devnet data: an unflagged upgrade fails the manifest root check (safe but disruptive). Mitigation: the chain parameter defaults to v1; documented activation procedure; pre-H snapshot.
R2 Consensus split at H if validators are not all upgraded. Mitigation: announce H, N-block lead time, readiness check; on devnets acceptable.
R3 Encoder drift between Rust and the reference (T2) and between versions. Mitigation: the Python reference, shared golden vectors, version selection by parameter, not by sniffing.
R4 Preimage availability for hashed substructures (only matters once a proof API exists). Mitigation: nodes keep full accounts; a future proof service returns preimages.
R5 Re-leafing cost at H. Mitigation: T10 measurement; if needed, spread re-leafing across blocks with a per-account leaf version (a larger design change; only if measured to be necessary).
R6 The QRC cleanup may delete `ext.escrow` and other dormant fields. Mitigation: sequence PR-C after that decision, or keep `escrow_hash` optional; the exhaustive-destructuring guard forces the question at compile time.
R7 `role` and charm fields are committed here although some are informational today. Cost is small; the benefit is that the leaf commits all account state, not a curated subset.
R8 Changing the domain-string family or the field order later is a new leaf version; get O1 to O5 right now.

## 8. Decisions
**Resolved by the owner on 2026-11-04:** O1 to O7 (section 0).
**Still open (new, from writing the byte-level spec):**
- O8 The size bounds in ENCODING.md section 7 (address 256, role 64, denom 64, 256 balance entries, 4096-byte keys, 64 guardians, 32 KiB leaf). They are part of the commitment profile; changing them later is a new profile.
- O9 Whether the first Rust implementation (PR-C) should also include the substructure decoders (needed only for proof servers and tamper diagnostics) or only the encoders.
- O10 `FORMAT_VERSION`: additive manifest field with the generic old-binary failure message (default), or a bump for a clear message (decide after the PR-E tests).
- O11 Whether the QRC cleanup removes `escrow` before PR-C (tag `0C` would then be reserved and unused, not renumbered).

## 9. Other state that is not authenticated by the root (task 7): needs its own investigation
Not a defect claim; a coverage map. For each: where it lives, how it is persisted, whether anything in the root covers it, and the question to answer.
| State | Lives in | Covered by the state root? | Why it may need a commitment |
|---|---|---|---|
| Identity records, attestation ledger (who attested whom, counts), sybil confirmations / penalties, epoch clock | `IdentityStore` -> `identity.json` | only the account copy of the **tier** | attestation counts and quorum progress decide tier changes and therefore consensus eligibility; the B-03 test could only observe them through the API, not through a root |
| Agent records, sponsor links, spend counters, limits | `AgentStore` -> `agents.json` | no | agent authority and spending limits |
| Validator registry, power, jail / liveness counters, slashing evidence | `validators.json`, `slashing.json`, `live_validator_set.json`, `historical_validator_sets.json` | validator bonds (accounts with the `validator-bond:` prefix) and owner bindings (metadata) are covered; power, jail status and liveness windows are not | voting power and jailing affect consensus; they are derived deterministically from committed data plus the identity store, so their divergence would appear as a consensus failure, not silently |
| Governance | metadata `gov:module` (JSON of a `BTreeMap`-based struct) | yes (deterministic serialization verified) | covered; keep the BTreeMap discipline |
| Crypto migration state | metadata `crypto_migration:active` | yes | covered |
| Node-local caches (nonce caches, mempool) | memory | no (by design) | not consensus state |
Recommended follow-up (separate, read-only first): "STATE-COMMIT-2": for the identity store and the validator/liveness state, decide for each whether it is (a) fully derivable from committed data, (b) consensus-relevant and should be committed, or (c) node-local. The identity store is the most important to settle because tier eligibility depends on it.

## 10. Summary
Owner-approved principle: versioned hybrid commitments (Option A) with `qattice/state/...` domains, fresh v2 genesis first, `role` and the full charm committed, escrow kept, additive manifest metadata subject to the fail-closed tests. This PR (design) stays a draft; PR-A (vectors and reference encoder) is the first deliverable; no Rust implementation is authorized yet, and STATE-COMMIT-2 precedes PR-C.
