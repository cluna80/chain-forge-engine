# Account-state leaf, version 2 — normative byte-level encoding

**Status: PROPOSED, NOT IMPLEMENTED.** This directory (PR-A) contains documentation, golden vectors and an independent Python reference encoder only. No Rust, consensus, state-root, genesis or persisted-format change. The executable form of this text is `reference_encoder.py`; the contract is `vectors/*.json`. Design rationale and the implementation plan are in `docs/ACCT-LEAF-1-state-leaf-v2-design.md`.
Baseline: Qattice `main` `baf7345`. Owner decisions 2026-11-04: O1 `qattice/state/...` domain family; O2 hybrid encoding; O3 fresh v2 genesis/devnet regeneration first, height-gated migration only as a separately gated design; O4 escrow commitment kept while the field exists; O5 `role` and all `IntrinsicCharm` fields committed; O6 additive manifest metadata if old-binary fail-closed behavior is demonstrated, else a format-version bump; O7 a separate STATE-COMMIT-2 investigation before production encoder work.

## 1. What is being encoded
The value stored in the state tree for an account: `AccountState::to_leaf_bytes()` today (v1, text) and `leaf_v2` here. The tree key is the account address and the tree hashes the value itself (section 4); this document defines only the value bytes and the hashes of the hashed substructures inside it.

## 2. Primitives (clarification 3)
All multi-byte integers are **big-endian, fixed width**. There is no variable-length integer, no text number, no `usize`, no floating point, no JSON anywhere in consensus bytes.
| Name | Encoding |
|---|---|
| `U8` / `U32` / `U64` / `U128` | 1 / 4 / 8 / 16 bytes, big-endian, unsigned |
| `BOOL` | one byte, `0x00` or `0x01`; any other value is invalid |
| `BYTES(max)` | `U32 n` then `n` raw bytes; `n > max` is invalid |
| `STR(max)` | `BYTES(max)` whose bytes must be valid UTF-8; never normalised; no other restriction (NUL and separators are allowed) |
| `HASH` | exactly 32 bytes |
| `OPT_U64` (inside a hashed substructure only) | `BOOL` flag, then `U64` only if the flag is `0x01` |
Optional leaf fields are represented by **tag presence** (section 5), not by a flag byte.

Enum values: `tier_code` = `0` none (no charm), `1` Provisional, `2` Verified, `3` Established (the declaration order of `VerificationTier`). Only these values are valid.

## 3. Domain-separated hash (clarification 1)
```
domain_hash(domain, body) = SHA3-256( U8(len(domain)) || domain || body )
```
`domain` is 1 to 255 bytes of printable ASCII (`0x20..0x7E`). The length byte makes the prefix unambiguous (no domain can be a prefix-confusable continuation of another). SHA3-256 is the FIPS 202 function (the same hash the tree uses; `Sha3_256` in the Rust code). Domains (O1), exact ASCII bytes:
| Substructure | Domain |
|---|---|
| recovery policy | `qattice/state/recovery-policy/v1` |
| pending recovery | `qattice/state/pending-recovery/v1` |
| charm | `qattice/state/charm/v1` |
| escrow | `qattice/state/escrow/v1` |
Legacy signing domains (`chain-forge/tx/v1\n`, `chain-forge/pq-tx/v1\n`, ...) and the v1 leaf encoding are untouched.

## 4. The leaf value versus the tree's own hashing (clarification 6)
Verified against `chain-forge-state/src/jmt.rs` and by test (the Python implementation reproduces the Rust-pinned leaf bytes and the roots of all eight single-account trees of the S1 parity corpus):
```
key_path   = SHA3-256( address_utf8 )                        // KeyPath::from_address
value_hash = SHA3-256( 0x02 || leaf_value )                  // hash_value(), TAG_VALUE = 0x02
leaf_node  = SHA3-256( 0x00 || key_path || value_hash )      // JmtNode::Leaf, TAG_LEAF = 0x00
internal   = SHA3-256( 0x01 || left || right )               // TAG_INTERNAL = 0x01
```
The root of a tree with exactly one account is that account's `leaf_node`. **The leaf value is the pre-image of `value_hash`; v2 adds no hash around it.** The domain-separated hashes of section 3 exist only *inside* the leaf value, for the hashed substructures. The two layers cannot collide: tree hashes start with a one-byte tag `0x00/0x01/0x02`, a substructure hash starts with a domain length byte of at least `0x14`, and the leaf value starts with the magic `0x00 'Q' 'A' 'L' 'E' 'A' 'F' 0x00`.

## 5. Leaf layout, version 2 (clarification 2)
```
leaf_v2 = MAGIC(8) || VERSION(1) || BODY_LEN(U32) || FIELD*
MAGIC   = 00 51 41 4C 45 41 46 00        // NUL "QALEAF" NUL
VERSION = 02
FIELD   = TAG(U8) || VALUE
```
`BODY_LEN` is the exact number of bytes after the header (`leaf length - 13`). It makes the format **prefix-free**: a truncated leaf and a leaf with trailing bytes are both rejected (a draft without it accepted a leaf cut at a field boundary as a shorter valid account; the test `test_every_proper_prefix_of_every_leaf_is_rejected` found this). Tags must be **strictly ascending**; each appears at most once.
| Tag | Field | Value encoding | Required |
|---|---|---|---|
| `01` | address | `STR(256)`, non-empty | yes |
| `02` | nonce | `U64` | yes |
| `03` | role | `STR(64)` | yes |
| `04` | tier | `U8` tier code | yes |
| `05` | balances | `U32 count (<= 256)`, then per entry `STR(64)` non-empty denom, `U128` amount; denoms **strictly ascending by UTF-8 bytes** | yes (count may be 0) |
| `06` | public key | `BYTES(4096)` (`Some(empty)` is a present, zero-length key) | no; absent means `None` |
| `07` | key_version | `U32` | yes |
| `08` | policy_generation | `U64` (always present, also when 0) | yes |
| `09` | recovery_policy_hash | `HASH` | no |
| `0A` | pending_recovery_hash | `HASH` | no |
| `0B` | charm_hash | `HASH` | no |
| `0C` | escrow_hash | `HASH` | no |
Consistency rule: `tier_code != 0` if and only if tag `0B` is present (a charm always has tier 1 to 3). Amounts of 0 are kept as entries. Any other tag is invalid in version 2.

## 6. Hashed substructures (clarification 4)
Each is `domain_hash(<its domain>, body)`. Field order inside a body is fixed and listed here; lists are in **stored order** and never sorted (guardian order is semantically significant).
- **recovery policy** (`RecoveryPolicy`): `U32 threshold`, `U32 enrolled_at_key_version`, `U64 policy_id`, `U32 n` (1..=64), then `n` x `BYTES(4096)` guardian public keys in stored order.
- **pending recovery** (`PendingRecovery`): `BYTES(4096) new_public_key`, `STR(64) new_key_scheme`, `U32 key_version`, `U64 submitted_at_height`, `U64 activation_height`, `U64 policy_id`, `BOOL cancelled`.
- **charm** (`IntrinsicCharm`): `U8 tier` (1..=3), `U32 decay_exemption.days`, `U64 decay_exemption.last_earned_epoch`, `OPT_U64 verified_since_epoch`, `U64 last_attested_epoch`, `U32 consecutive_active_epochs`, `BOOL verified_via_wot`.
- **escrow** (`EscrowBinding`): `STR(256) job_id`, `STR(256) agent_wallet`, `STR(256) funding_source`.
Every body must be consumed exactly (no trailing byte). `role`, `address` and the other scalars are inline in the leaf, not hashed.

## 7. Bounds and malformed-input rejection (clarification 5; bounds are proposal O8)
Bounds are part of the commitment profile: changing one is a profile change (section 8).
| Item | Bound |
|---|---|
| address | 1..=256 bytes |
| role | 0..=64 bytes |
| denom | 1..=64 bytes |
| balance entries | 0..=256 |
| public key / guardian key / pending key | 0..=4096 bytes (ML-DSA-65 is 1952) |
| guardians in a policy | 1..=64 (the transaction rule `MAX_GUARDIANS` is 10 and is a separate, stricter, policy limit) |
| key scheme string | 0..=64 bytes |
| escrow strings | 0..=256 bytes each |
| whole leaf | <= 32768 bytes |
A decoder must reject, with a stable code: `bad_magic`, `bad_version`, `truncated`, `trailing_bytes` (body length does not match), `unknown_tag`, `duplicate_tag`, `tag_out_of_order`, `missing_required_tag`, `tier_out_of_range`, `tier_charm_mismatch`, `length_over_bound`, `balance_count_over_bound`, `balances_not_strictly_ascending` (also catches duplicates), `empty_not_allowed`, `invalid_utf8`, `bool_not_01`, `guardian_count`, `leaf_over_bound`. Substructure decoders reject the same classes within their bodies. `vectors/state-leaf-v2.json` contains 51 negative vectors (each with the expected code); a Rust decoder must agree on the code, not only on rejection. Encoders refuse out-of-range integers, non-boolean flags, lone surrogates and over-bound inputs.

## 8. Versioning and the upgrade contract (clarification 9)
The leaf `VERSION` byte identifies a **commitment profile**: the leaf layout, the tag set and required set, every field encoding, the bounds, **and the exact domain strings and body encodings of all hashed substructures**.
| Profile | Meaning |
|---|---|
| 1 | legacy text leaf (frozen; see section 9) |
| 2 | this document: layout v2 with `recovery-policy/v1`, `pending-recovery/v1`, `charm/v1`, `escrow/v1` |
Rules:
1. Changing a substructure's body encoding, its domain string version (for example `charm/v1` to `charm/v2`), adding or removing a tag, changing a bound that changes validity, or changing any field encoding is **a new profile** (`VERSION = 3`, ...). A substructure domain is never changed in place.
2. A new profile takes effect only through an explicit chain parameter (`state_leaf_version`) and, for a chain that changes profile mid-life, a height-gated activation under a separately approved design (not part of the initial implementation, O3).
3. A decoder for profile N rejects any other `VERSION` (`bad_version`); it never guesses the profile from the bytes. The magic is a consistency check only.
4. Adding a field to the account always requires a new profile; the exhaustive-destructuring guard in the future Rust encoder (design T1) forces that decision at compile time.

## 9. Historical v1 roots stay verifiable (clarification 7)
- The v1 encoder is frozen and stays in the codebase permanently, selected by the chain parameter / `leaf_version_at(height)`, never by sniffing bytes. A v1 leaf starts with the address text (never `0x00`); a v2 leaf starts with `0x00`.
- `vectors/state-leaf-v1-legacy.json` records v1 leaf bytes and their tree hashes. The Python v1 encoder plus the tree hashing of section 4 reproduces the Rust-pinned corpus recorded from `main` `61e02c6` before any change (eight accounts, eight single-account roots): this is the evidence that old roots can be recomputed independently of the Rust code.
- v1 weaknesses are documented, not fixed: it does not commit `key_version`, the pending recovery, the guardian keys, `role`, or the charm beyond the tier, and it is ambiguous for denoms containing `|` or `=` (vectors `v1_ambiguity_*`).
- Block headers are never rewritten; a chain that stays on profile 1 keeps every historical root.

## 10. Mainnet v2-from-genesis without the migration machinery (clarification 8)
Yes. If a genesis declares `state_leaf_version = 2` for the whole life of the chain, the implementation needs only: the v2 encoder and decoder, the chain parameter (default 1 when absent, so every existing genesis hash is unchanged), `StateStore` plumbing that picks the encoder from that parameter, the manifest field and its check, and genesis validation. It does **not** need the height-gated activation pass (the one-time re-leafing of every account in block H), per-height version selection, or any v1-to-v2 conversion. `leaf_version_at(height)` is then a constant. The activation design stays a separate, gated document (design PR-F) and is required only for a chain that must change profile after genesis. The v1 encoder remains compiled for devnets and historical verification.

## 11. Persistence compatibility and old-binary behavior (O6)
Findings from the current code (verified): `SnapshotManifest` has no `deny_unknown_fields`, so an additive field is parsed and ignored by a binary that does not know it. A binary that does not know profile 2 would then recompute the root with the v1 encoder and compare it to the manifest's `state_root`; for any non-empty v2 state these differ and the restore is **refused** (existing tests `r1_a_manifest_root_that_does_not_match_the_restored_state_is_fatal` and `r5_state_content_that_no_longer_produces_the_recorded_root_is_fatal` pass today; `f1_unknown_future_format_version_is_refused` and `f2_*` show the explicit-version refusal path). So an old binary fails closed on a v2 data directory, with a generic root-mismatch message and not a "unsupported leaf version" message.
Proposal: add `state_leaf_version` (serde default 1) to the manifest and the storage v2 descriptor; a new binary reads an absent field as 1, restores with the recorded profile, and refuses a manifest whose profile disagrees with the genesis parameter. No `FORMAT_VERSION` bump if the owner accepts the generic old-binary message. **If a clear message is required, bump `FORMAT_VERSION`** (old binaries then refuse with the explicit unknown-format error). Tests required in PR-E before choosing: (a) a v1 manifest with an unknown extra field loads (tolerance); (b) the same directory with a `state_root` computed under profile 2 is refused by the unchanged v1 loader (fail-closed), and the refusal does not modify the directory; (c) a new binary refuses a profile/genesis disagreement; (d) a tampered `pending_recovery`, guardian key, `key_version` or `role` in `state.json` is refused under profile 2 (accepted under profile 1, documented).

## 12. Vectors and how a Rust implementation must use them
`vectors/state-leaf-v2.json`: 19 positive accounts (each with the expected leaf hex, `leaf_sha3_256`, the four substructure hashes, `jmt_value_hash`, `jmt_leaf_node_hash`) and 51 negative inputs (leaf and substructure bodies, each with `expected_error`). Large keys are written `{"seq": {"seed": s, "len": n}}` (byte `i` = `(s + i) mod 256`) to keep the file small. `vectors/state-leaf-v1-legacy.json`: 11 legacy cases, eight of them the S1 parity corpus. The Rust encoder (PR-C) must reproduce every positive vector byte for byte, reject every negative vector with the same code, and pass on Linux and Windows; the vector files are regenerated only by a reviewed change to `generate_vectors.py` (the test suite fails if the committed JSON differs from regeneration).

## 13. Running the checks
```
python3 -m unittest discover -s docs/state-leaf-v2 -v      # standard library only; openssl optional (independent SHA3 check)
python3 docs/state-leaf-v2/generate_vectors.py             # rewrites vectors/*.json (review the diff)
```
On Windows use `py -3` instead of `python3`.
