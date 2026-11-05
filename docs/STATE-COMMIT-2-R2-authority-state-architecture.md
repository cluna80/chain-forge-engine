# STATE-COMMIT-2 R2 — unified authenticated-state architecture (DESIGN PROPOSAL, draft)

Design only. Nothing here is implemented or authorized. No production, state-root, signing, genesis or persisted-format change.
Depends on: `docs/STATE-COMMIT-2-audit.md` (this PR) and the draft ACCT-LEAF-1 documents (PRs #82, #84, unmerged; referenced, not modified).
Evidence labels: **[E#]** = reproduced in sandbox (audit §11, Windows pending). **[R]** = source reading. **[D]** = design choice, unverified.

## 1. Problem in one paragraph

Consensus-relevant state lives in three places: the JMT (accounts, `meta:` entries), side stores that are persisted but not committed (identity, validators, agents, slashing, live/historical validator sets), and node-local data. Edits to the side stores restore cleanly with an unchanged root **[E2, E3, E4]**, and one committed mirror (account tier) already drifts from its authority **[E1]**.
R2 makes the side stores that decide authorization, eligibility, power or rewards part of what the state root authenticates, without changing how nodes execute.

## 2. State classification (what must be committed)

**Authoritative** (affects authorization / transitions / eligibility / power / rewards; must be committed):

| Store | Records to commit | Notes |
|---|---|---|
| Identity | `IdentityRecord` (id, address, full `IntrinsicCharm`, `PopAttestation`, `last_active_epoch`, `sponsored_agents`, `attestation_ledger`, `attestations_given_*`, `frozen`, `sybil_confirmed`); `AttestationRecord`s; `SybilConfirmationLog`; pending Sybil reports; `coordinator_id`; `EpochClock.current_epoch`; `epoch_reg_count` | [R] struct fields. `epoch_reg_count` and the clock affect admission and lapse |
| Validators | `ValidatorRecord` (id, keys, commission, bond, status, `pop_verified`, registered/last-status epoch, `registration_seq`, jail/evidence fields), `next_registration_seq`, `epoch_evidence`, `epoch_evidence_epoch` | `blocks_proposed/missed` excluded: unused [R] |
| Validator sets | live set (the set used for consensus at height H) and a per-height **digest** of each historical set | historical sets are large; commit the digest chain, keep bodies in the existing logs |
| Agents | `AgentRecord` including status, capabilities, limits, parent, per-epoch and lifetime spend counters, `tx_count` | persisted `*_uqrc` names are a separate rename decision |
| Slashing | `history`, `equivocation_set`, `liveness_windows`, the three `*_slashed` totals | policy/config is genesis-derived, not committed |

**Deterministic caches** (never committed; rebuilt by rule; restore recomputes and compares, refusing on mismatch):
`IdentityStore.by_address`; `ValidatorRegistry.by_pubkey / by_address / validators_by_human`; `AgentStore.by_address / by_sponsor`; `StakeTier` from bond; `pop_verified` and `verification_tier` on validators, **derived from identity at the end of the sweep** [D: invariant to be tested, §9]; `min_bond`, attestation quorum/cap, slashing policy (genesis).

**Node-local** (not committed, not trusted for consensus): ExplorerState, PoCD `DiscoveryRegistry` (while its consumer is disabled [R]), `seen_gossip_receipts`, mempool, consensus signing guard (own safety file; keeps its fail-closed behavior).

**Mirror removed**: on v2 chains the account `charm` field stops being a second source of truth. The account leaf carries no identity tier; the identity record is the only source. This eliminates the E1 class instead of patching it [D].

## 3. Architecture options

| | Option M: only `meta:*` entries | Option S: separate authority tree, root committed through one `meta` leaf | Option H: authority root in the block header |
|---|---|---|---|
| Idea | One `meta:authority/<store>/<key>` leaf per record (or one blob per store) in the existing JMT | A second JMT (same hashing as the state tree) holds all authority records; its root is stored as a single leaf `meta:authority_root/v1` in the state tree | Same second tree; root carried in the block header next to the state root |
| Root change | Existing root covers it automatically | Existing root covers it via one leaf | Header format change |
| Per-record proofs | Yes if one leaf per record; no for blobs | Yes (authority-tree proofs plus one state-tree proof for the root leaf) | Yes |
| Cost per block | One-leaf-per-record: JMT writes only for touched records. Blob: rewrite whole store every block | Only touched records plus one root-leaf write | Same as S |
| Failure mode | Namespace crowding: `meta:` already holds `gov:module`, `crypto_migration:active` and address-binding keys written by executor code; authority keys share the namespace and the full-tree iteration/snapshots | Isolated namespace; independent evolution/versioning of the authority encoding | Needs header-format change; touches consensus messages; largest blast radius |
| Compat | Smallest code change | Moderate | Largest |

**Recommendation [D]:** Option **S**. A per-record Option M works technically and is the smallest change, but it mixes high-churn authority records with the single-purpose `meta:` leaves and gives no clean version boundary for the authority encoding. Option H is rejected for Phase 0.5 because it changes the header and consensus messages. The cost of S is a second tree implementation — mitigated by reusing `jmt.rs` unchanged with a distinct key-hash domain (§5).
Owner decision Q1.

## 4. Relationship to ACCT-LEAF-1 v2

- The account leaf (PR #82/#84 draft encoding: magic, version, U32 body length, tags 01–0C) is unchanged by R2 except for one decision: **tag 04 (tier) is dropped or frozen to a constant on the authority profile**, because the tier now lives in the identity record. Q2.
- Both changes ship in **one commitment profile**, chosen by genesis, so a chain is either (legacy) v1 leaf + no authority tree, or (v2) v2 leaf + authority tree. No mixed state, no migration of a running chain.
- ACCT-LEAF-1 domain strings `qattice/state/{recovery-policy,pending-recovery,charm,escrow}/v1` stay as they are. R2 adds a disjoint family `qattice/authority/<kind>/v1` and reuses the **same hash construction** `SHA3-256(U8(len(domain))||domain||body)` so one set of independent-encoder tooling covers both.
- The `charm` substructure (tag 0B) is the one overlap: if Q2 removes the mirror, tag 0B is not emitted for identity-bearing accounts.
- The role/address/denom bounds (audit §14) are a prerequisite of both.

## 5. Canonical encoding and domain separation [D]

Same conventions as ENCODING.md in PR #84: big-endian fixed integers, `U32` length prefixes, explicit lengths for every variable field, **no JSON, no serde, no map iteration order**, collections sorted by byte order of their canonical key, optionals as presence-tagged fields, unknown tag = reject.

Record value (all kinds):
```
00 51 41 55 54 48 00   magic NUL "QAUTH" NUL
U8  profile (=1)
U8  kind                 (0x01 identity, 0x02 attestation, 0x03 sybil-log, 0x04 sybil-report-set,
                          0x05 validator, 0x06 live-valset, 0x07 valset-digest, 0x08 agent,
                          0x09 slashing-history, 0x0A equivocation, 0x0B liveness-window,
                          0x0C scalar (clocks, counters, coordinator))
U32 body_len
body = ordered tagged fields, per kind
```
Leaf key in the authority tree: `key_path = SHA3-256( U8(len(domain)) || domain || U32(len(key)) || key )` with `domain = "qattice/authority/key/v1"`; `key` = `U8(kind) || canonical natural key` (for example the identity id bytes, or `U64 height` for valset digests).
Leaf value hash: `SHA3-256( U8(len(d)) || d || record_bytes )`, `d = "qattice/authority/record/v1"`. This is deliberately different from the state-tree `TAG_VALUE=0x02` hashing so a state leaf can never be replayed as an authority leaf and vice versa.
Authority root leaf in the state tree: key `meta:authority_root/v1`, value = `U8(profile) || 32-byte root`.
Numbers: no floats in any committed record. `ValidatorRegistry.liveness_threshold` is an `f64` [R]: it is genesis/config-derived and **excluded**; if it ever becomes dynamic it must be encoded as a fixed-point integer first.
Bounds: every variable field gets an explicit maximum **together with** the admission/genesis rule that enforces it (owner rule). The numeric maxima are open (Q5) and are not proposed here.

## 6. State-transition ordering and root calculation [D, to be verified against `node.rs` in SC2-B]

For each block at height H the committed order must be fixed and identical on every node:
1. Execute transactions (account, identity, agent, validator-bond mutations as today).
2. Block-end modules in registered order (`TxModule::on_block_end`, e.g. recovery sweep).
3. If `H / validator_epoch_blocks` rolled: `identity.advance_epoch_to`, then the registry sweep (`revoke_pop`), then agent per-epoch spend reset.
4. Apply committed evidence → slashing → registry (jail/slash), then reward eligibility.
5. Recompute the affected authority leaves (touched-record set only), then the authority root, write `meta:authority_root/v1`.
6. Compute the state root (accounts + meta, now including the new authority-root leaf).
7. Persist.
The source today performs 3–4 inside the commit path and transaction execution in the proposal/commit path at separate sites (`node.rs ~4347` vs `~4532`) **[R]**. The audit did not establish the relative order of those sites on the proposer and validator paths. That is the first thing SC2-B must prove, since the root is only meaningful if proposer and validators run the identical sequence. Test T-AUTH-ORDER.
Touched-record tracking must be deterministic: derive the set from the operations performed, never from diffing HashMaps.

## 7. Deterministic reconstruction and restore checks

Restore (extension of `load_persisted_state`, after the existing `state_root` check):
1. Parse side-store files as today (no semantic trust).
2. Rebuild every cache (§2) from authoritative records.
3. Encode every authoritative record canonically, rebuild the authority tree, compare its root with the value in `meta:authority_root/v1` read from the **already-verified** state tree. Mismatch → fatal, naming store, key and both roots.
4. Cross-checks: derived-field invariants (`pop_verified == identity grants consensus` at block boundary; agent sponsor exists; validator set at H equals `build_validator_set(H)` from committed records).
5. Genesis-derived parameters stay reinstalled from genesis (already the pattern).
Outcome for the audit's findings: E2/E3 (coherent edits of side files) become **detected**, because the root chain, not the manifest, is the authority; E4 detected by step 2/4; a manifest rewritten to match edited side files is detected since the state root (from `state.json` + tree) no longer matches the committed authority root.
Residual: someone who can also rewrite `state.json` consistently, the tree and every file is outside what a root can detect; that is the R5 (manifest signing) and operating-system trust question, kept separate.

## 8. Activation and compatibility

- **Fresh-v2-genesis only** (owner-directed): a v2 profile chain starts with an empty authority tree and the v2 leaf. Mainnet is already planned as a fresh all-ML-DSA genesis.
- **Legacy chains** (existing devnets, `genesis-4node-mldsa.json`): keep the v1 leaf and no authority tree; roots must be byte-identical to today (S0/S1/S2 corpora). Selection by a genesis field; **adding a genesis field is a genesis change and needs its own owner decision (Q3)**. The genesis hash of legacy files must not change when the field is absent.
- No in-place migration. A legacy chain that must adopt R2 re-genesises.
- Mixed fleets: a node unaware of the profile must refuse to start on a v2 genesis (unknown-field behavior of `SnapshotManifest`/genesis needs checking; `SnapshotManifest` has no `deny_unknown_fields` [R]) → a deliberate version gate rather than silent ignore.
- Signing bytes and `TxBody` unchanged. Chain Forge unchanged; a Chain Forge variant is a separate proposal.

## 9. Acceptance tests (before any implementation PR)

Test-first order; all Windows-confirmed before ✅.
1. Vectors for each record kind from the independent Python encoder match Rust (PR-A method, 13+-mutation catch rate, prefix-freeness test).
2. T-AUTH-ROOT-DETERMINISM, T-AUTH-RESTORE-TAMPER, T-AUTH-DERIVED-CHECK, T-AUTH-ORDER, T-CLAIM-ROLE, T-LEGACY-PROFILE (audit §15).
3. T-DERIVED-INVARIANT: after every block of a randomized epoch-rollover/lapse/jail sequence, `pop_verified` equals the identity-derived value (decides whether `pop_verified` can be treated as a cache).
4. T-PROFILE-GATE: legacy node on v2 genesis refuses; v2 node on legacy genesis runs as legacy.
5. Proposer/validator parity: two nodes execute the same block with different internal HashMap seeds; identical authority and state roots.
6. Size/cost: authority-tree update cost for a block touching N records stays O(N log M); recorded, no guessed numbers.

## 10. Open decisions for the owner

Q1 tree layout (S recommended). Q2 drop the account tier/charm mirror on v2. Q3 genesis profile field and its hash rule. Q4 live validator set: commit full set or recompute from committed records and commit only a digest. Q5 numeric bounds and where admission enforces them (and the `claim:` role). Q6 whether `pop_verified` is a cache or authoritative. Q7 persisted `*_uqrc` names in agent records. Q8 whether R5 manifest signing ships with SC2-E or later. R5 stays optional and separate.

## 11. What this document does not claim

No performance figure, no proof of ordering equivalence between proposer and validator paths, no statement that Option S is implementable without changes to `jmt.rs`, and no Windows result. Those are the SC2-B/SC2-C deliverables.
