# STATE-COMMIT-2 — read-only security architecture audit (DRAFT, for owner review)

Base: `origin/main` @ `baf7345`. Docs only: no production code, state-root, signing, genesis or persistence change.
PRs #82 and #84 (ACCT-LEAF-1) are untouched.

**Evidence levels used below.** `READ` = established by reading source at the cited location. `NOT RUN` = no test was executed for it in this audit.
Nothing here is marked ✅; per CLAUDE.md, nothing is closed from sandbox evidence.
Line numbers refer to `baf7345` and are approximate (`~`).

## 1. What the state root authenticates today (READ)

One Jellyfish Merkle Tree holds (a) account leaves (`AccountState::to_leaf_bytes`, v1 text form) and (b) `meta:{key}` raw metadata entries.
Everything else lives in separate JSON files covered only by per-file SHA-256 in the snapshot manifest.
The manifest hash proves "these bytes are what was written", not "these bytes are consistent with the committed root".

The restore path (`node.rs ~2454–2560`) recomputes the root from `state.json` and compares it with the manifest root (error: `state_root mismatch`).
It then loads `identity.json`, `validators.json`, `agents.json`, `slashing.json`, `chain_store.json`, `historical_validator_sets.json` and `live_validator_set.json` with **no cross-check against the root**.
Genesis-derived parameters (attestation quorum and cap, min bond, slashing policy) are reinstalled from genesis, not from disk. This is a good pattern.

## 2. Field-level coverage matrix

Columns: **A** affects authorization / transitions / eligibility / power / rewards / consensus. **B** authenticated by the root. **C** derivable from authenticated inputs. **D** class (Auth = authoritative, Cache = deterministic cache/mirror, Local = node-local). **E** mutation undetected by root comparison. **F** restore catches tampering. **G** remediation (Commit = add a state commitment, Rule = deterministic reconstruction rule, None = no change).

| # | Store / field | A | B | C | D | E | F | G |
|---|---|---|---|---|---|---|---|---|
| 1 | Account `address, nonce, tier string, balances, pk, escrow, recovery policy summary, pgen` | yes | yes (v1 leaf) | – | Auth | no | yes (root) | None (but see ACCT-LEAF-1 for omitted fields) |
| 2 | Account `key_version, pending_recovery, guardian keys, role, charm beyond tier` | yes (signing and recovery) | **no** (omitted from v1) | no | Auth | **yes** | **no** | Commit — already addressed by ACCT-LEAF-1 v2 |
| 3 | Account `charm.tier` (mirror) | indirect | yes (as tier string) | **partly**: see §4 | Cache of #4 | stale-vs-authority drift is invisible | n/a | Rule: refresh at lapse, or commit #4 |
| 4 | `IdentityRecord.charm.tier`, `frozen` | **yes** (bond gating, governance vote, consensus grant: execution `~3674/3705/4141/4723/4757`) | **no** | no | **Auth** | **yes** | **no** (file hash only) | Commit |
| 5 | `IdentityRecord` attestations, Sybil log, penalties, PoP attestations | yes (tier derivation, quorum) | no | partly (from tx history, which is not retained in the state tree) | Auth | yes | no | Commit |
| 6 | `IdentityRecord.charm` decay exemption, `last_attested_epoch`, `consecutive_active_epochs`, `verified_via_wot` | yes (liveness lapse, `grants_consensus`) | no | no | Auth | yes | no | Commit |
| 7 | `IdentityStore.clock.current_epoch` | yes (drives lapse) | no | **yes**: `height / validator_epoch_blocks` (`node.rs ~4346`) | Cache | yes | no | Rule |
| 8 | Sponsorship list on `IdentityRecord` (`sponsor_agent`) | yes (agent authorization) | no | no | Auth | yes | no | Commit |
| 9 | `AgentStore` records (status, capabilities, limits, per-epoch and lifetime spend, tx count) | yes (spend limits, capability checks) | no | no | Auth | yes | no | Commit |
| 10 | `AgentStore.by_address`, `by_sponsor` indices | yes (lookup) | no | **yes**: rebuilt from `agents` | Cache | yes | no | Rule (rebuild on load, never trust the file) |
| 11 | `ValidatorRecord.bonded_uqcb, status, pop_verified, verification_tier, commission, keys, registration_seq` | **yes** (seating, power) | no | partly (`pop_verified` and tier are derived from identity; bond from bonded txs) | Auth | yes | no | Commit |
| 12 | `ValidatorRecord.blocks_proposed` and other counters | possible (rewards) | no | partly | Auth or Cache | yes | no | Needs classification (open question) |
| 13 | `ValidatorRegistry.min_bond` | yes | n/a | yes (genesis) | Cache | n/a | **yes** (re-set from genesis on load) | None |
| 14 | `live_validator_set.json` | **yes** (consensus view after restart, including keys and power) | no | partly (`build_validator_set(height)` is the documented fallback) | Auth for restart | yes | **no** | Commit or Rule (see §5) |
| 15 | `historical_validator_sets.json` | yes (verifying old commits and evidence) | no | partly | Auth | yes | no | Commit (digest per height) |
| 16 | `slashing.json` windows, history, jailed flags | yes (jail, slash, eligibility) | no | partly (from committed evidence) | Auth | yes | no | Commit |
| 17 | Slashing policy / config | yes | n/a | yes (genesis) | Cache | n/a | **yes** (re-installed from genesis) | None |
| 18 | `chain_store.json` (block, cert) history | consensus (last_commit evidence) | no (block hashes only chain forward) | no | Auth for history | yes | no | None or Rule (cert verification on load) |
| 19 | Governance `GovernanceModule{config, proposals: BTreeMap, next_id}` | yes | **unconfirmed** (see §7) | – | Auth | – | – | Audit |
| 20 | `meta:*` entries (e.g. `claim:{id}` replay keys) | yes (replay prevention) | **yes** | – | Auth | no | yes | None |
| 21 | ExplorerState and other API caches | no | no | yes (rebuilt from `chain_store` + state on restore) | Local | harmless | n/a | None |
| 22 | Consensus signing guard (`persist/consensus_signing.json`) | safety (double-sign) | no | no | Local, safety-critical | n/a | **yes** (fail-closed on unreadable; abstains if guard is ahead) | None |

Row 12 and row 19 are marked unconfirmed or open because this audit did not complete a read of them. See §7.

## 3. State-transition dependency map (READ)

```
Tx execution ──► IdentityStore (register/attest/verify/freeze/penalize/sponsor)
      │               └─ acct.attach_charm(rec.charm.clone()) + state.refresh_leaf()   [execution ~3997–4375]
      ├─► AgentStore (register/spawn/spend/revoke)          ── authorizes via IdentityStore sponsor list
      ├─► Validator bond / unbond ► ValidatorRegistry       ── gated by identity.charm.tier.grants_consensus()
      └─► Governance vote                                    ── gated by identity (no direct state-root input except meta)

Block commit (node.rs ~4337–4425)
   validator_epoch = cert.height / validator_epoch_blocks      (deterministic)
   identity.advance_epoch_to(validator_epoch)                  ── lapse(): tier → Provisional   [NO attach_charm, NO refresh_leaf]
   registry sweep: for each validator → revoke_pop() if identity no longer grants consensus
   apply_committed_evidence ► slashing ► registry (jail / slash)
   epoch close: rewards from committed evidence + registry state
   persist_state(): state.json, identity.json, validators.json, agents.json, slashing.json,
                    chain_store.json, historical_validator_sets.json, live_validator_set.json
```

Authoritative dependency chain for consensus power: `IdentityStore (not in root)` → `ValidatorRegistry.pop_verified/status (not in root)` → `live_validator_set (not in root)` → `consensus voting power`.
Two honest consequences follow:
1. **None of the inputs to voting power is in the state root.** Two nodes with the same state root can hold different validator sets.
2. Divergence in those stores is caught only if it shows up in later block hashes or votes. Nothing compares the stores directly.

## 4. Confirmed finding: account tier mirror can go stale (READ, NOT RUN)

- `IdentityStore::advance_epoch_to` (`chain-forge-identity/src/lib.rs ~1475–1495`) calls `record.charm.lapse()` on the stored record.
- The node's epoch rollover (`node.rs ~4347`) then runs only the registry sweep. There is no `attach_charm` and no `refresh_leaf` after the lapse. `grep` shows `attach_charm` in `node.rs` at one site (genesis validator sync, `~1477`).
- The other lapse site, `IntrinsicCharmRecord::DecayTick` (execution `~4364`), **does** call `attach_charm` and `refresh_leaf`.

So after a rollover lapse, `IdentityRecord.charm.tier == Provisional` while the committed account leaf can still say `Verified` or `Established`.
The existing test (`node.rs ~14623–14675`) asserts the registry demotion but, from what was read, does not assert on the account leaf.
Impact is bounded: no authorization path was found that reads `acct.charm` (READ), so this is a commitment-integrity and auditability defect, not a demonstrated authorization bypass.
A test is proposed in §8. Until it runs, the staleness is a code-reading conclusion only.

## 5. Security impact assessment

| ID | Issue | Severity (proposed) | Basis |
|---|---|---|---|
| SC2-1 | Identity tiers, freeze flags and attestations (authority for bond gating and voting) are outside the state root | High | READ: rows 4–6 |
| SC2-2 | Validator registry, live and historical validator sets are outside the root; consensus power is not state-root-bound | High | READ: rows 11, 14, 15 |
| SC2-3 | Restore verifies per-file SHA-256 and the account root only. A disk-write attacker who edits `validators.json` and `identity.json` and recomputes the manifest hashes restores a valid-looking node with altered power | Medium. It requires local write access to the data dir, and a manifest hash gives no authenticity because it is unsigned. NOT RUN: no tamper test was executed | READ: restore section; manifest has no signature in the fields read |
| SC2-4 | Account tier mirror stale after lapse (§4) | Medium, integrity only | READ |
| SC2-5 | Agent spend counters and limits outside the root | Medium | READ |
| SC2-6 | Slashing windows and jail state outside the root | Medium | READ |
| SC2-7 | `SnapshotManifest` lacks `deny_unknown_fields`, so additions in a future version may be silently ignored by an old node | Low | READ (summary of earlier audit) |

Not claimed: that any of these has been exploited, that a signature on the manifest is absent (only that none was seen in the fields read), or that the devnet is unsafe. Nothing was run.

## 6. Prioritized remediation options

Principle: commit authoritative state; reconstruct caches by rule; leave node-local data alone.

**R1 (smallest, ACCT-LEAF-1-compatible): refresh the mirror at lapse.** After `advance_epoch_to`, for each lapsed identity call `attach_charm` + `refresh_leaf`. Changes the state root at rollover for chains with lapses, so it needs a **height-gated activation**, never a silent change. Low design risk, fixes SC2-4 only.

**R2: one "authority root" commitment.** A second Merkle root (or `meta:` entries inside the existing tree) over `IdentityStore`, `ValidatorRegistry`, `AgentStore` and `slashing` in canonical encoding, with the digest included in the state root or in the block header. This is the real fix for SC2-1/2/5/6. Larger design: canonical encodings need their own vectors (same method as PR-A), plus a migration plan.

**R3: validator-set digest only.** Commit `H(live_validator_set)` and per-height `H(historical set)` as `meta:` entries. Cheapest path to close SC2-2 for consensus power, and it detects restore tampering for those files. Does not cover identity or agents.

**R4: restore-time re-derivation.** On load, rebuild caches by rule (agent indices, `pop_verified`/tier in the registry from identity, live set from `build_validator_set`) and compare with the stored values; refuse on mismatch. No state-root change. Detects incoherent edits but not coherent ones across files, so it is **not** a substitute for R2/R3.

**R5: sign or MAC the manifest** (node-local key). Defence in depth against SC2-3. Does not affect cross-node consensus.

Recommended order: R4 and R1 first (no wire change; R1 gated), then R3, then R2 designed with test vectors before any Rust.
This is a recommendation, not a decision; owner choice.

## 7. Compatibility and genesis implications

- R1, R2, R3 each change the state root at activation, so each needs an explicit **activation height / commitment profile**, the same mechanism as ACCT-LEAF-1. Existing devnet data dirs and `tests/devnet/genesis-4node-mldsa.json` keep working before activation.
- Genesis must record the profile (or default to the legacy one) so that the genesis hash is stable. Any change to genesis fields requires a separate owner decision.
- No change to signing bytes or `TxBody`.
- Chain Forge is not modified. Anything generic belongs in a separate Chain Forge proposal.
- Governance (row 19) was not audited to the end: `GovernanceModule` uses `BTreeMap` (deterministic), but whether its state is persisted into the tree or a side file was **not verified**. This remains open.
- Row 12: whether `blocks_proposed` and similar counters feed rewards was not verified.

## 8. O8 size-bound reconciliation (no encoding change)

O8 proposals (PR #82/#84): address 1..256, role ≤64, denom 1..64, ≤256 balance entries, keys ≤4096, guardians 1..64, scheme ≤64, escrow strings ≤256, leaf ≤32768.

| Bound | Existing constant / data | Discrepancy |
|---|---|---|
| Guardians 1..64 | `MAX_GUARDIANS = 10` (execution `~2731`) | O8 is **looser** than the enforced limit (not a conflict; encoder accepts a superset). Note the policy is enforced at execution, not at decode. |
| Public key ≤4096 | Ed25519 32, ML-DSA-65 `MLDSA65_PK_BYTES = 1952`, hybrid ≈1984 | Consistent (O8 bound ≥ largest key). |
| Address 1..256 | **No address-length check found.** Genesis addresses are ≤22 chars; the only visible bound is `max_tx_bytes` (65536 in the default template, hard cap by `max_block_bytes`). `Transfer.to` is accounted for gas by `to.len()+denom.len()+16` but not capped | **Discrepancy:** the Rust code accepts addresses longer than 256 bytes if the transaction fits. Whether a Transfer creates a new account with a >256-byte address was not exercised (NOT RUN). |
| Denom 1..64 | No denom length check found; `balances: BTreeMap<String,u128>` | **Discrepancy:** same as above. |
| Role ≤64 | Observed values ≤9 chars (`validator`) | Consistent with data. Enforcement at set-time not located. |
| ≤256 balance entries | Genesis files carry a single `balance`; no multi-denom accounts observed | Unverified against live chains. |
| Leaf ≤32768 | Largest plausible leaf (ML-DSA key 1952 plus guardians) is far smaller | Consistent. |
| `claim:*` | These are `meta:` entries, not accounts | **Earlier worry resolved**: they do not hit the address bound. |

Consequence to flag for the owner (not changed here): a v2 encoder that rejects over-bound fields would turn a currently-accepted transaction into a leaf-encoding failure at state-commit time. Either enforce the bound at transaction admission **before** activation, or define the failure behaviour. Both are owner decisions.

## 9. Proposed acceptance tests (none written or run in this PR)

All `*_live` tests below follow the CLAUDE.md rule: ✅ only after Windows confirmation.

1. **T-LAPSE-MIRROR**: register + verify a validator identity, force `last_attested_epoch=0`, call the rollover path, assert `identity.tier == Provisional` **and** `account.charm.tier` / leaf bytes. Expected today: the assertion on the leaf **fails** (documents SC2-4). After R1 it passes.
2. **T-RESTORE-TAMPER-VALIDATORS**: take a snapshot, edit `validators.json` (raise power), recompute the manifest SHA-256, restore. Expected today: **restores successfully** (documents SC2-3). After R3/R4: refuses.
3. **T-RESTORE-TAMPER-IDENTITY**: same for `identity.json`.
4. **T-ROOT-BINDS-VALSET**: two nodes, same state root, different `live_validator_set.json`: after R2/R3 must be detected.
5. **T-AGENT-INDEX-REBUILD**: corrupt `by_address` in `agents.json`; load must rebuild or refuse.
6. **T-ADDR-BOUND**: Transfer to a 300-byte address; record whether it is accepted today (decides the O8 bound policy).
7. **T-ACTIVATION-BOUNDARY**: for each of R1–R3, state root is identical before the activation height with the old and new binary, and differs after.
8. **T-DETERMINISM**: run the rollover with `HashMap`-order perturbation; the identity/validator digests must be byte-identical (extends S0/S2 corpora).

## 10. Open items and limits

- Not read to the end: governance persistence, `blocks_proposed` reward use, PoCD registry, `load_snapshot` signature/MAC fields, storage v2.
- Nothing here was compiled or run beyond reading source. All severities are proposals.
- Owner decisions needed: remediation order (§6), activation mechanism, O8 enforcement point (§8), whether R5 is in scope.
