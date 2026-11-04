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
| 12 | `ValidatorRecord.blocks_proposed / blocks_missed` | **no**: `ValidatorRegistry::record_block` has no caller outside tests (READ); liveness slashing uses `SlashingModule::record_block` (node.rs ~4247) | no | – | Dead/unused counter | n/a | n/a | None now. If wired later it becomes Auth and must be committed |
| 13 | `ValidatorRegistry.min_bond` | yes | n/a | yes (genesis) | Cache | n/a | **yes** (re-set from genesis on load) | None |
| 14 | `live_validator_set.json` | **yes** (consensus view after restart, including keys and power) | no | partly (`build_validator_set(height)` is the documented fallback) | Auth for restart | yes | **no** | Commit or Rule (see §5) |
| 15 | `historical_validator_sets.json` | yes (verifying old commits and evidence) | no | partly | Auth | yes | no | Commit (digest per height) |
| 16 | `slashing.json` windows, history, jailed flags | yes (jail, slash, eligibility) | no | partly (from committed evidence) | Auth | yes | no | Commit |
| 17 | Slashing policy / config | yes | n/a | yes (genesis) | Cache | n/a | **yes** (re-installed from genesis) | None |
| 18 | `chain_store.json` (block, cert) history | consensus (last_commit evidence) | no (block hashes only chain forward) | no | Auth for history | yes | no | None or Rule (cert verification on load) |
| 19 | Governance module (`gov:module`, JSON blob via `set_raw`) | yes | **yes**, as a `meta:` leaf (execution `~2597–2610`) | – | Auth | no | yes (root) | None for coverage; encoding caveat in §12 |
| 20 | `meta:*` entries (e.g. `claim:{id}` replay keys) | yes (replay prevention) | **yes** | – | Auth | no | yes | None |
| 20b | `crypto_migration:active`, `pq_consensus_activation_epoch`, address-binding keys (`set_raw`) | yes | yes (`meta:`) | – | Auth | no | yes | None |
| 20c | `claim:{id}` research-reward replay guard | yes | **yes, as an ACCOUNT** (not `meta:`; see §8 correction) | – | Auth | no | yes | Needs O8 decision |
| 20d | PoCD `DiscoveryRegistry` (challenges, receipts, seen proof ids; HashMaps) | **no today**: its only consumer, epoch reward distribution, is disabled (`if let (true, …)` is `(false, …)`, execution `~5361`) | no | – | Node-local, gossip-fed, not persisted | n/a | n/a | None now; commit or remove before any consumer is re-enabled |
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
- Governance state is already inside the root (row 19); its only weakness is the encoding (§12).

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
| `claim:{id}` | **CORRECTION of the earlier draft.** `claim:{id}` is created as an *account*: `AccountState::new(claim_key, claim_record_json)` (execution `~4950`), so a JSON audit record is stored in the `role` field | Address = `claim:` + 64 hex ≈ 70 bytes (inside 256). **Role = a JSON object well over 64 bytes** (six ID/hash fields, amounts, tx id). O8's `role ≤ 64` would reject every settled claim at v2 encoding. The v1 leaf omits `role`, so today this is invisible. |

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

- §1–§10 are source-reading conclusions (with the corrections above). §11 records what was **run**.
- All severities are proposals.
- Owner decisions needed: remediation order (§6), activation mechanism, O8 enforcement point (§8), whether R5 is in scope.

---

# Review-round update (owner direction on 79d6a1d)

## 11. Experimental results vs source-reading conclusions

Method: tests inserted into a throwaway worktree of `origin/main@baf7345` (no production edit, no golden baseline touched), run in the Linux sandbox with `-j 2`.
Source: `docs/state-commit-2/scratch-tests/*.rs.txt`. Captured output: `docs/state-commit-2/results/`.
**Windows reproduction (owner, BossKing MINGW64, 3 node runs + 1 executor run) matched the sandbox output line for line; see `docs/state-commit-2/results/windows-bossking.txt`.** These tests *characterize defects*; reproducing them confirms the defects exist, not that anything is fixed. No fix is ✅ (command in `docs/state-commit-2/README.md`).

| ID | Claim | Source reading said | Experiment | Status |
|---|---|---|---|---|
| E1 | Account tier mirror stale after epoch lapse | stale (§4) | Genesis validator Alice: identity tier `Provisional` after `advance_epoch_to` + `propose_block` (registry sweep ran); account charm tier still `Verified`; leaf bytes and state root **unchanged**. 3 identical runs | **Confirmed in sandbox and on Windows** |
| E2 | `validators.json` edited (4 `bonded_uqcb` fields +123,456,789) with manifest SHA-256/size recomputed is accepted | accepted (SC2-3) | `is_restored() == true`; Alice bond 1,000,000 → 124,456,789; state root identical. 3 identical runs | **Confirmed in sandbox and on Windows** |
| E3 | `identity.json` edited (4 `tier` fields → `Established`) with manifest recomputed is accepted | accepted | `is_restored() == true`; Alice tier `Verified` → `Established`; root identical. 3 runs | **Confirmed in sandbox and on Windows** |
| E4 | Agent `by_address` index is trusted from disk | index trusted (row 10) | `by_address` **is serialized**. A corrupted entry restores without error; `get_by_address("qcb1agent1")` → `Err("agent nonexistent not found")` while `get("a1")` succeeds. 3 runs | **Confirmed in sandbox and on Windows** (index not rebuilt) |
| E5 | No address/denom length limit | none found by grep | `execute_tx`: 300-byte address transfer **succeeded** (new account leaf 317 bytes); 100-byte denom **succeeded**; 70,000-byte address **succeeded**. 1 run | **Confirmed at executor level, sandbox and Windows.** The HTTP layer caps the body by `max_tx_bytes` (`api.rs ~183`, 65,536 in shipped templates). Other ingress (gossip, direct block proposal) was not tested |

Not demonstrated: any cross-node exploit; that E2/E3 survive the signing guard or p2p sync; anything on Windows.
E2/E3 need write access to the data directory. They show the manifest hash is an integrity check, not an authenticity check.

## 12. Supplementary audit results (source reading unless marked)

- **Governance**: inside the root as `meta:gov:module` (JSON text of `GovernanceModule`, `BTreeMap` collections). Caveat: the commitment is over `serde_json` text, so a serde or field-order change silently changes the root. A canonical encoding removes that coupling.
- **Reward counters**: `blocks_proposed/blocks_missed` are never incremented outside tests. Rewards use committed evidence (`node.rs ~4375–4425`) and slashing windows. Not authoritative today.
- **PoCD**: three `HashMap/HashSet`s fed by gossip (`node.rs ~3497`), not in `SNAPSHOT_FILES`, lost at restart; the reward consumer is compiled out by a constant `false`. Node-local and non-consensus *today*. `ClaimResearchReward` uses the `claim:` account, not the registry.
- **Settlement state**: replay guard `claim:{id}` is an account (correction in §8). Treasury and recipient balances are ordinary accounts (in the root).
- **Manifest authentication**: fields are `format_version, chain_id, genesis_hash, state_root, height, generation, files[sha256,size]`. No signature or MAC field. `genesis_hash` binds a directory to a chain, not to a writer. The v2 block-log hash chain is anchored with `anchor_for(genesis_hash, kind)` (public inputs): it detects corruption, not a deliberate rewrite by someone who can compute it.
- **storage v2** (default off): replays both logs, verifies the hash chain and descriptor tails, strict-decodes every record, fails closed on ambiguity (`storage_v2.rs ~142–175`). It feeds the **same** restore path, so identity/validators/agents/slashing get exactly the v1 checks. Block and validator-set *history* logs are chained; the live validator set is not.
- **Non-canonical serialization (matters for R2)**: `IdentityStore`, `ValidatorRegistry`, `SlashingModule` hold `HashMap/HashSet` (`records`, `validators`, `liveness_windows`, `equivocation_set`, `sybil_confirmations`, …). Their `serde_json` output is not order-stable, so **hashing the current JSON files is not a valid commitment**.
- **QRC flag (no action here)**: `AgentRecord` persists `epoch_spend_uqrc` / `lifetime_spend_uqrc`. R2 encodings should use unit-neutral tags. Renaming persisted fields is a separate owner decision.

## 13. Proposed implementation sequence (nothing authorized)

Gate: Phase 0.5 alongside ACCT-LEAF-1. Each step is its own reviewed PR; Windows confirmation before closing.

1. **SC2-A (tests only)**: promote E1–E5 into permanent characterization tests. No behavior change.
2. **SC2-B (design freeze)**: owner review of `docs/STATE-COMMIT-2-R2-authority-state-architecture.md`, decisions Q1–Q8, O8 reconciliation (§14).
3. **SC2-C (vectors)**: byte-level vectors and an independent Python encoder for authority records (PR-A method). No Rust.
4. **SC2-D (R4, no root change)**: restore-time re-derivation of caches (indices, `pop_verified`); refuse on mismatch. Closes E4; partly mitigates E2/E3 (incoherent edits only).
5. **SC2-E (fresh-v2-genesis)**: admission and genesis validators first, then authority tree plus `meta` root leaf and the ACCT-LEAF-1 v2 leaf under one genesis commitment profile.
6. **SC2-F (optional, separate)**: R5 manifest signing.
R1 is superseded by SC2-E on v2 chains and is only needed if a legacy-profile chain must keep running.

## 14. O8 reconciliation (revised; encoding unchanged)

Owner rule: no encoding limit without a matching validation rule. Validation rules found for address, denom, role, balance count and key size: **none** beyond signature-scheme checks and the HTTP body limit (grep-based; not exhaustive).

| O8 bound | Real data / rule | Needed before adoption |
|---|---|---|
| address 1..256 | genesis ≤ 22; `claim:` ≈ 70; executor accepts 300 and 70,000 (E5) | admission rule in `Transfer` and every account-creating op, genesis validation, pre-activation scan |
| denom 1..64 | executor accepts 100 (E5); seen: `uqcb`, `settled` | same |
| role ≤ 64 | genesis ≤ 9; **claim accounts store a JSON blob in `role` (> 64)** | a real bound ≥ the blob, or move the claim record out of `role` (changes state; separate decision) |
| ≤ 256 balances | single-denom accounts in all genesis files | admission rule on first credit of a new denom |
| keys ≤ 4096 | 32 / 1952 / ≈1984 | none beyond scheme checks |
| guardians 1..64 | `MAX_GUARDIANS = 10` enforced | consistent (looser) |
| leaf ≤ 32768 | breached by unbounded role/address | follows from the above |

Under fresh-v2-genesis, ship admission and genesis validators **before** the encoder so a bound can never be hit by an admitted transaction.

## 15. Acceptance tests (additions to §9)

All `*_live` style; ✅ only after Windows confirmation.
- **T-AUTH-ROOT-DETERMINISM**: shuffle `HashMap` insertion order across identity/validator/agent/slashing stores; authority root byte-identical.
- **T-AUTH-RESTORE-TAMPER**: E2/E3 become refusals under the v2 profile.
- **T-AUTH-DERIVED-CHECK**: edit a derived field (agent index, `pop_verified`) → restore refuses.
- **T-AUTH-ORDER**: rollover + sweep + evidence in one block; root computed after all authority mutations; two nodes agree.
- **T-CLAIM-ROLE**: a settled claim encodes under the final role rule.
- **T-LEGACY-PROFILE**: legacy genesis yields today's roots (S0/S1/S2 corpora unchanged).
