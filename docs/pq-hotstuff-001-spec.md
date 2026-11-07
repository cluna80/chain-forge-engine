# PQ-HOTSTUFF-001 — PQ-HotStuff-2 Consensus: Protocol Specification

Status: **Decisions D1–D5 locked (owner, 2026-10-28). Designation and cryptographic interface adopted (owner, 2026-11-06; §3.1, §15). Revision for review: not yet approved.** Implements the locked direction of 2026-10-28 ("Qattice PQ-HotStuff Consensus Specification"). No code yet. No activation on any network.
Date: 2026-10-28 (revised 2026-11-06)
Designation: **PQ-HotStuff-2** is the official name of this protocol (the first planned HotStuff-based Qattice consensus; not a successor to a shipped "PQ-HotStuff-1"). This file name, the document ID `PQ-HOTSTUFF-001`, the config value `pq-hotstuff` and the module path stay unchanged until a separately reviewed change renames them. In this document "PQ-HotStuff" means PQ-HotStuff-2.
Scope: Qattice mainnet consensus; a selectable Chain Forge `ConsensusEngine`.

This document turns the locked direction into a buildable protocol: message formats, safety rules, commit rule, pacemaker, persistence, reconfiguration, and the acceptance gates each phase must pass. Items marked **[decision]** need an owner choice; each has a recommendation.

---

## 1. Relationship to what exists

| Component | Status | Role here |
|---|---|---|
| Tendermint engine (`tendermint/engine.rs`) | Hardened (#18, gates 1–3), Windows-confirmed | **Stable devnet baseline** until PQ-HotStuff passes every gate in §12. Its patterns (engine-driven actions, persisted sign guard, model-based simulation) are reused. |
| ML-DSA-65 consensus keys (#24) | Windows-confirmed on Tendermint, **on the pre-standard `dilithium3` backend** (K1: 0 of 45 NIST signing vectors matched) | **Not reused for signing.** PQ-HotStuff-2 signs and verifies only through the FIPS 204 signer interface (§3.1, `docs/fips204-migration/PLAN.md` in PR #119). The existing Tendermint devnet is not migrated or modified. Registration/PoP *structure* (PQ-VAL-001/2/3) is reused, with the new PoP context. |
| Legacy `HotStuffEngine` (`lib.rs`) | Devnet-only (gate 2). No engine-driven voting, no persisted lock, `verify_commit` checks no signatures | **Not a base.** PQ-HotStuff is a new module. The legacy engine stays devnet-only and is retired once PQ-HotStuff lands. |
| Equivocation slashing | Committed-evidence slashing landed (gate 4, #26, Windows-confirmed) | Reused; evidence is compared on canonical signed messages, not signature bytes (§9). |
| Succinct committee proof (M0, `docs/succinct-proof-prototype-scope.md` on `docs/validator-sampling-spec`) | Scoped, in progress in another session | Decides the mainnet validator-set ceiling (§10). |

No consensus code is borrowed. The safety rules below follow the published two-chain HotStuff variant (DiemBFT v4 / Jolteon: Gelashvili et al., "Jolteon and Ditto", FC 2022; Diem team, "DiemBFT v4", 2021). They are implemented from the papers, and the arguments are re-checked in review (§12, Phase 3).

**Tendermint scope (owner, 2026-11-07).** The PQ-HotStuff-2 workstream makes **no change** to the Tendermint implementation or to the existing Tendermint devnet, and adds no Tendermint wiring. This statement concerns this workstream only. It does not supersede, authorize or forbid test-only research on Tendermint that is independently approved under PR #119 (for example a test-only signer integration); any such research is governed by that PR and its own approvals, and it must not change this engine's design or schedule.

---

## 2. Model and assumptions

- **Validators:** an epoch-fixed set V_e. Each v has voting power p(v) ≥ 0, a registered ML-DSA-65 key, and verified personhood. Power comes from the personhood layer (bounded per human; §8). Total T = Σp.
- **Faults:** Byzantine power f < T/3. **Quorum:** q = ⌊2T/3⌋ + 1 (gate 3 floor: never lower).
- **Network:** partial synchrony. After an unknown GST, messages between honest validators arrive within Δ.
- **Signatures:** FIPS 204 ML-DSA-65 only, selected by the versioned protocol profile and carrying an explicit algorithm identifier (§3.1). A message signed by any other algorithm, or whose identifier does not match the profile, is invalid; there is no fallback, negotiation or retry with another algorithm. The engine refuses to start unless every key in V_e is 1952 bytes and was registered with the profile's algorithm identifier.
- **Safety:** no two honest validators commit different blocks at the same height, under any network schedule.
- **Liveness:** after GST, with an honest leader, a new block commits within a bounded number of rounds.

---

## 3. Data types

Integers in canonical preimages and wire encodings are unsigned and **big-endian (network byte order)**; §3.2 is normative for every byte layout (this replaces the earlier "little-endian" statement; see §15 open item 1). Hashes are the chain's `ChainHash` (SHA3-256 at hash width 256). `epoch` and `round` are u64; round numbers never reset within an epoch.

```
Block {
  epoch, round, height,            // height = parent.height + 1
  parent_id,                        // = qc.block_id
  qc: QuorumCert,                   // certifies the parent
  tc: Option<TimeoutCert>,          // present iff round != qc.round + 1
  payload: BlockPayload,            // existing v1 payload: txs, last_commit -> replaced by qc, prev_state_root
  proposer,
  signature,                        // ML-DSA-65 over block_signing_bytes
}
block_id = H("CFH1|block|" || chain_id || epoch || round || height || parent_id || H(payload) || H(qc) || H(tc?) || proposer)

Vote      { epoch, round, block_id, parent_id, parent_round, voter, signature }
QuorumCert{ epoch, round, block_id, parent_id, parent_round, signers: Bitmap, signatures: [Sig] }   // v1 format (§10)
Timeout   { epoch, round, high_qc: QuorumCert, voter, signature }    // signs (epoch, round, high_qc.round)
TimeoutCert{ epoch, round, high_qc_rounds: [u64], signers: Bitmap, signatures: [Sig], high_qc: QuorumCert }
```

Every signature is carried in an envelope `Sig { alg_id, bytes }` (§3.1), and the QC/TC `signatures` lists hold such envelopes. Signing bytes are domain-separated, bind the chain and epoch, and **bind `alg_id`**:

| Message | Canonical bytes (the message passed to the signer, with the FIPS 204 context of §3.1) |
|---|---|
| Block | `"CFH1\|block\|" ‖ alg_id ‖ block_id` |
| Vote | `"CFH1\|vote\|" ‖ alg_id ‖ chain_id ‖ epoch ‖ round ‖ block_id ‖ parent_id ‖ parent_round` |
| Timeout | `"CFH1\|timeout\|" ‖ alg_id ‖ chain_id ‖ epoch ‖ round ‖ high_qc_round` |

Tag `CFH1` cannot collide with the Tendermint tags (`CFV|`, `CFP2`), so a signature from one engine is never valid in the other. The `CFH1` tag is **retained** (owner, 2026-11-07); the FIPS 204 context additionally separates it from every pre-standard signature. There is no automatic compatibility with, or fallback to, any earlier tag or algorithm. This table is a summary: the byte layouts in §3.2 are normative.

**QC validity:** every signer is in V_epoch, each counted once. Each signature envelope has the profile's `alg_id` and verifies under §3.1 against the signer's key. Signer power sums to at least q.
**TC validity:** the same, over timeout bytes for the same `(epoch, round)`. `high_qc` is valid, and `high_qc.round == max(high_qc_rounds)`.

### 3.1 Cryptographic profile (owner decisions 3, 4, 5, 2026-11-06)

1. **Backend derived from the versioned protocol profile.** The chain's profile determines which signature algorithm is permitted for each signing domain. The profile is named by a **mandatory, versioned genesis field `cryptography.protocol_profile`**; the devnet profile identifier is `qattice-pq-hotstuff-2-v2`. There is no separate backend switch and no fallback; for this profile exactly one algorithm is permitted. Compatibility with the existing schema (read against `main` at `1eabe37`; each point needs a test in the implementation PR):
   - `GenesisCryptography` has no `deny_unknown_fields`, so a node that predates the field would silently ignore it. Fail-closed comes from `consensus.bft_variant`: `GenesisConfig::bft_variant` rejects any value other than `tendermint`, `hotstuff` or `xrpl`, so an older node refuses a `pq-hotstuff` genesis outright. The new variant is an additive change to that function.
   - The genesis hash is the compact `serde_json` serialisation of the whole struct (`compute_genesis_hash`). The field must therefore be `Option<String>` with `skip_serializing_if = "Option::is_none"` (the technique `commitment_profile` already uses), so every existing genesis file keeps its hash.
   - "Mandatory" is enforced by validation, not by the type: `bft_variant = pq-hotstuff` without the field is refused, and the field present with any other engine is refused (never silently ignored). An unknown value is refused at startup.
   - The profile is consistent with the existing fields or the node refuses to start: it requires `commitment_profile = "qattice-v2"`, `signature_scheme = "pqc-native"` with `pqc_algorithm = "ml-dsa"`, and every validator key 1952 bytes. The existing label `validator_scheme: "ml-dsa-65"` stays for schema compatibility only and is not the source of the backend choice; the profile is.
2. **Explicit algorithm identifiers, rejected on mismatch.** `alg_id` is an **unsigned 16-bit integer encoded big-endian (network byte order), always exactly 2 bytes**. Value `1` is reserved for FIPS 204 ML-DSA-65; value `0` is reserved and always invalid; any value the profile does not permit is invalid. `alg_id` appears in every validator key registration (including PoP) and in every signature envelope, and is bound into the signed bytes of every message (§3.2). A registration, vote, proposal, timeout, QC entry or TC entry whose `alg_id` is not the one the profile permits for that domain is invalid. Verification never retries with another algorithm, and nothing is negotiated.
3. **One signer implementation.** The engine consumes the FIPS 204 signer interface planned in PR #119 (`MlDsa65Fips204Scheme`, pure ML-DSA-65 over `fips204`, explicit context, hedged). It adds no cryptographic implementation of its own and never calls the pre-standard `MlDsaScheme` / `dilithium3` code.
4. **Hedged signing.** Each signature uses fresh randomness (as signing v2). Two signatures over the same vote therefore differ; §5 and §9 are written so that this never matters.
5. **Contexts (domain separation):**

| Domain | FIPS 204 context | Status |
|---|---|---|
| Vote | `qattice/vote/v2` | approved |
| Block proposal | `qattice/proposal/v2` | approved |
| Validator proof of possession | `qattice/validator-pop/v2` | approved |
| Timeout | `qattice/timeout/v2` | approved (owner, 2026-11-07) |

A signature produced for one domain must fail verification in every other domain (a required negative test). Contexts are at most 255 bytes.

### 3.2 Canonical message serialization (normative)

Every signed or hashed preimage has exactly one valid byte string. Decoders reject everything else, and decode followed by encode is the identity.

**Primitive encodings** (no separators; fields are concatenated in the order shown):

| Type | Encoding |
|---|---|
| `u16`, `u32`, `u64` | unsigned, big-endian, fixed width (2, 4, 8 bytes) |
| `bytes32` | exactly 32 bytes (the profile fixes hash width at 256; any other width is refused) |
| `string` | UTF-8, `u32` byte length, then the bytes; no NUL bytes; at most 255 bytes for `chain_id` and addresses |
| `bytes` | `u32` length, then the bytes |
| `tag` | constant ASCII, **no** length prefix; the tags below are prefix-free (none is a prefix of another) |
| `option<T>` | one byte `0x00` (absent, nothing follows) or `0x01` followed by `T`; any other first byte is invalid |
| `list<T>` | `u32` count, then the elements in canonical order (signers by validator index, ascending; duplicates invalid) |
| `bitmap` | `u32` bit count, then `⌈n/8⌉` bytes, most significant bit first; unused trailing bits must be zero |

**Layouts:**

| Item | Fields, in order |
|---|---|
| Vote message | tag `CFH1\|vote\|` · `alg_id` u16 · `chain_id` string · `epoch` u64 · `round` u64 · `block_id` bytes32 · `parent_id` bytes32 · `parent_round` u64 |
| Timeout message | tag `CFH1\|timeout\|` · `alg_id` u16 · `chain_id` string · `epoch` u64 · `round` u64 · `high_qc_round` u64 |
| Block signing message | tag `CFH1\|block\|` · `alg_id` u16 · `block_id` bytes32 |
| `block_id` hash input | tag `CFH1\|blockid\|` · `chain_id` string · `epoch` u64 · `round` u64 · `height` u64 · `parent_id` bytes32 · `H(payload)` bytes32 · `H(qc)` bytes32 · `tc` option<bytes32> · `proposer` string |
| Proof-of-possession message | tag `CFH1\|pop\|` · `alg_id` u16 · `chain_id` string · `address` string · `public_key` bytes |
| Signature envelope | `alg_id` u16 · `signature` bytes |
| Key registration | `alg_id` u16 · `public_key` bytes |

For `alg_id = 1` the public key length must be exactly 1952 and the signature length exactly 3309. Length limits are checked before any allocation, and trailing bytes after a complete item are an error.

**Rules:**
1. **Context is separate from the message.** The FIPS 204 context (§3.1) is passed to the signer as its context argument and is never concatenated into the message; a signature must verify under both the message and the context.
2. **Binding.** `alg_id` is inside every signed message above, so a signature cannot be re-labelled as another algorithm. A mismatched or unknown `alg_id` is rejected before any cryptographic operation.
3. **Equality and deduplication** of signed votes use the canonical message bytes (or their SHA3-256 hash), never the signature bytes (§9).
4. **Clarification of the earlier draft.** The `block_id` hash input previously reused the `CFH1|block|` tag that the block signing message also uses. This revision gives it its own tag, `CFH1|blockid|`, so the hash input and the signed message can never coincide. The `CFH1` family is retained.
5. **Required tests:** a golden hex vector for every layout above; round-trip for each; mutating any single field changes the bytes; two messages that differ only in how a variable field is split (for example `chain_id` `"ab"` against `"a"` followed by a shifted field) produce different bytes; trailing bytes, an `option` byte other than 0 or 1, a bitmap with a non-zero pad bit, a non-ascending signer list and `alg_id` 0 or an unpermitted value are all rejected; a message of one type is never valid as another; and mutation tests that weaken each of these checks must fail a test.

---

## 4. Leader selection

`leader(epoch, round) = sorted(V_e)[ (round + seed_e) mod |V_e| ]`, over validators with p(v) > 0. `seed_e` is the hash of the epoch-change block.

- With personhood weighting at power 1 per human (the current cap), round-robin is already power-proportional. **[decision D3]** Weighted or reputation-based rotation (leaders that time out are skipped) is a Phase 3 option. Recommendation: plain round-robin until devnet data shows a need.
- Leader selection uses only committed state, so every node computes the same leader.

---

## 5. Safety rules (per validator)

Persisted safety state (§7): `highest_vote_round` (hvr), `highest_qc_round` (hqr; this is the lock), and `last_signed` (the last vote or timeout signed in round hvr).

**Vote on block B** only if all hold:
1. B is well formed. Its signature verifies under `leader(B.epoch, B.round)`. B.qc is valid. B.parent_id = B.qc.block_id. The payload passes the existing checks (txs, state root, participation evidence).
2. `B.round > max(hvr, B.qc.round)`.
3. Either `B.round == B.qc.round + 1`, or B.tc is valid for round `B.round − 1` and `B.qc.round ≥ max(B.tc.high_qc_rounds)`.

Then set `hvr = B.round` and `hqr = max(hqr, B.qc.round)`, **persist**, and only then send the Vote to `leader(B.round + 1)`.

**Sign a timeout for round r** only if all hold:
1. `high_qc.round ≥ hqr`.
2. `r > max(hvr − 1, high_qc.round)`.
3. Either `r == high_qc.round + 1`, or the node holds a valid TC for round `r − 1`.

Then set `hvr = max(hvr, r)`, **persist**, and broadcast the Timeout to all validators.

**Never** sign two different votes in one round, or two different timeouts in one round. Voting in round r and then timing out in round r is allowed (rule 2 permits `r == hvr`). After a restart, re-send `last_signed` byte-for-byte; never re-derive it.

These are the DiemBFT v4 `safe_to_vote` and `safe_to_timeout` rules. Rule 3 of the vote is what makes a two-chain commit safe across view changes: a leader can only extend a QC at least as high as every QC that 2f+1 validators reported when they timed out.

---

## 6. Commit rule (two-chain) and round advance

**[decision D1] Two-chain or three-chain commit.** Recommendation: **two-chain** (as above).

| | Two-chain (Jolteon / DiemBFT v4) | Three-chain (original HotStuff) |
|---|---|---|
| Commit latency | 2 rounds after proposal | 3 rounds |
| View change | Quadratic: timeouts broadcast, TC carries high-QC rounds | Linear |
| Responsiveness | Not optimistically responsive after a view change | Optimistically responsive |
| Track record | Ran in production (Diem/Aptos) | The textbook protocol |

At expected Qattice sizes the quadratic view change is a rare-path cost. Commit latency is paid on every block.

**Commit:** when a node holds a valid QC for block B, and B.qc certifies B's parent P with `B.round == P.round + 1`, then P and all its uncommitted ancestors commit, in height order. Execution, state root and rewards run on commit, exactly as today.

**Round advance:** a node enters round r + 1 on its first valid QC for round r, or its first valid TC for round r. It carries the highest QC and TC it has seen.

**Proposal:** the leader of round r proposes once it holds a QC for round r − 1, or a TC for round r − 1 (attached). It extends the highest QC it knows.

**Communication:** in the common case, votes go to the next leader only and the leader broadcasts one block, so the message count is O(n). Timeouts are broadcast, O(n²), on the view-change path only.

---

## 7. Persistence and restart

- **Safety state:** `{epoch, profile, hvr, hqr, last_signed}` is written atomically to `persist/pq_hotstuff_safety.json` **before** any vote or timeout leaves the node. This is the same write-before-broadcast discipline as the Tendermint `SignGuard`. If the file is present but unreadable, the node refuses to sign (fail closed).
- **Exact signed message and envelope (crash safety).** `last_signed` is not a summary. It stores, for the last vote or timeout, the **canonical message bytes (§3.2) and the complete signature envelope (`alg_id`, length, signature bytes)**, plus the message type and round. Order of operations, with no step skipped or reordered: (1) check the §5 rules against the persisted state; (2) build the canonical message; (3) sign it (hedged, §3.1); (4) write the updated safety state **including that exact message and envelope** to a temporary file, `fsync` it, rename it over the old file, and `fsync` the directory; (5) only then send. The same rule covers proposals the node signs as leader.
  - *Crash before step 4 completes:* the signature never left the process, so nothing is on the network; the old state is intact and the node may sign again. *Crash after step 4, before or during step 5:* on restart the node re-sends the stored message and envelope **byte-for-byte**. It never re-signs that message and never signs a different message of the same type in that round.
  - *On load:* the record must pass an integrity check; the message must decode under §3.2 and re-encode to identical bytes; the envelope must carry the profile's `alg_id`, the exact length, and a signature that verifies over the stored message under the node's own key and the right context. The stored profile must equal the chain's profile. Any failure, a torn or empty file, or a failed RNG at step 3, makes the node refuse to sign (fail closed); it never repairs a record by re-signing.
  - Required tests: a fault injected at every step (before, during and after each write, `fsync` and rename) never yields two different signed messages for one (type, round), never a re-sign of a persisted message, and never a send before step 4.
- **Block store:** the uncommitted blocks on the path from the highest committed block to the highest QC, plus that QC and the highest TC. On restart these are reloaded and the node resumes from round `max(hqr, highest TC round) + 1`.
- **Engine interface:** the `ConsensusEngine` lock hooks (`lock_state` / `restore_lock_state`) currently take a Tendermint-shaped `LockState`. They become a versioned enum `EngineSafetyState::{Tendermint(LockState), PqHotStuff(PqSafetyState)}`, with a serde tag so existing data dirs keep loading.

---

## 8. Personhood weighting and reconfiguration

- **Power:** every validator-set update applies, in this order: `apply_personhood_cap` (bounded per human), then `gate_voting_power` (no personhood or no key gives power 0), then the gate-3 quorum floor. This is the same path the Tendermint engine uses and cannot be bypassed.
- **Epochs:** V_e changes only through a committed epoch-change block. The new set takes effect from the first round of epoch e + 1. A QC or TC is always verified against the set of its own epoch, using the existing `historical_validator_sets`.
- **Revocation:** "without delay" means the revocation takes effect in **the first block after the one that commits the revocation**. That block starts a mini-epoch with the revoked validator at power 0. It cannot take effect mid-round: changing the set inside a round breaks the quorum-intersection argument that §5 relies on. **[decision D4]** Recommendation: apply revocations at the next block, not at the next regular epoch boundary.
- **Key rotation:** reuses PQ-VAL-003 (rotation takes effect at the next block, with a one-block power gap). The same set-change rule applies.

### 8.1 Fresh FIPS 204 validator keys and proof of possession (Phase 2 genesis)

- **Newly generated keys only.** Every genesis validator's ML-DSA-65 key pair is generated fresh through the FIPS 204 signer interface for this genesis. No key is converted, imported or derived from a pre-standard (`dilithium3`) key, a Tendermint devnet key, or any existing key file. Genesis holds **public keys only**; private keys never appear in genesis, in the repository or in a pull request.
- **Genesis entry per validator:** address, `alg_id` 1, the 1952-byte public key, and a proof-of-possession signature envelope.
- **Proof of possession:** the signature is over the §3.2 PoP message with context `qattice/validator-pop/v2`. It binds `chain_id`, the validator address, the public key and `alg_id`, so it fails for another chain, another validator, a substituted key, another algorithm or another context. These are required negative tests (they mirror the existing ML-DSA PoP tests: wrong chain id, cross-validator replay, key substitution).
- **Verification:** at startup, before any consensus state is built, every PoP is verified. Any failure, wrong length, wrong or unpermitted `alg_id`, duplicate key, or a key shared by two validators makes the node refuse to start. Post-genesis registration and rotation use the same message and context.
- **Running nodes need their private keys from somewhere.** How a Phase 2 node stores and loads its key is **not specified here**: persistent validator key storage stays blocked on the independent review of PR #109 (and PR #119 decision 6). Phase 0 uses in-memory keys only, and Phase 2 cannot begin until the owner approves a key-handling approach.
- The key generator, `genesis-4node-pq-hotstuff.json` and their tests are Phase 2 deliverables. Nothing is generated by this revision.

---

## 9. Equivocation

Evidence types:
- **double vote:** two votes, same `(epoch, round)`, different `block_id`.
- **double proposal:** two blocks from the leader of the same round.

Each item of evidence is self-verifying: both signatures check under the offender's key for that epoch (under §3.1, with the right context and `alg_id`).

**Evidence compares canonical signed messages, not signature bytes.** Because signing is hedged (§3.1), two signatures over the *same* canonical vote message differ in bytes and are **not** evidence (a restarted node that re-signs, or a relay that re-sends, never causes slashing). A double vote is two votes by the same voter for the same `(epoch, round)` whose canonical vote messages differ (different `block_id`). Evidence is deduplicated by the hash of the canonical message pair, never by signature bytes. Required tests: re-signing the same vote produces different bytes and no evidence; two different messages produce evidence; the same evidence cannot be included twice.

(A vote followed by a timeout in the same round is **not** evidence; §5 allows it. Lock-violation evidence, such as a timeout whose high QC is below a QC the signer already voted on, is a Phase 3 candidate.)

**Handling must be committed evidence (release gate 4).** Evidence is included in a block's payload. It is validated during proposal checks and applied during execution, identically on every node. A node never slashes from its own local observation. The #24 live run showed what happens otherwise: each node slashes when it happens to see the double vote, node states diverge, and the chain halts. Gate 4 builds this for Tendermint first. PQ-HotStuff reuses it unchanged.

---

## 10. Certificate size under ML-DSA

ML-DSA signatures do not aggregate. A v1 QC carries 2f+1 signatures of 3,309 bytes each.

| Validators n | Quorum | v1 QC size | Leader egress per block (n × QC) |
|---|---|---|---|
| 4 | 3 | ~10 KB | ~40 KB |
| 31 | 21 | ~70 KB | ~2.2 MB |
| 100 | 67 | ~222 KB | ~22 MB |
| 512 | 342 | ~1.13 MB | ~580 MB |

The message count is linear, but bytes grow roughly as n². At one-second blocks, n = 100 already needs about 180 Mbit/s of leader egress.

**[decision D2] Mainnet validator-set ceiling and QC format.**
- **QC v1** (signature list): devnet and testnet, n ≤ ~31.
- **QC v2** (succinct proof of the 2f+1 signatures): this is exactly the M0 question. The M0 targets are ≤ 100 KiB at C = 512 and verify ≤ 50 ms. If M0 meets them, v2 removes the n² term.
- If M0 does not meet them, the fallback is a committee: a per-epoch sample of the personhood pool (the other session's Option C), with n bounded by the v1 budget.

Recommendation: specify the QC as a versioned type now (`QuorumCert::V1 | V2`), build v1, and fix the mainnet ceiling only after M0 reports. Phase 2 measures the real bandwidth.

---

## 11. Chain Forge integration

- **Selection:** `consensus.bft_variant: "pq-hotstuff"`. The engine is **feature-gated**: it is compiled only with an explicit Cargo feature that is not in any default feature set (name proposed: `pq-hotstuff`), and a default build refuses the value. Startup also refuses it unless the genesis profile selects the FIPS 204 backend (§3.1); the label `validator_scheme: "ml-dsa-65"` is not sufficient because on existing chains it means the pre-standard backend. No classical path. Until the §12 Phase 2 gate passes, it is devnet-only, enforced by the same check as gate 2.
- **Engine:** a new module `chain-forge-consensus/src/pq_hotstuff/`. It implements `ConsensusEngine` with `drives_own_votes() = true`, and drives the node through the existing `ConsensusAction` / `next_action` / `on_step_timeout` / `gossip_messages` hooks. It gains new actions: `SendVoteTo(leader)` and `BroadcastTimeout`.
- **Reused unchanged:** the *structure* of key registration, PoP, activation and rotation (PQ-VAL-001/2/3, with the §3.1 identifiers and contexts); payload validation; block-hash agreement; state-root binding; committed-evidence slashing. Signing and verification go through the FIPS 204 signer interface, not `sign_consensus` / `verify_consensus` on the pre-standard backend.
- **Other chains:** the engine takes the power function as input. Personhood weighting is mandatory in **Qattice's** genesis profile, where startup refuses `pq-hotstuff` without `personhood_weighted: true`. Another Chain Forge chain can supply stake or equal weights.

---

## 12. Phases and acceptance gates

Each gate follows the project rule: failing tests first, then mutation checks, then sandbox, then **Windows confirmation** before ✅.

**Phase 0 — prerequisites and core engine** (authorized by the owner 2026-11-06 as tests-first draft PRs after this revision is approved)
- **Gate 4** (committed-evidence slashing, on Tendermint) has landed (#26).
- Scope: consensus message types and canonical signing bytes (§3, §3.1); the two-chain commit rule and safety invariants (§5, §6); pacemaker and timeout handling; feature-gated engine selection (§11); deterministic simulation and adversarial safety testing; mutation tests showing that removing each essential safety check makes a test fail. Phase 0 uses in-memory test keys only (no key files).
- Types, signing bytes, the §5 safety rules, the §6 commit rule and the pacemaker. Single-process unit tests:
  - Each safety rule individually.
  - The scripted counterexamples: voting without rule 3 forks across a view change; committing on a non-consecutive QC forks.
  - Each must fail when its rule is removed (mutation-checked).
- **Model-based simulation:** port `tendermint/engine/sim.rs` (staggered start, slow links, crash/restart, Random / SplitBrain / Withhold adversaries within f, fork detection beyond f) to drive PQ-HotStuff.
  - Gate: thousands of seeded runs with agreement, no unsafe signing, and termination after GST.

**Phase 1 — personhood and persistence**
- Wire §7 persistence and §8 reconfiguration.
- Gates:
  - A restarted validator never signs a conflicting vote or timeout.
  - A revocation removes power from the next block.
  - Mid-epoch rotation works.
  - The node refuses non-ML-DSA keys.

**Phase 2 — devnet candidate**
- `genesis-4node-pq-hotstuff.json` (ML-DSA keys from #24).
- The live suite parametrized like `CF_CONSENSUS_KEYS`, with `CF_BFT=pq-hotstuff`: `devnet_4node` (liveness, partition), `consensus_safety_live` (crash/restart, block-hash agreement), `h0_5_atomicity_live`, `mldsa_tx_live`, and an equivocation live test that slashes through committed evidence.
- Bandwidth and finality measured at n = 4, 7, 16, 31.

**Phase 3 — hardening and audit preparation**
- Adversarial cases: revocation mid-round, rotation during a view change, partial participation, leader withholding.
- Independent review of §5–§6 against the papers.
- Operator runbook.

**Phase 4 — mainnet genesis**
- A fresh genesis: PQ-HotStuff, ML-DSA from block 0, the D2 ceiling and QC format, no devnet state.

The Tendermint devnet stays the default until Phase 2 passes on Windows. Phase 2 uses a **fresh genesis and a separate four-node development network** with newly generated keys; the existing Tendermint devnet is not migrated or modified. Retiring Tendermint for any network is a separate owner decision after the Phase 2 gate and independent review.

**Restrictions on all PQ-HotStuff-2 work (owner, 2026-11-06):** no default consensus change; no network activation; no mainnet change; no automatic signature downgrade or fallback; no change to the existing Tendermint implementation; no production validator key-file change; no merge without separate owner approval. Each implementation PR must carry tests, reviewable changes and documented Windows results before merge approval.

---

## 13. Decisions (locked by the owner, 2026-10-28: all five as recommended)

| # | Decision | Recommendation |
|---|---|---|
| D1 | Two-chain or three-chain commit | Two-chain (DiemBFT v4 / Jolteon rules, §5–§6) |
| D2 | Mainnet validator ceiling and QC format | Versioned QC; build v1 now; set the ceiling after M0 reports |
| D3 | Leader rotation | Round-robin; revisit with devnet data |
| D4 | When a revocation takes effect | The block after the revocation commits (never mid-round) |
| D5 | Order of work | Gate 4 (committed-evidence slashing) first, then PQ-HotStuff Phase 0 |

## 14. Corrections to the direction document

These keep the locked direction. They make two claims precise:
- **"Linear communication":** linear in messages, not bytes. Under ML-DSA the bytes grow roughly as n² until QC v2 or committees (§10).
- **"Identity revocations respected without delay":** effective from the next block, never mid-round (§8). Immediate mid-round removal would break safety.

---

## 15. Owner decisions and open items for review

**Decisions recorded in this revision:**

| | Decision |
|---|---|
| N1 (2026-11-06) | The protocol is designated **PQ-HotStuff-2**; identifiers are unchanged until a reviewed rename. |
| N2 (2026-11-06) | Cryptography decisions 3, 4, 5 of PR #119: backend derived from the versioned profile with explicit algorithm identifiers and no fallback; FIPS 204 ML-DSA-65 hedged signing with equivocation compared on canonical signed messages; the v2 contexts (vote, proposal, validator PoP). |
| N3 (2026-11-06) | The standard signer is consumed by PQ-HotStuff-2 directly; there is no Tendermint wiring in this workstream (PR #119 decision 1). |
| N4 (2026-11-06) | Fresh genesis and a separate four-node development network; the existing Tendermint devnet is not migrated or modified. |
| N5 (2026-11-07) | The timeout context `qattice/timeout/v2` is approved. |
| N6 (2026-11-07) | `alg_id` is an unsigned 16-bit integer, big-endian; value 1 is ML-DSA-65 (FIPS 204); the algorithm identifier is bound into every signed message. |
| N7 (2026-11-07) | The mandatory versioned genesis field is `cryptography.protocol_profile`; the devnet value is `qattice-pq-hotstuff-2-v2` (schema compatibility is in §3.1 and must be verified by tests). |
| N8 (2026-11-07) | The `CFH1` domain tag is retained. No automatic compatibility or signature fallback. |
| N9 (2026-11-07) | Phase 0 uses in-memory keys. Persistent validator key storage stays blocked pending the independent review of PR #109. |
| N10 (2026-11-07) | DIS remains a separate P4 workstream and is not part of this specification. |

**Open items for the reviewer:**
1. **Byte order.** The owner asked for network byte order for `alg_id`. The earlier draft said all integers are little-endian. To avoid two conventions in one preimage, this revision makes **every** integer in canonical preimages and wire encodings big-endian (§3.2). Please confirm, or say if only `alg_id` should be big-endian.
2. **New tags.** §3.2 introduces `CFH1|blockid|` (separating the `block_id` hash input from the block signing message) and `CFH1|pop|` (the proof-of-possession message). Both stay inside the retained `CFH1` family.
3. **Schema checks.** The compatibility points for `cryptography.protocol_profile` in §3.1 were derived by reading `main` and need tests (an existing genesis keeps its hash; an older node refuses `pq-hotstuff`; the field present with another engine, absent with this engine, or unknown is refused).
4. **Phase 2 key handling.** How a running node stores its private key is unspecified and blocked (N9, §8.1).
