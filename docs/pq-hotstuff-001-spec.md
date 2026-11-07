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

**Consensus separation: Qattice versus Chain Forge (owner, 2026-11-07).** Chain Forge is the blockchain creation engine and keeps a modular consensus library; Qattice is one blockchain built with it.
- **Qattice** will ultimately replace Tendermint with PQ-HotStuff-2 as its **exclusive production consensus engine**. This is a Qattice-specific configuration and deployment decision.
- **Chain Forge** keeps Tendermint as an independently selectable engine for developers building other blockchains. Removing Tendermint from Qattice's configuration is not a removal from the Chain Forge codebase, and nothing in this workstream removes, disables or modifies Tendermint.
- **Current state:** Tendermint remains Qattice's devnet baseline until PQ-HotStuff-2 passes the gates below. No existing Qattice network is migrated automatically.
- **Conditions for the transition:** PQ-HotStuff-2 must first pass the safety, persistence, four-node devnet, adversarial testing and independent security-review gates of §12. Removing Tendermint from Qattice's configuration then requires a **separate owner approval** after successful testing.
- **Shared APIs stay modular:** the `ConsensusEngine` interface, the engine safety-state type and the genesis schema must stay engine-agnostic and must not be hard-coded to Qattice's choice (§11).

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

Integers in canonical preimages and wire encodings are unsigned and **big-endian (network byte order)**; §3.2 is normative for every byte layout (this replaces the earlier "little-endian" statement; confirmed by the owner, 2026-11-07). Hashes are the chain's `ChainHash` (SHA3-256 at hash width 256). `epoch` and `round` are u64; round numbers never reset within an epoch.

```
Block {
  epoch, round, height,            // height = parent.height + 1
  parent_id,                        // = qc.block_id
  qc: QuorumCert,                   // certifies the parent
  tc: Option<TimeoutCert>,          // present iff round != qc.round + 1
  payload: BlockPayload,            // existing v1 payload: txs, last_commit -> replaced by qc, prev_state_root
  proposer,
  signature,                        // Sig envelope over the block signing message (§3.2); covers block_id
}
block_id = SHA3-256(canonical block_id input of §3.2)   // commits to every consensus-critical field of the proposal (§3.2 rule 6)

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
| `block_id` hash input | tag `CFH1\|blockid\|` · `alg_id` u16 · `protocol_profile` string · `chain_id` string · `epoch` u64 · `round` u64 · `height` u64 · `parent_id` bytes32 · `H(payload)` bytes32 · `H(qc)` bytes32 · `tc` option<bytes32> · `proposer` string |
| Proof-of-possession message | tag `CFH1\|pop\|` · `alg_id` u16 · `chain_id` string · `address` string · `public_key` bytes |
| Signature envelope | `alg_id` u16 · `signature` bytes |
| Key registration | `alg_id` u16 · `public_key` bytes |

For `alg_id = 1` the public key length must be exactly 1952 and the signature length exactly 3309. Length limits are checked before any allocation, and trailing bytes after a complete item are an error.

**Rules:**
1. **Context is separate from the message.** The FIPS 204 context (§3.1) is passed to the signer as its context argument and is never concatenated into the message; a signature must verify under both the message and the context.
2. **Binding.** `alg_id` is inside every signed message above, so a signature cannot be re-labelled as another algorithm. A mismatched or unknown `alg_id` is rejected before any cryptographic operation.
3. **Equality and deduplication** of signed votes use the canonical message bytes (or their SHA3-256 hash), never the signature bytes (§9).
4. **Tags approved** (owner, 2026-11-07): `CFH1|blockid|` and `CFH1|pop|` join the retained `CFH1` family. **Clarification of the earlier draft.** The `block_id` hash input previously reused the `CFH1|block|` tag that the block signing message also uses. This revision gives it its own tag, `CFH1|blockid|`, so the hash input and the signed message can never coincide. The `CFH1` family is retained.
5. **Required tests (serialization):** a golden hex vector for every layout above; round-trip for each; mutating any single field changes the bytes; two messages that differ only in how a variable field is split (for example `chain_id` `"ab"` against `"a"` followed by a shifted field) produce different bytes; trailing bytes, an `option` byte other than 0 or 1, a bitmap with a non-zero pad bit, a non-ascending signer list and `alg_id` 0 or an unpermitted value are all rejected; a message of one type is never valid as another; and mutation tests that weaken each of these checks must fail a test.
6. **The block identifier commits to every consensus-critical proposal field.** A field is consensus-critical if changing it could change what any honest node accepts, votes for, executes or commits. `block_id` is the SHA3-256 of the canonical input above, so each such field is either a direct input or is committed through a hash that is a direct input:
   - **direct:** `protocol_profile`, `alg_id`, `chain_id`, `epoch`, `round`, `height`, `parent_id`, `proposer`, and the presence and content of `tc`;
   - **through `H(payload)`:** the complete canonical encoding of `BlockPayload`: the transactions (set and order), the state root the block commits to, participation evidence, committed equivocation evidence, the block timestamp, and every other payload field, including any added later. The exact payload byte layout must be added to this section before Phase 0 code is written; a payload field that is not part of that encoding is a specification defect;
   - **through `H(qc)`:** the complete canonical encoding of the QC, including its signer bitmap and every signature envelope, so signatures cannot be swapped after the block is formed.

   Only data that is not consensus-critical is outside the commitment: the proposer's own block signature (it signs `block_id`), local receive time and gossip metadata. A verifier **recomputes** `block_id` from the received fields and never trusts an identifier carried on the wire. Votes, timeouts and QCs bind to `block_id`, so a substituted field in a proposal invalidates every vote that was cast for the original.
7. **Required tests (field substitution), all negative:** for each field in the list above, taking an otherwise valid proposal and changing only that field (while keeping the original `block_id` and the original proposer signature, and separately recomputing `block_id` and keeping the old signature) is rejected, and a vote or QC for the original block never validates for the altered one. This includes: swapping or reordering transactions, altering the state root, dropping or altering evidence, changing the timestamp, replacing the QC's signatures or bitmap, adding, removing or altering `tc`, changing `proposer`, `height`, `round`, `epoch`, `chain_id` or `protocol_profile`, and replaying the block under a different profile. Mutation tests that remove each field from the `block_id` input must fail at least one of these tests.

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
- **Exact signed message and envelope (crash safety).** `last_signed` is not a summary. It stores, for the last vote or timeout, the **canonical message bytes (§3.2) and the complete signature envelope (`alg_id`, length, signature bytes)**, plus the message type and round. Order of operations, with no step skipped or reordered: (1) check the §5 rules against the persisted state; (2) build the canonical message; (3) sign it (hedged, §3.1); (4) write the updated safety state **including that exact message and envelope** to a temporary file, `fsync` it, rename it over the old file, and `fsync` the directory; (4b) advance the trusted monotonic counter (§7.1); (5) only then send. The same rule covers proposals the node signs as leader.
  - *Crash before step 4 completes:* the signature never left the process, so nothing is on the network; the old state is intact and the node may sign again. *Crash after step 4, before or during step 5:* on restart the node re-sends the stored message and envelope **byte-for-byte**. It never re-signs that message and never signs a different message of the same type in that round.
  - *On load:* the record must pass an integrity check; the message must decode under §3.2 and re-encode to identical bytes; the envelope must carry the profile's `alg_id`, the exact length, and a signature that verifies over the stored message under the node's own key and the right context. The stored profile must equal the chain's profile. Any failure, a torn or empty file, or a failed RNG at step 3, makes the node refuse to sign (fail closed); it never repairs a record by re-signing.
  - Required tests: a fault injected at every step (before, during and after each write, `fsync` and rename) never yields two different signed messages for one (type, round), never a re-sign of a persisted message, and never a send before step 4.
- **A missing safety-state file never resets signing history, and a fresh validator is explicitly distinguishable.**
  - *Explicit initialization.* Safety state is created only by an explicit operator initialization step for a key that has never signed (a new key, or genesis). A node never creates safety state implicitly on start. Initialization writes, atomically, a record with `state = "fresh"`, the profile, the validator public key, a random `instance_id`, and `last_signed = null` (an explicit "nothing signed yet", never a default of round 0). The same atomic write that stores the first signed message (above) moves the record from `fresh` to `active`.
  - *Existing validator, missing or damaged state.* If the node is configured as a validator and the safety-state file is missing, empty, torn, unreadable, or from a different profile or `instance_id`, or if the node has any evidence that this key has signed before (an initialization marker, the key in the committee at a non-genesis committed height, or committed participation evidence naming it) while the file is absent, then the node **refuses to sign and refuses to create new state**. It may keep running as a non-signing observer. It never treats absence as `fresh`.
  - *Stale file.* If the chain shows the validator's key signing in a round higher than the file's `hvr` (for example a restored old backup), the file is stale: the node abstains until its state is brought past that round by a reviewed procedure, and never signs below it.
  - *Fresh initialization is refused for a key that has already participated.* Initialization checks the committed chain the node holds or has synced; if the key appears in any committed QC, TC, vote evidence or participation record at a height above the key's activation, initialization is refused.
  - *Recovery.* Loss of safety state is not recoverable by re-initializing the same key. The safe options are to keep abstaining or to rotate to a new key (PQ-VAL-003), which then starts with an explicit fresh initialization. A reviewed recovery procedure may be specified in Phase 1; until then fail closed.
  - *Required tests (negative unless stated):* start with the file deleted after prior signing, with the file truncated to 0 bytes, torn at every offset, with `instance_id` or profile mismatched, and with an old backup restored: in each case no signature is produced and no new file is created. A fresh validator with explicit initialization signs normally (positive) and its `fresh` state is distinguishable from every damaged state. A key that already appears in committed participation cannot be initialized fresh. Mutation tests that treat absence as `fresh`, or skip the `fresh` to `active` transition, must fail a test. Phase 0 exercises all of this against an in-memory storage abstraction with injected failures; no key or state file is written to disk.
- **Block store:** the uncommitted blocks on the path from the highest committed block to the highest QC, plus that QC and the highest TC. On restart these are reloaded and the node resumes from round `max(hqr, highest TC round) + 1`.
- **Engine interface:** the `ConsensusEngine` lock hooks (`lock_state` / `restore_lock_state`) currently take a Tendermint-shaped `LockState`. They become a versioned enum `EngineSafetyState::{Tendermint(LockState), PqHotStuff(PqSafetyState)}`, with a serde tag so existing data dirs keep loading.

### 7.1 Trusted monotonic counter and rollback detection (PROPOSED amendment, owner review pending)

**Status.** Proposed on 2026-11-07 and implemented in draft PR #127 (`chain-forge-consensus`, `pq_hotstuff::safety`). Not a decision until the owner approves this section.

**Two different problems.** Crash recovery (an interrupted write) is solved by the atomic replace in §7. *Rollback* is different: an older but perfectly valid safety-state file restored from a backup, a snapshot revert or a cloned virtual machine. The file cannot detect this about itself, because the old file is internally consistent. A validator that signs from a rolled-back file can sign a message that conflicts with one it already broadcast, which is slashable equivocation. Only a record kept *outside the reach of whoever can restore the file* can detect it. That is the trusted counter. The checksum on the file detects corruption; it does not authenticate.

**Interface.** `read() -> u64`, `acquire_session() -> Session` and `advance(expected_previous, session) -> Result`. The session is the exclusive-writer credential of the signing-session requirement below. The record carries a `counter` field; every committed write increases it by exactly one, and the counter is advanced to match **after** the file is durable and **before** the signature is returned (step 4b).

**Properties a counter must have** (each is a requirement on the backend, not something the safety code can check):
1. **Durable:** survives power loss, process crash and reboot of the validator host.
2. **Atomic and compare-and-advance:** `advance(expected_previous)` succeeds only if the counter currently equals `expected_previous`, then becomes `expected_previous + 1`; otherwise it fails and changes nothing. It never succeeds for two callers with the same `expected_previous`. (This also stops two live copies of one validator from both progressing.)
3. **Monotonic and unresettable from the validator host:** there is no decrement and no reset reachable by the validator process, by the host's operating-system users, or by anyone who can restore the safety-state file or its backups. A reset, if it exists at all, needs a separate owner-controlled authority and is treated as key loss (below).
4. **Bound to one validator instance** (public key and `instance_id`): created at initialization with value 0 and never reused for another key or instance.
5. **Authenticated:** only that validator's signing path can advance it.
6. **Honest failures:** an unavailable or failing counter returns an error; it never reports success it did not achieve.
7. **Exclusive writer:** at most one signing session per validator identity is valid at any time, and this is enforced by the backend on **every** `advance`, not only checked when the node starts (see "Duplicated validators" below).

Acceptable families, not chosen by this document: a hardware or TPM non-volatile monotonic counter, an HSM, a remote witness with replicated durable storage. **Not acceptable:** a file or database on the validator host, anything the host's users can overwrite or restore, and the in-repository `TestCounter` (an in-memory test double with no durability and no protection).

**Rules at open** (file counter `f`, trusted counter `t`):

| Condition | Meaning | Action |
|---|---|---|
| `f == t` | normal | open |
| `f == t + 1` | the file is durable but the counter advance did not happen; nothing from this record was ever returned or sent | complete the advance with `advance(t, session)` (only after every other check passes); the node is not open, and returns and broadcasts nothing, until that call succeeds |
| `f < t` | rollback, or storage that lost data it had acknowledged | refuse (fail closed) |
| `f > t + 1` | counter reset or replaced, or a forged file | refuse (fail closed) |
| counter unreadable | | refuse to sign; the node may run as a non-signing observer |

**Recovery advance (`f == t + 1`).** Completing the outstanding advance is itself a compare-and-advance and follows the same rules as a normal commit:
1. **No signature is returned or broadcast, and no signing session is considered open, until the recovery advance has succeeded.** A failure of the call leaves the node not open and non-signing.
2. **It is `advance(t, session)`, never an unconditional set.** If another process advanced the same counter in the meantime, the call fails because the counter is no longer `t`. The node must treat that as a **fail-closed** event (it is evidence of a second writer or of a stale file), must not assume the advance succeeded, must not retry with a new expected value on its own, and must not sign. Re-reading the counter and restarting the open sequence from the beginning is allowed; it will then find `f < t` and refuse.
3. **A crash during the recovery advance is safe because the state is re-derived, not remembered:** after the crash the counter is either still `t` (the same rule applies again) or already `f` (the normal `f == t` case). No recovery step is repeated blindly.

**What happens when the counter advances and the file write fails.** By construction this cannot happen in the normal order: the counter advances only after the file and its directory entry are durable (steps 4 to 6). Every other interleaving is covered:

| Event | Durable state afterwards | Outcome |
|---|---|---|
| failure or crash before the rename is durable (steps 4 to 6) | old file, old counter | nothing was returned; continue normally; a different message for that round may still be signed |
| file durable, counter advance fails or the process dies (step 4b) | `f == t + 1` | nothing was returned; open completes the advance; the message is now durable, so a conflicting one for that round is refused (conservative) |
| counter advance succeeds, the acknowledgement is lost | `f == t` | normal; nothing to repeat |
| **storage acknowledged `fsync` but lost the data** (lying disk, write cache, power loss) | `f < t` | open reports rollback and **fails closed**; a loss of liveness, not of safety; recover by key rotation |
| counter reset, replaced or unreachable | `f > t + 1`, or unreadable | fail closed; the same key is never re-initialized (initialization requires counter 0, no marker or state, and no chain participation); rotate the key (PQ-VAL-003) |
| a snapshot revert or a cloned machine | file older than the counter | refused on open; a stale copy cannot commit (its expected value is behind); see "Duplicated validators" for what this does not cover |

**Duplicated validators: what is and is not guaranteed.** Compare-and-advance, with `expected_previous` taken from the record's own previous counter, gives these guarantees: two processes cannot both commit the same counter value, and a copy of the safety state that is behind the counter can never commit again (its advance fails and the store latches; on restart `f < t` refuses it). Two processes can therefore only take turns if they share one consistent safety state, in which case they behave as one validator. **It does not guarantee:**
1. **A signature is never computed by a stale or duplicate process.** In the commit sequence the signature is computed (step 3) before the counter is advanced (step 4b). A process that is paused and resumed, or a clone, can compute a valid signature over a conflicting message and then fail to commit it. The safety code discards that signature (it is never returned), but the signing key was used.
2. **Anyone holding the key material can sign outside the store.** The store protects against software and operator mistakes (rollback, restore, clone, restart). It does not stop an operator or an attacker who has copied the signing key from signing arbitrary messages directly. Deterrence there is slashing, and prevention is hardware.

**Production requirement: an exclusive signing session, enforced on every signing operation.** A production deployment must provide at least one of:
1. **A hardware-enforced exclusive signing session:** the signing key is non-exportable and lives in the same trusted boundary as the counter (HSM, TPM or secure enclave), which signs only when its own monotonic state matches, so a clone cannot obtain a signature at all; or
2. **A fenced single-writer lease tied to the validator identity:** acquiring the lease returns a **fencing token** that increases monotonically across holders; every `advance` presents the token; the backend rejects any token lower than the highest it has seen and any token whose lease has been superseded. The lease must be enforced by the backend **on every signing operation, not merely checked at startup**, must not depend on the validator host's clock for correctness, and a process that loses or cannot confirm its lease latches and stops signing. The lease is bound to the validator's public key and `instance_id`.

**Limit of option 2, stated plainly.** A fenced counter operation is not a fenced *cryptographic signing* operation. A lease controls who may **commit** signing state; it does not control who may **sign**. If the signing key is exportable, a lease does not and cannot prevent a holder of the key from producing signatures outside the store, and the remote counter must not be described as preventing unauthorized signatures. A deployment that relies on a lease alone gets rollback detection, containment of honest-software duplicates, and (through slashing) deterrence, not prevention. **Prevention of unauthorized signatures requires option 1: the signing operation itself controlled by a trusted signing boundary** that holds a non-exportable key and signs only when the exclusive-session and counter conditions hold.

This matters most for a network of personhood-weighted validator identities, where one human's duplicated validator is both a safety risk and an identity-integrity risk. Neither mechanism is implemented or reviewed yet; until one is, no backend is production-ready.

**How counter state survives restarts.** It lives in the counter backend, not in the safety directory, so restoring or deleting the safety directory does not touch it. On open, the counter is read first and compared with the file as above; initialization creates the counter at 0 and refuses a counter that is not 0.

**Backend direction (initial target, non-binding).** The interface stays technology-neutral. The first private implementation should target a **remotely enforced, authenticated counter with fencing and replicated durable state**, because it provides atomic compare-and-advance, exclusive-writer fencing and durability together. A TPM or HSM implementation remains an alternative and must meet the same requirements: strict atomicity, rollback resistance, identity binding and exclusive-writer enforcement. **No backend may be called production-ready until it has been independently reviewed.** The remotely operated counter is the choice for a **private prototype only**: it is not an approved production signer, because with an exportable key it cannot prevent signing outside the store (see the limit of option 2).

**Lease policy.** Leases are **renewable and enforced by the server**, carry **monotonically increasing fencing tokens**, and are checked on every advance. **No lease duration or renewal interval is fixed by this document;** both are to be determined by failure and latency testing of the chosen backend, and correctness must not depend on them. The validator **stops signing whenever it cannot establish that its session is valid**: a lease that has lapsed, a renewal that has failed, or a counter that cannot be reached all mean no signing.

**Recovery policy.** Fail closed. The only recovery authorized from a confirmed rollback, an inconsistent counter, a lost counter or a duplicated validator is **key rotation** (PQ-VAL-003) to a new key with a new counter and an explicit fresh initialization. The counter interface has no reset, decrement or set operation; if a backend offers one, it must be disabled for validator instances. An operator cannot reset a counter and continue signing with the same key.

### 7.1.1 Digest-bound counter commits (PROPOSED amendment, owner review pending; not approved for implementation)

**The gap this closes.** The commit sequence writes the state file (steps 4 to 6) before the counter advances (step 4b), and a counter that stores only a number cannot tell two different records with the same counter value apart. Found while writing the two-store tests for PR #127 and asserted there by `known_limitation_a_fenced_out_writer_leaves_an_uncommitted_record_the_counter_cannot_tell_from_the_committed_one`:
1. Writers A and B are both open on the same committed record (counter `t`); B acquires a later session, so A is fenced out.
2. B commits and broadcasts vote `m_B` for round `r` (counter `t + 1`).
3. A, on its own disk, signs a *different* vote `m_A` for the same round. It writes its file (counter `t + 1`) and then fails at the counter advance. Nothing is returned, but the record stays on A's disk.
4. A is restarted on its own disk. Its file counter equals the trusted counter, so it opens as if committed, holds `m_A`, and would re-send a vote that conflicts with the one B broadcast: slashable equivocation.

The same happens on a shared directory if the fenced-out writer overwrites the file after the new holder committed.

**The amendment.** The counter commits to *which record* each value belongs to, not only to the value.
1. **Counter state** is `(value, digest)`. The initial state is `(0, 0x00 x 32)`. `read()` returns both.
2. **Record digest.** The digest of a record is the SHA3-256 checksum already carried by its encoding (the 32 bytes that seal the record's canonical body). The body therefore must contain everything the digest should bind: the record gains a field `prev_digest`, the digest of the record it replaces (`0x00 x 32` for the first record), so records form a chain.
3. **Commit.** Step 4b becomes `advance(expected = (n - 1, d_(n-1)), new_digest = d_n, session)`: it succeeds only if the counter's current state equals `expected` exactly (value **and** digest) and the session is the latest, and then becomes `(n, d_n)`. Otherwise it fails and changes nothing.
4. **Open rules** (file counter `f`, file digest `d_f`, file `prev_digest` `p_f`; counter `(t, d_t)`):

| Condition | Meaning | Action |
|---|---|---|
| `f == t` and `d_f == d_t` | normal | open |
| `f == t` and `d_f != d_t` | **a fork: a record with the committed counter value that is not the committed record** (a fenced-out writer's leftover, or a file overwritten after the commit) | refuse (fail closed) |
| `f == t + 1` and `p_f == d_t` | the file is a durable successor of the committed record; its advance did not happen; nothing from it was ever returned or sent | complete with `advance((t, d_t), d_f, session)`, as in 7.1 (gated, fail closed if the counter moved) |
| `f == t + 1` and `p_f != d_t` | a successor of some other record | refuse |
| `f < t` | rollback | refuse |
| `f > t + 1` | counter reset or forged file | refuse |

**Crash and fork behavior.**
1. *Crash between file and counter (the 7.1 window).* Unchanged: the file is a successor of the committed record, the recovery advance commits it, and nothing was returned before.
2. *Two writers' files both one ahead (A fenced out, B crashed before its advance).* Both are valid successors of `(t, d_t)`, and **neither signature was ever returned**, so either may be committed. Whichever restarts first completes the advance; the other, on its next open, finds `f == t` with a different digest and is refused. No conflicting message is ever broadcast, because only a committed record's signature is returned.
3. *Fenced-out leftover after the new holder committed (the scenario above).* A's restart finds `d_f != d_t` and refuses. Recovery is key rotation, as for every fail-closed case.
4. *Overwrite after commit on a shared directory.* B's restart finds `d_f != d_t` and refuses; B's own committed record is lost to the file, so B also rotates its key (fail closed, not unsafe).

**Restart validation.** `open` performs, in this order: identity and binding checks; the table above; content verification and chain-evidence staleness; only then session acquisition and any recovery advance. A failed open still never supersedes the running store.

**Cost and compatibility.** The counter backend stores 32 more bytes and must treat the `(value, digest)` pair atomically. The record format gains `prev_digest` and moves to format version 2 (PR #127 is unmerged, so no deployed state exists). The digest reveals nothing about the record's contents beyond a hash of it.

**What it does not change.** It does not stop a holder of the signing key from signing outside the store, and it does not make a lease a signing control (7.1); it only makes the *state* a fenced-out writer leaves behind unusable.

**Required tests once approved** (each must fail on the current implementation): the two-disk scenario above is refused on A's restart; the shared-directory overwrite is refused on B's restart; both files one ahead: the first restart commits, the second is refused, and no conflicting message was ever returned; the recovery advance with `p_f != d_t` is refused; mutants that drop the digest comparison, compare only the value, drop `prev_digest` from the body, or accept `p_f != d_t` are caught. The record format golden vectors are regenerated from the independent oracle.

**Complementary checks, not replacements:** the chain-evidence staleness rule (§7, "Stale file") and the fresh-initialization refusal stay in force; the counter adds detection that does not depend on the chain.

**Operational acceptance requirements** (before any validator runs on a real network; these are not satisfied by the unit tests):
1. A production counter backend, with a written threat model, independently reviewed, and tested against reset, rollback, replacement and two-live-copies attempts on that backend.
2. **Storage durability acceptance on the target hardware, operating system and filesystem:** repeated hard power-loss (or equivalent hard stop with write caches enabled) during signing, showing no torn state file and no `f < t` anomaly. On NTFS this includes establishing what the directory flush actually guarantees. The Windows unit runs show only that the calls succeed.
3. A backup and restore rule: a backup of the safety directory must never be restored onto a live key; restoring is key rotation.
4. Monitoring and an operator procedure for the rollback, inconsistent-counter and unreadable-counter errors.

**What the tests established and did not** (PR #127): in an in-memory model every crash point and every post-crash state reopens and never allows two messages for one round; a restored old file is refused when the counter is separate, and a test asserts that with the file *and* the counter both restored the rollback is invisible. They do not establish durability on any real disk or filesystem, and `TestCounter` proves nothing about a real counter.

**Required changes to PR #127 once this section is approved** (found while writing this section and in the owner's review). Items 1 to 6 are the compare-and-advance and session work; the digest-bound commits of 7.1.1 are a further, separately approved change (item 7):
1. The counter trait becomes compare-and-advance, `advance(expected_previous, session)`, not "advance to the current value or the current value plus one": the current idempotent form lets two live copies sharing one counter both succeed, and the lost-acknowledgement case does not need idempotence.
2. The recovery advance on open (`f == t + 1`) uses the same call, does not open the store or return anything until it succeeds, and fails closed if the counter is no longer `t`. Regression tests: a recovery advance that loses a race; a crash during the recovery advance (both outcomes reopen correctly); no signing before the advance has succeeded.
3. A session (fencing token) is acquired when the store opens and presented on every advance; a stale session is rejected and latches the store. Regression tests with two stores sharing one simulated counter: a stale store cannot commit; a store whose session was superseded latches and stops; the superseded store never returns a signature; the new holder is unaffected.
4. The counter handle is constructed bound to one validator instance.
5. Documentation and tests that call the double a "trusted counter" must say it is not, and the test double must implement the strict semantics.
6. Fresh Linux and Windows validation of the changed implementation.
7. If 7.1.1 is approved: the digest-bound counter state, `prev_digest` in the record (format version 2), the open rules and the required tests of 7.1.1, and regenerated golden vectors; then fresh Linux and Windows validation again.

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
- **Modularity:** shared Chain Forge interfaces (`ConsensusEngine`, `EngineSafetyState`, the genesis `consensus` and `cryptography` sections, engine selection by `consensus.bft_variant`) stay generic, so Tendermint and PQ-HotStuff-2 are selected independently per chain. Qattice-specific choices (this engine, the FIPS 204 profile, personhood weighting) live in the chain's genesis and deployment configuration, never in shared code paths. Adding PQ-HotStuff-2 must not change Tendermint behaviour for any chain that selects it.
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

The Tendermint devnet stays the default until Phase 2 passes on Windows. Phase 2 uses a **fresh genesis and a separate four-node development network** with newly generated keys; the existing Tendermint devnet is not migrated or modified. Removing Tendermint from Qattice's configuration is a separate owner decision after PQ-HotStuff-2 passes its gates and independent review (§1); Tendermint stays available in Chain Forge for other chains in all cases.

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
| N17 (2026-11-07) | Consensus separation: Qattice will ultimately use PQ-HotStuff-2 as its exclusive production consensus engine, conditional on the safety, persistence, four-node devnet, adversarial and independent-review gates; Tendermint remains the Qattice devnet baseline until then, stays selectable in Chain Forge for other blockchains, is not removed, disabled or modified now, and no existing network is migrated automatically. Removal from Qattice's configuration needs separate approval (§1). |

**Confirmed in the final review (2026-11-07), now reflected in the text:** N11 all canonical integers are big-endian, including `alg_id`; N12 the tags `CFH1|blockid|` and `CFH1|pop|` are approved and `CFH1` is retained; N13 the `cryptography.protocol_profile` design is kept and its documented compatibility tests are required; N14 Phase 0 uses in-memory test keys only; N15 the block identifier commits to all consensus-critical proposal fields with negative substitution tests (§3.2 rules 6 and 7); N16 a missing safety-state file never resets signing history and a fresh validator has an explicit initialization state (§7).

**Proposed, awaiting owner decision (2026-11-07):** §7.1, the trusted monotonic counter as a required security interface, with the failure matrix and the operational acceptance requirements (production counter backend; storage durability acceptance on the target platform). Owner conditions of 2026-11-07, now written into §7.1: the recovery advance returns and broadcasts nothing until it succeeds and fails closed on a concurrent advance; duplicated validators need an exclusive signing session (hardware-enforced, or a fenced lease enforced on every signing operation); key rotation is the only authorized recovery; the first private backend targets a remotely enforced, authenticated, fenced, replicated counter; no backend is production-ready before independent review. Recommended by the owner's review (not yet an approved decision): accept §7.1 as the design basis with the limit of option 2 retained; the first backend is a remotely operated, authenticated, replicated, fenced counter **for the private prototype only**; renewable server-enforced leases with monotonically increasing fencing tokens, duration to be set by failure and latency testing; fail closed and key rotation for rollback recovery, with no counter reset for the same key. This is enough to proceed with updating PR #127's tests and interface once the specification direction is approved; it is **not** enough to declare the production validator security architecture complete. Proposed in 7.1.1 (development of the specification approved by the owner as a proposed amendment; implementation and merge not approved): digest-bound counter commits that close the fenced-out-writer residue. Open choices for the owner: the operator and deployment of the prototype backend; whether and when a trusted signing boundary (option 1) becomes a requirement for a public network.

**Still blocked:** Phase 2 persistent validator key handling. It waits for the independent review of PR #109 and separate owner approval (§8.1). No other specification question is open in this revision; the next gate is owner approval of this text before any implementation.
