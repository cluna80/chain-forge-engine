# PQ-HOTSTUFF-001 — PQ-HotStuff Consensus: Protocol Specification

Status: **Decisions D1–D5 locked (owner, 2026-10-28).** Implements the locked direction of 2026-10-28 ("Qattice PQ-HotStuff Consensus Specification"). No code yet.
Date: 2026-10-28
Scope: Qattice mainnet consensus; a selectable Chain Forge `ConsensusEngine`.

This document turns the locked direction into a buildable protocol: message formats, safety rules, commit rule, pacemaker, persistence, reconfiguration, and the acceptance gates each phase must pass. Items marked **[decision]** need an owner choice; each has a recommendation.

---

## 1. Relationship to what exists

| Component | Status | Role here |
|---|---|---|
| Tendermint engine (`tendermint/engine.rs`) | Hardened (#18, gates 1–3), Windows-confirmed | **Stable devnet baseline** until PQ-HotStuff passes every gate in §12. Its patterns (engine-driven actions, persisted sign guard, model-based simulation) are reused. |
| ML-DSA-65 consensus keys (#24) | Windows-confirmed on Tendermint | Reused as-is: `sign_consensus` / `verify_consensus`, ML-DSA-only genesis (`validator_scheme: "ml-dsa-65"`), key files, PoP registration. |
| Legacy `HotStuffEngine` (`lib.rs`) | Devnet-only (gate 2). No engine-driven voting, no persisted lock, `verify_commit` checks no signatures | **Not a base.** PQ-HotStuff is a new module. The legacy engine stays devnet-only and is retired once PQ-HotStuff lands. |
| Equivocation slashing | Broken (gate 4): signed evidence never verifies; fixing only that diverges node state | **Prerequisite.** Committed-evidence slashing is engine-independent and must land first (§9). |
| Succinct committee proof (M0, `docs/succinct-proof-prototype-scope.md` on `docs/validator-sampling-spec`) | Scoped, in progress in another session | Decides the mainnet validator-set ceiling (§10). |

No consensus code is borrowed. The safety rules below follow the published two-chain HotStuff variant (DiemBFT v4 / Jolteon: Gelashvili et al., "Jolteon and Ditto", FC 2022; Diem team, "DiemBFT v4", 2021). They are implemented from the papers, and the arguments are re-checked in review (§12, Phase 3).

---

## 2. Model and assumptions

- **Validators:** an epoch-fixed set V_e. Each v has voting power p(v) ≥ 0, a registered ML-DSA-65 key, and verified personhood. Power comes from the personhood layer (bounded per human; §8). Total T = Σp.
- **Faults:** Byzantine power f < T/3. **Quorum:** q = ⌊2T/3⌋ + 1 (gate 3 floor: never lower).
- **Network:** partial synchrony. After an unknown GST, messages between honest validators arrive within Δ.
- **Signatures:** ML-DSA-65 only. A message signed by any other scheme is invalid; there is no fallback. The engine refuses to start unless every key in V_e is 1952 bytes.
- **Safety:** no two honest validators commit different blocks at the same height, under any network schedule.
- **Liveness:** after GST, with an honest leader, a new block commits within a bounded number of rounds.

---

## 3. Data types

All integers are little-endian. Hashes are the chain's `ChainHash` (SHA3-256 at hash width 256). `epoch` and `round` are u64; round numbers never reset within an epoch.

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

Signing bytes are domain-separated and bind the chain and epoch:

| Message | Bytes |
|---|---|
| Block | `"CFH1\|block\|" ‖ block_id` |
| Vote | `"CFH1\|vote\|" ‖ chain_id ‖ epoch ‖ round ‖ block_id ‖ parent_id ‖ parent_round` |
| Timeout | `"CFH1\|timeout\|" ‖ chain_id ‖ epoch ‖ round ‖ high_qc_round` |

Tag `CFH1` cannot collide with the Tendermint tags (`CFV|`, `CFP2`), so a signature from one engine is never valid in the other.

**QC validity:** every signer is in V_epoch, each counted once. Each signature verifies with `verify_consensus` against the signer's key. Signer power sums to at least q.
**TC validity:** the same, over timeout bytes for the same `(epoch, round)`. `high_qc` is valid, and `high_qc.round == max(high_qc_rounds)`.

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

- **Safety state:** `{epoch, hvr, hqr, last_signed}` is written atomically to `persist/pq_hotstuff_safety.json` **before** any vote or timeout leaves the node. This is the same write-before-broadcast discipline as the Tendermint `SignGuard`. If the file is present but unreadable, the node refuses to sign (fail closed).
- **Block store:** the uncommitted blocks on the path from the highest committed block to the highest QC, plus that QC and the highest TC. On restart these are reloaded and the node resumes from round `max(hqr, highest TC round) + 1`.
- **Engine interface:** the `ConsensusEngine` lock hooks (`lock_state` / `restore_lock_state`) currently take a Tendermint-shaped `LockState`. They become a versioned enum `EngineSafetyState::{Tendermint(LockState), PqHotStuff(PqSafetyState)}`, with a serde tag so existing data dirs keep loading.

---

## 8. Personhood weighting and reconfiguration

- **Power:** every validator-set update applies, in this order: `apply_personhood_cap` (bounded per human), then `gate_voting_power` (no personhood or no key gives power 0), then the gate-3 quorum floor. This is the same path the Tendermint engine uses and cannot be bypassed.
- **Epochs:** V_e changes only through a committed epoch-change block. The new set takes effect from the first round of epoch e + 1. A QC or TC is always verified against the set of its own epoch, using the existing `historical_validator_sets`.
- **Revocation:** "without delay" means the revocation takes effect in **the first block after the one that commits the revocation**. That block starts a mini-epoch with the revoked validator at power 0. It cannot take effect mid-round: changing the set inside a round breaks the quorum-intersection argument that §5 relies on. **[decision D4]** Recommendation: apply revocations at the next block, not at the next regular epoch boundary.
- **Key rotation:** reuses PQ-VAL-003 (rotation takes effect at the next block, with a one-block power gap). The same set-change rule applies.

---

## 9. Equivocation

Evidence types:
- **double vote:** two votes, same `(epoch, round)`, different `block_id`.
- **double proposal:** two blocks from the leader of the same round.

Each item of evidence is self-verifying: both signatures check under the offender's key for that epoch. (A vote followed by a timeout in the same round is **not** evidence; §5 allows it. Lock-violation evidence, such as a timeout whose high QC is below a QC the signer already voted on, is a Phase 3 candidate.)

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

- **Selection:** `consensus.bft_variant: "pq-hotstuff"`. Startup refuses it unless `cryptography.validator_scheme == "ml-dsa-65"` (no classical path). Until the §12 Phase 2 gate passes, it is devnet-only, enforced by the same check as gate 2.
- **Engine:** a new module `chain-forge-consensus/src/pq_hotstuff/`. It implements `ConsensusEngine` with `drives_own_votes() = true`, and drives the node through the existing `ConsensusAction` / `next_action` / `on_step_timeout` / `gossip_messages` hooks. It gains new actions: `SendVoteTo(leader)` and `BroadcastTimeout`.
- **Reused unchanged:** key registration, PoP, activation and rotation (PQ-VAL-001/2/3); `sign_consensus` / `verify_consensus`; payload validation; block-hash agreement; state-root binding.
- **Other chains:** the engine takes the power function as input. Personhood weighting is mandatory in **Qattice's** genesis profile, where startup refuses `pq-hotstuff` without `personhood_weighted: true`. Another Chain Forge chain can supply stake or equal weights.

---

## 12. Phases and acceptance gates

Each gate follows the project rule: failing tests first, then mutation checks, then sandbox, then **Windows confirmation** before ✅.

**Phase 0 — prerequisites and core engine**
- **Gate 4** (committed-evidence slashing, on Tendermint) lands first.
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

The Tendermint devnet stays the default until Phase 2 passes on Windows.

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
