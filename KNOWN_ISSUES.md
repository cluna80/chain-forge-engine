# Known Issues

Issues discovered during integration testing, recorded here so they survive
session boundaries.  Each entry has a short title, the symptom, the root cause
(where known), and the fix needed.

---

## §1  Genesis stake underflows slash penalty (BME burn fails silently)

**Status: RESOLVED** — commit `87634ba`

**Was**: `tests/devnet/genesis-4node.json` gave each validator 5 QCB
(5_000_000 uqcb) but the bonded amount in `ValidatorRecord` defaulted to
ENTRY_STAKE (1000 QCB), making the computed slash (5% = 50 QCB) larger than
the bank balance, so the BME burn failed silently while the tombstone still
applied.

**Fix**: Raised the genesis account balance in `genesis-4node.json` from
5_000_000 to 500_000_000 uqcb (500 QCB) — safely above the maximum possible
equivocation slash (5% of ENTRY_STAKE = 50 QCB).

---

## §2  Liveness slashing misfires during startup gossip warmup

**Status: RESOLVED** — commit `87634ba`

**Was**: Two separate causes produced false tombstones at startup:

1. **Liveness grace period missing**: the liveness window started counting from
   block 0, before the P2P mesh formed, so the first several rounds looked like
   "missed" blocks.

2. **False equivocation detection (the primary cause)**: the consensus engine
   treated a nil-prevote followed by a real-prevote (or vice-versa) at the same
   (height, round) as a double-sign.  This is incorrect — changing from a nil
   vote to a real vote is standard BFT round-change behavior, not Byzantine.

**Fix**:
- Added `liveness_start_height: u64` (default 10) to `SlashingConfig`.
  `record_block()` now accepts `current_height` and skips enforcement below the
  threshold.
- Fixed the equivocation guard in `chain-forge-consensus/src/lib.rs` to require
  **both** conflicting votes to be non-nil:
  `existing.block_hash.is_some() && vote.block_hash.is_some() && existing != vote`.

**Verification**: `validators_api_live_power_snapshot` (personhood_live) now
passes 5-for-5 runs, showing 4 active validators with total_power=4.

---

## §3  Garbage-signature test is a Phase 0 stub (not verified rejection)

**Status: RESOLVED** — commit `c07f5d1`

**Was**: `adversarial_garbage_signature` passed but did NOT verify that
garbage signatures are rejected.  In Phase 0, `verify_vote_signature` took a
pass-through path when genesis had no `public_key` fields, so the garbage-sig
vote was silently accepted.  The chain remained safe only because a single
injected vote cannot manufacture quorum.

The test was marked `#[ignore]` and did not count as coverage.

**Root cause (discovered during fix)**

Two bugs combined to prevent real signature verification from working:

1. **`ConsensusConfig` had no `chain_id` field**: `TendermintEngine.chain_id`
   was never set from genesis during `init()`.  Vote signing used the real
   chain_id (`"qcb-devnet-4node"`) but verification used `""` — so all
   Ed25519 checks failed even for legitimate votes.

2. **Wrong error mapping**: the signature verification failure path mapped the
   crypto error to `ConsensusError::UnknownValidator` instead of
   `ConsensusError::InvalidVote`, producing misleading "validator X is not in
   the current validator set" log messages for what were actually signature
   failures.

**Fix**

1. Added `public_key` fields (Ed25519) for each validator in
   `tests/devnet/genesis-4node.json` (done in prior session).
2. Added `chain_id: String` field to `ConsensusConfig`.
3. `TendermintEngine::init()` now sets `self.chain_id = config.chain_id.clone()`.
4. `node.rs` `ConsensusConfig` construction passes `chain_id: genesis.chain_id.clone()`.
5. Fixed error mapping: signature failure → `ConsensusError::InvalidVote { reason: "invalid signature: ..." }`.
6. Removed the `#[ignore]` attribute from the test; it now runs in CI.

**Verification**

`adversarial_garbage_signature` passes with both assertions green:
- `PASS: chain advanced despite garbage-sig attack (liveness verified)` — the
  3-of-4 honest validators retain quorum and the chain advances past the
  attack height.
- `PASS: garbage-signature vote from qcb1bob was actively rejected` — node
  logs contain a line matching "invalid signature" with "qcb1bob".

**Affects**

`chain-forge-consensus/src/lib.rs` (`ConsensusConfig`, `TendermintEngine::init`,
signature error mapping),
`chain-forge-node/src/node.rs` (`ConsensusConfig` construction),
`chain-forge-node/tests/adversarial_gossip.rs` (`adversarial_garbage_signature`)

---

## §4  Duplicate-attestation guard not directly exercised in tests

**Status: RESOLVED** — live devnet verification 2026-09-30

**Was**: `attestation_guard_live` used `nonce=1` for the duplicate Attest
while Bob's committed nonce was still `0`.  The nonce guard fired first,
producing `"nonce mismatch: expected 0, got 1"` before the
duplicate-attestation guard in `IdentityStore::attest()` was reached.

**Fix applied**: Confirmed the duplicate-attestation guard fires correctly
by submitting the duplicate Attest with the correct post-first-attest nonce:

```
POST /api/tx  sender=qcb1alice  nonce=5 (read after first attest committed)
body: {"Attest": {"claimant_id": "qcb1eve"}}
```

Result (height 340):
```json
{ "success": false,
  "error": "attester qcb1alice has already vouched for this claimant" }
```

The guard in `IdentityStore::attest()` is functioning correctly.

**Remaining work**: Update `attestation_guard_live` in
`chain-forge-node/tests/attestation_live.rs` (phase 6) to poll for the
first attest's commit, read the committed nonce, then submit the duplicate
with the correct nonce and assert the "already vouched" error.

**Affects**

`chain-forge-node/tests/attestation_live.rs` (`attestation_guard_live`,
phase 6),
`chain-forge-identity/src/lib.rs` (`attest()` duplicate guard)

---

## §5  Governance preimage has no chain_id (cross-chain replay possible)

**Status: OPEN — must fix before governance moves on-chain**

**Summary**

`governance_vote_signing_bytes` uses a static domain prefix
`"chain-forge:governance:v1:"` with no runtime `chain_id`.  A governance vote
(add or revoke issuer) signed on one chain could in principle be replayed on a
second chain if both share the same ML-DSA validator set.

**Same-chain epoch replay is fixed** (see below).  Cross-chain replay remains.

**Root cause**

`GOVERNANCE_DOMAIN` is a compile-time constant.  Unlike consensus preimages
(`vote_signing_bytes`, `proposal_signing_bytes`), governance signing bytes are
constructed by a module-level function that does not take a `chain_id`
parameter.  There is no per-chain runtime value in the signed message.

**Conditions that make this exploitable**

The following conditions must all hold simultaneously:
1. Two chains share the same ML-DSA validator set (same keys, same quorum).
2. Both chains use the same issuer registry state at the time of the vote
   (`propose_change` binds to sorted registry IDs, so this is non-trivial).
3. A governance action is performed on chain A that the attacker wants
   accepted on chain B.

Under the current architecture, governance is out-of-band (no chain
transactions, per-instance registry), so the conditions are difficult to
satisfy.  Risk is low today.

**Fix**

Add `chain_id: &str` as a parameter to `governance_vote_signing_bytes` and
prepend it between the domain tag and the action tag:

```
chain-forge:governance:v1:<chain_id>:<action_tag>:<context_bytes>
```

Update all call sites and the `AuthorizedIssuerRegistry` methods to thread
`chain_id` through.  The change is mechanical; the protocol break is
intentional (old governance votes become invalid after the upgrade, which is
safe because governance has not yet produced any on-chain artifacts).

**Related fix already applied (same-chain epoch replay)**

`revoke_with_votes` now accepts an `epoch: u64` parameter and folds it into
the context bytes (`issuer_id_BE ++ epoch_LE`) so a revocation vote is bound
to a specific governance round.  Replay across epochs is no longer possible
for revocations.  `propose_change` is already epoch-safe by construction
(context includes the full registry state, which changes after each proposal).

**Trigger conditions for immediate escalation**

This issue must be resolved before any of the following:
- Governance votes become on-chain transaction types (roadmap §7.3, §6.8, §11).
- Multi-chain interoperability is introduced and validator sets are shared
  across chains (roadmap Phase 5+).
- The same issuer registry instance is used across multiple chain instances.

**Affects**

`chain-forge-personhood/src/governance_authority.rs`
(`governance_vote_signing_bytes`, `propose_change_with_votes`,
`revoke_with_votes`), all call sites in
`chain-forge-personhood/src/bin/governance_authority_demo.rs`.

---

## P02A-W1  P-02a Windows validation, and one unexplained `h0_3_crash_recovery_live` failure

**Status: RECORDED 2026-11-02 — not a P-02a defect as far as can be told; cause UNCONFIRMED.**
(Numbered P02A-W1 rather than §6 so it does not collide with the §6-§13 entries on the unmerged H0-11 branch.)

Validated on Windows / BossKing (MINGW64), commit `5fc1941` (branch `feat/p02a-gaps-rebased`; later commits are docs only):

| Command | Result |
| --- | --- |
| `cargo test -p chain-forge-core` | 62 passed |
| `cargo test -p chain-forge-state` | 74 passed, 3 ignored |
| `cargo test -p chain-forge-node --bin chain-forge-node` | 325 passed, 1 failed (`cs001_p7_mldsa_tx_accepted_during_and_after_migration`, the known failure, identical on `main`) |
| `h0_3_crash_recovery_live`, whole file: 6 parallel runs + 1 `--test-threads=1` (7 runs) | 12 passed in 5 parallel runs and the serial run; **11 passed, 1 failed in one parallel run** (`c_01_clean_restart_preserves_state`) |
| `h0_3_crash_recovery_live c_01`, alone, twice | passed (15 s each) |
| `h0_8_genesis_peer_verification_live` | 7 passed |

What the Windows run shows: the node suite includes the directory-fsync tests (D1, D2, D6), so `flush_dir_windows` (`FILE_FLAG_BACKUP_SEMANTICS` + `FlushFileBuffers`) ran and succeeded, and the live tests commit a snapshot through it on every block. It does **not** show that a rename survives power loss on NTFS; that was not tested.

**The anomaly.** In one of the first two parallel runs after a fresh build and an Avast exception, C-01 failed. The failure message was not captured. The next 7 runs of the same test (C-01 alone twice, the serial whole-file run, and 4 parallel whole-file runs) all passed; the 4 parallel and 2 single runs took about 15 s each. In total C-01 ran 9 times (7 whole-file runs, 2 alone): 1 failure, 8 passes. The two slow runs (42.6 s and 58.0 s) were the first two after the rebuild; the failing one was the 58 s run. The test waits up to 20 s for the API port and 30 s for height.

**Suspected cause (UNCONFIRMED):** antivirus (Avast) scanning a freshly built node executable, or machine load right after a rebuild, delaying startup past the 20 s port wait. A second candidate: the test's `free_port()` binds port 0, which hands out ephemeral-range ports and can collide on Windows (the cause of an earlier jail-test failure, os error 10048). Neither was observed. A persistence defect would be expected to fail repeatedly, and it did not.

**Not changed.** The test file was deliberately NOT hardened on the P-02a branch (separate change after merge: ports outside the ephemeral range and more wait margin). If C-01 fails again, capture the log (`... -- --nocapture 2>&1 | tee c01.log`) and grep for `panicked`, `FATAL`, `10048`.

---

## GOV-Q1  Governance quorum: misleading failure wording, vacuous quorum at zero population, floating point in the decision

**Status: OPEN, follow-up only. Found 2026-11-02 while reviewing the H0-12 Windows run (`governance_quorum_live`). Not a correctness failure: every GQ-01..GQ-06 outcome is correct. Not changed in code.** Code: `chain-forge-governance/src/lib.rs`, `GovernanceConfig::qcb_default` and the tally around line 467.

1. **The "4%" is the configured value, not a rounding artifact.** `ordinary_quorum_pct = 4` (a deliberate margin above the 3% floor; constitutional is 7 above 6), pinned by `ordinary_quorum_floor_is_above_3pct_sybil_threshold`.
2. **The message can mislead on small populations.** The required voters are `ceil(verified * pct / 100)`, so the effective threshold is above the configured percentage when the population is small (11 verified humans: 1 voter, which is 9.1%), yet the message prints "need 4% (1 voters)". Grammar aside ("1 voters"), a reader may think one voter is 4%. Suggested wording: "need 4% of 11 verified humans (at least 1 voter), got 0".
3. **Quorum is vacuous at zero population.** With `verified_humans_at_submission == 0`, `needed_voters` is 0, so the quorum check passes with no participants. Such a proposal still fails on the approval check (0.0% < 51%) and, for constitutional changes, on the absolute minimum of 10 voters, so nothing can pass. This rests on those later checks rather than on an explicit rule; either reject proposals submitted at zero population or document it.
4. **Floating point in a consensus decision.** The quorum (`f64` multiply, divide, `ceil`) and the approval comparison (`yes / decisive * 100.0 < threshold`) use `f64`. A comparison against integer arithmetic found **zero mismatches** for quorum percentages 4 and 7 with verified populations 0..200,000, and for approval thresholds 51 and 67 with 1..2,000 decisive votes. The ranges are bounded and the thresholds are configurable, so integer arithmetic (`(verified * pct + 99) / 100`, `yes * 100 < threshold * decisive`) is the recommended hardening for consensus-critical code.

Not blocking H0-12 (merged as #52). Fix as a separate, tested change.
