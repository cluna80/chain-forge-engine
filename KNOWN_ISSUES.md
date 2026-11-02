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

## §6  `adversarial_gossip` integration test does not compile

**Status: OPEN — pre-existing; found 2026-11-02 during H0-11B, reproduced on unmodified HEAD `f61f09c`**

`cargo test -p chain-forge-node --test adversarial_gossip --no-run` fails:
`error[E0063]: missing field 'genesis_hash' in initializer of 'NetworkConfig'`.
`NetworkConfig` gained a `genesis_hash` field with the H0-8 genesis-hash peer
check (`616bf0e`, `8fa0ecc`); `chain-forge-node/tests/adversarial_gossip.rs`
was not updated. Until it is, `cargo test -p chain-forge-node` (no `--test`)
cannot build every target, and its adversarial gossip coverage is not running.

**Fix:** initialise `genesis_hash` in the test's `NetworkConfig` (and decide
what value an adversarial peer should present).

---

## §7  `cs001_p7_mldsa_tx_accepted_during_and_after_migration` fails

**Status: OPEN — pre-existing; found 2026-11-02 during H0-11B, reproduced on unmodified HEAD `f61f09c`**

`node::tests::cs001_p7_mldsa_tx_accepted_during_and_after_migration` fails at
the "ML-DSA-65 tx must be accepted during grace window" assertion with:
`qcb1pquser has no bound key and is not derived from the signing key ...;
bind the account's ML-DSA key in genesis or send from the derived address`.
This looks like fallout from ML-DSA-only user accounts
(`b43e973`, `signature_scheme = "pqc-native"`): the test sends from an
account with no bound ML-DSA key. Unrelated to validator, jail or liveness
code. It is the only failure in the node unit suite (274 of 275 pass).

**Fix:** bind `qcb1pquser`'s ML-DSA key in the test genesis, or send from the
derived address; then confirm the grace-window behaviour the test intends.

---

## §8  Liveness jailing can mis-jail a healthy validator that is merely late

**Status: OPEN — measured 2026-11-02 (H0-11B evidence integrity). Automatic suspension must stay disabled in production genesis until a policy decision is made.**

**Mechanism (confirmed in code, `node.rs` tests `late_precommit_*`)**
Liveness is judged from the committed `last_commit` evidence the proposer
assembled. The proposer waits for every power-holding validator's precommit,
but only up to `COMMIT_GATHER_MS` (1,000 ms) after its own commit. A valid
precommit that arrives after the proposer builds the next block is omitted
and the live validator is recorded as a miss (`(1 observed, 100% missed)` vs
`(1, 0%)` for the same vote arriving in time). A precommit for a different
round than the one that committed is never published. Validators check the
evidence is valid, not that it is complete.

**What the policy does with a miss pattern**
(real `LivenessWindow`, 100-block window, 20% threshold, f = 1, 4 validators;
`chain-forge-slashing/tests/liveness_false_positive.rs`)
- Independent omission per block, P(jailed within 2,000 blocks):
  0–5%: ~0%; 10%: 2.2%; 15%: 74%; ≥20%: 100%. A sharp cliff near 12–15%.
- One isolated outage: ≤21 blocks never jails, ≥25 always does (~45 s at 2 s/block).
- Byzantine proposers: ≤ f always-omitting proposers are fully discounted;
  2 or more jail a healthy validator 100% of the time; 1 plus 10% honest-slow
  noise jailed it in 22% of trials. The discount does not cover f + 1, nor
  combined Byzantine and honest lateness.
- A genuinely offline validator is jailed ~21 blocks after the window is full.

**Measured on a real (loopback) 4-node network**
(`validator_liveness_integrity_live`, sandbox 575 s; Windows/BossKing-confirmed 2026-11-02, 561 s, identical results)
Worst plain miss for any healthy validator over a full 100-block window:
0% idle, 0% under light load; all four nodes served identical validator
status (including liveness windows) and state roots at 9 same-height checks.
Limits: loopback only, so this bounds behaviour on a good network and says
nothing about WAN delay; the "loaded" phase was light (a single sender can
keep about one tx per block in flight under the nonce-gap guard; block time
stayed ~2.4 s), so it did not exercise the 1 s collection window.

**Measured with injected arrival delay** (`validator_precommit_delay_live`,
cargo feature `fault-injection`, sandbox 2026-11-02; healthy Dave signs and
sends on time, only its ARRIVAL at the other nodes is delayed; idle chain)
Each row is 18 blocks; "omitted" is over blocks Dave did not propose himself.

| Arrival delay | Reached proposer before it built the block | In committed evidence | Window recorded miss | Median margin (proposal built minus arrival) |
| --- | --- | --- | --- | --- |
| 0 ms | 13 of 13 | 18 of 18 | 0 | 2,147 ms |
| 500 ms | 14 of 14 | 18 of 18 | 0 | 1,601 ms |
| 900 ms | 14 of 14 | 18 of 18 | 0 | 1,202 ms |
| 1,500 ms | 13 of 13 | 18 of 18 | 0 | 601 ms |
| 2,200 ms | 5 of 13 | 10 of 18 | 8 | -104 ms |
| 3,000 ms | 0 of 13 | 5 of 18 | 13 | -899 ms |
| 4,500 ms | 1 of 14 (see note) | 4 of 18 | 14 | -2,400 ms |

Windows/BossKing 2026-11-02 (`validator_precommit_delay_live`, 399.7 s) matches:
omitted from committed evidence (all counted as misses by the window) 0 of 18 at
0/500/900/1,500 ms; 6 of 18 at 2,200 ms (median margin +9 ms); 14 of 18 at
3,000 ms; 13 of 18 at 4,500 ms. Median margin at zero delay 2,162 ms. The
half-way point fell at 2,200 ms in the sandbox and just above it on Windows:
the transition is gradual across roughly 2.1-3 s, so "the cliff" depends on the
cut-off used, not on one sharp number.

Findings: (1) Stages agree end to end: whenever a precommit reached the
proposer before it built the block it was included, otherwise it was omitted,
and the liveness window recorded a miss for exactly the omitted blocks.
(2) On an idle chain the effective collection window is about 2.1 s (margin
at zero delay is ~2.15 s and falls one-for-one with injected delay), not the
1,000 ms `COMMIT_GATHER_MS`: the proposer also idles ~2 s with an empty
mempool. Omission begins just beyond that and is nearly total by 3 s.
(3) The cliff is therefore a property of proposer timing. With traffic the
proposer builds sooner (1 s gate), so the tolerance should shrink; NOT yet
measured. (4) One 4,500 ms row disagreed (arrival logged before the delayed
delivery was written when the log was read: a measurement-edge artifact).

Windows/BossKing 2026-11-02 idle experiment of the instrumented test (427 s) passed
and agrees with the sandbox (0 of 13-14 omitted up to 1,500 ms; 7 of 13 at 2,200 ms;
13 of 13 at 3,000 and 4,500 ms; block interval 2.3-3.0 s). It ran at the same time
as the loaded experiment because cargo runs tests in parallel, so treat it as
confirmed in direction; the tests now serialize themselves (commit 1bc5eab). The
loaded experiment's Windows run is INVALID for the same reason (eight nodes at
once; interval 2.2 s -> 5.4 s) and must be rerun on its own.

**Measured on a LOADED chain** (`validator_precommit_delay_loaded_live`, sandbox
2026-11-02; mempool non-empty at the proposer in >= 60% of blocks in every row,
~4.6 tx/s from 32 throttled accounts, ~5-11 txs per block). 14 blocks per row;
"networked" = blocks Dave did not propose himself. Block interval drifted
1.3 s -> 2.1 s (1.8x, worst 2.4 s) over the run because per-block persistence
cost grows with chain length (§9), so rows are not strictly comparable; the
first and last zero-delay controls both omitted 0 of 10.

| Arrival delay | Omitted from committed evidence | Median commit-to-proposal |
| --- | --- | --- |
| 0 ms | 0 of 10 | 1,297 ms |
| 500 ms | 0 of 10 | 1,016 ms |
| 900 ms | 1 of 11 | 1,065 ms |
| 1,200 ms | 3 of 11 | 1,188 ms |
| 1,500 ms | 6 of 10 | 1,058 ms |
| 2,200 ms | 8 of 10 | 1,085 ms |
| 3,000 ms | 11 of 11 | 1,041 ms |
| 0 ms (control, end) | 0 of 10 | 454 ms |

Findings: (5) Under load the proposer gives up on a missing precommit about
1.04-1.19 s after its own commit (the 1,000 ms `COMMIT_GATHER_MS` gate), in
every row where anything was omitted, so the safe arrival window is about 1 s,
half the idle chain's ~2.1 s. (6) Omission starts near 900 ms and passes half at
1,500 ms; the exact fraction at a given delay varies run to run with how busy
the proposer's event loop is (an earlier loaded run gave 12 of 13 at 1,500 ms,
another 8 of 14). Treat the transition as ~0.9-1.5 s, not a sharp edge.
(7) Every omission was attributable to the cutoff (received by the proposer,
arrived after the block was built), the liveness window recorded a miss for
exactly the omitted blocks, and all four nodes agreed on committed evidence
and on the liveness state after every row.

Consequence: a validator whose precommits regularly arrive more than ~1 s
after the proposer's commit, on a busy chain, accumulates misses while fully
participating; at ~35% omission a 20% threshold over 100 blocks jails it
(see the policy cliff above).

**Open decisions**
1. Whether to require the policy to tolerate a measured WAN delay profile
   (needs delay-injected or multi-host measurement).
2. Whether the evidence rule should change (e.g. count a validator present if
   its precommit appears in any committed block's evidence within N blocks).
3. Whether the threshold/window should change; not decided here.
4. The quorum-protection rule (removing a validator from 4 seats leaves f = 0).

---

## §9  Per-block persistence cost grows with chain length (blocks slow down under load)

**Status: OPEN — pre-existing; found 2026-11-02 while measuring a loaded chain**

`persist_state()` (called at the end of every `commit_block`) re-serializes
the entire `chain_store` with `to_string_pretty` and rewrites it synchronously,
on the consensus event loop, alongside several other whole-state files. The
cost therefore grows with chain length and block size.

Observed (4 local nodes, 40 single-in-flight senders, ~15-30 txs/block, no
round timeouts, no warnings): `chain_store.json` reached 27 MB by height ~190,
and the mean commit interval grew steadily from ~1.2 s (heights 25-75) to
3.3 s (100-125), 5.3 s (125-150), 6.1 s (150-175) and 7.8 s (175-200). An idle
chain stays at ~2.4 s/block. Block production, vote handling and the
collection of late precommits all share that blocked loop.

Effects: a sustained-load devnet slows quadratically; any timing-based
measurement (e.g. the late-precommit window in §8) drifts unless the run is
kept short or light. **Not fixed here** (outside H0-11B); candidate fixes are
incremental/append-only block persistence and off-loop writes.

---

## §10  API nonce cache never leaves the NO_PRIOR_TX sentinel (101-transaction lifetime cap, no ingress replay check)

**Status: OPEN — pre-existing; found 2026-11-02 (two load tests stalled at exactly 101 txs per account)**

`Node` seeds `nonce_cache` with `u64::MAX` (`NO_PRIOR_TX`) for every account
that has not committed a transaction, including every genesis account and
every funded recipient. After a block executes, the cache is updated with
`if tx_nonce >= entry { *entry = tx_nonce }`. No nonce is `>= u64::MAX`, so a
sentinel entry is never replaced. `f1_nonce_rejected(NO_PRIOR_TX, n)` then
rejects every `n > MAX_NONCE_GAP (100)` forever.

Observed: 8 fresh accounts, one transaction in flight each, queued exactly
808 = 8 x 101 transactions and then every further submission was refused,
although the chain kept committing and the accounts had funds.

Effects: (1) any account is capped at 101 API-submitted transactions over its
lifetime; (2) for such accounts ingress replay protection is effectively off
(execution still enforces nonces, so this alone does not endanger funds).

**Not fixed here.** Likely fix: treat a `u64::MAX` entry as "unset" in the
update (`if *entry == u64::MAX || tx_nonce >= *entry`), with tests for both
the cap and the ingress replay check.
