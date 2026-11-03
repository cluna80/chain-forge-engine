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

**Status: FIXED on `main` by #44 (`c26f572`, the test now sends from the key-derived address). Node suite: 0 failures since. Text below is the original finding (found 2026-11-02 during H0-11B, reproduced on `f61f09c`).**

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

**Mechanism (confirmed in code, `node.rs` tests `late_precommit_*`; Windows 4 of 4, 2026-11-02)**
Liveness is judged from the committed `last_commit` evidence the proposer
assembled. The proposer waits for every power-holding validator's precommit,
but only up to `COMMIT_GATHER_MS` (1,000 ms) after its own commit. A valid
precommit that arrives after the proposer builds the next block is omitted
and the live validator is recorded as a miss (`(1 observed, 100% missed)` vs
`(1, 0%)` for the same vote arriving in time). A precommit for a different
round than the one that committed is never published. Validators check the
evidence is valid, not that it is complete.

**What the policy does with a miss pattern**
(real `LivenessWindow`, 100-block window, 20% threshold, f = 1, 4 validators; Windows 5 of 5, tables identical to the sandbox;
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

Windows/BossKing, staggered load (commit af15c4a): idle PASSED (407 s; omitted 0 of 13-14 up to 1,500 ms,
3 of 14 at 2,200 ms, 14 of 14 at 3,000 ms, 13 of 13 at 4,500 ms; interval 2.3 -> 2.6 s). Loaded run FAILED
its 4x drift guard: median block interval 845 ms -> 1,148 / 1,618 / 1,760 / 2,935 / 3,482 / 5,148 ms
(worst 6.1x) as the chain grew by only ~1,500 txs / ~170 blocks. Rows up to 1,500 ms ran at <= 2.9 s
blocks and show omitted 0 of 11 (0 ms), 0 of 10 (500), 5 of 11 (900), 3 of 11 (1,200), 5 of 11 (1,500);
later rows and the closing control (1 of 13 omitted at 0 ms delay) ran on a 3.5-5 s chain and are NOT
usable for the cutoff. No omission was unattributed. Windows degrades much faster than the sandbox
under identical load, which makes §9 (whole-chain rewrite on every commit) the practical blocker for
any sustained-load measurement on the development platform.

Sandbox, reduced load (16 accounts, ~1.6 tx/s, commit af15c4a+): PASSED (321 s); mempool non-empty at
>= 60% of proposals in every row; block interval 1.4 s -> 1.3 s (worst 2.6 s, 1.9x); omitted 0 of 10
(0 ms), 0 of 10 (500), 4 of 11 (900), 4 of 11 (1,200), 6 of 10 (1,500), 10 of 10 (2,200), 10 of 10
(3,000), 0 of 10 (closing control); commit-to-proposal 851-1,074 ms in rows with omissions. Not yet
run on Windows. Note the load is deliberately light (2-4 txs per block); this does not prove the
evidence policy is safe under sustained production load (§9 prevents measuring that on one machine).

Sandbox rerun after staggering the load (commit following 96e39d1; PASSED, 320 s; mempool
non-empty at >= 60% of proposals in every row incl. the first; block-interval drift 1.7x,
1.2 s -> 2.0 s worst): networked blocks omitted 0 of 11 (0 ms), 0 of 10 (500), 4 of 11 (900),
6 of 10 (1,200), 6 of 10 (1,500), 11 of 11 (2,200), 10 of 10 (3,000), 0 of 11 (closing 0 ms
control). Commit-to-proposal in the rows with omissions: 803 / 888 / 1,035 / 1,046 / 1,057 ms.
Half omitted at 1,200 ms. This is the cleanest loaded sweep so far; the Windows run of this
exact version is not yet done.

Windows/BossKing, experiments serialized (commit 1bc5eab): idle experiment PASSED (396 s):
omitted 0 of 13-14 up to 1,500 ms, 8 of 14 at 2,200 ms, 14 of 14 at 3,000 ms, 13 of 13 at
4,500 ms; block interval flat at 2.3-2.4 s. Loaded experiment completed all eight rows but
FAILED its own load bar on the first row (mempool non-empty at 8 of 14 proposals, bar 60%;
all 32 load accounts started in one wave). Its data, with that caveat and a 2.0x block-
interval drift (1.7 s -> 3.3 s): networked blocks omitted 0 of 10 (0 ms), 0 of 11 (500),
2 of 10 (900), 5 of 10 (1,200), 4 of 10 (1,500), 8 of 11 (2,200), 9 of 11 (3,000), and
0 of 10 for the closing 0 ms control; commit-to-proposal 1,081 / 1,100 / 1,051 / 1,047 ms
in the 1,200 / 1,500 / 2,200 / 3,000 ms rows (the ~1 s gate). Same direction and the same
gate as the sandbox; exact fractions differ, as expected.

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


**Windows loaded run on the merged `main` (2026-11-02, BossKing/MINGW64, `b9f1e7e`, `validator_precommit_delay_loaded_live`, 304 s; 16 throttled accounts, one tx in flight each).** This is the first valid Windows loaded run (the first attempt, run in parallel, was invalid). Dave precommitted on time every block; only the arrival was delayed.

| Delay | Dave's precommits in committed evidence | Window misses |
| --- | --- | --- |
| 0 ms | 14/14 | 0 |
| 500 ms | 12/14 | 2 |
| 900 ms | 10/14 | 4 (29%) |
| 1200 ms | 7/14 | 7 |
| 1500 ms | 4/14 | 10 |
| 2200 ms | 3/14 | 11 |
| 3000 ms | 4/14 | 10 |
| 0 ms (control, at the end) | 11/14 | 3 |

First delay at which at least half were omitted: **1200 ms** (idle chain: 3000 ms, unchanged in shape from the earlier Windows idle run). The commit-to-proposal interval while Dave's precommit was missing was 1064–1706 ms, the gate. **Correction (2026-11-03):** this paragraph originally said that sustained lateness of roughly 500–900 ms "already produces 14–29% omission, i.e. above the 20% threshold". That was wrong on its face (14% is below 20%) and the 900 ms point did not reproduce in the second run below (4/14 then 1/14). See the two-run comparison that follows. The control row shows the effect is not only added delay: the block interval drifted 1.9x (1071 to 2077 ms) over the run, which is §9. **Automatic suspension stays disabled.** The Windows numbers match the sandbox finding that the loaded collection window is about 1 s.

**Second Windows loaded run, same test and load (2026-11-03, BossKing/MINGW64, merged `main` `385431f` with #58, `validator_precommit_delay_loaded_live`, 302 s).** Dave's precommit *arrival* delayed, signing on time:

| Delay | Run 1 (`b9f1e7e`): in evidence / misses | Run 2 (`385431f`): in evidence / misses |
| --- | --- | --- |
| 0 ms | 14/14 / 0 | 14/14 / 0 |
| 500 ms | 12/14 / 2 | 12/14 / 2 |
| 900 ms | 10/14 / 4 (29%) | **13/14 / 1 (7%)** |
| 1200 ms | 7/14 / 7 | 5/14 / 9 |
| 1500 ms | 4/14 / 10 | 4/14 / 10 |
| 2200 ms | 3/14 / 11 | 4/14 / 10 |
| 3000 ms | 4/14 / 10 | 3/14 / 11 |
| 0 ms (control, at the end) | 11/14 / 3 | 12/14 / 2 |

**Idle chain, run 2 (`385431f`, 436 s), Dave's precommit omitted from committed evidence:** 0 of 18 at 0–1,500 ms; 1 of 18 at 2,200 ms; 14 of 18 at 3,000 ms; **14 of 18 at 4,500 ms**. Run 1's 4,500 ms idle figure was **not captured in this table** and is not inferred here. (Earlier sandbox/Windows runs elsewhere in this section record 13 of 18 at 4,500 ms on other commits; they are not run 1.)

Block-interval drift: 1.9x (1071 to 2077 ms) in run 1, **1.6x (1269 to 2080 ms)** in run 2. Delay-0 control omissions at the end: 3 of 11 then 2 of 10. The commit-to-proposal interval while Dave's precommit was missing: 918–1690 ms in run 2.

**What is stable and what is not, across the two runs.** Stable: at 0 ms nothing is omitted; at 500 ms 2/14 (14%, below a 20% threshold); at 1200 ms at least half are omitted (7/14 and 9/14); from 1500 ms about 70–80% are omitted. **Not stable: the 900 ms point (7% to 29%)**, which sits between the two regimes, so a single run cannot say whether a validator that is ~900 ms late is above or below a 20% threshold. The idle chain moved the same way: omissions at 2200 ms were 5/18 in the first Windows run on the older base and 1/18 now; half were omitted at 3000 ms in both. Consequence: **the transition from "harmless" to "mostly omitted" lies between about 900 and 1200 ms of lateness on a loaded chain, but its exact position varies run to run, and the block interval itself drifts 1.6–1.9x during the run (§9).** No threshold should be chosen from these tables; repeat the experiment after PERSIST-001 P-02b with several runs per setting. **Automatic suspension stays disabled.**

## §9  Per-block persistence cost grows with chain length (blocks slow down under load)

**Status: OPEN — pre-existing; found 2026-11-02 while measuring a loaded chain. Not fixed by P-02a (#48): every block still rewrites and fsyncs all eight files, and the cost has not been re-measured. PERSIST-001 P-02b is the planned fix.**

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

**PERSIST-001 P-01 profile (read-only; 2026-11-02, sandbox, DEBUG build — release pending)**
`persist001_profile_commit_path` (ignored test, no production change): 4-validator in-process
commit path, 10 transfers per block, persistence on.

| Height | Median commit | chain_store.json | Serialize (pretty) | Write | persist_state() total |
| --- | --- | --- | --- | --- | --- |
| 25 | 378 ms | 2.5 MB | 83 ms | 4 ms | 113 ms |
| 100 | 697 ms | 9.8 MB | 301 ms | 8 ms | 254 ms |
| 200 | 1,345 ms | 19.5 MB | 435 ms | 14 ms | 463 ms |
| 300 | 2,096 ms | 29.2 MB | 732 ms | 24 ms | 730 ms |

- Cost is linear in height and dominated by SERIALIZATION, not the disk write (732 ms vs 24 ms at
  height 300). Compact (non-pretty) serialization is ~2.4x cheaper (306 ms), still linear.
- The chain store is ~97 KB per block for 10 transfers: block payload and signatures are Vec<u8>,
  which JSON writes as arrays of numbers.
- persist_state() is NOT the whole story. With persistence off (control) the same loop still goes
  243 ms (h25) -> 391 (h100) -> 806 (h200) -> 1,165 ms (h300): roughly 56% of the height-300 commit
  is other work that also grows with chain length. Not yet located.
- A temp+fsync+rename write of the compact store cost 112 ms at height 300 (fsync is not the
  main cost).

---

## §11  `persist_state` is not atomic and a failed load looks like a fresh start

**Status: FIXED on `main` by #48 (P-02a, `467b1ae`): snapshots are atomic generations with a checksummed manifest, a damaged or incomplete committed store is `Fatal` instead of a genesis start, legacy directories migrate strictly or refuse, and a signing guard with no chain state is refused. See P02A-W1 for the Windows validation and what it does not show (power-loss durability untested). The text below is the original finding (2026-11-02, while scoping PERSIST-001); the `persist001_audit_torn_files` measurement is kept as an ignored test of the OLD behaviour.**

`persist_state()` rewrites eight files in place with `std::fs::write` (truncate + write), with no
temp file, fsync or rename, and ignores write errors. Only the double-sign guard uses `write_atomic`.
`load_persisted_state()` logs "could not load persisted state — starting from genesis" on a parse
error and returns false; `main.rs` treats false as "no persisted state found — starting from genesis".

Audit (`persist001_audit_torn_files`, 12 committed blocks, one file damaged at a time):
state.json truncated or emptied, chain_store.json truncated or emptied, slashing.json truncated,
identity.json truncated, live_validator_set.json truncated: **all fall back to genesis**
(status height 0, engine height 0) with only that log line. validators.json missing: loads
"successfully" at height 11 with a registry rebuilt from genesis (silently inconsistent).

Windows/BossKing 2026-11-02 reproduces the audit exactly (debug build, 16.8 s): the same seven files fall
back to genesis (status height 0, engine height 0) and `validators.json` missing resumes at status
height 11 / engine height 12.

Why it matters: H0-3 is marked complete for "consistent after an unclean shutdown at any block
height"; the audit shows a crash MID-WRITE (torn file) is not covered by the load path. The
double-sign guard is atomic and would refuse conflicting votes, which limits the safety damage but not
the loss of the node's chain. This is also the baseline PERSIST-001 must beat, not merely preserve.

---

## §12  State tree lookups walk back through every version (commit cost grows linearly with height)

**Status: FIXED on `main` by #46 (`ca87fc1`, one file, `chain-forge-state/src/jmt.rs`): indexed lookup, identical roots. Windows: release benchmark flat at 30–33 µs per commit from 100 to 20,000 versions. The text below is the original finding (2026-11-02, PERSIST-001 P-01).**

Release-mode profile (same in-process 4-validator loop, 10 transfers per block, persistence ON; `persist001_profile_commit_path`):

| Height | Median commit | persist_state() | Share |
| --- | --- | --- | --- |
| 25 | 16 ms | 9 ms | 56% |
| 100 | 78 ms | 28 ms | 36% |
| 300 | 503 ms | 95 ms | 19% |
| 600 | 1,152 ms | 165 ms | 14% |

(The debug build is ~13x slower in serialization, which exaggerated persistence's share in §9.)

Sampling the running release binary with gdb (36 stack samples across heights ~300-700): **32 of 36
samples (89%) were inside `chain_forge_state::jmt::rebuild_subtree` / `create_internal_node`**,
and the innermost frames in those 32 were BTreeMap `get` and key comparisons (`memcmp`) under
`NodeStore::get`. Only 4 of 36 were in `persist_state` (2 in the file write).

Cause (`chain-forge-state/src/jmt.rs`): `NodeStore::get` and `get_at` do
`for v in (0..=key.version).rev() { probe = NodeKey{version: v, ..key.clone()}; nodes.get(&probe) }`,
i.e. one allocation-and-BTreeMap-probe per version back to the version where that node was last
written. `rebuild_subtree` calls it for every unchanged sibling, so a commit costs O(depth x
current version) lookups, and in a tree where few accounts change per block almost every node is
old. `prune_before` exists but is never called, and cannot be used as a fix: unchanged nodes must
be found at their old versions.

Windows/BossKing 2026-11-02, same release profile (35 s): commit 18.6 / 33.5 / 59.9 / 134 / 266 ms at heights
25 / 50 / 100 / 200 / 300 (persist_state() 8.1 / 13.5 / 24.2 / 49.2 / 75.0 ms = 44% -> 28%); temp+fsync+rename
of the compact store 8.8 ms at height 300. Same linear shape as the sandbox, and FASTER at height 300 (266 ms
vs 503 ms). So the in-process release profile does not show a Windows penalty. The 6x slowdown seen in the
live loaded run (§8/§9: debug build, four node processes, real network) is therefore NOT yet attributed to
the tree lookup or to persistence; the tree share on Windows has not been sampled (gdb was only run in the
sandbox).

Not fixed here (state-store change; PERSIST-001 is profiling and design only). A fix must not
change any state root: it can be verified by running the existing state tests plus a differential
test (old lookup vs. indexed lookup over the same update sequence) asserting identical roots.
Candidate: a per-path index of the latest version (or latest node per path, with older versions
kept only for proofs/rollback), making `get` O(1).

Consequence for PERSIST-001: persistence is the second cost (whole-store JSON rewrite, ~14-20% of a
release commit at heights 300-600 and linear in height) and, separately, is not atomic (§11).

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

---

## NODE-TOKIO-1  A node panicked inside tokio's time driver and went silent (once)

**Status: OPEN — intermittent, seen once; cause UNKNOWN. Found 2026-11-02 in a Linux sandbox run of `validator_jail_live` on the branch of PR #58.**

During the JL-02..JL-03 wait (Dave deliberately killed), **Bob's node panicked right after committing block 97** and logged nothing afterwards:

```
thread 'tokio-rt-worker' panicked at tokio-1.54.0/src/sync/task/atomic_waker.rs:324:17:
assertion failed: old_state == WAKING
  3: <tokio::sync::task::atomic_waker::AtomicWaker>::take_waker
  4: <tokio::runtime::time::entry::StateCell>::fire
  5: <tokio::runtime::time::entry::TimerHandle>::fire
  6: <tokio::runtime::time::handle::Handle>::process_at_time
  ...  <tokio::runtime::scheduler::multi_thread::worker::Context>::park / run
```

With Dave down on purpose, only Alice and Carol remained (2 of 4, below quorum), so the chain **stopped at height 97** and the test reported "JL-03: Dave was never jailed (max missed seen 86%)". Alice, Carol and Dave logged no panic, and the disk was not full. The next sandbox run of the identical tree **passed** (JL-01..JL-09, 660.03 s, no panic). Of the 8 sandbox jail-run log sets still on that machine (different code states), 1 contains a panic; none of the Windows runs (jail ×3, integrity, delay) has shown one.

**What is and is not known.** The backtrace is entirely inside tokio's runtime (the time driver firing a timer on a parking worker); it contains no chain-forge frame, so it cannot be attributed to our code from this evidence. **Equally, tokio-only frames do not clear the application:** a primitive misused by our code or a dependency (for example a waker or timer handled in a way tokio does not permit) can fail an invariant inside the library, so the application is neither implicated nor excluded. The assertion is an internal invariant of tokio's timer state; it is a debug-build check (the sandbox and the live tests run debug builds). It could be a bug in tokio 1.54.0, or memory corruption by `unsafe` code elsewhere in the dependency tree; neither has been investigated or ruled out. It was not reproduced.

**Why it matters.** A validator node that dies or hangs on a runtime panic can stop a chain that is already at its quorum margin, and the process went silent without exiting loudly. **Not changed.** Suggested follow-ups, none done: check tokio's upstream tracker and changelog for this assertion; try a newer tokio; decide whether the node binary should abort the process on a runtime-thread panic (so a supervisor restarts it) instead of continuing; if it recurs, capture `RUST_BACKTRACE=full` and the node's state at the time. The test failure it caused was a false negative for `validator_jail_live`, not a defect in the jail logic.

