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

**Status: OPEN for the default storage (v1); ADDRESSED in the experimental storage v2 (default off, test-only; #64, #65, Windows-validated for crash recovery, not yet for production use).** Original status: OPEN — pre-existing; found 2026-11-02 while measuring a loaded chain. Not fixed by P-02a (#48): every block still rewrites and fsyncs all eight files, and the cost has not been re-measured. PERSIST-001 P-02b is the planned fix.**

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

**Status: FIXED by RPC-TX-1 (PR #91, merge `486bd22`, head `73df50d`, 2026-11-05). Linux and Windows evidence below. This closes §10 only; it does NOT close the public-RPC security gate (see "Not covered" below). Text after the evidence block is the original finding (found 2026-11-02, two load tests stalled at exactly 101 txs per account).**

**Fix.** The nonce cache is now derived from authoritative account state (`refresh_nonce_cache`: last consumed nonce = `account.nonce - 1`, `u64::MAX` only for an account that has consumed none) after every executed block on **both** execution paths (`commit_block` and `propose_block`) and after a restore. Two further defects found while fixing it, both fixed by the same change: `propose_block` never updated the cache, and the cache was never rebuilt after restore (it stayed at the genesis sentinel, so a replay of an already-committed nonce was accepted at ingress); the start-up seed also used `account.nonce` instead of `account.nonce - 1`. Execution is unchanged: it still requires `tx.nonce == account.nonce` on every node. The same PR bounds the API queue (genesis `mempool_size`, 5,000 if 0; full gives HTTP 503), makes identical resubmissions idempotent, applies the O8 bounds at ingress, and adds a `state` response field (`queued_for_validation` | `rejected` | `queue_full`); the legacy `status` values are unchanged (owner decision 2026-11-05).

**Evidence.**
- Failing before (commit `0523c4f`, tests plus plumbing only, Linux): 5 of 6 new `rpc_tx1_*` tests failed, including `the API must still accept nonce 101 (cache last = 18446744073709551615)` and, after a restart, the cache holding the sentinel while the account nonce was 3. The concurrency test passed before and after (regression guard).
- After (`73df50d`), Linux: 6 of 6 pass; node unit suite 405 passed, 0 failed, 6 ignored; live suites `mldsa_tx_live` 1/1, `mldsa_only_accounts_live` 1/1, `h0_5_atomicity_live` 1/1, `attestation_live` 2/2. Four mutation checks (nonce refresh made a no-op, no capacity check, no duplicate detection, no ingress O8 guard) each made the matching new tests fail.
- After (`73df50d`), Windows (BossKing, MINGW64): node unit suite 405 passed, 0 failed, 6 ignored (138.50 s); `mldsa_tx_live` 1/1 (10.76 s), `mldsa_only_accounts_live` 1/1 (20.47 s), `h0_5_atomicity_live` 1/1 (41.20 s), `attestation_live` 2/2 (30.51 s). The filtered `rpc_tx1_` run was not pasted separately; the six tests are part of the 405.

**Not covered / still open.** The broader 24-suite live sweep remains open, so other live suites have not been re-run against this change. The public-RPC gate is not closed: no authentication, TLS, connection cap or rate limit; debug and wizard routes compiled into release builds; unbounded list endpoints serialized under the shared explorer lock; unauthenticated `gc-receipt` / `pocd/submit` writes; `verify_delegated` can answer `"verified"` for a structure-only check (RPC audit, PR #90). ML-DSA signatures are still verified at execution, not at ingress; whether a failed-signature transaction is charged a fee was not established. Gossip-received transactions still reach `submit_tx` without a per-peer limit.

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

**Status: FIXED (2026-11-04, PR #72, merge `db3f418`, head `e51b690`): `Cargo.lock` moves tokio 1.54.0 to 1.54.1. Root cause: an upstream tokio defect, not chain-forge code.** Found 2026-11-02 in a Linux sandbox run of `validator_jail_live` (PR #58's branch): Bob's node panicked after committing block 97 and went silent; the chain stopped (2 of 4 validators left) and the test reported a false "Dave was never jailed". The panic was `assertion failed: old_state == WAKING` at `tokio-1.54.0/src/sync/task/atomic_waker.rs:324`, called from `StateCell::fire` and `process_at_time` on a `tokio-rt-worker` thread. One occurrence in about eight sandbox log sets; none in the Windows runs.

**Root cause.** tokio 1.54.0 (now **yanked**) removed the runtime handle from timers (#8458). Upstream restored it in 1.54.1 (tokio-rs/tokio#8692, "revert 'remove the runtime handle from timers'", 2026-10-21), whose description documents the timer-driver use-after-free race. In 1.54.0 the driver marks a timer fired (`entry.rs`, state stored before `take_waker`), while `Interval::poll_tick` can observe that state and drop the timer through `reset_without_timer` ("the internal timer is elapsed") without synchronising with the driver. The driver can then touch freed memory. The node's run loop is a `select!` over two `tokio::time::interval`s on a multi-thread runtime, the pattern that triggers it. Our crates contain no `unsafe`, custom wakers or custom futures.

**Evidence.** A standalone program (no chain-forge code) reproduces the identical assertion and frames on 1.54.0 in 3 of 3 45-second runs and survives 3 of 3 runs on 1.54.1. **The assertion is a `debug_assert!`, so release builds do not report it, but the race is a use-after-free in any build: a release node on 1.54.0 would corrupt memory silently.** The lock edit changes only tokio's version and checksum (2 lines; tokio's own dependency table is identical, and a plain `cargo update --precise` also rewrote unrelated edges such as `quinn`'s `socket2`, so it was not used). Regression guards: `chain-forge-node/tests/tokio_timer_regression.rs` has a normal test that fails if `Cargo.lock` resolves tokio 1.54.0 (newer versions allowed) and an ignored 30 s stress test that fails on any process panic (worker-thread panics included, via a panic hook), any task that panics or ends early, and any task that stops making progress. **Validation:** Linux: on 1.54.0 the stress test hits the assertion and the process aborts; on 1.54.1 both tests pass; unit suite 398 passed / 0 failed / 2 ignored. **Windows (BossKing) at `e51b690`:** both tests pass (30.00 s), unit suite 398 passed / 0 failed / 2 ignored (the checkout also held unrelated modified Android Gradle files, not part of the PR).

**Limitations.** A finite stress run cannot prove every concurrency race absent; the upstream revert is the main assurance. On 1.54.0 the abort ends the run before the test's own `JoinHandle` and progress checks can report, so those are verified on passing runs only. That the single sandbox panic was exactly this interleaving is not proven, only the same assertion in the same code path. Earlier Linux and Windows evidence (including H0-3b) ran on tokio 1.54.0. **Open decision, separate from this fix:** whether the node should abort the process on a runtime-thread panic so a supervisor restarts it (`panic = "abort"` or a panic hook); not changed.

---

## LIVE-MLDSA-KEYS-1  Five live suites failed since 2026-10-29: static genesis ML-DSA keys vs per-process random test keys

**Status: FIXED (PR #75, merge `9738341`, head `2f5ffc1`, 2026-11-04; Linux 5/5 and Windows 5/5 passing). Found 2026-11-04 while validating S1 (PR #74); the five suites fail identically on unmodified `main` `61e02c6`.** `dis_002a_key_rotation_live`, `dis_002b_migration_live`, `dis_003a_policy_lifecycle_live`, `dis_003c_replay_attack_live` and `mldsa_tx_live` all failed at their first transaction with "ML-DSA signature verification failed" (each within about 9 s, on Linux and Windows).

**Root cause.** Commit `721c166` (2026-10-29, "production keys come from the OS RNG, never seeded keygen") made `MlDsaScheme::generate_keypair(seed)` return one random key per seed per process. These tests sign with seeded keys, but their static genesis files pre-bind the account's ML-DSA public key (the ML-DSA account-ownership fix binds named accounts in genesis), so a freshly started test process can never sign for those accounts. The suites that kept passing (`dis_002b_recovery`, `dis_003b`, `dis_003d`, `dis_003e`) already write a patched genesis with the live key.

**Fix (tests only; no node, genesis-file or protocol change).** New `chain-forge-node/tests/common/live_genesis.rs`: `with_ml_dsa_keys(template, tag, [(address, seed)])` copies the genesis to a temp file with each listed account's `public_key` replaced by the key the test signs with (and panics if the account is missing or has no pre-bound key, so a wrong mapping cannot pass silently). The five tests call it once per process: `dis002a` qcb1user/SEED_A; `dis002b` qcb1pilot/SEED_A; `dis003a` qcb1pilot/SEED_A; `dis003c` qcb1pilot/SEED_PILOT and qcb1victim/SEED_VICTIM; `mldsa_tx` qcb1sender/`SENDER_SEED`.

**Consequence for earlier evidence.** The ROADMAP's earlier Windows ✅ for `mldsa_tx_live` (P0-3..P0-6) and the DIS-002A/002B/003A/003C suites predate 2026-10-29. **Re-confirmed on Windows (BossKing) at `2f5ffc1`, 2026-11-04:** all five pass (dis_002a 23.2 s, dis_002b_migration 21.1 s, dis_003a 26.9 s, dis_003c 27.2 s, mldsa_tx 13.0 s). They also pass on S1 (`5e4d872`) combined with this fix.

## DIS-002B-B03-RACE  `dis_002b_migration_live` failed intermittently at B-03 (test race, not a node defect)

**Status: FIXED (PR #79, merge `9c6c91c`, head `1bda03f`, 2026-11-04; Linux 20 of 20, Windows 5 of 5).** Symptom: "B-03 FAIL: attestation_count changed from 0 to 1" in about 10 to 15 percent of runs (3 of 20 on `c501a7b`, 2 of 20 with the S2 step 2 change; no difference between them). Cause: the test did not establish a stable attestation baseline before rotating. Its convergence wait checked only `registered`, which was already true everywhere, and the "before" identity snapshot was read from Alice's node while Alice had not yet committed the block containing Bob's attestation (she commits it 26 to 64 ms after Bob). Fix: a bounded wait until all four nodes show the attestation (`attestation_count >= 1`, `qcb1bob` in `attested_by`) before the snapshot, plus a baseline assertion; the invariant (rotation must not change the tier or the attestation record) is unchanged. Test-only; no node, consensus, identity, crypto, transaction or persistence code changed. Twenty clean runs are strong practical evidence, not proof the race is gone.

## ACCT-LEAF-1  The account Merkle leaf does not commit several recovery-related account fields

**Status: OBSERVATION, INVESTIGATED READ-ONLY (2026-11-04); design decision needed; no code changed.** Found while recording the S0 baseline; investigated on Qattice `main` `64138a7`. The leaf (`AccountState::to_leaf_bytes`) commits address, nonce, tier, balances, `pk=`, `escrow=`, a summary `recovery=t{threshold}/{guardian_count}/{enrolled_at_key_version}/pid{policy_id}` and `pgen`. It does NOT commit: `key_version`; the whole `pending_recovery` record (new key, scheme, key_version, heights, policy_id, `cancelled`); the guardian PUBLIC KEYS; `IntrinsicCharm` beyond the tier string. No other commitment exists (the recovery transitions write no state-KV markers; a block carries only `state_root`). Measured with a scratch probe (not committed): the root is unchanged when `key_version` changes, when the guardian keys are replaced (same count and threshold), when the pending key or `activation_height` is replaced, when `cancelled` flips, and when the pending record is removed; controls (`policy_id`, `policy_generation`, `public_key`, removing the policy) do change it; a tampered JSON round trip restores with the same root. Transition table: only `RotateAccountKey`, `EnrollRecoveryPolicy`, `UpdateGuardianPolicy`, `RevokeRecoveryPolicy`, `RecoverAccountKey` (indirectly, by clearing the policy) and the sweep activation (through `public_key`) move the root; `CancelRecovery` moves it only through the sender's nonce.

**Assessment, not an exploitability claim:** execution is deterministic, so honest nodes do not diverge because of this; a wrong value on one node surfaces only when a dependent transaction or the sweep uses it (late detection, not absence). The real gaps are restart and restore integrity (the manifest root check cannot detect edits of these fields), no state proof of the key version, guardian set or pending recovery for light clients, and that a bug mutating only these fields is invisible to root comparison. No bypass of the recovery rules was found; persistence-write and network attack paths were not examined beyond reading.

**Options (each changes state roots; separate design and compatibility review required):** A. a versioned leaf that also commits `key_version`, a hash of the guardian set, a hash of the pending record and the full charm state, with an activation rule for existing devnets (for a fresh mainnet genesis it can apply from block 0 at no migration cost); B. a separate per-account state-KV commitment; C. leave the leaf and document the limitation plus a restore-time check. Compatibility risks: existing devnet data directories would fail the manifest root check after an unflagged upgrade, persisted snapshots and `storage_v2` logs record the root, and every golden corpus (S0 baseline, account leaf, S2 execution) must be re-recorded deliberately. Recommendation: settle before mainnet genesis. Full report: the ACCT-LEAF-1 investigation notes of 2026-11-04.

## EVICT-ROOT-1  The eviction live test's printed state root is not a cross-run constant

**Status: OPEN (documentation corrected 2026-11-03; no code defect found). Found while investigating a Linux/Windows root difference (`48d58b5f…` vs `1f2b492f…`).**

`validator_eviction_live` prints the state root at whatever height it happens to finish (EV-03). That root depends on the heights at which Eve's transactions land and on epoch-boundary accounting, both of which vary with timing, so two correct runs can print different roots.

**Evidence (Linux sandbox, same binary, same genesis, three consecutive runs, per-height roots dumped):** run A finished at height **32** with root `48d58b5f…`; runs B and C finished at height **33** with root `1f2b492f…`, and their per-height roots already differ from run A's from height 5 onward (different blocks carried the transactions). Run A's root equals the Windows value recorded in the ROADMAP; a Windows run on the v2 storage branch (2026-11-03, `ca4d0e2`) also finished at height 32 with `48d58b5f…`. So there is no evidence of a platform difference, and equal roots from different runs prove determinism only when the final heights are equal.

**What still holds:** EV-03's real assertion, that all four nodes report the same root within one run, passed in every run (v1, v2, `main`, Linux and Windows).

**Consequences:** earlier ROADMAP wording ("same state root `48d58b5f…`") has been softened. For regression comparisons use (a) the same final height, or (b) the per-height roots; `validator_eviction_live` now prints `final heights sampled` and, with `CF_EVICT_DUMP_ROOTS=<file>`, writes every height's root and the genesis file's size and CR count (change on the storage-v2 PR #65, not yet on `main`). The jail test's roots (`51136494701f`, `eebbee537f59`, `33362db6f1e0`) were identical across all recorded runs and platforms because its transactions are submitted at deterministic points.

---


## H0-3b  Reconciliation against the acceptance criteria (2026-11-04) — CLOSED (owner, 2026-11-04; supersedes the table statuses below)

**Update after PR #70 (merge `ed451d3`, test head `5d84dba`):** the section 6 component sweep closes the one partial cell. Windows at `5d84dba`: sweep passed, unit suite 398 passed / 0 failed / 2 ignored. All five section 11 criteria and all ten section 6 rows are satisfied; criterion 1 is no longer "owner to confirm". H0-3b acceptance is **not** storage v2 production readiness: v2 stays default-off, no migration, no default flip. P02A-W1 stays unexplained. The Windows trees also held unrelated modified Android Gradle files. The table below is the pre-#70 record.

Criteria are `docs/persist-001-p02-design.md` section 11. No new gates are added here. Status uses only evidence recorded in this repository.

| # | Criterion | Status | Evidence / what remains |
| --- | --- | --- | --- |
| 1 | Torn-file matrix: no scenario reaches genesis from a non-NEW directory | Evidence recorded, owner to confirm the matrix is complete | Live C-02..C-05, C-08, C-10 passed on Windows at `b38bc0c`; P-02a unit and live tests; v2 loader refusal and I/O-failure injection tests (PR A). A crash inside a single write or fsync and other filesystem-level torn behaviour are not exercised; the owner retained the existing requirement, so the owner must say whether the existing matrix covers it. |
| 2 | Crash injection at every section 5 boundary recovers to h-1 or h | Satisfied on both formats (Windows) | `storage_v2_live` (8 passed at `b38bc0c`): process abort at each of five commit boundaries, SIGKILL at heights 5/15/30, and guard-window crashes, on v1 and v2; every restart resumed at the committed height, roots agreed. Model-based commit/crash/restart test on both formats. |
| 3 | Restart-under-load consistency on Windows and Linux | Satisfied | C-01 (state preserved across SIGKILL; 5/5 repeats) and C-07 (four nodes converge) on Windows and Linux; four-node SIGKILL rounds with a transaction feeder. |
| 4 | Migration of an existing devnet directory succeeds, or refuses with the explicit error | Satisfied by the refusal branch | v1 directories are refused by v2 nodes and the reverse with the directory untouched; legacy-layout migration is P-02a. PR 3 (explicit v1 to v2 migration) is **not authorised and not started**. |
| 5 | KNOWN_ISSUES and ROADMAP updated; ROADMAP marks done only after developer's Windows confirmation | Windows confirmation recorded in this update | The checkmark itself is the owner's decision. |

**Unsatisfied, explicitly deferred or documented (not new gates):** P02A-W1 stays unexplained (6 clean C-01 runs earlier plus 5 at `b38bc0c`; no further repeats for now); physical power-loss on Windows is untested (documented limitation, not required); two-node outage and a live kill exactly between a guard write and the block commit are unit-tested only (deferred); sharing-violation retries deferred (fail closed); `--reset-data` deferred; v2 default activation and PR 3 not authorised. The proposal-signing guard is accepted by the owner.

## PERSIST-HALT-1  A persistence failure does not stop the validator from signing at the next height

**Status: FIXED in PR B (merged `540f3ef`, 2026-11-04; Linux-validated; Windows-validated at `b38bc0c`: unit 397/2 ignored, `storage_v2_live` 8, H0-3 12/12). Found by the H0-3b gap analysis; reproduced on BOTH storage formats by two tests that were first committed `#[ignore]`d (PR A) and are now normal regression tests.**

`commit_block` returns `Err("FATAL: snapshot write failed after commit — halting consensus to prevent double-signing on restart…")` when persisting block h fails, and the design (D1: no vote or proposal for h+1 until h is durable; "a failed write halts consensus") relies on that. But every caller on the multi-node path only **logs** the error and carries on: the engine's `Commit` action, the deferred-proposal commit, the quorum-via-own-vote and quorum-via-peer-vote commits, and the sync replay (`node.rs`, `drive_consensus` and `handle_event`). Nothing records the failure, and `cast_engine_vote` and `sign_and_register_own_proposal` do not check one. Only the single-node devnet path stops (`running = false`).

**Reproduction (two tests, `node::tests::h0_participation::a_persistence_failure_stops_the_validator_signing_at_the_next_height_v1` and `_v2`, run with `--ignored`):** a validator commits block 0, persisting block 1 fails (injected at `manifest_written`), the network moves on, and the validator **signs at height 2** (`sign_guard.last = (2, 0, 2)`) on both formats.

**Impact:** not an equivocation (the guard is made durable before any signature, and a restart abstains until it reaches the guard height), but it breaks the documented D1 rule: a validator whose disk is failing keeps voting and proposing from state it has not made durable, and after a crash it restarts behind its own guard (a liveness cost, bounded by sync). **Fix (PR B):** a one-way `persistence_failed` latch set by `commit_block` (and the single-node commit path) on any persistence error. While it is set the node: signs nothing (the vote and proposal entry points, the nil-vote paths and, as a safety net, `sign_vote` / `sign_proposal` themselves leave no signature); commits nothing (`commit_block` refuses); ignores consensus input (`handle_event` drops messages; `consensus_tick`, `drive_consensus` and round catch-up return; the heartbeat arm does nothing); reports `is_running = false`; stops the event loop; and `main` exits with status 2. There is no in-process way to clear it: only a new process, which re-runs the full recovery checks and the signing-guard consistency rules (a guard ahead of the committed state means abstain). The failure is local and is not turned into a protocol penalty. Tests: `after_a_persistence_failure_no_signing_or_commit_path_works`, `the_event_loop_stops_after_a_persistence_failure`, `restart_after_a_persistence_failure_reverifies_and_abstains_until_caught_up`, `a_v2_log_append_failure_latches_the_node`, `a_non_persistence_commit_refusal_does_not_latch`, and the two original demonstrations. A failed `commit_block` for a non-persistence reason (state divergence) deliberately does not latch.

---


## PERSIST-HALT-1b  A failed signing-guard write must stop the validator signing (owner decision 2026-11-04)

The first PR B latch covered a failed **block** persist. A failed **signing-guard** write (`persist/consensus_signing.json`) only withheld that one vote or proposal; the next message could be signed. The guard is the consensus safety boundary, so any failed guard write now latches the same one-way, process-local `persistence_failed` state: all vote, proposal, commit, tick and event-loop paths refuse (including `sign_vote`/`sign_proposal`, so no caller can bypass it), `status.is_running` becomes false, `main` exits with code 2, and there is **no automatic recovery**: a new process must start on a usable data directory, re-verify the guard and the committed chain state, and only then sign. The latch never jails the validator and never changes voting power (a local storage fault stops participation; it is not misbehaviour). v1 and v2 share the same code path. Tests: `a_failed_signing_guard_write_for_a_vote_latches_the_node_and_stops_all_signing`, `a_failed_signing_guard_write_for_a_proposal_latches_the_node`, `successful_guard_writes_never_latch_and_survive_a_restart` (both formats; mutation-checked at both latch sites). Linux-validated; Windows-validated at `b38bc0c` (merged `540f3ef`, 2026-11-04).

## PERSIST-DIR-1  A node given an unusable `--data-dir` ran memory-only (v1)

`main.rs` logged a warning and continued without persistence when `set_data_dir` failed on the default storage, so a restarted validator could sign with no signing guard and no committed state. **Fixed in PR B:** it now logs `FATAL` and exits non-zero (v2 already refused). Tests: `v1_/v2_a_node_with_an_unusable_data_dir_refuses_to_start` (`storage_v2_live`). Linux-validated; Windows-validated at `b38bc0c` (merged `540f3ef`, 2026-11-04).

## PERSIST-APPEND-1  A failed log append can be buried by a later append

**Status: FIXED in PR B (merged `540f3ef`, 2026-11-04; Linux-validated; Windows-validated at `b38bc0c`: unit 397/2 ignored, `storage_v2_live` 8, H0-3 12/12). Found 2026-11-03; low severity (defence in depth); the failing test was first committed `#[ignore]`d (PR A) and is now a normal regression test.**

If a `BlockLog::append` fails midway (full disk, failing device), the segment keeps the torn bytes while the in-memory tail does not advance. A later append on the same handle writes after those bytes, so the log no longer verifies and a restart rejects it as damage inside the committed region. Today this cannot happen only because a persistence error is supposed to stop the node (see PERSIST-HALT-1, which is not yet true). Test: `blocklog::tests::a_failed_append_followed_by_another_append_must_not_leave_an_unverifiable_log` (`--ignored`). **Fix (PR B):** a failed append (or a failed segment creation) **poisons** the handle: every further append returns `Poisoned`, so a later append can never bury the torn bytes. The handle also makes a best-effort attempt to cut the segment back to the end of the last complete record it had already written (never removing a record that was appended successfully; an append-only handle may not be truncatable on every platform, so correctness does not depend on it); recovery against the committed checkpoint is what restores the exact bytes and re-opens the log. The node treats the append error as a persistence failure (PERSIST-HALT-1), so cleanup is never permission to continue. Tests: `a_failed_append_poisons_the_handle_keeps_committed_records_and_recovery_cleans_up`, `a_failed_append_followed_by_another_append_cannot_leave_an_unverifiable_log`, `a_v2_log_append_failure_latches_the_node`.

---

## H0-3-FIXTURE-1  The H0-3 live tests C-01 and C-07 could not start after DIS-003E (#45)

**Status: FIXED in PR A (merged `2ed0e77`; Linux 12/12; Windows 12/12 at `b38bc0c`, 2026-11-04).** `genesis-1node-crash.json` and `genesis-4node-crash.json` lacked `execution.allow_zero_recovery_timelock`, so the node refused to start ("DIS-003E … allow_zero_recovery_timelock is not set"). On `main` the H0-3 live suite was 10 passed, 2 failed (C-01, C-07); with the flag added to both fixtures it is 12/12 on Linux. The earlier Windows "12/12" runs predate #45. A Windows re-run is required before this counts for H0-3b; P02A-W1 (the unexplained C-01 anomaly) stays open and is investigated through that re-run.

---

## GUARD-ID-1  The signing guard file carries no chain or genesis identity

**Status: OPEN — informational; predates this work.** `consensus_signing.json` is not bound to a `chain_id` or genesis hash, unlike the generation manifest. A guard copied between data directories can only make a node more conservative (it refuses or abstains), so no unsafe case is known, but the binding is absent. Not changed.
