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

**Status: OPEN — found 2026-11-02 while scoping PERSIST-001; needs an owner decision on H0-3 scope**

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

**Status: FIXED ON BRANCH `feat/state-perf-jmt-index` (sandbox-verified; NOT merged; Windows regression pending). Originally found 2026-11-02 by sampling a release build (PERSIST-001 P-01).**

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

**STATE-PERF result (branch `feat/state-perf-jmt-index`, sandbox, release builds)**
`NodeStore` now keeps an index of the versions at which each path has a node; `get`/`get_at` binary-search it
instead of probing every version. `nodes`, serialization and the rebuild logic are unchanged.

Safety net, written and run against the ORIGINAL code first (commit d79c81f), unchanged afterwards:
- golden state roots at 12 checkpoints of a deterministic 2,000-version tree history (updates, deletions,
  new accounts) captured from the original implementation;
- every stored key probed at its own, neighbouring, current and random versions: the indexed result is the
  same stored node (pointer identity) as the original walk, also after `prune_before`;
- insert/update-only history: incremental root equals a one-batch rebuild (the restart-recovery shape);
- node level: 120 real blocks of transfers through execution, fees and the tree give byte-identical state
  roots at heights 0/9/24/59/119, deterministic run to run.
All of these pass on the optimized code. State crate 73 passed; execution crate 141 passed; node unit suite
280 passed with the one known unrelated failure (§7).

Live multi-node checks on the optimized build (sandbox, 4 real node processes): `validator_jail_live` JL-01..JL-09
PASSED (643 s) with state roots IDENTICAL to the pre-change runs at JL-01 (`51136494701f`), JL-06 (`eebbee537f59`)
and JL-09 (`33362db6f1e0`), including Dave replaying the whole chain from peers to the same state;
`validator_eviction_live` EV-01..EV-03 PASSED (95 s), same root as the pre-change sandbox run (`1f2b492f...`).
Windows regression of this branch: pending.

Tree-only release benchmark (12 accounts, 3 updates per version), microseconds per commit:
| Versions | Original | Indexed |
| --- | --- | --- |
| 100 | 49.7 | 35.9 |
| 1,000 | 303.7 | 40.1 |
| 5,000 | 2,461.9 | 41.4 |
| 10,000 | 7,353.5 | 36.9 |
| 20,000 | 21,565.4 | 29.6 |

End-to-end release commit profile (in-process 4 validators, 10 transfers/block, persistence on), median commit:
| Height | Before | After |
| --- | --- | --- |
| 100 | 78.4 ms | 29.9 ms |
| 300 | 503.0 ms | 104.1 ms |
| 600 | 1,152 ms | 176.5 ms |
What remains is persistence (persist_state() = 157 of 176 ms at height 600), i.e. PERSIST-001.

---

## §13  Tree root after deletions depends on history (not a function of the final content)

**Status: OPEN — pre-existing; found 2026-11-02 while building STATE-PERF's differential tests. NOT changed by STATE-PERF (it must reproduce today's roots). Needs an owner decision: fixing it changes state roots.**

Minimal counterexample on the ORIGINAL code (`find_first_nonreproducible_root`, ignored diagnostic):
upsert A, upsert B, delete A, delete B (tree empty), upsert C, upsert C, upsert A. The incremental root differs from the root
of a fresh tree built in one batch from the same final content {A, C}. Without deletions the two always agree (tested).
Likely mechanism: a delete marks nodes stale but does not write an explicit empty node, so the version lookup can
resurrect pre-deletion nodes.

Why it matters: `StateStore::rollback_checkpoint` removes an account a rolled-back transaction had created (the only
production deletion), and its comment says the root is a function of the leaves. Recovery rebuilds the tree in ONE batch
(`restore_snapshot`). If a history contained such a deletion, a node that restarted could compute a different root than
nodes that did not. Not reproduced end to end here; needs a focused test through `StateStore` and a decision. All nodes
that see the same operations in the same order agree with each other, so this is a restart/rebuild and history-dependence
risk, not a disagreement between healthy running nodes.
