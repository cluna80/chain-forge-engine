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

**Symptom**

`adversarial_garbage_signature` passes but does NOT verify that garbage
signatures are rejected.  In Phase 0, `verify_vote_signature` takes a
pass-through path when genesis has no `public_key` fields, so the garbage-sig
vote is silently accepted.  The chain remains safe only because a single
injected vote cannot manufacture quorum.

**Status**

The test is marked `#[ignore]` so it does not count as coverage.  It is
intentionally left visible in the test suite as a TODO marker.

**Fix needed**

1. Add `public_key` fields (Ed25519 or equivalent) for each validator in
   `tests/devnet/genesis-4node.json`.
2. Update `verify_vote_signature` to actually verify against those keys.
3. Replace the Phase-0 pass branch in the test with an assertion that the
   garbage-sig vote is rejected (grep logs for "invalid signature" or the
   equivalent error variant).
4. Remove the `#[ignore]` attribute.

**Affects**

`chain-forge-node/tests/adversarial_gossip.rs`,
`chain-forge-node/src/node.rs` (`verify_vote_signature`),
`tests/devnet/genesis-4node.json`

---

## §4  Duplicate-attestation guard not directly exercised in tests

**Symptom**

The `attestation_guard_live` test submits a second `Attest` from `qcb1bob`
with `nonce=1`.  The tx is rejected at execution time with:

```
"error": "nonce mismatch: expected 0, got 1"
```

The rejection is correct (the tx fails), but it hit the **nonce guard**
before reaching the duplicate-attestation guard.  This means the
duplicate-attestation guard in `IdentityStore::attest()` has not been
directly exercised by the integration tests.

**Root cause**

In the test, the first `Attest` uses `nonce=0` and the duplicate also uses
`nonce=0` would re-use the same nonce, so `nonce=1` was chosen to make the tx
distinct. But `nonce=1` is invalid because Bob's account nonce is still `0`
after the first attest (the account nonce advances per-committed-tx, and Bob
sent the first attest at nonce=0). The nonce guard fires first.

**Fix needed**

To directly exercise the duplicate-attest guard, the test needs to:
1. Confirm the first attest landed (poll `GET /api/tx/{first_attest_id}`,
   assert `success: true`).
2. Read Bob's committed nonce from `/api/accounts/qcb1bob` and use it for
   the duplicate tx.
3. Submit the duplicate with the correct nonce.
4. Assert `success: false` with an error containing "duplicate" or "already
   attested" rather than "nonce mismatch".

This is a test coverage gap, not a code bug.  The nonce guard provides
defense-in-depth (the duplicate tx cannot slip through), but the
attestation-specific guard is not separately confirmed live.

**Affects**

`chain-forge-node/tests/attestation_live.rs` (`attestation_guard_live`,
phase 6),
`chain-forge-identity/src/lib.rs` (`attest()` duplicate guard)
