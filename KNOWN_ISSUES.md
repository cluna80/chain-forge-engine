# Known Issues

Issues discovered during integration testing, recorded here so they survive
session boundaries.  Each entry has a short title, the symptom, the root cause
(where known), and the fix needed.

---

## §1  Genesis stake underflows slash penalty (BME burn fails silently)

**Symptom**

During the adversarial equivocation test, Alice's node logs:

```
WARN  equivocation detected — validator tombstoned validator=qcb1alice slashed=50000000
WARN  BME burn failed; tombstone applied but tokens not burned
      validator=qcb1alice burn_uqcb=50000000
      error=insufficient balance: account qcb1alice has 5000000 but 50000000 required
```

The tombstone is correctly applied, but the burn (the economic penalty) is a
no-op because the genesis stake (5 000 000 uqcb = 5 UQCB) is smaller than the
configured slash penalty (50 000 000 uqcb = 50 UQCB).

**Root cause**

`tests/devnet/genesis-4node.json` gives each validator 5 000 000 uqcb.
The slashing module's `EQUIVOCATION_SLASH_RATE` (or equivalent constant) is
calibrated for a much larger stake.

**Fix needed**

Either:
- Raise the genesis stake to at least 10× the max slash amount (e.g. 500M uqcb
  per validator), or
- Lower the slash penalty to be a percentage of actual stake rather than an
  absolute amount.

The correct long-term answer is percentage-based slashing (e.g. 10% of bonded
stake), which scales correctly regardless of genesis amounts.

**Affects**

`chain-forge-node/tests/devnet/genesis-4node.json`,
`chain-forge-slashing/src/lib.rs`

---

## §2  Liveness slashing misfires during startup gossip warmup

**Symptom**

Immediately after the 4-node devnet starts, nodes jail each other for liveness
failures before the network has fully formed:

```
WARN  liveness failure — validator jailed validator="qcb1carol" missed_pct=40 slashed=1000000
WARN  liveness failure — validator jailed validator="qcb1dave"  missed_pct=60 slashed=1000000
WARN  liveness failure — validator jailed validator="qcb1alice" missed_pct=70 slashed=1000000
```

These fire in the first few seconds, before all nodes are connected and
participating in consensus.

**Root cause (likely)**

The liveness window begins counting rounds from block 0, before any validator
has had a chance to join the gossip mesh.  The first several rounds look like
"missed" because the P2P connections haven't formed yet.

**Fix needed**

One of:
1. **Warmup grace period**: Do not begin liveness enforcement until a node has
   participated in at least N rounds (e.g. N=10) or until a configurable
   `liveness_start_height` has been reached.
2. **Per-validator first-seen tracking**: Start each validator's liveness window
   from the first round where they sent a valid vote, not from genesis.

Option 2 is more correct for permissionless validator onboarding (Phase 4+).
Option 1 is simpler and acceptable for the current fixed-validator devnet.

**Risk**

If all four validators jail each other before quorum stabilises, the chain
halts at startup.  Current tests pass because the jailing happens after enough
blocks are committed, but this is not guaranteed as block times or network
latency change.  This will almost certainly manifest as a cold-start failure
when scaling to 7+ nodes or running on real hardware with startup latency.

**Affects**

`chain-forge-slashing/src/lib.rs` (liveness window logic),
`chain-forge-consensus/src/lib.rs` (participation tracking)

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
