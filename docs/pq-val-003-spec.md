# PQ-VAL-003 — ML-DSA-65 Consensus Key Rotation, Scheme Downgrade, and Revocation

**Status:** Specification — locked for implementation  
**Depends on:** PQ-VAL-002 (ML-DSA-65 activation, R3 power lift, EDA rollback)  
**Blocks:** PQ-VAL-004 (degraded-network Phase D testing)  
**Baseline:** `main` @ merge of PR #4 (PQ-VAL-002 implementation)

---

## Purpose

PQ-VAL-002 activated ML-DSA-65 in the consensus path and introduced the emergency deprecation (EDA) rollback. PQ-VAL-003 closes the validator key lifecycle: a validator must be able to rotate its ML-DSA key to a new ML-DSA key, downgrade from ML-DSA to classical (Ed25519), and have the power-gate and vote-verifier respond correctly in each case. It also hardens the already-implemented duplicate-key and cross-validator PoP-replay protections to cover the rotation path specifically.

**This milestone makes the ML-DSA-65 key lifecycle complete.**

---

## Non-negotiables (carry forward)

- Mandatory validator-key enforcement, personhood gating, and signature verification are not weakened.
- Validator eviction policy, quorum rules (2/3+1), and personhood semantics are unchanged.
- Existing operator keys and devnet data are preserved. The devnet is not reset.
- The classical (Ed25519) path remains fully operational throughout and after this milestone.
- No speculative implementation — all code follows from this locked spec.

---

## Requirements

### R1 — ML-DSA key rotation (ML-DSA → new ML-DSA)

A validator with a registered ML-DSA-65 consensus key may replace it with a new ML-DSA-65 key by submitting a second `TxBody::RegisterValidatorKey` with `scheme = "ml-dsa-65"` and a fresh key + PoP. The executor verifies:

1. The sender's account signature authenticates the tx (standard account-key auth).
2. `proof_of_possession` is a valid ML-DSA-65 signature over `validator_key_registration_signing_bytes_v2(chain_id, sender, new_pubkey)`, made with the **new** private key. The old PoP is not re-verified.
3. The new key is not already registered to a different validator (duplicate-key guard).

On success:
- The old key is removed from the `by_pubkey` index in `ValidatorRegistry`.
- The new key replaces it in the registry under the same validator id.
- The `scheme` field in `KeyBundle` stays `"ml-dsa-65"`.
- The validator's `voting_power` in the `ValidatorSet` is set to 0 at the moment of rotation; the existing `pop_verified` refresh loop in the next block will restore it (bond + personhood still present, scheme still `"ml-dsa-65"`, activation epoch still in effect).
- Votes signed with the old ML-DSA key are immediately invalid (`verify_consensus_vote` looks up the current registered key; the old key is gone).

### R2 — Scheme downgrade (ML-DSA → classical / Ed25519)

A validator may rotate from ML-DSA-65 to a classical Ed25519 key by submitting `TxBody::RegisterValidatorKey` with `scheme = "classical"` (or omitting the scheme field, which defaults to classical). The PoP is a classical Ed25519 signature over `validator_key_registration_signing_bytes(chain_id, sender)` (V1 format) or `validator_key_registration_signing_bytes_v2(chain_id, sender, pubkey)` (V2 format, `pop_version = 2`).

On success:
- The `scheme` field in `KeyBundle` changes from `"ml-dsa-65"` to `"classical"`.
- The old ML-DSA key is removed from the `by_pubkey` index.
- The classical key is registered under the same validator id.
- The next `pop_verified` refresh loop restores `voting_power` without waiting for the PQ activation epoch (classical validators are never R3-gated).
- `verify_consensus_vote` for this validator will now require scheme `"classical"` and an Ed25519 signature; an ML-DSA vote from this validator is rejected (key mismatch, wrong scheme).

This path is the expected recovery action for validators after an EDA rollback: the chain continues under classical consensus and the validator re-joins immediately with an Ed25519 key.

### R3 — Duplicate key blocked across rotation

After a key rotation, the old key is released from the `by_pubkey` index. A *different* validator may now register that old key for themselves (it is no longer bound). However:

- A validator may NOT register a key that is currently bound to a different validator, even during a rotation attempt.
- The guard fires before the PoP is verified — the tx fails at Guard 0 (duplicate-key check) without touching crypto.

### R4 — Cross-validator PoP replay blocked on rotation

A PoP is bound to `(chain_id, sender_address, consensus_pubkey)` via the V2 signing message. A rotation tx from validator B that carries a PoP originally produced by validator A (sender = A) is rejected because `sender` in the tx is B but the PoP message binds to A. The signature verification fails even if the PoP bytes are cryptographically valid.

This is a property of the existing V2 PoP format; PQ-VAL-003 adds explicit tests to confirm it holds on the rotation path.

### R5 — Vote rejection after key rotation (old key inert)

After a validator rotates its ML-DSA key, `verify_consensus_vote` looks up the validator's *current* registered key. A vote signed with the old (pre-rotation) ML-DSA private key is rejected because the stored public key no longer matches. The verifier does not maintain a history of old keys.

### R6 — Power zeroed at rotation, restored in next block

At the moment of rotation (within the block that includes the `RegisterValidatorKey` tx), the node's `commit_block` / `propose_block` post-execution hook zeros the validator's `voting_power` (same mechanism as key registration in PQ-VAL-001). The existing `pop_verified` refresh loop in the *next* block restores power if all gates pass (bond, personhood, scheme-appropriate epoch). This means there is a one-block gap in voting power during key rotation — this is correct and expected.

### R7 — EDA does not clear key registrations

After `EmergencyDeprecateAlgorithm("ml-dsa-65", ConsensusSignatures)` executes:
- ML-DSA validators have their `voting_power` re-zeroed (already implemented in PQ-VAL-002 R4).
- Their registry entries (`scheme = "ml-dsa-65"`, key bytes) are **not** cleared.
- If PQ consensus is later re-activated via a new `ActivatePqConsensus` tx, the ML-DSA validators' power is restored in the next `pop_verified` refresh sweep — no re-registration required.
- A validator that wants to resume voting *before* re-activation must rotate to a classical key (R2).

---

## Implementation scope

### chain-forge-node/src/node.rs

- **R1/R2/R5/R6**: The existing `RegisterValidatorKey` mirror loop (at post-execution in `propose_block` and `commit_block`) already fires on any successful `RegisterValidatorKey` tx, regardless of the scheme. It calls `register_consensus_key_with_scheme`, which drops the old key from `by_pubkey` and writes the new key. No new tx variant needed — rotation reuses the existing tx.
- **R6**: Add explicit test confirming that `voting_power` is 0 immediately after the rotation block and > 0 after the *next* block.
- **R7**: Add test confirming that ML-DSA key registry entries survive EDA and are usable after re-activation.

### chain-forge-execution/src/lib.rs

- No new tx variants.
- No execution logic changes for rotation — `RegisterValidatorKey` handling already supports re-registration (rotation) of existing validators.
- Confirm (via test) that the duplicate-key guard (Guard 0) fires correctly during rotation.

### chain-forge-validators/src/lib.rs

- No new methods needed. `register_consensus_key_with_scheme` already handles rotation (drops old key from `by_pubkey`, writes new key + scheme).
- Add `remove_consensus_key(validator_id)` method — needed for explicit key revocation (future) and testability. Returns `Ok(())` if no key is registered (idempotent).

---

## Acceptance tests (PQ-VAL-003 suite — target: 10 tests)

All tests live in `chain-forge-node/src/node.rs` under `#[cfg(test)]`, following the PQ-VAL-001/002 pattern.

| # | Name | What it proves |
|---|------|----------------|
| T01 | `mldsa_key_rotation_replaces_old_key` | After rotation, the new ML-DSA key is in the registry; the old key is gone. |
| T02 | `mldsa_key_rotation_rejects_old_key_vote` | A vote signed with the old (pre-rotation) ML-DSA private key is rejected. |
| T03 | `mldsa_key_rotation_accepts_new_key_vote` | A vote signed with the new ML-DSA private key is accepted (activation epoch in effect). |
| T04 | `mldsa_power_zeroed_during_rotation_block` | voting_power = 0 inside the rotation block; > 0 in the block after. |
| T05 | `mldsa_to_classical_scheme_downgrade` | After rotating ML-DSA → Ed25519, scheme in registry is "classical"; Ed25519 votes accepted. |
| T06 | `classical_downgrade_restores_power_without_pq_activation` | After ML-DSA → Ed25519 rotation, power is restored even without PQ activation epoch. |
| T07 | `rotation_cross_validator_pop_replay_rejected` | A rotation tx carrying another validator's PoP is rejected. |
| T08 | `rotation_duplicate_key_blocked` | Rotating to a key already registered to a different validator is rejected. |
| T09 | `eda_does_not_clear_mldsa_registry` | After EDA, ML-DSA key remains in registry; re-activation restores power without re-registration. |
| T10 | `released_key_reusable_after_rotation` | The old key, freed by rotation, can be registered by a different validator. |

---

## Out of scope for PQ-VAL-003

- Explicit key revocation without replacement (deregister-only path) — deferred to PQ-VAL-004.
- Slashing for double-signing with old key post-rotation — deferred.
- Governance quorum for key rotation — rotation is self-authorized (sender = validator's account address), same as initial registration.
- Phase D degraded-network / partition testing — PQ-VAL-004.
