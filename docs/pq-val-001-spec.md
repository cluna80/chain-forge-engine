# PQ-VAL-001 — ML-DSA Validator-Key Registration and Proof of Possession

**Status:** Approved, test-first development  
**Baseline:** `main` @ `90d7c03` (CF-DEVNET-VAL-001 resolved, 90 node tests passing)  
**Scope:** Execution layer only. Classical BFT consensus signing in `commit_block` is NOT changed.

---

## Problem statement

`RegisterValidatorKey` execution at `chain-forge-execution/src/lib.rs:1955` is
hardcoded to `ClassicalScheme.verify` regardless of the submitted key's algorithm:

```rust
// CURRENT — scheme-blind, always classical
let sig = Signature { scheme: SchemeId::Classical, bytes: proof_of_possession.clone() };
match ClassicalScheme.verify(&msg, &sig, consensus_pubkey) {
```

Additionally, `validator_key_registration_signing_bytes` does not bind the public
key bytes, allowing a valid PoP from one key to be submitted alongside a different
key. `RegisterValidatorKey` also carries no `scheme` field, so the executor has
no caller-supplied signal about which algorithm to use.

---

## Locked requirements

### R1 — Versioned PoP format (backward-compat)

Two PoP message versions are defined. Existing classical proofs continue to verify.

**V1 (classical legacy):**
```
b"CFVK|" || chain_id || b"|" || sender_address
```
Accepted only for `scheme = "classical"` when explicitly opted in via a V1 flag.
New classical registrations SHOULD use V2 from the activation boundary forward.

**V2 (canonical, all new registrations):**
```
b"CFVK-V2|" || chain_id || b"|" || sender_address || b"|" || hex(consensus_pubkey)
```
Binds chain_id + validator identity + algorithm-agnostic public key bytes.
Required for all ML-DSA registrations. Prevents:
- Cross-chain PoP replay (chain_id binding)
- Cross-validator key theft (sender_address binding)
- Key substitution (consensus_pubkey binding) [test 09, 14]

The activation boundary for requiring V2 on new classical registrations is
defined by governance via `EmergencyDeprecateAlgorithm` or a future
`RequirePopVersion` tx — NOT hardcoded in this milestone.

### R2 — Fail-closed scheme dispatch

The executor MUST:
1. Parse `scheme` from `RegisterValidatorKey`; reject if absent or unrecognized.
2. Check that the scheme is in the `VALIDATOR_AUTHORIZED_SCHEMES` allowlist.
3. Verify key length matches the scheme's expected public key size.
4. Route to the correct verifier (`ClassicalScheme` or `MlDsaScheme`).
5. Return a specific error for each failure mode (unknown scheme, wrong key
   length, PoP mismatch, unauthorized scheme).

Never fall through to ClassicalScheme when the scheme is unrecognized.

**`VALIDATOR_AUTHORIZED_SCHEMES` (this milestone):**
```rust
const VALIDATOR_AUTHORIZED_SCHEMES: &[&str] = &["classical", "ml-dsa-65"];
```
`ml-dsa-87` and hybrid schemes are NOT authorized at this milestone. Adding a
scheme to `SchemeRegistry` does not automatically authorize it for validator
registration.

### R3 — Registration decoupled from consensus activation

ML-DSA key registration succeeds and is persisted. The validator's `key` field
is set in `ValidatorRegistry`. However:

- The consensus vote verifier in `commit_block` remains classical-only.
- An ML-DSA-only validator (no classical key, ML-DSA key registered) MUST NOT
  acquire `voting_power > 0` in this milestone.
- Gate: `gate_voting_power` checks `consensus_scheme_active_for_consensus(scheme)`
  before granting power. Classical → always eligible. ML-DSA → ineligible until
  PQ-VAL-002 (consensus verifier milestone).

This prevents an ML-DSA-only validator from joining the live consensus set before
`commit_block` can verify its votes, which would harm liveness.

Validators that have BOTH a classical key (from an earlier registration) AND an
ML-DSA key registered (dual-key transition path) retain their classical voting
power. This transition path is deferred to PQ-VAL-002.

---

## Changes required (execution layer only)

### 1. `TxBody::RegisterValidatorKey` — add `scheme` field
```rust
RegisterValidatorKey {
    consensus_pubkey:    Vec<u8>,
    proof_of_possession: Vec<u8>,
    scheme:              String,   // "classical" | "ml-dsa-65"
    pop_version:         u8,       // 1 = legacy V1, 2 = canonical V2
}
```
`scheme` is required; no silent default. `pop_version` defaults to 2 for new
submissions; executors accept 1 only for `scheme = "classical"` (legacy compat).

### 2. `validator_key_registration_signing_bytes` — V2 construction
```rust
pub fn validator_key_registration_signing_bytes_v2(
    chain_id:       &str,
    sender:         &str,
    consensus_pubkey: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"CFVK-V2|");
    b.extend_from_slice(chain_id.as_bytes());
    b.push(b'|');
    b.extend_from_slice(sender.as_bytes());
    b.push(b'|');
    b.extend_from_slice(hex_encode_bytes(consensus_pubkey).as_bytes());
    b
}
```
V1 function kept unchanged for legacy path.

### 3. Executor dispatch in `RegisterValidatorKey` arm
```rust
// Pseudocode — exact implementation in chain-forge-execution/src/lib.rs
if !VALIDATOR_AUTHORIZED_SCHEMES.contains(&scheme.as_str()) {
    return Err(format!("scheme '{scheme}' is not authorized for validator registration"));
}
validate_key_length(scheme, consensus_pubkey)?;
let msg = match pop_version {
    1 => validator_key_registration_signing_bytes(chain_id, sender),
    2 => validator_key_registration_signing_bytes_v2(chain_id, sender, consensus_pubkey),
    _ => return Err("unknown pop_version".into()),
};
let sig = Signature { scheme: scheme.parse()?, bytes: proof_of_possession.clone() };
match scheme.as_str() {
    "classical"  => ClassicalScheme.verify(&msg, &sig, consensus_pubkey),
    "ml-dsa-65"  => MlDsaScheme.verify(&msg, &sig, consensus_pubkey),
    _            => unreachable!(), // already gated above
}
```

### 4. `ValidatorRegistry::register_consensus_key` — pass scheme through
Store `scheme` alongside the key bytes so `gate_voting_power` can check it.

### 5. `gate_voting_power` — scheme-aware eligibility (R3)
Classical key → eligible as today.  
ML-DSA key → ineligible for consensus power until PQ-VAL-002 activates the
consensus verifier. Log a warning when a validator's only key is ML-DSA.

---

## Test matrix

Regression baseline: all tests passing on `main @ 90d7c03`. Suite must not
shrink. Gossip-test port-race flakiness tracked separately (pre-existing).

| ID | Test name | Property tested | Expected outcome |
|---|---|---|---|
| 01 | `mldsa_validator_key_registers_with_valid_pop` | Valid ML-DSA-65 + V2 PoP accepted | Tx succeeds; key stored in registry |
| 02 | `mldsa_pop_with_wrong_private_key_is_rejected` | PoP signed by different ML-DSA keypair | Tx fails: "proof-of-possession verification failed" |
| 03 | `mldsa_pop_with_wrong_chain_id_is_rejected` | PoP built over wrong chain_id | Tx fails: PoP mismatch |
| 04 | `mldsa_pop_without_bond_is_rejected` | No bond, ML-DSA key registration | Validator absent from active set |
| 05 | `mldsa_pop_without_personhood_has_zero_power` | Bond + ML-DSA key, no personhood | `voting_power == 0` (personhood gate) |
| 06 | `classical_pop_on_mldsa_key_is_rejected` | Classical PoP sig for ML-DSA pubkey | Tx fails: scheme mismatch or PoP failure |
| 07 | `mldsa_validator_key_survives_restart` | ML-DSA key + lifecycle state persist | Key unchanged after disk restart |
| 08 | `classical_validator_path_unaffected` | All CF-DEVNET-VAL-001 tests still pass | Zero regression |
| 09 | `mldsa_pop_key_substitution_rejected` | PoP for key-A submitted with key-B | Tx fails: V2 binding catches substitution |
| 10 | `unknown_scheme_is_rejected` | `scheme = "ed448"` (unsupported) | Tx fails: "not authorized for validator registration" |
| 11 | `malformed_mldsa_key_fails_closed` | Correct scheme, wrong-length key bytes | Tx fails: key length validation |
| 12 | `classical_v1_pop_compat_preserved` | Existing classical V1 PoP still accepted | Tx succeeds (legacy path) |
| 13 | `mldsa_only_validator_has_zero_voting_power` | ML-DSA key registered, no classical key | `voting_power == 0` (R3 — consensus not yet ML-DSA-aware) |
| 14 | `mldsa_pop_cross_validator_replay_rejected` | Valid PoP for alice submitted for bob | Tx fails: sender mismatch in V2 message |

---

## Invariants that must not change

- Classical BFT consensus (`commit_block` signing and verification): unchanged
- Bond threshold, personhood gate, epoch admission: unchanged
- Quorum calculation: unchanged
- Validator eviction policy: unchanged
- Existing `register_consensus_key` behavior for classical keys: unchanged
- `gate_voting_power` logic (pop_verified + key presence): unchanged except for
  the new ML-DSA-ineligible-for-consensus branch (R3)

---

## What this milestone does NOT do

- Does not modify consensus vote signing or verification
- Does not activate ML-DSA validators for live consensus
- Does not implement key rotation or revocation (PQ-VAL-003)
- Does not wire `ml-dsa-87` or hybrid schemes for validators
- Does not change the gossip-test port-race issue (tracked separately)

---

## Next milestone after PQ-VAL-001

**PQ-VAL-002 — ML-DSA consensus signature verification**  
Extend `commit_block` vote verifier to dispatch on the validator's registered
key scheme. Dual-key transition path (classical → ML-DSA with no power gap).
Activation gated by `validator_scheme` in genesis/governance config.
