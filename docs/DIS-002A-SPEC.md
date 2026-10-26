# DIS-002A — Authenticated Account Key Rotation
## Formal Specification and Threat Model

**Branch:** `feature/dis-002a-key-rotation`  
**Baseline:** `v0.1.0-phase0` (tag `e269374`)  
**Date:** 2026-10-25  
**Status:** Pre-implementation specification

---

## 1. Motivation

At Phase 0, an account's authorized signing key is set once — on its first
signed transaction — and never changes. The account address is either a named
genesis address (e.g. `qcb1alice`) or derived from the initial public key via
`SHA3(pubkey)[..20]`.

There is no mechanism to replace a compromised key, migrate to a new device,
or upgrade cryptography without abandoning the existing account and its
balances, identity record, and permissions.

DIS-002A adds a `RotateAccountKey` transaction type that replaces the
authorized signing key while leaving the account address, balances,
verification tier, nonces, and identity record entirely unchanged.

---

## 2. Invariants

The following invariants MUST hold across a key rotation:

| # | Invariant |
|---|-----------|
| I-1 | `account.address` is unchanged |
| I-2 | `account.balance` is unchanged |
| I-3 | `account.nonce` advances exactly once (by the rotation tx itself) |
| I-4 | `IdentityRecord.id` is unchanged |
| I-5 | `IdentityRecord.charm.tier` is unchanged |
| I-6 | After rotation, only the new key authorizes future transactions |
| I-7 | The old key is permanently invalid for the rotated account |
| I-8 | No two nodes may commit a different authorized key for the same account |
| I-9 | A rotation tx cannot be replayed (standard nonce replay protection) |

---

## 3. Exact Code Paths Affected

### 3.1 Key binding (current behavior — Phase 0)

`chain-forge-execution/src/lib.rs` — `bind_key_if_unbound` (~L2084):

```
if acct.public_key.is_none() {
    acct.public_key = Some(tx.pq_public_key.clone());
}
```

This guard correctly prevents automatic re-binding. Rotation MUST NOT use this
path; it requires an explicit authenticated transaction.

### 3.2 ML-DSA signature verification

`chain-forge-execution/src/lib.rs` — `verify_mldsa_authorization` (~L1827):

```
let bound_key = state.get_account(&tx.sender).ok().and_then(|a| a.public_key.clone());
let pub_key = match bound_key {
    Some(ref k) if !k.is_empty() => k.clone(),  // use bound key
    _ => tx.pq_public_key.clone()                // first-use: use supplied key
};
```

**After rotation:** the new key is stored in `acct.public_key`. The bound-key
branch executes immediately on all subsequent transactions. No fallback to the
old key is possible because `bound_key` is `Some(new_key)` — the fallback
branch only fires when `bound_key` is `None` or empty.

### 3.3 Ed25519 signature verification

`chain-forge-execution/src/lib.rs` (~L1703):

```
match state.get_account(&tx.sender).ok().and_then(|a| a.public_key.clone()) {
    Some(bound) if bound == tx.public_key => Ok(()),
    Some(_) => Err("signing key does not match the key bound to {sender}"),
    None => { /* address-derivation fallback */ }
}
```

After rotation, `Some(new_key)` is bound. The old key hits the `Some(_) →
Err(...)` branch. The address-derivation fallback is unreachable.

**Security conclusion:** The fallback from Section 1 of the user's design
requirement is already structurally impossible once any key is bound. The
`RotateAccountKey` handler simply overwrites `acct.public_key` — existing
verification logic then enforces the "no old-key fallback" rule automatically.

### 3.4 Account state location

`chain-forge-state/src/lib.rs` — `StateStore`, field `accounts: HashMap<Address, Account>`.
`Account.public_key: Option<Vec<u8>>` — the single field to update on rotation.

### 3.5 No KeyRegistry needed (revised)

The proposed `KeyRegistry` indirection layer is unnecessary. The existing
`Account.public_key` field IS the key registry, per-account. A rotation
overwrites this field. The indirection adds complexity without security benefit
because the verification paths already consult `account.public_key` as the
authoritative source.

---

## 4. New Transaction Type: `RotateAccountKey`

### 4.1 Transaction body

```json
{
  "RotateAccountKey": {
    "new_public_key": "<hex-encoded ML-DSA-65 public key>",
    "new_key_scheme": "ml-dsa-65",
    "key_version":    1,
    "pop_signature":  "<hex-encoded proof-of-possession signature>"
  }
}
```

Fields:

| Field | Type | Description |
|-------|------|-------------|
| `new_public_key` | hex string | The replacement ML-DSA-65 public key (2592 bytes) |
| `new_key_scheme` | string | Must be `"ml-dsa-65"` for DIS-002A |
| `key_version` | u32 | Must equal `current_key_version + 1`; prevents replay of old rotation txs |
| `pop_signature` | hex string | Proof-of-possession: new key signs the domain-separated authorization message |

### 4.2 Authorization rules (execution guard sequence)

The executor checks all of these in order; the first failure rejects the tx:

1. **Sender must have a bound key** — `account.public_key.is_some()`. An
   unbound account uses `bind_key_if_unbound` on first use; it cannot rotate
   before it has ever transacted.

2. **Outer signature valid** — the transaction's `pq_signature` must verify
   against the *current* bound key (standard `verify_mldsa_authorization`).
   This is already enforced by the existing pre-execution authorization check.

3. **`key_version` is exactly `current + 1`** — prevents replay of a past
   rotation and ensures ordered rotation. `current_key_version` is stored in
   the account state (new field, initialized to 0, incremented on rotation).

4. **`new_public_key` is valid ML-DSA-65** — length must be 2592 bytes; scheme
   must be `"ml-dsa-65"`.

5. **`new_public_key` differs from current** — rotating to the same key is a
   no-op error, not a silent success.

6. **Proof-of-possession valid** — `pop_signature` must verify under
   `new_public_key` over the domain-separated message (see §4.3).

7. **Module gate** — `RotateAccountKey` belongs to a new `"key_management"`
   module (or reuses `"identity"` — TBD at implementation). The module must be
   enabled in genesis.

### 4.3 Proof-of-possession domain message

The PoP message binds the rotation to this account on this chain at this
specific key version, preventing:

- Cross-chain replay (different `chain_id`)
- Cross-account theft (different `sender`)
- Version rollback replay (different `key_version`)

```
CFAR|<chain_id>|<sender_address>|<key_version>|<hex(new_public_key)>
```

`CFAR` = "Chain Forge Account Rotation" domain tag.

Analogous to the existing `validator_key_registration_signing_bytes_v2` in
`chain-forge-execution/src/lib.rs` (~L1755).

### 4.4 Execution effect

On successful execution:

```
account.public_key      = Some(new_public_key)
account.key_version     += 1
account.nonce           += 1  (standard nonce increment on success)
// identity record:      unchanged
// balances:             unchanged (minus gas fee)
```

No other state is modified.

---

## 5. Account State Changes

Add two fields to the `Account` struct in `chain-forge-state`:

```rust
pub struct Account {
    // ... existing fields ...

    /// Current authorized signing key. Set on first use; replaced by RotateAccountKey.
    pub public_key: Option<Vec<u8>>,     // already exists

    /// Monotonically increasing key version. 0 = initial bind; +1 per rotation.
    /// Used to prevent replay of stale rotation transactions.
    #[serde(default)]
    pub key_version: u32,                // NEW
}
```

`#[serde(default)]` means existing accounts deserialise with `key_version = 0`
without breaking any existing state serialization.

---

## 6. Threat Model

### 6.1 Threats addressed by DIS-002A

| Threat | Mitigation |
|--------|-----------|
| Compromised key — attacker can authorize txs indefinitely | Owner rotates key; old key immediately invalid |
| Replay of a captured rotation tx | `key_version` must be exactly `current + 1`; nonce replay also blocks it |
| Attacker registers their key against victim's account | Outer signature requires current bound key (only owner holds it) |
| New key is not controlled by the rotator | PoP signature proves possession before activation |
| Rotation wipes identity or balance | Execution only modifies `public_key` and `key_version`; nothing else |
| Nodes disagree on rotated key | BFT consensus — `RotateAccountKey` goes through normal tx finalization |

### 6.2 Threats NOT addressed by DIS-002A

| Threat | Deferred to |
|--------|------------|
| Recovery after total key loss (no old key to sign the rotation) | DIS-002B (social / guardian recovery) |
| Device migration without simultaneous old-device access | DIS-002B |
| Validator consensus key rotation | Separate milestone (consensus layer, different security model) |
| Revocation of a compromised identity credential | DIS-002C |
| Multi-factor authorization for rotation | Future hardening; not required for devnet |

### 6.3 Assumptions

- The owner's current key is not compromised at the time of rotation. If it is,
  key rotation cannot help — that is the recovery problem (DIS-002B).
- The network is not under active BFT attack at rotation time (same assumption
  as all transactions).
- ML-DSA-65 is existentially unforgeable under chosen-message attack (NIST
  FIPS 204 assumption).

---

## 7. Acceptance Tests (DIS-002A)

All tests are four-node devnet acceptance tests on Windows/MINGW64, consistent
with the CLAUDE.md test validation policy.

| Case | Description | Expected result |
|------|-------------|-----------------|
| A | Happy path: Key_A signs rotation to Key_B; Key_B signs subsequent tx | Both txs finalize; state root agrees across all 4 nodes |
| B | Identity continuity: check address, balance, identity tier after rotation | All unchanged from pre-rotation state |
| C | Old-key rejection: submit tx signed with Key_A after rotation | Rejected with "signing key does not match" |
| D | New-key acceptance: tx signed with Key_B after rotation | Finalizes successfully |
| E | Replay of rotation tx: resubmit same rotation tx (same nonce) | Rejected by nonce replay protection |
| F | Stale key_version: rotation tx with `key_version = 0` after first rotation | Rejected with key version mismatch |
| G | Unauthorized rotation: rotation tx signed by a third party's key | Rejected — outer signature fails |
| H | Invalid PoP: rotation tx with garbage `pop_signature` | Rejected at PoP verification step |
| I | Cross-node consistency: all 4 nodes agree on account state after rotation | State roots match; no fork |

Test file: `chain-forge-node/tests/dis_002a_key_rotation_live.rs`

---

## 8. Implementation Sequence

1. **`chain-forge-state`** — Add `key_version: u32` field to `Account`.
   Verify existing state serialization round-trips with `#[serde(default)]`.

2. **`chain-forge-execution`** — Add `TxBody::RotateAccountKey { .. }` variant.
   Add PoP domain-separator function `account_key_rotation_signing_bytes`.
   Add `execute_rotate_account_key` handler enforcing all guards from §4.2.
   Add `"key_management"` to `required_module` match.

3. **`chain-forge-execution`** — Add `RotateAccountKey` to genesis module list
   in devnet genesis file.

4. **`chain-forge-node/tests`** — Write `dis_002a_key_rotation_live.rs` covering
   all 9 cases above.

5. **`chain-forge-wallet`** (optional, post-test) — Add `rotate-key` subcommand.

6. **`ROADMAP.md`** — Update DIS-002A entry after developer confirms tests pass.

---

## 9. Out of Scope

- Validator consensus key rotation (different mechanism, Phase 1)
- Key recovery without the current authorized key (DIS-002B)
- Device migration (DIS-002B)
- Credential revocation (DIS-002C)
- Ed25519 → ML-DSA-65 upgrade path (addressed separately; rotation here
  is ML-DSA-65 → ML-DSA-65 only for DIS-002A)
