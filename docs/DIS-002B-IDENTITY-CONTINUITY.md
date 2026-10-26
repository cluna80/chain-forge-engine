# DIS-002B — Identity Continuity, Device Migration, and Recovery

**Branch:** `feature/dis-002b-identity-continuity`  
**Depends on:** DIS-002A ✅ (authenticated account key rotation)  
**Status:** ⏸ Deferred — spec complete, implementation scheduled for a future session

---

## Objective

Allow a Qattice user to replace a device or recover access without losing their account,
verified identity, balances, or authorization history.

The central invariant:

```
Identity_before = Identity_after
```

DIS-002A proved that an account's authorized signing key can change while the address
stays fixed.  DIS-002B extends this to the full identity lifecycle:

1. **Path 1 — Authorized device migration**: user still controls the old device.
2. **Path 2 — Lost-device recovery**: user no longer controls the original signing key.

A lost or compromised device **must not** be able to regain control after successful
recovery.

---

## Architectural baseline

### How identity and key authority are split (Phase 0 / current)

Three data structures govern a user's on-chain presence:

| Structure | Location | Stable identifier | Stores signing key? |
|---|---|---|---|
| `AccountState` | `chain-forge-state` | `address: String` | Yes — `public_key: Option<Vec<u8>>`, `key_version: u32` |
| `IdentityRecord` | `chain-forge-identity` | `id: String` (= `address`) | **No** |
| `IntrinsicCharm` | inside `IdentityRecord` | — | **No** — stores `tier: VerificationTier` |

**Critical invariant already in place**: `IdentityRecord.id == IdentityRecord.address`.
Neither field stores a public key.  A `RotateAccountKey` tx only touches `AccountState`;
`IdentityRecord`, `IntrinsicCharm.tier`, `sponsored_agents`, and the attestation ledger
are entirely untouched.

`IdentityStore.by_address` (`HashMap<String, String>`) maps `address → identity_id`.
Because `id == address` today, this index is redundant but correct — it will become
meaningful if `id` and `address` diverge in a future protocol version.

**Consequence for DIS-002B Path 1**: device migration is a `RotateAccountKey` tx with
an authorization signature from the old device.  No additional identity-layer changes are
needed — the identity record survives rotation without any code changes.

**Consequence for DIS-002B Path 2**: no recovery mechanism exists today.
`IdentityRecord` has no `recovery_policy`, `guardians`, or `recovery_key` field.
Building lost-device recovery requires a new on-chain primitive (see §Recovery below).

### One-human-one-consensus-influence after rotation

The personhood-weighted consensus path (`BondValidator.owner_identity_id`) and the
Verified-tier gate both reference the **account address**, not the public key.  After
rotation:

- `state.get_account(address).public_key` = Key_B (correct, updated by RotateAccountKey)
- `identity_store.get_by_id(address).tier` = Verified (unchanged)
- `BondValidator` authorization uses `owner_identity_id == tx.sender` (address check) —
  still valid

No risk of a second `IdentityRecord` being created during rotation because the record
key is the address, which never changes.

---

## Path 1 — Authorized Device Migration

The user still controls the old device at the time of migration.

### Protocol

1. Install Qattice Wallet on the new device.
2. New device generates a fresh ML-DSA-65 keypair locally (never leaves the device).
3. New device produces a proof-of-possession signature over `account_key_rotation_signing_bytes(chain_id, address, key_version+1, new_pk)`.
4. Old device approves: signs the `RotateAccountKey` tx body with Key_A.
5. Tx is broadcast and committed exactly as in DIS-002A.
6. New device is now authoritative; old device's Key_A is invalid.

**No private key is transferred between devices.**

### What this adds over DIS-002A

DIS-002A proved the transaction works in isolation (synthetic keypairs on a single
machine).  DIS-002B Path 1 proves it works with **real pilot device identities**:

- BossKing, Laptop, Phone (Galaxy A15), King-OptiPlex-990 each hold a Verified-tier
  ML-DSA-65 key on the devnet.
- Migration means: old device signs the rotation; new device signs a post-migration tx;
  old device's key is then rejected.
- The identity record (tier, credential bindings) must survive unchanged.

### Acceptance criteria (B-01 through B-08)

| ID | Criterion |
|---|---|
| B-01 | Verified pilot identity migrates from Device A to Device B |
| B-02 | `IdentityRecord.id`, `address`, and the QCB account address are unchanged |
| B-03 | `IntrinsicCharm.tier` remains `Verified`; attestation ledger is intact |
| B-04 | Balance (minus gas), nonce progression, and sponsored agents are preserved |
| B-05 | New device (Key_B) signs and finalizes a transaction |
| B-06 | Old device (Key_A) can no longer authorize transactions |
| B-07 | Replayed or expired migration challenges are rejected (`key_version` guard) |
| B-08 | Unauthorized migration attempts — forged PoP or wrong outer signer — are rejected |

B-07 and B-08 are already proven by DIS-002A cases F, G, H.  They are listed here as
regression guards: they must pass with real pilot identity accounts (not synthetic ones).

---

## Path 2 — Lost-Device Recovery

The user **no longer** controls the original signing key.

### Design constraint

A personhood credential alone must **not** automatically grant account recovery.
Proving uniqueness of a human is not the same as proving ownership of a particular
account.  Without this separation:

- A compromised attestation coordinator could recover arbitrary accounts.
- A Sybil-confirmed identity could be weaponized to hijack an account.

### Recovery authority model

Recovery requires a **recovery policy** enrolled while the account is still under the
user's control.  The policy specifies one or more independently held recovery authorities
and the threshold required to authorize a recovery rotation.

#### Recovery policy structure (proposed)

```rust
pub struct RecoveryPolicy {
    /// Stable account address this policy covers.
    pub account:    String,
    /// Recovery authorities: each is a distinct ML-DSA-65 public key
    /// (e.g. a hardware key, a second phone, a trusted guardian's key).
    pub guardians:  Vec<Vec<u8>>,
    /// How many guardians must sign a valid recovery tx.
    pub threshold:  u32,
    /// key_version at policy enrollment.  Recovery is only valid if the
    /// account's current key_version matches this.  Prevents a stale
    /// policy from being used after the account has already rotated.
    pub enrolled_at_key_version: u32,
    /// Optional: number of blocks the recovery tx must wait before
    /// taking effect (cancellation window).
    pub timelock_blocks: Option<u64>,
}
```

#### Recovery transaction

A new `TxBody::RecoverAccountKey` variant:

```rust
RecoverAccountKey {
    /// The replacement key to install.
    new_public_key:  Vec<u8>,
    new_key_scheme:  String,
    key_version:     u32,
    /// PoP: new key signs account_key_rotation_signing_bytes().
    pop_signature:   Vec<u8>,
    /// Recovery authorizations: each guardian signs the same PoP domain
    /// message (or a designated recovery domain message).
    guardian_signatures: Vec<GuardianAuth>,
}

pub struct GuardianAuth {
    pub guardian_public_key: Vec<u8>,
    pub signature:           Vec<u8>,
}
```

Execution guards:
1. Account must have an enrolled `RecoveryPolicy`.
2. `key_version` == current + 1.
3. At least `threshold` guardian signatures are valid over the recovery domain message.
4. Each guardian key must be distinct and listed in the enrolled policy.
5. PoP from the new key verifies.
6. Timelock: if `timelock_blocks > 0`, the tx enters a pending queue and finalizes
   after that many blocks (cancellable by the account during the window — if the
   user still has the old key, they can cancel a fraudulent recovery).

### Acceptance criteria (B-09 through B-12)

| ID | Criterion |
|---|---|
| B-09 | Lost-device recovery succeeds with a valid enrolled policy and threshold met |
| B-10 | Recovery with insufficient guardian sigs is rejected |
| B-11 | Recovery with forged guardian sigs is rejected |
| B-12 | Rotation and recovery survive node restart (state persists to disk) |
| B-13 | Four nodes agree on identity, key version, and state root after recovery |

---

## Implementation plan

### Milestone 1 — Path 1 (authorized migration) with pilot identities

**Scope:**
- No new tx types needed — uses existing `RotateAccountKey`.
- Update the live acceptance test to use actual DIS-PILOT-001 keypairs from
  `chain-forge-node/tests/devnet/keys/`.
- Verify B-01 through B-08 on the 4-node devnet.

**Estimate:** 1–2 days.  The transaction path is already implemented; this is
integration and end-to-end verification with real pilot keys.

### Milestone 2 — Path 2 (lost-device recovery)

**Scope:**
- Add `RecoveryPolicy` to `chain-forge-state` (new field on `AccountState` or a
  separate `RecoveryStore`).
- New `TxBody::RecoverAccountKey` variant in `chain-forge-execution`.
- `execute_recover_account_key()` function with the 5 guards above.
- Optional timelock mechanism (can be deferred to M3).
- Live acceptance test: enroll policy, simulate lost device, recover with guardians.

**Estimate:** 3–5 days.

### Milestone 3 — Durability and cross-node consistency (B-12, B-13)

**Scope:**
- Restart the 4-node devnet after migration/recovery; confirm the new key is still
  authoritative and the old key is still rejected.
- Cross-node state-root agreement after both migration and recovery operations.

**Estimate:** 1 day (mostly test harness).

---

## Files to change

| File | Change |
|---|---|
| `chain-forge-state/src/lib.rs` | Add `recovery_policy: Option<RecoveryPolicy>` to `AccountState`; new `RecoveryPolicy` struct |
| `chain-forge-execution/src/lib.rs` | New `TxBody::RecoverAccountKey` variant; `execute_recover_account_key()` |
| `chain-forge-node/tests/dis_002b_migration_live.rs` | New live acceptance test (Path 1 first, then Path 2) |
| `ROADMAP.md` | Update status as milestones complete |

The `IdentityRecord` and `IdentityStore` in `chain-forge-identity` require **no changes**
for Path 1.  Path 2 may want to log recovery events in the attestation ledger as an
audit trail, but this is not required for acceptance.

---

## Non-goals for DIS-002B

- Social recovery UI (wallet app changes are out of scope for this milestone).
- Cross-device synchronization of agent authorizations or spending limits.
- Governance-triggered emergency rotation (Phase 2+).
- ZK proof for recovery (Phase 2+; Phase 0/1 uses threshold ML-DSA signatures).

---

## Test command

```
cargo build -p chain-forge-node
cargo test -p chain-forge-node --test dis_002b_migration_live -- --nocapture
```

Per `CLAUDE.md`: mark milestones ✅ only after the developer confirms acceptance tests
pass on Windows/MINGW64 (`krizz@BossKing`).
