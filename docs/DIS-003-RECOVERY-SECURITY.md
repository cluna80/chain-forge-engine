# DIS-003 — Recovery Security Hardening

**Branch:** `feature/dis-003-recovery-security`  
**Depends on:** DIS-002B ✅ (lost-device recovery, merged `c9f924c`)  
**Status:** 📐 Spec — implementation scheduled

---

## Objective

DIS-002B proved that threshold-guardian recovery works under cooperative conditions.
DIS-003 hardens the same mechanism against adversarial behavior: malicious guardians,
compromised policies, replay across chains or accounts, and griefing attacks that
permanently block legitimate recovery.

The central invariant being added:

```
A recovery that could not have been authorized at submission time
cannot activate, even if conditions later change in the attacker's favour.
```

DIS-002B's invariant (`Identity_before = Identity_after`) is preserved; DIS-003
adds security properties that hold *even when guardians are partially compromised*.

---

## Threat model additions over DIS-002B

| Threat | DIS-002B posture | DIS-003 requirement |
|--------|-----------------|---------------------|
| Guardian key compromise | Not modelled | Compromised guardians can be replaced; revoked guardians cannot contribute to new recovery |
| Policy replacement replay | Not modelled | Recovery authorized under a superseded policy is rejected |
| Cross-chain/cross-account replay | Domain bytes encode chain_id + account + key_version | Explicit adversarial test coverage added |
| Stale recovery request | Not modelled | Signed recovery authorizations expire; execution enforces the window |
| Recovery timelock | Not modelled | Submitted recovery is pending for a challenge window before it activates |
| Malicious-guardian griefing | Not modelled | Cancellation authority defined; cancelled recovery cannot later finalize |
| Identity/balance side-effects | Not modelled | Policy changes never alter identity tier, attested_by, or balances |

---

## Phases

### DIS-003A — Guardian-policy replacement and revocation

**Goal:** The current `EnrollRecoveryPolicy` tx replaces any existing policy atomically.
This phase adds the security invariant that all pending recovery requests are voided
on policy replacement and that the old policy's guardian signatures cannot be reused.

**Key design points:**

- `RecoverAccountKey` already enforces `enrolled_at_key_version == account.key_version`.
  This prevents replay of a pre-rotation policy. DIS-003A extends this to intra-version
  policy replacement: a nonce or policy-generation counter on `RecoveryPolicy` ties every
  pending request to the exact policy that was in force when the request was created.
- `RevokeRecoveryPolicy` (new tx): account holder signs a revocation using the current
  key. Clears `account.recovery_policy`. Any pending recovery under the cleared policy
  cannot finalize.

**New `RecoveryPolicy` field:**

```rust
pub policy_id: u64,  // monotonically incremented on every EnrollRecoveryPolicy
```

`RecoverAccountKey` must carry `policy_id`; executor rejects it if
`policy_id != account.recovery_policy.policy_id`.

**Acceptance criteria:**

| ID | Criterion |
|----|-----------|
| C-01 | Policy replacement increments `policy_id`; recovery signed under old `policy_id` is rejected |
| C-02 | `RevokeRecoveryPolicy` clears the policy; a recovery attempt with no enrolled policy is rejected |
| C-03 | Policy replacement does not alter tier, attestation_count, attested_by, or account balance |

---

### DIS-003B — Compromised-guardian resistance

**Goal:** A guardian whose key is compromised after enrollment cannot single-handedly
enable recovery below the threshold, and can be removed from the policy without the
account holder needing the original device.

**Key design points:**

- `UpdateGuardianPolicy` (new tx): signed by the current signing key OR by a super-majority
  of existing guardians (threshold + 1). Replaces one or more guardian public keys and
  resets `policy_id`.
- A guardian removed via `UpdateGuardianPolicy` cannot contribute a signature to any
  recovery request created after the update, even if the revoked key was previously valid.
- If every guardian key is compromised, account recovery falls back to governance
  (out of scope for DIS-003; tracked as a future milestone).

**Acceptance criteria:**

| ID | Criterion |
|----|-----------|
| C-04 | Guardian replaced via `UpdateGuardianPolicy`; recovery signed by the replaced key is rejected |
| C-05 | `UpdateGuardianPolicy` signed by threshold+1 of existing guardians succeeds without the account key (lost-device scenario) |
| C-06 | `UpdateGuardianPolicy` signed by fewer than threshold+1 guardians and without the account key is rejected |

---

### DIS-003C — Cross-chain and cross-account replay protection

**Goal:** A guardian signature authorizing recovery for account A on chain X cannot be
replayed to authorize recovery for account B or on chain Y, even if both accounts share
the same guardian set.

**Current state:** `recovery_domain_signing_bytes()` already encodes
`CFREC|{chain_id}|{account}|{key_version}|{new_pk_hex}`. The binding is present in the
construction but has no adversarial test coverage.

**New coverage required:**

- Signature created for correct account, wrong chain → rejected.
- Signature created for wrong account, correct chain → rejected.
- Signature created for correct account and chain but wrong `key_version` → rejected
  (stale key_version replay).
- Signature created for correct account, chain, and version but different `new_pk` →
  rejected (new-key substitution attack).

**Acceptance criteria:**

| ID | Criterion |
|----|-----------|
| C-07 | Guardian sig for same account on a different `chain_id` is rejected |
| C-08 | Guardian sig for a different account on the same chain is rejected |
| C-09 | Guardian sig referencing a superseded `key_version` is rejected |
| C-10 | Guardian sig referencing a different `new_pk` than submitted is rejected |

---

### DIS-003D — Recovery authorization expiry

**Goal:** A signed recovery authorization has a finite validity window. A request that was
never submitted (e.g. because the attack was abandoned) cannot be replayed months later.

**Design distinction from timelock (DIS-003E):**

- **Expiry** is a property of the *signed authorization*: the guardian signature is only
  valid until `expires_at`. It prevents stockpiling of valid guardian signatures.
- **Timelock** is a property of the *submitted request*: the blockchain delays activation
  after a valid request is accepted. It gives the account holder a challenge window.

These are independent mechanisms. Both are needed.

**New `GuardianAuth` field:**

```rust
pub expires_at_height: u64,  // guardian signature invalid after this block height
```

Executor rejects `RecoverAccountKey` if
`current_height > any guardian_auth.expires_at_height`.

Guardians choose `expires_at_height` when signing; wallets should recommend a window
of approximately 7 days in block-height terms (configurable per chain).

**Acceptance criteria:**

| ID | Criterion |
|----|-----------|
| C-11 | Recovery submitted with all guardian sigs valid for current height succeeds |
| C-12 | Recovery submitted with one or more expired guardian sigs is rejected, even if threshold would otherwise be met |
| C-13 | Guardian sig with `expires_at_height` in the past is rejected at submission, not silently ignored |

---

### DIS-003E — Recovery timelock and cancellation

**Goal:** After a valid `RecoverAccountKey` is submitted, the account enters a pending
state for a challenge window (the *timelock*). During this window, an authorized
canceller can reject the recovery. After the window, if unchallenged, the recovery
activates. A cancelled recovery can never finalize.

**The cancellation authority question** (the most important design decision in DIS-003):

> Who can cancel a recovery when the original account key has been lost or compromised?

Possible answers and trade-offs:

| Authority | Grants cancellation to | Risk |
|-----------|----------------------|------|
| Current account key | Legitimate owner (if they recover quickly) | Attacker who holds the key can also cancel |
| Super-majority of *different* guardians (not the signers who requested recovery) | Guardian committee | Requires selecting non-overlapping guardian subsets |
| External emergency key (held offline or by trusted party) | Owner's cold-storage device | Single point of failure; out of scope for devnet |
| Governance / validator vote | Protocol itself | High latency; appropriate for extreme cases only |

**Recommended design for DIS-003E (devnet):** cancellation by the *same* account key
(which survives recovery — it is only replaced on *activation*, not on *submission*).
This means:

1. Recovery is *submitted*: `pending_recovery: Option<PendingRecovery>` is set on `AccountState`.
2. During the timelock window, the existing key can submit `CancelRecovery` (new tx).
3. At activation height (submission height + timelock), if no cancellation was submitted,
   a block executor finalizes the key replacement.

This is not a complete defence against a lost key — if the key is truly lost, the owner
cannot cancel. However, it defends against an attacker who learns the guardian threshold
but does not yet control the account key, giving the legitimate owner a race window.

Full guardian-committee cancellation (non-requesting guardians) is deferred to a later
phase when wallet UX for emergency contacts is specified.

**New `AccountState` fields:**

```rust
pub pending_recovery: Option<PendingRecovery>,
```

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRecovery {
    pub new_public_key:      Vec<u8>,
    pub new_key_scheme:      String,
    pub key_version:         u32,
    pub submitted_at_height: u64,
    pub activation_height:   u64,  // submitted_at_height + timelock_blocks
    pub policy_id:           u64,
    pub cancelled:           bool,
}
```

**Block executor change:** after committing each block, sweep accounts with
`pending_recovery.activation_height <= current_height && !cancelled` and activate.

**Acceptance criteria:**

| ID | Criterion |
|----|-----------|
| C-14 | Valid recovery sets `pending_recovery`; key is NOT immediately replaced |
| C-15 | `CancelRecovery` signed by current account key during timelock sets `cancelled=true`; recovery never activates |
| C-16 | Unchallenged recovery activates at `activation_height`; key is replaced and `pending_recovery` is cleared |
| C-17 | A cancelled recovery cannot be re-activated, even after its original `activation_height` passes |
| C-18 | A new `EnrollRecoveryPolicy` while a recovery is pending cancels the pending recovery |

---

## Invariants (all phases)

These must hold throughout DIS-003 and must not be regressed:

1. **Identity preservation**: No DIS-003 tx (`RevokeRecoveryPolicy`, `UpdateGuardianPolicy`,
   `CancelRecovery`) alters `tier`, `attestation_count`, `attested_by`, or account balance.

2. **Policy binding**: A recovery request is bound to the exact `(key_version, policy_id)`
   that was active when the guardian signatures were created. Changes to either invalidate
   the request.

3. **Cancellation finality**: Once `pending_recovery.cancelled = true`, no code path
   can set it back to `false`. A new recovery requires a new submission.

4. **No double-rotation**: While `pending_recovery` is `Some(...)`, a new
   `RecoverAccountKey` is rejected. A new `EnrollRecoveryPolicy` or
   `RotateAccountKey` (if the account key is available) clears pending state first.

5. **Expiry honesty**: `expires_at_height` in a `GuardianAuth` is checked at the block
   height of the *submission* tx, not at *activation* height. An authorization valid at
   submission cannot expire before activation.

---

## Cryptographic architecture note

Per CLAUDE.md (`§ Cryptographic Architecture Decision`): devnet validators stay Ed25519;
full ML-DSA is mainnet/Phase 1. DIS-003 introduces no new signing schemes. All new txs
(`RevokeRecoveryPolicy`, `UpdateGuardianPolicy`, `CancelRecovery`) use existing
ML-DSA-65 or Ed25519 account-key signing, already present in the executor. Guardian
signatures in `GuardianAuth` remain ML-DSA-65.

---

## Implementation order

```
DIS-003A  →  DIS-003B  →  DIS-003C  →  DIS-003D  →  DIS-003E
(policy        (guardian     (replay       (expiry)      (timelock +
 replacement)   revocation)   coverage)                  cancellation)
```

DIS-003C (replay coverage) requires no new tx types — only new adversarial tests against
the existing executor. It can be parallelised with DIS-003B.

DIS-003E (timelock) is the most architecturally significant change: it converts
`RecoverAccountKey` from an immediate key-replacement into a two-phase commit and
requires a new block-finalisation sweep. It should be implemented last.

---

## Acceptance summary

| ID | Phase | Criterion |
|----|-------|-----------|
| C-01 | 003A | Policy replacement increments `policy_id`; old-policy recovery rejected |
| C-02 | 003A | `RevokeRecoveryPolicy` clears policy; no-policy recovery rejected |
| C-03 | 003A | Policy ops do not alter identity or balance |
| C-04 | 003B | Replaced guardian cannot contribute to recovery after update |
| C-05 | 003B | Guardian super-majority can update policy without account key |
| C-06 | 003B | Sub-threshold guardian update without account key is rejected |
| C-07 | 003C | Wrong `chain_id` guardian sig rejected |
| C-08 | 003C | Wrong account guardian sig rejected |
| C-09 | 003C | Superseded `key_version` guardian sig rejected |
| C-10 | 003C | Wrong `new_pk` guardian sig rejected |
| C-11 | 003D | Valid-window recovery succeeds |
| C-12 | 003D | Any expired guardian sig causes rejection |
| C-13 | 003D | Past-height `expires_at_height` rejected at submission |
| C-14 | 003E | Valid recovery sets pending state; key not immediately replaced |
| C-15 | 003E | Current-key cancellation prevents activation |
| C-16 | 003E | Unchallenged recovery activates at `activation_height` |
| C-17 | 003E | Cancelled recovery cannot be re-activated |
| C-18 | 003E | New policy enrollment clears pending recovery |

---

## Open questions (to resolve before implementing DIS-003E)

1. **Timelock duration**: what block height delta is appropriate for devnet?
   Recommendation: parameterise per-chain in genesis (`recovery_timelock_blocks: u64`);
   default 0 for devnet (instant, to keep B-09-style tests fast), configurable for
   testnet/mainnet.

2. **Activation sweep timing**: does the executor activate pending recoveries at the
   *start* of a block (before txs) or *end* (after txs)? End-of-block is safer — it
   avoids a race where the first tx in the activation block is signed by the new key
   before state reflects it.

3. **Guardian super-majority for `UpdateGuardianPolicy`**: is `threshold + 1` the right
   bar, or should it be `ceil(N * 2/3)`? The latter is more Byzantine-fault-tolerant but
   harder to explain to users.

4. **Interaction with `BondValidator`**: if a validator's signing key is their account
   key, a pending recovery that eventually activates will replace the validator's signing
   key mid-epoch. Does the consensus layer need to be notified of `activation_height`?
