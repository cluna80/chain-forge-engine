# DIS-AGENT-001 — Delegated Agent/Machine Authorization

**Status**: v0.1 prototype — ⚠️ Return before production deployment  
**Date**: 2026-10-21  
**Scope**: `dis-core` crate (`dis_core::delegation`)

---

## Overview

DIS-AGENT-001 adds scoped, expiring, revocable capability delegation to the DIS-KS-V1 protocol. A human holder can sign a `Delegation` granting an agent/machine a strict subset of their RP-granted capabilities for a specific resource and action. The RP verifies the full delegation chain without trusting the agent directly.

**Machine/agent credentials never imply human uniqueness.** An agent key enrolled via delegation is NOT a human identity credential. The RP's `enrolled_keys` set remains for human holders only; agent keys appear only in delegation chains and are verified transitively through the chain.

---

## Data Model

### `Delegation`

| Field | Type | Description |
|-------|------|-------------|
| `rp_id` | `String` | Must match the verifying RP |
| `delegator_public_key` | `Vec<u8>` | ML-DSA-65 public key of the granting party |
| `delegate_public_key` | `Vec<u8>` | ML-DSA-65 public key of the receiving agent |
| `scopes` | `Vec<String>` | Scopes granted — must be ⊆ delegator's own scopes |
| `resource_id` | `String` | Specific resource this delegation covers |
| `action` | `String` | Specific action this delegation covers |
| `issued_at` | `u64` | Unix seconds |
| `expires_at` | `u64` | Unix seconds; delegation is invalid at or after this time |
| `max_uses` | `Option<u32>` | If set, this delegation may be used at most N times |
| `requires_human_approval` | `bool` | If true, the RP requires `approve_challenge()` before accepting a proof |
| `signature` | `Vec<u8>` | Dilithium3 detached signature over `canonical_delegation_body` |

### `DelegatedProof`

```
chain:       [Delegation, ...]   — ordered, length 1..=MAX_CHAIN_DEPTH (4)
agent_proof: HolderProof         — agent's ML-DSA signature on the request transcript
```

`chain[0].delegator_public_key` must be enrolled at the RP. `chain[i].delegate_public_key == chain[i+1].delegator_public_key`. `chain.last().delegate_public_key == agent_proof.public_key`.

---

## Wire Format

`canonical_delegation_body(d)` produces the domain-separated bytes the delegator signs:

```
b"DIS-DEL-V1\0"         11 bytes, domain separator
rp_id                   u16-length-prefixed UTF-8
delegator_public_key    u16-length-prefixed bytes
delegate_public_key     u16-length-prefixed bytes
scopes_count            u16 BE
scopes[]                each u16-length-prefixed UTF-8
resource_id             u16-length-prefixed UTF-8
action                  u16-length-prefixed UTF-8
issued_at               u64 BE
expires_at              u64 BE
max_uses flag           u8 (0=None, 1=Some)
max_uses value          u32 BE (only if flag=1)
requires_human_approval u8 (0 or 1)
```

---

## Verification Rules (`RelyingParty::verify_delegated`)

1. Audience check: `rp_id`, `rp_origin`, `policy_id` match RP policy.
2. Suite check: `request.suite_id >= policy.min_suite_id`.
3. Time check: `request.issued_at <= now < request.expires_at`.
4. Challenge check: challenge_id matches a pending issued request.
5. Chain validation:
   - Length 1..=4.
   - Each link: `rp_id`, `resource_id`, `action` match the request.
   - Each link: `delegator_public_key` of link `i+1` equals `delegate_public_key` of link `i`.
   - Each link: scopes ⊆ parent scopes (parent = RP grants for root, previous link scopes for subsequent links).
   - Each link: Dilithium3 signature over `canonical_delegation_body` is valid.
   - Each link: `now < expires_at`.
6. Root delegator key: enrolled at RP and not revoked.
7. Agent key: `agent_proof.public_key == chain.last().delegate_public_key`.
8. Agent signature: Dilithium3 signature on `canonical_request(request)` is valid.
9. Challenge consumed (before remaining checks, so probing is impossible).
10. Human approval gate: if any link has `requires_human_approval`, `approve_challenge(challenge_id)` must have been called.
11. `max_uses`: each link's usage count is decremented; if already 0, reject.

---

## Security Properties

| Property | Enforced by |
|----------|------------|
| Scopes only narrow in chain | `validate_chain` scope subset check at each link |
| Agent cannot fabricate delegation | Dilithium3 signature on each link |
| Revoked human key blocks all delegations | Root delegator fingerprint check |
| Expired delegation rejected | `now >= expires_at` check per link |
| Replay of delegated proof blocked | Challenge consumed on first verify |
| High-risk actions gate on human signal | `requires_human_approval` + `approve_challenge` |
| One-time delegations enforceable | `max_uses` counter on RP |
| Agent key ≠ human identity | Agent key never added to `enrolled_keys` |

---

## What Is Not Claimed

| Property | Status |
|----------|--------|
| Persistent max_uses across restarts | ❌ In-memory only; must be stored in durable state for production |
| Cross-RP delegation | ❌ Not in scope; each delegation is bound to a specific `rp_id` |
| Delegation to anonymous agent | ❌ Agent's public key is visible to the RP |
| Capability revocation without key revocation | ❌ There is no per-delegation revocation list; revocation requires revoking the root delegator's key |

---

## Return Gates Before Production

- [ ] Durable `delegation_uses` storage (database row, not in-memory HashMap).
- [ ] Per-delegation revocation list (revoke a single delegation without rotating the human's key).
- [ ] Delegation bootstrap ceremony — how does the human securely provision the agent's public key?
- [ ] Spending limits for financial actions — `max_uses` is a count limit; a monetary limit requires a separate `max_amount` field and RP-side accounting.
- [ ] Independent security review of the delegation chain validation logic.
- [ ] Cross-platform canonical delegation bytes test vectors.

---

## References

- `dis-core/src/delegation.rs` — types, encoding, chain validation, 9 tests
- `dis-core/src/verifier.rs` — `verify_delegated`, `approve_challenge`
- `docs/DIS-PRIV-001-unlinkable-presentation.md`
- `docs/DIS-PQ-001-pq-security-inventory.md`
