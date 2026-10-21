# DIS-PRIV-001 — Unlinkable Presentation and Minimal Disclosure

**Status**: v0.1 prototype — ⚠️ Return before production deployment  
**Date**: 2026-10-21  
**Scope**: `dis-core` crate (DIS-KS-V1 / SUITE_ML_DSA_65)

---

## Privacy Properties Claimed

These properties are **demonstrated by the test suite**, not implied by the protocol name.
Claims match what the code actually enforces.

| Property | Status | Where enforced |
|----------|--------|----------------|
| No shared public key across vendors | ✅ Structural | `DemoWallet`: separate ML-DSA-65 keypair per `rp_id` |
| No shared key fingerprint across vendors | ✅ Structural | Distinct keys → distinct SHA-256 fingerprints |
| Cross-vendor proof submission rejected | ✅ Protocol | `canonical_request` binds `rp_id`, `rp_origin`, `policy_id` |
| Scope minimality — RP rejects unauthorized scopes | ✅ Enforced | `verify()`: every scope must be in the RP's `grants` set |
| Nonce and challenge freshness | ✅ Protocol | `issue()` overwrites `challenge_id` and `nonce` from CSPRNG |
| Same-vendor sessions linkable (expected) | ✅ Expected | Same enrolled key → same fingerprint; RP can correlate its own sessions |

---

## What Each RP Learns from a Verified Proof

A successfully verified `HolderProof` discloses the following to the receiving RP:

```
DisclosureInfo {
    key_fingerprint:  SHA-256 of this vendor's public key (vendor-specific)
    resource_id:      the resource the holder accessed
    action:           the action authorized
    scopes:           the scope list from the request (all in RP's grant)
    issued_at:        Unix timestamp of the challenge
}
```

The RP does **not** learn:
- The holder's public key or identity at any other vendor
- Any other vendor's enrolled key or fingerprint
- Any other vendor's resource/action grants
- Whether the holder has authenticated to any other RP

`dis_core::privacy::disclosure_info()` makes this contract explicit and testable.

---

## Unlinkability Mechanism

Two vendors (Vendor A, Vendor B) cannot link the same holder across their systems by comparing proofs because:

1. **Distinct keypairs**: `DemoWallet::provision()` calls `dilithium3::keypair()` fresh for each `rp_id`. The public keys enrolled at Vendor A and Vendor B are independent ML-DSA-65 keypairs.

2. **Transcript binding**: `canonical_request` encodes `rp_id` and `rp_origin` into the signed bytes. A proof generated for Vendor A's transcript is cryptographically invalid for Vendor B's transcript — the signature check fails before any key check.

3. **No global identifier**: The `Request` struct contains no holder-global public identifier. The `challenge_id` and `nonce` are issued per-request by the RP from a CSPRNG; neither can be used to correlate across vendors.

**Demonstrated by**: `privacy::tests::cross_vendor_public_keys_are_distinct`, `privacy::tests::cross_vendor_proofs_are_not_linkable`, `privacy::tests::cross_vendor_proof_submission_rejected`.

---

## Scope Minimality

The RP enforces minimal disclosure at `verify()`:

```rust
if request.scopes.iter().any(|scope| {
    !self.policy.grants.contains(&(resource_id, action, scope))
}) {
    return Err(VerifyError::Unauthorized);
}
```

- A wallet cannot include a scope the RP did not grant for the requested `(resource, action)` pair — the RP rejects it with `Unauthorized`.
- The wallet presents only the scopes needed for the specific operation; no blanket "all scopes for this vendor" presentation is possible.
- **Demonstrated by**: `privacy::tests::rp_rejects_unauthorized_scope`.

---

## What Is Not Claimed

| Property | Status | Notes |
|----------|--------|-------|
| Anonymous credentials / ZK proofs | ❌ Not implemented | ML-DSA signatures are pseudonymous per-vendor, not zero-knowledge |
| IP / metadata unlinkability | ❌ Not in scope | The RP observes the holder's IP, timing, and request metadata at the transport layer |
| Issuer unlinkability | ❌ Not in scope | There is no issuer in DIS-KS-V1; enrollment is RP-local |
| Multi-session unlinkability within one vendor | ❌ By design | The same enrolled key is reused across sessions at the same vendor; the RP can link its own sessions |
| Selective disclosure of credential attributes | ❌ Not implemented | The `scopes` field is the disclosure unit; no BBS+ or Merkle-tree attribute proofs |
| Hardware-bound key protection | ❌ Not in scope | Key custody is wallet-application responsibility |

---

## Return Gates Before Production

- [ ] Independent cryptographic review of the unlinkability claim against a formal threat model.
- [ ] Key enrollment authentication (production `enroll_test_key` is replaced with a bootstrap ceremony; see `verifier.rs` doc comment).
- [ ] Unlinkability property verified by independent cross-platform test (non-Rust client using the same DIS-KS-V1 wire format).
- [ ] Transport-layer metadata leakage analysis (IP, timing correlation) included in security assessment.
- [ ] Decision on whether multi-session within-vendor unlinkability is required (would need per-request ephemeral keys or ZK proofs).
- [ ] Privacy threat model for the optional `operation_digest` field (the digest reveals what transaction was authorized; RP learns the operation hash even if not the full operation).

---

## References

- `dis-core/src/privacy.rs` — `are_linkable()`, `disclosure_info()`, and 6 privacy tests
- `docs/DIS-KS-001B-vendor-independent-protocol.md`
- `docs/DIS-PQ-001-pq-security-inventory.md`
- NIST FIPS 204 — ML-DSA (Dilithium3)
