# DIS-PQ-001 — Post-Quantum Security Inventory

**Status**: v0.1 prototype — ⚠️ Return before production deployment  
**Date**: 2026-10-21  
**Scope**: `dis-core` crate (DIS-KS-V1 / SUITE_ML_DSA_65)

---

## Primitive Inventory

| Primitive | Algorithm | PQ-Safe? | Standard | Notes |
|-----------|-----------|----------|----------|-------|
| Signature | ML-DSA-65 (Dilithium3) | ✅ Yes | NIST FIPS 204 | 128-bit post-quantum security level. Used for all holder proofs. |
| Hashing (key fingerprint, API keys, reg tokens) | SHA-256 | ✅ Yes | FIPS 180-4 | 128-bit collision resistance at 256-bit output; quantum-safe. |
| Hashing (canonical transcript digest) | SHA-256 | ✅ Yes | FIPS 180-4 | `request_digest` is diagnostic only; no security claim follows from it alone. |
| Transport (vendor server ↔ wallet) | TLS 1.2/1.3 | ⚠️ Partial | RFC 8446 | TLS 1.3 key exchange (X25519/P-256) is classically secure but not PQ-safe. Hybrid PQ key exchange (e.g., X25519Kyber768) not yet deployed. |
| Key agreement (enrollment, rotation) | None (out-of-band) | N/A | — | Public key delivered directly; no in-band Diffie-Hellman. |
| Zero-knowledge / anonymous credential | Not implemented | N/A | — | No ZK primitive used in DIS-KS-V1. |
| Wallet key recovery | Not implemented | N/A | — | Out of scope for v0.1 prototype; return before production. |

---

## Downgrade Resistance

`RelyingParty` enforces a `min_suite_id: u16` floor:

- Checked in **`issue()`**: requests below the minimum are rejected with `VerifyError::DowngradedSuite` before a challenge is issued.
- Checked in **`verify()`** (belt-and-suspenders): replay of a lower-suite request is rejected even if it somehow bypassed `issue()`.
- Current floor: `SUITE_ML_DSA_65 = 1`. Raise to a new constant when migrating to a stronger suite.

Wire-format integrity is enforced by frozen **golden test vectors** in `dis-core/src/lib.rs`:
- `golden_vector_no_operation_digest`
- `golden_vector_with_operation_digest`

Any accidental encoding change (field reordering, length prefix width, domain change) breaks these tests immediately. Cross-platform implementations MUST produce identical bytes for the same inputs.

---

## Migration Path

1. **New suite**: add `SUITE_ML_DSA_87: u16 = 2` (or higher) in `lib.rs`.
2. **Bump domain**: if the wire format changes, increment `DOMAIN` (e.g., `b"DIS-KS-V2\0"`) so old signatures remain verifiable with the old constants.
3. **Golden vectors**: add a new frozen test for the new suite/domain; do not modify existing vectors.
4. **RP policy**: raise `min_suite_id` in each `RpPolicy` after all enrolled wallets have migrated.
5. **Key rotation**: use `rotate_key(old_pk, new_pk)` to atomically replace keys; old keys are revoked and cannot be replayed.
6. **TLS**: when PQ hybrid TLS (RFC 9180 / HPKE or X25519Kyber768) becomes widely supported in the Rust ecosystem, upgrade the transport layer. This is the main gap remaining.

---

## Return Gates Before Production

- [ ] Independent cryptographic review of the canonical encoding and `canonical_request` implementation.
- [ ] PQ hybrid TLS deployed on all `rp_origin` endpoints.
- [ ] Wallet key recovery mechanism designed and reviewed.
- [ ] Formal threat model covering multi-vendor cross-authorization flows.
- [ ] Golden vectors validated by at least one independent client implementation (non-Rust).
- [ ] External audit of `dis-vendor-server` authentication stack.

---

## References

- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- NIST FIPS 180-4 — Secure Hash Standard (SHA-256)
- RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
- `docs/DIS-KS-001-keystone-security-interoperability-spec.md`
- `dis-vendor-server/SECURITY-ROADMAP.md`
