# DIS-KS-001B — Vendor-Independent Keystone Protocol

**Status:** DRAFT v0.1 — proposed protocol; NOT implemented, tested, independently audited or declared PQ-secure end-to-end.  
**Date:** 2026-10-19  
**Parent:** DIS-KS-001 / DIS-KS-001A.  
**Compatibility:** Existing Qattice `DIS-AUTH-V1` and `/api/auth/*` MUST remain unchanged during initial work. This document specifies a distinct `DIS-KS-V1` profile, not a wire-compatible revision.

## 1. Non-negotiable properties

1. An independent RP (relying party) MUST verify a DIS proof without Qattice nodes, QCB tokens or DIS-operated central services.
2. Proof of private-key possession is **authentication**, not permission. RP authorization is a separate, local policy decision.
3. A single holder can maintain separate RP relationships, with independent permissions and revocation.
4. A proof MUST be bound to the actual RP, action, resource, nonce, expiry, and—where applicable—exact transaction parameters.
5. RPs MUST NOT receive a common globally stable holder identifier by default. **A single shared signing public key is itself a cross-RP correlator**; an RP-specific key pair alone is not a cryptographic proof of one underlying identity. Continuity or credential-binding claims require a reviewed mechanism.
6. Recovery, compromise and algorithm migration MUST NOT silently reactivate retired authority.
7. QPC/personhood is OPTIONAL and separate; a DIS key does not prove unique humanity.

## 2. Actors and trust

- **Wallet:** stores keys, authenticates RP request, obtains user consent, constructs holder proof.
- **RP:** authenticates its own identity to wallet, issues challenge, verifies holder proof, applies local permissions, maintains replay/revocation state.
- **Issuer (optional):** asserts attributes or capabilities accepted under RP-specific issuer policy.
- **Delegate (optional):** exercises attenuated authority from a holder under RP policy.
- **Qattice adapter (optional):** bridges a successful RP decision to chain-specific features; not in core verification.

**Critical distinction:** The wallet must authenticate the RP via a trusted origin / signed, trusted metadata / verified app association before displaying a request as genuine. A self-asserted `rp_id` inside a QR payload is not proof of RP identity.

## 3. DIS-KS-V1 messages (logical schema)

These are **abstract data models**, not a finalized serialized format. Field types, canonical encoding, limits, Unicode normalization, origin semantics and cryptographic transcript are **OPEN** pending review; implementations MUST NOT sign ad hoc JSON.

### 3.1 RPChallenge

```text
RPChallenge {
  protocol_version: "DIS-KS-V1",
  suite_id: <allowlisted suite>,
  rp_id: <authenticated relying-party identifier>,
  rp_origin: <verified origin or app association>,
  challenge_id: <at least 128 bits CSPRNG, opaque>,
  nonce: <at least 128 bits CSPRNG>,
  issued_at: <UTC instant>,
  expires_at: <UTC instant>,
  resource_id: <RP-defined canonical resource>,
  action: <RP-defined canonical verb>,
  scopes: <ordered canonical set>,
  request_digest: <digest of exact business operation, when relevant>,
  policy_id: <RP policy version identifier>,
  constraints: <typed spending/delegation/time constraints, when relevant>
}
```

**Requirements:** An RP MUST use fresh unpredictable nonces, enforce bounded TTL, and atomically consume a successful challenge. A valid proof for RP-A MUST fail at RP-B. For sensitive operations, `request_digest` MUST commit to the precise amount, recipient, asset, network and other decision-critical fields. Scope text alone is not sufficient for transactional authorization.

### 3.2 HolderPresentation

```text
HolderPresentation {
  protocol_version,
  challenge_id,
  rp_id,
  suite_id,
  rp_specific_subject_or_proof,
  holder_key_or_key_reference,
  holder_signature_or_presentation_proof,
  credentials: [optional RP-trusted issuer statements],
  delegation_chain: [optional bounded capabilities],
  status_evidence: [optional verifiable status data]
}
```

**Requirements:** The signed/proven transcript MUST bind every material challenge field and presentation context; RPs MUST reject unrecognized critical fields and suites. For privacy, avoid disclosing a master key, global DID, globally stable address, or common credential serial number. A credential signed once and shown verbatim to many RPs may be linkable; claim selective disclosure or unlinkability only when the actual construction supports it.

### 3.3 RPDecision (local)

```text
RPDecision {
  challenge_id,
  authenticated: bool,
  authorized: bool,
  granted_scopes: [canonical set],
  decision_policy_id,
  reason_code,
  expires_at,
  audit_reference
}
```

**Requirements:** `authenticated=true` MUST NOT automatically set `authorized=true`. The RP MUST enforce the decision on its protected resource and bind any issued session to the verified proof, policy and lifetime. Error messages MUST NOT leak unrelated identity or issuer metadata.

## 4. Validation algorithm (normative outline)

1. Parse with strict size limits and reject malformed/unknown-critical encodings.
2. Locate the outstanding challenge in RP-controlled replay storage; check freshness and authentic RP audience/origin.
3. Recompute the canonical transcript and verify allowlisted cryptographic suite and holder signature/proof.
4. Verify credential issuer chain and proof-to-holder binding if credential-based rights are claimed.
5. Validate revocation/status freshness and any continuity or delegation chain.
6. Apply RP-owned policy to exact resource/action/transaction; attenuate delegated authority.
7. Atomically consume challenge on successful cryptographic verification; reject duplicates.
8. Only after authorization, issue a narrowly scoped session/capability and enforce it server-side.

**Fail-closed rules:** Unknown suite, audience mismatch, expired/replayed challenge, untrusted issuer, invalid signature, revoked authority, excessive delegation, or insufficient policy evidence MUST deny access. A policy may allow limited low-risk offline use with explicit freshness bounds; high-risk authorization MUST fail closed when status is stale.

## 5. Cryptographic profile and transcript decisions

**Candidate:** ML-DSA-65 signature verification, reusing audited library interfaces from Chain Forge after independent test vectors and crypto review. The existing wallet signs `ML-DSA(SHA-256(DIS-AUTH-V1 payload))`; this is a documented DIS-specific prehash convention, not automatically interchangeable with standard ML-DSA message signing or HashML-DSA. **Do not silently copy it into DIS-KS-V1.**

Before code: choose a normative canonical encoding (e.g. deterministic CBOR with an exact profile), a domain-separated transcript, suite identifiers, key formats, error semantics, cross-language golden vectors, algorithm negotiation, and downgrade prevention. No post-quantum anonymity or ZK proof is specified here. Cryptographic review must assess whether and how to bind multiple RP-specific identities to a recoverable holder without enabling cross-RP correlation.

## 6. Continuity, revocation, recovery

A holder's logical identity is a set of independently authorized RP relationships, **not** one eternally reusable signing public key. Each RP MUST define how to accept key rotation and recovery, how to retire old keys, how to distribute revocation, and when reauthorization is required. Recovery evidence MUST NOT be solely a signature by a key reported compromised. Each RP MUST prevent rollback to an older key epoch.

**Cross-RP continuity is an unresolved design challenge:** No protocol step in this draft claims to prove that independent pseudonyms belong to the same person without introducing a correlation channel. Evaluate issuer-mediated blinded credentials, pairwise derived keys, or reviewed anonymous credentials against security and PQ goals before choosing.

## 7. Interoperability policy

- **OpenID4VP / W3C VC:** prefer existing wallet presentation patterns and standard credential data models where compatible; use adapters, not undocumented forks.
- **OIDC/OAuth 2.0:** RPs MAY exchange successful DIS proof for locally issued, tightly scoped sessions; DIS does not replace token lifecycle or web origin protections.
- **WebAuthn/FIDO2:** retain existing passkeys as a practical authentication option; do not claim present-day passkeys are universally post-quantum.
- **Capability authorization:** support signed attenuation and revocation as a future extension, not a v0.1 implemented guarantee.
- **Standards gap register:** for every custom field, document the missing standard feature, alternatives, compatibility cost and prior art.

## 8. Three-RP reference demonstration

| RP | Example domain | Local permission | Required rejection |
|---|---|---|---|
| A | game service | `game:play` | B/C permissions, altered resource, replay |
| B | document service | `document:read` | A/C permissions, revoked grant, replay |
| C | Qattice-facing service | `tx:submit` | A/B permissions, modified tx digest, replay |

RP-C may use Qattice as its own backend; RP-A and RP-B MUST function with no Qattice dependency. The wallet MAY use three independent RP-specific keys as an initial privacy *baseline*, but this does **not** yet prove a single unlinkable cryptographic identity or secure cross-RP recovery. Treat that as a separate research gate.

## 9. Required test vectors

- **TV-01** canonical encode/decode parity across wallet and RP.
- **TV-02** valid ML-DSA challenge response for each RP.
- **TV-03** wrong RP audience/origin.
- **TV-04** replay, expired, unknown and concurrently consumed nonce.
- **TV-05** altered action/resource/scope/policy/transaction digest.
- **TV-06** unknown algorithm, invalid key, malformed encoding and downgrade.
- **TV-07** trusted vs untrusted issuer and revoked/stale credential.
- **TV-08** independent per-RP authorization, revocation and fail-closed behavior.
- **TV-09** delegated authority attenuation and expiration.
- **TV-10** key rotation, recovery hijack and rollback denial.
- **TV-11** RP collusion/linkability evaluation with defined threat model.
- **TV-12** standalone RP verification without Qattice.

**Pass conditions for KS-001B (design gate):** stable message schema; normative canonical encoding and signing transcript; authenticated RP identity model; issuer/holder-binding and revocation model; explicit privacy and recovery limits; golden and negative test vectors; design review signoff. This draft does **not** meet all of these conditions.

## 10. Decisions required before implementation

| Decision | Recommended direction | Status |
|---|---|---|
| RP origin binding | Verified HTTPS origin / app association; signed metadata for QR handoff | OPEN |
| Canonical encoding | Versioned deterministic CBOR profile with fixed integer labels | OPEN |
| Signature mode | Reviewed direct ML-DSA transcript or standards-conformant HashML-DSA where appropriate | OPEN |
| Credential format | Standards-compatible VC/OpenID4VP adapter, explicit issuer trust | OPEN |
| Pairwise privacy | RP-specific identifiers, with separate research on unlinkable continuity | OPEN |
| Revocation | RP-local policy with bounded freshness and explicit offline failure | OPEN |
| Recovery | Per-RP key epochs and independently authenticated recovery policy | OPEN |
| Delegation | Typed signed capabilities with strict attenuation | OPEN |

## 11. Immediate next actions

1. Conduct design review and lock `RPChallenge`/presentation canonical serialization.
2. Write reference golden vectors and independent decoder tests **before** accepting any signatures.
3. Create standalone `dis-core` Rust crate and three mock RP policy fixtures, preserving old node APIs.
4. Implement signature verification, nonce consumption and exact-action binding; then layer issuer trust, privacy and continuity separately.
5. Run negative tests, fuzz parsing, benchmark, and request independent security review.

**No production readiness, patentability, quantum-safe unlinkability, or standards conformance is claimed.**
