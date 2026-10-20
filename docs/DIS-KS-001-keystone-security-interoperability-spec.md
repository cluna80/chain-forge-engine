# DIS-KS-001 — Keystone Security and Interoperability Specification

**Status:** DRAFT v0.1 — research/design only; not an implemented, audited, or standardized protocol  
**Date:** 2026-10-19  
**Owner:** Digital Identity Stone (DIS) / Qattice reference integration  
**Normative language:** MUST, MUST NOT, SHOULD, MAY are design requirements for future conforming implementations, not claims about current code.

## 1. Purpose and product boundary

DIS is a vendor-independent, holder-controlled identity and scoped-authorization protocol. One underlying holder can establish separate, privacy-preserving relationships with multiple relying parties (RPs), each of which independently controls access to its own resources.

DIS is **not** a global master access token, a universal permission issuer, a proof that an identity belongs to a unique human, or a replacement for all existing login standards. Qattice is the first reference integration, **not** a required runtime, settlement layer, or trust anchor. QPC is a separate optional human-personhood credential.

**Target demonstration:** An Android DIS wallet authenticates to three independently operated test RPs with different permissions; compromise or revocation of one RP authorization does not grant or remove access at unrelated RPs; wallet key rotation preserves legitimate identity continuity under a secure recovery process.

## 2. Scope

**In scope:** cryptographic holder control, verifier/RP discovery and trust, credential presentation, authorization request binding, RP-specific pseudonyms, per-RP policy enforcement, revocation, recovery, delegation, algorithm agility, integration adapters, and test vectors.

**Out of scope for v0.1:** proving one-human-one-credential, issuing government identity, production certification, universally trusted issuers, a new post-quantum zero-knowledge primitive, or a mandatory Qattice blockchain dependency.

## 3. Roles and trust boundaries

- **Holder:** person, organization, machine, or agent controlling one or more keys.
- **DIS Wallet / Holder Agent:** local custody, credential presentation, challenge response, recovery and consent UI.
- **Issuer:** signs claims/capabilities under a defined trust policy. Issuer trust is RP-specific.
- **Relying Party (RP):** owns resource, defines policy, validates proof, and enforces the decision.
- **Delegator / Delegate:** optionally issues and exercises scoped capabilities; an agent does not inherit human status.
- **Registry / Resolver (optional):** distributes issuer metadata, status and key history. No universal registry is mandatory.
- **QPC authority (optional):** separately assesses personhood; DIS verification MUST NOT imply QPC eligibility.

Trust is **not transitive**: holder control does not imply issuer trust; issuer trust does not imply permission; permission at RP-A does not imply permission at RP-B; authentication does not imply personhood.

## 4. Security goals (KS-SG)

| ID | Normative security goal |
|---|---|
| SG-01 | Every authorization MUST bind the holder proof to a canonical RP audience, resource, action, challenge/nonce, issue time, expiration, protocol version and algorithm suite. |
| SG-02 | Every RP MUST independently validate issuer trust, credential status, policy, signature/proof, key status, replay state and requested scope before enforcing access. |
| SG-03 | RP-A credentials/capabilities MUST NOT authorize RP-B unless RP-B explicitly trusts and accepts a narrowly defined cross-RP delegation. |
| SG-04 | RP-specific pseudonyms MUST be unlinkable by unrelated RPs under a stated adversary model; a shared public root key/identifier MUST NOT be transmitted by default. Network and timing metadata leakage MUST be documented. |
| SG-05 | Keys MUST be generated/held locally where feasible; private signing keys MUST NOT be sent to RPs. Recovery MUST invalidate compromised key authority without erasing valid continuity. |
| SG-06 | Revocation MUST have explicit effective-time, freshness, caching and offline-failure semantics. High-risk operations MUST fail closed when current authorization cannot be established. |
| SG-07 | Delegation MUST be attenuating: no delegate may expand its parent's scope, audience, amount, duration or authority. |
| SG-08 | Signature/credential/proof algorithms MUST be identified and allowlisted; downgrade and algorithm-confusion attacks MUST fail. Migration MUST bind old/new keys under a reviewed continuity policy. |
| SG-09 | Qattice, QCB tokens, or a DIS-hosted service MUST NOT be mandatory for standalone verification. |
| SG-10 | Implementations MUST distinguish cryptographic authentication from claims of human uniqueness and from regulatory identity assurance. |

## 5. Keystone authorization protocol — conceptual v0.1

### 5.1 Canonical authorization request

The RP constructs a canonical, unambiguous request (serialization to be selected and versioned):

```text
KeystoneRequest {
  version, suite_id, rp_id, audience, resource_id, action,
  requested_scopes, challenge_nonce, issued_at, expires_at,
  transaction_digest?, policy_id?, max_amount?, delegation_context?
}
```

**Requirements:** audience is an authenticated RP origin or stable verified RP identifier; resource and action have RP-defined canonical meanings; nonce is unpredictable, unique within RP freshness window and single-use for sensitive actions; expiry is bounded; transaction digest is mandatory for authorizing a particular financial operation; canonicalization MUST prevent ambiguous or alternate encodings.

### 5.2 Holder presentation

The wallet validates RP identity and request contents, obtains appropriate user consent or pre-authorized agent policy, and returns a proof of key control plus minimally disclosed credentials/capabilities. It MUST NOT reveal a global root identifier unless an explicitly selected policy requires it. An RP-specific pseudonym or credential-derived unlinkable proof MUST be cryptographically bound to the same authorized holder. Simply hashing a public master key with RP name is **not** assumed to provide adequate privacy.

### 5.3 RP verification and enforcement

The RP verifies (1) canonical request and intended audience, (2) holder proof and allowed algorithms, (3) trusted issuer/credential chain, (4) credential validity and revocation freshness, (5) request nonce and anti-replay, (6) local authorization policy and delegation limits, and (7) transaction-specific user approval where required. The RP returns **ALLOW** only if every mandatory check succeeds; otherwise **DENY** with non-sensitive reason codes. The RP remains the final enforcement point; a DIS proof is not itself access.

### 5.4 Example cross-vendor behavior

- RP-A gaming: `play:ranked`; no treasury permissions.
- RP-B enterprise: `documents:read`; no admin access.
- RP-C Qattice application: `wallet:submit_signed_tx`; no consensus vote without separate QPC eligibility.
- Revoking RP-B authorization MUST NOT revoke RP-A/RP-C relationships unless a separately specified root-key compromise or global suspension policy applies.

## 6. Cryptographic design and post-quantum claims

ML-DSA-65 (FIPS 204) is a candidate authentication signature suite; use vetted implementations and explicit domain separation. DIS MUST inventory every cryptographic dependency: issuer signatures, presentation proofs, credential commitments, key establishment, transport, device backup, recovery, hash functions and revocation mechanisms. **ML-DSA on login messages alone does not establish end-to-end post-quantum security.**

No claim of post-quantum unlinkable zero-knowledge credentials is authorized until a reviewed construction, assumptions, public inputs and test vectors exist. Conventional Groth16/BLS12-381 proof systems MUST NOT be silently labeled post-quantum secure. Specify classical/hybrid/PQ security levels honestly. Choose canonical encoding and signature suites through a separate reviewed crypto profile.

## 7. Identity continuity and recovery

The stable identity is a **logical continuity relationship**, not an eternally trusted private key. A key-change event MUST identify the affected relationship(s), authenticated continuity evidence, effective version, old-key retirement, revocation propagation and rollback protections. Recovery after suspected compromise MUST NOT rely solely on the compromised key. Recovery authorities, quorum rules, delays, social recovery or device attestations are policy choices requiring a separate threat model. RP-specific authorization MAY require explicit reapproval after recovery.

## 8. Existing standards: reuse and gaps to validate

| Standard/system | Reuse / interoperability intent | DIS-specific gap or research question |
|---|---|---|
| OAuth 2.0 / OpenID Connect | Integrate existing RP sessions and authorization gateways; avoid inventing web login/session management | How to bind holder-controlled PQ proof to token/session issuance without token substitution? |
| FIDO2 / WebAuthn / passkeys | Preserve phishing resistance, RP-origin binding, UX and platform authenticator strengths | How to interoperate with current passkeys while keeping PQ claims honest? |
| W3C Verifiable Credentials / DIDs | Credential data model, issuer/holder/verifier roles and identifier resolution where useful | How to support vendor-specific unlinkability, lifecycle and RP-specific policies? |
| OpenID4VP | Credential presentation request/response, verifier binding, wallet interoperability | Which standardized flows can carry DIS PQ credentials without proprietary incompatibility? |
| Capability authorization (e.g. macaroons / UCAN-style patterns) | Attenuating, scoped and delegable capabilities | How to cryptographically bind delegation to the holder, audience and exact action? |
| Enterprise IAM (e.g. Entra/Okta) | Federation, policy, revocation and operational controls | Can DIS complement existing IAM instead of requiring replacement? |

**Novelty rule:** Portability, multiple RPs, scoped credentials, unlinkable identifiers, passkeys and PQ signatures individually have prior art. DIS-KS-001 makes **no patentability or novelty claim**. A defensible differentiator requires a concrete new mechanism or measurable implementation/security advantage, compared against published prior art.

**Primary standards references (verify exact profiles and versions during design review):**
- NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
- W3C Verifiable Credentials Data Model: https://www.w3.org/TR/vc-data-model-2.0/
- W3C Web Authentication: https://www.w3.org/TR/webauthn-3/
- OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- OAuth 2.0: https://www.rfc-editor.org/rfc/rfc6749
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html

## 9. Threat model

**Adversaries:** malicious RP, malicious issuer, stolen phone, compromised holder key, compromised delegate, colluding RPs, compromised registry, network attacker, malicious verifier, clock manipulation, stale status data and downgrade attacker.

**Attack cases to explicitly test:** replay; cross-audience substitution; confused deputy; privilege escalation; altered resource/action/amount; forged issuer; revoked credential; malicious RP phishing; leaked cross-RP correlator; delegate scope widening; key-rotation rollback; recovery hijack; old-key reuse; suite downgrade; offline revocation bypass; duplicate credential enrollment (QPC only, separate track).

**Limitations:** Protocol cannot guarantee anonymity against network metadata, human uniqueness without independent enrollment evidence, or immediate revocation when an RP is intentionally offline unless access is denied.

## 10. Required conformance tests / exit criteria

| Test ID | Test | PASS condition |
|---|---|---|
| KS-T01 | Three independent RPs | One wallet authenticates to A/B/C; each RP grants only its own configured permissions. |
| KS-T02 | Cross-RP credential substitution | RP-A-scoped proof rejected by RP-B. |
| KS-T03 | Tamper request fields | Changing audience, resource, action, amount, nonce or expiry invalidates authorization. |
| KS-T04 | Replay | Reusing a consumed challenge for a protected action rejected. |
| KS-T05 | Selective revocation | Revoking RP-B credential blocks B; unrelated A/C credentials remain valid. |
| KS-T06 | Key rotation | New key accepted only after continuity authorization; retired key denied. |
| KS-T07 | Stolen-device recovery | Compromised key cannot silently regain access or roll back revocation. |
| KS-T08 | Privacy/linkability | No shared stable identifier exposed to colluding unrelated RPs; metadata caveats documented and tested. |
| KS-T09 | Delegation | Agent cannot widen scope, amount, audience or expiration. |
| KS-T10 | PQ suite integrity | Unsupported/downgraded/ambiguous algorithm identifiers rejected; classical dependencies documented. |
| KS-T11 | Standalone operation | RP verifies authorization without a Qattice node, QCB token or DIS-operated hosted endpoint. |
| KS-T12 | Interoperability | At least one documented integration path with standard IAM/presentation tooling, with compatibility and limitations tested. |

**Exit gate for DIS-KS-001 (specification only):** approved threat model, defined request/presentation/decision semantics, algorithm and privacy profiles identified or explicitly blocked, standards gap analysis, versioned test vectors plan, and documented open decisions. Passing implementation tests belongs to DIS-KS-002 / DIS-SEC-001 and MUST NOT be inferred from spec publication.

## 11. Open decisions (not silently resolved)

1. Exact RP trust discovery and origin binding, especially native/mobile apps.
2. Credential envelope and interoperable presentation profile (VC/OpenID4VP vs a documented adapter).
3. Privacy-preserving RP pseudonym and PQ-capable presentation construction.
4. Cryptographic suite identifiers, domain separation, canonical encoding and signature interoperability.
5. Issuer discovery, trust anchors, credential status and revocation freshness.
6. Recovery quorum, compromise handling and whether RPs must reauthorize.
7. Offline authorization policy and maximum credential lifetime.
8. Agent delegation encoding and transaction-specific consent UX.
9. Conformance test vectors, reference test RP implementations and benchmarks.
10. Licensing, standards participation, independent review and commercial claims.

## 12. Proposed work order

1. Review this v0.1 spec against current `chain-forge-identity`, `chain-forge-wallet` and DIS node authorization flows; record actual implemented vs missing features.
2. Select standards-compatible wire formats and formalize canonical request/signature transcript.
3. Prototype three independent RP adapters with a DIS wallet.
4. Validate negative tests, privacy and recovery, then commission independent cryptographic review.
5. Only after evidence, promote a subset of this draft to normative DIS v1.0.

**Cross-reference:** `ROADMAP.md` → DIS Standalone Product; QPC and consensus-personhood tracks remain independent.
