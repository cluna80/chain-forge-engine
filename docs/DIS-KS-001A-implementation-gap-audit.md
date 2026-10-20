# DIS-KS-001A — Implementation Gap Audit

**Status:** Static source-review complete (initial pass); **not** a runtime security audit, test execution, or independent assessment.  
**Date:** 2026-10-19  
**Repository:** cluna80/chain-forge-engine (default branch).  
**Basis:** inspected `chain-forge-node/src/auth.rs`, `chain-forge-node/src/api.rs`, `chain-forge-wallet/src/lib.rs`, `chain-forge-identity/src/lib.rs`, `chain-forge-agents/src/lib.rs`, `chain-forge-personhood/src/lib.rs`, `chain-forge-node/tests/dis_parity.rs`, `chain-forge-node/tests/dis_auth_live.rs`, and `KNOWN_ISSUES.md`. This is a targeted audit, not a complete repository call-graph or dependency audit.

## Executive decision

**Reuse** the DIS-AUTH-V1 challenge signing/verification logic and test patterns as a *reference*, not as the final standalone protocol. **Do not** lift Qattice identity-tier gating, address-derived identity, global scope registry, or proof-of-personhood verifier defaults into independent DIS vendor authorization. Design a standalone DIS core and RP-specific authorization protocol, with a backwards-compatible Qattice adapter.

## Findings and evidence

| ID | Finding | Evidence | Assessment | Action |
|---|---|---|---|---|
| A01 | DIS-AUTH-V1 canonical binary challenge exists with version, chain ID, node audience, scope, random challenge ID and timestamps. | `chain-forge-node/src/auth.rs` `AuthChallenge`, `canonical_payload`; `chain-forge-wallet/src/lib.rs` `dis_canonical_payload`. | **Reusable with redesign.** No general resource/action/amount/transaction digest; chain-specific audience. | Define DIS-KS-V1 transcript with RP ID, action, resource, expiry, nonce, suite, transaction binding and canonical serialization. |
| A02 | ML-DSA-65 wallet challenge signing and node verification implemented; signature over SHA-256(canonical payload), explicitly a DIS-specific construction, not standard direct-message ML-DSA signing. | Wallet `sign_challenge`; node `verify_challenge_signature`. | **Existing crypto path, needs cryptographic review.** | Choose vetted signature profile and explicit suite/domain separation; compatibility test old vs new formats. |
| A03 | Challenge store uses OS randomness, TTL, consume-after-valid-signature and atomic consume to prevent replay within a node process. | `auth.rs` `generate_challenge_id`, `ChallengeStore::try_consume_verified`; `api.rs` verify route. | **Implemented for devnet challenge flow.** In-memory state not a cross-instance production replay guarantee. | Define shared/distributed nonce lifecycle and rate limits for scaled RPs. |
| A04 | Node restricts scopes using global `SCOPE_REGISTRY` and `IdentityAuthStatus` from Qattice explorer account tier/frozen flags. | `auth.rs` `scope_policy`, `authorize_scope`; `api.rs` account lookup. | **Not independent vendor authorization.** | Introduce RP-specific policy, issuer trust and resource/action decisions. |
| A05 | `key_binding_from_explorer` returns true based on account tier string alone; actual cryptographic proof is of control of the submitted key whose derived address is looked up. | `auth.rs` `key_binding_from_explorer`; `api.rs` derives address and looks up explorer account. | **Naming/trust-model risk.** The tier check itself is not a cryptographic key-binding verification; assurance depends on account enrollment/state integrity. | Specify explicit holder-key binding evidence, enrollment authority, and revocation. |
| A06 | The verify API returns derived Qattice address and account-based authorization results. | `auth.rs` `pq_address_from_key`, `VerifySuccess`; `api.rs` response. | **Cross-vendor correlation/privacy blocker.** Reusing one stable public key/address across RPs makes holder linkable. | Build RP-specific pseudonyms or reviewed unlinkable presentations; do not claim privacy from a simple deterministic public hash. |
| A07 | Personhood attestation `PopAttestation::verify(None)` skips cryptographic proof verification; `NoOpVerifier` always succeeds. | `chain-forge-identity/src/lib.rs` `PopProofVerifier`, `NoOpVerifier`, `PopAttestation::verify`. | **Critical separation requirement.** Not proof that live DIS login accepts arbitrary signatures; risk is trusting tier/personhood state sourced from unverified enrollment paths. | No no-op proof verifier in production enrollment; separate QPC entirely from DIS authorization; audit live call graph before production. |
| A08 | Agent capability enums, spend limits, suspend/revoke paths exist in Qattice agent crate. | `chain-forge-agents/src/lib.rs` `AgentCapability`, `SpendingLimits`, `AgentStore::check_capability`. | **Reusable concepts, not standalone vendor delegation.** | Design signed, audience-specific attenuating capabilities and agent proof chains. |
| A09 | Wallet key file supports encrypted local storage; DIS signer uses wallet ML-DSA key. | `chain-forge-wallet/src/lib.rs` `WalletKeyFile`, `generate_wallet`, `load_wallet`, `sign_challenge`. | **Existing reference wallet core.** Android hardware-backed custody and secure recovery not established. | Separate DIS key lifecycle from chain address; document Android custody limitations. |
| A10 | Cross-encoder parity and live DIS tests are present, including Verified/Provisional/frozen/permissionless behavior. | `chain-forge-node/tests/dis_parity.rs`, `chain-forge-node/tests/dis_auth_live.rs`. | **Test assets present, not executed in this audit.** | Preserve old regression tests; add three-RP negative tests and run CI. |
| A11 | No reviewed implementation found in examined paths for cross-vendor RP credentials, selective revocation, PQ unlinkable presentation, identity recovery, or key migration. | Targeted files above; search is not proof of repo-wide absence. | **Not established / pending.** | Search full call graph and implement after spec decisions. |
| A12 | `KNOWN_ISSUES.md` documents governance cross-chain replay risk due to missing chain ID in another signing path. | `KNOWN_ISSUES.md` §5. | **Adjacent issue, not DIS challenge bug.** | Track independently; use explicit audience/domain separation in new DIS messages. |

## Highest priority security questions

1. **Enrollment-to-key assurance:** Does any path create a Verified explorer account without a verified proof or trusted bootstrap? Audit `IdentityStore::verify_identity` callers, transaction execution, genesis and node state projection. A cryptographically valid DIS login does not imply trusted enrollment.
2. **Verifier-origin authentication:** The wallet currently signs JSON-provided `node_id`/`chain_id` without an independently established RP identity. Specify trusted RP metadata, origin binding, QR phishing defenses and user confirmation.
3. **Cross-RP privacy:** Current public-key-derived address is a correlator. A stable holder identity must not mean a globally exposed stable verifier identifier.
4. **Action-specific consent:** Scope string is insufficient to authorize a particular resource/transaction/amount; add exact-action binding.
5. **Recovery and revocation:** No demonstrated secure key migration or cross-vendor revocation propagation; specify compromise and offline policies.
6. **PQC claims:** ML-DSA challenge signing does not prove that ZK presentation, recovery, transport, or all issuer credentials are quantum safe.

## Recommended standalone module boundaries

```text
dis-core         canonical types, suite registry, transcript, verifier (no Qattice dependency)
dis-wallet       local keys, signing, presentation, continuity/recovery client
dis-rp           issuer trust, nonce store, revocation, RP policy and enforcement adapter
dis-interop      OpenID4VP/VC/OIDC/WebAuthn compatibility adapters
dis-qattice      Qattice account/QPC integration adapter only (optional)
```

**Compatibility rule:** Keep existing `DIS-AUTH-V1` and node API unchanged during extraction; introduce a versioned `DIS-KS-V1` profile and test both. No silent cryptographic format change.

## Proposed next implementation order

1. **KS-001B:** finalize wire transcript, RP trust model, issuer/holder bindings, status and privacy profile; publish golden vectors and negative vectors.
2. **KS-001C:** trace `verify_identity` / account registration to `ExplorerState` and close no-op production paths (QPC issue tracked separately).
3. **CORE-001:** implement standalone Rust verifier and RP adapter without Qattice dependencies.
4. **KS-002:** three independent RP demo with selective revocation, action binding and continuity.
5. **SEC-001:** adversarial testing, fuzzing, independent review.

## Exit status

**DIS-KS-001A initial source audit: documented.** No code execution, full call-graph audit, or security certification performed. The principal architecture gap is **RP-owned authorization with unlinkable identity continuity**, not ML-DSA signature generation.
