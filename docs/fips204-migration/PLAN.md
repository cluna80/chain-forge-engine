# Moving validators, DIS and the legacy paths to FIPS 204: design plan (for owner approval; no code changes)

**Status: proposal.** Nothing here is implemented. It is a consensus-affecting change on a fresh chain, so no code is written until the decisions in section 7 are made.

## 1. The gap
Signing v2 (transactions) already uses the FIPS 204 backend (`fips204` 0.5.0, pure ML-DSA-65, context `qattice/tx/v2`). Everything else that signs or verifies
with "ML-DSA" still calls the **pre-standard** `pqcrypto-dilithium` (`dilithium3`) code, which the K1 evaluation found does not interoperate with final FIPS 204
(0 of 45 signing vectors matched). The label `validator_scheme: "ml-dsa-65"` and the name `MlDsaScheme` say "ML-DSA", but on those paths they mean the old backend.

## 2. Inventory (audited at tree `main` + the open PRs, 2026-11-06; counts include inline test modules)
| Surface | Where | What uses the old code | Closed by design on a `qattice-v2` chain? |
|---|---|---|---|
| **Single choke point** | `chain-forge-crypto/src/lib.rs` (`MlDsaScheme`, `dilithium3::detached_sign / verify_detached_signature`) | everything below that goes through `SignatureScheme` | n/a |
| **Consensus votes / proposals / commit certificates** | `chain-forge-consensus` (`vote_signing_bytes`, `proposal_signing_bytes`, verification; tests in `mldsa_consensus`) | validator consensus keys on the supported ML-DSA devnet | **No: this is the main gap** |
| **Validator key load, PoP at registration** | `chain-forge-node/src/node.rs`, `keygen.rs` | key files hold `private_key` hex; PoP verified with `MlDsaScheme` | **No** |
| **Auth challenge verification** | `chain-forge-node/src/auth.rs` | `MlDsaScheme.verify` | **No** |
| **Legacy transactions** | `chain-forge-execution` (`SchemeId::MlDsa` legacy digest), `chain-forge-wallet` legacy container | legacy ML-DSA tx signatures | **Yes**: a v2 chain accepts only v2 signatures (tested: legacy-digest signature refused, V-07) |
| **Governance authority (personhood)** | `chain-forge-personhood/src/governance_authority.rs` and a demo binary | `MlDsaScheme` | No |
| **DIS** | `dis-core` (`delegation.rs`, `verifier.rs`, `wallet.rs`, `privacy.rs`), `dis-vendor-server`, `dis-test-helper`, `dis-wallet-android/dis-jni` | `dilithium3` called directly; persisted keys and issued delegations | No; **plus persisted data and an Android key store** |
| Evaluation tooling | `tools/k1-backend-eval` | both backends, as an oracle | not production |

## 3. Principles (all already locked by the owner)
1. **Fresh chain only.** `commitment_profile = "qattice-v2"` selects the standard backend everywhere. Legacy chains and their signatures are untouched.
2. **No hybrid, no fallback, no downgrade, no cross-acceptance.** A v2 chain never accepts an old-backend signature; a legacy chain never accepts a new one.
3. **Pure ML-DSA-65 over a complete canonical preimage**, with a distinct, versioned context per domain. Never mix with HashML-DSA or the raw internal interface.
4. **No silent key conversion.** Fresh genesis uses newly generated keys. Legacy keys are not carried over.
5. **Do not change `MlDsaScheme`'s meaning in place.** Add a separate standard implementation and select it by profile, so no legacy path changes behaviour by accident.

## 4. Proposed design
* **A second scheme beside the old one:** `MlDsa65Fips204Scheme` implementing the same `SignatureScheme` trait, taking an explicit context. Selected by a small `ConsensusSigner` / verifier abstraction keyed on the chain profile.
* **Distinct contexts (names are proposals):** `qattice/tx/v2` (exists), `qattice/vote/v2`, `qattice/proposal/v2`, `qattice/validator-pop/v2`, `qattice/auth/v2`, `qattice/dis/delegation/v2`, `qattice/dis/verifier/v2`. A signature for one domain must fail in every other (tested).
* **Keys:** validator key files move to the encrypted `qattice-key` format (this depends on PR #109, which is **blocked pending independent review**).
* **Activation:** the profile, not a flag. A node built without the standard backend must refuse a v2 genesis (already true for signing v2). The public-alpha gate gains a check that the chain's validator keys are the standard kind.

## 5. Phases (tests first, as in every earlier workstream)
| Phase | Deliverable | Evidence |
|---|---|---|
| P0 | this plan, approved | owner decisions (section 7) |
| P1 | `MlDsa65Fips204Scheme` + contexts + golden vectors, **no activation** | vectors from an independent implementation (the K1 oracle); wrong-context / wrong-domain / legacy-vs-standard negative tests; mutation checks; Windows |
| P2 | validator key files, PoP and auth challenge on the standard backend, behind the profile | negative tests; key-file tests; Windows |
| P3 | consensus votes, proposals, commit certificates and slashing evidence on the standard backend, **test-only feature first** | real four-node devnet on a v2 genesis with standard-backend validators; state-root agreement; equivocation evidence still detected and slashed |
| P4 | DIS (`dis-core`, vendor server, Android) | separate design (section 6); versioned envelope; data migration |
| P5 | combined integration test, independent review | independent cryptographic review of signing v2 + consensus + DIS |

## 6. Risks and open design questions
* **Hedged vs deterministic vote signing.** Signing v2 uses fresh randomness per signature. Two signatures of the same vote would then differ, so equivocation and slashing logic must compare the *messages signed*, not the signature bytes. Needs an explicit decision and a test.
* **Signature size and the quorum certificate.** A standard ML-DSA-65 signature is the same size as the old one (3,309 bytes), so bandwidth does not get worse, but PQ-HotStuff's signature-list QC ceiling still has to be measured.
* **Performance.** Verification speed of the standard backend versus the old one is unmeasured here. It matters for the node event loop (see the admission-cost note in PR #116).
* **Consensus-breaking.** Votes, proposals, PoP and slashing evidence all embed signatures. This is a hard change; it only ever applies to a fresh genesis.
* **PQ-HotStuff.** It is the target consensus and a new engine. Building the standard signer once and consuming it from both the Tendermint devnet baseline and PQ-HotStuff avoids doing the work twice.
* **DIS** has persisted keys, issued delegations and an Android key store. Who verifies DIS signatures (vendors, the chain, or both) decides whether DIS must move together with the chain.
* **Backend maturity.** `fips204` passed the NIST vectors in K1 but has had no independent audit; neither has our wrapper.

## 7. Decisions needed from the owner before any code
1. Migrate the **Tendermint devnet** validators too (needed to run a real four-node v2 chain end to end), or only build the standard signer for PQ-HotStuff?
2. DIS: in this workstream, or a separate one? Who verifies DIS signatures?
3. Genesis: derive the backend from the profile (proposed), or add an explicit `signature_backend` field?
4. Votes: deterministic or hedged signing?
5. Approve the context names, or give me yours.
6. Validator key storage: wait for the #109 review, or use a minimal interim format for the devnet?
