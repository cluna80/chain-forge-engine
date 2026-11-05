# Cryptographic dependency audit for an ML-DSA-only Qattice Public Testnet Alpha (DRAFT, read-only)

Base: `origin/main` @ `486bd22`. Documentation only: no production, signing, genesis, state-root or Chain Forge change. Not merged. Companion to `docs/mldsa-tx-signing-v2/SPEC.md` (PR #94).

## 0. Policy and method

Owner decision (2026-11-05): ML-DSA-65 is the only transaction/account/authorization signature algorithm on the fresh alpha chain; Ed25519 and hybrid are retired from the new protocol; legacy code may remain only for historical compatibility and tests and must not weaken the new chain.

**Method:** source reading and greps across the workspace (Rust crates, the wallet app, DIS crates) for Ed25519 / classical / hybrid / signature use, plus two small measurements (§4). **Not done:** no network traffic captured, no build with different features, no review of Chain Forge (out of scope). "SR" = source reading, not run. Line numbers are approximate at `486bd22`. A row is "resolved" only when the replacement exists and is tested; **no row below is resolved yet**.

Columns: **Crit.** = security-critical for the alpha. **On alpha path** = reachable on a fresh ML-DSA-only chain as the code stands. **Action** = required change; **Disposition** = Replace (change the code), Gate (make unreachable on the profile), Test (add proof), Exclude+disclose (cannot be fixed before launch; owner must accept), Legacy-only (leave for historical chains/tests).

## 1. Dependency matrix

### 1a. Transactions and accounts

| ID | Component / location | Algorithm | Purpose | Crit. | On alpha path | Action | Disposition |
|---|---|---|---|---|---|---|---|
| T1 | ML-DSA tx digest (`mldsa_tx_prehash`, `verify_mldsa_authorization`) | ML-DSA-65 over v1 digest (chain id + body only) | transaction authorization | **Critical** | yes | signing v2: FIPS 204 pure ML-DSA-65 over the **full canonical preimage** (chain id, id, sender, nonce, gas, body, key; version-tagged) with context `qattice/tx/v2`; no separate digest (owner 2026-11-05, SPEC §1-2) | **Replace** (H0-4, reproduced on Windows) |
| T2 | Ed25519 tx path (`verify_signature`, `Transaction::sign`/`signing_bytes`, `ClassicalScheme`) | Ed25519 | legacy tx authorization | High | **refused** when account policy is `MlDsaOnly`, accepted otherwise | v2 profile must force `MlDsaOnly`; keep code for legacy profile and tests | Gate + Legacy-only |
| T3 | `tx_signature_scheme` maps `HybridEd25519MlDsa` to `"ml-dsa-65"` | hybrid tag | account policy | High | **yes: Hybrid-tagged txs pass the `pqc-native` policy** and then verify through the ML-DSA path only (Ed25519 half ignored) | reject any non-`MlDsa` tag on v2 (rule E1) | **Replace** |
| T4 | Implicit detection: `sig_scheme = None` plus an `mldsa65:` entry is accepted | legacy envelope | back-compat | Medium | yes | reject missing tag (E1) | **Replace** |
| T5 | First `mldsa65:` entry used, extras ignored; Ed25519 fields ignored when tagged ML-DSA | envelope | malleability / smuggled material | Medium | yes | exactly one entry, no Ed25519 material (E2, E3) | **Replace** |
| T6 | `RecoverAccountKey` is **exempt** from the account signature policy (`check_account_signature_policy` returns early) | guardian signatures | key recovery | High | yes | confirm guardian signatures are ML-DSA-only and domain-separated; add replay/downgrade tests for recovery on v2 | **Test** (not established here) |
| T7 | Execution crypto-migration state (`crypto_migration:active`, grace windows, `ActivatePqConsensus`, `pq_consensus_activation_epoch`) | classical to PQ migration | migration of a classical chain | Medium | possible | disable on v2 profile (nothing to migrate) | **Gate** |
| T8 | First-use binding (`bind_key_if_unbound`) | both | key ownership | High | yes | unchanged; H0-6 tests found no defect | Test (done, sandbox+Windows for #93) |
| T9 | Genesis account `public_key` (core doc says Ed25519; validation accepts hex; ML-DSA keys are 1,952 B) | either | pre-bound account keys | Medium | yes | v2 genesis validation: only 1,952-byte ML-DSA keys | **Replace** (validation rule) |
| T10 | Node `tx` CLI and `keygen` default to `"ed25519"`, accept `"hybrid"` (`node/src/tx.rs ~111`, `keygen.rs ~59`, `node.rs ~2049`) | Ed25519 / hybrid | operator tooling | Medium | yes (operators) | default to ML-DSA-65; refuse ed25519/hybrid key files on a v2 chain | **Replace** |
| T11 | `chain-forge-wallet` (`sign_transaction`, `generate`) | ML-DSA-65 | wallet signing | High | yes | already ML-DSA; update to the v2 preimage and context (two call sites) | **Replace** (digest only) |
| T12 | Wallet app (`Qattice wallet/`): `keypair-store.ts` scheme `"mldsa65"`; docs still describe the v1 prehash | ML-DSA-65 | end-user wallet | High | yes | update to v2; the app's `gate-identity.server.ts` verifies Ed25519 JWKs (an external identity provider, see X3) | **Replace** + Exclude (X3) |
| T13 | Scheduler `settlement.rs`, `verifier_registry.rs` | ML-DSA-65 | settlement txs, verifier PoP | Medium | only if scheduler/settlement is enabled | update to the v2 preimage and context | **Replace** if enabled |
| T14 | Android wallet path (PR #63) and `dis-wallet-android` JNI | ML-DSA-65 (JNI) | mobile signing | High | yes | update to the v2 preimage and context | **Replace** |

### 1b. Consensus and validators

| ID | Component / location | Algorithm | Purpose | Crit. | On alpha path | Action | Disposition |
|---|---|---|---|---|---|---|---|
| V1 | Tendermint engine vote/proposal signing | ML-DSA-65 supported (#24, Windows-confirmed) | consensus safety | **Critical** | yes | confirm no Ed25519 path remains reachable on the profile; stale comment says "Ed25519 signing keypair" (`engine.rs ~125`) | **Test** + fix comment |
| V2 | `Node::verify_consensus_vote`: a `"classical"` branch is **always accepted**; the `"ml-dsa-65"` branch requires an `ActivatePqConsensus` epoch | Ed25519 / ML-DSA | vote verification | High | yes (code present) | on v2: classical branch refused; ML-DSA accepted without activation epoch | **Gate** |
| V3 | Genesis validator keys: 32 B (Ed25519) or 1,952 B accepted; ML-DSA-only enforced only if `validator_scheme = "ml-dsa-65"` (`core ~972-985`) | either | validator identity | **Critical** | yes | v2 profile requires `validator_scheme = "ml-dsa-65"` | **Gate** |
| V4 | `RegisterValidatorKey` PoP: authorised schemes `classical`, `ml-dsa-65`; refused for Ed25519 when `mldsa_consensus_only` (tests exist: `mldsa_only_chain_refuses_ed25519_key_registration`) | both | validator key registration | High | yes | covered by V3; keep tests | **Test** (exists) |
| V5 | **Devnet simulation keys:** `node.rs ~6160` re-derives a deterministic keypair from the validator's public id (`ClassicalScheme.generate_keypair(&validator.id.0)`) to sign votes "for this simulation only"; devnet genesis files use such derivable keys | Ed25519, seeded | devnet / tests | **Critical if reachable** | not established | the alpha genesis must contain only operator-generated, OS-RNG ML-DSA keys; compile out or hard-disable the simulation path on a real chain; never publish a devnet genesis as the alpha genesis | **Gate** + **Test** |
| V6 | HotStuff / FBA engines (devnet-only; release gate 2) | not audited | alternative consensus | n/a | no (Tendermint is the baseline) | excluded from alpha by existing decision | **Exclude** |
| V7 | PQ-HotStuff (future) | ML-DSA-only by spec | mainnet target | n/a | no | out of alpha scope | Exclude |
| V8 | `KeyBundle::new_ed25519`, validator registry `scheme` strings (`"Ed25519"`, `"HybridEd25519MlDsa"`) | metadata | registry | Low | yes (data) | reject on v2 | Gate |
| V9 | Slashing evidence verification (equivocation proofs) | follows vote scheme | penalties | High | yes | evidence verification must use the same ML-DSA-only rule | **Test** |

### 1c. Network and transport

| ID | Component / location | Algorithm | Purpose | Crit. | On alpha path | Action | Disposition |
|---|---|---|---|---|---|---|---|
| N1 | **OPEN dependency (owner 2026-11-05; not post-quantum).** libp2p peer identity: `Keypair::generate_ed25519()` at every start (`p2p/lib.rs ~657`); `PeerId` derived from it | Ed25519 | peer authentication | **High, not post-quantum** | yes | I found no post-quantum peer-identity option in the configured stack (libp2p 0.54 with `tcp` + `noise`; not checked against every libp2p release). Needs engineering: application-layer ML-DSA peer authentication bound to the validator key, or a different transport | **Exclude+disclose** until engineered (owner decision) |
| N2 | Noise handshake (`noise`) | X25519 key agreement + Ed25519 identity signature | transport confidentiality/authentication | **High, not post-quantum** | yes | same as N1; a post-quantum key exchange (ML-KEM) is a transport change | **Exclude+disclose** |
| N3 | gossipsub `MessageAuthenticity::Signed(local_key)`, `ValidationMode::Strict` | Ed25519 | gossip message authentication | Medium | yes | same key as N1; note transactions and consensus messages carry their own ML-DSA signatures, so a forged gossip envelope cannot forge a vote or a transaction | **Exclude+disclose** |
| N4 | Public RPC TLS (reverse proxy, not yet built) | classical key exchange and certificates | RPC confidentiality | Medium | yes | terminate TLS with a hybrid post-quantum key exchange where the stack supports it; web PKI certificates are classical | **Exclude+disclose** (state plainly) |
| N5 | `/api/auth/*` challenge/response (wallet identity) | ML-DSA-65 | wallet authentication | Medium | excluded from the public allowlist (owner, 2026-11-05) | none for alpha | Exclude |

### 1d. Identity, recovery, delegation

| ID | Component / location | Algorithm | Purpose | Crit. | On alpha path | Action | Disposition |
|---|---|---|---|---|---|---|---|
| I1 | Identity/attestation store (`chain-forge-identity`) | none: attestations are ordinary signed transactions; PoP proofs verified through a `PopProofVerifier` trait | personhood | High | yes | covered by T1–T5; confirm the PoP verifier used on the alpha path is post-quantum (the `VerifyIdentityWithProof` verifier was not audited here) | **Test** |
| I2 | `vca-pq` credentials: carry a classical (Ed25519) and a PQ signature slot (hybrid by design) | hybrid | personhood credentials | Medium | not established | require PQ-only on v2 or keep the module off | **Gate** |
| I3 | DIS key rotation (`RotateAccountKey`) and recovery: `new_key_scheme` must equal `"ml-dsa-65"` (enforced); guardian signatures verified with `MlDsaScheme` | ML-DSA-65 | key lifecycle | High | yes | add negative tests on v2 (wrong scheme, replay, cross-chain) | **Test** |
| I4 | `dis-core` delegations (`delegation.rs`): `pqcrypto_dilithium::dilithium3` labelled `SUITE_ML_DSA_65` | ML-DSA-65 (same crate as the chain) | delegation proofs | Medium | via `/api/dis/*` (excluded) and DIS flows | covered by K1 | Test |
| I5 | Governance vote preimage lacks `chain_id` (KNOWN_ISSUES §5) | n/a | cross-chain replay | Medium | only if governance enabled | governance excluded from alpha unless fixed | **Gate** |

### 1e. Operations, tooling and other

| ID | Component / location | Algorithm | Purpose | Crit. | On alpha path | Action | Disposition |
|---|---|---|---|---|---|---|---|
| K1 | ML-DSA implementation: `pqcrypto-dilithium` 0.5.0 (`dilithium3`) used as "ML-DSA-65" in `chain-forge-crypto` and `dis-core` | ML-DSA-65 | all PQ signatures | **Critical** | yes | **MEASURED NOT CONFORMANT (PR #95):** 0/45 NIST ACVP signatures reproduced, all NIST-valid signatures rejected; cause: challenge derived from 32 of 48 c-tilde bytes; a 12-line patch fixes it (45/45). Sizes match FIPS 204 but the algorithm does not. Replace with a conformant backend (or patch and re-validate), then pass the full K1 list (KAT, interop, Linux+Windows) | **Replace** before launch (owner decision: REQUIRED) |
| K2 | Key generation: `MlDsaScheme.generate_random` is OS-RNG; `MlDsaScheme.generate_keypair(seed)` returns one random key per seed per process (cached; tests); `ClassicalScheme.generate_keypair(seed)` is deterministic and reproducible by anyone who knows the seed | mixed | key creation | High | yes | operators must use OS-RNG keygen only; refuse seeded keygen outside tests | **Gate** |
| K3 | Hashes: SHA-256 (digests, manifests), SHA3-256 (state tree, block hash) | hash | integrity | Low | yes | acceptable post-quantum at the 128-bit security level; no action | none |
| K4 | Snapshot manifest: SHA-256 per file, no signature | hash only | restore integrity | Medium | yes | optional ML-DSA-signed manifest (R5, separate) | optional |
| K5 | PoCD machine/verifier signatures (`pocd/types/*`, Ed25519; receipts stamped `devnet-no-sig`) | Ed25519 | research receipts | Low | only if `pocd` is in the alpha genesis `modules` | exclude `pocd` from the alpha genesis | **Gate** |
| K6 | Genesis/bootstrap configuration (`bootstrap_nodes`, validator keys, `settlement_operators`) | n/a | network start | High | yes | alpha genesis: only operator-generated ML-DSA keys; no devnet keys (see V5) | **Gate** |
| K7 | Chain Forge wizard/service key generation (`chain-forge-service`, scheme `classical-ed25519`) | Ed25519 | Chain Forge product | n/a | no | Chain Forge is out of scope and not modified | Exclude |

## 2. What the audit shows

1. **Transactions are closest to done, but not done:** the `pqc-native` policy exists and refuses Ed25519, yet it **accepts the Hybrid tag** (T3), implicit untagged ML-DSA (T4) and extra smuggled material (T5), and the ML-DSA digest has the replay defect (T1). These are fixed by the v2 specification's rules E1–E5 and the v2 digest.
2. **Consensus is policy-ready but needs a profile gate:** an ML-DSA-only validator mode exists (`validator_scheme = "ml-dsa-65"`), but classical branches remain in the vote-verification path and genesis validation (V2, V3). V5 (derivable devnet simulation keys) must be shown unreachable on a real chain.
3. **The network is not post-quantum and cannot be made so by the transaction work:** peer identity, the Noise handshake, gossip signing and RPC TLS are classical (N1–N4). On the alpha, transactions and consensus messages are ML-DSA-signed end to end, so forging them does not depend on the transport; but peer impersonation and transport confidentiality are classical. That is a **disclosed limitation**, not a closed gate.
4. **Conformance is unproven:** K1 is the single point the whole signature story rests on.
5. **Tooling still defaults to Ed25519** (T10) and the devnet genesis files use derivable classical keys (V5, K6).

## 3. Proposed implementation sequence (nothing authorized; each its own gated PR, tests first)

1. **Spec review** (PR #94) and owner decisions: Q-H1 hash, Q-A1 profile selector (with Q3), Q-A2 legacy disclosure, whether to accept the N1–N4 transport limitation for the alpha.
2. **K1 conformance** (PR #95): done for sigGen/sigVer, **result: the current library fails**; next a backend decision and an independent-implementation check, then re-run on Linux and Windows. Everything below is built on the replacement backend.
3. **Rust v2 preimage, contexts + envelope rules** behind the v2 profile, with `h0_4_mldsa_signature_must_bind_the_nonce` as the acceptance test, golden-vector parity with the Python encoder, and tests for every rejection code (E1–E5) and for v1-under-v2 and v2-under-v1.
4. **Profile gates:** genesis validation forcing `MlDsaOnly` + `validator_scheme = "ml-dsa-65"` + 1,952-byte keys only (T2, T9, V3, V8); classical vote branch and migration state unreachable (V2, T7); simulation keys unreachable (V5); `pocd`/governance/vca-pq off in the alpha genesis (K5, I5, I2).
5. **Signers:** wallet, scheduler, node `tx` CLI and keygen defaults, wallet app, Android path move to v2 and ML-DSA defaults (T10–T14).
6. **Negative tests across the stack:** recovery/rotation (T6, I3), slashing evidence (V9), PoP verifier (I1), seeded-keygen refusal (K2).
7. **Transport decision:** either engineer post-quantum peer authentication/transport or ship with the disclosed limitation and a published roadmap item; same for RPC TLS (N1–N4).
8. **Formal gate:** the ML-DSA-only acceptance gate = rows marked Replace/Gate/Test all closed with Linux + Windows evidence, and every Exclude+disclose row explicitly accepted by the owner in writing.

## 4. Measurements made for this audit

- `pqcrypto-dilithium` 0.5.0 `dilithium3`: public key 1,952 B, secret key 4,032 B, detached signature 3,309 B (scratch test in `chain-forge-crypto` with `--features real-pqc`; file restored afterwards, nothing committed).
- The Python v1 digest equals `chain_forge_crypto::mldsa_tx_prehash` on three real serialised bodies.

## 5. Limits

Not reviewed: HotStuff/FBA internals, the `vca-pq` verifier used by `VerifyIdentityWithProof`, `chain-forge-governance` signing beyond the grep hit, Android/JNI code beyond file listings, third-party crate internals, and whether V5's simulation path is compiled into release builds. Rows marked "not established" are open questions, not findings. This document does not claim the network is, or will be, fully post-quantum.
