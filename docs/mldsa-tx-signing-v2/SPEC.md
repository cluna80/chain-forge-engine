# ML-DSA-65-only transaction authorization and signing message, v2 (PROPOSED — DRAFT, design + vectors only)

Status: **proposal, revised 2026-11-05 for the owner's ML-DSA-only decision.** Nothing in the Rust code, wallets or genesis uses it. Evidence for why it is needed: `docs/H0-4-H0-6-findings.md` (PR #93): under the current ML-DSA digest an observer can replay a signed transaction under a new nonce, because the signature does not cover the nonce.

## 0. Policy this specification implements (owner decision)

Qattice Public Testnet Alpha is post-quantum native. **ML-DSA-65 is the only transaction and account-authorization signature algorithm.** Ed25519 and hybrid signatures are retired from the new protocol: no hybrid mode, no Ed25519 fallback, no silent downgrade, no negotiation. Legacy Ed25519 code may remain only for historical-compatibility chains and tests; it must not weaken the fresh chain's acceptance rules.

Supersedes the earlier draft of this document, which left open how hybrid transactions should verify (old Q-S2) and whether to sign `sig_scheme` (old Q-S1). Both questions disappear: there is one algorithm, identified by a fixed constant.

## 1. The signing message

ML-DSA-65 signs a 32-byte digest (unchanged). Only the digest construction changes.

```
message = DOMAIN_V2 ‖ ALG_MLDSA65
        ‖ LP(chain_id) ‖ LP(id) ‖ LP(sender)
        ‖ U64(nonce) ‖ U64(gas_limit)
        ‖ LP(body_json) ‖ LP(pq_public_key)
digest  = SHA-256(message)
```
- `DOMAIN_V2` = the 21 ASCII bytes `chain-forge/pq-tx/v2\n` (fixed prefix, not length-prefixed).
- `ALG_MLDSA65` = the single byte `0x01`. It is a **fixed identifier, not a selector**: no other value is defined, so it cannot be used to negotiate a legacy algorithm. It is in the preimage so a digest made for ML-DSA-65 can never be reinterpreted under a future algorithm.
- `LP(x)` = `U32` big-endian length then bytes (error above 2^32 − 1); `U64(n)` = 8 bytes big-endian, `0 ≤ n < 2^64`.
- Text fields are UTF-8; empty strings are valid.
- `body_json` = `serde_json::to_string(&tx.body)`, exactly what v1 signs (so serde field order and variant names remain signed bytes).
- `pq_public_key` = the **public key that verifies the signature** (see E5): the account's bound key if one exists, otherwise the first-use key carried in the transaction. The signer signs over its own public key.

**Covered:** chain ID, transaction ID, sender, nonce, gas limit, canonical body, ML-DSA public key, algorithm identifier, protocol version (domain). **Not covered, by design:** the signature itself and the envelope tags (`pq_signatures`, `sig_scheme`), which are validated structurally by the rules in §2 instead of being signed (a signed tag would only protect a choice that no longer exists).

Properties tested in `test_reference_encoder.py`: every covered field changes the digest; the encoding is prefix-free; v2 is domain-separated from v1 and from the Ed25519 domain; v1 digests differ from v2 digests for every vector; fixed-width integers reject out-of-range values.

## 2. Acceptance rules on a fresh ML-DSA-only chain (normative)

Applied before any cryptography; each rejection has a stable code. `check_envelope()` in the reference encoder implements them, and `vectors/v2.json` contains 19 envelope cases (3 accepted, 16 rejected).

| Rule | Reject when | Code |
|---|---|---|
| E1 | `sig_scheme` is absent (no implicit/legacy detection) | `E1_SCHEME_MISSING` |
| E1 | `sig_scheme` is anything but `MlDsa`: Ed25519 (`Classical`), `HybridEd25519MlDsa`, `SlhDsa`, `FnDsa`, or any unknown tag | `E1_SCHEME_NOT_MLDSA` |
| E2 | any Ed25519 material rides along: non-empty `signature` or `public_key` | `E2_CLASSICAL_MATERIAL_PRESENT` |
| E3 | `pq_signatures` does not contain exactly one entry | `E3_NOT_EXACTLY_ONE_SIGNATURE` |
| E4 | the entry is not tagged `mldsa65:`, is not hex, or its decoded length is not 3,309 bytes | `E4_BAD_SIGNATURE_TAG`, `E4_SIGNATURE_NOT_HEX`, `E4_SIGNATURE_WRONG_LENGTH` |
| E5 | unbound sender: `pq_public_key` missing or not exactly 1,952 bytes; bound sender: `pq_public_key` non-empty and different from the bound key | `E5_FIRST_USE_KEY_MISSING_OR_WRONG_LENGTH`, `E5_KEY_DIFFERS_FROM_BOUND_KEY`, `E5_KEY_NOT_HEX` |
| C1 | the ML-DSA-65 signature does not verify over `digest` with the key from E5 | (cryptographic; not modelled in Python) |
| C2 | digest was built with another chain ID, id, sender, nonce, gas limit, body or key; or is a **v1** digest | falls out of C1 |

After E1–E5 the existing first-use rule still applies unchanged: an unbound sender must be the address derived from the key, so a named genesis account cannot be claimed.

**What the current code does differently (source reading; this is why the rules are needed):**
- `tx_signature_scheme` maps `HybridEd25519MlDsa` to `"ml-dsa-65"`, so the existing `pqc-native` policy **accepts the Hybrid tag** (and dispatch then runs the ML-DSA path only; the Ed25519 half is ignored). Rule E1 rejects it.
- With `sig_scheme = None`, an `mldsa65:` entry is accepted by implicit detection. E1 rejects it.
- `verify_authorization_signed` takes the **first** `mldsa65:` entry and ignores any others, and ignores Ed25519 fields when the tag says ML-DSA. E2 and E3 reject both.
- `RecoverAccountKey` is **exempt** from the account signature policy (`check_account_signature_policy` returns early); it is authorized by guardian signatures instead. See the dependency audit for what that needs on a v2 chain.

## 3. Activation

By **chain profile, not per transaction**. A chain whose genesis selects the v2 profile (the fresh alpha genesis) accepts **only** this scheme; every other chain keeps today's behaviour. No new field on `Transaction`, and Ed25519 `signing_bytes` is untouched (legacy chains only). The v2 profile implies, and genesis validation must enforce: `signature_scheme = "pqc-native"` with `pqc_algorithm = "ml-dsa"` (account policy `MlDsaOnly`), `validator_scheme = "ml-dsa-65"`, and no `classical`/`hybrid` selection. The profile selector is a genesis-format change and needs its own owner decision (Q3 in the STATE-COMMIT-2 decision record, #85). **A v2 chain must reject v1 signatures and the reverse**; digest-level tests are here, chain-level tests belong to the Rust PR.

Legacy chains stay exposed to the v1 replay (H0-4); any publicly running legacy chain needs a disclosure.

## 4. Vectors and verification performed (Linux sandbox)

- `vectors/v2.json`: 16 digest cases (stand-in keys, not real ML-DSA keys; one is 1,952 bytes) plus 19 envelope cases. The nonce/id/sender/gas/key cases have a v1 digest identical to the baseline (the defect) and a different v2 digest.
- 22 unit tests pass.
- Independent hash check: `openssl dgst -sha256` over every v2 message matches, 16 of 16.
- v1 cross-check against Rust: the Python v1 digest equals `chain_forge_crypto::mldsa_tx_prehash` for three real serialised bodies (Transfer, Burn, CancelRecovery).
- 18 deliberate encoder/rule defects (drop nonce, gas, id, key or algorithm byte; un-prefix a field; wrong domain; little-endian integers; no overflow check; accept Hybrid; accept missing scheme; allow Ed25519 material; allow two signatures; skip tag, length or key checks) are each caught by the tests. The first draft's mutation run was contaminated because the determinism test overwrote the committed vectors; that test now writes to a temp file, and the 18 results above are from a clean re-run with the vectors verified unchanged (md5 before and after).
- **Not verified:** no Rust v2 exists; no ML-DSA signature is produced or verified here; the Python tests have not been run on Windows.

## 5. Size note

ML-DSA-65 sizes in this repo: public key 1,952 bytes, signature 3,309 bytes (measured here: pk 1,952, sk 4,032, sig 3,309). A first-use transaction carries the key; later transactions may omit it (E5), keeping steady-state transactions smaller. With the shipped `max_tx_bytes = 65,536` a first-use transaction fits comfortably.

## 6. Open decisions for the owner

- **Q-H1 Hash:** SHA-256 (matches v1) or SHA3-256 (matches the state tree). Recommendation: SHA-256, since only second-preimage resistance matters here.
- **Q-A1 Activation field:** name and location of the profile selector (with Q3).
- **Q-A2 Disclosure** for any publicly running legacy v1 chain.
- **Q-K1 Conformance:** the chain uses `pqcrypto-dilithium` 0.5.0 (`dilithium3`) as "ML-DSA-65"; sizes match FIPS 204 ML-DSA-65, but the repo has no NIST known-answer test. Recommendation: add ACVP/KAT vectors before launch (see the dependency audit).

Removed from the previous draft: hybrid-transaction rules (hybrid is rejected), `sig_scheme` signing question (fixed identifier, §1).

## 7. What this does not do

It does not implement anything in Rust, change a signer, genesis file or state root, or fix H0-4 by itself. The ignored test `h0_4_mldsa_signature_must_bind_the_nonce` (PR #93) turns green only when the Rust verifier and signers use this scheme. It also does not make the network post-quantum: peer authentication and transport still use classical cryptography (see `docs/CRYPTO-DEPENDENCY-AUDIT.md`).
