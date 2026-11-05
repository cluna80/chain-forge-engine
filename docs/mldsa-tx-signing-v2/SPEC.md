# ML-DSA-65-only transaction authorization and signing message, v2 (PROPOSED — DRAFT, design + vectors only)

Status: **proposal, revised 2026-11-05 for the owner's ML-DSA-only decision and updated for the owner's cryptographic architecture decisions of the same day (§6). Reference vectors are NOT frozen** (see §6, K1). Nothing in the Rust code, wallets or genesis uses it. Evidence for why it is needed: `docs/H0-4-H0-6-findings.md` (PR #93): under the current ML-DSA digest an observer can replay a signed transaction under a new nonce, because the signature does not cover the nonce.

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

By **chain profile, not per transaction**, selected by a **top-level genesis field `commitment_profile = "qattice-v2"`** (owner decision 2026-11-05):
- **Absent field = legacy behavior and legacy hashes** (the field must not enter the genesis hash when absent).
- **The fresh alpha genesis requires `qattice-v2`.**
- **Any other value fails closed** (a node refuses to start on a genesis whose `commitment_profile` it does not support, including a legacy node meeting `qattice-v2`).
- `qattice-v2` accepts **only** this scheme for ML-DSA transactions and enforces ML-DSA-65-only transaction **and** validator authentication: genesis validation must enforce `signature_scheme = "pqc-native"` with `pqc_algorithm = "ml-dsa"` (account policy `MlDsaOnly`), `validator_scheme = "ml-dsa-65"`, 1,952-byte keys only, and no `classical`/`hybrid` selection. **No hybrid, no Ed25519, no v1-signature fallback.**
- No new field on `Transaction`; Ed25519 `signing_bytes` is untouched (legacy chains only). Adding the genesis field is itself a genesis-format change and is implemented in its own reviewed PR. **A v2 chain must reject v1 signatures and the reverse**; digest-level tests are here, chain-level tests belong to the Rust PR.

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

## 6. Decisions (owner, 2026-11-05)

- **Q-H1 Hash: APPROVED, SHA-256** for the v2 prehash.
- **Q-A1 Activation field: DECIDED**, `commitment_profile = "qattice-v2"` (§3).
- **Q-A2 Disclosure: YES.** Any publicly accessible legacy v1 network must carry a disclosure of H0-4 (ML-DSA replay under a new nonce). The disclosure text is a separate deliverable.
- **Transport: OPEN.** Classical P2P identity (Ed25519), Noise, gossip signing and RPC TLS remain **open cryptographic dependencies and must not be described as post-quantum.** A separate design and threat-model review is required before any restricted-alpha exception is considered (see `docs/CRYPTO-DEPENDENCY-AUDIT.md`, rows N1-N4).
- **Q-K1 Conformance: REQUIRED before launch.** FIPS 204 ML-DSA-65 interoperability evidence: authoritative known-answer vectors, key-generation verification, signature generation and verification, independent-implementation interoperability, invalid-signature and malformed-key rejection, Linux and Windows parity. If the library is not FIPS 204 compatible, a standards-conformant replacement is proposed rather than renaming the algorithm.

**K1 result so far (PR #95, Linux sandbox): the current library is NOT FIPS 204 compatible** (0/45 NIST signatures reproduced; all NIST-valid signatures rejected; cause isolated to the challenge derivation). Consequences for this specification:
1. **The reference vectors in this PR are not frozen.** The digest framing here is independent of the library bug, but the final signing message may change to use the FIPS 204 context string (`M' = 0x00 ‖ |ctx| ‖ ctx ‖ M`) as the domain separator, and the vectors must then be regenerated. They are frozen only after the K1 backend decision.
2. Anything signed by the current library is not interoperable with conforming implementations; v2 must be built on the replacement backend.

Removed from the previous draft: hybrid-transaction rules (hybrid is rejected), `sig_scheme` signing question (fixed identifier, §1).

## 7. What this does not do

It does not implement anything in Rust, change a signer, genesis file or state root, or fix H0-4 by itself. The ignored test `h0_4_mldsa_signature_must_bind_the_nonce` (PR #93) turns green only when the Rust verifier and signers use this scheme. It also does not make the network post-quantum: peer authentication and transport still use classical cryptography (see `docs/CRYPTO-DEPENDENCY-AUDIT.md`).
