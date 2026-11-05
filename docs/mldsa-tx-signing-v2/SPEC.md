# Qattice signing v2: FIPS 204 pure ML-DSA-65 over the full canonical preimage (DRAFT specification and vectors)

Status: **design approved by the owner 2026-11-05; this document specifies it.** Nothing in the Rust code, wallets or genesis uses it yet. It is documentation, a reference encoder and reference vectors only. Still a draft PR (#94); not merged.

Evidence for why it is needed: `docs/H0-4-H0-6-findings.md` (PR #93): under the current ML-DSA digest an observer can replay a signed transaction under a new nonce, because the signature does not cover the nonce.

## 0. Locked decisions (owner, 2026-11-05)

| Decision | Value |
|---|---|
| Algorithm | **FIPS 204 ML-DSA-65** (and nothing else) |
| Preferred implementation | `fips204` 0.5.0, subject to the remaining validation (Windows K1 parity, the production-migration PRs) |
| Interface | **Standard FIPS 204 pure ML-DSA** (`ML-DSA.Sign` / `ML-DSA.Verify` with a context string) |
| Signed message | **The complete canonical, versioned preimage.** There is no separate SHA-256 digest |
| Domain separation | **Explicit Qattice contexts** (the FIPS 204 context string) for transactions, consensus votes and every other authorization protocol |
| Compatibility | **No Ed25519, no hybrid, no downgrade fallback, no v1 signatures** on the new chain |
| Activation | genesis field `commitment_profile = "qattice-v2"` (absent = legacy; unsupported values fail closed) |

This **supersedes** the earlier approval of SHA-256 as the transaction prehash. ML-DSA hashes its message internally (SHAKE256), so a separate prehash added nothing and a signature over a digest hides what was signed from any verifier that sees only the signature and the digest.

## 1. What is signed and how

```
signature = ML-DSA-65.Sign(sk, M, ctx)            // FIPS 204 Algorithm 2, pure interface
valid     = ML-DSA-65.Verify(pk, M, signature, ctx)   // FIPS 204 Algorithm 3
M   = tx_preimage(...)                             // §2: the whole canonical preimage, no hashing
ctx = "qattice/tx/v2"                              // §3
```
Inside the algorithm FIPS 204 forms `M' = 0x00 ‖ |ctx| ‖ ctx ‖ M` and signs that. The vectors record `M'` too, so an implementation that exposes only the internal interface (`Sign_internal`) can be tested with it.

Signing may be hedged (fresh randomness, FIPS 204's default) or deterministic (`rnd = 0^32`); verification is the same either way. The vectors use deterministic signing so they are reproducible. Production should use hedged signing; that choice belongs to the backend-integration PR.

## 2. The transaction preimage (normative)

```
M = U16(2)                                       // preimage version
  ‖ LP(chain_id) ‖ LP(id) ‖ LP(sender)
  ‖ U64(nonce) ‖ U64(gas_limit)
  ‖ LP(body_json) ‖ LP(pq_public_key)
```
- `LP(x)` = `U32` big-endian byte length then the bytes (error above 2^32 − 1). `U16`/`U64` are big-endian fixed width; `nonce` and `gas_limit` are in `0 … 2^64 − 1`.
- Text fields are UTF-8; empty strings are valid (length 0).
- `body_json` = `serde_json::to_string(&tx.body)`, exactly what v1 signs (serde field order and variant names remain signed bytes).
- `pq_public_key` = the **public key that verifies the signature**: the account's bound key if one exists, otherwise the first-use key carried in the transaction (rule E5). The signer signs over its own public key.
- **Covered:** version, chain ID, transaction ID, sender, nonce, gas limit, canonical body, ML-DSA public key (and, through the context, the protocol and its version). **Not covered, by design:** the signature itself and the envelope tags (`pq_signatures`, `sig_scheme`), which are validated structurally by §4.
- There is no domain prefix inside `M`: domain separation is the FIPS 204 context (§3), applied by the algorithm itself. The version `U16(2)` is in `M` so the preimage layout can evolve without ambiguity; a layout change also means a new context name.

Properties tested in `test_reference_encoder.py`: every covered field changes the preimage; the encoding is prefix-free (moving bytes between neighbouring fields changes it; no preimage is a prefix of another); integers reject values outside their range; `M` is variable-length and is not a 32-byte digest.

## 3. Contexts (normative registry)

A context is an ASCII byte string of at most **255 bytes** (the FIPS 204 limit), namespaced `qattice/`, ending in a version. **A context is never shared between message types, and a change to a protocol's preimage layout requires a new context version.** These names are reserved now; only the transaction preimage is specified here, and each other protocol gets its own versioned preimage specification before use.

| Protocol | Context |
|---|---|
| Transaction authorization | `qattice/tx/v2` |
| Consensus vote | `qattice/consensus/vote/v1` |
| Consensus proposal | `qattice/consensus/proposal/v1` |
| Validator key proof of possession | `qattice/validator-key-pop/v1` |
| Account key rotation | `qattice/dis/rotate-key/v1` |
| Recovery guardian authorization | `qattice/dis/recovery-guardian/v1` |
| Delegation proof | `qattice/dis/delegation/v1` |
| Wallet authentication challenge | `qattice/auth/challenge/v1` |
| Governance vote | `qattice/governance/vote/v1` |

Tested: all contexts are unique, ASCII, ≤ 255 bytes and `qattice/`-prefixed; a signature made in one protocol's context does not verify in another's (vectors below); a 256-byte context is refused by the encoder and by every conforming backend.

## 4. Acceptance rules on a fresh ML-DSA-only chain (normative)

Applied before any cryptography; each rejection has a stable code. `check_envelope()` implements them and `vectors/v2.json` has 19 envelope cases (3 accepted, 16 rejected). The envelope rules and codes are unchanged from the previous draft.

| Rule | Reject when | Code |
|---|---|---|
| E1 | `sig_scheme` is absent, or is anything but `MlDsa` (Ed25519 `Classical`, `HybridEd25519MlDsa`, `SlhDsa`, `FnDsa`, unknown) | `E1_SCHEME_MISSING`, `E1_SCHEME_NOT_MLDSA` |
| E2 | any Ed25519 material rides along (non-empty `signature` or `public_key`) | `E2_CLASSICAL_MATERIAL_PRESENT` |
| E3 | `pq_signatures` does not contain exactly one entry | `E3_NOT_EXACTLY_ONE_SIGNATURE` |
| E4 | the entry is not tagged `mldsa65:`, is not hex, or is not exactly 3,309 bytes | `E4_BAD_SIGNATURE_TAG`, `E4_SIGNATURE_NOT_HEX`, `E4_SIGNATURE_WRONG_LENGTH` |
| E5 | unbound sender: `pq_public_key` missing or not exactly 1,952 bytes; bound sender: `pq_public_key` non-empty and different from the bound key | `E5_FIRST_USE_KEY_MISSING_OR_WRONG_LENGTH`, `E5_KEY_DIFFERS_FROM_BOUND_KEY`, `E5_KEY_NOT_HEX` |
| C1 | `ML-DSA-65.Verify(pk, M, sig, "qattice/tx/v2")` is false, with `pk` from E5 | (cryptographic) |

After E1–E5 the existing first-use rule still applies: an unbound sender must be the address derived from the key, so a named genesis account cannot be claimed. A v1-style signature, a signature in another context, and any modified-field signature all fail C1 (vectors `replay_*`, `context_*`).

**What the current code does differently (source reading; why the rules are needed):** the `pqc-native` policy accepts the Hybrid tag as ML-DSA, accepts an untagged transaction that carries an `mldsa65:` entry, uses the first `mldsa65:` entry and ignores extras, and ignores Ed25519 fields when tagged ML-DSA; `RecoverAccountKey` is exempt from the account signature policy and is authorised by guardian signatures (its context is reserved above).

## 5. Activation

By chain profile, never per transaction: genesis field `commitment_profile = "qattice-v2"` (absent field = legacy behaviour and hashes; unsupported values fail closed; the fresh alpha genesis requires it). `qattice-v2` enforces ML-DSA-65-only transaction **and** validator authentication (`signature_scheme = "pqc-native"` with `pqc_algorithm = "ml-dsa"`, `validator_scheme = "ml-dsa-65"`, 1,952-byte keys only) and accepts only this scheme. No new field on `Transaction`; legacy Ed25519 `signing_bytes` is untouched on legacy chains. The genesis field is implemented in its own reviewed PR. Legacy chains stay exposed to the v1 replay (H0-4); any publicly running one needs the agreed disclosure.

## 6. Vectors and verification performed (Linux sandbox)

`vectors/v2.json`: **real keys and real signatures.** Two test keys are derived from fixed public seeds with FIPS 204 `KeyGen_internal`; 29 transaction cases (15 valid, 14 that must be rejected) plus 19 envelope cases. Each transaction case records the inputs, the full preimage `M`, the context, `M'`, the verifying key, the signature and the expected result, plus the v1 digest for contrast. Signatures are deterministic and were produced by the independent pure-Python implementation `dilithium-py` 1.5.1.

The 14 negatives: baseline signature replayed with a changed nonce (the H0-4 attack), id, sender, gas limit, chain id (cross-chain), body or key field; a flipped signature bit; a signature by another key; the same preimage signed in four other contexts (a vote context, empty, a v1-style name, and a 255-byte context) verified as a transaction; and a transaction signature verified in the vote context.

- **Five conforming verifiers agree on all 29 cases (15 accepted, 14 rejected):** `fips204` 0.5.0, `ml-dsa` 0.1.2, `libcrux-ml-dsa` 0.0.11, `pqcrypto-mldsa` 0.1.2 (PQClean) and `dilithium-py` 1.5.1. The command is `verify-v2` in `tools/k1-backend-eval` (PR #95).
- The **current chain library rejects all 15 valid signatures** (it is not FIPS 204 conformant; PR #95).
- The nonce, id, sender and gas cases have a v1 digest identical to the baseline (the defect) and a different v2 preimage; the corresponding replay vectors are rejected by every conforming verifier.
- 25 unit tests pass with the independent implementation (21 run and 4 are skipped without it); regeneration is byte-for-byte deterministic and writes to a temp file, never over the committed vectors.
- 24 deliberate defects (drop the nonce, gas, chain id, id, sender, key or body; un-prefix a field; wrong version; wrong endianness; missing overflow or range check; wrong `M'` framing; context limit; shared context; accept Hybrid or a missing scheme; allow Ed25519 material; allow two signatures; skip tag, length or key checks) are each caught; the committed vectors' md5 was unchanged before and after.
- **Not verified:** no Rust implementation of v2 exists; the Python tests have not been run on Windows; Windows K1 parity is pending.

## 7. Remaining decisions and open items

- **Backend:** `fips204` 0.5.0 is preferred "subject to remaining validation": Windows K1 parity, and the production-migration PRs.
- **Hedged versus deterministic signing** in production (hedged recommended).
- **Preimage specifications** for votes, proposals, validator PoP, rotation, recovery, delegation, wallet auth and governance (contexts are reserved above).
- **Genesis selector** `commitment_profile` implementation and its genesis-hash rule.
- **Transport** (libp2p identity, Noise, gossip, RPC TLS) stays an open, non-post-quantum dependency and must not be described otherwise.

## 8. What this does not do

It does not implement anything in Rust, change a signer, genesis file or state root, or fix H0-4 by itself. The ignored test `h0_4_mldsa_signature_must_bind_the_nonce` (PR #93) turns green only when the Rust verifier and signers use this scheme.
