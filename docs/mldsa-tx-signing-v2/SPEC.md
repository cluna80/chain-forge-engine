# ML-DSA-65 transaction signing message, v2 (PROPOSED — DRAFT, design + vectors only)

Status: **proposal**. Nothing in the Rust code, wallets or genesis uses it. Owner approved the design direction on 2026-11-05 (new signing domain over `(chain_id, id, sender, nonce, body, gas_limit, pq_public_key)`, activated by the fresh-v2 genesis profile). Open decisions are in §7. Motivation and evidence: `docs/H0-4-H0-6-findings.md` (PR #93): under v1 an observer can replay an ML-DSA-signed transaction under a new nonce, because the signature does not cover the nonce.

## 1. What changes

ML-DSA-65 signs a 32-byte digest (unchanged). Only the **digest construction** changes.

| | v1 (current) | v2 (proposed) |
|---|---|---|
| Code | `chain_forge_crypto::mldsa_tx_prehash` | new function, same crate |
| Domain | `chain-forge/pq-tx/v1\n` | `chain-forge/pq-tx/v2\n` |
| Hash | SHA-256 | SHA-256 (see Q-H1) |
| Covers | `chain_id`, `body_json` | `chain_id`, `id`, `sender`, `nonce`, `gas_limit`, `body_json`, `pq_public_key` |
| Framing | `domain ‖ chain_id ‖ "\n" ‖ body_json` (not prefix-free) | length-prefixed fields (prefix-free) |

## 2. Encoding (normative)

```
message = DOMAIN_V2
        ‖ LP(chain_id) ‖ LP(id) ‖ LP(sender)
        ‖ U64(nonce) ‖ U64(gas_limit)
        ‖ LP(body_json) ‖ LP(pq_public_key)
digest  = SHA-256(message)            // 32 bytes, passed to MlDsaScheme::sign / verify
```
- `DOMAIN_V2` = the 21 ASCII bytes `chain-forge/pq-tx/v2\n`, a fixed prefix, not length-prefixed.
- `LP(x)` = `U32` big-endian byte length of `x`, then `x`. A field longer than 2^32 − 1 bytes is an error.
- `U64(n)` = 8 bytes big-endian, `0 ≤ n ≤ 2^64 − 1`.
- Text fields (`chain_id`, `id`, `sender`, `body_json`) are their UTF-8 bytes. Empty strings are valid (length 0).
- `body_json` is exactly the string v1 already signs: `serde_json::to_string(&tx.body)`. The signed bytes therefore depend on serde's field order and variant names (the existing project rule: those names are signed bytes).
- `pq_public_key` is the raw key bytes from `tx.pq_public_key` (1,952 bytes for ML-DSA-65; the vectors also cover other lengths).

**Not signed, by design:** `signature`, `pq_signatures`, `sig_scheme`, `public_key` (the Ed25519 field). Rationale and the open question about `sig_scheme` are in §7.

Properties (all tested in `test_reference_encoder.py`): every covered field changes the digest; the encoding is prefix-free (moving bytes between neighbouring fields changes the digest; no message is a prefix of another); v2 is domain-separated from v1 and from the Ed25519 domain `chain-forge/tx/v1\n`; fixed-width integers reject values outside u64.

## 3. Relationship to v1 and Ed25519

Ed25519 already signs `(id, sender, nonce, body, gas_limit, public_key)` under `chain-forge/tx/v1\n ‖ chain_id ‖ \n ‖ JSON-tuple`. v2 brings ML-DSA to the same coverage. The Ed25519 framing is JSON, not length-prefixed; v2 deliberately does **not** copy that, to avoid JSON-ambiguity. Ed25519 is not changed by this proposal.

## 4. Activation and compatibility

- **By chain profile, not per transaction.** A chain whose genesis selects the v2 profile (the fresh alpha genesis) accepts **only** v2 digests for ML-DSA transactions; every other chain keeps v1. No new field on `Transaction`, so the transaction JSON and `signing_bytes` for Ed25519 are unchanged. Cross-acceptance is a hole, so a v2 chain must reject v1 signatures and the reverse (tested at the digest level here; a chain-level test is part of the Rust PR).
- The genesis selector is a genesis-format change and needs its own owner decision (Q3 in the STATE-COMMIT-2 decision record, #85). Absent selector = legacy v1, so legacy genesis hashes do not change.
- **Legacy chains stay exposed** to the v1 replay (H0-4). Any publicly running legacy chain needs a disclosure.
- The signed bytes change, so signers and verifiers must change together: `chain-forge-execution::verify_mldsa_authorization`; signers in `chain-forge-wallet` (two sites), `chain-forge-scheduler` (settlement), the node `tx` CLI and test helpers, and the Android wallet path (PR #63).

## 5. Vectors

`vectors/v2.json`: 16 deterministic cases (public keys are stand-ins, not real ML-DSA keys; there is one 1,952-byte case). Each case records the inputs, the full v2 message (hex), the v2 digest and the v1 digest. The `nonce_1`, `id_changed`, `sender_changed`, `gas_limit_changed` and `pq_public_key_changed` cases have a **v1 digest identical to the baseline** (the defect) and a **different v2 digest**. Regenerate with `python generate_vectors.py`; generation is deterministic (a test checks that).

## 6. Verification performed (Linux sandbox; Windows optional for the Python part)

- 14 unit tests pass.
- Independent hash check: `openssl dgst -sha256` over each v2 message matches the recorded digest, 16 of 16.
- v1 cross-check against Rust: the Python v1 digest equals `chain_forge_crypto::mldsa_tx_prehash` for three real serialised bodies (`Transfer`, `Burn`, unit variant `CancelRecovery`). This validates the harness and the body strings. **There is no Rust v2 yet, so v2 is checked only against this Python encoder and OpenSSL.**
- Encoder mutation checks: 10 deliberate defects (drop nonce, drop gas_limit, drop id, un-prefix a field, drop the key, wrong domain, little-endian integers, no length-overflow check, negative nonce accepted, concatenation without prefixes) are each caught by the tests.

## 7. Open decisions for the owner

- **Q-H1 Hash:** keep SHA-256 (matches v1 and the existing helper) or move to SHA3-256 with the state-tree hash. The helper's own comment says only second-preimage resistance matters here.
- **Q-S1 `sig_scheme`:** it selects the verification algorithm and is unsigned in both Ed25519 and v1. Including it in v2 prevents scheme-substitution; excluding it matches current behaviour. Recommendation: include it as a one-byte tag, decided together with the hybrid (`HybridEd25519MlDsa`) rules.
- **Q-S2 Hybrid transactions:** the executor currently routes `HybridEd25519MlDsa` through the ML-DSA path. Whether the Ed25519 half must also verify (and so already binds the nonce) was not established here.
- **Q-A1 Activation field:** name and location of the genesis selector (Q3).
- **Q-A2 Legacy disclosure** for any publicly running v1 chain.

## 8. What this does not do

It does not implement anything in Rust, change any signer, change a genesis file or state root, or fix H0-4 by itself. The ignored test `h0_4_mldsa_signature_must_bind_the_nonce` (PR #93) turns green only when the Rust verifier and signers use v2.
