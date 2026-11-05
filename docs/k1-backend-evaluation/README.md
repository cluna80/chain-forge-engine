# K1 backend evaluation: a FIPS 204 ML-DSA-65 implementation for Qattice (DRAFT)

Companion to `docs/k1-mldsa-conformance/README.md` (the finding that the current library is not conformant). Documentation, a test harness (`tools/k1-backend-eval/`, a separate Cargo workspace that is **not** part of the Qattice build) and recorded results only. **No production cryptography is replaced; no consensus, genesis, wallet, signing-domain or state-root change.** Not merged. Evidence is from the Linux sandbox; **Windows parity is pending** (§9).

Authorization: the owner approved fetching the four Rust candidates and a reputable pure-Python implementation for isolated evaluation only. Nothing else was installed; no installation script was run (Rust crates were fetched by `cargo`, whose only code execution is the candidates' own build scripts during the test build; the Python package was installed from a hash-checked pure-Python wheel that I inspected first).

## 1. Recommendation

**Adopt `fips204` 0.5.0 (integritychain) as the Qattice ML-DSA-65 backend**, used through the FIPS 204 external pure interface with a Qattice context string, and keep a second implementation (`libcrux-ml-dsa`, plus the pure-Python reference) only as a **differential-test oracle** in CI, never in production.

Why, from the measurements below:
1. It is the only candidate that passes **100% of every NIST vector class** (keyGen from seed, sigGen for internal, external-pure with contexts and HashML-DSA with all 12 pre-hash functions, sigVer including the negatives): 25/25, 45/45, 45/45.
2. It validates secret-key encodings on load (it rejected the invalid-encoding key that three others signed with or panicked on) and returns errors, not panics.
3. Pure Rust; its README states `no_std`, no heap allocation and no `unsafe` code (claims, not verified by me; see §6). Seeded key generation (so a 32-byte seed backup and KATs are possible) and signing with caller-supplied randomness for deterministic tests (`try_sign_with_seed`, which is what I tested; the default OS-RNG hedged path needs its `default-rng` feature and was not exercised).
4. MIT/Apache-2.0; 21 crates in `cargo tree -e normal` versus 33 for `ml-dsa` and 16 for `libcrux-ml-dsa`.

Costs, stated plainly: it is not the fastest (signing ~0.8 ms versus ~0.2 ms for `libcrux-ml-dsa`; verification ~0.2-0.3 ms), it is **maintained by volunteers on a reasonable-effort basis** with security fixes only for the latest release (its SECURITY.md), and **no independent audit of any candidate was found**. A signature scheme that is correct by test is not the same as one that is audited; the launch gate should say so.

## 2. Candidates and provenance

All pinned exactly in `tools/k1-backend-eval/Cargo.lock` (checksums are the crates.io index checksums).

| | `fips204` | `ml-dsa` (RustCrypto) | `libcrux-ml-dsa` (Cryspen) | `pqcrypto-mldsa` (rustpq / PQClean) |
|---|---|---|---|---|
| Version evaluated | 0.5.0 (2026-10-23) | 0.1.2 (2026-10-31) | 0.0.11 (2026-10-07) | 0.1.2 (2025-08-05) |
| crates.io sha256 | `a823e139…052093b` | `6f6d49c3…0743f5c` | `31f8706f…5920dda` | `f9f812cd…e130528` |
| Source | github.com/integritychain/fips204 | github.com/RustCrypto/signatures | github.com/cryspen/libcrux | github.com/rustpq/pqcrypto (PQClean `ml-dsa-65`, Dilithium commit `cbcd875…`) |
| Licence | MIT OR Apache-2.0 | Apache-2.0 OR MIT | Apache-2.0 | MIT OR Apache-2.0 |
| Downloads (total / recent) | 1.36 M / 0.71 M | 5.10 M / 3.43 M | 0.29 M / 0.16 M | 0.43 M / 0.16 M |
| Releases (history) | 14 | 22 | 19 | 3 |
| MSRV | 1.85 | 1.87 | not stated | not stated |
| Implementation | pure Rust | pure Rust | Rust (portable + AVX2, runtime multiplexed) | C via FFI (needs a C toolchain) |
| Version stability | 0.5.x, API changed between 0.4 and 0.5 | 0.1.x | **0.0.x** (pre-release numbering) | 0.1.x |
| Direct dependencies in the tree (excl. itself) | 21 | 33 | 16 | 6 |
| Current chain library (control) | `pqcrypto-dilithium` 0.5.0 (PQClean `dilithium3`), checksum `685de0fa…276726f` | | | |

Python reference: `dilithium-py` 1.5.1, wheel sha256 `21ab0cbd56e959d22b9dca59bd8af0e2a6f73703b14ad71d483ecf70438c73d7`, MIT, pure Python, no runtime dependencies; installed with `pip --no-deps` from the wheel after I listed its 24 files and found no network/process/`eval`-style calls. It claims to be a FIPS 204 implementation; we do not rely on that claim, we test it (§3).

## 3. NIST ACVP results (same vectors for all; tested)

Vectors: `chain-forge-crypto/tests/vectors/fips204/mldsa65.json` (K1 PR #95): ML-DSA-65 keyGen 25, sigGen deterministic 45, sigVer 45 (36 of them NIST rejections). "N/A" means the candidate's public API does not expose that operation; it is **not** counted as a pass.

| Implementation | keyGen from seed | sigGen internal | sigGen external pure (ctx ≤ 255 B) | sigGen HashML-DSA (12 hashes) | sigVer internal | sigVer pure | sigVer HashML-DSA |
|---|---|---|---|---|---|---|---|
| **fips204 0.5.0** | **25/25** | **15/15** | **15/15** | **15/15** | **15/15** | **15/15** | **15/15** |
| ml-dsa 0.1.2 | 25/25 | 15/15 | 15/15 | N/A (no API) | 15/15 | 15/15 | N/A |
| libcrux-ml-dsa 0.0.11 | 25/25 | 15/15 (needs `acvp` feature) | 15/15 | 2/2 of the SHAKE-128 cases; other 13 N/A (only SHAKE-128 pre-hash exposed) | 15/15 (`acvp`) | 15/15 | 1/1 SHAKE-128; 14 N/A |
| pqcrypto-mldsa 0.1.2 | N/A (random keygen only) | N/A | N/A (signing is hedged-only, so bytes cannot be reproduced) | N/A | N/A | **15/15** | N/A |
| dilithium-py 1.5.1 (independent) | 25/25 | 15/15 | 15/15 | 15/15 (via the internal interface with caller-built M') | 15/15 | 15/15 | 15/15 |
| *current chain library* | N/A | 0/15 | 0/15 | 0/15 | N/A | 12/15 (**rejects all 3 NIST-valid**) | N/A |

HashML-DSA is not needed by Qattice (we sign a digest as a pure-interface message), so its absence in `ml-dsa` and most of `libcrux` is not a disqualifier; it matters only for completeness.

## 4. Investigation of the three reported differences in the current library

1. **Challenge sampling (root cause of the signature mismatch): confirmed, with independent evidence.** The vendored C hashes only 32 of the 48 `c̃` bytes into the challenge polynomial. A 12-line patch makes it match NIST 45/45 (K1 PR #95). New here: the **independent Python implementation accepts 0 of 144** signatures made by the current library with the standard framing, while accepting all 144 from each of the four candidates and rejecting every mutation.
2. **Key generation.** Not a conformance failure for stored keys: the independent implementation recomputes the **same public key from the secret key for all 6 sampled keys of every library, including the current one** (`pk_from_sk`), and the four candidates accept the current library's key pairs and sign with them (12/12 verified by Python for each). So **existing key pairs remain valid ML-DSA-65 keys; only signatures are invalid**. What differs is the *seed to key* mapping (the current code expands `SHAKE256(ξ)`; FIPS 204 uses `H(ξ ‖ k ‖ l)`, which every seeded candidate and the NIST KATs confirm), observable only if keys are derived from seeds.
3. **Message framing.** The current library signs the raw message (the FIPS 204 *internal* interface). The candidates' external interface prepends `0x00 ‖ |ctx| ‖ ctx` (pure) or the HashML-DSA prefix; the NIST vectors for all three interfaces pass on `fips204`, and the cross-verification matrix (§5) shows the pure interface with contexts of 0, 13 and 255 bytes interoperates across all four libraries and the Python reference.

## 5. Interoperability (tested)

* **Rust ↔ Rust (all 5 × 5):** each library signed 144 messages (6 keys × 4 messages × 3 contexts of 0 / 13 / 255 bytes × deterministic and randomised signing; `pqcrypto-mldsa` is randomised-only) and every library verified every file. Among the four candidates: **every pair accepted 144/144 valid signatures and rejected 288/288 mutated copies** (a flipped bit and an appended message byte per case). The current library is accepted by nobody else (0/144 by each candidate) and accepts nobody else's.
* **Python ↔ Rust (both directions):** the independent implementation accepted 144/144 from each candidate (and rejected 144/144 mutations); each candidate accepted 36/36 of the Python-made signatures (and rejected 72/72 mutations). The independent Python implementation rejected all 144 of the current library's signatures, as in §4.
* **Key reuse:** 6 key pairs from the current library, re-signed by each candidate, verified 12/12 by Python.

## 6. Malformed input and API behavior (tested), versus documentation claims (not verified)

Tested (`results/linux-run_all.txt`). In every library: all bit flips (c̃, z, hint), wrong message, wrong context, wrong public key, wrong lengths, all-zero and all-0xFF signatures, a non-canonical hint region, all-zero public key and wrong-length public keys are **rejected**; wrong-length secret keys are rejected. The differences:

| Behavior | fips204 | ml-dsa | libcrux | pqcrypto-mldsa |
|---|---|---|---|---|
| Secret key with invalid η-encoding | **rejected with an error** | **panics** (its docs warn that the deprecated expanded-key API can panic) | signs | signs |
| Syntactically valid but inconsistent secret key (all zero, wrong `tr`) | signs | signs | signs | signs |
| Signing with a 256-byte context | error | error | error | **returns a signature without error** |
| Verification with a 256-byte context | rejects | rejects | rejects | rejects |

The third row is a property of the FIPS 204 encoding (it does not require key-consistency checks) and shows why the wallet should store the **32-byte seed** and re-derive the expanded key, rather than trust a 4,032-byte blob. The last row is a library bug class to avoid: the wrapper would need its own length check.

Claimed by documentation, **not verified by me**: `fips204` — no `unsafe`, `no_std`, no heap, constant-time within one attempt (dudect measurements by the authors), fuzzing harness, ACVP vectors in their test suite; `libcrux-ml-dsa` — field arithmetic, NTT and serialisation formally verified with hax/F\* (not the whole scheme); `ml-dsa` — "has never been independently audited"; `pqcrypto-mldsa` — a PQClean C implementation. I found **no independent security audit claimed or published for any candidate**.

## 7. Performance and footprint (measured, single thread, release build, Xeon 2.8 GHz with AVX2, noisy shared sandbox)

Median of three runs, microseconds per operation (signing uses a different message each iteration so rejection sampling averages out). Treat as order of magnitude; run-to-run variance in this sandbox was about ±40%.

| | keygen | sign | verify | smallest thread stack that worked (tested at 8/12/16/24/32/48/64/96/128/192/256/512 KiB) |
|---|---|---|---|---|
| fips204 | ~360 | ~790 | ~180-330 | between 128 and 192 KiB |
| ml-dsa | ~430 | ~1,550 | ~250-320 | between 128 and 192 KiB |
| libcrux-ml-dsa | ~80 | ~185-250 | ~75-95 | between 128 and 192 KiB |
| pqcrypto-mldsa | n/a | ~130-145 | ~46-48 | between 96 and 128 KiB |
| current library | n/a | ~120-190 | ~46-51 | between 64 and 96 KiB |

At 4 validators and a few hundred transactions per block even the slowest candidate verifies thousands of signatures per second per core; performance is not a selection constraint for the alpha. Peak memory was not separately measured (the harness's own 2.3 MB fixture dominated resident size); the stack figures above are the meaningful footprint number, and `fips204` documents no heap use.

Platforms: all four built and ran on Linux x86-64 here. Windows, macOS, aarch64, WASM and Android were **not tested**. `pqcrypto-mldsa` needs a C compiler; `libcrux-ml-dsa` selects AVX2 at runtime.

## 8. Comparison summary

| Criterion | fips204 | ml-dsa | libcrux-ml-dsa | pqcrypto-mldsa |
|---|---|---|---|---|
| All NIST vectors the API can take | **yes, all** | yes (no HashML-DSA) | yes (SHAKE-128 pre-hash only) | verify only |
| Seeded keygen (KAT, seed backup) | yes | yes | yes | no |
| Deterministic and hedged signing | both | deterministic API + manual hedged via internal | caller supplies randomness | hedged only |
| Rejects malformed secret keys | **yes** | panics | no | no |
| Context handling | correct | correct | correct | **silent signature at 256 B** |
| Interop with independent Python | yes | yes | yes | yes |
| Speed | slowest of the Rust ones except ml-dsa | slowest | **fastest** | fast |
| `unsafe` / FFI | none claimed | none claimed | some SIMD | C FFI |
| Audit | none found | "never audited" | partial formal verification | none found |
| Maintenance | volunteers, latest-only fixes | RustCrypto org | Cryspen (commercial) | rustpq |
| Version maturity | 0.5.0 | 0.1.2 | 0.0.11 | 0.1.2 |
| Fit for Qattice | **recommended** | acceptable second choice | best performance; pre-1.0, weaker input validation | not recommended |

## 9. Remaining gaps

1. **Windows and other platforms:** not run. Commands (MINGW64): `cd tools/k1-backend-eval && ./run_all.sh` prints the same tables; the Python steps need the wheel installed into a `pyeval/site` directory (see the script header). Expected output is in `results/linux-run_all.txt` (bench numbers will differ).
2. **No audit** of any candidate was found; constant-time and memory-safety claims are the authors', not verified here.
3. **`dis-core` and Android/JNI** use the current library; their migration (and the wire compatibility of delegation proofs) is separate.
4. **HashML-DSA** is only fully available in `fips204`.
5. **Production-feature builds** were not separately tested: the NIST internal-interface groups need the `acvp-internal` (fips204) and `acvp` (libcrux) test features, which a production build would not enable; the pure and pre-hash interfaces need no such feature.
6. The independent Python implementation is slow and not constant-time; it is an oracle, not a candidate.

## 10. Proposed isolated migration PR sequence (nothing authorized; each reviewed separately, tests first)

1. **Decision record** (this PR + #95): backend, version pin, interface = FIPS 204 external pure with context. Then freeze the #94 vectors.
2. **Backend seam:** add `fips204` behind a feature in `chain-forge-crypto` as a new `SignatureScheme` implementation; keep the old code as a clearly-named legacy backend. Parameterise the K1 conformance tests over both backends; the NIST tests pass for the new one. No caller switched yet.
3. **Wrapper hardening:** exact-length keys, no truncation, error on malformed secret keys and on contexts over 255 bytes, tests for each (turns the ignored wrapper test green).
4. **Signing domain v2:** FIPS 204 context string `qattice/tx/v2`-style domain, SHA-256 digest as message (as approved), envelope rules E1-E5, behind `commitment_profile = "qattice-v2"`; the H0-4 acceptance test turns green.
5. **Validator and consensus signing** on the new backend under the profile (PQ-HotStuff / Tendermint votes with their own contexts); remove the classical branches under the profile.
6. **Signers:** wallet, scheduler, node `tx`/keygen, wallet app, Android JNI; store the 32-byte seed form; key files from the current library remain valid (§4.2).
7. **`dis-core`** backend swap and delegation-proof compatibility decision.
8. **CI:** NIST ACVP vectors, a differential test against `libcrux-ml-dsa` (dev-dependency) and the Python oracle on a schedule, Linux and Windows jobs, `cargo-deny`/`cargo-audit`, exact version pins.
9. **Legacy:** keep the old backend only to verify the history of legacy chains, labelled a pre-standard Dilithium variant.

Compatibility facts that shape the sequence: keys carry over; **every existing signature is invalid under a conforming verifier** (so any persisted signed data of a legacy chain needs the legacy backend), and the fresh qattice-v2 genesis starts clean.
