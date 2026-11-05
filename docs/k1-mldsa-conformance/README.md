# K1 — FIPS 204 ML-DSA-65 conformance of the signature library (DRAFT, test-first)

Base: `origin/main` @ `486bd22`. This PR adds **tests, a NIST vector fixture, evidence and this document only**. It changes no consensus, genesis, signing-domain or wallet behavior, and no production source file (one `dev-dependency`, `sha3`, is added to `chain-forge-crypto` for the pre-hash vectors). Not merged. Evidence is from the Linux sandbox; **Windows parity is pending** (§6).

## 1. Result in one paragraph

**The ML-DSA-65 library the chain uses, `pqcrypto-dilithium` 0.5.0 (`dilithium3`), is not FIPS 204 compatible.** Against NIST's ACVP vectors it reproduces **0 of 45** deterministic signatures and **rejects all 9 NIST-valid signatures**, in every interface (internal, external pure with context, HashML-DSA with 12 hash functions). It does reject all 36 NIST-invalid signatures, and its key encodings and sizes are the standard ones. A **12-line change** to the vendored C (derive the challenge from all 48 bytes of `c̃` instead of the first 32) makes the same library match **45 of 45** signatures and agree on **45 of 45** verifications. So the chain's current "ML-DSA-65" signatures are not interoperable with any conforming implementation. Renaming is not the fix; the library must be replaced by a conformant one or patched and then re-validated (§5).

## 2. Evidence (Linux sandbox)

Vectors: the ML-DSA-65 subset of NIST's ACVP FIPS 204 files, `chain-forge-crypto/tests/vectors/fips204/mldsa65.json` (25 keyGen, 45 deterministic sigGen, 45 sigVer cases), extracted by `extract_acvp.py` from the downloaded ACVP-Server `internalProjection.json` files. Provenance: the SHA-256 of each source file is recorded in the fixture's `source` block; the ACVP-Server commit id was not retrievable from the sandbox. Skipped on purpose: nondeterministic sigGen (no fixed expected value) and `externalMu` groups (the library API cannot accept a precomputed μ).

| Check | Unpatched library | Same library + 12-line challenge change |
|---|---|---|
| Parameter sizes (pk 1,952 / sk 4,032 / sig 3,309) | match FIPS 204 | match |
| NIST keyGen keys: encoding, `rho`, `tr = SHAKE256(pk)`, sign/verify round trip (25) | pass | pass |
| sigGen byte-for-byte, **internal** interface (15) | **0/15** | 15/15 |
| sigGen byte-for-byte, **external pure** with contexts up to 255 B (15) | **0/15** | 15/15 |
| sigGen byte-for-byte, **HashML-DSA** (12 pre-hash functions) (15) | **0/15** | 15/15 |
| sigVer agreement, all three interfaces (45, of which 36 are NIST rejections) | **36/45** (all 9 valid signatures rejected) | 45/45 |
| Bit flips in c̃, z and hint; wrong message; wrong key; wrong lengths; constant 0x00/0xFF signatures; non-canonical hint | all rejected | all rejected |
| Malformed keys: wrong pk/sk length rejected at parse; all-zero pk does not verify | pass | pass |
| Library signing deterministic (`rnd = 0`) | yes | yes |

Logs: `results/linux-default.txt` (default run: 11 passed, 3 ignored), `results/linux-include-ignored.txt` (the two NIST tests fail, as intended), `results/linux-patched-library-experiment.txt` (patched copy: NIST tests pass; the characterization test flips, as intended).

## 3. Root cause (localised by experiment)

For the 15 internal-interface cases the first 48 bytes (`c̃`) of the library's signature equal NIST's in 11 cases, and the remainder (z, hint) differs. Equal `c̃` means the key handling, message hashing, randomness and commitment are identical; the 4 cases that diverge earlier are rejection-sampling iterations that stopped elsewhere because the challenge differed. The vendored source (`pqclean/crypto_sign/dilithium3/clean/poly.c`, `poly_challenge`) absorbs only `SEEDBYTES` = 32 bytes of the 48-byte `c̃` (the call sites carry the comment "uses only the first SEEDBYTES bytes"), while the FIPS 204 vectors require the challenge to depend on the whole `c̃`. `challenge-full-ctilde.patch` changes that in the x86 variants (`clean`, `avx2`); with it, every NIST case passes. The `aarch64` variant has the same function and was not built or tested.

## 4. Other findings (source reading unless stated)

1. **No FIPS 204 message framing.** `detached_sign(m, sk)` is `ML-DSA.Sign_internal(sk, M' = m)` with `rnd = 0^32`. The standard external interface signs `M' = 0x00 ‖ |ctx| ‖ ctx ‖ M` (pure) or `0x01 ‖ … ‖ OID ‖ PH(M)`. The tests show the mapping works when the caller builds `M'` itself (it does, in the patched run, including contexts up to 255 B), but **the chain's wrapper signs the raw message**, so even with a fixed library its signatures would not verify in a standard external-interface verifier. The FIPS 204 context string is the standard's own domain-separation mechanism; using it is the natural way to build the v2 signing domain (a design decision for #94, not made here).
2. **Key generation.** The vendored `crypto_sign_keypair` expands the 32-byte seed with `SHAKE256(ξ)`; to my reading FIPS 204 final derives `(ρ, ρ′, K)` from `H(ξ ‖ k ‖ l)`. The library has no seeded key generation API, so a NIST keyGen KAT **cannot be run** against it. What is verified: NIST-generated keys have the standard encoding and work in the library, and library-generated keys are structurally consistent (`rho`, `tr`) and round-trip. What is **not** verified: that library-generated keys are valid under an independent implementation (§7). The seed-to-key mapping matters only if wallets back keys up as seeds.
3. **Wrapper `MlDsaScheme::verify` truncates an over-long public key** (`public_key[..1952.min(len)]`): a 1,953-byte key verifies (characterization test `characterization_wrapper_accepts_an_overlong_public_key_today`, passes today; desired-behavior test `wrapper_must_reject_a_public_key_with_trailing_bytes` is ignored and fails today). Two different byte strings then name the same key and would derive different addresses. `sign` similarly accepts a longer private key (`private_key[..4032]`). The v2 envelope rule E5 (exactly 1,952 bytes) covers the transaction path but not the wrapper. The doc comment on `sign` says "Signature size: 2420 bytes"; the real size is 3,309.
4. **Signing is deterministic** (`rnd = 0`). FIPS 204 permits it; NIST recommends the hedged variant by default as defence against fault attacks. A design choice for the replacement.
5. **`dis-core` uses the same crate** (`pqcrypto_dilithium::dilithium3`, labelled `SUITE_ML_DSA_65`), so its delegation signatures have the same property. Not separately tested here.

## 5. Library compatibility conclusion and required changes

The current dependency does not meet the owner's requirement (FIPS 204 ML-DSA-65). Options, in my order of preference; **none has been evaluated here** (see §7), and any candidate must pass `tests/fips204_conformance.rs` unchanged:

1. **Replace with a maintained, standards-conformant implementation** (candidates I know of, not tested: `pqcrypto-mldsa` (PQClean `ml-dsa-65`), `fips204` (integritychain), RustCrypto `ml-dsa`, `libcrux-ml-dsa`, `aws-lc-rs`). Selection criteria: passes this suite (including contexts and HashML-DSA), seeded key generation for KATs, constant-time claims, maintenance, `no_std`/build footprint, licence, supply-chain posture.
2. **Vendor and patch PQClean** with `challenge-full-ctilde.patch`. It passes the vectors but makes the project the maintainer of a cryptographic fork; acceptable only as a stopgap.
3. Keep the current library for **legacy chains only**, labelled honestly as a pre-standard Dilithium variant (not "ML-DSA-65"), never for the qattice-v2 profile.

Required follow-up changes, each its own reviewed PR and **not made here**: backend swap behind the `SignatureScheme` trait; wrapper hardening (exact-length keys, no truncation); FIPS 204 `M'` framing with a Qattice context string as part of the signing-v2 domain; hedged-versus-deterministic decision; regenerating all test fixtures that embed signatures made by the old library; keeping legacy verification available for legacy chains if their history must stay verifiable.

## 6. Windows commands (parity requirement)

```bash
cd /c/Dev/chain-forge-engine
git fetch origin test/k1-mldsa-conformance
git worktree add ../k1-wt origin/test/k1-mldsa-conformance && cd ../k1-wt
export CARGO_INCREMENTAL=0
cargo test -j 2 -p chain-forge-crypto --features real-pqc --test fips204_conformance -- --nocapture --test-threads=1 2>&1 | grep -E "^test |K1-RESULT|test result"
cargo test -j 2 -p chain-forge-crypto --features real-pqc --test fips204_conformance -- --include-ignored --nocapture --test-threads=1 2>&1 | grep -E "^test |K1-RESULT|test result"
```
Expected: the first run `11 passed; 0 failed; 3 ignored`, with `siggen byte-matches 0/45`, `internal c-tilde prefix matches 11/15`, `sigver NIST-valid verified 0/9`, `NIST-invalid rejected 36/36`. The second run `11 passed; 3 failed`: the two NIST tests (`siggen: 0/15` per interface, `sigver: 36/45`) and the ignored wrapper-truncation test fail on purpose. Any difference on Windows (for example matching signatures) must be reported, not rerun away.

## 7. What is still missing against the owner's list

| Requirement | Status |
|---|---|
| Authoritative known-answer vectors | **Done** for sigGen (deterministic) and sigVer; **keyGen KAT not runnable** (no seeded API) |
| Key generation verification | **Partial**: structure and round trip; no independent-implementation check |
| Signature generation and verification | **Done** (fails today; passes with the patch) |
| Independent implementation interoperability | **Not done.** NIST's vectors come from NIST's own implementation, which is strong evidence, but a second, independent implementation (for example a pure-Python FIPS 204, or a Rust candidate) was not run: fetching third-party packages was blocked in this sandbox and I did not work around it. Needs owner permission |
| Invalid-signature and malformed-key rejection | **Done** (NIST negatives, bit flips, lengths, constants, zero key) |
| Linux and Windows parity | Linux done; **Windows pending** |
| Standards-conformant replacement | **Proposed, not evaluated** (needs permission to fetch candidates) |
