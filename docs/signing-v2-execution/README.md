# Signing v2 in the execution path: TEST-ONLY (DRAFT)

Stacked on PR #97 (`fips204` backend) which is stacked on #95. Implements the H0-4 replay fix in `chain-forge-execution`, **behind a cargo feature and a test-only config switch**. It is **not activated anywhere**: the `commitment_profile` genesis field that will activate it on a real chain is a separate PR and needs its own approval. Not merged.

## What it does

With `--features signing-v2` **and** `ExecutionConfig::mldsa_signing_v2 = true` (no genesis path sets it; it defaults to false):
- Transaction authorization uses **FIPS 204 pure ML-DSA-65 over the full canonical preimage** `U16(2) ‖ LP(chain_id) ‖ LP(id) ‖ LP(sender) ‖ U64(nonce) ‖ U64(gas_limit) ‖ LP(body_json) ‖ LP(pq_public_key)` in context `qattice/tx/v2` (docs/mldsa-tx-signing-v2/SPEC.md, PR #94), through the isolated `fips204` backend (#97). No pre-hash.
- The strict envelope rules **E1-E5** apply, with stable reject codes (`E1_SCHEME_MISSING`, `E1_SCHEME_NOT_MLDSA`, `E2_CLASSICAL_MATERIAL_PRESENT`, `E3_NOT_EXACTLY_ONE_SIGNATURE`, `E4_*`, `E5_*`): Ed25519, hybrid, SLH-DSA, FN-DSA, an untagged transaction, extra signatures, smuggled Ed25519 material, wrong lengths and a mismatching key are all rejected.
- The existing first-use rule is kept: an unbound sender must be the address derived from the key, so a named genesis account cannot be claimed.
- Rejection happens in the authorization step, before the nonce check and any fee debit, like the legacy step: a failed authorization takes no fee and changes no state (tested with the state root).

With the switch off (the default, and always without the feature), every code path is the legacy one; the `chain-forge-execution` build without the feature does not even depend on `fips204`.

## Evidence (Linux sandbox; Windows pending)

Tests `chain-forge-execution/tests/signing_v2_execution.rs` (19), written first. **Failing before:** the file did not compile (`unresolved import chain_forge_execution::signing_v2`, `no field mldsa_signing_v2`; `failing-before.txt`). **After: 19 passed, 0 failed.**
- **H0-4 acceptance:** a v2-signed transfer executes once (receiver credited 100); re-submitting the same signature with a new id and nonce 1 is rejected (`verification failed`), no fee, receiver still 100.
- Every covered field is bound: changing id, gas limit, amount or recipient after signing is rejected; cross-chain replay is rejected; a signature made in the vote context is not a transaction signature; the v1 ML-DSA signature format is not accepted; an unsigned transaction is rejected (`E1_SCHEME_MISSING`).
- Envelope rules E1-E5 each through the executor, plus first use from the derived address (binds the key, then the key may be omitted or repeated) and the named-account claim attempt.
- **Parity with the Python reference (PR #94 vectors):** the Rust preimage equals the reference preimage for all 29 vector cases (this also proves serde round-trips each body string); the Rust envelope check agrees with the reference on all 19 envelope cases; every one of the 29 vector signatures verifies or fails as recorded through the executor's verification function; and the executor **accepts the Python-made reference signature and rejects the Python-made replay** end to end.
- **Switch off:** the default is false, a legacy v1 ML-DSA transaction still executes, and the legacy replay defect is still present (which is exactly what the switch fixes).
- Regression: `chain-forge-execution` lib tests 152 passed / 1 ignored with and without the feature; `chain-forge-node` still compiles with default features; the default execution dependency tree contains no `fips204`.
- Mutation checks (19): drop the nonce, id, gas limit, chain id, sender or key from the preimage; wrong preimage version; wrong context; accept a non-MlDsa tag; allow Ed25519 material; allow two signatures; skip the derived-address rule; skip the bound-key mismatch rule; skip the hex, length, tag and first-use-key checks; disable the switch. **18 were caught at first. One survived**: changing the context constant went unnoticed because the signing helper and the verifier shared the constant. I added the end-to-end reference-signature test and a test pinning the constant; with them that mutant, and the rest, are caught (0 survivors).

## What this does NOT do (limits)

- **Not activated:** no genesis field; no real chain uses it. Legacy chains remain exposed to H0-4 until the profile is implemented and enabled.
- **Mempool/API ingress** still runs the legacy `check_account_signature_policy` (which, for example, accepts the Hybrid tag) and the API still skips ML-DSA verification at ingress; under v2 the executor rejects, but early rejection at ingress is not done.
- **Signers** (wallet, scheduler, node `tx`/keygen, wallet app, Android) are unchanged; tests sign with the new backend directly.
- Guardian/recovery signatures, validator and consensus signatures, validator-key proof of possession, rotation, delegation, governance and wallet-auth are unchanged (their contexts are reserved in the spec only).
- Node-level, multi-node and state-root-agreement behavior with v2 transactions is not tested; the node test suite was not re-run for this PR.
- The earlier ignored test `h0_4_mldsa_signature_must_bind_the_nonce` (PR #93) is not in this branch; the new `h0_4_v2_*` test above is its equivalent for the v2 path.

## Windows commands (MINGW64)

```bash
cd /c/Dev/chain-forge-engine
git fetch origin feat/signing-v2-execution
git worktree add ../sv2-wt origin/feat/signing-v2-execution && cd ../sv2-wt
export CARGO_INCREMENTAL=0
cargo test -j 2 -p chain-forge-execution --features signing-v2 --test signing_v2_execution 2>&1 | grep -E "^test |test result|^error"
cargo test -j 2 -p chain-forge-execution --lib 2>&1 | grep "test result"
cargo test -j 2 -p chain-forge-execution --features signing-v2 --lib 2>&1 | grep "test result"
```
Expected: 19 passed / 0 failed; then `152 passed; 0 failed; 1 ignored` twice.
