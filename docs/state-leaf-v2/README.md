# State-leaf v2: golden vectors and reference encoder (PR-A)

Documentation and test assets only. **No production code, consensus, genesis, state-root or persisted-format change; no existing golden baseline is replaced.** Part of the ACCT-LEAF-1 design (`docs/ACCT-LEAF-1-state-leaf-v2-design.md`).

| File | Purpose |
|---|---|
| `ENCODING.md` | normative byte-level encoding, bounds, versioning contract, v1 compatibility, persistence analysis |
| `reference_encoder.py` | independent reference encoder / strict decoder (standard library only), the frozen v1 encoder, the tree-level hashing |
| `generate_vectors.py` | defines the accounts and negative cases and regenerates the vector files |
| `vectors/state-leaf-v2.json` | 19 positive and 51 negative vectors |
| `vectors/state-leaf-v1-legacy.json` | frozen v1 leaf vectors (includes the S1 parity corpus) |
| `test_reference_encoder.py` | self-tests: vectors, malformed input, prefix-freeness, field mutation, determinism, injectivity, domain separation, independent SHA3 check, Rust-pinned v1 cross-check |

```
python3 -m unittest discover -s docs/state-leaf-v2 -v        # from the repository root; Windows: py -3 -m unittest ...
python3 docs/state-leaf-v2/generate_vectors.py              # only for a reviewed vector change; the tests fail if the JSON and the generator disagree
```
Nothing here is wired into the build or CI. A later PR (PR-C) implements the Rust encoder and must reproduce these vectors exactly.
