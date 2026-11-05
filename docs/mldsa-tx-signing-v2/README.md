# Qattice signing v2: FIPS 204 pure ML-DSA-65 over the full canonical preimage (design + vectors)

See `SPEC.md`. Files: `reference_encoder.py` (standard library only; builds the preimage, the context and `M'`, and the envelope rules; performs no cryptography), `generate_vectors.py`, `test_reference_encoder.py`, `vectors/v2.json` (real keys and signatures).

```
# structural tests only (standard library)
python3 -m unittest discover -s docs/mldsa-tx-signing-v2          # Windows: py -3 -m unittest discover -s docs\mldsa-tx-signing-v2
# plus signature checks and regeneration, with the independent implementation (dilithium-py 1.5.1, hash-checked wheel)
QATTICE_PYSITE=<dir with dilithium_py> python3 -m unittest discover -s docs/mldsa-tx-signing-v2
QATTICE_PYSITE=<dir with dilithium_py> python3 docs/mldsa-tx-signing-v2/generate_vectors.py   # deterministic
```
Rust cross-check of the vector file against four backends: `tools/k1-backend-eval` in PR #95 (`verify-v2`).
`.gitignore` ignores `*.py`; the Python files here are force-added.
