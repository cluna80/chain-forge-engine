# ML-DSA transaction signing v2 — spec and vectors (design only)

See `SPEC.md`. Files: `reference_encoder.py` (independent encoder, standard library only), `generate_vectors.py`, `test_reference_encoder.py`, `vectors/v2.json`.

```
python3 -m unittest discover -s docs/mldsa-tx-signing-v2      # on Windows: py -3 -m unittest discover -s docs\mldsa-tx-signing-v2
python3 docs/mldsa-tx-signing-v2/generate_vectors.py            # regenerates vectors/v2.json (deterministic)
```
`.gitignore` ignores `*.py`; the Python files here are force-added.
