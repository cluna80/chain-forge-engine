#!/usr/bin/env bash
# Runs the whole K1 backend evaluation. Needs a Rust toolchain; the Python cross-checks additionally need
# dilithium-py 1.5.1 installed with:  python -m pip install --no-deps --target pyeval/site dilithium_py-1.5.1-py3-none-any.whl
# (wheel sha256 21ab0cbd56e959d22b9dca59bd8af0e2a6f73703b14ad71d483ecf70438c73d7). Set QATTICE_PYSITE to the site dir.
set -u
cd "$(dirname "$0")"
export CARGO_INCREMENTAL=0
cargo build --release -j 2 2>&1 | tail -3
# Cargo writes binaries to $CARGO_TARGET_DIR when it is set (some shells set it globally), else to ./target.
BIN="${CARGO_TARGET_DIR:-./target}/release"
EXT=""; [ -f "$BIN/ev-fips204.exe" ] && EXT=".exe"
[ -f "$BIN/ev-fips204$EXT" ] || { echo "ERROR: $BIN/ev-fips204$EXT not found; build failed or CARGO_TARGET_DIR points elsewhere"; exit 1; }
mkdir -p out
BACKENDS="fips204 mldsa libcrux pqmldsa old"
for b in $BACKENDS; do
  "$BIN"/ev-$b$EXT kat ../../chain-forge-crypto/tests/vectors/fips204/mldsa65.json > out/kat-$b.json
  "$BIN"/ev-$b$EXT neg > out/neg-$b.json 2>/dev/null
  "$BIN"/ev-$b$EXT gen-interop > out/interop-$b.json 2>/dev/null
  "$BIN"/ev-$b$EXT keys > out/keys-$b.json
done
PY=${PYTHON:-python3}; command -v $PY >/dev/null 2>&1 || PY=python
$PY - <<'PYEOF'
import json
names=['fips204','mldsa','libcrux','pqmldsa','old']
for n in names:
    d=json.load(open(f'out/kat-{n}.json'))
    f=lambda t:f"{t['pass']}/{t['total']}"+(f" (N/A {t['not_exposed']})" if t['not_exposed'] else "")
    print(f"KAT  {d['backend']:50} keygen {f(d['keygen_from_seed'])} | siggen "+" ".join(f"{k}:{f(v)}" for k,v in sorted(d['siggen_deterministic'].items()))+" | sigver "+" ".join(f"{k}:{f(v)}" for k,v in sorted(d['sigver'].items())))
for n in names:
    d=json.load(open(f'out/neg-{n}.json'))['negative_tests']
    bad=[k for k,v in d.items() if any(x in v for x in ('ACCEPTED','PANIC','SIGNED'))]
    print(f"NEG  {n:10} entries with ACCEPTED/PANIC/SIGNED: {bad}")
PYEOF
echo "--- Rust cross-verification matrix (valid accepted / mutated rejected)"
for v in $BACKENDS; do for s in $BACKENDS; do
  printf "%-8s verifies %-8s: " $v $s; "$BIN"/ev-$v$EXT verify-interop out/interop-$s.json | $PY -c "import sys,json;d=json.load(sys.stdin);print(f\"{d['valid_accepted']}/{d['valid_total']} mutated {d['mutated_rejected']}/{d['mutated_total']}\")"
done; done
if [ -d "${QATTICE_PYSITE:-pyeval/site}" ]; then
  echo "--- independent pure-Python implementation"
  $PY py_eval.py kat
  for s in $BACKENDS; do $PY py_eval.py verify out/interop-$s.json; done
  for b in $BACKENDS; do $PY py_eval.py keycheck out/keys-$b.json; done
else echo "(Python site dir not found; skipping the independent-implementation checks)"; fi
echo "--- bench (microseconds per operation, single thread)"
for b in $BACKENDS; do "$BIN"/ev-$b$EXT bench 2>/dev/null; echo; done
