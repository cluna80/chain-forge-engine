#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Local 4-validator ML-DSA devnet: Alice · Bob · Carol · Dave on one machine.
#
# Uses tests/devnet/genesis-4node-mldsa.json (ML-DSA-65 consensus keys,
# ML-DSA-only user accounts) and the public test keys in
# tests/devnet/keys/mldsa/. Ports API 19080-19083 / P2P 28000-28003 and the
# data folder ~/chain-forge-data-mldsa never touch the legacy devnet's ports
# or ~/chain-forge-data. The keys are public: test use only.
#
# Usage: ./scripts/start-devnet-local.sh [--clean]
#   --clean   wipe this devnet's data folders (~/chain-forge-data-mldsa only)
# Optional: BINARY=/path/to/chain-forge-node (default: target/release)
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="${BINARY:-$REPO/target/release/chain-forge-node}"
GENESIS="$REPO/tests/devnet/genesis-4node-mldsa.json"
KEYS="$REPO/tests/devnet/keys/mldsa"
DATA_BASE="$HOME/chain-forge-data-mldsa"

NAMES=(alice bob carol dave)
API_PORTS=(19080 19081 19082 19083)
P2P_PORTS=(28000 28001 28002 28003)

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: node binary not found: $BINARY"
    echo "       Run: cargo build --release -p chain-forge-node"
    exit 1
fi

# ── Clean? ──────────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]]; then
    echo "==> Wiping $DATA_BASE ..."
    rm -rf "$DATA_BASE"
fi

# ── Start the four validators; each bootstraps to Alice ─────────
PIDS=()
for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    data="$DATA_BASE/$name"
    mkdir -p "$data"
    bootstrap=()
    if (( i > 0 )); then bootstrap=(--bootstrap "/ip4/127.0.0.1/tcp/${P2P_PORTS[0]}"); fi

    echo "==> Starting $name  (api :${API_PORTS[$i]}, p2p :${P2P_PORTS[$i]})"
    "$BINARY" \
        --genesis   "$GENESIS" \
        --validator "qcb1$name" \
        --key-file  "$KEYS/$name.key.json" \
        --data-dir  "$data" \
        --api-port  "${API_PORTS[$i]}" \
        --p2p-port  "${P2P_PORTS[$i]}" \
        "${bootstrap[@]}" \
        > "$data/node.log" 2>&1 &
    PIDS+=($!)
    echo "   PID=${PIDS[-1]}  log=$data/node.log"
    sleep 0.5
done

echo "${PIDS[*]}" > "$DATA_BASE/devnet.pids"

echo ""
echo "All four nodes started (local 4-node ML-DSA devnet)."
echo "PIDs: ${PIDS[*]}  (also in $DATA_BASE/devnet.pids)"
echo ""
echo "Check status and blocks after ~15s:"
echo "  curl -s http://localhost:19080/api/status"
echo "  curl -s http://localhost:19080/api/blocks"
echo ""
echo "Logs:  tail -f $DATA_BASE/alice/node.log"
echo "Stop:  kill \$(cat $DATA_BASE/devnet.pids)"
