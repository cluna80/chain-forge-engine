#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Local 3-validator devnet — Alice · Bob · Dave on one machine.
#
# Uses genesis-3node.json (validator_set_size: 3, mode: devnet)
# so quorum is 3/3 and no cross-machine peering is needed.
# Carol is listed as an observer/wallet in genesis but does NOT
# run a node here — she is used as the provider wallet address.
#
# Usage: ./scripts/start-devnet-local.sh [--clean]
#   --clean   wipe data dirs for a fresh chain
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$REPO/target/release/chain-forge-node"
GENESIS="$REPO/tests/devnet/genesis-3node.json"
KEYS="$REPO/tests/devnet/keys"
DATA_BASE="$HOME/chain-forge-data"

ALICE_DATA="$DATA_BASE/alice"
BOB_DATA="$DATA_BASE/bob"
DAVE_DATA="$DATA_BASE/dave"

# ── Clean? ──────────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]]; then
    echo "==> Wiping data dirs..."
    rm -rf "$ALICE_DATA" "$BOB_DATA" "$DAVE_DATA"
fi

mkdir -p "$ALICE_DATA" "$BOB_DATA" "$DAVE_DATA"

# ── Copy genesis to each data dir ────────────────────────────────
cp "$GENESIS" "$ALICE_DATA/genesis.json"
cp "$GENESIS" "$BOB_DATA/genesis.json"
cp "$GENESIS" "$DAVE_DATA/genesis.json"

# ── Start Alice (p2p :26656, api :8080) ──────────────────────────
echo "==> Starting Alice  (p2p :26656, api :8080)"
"$BINARY" \
    --genesis   "$GENESIS" \
    --validator qcb1alice \
    --key-file  "$KEYS/alice.key.json" \
    --data-dir  "$ALICE_DATA" \
    --p2p-port  26656 \
    --api-port  8080 \
    --bootstrap "/ip4/127.0.0.1/tcp/26657" \
    --bootstrap "/ip4/127.0.0.1/tcp/26658" \
    > "$ALICE_DATA/node.log" 2>&1 &
ALICE_PID=$!
echo "   PID=$ALICE_PID  log=$ALICE_DATA/node.log"

sleep 0.5

# ── Start Bob (p2p :26657, api :8081) ────────────────────────────
echo "==> Starting Bob    (p2p :26657, api :8081)"
"$BINARY" \
    --genesis   "$GENESIS" \
    --validator qcb1bob \
    --key-file  "$KEYS/bob.key.json" \
    --data-dir  "$BOB_DATA" \
    --p2p-port  26657 \
    --api-port  8081 \
    --bootstrap "/ip4/127.0.0.1/tcp/26656" \
    --bootstrap "/ip4/127.0.0.1/tcp/26658" \
    > "$BOB_DATA/node.log" 2>&1 &
BOB_PID=$!
echo "   PID=$BOB_PID  log=$BOB_DATA/node.log"

sleep 0.5

# ── Start Dave (p2p :26658, api :8082) ───────────────────────────
echo "==> Starting Dave   (p2p :26658, api :8082)"
"$BINARY" \
    --genesis   "$GENESIS" \
    --validator qcb1dave \
    --key-file  "$KEYS/dave.key.json" \
    --data-dir  "$DAVE_DATA" \
    --p2p-port  26658 \
    --api-port  8082 \
    --bootstrap "/ip4/127.0.0.1/tcp/26656" \
    --bootstrap "/ip4/127.0.0.1/tcp/26657" \
    > "$DAVE_DATA/node.log" 2>&1 &
DAVE_PID=$!
echo "   PID=$DAVE_PID  log=$DAVE_DATA/node.log"

# ── Write PID file ────────────────────────────────────────────────
echo "$ALICE_PID $BOB_PID $DAVE_PID" > "$DATA_BASE/machine1.pids"

echo ""
echo "All three nodes started (3-node local devnet)."
echo "PIDs: alice=$ALICE_PID  bob=$BOB_PID  dave=$DAVE_PID"
echo ""
echo "Wait ~5s then check status:"
echo "  curl -s http://localhost:8080/api/status | python3 -m json.tool"
echo ""
echo "Check blocks are being produced:"
echo "  curl -s http://localhost:8080/api/blocks | python3 -m json.tool"
echo ""
echo "Logs:"
echo "  tail -f $ALICE_DATA/node.log"
echo ""
echo "Stop: pkill -f chain-forge-node"
