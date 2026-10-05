#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Machine 1 (king@192.168.137.2) – Alice · Bob · Dave
#
# Starts three validator nodes and waits for them to peer with Carol
# on Machine 2 (192.168.137.3).
#
# Usage: ./scripts/start-machine1.sh [--clean]
#   --clean   wipes all data dirs before starting (fresh chain)
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$REPO/target/release/chain-forge-node"
GENESIS="$REPO/tests/devnet/genesis-4node.json"
KEYS="$REPO/tests/devnet/keys"
DATA_BASE="$HOME/chain-forge-data"

ALICE_DATA="$DATA_BASE/alice"
BOB_DATA="$DATA_BASE/bob"
DAVE_DATA="$DATA_BASE/dave"

MACHINE2_IP="192.168.137.3"
CAROL_P2P_PORT=27000    # carol binds this on Machine 2

# ── Clean? ──────────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]]; then
    echo "==> Wiping data dirs..."
    rm -rf "$ALICE_DATA" "$BOB_DATA" "$DAVE_DATA"
fi

mkdir -p "$ALICE_DATA" "$BOB_DATA" "$DAVE_DATA"

# ── Copy genesis to each data dir for easy reference ─────────────
cp "$GENESIS" "$ALICE_DATA/genesis.json"
cp "$GENESIS" "$BOB_DATA/genesis.json"
cp "$GENESIS" "$DAVE_DATA/genesis.json"

# ── Bootstrap: Machine 2 Carol's p2p address ─────────────────────
CAROL_BOOTSTRAP="/ip4/${MACHINE2_IP}/tcp/${CAROL_P2P_PORT}"

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
    --bootstrap "$CAROL_BOOTSTRAP" \
    > "$ALICE_DATA/node.log" 2>&1 &
ALICE_PID=$!
echo "   PID=$ALICE_PID  log=$ALICE_DATA/node.log"

sleep 0.5   # brief stagger so Alice binds its port first

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
    --bootstrap "$CAROL_BOOTSTRAP" \
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
    --bootstrap "$CAROL_BOOTSTRAP" \
    > "$DAVE_DATA/node.log" 2>&1 &
DAVE_PID=$!
echo "   PID=$DAVE_PID  log=$DAVE_DATA/node.log"

# ── Write PID file for stop script ───────────────────────────────
echo "$ALICE_PID $BOB_PID $DAVE_PID" > "$DATA_BASE/machine1.pids"
echo ""
echo "All three nodes started."
echo "PIDs: alice=$ALICE_PID  bob=$BOB_PID  dave=$DAVE_PID"
echo ""
echo "Tail logs:"
echo "  tail -f $ALICE_DATA/node.log"
echo "  tail -f $BOB_DATA/node.log"
echo "  tail -f $DAVE_DATA/node.log"
echo ""
echo "Health checks:"
echo "  curl -s http://localhost:8080/api/status | python3 -m json.tool"
echo "  curl -s http://localhost:8081/api/status | python3 -m json.tool"
echo "  curl -s http://localhost:8082/api/status | python3 -m json.tool"
echo ""
echo "Stop all: ./scripts/stop-machine1.sh"
