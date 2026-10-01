#!/usr/bin/env bash
# restart-machine1.sh — kill old nodes, deploy new binary, start Alice/Bob/Dave
# Run on Machine 1 (192.168.137.2) after scp-ing the new binary to ~/chain-forge-node
set -euo pipefail

BINARY="$HOME/chain-forge-node"
GENESIS="$HOME/genesis-4node.json"
KEYS="$HOME/chain-forge-engine/tests/devnet/keys"
LOG_DIR="$HOME/logs"

echo "==> Stopping any running chain-forge-node processes..."
pkill -9 -f chain-forge-node 2>/dev/null || true
sleep 1

mkdir -p "$LOG_DIR"

echo "==> Starting Alice (api=8080, p2p=26656)..."
nohup "$BINARY" \
  --genesis "$GENESIS" \
  --validator qcb1alice \
  --key-file "$KEYS/alice.key.json" \
  --api-port 8080 \
  --p2p-port 26656 \
  --bootstrap /ip4/192.168.137.3/tcp/26659 \
  > "$LOG_DIR/alice.log" 2>&1 &
echo "Alice PID=$!"

sleep 0.5

echo "==> Starting Bob (api=8081, p2p=26657)..."
nohup "$BINARY" \
  --genesis "$GENESIS" \
  --validator qcb1bob \
  --key-file "$KEYS/bob.key.json" \
  --api-port 8081 \
  --p2p-port 26657 \
  --bootstrap /ip4/192.168.137.3/tcp/26659 \
  > "$LOG_DIR/bob.log" 2>&1 &
echo "Bob PID=$!"

sleep 0.5

echo "==> Starting Dave (api=8082, p2p=26658)..."
nohup "$BINARY" \
  --genesis "$GENESIS" \
  --validator qcb1dave \
  --key-file "$KEYS/dave.key.json" \
  --api-port 8082 \
  --p2p-port 26658 \
  --bootstrap /ip4/192.168.137.3/tcp/26659 \
  > "$LOG_DIR/dave.log" 2>&1 &
echo "Dave PID=$!"

echo ""
echo "==> All 3 nodes started. Tailing alice.log (Ctrl-C to stop)..."
sleep 2
tail -f "$LOG_DIR/alice.log"
