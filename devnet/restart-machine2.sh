#!/usr/bin/env bash
# restart-machine2.sh — kill old Carol, deploy new binary, start Carol
# Run on Machine 2 (192.168.137.3) after scp-ing the new binary to ~/chain-forge-node
set -euo pipefail

BINARY="$HOME/chain-forge-node"
GENESIS="$HOME/genesis-3node.json"
LOG_DIR="$HOME/logs"

echo "==> Stopping any running chain-forge-node processes..."
pkill -9 -f chain-forge-node 2>/dev/null || true
sleep 1

mkdir -p "$LOG_DIR"

echo "==> Starting Carol (api=8083, p2p=26659)..."
nohup "$BINARY" \
  --genesis "$GENESIS" \
  --validator qcb1carol \
  --api-port 8083 \
  --p2p-port 26659 \
  --bootstrap /ip4/192.168.137.2/tcp/26656 \
  > "$LOG_DIR/carol.log" 2>&1 &
echo "Carol PID=$!"

echo ""
echo "==> Carol started. Tailing carol.log (Ctrl-C to stop)..."
sleep 2
tail -f "$LOG_DIR/carol.log"
