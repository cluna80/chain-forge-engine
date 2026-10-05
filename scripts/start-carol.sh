#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Machine 2 (bossking@192.168.137.3) – Carol only
#
# Starts Carol's validator node and bootstraps into the Machine 1
# peers at 192.168.137.2.
#
# Prerequisites on Machine 2:
#   - Binary:  $HOME/chain-forge-node      (scp'd from Machine 1 after build)
#   - Key:     $HOME/qcb1carol.key.json
#   - Genesis: $HOME/genesis-4node.json    (copy of tests/devnet/genesis-4node.json)
#
# Usage: ./start-carol.sh [--clean]
#   --clean   wipes Carol's data dir before starting
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

BINARY="$HOME/chain-forge-node"
GENESIS="$HOME/genesis-4node.json"
KEY="$HOME/qcb1carol.key.json"
DATA="$HOME/chain-forge-data/carol"

MACHINE1_IP="192.168.137.2"
ALICE_P2P=26656
BOB_P2P=26657
DAVE_P2P=26658

# ── Clean? ──────────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]]; then
    echo "==> Wiping Carol data dir..."
    rm -rf "$DATA"
fi

mkdir -p "$DATA"

# ── Validate prerequisites ────────────────────────────────────────
for f in "$BINARY" "$GENESIS" "$KEY"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: Missing required file: $f"
        echo ""
        echo "Setup checklist:"
        echo "  1. Build on Machine 1: cd ~/chain-forge-engine && cargo build --release"
        echo "  2. Copy binary:  scp ~/chain-forge-engine/target/release/chain-forge-node bossking@192.168.137.3:~/chain-forge-node"
        echo "  3. Copy genesis: scp ~/chain-forge-engine/tests/devnet/genesis-4node.json bossking@192.168.137.3:~/genesis-4node.json"
        echo "  4. Copy key:     scp ~/chain-forge-engine/tests/devnet/keys/carol.key.json bossking@192.168.137.3:~/qcb1carol.key.json"
        exit 1
    fi
done

chmod +x "$BINARY"

# ── Start Carol (p2p :27000, api :8080) ──────────────────────────
echo "==> Starting Carol  (p2p :27000, api :8080)"
echo "    Bootstrapping into Machine 1 ($MACHINE1_IP)"

"$BINARY" \
    --genesis   "$GENESIS" \
    --validator qcb1carol \
    --key-file  "$KEY" \
    --data-dir  "$DATA" \
    --p2p-port  27000 \
    --api-port  8080 \
    --bootstrap "/ip4/${MACHINE1_IP}/tcp/${ALICE_P2P}" \
    --bootstrap "/ip4/${MACHINE1_IP}/tcp/${BOB_P2P}" \
    --bootstrap "/ip4/${MACHINE1_IP}/tcp/${DAVE_P2P}" \
    > "$DATA/node.log" 2>&1 &
CAROL_PID=$!

echo "$CAROL_PID" > "$DATA/carol.pid"
echo "   PID=$CAROL_PID  log=$DATA/node.log"
echo ""
echo "Tail log:   tail -f $DATA/node.log"
echo "Status:     curl -s http://localhost:8080/api/status | python3 -m json.tool"
echo "Stop:       kill $CAROL_PID"
