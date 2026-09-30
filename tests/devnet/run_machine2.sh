#!/usr/bin/env bash
# run_machine2.sh — Machine 2: Carol (qcb1carol) + Dave (qcb1dave)
#
# Run this on Machine 2 BEFORE or at the same time as run_machine1.sh on Machine 1.
# Nodes retry peer connections, so a few seconds of difference is fine.
#
# Usage:
#   MACHINE1_IP=192.168.1.X ./tests/devnet/run_machine2.sh
#
# Or export before running:
#   export MACHINE1_IP=192.168.1.X
#   ./tests/devnet/run_machine2.sh
#
# Optional overrides:
#   BIN=/path/to/chain-forge-node   (default: target/release/chain-forge-node)
#   LOG_DIR=/path/to/logs           (default: /tmp/qcb-devnet-machine2)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${BIN:-$REPO_ROOT/target/release/chain-forge-node}"
GENESIS="$SCRIPT_DIR/genesis-4node.json"
KEY_DIR="$SCRIPT_DIR/keys"
LOG_DIR="${LOG_DIR:-/tmp/qcb-devnet-machine2}"

# ── Machine 1 IP (required) ─────────────────────────────────────────────────
if [[ -z "${MACHINE1_IP:-}" ]]; then
    echo "ERROR: set MACHINE1_IP to Machine 1's LAN IP."
    echo "       Example: MACHINE1_IP=192.168.1.41 $0"
    exit 1
fi

# Machine 1 runs Alice on P2P port 27000, Bob on 27001
ALICE_PEER="/ip4/${MACHINE1_IP}/tcp/27000"
BOB_PEER="/ip4/${MACHINE1_IP}/tcp/27001"

# ── Sanity checks ────────────────────────────────────────────────────────────
if [[ ! -x "$BIN" ]]; then
    echo "ERROR: node binary not found or not executable: $BIN"
    echo "       Run: cargo build --release --bin chain-forge-node"
    exit 1
fi
if [[ ! -f "$GENESIS" ]]; then
    echo "ERROR: genesis file not found: $GENESIS"
    exit 1
fi

# ── Cleanup function ─────────────────────────────────────────────────────────
PIDS=()

cleanup() {
    echo ""
    echo "── Tearing down Machine 2 nodes ────────────────────────────────────"
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in "${PIDS[@]:-}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    echo "── Logs: $LOG_DIR"
}
trap cleanup EXIT INT TERM

# ── Start nodes ──────────────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"

echo "═══════════════════════════════════════════════════════════════"
echo "  QCB 4-Node Devnet — Machine 2 (Carol + Dave)"
echo "  Machine 1 IP: $MACHINE1_IP"
echo "  Binary:       $BIN"
echo "  Logs:         $LOG_DIR"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Carol: API=18080, P2P=27000
echo "  Starting Carol  (api=:18080  p2p=:27000)"
"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1carol \
    --key-file "$KEY_DIR/carol.key.json" \
    --api-port 18080 \
    --p2p-port 27000 \
    --bootstrap "$ALICE_PEER" \
    --bootstrap "$BOB_PEER" \
    > "$LOG_DIR/carol.log" 2>&1 &
PIDS+=($!)

# Dave: API=18081, P2P=27001
echo "  Starting Dave   (api=:18081  p2p=:27001)"
"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1dave \
    --key-file "$KEY_DIR/dave.key.json" \
    --api-port 18081 \
    --p2p-port 27001 \
    --bootstrap "$ALICE_PEER" \
    --bootstrap "$BOB_PEER" \
    > "$LOG_DIR/dave.log" 2>&1 &
PIDS+=($!)

echo ""
echo "  Carol PID: ${PIDS[0]}   Dave PID: ${PIDS[1]}"
echo ""
echo "  Logs:"
echo "    tail -f $LOG_DIR/carol.log"
echo "    tail -f $LOG_DIR/dave.log"
echo ""
echo "  API:"
echo "    curl http://127.0.0.1:18080/api/status   # Carol"
echo "    curl http://127.0.0.1:18081/api/status   # Dave"
echo ""
echo "  Press Ctrl-C to stop."
echo ""

# ── Watch both processes and stream combined log ─────────────────────────────
echo "── Live log (both nodes) ────────────────────────────────────────────────"
tail -f "$LOG_DIR/carol.log" "$LOG_DIR/dave.log" &
TAIL_PID=$!

# Wait until a node dies or user interrupts
while true; do
    for i in 0 1; do
        pid="${PIDS[$i]}"
        name=$([[ $i -eq 0 ]] && echo "Carol" || echo "Dave")
        if ! kill -0 "$pid" 2>/dev/null; then
            echo ""
            echo "ERROR: $name (pid $pid) exited unexpectedly."
            echo "── Last 30 lines of ${name,,}.log ──"
            tail -30 "$LOG_DIR/${name,,}.log" 2>/dev/null || true
            kill "$TAIL_PID" 2>/dev/null || true
            exit 1
        fi
    done
    sleep 5
done
