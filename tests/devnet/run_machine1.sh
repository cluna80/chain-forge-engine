#!/usr/bin/env bash
# run_machine1.sh — Machine 1: Alice (qcb1alice) + Bob (qcb1bob)
#
# Run this on Machine 1 AFTER run_machine2.sh is already running on Machine 2
# (or run both within a few seconds of each other — nodes retry peer connections).
#
# Usage:
#   MACHINE2_IP=192.168.1.X ./tests/devnet/run_machine1.sh
#
# Or export before running:
#   export MACHINE2_IP=192.168.1.X
#   ./tests/devnet/run_machine1.sh
#
# Optional overrides:
#   BIN=/path/to/chain-forge-node   (default: target/release/chain-forge-node)
#   LOG_DIR=/path/to/logs           (default: /tmp/qcb-devnet-machine1)

# Upgraded ML-DSA devnet (genesis-4node-mldsa.json, keys/mldsa/). Ports
# 19080-19081 / 28000-28001 never collide with the legacy devnet.
# The legacy Ed25519 devnet runs from branch devnet-legacy-2026-10.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${BIN:-$REPO_ROOT/target/release/chain-forge-node}"
GENESIS="$SCRIPT_DIR/genesis-4node-mldsa.json"
KEY_DIR="$SCRIPT_DIR/keys/mldsa"
LOG_DIR="${LOG_DIR:-/tmp/qcb-devnet-machine1}"

# ── Machine 2 IP (required) ─────────────────────────────────────────────────
if [[ -z "${MACHINE2_IP:-}" ]]; then
    echo "ERROR: set MACHINE2_IP to Machine 2's LAN IP."
    echo "       Example: MACHINE2_IP=192.168.1.42 $0"
    exit 1
fi

# Machine 2 runs Carol on P2P port 28000, Dave on 28001
CAROL_PEER="/ip4/${MACHINE2_IP}/tcp/28000"
DAVE_PEER="/ip4/${MACHINE2_IP}/tcp/28001"

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
    echo "── Tearing down Machine 1 nodes ────────────────────────────────────"
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
echo "  QCB 4-Node ML-DSA Devnet — Machine 1 (Alice + Bob)"
echo "  Machine 2 IP: $MACHINE2_IP"
echo "  Binary:       $BIN"
echo "  Logs:         $LOG_DIR"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Alice: API=19080, P2P=28000
echo "  Starting Alice  (api=:19080  p2p=:28000)"
"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1alice \
    --key-file "$KEY_DIR/alice.key.json" \
    --api-port 19080 \
    --p2p-port 28000 \
    --bootstrap "$CAROL_PEER" \
    --bootstrap "$DAVE_PEER" \
    > "$LOG_DIR/alice.log" 2>&1 &
PIDS+=($!)

# Bob: API=19081, P2P=28001
echo "  Starting Bob    (api=:19081  p2p=:28001)"
"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1bob \
    --key-file "$KEY_DIR/bob.key.json" \
    --api-port 19081 \
    --p2p-port 28001 \
    --bootstrap "$CAROL_PEER" \
    --bootstrap "$DAVE_PEER" \
    > "$LOG_DIR/bob.log" 2>&1 &
PIDS+=($!)

echo ""
echo "  Alice PID: ${PIDS[0]}   Bob PID: ${PIDS[1]}"
echo ""
echo "  Logs:"
echo "    tail -f $LOG_DIR/alice.log"
echo "    tail -f $LOG_DIR/bob.log"
echo ""
echo "  API:"
echo "    curl http://127.0.0.1:19080/api/status   # Alice"
echo "    curl http://127.0.0.1:19081/api/status   # Bob"
echo ""
echo "  Press Ctrl-C to stop."
echo ""

# ── Watch both processes and stream combined log ─────────────────────────────
echo "── Live log (both nodes) ────────────────────────────────────────────────"
tail -f "$LOG_DIR/alice.log" "$LOG_DIR/bob.log" &
TAIL_PID=$!

# Wait until a node dies or user interrupts
while true; do
    for i in 0 1; do
        pid="${PIDS[$i]}"
        name=$([[ $i -eq 0 ]] && echo "Alice" || echo "Bob")
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
