#!/usr/bin/env bash
# run_4node_devnet.sh — 4-node devnet integration test
#
# Spawns four chain-forge-node processes (Alice, Bob, Carol, Dave) against
# the 4-node genesis, waits for all of them to reach height >= TARGET_HEIGHT
# by polling their /api/status endpoints, then tears them down cleanly.
#
# Exit codes:
#   0 — all four nodes reached TARGET_HEIGHT within TIMEOUT_SECS
#   1 — one or more nodes failed to reach TARGET_HEIGHT (timeout or crash)
#
# Usage:
#   ./tests/devnet/run_4node_devnet.sh [--bin <path>] [--timeout <secs>] [--target-height <n>]
#
# From repo root:
#   cargo build --bin chain-forge-node
#   ./tests/devnet/run_4node_devnet.sh

set -euo pipefail

# ── Defaults -----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${BIN:-$REPO_ROOT/target/debug/chain-forge-node}"
GENESIS="$SCRIPT_DIR/genesis-4node.json"
TIMEOUT_SECS="${TIMEOUT_SECS:-60}"
TARGET_HEIGHT="${TARGET_HEIGHT:-3}"
LOG_DIR="${LOG_DIR:-/tmp/qcb-devnet-4node}"

# Ports: each node gets its own API port and P2P port so they don't collide.
VALIDATORS=("qcb1alice" "qcb1bob" "qcb1carol" "qcb1dave")
API_PORTS=(18080 18081 18082 18083)
P2P_PORTS=(27000 27001 27002 27003)

# ── Parse args ---------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin)       BIN="$2";           shift 2 ;;
        --timeout)   TIMEOUT_SECS="$2";  shift 2 ;;
        --target-height) TARGET_HEIGHT="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 1 ;;
    esac
done

# ── Sanity checks ------------------------------------------------------------
if [[ ! -x "$BIN" ]]; then
    echo "ERROR: node binary not found or not executable: $BIN"
    echo "       Run: cargo build --bin chain-forge-node"
    exit 1
fi

if [[ ! -f "$GENESIS" ]]; then
    echo "ERROR: genesis file not found: $GENESIS"
    exit 1
fi

# ── Cleanup function ---------------------------------------------------------
PIDS=()

cleanup() {
    local exit_code=$?
    echo ""
    echo "── Tearing down nodes ──────────────────────────────────────────────"
    for pid in "${PIDS[@]:-}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # Give them a moment to exit cleanly
    sleep 0.5
    for pid in "${PIDS[@]:-}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    echo "── Done. Logs in: $LOG_DIR"
    exit $exit_code
}
trap cleanup EXIT INT TERM

# ── Start nodes --------------------------------------------------------------
mkdir -p "$LOG_DIR"

echo "── Starting 4-node devnet ──────────────────────────────────────────────"
echo "   Binary:        $BIN"
echo "   Genesis:       $GENESIS"
echo "   Target height: $TARGET_HEIGHT"
echo "   Timeout:       ${TIMEOUT_SECS}s"
echo "   Log dir:       $LOG_DIR"
echo ""

for i in "${!VALIDATORS[@]}"; do
    validator="${VALIDATORS[$i]}"
    api_port="${API_PORTS[$i]}"
    p2p_port="${P2P_PORTS[$i]}"
    log_file="$LOG_DIR/${validator}.log"

    echo "   Starting $validator  api=:$api_port  p2p=:$p2p_port"

    "$BIN" \
        --genesis "$GENESIS" \
        --validator "$validator" \
        --api-port "$api_port" \
        --p2p-port "$p2p_port" \
        > "$log_file" 2>&1 &

    PIDS+=($!)
done

echo ""
echo "   Node PIDs: ${PIDS[*]}"
echo ""

# ── Poll until all nodes reach target height ---------------------------------
echo "── Polling /api/status until all nodes reach height $TARGET_HEIGHT ─────"

start_time=$(date +%s)
declare -A node_heights

while true; do
    now=$(date +%s)
    elapsed=$(( now - start_time ))

    if (( elapsed >= TIMEOUT_SECS )); then
        echo ""
        echo "TIMEOUT after ${TIMEOUT_SECS}s. Final heights:"
        for i in "${!VALIDATORS[@]}"; do
            validator="${VALIDATORS[$i]}"
            api_port="${API_PORTS[$i]}"
            height="${node_heights[$validator]:-?}"
            echo "   $validator  height=$height  (need $TARGET_HEIGHT)"
        done
        echo ""
        echo "FAIL: 4-node devnet did not reach height $TARGET_HEIGHT within ${TIMEOUT_SECS}s"

        # Print last 20 lines of each node log for diagnosis
        for validator in "${VALIDATORS[@]}"; do
            log_file="$LOG_DIR/${validator}.log"
            echo ""
            echo "── $validator log (last 20 lines) ──────────────────────────"
            tail -20 "$log_file" 2>/dev/null || echo "(no log)"
        done

        exit 1
    fi

    all_reached=true
    status_line=""

    for i in "${!VALIDATORS[@]}"; do
        validator="${VALIDATORS[$i]}"
        api_port="${API_PORTS[$i]}"

        # Check the process is still alive
        pid="${PIDS[$i]}"
        if ! kill -0 "$pid" 2>/dev/null; then
            echo ""
            echo "FAIL: $validator (pid $pid) has exited unexpectedly."
            echo "Last 30 lines of ${validator}.log:"
            tail -30 "$LOG_DIR/${validator}.log" 2>/dev/null || true
            exit 1
        fi

        # Poll /api/status
        response=$(curl -sf --max-time 1 "http://127.0.0.1:${api_port}/api/status" 2>/dev/null || echo "")
        if [[ -n "$response" ]]; then
            height=$(echo "$response" | grep -o '"height":[0-9]*' | grep -o '[0-9]*' || echo "0")
            node_heights[$validator]="${height:-0}"
        else
            node_heights[$validator]="${node_heights[$validator]:-0}"
        fi

        h="${node_heights[$validator]:-0}"
        status_line+="  $validator=$h"
        if (( h < TARGET_HEIGHT )); then
            all_reached=false
        fi
    done

    printf "\r   [%3ds] %s" "$elapsed" "$status_line"

    if $all_reached; then
        echo ""
        echo ""
        echo "── All nodes reached height $TARGET_HEIGHT ─────────────────────"
        for validator in "${VALIDATORS[@]}"; do
            echo "   $validator  height=${node_heights[$validator]}"
        done
        echo ""
        echo "PASS: 4-node devnet reached height $TARGET_HEIGHT in ${elapsed}s"
        exit 0
    fi

    sleep 0.5
done
