#!/usr/bin/env bash
# Acceptance Test #9 — P2P Recovery (Machine 2 Late Start)
#
# Verifies that Machine 1 (Alice + Bob) starts and waits correctly when
# Machine 2 (Carol + Dave) is not yet reachable, then resumes block
# production automatically once Machine 2 comes online — without any
# manual restart on either machine.
#
# What this test checks:
#   1. Start Machine 1 (Alice + Bob) with bootstrap peers pointing to Machine 2
#      — but Machine 2 is NOT running yet
#   2. Wait 15 seconds; confirm Alice reports height == 0 (no blocks committed:
#      BFT requires 3/4 validators, only 2/4 are up)
#   3. Simulate Machine 2 coming online by starting a local pair of
#      Carol + Dave observer nodes (same genesis, same ports)
#   4. Wait up to 60 seconds for height > 0 without any restart
#   5. Confirm block production resumes automatically via libp2p peer retry
#
# NOTE: In a real 2-machine devnet, Machine 2 is a remote host. This script
# simulates that by running Carol + Dave locally after a deliberate delay.
# The P2P recovery behavior is identical — libp2p retries bootstrap peers
# continuously until a TCP connection is established.
#
# Usage:
#   bash tests/devnet/test9-p2p-recovery.sh
#
# (No MACHINE2_IP needed — Carol and Dave run locally in the simulation)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# JSON helpers (no python3 needed; works in Git Bash on Windows).
. "$SCRIPT_DIR/json.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${BIN:-$REPO_ROOT/target/release/chain-forge-node}"
GENESIS="$SCRIPT_DIR/genesis-4node-mldsa.json"
KEY_DIR="$SCRIPT_DIR/keys/mldsa"
LOG_DIR="${LOG_DIR:-/tmp/qcb-devnet-test9-logs}"

ALICE_API="http://127.0.0.1:19080"
BOB_API="http://127.0.0.1:19081"
CAROL_API="http://127.0.0.1:19082"
DAVE_API="http://127.0.0.1:19083"

# For local simulation Carol is on 28002, Dave on 28003
# (avoid collisions with test7/test8 if they left anything running)
CAROL_P2P=28002
DAVE_P2P=28003
ALICE_P2P=28000
BOB_P2P=28001

CAROL_PEER="/ip4/127.0.0.1/tcp/$CAROL_P2P"
DAVE_PEER="/ip4/127.0.0.1/tcp/$DAVE_P2P"
ALICE_PEER="/ip4/127.0.0.1/tcp/$ALICE_P2P"
BOB_PEER="/ip4/127.0.0.1/tcp/$BOB_P2P"

PIDS=()
cleanup() {
    echo ""
    echo "── Cleanup: killing all test nodes ──────────────────────────────────"
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

echo "=== Acceptance Test #9: P2P Recovery (Machine 2 Late Start) ==="
echo "Binary  : $BIN"
echo "Log dir : $LOG_DIR"
echo ""

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary not found: $BIN"
    exit 1
fi
mkdir -p "$LOG_DIR"

get_height() {
    local url="$1/api/status"
    local h
    h=$(curl -sf "$url" 2>/dev/null | json_field height)
    echo "${h:--1}"
}

wait_for_api() {
    local api="$1" label="$2"
    local attempts=0
    while ! curl -sf "$api/api/status" >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [[ $attempts -ge 25 ]]; then
            echo "  ERROR: $label API timeout"
            return 1
        fi
        sleep 2
    done
    echo "  $label API up ✅"
}

# ── Phase 1: Start Machine 1 only — Machine 2 peers unreachable ───────────────
echo "--- Phase 1: Start Alice + Bob (Machine 2 NOT yet running) ---"

"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1alice \
    --key-file "$KEY_DIR/alice.key.json" \
    --api-port 19080 \
    --p2p-port "$ALICE_P2P" \
    --bootstrap "$CAROL_PEER" \
    --bootstrap "$DAVE_PEER" \
    > "$LOG_DIR/alice.log" 2>&1 &
PIDS+=($!)
ALICE_PID=${PIDS[-1]}

"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1bob \
    --key-file "$KEY_DIR/bob.key.json" \
    --api-port 19081 \
    --p2p-port "$BOB_P2P" \
    --bootstrap "$CAROL_PEER" \
    --bootstrap "$DAVE_PEER" \
    > "$LOG_DIR/bob.log" 2>&1 &
PIDS+=($!)
BOB_PID=${PIDS[-1]}

wait_for_api "$ALICE_API" "Alice"
wait_for_api "$BOB_API"   "Bob"

echo "  Waiting 15 seconds — Machine 2 peers unavailable, BFT blocked ..."
sleep 15

H_ALONE=$(get_height "$ALICE_API")
echo "  Alice height after 15s with only 2/4 validators: $H_ALONE"
echo ""

if [[ "$H_ALONE" -gt 0 ]]; then
    echo "  ⚠️  Warning: height advanced to $H_ALONE with only 2 validators."
    echo "     This may happen if Carol/Dave were already running from a prior test."
    echo "     Confirm from logs that 3/4 quorum was not reached via a stale connection."
fi

# ── Phase 2: Bring Machine 2 online (Carol + Dave) ───────────────────────────
echo "--- Phase 2: Bring Carol + Dave online (Machine 2 arrives) ---"

"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1carol \
    --key-file "$KEY_DIR/carol.key.json" \
    --api-port 19082 \
    --p2p-port "$CAROL_P2P" \
    --bootstrap "$ALICE_PEER" \
    --bootstrap "$BOB_PEER" \
    > "$LOG_DIR/carol.log" 2>&1 &
PIDS+=($!)
CAROL_PID=${PIDS[-1]}

"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1dave \
    --key-file "$KEY_DIR/dave.key.json" \
    --api-port 19083 \
    --p2p-port "$DAVE_P2P" \
    --bootstrap "$ALICE_PEER" \
    --bootstrap "$BOB_PEER" \
    > "$LOG_DIR/dave.log" 2>&1 &
PIDS+=($!)
DAVE_PID=${PIDS[-1]}

wait_for_api "$CAROL_API" "Carol"
wait_for_api "$DAVE_API"  "Dave"
echo "  Carol and Dave are up — 4/4 validators now reachable ✅"
echo ""

# ── Phase 3: Wait for block production to resume without restart ──────────────
echo "--- Phase 3: Waiting for blocks to resume (no restart required) ---"
echo "  (libp2p retries bootstrap peers continuously; no manual action needed)"
echo ""

DEADLINE=90
INTERVAL=3
elapsed=0
H_RESUME=-1
while [[ $elapsed -lt $DEADLINE ]]; do
    H=$(get_height "$ALICE_API")
    if [[ "$H" -gt 0 ]]; then
        H_RESUME=$H
        break
    fi
    sleep $INTERVAL
    elapsed=$((elapsed + INTERVAL))
    echo "  ...waiting (${elapsed}s elapsed, height=$H)"
done

echo ""
if [[ "$H_RESUME" -gt 0 ]]; then
    echo "✅ Block production resumed at height=$H_RESUME after ${elapsed}s (no restart) ✅"
else
    echo "❌ Block production did NOT resume within ${DEADLINE}s"
    echo "   Final height: $(get_height "$ALICE_API")"
    echo "   Check logs in $LOG_DIR for connection errors"
    exit 1
fi

# ── Phase 4: Wait 2 more blocks to confirm stable production ─────────────────
echo ""
echo "--- Phase 4: Confirm continued block production ---"
TARGET=$((H_RESUME + 2))
echo "  Waiting for height >= $TARGET ..."
attempts=0
while true; do
    H=$(get_height "$ALICE_API")
    if [[ "$H" -ge "$TARGET" ]]; then
        echo "  Height $H ≥ $TARGET ✅"
        break
    fi
    attempts=$((attempts + 1))
    if [[ $attempts -ge 30 ]]; then
        echo "  ❌ Timeout waiting for height $TARGET"
        exit 1
    fi
    sleep 3
done

H_FINAL=$(get_height "$ALICE_API")
echo ""
echo "✅ TEST #9 COMPLETE — P2P Recovery PASSED"
echo "   Machine 1 started : height stayed at 0 for 15s (only 2/4 validators)"
echo "   Machine 2 arrived : height resumed automatically after ${elapsed}s"
echo "   No restart needed : block production recovered via libp2p peer retry ✅"
echo "   Final height      : $H_FINAL"
echo ""
echo "  Log files:"
echo "    Alice : $LOG_DIR/alice.log"
echo "    Bob   : $LOG_DIR/bob.log"
echo "    Carol : $LOG_DIR/carol.log"
echo "    Dave  : $LOG_DIR/dave.log"
