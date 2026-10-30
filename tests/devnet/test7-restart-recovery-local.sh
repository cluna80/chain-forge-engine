#!/usr/bin/env bash
# Acceptance Test #7 — Restart Recovery (local 4-node simulation)
#
# Same as test7-restart-recovery.sh but runs all 4 validators locally
# (no MACHINE2_IP required). Carol and Dave run on ports 28002/28003,
# api 19082/19083. Alice and Bob are the nodes being restarted.
#
# Usage:
#   bash tests/devnet/test7-restart-recovery-local.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# JSON helpers (no python3 needed; works in Git Bash on Windows).
. "$SCRIPT_DIR/json.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${BIN:-$REPO_ROOT/target/release/chain-forge-node}"
GENESIS="$SCRIPT_DIR/genesis-4node-mldsa.json"
KEY_DIR="$SCRIPT_DIR/keys/mldsa"
DATA_DIR="${DATA_DIR:-/tmp/qcb-devnet-test7-data}"
LOG_DIR="${LOG_DIR:-/tmp/qcb-devnet-test7-logs}"

ALICE_API="http://127.0.0.1:19080"
BOB_API="http://127.0.0.1:19081"
CAROL_API="http://127.0.0.1:19082"
DAVE_API="http://127.0.0.1:19083"

ALICE_DATA_DIR="$DATA_DIR/alice"
BOB_DATA_DIR="$DATA_DIR/bob"

CAROL_PEER="/ip4/127.0.0.1/tcp/28002"
DAVE_PEER="/ip4/127.0.0.1/tcp/28003"
ALICE_PEER="/ip4/127.0.0.1/tcp/28000"
BOB_PEER="/ip4/127.0.0.1/tcp/28001"

CAROL_PID=0
DAVE_PID=0
ALICE_PID=0
BOB_PID=0

cleanup() {
    echo ""
    echo "── Cleanup: killing all test nodes ──────────────────────────────────"
    for pid in $ALICE_PID $BOB_PID $CAROL_PID $DAVE_PID; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in $ALICE_PID $BOB_PID $CAROL_PID $DAVE_PID; do
        kill -9 "$pid" 2>/dev/null || true
    done
    echo "── Logs: $LOG_DIR"
}
trap cleanup EXIT INT TERM

echo "=== Acceptance Test #7: Restart Recovery (local 4-node) ==="
echo "Binary  : $BIN"
echo "Data dir: $DATA_DIR"
echo "Log dir : $LOG_DIR"
echo ""

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary not found: $BIN"
    exit 1
fi

# Clean data dirs so we start fresh
rm -rf "$DATA_DIR"
mkdir -p "$ALICE_DATA_DIR" "$BOB_DATA_DIR" "$LOG_DIR"

get_height() {
    # /api/status "height" reflects live session commits only.
    # /api/blocks returns the full chain including persisted blocks.
    # We use the first (highest) block from /api/blocks as the authoritative height.
    local api="$1"
    # Try /api/blocks first (authoritative: includes persisted chain)
    local h
    local body
    if body=$(curl -sf "$api/api/blocks" 2>/dev/null); then
        h=$(printf '%s' "$body" | json_max_height)
    else
        h=-1
    fi
    echo "$h"
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

wait_for_height() {
    local api="$1" target="$2" label="$3"
    local attempts=0
    while true; do
        local h
        h=$(get_height "$api")
        if [[ "$h" -ge "$target" ]]; then
            echo "  $label at height $h ✅"
            return 0
        fi
        attempts=$((attempts + 1))
        if [[ $attempts -ge 60 ]]; then
            echo "  ERROR: $label timeout waiting for height $target (currently $h)"
            return 1
        fi
        sleep 2
    done
}

# ── Start Carol and Dave (they stay up through the whole test) ────────────────
echo "--- Starting Carol + Dave (stay up throughout) ---"
"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1carol \
    --key-file "$KEY_DIR/carol.key.json" \
    --api-port 19082 \
    --p2p-port 28002 \
    --bootstrap "$ALICE_PEER" \
    --bootstrap "$BOB_PEER" \
    > "$LOG_DIR/carol.log" 2>&1 &
CAROL_PID=$!

"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1dave \
    --key-file "$KEY_DIR/dave.key.json" \
    --api-port 19083 \
    --p2p-port 28003 \
    --bootstrap "$ALICE_PEER" \
    --bootstrap "$BOB_PEER" \
    > "$LOG_DIR/dave.log" 2>&1 &
DAVE_PID=$!

wait_for_api "$CAROL_API" "Carol"
wait_for_api "$DAVE_API"  "Dave"
echo ""

# ── Phase 1: Start Alice + Bob and let chain run ──────────────────────────────
echo "--- Phase 1: Start Alice + Bob ---"
"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1alice \
    --key-file "$KEY_DIR/alice.key.json" \
    --api-port 19080 \
    --p2p-port 28000 \
    --data-dir "$ALICE_DATA_DIR" \
    --bootstrap "$CAROL_PEER" \
    --bootstrap "$DAVE_PEER" \
    > "$LOG_DIR/alice-run1.log" 2>&1 &
ALICE_PID=$!

"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1bob \
    --key-file "$KEY_DIR/bob.key.json" \
    --api-port 19081 \
    --p2p-port 28001 \
    --data-dir "$BOB_DATA_DIR" \
    --bootstrap "$CAROL_PEER" \
    --bootstrap "$DAVE_PEER" \
    > "$LOG_DIR/bob-run1.log" 2>&1 &
BOB_PID=$!

wait_for_api "$ALICE_API" "Alice"
wait_for_api "$BOB_API"   "Bob"

echo "  Waiting for height ≥ 5 ..."
wait_for_height "$ALICE_API" 5 "Alice"

HEIGHT_BEFORE=$(get_height "$ALICE_API")
echo "  Height before shutdown: $HEIGHT_BEFORE"
echo ""

# ── Phase 2: Graceful shutdown of Alice + Bob ─────────────────────────────────
echo "--- Phase 2: Shutdown Alice + Bob ---"
kill "$ALICE_PID" "$BOB_PID" 2>/dev/null || true
sleep 2
kill -9 "$ALICE_PID" "$BOB_PID" 2>/dev/null || true
sleep 1
ALICE_PID=0
BOB_PID=0
echo "  Alice and Bob stopped ✅"
echo ""

# ── Phase 3: Restart Alice + Bob from disk ────────────────────────────────────
echo "--- Phase 3: Restart Alice + Bob from disk ---"
"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1alice \
    --key-file "$KEY_DIR/alice.key.json" \
    --api-port 19080 \
    --p2p-port 28000 \
    --data-dir "$ALICE_DATA_DIR" \
    --bootstrap "$CAROL_PEER" \
    --bootstrap "$DAVE_PEER" \
    > "$LOG_DIR/alice-run2.log" 2>&1 &
ALICE_PID=$!

"$BIN" \
    --genesis "$GENESIS" \
    --validator qcb1bob \
    --key-file "$KEY_DIR/bob.key.json" \
    --api-port 19081 \
    --p2p-port 28001 \
    --data-dir "$BOB_DATA_DIR" \
    --bootstrap "$CAROL_PEER" \
    --bootstrap "$DAVE_PEER" \
    > "$LOG_DIR/bob-run2.log" 2>&1 &
BOB_PID=$!

wait_for_api "$ALICE_API" "Alice (restart)"
wait_for_api "$BOB_API"   "Bob (restart)"

HEIGHT_AFTER_RESTART=$(get_height "$ALICE_API")
echo "  Height at restart: $HEIGHT_AFTER_RESTART"
echo ""

# ── Assertion: resumed from persisted height, not from genesis ────────────────
if [[ "$HEIGHT_AFTER_RESTART" -ge "$HEIGHT_BEFORE" ]]; then
    echo "✅ RESTART RECOVERY PASSED"
    echo "   Height before shutdown : $HEIGHT_BEFORE"
    echo "   Height at restart      : $HEIGHT_AFTER_RESTART"
    echo "   Node resumed from disk, NOT from genesis (height 0) ✅"
else
    echo "❌ RESTART RECOVERY FAILED"
    echo "   Height before shutdown : $HEIGHT_BEFORE"
    echo "   Height at restart      : $HEIGHT_AFTER_RESTART"
    echo "   Expected height_at_restart >= height_before_shutdown"
    exit 1
fi
echo ""

# ── Phase 4: Confirm chain continues producing after restart ──────────────────
echo "--- Phase 4: Confirm continued block production ---"
TARGET=$((HEIGHT_AFTER_RESTART + 2))
echo "  Waiting for height ≥ $TARGET (2 new blocks beyond restart height) ..."
wait_for_height "$ALICE_API" "$TARGET" "Alice"
HEIGHT_FINAL=$(get_height "$ALICE_API")
echo "  Final height: $HEIGHT_FINAL ✅"
echo ""

echo "✅ TEST #7 COMPLETE — Restart Recovery PASSED"
echo "   Run1 final height  : $HEIGHT_BEFORE"
echo "   After restart      : $HEIGHT_AFTER_RESTART  (from disk, chain_store)"
echo "   After 2 more blocks: $HEIGHT_FINAL"
