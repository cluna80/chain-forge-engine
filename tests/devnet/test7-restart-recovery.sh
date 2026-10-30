#!/usr/bin/env bash
# Acceptance Test #7 — Restart Recovery
#
# Verifies that a node resumes chain state from the last committed height
# after a clean shutdown and restart, rather than re-genesisin from height 0.
#
# What this test checks:
#   1. Start Machine 1 (Alice + Bob) with --data-dir so state is persisted
#   2. Wait for at least 5 blocks to be committed
#   3. Record the current height from Alice's API
#   4. Kill Alice and Bob
#   5. Restart Alice and Bob with the same --data-dir
#   6. Confirm the reported height on restart == height_before_shutdown
#      (i.e. node resumed from disk, not from genesis)
#   7. Wait for 2 more blocks to confirm chain continues producing after restart
#
# Prerequisites:
#   - Machine 2 (Carol + Dave) is already running on $MACHINE2_IP
#   - chain-forge-node binary is built (cargo build --release --bin chain-forge-node)
#   - Run from the repo root or pass BIN=, MACHINE2_IP=, DATA_DIR= as env vars
#
# Usage:
#   MACHINE2_IP=192.168.137.2 bash tests/devnet/test7-restart-recovery.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${BIN:-$REPO_ROOT/target/release/chain-forge-node}"
GENESIS="$SCRIPT_DIR/genesis-4node-mldsa.json"
KEY_DIR="$SCRIPT_DIR/keys/mldsa"
DATA_DIR="${DATA_DIR:-/tmp/qcb-devnet-test7-data}"
LOG_DIR="${LOG_DIR:-/tmp/qcb-devnet-test7-logs}"

# ── Machine 2 IP (required) ──────────────────────────────────────────────────
if [[ -z "${MACHINE2_IP:-}" ]]; then
    echo "ERROR: set MACHINE2_IP to Machine 2's LAN IP."
    echo "       Example: MACHINE2_IP=192.168.137.2 $0"
    exit 1
fi

CAROL_PEER="/ip4/${MACHINE2_IP}/tcp/28000"
DAVE_PEER="/ip4/${MACHINE2_IP}/tcp/28001"
ALICE_API="http://127.0.0.1:19080"
BOB_API="http://127.0.0.1:19081"

ALICE_DATA_DIR="$DATA_DIR/alice"
BOB_DATA_DIR="$DATA_DIR/bob"

echo "=== Acceptance Test #7: Restart Recovery ==="
echo "Machine 2 IP : $MACHINE2_IP"
echo "Binary       : $BIN"
echo "Data dirs    : $ALICE_DATA_DIR  $BOB_DATA_DIR"
echo ""

# ── Sanity checks ────────────────────────────────────────────────────────────
if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary not found: $BIN"
    exit 1
fi
mkdir -p "$ALICE_DATA_DIR" "$BOB_DATA_DIR" "$LOG_DIR"

# ── Helpers ──────────────────────────────────────────────────────────────────
get_height() {
    local url="$1/api/status"
    curl -sf "$url" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('height', -1))" 2>/dev/null || echo "-1"
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

wait_for_api() {
    local api="$1" label="$2"
    echo "  Waiting for $label API at $api ..."
    local attempts=0
    while true; do
        if curl -sf "$api/api/status" >/dev/null 2>&1; then
            echo "  $label API is up ✅"
            return 0
        fi
        attempts=$((attempts + 1))
        if [[ $attempts -ge 30 ]]; then
            echo "  ERROR: $label API timeout"
            return 1
        fi
        sleep 2
    done
}

start_nodes() {
    local suffix="$1"
    echo "  Starting Alice (api=:19080 p2p=:28000) ..."
    "$BIN" \
        --genesis "$GENESIS" \
        --validator qcb1alice \
        --key-file "$KEY_DIR/alice.key.json" \
        --api-port 19080 \
        --p2p-port 28000 \
        --data-dir "$ALICE_DATA_DIR" \
        --bootstrap "$CAROL_PEER" \
        --bootstrap "$DAVE_PEER" \
        > "$LOG_DIR/alice-${suffix}.log" 2>&1 &
    ALICE_PID=$!

    echo "  Starting Bob (api=:19081 p2p=:28001) ..."
    "$BIN" \
        --genesis "$GENESIS" \
        --validator qcb1bob \
        --key-file "$KEY_DIR/bob.key.json" \
        --api-port 19081 \
        --p2p-port 28001 \
        --data-dir "$BOB_DATA_DIR" \
        --bootstrap "$CAROL_PEER" \
        --bootstrap "$DAVE_PEER" \
        > "$LOG_DIR/bob-${suffix}.log" 2>&1 &
    BOB_PID=$!

    echo "  Alice PID=$ALICE_PID  Bob PID=$BOB_PID"
}

kill_nodes() {
    echo "  Killing Alice ($ALICE_PID) and Bob ($BOB_PID) ..."
    kill "$ALICE_PID" "$BOB_PID" 2>/dev/null || true
    sleep 2
    kill -9 "$ALICE_PID" "$BOB_PID" 2>/dev/null || true
    sleep 1
    echo "  Nodes stopped ✅"
}

# ── Phase 1: Start and let chain run ─────────────────────────────────────────
echo "--- Phase 1: Start nodes ---"
ALICE_PID=0
BOB_PID=0
start_nodes "run1"

wait_for_api "$ALICE_API" "Alice"
wait_for_api "$BOB_API"   "Bob"

echo "  Waiting for height ≥ 5 ..."
wait_for_height "$ALICE_API" 5 "Alice"

HEIGHT_BEFORE=$(get_height "$ALICE_API")
echo "  Height before shutdown: $HEIGHT_BEFORE"
echo ""

# ── Phase 2: Graceful shutdown ────────────────────────────────────────────────
echo "--- Phase 2: Shutdown ---"
kill_nodes
echo ""

# ── Phase 3: Restart from disk ───────────────────────────────────────────────
echo "--- Phase 3: Restart ---"
start_nodes "run2"

wait_for_api "$ALICE_API" "Alice (restart)"
wait_for_api "$BOB_API"   "Bob (restart)"

HEIGHT_AFTER_RESTART=$(get_height "$ALICE_API")
echo "  Height at restart: $HEIGHT_AFTER_RESTART"
echo ""

# ── Assertion: resumed from persisted height, not from genesis ───────────────
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
    kill_nodes
    exit 1
fi

echo ""

# ── Phase 4: Confirm chain continues producing ───────────────────────────────
echo "--- Phase 4: Confirm continued block production ---"
TARGET=$((HEIGHT_AFTER_RESTART + 2))
echo "  Waiting for height ≥ $TARGET ..."
wait_for_height "$ALICE_API" "$TARGET" "Alice"
HEIGHT_FINAL=$(get_height "$ALICE_API")
echo "  Final height: $HEIGHT_FINAL ✅"
echo ""

echo "✅ TEST #7 COMPLETE — Restart Recovery PASSED"
echo "   Run1 final height  : $HEIGHT_BEFORE"
echo "   After restart      : $HEIGHT_AFTER_RESTART  (from disk)"
echo "   After 2 more blocks: $HEIGHT_FINAL"

kill_nodes
