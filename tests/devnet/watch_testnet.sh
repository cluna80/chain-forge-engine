#!/usr/bin/env bash
# watch_testnet.sh — Poll all 4 nodes every 30s and print a status table.
#
# Run from either machine. Needs both IPs.
#
# Usage:
#   MACHINE1_IP=192.168.1.X MACHINE2_IP=192.168.1.Y ./tests/devnet/watch_testnet.sh
#
# Logs a line per poll to /tmp/qcb-devnet-watch.log so you have a height
# history to review after the 72-hour run.

set -euo pipefail

if [[ -z "${MACHINE1_IP:-}" || -z "${MACHINE2_IP:-}" ]]; then
    echo "Usage: MACHINE1_IP=x.x.x.x MACHINE2_IP=y.y.y.y $0"
    exit 1
fi

POLL_SECS="${POLL_SECS:-30}"
LOG_FILE="${LOG_FILE:-/tmp/qcb-devnet-watch.log}"

# Node name → host:port
declare -A NODES
NODES["Alice"]="${MACHINE1_IP}:18080"
NODES["Bob"]="${MACHINE1_IP}:18081"
NODES["Carol"]="${MACHINE2_IP}:18080"
NODES["Dave"]="${MACHINE2_IP}:18081"

ORDER=("Alice" "Bob" "Carol" "Dave")

echo "QCB 4-Node Devnet Watcher"
echo "  Machine 1 ($MACHINE1_IP): Alice :18080, Bob :18081"
echo "  Machine 2 ($MACHINE2_IP): Carol :18080, Dave :18081"
echo "  Poll interval: ${POLL_SECS}s"
echo "  Log: $LOG_FILE"
echo ""
printf "%-20s %8s %8s %8s %8s\n" "Time" "Alice" "Bob" "Carol" "Dave"
printf "%-20s %8s %8s %8s %8s\n" "--------------------" "--------" "--------" "--------" "--------"

while true; do
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    heights=()
    statuses=()

    for name in "${ORDER[@]}"; do
        addr="${NODES[$name]}"
        response=$(curl -sf --max-time 3 "http://${addr}/api/status" 2>/dev/null || echo "")
        if [[ -n "$response" ]]; then
            height=$(echo "$response" | grep -o '"height":[0-9]*' | grep -o '[0-9]*' || echo "?")
            heights+=("${height:-?}")
            statuses+=("ok")
        else
            heights+=("ERR")
            statuses+=("unreachable")
        fi
    done

    line=$(printf "%-20s %8s %8s %8s %8s" \
        "$ts" "${heights[0]}" "${heights[1]}" "${heights[2]}" "${heights[3]}")

    echo "$line"
    echo "$line" >> "$LOG_FILE"

    # Flag if any node is more than 3 blocks behind the max
    max_h=0
    for h in "${heights[@]}"; do
        [[ "$h" =~ ^[0-9]+$ ]] && (( h > max_h )) && max_h=$h
    done
    for i in "${!ORDER[@]}"; do
        h="${heights[$i]}"
        name="${ORDER[$i]}"
        if [[ "$h" == "ERR" ]]; then
            echo "  ⚠  ${name} is unreachable" | tee -a "$LOG_FILE"
        elif [[ "$h" =~ ^[0-9]+$ ]] && (( max_h - h > 3 )); then
            echo "  ⚠  ${name} is lagging: height=$h, max=$max_h" | tee -a "$LOG_FILE"
        fi
    done

    sleep "$POLL_SECS"
done
