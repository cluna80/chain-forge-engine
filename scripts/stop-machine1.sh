#!/usr/bin/env bash
# Kill all Machine 1 nodes started by start-machine1.sh
set -euo pipefail
DATA_BASE="$HOME/chain-forge-data"
PID_FILE="$DATA_BASE/machine1.pids"

if [[ ! -f "$PID_FILE" ]]; then
    echo "No PID file found at $PID_FILE — nothing to stop."
    exit 0
fi

read -ra PIDS < "$PID_FILE"
for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
        echo "Stopping PID $pid"
        kill "$pid"
    else
        echo "PID $pid already exited"
    fi
done
rm -f "$PID_FILE"
echo "Done."
