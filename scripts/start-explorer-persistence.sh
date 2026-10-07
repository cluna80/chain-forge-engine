#!/usr/bin/env bash
# start-explorer-persistence.sh
#
# Launch the explorer persistence daemon on Machine 1.
# Run this AFTER the devnet nodes are up (start-machine1.sh).
#
# The script polls Alice (8080), Bob (8081), Dave (8082) every 3 seconds
# and writes JSON snapshots to ~/chain-forge-engine/explorer-data/.
#
# The React frontend at C:\Dev\chain-forge-frontend should point its
# API base URL to http://192.168.137.2:8080 (Alice) for live REST calls,
# OR be configured to read the local data/ directory if served statically.
#
# Usage (on Machine 1):
#   cd ~/chain-forge-engine
#   ./scripts/start-explorer-persistence.sh
#
# To run in the background:
#   nohup ./scripts/start-explorer-persistence.sh > explorer-persistence.log 2>&1 &

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$REPO_ROOT/explorer-data"
LOG_FILE="$REPO_ROOT/explorer-persistence.log"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  QCB Chain Explorer Persistence"
echo "  Polling:  127.0.0.1:8080 (Alice), :8081 (Bob), :8082 (Dave)"
echo "  Output:   $OUT_DIR"
echo "  Log:      $LOG_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

mkdir -p "$OUT_DIR"

python3 "$SCRIPT_DIR/write_explorer_persistence.py" \
    --host 127.0.0.1 \
    --ports 8080,8081,8082 \
    --out "$OUT_DIR" \
    --interval 3
