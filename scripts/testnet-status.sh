#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Query status from all 4 testnet nodes and display a summary.
# Run from Machine 1; requires curl.
# ─────────────────────────────────────────────────────────────────
MACHINE2_IP="192.168.137.3"

check_node() {
    local label="$1"
    local url="$2"
    local result
    result=$(curl -s --connect-timeout 3 "$url/api/status" 2>/dev/null) || true
    if [[ -z "$result" ]]; then
        printf "  %-8s  %-30s  %-10s\n" "$label" "$url" "OFFLINE"
        return
    fi
    local height peers chain_id
    height=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('height', '?'))" 2>/dev/null || echo "?")
    peers=$(echo  "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('peers', '?'))"  2>/dev/null || echo "?")
    chain_id=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('chain_id', '?'))" 2>/dev/null || echo "?")
    printf "  %-8s  %-30s  height=%-6s  peers=%-3s  chain=%s\n" "$label" "$url" "$height" "$peers" "$chain_id"
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Chain Forge 4-Node Testnet Status"
echo "═══════════════════════════════════════════════════════════"
echo ""
check_node "Alice"  "http://localhost:8080"
check_node "Bob"    "http://localhost:8081"
check_node "Dave"   "http://localhost:8082"
check_node "Carol"  "http://${MACHINE2_IP}:8080"
echo ""
