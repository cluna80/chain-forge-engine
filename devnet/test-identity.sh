#!/usr/bin/env bash
# test-identity.sh — verify identity registration flow on running devnet
# Run from Machine 1 or any machine that can reach 192.168.137.2:8080
set -euo pipefail

API="http://192.168.137.2:8080"

echo "=== Chain status ==="
curl -s "$API/api/status" | python3 -m json.tool

echo ""
echo "=== Pre-test: Alice balance and nonce ==="
curl -s "$API/api/accounts/qcb1alice" | python3 -m json.tool

# Get current nonce
NONCE=$(curl -s "$API/api/accounts/qcb1alice" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('nonce',0))")
echo "Alice current nonce: $NONCE"

echo ""
echo "=== Registering Alice identity (nonce=$NONCE) ==="
RESULT=$(curl -s -X POST "$API/api/tx" \
  -H "Content-Type: application/json" \
  -d "{
    \"id\": \"reg-alice-$(date +%s)\",
    \"sender\": \"qcb1alice\",
    \"nonce\": $NONCE,
    \"body\": {\"RegisterIdentity\": null},
    \"gas_limit\": 100000
  }")
echo "$RESULT" | python3 -m json.tool
TX_ID=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

if [ -n "$TX_ID" ]; then
  echo ""
  echo "=== Waiting 4s for block... ==="
  sleep 4
  echo "=== Transaction result ==="
  curl -s "$API/api/tx/$TX_ID" | python3 -m json.tool
fi

echo ""
echo "=== Identity record for Alice ==="
sleep 1
curl -s "$API/api/identity/qcb1alice" | python3 -m json.tool

echo ""
echo "=== Account state for Alice (should show tier) ==="
curl -s "$API/api/accounts/qcb1alice" | python3 -m json.tool
