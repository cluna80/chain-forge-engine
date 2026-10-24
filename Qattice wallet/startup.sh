#!/bin/sh
set -eu
cd /workspace
if curl -sf -o /dev/null --max-time 1 http://127.0.0.1:8080/; then
  exit 0
fi
npm run dev >/tmp/qattice-dev.log 2>&1 &
