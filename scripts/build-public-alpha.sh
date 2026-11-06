#!/usr/bin/env bash
# Build the Qattice public-alpha release binary.
#
#   scripts/build-public-alpha.sh <launch-manifest.json> <genesis.json>
#
# 1. Verifies the genesis against the launch manifest (qcb-launch). A genesis that omits or changes
#    commitment_profile "qattice-v2", is not ML-DSA-only, or differs from the manifest's pinned hash STOPS the build here.
# 2. Builds chain-forge-node in release mode with the `public-alpha` feature, which includes `signing-v2` and the conformant
#    FIPS 204 backend. The general development build keeps these feature-gated.
#
# Environment: QCB_LAUNCH_BIN = path to a prebuilt qcb-launch (default: built with cargo); QCB_DRY_RUN=1 = print the build
# command instead of running it.
set -euo pipefail

manifest="${1:?usage: build-public-alpha.sh <launch-manifest.json> <genesis.json>}"
genesis="${2:?usage: build-public-alpha.sh <launch-manifest.json> <genesis.json>}"

if [ -n "${QCB_LAUNCH_BIN:-}" ]; then
  "$QCB_LAUNCH_BIN" verify --manifest "$manifest" --genesis "$genesis"
else
  cargo run -q -p chain-forge-launch --bin qcb-launch -- verify --manifest "$manifest" --genesis "$genesis"
fi

build=(cargo build --release -p chain-forge-node --features public-alpha)
if [ "${QCB_DRY_RUN:-}" = "1" ]; then
  echo "${build[*]}"
else
  "${build[@]}"
fi
