# Claude Code — Project Notes

## Test validation policy

**Never mark a test or milestone ✅ based only on a sandbox/CI compile or run.**

All acceptance tests (`*_live` integration tests) must be confirmed passing on the
developer's local machine (Windows, MINGW64) before a milestone is closed.

Workflow:
1. Write the test, compile-check in sandbox (`cargo test --no-run`).
2. Commit and push.
3. Developer runs on their machine: `git pull origin main && cargo build -p chain-forge-node && cargo test -p chain-forge-node --test <name> -- --nocapture`
4. Only after the developer confirms it passes locally does the ROADMAP entry get ✅.

If a test passes in sandbox but fails locally, treat it as **not done** and investigate
the discrepancy before closing the milestone.

## Cryptographic architecture (locked)

See ROADMAP.md § "Cryptographic Architecture Decision". Do not re-litigate during Phase 0/1.

Owner decision 2026-10-28 (supersedes the earlier "devnet validators stay Ed25519"):
the devnet moves to **ML-DSA-65 consensus keys on the Tendermint engine**. The
Ed25519 devnet genesis stays runnable as a fallback until the ML-DSA devnet passes
on Windows. HotStuff/FBA stay devnet-only (release gate 2); the consensus engine is
not changing on devnet. Mainnet is still a fresh all-ML-DSA genesis.

Consensus direction (owner, locked 2026-10-28): **PQ-HotStuff** is the target
consensus for Qattice mainnet and a selectable Chain Forge engine. Spec:
`docs/pq-hotstuff-001-spec.md`. It is a new engine module, not the legacy
`HotStuffEngine`. Tendermint stays the devnet baseline until PQ-HotStuff passes
its Phase 2 gate on Windows.
