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
Short answer: devnet validators stay Ed25519, full ML-DSA is mainnet/Phase 1.
