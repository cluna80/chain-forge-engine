# Targeted Windows validation of the signing-v2 integration (`main` @ e8326ea)

Status: **record of a targeted test matrix. It is not a production-readiness assessment.**
Date: 2026-11-06. Run by the owner on the Windows development machine (BossKing, MINGW64 / Git Bash); output pasted into the session and compared by Claude to the expected counts below.

## What was validated

| | |
|---|---|
| Commit | `e8326ea40289900fa42aeb209c6e65e3d131362c` (merge of #96, last step of the 13-step integration) |
| Tree | `f8aa66c615e40432b9e89f6880ce78e6eb68c741` (the approved step-6b tree) |
| Checkout | detached worktree; `git rev-parse HEAD` and `HEAD^{tree}` were printed and matched before testing |
| Flags | `--locked -j 2` |

The integration merged #115, #114, #116, #112, #110, #103, #105, #106, #102, #108, #104, #111 and #96 in the approved order with regular merge commits, each step's tree matching the approved hash. #109 is **not** included (blocked pending independent cryptographic review).

Roadmap merges #121 and #122 landed afterwards. They change `ROADMAP.md` only, so the validated code is identical to current `main`; only the documentation tree differs.

## Results

| Suite | Command (abbreviated) | Result | Expected |
|---|---|---|---|
| Node unit tests | `-p chain-forge-node --bin chain-forge-node` | 417 passed, 0 failed, 6 ignored (131 s) | 417-442 |
| Adversarial gossip | `-p chain-forge-node --features signing-v2 --test adversarial_gossip` | 4 passed (44.9 s and 44.4 s on two runs) | 3 attacks + port guard |
| Bootstrap order (live) | `--test bootstrap_order_live` | 1 test, 3 trials, peers `[3,1,1,1]`, state roots agree each trial (about 32 s) | 3/3 |
| P2P unit | `-p chain-forge-p2p` | 20 passed | 20 |
| P2P bootstrap retry (real libp2p) | `-p chain-forge-p2p --features real-network --test bootstrap_retry` | 2 passed (about 10 s) | 2 |
| Scheduler, signing-v2 | `-p chain-forge-scheduler --features signing-v2` | lib 66, `claim_flow_e2e` 1, `claim_signer` 6, `migration_doc` 5, all passed | same |
| Scheduler, default | `-p chain-forge-scheduler` | lib 53, `default_build` 2, `migration_doc` 5, all passed | same |

`0 passed` lines for doc-tests, binaries, and feature-gated targets are expected.

## Invalid first attempt (excluded)

The first run was made in a worktree that was still on an older `main` (`3fa3754`, merge of #101), 53 commits behind. It failed to compile `adversarial_gossip`, lacked `bootstrap_order_live`, and had no scheduler `signing-v2` feature, exactly what that older tree should show. Every result from it was discarded. All results above are from the verified `e8326ea` checkout.

## Known coverage limitations

Not run on this commit:

- core, wallet, keygen and launch crates (they passed in the earlier combined-tree matrix at `68b4807`, which has the same content apart from merge commits, but were not re-run here);
- the roughly 30 other node live suites, including the 22 that still use the racy port helper (scope A, proposed, not done);
- `four_node_signing_v2_live` (lives in #113, deliberately not merged);
- Linux runs of this exact commit (the Linux matrix was run on the equivalent combined tree before merging).

Evidence strength:

- `adversarial_gossip` passed twice on this commit and 6/6 earlier at `a42dbe4`. This is good evidence that the Windows ephemeral-port race is fixed, not proof.
- The warnings in the build output (unused imports, dead code) are pre-existing and are not failures.

## What this does not establish

This is **not** production or mainnet readiness. Still open:

- #109 (key-storage hardening) is blocked pending independent cryptographic review;
- validators, DIS and legacy transactions still use pre-standard Dilithium code (migration plan in #119, six decisions pending);
- no independent security review of the signing-v2 stack;
- API-bind failure handling (scope B) and per-transaction verification cost with no rate limiting;
- the scheduler API has no TLS or authentication, and legacy chains have no scheduler settlement path (by design);
- PQ-HotStuff-2, a real genesis and classical transport security are prerequisites for any public alpha.

## Reproduce

```bash
git worktree add ../qattice-main-wt e8326ea40289900fa42aeb209c6e65e3d131362c
cd ../qattice-main-wt
git rev-parse HEAD^{tree}   # f8aa66c615e40432b9e89f6880ce78e6eb68c741
cargo build --locked -j 2 -p chain-forge-node --features signing-v2
cargo test --locked -j 2 -p chain-forge-node --bin chain-forge-node
cargo test --locked -j 2 -p chain-forge-node --features signing-v2 --test adversarial_gossip -- --nocapture
cargo test --locked -j 2 -p chain-forge-node --test bootstrap_order_live -- --nocapture
cargo test --locked -j 2 -p chain-forge-p2p
cargo test --locked -j 2 -p chain-forge-p2p --features real-network --test bootstrap_retry -- --nocapture
cargo test --locked -j 2 -p chain-forge-scheduler --features signing-v2
cargo test --locked -j 2 -p chain-forge-scheduler
```

Build the node first: the scheduler suite needs `chain-forge-node.exe`.
