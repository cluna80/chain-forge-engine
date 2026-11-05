# STATE-COMMIT-2 scratch evidence

Scratch-only. The `.rs.txt` files are test source that was inserted into a **throwaway git worktree** of `origin/main@baf7345`
(never into this tree) and run there. They are stored as `.txt` so they cannot be compiled by accident. Nothing here is a
golden baseline and no production file was edited.

| File | Inserted into | Test |
|---|---|---|
| `scratch-tests/node_tests_a.rs.txt` | `chain-forge-node/src/node.rs`, `mod tests` | `sc2_scratch_stale_account_tier_after_epoch_lapse` |
| `scratch-tests/node_tests_b.rs.txt` | `node.rs`, end of `mod p02a_gaps` | validator tamper, identity tamper, agent index |
| `scratch-tests/exec_tests.rs.txt` | `chain-forge-execution/src/lib.rs`, `mod tests` | overlength address and denom |

Reproduce (sandbox; **Windows confirmation still required** before any ✅):
`cargo test -j 2 -p chain-forge-node --bin chain-forge-node sc2_scratch -- --nocapture --test-threads=1`
and `cargo test -j 2 -p chain-forge-execution --lib sc2_scratch -- --nocapture`.
`results/` holds the captured `SC2-RESULT` lines (node: 3 runs, identical; executor: 1 run).
