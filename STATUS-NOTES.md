# Qattice / Chain Forge — Status Notes

_As of 2026-10-28. Working notes, not committed._

## Pull requests and branches

| PR / branch | What | Status |
|---|---|---|
| #14 `security/h0-attestation-quorum-hardening` | Genesis-configurable attestation quorum | Open |
| #15 `security/h0-5-7-atomicity-fee-conservation` | H0-5/H0-7 atomicity and fee conservation | Open |
| #16 `test/fs03-mn7-mn8-hardening` | MN-7 rewrite (MN-8 removed) | Open; still needs a real second Windows `fee_settle_live` run |
| #17 `security/h0-1-2-deterministic-participation` | Deterministic participation, state-root binding, liveness hardening | Windows-confirmed; awaiting merge decision |
| **#18** `security/h0-tendermint-polka-lock` | **Consensus safety fix**: full Tendermint prevote/precommit/lock/unlock | **All acceptance tests confirmed on Windows**; draft, unmerged |
| `security/h0-epoch-rewards` (no PR yet) | Epoch rewards plus MN-8 | In progress; see below |

Merge order: #16 into #14's branch, then #14 into main, then #13, then #15 (rebased), then #17, then #18. Nothing is merged to `main`.

## #18 consensus safety fix (done; acceptance confirmed)

Windows (MINGW64) results at commit 0092ba4:

- consensus: 91/91
- node: 231/231
- `devnet_4node`: pass, with block-hash agreement
- `h0_5_atomicity_live`: pass; block hashes unchanged across restart
- `consensus_safety_live`: 3/3 runs

Gap: `devnet_4node_partition_recovery` is skipped on Windows (no iptables). It passed in the Linux sandbox.

### Release gates (open, recorded on #18)

1. **Proposal authentication.** Proposals aren't signed in practice; receivers must fail closed when the proposer has a registered key.
2. **HotStuff / FBA.** Both still use the legacy unsafe voting path. They need a safety review, or must refuse to run off devnet.
3. **VCA quorum floor.** `verify_commit` can use `vca_quorum` with no lower bound. It must never go below ⌊2·total/3⌋+1.

## Epoch rewards branch (`security/h0-epoch-rewards`)

### Done

- Rewards pay the **closed** epoch, from committed `last_commit` evidence only.
- Participation is Byzantine-robust (the f worst-omitting proposers are discounted).
- `consensus.rewards.min_participation_pct` is set in genesis: default 67, range 50–90.
- Per-human tie-break is deterministic; the jail units bug is fixed; shares are u128.
- Unit tests, determinism tests, restart tests and mutation checks all pass. Node 237/237 after rebasing onto #18.
- The branch is **rebased locally onto #18 (clean, all tests pass), but not pushed**: the force-push was blocked by the permission check. The remote still has the pre-rebase branch. Pushing needs your OK for `git push --force-with-lease`, or a new branch name.

### MN-8 investigation

- The live MN-8 test still fails at MN8-4 on the new engine: Eve earns 0, the others get pool/4.
- **Eve's votes ARE in the committed evidence.** She is in every `last_commit` from height 28 to 41 (5/5). Participation is fine.
- **Root cause:** Eve's `ValidatorRegistry` record stays `Candidate` / `pop_verified=false` / `owner_identity_id=None`, while the live `ValidatorSet` seats her with full power. Reward eligibility reads the registry.
  - The registry PoP sync for bond-admitted validators existed only in the solo `propose_block` path. The multi-node `commit_block` (every real network) never ran it.
  - Separately, `register_bonded_validator` returns early when a record already exists. It was created earlier, by key registration, so the authenticated owner binding never reaches the registry.

### In progress (uncommitted in the working tree)

- Committed: failing test `multi_node_commit_keeps_bonded_validator_registry_in_sync` (c83a6c2).
- Uncommitted fix: new `sync_registry_pop_from_validator_set()`, called from both `commit_block` and `propose_block`. Personhood resolves the same way as the set's PoP refresh (genesis: own identity; bonded: owner binding).
- **The test still fails, and the probe shows why: the test fixture is wrong, not (only) the code.** `fund_bond_and_verify_personhood` bonds *without* an owner binding. On the multi-node commit, the PoP refresh correctly fails closed: the seat drops to `pop_verified=false` and power 0. So there's nothing to sync.
  - The fix to make: bond with an authenticated `owner_identity_id` (as Eve does) in that test.
  - (The temporary probe lines have been removed.)

## Next steps (in order)

1. Fix the registry-sync test fixture (bond with an owner binding). Confirm the test fails without the fix and passes with it.
2. Fix `register_bonded_validator` (or the sync) so an existing record receives the authenticated owner binding, and add a test.
3. Run the full node suite, rerun MN-8 live in the sandbox, and expect MN8-4/MN8-5 to pass. Diagnose further if they don't.
4. Commit, then push the rebased rewards branch (needs your permission for the force-push). Open a draft PR stacked on #18.
5. Windows: node unit tests, `mn8_reward_exclusion_live`, plus the reward unit tests.
6. Later: the release gates above; `attestation_guard_live` registers an unfunded account that ingress now rejects (test fix); per-tx identity/agent clone performance; genesis-hash peer agreement (H0-8).

## Policies in force

- No milestone is ✅ until it passes on Windows (CLAUDE.md).
- Crypto architecture is locked: devnet stays Ed25519; ML-DSA is mainnet/Phase 1.
- Liveness only jails, never burns stake. Only objective faults (double-signing) burn stake.
- Draft PRs only; no merges to `main` without your decision.

## Decisions (2026-10-28, owner)

- **Rewards: fixed pool.** Each epoch's validator pool is split among eligible validators. The capital premium (`k`, `premium_cap`; Model C in `docs/validator-economics-spec.md`) reweights shares within the pool and never adds to it. Both default to 0 (off) until values are chosen.
- **One minimum bond** (`bond_min`, genesis `validator_bonding.min_bond_amount`) decides both seating and reward eligibility. Fixes MN-8: Eve was seated at 1 QCB but needed 1,000 QCB for registry Active.
- **M0 approved** with the scope doc's goals (100 KiB at C = 512, verify ≤ 50 ms, hash-based only, 4–7 weeks gated at M2, zkVM first). The **other session** runs M0; this session finishes rewards and MN-8.
- Local Windows repo: use `/c/Dev/chain-forge-engine`, not the nested `/c/Dev/chain-forge-engine/chain-forge-engine` clone.
