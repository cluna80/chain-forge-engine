# CF-QAT-REPO-001 — Chain Forge / Qattice Repository Separation Plan

**Status:** PLANNED — documentation only; no migration authorized.
**Target:** Two independently versioned repositories. Chain Forge's existing frontend repository becomes the home of its reusable Rust backend; Qattice becomes a separate chain-specific repository.
**Owner approval required:** Explicit go/no-go after all prerequisites are met.

## 1. Architectural contract

- **Chain Forge** is a general-purpose blockchain creation platform. Its existing GitHub frontend repository will also contain its backend: reusable Rust engine crates, generic consensus/execution/storage/network interfaces and implementations, chain-building APIs, frontend, SDK/CLI, generic test harnesses, and templates.
- **Qattice** is the first independent sovereign L1 built with Chain Forge. Its own repository contains Qattice-specific genesis/configuration, personhood-weighted policies, QPC/DIS integrations, QCB/QRC monetary rules, governance, network launch/operations, validators, and chain-specific acceptance tests.
- Qattice consumes **versioned, pinned Chain Forge dependencies**, not a copied fork of engine code. Keep engine APIs generic; isolate chain-specific policy behind versioned interfaces. Avoid cyclic dependencies.
- PoCD **application-layer** work is deferred. Preserve any existing PoCD source/history without expanding its scope during the split; decide module ownership in the inventory before moving it.
- Do not change consensus rules, cryptographic signing domains, chain IDs, state serialization, genesis data, addresses, supply accounting, or protocol behavior as part of a structural migration.

## 2. Preconditions — NO-GO until all are satisfied

- [ ] The current 24-suite live-test sweep finishes; all results, known failures and environment details are recorded.
- [ ] The ML-DSA unbound-account ownership vulnerability is fixed and regression-tested, including genesis-funded accounts and restart persistence.
- [ ] Phase 0 current-code acceptance baseline is recorded in `docs/PHASE-0-CLOSEOUT.md` with implementation, verification and evidence for P0-1..P0-9. Outstanding failures must be triaged and explicitly accepted or resolved before cutover.
- [ ] Identify all in-flight PRs, stashes, worktrees, deployment scripts and local uncommitted changes. Do not silently discard or relocate them.
- [ ] Record the exact source `main` commit, existing Chain Forge frontend repo and branch, proposed Qattice repo, Cargo workspace graph, test commands, devnet state roots, genesis checksums, tags, and known failures.
- [ ] Produce a crate/file ownership inventory and an explicit move map; review shared interfaces and the dependency direction.
- [ ] Back up existing repositories and devnet data; verify restoration. Preserve `v0.1.0-phase0` and `devnet-legacy-2026-10` without moving or rewriting them.
- [ ] Approve a maintenance/cutover window and rollback owner. Do not start migration while the security PR or acceptance sweep is changing the baseline.

## 3. Repository ownership inventory (fill before execution)

| Component | Current path / repository | Future owner | Dependency / rationale | Test owner |
|---|---|---|---|---|
| Chain Forge frontend | TBD — existing frontend GitHub repository | Chain Forge | Preserve frontend history | Chain Forge |
| Generic Rust consensus, networking, storage, execution | TBD — audit each crate | Chain Forge | No Qattice-specific assumptions | Chain Forge |
| Engine API, CLI, SDK, generic test harness | TBD | Chain Forge | Stable, versioned interface | Chain Forge |
| Qattice genesis and node/network configuration | TBD | Qattice | Chain-specific protocol configuration | Qattice |
| QPC/DIS and personhood policy | TBD | TBD by reusable core vs chain policy | Avoid embedding Qattice policy in engine | Both as applicable |
| QCB/QRC economics, governance, validator policy | TBD | Qattice | Qattice-specific rules | Qattice |
| PoCD source, research scheduler and miner/verifier | TBD | TBD; frozen during migration | Application-layer development deferred | TBD |
| Devnet scripts, fixtures, CI and release tooling | TBD | Split by generic vs Qattice-specific use | Keep end-to-end tests runnable | Both |

**No move is authorized by this table.** Replace TBD only after inspecting actual code and target repositories.

## 4. Execution sequence (only after separate explicit authorization)

1. **Freeze and tag a baseline:** Record immutable commit IDs, test results, source tree and genesis/state checksums. Back up working data and ensure all open work is accounted for.
2. **Prepare target repositories:** Confirm the existing Chain Forge frontend repository, create/approve the Qattice destination, configure branch protection, access permissions, secrets and CI without changing production deployments.
3. **Extract history safely:** Use reviewed history-preserving extraction where practical (for example `git filter-repo` in disposable clones), retaining original repositories/tags as archives. Never force-push or rewrite the source `main` or historical release tags.
4. **Move reusable engine into the existing Chain Forge frontend repository:** Integrate the Rust workspace with the frontend and its CI. Resolve crate boundaries and generic APIs without protocol refactors.
5. **Move chain-specific implementation into Qattice:** Add pinned Git revision or released crate dependencies on Chain Forge. Keep the Qattice genesis, chain ID, serialization and consensus behavior byte-for-byte compatible where required.
6. **Build and test independently:** Chain Forge must build/test without Qattice. Qattice must build/test against the pinned engine revision. Run the Phase 0 baseline, H0 protocol regressions and relevant four-node Windows/Linux acceptance tests.
7. **Compare protocol artifacts:** Verify unchanged genesis checksums, chain IDs, state roots, transaction encoding, signatures, replay protection, balances, finality and persistence against the approved baseline. Any intentional deviation needs its own reviewed protocol PR.
8. **Cut over CI/deployment:** Update clone URLs, workflow permissions, documentation, release automation, dependency update process and deployment scripts. Test fresh clones and disaster recovery.
9. **Close out:** Publish a migration report listing both repo URLs, commit mappings, retained tags, test evidence, exceptions, rollback procedure and owner sign-off.

## 5. Acceptance criteria

- [ ] Existing Chain Forge frontend and reusable Rust backend build together in **one Chain Forge repository**.
- [ ] Qattice builds from **its own repository** against a **pinned, immutable Chain Forge version/revision**.
- [ ] Neither repository requires the other's working tree or a developer-specific absolute path.
- [ ] No duplicated engine implementation and no cyclic dependency.
- [ ] Original Phase 0 tag, legacy devnet branch, historical commits and backups remain recoverable.
- [ ] CI, tests, four-node devnet scripts and documentation work from clean checkouts.
- [ ] Baseline protocol invariants and security regressions pass; any known pre-existing failures are explicitly tracked rather than silently relabeled.
- [ ] State and genesis compatibility checks pass; no unapproved network reset, key change, token-supply change or chain fork.
- [ ] Rollback is rehearsed; migration is declared complete only with explicit approval.

## 6. Stop / rollback conditions

Stop immediately for any unaccounted-for state-root or genesis change, lost history, unreviewed cryptographic behavior change, unresolved account-ownership exploit, broken validator consensus, unrecoverable node data, or missing baseline test evidence. Revert deployment pointers to the frozen source revision; restore backed-up state; keep source repositories intact. Never attempt to repair a failed migration by silently resetting a chain.

## 7. Phase ordering and change control

**Protocol-first sequence:** Phase 0 current-code acceptance → Phase 0.5 hardening → Phase 1 protocol completion → application layer (including PoCD).

**Migration timing:** Prepare this document now. Perform the repository split after the current sweep and security fix, once Phase 0's reproducible baseline is approved, and before further major protocol expansion if practical. The split itself is a controlled infrastructure change, **not** evidence that Phase 0, Phase 0.5 or Phase 1 exit criteria passed. Maintain those independent acceptance gates.

**Approval boundary:** Documentation updates may be reviewed/merged separately. Do not create/move/delete repositories, rewrite history, change remotes, alter CI/deployments or migrate source until a subsequent explicit user authorization.
