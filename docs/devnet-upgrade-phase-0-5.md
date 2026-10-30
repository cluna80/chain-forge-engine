# Devnet upgrade: Phase 0.5 security stack

Status: **procedure for review.** Nothing in it has been run against the live devnet.
Applies to: merging the Phase 0.5 stack (#14 → #30, #32 → #34, plus #16 and #19) into `main`.
Principle (owner, 2026-10-29): **preserve the existing devnet.** The upgraded network runs as a separate, new chain next to it. Nothing is deleted, and pilot identities are re-enrolled only with each owner's explicit confirmation.

---

## 1. Why this is a new chain, not an in-place upgrade

The stack changes consensus and block formats. Old and new binaries cannot run on one network, and a new binary must not be pointed at an old node's data directory.

| Area | Change | Effect |
|---|---|---|
| Block payload | v1 envelope: `txs`, `last_commit`, `prev_state_root`, optional `evidence` (#17, #26) | New nodes refuse proposals without a valid v1 payload |
| Block hash | Bound to the block contents and checked on receipt (#18) | Old blocks don't satisfy the new hash check when re-proposed |
| Consensus | Tendermint engine-driven voting with locks, persisted in `persist/consensus_signing.json` (#18) | Mixed old and new voters break the lock rules |
| Proposal signatures | `CFP2` tag, covering `pol_round`; unsigned proposals refused when the proposer has a key (#21) | Old nodes' proposals are rejected |
| Quorum | Every commit quorum ≥ ⌊2·total/3⌋+1 (#22) | n/a on devnet (VCA off), safety fix |
| Engine selection | HotStuff/FBA devnet-only; an unknown `bft_variant` is refused (#23) | Genesis files with a typo now fail at startup |
| Consensus keys | Ed25519 or ML-DSA-65 by key length; ML-DSA-only genesis supported (#24) | Genesis keys must be exactly 32 or 1952 bytes |
| Slashing | Equivocation slashed only from committed evidence (#26) | Changes state roots when evidence is included |
| Rewards | Epoch rewards from committed evidence; one minimum bond (#20) | Different state roots from the old chain |
| Block size | Proposals limited to `max_block_bytes`; larger ones are rejected (#34) | A new validity rule |
| Execution | H0-5 atomicity and fee conservation (#15); DIS-003 recovery security (#13 via #28) | Different transaction outcomes and state roots |
| Keys | Wallet and `qcb-keygen` keys come from the OS RNG (#27) | See §5: some existing keys must be replaced |

## 2. Before anything: freeze and back up every machine

Do this on each devnet machine (BossKing, Laptop, Phone, King-OptiPlex-990, …) **before** building the new code. In Git Bash (MINGW64):

```bash
# 1. Record where the chain is (height, state root) while it still runs.
NODE_API=18080            # this machine's API port
curl -s localhost:$NODE_API/api/status > ~/devnet-legacy-status-$(hostname).json

# 2. Stop the node (Ctrl+C in its terminal), then copy everything it uses.
BACKUP=~/devnet-legacy-backup-$(date +%Y%m%d)-$(hostname)
mkdir -p "$BACKUP"
cp -a <data-dir>        "$BACKUP/data"        # the --data-dir the node runs with
cp -a <genesis.json>    "$BACKUP/"            # the --genesis it runs with
cp -a <key files>       "$BACKUP/keys/"       # --key-file, wallet *.wallet.json, any *.key.json
cp ~/devnet-legacy-status-$(hostname).json "$BACKUP/"

# 3. Checksums, so the backup can be verified later.
(cd "$BACKUP" && find . -type f -exec sha256sum {} \; > SHA256SUMS)
```

- Keep the backups **outside the repository folder**. Never `git add` them: they contain private keys.
- The backup includes identity records, recovery policies and the pilot accounts as they exist on the legacy chain. They are evidence and stay untouched.

## 3. Keep the legacy devnet runnable

1. Tag the code the legacy devnet runs, before anything is merged:
   ```bash
   git tag devnet-legacy-2026-10 c9f924c   # current main; confirm the SHA your machines actually run
   git push origin devnet-legacy-2026-10
   ```
2. Keep a build of that tag next to the new one, for example:
   ```bash
   git worktree add ../chain-forge-legacy devnet-legacy-2026-10
   (cd ../chain-forge-legacy && cargo build --release -p chain-forge-node)
   ```
3. To run the legacy devnet later, use that build with the **backed-up** data directory copies, the original genesis and the original ports. It stays a reproducible historical test environment.

## 4. Start the upgraded devnet next to it

Use a **new chain id, new data directories and new ports**, so the two networks can never connect to each other and can run at the same time.

| | Legacy devnet | Upgraded devnet |
|---|---|---|
| Code | tag `devnet-legacy-2026-10` | `main` after the merge |
| `chain_id` / `network.network_id` | unchanged | new, e.g. `qcb-devnet-0-5` |
| Data dir | existing | new empty folder, e.g. `~/qcb-devnet-0-5/data` |
| API ports | 18080–18083 | e.g. 19080–19083 |
| P2P ports | 27000–27003 | e.g. 28000–28003 |
| Validator keys | existing | **newly generated** (§5) |
| Consensus keys | Ed25519 | ML-DSA-65 (recommended, #24) or Ed25519 |

Steps:
1. Generate fresh validator keys on each machine with the fixed keygen:
   ```bash
   cargo build --release -p chain-forge-node
   ./target/release/chain-forge-keygen --address qcb1<name> --scheme ml-dsa-65 --out ~/qcb-devnet-0-5/keys/<name>.key.json
   ```
2. Build the new genesis from `tests/devnet/genesis-4node-mldsa.json`:
   - set the new `chain_id`, `network_id` and ports;
   - put each machine's new public key in its validator account;
   - keep `validator_scheme: "ml-dsa-65"`.
   - keep `signature_scheme: "pqc-native"` (ML-DSA-only user accounts): Ed25519-signed and unsigned user txs are refused, even with `require_signatures: false`. Re-enrolled pilot identities must sign with their ML-DSA-65 keys.
   - keep `limits.max_tx_bytes: 262144` (owner decision 2026-10-30, #33): ML-DSA guardian recovery needs it. It is not the mainnet value.
3. Start each node with `--genesis`, `--key-file`, `--data-dir`, `--api-port`, `--p2p-port` and `--bootstrap` pointing at the **new** values.
4. Acceptance on the upgraded devnet:
   - all nodes reach the same height with the same block hash and state root (`/api/status`, `/api/blocks/<height>`);
   - a node restarted from its data directory rejoins;
   - an ML-DSA user transaction is accepted on all nodes;
   - the live suite on the merged code passes on Windows (§7).

## 5. Keys that must be replaced (#27)

- **Ed25519 keys made with `qcb-keygen ed25519 <label>`.** The private key was SHA-256 of `"<label>-ed25519"`, so anyone who knows the label can recompute it. Treat every such key as compromised: generate a new one and never use the old one on the upgraded devnet.
- **Wallets generated by a program that created several wallets in one process.** They may share one private key. Wallets made with the wallet CLI (one wallet per run) are distinct. If you're unsure where a wallet came from, regenerate it.
- **Devnet test keys committed in the repository** (`tests/devnet/keys/**`) are public by design. Use them only for tests, never for a network anyone relies on.

## 6. Pilot identities

The legacy chain's pilot identities (BossKing, Laptop, Phone, King-OptiPlex-990) remain on the legacy chain and in the backups. On the upgraded devnet:
- re-enroll a pilot identity **only after its owner confirms**;
- record the mapping legacy address → new address for each re-enrolled identity;
- if one is not re-enrolled, the legacy chain remains its record.

## 7. Validation gate before any merge to `main`

All on the **integration candidate branch** `integration/phase-0-5-candidate`, which is exactly the tree `main` will contain:
1. The sandbox full suite (results recorded on the integration PR).
2. Windows (MINGW64): the command list on the integration PR, including the live tests run twice.
3. The owner reviews the results, then merges in the documented order with **merge commits** (not squash/rebase), marking each draft PR ready for review first.

## 8. Rollback

The upgraded devnet is separate. Stopping it leaves the legacy devnet, its data and its keys exactly as backed up. If a merge to `main` must be undone, `devnet-legacy-2026-10` marks the pre-merge code.
