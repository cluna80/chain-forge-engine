# Devnet files

The supported devnet is the **ML-DSA devnet**. The Ed25519 fallback devnet is retired (owner, 2026-10-30). Ed25519 files stay only as classical-compatibility test fixtures.

| File | Status | Used by |
|---|---|---|
| `genesis-4node-mldsa.json`, `keys/mldsa/*.key.json` | **Supported devnet.** ML-DSA-65 consensus keys; ML-DSA-only user accounts (`signature_scheme = "pqc-native"`). | `run_4node_devnet.sh`, `run_machine1.sh`, `run_machine2.sh`, `devnet_4node` (`*_mldsa_*`), `mldsa_only_accounts_live`; template for the upgraded devnet (`docs/devnet-upgrade-phase-0-5.md`) |
| `genesis-4node.json`, `keys/{alice,bob,carol,dave}.key.json` | Classical-compatibility fixture: Ed25519 consensus keys. Not a supported devnet. | `devnet_4node` (non-`mldsa` tests) |
| `genesis-mldsa.json`, `genesis-val002.json`, `genesis-3node.json` | Test fixtures for specific suites (Ed25519 or `pqc-native` validator keys, hybrid accounts) | the live tests that name them; `scripts/start-devnet-local.sh` and `scripts/start-testnet.ps1` (local, `genesis-3node.json`) |
| repo root `genesis-4node.json` (`qcb-testnet-4node`) | **Legacy pilot devnet.** Preserved as is; runs from branch `devnet-legacy-2026-10` with the backed-up data. | `scripts/start-carol.sh` (legacy only) |

All keys in this folder are **public test keys**. Never use them on a network anyone relies on.

Ports used by the supported devnet scripts: API 19080–19083, P2P 28000–28003. They stay clear of the legacy devnet's 18080–18083 / 27000–27003.
