# Qattice launch manifests

Public Alpha is identified by an explicit, version-controlled **launch manifest**, not by a new `environment.mode`
(`devnet`, `testnet`, `mainnet` are unchanged). The manifest pins one genesis; `qcb-launch verify` is the deployment gate and
`scripts/build-public-alpha.sh` runs it before building the release binary.

## Manifest (schema v1, unknown fields are rejected)
```json
{
  "schema_version": 1,
  "network": "qattice-public-alpha",
  "chain_id": "<the alpha chain id>",
  "environment_mode": "<the genesis environment.mode>",
  "genesis_hash": "<64 lowercase hex: chain_forge_core::compute_genesis_hash of the genesis>",
  "required_commitment_profile": "qattice-v2",
  "required_signature_scheme": "pqc-native",
  "required_pqc_algorithm": "ml-dsa",
  "required_validator_scheme": "ml-dsa-65",
  "release_build_features": ["signing-v2"]
}
```
The `required_*` fields are constants: a manifest that lists anything else is refused (`PA_MANIFEST_WEAKENED`).

## Gate codes (`qcb-launch verify --manifest M --genesis G`; exit 0 ok, 1 violations as JSON, 2 usage/I-O)
`PA_PROFILE_MISSING`, `PA_PROFILE_INVALID`, `PA_CRYPTO_NOT_MLDSA`, `PA_VALIDATOR_SCHEME`, `PA_CHAIN_ID_MISMATCH`,
`PA_MODE_MISMATCH`, `PA_GENESIS_HASH_MISMATCH`, `PA_GENESIS_INVALID`, `PA_MANIFEST_INVALID`, `PA_MANIFEST_SCHEMA`,
`PA_MANIFEST_NETWORK`, `PA_MANIFEST_HASH_FORMAT`, `PA_MANIFEST_WEAKENED`, `PA_MANIFEST_BUILD_FEATURES`.

## Release build
`scripts/build-public-alpha.sh <manifest> <genesis>` verifies first, then runs
`cargo build --release -p chain-forge-node --features public-alpha`. The node feature `public-alpha` implies `signing-v2` and
the conformant FIPS 204 backend. General development builds keep both feature-gated.

## Not here yet
No real alpha manifest or genesis is committed: the chain id, environment mode, validator set (ML-DSA keys) and balances are
owner inputs. Until they exist, the only manifests in the repository are test fixtures built inside `chain-forge-launch/tests`.
Historical genesis files are unchanged; `chain-forge-launch/tests/fixtures/historical_genesis_hashes.tsv` pins their hashes
(computed on unmodified `main`).
