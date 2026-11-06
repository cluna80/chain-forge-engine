# Qattice — 

**Qattice** is a sovereign Layer-1 blockchain built from the Chain Forge Engine in Rust. Its distinguishing
feature is personhood-weighted Byzantine Fault Tolerant consensus: voting power derives from
verified human identity rather than capital or computation. The native token is **QCB**
(QuarkCharmBit), fixed at 210,000,000 at genesis with no inflation. A Grand Challenge system
coordinates verifiable distributed scientific computation, rewarding contributors from a
pre-funded research treasury. The Digital Identity Stone (DIS) protocol provides
holder-controlled, post-quantum cryptographic identity that works across independent vendors
without a central authority. Chain Forge is the engine that creates it all — a ~50-crate Rust
workspace with no borrowed consensus or state-machine code from any other chain.

---

## Current status — Devnet (November 2026)

**Supported four-node devnet and separately tested integration configurations:**

| Area | Status |
|---|---|
| BFT consensus (Tendermint-style, pluggable) | ✅ Running — 4-node, block-producing; supported devnet validators use ML-DSA-65-format keys on the legacy consensus cryptography backend |
| ML-DSA-65 user transactions | ✅ Legacy devnet transactions tested; separate FIPS 204-based signing-v2 implementation tested on a fresh private integration fixture, not enabled on the supported devnet |
| Replay / nonce protection | ✅ All rejection cases pass |
| Timestamp monotonicity | ✅ Enforced and regression-tested |
| Post-quantum identity (DIS protocol) | ✅ 4 pilot devices at Verified tier |
| Fee accounting (70/20/10 bps split) | ✅ 5-node multi-machine devnet |
| Epoch-close validator reward distribution | ✅ Per-human dedup, participation gate |
| PoCD reward settlement (`ClaimResearchReward`) | ✅ Happy path + 3 rejection cases pass |
| FeeSponsor live authorization | 🔲 Crypto + store done; execution wiring pending |

**Not yet working / out of scope for Phase 0:**

- **Validator keys versus cryptographic backend:** The supported four-node devnet (`tests/devnet/genesis-4node-mldsa.json`) declares `validator_scheme: ml-dsa-65` and `signature_scheme: pqc-native`; its validator public keys use the ML-DSA-65 format (1,952 bytes). **Consensus votes and block signatures still use the legacy ML-DSA backend, not the FIPS 204-based signing-v2 transaction backend.** Migration and verification of validator/consensus signing remain open (QAT-01/02 / legacy ML-DSA roadmap work). Ed25519 validator keys remain in classical-compatibility test fixtures, not the supported ML-DSA devnet.
- **FIPS 204 scope:** `chain-forge-execution/src/signing_v2.rs` uses the `fips204_backend` for **user transaction** authorization only, under the `signing-v2` feature and an explicit chain commitment profile. It does not upgrade validator votes or block signatures. Four-node signing-v2 integration tests do not establish FIPS 204 conformity of consensus signing.
- PQ-HotStuff consensus is not implemented or deployed; the supported devnet uses the Tendermint-style engine.
- No public testnet — devnet is single-operator
- No resource marketplace (removed; may return as an optional module post-Phase 0)
- No independent cryptographic audit of DIS transcript format (return gate documented)
- Android wallet builds but is a reference implementation, not production-ready

Full engineering detail and test results: [`ROADMAP.md`](ROADMAP.md)  
Economic design: [`QCB-Chain-Whitepaper-v2.md`](QCB-Chain-Whitepaper-v2.md)

---

## Quick start — run a devnet node

**Prerequisites:** Rust stable toolchain (`rustup`), a Unix-like shell (Linux or macOS;
Windows via MINGW64/Git Bash works).

```sh
# Build the node binary
cargo build -p chain-forge-node

# Launch the 4-node ML-DSA devnet (ML-DSA-65 consensus keys, ML-DSA-only
# user accounts) on ports 19080-19083 / 28000-28003; it stops once all four
# nodes reach height 3. One node alone cannot reach quorum.
./tests/devnet/run_4node_devnet.sh

# While it runs (raise --target-height to keep it up longer), query a node:
curl http://127.0.0.1:19080/api/status
curl http://127.0.0.1:19080/api/blocks
```

**Run the 4-node devnet acceptance suite** (all nodes in-process, no manual port wiring):

```sh
cargo build -p chain-forge-node

# Core consensus + ML-DSA transactions
cargo test -p chain-forge-node --test mldsa_tx_live -- --nocapture

# Timestamp monotonicity (P0-7)
cargo test -p chain-forge-node --test timestamp_monotonic_live -- --nocapture

# Fee settlement across 5 nodes
cargo test -p chain-forge-node --test fee_settle_live -- --nocapture
```

Tests spawn real node processes, use dynamic ports, and clean up after themselves.
Expected runtime: 60–120 s per test.

---

## Quick start — Qattice wallet

```sh
# Build the wallet CLI
cargo build -p chain-forge-wallet

# Generate a new ML-DSA-65 keypair
./target/debug/chain-forge-wallet keygen --output my-wallet.key.json

# Check balance (node must be running)
./target/debug/chain-forge-wallet balance \
  --node http://127.0.0.1:8080 \
  --key my-wallet.key.json

# Send a transfer
./target/debug/chain-forge-wallet transfer \
  --node http://127.0.0.1:8080 \
  --key my-wallet.key.json \
  --to qcb1recipient \
  --amount 1000000
```

The Android reference wallet lives in `dis-wallet-android/`. It requires the Android SDK
and targets the same devnet API.

---

## Repository layout

```
chain-forge-node/       Node binary — wires everything together
chain-forge-consensus/  BFT engine (Tendermint-style, HotStuff, FBA variants)
chain-forge-execution/  Transaction executor and state machine
chain-forge-state/      Merkle state store
chain-forge-crypto/     ML-DSA-65, Ed25519, hybrid scheme
chain-forge-identity/   On-chain identity and attestation
chain-forge-pocd/       Proof of Useful Discovery module
chain-forge-wallet/     CLI wallet (ML-DSA-65 keys, sign, submit)
dis-core/               Digital Identity Stone protocol (MIT)
dis-vendor-server/      DIS vendor server (BUSL-1.1 → Apache-2.0 2030)
dis-wallet-android/     Android reference wallet
tests/devnet/           Genesis files and key fixtures for integration tests
ROADMAP.md              Engineering roadmap with milestone status
QCB-Chain-Whitepaper-v2.md  Full protocol and economic design
```

---

## Looking for cofounders and core contributors

Qattice is founder-led and early. The protocol and engine are functional; what's missing
is the team to take it to a public testnet, an audit, and eventually mainnet.

**Skill gaps — actively looking:**

| Role | What's needed |
|---|---|
| **Cryptographer / protocol security** | Independent review of the DIS transcript format and ML-DSA integration; formal security model for the personhood-weighted consensus design; help specifying the ZK-VRC proof system for humanity verification |
| **Distributed systems / consensus** | Migrate the existing ML-DSA-65 validator consensus signing path from the legacy backend to a reviewed FIPS 204-conformant backend; implement and validate PQ-HotStuff, formal liveness/safety analysis and personhood-weighted threshold proofs |
| **Mobile / Android** | Take `dis-wallet-android` from reference implementation to production: HSM key storage, secure enclave integration, UX for the DIS identity flow |
| **Rust / blockchain infra** | Network hardening, persistent storage (current devnet is in-memory after restart), peering and discovery for a public testnet, the FeeSponsor execution wiring |
| **Scientific computing / Grand Challenge** | Domain expertise to evaluate and design Grand Challenge tasks; verifier independence and quorum design; integration with real computational workloads |
| **DevRel / technical writing** | Developer docs, SDK examples, explainers for the DIS protocol and the Grand Challenge system aimed at potential operator partners |

If you're interested in any of these, open an issue or reach out directly. The codebase is
public and the best introduction is reading `ROADMAP.md` and running the devnet tests.

---

## Licensing

- `dis-core`, `dis-sdk`, most Chain Forge crates: **MIT**
- `dis-vendor-server`: **BUSL-1.1** (converts to Apache-2.0 on 2030-01-01)

See [`LICENSE.md`](LICENSE.md) for the full split.
