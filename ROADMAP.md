# Chain Forge / QCB Chain — Engineering Roadmap

> **How to use this doc**: This is the running reference for what's done, what's next, and what's on the horizon. Update it when a milestone ships. Cross-reference the whitepaper (`QCB-Chain-Whitepaper-v2.md`) for economic design rationale; this doc is the engineering view.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Shipped / confirmed working |
| 🔄 | In progress |
| ⬜ | Pending — prerequisite complete |
| 🔲 | Pending — prerequisite not yet complete |
| ❓ | Open question / design decision needed |

---

## Phase 0 — Chain Forge Engine Foundation

**Goal**: A working, partition-tolerant BFT consensus engine with a real resource economy crate, hardened against known attack vectors, running on a live multi-node testnet.

### Consensus & Networking

| Item | Status | Notes |
|------|--------|-------|
| Tendermint-style BFT engine (`chain-forge-consensus`) | ✅ | Operational on 4-node devnet |
| `chain_id`-aware vote scoping | ✅ | Prevents cross-chain vote contamination |
| Real libp2p P2P (`--features real-network`) | ✅ | 4 nodes exchanging gossip; `/api/status` shows peer count |
| 4-node genesis (quorum=3, f=1 BFT) | ✅ | Alice/Bob/Dave on Machine 1; Carol on Machine 2 |
| Partition tolerance — iptables DROP test | ✅ | 5s hard TCP partition; 3-of-4 quorum continued; Alice synced in <2s on heal |
| State persistence (block-by-block to disk) | ✅ | Nodes resume from last committed height on restart |
| Proposer rate-limiting | ✅ | MAX_PROPOSALS_PER_ROUND=3; flood-stop + accepted-proposal dedup |
| Equivocation detection | ✅ | Double-vote/double-precommit at same (height, round, type) → `ConsensusError::Equivocation` |
| `verify_commit()` hardening | ✅ | Dedup stuffing blocked; mismatch checks; unknown-validator rejection |
| Validator set governance | ✅ | `ValidatorSetChange`, epoch-delayed activation, personhood cap |
| HotStuff-style BFT variant | ✅ | `HotStuffEngine` — three-phase (PREPARE/PRE-COMMIT/COMMIT), QC-locked, linear messaging; 17 dedicated tests passing; personhood cap + VCA weights applied at init; equivocation detection in PREPARE phase; safety rule (Theorem 2) enforced |
| XRPL-inspired FBA variant | ⬜ | Next consensus variant — HotStuff now proves pluggability is real |

### Slashing & Safety

| Item | Status | Notes |
|------|--------|-------|
| `chain-forge-slashing` crate | ✅ | `SlashingModule`, `EquivocationEvidence`, `ValidatorRegistry` |
| `ValidatorRegistry` — genesis validators activated at startup | ✅ | `confirm_pop()` called at block 0; registry fully populated |
| Liveness slashing — confirmed on live testnet | ✅ | >20% missed blocks in window → jail + 1,000,000 uQCB slash |
| Equivocation → `SlashingModule::slash_equivocation()` wire | ✅ | `process_equivocation_evidence()` in `node.rs` routes consensus-detected equivocation to slasher |
| Forged vote rejection (in-process test) | ✅ | Garbage-signature vote does not advance height |
| **Adversarial libp2p gossip test** | ⬜ | Forged/equivocating messages over real TCP — **next adversarial milestone** |

### Cryptography

| Item | Status | Notes |
|------|--------|-------|
| ML-DSA (Dilithium3) post-quantum signing (`chain-forge-crypto`) | ✅ | Validator signing scheme; `--features real-crypto` |
| Crypto-agility constitutional guarantee | 🔄 | Design captured in whitepaper §10 + §7.3; not yet protocol-enforced |
| Signature scheme pluggability in `chain-forge-consensus` | ⬜ | Architectural requirement for PQ migration path |

### QRC Resource Economy

| Item | Status | Notes |
|------|--------|-------|
| `chain-forge-qrc` crate | ✅ | `QrcEngine`, `ResourceKind` (7 types), `CapacityEvidence_v0` |
| Dynamic conversion rate (Control 1) | ✅ | R_t = R_0 × (U*/U_bar)^γ, clamped [R_min, R_max] |
| Epoch conversion cap (Control 2) | ✅ | Adaptive: L_e = β_cap × Capacity + λ_cap × Demand |
| On-chain capacity tracking (Control 3) | ✅ | Byzantine-resistant median across 7 resource types |
| Consumption burn (Control 4) | ✅ | p_burn = 0.25; 60% providers / 15% reserve |
| CoverageRatio circuit breaker (Control 5) | ✅ | CR_halt=0.75 / CR_resume=1.00; NORMAL / RESTRICTED / HALTED hysteresis |
| `QrcEngine` serde + persistence (`qrc.json`) | ✅ | Persists across node restarts |
| `CapacityReport` sub-protocol | ✅ | `chain-forge-qrc::capacity_report` — median aggregation |
| **`PurchaseQrc` tx type** | ✅ | Job-scoped QCB→QRC buy-in; slippage guard; blocked in RESTRICTED + HALTED |
| **`CreditProvider` tx type** | ✅ | Coordinator-issued post-job credit; Verified-tier required; auto-creates provider account; blocked in HALTED only |
| Per-resource congestion pricing | ✅ | Wired in `QrcEngine` |
| Node-layer CR exposure (block header / chain event) | ⬜ | Light clients / agents need current CR without running full node; header schema must stabilize first |

### Execution Layer

| Item | Status | Notes |
|------|--------|-------|
| `chain-forge-execution` crate | ✅ | 74 tests, 0 failures |
| All QRC tx types wired (`QrcPurchase`, `QrcContributionSettle`, `PurchaseQrc`, `CreditProvider`) | ✅ | Gas model, `variant_name`, `payload_size_bytes`, `required_module`, `execute_tx` |
| `tx_kind_label()` exhaustive match in `node.rs` | ✅ | Compiler-enforced; updated with every new variant |
| Attestation guard tx types (Phases A–D) | ✅ | `AttestEntity`, `RevokeAttestation`, `ConfirmSybil`, `ReportSuspectedSybil`, `ReverseSybil` |
| QCB native tx types (Transfer, Stake, Unstake, etc.) | ✅ | |
| Governance tx types | ✅ | `ProposeChange`, `VoteOnProposal`, `ActivateChange` |
| **EVM precompile / permissioned EVM layer** | 🔲 | Phase 5+ — identity layer must be proven at scale first |

### Identity / Personhood

| Item | Status | Notes |
|------|--------|-------|
| Attestation guard Phases A–D (`chain-forge-identity`) | ✅ | 65 tests passing; coordinator-gated |
| ZK-VRC prototype (`chain-forge-personhood`) | ✅ | Groth16 / BLS12-381; 5 binaries; integrated into workspace |
| `governance_authority.rs` — uses real `ValidatorSet` | ✅ | Quorum tied to `quorum_power()` / `revocation_quorum_power()` |
| `/api/identity/{address}` REST endpoint | ✅ | Returns verification tier + CS score |
| Personhood-weighting overlay on BFT | ⬜ | Overlay not yet built; consensus base ready |
| Identity pilot — real-world sybil test | 🔲 | Requires Phase 1 (personhood-weighted BFT) complete |
| Coordinator role decentralized | 🔲 | Currently a named temporary centralization (see `QCB-Attestation-Guard-Design.md §Coordinator`) |

### Infrastructure & Tooling

| Item | Status | Notes |
|------|--------|-------|
| Block explorer REST API (`/api/blocks`, `/api/txs`, `/api/accounts`, `/api/status`) | ✅ | Live on every block commit |
| React frontend (`chain-forge-frontend`) | ✅ | At `C:\Dev\chain-forge-frontend`; vite dev server running |
| Explorer persistence (`write_explorer_persistence.py`) | ⬜ | Packaged, not yet deployed on engine machine |
| VCA PQ (`chain-forge-vca-pq`) | ✅ | Post-quantum VCA attestation crate in workspace |
| devnet scripts (`devnet/`) | ✅ | Start/stop scripts for Machine 1 (Alice/Bob/Dave); Machine 2 (Carol) via scp |

---

## Phase 1 — Personhood-Weighted BFT on Testnet

**Goal**: Consensus power tied to verified human identity, not raw stake. Charm Confinement and Intrinsic Charm implemented.

**Prerequisite**: Phase 0 complete (Tendermint base ✅; HotStuff variant pending).

| Item | Status | Notes |
|------|--------|-------|
| Personhood-weighting overlay on TendermintEngine | ⬜ | Cap per-human validator influence regardless of stake |
| `ValidatorInfo.pop_verified` gating in consensus | ⬜ | Only PoP-confirmed validators counted for quorum |
| Charm Confinement (`chain-forge-identity` extension) | ⬜ | Identity-scoped state isolation; one claim per epoch |
| Intrinsic Charm module | ⬜ | Verification tier + decay-exemption credits intrinsic to identity |
| Stake → influence cap enforcement | ⬜ | See whitepaper §3.3 |
| Validator liveness under partial-participation (Open Q14) | ❓ | How does finality behave if large fraction of verified humans go offline? |
| Governance quorum floor enforcement | ⬜ | >3% turnout for ordinary QRC votes; >6% for constitutional (derived from §6.6) |

---

## Phase 2 — Identity Pilot + QRC Paths Open

**Goal**: Real-world sybil-resistance pilot; both $QRC minting paths live (purchase + contribution).

**Prerequisite**: Phase 1 complete.

| Item | Status | Notes |
|------|--------|-------|
| Identity pilot design — cost/sybil targets finalized | ❓ | Provisional: <3% sybil rate, <$5/verification; see Open Q1 |
| Red-team / adversarial sybil test | ⬜ | Phase A–D attacks: attestation-guard bypass attempts |
| `PurchaseQrc` path open on testnet | ⬜ | Execution tx type ✅; needs live QrcEngine + identity gate |
| `CreditProvider` path open — Verified-tier coordinators | ⬜ | Execution tx type ✅; needs VCA attestation pipeline live |
| `QrcContributionSettle` — epoch-boundary settlement | ⬜ | Existing tx type; needs real CapacityEvidence reports |
| Settlement layer cold-start reserve (Open Q22) | ❓ | Who funds initial reserves; legal form |
| Settlement rate regime (Open Q19) | ❓ | Fixed / floating / managed float |

---

## Phase 3 — Merchant API + BME Activation

**Goal**: Stripe-compatible payment API live; first real QCB buyback-and-burn.

**Prerequisite**: Phase 2 identity pilot hitting targets.

| Item | Status | Notes |
|------|--------|-------|
| Merchant API — Stripe-compatible REST | ⬜ | See whitepaper §9.3 |
| Shopify / WooCommerce plugin | ⬜ | |
| Fiat settlement layer integration | ⬜ | See Open Q20 (governance), Q18 (reserve sizing) |
| BME activation — first on-chain $QCB burn | ⬜ | Requires merchant fee revenue; see §6.3 "live" threshold |
| BME "live vs. speculative" threshold finalization | ❓ | Provisional: burns ≥1% of daily $QCB volume for 90 days |
| Merchant incentive allocations from genesis reserve | ⬜ | See §6.7 |

---

## Phase 4 — Charmed Agents + Merchant Scale

**Goal**: Autonomous agents as first-class chain citizens; physical merchant expansion; 1M verified humans.

**Prerequisite**: Phase 3 merchant API live.

| Item | Status | Notes |
|------|--------|-------|
| Charmed Agent registry | ⬜ | `chain-forge-agents` extension |
| Agent Service Registry (on-chain directory) | ⬜ | See whitepaper §5.3 — "not yet specified" |
| Streaming / metered payment primitives | ⬜ | See whitepaper §5.3 — "not yet specified" |
| Python Agent OS backend | ⬜ | See whitepaper §9.2 |
| SponsorID → agent linkage (AEI spec) | ❓ | Design sketch only; not yet a protocol spec |
| 1M verified humans milestone | 🔲 | Adoption-dependent |
| Liveness of identity (per-human participation requirement) | ❓ | Open Q24 |

---

## Phase 5+ — Governance Maturity + EVM + Interoperability

**Goal**: Decentralized governance; permissioned EVM; interoperability only if PoP-preserving.

**Prerequisite**: Identity layer proven at scale.

| Item | Status | Notes |
|------|--------|-------|
| Permissioned EVM (`chain-forge-evm`) | 🔲 | Every contract needs SponsorID; see whitepaper §7.2 and Open Q23 |
| Sponsored Contracts (Solidity + identity constraints) | 🔲 | Subclass of Charmed Agent; EVM opcode subset TBD (Open Q23e) |
| RWA issuance layer | 🔲 | Tokenized assets via permissioned EVM; QCB compliance-at-protocol-layer |
| Governance succession (post-founder) | ❓ | Open Q10 |
| Interoperability (PoP-preserving bridge only) | 🔲 | Forbidden until chain stable and identity proven; Open Q per §7.1 |
| HotStuff BFT variant | ✅ | Shipped — pluggability proven |
| XRPL-inspired FBA variant | ⬜ | Next variant in sequence |
| Production-grade JMT state tree | ⬜ | Replaces current state layer |
| Chain Forge standalone whitepaper | ⬜ | Aimed at developers building their own chains on the engine |

---

## Immediate Next Items (October 2026)

These are the concrete engineering tasks to pick up next, roughly in priority order:

1. **Adversarial libp2p gossip test** — forge/equivocate over real TCP, not in-process injection. This is the gap left after the in-process attack tests passed.

2. **Node-layer CR exposure** — embed current CoverageRatio in block header or emit as a chain event so light clients and agents can react without running a full node. (Header schema must stabilize first.)

3. **XRPL-inspired FBA variant** — third consensus engine; HotStuff ✅ already proved pluggability is real, so FBA is the next variant in the sequence.

4. **Explorer persistence deployment** — `write_explorer_persistence.py` is packaged; deploy it on the engine machine (Machine 1).

5. **Personhood-weighting overlay** — per-human validator influence cap on `TendermintEngine`, using `ValidatorInfo.pop_verified` already in the registry.

6. **AI red-team Agent 1 (Phase A–D attestation guard bypass)** — strategy-search agent for adversarial attempts against the attestation guard. Backlogged from prior session.

7. **VCA attestation pipeline** — end-to-end `CapacityEvidence_v0` submission from a real provider node to the on-chain `QrcEngine`, so `CreditProvider` and `QrcContributionSettle` can run against real data rather than test fixtures.

---

## Open Questions Index

> See `QCB-Chain-Whitepaper-v2.md §12` for full descriptions. Listed here for quick reference.

| # | Topic | Urgency |
|---|-------|---------|
| Q1 | Final identity layer design; pilot cost/sybil targets | 🔴 High — gates everything |
| Q2 | BFT variant selection for QCB | 🟡 Medium — after HotStuff ships |
| Q5 | Jurisdiction / legal entity | 🔴 High — needed before mainnet |
| Q9 | Identity replacement constitutional mechanism | 🟡 Medium |
| Q10 | Governance succession past founder control | 🟡 Medium |
| Q11 | Stagnation resilience / BME "live" threshold | 🟡 Medium |
| Q13 | Consensus bug migration path | 🟡 Medium |
| Q14 | Validator liveness under partial participation | 🔴 High — needed before Phase 1 |
| Q16 | PQ migration trigger + algorithm choice | 🟡 Medium |
| Q17 | Turnout-suppression resistance | 🟡 Medium |
| Q18 | Settlement layer reserve sizing | 🔴 High — needed before mainnet issuance |
| Q19 | Settlement rate regime (fixed/float/managed) | 🔴 High |
| Q20 | Settlement layer governance | 🔴 High — permanence question |
| Q22 | Settlement layer cold-start + underwriter | 🔴 High — viability question |
| Q23 | Permissioned EVM design (SponsorID enforcement, opcode set, gas denom) | 🟢 Low — Phase 5+ |
| Q24 | Identity liveness requirement (per-human participation) | 🟡 Medium |

---

## Hardware Reference

| Machine | Role | IP | User | Path |
|---------|------|----|------|------|
| Machine 1 (king-OptiPlex-990) | Alice (26656), Bob (26657), Dave (26658) | 192.168.137.2 | king | `/home/king/chain-forge-engine` |
| Machine 2 (bossking-node) | Carol | 192.168.137.3 | bossking | `/home/bossking/` |
| Windows dev (BossKing) | Build + SSH control | — | — | `C:\Dev\chain-forge-engine` |

To update Machine 2 binary: `scp target/release/chain-forge-node bossking@192.168.137.3:/home/bossking/chain-forge-node`

Key files are gitignored (`keys/*.key.json`) — never commit Ed25519 signing seeds.
