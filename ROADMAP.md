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

**Goal**: A working, partition-tolerant BFT consensus engine plus one complete, adversarially-verified, cross-machine resource purchase using QRC — Machine 1's agent buys computation from Machine 2's resource node, escrow settles, and the settlement survives ten deliberate attack scenarios.

**Architecture shift (October 2026)**: The original QRC model assumed resources are minted by providing capacity. The revised model is simpler and cleaner: **resources are purchased with existing QRC; providing resources does not automatically mint QRC.** Provider payment = releasing pre-escrowed QRC. This reorients `chain-forge-qrc` (handles money) and introduces `chain-forge-resource` (handles what was bought with the money). Existing engine work is not wasted — it is reclassified below.

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
| XRPL-inspired FBA variant | ✅ | `FbaEngine` — global UNL, 80% agreement threshold (tunable), single-phase (Open → Committed), no leader rotation; equivocation detection on double-vote; personhood cap + VCA adaptive quorum applied at init; min-UNL guard; 18 dedicated tests passing; all three BFT variants now confirm pluggable `ConsensusEngine` trait |

### Slashing & Safety

| Item | Status | Notes |
|------|--------|-------|
| `chain-forge-slashing` crate | ✅ | `SlashingModule`, `EquivocationEvidence`, `ValidatorRegistry` |
| `ValidatorRegistry` — genesis validators activated at startup | ✅ | `confirm_pop()` called at block 0; registry fully populated |
| Liveness slashing — confirmed on live testnet | ✅ | >20% missed blocks in window → jail + 1,000,000 uQCB slash |
| Equivocation → `SlashingModule::slash_equivocation()` wire | ✅ | `process_equivocation_evidence()` in `node.rs` routes consensus-detected equivocation to slasher |
| Forged vote rejection (in-process test) | ✅ | Garbage-signature vote does not advance height |
| **Adversarial libp2p gossip test** | ✅ | Three tests over real libp2p TCP (not in-process injection): `adversarial_unknown_validator` (UnknownValidator rejection confirmed); `adversarial_equivocation_over_gossip` (equivocation detected, asserted at correct validator + height in logs); `adversarial_garbage_signature` (garbage-sig vote actively rejected via real Ed25519 verification — KNOWN_ISSUES §3 resolved) |

### Cryptography

| Item | Status | Notes |
|------|--------|-------|
| ML-DSA (Dilithium3) post-quantum signing (`chain-forge-crypto`) | ✅ | Validator signing scheme; `--features real-crypto` |
| Crypto-agility constitutional guarantee | 🔄 | Design captured in whitepaper §10 + §7.3; not yet protocol-enforced |
| Signature scheme pluggability in `chain-forge-consensus` | ⬜ | Architectural requirement for PQ migration path |

### QRC Money Layer (`chain-forge-qrc`) — Reclassified

> **What changed**: `chain-forge-qrc` is now solely responsible for QRC as currency. It does not define jobs, match providers, or settle resource-specific receipts — that moves to `chain-forge-resource`. Each existing component is classified below.

| Component | Status | Direction |
|-----------|--------|-----------|
| `QrcEngine`, `ResourceKind` (7 types), serde + persistence | ✅ | **Keep** — QRC account balances, conversion rate, pricing foundation |
| Dynamic conversion rate (Control 1) | ✅ | **Keep** — congestion-based QCB→QRC rate; still valid pricing signal |
| Epoch conversion cap (Control 2) | ✅ | **Keep** — prevents adversarial conversion flooding |
| CoverageRatio circuit breaker (Control 5) | ✅ | **Re-evaluate** — designed for contribution-minting model; review after escrow settlement is wired |
| Per-resource congestion pricing | ✅ | **Keep** — excellent marketplace signal; wires into resource discovery |
| `PurchaseQrc` tx type | ✅ | **Keep** — QCB→QRC on-ramp; job-scoped buy-in path still needed |
| `CapacityReport` / `CapacityEvidence_v0` | ✅ | **Evolve** → `ResourceExecutionReceipt` in `chain-forge-resource`; same Byzantine-resistant median, new meaning: "job fulfilled" not "capacity contributed" |
| `CreditProvider` tx type | ✅ | **Legacy / under review** — minting-era primitive; not the right primitive for escrow release; do not build new dependencies on it |
| `QrcContributionSettle` | ✅ | **Legacy / under review** — contribution-minting model artefact; defer pending revised issuance model |
| Consumption burn (Control 4) — `p_burn = 0.25` | ✅ | **Re-evaluate** — burning the money providers expect to receive is wrong; suspend automatic burn until escrow/revenue-policy design settles |
| On-chain capacity tracking (Control 3) | ✅ | **Keep for market health** — use for discovery pricing + CR; not for minting |
| Node-layer CR exposure (block header / chain event) | ⬜ | **Keep** — light clients / agents need current CR; header schema must stabilize first |

### Resource Market Layer (`chain-forge-resource`) — NEW CRATE

> **Separation principle**: `chain-forge-qrc` handles money. `chain-forge-resource` handles what was bought with the money. This separation matters enormously when the market scales.

| Item | Status | Notes |
|------|--------|-------|
| `chain-forge-resource` crate scaffold | ⬜ | New workspace crate; `ResourceOffer`, `ResourceRequest`, `ResourceMatch`, `ResourceJob`, `ResourceReceipt`, `ResourceMeter`, `ResourceProof`, `ResourceSettlement` |
| `ResourceCapabilityDescriptor` | ⬜ | Standardized vocabulary: `kind`, `architecture`, `cpu_cores`, `memory_bytes`, `gpu_model`, `gpu_memory`, `storage_bytes`, `bandwidth`, `runtime_types`, `price`, `max_job_duration`; agents use this to intelligently choose providers |
| `ResourceJob` state machine | ⬜ | States: `CREATED → FUNDED → MATCHED → RUNNING → (COMPLETED / FAILED) → (VERIFIED / REFUND) → SETTLED`; plus `DISPUTED → RESOLUTION` branch; state machine must have room for future decentralized arbitration |
| `ResourceExecutionReceipt` | ⬜ | Evolves from `CapacityEvidence_v0`; fields: `job_id`, `provider_id`, **`machine_id`**, `requester_agent_id`, `resource_type`, `requested_units`, `measured_units`, `started_at`, `finished_at`, `input_hash`, `output_hash`, `provider_signature`, `requester_confirmation`, `verification_status`; `machine_id` is essential later when one ProviderID covers many machines — you need to know which physical resource did the work |
| P2P resource discovery | ⬜ | Agents broadcast `ResourceRequest` over libp2p gossip; providers respond with `ResourceOffer`; live availability stays off-chain; only economically important commitments/results go on-chain |
| QRC escrow (`LockQrcForJob` / `ReleaseQrcForJob` / `RefundQrcForJob`) | ⬜ | Agent locks QRC before job starts; provider receives only on verified completion; refund path for failure/timeout; `DisputeResourceJob` stub for Phase 1 |
| `ResourceNode` prototype (Machine 2) | ⬜ | Machine 2 (Carol) advertises: `ProviderID`, `SponsorID`, **`MachineID`**, resource capabilities, `container_execution` + `python_execution` runtime types, availability, price, location/latency region, resource limits |
| Secure workload sandbox (container) | ⬜ | Resource providers cannot execute arbitrary agent code on bare host; Docker/container prototype for Phase 0; note: production hostile multi-tenant workloads need stronger isolation — containers are a Phase 0 approximation only |
| Job cancellation / failure / timeout handling | ⬜ | Explicit handling for: provider disappear mid-job, agent sends invalid workload, connection fails, provider produces wrong output, agent falsely claims failure, provider claims completion but result is unusable |

### Agent Economic Identity (AEI) — Moved forward from Phase 4

> Required to properly test the new QRC resource model. Without it you cannot prove Alice's agent cannot exceed Alice's authorization.

| Item | Status | Notes |
|------|--------|-------|
| `AgentID` + `SponsorID` linkage primitive | ⬜ | `MachineID → ProviderID → SponsorID` for resource nodes; one verified human can operate multiple machines; machines have cryptographic identities tracing to human SponsorID |
| **`MachineID` formalization** | ⬜ | `MachineRecord { machine_id, provider_id, owner: ProviderOwner, attestation_key, capability_descriptor, status }`; `MachineAttestationKey` is a separate signing key from the provider's identity key; `MachineStatus` (Active / Inactive / Suspended) |
| **`ProviderOwner` enum** | ⬜ | `enum ProviderOwner { Individual(SponsorId), Enterprise(EnterpriseId) }` — Phase 0 uses `Individual(Carol)`; Phase 1 adds `Enterprise(Acme)` without ripping apart `ResourceJob`, escrow, reputation, or discovery; **define the enum now so Phase 0 code doesn't hard-assume `provider.sponsor_id` is the only ownership structure forever** |
| `AgentTreasury` primitive | ⬜ | `{agent_id, sponsor_id, balance, daily_limit, per_job_limit, allowed_resource_types}`; Alice deposits QRC; agent can spend ≤ per_job_limit; agent cannot withdraw to arbitrary account |
| `CapabilitySet` + `SpendingLimits` | ⬜ | Agent cannot exceed sponsor's authorization; Charm Confinement enforcement begins here |
| `RevenuePolicy` primitive | ⬜ | Configurable destination for agent revenue; e.g. `Sponsor: 30% / AgentTreasury: 60% / Reserve: 10%`; successful service settles automatically |

### Phase 0 Acceptance Test — Cross-Machine Resource Purchase

> **The new Phase 0 completion criterion**: not merely "working BFT + resource economy crate" — but one real, adversarially-verified, cross-machine resource purchase using QRC.

**Happy path**:
```
Machine 1 (Alice) → creates Agent-A → funds 100 test QRC
  → Agent-A requests computation → P2P resource discovery
  → Machine 2 (Carol) Resource Node accepts job
  → Job runs in sandboxed container → Carol returns result
  → ResourceExecutionReceipt generated + verified
  → QRC escrow releases → Carol receives QRC
```

**Attack scenarios** (must survive all ten before Phase 0 is complete):

| # | Attack | Expected outcome |
|---|--------|-----------------|
| 1 | Fake completion (Carol claims done; job never ran) | Escrow not released; refund to Agent-A |
| 2 | Duplicate settlement (Carol submits receipt twice) | Second settlement rejected |
| 3 | Replayed receipt (old job receipt submitted for new job) | Receipt rejected (job_id + height scoped) |
| 4 | Provider disconnect mid-job | Job → FAILED; escrow refunded after timeout |
| 5 | Requester disconnect mid-job | Job continues; result held; no double-payment |
| 6 | Tampered result (output_hash mismatch) | Verification fails; escrow refund |
| 7 | Unauthorized agent spending (Agent-A tries to exceed Alice's limit) | Tx rejected at execution layer |
| 8 | Spending-limit bypass attempt | SpendingLimits enforced; rejection confirmed in test |
| 9 | Forged provider identity (unknown ProviderID submits receipt) | Unknown provider → receipt rejected |
| 10 | Double payment (two settlement attempts for one job) | Second payment rejected; idempotency guard |

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

## Phase 1 — Personhood-Weighted BFT + Resource Market Foundation

**Goal**: Consensus power tied to verified human identity, not raw stake. Resource market hardened with provider reputation, dispute resolution skeleton, and multi-provider discovery. Charmed Agent identity/budget primitive live.

**Prerequisite**: Phase 0 complete — includes cross-machine resource purchase acceptance test passing.

### Consensus — Personhood Weighting

| Item | Status | Notes |
|------|--------|-------|
| Personhood-weighting overlay on TendermintEngine | ⬜ | Cap per-human validator influence regardless of stake |
| `ValidatorInfo.pop_verified` gating in consensus | ⬜ | Only PoP-confirmed validators counted for quorum |
| Stake → influence cap enforcement | ⬜ | See whitepaper §3.3 |
| Validator liveness under partial-participation (Open Q14) | ❓ | How does finality behave if large fraction of verified humans go offline? |
| Governance quorum floor enforcement | ⬜ | >3% turnout for ordinary QRC votes; >6% for constitutional (derived from §6.6) |

### Identity — Charm Confinement

| Item | Status | Notes |
|------|--------|-------|
| Charm Confinement (`chain-forge-identity` extension) | ⬜ | Identity-scoped state isolation; one claim per epoch |
| Intrinsic Charm module | ⬜ | Verification tier intrinsic to identity; **note: decay-exemption credits removed** — demurrage is out of QRC v3, so decay-exemption credits have no referent; drop this concept |

### Resource Market — Phase 1 Hardening

| Item | Status | Notes |
|------|--------|-------|
| Provider reputation (minimal) | ⬜ | Track: `completed_jobs`, `failed_jobs`, `disputes`, `uptime`, `verification_failures`, `latency`; agents choose provider on price + reputation; reputation must resist self-dealing (Alice cannot manufacture reputation by hiring Alice's own node) |
| `DisputeResourceJob` tx type | ⬜ | Phase 0 stubbed the state; Phase 1 wires the submission and resolution path; decentralized arbitration is Phase 2+ but the state machine must accept disputes now |
| Multi-provider resource discovery | ⬜ | Agent broadcasts `ResourceRequest`; multiple `ResourceOffer` responses ranked by price + reputation; agent selects |
| Provider-identity → SponsorID tracing | ⬜ | `MachineID → ProviderID → SponsorID`; one human can operate N resource nodes legitimately; prevents sybil inflation of reputation |
| Sandboxed workload hardening | ⬜ | Move beyond basic container toward resource-limit enforcement (CPU, RAM, disk, network policy, runtime cap); document that Docker is a Phase 0 approximation |
| Machine-level reputation → Provider-level reputation aggregation | ⬜ | Reputation tracks at the machine level first; aggregated up to ProviderID; extends cleanly to EnterpriseID in Phase 1 without redesign |

### Enterprise Authorization Tree — EAT-v0

> **What this is**: An optional organizational layer that sits between verified humans and enterprise-controlled resources. `EnterpriseID` does not replace `SponsorID`, `MachineID`, `ProviderID`, or `AgentID` — it becomes a container above them for resources operated by organizations. Every enterprise-controlled machine or agent must resolve through an authorization path to at least one active verified `SponsorID`.
>
> **Identity hierarchy**:
> ```
>               VERIFIED HUMAN
>                  SponsorID
>                      │
>        ┌─────────────┴─────────────┐
>        │                           │
> Individual Path             Enterprise Path
>        │                           │
>        │                    EnterpriseID
>        │                           │
>   ┌────┴────┐               ┌─────┴──────┐
>   │         │               │            │
> AgentID  MachineID       AgentID      MachineID
>              │                           │
>          ProviderID                  ProviderID
>              └──────────┬────────────────┘
>                         │
>                   ResourceOffer
>                         │
>                   ResourceJob
>                         │
>          ResourceExecutionReceipt
>                         │
>                    QRC Settlement
> ```

| Item | Status | Notes |
|------|--------|-------|
| `EnterpriseID` primitive | ⬜ | Organization container; does not replace SponsorID |
| `ControllerBinding` | ⬜ | Connects one or more verified human `SponsorID`s to an `EnterpriseID`; every enterprise resource traces to at least one active human controller |
| `EnterpriseCapabilitySet` | ⬜ | Limits what each controller can authorize within the enterprise |
| `ResourcePool` | ⬜ | Groups multiple enterprise `MachineID`s under one `EnterpriseID`; agents purchase from the pool, not individual machines |
| Enterprise → `MachineID` binding | ⬜ | `ProviderOwner::Enterprise(EnterpriseId)` activated (Phase 0 defines the enum; Phase 1 activates this variant) |
| Enterprise → `AgentID` binding | ⬜ | Corporate agents sponsored by enterprise rather than individual `SponsorID` |
| Controller revocation | ⬜ | An `EnterpriseID` controller can be removed; remaining controllers must still satisfy minimum `SponsorID` accountability |
| Authorization subtree freeze | ⬜ | Emergency halt for a compromised enterprise authorization tree |
| Enterprise reputation aggregation | ⬜ | Machine reputation → ProviderID reputation → enterprise resource reputation (separate track from individual human controller reputation) |
| `PersonhoodMultisig` | ⬜ | M-of-N verified human controllers required to authorize high-value enterprise operations; implement *after* basic `EnterpriseID → ControllerBinding → CapabilitySet` works |

> **Not in Phase 1**: corporate legal verification, incorporation documents, jurisdiction, tax status — those belong to the `Enterprise → Organization Attestation → Legal/KYC/RWA compliance` layer, which arrives with the Phase 5+ permissioned EVM and RWA work.

### Dual Resource Participation — Machine Modes

> **What this is**: A machine running a QCB Resource Node is not required to sell capacity to commercial customers. It can contribute capacity directly to QCB network infrastructure instead — or do both simultaneously, subject to the owner's policy.

```
                         MACHINE
                            │
                ┌───────────┴───────────┐
                │                       │
         MARKETPLACE MODE        CONTRIBUTION MODE
                │                       │
       Customer workloads         Network workloads
                │                       │
       QRC compensation          Contribution credit
                │                       │
                └───────────┬───────────┘
                            │
                   UsefulWorkReceipt
                            │
                       Reputation
                            │
                  uQCB eligibility
```

> Machines can run both modes simultaneously. Owner policy controls resource allocation, hours, and which modes are active.

| Item | Status | Notes |
|------|--------|-------|
| `MachineMode` flag on `MachineRecord` | ⬜ | `enum MachineMode { MarketplaceOnly, ContributionOnly, Both }`; persisted in machine registration |
| Machine owner resource policy | ⬜ | Owner declares: GPU%, storage TB, bandwidth Mbps, hours window, allowed modes; respected by resource node at runtime |
| `NetworkContributionJob` type | ⬜ | QCB-assigned workload submitted to a machine in Contribution Mode; structured as a well-defined task with verifiable output (storage proof, compute proof, etc.) — not open-ended execution |
| `UsefulWorkReceipt` | ⬜ | Receipt for a completed `NetworkContributionJob`; shares shape with `ResourceExecutionReceipt` (job_id, machine_id, work_type, proof, verification_status) but payer is the QCB network contribution pool, not a customer agent; a `receipt_type` field distinguishes the two — avoid two entirely separate receipt types |
| Network Contribution Pool coordinator | ⬜ | Assigns `NetworkContributionJob`s to available machines in Contribution Mode; defines what work is legitimately available; must be decentralized in Phase 2+ |

### Useful Contribution / uQCB — Verified Network Work

> **Economic rule**: machines earn contribution credit only for completing assigned, verifiable network work — not merely for being online. The flow is:
> ```
> machine online → capacity available → network assigns useful work
>   → machine completes work → cryptographic proof/receipt
>   → UsefulWorkReceipt → Contribution Score → uQCB epoch eligibility
> ```
> This is structurally different from a fake-customer self-dealing attack. The network itself has a legitimate need for the resource; the machine fulfills a real assigned task; an objective cryptographic proof demonstrates completion.

| Item | Status | Notes |
|------|--------|-------|
| Contribution Score primitive | ⬜ | Per-machine tally of verified `UsefulWorkReceipt`s within an epoch; decays for inactivity; weighted by work type difficulty/verifiability |
| uQCB epoch distribution | ⬜ | Predefined scarce QCB contribution pool distributed each epoch to machines above a Contribution Score threshold; **pool is fixed/predefined — uQCB is not newly minted QRC**; keeps uQCB separate from consensus entirely |
| **uQCB → QCB conversion ratio** | ✅ LOCKED | **1,000,000 uQCB = 1 QCB** (Satoshi-model micro-unit; fixed at protocol level; not governance-adjustable) |
| **uQCB conversion — permissionless on-chain** | ✅ LOCKED | Operator calls conversion tx when balance ≥ 1,000,000; protocol burns uQCB, mints 1 QCB to registered address; no governance gate, no approval committee |
| **uQCB non-transferable / non-AMM** | ✅ LOCKED | uQCB is bound to earning machine; cannot be bought, sold, or transferred; does not appear on AMM; only the earner can convert to QCB |
| Contribution pool supply schedule | ❓ | **Open Q**: total pool size, epoch allocation rate, decay/halving schedule; must be defined before any uQCB distribution goes live |
| **Native AMM (XRPL-style)** | ⬜ | On-chain AMM; QRC and QCB are AMM-tradeable; uQCB explicitly excluded; QRC/BTC and QRC/stablecoin pools for external asset inflow; LP fee rewards for liquidity providers; Phase 2 |
| Contribution Mode ↔ QRC settlement distinction | ⬜ | Commercial work (customer agent → QRC payment) and protocol contribution (network job → contribution credit) are distinct flows; QRC is not automatically issued for idle capacity or contribution-mode work; clarify whether certain protocol jobs can also earn QRC in Phase 2+ |
| Self-dealing guard for Contribution Mode | ⬜ | Owner cannot submit jobs to their own machine from the contribution pool; pool coordinator must assign work independently |

### Anti-Farming Architecture

> Before uQCB distribution goes live, the following defenses must all be in place. None of these are optional — any one missing creates a farming vector.

| Defense | Status | Notes |
|---------|--------|-------|
| SponsorID verification required | ⬜ | Machine must trace to a verified human `SponsorID` before Contribution Mode is active; unverified machines cannot earn contribution credit |
| `MachineID` uniqueness enforcement | ⬜ | One `MachineID` per physical machine; attestation key bound at registration; cannot register multiple `MachineID`s from the same hardware fingerprint |
| Execution receipts (not heartbeats) | ⬜ | Contribution credit requires `UsefulWorkReceipt` proving work completed — being online earns nothing |
| Self-dealing detection | ⬜ | Machine's owner cannot be the entity assigning network jobs to that machine; coordinator independence required |
| Consumer diversity requirement | ⬜ | Reputation and contribution credit must reflect work for independent parties — not circular self-transactions |
| Resource proofs (not claims) | ⬜ | Storage: possession proofs over time (e.g., challenge-response on stored shards); compute: output hash + timing verifiable against known benchmark; bandwidth: relay measurement by independent nodes |
| Reliability scoring | ⬜ | Machines that accept jobs and fail to deliver are penalized in Contribution Score; serial failure triggers `MachineStatus::Suspended` |
| Integrity scoring | ⬜ | Tampered outputs, forged proofs, or disputed receipts reduce contribution score; extreme cases trigger SponsorID-level review |
| Contribution Score gate before uQCB eligibility | ⬜ | Epoch distribution requires score above minimum threshold; newly registered machines cannot immediately claim distribution |

### Agent Economic Identity — Phase 1 Extension

| Item | Status | Notes |
|------|--------|-------|
| `CapabilitySet` enforcement on-chain | ⬜ | Agent's allowed resource types enforced at tx execution, not just client-side |
| `RevenuePolicy` settlement automation | ⬜ | Successful service auto-settles to sponsor + agent treasury + reserve per configured policy |
| Agent treasury → spending audit endpoint | ⬜ | Sponsor can query: what has my agent spent, on what, and to whom |

---

## Phase 2 — Identity Pilot + QRC Issuance Model Finalized

**Goal**: Real-world sybil-resistance pilot; QRC issuance model finalized (purchase path confirmed; contribution-minting model resolved as legacy or deliberately retired); resource market running at testnet scale; BTC miner community portal live with Grand Challenge pool mode.

**Prerequisite**: Phase 1 complete.

| Item | Status | Notes |
|------|--------|-------|
| Identity pilot design — cost/sybil targets finalized | ❓ | Provisional: <3% sybil rate, <$5/verification; see Open Q1 |
| Red-team / adversarial sybil test | ⬜ | Phase A–D attacks: attestation-guard bypass attempts |
| `PurchaseQrc` path open on testnet | ⬜ | Execution tx type ✅; needs live QrcEngine + identity gate |
| QRC issuance model decision | ❓ | **Open Q**: does provider contribution ever mint new QRC, or is all QRC acquired via `PurchaseQrc` only? Until resolved, `CreditProvider` and `QrcContributionSettle` remain legacy/under-review — do not build new dependencies on them |
| `CreditProvider` / `QrcContributionSettle` — resolve or retire | ❓ | If contribution-minting is confirmed retired: deprecate these tx types; if a narrow minting path survives, redesign it around the escrow-release model, not coordinator-issued credits |
| Settlement layer cold-start reserve (Open Q22) | ❓ | Who funds initial reserves; legal form |
| Settlement rate regime (Open Q19) | ❓ | Fixed / floating / managed float |
| Grand Challenge pool mode live | ⬜ | Pool operators aggregate $QRC earnings across member machines; distribute by hash-rate share; supports BTC mining farms participating as a unit |
| Community portal v1 — challenge dashboard | ⬜ | Public site: live challenge metrics, $QRC/TH/s earnings rate, leaderboards per track, individual machine history; the "point your rig at science" onboarding moment |
| BTC miner outreach program | ⬜ | Documentation, daemon packaging, community presence in BTC mining forums and BOINC communities; first wave of SHA256 hardware directed at Grand Challenge tracks |

---

## QCB Grand Challenge — Long-Term Distributed Research Compute

> **What this is**: When commercial demand is absent, voluntarily contributed QCB resources can be directed toward objectively verifiable computational challenges intended to advance cryptography, mathematics, computational efficiency, and machine-assisted discovery. This is not consensus. Personhood-anchored BFT remains solely responsible for block production and finality. The Grand Challenge and network contribution sit above consensus as productive economic and research layers.
>
> **Long-term research principle**: QCB does not ask machines to compute meaningless hashes. When machines contribute capacity to the network, that capacity is directed toward useful, objectively verifiable work — including research challenges with real scientific or cryptographic value.
>
> **Safety boundary** (hard constraint): Discoveries never automatically change QCB protocol behavior. Any finding that could affect protocol cryptography must pass independent expert review, formal security analysis, adversarial testing, and explicit QCB governance approval before it influences any protocol parameter. Research and governance are entirely separate.

### Grand Challenge Tracks

| Track | Description | Verification method |
|-------|-------------|---------------------|
| Constructive / post-quantum cryptography | Finding new PQ candidates, analyzing existing schemes, searching for parameter weaknesses | Peer review + formal proof; independent cryptographer validation |
| Privacy | ZK circuit optimization, proof system improvements, privacy-preserving computation research | Benchmark against known baselines; formal verification where applicable |
| Computational efficiency | Algorithm improvements for QCB-relevant operations (hashing, proof generation, state trie ops) | Reproducible benchmark; independently confirmed speedup |
| Verifiable mathematical research | Formally specified open problems with objective pass/fail criteria (e.g., known search spaces, conjectured bounds) | Formal verification tool output; mathematical proof |
| AI-assisted computational discovery | Privacy-safe network telemetry analysis, capacity/demand modeling, protocol parameter research | Methodology review; reproducibility; no personal data |
| Physics & open science | Problems beyond what any single machine or quantum computer can reach today: lattice QCD simulations (quark-gluon behavior at high precision), many-body quantum systems, cosmological structure formation, dark matter candidate modeling, quantum gravity approximations. Results must be reproducible by an independent verifier machine; methodology must be published alongside the output hash. | Independent verifier reproduction; domain-expert quorum ratification; hash-committed methodology artifact |

### Proof of Useful Discovery

> Machines earn contribution credit for objectively verifiable research work, following the same `UsefulWorkReceipt` flow as other Network Contribution Mode jobs. Exceptional verified discoveries — a genuine cryptographic improvement, a formally verified mathematical result — can have separate, predetermined discovery rewards defined in advance by governance. No discovery reward is issued retroactively or by discretion.

| Item | Status | Notes |
|------|--------|-------|
| Grand Challenge work pool | 🔲 | Defined research challenges submitted to network contribution pool; machines in Contribution Mode can opt into research tracks; Phase 2+ |
| Research `UsefulWorkReceipt` variant | ✅ | `work_type: ResearchContribution`; includes output hash, methodology reference, verifier ID; same anti-farming defenses as other contribution jobs. **Simulation proven 2026-10-06 — see `grand-challenge/simulations/GC-DEVNET-001`** |
| Discovery reward schedule | 🔲 | Predetermined pool per track; governance-approved before any track goes live; rewards are fixed/predefined, not minted on discovery |
| Independent verifier registry | 🔲 | Track-specific domain experts registered on-chain; discovery claims require independent verification before reward release |
| Formal safety review gate | 🔲 | Any cryptographic finding that could affect QCB protocol must pass: independent expert review → formal/security analysis → adversarial testing → governance vote; no automatic protocol changes |

### Useful Hash Commitments — BTC Ecosystem Integration

> **What this is**: Grand Challenge receipts carry a `seal_hash = SHA256(nonce || output_hash || challenge_id)` with a target difficulty prefix — structurally identical to Bitcoin's mining loop. The same SHA256 ASICs and GPUs used for Bitcoin mining can compute seal hashes. The hash is a tamper seal around a scientific output, not the product itself. Bitcoin mining and Grand Challenge work are not in competition; the machine daemon runs alongside existing mining software.
>
> **Who this reaches**: solo miners and small farms (second income stream on existing hardware), BOINC veterans (familiar model, now with cryptographic accountability and $QRC reward), pool operators (Grand Challenge pool mode), and the Bitcoin philosophy crowd (computational work that produces something real).

| Item | Status | Notes |
|------|--------|-------|
| BTC block hash randomness beacon | ⬜ | Grand Challenge job slice assignment derived from recent BTC block hash: `job_seed = SHA256(btc_block_hash \|\| challenge_id \|\| machine_id)`; prevents QCB or any participant from steering which machine gets which problem slice; established technique (used by Chainlink VRF, drand, bitcoin anchors), applied here to research job fairness; Phase 1 |
| `seal_hash` field on `UsefulWorkReceipt` | ⬜ | `seal_hash: String` — `SHA256(nonce \|\| output_hash \|\| challenge_id)` with target difficulty prefix; added to `chain-forge-resource` receipt types; Phase 1 |
| Seal difficulty target per challenge track | ⬜ | Governance-settable difficulty for each active Grand Challenge track; stored in challenge config; Phase 1 |
| Seal verification in receipt submission | ⬜ | Receipt submission path checks difficulty prefix before accepting `UsefulWorkReceipt`; verifier re-hashes from submitted `nonce + output_hash + challenge_id` — fast, one SHA256 call; Phase 1 |
| Grand Challenge machine daemon (`gc-daemon`) | ⬜ | Lightweight process: pulls active challenge jobs from network, runs computation in sandboxed environment, finds seal nonce, submits `UsefulWorkReceipt`; runs alongside existing mining software without conflict; Phase 1 |
| SHA256 hardware compatibility documentation | ⬜ | Document that standard Bitcoin mining ASICs and GPUs can compute seal hashes; include benchmark: TH/s → expected seals/hour at target difficulty; Phase 1 |
| BTC miner onboarding guide | ⬜ | Step-by-step: install daemon, point at challenge, earn QRC alongside BTC mining; Phase 1 community milestone |
| Grand Challenge resource pool mode | ⬜ | Pool operator mode: pool collects `UsefulWorkReceipt`s from member machines, aggregates $QRC earnings, distributes to members by hash-rate contribution share; Phase 2 |
| Community portal — challenge dashboard | ⬜ | Live metrics: hash rate contributing to each active challenge, $QRC earnings per TH/s, challenge leaderboards, individual machine contribution history; Phase 2 |

### Public Discovery Dashboard

> Transparency is a first-class requirement. All Grand Challenge metrics are publicly verifiable on-chain.

| Item | Status | Notes |
|------|--------|-------|
| Verified compute contributed | 🔲 | Total and per-track; per-machine contribution history available to machine owner |
| Active participants | 🔲 | Count of `MachineID`s currently in research contribution tracks |
| Candidates tested / problems explored | 🔲 | Per-track progress against defined search space |
| Milestone achievements | 🔲 | On-chain record of verified discoveries and governance decisions about them |
| Search-space percentage + ETA | 🔲 | **Only when mathematically measurable** — tracks with formally defined finite search spaces may publish completion percentage; tracks without a measurable bound publish raw progress only, never an estimated completion date |
| Individual contribution history | 🔲 | Machine owner can view their own `UsefulWorkReceipt` history and contribution score breakdown; no cross-machine correlation visible to third parties |

### Grand Challenge Simulation Log

| ID | Date | Type | Winner | Result | Record |
|----|------|------|--------|--------|--------|
| GC-DEVNET-001 | 2026-10-06 | Hash preimage search (`SHA256('QCB:<nonce>')` prefix `0000`) | Carol (MACH-CAROL-003) | Nonce `6,682,026` → `000050f1...` — verified by Dave | `grand-challenge/simulations/GC-DEVNET-001-discovery-record.json` |

> **What GC-DEVNET-001 proved**: Three parallel machines (Alice, Bob, Carol) searched independent nonce ranges. Carol found the solution in 15,361 checks (0.04s). Dave independently reproduced the hash from the nonce alone and signed the verification. Full `UsefulWorkReceipt` with `work_type: ResearchContribution`, machine signature, and verifier signature produced. The coordination and verification logic is complete — only the Rust crate and Ed25519 signing remain to wire to the real devnet.

**Next simulations planned:**
- GC-DEVNET-002 — Multi-track parallel (two challenges running simultaneously)
- GC-DEVNET-003 — Disputed result + rejection flow
- GC-DEVNET-004 — Physics-flavored: tiny lattice simulation with verified output hash

---

## QCB Equilibrium State — When the Network Becomes Alive

> Equilibrium is not a launch event. It is a threshold the network crosses — gradually, over years — as machines join, attestations accumulate, and the resource market deepens. Below equilibrium, QCB is a blockchain with a research layer. Above equilibrium, it is a trustworthy distributed supercomputer: self-sustaining, self-healing, and capable of scientific work no individual machine or centralized facility could reach.

### Equilibrium Criteria

All five conditions must hold simultaneously and sustain for a meaningful period before the network is considered to have reached Equilibrium State:

| Criterion | Definition | Status |
|-----------|------------|--------|
| Validator depth | Validator set large and geographically distributed enough that no regional outage, coordinated departure, or single bad actor can halt block production or reverse finality | 🔲 Phase 3+ |
| Machine population | Machine count deep enough that every active Grand Challenge track has sufficient independent verifier machines to confirm results without any track going dark for lack of participants | 🔲 Phase 4+ |
| Resource market competition | Enough competing providers that no single provider or cartel can price-fix QRC or starve agents of capacity | 🔲 Phase 3+ |
| Anti-farming maturity | All 9 anti-farming defenses battle-tested under real adversarial load; contribution score trustworthy enough to govern uQCB distributions without manual oversight | 🔲 Phase 2/3 |
| Governance participation | Protocol vote participation rate reflects the network's actual human base, not a mobilized minority | 🔲 Phase 4+ |

### What Changes Above Equilibrium

| Capability | Below Equilibrium | Above Equilibrium |
|------------|-------------------|-------------------|
| Grand Challenge throughput | Limited — fewer tracks, slower verification | Multiple tracks run simultaneously with full independent verifier coverage |
| Physics & open science problems | Out of reach — insufficient parallel verified runs | Tractable — coordinated scale enables lattice QCD, many-body quantum systems, cosmological simulation |
| Network resilience | Requires active maintenance | Self-healing — machine churn absorbed without disrupting ongoing research jobs |
| Discovery rate | Bottlenecked by verifier availability | Scales with machine population; faster iteration on hard problems |
| Governance integrity | Vulnerable to minority mobilization | Reflects genuine human base of the network |

### Timeline Honesty

Reaching Equilibrium State will take years. Bitcoin took years to harden its consensus under real adversarial conditions. Ethereum took years to reach the validator depth where its consensus felt genuinely robust. QCB accepts the same timeline — and names it here rather than implying otherwise.

The architectural commitment is different from the timeline: QCB is designed for equilibrium from the first block. The MachineID registry, ResourceExecutionReceipt accountability layer, Grand Challenge tracks, and hard safety boundary are not retrofits. They are load-bearing from day one, so that when the network reaches scale, the capability is already there waiting.

> No specific machine count is required for Equilibrium State. Scale is a means, not the definition. The five criteria above — not any headcount target — determine when equilibrium is reached.

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
| XRPL-inspired FBA variant | ✅ | Shipped — global UNL, 80% threshold, 18 tests passing; all three pluggable BFT variants now confirmed |
| Production-grade JMT state tree | ⬜ | Replaces current state layer |
| Chain Forge standalone whitepaper | ⬜ | Aimed at developers building their own chains on the engine |

---

## Immediate Next Items (October 2026)

These are the concrete engineering tasks to pick up next, in priority order. The architecture pivot is captured above — before touching code, confirm the ordering below against the new Phase 0 acceptance test goal.

### Code tasks (Phase 0 resource market foundation)

1. **`chain-forge-resource` crate scaffold** — create the workspace crate with the eight core types (`ResourceOffer`, `ResourceRequest`, `ResourceMatch`, `ResourceJob`, `ResourceReceipt`, `ResourceMeter`, `ResourceProof`, `ResourceSettlement`) and the `ResourceJob` state machine. No business logic yet — just the types and state transitions that everything else will build on.

2. **`ResourceCapabilityDescriptor`** — standardized vocabulary struct; wire into Machine 2 (Carol) `ResourceNode` prototype so it can advertise capabilities over libp2p gossip.

3. **QRC escrow primitives** — `LockQrcForJob`, `ReleaseQrcForJob`, `RefundQrcForJob` as new tx types in `chain-forge-execution`; wire into `QrcEngine` balance accounting; timeout/refund path must be explicit.

4. **`AgentTreasury` + `AgentID`/`SponsorID` primitives** — minimum needed to run the Phase 0 acceptance test; Alice can fund an agent treasury; agent cannot exceed `per_job_limit`; agent cannot withdraw to arbitrary account.

5. **`MachineID` + `ProviderOwner` + `ResourceExecutionReceipt`** — formalize `MachineRecord` and `ProviderOwner { Individual(SponsorId), Enterprise(EnterpriseId) }` while building the first resource types (don't wait — this small abstraction prevents a major refactor later); then evolve `CapacityEvidence_v0` into `ResourceExecutionReceipt` adding `machine_id` field; provider signs receipt on job completion; requester confirms; verification triggers escrow release.

6. **Sandboxed container execution on Machine 2** — Docker-based prototype; Carol's resource node executes submitted workloads inside a container with CPU/RAM limits; returns result + receipt.

7. **Cross-machine happy-path integration test** — Machine 1 agent purchases computation from Machine 2 Carol; full flow from `LockQrcForJob` → job runs in container → `ResourceExecutionReceipt` submitted → `ReleaseQrcForJob` completes.

8. **Ten attack scenarios** (see Phase 0 acceptance test table above) — one test per scenario; all must pass before Phase 0 is declared complete.

### Infrastructure tasks (can run in parallel)

9. **Node-layer CR exposure** — embed CoverageRatio in block header or chain event; light clients / agents need it without running a full node.

10. **Explorer persistence deployment** — `write_explorer_persistence.py` packaged; deploy on Machine 1.

### Phase 1 prep (after Phase 0 acceptance test passes)

11. **Personhood-weighting overlay** — per-human validator influence cap on `TendermintEngine`, using `ValidatorInfo.pop_verified` already in the registry.

12. **AI red-team Agent 1 (Phase A–D attestation guard bypass)** — strategy-search agent for adversarial attestation guard bypass attempts. Backlogged from prior session.

13. **`seal_hash` field on `UsefulWorkReceipt`** — add `seal_hash: String` and `seal_nonce: u64` to the receipt struct in `chain-forge-resource`; add seal difficulty verification to the receipt submission path; wire into Grand Challenge simulation scripts so GC-DEVNET-002+ generate sealed receipts.

14. **Grand Challenge machine daemon skeleton** — `gc-daemon` binary: connects to devnet, polls for active challenge jobs, executes assigned computation in subprocess sandbox, runs seal-nonce search loop, submits completed `UsefulWorkReceipt`. First target: replicate GC-DEVNET-001 as a daemon invocation rather than a Python script.

---

## Open Questions Index

> See `QCB-Chain-Whitepaper-v2.md §12` for full descriptions. Listed here for quick reference.

| # | Topic | Urgency |
|---|-------|---------|
| Q1 | Final identity layer design; pilot cost/sybil targets | 🔴 High — gates everything |
| Q2 | BFT variant selection for QCB | 🟡 Medium — all three variants shipped; selection decision now unblocked |
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
