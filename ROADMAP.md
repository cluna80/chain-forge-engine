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

> **Security hardening milestones QCB-CS-001 and QCB-KR-001** are Phase 1 items that build directly on the work above. See Phase 1 → Cryptographic Security Hardening.

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
| `chain-forge-resource` crate scaffold | ✅ | `MachineRecord`, `ResourceCapabilityDescriptor`, `ResourceJob`, `ResourceExecutionReceipt`, `LockQrcForJob`/`ReleaseQrcForJob`/`RefundQrcForJob`; 23 unit tests passing |
| `ResourceCapabilityDescriptor` | ✅ | `ComputeClass`, `MemoryTier`, `StorageTier`, `PriceModel`, ISA tags; `satisfies()` matcher lets agents check if provider meets job requirements; 8 unit tests |
| `ResourceJob` state machine | ✅ | Full `CREATED→FUNDED→MATCHED→RUNNING→(COMPLETED/FAILED)→(VERIFIED/REFUND)→SETTLED` + `DISPUTED→RESOLUTION` branch; `is_terminal()` guard; 9 unit tests covering all paths + invalid-transition rejection |
| `ResourceExecutionReceipt` | ✅ | `ResourceExecutionReceipt` + `UsefulWorkReceipt`; `compute_seal_hash`, `find_seal_nonce`, `meets_difficulty`, `verify_seal`; 6 unit tests |
| P2P resource discovery | ⬜ | Agents broadcast `ResourceRequest` over libp2p gossip; providers respond with `ResourceOffer`; live availability stays off-chain; only economically important commitments/results go on-chain |
| QRC escrow (`LockQrcForJob` / `ReleaseQrcForJob` / `RefundQrcForJob`) | ✅ | Agent locks QRC before job starts; provider receives only on verified completion; refund path for failure/timeout; N3/N4/N5 guards tested; `DisputeResourceJob` stub for Phase 1; `RefundReason` enum covers all failure cases |
| `ResourceNode` prototype (Machine 2) | ⬜ | Machine 2 (Carol) advertises: `ProviderID`, `SponsorID`, **`MachineID`**, resource capabilities, `container_execution` + `python_execution` runtime types, availability, price, location/latency region, resource limits |
| Secure workload sandbox (container) | ⬜ | Resource providers cannot execute arbitrary agent code on bare host; Docker/container prototype for Phase 0; note: production hostile multi-tenant workloads need stronger isolation — containers are a Phase 0 approximation only |
| Job cancellation / failure / timeout handling | ⬜ | Explicit handling for: provider disappear mid-job, agent sends invalid workload, connection fails, provider produces wrong output, agent falsely claims failure, provider claims completion but result is unusable |

### Agent Economic Identity (AEI) — Moved forward from Phase 4

> Required to properly test the new QRC resource model. Without it you cannot prove Alice's agent cannot exceed Alice's authorization.

| Item | Status | Notes |
|------|--------|-------|
| `AgentID` + `SponsorID` linkage primitive | ✅ | `AgentId` in `chain-forge-resource`; `SponsorId` in `MachineRecord.owner`; `MachineID → ProviderID → SponsorID` hierarchy is expressed via `ProviderOwner` |
| **`MachineID` formalization** | ✅ | `MachineRecord { machine_id, owner: ProviderOwner, attestation_key, capability_descriptor, mode, status }`; `MachineAttestationKey` (Ed25519 pubkey, base64); `MachineStatus` (Pending/Active/Inactive/Banned) |
| **`ProviderOwner` enum** | ✅ | `enum ProviderOwner { Individual(SponsorId), Enterprise(EnterpriseId) }` — defined; Phase 0 uses `Individual(Carol)`; Phase 1 adds `Enterprise(Acme)` without ripping apart ResourceJob, escrow, or discovery |
| `AgentTreasury` primitive | ✅ | `treasury:{agent_id}` virtual account; credited by `DepositToTreasury` tx; debited by `LockQrcForJob` (treasury-first, fallback to agent wallet); `per_job_limit_uqrc` cap enforced at execution; sponsor gate on deposit |
| `CapabilitySet` + `SpendingLimits` | ✅ | `SpendingLimits` struct (`epoch_limit`, `lifetime_limit`, `max_balance`, `per_job_limit`); `check_per_job()` enforcer; `resource_agent()` preset; agent cannot exceed sponsor's authorization |
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
| Explorer persistence (`write_explorer_persistence.py`) | ✅ | `scripts/write_explorer_persistence.py` + `scripts/start-explorer-persistence.sh` — deploy on Machine 1 after devnet is up |
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

### Cryptographic Security Hardening

> These are **Chain Forge modules** first — reusable by any sovereign chain built on Chain Forge. QCB is the first chain to enable and adversarially test them, exactly as with PoCD. Future chains can adopt cryptographic-agility and key-lifecycle capabilities independently of QCB's QRC economy or personhood rules.
>
> **Implementation order:** QCB-CS-001 first (defines the migration architecture); QCB-DIS-001 Phase A builds the wallet on top of that architecture; QCB-KR-001 implements account-level and multisig key management; QCB-PM-001 adds zero-knowledge identity privacy as a separate research layer.  
> **Completion rule:** No milestone is ✅ until implementation **and** adversarial tests pass.

**Post-Quantum Security Roadmap summary:**

| Milestone | Technology | Status |
|---|---|---|
| **QCB-CS-001** | Cryptographic Survivability and Migration | ⬜ Phase 1 |
| **QCB-DIS-001** | Digital Identity Stone — Native QCB Wallet | ✅ Phase A + B complete |
| **QCB-KR-001** | Post-Quantum Multisig and Key Lifecycle | ⬜ Phase 1 |
| **QCB-PM-001** | Private Post-Quantum Threshold Authorization | ❓ Research |
| **QSWIP-001** | Open Post-Quantum Wallet Identity Protocol | 🔲 Proposed standard |

#### QCB-CS-001 — Cryptographic Survivability and Migration

*Goal: Ensure QCB can safely migrate to different cryptographic algorithms if an existing algorithm becomes vulnerable to AI-assisted cryptanalysis, quantum computing, or other attacks.*

| Requirement | Status | Notes |
|---|---|---|
| Complete cryptographic dependency inventory | ⬜ | Audit every hash function, signature scheme, and KDF used across all Chain Forge / QCB crates |
| Public-key exposure audit across QCB | ⬜ | Identify every place a public key is stored on-chain or transmitted; classify exposure risk |
| Post-quantum authentication for critical operations | ⬜ | Validator signing, treasury multisig, governance votes — must tolerate PQ threat model |
| Pluggable signature algorithms (`chain-forge-crypto`) | ⬜ | `SignatureScheme` trait with versioned algorithm identifiers; builds on existing `chain-forge-consensus` pluggability work |
| Safe cryptographic migration procedures | ⬜ | Documented + tested path: old algorithm → new algorithm without disrupting in-flight transactions or active multisig sets |
| Emergency algorithm-deprecation mechanism | ⬜ | Governance tx to flag an algorithm as deprecated; grace period for key rotation; hard cutoff enforcement in consensus |
| Simulated cryptographic compromise tests | ⬜ | Deliberately treat one scheme as "broken"; verify network migrates cleanly under simulated adversarial conditions |
| Independent security review | 🔲 | Prerequisite: all above items pass; external review before mainnet |

#### QCB-DIS-001 — Digital Identity Stone (QCB Native Wallet)

*Goal: A scannable, post-quantum authentication protocol that lets users access QCB services without exposing private keys. The QR code is the doorway, not the key.*

**Core architectural principles:**
1. Private keys never leave the wallet — transactions are signed locally using ML-DSA.
2. Scannable authentication — temporary QR challenges provide secure access without exposing signing secrets.
3. Privacy-preserving identity — applications receive only the authorization or identity information they require.
4. Post-quantum multisig — multiple owners can securely authorize treasury operations.
5. Cryptographic adaptability — QCB can migrate to new algorithms if existing cryptography becomes vulnerable.
6. Network-wide security — post-quantum protections extend beyond wallets to validators and other critical authorization paths.
7. Open-standard ambitions — QSWIP can eventually provide reusable security specifications for other Chain Forge chains.

**Authentication flow:**
```
User opens QCB app → QR challenge displayed
  → User scans with QCB wallet on phone
  → Wallet signs challenge using ML-DSA
  → Service verifies signature → grants access
  (Private key never leaves device; QR expires after use)
```

**Privacy guarantee** (plain ML-DSA limitation noted): ordinary ML-DSA signatures do not automatically hide the signing public key. If a service must learn only that *a* valid identity authorized a request — without identifying *which* identity — a zero-knowledge credential layer is required. That is QCB-PM-001.

| Phase | Scope | Status |
|-------|-------|--------|
| A — Digital identity and authentication | ML-DSA wallet identity, temporary QR challenges, signature verification | ✅ Complete |
| B — Security hardening (DIS-001 Phase B) | Chain-ID binding in ML-DSA sigs, nonce/balance/gas enforcement, restart+replay persistence, 4-node finality | ✅ Complete |
| B-Privacy | Selective disclosure, service-specific pseudonyms, zero-knowledge authorization | 🔲 |
| C — Post-quantum credential storage | Encrypted credential storage using PQ key-establishment + authenticated encryption | 🔲 |
| D — Integration | Connect to QCB wallets, personhood, Charmed Agents, enterprise authorization, private multisig | 🔲 |
| E — Security testing | QR replay, phishing, session hijacking, key compromise, identity correlation, account recovery | 🔲 |

**DIS-001 Phase B — ✅ COMPLETE (2026-10-09):**
- **B4 — Chain-ID binding in ML-DSA signatures:** `verify_mldsa_authorization()` now hashes `SHA-256("chain-forge/pq-tx/v1\n" + chain_id + "\n" + body_json)` — identical construction in both `chain-forge-execution` verifier and `chain-forge-wallet` signer. Cross-chain replay is cryptographically impossible: a valid sig for `qcb-chain-A` cannot be accepted by `qcb-chain-B`. Wallet CLI gains `--chain-id` flag on `sign-tx` and `submit` (default: `qcb-testnet-1`).
- **B4 unit tests:** `b4_mldsa_correct_chain_id_accepted` + `b4_mldsa_wrong_chain_id_rejected` in `chain-forge-execution/src/lib.rs`; both use `require_signatures: true` executor and `MlDsaScheme.generate_keypair()` for deterministic keys. Both pass.
- **B1–B3, B5–B6 regression tests:** `scripts/phase1_dis001_phase_b_test.py` — B1 nonce enforcement (duplicate + future nonce rejected), B2 balance enforcement (overdraft rejected), B3 gas cap (zero + absurd gas_limit rejected), B5 malformed tx (garbled JSON + missing fields rejected), B6 Phase A regression (challenge → sign → verify → anti-replay cycle).
- **B7 — Restart + replay persistence test:** Test in Phase B script SIGKILLs Alice, restarts her from the same `--data-dir`, then replays the original tx (same nonce). The nonce is persisted in `state.json` (AccountState.nonce committed to disk on every block); the replay is rejected post-restart.
- **B8 — 4-node finality (Carol receives funds):** Phase B script sends uQCB to Carol's address (genesis wallet, no running node) and asserts Alice, Bob, and Dave all report the same updated Carol balance. `tests/devnet/run_4node_devnet.sh` also exercises true 4-node BFT consensus (Alice/Bob/Carol/Dave all running) and is available for extended finality verification.
- **Wallet test suite: 12/12 tests passing** after chain_id binding update.
- **Execution test suite: 76/76 non-pre-existing tests passing** (2 pre-existing escrow-settlement failures unrelated to Phase B).

**DIS-001 Phase A — ✅ COMPLETE (2026-10-09):**
- **`chain-forge-node/src/auth.rs`** (NEW): `AuthChallenge` with 60-second TTL and 32-char hex ID; `ChallengeStore` with anti-replay `consume()` and capacity eviction at 1024 pending challenges; `verify_challenge_signature()` verifies ML-DSA-65 over SHA-256(challenge_json) and derives `"qcb1pq…"` address from double-SHA-256 of public key.
- **`POST /api/auth/challenge`**: issues time-bounded challenge JSON; optional `scope` field (defaults to `"qcb-auth"`); challenge inserted into per-node `ChallengeStore`.
- **`POST /api/auth/verify`**: consumes challenge (atomic anti-replay), verifies ML-DSA-65 signature, returns `{"status":"verified","address":"qcb1pq…","scope":…}` or 400 rejected.
- **`chain-forge-wallet`: `sign_challenge()`** signs SHA-256(challenge_json) with ML-DSA-65 and returns `"mldsa65:<hex>"` tagged string; `qcb-wallet sign-challenge` CLI subcommand exposes it for scripting.
- **13 node auth tests + 2 wallet sign_challenge tests** — all 59 tests passing (47 node, 12 wallet).
- **`scripts/phase1_dis001_test.py`**: 5-scenario adversarial test (happy path, anti-replay, forged sig, wrong key, unknown challenge_id); run against live devnet.
- **Devnet verification (2026-10-09) — 12/12 checks passed:** Happy path: challenge issued, ML-DSA-65 signed, verified, `qcb1pq…` address derived ✓; Anti-replay: consumed challenge_id rejected on second use ✓; Forged signature: random 3309-byte payload rejected by ML-DSA verification ✓; Wrong key: Alice's signature rejected against Bob's public key ✓; Unknown challenge_id: fabricated ID not found in node store ✓.

**First wallet objective — QCB-WALLET-001 (Four-Node PQ Transaction Test):** Build a native Rust wallet that generates and securely stores an ML-DSA key pair; signs a QCB transaction locally; submits only the signed transaction through `/api/tx`; has its signature verified by the protocol; achieves finality across Alice, Bob, Carol, and Dave; and rejects forged, modified, or replayed transactions.

**QCB-WALLET-001 — ✅ COMPLETE (2026-10-09):**
- **Phase A (crate scaffold + ML-DSA keygen):** `chain-forge-wallet` crate created; `generate_wallet()` produces ML-DSA-65 (Dilithium3) key pairs via `pqcrypto-dilithium`; private keys encrypted at rest with AES-256-GCM(Argon2id); `sign_transaction()` signs SHA-256(tx_body_json); `SignedTxEnvelope` with `"mldsa65:<hex>"` scheme tag; 10 adversarial tests passing (forge, tamper, replay, wrong-passphrase, overwrite guard); `*.wallet.json` gitignored; `qcb-wallet` CLI binary for generate/address/info/sign-tx/submit.
- **Task #176 (protocol-side ML-DSA verification):** `chain-forge-execution` extended with `pq_signatures: Vec<String>` + `pq_public_key: Vec<u8>` fields (both `#[serde(default)]` for backward compat); `verify_mldsa_authorization()` verifies ML-DSA-65 over SHA-256(tx_body_json); `bind_key_if_unbound()` stores 1952-byte ML-DSA-65 public key in `AccountState.public_key` on first verified PQ tx; address namespace `"qcb1pq"` avoids collision with Ed25519 `"qcb1"` addresses; 74/74 execution tests still passing.
- **Devnet test (Task #176 finality proof):** `scripts/phase1_wallet_test.py` — four scenarios: happy path accepted, forged sig rejected, tampered body rejected, replay rejected; propagation check across Bob/Dave; ephemeral wallet in `/tmp` (no key material in repo).

**Prerequisite:** QCB-CS-001 complete (defines the underlying migration architecture that the wallet must be built on).

> **QSWIP-001 — Open Post-Quantum Wallet Identity Protocol**: Long-term open standard so other Chain Forge blockchains can reuse QCB's wallet identity and authentication infrastructure. Proposed; timing deferred until Phase B–D of QCB-DIS-001 is battle-tested.

#### QCB-PM-001 — Private Post-Quantum Threshold Authorization

*Goal: Allow QCB identity holders to prove they are authorized — without revealing which identity they hold — using zero-knowledge or threshold credential mechanisms.*

| Item | Status | Notes |
|---|---|---|
| ZK credential research | ❓ | Research milestone; no implementation commitment yet |
| Selective disclosure design | ❓ | What attributes a service may learn; what remains hidden |
| Service-specific pseudonyms | 🔲 | Different credential per service; unlinkable across services |
| Integration with QCB-DIS-001 Phase B | 🔲 | ZK layer added on top of Phase A authentication |

#### QCB-KR-001 — Post-Quantum Multisig Key Lifecycle

*Goal: Protect QCB accounts, multisig treasuries, and authorized signers with secure key rotation, revocation, and recovery — without ever accidentally locking legitimate owners out of their assets.*

Integrates with: `PersonhoodMultisig`, `SponsorID`, `AgentTreasury`, Enterprise Authorization Tree.

| Requirement | Status | Notes |
|---|---|---|
| Post-quantum multisig authorization | ⬜ | Multisig threshold signing using ML-DSA keys; quorum threshold configurable per account type |
| Configurable per-operation key rotation | ⬜ | Rotation policy settable per account: time-based, usage-count-based, or governance-triggered |
| Off-chain signature collection | ⬜ | Signers collect partial signatures off-chain; only the aggregated authorization hits the chain |
| Atomic key rotation and transaction execution | ⬜ | Rotate key and execute the protected operation in one atomic tx — no window where old key is revoked but new key isn't yet active |
| Old-key revocation and replay protection | ⬜ | Revoked keys produce `InvalidSignature` on any subsequent use; revocation committed to chain state |
| Secure recovery and emergency rotation | ⬜ | Social recovery (N-of-M guardians) + governance-assisted emergency rotation path for compromised accounts |
| Adversarial tests for failed rotations | ⬜ | Scenarios: rotation interrupted mid-flight, guardian collusion, replayed old-key tx, double-rotation race condition |

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
| **Native AMM (XRPL-style)** | ⬜ | On-chain AMM; **QRC is the only AMM-tradeable token** — QCB and uQCB explicitly excluded; QRC/BTC and QRC/stablecoin pools for external asset inflow; LP fee rewards for liquidity providers; Phase 2 |
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
| `seal_hash` field on `UsefulWorkReceipt` | ✅ | `seal_nonce: u64`, `seal_hash: String`, `seal_difficulty_bits: u32` added; `compute_seal_hash()`, `find_seal_nonce()`, `verify_seal()`, `meets_difficulty()` helpers implemented and tested; 6 tests passing |
| Seal difficulty target per challenge track | ⬜ | Governance-settable difficulty for each active Grand Challenge track; stored in challenge config; Phase 1 |
| Seal verification in receipt submission | ✅ | `SubmitUsefulWork` tx type calls `chain_forge_resource::verify_seal()` (single SHA256) at execution time; rejects invalid seals, trivial difficulty (< 8-bit absolute floor), duplicates, and wrong-owner submissions; 6 anti-farming guards enforced; 9 adversarial tests in `scripts/phase1_contribution_test.py` |
| Grand Challenge machine daemon (`gc-daemon`) | ✅ | `chain-forge-node/src/bin/gc-daemon.rs` — full 3-step cycle: hash preimage search → seal nonce search → `UsefulWorkReceipt` JSON; smoke-tested: GC-DEVNET-002 found nonce 80,468 + seal nonce 161 in <500ms; `cargo run --bin gc-daemon -- --dry-run` |
| SHA256 hardware compatibility documentation | ⬜ | Document that standard Bitcoin mining ASICs and GPUs can compute seal hashes; include benchmark: TH/s → expected seals/hour at target difficulty; Phase 1 |
| BTC miner onboarding guide | ⬜ | Step-by-step: install daemon, point at challenge, earn QRC alongside BTC mining; Phase 1 community milestone |
| Grand Challenge resource pool mode | ⬜ | Pool operator mode: pool collects `UsefulWorkReceipt`s from member machines, aggregates $QRC earnings, distributes to members by hash-rate contribution share; Phase 2 |
| **Challenge QRC reward pool** | ⬜ | Sponsors deposit QRC into a named challenge track's reward pool; funds three destinations: verifier rewards, discovery bonus pool, priority queue weight; on-chain deposit tx; Phase 2 |
| **Verifier QRC rewards** | ⬜ | Independent verifier machines earn QRC from the challenge's reward pool for confirmed `UsefulWorkReceipt` verification; separate from machine uQCB accumulation; Phase 2 |
| **Discovery bonus pool (QRC)** | ⬜ | QRC bonus released to machine whose slice produces a confirmed breakthrough; paid on top of uQCB accumulation; lottery-style outcome, not guaranteed; Phase 2 |
| **Priority queue weighting by QRC** | ⬜ | Challenge tracks with higher QRC pool balance attract more machines via priority routing; QRC as demand signal directing compute supply; Phase 2 |
| **Private commission tracks** | ⬜ | Any individual or company deposits QRC to open a named private challenge track; same machine assignment, receipt format, and verification flow as public tracks; result returned as hash-committed, independently-verified on-chain proof; Phase 2 |
| **Public vs. private track distinction on-chain** | ⬜ | `ChallengeKind { Public, Private }` flag on challenge config; public tracks governance-activated from treasury; private tracks sponsor-funded via QRC deposit tx; Phase 2 |
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
| GC-DEVNET-002 | 2026-10-07 | Hash preimage via `gc-daemon` binary (Rust) + seal hash | MACH-CAROL-003 (simulated) | Nonce `80,468` → `0000ce63...`; seal nonce `161`; `verify_seal` ✓; full `UsefulWorkReceipt` JSON produced | `gc-daemon --dry-run --seal-difficulty 8` |

> **What GC-DEVNET-001 proved**: Three parallel machines (Alice, Bob, Carol) searched independent nonce ranges. Carol found the solution in 15,361 checks (0.04s). Dave independently reproduced the hash from the nonce alone and signed the verification. Full `UsefulWorkReceipt` with `work_type: ResearchContribution`, machine signature, and verifier signature produced. The coordination and verification logic is complete — only the Rust crate and Ed25519 signing remain to wire to the real devnet.

**Next simulations planned:**
- GC-DEVNET-003 — Multi-track parallel (two challenges running simultaneously)
- GC-DEVNET-004 — Disputed result + rejection flow
- GC-DEVNET-005 — Physics-flavored: tiny lattice simulation with verified output hash

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

10. ~~**Explorer persistence deployment**~~ **✅ DONE** — `scripts/write_explorer_persistence.py` + `scripts/start-explorer-persistence.sh` ready to deploy on Machine 1.

### Phase 1 prep (after Phase 0 acceptance test passes)

11. **Personhood-weighting overlay** — per-human validator influence cap on `TendermintEngine`, using `ValidatorInfo.pop_verified` already in the registry.

12. **AI red-team Agent 1 (Phase A–D attestation guard bypass)** — strategy-search agent for adversarial attestation guard bypass attempts. Backlogged from prior session.

13. ~~**`seal_hash` field on `UsefulWorkReceipt`**~~ **✅ DONE** — `seal_nonce`, `seal_hash`, `seal_difficulty_bits` fields live in `chain-forge-resource`; `find_seal_nonce()`, `verify_seal()` helpers; 6 tests passing.

14. ~~**Grand Challenge machine daemon skeleton**~~ **✅ DONE** — `cargo run --bin gc-daemon -- --machine MACH-CAROL-003 --dry-run`; full 3-step cycle proven end-to-end; GC-DEVNET-002 logged.

### Next up (Phase 0 cross-machine foundation)

15. **Wire `/api/gc-receipt` endpoint** — add handler in `chain-forge-node/src/api.rs` to receive `UsefulWorkReceipt` JSON POSTs from `gc-daemon`; store in `ExplorerState`; expose via `/api/gc-receipts`.

16. ~~**QRC escrow primitives**~~ **✅ DONE** — `LockQrcForJob`, `ReleaseQrcForJob`, `RefundQrcForJob` wired as tx types in `chain-forge-execution` and `chain-forge-resource`; `tx_type_label()` exhaustive match updated; `RefundReason` enum (`Timeout`, `ExecutionFailure`, `VerificationFailed`, `DisputeResolution`, `CancelledBeforeStart`); all escrow types serialize/deserialize clean; build is green.

17. ~~**`AgentTreasury` + spending limits**~~ **✅ DONE** — `DepositToTreasury` tx type live; `treasury:{agent_id}` virtual account credited on deposit; `LockQrcForJob` does treasury-first funding (falls back to agent wallet); `per_job_limit_uqrc` field on `SpendingLimits` (`#[serde(default)]` for backwards compat); `check_per_job()` enforces cap at execution; `SpendingLimits::resource_agent()` preset added; `AgentStore::get_mut_by_id/address()` mutable accessors added; 74 tests passing.

18. ~~**Phase 0 cross-machine purchase acceptance test script**~~ **✅ DONE** — `scripts/phase0_acceptance_test.py`; submits all 5 txs (QrcPurchase → RegisterAgent → AuthorizeAgent → DepositToTreasury → LockQrcForJob) to Alice's node; waits for propagation; polls all 4 nodes (Alice/Bob/Dave/Carol) for tx commitment + treasury/escrow balance assertions; per-node PASS/FAIL output; `--skip-carol` flag for single-machine runs.

19. ~~**Phase 0 happy-path acceptance test — PASSING**~~ **✅ DONE** — Run ID `ad255b9f`; OVERALL PASS on Alice, Bob, Dave (8/8 checks each, height=17); Alice uQRC=5,000,000; treasury=4,200,000 (5M deposit − 800K lock); all 5 txs committed and replicated across all 3 nodes.

20. ~~**Phase 0b negative-path tests — N1 PASSING**~~ **✅ DONE** — N1 (over-cap lock: 1,000,001 > per_job_limit 1,000,000) hard-fails correctly at execution layer; treasury balance verified unchanged at 5,000,000 uQRC after rejection.

21. ~~**Phase 0b N2 — duplicate escrow_id guard**~~ **✅ DONE** — Run ID `b16e3bd6`; duplicate `escrow_id` now hard-fails at execution layer (`LockQrcForJob: escrow_id 'esc-…' already exists`); treasury balance verified unchanged at 5,000,000 uQRC after rejection; escrow account is now written to state on lock so `escrow:{id}` is queryable — Step 7 escrow check promoted from soft-skip ⚠ to hard assertion ✓ (9/9 checks per node); N1 + N2 + happy-path all PASS.

22. **`ReleaseQrcForJob` + `RefundQrcForJob` happy-path tests** ✅ **DONE — three-node devnet verified (2026-10-08/09)** — Run `20eee23f` (initial), `24963a9f` (final): 10 transactions checked on Alice, Bob, Dave. Release debited escrow and credited provider; refund restored original treasury; repeated full payouts rejected without balance changes. `scripts/phase0_settlement_test.py` committed. Provider balance assertions now use relative baseline (persistent `qcb1carol` wallet accumulates across runs). Carol node validation remains item 23; scientific receipt verification is separate.

23. **4-node test with Dave (Machine 2)** ✅ **DONE — cross-machine 4-node devnet verified (2026-10-09)** — Machine 1 (192.168.137.2): Alice :26656, Bob :26657, Carol :26658. Machine 2 (192.168.137.3): Dave :26659. Dave synced from genesis, reached height 111+, `precommit_count=3` (BFT quorum of 4). Full N3/N4/N5 negative release test suite passed on 4-node chain. `genesis-4node.json` committed with all 4 classical-ed25519 validator keys.

24. **`ReleaseQrcForJob` negative-path tests** ✅ **DONE — three-node devnet verified (2026-10-09)** — N3/N4/N5 guards all enforced. Happy path + 3 adversarial cases passed on Alice/Bob/Carol devnet. `scripts/phase0_negative_release_test.py` committed. Escrow role encodes authorized coordinator (`escrow:authorized={sender}`); wrong sender, over-amount, and ghost escrow all correctly rejected.

25. **`RefundQrcForJob` negative-path tests** ✅ **DONE — three-node devnet verified (2026-10-09)** — N6/N7/N8/N9 guards all enforced. Happy path (lock + refund) + 4 adversarial cases passed on Alice/Bob/Carol devnet. `scripts/phase0_negative_refund_test.py` committed. Guards: N6 non-existent escrow, N7 wrong sender (attacker nonce 0 ≠ chain nonce, coordinator tier gate), N8 over-amount refund, N9 double-settlement after release. `RefundReason` enum fix: `"Timeout"` (not `"JobTimeout"`). Live nonce sync (`sync_nonce()`) added before each test case to prevent nonce-mismatch masking guard failures.

26. ~~**PoCD epoch reward distribution bug fix + end-to-end devnet verification**~~ ✅ **DONE (2026-10-09)** — Commit `daf642b` (`chain-forge-execution/src/lib.rs`): renamed `epoch_close_succeeded → epoch_close_seen`; rewards now fire on *presence* of `EpochClose` tx unconditionally (no longer gated on QRC `close_epoch()` result). All three PoCD miners (alice/bob/dave) via `scripts/pocd_miner.py` confirmed running clean on Windows devnet (`failed=0`, ~3.6 kH/s each). At block 720 boundary: `rewarded_receipts: 8,586`, `pending_receipts: 0`. `qcb1devminer-alice` earned `719,996,202 uQCB`; `treasury:pocd` debited by exact same amount from 50,000,000,000 → 49,280,003,798 uQCB. **uQCB** (not QRC) accumulates toward QCB at 1,000,000 uQCB = 1 QCB.

27. **Windows devnet process management** ✅ **DONE (2026-10-09)** — Established pattern: nodes run as foreground VS Code terminals; kill with PowerShell (not Git Bash) `Get-Process chain-forge-node | Stop-Process -Force` directly. Git Bash mangling of `$_` → `\_` in `powershell -Command "..."` confirmed as footgun; always open PowerShell directly for `Get-Process`/`Stop-Process`. Build lock (`Access is denied, os error 5`) clears after killing all node processes.

---

## Phase 0d — Proof of Cryptographic Discovery (PoCD) Scaffold

**Goal**: Build the reusable `chain-forge-pocd` crate so any blockchain created with Chain Forge can opt into PoCD mining.  QCB Chain will be the first integrator.

**Design principle**: The crate is fully chain-agnostic — no QRC, uQRC, or QCB hardcoding.  Chains wire in their own `RewardPolicy` implementation and `PoCDConfig`.

### PoCD Crate (`chain-forge-pocd`)

| Item | Status | Notes |
|------|--------|-------|
| `Cargo.toml` + workspace member | ✅ **DONE** | Added to `chain-forge-engine` workspace |
| `PoCDConfig` struct | ✅ **DONE** | `enabled`, `chain_id`, `challenge_tracks`, `reward_epoch_blocks`, `require_verified_identity`, `min_seal_difficulty_bits` |
| `ChallengeTrack` enum + `ChallengeStatus` | ✅ **DONE** | `Cryptography`, `Privacy`, `ComputationalEfficiency`, `Mathematics`, `PhysicsAndOpenScience`, `AiAssistedDiscovery`, `Custom(String)` |
| `DiscoveryChallenge` struct | ✅ **DONE** | ID format `{chain_id}::{track}::{slug}`; cross-chain replay guard embedded in challenge_id |
| `DiscoveryProof` struct + seal functions | ✅ **DONE** | `compute_seal_hash`, `find_seal_nonce`, `meets_difficulty`, `verify_seal` — Bitcoin-compatible SHA256 mining loop |
| `DiscoveryReceipt` struct | ✅ **DONE** | Dual cross-chain guard: `chain_id` field + challenge_id prefix; `is_for_chain()` enforces both; `reward_distributed` flag prevents double-payment |
| `PoCDError` enum | ✅ **DONE** | Full error taxonomy: seal, challenge, cross-chain, identity, registry, reward, track |
| `DiscoveryRegistry` | ✅ **DONE** | In-memory ledger: active challenges, accepted receipts, proof deduplication, `pending_reward_receipts(from, to)` for epoch boundary |
| `RewardPolicy` trait | ✅ **DONE** | `compute_rewards(&[&DiscoveryReceipt]) -> Vec<RewardGrant>`; `NullRewardPolicy` and `FlatRewardPolicy` provided |
| `DiscoveryWorker` trait | ✅ **DONE** | `run_challenge` + `sign`; `build_proof` helper finds seal nonce and packages `DiscoveryProof` |
| `DiscoveryVerifier` trait | ✅ **DONE** | `verify_result` (domain-specific) + `verify_identity` (optional); `build_receipt` helper |
| `cargo build -p chain-forge-pocd` passes | ✅ **DONE (2026-10-08)** | Clean compile, zero warnings |

### QCB PoCD Integration (next phase)

| Item | Status | Notes |
|------|--------|-------|
| `QcbRewardPolicy` in `chain-forge-qrc` | ✅ | Pays rewards in uQRC; implements `RewardPolicy` trait; difficulty + track multipliers; pro-rata epoch pool cap; full test suite |
| Wire `PoCDConfig` into QCB genesis | ✅ | `genesis.pocd: Option<serde_json::Value>` in `chain-forge-core`; node parses at startup into `PoCDConfig`; `pocd_registry` Arc<Mutex> wired through to API |
| PoCD API endpoints | ✅ | `GET /api/pocd/challenges`, `GET /api/pocd/receipts`, `POST /api/pocd/submit`; self-verifies seal in Phase 0; no external verifier sig required |
| First live PoCD mining round on devnet | ✅ | `scripts/phase0_pocd_test.py` — mines 4-bit seal, submits proof, verifies receipt; runs against live devnet |
| `QcbVerifier` adapter | ⬜ | Wraps identity layer + `chain-forge-resource` scientific receipt; Phase 1 |
| Wire `QcbRewardPolicy` into epoch processing | ✅ | `EpochClose` handler scans `gc_receipt:*` state for unawarded receipts, converts to `DiscoveryReceipt`, calls `QcbRewardPolicy::compute_rewards()`, debits `treasury:pocd`, credits each machine wallet; `gc_reward_paid` sentinel prevents double-payment; non-fatal failure path retries next epoch |
| **PoCD epoch reward distribution — end-to-end verified on Windows devnet (2026-10-09)** | ✅ | **Bug fix (commit `daf642b`)**: `epoch_close_seen` renamed from `epoch_close_succeeded`; PoCD rewards now fire on *presence* of `EpochClose` tx in block — decoupled from QRC `close_epoch()` success/failure. At block 720 epoch boundary: `rewarded_receipts: 8,586`, `pending_receipts: 0`. Miner wallet `qcb1devminer-alice` balance: `719,996,202 uQCB`. `treasury:pocd` debited from 50,000,000,000 → 49,280,003,798 uQCB (exact match — no double-payment, no leak). **uQCB accumulates toward QCB at 1,000,000 uQCB = 1 QCB**; miners earn uQCB, not QRC. |
| **`scripts/pocd_miner.py` — PoCD mining client confirmed (2026-10-09)** | ✅ | Python 3.8+ stdlib-only script; `--node alice/bob/dave` targets ports 8080/8081/8082; `HASH_BATCH=4096`, `MAX_SEAL_ATTEMPTS=1,000,000`, `POLL_INTERVAL=15s`; polls `/api/pocd/challenges`, mines SHA256 seals, submits proofs via `/api/pocd/submit`; 3 miners (alice/bob/dave) run clean, `failed=0`, proven hashrate ~3.6 kH/s per miner; >44,000 proofs submitted across the session |
| Migrate `chain-forge-resource` seal functions to delegate to `chain-forge-pocd` | ⬜ | Remove duplication; `UsefulWorkReceipt` becomes a wrapper |

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
