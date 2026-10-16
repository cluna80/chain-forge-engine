# QATTICE | WHITEPAPER

**Editorial edition — 16 October 2026**

Brand and terminology: Qattice is the ecosystem and Layer-1 network; QCB ($QCB) is the native asset; Chain Forge is the Rust engine. Historical code identifiers, account denominations, transaction types, and citations retain their original spellings.

Editorial status (16 October 2026): reported devnet functionality is not production validation. Qattice has 210,000,000 QCB minted at genesis and no PoCD minting. Verified Grand Challenge work earns Pending uQCB, redeemable for existing QCB from the funded research treasury. No protocol-level resource marketplace, resource-consumption fee, or burn is active.

Editorial integrity: This edition retains Qattice consensus, identity, scientific discovery, Charmed Agents, Chain Forge, and security discussions and historical test context while removing the proposed native resource marketplace and its five-control architecture.

**MONETARY POLICY — AUTHORITATIVE OCTOBER 2026:** Qattice has a fixed genesis allocation of 210,000,000 QCB; no PoCD minting. Verified Grand Challenge work earns non-transferable Pending uQCB bound to MachineID. Every 1,000,000 Pending uQCB redeemed transfers 1 QCB from the funded research treasury to the registered beneficiary; remainders carry forward. QCB is used for staking, gas, governance, and supported on-chain settlement. There is no protocol-level resource marketplace, demurrage, or consumption burn.

---

## Qattice — A Sovereign Layer-1 for Charm-Based Agent Economies and Verifiable Scientific Discovery

*Money engineered to move. Agents engineered to work. Built from the ground up, owned by no one else's framework.*

---

## Abstract

Qattice is a sovereign Layer-1 blockchain built on Chain Forge, a from-scratch Rust blockchain engine. It proposes personhood-weighted Byzantine Fault Tolerant consensus and native identity, Charm Confinement, Intrinsic Charm, and Charmed Agent capabilities. Grand Challenge research coordinates machine contributions, verification receipts, and treasury-funded Pending uQCB redemption. Qattice does not define a native resource marketplace.

Qattice does not derive its consensus, its state machine, or its core modules from any other chain's codebase. In this, it follows the lineage of Bitcoin and XRP Ledger — chains with their own original designs — while making a deliberate departure from both: consensus power tied to verified human identity rather than computational work or capital. The chain is self-contained by design: no bridges, no wrapped assets, no interoperability that could allow unverified actors into the system.

The Grand Challenge system remains subject to staged validation, especially identity, verifier independence, and actual computational reproduction. Qattice uses a fixed 210,000,000 QCB genesis supply; research rewards redeem treasury-held QCB rather than minting new tokens.

A note on dependency chains: the sections that follow trace a sequence of dependencies, each of which has its own precondition. Identity depends on sybil resistance. Sybil resistance depends on live-challenge ceremonies not being defeated by well-resourced bots. Grand Challenge throughput depends on the network reaching meaningful scale. Each dependency is real and is named where it arises. The staged pilots described in Section 4 are designed to determine whether these dependencies resolve into solvable engineering and legal decisions, or whether some of them represent constraints the system cannot satisfy under its own stated principles. The document does not claim to know which outcome will prevail — only that the honest path is to name the chain and test it.

---

## Vision: A Trustworthy Distributed Supercomputer for Humanity

Distributed compute networks are not new. SETI@home pointed millions of machines at a single problem. Folding@home applied crowd-sourced cycles to protein simulation. Both produced real results. Both shared a fundamental limitation: a central organization decided the problem, collected the output, and published what it chose. Participants had no verifiable record of what their machine did, no accountability for results, and no say in what happened next.

Qattice's Grand Challenge architecture is a different thing entirely.

Every machine on Qattice is a first-class citizen on-chain — attested by a MachineID, with every ResourceExecutionReceipt cryptographically signed and hash-committed before any result is accepted. You cannot fake a discovery. You cannot claim credit for work you did not do. The network does not just solve a problem — it proves it solved it, in a form any independent machine can verify, on a ledger no single party controls.

Discoveries pass through human review gates before any reward is issued or any acceptance is recorded. The Proof of Useful Discovery requirement — independent verifier reproduction, domain-expert quorum ratification — means the network cannot be gamed by volume. Every accepted result is something humans examined and confirmed.

And the hard safety boundary is architectural, not policy: discoveries never automatically change Qattice protocol behavior. The network could produce a result that rewrites a field of mathematics and it would still require a full governance vote before a single protocol parameter moved.

This design points at the hardest open problems in science — not because they are tractable today, but because they will become tractable as the network grows:

- Lattice QCD simulations that model quark-gluon behavior at precisions classical hardware cannot sustain
- Many-body quantum systems where the interaction space grows faster than any single machine can track
- Cosmological structure formation models that require more simulation fidelity than any national facility can provide
- Dark matter and dark energy candidate modeling at scales that rule out whole classes of theory
- Quantum gravity approximations that require sustained, verified compute across thousands of parallel runs

None of these are unsolved because physicists are not smart enough. They are unsolved because the verified, coordinated compute does not exist yet. Qattice is building it — not as a product, but as a protocol-layer public good that belongs to no one organization and can be governed away from no one's control.

---

## The Name Is the Mission

Qattice draws its identity from the lattice: a mathematical structure used across cryptography, physics, and computational science. The name signals a network of independently operated machines coordinating verifiable research, not a claim to reproduce a physical particle collider.

- **Quark** — a reference to the frontier of particle physics.
- **Charm** — both a quark flavor and the name of Qattice's authorization-scoped agent concepts.
- **Bit** — the digital foundation of computation.

Together these explain the historical token name QuarkCharmBit (QCB); the blockchain and ecosystem are named Qattice. QCB remains the native token.

---

## What's Been Built: Phase 0 Status (October 2026)

> **For full engineering detail, test results, and change-set logs, see the Technical Appendix.**

Chain Forge has crossed its first major milestone. The following capabilities are confirmed working on a live, adversarially-tested devnet as of October 2026:

**Consensus engine.** A 4-node Tendermint-style BFT testnet is producing and committing blocks. All three planned consensus variants — Tendermint-style, HotStuff-style (17 tests), and XRPL-inspired FBA (18 tests) — are implemented and passing, confirming the pluggable architecture. A deliberate 5-second TCP-level partition test showed the 3-of-4 quorum continued block production throughout; the partitioned node synced in under 2 seconds on heal with no manual intervention.

**Slashing and safety.** Liveness slashing (>20% missed blocks triggers jail + slash), equivocation detection, forged vote rejection, and adversarial libp2p gossip tests all pass on the live devnet.

**Post-quantum cryptography.** ML-DSA-65 (CRYSTALS-Dilithium3 / NIST FIPS 204) is the validator signing scheme. The native Rust wallet generates and stores ML-DSA keypairs encrypted at rest; signs transactions locally; submits only signed transactions to the node. 10/10 adversarial wallet tests pass (forged signature, tampered body, nonce replay, wrong key all rejected).

**Digital Identity Stone — Phase A and B.** Challenge-response authentication is live: a 60-second single-use QR challenge is issued by the node; the wallet signs it locally with ML-DSA-65; the node verifies and grants access. The private key never leaves the device. Chain-ID binding prevents cross-chain replay. All 25 Phase B security regression checks pass.

**Grand Challenge pipeline.** The full earn path is live: RegisterMachine → SubmitUsefulWork → epoch-close → uQCB distribution. Six anti-farming guards enforce at execution time. Three independent miners ran concurrently on the devnet; at the block 720 epoch boundary all three received separate per-wallet uQCB credits totalling 8,586 rewarded receipts with zero double-payment. The research treasury debit matched wallet credits exactly.

**Grand Challenge daemon.** The gc-daemon binary completes the full 3-step cycle — research computation, seal hash search, UsefulWorkReceipt submission — confirmed in under 500ms on a dry-run test (GC-DEVNET-002).

**Escrow and settlement.** LockQrcForJob, ReleaseQrcForJob, and RefundQrcForJob are wired and adversarially tested. (Note: these are legacy tx type names; all amounts execute in uQCB. See QRC Layer retirement note in the Technical Appendix.) Over-cap locks, duplicate escrow IDs, wrong-sender releases, over-amount releases, ghost escrow IDs, and double-settlement attempts all reject correctly. Cross-machine 4-node devnet (two physical machines) confirmed BFT quorum and settlement.

**PoCD scheduler, miner, and verifier.** A standalone qcb-scheduler crate handles task lease assignment with two-phase cascade enforcement (a single machine cannot earn both phase-1 and phase-2 rewards for the same task). The standalone qcb-miner binary runs without any compile-time dependency on other chain-forge crates. The qcb-verifier signs accepted results with ML-DSA-65; quorum-based acceptance with per-verifier rate limiting is in place. 9/9 PoCD devnet acceptance tests pass.

**P2P gossip.** PoCD proof gossip ensures all nodes converge to the same proof pool before epoch boundaries. Capacity advertisement (CapacityAd gossip topic) gives the scheduler live peer load data for task assignment.

**Attestation guard.** On-chain sybil-resistance layer implemented through Phase D: quadratic-cost cap on attestations, revocation with cost, sybil confirmation with contribution-score penalty, and coordinator-gated reversal. 65 tests passing.

---

## First Simulation — GC-DEVNET-001 (2026-10-06)

In an early coordination simulation, the Grand Challenge discovery flow was simulated end-to-end. Three machines — Alice, Bob, Carol — searched parallel nonce ranges for a SHA256 hash of 'QCB:' beginning with '0000'. Carol found nonce 6,682,026 in 15,361 checks. Dave independently reproduced the hash from the nonce alone and signed the verification. A full UsefulWorkReceipt with work_type ResearchContribution, machine signature, and verifier signature was produced and saved on-chain to the repository.

This simulation demonstrated a limited coordination and hash-recheck workflow, not proof of useful scientific computation or production readiness.

---

## Useful Hash Commitments: Bitcoin's Energy, Pointed at Science

> **Technical assurance boundary** — A difficulty-targeted SHA-256 seal demonstrates that a commitment was computed for an identified output hash; it does not prove that the scientific workload was executed correctly or that a discovery occurred. Verification must separately authenticate verifier signatures, enforce independence constraints, reproduce the track-specific computation, and, where discovery is claimed, obtain qualified domain-expert review.

When a machine completes a Grand Challenge contribution, it commits to a reported output by finding a nonce such that:

`seal_hash = SHA256(nonce || output_hash || challenge_id)`

begins with a target number of zero bits. This is structurally identical to Bitcoin's mining loop. The same ASIC that finds a Bitcoin block can find a seal hash. The difference is what the hash seals: not an empty block header, but a scientific output. A verifier re-hashes once, checks the difficulty prefix, then performs domain verification of the output itself.

> **Randomness beacon limitations.** Qattice proposes using recent Bitcoin block hashes as a tamper-resistant job-assignment beacon: `job_seed = SHA256(btc_block_hash || challenge_id || machine_id)`. Miner influence, withholding/grinding, and reorganizations are acknowledged. Confirmation depth, fixed reference rules, and fallback behavior remain open design decisions.

---

## Why This Opens the Bitcoin Ecosystem

Solo Bitcoin miners and small farms are structurally underserved by pool consolidation. Qattice's Grand Challenge daemon changes that equation: a miner points existing SHA256 hardware at a Grand Challenge job, does real science, and earns Pending uQCB accumulating toward whole-QCB treasury redemption — on top of whatever BTC mining it was already doing. The two are not in competition.

The audiences this reaches: solo miners and small farms earning a second income stream on existing hardware; BOINC veterans who understand the model and now get cryptographic accountability and economic reward; pool operators running Grand Challenge pool mode; and the Bitcoin philosophy crowd who believe computational work should produce something real.

---

## uQCB Accumulation and the Path to Full QCB

Verified Grand Challenge work earns Pending uQCB: a machine-bound, non-transferable research-credit balance. Eligible whole-unit redemptions transfer existing QCB from the research treasury — never minting new supply.

**1,000,000 uQCB = 1 QCB** (fixed at the protocol level; not governance-adjustable).

Treasury redemption is operator-initiated and requires no discretionary governance approval. At 100,000 machines all accumulating uQCB, no approval process survives. The pending balance reaches at least 1,000,000 uQCB; the operator redeems: `redeemed_QCB = floor(pending_uQCB / 1,000,000)`, carrying any remainder forward. Redemption fails atomically if the treasury is insufficient — credits remain intact.

Pending uQCB is bound to the earning MachineID and cannot be traded, sold, or transferred. Non-transferability means the only path from uQCB to QCB is the one who earned it. The work and the reward stay with the same entity.

> **Verifier assurance model.** Layer 1: an authenticated verifier key signs a statement about a specific task. Layer 2: verifier registry and independence-group checks limit duplicate control. Layer 3: the verifier actually recomputes the track-specific result against a deterministic reference procedure. Layer 4: scientific novelty requires qualified domain-expert review. A signed vote does not prove that layer 3 occurred.

---

## The Grand Challenge Economy

Qattice's economic architecture is built around a single flywheel:

- **Grand Challenge rewards loop** — Machine operators contribute verified computation and earn Pending uQCB. At 1,000,000 Pending uQCB, the operator redeems whole QCB from the funded research treasury. Pre-allocated QCB moves; no new supply is minted.

- **Staking loop** — QCB is staked by validators to secure consensus, earning staking yield from defined fee flows. Validator influence is bounded by personhood rather than stake size.

- **Application settlement loop** — QCB moves between accounts when Grand Challenge tracks are funded by external sponsors, when verifiers are paid, and when gas fees are settled. These flows create transactional demand without minting new supply.

The research flywheel: more eligible machines → greater research throughput → more independently checked results and public scientific value.

### $QCB as the Demand Signal Inside Grand Challenges

Any participant can fund a Grand Challenge track with $QCB. Deposited $QCB is allocated across three destinations: **verifier rewards** (independent machines confirming receipts earn $QCB directly from sponsors), **discovery bonus pool** (a predetermined QCB bonus released on confirmed breakthroughs), and **priority queue funding** (higher-funded tracks attract more machines — $QCB is the signal that turns scientific demand into compute supply).

### Public Tracks and Private Commissions

Public tracks are governance-activated problems of humanity-scale importance — lattice QCD simulations, protein folding campaigns, cosmological structure modeling. They are funded by the protocol treasury and open sponsors; results belong to the public record.

Private commissions allow any individual or institution to deposit $QCB into a named challenge track and receive results that come back hash-committed, independently verified, and chain-of-custody accountable from assigned slice to confirmed receipt. An auditor, regulator, or peer reviewer can validate the result from the on-chain receipt alone.

---

## Equilibrium State: When the Network Becomes Alive

Qattice defines Equilibrium State as the condition where the validator set is deep and geographically distributed enough to absorb any regional outage; the machine population is deep enough that every active Grand Challenge track has sufficient independent verifier coverage; the anti-farming defenses have been battle-tested under real adversarial load; and governance participation reflects the network's genuine human base.

Below equilibrium, the Grand Challenge is a research layer with limited throughput. Above equilibrium: multiple tracks run simultaneously with full verifier coverage; lattice QCD simulations and many-body quantum system modeling become tractable; the network becomes self-healing as machine churn is absorbed without disrupting ongoing research jobs.

Reaching Equilibrium State will take years. The architectural commitment is different from the timeline: QCB is designed for equilibrium from the first block. The MachineID registry, the ResourceExecutionReceipt accountability layer, the Grand Challenge tracks, and the hard safety boundary are load-bearing from day one.

---

## What Qattice Is

Qattice is a from-scratch Layer-1 blockchain, built on Chain Forge — a purpose-built Rust blockchain engine. It provides four things no general-purpose chain offers natively, together, at the protocol layer:

- **Personhood-weighted BFT consensus** — validator power tied to verified human identity, not stake or hashpower
- **Charm-based state confinement and agent representation** — identity-scoped state and native support for autonomous agents as first-class chain citizens
- **A working monetary engine** — $QCB is the sole protocol token; uQCB accumulates from verified Grand Challenge work and converts permissionlessly to $QCB at 1,000,000:1
- **Full sovereignty** — no dependency on another chain's consensus engine, module framework, or governance assumptions

### Why Build From Scratch

Frameworks like Cosmos SDK and Solana offer fast paths to a working chain, but both come with inherited assumptions QCB is not willing to accept: stake-weighted consensus power, framework dependency, no native identity layer, and shared infrastructure risk. Building on Chain Forge removes all four constraints. The cost is real — a multi-year infrastructure project — and sovereignty has a price beyond the calendar.

---

## Section 3: Consensus: Personhood-Weighted BFT

### 3.1 The Mechanism

Validator voting power is weighted by verified personhood, not stake. Each verified human can control a bounded amount of validator influence regardless of how much QCB they hold. This directly ties consensus security to the same identity primitive that governs Grand Challenge reward claims and governance votes.

> **Implementation status:** Tendermint-style BFT confirmed operational on a 4-node devnet. HotStuff-style and XRPL-inspired FBA variants also implemented and tested — all three share the same pluggable ConsensusEngine interface. Partition tolerance, liveness slashing, equivocation detection, and adversarial libp2p gossip tests all confirmed on the live devnet. Personhood-weighting overlay is the next Phase 1 milestone.

### 3.2 Why Not Proof of Work or Plain Proof of Stake

Proof of Work is energy-intensive and settlement-slow. Plain Proof of Stake concentrates consensus power with capital, which conflicts with Qattice's governance philosophy at the deepest layer of the system. Personhood-weighted BFT is the design that makes "one human, one vote" true from consensus up through governance.

### 3.3 Staking and Personhood Bounds

$QCB is the token staked to participate in consensus. Validators bond whole QCB to enter the active set. However, stake size alone does not determine validator influence: no single verified human may exercise more than a fixed cap of total validator power regardless of how much $QCB they stake. Stake determines participation and reward eligibility; personhood bounds determine actual influence.

The security of personhood-weighted BFT is bounded by the sybil resistance of the identity layer. If the identity layer can be gamed at scale, an attacker who controls many fraudulent identities can accumulate disproportionate validator power through the same mechanism intended to prevent that outcome.

---

## Section 4: Identity: Protocol-Level Proof-of-Personhood

Proof-of-personhood is wired into the protocol itself, through Charm Confinement and Intrinsic Charm. Qattice's current direction is a decentralized web-of-trust base layer, strengthened by live-challenge ceremonies as a sybil-resistance backstop. It avoids both government and corporate control, consistent with Qattice's sovereignty principle.

> **Implementation status:** The attestation guard mechanism — the on-chain sybil-resistance layer — is implemented through Phase D in chain-forge-identity and wired into the execution layer and node startup. 65 tests passing. This remains the single highest-risk open question in the entire system: every downstream mechanism depends on this layer holding up under real adversarial pressure. The pilot will run against provisional targets: sybil rate below 3%, per-verification cost below $5.

This remains the single highest-risk open question in the entire system: every downstream mechanism (Grand Challenge rewards, consensus weighting, governance, treasury funding) depends on this layer holding up under real adversarial pressure.

**Framing correction:** 3% sybil penetration should not be read as "safe" in isolation. The same 3% fraud rate that's negligible against consensus safety can dominate governance votes if legitimate turnout is low. The correct statement: 3% is the maximum adversarial identity rate the initial pilot is designed to tolerate, subject to the governance participation and BFT safety models in Sections 6.6 and 3.

### 4.5 The Identity Layer as Strategic Asset

Qattice offers four things no other chain offers, every one of which requires identity verification:

**Personhood-weighted consensus** — validator power bounded by verified human identity, not capital or compute.

**Grand Challenge research** — verified machine contributions earn Pending uQCB redeemable from the funded research treasury. This does not mint new QCB.

**Charmed Agents with bounded authorization** — autonomous agents sponsored by verified humans, with cryptographic scoping of their economic footprint.

**RWA issuance with protocol-level compliance** — tokenized real-world assets held by SponsorID-linked accounts, making KYC/AML compliance a property of the protocol rather than an external wrapper.

None of these capabilities can be replicated on another chain without changing that chain's fundamental architecture. That is what makes them a moat rather than a feature list.

**The coupling principle:** identity gates participation (Grand Challenge participation, consensus power, governance votes, Charmed Agent sponsorship, and Sponsored Contract deployment all require verified identity); and participation maintains identity (a liveness requirement to maintain active verification status closes the gap where identity becomes a free-standing credential other chains query without compensating Qattice).

**What this document does and does not claim:** the mechanism is real, the coupling is intentional, and the pilot will determine whether it holds. The identity is the door. Behind it is Qattice's own economy: the Grand Challenge rewards participants can earn, the agents they can run, the governance they can participate in, the assets they can issue with compliance built in.

---

## Digital Identity Stone (DIS) — Authentication Without Key Exposure

DIS is the authentication layer that sits on top of the identity layer. The identity layer is the door; DIS is the key — and a key that never leaves the holder's device.

**Authentication flow:** User opens Qattice application → challenge presented → User signs the challenge locally using ML-DSA-65 → Service verifies the signature → Service grants access. The private key never leaves the device; the challenge expires after use.

**What DIS guarantees:** key non-exposure; replay resistance (single-use, 60-second challenges); chain binding (cross-chain replay is cryptographically impossible); post-quantum authentication (ML-DSA-65 / NIST FIPS 204); nonce and balance enforcement.

**What DIS does not guarantee on its own:** unlinkability across services (that requires a zero-knowledge credential layer — QCB-PM-001, a research milestone); transport-layer privacy; device compromise protection beyond encrypted-at-rest storage.

> **Implementation status:** Phase A (ML-DSA-65 challenge/response authentication) and Phase B (chain-ID binding, nonce/balance/gas enforcement, restart+replay persistence, 4-node finality) are complete and adversarially tested. 25/25 Phase B regression checks pass. 5/5 adversarial Phase A scenarios pass on the live devnet. Phases B-Privacy, C, D, and E (unlinkable authorization, credential storage, integration, security testing) are pending.

---

## 4.6 Strategic Directions: Three Phases, One Mechanism

Everything in this section is contingent on the identity layer pilot hitting its targets.

**Phase A — RWA compliance (near-term, post-EVM).** RWA issuers need verified holders for regulatory compliance. Qattice's answer: every SponsorID-linked account is a verified human, and the verification is the protocol. The issuer does not build a KYC stack; the chain provides one. Success test: an RWA issuer uses Qattice's identity layer as their compliance layer instead of building or licensing a separate one.

**Phase B — Agent authorization (mid-term, post-AEI).** External agent frameworks need to verify which agents are authorized to act on behalf of which humans. An external system that accepts Qattice's SponsorID attestations as authorization gets the same property Qattice's own Charmed Agents have: a cryptographic guarantee that a verified human is accountable for the agent's actions.

**Phase C — General proof-of-personhood standard (long-term, post-Phase B).** Any system that needs to verify a user is human — spam prevention, governance, AI-interaction controls, content authentication — is a potential consumer of Qattice's identity layer. Phase C is only worth attempting if Phase B has demonstrated that external systems will integrate Qattice attestations.

These are not predictions. They are a testable sequence where each phase's success is a precondition for attempting the next.

---

## Section 5: Core Protocol Modules

Qattice defines native identity, Charm Confinement, Intrinsic Charm, and Charmed Agent capabilities. Grand Challenge research uses registered machines and verifiable receipts. A protocol-level resource marketplace is not part of the current design.

### 5.0 What "Charm" Means

"Charm" is Qattice's term for a bundle of protocol-enforced properties, including identity verification tier, scoped authorization, and permitted agent behavior. It does not imply demurrage exemptions.

### 5.1 Charm Confinement

Scoped state isolation at the protocol layer. Ensures identity-linked claims (such as Grand Challenge reward claim rights) and agent-controlled resources remain bound to their defined context — one verified identity, one reward claim per epoch, with no cross-context leakage.

### 5.2 Intrinsic Charm

Properties treated as inherent to identity-linked state and carried with that state subject to protocol authorization rules.

### 5.3 Charmed Agents

Protocol-level representations for autonomous agents operating under a verified human sponsor and explicit authorization. Proposed roles include scheduled operations, Grand Challenge participation, attestation, verification assistance, and other bounded tasks.

> **Scope note:** Charmed Agents are authorization-scoped entities. Their signatures, SponsorID bindings, and permitted capabilities require independent validation; the presence of an agent identity does not prove its work was performed.

Sponsored Contracts (Section 7.2) are a distinct subclass of Charmed Agent covering developer-deployed Solidity contracts with a verified human SponsorID. They are a Phase 5+ addition.

Two pieces of protocol infrastructure are not yet specified: an **Agent Service Registry** (on-chain directory of agent services and prices) and **payment primitives beyond a single transfer** (streaming or usage-metered payments for recurring and metered agent services).

### 5.4 Discovery Records

Every verified Grand Challenge contribution that qualifies as a discovery produces a permanent on-chain record alongside its reward. The record — defined in `chain-forge-pocd` and minted through the same verification path that produces the PoCD pipeline's `DiscoveryReceipt` — captures the challenge identifier, output hash, seal difficulty, verifier identities (MachineIDs and SponsorIDs), and timestamp. It is non-transferable, queryable by anyone (by MachineID or by SponsorID), and permanently bound to the discovering MachineID.

A Discovery Record is a badge, not a token: it cannot be sold, transferred, spent, or used as governance weight, and it confers no voting rights, priority access, future payment claim, or special status. It does not affect the Pending uQCB reward path, which remains the sole mechanism through which verified work earns treasury-funded QCB redemption. Discovery Records supplement attribution; they do not replace or extend the reward system.

A `DiscoveryReceipt` is ephemeral — it lives in the PoCD registry, gets converted into a reward at epoch close, and then fades. A Discovery Record is the permanent version of the same verification event: committed to chain state and queryable forever. Because the record attaches to the discovery event itself, it cannot be minted until the track-specific criteria that define a "discovery" are formalized through governance — the same dependency the discovery bonus reward already has. Until those criteria exist for at least one challenge track, there is no event for a Discovery Record to attach to.

Discovery Records are a chain-agnostic PoCD feature, not a QCB-specific addition: any chain built on Chain Forge that integrates PoCD can mint them with the same shape.

---

## Section 6: Token Economics

Qattice uses a single native tradeable asset, $QCB. Pending uQCB is a non-transferable machine-bound accounting balance for Grand Challenge research rewards, not a second currency.

### 6.1 Design Principle: One Native Tradeable Asset

| Asset | Purpose | Transferability |
|---|---|---|
| QCB | Staking, gas, governance, on-chain settlement | Transferable |
| Pending uQCB | Grand Challenge reward accounting before treasury redemption | Non-transferable, MachineID-bound |

No QCB is minted through research rewards, and no consumption-driven burn or demurrage applies to QCB balances.

### 6.2 $QCB — The Native Staking, Governance, and Settlement Asset

QCB is the network's native tradeable asset for validator staking, gas fees, governance, and authorized on-chain transfers. It is not a redeemable claim on network compute or storage capacity.

Validators bond whole QCB to enter the active validator set. Stake determines set membership; personhood cap limits influence within the set.

Verified Grand Challenge work earns non-transferable Pending uQCB bound to the registered MachineID. At each 1,000,000 Pending uQCB threshold, the registered beneficiary may redeem 1 QCB from the funded research treasury; remainders carry forward. Treasury insufficiency fails atomically without consuming pending credits. Redemption transfers existing genesis-allocated QCB; it never mints new supply. The maximum QCB supply is 210,000,000, minted at genesis.

### 6.3 $QCB Value Capture

**Supply.** The 210,000,000 QCB genesis allocation is the maximum supply. Grand Challenge redemption transfers pre-allocated QCB from the research treasury to the registered beneficiary. Staking locks balances without burning them.

> **Historical burn proposal — not active.** Earlier drafts described Burn-and-Mint Equilibrium (BME) for a resource economy. That proposal is not part of Qattice's current monetary mechanism and is retained here only as historical context.

**Potential utility drivers:** gas payments and authorized on-chain settlement (transactional demand); verified research work distributing existing treasury-held QCB; validators locking existing QCB via staking; QCB participation in governance. QCB's market value is uncertain and not guaranteed by any of these.

### 6.4 $QCB Value Flow

Grand Challenge participants perform verified work → accumulate Pending uQCB → redeem whole QCB from the funded research treasury. Validators stake QCB → existing QCB is locked and later unlocked. Authorized on-chain transfers and gas payments move existing QCB between accounts. These flows distribute or lock existing QCB; they do not depend on a native resource marketplace or active consumption burn.

### 6.5 Why a Single Native Asset

The former QRC resource-currency split has been removed. QCB remains the sole native tradeable asset; Pending uQCB is an accounting state rather than a token. A fixed supply does not by itself create demand or assure economic security. Qattice must separately demonstrate reliable consensus, identity safeguards, and sustainable validator incentives.

**Single-tradeable-asset rule.** QCB is the sole protocol-recognized tradeable asset; non-transferable internal records such as Pending uQCB, receipts, and reputation do not constitute additional currencies.

### 6.6 Governance

Governance covers validator eligibility, consensus and identity parameters, research-treasury policy, redemption rules, and constitutional amendments.

**Why one-human-one-vote needs a quorum floor:** attacker vote share modeled as f / (p + f), where f is the fraudulent-identity fraction and p is legitimate turnout. Solving for QCB's 3% fraud target: p > 3% for ordinary governance (majority-safety), p > 6% for supermajority/constitutional changes (blocking-safety).

QCB's governance enforces three protections: a **participation quorum** (floors at >3% and >6% as derived above); an **approval threshold** (simple majority for ordinary parameters, two-thirds for constitutional changes); and an **absolute minimum voter count** (a percentage-based quorum alone is insufficient at scale — the specific floor is an open question pending population data).

**Limits of this model:** the derivation assumes fraudulent identities act as a single coordinated bloc and that legitimate turnout is exogenous. A sophisticated attacker can suppress legitimate turnout directly — spamming proposals, inducing governance fatigue — without needing more fraudulent identities. The quorum floors protect against passive, uncoordinated fraud. Turnout suppression is a named open risk. See Open Question 17.

### 6.7 Distribution

| Allocation | Notes |
|---|---|
| Research treasury / Grand Challenge rewards | Existing genesis QCB funds verified work |
| Validators and network security | Existing supply and defined fee flows |
| Development and reserve | Subject to governance and disclosure |

Illustrative percentages are non-final; the genesis distribution must explicitly fund the research treasury and network operations without assuming resource-market demand, resource burns, or new QCB issuance.

### 6.8 Summary

| Asset | QCB | Pending uQCB |
|---|---|---|
| Purpose | Staking, gas, governance, settlement | Grand Challenge research credit |
| Supply | Fixed 210,000,000 minted at genesis | Machine-bound, redeemable from existing treasury |
| Tradeable | Yes | No |
| Demurrage | No | No |
| Redemption | Not applicable | 1,000,000 Pending uQCB redeems 1 QCB; remainder carried forward |

### 6.9 Long-Term Distribution

A locked release schedule is carved from the existing genesis allocation — 4% of total $QCB supply (8.4 million $QCB), released linearly over 8 years — to verified humans who stake or lock $QCB or accumulate qualifying Grand Challenge Pending uQCB redemptions. Nothing is created; existing, capped supply moves. The mechanism, duration, and proportional-share formula are governed through the protocol governance process (Section 6.6), not constitutionally.

### 6.10 FeeSponsor — Native Transaction Fee Sponsorship

FeeSponsor lets a verified developer, research institution, enterprise, or Charmed Agent pre-fund a sponsor account and pay the gas fee on a user's behalf, without taking custody of the user's funds or operation. It is a native fee-payer primitive, **not** a second token and not a protocol-level resource marketplace: a sponsored transaction still moves only existing QCB/uQCB, with no new minting and no change to PoCD rewards or BFT voting power.

**Dual authorization.** Every sponsored transaction carries two independent signatures: the user's own signature over their operation, unchanged from an ordinary transaction, and a separate `SponsorAuthorization` signed by the sponsor's ML-DSA key. The sponsor's signature is bound — via a domain-separated signing message — to the chain ID, the canonical hash of the user's unsigned transaction body, the authorization's own single-use ID, the sponsor's ID, the maximum fee the sponsor agreed to cover, and the block window in which the authorization is valid. Tampering with any one of those fields invalidates the signature; nothing is left implicitly trusted.

**No automatic fallback.** If a sponsor authorization is present but the sponsor cannot or will not pay — policy limit, expired or already-used authorization, insufficient sponsor balance, revocation — the transaction is rejected outright. It is never silently charged to the user's own wallet. A user who wants that fallback behavior must attach their own explicit, separately signed fallback authorization; nothing about sponsorship happens by default.

**Sponsor policy and single-use authorizations.** Each sponsor account carries a policy capping the maximum fee per transaction and a budget per epoch, and nodes track the sponsor's balance deterministically against both. Each authorization is single-use, identified by a random ID, and expires within a bounded window; once consumed or expired it cannot be replayed, and used IDs are pruned from state once they age past their expiry plus a fixed retention window, keeping the storage bound predictable. A sponsor can revoke service immediately, or retroactively invalidate every authorization issued up to a given point, without having to enumerate individual authorizations.

**Deterministic accounting.** Every node must reach the same decision about who pays and whether the transaction is accepted. Fee calculation, sponsor-authorization validation, and the fee debit itself happen deterministically before the transaction's own application logic runs, so that a transaction that fails after a valid sponsor debit still leaves every node in the same state. Full execution semantics, data types, and the acceptance-test suite are specified in `docs/FeeSponsor.md`.

> **Implementation status:** the cryptographic primitives (sponsor account/policy/authorization types, canonical hashing, and ML-DSA verification binding every authorized field) and a persistent sponsor store (balances, single-use replay tracking, revocation, per-tx and epoch policy enforcement) exist and are tested, but are not yet wired into live transaction execution or merged to the main branch. Native per-transaction fee debiting does not yet exist in the engine for ordinary (unsponsored) transactions either — that is the actual prerequisite this feature is waiting on, tracked in `ROADMAP.md`.

---

## Section 7: Sovereignty, Execution Environment, and the Constitutional Layer

### 7.1 The Sovereignty Constraint

Qattice is designed as a self-contained Layer-1. There are no bridges, no interoperability connections, and no wrapped assets in the initial architecture. Any bridge that would allow unverified actors to hold or use $QCB is architecturally forbidden. This constraint will be revisited only after the chain is live and stable, the identity layer has survived adversarial pressure at scale, and there is a concrete reason to interoperate.

### 7.2 Permissioned EVM Layer

Qattice absorbs EVM capability natively rather than bridging to an EVM-compatible chain. EVM contracts on QCB are Sponsored Contracts — a subclass of Charmed Agent. Every contract must have a SponsorID linking it to a verified human; every $QCB transfer in or out of an EVM contract passes through the protocol's identity checks; no EVM contract can issue tokens that bypass $QCB's sole-asset status.

The permissioned EVM is a Phase 5+ addition, dependent on the identity layer being proven at scale first.

**What it enables:** Solidity smart contracts sponsored by verified Charmed Agents; EVM-compatible wallets linked to verified identities; DeFi protocols under Qattice's identity and governance rules; RWA asset tokens issued and held under SponsorID.

**What it does not enable:** anonymous EVM accounts; contracts without a SponsorID; synthetic tokens substituting for $QCB; governance votes from EVM contracts; EVM-based bridges importing unverified actors.

**Currency issuance reserved to the protocol:** Sponsored Contracts can issue non-currency tokens (utility tokens, NFTs, community tokens) but cannot issue tokens designed to function as a medium of exchange. Only $QCB can access Qattice's economic plumbing.

### 7.3 The Constitutional Layer

What lives in the constitutional layer:

- **The identity primitive's replacement mechanism** — the guarantee that it can be replaced without forking the chain, losing state, or invalidating existing verified claims and Grand Challenge rewards history.
- **The cryptographic-primitive replacement mechanism** — the guarantee that the signature scheme can be replaced without forking the chain.
- **The single-tradeable-asset rule** — $QCB is the sole protocol tradeable asset; no application-layer token may substitute for $QCB in QCB's economic plumbing.
- **The sovereignty constraint** — no bridge allowing unverified actors into $QCB; no anonymous EVM accounts; no parallel resource token substituting for $QCB.
- **The amendment process itself.**

**Amendment process:** a constitutional change requires (a) a supermajority of verified-human votes (proposed at two-thirds or greater), (b) the >6% blocking-safety quorum from Section 6.6 plus the absolute-minimum-voter-count protection, and (c) a mandatory public waiting period. Exact thresholds remain an open question.

**Interface vs. implementation:** what is constitutional is the identity interface — the uniqueness guarantee per human, no single party able to unilaterally control verification, and a bounded disclosed verification cost. The current implementation is not itself constitutional and can evolve under ordinary governance so long as it continues to satisfy the interface.

### 7.4 Chain Forge — The Foundation Beneath Qattice

| Dimension | Chain Forge | Qattice |
|---|---|---|
| What it is | The engine — a Rust blockchain-building toolkit | The first chain built with that engine |
| Audience | Developers building their own sovereign chains | Verified humans, merchants, agent operators |
| Purpose | Infrastructure — makes sovereign, from-scratch chains possible | Flagship — proves the infrastructure works under real conditions |
| Lifespan | An ongoing engine, evolving with each chain built on it | Intended to outlast any single team or founder |

> **Implementation status:** All three BFT consensus variants implemented and tested (Tendermint-style, HotStuff-style, XRPL-inspired FBA), confirming the pluggable ConsensusEngine architecture. 4-node cross-machine consensus verified. Production-grade JMT state tree and personhood-weighting overlay are the remaining Phase 0→1 engine milestones. A dedicated Chain Forge whitepaper aimed at developers building their own chains is planned once the engine is closer to general release.

---

## Section 8: Merchant Integration — Deferred

Merchant acceptance, fiat conversion, and payment processing are deferred application-level possibilities, not active Qattice protocol capabilities. QCB utility in the current design is staking, gas, governance, funded Grand Challenge rewards, and authorized transfers.

---

## Section 9: Supporting Infrastructure

**9.1 React Explorer** — a web-based explorer for blocks, transactions, addresses, identity status, Charmed Agent activity, Grand Challenge receipts, Pending uQCB balances, and research-treasury status.

> **Implementation status:** REST API (/api/status, /api/blocks/, /api/txs/, /api/accounts/) live on every block commit. React frontend running. Explorer persistence scripts deployed.

**9.2 Python Agent OS Backend** — the runtime environment autonomous agents use to interact with QCB: agent lifecycle, decision logic, and chain interaction.

**9.3 Research Verification API** — proposed interface for submitting Grand Challenge work, checking task status, and retrieving verification receipts. Distinct from a commercial resource-job marketplace.

---

## Section 10: Post-Quantum Security

### 10.1 What's Actually at Risk

**Shor's algorithm** breaks elliptic-curve signatures completely — a direct threat to validator signing and account security. **Grover's algorithm** only provides a quadratic speedup against hash functions — still considered adequate at 256-bit output under current NIST guidance.

QCB's signature scheme is the actual exposure. Its hash functions are not.

### 10.2 The Specific Risk to a Personhood-Weighted Chain

If validator signatures are forgeable, the personhood-weighting that bounds Sybil influence becomes irrelevant — an attacker who can forge signatures bypasses the identity layer entirely. Additionally, once an account signs a transaction, its public key is visible on-chain and is a standing target for a future CRQC. For a chain designed to still be functioning long after its founders are no longer involved, a multi-decade CRQC risk window is within the design horizon.

### 10.3 Mitigation: Crypto-Agility as a Constitutional Guarantee

The fix is not simply "use a post-quantum signature algorithm" — algorithm choice alone doesn't survive the next cryptographic break. Section 7.3's interface/implementation split applies here too: what is constitutional is the guarantee that the signature scheme can be replaced without forking the chain, not any specific algorithm.

> **Implementation status:** ML-DSA-65 (CRYSTALS-Dilithium3 / NIST FIPS 204) is already live as the validator signing scheme and the wallet signing scheme. The crypto-agility constitutional guarantee — ensuring the scheme can be replaced under governance — is captured in the whitepaper and roadmap but is not yet protocol-enforced. Pluggable signature scheme support in chain-forge-consensus is a Phase 1 item.

The size tradeoff is real and stated plainly: ML-DSA signatures are ~2.4KB against ECDSA's ~64 bytes. There is no PQC option that matches ECDSA's compactness — adopting post-quantum signatures means accepting this cost. Which specific algorithm Qattice adopts at launch versus in reserve, and how the size cost is absorbed, are addressed in Open Question 16.

---

## Section 11: Roadmap

| Phase | Milestone | Status |
|---|---|---|
| Phase 0 | Chain Forge BFT devnet, PoCD pipeline, cross-machine escrow, adversarial security | ✅ Demonstrated on live devnet |
| Phase 1 | Personhood-weighted BFT overlay, permissionless validator onboarding, cryptographic security hardening, identity hardening | 🔄 In progress |
| Phase 2 | Identity pilot (real-world sybil test), Grand Challenge pool mode, community portal | ⬜ Pending Phase 1 |
| Phase 3 | Merchant API, BME activation | 🔲 Pending Phase 2 identity pilot |
| Phase 4 | Charmed Agents at scale, 1M verified humans | 🔲 Pending Phase 3 |
| Phase 5+ | Permissioned EVM, RWA issuance, PoP-preserving interoperability | 🔲 Identity layer must be proven at scale first |

**Phase 0 is complete.** The engineering work described in the "What's Been Built" section above is confirmed on a live, adversarially-tested, cross-machine devnet. Full detail is in the Technical Appendix.

**Phase 1 priorities:** personhood-weighting overlay on TendermintEngine; permissionless validator onboarding via QCB stake bond; cryptographic survivability and migration architecture (QCB-CS-001); DIS Phase B-Privacy (unlinkable authorization research); post-quantum multisig and key lifecycle (QCB-KR-001); Charm Confinement module.

---

## Section 12: Open Questions

**Calibration questions:**

1. Final identity layer design and pilot targets (sybil rate < 3%, cost < $5/human — both provisional)
2. Final BFT variant selection for QCB
3. Base exemption calibration
4. Reserve strategy
5. Jurisdiction and legal entity structure
6. Validator economics — staking incentives, slashing conditions, personhood bounds
7. Exact token distribution percentages
8. Constitutional amendment thresholds — exact quorum, absolute voter count, waiting period

**Permanence questions:**

9. Identity replacement constitutional mechanism
10. Governance succession past founder control
11. Long-horizon funding (year 15–20)
12. Consensus-layer bug migration path
13. Validator liveness under partial participation — what happens to finality if a large fraction of verified humans go offline
14. Minimum legitimate participation rate required for governance Sybil-resistance
15. Absolute minimum voter count for sensitive parameter changes
16. Post-quantum migration trigger and algorithm choice
17. Turnout-suppression resistance — mechanism to close the gap against active campaigns to depress legitimate participation
18–22. **[Archived — merchant settlement layer. Deferred to future phase; no active urgency.]** These questions are archived for reference if merchant integration is introduced as a future-phase extension.
23. Permissioned EVM design (SponsorID enforcement, SponsorID revocation handling, gas denomination, opcode set)
24. Liveness of identity — minimum periodic activity to maintain active verification status
25. Human Capacity Markets (considered, not committed) — prerequisites: price discovery mechanism, bonding and liability design, sybil-farming resistance. Also recorded: activity-based $QCB accrual, which inherits the same three prerequisites in a stricter form.

---

## Conclusion

Qattice is not trying to be digital gold, and it is not trying to be someone else's framework with a new name. It is a sovereign chain, built from its own foundation, where consensus power, governance, and economic participation all trace back to the same principle: one verified human, one share of the system.

That requires a constitutional layer (Section 7.3) that can outlive any single identity method, any single development team, and any single jurisdiction — and the discipline to treat that layer as genuinely load-bearing, not aspirational language. The identity primitive described in this document is a current best answer, not a permanent one. What makes Qattice durable is not that this answer is correct forever, but that the protocol has a defined, legitimate way to replace it if it isn't.

Its security comes not from capital or hardware, but from verified humans. Its independence comes from having built its own foundation, on Chain Forge, rather than borrowing one. And its claim to permanence rests not on any individual's commitment to it, but on whether the rules it launches with are the rules that let it keep changing without breaking.

*The engine, not the vault. The economy, not the chain. Built to be replaced by better versions of itself, not by its own collapse.*

---

## Editorial Reconciliation Notes

1. **RESOLVED** — QCB supply and PoCD rewards. Fixed 210,000,000 genesis; treasury-redemption model throughout.
2. **RESOLVED** — Denomination and reward states. 1 QCB = 1,000,000 uQCB; ordinary wallet uQCB transferable; Pending uQCB non-transferable.
3. **RESOLVED AT DESIGN LEVEL** — Escrow versus burn. Current fee and burn are zero.
4. **RESOLVED** — Supply cap. 210,000,000 QCB; no research-reward minting.
5. **PARTIALLY SPECIFIED** — Phase-0 consensus keys. Keyless validator behavior is devnet/bootstrap only.
6. **PARTIALLY SPECIFIED** — Verification and scientific discovery. Assurance layers distinguished; end-to-end enforcement on production network remains an open validation item.
7. **PARTIALLY SPECIFIED** — SHA-256 seals versus research computation. Seals do not prove useful execution, timing, novelty, or correctness.
8. **PARTIALLY SPECIFIED** — BTC beacon assumptions. Miner influence and reorganizations acknowledged; confirmation depth and fallback rules undecided.
9. **PARTIALLY SPECIFIED** — DIS privacy and compliance. Authentication, personhood, unlinkability, and KYC/AML explicitly separated.
10. **PARTIALLY SPECIFIED** — Scientific positioning. Individual research tracks need feasibility evidence and carefully bounded claims.
11. **PARTIALLY RESOLVED** — Brand audit. Qattice names the network; QCB ($QCB) names the cryptocurrency. Legacy code identifiers preserved.
12. **PARTIALLY SPECIFIED** — Roadmap and acceptance status. Historical milestone text preserved; repository-based audit and third-party validation outstanding.
13. **RESOLVED** — Staking denomination. QCB (whole units) is the staking and bonding token throughout; uQCB is the internal micro-denomination used in protocol accounting and escrow.

---
---

# TECHNICAL APPENDIX
## Chain Forge / Qattice — Engineering Roadmap (October 2026)

*How to use this appendix: This is the full engineering reference for what is done, what is next, and what is on the horizon. Cross-reference the whitepaper body above for economic design rationale. This section is the engineering view.*

### Legend

| Symbol | Meaning |
|---|---|
| ✅ | Shipped / confirmed working |
| 🔄 | In progress |
| ⬜ | Pending — prerequisite complete |
| 🔲 | Pending — prerequisite not yet complete |
| ❓ | Open question / design decision needed |

*The network name is Qattice. The token is $QCB. 1 QCB = 1,000,000 uQCB.*

---

## Phase 0 — Chain Forge Engine Foundation

**Goal:** A working, partition-tolerant BFT consensus engine plus one complete, adversarially-verified, cross-machine resource purchase and a live PoCD research pipeline.

**Token model (current — single token):** QCB / uQCB is the one and only token. All balances, escrow, job payments, PoCD rewards, staking, and governance use QCB (expressed internally in uQCB). QRC is retired. The "Qrc" in escrow tx type names is a naming artifact — those tx types already operate entirely in uQCB. A future cleanup change set will rename them.

---

### Consensus & Networking

| Item | Status | Notes |
|---|---|---|
| Tendermint-style BFT engine (chain-forge-consensus) | ✅ | Operational on 4-node devnet |
| chain_id-aware vote scoping | ✅ | Prevents cross-chain vote contamination |
| Real libp2p P2P (--features real-network) | ✅ | 4 nodes exchanging gossip; /api/status shows peer count |
| 4-node genesis (quorum=3, f=1 BFT) | ✅ | Alice/Bob/Dave on Machine 1; Carol on Machine 2 |
| Partition tolerance — iptables DROP test | ✅ | 5s hard TCP partition; 3-of-4 quorum continued; Alice synced in <2s on heal |
| State persistence (block-by-block to disk) | ✅ | Nodes resume from last committed height on restart |
| Proposer rate-limiting | ✅ | MAX_PROPOSALS_PER_ROUND=3; flood-stop + accepted-proposal dedup |
| Equivocation detection | ✅ | Double-vote/double-precommit at same (height, round, type) → ConsensusError::Equivocation |
| verify_commit() hardening | ✅ | Dedup stuffing blocked; mismatch checks; unknown-validator rejection |
| Validator set governance | ✅ | ValidatorSetChange, epoch-delayed activation, personhood cap |
| HotStuff-style BFT variant | ✅ | HotStuffEngine — three-phase (PREPARE/PRE-COMMIT/COMMIT), QC-locked, linear messaging; 17 tests passing |
| XRPL-inspired FBA variant | ✅ | FbaEngine — global UNL, 80% threshold, single-phase; 18 tests passing; all three BFT variants confirm pluggable ConsensusEngine trait |

---

### Slashing & Safety

| Item | Status | Notes |
|---|---|---|
| chain-forge-slashing crate | ✅ | SlashingModule, EquivocationEvidence, ValidatorRegistry |
| ValidatorRegistry — genesis validators activated at startup | ✅ | confirm_pop() called at block 0; registry fully populated |
| Liveness slashing — confirmed on live testnet | ✅ | >20% missed blocks in window → jail + 1,000,000 uQCB slash |
| Equivocation → SlashingModule wire | ✅ | process_equivocation_evidence() in node.rs routes to slasher |
| Forged vote rejection (in-process test) | ✅ | Garbage-signature vote does not advance height |
| Adversarial libp2p gossip test | ✅ | Three tests over real libp2p TCP: unknown validator rejection; equivocation over gossip detected; garbage-signature vote rejected via real Ed25519 verification |

---

### Cryptography

| Item | Status | Notes |
|---|---|---|
| ML-DSA (Dilithium3) post-quantum signing (chain-forge-crypto) | ✅ | Validator signing scheme; --features real-crypto |
| Crypto-agility constitutional guarantee | 🔄 | Design captured in whitepaper §10 + §7.3; not yet protocol-enforced |
| Signature scheme pluggability in chain-forge-consensus | ⬜ | Architectural requirement for PQ migration path |

---

### QRC Layer (chain-forge-qrc) — Retired

QRC is a retired concept. QCB Chain is a single-token chain. The chain-forge-qrc crate remains compiled as a vestigial artifact but none of its logic runs in any active devnet flow.

| Component | Status | Direction |
|---|---|---|
| QrcEngine, uqrc balances | ⬜ | Retired |
| Dynamic conversion rate (Control 1) | ⬜ | Retired — second token does not exist |
| Epoch conversion cap (Control 2) | ⬜ | Retired |
| CoverageRatio circuit breaker (Control 5) | ⬜ | Retired |
| PurchaseQrc tx type | ⬜ | Retired |
| CreditProvider tx type | ⬜ | Retired |
| QrcContributionSettle | ⬜ | Retired |
| Consumption burn (Control 4) — p_burn = 0.25 | ⬜ | Retired — never activated |
| LockQrcForJob / ReleaseQrcForJob tx type names | ✅ | Legacy naming artifact — operate entirely in uQCB; future cleanup will rename |

---

### Resource Market Layer (chain-forge-resource)

| Item | Status | Notes |
|---|---|---|
| chain-forge-resource crate scaffold | ✅ | MachineRecord, ResourceCapabilityDescriptor, ResourceJob, ResourceExecutionReceipt, LockQrcForJob/ReleaseQrcForJob/RefundQrcForJob; 23 unit tests |
| ResourceCapabilityDescriptor | ✅ | ComputeClass, MemoryTier, StorageTier, PriceModel, ISA tags; satisfies() matcher; 8 unit tests |
| ResourceJob state machine | ✅ | Full CREATED→FUNDED→MATCHED→RUNNING→(COMPLETED/FAILED)→(VERIFIED/REFUND)→SETTLED + DISPUTED→RESOLUTION; 9 unit tests |
| ResourceExecutionReceipt | ✅ | ResourceExecutionReceipt + UsefulWorkReceipt; compute_seal_hash, find_seal_nonce, meets_difficulty, verify_seal; 6 unit tests |
| P2P resource discovery | ⬜ | Agents broadcast ResourceRequest over libp2p gossip; providers respond with ResourceOffer |
| uQCB job escrow (LockQrcForJob / ReleaseQrcForJob / RefundQrcForJob) | ✅ | Agent locks uQCB before job; provider receives only on verified completion; refund path for failure/timeout; N3/N4/N5 guards tested |
| ResourceNode prototype (Machine 2) | ⬜ | Machine 2 (Carol) advertises capabilities over libp2p |
| Secure workload sandbox (container) | ⬜ | Docker/container prototype for Phase 0 approximation only |
| Job cancellation / failure / timeout handling | ⬜ | Explicit handling for all failure modes |

---

### Agent Economic Identity (AEI) — Phase 0 Foundation

| Item | Status | Notes |
|---|---|---|
| AgentID + SponsorID linkage primitive | ✅ | AgentId in chain-forge-resource; SponsorId in MachineRecord.owner |
| MachineID formalization | ✅ | MachineRecord { machine_id, owner: ProviderOwner, attestation_key, capability_descriptor, mode, status } |
| ProviderOwner enum | ✅ | enum ProviderOwner { Individual(SponsorId), Enterprise(EnterpriseId) } |
| AgentTreasury primitive | ✅ | treasury:{agent_id} virtual account; DepositToTreasury tx; LockQrcForJob treasury-first funding (debits uQCB); per_job_limit_uqrc enforced |
| CapabilitySet + SpendingLimits | ✅ | SpendingLimits (epoch_limit, lifetime_limit, max_balance, per_job_limit); check_per_job() enforcer |
| RevenuePolicy primitive | ⬜ | Configurable destination for agent revenue |

---

### Phase 0 Acceptance Tests — Results

**Happy path — PASSED ✅ (Run ID ad255b9f, 2026-10-07)**
All 8 checks green on Alice, Bob, Dave at height=17. Five-transaction sequence committed: QrcPurchase → RegisterAgent → AuthorizeAgent → DepositToTreasury → LockQrcForJob. (Note: QrcPurchase and LockQrcForJob are legacy tx type names from the original QRC era; both operate entirely in uQCB in all active devnet flows.) Alice uQCB=5,000,000; treasury=4,200,000 (5M deposit − 800K lock).

**Negative-path N1 — PASSED ✅** Over-cap lock (1,000,001 > per_job_limit 1,000,000) hard-fails at execution layer; treasury balance verified unchanged.

**Negative-path N2 — PASSED ✅** Duplicate escrow_id hard-fails at execution layer; escrow:{id} now queryable.

**Settlement happy-path — PASSED ✅ (Run ID 24963a9f, 2026-10-09)** Release debited escrow and credited provider; refund restored original treasury; repeated full payouts rejected without balance changes.

**4-node cross-machine devnet — VERIFIED ✅ (2026-10-09)** Dave on Machine 2 (192.168.137.3, port 26659) synced to height 111+, precommit_count=3. Full N3/N4/N5 negative release test suite passed on 4-node chain. genesis-4node.json committed.

**ReleaseQrcForJob N3/N4/N5 — PASSED ✅** Wrong sender, over-amount, ghost escrow all correctly rejected.

**RefundQrcForJob N6/N7/N8/N9 — PASSED ✅** RefundReason::Timeout, wrong sender, over-amount refund, double-settlement after release all rejected correctly.

**Phase 0 cross-machine attack scenarios:**

| # | Attack | Result |
|---|---|---|
| 1 | Fake completion | ✅ Escrow not released |
| 2 | Duplicate settlement | ✅ Second settlement rejected |
| 3 | Replayed receipt | ✅ Receipt rejected (job_id + height scoped) |
| 4 | Provider disconnect mid-job | ✅ Job → FAILED; escrow refunded after timeout |
| 5 | Requester disconnect mid-job | ✅ Job continues; no double-payment |
| 6 | Tampered result (output_hash mismatch) | ✅ Verification fails; escrow refund |
| 7 | Unauthorized agent spending | ✅ Tx rejected at execution layer |
| 8 | Spending-limit bypass attempt | ✅ SpendingLimits enforced |
| 9 | Forged provider identity | ✅ Unknown provider → receipt rejected |
| 10 | Double payment | ✅ Second payment rejected; idempotency guard |

---

### Execution Layer

| Item | Status | Notes |
|---|---|---|
| chain-forge-execution crate | ✅ | 74 tests, 0 failures |
| All QRC tx types wired | ✅ | Gas model, variant_name, payload_size_bytes, required_module, execute_tx |
| tx_kind_label() exhaustive match in node.rs | ✅ | Compiler-enforced; updated with every new variant |
| Attestation guard tx types (Phases A–D) | ✅ | AttestEntity, RevokeAttestation, ConfirmSybil, ReportSuspectedSybil, ReverseSybil |
| QCB native tx types | ✅ | Transfer, Stake, Unstake, etc. |
| Governance tx types | ✅ | ProposeChange, VoteOnProposal, ActivateChange |
| EVM precompile / permissioned EVM layer | 🔲 | Phase 5+ |

---

### Identity / Personhood

| Item | Status | Notes |
|---|---|---|
| Attestation guard Phases A–D (chain-forge-identity) | ✅ | 65 tests passing; coordinator-gated |
| ZK-VRC prototype (chain-forge-personhood) | ✅ | Groth16 / BLS12-381; 5 binaries; integrated into workspace |
| governance_authority.rs — uses real ValidatorSet | ✅ | Quorum tied to quorum_power() / revocation_quorum_power() |
| /api/identity/{address} REST endpoint | ✅ | Returns verification tier + CS score |
| Personhood-weighting overlay on BFT | ⬜ | Overlay not yet built; consensus base ready |
| Identity pilot — real-world sybil test | 🔲 | Requires Phase 1 complete |
| Coordinator role decentralized | 🔲 | Currently a named temporary centralization |

---

### Infrastructure & Tooling

| Item | Status | Notes |
|---|---|---|
| Block explorer REST API | ✅ | /api/blocks, /api/txs, /api/accounts, /api/status — live on every block commit |
| React frontend (chain-forge-frontend) | ✅ | Vite dev server running |
| Explorer persistence | ✅ | scripts/write_explorer_persistence.py + scripts/start-explorer-persistence.sh deployed |
| VCA PQ (chain-forge-vca-pq) | ✅ | Post-quantum VCA attestation crate in workspace |
| devnet scripts (devnet/) | ✅ | Start/stop scripts for Machine 1 and Machine 2 |

---

## Phase 1 — Personhood-Weighted BFT + Research Foundation

**Goal:** Consensus power tied to verified human identity. Research pipeline hardened with provider reputation and dispute resolution skeleton. Charmed Agent identity/budget primitive live.

**Prerequisite:** Phase 0 complete (cross-machine acceptance test passing).

---

### Validator Onboarding — Permissionless Entry via Stake Bond

| Item | Status | Notes |
|---|---|---|
| BondValidator tx type | ⬜ | Lock QCB as validator stake; enter pending set |
| UnbondValidator tx type | ⬜ | Start unbonding timer; stake released after cooldown |
| Minimum bond threshold | ❓ | Low enough for individual participation; high enough to deter Sybil attacks |
| Maximum active validator set size | ❓ | BFT doesn't scale to thousands; cap at ~100–200, ranked by stake |
| Stake-ranked validator set at epoch boundary | ⬜ | Top-N stakers automatically enter/exit active set |
| Unbonding cooldown enforcement | ⬜ | Stake locked for N epochs after UnbondValidator; slashable during cooldown |
| Validator commission rate | ⬜ | Configurable % of PoCD research rewards |
| Validator self-service docs | ⬜ | Operator guide: keygen → bond QCB → run node → monitor → unbond |

---

### Consensus — Personhood Weighting

| Item | Status | Notes |
|---|---|---|
| Personhood-weighting overlay on TendermintEngine | ⬜ | Cap per-human validator influence regardless of stake |
| ValidatorInfo.pop_verified gating in consensus | ⬜ | Only PoP-confirmed validators counted for quorum |
| Stake → influence cap enforcement | ⬜ | See whitepaper §3.3 |
| Validator liveness under partial-participation (Open Q13) | ❓ | How does finality behave if large fraction of verified humans go offline? |
| Governance quorum floor enforcement | ⬜ | >3% for ordinary votes; >6% for constitutional |

---

### Identity — Charm Confinement

| Item | Status | Notes |
|---|---|---|
| Charm Confinement (chain-forge-identity extension) | ⬜ | Identity-scoped state isolation; one claim per epoch |
| Intrinsic Charm module | ⬜ | Verification tier intrinsic to identity; decay-exemption credits removed |

---

### Cryptographic Security Hardening

| Milestone | Technology | Status |
|---|---|---|
| QCB-CS-001 | Cryptographic Survivability and Migration | ⬜ Phase 1 |
| QCB-DIS-001 | Digital Identity Stone — Native QCB Wallet | ✅ Phase A + B complete |
| QCB-KR-001 | Post-Quantum Multisig and Key Lifecycle | ⬜ Phase 1 |
| QCB-PM-001 | Private Post-Quantum Threshold Authorization | ❓ Research |
| QSWIP-001 | Open Post-Quantum Wallet Identity Protocol | 🔲 Proposed standard |

**QCB-CS-001 — Cryptographic Survivability and Migration**

| Requirement | Status |
|---|---|
| Complete cryptographic dependency inventory | ⬜ |
| Public-key exposure audit | ⬜ |
| Post-quantum authentication for critical operations | ⬜ |
| Pluggable signature algorithms (SignatureScheme trait) | ⬜ |
| Safe cryptographic migration procedures | ⬜ |
| Emergency algorithm-deprecation mechanism | ⬜ |
| Simulated cryptographic compromise tests | ⬜ |
| Independent security review | 🔲 |

**QCB-DIS-001 — Digital Identity Stone**

| Phase | Scope | Status |
|---|---|---|
| A — Identity and authentication | ML-DSA-65 wallet identity, QR challenges, signature verification, anti-replay | ✅ Complete |
| B — Security hardening | Chain-ID binding, nonce/balance/gas enforcement, restart+replay persistence, 4-node finality | ✅ Complete |
| B-Privacy — Unlinkable authorization | Selective disclosure, service-specific pseudonyms, ZK authorization | 🔲 |
| C — Post-quantum credential storage | Encrypted credential storage using PQ key-establishment | 🔲 |
| D — Integration | Wallets, personhood, Charmed Agents, enterprise authorization, private multisig | 🔲 |
| E — Security testing | QR replay, phishing, session hijacking, key compromise, identity correlation | 🔲 |

**DIS-001 Phase B — COMPLETE ✅ (2026-10-09):** 25/25 checks green. B1 nonce enforcement ✅, B2 balance enforcement ✅, B3 gas cap enforcement ✅ (gas_limit=0 rejected; gas_limit=10B rejected), B4 chain-ID enforcement ✅, B5 malformed tx rejection ✅, B6 Phase A regression ✅, B7 SIGKILL+restart+replay rejection ✅, B8 Carol finality confirmed across all 3 nodes ✅.

**DIS-001 Phase A — COMPLETE ✅ (2026-10-09):** 5/5 adversarial scenarios passed on live 3-node devnet: happy path ✓, anti-replay ✓, forged signature ✓, wrong key ✓, unknown challenge ID ✓.

**QCB-WALLET-001 — COMPLETE ✅ (2026-10-09):** ML-DSA-65 wallet (chain-forge-wallet crate): AES-256-GCM + Argon2id key storage; sign_transaction() over SHA-256(tx_body_json); "qcb1pq…" address namespace; 10/10 adversarial tests passing. End-to-end devnet: happy path, forged sig, tampered body, nonce replay all verified.

**QCB-KR-001 — Post-Quantum Multisig Key Lifecycle**

| Requirement | Status |
|---|---|
| Post-quantum multisig authorization (ML-DSA threshold signing) | ⬜ |
| Configurable per-operation key rotation | ⬜ |
| Off-chain signature collection | ⬜ |
| Atomic key rotation and transaction execution | ⬜ |
| Old-key revocation and replay protection | ⬜ |
| Secure recovery and emergency rotation | ⬜ |
| Adversarial tests for failed rotations | ⬜ |

---

### Grand Challenge Pipeline — Phase 1 Items

**seal_hash on UsefulWorkReceipt — COMPLETE ✅:** seal_nonce, seal_hash, seal_difficulty_bits fields live; compute_seal_hash(), find_seal_nonce(), verify_seal(), meets_difficulty() implemented; 6 tests passing.

**Grand Challenge machine daemon — COMPLETE ✅:** chain-forge-node/src/bin/gc-daemon.rs — full 3-step cycle: hash preimage search → seal nonce search → UsefulWorkReceipt JSON. GC-DEVNET-002: nonce 80,468 + seal nonce 161 found in <500ms. `cargo run --bin gc-daemon -- --dry-run`.

**Grand Challenge contribution layer — Phases 1A, 1B, 1C COMPLETE ✅ (2026-10-09):**
- Phase 1A: RegisterMachine and SubmitUsefulWork tx types in chain-forge-execution; gates on Verified-tier identity; accumulates contribution_score:{machine_id}; duplicate receipt guard; minimum seal difficulty ≥8 bits.
- Phase 1B: QcbRewardPolicy wired into EpochClose handler; scans gc_receipt:* state for unawarded receipts; converts to DiscoveryReceipt; computes uQCB grants (difficulty × track multiplier, pro-rata epoch pool of 720,000,000 uQCB); debits treasury:pocd; credits machine wallets; gc_reward_paid=1 sentinel prevents double-payment.
- Phase 1C: Six anti-farming guards on SubmitUsefulWork: machine must be registered; sender must be registered owner or Verified-tier coordinator; duplicate receipts rejected; absolute minimum difficulty 8 bits; per-tx min_difficulty_override enforced; per-machine epoch rate limit of 100 receipts.
- Nine adversarial tests in scripts/phase1_contribution_test.py verified all guards on live devnet.

**PoCD epoch reward — END-TO-END VERIFIED ✅ (2026-10-09, commit daf642b):** Three independent miners (qcb1devminer-alice, -bob, -dave) received separate per-wallet uQCB credits at block 720 epoch boundary. 8,586 rewarded receipts, 0 pending. alice balance: 719,996,202 uQCB. treasury:pocd debited from 50,000,000,000 → 49,280,003,798 uQCB — exact match, no double-payment.

**PoCD proof pool P2P gossip — COMPLETE ✅ (commit 93a2018):** GossipTopic::DiscoveryProof; proofs published to libp2p gossip layer; all nodes converge to same proof pool before epoch boundary.

**Pending Phase 1 Grand Challenge items:**

| Item | Status |
|---|---|
| BTC block hash randomness beacon for job slice assignment | ⬜ |
| Seal difficulty target governance per challenge track | ⬜ |
| SHA256 hardware compatibility documentation | ⬜ |
| BTC miner onboarding guide | ⬜ |
| QcbVerifier adapter (wraps identity layer + scientific receipt) | ⬜ |

---

### Resource Market — Phase 1 Hardening

| Item | Status |
|---|---|
| Provider reputation (minimal) | ⬜ |
| DisputeResourceJob tx type (wire submission and resolution path) | ⬜ |
| Multi-provider resource discovery | ⬜ |
| Provider-identity → SponsorID tracing | ⬜ |
| Sandboxed workload hardening | ⬜ |
| Machine-level → Provider-level reputation aggregation | ⬜ |

---

### Enterprise Authorization Tree (EAT-v0)

| Item | Status |
|---|---|
| EnterpriseID primitive | ⬜ |
| ControllerBinding (SponsorID → EnterpriseID) | ⬜ |
| EnterpriseCapabilitySet | ⬜ |
| ResourcePool | ⬜ |
| Enterprise → MachineID binding | ⬜ |
| Enterprise → AgentID binding | ⬜ |
| Controller revocation | ⬜ |
| Authorization subtree freeze | ⬜ |
| PersonhoodMultisig | ⬜ |

---

### Anti-Farming Architecture (all required before uQCB distribution goes live)

| Defense | Status |
|---|---|
| SponsorID verification required for Contribution Mode | ⬜ |
| MachineID uniqueness enforcement | ⬜ |
| Execution receipts (not heartbeats) — work must complete | ⬜ |
| Self-dealing detection | ⬜ |
| Consumer diversity requirement | ⬜ |
| Resource proofs (not claims) | ⬜ |
| Reliability scoring | ⬜ |
| Integrity scoring | ⬜ |
| Contribution Score gate before uQCB eligibility | ⬜ |

---

## Phase 0d — PoCD Crate (chain-forge-pocd)

| Item | Status |
|---|---|
| Cargo.toml + workspace member | ✅ |
| PoCDConfig struct | ✅ |
| ChallengeTrack enum + ChallengeStatus | ✅ |
| DiscoveryChallenge struct | ✅ |
| DiscoveryProof struct + seal functions | ✅ |
| DiscoveryReceipt struct | ✅ |
| PoCDError enum | ✅ |
| DiscoveryRegistry | ✅ |
| RewardPolicy trait (NullRewardPolicy + FlatRewardPolicy) | ✅ |
| DiscoveryWorker trait | ✅ |
| DiscoveryVerifier trait | ✅ |
| cargo build -p chain-forge-pocd passes | ✅ |
| QcbRewardPolicy in chain-forge-qrc | ✅ |
| Wire PoCDConfig into QCB genesis | ✅ |
| PoCD API endpoints (/api/pocd/challenges, /receipts, /submit) | ✅ |
| First live PoCD mining round on devnet | ✅ |
| Wire QcbRewardPolicy into epoch processing | ✅ |
| PoCD epoch reward distribution — end-to-end verified | ✅ |
| scripts/pocd_miner.py — confirmed (2026-10-09) | ✅ |
| scripts/pocd_miner.py — rewritten with real per-track computation + multi-threading | ✅ |
| Genesis files upgraded — 5 challenge tracks, 8-bit difficulty | ✅ |
| Migrate chain-forge-resource seal functions to delegate to chain-forge-pocd | ⬜ |

**Per-track computation (pocd_miner.py — rewritten 2026-10-09):** Mathematics (Fibonacci(n), SHA256 of decimal string); Cryptography (real hash pre-image search — SHA256 prefix '0'); ComputationalEfficiency (16×16 integer matrix multiply A×B mod 2^31, SHA256 of diagonal checksum); PhysicsAndOpenScience (4-dim lattice SVP, exhaustive [-6,6]^4 coefficient search over LCG-seeded basis); AiAssistedDiscovery (Sieve of Eratosthenes for π(n)). Multi-threaded seal mining: --threads N (default: min(cpu_count, 8)).

---

## Phase 0e — PoCD Scheduler, Miner, and External Verifier

### Change Set L — PoCD Scheduler (chain-forge-scheduler) ✅ COMPLETE

| Item | Status |
|---|---|
| chain-forge-scheduler crate | ✅ |
| Task lease model (lease_expires_at; expired leases reassigned) | ✅ |
| Two-phase cascade enforcement (phase-2 always assigned to different miner) | ✅ |
| Miner registration API (POST /scheduler/miners/register) | ✅ |
| Task poll API (GET /scheduler/miners/{id}/task) | ✅ |
| Result submission API (POST /scheduler/tasks/{id}/result; 409/410 handling) | ✅ |
| Objective management API | ✅ |
| Task range assignment | ✅ |
| Result deduplication | ✅ |
| Independent verification queue (quorum-based acceptance) | ✅ |

### Change Set M — Two-Phase PoCD Protocol ✅ COMPLETE

| Item | Status |
|---|---|
| Phase-1: SHA-256(seed_le64 ∥ nonce_le64) ≥ 16 leading zero bits | ✅ |
| Phase-2: SHA-256(H1_bytes ∥ nonce_le64) ≥ 8 leading zero bits | ✅ |
| Parent-hash chaining (phase-2 carries H1 from phase-1 winner) | ✅ |
| Cross-machine constraint (scheduler never assigns phase-2 to phase-1 solver) | ✅ |
| Content hash derivation (phase-1: SHA-256(H1); phase-2: SHA-256(H1 ∥ H2)) | ✅ |

### Change Set N — chain-forge-miner (qcb-miner binary) ✅ COMPLETE

| Item | Status |
|---|---|
| chain-forge-miner crate (zero compile-time deps on other chain-forge crates) | ✅ |
| CLI (clap): --node-url, --miner-id, --objective-id, --workload-class, all env var equivalents | ✅ |
| solve_phase1() — searches assigned range; returns winning nonce + H1 | ✅ |
| solve_phase2() — decodes parent_hash hex; returns winning nonce + H2 | ✅ |
| spawn_blocking for CPU work | ✅ |
| Event loop (Register → poll → solve → submit → loop) | ✅ |
| HTTP 409/410 handling | ✅ |
| SchedulerClient (async, 30s timeout, rustls-tls) | ✅ |
| 13 unit tests | ✅ |

### Change Set N+1 — Avalanche Experiments ✅ COMPLETE

| Item | Status |
|---|---|
| solve_avalanche() — deterministic; two SHA-256 calls; no nonce search | ✅ |
| Canonical seed derivation: SHA-256("qcb-avalanche-v1" ∥ objective_id ∥ seed_index_le64) | ✅ |
| Bit-flip experiment + XOR diff + Hamming distance | ✅ |
| Avalanche test coverage | ✅ |

### Change Set O — Consensus Vote Security Fix ✅ COMPLETE

| Item | Status |
|---|---|
| Fail-closed empty-signature guard | ✅ |
| Regression tests | ✅ |

### Change Set P — Authenticated PoCD Verification ✅ P1–P5 COMPLETE

| Phase | Item | Status |
|---|---|---|
| P1 | chain-forge-verifier crate (qcb-verifier binary) | ✅ |
| P1 | qcb-keygen binary (ML-DSA-65 verifier keypairs, encrypted at rest) | ✅ |
| P2 | Verifier result signing (ML-DSA-65) | ✅ |
| P3 | Scheduler verifier API (POST /scheduler/tasks/{id}/verification) | ✅ |
| P4 | Quorum logic (configurable N independent verifier confirmations) | ✅ |
| P5 | Sybil resistance (per-verifier rate limiting) | ✅ |
| P6 | Devnet demo — verifier Sybil protection (7 adversarial scenarios) | ⬜ |

### Change Set R — P2P Proof Gossip ✅ COMPLETE (commit 93a2018)

| Item | Status |
|---|---|
| GossipTopic::DiscoveryProof | ✅ |
| Proof gossip handler | ✅ |
| Cross-node proof pool convergence | ✅ |
| Anti-spam guards | ✅ |
| Proof gossip integration tests | ✅ |

### Change Set T — Light P2P Resource/Capacity Discovery ✅ COMPLETE (commit bd9d4ff)

| Item | Status |
|---|---|
| GossipTopic::CapacityAd | ✅ |
| PeerCapacityTable (500-entry bounded; 5-minute TTL eviction) | ✅ |
| GET /api/peers/capacity | ✅ |
| Advisory-only semantics | ✅ |
| Anti-spam rate limiting (30s per-peer) | ✅ |
| Capacity ad integration tests | ✅ |

### Item 5 — External Miner Documentation ✅ COMPLETE (commit 0e589ec)

| Item | Status |
|---|---|
| chain-forge-miner/README.md | ✅ |
| docs/QCB-Miner-External-Guide.md | ✅ |

### PoCD Devnet Acceptance Tests — 9/9 PASSING

| Test | Result |
|---|---|
| Phase-1 SHA-256 preimage search (16-bit difficulty) | ✅ |
| Phase-2 chained search (8-bit difficulty, parent-hash dep) | ✅ |
| Determinism across multiple solver runs | ✅ |
| Phase-2 cross-miner content-hash agreement | ✅ |
| Avalanche seed derivation (deterministic by objective_id, seed_index) | ✅ |
| Avalanche hamming-distance consistency | ✅ |
| Invalid-hex parent-hash returns None gracefully | ✅ |
| Result deduplication (duplicate submit rejected, HTTP 409) | ✅ |
| Lease expiry handling (HTTP 410 logged as WARN; miner continues) | ✅ |

---

## Grand Challenge Simulation Log

| ID | Date | Type | Winner | Result | Record |
|---|---|---|---|---|---|
| GC-DEVNET-001 | 2026-10-06 | Hash preimage search (SHA256('QCB:\<nonce\>') prefix 0000) | Carol (MACH-CAROL-003) | Nonce 6,682,026 → 000050f1... — verified by Dave | grand-challenge/simulations/GC-DEVNET-001-discovery-record.json |
| GC-DEVNET-002 | 2026-10-07 | Hash preimage via gc-daemon binary (Rust) + seal hash | MACH-CAROL-003 (simulated) | Nonce 80,468 → 0000ce63...; seal nonce 161; verify_seal ✓; full UsefulWorkReceipt JSON produced | gc-daemon --dry-run --seal-difficulty 8 |

**Next simulations planned:** GC-DEVNET-003 (multi-track parallel), GC-DEVNET-004 (disputed result + rejection flow), GC-DEVNET-005 (physics-flavored: tiny lattice simulation with verified output hash).

---

## Phase 2 — Identity Pilot + Community Portal

**Prerequisite:** Phase 1 complete.

| Item | Status |
|---|---|
| Identity pilot design — cost/sybil targets finalized | ❓ |
| Red-team / adversarial sybil test | ⬜ |
| Grand Challenge pool mode live | ⬜ |
| Community portal v1 — challenge dashboard | ⬜ |
| BTC miner outreach program | ⬜ |

---

## Phase 3 — Merchant API + BME Activation

**Prerequisite:** Phase 2 identity pilot hitting targets.

| Item | Status |
|---|---|
| Merchant API — Stripe-compatible REST | ⬜ |
| Shopify / WooCommerce plugin | ⬜ |
| Fiat settlement layer integration | ⬜ |
| BME activation — first on-chain $QCB burn | ⬜ |
| BME "live vs. speculative" threshold finalization | ❓ |

---

## Phase 4 — Charmed Agents + Scale

**Prerequisite:** Phase 3 merchant API live.

| Item | Status |
|---|---|
| Charmed Agent registry (chain-forge-agents extension) | ⬜ |
| Agent Service Registry (on-chain directory) | ⬜ |
| Streaming / metered payment primitives | ⬜ |
| Python Agent OS backend | ⬜ |
| SponsorID → agent linkage (AEI spec formalized) | ❓ |
| 1M verified humans milestone | 🔲 |
| Liveness of identity (per-human participation requirement) | ❓ |

---

## Phase 5+ — Governance Maturity + EVM + Interoperability

| Item | Status |
|---|---|
| Permissioned EVM (chain-forge-evm) | 🔲 |
| Sponsored Contracts (Solidity + identity constraints) | 🔲 |
| RWA issuance layer | 🔲 |
| Governance succession (post-founder) | ❓ |
| Interoperability (PoP-preserving bridge only) | 🔲 |
| Production-grade JMT state tree | ⬜ |
| Chain Forge standalone whitepaper | ⬜ |

---

## Equilibrium Criteria

All five conditions must hold simultaneously and sustain for a meaningful period:

| Criterion | Definition | Status |
|---|---|---|
| Validator depth | Set large and geographically distributed enough that no regional outage halts block production | 🔲 Phase 3+ |
| Machine population | Deep enough that every active Grand Challenge track has sufficient verifier coverage | 🔲 Phase 4+ |
| Anti-farming maturity | All defenses battle-tested; contribution score trustworthy | 🔲 Phase 2/3 |
| Governance participation | Vote participation reflects network's actual human base | 🔲 Phase 4+ |

---

## Open Questions Index

| # | Topic | Urgency |
|---|---|---|
| Q1 | Final identity layer design; pilot cost/sybil targets | 🔴 High — gates everything |
| Q2 | BFT variant selection for QCB | 🟡 Medium — all three variants shipped; selection now unblocked |
| Q5 | Jurisdiction / legal entity | 🔴 High — needed before mainnet |
| Q9 | Identity replacement constitutional mechanism | 🟡 Medium |
| Q10 | Governance succession past founder control | 🟡 Medium |
| Q11 | Stagnation resilience / BME "live" threshold | 🟡 Medium |
| Q13 | Consensus bug migration path | 🟡 Medium |
| Q14 | Validator liveness under partial participation | 🔴 High — needed before Phase 1 |
| Q16 | PQ migration trigger + algorithm choice | 🟡 Medium |
| Q17 | Turnout-suppression resistance | 🟡 Medium |
| Q18–22 | Merchant settlement layer questions | 🟢 Archived — deferred to future phase |
| Q23 | Permissioned EVM design | 🟢 Low — Phase 5+ |
| Q24 | Identity liveness requirement | 🟡 Medium |

---

## Hardware Reference

| Machine | Role | IP | User | Path |
|---|---|---|---|---|
| Machine 1 (king-OptiPlex-990) | Alice (26656), Bob (26657), Dave (26658) | 192.168.137.2 | king | /home/king/chain-forge-engine |
| Machine 2 (bossking-node) | Carol | 192.168.137.3 | bossking | /home/bossking/ |
| Windows dev (BossKing) | Build + SSH control | — | — | C:\Dev\chain-forge-engine |

To update Machine 2 binary: `scp target/release/chain-forge-node bossking@192.168.137.3:/home/bossking/chain-forge-node`

Key files are gitignored (keys/*.key.json) — never commit Ed25519 signing seeds.
