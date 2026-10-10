QCB Chain Whitepaper

QuarkCharmBit — A Sovereign, Ground-Up Layer-1 for Charm-Based Agent Economies

Money engineered to move. Agents engineered to work. Built from the ground up, owned by no one else's framework.

---

Abstract

QCB Chain (QuarkCharmBit) is a sovereign Layer-1 blockchain, built on Chain Forge — a from-scratch Rust blockchain engine — rather than on an existing framework like Cosmos SDK or Solana. QCB combines a novel consensus mechanism — Byzantine Fault Tolerant agreement with validator power weighted by verified personhood rather than raw stake — with four native protocol components: a single-token resource and value economy (burn $QCB to access network resources — compute, storage, ZK proving, oracle queries, AI inference, and bandwidth; earn uQCB for verified Grand Challenge work and convert to $QCB; $QCB supply contracts over time as usage burns it), alongside three charm-based agent and identity modules — Charm Confinement, Intrinsic Charm, and Charmed Agents.

QCB does not derive its consensus, its state machine, or its core modules from any other chain's codebase. In this, it follows the lineage of Bitcoin and XRP Ledger — chains with their own original designs — while making a deliberate departure from both: consensus power tied to verified human identity rather than computational work or capital, and a monetary engine designed to circulate rather than accumulate. The chain is self-contained by design: no bridges, no wrapped assets, no interoperability that could allow unverified actors into the system.

The monetary engine described in Section 6 is contingent on one unvalidated component: the identity layer (Section 4). Until the identity layer is validated through the staged pilot process, $QCB's resource economy and Grand Challenge earnings should be understood as a research deployment, not a production system. QCB operates a single-token model: $QCB is both the resource access token (burn to use network capacity) and the value-capture asset (held, staked, appreciated). uQCB is a non-tradeable micro-denomination earned from verified Grand Challenge work and converted to $QCB at 1,000,000:1. A separate resource token (QRC) has been prototyped in `chain-forge-qrc` and may be introduced in a future phase if resource pricing genuinely requires separation from network ownership; until that need is demonstrated at scale, QCB is the sole protocol token. This document describes the intended steady-state system in full; the early-adoption phase — when the network is small and belief precedes evidence — is described in Section 8.

A note on dependency chains: the sections that follow trace a sequence of dependencies, each of which has its own precondition. Identity depends on sybil resistance. Sybil resistance depends on live-challenge ceremonies not being defeated by well-resourced bots. Resource economy depends on the Grand Challenge network reaching meaningful throughput. Each dependency is real and is named where it arises. The staged pilots described in Section 4 are designed to determine whether these dependencies resolve into solvable engineering and legal decisions, or whether some of them represent constraints the system cannot satisfy under its own stated principles. The document does not claim to know which outcome will prevail — only that the honest path is to name the chain and test it.

---

Vision: A Trustworthy Distributed Supercomputer for Humanity

Distributed compute networks are not new. SETI@home pointed millions of machines at a single problem. Folding@home applied crowd-sourced cycles to protein simulation. Both produced real results. Both shared a fundamental limitation: a central organization decided the problem, collected the output, and published what it chose. Participants had no verifiable record of what their machine did, no accountability for results, and no say in what happened next.

QCB's Grand Challenge architecture is a different thing entirely.

Every machine on QCB is a first-class citizen on-chain — attested by a MachineID, with every ResourceExecutionReceipt cryptographically signed and hash-committed before any result is accepted. You cannot fake a discovery. You cannot claim credit for work you did not do. The network does not just solve a problem — it proves it solved it, in a form any independent machine can verify, on a ledger no single party controls.

Discoveries pass through human review gates before any reward is issued or any acceptance is recorded. The Proof of Useful Discovery requirement — independent verifier reproduction, domain-expert quorum ratification — means the network cannot be gamed by volume. Every accepted result is something humans examined and confirmed.

And the hard safety boundary is architectural, not policy: discoveries never automatically change QCB protocol behavior. The network could produce a result that rewrites a field of mathematics and it would still require a full governance vote before a single protocol parameter moved.

This design points at the hardest open problems in science — not because they are tractable today, but because they will become tractable as the network grows:

· Lattice QCD simulations that model quark-gluon behavior at precisions classical hardware cannot sustain
· Many-body quantum systems where the interaction space grows faster than any single machine can track
· Cosmological structure formation models that require more simulation fidelity than any national facility can provide
· Dark matter and dark energy candidate modeling at scales that rule out whole classes of theory
· Quantum gravity approximations that require sustained, verified compute across thousands of parallel runs

None of these are unsolved because physicists are not smart enough. They are unsolved because the verified, coordinated compute does not exist yet.

QCB is building it — not as a product, but as a protocol-layer public good that belongs to no one organization and can be governed away from no one's control.

The Name Is the Mission

The Large Hadron Collider is the largest, most complex scientific instrument humanity has ever built. Thousands of scientists, dozens of countries, decades of construction — all pointed at the smallest things in existence. It found the Higgs boson. It mapped quark-gluon behavior at energies no other machine could reach. It answered questions that had been open for fifty years.

But the LHC is centralized. CERN owns it. A handful of institutions control what gets studied. The data is vast but the governance is narrow. No individual scientist, no matter how brilliant, votes on what problem the collider works on next.

QCB is the decentralized version of that ambition — not a physical collider, but a computational one. Instead of accelerating particles, it accelerates verified human and machine intelligence toward the hardest open problems. Instead of CERN governance, it has on-chain governance where every verified human has a voice in which challenges get activated next. Instead of a single facility in Geneva, it is distributed across machines worldwide — every one of them attested, every result verified, every discovery hash-committed on a ledger no single institution controls.

The name carries that weight deliberately:

· Quark — the smallest known constituent of matter; the frontier of what physics has reached
· Charm — a quark flavor; and the agent coordination layer that directs work across the network
· Bit — the fundamental unit of computation; what every machine in the network contributes

QuarkCharmBit is not a name chosen for memorability. It is a statement of what the network intends to become: the first decentralized scientific instrument — a blockchain LHC, built from the ground up, owned by no one, and pointed at the hardest problems mankind has ever tried to solve.

First Simulation — GC-DEVNET-001 (2026-10-06)

Before the resource crate exists, before the chain runs at scale, the Grand Challenge discovery flow was simulated end-to-end on 2026-10-06. Three machines — Alice, Bob, Carol — searched parallel nonce ranges for a SHA256 hash of 'QCB:<nonce>' beginning with '0000'. Carol found nonce 6,682,026 in 15,361 checks. Dave independently reproduced the hash from the nonce alone and signed the verification. A full UsefulWorkReceipt with work_type ResearchContribution, machine signature, and verifier signature was produced and saved on-chain to the repository.

The coordination logic, the receipt format, and the independent verification flow are proven. What remains is the Rust implementation in chain-forge-resource, Ed25519 signing with real machine keys, and submission as an on-chain transaction. The path from simulation to devnet is a single crate away.

---

Useful Hash Commitments: Bitcoin's Energy, Pointed at Science

Bitcoin mining is the largest coordinated computational effort in human history. Millions of machines, running SHA256 around the clock, producing hashes that — by design — go nowhere. The hashes are not the product. They are a proof-of-work mechanism, a way of making block production expensive so that no one can rewrite history cheaply. The computation itself produces nothing beyond consensus.

QCB does not compete with Bitcoin's consensus model. It builds on the same hardware intuition — SHA256 ASICs and GPUs are abundant, widely distributed, and operated by people who understand hash rates, uptime, and work verification — and points that hardware at something real.

The mechanism is a Useful Hash Commitment.

When a machine completes a Grand Challenge contribution — a lattice simulation segment, a cryptographic search, a cosmological structure calculation — it needs to prove that it did the work and that the output has not been tampered with since. It does this by finding a nonce such that:

    seal_hash = SHA256(nonce || output_hash || challenge_id)

must begin with a target number of zero bits — a difficulty prefix. This is structurally identical to Bitcoin's mining loop. The same ASIC that finds a Bitcoin block can find a seal hash. The difference is what the hash seals: not an empty block header, but a scientific output.

The hash is not the product. The science is the product. The hash is a tamper seal — a cryptographic commitment that the output existed, unchanged, at the moment the seal was computed. A verifier does not repeat the full computation. It re-hashes once, checks the difficulty prefix, and then performs domain verification of the output itself (reproducing the simulation segment, checking the mathematical result, or running the cryptographic check — whichever the challenge track requires). Verification is cheap; the work was real.

The seal_hash field is added to UsefulWorkReceipt. Every Grand Challenge receipt carries it. Any independent party — another machine on the network, a domain expert, a light client — can verify both that the output was sealed at the right difficulty and that the seal matches the claimed output_hash.

BTC Block Hashes as a Randomness Beacon

QCB makes one additional, specific use of the Bitcoin network: as an unpredictable randomness source for Grand Challenge job assignment.

When a machine joins an active challenge track, it needs to be assigned a specific slice of the problem space — a nonce range to search, a simulation starting condition, a subproblem partition. That assignment has to be fair and tamper-resistant. If QCB itself picks the numbers, a malicious operator could steer easy slices to friendly machines or hard slices to competitors. If a machine picks its own slice, it can cherry-pick favorable regions of the search space.

The solution is to derive the assignment from something neither QCB nor any participant controls: a recent Bitcoin block hash. No one knows in advance what the next BTC block hash will be. Once it is produced, it is publicly verifiable, tamper-evident, and permanent.

    job_seed = SHA256(btc_block_hash || challenge_id || machine_id)
    assigned_slice_start = job_seed[0..8] as u64

This is not recycling Bitcoin's mining work — the discarded BTC hashes carry no information that can be repurposed. What QCB uses is the block hash as a public, unmanipulable beacon: a number that everyone can see, nobody predicted, and nobody influenced. The Bitcoin network produces it as a byproduct of its own consensus. QCB reads it as an entropy source.

This technique — using an external blockchain's output as a randomness beacon — is established practice in the broader blockchain ecosystem. QCB's application of it to distributed scientific job assignment, where fairness of slice allocation directly affects research integrity, is the specific use case that makes it valuable here.

Why This Opens the Bitcoin Ecosystem

Solo Bitcoin miners and small farms are structurally underserved by the current mining landscape. Pool consolidation has moved the economics toward large operators; a solo miner with a few ASICs earns erratically and with high variance. The SHA256 hardware sits idle between rare finds.

QCB's Grand Challenge daemon changes that equation. A miner points existing SHA256 hardware at a Grand Challenge job. The machine does real science — runs the assigned computation — then finds a seal hash at the target difficulty. It submits a UsefulWorkReceipt. If the result is verified, it earns uQCB (accumulating toward a full $QCB conversion) on top of whatever BTC mining it was already doing. The two are not in competition: a machine can run Bitcoin mining and a QCB Grand Challenge daemon simultaneously, allocating compute across both.

The audiences this reaches:

· Solo miners and small farms — SHA256 hardware earns a second income stream from verifiable science, not just block lottery tickets; uQCB accumulates into $QCB at 1,000,000:1
· BOINC veterans — people who already donate compute to SETI@home, Folding@home, and similar projects understand the model; QCB adds cryptographic accountability and economic reward
· Pool operators — a Grand Challenge resource pool mode for enterprise operators, with uQCB settlement to the pool, distributed to participants by hash-rate contribution
· The Bitcoin philosophy crowd — people who believe computational work should produce something real; the useful hash commitment is the answer to "what if mining did something"

The onboarding path is a machine daemon: a lightweight process that runs alongside existing mining software, pulls Grand Challenge jobs from the network, executes them in a sandboxed environment, and handles seal hash computation and receipt submission. The community portal shows real-time hash rate contributing to active challenges, uQCB earnings per terahash per second, live challenge leaderboards, and individual machine contribution history.

QCB is, in a meaningful sense, what Bitcoin would have been if Satoshi had known about the LHC. The proof-of-work loop — compute a hash until you find one with the right prefix — is the same. What changed is that the prefix is attached to something true.

---

uQCB Accumulation and the Path to Full QCB

Grand Challenge work earns uQCB — the micro-denomination of QCB issued as contribution credit. uQCB is the building block of the network's scientific issuance model: the only way to accumulate it is to do verified assigned work.

The Conversion Model

1,000,000 uQCB = 1 QCB

This mirrors Satoshi's design for Bitcoin: a micro-unit accumulates into the full coin. The ratio is fixed at the protocol level. A participant earning contribution credit is always building toward something whole — not just accumulating fractions with no clear destination.

Conversion is permissionless and on-chain. The moment a machine's uQCB balance reaches 1,000,000, the operator calls the conversion function. The protocol verifies the balance, burns the uQCB, and mints 1 QCB to the machine's registered address. No governance approval, no committee, no waiting period. The chain is the authority — if you earned it, you can convert it.

This is intentional. A governance gate would introduce friction, a trust assumption, and a human bottleneck that breaks down at the scale QCB is built for. At 100,000 machines all accumulating uQCB, no approval process survives.

uQCB Is Non-Tradeable

uQCB does not appear on the AMM. It cannot be bought, sold, or transferred between addresses. It is bound to the machine that earned it and redeemable only by that machine's registered owner.

This is a deliberate design constraint, not a limitation. If uQCB were AMM-tradeable, large holders could purchase accumulated contribution credit from small participants and convert it to QCB without doing any research. The scientific contribution — the actual thing the token is supposed to represent — would become a fiction. Non-transferability means the only path from uQCB to QCB is the one who earned it converting it themselves. The work and the reward stay with the same entity.

The Three Economic Loops

QCB's economic architecture has three interlocking loops, all denominated in $QCB (or its micro-unit uQCB):

· Resource Marketplace ($QCB) — Machine operators list resources. Buyers burn $QCB to purchase compute time. Operators receive $QCB via escrow-release on verified job completion. The commercial layer works independently of research activity and uses the same token as staking and governance.

· Grand Challenge (uQCB → QCB) — Machines contribute to assigned research slices. Verified UsefulWorkReceipts earn uQCB. At 1,000,000 uQCB accumulated, the operator converts permissionlessly to 1 QCB. The scientific layer issues QCB directly tied to research output — more QCB in circulation means more verified science was done.

· Both Simultaneously (MachineMode::Both) — The same GPU runs marketplace jobs during peak commercial demand and gc-daemon during off-peak hours. The operator earns from compute jobs and accumulates uQCB from the same hardware investment. Idle compute that would otherwise generate zero revenue is now generating research contributions and building toward a full QCB conversion.

The flywheel: more machines → more research throughput and more marketplace supply → more buyers attracted by competitive pricing → more $QCB flowing through the resource economy → more operators join → more machines. The Grand Challenge layer and the marketplace layer reinforce each other instead of competing.

$QCB as the Demand Signal Inside Grand Challenges

$QCB participates in the Grand Challenge on the demand side as well as the earning side. Machines earn uQCB for doing the work. $QCB is also how external value — from sponsors who need the science done — flows into the network and directs where compute goes.

Any participant can fund a Grand Challenge track with $QCB: a university accelerating a protein fold study, a biotech company that needs drug discovery results, a research foundation backing a physics problem, or an individual who wants a specific challenge prioritized. $QCB deposited into a challenge's reward pool is allocated across three destinations:

· Verifier rewards — independent machines that confirm submitted UsefulWorkReceipts earn $QCB for their verification work. This funds the accountability layer directly; verifiers are compensated by the sponsors who need accurate results, not by the protocol treasury.

· Discovery bonus pool — if a machine's assigned slice produces a confirmed breakthrough, the $QCB bonus is released on top of the earner's uQCB accumulation. The discovery bonus is a lottery ticket; the uQCB accumulation is the guaranteed return for doing verified assigned work.

· Priority queue funding — a sponsor who needs results faster can put $QCB behind a challenge track to attract more machines to it. $QCB becomes the signal that tells the network which problems are most urgently demanded. The market routes compute toward the highest-funded tracks.

This closes the economic loop between science and capital. A researcher with a grant, a company with a drug candidate, or a foundation with a mission can acquire $QCB and point it directly at the problem they need solved. The network routes machines. The machines do the work. The results come back verified and hash-committed on-chain.

$QCB is the language that turns scientific demand into compute supply. That is a funding mechanism no traditional research institution offers: more direct than grants, more transparent than contracts, accountable on-chain, and open to anyone with $QCB to spend.

Public Tracks and Private Commissions

Grand Challenge work runs on two tiers, both on the same infrastructure, using the same machines, the same receipt format, and the same verification flow.

Public tracks are governance-activated problems of humanity-scale importance — lattice QCD simulations, protein folding campaigns, cosmological structure modeling, dark matter candidate searches. They are funded by the protocol treasury and open sponsors. No single institution owns them. Any verified participant can contribute. Results belong to the public record.

Private commissions are side quests. A biotech company has a specific molecule they need modeled. A university has a computation too large for their own cluster. An individual researcher has a problem they are willing to pay to get solved. They deposit $QCB into a named challenge track, define the parameters, and the QCB distributed supercomputer picks it up. The network routes machines to the funded track. Machines complete assigned slices, submit UsefulWorkReceipts, and earn the same way they would on any public track.

The distinction is who asked and why — not how the work is done.

What private commissions provide that no cloud provider can match: the result comes back hash-committed, independently verified, and chain-of-custody accountable from assigned slice to confirmed receipt. A biotech company does not get an answer from a black box — they get a cryptographic proof that the computation ran as specified, that the output was not tampered with, and that an independent verifier machine reproduced it. Any auditor, regulator, or peer reviewer can validate the result from the on-chain receipt alone. AWS runs your computation. QCB proves it ran correctly.

The two tiers reinforce each other. Private commissions bring $QCB into the network from institutions and companies that need specific results. That $QCB funds verifiers, builds discovery bonus pools, and weights priority routing — the same mechanisms that serve the public tracks. A well-funded private commission pulls more machines onto the network, which deepens verifier coverage for the public tracks running alongside it.

The QCB distributed supercomputer does not choose between serving humanity and serving a paying client. It does both at once.

---

Equilibrium State: When the Network Becomes Alive

Reaching equilibrium is not a launch event. It is a threshold the network crosses — gradually, over years — as machines join, attestations accumulate, and the resource market deepens. No single moment marks it. But there is a point at which the network stops being something that requires active maintenance to stay alive and becomes something that sustains itself.

QCB defines Equilibrium State as the condition where:

· The validator set is large and geographically distributed enough that no regional outage, no coordinated departure, and no single bad actor can halt block production or reverse finality
· The machine population is deep enough that every active Grand Challenge track has sufficient independent verifier machines to confirm results without any track going dark for lack of participants
· The resource market has enough competing providers that no provider or cartel can price-fix $QCB resource rates or starve agents of capacity
· The anti-farming defenses have been battle-tested under real adversarial load and the contribution score is trustworthy enough to govern uQCB distributions without manual oversight
· The governance participation rate is high enough that protocol votes reflect the network's actual human base, not a mobilized minority

How long this takes is honest: years, not months. Bitcoin took years to harden. Ethereum took years to reach the validator count where its consensus felt genuinely robust. QCB accepts the same timeline. The difference is that QCB's architecture is designed for equilibrium from the first block — the MachineID registry, the ResourceExecutionReceipt accountability layer, the Grand Challenge tracks, the hard safety boundary — none of these are retrofits. They are load-bearing from day one, so that when the network reaches scale, the capability is already there.

What the Network Can Do Above Equilibrium That It Cannot Do Below It

Below equilibrium, the Grand Challenge is a research layer with limited throughput. Results take longer to verify. Fewer tracks can run simultaneously. The physics problems — the ones that require thousands of parallel verified runs — are out of reach.

Above equilibrium, the picture changes:

· Multiple Grand Challenge tracks run simultaneously with full independent verifier coverage
· Lattice QCD simulations, many-body quantum system modeling, and cosmological structure formation become tractable because the coordinated whole is large enough — not because any individual machine got faster
· Discovery throughput increases: more machines in Contribution Mode means more parallel work, more verifications per day, faster iteration on hard problems
· The network becomes genuinely self-healing: machines leave and rejoin without disrupting ongoing research jobs, because the redundancy is deep enough to absorb churn

This is what no other blockchain can offer. Other chains offer decentralized finance, decentralized applications, decentralized storage. QCB — at equilibrium — offers decentralized scientific discovery: verifiable, accountable, governed by the humans who built and operate it, pointed at problems that matter to all of them.

The scale required is large. The timeline is long. Both facts are stated here plainly, because the vision is only worth building toward if the foundation is honest about what it takes to get there.

---

1. What QCB Is

QCB Chain is a from-scratch Layer-1 blockchain, built on Chain Forge — a purpose-built Rust blockchain engine — rather than an existing chain framework. It provides four things no general-purpose chain offers natively, together, at the protocol layer:

1. Personhood-weighted BFT consensus — validator power tied to verified human identity, not stake or hashpower
2. Charm-based state confinement and agent representation — identity-scoped state and native support for autonomous agents as first-class chain citizens
3. A working monetary engine — $QCB is the sole protocol token, serving as both the resource access token (burn $QCB to submit compute jobs; network usage drives deflationary pressure) and the value-capture asset (held, staked, appreciated); uQCB accumulates from verified Grand Challenge work and converts permissionlessly to $QCB at 1,000,000:1; a five-control resource solvency architecture enforces capacity invariants; a separate resource token (QRC) exists as a prototype in `chain-forge-qrc` and may be introduced if resource pricing separation earns its complexity cost at scale
4. Full sovereignty — no dependency on another chain's consensus engine, module framework, or governance assumptions

QCB's purpose is to be the substrate for a charm-based agent economy where identity, state confinement, agent behavior, consensus power, and money circulation are all protocol-level concerns — not application-layer add-ons.

---

2. Why Build From Scratch

Frameworks like Cosmos SDK (via CometBFT) and Solana offer fast paths to a working chain, but both come with inherited assumptions QCB is not willing to accept:

· Stake-weighted consensus power — validator influence tracks capital, not verified humans. This directly conflicts with QCB's one-human-one-vote governance philosophy.
· Framework dependency — QCB's consensus safety would depend on another project's codebase, upgrade cycle, and maintainers, not its own.
· No native identity layer — proof-of-personhood would have to be bolted on as an application-layer concern, disconnected from consensus and governance.
· Shared infrastructure risk — bugs or exploits in a shared framework become QCB's risk, not just the framework's.

Building QCB from the ground up, in Rust, on its own engine (Chain Forge) removes all four constraints. The cost is real: this is a multi-year infrastructure project, not a fork-and-configure exercise. Bitcoin and XRP Ledger both took years to harden their original consensus designs under real adversarial conditions before being trusted with real value — QCB accepts the same timeline as the price of genuine sovereignty. The cost is not only development time — it is the competitive gap that opens while QCB builds from zero and existing L1s continue to harden and grow. Sovereignty has a price beyond the calendar.

---

3. Consensus: Personhood-Weighted BFT

3.1 The Mechanism

QCB uses a Byzantine Fault Tolerant consensus algorithm (BFT family — the specific implementation is being developed via Chain Forge, which is designed to support multiple pluggable BFT variants). What makes QCB's consensus novel is not the BFT algorithm itself, but how validator power is assigned:

Validator voting power is weighted by verified personhood, not stake.

Each verified human (per the identity layer in Section 4) can control a bounded amount of validator influence, regardless of how much QCB they hold. This directly ties consensus security to the same identity primitive that governs activity reward claims and governance votes — making "one human" a meaningful unit at every layer of the stack, not just in a voting module bolted on top of a stake-weighted base.

3.2 Why Not Proof of Work or Plain Proof of Stake

· Proof of Work is energy-intensive and settlement-slow — directly at odds with QCB's goal of fast, low-cost resource transactions.
· Plain Proof of Stake concentrates consensus power with capital, which conflicts with QCB's governance philosophy at the deepest layer of the system.

Personhood-weighted BFT is the design that makes "one human, one vote" true from consensus up through governance, not just at the surface.

3.3 Staking and Personhood Bounds

$QCB is the token staked to participate in consensus — it is the chain's security asset (see Section 6.3). However, stake size alone does not determine validator influence: no single verified human may exercise more than a fixed cap of total validator power, regardless of how much $QCB they stake. A human can stake more $QCB for yield, but cannot convert that stake into disproportionate consensus power. This is what makes the consensus layer "personhood-weighted" in practice, not just in name — stake determines participation and reward eligibility; personhood bounds determine actual influence over the chain.

The security of personhood-weighted BFT is bounded by the sybil resistance of the identity layer (Section 4). This consensus design does not solve identity — it inherits whatever weaknesses the identity layer has. If the identity layer can be gamed at scale, an attacker who controls many fraudulent "verified" identities can accumulate disproportionate validator power through the same mechanism intended to prevent that outcome.

---

4. Identity: Protocol-Level Proof-of-Personhood

Proof-of-personhood is not an application built on QCB — it is wired into the protocol itself, through Charm Confinement and Intrinsic Charm (Section 5). This is a deliberate departure from every existing PoP approach studied in the course of this design:

· Government ID + ZK proof — highest trust per dollar, but reintroduces the exact government dependency QCB is built to avoid.
· Biometric hardware (e.g., World ID's Orb model) — strong sybil resistance, but re-centralizes trust in a single hardware/corporate provider.
· Self-attestation ("click yes I'm human") — effectively no sybil resistance; incompatible with a system where identity gates activity reward claims, consensus power, and governance votes.
· Web-of-trust / social graph (e.g., BrightID, Circles) — no central authority, but gameable at scale without a strong backstop.
· Live human-intelligence ceremonies (e.g., Idena's synchronized validation) — no government or corporate dependency, real sybil-resistance properties, but with real friction and an open engineering challenge against well-resourced bot farms.

QCB's identity layer design has advanced past the research phase: the attestation guard mechanism (the on-chain sybil-resistance layer for the web-of-trust base) has been implemented through Phase D in `chain-forge-identity` and wired into the execution layer and node startup. The current direction — a decentralized web-of-trust base layer, strengthened by live-challenge ceremonies as a sybil-resistance backstop — is now code, not just design. It avoids both government and corporate control, consistent with QCB's sovereignty principle. This remains the single highest-risk open question in the entire system: every downstream mechanism (activity rewards, consensus weighting, governance, BME funding) depends on this layer holding up under real adversarial pressure. The attestation guard implementation is the first falsifiable step — a pilot that can now run against the concrete cost and sybil-rate targets below — before being treated as production-ready. See `docs/QCB-Attestation-Guard-Design.md` for the full guard design and `Section 11` for the Phase 0 checkpoint note.

As a starting point for those targets (illustrative, not final — subject to revision as the pilot is designed): a sybil rate below 3% under adversarial red-team testing, and a per-verification cost below $5 per verified human. Naming even provisional numbers here converts the pilot from a procedural commitment into a falsifiable one; see Open Question 1 for where these get finalized against real pilot data.

Important framing correction: 3% sybil penetration should not be read as "safe" in isolation. Quantitative modeling (Section 6.6) shows that whether 3% fraudulent identities pose a real threat depends heavily on legitimate governance participation — the same 3% fraud rate that's negligible against consensus safety (which tolerates fraud up to roughly 50% of the legitimate population) can dominate governance votes if legitimate turnout is low. The correct statement is: 3% is the maximum adversarial identity rate the initial identity pilot is designed to tolerate, subject to the governance participation and BFT safety models in Sections 6.6 and 3, not a number that is safe on its own terms.

---

4.5 The Identity Layer as Strategic Asset

The identity layer is described elsewhere in this document as a precondition — the thing that has to work before consensus, activity rewards, governance, and agent authorization can work. That framing is correct mechanically, but it understates what the identity layer actually is. It is not a dependency. It is the product. Everything else on QCB exists to make the identity layer valuable, and the identity layer makes everything else on QCB defensible.

This section names that explicitly, because the document otherwise distributes the argument across eight sections without stating the conclusion they add up to.

Four unique capabilities, all requiring identity

QCB offers four things no other chain offers, and every one of them requires identity verification:

Personhood-weighted consensus (Section 3) — validator power is bounded by verified human identity, not capital or compute. No other chain ties governance authority to verified personhood at the consensus layer. If you want to participate in a chain where one human's influence is structurally capped regardless of wealth, QCB is the only option, and it requires verifying as a human.

Resource economy (Section 6.2) — verified resource providers earn $QCB through VCA-attested contribution (via escrow-release on job completion), and resource consumers burn $QCB to submit jobs. $QCB is the single resource claim on network compute, storage, ZK proving, oracle queries, AI inference, and bandwidth. No other chain implements a native resource economy whose solvency is enforced by an on-chain CoverageRatio circuit breaker. If you want to participate in a network where resource access is priced, rationed, and governed at the protocol layer — with provider economics tied directly to attested capacity — QCB is the only option, and the contribution path requires verified provider status.

Charmed Agents with bounded authorization (Section 5.3) — autonomous agents are sponsored by verified humans, with cryptographic scoping of their economic footprint. No other chain has native agent identity with a human accountability chain. If you want to run an economic agent that a verified human is responsible for, QCB is the only option, and it requires a verified sponsor.

RWA issuance with protocol-level compliance (Section 7.2) — tokenized real-world assets on QCB are held by SponsorID-linked accounts, making KYC/AML compliance a property of the protocol rather than an external wrapper. No other chain provides compliance-at-the-protocol-layer as a native feature. If you want to issue tokenized securities without building a separate compliance stack, QCB is the only option, and it requires verified participants.

None of these capabilities can be replicated on another chain without changing that chain's fundamental architecture. That is what makes them a moat rather than a feature list.

The coupling principle

The identity layer has value only if it is coupled to the economy, and the economy has value only if it is coupled to the identity layer. Each direction of the coupling is a design decision:

Identity gates participation (already specified): activity rewards, consensus power, governance votes, Charmed Agent sponsorship, and Sponsored Contract deployment all require verified identity. A non-verified actor cannot access QCB's economic plumbing.

Participation maintains identity (not yet specified): verified humans who never claim activity rewards, never vote, and never transact may be able to hold verification indefinitely. If so, identity becomes a free-standing credential that other systems can query without the holder participating in QCB's economy. This decouples identity from the chain and turns QCB into infrastructure for other chains' benefit — a public good that QCB cannot capture value from. A liveness requirement — some minimum periodic participation (activity reward claims, governance votes, or $QCB resource transactions) to maintain active verification status — closes this gap. The specific requirement is an open question (Open Question 24), but the principle is a founding commitment: identity and economic participation are coupled in both directions, not just one.

The failure mode

If the coupling breaks in the participation-to-identity direction, QCB's identity layer becomes a public good: a proof-of-personhood API that other chains and applications query without compensating QCB or requiring their users to participate in its economy. The identity layer provides real value, but QCB captures none of it. This is the equivalent of the settlement layer becoming a public utility — structurally important but economically empty for the chain that built it.

The design has to prevent this through the liveness requirement above, not hope it does not happen. A chain whose strategic asset is its identity layer cannot afford to let that layer exist independent of the economy it is meant to anchor.

What this document does and does not claim

The whitepaper describes a mechanism: identity and economy are coupled, neither works without the other, and the coupling creates something no other chain has built. Whether that mechanism becomes valuable is an empirical question the pilot phases must answer — through the identity layer validation in Section 4, the merchant adoption in Section 8, and the RWA demand described in Section 8.2. The document does not claim QCB will become the identity layer of the broader ecosystem, or that every chain will need it. Those outcomes depend on whether the mechanism works as designed, and no whitepaper can determine that in advance. The claim is narrower and stronger: the mechanism is real, the coupling is intentional, and the pilot will determine whether it holds.

The identity is the door, and QCB's economy is what is behind it. A person who holds BTC, ETH, XRP, or SOL and wants the four unique capabilities described above — personhood governance, $QCB resource access and value capture, Charmed Agents, RWA compliance — verifies on QCB and participates. Their existing holdings are irrelevant to their verification; the identity is not a service their coins can access. It is a door that a person walks through, and what is behind it is QCB's own economy: the activity rewards they can earn, the agents they can run, the governance they can participate in, the assets they can issue with compliance built in. QCB does not want people's coins. It wants people, and the economy their participation creates is the thing that makes $QCB valuable. This is the inversion at the core of the design: most chains attract capital and hope people follow. QCB attracts people and the capital follows from what people do once they are here. Whether that inversion produces adoption is the empirical question that the rest of this document routes, correctly, to the pilot phases.

---

4.6 Strategic Directions: Three Phases, One Mechanism

Everything in this section is contingent on the identity layer pilot (Section 4) hitting its targets. If the pilot fails, this section describes directions that were considered and not pursued, not capabilities QCB has. That framing is deliberate — the document's discipline has been to name dependencies before claiming outcomes, and this section follows the same rule.

Subject to that caveat: if the identity layer holds up under adversarial testing, QCB has a three-phase strategy for becoming something larger than an activity rewards chain with good architecture. The three phases are the same mechanism pointed at three different markets in sequence.

The shared mechanism

QCB's identity layer answers verification questions: is this address a verified human, is this agent authorized, does this holder meet compliance requirements? Every external system that needs to answer a verification question is a potential consumer of QCB's identity layer. The three phases below are three markets where that question is being asked and where QCB's answer is structurally better than alternatives — not because it is more accurate, but because it provides the answer at the protocol layer rather than as a wrapper that has to be trusted separately from the chain.

Phase A: RWA compliance (near-term, post-EVM)

Market: RWA issuers who need verified holders for regulatory compliance. The traditional approach requires a separate KYC/AML stack, periodic re-verification, and a trust relationship between the issuer and the compliance provider. QCB's answer: every SponsorID-linked account is a verified human, and the verification is the protocol, not a wrapper. The issuer does not build a KYC stack; the chain provides one.

What this requires: the permissioned EVM (Phase 5+ in the roadmap), RWA-ready compliance primitives (issuer registry, jurisdictional flags, transfer restrictions on non-verified receivers), and one real issuer willing to build on QCB rather than a purpose-built RWA chain.

Success test: an RWA issuer uses QCB's identity layer as their compliance layer instead of building or licensing a separate one.

Failure mode: no issuer finds QCB's compliance primitives sufficient, or the regulatory posture (Open Question 5) is unresolved in a way that makes QCB-native compliance legally uncertain. The strategy stops at Phase A.

Phase B: Agent authorization (mid-term, post-AEI)

Market: external agent frameworks that need to verify which agents are authorized to act on behalf of which humans. The AEI (Agent Economic Identity) specification — SponsorID, CapabilitySet, SpendingLimits, ParentAgentID — provides a standard way to answer this question. An external system that accepts QCB's SponsorID attestations as authorization gets the same property QCB's own Charmed Agents have: a cryptographic guarantee that a verified human is accountable for the agent's actions.

What this requires: the AEI specification formalized (currently a design sketch in this document, not a protocol specification), agent-to-agent settlement in $QCB functional, and one external agent framework willing to reference QCB's SponsorID scheme rather than its own.

Success test: an external agent framework accepts QCB SponsorID attestations as its authorization mechanism, without requiring those agents to run entirely on QCB.

Failure mode: the AEI specification proves incompatible with how external frameworks model agent identity, or no external framework finds the QCB-native guarantee compelling enough to integrate. The strategy stops at Phase B.

Phase C: General proof-of-personhood standard (long-term, post-Phase B)

Market: any system that needs to verify a user is human — spam prevention, governance, AI-interaction controls, content authentication. This is the market the document's Section 4.5 explicitly declines to claim in advance. Phase C is only worth attempting if Phase B has demonstrated that external systems will integrate QCB attestations.

What this requires: a public attestation interface (any system can query "is this address a verified human" without learning which human), zero-knowledge proofs of identity properties (prove humanity without revealing identity), and at least one non-QCB system outside the agent or RWA verticals accepting QCB attestations as proof of humanity.

Success test: a system with no other connection to QCB — not an RWA platform, not an agent framework — accepts QCB attestations as its proof-of-humanity mechanism.

Failure mode: Phase B succeeds but Phase C's market turns out to use identity differently (wanting government-backed attestations, biometric proofs, or social-graph trust that QCB's web-of-trust model doesn't provide). The strategy stops at Phase C.

What the three phases are and are not

They are: a testable sequence where each phase uses the same identity layer infrastructure to serve a progressively larger market, and where each phase's success is a precondition for attempting the next.

They are not: a prediction that QCB will become the ecosystem's identity layer. Section 4.5's caveat applies here too — the mechanism is real, the sequence is coherent, and whether it produces adoption is what the phases are designed to determine. Writing the phases into the whitepaper is not a commitment to completing them. It is a commitment to attempting Phase A if the pilot succeeds, attempting Phase B if Phase A succeeds, and attempting Phase C if Phase B succeeds. At each step, the strategy is tested against reality before the next step is claimed.

The strategy is only as strong as the pilot. Everything above is downstream of the identity layer proving that it can detect sybils at scale, at a cost below $5 per verification, with a fraud rate below 3%. If the pilot misses those targets, Phase A never starts, and the strategic directions described here are archived as considered and not pursued rather than executed.

---

5. Core Protocol Modules

QCB has four native protocol-level components, implemented directly in the chain's own state machine rather than as smart contracts or SDK modules. Being protocol-level is not the same as being constitutional (Section 7.3): existing as native state-machine logic determines where these components run; the constitutional layer determines how hard they are to change. Charm Confinement and Intrinsic Charm's specific mechanics, and Charmed Agents' operating rules, are protocol-level but ordinary-governance-adjustable — they can be tuned as the system matures. Only the pieces named explicitly in Section 7.3 (the identity interface, the single-resource-token rule, and the sovereignty constraint) sit behind the higher constitutional bar. $QCB's resource economy parameters — conversion rate bounds, epoch cap coefficients, CoverageRatio thresholds, consumption burn fraction — are protocol-level and governance-adjustable (Section 6.6), but the single-resource-token rule they operate under is itself constitutional.

5.0 What "Charm" Means

"Charm" is QCB's term for a bundle of protocol-enforced properties — identity verification tier, decay-exemption credits, scope boundaries — that travel with a piece of state or an identity rather than being assigned or checked by an external application. A charm is intrinsic to what it's attached to, not a permission granted from outside it. The three modules below apply this concept in three different ways: confining state to its rightful context (5.1), attaching properties directly to identity (5.2), and extending first-class chain citizenship to autonomous agents (5.3).

5.1 Charm Confinement
Scoped state isolation at the protocol layer. Ensures identity-linked claims (such as activity reward claim rights) and agent-controlled resources remain bound to their defined context — one verified identity, one claim per epoch, with no cross-context leakage.

5.2 Intrinsic Charm
Properties treated as inherent to a piece of state or identity, traveling with it rather than being externally assigned. Proof-of-personhood attestations, verification tier, and decay-exemption credits are encoded as intrinsic properties that persist with an identity across the chain.

5.3 Charmed Agents
Native, first-class representation for autonomous agents on-chain. Merchants and activity reward distributors can operate as Charmed Agents — handling payment acceptance, fiat conversion, and daily distribution automatically, without being modeled as ordinary externally-owned accounts running arbitrary contract calls.

Scope note: as currently designed, Charmed Agents cover scheduled, rule-bound operational roles — merchant settlement and activity rewards distribution — not open-ended autonomous behavior. This is a narrower claim than "agent economy" in the title and Abstract might suggest; the broader vision (agents with more general decision-making scope, charm-scoped in richer ways) is a future-phase direction, not something this document specifies yet. What makes charm-scoping matter even for this narrower case is that agent state stays bound to its identity context (Section 5.1) rather than behaving as an unscoped, arbitrary contract account.

Sponsored Contracts (Section 7.2) are a distinct subclass of Charmed Agent and should not be confused with the operational roles described here. Sponsored Contracts cover developer-deployed Solidity contracts with a verified human SponsorID — arbitrary computation within QCB's identity constraints, not scheduled merchant or activity rewards operations. The subclass relationship means Sponsored Contracts inherit Charm Confinement's identity-binding guarantees (Section 5.1) and Intrinsic Charm's attestation properties (Section 5.2), but they are a Phase 5+ addition and their specific rules are governed by Section 7.2 and Open Question 23, not by this section.

Agent services as a demand engine: Section 7.2 already establishes, at the constitutional level, that only $QCB may be used for payment to Charmed Agents — this is not a tier or an option some agents opt into, it is a sovereignty constraint (Section 7.3) that applies to every Charmed Agent without exception, specifically to prevent the currency fragmentation that would result from some agents accepting substitutes. What is worth naming explicitly is what this constraint becomes as Charmed Agents grow more capable: every agent that does useful work — monitoring, research, recurring automation, agent-to-agent services — is a reason someone has to acquire and spend $QCB. The more useful the agent economy becomes, the more this constraint does real economic work. This is not a new restriction; it is the existing rule's consequence made explicit.

Two pieces of protocol infrastructure this implies, and does not yet have:

An Agent Service Registry — an on-chain directory where a Charmed Agent publishes its service description, its $QCB price (fixed or usage-based), its capability scope (bound by Charm Confinement, Section 5.1), and the SponsorID of the verified human accountable for it. Without this, agent services exist but are not discoverable at the protocol layer.

Payment primitives beyond a single transfer — the current design covers a discrete $QCB payment; it does not yet cover a streaming payment (pay continuously while a service runs) or a usage-metered payment (pay per unit of work). Recurring and metered agent services need one of these, and neither is specified yet.

Both are additive engineering work on top of `chain-forge-agents` — a registry module and new payment-primitive transaction types — not a change to the $QCB-only rule, which is already as strict as it can be.

What this section deliberately does not resolve: whether a sponsor should be required to maintain their own minimum $QCB resource activity to keep sponsoring high-value agents is a real incentive-design question, but it overlaps directly with the activity-based $QCB accrual idea recorded as Open Question 26(d) — attaching a $QCB-activity requirement to agent sponsorship, and rewarding $QCB activity with $QCB accrual, are close enough in shape that designing one without the other risks two uncoordinated mechanisms measuring the same thing differently. This is left unresolved here and flagged at 26(d) rather than decided in this section.

5.4 $QCB Resource Economy
$QCB serves as the chain's sole resource token — a redeemable claim on network resources as well as the network's value-capture and governance asset:

· $QCB is consumed to access network resources — compute, storage, ZK proving, oracle queries, AI inference, and bandwidth. The correct economic invariant is resource solvency: QCB_outstanding ≤ Capacity / CR_min (see Section 6.10).
· Two paths bring $QCB into a provider's wallet: (1) Resource purchase path — job submitters burn $QCB, which is pre-escrowed; on verified job completion the escrowed $QCB is released to the provider; (2) Grand Challenge path — machines doing assigned verified work earn uQCB, which converts permissionlessly to $QCB at 1,000,000:1. Providing resources does not automatically mint $QCB; provider payment is the release of $QCB already escrowed by the requesting party.
· There is no demurrage on $QCB balances. $QCB consumed in network resource usage previously triggered a 25% consumption burn (p_burn = 0.25); **this burn is suspended pending redesign of the escrow/revenue-split policy** (see §6.10 Control 4 and §6.10 Architecture Summary for rationale).
· A five-control resource solvency architecture enforces the invariant — dynamic conversion rate, epoch conversion cap, on-chain capacity tracking, consumption burn, and a CoverageRatio circuit breaker. See Section 6.10 for the full architecture and simulation-derived parameters.
· **QRC as future extension.** A separate resource token (QRC, prototyped in `chain-forge-qrc`) may be introduced if resource pricing genuinely needs to be separated from network ownership at scale. That complexity is not warranted until the single-token model's limitations are demonstrated empirically. `chain-forge-qrc` remains in the repository as a reference implementation; it is not active on-chain.

---

6. Token Economics

Note: everything in this section describes the tokenomics as designed. Their real-world behavior — particularly resource solvency (Section 6.10's five-control architecture) and the network's ability to fund meaningful burns — depends on the identity layer (Section 4) for VCA-verified provider attestation and on the network reaching meaningful resource utilization. See the Abstract for the dependency chain stated plainly.

QCB Chain operates with a single protocol token — $QCB — that serves dual functions: resource access (burn to use network capacity) and value capture (hold, stake, appreciate). uQCB is the non-tradeable micro-denomination earned from Grand Challenge work, bound to the earning machine, and convertible permissionlessly to $QCB. This is not a simplification that sacrifices economic coherence — it is a deliberate architectural choice to avoid the complexity and bootstrapping cost of a two-token model until that complexity is justified by scale.

6.1 Design Principle: Single Token, Dual Role

Most blockchain networks either force a single token to serve contradictory roles incoherently, or split into two tokens and inherit two-token bootstrapping costs (the resource token needs value before users want it; the value token needs utility before stakers want it). QCB takes a third path: a single token with explicitly different behaviors depending on how it is used.

Token | Resource role | Value role
$QCB | Burned to access network compute, storage, ZK proving, oracle, AI, bandwidth | Held, staked, appreciated; governance weight
uQCB | Non-tradeable earning unit; converts to $QCB at 1,000,000:1 | (not held — converted or bound)

The tension between spending and holding is real but manageable at QCB's current scale: the resource burn rate is set by governance and the five-control architecture (Section 6.10) ensures it remains proportional to actual capacity. A second token (QRC) has been prototyped for a future phase if resource pricing separation proves necessary at larger scale; see §5.4 and §6.5.

6.2 $QCB — The Resource and Value Token

$QCB is the chain's sole protocol token — a redeemable claim on network resources and the network's value-capture and governance asset. These roles are unified in a single token to keep the protocol simple at current scale.

**What this design replaces.** The earlier design included a separate resource token ("CIRFI — Circulating Finance", later renamed $QRC) using demurrage, population-linked daily issuance, and activity rewards to drive spending. That model has been superseded. QCB's current model carries no demurrage, no daily issuance to verified humans, and no UBI component. The correct economic frame is resource solvency — not monetary velocity.

**Two paths involving $QCB in the resource economy.**

1. **Resource purchase path (burn → escrow → release).** A $QCB holder submits a resource job. The required $QCB is burned from the consumer's account and placed in escrow. On verified job completion, the escrowed $QCB is released to the verified provider. **Provider payment is the release of pre-escrowed $QCB, not the minting of new supply.** The epoch cap (Section 6.10, Control 2) applies to total $QCB committed to the resource pool per epoch; escrow-release events do not increase outstanding supply.

2. **Grand Challenge path (work → uQCB → $QCB).** Verified compute nodes assigned to a Grand Challenge track — lattice QCD, protein folding, cosmological modeling, or other externally-funded scientific workloads — earn uQCB for each verified unit of work. uQCB is non-tradeable, bound to the earning machine, and does not appear on any AMM. At 1,000,000 uQCB accumulated, the machine converts them to 1 $QCB permissionlessly. This conversion mints new $QCB supply; it is the protocol's only new-supply event and is tied to real scientific output. External parties fund challenge tracks with $QCB; verifiers earn $QCB from the challenge fee pools.

**Consumption burn — suspended pending redesign.** The original design called for 25% of every consumed $QCB resource-spend to be permanently destroyed (p_burn = 0.25). **This consumption burn is suspended as of October 2026.** The rationale: under the escrow-release model, the $QCB a provider expects to receive has already been committed by the consumer at job submission; burning a fraction of it at settlement penalizes the provider for usage rather than the consumer, which inverts the intended incentive. The burn fraction, the escrow/revenue split, and provider payment timing will be redesigned together before the burn is re-enabled. See §6.10 Control 4 for the original mechanism and its suspension rationale.

**No demurrage on $QCB.** $QCB balances do not decay. The spending incentive on the resource side comes from the resource economy itself: you burn $QCB because you want network capacity, not because idle balances are penalized.

**Denomination.** The sole protocol base denom is `uqcb` (micro-QCB). Protocol-layer amounts are always in `uqcb`; wallets and interfaces display human-readable $QCB amounts at the appropriate scale. uQCB (micro-denomination from Grand Challenge earnings) is a separate off-ledger accumulator tracked per machine until the 1,000,000 threshold triggers an on-chain conversion to `uqcb`.

**$QCB resource value.** $QCB's resource-economy value is the value of the network capacity it redeems. The correct solvency measure is the CoverageRatio (Capacity / QCB_resource_outstanding) — this must remain at or above CR_min. See Section 6.10 for the five-control architecture that enforces resource solvency in $QCB terms.

**Resource path and VCA.** The VCA (Verifiable Contribution Attestation) mechanism provides the attestation infrastructure for provider eligibility on the resource purchase path. Providers submit `CapacityEvidence_v0` reports containing Byzantine-resistant median aggregation of resource measurements across the seven resource types (compute, storage, ZK, oracle, AI inference, bandwidth, and combined). The protocol uses these reports to verify provider eligibility for escrow-release settlements and to update the on-chain capacity measurement that the CoverageRatio and epoch cap depend on (Controls 2 and 3). Gaming the capacity reports inflates the denominator of the CoverageRatio and tightens the epoch cap — making the resource path less profitable, not more, which is a natural alignment between attestation honesty and provider economics.

6.3 $QCB Value Capture

$QCB is the network's value-capture and governance asset. Because it now also serves as the resource token (§6.2), its value drivers are unified rather than separated.

**Function.** Chain security (staking to validators), gas fees on QCB Chain, governance over protocol parameters, and capturing value from network resource activity.

**Supply.** $QCB has a fixed or capped supply from chain genesis. The only new-supply event is Grand Challenge conversion (1,000,000 uQCB → 1 $QCB), tied to verified scientific output. Supply contracts over time through resource-consumption burns (when the suspended p_burn is re-enabled) and staking lockups that remove circulating tokens.

**Staking.** $QCB holders stake to validators to secure the chain, earning yield from a portion of resource-economy fee flows, governance rights over protocol parameters, and consensus participation. Staked $QCB is the mechanism through which validator influence is exercised, bounded by proof-of-personhood (see Section 3.3).

**Burn-and-Mint Equilibrium (BME) — resource-consumption driven.**

Network usage burns $QCB: consumers burn $QCB to submit resource jobs → deflationary pressure on supply → value capture for holders. The BME engine is resource demand, not merchant settlement. The burn fraction p_burn (currently suspended, see §6.2) will apply to the $QCB committed per job when re-enabled.

Working definition — BME "live" vs. "speculative": BME is considered live, rather than speculative, once resource-consumption burns equal at least 1% of $QCB's daily circulating trading volume, sustained for 90 consecutive days. Below that bar, any $QCB price appreciation should be attributed to adoption expectations, not to realized BME activity — the two should not be conflated in external communication about the token. This threshold is provisional and revisable once real resource-volume data is available.

**$QCB value drivers (in the single-token model):**
- Resource demand: the more jobs submitted, the more $QCB burned → deflation
- Grand Challenge activity: verified scientific output drives the only new-supply path, aligning inflation with real work
- Staking yield: funded from resource-economy fee flows and Grand Challenge fee pools
- Governance premium: the asset that governs the chain carries governance value independent of resource demand

$QCB is not designed to be spent rapidly on small transactions — it is designed to be held, staked, and appreciated as network resource demand grows. If resource burn revenue is insufficient to fund meaningful burns at current scale, $QCB's value rests on adoption expectations — a condition the protocol treats as a transitional phase, not a steady state, and one addressed as a permanence risk in Section 12.

6.4 $QCB Value Flow

In the single-token architecture, value flow is internal to $QCB rather than between two separate tokens:

**Resource consumers** burn $QCB to submit jobs → $QCB placed in escrow → on verified completion, escrowed $QCB released to provider → when consumption burn is re-enabled, a fraction (p_burn) is permanently destroyed → supply contracts, scarcity rises, and price appreciates.

**Grand Challenge participants** (machines) perform verified scientific work → accumulate uQCB → at 1,000,000 uQCB, convert to 1 $QCB → new supply enters circulation, tied to real output rather than speculation.

**Stakers** lock $QCB to validators → earn yield from resource-economy fee flows and Grand Challenge fee pools → staked supply removed from circulation → scarcity reinforced.

The two roles of $QCB — resource access token and value-capture asset — are in constructive tension: spending $QCB on resources (when burn is re-enabled) is deflationary, rewarding holders who don't spend; but holders who do spend are what funds the resource economy that makes the token valuable in the first place. The five-control architecture (Section 6.10) manages this tension through dynamic conversion rates, epoch caps, and the CoverageRatio circuit breaker.

6.5 Why Single Token — and QRC as a Future Extension

The previous design proposed two separate tokens ($QRC for resource consumption, $QCB for value capture). That separation is now superseded. $QCB serves both roles at current scale.

**The trap to avoid — ATOM's experience.** The Cosmos ecosystem is instructive: ATOM's staking yield comes mainly from inflation, not real revenue. In 2024, ATOM earned only $426,000 from Interchain Security while its annual issuance cost was $367,000,000 — real revenue was 0.12% of inflation. A resource token with its own inflationary issuance risks the same dynamic: a large population earns the resource token daily; the token circulates but doesn't appreciate; holders face constant dilution; the value-capture asset (QCB) can't fund its burn engine if the resource token absorbs all the economic activity.

**Why single-token works here.** QCB's resource economy is not a mass-consumer payment layer — it is compute capacity pricing. Consumers burn $QCB to buy jobs; providers earn $QCB from escrow release; machines earn uQCB from Grand Challenges and convert at threshold. None of these require a second currency. The spending tension (using $QCB depletes holdings) is resolved by the escrow model: the consumer commits $QCB at job submission; the provider earns it on verified completion; the protocol's five-control architecture keeps resource capacity solvent without a separate resource currency.

**QRC as a named future extension.** If, at scale, resource pricing genuinely requires separation from network ownership — because the volatility of $QCB makes stable resource pricing impossible, or because on-chain resource demand grows so large that a dedicated resource token's epoch cap and conversion rate controls are needed to protect $QCB holders — the protocol may introduce QRC at that time. The `chain-forge-qrc` crate exists in the repository as a prototype and reference implementation. It is **not active on-chain** and is not a current design commitment. Any future introduction would require a governance vote and a formal token-separation proposal.

**One resource token, by design.** The protocol does not permit application-layer currency or resource-token issuance. Other tokens on the chain — NFTs, access tokens, community tokens — serve non-resource purposes and are explicitly not resource claims. This is a positive design commitment: the five-control resource solvency architecture (Section 6.10) only works if $QCB is the sole resource claim. Multiple resource tokens would split the value capture, make the CoverageRatio untrackable, and weaken $QCB's long-term thesis.

6.6 Governance

Governance operates on a one-human, one-vote basis for resource economy parameters (conversion rate bounds R_min/R_max, epoch cap parameters β_cap/λ_cap, CoverageRatio thresholds CR_halt/CR_resume, consumption burn fraction p_burn, uQCB conversion threshold), ensuring the resource economy's rules are set by its users, not by capital. $QCB holders govern parameters affecting the chain itself (validator set, gas fees, treasury allocation) — stake-weighted, consistent with the asset's role as network ownership, but bounded by the personhood weighting described in Section 3.3.

Why one-human-one-vote needs a quorum floor: with attacker vote share modeled as f / (p + f), where f is the fraudulent-identity fraction of the legitimate population and p is legitimate turnout, low turnout directly amplifies a fixed fraud rate's practical power — a fraud rate that's negligible against 50% turnout can approach majority control at 3% turnout. Consensus safety (Section 3) tolerates fraud up to roughly 50% of the legitimate population; governance has no such cushion unless turnout is bounded from below.

Deriving the quorum from the Section 4 target, rather than picking a number arbitrarily: solving f / (p + f) < 0.5 for QCB's target fraud rate (f = 3%) gives p > 3% — legitimate turnout above 3% is sufficient to keep a 3% fraudulent population from reaching a majority of votes cast on its own. Solving the same inequality against the 1/3 threshold relevant to blocking a supermajority vote (f / (p + f) < 1/3) gives p > 6% — turnout above 6% is needed to keep a 3% fraud rate from being able to block a two-thirds-approval vote (Section 7.3) by holding more than a third of votes cast.

QCB's governance therefore enforces three distinct protections, not a single quorum percentage:

1. **Participation quorum** — a minimum share of the total verified-human population must participate for a vote to be valid at all. For ordinary resource-economy governance, this floor is set above 3% (the derived majority-safety threshold); for changes requiring supermajority approval, it is set above 6% (the derived blocking-safety threshold). Both floors scale automatically if the Section 4 sybil-rate target is later revised — they are a function of the target, not a fixed constant.
2. **Approval threshold** — among votes actually cast, the percentage required to pass: simple majority for ordinary resource-economy parameters, two-thirds or greater for constitutional changes (Section 7.3).
3. **Absolute minimum voter count** — a percentage-based quorum alone is insufficient at scale: 10% turnout means 100,000 voters at 1 million verified humans, but 10 million voters at 100 million. QCB additionally requires a minimum absolute number of participating verified humans for sensitive parameter changes, so that a percentage-based quorum satisfied by a small absolute population is not treated as equivalent to the same percentage satisfied by a large one. The specific absolute floor is an open question (Open Question 15) rather than fixed here, since it depends on population scale data not yet available.

These three protections compose: a proposal needs the participation quorum, the approval threshold among those who voted, and the absolute minimum count, all three, to take effect. This is deliberately more conservative than a single quorum number, because the 6% and 3% derivations above are lower bounds calculated against QCB's current worst-case sybil target — they should be treated as floors to build margin above, not targets to hit exactly.

Limits of this model: the f / (p + f) derivation assumes fraudulent identities act as a single coordinated bloc and that legitimate turnout p is exogenous — independent of what the attacker does. Both assumptions cut in different directions. Treating fraud as one coordinated bloc is conservative: real Sybil populations that split, abstain strategically, or vote with legitimate blocs to avoid detection are less dangerous than the model assumes, so uncoordinated fraud is safer than these floors imply. Treating turnout as exogenous is not conservative: a sophisticated attacker can suppress legitimate turnout directly — spamming proposals, inducing governance fatigue, targeted discouragement of specific voters — which lowers p and raises the attacker's effective vote share without raising f at all. The quorum floors derived above should therefore be read as minimum protection against passive, uncoordinated fraud, not as sufficient protection against an active turnout-suppression campaign, which is a distinct attack surface this model does not cover. Until Open Question 17 is resolved, QCB's governance should be treated as defended against passive fraud only — turnout suppression is an accepted, named open risk during the pilot phase, not a solved problem. See Open Question 17.

6.7 Distribution

Clarification on scope: the genesis allocation has no daily-issuance formula tied to verified-human count. $QCB enters active resource circulation only through the two paths described in Section 6.2 — resource purchase (burn→escrow→release) and Grand Challenge contribution (work→uQCB→$QCB) — controlled by the five-control architecture (Section 6.10). The table below describes a one-time genesis allocation, funded from the initial $QCB supply, used to bootstrap development, validator participation, and a stability reserve before organic resource-burn volume is self-sustaining.

Allocation | Share | Illustrative % | Notes
Resource economy seed (genesis reserve contribution) | Majority | ~70% | Seeds initial $QCB liquidity for the resource purchase path before organic burn volume is self-sustaining; distributed to the resource pool and Grand Challenge tracks
Reserve pool | Minority | ~11% | Yield-bearing assets backing stability
Long-term distribution | Small | ~4% | Released to $QCB stakers and Grand Challenge participants over 8 years — see Section 6.9
Development | Small | ~7% | Vested, disclosed on-chain
Merchant incentives | Small | ~5% | Onboarding rewards, early-adopter bonuses
Validator rewards | Small | ~3% | Staking incentives for chain security

Illustrative percentages shown are non-final examples consistent with the ceiling below, not committed figures — percentages are of the total genesis allocation, whose absolute size (in $QCB or USD) is itself unset pending Open Question 7.

Distribution principle: this genesis allocation is designed so the resource economy seed (the majority allocation) goes toward bootstrapping the resource purchase and Grand Challenge contribution paths rather than toward any single interest group. For the allocations funded separately (development, merchant incentives, validator rewards, reserve pool), no single non-liquidity allocation is intended to exceed a low double-digit percentage of the genesis allocation — a ceiling meant to prevent any one interest group (founders, merchants, or validators) from accumulating outsized claims on the system's initial resources. Exact percentages within that ceiling remain to be finalized (see Section 12), but the ceiling itself, and the structural dominance of the liquidity seed, are intended as founding commitments rather than launch-day placeholders.

6.8 Summary

| $QCB | uQCB
Purpose | Resource access token + value-capture asset + governance | Grand Challenge micro-denomination; non-tradeable accumulator
Supply | Fixed or capped genesis supply; only new-supply path is Grand Challenge conversion | Off-ledger per-machine accumulator; converts to $QCB at 1,000,000:1
Demurrage | No | No (bound to machine until threshold)
Staking | Yes (chain security, governance) | Not applicable
Value driver | Resource demand (consumption burns); Grand Challenge scientific output; staking scarcity | Tied 1:1,000,000 to $QCB conversion value
Governance | Stake-weighted, personhood-bounded (chain params); one-human-one-vote (resource economy params) | Not applicable
Holder profile | Resource consumers, providers, stakers, long-term holders | Compute nodes performing Grand Challenge work
Appreciation | Primary goal | Tracks $QCB at fixed conversion ratio

$QCB is the sole protocol token: burn it to buy resources, hold it for value, stake it for governance. uQCB is the Grand Challenge accumulator that converts to $QCB on verified scientific output. QRC exists only as a named future extension if resource pricing genuinely needs its own token at scale.

6.9 Long-Term Distribution

The genesis allocation in Section 6.7 solves how QCB bootstraps before organic issuance and fee revenue are self-sustaining. It does not, on its own, solve a separate problem: with the entire 210 million $QCB cap minted at genesis, every unit is already spoken for on day one. A person who verifies and begins participating years into QCB's life has no path to $QCB that a person present at genesis didn't already have. For a chain designed to still be functioning long after its founders are gone (Section 7.3), that is a real legitimacy gap, not a cosmetic one.

The fix is not new issuance — the 210 million cap stays exactly as fixed and tested as it already is. The fix is a locked release schedule carved out of the existing genesis allocation: a portion is set aside at genesis and released gradually, over years, to verified humans who stake or lock $QCB (or meet participation criteria through Grand Challenge contribution), rather than being distributed to its final holders all at once.

This is deliberately not described as mining. Nothing is created; existing, already-capped supply is what moves. The correct category is a locked distribution schedule — the same category of mechanism as a vesting contract or a liquidity-mining program, both well-understood and non-controversial across other chains (Solana's multi-year release schedule, Ethereum's ICO-token vesting, Cosmos chains' validator and community-pool releases). None of those are described as mining, and neither is this.

Parameters:

Size — 4% of total $QCB supply (8.4 million $QCB), carved from the Reserve pool line in Section 6.7's genesis allocation (reducing it from ~15% to ~11% of the total genesis allocation). This keeps the mechanism well inside the "low double-digit percentage" ceiling Section 6.7 already sets for any single non-activity-rewards allocation.

Duration — 8 years.

Curve — linear, not decaying. This is a deliberate choice, not a default: Section 6.7's merchant incentives line already carries the "be early" incentive — rewarding merchants who onboard sooner rather than later. A decaying curve here (Bitcoin-style halving, front-loaded release) would duplicate that same message through a second mechanism aimed at a different audience. This mechanism's job is different: staying open to genuine latecomers for a meaningful stretch of QCB's life, not accelerating early participation. A flat, linear release is what actually keeps that door open for eight years instead of mostly closing it in the first one or two.

Mechanism — verified humans who lock or stake $QCB (or accumulate qualifying Grand Challenge uQCB conversions) receive a proportional share of the pool as it releases. The specific lock duration, minimum lock size, and proportional-share formula are implementation parameters, not fixed here; they are governed through the resource economy governance process (Section 6.6), not constitutionally.

What this is not: this section does not cover activity-based $QCB accrual — a related but distinct idea where $QCB is earned through measured $QCB economic activity (resource spending, Grand Challenge work, agent activity) rather than through locking a balance. That mechanism depends on unresolved questions this document is not yet in a position to answer, including — in one of its proposed forms — a dependency on Human Capacity Markets, which is itself unresolved. It is recorded as a named extension under Open Question 26, not specified here, and not treated as a second claim on this section's 4% allocation.

6.10 $QCB Resource Economy — Five-Control Architecture

The $QCB resource economy has two distinct paths for $QCB to flow to a provider. Section 6.2 describes both: (1) the **resource purchase path** (consumer burns $QCB → escrow → release to provider on verified job completion — a transfer, not new supply); and (2) the **Grand Challenge path** (machines earn uQCB for verified work → convert to $QCB at 1,000,000:1 — this mints new supply tied to scientific output). This section governs the resource purchase path through five controls.

The resource economy framing: $QCB committed to resource jobs is a redeemable claim on network capacity — compute, storage, ZK proving, oracle queries, AI inference, and bandwidth. The correct economic invariant is not price stability. It is resource solvency:

QCB_resource_outstanding ≤ Capacity / CR_min

If the network has committed more $QCB to resource claims than it can service at the target coverage ratio, the system is resource-insolvent regardless of price. The five controls below enforce this invariant.

Why this framing matters: a token-inflation lens misses the failure mode the v2 simulation uncovered — a scenario with only +1.5% supply growth and apparently stable monetary behavior, but a CoverageRatio of 0.005. The network had issued 200× more resource claims than it could service. Price and supply metrics showed nothing. Only the CoverageRatio showed the solvency collapse. The five-control architecture is designed to prevent exactly this.

Control 1 — Dynamic Conversion Rate

$QCB resource-purchase jobs are priced at a rate R_t that responds to network utilization:

R_t = R_0 × (U* / U_bar_t)^γ, clamped to [R_min, R_max]

where U_bar_t is an exponential moving average of utilization (smoothing parameter α = 0.10 prevents rapid rate oscillations), U* = 0.70 is the target utilization level, and γ = 1.5 controls the price sensitivity to utilization deviations. When the network is near empty (U_bar → 0), the price ceiling R_max becomes the binding constraint, preventing unlimited $QCB commitment at negligible resource cost.

Simulation-derived starting parameters: R_max = 2.0, R_min = 0.5. These values were determined empirically: stress tests showed that R_max = 5.0 allows +489% resource-claim growth under a sustained adversarial dump at near-zero utilization. R_max = 2.0 limits adversarial claim growth to under 6% — but the price ceiling alone is not the load-bearing safety mechanism. That role belongs to Control 2.

Control 2 — Epoch Resource Commitment Cap

The maximum $QCB committed to resource jobs in any epoch is bounded independently of price:

QCB_committed(epoch) ≤ L_e

This is the dominant safety control. An adversary cannot flood the resource pool with large commitments by exploiting low utilization and the price ceiling — the epoch cap limits total commitment volume regardless of rate. Simulation confirmed that with L_e = 1,000 QCB/epoch, a sustained adversarial dump of 5,000 QCB/tick is fully contained (CR_min = 0.999 over 200 epochs).

The epoch cap is adaptive by default:

L_e = β_cap × Capacity_e + λ_cap × Demand_e

where β_cap = 0.001 and λ_cap = 0.0005. The adaptive form automatically tightens when the network is empty: at near-zero utilization, Demand_e → 0, so L_e ≈ β_cap × Capacity — the cap scales with available resources rather than being fixed at a value that may be appropriate for one network size but wrong for another. This eliminates the adversarial exploit of committing into an empty network, because an empty network produces a small cap.

Control 3 — Capacity Tracking

$QCB resource claims depend on real network capacity. If the measurement of available resources is wrong, the solvency invariant cannot be enforced. Control 3 requires on-chain, per-epoch measurement of total active provider capacity across all resource types: compute, storage, ZK proving, oracle, AI inference, bandwidth. Provider capacity is not self-reported without check — the VCA mechanism (Section 6.2) provides the attestation infrastructure for this measurement.

This control is what makes CoverageRatio meaningful rather than circular: without independent capacity tracking, CR could be gamed by providers inflating their reported capacity. With it, outstanding $QCB resource commitments can be compared against real, attested resource availability.

Control 4 — Consumption Burn (**suspended October 2026**)

The original design called for a fraction p_burn of every consumed $QCB resource amount to be permanently destroyed:

QCB_burned = p_burn × QCB_consumed

At p_burn = 0.25, 25% of every resource-consumption event would be destroyed, creating a supply contraction proportional to usage.

**This burn is suspended as of October 2026, pending a redesign of the escrow/revenue-split policy.** The reason: under the escrow-release model for provider payment (§6.2), the $QCB a provider expects to receive is already pre-committed by the consumer at job start. Burning 25% of it at settlement time means the provider receives less than the consumer agreed to pay — the burn penalizes the provider, not the consumer, for the act of consumption. Burning money that providers expect to receive is economically wrong and misaligns provider incentives. Until the escrow settlement mechanics are finalized (who holds the escrow, when it releases, how fees are structured relative to the escrowed amount), the burn cannot be applied without distorting provider economics in ways that undermine the contribution path.

Simulation result (original model, for reference): at high utilization (U = 0.99) with p_burn = 0.25 and a moderate earn rate, the resource path became nearly self-canceling — $QCB earned ≈ $QCB consumed, and the 25% burn permanently contracted supply over time. This result was derived under the earlier minting model and must be re-evaluated once the escrow/revenue-split design is settled.

Control 4 will be re-enabled, potentially with a different split and timing, once the escrow and revenue-policy design is finalized. Until then, supply contraction from consumption is zero; the CoverageRatio circuit breaker (Control 5) is the primary solvency safeguard.

Control 5 — CoverageRatio Circuit Breaker (Resource Solvency Mechanism)

The CoverageRatio measures network solvency in resource terms:

CR_t = Capacity_t / QCB_resource_outstanding_t

This is not a monetary policy mechanism. It is a resource solvency mechanism. The distinction is important for QCB specifically: $QCB committed to resource jobs represents a claim on actual network capacity, not a speculative token. CR < 1.0 means the network cannot service all outstanding $QCB resource claims simultaneously. CR → 0 means the network is resource-insolvent — it has committed far more resource claims than it can honor.

The circuit breaker enforces a minimum coverage ratio through a three-state hysteresis machine:

State | Condition | Conversion | Contribution earn
NORMAL | CR ≥ CR_resume | Open | Open
RESTRICTED | CR_halt ≤ CR < CR_resume | Suspended | Open
HALTED | CR < CR_halt | Suspended | Suspended

The hysteresis band (CR_halt < CR_resume) prevents oscillation: without it, a single threshold would repeatedly switch minting on and off as CR hovers near the boundary. The contribution earn path remains open in RESTRICTED because providers should not be penalized for a capacity collapse they did not cause — only QCB conversion, the discretionary mint path, is suspended.

Simulation-derived starting parameters: CR_halt = 0.75, CR_resume = 1.00.

Why CR_halt = 1.00 was rejected: the recovery test (capacity collapses to 20% of baseline, then recovers to 100% over 400 epochs) showed that CR_halt = 1.00 / CR_resume = 1.25 results in minting never resuming within 400 ticks. The system cannot recover from realistic capacity shocks under those parameters. CR_halt = 0.75 / CR_resume = 1.00 resumes minting at t = 262, giving the system adequate headroom to recover from provider-exit scenarios without the circuit breaker becoming a permanent lock.

What the circuit breaker cannot do: it can halt new minting when capacity falls, but it cannot restore capacity. Provider exodus scenarios (Scenario 3 in the v3 stress test) saw CR → 0.027 despite the circuit breaker halting minting at tick 23. The breaker buys time and prevents supply accumulation during a capacity collapse — it does not rebuild the network. Real recovery requires providers to return or new capacity to join. The circuit breaker is one layer of protection, not a substitute for capacity incentives.

Architecture Summary

The five controls form a layered defense with the following separation of concerns:

Control | Mechanism | Protects against
1 — Dynamic price | R_t ∈ [R_min, R_max] | Mispricing under congestion or low utilization
2 — Epoch commitment cap | L_e = β_cap × Capacity + λ_cap × Demand | Resource-pool floods; adversarial dump at low U
3 — Capacity tracking | On-chain VCA-attested resource measurement | Resource over-commitment; measurement gaming
4 — Consumption burn | **SUSPENDED** (was p_burn = 0.25); to be redesigned with escrow/revenue policy | Persistent $QCB resource-claim accumulation; sybil farming (re-evaluate after escrow design settles)
5 — CR circuit breaker | CR_halt = 0.75, CR_resume = 1.00, three-state hysteresis | Capacity collapse / provider exodus

**Note on Control 5 (CoverageRatio) under the escrow-release model:** The CoverageRatio was designed primarily as a safeguard against unconstrained minting inflating outstanding claims beyond network capacity. Under the escrow-release model, provider payments do not increase outstanding $QCB resource supply (they release pre-escrowed amounts). The CR circuit breaker remains relevant as a solvency check on the resource purchase path (Controls 1/2) but its parameters and the definition of "outstanding" claims under escrow conditions are under re-evaluation. CR thresholds (CR_halt, CR_resume) remain unchanged for now; full re-evaluation is deferred until escrow settlement is wired.

The economic architecture (resource purchase path):

Consumer burns $QCB → escrowed for resource job → released to provider on verified job completion

(Consumption burn — previously `(p_burn) → destroyed` — is suspended pending redesign.)

and the safety boundary is:

CR < CR_halt ⟹ new resource commitments suspended

Simulation basis: the five-control architecture was validated through three simulation passes totaling 135 scenario configurations (qrc_stress_test.py, qrc_stress_test_v2.py, qrc_stress_test_v3.py in the chain-forge-engine repository). The parameters above are simulation-derived starting values, not immutable economic constants. The core protocol invariant — zero ticks where commitment was allowed while CR < 0.10 — was verified across all 15 main scenarios in the v3 sweep. **Note: these simulations were run under the earlier contribution-minting model. Control 4's suspension and the switch to escrow-release for provider payments (§6.2) invalidate the simulation scenarios that depend on p_burn > 0; Controls 1, 2, 3, and 5 remain valid. A new simulation sweep is needed once the escrow/revenue-split design is settled.** Governance may adjust all parameters in this section (Controls 1–5 thresholds) through the resource economy governance process described in Section 6.6.

---

7. Sovereignty, Execution Environment, and the Constitutional Layer

7.1 The sovereignty constraint

QCB Chain is designed as a self-contained Layer-1. There are no bridges, no interoperability connections, and no wrapped assets in the initial architecture. This is intentional: interoperability introduces attack surface, identity leakage, and governance complexity that conflict with QCB's core design — one verified human, one vote, at every layer of the stack.

Interoperability is deferred to a future phase and will only be pursued if a bridge design can preserve proof-of-personhood end to end. Any bridge that would allow unverified actors to hold or use $QCB is architecturally forbidden — this is the specific, narrow thing "forbidden" refers to, not a blanket ban on ever building a bridge. This constraint will be revisited only after the chain is live and stable, merchant adoption is real, the identity layer has survived adversarial pressure at scale, and there is a concrete reason to interoperate.

7.2 Permissioned EVM layer

QCB absorbs EVM capability natively rather than bridging to an EVM-compatible chain. The distinction matters: bridging to Ethereum or an EVM chain violates the sovereignty constraint and allows unverified actors into the system. Running a permissioned EVM execution environment inside QCB — where the EVM is subject to QCB's identity layer rather than bypassing it — does not.

The design is inspired by Flare Network in the general sense: an EVM environment that is not simply a clone of Ethereum's assumptions — one that operates under additional protocol-layer constraints rather than inheriting the anonymity and permissionlessness of the original EVM. The specific constraint QCB applies is its own: identity linkage through Charm Confinement (Section 5.1). EVM contracts on QCB are Sponsored Contracts — a subclass of Charmed Agent — not anonymous accounts. Every Sponsored Contract has a SponsorID linking it to a verified human, and the sponsor is accountable for the contract's behavior under QCB's governance model. Every contract must have a SponsorID linking it to a verified human, every $QCB transfer in or out of an EVM contract passes through the protocol's identity checks, and no EVM contract can hold or issue tokens that bypass $QCB's sole-resource-token status or governance layers.

Why EVM on these terms is worth having: the EVM is the largest smart contract developer ecosystem in existence. Solidity developers can deploy on QCB without learning a new language, provided they are deploying code that does not depend on anonymous counterparties or excluded opcodes (see Open Question 23(e) — the opcode subset question is not yet resolved, and full EVM equivalence is not guaranteed). Existing wallets (MetaMask and equivalents) work with QCB's EVM layer for accounts that are SponsorID-linked. DeFi protocols, NFT systems, and autonomous agent frameworks built for EVM chains can be ported to QCB with the caveat that every participant must be sponsor-verified — they inherit QCB's identity constraints rather than importing EVM's anonymity assumptions.

Why general EVM without identity constraints would break QCB: an anonymous EVM contract can receive $QCB, pool it, and issue synthetic tokens against it — effectively creating a shadow resource economy that bypasses the identity layer without requiring a cross-chain bridge. The same attack that bridges enable (unverified actors accessing $QCB as a resource claim substitute) can be executed entirely on-chain through an anonymous contract. A permissioned EVM prevents this: every contract is sponsored by a verified human, and the sponsor is accountable for the contract's behavior under QCB's governance model.

The permissioned EVM layer is a Phase 5+ addition — not because the concept conflicts with QCB's design, but because it depends on the identity layer being proven at scale first (Section 4). The identity layer must be able to reliably link EVM accounts to verified humans before anonymous EVM contracts become a gating risk. Adding EVM before identity is proven would give the EVM layer's anonymity assumptions priority over QCB's identity guarantees, which inverts the dependency. See Open Question 23.

What the permissioned EVM does and does not enable:

Enabled: Solidity smart contracts sponsored by verified Charmed Agents; EVM-compatible wallets interacting with QCB accounts linked to verified identities; DeFi protocols operating under QCB's demurrage and governance rules; autonomous agent frameworks using EVM tooling within Charm Confinement boundaries; asset tokens — tokenized real-world assets including securities, Treasuries, commodities, real estate, and private credit — issued and held under the same SponsorID and non-currency rules that govern all application-layer tokens. Asset tokens represent ownership of an underlying asset; they are not mediums of exchange, and RWA transactions on QCB are denominated in $QCB (the asset token is what is being bought or sold, not the settlement currency). QCB's identity layer provides compliance-at-the-protocol-layer for RWA issuance — every holder is a verified human with a SponsorID — which is the property that traditional RWA platforms spend the most effort achieving through external KYC/AML wrappers. The role of RWA trading as a potential demand source for $QCB is a future-phase consideration; the merchant settlement layer has been deferred (Section 8).

Not enabled: anonymous EVM accounts; contracts without a SponsorID; synthetic tokens that substitute for $QCB as a resource claim or that bypass QCB's single-resource-token rule; governance votes from EVM contracts rather than from the verified human sponsors behind them; EVM-based bridges to external chains that import unverified actors.

Currency issuance reserved to the protocol: Sponsored Contracts can issue non-currency tokens — utility tokens, access tokens, NFTs, community tokens, meme coins — but cannot issue tokens designed to function as a medium of exchange. Currency issuance on QCB is reserved to the protocol itself, in the same way that identity verification is reserved to the protocol. This is enforced at the protocol layer: only $QCB can be used for resource escrow, Charmed Agent settlement, Grand Challenge funding, and payment to verified providers. Non-currency tokens are excluded from QCB's economic plumbing — they can exist and trade, but they cannot access the mechanisms (resource economy, Grand Challenge tracks, agent infrastructure) that give $QCB its utility. A token that bypasses these mechanisms exists in a parallel economy without active earners or resource access; it is, functionally, a collectible with a ticker rather than a currency. The protocol cannot prevent all informal peer-to-peer use of arbitrary tokens, but it does not need to: the economic plumbing is what makes $QCB valuable, and nothing else gets that plumbing.

What the permissioned EVM cannot build: the class of DeFi primitives that depend on anonymous counterparties — permissionless automated market makers, lending pools with unlinked borrowers and lenders, composable derivatives where participants are not individually verified — cannot be built on QCB's permissioned EVM, because every participant must be sponsor-verified. This is a real reduction in what "EVM compatibility" means relative to Ethereum. QCB's EVM is compatible with Solidity as a language and with EVM tooling as an ecosystem; it is not compatible with Ethereum's permissionlessness as a design principle. A developer porting a project from Ethereum should expect to rethink any component that relies on anonymous participation before it can run on QCB.

Identity-layer coupling: every EVM state transition in QCB requires a SponsorID check against the identity layer. This means identity-layer availability is EVM availability, and identity-layer throughput is an EVM throughput ceiling. Section 3.3 established that consensus security inherits identity-layer weaknesses; the permissioned EVM extends that inheritance to the execution environment as well. This is a deliberate cost of the permissioned model — the alternative is an anonymous EVM, which the sovereignty constraint forbids — but it is a coupling, not a free abstraction. An identity-layer outage or performance degradation affects EVM execution directly.

Scope: the permissioned EVM is orthogonal to the merchant settlement layer (deferred — Section 8) and does not change $QCB's external value proposition or the resource-economy bootstrapping requirement. Adding an EVM execution environment adds a familiar development surface for building on QCB's economy; it does not add a reason for that economy to exist. $QCB's resource demand (from compute job burns and Grand Challenge funding) remains the load-bearing economic driver, regardless of what execution environment sits above it.

7.3 The Constitutional Layer

QCB is designed for long-term survival — past any single development team, jurisdiction, or identity method. That requirement is different from designing for launch, and it demands a layer of rules that sits above ordinary governance.

Ordinary governance changes parameters: decay rates, fee levels, exemption thresholds, treasury allocation. The constitutional layer is different — it defines what cannot be changed by ordinary governance, and the specific, higher-bar process by which it can be changed if it must be. Other durable chains have such a layer too, even where it's informal and enforced only by social consensus rather than being written down explicitly. QCB's is explicit, because QCB has more interdependent parts that need to survive longer.

What lives in the constitutional layer:

· The identity primitive's replacement mechanism — not the current PoP method itself, but the guarantee that it can be replaced if it fails, is gamed, or is made obsolete by new technology, without forking the chain, losing state, or invalidating existing verified claims and activity rewards history.
· The cryptographic-primitive replacement mechanism (Section 10) — structurally identical to the identity-primitive replacement mechanism above: not any specific signature algorithm, but the guarantee that the signature scheme securing accounts, validators, and identity proofs can be replaced — most urgently in response to quantum-computing advances — without forking the chain or invalidating existing account history.
· The single-resource-token rule ($QCB is the sole protocol resource and value-capture token; QRC may be introduced by governance only if resource pricing genuinely requires separation at scale, and only after a formal governance vote — it is not active on-chain) — this is foundational to the economic model, not a parameter to be tuned.
· The sovereignty constraint — three related commitments that form a unified whole: (a) no bridge or interoperability path that allows unverified actors to hold or use $QCB; (b) no EVM execution environment that allows anonymous accounts (accounts without a verified SponsorID) to hold, transfer, or govern $QCB — the permissioned EVM layer (Section 7.2) is explicitly carved out as constitutional-compliant because it enforces SponsorID linkage; and (c) no token issued on QCB may function as a resource-claim substitute for $QCB — resource-token issuance is reserved to the protocol, and no application-layer token may substitute for $QCB in QCB's economic plumbing (resource escrow, Charmed Agent settlement, Grand Challenge funding). The three constraints reinforce each other: bridges, anonymous accounts, and parallel resource tokens are all vectors for the same attack — allowing unverified or unaccountable actors to access the economic mechanisms the identity layer is designed to control.
· The amendment process itself — what supermajority, what verification-of-humans threshold, and what waiting period is required to change anything in this layer.

What does not live here: decay rates, fee percentages, exemption thresholds, treasury allocations, and other tunable parameters remain ordinary governance — adjustable by the one-human-one-vote process described in Section 6.6, without the higher bar required for constitutional change.

How the constitutional layer is enforced: hybrid, and honestly so. Ordinary governance transactions are code-restricted from touching constitutional values directly — no standard parameter-change vote can alter the identity-replacement mechanism, the two-token split, or the sovereignty constraint. But as with any permissionless chain, code enforcement has a ceiling: validators could still, in principle, agree to run modified client software that ignores these restrictions — the same way Bitcoin's 21 million cap or Ethereum's Merge were ultimately upheld by social consensus, not by any barrier a sufficiently coordinated majority couldn't route around. QCB does not claim its constitutional layer is unbreakable. It claims that breaking it requires an explicit, visible, and deliberately difficult act — not an ordinary governance vote — and that this friction is the actual protection, consistent with how every durable chain's hardest constraints have worked in practice.

Amendment process (sketch, to be finalized): a constitutional change requires (a) a supermajority of verified-human votes substantially higher than the threshold for ordinary governance — proposed at two-thirds or greater — (b) a minimum quorum of total verified humans participating, derived in Section 6.6 (see that section for the derivation): not the 3% majority-safety floor used for ordinary resource-economy governance votes, but the stricter 6% blocking-safety floor Section 6.6 sets for supermajority-approval changes, per the f / (p + f) < 1/3 condition against the Section 4 sybil-rate target, plus the absolute-minimum-voter-count protection from 6.6 rather than a percentage alone, and (c) a mandatory public waiting period between proposal and execution, giving the network time to review, contest, or exit before the change takes effect. Exact thresholds remain an open question (Section 12), but the shape — higher bar, broader participation, enforced delay, all three of 6.6's protections applied at the higher constitutional bar — is intended to be a founding commitment.

The purpose of this separation is specific: a chain intended to last for generations cannot depend on any single identity method surviving decades of adversarial pressure unchanged. The current identity layer (Section 4) is a design choice, not a permanent commitment — the constitutional layer's amendment process is what makes it replaceable without the chain itself dying alongside it.

Interface vs. implementation: what is constitutional is the identity interface — the contract any proof-of-personhood method must satisfy (a uniqueness guarantee per human, no single party able to unilaterally control verification, and a bounded, disclosed verification cost). The current implementation (Section 4's web-of-trust base with live-challenge backstop) is not itself constitutional — it can evolve under ordinary governance as pilot results, sybil-rate data, and better methods become available, so long as it continues to satisfy the interface. Only a change to the interface itself — the underlying guarantees, not the specific mechanism delivering them — requires constitutional amendment. This distinction is deliberate: constitutionalizing the current, unvalidated implementation would risk ossifying a design before it has been tested against real adversarial pressure.

---

7.4 Chain Forge — The Foundation Beneath QCB

QCB Chain is the first chain built on Chain Forge, a from-scratch Rust blockchain engine with a pluggable consensus architecture supporting multiple BFT algorithm variants. The two projects are related but distinct, and worth being explicit about:

Dimension | Chain Forge | QCB Chain
What it is | The engine — a Rust blockchain-building toolkit | The first chain built with that engine
Audience | Developers building their own sovereign chains | Verified humans, merchants, agent operators
Purpose | Infrastructure — makes sovereign, from-scratch chains possible without each builder re-solving consensus from zero | Flagship — proves the infrastructure works under real conditions
Lifespan | An ongoing engine, evolving with each chain built on it | Intended to outlast any single team or founder
Relationship | Foundation | First building on that foundation

Chain Forge's current priority is its consensus module — building out multiple pluggable BFT variants (Tendermint-style, HotStuff-style, and an XRPL-inspired agreement model) so that QCB, and any future chain built on the engine, can select the algorithm that fits its needs rather than inheriting one hardcoded choice. QCB's personhood-weighted BFT (Section 3) is one configuration of that engine, not a separate codebase — validating Chain Forge's pluggable design is itself part of what QCB's launch needs to prove.

**Phase 0 progress as of September 2026.** The Chain Forge consensus engine has crossed its first major milestone: a 4-node Tendermint-style BFT testnet is producing and committing blocks under real network conditions. Specific achievements confirmed on the development network:

· **Tendermint consensus operational.** A `chain_id`-aware TendermintEngine is live in `chain-forge-node`. The prior bug where `chain_id` was never set in `init()` — which caused silent consensus failures across multi-node networks — has been identified and fixed. Nodes now correctly scope their vote sets to their configured chain ID, preventing cross-chain vote contamination.

· **Real libp2p P2P networking.** The `--features real-network` build flag activates genuine libp2p peer-to-peer communication in place of the mock transport used during unit testing. Four nodes (Alice, Bob, Carol, Dave) have been demonstrated exchanging consensus messages and reaching quorum across a local network, with peer counts visible via the `/api/status` REST endpoint.

· **4-node genesis with configurable quorum.** The tested configuration (4 validators, quorum=3) matches a standard BFT fault tolerance of f=1 — the chain continues producing blocks with 3 of 4 validators, providing a meaningful liveness-under-attack test surface.

· **Partition tolerance and recovery verified live.** A hard TCP-level network partition was applied to Alice's P2P port using iptables DROP rules (not a polite disconnect — all packets silently discarded). During the 5-second partition hold, Bob, Carol, and Dave continued committing blocks (height 3 → 7) using the 3-of-4 quorum, with no chain halt, no fork, and no loss of finality. When the partition was healed, Alice synced from height 3 to 7 in under 2 seconds and resumed consensus participation — with zero manual intervention. This is the first time the whitepaper's BFT fault-tolerance claim (f=1, Section 3) has live evidence behind it, and it confirms the `pending_certs` recovery path introduced in an earlier session works correctly under real network conditions. The partition recovery path is also the node catch-up path: this result incidentally proves that a fresh node joining an existing network can bootstrap from peers, a prerequisite for the Phase 4 / Phase 5+ permissionless validator onboarding design.

· **ValidatorRegistry fix: genesis validators activated at startup.** `ValidatorRegistry::qcb_devnet()` previously created an empty registry, causing the slashing module to silently return `Ok(None)` for every liveness-tracking call. The fix registers all genesis-account validators at node startup and calls `confirm_pop()` to activate them, so the slashing module has a fully-populated, active registry from block 1.

· **Liveness slashing confirmed working.** Stopping a validator mid-run produces the expected sequence: the slashing module detects >20% missed blocks within the liveness window, emits a jailed warning, applies a 1,000,000 uQCB slash, and records the event in slash history.

· **Attack tests passing (in-process).** Three adversarial scenarios covered by in-process integration tests: forged vote rejection (garbage-signature vote does not advance consensus height), equivocation detection and slash (two conflicting prevotes from same validator trigger a slash record), and liveness slash (confirmed on live testnet above). Note: these tests inject events directly into the consensus engine's internal event handler. The corresponding gap — a misbehaving peer sending forged or equivocating messages over real libp2p gossip — has not yet been exercised. That test is the next adversarial milestone.

· **ML-DSA (Dilithium3) post-quantum crypto wired.** The `chain-forge-crypto` crate implements CRYSTALS-Dilithium3 (ML-DSA) as the validator signing scheme, addressing the post-quantum exposure described in Section 10.

· **Block explorer REST API live.** `/api/status`, `/api/blocks/`, `/api/txs/`, and `/api/accounts/` serve live chain state on every block commit.

· **State persistence.** Committed blocks are written to disk on every commit; restarted nodes resume from their last committed height.

· **$QCB resource economy prototype implemented (`chain-forge-qrc`).** The token previously named CIRFI (Circulating Finance) was renamed $QRC (Quark Resource Credit) throughout the codebase — Rust sources, TOML manifests, markdown docs, and simulation scripts. The `chain-forge-qrc` crate implements the resource economy prototype: `QrcEngine` (dynamic conversion rate, epoch commitment cap, CoverageRatio circuit breaker); `contribution_settlement` (VCA-verified provider earn path); and the `CapacityEvidence_v0` sub-protocol (Byzantine-resistant median aggregation of provider capacity reports across 7 resource types). The consumption split (60% providers / 25% burn / 15% reserve) and per-resource congestion pricing are wired. `QrcEngine` is serde-serializable and persisted to `qrc.json` across node restarts. 65+ crate-level tests passing; three adversarial network integration tests remain pending live-TCP infrastructure. **Note:** the two-token QRC architecture this crate prototyped has been superseded by the single-token $QCB model described in §6.2–§6.5. `chain-forge-qrc` remains in the repository as a reference implementation; it is not active on-chain.

**BFT variant status (October 2026):** All three planned consensus variants are now implemented and tested:

· **Tendermint-style BFT — ✅ complete** (live 4-node testnet, partition tolerance confirmed, described above)
· **HotStuff-style BFT — ✅ complete** — the HotStuff variant is implemented in Chain Forge with a pipelined two-phase commit. 17 unit/integration tests passing.
· **XRPL-inspired Federated Byzantine Agreement — ✅ complete** — the FBA variant with configurable quorum slices is implemented. 18 unit/integration tests passing.

All three variants share the same pluggable `ConsensusEngine` interface, confirming the architectural premise that QCB can select its consensus algorithm independently of the application layer.

What remains open at the Chain Forge layer: production-grade state tree (JMT-based); personhood-weighting overlay; dedicated Chain Forge whitepaper. The three BFT implementations provide the working baseline for the personhood-weighting overlay (Phase 1).

A dedicated Chain Forge whitepaper, aimed at the developer audience who would build their own chains on it, is expected once the engine is closer to a general release. For now, this document is the only public artifact and carries both the engine's story and the flagship chain's.

---

8. Merchant Integration — Deferred

**Merchant acceptance is not part of QCB's current design phase.** The prior design included a fiat settlement layer, a Stripe-compatible merchant API, and a value loop driven by merchant fee revenue funding $QCB buyback-and-burn. That architecture has been removed.

$QCB's demand driver is resource consumption, not merchant payment volume. Every resource job — AI inference call, ZK proof, oracle query, storage operation, compute task — requires $QCB. The resource economy is QCB's primary and sufficient demand source at current scale.

**Why merchants were removed.** The settlement layer was the load-bearing piece: without a fiat settlement mechanism, merchant acceptance of $QCB collapses; without merchant acceptance, the BME loop funded by merchant fees collapses; without that loop, $QCB's value-capture thesis depended on a complex, legally fraught, and capital-intensive infrastructure that hasn't been built. In a single-token architecture where $QCB already captures value through resource burns and Grand Challenge output, the merchant layer adds complexity without adding a new demand source that the resource economy doesn't already provide.

**Future phase.** If the resource economy alone proves insufficient to sustain $QCB demand at large scale — or if real-world-asset (RWA) trading denominated in $QCB creates a natural path to merchant-adjacent settlement — merchant integration may be introduced as a named extension, subject to a governance vote. The design questions from the prior architecture (Open Questions 18–22 on reserve sizing, rate stability, settlement governance, burn/settlement interaction, and cold-start funding) are archived below in Open Questions rather than being active design commitments.

---

9. Supporting Infrastructure

9.1 React Explorer — a web-based block explorer for human users. Beyond standard chain data (blocks, transactions, addresses), it surfaces module-specific state that a generic Cosmos or Ethereum explorer wouldn't have anywhere to show: Charm Confinement boundaries (which identities hold which scoped claims), Intrinsic Charm attestations (verification tier, decay-exemption credits), Charmed Agent activity (which agents are operating and what they've executed), and $QCB resource economy metrics (resource jobs submitted, tokens burned via BME, Grand Challenge uQCB accumulated, CoverageRatio). Its primary users are verified humans checking their own claims and balances, merchants reviewing settlement history, and outside observers auditing the chain's economic activity.

9.2 Python Agent OS Backend — the runtime environment autonomous agents use to interact with QCB. It handles agent lifecycle (registration as a Charmed Agent, credential management, uptime), decision logic (the rules or models an agent executes — e.g., a resource-job-submission agent batching compute jobs on a schedule, or a Grand Challenge contribution agent executing work slices and submitting UsefulWorkReceipts), and the actual chain interaction (submitting transactions, reading state) on the agent's behalf. It is deliberately separate from the human-facing Explorer, since agents and humans have different interfaces to the same underlying protocol state.

9.3 Resource API — a REST API for resource consumers to submit jobs, check job status, and query provider capacity without direct chain interaction. Consumers never touch private keys or gas directly — the API handles job submission, $QCB escrow authorization, and completion attestation. A merchant-payment variant of this API (Stripe-compatible, with Shopify/WooCommerce plugins) is a named future extension if merchant integration is introduced in a later phase (see Section 8).

---

10. Post-Quantum Security

Every prior section describes QCB's design against classical adversaries. This section addresses a different adversary: a cryptographically-relevant quantum computer (CRQC) — one large and stable enough to run Shor's algorithm against the elliptic-curve cryptography most blockchains, including a naive implementation of QCB, would otherwise use by default.

10.1 What's actually at risk, and what isn't

Two different quantum algorithms threaten two different things, and conflating them overstates the danger to one part of the system while understating it for another:

· **Shor's algorithm breaks discrete-log and factoring-based cryptography completely**, not just weakens it. This is a direct threat to elliptic-curve signatures (ECDSA, EdDSA) — the scheme used to sign transactions and, more critically for QCB, the scheme a naive implementation would use for validator signatures in personhood-weighted BFT consensus (Section 3) and for any elliptic-curve-based zero-knowledge proofs the identity layer's live-challenge ceremonies (Section 4) might use. A CRQC capable of running Shor's algorithm at sufficient scale can forge signatures outright, not just accelerate guessing them.
· **Grover's algorithm only provides a quadratic speedup against symmetric primitives and hash functions** — it does not break them the way Shor's algorithm breaks signatures. QCB's state tree hashing (the JMT-based state layer planned for Chain Forge, Section 7.4) and block hashing are affected only in the sense that a 256-bit hash's effective security drops to roughly 128-bit under quantum attack — still considered adequate by current NIST guidance, and trivially hardened further by using a wider output (SHA3-384 or larger) if extra margin is wanted. This is a tuning parameter, not an open vulnerability.

The asymmetry matters: QCB's signature scheme is the actual exposure. Its hash functions are not.

10.2 The specific risk to a personhood-weighted chain

QCB's threat surface here is a superset of a typical chain's, for a structural reason: Section 3.3 already establishes that consensus security inherits identity-layer weaknesses. The same is true of cryptographic weaknesses — if validator signatures are forgeable, the personhood-weighting that bounds Sybil influence (Section 6.6's entire quorum derivation) becomes irrelevant, because an attacker who can forge signatures doesn't need fraudulent identities at all. Quantum vulnerability in the signature scheme is a more direct path to consensus and governance compromise than Sybil attacks are, because it bypasses the identity layer entirely rather than gaming it.

There is also a forward-exposure risk specific to how blockchains reveal public keys: once an account signs a transaction, its public key becomes visible on-chain. This does not expose past transactions to retroactive forgery — those are already settled and finalized — but it does mean that from the moment of first use, an account's public key is a standing target: a sufficiently capable CRQC could forge future signatures from that exposed key at any point afterward, for as long as the account continues using a quantum-vulnerable scheme. For a chain explicitly designed to still be functioning "long after its founders are no longer involved" (Section 7.3), a multi-decade CRQC risk window is not a hypothetical edge case — it's within the chain's stated design horizon.

10.3 Mitigation: crypto-agility as a constitutional guarantee, not a launch-day algorithm choice

The fix is not simply "use a post-quantum signature algorithm" — algorithm choice alone doesn't survive the next cryptographic break either. QCB already has the right pattern for this in Section 7.3: the identity layer's interface/implementation split, where the guarantee (a uniqueness property) is constitutional but the specific mechanism delivering it is ordinary-governance-replaceable. The same split should apply to signatures.

Proposed addition to Section 7.3's constitutional layer: a **cryptographic-primitive replacement mechanism**, structurally identical to the existing identity-primitive replacement mechanism — not committing to any specific signature algorithm at the constitutional level, but guaranteeing that the signature scheme can be replaced (for validators, for accounts, for the identity layer's own proofs) without forking the chain, losing state, or invalidating existing account history, the same way the identity method itself is designed to be replaceable.

Concretely, that means:

· Chain Forge (Section 7.4), being built from scratch rather than inheriting Cosmos SDK or Solana's cryptographic assumptions, should treat the signature scheme as pluggable from the start — the same architectural principle already applied to consensus (multiple BFT variants) and intended for identity (multiple PoP methods behind one interface). NIST has already standardized post-quantum signature schemes (ML-DSA/CRYSTALS-Dilithium, SLH-DSA/SPHINCS+, and FN-DSA/Falcon); Chain Forge does not need to invent new cryptography, only avoid hardcoding classical-only assumptions into its consensus and account-model code.
· Given QCB's own roadmap timeline (Section 11 puts testnet 3–6+ years out), launching with a hybrid classical+post-quantum signature scheme, or a PQC-native scheme outright, is a materially lower-risk starting position than launching with pure ECDSA and treating PQC migration as a later retrofit. A chain designed for multi-decade survival should not launch already carrying its single most consequential cryptographic weakness by default.

This tradeoff is real and worth stating plainly rather than deferring entirely: NIST's standardized ML-DSA (Dilithium) signatures run roughly 2.4KB against ECDSA's ~64 bytes — a two-order-of-magnitude size increase that lands directly on Section 8's fast, low-cost merchant-payment goal, since larger signatures mean larger transactions, more state growth, and more bandwidth per block. Falcon offers a smaller signature at the cost of a more complex, harder-to-implement-safely signing algorithm; SPHINCS+ is smaller still on the public key but produces the largest signatures of the three. There is no PQC option that matches ECDSA's compactness — adopting post-quantum signatures means accepting this cost somewhere in the stack, not engineering it away. This section does not resolve which specific algorithm QCB adopts, what triggers migration, or how the size cost is absorbed (larger blocks, fee adjustments, or a hybrid scheme that only pays the PQC cost for high-value or validator transactions) — those are addressed in Open Question 16.

---

11. Roadmap

Time horizons below are rough ranges, not commitments — appropriate for a multi-year infrastructure build where later phases depend on unresolved questions (identity layer design, consensus variant selection) that earlier phases must answer first. Phase 0's range for Chain Forge has been widened from an earlier draft: a from-scratch, safety-proofed, pluggable BFT engine is a materially harder problem than Bitcoin's original client, which itself took roughly two years of focused solo development for a simpler design (a single, non-pluggable consensus mechanism, no personhood-weighting layer). A small team building a harder problem should expect a longer, not shorter, timeline.

Phase | Milestone | Rough Horizon | Status
Phase 0 (Chain Forge) | Consensus engine design and implementation — pluggable BFT variants (Tendermint-style, HotStuff-style, XRPL-inspired); $QCB resource economy crate (`chain-forge-qrc`, prototype/reference implementation); cross-machine resource purchase acceptance test with 10 adversarial attack scenarios | 18–48 months | **In progress — Tendermint-style BFT ✅ (4-node testnet, partition-tolerant, September 2026); HotStuff-style BFT ✅ (17 tests passing, October 2026); XRPL-inspired FBA ✅ (18 tests passing, October 2026); $QCB resource economy prototype ✅ in `chain-forge-qrc` (QrcEngine + contribution_settlement + CapacityEvidence_v0, October 2026; architecture superseded by single-token model — see §6.5); cross-machine resource purchase acceptance test (10 attack scenarios required) — in progress. See Section 7.4 for detail.**
Phase 0 (QCB) | Whitepaper, identity layer research — proceeds in parallel with Chain Forge Phase 0, dependent on it for a working consensus target | 18–48 months | **In progress — whitepaper complete (this document); attestation guard Phases A–D implemented in chain-forge-identity (65 tests passing, September 2026); single-token $QCB resource economy model adopted (October 2026, supersedes prior QRC two-token model); identity pilot parameters provisional.**
Phase 1 | Personhood-weighted BFT consensus live on testnet; Charm Confinement + Intrinsic Charm implemented | 18–30 months following Phase 0 | Pending — prerequisite (pluggable BFT consensus) now has a working base; personhood-weighting overlay not yet built
Phase 2 | Identity layer pilot (small integration test, then real-world pilot against cost/sybil targets); $QCB resource economy activation, Grand Challenge tracks open, activity reward claims open | 6–12 months following Phase 1 | Pending
Phase 3 | Merchant API + Stripe-compatible integration, BME activation, first on-chain burns | 6–12 months following Phase 2 | Pending
Phase 4 | Charmed Agents live, physical merchant expansion, 1 million verified humans | Multi-year, adoption-dependent | Pending
Phase 5+ | Decentralized governance maturity; permissioned EVM layer (Section 7.2) activated once identity layer is proven at scale; interoperability reconsidered only if a PoP-preserving bridge design exists | — | Pending

**Phase 0 checkpoint (October 2026).** All three pluggable BFT consensus variants are now implemented and tested: Tendermint-style (4-node testnet, partition-tolerant, September 2026), HotStuff-style (17 tests passing), and XRPL-inspired FBA (18 tests passing). This confirms the pluggable architecture's core premise: consensus variants can be built, tested, and selected independently of the application layer. The $QCB resource economy prototype is implemented in `chain-forge-qrc` (see §6.5 for its status as a reference implementation, superseded by the single-token architecture). Three acceptance and security test suites have now passed on the live 3-node devnet (Alice, Bob, Dave on Machine 1) — see entries below.

**Phase 0 cross-machine resource purchase acceptance test — PASSED (2026-10-07).** Run ID `74e74616`. All 8 checks green on Alice, Bob, and Dave at height=14. A complete five-transaction sequence committed and executed correctly on all three nodes: `QrcPurchase → RegisterAgent → AuthorizeAgent → DepositToTreasury → LockQrcForJob`. Final verified state: Alice wallet = 5,000,000 uQCB; `treasury:test-agent-74e74616` = 4,200,000 uQCB (5M deposited − 800K locked). Live nonce fetch, per-step abort on failure, and a 30s commit timeout were all exercised. Script committed as `phase0_acceptance_test.py` (commit `5841e2d`). Root cause of earlier run failures: nodes were bootstrapped against Carol (192.168.137.3, unreachable on Machine 1 alone), causing the event loop to stall waiting for peers and blocking block production; fix was to bootstrap each node against its local siblings only and wipe state before each fresh run. Known gap: escrow account `escrow:esc-{id}` is not yet queryable — soft-skipped in the test, not blocking.

**Phase 0b negative-path tests — PASSED (2026-10-07).** Run ID `ad255b9f`. Setup agent registered, authorized, and funded successfully (fix: added missing `capabilities` + `spending_limits` fields to inline `RegisterAgent` body, commit `353687b`). N1 (over-cap lock): ✅ hard fail as expected — `LockQrcForJob` with 1,000,001 uQCB rejected with "amount 1000001 exceeds per-job limit 1000000"; treasury balance confirmed unchanged. N2 (duplicate escrow ID): ⚠️ soft warn — re-using an existing escrow ID was not rejected; duplicate escrow guard not yet implemented in `chain-forge-execution`'s `LockQrcForJob` handler (tracked as next work item). Genesis key mismatch fixed permanently (commit `965f524`) — `genesis-4node.json` now carries the correct validator public keys matching `keys/*.key.json`; `git reset --hard origin/main` no longer breaks consensus.

**DIS-001 Phase B security regression — PASSED (2026-10-09).** 25/25 checks green on a clean 3-node devnet. Checks covered: B1 nonce enforcement ✅, B2 balance enforcement ✅, B3 gas cap enforcement ✅ (gas_limit=0 rejected "below required 103"; gas_limit=10B rejected "exceeds block gas cap 10,000,000"), B4 chain-ID enforcement ✅, B5 malformed tx rejection ✅, B6 Phase A regression ✅, B7 SIGKILL+restart+replay rejection ✅, B8 Carol finality confirmed across all 3 nodes ✅. Root cause of earlier B3 failures: release binary was stale (built before the gas ceiling check was added to `execute_tx_with_identity`); fix was a forced recompile of `chain-forge-node` after touching `chain-forge-execution/src/lib.rs`, plus releasing persist-dir file locks with `pkill` before wiping state.

**PoCD mining — 3-miner epoch reward split confirmed (2026-10-09).** Three independent miners (`qcb1devminer-alice`, `qcb1devminer-bob`, `qcb1devminer-dave`) ran concurrently against the 3-node devnet using `scripts/pocd_miner.py`, each targeting a distinct `--machine` flag against Alice's node. All three miners received separate per-wallet uQCB credits at the block 720 epoch boundary. 100+ `pocd_reward` log lines confirmed across all three wallets in a single epoch. Per-proof rewards ranged 29,259–73,148 uQCB depending on challenge track weighting. Aggregate result: 8,586 rewarded receipts, 0 pending; `qcb1devminer-alice` balance 719,996,202 uQCB; `treasury:pocd` debited the exact matching amount (50,000,000,000 → 49,280,003,798 uQCB) — no double-payment. Mining throughput approximately 3.6 kH/s per miner. This confirms the core Grand Challenge earn path: verified work accumulates uQCB per miner, epoch close distributes rewards proportionally by track weighting, and the treasury debit matches wallet credits exactly. Known gap (Phase 1 item): proof pools are currently node-local — proofs submitted to one node are not gossiped to peers; all miners must point at the same node for unified epoch accounting until P2P proof-pool gossip is implemented.

**$QCB single-token resource economy (October 2026).** The resource token formerly named CIRFI (Circulating Finance) was renamed $QRC and prototyped as a two-token resource consumption model. That model is now superseded: the whitepaper adopts a single-token architecture in which $QCB is both the resource access token and the value-capture asset (see §6.2–§6.5). The `chain-forge-qrc` crate remains in the repository as a reference implementation and prototype. Its components — `QrcEngine` with dynamic conversion rate (R_t), epoch commitment cap (L_e), and CoverageRatio circuit breaker (CR_halt = 0.75, CR_resume = 1.00); `contribution_settlement` for VCA-verified provider earn (escrow-release model); and `CapacityEvidence_v0` for Byzantine-resistant median aggregation of capacity reports across 7 resource types — are not active on-chain and would require a governance vote to activate as a future extension. The consumption burn (previously 60% providers / 25% burn / 15% reserve split) is suspended pending escrow/revenue-policy redesign. `QrcEngine` serializes to `qrc.json`. The CIRFI rename is complete across all Rust sources, TOML manifests, markdown docs, and simulation scripts — zero remaining CIRFI references verified by grep.

**Attestation guard implementation (September 2026).** The on-chain sybil-resistance layer for the identity pilot has been implemented through Phase D in the `chain-forge-identity` crate. The four phases cover: (A) quadratic-cost cap enforcement — hard limit of 3 outbound attestations per 90-epoch window per attester; (B) revocation with cost — `RevokeAttestation` at 10% CS deduction (1,000 bps), cap slot freed on revocation; (C) sybil confirmation with CS penalty — coordinator-gated `ConfirmSybil` applies 120% CS clawback to penalized attesters (12,000 bps), `ReportSuspectedSybil` logs a self-report with 50% penalty reduction on independent confirmation; (D) `ReverseSybil` — coordinator can reverse a confirmed sybil, crediting back CS penalties. Execution layer updated with four new `TxBody` variants. REST endpoint `/api/identity/{address}` added. Pilot parameters from `QCB-Attestation-Guard-Design.md` are implemented as compiled constants; governance-tunable parameterization is deferred to Phase 1. The coordinator role is a named temporary centralization — see `docs/QCB-Attestation-Guard-Design.md §Coordinator`.

---

12. Open Questions

Calibration questions — decisions needed before or shortly after launch:

1. Final identity layer design — web-of-trust base plus live-challenge backstop, or a different hybrid; cost and sybil-rate results from pilot testing against the provisional targets named in Section 4 (sybil rate below 3%, verification cost below $5/human — both illustrative, to be revised as the pilot is designed)
2. Final BFT variant selection for QCB specifically (Chain Forge will support multiple; QCB must pick one)
3. Base exemption calibration — fixed at 30 days of activity rewards, or dynamic
4. Reserve strategy — what backs price stability, if anything
5. Jurisdiction and legal entity structure, given activity rewards distribution and merchant payment processing
6. Validator economics — staking incentives, slashing conditions, bounds on per-human validator power
7. Exact token distribution percentages within the Section 6.7 ceiling (illustrative percentages shown there are examples, not commitments)
8. Constitutional amendment thresholds — the exact percentage-quorum, absolute-minimum-voter-count, and waiting-period length for Section 7.3's amendment process; Section 6.6/7.3 now derive a floor (>6% turnout) from the Section 4 sybil target, but the absolute-count floor and exact waiting period are still unset

Permanence questions — decisions that matter because QCB is designed for long-term survival, not just launch:

9. Identity replacement process — the specific constitutional mechanism (Section 7.3) by which the identity primitive is swapped if it fails or is gamed, without forking the chain or invalidating existing verified claims
10. Governance succession — how decision-making authority moves past founder control over time without collapsing into either stagnation or capture
11. Stagnation resilience — what happens to the economic model if resource-consumption demand never reaches the threshold needed for BME to function meaningfully. Section 6.3 proposes a provisional working definition (resource-consumption burns funded at ≥1% of daily $QCB trading volume, sustained 90 days) for when BME should be considered live versus speculative; this open question is where that threshold gets finalized against real data. Grand Challenge demand (externally-funded scientific compute) is the secondary demand source if organic resource consumption is slow to bootstrap.
12. Long-horizon funding — how core protocol development is funded in year 15 or 20, once initial development allocations are spent and the chain's original team may no longer be primarily responsible for it
13. Consensus-layer bug migration path — the process for patching or replacing the consensus implementation itself if a critical flaw is found, without a chain split or loss of finality guarantees
14. Validator availability and liveness under partial-participation conditions — unlike Proof of Work (recruit more hashpower) or Proof of Stake (recruit more stake), a personhood-weighted validator set is bounded by a fixed, slow-growing pool of verified humans. What happens to finality and block production if a large fraction of verified humans go offline at once — through censorship, coercion, natural events, or simple apathy — has not yet been addressed. This is a consensus-design constraint arising directly from Section 3's personhood-weighting choice, not a tunable parameter, and needs a concrete answer before Phase 1 testnet. Related to, but distinct from, Q13: a sustained liveness failure may be one of the triggers for Q13's consensus-migration path, but liveness itself (can the chain keep producing blocks right now) and migration (replacing the consensus implementation) are separate problems needing separate answers.
15. Minimum legitimate participation rate required for governance to remain Sybil-resistant at the maximum tolerated fraudulent-identity rate — Sections 4, 6.6, and 7.3 are now mathematically linked via two distinct derivations against Section 4's sybil-rate target: a >3% turnout floor from the majority-safety condition (f / (p + f) < 0.5, protecting ordinary resource-economy governance votes) and a >6% floor from the stricter blocking-safety condition (f / (p + f) < 1/3, protecting supermajority constitutional votes). The absolute-minimum-voter-count floor referenced in 6.6, and how both thresholds should adjust if the Section 4 target itself changes after pilot data comes in, remain unset. This question exists specifically to keep identity, ordinary governance, and constitutional governance treated as one linked security model rather than three separate ones.
16. Post-quantum migration trigger and algorithm choice — Section 10 establishes that the signature scheme must be constitutionally replaceable, but not which post-quantum algorithm(s) QCB adopts at launch versus in reserve, what specific event (a NIST guidance update, a demonstrated cryptographically-relevant quantum computer, a fixed calendar review date) triggers migration for already-live accounts and validators, and which of Section 10.3's three candidate approaches to absorbing PQC's larger signature size (larger blocks, fee adjustments, or a hybrid scheme applied only to high-value/validator transactions) QCB actually adopts.
17. Turnout-suppression resistance — Section 6.6's quorum floors are derived assuming legitimate turnout is independent of attacker behavior, but a sophisticated attacker can suppress legitimate turnout directly (proposal spam, governance fatigue, targeted discouragement), lowering p and raising fraud's effective vote share without needing more fraudulent identities. The current model defends against passive, uncoordinated fraud; it does not yet defend against an active campaign to depress legitimate participation. What mechanism (participation incentives, spam-resistant proposal costs, fatigue-aware quorum adjustment) closes this gap is unresolved.
18–22. [ARCHIVED — Merchant settlement layer questions] These open questions (settlement layer reserve sizing, rate regime, governance, consumption burn / settlement reserve interaction, and cold-start funding) were design questions for the merchant fiat settlement layer. That layer has been removed from the current design phase (see Section 8). These questions are archived here for reference if merchant integration is introduced as a future-phase extension. They are not active design commitments.
23. Permissioned EVM layer design — Section 7.2 commits to a permissioned EVM environment where every contract must be linked to a verified Charmed Agent SponsorID and every $QCB transfer passes through QCB's identity checks. The open questions are: (a) how is the SponsorID link enforced at the EVM level — through a modified EVM precompile, a wrapper contract, or a protocol-layer check before every state transition; (b) what happens to an EVM contract whose SponsorID is revoked (human loses verified status, or agent's authorization expires) — freezing the contract (state persists, no new calls accepted) is the conservative default and avoids destroying user funds, but creates indefinite state lockup; transferring the SponsorID to another verified human requires a governance mechanism for reassignment; destroying the contract and its state is irreversible and likely wrong in most cases; the conservative default is freeze, with transfer as an exception path requiring explicit governance; (c) how are gas fees denominated and collected in the permissioned EVM — in $QCB (consistent with $QCB's role as the chain's sole protocol token and fee token); (d) how does the EVM layer interact with the consumption burn — does $QCB spent on EVM execution trigger the p_burn = 0.25 consumption burn (currently suspended), and who settles that burn (the contract or the protocol); and (e) which EVM opcode set is supported — full EVM equivalence (including SELFDESTRUCT, DELEGATECALL, and other operations that complicate identity tracking) or a constrained subset that makes identity enforcement tractable.
24. Liveness of identity — Section 4.5 establishes that identity and economic participation must be coupled in both directions: identity gates participation, and participation maintains identity. The open question is the specific liveness requirement: what minimum periodic activity must a verified human perform to maintain active verification status? Candidates include periodic activity reward claims (e.g., claim at least once per epoch), periodic governance votes, periodic $QCB transactions above a threshold, or some combination. The requirement must be low enough not to exclude humans who are temporarily inactive (illness, travel, life events) and high enough to prevent identity from becoming a free-standing credential that confers rights without chain participation. It must also specify what happens to a lapsed verification — is it suspended (recoverable with re-verification) or revoked (requires fresh verification from scratch) — and what happens to the lapsed human's Charmed Agents and Sponsored Contracts during the lapse period. This question is distinct from Open Question 14 (validator liveness, which concerns block production) and from Open Question 9 (identity replacement process, which concerns protocol-level swaps of the verification method). It is specifically the individual-level liveness requirement that keeps identity coupled to economic participation.
25. Resource-consumption BME calibration — In the single-token architecture, BME is driven by resource-consumption burns rather than merchant fees or circulation-event redirects. The open questions are: (a) what fraction p_burn on $QCB resource jobs (when the suspended burn is re-enabled) keeps resource-consumption from being suppressed by the burn cost — too high makes resource use expensive; too low makes BME negligible; (b) under what conditions is resource-consumption BME considered "live vs. speculative" — the working definition (burns ≥ 1% of $QCB daily trading volume for 90 consecutive days) may need revising once real resource-demand data is available; and (c) how does the burn fraction interact with the escrow/revenue-split redesign — burn should be charged to the consumer at job submission, not deducted from provider payment at job completion. This question replaces the prior OQ 25 (circulation-event fee calibration under the merchant model, now archived with OQ 18–22).
26a. uQCB / contribution-pool supply schedule — **open design question.** The Grand Challenge section describes uQCB accumulation and conversion to $QCB (1,000,000 uQCB = 1 QCB), and §6.7 references a "contribution pool" funded from the genesis allocation. Neither the per-epoch issuance rate of uQCB, the total uQCB supply cap, the rate at which the contribution pool is drawn down, nor the mechanism by which contribution-pool funding responds to network conditions is currently specified. These parameters determine the economic reward rate for Grand Challenge participants and the long-run $QCB issuance schedule from the contribution path. They must be specified before the Grand Challenge resource crate is built and before meaningful economic modeling of the contribution path is possible. This is flagged as a blocking open question for the Grand Challenge / resource-layer implementation.

26. Human Capacity Markets (considered, not committed) — a proposed extension under which verified humans could be paid, in $QCB, to sponsor agents on a bounded, time-limited basis, rather than sponsorship being an unpaid accountability relationship as currently specified in Section 5.3. The idea surfaced from a broader (and explicitly rejected) framing that described verified personhood itself as "a scarce, rentable economic resource" — that framing is not adopted here, because it inverts Section 4.5's coupling principle (identity's value comes from participation in QCB's own economy, not from being sold as a queryable input to others) and because "rentable personhood" invites a reading — humans selling themselves to agents — that the mechanism, if built carefully, would not actually be. What might be worth building, if anything, is much narrower: paid, scoped, revocable sponsorship, structurally close to the existing `sponsor_agent` mechanism, not a new identity-as-a-service primitive.

This question is intentionally left open rather than specified, because three prerequisites are unresolved and each changes what the mechanism actually is:

(a) Price discovery — is the sponsorship fee fixed, or does it require a matching market (an order book of sponsorship offers and agent requests)? A fixed fee is a simple transaction type; a market is a new subsystem.

(b) Bonding and liability — does a paid sponsor stake something at risk beyond the existing reputational accountability, so that being paid to sponsor doesn't create an incentive to sponsor recklessly for fee income with no offsetting downside? Unpaid sponsorship relies on the human having chosen to vouch for something they understand; paid sponsorship removes that selection pressure unless a bond replaces it.

(c) Sybil-farming resistance — turning sponsorship into an income stream gives verified humans a direct financial incentive to accumulate sponsorship slots and approve agents without real vetting, which is a new attack surface layered on top of the identity layer's existing sybil problem (Section 4). A per-human cap on concurrent paid sponsorships, separate from the existing per-sponsor limits in the agent registry, is a candidate mitigation but is unspecified.

Until (a)-(c) have concrete answers, Human Capacity Markets remains a named possibility, not a designed mechanism, and it does not appear in the Abstract, Section 5, or the token-economics sections. If it is pursued, it should enter the document the way Section 4.6's strategic directions do: as a contingent extension with named success and failure conditions, evaluated against a working pilot before being described as a feature QCB has.

A related, equally unresolved idea has been proposed alongside this one: activity-based $QCB accrual, under which verified humans (and, by attribution, their sponsored agents) would earn $QCB credits for measured $QCB economic activity — resource spending, Grand Challenge work, Capacity Market work, agent activity that passes some quality filter — rather than for locking a balance, which is what Section 6.9's long-term distribution mechanism already covers. It is recorded here, as a fourth prerequisite, rather than specified, because it inherits the same three open questions above in a stricter form:

(d) Source of funds and gaming resistance — any real version of this draws $QCB from the same fixed, genesis-minted 210 million supply as everything else (Section 6.7); it is not a second, independently-sized allocation, and sizing it correctly requires deciding how it relates to Section 6.9's 4% long-term distribution pool before either can be finalized. Two of its proposed qualifying activities — Capacity Market work and sponsored-agent volume — are Human Capacity Market primitives, so this cannot be resolved ahead of (a)-(c) above; it is downstream of them, not parallel to them. It also introduces its own attack surface on top of HCM's: attributing agent activity to a human sponsor's accrual creates a direct incentive to run low-quality or synthetic agent activity purely to farm credits. Candidate mitigations — quality filters on what counts as attributable activity, per-identity rate limits or diminishing returns, a requirement that the sponsor maintain their own qualifying activity alongside their agents' — are named here as directions, not as a specified design. As with Human Capacity Markets itself, the identity layer's sybil resistance (Section 4) is the first line of defense against this, not a substitute for it; a mechanism that pays out real $QCB for activity is a stronger incentive to defeat that sybil resistance than sponsorship alone, and should be evaluated with that in mind before it is built, not after.

---

13. Conclusion

QCB Chain is not trying to be digital gold, and it is not trying to be someone else's framework with a new name. It is a sovereign chain, built from its own foundation, where consensus power, governance, and economic participation all trace back to the same principle: one verified human, one share of the system.

But sovereignty at launch and survival across decades are different achievements. Bitcoin and Ethereum have each proven roughly a decade of resilience, and both have done so imperfectly — through contentious forks, informal social consensus, and identity questions of their own that they never had to solve at the protocol level, because they never tried to gate participation by verified personhood. QCB is attempting something neither has: tying consensus power, currency issuance, and governance to human identity itself, at a protocol layer meant to still be functioning long after its founders are no longer involved.

That requires more than good token design. It requires a constitutional layer (Section 7.3) that can outlive any single identity method, any single development team, and any single jurisdiction — and the discipline to treat that layer as genuinely load-bearing, not aspirational language. The identity primitive described in this document is a current best answer, not a permanent one. What makes QCB durable is not that this answer is correct forever, but that the protocol has a defined, legitimate way to replace it if it isn't.

Its value comes not from scarcity, but from circulation. Its security comes not from capital or hardware, but from verified humans. Its independence comes from having built its own foundation, on Chain Forge, rather than borrowing one. And its claim to permanence rests not on any individual's commitment to it, but on whether the rules it launches with are the rules that let it keep changing without breaking.

The engine, not the vault. The economy, not the chain. Built to be replaced by better versions of itself, not by its own collapse.
