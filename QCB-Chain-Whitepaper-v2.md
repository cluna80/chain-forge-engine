QCB Chain Whitepaper

QuarkCharmBit — A Sovereign, Ground-Up Layer-1 for Charm-Based Agent Economies

Money engineered to move. Agents engineered to work. Built from the ground up, owned by no one else's framework.

---

Abstract

QCB Chain (QuarkCharmBit) is a sovereign Layer-1 blockchain, built on Chain Forge — a from-scratch Rust blockchain engine — rather than on an existing framework like Cosmos SDK or Solana. QCB combines a novel consensus mechanism — Byzantine Fault Tolerant agreement with validator power weighted by verified personhood rather than raw stake — with four native protocol components: QRC, a resource consumption token (redeemable claims on network resources — compute, storage, ZK proving, oracle queries, AI inference, and bandwidth), alongside three charm-based agent and identity modules — Charm Confinement, Intrinsic Charm, and Charmed Agents.

QCB does not derive its consensus, its state machine, or its core modules from any other chain's codebase. In this, it follows the lineage of Bitcoin and XRP Ledger — chains with their own original designs — while making a deliberate departure from both: consensus power tied to verified human identity rather than computational work or capital, and a monetary engine designed to circulate rather than accumulate. The chain is self-contained by design: no bridges, no wrapped assets, no interoperability that could allow unverified actors into the system.

The monetary engine described in Section 6 is contingent on two unvalidated components and one external precondition. The unvalidated components are the identity layer (Section 4) and the fiat settlement layer (Section 8). The external precondition is the settlement layer's cold-start: before $QRC has any value at all, someone outside the protocol must seed the settlement layer with real external money (Section 8.5). Until the identity layer is validated through the staged pilot process, until the settlement layer's reserves, rate regime, and governance are specified and funded, and until the cold-start funding is secured, $QRC issuance and $QCB's Burn-and-Mint Equilibrium should be understood as a research deployment, not a production currency. This document describes the intended steady-state system in full; the early-adoption phase — when the value loop has not yet started and belief precedes evidence — is described in Section 8.5.

A note on dependency chains: the sections that follow trace a sequence of dependencies, each of which has its own precondition. Identity depends on sybil resistance. Sybil resistance depends on live-challenge ceremonies not being defeated by well-resourced bots. Settlement depends on reserves. Reserves depend on an underwriter. The underwriter depends on terms compatible with QCB's design principles. Each dependency is real and is named where it arises. The staged pilots described in Sections 4 and 8 are designed to determine whether these dependencies resolve into solvable engineering and legal decisions, or whether some of them represent constraints the system cannot satisfy under its own stated principles. The document does not claim to know which outcome will prevail — only that the honest path is to name the chain and test it.

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

---

Equilibrium State: When the Network Becomes Alive

Reaching equilibrium is not a launch event. It is a threshold the network crosses — gradually, over years — as machines join, attestations accumulate, and the resource market deepens. No single moment marks it. But there is a point at which the network stops being something that requires active maintenance to stay alive and becomes something that sustains itself.

QCB defines Equilibrium State as the condition where:

· The validator set is large and geographically distributed enough that no regional outage, no coordinated departure, and no single bad actor can halt block production or reverse finality
· The machine population is deep enough that every active Grand Challenge track has sufficient independent verifier machines to confirm results without any track going dark for lack of participants
· The resource market has enough competing providers that no provider or cartel can price-fix QRC or starve agents of capacity
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

QCB is a sovereign resource network anchored to verified human identity. Humans prove unique participation without exposing personal information, machines provide capacity, agents coordinate workloads, QRC settles payment, and QCB token holders govern the economy. QCB proves personhood without requiring public disclosure of the person's real-world identity.

Six pillars underpin the system:

1. **Verified human identity** — privacy-preserving proof of unique participation.
2. **Human accountability** — every agent, machine, and provider traces ultimate responsibility to a verified human.
3. **Machine capacity** — compute, storage, bandwidth, data, and other resources.
4. **Agent coordination** — agents discover, purchase, and orchestrate workloads.
5. **QRC settlement** — payment and accounting for verified resource consumption.
6. **QCB governance** — QCB holders govern economic and protocol parameters, subject to QCB's personhood and constitutional constraints.

As a from-scratch Layer-1 blockchain built on Chain Forge — a purpose-built Rust blockchain engine — QCB provides four things no general-purpose chain offers natively, together, at the protocol layer:

1. Personhood-weighted BFT consensus — validator power tied to verified human identity, not stake or hashpower
2. Charm-based state confinement and agent representation — identity-scoped state and native support for autonomous agents as first-class chain citizens
3. A working monetary engine — $QRC acquired primarily via QCB purchase (QCB holders burn $QCB to acquire $QRC); resource providers receive payment in existing QRC released from job escrow rather than through new minting; a five-control resource solvency architecture; and Burn-and-Mint Equilibrium (BME) burns, native to the protocol
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

· Proof of Work is energy-intensive and settlement-slow — directly at odds with QRC's pitch of fast, low-cost merchant payments.
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

Resource consumption token (Section 6.2) — QCB holders acquire $QRC by burning $QCB; verified resource providers are paid in existing $QRC released from job escrow when they fulfill a resource contract, rather than through new minting. $QRC is a redeemable claim on network compute, storage, ZK proving, oracle queries, AI inference, and bandwidth. No other chain implements a native resource consumption token whose solvency is enforced by an on-chain CoverageRatio circuit breaker backed by a full resource-market escrow layer. If you want to participate in a network where resource access is priced, rationed, and governed at the protocol layer — with provider economics tied directly to verifiable job execution — QCB is the only option, and resource provider status requires identity verification.

Charmed Agents with bounded authorization (Section 5.3) — autonomous agents are sponsored by verified humans, with cryptographic scoping of their economic footprint. No other chain has native agent identity with a human accountability chain. If you want to run an economic agent that a verified human is responsible for, QCB is the only option, and it requires a verified sponsor.

RWA issuance with protocol-level compliance (Section 7.2) — tokenized real-world assets on QCB are held by SponsorID-linked accounts, making KYC/AML compliance a property of the protocol rather than an external wrapper. No other chain provides compliance-at-the-protocol-layer as a native feature. If you want to issue tokenized securities without building a separate compliance stack, QCB is the only option, and it requires verified participants.

None of these capabilities can be replicated on another chain without changing that chain's fundamental architecture. That is what makes them a moat rather than a feature list.

The coupling principle

The identity layer has value only if it is coupled to the economy, and the economy has value only if it is coupled to the identity layer. Each direction of the coupling is a design decision:

Identity gates participation (already specified): activity rewards, consensus power, governance votes, Charmed Agent sponsorship, and Sponsored Contract deployment all require verified identity. A non-verified actor cannot access QCB's economic plumbing.

Participation maintains identity (not yet specified): verified humans who never claim activity rewards, never vote, and never transact may be able to hold verification indefinitely. If so, identity becomes a free-standing credential that other systems can query without the holder participating in QCB's economy. This decouples identity from the chain and turns QCB into infrastructure for other chains' benefit — a public good that QCB cannot capture value from. A liveness requirement — some minimum periodic participation (activity reward claims, governance votes, or $QRC transactions) to maintain active verification status — closes this gap. The specific requirement is an open question (Open Question 24), but the principle is a founding commitment: identity and economic participation are coupled in both directions, not just one.

The failure mode

If the coupling breaks in the participation-to-identity direction, QCB's identity layer becomes a public good: a proof-of-personhood API that other chains and applications query without compensating QCB or requiring their users to participate in its economy. The identity layer provides real value, but QCB captures none of it. This is the equivalent of the settlement layer becoming a public utility — structurally important but economically empty for the chain that built it.

The design has to prevent this through the liveness requirement above, not hope it does not happen. A chain whose strategic asset is its identity layer cannot afford to let that layer exist independent of the economy it is meant to anchor.

What this document does and does not claim

The whitepaper describes a mechanism: identity and economy are coupled, neither works without the other, and the coupling creates something no other chain has built. Whether that mechanism becomes valuable is an empirical question the pilot phases must answer — through the identity layer validation in Section 4, the merchant adoption in Section 8, and the RWA demand described in Section 8.2. The document does not claim QCB will become the identity layer of the broader ecosystem, or that every chain will need it. Those outcomes depend on whether the mechanism works as designed, and no whitepaper can determine that in advance. The claim is narrower and stronger: the mechanism is real, the coupling is intentional, and the pilot will determine whether it holds.

The identity is the door, and QCB's economy is what is behind it. A person who holds BTC, ETH, XRP, or SOL and wants the four unique capabilities described above — personhood governance, earned $QRC circulation, Charmed Agents, RWA compliance — verifies on QCB and participates. Their existing holdings are irrelevant to their verification; the identity is not a service their coins can access. It is a door that a person walks through, and what is behind it is QCB's own economy: the activity rewards they can earn, the agents they can run, the governance they can participate in, the assets they can issue with compliance built in. QCB does not want people's coins. It wants people, and the economy their participation creates is the thing that makes the coins ($QRC, $QCB) valuable. This is the inversion at the core of the design: most chains attract capital and hope people follow. QCB attracts people and the capital follows from what people do once they are here. Whether that inversion produces adoption is the empirical question that the rest of this document routes, correctly, to the pilot phases.

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

What this requires: the AEI specification formalized (currently a design sketch in this document, not a protocol specification), agent-to-agent settlement in $QRC functional, and one external agent framework willing to reference QCB's SponsorID scheme rather than its own.

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

QCB has four native protocol-level components, implemented directly in the chain's own state machine rather than as smart contracts or SDK modules. Being protocol-level is not the same as being constitutional (Section 7.3): existing as native state-machine logic determines where these components run; the constitutional layer determines how hard they are to change. Charm Confinement and Intrinsic Charm's specific mechanics, and Charmed Agents' operating rules, are protocol-level but ordinary-governance-adjustable — they can be tuned as the system matures. Only the pieces named explicitly in Section 7.3 (the identity interface, the two-token separation, and the sovereignty constraint) sit behind the higher constitutional bar. QRC's core parameters — conversion rate bounds, epoch cap coefficients, CoverageRatio thresholds, consumption burn fraction — are protocol-level and governance-adjustable (Section 6.6), but the two-token separation of function that QRC depends on is itself constitutional.

5.0 What "Charm" Means

"Charm" is QCB's term for a bundle of protocol-enforced properties — identity verification tier, scope boundaries, and spending authorization constraints — that travel with a piece of state or an identity rather than being assigned or checked by an external application. A charm is intrinsic to what it's attached to, not a permission granted from outside it. The three modules below apply this concept in three different ways: confining state to its rightful context (5.1), attaching properties directly to identity (5.2), and extending first-class chain citizenship to autonomous agents (5.3).

5.1 Charm Confinement
Scoped state isolation at the protocol layer. Ensures identity-linked claims (such as activity reward claim rights) and agent-controlled resources remain bound to their defined context — one verified identity, one claim per epoch, with no cross-context leakage.

5.2 Intrinsic Charm
Properties treated as inherent to a piece of state or identity, traveling with it rather than being externally assigned. Proof-of-personhood attestations, verification tier, and agent spending authorization scopes are encoded as intrinsic properties that persist with an identity across the chain. Note: decay-exemption credits are not part of Intrinsic Charm under QRC v3 — demurrage was removed from the $QRC model, making decay-exemption a concept without a referent.

5.3 Charmed Agents
Native, first-class representation for autonomous agents on-chain. Merchants and activity reward distributors can operate as Charmed Agents — handling payment acceptance, fiat conversion, and daily distribution automatically, without being modeled as ordinary externally-owned accounts running arbitrary contract calls.

Scope note: as currently designed, Charmed Agents cover scheduled, rule-bound operational roles — merchant settlement and activity rewards distribution — not open-ended autonomous behavior. This is a narrower claim than "agent economy" in the title and Abstract might suggest; the broader vision (agents with more general decision-making scope, charm-scoped in richer ways) is a future-phase direction, not something this document specifies yet. What makes charm-scoping matter even for this narrower case is that agent state stays bound to its identity context (Section 5.1) rather than behaving as an unscoped, arbitrary contract account.

Sponsored Contracts (Section 7.2) are a distinct subclass of Charmed Agent and should not be confused with the operational roles described here. Sponsored Contracts cover developer-deployed Solidity contracts with a verified human SponsorID — arbitrary computation within QCB's identity constraints, not scheduled merchant or activity rewards operations. The subclass relationship means Sponsored Contracts inherit Charm Confinement's identity-binding guarantees (Section 5.1) and Intrinsic Charm's attestation properties (Section 5.2), but they are a Phase 5+ addition and their specific rules are governed by Section 7.2 and Open Question 23, not by this section.

Agent services as a demand engine: Section 7.2 already establishes, at the constitutional level, that only $QRC may be used for payment to Charmed Agents — this is not a tier or an option some agents opt into, it is a sovereignty constraint (Section 7.3) that applies to every Charmed Agent without exception, specifically to prevent the currency fragmentation that would result from some agents accepting substitutes. What is worth naming explicitly is what this constraint becomes as Charmed Agents grow more capable: every agent that does useful work — monitoring, research, recurring automation, agent-to-agent services — is a reason someone has to acquire and spend $QRC that has nothing to do with activity rewards or merchant payments. The more useful the agent economy becomes, the more this constraint does real economic work, independent of the merchant-adoption bootstrapping problem in Section 8.1. This is not a new restriction; it is the existing rule's consequence made explicit.

Two pieces of protocol infrastructure this implies, and does not yet have:

An Agent Service Registry — an on-chain directory where a Charmed Agent publishes its service description, its $QRC price (fixed or usage-based), its capability scope (bound by Charm Confinement, Section 5.1), and the SponsorID of the verified human accountable for it. Without this, agent services exist but are not discoverable at the protocol layer.

Payment primitives beyond a single transfer — the current design covers a discrete $QRC payment; it does not yet cover a streaming payment (pay continuously while a service runs) or a usage-metered payment (pay per unit of work). Recurring and metered agent services need one of these, and neither is specified yet.

Both are additive engineering work on top of `chain-forge-agents` — a registry module and new payment-primitive transaction types — not a change to the $QRC-only rule, which is already as strict as it can be.

What this section deliberately does not resolve: whether a sponsor should be required to maintain their own minimum $QRC activity to keep sponsoring high-value agents is a real incentive-design question, but it overlaps directly with the activity-based $QCB accrual idea recorded as Open Question 26(d) — attaching a $QRC-activity requirement to agent sponsorship, and rewarding $QRC activity with $QCB accrual, are close enough in shape that designing one without the other risks two uncoordinated mechanisms measuring the same thing differently. This is left unresolved here and flagged at 26(d) rather than decided in this section.

5.4 QRC — The Resource Consumption Token
The chain's native resource token (QRC Economic Model v0.2, implemented across `chain-forge-qrc` and `chain-forge-execution`):

· $QRC is a redeemable claim on network resources — compute, storage, ZK proving, oracle queries, AI inference, and bandwidth. It is not a UBI payment or a circulating currency in the demurrage sense. Its correct economic invariant is resource solvency: QRC_outstanding ≤ Capacity / CR_min.
· Primary issuance path — QCB holders submit a `PurchaseQrc` transaction (job-scoped, with slippage guard) to burn $QCB and mint $QRC at the dynamic conversion rate R_t. This is the canonical way new $QRC enters circulation. A legacy contribution-minting path (`CreditProvider`) exists in the codebase but is classified as under review; under the October 2026 architecture pivot, resource providers are paid from job escrow (existing $QRC) rather than through new minting. See Section 6.2 for the full model.
· There is no QRC→QCB reverse conversion and no demurrage on QRC balances. $QRC consumed in network resource usage triggers a 25% consumption burn (p_burn = 0.25), permanently removing that fraction from supply.
· A five-control resource solvency architecture enforces the invariant — dynamic conversion rate, epoch conversion cap, on-chain capacity tracking, consumption burn, and a CoverageRatio circuit breaker. See Section 6.10 for the full architecture and simulation-derived parameters.

---

6. Token Economics

Note: everything in this section describes the tokenomics as designed. Their real-world behavior — particularly $QRC resource solvency (Section 6.10's five-control architecture) and BME's ability to fund meaningful burns — depends on the identity layer (Section 4) for VCA-verified provider attestation and on the network reaching meaningful resource utilization. See the Abstract for the dependency chain stated plainly.

QCB Chain operates with two distinct tokens, each engineered for a specific function. They are not competitors and are not interchangeable. One is designed to move; the other is designed to hold. Together they form a complete monetary system where circulation drives value capture.

6.1 Design Principle: Separation of Function

Most blockchain networks force a single token to serve contradictory roles — gas, staking, payments, governance, and value capture. This produces a structural problem: the behaviors that make a good currency (spending, circulating) are opposed to the behaviors that make a good investment (holding, staking).

QCB resolves this by splitting the functions:

Token | Purpose | Behavior
$QRC | Resource consumption token | Spent on network resources, burned on use
$QCB | Value-capture asset | Held, staked, appreciated

This mirrors proven two-token models — MakerDAO's DAI/MKR, VeChain's VTHO/VET, dYdX's USDC/DYDX — where a utility token handles consumption and a separate asset captures network value.

6.2 $QRC — The Resource Token

$QRC is a redeemable claim on network resources, not a circulating currency in the UBI or demurrage sense. Its purpose is to price and ration access to the network's computational capacity: compute, storage, ZK proving, oracle queries, AI inference, and bandwidth.

**What $QRC is not.** The earlier design for this token ("CIRFI — Circulating Finance") used demurrage, population-linked daily issuance, and activity rewards to drive spending. That model has been superseded. $QRC under the QRC Economic Model v0.1 (implemented in `chain-forge-qrc`) carries no demurrage, no daily issuance to verified humans, and no UBI component. The correct economic frame is resource solvency — not monetary velocity.

**Primary issuance path.** $QRC enters circulation primarily through one mechanism: QCB holders submit a `PurchaseQrc` transaction. The protocol destroys the specified $QCB amount and mints $QRC at the current dynamic conversion rate R_t (see Section 6.10, Control 1). There is no reverse path: $QRC cannot be converted back to $QCB. Once acquired, $QRC is spent on network resources, placed in job escrow, or transferred; it has no guaranteed redemption price.

**Resource provider payment — escrow, not minting.** Under the October 2026 architecture pivot, resource providers do not receive newly-minted $QRC. Instead, an agent purchasing computation locks existing $QRC into a `ResourceEscrow` at job start. When the provider fulfills the contract and the result is verified (via `ResourceExecutionReceipt`), the escrowed $QRC is released to the provider. If the job fails, the $QRC is refunded to the requester. This cleanly separates the monetary supply question from the resource market: the supply of $QRC is determined entirely by `PurchaseQrc` activity; the resource market merely moves existing $QRC between parties. Escrow primitives: `LockQrcForJob`, `ReleaseQrcForJob`, `RefundQrcForJob` (future: `DisputeResourceJob`).

**Legacy contribution path — under review.** The codebase contains a `CreditProvider` transaction type and `contribution_settlement` mechanism from an earlier design where VCA-verified providers earned newly-minted $QRC proportional to attested capacity. This mechanism is classified as legacy/under review following the October 2026 pivot. `CreditProvider` and `QrcContributionSettle` should not be built upon further until the question of whether any contribution-minting path survives in the new model is resolved. See the ROADMAP for current classification.

**Consumption and burn.** When $QRC is spent on actual resource usage, 25% of the consumed amount (p_burn = 0.25) is permanently destroyed. The remaining 75% is split: 60% paid to the provider nodes that served the request, 15% added to a reserve. This creates a supply contraction proportional to network utilization — the more the network is used, the more $QRC is removed from circulation permanently.

**No demurrage on $QRC.** Resource claims do not decay. A holder who acquires $QRC and does not spend it retains the full nominal balance indefinitely. The spending incentive comes from the resource economy itself (you acquire $QRC because you intend to use network resources, not to hold them), not from a penalty on idle balances.

**Denomination.** The base denom is `uqrc` (micro-QRC), matching `uqcb` for $QCB. Protocol-layer amounts are always in `uqrc`; wallets and interfaces display human-readable $QRC amounts at the appropriate scale.

**$QRC value.** $QRC's value is the value of the network capacity it redeems. The correct measure is not price stability but resource solvency: the CoverageRatio (Capacity / QRC_outstanding) must remain at or above CR_min. See Section 6.10 for the five-control architecture that enforces this.

**VCA and resource verification.** The VCA (Verifiable Contribution Attestation) mechanism is evolving from a capacity-reporting oracle into the verification infrastructure for the resource market. Providers will submit `ResourceExecutionReceipt` records — the successor to `CapacityEvidence_v0` — attesting to actual job execution: CPU-core-minutes used, input and output hashes, start/end timestamps, and provider signature, confirmed by requester. The protocol uses these receipts to release job escrow (releasing $QRC to the provider on success) and to update on-chain capacity measurements that the CoverageRatio and epoch cap depend on (Controls 2 and 3). The `CapacityEvidence_v0` sub-protocol is the direct evolutionary predecessor; its PQ attestation infrastructure (ML-DSA signatures) is reused rather than discarded.

6.3 $QCB — The Value-Capture Asset

$QCB is the asset that captures the network's value.

Function: chain security (staking to validators), gas fees on QCB Chain, governance over protocol parameters, and capturing value from network activity.

Supply mechanism: $QCB has a fixed or capped supply. Unlike $QRC, it does not grow with population — scarce by design, appropriate for an asset intended to be held and appreciate. Supply contracts over time through buyback-and-burn funded by merchant fees and staking lockups that remove tokens from circulation.

Staking: $QCB holders stake to validators to secure the chain, earning yield from a portion of merchant fees, governance rights over protocol parameters, and consensus participation — staked $QCB is the mechanism through which validator influence is exercised, bounded by proof-of-personhood (see Section 3.3).

Buyback and Burn (BME):

Daily $QCB burned = Daily merchant fee revenue in fiat ÷ Current $QCB price

Merchant fees, collected in fiat or stablecoin, buy $QCB on the open market and burn it permanently. The burn rate is inversely proportional to price — at $0.01, $20,000 in daily fees burns 2 million $QCB; at $1, the same fees burn only 20,000 $QCB. When price is low, burning accelerates; when price is high, burning slows — self-adjusting, not discretionary. This assumes price is the only variable driving burn significance; in practice, low prices often coincide with weak holder confidence and higher selling pressure, so the fiat value destroyed per burn can fall even as the token quantity burned rises. The mechanism is self-adjusting in token terms, not necessarily in economic-impact terms.

$QCB value: driven by network activity. As more $QRC is spent at merchants, more fees flow into the system, buying and burning $QCB and paying staking yield to holders. $QCB is not designed to be spent — it is designed to be held, staked, and appreciated over time. If merchant fee revenue is insufficient to fund meaningful burns, $QCB's value rests on the eventual prospect of adoption rather than current activity — a condition the protocol treats as a transitional phase, not a steady state, and one addressed as a permanence risk in Section 12.

Working definition — BME "live" vs. "speculative": BME is considered live, rather than speculative, once merchant fee revenue funds burns equal to at least 1% of $QCB's daily circulating trading volume, sustained for 90 consecutive days. Below that bar, any $QCB price appreciation should be attributed to adoption expectations, not to realized BME mechanism activity — the two should not be conflated in external communication about the token. This threshold is provisional; it is finalized alongside Open Question 11 as real merchant-volume data becomes available.

This threshold has a measurement caveat worth naming: trading volume is itself partly a function of whether the market believes BME is live — speculative interest can inflate the denominator, making the bar easier to clear without more real merchant activity behind it. A denominator less exposed to this reflexivity, such as burns relative to trailing merchant fee revenue rather than to trading volume, may prove more robust once real data is available to compare the two.

Broadened circulation events and activity rewards pool redirect: BME is not limited to merchant settlements. Any $QRC movement that a holder designates as a circulation event — spending at a merchant, a peer-to-peer transfer, or a proactive redirect of balance to the activity rewards pool — generates a small fee (provisionally 0.5%, consistent with the merchant fee range in Section 8.1) that funds $QCB buy-and-burn. This broadens BME funding beyond merchant adoption, which is currently the design's weakest point during the bootstrapping phase: if merchants have not yet adopted $QRC, a verified human can still trigger BME by redirecting their balance to the activity rewards pool instead of letting it decay passively.

Proactive redirect vs. passive decay: these two pathways diverge in their effect on $QCB. A holder who redirects their balance to the activity rewards pool triggers BME; a holder who lets it decay passively does not. The activity rewards pool receives the $QRC in both cases. The design reason for the asymmetry is that proactive redirect is an action the holder takes, and actions should be rewarded; passive decay is the absence of action, and absences should neither be rewarded nor punished. This creates an incentive for participation without penalizing indifference.

The reflexive risk: BME funded by speculative redirects is not the same as BME funded by commerce. If holders redirect because they believe $QCB will appreciate, and $QCB appreciates because holders redirect, that is a self-referential loop that can inflate and then correct. The existing BME "live vs. speculative" threshold — burns funded at 1% of $QCB daily volume for 90 consecutive days — is the guard against this: redirect-driven BME, like any BME activity, is classified as speculative until it is complemented by merchant-driven BME that confirms real economic activity underlies the volume. The fee calibration and the specific conditions under which redirect-driven BME counts toward the "live" threshold are Open Question 25.

6.4 Value Flow Between the Two Tokens

The relationship is a one-directional value flow: $QRC is acquired (via QCB purchase path) → spent at merchants, consumed on network resources, or placed in resource-job escrow → the merchant or network charges a fee in fiat → that fee funds both buyback-and-burn of $QCB and staking yield to $QCB stakers → $QCB supply contracts, staking demand rises, and price appreciates. This flow describes the token movements that fund $QCB's value capture, not the sole mechanism that gives $QRC itself value — $QRC's value comes from the network resources it redeems (resource demand floor) and from the fiat settlement layer described in Section 8.2, which is the load-bearing piece that makes merchant acceptance possible.

$QRC does not benefit directly from $QCB's appreciation, and $QRC holders do not receive $QCB. The engine is $QRC being consumed in the resource economy; the pool is $QCB deepening as a result. $QRC's job is to price and ration network resources. $QCB's job is to appreciate, not circulate.

6.5 Why Two Tokens

A single-token model cannot serve both functions without contradiction:

Requirement | Single Token | Two Tokens
Spendable on resources | Holding competes with resource use | $QRC handles this (consumption burn drives natural supply contraction)
Holdable for value | Resource spending erodes holder value | $QCB handles this (no demurrage, no consumption obligation)
Value capture | Burns reduce spendable supply | $QCB captures value via BME
Governance | Token-weighted (whales dominate) | $QCB-weighted, or one-human-one-vote

The Cosmos ecosystem's experience is instructive: ATOM's staking yield comes mainly from inflation, not real revenue. In 2024, ATOM earned only $426,000 from Interchain Security while its annual issuance cost was $367,000,000 — real revenue was 0.12% of inflation. QCB avoids this trap by separating the currency from the asset: $QRC doesn't need to appreciate to function, and $QCB doesn't need to circulate to capture value.

One resource token, by design: QCB operates with exactly two protocol-level tokens ($QRC and $QCB), and the protocol does not permit application-layer currency or resource-token issuance. Other tokens on the chain — utility tokens, access tokens, NFTs, community tokens, meme coins — serve non-currency, non-resource purposes (collectibles, reputation, culture, access) and are explicitly not resource claims. This is not a limitation on what developers can build; it is a positive design commitment that makes $QRC's resource solvency invariant enforceable and $QCB's value capture coherent. The five-control resource solvency architecture (Section 6.10) only works if $QRC is the sole resource claim — the moment resource-substitutes are permitted, the CoverageRatio cannot be tracked and the epoch cap cannot be enforced. A single protocol resource token also means all network capacity consumption traces through the QRC consumption burn and through the BME to $QCB; multiple resource tokens would split the value capture and weaken $QCB's long-term thesis.

6.6 Governance

Governance operates on a one-human, one-vote basis for parameters affecting $QRC (conversion rate bounds R_min/R_max, epoch cap parameters β_cap/λ_cap, CoverageRatio thresholds CR_halt/CR_resume, consumption burn fraction p_burn), ensuring the resource token's rules are set by its users, not by capital. $QCB holders govern parameters affecting the chain itself (validator set, gas fees, treasury allocation) — stake-weighted, consistent with the asset's role as network ownership, but bounded by the personhood weighting described in Section 3.3.

Why one-human-one-vote needs a quorum floor: with attacker vote share modeled as f / (p + f), where f is the fraudulent-identity fraction of the legitimate population and p is legitimate turnout, low turnout directly amplifies a fixed fraud rate's practical power — a fraud rate that's negligible against 50% turnout can approach majority control at 3% turnout. Consensus safety (Section 3) tolerates fraud up to roughly 50% of the legitimate population; governance has no such cushion unless turnout is bounded from below.

Deriving the quorum from the Section 4 target, rather than picking a number arbitrarily: solving f / (p + f) < 0.5 for QCB's target fraud rate (f = 3%) gives p > 3% — legitimate turnout above 3% is sufficient to keep a 3% fraudulent population from reaching a majority of votes cast on its own. Solving the same inequality against the 1/3 threshold relevant to blocking a supermajority vote (f / (p + f) < 1/3) gives p > 6% — turnout above 6% is needed to keep a 3% fraud rate from being able to block a two-thirds-approval vote (Section 7.3) by holding more than a third of votes cast.

QCB's governance therefore enforces three distinct protections, not a single quorum percentage:

1. **Participation quorum** — a minimum share of the total verified-human population must participate for a vote to be valid at all. For ordinary QRC governance, this floor is set above 3% (the derived majority-safety threshold); for changes requiring supermajority approval, it is set above 6% (the derived blocking-safety threshold). Both floors scale automatically if the Section 4 sybil-rate target is later revised — they are a function of the target, not a fixed constant.
2. **Approval threshold** — among votes actually cast, the percentage required to pass: simple majority for ordinary QRC parameters, two-thirds or greater for constitutional changes (Section 7.3).
3. **Absolute minimum voter count** — a percentage-based quorum alone is insufficient at scale: 10% turnout means 100,000 voters at 1 million verified humans, but 10 million voters at 100 million. QCB additionally requires a minimum absolute number of participating verified humans for sensitive parameter changes, so that a percentage-based quorum satisfied by a small absolute population is not treated as equivalent to the same percentage satisfied by a large one. The specific absolute floor is an open question (Open Question 15) rather than fixed here, since it depends on population scale data not yet available.

These three protections compose: a proposal needs the participation quorum, the approval threshold among those who voted, and the absolute minimum count, all three, to take effect. This is deliberately more conservative than a single quorum number, because the 6% and 3% derivations above are lower bounds calculated against QCB's current worst-case sybil target — they should be treated as floors to build margin above, not targets to hit exactly.

Limits of this model: the f / (p + f) derivation assumes fraudulent identities act as a single coordinated bloc and that legitimate turnout p is exogenous — independent of what the attacker does. Both assumptions cut in different directions. Treating fraud as one coordinated bloc is conservative: real Sybil populations that split, abstain strategically, or vote with legitimate blocs to avoid detection are less dangerous than the model assumes, so uncoordinated fraud is safer than these floors imply. Treating turnout as exogenous is not conservative: a sophisticated attacker can suppress legitimate turnout directly — spamming proposals, inducing governance fatigue, targeted discouragement of specific voters — which lowers p and raises the attacker's effective vote share without raising f at all. The quorum floors derived above should therefore be read as minimum protection against passive, uncoordinated fraud, not as sufficient protection against an active turnout-suppression campaign, which is a distinct attack surface this model does not cover. Until Open Question 17 is resolved, QCB's governance should be treated as defended against passive fraud only — turnout suppression is an accepted, named open risk during the pilot phase, not a solved problem. See Open Question 17.

6.7 Distribution

Clarification on scope: the QRC Economic Model v0.1 has no daily-issuance formula tied to verified-human count. $QRC enters circulation primarily through the QCB purchase path — controlled by the five-control architecture (Section 6.10). The legacy VCA contribution-minting path is under review following the October 2026 architecture pivot; see Section 6.2 for the current model. The table below describes a one-time genesis allocation, funded from the initial $QCB supply and/or a dedicated QRC seed reserve set aside at launch, used to bootstrap development, merchant incentives, validator participation, and a stability reserve before organic $QRC minting (from QCB burns and provider contributions) and merchant fee revenue are self-sustaining.

Allocation | Share | Illustrative % | Notes
QRC liquidity seed (genesis reserve contribution) | Majority | ~70% | Seeds initial $QRC liquidity for the purchase path before QCB burn volume is self-sustaining; distributed through the settlement layer as initial conversion reserve
Reserve pool | Minority | ~11% | Yield-bearing assets backing stability
Long-term distribution | Small | ~4% | Released to $QRC lockers over 8 years — see Section 6.9
Development | Small | ~7% | Vested, disclosed on-chain
Merchant incentives | Small | ~5% | Onboarding rewards, early-adopter bonuses
Validator rewards | Small | ~3% | Staking incentives for chain security

Illustrative percentages shown are non-final examples consistent with the ceiling below, not committed figures — percentages are of the total genesis allocation, whose absolute size (in $QCB, USD, or QRC) is itself unset pending Open Question 7.

Distribution principle: this genesis allocation is designed so the QRC liquidity seed (the majority allocation) goes toward bootstrapping the purchase and contribution paths rather than toward any single interest group. For the allocations funded separately (development, merchant incentives, validator rewards, reserve pool), no single non-liquidity allocation is intended to exceed a low double-digit percentage of the genesis allocation — a ceiling meant to prevent any one interest group (founders, merchants, or validators) from accumulating outsized claims on the system's initial resources. Exact percentages within that ceiling remain to be finalized (see Section 12), but the ceiling itself, and the structural dominance of the liquidity seed, are intended as founding commitments rather than launch-day placeholders.

6.8 Summary

| $QRC | $QCB
Purpose | Resource consumption (network capacity claims) | Capture value
Supply | Minted via QCB purchase (primary); contribution-minting path under review | Fixed or capped
Demurrage | No (resource claims do not decay) | No
Staking | No | Yes
Value driver | Network resource demand; resource solvency (CoverageRatio ≥ CR_min) | Network activity (fees → burns)
Governance | One human, one vote | Stake-weighted, personhood-bounded
Holder profile | Resource consumers, provider nodes, developers | Long-term believers, stakers
Appreciation | Not a goal | Primary goal

$QRC is spent on network resources. $QCB is the asset you hold. QCB captures the value. QRC prices the compute.

6.9 Long-Term Distribution

The genesis allocation in Section 6.7 solves how QCB bootstraps before organic issuance and fee revenue are self-sustaining. It does not, on its own, solve a separate problem: with the entire 210 million $QCB cap minted at genesis, every unit is already spoken for on day one. A person who verifies and begins participating years into QCB's life has no path to $QCB that a person present at genesis didn't already have. For a chain designed to still be functioning long after its founders are gone (Section 7.3), that is a real legitimacy gap, not a cosmetic one.

The fix is not new issuance — the 210 million cap stays exactly as fixed and tested as it already is. The fix is a locked release schedule carved out of the existing genesis allocation: a portion is set aside at genesis and released gradually, over years, to verified humans who lock $QRC, rather than being distributed to its final holders all at once.

This is deliberately not described as mining. Nothing is created; existing, already-capped supply is what moves. The correct category is a locked distribution schedule — the same category of mechanism as a vesting contract or a liquidity-mining program, both well-understood and non-controversial across other chains (Solana's multi-year release schedule, Ethereum's ICO-token vesting, Cosmos chains' validator and community-pool releases). None of those are described as mining, and neither is this.

Parameters:

Size — 4% of total $QCB supply (8.4 million $QCB), carved from the Reserve pool line in Section 6.7's genesis allocation (reducing it from ~15% to ~11% of the total genesis allocation). This keeps the mechanism well inside the "low double-digit percentage" ceiling Section 6.7 already sets for any single non-activity-rewards allocation.

Duration — 8 years.

Curve — linear, not decaying. This is a deliberate choice, not a default: Section 6.7's merchant incentives line already carries the "be early" incentive — rewarding merchants who onboard sooner rather than later. A decaying curve here (Bitcoin-style halving, front-loaded release) would duplicate that same message through a second mechanism aimed at a different audience. This mechanism's job is different: staying open to genuine latecomers for a meaningful stretch of QCB's life, not accelerating early participation. A flat, linear release is what actually keeps that door open for eight years instead of mostly closing it in the first one or two.

Mechanism — verified humans who lock $QRC receive a proportional share of the pool as it releases. The specific lock duration, minimum lock size, and proportional-share formula are implementation parameters, not fixed here; they are governed the same way other QRC parameters are (Section 6.6), not constitutionally.

What this is not: this section does not cover activity-based $QCB accrual — a related but distinct idea where $QCB is earned through measured $QRC economic activity rather than through locking a balance. That mechanism depends on unresolved questions this document is not yet in a position to answer, including — in one of its proposed forms — a dependency on Human Capacity Markets, which is itself unresolved. It is recorded as a named extension under Open Question 26, not specified here, and not treated as a second claim on this section's 4% allocation.

6.10 QRC Resource Economy — Five-Control Architecture

The $QRC model uses one primary issuance path: QCB holders burn $QCB to convert it into $QRC. A legacy contribution-minting path (VCA-attested `CreditProvider`) exists in the codebase but is classified as under review following the October 2026 architecture pivot, under which resource providers receive payment from job escrow rather than through new issuance. The five controls below govern the primary purchase path. Section 6.2 describes the full issuance model, including the escrow-based provider payment mechanism and the status of the legacy contribution path.

This section also introduces the resource economy framing that governs both paths: $QRC is not a monetary supply whose price must remain stable. It is a redeemable claim on network resources — compute, storage, ZK proving, oracle queries, AI inference, and bandwidth. The correct economic invariant is not price stability. It is resource solvency:

QRC_outstanding ≤ Capacity / CR_min

If the network has issued more $QRC than it can service at the target coverage ratio, the system is insolvent regardless of price. The five controls below enforce this invariant.

Why this framing matters: a token-inflation lens (is $QRC supply growing too fast?) misses the failure mode that the v2 simulation uncovered — a scenario with only +1.5% supply growth and apparently stable monetary behavior, but a CoverageRatio of 0.005. The network had issued 200x more resource claims than it could service. Price and supply metrics showed nothing. Only the CoverageRatio showed the solvency collapse. The five-control architecture is designed to prevent exactly this.

Control 1 — Dynamic Conversion Rate

$QCB converts to $QRC at a rate R_t that responds to network utilization:

R_t = R_0 × (U* / U_bar_t)^γ, clamped to [R_min, R_max]

where U_bar_t is an exponential moving average of utilization (smoothing parameter α = 0.10 prevents rapid rate oscillations), U* = 0.70 is the target utilization level, and γ = 1.5 controls the price sensitivity to utilization deviations. When the network is near empty (U_bar → 0), the price ceiling R_max becomes the binding constraint, preventing the unlimited QRC creation that a pure utilization-based rate would allow at low utilization.

Simulation-derived starting parameters: R_max = 2.0, R_min = 0.5. These values were determined empirically: stress tests showed that R_max = 5.0 allows +489% supply growth under a sustained adversarial QCB dump at near-zero utilization. R_max = 2.0 limits adversarial supply growth to under 6% — but the price ceiling alone is not the load-bearing safety mechanism. That role belongs to Control 2.

Control 2 — Epoch Conversion Cap

The maximum $QCB that any epoch may convert into $QRC is bounded independently of price:

QCB_converted(epoch) ≤ L_e

This is the dominant safety control. An adversary cannot manufacture large quantities of $QRC by exploiting low utilization and the price ceiling — the epoch cap limits total conversion volume regardless of the rate. Simulation confirmed that with L_e = 1,000 QCB/epoch, a sustained adversarial dump of 5,000 QCB/tick is fully contained (CR_min = 0.999 over 200 epochs).

The epoch cap is adaptive by default:

L_e = β_cap × Capacity_e + λ_cap × Demand_e

where β_cap = 0.001 and λ_cap = 0.0005. The adaptive form automatically tightens when the network is empty: at near-zero utilization, Demand_e → 0, so L_e ≈ β_cap × Capacity — the cap scales with available resources rather than being fixed at a value that may be appropriate for one network size but wrong for another. This eliminates the adversarial exploit of dumping into an empty network, because an empty network produces a small cap.

Control 3 — Capacity Tracking

$QRC is a claim on network resources. If the measurement of available resources is wrong, the solvency invariant cannot be enforced. Control 3 requires on-chain, per-epoch measurement of total active provider capacity across all resource types: compute, storage, ZK proving, oracle, AI inference, bandwidth. Provider capacity is not self-reported without check — the VCA mechanism (Section 6.2) provides the attestation infrastructure for this measurement.

This control is what makes CoverageRatio meaningful rather than circular: without independent capacity tracking, CR could be gamed by providers inflating their reported capacity. With it, outstanding QRC can be compared against real, attested resource availability.

Control 4 — Consumption Burn

Every unit of $QRC consumed — spent on actual network resource usage — destroys a fraction p_burn permanently:

QRC_burned = p_burn × QRC_consumed

At p_burn = 0.25, 25% of every resource-consumption event is destroyed. This creates a natural supply contraction proportional to usage: the more the network is used, the more $QRC is permanently removed from circulation. This prevents indefinite accumulation of outstanding claims even when the network is busy.

Simulation result: at high utilization (U = 0.99) with p_burn = 0.25, the 25% burn permanently contracts supply over time. Attempts to accumulate $QRC without actual resource consumption face the circuit breaker (Control 5).

Control 5 — CoverageRatio Circuit Breaker (Resource Solvency Mechanism)

The CoverageRatio measures network solvency in resource terms:

CR_t = Capacity_t / QRC_outstanding_t

This is not a monetary policy mechanism. It is a resource solvency mechanism. The distinction is important for QCB specifically: $QRC is a claim on actual network capacity, not a speculative token. CR < 1.0 means the network cannot service all outstanding $QRC claims simultaneously. CR → 0 means the network is economically insolvent — it has issued far more resource claims than it can honor.

The circuit breaker enforces a minimum coverage ratio through a three-state hysteresis machine:

State | Condition | QCB→QRC Conversion | Resource escrow/payment
NORMAL | CR ≥ CR_resume | Open | Open
RESTRICTED | CR_halt ≤ CR < CR_resume | Suspended | Open
HALTED | CR < CR_halt | Suspended | Suspended

The hysteresis band (CR_halt < CR_resume) prevents oscillation: without it, a single threshold would repeatedly switch minting on and off as CR hovers near the boundary. Resource escrow and provider payment remain available in RESTRICTED because providers should not be penalized for a capacity collapse they did not cause — only QCB conversion, the discretionary mint path, is suspended.

Simulation-derived starting parameters: CR_halt = 0.75, CR_resume = 1.00.

Why CR_halt = 1.00 was rejected: the recovery test (capacity collapses to 20% of baseline, then recovers to 100% over 400 epochs) showed that CR_halt = 1.00 / CR_resume = 1.25 results in minting never resuming within 400 ticks. The system cannot recover from realistic capacity shocks under those parameters. CR_halt = 0.75 / CR_resume = 1.00 resumes minting at t = 262, giving the system adequate headroom to recover from provider-exit scenarios without the circuit breaker becoming a permanent lock.

What the circuit breaker cannot do: it can halt new minting when capacity falls, but it cannot restore capacity. Provider exodus scenarios (Scenario 3 in the v3 stress test) saw CR → 0.027 despite the circuit breaker halting minting at tick 23. The breaker buys time and prevents supply accumulation during a capacity collapse — it does not rebuild the network. Real recovery requires providers to return or new capacity to join. The circuit breaker is one layer of protection, not a substitute for capacity incentives.

Architecture Summary

The five controls form a layered defense with the following separation of concerns:

Control | Mechanism | Protects against
1 — Dynamic price | R_t ∈ [R_min, R_max] | Mispricing under congestion or low utilization
2 — Epoch conversion cap | L_e = β_cap × Capacity + λ_cap × Demand | QCB conversion floods; adversarial dump at low U
3 — Capacity tracking | On-chain VCA-attested resource measurement | Resource over-issuance; measurement gaming
4 — Consumption burn | p_burn = 0.25 of every consumption event | Persistent QRC accumulation; sybil farming
5 — CR circuit breaker | CR_halt = 0.75, CR_resume = 1.00, three-state hysteresis | Capacity collapse / provider exodus

The economic architecture is:

QCB → (burn) → QRC → Network Resources → (p_burn) → destroyed

while the resource market path (escrow model) is:

Agent $QRC → ResourceEscrow → (job verified) → Provider $QRC → Resource consumption → (p_burn) → destroyed

and the safety boundary is:

CR < CR_halt ⟹ QRC issuance suspended

Simulation basis: the five-control architecture was validated through three simulation passes totaling 135 scenario configurations (qrc_stress_test.py, qrc_stress_test_v2.py, qrc_stress_test_v3.py in the chain-forge-engine repository). The parameters above are simulation-derived starting values, not immutable economic constants. The core protocol invariant — zero ticks where minting was allowed while CR < 0.10 — was verified across all 15 main scenarios in the v3 sweep. Governance may adjust all parameters in this section (Controls 1–5 thresholds) through the ordinary $QRC governance process described in Section 6.6.

---

7. Sovereignty, Execution Environment, and the Constitutional Layer

7.1 The sovereignty constraint

QCB Chain is designed as a self-contained Layer-1. There are no bridges, no interoperability connections, and no wrapped assets in the initial architecture. This is intentional: interoperability introduces attack surface, identity leakage, and governance complexity that conflict with QCB's core design — one verified human, one vote, at every layer of the stack.

Interoperability is deferred to a future phase and will only be pursued if a bridge design can preserve proof-of-personhood end to end. Any bridge that would allow unverified actors to hold or use $QRC or $QCB is architecturally forbidden — this is the specific, narrow thing "forbidden" refers to, not a blanket ban on ever building a bridge. This constraint will be revisited only after the chain is live and stable, merchant adoption is real, the identity layer has survived adversarial pressure at scale, and there is a concrete reason to interoperate.

7.2 Permissioned EVM layer

QCB absorbs EVM capability natively rather than bridging to an EVM-compatible chain. The distinction matters: bridging to Ethereum or an EVM chain violates the sovereignty constraint and allows unverified actors into the system. Running a permissioned EVM execution environment inside QCB — where the EVM is subject to QCB's identity layer rather than bypassing it — does not.

The design is inspired by Flare Network in the general sense: an EVM environment that is not simply a clone of Ethereum's assumptions — one that operates under additional protocol-layer constraints rather than inheriting the anonymity and permissionlessness of the original EVM. The specific constraint QCB applies is its own: identity linkage through Charm Confinement (Section 5.1). EVM contracts on QCB are Sponsored Contracts — a subclass of Charmed Agent — not anonymous accounts. Every Sponsored Contract has a SponsorID linking it to a verified human, and the sponsor is accountable for the contract's behavior under QCB's governance model. Every contract must have a SponsorID linking it to a verified human, every $QRC or $QCB transfer in or out of an EVM contract passes through the protocol's identity checks, and no EVM contract can hold or issue tokens that bypass the two-token separation or governance layers.

Why EVM on these terms is worth having: the EVM is the largest smart contract developer ecosystem in existence. Solidity developers can deploy on QCB without learning a new language, provided they are deploying code that does not depend on anonymous counterparties or excluded opcodes (see Open Question 23(e) — the opcode subset question is not yet resolved, and full EVM equivalence is not guaranteed). Existing wallets (MetaMask and equivalents) work with QCB's EVM layer for accounts that are SponsorID-linked. DeFi protocols, NFT systems, and autonomous agent frameworks built for EVM chains can be ported to QCB with the caveat that every participant must be sponsor-verified — they inherit QCB's identity constraints rather than importing EVM's anonymity assumptions.

Why general EVM without identity constraints would break QCB: an anonymous EVM contract can receive $QRC, pool it, and issue synthetic tokens against it — effectively creating a shadow economy that bypasses the identity layer without requiring a cross-chain bridge. The same attack that bridges enable (unverified actors accessing $QRC) can be executed entirely on-chain through an anonymous contract. A permissioned EVM prevents this: every contract is sponsored by a verified human, and the sponsor is accountable for the contract's behavior under QCB's governance model.

The permissioned EVM layer is a Phase 5+ addition — not because the concept conflicts with QCB's design, but because it depends on the identity layer being proven at scale first (Section 4). The identity layer must be able to reliably link EVM accounts to verified humans before anonymous EVM contracts become a gating risk. Adding EVM before identity is proven would give the EVM layer's anonymity assumptions priority over QCB's identity guarantees, which inverts the dependency. See Open Question 23.

What the permissioned EVM does and does not enable:

Enabled: Solidity smart contracts sponsored by verified Charmed Agents; EVM-compatible wallets interacting with QCB accounts linked to verified identities; DeFi protocols operating under QCB's demurrage and governance rules; autonomous agent frameworks using EVM tooling within Charm Confinement boundaries; asset tokens — tokenized real-world assets including securities, Treasuries, commodities, real estate, and private credit — issued and held under the same SponsorID and non-currency rules that govern all application-layer tokens. Asset tokens represent ownership of an underlying asset; they are not mediums of exchange, and RWA transactions on QCB are denominated in $QRC (the asset token is what is being bought or sold, not the settlement currency). QCB's identity layer provides compliance-at-the-protocol-layer for RWA issuance — every holder is a verified human with a SponsorID — which is the property that traditional RWA platforms spend the most effort achieving through external KYC/AML wrappers. The role of RWA trading as a second demand source for $QRC, and how it relates to the merchant-adoption bootstrapping problem, is described in Section 8.2.

Not enabled: anonymous EVM accounts; contracts without a SponsorID; synthetic tokens that substitute for $QRC as a resource claim or that bypass QCB's two-token separation; governance votes from EVM contracts rather than from the verified human sponsors behind them; EVM-based bridges to external chains that import unverified actors.

Currency issuance reserved to the protocol: Sponsored Contracts can issue non-currency tokens — utility tokens, access tokens, NFTs, community tokens, meme coins — but cannot issue tokens designed to function as a medium of exchange. Currency issuance on QCB is reserved to the protocol itself, in the same way that identity verification is reserved to the protocol. This is enforced at the protocol layer: only $QRC can be used for activity rewards distribution, merchant settlement through the Merchant API, and payment to Charmed Agents. Non-currency tokens are excluded from QCB's economic plumbing — they can exist and trade, but they cannot access the mechanisms (activity rewards, settlement layer, agent infrastructure) that give $QRC its utility. A token that bypasses these mechanisms exists in a parallel economy without active earners, merchant settlement, or agent infrastructure; it is, functionally, a collectible with a ticker rather than a currency. The protocol cannot prevent all informal peer-to-peer use of arbitrary tokens, but it does not need to: the economic plumbing is what makes $QRC valuable, and nothing else gets that plumbing.

What the permissioned EVM cannot build: the class of DeFi primitives that depend on anonymous counterparties — permissionless automated market makers, lending pools with unlinked borrowers and lenders, composable derivatives where participants are not individually verified — cannot be built on QCB's permissioned EVM, because every participant must be sponsor-verified. This is a real reduction in what "EVM compatibility" means relative to Ethereum. QCB's EVM is compatible with Solidity as a language and with EVM tooling as an ecosystem; it is not compatible with Ethereum's permissionlessness as a design principle. A developer porting a project from Ethereum should expect to rethink any component that relies on anonymous participation before it can run on QCB.

Identity-layer coupling: every EVM state transition in QCB requires a SponsorID check against the identity layer. This means identity-layer availability is EVM availability, and identity-layer throughput is an EVM throughput ceiling. Section 3.3 established that consensus security inherits identity-layer weaknesses; the permissioned EVM extends that inheritance to the execution environment as well. This is a deliberate cost of the permissioned model — the alternative is an anonymous EVM, which the sovereignty constraint forbids — but it is a coupling, not a free abstraction. An identity-layer outage or performance degradation affects EVM execution directly.

Scope: the permissioned EVM is orthogonal to the settlement layer (Section 8) and does not change $QRC's external value proposition, the merchant-adoption problem, or the cold-start requirement (Section 8.5). Adding an EVM execution environment adds a familiar development surface for building on QCB's economy; it does not add a reason for that economy to exist. The settlement layer remains the load-bearing precondition for $QRC having external value, regardless of what execution environment sits above it.

7.3 The Constitutional Layer

QCB is designed for long-term survival — past any single development team, jurisdiction, or identity method. That requirement is different from designing for launch, and it demands a layer of rules that sits above ordinary governance.

Ordinary governance changes parameters: decay rates, fee levels, exemption thresholds, treasury allocation. The constitutional layer is different — it defines what cannot be changed by ordinary governance, and the specific, higher-bar process by which it can be changed if it must be. Other durable chains have such a layer too, even where it's informal and enforced only by social consensus rather than being written down explicitly. QCB's is explicit, because QCB has more interdependent parts that need to survive longer.

What lives in the constitutional layer:

· The identity primitive's replacement mechanism — not the current PoP method itself, but the guarantee that it can be replaced if it fails, is gamed, or is made obsolete by new technology, without forking the chain, losing state, or invalidating existing verified claims and activity rewards history.
· The cryptographic-primitive replacement mechanism (Section 10) — structurally identical to the identity-primitive replacement mechanism above: not any specific signature algorithm, but the guarantee that the signature scheme securing accounts, validators, and identity proofs can be replaced — most urgently in response to quantum-computing advances — without forking the chain or invalidating existing account history.
· The two-token separation of function ($QRC circulates, $QCB captures value) — this split is foundational to the economic model, not a parameter to be tuned.
· The sovereignty constraint — three related commitments that form a unified whole: (a) no bridge or interoperability path that allows unverified actors to hold or use $QRC or $QCB; (b) no EVM execution environment that allows anonymous accounts (accounts without a verified SponsorID) to hold, transfer, or govern $QRC or $QCB — the permissioned EVM layer (Section 7.2) is explicitly carved out as constitutional-compliant because it enforces SponsorID linkage; and (c) no token issued on QCB may function as a currency substitute for $QRC — currency issuance is reserved to the protocol, and no application-layer token may be accepted as payment through QCB's economic plumbing (activity rewards, Merchant API, Charmed Agent settlement). The three constraints reinforce each other: bridges, anonymous accounts, and parallel currencies are all vectors for the same attack — allowing unverified or unaccountable actors to access the economic mechanisms the identity layer is designed to control.
· The amendment process itself — what supermajority, what verification-of-humans threshold, and what waiting period is required to change anything in this layer.

What does not live here: decay rates, fee percentages, exemption thresholds, treasury allocations, and other tunable parameters remain ordinary governance — adjustable by the one-human-one-vote process described in Section 6.6, without the higher bar required for constitutional change.

How the constitutional layer is enforced: hybrid, and honestly so. Ordinary governance transactions are code-restricted from touching constitutional values directly — no standard parameter-change vote can alter the identity-replacement mechanism, the two-token split, or the sovereignty constraint. But as with any permissionless chain, code enforcement has a ceiling: validators could still, in principle, agree to run modified client software that ignores these restrictions — the same way Bitcoin's 21 million cap or Ethereum's Merge were ultimately upheld by social consensus, not by any barrier a sufficiently coordinated majority couldn't route around. QCB does not claim its constitutional layer is unbreakable. It claims that breaking it requires an explicit, visible, and deliberately difficult act — not an ordinary governance vote — and that this friction is the actual protection, consistent with how every durable chain's hardest constraints have worked in practice.

Amendment process (sketch, to be finalized): a constitutional change requires (a) a supermajority of verified-human votes substantially higher than the threshold for ordinary governance — proposed at two-thirds or greater — (b) a minimum quorum of total verified humans participating, derived in Section 6.6 (see that section for the derivation): not the 3% majority-safety floor used for ordinary QRC votes, but the stricter 6% blocking-safety floor Section 6.6 sets for supermajority-approval changes, per the f / (p + f) < 1/3 condition against the Section 4 sybil-rate target, plus the absolute-minimum-voter-count protection from 6.6 rather than a percentage alone, and (c) a mandatory public waiting period between proposal and execution, giving the network time to review, contest, or exit before the change takes effect. Exact thresholds remain an open question (Section 12), but the shape — higher bar, broader participation, enforced delay, all three of 6.6's protections applied at the higher constitutional bar — is intended to be a founding commitment.

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

· **Attack tests passing — in-process and over real libp2p TCP.** In-process scenarios: forged vote rejection, equivocation detection and slash, liveness slash (confirmed on live testnet). Over-gossip adversarial integration tests (September 2026): a real libp2p attacker peer opens a genuine TCP connection to the devnet and publishes malicious gossip — not in-process injection. Three tests: `adversarial_unknown_validator` (vote from `qcb1evil` not in genesis → UnknownValidator rejection confirmed, chain keeps advancing); `adversarial_equivocation_over_gossip` (two conflicting Prevotes for the same height/round from `qcb1alice` → equivocation detected, asserted at the correct validator + height in node logs); `adversarial_garbage_signature` (garbage-sig vote from `qcb1bob` → actively rejected via real Ed25519 verification after resolving KNOWN_ISSUES §3 — root cause was `TendermintEngine.chain_id` never initialised from genesis, now fixed). All three passing.

· **ConsensusError::Equivocation → SlashingModule::slash_equivocation() fully wired.** `process_equivocation_evidence()` in `chain-forge-node` receives consensus-detected equivocation evidence (double vote / double precommit at the same height, round, and type) and routes it to `self.slasher.slash_equivocation()` in `chain-forge-slashing`. The `SlashingModule` is imported, instantiated at node startup, and integrated with the `ValidatorRegistry` (genesis validators activated and PoP-confirmed at block 0). Equivocation slash records are written to slash history and validator power is immediately reduced. Full round-trip: a validator that double-votes on-chain is detected by consensus, slashed by the slashing module, and its status reflected in the registry — no manual intervention.

· **ML-DSA (Dilithium3) post-quantum crypto wired.** The `chain-forge-crypto` crate implements CRYSTALS-Dilithium3 (ML-DSA) as the validator signing scheme, addressing the post-quantum exposure described in Section 10.

· **Block explorer REST API live.** `/api/status`, `/api/blocks/`, `/api/txs/`, and `/api/accounts/` serve live chain state on every block commit.

· **State persistence.** Committed blocks are written to disk on every commit; restarted nodes resume from their last committed height.

· **QRC Economic Model v0.1 implemented (`chain-forge-qrc`).** The token previously named CIRFI (Circulating Finance) has been renamed $QRC (Quark Resource Credit) throughout the codebase — Rust sources, TOML manifests, markdown docs, and simulation scripts. The `chain-forge-qrc` crate implements the full QRC Economic Model v0.1: `QrcEngine` (dynamic conversion rate, epoch conversion cap, CoverageRatio circuit breaker); `contribution_settlement` (VCA-verified provider earn path — legacy, under review); and the `CapacityEvidence_v0` sub-protocol (Byzantine-resistant median aggregation of provider capacity reports across 7 resource types). The consumption split (60% providers / 25% burn / 15% reserve) and per-resource congestion pricing are wired. `QrcEngine` is serde-serializable and persisted to `qrc.json` across node restarts. 65+ crate-level tests passing; adversarial over-gossip integration tests shipped separately in `chain-forge-node` (see attack tests above).

**QRC Architecture Pivot (October 2026).** Following extended design review, the economic assumption underlying provider payment has been revised: resources are primarily sold for existing $QRC rather than minting new $QRC through contribution. Provider nodes receive payment when job-escrowed $QRC is released on verified completion (`ResourceExecutionReceipt`), not when `CreditProvider` credits are applied. This keeps total supply controlled entirely by the purchase path and eliminates the inflationary pressure of contribution-minting. The `chain-forge-resource` crate (new, Phase 0) will implement the resource market layer — `ResourceOffer`, `ResourceRequest`, `ResourceMatch`, `ResourceJob`, `ResourceReceipt`, `ResourceMeter`, `ResourceProof`, `ResourceSettlement` — cleanly separated from `chain-forge-qrc`, which handles money. `CreditProvider` and `QrcContributionSettle` are classified as legacy/under review; `CapacityEvidence_v0` is evolving toward `ResourceExecutionReceipt`. See the ROADMAP Phase 0 section for the full component classification table and the Phase 0 acceptance test specification.

What remains open at the Chain Forge layer: production-grade state tree (JMT-based); personhood-weighting overlay; dedicated Chain Forge whitepaper. All three planned BFT variants are now shipped (see below).

**HotStuff-style BFT variant shipped (October 2026).** `HotStuffEngine` implements three-phase (PREPARE → PRE-COMMIT → COMMIT) QC-locked consensus with linear O(n) messaging per block. Key properties: safety rule (Theorem 2 — a new block must extend the highest locked QC or carry a higher-view PREPARE QC); locked QC set on PRE-COMMIT quorum and cleared on COMMIT; personhood cap and VCA weight adjustments applied at init; equivocation detection in the PREPARE phase; view-change via `record_new_view()`. 17 dedicated tests passing. This confirmed the pluggable architecture is real — two independent BFT variants (Tendermint-style and HotStuff-style) running against the same `ConsensusEngine` trait.

**XRPL-inspired FBA variant shipped (October 2026).** `FbaEngine` implements Federated Byzantine Agreement with a global Unique Node List (UNL) and an 80% agreement threshold (tunable via `FbaConfig`). Key properties: no leader rotation — every validator proposes independently; single-phase (Open → Committed) rather than multi-phase like Tendermint or HotStuff; equivocation detection on double-vote (same height, different block); personhood cap and VCA adaptive quorum applied at init; min-UNL guard (consensus refuses to start with an undersized validator set). The design follows XRPL's proven model: safety requires only 80% UNL agreement rather than a 2/3 supermajority, and the system tolerates up to 20% Byzantine validators without forking. 18 dedicated tests passing. This completes the three-variant pluggable consensus suite — Tendermint-style, HotStuff-style, and XRPL-inspired FBA all implement the same `ConsensusEngine` trait and are switchable at node configuration time. BFT variant selection for QCB mainnet (Open Question 2) is now unblocked.

A dedicated Chain Forge whitepaper, aimed at the developer audience who would build their own chains on it, is expected once the engine is closer to a general release. For now, this document is the only public artifact and carries both the engine's story and the flagship chain's.

---

8. Merchant Integration and the Settlement Layer

8.1 What merchants receive

Merchants receive: a fiat settlement option (zero volatility exposure), fees of 0.5%–1% versus 2%–3% for credit cards, and a Stripe-compatible API with Shopify/WooCommerce plugins for fast onboarding. QCB's structural demand driver for $QRC is not demurrage but resource consumption: every agent service, AI inference call, oracle query, ZK proof, and storage operation requires $QRC, giving the network a built-in resource-demand floor that grows with agent economy usage rather than requiring merchant density to exist first.

Bootstrapping gap: merchant integration as a $QRC payment channel is an additive demand source on top of resource-consumption demand. In the first 6–12 months post-launch, onboarding is expected to rely on direct merchant incentive allocations (Section 6.7) and manual outreach. The protocol does not yet specify what happens if merchant acceptance fails to reach critical mass within that window — that scenario is covered by Open Question 11's stagnation-resilience question, not by an automatic fallback mechanism described here.

8.2 Where $QRC's value comes from — and why the settlement layer is load-bearing

$QRC is designed to be spent, not held. But spending presupposes value: a merchant who accepts $QRC is committing to trade real goods for it, which only makes sense if $QRC can be converted into something the merchant can use. This is not a design flaw — it is the system working as intended — but it requires a mechanism the whitepaper has previously treated as a bullet point rather than a load-bearing component.

The mechanism is the fiat settlement layer. When a merchant accepts $QRC and opts for fiat settlement, the settlement layer buys that $QRC at a defined rate and pays the merchant in fiat. The settlement layer then holds the $QRC it purchased — or sells it on the open market — to replenish its reserves. This creates the value loop:

$QRC acquired (via QCB burn) -> spent at merchants, consumed on network resources, or placed in resource-job escrow -> merchants settle to fiat via settlement layer -> settlement layer buys $QRC on the open market -> market price is discovered.

The market price that emerges from this loop is not the source of $QRC's value — it is the discovery mechanism. The source of value is merchant acceptance, which is enabled by the settlement layer, which is backed by reserves. $QRC's value is, precisely: whatever the settlement layer is willing to convert it for, backed by the reserves that fund that conversion. This is why the settlement layer is load-bearing: without it, merchant acceptance collapses, and without merchant acceptance, $QRC has no demand source and therefore no value, and therefore cannot function as a circulating currency regardless of how many verified humans receive it.

$QRC must therefore exist on a market — this is correct and intended. It is not in tension with the design. The question is not whether $QRC has a market price, but whether the settlement layer is robust enough to sustain that price under adversarial conditions and redemption pressure.

A second demand source: real-world asset (RWA) trading on QCB provides a second demand source for $QRC alongside merchant payments. RWA transactions — buying tokenized Treasuries, trading tokenized real estate, settling private credit — are all denominated in $QRC (the RWA token is the asset being exchanged; $QRC is the settlement currency). Every RWA trade is therefore a $QRC transaction, which flows through the BME and benefits $QCB holders. The RWA market is large and growing — on-chain tradable RWA value reached approximately $33.5 billion by mid-2026, nearly triple the prior year — and QCB's identity layer provides compliance-at-the-protocol-layer that most RWA platforms achieve only through external wrappers. This makes QCB a natural fit for institutional RWA issuance, and institutional RWA trading a natural fit for $QRC demand, without requiring any new protocol features beyond the permissioned EVM layer already planned for Phase 5+.

RWA demand is also a weaker-precondition demand source than merchant demand — and that distinction matters for the bootstrapping problem. Merchant demand requires merchants to be onboarded and active resource consumers to hold $QRC. RWA demand requires none of those: it depends only on the settlement layer being able to convert $QRC, and on there being tokenized assets worth trading. That is a lower bar to clear. If merchant adoption is slow to bootstrap (Section 8.1's bootstrapping gap), RWA trading could provide $QRC with a functioning demand source and a real market price before the resource-consumption loop reaches meaningful volume — partially decoupling $QRC's early value from the harder bootstrapping problem. The two demand sources are parallel paths, and either one reaching meaningful volume is sufficient to give $QRC external value; neither is strictly required before the other.

8.3 Settlement layer design requirements

For the settlement layer to fulfill its role, it must satisfy four properties:

Reserve adequacy — the settlement layer must hold sufficient reserves (fiat, stablecoins, or liquid assets) to cover redemption demand. The minimum reserve requirement is a function of daily $QRC issuance, merchant conversion volume, and the settlement rate. At launch, this is a bootstrapping problem: reserves must be seeded before activity rewards issuance begins, or the first merchant conversion will exhaust them. Reserve sizing is an open question (Open Question 18); the pre-launch cold-start case — which is a distinct problem from ongoing reserve sizing, because it requires external money before the protocol has any value to offer in return — is Section 8.5.

Rate stability — the conversion rate at which the settlement layer accepts $QRC for fiat determines $QRC's effective purchasing power. A floating rate exposes merchants to volatility (undermining the "zero volatility exposure" promise); a fixed rate requires the settlement layer to absorb all price fluctuation through its reserves. The whitepaper does not yet specify which regime QCB uses; this is Open Question 19.

Governance and trust minimization — whoever operates the settlement layer has significant power: they set the rate, manage the reserves, and decide who gets to convert. A centrally-operated settlement layer is a single point of failure and a centralization risk inconsistent with QCB's sovereignty principle. The settlement layer's governance — whether it is operated by a protocol-native reserve mechanism, a multi-sig DAO, or a licensed financial entity — is an open question (Open Question 20) with legal and jurisdictional dimensions that interact with Open Question 5 (jurisdiction and legal entity structure).

Consumption burn and settlement rate interaction — $QRC under the QRC Economic Model v0.1 carries no demurrage; balances do not decay passively. However, $QRC consumed on actual network resources triggers a 25% burn (p_burn = 0.25). This does not affect the fiat settlement rate directly, but it does affect the outstanding supply that the settlement layer must stand behind. If network utilization is high and large fractions of outstanding $QRC are being burned, the settlement layer's reserve denominated in $QRC may shrink faster than anticipated. The interaction between the consumption burn rate, outstanding supply, and the settlement rate regime is not yet fully specified and is an open question (Open Question 21).

8.4 Settlement layer failure modes

The settlement layer's failure modes are distinct from the identity layer's and deserve explicit naming:

Reserve exhaustion — if conversion demand exceeds reserves, the settlement layer must either halt conversions (breaking the value link entirely) or let the rate float (causing $QRC to depreciate). Either outcome causes merchant confidence to collapse, which reduces conversion demand, which may allow reserves to partially recover — but the recovery path is not guaranteed and the damage to merchant adoption may be permanent.

Reflexive collapse — $QRC's value depends on merchant acceptance, and merchant acceptance depends on $QRC having value. If a large merchant stops accepting $QRC, the resulting price decline may cause other merchants to follow, triggering a spiral. This is the same reflexivity problem identified in BME (Section 6.3), applied to $QRC's demand side rather than $QCB's supply side. The settlement layer is the circuit breaker — it can support the price by buying $QRC — but only for as long as its reserves last.

Settlement layer capture — if the entity or mechanism operating the settlement layer is compromised, captured by an attacker, or acts adversarially, it can manipulate conversion rates or halt redemptions. This is the most serious centralization risk in QCB's current design and is the reason Open Question 20 (settlement layer governance) is a permanence question rather than a calibration question.

These failure modes are named here rather than routed to Section 12 (Open Questions) because they are not calibration choices — they are the consequences of how the settlement layer is designed, and any design choice in Open Questions 18–21 must be evaluated against them explicitly.

8.5 Settlement layer cold-start

The settlement layer has the same cold-start problem as the identity layer and the merchant layer — but it is the hardest of the three, because it requires real external value rather than just user adoption.

At genesis, $QRC has no market price, because there is no market. $QCB has no market price for the same reason. The settlement layer has no reserves unless they are seeded from outside the system before any $QRC exists. BME cannot function because there are no merchants and no fees. The value loop described in Section 8.2 (active earners spend -> merchants settle -> settlement layer buys $QRC -> market price is discovered) cannot start because none of its components exist yet. The loop has to be started from outside.

This means the founding team, an initial investor group, or a partner entity must underwrite $QRC's initial value with real external money — fiat or stablecoins — before the protocol can bootstrap itself. Unlike the identity layer, which can be seeded with volunteer pilot participants, and unlike the merchant layer, which can be seeded with incentive allocations from the genesis reserve, the settlement layer cannot be seeded from within the protocol's own issuance: the genesis reserve is denominated in $QCB and $QRC, and those tokens have no external value until someone buys them with real money. There is no path from "all assets denominated in tokens that don't have value yet" to "reserves that back $QRC's value" without an external actor putting real money in first.

The identity of that underwriter, the size of the initial reserve, the rate at which $QRC's initial conversion price is set, and the legal form of the arrangement (which interacts with Open Questions 5 and 20) are not specified here. They are named as Open Question 22.

Provisional note on self-fundability: at the provisional launch price of $0.0000001 per $QRC (Section 6.2), the genesis reserve required to cover 90 days of settlement demand at a 1,000-person pilot scale is under $10. Even at a 10,000-person testnet scale, the 90-day reserve is under $100. At these parameters, the cold-start reserve is self-fundable by a solo founder without external investment. This does not eliminate the cold-start problem (the reserve must still exist before activity rewards issuance begins, and the legal and governance questions in Q20 and Q22 still apply), but it removes the cold-start funding as a practical barrier to launching a pilot at pilot scale.

Three qualifications on this claim: first, the reserve is small because the price is small — the cold-start is self-fundable at $0.0000001/QRC, not because the design makes the cold-start inherently easy, but because at that price the activity rewards are symbolic and the settlement demand is negligible. At a price where activity rewards are economically meaningful (say, $0.01/QRC), the 90-day reserve for 1,000 users would be approximately $360,000 — far beyond self-fundable for a solo founder. Second, the "5,000-day runway" claim assumes the price never changes; a 100x price increase reduces the runway to 50 days against the same $500 reserve, because each conversion now demands 100x more fiat. Third, the self-fundability claim holds for the mechanical integration pilot — proving the loop works — but not for the phase where the economic loop is meant to function meaningfully. By the time activity rewards are worth acting on, the reserve requirement has grown with the price. The growth-phase reserve is Open Question 18, not this section. The honest summary: the cold-start barrier is small at pilot scale and at the illustrative launch price; it is not intrinsically small, and it grows proportionally with adoption and price.

This is not unique to QCB — Bitcoin in 2009 had no market price, and the first miners were operating on belief before the system could validate that belief. But it means the early-adoption phase of QCB is a different story from the steady-state design that most of this document describes. The first users are not responding to a market signal; they are creating one. The first merchants are not responding to existing demand; they are creating it. The first settlement layer funders are not responding to $QRC's demonstrated value; they are creating it. That framing is honest and should be communicated as such, rather than implied by the steady-state description alone.

---

9. Supporting Infrastructure

9.1 React Explorer — a web-based block explorer for human users. Beyond standard chain data (blocks, transactions, addresses), it surfaces module-specific state that a generic Cosmos or Ethereum explorer wouldn't have anywhere to show: Charm Confinement boundaries (which identities hold which scoped claims), Intrinsic Charm attestations (verification tier, spending authorization scopes), Charmed Agent activity (which agents are operating and what they've executed), resource market state (active jobs, escrow balances, provider receipts), and QRC metrics (tokens purchased via burn, tokens in escrow, tokens burned via BME). Its primary users are verified humans checking their own claims and balances, merchants reviewing settlement history, and outside observers auditing the chain's economic activity.

9.2 Python Agent OS Backend — the runtime environment autonomous agents use to interact with QCB. It handles agent lifecycle (registration as a Charmed Agent, credential management, uptime), decision logic (the rules or models an agent executes — e.g., a merchant-settlement agent converting $QRC to fiat on a schedule, or an activity-rewards-distributor agent executing daily claims), and the actual chain interaction (submitting transactions, reading state) on the agent's behalf. It is deliberately separate from the human-facing Explorer, since agents and humans have different interfaces to the same underlying protocol state.

9.3 Merchant API — a Stripe-compatible REST API, with Shopify and WooCommerce plugins, designed so merchant integration requires no blockchain expertise. A merchant calls the API the way they'd call any payment processor; behind the scenes, the API handles $QRC acceptance, optional fiat settlement, and fee routing into the BME mechanism. Merchants never touch private keys, hold gas, or interact with the chain directly — the API is the abstraction layer that makes Section 8's "five-minute setup" claim operational rather than aspirational.

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
Phase 0 (Chain Forge) | Consensus engine design and implementation — pluggable BFT variants (Tendermint-style, HotStuff-style, XRPL-inspired); QRC resource economy crate (`chain-forge-qrc`); new `chain-forge-resource` crate (resource market layer); Agent Economic Identity (AEI) primitives; Phase 0 acceptance test: one complete adversarially-verified cross-machine resource purchase using QRC | 18–48 months | **In progress — Tendermint-style BFT operational and partition-tolerant on 4-node testnet (September 2026); HotStuff-style BFT variant shipped (October 2026) — three-phase QC-locked consensus, 17 tests passing; XRPL-inspired FBA variant shipped (October 2026) — global UNL, 80% threshold, 18 tests passing; all three pluggable BFT variants confirmed; QRC Economic Model v0.2 implemented in `chain-forge-qrc` and `chain-forge-execution` (PurchaseQrc + CreditProvider tx types, October 2026); QRC architecture pivot (October 2026) — resource market separated into `chain-forge-resource`, provider payment via escrow not minting, AEI pulled forward. See Section 7.4 for detail.**
Phase 0 (QCB) | Whitepaper, identity layer research — proceeds in parallel with Chain Forge Phase 0, dependent on it for a working consensus target | 18–48 months | **In progress — whitepaper complete (this document); attestation guard Phases A–D implemented in chain-forge-identity (65 tests passing, September 2026); QRC Economic Model v0.1 incorporated (October 2026); identity pilot parameters provisional.**
Phase 1 | Personhood-weighted BFT consensus live on testnet; Charm Confinement + Intrinsic Charm implemented (decay-exemption credits removed — demurrage is out of QRC v3); Resource Market Foundation: provider reputation, dispute skeleton, multi-provider discovery | 18–30 months following Phase 0 | Pending — prerequisite (pluggable BFT consensus) now has a working base; personhood-weighting overlay not yet built
Phase 2 | Identity layer pilot (small integration test, then real-world pilot against cost/sybil targets); QRC module live — purchase path (QCB burn → QRC) open; resource market escrow and provider payment live; `CreditProvider` / `QrcContributionSettle` resolved or retired before this milestone | 6–12 months following Phase 1 | Pending
Phase 3 | Merchant API + Stripe-compatible integration, BME activation, first on-chain burns | 6–12 months following Phase 2 | Pending
Phase 4 | Charmed Agents live, physical merchant expansion, 1 million verified humans | Multi-year, adoption-dependent | Pending
Phase 5+ | Decentralized governance maturity; permissioned EVM layer (Section 7.2) activated once identity layer is proven at scale; interoperability reconsidered only if a PoP-preserving bridge design exists | — | Pending

**Phase 0 checkpoint (September–October 2026).** The Chain Forge engine has reached a significant internal milestone within Phase 0: all three planned BFT consensus variants are now functional. The Tendermint-style variant was operational end-to-end by September 2026 — multi-node quorum, liveness enforcement, and adversarial attack resistance confirmed. HotStuff-style (three-phase QC-locked) and XRPL-inspired FBA (global UNL, 80% threshold) both shipped in October 2026, with 17 and 18 dedicated tests passing respectively. This is not Phase 0 complete — the state layer is not production-grade, personhood-weighting is not yet overlaid, and the resource market layer (`chain-forge-resource`) is not yet built — but it conclusively validates the pluggable `ConsensusEngine` architecture: three independent BFT variants, built and tested against the same trait interface, switchable at node configuration time. BFT variant selection for QCB mainnet (Open Question 2) is now unblocked. Phase 0 completion requires the full acceptance test: one complete adversarially-verified cross-machine resource purchase (Machine 1's agent buys computation from Machine 2's resource node, escrow settles, and the settlement survives ten deliberate attack scenarios — see ROADMAP Phase 0 Acceptance Test).

**QRC Economic Model v0.1 implementation (October 2026).** The resource token formerly named CIRFI (Circulating Finance) has been renamed $QRC (Quark Resource Credit) and redesigned as a resource consumption token rather than a UBI/demurrage currency. The `chain-forge-qrc` crate implements: `QrcEngine` with dynamic conversion rate (R_t), epoch conversion cap (L_e), and CoverageRatio circuit breaker (CR_halt = 0.75, CR_resume = 1.00); `contribution_settlement` for VCA-verified provider earn; and the `CapacityEvidence_v0` sub-protocol for Byzantine-resistant median aggregation of capacity reports across 7 resource types. The consumption split (60% providers / 25% burn / 15% reserve) and per-resource congestion pricing are wired into the engine. `QrcEngine` serializes to `qrc.json` and persists across node restarts. The rename is complete across all Rust sources, TOML manifests, markdown docs, and simulation scripts — zero remaining CIRFI references verified by grep.

**QRC Resource Network v0.2 marketplace tx types (October 2026).** Two first-class transaction types have been added to `chain-forge-execution` implementing the Resource Network v0.2 marketplace design: `PurchaseQrc` (job-scoped QCB→QRC buy-in: `job_id`, `qcb_amount`, `min_qrc_out`, `resource_type`; blocked by Control 5 in RESTRICTED and HALTED states; slippage guard rolls back the QCB debit if minted QRC falls below `min_qrc_out`) and `CreditProvider` (coordinator-issued post-job credit: `job_id`, `provider_id [u8;32]`, `resource_type`, `verified_units`; requires Verified-tier sender; blocked only in HALTED; auto-creates provider account on first credit via hex-encoded 32-byte key as on-chain address). Both variants are fully wired through gas accounting, `variant_name`, `payload_size_bytes`, `required_module`, and the exhaustive `tx_kind_label()` match in `chain-forge-node`. 74 execution-layer tests passing (8 new: happy-path, Control 5 state tests, slippage guard, non-verified-coordinator rejection, provider-account auto-creation). **Note:** `CreditProvider` is classified as legacy/under review following the October 2026 architecture pivot (see QRC Architecture Pivot note above); `PurchaseQrc` is the canonical active path.

**Attestation guard implementation (September 2026).** The on-chain sybil-resistance layer for the identity pilot has been implemented through Phase D in the `chain-forge-identity` crate. The four phases cover: (A) quadratic-cost cap enforcement — hard limit of 3 outbound attestations per 90-epoch window per attester; (B) revocation with cost — `RevokeAttestation` at 10% CS deduction (1,000 bps), cap slot freed on revocation; (C) sybil confirmation with CS penalty — coordinator-gated `ConfirmSybil` applies 120% CS clawback to penalized attesters (12,000 bps), `ReportSuspectedSybil` logs a self-report with 50% penalty reduction on independent confirmation; (D) `ReverseSybil` — coordinator can reverse a confirmed sybil, crediting back CS penalties. Execution layer updated with four new `TxBody` variants. REST endpoint `/api/identity/{address}` added. Pilot parameters from `QCB-Attestation-Guard-Design.md` are implemented as compiled constants; governance-tunable parameterization is deferred to Phase 1. The coordinator role is a named temporary centralization — see `docs/QCB-Attestation-Guard-Design.md §Coordinator`.

---

12. Open Questions

Calibration questions — decisions needed before or shortly after launch:

1. Final identity layer design — web-of-trust base plus live-challenge backstop, or a different hybrid; cost and sybil-rate results from pilot testing against the provisional targets named in Section 4 (sybil rate below 3%, verification cost below $5/human — both illustrative, to be revised as the pilot is designed)
2. Final BFT variant selection for QCB specifically (Chain Forge will support multiple; QCB must pick one)
3. Base exemption calibration — no longer applicable to $QRC (no demurrage on QRC balances under QRC Economic Model v0.1); this question now applies only to any future $QCB staking-exemption mechanics if introduced
4. Reserve strategy — what backs price stability, if anything
5. Jurisdiction and legal entity structure, given activity rewards distribution and merchant payment processing
6. Validator economics — staking incentives, slashing conditions, bounds on per-human validator power
7. Exact token distribution percentages within the Section 6.7 ceiling (illustrative percentages shown there are examples, not commitments)
8. Constitutional amendment thresholds — the exact percentage-quorum, absolute-minimum-voter-count, and waiting-period length for Section 7.3's amendment process; Section 6.6/7.3 now derive a floor (>6% turnout) from the Section 4 sybil target, but the absolute-count floor and exact waiting period are still unset

Permanence questions — decisions that matter because QCB is designed for long-term survival, not just launch:

9. Identity replacement process — the specific constitutional mechanism (Section 7.3) by which the identity primitive is swapped if it fails or is gamed, without forking the chain or invalidating existing verified claims
10. Governance succession — how decision-making authority moves past founder control over time without collapsing into either stagnation or capture
11. Stagnation resilience — what happens to the economic model if merchant adoption never reaches the threshold needed for BME to function meaningfully. Section 6.3 proposes a provisional working definition (burns funded at ≥1% of daily $QCB volume, sustained 90 days) for when BME should be considered live versus speculative; this open question is where that threshold gets finalized against real data.
12. Long-horizon funding — how core protocol development is funded in year 15 or 20, once initial development allocations are spent and the chain's original team may no longer be primarily responsible for it
13. Consensus-layer bug migration path — the process for patching or replacing the consensus implementation itself if a critical flaw is found, without a chain split or loss of finality guarantees
14. Validator availability and liveness under partial-participation conditions — unlike Proof of Work (recruit more hashpower) or Proof of Stake (recruit more stake), a personhood-weighted validator set is bounded by a fixed, slow-growing pool of verified humans. What happens to finality and block production if a large fraction of verified humans go offline at once — through censorship, coercion, natural events, or simple apathy — has not yet been addressed. This is a consensus-design constraint arising directly from Section 3's personhood-weighting choice, not a tunable parameter, and needs a concrete answer before Phase 1 testnet. Related to, but distinct from, Q13: a sustained liveness failure may be one of the triggers for Q13's consensus-migration path, but liveness itself (can the chain keep producing blocks right now) and migration (replacing the consensus implementation) are separate problems needing separate answers.
15. Minimum legitimate participation rate required for governance to remain Sybil-resistant at the maximum tolerated fraudulent-identity rate — Sections 4, 6.6, and 7.3 are now mathematically linked via two distinct derivations against Section 4's sybil-rate target: a >3% turnout floor from the majority-safety condition (f / (p + f) < 0.5, protecting ordinary QRC votes) and a >6% floor from the stricter blocking-safety condition (f / (p + f) < 1/3, protecting supermajority constitutional votes). The absolute-minimum-voter-count floor referenced in 6.6, and how both thresholds should adjust if the Section 4 target itself changes after pilot data comes in, remain unset. This question exists specifically to keep identity, ordinary governance, and constitutional governance treated as one linked security model rather than three separate ones.
16. Post-quantum migration trigger and algorithm choice — Section 10 establishes that the signature scheme must be constitutionally replaceable, but not which post-quantum algorithm(s) QCB adopts at launch versus in reserve, what specific event (a NIST guidance update, a demonstrated cryptographically-relevant quantum computer, a fixed calendar review date) triggers migration for already-live accounts and validators, and which of Section 10.3's three candidate approaches to absorbing PQC's larger signature size (larger blocks, fee adjustments, or a hybrid scheme applied only to high-value/validator transactions) QCB actually adopts.
17. Turnout-suppression resistance — Section 6.6's quorum floors are derived assuming legitimate turnout is independent of attacker behavior, but a sophisticated attacker can suppress legitimate turnout directly (proposal spam, governance fatigue, targeted discouragement), lowering p and raising fraud's effective vote share without needing more fraudulent identities. The current model defends against passive, uncoordinated fraud; it does not yet defend against an active campaign to depress legitimate participation. What mechanism (participation incentives, spam-resistant proposal costs, fatigue-aware quorum adjustment) closes this gap is unresolved.
18. Settlement layer reserve sizing — how large must the fiat/stablecoin reserve be at genesis to absorb the first wave of merchant conversions without exhausting? The minimum reserve is a function of daily $QRC issuance rate, the fraction of activity rewards that gets spent at merchants (rather than held or transferred peer-to-peer), the merchant conversion rate (what share of merchants opt for fiat vs. holding $QRC), and the settlement rate. None of these are known at genesis; the reserve must be sized against a plausible range of outcomes rather than a point estimate. This question links to Open Question 4 (reserve strategy) and must be resolved before mainnet activity rewards issuance begins.

Provisional reserve model at launch parameters ($0.0000001/QRC, 1,000 $QRC/day activity rewards, assumptions: 50% of activity rewards spent at merchants, 80% of merchants take fiat settlement):

Pilot scale (1,000 verified humans): ~$0.10/day settlement demand → $9 for 90-day reserve
Testnet scale (10,000 verified humans): ~$1.00/day → $90 for 90-day reserve
Early mainnet (100,000 verified humans): ~$10/day → $900 for 90-day reserve

At these parameters a $500 genesis reserve covers approximately 5,000 days of pilot-scale runway at a fixed price — self-fundable without external investment. This figure assumes the price does not change: a 100x price increase reduces the effective runway to 50 days against the same $500 reserve, because each fiat conversion now demands 100x more reserve capital per unit of $QRC converted. The 5,000-day figure is therefore accurate only for the mechanical integration pilot, where the price is fixed and settlement volume is minimal. Reserve requirements scale linearly with user count and proportionally with price; the growth-phase reserve must be re-sized against real adoption data rather than extrapolated from pilot-scale assumptions. The exact sizing must be re-run against real pilot data once user count, activity rewards spend rate, merchant conversion fraction, and realized price are measured rather than assumed.
19. Settlement rate regime — fixed rate vs. floating rate vs. a managed float with a circuit breaker. Fixed rate gives merchants the "zero volatility" promise but requires the settlement layer to absorb all $QRC price fluctuation through its reserves; if $QRC depreciates, the settlement layer bleeds reserves until exhaustion. Floating rate protects reserves but breaks the merchant value proposition. A managed float (fixed within a band, floating outside it) is a middle path but requires a governance mechanism to set and update the band. Which regime QCB adopts, and how the QRC consumption burn rate (p_burn = 0.25, Section 6.10 Control 4) interacts with the outstanding supply the settlement layer must backstop (Section 8.4 / Open Question 21), must be specified before the settlement layer can be designed or audited.
20. Settlement layer governance — who operates the settlement layer, how are conversion rate decisions made, and how is the operator replaced or upgraded without breaking $QRC's value link? A centrally-operated settlement layer (a company or foundation holding reserves and setting rates) is the simplest implementation but introduces a single point of failure and a centralization risk inconsistent with QCB's sovereignty principle (Section 7). A protocol-native reserve mechanism (an on-chain DAO controlling a reserve pool, with rates set by governance) avoids centralization but introduces governance attack surface and requires the reserve pool to be denominated in something $QRC governance controls. A licensed financial entity (a regulated payment processor or bank) provides regulatory cover but reintroduces the government-dependency QCB is built to avoid. This is a permanence question — the wrong answer compounds over time as the settlement layer grows — not a calibration question.
21. Consumption burn and settlement reserve interaction — $QRC under the QRC Economic Model v0.1 has no demurrage. Balances do not decay passively. The settlement layer's $QRC reserve is not subject to any decay mechanism. However, the 25% consumption burn (p_burn = 0.25, Section 6.10 Control 4) permanently removes $QRC from circulation on every resource-consumption event. This affects how the settlement layer should size its reserves: as network utilization rises, a larger fraction of outstanding $QRC is being burned, which contracts the supply the settlement layer is backing. At high utilization, the settlement layer may find its reserve covers a larger share of outstanding supply than intended, while at low utilization the reserve may cover a smaller share. How the settlement layer should adjust reserve targets based on real-time utilization data and the effective burn rate is unspecified and is an open question linked to Open Question 18 (reserve sizing) and Open Question 19 (rate regime).
22. Settlement layer cold-start and design-compatibility — who funds the settlement layer's initial reserves, how much is required before activity rewards issuance can begin, at what rate is the initial $QRC conversion price set, and what legal form does the arrangement take? This is distinct from Open Question 18 (ongoing reserve sizing) and Open Question 20 (ongoing governance): it is specifically the pre-launch bootstrapping question — what has to be true before the value loop in Section 8.2 can start at all. The answer determines who bears the financial risk of QCB's early phase, which is a disclosure obligation as much as a design question. Critically, this question also covers whether the cold-start funding can be secured on terms compatible with QCB's design principles — a licensed financial entity as underwriter might require government-ID verification of users, reintroducing the government dependency the identity layer was designed to avoid; a large investor as underwriter might require token supply or governance terms that compromise QCB's sovereignty principle; a foundation underwriter might be jurisdictionally constrained in ways that conflict with Open Question 5. If no underwriter can be found on acceptable terms, the system cannot launch under its own stated constraints — making this question not just a design and disclosure question but a viability question. It should be treated with the same priority as Open Question 1 (identity layer design), not as a later-phase concern.
23. Permissioned EVM layer design — Section 7.2 commits to a permissioned EVM environment where every contract must be linked to a verified Charmed Agent SponsorID and every $QRC/$QCB transfer passes through QCB's identity checks. The open questions are: (a) how is the SponsorID link enforced at the EVM level — through a modified EVM precompile, a wrapper contract, or a protocol-layer check before every state transition; (b) what happens to an EVM contract whose SponsorID is revoked (human loses verified status, or agent's authorization expires) — freezing the contract (state persists, no new calls accepted) is the conservative default and avoids destroying user funds, but creates indefinite state lockup; transferring the SponsorID to another verified human requires a governance mechanism for reassignment; destroying the contract and its state is irreversible and likely wrong in most cases; the conservative default is freeze, with transfer as an exception path requiring explicit governance; (c) how are gas fees denominated and collected in the permissioned EVM — in $QCB (consistent with $QCB's role as the chain's fee token) or in $QRC (resource consumption framing would support this, since EVM execution is itself a network resource); (d) how does the EVM layer interact with the consumption burn — does $QRC transferred into an EVM contract and then spent on execution trigger the p_burn = 0.25 consumption burn, and who settles that burn (the contract or the protocol); and (e) which EVM opcode set is supported — full EVM equivalence (including SELFDESTRUCT, DELEGATECALL, and other operations that complicate identity tracking) or a constrained subset that makes identity enforcement tractable.
24. Liveness of identity — Section 4.5 establishes that identity and economic participation must be coupled in both directions: identity gates participation, and participation maintains identity. The open question is the specific liveness requirement: what minimum periodic activity must a verified human perform to maintain active verification status? Candidates include periodic activity reward claims (e.g., claim at least once per epoch), periodic governance votes, periodic $QRC transactions above a threshold, or some combination. The requirement must be low enough not to exclude humans who are temporarily inactive (illness, travel, life events) and high enough to prevent identity from becoming a free-standing credential that confers rights without chain participation. It must also specify what happens to a lapsed verification — is it suspended (recoverable with re-verification) or revoked (requires fresh verification from scratch) — and what happens to the lapsed human's Charmed Agents and Sponsored Contracts during the lapse period. This question is distinct from Open Question 14 (validator liveness, which concerns block production) and from Open Question 9 (identity replacement process, which concerns protocol-level swaps of the verification method). It is specifically the individual-level liveness requirement that keeps identity coupled to economic participation.
25. Circulation event fee calibration and redirect-vs-commerce BME classification — Section 6.3 broadens BME funding to include proactive activity rewards pool redirects alongside merchant settlements and peer transfers. The open questions are: (a) what fee rate on circulation events keeps redirects from suppressing real resource-consumption activity — a rate that is too high makes spending irrational; too low makes BME negligible; the provisional 0.5% is consistent with merchant fee levels but needs real data to validate; (b) under what conditions does redirect-driven BME count toward the "live vs. speculative" BME threshold — the existing threshold requires burns funded at 1% of $QCB daily trading volume for 90 days, but this measure is ambiguous about whether redirect-driven burns satisfy it or only merchant-driven and resource-consumption-driven burns do; and (c) whether the redirect mechanism interacts with the consumption burn (p_burn = 0.25) in a way that creates unintended incentives — for example, a holder who redirects rather than spending on network resources avoids the consumption burn while still triggering BME, which may be an intentional feature (rewards proactive participation) or an imbalance in how different $QRC exits are treated).
26. Human Capacity Markets (considered, not committed) — a proposed extension under which verified humans could be paid, in $QRC, to sponsor agents on a bounded, time-limited basis, rather than sponsorship being an unpaid accountability relationship as currently specified in Section 5.3. The idea surfaced from a broader (and explicitly rejected) framing that described verified personhood itself as "a scarce, rentable economic resource" — that framing is not adopted here, because it inverts Section 4.5's coupling principle (identity's value comes from participation in QCB's own economy, not from being sold as a queryable input to others) and because "rentable personhood" invites a reading — humans selling themselves to agents — that the mechanism, if built carefully, would not actually be. What might be worth building, if anything, is much narrower: paid, scoped, revocable sponsorship, structurally close to the existing `sponsor_agent` mechanism, not a new identity-as-a-service primitive.

This question is intentionally left open rather than specified, because three prerequisites are unresolved and each changes what the mechanism actually is:

(a) Price discovery — is the sponsorship fee fixed, or does it require a matching market (an order book of sponsorship offers and agent requests)? A fixed fee is a simple transaction type; a market is a new subsystem.

(b) Bonding and liability — does a paid sponsor stake something at risk beyond the existing reputational accountability, so that being paid to sponsor doesn't create an incentive to sponsor recklessly for fee income with no offsetting downside? Unpaid sponsorship relies on the human having chosen to vouch for something they understand; paid sponsorship removes that selection pressure unless a bond replaces it.

(c) Sybil-farming resistance — turning sponsorship into an income stream gives verified humans a direct financial incentive to accumulate sponsorship slots and approve agents without real vetting, which is a new attack surface layered on top of the identity layer's existing sybil problem (Section 4). A per-human cap on concurrent paid sponsorships, separate from the existing per-sponsor limits in the agent registry, is a candidate mitigation but is unspecified.

Until (a)-(c) have concrete answers, Human Capacity Markets remains a named possibility, not a designed mechanism, and it does not appear in the Abstract, Section 5, or the token-economics sections. If it is pursued, it should enter the document the way Section 4.6's strategic directions do: as a contingent extension with named success and failure conditions, evaluated against a working pilot before being described as a feature QCB has.

A related, equally unresolved idea has been proposed alongside this one: activity-based $QCB accrual, under which verified humans (and, by attribution, their sponsored agents) would earn $QCB credits for measured $QRC economic activity — spending, Capacity Market work, agent activity that passes some quality filter — rather than for locking a balance, which is what Section 6.9's long-term distribution mechanism already covers. It is recorded here, as a fourth prerequisite, rather than specified, because it inherits the same three open questions above in a stricter form:

(d) Source of funds and gaming resistance — any real version of this draws $QCB from the same fixed, genesis-minted 210 million supply as everything else (Section 6.7); it is not a second, independently-sized allocation, and sizing it correctly requires deciding how it relates to Section 6.9's 4% long-term distribution pool before either can be finalized. Two of its proposed qualifying activities — Capacity Market work and sponsored-agent volume — are Human Capacity Market primitives, so this cannot be resolved ahead of (a)-(c) above; it is downstream of them, not parallel to them. It also introduces its own attack surface on top of HCM's: attributing agent activity to a human sponsor's accrual creates a direct incentive to run low-quality or synthetic agent activity purely to farm credits. Candidate mitigations — quality filters on what counts as attributable activity, per-identity rate limits or diminishing returns, a requirement that the sponsor maintain their own qualifying activity alongside their agents' — are named here as directions, not as a specified design. As with Human Capacity Markets itself, the identity layer's sybil resistance (Section 4) is the first line of defense against this, not a substitute for it; a mechanism that pays out real $QCB for activity is a stronger incentive to defeat that sybil resistance than sponsorship alone, and should be evaluated with that in mind before it is built, not after.

---

13. Conclusion

QCB Chain is not trying to be digital gold, and it is not trying to be someone else's framework with a new name. It is a sovereign chain, built from its own foundation, where consensus power, governance, and economic participation all trace back to the same principle: one verified human, one share of the system.

But sovereignty at launch and survival across decades are different achievements. Bitcoin and Ethereum have each proven roughly a decade of resilience, and both have done so imperfectly — through contentious forks, informal social consensus, and identity questions of their own that they never had to solve at the protocol level, because they never tried to gate participation by verified personhood. QCB is attempting something neither has: tying consensus power, currency issuance, and governance to human identity itself, at a protocol layer meant to still be functioning long after its founders are no longer involved.

That requires more than good token design. It requires a constitutional layer (Section 7.3) that can outlive any single identity method, any single development team, and any single jurisdiction — and the discipline to treat that layer as genuinely load-bearing, not aspirational language. The identity primitive described in this document is a current best answer, not a permanent one. What makes QCB durable is not that this answer is correct forever, but that the protocol has a defined, legitimate way to replace it if it isn't.

Its value comes not from scarcity, but from circulation. Its security comes not from capital or hardware, but from verified humans. Its independence comes from having built its own foundation, on Chain Forge, rather than borrowing one. And its claim to permanence rests not on any individual's commitment to it, but on whether the rules it launches with are the rules that let it keep changing without breaking.

The engine, not the vault. The economy, not the chain. Built to be replaced by better versions of itself, not by its own collapse.
