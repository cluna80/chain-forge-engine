# QCB Chain — Identity Layer Pilot Design

**Companion document to the QCB Chain Whitepaper v2**
**Status: Draft — pre-pilot**
**Purpose: Convert the whitepaper's identity commitments into a testable, falsifiable pilot plan**

---

## 1. Why This Document Exists

The QCB Chain Whitepaper (Section 4) names the identity layer as the single highest-risk open question in the entire system. Every downstream mechanism — UBI distribution, personhood-weighted consensus, governance voting, Charmed Agent sponsorship, RWA compliance — depends on the identity layer holding up under real adversarial pressure.

The whitepaper states two provisional targets:

- **Sybil rate below 3%** under adversarial red-team testing
- **Per-verification cost below $5** per verified human

And names two pilot phases:

1. A small **mechanical integration test** — proving the loop works
2. A larger **real-world pilot** — proving it works under adversarial conditions

This document specifies what those phases actually mean: what adversarial red-team testing is, how sybil rate is measured, what the cost target covers, what happens if the pilot misses its targets, and what the pilot's output is used for.

The whitepaper's discipline has been to name dependencies before claiming outcomes. This document applies the same discipline to the pilot itself.

---

## 2. What the Pilot Is Not

Before specifying what the pilot is, naming what it is not prevents scope creep and false success signals.

**The pilot is not a UBI launch.** The UBI loop is symbolic at launch prices ($0.0001/day per human at $0.0000001/CIRFI). The pilot's purpose is to validate the identity mechanism, not to create meaningful income.

**The pilot is not a consensus test.** Chain Forge's BFT consensus is already running and producing blocks. The pilot tests whether the humans feeding the identity layer are real humans, not whether the consensus engine works.

**The pilot is not a market test.** It does not answer whether merchants will accept $CIRFI or whether $QCB has value. Those are downstream of identity working; the pilot answers only the upstream question.

**The pilot is not a single point-in-time event.** A sybil attack that costs more than it gains will not appear on day one — it will appear once the attacker has confirmed the system is producing value worth attacking. The pilot must run long enough that adversarial pressure has time to materialize.

**The pilot does not prove the identity layer is production-ready.** It proves the identity layer is ready for the next phase. Production readiness requires the larger Phase 2 pilot under higher adversarial pressure.

---

## 3. Identity Method: The Hybrid Model

The whitepaper's current direction is a hybrid of two mechanisms. This section specifies each.

### 3.1 Base Layer: Web-of-Trust

**What it is:** Existing verified humans attest to new claimants. Each attestation says "I vouch that this person is a unique human I personally know." A new human needs attestations from a minimum quorum of existing verified humans (provisional target: 3 attestations).

**Why it provides sybil resistance:** Creating a synthetic identity requires either (a) compromising real humans into vouching for fake ones, or (b) controlling enough of the existing verified population to be self-vouching. Attack (a) is social engineering at scale; attack (b) is a Sybil attack on the web-of-trust itself, which requires the attacker to have established a large cohort of fake identities before the attack — a bootstrapping problem that the pilot phase should detect.

**Why it is not sufficient alone:** A well-resourced attacker with patience can build a cohort of fake identities that vouch for each other over time. The web-of-trust base layer is necessary but not sufficient; it provides resistance against unsophisticated attacks and raises the cost of sophisticated ones. It does not eliminate sophisticated attacks.

**Phase 0 implementation (current):** The `PopAttestation` struct in `chain-forge-identity` has an `attester` field and a `proof` field. In Phase 0, `proof` is empty (stub). The web-of-trust logic — tracking which humans have vouched for which, enforcing the quorum, and preventing circular vouching — is the Phase 1 implementation target.

**Parameters to be finalized before Phase 1:**
- Minimum attestations per new claimant (provisional: 3)
- Maximum attestations one human can give per epoch (prevents one person from vouching for many fake identities rapidly)
- Cooling-off period after attestation (prevents rapid churn)
- Whether attestations can be revoked (and if so, what happens to identities that lose quorum)

### 3.2 Backstop Layer: Live-Challenge Ceremonies

**What it is:** Periodic synchronized events where existing verified humans prove they are present and human in real time, through tasks that cannot be completed by automated systems without human-level intelligence. The model is Idena's synchronized validation, adapted for QCB's sovereignty constraints.

**Why it strengthens the web-of-trust:** A synthetic identity that has successfully accumulated web-of-trust attestations still has to pass live challenges. A bot farm that has built up fake identities over months faces a binary event: show up at the ceremony as a real human, or lose verified status.

**The core adversarial challenge:** A well-resourced bot farm with access to capable language models can pass many live challenges that were designed before such models existed. Challenge design must assume that any text or image task can be automated; the challenge must require capabilities that are structurally harder for automated systems — not tasks that are hard today, but tasks that are hard by design.

**Phase 0 implementation (current):** The `PopAttestation::verify()` method returns `Ok(())` for any non-empty attester in Phase 0. The ceremony interface — the protocol for conducting a synchronized challenge, submitting proofs, and verifying results on-chain — is the Phase 2 implementation target.

**Parameters to be finalized before Phase 2:**
- Challenge frequency (how often verified humans must participate)
- Challenge format (what constitutes a valid challenge type)
- Grace period for missed challenges before liveness lapse
- What happens to identities that miss multiple consecutive ceremonies

---

## 4. The Two Pilot Phases

### 4.1 Phase 1 — Mechanical Integration Test

**Purpose:** Prove the loop works. Not that it resists adversarial pressure — just that verified humans can receive UBI, that the web-of-trust registration flow functions end to end, and that the on-chain state (VerificationTier, IntrinsicCharm, UBI claims) updates correctly.

**Scale:** 10–50 participants. All known to the team. No anonymity, no adversarial pressure.

**Duration:** 30 days.

**What this phase tests:**
- Registration flow: a new participant registers a Provisional identity, accumulates 3 attestations from existing Verified humans, upgrades to Verified
- UBI claim: a Verified human claims 1,000 $CIRFI per day for 30 consecutive days, on-chain
- Demurrage: idle balances decay on schedule; decay flows to UBI pool
- Liveness enforcement: an identity that misses 90 consecutive epochs lapses to Provisional
- Charm Confinement: the one-claim-per-epoch rule holds; no double-claiming in tests

**What this phase does NOT test:**
- Sybil resistance (all participants are known)
- Live-challenge ceremonies (not yet implemented)
- Cost at scale (10–50 people is not a meaningful cost sample)

**Success criteria:**
- All 4 CharmConfinement rules hold for all participants for 30 days
- Zero double-claims observed
- Liveness enforcement fires correctly for deliberately inactive test accounts
- UBI pool receives decayed tokens (not direct burns) confirmed by state root audit
- Per-registration cost: time to complete the web-of-trust attestation flow, manually measured, below 10 minutes per person

**Failure criteria:**
- Any double-claim succeeds on-chain
- Liveness enforcement fails to demote inactive identities
- The registration flow is too complex for a non-technical participant to complete
- Any state root inconsistency between expected and actual account state

**Output:** A technical report confirming the loop works (or documenting what broke), plus a revised estimate of Phase 2 scale and parameters.

### 4.2 Phase 2 — Adversarial Real-World Pilot

**Purpose:** Prove the identity layer holds under real adversarial pressure, at a scale where the sybil rate and cost targets are meaningful.

**Scale:** 1,000 participants minimum. Mix of known participants (team, community) and unknown participants (public recruitment). Unknown participants are the adversarial signal — some will attempt to register multiple identities.

**Duration:** 90 days minimum. The 90-day window corresponds to the BME "live vs. speculative" threshold from the whitepaper (Section 6.3) and provides enough time for adversarial pressure to materialize.

**What this phase tests:**

Everything from Phase 1, plus:
- **Web-of-trust sybil resistance:** can an attacker register multiple identities by controlling vouching relationships?
- **Live-challenge ceremony resistance:** can a bot or a paid human farm pass challenges that should require genuine human participation?
- **Scale cost:** what does it actually cost to verify 1,000 humans, end to end, including coordinator time, infrastructure, and challenge design?
- **Governance safety:** with a 1,000-person set and the measured sybil rate, do the quorum derivations from Section 6.6 hold? Is the 3%/6% turnout floor model validated or falsified?

---

## 5. How Sybil Rate Is Measured

The whitepaper's 3% target needs an operational definition, not just a percentage.

### 5.1 Definition

**Sybil rate** = (number of fraudulent verified identities) / (total verified identities) at the end of the measurement window.

A fraudulent identity is one that does not correspond to a unique real human — either it is fully synthetic (no human behind it) or it is a duplicate (one human controlling multiple verified identities).

### 5.2 Measurement Method

The pilot cannot directly observe fraudulent identities during the pilot — if it could, it would simply remove them. Instead, sybil rate is estimated through a combination of:

**Red-team disclosure:** at the end of the pilot, a designated red team that attempted to register fake identities discloses how many they successfully registered. The red team is compensated based on successful registrations (creates incentive to actually try). This gives a lower bound: if the red team succeeded with N fake identities, the sybil rate is at least N / (total verified).

**Cross-reference audit:** at the end of the pilot, the web-of-trust graph is audited for structural signals of Sybil clusters — tightly connected subgraphs with no external connections, identities that vouched for each other in a short time window, or identities that appeared simultaneously. This is heuristic, not definitive, but it provides a second estimate.

**Declared-duplicate removal:** participants who voluntarily disclose they registered multiple identities (in exchange for immunity from future bans) are counted. This is the most honest signal; the incentive structure has to make disclosure more attractive than keeping the extra identities.

**Sybil rate estimate** = max(red-team disclosure count, cross-reference audit count) / total verified, expressed as a percentage with an explicit confidence interval.

### 5.3 The 3% Target in Context

The whitepaper's Section 6.6 derives that a 3% sybil rate is safe for consensus (which tolerates fraud up to ~50% of the legitimate population) but potentially dangerous for governance if legitimate turnout is low.

The pilot should report sybil rate alongside the observed governance participation rate, so the two can be evaluated together against the Section 6.6 model. Reporting the sybil rate without the turnout rate is incomplete; the target is not 3% in isolation — it is 3% with turnout high enough that the quorum floors hold.

**Pilot pass on sybil rate:** sybil rate estimate ≤ 3% at 90% confidence, AND observed turnout in any pilot governance votes ≥ 6%.

**Pilot fail on sybil rate:** sybil rate estimate > 3% at any confidence level, OR observed turnout < 3% in pilot governance votes.

---

## 6. How Per-Verification Cost Is Measured

### 6.1 What the $5 Target Covers

The whitepaper's $5/verification target is a total cost figure, not a transaction fee. It covers:

- **Coordinator time:** the human effort required to run the web-of-trust ceremony and live-challenge session for one participant. At $25/hour, this is 12 minutes of coordinator time per participant.
- **Infrastructure cost:** compute, storage, and bandwidth for the verification node and ceremony infrastructure, amortized per participant.
- **Challenge design cost:** the one-time cost of designing challenges that resist automation, amortized over the pilot population. At 1,000 participants, a $1,000 challenge design cost adds $1/participant.
- **Dispute resolution:** the time spent investigating contested verifications, amortized over the pilot population.

**Explicitly excluded from the $5 target:**
- Participant time (the human being verified does not pay)
- Network transaction fees (these are gas costs, separate from verification cost)
- Post-quantum signature upgrade cost (deferred to Phase 3)

### 6.2 Measurement Method

For each participant verified during Phase 2:

1. Log coordinator start time and end time for that participant's verification
2. Log all infrastructure costs for the verification period (amortized per participant)
3. After the pilot, calculate: (total coordinator time cost + total infrastructure cost + challenge design cost) / total verified participants

This gives a cost per verified human that can be compared against the $5 target.

### 6.3 Cost Scaling Concern

The $5 target is provisional at 1,000-person pilot scale. The honest note from Section 8.5 applies here: at the price where UBI is economically meaningful ($0.01/CIRFI), the reservation and verification economics change significantly. The pilot should report not just cost at 1,000 people but the marginal cost curve — what verification costs at 100 people, 1,000 people, and the projected cost at 10,000 and 100,000 people — so that the $5 target can be evaluated against the growth phase, not just the pilot phase.

---

## 7. What "Adversarial Red-Team Testing" Means

The whitepaper uses "adversarial red-team testing" as a phrase but doesn't specify it. This section does.

### 7.1 Red Team Composition

The red team for Phase 2 consists of:

- **Technical attackers:** people with software engineering skills attempting to automate registrations, exploit the web-of-trust graph structure, or defeat the challenge mechanism programmatically
- **Social engineers:** people attempting to convince existing verified humans to vouch for fake identities, or to coordinate a group of real humans to share an identity
- **Bot farms:** simple automated accounts attempting to register without human participation — the lowest-sophistication attack, included as a baseline
- **AI-assisted attackers:** accounts using capable language models to pass text-based challenges that were designed before such models were considered

The red team should be told the target (register as many fake verified identities as possible) and compensated proportionally ($X per successful fake identity that survives 90 days). The compensation structure is the key design: it must make the attack economically attractive enough that the red team actually tries.

### 7.2 What the Red Team Is Not Told

The red team is not told the specific challenge format in advance. If challenges are disclosed before the ceremony, they can be prepared for; the whole point of live challenges is that preparation is impossible.

The red team IS told the general mechanism (web-of-trust + live challenge), the timing of ceremonies, and the verification flow. Security through obscurity is not a goal; the goal is resistance to attacks conducted with full knowledge of the system design.

### 7.3 Red Team Budget

The red team budget should be set at a level that would make a real attacker's cost-benefit analysis roughly neutral at 3% penetration. If 30 fake identities out of 1,000 (3%) earn the red team $X, and the cost of mounting the attack is $Y, the red team budget should be set so that $X ≈ $Y. If the budget is too low, the red team won't try seriously. If it's too high, a 3% result is not informative (the attack was over-resourced).

Provisional red team budget: $10 per successful fake identity sustained for 90 days, capped at $1,000 total. At 1,000 participants, a 3% penetration (30 fake identities) earns the red team $300 — a meaningful incentive at the pilot's resource level, but not enough to justify a sophisticated sustained attack by professional attackers. This is appropriate for Phase 2; Phase 3 will require a larger, more professional red team.

---

## 8. Failure Modes and What Happens Next

The pilot has three outcomes: pass, fail, or inconclusive. Each has a specified next step.

### 8.1 Pass

**Definition:** sybil rate ≤ 3% at 90% confidence, per-verification cost ≤ $5, turnout in pilot governance votes ≥ 6%, and all Phase 1 CharmConfinement rules hold for all participants for 90 days.

**What happens next:** Phase 3 — scale to 10,000 participants. Design live-challenge ceremonies. Integrate the identity layer with the full QCB Chain node (replacing the Phase 0 stub in `PopAttestation::verify()`). Begin Phase A of the Section 4.6 strategic directions (RWA compliance), which requires the permissioned EVM.

The pass does not mean the identity layer is production-ready. It means it is ready for the next phase at the next scale.

### 8.2 Fail on Sybil Rate

**Definition:** sybil rate > 3% at any confidence level.

**What this means mechanically:** the web-of-trust base layer (and/or the live-challenge backstop, if implemented) did not provide sufficient resistance. A 3% failure at 1,000 participants means approximately 30 fake identities survived. Whether this is a design failure or an implementation failure determines the response.

**If it's an implementation failure** (the ceremony was run incorrectly, the challenge was too easy, the web-of-trust enforcement had a bug): fix the implementation and re-run Phase 2 with a fresh cohort. The design is not invalidated.

**If it's a design failure** (the web-of-trust model is structurally gameable at this scale, or the live-challenge format is automatable with current AI): return to the identity design. Section 4's list of alternative approaches (government ID + ZK, biometric hardware) must be reconsidered. The whitepaper's sovereignty constraint may need to be re-examined against the cost of weaker sybil resistance.

**The hard outcome:** if the identity layer cannot achieve 3% sybil rate without either government ID or biometric hardware, QCB's sovereignty principle and its sybil resistance are in direct tension. The whitepaper acknowledges this tension exists; the pilot is what determines whether it can be resolved. If it cannot, the design must change — not the target.

### 8.3 Fail on Cost

**Definition:** per-verification cost > $5 at 1,000-person scale.

**What this means:** verification is too expensive to scale to the population size required for meaningful UBI or governance. At $50/verification, reaching 100,000 verified humans costs $5,000,000 — plausible but limiting. At $500/verification, the system cannot scale to meaningful UBI without external subsidy.

**Response:** redesign the verification flow to reduce coordinator time, automate infrastructure, and reduce challenge design cost per verification. The $5 target is specifically designed to be self-fundable at pilot scale (Section 8.5's cold-start analysis) — if verification costs $50, the cold-start analysis changes materially.

### 8.4 Inconclusive

**Definition:** the pilot ran but the red team did not attempt a serious attack, the participant count was too low for the statistical confidence interval to be meaningful, or a significant infrastructure failure prevented 90 days of continuous operation.

**Response:** extend the pilot. An inconclusive result is not a pass. The whitepaper's commitment is to a falsifiable pilot — an inconclusive result does not falsify anything, but it also does not validate anything.

---

## 9. Liveness Requirement Design (Open Question 24)

The whitepaper (Section 4.5 and Q24) establishes the principle: participation maintains identity. The pilot is where the specific liveness requirement gets designed and tested.

### 9.1 Candidate Requirements

Three candidates, from most to least restrictive:

**Option A — UBI claim required:** a verified human must claim UBI at least once per 90-epoch window (90 days in production) to maintain Verified status. This is the tightest coupling to economic participation — identity requires actively engaging with the UBI mechanism. The downside: participants who are ill, traveling without internet access, or in jurisdictions where the app is inaccessible for 90 days lose verified status.

**Option B — Any on-chain activity required:** any $CIRFI transaction, governance vote, or UBI claim within 90 epochs maintains Verified status. This is less restrictive than Option A — a participant who holds $CIRFI and occasionally transacts maintains status without claiming UBI. The downside: someone who holds $CIRFI and transacts occasionally but never claims UBI can maintain verified status without engaging with the UBI economy.

**Option C — Live-challenge attendance required:** attendance at any live-challenge ceremony within a 180-epoch window maintains Verified status. This is the loosest requirement — once per 6 months — and is specifically designed for people who are intermittently active. The downside: it couples liveness to the live-challenge infrastructure, which does not exist in Phase 0 or Phase 1.

**Current implementation (Phase 0):** `LIVENESS_EPOCH_WINDOW = 90` in `chain-forge-identity`, checked in `IntrinsicCharm::is_lively()`. Any participation event (UBI claim, governance vote, transfer) recorded via `record_participation()` resets the window. This maps closest to Option B.

### 9.2 What the Pilot Tests

Phase 2 deliberately includes participants who will be intermittently inactive — travel, illness, absence. Observing how many participants lapse under the current 90-epoch window, and whether they are able to recover, gives real data on whether the requirement is calibrated correctly.

**Pilot output on liveness:** the fraction of Phase 2 participants who lapse at least once during 90 days, the average duration of lapses, and the fraction who successfully recover. This data feeds directly into finalizing Q24.

### 9.3 What Happens on Lapse

The current implementation downgrades lapsed identities to Provisional. The pilot tests whether this is the right behavior:

- Does lapsing to Provisional and requiring re-verification feel punitive enough to deter gaming (someone who wants to maintain identity without participating)?
- Does it feel punitive enough to cause legitimate users who had a life event to abandon the system?

These are empirical questions. The pilot measures both.

---

## 10. Open Questions This Pilot Is Designed to Answer

The pilot is directly connected to whitepaper Open Questions 1, 9, 14, 15, and 24. Each question has a pilot measurement that addresses it.

| Open Question | What the Pilot Measures |
|---|---|
| Q1: Final identity layer design | Phase 2 determines whether web-of-trust + live-challenge achieves 3% sybil rate, or whether a different approach is needed |
| Q9: Identity replacement process | Phase 2 tests the governance mechanism for challenge format rotation — do participants accept a changed challenge format mid-pilot? |
| Q14: Validator liveness under partial participation | Phase 2 observes what fraction of verified humans would participate as validators, giving the first real data on the validator availability problem |
| Q15: Minimum legitimate participation rate | Phase 2 measures actual turnout in pilot governance votes, validating or falsifying the 3%/6% quorum floors derived in Section 6.6 |
| Q24: Liveness requirement | Phase 2 measures lapse rates and recovery rates under the current 90-epoch window, feeding the calibration of the final liveness requirement |

---

## 11. What This Document Does Not Specify

Three things are deliberately left unspecified because they require decisions this document cannot make:

**The challenge format.** What the live-challenge ceremony looks like — the specific tasks, the platform, the coordination mechanism — is not specified here. Challenge design is a separate deliverable, and it must be designed specifically to resist the current state of AI automation, which changes faster than this document can track. The challenge format is designed immediately before Phase 2, not now.

**The web-of-trust graph rules.** The specific rules for how many attestations are required, how long attestations are valid, how circular attestations are detected, and how attestation chains work — these are Phase 1 implementation decisions, not pre-pilot design decisions. They emerge from running Phase 1 and observing what goes wrong.

**The legal and jurisdictional structure.** The pilot operates in specific jurisdictions with specific participants. Whether the verification ceremony constitutes a regulated activity, what data is collected, and what privacy protections apply to the web-of-trust graph are legal questions, not engineering questions. These require counsel (Open Question 5) before Phase 2 involves participants from regulated jurisdictions.

---

## 12. Pilot Output

The pilot produces four deliverables:

1. **Sybil rate report** — the measured sybil rate from Phase 2, with methodology, confidence interval, and red-team disclosure. Explicitly states whether the 3% target was met, missed, or inconclusive.

2. **Cost report** — the measured per-verification cost from Phase 2, with breakdown by coordinator time, infrastructure, and challenge design. Explicitly states whether the $5 target was met, missed, or inconclusive.

3. **Liveness calibration report** — lapse rates, recovery rates, and a recommendation for the final liveness requirement value (Q24). Feeds directly into the mainnet launch parameter for `LIVENESS_EPOCH_WINDOW`.

4. **Identity design recommendation** — based on Phase 2 results, one of: (a) proceed to Phase 3 with current design, (b) modify web-of-trust parameters and re-run Phase 2, (c) modify challenge format and re-run Phase 2, or (d) return to identity design — the current approach does not meet targets and an alternative mechanism is required.

Deliverable (d) is the one the whitepaper has always said is possible. The pilot is how QCB finds out whether it is necessary.

---

*This document is a companion to the QCB Chain Whitepaper v2. It does not supersede the whitepaper — it operationalizes the commitments the whitepaper makes about the identity pilot. If the whitepaper changes, this document should be updated to match.*
