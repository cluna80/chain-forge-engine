# QCB Attestation Guard Design

**Status:** Implemented through Phase D — `chain-forge-identity` crate, September 2026 (65 tests passing). Pilot parameters compiled as constants; governance-tunable parameterization deferred to Phase 1.  
**Relates to:** Section 3.3 (PoP), Section 4 (Identity), Section 11 (Phase 0 checkpoint)  
**Not a whitepaper amendment.** Policy parameters are tunable; this doc is the input to a future whitepaper amendment once pilot data is in.

**Implementation surface (as of September 2026):**
- `chain-forge-identity/src/lib.rs` — attestation guard Phases A–D
- `chain-forge-execution/src/lib.rs` — `TxBody` variants: `RevokeAttestation`, `ConfirmSybil`, `ReverseSybil`, `ReportSuspectedSybil`
- `chain-forge-core/src/lib.rs` — `GenesisConfig.attestation_coordinator: Option<String>`
- `chain-forge-node/src/node.rs` — coordinator wiring at node startup from genesis config
- `chain-forge-node/src/api.rs` — `GET /api/identity/{address}` REST endpoint
- `genesis-3node.json` — `attestation_coordinator: "qcb1alice"` (pilot coordinator, Alice validator)

---

## What the VRC Circuit Actually Proves

Before designing guards, the cryptographic guarantee needs to be stated precisely, because the guard design inherits from it.

The current `VrcMembershipCircuit` (Groth16 over BLS12-381) proves:

> **"I know a valid credential that is a member of this VRC registry (identified by its Merkle root), issued by an approved issuer."**

What it does **not** prove:
- That the credential belongs to this specific claimant and no one else
- That the credential has not been used before (no nullifier)
- That the credential has not been shared or transferred

**Implication for sybil resistance:** A single valid credential can produce unlimited membership proofs against the same root. The circuit does not bind a proof to a single identity claim. Sybil resistance at the credential level therefore depends entirely on the issuance policy — specifically, that issuers issue each credential to exactly one human and do not issue duplicates, and that credentials are non-transferable by social/legal agreement enforced through the issuer relationship.

The circuit boundary is cryptographically confirmed: a proof from a foreign registry (different proving key, different root) is rejected by this registry's verifier. The guarantee is **membership in this specific registry**, not membership in any registry.

**The nullifier decision (make it now, not later):** A nullifier (hash of the leaf plus a domain separator) added as a public input would allow on-chain double-spend detection — each leaf could only produce one accepted proof per domain. This is a real cryptographic change, not a test fix.

The honest position on deferral: the pilot cannot detect credential reuse without a nullifier. There is no instrumentation path — detecting that the same credential produced two identity claims requires either (a) a nullifier on-chain, or (b) an off-chain registry of credential→claim mappings, which reintroduces centralization. "Wait for pilot evidence" is therefore not a real trigger, because the pilot won't surface what it can't measure.

**Decision for Phase 1:** The pilot will *not* attempt to detect or prevent credential reuse. The risk is accepted and named: a single valid credential could produce proofs for multiple identity claims in different contexts, and the pilot has no mechanism to detect this. The defense is issuance policy — single-credential-per-human, enforced by the issuer relationship — and the pilot will instrument issuer behavior (credential issuance counts per issuer), not proof reuse.

**Trigger for adding a nullifier:** A nullifier becomes necessary when (a) the system moves to permissionless issuers who cannot be held to a single-credential policy, or (b) pilot issuers report credential transfers or compromise at any non-trivial rate. Either condition requires the nullifier before the next credential issuance round, not after it.

---

## Design Principle

The attestation guard system is a **quadratic-cost reputation system, not a token-cost system.** The scarcity resource is the attester's own credibility, not their balance. This is what gives attestation meaning as a trust signal — an attester with nothing to lose can attest freely, but an attester whose Contribution Score is built on verified attestations has skin in the game.

---

## The Four Guard Decisions

### 1. Attestation Cost

**Decision:** Attestation is not free, but the cost is not gas. The cost is **reputation exposure**.

Rationale: Gas fees penalize low-frequency honest attesters (who attest people they actually know) at the same rate as high-frequency farmers. Reputation exposure scales with behavior — an honest attester who vouches for 3 real humans accumulates 3 clean attestations. A farmer who vouches for 50 sybils accumulates 50 bad bets that detonate on discovery.

**Mechanism:** When a sybil is confirmed (see below), the attester's Contribution Score (CS) takes a proportional penalty equal to a configurable percentage of the CS points they earned from that attestation. Implementation: `attest_penalty_rate` (governance-tunable, initially 100% — attester gives back all CS earned from the bad attestation plus an additional 20% as a deterrent signal).

### 2. Per-Epoch Cap

**Decision:** Hard cap of **3 outbound attestations per 90-day rolling window**, enforced on-chain.

Rationale: The cap must be *below* typical honest usage so that farmers exhaust their budget before making a meaningful impact. Pilot hypothesis: honest users attest 1–3 people over 90 days (close contacts, colleagues, community members they actually know). Starting at 3, not 5, leaves room to raise based on data. Raising the cap is reversible; setting it too high and enabling early farming is harder to undo.

**On-chain state:** `(attester_id, epoch_window) → count` where `epoch_window = current_epoch / 90_day_epochs`. Checked at attestation submission; rejected if count ≥ cap.

### 3. Attester Penalty for Discovered Sybils

**Decision:** CS-based penalty (not stake-slash) on sybil discovery. Self-reporting exemption applies only when an independent process confirms the reported identity as a sybil — not when the attester says so unilaterally.

**Why not stake-slash:** Slashing is disproportionate for honest mistakes and removes the attester from the system entirely. CS loss is recoverable over time, proportional, and keeps the attester in the web of trust where they can rebuild credibility.

**Self-reporting:** An attester may flag a vouched identity as suspected sybil via governance. If governance confirms the sybil independently, the attester's penalty is reduced (currently: 50% of the standard penalty — the "I flagged it before discovery" signal carries weight). Unilateral self-reporting without independent confirmation receives no reduction — this closes the cooperative-exit attack described below.

**Cooperative-exit attack (closed):** Two colluding accounts attest each other, one "self-reports" the other as sybil, penalty-free exit for both. This attack fails under the above rule because: (a) unilateral self-reporting gets no reduction, (b) independent confirmation (governance/coordinator) is required for the reduction, and (c) the "sybil" account's CS and identity record are forfeited on confirmation — making the pair-wise collude-then-exit loop net negative for both parties.

### 4. Attestation Revocation

**Decision:** Revocation is allowed at any time, with an immediate CS cost. Governance sees a pattern feed, not a veto queue.

**Cost:** A small, flat CS deduction on revocation (initially: 10% of CS earned from that attestation), regardless of reason or timing. This creates honest-mistake exit ramp with real but recoverable cost. The cost is the same whether the attester learned they were wrong in week 1 or month 6.

**Governance role:** Revocations are surfaced to governance as a pattern feed (e.g., "attester X revoked 3 attestations in 30 days — flag for review"). Individual revocations are not gated; pattern detection is. Revocation gating would make correction slow enough to be useless for its primary purpose.

**Effect on the revoked identity:** Revocation removes the attestation's CS contribution from the revoked identity's score and flags the identity for coordinator review. It does not itself mark the identity as a sybil — that requires confirmation.

---

## Implementation Design Decisions

Before code, these questions need explicit answers — the code defaults to whatever we write here.

**Q1: Does revocation free a cap slot?**
Yes. A revoked attestation does not count against the attester's 3-slot budget. Rationale: if revocation permanently consumed a slot, an honest attester who discovers a mistake is penalized twice — once by the CS hit, once by a permanently reduced future budget. That's disproportionate. The ring buffer implementation should free the slot on revocation.

**Q2: Is the CS penalty applied at the moment of sybil confirmation, or does it reach back to affect past CS calculations?**
At the moment of confirmation. Alice's CS at epoch 100 (when Bob is confirmed sybil) takes the -20% hit on the CS she earned from that attestation. It does not retroactively change her CS history at earlier epochs. Rationale: retroactive recalculation is complex and surprising; at-confirmation is auditable and predictable. The penalty is on the *current* CS balance as a deduction, not a re-scoring of the past.

**Q3: Can the coordinator reverse a sybil confirmation? Do reversed penalties come back?**
Yes on both counts. `ReverseSybil` is a valid coordinator action. When reversed: CS penalties are credited back, attestation records are un-penalized, and the reversal is logged. Rationale: false positives happen, and a system where coordinator mistakes are permanent has a different trust property than one where mistakes are correctable. The log ensures reversals are auditable. Note: this means coordinator authority includes CS modification (confirm increases penalty, reverse credits it back) — see Q5.

**Q4: What's the minimum pilot size for the cap to actually bind behavior?**
The cap starts to matter around 30–50 active attesters. At 5 people, 3 attestations/90 days is unconstrained. At 30+, the cap starts to differentiate honest-but-limited-network attesters from would-be farmers. The coordinator should track "attesters who have hit the cap" as a metric from day 1 — if no one hits the cap in the first 90 days, the cap is decorative and should be revisited. If >20% of attesters hit the cap, it may be too low.

**Q5: Does the coordinator have authority over CS directly, or only over sybil flags (with CS as an automatic consequence)?**
The coordinator flags sybils; CS modification is automatic on the on-chain side. But because the coordinator can `ReverseSybil` (Q3), the coordinator effectively has indirect CS modification authority through confirmation and reversal. This is intentional and named here: during the pilot, the coordinator is the effective CS modification authority for sybil-related penalties. This is centralization. See the coordinator caveat below.

---

## Pilot-Phase Centralization: Coordinator Role

**This is a temporary deviation from the sovereignty design principle, and it must be named as such.**

During the pilot, sybil confirmation (`ConfirmSybil`) and reversal (`ReverseSybil`) are performed by a designated coordinator role — a specific key or multisig with authority to call those methods on the identity store. This coordinator role:

- Is the only entity that can confirm a sybil (no governance challenge mechanism in Phase 1)
- Has indirect CS modification authority through sybil confirmation and reversal
- Is a centralized dependency in a system designed to remove centralized dependencies

**Why this is acceptable for the pilot:** The pilot needs a mechanism to confirm sybils. Designing on-chain governance challenges before the pilot has produced a single confirmed sybil is designing in the dark. The coordinator role is the honest minimum for pilot-phase sybil confirmation.

**Migration path:** Upon pilot completion, sybil confirmation migrates to one of:
- (a) On-chain governance: `ConfirmSybil { identity, evidence }` governance transaction with defined evidence format and challenge process
- (b) Retirement: if the pilot produces no confirmed sybils, the mechanism may not be needed, and the coordinator role is removed without replacement

The coordinator role is not a permanent feature. If it persists past the pilot without an explicit decision to keep it, that is a governance failure, not an intended design.

---

## Implementation Surface

**New on-chain state:**
- `attestation_records: Map<(attester_id, identity_id), AttestationRecord>` — full record per attestation: epoch, status (Active/Revoked/Penalized), revocation_epoch, penalty_applied
- `attester_cap_window: Map<attester_id, [Option<u64>; 3]>` — ring buffer of 3 epoch slots per attester for rolling-window cap tracking (replaces the simpler `attestation_window_count` map; ring buffer is bounded and handles the 90-day rollover correctly without additional queries)
- `pending_sybil_reports: Map<identity_id, Vec<(attester_id, report_epoch)>>` — self-reports awaiting coordinator confirmation
- `coordinator_id: Option<ValidatorId>` — pilot-phase coordinator key; None until set at pilot launch

**New governance-tunable parameters:**
- `attest_cap_per_window: u32` — initial value: 3
- `attest_window_epochs: u64` — initial value: 90 days in epochs
- `attest_penalty_rate: Percent` — CS clawback on sybil discovery, initial: 120% (100% earned back + 20% deterrent)
- `attest_revocation_cost: Percent` — CS cost on revocation, initial: 10% of earned
- `self_report_penalty_reduction: Percent` — reduction if attester flagged before confirmation, initial: 50%

**Not in scope for Phase 1:** Nullifier-based double-spend detection. Deferred until pilot data indicates it's needed.

---

## What This Mechanism Does Not Defend Against

**Coordinated sybil rings:** A group of N humans who all attest each other form a closed ring where no member has incentive to report any other member. The ring generates valid attestations and CS for all members. Detection requires an external signal (coordinator challenge, behavioral anomaly, ZK proof reuse across identities). The attestation guard design does not solve this — it makes individual farming more expensive, not coordinated farming impossible.

**Issuer compromise:** If a VRC issuer issues credentials to non-humans or sells credentials, every proof built on those credentials is cryptographically valid. The guards cannot distinguish a compromised-issuer credential from a legitimate one. Issuer governance (existing) is the defense here, not attestation guards.

**Credential sharing:** As noted above, the current circuit does not bind a proof to a single holder. If credentials are transferred, the recipient can generate valid proofs. This is a social/legal constraint enforced through the issuer relationship, not a cryptographic constraint in the current circuit design.

**Timing attacks:** An attacker who learns that a sybil confirmation is imminent could revoke their attestation just before confirmation, paying only the revocation cost rather than the full penalty. Mitigation: a confirmation lock period (e.g., 7 days during which pending confirmations block revocations at penalty reduction) — deferred to post-pilot.

---

## Pilot-Phase Parameters (Provisional)

| Parameter | Pilot Value | Rationale |
|---|---|---|
| Cap per 90-day window | 3 | Below estimated honest usage ceiling |
| Penalty on sybil discovery | 120% of earned CS | Deterrent above break-even |
| Self-report reduction | 50% | Incentivizes early flagging |
| Revocation cost | 10% of earned CS | Affordable correction, non-zero signal |
| Confirmation lock period | Not enforced (Phase 1) | Simplicity; revisit if timing abuse observed |

All parameters are governance-tunable without a protocol upgrade. Adjust based on pilot data, not prior expectations.

**Review trigger:** Parameters are reviewed at the earlier of (a) 90 days after pilot opens, or (b) 50 verified humans reached. At that point: check observed attestation frequency against the cap (raise if honest users are hitting the ceiling), check sybil discovery rate against the penalty rate (raise if discovery is frequent enough that farmers are still net-positive), and check revocation frequency for timing-attack patterns (enforce the confirmation lock period if observed). Parameters that float without a review point are parameters that never get reviewed.

---

## Path to Whitepaper Amendment

This doc becomes input to Open Question 24's resolution. The whitepaper amendment should happen once, after the pilot produces data on:
- Observed attestation frequency distribution (actual vs. assumed cap)
- Sybil discovery rate and attester correlation
- Revocation frequency and reason patterns

The amendment closes Open Question 24 with the finalized mechanism description and removes the "still in active design" language from Section 4.
