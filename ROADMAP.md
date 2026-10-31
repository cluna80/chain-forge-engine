# Chain Forge / Qattice — Engineering Roadmap

> **How to use this doc**: This is the running reference for what's done, what's next, and what's on the horizon. Update it when a milestone ships. Cross-reference the whitepaper (`QCB-Chain-Whitepaper-v2.md`) for economic design rationale; this doc is the engineering view.

---

## Locked Working Plan — what to do next (owner, 2026-10-30)

Protocol first; applications (PoCD, marketplace, research apps) come after the protocol acceptance gates. Order: **Phase 0 → Phase 0.5 → repository separation → PQ-HotStuff**. Status detail and audit findings: issue #37.

| # | Step | Done when |
|---|---|---|
| 1 | **P0 security: ML-DSA account ownership** (branch `security/mldsa-account-ownership`). On first use, the sender must be the address derived from its ML-DSA key. The key is bound whenever signatures are verified. Named accounts get their key bound in genesis. | Node and live tests pass (incl. `mldsa_only_accounts_live` A-01..A-09), draft PR, Windows ✅, merged. **The upgraded devnet is not deployed before this.** |
| 2 | **#36: retire the Ed25519 fallback devnet** (scripts, README, local launchers on the ML-DSA devnet) | Owner review and merge (Windows ✅ already) |
| 3 | **Test fixes:** `attestation_guard_live` (fund a key-derived account), `dis_auth_live` (`generate_random()` instead of the seed `"random"`), `dis_003b` D-09 (poll instead of one read) | Pass on Linux and Windows; gives P0-2 its automated evidence | ✅ Windows-confirmed 2026-10-31 — `dis_auth_live` ✅, `dis_003b_guardian_update_live` (D-01–D-09) ✅, `attestation_live::attestation_guard_live` + `attestation_coordinator_gate` ✅ (PR #40, commits `aeb6428`, `44dd826`, `32c8519`, `9dc0df9`). Root causes: ML-DSA non-deterministic keypair (dis_003b), RegisterIdentity/Attest ordering race (attestation_live). |
| 4 | **Phase 0 closeout:** finish the audit sweep on current `main`; write `docs/PHASE-0-CLOSEOUT.md`. For each of P0-1..P0-9: Implementation, Verification (Linux and Windows), Evidence (test, result, commit). P0-1 needs a two-machine run on the ML-DSA devnet. P0-9 (PoCD) is classed as application layer. | Every Phase 0 criterion has current evidence. 100% = all defined acceptance criteria pass. Tag `v0.1.0-phase0` and branch `devnet-legacy-2026-10` stay untouched. |
| 5 | **Phase 0.5 blockers:** <br>• H0-3: atomic state persistence; fail safely, never silently restart from genesis. <br>• H0-8: genesis-hash peer check; cross-chain block-replay test. <br>• H0-10: recovery timelock and cancellation. <br>• H0-12: governance proposals and votes with quorum. <br>• H0-11: after the owner's eviction-policy decision. <br>• P2P reconnection, with a Linux partition test. | Each: failing tests first, then sandbox, then Windows ✅ |
| 6 | **Repository separation** (CF-QAT-REPO-001, below) | Its go/no-go gates pass |
| 7 | **PQ-HotStuff** (`docs/pq-hotstuff-001-spec.md`), in the Chain Forge repo as a new engine module: <br>• **Phase 0:** start with a short design step that makes block commit evidence generic over the certificate type, so participation and rewards don't depend on the engine. Then the engine, the safety rules and simulations. <br>• **Phase 1:** persistence and personhood weighting. <br>• **Phase 2:** devnet candidate; only then a new genesis, `genesis-4node-pq-hotstuff.json`: a copy of the ML-DSA devnet genesis with `bft_variant: "pq-hotstuff"`, `personhood_weighted: true`, a new `chain_id` / `network_id`, and its own ports and data. <br>• **Phases 3–4:** hardening and review, then a fresh mainnet genesis. | Per the spec's gates. Tendermint stays the devnet default until PQ-HotStuff passes Phase 2 on Windows. Existing chains are not converted; the PQ-HotStuff devnet runs alongside them. |

## Planned Repository Separation — CF-QAT-REPO-001

**Status: PLANNED / NOT AUTHORIZED FOR EXECUTION.** Chain Forge and Qattice will become separate, independently versioned repositories. The existing Chain Forge frontend repository is the intended home of the reusable Rust backend; Qattice will have its own chain-specific repository with a pinned dependency on Chain Forge.

**Normative migration procedure:** [docs/CF-QAT-REPO-001-repository-separation.md](docs/CF-QAT-REPO-001-repository-separation.md). Follow its preconditions, ownership inventory, sequence, acceptance tests, stop conditions and rollback requirements. This document is planning only: **do not migrate source, create/delete repositories, rewrite history, change remotes or modify deployments without a separate explicit go-ahead**.

**Start gate:** Finish and document the 24-suite sweep; fix and regression-test the ML-DSA account-ownership issue; record the Phase 0 current-code baseline and all open failures; inventory crates, existing frontend repo, target repo and in-flight work; back up tags/devnet data. Then request explicit migration authorization. Preserve `v0.1.0-phase0`, `devnet-legacy-2026-10`, the original Phase 0 table and all historical evidence.

**Development priority:** Complete Phase 0, then Phase 0.5, then Phase 1 protocol acceptance. PoCD and other application-layer development are deferred. Repository separation does not itself close any protocol acceptance gate.

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
### The name is Qattice, changed from QCB but still uses $QCB as the token to the ecosystem.

---

## Qattice LLC — Business Activation (Future Milestone)

> **What:** Formally activate Qattice LLC as a U.S. software engineering company. The LLC is the legal entity that owns all IP, signs government contracts, holds SBIR awards, and enters commercial agreements. The company builds three core products: **Chain Forge** (modular blockchain creation platform), **Qattice** (the first production chain built with Chain Forge), and **DIS** (post-quantum cryptographic identity enforcement for regulated contracts and high-security systems).
>
> **One-line description (SAM.gov / SBIR / contracts):**
> *Qattice LLC is a software engineering company building post-quantum blockchain infrastructure, modular distributed computing platforms, and cryptographic identity systems for regulated contracts and decentralized applications.*
>
> **Status:** 🔲 Locked — activate when prerequisite tracks reach completion gates below.

### Activation Prerequisites

| # | Track | Required completion gate | Status |
|---|-------|--------------------------|--------|
| BIZ-PRE-1 | **Phase 0.5 — Protocol Hardening** | H0-5 (execution rollback) and H0-7 (supply conservation) confirmed locally | 🔲 |
| BIZ-PRE-2 | **DIS — Account Security and Recovery** | DIS-003D and DIS-003E confirmed locally on Windows/MINGW64 | 🔲 |
| BIZ-PRE-3 | **DIS Standalone Product** | Independent cryptographic review gate passed (currently marked ⚠️ return before production on DIS-CORE-001, DIS-PQ-001, DIS-PRIV-001) | 🔲 |
| BIZ-PRE-4 | **FeeSponsor** | FS-03 live authorization complete (SponsorAuthorization wired into execution path) | 🔲 |
| BIZ-PRE-5 | **Validator Onboarding** | Validator eviction policy decided and implemented (H0-11) | 🔲 |

> All five gates do not need to close simultaneously. BIZ-PRE-1 and BIZ-PRE-2 are the minimum viable gates — the company can be formed and SAM.gov registration started in parallel with engineering, but active SBIR pursuit requires a demonstrable post-quantum identity capability (DIS-003D/E complete) and a provably correct state machine (H0-5/H0-7 confirmed).

### Business Activation Checklist (when prerequisites met)

| Step | Action | Notes |
|------|--------|-------|
| CORP-1 | Form Qattice LLC in home state | Sole member LLC; ~$50–150 state filing fee |
| CORP-2 | Register on SAM.gov — obtain UEI | Takes 1–2 weeks; required before any federal contract or SBIR submission |
| CORP-3 | Register on SBIR.gov using UEI | Unlocks submission to all 11 SBIR agencies including Army |
| CORP-4 | File NAICS codes: 541511 (Custom Computer Programming), 541519 | Primary codes for software engineering company |
| CORP-5 | Prepare technical capability statement | 1-page: Chain Forge + Qattice + DIS, framed for Army MOSA open-architecture requirement |
| CORP-6 | Monitor Army SBIR topic releases at armysbir.army.mil | Army releases topics several times per year; Phase I window ~30–60 days |
| CORP-7 | Submit Phase I proposal | Target: post-quantum machine/operator identity for MOSA-compliant defense platforms |

### Defense Market Positioning

**Primary SBIR pitch:** Post-quantum machine and operator identity for MOSA-compliant defense platforms — DIS as a drop-in ML-DSA-65 authentication module that any open-architecture defense system can integrate.

**Secondary (Phase II expansion):** Chain Forge Secure Compute — private, verifiable distributed computing for defense research laboratories and contractors, with DIS authorization, PoCD verification, and signed execution receipts.

**Relevant Army priorities (per Secretary Driscoll, 2026):** Modular open-system architecture software, next-gen sensors and software payloads, resilient logistics, and advanced manufacturing — Qattice targets the software and identity layer of that stack.

---

## DIS Standalone Product — Keystone Identity and Authorization (Planned)

**Status:** 🔲 Research/design; no standalone DIS release or independent security audit claimed. **Scope:** Vendor-independent Digital Identity Stone (DIS) protocol; Qattice Android wallet is the first reference client, not a required dependency.

**Product thesis:** One holder-controlled cryptographic identity can access multiple independent systems, each with its own issuer trust, resources, policies, and permissions. Authentication alone never grants access. DIS is not equivalent to QPC: QPC is an optional verified-human credential; DIS must also support organization, machine, and delegated agent identities without claiming personhood.

**Security invariants:** No cross-vendor permission leakage; no universal access token; audience/resource/action/nonce/expiry binding; replay and confused-deputy resistance; local private-key custody; least-privilege delegated authorization; vendor-controlled revocation; privacy-preserving vendor-specific identifiers; secure recovery without resurrecting compromised keys; cryptographic agility with explicit algorithm migration; offline/local verification where practical. ML-DSA authentication alone does not make every credential, proof, transport, or recovery flow post-quantum secure.

| Milestone | Status | Deliverable / acceptance criteria |
|---|---|---|
| **Vendor server foundation** (DIS-SEC-002/003, DIS-STATE-001/002/003, DIS-SEC-004/005, DIS-GAP-001/002/003) | ✅ Complete (2026-10-21) | Production-ready `dis-vendor-server` v0.6.0: authenticated enrollment (ML-DSA-65 ownership proof), authenticated vendor registration (registration key + origin well-known ownership proof + SSRF hardening), shared PostgreSQL state (multi-instance replay/revocation/session safety), challenge purge sweep, registration token single-use, 36/36 tests. |
| **DIS-KS-001 — Competitive Security and Interoperability Specification** | ✅ Complete (2026-10-19) | Threat model and normative protocol spec; compatibility analysis vs OAuth 2.0/OIDC, FIDO2/passkeys, W3C VCs/DIDs, OpenID4VP; implementation gap audit (DIS-KS-001A); vendor-independent protocol proposal (DIS-KS-001B). Docs: `docs/DIS-KS-001*.md`. |
| **DIS-CORE-001 — Standalone Rust core** | ✅ Complete v0.1 (2026-10-21) — **⚠️ return before production** | `dis-core` crate: no Qattice/blockchain deps, versioned wire format (`DIS-KS-V1`, `SUITE_ML_DSA_65`), domain-separated transcript (`DOMAIN = b"DIS-KS-V1\0"`), canonical request, sign/verify in `wallet`/`verifier` modules. **Must return to:** independent cryptographic review of the transcript format before production or SDK use (golden vectors shipped in DIS-PQ-001). |
| **DIS-KS-002 — Keystone Continuity and Cross-Vendor Authorization** | ✅ Complete (2026-10-21) | One `DemoWallet` connects to three independent `RelyingParty` instances with distinct resource/action/scope grants; each RP stores its own enrolled keys; cross-vendor substitution and replay rejected; `revoke` / `rotate_key` on `RelyingParty` + `rotate` on `DemoWallet` — old-key proofs rejected with `Revoked`, new-key proofs accepted; rotation of one vendor does not affect others — 15/15 `dis-core` tests passed. |
| **DIS-PQ-001 — End-to-end PQ security and migration** | ✅ Complete v0.1 (2026-10-21) — **⚠️ return before production** | `min_suite_id` downgrade resistance enforced at `issue()` and `verify()` with `VerifyError::DowngradedSuite`; frozen golden test vectors for both wire-format variants (`golden_vector_no_operation_digest`, `golden_vector_with_operation_digest`); PQ inventory doc at `docs/DIS-PQ-001-pq-security-inventory.md`. **Must return to:** (1) PQ hybrid TLS on all `rp_origin` endpoints; (2) wallet key recovery design; (3) independent cryptographic review of the transcript format; (4) golden vector validation by a non-Rust client. |
| **DIS-PRIV-001 — Unlinkable presentation and minimal disclosure** | ✅ Complete v0.1 (2026-10-21) — **⚠️ return before production** | `dis_core::privacy` module: `are_linkable()` function + `DisclosureInfo` struct; 6 tests demonstrate no shared public key across vendors, cross-vendor proof rejection, and RP-enforced scope minimality. Docs: `docs/DIS-PRIV-001-unlinkable-presentation.md`. **Must return to:** independent review of unlinkability claim, formal threat model, transport-layer metadata analysis, decision on multi-session within-vendor unlinkability. |
| **DIS-AGENT-001 — Delegated agent/machine authorization** | ✅ Complete v0.1 (2026-10-21) — **⚠️ return before production** | `dis_core::delegation` module: `Delegation` + `DelegatedProof` types, domain-separated `canonical_delegation_body` (`DIS-DEL-V1\0`), `validate_chain` (scopes narrow, sigs valid, expiry), `RelyingParty::verify_delegated` + `approve_challenge`; `max_uses` counter; chain depth limit (4); 9 tests covering basic delegation, scope excess, expiry, 2-level chain, scope widening rejection, human approval gate, max_uses, revoked delegator. Docs: `docs/DIS-AGENT-001-delegated-agent-authorization.md`. **Must return to:** durable max_uses storage, per-delegation revocation, agent key provisioning ceremony, spending limits for financial actions. |
| **DIS-SDK-001 — Vendor SDKs and Android reference wallet** | ✅ Complete v0.1 | `dis-sdk` crate: `VendorSdk` + `WalletSdk`; Android reference wallet (`dis-jni` JNI bridge, `WalletKeyStore`, `WalletViewModel`, key rotation); conformance vectors at `dis-core/conformance/vectors.json`; return gates documented in `docs/DIS-SDK-001-vendor-sdk-and-wallet.md`. Production use requires HSM key storage, authenticated enrollment, and external audit. |
| **DIS-SEC-001 — Assurance and adversarial validation** | ✅ Complete v0.1 | 33 labeled attack scenarios in `dis-core/tests/adversarial.rs`: signature forgery, replay, cross-RP challenge, wrong audience, scope injection, revocation, key rotation, downgrade, delegation chain abuse (depth overflow, scope widening, expired links, max_uses exhaustion, forged delegation sigs, human-approval bypass), stolen-device recovery. All 33 pass. **Full pre-merge validation (2026-10-21):** 104 tests across all DIS crates — 35 `dis-core` unit, 33 adversarial, 16 `dis-vendor-server` unit, 20 `dis-vendor-server` integration, 0 failures; conformance vectors verified (no encoding drift). Return gates in `docs/DIS-SEC-001-adversarial-validation.md`. |
| **DIS-COM-001 — Commercialization readiness** | ✅ Complete v0.1 | Open-core licensing: `dis-core` + `dis-sdk` under MIT (see `LICENSE`); `dis-vendor-server` under BUSL-1.1 converting to Apache-2.0 on 2030-01-01 (see `dis-vendor-server/LICENSE`); split documented in `LICENSE.md`. Revenue path: hosted DIS service + enterprise self-host licenses. Remaining: trademark/prior-art review, formal pricing, pilot customer agreements. |
| **DIS-PILOT-001 — Real-device identity pilot (4 nodes, Verified tier)** | ✅ Complete (2026-10-25) | All 4 pilot device identities — BossKing, Laptop, Phone (Galaxy A15), King-OptiPlex-990 — reached **Verified** tier on the chain-forge devnet node (`qcb-testnet-4node`). Each pilot holds an ML-DSA-65 key (`qcb1pq…` address); ML-DSA-65 identity verification is fully independent of the Ed25519 consensus keys required by genesis validators (pilots registered as `role: "user"`). Bootstrap mechanism: `ATTESTATION_QUORUM` lowered to 1 (from 3) so Alice's single attestation satisfies quorum; `ATTESTATION_CAP_PER_WINDOW` raised to 10 (from 3) to allow Alice to attest all 4 pilots within one rolling window. Key findings: (1) `RegisterIdentity` body must be the string `"RegisterIdentity"` (Rust unit enum variant, not a map); (2) each pilot account has an independent nonce starting at 0; (3) Alice's sequential nonces 0–3 cover all 4 attestations; (4) Qattice wallet UI reflects Verified tier after a page refresh (node state overrides cache). All 4 wallets confirmed Verified across BossKing, Laptop, Phone, and King-OptiPlex-990. Commits: `fcf839d` (lower quorum to 1, revert pilot roles to user), `e59c776` (raise attestation cap to 10). |
| **DIS-002A / DIS-002B / DIS-003 — Qattice on-chain account security** | ➡ See Phase 1 → *Digital Identity Stone — Account Security and Recovery* | DIS-002A (key rotation), DIS-002B (recovery), DIS-003A–E (security hardening) are Protocol Phase 1 milestones; full records live in the Phase 1 section below. |

**First demonstration (DIS-KS-002):** Install a DIS-enabled Qattice Android devnet wallet; connect to three separately operated mock vendors; assign different rights; authenticate with locally held ML-DSA keys; revoke one vendor without impacting the others; rotate/recover the key while preserving authorized continuity; reject old-key signatures, cross-vendor credential reuse, and replay. Measure integration time, latency, privacy leakage, and revocation propagation against reference standards.

**Dependencies / gates:** Define precise security claims and trust boundaries before implementation. DIS identity binding does **not** prove one-human-one-credential; QPC uniqueness remains a separate research/pilot gate. Do not claim production readiness, novelty, post-quantum end-to-end security, or interoperability until demonstrated and independently assessed.

---



## Planned Feature — FeeSponsor (Native Transaction Fee Sponsorship)

**Status:** 🔄 In progress on branch `fs-01-feesponsor` (FS-01 + FS-02 landed; not yet merged to `main`, not yet wired into live execution). **Placement:** After core deterministic transaction-fee accounting and before broad application onboarding.

**Goal:** Let verified developers, research institutions, enterprises, and Charmed Agents sponsor Qattice transaction fees in QCB on behalf of users. The user authorizes the operation; the sponsor separately authorizes the fee payment. This is a native fee-payer primitive, **not** a second token or a protocol-level resource marketplace. Full design: `docs/FeeSponsor.md`.

| Milestone | Status | Acceptance criteria |
|---|---|---|
| Fee accounting prerequisite | ✅ **Complete (2026-10-24).** Deterministic 70/20/10 bps fee split (validators / treasury / burn) implemented in `chain-forge-execution`. `FeeDistribution::split()` applies integer floor division with remainder to validator share. `distribute_block_fees()` transfers validator share → `treasury:validator-pool`, treasury share → `treasury:network`, and burns the burn share via `StateStore::burn()`. Called at end of every `execute_block` and `execute_block_with_identity`. Genesis `ExecutionConfig` accepts optional `fee_distribution_bps` override (sum must equal 10 000). Epoch-close equal reward distribution among eligible validators (Active + pop_verified + nonzero consensus power + not jailed + ≥ 95% participation + per-human dedup via `owner_identity_id`) implemented in `chain-forge-validators::eligible_validators_for_epoch_reward()` and wired into `node.rs`. Zero eligible → pool carries forward unchanged. | Deterministic uQCB fees, charge/refund/failure rules, fee recipient policy, and insufficient-funds handling |
| FeeSponsor crypto primitives (FS-01) | ✅ `chain-forge-execution::feesponsor` — `SponsorAccount`/`SponsorPolicy`/`SponsorAuthorization` types, canonical body hashing matched to the executor's existing `body_json` tx-signing convention, and ML-DSA signature verification with every authorized field (not just `tx_body_hash`) bound into the signed message. 20 unit tests. | Pre-funded uQCB balance type, distinct from user accounts and PoCD research treasury |
| Dual authorization | ✅ (crypto-level) `sponsor_signing_message()` binds chain_id, tx_body_hash, auth_id, sponsor_id, max_fee_uqcb, issued_at_block, expires_at_block | User operation signature and scoped sponsor authorization bound to chain ID, transaction hash, max fee, nonce, and expiration |
| Sponsor policies & persistent storage (FS-02) | ✅ `feesponsor::store::SponsorStore` — `register`/`deposit`, `revoke_now`/`revoke_before_block` (RevokeAuthPrefix), per-tx-max-fee + epoch-budget enforcement, single-use `auth_id` replay tracking with GC pruning, `advance_epoch()`. Self-contained; not yet threaded through `StateStore`/block execution the way `AgentStore`/`IdentityStore` are. | SponsorID linkage without conflating identity sponsorship and fee payment; allowlists, per-tx/epoch budgets, revocation |
| Deterministic execution (FS-03 core) | ✅ **Complete (2026-10-24).** 70/20/10 bps fee split (validators / treasury / burn) with integer-division remainder to treasury. `distribute_block_fees()` operates only on the current block's `fees_collected`, preventing double-settlement. Epoch-close equal validator reward distribution among eligible verified validators (Active + pop_verified + ≥ 95% participation + per-human dedup). 7 accounting acceptance tests cover conservation, remainder rule, double-settlement prevention, failed-tx fee charge, burn supply accounting, zero-fee no-op, and custom bps validation. 6 epoch-reward acceptance tests cover full participation, below-threshold exclusion, zero-eligible carry-forward, per-human dedup, epoch-boundary ordering invariant, and PoP-unverified exclusion. | All nodes agree on fee payer, fee debit, nonce use, failed-tx behavior, atomic state updates, and equal validator rewards |
| FeeSponsor live authorization (FS-03 follow-on) | 🔲 `SponsorAuthorization` wiring into the `Transaction` envelope and `execute_tx_with_identity()` branch through `SponsorStore::validate_and_consume()`. Blocked on finalizing the sponsored-tx envelope format. `SponsorStore` (FS-02) is ready; only the execution-path integration remains. | Sponsor-paid transactions execute identically to self-paid ones from the node's perspective; sponsor balance debited, user balance unchanged |
| Adversarial tests | ✅ (crypto + store level) Forged signature, tampered max_fee/expiry, cross-chain replay, duplicate auth_id, revocation-before-vs-after-issuance, policy bypass, insufficient balance — all rejected with no partial debit. ⬜ Still needed: adversarial tests against the real `Transaction`/`TxBody` envelope and multi-node execution (unblocked now that core fee flow is live). | Forged signatures, replay/cross-chain replay, budget exhaustion, policy bypass, and double charging rejected |
| Multi-node devnet — FS-03-MN-001 | ⚠️ **MN-1–MN-6 PASS (2026-10-24); MN-7/MN-8 pending revalidation (2026-10-27).** Live acceptance test `cargo test --test fee_settle_live`. Verified: **MN-1** identical state roots across all nodes after fee-bearing txs; **MN-2** `treasury:fees`, `treasury:validator-pool`, `treasury:network` balances consistent; **MN-3** per-tx fee deducted beyond raw transfer amount; **MN-4** epoch-close validator balances identical on all nodes; **MN-5** restarted node recovers to peers' state root from persisted data; **MN-6** no double-distribution after crash-restart. **Re-audit (2026-10-27): MN-7 and MN-8 never exercised what they claim.** Rerunning the 2026-10-24 commit shows nearly every MN-7/MN-8 tx failing (hard-coded nonces → `nonce mismatch`, `identity qcb1user1 not found`, Eve's unsigned `RegisterValidatorKey` rejected); MN-7 passed only because fees still moved the root, MN-8 only because its assertion (`balance_after >= balance_before`) accepts "nothing happened". Protocol defects surfaced: (1) the epoch-close sweep judged eligibility on the *new* epoch after resetting participation counters, so no validator has ever been paid (70% of fees accumulate in `treasury:validator-pool`); (2) participation is counted from commit certificates, which carry only the first 2/3+1 precommits, so the 95% bar is out of reach on a multi-validator network; (3) **🔴 state divergence (H0-2):** those certificates are assembled locally by each node from whichever precommits it received first. Fixing (1) made rewards payable and a live 4-node run diverged immediately — at the epoch-1 close the nodes computed 3, 2, 1 and 1 eligible validators from the same 150 uqcb pool. The fix for (1) is therefore **held back (reverted)**; rewards stay unpaid and deterministic until participation comes from a block-included last-commit. The same local certificates also feed `identity.record_activity` (liveness lapses), a latent divergence path on `main`, and state roots are not part of consensus votes, so divergence is not detected. **Decision: deterministic full last-commit participation is the first H0-1/H0-2 item.** MN-7 has been rewritten to assert confirmed tx outcomes, exact fees, nonces and tier transitions (passes in sandbox); MN-8 returns as its own test after the last-commit work. FS-03-MN-001 is not complete until MN-7 and MN-8 pass on Windows/MINGW64. Key discovery (still valid): post-restart consensus requires bootstrap addresses for ALL surviving peers. | Sponsored and ordinary transactions yield consistent state on multiple nodes, including failures |
| Developer SDK | 🔲 | Examples for Grand Challenge, Charmed Agents, and third-party applications; verified sponsors first |

**Invariants:** Only existing QCB/uQCB moves; no new minting, no default burn, no changes to PoCD rewards or BFT voting power. Sponsorship grants no control over user funds. Fee rate (70/20/10 bps) and remainder policy (to treasury) are now established defaults; genesis `fee_distribution_bps` allows override.

**Next step:** finalize the `SponsorAuthorization` fields in the `Transaction` envelope, then branch `execute_tx_with_identity()` through `SponsorStore::validate_and_consume()` for the sponsored path. Multi-node devnet acceptance (FS-03-MN-001) is complete; FeeSponsor live authorization is the remaining FS-03 milestone.

---

## Phase 0.5 — Protocol Foundation Hardening (status 2026-10-28)

Hardening the foundation before adding features. Each item is a draft PR, unmerged until its gates pass on Windows (MINGW64). Merge order: #16 into #14's branch, then #14, #13, #15, #17, #18, #20, #21, #22, #23.

| Item | PR / branch | Status |
|---|---|---|
| Attestation quorum hardening (genesis-configurable) | #14 | 🔄 open |
| H0-5/H0-7 execution atomicity + fee conservation | #15 | 🔄 open |
| MN-7 rewrite (verified outcomes); MN-8 removed pending rewards | #16 | 🔄 open; needs a genuine second Windows `fee_settle_live` run |
| H0-1/H0-2 deterministic participation (committed `last_commit`), state-root binding, liveness jails without burning, Byzantine-robust miss counting, genesis liveness policy, HotStuff/FBA restart height | #17 | ✅ Windows-confirmed; awaiting merge |
| **Consensus safety**: full Tendermint prevote/precommit/lock/unlock; persisted double-sign guard; block-hash verification and agreement | #18 | ✅ Windows-confirmed (consensus 91/91, node 231/231, devnet, restart, `consensus_safety_live` 3/3); awaiting merge |
| Epoch rewards from committed evidence + MN-8 + capital premium (fixed pool) | #20 | ✅ Windows-confirmed (MN-8 live 6/6); awaiting merge after #18 |
| **Release gate 1**: proposal authentication (signed proposals incl. `pol_round`, fail-closed) | #21 | ✅ Windows-confirmed (node 242/242, devnet, `consensus_safety_live` 3/3, MN-8 6/6); awaiting merge after #20 |
| **Release gate 3**: VCA quorum floor (every commit quorum ≥ ⌊2·total/3⌋+1, all engines) | #22 | ✅ Windows-confirmed (node 242/242, devnet 2/2, `consensus_safety_live` 3/3); awaiting merge after #21 |
| **Release gate 2**: HotStuff/FBA devnet-only; unknown `bft_variant` rejected | #23 | ✅ Windows-confirmed (core 55/55, node 243/243, devnet 2/2); awaiting merge after #22 |
| **ML-DSA-65 consensus keys on Tendermint** (devnet; owner decision 2026-10-28) | #24 | ✅ Windows-confirmed (node 253/253; ML-DSA devnet_4node liveness with block-hash + state-root agreement; ML-DSA consensus_safety_live 3/3 with crash/restart; ML-DSA mldsa_tx_live P0-3..P0-6). Partition recovery sandbox-only (no iptables on Windows). Equivocation slashing is gate 4 |

### Consensus safety (#18): why it was needed
A 5-node run with only honest nodes finalized two conflicting blocks at height 1. Validators precommitted without a prevote polka and locked only at commit. The blocks were empty, so state roots matched and only block hashes revealed the fork. Fixed by the full Tendermint state machine (Buchman, Kwon & Milosevic, Algorithm 1). Covered by unit lock-rule tests, a scripted fork counterexample, a seeded model-based simulation (staggered starts, crashes, equivocators within f, fork detection beyond f), and live block-hash agreement tests. Partition recovery passed in the Linux sandbox; it can't run on Windows (no iptables).

### PQ-HotStuff (locked direction, owner 2026-10-28)
PQ-HotStuff (personhood-weighted, ML-DSA-only, two-chain HotStuff) is the target consensus for Qattice mainnet and a selectable Chain Forge engine. Protocol spec: `docs/pq-hotstuff-001-spec.md`. Decisions locked 2026-10-28: D1 two-chain commit; D2 versioned QC (v1 signature list now, mainnet ceiling after M0); D3 round-robin leaders; D4 revocation effective the block after it commits; D5 gate 4 first. The hardened Tendermint devnet (ML-DSA keys, #24) stays the default until PQ-HotStuff passes its Phase 2 gate on Windows. Order: release gate 4 (committed-evidence slashing) first, then PQ-HotStuff Phase 0. The legacy `HotStuffEngine` is not a base and stays devnet-only.

### Integration before merging to `main` (owner decision 2026-10-29)
Nothing merges until these pass and the owner reviews the combined tree. All PRs stay draft.
| Item | PR | Status |
|---|---|---|
| **Security: production keys from the OS RNG.** Wallets generated in one process shared one ML-DSA private key; `qcb-keygen ed25519` keys were SHA-256 of the label (treat as compromised) | #27 | ✅ Windows-confirmed (crypto 47, wallet 14, keygen) |
| DIS-003 (#13) integrated onto the stack (merging #13 directly does not compile) | #28 | ✅ Windows-confirmed (DIS-003A/B/C, DIS-002B live) |
| Deterministic equivocation live test (confirm the evidence reached validation; retry) | #29 | ✅ Windows-confirmed (adversarial_gossip 3/3 ×3) |
| `pocd_reward_live` follows H0-5 nonce semantics (found by the candidate run) | #30 | ✅ Windows-confirmed |
| API: explicit 413 for oversized requests; body limit = genesis `max_tx_bytes`; DIS-003D test genesis 256 KiB; `dis_003d_expiry_live` F-00..F-08 | #32 | ✅ Windows-confirmed (2026-10-30) |
| ML-DSA devnet genesis `max_tx_bytes` 262144 (owner decision 2026-10-30) + 10-guardian recovery size test | #33 | ✅ Windows-confirmed (2026-10-30): devnet_4node 6/6 (10-guardian recovery 221,105 bytes; partition tests skip without iptables) |
| **Security (liveness): proposals stay within `max_block_bytes`.** Every proposal carried the whole mempool; a burst of large txs outgrew the 16 MB gossip limit and stalled finality (reproduced: 25 × 221 KB recoveries stalled a 4-node devnet at height 3). Proposer takes the fitting mempool prefix; validators reject oversized payloads. Live `max_block_live` M-01..M-05 | #34 | ✅ Windows-confirmed (2026-10-30): unit 3/3; max_block_live M-01..M-05 on Ed25519 and ML-DSA keys (25 txs over 8 blocks). Head-of-line follow-up (owner review): an oversized tx no longer blocks other senders; a tx that can't fit any block is evicted. ✅ Windows-confirmed (2026-10-30): h0_participation 26/26; max_block_live 4/4 (2 Ed25519, 2 ML-DSA), no node crash |
| Integration candidate `integration/phase-0-5-candidate` = `main` + #14→#30, #32→#34 + #16 + #19 | #31 | ✅ Windows-confirmed: 24/24 crates, node 257, all live acceptance tests (2026-10-30); ready for owner review |
| Devnet upgrade procedure (preserve the legacy devnet; new chain side by side) | `docs/devnet-upgrade-phase-0-5.md` | draft for review |

**First follow-up after the merge: P2P reconnection.** With `peer_discovery: "bootstrap"` a node dials its bootstrap peers once and never reconnects; failed dials and unparseable bootstrap addresses are silently ignored (unchanged from `main`). Found while explaining one ML-DSA `consensus_safety_live` stall during a ~99-minute machine suspend (rerun 3/3; sandbox 15/15; a 5–10 minute sleep test recovered).

~~Known failing live tests that **also fail on `main`** (not caused by the stack): `validator_key_live::post_genesis_validator_admission` (2 on `main`).~~ **Resolved 2026-10-31 (Windows/MINGW64 confirmed): all 5 `validator_key_live` tests pass** (5/5 ok, 124 s). Three root causes fixed on `main`: (1) `genesis-val002.json` missing — created; (2) `build_bond_tx` sent `owner_identity_id: None` — genesis validators were "unbound", no `bond_validator_owner_binding` event, `pop_verified` never set (`0207bca`); (3) per-human power cap block in `commit_block` ran `unwrap_or(1)` when `personhood_weighted=false`, revoking all validators with power > 1 uqcb at epoch boundary — gated on `personhood_power_cap.is_some()` (`7ffc3c2`). (**Resolved on PR #40, 2026-10-31:** `attestation_guard_live`, `attestation_coordinator_gate`, `dis_auth_live`, `dis_003b_guardian_update_live` all now pass on Windows/MINGW64.) (`dis_003d_expiry_live` is fixed by #32.) Owner decision 2026-10-30: the upgraded ML-DSA devnet uses `max_tx_bytes` 262144 (#33; a 10-guardian ML-DSA recovery is ~221 KB). The mainnet transaction limit is not final (review mempool admission, block capacity, execution cost, resource exhaustion); `max_block_bytes` is reviewed separately. `chain-forge-intelligence` tests do not compile on `main` either.

### Release gates (all four closed; Windows-confirmed)
- ✅ **Proposal authentication** (#21): validators sign their proposals and re-proposals; the signature covers `pol_round`. Receivers fail closed when the proposer has a registered key. Windows-confirmed.
- ✅ **HotStuff / FBA** (#23, Windows-confirmed): `consensus.bft_variant` "hotstuff"/"xrpl" now refuse to start unless `environment.mode = "devnet"`, and an unknown value is rejected instead of silently selecting Tendermint. Neither engine has engine-driven voting, persisted locks or commit-signature checks; a full safety review is needed before they run anywhere else. The chain itself runs Tendermint.
- ✅ **Equivocation slashing from committed evidence** (gate 4, #26, Windows-confirmed: node 257/257; `adversarial_equivocation_over_gossip` passes on Ed25519 and ML-DSA keys with alice slashed identically on 4/4 nodes; devnet_4node 4/4): detection only verifies and queues evidence. Proposers include it in `BlockPayload.evidence`, every voter checks it (signatures under the offender's key at that height, different blocks, age ≤ 1,000 blocks, not already slashed), and it is slashed at commit before execution, identically on every node. Signed bytes now match `vote_signing_bytes` (round u32). Live: alice is slashed identically on 4/4 nodes with no divergence, on Ed25519 and ML-DSA keys.
- ✅ **VCA quorum floor** (#22, Windows-confirmed): every commit quorum is floored at ⌊2·total/3⌋+1 of the set being voted on or verified, in all three engines, at computation and at use. Found: the default VCA config used ⌈2·total/3⌉ (one unit short when total is divisible by 3), and a stored quorum was applied to any set passed in (a certificate with 1/3 of a larger set's power verified).

### Epoch rewards + MN-8 (#20, Windows-confirmed)
- ✅ Rewards pay the closed epoch from committed evidence only. Participation is Byzantine-robust. `consensus.rewards.min_participation_pct` is set in genesis (default 67, range 50–90). Tie-breaks are deterministic.
- ✅ **One minimum bond** (genesis `validator_bonding.min_bond_amount`) decides both seating and reward eligibility (owner decision 2026-10-28).
- ✅ **Capital premium, Model C, fixed pool**: weight = 10,000 + min(k·(bond − bond_min)/1,000 QCB, cap) bps. `premium_k_bps_per_kqcb` ≤ 10,000; `premium_cap_bps` ≤ 5,000. Both default to **0 (off)** until values are chosen. Voting power is unaffected.
- ✅ **MN-8 live passes 6/6.** A post-genesis validator earns exactly pool/5 while voting, and 0 after personhood revocation, when the others earn exactly pool/4.
  - Root causes fixed: the registry PoP sync ran only on the solo path; the record kept a stale 0 bond and no owner binding; there were two different minimum bonds.
- ✅ Windows (MINGW64): consensus 91/91, node 239/239, MN-8 live 6/6 (state root `3ac2b684…` identical to the Linux sandbox). Merge after #18.
- ❓ Open (economics spec): values for `bond_min`, `k`, `premium_cap`; the per-human bond limit (whitepaper §3.3).

### Other follow-ups
- ✅ `attestation_guard_live` / `attestation_coordinator_gate` — fixed in PR #40 (2026-10-31, Windows-confirmed). Root cause: Attest submitted before RegisterIdentity committed; added pre-Attest wait for `registered=true` on all nodes + post-Attest `attestation_count>=1` assertion.
- ⬜ Genesis-hash peer agreement (H0-8); per-tx identity/agent clone performance.
- ⬜ Proposers don't budget gas. `block_gas_limit` is enforced per block at execution (txs past the limit are recorded as failed), so a tx that would exceed this block's gas is failed instead of waiting for the next block. Corrects the #34 note that said per-block gas was not enforced.
- ⬜ `mempool_ttl_seconds` is not enforced (found with #34).
- ⬜ **Investigate:** a node process aborted twice in the sandbox (`max_block_live`, 2 of ~14 runs, debug build) on a tokio-internal `debug_assert!` in the timer driver (`AtomicWaker::take_waker`, tokio 1.54.0). There were no Chain Forge frames in the backtrace, and 6/6 A/B reruns (3 with #34's head-of-line fix, 3 without) passed. Next steps: rerun under a release build and with `RUST_BACKTRACE=full`; check for unsafe or FFI memory errors (pqcrypto, libp2p).
- ⬜ A failed proposal publish is silently ignored (`let _ = network.publish`); log it (found with #34).
- ⬜ Mainnet `max_tx_bytes` / `max_block_bytes`: not decided. Review mempool admission, block capacity, execution cost and resource exhaustion first.
- ✅ **ML-DSA-only user accounts** (owner, 2026-10-30; #35, ✅ Windows-confirmed 2026-10-30: node 270/270, mldsa_only_accounts_live A-01..A-05, mldsa_tx_live, devnet_4node 6/6). Genesis `cryptography.signature_scheme = "pqc-native"` (with `pqc_algorithm = "ml-dsa"`) refuses Ed25519-signed and unsigned user txs, whatever `require_signatures` says; `"classical"`/`"hybrid"` explicitly allow Ed25519. One function, `check_account_signature_policy`, is applied at API admission, gossip intake and execution. An unknown scheme stops the node. The upgraded-devnet template `genesis-4node-mldsa.json` is now `pqc-native`. Live: `mldsa_only_accounts_live` A-01..A-05.
- 🔄 **Retire the Ed25519 fallback devnet** (owner, 2026-10-30; this PR, sandbox ✅, Windows pending). The devnet scripts (`run_4node_devnet.sh`, `run_machine1.sh`, `run_machine2.sh`) and the README quick start now run the ML-DSA devnet (`genesis-4node-mldsa.json`, `keys/mldsa/`) on ports 19080+/28000+, clear of the legacy devnet. Ed25519 genesis files and keys remain as classical-compatibility fixtures (`tests/devnet/README.md`). The legacy pilot devnet (`genesis-4node.json` at the repo root, `qcb-testnet-4node`) is untouched and runs from branch `devnet-legacy-2026-10`. The README's single-node quick start never produced blocks (one of four validators cannot reach quorum); replaced. The local launchers `scripts/start-devnet-local.sh` and `scripts/start-testnet.ps1` also run the 4-node ML-DSA devnet now (owner, 2026-10-30), with their own data folders. The devnet test scripts no longer need `python3` (`tests/devnet/json.sh`); `test7` had failed on Windows because of it.
- ⬜ ML-DSA signatures are verified at execution, not at API admission: a tx with a bad ML-DSA signature is admitted to the mempool, then refused deterministically at execution (no fee, no nonce). Verify at admission too, to keep junk out of the mempool.
- ⬜ Partition recovery is only exercised where iptables is available (skipped on Windows); run it on Linux with the P2P work.

---

## Phase 0 — Core Network and Post-Quantum Identity Validation

> **Re-scoped 2026-10-25.** The original Phase 0 goal — an adversarially-verified cross-machine resource purchase — was invalidated when `chain-forge-resource` and `chain-forge-qrc` were removed from the workspace on 2026-10-18 (commit `211430c`). The execution infrastructure for that acceptance test (escrow tx types, `ResourceNode`, `RegisterMachine`, `SubmitUsefulWork`) no longer exists. Re-introducing those crates solely to satisfy an outdated roadmap would create unnecessary work. The historical resource-market Phase 0 milestones and test results are preserved in the archive section below. Resource-market functionality is deferred as a future optional Chain Forge module; it does not block Qattice's identity and consensus development.

**New goal**: Demonstrate that the Qattice core network — BFT consensus, ML-DSA-65 post-quantum identity, replay and nonce protection, and PoCD reward settlement — operates correctly and safely under the *current* codebase. Phase 0 is complete when every exit criterion below has a passing test mapped to it.

### Cryptographic Architecture Decision (locked 2026-10-25)

> **Superseded (2026-10-30):** the devnet now runs ML-DSA-65 consensus keys and ML-DSA-only user accounts (see the amendment below, #24 and #35). Kept for history.

**Devnet (Phase 0 / testnet):** Hybrid — Ed25519 validator consensus keys, ML-DSA-65 user account keys. Ed25519 was baked into genesis from the start; validators can rotate to ML-DSA consensus keys post-genesis once the BFT vote-signing layer supports it. This is the correct intermediate state: ML-DSA user-account enforcement is proven end-to-end while consensus remains on a well-audited classical scheme.

**Mainnet:** Full ML-DSA-65 from block 1. A new chain is generated with ML-DSA-65 genesis keys for all validators. No Ed25519 anywhere in the signing paths. Quantum resistance from the first block, not retrofitted. There is no migration from devnet state to mainnet — mainnet is a fresh genesis.

This decision is final. Do not re-litigate it during Phase 0 or Phase 1 work.

**Amendment (owner decision 2026-10-28):** the devnet moves to **ML-DSA-65 consensus keys on the Tendermint engine** (branch `devnet-mldsa-consensus-keys`). One variable changes at a time: the engine stays Tendermint (HotStuff/FBA remain devnet-only per release gate 2). The Ed25519 devnet genesis stays runnable as a fallback until the ML-DSA devnet is confirmed on Windows. Found while scoping: after an `ActivatePqConsensus` tx, ML-DSA validators receive voting power, but the engine verified every vote with Ed25519, so their votes were all rejected (a liveness hazard above 1/3 of power).

> **Superseded (2026-10-28):** done in #24; consensus signing is scheme-agnostic. Kept for history.

**Why not change devnet validators to ML-DSA now?** `chain-forge-consensus` is hardwired to `ClassicalScheme` (Ed25519) for all BFT vote signing and verification — `ValidatorInfo.public_key` is a 32-byte Ed25519 key, votes are signed with `SchemeId::Classical`, and `ClassicalScheme.verify()` is called directly in `receive_vote` and `verify_commit`. Switching consensus keys to ML-DSA requires updating those paths, regenerating all validator key files with 1952-byte ML-DSA keys, and auditing every test that constructs `ValidatorInfo` or signs votes. That is Phase 1 / mainnet genesis work, not a devnet patch. The devnet already proves the full ML-DSA user-transaction path end-to-end (P0-3 through P0-6). That is sufficient for Phase 0.

**Token model (current — single token)**:
- **QCB / uQCB** — the one and only token on Qattice. 1 QCB = 1,000,000 uQCB (micro-QCB). All balances, PoCD rewards, staking, and governance use uQCB. There is no second token.
- **PoCD research rewards** — paid from `treasury:pocd-research` in uQCB.

### Phase 0 Exit Criteria

> A milestone is ✅ only when implementation **and** a passing acceptance test both exist. Code alone is not sufficient.

| # | Criterion | Status | Acceptance evidence |
|---|-----------|--------|---------------------|
| P0-1 | Clean genesis launches successfully across independent machines | ✅ | 4-node devnet (`genesis-4node.json`) starts, reaches block 5, all validators active — confirmed multiple sessions |
| P0-2 | All four DIS pilot identities remain Verified after node restart | ✅ | BossKing, Laptop, Phone, King-OptiPlex-990 all Verified (2026-10-25); wallet re-fetches from node on refresh |
| P0-3 | An ML-DSA-65-signed transaction is accepted and finalized across the network | ✅ | `mldsa_tx_live` (commit `b46de7c`): `qcb1sender` ML-DSA-65 Transfer queued, executed `success: true` at height 3, receiver balance confirmed on 4/4 nodes; three ingress bugs found and fixed in the process (wire-format size, F5 hex check, classical sig guard) |
| P0-4 | Invalid signatures are rejected | ✅ | `mldsa_tx_live` P0-4 case: 3309-byte garbage ML-DSA-65 sig rejected at submission or fails execution with verification error |
| P0-5 | Replayed transactions are rejected | ✅ | `mldsa_tx_live` P0-5 case: nonce-0 tx resubmitted → rejected with nonce/replay error |
| P0-6 | Incorrect nonces are rejected | ✅ | `mldsa_tx_live` P0-6 case: nonce-999 tx (expected 1) → rejected with nonce mismatch |
| P0-7 | Timestamp monotonicity finding resolved and regression-tested | ✅ | `node.rs`: both commit paths now use `proposal.timestamp_ms.max(last+1)`; `last_committed_timestamp_ms` field enforces strict monotonicity; `timestamp_monotonic_live` regression test (commit `0b0a611`) |
| P0-8 | Consensus safety and finality pass under current validator config | ✅ | Partition tolerance test (iptables DROP, 5s), equivocation detection, restart recovery — all confirmed; adversarial gossip 3/3 |
| P0-9 | PoCD proof submission and reward settlement verified on current code | ✅ | `pocd_reward_live` (7 cases): valid claim (A), replay rejected (B), unauthorized operator rejected (C), insolvent treasury rejected (D), concurrent claims both settle (E), unknown objective_id/task_id accepted by trusted operator (F), settlement persists across block boundary (G) — all pass on 4-node devnet |

### Resource-Market Phase 0 — Archived (2026-10-25)

> The following section records the original Phase 0 scope and historical test results. It is preserved for reference. **Do not treat these milestones as current requirements.** The execution path they describe was removed from the workspace on 2026-10-18.

<details>
<summary>Original Phase 0 — Cross-Machine Resource Purchase (archived)</summary>

**Original goal**: Machine 1's agent buys computation from Machine 2's resource node; escrow settles; settlement survives ten deliberate attack scenarios.

**Happy path (historical)**:
```
Machine 1 (Alice) → creates Agent-A → funds 100 test QCB
  → Agent-A requests computation → P2P resource discovery
  → Machine 2 (Carol) Resource Node accepts job
  → Job runs in sandboxed container → Carol returns result
  → ResourceExecutionReceipt generated + verified
  → uQCB escrow releases → Carol receives uQCB
```

**Adversarial scenarios (historical — 6 of 10 had zero coverage before removal):**

| # | Attack | Coverage at removal |
|---|--------|---------------------|
| 1 | Fake completion | ❌ No test — `SubmitUsefulWork` removed |
| 2 | Duplicate settlement | ❌ No test — settlement path removed |
| 3 | Replayed receipt | ❌ No test — never wired to execution |
| 4 | Provider disconnect mid-job | ❌ No test — `ResourceNode` never built |
| 5 | Requester disconnect mid-job | ❌ No test — same reason |
| 6 | Tampered result | ⚠️ Unit test in orphaned crate only |
| 7 | Unauthorized agent spending | ✅ Unit test in `chain-forge-agents` |
| 8 | Spending-limit bypass | ✅ `SpendingLimits::check_per_job()` unit test |
| 9 | Forged provider identity | ❌ No test — `RegisterMachine` removed |
| 10 | Double payment / idempotency | ⚠️ Exists for PoCD; not for resource settlement |

**Infrastructure that was removed (commit `211430c`, 2026-10-18):**
- `chain-forge-resource` crate (removed from workspace)
- `chain-forge-qrc` crate (removed from workspace)
- `LockQrcForJob`, `ReleaseQrcForJob`, `RefundQrcForJob`, `RegisterMachine`, `SubmitUsefulWork` tx types

**Future path**: Resource-market functionality may return as an optional Chain Forge module after Phase 0 and DIS-002 are complete. Design should use the uQCB single-token model from the start. Scope and acceptance criteria must be redefined before any re-implementation begins.

</details>

**Token model note**: `chain-forge-qrc` and `chain-forge-resource` have been removed. No escrow tx types exist in the current workspace. The QRC concept is fully retired.

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


### Execution Layer

| Item | Status | Notes |
|------|--------|-------|
| `chain-forge-execution` crate | ✅ | 74 tests, 0 failures |
| All QRC tx types wired (`QrcPurchase`, `QrcContributionSettle`, `PurchaseQrc`, `CreditProvider`) | ✅ | Gas model, `variant_name`, `payload_size_bytes`, `required_module`, `execute_tx` |
| `tx_kind_label()` exhaustive match in `node.rs` | ✅ | Compiler-enforced; updated with every new variant |
| Attestation guard tx types (Phases A–D) | ✅ | `AttestEntity`, `RevokeAttestation`, `ConfirmSybil`, `ReportSuspectedSybil`, `ReverseSybil` |
| Qattice native tx types (Transfer, Stake, Unstake, etc.) | ✅ | |
| Governance tx types | ✅ | `ProposeChange`, `VoteOnProposal`, `ActivateChange` |
| **EVM precompile / permissioned EVM layer** | 🔲 | Phase 5+ — identity layer must be proven at scale first |

### Identity / Personhood

| Item | Status | Notes |
|------|--------|-------|
| Attestation guard Phases A–D (`chain-forge-identity`) | ✅ | 65 tests passing; coordinator-gated |
| ZK-VRC prototype (`chain-forge-personhood`) | ✅ | Groth16 / BLS12-381; 5 binaries; integrated into workspace |
| `governance_authority.rs` — uses real `ValidatorSet` | ✅ | Quorum tied to `quorum_power()` / `revocation_quorum_power()` |
| `/api/identity/{address}` REST endpoint | ✅ | Returns verification tier + CS score |
| Personhood-weighting overlay on BFT | ✅ | PH-OVL-001 merged (PR #6) — per-block refresh clamps power through `power_cap`; 132/132 tests |
| Identity pilot — real-world sybil test | 🔲 | Requires Phase 1 (personhood-weighted BFT) complete |
| Epoch timestamp validation (block proposer drift) | ⚠️ | **Audit finding (2026-10-19, full dependency trace):** `proposal.timestamp_ms` is stored in block summaries (restart replay path only) but is **never used in any consensus-relevant calculation**. Full trace: (1) `commit_block` and `propose_block` both call `advance_epoch_to(cert.height / validator_epoch_blocks)` before `execute_block_with_identity` — epoch is 100% height-derived; (2) `execute_block_with_identity` receives `now_ms` (wall-clock `SystemTime::now()`, not `proposal.timestamp_ms`) which flows only to `state.commit(height, now_ms, ...)` → `StateRoot.timestamp_ms` (audit log, no state-transition feedback); (3) the execution crate never calls `advance_epoch`/`advance_epoch_to` itself — it only reads `identity.clock.current_epoch` already set by the node; (4) all cooldown calculations (`UnbondValidator` unlock, `S3` revocation, `INV-8` epoch cap) use `identity.clock.current_epoch`; (5) `proposal.timestamp_ms` appears only in the restart explorer-rebuild path (`BlockSummary.timestamp_ms`) — not in live `commit_block` block summaries which use `now_ms`. **Consensus/identity/cooldown safety impact: NONE.** **Explorer integrity impact: medium** — proposer-controlled `timestamp_ms` in persisted chain entries can produce misleading block timestamps in `/api/blocks` after restart. **Recommended fix:** monotonicity + drift-bound enforcement in proposal-acceptance path before Phase 2 mainnet (does not affect identity, epoch, or quorum logic). |
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

## Phase 0.5 — Protocol Hardening and Integration

> **Chain Forge vs. Qattice:** Chain Forge is the blockchain creation platform and framework. Qattice is the first independent Layer-1 blockchain being built with it. Phase 0.5 hardening work therefore has two layers: (1) the reusable Chain Forge engine — transaction atomicity, deterministic execution, state persistence, consensus interfaces — and (2) Qattice-specific validation through its own 4-node devnet, post-quantum transactions, identity system, monetary rules, and PoCD mining. Improvements to Chain Forge's engine benefit every future chain built on the platform. The acceptance tests are Qattice-specific because Qattice is the live implementation.

> **Purpose:** This is a security-hardening gate, not a feature phase. Phase 0 proved that Qattice works under cooperative conditions. Phase 0.5 proves it holds under adversarial ones. This phase runs **in parallel** with selective Phase 1 work; however, the protocol blockers listed below must be resolved before any Phase 1 milestone that depends on the affected subsystem can be closed.
>
> **How milestones close:** Same rule as Phase 0 — implementation **and** a passing adversarial acceptance test confirmed locally on Windows/MINGW64. Passing in sandbox only is not sufficient.

### Recommended Execution Order

| Priority | Criterion | Rationale |
|----------|-----------|-----------|
| **1st** | **H0-5 — Execution rollback** | Most fundamental question about the Chain Forge state machine: can a failed transaction leave behind unauthorized state mutations? Transaction atomicity must be provably correct before building on top of it. |
| **2nd** | **H0-7 — Supply conservation** | Verify the monetary rules: fees, burns, PoCD rewards, and transfers must follow the correct conservation law. Note: the correct invariant is `S_after = S_before + I - B` where `I` is authorized issuance and `B` is authorized burning — `S_after == S_before` is only valid for blocks with no mint or burn events. |
| **3rd** | **H0-9 — Test harness repair** | Restore reliable large-transaction testing (needed for DIS-003D/E). Can run in parallel with H0-5 since it is a harness infrastructure problem, not a protocol change. |

**H0-5 acceptance criteria (Qattice 4-node, Chain Forge atomicity gate):**

1. **Mid-tx failure:** Force a failure after an earlier state mutation; verify none of that tx's intended state changes persist anywhere in the state store.
2. **Balance protection:** Failed transfers, treasury operations, and fee sponsorship must not leave partial debits or credits on any account.
3. **Identity protection:** Failed account-key rotation or recovery must not modify authorized keys, policy generations, or identity state.
4. **Nonce and fee semantics:** Verify the distinction between a *rejected* tx (never included in a block — nonce not consumed) and an *included-but-failed* tx (in the block, nonce consumed, fee charged, zero other state changes). Both cases must be tested.
5. **Cross-node determinism:** All four validators agree on the final state root after the adversarial tx sequence.
6. **Restart persistence:** Restart all four nodes; verify no partial mutation reappears from disk.

### Exit Criteria

| # | Domain | Invariant / Test required | Status |
|---|--------|--------------------------|--------|
| H0-1 | Consensus safety | No two nodes finalize conflicting blocks at the same height under any validator failure pattern within f=1 | 🔲 |
| H0-2 | State determinism | All nodes produce identical state roots after processing the same tx sequence regardless of arrival order | 🔲 |
| H0-3 | Crash recovery | Node state is consistent with the canonical chain after an unclean shutdown at any block height | 🔲 |
| H0-4 | Nonce / replay | Nonce wrap-around and duplicate txs across blocks are rejected with zero partial state change | 🔲 |
| H0-5 | Execution rollback | A tx that fails mid-execution or runs out of gas applies zero state changes — full rollback, not partial | 🔲 |
| H0-6 | Key binding race | Two txs in the same block cannot both successfully bind a key to the same account | 🔲 |
| H0-7 | Supply invariant | No tx sequence increases total uQCB supply; `treasury + burn + validator_rewards = fees_collected` per block, verified end-to-end | 🔲 |
| H0-8 | Chain-ID isolation | A committed block from chain A cannot be replayed against chain B even with matching height and validator set | 🔲 |
| H0-9 | DIS-003D harness fix | `dis_003d_expiry_live` passes locally on Windows/MINGW64 — fix `submit_tx` returning null for ~77 KB recovery tx bodies | 🔴 Blocked (see DIS-003D entry in Phase 1) |
| H0-10 | DIS-003E completion | Recovery timelock and cancellation (`CancelRecovery`, pending sweep) confirmed locally on Windows/MINGW64 | 🔲 Blocked on H0-9 |
| H0-11 | Validator eviction | Product decision on eviction policy recorded (are genesis validators exempt forever or swept on first outbid?); decision implemented and tested | 🔲 |
| H0-12 | Governance quorum | >3% turnout for ordinary votes, >6% for constitutional changes — implemented, wired to `VoteOnProposal`, and adversarially tested | 🔲 |

### Protocol Blockers

The following open items in Phase 0.5 block specific Phase 1 milestones. Phase 1 work that does **not** touch these subsystems may continue in parallel.

| Blocker | Blocks |
|---|---|
| H0-9 / H0-10 — DIS-003D/E confirmation | DIS-003E, QCB-KR-001 multisig key lifecycle |
| H0-5 — Execution rollback guarantee | FeeSponsor live authorization (FS-03 follow-on); any multi-step tx type |
| H0-11 — Validator eviction decision | Validator Onboarding section marked complete |
| H0-12 — Governance quorum | `ProposeChange` / `VoteOnProposal` / `ActivateChange` in any production tx flow |

### What Is NOT in Scope for Phase 0.5

- ZK block proving (QCB-ZKP-001) — long-horizon research, independent of foundation hardening
- EVM precompile layer — Phase 5+
- Libp2p PQ transport (CS-001-L3) — follows upstream
- QSWIP standard — proposed, not protocol-blocking

### Relationship to Phase 0

Phase 0 milestones remain closed. Phase 0.5 adds adversarial coverage on top of the cooperative devnet acceptance tests already confirmed in Phase 0. Nothing is reopened; the completed work is the baseline that Phase 0.5 tests against.

---

## Phase 1 — Personhood-Weighted BFT + Resource Market Foundation

**Goal**: Consensus power tied to verified human identity, not raw stake. Resource market hardened with provider reputation, dispute resolution skeleton, and multi-provider discovery. Charmed Agent identity/budget primitive live.

**Prerequisite**: Phase 0 complete — includes cross-machine resource purchase acceptance test passing.

### Digital Identity Stone (DIS) — Account Security and Recovery

> On-chain protocol milestones for Qattice account key lifecycle, guardian-based recovery,
> and recovery security hardening. These are distinct from the standalone DIS protocol
> (see the *DIS Standalone Product* section above), which targets vendor-independent identity
> across multiple systems. These milestones prove the account security properties of the
> Qattice chain itself, independent of any wallet or vendor integration.

| Milestone | Status | Acceptance summary |
|---|---|---|
| **DIS-002A — Authenticated Account Key Rotation** | ✅ Complete (2026-10-25) | 9 live acceptance cases confirmed on Windows/MINGW64 (`dis_002a_key_rotation_live`): rotation succeeds; address/nonce/balance unchanged; old key rejected; new key accepted; replay rejected; stale key_version rejected; unauthorized rotation rejected; invalid PoP rejected; 4-node state root convergence `4113853e…`. Branch: `feature/dis-002a-key-rotation`. |
| **DIS-002B — Identity Continuity, Device Migration, and Recovery** | ✅ Complete (2026-10-26) | 13 live acceptance cases confirmed on Windows/MINGW64 (`dis_002b_migration_live` + `dis_002b_recovery_live`): Path 1 (authorized migration, B-01..B-08) — key rotation, identity unchanged, old key rejected, replay rejected; Path 2 (lost-device recovery, B-09..B-13) — 2-of-3 guardian threshold, below-threshold rejected, forged guardian rejected, restart persistence, 4-node convergence. Branch: `feature/dis-002b-identity-continuity`. |
| **DIS-003A — Recovery-Policy Lifecycle Security** | ✅ Complete (2026-10-26) | 8 live acceptance cases confirmed on Windows/MINGW64 (`dis_003a_policy_lifecycle_live`, 38.72 s): `policy_id` counter prevents guardian-sig replay across policy generations; `RevokeRecoveryPolicy` clears policy with monotone generation counter; 4-node convergence `97255bd9…`. |
| **DIS-003B — Guardian Policy Updates and Compromise Resistance** | ✅ Complete (2026-10-26) | 9 live acceptance cases confirmed on Windows/MINGW64 (`dis_003b_guardian_update_live`, 37.88 s): `UpdateGuardianPolicy` replaces guardian set, increments generation; removed guardian rejected post-update; `policy_generation=4` survived 4-node full restart; convergence `3d49fa98…`. |
| **DIS-003C — Cross-Chain / Cross-Account Replay Protection** | ✅ Complete (2026-10-26) | 8 live acceptance cases confirmed on Windows/MINGW64 (`dis_003c_replay_attack_live`, 42.74 s): guardian sigs and PoP bound to `(chain_id, account, key_version, new_pk)` tuple; cross-chain, cross-account, stale key_version, wrong-pk, and wrong-PoP attacks all rejected; 4-node convergence `b86fb2e9…`. |
| **DIS-003D — Recovery Authorization Expiry** | 🔴 Blocked — test harness bug | `expires_at_height: Option<u64>` in `GuardianAuth`; executor logic complete and verified in sandbox. **Local test (`dis_003d_expiry_live`) currently fails with a test-harness infrastructure issue, not a protocol bug.** Root cause under investigation: `submit_tx` returns `null` for the F-01 recovery tx (the enroll tx immediately before it succeeds). Two causes fixed so far — wrong `key_version` in F-01 (`nonce+1` instead of `account.key_version+1`) and `http_raw` read timeout too short (3 s → 15 s) — but `submit_tx` still returns `null`. Likely cause: the ~77 KB recovery tx body (ML-DSA guardian signatures + PoP serialised as JSON arrays of integers) exceeds what the raw TCP+HTTP/1.0 client in the test harness can write or the node can receive in one shot on Windows/MINGW64. **Needs:** diagnose whether `write_all` fails, whether the node HTTP server has a body-size limit, or whether the harness needs chunked writes / a larger send buffer. Protocol implementation (`execute_recover_account_key`, expiry guard, signing domain) is not in question. Branch: `feature/dis-003-recovery-security`. Commits: `91bec73` (impl), `e5f9dbb` (kv fix), `02cdbde` (timeout). |
| **DIS-003E — Recovery Timelock and Cancellation** | 🔲 Pending | Two-phase commit: `PendingRecovery` state, `CancelRecovery` tx, block-finalisation sweep. Blocked on DIS-003D local confirmation. |

### Validator Onboarding — Permissionless Entry via Stake Bond

> **Design decision (October 2026)**: Qattice mainnet should attract validators, not gatekeep them. The onboarding model is stake-based and permissionless — anyone who bonds the minimum uQCB can join the active validator set. No whitelist, no committee approval. Existing slashing (liveness + equivocation) is the Sybil defense.

| Item | Status | Notes |
|------|--------|-------|
| `BondValidator` tx type | ✅ | Shipped on `phase1-validator-onboarding` (`3862d60`). Locks uQCB into a per-validator virtual account (`validator-bond:{addr}`); bonding is incremental and accumulates across calls. |
| `UnbondValidator` tx type | ✅ | Shipped (`3862d60`). Moves the full bond into `validator-unbonding:{addr}` with `unlock_epoch = current_epoch + cooldown`; stake stops counting toward the active set immediately. Double-sweep and slash-and-run (re-unbonding mid-cooldown) both rejected. |
| Minimum bond threshold | ✅ | `DEFAULT_MIN_BOND_UQCB = 1_000_000` uqcb, a constant in `validator_bond.rs`. Not yet promoted to a genesis config field — explicitly deferred, not blocking. |
| Maximum active validator set size | ✅ | `DEFAULT_MAX_ACTIVE_VALIDATORS = 150`, same basis as above. |
| Stake-ranked validator set at epoch boundary (entry) | ✅ | Shipped (`99fb3ce`). `compute_stake_active_set()` reads the live bonded-stake ledger from `StateStore`; `chain-forge-node` admits newly-qualifying addresses into the live `ValidatorSet` at each epoch boundary ("Integration Point 4"). |
| Stake-ranked validator set at epoch boundary (exit/eviction) | 🔲 | **Not implemented — explicitly out of scope.** Entry admits candidates but never evicts a seated validator whose stake later drops below minimum or is outranked. Blocked on an explicit product decision (are genesis/synthetic validators exempt forever, or swept on first outbid?) that has not been authorized; do not implement without that decision. |
| Unbonding cooldown enforcement | ✅ | `DEFAULT_UNBONDING_COOLDOWN_EPOCHS = 21`, enforced via `identity.clock.current_epoch` in `execute_tx_with_identity()`. Slashing-during-cooldown is not separately implemented — unbonding stake sits untouched by the slashing module. |
| Mandatory registered consensus keys at genesis | ✅ | Shipped (`fa215d0`). `GenesisConfig::validate_validator_keys()` hard-rejects any genesis `role=="validator"` account missing a valid ≥32-byte hex public key; enforced at `Node::new_with_config` startup, not just a warning. All 4 real genesis files (`genesis-3node.json`, `genesis-4node.json`, and both under `tests/devnet/`) already carry keys for every validator. 6 `chain-forge-core` tests. |
| **Mandatory authenticated consensus keys for post-genesis validators (CF-VAL-KEY-002)** | ✅ | Shipped (`ef1b363`, branch `phase1-validator-onboarding`). Eliminates the unsigned-vote acceptance vulnerability affecting validators admitted after genesis via `BondValidator`. **Root cause:** `BondValidator` never carried a consensus key; `build_validator_set()` hardcoded `public_key: vec![]` for every non-genesis validator; `gate_voting_power()` overwrote (not masked) `voting_power = 0` in place, making post-genesis validators permanently stuck at zero power even after later qualifying; and restart reconstructed the `ValidatorSet` via `build_validator_set()` which omitted bonded validators entirely. **Fixes:** (1) `TxBody::RegisterValidatorKey { consensus_pubkey, proof_of_possession }` — two-factor auth: outer tx unconditionally signed by the validator's bonded address (via `verify_authorization_for`, bypassing optional-signature setting) plus a proof-of-possession signature over `validator_key_registration_signing_bytes(chain_id, sender)`, verified against the claimed key; (2) `ValidatorRegistry::register_consensus_key()` — duplicate-protected, blocks replacement without unbonding; (3) live `ValidatorSet` persisted verbatim to `live_validator_set.json` every commit and restored directly at restart — `build_validator_set()` removed from the restart path; (4) `TendermintEngine::reset_to_height()` applies `gate_voting_power()` on the restored set; (5) per-block key/personhood/voting-power refresh on both `commit_block` and `propose_block` paths; voting-power restoration when both gates clear corrects the destruction-not-masking gap. 23 regression tests across 4 crates; CF-DEVNET-VAL-002 5-test suite: PASS. **Windows/MINGW64 confirmed 2026-10-31: 5/5 ok (124 s).** |
| Deterministic block-height validator-set epochs | ✅ | Shipped (`61436a9`). Replaced `IdentityStore::advance_epoch(now_ms)` (wall-clock-driven, divergence-prone across nodes) with `advance_epoch_to(height / validator_epoch_blocks)` on both commit paths — same epoch number on every node from the same block sequence, independent of wall-clock skew. Verified by `validator_epoch_and_admission_converge_identically_across_nodes` (two independently-constructed nodes with a real 50ms clock offset reach identical epoch + validator-set state). |
| Historical validator-set preservation for certificate verification | ✅ | Shipped (`61436a9`). `historical_validator_sets: BTreeMap<height, ValidatorSet>` snapshots the set that actually produced each height's certificate, persisted to disk; `Node::verify_certificate_against_history(cert)` verifies a cert against the set effective at `cert.height`, not whatever is live now. Verified by `verify_certificate_against_history_uses_set_effective_at_height_not_live_set`. Exposed as infrastructure; not yet called from a production code path (the one live sync site, `GossipTopic::SyncResponse`, only ever requests the immediate next height, where the live set is still the effective one) — available for light-client / out-of-order verification use when needed. |
| Validator commission rate | ⬜ | Validators take a configurable % of PoCD research rewards routed through their node |
| Validator self-service docs | ⬜ | Operator guide: keygen → bond → run node → monitor → unbond |

> **Relationship to personhood weighting**: Stake determines who is in the active set; personhood cap determines how much influence any one human can accumulate within that set. Both constraints apply simultaneously — enforced in code, not just in this doc's framing (see below).

### Consensus — Personhood Weighting

| Item | Status | Notes |
|------|--------|-------|
| Unconditional voting-power gate across all three engines | ✅ | Shipped (`fddcfa6`). `gate_voting_power()` zeroes voting power for any validator missing a registered public key or `pop_verified=true` — unconditional, not dependent on whether `PersonhoodConfig` is even set. Wired into `FbaEngine`, `TendermintEngine`, and `HotStuffEngine`'s `update_validator_set()`, always applied last. `TendermintEngine` previously had no such gating on write; that gap is closed. 66 `chain-forge-consensus` tests pass. |
| `ValidatorInfo.pop_verified` gating in consensus | ✅ | Only verified-identity validators carry non-zero voting power (see gate above); genesis validators are seeded through a documented bootstrap attestation path (`PopAttestation::genesis` + `verify_identity`, `Node::new_with_config`) — a real identity record, not a bypass of the requirement. |
| Mandatory personhood for ALL validators, including genesis | ✅ | Shipped (`fa215d0`), staged as a coordinated migration rather than an immediate break. Node startup now hard-refuses to boot if the genesis set has zero eligible (`voting_power > 0`) validators, and warns if some-but-not-all are eligible or eligible count < 4 (BFT has zero fault tolerance below that regardless of nominal set size). |
| Stake → influence cap enforcement | ✅ | Stake (via `BondValidator`/admission) determines who is seated and ranked; personhood verification (via the gate above) determines whether that seat carries any voting power. A newly-bonded, unverified entrant is seated with `voting_power == 0` until `IdentityStore` marks it verified — confirmed by `bonded_stake_admits_new_validator_candidate_at_epoch_boundary`. |
| Validator liveness under partial-participation (Open Q14) | ❓ | How does finality behave if large fraction of verified humans go offline? |
| Governance quorum floor enforcement | ⬜ | >3% turnout for ordinary votes; >6% for constitutional (derived from §6.6) |

| **QPC-CONS-001 — Personhood-to-Consensus Integration** (PRs #10, #11) | ✅ Fully complete (2026-10-24) | **Shipped:** (1) `confirm_pop()` rejects any `VerificationTier` where `!grants_consensus()` (`ValidatorError::IneligibleTier`) — the registry boundary is now a hard gate, not a trusted-caller convention; (2) `consensus_power()` requires an eligible stored tier — `Active + pop_verified + Provisional tier → 0`, defense-in-depth against corrupt persisted state; (3) `build_validator_set()` filters ineligible-tier validators entirely from the candidate set; (4) epoch-boundary sweep (`propose_block` Integration Point 3) revokes any validator whose owner identity no longer satisfies `grants_consensus()`, confirmed by four node-level integration tests. **All three acceptance criteria closed (AV, AV2, AV3):** full production onboarding + revocation path, plus demonstration that an actively-voting validator (registered key, voting_power > 0) loses quorum authority immediately on the block after `RevokeAttestation`. **216 node unit tests, 5 node integration tests.** |
| QPC-CONS-001-AV — End-to-end revocation lifecycle (identity path) | ✅ Complete (2026-10-24) | `revoke_attestation_tx_triggers_epoch_boundary_validator_exclusion` in `chain-forge-node/src/node.rs`. Covers: real `RegisterIdentity` + 3 `Attest` txs → `Verified (verified_via_wot=true)`; real `RevokeAttestation` → `tier_downgraded=true`; epoch-boundary sweep → `pop_verified=false`, `Candidate`, `consensus_power()=0`; restart recovery. **Gap:** Phase B uses direct registry setup (`register_genesis_validator` + `confirm_pop`) rather than the production `BondValidator + owner_identity_id` path. Superseded by QPC-CONS-001-AV2. |
| QPC-CONS-001-AV2 — End-to-end production validator-onboarding + revocation path | ✅ Complete (2026-10-24) | `bond_validator_owner_binding_revocation_excludes_validator` in `chain-forge-node/src/node.rs`. Full production path, zero manual registry setup: `RegisterIdentity` + 3 `Attest` txs → `Verified`; `BondValidator { owner_identity_id: Some(...) }` → `bond_validator_owner_binding` event → `bond_owner_bindings` recorded; epoch boundary → validator admitted to consensus set via `compute_stake_active_set` + `register_bonded_validator`; pop_verified refresh via `bond_owner_bindings` lookup → `pop_verified=true`; `RevokeAttestation` → `Provisional`; next epoch sweep → `pop_verified=false`, `Candidate`; restart → `rebuild_bond_owner_bindings` from persisted `StateStore` → revocation survives. **Scope note:** Eve is admitted with `voting_power=0` because `gate_voting_power()` correctly zeros power until `RegisterValidatorKey` is submitted (a separate tx). The test therefore demonstrates eligibility tracking and revocation but not revocation of an *actively-voting* validator. See QPC-CONS-001-AV3 for that property. |
| QPC-CONS-001-AV3 — Revocation of an actively-voting validator (key registered, power > 0) | ✅ Complete (2026-10-24) | `revocation_zeros_voting_power_for_keyed_active_validator` in `chain-forge-node/src/node.rs`. Full actively-voting revocation path: `RegisterIdentity` + 3 `Attest` → `Verified`; `BondValidator { owner_identity_id }` → epoch admission; `RegisterValidatorKey` → `voting_power > 0` and consensus key registered in the same block; prevote from Eve is ACCEPTED by `receive_vote`; `RevokeAttestation` → `Provisional`; next block's ValidatorSet refresh → `pop_verified=false`, `voting_power=0` (gate_voting_power); subsequent prevote from Eve is REJECTED by `receive_vote`; next epoch sweep → `pop_verified=false`, `Candidate`, `consensus_power()=0` in the registry; restart → revocation survives. **216 node unit tests pass.** |

**Evidence for the rows above (2026-10-19, `main` at `966a130`):** `cargo build --workspace` clean. `chain-forge-core` 27/27, `chain-forge-identity` 65/65, `chain-forge-consensus` 67/67, `chain-forge-execution` 106/106, `chain-forge-validators` 35/35, `chain-forge-node` (unit + in-process integration) 85/85, `adversarial_gossip` 3/3 — all pass. Three new identity unit tests added in `71d53df`: INV-8 serde round-trip (epoch cap survives serialize/deserialize), IP-2 duplicate-attestation dedup (AlreadyAttested at execution), S3 cooldown boundary (rejected at revocation epoch, accepted at first valid epoch). **IP-2 live devnet test (2026-10-19, height ~293):** Fresh address funded from Alice, registered as Provisional, Alice attested (tx `1499decd` — `success=true`); second identical Alice→claimant attest (tx `14a1215c`) returned `success=false, error="attester qcb1alice has already vouched for this claimant"` — `AlreadyAttested` guard confirmed at block execution in the live 3-node devnet. 4-node devnet restart-recovery (`tests/devnet/test7-restart-recovery-local.sh`): PASS — chain reached height 5, Alice+Bob killed and restarted from disk (resumed at height 5 from `live_validator_set.json`, not 0), chain advanced to height 7. Integration tests `devnet_4node_reaches_target_height` / `devnet_4node_partition_recovery`: fail in this sandbox (nodes never reach height 3 in 30s) — traced to non-routable P2P addresses in this container's network namespace (peers "discover" each other but real TCP gossip can't complete), not a validator-onboarding regression; pre-existing per commit `61436a9`'s own test run. `attestation_live::attestation_guard_live`: **fixed in PR #40 (2026-10-31, Windows-confirmed).** Root cause: Attest executed before RegisterIdentity committed (ordering race), not a nonce-ordering bug. The duplicate-attest guard (`AlreadyAttested`) was masked because the first Attest failed with `NotFound` and the identity write was rolled back. Fix: pre-Attest wait for `registered=true` on all 4 nodes; post-Attest `attestation_count>=1` assertion closes the gap. KNOWN_ISSUES §4 is now resolved end-to-end.

### Identity — Charm Confinement

| Item | Status | Notes |
|------|--------|-------|
| Charm Confinement (`chain-forge-identity` extension) | ⬜ | Identity-scoped state isolation; one claim per epoch |
| Intrinsic Charm module | ⬜ | Verification tier intrinsic to identity; **note: decay-exemption credits removed** — demurrage is out of QRC v3, so decay-exemption credits have no referent; drop this concept |

### Cryptographic Security Hardening

> These are **Chain Forge modules** first — reusable by any sovereign chain built on Chain Forge. Qattice is the first chain to enable and adversarially test them, exactly as with PoCD. Future chains can adopt cryptographic-agility and key-lifecycle capabilities independently of Qattice's QRC economy or personhood rules.
>
> **Implementation order:** QCB-CS-001 first (defines the migration architecture); QCB-DIS-001 Phase A builds the wallet on top of that architecture; QCB-KR-001 implements account-level and multisig key management; QCB-PM-001 adds zero-knowledge identity privacy as a separate research layer.  
> **Completion rule:** No milestone is ✅ until implementation **and** adversarial tests pass.

**Post-Quantum Security Roadmap summary:**

| Milestone | Technology | Status |
|---|---|---|
| **QCB-CS-001** | Cryptographic Survivability and Migration | 🔄 P1+P2+P3 complete; P4 tracked |
| **PQ-VAL-001** | ML-DSA-65 validator-key registration + PoP | ✅ Merged to main (PR #2) |
| **PQ-VAL-002** | ML-DSA-65 consensus activation + EDA | ✅ Merged to main (PR #4) |
| **PQ-VAL-003** | ML-DSA-65 key rotation/revocation lifecycle | ✅ Merged to main (PR #5) |
| **QCB-ZKP-001** | ZK Block Proving — Hash-Based STARKs | 🔲 Research / long-horizon |
| **QCB-DIS-001** | Digital Identity Stone — Native QCB Wallet | ✅ Phase A + B + DIS-001-13 live test complete |
| **QCB-KR-001** | Post-Quantum Multisig and Key Lifecycle | ⬜ Phase 1 |
| **QCB-PM-001** | Private Post-Quantum Threshold Authorization | ❓ Research |
| **QSWIP-001** | Open Post-Quantum Wallet Identity Protocol | 🔲 Proposed standard |

#### QCB-CS-001 — Cryptographic Survivability and Migration

*Goal: Ensure Qattice can safely migrate to different cryptographic algorithms if an existing algorithm becomes vulnerable to AI-assisted cryptanalysis, quantum computing, or other attacks.*

**Branch:** `security/cs-001-crypto-hardening` | **Full inventory:** `docs/security/QCB-CS-001-crypto-inventory.md`

**Completed (2026-10-17) — branch `security/cs-001-crypto-hardening`:**
- ✅ **CS-001-H1** — Scheme-versioned address derivation: `AddressScheme` enum; `qcb1pq{hex}` namespace for PQ keys; classical addresses remain `qcb1{hex}`. All derivation sites delegate to `Address::from_public_key_schemed()`.
- ✅ **CS-001-H2** — `sig_scheme: Option<SchemeId>` on `Transaction`; signer stamps it, verifier dispatches explicitly; legacy `None` falls back to prefix scan. Enables live algorithm migration without hard fork.
- ✅ **CS-001-M1** — `MLDSA_TX_DOMAIN_V1` and `ED25519_TX_DOMAIN_V1` as `pub const` in `chain-forge-crypto`. Single authoritative source for signing domain separation.
- ✅ **CS-001-M2** — `mldsa_tx_prehash(chain_id, body_json) -> [u8; 32]` helper. Replaced 5 independent inline SHA-256 signing blocks across execution, wallet, scheduler.
- ✅ **CS-001-L1** — `chain-forge-qrc/pocd_reward.rs` claim_id derivation routes through `ChainHash` (SHA-3-256); raw `sha2` dep removed from that crate.

**Branch:** `security/cs-001-crypto-hardening` | **Full inventory:** `docs/security/QCB-CS-001-crypto-inventory.md`

**Completed this branch (2026-10-17):**
- ✅ **CS-001-H1** — Scheme-versioned address derivation: `AddressScheme` enum in core; `qcb1pq{hex}` namespace for PQ keys; classical addresses remain `qcb1{hex}`. All derivation sites delegate to `Address::from_public_key_schemed()`. Eliminates double-SHA-256 address derivation.
- ✅ **CS-001-H2** — Versioned `sig_scheme: Option<SchemeId>` field on `Transaction`; signer stamps it, verifier dispatches explicitly; legacy `None` falls back to prefix scan. Enables live algorithm migration without hard fork.
- ✅ **CS-001-M1** — `MLDSA_TX_DOMAIN_V1` and `ED25519_TX_DOMAIN_V1` as `pub const` in `chain-forge-crypto`. Single authoritative source; eliminates risk of divergence between signers and verifiers.
- ✅ **CS-001-M2** — `mldsa_tx_prehash(chain_id, body_json) -> [u8; 32]` helper. Replaced 5 independent inline SHA-256 signing blocks across execution, wallet, scheduler. Upgrade to SHA3-256 is a one-line change + domain version bump.
- ✅ **CS-001-L1** — `chain-forge-qrc/pocd_reward.rs` claim_id derivation routes through `ChainHash` (SHA-3-256); raw `sha2` dep removed from that crate.

| Requirement | Status | Notes |
|---|---|---|
| Complete cryptographic dependency inventory | ✅ | `docs/security/QCB-CS-001-crypto-inventory.md` — 14 crates audited |
| Scheme-versioned address derivation (CS-001-H1) | ✅ | `qcb1pq` namespace for PQ; `qcb1` for classical; breaking devnet change, intentional |
| Versioned signature scheme tag on all transactions (CS-001-H2) | ✅ | `sig_scheme: Option<SchemeId>` — live migration path now exists without hard fork |
| Canonical domain constants + pre-hash helper (CS-001-M1/M2) | ✅ | `MLDSA_TX_DOMAIN_V1`, `mldsa_tx_prehash()` in `chain-forge-crypto`; 5 inline blocks replaced |
| Route non-signing hash sites through `ChainHash` (CS-001-L1) | ✅ | `pocd_reward.rs` claim_id now uses SHA-3-256 via `ChainHash` |
| BLS12-381 / Groth16 ZK migration (CS-001-L2) | 🔲 | Superseded by QCB-ZKP-001 (hash-based STARKs preferred); long-horizon (10–15 yr) |
| libp2p PQ transport (CS-001-L3) | 🔲 | Follow upstream libp2p NIST PQC adoption; ephemeral key, not on-chain |
| Safe cryptographic migration procedures | ✅ | `CryptoMigrationState` persisted in `StateStore::metadata`; grace window + hard cutoff enforced by consensus |
| Emergency algorithm-deprecation governance tx | ✅ | `EmergencyDeprecateAlgorithm` TxBody variant; `crypto_governors` constitutional keyholder set; fail-closed semantics |
| Simulated cryptographic compromise tests | ✅ | 9 CS-001 P4 tests including full adversarial CRQC-emergency migration sequence |
| Independent security review | 🔲 | Prerequisite: migration procedures + adversarial tests pass; external review before mainnet |

---

#### PQ-VAL Series — Post-Quantum Validator Key Lifecycle ✅ COMPLETE

*Goal: Harden the validator set against quantum adversaries — mandatory ML-DSA-65 keys, post-quantum consensus signature verification, and a full key rotation/revocation lifecycle with proof-of-possession replay protection.*

> All three milestones merged to `main` (2026-10-18). Specs in `docs/pq-val-00{1,2,3}-spec.md`.

| Milestone | Branch | PR | Status | Requirements covered |
|---|---|---|---|---|
| **PQ-VAL-001** — ML-DSA-65 key registration + PoP | `feat/pq-val-001-mldsa-key-registration` | #2 | ✅ Merged | Mandatory validator-key enforcement; proof-of-possession binding; personhood gating; signature verification |
| **PQ-VAL-001b** — BFT performance benchmark | `feat/pq-val-001b-benchmarks` | #3 | ✅ Merged | ML-DSA signing/verification throughput at BFT scale; all phases pass |
| **PQ-VAL-002** — ML-DSA-65 consensus activation + EDA | `feat/pq-val-002-mldsa-consensus-activation` | #4 | ✅ Merged | `ActivatePqConsensus` tx type (R1); `Vote.scheme` field (R2); `consensus_precommit_signing_bytes()` (R2); 14/14 acceptance tests |
| **PQ-VAL-003** — Key rotation/revocation lifecycle | `feat/pq-val-003-key-rotation-revocation` | #5 | ✅ Merged | R1 (ML-DSA→new ML-DSA); R2 (ML-DSA→classical downgrade with scheme update); R3 (duplicate-key blocked); R4 (PoP replay blocked); R5 (vote rejected after rotation); R6 (power zeroed at rotation block, restored next block); R7 (released key reusable by different validator); 10/10 tests |

**Invariants upheld across all three milestones:**
- Validator-key enforcement is mandatory and cannot be weakened — `gate_voting_power()` zeroes power for any validator missing a registered key or `pop_verified=true`
- Personhood gating is unconditional across all three BFT engines (Tendermint, HotStuff, FBA)
- Key rotation uses `register_consensus_key_with_scheme()` on both `commit_block` and `propose_block` paths; first-time registrations do NOT get the R6 one-block power gap — only rotations do
- No post-quantum consensus cryptography modified (PQ migration is a separate governance tx, not an implicit side-effect of key rotation)

---

#### QCB-ZKP-001 — ZK Block Proving (Hash-Based STARKs)

*Goal: Every Qattice block carries a cryptographic proof that its execution was correct — independently verifiable by any party without re-executing the block. Proof system must be post-quantum safe by construction.*

**Motivation:** zkSync's Airbender Prime (2026) demonstrated real-time ZK block proving on a single GPU using hash-based STARKs (WHIR polynomial commitments + BLAKE2s/Keccak-256 + GKR sumcheck), achieving sub-10s proof generation for 99% of Ethereum mainnet blocks. This approach:
- Is **inherently post-quantum** — no elliptic curve pairings; security reduces to hash collision resistance
- **Supersedes the BLS12-381/Groth16 path** (CS-001-L2) — hash-based STARKs provide stronger long-term security without the quantum vulnerability of pairing-based systems
- Enables **independent verification** — a standalone verifier checks block validity without running a full node; directly supports the RedTeam suite and external auditors
- Makes **compromised execution servers unable to forge valid state transitions** — even a fully compromised node cannot produce a proof for an invalid block

**Proof system primitives (target):**

| Primitive | Role | PQ-safe? |
|---|---|---|
| Hash-based STARKs | Proof system backbone | ✅ (hash security only) |
| WHIR polynomial commitments | Fast polynomial IOP | ✅ |
| BLAKE2s / SHA-3 | Hash primitive | ✅ |
| GKR sumcheck | Efficient circuit evaluation | ✅ |
| No BN254 / BLS12-381 pairings | Eliminated | N/A — removed |

**Rust ecosystem to track:**
- [`stwo`](https://github.com/starkware-libs/stwo) — StarkWare's next-gen STARK prover (Circle STARKs, Rust)
- [`plonky3`](https://github.com/Plonky3/Plonky3) — modular STARK framework (Polygon/external, Rust)
- [`whir`](https://github.com/WizardOfMenlo/whir) — WHIR polynomial commitment reference implementation

**Implementation phases:**

| Phase | Scope | Status |
|---|---|---|
| Research | Track `stwo` / `plonky3` maturity; define Qattice execution circuit formally | 🔲 Ongoing |
| Circuit design | Formalize what "valid Qattice block" means as an arithmetic circuit over `chain-forge-execution` output | 🔲 After execution stabilizes |
| Prover integration | Wire STARK prover to block production in `chain-forge-scheduler` | 🔲 12–24 months |
| Verifier | Standalone block verifier; integrate into `chain-forge-consensus` and RedTeam suite | 🔲 |
| Real-time proving | Single-GPU target (RTX class); benchmark against Airbender Prime baseline | 🔲 Long-horizon |

**Prerequisites:** `chain-forge-execution` state model stable; CS-001-H1/H2 merged to main (execution circuit must reflect versioned signature scheme).

#### QCB-DIS-001 — Digital Identity Stone (QCB Native Wallet)

*Goal: A scannable, post-quantum authentication protocol that lets users access Qattice services without exposing private keys. The QR code is the doorway, not the key.*

**Core architectural principles:**
1. Private keys never leave the wallet — transactions are signed locally using ML-DSA.
2. Scannable authentication — temporary QR challenges provide secure access without exposing signing secrets.
3. Privacy-preserving identity — applications receive only the authorization or identity information they require.
4. Post-quantum multisig — multiple owners can securely authorize treasury operations.
5. Cryptographic adaptability — Qattice can migrate to new algorithms if existing cryptography becomes vulnerable.
6. Network-wide security — post-quantum protections extend beyond wallets to validators and other critical authorization paths.
7. Open-standard ambitions — QSWIP can eventually provide reusable security specifications for other Chain Forge chains.

**Authentication flow:**
```
User opens Qattice app → QR challenge displayed
  → User scans with Qattice wallet on phone
  → Wallet signs challenge using ML-DSA
  → Service verifies signature → grants access
  (Private key never leaves device; QR expires after use)
```

**Privacy guarantee** (plain ML-DSA limitation noted): ordinary ML-DSA signatures do not automatically hide the signing public key. If a service must learn only that *a* valid identity authorized a request — without identifying *which* identity — a zero-knowledge credential layer is required. That is QCB-PM-001.

| Phase | Scope | Status |
|-------|-------|--------|
| A — Digital identity and authentication | ML-DSA wallet identity, temporary QR challenges, signature verification | ✅ Complete |
| B — Security hardening (DIS-001 Phase B) | Chain-ID binding in ML-DSA sigs, nonce/balance/gas enforcement, restart+replay persistence, 4-node finality | ✅ Complete |
| B-Live — DIS-001-13 live authentication acceptance test | End-to-end proof of key-binding, scope-authorization, freeze semantics, and restart reconstruction on real 4-node devnet | ✅ Complete (2026-10-19) |
| B-Android — DIS Android wallet (Galaxy A15) | Rust DIS Core cross-compiled to ARM64 via JNI; Kotlin wallet app; ML-DSA-65 signing on real device; QR scan-to-sign | ✅ Complete (2026-10-20) |
| B-Android-2 — Persistent key storage | Android Keystore-backed key persistence; keys survive app restarts | ✅ Complete (2026-10-20) |
| B-Android-3 — Vendor server | Rust HTTP server issues challenges and verifies DIS proofs; full phone-to-server auth | ✅ Complete (2026-10-20) |
| B-Android-4 — GitHub Actions APK builder | Auto-builds and publishes APK on every push to dis-wallet-android/ or dis-core/ | ✅ Complete (2026-10-20) |
| B-Android-5 — Licensing | Apache 2.0 for dis-core; BSL 1.1 for Android SDK and vendor server; commercial licensing info | ✅ Complete (2026-10-20) |
| B-Security — DIS-SEC-002 | Authenticated enrollment, protected sessions, vendor identity isolation, authorization hardening | ✅ Complete (2026-10-21) |
| B-Security — DIS-SEC-003 | Adversarial testing — 8/8 attack scenarios rejected; enrollment replay, key replacement, cross-vendor substitution, concurrent replay | ✅ Complete (2026-10-21) |
| C-State — DIS-STATE-001 | Persistent vendor registrations, enrolled keys, revocations, and consumed challenges across server restarts | ✅ Complete (2026-10-21) |
| C-State — DIS-STATE-002 | Revocation persistence, DB atomicity (10 concurrent → 1 accepted), crash recovery (SIGKILL) — 9/9 tests passed | ✅ Complete (2026-10-21) |
| C-State — DIS-STATE-003 | Shared PostgreSQL backend — two independent instances coordinate on challenges, revocations, and sessions; signature verified before any DB write; atomic consume+revocation-check in one `SELECT FOR UPDATE` transaction; fail-closed on DB errors — 11/11 tests passed | ✅ Complete (2026-10-21) |
| B-Security — DIS-SEC-004 | Authenticated vendor registration — registration key gates `/vendor/register`; origin-ownership proof via well-known HTTP token before any DB write; `origin_verified_at` tracks verification; unverified vendor rows cannot issue challenges — 16/16 tests passed | ✅ Complete (2026-10-21) |
| B-Security — DIS-SEC-005 | SSRF hardening for origin verification — HTTPS enforcement, URL structure validation (no path/query/fragment/credentials), internal IP blocking (loopback/RFC1918/link-local/CGNAT), redirect suppression, DNS rebinding prevention via `resolve_to_addrs` pinning, proxy bypass prevention via `.no_proxy()`, two-key test-mode acknowledgment (`DIS_ALLOW_HTTP_ORIGINS=1` + `DIS_TEST_MODE=1`) — 36/36 tests (16 unit + 20 integration) passed | ✅ Complete (2026-10-21) |
| B-Security — DIS-GAP-001/002/003 | Gap closures: (1) registration token single-use enforced via `used_registration_tokens` table + atomic transaction; (2) background challenge-row purge (every 10 min, 1 h grace for consumed rows); (3) stale `dis_state.db*` SQLite files removed, `*.db*` added to `.gitignore` | ✅ Complete (2026-10-21) |
| **B-Security — Identity Pilot Red-Team (agent8, rounds 1–7)** | 11-finding adversarial sweep against live 3-node devnet (`agent8_identity_pilot.py`). **7 CRITICAL/HIGH closed (rounds 1–6):** coordinator-only gate for `ConfirmSybil`/`ReverseSybil`; governance-only gate for `ActivatePqConsensus`; DIS delegation chain structural validation (depth, scope monotonicity, human-approval token); `attestation_coordinator` + `governance_authorities` wired through `TxPrecheck`. **Nonce regression (rounds 6–7):** `check_tx` round-5 ban on `nonce=0` created a deadlock — execution expects `nonce==state.nonce` (0 for fresh accounts) but ingress rejected it; fixed by removing the ban and reverting 4 test nonces; nonce cache moved to post-execution using committed `tx.nonce` (not `state.nonce` post-increment) to keep cache semantics consistent with API replay guard. **Round 7 result:** 1 MEDIUM finding remaining (`max_uses` not enforced — deferred to Phase C durable usage store). All identity-registration and attestation paths verified on live devnet. Commits `6eecbb7`, `cd49deb`, `928853e`, `7d7232d` (2026-10-21/22). | ✅ Complete (2026-10-22) |
| B-Privacy | Selective disclosure, service-specific pseudonyms, zero-knowledge authorization | 🔲 |
| C — Post-quantum credential storage | Encrypted credential storage using PQ key-establishment + authenticated encryption | 🔲 |
| D — Integration | Connect to Qattice wallets, personhood, Charmed Agents, enterprise authorization, private multisig | 🔲 |
| E — Security testing | QR replay, phishing, session hijacking, key compromise, identity correlation, account recovery | 🔲 |

**DIS-001-13 — Live Authentication Acceptance Test — ✅ COMPLETE (2026-10-19):**
- **Test:** `chain-forge-node/tests/dis_auth_live.rs` — 8-step end-to-end acceptance test against a real 4-node devnet; runtime ~30s; committed `c69eef3` + `6af728d`.
- **Step 1 ✅** — Two fresh ML-DSA-65 keypairs registered as Provisional identities on all 4 nodes; ML-DSA-derived `qcb1pq…` addresses pre-funded (10,000 uqcb each) from `qcb1alice` genesis account to cover 92 uqcb gas cost.
- **Step 2 ✅** — Three attestations (bob + carol + dave) satisfy `ATTESTATION_QUORUM=3`; Wallet A promoted to Verified across all nodes with BFT convergence within ~4s.
- **Step 4 ✅** — Verified wallet: `key_binding_verified=true`, `scope_authorized=true` for restricted scope `identity:attest`.
- **Step 5 ✅** — Provisional wallet (Wallet B): `key_binding_verified=false`, `scope_authorized=false` — restricted scope denied.
- **Step 6 ✅** — `ConfirmSybil` freezes Wallet A; `key_binding_verified` stays `true` (orthogonality invariant), `scope_authorized` drops to `false`.
- **Step 6.5 ✅** — `ReverseSybil` restores Wallet A; restricted auth re-enabled on all nodes.
- **Step 7 ✅** — Alice node SIGKILL + restart; `ExplorerState` reconstructs from `IdentityStore`; Wallet A auth correct post-restart (`key_binding_verified=true`, `scope_authorized=true`).
- **Step 8 ✅** — Permissionless scope (`wallet:authenticate`) authorized for both Wallet A (Verified) and Wallet B (Provisional).
- **Key fixes proved by test:** zero-balance ML-DSA addresses must be pre-funded before any tx; nonce sequencing required between back-to-back txs from the same sender; `ATTESTATION_QUORUM=3` requires 3 distinct Verified/Established attesters.

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

> **QSWIP-001 — Open Post-Quantum Wallet Identity Protocol**: Long-term open standard so other Chain Forge blockchains can reuse Qattice's wallet identity and authentication infrastructure. Proposed; timing deferred until Phase B–D of QCB-DIS-001 is battle-tested.

#### QCB-PM-001 — Private Post-Quantum Threshold Authorization

*Goal: Allow Qattice identity holders to prove they are authorized — without revealing which identity they hold — using zero-knowledge or threshold credential mechanisms.*

| Item | Status | Notes |
|---|---|---|
| ZK credential research | ❓ | Research milestone; no implementation commitment yet |
| Selective disclosure design | ❓ | What attributes a service may learn; what remains hidden |
| Service-specific pseudonyms | 🔲 | Different credential per service; unlinkable across services |
| Integration with QCB-DIS-001 Phase B | 🔲 | ZK layer added on top of Phase A authentication |

#### QCB-KR-001 — Post-Quantum Multisig Key Lifecycle

*Goal: Protect Qattice accounts, multisig treasuries, and authorized signers with secure key rotation, revocation, and recovery — without ever accidentally locking legitimate owners out of their assets.*

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

> **What this is**: A machine running a Qattice Resource Node is not required to sell capacity to commercial customers. It can contribute capacity directly to Qattice network infrastructure instead — or do both simultaneously, subject to the owner's policy.

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
| `UsefulWorkReceipt` | ⬜ | Receipt for a completed `NetworkContributionJob`; shares shape with `ResourceExecutionReceipt` (job_id, machine_id, work_type, proof, verification_status) but payer is the Qattice network contribution pool, not a customer agent; a `receipt_type` field distinguishes the two — avoid two entirely separate receipt types |
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

### Identity Pilot — Staged Vision

The ceremony today isn't a limitation — it is the honest first step of a ladder where each stage makes human involvement smaller and cryptographic proof stronger, ending with something no other chain has: post-quantum, privacy-preserving, device-native personhood that other protocols can query instead of building their own.

**Stage 1 — Bootstrap (can start now)**
- You + 2 trusted people form the genesis verified set; round-robin attest each other on a video call, then collectively verify relatives and early testers.
- Measure: time per person, friction, cost toward the <$5/human target; <3% sybil rate.

**Stage 2 — Wallet Liveness (near-term engineering)**
- Wallet generates randomized real-time challenges during the ceremony; person must respond live — proves a human is holding the device.
- Makes the ceremony harder to fake even before ZK. Built on top of the QR scan-to-sign flow already running on the Galaxy A15.

**Stage 3 — ZK Credential (QCB-PM-001, medium term)**
- Wallet produces a zero-knowledge proof: "I am a verified unique human" without revealing which human.
- No iris scan, no government ID, no hardware token. This is where Qattice leaps ahead of most competitors on privacy.

**Stage 4 — Universal Proof of Personhood (long term)**
- Other protocols query Qattice's identity layer instead of building their own.
- The chain becomes post-quantum identity infrastructure for the broader ecosystem.

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

## Qattice Grand Challenge — Long-Term Distributed Research Compute

> **What this is**: When commercial demand is absent, voluntarily contributed Qattice resources can be directed toward objectively verifiable computational challenges intended to advance cryptography, mathematics, computational efficiency, and machine-assisted discovery. This is not consensus. Personhood-anchored BFT remains solely responsible for block production and finality. The Grand Challenge and network contribution sit above consensus as productive economic and research layers.
>
> **Long-term research principle**: Qattice does not ask machines to compute meaningless hashes. When machines contribute capacity to the network, that capacity is directed toward useful, objectively verifiable work — including research challenges with real scientific or cryptographic value.
>
> **Safety boundary** (hard constraint): Discoveries never automatically change Qattice protocol behavior. Any finding that could affect protocol cryptography must pass independent expert review, formal security analysis, adversarial testing, and explicit Qattice governance approval before it influences any protocol parameter. Research and governance are entirely separate.

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
| Formal safety review gate | 🔲 | Any cryptographic finding that could affect Qattice protocol must pass: independent expert review → formal/security analysis → adversarial testing → governance vote; no automatic protocol changes |

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
| **Discovery Records** | ⬜ Design complete, implementation blocked on discovery criteria | Permanent, non-transferable on-chain records minted when a verified Grand Challenge contribution qualifies as a discovery. Defined in `chain-forge-pocd` (natural extension of `DiscoveryReceipt`, chain-agnostic); minted through the same verification path as the discovery bonus reward, not a separate module. Queryable by MachineID and SponsorID (`/api/discoveries/{machine_id}`, `/api/discoveries/by_sponsor/{sponsor_id}`); no token model, governance, or consensus change; no new verification or reward mechanism. **Blocked on**: the track-specific discovery criteria being formalized through governance — the record attaches to the discovery event, and until that event is defined (same prerequisite the discovery bonus already has), there's nothing to attach it to. Est. ~1 week engineering once criteria land, most of it the explorer UI. Whitepaper: §5.4. Phase 1 |
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

## Qattice Equilibrium State — When the Network Becomes Alive

> Equilibrium is not a launch event. It is a threshold the network crosses — gradually, over years — as machines join, attestations accumulate, and the resource market deepens. Below equilibrium, Qattice is a blockchain with a research layer. Above equilibrium, it is a trustworthy distributed supercomputer: self-sustaining, self-healing, and capable of scientific work no individual machine or centralized facility could reach.

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

Reaching Equilibrium State will take years. Bitcoin took years to harden its consensus under real adversarial conditions. Ethereum took years to reach the validator depth where its consensus felt genuinely robust. Qattice accepts the same timeline — and names it here rather than implying otherwise.

The architectural commitment is different from the timeline: Qattice is designed for equilibrium from the first block. The MachineID registry, ResourceExecutionReceipt accountability layer, Grand Challenge tracks, and hard safety boundary are not retrofits. They are load-bearing from day one, so that when the network reaches scale, the capability is already there waiting.

> No specific machine count is required for Equilibrium State. Scale is a means, not the definition. The five criteria above — not any headcount target — determine when equilibrium is reached.

---

## Phase 3 — Merchant API + BME Activation

**Goal**: Stripe-compatible payment API live; first real Qattice buyback-and-burn.

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
| RWA issuance layer | 🔲 | Tokenized assets via permissioned EVM; Qattice compliance-at-protocol-layer |
| Governance succession (post-founder) | ❓ | Open Q10 |
| Interoperability (PoP-preserving bridge only) | 🔲 | Forbidden until chain stable and identity proven; Open Q per §7.1 |
| Post-quantum verification services — external verification API | 🔲 | `POST /api/verify/credential`, `GET /api/attestation/{subject}`, `POST /api/verify/signature`; public key for verifying Qattice's own attestation signatures. Whitepaper §10.4. Contingent on the identity pilot succeeding — see §4 |
| Post-quantum verification services — attestation format & signing | 🔲 | The "Qattice Attestation" structure (subject, verification result, timestamp, chain ID), signed ML-DSA-65; once external protocols integrate, this format becomes constitutional (§7.3), not ordinary-governance-changeable |
| Post-quantum verification services — revocation propagation | 🔲 | Pull model with a documented maximum staleness window (re-query after N seconds), not push/subscription — avoids Qattice maintaining broadcast infrastructure for external integrators |
| Post-quantum verification services — integrator documentation and SDK | 🔲 | Onboarding material for other protocols integrating Models A (cross-chain identity verification), B (signature verification as a service), and C (credential issuance) |
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

11. **Personhood-weighting overlay** ✅ — per-human validator influence cap applied in the per-block `pop_verified` refresh loop on both `commit_block` and `propose_block` paths (`node.rs`). PH-OVL-001 merged to main (PR #6, commit `ccc8239`). All three BFT engines (Tendermint, HotStuff, FBA) already had the cap at `update_validator_set`/`init`; the refresh loop gap is now closed. 132/132 node tests, 67/67 consensus tests.

12. ~~**AI red-team Agent 1 (Phase A–D attestation guard bypass)**~~ ✅ **DONE (2026-10-21)** — `agent1_tx_fuzzer.py` + `agent8_identity_pilot.py` ran 6 rounds against the live 3-node devnet. All CRITICAL and HIGH ingress findings closed (coordinator auth gate, governance spam gate, DIS delegation structural validation). 4 findings deferred to Phase C (`/api/dis/verify_delegated` + `max_uses` durable store). See QCB-DIS-001 B-Security — Identity Pilot Red-Team row above.

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

28. **PoCD miner hardening + 5-track challenge upgrade** ✅ **DONE (2026-10-09)** — `scripts/pocd_miner.py` fully rewritten: real per-track deterministic computation (Fibonacci, pre-image search, matrix multiply, lattice SVP, prime sieve); multi-threaded seal mining (`--threads N`); round-robin track selection by default (`--track all`). Genesis files upgraded: 3-node devnet → 8-bit seal difficulty across all 5 tracks; 4-node devnet gets full `pocd` block + `treasury:pocd` + 5 genesis challenges for the first time. All `verification_criteria` are fully specified and independently reproducible — any verifier can recompute the expected output_hash from challenge_id alone.

29. **3-way PoCD epoch reward split — confirmed on 3-node devnet (2026-10-09)** ✅ **DONE** — All three miners (machine IDs: `qcb1devminer-alice`, `bob`, `dave`) running against Alice's node via `--machine` flag receive separate per-wallet uQCB credits at the block 720 epoch boundary. 100+ `pocd_reward distributed` log lines confirmed across all three wallets in a single epoch. Per-proof amounts: 29,259 / 36,574 / 48,765 / 60,957 / 73,148 uQCB (track-weighted). Confirmed devnet startup sequence: Alice node (no bootstrap) → Bob + Dave nodes (`--bootstrap /ip4/127.0.0.1/tcp/27000`) → all three miners pointing at Alice with distinct `--machine` flags. **Known gap**: PoCD proof pools are node-local — proofs submitted to Alice are not gossiped to Bob/Dave over P2P. See item 30 below.

30. ~~**PoCD proof pool P2P gossip**~~ ✅ **DONE (commit `93a2018`)** — `GossipTopic::DiscoveryProof` added; proofs published to libp2p gossip layer and inserted into every node's `DiscoveryRegistry` on receipt; all nodes converge to the same proof pool before the epoch boundary fires. See Change Set R above.

---

## Phase 0d — Proof of Cryptographic Discovery (PoCD) Scaffold

**Goal**: Build the reusable `chain-forge-pocd` crate so any blockchain created with Chain Forge can opt into PoCD mining.  Qattice will be the first integrator.

**Design principle**: The crate is fully chain-agnostic — no QRC, uQRC, or Qattice hardcoding.  Chains wire in their own `RewardPolicy` implementation and `PoCDConfig`.

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

### Qattice PoCD Integration (next phase)

| Item | Status | Notes |
|------|--------|-------|
| `QcbRewardPolicy` in `chain-forge-qrc` | ✅ | Pays rewards in uQRC; implements `RewardPolicy` trait; difficulty + track multipliers; pro-rata epoch pool cap; full test suite |
| Wire `PoCDConfig` into Qattice genesis | ✅ | `genesis.pocd: Option<serde_json::Value>` in `chain-forge-core`; node parses at startup into `PoCDConfig`; `pocd_registry` Arc<Mutex> wired through to API |
| PoCD API endpoints | ✅ | `GET /api/pocd/challenges`, `GET /api/pocd/receipts`, `POST /api/pocd/submit`; self-verifies seal in Phase 0; no external verifier sig required |
| First live PoCD mining round on devnet | ✅ | `scripts/phase0_pocd_test.py` — mines 4-bit seal, submits proof, verifies receipt; runs against live devnet |
| `QcbVerifier` adapter | ⬜ | Wraps identity layer + `chain-forge-resource` scientific receipt; Phase 1 |
| Wire `QcbRewardPolicy` into epoch processing | ✅ | `EpochClose` handler scans `gc_receipt:*` state for unawarded receipts, converts to `DiscoveryReceipt`, calls `QcbRewardPolicy::compute_rewards()`, debits `treasury:pocd`, credits each machine wallet; `gc_reward_paid` sentinel prevents double-payment; non-fatal failure path retries next epoch |
| **PoCD epoch reward distribution — end-to-end verified on Windows devnet (2026-10-09)** | ✅ | **Bug fix (commit `daf642b`)**: `epoch_close_seen` renamed from `epoch_close_succeeded`; PoCD rewards now fire on *presence* of `EpochClose` tx in block — decoupled from QRC `close_epoch()` success/failure. At block 720 epoch boundary: `rewarded_receipts: 8,586`, `pending_receipts: 0`. Miner wallet `qcb1devminer-alice` balance: `719,996,202 uQCB`. `treasury:pocd` debited from 50,000,000,000 → 49,280,003,798 uQCB (exact match — no double-payment, no leak). **uQCB accumulates toward QCB at 1,000,000 uQCB = 1 QCB**; miners earn uQCB, not QRC. |
| **`scripts/pocd_miner.py` — PoCD mining client confirmed (2026-10-09)** | ✅ | Python 3.8+ stdlib-only script; `--node alice/bob/dave` targets ports 8080/8081/8082; `HASH_BATCH=4096`, `MAX_SEAL_ATTEMPTS=1,000,000`, `POLL_INTERVAL=15s`; polls `/api/pocd/challenges`, mines SHA256 seals, submits proofs via `/api/pocd/submit`; 3 miners (alice/bob/dave) run clean, `failed=0`, proven hashrate ~3.6 kH/s per miner; >44,000 proofs submitted across the session |
| **`scripts/pocd_miner.py` — rewritten with real per-track computation + multi-threading (2026-10-09)** | ✅ | Old miner used `random_output_hash()` (unverifiable); replaced with 5 deterministic per-track workers: **Mathematics** (Fibonacci(n), n seeded from challenge_id, 100–200 range; SHA256 of decimal string), **Cryptography** (real hash pre-image search — find `qcb-preimage-{N}` where SHA256 starts with `0`; seeded start nonce), **ComputationalEfficiency** (16×16 integer matrix multiply A×B mod 2^31; SHA256 of diagonal checksum), **PhysicsAndOpenScience** (4-dim lattice SVP — exhaustive [-6,6]^4 coefficient search over LCG-seeded basis; verifiable by any node from challenge_id alone), **AiAssistedDiscovery** (Sieve of Eratosthenes for π(n) where n seeded to 10k–50k range). Multi-threaded seal mining: `--threads N` (default: min(cpu_count, 8)); each thread searches independent random nonce range; `queue.Queue` + `threading.Event` for coordination. CLI additions: `--threads`, `--track all` (round-robin, new default), `--node carol` (127.0.0.1:8083). Python 3.8+ stdlib-only. |
| **Genesis files upgraded — 5 challenge tracks, 8-bit difficulty (2026-10-09)** | ✅ | `tests/devnet/genesis-3node.json`: `min_seal_difficulty_bits` raised 4→8; `AiAssistedDiscovery` added to `challenge_tracks`; new `PhysicsAndOpenScience::devnet-lattice-1` challenge added; all 5 genesis challenges now have `seal_difficulty_bits: 8`; full `verification_criteria` strings (deterministic, reproducible by any verifier from challenge_id alone). `tests/devnet/genesis-4node.json`: full `pocd` block added (was absent); `treasury:pocd` genesis account added (50,000,000,000 uqcb); 5 genesis challenges added at 8-bit difficulty (Mathematics, Cryptography, ComputationalEfficiency, PhysicsAndOpenScience, AiAssistedDiscovery); `challenge_tracks` includes all 5. 4-node genesis is now PoCD-ready for testnet. |
| Migrate `chain-forge-resource` seal functions to delegate to `chain-forge-pocd` | ⬜ | Remove duplication; `UsefulWorkReceipt` becomes a wrapper |

---

## Phase 0e — PoCD Scheduler, Verifier, and External Miner

**Goal**: A production-grade PoCD pipeline that external machines can join. Dedicated scheduler distributes cryptographic challenge tasks across independent miners; independent verifiers reproduce and confirm results; `qcb-miner` binary ships as a standalone binary any operator can run.

**Design principles**:
- Scheduler, miner, and verifier are **separate binaries** — no compile-time dependency between them; all communication over HTTP.
- Two-phase cascade enforces independent machine cooperation: a single machine cannot earn both phase-1 and phase-2 rewards for the same task.
- No result is automatically classified as a cryptographic breakthrough or scientific discovery. Human review is always required.
- Consensus (BFT) is entirely unaffected by PoCD mining activity.

### Change Set L — PoCD Scheduler (`chain-forge-scheduler`) ✅ COMPLETE

| Item | Status | Notes |
|------|--------|-------|
| `chain-forge-scheduler` crate | ✅ | Standalone binary `qcb-scheduler`; workspace member |
| Task lease model | ✅ | Tasks assigned with `lease_expires_at`; expired leases reassigned; HTTP 410 on late submit |
| Two-phase cascade enforcement | ✅ | Phase-2 tasks always assigned to a different miner than phase-1 solver; scheduler enforces constraint |
| Miner registration API | ✅ | `POST /scheduler/miners/register` — `{miner_id, workload_class}` |
| Task poll API | ✅ | `GET /scheduler/miners/{id}/task?objective_id=…&workload_class=…`; HTTP 204 = no task available |
| Result submission API | ✅ | `POST /scheduler/tasks/{id}/result`; 409 = lease superseded; 410 = lease expired |
| Objective management API | ✅ | `GET /scheduler/objectives`; administrators create and manage research objectives |
| Task range assignment | ✅ | Scheduler assigns `[range_start, range_end)` nonce ranges; miners search the assigned slice |
| Result deduplication | ✅ | Duplicate result submissions rejected; idempotency preserved |
| Independent verification queue | ✅ | Accepted results queued for verifier confirmation; quorum-based acceptance |

### Change Set M — Two-Phase PoCD Protocol ✅ COMPLETE

| Item | Status | Notes |
|------|--------|-------|
| Phase-1 algorithm | ✅ | `SHA-256(seed_le64 ∥ nonce_le64)` ≥ 16 leading zero bits; content hash = `SHA-256(H1)` |
| Phase-2 algorithm | ✅ | `SHA-256(H1_bytes ∥ nonce_le64)` ≥ 8 leading zero bits; content hash = `SHA-256(H1 ∥ H2)` |
| Parent-hash chaining | ✅ | Phase-2 task carries `parent_hash` (hex-encoded H1) from phase-1 winner; scheduler supplies it |
| Cross-machine constraint | ✅ | Scheduler never assigns phase-2 to the phase-1 solver; miner binary is unaware of constraint |
| Content hash derivation | ✅ | Phase-1: `SHA-256(H1_bytes)`; Phase-2: `SHA-256(H1_bytes ∥ H2_bytes)` — combined two-machine proof |

### Change Set N — `chain-forge-miner` (`qcb-miner` binary) ✅ COMPLETE

| Item | Status | Notes |
|------|--------|-------|
| `chain-forge-miner` crate | ✅ | Workspace member; `qcb-miner` standalone binary; zero compile-time deps on other chain-forge crates |
| CLI (`clap`) | ✅ | `--node-url`, `--miner-id`, `--objective-id`, `--workload-class`, `--poll-interval-secs`, `--algorithm-version`, `--workload-version`; all flags have env var equivalents (`QCB_NODE_URL`, etc.) |
| `solve_phase1()` | ✅ | Searches `[range_start, range_end)` nonces; returns winning nonce + H1 when ≥ 16 leading zero bits found |
| `solve_phase2()` | ✅ | Decodes parent_hash hex; searches nonces; returns winning nonce + H2 when ≥ 8 leading zero bits found |
| `spawn_blocking` for CPU work | ✅ | All SHA-256 nonce search runs in `tokio::task::spawn_blocking`; async runtime never blocked |
| Event loop | ✅ | Register → poll → solve → submit → loop; `poll_interval_secs` configurable (default 5s) |
| HTTP 409 / 410 handling | ✅ | Lease superseded (409) and lease expired (410) logged as WARN and miner continues |
| `SchedulerClient` | ✅ | Thin async wrapper; 30s timeout; rustls-tls (no OpenSSL dep) |
| `MinerError` enum | ✅ | `Http`, `Scheduler`, `Deserialize`, `LeaseExpired`, `LeaseSuperseded`, `Forbidden`, `Worker` |
| 13 unit tests | ✅ | Phase-1 and phase-2 solvers; determinism; cross-miner content-hash agreement; avalanche seed derivation; hamming-distance consistency; invalid-hex parent-hash graceful None |

### Change Set N+1 — Avalanche Experiments ✅ COMPLETE

| Item | Status | Notes |
|------|--------|-------|
| `solve_avalanche()` | ✅ | Deterministic; two SHA-256 calls; no nonce search |
| Canonical seed derivation | ✅ | `SHA-256("qcb-avalanche-v1" ∥ objective_id_utf8 ∥ seed_index_le64)` |
| Bit-flip experiment | ✅ | `original_hash = SHA-256(canonical_seed)`; bit `bit_index` flipped; `flipped_hash = SHA-256(flipped_seed)` |
| XOR diff + Hamming distance | ✅ | `xor_diff = original_hash XOR flipped_hash`; `hamming_dist = popcount(xor_diff)` |
| Content hash | ✅ | `SHA-256(original_hash_bytes ∥ flipped_hash_bytes)` |
| Task dispatch | ✅ | `task_kind == "avalanche_experiment" | "avalanche_replication"` → `solve_avalanche()`; otherwise → phase-based PoCD solver |
| Avalanche test coverage | ✅ | Seed derivation determinism; hamming-distance consistency; cross-miner agreement |

### Change Set O — Consensus Vote Security Fix ✅ COMPLETE

| Item | Status | Notes |
|------|--------|-------|
| Fail-closed empty-signature guard | ✅ | Consensus votes with an empty or zero-length signature are rejected before verification attempt; previously could panic or accept; now hard-fail |
| Regression tests | ✅ | Empty-sig vote rejected at the consensus layer; existing adversarial gossip tests unaffected |

### Change Set Q — CF-VAL-KEY-002: Mandatory Authenticated Consensus Keys for Post-Genesis Validators ✅ COMPLETE (commit `ef1b363`)

| Item | Status | Notes |
|------|--------|-------|
| `TxBody::RegisterValidatorKey` tx type | ✅ | Two-factor auth: (1) outer tx unconditionally signed by the validator's bonded address via `verify_authorization_for` (forced regardless of chain's `require_signatures` setting); (2) `proof_of_possession` over domain-separated `validator_key_registration_signing_bytes(chain_id, sender)` verified against claimed `consensus_pubkey` |
| `ValidatorRegistry::register_consensus_key()` | ✅ | Duplicate-protected (same key is a no-op); blocks replacement without unbonding; `consensus_pubkey_bytes()` accessor; `build_validator_set()` reads registered keys |
| Live `ValidatorSet` persistence | ✅ | Full `ValidatorSet` serialized to `live_validator_set.json` every committed block; `load_persisted_state()` restores it directly — `build_validator_set()` removed from the restart path entirely, closing the gap where bonded validators vanished on restart |
| `TendermintEngine::reset_to_height()` gate | ✅ | Applies `gate_voting_power()` on the restored set so a validator that lost a key or personhood between shutdown and restart is still correctly gated |
| Per-block refresh + voting-power restoration | ✅ | Both `commit_block` and `propose_block` paths now refresh each validator's `pop_verified`, `public_key`, and — when both gates are satisfied and `voting_power == 0` — restore real bonded-stake voting power from the ledger, fixing the `gate_voting_power()` destruction-not-masking gap |
| 10 Phase 4 regression tests | ✅ | `chain-forge-node`: eligible-after-key, zero-power-without-key, unsigned-precommit-rejected, wrong-key-rejected, cross-node convergence, key-survives-restart, historical-set-retains-key (+ 3 previously complete) |
| Full regression suite | ✅ | `chain-forge-execution` 106/106, `chain-forge-validators` 35/35, `chain-forge-consensus` 67/67, `chain-forge-node` 85/85, `adversarial_gossip` 3/3 — no regressions vs. baseline commit `b9805b8` |
| 4-node devnet restart-recovery rerun | ✅ | `tests/devnet/test7-restart-recovery-local.sh` — chain height 5 → Alice+Bob killed → restarted from disk at height 5 (not 0) → chain advanced to height 7; PASS |

### Change Set P — Authenticated PoCD Verification (`chain-forge-verifier`, `qcb-verifier`) ✅ P1–P5 COMPLETE

| Phase | Item | Status | Notes |
|-------|------|--------|-------|
| P1 | `chain-forge-verifier` crate | ✅ | Workspace member; `qcb-verifier` binary; verifier reproduces miner hash and confirms or rejects |
| P1 | `qcb-keygen` binary | ✅ | Standalone key-generation tool; creates ML-DSA-65 verifier keypairs; keys stored encrypted at rest |
| P2 | Verifier result signing | ✅ | Accepted results signed with ML-DSA-65; signature included in verification response |
| P3 | Scheduler verifier API | ✅ | `POST /scheduler/tasks/{id}/verification`; verifier submits signed acceptance/rejection |
| P4 | Quorum logic | ✅ | Scheduler accepts result as canonical after N independent verifier confirmations (configurable) |
| P5 | Sybil resistance (rate-limiting) | ✅ | Per-verifier submission rate limit; Sybil-flooding of verification queue blocked |
| P6 | Devnet demo — verifier Sybil protection | ⬜ | 7 adversarial scenarios: duplicate verifier, fake quorum, replayed verification, spoofed verifier ID, quorum stuffing, late verification, verifier collusion; devnet proof required |

### Change Set R — P2P Proof Gossip ✅ COMPLETE (commit `93a2018`)

| Item | Status | Notes |
|------|--------|-------|
| `GossipTopic::DiscoveryProof` | ✅ | New gossip topic; miners publish accepted PoCD proofs to the libp2p gossip layer |
| Proof gossip handler in `chain-forge-node` | ✅ | Nodes receive gossiped proofs and insert into their local `DiscoveryRegistry` |
| Cross-node proof pool convergence | ✅ | All nodes converge to same proof set before epoch boundary; resolves item 30 (node-local proof pool isolation) |
| Anti-spam guards | ✅ | Duplicate proofs rejected at gossip layer; proof already in registry silently dropped |
| Proof gossip integration tests | ✅ | Proof submitted to Alice propagates to Bob and Dave before epoch close |

### Change Set T — Light P2P Resource/Capacity Discovery ✅ COMPLETE (commit `bd9d4ff`)

| Item | Status | Notes |
|------|--------|-------|
| `GossipTopic::CapacityAd` | ✅ | New gossip topic; nodes broadcast `CapacityAdGossip { node_id, cpu_free_pct, mem_free_pct, disk_free_gb, timestamp_secs }` |
| `PeerCapacityTable` | ✅ | In-memory table; 500-entry bounded; 5-minute TTL eviction; O(N) scan, no flood-fill |
| `GET /api/peers/capacity` | ✅ | REST endpoint returns current table; scheduler can query to prefer idle nodes for task assignment |
| Advisory-only semantics | ✅ | Capacity ads are hints, not commitments; no consensus dependency; stale/missing entries handled gracefully |
| Anti-spam rate limiting | ✅ | 30-second per-peer rate limit on capacity ad acceptance; flood of ads from one peer ignored |
| Capacity ad integration tests | ✅ | Ad broadcast, table insertion, TTL eviction, anti-spam guard all tested |
| `qcb-miner` does not send capacity ads | ✅ | Capacity ads are emitted by `chain-forge-node`; miner's queue depth reflected indirectly if co-hosted with a node |

### Item 5 — External Miner Documentation ✅ COMPLETE (commit `0e589ec`)

| Item | Status | Notes |
|------|--------|-------|
| `chain-forge-miner/README.md` | ✅ | Developer-facing crate README: build commands, test summary (13/13), architecture, two-phase cascade table, task dispatch logic, scheduler API surface, dependency table, invariants |
| `docs/QCB-Miner-External-Guide.md` | ✅ | Complete operator guide: prerequisites, quick-start, full CLI reference, algorithm specs, task lease semantics, running multiple miners, structured log event guide, env var table, systemd unit example, troubleshooting, security notes, capacity ad context, protocol invariants, API endpoint reference |

### PoCD Devnet Acceptance Test Results ✅ 9/9 PASSING

| Test | Result | Notes |
|------|--------|-------|
| Phase-1 SHA-256 preimage search (16-bit difficulty) | ✅ | Solver finds winning nonce in assigned range |
| Phase-2 chained search (8-bit difficulty, parent-hash dep) | ✅ | H1 bytes chained correctly; different miner enforced |
| Determinism across multiple solver runs | ✅ | Same seed + nonce always produces same hash |
| Phase-2 cross-miner content-hash agreement | ✅ | `SHA-256(H1 ∥ H2)` agrees across independent solvers |
| Avalanche seed derivation (deterministic by `(objective_id, seed_index)`) | ✅ | Canonical seed reproducible by any machine |
| Avalanche hamming-distance consistency | ✅ | XOR diff + popcount verified against reference |
| Invalid-hex parent-hash returns `None` gracefully | ✅ | No panic; solver returns None cleanly |
| Result deduplication (duplicate submit rejected) | ✅ | HTTP 409 on duplicate; miner continues |
| Lease expiry handling | ✅ | HTTP 410 logged as WARN; miner moves on |

---

## Open Questions Index

> See `QCB-Chain-Whitepaper-v2.md §12` for full descriptions. Listed here for quick reference.

| # | Topic | Urgency |
|---|-------|---------|
| Q1 | Final identity layer design; pilot cost/sybil targets | 🔴 High — gates everything |
| Q2 | BFT variant selection for Qattice | 🟡 Medium — all three variants shipped; selection decision now unblocked |
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

---

## Milestone: Transaction Nonce Cache Consistency and Restart Recovery
**Status: COMPLETE**
**Commit:** 1849ed3
**Date:** 2026-10-22

### What was fixed
`SharedNonceCache` was initialized empty on every startup, causing the API
admission gate to diverge from committed execution state after any restart.
The cache now loads from `state.all_accounts()` before `state` is moved into
`Self`, inserting `(address, account.nonce - 1)` for all accounts with
`nonce > 0`. Absence of an entry correctly admits `nonce=0` for fresh accounts.

### Verified observations (3-node devnet regression, 2026-10-22)
- Fresh account nonce=0 executed successfully ✅
- Sequential nonce execution advanced committed account state ✅
- Previously committed nonce replay rejected ✅
- Account nonce consistent across devnet restart ✅
- Invalid future nonce=10 queued but did not advance committed account nonce=4 ✅
- Subsequent valid nonce=4 accepted and executed ✅
- Final committed account nonce advanced to 5 ✅
- Final Alice balance: 499,997,677 uQCB ✅

### Scope
These results validate the tested nonce-cache recovery path on a 3-node devnet.
They do not cover all possible concurrent or adversarial transaction scenarios.
Consensus logic is unchanged.

### Nonce semantics (now consistent end-to-end)
| Layer | Convention |
|-------|-----------|
| cache stores | last committed tx.nonce |
| API rejects | tx.nonce <= cache[sender] |
| execution expects | tx.nonce == account.nonce (post-increment, starts at 0) |
| cache absent | sender unknown — admits nonce=0 |

---

## Identity Pilot — Phase 2 Complete
**Date:** 2026-10-22
**Red-team suite:** github.com/cluna80/RedTeam (agent8_identity_pilot.py)
**Final status:** 0 findings across all 16 attack scenarios

### What was demonstrated
- RegisterIdentity end-to-end: fund → register → Provisional tier ✅
- Attestation quorum (ATTESTATION_QUORUM=3): 3 independent attestors → Verified tier ✅
- Web-of-trust propagation: Verified identities can attest new identities ✅
- Single controller cannot bulk-verify identities ✅
- ConfirmSybil coordinator gate enforced at mempool ingress ✅
- ReverseSybil coordinator gate enforced at mempool ingress ✅
- Governance rate limiting: spam proposals blocked ✅
- DIS delegation depth overflow (>4 links) rejected ✅
- DIS delegation scope widening rejected ✅
- DIS human-approval bypass rejected ✅
- DIS max_uses enforced durably via delegation_usage DB table ✅
- Tx ingress hardened: 0 findings across F1-F8 (27 findings closed) ✅
- Nonce cache initialized from committed state on startup ✅

### Qualification
End-to-end security hardening and quorum-based verification confirmed.
Verification cost measurement (< $5/human target) requires real human ceremony.
Sybil rate measurement (< 3% target) demonstrated structurally; full pilot
requires RegisterIdentity path wired to real attestation ceremony.

### Commits
- check_tx stateless validation: multiple commits
- Coordinator gate: 6eecbb7
- Nonce cache fix: 1849ed3
- DIS delegation validation: auth.rs validate_delegation_chain_structure
- Durable max_uses: fe7d959, 11cdb8f, 70df9d3

### Status: QPC-CONS-001 fully closed (PRs #10, #11 + QPC-CONS-001-AV + QPC-CONS-001-AV2 — 2026-10-24)
Registry eligibility enforcement, node-level revocation invariant tests, end-to-end
`RevokeAttestation` lifecycle acceptance test, and the full production validator-onboarding
+ revocation path (`bond_validator_owner_binding_revocation_excludes_validator`) all merged
to `main`. See Phase 1 → Consensus — Personhood Weighting for the formal milestone entry.

---

## Phase C DIS — Complete
**Date:** 2026-10-22
**Status: COMPLETE — All 16 agent8 identity pilot scenarios passing**

### What was built and verified
- `/api/dis/verify_delegated` endpoint with full 5-phase verification
- Durable `max_uses` enforcement via `delegation_usage` table + `SELECT FOR UPDATE`
- Human-approval token gate (`requires_human_approval` enforced at Phase 0.5)
- Root delegator key fingerprint fix (SHA-256 of raw bytes, not hex string)
- `DelegationLinkJson.human_approval_token` field added to request struct
- `dis-test-helper` binary for Dilithium3 keygen/sign/delegation in tests
- 5 binding checks in `verify_delegated_inner`: rp_id, resource, action, scope, wallet

### Agent 8 final result (all 16 scenarios)
| Scenario | Result |
|----------|--------|
| I1–I8 | Passed (attestation, coordinator gates, tx ingress) |
| I9 Delegation depth overflow | Correctly rejected at /api/auth/verify |
| I10 Scope widening | Correctly rejected |
| I11 max_uses exhaustion | use1=200, use2=200, use3=403 (durable enforcement) |
| I12 Human-approval bypass | Correctly rejected with token check |
| I13–I16 | Passed |
| **Total** | **16/16 passed, 0 findings, 0 errors** |

### Status: QPC-CONS-001 original acceptance criteria closed (2026-10-24)
QPC-CONS-001-AV2 production validator-onboarding + revocation path acceptance test shipped
(`bond_validator_owner_binding_revocation_excludes_validator`). All originally-stated
acceptance criteria met. One narrower follow-on criterion recorded as QPC-CONS-001-AV3:
revocation of a validator that already holds nonzero voting power (post-`RegisterValidatorKey`).
That property is not covered by AV2 because `gate_voting_power()` correctly zeros power
before key registration — this is correct security behavior, not a bug.

**`attestation_guard_live` integration test:** fixed in PR #40 (2026-10-31, Windows-confirmed). Root cause was a RegisterIdentity/Attest ordering race in the test harness (not a protocol bug). See PR #40 and locked plan step 3 for full root-cause analysis.

Next: resource market hardening, enterprise authorization tree, FeeSponsor FS-03 follow-on
(sponsored-tx envelope + `SponsorStore` execution wiring), multi-node devnet fee validation.

---

## Red-Team Suite — TX Ingress Hardening (2026-10-22)
**Date:** 2026-10-22
**Status: SUITE STABLE — all confirmed real findings closed; 1 pending verification after rebuild**

### Suite run history
| Run | Findings | Notes |
|-----|----------|-------|
| Initial run | 2 real findings | F1 nonce-gap, F5 unknown sender |
| After F1+F5 fix (`802acfb`) + rebuild | 2 findings | sig=double-length, sig=empty-string |
| After sig-length arm fix (pending rebuild) | 0 expected | sig-length arm added to api.rs ingress |

### Suite run results (clean devnet, 7 agents)
| Agent | Result | Notes |
|-------|--------|-------|
| Agent 1 (TxFuzzer) | ✅ expected clean after rebuild | sig-length ingress arm added (commit pending) |
| Agent 2 (Economic) | ✅ clean | 6 scheduler/treasury endpoints not yet deployed → NOT_TESTED |
| Agent 3 (Gossip) | ✅ clean | Gossip injection endpoints not deployed → NOT_TESTED |
| Agent 4 (Sybil) | ✅ clean | All 7 sybil scenarios pass |
| Agent 5 (Invariant) | ✅ clean | 0 invariant violations |
| Agent 7 (Consensus) | ✅ clean | C1/C7 vote endpoint not deployed → NOT_TESTED |
| Agent 8 (Identity) | ✅ clean | 16/16 DIS scenarios pass |

### Suite infrastructure fixes shipped
- `run_suite.py`: `--once` flag now forwarded only to agent5 (InvariantMonitor)
- `run_suite.py`: removed duplicate agent8 entry in default run order
- `run_suite.py`: agent8 entry updated to `agent8_identity_pilot.py`
- Agents 2, 3, 7: 404 responses (undeployed endpoints) now treated as NOT_TESTED instead of findings

### Closed findings
| ID | Agent | Severity | Description | Fix | Commit |
|----|-------|----------|-------------|-----|--------|
| F1 | agent1_tx_fuzzer | critical | Tx with nonce=gap+1000 accepted (mempool not enforcing nonce ordering) | `MAX_NONCE_GAP=100` guard in api.rs ingress | `802acfb` |
| F5 | agent1_tx_fuzzer | critical | Tx with unknown sender accepted (no sender auth at ingress) | Unknown-sender check against `nonce_cache` in api.rs | `802acfb` |
| F5-sig | agent1_tx_fuzzer | critical | Tx with 1000-byte Ed25519 sig (sig=double-length) accepted | Explicit sig-length arm in api.rs (`!sig.is_empty() && sig.len() != 64`) | pending |

### Pending verification
- `sig=empty-string` (`signature="not-a-list"`): serde should propagate Err for invalid hex → 400 → rejected. May be a false positive or transient test artifact. If finding persists after rebuild, investigate serde `#[serde(default)]` fallback behavior on the `signature` field.

### Next steps
1. Restart devnet after rebuild and re-run full suite to confirm 0 findings
2. Deploy scheduler, gossip, and treasury endpoints to enable remaining NOT_TESTED scenarios
3. QPC-CONS-001-AV — ✅ Closed (2026-10-24); see Phase 1 → Consensus — Personhood Weighting


---

## RedTeam Devnet Debug Hooks — Intentional Simulation Boundary (2026-10-22)
**Status: DOCUMENTED — scaffolding retained; real consensus adversarial validation OPEN**
**Reference:** Chain Forge commit `0979750` and RedTeam `agents/agent7_consensus.py`.

### Decision
The `POST /debug/inject_view_change`, `/debug/inject_vote`,
`/debug/inject_proposal`, and `/debug/nil_block` routes were intentionally
introduced as devnet-only test scaffolding. They return HTTP 200 with
`{"status":"ok","discarded":true}` and do **not** deliver payloads to the
consensus engine. Retain for development compatibility, but do not treat
responses from these routes as evidence of consensus security. Ensure the
routes are unavailable in production configurations.

### Evidence and limitations
- Agent7 C1 (cross-chain votes), C2 (conflicting proposals), C6 (view-change
  flood), and C7 (equivocation) cannot establish the advertised security
  invariants through discard-only endpoints. Mark **SIMULATED/NOT_TESTED**
  until real authenticated, devnet-only injection hooks or equivalent
  network-level tests are implemented.
- Prior RedTeam suite reported three findings: F1 nonce=0/unsigned tx queued,
  INV-13 ConfirmSybil queued without observed freeze, and C6 height stall.
  Commit `0979750` introduced a genesis-account nonce sentinel and debug
  stubs, but **does not independently verify** the three findings are closed.
- Observed live three-node status before rebuild/restart: Alice height 1;
  Bob and Dave height 0; Alice remained at height 1 after 15 seconds;
  all three reported two peers. This is an **open liveness/synchronization
  investigation**; the view-change flood has not been proven causal.
- An HTTP `{"status":"queued"}` response is not a committed execution
  receipt. F1 must check signature enforcement and nonce replay at
  admission and execution; INV-13 must wait for commit and verify durable
  `frozen=true` and `sybil_confirmed=true`.
- Agent7 `_current_height()` uses `or` fallback, which mishandles a
  legitimate zero height; fix the harness before relying on C6 results.

### Follow-up acceptance gates
1. **CONS-LIVE-001:** On a clean three-validator baseline, all validators
   advance and converge on the same committed height/block hashes; capture
   startup/consensus logs and diagnose the 1/0/0 stall before attack testing.
2. **CONS-ADV-001:** Replace discard-only checks with real consensus-path
   tests; verify wrong-chain rejection, conflicting proposal safety,
   equivocation evidence, and rate-limited view-change flood with measured
   pre-attack and post-attack liveness. Stubs must never count as PASS.
3. **TX-NONCE-001:** Verify legitimate genesis nonce=0, unsigned transaction
   rejection, duplicate pending nonce behavior, replay after commit/restart,
   and new funded-account onboarding; evaluate `u64::MAX` sentinel
   semantics against execution state.
4. **ID-SYBIL-001:** Submit ConfirmSybil, observe commit/execution result,
   then verify frozen and sybil-confirmed flags and persistence.
5. **REDTEAM-REPORT-001:** Distinguish PASS / FAIL / NOT_TESTED / SIMULATED
   in suite reporting; do not equate zero findings with complete coverage.

**Status:** QPC-CONS-001 fully closed (2026-10-24) — QPC-CONS-001-AV end-to-end
revocation lifecycle test shipped (see Phase 1 → Consensus — Personhood Weighting).
The devnet liveness and authentic adversarial test gates above remain open
security-validation prerequisites, not completed findings.


---

## Qattice ComputeOS + PoCD Integration — Planned Initiative

**Status:** 🔲 Planned / architecture definition (2026-10-26). This is a Qattice product initiative; it is not a change to the independent blockchain-creation platform. No production ComputeOS marketplace or customer-funded compute settlement is claimed.

**Product thesis:** Qattice ComputeOS coordinates independently owned CPU/GPU resources, workload discovery, scheduling, isolated execution, independent result verification where feasible, and customer settlement. PoCD is its native scientific-research workload engine: both share worker registration and orchestration infrastructure, but commercial jobs do not have to generate discoveries. ComputeOS is an application/service layer integrating with Qattice L1; it is not a new consensus mechanism.

**Locked architectural invariants:**
- Preserve Qattice's personhood-bounded BFT consensus. PoCD computation, discovery, and receipts do not grant block voting power or become prerequisites for finality.
- Preserve the fixed genesis supply of 210,000,000 QCB; no PoCD or ComputeOS token minting. Research rewards follow existing treasury/sponsor-funded Pending uQCB redemption rules; commercial jobs use separately funded customer escrow/payment paths.
- Reuse existing PoCD task scheduler, miner, independent verifier, acceptance flow, MachineID, signed discovery/useful-work receipts, and research reward settlement wherever compatible; keep existing discovery receipt semantics.
- A signed receipt or hash seal alone is not proof of arbitrary computational correctness. Each workload class needs explicit reproducible verification, formal proof, redundancy, or an agreed acceptance policy; unsupported workloads must not be advertised as cryptographically verified.
- Separate accounting and anti-double-payment controls for PoCD research rewards and customer-funded jobs. Shared machines may opt into both; participation in one does not imply entitlement to the other.
- Provider resource contribution is opt-in, policy-controlled, and permissionless where safe. Identity/authorization for machine operators, buyers, and delegated agents is distinct from QPC personhood requirements for consensus/governance.
- Compute executes off-chain in isolated workers; Qattice stores only necessary commitments, identities/authorizations, receipts, and settlement state. Do not place raw customer workloads, sensitive data, or large outputs on-chain by default.
- Do not revive the previously archived protocol-level resource marketplace or modify monetary rules as a prerequisite. Commercial compute marketplace functionality begins outside consensus.

| Milestone | Status | Deliverable / acceptance criteria |
|---|---|---|
| **COS-PoCD-000 — Code and threat-model audit** | 🔲 Planned | Inventory live scheduler/miner/verifier/receipt/MachineID/settlement APIs; map reusable modules versus missing pieces; define adversaries, provider trust, workload confidentiality, resource abuse, and payout risks; reconcile docs with tested code before claiming capabilities. |
| **COS-PoCD-001 — Shared worker registry and resource advertisement** | 🔲 Planned | Two independently operated physical machines register/advertise supported CPU/RAM/GPU capacity, availability, pricing/policy, and PoCD opt-in; signed updates, freshness/expiry, duplicate identity and spoofed-capacity defenses. |
| **COS-PoCD-002 — Unified scheduler with distinct workload classes** | 🔲 Planned | Schedule deterministic PoCD tasks and separately funded commercial tasks on the same worker fleet; enforce provider resource limits, lease expiry/retry, task cancellation, fair resource allocation, and no double assignment/settlement. |
| **COS-PoCD-003 — Sandboxed execution and result verification** | 🔲 Planned | Isolated, resource-limited worker execution; reproducible deterministic research task with independent verifier; workload-specific commercial acceptance rules; failure, timeout, dishonest-result, and verifier-collusion tests. |
| **COS-PoCD-004 — Receipts, accounting, and settlement** | 🔲 Planned | Preserve existing PoCD discovery/useful-work receipt and treasury-funded reward path; introduce separately identified customer-job execution receipts, pre-funded customer payment/escrow, dispute/failure/refund rules, replay resistance, and conservation tests; no inflation or reward cross-subsidy. |
| **COS-PoCD-005 — Two-machine end-to-end pilot** | 🔲 Planned | From an independent client, submit one PoCD task and one customer-funded deterministic compute task; schedule on independent machines, independently verify results, produce distinct signed receipts, and demonstrate correct research reward versus customer payment settlement; publish logs and repeatable test instructions. |
| **COS-PoCD-006 — Developer API and first paying pilot** | 🔲 Future | Document job submission/status/results, provider onboarding, cost and verification guarantees; validate with at least one external customer and measure reliability, verification overhead, job economics, and payment completion. |
| **COS-PoCD-007 — Authorized agent purchasing (optional)** | 🔲 Future | Delegated agent permissions with enforceable budgets, provider allowlists, revocation, replay protection, and independent security review before production financial use. |

**First product wedge:** Verified deterministic scientific/cryptographic computation. General-purpose GPU/AI workloads are a later expansion and must not inherit unsupported PoCD verification claims.

**Non-goals for initial milestone:** Replacing BFT with PoCD; requiring every paid job to produce scientific discoveries; creating a new token; modifying the fixed QCB supply; claiming general-purpose zero-knowledge proof of computation; production launch before security review and customer validation.
