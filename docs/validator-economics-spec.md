# Qattice Validator Economics — Specification (Draft v1)

Status: Draft for protocol specification. Not authorization to change code.
Date: 2026-10-28

## 1. Decision log

- **Decided:** Additional bonded QCB earns a capped reward premium. Model C is selected.
- **Rationale (owner):** Loyalty is commitment, and commitment is expressed by staking more. Validators who bond more earn more.
- **Fixed:** Consensus voting power stays equal per verified human. Bonding more QCB never increases voting power.
- **Fixed:** The premium is bounded by a hard cap, set by governance within protocol-defined limits.
- **Superseded:** The Standard and Full reward multipliers from the earlier draft are removed from the initial calculation and kept in design history as research options.

## 2. Three kinds of value

| Mechanism | Provides | Scales with QCB bonded? |
|---|---|---|
| Consensus voting power | Authority to finalize blocks | No. Bounded per verified human. |
| Reliability rewards | Pay for verified, correct, available participation | No. Same rate for all eligible validators. |
| Capital premium (new) | Bonus for committed capital | Yes, up to a hard cap. |

## 3. Reward model

Reward for validator *v* in an epoch:

    reward(v) = base_reliability_reward(v) × (1 + premium(v))

where:

- `base_reliability_reward(v)` is paid only if *v* meets the reliability threshold for the epoch (duty completion, uptime, and safety compliance).
- `premium(v)` is zero if *v* does not meet the reliability threshold.
- `premium(v) = min(k × (bond(v) − bond_min), premium_cap)` for bonds above the minimum, where `k` and `premium_cap` are governance parameters.

Illustrative values only (not implementation behavior):

| Validator | Bond (QCB) | Reliable this epoch | Premium (illustrative) | Voting power |
|---|---|---|---|---|
| Alice | 1,000 | Yes | 0% | 1 human-share |
| Bob | 10,000 | Yes | 10% | 1 human-share |
| Carol | 100,000 | Yes | 25% (capped) | 1 human-share |
| Dan | 100,000 | No | 0% | 1 human-share |

## 4. Required safeguards

These follow from accepting a capital-based premium. They are not optional.

1. **Premium cap.** An absolute cap on the premium, set by governance and bounded by protocol constants. Without it, large holders can capture most rewards.
2. **Reliability gate.** The premium applies only to validators who met the reliability threshold for that epoch. Capital alone cannot earn the premium.
3. **Equal voting power.** Consensus weight is independent of bond size and is bounded per verified human.
4. **Per-human bond limit.** Interacts with the stake cap in whitepaper Section 3.3 (cap expressed in months of UBI income). The premium must not allow a single verified human to exceed that limit through multiple bonds.
5. **Governance-controlled parameters.** `bond_min`, `k`, and `premium_cap` are governance parameters with defined safety bounds, because QCB's market value and operating costs are not yet known.
6. **Slashing.** Bonded capital is subject to slashing for provable misconduct, so the premium is backed by collateral that can be penalized.

## 5. Known trade-off

The capital premium reintroduces income differences tied to holdings. Equal voting power protects consensus, but it does not make income equal. The premium cap and reliability gate limit the size of that gap, but they do not remove it. This should be stated openly in the whitepaper rather than presented as eliminated.

## 6. Open items

- Values for `bond_min`, `k`, and `premium_cap`, with safety bounds.
- Reliability threshold definition and measurement window (epoch length).
- Unbonding period and its interaction with slashing.
- How the premium interacts with the active validator limit (benchmark target 1,000).
- Whether the premium should be reviewed periodically, and by what governance process.

## 7. Personhood-based committee sampling (draft)

Status: Proposed design for research and specification. Not implemented. The randomness beacon and certificate format are open research items.

### 7.1 Purpose

When the active validator set grows beyond the benchmark target, not every verified validator votes on every block. Each epoch, a committee is sampled from the eligible pool. Committee sampling keeps per-block vote load bounded as the network grows.

Unlike stake-weighted sampling, selection here draws from verified humans. Capital does not change the odds of being selected.

### 7.2 Eligible pool

- The sampling pool is the set of verified humans who are eligible validators for the epoch: verified identity, meeting the minimum bond, and not evicted.
- Each verified human contributes at most one entry to the pool, regardless of how many bonds or keys they hold. The one-share-per-human rule is enforced when the pool is built, not only when votes are counted.
- Bond size does not change selection probability. A validator who bonds more earns the capped premium from Section 3, but is not sampled more often.

### 7.3 Selection

- Each epoch, a committee of size `C` is drawn from the pool using a shared random seed.
- The seed must be unpredictable before it is revealed and verifiable after it is revealed, and it must not depend on any single party's choice.
- Members who are sampled are notified in advance so they can prepare to vote. The notification scheme must not reveal committee membership to outside observers before the block is produced, to limit targeted attacks.
- Committee size `C` is a governance parameter with a defined safety bound. Smaller committees reduce cost but increase the chance a committee is dishonest or offline.

### 7.4 Post-quantum requirements

This section depends on primitives that are not yet specified for Qattice.

1. **Verifiable randomness.** The seed source must be post-quantum. Ethereum's randomness and signatures rely on BLS, which is on the quantum-vulnerable list. Qattice needs a hash-based or otherwise post-quantum beacon. Candidate approaches (commit-reveal with threshold reveal, or a verifiable delay function) are open research items.
2. **Certificate size.** A committee vote must be aggregated into one compact certificate per block. ML-DSA-65 signatures are about 2.4KB each and do not aggregate the way BLS signatures do. Naively attaching `C` ML-DSA signatures per block would make certificates very large. Candidate approaches include a hash-based multi-signature scheme, a succinct proof that the required signatures are valid (the STARK direction from the ZK roadmap item), or a smaller committee size. This is the main engineering bottleneck and should be prototyped first.
3. **Epoch boundary.** The seed for epoch *n+1* must be fixed before epoch *n+1* begins, so no party can choose a favorable committee.

### 7.5 Safeguards

1. **Sybil dependence.** Committee sampling is only as fair as the identity layer. If one operator can register many verified humans, it can capture a larger share of committee seats. Sybil resistance in the personhood pilot is therefore a consensus requirement, not an identity feature alone. The pilot's sybil targets should be treated as a gate before sampling goes live.
2. **Liveness fallback.** If a sampled committee fails to finalize a block, the protocol needs a defined fallback, such as a larger committee or a wider attestation round, so the chain does not halt. The fallback must not reintroduce capital-weighted voting.
3. **Grinding resistance.** Participants must not be able to repeatedly register or withdraw keys to influence which committee they land on. Registration and unbonding timing should limit this.
4. **Genesis set.** During bootstrap, the genesis validator set is small and may be the entire active pool. Sampling has little effect until the pool is large enough that a committee is a strict subset of it.

### 7.6 Open items

- Choice and specification of the post-quantum randomness beacon.
- Choice of certificate scheme and maximum certificate size per block.
- Committee size `C` and its safety bounds.
- Epoch length and the registration-to-eligibility delay.
- Fallback procedure when a committee stalls.
- Threshold at which sampling replaces all-validator voting, tied to the active validator limit.

## 8. Design history

- Standard and Full reward tiers (earlier draft): retained as research options, not part of the initial calculation.
- Model A (fixed bond, reliability-only rewards) and Model B (voluntary extra collateral, no reward premium): considered and not selected.
