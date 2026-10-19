# PQ-VAL-002 — ML-DSA-65 Consensus Signature Verification and Activation

**Status:** Specification — locked for implementation  
**Depends on:** PQ-VAL-001 (ML-DSA key registration), PQ-VAL-001b (benchmark gate passed)  
**Blocks:** PQ-VAL-003 (full PQ validator lifecycle, Phase D degraded-network testing)  
**Baseline:** `main` @ `bda89a5` (PQ-VAL-001b spec) / implementation branch from `feat/pq-val-001b-benchmarks` merge

---

## Purpose

PQ-VAL-001 registered ML-DSA-65 keys and held ML-DSA-only validator voting power at zero (R3 gate). PQ-VAL-001b confirmed ML-DSA-65 meets the finality target with 12.7× margin. PQ-VAL-002 activates ML-DSA-65 in the consensus signature-verification path and lifts the R3 power gate at a governance-controlled epoch boundary.

**This milestone makes ML-DSA-65 a first-class consensus signing scheme on Qattice.**

---

## Non-negotiables (carry forward from PQ-VAL-001)

- Mandatory validator-key enforcement, personhood gating, and signature verification are not weakened.
- Validator eviction policy, quorum rules (2/3+1), and personhood semantics are unchanged.
- Existing operator keys and devnet data are preserved. The devnet is not reset.
- Consensus cryptography changes are additive only: the classical (Ed25519) path remains fully operational throughout and after this milestone.
- No speculative implementation — all code follows from this locked spec.

---

## Requirements

### R1 — Governance-controlled activation at an epoch boundary

A dedicated governance transaction `TxBody::ActivatePqConsensus { activation_epoch: u64 }` sets the epoch at which ML-DSA-65 precommits are accepted by the consensus verifier. The activation epoch must be strictly in the future (> current epoch) at the time the transaction is executed. Once set, the activation epoch is immutable unless a `TxBody::EmergencyDeprecateAlgorithm` transaction (CS-001) overrides it.

The governance transaction is authorised by the same rules as other constitutional proposals (existing governance path). No feature flag, no calendar trigger, no automatic activation.

The activation epoch is stored in chain state and survives node restart.

### R2 — Dual-scheme consensus verification (scheme-tagged votes)

At and after the activation epoch, the consensus verifier accepts both Ed25519 and ML-DSA-65 precommit signatures. Each vote message carries an explicit `scheme` tag (`"classical"` or `"ml-dsa-65"`). The verifier dispatches on this tag using the same `VALIDATOR_AUTHORIZED_SCHEMES` allowlist from PQ-VAL-001. Unknown or unauthorised scheme tags fail closed — the vote is rejected before any cryptography runs.

The classical verification path (Ed25519) is not modified. ML-DSA-65 verification uses `MlDsaScheme.verify` from `chain-forge-crypto` with the same domain-separated message format established in PQ-VAL-001 (V2 PoP format adapted to precommit context — see §Message format below).

Before the activation epoch, ML-DSA-65 scheme tags on votes are rejected regardless of key registration state. The consensus verifier is epoch-gated.

### R3 — R3 power-gate lift at activation epoch

At the activation epoch roll, the power-restore logic in `propose_block` and `commit_block` lifts the R3 hold for validators whose `consensus_key_scheme` is `"ml-dsa-65"`, provided they also satisfy the existing gates (bond ≥ entry stake, personhood verified, pop_verified). No other change to the power calculation.

Classical validators are unaffected — their power path is unchanged.

The lift is applied during the normal epoch-transition sweep, not as a one-off migration.

### R4 — Emergency rollback via EmergencyDeprecateAlgorithm

The existing `TxBody::EmergencyDeprecateAlgorithm { scheme: String }` governance transaction (CS-001) serves as the ML-DSA consensus off-switch. Executing it with `scheme = "ml-dsa-65"` does the following atomically at the next block boundary:

1. ML-DSA-65 is removed from `VALIDATOR_AUTHORIZED_SCHEMES` in the consensus verifier.
2. ML-DSA-65 votes in the current and future blocks are rejected (fail-closed).
3. ML-DSA-only validators have their voting power re-zeroed (R3 gate re-applied).
4. Classical validators retain full power.
5. The activation epoch record is marked deprecated; a new `ActivatePqConsensus` tx is required to re-enable.

This does not require a hard fork. The chain continues under classical consensus. Validators with ML-DSA-only keys become inactive until they register a classical key or until a new activation governance tx passes.

### R5 — No change to quorum math or personhood rules

The 2/3+1 quorum is calculated over total bonded voting power. Whether a validator's vote uses Ed25519 or ML-DSA-65 does not affect their weight in quorum calculation. Personhood gating is unchanged. A validator without verified personhood has voting_power = 0 regardless of key scheme.

---

## Message format for consensus votes

PQ-VAL-001 established the V2 PoP format for key registration. Consensus precommit signing uses a parallel domain-separated format:

### Precommit signing bytes (V1 — initial activation format)

```
b"QATTICE-PRECOMMIT|" || chain_id || b"|" || height_le8 || b"|" || round_le4 || b"|" || hex(block_hash)
```

Where:
- `chain_id`: UTF-8 chain identifier (e.g. `"qattice-devnet-1"`)
- `height_le8`: block height as 8-byte little-endian
- `round_le4`: consensus round as 4-byte little-endian
- `block_hash`: 32-byte block hash, hex-encoded

This format is scheme-agnostic. Both classical and ML-DSA-65 validators sign the same bytes. The scheme tag is carried in the vote message envelope, not in the signing bytes.

A public function `consensus_precommit_signing_bytes(chain_id, height, round, block_hash) -> Vec<u8>` will be added to `chain-forge-execution` (parallel to `validator_key_registration_signing_bytes_v2`).

---

## Implementation scope

### chain-forge-execution

- Add `TxBody::ActivatePqConsensus { activation_epoch: u64 }` variant.
- Add `fn consensus_precommit_signing_bytes(chain_id, height, round, block_hash) -> Vec<u8>`.
- Executor arm for `ActivatePqConsensus`: validate future epoch, store in chain state, emit event.
- `TxBody::EmergencyDeprecateAlgorithm` arm: extend to handle `"ml-dsa-65"` target — re-zero ML-DSA validator power, mark activation epoch deprecated.

### chain-forge-consensus

- Add `scheme: String` field to the precommit/vote message type.
- Consensus verifier: epoch-gate check before dispatch; dual-scheme dispatch on `scheme` tag using `VALIDATOR_AUTHORIZED_SCHEMES`; classical path unchanged; ML-DSA path via `MlDsaScheme.verify`.
- Expose `activation_epoch() -> Option<u64>` from chain state for the verifier to read.

### chain-forge-node (node.rs)

- Store `activation_epoch: Option<u64>` in node state; persist across restart.
- Epoch-transition sweep: at `current_epoch == activation_epoch`, lift R3 gate for `"ml-dsa-65"` validators that pass all other gates.
- `EmergencyDeprecateAlgorithm` handler: re-apply R3 gate, mark activation deprecated.

### chain-forge-validators

- No new API required beyond what PQ-VAL-001 added (`consensus_key_scheme`, `register_consensus_key_with_scheme`).

---

## Acceptance tests (14 tests, test-first)

Write all 14 tests before any implementation. Record failures as the failure matrix. Implement to green.

| # | Test name | What it proves |
|---|---|---|
| 01 | `activation_epoch_set_by_governance_tx` | `ActivatePqConsensus` stores epoch; query returns it |
| 02 | `activation_epoch_must_be_future` | tx with past/current epoch is rejected |
| 03 | `mldsa_vote_rejected_before_activation_epoch` | ML-DSA precommit fails before activation |
| 04 | `classical_vote_accepted_before_activation_epoch` | Ed25519 precommit passes before activation (regression) |
| 05 | `mldsa_vote_accepted_after_activation_epoch` | ML-DSA precommit passes at/after activation epoch |
| 06 | `classical_vote_accepted_after_activation_epoch` | Ed25519 still passes after activation (dual-scheme) |
| 07 | `r3_gate_lifts_at_activation_epoch` | ML-DSA-only validator gains voting_power > 0 at activation |
| 08 | `r3_gate_requires_bond_and_personhood` | ML-DSA validator without bond or personhood stays at 0 after activation |
| 09 | `unknown_scheme_vote_rejected_after_activation` | Unknown scheme tag fails closed post-activation |
| 10 | `emergency_deprecate_zeros_mldsa_power` | `EmergencyDeprecateAlgorithm("ml-dsa-65")` re-zeros ML-DSA validators |
| 11 | `emergency_deprecate_rejects_mldsa_votes` | ML-DSA votes rejected after emergency deprecation |
| 12 | `classical_unaffected_by_emergency_deprecate` | Classical validators keep power after deprecation |
| 13 | `activation_epoch_survives_restart` | Stored activation epoch persists across node restart |
| 14 | `reactivation_requires_new_governance_tx` | Deprecated activation cannot resume without new `ActivatePqConsensus` tx |

---

## Deliverables

1. `chain-forge-node/src/node.rs` — 14 acceptance tests (commit first, all red)
2. `chain-forge-execution/src/lib.rs` — `ActivatePqConsensus` tx, `EmergencyDeprecateAlgorithm` ML-DSA arm, `consensus_precommit_signing_bytes`
3. `chain-forge-consensus/src/lib.rs` — scheme-tagged vote type, dual-scheme verifier, epoch gate
4. `chain-forge-node/src/node.rs` — activation epoch state, R3 lift sweep, deprecation handler

---

## Out of scope for PQ-VAL-002

- Phase D degraded-network and Byzantine-tolerance testing (PQ-VAL-003)
- Validator migration tooling (classical → ML-DSA key rotation for existing validators)
- Mainnet activation governance proposal
- Any change to the gossip layer or wire encoding for large ML-DSA signatures
- Post-quantum aggregation research (deferred indefinitely per 001b decision)
