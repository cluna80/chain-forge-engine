# Phase 0 Security Assumptions and Boundaries

**Baseline commit:** `6fbd6bfbd4235e0a07862cca20c789dc7fc53ef3`  
**Tag:** `v0.1.0-phase0`  
**Date:** 2026-10-25

This document records the explicit security boundaries in effect at Phase 0
completion. Each item is a known limitation, not a defect. Items marked
**Phase 1** are on the engineering roadmap for the next phase.

---

## 1. PoCD Settlement — Trusted Operator Model

The `ClaimResearchReward` transaction requires the sender to be a registered
settlement operator (configured in genesis). The executor does not
independently verify that the submitted `objective_id`, `task_id`, or
`contribution_hash` correspond to genuine completed research. These fields
are operator-asserted metadata stored verbatim in the claim record.

**Trust assumption:** The settlement operator is responsible for verifying
research validity off-chain before signing a `ClaimResearchReward` transaction.
The chain enforces operator identity, replay prevention, and treasury solvency,
but not research correctness.

**Confirmed by test P0-9-F:** A trusted operator can submit any string as
`objective_id`/`task_id` and the claim will succeed. This is by design for
the pilot phase; a later phase may require on-chain verifier attestation
quorum before the operator can settle.

**Phase 1 path:** Require a minimum verifier attestation count
(`attestation_accumulator` quorum) before `ClaimResearchReward` is accepted,
so research correctness has independent consensus backing.

---

## 2. Consensus Cryptography — Ed25519 Validators

Validator signing keys are Ed25519 (32-byte private key, 32-byte public key).
User transactions and DIS identity operations are already protected by
ML-DSA-65 (NIST FIPS 204), which is post-quantum secure.

**Boundary:** A sufficiently powerful quantum adversary could forge validator
votes. This does not affect user transaction security or identity bindings,
which use ML-DSA-65.

**Not a bug:** This is a deliberate Phase 0 choice. ML-DSA-65 consensus keys
require a larger signature size and more complex key lifecycle management.
Migrating to them in a running devnet is a Phase 1 task.

**Phase 1 path:** Replace Ed25519 consensus keys with ML-DSA-65. Key rotation
procedure and equivocation slashing must be re-validated after the migration.

---

## 3. State Persistence — In-Memory Devnet Only

The devnet state is held entirely in memory. A node restart returns to genesis.
There is no WAL, no RocksDB backend, no snapshot mechanism.

**Boundary:** P0-9-G confirms that settlement survives a **block boundary**
(the state is correctly committed into the next block). It does not test
survival across a **process restart**. These are different durability
guarantees. The test passes because all nodes hold state in-memory
throughout the test run.

**Phase 1 path:** Persistent storage (RocksDB or equivalent), WAL for
crash recovery, and a restart-survival regression test added to the
acceptance suite.

---

## 4. Network Testing Scope — Single-Operator Devnet

P0-8 validated:
- Partition tolerance (iptables DROP, 5 s isolation, recovery)
- Equivocation detection and slashing
- Node restart recovery

What has **not** been tested:
- Eclipse attacks (isolation of a single validator from the honest majority)
- Long-range network partitions (> 30 s)
- Sybil peer connections at the libp2p layer
- BGP-level routing attacks or latency injection across machines
- Validator set changes under network stress

All Phase 0 tests run on a single machine (localhost). Multi-machine adversarial
network testing is a prerequisite for a public testnet.

**Note on validator count vs. operator count:** Qattice already runs a
multi-node consensus devnet (4 validators, all independent processes). The
"single-operator" limitation refers to the **test operator** — all devnet
nodes are run by the same person from the same machine. It does not mean
the consensus is single-node.

---

## 5. Identity — DIS Pilot Tier Only

The Digital Identity Stone protocol is implemented and verified at the
**Verified tier** (4 pilot devices confirmed in P0-2). The following DIS
operations are **not yet tested**:

- Authenticated key rotation (new keypair, same identity — DIS-002)
- Device migration (move identity to a new device without losing personhood)
- Revocation (invalidate a compromised key without creating a duplicate identity)
- Recovery (restore access after device loss without issuing a second credential)

These are the subject of the DIS-002 milestone. The protocol invariant:
`Identity_before = Identity_after` must hold across all of the above
operations — the persistent personhood identity must remain the same even
when the controlling public key or device changes.

---

## Summary Table

| Area | Phase 0 limitation | Phase 1 path |
|------|--------------------|--------------|
| PoCD settlement | Operator-trusted; objective/task IDs not chain-verified | Verifier attestation quorum required before settlement |
| Consensus keys | Ed25519 (quantum-vulnerable) | ML-DSA-65 validator keys |
| State persistence | In-memory only; restart returns to genesis | RocksDB backend + WAL + restart regression test |
| Network testing | Single-machine, localhost devnet | Multi-machine adversarial network tests |
| DIS key lifecycle | Verified tier only; no rotation/revocation/recovery | DIS-002: rotation, migration, revocation, recovery |
