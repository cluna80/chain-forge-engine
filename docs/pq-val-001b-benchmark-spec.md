# PQ-VAL-001b — ML-DSA-65 BFT Performance Benchmark

**Status:** Specification-locked, benchmark-first (implement before PQ-VAL-002)  
**Depends on:** PQ-VAL-001 (ML-DSA key registration)  
**Blocks:** PQ-VAL-002 (ML-DSA consensus activation) — activation target is set
by this benchmark's Phase C results, not by calendar  
**Baseline:** `main` @ `805a3ae`

---

## Purpose

ML-DSA-65 signatures are 3,309 bytes each — approximately 52× larger than
Ed25519's 64 bytes. In a BFT round every active validator signs a precommit.
At 1,000 validators that is ~3.3 MB of signature data per consensus round,
before proposals, prevotes, or gossip overhead.

This benchmark determines whether ML-DSA-65 can meet Qattice's finality target
before the consensus verifier is modified. A failed benchmark changes the
PQ-VAL-002 design (scheme choice, aggregation strategy, or phased activation
ceiling); a passing benchmark unlocks PQ-VAL-002 implementation.

**The benchmark is a decision gate, not a tuning exercise.**

---

## Target parameters (locked)

| Parameter | Value | Rationale |
|---|---|---|
| Active validator count | 1,000 | Qattice production target |
| Finality target (p99) | < 3 seconds | End-to-end BFT round |
| Network model | 50 ms one-way latency | Representative global validator distribution |
| Signature scheme | ML-DSA-65 (CRYSTALS-Dilithium, NIST FIPS 204) | PQ-VAL-001 registration scheme |
| Public key size | 1,952 bytes | ML-DSA-65 spec |
| Signature size | 3,309 bytes | ML-DSA-65 spec |
| Signing message | V2 PoP format (chain_id + sender + scheme + pubkey) | PQ-VAL-001 spec |

---

## Benchmark phases

### Phase A — Single-node cryptographic primitives

**Goal:** Establish raw ML-DSA-65 sign/verify throughput on a single thread and
under Rayon parallelism. No network. No BFT protocol.

**Measurements:**

| Metric | Target | Notes |
|---|---|---|
| Single sign latency (p50, p99) | < 5 ms p50 | `MlDsaScheme.sign` on V2 message |
| Single verify latency (p50, p99) | < 5 ms p50 | `MlDsaScheme.verify` on precommit bytes |
| Batch verify throughput (1,000 sigs, parallel) | < 500 ms wall-clock | Rayon parallel_iter, release build |
| Key generation latency | < 10 ms | `MlDsaScheme.generate_keypair` |

**Implementation:** Rust criterion benchmark in
`chain-forge-crypto/benches/mldsa_validator.rs`. Release build required
(`cargo bench`). Record system: CPU model, core count, RAM, OS.

**Pass criterion:** Batch verify of 1,000 signatures completes in < 500 ms.
This leaves headroom for network + serialization within the 3-second target.

---

### Phase B — Serialization and wire size

**Goal:** Measure actual bytes on wire per BFT round at 1,000 validators and
the CPU cost of encoding/decoding that volume.

**Measurements:**

| Metric | Value | Notes |
|---|---|---|
| Precommit message size (per validator) | 3,309 + ~100 bytes overhead | sig + validator_id + height + round + block_hash |
| Total precommit payload (1,000 validators) | ~3.4 MB | Before any compression |
| Serialization cost (1,000 messages) | — | Measured, not assumed |
| Deserialization cost (1,000 messages) | — | Measured, not assumed |

**Pass criterion:** Serialization + deserialization of 1,000 precommit messages
completes in < 100 ms (leaves 2.4 s for network + crypto after 500 ms batch verify).

---

### Phase C — Simulated BFT round (in-process, no real network)

**Goal:** Simulate one complete BFT round (propose → prevote → precommit →
commit) with 1,000 validators in-process, measuring wall-clock time from
proposal broadcast to commit certificate. No gossip layer. No TCP. Channels
replace network transport.

**Round structure simulated:**

1. Leader signs and broadcasts proposal (~1,952-byte pubkey + ~3,309-byte sig)
2. Each of 1,000 validators signs a prevote (ML-DSA-65)
3. Leader aggregates 667+ prevotes (2/3+1 quorum), verifies all
4. Each of 1,000 validators signs a precommit (ML-DSA-65)
5. Leader aggregates 667+ precommits, verifies all → commit certificate

**Measurements:**

| Metric | Target |
|---|---|
| Full round wall-clock (p50) | < 2,000 ms |
| Full round wall-clock (p99) | < 3,000 ms |
| Sign phase (1,000 prevotes) | < 500 ms |
| Sign phase (1,000 precommits) | < 500 ms |
| Verify phase (667+ prevotes) | < 500 ms |
| Verify phase (667+ precommits) | < 500 ms |
| Memory high-water mark | < 512 MB |

**Implementation:** `chain-forge-node/benches/bft_round_mldsa.rs` or a
standalone binary under `chain-forge-node/src/bin/`. Not a `#[test]` — a
dedicated benchmark binary to allow release-mode profiling.

**Pass criterion:** p99 full-round wall-clock < 3,000 ms. This is the gate for
PQ-VAL-002.

---

### Phase D — Degraded network and Byzantine tolerance

**Goal:** Confirm finality target holds under conditions that differ from the
50 ms nominal model. Not a gate for PQ-VAL-002 but required before mainnet.

**Scenarios:**

| Scenario | Parameters |
|---|---|
| High latency | 200 ms one-way latency (intercontinental validators) |
| Packet loss | 1% random drop, retransmit modeled |
| Byzantine validators | Up to f = 333 (floor(1000/3)) non-responding |
| Mixed validator speeds | 10% of validators sign 10× slower (degraded hardware) |

**Pass criterion:** Finality achieved in all scenarios with correct quorum,
even if p99 exceeds 3 seconds in the high-latency case (document the ceiling,
do not fail on it).

---

## Engineering notes

### Why not BLS aggregation?

BLS12-381 (Ethereum's choice) produces constant-size aggregate signatures
regardless of validator count. ML-DSA-65 has no standard aggregation scheme —
each validator's signature is verified independently. This is the fundamental
scalability tradeoff for ML-DSA. If Phase C fails the target, the options are:

1. **Lower the activation ceiling** — activate ML-DSA consensus at ≤ N
   validators, with a governance trigger to raise it when hardware improves.
2. **Threshold ML-DSA** — research-level; not standardized; deferred.
3. **Hybrid scheme** — BFT votes stay Ed25519 through a transition epoch;
   ML-DSA used for a separate authentication binding. Activated by
   `EmergencyDeprecateAlgorithm` governance tx.
4. **Defer ML-DSA consensus entirely** — register ML-DSA keys (PQ-VAL-001)
   for future use; keep Ed25519 consensus indefinitely until a standard
   aggregation scheme exists.

The benchmark result picks the path. Do not pick the path before the benchmark.

### Ethereum comparison

Ethereum's published PQ roadmap (I* milestone) takes the staged
registration-before-activation approach: validators register quantum-resistant
keys alongside BLS keys, then a later hard fork activates PQ attestations.
Ethereum is researching leanXMSS (hash-based, ~2.5 KB sigs, stateful) rather
than ML-DSA, motivated specifically by aggregation cost. The leanVM execution
environment is designed to amortize verification cost.

Qattice's architecture differs: BFT (not PoS attestation committees), smaller
initial validator set, and an explicit personhood gate that caps validator count
growth differently than ETH's permissionless deposit model. These differences
may make ML-DSA-65 viable at Qattice's scale where it would be impractical at
Ethereum's scale. The benchmark determines which regime Qattice is in.

### Finality note

The 3-second p99 target applies to the 50 ms one-way latency profile. Global
network paths exceeding 150 ms RTT (e.g., validator in São Paulo ↔ Tokyo) will
push beyond this target. The benchmark establishes the engineering guarantee,
not the worst-case global guarantee. Phase D documents the ceiling.

---

## Deliverables

1. `chain-forge-crypto/benches/mldsa_validator.rs` — Phase A criterion benchmark
2. Phase B serialization measurements (inline in benchmark binary or separate)
3. `chain-forge-node/benches/bft_round_mldsa.rs` — Phase C simulation
4. Results document: `docs/pq-val-001b-results.md` (written after execution)
5. Go/no-go decision recorded in `docs/pq-val-001b-results.md` with the chosen
   PQ-VAL-002 path

---

## Decision gate

| Phase C result | Action |
|---|---|
| p99 < 3,000 ms | Proceed to PQ-VAL-002 with ML-DSA-65 consensus activation |
| p99 3,000–5,000 ms | Proceed with activation ceiling (governance-set max validator count) |
| p99 > 5,000 ms | Revisit scheme; consider hybrid or deferred consensus path |
