# Succinct Proof of Committee Signatures — Prototype Scope

Status: Scope only. No code written. Supports Option B in `certificate-and-beacon-comparison.md`.
Date: 2026-10-28

## 1. Question to answer

For a fixed committee size C, can C valid ML-DSA-65 signatures over one block hash be replaced by a single succinct proof whose size, proving time, and verification time are acceptable for block production?

"Acceptable" must be defined before measuring. Proposed thresholds (to be confirmed by the owner):

| Metric | Target | Why |
|---|---|---|
| Certificate size per block | ≤ 100 KiB at C = 512 | Naive certificate is ~1.6 MiB; must shrink by an order of magnitude |
| Verification time | ≤ 50 ms on a commodity node | Must not slow finality |
| Proving time, C = 512 | Within one block interval, on a single prover machine | Prover runs at block production |
| Post-quantum assumption | Hash-based proof system only (no pairings, no elliptic curves) | Matches the sovereignty and PQ constraints |

If the proving-time target cannot be met, the answer is "not practical at C = 512", and the fallback is a smaller committee (Option C).

## 2. What is being proven

Statement: "There exist C distinct verified-human public keys in the epoch's eligible pool, and C valid ML-DSA-65 signatures over the block hash under those keys."

Two sub-problems:

1. **Signature verification inside a circuit.** ML-DSA-65 verification uses SHAKE hashing, polynomial arithmetic over a ring, and rejection-sampling checks. Encoding this in a proof system is the expensive part and is not an established library.
2. **Membership and distinctness.** Proving the keys belong to the eligible pool (Merkle path into the pool root) and are distinct. This part is standard and cheap relative to (1).

Prototype should measure (1) first, because it dominates cost.

## 3. Candidate toolchains

Verify each one before relying on it. None has been checked for this use.

- **Plonky3** (Rust, hash-based STARK framework). Candidate for the proof system.
- **stwo** (StarkWare's Rust prover). Candidate, same category.
- **General zkVM** (run ML-DSA verification as guest code, prove execution). Fastest to prototype, probably slowest to prove.

The prototype should pick one toolchain and state why. A zkVM route is a reasonable first measurement because it needs no custom circuit.

## 4. Milestones

| # | Milestone | Output | Estimate |
|---|---|---|---|
| M0 | Confirm toolchain availability, licenses, and that a hash-based proof system runs on the target platforms | Written check, pass/fail | 1–2 days |
| M1 | Baseline: prove and verify a trivial statement (C hashes in a Merkle tree) to measure framework overhead | Size, prove, verify numbers | 2–3 days |
| M2 | Prove one ML-DSA-65 verification inside the chosen system | Cycles/constraints, prove time, proof size for C = 1 | 1–3 weeks (highest risk) |
| M3 | Scale to C = 32, 128, 512 (batched or recursive aggregation) | Size and time curve vs C | 1–2 weeks |
| M4 | Compare to Option C at the same C values; write results into the comparison doc | Decision memo | 2–3 days |

Total estimate: roughly 4–7 weeks of focused work. M2 is the gate. If one ML-DSA verification takes an unreasonable proving time, stop and report, since C = 512 cannot be met.

## 5. Measurement protocol

- Same hardware for every run; record CPU, RAM, OS, toolchain version, and commit hash.
- Run each measurement at least 5 times; report median and p95.
- Report proof size, prover time, verifier time, and peak memory.
- Negative test: a proof with one invalid signature must be rejected. Without this, the numbers mean nothing.
- Publish raw results with the script, in the same way as `bench_cert_mldsa65_native.py`.

## 6. Risks

- **ML-DSA circuit cost.** Could make proving impractical even at C = 1. Mitigation: M2 is a gate, decide early.
- **Immature tooling.** Post-quantum STARK tooling is young. Mitigation: pin versions, record breakage.
- **Trusted setup.** Must not be needed. STARK-style systems avoid it, SNARK-style with a setup would violate the PQ goal.
- **Scope creep into the full consensus.** This prototype is about certificates only. It does not touch the BFT code or the ROADMAP status.

## 7. Out of scope

- Changing `chain-forge-consensus` or any ROADMAP status.
- Choosing the randomness beacon (separate item).
- Committee size safety analysis (separate item).
- Any mainnet decision.

## 8. Decisions needed from the owner

1. Confirm the performance targets in Section 1.
2. Approve the time budget (4–7 weeks, gated at M2).
3. Choose whether to start with a zkVM route (faster to prototype) or a custom circuit (possibly faster to prove, more work).
