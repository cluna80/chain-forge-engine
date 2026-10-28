# Qattice Committee Sampling — Certificate Scheme and Randomness Beacon Comparison

Status: Research note supporting Section 7 of the validator economics spec. Not a final decision.
Date: 2026-10-28

## 1. Measured baseline (ML-DSA-65, FIPS 204)

Measured with the native `pqcrypto` ML-DSA-65 binding (`scripts/bench_cert_mldsa65_native.py`, 500 runs each). Sizes match the standard. An earlier pure-Python run (`scripts/bench_cert_mldsa65.py`) gave verify times about 45x slower and is kept only as a cross-check.

| Item | Value |
|---|---|
| Public key | 1,952 bytes |
| Signature | 3,309 bytes |
| Sign (median, 500 runs) | ~11.1 ms |
| Verify (median, 500 runs) | ~0.22 ms |

Naive certificate (C ML-DSA signatures concatenated):

| Committee C | Certificate size | Serial verify time (native, naive) |
|---|---|---|
| 32 | ~103 KiB | ~7 ms |
| 128 | ~414 KiB | ~28 ms |
| 256 | ~827 KiB | ~56 ms |
| 512 | ~1,654 KiB | ~112 ms |

Second machine (Windows 11, MINGW64, Python with `pqcrypto` 1.0.0 wheel, same script, 500 runs each):

| Item | Linux sandbox | Windows (second machine) |
|---|---|---|
| Sign (median) | ~11.1 ms | ~10.2 ms |
| Verify (median) | ~0.22 ms | ~0.24 ms |
| Serial verify, C = 128 | ~28 ms | ~30 ms |
| Serial verify, C = 512 | ~112 ms | ~121 ms |

Sizes are identical on both machines. The two machines agree within about 10%, so the timings are stable enough for planning. They are still two data points, not a benchmark suite.

Naive certificates are not acceptable at block frequency. The schemes below are compared against this baseline.

## 2. Certificate scheme options

### Option A — Hash-based multi-signature

Signatures built only from hash functions (for example, SLH-DSA/SPHINCS+ or XMSS-style schemes) are the conservative post-quantum choice because their security rests on hash assumptions alone.

- **Size:** Individual hash-based signatures are large. SLH-DSA small variants are roughly 8 KB per signature, so naive concatenation is worse than ML-DSA. Aggregation is the only way this works.
- **Aggregation:** Standard hash-based signatures do not aggregate the way BLS does. Multi-signature constructions exist in research, but none is standardized for this use.
- **Verification cost:** Low per signature, but aggregated verification depends on the construction.
- **Assumptions:** Hash function security only. Most conservative.
- **Maturity:** Signature standards are mature; aggregation is not.

### Option B — Succinct proof of committee signatures

Prove, in a zero-knowledge or succinct proof system, that C valid ML-DSA signatures exist over the block hash from members of the committee. The certificate becomes one proof instead of C signatures.

- **Size:** A STARK-style proof is typically tens to hundreds of KB and does not grow linearly with C. The exact size depends on the proof system and parameters, which must be measured.
- **Verification cost:** Verifying a proof is much cheaper than verifying C signatures, but the verifier still does real hashing work.
- **Proving cost:** Heavy. Proving ML-DSA verification inside a circuit is expensive, and the prover runs during block production. This may be the hardest practical constraint.
- **Assumptions:** Hash-based proof systems (STARK direction) are post-quantum. The circuit must correctly encode ML-DSA verification.
- **Maturity:** Proof systems are active research. Circuits for ML-DSA are not established. This option also ties into the existing ZK roadmap item.

### Option C — Smaller committee

Keep naive ML-DSA certificates but reduce C.

- **Size:** Linear in C. C = 64 would be roughly 207 KiB; C = 32 would be roughly 104 KiB.
- **Verification cost:** Linear in C, but small.
- **Safety:** A smaller committee is more likely to be dishonest or offline. The honest-majority threshold has to be stated per committee, and sampling variance rises as C shrinks.
- **Assumptions:** Unchanged signature assumptions. Safety depends on the sampling model.
- **Maturity:** Immediately implementable. The cost is in safety analysis, not engineering.

### Option D — Falcon (FN-DSA), noted for completeness

Falcon signatures are about 666 bytes with a 897-byte public key, roughly a fifth the size of ML-DSA-65 signatures. Like ML-DSA, it has no standard aggregation, so naive certificates would still scale with C. It could shrink Option C's numbers but does not solve the aggregation problem. Its implementation is harder to get constant-time, which is a practical concern.

## 3. Comparison summary

| Option | Certificate size per block | Verification | Proving cost | Post-quantum assumption | Maturity |
|---|---|---|---|---|---|
| Naive ML-DSA, C = 512 | ~1.6 MiB | Linear, ~112 ms serial (native) | None | ML-DSA (lattice) | Standard, but size fails |
| A. Hash multi-sig | Unknown until scheme chosen | Depends on scheme | None | Hash only | Aggregation not standard |
| B. Succinct proof | Tens to hundreds of KB (to measure) | Fast | Heavy | Hash-based proof system | Research; ML-DSA circuit not established |
| C. Smaller committee | ~3.2 KiB per 1 signature (linear) | Linear, small | None | ML-DSA (lattice) | Ready; safety analysis needed |
| D. Falcon with C | ~0.65 KB per signature (linear) | Linear | None | Lattice (Falcon) | Standard; aggregation missing; harder to implement safely |

## 4. Recommendation

Start with **Option C plus a measured Option B prototype**, and keep Option A as the long-term conservative candidate.

- Option C is the only option that works today with a standard signature. It can be specified now, with a committee size chosen by safety analysis rather than size alone.
- Option B is the most promising path to large committees, but its proving cost is unknown. A prototype should measure proving time and proof size for a fixed committee size before any decision.
- Option A should be tracked for an aggregation standard. If one appears, it may remove the need for B.

This is a recommendation for research, not a protocol decision.

## 5. Randomness beacon options

The beacon produces the seed that selects each epoch's committee. It must be unpredictable before reveal, verifiable after reveal, and must not depend on any single party.

### Option 1 — Commit-reveal with threshold reveal

Each participant commits to a secret value, then reveals it. A threshold scheme lets any sufficiently large group reconstruct the output even if some participants withhold their reveal.

- **Post-quantum status:** The commitment can be hash-based, which is post-quantum. The threshold secret sharing and the reveal mechanism must also be post-quantum. Lattice-based threshold schemes exist in research but are not standardized, so this is the open part.
- **Assumptions:** Honest majority of participants plus a post-quantum secret-sharing primitive.
- **Known weakness:** Participants who withhold reveals can bias the output (the last-revealer problem). The threshold design limits this but does not eliminate it.
- **Engineering:** Simpler to implement and to reason about. Easier to prototype first.

### Option 2 — Verifiable delay function (VDF)

A VDF requires a fixed amount of sequential computation to produce an output, then yields a proof that anyone can check quickly. No one can predict the output before the delay has passed.

- **Post-quantum status:** Most practical VDFs rely on RSA groups or class groups. Shor's algorithm breaks both, so these are not post-quantum. A post-quantum VDF would need a different construction, such as one built on hash chains with succinct proofs, and that is research.
- **Assumptions:** Sequential computation cannot be sped up. Hash-based constructions could fit, but none is standard.
- **Engineering:** The delay has to be tuned against hardware speed, and the verification proof adds design work.

### Recommendation for the beacon

Start with **Option 1 (commit-reveal with threshold reveal)**. It is the simpler design to specify and the threshold primitive is the research item to fund. Treat Option 2 as a second option that is not post-quantum with the standard constructions, so it is not usable for Qattice until a post-quantum VDF exists.

## 6. Next steps

1. Write a short spec for Option 1 with the threshold primitive named as an open item.
2. Measure a succinct-proof prototype (Option B) for a fixed committee size, recording proof size, proving time, and verification time.
3. Set the committee size from a safety analysis, combining Option C numbers with the sampling model.
4. Revisit Option A and Falcon as aggregation standards and implementations mature.

## 7. Limits of this note

- Timings are from one machine (Linux sandbox) and one native binding. Re-run on the target hardware before any timing goes into the spec.
- The Option B proving cost, Option A aggregation, and post-quantum threshold primitives are not measured or standardized. Treat those rows as hypotheses.
- Sizes for SLH-DSA and Falcon are from memory of the standards and should be confirmed against the FIPS documents before publication.
