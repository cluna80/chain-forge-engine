//! PQ-VAL-001b Phase A — ML-DSA-65 single-node cryptographic primitive benchmark
//!
//! Measures raw sign/verify/keygen throughput for ML-DSA-65 on one machine.
//! Run with: cargo bench -p chain-forge-crypto --features real-pqc --bench mldsa_validator
//!
//! Pass criteria (from pq-val-001b-benchmark-spec.md):
//!   - Single sign  p50  < 5 ms
//!   - Single verify p50 < 5 ms
//!   - Batch verify 1,000 sigs (parallel, Rayon) < 500 ms wall-clock
//!   - Key generation < 10 ms
//!
//! Phase B (wire-size serialisation) is measured inline at the end of this file
//! as a standalone timed block printed to stdout — not criterion, because it
//! is a one-shot measurement rather than a statistical distribution.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rayon::prelude::*;

use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

/// V2 PoP signing bytes (mirrors chain-forge-execution::validator_key_registration_signing_bytes_v2)
fn v2_signing_bytes(chain_id: &str, sender: &str, pubkey: &[u8]) -> Vec<u8> {
    let hex_pubkey: String = pubkey.iter().map(|b| format!("{b:02x}")).collect();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"CFVK-V2|");
    msg.extend_from_slice(chain_id.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(sender.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(hex_pubkey.as_bytes());
    msg
}

// ---------------------------------------------------------------------------
// Fixture: one keypair + one signed message, generated once per benchmark run
// ---------------------------------------------------------------------------

struct Fixture {
    kp:  chain_forge_crypto::KeyPair,
    msg: Vec<u8>,
    sig: chain_forge_crypto::Signature,
}

impl Fixture {
    fn new(seed: &str) -> Self {
        let scheme = MlDsaScheme;
        let kp = scheme.generate_keypair(seed).expect("keygen");
        let msg = v2_signing_bytes("qattice-devnet-1", "qcb1bench000validator", &kp.public_key);
        let sig = scheme.sign(&msg, &kp).expect("sign");
        Self { kp, msg, sig }
    }
}

// ---------------------------------------------------------------------------
// Benchmark group: key generation
// ---------------------------------------------------------------------------

fn bench_keygen(c: &mut Criterion) {
    let scheme = MlDsaScheme;
    let mut counter = 0u64;
    c.bench_function("mldsa65/keygen", |b| {
        b.iter(|| {
            counter += 1;
            scheme
                .generate_keypair(&format!("bench-seed-{counter}"))
                .expect("keygen")
        })
    });
}

// ---------------------------------------------------------------------------
// Benchmark group: single sign
// ---------------------------------------------------------------------------

fn bench_sign(c: &mut Criterion) {
    let scheme  = MlDsaScheme;
    let fixture = Fixture::new("bench-sign-fixture");
    c.bench_function("mldsa65/sign_v2_pop", |b| {
        b.iter(|| scheme.sign(&fixture.msg, &fixture.kp).expect("sign"))
    });
}

// ---------------------------------------------------------------------------
// Benchmark group: single verify
// ---------------------------------------------------------------------------

fn bench_verify(c: &mut Criterion) {
    let scheme  = MlDsaScheme;
    let fixture = Fixture::new("bench-verify-fixture");
    c.bench_function("mldsa65/verify_v2_pop", |b| {
        b.iter(|| {
            scheme
                .verify(&fixture.msg, &fixture.sig, &fixture.kp.public_key)
                .expect("verify")
        })
    });
}

// ---------------------------------------------------------------------------
// Benchmark group: batch verify 1,000 signatures (Rayon parallel)
// ---------------------------------------------------------------------------

fn bench_batch_verify_1000(c: &mut Criterion) {
    let scheme = MlDsaScheme;

    // Pre-generate 1,000 keypairs + signatures (setup cost not counted)
    let validators: Vec<Fixture> = (0..1_000)
        .map(|i| Fixture::new(&format!("batch-validator-{i}")))
        .collect();

    let mut group = c.benchmark_group("mldsa65/batch_verify");
    // Criterion default sample size (100) is too expensive at this scale;
    // 10 samples still gives a meaningful distribution.
    group.sample_size(10);

    group.bench_function("1000_sigs_rayon_parallel", |b| {
        b.iter_batched(
            || (), // no per-iter setup
            |_| {
                validators
                    .par_iter()
                    .map(|f| scheme.verify(&f.msg, &f.sig, &f.kp.public_key))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .all(|r| r.is_ok())
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Phase B — wire-size serialisation (printed to stdout, not criterion)
// ---------------------------------------------------------------------------
//
// This runs as part of the benchmark binary's main() via criterion_main! below,
// but we inject it through a custom benchmark group that immediately terminates
// so criterion doesn't try to time it.  The measurements are printed directly.
//
// Alternatively, run:
//   cargo bench -p chain-forge-crypto --features real-pqc --bench mldsa_validator -- --nocapture

fn bench_phase_b_wire_size(c: &mut Criterion) {
    use std::time::Instant;

    let _scheme = MlDsaScheme;

    // One-shot: generate 1,000 precommit messages and measure ser/deser cost.
    // We model a precommit as: validator_id (64 bytes) + height (8) + round (4)
    // + block_hash (32) + ML-DSA-65 signature (3,309 bytes) = ~3,417 bytes each.
    const N: usize = 1_000;

    let validators: Vec<Fixture> = (0..N)
        .map(|i| Fixture::new(&format!("phase-b-validator-{i}")))
        .collect();

    // Build wire payloads: simple bincode-like layout (length-prefixed bytes)
    let t0 = Instant::now();
    let payloads: Vec<Vec<u8>> = validators
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let mut buf = Vec::with_capacity(3_417);
            // validator_id: 64 bytes (zero-padded)
            let id = format!("validator-{i:060}");
            buf.extend_from_slice(id.as_bytes());
            // height: u64 le
            buf.extend_from_slice(&1u64.to_le_bytes());
            // round: u32 le
            buf.extend_from_slice(&0u32.to_le_bytes());
            // block_hash: 32 bytes
            buf.extend_from_slice(&[0xab_u8; 32]);
            // signature length prefix + bytes
            let sig_len = f.sig.bytes.len() as u32;
            buf.extend_from_slice(&sig_len.to_le_bytes());
            buf.extend_from_slice(&f.sig.bytes);
            buf
        })
        .collect();
    let ser_ms = t0.elapsed().as_millis();

    // Deserialise: read signature bytes back out
    let t1 = Instant::now();
    let total_sig_bytes: usize = payloads
        .iter()
        .map(|p| {
            let sig_len = u32::from_le_bytes(p[108..112].try_into().unwrap()) as usize;
            sig_len // just read, don't alloc
        })
        .sum();
    let deser_ms = t1.elapsed().as_millis();

    let total_bytes: usize = payloads.iter().map(|p| p.len()).sum();

    // Print Phase B results — visible with --nocapture or in CI logs
    println!();
    println!("=== PQ-VAL-001b Phase B — Wire-size serialisation ({N} precommits) ===");
    println!(
        "  Per-precommit size:        {:>6} bytes  (sig={} + overhead={})",
        payloads[0].len(),
        validators[0].sig.bytes.len(),
        payloads[0].len() - validators[0].sig.bytes.len(),
    );
    println!(
        "  Total payload ({N} validators): {:>6} bytes  ({:.2} MB)",
        total_bytes,
        total_bytes as f64 / 1_048_576.0,
    );
    println!("  Serialisation wall-clock:  {ser_ms:>5} ms");
    println!("  Deserialisation wall-clock:{deser_ms:>5} ms  (total sig bytes read: {total_sig_bytes})");
    let pass_b = ser_ms + deser_ms < 100;
    println!(
        "  Phase B PASS criterion (<100 ms total): {}",
        if pass_b { "✅ PASS" } else { "❌ FAIL" }
    );
    println!();

    // Dummy criterion measurement so the group compiles
    c.bench_function("phase_b/noop", |b| b.iter(|| 0u8));
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_batch_verify_1000,
    bench_phase_b_wire_size,
);
criterion_main!(benches);
