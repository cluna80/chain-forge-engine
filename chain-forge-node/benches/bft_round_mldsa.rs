//! PQ-VAL-001b Phase C — Simulated BFT round with 1,000 ML-DSA-65 validators
//!
//! Simulates one complete BFT round (propose → prevote → precommit → commit)
//! entirely in-process with channels replacing network transport.
//! No real TCP. No gossip layer. No tokio runtime overhead beyond channels.
//!
//! Run with:
//!   cargo bench -p chain-forge-node --bench bft_round_mldsa
//!
//! Pass criteria (from pq-val-001b-benchmark-spec.md):
//!   - Full round wall-clock p50 < 2,000 ms
//!   - Full round wall-clock p99 < 3,000 ms   ← gate for PQ-VAL-002
//!   - Sign phase  (1,000 prevotes)    < 500 ms
//!   - Sign phase  (1,000 precommits)  < 500 ms
//!   - Verify phase (667+ prevotes)    < 500 ms
//!   - Verify phase (667+ precommits)  < 500 ms
//!   - Memory high-water mark          < 512 MB

use criterion::{criterion_group, criterion_main, Criterion};
use rayon::prelude::*;
use std::time::Instant;

use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const N_VALIDATORS: usize = 1_000;
const QUORUM: usize = 667; // ceil(2/3 * 1000) + 1 = 667
const CHAIN_ID: &str = "qattice-devnet-1";
const BLOCK_HASH: [u8; 32] = [0xca; 32];
const BLOCK_HEIGHT: u64 = 1;
const ROUND: u32 = 0;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Prevote: validator signs (height || round || block_hash)
fn prevote_msg(height: u64, round: u32, block_hash: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(44);
    m.extend_from_slice(b"PREVOTE|");
    m.extend_from_slice(CHAIN_ID.as_bytes());
    m.push(b'|');
    m.extend_from_slice(&height.to_le_bytes());
    m.extend_from_slice(&round.to_le_bytes());
    m.extend_from_slice(block_hash);
    m
}

/// Precommit: validator signs (height || round || block_hash)
fn precommit_msg(height: u64, round: u32, block_hash: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(47);
    m.extend_from_slice(b"PRECOMMIT|");
    m.extend_from_slice(CHAIN_ID.as_bytes());
    m.push(b'|');
    m.extend_from_slice(&height.to_le_bytes());
    m.extend_from_slice(&round.to_le_bytes());
    m.extend_from_slice(block_hash);
    m
}

// ---------------------------------------------------------------------------
// Validator fixture: keypair pre-generated at benchmark setup time
// ---------------------------------------------------------------------------

struct Validator {
    #[allow(dead_code)]
    id: String,
    kp: chain_forge_crypto::KeyPair,
}

fn generate_validators(n: usize) -> Vec<Validator> {
    (0..n)
        .into_par_iter()
        .map(|i| {
            let kp = MlDsaScheme
                .generate_keypair(&format!("bft-round-validator-{i}"))
                .expect("keygen");
            Validator {
                id: format!("val{i:06}"),
                kp,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Phase C: one full BFT round
// ---------------------------------------------------------------------------

struct RoundResult {
    propose_ms:         u128,
    prevote_sign_ms:    u128,
    prevote_verify_ms:  u128,
    precommit_sign_ms:  u128,
    precommit_verify_ms: u128,
    total_ms:           u128,
}

fn simulate_bft_round(validators: &[Validator]) -> RoundResult {
    let scheme = MlDsaScheme;
    let t_round_start = Instant::now();

    // ---- Step 1: Leader signs proposal ----
    let t0 = Instant::now();
    let leader = &validators[0];
    let proposal_msg = {
        let mut m = Vec::new();
        m.extend_from_slice(b"PROPOSAL|");
        m.extend_from_slice(CHAIN_ID.as_bytes());
        m.push(b'|');
        m.extend_from_slice(&BLOCK_HEIGHT.to_le_bytes());
        m.extend_from_slice(&ROUND.to_le_bytes());
        m.extend_from_slice(&BLOCK_HASH);
        m.extend_from_slice(&leader.kp.public_key); // pubkey in proposal
        m
    };
    let _proposal_sig = scheme.sign(&proposal_msg, &leader.kp).expect("proposal sign");
    let propose_ms = t0.elapsed().as_millis();

    // ---- Step 2: All 1,000 validators sign prevote (parallel) ----
    let prevote_msg = prevote_msg(BLOCK_HEIGHT, ROUND, &BLOCK_HASH);
    let t1 = Instant::now();
    let prevotes: Vec<chain_forge_crypto::Signature> = validators
        .par_iter()
        .map(|v| scheme.sign(&prevote_msg, &v.kp).expect("prevote sign"))
        .collect();
    let prevote_sign_ms = t1.elapsed().as_millis();

    // ---- Step 3: Leader verifies quorum of prevotes (667) ----
    let t2 = Instant::now();
    let prevote_ok: usize = validators[..QUORUM]
        .par_iter()
        .zip(prevotes[..QUORUM].par_iter())
        .filter(|(v, sig)| {
            scheme
                .verify(&prevote_msg, sig, &v.kp.public_key)
                .is_ok()
        })
        .count();
    let prevote_verify_ms = t2.elapsed().as_millis();
    assert_eq!(prevote_ok, QUORUM, "prevote quorum verification failed");

    // ---- Step 4: All 1,000 validators sign precommit (parallel) ----
    let precommit_msg = precommit_msg(BLOCK_HEIGHT, ROUND, &BLOCK_HASH);
    let t3 = Instant::now();
    let precommits: Vec<chain_forge_crypto::Signature> = validators
        .par_iter()
        .map(|v| scheme.sign(&precommit_msg, &v.kp).expect("precommit sign"))
        .collect();
    let precommit_sign_ms = t3.elapsed().as_millis();

    // ---- Step 5: Leader aggregates and verifies quorum of precommits (667) ----
    let t4 = Instant::now();
    let precommit_ok: usize = validators[..QUORUM]
        .par_iter()
        .zip(precommits[..QUORUM].par_iter())
        .filter(|(v, sig)| {
            scheme
                .verify(&precommit_msg, sig, &v.kp.public_key)
                .is_ok()
        })
        .count();
    let precommit_verify_ms = t4.elapsed().as_millis();
    assert_eq!(precommit_ok, QUORUM, "precommit quorum verification failed");

    // ---- Commit certificate formed ----
    let total_ms = t_round_start.elapsed().as_millis();

    RoundResult {
        propose_ms,
        prevote_sign_ms,
        prevote_verify_ms,
        precommit_sign_ms,
        precommit_verify_ms,
        total_ms,
    }
}

// ---------------------------------------------------------------------------
// Criterion benchmark wrapper
// ---------------------------------------------------------------------------

fn bench_bft_round(c: &mut Criterion) {
    // Generate validators once — this is setup cost, not measured
    println!("\nGenerating {} ML-DSA-65 keypairs (setup, not timed)…", N_VALIDATORS);
    let t_setup = Instant::now();
    let validators = generate_validators(N_VALIDATORS);
    println!("Setup complete in {} ms\n", t_setup.elapsed().as_millis());

    // Collect individual round timings for p50/p99 reporting
    let mut all_results: Vec<RoundResult> = Vec::new();

    let mut group = c.benchmark_group("bft_round_mldsa");
    group.sample_size(10); // 10 full rounds; each takes ~seconds

    group.bench_function("full_round_1000_validators", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let t = Instant::now();
                let result = simulate_bft_round(&validators);
                total += t.elapsed();
                all_results.push(result);
            }
            total
        })
    });

    group.finish();

    // ---- Print Phase C summary ----
    if !all_results.is_empty() {
        let mut totals: Vec<u128> = all_results.iter().map(|r| r.total_ms).collect();
        totals.sort_unstable();
        let n = totals.len();
        let p50 = totals[n / 2];
        let p99 = totals[(n * 99 / 100).min(n - 1)];

        println!();
        println!("=== PQ-VAL-001b Phase C — BFT Round Simulation ({N_VALIDATORS} validators, {n} rounds) ===");
        println!("  Propose sign (leader):          {:>5} ms  (last round)", all_results.last().unwrap().propose_ms);
        println!("  Prevote sign  (1,000 parallel): {:>5} ms  (last round)", all_results.last().unwrap().prevote_sign_ms);
        println!("  Prevote verify ({QUORUM} parallel):  {:>5} ms  (last round)", all_results.last().unwrap().prevote_verify_ms);
        println!("  Precommit sign (1,000 parallel):{:>5} ms  (last round)", all_results.last().unwrap().precommit_sign_ms);
        println!("  Precommit verify ({QUORUM} parallel):{:>4} ms  (last round)", all_results.last().unwrap().precommit_verify_ms);
        println!("  ──────────────────────────────────────────");
        println!("  Full round p50: {:>5} ms", p50);
        println!("  Full round p99: {:>5} ms", p99);
        println!();

        let gate_p99 = p99 < 3_000;
        let gate_p50 = p50 < 2_000;
        println!(
            "  PQ-VAL-002 gate (p99 < 3,000 ms): {}",
            if gate_p99 { "✅ PASS — proceed to PQ-VAL-002 with ML-DSA-65" } else { "❌ FAIL — revisit scheme" }
        );
        println!(
            "  p50 target  (p50 < 2,000 ms):     {}",
            if gate_p50 { "✅ PASS" } else { "⚠️  MISS" }
        );
        println!();

        // Phase sub-timings pass criteria
        let last = all_results.last().unwrap();
        let sub_pass = [
            ("Prevote sign   < 500 ms", last.prevote_sign_ms < 500),
            ("Prevote verify < 500 ms", last.prevote_verify_ms < 500),
            ("Precommit sign < 500 ms", last.precommit_sign_ms < 500),
            ("Precommit verify < 500 ms", last.precommit_verify_ms < 500),
        ];
        for (label, pass) in &sub_pass {
            println!("  {}: {}", label, if *pass { "✅" } else { "❌" });
        }
        println!();
    }
}

criterion_group!(benches, bench_bft_round);
criterion_main!(benches);
