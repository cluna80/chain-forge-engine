//! Pretty-prints the seeding plan before any DB writes happen.

use crate::Args;

/// Print the plan for PoCD (partial preimage search) mode.
pub fn print_plan(args: &Args, objective_id: &str, total_nonces: u64) {
    let avg_hashes_per_solution = 2u64.pow(args.difficulty);
    let expected_solutions = total_nonces / avg_hashes_per_solution;

    println!();
    println!("════════════════════════════════════════════════════════");
    println!("  QCB PoCD Seed Plan — SHA-256 Partial Preimage Search");
    println!("════════════════════════════════════════════════════════");
    println!("  Objective ID      : {objective_id}");
    println!("  Challenge ID      : {}", args.challenge_id);
    println!("  Slug              : {}", args.slug);
    println!("  Track             : cryptographic-search");
    println!();
    println!("  ── Challenge parameters ─────────────────────────────");
    println!("  Algorithm         : SHA-256 partial preimage");
    println!("  Global seed       : {}", args.global_seed);
    println!("  Difficulty        : {} leading zero bits", args.difficulty);
    println!("  Avg hashes/task   : ~{}", avg_hashes_per_solution);
    println!();
    println!("  ── Task layout ──────────────────────────────────────");
    println!("  Task count        : {}", args.task_count);
    println!("  Nonces per task   : {}", args.range_per_task);
    println!("  Total nonce space : {total_nonces}");
    println!("  Expected solutions: ~{expected_solutions} across all tasks");
    println!();
    println!("  ── Verification ─────────────────────────────────────");
    println!("  Quorum required   : {} miners must agree", args.verification_quorum);
    println!("  How miners verify : re-run SHA-256(seed || winning_nonce),");
    println!("                      check leading zeros, hash result → content_hash");
    println!();

    if args.dry_run || args.database_url.is_none() {
        println!("  ⚠  DRY-RUN — writing to in-memory DB only");
    } else {
        println!("  ✓  LIVE — writing to Postgres");
    }
    println!("════════════════════════════════════════════════════════");
    println!();
}

/// Print the plan for avalanche experiment mode.
pub fn print_avalanche_plan(args: &Args, objective_id: &str) {
    let primary_count     = args.seed_count as u64 * 256;
    let replication_count = ((primary_count as f64 * 0.05).ceil()) as u64;
    let total_tasks       = primary_count + replication_count;

    println!();
    println!("════════════════════════════════════════════════════════");
    println!("  QCB Avalanche Seed Plan — SHA-256 Avalanche Experiment");
    println!("════════════════════════════════════════════════════════");
    println!("  Objective ID      : {objective_id}");
    println!("  Challenge ID      : {}", args.challenge_id);
    println!("  Slug              : {}", args.slug);
    println!("  Track             : cryptographic-research");
    println!();
    println!("  ── Experiment parameters ────────────────────────────");
    println!("  Algorithm         : SHA-256 avalanche effect measurement");
    println!("  Canonical seeds   : {} (indices 0..{})", args.seed_count, args.seed_count - 1);
    println!("  Bit positions     : 256 (indices 0..255)");
    println!("  Seed derivation   : SHA-256('qcb-avalanche-v1' || objective_id || seed_index_le64)");
    println!("  Bit flip rule     : byte = bit/8; shift = 7 - (bit%8)  [MSB = bit 7 of byte 0]");
    println!();
    println!("  ── Task layout ──────────────────────────────────────");
    println!("  Primary tasks     : {} ({} seeds × 256 bit positions)", primary_count, args.seed_count);
    println!("  Replication tasks : {} (5% cross-machine sample)", replication_count);
    println!("  Total tasks       : {total_tasks}");
    println!("  Primary miner     : {}",
        args.primary_miner_id.as_deref().unwrap_or("(dry-run-miner)"));
    println!("  Replication miner : DIFFERENT machine (enforced by exclude_miner filter)");
    println!();
    println!("  ── Measurement ──────────────────────────────────────");
    println!("  Per task computes : original_hash = SHA-256(canonical_seed)");
    println!("                      flipped_hash  = SHA-256(flip(seed, bit_index))");
    println!("                      xor_diff      = original XOR flipped  (256-bit vector)");
    println!("                      hamming_dist  = popcount(xor_diff)");
    println!("  content_hash      : SHA-256(original_hash_bytes || flipped_hash_bytes)");
    println!();
    println!("  ── Scientific note ──────────────────────────────────");
    println!("  Expected hamming  : ~128 bits changed per experiment (binomial p=0.5, n=256)");
    println!("  Std deviation     : ~8 bits");
    println!("  IMPORTANT: No result is automatically classified as a cryptographic");
    println!("             breakthrough. Results require independent human review.");
    println!();
    println!("  ── Verification ─────────────────────────────────────");
    println!("  Quorum required   : {} miners must agree", args.verification_quorum);
    println!("  How miners verify : recompute both hashes from (objective_id, seed_index,");
    println!("                      bit_index) — fully deterministic, no nonce search");
    println!();

    if args.dry_run || args.database_url.is_none() {
        println!("  ⚠  DRY-RUN — writing to in-memory DB only");
    } else {
        println!("  ✓  LIVE — writing to Postgres");
    }
    println!("════════════════════════════════════════════════════════");
    println!();
}
