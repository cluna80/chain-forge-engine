//! Pretty-prints the seeding plan before any DB writes happen.

use crate::Args;

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
