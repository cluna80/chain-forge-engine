//! # qcb-seed
//!
//! QCB devnet seed tool — creates a `ResearchObjective` and populates it with
//! cryptographic challenge tasks ready for miners to pick up.
//!
//! ## Challenge: SHA-256 Partial Preimage Search
//!
//! This is a real cryptographic problem with a clean, independently verifiable
//! answer:
//!
//! > Given a 64-bit `seed` S, find a 64-bit nonce N in a search range such
//! > that SHA-256(S || N) has at least `difficulty` leading zero bits.
//!
//! - Difficulty 8  → 1 leading zero byte   → avg ~256 hashes  (instant)
//! - Difficulty 16 → 2 leading zero bytes   → avg ~65 536 hashes (~ms)
//! - Difficulty 24 → 3 leading zero bytes   → avg ~16 M hashes  (~seconds)
//!
//! The default for this test is **difficulty 16** — fast enough to finish in
//! well under a minute on any machine, but real enough to stress the pipeline.
//!
//! Each task covers a non-overlapping 500 000-nonce slice of a 50 000 000
//! nonce search space, giving 100 tasks total for 3 miners to race through.
//!
//! ## Usage
//!
//! ```bash
//! # Seed with defaults (MemDb dry-run mode — prints what would be inserted)
//! qcb-seed --dry-run
//!
//! # Seed against a live Postgres instance
//! qcb-seed --database-url postgres://user:pass@localhost/qcb
//!
//! # Custom objective / difficulty
//! qcb-seed --database-url postgres://... \
//!           --challenge-id SHA256-PREIMAGE-001 \
//!           --difficulty 16 \
//!           --task-count 100 \
//!           --range-per-task 500000
//! ```

mod challenge;
mod plan;

use clap::Parser;
use tracing::{info, warn};
use uuid::Uuid;

use chain_forge_research_db::{
    MemResearchDb,
    ResearchDb,
    models::{NewObjective, NewTask},
};

// ── CLI ───────────────────────────────────────────────────────────────────────

/// QCB seed tool — populate the research DB with SHA-256 preimage challenges.
#[derive(Parser, Debug)]
#[command(name = "qcb-seed", version, about)]
struct Args {
    /// Postgres connection string. If omitted, runs in dry-run mode against
    /// an in-memory DB and prints a summary without writing to Postgres.
    #[arg(long, env = "QCB_DATABASE_URL")]
    database_url: Option<String>,

    /// Slug / display name for the objective
    #[arg(long, default_value = "sha256-preimage-hunt")]
    slug: String,

    /// Unique challenge identifier (reuse to resume an existing objective)
    #[arg(long, default_value = "SHA256-PREIMAGE-001")]
    challenge_id: String,

    /// Number of tasks to create (each covers a non-overlapping nonce slice)
    #[arg(long, default_value = "100")]
    task_count: u64,

    /// Nonces per task (range_end - range_start per task)
    #[arg(long, default_value = "500000")]
    range_per_task: u64,

    /// Difficulty in leading zero BITS (8 = 1 byte, 16 = 2 bytes, 24 = 3 bytes)
    #[arg(long, default_value = "16")]
    difficulty: u32,

    /// Global seed used for all tasks (miners use this + their nonce range)
    #[arg(long, default_value = "31415926535897932")]
    global_seed: i64,

    /// Verification quorum — how many miners must agree before a result is accepted
    #[arg(long, default_value = "2")]
    verification_quorum: u32,

    /// Dry-run: use in-memory DB and print summary only (no Postgres needed)
    #[arg(long)]
    dry_run: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qcb_seed=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    let use_mem = args.dry_run || args.database_url.is_none();
    if use_mem {
        warn!("Running in DRY-RUN mode — using in-memory DB, nothing written to Postgres");
    }

    if use_mem {
        let db = MemResearchDb::new();
        run(&db, &args).await;
    } else {
        // Live Postgres path
        let url = args.database_url.as_deref().unwrap();
        match chain_forge_research_db::PgResearchDb::connect(url).await {
            Ok(db) => run(&db, &args).await,
            Err(e) => {
                eprintln!("Failed to connect to Postgres: {e}");
                std::process::exit(1);
            }
        }
    }
}

// ── Core seeding logic (works with any ResearchDb impl) ───────────────────────

async fn run(db: &impl ResearchDb, args: &Args) {
    let objective_id = Uuid::new_v4().to_string();
    let total_nonces = args.task_count * args.range_per_task;

    // ── Print the plan ────────────────────────────────────────────────────────
    plan::print_plan(args, &objective_id, total_nonces);

    // ── Create the objective ──────────────────────────────────────────────────
    let verification_spec = serde_json::json!({
        "type":             "sha256_preimage",
        "difficulty_bits":  args.difficulty,
        "global_seed":      args.global_seed,
        "algorithm":        "sha256-preimage-v1",
        "description":      format!(
            "Find nonce N in range such that SHA-256(seed || N) has {} leading zero bits",
            args.difficulty
        ),
    });

    let obj = NewObjective {
        objective_id:        objective_id.clone(),
        challenge_id:        args.challenge_id.clone(),
        slug:                args.slug.clone(),
        track:               "cryptographic-search".to_string(),
        algorithm_version:   "sha256-preimage-v1".to_string(),
        range_start:         0,
        range_end:           total_nonces,
        workload_class:      "cpu".to_string(),
        verification_spec,
        verification_quorum: args.verification_quorum,
    };

    match db.insert_objective(obj).await {
        Ok(row) => info!(objective_id = %row.objective_id, slug = %row.slug, "Objective created"),
        Err(e) => {
            eprintln!("Failed to insert objective: {e}");
            std::process::exit(1);
        }
    }

    // ── Create tasks ──────────────────────────────────────────────────────────
    let tasks: Vec<NewTask> = (0..args.task_count)
        .map(|i| {
            let range_start = i * args.range_per_task;
            let range_end   = range_start + args.range_per_task;
            // Each task gets a unique derived seed = global_seed XOR task_index
            // so miners searching different ranges don't all hash the same values.
            let input_seed  = args.global_seed ^ (i as i64);
            NewTask {
                task_id:        format!("task-{objective_id}-{i:04}"),
                objective_id:   objective_id.clone(),
                range_start,
                range_end,
                workload_class: "cpu".to_string(),
                input_seed:     input_seed as u64,
            }
        })
        .collect();

    let task_count = tasks.len();
    match db.upsert_tasks(tasks).await {
        Ok(n) => info!(tasks_inserted = n, "Tasks created"),
        Err(e) => {
            eprintln!("Failed to insert tasks: {e}");
            std::process::exit(1);
        }
    }

    // ── Verify one task's challenge to prove it's solvable ───────────────────
    info!("Verifying challenge is solvable on task 0 (quick sanity check)...");
    let seed_0     = args.global_seed ^ 0i64;
    let range_end  = args.range_per_task.min(10_000_000);
    match challenge::verify_solvable(seed_0, 0, range_end as i64, args.difficulty) {
        Some((nonce, hash_hex)) => {
            info!(
                nonce      = nonce,
                hash_prefix = &hash_hex[..8],
                difficulty  = args.difficulty,
                "✓ Challenge verified — found solution in task 0"
            );
        }
        None => {
            warn!(
                "No solution found for task 0 in first {} nonces with difficulty {}. \
                 Try lowering --difficulty or increasing --range-per-task.",
                range_end, args.difficulty
            );
        }
    }

    // ── Final summary ─────────────────────────────────────────────────────────
    println!();
    println!("════════════════════════════════════════════════════════");
    println!("  QCB Seed complete");
    println!("════════════════════════════════════════════════════════");
    println!("  Objective ID : {objective_id}");
    println!("  Challenge    : {}", args.challenge_id);
    println!("  Tasks        : {task_count}");
    println!("  Difficulty   : {} leading zero bits", args.difficulty);
    println!("  Global seed  : {}", args.global_seed);
    println!("  Total nonces : {total_nonces}");
    println!();
    println!("  Run a miner with:");
    println!();
    println!("    qcb-miner \\");
    println!("      --node-url http://192.168.137.2:8080 \\");
    println!("      --miner-id <your-machine-name> \\");
    println!("      --objective-id {objective_id}");
    println!();
    if args.dry_run || args.database_url.is_none() {
        println!("  (Dry-run: add --database-url postgres://... to persist to Postgres)");
        println!();
    }
}
