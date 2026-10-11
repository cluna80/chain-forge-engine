//! # qcb-seed
//!
//! QCB devnet seed tool — creates a `ResearchObjective` and populates it with
//! cryptographic challenge tasks ready for miners to pick up.
//!
//! ## Research modes
//!
//! ### `pocd` (default) — SHA-256 Partial Preimage Search
//!
//! A real cryptographic problem with a clean, independently verifiable answer:
//!
//! > Given a 64-bit `seed` S, find a 64-bit nonce N in a search range such
//! > that SHA-256(S || N) has at least `difficulty` leading zero bits.
//!
//! - Difficulty 8  → 1 leading zero byte   → avg ~256 hashes  (instant)
//! - Difficulty 16 → 2 leading zero bytes   → avg ~65 536 hashes (~ms)
//! - Difficulty 24 → 3 leading zero bytes   → avg ~16 M hashes  (~seconds)
//!
//! Each task covers a non-overlapping 500 000-nonce slice of a 50 000 000
//! nonce search space, giving 100 tasks total for miners to race through.
//!
//! ### `avalanche` — SHA-256 Avalanche Experiment
//!
//! Measures how many output bits change when a single input bit is flipped.
//! A well-designed hash function should change ~128 out of 256 bits (the
//! "avalanche effect" or "strict avalanche criterion").
//!
//! Each experiment: canonical_seed = SHA-256("qcb-avalanche-v1" || objective_id || seed_index_le64)
//!   - original_hash = SHA-256(canonical_seed)
//!   - flipped_hash  = SHA-256(flip(canonical_seed, bit_index))
//!   - xor_diff      = original_hash XOR flipped_hash  (full 256-bit vector)
//!   - hamming_dist  = popcount(xor_diff)
//!
//! Generates:
//!   - 2 560 primary tasks (10 seeds × 256 bit positions), task_kind = "avalanche_experiment"
//!   - 128 replication tasks (5% sample), task_kind = "avalanche_replication",
//!     phase1_miner_id set so the scheduler assigns them to a DIFFERENT miner.
//!
//! IMPORTANT: Avalanche experiments are deterministic measurements, not searches.
//! No result is automatically classified as a cryptographic breakthrough.
//!
//! ## Usage
//!
//! ```bash
//! # PoCD mode (default) — dry-run
//! qcb-seed --dry-run
//!
//! # PoCD mode against a live scheduler
//! qcb-seed --node-url http://192.168.137.2:8080
//!
//! # Avalanche mode against a live scheduler
//! qcb-seed --node-url http://192.168.137.2:8080 \
//!           --research-mode avalanche \
//!           --primary-miner-id machine1
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

// HTTP seeding (posts directly to a running qcb-scheduler)
mod http_seed {
    use chain_forge_research_db::models::{NewObjective, NewTask};
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct SeedResponse {
        pub objective_id:   String,
        pub tasks_inserted: usize,
    }

    pub async fn post_to_scheduler(
        node_url: &str,
        objective: NewObjective,
        tasks: Vec<NewTask>,
    ) -> anyhow::Result<SeedResponse> {
        let client = reqwest::Client::new();
        let url = format!("{node_url}/scheduler/seed");
        let body = serde_json::json!({ "objective": objective, "tasks": tasks });
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Scheduler returned {status}: {text}");
        }
        Ok(resp.json::<SeedResponse>().await?)
    }
}

// ── CLI ───────────────────────────────────────────────────────────────────────

/// QCB seed tool — populate the research DB with cryptographic challenge tasks.
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

    /// Research mode: "pocd" (partial preimage search) or "avalanche" (SHA-256
    /// avalanche effect measurement).
    #[arg(long, default_value = "pocd")]
    research_mode: String,

    // ── PoCD-only parameters ──────────────────────────────────────────────────

    /// [PoCD] Number of tasks to create (each covers a non-overlapping nonce slice)
    #[arg(long, default_value = "100")]
    task_count: u64,

    /// [PoCD] Nonces per task (range_end - range_start per task)
    #[arg(long, default_value = "500000")]
    range_per_task: u64,

    /// [PoCD] Difficulty in leading zero BITS (8 = 1 byte, 16 = 2 bytes, 24 = 3 bytes)
    #[arg(long, default_value = "16")]
    difficulty: u32,

    /// [PoCD] Global seed used for all tasks
    #[arg(long, default_value = "31415926535897932")]
    global_seed: i64,

    // ── Avalanche-only parameters ─────────────────────────────────────────────

    /// [Avalanche] Number of canonical seeds (0..seed_count-1).
    /// Each seed × 256 bit positions = seed_count × 256 primary tasks.
    #[arg(long, default_value = "10")]
    seed_count: u32,

    /// [Avalanche] Miner ID that will run the primary experiments.
    /// Replication tasks set phase1_miner_id = this value so the scheduler
    /// assigns them to a DIFFERENT miner (exclude_miner filter).
    /// Required when --research-mode avalanche.
    #[arg(long)]
    primary_miner_id: Option<String>,

    // ── Shared parameters ─────────────────────────────────────────────────────

    /// Verification quorum — how many miners must agree before a result is accepted
    #[arg(long, default_value = "2")]
    verification_quorum: u32,

    /// Dry-run: use in-memory DB and print summary only (no Postgres needed)
    #[arg(long)]
    dry_run: bool,

    /// Base URL of a running qcb-scheduler to POST the objective + tasks to.
    /// When set, skips local DB writes and seeds the live scheduler directly.
    /// Example: http://127.0.0.1:8080
    #[arg(long, env = "QCB_NODE_URL")]
    node_url: Option<String>,
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

    // Validate mode-specific requirements
    if args.research_mode == "avalanche" && args.primary_miner_id.is_none() && !args.dry_run {
        eprintln!(
            "Error: --primary-miner-id is required in avalanche mode \
             (used to route replication tasks to a different miner).\n\
             Use --dry-run to preview without specifying a miner."
        );
        std::process::exit(1);
    }

    // ── Route: POST to live scheduler ─────────────────────────────────────────
    if let Some(ref node_url) = args.node_url {
        info!(node_url = %node_url, mode = %args.research_mode, "Seeding live scheduler via HTTP");
        run_http(node_url, &args).await;
        return;
    }

    // ── Route: local DB (dry-run or Postgres) ─────────────────────────────────
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

// ── Task generation helpers ───────────────────────────────────────────────────

/// Build the NewObjective and task list for PoCD mode.
fn build_pocd(args: &Args, objective_id: &str) -> (NewObjective, Vec<NewTask>) {
    let total_nonces = args.task_count * args.range_per_task;

    let verification_spec = serde_json::json!({
        "type":            "sha256_preimage",
        "difficulty_bits": args.difficulty,
        "global_seed":     args.global_seed,
        "algorithm":       "sha256-preimage-v1",
        "description":     format!(
            "Find nonce N in range such that SHA-256(seed || N) has {} leading zero bits",
            args.difficulty
        ),
    });

    let objective = NewObjective {
        objective_id:        objective_id.to_string(),
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

    let tasks: Vec<NewTask> = (0..args.task_count)
        .map(|i| {
            let range_start = i * args.range_per_task;
            let range_end   = range_start + args.range_per_task;
            let input_seed  = args.global_seed ^ (i as i64);
            NewTask {
                task_id:         format!("task-{objective_id}-{i:04}"),
                objective_id:    objective_id.to_string(),
                range_start,
                range_end,
                workload_class:  "cpu".to_string(),
                input_seed:      input_seed as u64,
                phase:           1,
                parent_hash:     None,
                phase1_miner_id: None,
                task_kind:       "pocd_phase1".to_string(),
                avl_seed_index:  None,
                avl_bit_index:   None,
            }
        })
        .collect();

    (objective, tasks)
}

/// Build the NewObjective and task list for avalanche mode.
///
/// Generates:
///   - `seed_count × 256` primary tasks (task_kind = "avalanche_experiment")
///   - 5% of primary count replication tasks (task_kind = "avalanche_replication",
///     phase1_miner_id = primary_miner_id to enforce exclude_miner routing)
///
/// The 5% replication sample is drawn uniformly by keeping every 20th task
/// in the (seed_index, bit_index) iteration order.
fn build_avalanche(
    args:             &Args,
    objective_id:     &str,
    primary_miner_id: &str,
) -> (NewObjective, Vec<NewTask>) {
    let primary_count = args.seed_count as u64 * 256;
    // 5% of 2 560 = 128, rounded up
    let replication_count = ((primary_count as f64 * 0.05).ceil()) as u64;

    let verification_spec = serde_json::json!({
        "type":        "sha256_avalanche",
        "algorithm":   "sha256-avalanche-v1",
        "seed_count":  args.seed_count,
        "bit_count":   256,
        "description": format!(
            "Measure SHA-256 avalanche effect: {} seeds × 256 bit positions = {} experiments, \
             plus {} cross-machine replications (5%). \
             No result is automatically classified as a cryptographic breakthrough.",
            args.seed_count, primary_count, replication_count
        ),
        "canonical_seed_derivation":
            "SHA-256('qcb-avalanche-v1' || objective_id_utf8 || seed_index_le64)",
        "bit_flip_convention":
            "byte_idx = bit_index / 8; bit_shift = 7 - (bit_index % 8)  [MSB = bit 7 of byte 0]",
        "content_hash_derivation":
            "SHA-256(original_hash_bytes || flipped_hash_bytes)",
        "replication_fraction": 0.05,
    });

    let objective = NewObjective {
        objective_id:        objective_id.to_string(),
        challenge_id:        args.challenge_id.clone(),
        slug:                args.slug.clone(),
        track:               "cryptographic-research".to_string(),
        algorithm_version:   "sha256-avalanche-v1".to_string(),
        range_start:         0,
        range_end:           primary_count + replication_count,
        workload_class:      "cpu".to_string(),
        verification_spec,
        verification_quorum: args.verification_quorum,
    };

    // ── Primary tasks: all (seed_index, bit_index) pairs ─────────────────────
    let mut tasks: Vec<NewTask> = Vec::with_capacity(
        (primary_count + replication_count) as usize,
    );

    // Track which (seed_index, bit_index) pairs get replicated (every 20th)
    let replication_step = (primary_count / replication_count).max(1);
    let mut flat_idx: u64 = 0;

    for seed_idx in 0..args.seed_count {
        for bit_idx in 0u32..256 {
            let task_id = format!(
                "avl-{objective_id}-s{seed_idx:02}-b{bit_idx:03}"
            );
            tasks.push(NewTask {
                task_id,
                objective_id:    objective_id.to_string(),
                // range_start/end not used for avalanche — set to 0
                range_start:     0,
                range_end:       0,
                workload_class:  "cpu".to_string(),
                // input_seed not used for avalanche — avl_seed_index drives derivation
                input_seed:      0,
                phase:           1,
                parent_hash:     None,
                phase1_miner_id: None,
                task_kind:       "avalanche_experiment".to_string(),
                avl_seed_index:  Some(seed_idx),
                avl_bit_index:   Some(bit_idx),
            });

            // Every replication_step-th primary task gets a replication twin
            if flat_idx % replication_step == 0 {
                let repl_id = format!(
                    "avl-{objective_id}-s{seed_idx:02}-b{bit_idx:03}-repl"
                );
                tasks.push(NewTask {
                    task_id:         repl_id,
                    objective_id:    objective_id.to_string(),
                    range_start:     0,
                    range_end:       0,
                    workload_class:  "cpu".to_string(),
                    input_seed:      0,
                    phase:           1,
                    parent_hash:     None,
                    // Setting phase1_miner_id causes the scheduler's
                    // exclude_miner filter to route this to a DIFFERENT miner.
                    phase1_miner_id: Some(primary_miner_id.to_string()),
                    task_kind:       "avalanche_replication".to_string(),
                    avl_seed_index:  Some(seed_idx),
                    avl_bit_index:   Some(bit_idx),
                });
            }

            flat_idx += 1;
        }
    }

    (objective, tasks)
}

// ── HTTP seeding (posts directly to a running qcb-scheduler) ─────────────────

async fn run_http(node_url: &str, args: &Args) {
    let objective_id = Uuid::new_v4().to_string();

    let (objective, tasks) = if args.research_mode == "avalanche" {
        let primary_miner = args.primary_miner_id
            .as_deref()
            .unwrap_or("unknown-miner");
        plan::print_avalanche_plan(args, &objective_id);
        build_avalanche(args, &objective_id, primary_miner)
    } else {
        plan::print_plan(args, &objective_id, args.task_count * args.range_per_task);
        build_pocd(args, &objective_id)
    };

    let task_count = tasks.len();
    match http_seed::post_to_scheduler(node_url, objective, tasks).await {
        Ok(resp) => {
            info!(
                objective_id   = %resp.objective_id,
                tasks_inserted = resp.tasks_inserted,
                mode           = %args.research_mode,
                "✓ Scheduler seeded successfully"
            );
            print_completion_banner(node_url, args, &resp.objective_id, task_count);
        }
        Err(e) => {
            eprintln!("Failed to seed scheduler: {e}");
            std::process::exit(1);
        }
    }
}

// ── Core seeding logic (works with any ResearchDb impl) ───────────────────────

async fn run(db: &impl ResearchDb, args: &Args) {
    let objective_id = Uuid::new_v4().to_string();

    let (objective, tasks) = if args.research_mode == "avalanche" {
        let primary_miner = args.primary_miner_id
            .as_deref()
            .unwrap_or("dry-run-miner");
        plan::print_avalanche_plan(args, &objective_id);
        build_avalanche(args, &objective_id, primary_miner)
    } else {
        let total_nonces = args.task_count * args.range_per_task;
        plan::print_plan(args, &objective_id, total_nonces);
        build_pocd(args, &objective_id)
    };

    // ── Insert objective ──────────────────────────────────────────────────────
    match db.insert_objective(objective).await {
        Ok(row) => info!(
            objective_id = %row.objective_id,
            slug = %row.slug,
            mode = %args.research_mode,
            "Objective created"
        ),
        Err(e) => {
            eprintln!("Failed to insert objective: {e}");
            std::process::exit(1);
        }
    }

    // ── Insert tasks ──────────────────────────────────────────────────────────
    let task_count = tasks.len();
    match db.upsert_tasks(tasks).await {
        Ok(n) => info!(tasks_inserted = n, "Tasks created"),
        Err(e) => {
            eprintln!("Failed to insert tasks: {e}");
            std::process::exit(1);
        }
    }

    // ── PoCD only: verify challenge is solvable ───────────────────────────────
    if args.research_mode != "avalanche" {
        info!("Verifying challenge is solvable on task 0 (quick sanity check)...");
        let seed_0    = args.global_seed ^ 0i64;
        let range_end = args.range_per_task.min(10_000_000);
        match challenge::verify_solvable(seed_0, 0, range_end as i64, args.difficulty) {
            Some((nonce, hash_hex)) => {
                info!(
                    nonce        = nonce,
                    hash_prefix  = &hash_hex[..8],
                    difficulty   = args.difficulty,
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
    }

    // ── Final summary ─────────────────────────────────────────────────────────
    print_completion_banner(
        args.node_url.as_deref().unwrap_or("(local DB)"),
        args,
        &objective_id,
        task_count,
    );
    if args.dry_run || args.database_url.is_none() {
        println!("  (Dry-run: add --database-url postgres://... to persist to Postgres)");
        println!();
    }
}

// ── Banner helpers ────────────────────────────────────────────────────────────

fn print_completion_banner(node_url: &str, args: &Args, objective_id: &str, task_count: usize) {
    println!();
    println!("════════════════════════════════════════════════════════");
    if args.research_mode == "avalanche" {
        println!("  QCB Avalanche Seed complete");
    } else {
        println!("  QCB PoCD Seed complete");
    }
    println!("════════════════════════════════════════════════════════");
    println!("  Objective ID : {objective_id}");
    println!("  Challenge    : {}", args.challenge_id);
    println!("  Mode         : {}", args.research_mode);
    println!("  Tasks        : {task_count}");
    println!();
    if args.research_mode == "avalanche" {
        println!("  Run the primary miner ({}) with:",
            args.primary_miner_id.as_deref().unwrap_or("<primary-miner-id>"));
        println!();
        println!("    qcb-miner \\");
        println!("      --node-url {node_url} \\");
        println!("      --miner-id {} \\",
            args.primary_miner_id.as_deref().unwrap_or("<primary-miner-id>"));
        println!("      --objective-id {objective_id}");
        println!();
        println!("  Run the replication miner (DIFFERENT machine) with:");
        println!();
        println!("    qcb-miner \\");
        println!("      --node-url {node_url} \\");
        println!("      --miner-id <other-machine-name> \\");
        println!("      --objective-id {objective_id}");
    } else {
        println!("  Run a miner with:");
        println!();
        println!("    qcb-miner \\");
        println!("      --node-url {node_url} \\");
        println!("      --miner-id <your-machine-name> \\");
        println!("      --objective-id {objective_id}");
    }
    println!();
}
