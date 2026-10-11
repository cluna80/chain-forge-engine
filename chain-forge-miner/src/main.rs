//! # qcb-miner
//!
//! QCB PoCD miner client.
//!
//! ## What it does
//!
//! 1. Registers with the QCB scheduler node (POST /scheduler/miners/register)
//! 2. Polls for an available task (GET /scheduler/miners/{id}/task)
//! 3. Performs the cryptographic challenge work locally
//! 4. Submits the result (POST /scheduler/tasks/{id}/result)
//! 5. Loops back to step 2
//!
//! ## Cryptographic challenge (PoCD work unit)
//!
//! Each task carries a `range_start`, `range_end`, and `input_seed`.
//! The miner searches the range [range_start, range_end) for a nonce N such
//! that SHA-256(seed || N) has at least 16 leading zero bits (2 zero bytes).
//! The first matching nonce is the solution.  The content_hash of the result is
//! the hex-encoded SHA-256 of the winning hash itself, so verifiers can
//! re-derive it deterministically.
//!
//! Algorithm: `sha256-preimage-v1` — matches the challenge seeded by `qcb-seed`.
//!
//! ## Usage
//!
//! ```
//! qcb-miner --node-url http://192.168.137.2:8080 \
//!           --miner-id machine2 \
//!           --objective-id <objective_uuid>
//! ```

mod challenge;
mod client;
mod error;

use std::time::Duration;

use clap::Parser;
use tracing::{error, info, warn};

use crate::client::SchedulerClient;
use crate::error::MinerError;

// ── CLI ───────────────────────────────────────────────────────────────────────

/// QCB PoCD miner — connects to a QCB node and performs cryptographic discovery work.
#[derive(Parser, Debug)]
#[command(name = "qcb-miner", version, about)]
struct Args {
    /// Base URL of the QCB scheduler node (e.g. http://192.168.137.2:8080)
    #[arg(long, env = "QCB_NODE_URL", default_value = "http://127.0.0.1:8080")]
    node_url: String,

    /// Unique identifier for this miner (e.g. "machine1", "bossking")
    #[arg(long, env = "QCB_MINER_ID")]
    miner_id: String,

    /// Objective ID to mine against (UUID)
    #[arg(long, env = "QCB_OBJECTIVE_ID")]
    objective_id: String,

    /// Workload class to advertise (default: cpu)
    #[arg(long, env = "QCB_WORKLOAD_CLASS", default_value = "cpu")]
    workload_class: String,

    /// Seconds to wait between polls when no task is available
    #[arg(long, default_value = "5")]
    poll_interval_secs: u64,

    /// Algorithm version string embedded in results
    #[arg(long, default_value = "sha256-preimage-v1")]
    algorithm_version: String,

    /// Workload version string embedded in results
    #[arg(long, default_value = "pocd-challenge-v1")]
    workload_version: String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qcb_miner=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    info!(
        miner_id   = %args.miner_id,
        node_url   = %args.node_url,
        objective  = %args.objective_id,
        "QCB miner starting"
    );

    if let Err(e) = run(args).await {
        error!(error = %e, "Miner exited with error");
        std::process::exit(1);
    }
}

// ── Main loop ─────────────────────────────────────────────────────────────────

async fn run(args: Args) -> Result<(), MinerError> {
    let client = SchedulerClient::new(&args.node_url)?;
    let poll_interval = Duration::from_secs(args.poll_interval_secs);

    // ── Register ──────────────────────────────────────────────────────────────
    client
        .register(&args.miner_id, &args.workload_class)
        .await?;
    info!(miner_id = %args.miner_id, "Registered with scheduler");

    let mut tasks_completed: u64 = 0;

    loop {
        // ── Poll for task ─────────────────────────────────────────────────────
        let task = match client
            .get_task(&args.miner_id, &args.objective_id, &args.workload_class)
            .await?
        {
            Some(t) => t,
            None => {
                info!(
                    objective = %args.objective_id,
                    "No task available — waiting {poll_interval_secs}s",
                    poll_interval_secs = args.poll_interval_secs,
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        info!(
            task_id    = %task.task_id,
            range      = ?task.range_start..task.range_end,
            seed       = task.input_seed,
            lease_exp  = %task.lease_expires_at,
            "Task assigned — starting work"
        );

        // ── Do the work ───────────────────────────────────────────────────────
        let solution = tokio::task::spawn_blocking({
            let task_id   = task.task_id.clone();
            let seed      = task.input_seed;
            let start     = task.range_start;
            let end       = task.range_end;
            move || {
                info!(task_id = %task_id, "Computing challenge...");
                challenge::solve(seed, start, end)
            }
        })
        .await
        .map_err(|e| MinerError::Worker(e.to_string()))?;

        match solution {
            Some(sol) => {
                info!(
                    task_id      = %task.task_id,
                    winning_nonce = sol.nonce,
                    content_hash  = %sol.content_hash,
                    "Solution found — submitting"
                );

                let result = client::NewResult {
                    task_id:           task.task_id.clone(),
                    miner_id:          args.miner_id.clone(),
                    content_hash:      sol.content_hash.clone(),
                    result_payload:    serde_json::json!({
                        "nonce":        sol.nonce,
                        "winning_hash": sol.winning_hash,
                        "range_start":  task.range_start,
                        "range_end":    task.range_end,
                        "input_seed":   task.input_seed,
                    }),
                    algorithm_version: args.algorithm_version.clone(),
                    workload_version:  args.workload_version.clone(),
                    seal_nonce:        Some(sol.nonce as u64),
                };

                match client
                    .submit_result(
                        &task.task_id,
                        &args.miner_id,
                        task.lease_generation,
                        result,
                    )
                    .await
                {
                    Ok(()) => {
                        tasks_completed += 1;
                        info!(
                            task_id         = %task.task_id,
                            tasks_completed,
                            "Result accepted by scheduler"
                        );
                    }
                    Err(MinerError::LeaseExpired(msg)) => {
                        warn!(task_id = %task.task_id, reason = %msg, "Lease expired — dropping result");
                    }
                    Err(MinerError::LeaseSuperseded(msg)) => {
                        warn!(task_id = %task.task_id, reason = %msg, "Lease superseded — dropping result");
                    }
                    Err(e) => return Err(e),
                }
            }
            None => {
                warn!(
                    task_id = %task.task_id,
                    "No solution found in range — task will expire naturally"
                );
            }
        }
    }
}
