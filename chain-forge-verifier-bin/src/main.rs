//! # qcb-verifier
//!
//! QCB independent result verifier — reproduces submitted PoCD and avalanche
//! results from task parameters alone, then calls the scheduler's verify
//! endpoint to advance each result toward canonical acceptance.
//!
//! ## What it does
//!
//! 1. Polls `GET /scheduler/objectives/{objective_id}/results` for results
//!    with `result_status = "submitted"`.
//! 2. For each submitted result, re-derives the expected `content_hash`
//!    deterministically from the result payload (nonce, phase, parent_hash,
//!    seed indices — the same inputs the original miner used).
//! 3. If the re-derived hash matches the recorded `content_hash`:
//!    - Posts `POST /scheduler/tasks/{task_id}/verify` with outcome `"reproduced"`.
//! 4. If the hashes differ:
//!    - Posts with outcome `"rejected"` so the discrepancy is recorded.
//! 5. Tracks which `result_id`s have already been verified this run to avoid
//!    duplicates (the scheduler also guards against these server-side).
//!
//! ## Two-Phase PoCD verification
//!
//! Phase 1:
//!   nonce       = result_payload["nonce"]
//!   seed        = result_payload["input_seed"]   (or task.input_seed)
//!   H1          = SHA-256(seed_le64 || nonce_le64)
//!   content_hash = hex(SHA-256(H1))
//!
//! Phase 2:
//!   nonce       = result_payload["nonce"]
//!   parent_hash = result_payload["winning_hash"] of the phase-1 parent
//!                 (carried in task as parent_hash — NOT in the result payload
//!                  directly; use the task row's parent_hash field)
//!   H2          = SHA-256(H1_bytes || nonce_le64)   where H1 = hex::decode(parent_hash)
//!   content_hash = hex(SHA-256(H1_bytes || H2_bytes))
//!
//! ## Avalanche verification
//!
//!   seed_index = result_payload["seed_index"]
//!   bit_index  = result_payload["bit_index"]
//!   canonical_seed   = SHA-256("qcb-avalanche-v1" || objective_id_utf8 || seed_index_le64)
//!   original_hash    = SHA-256(canonical_seed)
//!   flipped_seed     = canonical_seed with bit `bit_index` flipped (MSB-first: byte=bit/8, shift=7-(bit%8))
//!   flipped_hash     = SHA-256(flipped_seed)
//!   content_hash     = hex(SHA-256(original_hash || flipped_hash))
//!
//! ## Scientific integrity
//!
//! This binary re-derives hashes mechanically.  It does NOT classify results
//! as cryptographic breakthroughs, anomalies, or scientific discoveries.
//! "reproduced" means only that the same deterministic hash function produced
//! the same output from the same inputs.
//!
//! ## Usage
//!
//! ```bash
//! qcb-verifier \
//!   --node-url http://192.168.137.1:8080 \
//!   --verifier-id machine-b \
//!   --objective-id <objective-uuid>
//! ```

mod challenge;
mod client;

use std::collections::HashSet;
use std::time::Duration;

use clap::Parser;
use tracing::{error, info, warn};

use crate::client::{SchedulerClient, VerifyOutcome};

// ── CLI ───────────────────────────────────────────────────────────────────────

/// QCB independent result verifier — re-derives content hashes and submits
/// verification records to the scheduler.
#[derive(Parser, Debug)]
#[command(name = "qcb-verifier", version, about)]
struct Args {
    /// Base URL of the QCB scheduler (e.g. http://192.168.137.1:8080)
    #[arg(long, env = "QCB_NODE_URL", default_value = "http://127.0.0.1:8080")]
    node_url: String,

    /// Unique identity for this verifier (must differ from the original miner)
    #[arg(long, env = "QCB_VERIFIER_ID")]
    verifier_id: String,

    /// Objective ID to verify against (UUID)
    #[arg(long, env = "QCB_OBJECTIVE_ID")]
    objective_id: String,

    /// Seconds between polling cycles when no submitted results are found
    #[arg(long, default_value = "10")]
    poll_interval_secs: u64,

    /// Maximum results to fetch per poll cycle
    #[arg(long, default_value = "100")]
    batch_size: usize,

    /// Run one verification pass then exit (useful for scripted tests)
    #[arg(long)]
    once: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qcb_verifier=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    info!(
        verifier_id = %args.verifier_id,
        node_url    = %args.node_url,
        objective   = %args.objective_id,
        "QCB verifier starting"
    );

    if let Err(e) = run(args).await {
        error!(error = %e, "Verifier exited with error");
        std::process::exit(1);
    }
}

// ── Main loop ─────────────────────────────────────────────────────────────────

async fn run(args: Args) -> anyhow::Result<()> {
    let client = SchedulerClient::new(&args.node_url)?;
    let poll_interval = Duration::from_secs(args.poll_interval_secs);

    // Track which result_ids we've already verified this run — the scheduler
    // enforces duplicate detection server-side, but avoiding the round-trip
    // is cleaner.
    let mut verified: HashSet<String> = HashSet::new();
    let mut total_reproduced: u64 = 0;
    let mut total_rejected: u64   = 0;

    loop {
        // ── Fetch submitted results ───────────────────────────────────────────
        let results = client
            .list_submitted_results(&args.objective_id, args.batch_size)
            .await?;

        let pending: Vec<_> = results
            .into_iter()
            .filter(|r| !verified.contains(&r.result_id))
            .collect();

        if pending.is_empty() {
            if args.once {
                info!(
                    total_reproduced,
                    total_rejected,
                    "No submitted results to verify — exiting (--once mode)"
                );
                break;
            }
            info!(
                total_reproduced,
                total_rejected,
                "No new submitted results — waiting {poll_interval_secs}s",
                poll_interval_secs = args.poll_interval_secs,
            );
            tokio::time::sleep(poll_interval).await;
            continue;
        }

        info!(count = pending.len(), "Found submitted results to verify");

        for result in pending {
            let result_id   = result.result_id.clone();
            let task_id     = result.task_id.clone();

            // ── Re-derive content_hash independently ──────────────────────────
            let rederived = challenge::rederive_content_hash(
                &result,
                &args.objective_id,
            );

            let (outcome, verifier_hash) = match rederived {
                Ok(h) if h == result.content_hash => {
                    info!(
                        task_id    = %task_id,
                        result_id  = %result_id,
                        hash       = %h,
                        "Hash reproduced ✓"
                    );
                    (VerifyOutcome::Reproduced, h)
                }
                Ok(h) => {
                    warn!(
                        task_id          = %task_id,
                        result_id        = %result_id,
                        our_hash         = %h,
                        original_hash    = %result.content_hash,
                        "Hash mismatch — submitting rejected"
                    );
                    (VerifyOutcome::Rejected, h)
                }
                Err(e) => {
                    warn!(
                        task_id   = %task_id,
                        result_id = %result_id,
                        error     = %e,
                        "Could not re-derive hash — submitting inconclusive"
                    );
                    (VerifyOutcome::Inconclusive, result.content_hash.clone())
                }
            };

            // ── POST /scheduler/tasks/{task_id}/verify ────────────────────────
            match client
                .verify(&task_id, &result_id, &args.verifier_id, outcome, &verifier_hash)
                .await
            {
                Ok(resp) => {
                    match outcome {
                        VerifyOutcome::Reproduced => {
                            total_reproduced += 1;
                            if resp.quorum_reached {
                                info!(
                                    task_id           = %task_id,
                                    result_id         = %result_id,
                                    reproduced_count  = resp.reproduced_count,
                                    quorum_required   = resp.quorum_required,
                                    status            = %resp.status,
                                    "Quorum reached — task accepted ✓"
                                );
                            } else {
                                info!(
                                    task_id           = %task_id,
                                    result_id         = %result_id,
                                    reproduced_count  = resp.reproduced_count,
                                    quorum_required   = resp.quorum_required,
                                    "Verification recorded — awaiting more verifiers"
                                );
                            }
                        }
                        VerifyOutcome::Rejected => {
                            total_rejected += 1;
                            warn!(
                                task_id   = %task_id,
                                result_id = %result_id,
                                "Rejection recorded"
                            );
                        }
                        VerifyOutcome::Inconclusive => {
                            warn!(
                                task_id   = %task_id,
                                result_id = %result_id,
                                "Inconclusive recorded"
                            );
                        }
                    }
                    verified.insert(result_id);
                }

                Err(e) if e.to_string().contains("self_verification") => {
                    // We are the original miner — skip silently
                    info!(
                        task_id   = %task_id,
                        result_id = %result_id,
                        "Skipping own result (self-verification not allowed)"
                    );
                    verified.insert(result_id);
                }
                Err(e) if e.to_string().contains("already") || e.to_string().contains("conflict") => {
                    // Already verified by us in a prior run
                    info!(
                        task_id   = %task_id,
                        result_id = %result_id,
                        "Already verified in a prior run — skipping"
                    );
                    verified.insert(result_id);
                }
                Err(e) => {
                    warn!(task_id = %task_id, result_id = %result_id, error = %e, "Verify call failed");
                }
            }
        }

        if args.once {
            info!(total_reproduced, total_rejected, "Pass complete — exiting (--once mode)");
            break;
        }

        tokio::time::sleep(poll_interval).await;
    }

    Ok(())
}
