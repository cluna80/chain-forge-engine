//! # qcb-analyzer
//!
//! QCB SHA-256 Avalanche Experiment Analyzer.
//!
//! ## What it does
//!
//! 1. Fetches all settled results for an objective from the QCB scheduler.
//! 2. **Independently recomputes** every experiment from first principles:
//!    `(objective_id, seed_index, bit_index)` → canonical_seed → both hashes.
//!    This is the analyzer's own calculation, NOT a second miner verification.
//! 3. Flags any result whose submitted hashes disagree with the local recomputation.
//! 4. Checks cross-machine replication pairs: primary vs replication result.
//! 5. Outputs a JSON data file and a Markdown report.
//!
//! ## Scientific integrity
//!
//! - The analyzer recomputes results itself for error detection, but this does
//!   NOT constitute independent miner verification — it is a software check.
//! - No result is automatically classified as a cryptographic anomaly or
//!   breakthrough; outliers are flagged for human review.
//! - Statistical summaries describe the data; they do not make inferences.
//!
//! ## Usage
//!
//! ```bash
//! qcb-analyzer \
//!   --node-url http://192.168.137.2:8080 \
//!   --objective-id <uuid> \
//!   --output-dir ./reports
//! ```

mod compute;
mod fetch;
mod report;
mod stats;

use clap::Parser;
use tracing::info;

use crate::fetch::SchedulerClient;

// ── CLI ───────────────────────────────────────────────────────────────────────

/// QCB avalanche experiment analyzer.
#[derive(Parser, Debug)]
#[command(name = "qcb-analyzer", version, about)]
struct Args {
    /// Base URL of the QCB scheduler node
    #[arg(long, env = "QCB_NODE_URL", default_value = "http://127.0.0.1:8080")]
    node_url: String,

    /// Objective ID to analyze (UUID)
    #[arg(long, env = "QCB_OBJECTIVE_ID")]
    objective_id: String,

    /// Directory to write the JSON data file and Markdown report into.
    /// Defaults to the current directory.
    #[arg(long, default_value = ".")]
    output_dir: String,

    /// Also print the Markdown report to stdout
    #[arg(long)]
    print_report: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qcb_analyzer=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    info!(
        objective_id = %args.objective_id,
        node_url     = %args.node_url,
        "QCB Analyzer starting"
    );

    // ── Fetch results ─────────────────────────────────────────────────────────
    let client  = SchedulerClient::new(&args.node_url)?;
    let results = client.fetch_results(&args.objective_id).await?;

    info!(count = results.len(), "Fetched results from scheduler");

    // ── Recompute and verify ──────────────────────────────────────────────────
    let verified = compute::verify_all(&args.objective_id, &results);

    // ── Build statistics ──────────────────────────────────────────────────────
    let stats = stats::compute(&verified);

    // ── Replication agreement check ───────────────────────────────────────────
    let replication = stats::check_replication(&verified);

    // ── Write outputs ─────────────────────────────────────────────────────────
    let out_dir = std::path::Path::new(&args.output_dir);
    std::fs::create_dir_all(out_dir)?;

    let json_path = out_dir.join(format!("avalanche-{}.json", &args.objective_id[..8]));
    let md_path   = out_dir.join(format!("avalanche-{}.md",   &args.objective_id[..8]));

    report::write_json(&json_path, &args.objective_id, &verified, &stats, &replication)?;
    let markdown = report::write_markdown(&md_path, &args.objective_id, &verified, &stats, &replication)?;

    info!(json = %json_path.display(), markdown = %md_path.display(), "Reports written");

    if args.print_report {
        println!("{markdown}");
    }

    // Print a terse summary
    println!();
    println!("════════════════════════════════════════════════════════");
    println!("  QCB Avalanche Analysis — {}", &args.objective_id);
    println!("════════════════════════════════════════════════════════");
    println!("  Results analyzed    : {}", verified.len());
    println!("  Compute mismatches  : {}", stats.compute_mismatches);
    println!("  Replication pairs   : {}", replication.pairs_checked);
    println!("  Replication disagree: {}", replication.disagreements);
    if let (Some(mean), Some(std)) = (stats.hamming_mean, stats.hamming_std) {
        println!("  Hamming mean        : {:.2} bits (expected ~128)", mean);
        println!("  Hamming std dev     : {:.2} bits (expected ~8)", std);
    } else {
        println!("  Hamming stats       : insufficient data");
    }
    println!("  Outliers (>3σ)      : {}", stats.outliers_3sigma);
    println!();
    println!("  JSON  : {}", json_path.display());
    println!("  Report: {}", md_path.display());
    println!();
    println!("  NOTE: Outliers require independent human review.");
    println!("        No result is automatically a cryptographic anomaly.");
    println!("════════════════════════════════════════════════════════");
    println!();

    Ok(())
}
