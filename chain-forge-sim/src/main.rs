//! chain-forge-sim binary -- runs the standard persona roster against a
//! live chain-forge-node and prints/saves the report.
//!
//! Usage:
//!   chain-forge-sim [--base-url http://localhost:8080] [--epochs 6] [--epoch-seconds 3]
//!
//! Point --base-url at whichever validator's API you want to drive this
//! against -- any one of the four VMs works, since a transaction submitted
//! to one propagates to all of them via real gossip.

use chain_forge_sim::{SimRunner, personas::standard_roster};
use std::time::Duration;

fn parse_args() -> (String, u64, u64) {
    let mut base_url = "http://localhost:8080".to_string();
    let mut epochs: u64 = 6;
    let mut epoch_seconds: u64 = 3;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--base-url" => {
                i += 1;
                if i < args.len() { base_url = args[i].clone(); }
            }
            "--epochs" => {
                i += 1;
                if i < args.len() { epochs = args[i].parse().unwrap_or(6); }
            }
            "--epoch-seconds" => {
                i += 1;
                if i < args.len() { epoch_seconds = args[i].parse().unwrap_or(3); }
            }
            "--help" | "-h" => {
                println!("chain-forge-sim -- mechanical integration test harness");
                println!("  --base-url <url>       Node API to drive this against (default: http://localhost:8080)");
                println!("  --epochs <n>           Number of simulated epochs to run (default: 6)");
                println!("  --epoch-seconds <n>    Seconds to pause between epochs (default: 3)");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    (base_url, epochs, epoch_seconds)
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_target(false).with_env_filter(filter).init();

    let (base_url, epochs, epoch_seconds) = parse_args();

    println!("chain-forge-sim starting");
    println!("  target:  {base_url}");
    println!("  epochs:  {epochs}");
    println!("  pause:   {epoch_seconds}s between epochs\n");
    println!("Reminder: this is a mechanical integration test, not evidence of");
    println!("sybil resistance. See the report's own scope banner.\n");

    let mut runner = SimRunner::new(base_url, epochs, Duration::from_secs(epoch_seconds));
    for persona in standard_roster() {
        runner.add_persona(persona);
    }

    let report = match runner.run().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("simulation run failed: {e}");
            std::process::exit(1);
        }
    };

    let text = report.render();
    println!("{text}");

    let filename = format!(
        "chain-forge-sim-report-{}.txt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    if let Err(e) = std::fs::write(&filename, &text) {
        eprintln!("(could not save report to {filename}: {e})");
    } else {
        println!("Report saved to {filename}");
    }

    if report.total_failures() > 0 || report.total_persona_errors() > 0 {
        std::process::exit(1);
    }
}
