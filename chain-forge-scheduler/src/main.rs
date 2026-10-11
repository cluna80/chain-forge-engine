//! # qcb-scheduler
//!
//! Standalone binary that runs the QCB research scheduling HTTP server.
//!
//! ## Usage
//!
//! ```bash
//! # In-memory mode (no Postgres required — tasks reset on restart)
//! qcb-scheduler
//!
//! # Postgres mode (persistent tasks survive restarts)
//! qcb-scheduler --database-url postgres://user:pass@localhost/qcb
//!
//! # Custom bind address
//! qcb-scheduler --bind 0.0.0.0:9090
//! ```
//!
//! ## Endpoints
//!
//! | Method | Path                                  | Description                    |
//! |--------|---------------------------------------|--------------------------------|
//! | POST   | `/scheduler/miners/register`          | Register / heartbeat a miner   |
//! | GET    | `/scheduler/miners/{miner_id}/task`   | Poll for a task assignment     |
//! | POST   | `/scheduler/tasks/{task_id}/result`   | Submit task result             |
//! | GET    | `/scheduler/status`                   | Queue depth + active leases    |

use std::sync::Arc;
use std::time::Duration; // used by expire_interval sleep

use clap::Parser;
use tracing::info;

use chain_forge_research_db::MemResearchDb;
use chain_forge_scheduler::{AppState, MinerRegistry, ResearchScheduler, router};

// ── CLI ───────────────────────────────────────────────────────────────────────

/// QCB research scheduler — distributes PoCD microtasks to miners.
#[derive(Parser, Debug)]
#[command(name = "qcb-scheduler", version, about)]
struct Args {
    /// TCP address to listen on.
    #[arg(long, env = "QCB_BIND", default_value = "0.0.0.0:8080")]
    bind: String,

    /// Postgres connection string.
    /// If omitted, an in-memory database is used (tasks reset on restart).
    #[arg(long, env = "QCB_DATABASE_URL")]
    database_url: Option<String>,

    /// Lease duration in seconds — how long a miner has to submit a result
    /// before the task is reassigned to another miner.
    #[arg(long, env = "QCB_LEASE_SECS", default_value_t = 120)]
    lease_secs: u64,

    /// How often (in seconds) the scheduler scans for expired leases.
    #[arg(long, env = "QCB_EXPIRE_INTERVAL_SECS", default_value_t = 15)]
    expire_interval_secs: u64,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "info,chain_forge_scheduler=debug".into()),
        )
        .init();

    let args = Args::parse();

    // ── Database ─────────────────────────────────────────────────────────────
    let db: Arc<dyn chain_forge_research_db::ResearchDb> = if let Some(ref url) = args.database_url
    {
        // Postgres support can be added later by wiring PgResearchDb here.
        // For the real-machine test, in-memory is sufficient — tasks are
        // seeded fresh each run via qcb-seed.
        tracing::warn!(
            url = %url,
            "Postgres support not yet compiled in — falling back to in-memory DB. \
             Run qcb-seed to re-populate tasks after each scheduler restart."
        );
        Arc::new(MemResearchDb::new())
    } else {
        info!("No --database-url provided — using in-memory research DB");
        info!("NOTE: All tasks will be lost when the scheduler restarts.");
        Arc::new(MemResearchDb::new())
    };

    // ── Scheduler + background expiry loop ────────────────────────────────────
    let scheduler = ResearchScheduler::new(db.clone())
        .with_lease_secs(args.lease_secs as i64);

    {
        let scheduler_bg = scheduler.clone();
        let interval = Duration::from_secs(args.expire_interval_secs);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match scheduler_bg.expire_stale_leases().await {
                    Ok(n) if n > 0 => info!(count = n, "Expired stale leases"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "Lease expiry scan failed"),
                }
            }
        });
    }

    // ── HTTP server ───────────────────────────────────────────────────────────
    let state = AppState {
        scheduler,
        miners: MinerRegistry::new(),
    };

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&args.bind).await?;

    info!(addr = %args.bind, "QCB scheduler listening");
    info!("Endpoints:");
    info!("  POST /scheduler/miners/register");
    info!("  GET  /scheduler/miners/{{miner_id}}/task?objective_id=<UUID>");
    info!("  POST /scheduler/tasks/{{task_id}}/result");
    info!("  GET  /scheduler/status");

    axum::serve(listener, app).await?;
    Ok(())
}
