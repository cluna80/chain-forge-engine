/// chain-forge-node
///
/// The Chain Forge node binary. Wires all five crates together and runs
/// the main event loop.
///
/// Usage:
///   chain-forge-node --genesis <path-to-genesis.json> [--validator <address>]
///
/// What this binary does:
///   1. Reads and validates genesis.json (produced by the Chain Forge wizard)
///   2. Initialises state (seeds genesis accounts)
///   3. Initialises consensus (Tendermint-style BFT, personhood cap applied)
///   4. Starts the P2P network (mock in Phase 0; libp2p in Phase 1)
///   5. Runs the node event loop (process proposals, votes, txs, commits)
///   6. Exposes an HTTP API so the wizard frontend can trigger builds
///
/// Phase 0 status: steps 1-5 run in mock/devnet mode (no real networking,
/// no real signatures). Step 6 (HTTP API) is stubbed -- the endpoint exists
/// but just returns the genesis config and node status as JSON.
///
/// Whitepaper refs: Section 7.6 (Chain Forge architecture),
/// Roadmap Phase 0-1 (Section 11).

mod node;
mod api;

use std::path::PathBuf;
use tracing::info;

/// Command-line arguments (minimal for Phase 0).
struct Args {
    genesis_path: PathBuf,
    validator_address: Option<String>,
    api_port: u16,
    /// Overrides the P2P bind port from genesis. Needed to run more than
    /// one node locally on the same machine for a local multi-node testnet --
    /// each instance must bind a distinct port even though they share genesis.
    p2p_port: Option<u16>,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut genesis_path = PathBuf::from("genesis.json");
    let mut validator_address = None;
    let mut api_port = 8080u16;
    let mut p2p_port: Option<u16> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--genesis" | "-g" => {
                i += 1;
                if i < args.len() { genesis_path = PathBuf::from(&args[i]); }
            }
            "--validator" | "-v" => {
                i += 1;
                if i < args.len() { validator_address = Some(args[i].clone()); }
            }
            "--api-port" | "-p" => {
                i += 1;
                if i < args.len() {
                    api_port = args[i].parse().unwrap_or(8080);
                }
            }
            "--p2p-port" | "-P" => {
                i += 1;
                if i < args.len() {
                    p2p_port = args[i].parse().ok();
                }
            }
            "--help" | "-h" => {
                println!("chain-forge-node");
                println!("  --genesis <path>     Path to genesis.json (default: genesis.json)");
                println!("  --validator <addr>   This node's validator address");
                println!("  --api-port <port>    HTTP API port (default: 8080)");
                println!("  --p2p-port <port>    Override P2P bind port from genesis");
                println!("                       (needed to run multiple local nodes)");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    Args { genesis_path, validator_address, api_port, p2p_port }
}

#[tokio::main]
async fn main() {
    // Initialise structured logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let args = parse_args();

    info!(
        genesis = %args.genesis_path.display(),
        api_port = args.api_port,
        "Chain Forge node starting"
    );

    // Read genesis
    let genesis_json = match std::fs::read_to_string(&args.genesis_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: cannot read genesis file {:?}: {e}", args.genesis_path);
            std::process::exit(1);
        }
    };

    // Build and run the node
    let mut node = match node::Node::new_with_p2p_port(
        &genesis_json, args.validator_address, args.p2p_port,
    ).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Error: failed to initialise node: {e}");
            std::process::exit(1);
        }
    };

    info!(
        chain_id = %node.chain_id(),
        environment = %node.environment(),
        "node initialised successfully"
    );

    // Start HTTP API FIRST so it's available immediately.
    let status        = node.status();
    let explorer      = node.explorer();
    let cirfi_metrics = node.cirfi_metrics();
    let peers         = node.peers();
    let api_port      = args.api_port;
    tokio::spawn(async move {
        api::serve(api_port, status, explorer, cirfi_metrics, peers).await;
    });

    // Give the API a moment to bind before the event loop starts.
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Run the main event loop (blocks until node exits).
    node.run().await;
}
