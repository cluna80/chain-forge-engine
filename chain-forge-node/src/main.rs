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
    /// Path to this validator's key file (*.key.json). Required for signing
    /// proposals and votes on a real multi-node network.
    key_file: Option<std::path::PathBuf>,
    /// Directory to persist state between restarts. If absent, state is lost on shutdown.
    data_dir: Option<std::path::PathBuf>,
    /// Extra bootstrap peer addresses (libp2p multiaddrs, e.g. /ip4/127.0.0.1/tcp/27001).
    /// Merged with genesis `network.bootstrap_nodes`. Repeatable: --bootstrap A --bootstrap B.
    bootstrap_peers: Vec<String>,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut genesis_path = PathBuf::from("genesis.json");
    let mut validator_address = None;
    let mut api_port = 8080u16;
    let mut p2p_port: Option<u16> = None;
    let mut key_file: Option<std::path::PathBuf> = None;
    let mut data_dir: Option<std::path::PathBuf> = None;
    let mut bootstrap_peers: Vec<String> = Vec::new();

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
            "--data-dir" | "-d" => {
                i += 1;
                if i < args.len() { data_dir = Some(std::path::PathBuf::from(&args[i])); }
            }
            "--key-file" | "-k" => {
                i += 1;
                if i < args.len() { key_file = Some(std::path::PathBuf::from(&args[i])); }
            }
            "--bootstrap" | "-b" => {
                i += 1;
                if i < args.len() { bootstrap_peers.push(args[i].clone()); }
            }
            "--help" | "-h" => {
                println!("chain-forge-node");
                println!("  --genesis <path>     Path to genesis.json (default: genesis.json)");
                println!("  --validator <addr>   This node's validator address");
                println!("  --api-port <port>    HTTP API port (default: 8080)");
                println!("  --p2p-port <port>    Override P2P bind port from genesis");
                println!("  --key-file <path>    Path to this validator's *.key.json file (for signing)");
                println!("  --data-dir <path>    Directory to persist chain state (default: memory-only)");
                println!("                       (needed to run multiple local nodes)");
                println!("  --bootstrap <addr>   Extra bootstrap peer (libp2p multiaddr, e.g. /ip4/127.0.0.1/tcp/27001)");
                println!("                       Repeatable: --bootstrap A --bootstrap B");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    Args { genesis_path, validator_address, api_port, p2p_port, key_file, data_dir, bootstrap_peers }
}

#[tokio::main]
async fn main() {
    // Initialise structured logging. Without an explicit EnvFilter, the
    // default subscriber does NOT read RUST_LOG at all -- setting
    // $env:RUST_LOG="debug" silently had no effect, which is exactly why
    // debug-level diagnostics (received gossip, sync requests, etc.) never
    // showed up no matter what the env var was set to. Falls back to "info"
    // when RUST_LOG isn't set, matching the previous default behavior.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_env_filter(filter)
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

    // Build and run the node. Pass CLI-supplied bootstrap peers so nodes can
    // find each other immediately via direct dial rather than relying on mDNS
    // (which is unreliable in CI / container environments).
    let mut node = match node::Node::new_with_config(
        &genesis_json, args.validator_address, args.p2p_port, args.bootstrap_peers,
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
    let qrc_metrics = node.qrc_metrics();
    let peers         = node.peers();
    let tx_queue      = node.tx_queue();
    let api_port      = args.api_port;
    let precheck      = api::TxPrecheck {
        chain_id:           node.chain_id().to_string(),
        require_signatures: node.require_signatures(),
        modules:            node.enabled_modules(),
    };
    // Set the data directory for state persistence.
    if let Some(ref dir) = args.data_dir {
        match node.set_data_dir(dir.clone()) {
            Ok(()) => {
                if node.load_persisted_state() {
                    info!(dir = %dir.display(), "resumed from persisted state");
                } else {
                    info!(dir = %dir.display(), "no persisted state found — starting from genesis");
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not set data dir — running memory-only"),
        }
    }

    // Load the validator signing key if one was supplied.
    if let Some(ref path) = args.key_file {
        if let Err(e) = node.load_signing_key(path) {
            tracing::warn!(path = %path.display(), error = %e, "could not load key file — node will run as observer");
        }
    }

    info!(require_signatures = precheck.require_signatures, "transaction signature enforcement");
    tokio::spawn(async move {
        api::serve(api_port, status, explorer, qrc_metrics, peers, tx_queue, precheck).await;
    });

    // Give the API a moment to bind before the event loop starts.
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Run the main event loop (blocks until node exits).
    node.run().await;
}
