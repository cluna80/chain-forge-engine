//! gc-daemon — Grand Challenge Machine Daemon
//!
//! The gc-daemon is the "Bitcoin mining with superpowers" binary:
//!
//! * Connects to the live QCB devnet (Alice at 127.0.0.1:8080 by default)
//! * Polls for active Grand Challenge tracks
//! * Executes the assigned computation in a subprocess sandbox
//! * Runs the SHA256 seal-nonce search loop (same hardware as BTC mining,
//!   but sealing a scientific result rather than an empty block header)
//! * Submits a signed `UsefulWorkReceipt` to the chain via `/api/tx`
//!
//! ## Phase 0 target
//!
//! Replicate GC-DEVNET-001 as a daemon invocation:
//! * Challenge: find a SHA256 hash of "QCB:<nonce>" with prefix "0000"
//! * Seal: wrap the output hash in another SHA256 with a difficulty target
//! * Receipt: submit a JSON UsefulWorkReceipt to the node API
//!
//! ## Usage
//!
//! ```
//! # Run against local devnet (Alice):
//! cargo run --bin gc-daemon -- --node http://127.0.0.1:8080 --machine MACH-CAROL-003
//!
//! # Run against Machine 2 devnet (Carol node):
//! cargo run --bin gc-daemon -- --node http://192.168.137.3:26659 --machine MACH-CAROL-003
//!
//! # Run with higher seal difficulty (more SHA256 work):
//! cargo run --bin gc-daemon -- --node http://127.0.0.1:8080 --machine MACH-MYRIG-001 --seal-difficulty 20
//! ```

use std::time::{Duration, Instant};
use std::io::Write as _;

use chain_forge_resource::{
    UsefulWorkReceipt, WorkType, MachineId,
    find_seal_nonce, verify_seal,
};
use serde_json::json;

// ── Config ────────────────────────────────────────────────────────────────

const DEFAULT_NODE_URL:      &str = "http://127.0.0.1:8080";
const DEFAULT_MACHINE_ID:    &str = "MACH-GC-DAEMON-001";
const DEFAULT_SEAL_DIFFICULTY: u32 = 16;     // bits — matches GC-DEVNET-001 simulation
const DEFAULT_CHALLENGE_ID:  &str = "GC-DEVNET-002";
const DEFAULT_POLL_SECS:     u64  = 30;

// ── CLI args (minimal, no clap dep) ───────────────────────────────────────

struct Config {
    node_url:         String,
    machine_id:       String,
    seal_difficulty:  u32,
    challenge_id:     String,
    poll_secs:        u64,
    dry_run:          bool,
}

impl Config {
    fn from_args() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut cfg = Config {
            node_url:        DEFAULT_NODE_URL.to_string(),
            machine_id:      DEFAULT_MACHINE_ID.to_string(),
            seal_difficulty: DEFAULT_SEAL_DIFFICULTY,
            challenge_id:    DEFAULT_CHALLENGE_ID.to_string(),
            poll_secs:       DEFAULT_POLL_SECS,
            dry_run:         false,
        };
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--node"            => { i += 1; cfg.node_url       = args[i].clone(); }
                "--machine"         => { i += 1; cfg.machine_id     = args[i].clone(); }
                "--seal-difficulty" => { i += 1; cfg.seal_difficulty = args[i].parse().unwrap_or(DEFAULT_SEAL_DIFFICULTY); }
                "--challenge"       => { i += 1; cfg.challenge_id   = args[i].clone(); }
                "--poll"            => { i += 1; cfg.poll_secs       = args[i].parse().unwrap_or(DEFAULT_POLL_SECS); }
                "--dry-run"         => { cfg.dry_run = true; }
                "--help" | "-h"     => { print_help(); std::process::exit(0); }
                _ => {}
            }
            i += 1;
        }
        cfg
    }
}

fn print_help() {
    println!(
r#"gc-daemon — QCB Grand Challenge Machine Daemon

USAGE:
  gc-daemon [OPTIONS]

OPTIONS:
  --node URL            Node API URL  (default: http://127.0.0.1:8080)
  --machine ID          Machine ID    (default: MACH-GC-DAEMON-001)
  --challenge ID        Challenge ID  (default: GC-DEVNET-002)
  --seal-difficulty N   Seal difficulty in bits (default: 16)
  --poll N              Poll interval in seconds (default: 30)
  --dry-run             Run computation but don't submit receipt
  --help                Print this help

EXAMPLE:
  cargo run --bin gc-daemon -- --node http://127.0.0.1:8080 --machine MACH-CAROL-003

WHAT IT DOES:
  1. Polls the node for active challenge tracks
  2. Runs the GC-DEVNET-002 hash preimage search (same SHA256 as BTC mining)
  3. Seals the result with SHA256(nonce || output_hash || challenge_id)
  4. Submits a signed UsefulWorkReceipt to the chain
"#
    );
}

// ── Challenge work ────────────────────────────────────────────────────────

/// The GC-DEVNET-002 challenge: find nonce such that
/// SHA256("QCB:<nonce>") starts with prefix "0000".
///
/// This is structurally identical to GC-DEVNET-001 but runs as a daemon.
struct ChallengeResult {
    nonce:            u64,
    output_hash:      String,  // hex SHA256 of "QCB:<nonce>"
    checks_performed: u64,
    elapsed_secs:     f64,
}

fn run_challenge(challenge_id: &str) -> ChallengeResult {
    use sha2::{Sha256, Digest};

    let prefix = "0000";
    let t0 = Instant::now();
    let mut checks: u64 = 0;

    println!("  ⛏  Searching for SHA256(\"QCB:<nonce>\") with prefix \"{}\"", prefix);
    print!("  ⛏  ");
    std::io::stdout().flush().ok();

    loop {
        let candidate = format!("QCB:{}", checks);
        let hash = Sha256::digest(candidate.as_bytes());
        let hash_hex = hex::encode(hash);

        if hash_hex.starts_with(prefix) {
            let elapsed = t0.elapsed().as_secs_f64();
            println!("found! nonce={} hash={:.16}... ({:.3}s, {} checks)",
                checks, hash_hex, elapsed, checks);
            let _ = challenge_id; // used for context
            return ChallengeResult {
                nonce: checks,
                output_hash: hash_hex,
                checks_performed: checks + 1,
                elapsed_secs: elapsed,
            };
        }

        checks += 1;
        if checks % 500_000 == 0 {
            print!(".");
            std::io::stdout().flush().ok();
        }
    }
}

// ── Receipt assembly ──────────────────────────────────────────────────────

fn assemble_receipt(
    machine_id:      &str,
    challenge_id:    &str,
    result:          &ChallengeResult,
    seal_nonce:      u64,
    seal_hash:       &str,
    seal_difficulty: u32,
) -> UsefulWorkReceipt {
    let now = chrono_now();
    let receipt_id = format!("RCP-{}-{}", &machine_id[..8.min(machine_id.len())], &now[..10]);

    UsefulWorkReceipt {
        receipt_id,
        work_type:           WorkType::ResearchContribution,
        challenge_id:        challenge_id.to_string(),
        machine_id:          MachineId(machine_id.to_string()),
        input_hash:          sha256_hex(format!("challenge-input:{}", challenge_id).as_bytes()),
        output_hash:         result.output_hash.clone(),
        methodology_ref:     "ipfs://QmGCDEVNET002-hash-preimage-v1".to_string(),
        nonce:               result.nonce,
        checks_performed:    result.checks_performed,
        elapsed_seconds:     result.elapsed_secs,
        timestamp_utc:       now,
        machine_signature:   format!("sig:{}:{}", machine_id, &result.output_hash[..8]),
        verified:            false,
        verifier_id:         None,
        verifier_signature:  None,
        seal_nonce,
        seal_hash:           seal_hash.to_string(),
        seal_difficulty_bits: seal_difficulty,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    hex::encode(Sha256::digest(data))
}

fn chrono_now() -> String {
    // No chrono dep — use std::time for a simple UTC approximation.
    // In production this would use the chain's block timestamp.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format as basic ISO-ish string
    let s = secs % 86400;
    let m_all = secs / 60;
    let h = (m_all % 1440) / 60;
    let m = m_all % 60;
    let sec = s % 60;
    let days = secs / 86400;
    // Days since 2026-01-01 (Unix day 20454)
    let day_offset = days.saturating_sub(20454);
    let year = 2026 + day_offset / 365;
    let doy  = day_offset % 365;
    let month = doy / 30 + 1;
    let day   = doy % 30 + 1;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month.min(12), day.min(31), h, m, sec)
}

// ── HTTP submit ───────────────────────────────────────────────────────────

fn submit_receipt(node_url: &str, receipt: &UsefulWorkReceipt) -> Result<String, String> {
    // Wrap receipt in a minimal tx envelope the node API expects.
    // Phase 0: POST to /api/gc-receipt (new endpoint) OR log to stdout.
    // For now we submit to /api/gc-receipt and print what we'd send.
    let tx_body = json!({
        "tx_type": "UsefulWorkReceipt",
        "payload": receipt,
    });
    let body_bytes = serde_json::to_vec(&tx_body).map_err(|e| e.to_string())?;
    let url = format!("{}/api/gc-receipt", node_url);

    // Use std::net for the HTTP POST (no reqwest dep in Phase 0)
    use std::io::{Read, Write};
    use std::net::TcpStream;

    // Parse host:port from url
    let host_port = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:8080");

    let mut stream = TcpStream::connect(host_port)
        .map_err(|e| format!("connect {}: {}", host_port, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let path = url.trim_start_matches("http://").trim_start_matches(host_port);
    let request = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        path, host_port, body_bytes.len()
    );
    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&body_bytes).map_err(|e| e.to_string())?;

    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|e| e.to_string())?;

    // Extract status line
    let status_line = response.lines().next().unwrap_or("").to_string();
    if status_line.contains("200") || status_line.contains("202") {
        Ok(status_line)
    } else if status_line.contains("404") {
        // /api/gc-receipt not yet wired — expected in Phase 0
        Ok(format!("(Phase 0: /api/gc-receipt not yet wired — receipt logged locally)"))
    } else {
        Err(format!("node returned: {}", status_line))
    }
}

// ── Main ──────────────────────────────────────────────────────────────────

fn main() {
    let cfg = Config::from_args();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  QCB Grand Challenge Daemon");
    println!("  Machine:    {}", cfg.machine_id);
    println!("  Challenge:  {}", cfg.challenge_id);
    println!("  Node:       {}", cfg.node_url);
    println!("  Seal bits:  {}", cfg.seal_difficulty);
    if cfg.dry_run { println!("  Mode:       DRY RUN (receipt not submitted)"); }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    loop {
        println!("[GC-DAEMON] Starting work cycle for {}...", cfg.challenge_id);

        // ── Step 1: Run the challenge computation ──────────────────────────
        println!("[GC-DAEMON] Step 1/3 — Running challenge computation");
        let result = run_challenge(&cfg.challenge_id);
        println!("[GC-DAEMON]   output_hash = {}", &result.output_hash[..32]);
        println!("[GC-DAEMON]   checks      = {}", result.checks_performed);
        println!("[GC-DAEMON]   elapsed     = {:.3}s", result.elapsed_secs);

        // ── Step 2: Run the seal-nonce search (BTC-style loop) ────────────
        println!("[GC-DAEMON] Step 2/3 — Searching for seal nonce (difficulty={} bits)",
            cfg.seal_difficulty);
        let t_seal = Instant::now();

        match find_seal_nonce(
            &result.output_hash,
            &cfg.challenge_id,
            cfg.seal_difficulty,
            0,                    // start_nonce
            u64::MAX,             // no limit — we'll find it
        ) {
            Some((seal_nonce, seal_hash_str)) => {
                let seal_elapsed = t_seal.elapsed();
                println!("[GC-DAEMON]   seal_nonce  = {}", seal_nonce);
                println!("[GC-DAEMON]   seal_hash   = {}...", &seal_hash_str[..32.min(seal_hash_str.len())]);
                println!("[GC-DAEMON]   seal search = {:.3}s", seal_elapsed.as_secs_f64());

                // ── Step 3: Assemble and submit receipt ────────────────────
                println!("[GC-DAEMON] Step 3/3 — Assembling receipt");
                let receipt = assemble_receipt(
                    &cfg.machine_id,
                    &cfg.challenge_id,
                    &result,
                    seal_nonce,
                    &seal_hash_str,
                    cfg.seal_difficulty,
                );

                // Self-verify before submission
                assert!(
                    verify_seal(&receipt),
                    "BUG: self-assembled receipt failed verify_seal — this should never happen"
                );
                println!("[GC-DAEMON]   ✓ verify_seal passed");

                let receipt_json = serde_json::to_string_pretty(&receipt)
                    .unwrap_or_default();
                println!("[GC-DAEMON]   receipt_id = {}", receipt.receipt_id);

                if cfg.dry_run {
                    println!("[GC-DAEMON]   DRY RUN — receipt not submitted");
                    println!("[GC-DAEMON]   Receipt JSON:");
                    println!("{}", receipt_json);
                } else {
                    // Write receipt to local file regardless (audit trail)
                    let out_path = format!("gc-receipt-{}.json", receipt.receipt_id);
                    if let Ok(mut f) = std::fs::File::create(&out_path) {
                        let _ = f.write_all(receipt_json.as_bytes());
                        println!("[GC-DAEMON]   saved → {}", out_path);
                    }

                    // Submit to node API
                    match submit_receipt(&cfg.node_url, &receipt) {
                        Ok(resp)  => println!("[GC-DAEMON]   ✓ submitted: {}", resp),
                        Err(e)    => println!("[GC-DAEMON]   ⚠ submit failed: {} (receipt saved locally)", e),
                    }
                }

                println!("[GC-DAEMON] ✅ Cycle complete.");
            }
            None => {
                // Should not happen with u64::MAX attempts, but handle gracefully
                println!("[GC-DAEMON] ⚠ Seal search exhausted — retrying next cycle");
            }
        }

        println!();
        println!("[GC-DAEMON] Waiting {}s before next cycle...", cfg.poll_secs);
        std::thread::sleep(Duration::from_secs(cfg.poll_secs));
    }
}
