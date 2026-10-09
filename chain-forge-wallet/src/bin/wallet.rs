//! qcb-wallet — CLI for QCB-WALLET-001
//!
//! Subcommands:
//!   generate --out <file> [--label <name>]
//!       Generate a new ML-DSA-65 wallet.  Prompts for passphrase.
//!
//!   address --wallet <file>
//!       Print the wallet's QCB address (no passphrase needed).
//!
//!   info --wallet <file>
//!       Print wallet metadata (scheme, address, public key prefix, created_at).
//!
//!   sign-tx --wallet <file> --body <json>
//!       Sign a transaction body JSON string. Prints hex signature.
//!
//!   submit --wallet <file> --body <json> --node <host:port> [--dry-run]
//!       Sign and submit a transaction to a QCB node.
//!
//! Environment variable: QCB_WALLET_PASSPHRASE — bypasses interactive prompt
//! (useful for scripts and tests; keep secrets out of shell history).

use chain_forge_wallet::{
    generate_wallet, load_wallet, sign_transaction, submit_tx,
    SignedTxEnvelope,
};

fn usage() -> ! {
    eprintln!("qcb-wallet — QCB-WALLET-001 post-quantum wallet");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  qcb-wallet generate --out <file> [--label <name>]");
    eprintln!("  qcb-wallet address  --wallet <file>");
    eprintln!("  qcb-wallet info     --wallet <file>");
    eprintln!("  qcb-wallet sign-tx  --wallet <file> --body <json>");
    eprintln!("  qcb-wallet submit   --wallet <file> --body <json> --node <host:port> [--dry-run]");
    eprintln!();
    eprintln!("Set QCB_WALLET_PASSPHRASE env var to skip the passphrase prompt.");
    std::process::exit(2);
}

fn passphrase() -> String {
    if let Ok(p) = std::env::var("QCB_WALLET_PASSPHRASE") {
        return p;
    }
    eprint!("Passphrase: ");
    // Simple passphrase read: avoid echo in a real terminal; for Phase 1 devnet
    // this is acceptable (devnet keys are not production keys).
    let mut pass = String::new();
    std::io::stdin().read_line(&mut pass).unwrap_or(0);
    pass.trim().to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { usage(); }

    match args[1].as_str() {
        "generate" => cmd_generate(&args[2..]),
        "address"  => cmd_address(&args[2..]),
        "info"     => cmd_info(&args[2..]),
        "sign-tx"  => cmd_sign_tx(&args[2..]),
        "submit"   => cmd_submit(&args[2..]),
        "--help" | "-h" => usage(),
        other => {
            eprintln!("unknown subcommand: {other}");
            usage();
        }
    }
}

fn cmd_generate(args: &[String]) {
    let mut out: Option<String>   = None;
    let mut label = "my-wallet".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out"   => { i += 1; out   = args.get(i).cloned(); }
            "--label" => { i += 1; if let Some(l) = args.get(i) { label = l.clone(); } }
            other => { eprintln!("unknown flag: {other}"); usage(); }
        }
        i += 1;
    }

    let out = out.unwrap_or_else(|| { eprintln!("--out <file> is required"); usage(); });
    let passphrase = passphrase();

    println!("Generating ML-DSA-65 key pair…");
    match generate_wallet(&out, &label, &passphrase) {
        Ok(kf) => {
            println!("✓  Wallet written to: {out}");
            println!("   Address:    {}", kf.address);
            println!("   Scheme:     {}", kf.scheme);
            println!("   Public key: {}…", &kf.public_key[..32]);
            println!();
            println!("IMPORTANT: This file contains your encrypted private key.");
            println!("  • Never commit *.wallet.json to git.");
            println!("  • Back up the file AND remember your passphrase.");
            println!("  • There is no recovery if both are lost.");
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_address(args: &[String]) {
    let wallet = wallet_flag(args);
    let json = std::fs::read_to_string(&wallet).unwrap_or_else(|_| {
        eprintln!("could not read wallet file: {wallet}");
        std::process::exit(1);
    });
    let kf: chain_forge_wallet::WalletKeyFile = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("invalid wallet file: {e}");
        std::process::exit(1);
    });
    println!("{}", kf.address);
}

fn cmd_info(args: &[String]) {
    let wallet = wallet_flag(args);
    let json = std::fs::read_to_string(&wallet).unwrap_or_else(|_| {
        eprintln!("could not read wallet file: {wallet}");
        std::process::exit(1);
    });
    let kf: chain_forge_wallet::WalletKeyFile = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("invalid wallet file: {e}");
        std::process::exit(1);
    });
    println!("Wallet: {wallet}");
    println!("  label:      {}", kf.label);
    println!("  scheme:     {}", kf.scheme);
    println!("  address:    {}", kf.address);
    println!("  public_key: {}… ({} chars)", &kf.public_key[..32], kf.public_key.len());
    println!("  kdf:        {} m={} t={} p={}",
        kf.kdf.algorithm, kf.kdf.m_cost, kf.kdf.t_cost, kf.kdf.p_cost);
    println!("  created_at: {}", kf.created_at);
}

fn cmd_sign_tx(args: &[String]) {
    let mut wallet: Option<String> = None;
    let mut body:   Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" => { i += 1; wallet = args.get(i).cloned(); }
            "--body"   => { i += 1; body   = args.get(i).cloned(); }
            other => { eprintln!("unknown flag: {other}"); usage(); }
        }
        i += 1;
    }

    let wallet = wallet.unwrap_or_else(|| { eprintln!("--wallet is required"); usage(); });
    let body   = body.unwrap_or_else(||   { eprintln!("--body is required"); usage(); });
    let pass   = passphrase();

    let (_kf, kp) = load_wallet(&wallet, &pass).unwrap_or_else(|e| {
        eprintln!("error loading wallet: {e}");
        std::process::exit(1);
    });

    match sign_transaction(&body, &kp) {
        Ok(sig_hex) => {
            println!("mldsa65:{sig_hex}");
        }
        Err(e) => {
            eprintln!("signing failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_submit(args: &[String]) {
    let mut wallet:  Option<String> = None;
    let mut body:    Option<String> = None;
    let mut node:    Option<String> = None;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet"  => { i += 1; wallet  = args.get(i).cloned(); }
            "--body"    => { i += 1; body    = args.get(i).cloned(); }
            "--node"    => { i += 1; node    = args.get(i).cloned(); }
            "--dry-run" => { dry_run = true; }
            other => { eprintln!("unknown flag: {other}"); usage(); }
        }
        i += 1;
    }

    let wallet = wallet.unwrap_or_else(|| { eprintln!("--wallet is required"); usage(); });
    let body   = body.unwrap_or_else(||   { eprintln!("--body is required"); usage(); });
    let pass   = passphrase();

    let (kf, kp) = load_wallet(&wallet, &pass).unwrap_or_else(|e| {
        eprintln!("error loading wallet: {e}");
        std::process::exit(1);
    });

    // Parse body JSON
    let body_value: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| {
        eprintln!("--body is not valid JSON: {e}");
        std::process::exit(1);
    });

    // Sign the body
    let sig_hex = sign_transaction(&body, &kp).unwrap_or_else(|e| {
        eprintln!("signing failed: {e}");
        std::process::exit(1);
    });

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let env = SignedTxEnvelope {
        id:        format!("wallet-tx-{nonce}"),
        sender:    kf.address.clone(),
        nonce,
        body:      body_value,
        gas_limit: 500_000,
        signature: vec![format!("mldsa65:{sig_hex}")],
    };

    if dry_run {
        println!("-- DRY RUN (not submitted) --");
        println!("{}", serde_json::to_string_pretty(&env).unwrap());
        return;
    }

    let node_str = node.unwrap_or_else(|| { eprintln!("--node is required (not --dry-run)"); usage(); });
    let (host, port_str) = node_str.split_once(':').unwrap_or_else(|| {
        eprintln!("--node must be host:port (e.g. 127.0.0.1:8080)");
        std::process::exit(1);
    });
    let port: u16 = port_str.parse().unwrap_or_else(|_| {
        eprintln!("port must be a number");
        std::process::exit(1);
    });

    println!("Submitting to http://{host}:{port}/api/tx …");
    match submit_tx(host, port, &env) {
        Ok(resp) => {
            println!("Response: {}", serde_json::to_string_pretty(&resp).unwrap());
        }
        Err(e) => {
            eprintln!("submission failed: {e}");
            std::process::exit(1);
        }
    }
}

fn wallet_flag(args: &[String]) -> String {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--wallet" {
            if let Some(v) = args.get(i + 1) {
                return v.clone();
            }
        }
        i += 1;
    }
    eprintln!("--wallet <file> is required");
    usage();
}
