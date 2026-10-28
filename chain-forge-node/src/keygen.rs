/// chain-forge-keygen
///
/// Generates consensus signing key files for Chain Forge validators.
///
/// Each key file is a JSON object:
///   {
///     "address":     "qcb1alice",          -- validator address (matches genesis)
///     "scheme":      "ed25519",             -- "ed25519" (default) or "ml-dsa-65"
///     "public_key":  "<hex>",               -- 32-byte Ed25519 / 1952-byte ML-DSA-65 key
///     "private_key": "<hex>"                -- 32-byte Ed25519 seed / 4032-byte ML-DSA-65 key
///   }
///
/// Usage:
///   chain-forge-keygen --address qcb1alice --out keys/qcb1alice.key.json
///   chain-forge-keygen --address qcb1alice --scheme ml-dsa-65 --out keys/qcb1alice.key.json
///   chain-forge-keygen --address qcb1bob   --out keys/qcb1bob.key.json
///   chain-forge-keygen --address qcb1carol --out keys/qcb1carol.key.json
///
/// The public_key field must be copied into the matching genesis account's
/// "public_key" field so that peer validators can verify signatures without
/// an out-of-band key exchange.

use chain_forge_crypto::{ClassicalScheme, MlDsaScheme, SignatureScheme};
use std::path::PathBuf;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Args {
    address: String,
    out:     PathBuf,
    force:   bool,
    mldsa:   bool,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut address = String::new();
    let mut out     = PathBuf::new();
    let mut force   = false;
    let mut mldsa   = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--address" | "-a" => {
                i += 1;
                if i < args.len() { address = args[i].clone(); }
            }
            "--out" | "-o" => {
                i += 1;
                if i < args.len() { out = PathBuf::from(&args[i]); }
            }
            "--force" | "-f" => { force = true; }
            "--scheme" | "-s" => {
                i += 1;
                match args.get(i).map(String::as_str) {
                    Some("ed25519")   => mldsa = false,
                    Some("ml-dsa-65") => mldsa = true,
                    other => {
                        eprintln!("Error: --scheme must be ed25519 or ml-dsa-65, got {other:?}");
                        std::process::exit(1);
                    }
                }
            }
            "--help" | "-h" => {
                println!("chain-forge-keygen");
                println!("  --address <addr>   Validator address (e.g. qcb1alice)");
                println!("  --out <path>       Output key file path (e.g. keys/qcb1alice.key.json)");
                println!("  --scheme <s>       ed25519 (default) or ml-dsa-65");
                println!("  --force            Overwrite an existing key file");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    if address.is_empty() {
        eprintln!("Error: --address is required");
        eprintln!("Usage: chain-forge-keygen --address qcb1alice --out keys/qcb1alice.key.json");
        std::process::exit(1);
    }
    if out.as_os_str().is_empty() {
        // Default: keys/<address>.key.json
        out = PathBuf::from(format!("keys/{}.key.json", address));
    }

    Args { address, out, force, mldsa }
}

pub fn main() {
    let args = parse_args();

    // Guard against accidental overwrite of an existing key
    if args.out.exists() && !args.force {
        eprintln!(
            "Error: key file already exists: {}\nUse --force to overwrite.",
            args.out.display()
        );
        std::process::exit(1);
    }

    // Create parent directory if needed
    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("Error: cannot create directory {:?}: {e}", parent);
                std::process::exit(1);
            }
        }
    }

    // Fresh random keypair. ML-DSA-65 keygen is randomised per call; the
    // seed argument only names the in-process cache entry.
    let generated = if args.mldsa {
        MlDsaScheme.generate_keypair(&args.address)
    } else {
        ClassicalScheme.generate_random()
    };
    let kp = match generated {
        Ok(k)  => k,
        Err(e) => {
            eprintln!("Error: key generation failed: {e}");
            std::process::exit(1);
        }
    };

    let json = serde_json::json!({
        "address":     args.address,
        "scheme":      if args.mldsa { "ml-dsa-65" } else { "ed25519" },
        "public_key":  hex_encode(&kp.public_key),
        "private_key": hex_encode(&kp.private_key),
    });

    let text = serde_json::to_string_pretty(&json).unwrap() + "\n";

    if let Err(e) = std::fs::write(&args.out, &text) {
        eprintln!("Error: cannot write key file {:?}: {e}", args.out);
        std::process::exit(1);
    }

    println!("Generated key for validator '{}'", args.address);
    println!("  File:       {}", args.out.display());
    println!("  Public key: {}", hex_encode(&kp.public_key));
    println!();
    println!("Add this public_key to the matching genesis account:");
    println!(r#"  {{ "address": "{}", "public_key": "{}" }}"#,
        args.address, hex_encode(&kp.public_key));
    println!();
    println!("Keep the key file SECRET — it contains the private signing key.");
}
