//! chain-forge-keygen -- generate an Ed25519 key file for a Chain Forge account.
//!
//! Two uses:
//!   chain-forge-keygen --out me.key.json
//!       New account. Its address is DERIVED from the key, so it can
//!       register and transact immediately; the key is bound on first use.
//!
//!   chain-forge-keygen --out alice.key.json --address qcb1alice
//!       Key for a NAMED genesis account. Named addresses aren't derived
//!       from keys, so the printed public key must be added to that
//!       account's "public_key" in the genesis file before the account
//!       can transact.
//!
//! The key file holds the PRIVATE key. Anyone with the file controls the
//! account. Never commit it, never copy it anywhere it doesn't need to be.

use chain_forge_core::{Address, HashWidth};
use chain_forge_crypto::ClassicalScheme;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out: Option<String> = None;
    let mut named: Option<String> = None;
    let mut prefix = "qcb".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out"     => { i += 1; out = args.get(i).cloned(); }
            "--address" => { i += 1; named = args.get(i).cloned(); }
            "--prefix"  => { i += 1; if let Some(p) = args.get(i) { prefix = p.clone(); } }
            "--help" | "-h" => {
                println!("chain-forge-keygen --out <file> [--address <named-genesis-address>] [--prefix qcb]");
                return;
            }
            other => { eprintln!("unknown argument: {other}"); std::process::exit(2); }
        }
        i += 1;
    }

    let Some(out) = out else {
        eprintln!("--out <file> is required");
        std::process::exit(2);
    };
    if std::path::Path::new(&out).exists() {
        eprintln!("refusing to overwrite existing key file {out}");
        std::process::exit(1);
    }

    let kp = match ClassicalScheme.generate_random() {
        Ok(k) => k,
        Err(e) => { eprintln!("key generation failed: {e}"); std::process::exit(1); }
    };
    let derived = Address::from_public_key(&kp.public_key, &prefix, HashWidth::Bits256);
    let address = named.clone().unwrap_or_else(|| derived.as_str().to_string());

    let file = serde_json::json!({
        "scheme":      "classical-ed25519",
        "address":     address,
        "public_key":  hex(&kp.public_key),
        "private_key": hex(&kp.private_key),
    });
    if let Err(e) = std::fs::write(&out, serde_json::to_string_pretty(&file).unwrap()) {
        eprintln!("could not write {out}: {e}");
        std::process::exit(1);
    }

    println!("wrote {out}");
    println!("  address:    {address}");
    println!("  public_key: {}", hex(&kp.public_key));
    if named.is_some() {
        println!();
        println!("Named account: add this to its entry in the genesis file:");
        println!("  \"public_key\": \"{}\"", hex(&kp.public_key));
    }
    println!();
    println!("{out} contains the PRIVATE key. Keep it off git and off shared drives.");
}
