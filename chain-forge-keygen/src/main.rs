//! qcb-keygen — Generate ML-DSA-65 and Ed25519 keypairs for QCB devnet.
//!
//! Usage:
//!   qcb-keygen mldsa <label>       — generate an ML-DSA-65 keypair
//!   qcb-keygen ed25519 <label>     — generate an Ed25519 keypair
//!
//! Output: JSON to stdout, save to a file:
//!   qcb-keygen mldsa alice-settlement > alice-mldsa.key.json

use chain_forge_crypto::{ClassicalScheme, MlDsaScheme};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: qcb-keygen <mldsa|ed25519> <label>");
        std::process::exit(1);
    }

    let scheme_name = &args[1];
    let label       = &args[2];

    match scheme_name.as_str() {
        "mldsa" => {
            // Fresh OS-random key; the label is only a name.
            let kp = MlDsaScheme.generate_random().expect("ML-DSA keygen failed");

            let out = serde_json::json!({
                "label":       label,
                "scheme":      "mldsa65",
                "public_key":  hex::encode(&kp.public_key),
                "private_key": hex::encode(&kp.private_key),
                "public_key_bytes":  kp.public_key.len(),
                "private_key_bytes": kp.private_key.len(),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }

        "ed25519" => {
            // Fresh OS-random key. (It used to be SHA-256 of the label, so
            // anyone who knew the label could recompute the private key.)
            let kp = ClassicalScheme.generate_random().expect("Ed25519 keygen failed");

            let out = serde_json::json!({
                "label":      label,
                "scheme":     "classical-ed25519",
                "address":    format!("qcb1{}", label.to_lowercase().replace(' ', "")),
                "public_key": hex::encode(&kp.public_key),
                "private_key": hex::encode(&kp.private_key),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }

        other => {
            eprintln!("Unknown scheme '{other}'. Use 'mldsa' or 'ed25519'.");
            std::process::exit(1);
        }
    }
}
