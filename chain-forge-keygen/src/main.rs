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

        #[cfg(feature = "signing-v2")]
        "mldsa-v2" => v2::cmd_generate(&args[2..]),

        #[cfg(feature = "signing-v2")]
        "check-v2" => v2::cmd_check(&args[2..]),

        other => {
            eprintln!("Unknown scheme '{other}'. Use 'mldsa' or 'ed25519'.");
            std::process::exit(1);
        }
    }
}

/// TEST-ONLY signing-v2 key generation and checking (feature `signing-v2`). Conforming FIPS 204 ML-DSA-65 key generation.
/// Secrets go to a file (never a terminal), the file is never overwritten, and is owner-only on Unix. Production randomness
/// and key-management policy are separate gates (see the PR).
#[cfg(feature = "signing-v2")]
mod v2 {
    use chain_forge_core::{Address, AddressScheme, HashWidth};
    use chain_forge_crypto::fips204_backend::{MlDsa65Fips204 as B, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES};
    use std::io::Write;

    fn die(msg: &str) -> ! { eprintln!("error: {msg}"); std::process::exit(1) }

    fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

    fn unhex(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) { return None; }
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
    }

    fn address(pk: &[u8], prefix: &str) -> String {
        Address::from_public_key_schemed(pk, prefix, HashWidth::Bits256, AddressScheme::PostQuantum).as_str().to_string()
    }

    pub fn cmd_generate(args: &[String]) {
        let (mut label, mut out, mut prefix) = (None::<String>, None::<String>, "qcb".to_string());
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--out" => { i += 1; out = args.get(i).cloned(); }
                "--prefix" => { i += 1; if let Some(p) = args.get(i) { prefix = p.clone(); } }
                other if other.starts_with("--") => die(&format!("unknown flag {other}")),
                other => label = Some(other.to_string()),
            }
            i += 1;
        }
        let label = label.unwrap_or_else(|| die("usage: qcb-keygen mldsa-v2 <label> --out <file> [--prefix <p>]"));
        let out = out.unwrap_or_else(|| die("--out <file> is required: secret keys are never printed to a terminal"));

        let (seed, kp) = B::generate().unwrap_or_else(|e| die(&format!("key generation failed: {e}")));
        let doc = serde_json::json!({
            "label": label,
            "scheme": "ml-dsa-65",
            "address": address(&kp.public_key, &prefix),
            "public_key": hex(&kp.public_key),
            "seed": hex(&seed),
            "private_key": hex(&kp.private_key),
        });
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true); // never overwrite an existing key file
        #[cfg(unix)]
        { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o600); }
        let mut f = opts.open(&out).unwrap_or_else(|e| die(&format!("cannot create {out}: {e}")));
        f.write_all(serde_json::to_string_pretty(&doc).unwrap().as_bytes()).unwrap_or_else(|e| die(&format!("write failed: {e}")));
        f.sync_all().unwrap_or_else(|e| die(&format!("sync failed: {e}")));
        println!("key written to {out}");
        println!("address:    {}", doc["address"].as_str().unwrap());
        println!("public_key: {}…", &hex(&kp.public_key)[..32]);
    }

    pub fn cmd_check(args: &[String]) {
        let mut file = None::<String>;
        let mut prefix = "qcb".to_string();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--prefix" => { i += 1; if let Some(p) = args.get(i) { prefix = p.clone(); } }
                other if other.starts_with("--") => die(&format!("unknown flag {other}")),
                other => file = Some(other.to_string()),
            }
            i += 1;
        }
        let file = file.unwrap_or_else(|| die("usage: qcb-keygen check-v2 <file> [--prefix <p>]"));
        let raw = std::fs::read(&file).unwrap_or_else(|e| die(&format!("cannot read {file}: {e}")));
        let j: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_else(|e| die(&format!("not valid JSON: {e}")));
        let field = |name: &str, len: usize| -> Vec<u8> {
            let s = j[name].as_str().unwrap_or_else(|| die(&format!("missing field {name}")));
            let b = unhex(s).unwrap_or_else(|| die(&format!("{name} is not valid hex")));
            if b.len() != len { die(&format!("{name} has {} bytes, expected {len}", b.len())); }
            b
        };
        let pk = field("public_key", PUBLIC_KEY_BYTES);
        let sk = field("private_key", SECRET_KEY_BYTES);
        B::validate_keypair(&pk, &sk).unwrap_or_else(|e| die(&format!("key pair is not consistent: {e}")));
        if j.get("seed").is_some() {
            let seed = field("seed", 32);
            let mut s = [0u8; 32]; s.copy_from_slice(&seed);
            if B::keygen_from_seed(&s).public_key != pk { die("seed does not regenerate the public key"); }
        }
        let addr = address(&pk, &prefix);
        if let Some(a) = j.get("address") {
            if a.as_str() != Some(addr.as_str()) { die("address does not match the public key"); }
        }
        println!("ok: ML-DSA-65 key file is consistent");
        println!("address:    {addr}");
        println!("public_key: {}…", &hex(&pk)[..32]);
        println!("seed:       {}", if j.get("seed").is_some() { "present, regenerates the public key" } else { "absent (legacy file)" });
    }
}
