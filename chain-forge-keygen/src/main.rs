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
    // The encrypted-storage commands (issue #107) do their own argument handling and usage errors (exit 2).
    let own_usage = matches!(args.get(1).map(String::as_str), Some("key-new" | "key-check" | "key-migrate"));
    if args.len() < 3 && !own_usage {
        eprintln!("Usage: qcb-keygen <mldsa|ed25519> <label>");
        std::process::exit(1);
    }

    let scheme_name = &args[1];
    let label       = args.get(2).cloned().unwrap_or_default();
    let label       = &label;

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

        // Encrypted production key storage (issue #107; docs/key-storage/SPEC.md).
        #[cfg(feature = "signing-v2")]
        "key-new" => store::cmd_new(&args[2..]),
        #[cfg(feature = "signing-v2")]
        "key-check" => store::cmd_check(&args[2..]),
        #[cfg(feature = "signing-v2")]
        "key-migrate" => store::cmd_migrate(&args[2..]),

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

/// Encrypted key storage commands (issue #107). Secrets never reach a terminal or a log; the passphrase is never accepted on the
/// command line (it would sit in the process list and shell history). Exit codes: 0 ok, 1 failure, 2 usage.
#[cfg(feature = "signing-v2")]
mod store {
    use chain_forge_keygen::keystore::{self, CreateOptions, KdfCost, OsPlatform};
    use std::io::BufRead;
    use std::path::PathBuf;

    fn usage(msg: &str) -> ! {
        eprintln!("error: {msg}");
        eprintln!("usage: qcb-keygen key-new <label> --out <file> [--prefix p] [--passphrase-file f] [--harden-existing-dir]");
        eprintln!("                          [--kdf-memory-kib n --kdf-iterations n --kdf-parallelism n]");
        eprintln!("       qcb-keygen key-check <file> [--passphrase-file f]");
        eprintln!("       qcb-keygen key-migrate --from <plaintext.json> --out <file> [same options as key-new]");
        eprintln!("The passphrase comes from --passphrase-file, the QCB_KEY_PASSPHRASE variable, or stdin; never from the command line.");
        std::process::exit(2)
    }

    fn fail(e: impl std::fmt::Display) -> ! { eprintln!("error: {e}"); std::process::exit(1) }

    #[derive(Default)]
    struct Args {
        positional: Vec<String>,
        out: Option<PathBuf>,
        from: Option<PathBuf>,
        prefix: Option<String>,
        passphrase_file: Option<PathBuf>,
        harden: bool,
        m: Option<u32>,
        t: Option<u32>,
        p: Option<u32>,
    }

    fn parse(args: &[String]) -> Args {
        let mut a = Args::default();
        let mut i = 0;
        let num = |v: Option<&String>, flag: &str| -> u32 {
            v.and_then(|s| s.parse().ok()).unwrap_or_else(|| usage(&format!("{flag} needs a whole number")))
        };
        while i < args.len() {
            match args[i].as_str() {
                "--passphrase" | "--password" | "-p" => usage("a passphrase is never accepted on the command line"),
                "--out" => { i += 1; a.out = Some(args.get(i).unwrap_or_else(|| usage("--out needs a value")).into()); }
                "--from" => { i += 1; a.from = Some(args.get(i).unwrap_or_else(|| usage("--from needs a value")).into()); }
                "--prefix" => { i += 1; a.prefix = Some(args.get(i).unwrap_or_else(|| usage("--prefix needs a value")).clone()); }
                "--passphrase-file" => { i += 1; a.passphrase_file = Some(args.get(i).unwrap_or_else(|| usage("--passphrase-file needs a value")).into()); }
                "--harden-existing-dir" => a.harden = true,
                "--kdf-memory-kib" => { i += 1; a.m = Some(num(args.get(i), "--kdf-memory-kib")); }
                "--kdf-iterations" => { i += 1; a.t = Some(num(args.get(i), "--kdf-iterations")); }
                "--kdf-parallelism" => { i += 1; a.p = Some(num(args.get(i), "--kdf-parallelism")); }
                other if other.starts_with("--") => usage(&format!("unknown flag {other}")),
                other => a.positional.push(other.to_string()),
            }
            i += 1;
        }
        a
    }

    fn strip_newline(mut s: String) -> String {
        if s.ends_with('\n') { s.pop(); }
        if s.ends_with('\r') { s.pop(); }
        s
    }

    fn passphrase(a: &Args) -> String {
        if let Some(f) = &a.passphrase_file {
            return strip_newline(std::fs::read_to_string(f).unwrap_or_else(|e| fail(format!("cannot read the passphrase file: {e}"))));
        }
        if let Ok(p) = std::env::var("QCB_KEY_PASSPHRASE") { return p; }
        eprintln!("Passphrase (read from stdin; it is not hidden):");
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).unwrap_or_else(|e| fail(format!("cannot read the passphrase: {e}")));
        strip_newline(line)
    }

    fn options(a: &Args) -> CreateOptions {
        let d = KdfCost::PRODUCTION;
        CreateOptions {
            cost: KdfCost { m_cost_kib: a.m.unwrap_or(d.m_cost_kib), t_cost: a.t.unwrap_or(d.t_cost), p_cost: a.p.unwrap_or(d.p_cost) },
            harden_existing_dir: a.harden,
            prefix: a.prefix.clone().unwrap_or_else(|| "qcb".to_string()),
        }
    }

    pub fn cmd_new(args: &[String]) {
        let a = parse(args);
        let label = a.positional.first().unwrap_or_else(|| usage("key-new needs a <label>")).clone();
        let out = a.out.clone().unwrap_or_else(|| usage("--out <file> is required"));
        let pass = passphrase(&a);
        let c = keystore::create_new(&out, &label, &pass, &options(&a), &OsPlatform).unwrap_or_else(|e| fail(e));
        println!("encrypted key written to {}", out.display());
        println!("address:      {}", c.address);
        println!("payload:      {}", match c.payload_kind { keystore::PayloadKind::Seed => "seed only (the expanded key is not stored)", keystore::PayloadKind::ExpandedSecretKey => "expanded secret key" });
    }

    pub fn cmd_check(args: &[String]) {
        let a = parse(args);
        let file: PathBuf = a.positional.first().unwrap_or_else(|| usage("key-check needs a <file>")).into();
        let pass = passphrase(&a);
        let l = keystore::load(&file, &pass, &OsPlatform).unwrap_or_else(|e| fail(e));
        println!("ok: {} decrypts, its permissions are private, and its public key and address are consistent", file.display());
        println!("address:      {}", l.address);
        println!("label:        {}", l.label);
        println!("payload:      {}", match l.payload_kind { keystore::PayloadKind::Seed => "seed", keystore::PayloadKind::ExpandedSecretKey => "expanded secret key (migrated legacy key)" });
    }

    pub fn cmd_migrate(args: &[String]) {
        let a = parse(args);
        let from = a.from.clone().unwrap_or_else(|| usage("--from <plaintext.json> is required"));
        let out = a.out.clone().unwrap_or_else(|| usage("--out <file> is required"));
        let pass = passphrase(&a);
        let c = keystore::migrate_plaintext(&from, &out, &pass, &options(&a), &OsPlatform).unwrap_or_else(|e| fail(e));
        println!("encrypted key written to {} and verified by decrypting it", out.display());
        println!("address:      {}", c.address);
        println!("The old plaintext file {} still exists and was NOT deleted or changed.", from.display());
        println!("After you have confirmed the new file works, remove the old one yourself (and any copies or backups of it).");
    }
}
