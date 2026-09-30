//! Generate deterministic Ed25519 key files for the 4-node devnet.
//!
//! Keys are derived from the validator address via SHA-256 so the same
//! public keys can be embedded in genesis-4node.json and will always match.
//!
//! Run:
//!   cargo run --features real-crypto -p chain-forge-crypto --bin gen_devnet_keys
//!
//! Output: tests/devnet/keys/{alice,bob,carol,dave}.key.json
//! These files hold PRIVATE KEYS — do not commit them if ever using real funds.
//! For a test devnet they are safe to commit (no real value at stake).

use chain_forge_crypto::{ClassicalScheme, SignatureScheme};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let validators = [
        ("qcb1alice", "alice"),
        ("qcb1bob",   "bob"),
        ("qcb1carol", "carol"),
        ("qcb1dave",  "dave"),
    ];

    // Output directory relative to the repo root
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().to_path_buf();
    let keys_dir = repo_root.join("tests").join("devnet").join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();

    for (address, label) in validators {
        // generate_keypair uses SHA-256(seed) internally → same seed → same key
        let kp = ClassicalScheme.generate_keypair(address).expect("keygen");
        let pub_hex  = hex(&kp.public_key);
        let priv_hex = hex(&kp.private_key);

        let key_json = serde_json::json!({
            "scheme":      "classical-ed25519",
            "address":     address,
            "public_key":  pub_hex,
            "private_key": priv_hex,
        });

        let out = keys_dir.join(format!("{label}.key.json"));
        std::fs::write(&out, serde_json::to_string_pretty(&key_json).unwrap()).unwrap();
        println!("{address}");
        println!("  public_key:  {pub_hex}");
        println!("  written to:  {}", out.display());
    }
}
