//! Live-test genesis with ML-DSA keys that match the keys the test will sign with.
//!
//! Since 721c166 (2026-10-29, "production keys come from the OS RNG, never seeded keygen") `MlDsaScheme::generate_keypair(seed)`
//! returns one RANDOM key per seed per process. A static genesis file that pre-binds an account's ML-DSA public key
//! (the ML-DSA account-ownership fix binds named accounts in genesis) therefore cannot match the key a freshly started
//! test process signs with, and every transaction from that account fails with "ML-DSA signature verification failed".
//! The test writes a copy of the genesis with each listed account's `public_key` replaced by the key it will sign with.

use std::path::{Path, PathBuf};

use chain_forge_crypto::{MlDsaScheme, SignatureScheme};

/// Copy `template` to a temp file with `public_key` of each `(address, seed)` account set to the process's ML-DSA key for
/// that seed. Panics if an account is missing or has no pre-bound key (so a wrong mapping cannot pass silently).
pub fn with_ml_dsa_keys(template: &Path, tag: &str, accounts: &[(&str, &str)]) -> PathBuf {
    let text = std::fs::read_to_string(template).unwrap_or_else(|e| panic!("read {}: {e}", template.display()));
    let mut genesis: serde_json::Value = serde_json::from_str(&text).expect("parse genesis template");
    let list = genesis["genesis_accounts"].as_array_mut().expect("genesis_accounts array");
    for (addr, seed) in accounts {
        let kp = MlDsaScheme.generate_keypair(seed).expect("ML-DSA keygen");
        let acct = list.iter_mut().find(|a| a["address"] == *addr)
            .unwrap_or_else(|| panic!("account {addr} not in {}", template.display()));
        assert!(acct["public_key"].as_str().is_some_and(|k| !k.is_empty()),
            "account {addr} has no pre-bound public_key in the template; this helper only replaces bound ML-DSA keys");
        acct["public_key"] = serde_json::Value::String(kp.public_key.iter().map(|b| format!("{b:02x}")).collect());
    }
    let dir = std::env::temp_dir().join(format!("cf-live-genesis-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out = dir.join("genesis.json");
    std::fs::write(&out, serde_json::to_string_pretty(&genesis).unwrap()).expect("write patched genesis");
    out
}
