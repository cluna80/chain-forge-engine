//! `qcb-wallet transfer-v2` (TEST-ONLY, feature `signing-v2`). Runs the real binary and feeds its output to the real executor.
#![cfg(feature = "signing-v2")]

use chain_forge_core::{GenesisConfig, HashWidth};
use chain_forge_execution::{ExecutionConfig, Executor, Transaction};
use chain_forge_state::StateStore;
use std::process::{Command, Output};

const CHAIN: &str = "qattice-alpha-1";
const PASS: &str = "correct horse";

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("qcb-cli-v2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn wallet(dir: &std::path::Path) -> (String, String) {
    let path = dir.join("w.wallet.json").to_string_lossy().to_string();
    let kf = chain_forge_wallet::generate_wallet(&path, "t", PASS).unwrap();
    (path, kf.address)
}

fn cli(args: &[&str], pass: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qcb-wallet")).args(args).env("QCB_WALLET_PASSPHRASE", pass).output().unwrap()
}

fn base<'a>(w: &'a str) -> Vec<&'a str> {
    vec!["transfer-v2", "--wallet", w, "--to", "qcb1recv", "--amount", "1000", "--nonce", "0", "--chain-id", CHAIN]
}

fn executor_for(sender: &str) -> (Executor, StateStore) {
    let g = GenesisConfig::from_json(&format!(r#"{{
        "chain_id": "{CHAIN}", "chain_name": "cli v2", "engine_version": "0.1.0", "genesis_time": "2026-11-05T00:00:00Z",
        "environment": {{ "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true }},
        "native_token": {{ "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" }},
        "address_prefix": "qcb",
        "consensus": {{ "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 }},
        "execution": {{ "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": true }},
        "cryptography": {{ "signature_scheme": "pqc-native", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "ml-dsa-65" }},
        "network": {{ "network_id": "c-net", "p2p_port": 27000, "rpc_port": 27001, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 }},
        "limits": {{ "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 }},
        "modules": ["bank"], "custom_modules": [],
        "genesis_accounts": [
            {{ "label": "u", "address": "{sender}", "balance": "5000000", "role": "user" }},
            {{ "label": "r", "address": "qcb1recv", "balance": "0", "role": "user" }}
        ]
    }}"#)).unwrap();
    let mut cfg = ExecutionConfig::from_genesis(&g);
    cfg.mldsa_signing_v2 = true;
    let mut st = StateStore::new(HashWidth::Bits256);
    st.apply_genesis(&g).unwrap();
    (Executor::new(cfg), st)
}

fn parse(o: &Output) -> Transaction {
    assert!(o.status.success(), "command failed: {}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).expect("stdout must be exactly one transaction JSON document")
}

#[test]
fn transfer_v2_prints_a_transaction_the_executor_accepts() {
    let d = tmpdir("ok"); let (w, addr) = wallet(&d);
    let mut args = base(&w); args.push("--first-use");
    let tx = parse(&cli(&args, PASS));
    assert_eq!(tx.sender, addr, "sender is the wallet's address");
    assert_eq!(tx.pq_public_key.len(), 1952, "--first-use carries the key");
    let (ex, mut st) = executor_for(&addr);
    let r = ex.execute_tx(&tx, &mut st, 1);
    assert!(r.success, "{:?}", r.error);
    assert_eq!(st.get_account("qcb1recv").unwrap().balance_of("uqcb"), 1_000);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn without_first_use_the_key_is_not_carried() {
    let d = tmpdir("nokey"); let (w, _) = wallet(&d);
    let tx = parse(&cli(&base(&w), PASS));
    assert!(tx.pq_public_key.is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn nonce_is_required_and_nothing_is_signed_without_it() {
    let d = tmpdir("nonce"); let (w, _) = wallet(&d);
    let o = cli(&["transfer-v2", "--wallet", &w, "--to", "qcb1recv", "--amount", "1", "--chain-id", CHAIN], PASS);
    assert!(!o.status.success());
    assert!(!String::from_utf8_lossy(&o.stdout).contains("mldsa65:"), "no signature may be printed");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn bad_amount_and_wrong_passphrase_fail_without_output() {
    let d = tmpdir("bad"); let (w, _) = wallet(&d);
    let mut a = base(&w); let i = a.iter().position(|x| *x == "1000").unwrap(); a[i] = "12x";
    let o = cli(&a, PASS);
    assert!(!o.status.success() && o.stdout.is_empty(), "invalid amount");
    let o = cli(&base(&w), "wrong passphrase");
    assert!(!o.status.success() && o.stdout.is_empty(), "wrong passphrase");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn chain_id_is_required_so_a_signature_is_never_made_for_a_default_chain() {
    let d = tmpdir("chain"); let (w, _) = wallet(&d);
    let o = cli(&["transfer-v2", "--wallet", &w, "--to", "qcb1recv", "--amount", "1", "--nonce", "0"], PASS);
    assert!(!o.status.success() && o.stdout.is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn output_never_contains_the_secret_key_or_the_passphrase() {
    let d = tmpdir("secret"); let (w, _) = wallet(&d);
    let (_, kp) = chain_forge_wallet::load_wallet(&w, PASS).unwrap();
    let sk_hex: String = kp.private_key.iter().map(|b| format!("{b:02x}")).collect();
    for args in [base(&w), { let mut a = base(&w); a[1] = "--nope"; a }] {
        let o = cli(&args, PASS);
        let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(!all.contains(&sk_hex[..64]) && !all.contains(PASS));
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn two_runs_give_different_signatures_and_ids() {
    let d = tmpdir("hedge"); let (w, _) = wallet(&d);
    let a = parse(&cli(&base(&w), PASS)); let b = parse(&cli(&base(&w), PASS));
    assert_ne!(a.pq_signatures, b.pq_signatures, "hedged");
    assert_ne!(a.id, b.id, "default ids are unique");
    let _ = std::fs::remove_dir_all(&d);
}
