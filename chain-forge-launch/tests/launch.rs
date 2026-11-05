//! Qattice Public Alpha launch-manifest acceptance tests (owner decisions 2026-11-05).
//!
//! Public Alpha is identified by an explicit, version-controlled launch manifest, not a new environment mode. A genesis is
//! deployable only if it carries `commitment_profile: "qattice-v2"`, is ML-DSA-only, and is exactly the genesis the manifest
//! pins. Historical genesis files keep their behaviour and hashes.

use chain_forge_core::{compute_genesis_hash, GenesisConfig};
use chain_forge_launch::{verify, Violation};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};

const NETWORK: &str = "qattice-public-alpha";
const CHAIN: &str = "qattice-alpha-test-1";

fn genesis_value() -> Value {
    json!({
        "chain_id": CHAIN, "chain_name": "Qattice Public Alpha (test fixture)", "engine_version": "0.1.0",
        "genesis_time": "2026-11-05T00:00:00Z",
        "environment": { "mode": "testnet", "faucet_enabled": false, "relaxed_limits": false },
        "native_token": { "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" },
        "address_prefix": "qcb", "commitment_profile": "qattice-v2",
        "consensus": { "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 },
        "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": true },
        "cryptography": { "signature_scheme": "pqc-native", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "ml-dsa-65" },
        "network": { "network_id": "alpha-net", "p2p_port": 27000, "rpc_port": 27001, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 },
        "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 },
        "modules": ["bank"], "custom_modules": [],
        "genesis_accounts": [ { "label": "u", "address": "qcb1user", "balance": "5000000", "role": "user" } ]
    })
}

fn hash_of(g: &Value) -> String {
    compute_genesis_hash(&GenesisConfig::from_json(&g.to_string()).expect("fixture genesis parses"))
}

fn manifest_value(g: &Value) -> Value {
    json!({
        "schema_version": 1, "network": NETWORK, "chain_id": CHAIN, "environment_mode": "testnet",
        "genesis_hash": hash_of(g),
        "required_commitment_profile": "qattice-v2", "required_signature_scheme": "pqc-native",
        "required_pqc_algorithm": "ml-dsa", "required_validator_scheme": "ml-dsa-65",
        "release_build_features": ["signing-v2"]
    })
}

fn codes(r: Result<chain_forge_launch::Report, Vec<Violation>>) -> Vec<&'static str> {
    match r { Ok(_) => vec![], Err(v) => v.into_iter().map(|x| x.code).collect() }
}

fn check(m: &Value, g: &Value) -> Vec<&'static str> { codes(verify(&m.to_string(), &g.to_string())) }

/// A genesis edited after the manifest was pinned, with the manifest re-pinned only when the test says so.
fn edited(f: impl FnOnce(&mut Value)) -> (Value, Value) {
    let g0 = genesis_value();
    let m = manifest_value(&g0);
    let mut g = g0; f(&mut g);
    (m, g)
}

// ── the accepted case ────────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_genesis_that_matches_its_manifest_is_accepted() {
    let g = genesis_value();
    let r = verify(&manifest_value(&g).to_string(), &g.to_string()).expect("must be accepted");
    assert_eq!(r.network, NETWORK);
    assert_eq!(r.chain_id, CHAIN);
    assert_eq!(r.genesis_hash, hash_of(&g));
}

// ── commitment profile: omitted or changed ───────────────────────────────────────────────────────────────────────────

#[test]
fn a_genesis_that_omits_the_commitment_profile_is_rejected() {
    let (m, g) = edited(|g| { g.as_object_mut().unwrap().remove("commitment_profile"); });
    assert!(check(&m, &g).contains(&"PA_PROFILE_MISSING"));
    // Even a manifest re-pinned to the profile-less genesis must not make it deployable.
    let m2 = manifest_value(&g);
    assert!(check(&m2, &g).contains(&"PA_PROFILE_MISSING"), "re-pinning the hash must not excuse a missing profile");
}

#[test]
fn a_genesis_that_changes_the_commitment_profile_is_rejected() {
    for v in [json!("qattice-v3"), json!(""), json!("Qattice-V2"), json!(" qattice-v2"), json!("legacy"), json!(2), json!(true), json!(null), json!(["qattice-v2"])] {
        let (_, g) = edited(|g| { g["commitment_profile"] = v.clone(); });
        let m = { let mut m = manifest_value(&genesis_value()); m["genesis_hash"] = json!("0".repeat(64)); m };
        let c = check(&m, &g);
        assert!(c.contains(&"PA_PROFILE_INVALID"), "{v}: expected PA_PROFILE_INVALID, got {c:?}");
    }
}

// ── cryptography ─────────────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_genesis_that_is_not_ml_dsa_only_is_rejected() {
    for scheme in ["hybrid", "classical"] {
        let (m, g) = edited(|g| { g["cryptography"]["signature_scheme"] = json!(scheme); });
        let c = check(&m, &g);
        assert!(c.contains(&"PA_CRYPTO_NOT_MLDSA"), "{scheme}: {c:?}");
    }
    let (m, g) = edited(|g| { g["cryptography"]["pqc_algorithm"] = json!("slh-dsa"); });
    assert!(check(&m, &g).contains(&"PA_CRYPTO_NOT_MLDSA"));
    let (m, g) = edited(|g| { g["cryptography"]["validator_scheme"] = json!("classical"); });
    assert!(check(&m, &g).contains(&"PA_VALIDATOR_SCHEME"));
}

// ── identity of the launch ───────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn any_change_to_the_pinned_genesis_is_rejected() {
    let (m, g) = edited(|g| { g["genesis_time"] = json!("2026-11-06T00:00:00Z"); });
    assert!(check(&m, &g).contains(&"PA_GENESIS_HASH_MISMATCH"));
    let (m, g) = edited(|g| { g["genesis_accounts"][0]["balance"] = json!("5000001"); });
    assert!(check(&m, &g).contains(&"PA_GENESIS_HASH_MISMATCH"));
}

#[test]
fn chain_id_and_environment_mode_must_match_the_manifest() {
    let (m, g) = edited(|g| { g["chain_id"] = json!("some-other-chain"); });
    assert!(check(&m, &g).contains(&"PA_CHAIN_ID_MISMATCH"));
    let (m, g) = edited(|g| { g["environment"]["mode"] = json!("devnet"); });
    assert!(check(&m, &g).contains(&"PA_MODE_MISMATCH"));
}

#[test]
fn every_violation_is_reported_not_just_the_first() {
    let (m, g) = edited(|g| {
        g.as_object_mut().unwrap().remove("commitment_profile");
        g["cryptography"]["signature_scheme"] = json!("hybrid");
        g["chain_id"] = json!("other");
    });
    let c = check(&m, &g);
    for want in ["PA_PROFILE_MISSING", "PA_CRYPTO_NOT_MLDSA", "PA_CHAIN_ID_MISMATCH", "PA_GENESIS_HASH_MISMATCH"] {
        assert!(c.contains(&want), "missing {want} in {c:?}");
    }
}

#[test]
fn an_unparseable_genesis_is_rejected() {
    let m = manifest_value(&genesis_value());
    assert!(codes(verify(&m.to_string(), "{ not json")).contains(&"PA_GENESIS_INVALID"));
    assert!(codes(verify(&m.to_string(), "{}")).contains(&"PA_GENESIS_INVALID"));
}

// ── the manifest itself cannot weaken the rules ──────────────────────────────────────────────────────────────────────

#[test]
fn a_manifest_cannot_weaken_the_requirements() {
    let g = genesis_value();
    let base = manifest_value(&g);
    let weaken: Vec<(&str, Value)> = vec![
        ("required_commitment_profile", json!("legacy")),
        ("required_commitment_profile", json!("")),
        ("required_signature_scheme", json!("hybrid")),
        ("required_pqc_algorithm", json!("slh-dsa")),
        ("required_validator_scheme", json!("classical")),
    ];
    for (k, v) in weaken {
        let mut m = base.clone(); m[k] = v.clone();
        assert!(check(&m, &g).contains(&"PA_MANIFEST_WEAKENED"), "{k}={v} must be refused");
    }
    let mut m = base.clone(); m["release_build_features"] = json!([]);
    assert!(check(&m, &g).contains(&"PA_MANIFEST_BUILD_FEATURES"), "the release build must include signing-v2");
    let mut m = base.clone(); m["release_build_features"] = json!(["real-network"]);
    assert!(check(&m, &g).contains(&"PA_MANIFEST_BUILD_FEATURES"));
}

#[test]
fn malformed_manifests_are_rejected() {
    let g = genesis_value();
    let base = manifest_value(&g);
    let mut cases: Vec<(&str, String)> = vec![("not json", "{ nope".into()), ("empty object", "{}".into())];
    let mut m = base.clone(); m["schema_version"] = json!(2); cases.push(("schema_version 2", m.to_string()));
    let mut m = base.clone(); m["network"] = json!("qattice-mainnet"); cases.push(("wrong network", m.to_string()));
    let mut m = base.clone(); m["genesis_hash"] = json!("xyz"); cases.push(("bad hash", m.to_string()));
    let mut m = base.clone(); m["genesis_hash"] = json!("A".repeat(64)); cases.push(("uppercase hash", m.to_string()));
    let mut m = base.clone(); m["surprise"] = json!(1); cases.push(("unknown field", m.to_string()));
    let mut m = base.clone(); m.as_object_mut().unwrap().remove("chain_id"); cases.push(("missing chain_id", m.to_string()));
    for (label, text) in cases {
        let c = codes(verify(&text, &g.to_string()));
        assert!(!c.is_empty() && c.iter().any(|x| x.starts_with("PA_MANIFEST")), "{label}: expected a PA_MANIFEST_* code, got {c:?}");
    }
}

// ── historical genesis files are untouched ───────────────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf() }

/// Golden hashes computed on unmodified `main` (before `commitment_profile` existed). Omitting the field must keep every
/// historical genesis legacy, with the same hash.
#[test]
fn historical_genesis_files_keep_their_hashes_and_stay_legacy() {
    let golden = std::fs::read_to_string(repo_root().join("chain-forge-launch/tests/fixtures/historical_genesis_hashes.tsv")).unwrap();
    let mut n = 0;
    for line in golden.lines() {
        let (rel, want) = line.split_once('\t').expect("tab separated");
        let text = std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let g = GenesisConfig::from_json(&text).unwrap_or_else(|e| panic!("{rel} must still parse: {e}"));
        assert_eq!(compute_genesis_hash(&g), want, "{rel}: genesis hash changed");
        assert_eq!(g.commitment_profile(), Ok(chain_forge_core::CommitmentProfile::Legacy), "{rel} must stay legacy");
        assert!(!text.contains("commitment_profile"), "{rel} must not mention the field");
        n += 1;
    }
    assert!(n >= 27, "the golden list covers every historical genesis file, got {n}");
}

/// Every genesis file in the repo that lacks the profile is rejected by the launch gate (none is deployable as public alpha).
#[test]
fn no_historical_genesis_passes_the_public_alpha_gate() {
    let golden = std::fs::read_to_string(repo_root().join("chain-forge-launch/tests/fixtures/historical_genesis_hashes.tsv")).unwrap();
    let m = manifest_value(&genesis_value());
    for line in golden.lines() {
        let rel = line.split('\t').next().unwrap();
        let text = std::fs::read_to_string(repo_root().join(rel)).unwrap();
        assert!(codes(verify(&m.to_string(), &text)).contains(&"PA_PROFILE_MISSING"), "{rel}");
    }
}

// ── the command-line tool ────────────────────────────────────────────────────────────────────────────────────────────

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qcb-launch-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn cli(m: &std::path::Path, g: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qcb-launch"))
        .args(["verify", "--manifest", m.to_str().unwrap(), "--genesis", g.to_str().unwrap()]).output().unwrap()
}

#[test]
fn the_tool_exits_zero_on_a_good_pair_and_one_with_codes_on_a_bad_one() {
    let d = tmpdir("cli");
    let g = genesis_value();
    let (mf, gf) = (d.join("m.json"), d.join("g.json"));
    std::fs::write(&mf, manifest_value(&g).to_string()).unwrap();
    std::fs::write(&gf, g.to_string()).unwrap();
    let ok = cli(&mf, &gf);
    assert_eq!(ok.status.code(), Some(0), "{}", String::from_utf8_lossy(&ok.stderr));
    let j: Value = serde_json::from_slice(&ok.stdout).unwrap();
    assert_eq!(j["ok"], true);

    let mut bad = g.clone(); bad.as_object_mut().unwrap().remove("commitment_profile");
    std::fs::write(&gf, bad.to_string()).unwrap();
    let o = cli(&mf, &gf);
    assert_eq!(o.status.code(), Some(1));
    let j: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["ok"], false);
    let codes: Vec<&str> = j["violations"].as_array().unwrap().iter().map(|v| v["code"].as_str().unwrap()).collect();
    assert!(codes.contains(&"PA_PROFILE_MISSING"), "{codes:?}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_tool_fails_closed_on_missing_files_and_bad_usage() {
    let d = tmpdir("cli-io");
    let o = cli(&d.join("nope-m.json"), &d.join("nope-g.json"));
    assert_eq!(o.status.code(), Some(2), "unreadable input is a usage/IO error, never a pass");
    let o = Command::new(env!("CARGO_BIN_EXE_qcb-launch")).args(["verify"]).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    let o = Command::new(env!("CARGO_BIN_EXE_qcb-launch")).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&d);
}

// ── the release build recipe ─────────────────────────────────────────────────────────────────────────────────────────

fn script() -> PathBuf { repo_root().join("scripts/build-public-alpha.sh") }

fn run_script(m: &std::path::Path, g: &std::path::Path, dry: bool) -> Output {
    let mut c = Command::new("bash");
    c.arg(script()).arg(m).arg(g).env("QCB_LAUNCH_BIN", env!("CARGO_BIN_EXE_qcb-launch"));
    if dry { c.env("QCB_DRY_RUN", "1"); }
    c.output().unwrap()
}

#[test]
fn the_release_recipe_verifies_first_and_builds_with_the_public_alpha_feature() {
    assert!(script().exists(), "scripts/build-public-alpha.sh must exist");
    let d = tmpdir("script");
    let g = genesis_value();
    let (mf, gf) = (d.join("m.json"), d.join("g.json"));
    std::fs::write(&mf, manifest_value(&g).to_string()).unwrap();
    std::fs::write(&gf, g.to_string()).unwrap();
    let o = run_script(&mf, &gf, true);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(out.contains("--release") && out.contains("--features public-alpha") && out.contains("chain-forge-node"), "{out}");

    // A genesis the gate rejects: the recipe stops before any build step.
    let mut bad = g.clone(); bad["commitment_profile"] = json!("qattice-v3");
    std::fs::write(&gf, bad.to_string()).unwrap();
    let o = run_script(&mf, &gf, true);
    assert!(!o.status.success(), "a rejected genesis must stop the release build");
    assert!(!String::from_utf8_lossy(&o.stdout).contains("--features public-alpha"), "no build command may be printed or run");
    let _ = std::fs::remove_dir_all(&d);
}
