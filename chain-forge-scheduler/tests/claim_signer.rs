//! `qcb-claim-signer`: the signer side of the two-step flow (TEST-ONLY, feature `signing-v2`). Runs the real binary. Written first.
//! The signer is the trust boundary: it holds the key, so it must check what the (untrusted) scheduler asks it to sign.
#![cfg(feature = "signing-v2")]

use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use chain_forge_execution::signing_v2;
use chain_forge_execution::Transaction;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CHAIN: &str = "qattice-alpha-1";
const PASS: &str = "correct horse battery";

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qcb-signer-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

/// A wallet file made by the wallet crate, and a "prepare" response for its address, built the way the scheduler builds it.
fn setup(d: &Path) -> (String, chain_forge_wallet::WalletKeyFile, Value) {
    let wf = d.join("w.wallet.json").to_string_lossy().to_string();
    let kf = chain_forge_wallet::generate_wallet(&wf, "t", PASS).unwrap();
    let pk = unhex(&kf.public_key);
    let body = json!({ "ClaimResearchReward": { "claim_id": "c".repeat(64), "objective_id": "obj", "task_id": "task", "result_id": "r".repeat(8),
        "contribution_hash": "h".repeat(8), "recipient": "qcb1miner", "amount_uqcb": 5_000_000u64, "policy_version": "QcbResearchRewardPolicy-v1", "reward_kind": "primary" } });
    let tx: Transaction = serde_json::from_value(json!({
        "id": "tx-1", "sender": kf.address, "nonce": 0, "body": body, "gas_limit": 500_000, "sig_scheme": "MlDsa", "signature": "", "public_key": "",
        "pq_signatures": [], "pq_public_key": hex(&pk) })).unwrap();
    let pre = signing_v2::tx_preimage(CHAIN, &tx, &pk).unwrap();
    let prepared = json!({ "claim_id": "c".repeat(64), "tx_id": "tx-1", "amount_uqcb": 5_000_000u64, "unsigned_tx": serde_json::to_value(&tx).unwrap(),
        "signing_request": { "profile": "qattice-v2", "context": "qattice/tx/v2", "chain_id": CHAIN, "signer": kf.address, "pq_public_key_hex": hex(&pk), "preimage_hex": hex(&pre) } });
    (wf, kf, prepared)
}

fn run(args: &[&str], pass: Option<&str>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_qcb-claim-signer"));
    c.args(args).env_remove("QCB_WALLET_PASSPHRASE");
    if let Some(p) = pass { c.env("QCB_WALLET_PASSPHRASE", p); }
    c.output().unwrap()
}
fn text(o: &Output) -> String { format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)) }

fn sign(d: &Path, wf: &str, prepared: &Value, extra: &[&str]) -> Output {
    let pf = d.join("prepared.json");
    std::fs::write(&pf, serde_json::to_vec(prepared).unwrap()).unwrap();
    let mut a = vec!["--wallet", wf, "--prepared", pf.to_str().unwrap(), "--expect-chain-id", CHAIN];
    a.extend_from_slice(extra);
    run(&a, Some(PASS))
}

#[test]
fn the_signer_signs_a_genuine_prepared_claim_and_the_result_verifies_under_signing_v2() {
    let d = tmpdir("ok"); let (wf, kf, prepared) = setup(&d);
    let o = sign(&d, &wf, &prepared, &[]);
    assert!(o.status.success(), "{}", text(&o));
    let out: Value = serde_json::from_slice(&o.stdout).expect("stdout is exactly one JSON document");
    assert_eq!(out["claim_id"], prepared["claim_id"]);
    let tx: Transaction = serde_json::from_value(out["signed_tx"].clone()).unwrap();
    assert_eq!(tx.sender, kf.address);
    signing_v2::verify_carried_key(CHAIN, &tx).expect("the signature verifies over the full v2 preimage");
    assert_eq!(tx.pq_signatures.len(), 1);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_signer_never_prints_the_secret_key_or_the_passphrase_and_never_takes_it_on_the_command_line() {
    let d = tmpdir("quiet"); let (wf, _kf, prepared) = setup(&d);
    let (_, kp) = chain_forge_wallet::load_wallet(&wf, PASS).unwrap();
    let o = sign(&d, &wf, &prepared, &[]);
    let t = text(&o);
    assert!(o.status.success(), "{t}");
    assert!(!t.contains(PASS) && !t.contains(&hex(&kp.private_key)[64..192]));
    let pf = d.join("prepared.json");
    let o = run(&["--wallet", &wf, "--prepared", pf.to_str().unwrap(), "--expect-chain-id", CHAIN, "--passphrase", PASS], None);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(!text(&o).contains(PASS), "the rejected passphrase must not be echoed");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_signer_refuses_to_sign_anything_but_the_claim_it_was_told_to_expect() {
    let d = tmpdir("refuse"); let (wf, _kf, prepared) = setup(&d);
    let mut cases: Vec<(&str, Value, Vec<&str>)> = vec![];
    cases.push(("wrong expected chain id", prepared.clone(), vec!["--expect-chain-id", "other-chain"]));
    let mut p = prepared.clone(); p["signing_request"]["chain_id"] = json!("other-chain"); cases.push(("request names another chain", p, vec![]));
    let mut p = prepared.clone(); p["unsigned_tx"]["sender"] = json!("qcb1someoneelse"); cases.push(("sender is not this wallet", p, vec![]));
    let mut p = prepared.clone(); p["unsigned_tx"]["body"] = json!({ "Transfer": { "to": "qcb1thief", "amount": 1, "denom": "uqcb" } }); cases.push(("a transfer instead of a claim", p, vec![]));
    let mut p = prepared.clone(); p["signing_request"]["preimage_hex"] = json!("00".repeat(40)); cases.push(("the scheduler's preimage is not the transaction's", p, vec![]));
    let mut p = prepared.clone(); p["signing_request"]["profile"] = json!("legacy"); cases.push(("legacy profile", p, vec![]));
    let mut p = prepared.clone(); p["unsigned_tx"]["pq_signatures"] = json!(["mldsa65:ab"]); cases.push(("already carries a signature", p, vec![]));
    let mut p = prepared.clone(); p["unsigned_tx"]["gas_limit"] = json!(50_000_000u64); cases.push(("gas limit above the claim limit", p, vec![]));
    let mut p = prepared.clone(); p["unsigned_tx"]["pq_public_key"] = json!(hex(&B::keygen_from_seed(&[3u8; 32]).public_key)); cases.push(("carries a different public key", p, vec![]));
    cases.push(("amount above the ceiling the operator set", prepared.clone(), vec!["--max-amount-uqcb", "1000"]));
    for (label, p, extra) in cases {
        let o = sign(&d, &wf, &p, &extra);
        assert!(!o.status.success(), "{label}: must refuse (stdout: {})", String::from_utf8_lossy(&o.stdout));
        assert!(o.stdout.is_empty(), "{label}: nothing may be printed on stdout when refusing");
        assert!(!text(&o).contains(PASS));
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_wrong_passphrase_or_a_missing_input_fails_without_output() {
    let d = tmpdir("bad"); let (wf, _kf, prepared) = setup(&d);
    let pf = d.join("prepared.json");
    std::fs::write(&pf, serde_json::to_vec(&prepared).unwrap()).unwrap();
    let o = run(&["--wallet", &wf, "--prepared", pf.to_str().unwrap(), "--expect-chain-id", CHAIN], Some("not the passphrase!!"));
    assert!(!o.status.success() && o.stdout.is_empty());
    let o = run(&["--wallet", &wf, "--expect-chain-id", CHAIN], Some(PASS));
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["--wallet", &wf, "--prepared", pf.to_str().unwrap()], Some(PASS));
    assert_eq!(o.status.code(), Some(2), "the expected chain id is mandatory: the signer never signs for a guessed chain");
    let _ = std::fs::remove_dir_all(&d);
}

/// Recompute the scheduler's preimage for a (tampered) transaction, so the preimage comparison cannot be what refuses it.
fn with_fresh_preimage(mut p: Value, pk: &[u8]) -> Value {
    let tx: Transaction = serde_json::from_value(p["unsigned_tx"].clone()).unwrap();
    p["signing_request"]["preimage_hex"] = json!(hex(&signing_v2::tx_preimage(CHAIN, &tx, pk).unwrap()));
    p
}

#[test]
fn every_signer_check_refuses_on_its_own_even_when_the_preimage_is_consistent() {
    let d = tmpdir("alone"); let (wf, kf, prepared) = setup(&d);
    let pk = unhex(&kf.public_key);
    let mut cases: Vec<(&str, Value)> = vec![];
    let mut p = prepared.clone(); p["unsigned_tx"]["sender"] = json!("qcb1someoneelse"); cases.push(("tx sender is another address", with_fresh_preimage(p, &pk)));
    let mut p = prepared.clone(); p["signing_request"]["signer"] = json!("qcb1someoneelse"); cases.push(("request names another signer", p));
    let mut p = prepared.clone(); p["unsigned_tx"]["gas_limit"] = json!(400_000u64); cases.push(("gas below the claim limit", with_fresh_preimage(p, &pk)));
    let mut p = prepared.clone(); p["signing_request"]["context"] = json!("qattice/tx/v1"); cases.push(("another signing context", p));
    let mut p = prepared.clone(); p["unsigned_tx"]["body"]["ClaimResearchReward"]["amount_uqcb"] = json!(0u64); p["amount_uqcb"] = json!(0u64);
    cases.push(("zero amount", with_fresh_preimage(p, &pk)));
    let mut p = prepared.clone(); p["signing_request"]["pq_public_key_hex"] = json!(hex(&B::keygen_from_seed(&[3u8; 32]).public_key));
    cases.push(("request names another public key", p));
    for (label, p) in cases {
        let o = sign(&d, &wf, &p, &[]);
        assert!(!o.status.success(), "{label}: must refuse (stdout: {})", String::from_utf8_lossy(&o.stdout));
        assert!(o.stdout.is_empty(), "{label}: nothing on stdout");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_passphrase_flag_is_rejected_by_name_with_a_usage_error() {
    let d = tmpdir("flag"); let (wf, _kf, prepared) = setup(&d);
    let pf = d.join("prepared.json");
    std::fs::write(&pf, serde_json::to_vec(&prepared).unwrap()).unwrap();
    for flag in ["--passphrase", "--password", "-p"] {
        let o = run(&["--wallet", &wf, "--prepared", pf.to_str().unwrap(), "--expect-chain-id", CHAIN, flag, PASS], None);
        assert_eq!(o.status.code(), Some(2), "{flag}");
        assert!(text(&o).contains("never accepted on the command line"), "{flag}: {}", text(&o));
        assert!(!text(&o).contains(PASS) && o.stdout.is_empty());
    }
    let _ = std::fs::remove_dir_all(&d);
}
