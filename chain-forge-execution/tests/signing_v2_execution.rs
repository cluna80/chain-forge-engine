//! Signing v2 in the execution path (TEST-ONLY switch `ExecutionConfig::mldsa_signing_v2`, cargo feature `signing-v2`).
//!
//! Spec: docs/mldsa-tx-signing-v2/SPEC.md (PR #94). Run: `cargo test -p chain-forge-execution --features signing-v2`.
//! This is the H0-4 fix path: the signature covers the nonce, id, sender, gas limit, body, chain id and key, in the context
//! `qattice/tx/v2`, so a signed transaction cannot be replayed under a new nonce.
#![cfg(feature = "signing-v2")]

use chain_forge_core::{Address, AddressScheme, GenesisConfig, HashWidth};
use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use chain_forge_crypto::{mldsa_tx_prehash, KeyPair, MlDsaScheme, SchemeId, SignatureScheme};
use chain_forge_execution::signing_v2::{self, TX_CONTEXT};
use chain_forge_execution::{ExecutionConfig, Executor, Transaction, TxBody};
use chain_forge_state::{AccountState, StateStore};
use serde_json::Value;

const CHAIN: &str = "qattice-alpha-1";

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

fn genesis(chain_id: &str) -> GenesisConfig {
    GenesisConfig::from_json(&format!(r#"{{
        "chain_id": "{chain_id}", "chain_name": "signing v2 test chain", "engine_version": "0.1.0", "genesis_time": "2026-11-05T00:00:00Z",
        "environment": {{ "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true }},
        "native_token": {{ "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" }},
        "address_prefix": "qcb",
        "consensus": {{ "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 }},
        "execution": {{ "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": true }},
        "cryptography": {{ "signature_scheme": "pqc-native", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "ml-dsa-65" }},
        "network": {{ "network_id": "v2-net", "p2p_port": 27000, "rpc_port": 27001, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 }},
        "limits": {{ "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 }},
        "modules": ["bank"], "custom_modules": [],
        "genesis_accounts": [
            {{ "label": "sender", "address": "qcb1sender", "balance": "5000000", "role": "user" }},
            {{ "label": "recv",   "address": "qcb1recv",  "balance": "0",       "role": "user" }}
        ]
    }}"#)).expect("genesis")
}

/// Executor on a pqc-native chain; `v2` selects the test-only signing-v2 switch.
fn setup(chain_id: &str, v2: bool) -> (Executor, StateStore) {
    let g = genesis(chain_id);
    let mut config = ExecutionConfig::from_genesis(&g);
    config.mldsa_signing_v2 = v2;
    let mut state = StateStore::new(HashWidth::Bits256);
    state.apply_genesis(&g).unwrap();
    (Executor::new(config), state)
}

fn key(seed: u8) -> KeyPair { B::keygen_from_seed(&[seed; 32]) }

/// Sign `tx` with the v2 scheme. `carry_key` puts the public key in the transaction (first use).
fn sign_v2(kp: &KeyPair, tx: &mut Transaction, chain_id: &str, carry_key: bool) {
    tx.sig_scheme = Some(SchemeId::MlDsa);
    tx.signature.clear();
    tx.public_key.clear();
    tx.pq_public_key = if carry_key { kp.public_key.clone() } else { vec![] };
    let pre = signing_v2::tx_preimage(chain_id, tx, &kp.public_key).unwrap();
    let sig = B::sign_with_randomness(&kp.private_key, &pre, TX_CONTEXT, &[0u8; 32]).unwrap();
    tx.pq_signatures = vec![format!("mldsa65:{}", hex(&sig))];
}

fn transfer(id: &str, nonce: u64, amount: u128) -> Transaction {
    let mut t = Transaction::transfer(id, "qcb1sender", "qcb1recv", "uqcb", amount, nonce);
    t.gas_limit = 500_000;
    t
}

/// Bind `kp` as the key of the named genesis account (a genesis-bound key).
fn bind(state: &mut StateStore, addr: &str, kp: &KeyPair) {
    state.get_account_mut(addr).unwrap().public_key = Some(kp.public_key.clone());
}

fn recv_balance(state: &StateStore) -> u128 { state.get_account("qcb1recv").unwrap().balance_of("uqcb") }

// ---------------------------------------------------------------------------------------------------------------
// H0-4: the acceptance scenario
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn h0_4_v2_signed_transfer_executes_once_and_cannot_be_replayed_under_a_new_nonce() {
    let (exec, mut state) = setup(CHAIN, true);
    let kp = key(1);
    bind(&mut state, "qcb1sender", &kp);
    let mut tx0 = transfer("tx-0", 0, 100);
    sign_v2(&kp, &mut tx0, CHAIN, false);
    let r0 = exec.execute_tx(&tx0, &mut state, 1);
    assert!(r0.success, "{:?}", r0.error);
    assert_eq!(recv_balance(&state), 100);

    // the attacker keeps the signature and changes only the unsigned-under-v1 fields
    let mut replay = tx0.clone();
    replay.id = "attacker-replay".into();
    replay.nonce = 1;
    let r1 = exec.execute_tx(&replay, &mut state, 2);
    assert!(!r1.success, "a signature made for nonce 0 must not authorize nonce 1");
    assert!(r1.error.as_deref().unwrap_or("").contains("verification failed"), "{:?}", r1.error);
    assert_eq!(r1.fee_charged, 0, "an authorization failure takes no fee");
    assert_eq!(recv_balance(&state), 100, "the receiver was credited once");
    assert_eq!(state.get_account("qcb1sender").unwrap().nonce, 1);
}

#[test]
fn every_covered_field_is_bound_by_the_signature() {
    let kp = key(2);
    // (what the attacker changes, how)
    type Edit = fn(&mut Transaction);
    let edits: [(&str, Edit); 5] = [
        ("id", |t| t.id = "other-id".into()),
        ("gas_limit", |t| t.gas_limit += 1),
        ("amount (body)", |t| t.body = TxBody::Transfer { to: "qcb1recv".into(), denom: "uqcb".into(), amount: 101 }),
        ("recipient (body)", |t| t.body = TxBody::Transfer { to: "qcb1other".into(), denom: "uqcb".into(), amount: 100 }),
        ("nonce", |t| t.nonce = 0), // same nonce is valid for the executor; see below for a changed value
    ];
    for (what, edit) in edits {
        if what == "nonce" { continue; }
        let (exec, mut state) = setup(CHAIN, true);
        bind(&mut state, "qcb1sender", &kp);
        let mut tx = transfer("tx-0", 0, 100);
        sign_v2(&kp, &mut tx, CHAIN, false);
        edit(&mut tx);
        let root = state.current_root().unwrap_or("").to_string();
        let r = exec.execute_tx(&tx, &mut state, 1);
        assert!(!r.success && r.error.as_deref().unwrap_or("").contains("verification failed"), "{what}: {:?}", r.error);
        assert_eq!(state.current_root().unwrap_or(""), root, "{what}: a rejected transaction changes no state");
        assert_eq!(r.fee_charged, 0, "{what}");
    }
}

#[test]
fn cross_chain_replay_is_rejected() {
    let kp = key(3);
    let (exec_a, mut state_a) = setup("qattice-alpha-1", true);
    let (exec_b, mut state_b) = setup("qattice-alpha-2", true);
    bind(&mut state_a, "qcb1sender", &kp);
    bind(&mut state_b, "qcb1sender", &kp);
    let mut tx = transfer("tx-0", 0, 100);
    sign_v2(&kp, &mut tx, "qattice-alpha-1", false);
    assert!(exec_a.execute_tx(&tx, &mut state_a, 1).success);
    let r = exec_b.execute_tx(&tx, &mut state_b, 1);
    assert!(!r.success && r.error.as_deref().unwrap_or("").contains("verification failed"), "{:?}", r.error);
    assert_eq!(recv_balance(&state_b), 0);
}

#[test]
fn a_signature_made_in_another_protocols_context_is_not_a_transaction_signature() {
    let kp = key(4);
    let (exec, mut state) = setup(CHAIN, true);
    bind(&mut state, "qcb1sender", &kp);
    let mut tx = transfer("tx-0", 0, 100);
    tx.sig_scheme = Some(SchemeId::MlDsa);
    let pre = signing_v2::tx_preimage(CHAIN, &tx, &kp.public_key).unwrap();
    let sig = B::sign_with_randomness(&kp.private_key, &pre, b"qattice/consensus/vote/v1", &[0u8; 32]).unwrap();
    tx.pq_signatures = vec![format!("mldsa65:{}", hex(&sig))];
    let r = exec.execute_tx(&tx, &mut state, 1);
    assert!(!r.success && r.error.as_deref().unwrap_or("").contains("verification failed"), "{:?}", r.error);
}

#[test]
fn the_v1_signature_format_is_not_accepted_under_v2() {
    let (exec, mut state) = setup(CHAIN, true);
    let kp = MlDsaScheme.generate_random().unwrap();   // legacy library key and signature
    state.get_account_mut("qcb1sender").unwrap().public_key = Some(kp.public_key.clone());
    let mut tx = transfer("tx-0", 0, 100);
    let body_json = serde_json::to_string(&tx.body).unwrap();
    let msg = mldsa_tx_prehash(CHAIN, body_json.as_bytes());
    let sig = MlDsaScheme.sign(&msg, &kp).unwrap();
    tx.sig_scheme = Some(SchemeId::MlDsa);
    tx.pq_signatures = vec![format!("mldsa65:{}", hex(&sig.bytes))];
    let r = exec.execute_tx(&tx, &mut state, 1);
    assert!(!r.success, "a v1 signature must not authorize a v2 transaction");
}

// ---------------------------------------------------------------------------------------------------------------
// Strict envelope rules E1-E5 through the executor
// ---------------------------------------------------------------------------------------------------------------

fn envelope_rejection(mut mutate: impl FnMut(&mut Transaction, &KeyPair), expect_code: &str) {
    let kp = key(5);
    let (exec, mut state) = setup(CHAIN, true);
    bind(&mut state, "qcb1sender", &kp);
    let mut tx = transfer("tx-0", 0, 100);
    sign_v2(&kp, &mut tx, CHAIN, false);
    mutate(&mut tx, &kp);
    let root = state.current_root().unwrap_or("").to_string();
    let r = exec.execute_tx(&tx, &mut state, 1);
    assert!(!r.success, "{expect_code} must be rejected");
    assert!(r.error.as_deref().unwrap_or("").contains(expect_code), "expected {expect_code}, got {:?}", r.error);
    assert_eq!(r.fee_charged, 0);
    assert_eq!(state.current_root().unwrap_or(""), root, "{expect_code}: no state change");
}

#[test]
fn e1_scheme_must_be_present_and_must_be_mldsa() {
    envelope_rejection(|t, _| t.sig_scheme = None, "E1_SCHEME_MISSING");
    envelope_rejection(|t, _| t.sig_scheme = Some(SchemeId::Classical), "E1_SCHEME_NOT_MLDSA");
    envelope_rejection(|t, _| t.sig_scheme = Some(SchemeId::HybridEd25519MlDsa), "E1_SCHEME_NOT_MLDSA");
    envelope_rejection(|t, _| t.sig_scheme = Some(SchemeId::SlhDsa), "E1_SCHEME_NOT_MLDSA");
    envelope_rejection(|t, _| t.sig_scheme = Some(SchemeId::FnDsa), "E1_SCHEME_NOT_MLDSA");
}

#[test]
fn e2_no_ed25519_material_may_ride_along() {
    envelope_rejection(|t, _| t.signature = vec![0u8; 64], "E2_CLASSICAL_MATERIAL_PRESENT");
    envelope_rejection(|t, _| t.public_key = vec![0x11u8; 32], "E2_CLASSICAL_MATERIAL_PRESENT");
}

#[test]
fn e3_exactly_one_signature() {
    envelope_rejection(|t, _| t.pq_signatures.clear(), "E3_NOT_EXACTLY_ONE_SIGNATURE");
    envelope_rejection(|t, _| { let s = t.pq_signatures[0].clone(); t.pq_signatures.push(s); }, "E3_NOT_EXACTLY_ONE_SIGNATURE");
}

#[test]
fn e4_signature_tag_hex_and_length() {
    envelope_rejection(|t, _| t.pq_signatures = vec![t.pq_signatures[0].replacen("mldsa65:", "slhdsa:", 1)], "E4_BAD_SIGNATURE_TAG");
    envelope_rejection(|t, _| t.pq_signatures = vec![format!("mldsa65:{}", "zz".repeat(3309))], "E4_SIGNATURE_NOT_HEX");
    envelope_rejection(|t, _| t.pq_signatures = vec![format!("mldsa65:{}", "ab".repeat(3308))], "E4_SIGNATURE_WRONG_LENGTH");
    envelope_rejection(|t, _| t.pq_signatures = vec![format!("mldsa65:{}", "ab".repeat(3310))], "E4_SIGNATURE_WRONG_LENGTH");
}

#[test]
fn e5_public_key_rules_for_bound_and_unbound_senders() {
    // bound sender: a different key in the transaction is refused
    envelope_rejection(|t, _| t.pq_public_key = key(99).public_key, "E5_KEY_DIFFERS_FROM_BOUND_KEY");
    // unbound sender (first use): missing, short and over-long keys are refused
    let kp = key(6);
    for (key_bytes, label) in [(vec![], "missing"), (kp.public_key[..1951].to_vec(), "short"), ([kp.public_key.clone(), vec![0u8]].concat(), "long")] {
        let (exec, mut state) = setup(CHAIN, true);                 // qcb1sender has NO bound key here
        let mut tx = transfer("tx-0", 0, 100);
        sign_v2(&kp, &mut tx, CHAIN, true);
        tx.pq_public_key = key_bytes;
        let r = exec.execute_tx(&tx, &mut state, 1);
        assert!(!r.success && r.error.as_deref().unwrap_or("").contains("E5_FIRST_USE_KEY_MISSING_OR_WRONG_LENGTH"), "{label}: {:?}", r.error);
        assert_eq!(recv_balance(&state), 0);
    }
}

#[test]
fn an_unsigned_transaction_is_rejected_on_a_v2_chain() {
    let (exec, mut state) = setup(CHAIN, true);
    let r = exec.execute_tx(&transfer("tx-0", 0, 100), &mut state, 1);
    assert!(!r.success && r.error.as_deref().unwrap_or("").contains("E1_SCHEME_MISSING"), "{:?}", r.error);
}

// ---------------------------------------------------------------------------------------------------------------
// Key binding
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn first_use_from_the_derived_address_binds_the_key_then_the_key_may_be_omitted() {
    let (exec, mut state) = setup(CHAIN, true);
    let kp = key(7);
    let addr = Address::from_public_key_schemed(&kp.public_key, "qcb", HashWidth::Bits256, AddressScheme::PostQuantum);
    let mut acct = AccountState::new(addr.as_str().to_string(), "user".into());
    acct.credit("uqcb", 1_000_000);
    state.upsert_account(acct);
    let mk = |id: &str, nonce: u64| {
        let mut t = Transaction::transfer(id, addr.as_str(), "qcb1recv", "uqcb", 10, nonce);
        t.gas_limit = 500_000;
        t
    };
    let mut t0 = mk("t0", 0);
    sign_v2(&kp, &mut t0, CHAIN, true);                          // first use: the key rides in the transaction
    let r0 = exec.execute_tx(&t0, &mut state, 1);
    assert!(r0.success, "{:?}", r0.error);
    assert_eq!(state.get_account(addr.as_str()).unwrap().public_key.as_deref(), Some(kp.public_key.as_slice()), "first success binds the key");
    let mut t1 = mk("t1", 1);
    sign_v2(&kp, &mut t1, CHAIN, false);                         // bound: the key may be omitted
    assert!(exec.execute_tx(&t1, &mut state, 2).success);
    let mut t2 = mk("t2", 2);
    sign_v2(&kp, &mut t2, CHAIN, true);                          // bound: repeating the same key is fine
    assert!(exec.execute_tx(&t2, &mut state, 3).success);
    assert_eq!(recv_balance(&state), 30);
}

#[test]
fn a_named_unbound_account_cannot_be_claimed_by_whoever_signs_first() {
    let (exec, mut state) = setup(CHAIN, true);                  // "qcb1sender" is a genesis label with no bound key
    let attacker = key(8);
    let mut tx = transfer("tx-0", 0, 100);
    sign_v2(&attacker, &mut tx, CHAIN, true);
    let r = exec.execute_tx(&tx, &mut state, 1);
    assert!(!r.success && r.error.as_deref().unwrap_or("").contains("not derived from the signing key"), "{:?}", r.error);
    assert!(state.get_account("qcb1sender").unwrap().public_key.is_none());
    assert_eq!(recv_balance(&state), 0);
}

// ---------------------------------------------------------------------------------------------------------------
// The switch is off by default and the legacy path is intact
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_switch_defaults_to_off_and_legacy_ml_dsa_transactions_still_execute() {
    let g = genesis(CHAIN);
    assert!(!ExecutionConfig::from_genesis(&g).mldsa_signing_v2, "signing v2 must be off unless a test turns it on");
    let (exec, mut state) = setup(CHAIN, false);
    let kp = MlDsaScheme.generate_random().unwrap();
    state.get_account_mut("qcb1sender").unwrap().public_key = Some(kp.public_key.clone());
    let mut tx = transfer("tx-0", 0, 100);
    let body_json = serde_json::to_string(&tx.body).unwrap();
    let sig = MlDsaScheme.sign(&mldsa_tx_prehash(CHAIN, body_json.as_bytes()), &kp).unwrap();
    tx.sig_scheme = Some(SchemeId::MlDsa);
    tx.pq_signatures = vec![format!("mldsa65:{}", hex(&sig.bytes))];
    let r = exec.execute_tx(&tx, &mut state, 1);
    assert!(r.success, "legacy v1 path must be unchanged when the switch is off: {:?}", r.error);
    // and the legacy replay defect is still there when the switch is off (that is what v2 fixes)
    let mut replay = tx.clone();
    replay.id = "replay".into();
    replay.nonce = 1;
    assert!(exec.execute_tx(&replay, &mut state, 2).success, "legacy: replay under a new nonce succeeds (H0-4)");
}

// ---------------------------------------------------------------------------------------------------------------
// Parity with the Python reference vectors (PR #94)
// ---------------------------------------------------------------------------------------------------------------

fn vectors() -> Value { serde_json::from_str(include_str!("../../chain-forge-crypto/tests/vectors/signing_v2/v2.json")).unwrap() }

#[test]
fn preimage_matches_the_reference_encoder_for_all_29_vector_cases() {
    let v = vectors();
    for c in v["cases"].as_array().unwrap() {
        let body: TxBody = serde_json::from_str(c["body_json"].as_str().unwrap()).expect("body parses");
        assert_eq!(serde_json::to_string(&body).unwrap(), c["body_json"].as_str().unwrap(), "{}: serde round-trip of the body", c["name"]);
        let mut tx = Transaction::transfer("x", "x", "x", "x", 0, 0);
        tx.id = c["id"].as_str().unwrap().into();
        tx.sender = c["sender"].as_str().unwrap().into();
        tx.nonce = c["nonce"].as_u64().unwrap();
        tx.gas_limit = c["gas_limit"].as_u64().unwrap();
        tx.body = body;
        let pre = signing_v2::tx_preimage(c["chain_id"].as_str().unwrap(), &tx, &unhex(c["pq_public_key_hex"].as_str().unwrap())).unwrap();
        assert_eq!(hex(&pre), c["preimage_hex"].as_str().unwrap(), "case {}", c["name"]);
    }
}

#[test]
fn envelope_rules_match_the_reference_for_all_19_vector_cases() {
    let v = vectors();
    for c in v["envelope_cases"].as_array().unwrap() {
        let t = &c["tx"];
        let mut tx = Transaction::transfer("x", "x", "x", "x", 0, 0);
        tx.sig_scheme = match t["sig_scheme"].as_str() {
            None => None,
            Some("MlDsa") => Some(SchemeId::MlDsa),
            Some("Classical") => Some(SchemeId::Classical),
            Some("HybridEd25519MlDsa") => Some(SchemeId::HybridEd25519MlDsa),
            Some("SlhDsa") => Some(SchemeId::SlhDsa),
            Some("FnDsa") => Some(SchemeId::FnDsa),
            Some(other) => panic!("unknown scheme {other}"),
        };
        tx.signature = unhex(t["signature_hex"].as_str().unwrap());
        tx.public_key = unhex(t["public_key_hex"].as_str().unwrap());
        tx.pq_signatures = t["pq_signatures"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
        tx.pq_public_key = unhex(t["pq_public_key_hex"].as_str().unwrap());
        let bound = c["bound_key_hex"].as_str().map(unhex);
        let got = signing_v2::check_envelope(&tx, bound.as_deref());
        match c["expect"].as_str().unwrap() {
            "ok" => assert_eq!(got, Ok(()), "case {}", c["name"]),
            _ => assert_eq!(got, Err(c["code"].as_str().unwrap()), "case {}", c["name"]),
        }
    }
}

#[test]
fn vector_signatures_verify_through_the_executor_verification_function() {
    let v = vectors();
    for c in v["cases"].as_array().unwrap() {
        let body: TxBody = serde_json::from_str(c["body_json"].as_str().unwrap()).unwrap();
        let mut tx = Transaction::transfer("x", "x", "x", "x", 0, 0);
        tx.id = c["id"].as_str().unwrap().into();
        tx.sender = c["sender"].as_str().unwrap().into();
        tx.nonce = c["nonce"].as_u64().unwrap();
        tx.gas_limit = c["gas_limit"].as_u64().unwrap();
        tx.body = body;
        let pk = unhex(c["verify_public_key_hex"].as_str().unwrap());
        // the preimage names the case's signed key; the verifying key may differ (negative cases)
        let preimage_key = unhex(c["pq_public_key_hex"].as_str().unwrap());
        let ok = signing_v2::verify_with_key(c["chain_id"].as_str().unwrap(), &tx, &preimage_key, &pk, &unhex(c["signature_hex"].as_str().unwrap()), c["context"].as_str().unwrap().as_bytes());
        assert_eq!(ok, c["expect_valid"].as_bool().unwrap(), "case {}", c["name"]);
    }
}
