//! Wallet signer for signing v2 (TEST-ONLY, feature `signing-v2`). Run: `cargo test -p chain-forge-wallet --features signing-v2`.
//! The signed transaction must be accepted and executed by the real executor with the v2 switch on, and rejected when anything
//! signed is changed.
#![cfg(feature = "signing-v2")]

use chain_forge_core::{Address, AddressScheme, GenesisConfig, HashWidth};
use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use chain_forge_crypto::{KeyPair, MlDsaScheme, SchemeId};
use chain_forge_execution::{ExecutionConfig, Executor, Transaction, TxBody};
use chain_forge_state::StateStore;
use chain_forge_wallet::signing_v2::{sign_transaction_v2, V2TxParams};

const CHAIN: &str = "qattice-alpha-1";

fn addr(kp: &KeyPair) -> String {
    Address::from_public_key_schemed(&kp.public_key, "qcb", HashWidth::Bits256, AddressScheme::PostQuantum).as_str().to_string()
}

fn setup(sender: &str) -> (Executor, StateStore) {
    let g = GenesisConfig::from_json(&format!(r#"{{
        "chain_id": "{CHAIN}", "chain_name": "wallet v2", "engine_version": "0.1.0", "genesis_time": "2026-11-05T00:00:00Z",
        "environment": {{ "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true }},
        "native_token": {{ "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" }},
        "address_prefix": "qcb",
        "consensus": {{ "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 }},
        "execution": {{ "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": true }},
        "cryptography": {{ "signature_scheme": "pqc-native", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "ml-dsa-65" }},
        "network": {{ "network_id": "w-net", "p2p_port": 27000, "rpc_port": 27001, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 }},
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

fn xfer(id: &str, nonce: u64, carry: bool, amount: u128) -> V2TxParams {
    V2TxParams {
        id: id.into(), nonce, gas_limit: 500_000, sender: None, carry_key: carry,
        body: TxBody::Transfer { to: "qcb1recv".into(), amount, denom: "uqcb".into() },
    }
}

fn run(ex: &Executor, st: &mut StateStore, tx: Transaction) -> bool {
    let r = ex.execute_tx(&tx, st, 1);
    if !r.success { eprintln!("rejected: {:?}", r.error); }
    r.success
}

fn recv(st: &StateStore) -> u128 { st.get_account("qcb1recv").unwrap().balance_of("uqcb") }

fn key() -> KeyPair { B::keygen_from_seed(&[3u8; 32]) }

#[test]
fn a_wallet_signed_transfer_executes_and_binds_the_key() {
    let kp = key(); let a = addr(&kp);
    let (ex, mut st) = setup(&a);
    let tx = sign_transaction_v2(&kp, CHAIN, "qcb", xfer("w0", 0, true, 1_000)).expect("signing must succeed");
    assert_eq!(tx.sender, a, "the default sender is the address derived from the key");
    assert_eq!(tx.sig_scheme, Some(SchemeId::MlDsa));
    assert!(run(&ex, &mut st, tx));
    assert_eq!(recv(&st), 1_000);
    assert_eq!(st.get_account(&a).unwrap().public_key.as_deref(), Some(&kp.public_key[..]));
}

#[test]
fn once_bound_the_key_can_be_omitted() {
    let kp = key(); let a = addr(&kp);
    let (ex, mut st) = setup(&a);
    assert!(run(&ex, &mut st, sign_transaction_v2(&kp, CHAIN, "qcb", xfer("w0", 0, true, 1_000)).unwrap()));
    let t1 = sign_transaction_v2(&kp, CHAIN, "qcb", xfer("w1", 1, false, 500)).unwrap();
    assert!(t1.pq_public_key.is_empty());
    assert!(run(&ex, &mut st, t1));
    assert_eq!(recv(&st), 1_500);
}

#[test]
fn signatures_are_hedged_two_signatures_over_one_transaction_differ_and_both_verify() {
    let kp = key(); let a = addr(&kp);
    let t1 = sign_transaction_v2(&kp, CHAIN, "qcb", xfer("same", 0, true, 7)).unwrap();
    let t2 = sign_transaction_v2(&kp, CHAIN, "qcb", xfer("same", 0, true, 7)).unwrap();
    assert_ne!(t1.pq_signatures, t2.pq_signatures, "hedged signing: fresh randomness per signature");
    for t in [t1, t2] {
        let (ex, mut st) = setup(&a);
        assert!(run(&ex, &mut st, t), "both hedged signatures verify");
    }
}

#[test]
fn a_wallet_signature_does_not_survive_any_change_to_what_it_signs() {
    let kp = key(); let a = addr(&kp);
    let base = sign_transaction_v2(&kp, CHAIN, "qcb", xfer("w0", 0, true, 1_000)).unwrap();
    type Edit = Box<dyn Fn(&mut Transaction)>;
    let edits: Vec<(&str, Edit)> = vec![
        ("nonce (H0-4)", Box::new(|t| t.nonce = 1)),
        ("id", Box::new(|t| t.id = "other".into())),
        ("gas limit", Box::new(|t| t.gas_limit += 1)),
        ("amount", Box::new(|t| if let TxBody::Transfer { amount, .. } = &mut t.body { *amount += 1 })),
    ];
    for (label, edit) in edits {
        let (ex, mut st) = setup(&a);
        let mut t = base.clone(); edit(&mut t);
        assert!(!run(&ex, &mut st, t), "{label}: a changed transaction must not verify");
        assert_eq!(recv(&st), 0);
    }
    // Control: the unmodified transaction executes.
    let (ex, mut st) = setup(&a);
    assert!(run(&ex, &mut st, base));
}

#[test]
fn the_signed_transaction_survives_a_json_round_trip() {
    let kp = key(); let a = addr(&kp);
    let tx = sign_transaction_v2(&kp, CHAIN, "qcb", xfer("w0", 0, true, 1_000)).unwrap();
    let back: Transaction = serde_json::from_str(&serde_json::to_string(&tx).unwrap()).unwrap();
    let (ex, mut st) = setup(&a);
    assert!(run(&ex, &mut st, back), "what the node receives over /api/tx must verify");
}

/// A key made by the legacy library (as every existing wallet file holds) must sign with the conforming backend.
#[test]
fn a_legacy_generated_wallet_key_signs_under_the_conforming_backend() {
    use chain_forge_crypto::SignatureScheme;
    let kp = MlDsaScheme.generate_random().unwrap();
    let a = addr(&kp);
    let (ex, mut st) = setup(&a);
    let tx = sign_transaction_v2(&kp, CHAIN, "qcb", xfer("w0", 0, true, 1_000)).expect("a legacy-generated key must work");
    assert!(run(&ex, &mut st, tx));
}

#[test]
fn signing_refuses_a_key_pair_whose_halves_do_not_match() {
    let a = key();
    let b = B::keygen_from_seed(&[4u8; 32]);
    let bad = KeyPair { scheme: SchemeId::MlDsa, public_key: a.public_key.clone(), private_key: b.private_key.clone() };
    assert!(sign_transaction_v2(&bad, CHAIN, "qcb", xfer("w0", 0, true, 1)).is_err());
    let garbage = KeyPair { scheme: SchemeId::MlDsa, public_key: a.public_key.clone(), private_key: vec![1u8; 4032] };
    assert!(sign_transaction_v2(&garbage, CHAIN, "qcb", xfer("w0", 0, true, 1)).is_err(), "garbage secret key must be an error, not a panic");
}

#[test]
fn an_explicit_sender_is_used_for_genesis_bound_accounts() {
    let kp = key();
    let (ex, mut st) = setup("qcb1named");
    st.get_account_mut("qcb1named").unwrap().public_key = Some(kp.public_key.clone());
    let mut p = xfer("w0", 0, false, 100);
    p.sender = Some("qcb1named".into());
    let tx = sign_transaction_v2(&kp, CHAIN, "qcb", p).unwrap();
    assert_eq!(tx.sender, "qcb1named");
    assert!(run(&ex, &mut st, tx));
}
