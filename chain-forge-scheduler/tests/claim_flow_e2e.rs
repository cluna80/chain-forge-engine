//! The whole settlement chain with nothing faked: the real HTTP API prepares the claim, the real `qcb-claim-signer` binary signs it with a
//! real encrypted wallet file, the API verifies and forwards it, and the real executor accepts it and pays. The operator's private key
//! exists only inside the signer process. (TEST-ONLY, feature `signing-v2`.)
#![cfg(feature = "signing-v2")]

use std::sync::{Arc, Mutex};

use chain_forge_execution::Transaction;
use chain_forge_research_db::{
    models::{NewExperimentResult, NewObjective, NewTask},
    MemResearchDb, ResearchDb,
};
use chain_forge_scheduler::{router, AppState, BeaconService, MinerRegistry, ResearchScheduler, VerificationEngine, VerifyRequest};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHAIN: &str = "qattice-alpha-1";
const PASS: &str = "correct horse battery";

async fn mock_node() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let seen = bodies.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                loop {
                    let n = s.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 { break; }
                    buf.extend_from_slice(&tmp[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(i) = text.find("\r\n\r\n") {
                        let len = text[..i].lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                        if buf.len() >= i + 4 + len { seen.lock().unwrap().push(text[i + 4..i + 4 + len].to_string()); break; }
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await;
            });
        }
    });
    (url, bodies)
}

async fn accepted_task() -> (Arc<dyn ResearchDb>, String, String) {
    let db = MemResearchDb::new();
    let obj = NewObjective {
        objective_id: "ch::obj::s".into(), challenge_id: "ch".into(), slug: "s".into(), track: "hash".into(),
        algorithm_version: "sha256_v1".into(), range_start: 0, range_end: 1_000, workload_class: "cpu".into(),
        verification_spec: json!({ "method": "sha256_preimage" }), verification_quorum: 2,
    };
    let obj_id = obj.objective_id.clone();
    let task = NewTask {
        task_id: format!("{obj_id}::task::0"), objective_id: obj_id.clone(), range_start: 0, range_end: 1_000, workload_class: "cpu".into(),
        input_seed: 1, phase: 1, parent_hash: None, phase1_miner_id: None, task_kind: "pocd_phase1".into(), avl_seed_index: None, avl_bit_index: None,
    };
    db.insert_objective(obj).await.unwrap();
    db.upsert_tasks(vec![task]).await.unwrap();
    let sched = ResearchScheduler::new(Arc::new(db.clone())).with_lease_secs(60);
    let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
    let gen = row.lease_generation;
    sched.submit_result(&row.task_id, "miner_a", gen, NewExperimentResult {
        task_id: row.task_id.clone(), receipt_id: format!("rcpt_a_{gen}"), miner_id: "miner_a".into(), content_hash: format!("hash_miner_a_{gen}"),
        result_payload: json!({ "nonce": gen, "winning_hash": "aa".repeat(32), "phase": 1 }), algorithm_version: "sha256_v1".into(),
        workload_version: "1.0".into(), seal_nonce: Some(gen as u64), avl_original_hash: None, avl_flipped_hash: None, avl_xor_diff: None, avl_hamming_dist: None,
    }).await.unwrap();
    let r = db.list_results_for_task(&row.task_id).await.unwrap().remove(0);
    let engine = VerificationEngine::new(Arc::new(db.clone()));
    for (v, rc) in [("verifier_x", None), ("verifier_y", Some("rcpt_verifier_y_001".to_string()))] {
        engine.record_verification(&row.task_id, VerifyRequest {
            result_id: r.result_id, verifier_id: v.into(), outcome: "reproduced".into(), verifier_content_hash: r.content_hash.clone(),
            signature: None, workload_version: None, submission_nonce: None, verifier_receipt_id: rc, notes: None,
        }).await.unwrap();
    }
    (Arc::new(db), obj_id, row.task_id)
}

async fn start_api(db: Arc<dyn ResearchDb>) -> String {
    let state = AppState {
        scheduler: ResearchScheduler::new(db.clone()).with_lease_secs(60), miners: MinerRegistry::new(),
        verification: VerificationEngine::new(db), verifier_registry: None, beacon: BeaconService::stub(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap(); });
    url
}

async fn post(url: &str, body: &Value) -> (u16, Value) {
    let r = reqwest::Client::new().post(url).json(body).send().await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

fn executor_world(operator: &str) -> (chain_forge_execution::Executor, chain_forge_state::StateStore) {
    use chain_forge_core::{GenesisConfig, HashWidth};
    use chain_forge_execution::{ExecutionConfig, Executor};
    let g = GenesisConfig::from_json(&format!(r#"{{
        "chain_id": "{CHAIN}", "chain_name": "claim e2e", "engine_version": "0.1.0", "genesis_time": "2026-11-05T00:00:00Z",
        "environment": {{ "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true }},
        "native_token": {{ "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" }}, "address_prefix": "qcb",
        "consensus": {{ "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 }},
        "execution": {{ "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": true }},
        "cryptography": {{ "signature_scheme": "pqc-native", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "ml-dsa-65" }},
        "network": {{ "network_id": "c-net", "p2p_port": 27000, "rpc_port": 27001, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 }},
        "limits": {{ "max_block_bytes": 1048576, "max_tx_bytes": 1048576, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 }},
        "modules": ["bank", "identity", "pocd"], "custom_modules": [], "settlement_operators": ["{operator}"],
        "genesis_accounts": [
            {{ "label": "operator", "address": "{operator}", "balance": "5000000000", "role": "user" }},
            {{ "label": "miner", "address": "qcb1miner", "balance": "0", "role": "user" }}
        ]
    }}"#)).expect("genesis");
    let mut cfg = ExecutionConfig::from_genesis(&g);
    cfg.mldsa_signing_v2 = true; // first use: the operator is its own derived address, so no key needs binding
    let mut st = chain_forge_state::StateStore::new(HashWidth::Bits256);
    st.apply_genesis(&g).unwrap();
    let mut t = chain_forge_state::AccountState::new("treasury:pocd-research".into(), "pocd-research-treasury".into());
    t.credit("uqcb", 1_000_000_000_000);
    st.upsert_account(t);
    st.refresh_leaf("treasury:pocd-research");
    (Executor::new(cfg), st)
}

#[tokio::test]
async fn prepare_then_the_real_signer_then_submit_then_the_real_executor_pays_and_the_scheduler_never_saw_the_key() {
    let d = std::env::temp_dir().join(format!("qcb-claim-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let wf = d.join("operator.wallet.json").to_string_lossy().to_string();
    let kf = chain_forge_wallet::generate_wallet(&wf, "operator", PASS).unwrap();
    let (_, kp) = chain_forge_wallet::load_wallet(&wf, PASS).unwrap();
    let sk_hex: String = kp.private_key.iter().map(|b| format!("{b:02x}")).collect();

    let (db, obj, task) = accepted_task().await;
    let api = start_api(db.clone()).await;
    let (node, node_log) = mock_node().await;

    // 1. prepare: public data only
    let (code, prepared) = post(&format!("{api}/scheduler/objectives/{obj}/settle/prepare"), &json!({
        "task_id": task, "reward_kind": "primary", "recipient": "qcb1miner", "chain_id": CHAIN, "operator_address": kf.address,
        "operator_public_key_hex": kf.public_key, "carry_key": true, "operator_nonce": 0, "disbursed_uqcb": 0, "signing_profile": "qattice-v2" })).await;
    assert_eq!(code, 200, "{prepared}");
    assert!(!prepared.to_string().contains(&sk_hex[64..192]), "the response holds no key material");

    // 2. the signer, a separate process that owns the key
    let pf = d.join("prepared.json");
    std::fs::write(&pf, serde_json::to_vec(&prepared).unwrap()).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_qcb-claim-signer"))
        .args(["--wallet", &wf, "--prepared", pf.to_str().unwrap(), "--expect-chain-id", CHAIN])
        .env("QCB_WALLET_PASSPHRASE", PASS).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let signed: Value = serde_json::from_slice(&out.stdout).unwrap();

    // 3. submit the signed transaction
    let (code, resp) = post(&format!("{api}/scheduler/objectives/{obj}/settle/submit"), &json!({
        "claim_id": signed["claim_id"], "chain_id": CHAIN, "signed_tx": signed["signed_tx"], "node_url": node })).await;
    assert_eq!(code, 201, "{resp}");

    // 4. the real executor accepts what the node would have received
    let forwarded: Transaction = serde_json::from_str(&node_log.lock().unwrap()[0]).unwrap();
    let amount = match &forwarded.body { chain_forge_execution::TxBody::ClaimResearchReward { amount_uqcb, .. } => *amount_uqcb as u128, _ => panic!("a claim") };
    let (ex, mut st) = executor_world(&kf.address);
    let mut identity = chain_forge_identity::IdentityStore::new(0);
    let mut agents = chain_forge_agents::AgentStore::new();
    let r = ex.execute_tx_with_identity(&forwarded, &mut st, &mut identity, &mut agents, 1);
    assert!(r.success, "the executor must accept it: {:?}", r.error);
    assert_eq!(st.get_account("qcb1miner").unwrap().balance_of("uqcb"), amount);
    let _ = std::fs::remove_dir_all(&d);
}
