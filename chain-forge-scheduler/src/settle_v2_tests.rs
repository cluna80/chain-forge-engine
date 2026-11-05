//! Settlement transactions under signing v2 (TEST-ONLY, feature `signing-v2`). Drives `settle_objective` against an in-memory
//! DB and a mock node that captures the submitted transaction.

use std::sync::{Arc, Mutex};

use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use chain_forge_crypto::KeyPair;
use chain_forge_execution::signing_v2::{check_envelope, verify_carried_key};
use chain_forge_execution::Transaction;
use chain_forge_research_db::{
    models::{NewExperimentResult, NewObjective, NewTask},
    MemResearchDb, ResearchDb,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::settlement::{settle_objective, SettleRequest, SettlementError};
use crate::{scheduler::ResearchScheduler, verification::{VerificationEngine, VerifyRequest}};

const CHAIN: &str = "qattice-alpha-1";
const OPERATOR: &str = "qcb1operator";

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn key() -> KeyPair { B::keygen_from_seed(&[5u8; 32]) }

/// A tiny HTTP server that records every POST body and answers 200 `{}`.
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
                        if buf.len() >= i + 4 + len {
                            seen.lock().unwrap().push(text[i + 4..i + 4 + len].to_string());
                            break;
                        }
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await;
            });
        }
    });
    (url, bodies)
}

/// An objective with one task whose result has been accepted (verification quorum 2).
async fn accepted_task() -> (Arc<dyn ResearchDb>, String, String) {
    let db = MemResearchDb::new();
    let obj = NewObjective {
        objective_id: "ch::obj::s".into(), challenge_id: "ch".into(), slug: "s".into(), track: "hash".into(),
        algorithm_version: "sha256_v1".into(), range_start: 0, range_end: 1_000, workload_class: "cpu".into(),
        verification_spec: json!({ "method": "sha256_preimage" }), verification_quorum: 2,
    };
    let obj_id = obj.objective_id.clone();
    let task = NewTask {
        task_id: format!("{obj_id}::task::0"), objective_id: obj_id.clone(), range_start: 0, range_end: 1_000,
        workload_class: "cpu".into(), input_seed: 1, phase: 1, parent_hash: None, phase1_miner_id: None,
        task_kind: "pocd_phase1".into(), avl_seed_index: None, avl_bit_index: None,
    };
    db.insert_objective(obj).await.unwrap();
    db.upsert_tasks(vec![task]).await.unwrap();
    let sched = ResearchScheduler::new(Arc::new(db.clone())).with_lease_secs(60);
    let row = sched.assign_task(&obj_id, "cpu", "miner_a").await.unwrap();
    let gen = row.lease_generation;
    sched.submit_result(&row.task_id, "miner_a", gen, NewExperimentResult {
        task_id: row.task_id.clone(), receipt_id: format!("rcpt_a_{gen}"), miner_id: "miner_a".into(),
        content_hash: format!("hash_miner_a_{gen}"),
        result_payload: json!({ "nonce": gen, "winning_hash": "aa".repeat(32), "phase": 1 }),
        algorithm_version: "sha256_v1".into(), workload_version: "1.0".into(), seal_nonce: Some(gen as u64),
        avl_original_hash: None, avl_flipped_hash: None, avl_xor_diff: None, avl_hamming_dist: None,
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

fn request(task_id: &str, node_url: &str, kp: &KeyPair, profile: Option<&str>) -> SettleRequest {
    let mut v = json!({
        "task_id": task_id, "reward_kind": "primary", "recipient": "qcb1miner", "chain_id": CHAIN, "node_url": node_url,
        "operator_address": OPERATOR, "operator_secret_key_hex": hex(&kp.private_key), "operator_public_key_hex": hex(&kp.public_key),
        "operator_nonce": 7, "disbursed_uqcb": 0,
    });
    if let Some(p) = profile { v["signing_profile"] = json!(p); }
    serde_json::from_value(v).unwrap()
}

async fn settle(profile: Option<&str>, kp: &KeyPair) -> (Result<(), SettlementError>, Vec<String>, usize) {
    let (db, obj, task) = accepted_task().await;
    let (url, bodies) = mock_node().await;
    let r = settle_objective(&db, &obj, request(&task, &url, kp, profile)).await.map(|_| ());
    let claims = db.list_reward_claims_for_objective(&obj).await.unwrap().len();
    let got = bodies.lock().unwrap().clone();
    (r, got, claims)
}

fn tx_of(bodies: &[String]) -> Transaction {
    assert_eq!(bodies.len(), 1, "exactly one transaction must reach the node");
    serde_json::from_str(&bodies[0]).expect("the node receives a Transaction")
}

#[tokio::test]
async fn a_v2_settlement_submits_a_transaction_that_verifies_under_signing_v2() {
    let kp = key();
    let (r, bodies, claims) = settle(Some("qattice-v2"), &kp).await;
    r.expect("settlement must succeed");
    assert_eq!(claims, 1);
    let tx = tx_of(&bodies);
    assert_eq!(tx.sender, OPERATOR);
    assert_eq!(tx.nonce, 7);
    check_envelope(&tx, None).expect("strict v2 envelope");
    verify_carried_key(CHAIN, &tx).expect("signature verifies over the full v2 preimage");
}

#[tokio::test]
async fn a_v2_settlement_signature_does_not_survive_changes_to_what_it_signs() {
    let kp = key();
    let (r, bodies, _) = settle(Some("qattice-v2"), &kp).await;
    r.unwrap();
    let base = tx_of(&bodies);
    let mut n = base.clone(); n.nonce += 1;
    assert!(verify_carried_key(CHAIN, &n).is_err(), "nonce is covered (H0-4)");
    let mut g = base.clone(); g.gas_limit += 1;
    assert!(verify_carried_key(CHAIN, &g).is_err(), "gas limit is covered");
    let mut i = base.clone(); i.id.push('x');
    assert!(verify_carried_key(CHAIN, &i).is_err(), "id is covered");
    assert!(verify_carried_key("other-chain", &base).is_err(), "chain id is covered");
}

/// Control: with no profile the legacy path is unchanged (it signs only chain id + body, so v2 verification must fail).
#[tokio::test]
async fn control_without_a_profile_the_legacy_signature_is_unchanged() {
    let kp = key();
    let (r, bodies, _) = settle(None, &kp).await;
    r.unwrap();
    let tx = tx_of(&bodies);
    assert!(verify_carried_key(CHAIN, &tx).is_err(), "a legacy settlement is not a v2 signature");
}

#[tokio::test]
async fn an_unknown_profile_is_refused_before_anything_is_stored_or_sent() {
    let kp = key();
    for p in ["qattice-v3", "", "Qattice-V2", " qattice-v2"] {
        let (r, bodies, claims) = settle(Some(p), &kp).await;
        assert!(r.is_err(), "{p:?} must be refused");
        assert_eq!(claims, 0, "{p:?}: no claim may be stored");
        assert!(bodies.is_empty(), "{p:?}: nothing may reach the node");
    }
}

#[tokio::test]
async fn a_bad_key_under_v2_is_refused_before_a_claim_is_stored() {
    let good = key();
    let b = B::keygen_from_seed(&[6u8; 32]);
    let mismatched = KeyPair { scheme: good.scheme.clone(), public_key: good.public_key.clone(), private_key: b.private_key.clone() };
    let garbage = KeyPair { scheme: good.scheme.clone(), public_key: good.public_key.clone(), private_key: vec![1u8; 4032] };
    for (label, kp) in [("mismatched", mismatched), ("garbage", garbage)] {
        let (r, bodies, claims) = settle(Some("qattice-v2"), &kp).await;
        assert!(r.is_err(), "{label} key must be an error, not a panic");
        assert_eq!(claims, 0, "{label}: no claim may be left pending by a signing failure");
        assert!(bodies.is_empty(), "{label}");
    }
}

#[tokio::test]
async fn v2_signatures_are_hedged_and_the_transaction_id_is_unchanged() {
    let kp = key();
    let (r1, b1, _) = settle(Some("qattice-v2"), &kp).await; r1.unwrap();
    let (r2, b2, _) = settle(Some("qattice-v2"), &kp).await; r2.unwrap();
    let (r3, b3, _) = settle(None, &kp).await; r3.unwrap();
    let (t1, t2, t3) = (tx_of(&b1), tx_of(&b2), tx_of(&b3));
    assert_ne!(t1.pq_signatures, t2.pq_signatures, "hedged signing");
    assert_eq!(t1.id, t2.id);
    assert_eq!(t1.id, t3.id, "the deterministic transaction id is the same under both profiles");
}
