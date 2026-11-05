//! Scheduler settlement without private keys (TEST-ONLY, feature `signing-v2`). Written before the implementation.
//!
//! The operator's key never reaches the scheduler: `POST …/settle/prepare` returns an unsigned transaction and a signing request,
//! an external signer signs, and `POST …/settle/submit` accepts the SIGNED transaction. These tests drive the real HTTP router.

use std::sync::{Arc, Mutex};

use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use chain_forge_crypto::{KeyPair, SchemeId};
use chain_forge_execution::signing_v2::{self, verify_carried_key, TX_CONTEXT};
use chain_forge_execution::Transaction;
use chain_forge_research_db::{
    models::{ClaimStatus, NewExperimentResult, NewObjective, NewTask},
    MemResearchDb, ResearchDb,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    api::{router, AppState},
    scheduler::ResearchScheduler,
    verification::{VerificationEngine, VerifyRequest},
    BeaconService, MinerRegistry,
};

const CHAIN: &str = "qattice-alpha-1";
const OPERATOR: &str = "qcb1operator";

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn key() -> KeyPair { B::keygen_from_seed(&[5u8; 32]) }

// ── a mock node that records every POST body ─────────────────────────────────────────────────────────────────────────────
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

/// The real HTTP router on an ephemeral port.
async fn start_api(db: Arc<dyn ResearchDb>) -> String {
    let state = AppState {
        scheduler: ResearchScheduler::new(db.clone()).with_lease_secs(60),
        miners: MinerRegistry::new(),
        verification: VerificationEngine::new(db),
        verifier_registry: None,
        beacon: BeaconService::stub(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap(); });
    url
}

async fn post(url: &str, body: &str) -> (u16, String) {
    let r = reqwest::Client::new().post(url).header("content-type", "application/json").body(body.to_string()).send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}
fn jv(text: &str) -> Value { serde_json::from_str(text).unwrap_or(Value::Null) }

fn prepare_body(task: &str, kp: &KeyPair, nonce: u64) -> Value {
    json!({
        "task_id": task, "reward_kind": "primary", "recipient": "qcb1miner", "chain_id": CHAIN, "operator_address": OPERATOR,
        "operator_public_key_hex": hex(&kp.public_key), "carry_key": true, "operator_nonce": nonce, "disbursed_uqcb": 0,
        "signing_profile": "qattice-v2",
    })
}

struct Env { api: String, obj: String, task: String, db: Arc<dyn ResearchDb>, node: String, node_log: Arc<Mutex<Vec<String>>> }
async fn env() -> Env {
    let (db, obj, task) = accepted_task().await;
    let api = start_api(db.clone()).await;
    let (node, node_log) = mock_node().await;
    Env { api, obj, task, db, node, node_log }
}
impl Env {
    fn prepare_url(&self) -> String { format!("{}/scheduler/objectives/{}/settle/prepare", self.api, self.obj) }
    fn submit_url(&self) -> String { format!("{}/scheduler/objectives/{}/settle/submit", self.api, self.obj) }
    fn old_url(&self) -> String { format!("{}/scheduler/objectives/{}/settle", self.api, self.obj) }
    async fn prepare(&self, kp: &KeyPair, nonce: u64) -> Value {
        let (code, text) = post(&self.prepare_url(), &prepare_body(&self.task, kp, nonce).to_string()).await;
        assert_eq!(code, 200, "prepare must succeed: {text}");
        jv(&text)
    }
    async fn claims(&self) -> usize { self.db.list_reward_claims_for_objective(&self.obj).await.unwrap().len() }
    fn node_posts(&self) -> usize { self.node_log.lock().unwrap().len() }
    fn submit_body(&self, claim_id: &str, signed_tx: &Value) -> String { json!({ "claim_id": claim_id, "chain_id": CHAIN, "signed_tx": signed_tx, "node_url": self.node }).to_string() }
}

/// What an external signer does: recompute the v2 preimage from the unsigned transaction, sign it, return the signed transaction.
fn external_sign(prepared: &Value, kp: &KeyPair, chain: &str) -> Value {
    let mut tx: Transaction = serde_json::from_value(prepared["unsigned_tx"].clone()).unwrap();
    tx.sig_scheme = Some(SchemeId::MlDsa);
    let pre = signing_v2::tx_preimage(chain, &tx, &kp.public_key).unwrap();
    let sig = B::sign(&kp.private_key, &pre, TX_CONTEXT).unwrap();
    tx.pq_signatures = vec![format!("mldsa65:{}", hex(&sig))];
    serde_json::to_value(&tx).unwrap()
}

/// Re-sign after the test changed a field (a valid signature over a transaction that no longer matches the claim).
fn resign(tx: &Value, kp: &KeyPair, chain: &str) -> Value {
    let mut t: Transaction = serde_json::from_value(tx.clone()).unwrap();
    t.pq_signatures.clear();
    let pre = signing_v2::tx_preimage(chain, &t, &kp.public_key).unwrap();
    t.pq_signatures = vec![format!("mldsa65:{}", hex(&B::sign(&kp.private_key, &pre, TX_CONTEXT).unwrap()))];
    serde_json::to_value(&t).unwrap()
}

// ── prepare ──────────────────────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn prepare_returns_an_unsigned_transaction_and_a_signing_request_and_stores_a_pending_claim() {
    let e = env().await; let kp = key();
    let p = e.prepare(&kp, 7).await;
    let tx: Transaction = serde_json::from_value(p["unsigned_tx"].clone()).expect("a Transaction");
    assert!(tx.pq_signatures.is_empty() && tx.signature.is_empty(), "nothing is signed yet");
    assert_eq!(tx.sender, OPERATOR);
    assert_eq!(tx.nonce, 7);
    assert_eq!(tx.pq_public_key, kp.public_key, "carry_key puts the public key in the transaction");
    assert!(matches!(tx.body, chain_forge_execution::TxBody::ClaimResearchReward { .. }));
    let sr = &p["signing_request"];
    assert_eq!(sr["profile"], "qattice-v2");
    assert_eq!(sr["context"], "qattice/tx/v2");
    assert_eq!(sr["chain_id"], CHAIN);
    assert_eq!(sr["signer"], OPERATOR);
    let want = hex(&signing_v2::tx_preimage(CHAIN, &tx, &kp.public_key).unwrap());
    assert_eq!(sr["preimage_hex"], want, "the preimage is the full v2 preimage of the unsigned transaction");
    assert_eq!(e.claims().await, 1);
    let c = e.db.get_reward_claim(p["claim_id"].as_str().unwrap()).await.unwrap().unwrap();
    assert_eq!(c.claim_status, "pending");
    assert_eq!(e.node_posts(), 0, "prepare never talks to the node");
}

#[tokio::test]
async fn prepare_is_idempotent_until_the_claim_is_submitted() {
    let e = env().await; let kp = key();
    let a = e.prepare(&kp, 7).await;
    let b = e.prepare(&kp, 7).await;
    assert_eq!(a["claim_id"], b["claim_id"]);
    assert_eq!(e.claims().await, 1, "one claim row, not two");
    let signed = external_sign(&a, &kp, CHAIN);
    let (code, text) = post(&e.submit_url(), &e.submit_body(a["claim_id"].as_str().unwrap(), &signed)).await;
    assert_eq!(code, 201, "{text}");
    let (code, _) = post(&e.prepare_url(), &prepare_body(&e.task, &kp, 8).to_string()).await;
    assert_eq!(code, 409, "a submitted claim cannot be prepared again");
}

#[tokio::test]
async fn prepare_refuses_anything_but_the_v2_profile_and_bad_public_keys_and_stores_nothing() {
    let e = env().await; let kp = key();
    let mut cases: Vec<(&str, Value)> = vec![];
    for p in [json!("legacy"), json!(""), json!("qattice-v3"), json!("Qattice-V2"), json!(null), json!(2)] {
        let mut b = prepare_body(&e.task, &kp, 0); b["signing_profile"] = p.clone(); cases.push(("profile", b));
    }
    let mut b = prepare_body(&e.task, &kp, 0); b.as_object_mut().unwrap().remove("signing_profile"); cases.push(("profile missing", b));
    let mut b = prepare_body(&e.task, &kp, 0); b["operator_public_key_hex"] = json!("ab".repeat(100)); cases.push(("short key", b));
    let mut b = prepare_body(&e.task, &kp, 0); b["operator_public_key_hex"] = json!("zz".repeat(1952)); cases.push(("non-hex key", b));
    let mut b = prepare_body(&e.task, &kp, 0); b["reward_kind"] = json!("jackpot"); cases.push(("reward kind", b));
    let mut b = prepare_body(&e.task, &kp, 0); b["task_id"] = json!("no-such-task"); cases.push(("unknown task", b));
    let mut b = prepare_body(&e.task, &kp, 0); b["surprise"] = json!(1); cases.push(("unknown field", b));
    for (label, body) in cases {
        let (code, text) = post(&e.prepare_url(), &body.to_string()).await;
        assert!(matches!(code, 400 | 404 | 422), "{label}: got {code} {text}");
    }
    assert_eq!(e.claims().await, 0, "no refused request may leave a claim behind");
}

// ── private-key material is refused ─────────────────────────────────────────────────────────────────────────────────────

fn secret_bodies(task: &str, kp: &KeyPair) -> Vec<(&'static str, Value)> {
    let sk = hex(&kp.private_key);
    let base = || prepare_body(task, kp, 0);
    let mut v = vec![];
    let mut b = base(); b["operator_secret_key_hex"] = json!(sk); v.push(("the old operator_secret_key_hex field", b));
    let mut b = base(); b["OPERATOR_SECRET_KEY_HEX"] = json!(sk); v.push(("upper-case field name", b));
    let mut b = base(); b["private_key"] = json!(sk); v.push(("private_key", b));
    let mut b = base(); b["secret_key"] = json!(sk); v.push(("secret_key", b));
    let mut b = base(); b["seed"] = json!("ab".repeat(32)); v.push(("seed", b));
    let mut b = base(); b["mnemonic"] = json!("abandon abandon abandon"); v.push(("mnemonic", b));
    let mut b = base(); b["passphrase"] = json!("hunter2hunter2"); v.push(("passphrase", b));
    let mut b = base(); b["policy"] = json!({ "treasury_address": "t", "private_key": sk }); v.push(("nested private_key", b));
    let mut b = base(); b["memo"] = json!(sk); v.push(("a secret key hidden under an innocent field name", b));
    let mut b = base(); b["memo"] = json!("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"); v.push(("PEM private key", b));
    v
}

#[tokio::test]
async fn requests_carrying_private_key_material_are_rejected_on_every_settlement_endpoint_and_leave_no_trace() {
    let e = env().await; let kp = key();
    let sk = hex(&kp.private_key);
    for (label, body) in secret_bodies(&e.task, &kp) {
        for url in [e.prepare_url(), e.submit_url()] {
            let (code, text) = post(&url, &body.to_string()).await;
            assert_eq!(code, 400, "{label} to {url}: got {code} {text}");
            assert_eq!(jv(&text)["error"], "private_key_material_rejected", "{label}: {text}");
            assert!(!text.contains(&sk[..64]) && !text.contains(&sk[64..128]), "{label}: the response must not echo the key");
        }
    }
    assert_eq!(e.claims().await, 0, "nothing may be stored");
    assert_eq!(e.node_posts(), 0, "nothing may be sent to the node");
}

#[tokio::test]
async fn the_old_settle_endpoint_that_took_a_private_key_is_gone() {
    let e = env().await; let kp = key();
    let mut legacy = prepare_body(&e.task, &kp, 0);
    legacy["operator_secret_key_hex"] = json!(hex(&kp.private_key)); legacy["node_url"] = json!(e.node);
    let (code, text) = post(&e.old_url(), &legacy.to_string()).await;
    assert_eq!(code, 410, "{text}");
    assert_eq!(jv(&text)["error"], "settle_endpoint_removed");
    assert!(!text.contains(&hex(&kp.private_key)[..64]));
    // Even a body with no key at all is refused: the route no longer does anything.
    let (code, _) = post(&e.old_url(), "{}").await;
    assert_eq!(code, 410);
    assert_eq!(e.claims().await, 0);
    assert_eq!(e.node_posts(), 0);
}

#[tokio::test]
async fn legitimate_long_hex_is_not_mistaken_for_a_secret() {
    let e = env().await; let kp = key();
    // A 3,904-character public key and 64-character hashes are public data and must pass.
    let mut b = prepare_body(&e.task, &kp, 0);
    b["recipient"] = json!("qcb1miner");
    let p = { let (code, text) = post(&e.prepare_url(), &b.to_string()).await; assert_eq!(code, 200, "{text}"); jv(&text) };
    let signed = external_sign(&p, &kp, CHAIN); // carries a 6,618-character signature and the public key
    let (code, text) = post(&e.submit_url(), &e.submit_body(p["claim_id"].as_str().unwrap(), &signed)).await;
    assert_eq!(code, 201, "public key, signature and hashes are not secrets: {text}");
}

// ── submit ───────────────────────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_correctly_signed_transaction_is_verified_forwarded_unchanged_and_the_claim_marked_submitted() {
    let e = env().await; let kp = key();
    let p = e.prepare(&kp, 7).await;
    let signed = external_sign(&p, &kp, CHAIN);
    let (code, text) = post(&e.submit_url(), &e.submit_body(p["claim_id"].as_str().unwrap(), &signed)).await;
    assert_eq!(code, 201, "{text}");
    let r = jv(&text);
    assert_eq!(r["status"], "submitted");
    assert_eq!(r["tx_id"], p["tx_id"]);
    let got = e.node_log.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "exactly one transaction reaches the node");
    let sent: Transaction = serde_json::from_str(&got[0]).unwrap();
    assert_eq!(serde_json::to_value(&sent).unwrap(), signed, "the node receives exactly the signed transaction");
    verify_carried_key(CHAIN, &sent).expect("and it verifies under signing v2");
    let c = e.db.get_reward_claim(p["claim_id"].as_str().unwrap()).await.unwrap().unwrap();
    assert_eq!(c.claim_status, "submitted");
    assert_eq!(c.tx_id.as_deref(), p["tx_id"].as_str());
}

#[tokio::test]
async fn submit_refuses_every_transaction_that_is_not_exactly_the_prepared_claim_signed_by_the_operator() {
    let e = env().await; let kp = key();
    let other = B::keygen_from_seed(&[9u8; 32]);
    let p = e.prepare(&kp, 7).await;
    let cid = p["claim_id"].as_str().unwrap().to_string();
    let good = external_sign(&p, &kp, CHAIN);
    let unsigned = p["unsigned_tx"].clone();

    let flip = |s: &str| { let mut b = s.as_bytes().to_vec(); let i = "mldsa65:".len() + 50; b[i] = if b[i] == b'0' { b'1' } else { b'0' }; String::from_utf8(b).unwrap() };
    let mut cases: Vec<(&str, Value, u16)> = vec![];
    // a valid-looking signature that does not verify
    let mut t = good.clone(); t["pq_signatures"][0] = json!(flip(good["pq_signatures"][0].as_str().unwrap())); cases.push(("flipped signature nibble", t, 422));
    // the body is not the claim, even though a valid signature covers it
    let mut t = unsigned.clone(); let a = t["body"]["ClaimResearchReward"]["amount_uqcb"].as_u64().unwrap(); t["body"]["ClaimResearchReward"]["amount_uqcb"] = json!(a + 1); cases.push(("amount raised, re-signed", resign(&t, &kp, CHAIN), 422));
    let mut t = unsigned.clone(); t["body"]["ClaimResearchReward"]["recipient"] = json!("qcb1thief"); cases.push(("recipient changed, re-signed", resign(&t, &kp, CHAIN), 422));
    let mut t = unsigned.clone(); t["body"]["ClaimResearchReward"]["claim_id"] = json!("0".repeat(64)); cases.push(("claim id changed, re-signed", resign(&t, &kp, CHAIN), 422));
    let mut t = unsigned.clone(); t["id"] = json!("custom-id"); cases.push(("transaction id changed, re-signed", resign(&t, &kp, CHAIN), 422));
    let mut t = unsigned.clone(); t["gas_limit"] = json!(10_000_000u64); cases.push(("gas limit changed, re-signed", resign(&t, &kp, CHAIN), 422));
    // a body swapped for a different transaction type entirely
    let mut t = unsigned.clone(); t["body"] = json!({ "Transfer": { "to": "qcb1thief", "amount": 5, "denom": "uqcb" } }); cases.push(("a transfer instead of a claim, re-signed", resign(&t, &kp, CHAIN), 422));
    // signed for another chain, signed by another key, signed by the legacy scheme
    cases.push(("signed for a different chain", external_sign(&p, &kp, "some-other-chain"), 422));
    cases.push(("signed by a different key but carrying the operator key", external_sign(&p, &other, CHAIN), 422));
    let mut t = good.clone(); let d = t["pq_signatures"][0].clone(); t["pq_signatures"].as_array_mut().unwrap().push(d); cases.push(("two signatures", t, 422));
    let mut t = good.clone(); t["pq_signatures"] = json!([]); cases.push(("no signature", t, 422));
    let mut t = good.clone(); t["signature"] = json!(hex(&[7u8; 64])); cases.push(("classical material present", t, 422));
    let mut t = good.clone(); t["sig_scheme"] = json!("Classical"); cases.push(("classical scheme tag", t, 422));
    let mut t = good.clone(); t["pq_signatures"][0] = json!(format!("mldsa65:{}", "ab".repeat(2420))); cases.push(("wrong-length signature", t, 422));
    let mut t = good.clone(); t["pq_public_key"] = json!(hex(&other.public_key)); cases.push(("a different key carried, same signature", t, 422));

    for (label, tx, want) in cases {
        let (code, text) = post(&e.submit_url(), &e.submit_body(&cid, &tx)).await;
        assert_eq!(code, want, "{label}: got {code} {text}");
    }
    // unknown claim, a claim under another objective's URL, unknown JSON fields
    let (code, _) = post(&e.submit_url(), &e.submit_body(&"f".repeat(64), &good)).await;
    assert_eq!(code, 404, "unknown claim");
    let (code, _) = post(&format!("{}/scheduler/objectives/other-objective/settle/submit", e.api), &e.submit_body(&cid, &good)).await;
    assert!(matches!(code, 404 | 422), "a claim must be submitted under its own objective, got {code}");
    let mut b: Value = serde_json::from_str(&e.submit_body(&cid, &good)).unwrap(); b["extra"] = json!(1);
    let (code, _) = post(&e.submit_url(), &b.to_string()).await;
    assert_eq!(code, 422, "unknown field");

    assert_eq!(e.node_posts(), 0, "nothing refused may reach the node");
    let c = e.db.get_reward_claim(&cid).await.unwrap().unwrap();
    assert_eq!(c.claim_status, "pending", "a refused submission leaves the claim pending");
    // and the genuine transaction still goes through afterwards
    let (code, text) = post(&e.submit_url(), &e.submit_body(&cid, &good)).await;
    assert_eq!(code, 201, "{text}");
    // submitting the same claim again is a conflict, not a second payout
    let (code, _) = post(&e.submit_url(), &e.submit_body(&cid, &good)).await;
    assert_eq!(code, 409);
    assert_eq!(e.node_posts(), 1);
    let _ = ClaimStatus::Pending;
}

// ── static guards ────────────────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_scheduler_source_has_no_field_or_variable_for_a_secret_key() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for f in ["settlement.rs", "api.rs", "main.rs", "lib.rs"] {
        let text = std::fs::read_to_string(dir.join(f)).unwrap();
        let code: String = text.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        for forbidden in ["operator_secret_key", "secret_key_hex", "private_key_hex", "KeyPair {", "sign_transaction_v2", "mldsa_tx_prehash"] {
            assert!(!code.contains(forbidden), "{f} must not contain {forbidden}");
        }
    }
}

// ── end to end: the REAL executor accepts the transaction the scheduler forwarded ────────────────────────────────────────

fn executor_world(kp: &KeyPair) -> (chain_forge_execution::Executor, chain_forge_state::StateStore) {
    use chain_forge_core::{GenesisConfig, HashWidth};
    use chain_forge_execution::{ExecutionConfig, Executor};
    let g = GenesisConfig::from_json(&format!(r#"{{
        "chain_id": "{CHAIN}", "chain_name": "claim e2e", "engine_version": "0.1.0", "genesis_time": "2026-11-05T00:00:00Z",
        "environment": {{ "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true }},
        "native_token": {{ "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" }},
        "address_prefix": "qcb",
        "consensus": {{ "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 }},
        "execution": {{ "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": true }},
        "cryptography": {{ "signature_scheme": "pqc-native", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "ml-dsa-65" }},
        "network": {{ "network_id": "c-net", "p2p_port": 27000, "rpc_port": 27001, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 }},
        "limits": {{ "max_block_bytes": 1048576, "max_tx_bytes": 1048576, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 }},
        "modules": ["bank", "identity", "pocd"], "custom_modules": [],
        "settlement_operators": ["{OPERATOR}"],
        "genesis_accounts": [
            {{ "label": "operator", "address": "{OPERATOR}", "balance": "5000000000", "role": "user" }},
            {{ "label": "miner", "address": "qcb1miner", "balance": "0", "role": "user" }}
        ]
    }}"#)).expect("genesis");
    let mut cfg = ExecutionConfig::from_genesis(&g);
    cfg.mldsa_signing_v2 = true;
    let mut st = chain_forge_state::StateStore::new(HashWidth::Bits256);
    st.apply_genesis(&g).unwrap();
    st.get_account_mut(OPERATOR).unwrap().public_key = Some(kp.public_key.clone()); // key bound in genesis
    let mut t = chain_forge_state::AccountState::new("treasury:pocd-research".into(), "pocd-research-treasury".into());
    t.credit("uqcb", 1_000_000_000_000);
    st.upsert_account(t);
    st.refresh_leaf("treasury:pocd-research");
    (Executor::new(cfg), st)
}

fn run_tx(ex: &chain_forge_execution::Executor, st: &mut chain_forge_state::StateStore, tx: &Transaction) -> chain_forge_execution::TransactionResult {
    let mut identity = chain_forge_identity::IdentityStore::new(0);
    let mut agents = chain_forge_agents::AgentStore::new();
    ex.execute_tx_with_identity(tx, st, &mut identity, &mut agents, 1)
}

#[tokio::test]
async fn the_real_executor_accepts_the_signed_claim_the_scheduler_forwarded_pays_once_and_refuses_a_replay() {
    let e = env().await; let kp = key();
    let p = e.prepare(&kp, 0).await;
    let signed = external_sign(&p, &kp, CHAIN);
    let (code, text) = post(&e.submit_url(), &e.submit_body(p["claim_id"].as_str().unwrap(), &signed)).await;
    assert_eq!(code, 201, "{text}");
    let forwarded: Transaction = serde_json::from_str(&e.node_log.lock().unwrap()[0]).unwrap();
    let amount = match &forwarded.body { chain_forge_execution::TxBody::ClaimResearchReward { amount_uqcb, .. } => *amount_uqcb as u128, _ => panic!("a claim") };
    assert!(amount > 0);

    let (ex, mut st) = executor_world(&kp);
    let r = run_tx(&ex, &mut st, &forwarded);
    assert!(r.success, "the executor must accept the scheduler's transaction: {:?}", r.error);
    assert_eq!(st.get_account("qcb1miner").unwrap().balance_of("uqcb"), amount, "the recipient is paid");
    assert_eq!(st.get_account("treasury:pocd-research").unwrap().balance_of("uqcb"), 1_000_000_000_000 - amount, "from the treasury");
    let claim_key = format!("claim:{}", p["claim_id"].as_str().unwrap());
    assert!(st.get_account(&claim_key).is_ok(), "the idempotency key is written");

    let again = run_tx(&ex, &mut st, &forwarded);
    assert!(!again.success, "a replay must not pay again");
    assert_eq!(st.get_account("qcb1miner").unwrap().balance_of("uqcb"), amount);
}

#[tokio::test]
async fn a_claim_signed_for_another_chain_or_by_another_key_is_refused_by_the_executor_too() {
    let e = env().await; let kp = key();
    let other = B::keygen_from_seed(&[9u8; 32]);
    let p = e.prepare(&kp, 0).await;
    for (label, tx) in [("another chain", external_sign(&p, &kp, "some-other-chain")), ("another key", external_sign(&p, &other, CHAIN))] {
        let t: Transaction = serde_json::from_value(tx).unwrap();
        let (ex, mut st) = executor_world(&kp);
        let r = run_tx(&ex, &mut st, &t);
        assert!(!r.success, "{label}: the executor must refuse it");
        assert_eq!(st.get_account("qcb1miner").unwrap().balance_of("uqcb"), 0, "{label}: nobody is paid");
    }
}
