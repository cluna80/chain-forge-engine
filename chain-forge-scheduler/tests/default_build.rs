//! Default build (no `signing-v2`): the scheduler has no signing path at all. The old key-taking route is gone, prepare/submit answer
//! 501, and the private-key scan still runs first, so a secret is rejected rather than merely ignored.
#![cfg(not(feature = "signing-v2"))]

use std::sync::Arc;

use chain_forge_research_db::MemResearchDb;
use chain_forge_scheduler::{router, AppState, BeaconService, MinerRegistry, ResearchScheduler, VerificationEngine};
use serde_json::{json, Value};

async fn api() -> String {
    let db = Arc::new(MemResearchDb::new());
    let state = AppState {
        scheduler: ResearchScheduler::new(db.clone()).with_lease_secs(60), miners: MinerRegistry::new(),
        verification: VerificationEngine::new(db), verifier_registry: None, beacon: BeaconService::stub(),
    };
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, router(state)).await.unwrap(); });
    url
}

async fn post(url: &str, body: &Value) -> (u16, String) {
    let r = reqwest::Client::new().post(url).json(body).send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test]
async fn without_the_feature_prepare_and_submit_are_501_and_settle_is_410() {
    let u = api().await;
    let base = format!("{u}/scheduler/objectives/o/settle");
    let prep = json!({ "task_id": "t", "reward_kind": "primary", "recipient": "qcb1r", "chain_id": "c", "operator_address": "qcb1o",
        "operator_public_key_hex": "00", "operator_nonce": 0, "disbursed_uqcb": 0, "signing_profile": "qattice-v2" });
    let (c, t) = post(&format!("{base}/prepare"), &prep).await;
    assert_eq!(c, 501, "{t}");
    assert!(t.contains("signing_unavailable"), "{t}");
    let sub = json!({ "claim_id": "x", "chain_id": "c", "signed_tx": {}, "node_url": "http://127.0.0.1:1" });
    let (c, t) = post(&format!("{base}/submit"), &sub).await;
    assert_eq!(c, 501, "{t}");
    let (c, t) = post(&base, &json!({})).await;
    assert_eq!(c, 410, "{t}");
    assert!(t.contains("settle_endpoint_removed"), "{t}");
}

#[tokio::test]
async fn without_the_feature_a_private_key_is_still_rejected_not_ignored() {
    let u = api().await;
    let secret = "ab".repeat(4032);
    for ep in ["settle/prepare", "settle/submit"] {
        let (c, t) = post(&format!("{u}/scheduler/objectives/o/{ep}"), &json!({ "operator_secret_key_hex": secret })).await;
        assert_eq!(c, 400, "{ep}: {t}");
        assert!(t.contains("private_key_material_rejected"), "{t}");
        assert!(!t.contains(&secret[..64]), "never echoed");
    }
}
