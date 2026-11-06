//! Settlement operator logic: the scheduler side of the two-step claim flow (no private keys).
//!
//! ## Flow
//!
//! 1. `prepare`: look up the objective's canonical accepted result, compute the reward with `QcbResearchRewardPolicy`, store a
//!    `pending` reward claim (idempotent via the deterministic `claim_id`), and return the **unsigned** `ClaimResearchReward`
//!    transaction plus a signing request (profile, context, chain id, signer, full v2 preimage).
//! 2. The operator's **signer** (`qcb-claim-signer`) signs it. The scheduler is not involved and never sees the key.
//! 3. `submit`: accept the **signed** transaction only if it is exactly the stored claim (body, id, gas limit), check the signing-v2
//!    envelope and, when the public key is carried, the signature; forward it unchanged to the node's `/api/tx`; mark the claim
//!    `submitted`.
//!
//! ## Security
//!
//! - **No type in this module can hold a private key**, and requests containing key material are refused before anything is parsed
//!   or stored ([`reject_private_key_material`]). The audit and design are in `docs/scheduler-signing-boundary/`.
//! - Only profile `qattice-v2` is accepted: FIPS 204 ML-DSA-65, context `qattice/tx/v2`, full canonical preimage. There is no legacy
//!   fallback.
//! - The deterministic `claim_id` and the on-chain `claim:{claim_id}` key keep settlement idempotent across crashes and racing
//!   schedulers. The node remains the authority on signature validity, key binding and settlement-operator membership.
//!
//! ## Scientific integrity
//!
//! No result is automatically classified as a cryptographic breakthrough or discovery. Consensus is unchanged.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::research_reward::QcbResearchRewardPolicy;
use chain_forge_research_db::{
    models::{ClaimStatus, RewardKind},
    ResearchDb, ResearchDbError,
};

// ── Public request / response types ──────────────────────────────────────────
//
// SECURITY (issue: scheduler secret-key exposure): no type in this module can hold private-key material. The operator's key
// stays in the signer; the scheduler prepares an unsigned transaction and a signing request, and later accepts the SIGNED
// transaction. SCAFFOLD (tests first): the functions below return `NotImplemented`.

/// Fixed gas limit of a claim transaction.
pub const CLAIM_GAS_LIMIT: u64 = 500_000;

fn default_true() -> bool { true }

/// Request body for `POST /scheduler/objectives/:id/settle/prepare`. Public information only.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub task_id: String,
    /// `"primary"` or `"replication"`.
    pub reward_kind: String,
    /// Payout address on the QCB chain.
    pub recipient: String,
    /// Must match the node's genesis `chain_id`; bound into the signature.
    pub chain_id: String,
    /// Settlement operator's address (must be in genesis `settlement_operators`).
    pub operator_address: String,
    /// Settlement operator's ML-DSA-65 **public** key, hex (1,952 bytes). Named in the signed preimage.
    pub operator_public_key_hex: String,
    /// Put the public key in the transaction (required until the account's key is bound on chain).
    #[serde(default = "default_true")]
    pub carry_key: bool,
    pub operator_nonce: u64,
    pub disbursed_uqcb: u64,
    #[serde(default)]
    pub policy: Option<PolicyOverride>,
    /// Must be `"qattice-v2"`: there is no legacy fallback.
    pub signing_profile: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyOverride {
    pub primary_rate_uqcb:     Option<u64>,
    pub replication_rate_uqcb: Option<u64>,
    pub objective_budget_uqcb: Option<u64>,
    pub treasury_address:      Option<String>,
}

/// What the signer is asked to sign. The signer must recompute the preimage itself and must not trust `preimage_hex`.
#[derive(Debug, Serialize)]
pub struct SigningRequest {
    pub profile: String,
    pub context: String,
    pub chain_id: String,
    pub signer: String,
    pub pq_public_key_hex: String,
    pub preimage_hex: String,
}

#[derive(Debug, Serialize)]
pub struct PrepareResponse {
    pub claim_id: String,
    pub tx_id: String,
    pub amount_uqcb: u64,
    /// The transaction to sign, with no signature yet.
    pub unsigned_tx: serde_json::Value,
    pub signing_request: SigningRequest,
}

/// Request body for `POST /scheduler/objectives/:id/settle/submit`: the transaction **after** the signer signed it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitRequest {
    pub claim_id: String,
    /// The chain id the transaction was signed for (public; bound into the signature).
    pub chain_id: String,
    pub signed_tx: serde_json::Value,
    /// Base URL of the QCB node's HTTP API.
    pub node_url: String,
}

/// Response body for a successful submission.
#[derive(Debug, Serialize)]
pub struct SettleResponse {
    pub claim_id:    String,
    pub tx_id:       String,
    pub amount_uqcb: u64,
    pub status:      String,
}

/// Settlement-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum SettlementError {
    #[error("request contains private-key material: {0}")]
    PrivateKeyMaterial(String),
    #[error("signing profile {0:?} is not supported: only \"qattice-v2\"")]
    UnsupportedProfile(String),
    #[error("this scheduler build does not include signing v2")]
    SigningUnavailable,
    #[error("unknown reward_kind '{0}': expected 'primary' or 'replication'")]
    UnknownRewardKind(String),
    #[error("objective '{0}' has no accepted result for task '{1}'")]
    NoAcceptedResult(String, String),
    #[error("reward policy rejected: {0}")]
    PolicyRejected(String),
    #[error("claim already exists (idempotent): claim_id={0}")]
    ClaimAlreadyExists(String),
    #[error("claim not found: {0}")]
    ClaimNotFound(String),
    #[error("public key invalid: {0}")]
    KeyDecode(String),
    #[error("signed transaction does not match the claim: {0}")]
    TxMismatch(String),
    #[error("signature rejected: {0}")]
    BadSignature(String),
    #[error("database error: {0}")]
    Db(String),
    #[error("node submission failed: {0}")]
    NodeSubmission(String),
}

// ── refusing private-key material ───────────────────────────────────────────────────────────────────────────────────────

/// Field-name fragments (compared lower-case with punctuation removed) that mark a field as secret material.
const FORBIDDEN_NAME_PARTS: [&str; 7] = ["secret", "private", "seed", "mnemonic", "passphrase", "password", "privkey"];
/// A contiguous hex run at least this long cannot be a public key (3,904), a signature (6,618) or a hash: an ML-DSA-65 secret key is
/// 8,064 hex characters.
const SECRET_HEX_RUN: usize = 7_500;

fn normalised(name: &str) -> String { name.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect() }

fn longest_hex_run(text: &str) -> usize {
    let (mut best, mut cur) = (0usize, 0usize);
    for b in text.bytes() {
        if b.is_ascii_hexdigit() { cur += 1; best = best.max(cur); } else { cur = 0; }
    }
    best
}

fn scan_value(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                let n = normalised(k);
                if FORBIDDEN_NAME_PARTS.iter().any(|p| n.contains(p)) { return Some("a field name marks it as secret material".into()); }
                if let Some(r) = scan_value(val) { return Some(r); }
            }
            None
        }
        serde_json::Value::Array(a) => a.iter().find_map(scan_value),
        serde_json::Value::String(t) => {
            if t.contains("PRIVATE KEY") { Some("a private-key block (PEM) is present".into()) }
            else if longest_hex_run(t) >= SECRET_HEX_RUN { Some("a value has the size of an ML-DSA-65 secret key".into()) }
            else { None }
        }
        _ => None,
    }
}

/// Refuse a request body that contains private-key material, **before** it is parsed into a request or anything is stored. Checks field
/// names at any depth, PEM private-key blocks, and values of secret-key size, in valid JSON and in text that is not valid JSON.
/// The message never echoes the offending value. Limits: it cannot recognise a key hidden in an unrelated encoding (for example
/// base64 or split across fields); the design makes such a key useless to the scheduler instead of relying on detection alone.
pub fn reject_private_key_material(raw: &[u8]) -> Result<(), SettlementError> {
    let text = String::from_utf8_lossy(raw);
    let reason = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(v) => scan_value(&v),
        Err(_) => {
            if text.contains("PRIVATE KEY") { Some("a private-key block (PEM) is present".to_string()) }
            else if longest_hex_run(&text) >= SECRET_HEX_RUN { Some("the body contains a value of secret-key size".to_string()) }
            else { None }
        }
    };
    match reason { Some(r) => Err(SettlementError::PrivateKeyMaterial(r)), None => Ok(()) }
}

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────────

fn db_err(e: ResearchDbError) -> SettlementError { SettlementError::Db(e.to_string()) }

/// The deterministic transaction id: independent of the signature so the node can deduplicate on mempool ingress.
pub fn claim_tx_id(claim_id: &str, operator: &str, nonce: u64) -> String {
    let mut h = Sha256::new();
    h.update(b"claim-tx-v1\x00");
    h.update(claim_id.as_bytes());
    h.update(b"\x00");
    h.update(operator.as_bytes());
    h.update(b"\x00");
    h.update(nonce.to_le_bytes());
    hex::encode(h.finalize())
}

fn strict_hex(s: &str, bytes: usize) -> Option<Vec<u8>> {
    if s.len() != bytes * 2 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(feature = "signing-v2")]
mod v2 {
    use super::*;
    use chain_forge_crypto::SchemeId;
    use chain_forge_execution::signing_v2;
    use chain_forge_execution::{Transaction, TxBody};
    use chain_forge_research_db::models::ResearchRewardClaim;

    const PUBLIC_KEY_BYTES: usize = 1952;

    fn body_of(c: &ResearchRewardClaim) -> TxBody {
        TxBody::ClaimResearchReward {
            claim_id: c.claim_id.clone(), objective_id: c.objective_id.clone(), task_id: c.task_id.clone(), result_id: c.result_id.to_string(),
            contribution_hash: c.contribution_hash.clone(), recipient: c.recipient.clone(), amount_uqcb: c.amount_uqcb.max(0) as u64,
            policy_version: c.policy_version.clone(), reward_kind: c.reward_kind.clone(),
        }
    }

    pub async fn prepare(db: &Arc<dyn ResearchDb>, objective_id: &str, req: PrepareRequest) -> Result<PrepareResponse, SettlementError> {
        // -- everything is validated before anything is stored --
        if req.signing_profile != "qattice-v2" { return Err(SettlementError::UnsupportedProfile(req.signing_profile)); }
        let reward_kind = match req.reward_kind.as_str() {
            "primary" => RewardKind::Primary,
            "replication" => RewardKind::Replication,
            other => return Err(SettlementError::UnknownRewardKind(other.to_owned())),
        };
        let pk = strict_hex(&req.operator_public_key_hex, PUBLIC_KEY_BYTES)
            .ok_or_else(|| SettlementError::KeyDecode("operator_public_key_hex must be 1,952 bytes of lowercase hex".into()))?;
        let canonical = db.get_accepted_results_for_objective(objective_id).await.map_err(db_err)?
            .into_iter().find(|r| r.task_id == req.task_id)
            .ok_or_else(|| SettlementError::NoAcceptedResult(objective_id.to_owned(), req.task_id.clone()))?;

        let treasury = req.policy.as_ref().and_then(|p| p.treasury_address.clone()).unwrap_or_else(|| "treasury:pocd-research".to_owned());
        let mut policy = QcbResearchRewardPolicy::default_for_devnet(treasury);
        if let Some(p) = &req.policy {
            if let Some(v) = p.primary_rate_uqcb { policy.primary_rate_uqcb = v; }
            if let Some(v) = p.replication_rate_uqcb { policy.replication_rate_uqcb = v; }
            if let Some(v) = p.objective_budget_uqcb { policy.objective_budget_uqcb = v; }
        }
        let output = policy.compute_reward(&req.chain_id, objective_id, &req.task_id, canonical.result_id, &canonical.content_hash,
                                           &req.recipient, reward_kind, req.disbursed_uqcb)
            .map_err(|e| SettlementError::PolicyRejected(e.to_string()))?;
        let claim_id = output.claim.claim_id.clone();

        // -- store the claim (idempotent). A pending claim may be prepared again; anything else is a conflict. --
        let claim = match db.insert_reward_claim(output.claim).await {
            Ok(c) => c,
            Err(ResearchDbError::Duplicate(_)) => {
                match db.get_reward_claim(&claim_id).await.map_err(db_err)? {
                    Some(c) if c.claim_status == "pending" => {
                        if c.recipient != req.recipient { return Err(SettlementError::TxMismatch("a pending claim exists for a different recipient".into())); }
                        c
                    }
                    _ => { info!(claim_id, "claim already exists and is not pending"); return Err(SettlementError::ClaimAlreadyExists(claim_id)); }
                }
            }
            Err(e) => return Err(db_err(e)),
        };

        let tx = Transaction {
            id: claim_tx_id(&claim.claim_id, &req.operator_address, req.operator_nonce),
            sender: req.operator_address.clone(),
            nonce: req.operator_nonce,
            body: body_of(&claim),
            gas_limit: CLAIM_GAS_LIMIT,
            sig_scheme: Some(SchemeId::MlDsa),
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            pq_public_key: if req.carry_key { pk.clone() } else { vec![] },
        };
        let preimage = signing_v2::tx_preimage(&req.chain_id, &tx, &pk).map_err(SettlementError::TxMismatch)?;
        Ok(PrepareResponse {
            claim_id: claim.claim_id.clone(),
            tx_id: tx.id.clone(),
            amount_uqcb: claim.amount_uqcb.max(0) as u64,
            unsigned_tx: serde_json::to_value(&tx).map_err(|e| SettlementError::TxMismatch(e.to_string()))?,
            signing_request: SigningRequest {
                profile: "qattice-v2".into(), context: String::from_utf8_lossy(signing_v2::TX_CONTEXT).into_owned(), chain_id: req.chain_id,
                signer: req.operator_address, pq_public_key_hex: hex::encode(&pk), preimage_hex: hex::encode(&preimage),
            },
        })
    }

    pub async fn submit(db: &Arc<dyn ResearchDb>, objective_id: &str, req: SubmitRequest) -> Result<SettleResponse, SettlementError> {
        if !(req.node_url.starts_with("http://") || req.node_url.starts_with("https://")) {
            return Err(SettlementError::NodeSubmission("node_url must be http:// or https://".into()));
        }
        let claim = db.get_reward_claim(&req.claim_id).await.map_err(db_err)?
            .filter(|c| c.objective_id == objective_id)
            .ok_or_else(|| SettlementError::ClaimNotFound(req.claim_id.clone()))?;
        if claim.claim_status != "pending" { return Err(SettlementError::ClaimAlreadyExists(claim.claim_id)); }

        let tx: Transaction = serde_json::from_value(req.signed_tx).map_err(|_| SettlementError::TxMismatch("signed_tx is not a transaction".into()))?;

        // The transaction must be exactly the stored claim: the endpoint is not a generic relay.
        let want = serde_json::to_value(body_of(&claim)).map_err(|e| SettlementError::TxMismatch(e.to_string()))?;
        let have = serde_json::to_value(&tx.body).map_err(|e| SettlementError::TxMismatch(e.to_string()))?;
        if want != have { return Err(SettlementError::TxMismatch("the body is not the stored claim".into())); }
        if tx.id != claim_tx_id(&claim.claim_id, &tx.sender, tx.nonce) { return Err(SettlementError::TxMismatch("the transaction id is not the deterministic claim id".into())); }
        if tx.gas_limit != CLAIM_GAS_LIMIT { return Err(SettlementError::TxMismatch("the gas limit is not the claim gas limit".into())); }

        // Signing v2: strict envelope, and the signature when the key is carried (the node settles bound-key transactions).
        let bound: Option<&[u8]> = if tx.pq_public_key.is_empty() { Some(&[]) } else { None };
        signing_v2::check_envelope(&tx, bound).map_err(|code| SettlementError::BadSignature(code.to_string()))?;
        signing_v2::verify_carried_key(&req.chain_id, &tx).map_err(SettlementError::BadSignature)?;

        let url = format!("{}/api/tx", req.node_url.trim_end_matches('/'));
        let resp = reqwest::Client::new().post(&url).json(&tx).send().await
            .map_err(|e| SettlementError::NodeSubmission(format!("HTTP error: {e}")))?;
        let code = resp.status();
        if !code.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!(claim_id = %claim.claim_id, %code, "node rejected ClaimResearchReward tx");
            let _ = db.mark_claim_rejected(&claim.claim_id, &format!("node returned {code}: {body}")).await;
            return Err(SettlementError::NodeSubmission(format!("node returned {code}")));
        }
        db.mark_claim_submitted(&claim.claim_id, &tx.id).await.map_err(db_err)?;
        info!(claim_id = %claim.claim_id, tx_id = %tx.id, "ClaimResearchReward submitted");
        Ok(SettleResponse { claim_id: claim.claim_id, tx_id: tx.id, amount_uqcb: claim.amount_uqcb.max(0) as u64, status: "submitted".into() })
    }
}

/// Step 1: compute the claim, store it as pending, and return the unsigned transaction and the signing request.
pub async fn prepare_settlement(db: &Arc<dyn ResearchDb>, objective_id: &str, req: PrepareRequest) -> Result<PrepareResponse, SettlementError> {
    if req.signing_profile != "qattice-v2" { return Err(SettlementError::UnsupportedProfile(req.signing_profile)); }
    #[cfg(feature = "signing-v2")]
    { v2::prepare(db, objective_id, req).await }
    #[cfg(not(feature = "signing-v2"))]
    { let _ = (db, objective_id); Err(SettlementError::SigningUnavailable) }
}

/// Step 2: verify the signed transaction against the stored claim and forward it to the node.
pub async fn submit_settlement(db: &Arc<dyn ResearchDb>, objective_id: &str, req: SubmitRequest) -> Result<SettleResponse, SettlementError> {
    #[cfg(feature = "signing-v2")]
    { v2::submit(db, objective_id, req).await }
    #[cfg(not(feature = "signing-v2"))]
    { let _ = (db, objective_id, req); Err(SettlementError::SigningUnavailable) }
}

#[allow(dead_code)]
fn _status_is_used(_: ClaimStatus) {}
