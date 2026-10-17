//! Settlement operator logic for `POST /scheduler/objectives/:id/settle`.
//!
//! ## Flow
//!
//! 1. Look up the objective's canonical accepted result from the research DB.
//! 2. Compute the reward amount via `QcbResearchRewardPolicy`.
//! 3. Insert a `pending` reward claim into the DB (idempotent via deterministic
//!    `claim_id`).
//! 4. Build a `ClaimResearchReward` transaction, sign it with the settlement
//!    operator's ML-DSA-65 key.
//! 5. POST the signed tx to the node's `/api/tx` endpoint.
//! 6. Mark the claim `submitted` with the returned tx_id.
//!
//! ## Security
//!
//! - The operator's ML-DSA-65 private key is passed per-request (never stored
//!   by the scheduler).  In production it comes from a hardware key vault;
//!   for devnet it is passed directly in the request body.
//! - The deterministic `claim_id` ensures that a crash-recovered re-submission
//!   hits `ResearchDbError::Duplicate` at step 3, short-circuiting without
//!   a duplicate on-chain tx.
//! - Chain-ID binding and the `claim:{claim_id}` on-chain idempotency key
//!   prevent replay even if two scheduler instances race.
//!
//! ## Scientific integrity
//!
//! No result is automatically classified as a cryptographic breakthrough.
//! No experimental result is automatically classified as a cryptographic
//! anomaly or scientific discovery.  The scheduler does not introduce AI
//! inference, new token economics, or automatic scientific discovery claims.
//! Blockchain consensus is unchanged.  Result deduplication, lease
//! protections, and task ownership checks are preserved.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use tracing::{info, warn};

use chain_forge_crypto::{KeyPair, MlDsaScheme, SchemeId, SignatureScheme, mldsa_tx_prehash};
use chain_forge_execution::{Transaction, TxBody};
use chain_forge_qrc::{QcbResearchRewardPolicy, ResearchRewardError};
use chain_forge_research_db::{
    models::{ClaimStatus, RewardKind},
    ResearchDb, ResearchDbError,
};

// ── Public request / response types ──────────────────────────────────────────

/// Request body for `POST /scheduler/objectives/:id/settle`.
#[derive(Debug, serde::Deserialize)]
pub struct SettleRequest {
    /// Task ID within the objective whose canonical result should be settled.
    pub task_id: String,

    /// Which reward class is being claimed.
    ///
    /// - `"primary"` — the miner whose result was accepted as canonical.
    /// - `"replication"` — a miner whose result independently reproduced the
    ///   canonical result (rewarded at a lower rate).
    pub reward_kind: String,

    /// Payout address on the QCB chain.  Must match the miner's registered
    /// address; the settlement operator is responsible for verifying this
    /// before calling the endpoint.
    pub recipient: String,

    /// QCB chain ID — must match the node's genesis `chain_id`.
    /// Used for ML-DSA-65 signature binding and `claim_id` derivation.
    pub chain_id: String,

    /// Base URL of the QCB node's HTTP API (e.g. `http://localhost:8545`).
    pub node_url: String,

    /// Settlement operator's address on the QCB chain (must be in genesis
    /// `settlement_operators`).
    pub operator_address: String,

    /// Settlement operator's ML-DSA-65 private key, hex-encoded (4000 bytes
    /// → 8000 hex chars).  Never logged or persisted by the scheduler.
    pub operator_secret_key_hex: String,

    /// Settlement operator's ML-DSA-65 public key, hex-encoded (1952 bytes
    /// → 3904 hex chars).  Sent on the first tx to bind the key on-chain.
    pub operator_public_key_hex: String,

    /// Sender nonce — the operator's current account nonce on the QCB chain.
    /// The caller must fetch this from `/api/account/:address` before calling.
    pub operator_nonce: u64,

    /// Disbursed amount for this objective so far (in uqcb).
    /// The caller fetches the sum of finalized claims from the DB or the
    /// chain before calling.  Used for per-objective budget enforcement.
    pub disbursed_uqcb: u64,

    /// QcbResearchRewardPolicy overrides.  When omitted, devnet defaults apply.
    #[serde(default)]
    pub policy: Option<PolicyOverride>,
}

#[derive(Debug, serde::Deserialize, Default)]
pub struct PolicyOverride {
    pub primary_rate_uqcb:     Option<u64>,
    pub replication_rate_uqcb: Option<u64>,
    pub objective_budget_uqcb: Option<u64>,
    pub treasury_address:      Option<String>,
}

/// Response body for a successful settlement.
#[derive(Debug, serde::Serialize)]
pub struct SettleResponse {
    pub claim_id:    String,
    pub tx_id:       String,
    pub amount_uqcb: u64,
    pub status:      String,
}

/// Settlement-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum SettlementError {
    #[error("unknown reward_kind '{0}': expected 'primary' or 'replication'")]
    UnknownRewardKind(String),

    #[error("objective '{0}' has no accepted result for task '{1}'")]
    NoAcceptedResult(String, String),

    #[error("reward policy rejected: {0}")]
    PolicyRejected(#[from] ResearchRewardError),

    #[error("claim already exists (idempotent): claim_id={0}")]
    ClaimAlreadyExists(String),

    #[error("operator key decode error: {0}")]
    KeyDecode(String),

    #[error("ML-DSA-65 signing failed: {0}")]
    SigningFailed(String),

    #[error("database error: {0}")]
    Db(#[from] ResearchDbError),

    #[error("node submission failed: {0}")]
    NodeSubmission(String),
}

// ── Core settlement logic ─────────────────────────────────────────────────────

/// Execute one settlement operation end-to-end.
///
/// This is the entry point called by the Axum handler.  All steps are
/// described in the module-level doc.
pub async fn settle_objective(
    db:           &Arc<dyn ResearchDb>,
    objective_id: &str,
    req:          SettleRequest,
) -> Result<SettleResponse, SettlementError> {
    // ── 1. Parse reward kind ──────────────────────────────────────────────────
    let reward_kind = match req.reward_kind.as_str() {
        "primary"     => RewardKind::Primary,
        "replication" => RewardKind::Replication,
        other         => return Err(SettlementError::UnknownRewardKind(other.to_owned())),
    };

    // ── 2. Look up the canonical accepted result for this task ────────────────
    //
    // We fetch the task's canonical result from the DB.  The `list_submitted_tasks`
    // and `get_accepted_results_for_objective` paths are available; here we use
    // the accepted results list and filter to the requested task_id.
    let accepted = db.get_accepted_results_for_objective(objective_id).await?;
    let canonical = accepted
        .into_iter()
        .find(|r| r.task_id == req.task_id)
        .ok_or_else(|| {
            SettlementError::NoAcceptedResult(objective_id.to_owned(), req.task_id.clone())
        })?;

    // ── 3. Build the reward policy and compute the claim ─────────────────────
    let treasury = req
        .policy
        .as_ref()
        .and_then(|p| p.treasury_address.clone())
        .unwrap_or_else(|| "treasury:pocd-research".to_owned());

    let mut policy = QcbResearchRewardPolicy::default_for_devnet(treasury);
    if let Some(p) = &req.policy {
        if let Some(v) = p.primary_rate_uqcb     { policy.primary_rate_uqcb     = v; }
        if let Some(v) = p.replication_rate_uqcb  { policy.replication_rate_uqcb = v; }
        if let Some(v) = p.objective_budget_uqcb  { policy.objective_budget_uqcb = v; }
    }

    let output = policy.compute_reward(
        &req.chain_id,
        objective_id,
        &req.task_id,
        canonical.result_id,
        &canonical.content_hash,
        &req.recipient,
        reward_kind,
        req.disbursed_uqcb,
    )?;

    let claim_id    = output.claim.claim_id.clone();
    let amount_uqcb = output.amount_uqcb;

    // ── 4. Insert pending claim (idempotent) ──────────────────────────────────
    let _claim = match db.insert_reward_claim(output.claim).await {
        Ok(c) => c,
        Err(ResearchDbError::Duplicate(_)) => {
            // Idempotent re-submission: always return 409 so callers can
            // distinguish a new settlement from a replay.  The existing
            // claim_id is included in the 409 body so the caller can look
            // up the original tx_id if needed.
            info!(claim_id, "claim already exists — returning 409 ClaimAlreadyExists");
            return Err(SettlementError::ClaimAlreadyExists(claim_id));
        }
        Err(e) => return Err(e.into()),
    };

    // ── 5. Build the ClaimResearchReward transaction ──────────────────────────
    //
    // The tx_id is the SHA-256 of the canonical fields — deterministic and
    // independent of the signature so the node can deduplicate on mempool ingress.
    let tx_id = {
        let mut h = Sha256::new();
        h.update(b"claim-tx-v1\x00");
        h.update(claim_id.as_bytes());
        h.update(b"\x00");
        h.update(req.operator_address.as_bytes());
        h.update(b"\x00");
        h.update(req.operator_nonce.to_le_bytes());
        hex::encode(h.finalize())
    };

    let mut tx = Transaction {
        id:          tx_id.clone(),
        sender:      req.operator_address.clone(),
        nonce:       req.operator_nonce,
        body:        TxBody::ClaimResearchReward {
            claim_id:         claim_id.clone(),
            objective_id:     objective_id.to_owned(),
            task_id:          req.task_id.clone(),
            result_id:        canonical.result_id.to_string(),
            contribution_hash: canonical.content_hash.clone(),
            recipient:        req.recipient.clone(),
            amount_uqcb,
            policy_version:   policy.policy_version().to_owned(),
            reward_kind:      req.reward_kind.clone(),
        },
        gas_limit:      500_000,
        signature:      vec![],
        public_key:     vec![],
        pq_signatures:  vec![],
        sig_scheme:     None,         // set to MlDsa below after signing (CS-001-H2)
        pq_public_key:  vec![],
    };

    // ── 6. Sign with ML-DSA-65 ────────────────────────────────────────────────
    //
    // The executor verifies: SHA-256("chain-forge/pq-tx/v1\n" || chain_id || "\n" || body_json)
    // signed with the operator's ML-DSA-65 key.
    let sk_bytes = hex::decode(&req.operator_secret_key_hex)
        .map_err(|e| SettlementError::KeyDecode(format!("secret key: {e}")))?;
    let pk_bytes = hex::decode(&req.operator_public_key_hex)
        .map_err(|e| SettlementError::KeyDecode(format!("public key: {e}")))?;

    let keypair = KeyPair {
        scheme:      SchemeId::MlDsa,
        public_key:  pk_bytes.clone(),
        private_key: sk_bytes,
    };

    // CS-001-M2: canonical pre-hash via mldsa_tx_prehash (MLDSA_TX_DOMAIN_V1 || chain_id || body).
    let body_json = serde_json::to_vec(&tx.body)
        .map_err(|e| SettlementError::SigningFailed(format!("body serialization: {e}")))?;
    let pq_message = mldsa_tx_prehash(&req.chain_id, &body_json);

    let sig = MlDsaScheme
        .sign(&pq_message, &keypair)
        .map_err(|e| SettlementError::SigningFailed(e.to_string()))?;

    tx.pq_signatures = vec![format!("mldsa65:{}", hex::encode(&sig.bytes))];
    tx.sig_scheme    = Some(SchemeId::MlDsa);  // CS-001-H2: explicit scheme tag
    tx.pq_public_key = pk_bytes;

    // ── 7. POST to node ───────────────────────────────────────────────────────
    let node_url = req.node_url.trim_end_matches('/');
    let submit_url = format!("{node_url}/api/tx");

    let client = reqwest::Client::new();
    let resp = client
        .post(&submit_url)
        .json(&tx)
        .send()
        .await
        .map_err(|e| SettlementError::NodeSubmission(format!("HTTP error: {e}")))?;

    let status_code = resp.status();
    if !status_code.is_success() {
        let body = resp.text().await.unwrap_or_default();
        warn!(
            claim_id,
            %status_code,
            %body,
            "node rejected ClaimResearchReward tx"
        );
        // Mark claim rejected in DB.
        let _ = db.mark_claim_rejected(
            &claim_id,
            &format!("node returned {status_code}: {body}"),
        ).await;
        return Err(SettlementError::NodeSubmission(
            format!("node returned {status_code}: {body}")
        ));
    }

    // ── 8. Mark claim submitted ───────────────────────────────────────────────
    db.mark_claim_submitted(&claim_id, &tx_id).await?;

    info!(
        claim_id,
        tx_id,
        amount_uqcb,
        objective_id,
        task_id = req.task_id,
        recipient = req.recipient,
        "ClaimResearchReward submitted successfully"
    );

    Ok(SettleResponse {
        claim_id,
        tx_id,
        amount_uqcb,
        status: ClaimStatus::Submitted.as_str().to_owned(),
    })
}
