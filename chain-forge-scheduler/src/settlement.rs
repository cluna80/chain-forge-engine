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

use serde::{Deserialize, Serialize};

use chain_forge_research_db::ResearchDb;

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
    #[error("not implemented")]
    NotImplemented,
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

/// Refuse a request body that contains private-key material, before it is parsed or stored. SCAFFOLD: accepts everything.
pub fn reject_private_key_material(_raw: &[u8]) -> Result<(), SettlementError> { Ok(()) }

/// Step 1: compute the claim, store it as pending, and return the unsigned transaction and the signing request.
pub async fn prepare_settlement(
    _db: &Arc<dyn ResearchDb>, _objective_id: &str, _req: PrepareRequest,
) -> Result<PrepareResponse, SettlementError> {
    Err(SettlementError::NotImplemented)
}

/// Step 2: verify the signed transaction against the stored claim and forward it to the node.
pub async fn submit_settlement(
    _db: &Arc<dyn ResearchDb>, _objective_id: &str, _req: SubmitRequest,
) -> Result<SettleResponse, SettlementError> {
    Err(SettlementError::NotImplemented)
}
