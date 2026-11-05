//! Axum HTTP handlers for the scheduler API.
//!
//! ## Endpoints
//!
//! | Method | Path                                        | Description                              |
//! |--------|---------------------------------------------|------------------------------------------|
//! | POST   | `/scheduler/seed`                           | Insert objective + tasks (seed)          |
//! | POST   | `/scheduler/miners/register`                | Register / heartbeat a miner             |
//! | GET    | `/scheduler/miners/{miner_id}/task`         | Poll for a task assignment               |
//! | POST   | `/scheduler/tasks/{task_id}/result`         | Submit task result                       |
//! | POST   | `/scheduler/tasks/{task_id}/verify`         | Submit independent verification (CS M)   |
//! | GET    | `/scheduler/objectives/{id}/results`        | List results for an objective            |
//! | POST   | `/scheduler/objectives/{id}/settle/prepare` | Prepare a claim: unsigned tx + signing request |
//! | POST   | `/scheduler/objectives/{id}/settle/submit`  | Submit the SIGNED claim tx (no private key ever) |
//! | POST   | `/scheduler/objectives/{id}/settle`         | REMOVED (410): it accepted a private key |
//! | GET    | `/scheduler/status`                         | Queue depth + active lease count         |
//!
//! ## State sharing
//!
//! All handlers share a single `AppState` held in an `Arc`.  Routes are
//! built in `router()` and consumed by the binary's `main`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use chain_forge_research_db::models::{NewExperimentResult, NewObjective, NewTask};

use crate::{
    beacon::BeaconService,
    error::SchedulerError,
    miner::MinerRegistry,
    scheduler::ResearchScheduler,
    settlement::{prepare_settlement, reject_private_key_material, submit_settlement, PrepareRequest, SettlementError, SubmitRequest},
    verification::{VerificationEngine, VerificationError, VerifyRequest},
    verifier_registry::{
        RegisterVerifierRequest, RegistryError, VerifierRegistry,
    },
};

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub scheduler:    ResearchScheduler,
    pub miners:       MinerRegistry,
    /// Change Set M: verification engine for independent result reproduction.
    pub verification: VerificationEngine,
    /// Change Set P (P1): verifier identity registry.
    /// `None` — legacy mode (no signature or independence checks).
    /// `Some` — registry mode: all verifications must be authenticated.
    pub verifier_registry: Option<VerifierRegistry>,
    /// Change Set Q: BTC-beacon deterministic job assignment service.
    /// Miners can call GET /scheduler/beacon to get the current slot without
    /// running their own BTC node.
    pub beacon: BeaconService,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/scheduler/seed",                                   post(seed_objective))
        .route("/scheduler/miners/register",                        post(register_miner))
        .route("/scheduler/miners/:miner_id/task",                  get(get_task_for_miner))
        .route("/scheduler/tasks/:task_id/result",                  post(submit_result))
        // Change Set M: independent verification
        .route("/scheduler/tasks/:task_id/verify",                  post(verify_result))
        .route("/scheduler/objectives/:objective_id/results",       get(list_objective_results))
        // Change Set L: settlement operator endpoint
        .route("/scheduler/objectives/:objective_id/settle",        post(settle_removed_handler))
        .route("/scheduler/objectives/:objective_id/settle/prepare", post(settle_prepare_handler))
        .route("/scheduler/objectives/:objective_id/settle/submit",  post(settle_submit_handler))
        // Change Set P (P1): verifier identity registration
        .route("/scheduler/verifiers/register",                     post(register_verifier))
        .route("/scheduler/verifiers",                              get(list_verifiers))
        // Change Set Q: BTC-beacon deterministic assignment
        .route("/scheduler/beacon",                                 get(get_beacon))
        .route("/scheduler/status",                                 get(status))
        .with_state(Arc::new(state))
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterMinerRequest {
    pub miner_id:      String,
    pub workload_class: String,
}

#[derive(Serialize)]
pub struct RegisterMinerResponse {
    pub miner_id:      String,
    pub workload_class: String,
}

#[derive(Deserialize)]
pub struct GetTaskQuery {
    pub objective_id:  String,
    pub workload_class: Option<String>,
    /// Change Set Q: BTC block hash (64 hex chars) for deterministic beacon
    /// assignment.  When present, the scheduler uses `assign_task_by_beacon`.
    /// When absent, falls back to legacy FIFO-random assignment.
    pub btc_hash: Option<String>,
}

#[derive(Deserialize)]
pub struct ResultsQuery {
    #[serde(default = "default_limit")]
    pub limit:  usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize { 1000 }

#[derive(Serialize)]
pub struct TaskAssignmentResponse {
    pub task_id:          String,
    pub objective_id:     String,
    pub range_start:      i64,
    pub range_end:        i64,
    pub workload_class:   String,
    pub input_seed:       i64,
    pub lease_expires_at: chrono::DateTime<chrono::Utc>,
    pub lease_generation: i64,
    /// Which cascade phase this task belongs to (1 or 2).
    pub phase:            i32,
    /// Phase-2 only: hex-encoded phase-1 winning hash that seeds this task.
    pub parent_hash:      Option<String>,
    /// Task kind discriminator: "pocd_phase1" | "pocd_phase2" |
    /// "avalanche_experiment" | "avalanche_replication".
    pub task_kind:        String,
    /// Avalanche tasks only: which of the 10 canonical seeds (0..9).
    pub avl_seed_index:   Option<i32>,
    /// Avalanche tasks only: which input bit position is flipped (0..255).
    pub avl_bit_index:    Option<i32>,
}

#[derive(Deserialize)]
pub struct SubmitResultRequest {
    pub miner_id:             String,
    pub submitted_generation: i64,
    pub result:               NewExperimentResult,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub registered_miners: usize,
}

// ── Seed request / response ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SeedRequest {
    pub objective: NewObjective,
    pub tasks:     Vec<NewTask>,
}

#[derive(Serialize)]
pub struct SeedResponse {
    pub objective_id:   String,
    pub tasks_inserted: usize,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn seed_objective(
    State(state): State<Arc<AppState>>,
    Json(req):    Json<SeedRequest>,
) -> Response {
    let objective_id = req.objective.objective_id.clone();
    let _task_count  = req.tasks.len();

    if let Err(e) = state.scheduler.db().insert_objective(req.objective).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    match state.scheduler.db().upsert_tasks(req.tasks).await {
        Ok(n) => (StatusCode::CREATED, Json(SeedResponse {
            objective_id,
            tasks_inserted: n,
        })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn register_miner(
    State(state): State<Arc<AppState>>,
    Json(req):    Json<RegisterMinerRequest>,
) -> Response {
    state.miners.register(&req.miner_id, &req.workload_class);
    (
        StatusCode::OK,
        Json(RegisterMinerResponse {
            miner_id:      req.miner_id,
            workload_class: req.workload_class,
        }),
    )
        .into_response()
}

async fn get_task_for_miner(
    State(state): State<Arc<AppState>>,
    Path(miner_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<GetTaskQuery>,
) -> Response {
    let workload = q.workload_class.as_deref().unwrap_or("cpu");

    // Change Set Q — beacon path when btc_hash is provided.
    let assign_result = if let Some(ref btc_hex) = q.btc_hash {
        match decode_btc_hash(btc_hex) {
            Ok(hash) => {
                state.scheduler
                    .assign_task_by_beacon(&q.objective_id, workload, &miner_id, &hash)
                    .await
            }
            Err(msg) => {
                return (StatusCode::BAD_REQUEST, msg).into_response();
            }
        }
    } else {
        // Legacy FIFO path — no btc_hash provided.
        state.scheduler.assign_task(&q.objective_id, workload, &miner_id).await
    };

    match assign_result {
        Ok(row) => {
            let resp = TaskAssignmentResponse {
                task_id:          row.task_id,
                objective_id:     row.objective_id,
                range_start:      row.range_start,
                range_end:        row.range_end,
                workload_class:   row.workload_class,
                input_seed:       row.input_seed,
                lease_expires_at: row.lease_expires_at.unwrap_or_else(chrono::Utc::now),
                lease_generation: row.lease_generation,
                phase:            row.phase,
                parent_hash:      row.parent_hash,
                task_kind:        row.task_kind,
                avl_seed_index:   row.avl_seed_index,
                avl_bit_index:    row.avl_bit_index,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(SchedulerError::NoTaskAvailable { .. }) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => scheduler_error_response(e),
    }
}

/// GET /scheduler/beacon — return the current BTC beacon slot.
///
/// Miners without a BTC RPC node call this to get the beacon hash for
/// deterministic job selection.
async fn get_beacon(State(state): State<Arc<AppState>>) -> Response {
    match state.beacon.fetch().await {
        Ok(slot) => (StatusCode::OK, Json(slot)).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Beacon unavailable: {e}"),
        )
            .into_response(),
    }
}

/// Decode a 64-char hex BTC block hash to raw bytes.
fn decode_btc_hash(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex).map_err(|_| format!("btc_hash: invalid hex: {hex}"))?;
    bytes.try_into().map_err(|_| format!("btc_hash: expected 32 bytes (64 hex chars), got {}", hex.len() / 2))
}

async fn submit_result(
    State(state):   State<Arc<AppState>>,
    Path(task_id):  Path<String>,
    Json(req):      Json<SubmitResultRequest>,
) -> Response {
    match state
        .scheduler
        .submit_result(&task_id, &req.miner_id, req.submitted_generation, req.result)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e @ SchedulerError::LeaseSuperseded { .. }) => {
            (StatusCode::CONFLICT, e.to_string()).into_response()
        }
        Err(e @ SchedulerError::LeaseExpired { .. }) => {
            (StatusCode::GONE, e.to_string()).into_response()
        }
        Err(e @ SchedulerError::WrongMiner { .. }) => {
            (StatusCode::FORBIDDEN, e.to_string()).into_response()
        }
        Err(e) => scheduler_error_response(e),
    }
}

// ── Verify handler (Change Set M) ─────────────────────────────────────────────

/// `POST /scheduler/tasks/{task_id}/verify`
///
/// Independent verifiers call this endpoint after reproducing (or attempting
/// to reproduce) a submitted result.  When the number of independent
/// `"reproduced"` verifications reaches the objective's `verification_quorum`,
/// the result is atomically promoted to canonical and the task transitions to
/// `'accepted'`, making it eligible for reward settlement.
///
/// Returns `201 Created` on success, with `quorum_reached: true` when the
/// submission triggered canonical acceptance.
async fn verify_result(
    State(state):   State<Arc<AppState>>,
    Path(task_id):  Path<String>,
    Json(req):      Json<VerifyRequest>,
) -> Response {
    match state.verification.record_verification(&task_id, req).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),

        Err(VerificationError::ResultNotFound(id)) => {
            let body = serde_json::json!({
                "error": "result_not_found",
                "result_id": id.to_string(),
            });
            (StatusCode::NOT_FOUND, Json(body)).into_response()
        }

        Err(VerificationError::TaskNotFound(ref id)) => {
            let body = serde_json::json!({
                "error": "task_not_found",
                "task_id": id,
            });
            (StatusCode::NOT_FOUND, Json(body)).into_response()
        }

        Err(VerificationError::UnknownOutcome(ref o)) => {
            let body = serde_json::json!({
                "error": "unknown_outcome",
                "outcome": o,
                "message": "Expected 'reproduced', 'rejected', or 'inconclusive'.",
            });
            (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
        }

        Err(VerificationError::HashMismatch { ref verifier, ref original }) => {
            let body = serde_json::json!({
                "error": "hash_mismatch",
                "verifier_content_hash": verifier,
                "original_content_hash": original,
                "message": "Verifier hash differs from the original result. \
                            Use outcome 'rejected' or 'inconclusive' when hashes differ.",
            });
            (StatusCode::CONFLICT, Json(body)).into_response()
        }

        Err(VerificationError::SelfVerification) => {
            let body = serde_json::json!({
                "error": "self_verification",
                "message": "verifier_id must differ from the original miner_id.",
            });
            (StatusCode::FORBIDDEN, Json(body)).into_response()
        }

        Err(VerificationError::NotSubmitted(id)) => {
            let body = serde_json::json!({
                "error": "not_submitted",
                "result_id": id.to_string(),
                "message": "Result is not in 'submitted' status. \
                            Only submitted results can receive independent verifications.",
            });
            (StatusCode::CONFLICT, Json(body)).into_response()
        }

        // ── Change Set P (P2) errors ──────────────────────────────────────────

        Err(VerificationError::UnregisteredVerifier(ref id)) => {
            let body = serde_json::json!({
                "error": "unregistered_verifier",
                "verifier_id": id,
                "message": "Verifier identity is not registered. \
                            POST /scheduler/verifiers/register first.",
            });
            (StatusCode::FORBIDDEN, Json(body)).into_response()
        }

        Err(VerificationError::UnauthorizedVerifier(ref id)) => {
            let body = serde_json::json!({
                "error": "unauthorized_verifier",
                "verifier_id": id,
                "message": "Verifier is registered but not currently authorized \
                            (may be revoked or suspended).",
            });
            (StatusCode::FORBIDDEN, Json(body)).into_response()
        }

        Err(VerificationError::SignatureRequired) => {
            let body = serde_json::json!({
                "error": "signature_required",
                "message": "This scheduler requires signed verification submissions. \
                            Include 'signature', 'workload_version', and 'submission_nonce' \
                            fields (Change Set P).",
            });
            (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
        }

        Err(VerificationError::InvalidSignature) => {
            let body = serde_json::json!({
                "error": "invalid_signature",
                "message": "Submission signature did not verify against the registered \
                            public key for this verifier_id.",
            });
            (StatusCode::FORBIDDEN, Json(body)).into_response()
        }

        // ── Change Set P (P3) errors ──────────────────────────────────────────

        Err(VerificationError::ControllerOverlap(ref ids)) => {
            let body = serde_json::json!({
                "error": "controller_overlap",
                "verifiers": ids,
                "message": "Quorum cannot be reached: two or more of the submitting \
                            verifiers are controlled by the same entity.",
            });
            (StatusCode::CONFLICT, Json(body)).into_response()
        }

        Err(VerificationError::IndependenceGroupOverlap(ref group)) => {
            let body = serde_json::json!({
                "error": "independence_group_overlap",
                "group": group,
                "message": "Quorum cannot be reached: two or more of the submitting \
                            verifiers are in the same independence group.",
            });
            (StatusCode::CONFLICT, Json(body)).into_response()
        }

        Err(VerificationError::MinerVerifierOverlap { ref verifier, ref controller }) => {
            let body = serde_json::json!({
                "error": "miner_verifier_overlap",
                "verifier_id": verifier,
                "controller_id": controller,
                "message": "A verifier controlled by the same entity as the original \
                            miner cannot contribute to this result's quorum.",
            });
            (StatusCode::FORBIDDEN, Json(body)).into_response()
        }

        Err(e) => {
            tracing::error!(error = %e, "verification failed");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

async fn list_objective_results(
    State(state):          State<Arc<AppState>>,
    Path(objective_id):    Path<String>,
    axum::extract::Query(q): axum::extract::Query<ResultsQuery>,
) -> Response {
    match state.scheduler.db().list_results_for_objective(&objective_id, q.limit, q.offset).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e)   => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn status(State(state): State<Arc<AppState>>) -> Response {
    let resp = StatusResponse {
        registered_miners: state.miners.count(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

// ── Settlement handler (Change Set L) ─────────────────────────────────────────

/// `POST /scheduler/objectives/:objective_id/settle` — REMOVED. It accepted the operator's private key in the request body. The body is
/// never read. Use `…/settle/prepare`, sign with `qcb-claim-signer`, then `…/settle/submit`.
async fn settle_removed_handler() -> Response {
    let body = serde_json::json!({
        "error": "settle_endpoint_removed",
        "message": "This endpoint accepted a private key and has been removed. Never send a private key to the scheduler: \
                    use POST /settle/prepare, sign the result with qcb-claim-signer, then POST /settle/submit.",
    });
    (StatusCode::GONE, Json(body)).into_response()
}

fn settlement_error_response(e: SettlementError) -> Response {
    let (status, code) = match &e {
        SettlementError::PrivateKeyMaterial(_) => (StatusCode::BAD_REQUEST, "private_key_material_rejected"),
        SettlementError::UnsupportedProfile(_) => (StatusCode::UNPROCESSABLE_ENTITY, "unsupported_signing_profile"),
        SettlementError::SigningUnavailable => (StatusCode::NOT_IMPLEMENTED, "signing_unavailable"),
        SettlementError::UnknownRewardKind(_) => (StatusCode::UNPROCESSABLE_ENTITY, "unknown_reward_kind"),
        SettlementError::PolicyRejected(_) => (StatusCode::UNPROCESSABLE_ENTITY, "policy_rejected"),
        SettlementError::KeyDecode(_) => (StatusCode::UNPROCESSABLE_ENTITY, "public_key_invalid"),
        SettlementError::TxMismatch(_) => (StatusCode::UNPROCESSABLE_ENTITY, "transaction_does_not_match_claim"),
        SettlementError::BadSignature(_) => (StatusCode::UNPROCESSABLE_ENTITY, "signature_rejected"),
        SettlementError::NoAcceptedResult(..) => (StatusCode::NOT_FOUND, "no_accepted_result"),
        SettlementError::ClaimNotFound(_) => (StatusCode::NOT_FOUND, "claim_not_found"),
        SettlementError::ClaimAlreadyExists(_) => (StatusCode::CONFLICT, "claim_already_exists"),
        SettlementError::NodeSubmission(_) => (StatusCode::BAD_GATEWAY, "node_submission_failed"),
        SettlementError::Db(_) => {
            tracing::error!(error = %e, "settlement database error");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "internal_error" }))).into_response();
        }
    };
    (status, Json(serde_json::json!({ "error": code, "message": e.to_string() }))).into_response()
}

fn invalid_request() -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({ "error": "invalid_request", "message": "the body is not a valid request for this endpoint" }))).into_response()
}

/// `POST /scheduler/objectives/:objective_id/settle/prepare`: public data in, unsigned transaction and signing request out. A body that
/// contains private-key material is refused before it is parsed or anything is stored.
async fn settle_prepare_handler(
    State(state):       State<Arc<AppState>>,
    Path(objective_id): Path<String>,
    body:               axum::body::Bytes,
) -> Response {
    if let Err(e) = reject_private_key_material(&body) { return settlement_error_response(e); }
    let Ok(req) = serde_json::from_slice::<PrepareRequest>(&body) else { return invalid_request() };
    match prepare_settlement(state.scheduler.db(), &objective_id, req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => settlement_error_response(e),
    }
}

/// `POST /scheduler/objectives/:objective_id/settle/submit`: the SIGNED claim transaction in; the scheduler checks it is exactly the stored
/// claim, verifies it, and forwards it to the node. Returns `201` on success, `409` when the claim is no longer pending.
async fn settle_submit_handler(
    State(state):       State<Arc<AppState>>,
    Path(objective_id): Path<String>,
    body:               axum::body::Bytes,
) -> Response {
    if let Err(e) = reject_private_key_material(&body) { return settlement_error_response(e); }
    let Ok(req) = serde_json::from_slice::<SubmitRequest>(&body) else { return invalid_request() };
    match submit_settlement(state.scheduler.db(), &objective_id, req).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(e) => settlement_error_response(e),
    }
}

// ── Verifier registration handlers (Change Set P — P1) ───────────────────────

/// `POST /scheduler/verifiers/register`
///
/// Register a new verifier identity with proof-of-possession of the ML-DSA-65
/// private key.  Returns `201 Created` on success.
///
/// Requires the scheduler to have been started with a verifier registry
/// (`--verifier-registry` flag).  Returns `501 Not Implemented` when no
/// registry is configured (legacy mode).
async fn register_verifier(
    State(state): State<Arc<AppState>>,
    Json(req):    Json<RegisterVerifierRequest>,
) -> Response {
    let Some(ref registry) = state.verifier_registry else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({
                "error": "registry_not_configured",
                "message": "This scheduler instance is running in legacy mode without a \
                            verifier registry.  Restart with --verifier-registry to enable \
                            authenticated verifier identities (Change Set P).",
            })),
        )
            .into_response();
    };

    match registry.register(req) {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),

        Err(RegistryError::AlreadyRegistered(id)) => {
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "already_registered",
                    "verifier_id": id,
                    "message": "A verifier with this ID is already registered.",
                })),
            )
                .into_response()
        }

        Err(RegistryError::InvalidPoP) => {
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "invalid_pop",
                    "message": "Proof-of-possession signature did not verify. \
                                Sign b\"QCB-VERIFIER-POP-v1\\x00\" || verifier_id \
                                with your ML-DSA-65 private key.",
                })),
            )
                .into_response()
        }

        Err(RegistryError::KeyDecode(msg)) => {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "key_decode_error",
                    "message": msg,
                })),
            )
                .into_response()
        }

        Err(RegistryError::SigDecode(msg)) => {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "signature_decode_error",
                    "message": msg,
                })),
            )
                .into_response()
        }

        Err(e) => {
            tracing::error!(error = %e, "verifier registration failed");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

/// `GET /scheduler/verifiers`
///
/// List all registered verifiers.  Includes revoked and suspended entries for
/// administrative inspection.
async fn list_verifiers(
    State(state): State<Arc<AppState>>,
) -> Response {
    let Some(ref registry) = state.verifier_registry else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({
                "error": "registry_not_configured",
                "message": "No verifier registry is configured.",
            })),
        )
            .into_response();
    };

    let all = registry.list_all();
    (StatusCode::OK, Json(all)).into_response()
}

// ── Error helper ──────────────────────────────────────────────────────────────

fn scheduler_error_response(e: SchedulerError) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
}
