//! Axum HTTP handlers for the scheduler API.
//!
//! ## Endpoints
//!
//! | Method | Path                                        | Description                           |
//! |--------|---------------------------------------------|---------------------------------------|
//! | POST   | `/scheduler/seed`                           | Insert objective + tasks (seed)       |
//! | POST   | `/scheduler/miners/register`                | Register / heartbeat a miner          |
//! | GET    | `/scheduler/miners/{miner_id}/task`         | Poll for a task assignment            |
//! | POST   | `/scheduler/tasks/{task_id}/result`         | Submit task result                    |
//! | GET    | `/scheduler/objectives/{id}/results`        | List results for an objective         |
//! | POST   | `/scheduler/objectives/{id}/settle`         | Settle a canonical result (Change Set L) |
//! | GET    | `/scheduler/status`                         | Queue depth + active lease count      |
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
    error::SchedulerError,
    miner::MinerRegistry,
    scheduler::ResearchScheduler,
    settlement::{settle_objective, SettleRequest, SettlementError},
};

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub scheduler: ResearchScheduler,
    pub miners:    MinerRegistry,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/scheduler/seed",                                   post(seed_objective))
        .route("/scheduler/miners/register",                        post(register_miner))
        .route("/scheduler/miners/:miner_id/task",                  get(get_task_for_miner))
        .route("/scheduler/tasks/:task_id/result",                  post(submit_result))
        .route("/scheduler/objectives/:objective_id/results",       get(list_objective_results))
        // Change Set L: settlement operator endpoint
        .route("/scheduler/objectives/:objective_id/settle",        post(settle_handler))
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
    match state.scheduler.assign_task(&q.objective_id, workload, &miner_id).await {
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

/// `POST /scheduler/objectives/:objective_id/settle`
///
/// Settlement operators call this endpoint to pay a miner whose canonical
/// research result has been accepted.  The handler:
///
/// 1. Looks up the canonical accepted result for the given task.
/// 2. Computes the reward via `QcbResearchRewardPolicy`.
/// 3. Inserts a `pending` claim record (idempotent — duplicate claim_id returns
///    the existing record).
/// 4. Builds and ML-DSA-65 signs a `ClaimResearchReward` transaction.
/// 5. POSTs the tx to the QCB node.
/// 6. Marks the claim `submitted`.
///
/// Returns `201 Created` on success, `409 Conflict` when the claim already
/// exists and has been submitted, and `422 Unprocessable` for policy or key
/// errors.
async fn settle_handler(
    State(state):          State<Arc<AppState>>,
    Path(objective_id):    Path<String>,
    Json(req):             Json<SettleRequest>,
) -> Response {
    match settle_objective(state.scheduler.db(), &objective_id, req).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),

        Err(SettlementError::ClaimAlreadyExists(id)) => {
            // Idempotent: a prior run already submitted this claim.
            let body = serde_json::json!({
                "error": "claim_already_exists",
                "claim_id": id,
                "message": "This claim was already submitted in a prior request.",
            });
            (StatusCode::CONFLICT, Json(body)).into_response()
        }

        Err(SettlementError::NoAcceptedResult(obj, task)) => {
            let body = serde_json::json!({
                "error": "no_accepted_result",
                "objective_id": obj,
                "task_id": task,
                "message": "No canonical accepted result found for this task. \
                            Ensure the result has been verified and accepted before settling.",
            });
            (StatusCode::NOT_FOUND, Json(body)).into_response()
        }

        Err(SettlementError::PolicyRejected(e)) => {
            let body = serde_json::json!({
                "error": "policy_rejected",
                "message": e.to_string(),
            });
            (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
        }

        Err(SettlementError::UnknownRewardKind(kind)) => {
            let body = serde_json::json!({
                "error": "unknown_reward_kind",
                "reward_kind": kind,
                "message": "Expected 'primary' or 'replication'.",
            });
            (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
        }

        Err(SettlementError::KeyDecode(msg)) => {
            let body = serde_json::json!({
                "error": "key_decode_error",
                "message": msg,
            });
            (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
        }

        Err(e) => {
            tracing::error!(error = %e, "settlement failed");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

// ── Error helper ──────────────────────────────────────────────────────────────

fn scheduler_error_response(e: SchedulerError) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
}
