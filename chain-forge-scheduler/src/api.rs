//! Axum HTTP handlers for the scheduler API.
//!
//! ## Endpoints
//!
//! | Method | Path                                  | Description                       |
//! |--------|---------------------------------------|-----------------------------------|
//! | POST   | `/scheduler/miners/register`          | Register / heartbeat a miner      |
//! | GET    | `/scheduler/miners/{miner_id}/task`   | Poll for a task assignment        |
//! | POST   | `/scheduler/tasks/{task_id}/result`   | Submit task result                |
//! | GET    | `/scheduler/status`                   | Queue depth + active lease count  |
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

use chain_forge_research_db::models::NewExperimentResult;

use crate::{
    error::SchedulerError,
    miner::MinerRegistry,
    scheduler::ResearchScheduler,
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
        .route("/scheduler/miners/register",        post(register_miner))
        .route("/scheduler/miners/:miner_id/task",  get(get_task_for_miner))
        .route("/scheduler/tasks/:task_id/result",  post(submit_result))
        .route("/scheduler/status",                 get(status))
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

#[derive(Serialize)]
pub struct TaskAssignmentResponse {
    pub task_id:         String,
    pub objective_id:    String,
    pub range_start:     i64,
    pub range_end:       i64,
    pub workload_class:  String,
    pub input_seed:      i64,
    pub lease_expires_at: chrono::DateTime<chrono::Utc>,
    pub lease_generation: i64,
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

// ── Handlers ──────────────────────────────────────────────────────────────────

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

async fn status(State(state): State<Arc<AppState>>) -> Response {
    let resp = StatusResponse {
        registered_miners: state.miners.count(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

// ── Error helper ──────────────────────────────────────────────────────────────

fn scheduler_error_response(e: SchedulerError) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
}
