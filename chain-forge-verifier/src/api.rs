//! Axum HTTP handlers for the verifier API.
//!
//! ## Endpoints
//!
//! | Method | Path                                                      | Description                                    |
//! |--------|-----------------------------------------------------------|------------------------------------------------|
//! | POST   | `/verifier/tasks/{task_id}/verify`                        | Submit an independent verification             |
//! | GET    | `/verifier/objectives/{objective_id}/submitted`           | List tasks awaiting verification               |
//!
//! ## State sharing
//!
//! All handlers share a single `AppState` held in an `Arc`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    engine::VerificationEngine,
    error::VerifierError,
};

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub engine: VerificationEngine,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/verifier/tasks/:task_id/verify",
            post(submit_verification),
        )
        .route(
            "/verifier/objectives/:objective_id/submitted",
            get(list_submitted),
        )
        .with_state(Arc::new(state))
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SubmitVerificationRequest {
    pub result_id:              Uuid,
    pub verifier_id:            String,
    pub outcome:                String,
    pub verifier_content_hash:  String,
    pub notes:                  Option<String>,
    pub verifier_receipt_id:    Option<String>,
}

#[derive(Serialize)]
pub struct SubmitVerificationResponse {
    pub accepted: bool,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn submit_verification(
    State(state):  State<Arc<AppState>>,
    Path(task_id): Path<String>,
    Json(req):     Json<SubmitVerificationRequest>,
) -> Response {
    match state
        .engine
        .submit_verification(
            &task_id,
            req.result_id,
            &req.verifier_id,
            &req.outcome,
            &req.verifier_content_hash,
            req.notes,
            req.verifier_receipt_id,
        )
        .await
    {
        Ok(accepted) => {
            let code = if accepted {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            (code, Json(SubmitVerificationResponse { accepted })).into_response()
        }
        Err(e @ VerifierError::SelfVerification(_)) => {
            (StatusCode::FORBIDDEN, e.to_string()).into_response()
        }
        Err(e @ VerifierError::DuplicateVerification { .. }) => {
            (StatusCode::CONFLICT, e.to_string()).into_response()
        }
        Err(e @ VerifierError::InvalidOutcome(_)) => {
            (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response()
        }
        Err(e @ VerifierError::TaskNotSubmitted { .. }) => {
            (StatusCode::CONFLICT, e.to_string()).into_response()
        }
        Err(e @ VerifierError::AlreadyAccepted { .. }) => {
            (StatusCode::CONFLICT, e.to_string()).into_response()
        }
        Err(e @ VerifierError::ResultNotFound(_)) | Err(e @ VerifierError::TaskNotFound { .. }) => {
            (StatusCode::NOT_FOUND, e.to_string()).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_submitted(
    State(state):        State<Arc<AppState>>,
    Path(objective_id):  Path<String>,
) -> Response {
    match state.engine.list_submitted_tasks(&objective_id).await {
        Ok(tasks) => (StatusCode::OK, Json(tasks)).into_response(),
        Err(e)    => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
