//! axum 0.7 HTTP layer for the intelligence engine.
//!
//! Routes:
//!   GET  /intelligence/objectives/:id/report    — fetch persisted report
//!   POST /intelligence/objectives/:id/analyze   — (re-)generate and persist
//!   GET  /intelligence/objectives/:id/anomalies — anomaly detection only

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use crate::engine::AnalysisEngine;
use crate::error::IntelligenceError;

// ── AppState ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<AnalysisEngine>,
}

impl AppState {
    pub fn new(engine: AnalysisEngine) -> Self {
        Self {
            engine: Arc::new(engine),
        }
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/intelligence/objectives/:objective_id/report",
            get(get_report),
        )
        .route(
            "/intelligence/objectives/:objective_id/analyze",
            post(analyze),
        )
        .route(
            "/intelligence/objectives/:objective_id/anomalies",
            get(get_anomalies),
        )
        .with_state(state)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /intelligence/objectives/:id/report
///
/// Returns the most recently persisted `ObjectiveReport` as JSON.
/// Returns 404 if no report has been generated yet.
async fn get_report(
    State(state): State<AppState>,
    Path(objective_id): Path<String>,
) -> Response {
    match state.engine.get_report(&objective_id).await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(IntelligenceError::ReportNotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no report found", "objective_id": objective_id })),
        )
            .into_response(),
        Err(IntelligenceError::ObjectiveNotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "objective not found", "objective_id": objective_id })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /intelligence/objectives/:id/analyze
///
/// (Re-)generates an `ObjectiveReport`, persists it, and returns it.
/// Returns 404 if the objective does not exist.
async fn analyze(
    State(state): State<AppState>,
    Path(objective_id): Path<String>,
) -> Response {
    match state.engine.generate_report(&objective_id).await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(IntelligenceError::ObjectiveNotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "objective not found", "objective_id": objective_id })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /intelligence/objectives/:id/anomalies
///
/// Runs anomaly detection against current DB state without persisting a report.
async fn get_anomalies(
    State(state): State<AppState>,
    Path(objective_id): Path<String>,
) -> Response {
    match state.engine.detect_anomalies(&objective_id).await {
        Ok(anomalies) => (StatusCode::OK, Json(json!({ "anomalies": anomalies }))).into_response(),
        Err(IntelligenceError::ObjectiveNotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "objective not found", "objective_id": objective_id })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
