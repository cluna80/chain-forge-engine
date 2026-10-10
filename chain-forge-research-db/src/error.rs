//! Error types for the research persistence layer.

use thiserror::Error;

/// Errors produced by the research database layer.
#[derive(Debug, Error)]
pub enum ResearchDbError {
    /// A record with this primary key already exists.
    #[error("duplicate record: {0}")]
    Duplicate(String),

    /// The referenced parent record (objective, task, result) does not exist.
    #[error("reference not found: {0}")]
    NotFound(String),

    /// A submitted result was rejected because an identical content_hash already
    /// exists for the same (task_id, miner_id) pair.
    #[error("duplicate experiment result: task={task_id} miner={miner_id} hash={content_hash}")]
    DuplicateResult {
        task_id:      String,
        miner_id:     String,
        content_hash: String,
    },

    /// A verifier attempted to verify their own submission.
    #[error("self-verification rejected: verifier_id matches original miner_id ({0})")]
    SelfVerification(String),

    /// A state-transition that is not permitted (e.g. accepting an already-accepted task).
    #[error("invalid state transition: {0}")]
    InvalidTransition(String),

    /// Underlying database error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Migration error.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Serialisation error.
    #[error("serialisation error: {0}")]
    Json(#[from] serde_json::Error),

    /// Any other error.
    #[error("{0}")]
    Other(String),
}
