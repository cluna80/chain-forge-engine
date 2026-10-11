//! Typed error enum for the intelligence engine.

use uuid::Uuid;

use chain_forge_research_db::ResearchDbError;

#[derive(Debug, thiserror::Error)]
pub enum IntelligenceError {
    /// The requested objective does not exist.
    #[error("objective not found: {0}")]
    ObjectiveNotFound(String),

    /// The requested intelligence report has not been generated yet.
    #[error("no intelligence report found for objective: {0}")]
    ReportNotFound(String),

    /// The result referenced during analysis does not exist.
    #[error("result not found: {0}")]
    ResultNotFound(Uuid),

    /// A propagated database error.
    #[error("database error: {0}")]
    Db(#[from] ResearchDbError),
}

/// Result type for the intelligence engine.
pub type IntelligenceResult<T> = Result<T, IntelligenceError>;
