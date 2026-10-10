//! Typed error enum for the verification engine.

use uuid::Uuid;

use chain_forge_research_db::ResearchDbError;

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    /// The result to be verified does not exist.
    #[error("result not found: {0}")]
    ResultNotFound(Uuid),

    /// The task associated with the result does not exist.
    #[error("task not found: {task_id}")]
    TaskNotFound { task_id: String },

    /// The task is not in `submitted` status.
    ///
    /// Verifications can only be submitted for tasks that have been
    /// submitted by a miner.  A task in `available`, `assigned`, or
    /// `accepted` status cannot receive new verifications.
    #[error("task {task_id} has status '{status}', expected 'submitted'")]
    TaskNotSubmitted { task_id: String, status: String },

    /// A miner attempted to verify their own result.
    ///
    /// Self-verification is prohibited at every layer: DB constraint,
    /// `insert_verification`, and here.
    #[error("verifier_id '{0}' matches the original submitter — self-verification is prohibited")]
    SelfVerification(String),

    /// The verifier has already submitted a verification for this result.
    #[error("verifier '{verifier_id}' has already submitted a verification for result {result_id}")]
    DuplicateVerification { verifier_id: String, result_id: Uuid },

    /// An invalid outcome value was supplied.
    ///
    /// Valid values: `'reproduced'`, `'diverged'`, `'inconclusive'`.
    #[error("invalid verification outcome '{0}'; valid values: reproduced, diverged, inconclusive")]
    InvalidOutcome(String),

    /// The task is already in `'accepted'` status.
    #[error("task {task_id} is already accepted")]
    AlreadyAccepted { task_id: String },

    /// A propagated database error.
    #[error("database error: {0}")]
    Db(#[from] ResearchDbError),
}

/// Result type for the verification engine.
pub type VerifierResult<T> = Result<T, VerifierError>;
