//! Error types for `chain-forge-scheduler`.

use thiserror::Error;

/// All errors the scheduler can return.
#[derive(Debug, Error)]
pub enum SchedulerError {
    /// A miner tried to submit results for a task it no longer owns.
    ///
    /// This happens when:
    /// * The lease expired and the task was reassigned, OR
    /// * The submitted `lease_generation` does not match the stored value.
    ///
    /// In both cases the submission is dropped without touching the database.
    #[error("lease superseded: task {task_id} generation expected {expected}, got {submitted}")]
    LeaseSuperseded {
        task_id:   String,
        expected:  i64,
        submitted: i64,
    },

    /// The submitting miner does not hold the current assignment.
    #[error("wrong miner: task {task_id} is assigned to {actual:?}, not {attempted}")]
    WrongMiner {
        task_id:  String,
        attempted: String,
        actual:   Option<String>,
    },

    /// The lease has expired (wall-clock check in the scheduler layer).
    #[error("lease expired: task {task_id} expired at {expired_at}")]
    LeaseExpired {
        task_id:    String,
        expired_at: chrono::DateTime<chrono::Utc>,
    },

    /// No task is currently available for the requested objective / workload.
    #[error("no available task for objective={objective_id} workload={workload_class}")]
    NoTaskAvailable {
        objective_id:  String,
        workload_class: String,
    },

    /// The requested task or miner was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Database layer error.
    #[error("database error: {0}")]
    Db(#[from] chain_forge_research_db::ResearchDbError),
}
