use crate::types::job::JobState;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("invalid job state transition: {from:?} → {to:?}")]
    InvalidTransition { from: JobState, to: JobState },

    #[error("machine not found: {0}")]
    MachineNotFound(String),

    #[error("job not found: {0}")]
    JobNotFound(String),

    #[error("insufficient QRC: required {required}, available {available}")]
    InsufficientQrc { required: u64, available: u64 },

    #[error("escrow already locked for job {0}")]
    EscrowAlreadyLocked(String),

    #[error("escrow not found for job {0}")]
    EscrowNotFound(String),

    #[error("signature verification failed: {0}")]
    SignatureError(String),

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),
}
