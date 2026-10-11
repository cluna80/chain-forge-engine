//! Error types for the miner client.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MinerError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Scheduler error: {0}")]
    Scheduler(String),

    #[error("Deserialize error: {0}")]
    Deserialize(String),

    #[error("Lease expired: {0}")]
    LeaseExpired(String),

    #[error("Lease superseded: {0}")]
    LeaseSuperseded(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Worker thread error: {0}")]
    Worker(String),
}
