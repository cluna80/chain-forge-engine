//! DIS-SDK-001: ergonomic Rust SDK for DIS-KS-V1 vendor (RP) and wallet integrations.
//!
//! This crate wraps `dis-core` with a higher-level API suitable for vendor server
//! integrations and reference wallet implementations. It is NOT a production-ready
//! SDK; see return gates in `docs/DIS-SDK-001-vendor-sdk-and-wallet.md`.

pub mod vendor;
pub mod wallet;

pub use dis_core::{Request, SUITE_ML_DSA_65};
pub use dis_core::verifier::{HolderProof, VerifyError};
pub use dis_core::delegation::{DelegatedProof, Delegation};

/// A (resource, action, scope) grant triple.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Grant {
    pub resource: String,
    pub action: String,
    pub scope: String,
}

impl Grant {
    pub fn new(resource: impl Into<String>, action: impl Into<String>, scope: impl Into<String>) -> Self {
        Self { resource: resource.into(), action: action.into(), scope: scope.into() }
    }
}

/// Top-level SDK error.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("verify error: {0}")]
    Verify(#[from] VerifyError),
    #[error("encoding error: {0}")]
    Encoding(#[from] dis_core::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}
