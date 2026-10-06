//! Work receipts.
//!
//! Two receipt types:
//!
//! * `ResourceExecutionReceipt` — proof that a marketplace job ran and
//!   finished (success or failure).
//! * `UsefulWorkReceipt` — proof that a machine contributed to a Grand
//!   Challenge and that an independent verifier validated the result.

use serde::{Deserialize, Serialize};

use super::job::JobId;
use super::machine::MachineId;

/// Category of work contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkType {
    /// General marketplace compute (CPU/GPU rental).
    MarketplaceCompute,
    /// Contribution to a governance-voted Grand Challenge.
    ResearchContribution,
}

/// Receipt produced at the end of a marketplace job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceExecutionReceipt {
    pub receipt_id: String,
    pub job_id: JobId,
    pub machine_id: MachineId,
    /// Whether the job completed successfully.
    pub success: bool,
    /// SHA-256 hash of the output bundle (hex).
    pub output_hash: String,
    /// Wall-clock seconds actually used.
    pub elapsed_seconds: f64,
    /// QRC owed to the provider (may differ from escrowed amount if billed
    /// by the second).
    pub qrc_earned: u64,
    pub timestamp_utc: String,
    /// Machine's Ed25519 signature over the receipt fields (base64).
    pub machine_signature: String,
}

/// Receipt for a Grand Challenge contribution (maps to the GC-DEVNET-001
/// format proven in the simulation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsefulWorkReceipt {
    pub receipt_id: String,
    pub work_type: WorkType,
    /// The Grand Challenge ID this work is credited to.
    pub challenge_id: String,
    pub machine_id: MachineId,
    /// SHA-256 hash of the challenge input / parameters (hex).
    pub input_hash: String,
    /// SHA-256 hash of the output / discovery (hex).
    pub output_hash: String,
    /// IPFS CID or on-chain ref to the methodology / algorithm description.
    pub methodology_ref: String,
    /// Domain-specific nonce or proof parameter.
    pub nonce: u64,
    /// Number of candidate checks / iterations performed.
    pub checks_performed: u64,
    pub elapsed_seconds: f64,
    pub timestamp_utc: String,
    /// Machine's Ed25519 signature over the receipt fields (base64).
    pub machine_signature: String,
    /// True once an independent verifier has validated the result.
    pub verified: bool,
    pub verifier_id: Option<String>,
    /// Verifier's Ed25519 signature (base64).
    pub verifier_signature: Option<String>,
}
