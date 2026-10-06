//! QRC escrow transaction types.
//!
//! Three escrow operations cover the full job lifecycle:
//!
//! | Operation | When | Effect |
//! |-----------|------|--------|
//! | `LockQrcForJob`    | Job moves to `Funded`    | QRC leaves agent wallet, held by chain |
//! | `ReleaseQrcForJob` | Job moves to `Settled`   | QRC sent to provider                   |
//! | `RefundQrcForJob`  | Job moves to `Refunded`  | QRC returned to agent                  |

use serde::{Deserialize, Serialize};

use super::job::JobId;
use super::machine::MachineId;

/// Lock QRC in escrow when an agent funds a job.
///
/// Emitted by the agent's chain-forge-agents layer; processed by
/// chain-forge-qrc.  The amount is the *maximum* the agent will pay
/// (`max_qrc_budget` from the `JobSpec`); actual charge may be lower if
/// billed by the second.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockQrcForJob {
    /// Unique identifier for this escrow operation.
    pub escrow_id: String,
    pub job_id: JobId,
    /// Wallet address of the requesting agent.
    pub agent_wallet: String,
    /// QRC amount to lock (atomic units).
    pub amount: u64,
    pub timestamp_utc: String,
    /// Agent's Ed25519 signature (base64).
    pub agent_signature: String,
}

/// Release escrowed QRC to the provider on successful, verified completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseQrcForJob {
    pub escrow_id: String,
    pub job_id: JobId,
    pub machine_id: MachineId,
    /// Provider's wallet address (derived from the machine record).
    pub provider_wallet: String,
    /// Actual QRC earned (≤ locked amount).
    pub amount: u64,
    /// SHA-256 of the `UsefulWorkReceipt` / `ResourceExecutionReceipt` that
    /// authorises this release.
    pub receipt_hash: String,
    pub timestamp_utc: String,
    /// Chain validator's collective signature authorising the release.
    pub validator_signature: String,
}

/// Return escrowed QRC to the agent when a job fails or is refunded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundQrcForJob {
    pub escrow_id: String,
    pub job_id: JobId,
    /// Wallet address of the requesting agent.
    pub agent_wallet: String,
    /// Full locked amount returned.
    pub amount: u64,
    /// Reason code for the refund.
    pub reason: RefundReason,
    pub timestamp_utc: String,
    pub validator_signature: String,
}

/// Why a refund was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefundReason {
    /// Machine failed to produce output within the deadline.
    Timeout,
    /// Machine reported an execution error.
    ExecutionFailure,
    /// Verifier rejected the output as incorrect.
    VerificationFailed,
    /// Dispute resolved in favour of the agent.
    DisputeResolution,
    /// Job was cancelled before it started.
    CancelledBeforeStart,
}
