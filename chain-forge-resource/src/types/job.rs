//! Resource job lifecycle.
//!
//! State machine:
//!
//! ```text
//!   CREATED
//!      │
//!   FUNDED  (QRC locked in escrow)
//!      │
//!   MATCHED (machine assigned)
//!      │
//!   RUNNING
//!      │
//!   ┌──┴──┐
//! COMPLETED  FAILED
//!      │        │
//!   VERIFIED  REFUND
//!      │        │
//!   SETTLED  SETTLED
//!
//! Any state → DISPUTED → RESOLUTION → SETTLED / REFUND
//! ```

use serde::{Deserialize, Serialize};

use super::machine::MachineId;
use super::capability::ResourceCapabilityDescriptor;

/// Opaque job identifier (UUID or hash on real chain).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub String);

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifier of the agent (buyer) that created the job.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

/// All possible states in the job lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    /// Job has been submitted but no QRC locked yet.
    Created,
    /// Requesting agent has locked QRC in escrow.
    Funded,
    /// A machine has been matched; work has not started.
    Matched,
    /// Machine is executing the job.
    Running,
    /// Machine reports successful completion.
    Completed,
    /// Machine reports failure (hardware fault, timeout, etc.).
    Failed,
    /// An independent verifier has signed off on the output.
    Verified,
    /// A participant has raised a dispute.
    Disputed,
    /// Governance / arbitration has resolved the dispute.
    Resolution,
    /// QRC has been released to the provider (success path).
    Settled,
    /// QRC has been returned to the agent (failure / dispute path).
    Refunded,
}

/// What the buyer wants the machine to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    /// Human-readable description of the task.
    pub description: String,
    /// IPFS CID or on-chain reference to the workload bundle.
    pub workload_ref: String,
    /// Minimum resource requirements (used for matchmaking).
    pub requirements: ResourceCapabilityDescriptor,
    /// Wall-clock deadline in seconds from job start.
    pub timeout_seconds: u64,
    /// Maximum QRC the agent is willing to pay.
    pub max_qrc_budget: u64,
}

/// A single transition recorded on the job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from: JobState,
    pub to: JobState,
    pub timestamp_utc: String,
    pub note: Option<String>,
}

/// Full job record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceJob {
    pub job_id: JobId,
    pub requester: AgentId,
    pub spec: JobSpec,
    pub state: JobState,
    /// Set when a machine is matched.
    pub assigned_machine: Option<MachineId>,
    /// QRC locked in escrow (set when state moves to `Funded`).
    pub escrowed_qrc: u64,
    /// Audit trail of every state transition.
    pub history: Vec<StateTransition>,
    pub created_at: String,
    pub updated_at: String,
}

impl ResourceJob {
    /// Create a new job in the `Created` state.
    pub fn new(job_id: JobId, requester: AgentId, spec: JobSpec, now: &str) -> Self {
        Self {
            job_id,
            requester,
            spec,
            state: JobState::Created,
            assigned_machine: None,
            escrowed_qrc: 0,
            history: vec![],
            created_at: now.to_owned(),
            updated_at: now.to_owned(),
        }
    }

    /// Attempt a state transition, appending to the history.
    /// Returns `Err` if the transition is not permitted.
    pub fn transition(
        &mut self,
        to: JobState,
        now: &str,
        note: Option<String>,
    ) -> Result<(), crate::error::ResourceError> {
        use JobState::*;
        let allowed = matches!(
            (&self.state, &to),
            (Created,   Funded)     |
            (Funded,    Matched)    |
            (Matched,   Running)    |
            (Running,   Completed)  |
            (Running,   Failed)     |
            (Completed, Verified)   |
            (Verified,  Settled)    |
            (Failed,    Refunded)   |
            // Dispute can be raised from most active states
            (Funded,    Disputed)   |
            (Matched,   Disputed)   |
            (Running,   Disputed)   |
            (Completed, Disputed)   |
            (Disputed,  Resolution) |
            (Resolution,Settled)    |
            (Resolution,Refunded)
        );
        if !allowed {
            return Err(crate::error::ResourceError::InvalidTransition {
                from: self.state,
                to,
            });
        }
        self.history.push(StateTransition {
            from: self.state,
            to,
            timestamp_utc: now.to_owned(),
            note,
        });
        self.state = to;
        self.updated_at = now.to_owned();
        Ok(())
    }
}
