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

    /// Returns true if the job has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, JobState::Settled | JobState::Refunded)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::capability::{
        ComputeClass, MemoryTier, PriceModel, ResourceCapabilityDescriptor, StorageTier,
    };

    fn test_spec() -> JobSpec {
        JobSpec {
            description: "unit test job".into(),
            workload_ref: "ipfs://Qm000".into(),
            requirements: ResourceCapabilityDescriptor {
                compute_class:  ComputeClass::Cpu,
                compute_units:  4,
                memory_tier:    MemoryTier::Small,
                storage_tier:   StorageTier::Ssd,
                isa_tags:       vec![],
                price_model:    PriceModel::PerJob { qrc_flat: 1_000 },
                daemon_version: "0.1.0".into(),
                extra:          Default::default(),
            },
            timeout_seconds: 300,
            max_qrc_budget:  5_000,
        }
    }

    fn make_job() -> ResourceJob {
        ResourceJob::new(
            JobId("job-001".into()),
            AgentId("agent-alice".into()),
            test_spec(),
            "2026-10-09T00:00:00Z",
        )
    }

    // ── Happy path: Created → Funded → Matched → Running → Completed → Verified → Settled

    #[test]
    fn happy_path_success() {
        let mut job = make_job();
        assert_eq!(job.state, JobState::Created);
        assert!(!job.is_terminal());

        job.transition(JobState::Funded,    "t1", None).unwrap();
        job.transition(JobState::Matched,   "t2", None).unwrap();
        job.transition(JobState::Running,   "t3", None).unwrap();
        job.transition(JobState::Completed, "t4", None).unwrap();
        job.transition(JobState::Verified,  "t5", None).unwrap();
        job.transition(JobState::Settled,   "t6", None).unwrap();

        assert_eq!(job.state, JobState::Settled);
        assert!(job.is_terminal());
        assert_eq!(job.history.len(), 6);
    }

    // ── Failure path: Created → Funded → Matched → Running → Failed → Refunded

    #[test]
    fn failure_path_refund() {
        let mut job = make_job();
        job.transition(JobState::Funded,   "t1", None).unwrap();
        job.transition(JobState::Matched,  "t2", None).unwrap();
        job.transition(JobState::Running,  "t3", None).unwrap();
        job.transition(JobState::Failed,   "t4", Some("machine timed out".into())).unwrap();
        job.transition(JobState::Refunded, "t5", None).unwrap();

        assert_eq!(job.state, JobState::Refunded);
        assert!(job.is_terminal());
        assert_eq!(job.history[3].note.as_deref(), Some("machine timed out"));
    }

    // ── Dispute path: Running → Disputed → Resolution → Settled

    #[test]
    fn dispute_path_settled() {
        let mut job = make_job();
        job.transition(JobState::Funded,     "t1", None).unwrap();
        job.transition(JobState::Matched,    "t2", None).unwrap();
        job.transition(JobState::Running,    "t3", None).unwrap();
        job.transition(JobState::Disputed,   "t4", Some("requester claims no output".into())).unwrap();
        job.transition(JobState::Resolution, "t5", None).unwrap();
        job.transition(JobState::Settled,    "t6", None).unwrap();

        assert_eq!(job.state, JobState::Settled);
        assert!(job.is_terminal());
    }

    // ── Dispute path: Funded → Disputed → Resolution → Refunded

    #[test]
    fn dispute_from_funded_refund() {
        let mut job = make_job();
        job.transition(JobState::Funded,     "t1", None).unwrap();
        job.transition(JobState::Disputed,   "t2", Some("no machine assigned".into())).unwrap();
        job.transition(JobState::Resolution, "t3", None).unwrap();
        job.transition(JobState::Refunded,   "t4", None).unwrap();

        assert_eq!(job.state, JobState::Refunded);
        assert!(job.is_terminal());
    }

    // ── Invalid transitions must be rejected ──────────────────────────────────

    #[test]
    fn reject_created_to_running() {
        let mut job = make_job();
        let err = job.transition(JobState::Running, "t1", None).unwrap_err();
        assert!(matches!(err, crate::error::ResourceError::InvalidTransition { .. }));
        assert_eq!(job.state, JobState::Created); // state unchanged
        assert_eq!(job.history.len(), 0);         // no history entry
    }

    #[test]
    fn reject_settled_to_any() {
        let mut job = make_job();
        for s in [JobState::Funded, JobState::Matched, JobState::Running,
                   JobState::Completed, JobState::Verified] {
            job.transition(s, "tx", None).unwrap_or_default();
        }
        job.transition(JobState::Settled, "tx", None).unwrap_or_default();
        assert_eq!(job.state, JobState::Settled);

        // From terminal Settled, no further transitions are allowed.
        for next in [JobState::Funded, JobState::Disputed, JobState::Refunded,
                      JobState::Created] {
            let err = job.transition(next, "tx", None).unwrap_err();
            assert!(matches!(err, crate::error::ResourceError::InvalidTransition { .. }));
        }
        assert_eq!(job.state, JobState::Settled); // still terminal
    }

    #[test]
    fn reject_skip_funded_to_completed() {
        let mut job = make_job();
        job.transition(JobState::Funded,  "t1", None).unwrap();
        job.transition(JobState::Matched, "t2", None).unwrap();
        // Skip Running → directly to Completed is illegal
        let err = job.transition(JobState::Completed, "t3", None).unwrap_err();
        assert!(matches!(err, crate::error::ResourceError::InvalidTransition { .. }));
        assert_eq!(job.state, JobState::Matched);
    }

    // ── History audit trail ───────────────────────────────────────────────────

    #[test]
    fn history_records_from_and_to() {
        let mut job = make_job();
        job.transition(JobState::Funded, "2026-10-09T00:01:00Z", Some("funded".into())).unwrap();
        assert_eq!(job.history[0].from, JobState::Created);
        assert_eq!(job.history[0].to,   JobState::Funded);
        assert_eq!(job.history[0].timestamp_utc, "2026-10-09T00:01:00Z");
        assert_eq!(job.history[0].note.as_deref(), Some("funded"));
    }

    // ── is_terminal covers all terminal states ────────────────────────────────

    #[test]
    fn is_terminal_only_settled_and_refunded() {
        use JobState::*;
        let non_terminal = [Created, Funded, Matched, Running, Completed,
                             Failed, Verified, Disputed, Resolution];
        let terminal     = [Settled, Refunded];

        for s in non_terminal {
            let mut job = make_job();
            job.state = s;
            assert!(!job.is_terminal(), "{s:?} should not be terminal");
        }
        for s in terminal {
            let mut job = make_job();
            job.state = s;
            assert!(job.is_terminal(), "{s:?} should be terminal");
        }
    }
}
