//! Resource matchmaking — the bridge between an agent's compute request and
//! the resource market.
//!
//! ## Flow
//!
//! ```text
//!  Agent (Alice)               Marketplace             Machine (Carol)
//!       │                          │                        │
//!       │── AgentResourceRequest ──▶│                        │
//!       │                          │── find_best_match() ──▶│
//!       │                          │◀─ MachineRecord ───────│
//!       │◀── MatchResult ──────────│                        │
//!       │                          │                        │
//!       │── initiate_escrow_lock() │                        │
//!       │   (LockQrcForJob) ───────▶ chain-forge-qrc        │
//!       │                          │                        │
//!       │── confirm_match() ───────▶ job: Funded → Matched  │
//!       │                          │── notify_machine() ───▶│
//!       │                          │                        │── Running
//! ```
//!
//! Phase 0 scope: matchmaking is single-round (no auction).  The first
//! machine whose `ResourceCapabilityDescriptor` satisfies the request's
//! minimum requirements is selected.  Multi-round auction (PriceModel::Auction)
//! is logged as Phase 1 work.

use serde::{Deserialize, Serialize};

use chain_forge_resource::{
    MachineId, MachineMode, MachineRecord, MachineStatus,
    ResourceCapabilityDescriptor,
    LockQrcForJob,
    JobId, AgentId, JobSpec, JobState, ResourceJob,
};

use crate::{AgentCapability, AgentError, AgentStore};

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum MatchError {
    #[error("agent error: {0}")]
    Agent(#[from] AgentError),

    #[error("no machine available that satisfies the request")]
    NoMatchFound,

    #[error("machine {0} is not accepting {1} mode jobs")]
    MachineModeRejected(String, String),

    #[error("machine {0} is not active (status: {1:?})")]
    MachineNotActive(String, MachineStatus),

    #[error("requested budget {requested} is below machine's minimum price {minimum}")]
    BudgetTooLow { requested: u64, minimum: u64 },

    #[error("escrow already exists for job {0}")]
    EscrowConflict(String),

    #[error("internal matchmaking error: {0}")]
    Internal(String),
}

pub type MatchResult<T> = Result<T, MatchError>;

// ── Request ──────────────────────────────────────────────────────────────────

/// What an agent is asking the marketplace to find.
///
/// This is Alice's side of the negotiation.  It maps directly to the
/// `JobSpec` on the resource side but adds agent-layer context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResourceRequest {
    /// The agent making the request.
    pub agent_id: AgentId,
    /// The agent's wallet address (source of escrowed QRC).
    pub agent_wallet: String,
    /// The job to be run — includes `ResourceCapabilityDescriptor` requirements.
    pub job_spec: JobSpec,
    /// If set, only match this specific machine (direct-hire mode).
    pub preferred_machine: Option<MachineId>,
    /// Whether this is a marketplace job or a Grand Challenge contribution.
    pub job_kind: JobKind,
    /// Caller-supplied idempotency key — becomes the `JobId`.
    pub idempotency_key: String,
}

/// Whether the request is for marketplace compute or a Grand Challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobKind {
    Marketplace,
    GrandChallenge,
}

// ── Match outcome ────────────────────────────────────────────────────────────

/// The result of a successful match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub job_id: JobId,
    pub matched_machine: MachineId,
    /// Agreed QRC price for the job (may be lower than `max_qrc_budget`).
    pub agreed_price_qrc: u64,
    /// The `LockQrcForJob` transaction the agent must submit to the QRC layer.
    pub escrow_tx: LockQrcForJob,
    /// The `ResourceJob` record initialised in the `Funded` state ready to be
    /// forwarded to the machine and stored on-chain.
    pub resource_job: ResourceJob,
}

// ── Matchmaker ───────────────────────────────────────────────────────────────

/// In-memory registry of available machines.
///
/// Phase 0: a simple slice — first satisfactory machine wins.
/// Phase 1: replace `find_best_match` with a sealed-bid auction engine.
#[derive(Debug, Default)]
pub struct Matchmaker {
    machines: Vec<MachineRecord>,
}

impl Matchmaker {
    pub fn new() -> Self { Self::default() }

    /// Register a machine with the marketplace.
    pub fn register_machine(&mut self, machine: MachineRecord) {
        self.machines.push(machine);
    }

    /// Remove a machine from the marketplace (it went offline, was banned, etc.).
    pub fn deregister_machine(&mut self, id: &MachineId) {
        self.machines.retain(|m| &m.machine_id != id);
    }

    /// Find the best available machine for a request.
    ///
    /// Phase 0: returns the first machine whose capability descriptor satisfies
    /// the minimum requirements and whose mode allows the requested job kind.
    pub fn find_best_match(
        &self,
        req: &AgentResourceRequest,
    ) -> MatchResult<&MachineRecord> {
        // Direct-hire: skip search, just validate the named machine.
        if let Some(preferred) = &req.preferred_machine {
            return self
                .machines
                .iter()
                .find(|m| &m.machine_id == preferred)
                .ok_or_else(|| MatchError::NoMatchFound)
                .and_then(|m| self.validate_machine(m, req).map(|_| m));
        }

        // Collect the first machine that passes, or propagate the most
        // informative error from the first machine that failed validation.
        let mut last_err = MatchError::NoMatchFound;
        for machine in &self.machines {
            match self.validate_machine(machine, req) {
                Ok(()) => return Ok(machine),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    /// Check a single machine against the request.
    fn validate_machine(
        &self,
        machine: &MachineRecord,
        req: &AgentResourceRequest,
    ) -> MatchResult<()> {
        // Must be Active.
        if machine.status != MachineStatus::Active {
            return Err(MatchError::MachineNotActive(
                machine.machine_id.0.clone(),
                machine.status,
            ));
        }

        // Mode must allow the job kind.
        match (&machine.mode, &req.job_kind) {
            (MachineMode::MarketplaceOnly, JobKind::GrandChallenge) => {
                return Err(MatchError::MachineModeRejected(
                    machine.machine_id.0.clone(),
                    "GrandChallenge".into(),
                ));
            }
            (MachineMode::ContributionOnly, JobKind::Marketplace) => {
                return Err(MatchError::MachineModeRejected(
                    machine.machine_id.0.clone(),
                    "Marketplace".into(),
                ));
            }
            _ => {}
        }

        // Compute class must match.
        let req_cap = &req.job_spec.requirements;
        let mac_cap = &machine.capability_descriptor;
        if mac_cap.compute_class != req_cap.compute_class {
            return Err(MatchError::NoMatchFound);
        }

        // Compute units: machine must offer at least what's requested.
        if mac_cap.compute_units < req_cap.compute_units {
            return Err(MatchError::NoMatchFound);
        }

        // Memory tier: machine tier must be >= requested tier.
        if mac_cap.memory_tier < req_cap.memory_tier {
            return Err(MatchError::NoMatchFound);
        }

        // ISA tags: machine must support every tag the job requires.
        for tag in &req_cap.isa_tags {
            if !mac_cap.isa_tags.contains(tag) {
                return Err(MatchError::NoMatchFound);
            }
        }

        // Price: agent's budget must cover the machine's minimum price.
        let minimum_price = minimum_price_qrc(mac_cap, req.job_spec.timeout_seconds);
        if req.job_spec.max_qrc_budget < minimum_price {
            return Err(MatchError::BudgetTooLow {
                requested: req.job_spec.max_qrc_budget,
                minimum: minimum_price,
            });
        }

        Ok(())
    }

    /// Execute the full match: validate the agent, find a machine, build the
    /// `LockQrcForJob` escrow transaction, and return a `Match`.
    ///
    /// The caller is responsible for:
    /// 1. Submitting `match.escrow_tx` to the QRC layer.
    /// 2. Storing `match.resource_job` on-chain.
    /// 3. Notifying the machine of the assignment.
    pub fn execute_match(
        &self,
        req: &AgentResourceRequest,
        agent_store: &AgentStore,
        now: &str,
    ) -> MatchResult<Match> {
        // 1. Agent must be active and authorised to buy compute.
        agent_store.check_capability(&req.agent_id.0, &AgentCapability::BuyCompute)?;

        // 2. Find the machine.
        let machine = self.find_best_match(req)?;

        // 3. Compute agreed price.
        let agreed_price = minimum_price_qrc(
            &machine.capability_descriptor,
            req.job_spec.timeout_seconds,
        );

        // 4. Build the job id and resource job (starts in Created → transition to Funded).
        let job_id = JobId(req.idempotency_key.clone());
        let mut resource_job = ResourceJob::new(
            job_id.clone(),
            req.agent_id.clone(),
            req.job_spec.clone(),
            now,
        );

        // Fund the job (escrow lock happens externally, but we advance state here).
        resource_job.escrowed_qrc = agreed_price;
        resource_job
            .transition(JobState::Funded, now, Some("escrow lock initiated".into()))
            .map_err(|e| MatchError::Internal(e.to_string()))?;

        // Assign machine → Matched.
        resource_job.assigned_machine = Some(machine.machine_id.clone());
        resource_job
            .transition(
                JobState::Matched,
                now,
                Some(format!("matched to {}", machine.machine_id)),
            )
            .map_err(|e| MatchError::Internal(e.to_string()))?;

        // 5. Build the escrow transaction (submitted by agent to chain-forge-qrc).
        let escrow_tx = LockQrcForJob {
            escrow_id: format!("ESC-{}", req.idempotency_key),
            job_id: job_id.clone(),
            agent_wallet: req.agent_wallet.clone(),
            amount: agreed_price,
            timestamp_utc: now.to_owned(),
            // Placeholder: real signing happens in chain-forge-crypto / chain-forge-identity.
            agent_signature: format!("SIM-SIG-{}", req.agent_id.0),
        };

        tracing::info!(
            agent   = %req.agent_id.0,
            machine = %machine.machine_id,
            job     = %job_id,
            price   = agreed_price,
            "match confirmed"
        );

        Ok(Match {
            job_id,
            matched_machine: machine.machine_id.clone(),
            agreed_price_qrc: agreed_price,
            escrow_tx,
            resource_job,
        })
    }
}

// ── Pricing helpers ───────────────────────────────────────────────────────────

/// Compute the minimum QRC price for a machine given the job's timeout.
///
/// Phase 0: only `PerSecond` and `PerJob` models are used; `Auction` falls
/// back to `PerJob` at the flat rate of 1 QRC per compute unit per second.
fn minimum_price_qrc(cap: &ResourceCapabilityDescriptor, timeout_seconds: u64) -> u64 {
    use chain_forge_resource::PriceModel;
    match &cap.price_model {
        PriceModel::PerSecond { qrc_per_second } => qrc_per_second * timeout_seconds,
        PriceModel::PerJob { qrc_flat } => *qrc_flat,
        // Auction: fall back to a simple per-unit-per-second estimate.
        PriceModel::Auction => cap.compute_units as u64 * timeout_seconds,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_resource::{
        ComputeClass, MemoryTier, StorageTier, PriceModel,
        MachineAttestationKey, MachineMode, MachineStatus, ProviderOwner, SponsorId,
    };
    use crate::{AgentStore, AgentCapability, AgentType, SpendingLimits};

    fn carol_machine() -> MachineRecord {
        MachineRecord {
            machine_id: MachineId("MACH-CAROL-003".into()),
            owner: ProviderOwner::Individual(SponsorId("carol".into())),
            attestation_key: MachineAttestationKey {
                public_key_b64: "SIMULATED_KEY_BASE64".into(),
            },
            capability_descriptor: ResourceCapabilityDescriptor {
                compute_class: ComputeClass::Cpu,
                compute_units: 16,
                memory_tier: MemoryTier::Large,
                storage_tier: StorageTier::Nvme,
                isa_tags: vec!["AVX2".into()],
                price_model: PriceModel::PerSecond { qrc_per_second: 10 },
                daemon_version: "0.1.0".into(),
                extra: Default::default(),
            },
            mode: MachineMode::Both,
            status: MachineStatus::Active,
        }
    }

    fn alice_agent_store() -> AgentStore {
        let mut store = AgentStore::new();
        store.register(
            "AGENT-ALICE-001".into(),
            "qcb1alice".into(),
            "alice".into(),
            vec![
                AgentCapability::BuyCompute,
                AgentCapability::HoldBalance,
                AgentCapability::Transfer,
                AgentCapability::ReadState,
            ],
            SpendingLimits::merchant(1_000_000),
            None,
            "Alice's resource-buying agent".into(),
            AgentType::Native,
            0,
        ).unwrap();
        store.authorize("AGENT-ALICE-001", 1).unwrap();
        store
    }

    fn alice_request(budget: u64) -> AgentResourceRequest {
        AgentResourceRequest {
            agent_id: AgentId("AGENT-ALICE-001".into()),
            agent_wallet: "qcb1alice".into(),
            job_spec: JobSpec {
                description: "Run lattice-QCD subgraph".into(),
                workload_ref: "ipfs://QmSIMULATED".into(),
                requirements: ResourceCapabilityDescriptor {
                    compute_class: ComputeClass::Cpu,
                    compute_units: 8,
                    memory_tier: MemoryTier::Medium,
                    storage_tier: StorageTier::Nvme,
                    isa_tags: vec!["AVX2".into()],
                    price_model: PriceModel::PerSecond { qrc_per_second: 0 }, // ignored on req side
                    daemon_version: "".into(),
                    extra: Default::default(),
                },
                timeout_seconds: 60,
                max_qrc_budget: budget,
            },
            preferred_machine: None,
            job_kind: JobKind::Marketplace,
            idempotency_key: "JOB-TEST-001".into(),
        }
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[test]
    fn alice_buys_compute_from_carol() {
        let mut mm = Matchmaker::new();
        mm.register_machine(carol_machine());
        let store = alice_agent_store();

        let result = mm.execute_match(&alice_request(1_000), &store, "2026-10-06T00:00:00Z");
        assert!(result.is_ok(), "match should succeed: {:?}", result);

        let m = result.unwrap();
        assert_eq!(m.matched_machine.0, "MACH-CAROL-003");
        assert_eq!(m.agreed_price_qrc, 600); // 10 qrc/sec × 60 sec
        assert_eq!(m.resource_job.state, JobState::Matched);
        assert_eq!(m.resource_job.escrowed_qrc, 600);
        assert_eq!(m.escrow_tx.amount, 600);
    }

    // ── Mode enforcement ──────────────────────────────────────────────────────

    #[test]
    fn contribution_only_machine_rejects_marketplace_job() {
        let mut mm = Matchmaker::new();
        let mut carol = carol_machine();
        carol.mode = MachineMode::ContributionOnly;
        mm.register_machine(carol);
        let store = alice_agent_store();

        let result = mm.execute_match(&alice_request(1_000), &store, "2026-10-06T00:00:00Z");
        assert!(matches!(result, Err(MatchError::MachineModeRejected(_, _))));
    }

    #[test]
    fn marketplace_only_machine_rejects_grand_challenge() {
        let mut mm = Matchmaker::new();
        let mut carol = carol_machine();
        carol.mode = MachineMode::MarketplaceOnly;
        mm.register_machine(carol);
        let store = alice_agent_store();

        let mut req = alice_request(1_000);
        req.job_kind = JobKind::GrandChallenge;

        let result = mm.execute_match(&req, &store, "2026-10-06T00:00:00Z");
        assert!(matches!(result, Err(MatchError::MachineModeRejected(_, _))));
    }

    // ── Budget enforcement ────────────────────────────────────────────────────

    #[test]
    fn budget_too_low_rejected() {
        let mut mm = Matchmaker::new();
        mm.register_machine(carol_machine()); // 10 qrc/sec × 60 sec = 600 minimum
        let store = alice_agent_store();

        let result = mm.execute_match(&alice_request(599), &store, "2026-10-06T00:00:00Z");
        assert!(matches!(result, Err(MatchError::BudgetTooLow { .. })));
    }

    // ── Capability enforcement ────────────────────────────────────────────────

    #[test]
    fn agent_without_buy_compute_capability_rejected() {
        let mut mm = Matchmaker::new();
        mm.register_machine(carol_machine());

        // Register an agent without BuyCompute
        let mut store = AgentStore::new();
        store.register(
            "AGENT-BOB-001".into(),
            "qcb1bob".into(),
            "bob".into(),
            vec![AgentCapability::ReadState], // no BuyCompute
            SpendingLimits::unlimited(),
            None,
            "Bob's read-only agent".into(),
            AgentType::Native,
            0,
        ).unwrap();
        store.authorize("AGENT-BOB-001", 1).unwrap();

        let mut req = alice_request(1_000);
        req.agent_id = AgentId("AGENT-BOB-001".into());
        req.agent_wallet = "qcb1bob".into();

        let result = mm.execute_match(&req, &store, "2026-10-06T00:00:00Z");
        assert!(matches!(result, Err(MatchError::Agent(_))));
    }

    // ── Machine capability matching ───────────────────────────────────────────

    #[test]
    fn machine_with_wrong_compute_class_not_matched() {
        let mut mm = Matchmaker::new();
        let mut carol = carol_machine();
        carol.capability_descriptor.compute_class = ComputeClass::Gpu;
        mm.register_machine(carol);
        let store = alice_agent_store();

        // Request asks for CPU — GPU machine should not match
        let result = mm.execute_match(&alice_request(1_000), &store, "2026-10-06T00:00:00Z");
        assert!(matches!(result, Err(MatchError::NoMatchFound)));
    }

    #[test]
    fn machine_missing_isa_tag_not_matched() {
        let mut mm = Matchmaker::new();
        let mut carol = carol_machine();
        carol.capability_descriptor.isa_tags = vec![]; // no AVX2
        mm.register_machine(carol);
        let store = alice_agent_store();

        let result = mm.execute_match(&alice_request(1_000), &store, "2026-10-06T00:00:00Z");
        assert!(matches!(result, Err(MatchError::NoMatchFound)));
    }

    #[test]
    fn inactive_machine_not_matched() {
        let mut mm = Matchmaker::new();
        let mut carol = carol_machine();
        carol.status = MachineStatus::Inactive;
        mm.register_machine(carol);
        let store = alice_agent_store();

        let result = mm.execute_match(&alice_request(1_000), &store, "2026-10-06T00:00:00Z");
        // An inactive machine returns the specific MachineNotActive error so
        // the agent knows *why* there is no match (not just "nobody available").
        assert!(
            matches!(result, Err(MatchError::MachineNotActive(_, _))),
            "expected MachineNotActive, got: {:?}", result,
        );
    }

    // ── Job state machine after match ─────────────────────────────────────────

    #[test]
    fn matched_job_can_transition_to_running() {
        let mut mm = Matchmaker::new();
        mm.register_machine(carol_machine());
        let store = alice_agent_store();

        let mut m = mm.execute_match(&alice_request(1_000), &store, "2026-10-06T00:00:00Z").unwrap();
        // Simulate the machine acknowledging the job and starting work.
        m.resource_job.transition(JobState::Running, "2026-10-06T00:00:01Z", None).unwrap();
        assert_eq!(m.resource_job.state, JobState::Running);
    }

    #[test]
    fn completed_job_can_be_verified_and_settled() {
        let mut mm = Matchmaker::new();
        mm.register_machine(carol_machine());
        let store = alice_agent_store();

        let mut m = mm.execute_match(&alice_request(1_000), &store, "2026-10-06T00:00:00Z").unwrap();
        m.resource_job.transition(JobState::Running,   "T1", None).unwrap();
        m.resource_job.transition(JobState::Completed, "T2", None).unwrap();
        m.resource_job.transition(JobState::Verified,  "T3", Some("Dave verified".into())).unwrap();
        m.resource_job.transition(JobState::Settled,   "T4", None).unwrap();
        assert_eq!(m.resource_job.state, JobState::Settled);
        assert_eq!(m.resource_job.history.len(), 6); // Created→Funded→Matched→Running→Completed→Verified→Settled = 6 transitions
    }

    #[test]
    fn failed_job_is_refunded() {
        let mut mm = Matchmaker::new();
        mm.register_machine(carol_machine());
        let store = alice_agent_store();

        let mut m = mm.execute_match(&alice_request(1_000), &store, "2026-10-06T00:00:00Z").unwrap();
        m.resource_job.transition(JobState::Running,  "T1", None).unwrap();
        m.resource_job.transition(JobState::Failed,   "T2", Some("timeout".into())).unwrap();
        m.resource_job.transition(JobState::Refunded, "T3", None).unwrap();
        assert_eq!(m.resource_job.state, JobState::Refunded);
    }
}
