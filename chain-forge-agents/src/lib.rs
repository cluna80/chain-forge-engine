/// chain-forge-agents
///
/// Charmed Agents: native first-class autonomous agent representation on QCB.
///
/// Implements Whitepaper Section 5.3 and the AEI specification from Section 4.6:
///
///   - AgentCapability: what a Charmed Agent is authorized to do
///   - SpendingLimits: per-epoch and lifetime $QRC spending caps
///   - AgentRecord: full on-chain identity for one agent (the AEI)
///   - AgentStore: canonical registry of all Charmed Agents
///   - Full lifecycle: register → authorize → (suspend) → revoke
///   - SponsorID: every agent is cryptographically linked to a verified human
///   - Sponsored Contracts are a subclass (Section 7.2 / Phase 5+)
///
/// The scope note from Section 5.3 applies here too: Phase 0 Charmed Agents
/// cover scheduled, rule-bound operational roles -- merchant settlement and
/// UBI distribution -- not open-ended autonomous behavior. The data structures
/// are designed for the broader AEI vision; the enforcement in Phase 0 is
/// the lifecycle and spending-limit layer only.
///
/// Whitepaper refs: Sections 4.6 (Phase B strategy), 5.0, 5.3, 7.2, Q23.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("agent {0} not found")]
    NotFound(String),

    #[error("agent {0} already exists")]
    AlreadyExists(String),

    #[error("agent {0} is not active (status: {1:?})")]
    NotActive(String, AgentStatus),

    #[error("sponsor {0} is not a verified human")]
    SponsorNotVerified(String),

    #[error("capability {0:?} not in agent {1}'s authorized set")]
    CapabilityNotAuthorized(AgentCapability, String),

    #[error("spending limit exceeded: epoch spend {epoch_spend} + {amount} > epoch limit {epoch_limit}")]
    EpochLimitExceeded { epoch_spend: u128, amount: u128, epoch_limit: u128 },

    #[error("lifetime spending limit exceeded: lifetime spend {lifetime_spend} + {amount} > limit {lifetime_limit}")]
    LifetimeLimitExceeded { lifetime_spend: u128, amount: u128, lifetime_limit: u128 },

    #[error("parent agent {0} not found or not active")]
    ParentNotActive(String),

    #[error("agent {0} is a Sponsored Contract -- use the EVM layer")]
    IsSponsoredContract(String),

    #[error("internal agent error: {0}")]
    Internal(String),
}

pub type AgentResult<T> = Result<T, AgentError>;

// -- AgentCapability ----------------------------------------------------------

/// What a Charmed Agent is authorized to do (Section 5.3).
/// This is the CapabilitySet from the AEI specification (Section 4.6 Phase B).
///
/// Phase 0: MerchantSettlement and UbiDistribution are the operational roles
/// described in Section 5.3's scope note. The others are framework for Phase 1+.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentCapability {
    /// Accept $QRC payments on behalf of a merchant and trigger fiat settlement.
    MerchantSettlement,
    /// Claim and distribute $QRC UBI to verified humans.
    UbiDistribution,
    /// Hold $QRC balance up to the agent's spending limit.
    HoldBalance,
    /// Transfer $QRC to other verified accounts (not agents, unless authorized).
    Transfer,
    /// Interact with a Sponsored Contract (Section 7.2, Phase 5+).
    SponsoredContractCall,
    /// Spawn a child agent (sub-agent delegation, bounded by parent's limits).
    SpawnChildAgent,
    /// Read on-chain state (read-only, no balance changes).
    ReadState,
    /// Execute RWA settlement transactions (Section 8.2, Phase 5+).
    RwaSettlement,
}

impl AgentCapability {
    /// Whether this capability requires the permissioned EVM (Phase 5+).
    pub fn requires_evm(&self) -> bool {
        matches!(self, Self::SponsoredContractCall | Self::RwaSettlement)
    }

    /// Whether this capability is available in Phase 0.
    pub fn is_phase0(&self) -> bool {
        matches!(
            self,
            Self::MerchantSettlement | Self::UbiDistribution
            | Self::HoldBalance | Self::Transfer | Self::ReadState
        )
    }
}

impl std::fmt::Display for AgentCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MerchantSettlement    => write!(f, "MerchantSettlement"),
            Self::UbiDistribution       => write!(f, "UbiDistribution"),
            Self::HoldBalance           => write!(f, "HoldBalance"),
            Self::Transfer              => write!(f, "Transfer"),
            Self::SponsoredContractCall => write!(f, "SponsoredContractCall"),
            Self::SpawnChildAgent       => write!(f, "SpawnChildAgent"),
            Self::ReadState             => write!(f, "ReadState"),
            Self::RwaSettlement         => write!(f, "RwaSettlement"),
        }
    }
}

// -- SpendingLimits -----------------------------------------------------------

/// Per-epoch and lifetime $QRC spending caps for a Charmed Agent.
/// This is the SpendingLimits field from the AEI specification (Section 4.6).
///
/// Phase 0: enforced in AgentStore::record_spend().
/// The human sponsor sets these at registration time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingLimits {
    /// Maximum uqrc this agent may spend in one epoch (daily cap).
    /// 0 means no limit.
    pub epoch_limit_uqrc: u128,
    /// Maximum uqrc this agent may spend across its lifetime.
    /// 0 means no limit.
    pub lifetime_limit_uqrc: u128,
    /// Maximum uqrc this agent may hold at any one time.
    /// 0 means no limit.
    pub max_balance_uqrc: u128,
}

impl SpendingLimits {
    /// No spending limits (trusted agent).
    pub fn unlimited() -> Self {
        Self {
            epoch_limit_uqrc:    0,
            lifetime_limit_uqrc: 0,
            max_balance_uqrc:    0,
        }
    }

    /// Merchant agent: high throughput, no lifetime cap.
    pub fn merchant(epoch_limit_uqrc: u128) -> Self {
        Self {
            epoch_limit_uqrc,
            lifetime_limit_uqrc: 0,
            max_balance_uqrc:    epoch_limit_uqrc * 2,
        }
    }

    /// UBI distributor: bounded by daily issuance.
    pub fn ubi_distributor(daily_issuance_uqrc: u128, population: u64) -> Self {
        let epoch = daily_issuance_uqrc * population as u128;
        Self {
            epoch_limit_uqrc:    epoch,
            lifetime_limit_uqrc: 0,
            max_balance_uqrc:    epoch,
        }
    }

    /// Check if a spend of `amount` would exceed limits given current state.
    pub fn check_epoch(&self, epoch_spend: u128, amount: u128) -> AgentResult<()> {
        if self.epoch_limit_uqrc > 0 && epoch_spend + amount > self.epoch_limit_uqrc {
            return Err(AgentError::EpochLimitExceeded {
                epoch_spend, amount, epoch_limit: self.epoch_limit_uqrc,
            });
        }
        Ok(())
    }

    pub fn check_lifetime(&self, lifetime_spend: u128, amount: u128) -> AgentResult<()> {
        if self.lifetime_limit_uqrc > 0
            && lifetime_spend + amount > self.lifetime_limit_uqrc
        {
            return Err(AgentError::LifetimeLimitExceeded {
                lifetime_spend, amount, lifetime_limit: self.lifetime_limit_uqrc,
            });
        }
        Ok(())
    }
}

// -- AgentStatus --------------------------------------------------------------

/// Lifecycle status of a Charmed Agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    /// Registered but not yet authorized. Cannot act.
    Pending,
    /// Authorized and active. Can act within its CapabilitySet.
    Active,
    /// Temporarily suspended (sponsor's verified status lapsed, or governance).
    /// State is preserved; agent cannot act.
    Suspended,
    /// Permanently revoked. State is preserved but agent can never act again.
    Revoked,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending   => write!(f, "Pending"),
            Self::Active    => write!(f, "Active"),
            Self::Suspended => write!(f, "Suspended"),
            Self::Revoked   => write!(f, "Revoked"),
        }
    }
}

// -- AgentType ----------------------------------------------------------------

/// Whether this is a native Charmed Agent or a Sponsored Contract (Section 7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentType {
    /// A native Charmed Agent (merchant settlement, UBI distribution, etc.).
    /// Phase 0 and Phase 1.
    Native,
    /// A Sponsored Contract -- a Solidity contract deployed via the permissioned EVM.
    /// Phase 5+ only. Inherits Charm Confinement and Intrinsic Charm (Section 5.3 scope note).
    SponsoredContract { contract_address: String },
}

// -- AgentRecord (the AEI) ---------------------------------------------------

/// The full on-chain Agent Economic Identity (AEI) for one Charmed Agent.
/// This is the data structure described in Whitepaper Section 4.6 Phase B.
///
/// AEI fields: SponsorID, CapabilitySet, SpendingLimits, ParentAgentID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    /// Unique identifier for this agent on-chain.
    pub agent_id: String,
    /// The account address this agent controls.
    pub address: String,
    /// AEI field 1: SponsorID -- the verified human accountable for this agent.
    pub sponsor_id: String,
    /// AEI field 2: CapabilitySet -- what this agent is authorized to do.
    pub capabilities: Vec<AgentCapability>,
    /// AEI field 3: SpendingLimits -- $QRC caps per epoch and lifetime.
    pub spending_limits: SpendingLimits,
    /// AEI field 4: ParentAgentID -- if this is a sub-agent, its parent's ID.
    pub parent_agent_id: Option<String>,
    /// Human-readable description of this agent's role.
    pub description: String,
    /// Agent type: native or Sponsored Contract.
    pub agent_type: AgentType,
    /// Current lifecycle status.
    pub status: AgentStatus,
    /// Epoch in which this agent was registered.
    pub registered_epoch: u64,
    /// Epoch of the most recent authorization or status change.
    pub last_status_epoch: u64,
    /// Total uqrc spent this epoch (reset each epoch advance).
    pub epoch_spend_uqrc: u128,
    /// Total uqrc spent across the agent's lifetime.
    pub lifetime_spend_uqrc: u128,
    /// Total transactions executed.
    pub tx_count: u64,
}

impl AgentRecord {
    pub fn new(
        agent_id:       String,
        address:        String,
        sponsor_id:     String,
        capabilities:   Vec<AgentCapability>,
        spending_limits: SpendingLimits,
        parent_agent_id: Option<String>,
        description:    String,
        agent_type:     AgentType,
        epoch:          u64,
    ) -> Self {
        Self {
            agent_id,
            address,
            sponsor_id,
            capabilities,
            spending_limits,
            parent_agent_id,
            description,
            agent_type,
            status:               AgentStatus::Pending,
            registered_epoch:     epoch,
            last_status_epoch:    epoch,
            epoch_spend_uqrc:   0,
            lifetime_spend_uqrc: 0,
            tx_count:             0,
        }
    }

    pub fn is_active(&self) -> bool {
        self.status == AgentStatus::Active
    }

    /// Whether this agent has a given capability.
    pub fn has_capability(&self, cap: &AgentCapability) -> bool {
        self.capabilities.contains(cap)
    }

    /// Authorize (activate) this agent.
    pub fn authorize(&mut self, epoch: u64) {
        self.status = AgentStatus::Active;
        self.last_status_epoch = epoch;
        tracing::info!(
            agent = %self.agent_id,
            sponsor = %self.sponsor_id,
            "agent authorized"
        );
    }

    /// Suspend this agent (sponsor lapsed, governance action, etc.).
    /// State is preserved; agent cannot act. See Q23(b).
    pub fn suspend(&mut self, epoch: u64) {
        self.status = AgentStatus::Suspended;
        self.last_status_epoch = epoch;
        tracing::warn!(agent = %self.agent_id, "agent suspended");
    }

    /// Revoke this agent permanently.
    pub fn revoke(&mut self, epoch: u64) {
        self.status = AgentStatus::Revoked;
        self.last_status_epoch = epoch;
        tracing::warn!(agent = %self.agent_id, "agent revoked");
    }

    /// Record a spend and validate it against limits.
    pub fn record_spend(&mut self, amount: u128) -> AgentResult<()> {
        self.spending_limits.check_epoch(self.epoch_spend_uqrc, amount)?;
        self.spending_limits.check_lifetime(self.lifetime_spend_uqrc, amount)?;
        self.epoch_spend_uqrc   += amount;
        self.lifetime_spend_uqrc += amount;
        self.tx_count              += 1;
        Ok(())
    }

    /// Reset epoch spend counter (called on each epoch advance).
    pub fn reset_epoch_spend(&mut self) {
        self.epoch_spend_uqrc = 0;
    }
}

// -- AgentStore ---------------------------------------------------------------

/// Canonical registry of all Charmed Agents on QCB.
///
/// This is what Section 5.3's "native first-class representation" means
/// concretely: agents are not smart contracts or EOAs, they are entries
/// in this registry with enforced lifecycle and spending constraints.
pub struct AgentStore {
    agents: HashMap<String, AgentRecord>,
    /// Index: address -> agent_id for fast lookup.
    by_address: HashMap<String, String>,
    /// Index: sponsor_id -> list of agent_ids for sponsor lookup.
    by_sponsor: HashMap<String, Vec<String>>,
}

impl AgentStore {
    pub fn new() -> Self {
        Self {
            agents:     HashMap::new(),
            by_address: HashMap::new(),
            by_sponsor: HashMap::new(),
        }
    }

    // -- Registration ---------------------------------------------------------

    /// Register a new Charmed Agent (status: Pending).
    /// The sponsor must be verified -- checked by caller (IdentityStore).
    pub fn register(
        &mut self,
        agent_id:        String,
        address:         String,
        sponsor_id:      String,
        capabilities:    Vec<AgentCapability>,
        spending_limits: SpendingLimits,
        parent_agent_id: Option<String>,
        description:     String,
        agent_type:      AgentType,
        epoch:           u64,
    ) -> AgentResult<()> {
        if self.agents.contains_key(&agent_id) {
            return Err(AgentError::AlreadyExists(agent_id));
        }

        // Validate parent agent exists and is active if specified
        if let Some(parent) = &parent_agent_id {
            let parent_rec = self.agents.get(parent)
                .ok_or_else(|| AgentError::ParentNotActive(parent.clone()))?;
            if !parent_rec.is_active() {
                return Err(AgentError::ParentNotActive(parent.clone()));
            }
        }

        let record = AgentRecord::new(
            agent_id.clone(), address.clone(), sponsor_id.clone(),
            capabilities, spending_limits, parent_agent_id,
            description, agent_type, epoch,
        );

        self.by_address.insert(address, agent_id.clone());
        self.by_sponsor
            .entry(sponsor_id)
            .or_default()
            .push(agent_id.clone());
        self.agents.insert(agent_id, record);
        Ok(())
    }

    /// Authorize a Pending agent (transition to Active).
    pub fn authorize(&mut self, agent_id: &str, epoch: u64) -> AgentResult<()> {
        let record = self.agents.get_mut(agent_id)
            .ok_or_else(|| AgentError::NotFound(agent_id.to_string()))?;
        if record.status != AgentStatus::Pending && record.status != AgentStatus::Suspended {
            return Err(AgentError::NotActive(agent_id.to_string(), record.status.clone()));
        }
        record.authorize(epoch);
        Ok(())
    }

    /// Suspend an active agent. State preserved, cannot act. See Q23(b).
    pub fn suspend(&mut self, agent_id: &str, epoch: u64) -> AgentResult<()> {
        let record = self.agents.get_mut(agent_id)
            .ok_or_else(|| AgentError::NotFound(agent_id.to_string()))?;
        record.suspend(epoch);
        Ok(())
    }

    /// Revoke an agent permanently.
    pub fn revoke(&mut self, agent_id: &str, epoch: u64) -> AgentResult<()> {
        let record = self.agents.get_mut(agent_id)
            .ok_or_else(|| AgentError::NotFound(agent_id.to_string()))?;
        record.revoke(epoch);
        Ok(())
    }

    /// Suspend all agents of a sponsor (called when sponsor's identity lapses -- Q23(b)).
    /// Conservative default: freeze, not destroy. State preserved.
    pub fn suspend_sponsor_agents(&mut self, sponsor_id: &str, epoch: u64) {
        let agent_ids: Vec<String> = self.by_sponsor
            .get(sponsor_id)
            .cloned()
            .unwrap_or_default();

        for id in agent_ids {
            if let Some(record) = self.agents.get_mut(&id) {
                if record.status == AgentStatus::Active {
                    record.suspend(epoch);
                    tracing::warn!(
                        agent    = %id,
                        sponsor  = sponsor_id,
                        "agent suspended: sponsor identity lapsed"
                    );
                }
            }
        }
    }

    // -- Capability and spend enforcement -------------------------------------

    /// Check that an agent is active and has a given capability.
    pub fn check_capability(
        &self,
        agent_id: &str,
        cap: &AgentCapability,
    ) -> AgentResult<()> {
        let record = self.agents.get(agent_id)
            .ok_or_else(|| AgentError::NotFound(agent_id.to_string()))?;

        if !record.is_active() {
            return Err(AgentError::NotActive(agent_id.to_string(), record.status.clone()));
        }
        if !record.has_capability(cap) {
            return Err(AgentError::CapabilityNotAuthorized(cap.clone(), agent_id.to_string()));
        }
        Ok(())
    }

    /// Record a spend for an agent and enforce limits.
    pub fn record_spend(&mut self, agent_id: &str, amount: u128) -> AgentResult<()> {
        let record = self.agents.get_mut(agent_id)
            .ok_or_else(|| AgentError::NotFound(agent_id.to_string()))?;

        if !record.is_active() {
            return Err(AgentError::NotActive(agent_id.to_string(), record.status.clone()));
        }
        record.record_spend(amount)
    }

    /// Advance the epoch: reset all agents' epoch spend counters.
    pub fn advance_epoch(&mut self) {
        for record in self.agents.values_mut() {
            record.reset_epoch_spend();
        }
    }

    // -- Lookups --------------------------------------------------------------

    pub fn get(&self, agent_id: &str) -> AgentResult<&AgentRecord> {
        self.agents.get(agent_id)
            .ok_or_else(|| AgentError::NotFound(agent_id.to_string()))
    }

    pub fn get_by_address(&self, address: &str) -> AgentResult<&AgentRecord> {
        let id = self.by_address.get(address)
            .ok_or_else(|| AgentError::NotFound(address.to_string()))?;
        self.get(id)
    }

    pub fn agents_for_sponsor(&self, sponsor_id: &str) -> Vec<&AgentRecord> {
        self.by_sponsor.get(sponsor_id)
            .map(|ids| ids.iter()
                .filter_map(|id| self.agents.get(id))
                .collect())
            .unwrap_or_default()
    }

    pub fn active_count(&self) -> usize {
        self.agents.values()
            .filter(|r| r.status == AgentStatus::Active)
            .count()
    }

    pub fn total_registered(&self) -> usize {
        self.agents.len()
    }

    pub fn is_active(&self, agent_id: &str) -> bool {
        self.agents.get(agent_id)
            .map(|r| r.is_active())
            .unwrap_or(false)
    }
}

impl Default for AgentStore {
    fn default() -> Self { Self::new() }
}

// -- Preset agent builders ----------------------------------------------------

/// Build a standard merchant settlement agent AEI.
pub fn merchant_agent(
    agent_id:           &str,
    address:            &str,
    sponsor_id:         &str,
    epoch_limit_uqrc: u128,
    epoch:              u64,
) -> (String, String, String, Vec<AgentCapability>, SpendingLimits, Option<String>, String, AgentType) {
    (
        agent_id.to_string(),
        address.to_string(),
        sponsor_id.to_string(),
        vec![
            AgentCapability::MerchantSettlement,
            AgentCapability::HoldBalance,
            AgentCapability::Transfer,
            AgentCapability::ReadState,
        ],
        SpendingLimits::merchant(epoch_limit_uqrc),
        None,
        format!("Merchant settlement agent for sponsor {sponsor_id}"),
        AgentType::Native,
    )
}

/// Build a UBI distributor agent AEI.
pub fn ubi_distributor_agent(
    agent_id:           &str,
    address:            &str,
    sponsor_id:         &str,
    daily_issuance:     u128,
    population:         u64,
    epoch:              u64,
) -> (String, String, String, Vec<AgentCapability>, SpendingLimits, Option<String>, String, AgentType) {
    let _ = epoch;
    (
        agent_id.to_string(),
        address.to_string(),
        sponsor_id.to_string(),
        vec![
            AgentCapability::UbiDistribution,
            AgentCapability::HoldBalance,
            AgentCapability::Transfer,
            AgentCapability::ReadState,
        ],
        SpendingLimits::ubi_distributor(daily_issuance, population),
        None,
        format!("UBI distributor agent for sponsor {sponsor_id}"),
        AgentType::Native,
    )
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> AgentStore { AgentStore::new() }

    fn register_merchant(store: &mut AgentStore, id: &str, sponsor: &str, epoch: u64) {
        let (aid, addr, sid, caps, limits, parent, desc, atype) =
            merchant_agent(id, &format!("qcb1{id}"), sponsor, 10_000_000_000, epoch);
        store.register(aid, addr, sid, caps, limits, parent, desc, atype, epoch).unwrap();
    }

    // -- AgentCapability tests ------------------------------------------------

    #[test]
    fn phase0_capabilities_identified() {
        assert!(AgentCapability::MerchantSettlement.is_phase0());
        assert!(AgentCapability::UbiDistribution.is_phase0());
        assert!(!AgentCapability::SponsoredContractCall.is_phase0());
        assert!(!AgentCapability::RwaSettlement.is_phase0());
    }

    #[test]
    fn evm_capabilities_require_phase5() {
        assert!(AgentCapability::SponsoredContractCall.requires_evm());
        assert!(AgentCapability::RwaSettlement.requires_evm());
        assert!(!AgentCapability::MerchantSettlement.requires_evm());
    }

    // -- SpendingLimits tests -------------------------------------------------

    #[test]
    fn epoch_limit_enforced() {
        let limits = SpendingLimits::merchant(1_000_000);
        assert!(limits.check_epoch(0, 500_000).is_ok());
        assert!(limits.check_epoch(0, 1_000_001).is_err());
        assert!(limits.check_epoch(800_000, 300_000).is_err());
    }

    #[test]
    fn unlimited_spending_always_ok() {
        let limits = SpendingLimits::unlimited();
        assert!(limits.check_epoch(u128::MAX - 1, 1).is_ok());
        assert!(limits.check_lifetime(u128::MAX - 1, 1).is_ok());
    }

    #[test]
    fn lifetime_limit_enforced() {
        let limits = SpendingLimits {
            epoch_limit_uqrc:    0,
            lifetime_limit_uqrc: 5_000_000,
            max_balance_uqrc:    0,
        };
        assert!(limits.check_lifetime(4_999_999, 1).is_ok());
        assert!(limits.check_lifetime(5_000_000, 1).is_err());
    }

    // -- AgentRecord tests ----------------------------------------------------

    #[test]
    fn agent_starts_pending() {
        let record = AgentRecord::new(
            "agent1".into(), "qcb1agent1".into(), "sponsor1".into(),
            vec![AgentCapability::MerchantSettlement],
            SpendingLimits::unlimited(), None, "test".into(), AgentType::Native, 0,
        );
        assert_eq!(record.status, AgentStatus::Pending);
        assert!(!record.is_active());
    }

    #[test]
    fn agent_activation_lifecycle() {
        let mut record = AgentRecord::new(
            "agent1".into(), "qcb1agent1".into(), "sponsor1".into(),
            vec![AgentCapability::MerchantSettlement],
            SpendingLimits::unlimited(), None, "test".into(), AgentType::Native, 0,
        );
        record.authorize(1);
        assert!(record.is_active());

        record.suspend(2);
        assert_eq!(record.status, AgentStatus::Suspended);
        assert!(!record.is_active());

        record.authorize(3);
        assert!(record.is_active());

        record.revoke(4);
        assert_eq!(record.status, AgentStatus::Revoked);
        assert!(!record.is_active());
    }

    #[test]
    fn capability_check() {
        let record = AgentRecord::new(
            "agent1".into(), "qcb1agent1".into(), "sponsor1".into(),
            vec![AgentCapability::MerchantSettlement, AgentCapability::HoldBalance],
            SpendingLimits::unlimited(), None, "test".into(), AgentType::Native, 0,
        );
        assert!(record.has_capability(&AgentCapability::MerchantSettlement));
        assert!(record.has_capability(&AgentCapability::HoldBalance));
        assert!(!record.has_capability(&AgentCapability::UbiDistribution));
    }

    #[test]
    fn spend_tracking_and_limits() {
        let mut record = AgentRecord::new(
            "agent1".into(), "qcb1agent1".into(), "sponsor1".into(),
            vec![AgentCapability::Transfer],
            SpendingLimits::merchant(1_000_000), None, "test".into(), AgentType::Native, 0,
        );
        record.authorize(0);
        record.record_spend(500_000).unwrap();
        assert_eq!(record.epoch_spend_uqrc, 500_000);
        assert_eq!(record.lifetime_spend_uqrc, 500_000);
        assert_eq!(record.tx_count, 1);

        // Should fail: would exceed epoch limit
        assert!(record.record_spend(600_000).is_err());

        // Reset epoch and try again
        record.reset_epoch_spend();
        assert_eq!(record.epoch_spend_uqrc, 0);
        assert!(record.record_spend(600_000).is_ok());
        assert_eq!(record.lifetime_spend_uqrc, 1_100_000); // cumulative
    }

    // -- AgentStore tests -----------------------------------------------------

    #[test]
    fn register_and_activate_agent() {
        let mut store = make_store();
        register_merchant(&mut store, "merchant1", "qcb1alice", 0);
        assert_eq!(store.total_registered(), 1);
        assert_eq!(store.active_count(), 0); // still Pending

        store.authorize("merchant1", 1).unwrap();
        assert_eq!(store.active_count(), 1);
        assert!(store.is_active("merchant1"));
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        // Second registration with the same agent_id must be rejected
        let result = store.register(
            "m1".into(), "qcb1m1b".into(), "qcb1alice".into(),
            vec![], SpendingLimits::unlimited(), None, "dup".into(), AgentType::Native, 0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn capability_check_on_store() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        store.authorize("m1", 1).unwrap();

        assert!(store.check_capability("m1", &AgentCapability::MerchantSettlement).is_ok());
        assert!(store.check_capability("m1", &AgentCapability::UbiDistribution).is_err());
    }

    #[test]
    fn inactive_agent_cannot_use_capabilities() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        // Still Pending -- should fail
        assert!(store.check_capability("m1", &AgentCapability::MerchantSettlement).is_err());
    }

    #[test]
    fn spend_enforcement_on_store() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        store.authorize("m1", 1).unwrap();

        assert!(store.record_spend("m1", 5_000_000_000).is_ok());
        assert!(store.record_spend("m1", 5_000_000_001).is_err()); // exceeds epoch limit
    }

    #[test]
    fn epoch_advance_resets_spend() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        store.authorize("m1", 1).unwrap();

        store.record_spend("m1", 10_000_000_000).unwrap(); // hit epoch limit
        assert!(store.record_spend("m1", 1).is_err());

        store.advance_epoch();
        assert!(store.record_spend("m1", 1).is_ok()); // reset
    }

    #[test]
    fn sponsor_suspension_cascades_to_agents() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        register_merchant(&mut store, "m2", "qcb1alice", 0);
        store.authorize("m1", 1).unwrap();
        store.authorize("m2", 1).unwrap();
        assert_eq!(store.active_count(), 2);

        // Sponsor lapses -- all their agents should suspend (Q23(b) conservative default)
        store.suspend_sponsor_agents("qcb1alice", 2);
        assert_eq!(store.active_count(), 0);
        assert_eq!(store.get("m1").unwrap().status, AgentStatus::Suspended);
        assert_eq!(store.get("m2").unwrap().status, AgentStatus::Suspended);
    }

    #[test]
    fn suspended_agent_can_be_reactivated() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        store.authorize("m1", 1).unwrap();
        store.suspend("m1", 2).unwrap();
        assert!(!store.is_active("m1"));

        // Re-authorize (sponsor re-verified)
        store.authorize("m1", 3).unwrap();
        assert!(store.is_active("m1"));
    }

    #[test]
    fn lookup_by_address() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        let record = store.get_by_address("qcb1m1").unwrap();
        assert_eq!(record.agent_id, "m1");
        assert_eq!(record.sponsor_id, "qcb1alice");
    }

    #[test]
    fn agents_for_sponsor_lists_all() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        register_merchant(&mut store, "m2", "qcb1alice", 0);
        register_merchant(&mut store, "m3", "qcb1bob",   0);

        let alice_agents = store.agents_for_sponsor("qcb1alice");
        assert_eq!(alice_agents.len(), 2);

        let bob_agents = store.agents_for_sponsor("qcb1bob");
        assert_eq!(bob_agents.len(), 1);
    }

    #[test]
    fn child_agent_requires_active_parent() {
        let mut store = make_store();
        register_merchant(&mut store, "parent", "qcb1alice", 0);
        // Parent is Pending -- child registration should fail
        let result = store.register(
            "child".into(), "qcb1child".into(), "qcb1alice".into(),
            vec![AgentCapability::ReadState],
            SpendingLimits::unlimited(),
            Some("parent".into()),
            "child agent".into(),
            AgentType::Native,
            0,
        );
        assert!(result.is_err(), "parent must be Active for child to register");
    }

    #[test]
    fn child_agent_registers_with_active_parent() {
        let mut store = make_store();
        register_merchant(&mut store, "parent", "qcb1alice", 0);
        store.authorize("parent", 1).unwrap();

        let result = store.register(
            "child".into(), "qcb1child".into(), "qcb1alice".into(),
            vec![AgentCapability::ReadState],
            SpendingLimits::unlimited(),
            Some("parent".into()),
            "child agent".into(),
            AgentType::Native,
            1,
        );
        assert!(result.is_ok());
        assert_eq!(store.total_registered(), 2);
    }

    #[test]
    fn revoked_agent_cannot_be_reactivated() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        store.authorize("m1", 1).unwrap();
        store.revoke("m1", 2).unwrap();

        // Revoked agents cannot be authorized again
        let result = store.authorize("m1", 3);
        assert!(result.is_err(), "revoked agent cannot be reauthorized");
    }

    #[test]
    fn ubi_distributor_limits_match_population() {
        use chain_forge_identity::DAILY_UBI_RATE_UQRC;
        let (_, _, _, _, limits, _, _, _) =
            ubi_distributor_agent("ubi1", "qcb1ubi", "qcb1alice",
                DAILY_UBI_RATE_UQRC, 1000, 0);

        let expected_epoch = DAILY_UBI_RATE_UQRC * 1000;
        assert_eq!(limits.epoch_limit_uqrc, expected_epoch);
    }

    #[test]
    fn merchant_agent_has_correct_capabilities() {
        let mut store = make_store();
        register_merchant(&mut store, "m1", "qcb1alice", 0);
        store.authorize("m1", 1).unwrap();

        assert!(store.check_capability("m1", &AgentCapability::MerchantSettlement).is_ok());
        assert!(store.check_capability("m1", &AgentCapability::HoldBalance).is_ok());
        assert!(store.check_capability("m1", &AgentCapability::Transfer).is_ok());
        assert!(store.check_capability("m1", &AgentCapability::UbiDistribution).is_err());
    }
}
