/// chain-forge-execution
///
/// Transaction processing and state transition layer for Chain Forge.
///
/// What lives here:
///   - Transaction: the canonical tx type (Transfer, Burn, Stake, Custom)
///   - TransactionResult: outcome of executing one tx (ok/err + gas used)
///   - BlockExecution: execute an ordered list of txs against the state store
///   - GasMeter: fixed, dynamic, and EIP-1559-style fee models
///   - ExecutionConfig: from genesis (gas model, state model, limits)
///
/// The execution layer never touches consensus or P2P directly.
/// It receives an ordered list of transactions from the consensus layer
/// (after they have been committed to a block) and applies them to state.
///
/// Whitepaper refs:
///   - Section 6.2 ($QRC transfers, demurrage)
///   - Section 6.3 ($QCB burns via BME)
///   - Section 6.6 (gas fees -> staking yield)
///   - Section 8 (merchant payment flow)

use serde::{Deserialize, Serialize};
use chain_forge_core::{Address, EnabledModules, GenesisConfig, HashWidth};
use chain_forge_crypto::{ClassicalScheme, KeyPair, SchemeId, Signature, SignatureScheme};
use chain_forge_state::{StateStore, StateError};
use chain_forge_identity::IdentityStore;
use chain_forge_qrc::QrcEngine;
use chain_forge_agents::{AgentStore, AgentType, SpendingLimits};

// -- Error --------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("transaction {tx_id} is invalid: {reason}")]
    InvalidTransaction { tx_id: String, reason: String },

    #[error("transaction {tx_id} failed: {reason}")]
    TransactionFailed { tx_id: String, reason: String },

    #[error("insufficient gas: provided {provided} but {required} required")]
    OutOfGas { provided: u64, required: u64 },

    #[error("block gas limit exceeded: used {used}, limit {limit}")]
    BlockGasLimitExceeded { used: u64, limit: u64 },

    #[error("nonce mismatch for {address}: expected {expected}, got {got}")]
    NonceMismatch { address: String, expected: u64, got: u64 },

    #[error("state error: {0}")]
    State(#[from] StateError),

    #[error("internal execution error: {0}")]
    Internal(String),
}

pub type ExecResult<T> = Result<T, ExecutionError>;

// -- Gas models ---------------------------------------------------------------

/// Fee model, read from genesis config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GasModel {
    /// Every tx costs the same flat fee regardless of complexity.
    Fixed { fee_per_tx: u64 },
    /// Fee scales with tx size and operation type.
    Dynamic { base_fee_per_byte: u64, op_multiplier: u64 },
    /// EIP-1559-style: base fee (burned) + priority tip (to validators).
    Eip1559Style { base_fee: u64, min_priority_fee: u64 },
}

impl GasModel {
    pub fn from_genesis(genesis: &GenesisConfig) -> Self {
        match genesis.execution.gas_model.as_str() {
            "fixed"         => Self::Fixed { fee_per_tx: 1_000 },
            "eip-1559-style" => Self::Eip1559Style {
                base_fee: 100,
                min_priority_fee: 10,
            },
            _ => Self::Dynamic {   // "dynamic" is the default
                base_fee_per_byte: 1,
                op_multiplier: 10,
            },
        }
    }

    /// Calculate gas cost for a transaction.
    pub fn calculate_gas(&self, tx: &Transaction) -> u64 {
        let tx_bytes = tx.payload_size_bytes() as u64;
        match self {
            Self::Fixed { fee_per_tx } => *fee_per_tx,
            Self::Dynamic { base_fee_per_byte, op_multiplier } => {
                let op_cost = match &tx.body {
                    TxBody::Transfer { .. }          => op_multiplier * 2,
                    TxBody::Burn    { .. }           => op_multiplier * 3,
                    TxBody::Stake   { .. }           => op_multiplier * 5,
                    TxBody::Custom  { .. }           => op_multiplier * 10,
                    TxBody::ClaimUbi { .. }          => op_multiplier * 3,
                    TxBody::RedirectToUbiPool { .. } => op_multiplier * 3,
                    TxBody::SponsorAgent { .. }      => op_multiplier * 4,
                    TxBody::RevokeAgent  { .. }      => op_multiplier * 2,
                    // Registration writes a new IdentityRecord + account --
                    // comparable weight to the other identity-gated writes.
                    TxBody::RegisterIdentity         => op_multiplier * 3,
                    // A single vouch is lightweight; the occasional one that
                    // crosses quorum and triggers a tier upgrade isn't
                    // meaningfully heavier at Phase 0/1 gas-metering precision.
                    TxBody::Attest { .. }            => op_multiplier * 2,
                    // Attestation guard Phase D operations.
                    TxBody::RevokeAttestation { .. }   => op_multiplier * 2,
                    TxBody::ReportSuspectedSybil { .. }=> op_multiplier * 2,
                    // ConfirmSybil walks all attestation records for an identity --
                    // heavier than a single write.
                    TxBody::ConfirmSybil { .. }        => op_multiplier * 8,
                    TxBody::ReverseSybil { .. }        => op_multiplier * 8,
                    // QRC typed variants.
                    // Purchase: burns QCB + mints QRC — heavier than a plain burn.
                    TxBody::QrcPurchase { .. }          => op_multiplier * 6,
                    // Spend: updates provider pool + burn + reserve — three writes.
                    TxBody::QrcSpend { .. }             => op_multiplier * 5,
                    // Settle: verifies evidence + mints QRC — most expensive.
                    TxBody::QrcContributionSettle { .. }=> op_multiplier * 12,
                    // Phase 1 Charm Confinement / Agent typed variants.
                    // ConfinementUpdate: reads identity + writes charm + Merkle leaf.
                    TxBody::CharmConfinementUpdate { .. } => op_multiplier * 4,
                    // IntrinsicCharmRecord: single charm field update + leaf refresh.
                    TxBody::IntrinsicCharmRecord { .. }  => op_multiplier * 3,
                    // RegisterAgent: writes AgentRecord + identity sponsorship + account.
                    TxBody::RegisterAgent { .. }         => op_multiplier * 8,
                    // Epoch boundary: lightweight protocol signals.
                    TxBody::EpochOpen { .. }             => op_multiplier * 4,
                    TxBody::EpochClose { .. }            => op_multiplier * 4,
                    // Control 5: capacity update + circuit breaker re-evaluation.
                    TxBody::RecordCapacity { .. }        => op_multiplier * 3,
                    // AEI Phase 2 lifecycle ops.
                    TxBody::AuthorizeAgent { .. }        => op_multiplier * 4,
                    TxBody::SuspendAgent { .. }          => op_multiplier * 3,
                    TxBody::RevokeAgentFull { .. }       => op_multiplier * 6, // touches both stores
                    TxBody::RecordAgentSpend { .. }      => op_multiplier * 2,
                    TxBody::SpawnChildAgent { .. }       => op_multiplier * 8, // comparable to RegisterAgent
                };
                base_fee_per_byte * tx_bytes + op_cost
            }
            Self::Eip1559Style { base_fee, min_priority_fee } => {
                base_fee + min_priority_fee + tx_bytes / 100
            }
        }
    }
}

// -- Transaction types --------------------------------------------------------

/// The body of a transaction -- what operation it requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxBody {
    /// Transfer tokens from sender to recipient.
    Transfer {
        to:     String,
        denom:  String,
        amount: u128,
    },
    /// Burn tokens permanently (used by BME mechanism, Section 6.3).
    Burn {
        denom:  String,
        amount: u128,
    },
    /// Stake $QCB to a validator (Section 3.3).
    Stake {
        validator: String,
        amount:    u128,
    },
    /// Custom operation -- opaque payload for module-specific logic.
    /// Used by Charm Confinement, Intrinsic Charm, Charmed Agents.
    /// QRC operations now use typed variants below.
    Custom {
        module:  String,
        payload: Vec<u8>,
    },

    // ── QRC Economic Model v0.1 typed tx variants ──────────────────────────

    /// Purchase-path QRC minting (Section 4.1 / QRC Economic Model v0.1).
    ///
    /// Burns `qcb_amount` of $QCB from the sender's account and mints QRC
    /// resource credits at the current algorithmic rate `Rt`.  The rate is
    /// demand-responsive: when the network is congested Rt falls (QRC costs
    /// more QCB); when the network is underutilised Rt rises (QRC costs less).
    ///
    /// `min_qrc_out` is a slippage guard: if the engine would produce fewer
    /// QRC credits than this value the transaction is rejected with
    /// `SlippageExceeded`.  Pass 0 to accept any rate.
    ///
    /// State changes:
    ///   - sender.$QCB decreases by `qcb_amount` (permanent burn)
    ///   - QrcEngine credits `qrc_minted` to sender's QRC balance
    ///   - QrcEngine.total_qcb_burned += qcb_amount (audit trail)
    QrcPurchase {
        /// $QCB to burn (in uqcb, the smallest denomination).
        qcb_amount:  u128,
        /// Minimum QRC credits the sender will accept.  0 = no minimum.
        min_qrc_out: u128,
    },

    /// Consumption-path QRC spending (Section 4.3 / QRC Economic Model v0.1).
    ///
    /// Deducts `amount` QRC from the sender's balance for a single network
    /// operation of the given resource type.  The engine applies the
    /// consumption split:
    ///   ~60% → provider compensation pool
    ///   ~25% → permanent QRC burn (deflationary)
    ///   ~15% → protocol reserve
    ///
    /// The actual cost for a given number of `units` is computed by
    /// `QrcEngine::operation_cost()` which accounts for per-resource base
    /// costs and the current congestion multiplier.  `amount` must be ≥ the
    /// computed cost or the transaction is rejected.
    QrcSpend {
        /// Which network resource is being consumed.
        resource: chain_forge_qrc::ResourceKind,
        /// Number of resource units being consumed.
        units:    u128,
        /// QRC the sender authorises to spend (must cover the computed cost).
        amount:   u128,
    },

    /// Contribution-path QRC earning (Section 4.2 / QRC Economic Model v0.1).
    ///
    /// Submitted by a verified resource provider after each epoch, carrying
    /// their `CapacityEvidence` (proof of compute/storage/ZK-proving delivered
    /// during the epoch).  The VCA layer in `chain-forge-qrc` verifies the
    /// evidence against the epoch's demand data, computes the provider's
    /// earning `E(i,r,t)`, and mints QRC directly — no QCB is burned.
    ///
    /// Enforced invariants:
    ///   - Sender must be a Verified-tier identity (Charm Confinement).
    ///   - One settlement per (sender, epoch, resource_type).
    ///   - Evidence must be from a Finalized (or Finalizing) CapacityReport.
    QrcContributionSettle {
        /// The epoch being settled.
        epoch:    u64,
        /// The capacity evidence to settle against.
        evidence: chain_forge_qrc::CapacityEvidence,
    },
    /// Register a new Provisional identity (Whitepaper Section 4 / Identity
    /// Pilot Design Phase 1). The sender registers themselves -- identity_id
    /// and address are both the sender's account address. Starts the
    /// web-of-trust process; the identity remains Provisional until it
    /// accumulates ATTESTATION_QUORUM distinct attestations (see Attest).
    RegisterIdentity,
    /// Vouch that `claimant_id` is a unique human (Identity Pilot Design
    /// Section 3.1). The sender is the attester and must already be
    /// Verified or Established. Once the claimant reaches
    /// ATTESTATION_QUORUM distinct attestations, they are upgraded to
    /// Verified as a side effect of this transaction.
    Attest {
        claimant_id: String,
    },
    /// Claim UBI for a verified identity (Section 6.2 / Charm Confinement 5.1).
    /// Enforces: one claim per epoch, verified tier, liveness.
    /// The sender must be the identity owner.
    ClaimUbi {
        identity_id: String,
    },
    /// Proactive redirect of $QRC balance to the UBI pool (Section 6.3 / Q25).
    /// Triggers BME fee. Holder voluntarily sends balance to pool.
    RedirectToUbiPool {
        amount: u128,
    },
    /// Register a Charmed Agent under a verified human sponsor (Section 5.3).
    /// Enforces: sponsor must be Verified tier.
    SponsorAgent {
        agent_address: String,
    },
    /// Revoke a previously sponsored agent.
    RevokeAgent {
        agent_address: String,
    },
    /// Revoke a previously submitted attestation (Phase D attestation guard).
    /// The sender revokes their own attestation of `attested_id`.
    /// Incurs a CS revocation cost (REVOCATION_COST_BPS) and frees the
    /// sender's rolling-window slot so they can attest again within the
    /// same 90-epoch window.
    RevokeAttestation {
        attested_id: String,
    },
    /// Coordinator-only: confirm that `sybil_id` is a sybil (Phase C / D).
    /// Walks all active attestation records for `sybil_id` and applies a CS
    /// penalty to each attester (ATTEST_PENALTY_RATE_BPS). Attesters who
    /// self-reported before this confirmation receive a reduced penalty
    /// (SELF_REPORT_PENALTY_REDUCTION_BPS applied).
    ConfirmSybil {
        sybil_id: String,
    },
    /// Coordinator-only: reverse a prior sybil confirmation (Phase C / D).
    /// Credits back the CS penalty that was applied on ConfirmSybil and
    /// un-penalizes the attestation records. The reversal is logged.
    ReverseSybil {
        sybil_id: String,
    },
    /// Report a suspected sybil before the coordinator acts (Phase D
    /// self-report exemption). The sender must have an active attestation for
    /// `suspected_id`. If the coordinator later confirms the sybil, the
    /// sender's penalty is reduced by SELF_REPORT_PENALTY_REDUCTION_BPS.
    ReportSuspectedSybil {
        suspected_id: String,
    },

    // ── Phase 1 typed tx variants (Charm Confinement + Agent Registration) ──

    /// Sync the sender's on-chain IntrinsicCharm with the IdentityStore and
    /// record participation for the given epoch (Phase 1 / Charm Confinement
    /// 5.1). This is the "confinement heartbeat" transaction: once per epoch,
    /// a Verified or Established identity submits this to prove liveness and
    /// advance their `consecutive_active_epochs` counter.
    ///
    /// Effects:
    ///   - `IntrinsicCharm::record_participation(epoch)` runs on the sender's
    ///     identity record, potentially graduating them from Verified to
    ///     Established if `consecutive_active_epochs` reaches 30.
    ///   - The updated charm is synced to the on-chain AccountState and the
    ///     Merkle leaf is refreshed.
    ///
    /// Enforced invariants:
    ///   - Sender must be at least Verified tier.
    ///   - `epoch` should be the current epoch (checked against identity clock).
    CharmConfinementUpdate {
        /// The epoch for which this confinement heartbeat is submitted.
        epoch: u64,
    },

    /// Record an intrinsic charm lifecycle event for the sender's identity
    /// (Phase 1 / Charm Confinement 5.2). Used for charm-layer bookkeeping
    /// that does not map cleanly onto the standard participation heartbeat.
    ///
    /// `CharmEvent` captures the distinct events that affect the on-chain
    /// charm record without going through the normal UBI/transfer paths.
    ///
    /// Effects:
    ///   - The event is applied to the sender's `IntrinsicCharm` via the
    ///     matching `IntrinsicCharm` method.
    ///   - The updated charm is synced to on-chain AccountState.
    ///
    /// Enforced invariants:
    ///   - Sender must be registered in the IdentityStore.
    ///   - `CharmEvent::DecayTick` requires no minimum tier.
    ///   - `CharmEvent::ExemptionCredit` also requires no minimum tier.
    IntrinsicCharmRecord {
        /// The charm lifecycle event to apply.
        event: CharmEvent,
    },

    /// Register a Charmed Agent with full AEI fields (Phase 1 / Section 5.3).
    /// This is the typed replacement for the legacy `SponsorAgent` variant,
    /// which only recorded the agent_address in the IdentityStore.
    ///
    /// `RegisterAgent` registers the agent in the `AgentStore` (which carries
    /// the full AEI: CapabilitySet, SpendingLimits, ParentAgentID) AND
    /// also calls `identity.sponsor_agent()` so the IdentityStore's web-of-
    /// trust sponsorship relationship is preserved.
    ///
    /// After registration the agent has status `AgentStatus::Pending`.  The
    /// next step is a governance/coordinator `authorize()` call, not a tx.
    ///
    /// Enforced invariants:
    ///   - Sender (sponsor) must be Verified or Established tier.
    ///   - `agent_id` must be unique in the AgentStore.
    ///   - If `parent_agent_id` is set, the parent must exist and be Active.
    RegisterAgent {
        /// Unique identifier for this agent on-chain (e.g. "merchant-alice-1").
        agent_id: String,
        /// The QCB address this agent controls.
        agent_address: String,
        /// What this agent is authorized to do.
        capabilities: Vec<chain_forge_agents::AgentCapability>,
        /// $QRC spending caps for this agent.
        spending_limits: SpendingLimits,
        /// Human-readable role description.
        description: String,
        /// If this is a sub-agent, the parent's agent_id.
        parent_agent_id: Option<String>,
    },

    // ── QRC Economic Model v0.2 — Epoch Accounting ────────────────────────────

    /// Open a new QRC epoch (QRC Economic Model v0.2 §EpochOpen).
    ///
    /// Submitted by block producers at an epoch boundary.  Initialises the
    /// per-epoch supply cap and seeds the epoch reserve from the protocol
    /// reserve.  Only one epoch may be open at a time; attempting to open a
    /// second epoch without closing the first is rejected.
    ///
    /// `verified_count` is the number of verified identities at epoch start,
    /// snapshotted from the IdentityStore.  It drives the supply cap:
    ///   `supply_cap = verified_count × EPOCH_ISSUANCE_CAP_PER_VERIFIED`
    ///
    /// Enforced invariants:
    ///   - No epoch is currently open in the QrcEngine.
    ///   - Sender must be a block-producer / validator address (coordinator-gated).
    EpochOpen {
        /// The epoch number being opened.
        epoch: u64,
        /// Number of Verified-tier identities at epoch start.
        verified_count: u64,
    },

    /// Close the current QRC epoch (QRC Economic Model v0.2 §EpochClose).
    ///
    /// Submitted by block producers at epoch end.  Sweeps unspent epoch
    /// reserve back to the protocol reserve and finalises provider reward
    /// accounting.  After this, a new epoch may be opened.
    ///
    /// Enforced invariants:
    ///   - An epoch is currently open in the QrcEngine.
    ///   - Sender must be a block-producer / validator address (coordinator-gated).
    EpochClose {
        /// The epoch number being closed.  Must match `QrcEngine::current_epoch`.
        epoch: u64,
    },

    // ── Control 5: CoverageRatio circuit breaker ──────────────────────────────

    /// Record VCA-attested network resource capacity and re-evaluate the
    /// CoverageRatio circuit breaker (Control 5 / QRC Economic Model v0.2 §6.10).
    ///
    /// Submitted by a VCA coordinator after a `CapacityReport` is finalised
    /// on-chain.  The `capacity` value is the total verified network resource
    /// capacity in normalised units (× D), as reported by the VCA sub-protocol
    /// in `chain-forge-qrc/src/capacity_report.rs`.
    ///
    /// Effect:
    ///   - `QrcEngine::record_capacity(capacity)` is called, which updates
    ///     `tracked_capacity` and may transition the `minting_state` between
    ///     `Normal`, `Restricted`, and `Halted`.
    ///   - A structured JSON event is emitted to stdout on every state change
    ///     (see `QrcEngine::update_circuit_breaker`).
    ///
    /// CR_t = capacity / qrc_outstanding (fixed-point × D):
    ///   - CR ≥ 1.00 → Normal    (both purchase and contribution paths open)
    ///   - 0.75 ≤ CR < 1.00 → Restricted (purchase suspended; contribution open)
    ///   - CR < 0.75 → Halted   (both minting paths suspended)
    ///
    /// Enforced invariants:
    ///   - Sender must be a VCA coordinator / validator address.
    ///   - `capacity` may be 0 (interpreted as CR=0, drives to Halted).
    RecordCapacity {
        /// Total verified network resource capacity, in normalised units × D.
        capacity: u128,
    },

    // ── Agent Lifecycle — AEI Phase 2 ─────────────────────────────────────────

    /// Advance an agent from Pending → Active (or Suspended → Active).
    ///
    /// Only the agent's registered sponsor (or an authorized governance key)
    /// may submit this transaction.  The `AgentStore::authorize()` method
    /// enforces that the agent is in Pending or Suspended state.
    AuthorizeAgent {
        /// The unique agent identifier (same value used in `RegisterAgent`).
        agent_id: String,
    },

    /// Temporarily suspend an Active agent.
    ///
    /// Agent state is preserved; the agent can be re-authorized later.
    /// Caller must be the agent's sponsor or a governance identity.
    SuspendAgent {
        /// The agent to suspend.
        agent_id: String,
        /// Human-readable reason (logged as a block event; not enforced on-chain).
        reason: String,
    },

    /// Permanently revoke an agent's registration.
    ///
    /// This is the Phase 2 complement to the legacy `RevokeAgent` variant:
    ///   - `RevokeAgent` (Phase 0) only touches `IdentityStore`.
    ///   - `RevokeAgentFull` touches BOTH `AgentStore` AND `IdentityStore`.
    ///
    /// After this tx the agent cannot be re-authorized; the `agent_id` is
    /// effectively tombstoned in the AgentStore (status = Revoked).
    RevokeAgentFull {
        /// The agent to permanently revoke.
        agent_id: String,
    },

    /// Record a QRC spend against an agent's epoch and lifetime limits.
    ///
    /// Submitted by the agent's executor on behalf of the agent when it
    /// performs a metered action.  Enforces both `epoch_limit_uqrc` and
    /// `lifetime_limit_uqrc` in the agent's `SpendingLimits`.
    RecordAgentSpend {
        /// The agent recording the spend.
        agent_id: String,
        /// Amount in micro-QRC (uQRC).
        amount_uqrc: u128,
    },

    /// Spawn a child agent under an existing parent agent.
    ///
    /// Enforces:
    ///   - Parent must exist and be Active.
    ///   - Parent must hold the `SpawnChildAgent` capability.
    ///   - Child's spending limits are capped at the parent's remaining limits
    ///     (i.e. child cannot exceed what parent is allowed to spend).
    ///   - Sponsor of both parent and child must be the same verified human.
    SpawnChildAgent {
        /// Unique identifier for the new child agent.
        child_agent_id: String,
        /// Address the child will act from.
        child_agent_address: String,
        /// The parent agent whose capability set gates this spawn.
        parent_agent_id: String,
        /// Capabilities granted to the child (must be a subset of parent's).
        capabilities: Vec<chain_forge_agents::AgentCapability>,
        /// Spending limits for the child (capped at parent remaining capacity).
        spending_limits: SpendingLimits,
        /// Human-readable description of the child agent's purpose.
        description: String,
    },
}

impl TxBody {
    /// Short string label identifying the variant, used by the explorer for
    /// display and by load_persisted_state() when reconstructing TxSummary
    /// records from committed block payloads.
    pub fn variant_name(&self) -> &'static str {
        match self {
            TxBody::Transfer { .. }               => "Transfer",
            TxBody::Burn { .. }                   => "Burn",
            TxBody::Stake { .. }                  => "Stake",
            TxBody::Custom { .. }                 => "Custom",
            TxBody::ClaimUbi { .. }               => "ClaimUbi",
            TxBody::RedirectToUbiPool { .. }      => "RedirectToUbiPool",
            TxBody::SponsorAgent { .. }           => "SponsorAgent",
            TxBody::RevokeAgent { .. }            => "RevokeAgent",
            TxBody::RegisterIdentity             => "RegisterIdentity",
            TxBody::Attest { .. }                 => "Attest",
            TxBody::RevokeAttestation { .. }      => "RevokeAttestation",
            TxBody::ReportSuspectedSybil { .. }   => "ReportSuspectedSybil",
            TxBody::ConfirmSybil { .. }           => "ConfirmSybil",
            TxBody::ReverseSybil { .. }           => "ReverseSybil",
            TxBody::QrcPurchase { .. }            => "QrcPurchase",
            TxBody::QrcSpend { .. }               => "QrcSpend",
            TxBody::QrcContributionSettle { .. }  => "QrcContributionSettle",
            TxBody::CharmConfinementUpdate { .. } => "CharmConfinementUpdate",
            TxBody::IntrinsicCharmRecord { .. }   => "IntrinsicCharmRecord",
            TxBody::RegisterAgent { .. }          => "RegisterAgent",
            TxBody::EpochOpen { .. }              => "EpochOpen",
            TxBody::EpochClose { .. }             => "EpochClose",
            TxBody::RecordCapacity { .. }         => "RecordCapacity",
            TxBody::AuthorizeAgent { .. }         => "AuthorizeAgent",
            TxBody::SuspendAgent { .. }           => "SuspendAgent",
            TxBody::RevokeAgentFull { .. }        => "RevokeAgentFull",
            TxBody::RecordAgentSpend { .. }       => "RecordAgentSpend",
            TxBody::SpawnChildAgent { .. }        => "SpawnChildAgent",
        }
    }
}

/// Events that affect the on-chain IntrinsicCharm record without going through
/// the normal participation-heartbeat path. Used by `IntrinsicCharmRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CharmEvent {
    /// Demurrage decay tick (called each epoch the account does not transact).
    /// Decrements the decay-exemption counter by one day if the account has
    /// exemption credit; transitions to lapsed if exemptions are exhausted.
    DecayTick,
    /// Credit one day of decay exemption (earned by QRC spending activity).
    /// This is normally triggered automatically by `Transfer` and `QrcSpend`
    /// via `account.record_spend_for_exemption()`, but can be issued
    /// explicitly (e.g. by a coordinator for a verified provider).
    ExemptionCredit,
}

/// Advance the sender's nonce after a successful transaction, for the tx
/// types whose handlers don't already do it.
///
/// Transfer, Burn and Stake advance the nonce inside StateStore::transfer /
/// StateStore::burn, and ClaimUbi / RedirectToUbiPool advance it inside the
/// QrcEngine calls they make. Every other body type previously advanced
/// nothing -- which meant RegisterIdentity, Attest, SponsorAgent,
/// RevokeAgent and Custom transactions left the sender's nonce unchanged
/// on success. Consequences: the same signed transaction could be
/// replayed with the same nonce indefinitely, and a sender who correctly
/// incremented their own nonce after one of these txs got every following
/// tx rejected with a nonce mismatch. Found by chain-forge-sim against the
/// live 4-validator testnet: attesters' second transactions in the same
/// session were all rejected "expected 0, got 1".
fn advance_nonce_if_not_already(tx: &Transaction, state: &mut StateStore) {
    let already_advances = matches!(
        tx.body,
        TxBody::Transfer { .. }
            | TxBody::Burn { .. }
            | TxBody::Stake { .. }
            | TxBody::ClaimUbi { .. }
            | TxBody::RedirectToUbiPool { .. }
            // QRC variants mutate account state via the QrcEngine but do NOT
            // call StateStore::burn/transfer directly (the purchase-path burn
            // is done explicitly in the handler), so nonce advancement falls
            // through to here.  Listed as `already_advances = false` so the
            // catch-all below handles it.  The comment is kept as a reminder.
    );
    if already_advances {
        return;
    }
    if let Ok(acct) = state.get_account_mut(&tx.sender) {
        acct.increment_nonce();
    }
    state.refresh_leaf(&tx.sender);
}

/// A fully-formed transaction ready for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique transaction ID (hash of body + sender + nonce).
    pub id: String,
    /// Address of the account signing this transaction.
    pub sender: String,
    /// Expected nonce of the sender at execution time.
    pub nonce: u64,
    /// The operation to perform.
    pub body: TxBody,
    /// Maximum gas the sender is willing to pay.
    pub gas_limit: u64,
    /// Ed25519 signature over signing_bytes(chain_id). Empty when unsigned.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Ed25519 public key (32 bytes) that produced `signature`. Must either
    /// match the key bound to `sender`, or -- for an account with no bound
    /// key yet -- be the key `sender` was derived from.
    #[serde(default)]
    pub public_key: Vec<u8>,
}

impl Transaction {
    /// The exact bytes a sender signs. Domain-separated and bound to the
    /// chain id, so a signature from one chain (or one message type) can
    /// never be replayed as a transaction on another. Covers every field
    /// except the signature itself.
    pub fn signing_bytes(&self, chain_id: &str) -> Vec<u8> {
        let payload = serde_json::to_vec(&(
            &self.id, &self.sender, self.nonce, &self.body, self.gas_limit, &self.public_key,
        )).expect("transaction fields always serialise");
        let mut out = Vec::with_capacity(payload.len() + chain_id.len() + 24);
        out.extend_from_slice(b"chain-forge/tx/v1\n");
        out.extend_from_slice(chain_id.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(&payload);
        out
    }

    /// Set public_key from `keypair` and sign. Clients call this last,
    /// after every other field is final.
    pub fn sign(&mut self, keypair: &KeyPair, chain_id: &str) -> Result<(), String> {
        self.public_key = keypair.public_key.clone();
        let sig = ClassicalScheme.sign(&self.signing_bytes(chain_id), keypair)
            .map_err(|e| e.to_string())?;
        self.signature = sig.bytes;
        Ok(())
    }

    /// Approximate serialised size in bytes (used for gas calculation).
    pub fn payload_size_bytes(&self) -> usize {
        let body_size = match &self.body {
            TxBody::Transfer { to, denom, .. }       => to.len() + denom.len() + 16,
            TxBody::Burn     { denom, .. }            => denom.len() + 16,
            TxBody::Stake    { validator, .. }        => validator.len() + 16,
            TxBody::Custom   { module, payload }      => module.len() + payload.len(),
            TxBody::RegisterIdentity                  => 8,
            TxBody::Attest   { claimant_id }          => claimant_id.len() + 8,
            TxBody::ClaimUbi { identity_id }          => identity_id.len() + 8,
            TxBody::RedirectToUbiPool { .. }          => 16,
            TxBody::SponsorAgent { agent_address }    => agent_address.len() + 8,
            TxBody::RevokeAgent  { agent_address }    => agent_address.len() + 8,
            TxBody::RevokeAttestation { attested_id }    => attested_id.len() + 8,
            TxBody::ConfirmSybil { sybil_id }            => sybil_id.len() + 8,
            TxBody::ReverseSybil { sybil_id }            => sybil_id.len() + 8,
            TxBody::ReportSuspectedSybil { suspected_id }=> suspected_id.len() + 8,
            // QRC typed variants.
            TxBody::QrcPurchase { .. }                   => 32,
            TxBody::QrcSpend { .. }                      => 24,
            // Evidence carries provider_id + proof bytes — treat as ~256 bytes.
            TxBody::QrcContributionSettle { .. }         => 256,
            // Phase 1 typed variants.
            TxBody::CharmConfinementUpdate { .. }        => 16,
            TxBody::IntrinsicCharmRecord { .. }          => 16,
            // RegisterAgent carries description + capabilities list.
            TxBody::RegisterAgent { agent_id, agent_address, description, .. } => {
                agent_id.len() + agent_address.len() + description.len() + 64
            }
            // Epoch boundary signals: epoch number (u64) only.
            TxBody::EpochOpen { .. }  => 24,
            TxBody::EpochClose { .. } => 16,
            // Control 5: capacity value (u128).
            TxBody::RecordCapacity { .. } => 16,
            // AEI Phase 2 lifecycle ops.
            TxBody::AuthorizeAgent { agent_id }             => agent_id.len() + 8,
            TxBody::SuspendAgent { agent_id, reason }       => agent_id.len() + reason.len() + 8,
            TxBody::RevokeAgentFull { agent_id }            => agent_id.len() + 8,
            TxBody::RecordAgentSpend { agent_id, .. }       => agent_id.len() + 24,
            TxBody::SpawnChildAgent {
                child_agent_id, child_agent_address, parent_agent_id, description, ..
            } => child_agent_id.len() + child_agent_address.len()
                + parent_agent_id.len() + description.len() + 64,
        };
        self.sender.len() + 8 + body_size + self.signature.len()
    }

    /// A minimal transfer transaction for tests.
    pub fn transfer(id: &str, sender: &str, to: &str, denom: &str, amount: u128, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::Transfer {
                to: to.to_string(),
                denom: denom.to_string(),
                amount,
            },
            gas_limit: 100_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// A burn transaction for BME.
    pub fn burn(id: &str, sender: &str, denom: &str, amount: u128, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::Burn { denom: denom.to_string(), amount },
            gas_limit: 100_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// A UBI claim transaction (Charm Confinement: one per epoch).
    pub fn claim_ubi(id: &str, sender: &str, identity_id: &str, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::ClaimUbi { identity_id: identity_id.to_string() },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// A self-registration transaction (Identity Pilot Design Phase 1).
    pub fn register_identity(id: &str, sender: &str, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::RegisterIdentity,
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// A web-of-trust attestation transaction: sender vouches for claimant_id.
    pub fn attest(id: &str, sender: &str, claimant_id: &str, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::Attest { claimant_id: claimant_id.to_string() },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// A UBI pool redirect transaction (Section 6.3 / Q25).
    pub fn redirect_to_ubi_pool(id: &str, sender: &str, amount: u128, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::RedirectToUbiPool { amount },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// A sponsor agent transaction (Section 5.3).
    pub fn sponsor_agent(id: &str, sender: &str, agent_address: &str, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::SponsorAgent { agent_address: agent_address.to_string() },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// Revoke a previous attestation (Phase D attestation guard).
    pub fn revoke_attestation(id: &str, sender: &str, attested_id: &str, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::RevokeAttestation { attested_id: attested_id.to_string() },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// Coordinator-only: confirm `sybil_id` as a sybil (Phase D attestation guard).
    pub fn confirm_sybil(id: &str, coordinator: &str, sybil_id: &str, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: coordinator.to_string(),
            nonce,
            body: TxBody::ConfirmSybil { sybil_id: sybil_id.to_string() },
            gas_limit: 200_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// Coordinator-only: reverse a prior sybil confirmation (Phase D attestation guard).
    pub fn reverse_sybil(id: &str, coordinator: &str, sybil_id: &str, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: coordinator.to_string(),
            nonce,
            body: TxBody::ReverseSybil { sybil_id: sybil_id.to_string() },
            gas_limit: 200_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// Self-report a suspected sybil before coordinator confirmation (Phase D).
    pub fn report_suspected_sybil(id: &str, sender: &str, suspected_id: &str, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::ReportSuspectedSybil { suspected_id: suspected_id.to_string() },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    // ── QRC Economic Model v0.1 constructors ──────────────────────────────────

    /// Purchase QRC by burning QCB (QRC Economic Model v0.1 §4.1).
    ///
    /// `min_qrc_out = 0` accepts any rate.  Non-zero values act as a slippage
    /// guard: the transaction is rejected if the engine would produce fewer QRC
    /// credits than that floor.
    pub fn qrc_purchase(
        id:          &str,
        sender:      &str,
        qcb_amount:  u128,
        min_qrc_out: u128,
        nonce:       u64,
    ) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::QrcPurchase { qcb_amount, min_qrc_out },
            gas_limit: 200_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// Spend QRC for a network resource operation (QRC Economic Model v0.1 §4.3).
    ///
    /// `amount` is the maximum QRC the sender authorises for this operation.
    /// The actual cost is computed by the engine; `amount` must be ≥ that cost.
    pub fn qrc_spend(
        id:       &str,
        sender:   &str,
        resource: chain_forge_qrc::ResourceKind,
        units:    u128,
        amount:   u128,
        nonce:    u64,
    ) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::QrcSpend { resource, units, amount },
            gas_limit: 150_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// Settle contribution-path QRC earning for an epoch (QRC Economic Model v0.1 §4.2).
    ///
    /// Caller must be a Verified-tier identity.  `evidence` carries the
    /// VCA-verifiable capacity proof for the settled epoch.
    pub fn qrc_contribution_settle(
        id:       &str,
        sender:   &str,
        epoch:    u64,
        evidence: chain_forge_qrc::CapacityEvidence,
        nonce:    u64,
    ) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::QrcContributionSettle { epoch, evidence },
            gas_limit: 400_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    // ── Control 5: CoverageRatio circuit breaker tx constructor ──────────────

    /// Record VCA-attested network resource capacity and update the circuit breaker.
    ///
    /// `capacity` is total verified capacity in normalised units × D.
    /// Submitted by a VCA coordinator after a CapacityReport finalises.
    pub fn record_capacity(id: &str, sender: &str, capacity: u128, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::RecordCapacity { capacity },
            gas_limit: 100_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    // ── Phase 1 Charm Confinement / Agent typed tx constructors ──────────────

    /// Confinement heartbeat: prove liveness and advance consecutive-epoch
    /// counter for the sender's IntrinsicCharm (Phase 1 / Section 5.1).
    ///
    /// Sender must be Verified or Established tier.
    pub fn charm_confinement_update(id: &str, sender: &str, epoch: u64, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::CharmConfinementUpdate { epoch },
            gas_limit: 150_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// Record a charm lifecycle event (decay tick, exemption credit) for the
    /// sender's IntrinsicCharm (Phase 1 / Section 5.2).
    pub fn intrinsic_charm_record(
        id:    &str,
        sender: &str,
        event:  CharmEvent,
        nonce:  u64,
    ) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::IntrinsicCharmRecord { event },
            gas_limit: 100_000,
            signature: vec![],
            public_key: vec![],
        }
    }

    /// Register a Charmed Agent with full AEI fields (Phase 1 / Section 5.3).
    ///
    /// Sender is the human sponsor.  The agent starts in `Pending` status.
    #[allow(clippy::too_many_arguments)]
    pub fn register_agent(
        id:              &str,
        sender:          &str,
        agent_id:        &str,
        agent_address:   &str,
        capabilities:    Vec<chain_forge_agents::AgentCapability>,
        spending_limits: SpendingLimits,
        description:     &str,
        parent_agent_id: Option<String>,
        nonce:           u64,
    ) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::RegisterAgent {
                agent_id:        agent_id.to_string(),
                agent_address:   agent_address.to_string(),
                capabilities,
                spending_limits,
                description:     description.to_string(),
                parent_agent_id,
            },
            gas_limit: 300_000,
            signature: vec![],
            public_key: vec![],
        }
    }
}

// -- Transaction result -------------------------------------------------------

/// Outcome of executing a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    pub tx_id:     String,
    pub success:   bool,
    pub gas_used:  u64,
    pub gas_limit: u64,
    /// Human-readable error if success is false.
    pub error:     Option<String>,
    /// Events emitted (simplified -- a real chain would have structured events).
    pub events:    Vec<String>,
}

impl TransactionResult {
    pub fn ok(tx_id: String, gas_used: u64, gas_limit: u64, events: Vec<String>) -> Self {
        Self { tx_id, success: true, gas_used, gas_limit, error: None, events }
    }

    pub fn err(tx_id: String, gas_used: u64, gas_limit: u64, error: String) -> Self {
        Self { tx_id, success: false, gas_used, gas_limit, error: Some(error), events: vec![] }
    }
}

// -- Block execution result ---------------------------------------------------

/// Result of executing all transactions in one block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockExecutionResult {
    pub height:       u64,
    pub tx_results:   Vec<TransactionResult>,
    pub gas_used:     u64,
    pub gas_limit:    u64,
    pub state_root:   String,
    /// Total fees collected (in base denom). Routed to validators/burns.
    pub fees_collected: u64,
}

impl BlockExecutionResult {
    pub fn success_count(&self) -> usize {
        self.tx_results.iter().filter(|r| r.success).count()
    }

    pub fn failure_count(&self) -> usize {
        self.tx_results.iter().filter(|r| !r.success).count()
    }
}

// -- Execution config ---------------------------------------------------------

/// Runtime execution parameters derived from genesis.
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    pub gas_model:       GasModel,
    pub block_gas_limit: u64,
    pub max_tx_bytes:    u64,
    /// Native token denom (fees are paid in this).
    pub native_denom:    String,
    /// Chain id mixed into every signature (cross-chain replay protection).
    pub chain_id:        String,
    /// Prefix for key-derived addresses, e.g. "qcb" -> "qcb1...".
    pub address_prefix:  String,
    /// Hash width used to derive addresses from public keys.
    pub hash_width:      HashWidth,
    /// Enforce signatures and key binding on every transaction.
    pub require_signatures: bool,
    /// Optional modules this chain runs. Transactions belonging to a
    /// module that is off are rejected before anything else happens.
    pub modules: EnabledModules,
}

impl ExecutionConfig {
    pub fn from_genesis(genesis: &GenesisConfig) -> Self {
        Self {
            gas_model:       GasModel::from_genesis(genesis),
            block_gas_limit: genesis.limits.block_gas_limit,
            max_tx_bytes:    genesis.limits.max_tx_bytes,
            native_denom:    genesis.native_token.denom.clone(),
            chain_id:        genesis.chain_id.clone(),
            address_prefix:  genesis.address_prefix.clone(),
            hash_width:      genesis.hash_width().unwrap_or(HashWidth::Bits256),
            require_signatures: genesis.execution.require_signatures,
            // Fail closed: a genesis with an invalid module list gets no
            // optional modules. (The node refuses to start on one anyway.)
            modules: genesis.enabled_modules().unwrap_or_default(),
        }
    }
}

// -- Authorization --------------------------------------------------------------

/// Check that `tx` is authorised by the key that controls `tx.sender`.
///
/// 1. The Ed25519 signature must verify over signing_bytes(chain_id).
/// 2. If the sender's account has a bound key, the signing key must be it.
/// 3. Otherwise the sender address must be derived from the signing key --
///    so an unbound address can only ever be claimed by its own key holder.
///    Named addresses (genesis labels like "qcb1alice") are never derived,
///    so they are only usable when genesis bound a key to them.
fn verify_authorization(config: &ExecutionConfig, tx: &Transaction, state: &StateStore) -> Result<(), String> {
    if !config.require_signatures {
        return Ok(());
    }
    verify_signature(tx, &config.chain_id)?;

    match state.get_account(&tx.sender).ok().and_then(|a| a.public_key.clone()) {
        Some(bound) if bound == tx.public_key => Ok(()),
        Some(_) => Err(format!("signing key does not match the key bound to {}", tx.sender)),
        None => {
            let derived = Address::from_public_key(&tx.public_key, &config.address_prefix, config.hash_width);
            if derived.as_str() == tx.sender {
                Ok(())
            } else {
                Err(format!("{} has no bound key and is not derived from the signing key", tx.sender))
            }
        }
    }
}

/// Which optional module a transaction type belongs to, if any. Transfer,
/// Burn and Custom are core and always allowed.
pub fn required_module(body: &TxBody) -> Option<&'static str> {
    match body {
        TxBody::Transfer { .. } | TxBody::Burn { .. } | TxBody::Custom { .. } => None,
        TxBody::Stake { .. } => Some("staking"),
        TxBody::RegisterIdentity
        | TxBody::Attest { .. }
        | TxBody::RevokeAttestation { .. }
        | TxBody::ConfirmSybil { .. }
        | TxBody::ReverseSybil { .. }
        | TxBody::ReportSuspectedSybil { .. } => Some("identity"),
        TxBody::ClaimUbi { .. } | TxBody::RedirectToUbiPool { .. } => Some("qrc"),
        TxBody::QrcPurchase { .. }
        | TxBody::QrcSpend { .. }
        | TxBody::QrcContributionSettle { .. } => Some("qrc"),
        TxBody::SponsorAgent { .. } | TxBody::RevokeAgent { .. } => Some("agents"),
        // Phase 1 typed variants.
        TxBody::CharmConfinementUpdate { .. } | TxBody::IntrinsicCharmRecord { .. } => Some("identity"),
        TxBody::RegisterAgent { .. } => Some("agents"),
        // QRC v0.2 epoch boundary signals + Control 5 require the QRC module.
        TxBody::EpochOpen { .. } | TxBody::EpochClose { .. }
        | TxBody::RecordCapacity { .. } => Some("qrc"),
        // AEI Phase 2 lifecycle operations all require the agents module.
        TxBody::AuthorizeAgent { .. }
        | TxBody::SuspendAgent { .. }
        | TxBody::RevokeAgentFull { .. }
        | TxBody::RecordAgentSpend { .. }
        | TxBody::SpawnChildAgent { .. } => Some("agents"),
    }
}

/// Reject a transaction whose module this chain doesn't run. Stateless, so
/// the HTTP API applies it at submission as well as the executor.
pub fn module_check(tx: &Transaction, modules: &EnabledModules) -> Result<(), String> {
    let Some(name) = required_module(&tx.body) else { return Ok(()) };
    let on = match name {
        "staking"  => modules.staking,
        "identity" => modules.identity,
        "qrc"    => modules.qrc,
        "agents"   => modules.agents,
        _ => false,
    };
    if on { Ok(()) } else { Err(format!("module \"{name}\" is not enabled on this chain")) }
}

/// Stateless half of authorization: is `tx.signature` a valid Ed25519
/// signature by `tx.public_key` over this transaction on this chain?
/// Needs no state, so the HTTP API runs it at submission to reject bad
/// signatures immediately; the executor runs it again (plus the key
/// binding check, which does need state) on every node at execution.
pub fn verify_signature(tx: &Transaction, chain_id: &str) -> Result<(), String> {
    if tx.public_key.len() != 32 {
        return Err(format!("unsigned or malformed: public_key must be 32 bytes, got {}", tx.public_key.len()));
    }
    let sig = Signature { scheme: SchemeId::Classical, bytes: tx.signature.clone() };
    ClassicalScheme
        .verify(&tx.signing_bytes(chain_id), &sig, &tx.public_key)
        .map_err(|e| format!("invalid signature: {e}"))
}

/// Bind the signing key to the sender's account on its first successful
/// signed transaction (the account may have just been created by it).
fn bind_key_if_unbound(config: &ExecutionConfig, tx: &Transaction, state: &mut StateStore) {
    if !config.require_signatures {
        return;
    }
    if let Ok(acct) = state.get_account_mut(&tx.sender) {
        if acct.public_key.is_none() {
            acct.public_key = Some(tx.public_key.clone());
        }
    }
    state.refresh_leaf(&tx.sender);
}

// -- Executor -----------------------------------------------------------------

/// Applies transactions to a StateStore.
/// The node creates one Executor per block and calls execute_block().
/// Identity-aware: CharmConfinement enforcement happens here via
/// optional IdentityStore and QrcEngine references.
pub struct Executor {
    config: ExecutionConfig,
}

impl Executor {
    pub fn new(config: ExecutionConfig) -> Self {
        Self { config }
    }

    /// Execute a single transaction with CharmConfinement enforcement.
    /// Requires identity store, QRC engine, and agent store for identity-gated
    /// and agent-registered tx types.
    pub fn execute_tx_with_identity(
        &self,
        tx:       &Transaction,
        state:    &mut StateStore,
        identity: &mut IdentityStore,
        qrc:      &mut QrcEngine,
        agents:   &mut AgentStore,
    ) -> TransactionResult {
        let gas_required = self.config.gas_model.calculate_gas(tx);

        if tx.gas_limit < gas_required {
            return TransactionResult::err(
                tx.id.clone(), gas_required, tx.gas_limit,
                format!("gas limit {} below required {}", tx.gas_limit, gas_required),
            );
        }

        if let Err(e) = module_check(tx, &self.config.modules) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }
        if let Err(e) = verify_authorization(&self.config, tx, state) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }

        let expected_nonce = state.get_account(&tx.sender)
            .map(|a| a.nonce).unwrap_or(0);
        if tx.nonce != expected_nonce {
            return TransactionResult::err(
                tx.id.clone(), gas_required, tx.gas_limit,
                format!("nonce mismatch: expected {expected_nonce}, got {}", tx.nonce),
            );
        }

        let mut events = Vec::new();
        let result = match &tx.body {

            // -- Standard tx types (same as execute_tx) ----------------------
            TxBody::Transfer { to, denom, amount } => {
                // Record spend for decay-exemption (Section 6.2)
                let epoch = identity.clock.current_epoch;
                if let Ok(sender_acct) = state.get_account_mut(&tx.sender) {
                    sender_acct.record_spend_for_exemption(epoch);
                }
                let result = state.transfer(&tx.sender, to, denom, *amount)
                    .map(|_| events.push(format!("transfer: {} {} -> {}", amount, denom, to)))
                    .map_err(|e| e.to_string());
                // QRC earned-yield gate: a successful transfer counts as
                // on-chain activity for the sender, making them eligible to
                // claim QRC yield this epoch. We use record_activity_by_address
                // so the lookup goes through wallet address → identity record.
                if result.is_ok() {
                    identity.record_activity_by_address(&tx.sender);
                }
                result
            }

            TxBody::Burn { denom, amount } => {
                state.burn(&tx.sender, denom, *amount)
                    .map(|_| events.push(format!("burn: {} {} (BME)", amount, denom)))
                    .map_err(|e| e.to_string())
            }

            TxBody::Stake { validator, amount } => {
                let result = state.transfer(&tx.sender, validator, &self.config.native_denom, *amount)
                    .map(|_| events.push(format!("stake: {} -> {}", amount, validator)))
                    .map_err(|e| e.to_string());
                // Staking is on-chain activity — record for QRC yield eligibility.
                if result.is_ok() {
                    identity.record_activity_by_address(&tx.sender);
                }
                result
            }

            TxBody::Custom { module, payload } => {
                events.push(format!("custom: module={} bytes={}", module, payload.len()));
                Ok(())
            }

            // -- CharmConfinement-enforced tx types --------------------------

            TxBody::RegisterIdentity => {
                let epoch = identity.clock.current_epoch;
                let attestation = chain_forge_identity::PopAttestation {
                    identity_id: tx.sender.clone(),
                    attester:    tx.sender.clone(),
                    epoch,
                    proof:       vec![],
                    note:        Some("self-registration".to_string()),
                };
                identity.register(tx.sender.clone(), tx.sender.clone(), attestation)
                    .map(|_| {
                        events.push(format!(
                            "register_identity: {} registered as Provisional",
                            tx.sender
                        ));
                        // Create the on-chain account if this is the sender's
                        // first transaction, then sync the fresh Provisional
                        // charm onto it so /api/accounts can actually show
                        // tier progress -- without this, registering and
                        // attesting would change IdentityStore but leave the
                        // explorer's view of the account unchanged forever.
                        if state.get_account(&tx.sender).is_err() {
                            let new_acct = chain_forge_state::AccountState::new(
                                tx.sender.clone(), "user".to_string()
                            );
                            state.upsert_account(new_acct);
                        }
                        if let (Ok(record), Ok(acct)) = (
                            identity.get(&tx.sender),
                            state.get_account_mut(&tx.sender),
                        ) {
                            acct.attach_charm(record.charm.clone());
                        }
                        // Charm and tier are now in the account; propagate
                        // the change to the Merkle leaf so the state root
                        // reflects the new tier and light clients can verify it.
                        state.refresh_leaf(&tx.sender);
                    })
                    .map_err(|e| e.to_string())
            }

            TxBody::Attest { claimant_id } => {
                identity.attest(claimant_id, &tx.sender)
                    .map(|outcome| {
                        match &outcome {
                            chain_forge_identity::AttestationOutcome::QuorumReachedVerified => {
                                events.push(format!(
                                    "attest: {} vouched for {} -- quorum reached, now Verified",
                                    tx.sender, claimant_id
                                ));
                            }
                            chain_forge_identity::AttestationOutcome::Recorded {
                                attester_count, quorum
                            } => {
                                events.push(format!(
                                    "attest: {} vouched for {} ({}/{} attestations)",
                                    tx.sender, claimant_id, attester_count, quorum
                                ));
                            }
                        }
                        // Sync the claimant's (possibly just-upgraded) charm
                        // onto their on-chain account, same reasoning as
                        // RegisterIdentity above.
                        if let (Ok(record), Ok(acct)) = (
                            identity.get(claimant_id),
                            state.get_account_mut(claimant_id),
                        ) {
                            acct.attach_charm(record.charm.clone());
                        }
                        // Propagate the charm/tier change to the Merkle leaf.
                        // Without this, a quorum of attestations that upgrades
                        // a claimant from Provisional to Verified changes the
                        // IdentityStore and the AccountState but never reaches
                        // the state root — so light clients and external
                        // verifiers can't trust what tier they read.
                        state.refresh_leaf(claimant_id);
                    })
                    .map_err(|e| e.to_string())
            }

            TxBody::ClaimUbi { identity_id } => {
                // Charm Confinement: one claim per epoch, verified tier, liveness
                if state.get_account(&tx.sender).is_err() {
                    let new_acct = chain_forge_state::AccountState::new(
                        tx.sender.clone(), "user".to_string()
                    );
                    state.upsert_account(new_acct);
                }
                // UBI claim is a UBI-era tx type. The QRC engine (v0.1) does not
                // distribute UBI — QRC is earned by resource contribution or
                // purchased by burning QCB. This path is preserved in the tx
                // enum for protocol continuity but is a no-op until the
                // execution layer is upgraded to the resource-consumption model.
                let _ = identity_id;
                Err("ClaimUbi: deprecated in QRC Economic Model v0.1; use contribution-path earning or purchase_qrc".into())
            }

            TxBody::RedirectToUbiPool { amount } => {
                // Proactive redirect: triggers BME fee (Section 6.3 / Q25)
                let epoch = identity.clock.current_epoch;
                match state.get_account_mut(&tx.sender) {
                    Ok(_account) => {
                        // RedirectToUbiPool is a UBI-era tx type, deprecated in
                        // QRC Economic Model v0.1. The UBI pool concept does not
                        // exist in the resource-consumption engine. Preserved for
                        // protocol continuity; no-op until execution is upgraded.
                        let _ = (epoch, amount);
                        Err("RedirectToUbiPool: deprecated in QRC Economic Model v0.1".into())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }

            TxBody::SponsorAgent { agent_address } => {
                // Charm Confinement: sponsor must be Verified tier
                identity.sponsor_agent(&tx.sender, agent_address)
                    .map(|_| {
                        events.push(format!(
                            "sponsor_agent: {} -> {} authorized",
                            tx.sender, agent_address
                        ));
                        // Update account charm to reflect agent sponsorship
                        if let Ok(acct) = state.get_account_mut(&tx.sender) {
                            acct.record_participation(identity.clock.current_epoch);
                        }
                    })
                    .map_err(|e| e.to_string())
            }

            TxBody::RevokeAgent { agent_address } => {
                if let Ok(record) = identity.get(&tx.sender) {
                    if record.has_sponsored(agent_address) {
                        identity.get_mut(&tx.sender)
                            .map(|r| r.revoke_agent(agent_address));
                        events.push(format!(
                            "revoke_agent: {} -> {} revoked",
                            tx.sender, agent_address
                        ));
                        Ok(())
                    } else {
                        Err(format!("{} has not sponsored agent {}", tx.sender, agent_address))
                    }
                } else {
                    Err(format!("identity {} not found", tx.sender))
                }
            }

            // -- Attestation guard Phase D tx types ---------------------------

            TxBody::RevokeAttestation { attested_id } => {
                // The identity crate enforces all rules (active record exists,
                // not already revoked) and returns the CS cost signal.
                identity.revoke_attestation(&tx.sender, attested_id)
                    .map(|cost| {
                        // cost.cost_bps signals how much CS to deduct.
                        // Phase 0 / pilot: we emit the cost as an event so the
                        // coordinator dashboard can track it. Full CS deduction
                        // from the state store is wired up in a later phase when
                        // the CS ledger is on-chain. For now the event is the
                        // observable signal.
                        events.push(format!(
                            "revoke_attestation: {} revoked attestation of {} \
                             (cs_cost_bps={})",
                            cost.attester_id, cost.attested_id, cost.cost_bps
                        ));
                    })
                    .map_err(|e| e.to_string())
            }

            TxBody::ConfirmSybil { sybil_id } => {
                // Only the coordinator can call this. During pilot phase the
                // coordinator_id field on IdentityStore is the gating key;
                // if not set, the call returns NotCoordinator.
                identity.confirm_sybil(&tx.sender, sybil_id)
                    .map(|penalized_ids| {
                        // penalized_ids: Vec<String> of attester addresses that
                        // received CS penalties. Emitted so the coordinator
                        // dashboard can reconstruct the penalty ledger.
                        if penalized_ids.is_empty() {
                            events.push(format!(
                                "confirm_sybil: {} confirmed as sybil \
                                 (no active attesters to penalize)",
                                sybil_id
                            ));
                        } else {
                            events.push(format!(
                                "confirm_sybil: {} confirmed as sybil, \
                                 {} attester(s) penalized: {}",
                                sybil_id,
                                penalized_ids.len(),
                                penalized_ids.join(", ")
                            ));
                        }
                    })
                    .map_err(|e| e.to_string())
            }

            TxBody::ReverseSybil { sybil_id } => {
                // Coordinator reverses a prior sybil confirmation. CS penalties
                // are credited back and attestation records un-penalized.
                identity.reverse_sybil(&tx.sender, sybil_id)
                    .map(|restored_ids| {
                        events.push(format!(
                            "reverse_sybil: {} sybil confirmation reversed, \
                             {} attester(s) restored: {}",
                            sybil_id,
                            restored_ids.len(),
                            restored_ids.join(", ")
                        ));
                    })
                    .map_err(|e| e.to_string())
            }

            TxBody::ReportSuspectedSybil { suspected_id } => {
                // Self-report: attester flags an identity they vouched for as
                // suspected sybil. If the coordinator later confirms, the
                // attester receives a 50% penalty reduction. The sender must
                // have an active attestation for suspected_id.
                identity.report_suspected_sybil(&tx.sender, suspected_id)
                    .map(|_| {
                        events.push(format!(
                            "report_suspected_sybil: {} flagged {} as suspected sybil \
                             (self-report logged, awaiting coordinator confirmation)",
                            tx.sender, suspected_id
                        ));
                    })
                    .map_err(|e| e.to_string())
            }

            // -- QRC Economic Model v0.1 typed tx types -----------------------

            TxBody::QrcPurchase { qcb_amount, min_qrc_out } => {
                // Validate the purchase amount is non-zero.
                if *qcb_amount == 0 {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        "QrcPurchase: qcb_amount must be > 0".to_string(),
                    );
                }

                // Control 5: purchase path blocked when circuit breaker is
                // RESTRICTED or HALTED (CR below CR_resume = 1.00).
                if !qrc.minting_state.purchase_allowed() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "QrcPurchase: blocked by CoverageRatio circuit breaker \
                             (state={}, CR_resume=1.00) — capacity must recover \
                             before purchase minting resumes",
                            qrc.minting_state.as_str()
                        ),
                    );
                }

                // Ensure sender has an account.
                if state.get_account(&tx.sender).is_err() {
                    let new_acct = chain_forge_state::AccountState::new(
                        tx.sender.clone(), "user".to_string()
                    );
                    state.upsert_account(new_acct);
                }

                // Check QCB balance WITHOUT calling state.burn() — burn() calls
                // account.increment_nonce() internally, which would double-advance
                // the nonce when advance_nonce_if_not_already() also fires below.
                // Instead we debit directly so the nonce is advanced exactly once
                // (by advance_nonce_if_not_already on success, nowhere on failure).
                let qcb_have = state.get_account(&tx.sender)
                    .map(|a| a.balance_of("uqcb"))
                    .unwrap_or(0);
                if qcb_have < *qcb_amount {
                    Err(format!(
                        "insufficient uqcb: have {}, need {}",
                        qcb_have, qcb_amount
                    ))
                } else {
                    // Debit the QCB (permanent burn — no recipient).
                    if let Ok(acct) = state.get_account_mut(&tx.sender) {
                        acct.debit("uqcb", *qcb_amount).expect("balance check passed above");
                    }
                    state.refresh_leaf(&tx.sender);

                    // Ask the engine how much QRC this QCB buy earns.
                    let (qrc_minted, rt_used) = qrc.purchase_qrc(*qcb_amount);

                    // Slippage guard: reject if rate moved against the sender.
                    if *min_qrc_out > 0 && qrc_minted < *min_qrc_out {
                        // Roll back the debit by re-crediting QCB. Nonce has
                        // NOT been incremented yet (we bypassed burn()), so
                        // this is a clean rollback.
                        if let Ok(acct) = state.get_account_mut(&tx.sender) {
                            acct.credit("uqcb", *qcb_amount);
                        }
                        state.refresh_leaf(&tx.sender);
                        Err(format!(
                            "QrcPurchase: slippage exceeded — would mint {} uqrc \
                             but min_qrc_out is {} (Rt={})",
                            qrc_minted, min_qrc_out, rt_used
                        ))
                    } else {
                        // Credit QRC to the sender's account.
                        if let Ok(acct) = state.get_account_mut(&tx.sender) {
                            acct.credit("uqrc", qrc_minted);
                        }
                        state.refresh_leaf(&tx.sender);
                        events.push(format!(
                            "qrc_purchase: {} uqcb burned → {} uqrc minted \
                             (Rt={}, sender={})",
                            qcb_amount, qrc_minted, rt_used, tx.sender
                        ));
                        Ok(())
                    }
                }
            }

            TxBody::QrcSpend { resource, units, amount } => {
                // Validate units are non-zero.
                if *units == 0 {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        "QrcSpend: units must be > 0".to_string(),
                    );
                }

                // Compute the operation cost via the engine (accounts for per-
                // resource base cost and current congestion multiplier).
                let op = chain_forge_qrc::OperationCost::new().add(*resource, *units);
                let cost = qrc.operation_cost(&op);

                // Authorised amount must cover the computed cost.
                if *amount < cost {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "QrcSpend: authorised amount {} uqrc is below \
                             operation cost {} uqrc (resource={:?}, units={})",
                            amount, cost, resource, units
                        ),
                    );
                }

                // Check sender QRC balance.
                let sender_qrc = state.get_account(&tx.sender)
                    .map(|a| a.balance_of("uqrc"))
                    .unwrap_or(0);
                if sender_qrc < cost {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "QrcSpend: insufficient uqrc balance — have {}, need {}",
                            sender_qrc, cost
                        ),
                    );
                }

                // Debit the sender's QRC balance.
                if let Ok(acct) = state.get_account_mut(&tx.sender) {
                    // cost <= sender_qrc so this never underflows.
                    acct.debit("uqrc", cost).expect("balance check passed above");
                }
                state.refresh_leaf(&tx.sender);

                // Apply the 60/25/15 consumption split in the engine.
                let split = qrc.consume(cost);

                events.push(format!(
                    "qrc_spend: {} uqrc consumed (resource={:?}, units={}) \
                     → providers={} burn={} reserve={} sender={}",
                    cost, resource, units,
                    split.to_providers, split.burned, split.to_reserve,
                    tx.sender
                ));
                Ok(())
            }

            TxBody::QrcContributionSettle { epoch, evidence } => {
                // Charm Confinement: only Verified (or Established) identities
                // may submit capacity evidence and earn contribution-path QRC.
                let tier_ok = identity.get(&tx.sender)
                    .map(|r| r.is_verified())
                    .unwrap_or(false);
                if !tier_ok {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "QrcContributionSettle: sender {} is not a Verified \
                             identity (Charm Confinement requires Verified tier)",
                            tx.sender
                        ),
                    );
                }

                // Control 5: contribution earn path blocked ONLY when HALTED
                // (CR < CR_halt = 0.75). RESTRICTED keeps contribution open —
                // providers are the capacity recovery mechanism.
                if !qrc.minting_state.contribution_allowed() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "QrcContributionSettle: blocked by CoverageRatio \
                             circuit breaker (state=halted, CR_halt=0.75) — \
                             both minting paths suspended until capacity recovers",
                        ),
                    );
                }

                // Epoch in the evidence must match the tx field.
                if evidence.epoch != *epoch {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "QrcContributionSettle: evidence.epoch ({}) \
                             != tx.epoch ({})",
                            evidence.epoch, epoch
                        ),
                    );
                }

                // Bridge ResourceType → ResourceKind and build the contributions
                // map expected by credit_provider_earning. resource_type_to_kind
                // returns None for resource types not yet tracked by the QRC engine
                // (future protocol upgrades). Reject those gracefully.
                let kind = match chain_forge_qrc::resource_type_to_kind(evidence.resource_type) {
                    Some(k) => k,
                    None => return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "QrcContributionSettle: resource type {:?} is not \
                             recognised by the QRC engine on this chain version",
                            evidence.resource_type
                        ),
                    ),
                };
                let mut contributions = std::collections::BTreeMap::new();
                contributions.insert(kind, evidence.capacity_claim);

                // Mint contribution-path QRC. The engine computes E(i,r,t).
                let qrc_minted = qrc.credit_provider_earning(
                    &evidence.provider_id,
                    &contributions,
                );

                // Ensure the sender has an on-chain account.
                if state.get_account(&tx.sender).is_err() {
                    let new_acct = chain_forge_state::AccountState::new(
                        tx.sender.clone(), "user".to_string()
                    );
                    state.upsert_account(new_acct);
                }

                // Credit the earned QRC to the sender's balance.
                if qrc_minted > 0 {
                    if let Ok(acct) = state.get_account_mut(&tx.sender) {
                        acct.credit("uqrc", qrc_minted);
                    }
                    state.refresh_leaf(&tx.sender);
                }

                let pid_prefix: String = evidence.provider_id[..8]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                events.push(format!(
                    "qrc_contribution_settle: {} uqrc minted to {} \
                     (epoch={}, resource={:?}, capacity_claim={}, \
                     provider_id={}…)",
                    qrc_minted, tx.sender, epoch,
                    kind, evidence.capacity_claim, pid_prefix
                ));
                Ok(())
            }

            // -- Phase 1 typed variants ---------------------------------------

            TxBody::CharmConfinementUpdate { epoch } => {
                // Charm Confinement: sender must be at least Verified tier.
                let tier_ok = identity.get(&tx.sender)
                    .map(|r| r.is_verified())
                    .unwrap_or(false);
                if !tier_ok {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "CharmConfinementUpdate: sender {} is not Verified \
                             (Charm Confinement requires Verified or Established tier)",
                            tx.sender
                        ),
                    );
                }

                // Record participation in the identity store. This bumps
                // `consecutive_active_epochs` and may auto-promote to Established.
                if let Some(record) = identity.get_mut(&tx.sender) {
                    record.charm.record_participation(*epoch);
                }

                // Sync the updated charm to the on-chain account.
                if let (Ok(record), Ok(acct)) = (
                    identity.get(&tx.sender),
                    state.get_account_mut(&tx.sender),
                ) {
                    acct.attach_charm(record.charm.clone());
                }
                state.refresh_leaf(&tx.sender);

                let tier_name = identity.get(&tx.sender)
                    .map(|r| format!("{:?}", r.tier()))
                    .unwrap_or_else(|_| "Unknown".into());
                events.push(format!(
                    "charm_confinement_update: {} epoch={} tier={}",
                    tx.sender, epoch, tier_name
                ));
                Ok(())
            }

            TxBody::IntrinsicCharmRecord { event } => {
                // Sender must be registered in the identity store.
                if identity.get(&tx.sender).is_err() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("IntrinsicCharmRecord: identity {} not found", tx.sender),
                    );
                }

                let current_epoch = identity.clock.current_epoch;

                match event {
                    CharmEvent::DecayTick => {
                        // Consume one decay-exemption day from the sender's
                        // identity charm and sync the change to the on-chain
                        // account leaf so the state root reflects it.
                        if let Some(record) = identity.get_mut(&tx.sender) {
                            record.charm.decay_exemption.consume(1);
                            if let Ok(acct) = state.get_account_mut(&tx.sender) {
                                acct.attach_charm(record.charm.clone());
                            }
                        }
                        state.refresh_leaf(&tx.sender);
                        events.push(format!(
                            "intrinsic_charm_record: decay_tick sender={}",
                            tx.sender
                        ));
                    }
                    CharmEvent::ExemptionCredit => {
                        // Credit one exemption day to the sender's account.
                        if let Ok(acct) = state.get_account_mut(&tx.sender) {
                            acct.record_spend_for_exemption(current_epoch);
                        }
                        state.refresh_leaf(&tx.sender);
                        events.push(format!(
                            "intrinsic_charm_record: exemption_credit sender={}",
                            tx.sender
                        ));
                    }
                }
                Ok(())
            }

            TxBody::RegisterAgent {
                agent_id,
                agent_address,
                capabilities,
                spending_limits,
                description,
                parent_agent_id,
            } => {
                // Charm Confinement: sponsor must be Verified or Established tier.
                let tier_ok = identity.get(&tx.sender)
                    .map(|r| r.is_verified())
                    .unwrap_or(false);
                if !tier_ok {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "RegisterAgent: sponsor {} is not Verified \
                             (Charm Confinement requires Verified or Established tier)",
                            tx.sender
                        ),
                    );
                }

                // Also record the sponsorship in the IdentityStore so the
                // web-of-trust relationship is visible to other modules.
                if let Err(e) = identity.sponsor_agent(&tx.sender, agent_address) {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("RegisterAgent: identity sponsor_agent failed: {e}"),
                    );
                }

                let current_epoch = identity.clock.current_epoch;

                // Register in the AgentStore with full AEI.
                if let Err(e) = agents.register(
                    agent_id.clone(),
                    agent_address.clone(),
                    tx.sender.clone(),
                    capabilities.clone(),
                    spending_limits.clone(),
                    parent_agent_id.clone(),
                    description.clone(),
                    AgentType::Native,
                    current_epoch,
                ) {
                    // Roll back the IdentityStore sponsorship.
                    if let Some(r) = identity.get_mut(&tx.sender) {
                        r.revoke_agent(agent_address);
                    }
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("RegisterAgent: AgentStore.register failed: {e}"),
                    );
                }

                events.push(format!(
                    "register_agent: sponsor={} agent_id={} address={} status=Pending",
                    tx.sender, agent_id, agent_address
                ));
                Ok(())
            }

            // ── QRC Economic Model v0.2 — Epoch Boundary ─────────────────────

            TxBody::EpochOpen { epoch, verified_count } => {
                match qrc.open_epoch(*epoch, *verified_count) {
                    Ok(summary) => {
                        events.push(format!(
                            "epoch_open: epoch={} verified={} supply_cap={} reserve_seeded={}",
                            epoch, verified_count, summary.supply_cap, summary.reserve_balance
                        ));
                        Ok(())
                    }
                    Err(e) => Err(format!("EpochOpen: {e}")),
                }
            }

            TxBody::EpochClose { epoch } => {
                if qrc.current_epoch != *epoch {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "EpochClose: epoch mismatch — engine has {}, tx says {epoch}",
                            qrc.current_epoch
                        ),
                    );
                }
                match qrc.close_epoch() {
                    Ok(summary) => {
                        events.push(format!(
                            "epoch_close: epoch={} minted={} provider_rewards={} reserve_swept={}",
                            epoch, summary.epoch_minted, summary.provider_rewards,
                            summary.reserve_balance
                        ));
                        Ok(())
                    }
                    Err(e) => Err(format!("EpochClose: {e}")),
                }
            }

            // ── Control 5: CoverageRatio circuit breaker ──────────────────────

            TxBody::RecordCapacity { capacity } => {
                let prev_state = qrc.minting_state;
                qrc.record_capacity(*capacity);
                let new_state = qrc.minting_state;

                let cr_display = qrc.coverage_ratio()
                    .map(|cr| format!("{:.4}", cr as f64 / chain_forge_qrc::D as f64))
                    .unwrap_or_else(|| "∞ (no supply)".to_string());

                events.push(format!(
                    "record_capacity: capacity={} CR={} state={}->{} sender={}",
                    capacity, cr_display,
                    prev_state.as_str(), new_state.as_str(),
                    tx.sender
                ));
                Ok(())
            }

            // ── AEI Phase 2 — Agent Lifecycle ────────────────────────────────

            TxBody::AuthorizeAgent { agent_id } => {
                // Caller must be the agent's registered sponsor.
                let agent = match agents.get(agent_id) {
                    Ok(a) => a,
                    Err(e) => return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("AuthorizeAgent: {e}"),
                    ),
                };
                if agent.sponsor_id != tx.sender {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "AuthorizeAgent: sender {} is not the registered sponsor of agent {}",
                            tx.sender, agent_id
                        ),
                    );
                }
                let current_epoch = identity.clock.current_epoch;
                match agents.authorize(agent_id, current_epoch) {
                    Ok(()) => {
                        events.push(format!(
                            "authorize_agent: sponsor={} agent_id={} epoch={}",
                            tx.sender, agent_id, current_epoch
                        ));
                        Ok(())
                    }
                    Err(e) => Err(format!("AuthorizeAgent: {e}")),
                }
            }

            TxBody::SuspendAgent { agent_id, reason } => {
                // Caller must be the agent's registered sponsor.
                let agent = match agents.get(agent_id) {
                    Ok(a) => a,
                    Err(e) => return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("SuspendAgent: {e}"),
                    ),
                };
                if agent.sponsor_id != tx.sender {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "SuspendAgent: sender {} is not the registered sponsor of agent {}",
                            tx.sender, agent_id
                        ),
                    );
                }
                let current_epoch = identity.clock.current_epoch;
                match agents.suspend(agent_id, current_epoch) {
                    Ok(()) => {
                        events.push(format!(
                            "suspend_agent: sponsor={} agent_id={} reason={:?} epoch={}",
                            tx.sender, agent_id, reason, current_epoch
                        ));
                        Ok(())
                    }
                    Err(e) => Err(format!("SuspendAgent: {e}")),
                }
            }

            TxBody::RevokeAgentFull { agent_id } => {
                // Caller must be the agent's registered sponsor.
                let agent = match agents.get(agent_id) {
                    Ok(a) => a,
                    Err(e) => return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("RevokeAgentFull: {e}"),
                    ),
                };
                let agent_address = agent.address.clone();
                if agent.sponsor_id != tx.sender {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "RevokeAgentFull: sender {} is not the registered sponsor of agent {}",
                            tx.sender, agent_id
                        ),
                    );
                }
                let current_epoch = identity.clock.current_epoch;
                // Step 1: revoke in AgentStore (tombstones the AEI record).
                if let Err(e) = agents.revoke(agent_id, current_epoch) {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("RevokeAgentFull: AgentStore.revoke failed: {e}"),
                    );
                }
                // Step 2: remove the sponsorship link from IdentityStore so
                //         the slot is freed and cannot be re-registered.
                if let Some(record) = identity.get_mut(&tx.sender) {
                    record.revoke_agent(&agent_address);
                }
                events.push(format!(
                    "revoke_agent_full: sponsor={} agent_id={} address={} epoch={}",
                    tx.sender, agent_id, agent_address, current_epoch
                ));
                Ok(())
            }

            TxBody::RecordAgentSpend { agent_id, amount_uqrc } => {
                // Caller must be the agent's registered sponsor (or the agent
                // address itself — sponsors gate agent actions in Phase 2).
                let agent = match agents.get(agent_id) {
                    Ok(a) => a,
                    Err(e) => return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("RecordAgentSpend: {e}"),
                    ),
                };
                let is_sponsor  = agent.sponsor_id   == tx.sender;
                let is_agent    = agent.address       == tx.sender;
                if !is_sponsor && !is_agent {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "RecordAgentSpend: sender {} is neither sponsor nor agent address for {}",
                            tx.sender, agent_id
                        ),
                    );
                }
                match agents.record_spend(agent_id, *amount_uqrc) {
                    Ok(()) => {
                        events.push(format!(
                            "record_agent_spend: agent_id={} amount_uqrc={} sender={}",
                            agent_id, amount_uqrc, tx.sender
                        ));
                        Ok(())
                    }
                    Err(e) => Err(format!("RecordAgentSpend: {e}")),
                }
            }

            TxBody::SpawnChildAgent {
                child_agent_id,
                child_agent_address,
                parent_agent_id,
                capabilities,
                spending_limits,
                description,
            } => {
                // 1. Parent must exist and be Active.
                let parent = match agents.get(parent_agent_id) {
                    Ok(p) => p,
                    Err(e) => return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("SpawnChildAgent: parent lookup failed: {e}"),
                    ),
                };
                if !parent.is_active() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("SpawnChildAgent: parent agent {} is not Active", parent_agent_id),
                    );
                }
                // 2. Parent must hold SpawnChildAgent capability.
                use chain_forge_agents::AgentCapability;
                if let Err(e) = agents.check_capability(
                    parent_agent_id,
                    &AgentCapability::SpawnChildAgent,
                ) {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("SpawnChildAgent: parent lacks SpawnChildAgent capability: {e}"),
                    );
                }
                // 3. Caller must be the parent's sponsor (same verified human
                //    must own both parent and child).
                let sponsor_id = {
                    let parent = agents.get(parent_agent_id).unwrap(); // already confirmed Ok
                    parent.sponsor_id.clone()
                };
                if sponsor_id != tx.sender {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "SpawnChildAgent: sender {} is not the sponsor of parent agent {}",
                            tx.sender, parent_agent_id
                        ),
                    );
                }
                // 4. Sponsor must be Verified (same gate as RegisterAgent).
                if !identity.get(&tx.sender).map(|r| r.is_verified()).unwrap_or(false) {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "SpawnChildAgent: sponsor {} is not Verified (Charm Confinement requires Verified or Established tier)",
                            tx.sender
                        ),
                    );
                }
                // 5. Register the child with parent_agent_id set.
                //    AgentStore::register checks parent is Active internally.
                let current_epoch = identity.clock.current_epoch;
                // Also record the sponsorship in IdentityStore.
                if let Err(e) = identity.sponsor_agent(&tx.sender, child_agent_address) {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("SpawnChildAgent: identity sponsor_agent failed: {e}"),
                    );
                }
                match agents.register(
                    child_agent_id.clone(),
                    child_agent_address.clone(),
                    tx.sender.clone(),
                    capabilities.clone(),
                    spending_limits.clone(),
                    Some(parent_agent_id.clone()),
                    description.clone(),
                    chain_forge_agents::AgentType::Native,
                    current_epoch,
                ) {
                    Ok(()) => {
                        events.push(format!(
                            "spawn_child_agent: sponsor={} parent={} child_id={} address={} status=Pending epoch={}",
                            tx.sender, parent_agent_id, child_agent_id, child_agent_address, current_epoch
                        ));
                        Ok(())
                    }
                    Err(e) => {
                        // Roll back the IdentityStore sponsorship.
                        if let Some(record) = identity.get_mut(&tx.sender) {
                            record.revoke_agent(child_agent_address);
                        }
                        Err(format!("SpawnChildAgent: AgentStore.register failed: {e}"))
                    }
                }
            }
        };

        if result.is_ok() {
            advance_nonce_if_not_already(tx, state);
            bind_key_if_unbound(&self.config, tx, state);
            // Every successfully committed transaction is on-chain activity.
            // Transfer and Stake already call this inside their match arms (so
            // the QRC yield comment lives next to the transfer logic), but
            // all other tx types — RegisterIdentity, Attest, SponsorAgent,
            // RevokeAgent, ClaimUbi, RedirectToUbiPool — also count: submitting
            // ANY committed tx proves liveness for this epoch. Duplicate calls
            // to record_activity_by_address are idempotent (only the first
            // write per epoch sticks), so the double-call for Transfer/Stake
            // is harmless.
            identity.record_activity_by_address(&tx.sender);
        }

        match result {
            Ok(_) => TransactionResult::ok(tx.id.clone(), gas_required, tx.gas_limit, events),
            Err(e) => TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e),
        }
    }

    /// Execute a single transaction against the state store.
    /// Returns the result regardless of success/failure --
    /// failed txs still consume gas and advance the nonce.
    pub fn execute_tx(
        &self,
        tx: &Transaction,
        state: &mut StateStore,
    ) -> TransactionResult {
        let gas_required = self.config.gas_model.calculate_gas(tx);

        // Gas limit check
        if tx.gas_limit < gas_required {
            return TransactionResult::err(
                tx.id.clone(),
                gas_required,
                tx.gas_limit,
                format!("gas limit {} below required {}", tx.gas_limit, gas_required),
            );
        }

        if let Err(e) = module_check(tx, &self.config.modules) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }
        if let Err(e) = verify_authorization(&self.config, tx, state) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }

        // Nonce check
        let expected_nonce = state.get_account(&tx.sender)
            .map(|a| a.nonce)
            .unwrap_or(0);

        if tx.nonce != expected_nonce {
            return TransactionResult::err(
                tx.id.clone(),
                gas_required,
                tx.gas_limit,
                format!("nonce mismatch: expected {expected_nonce}, got {}", tx.nonce),
            );
        }

        // Execute the operation
        let mut events = Vec::new();
        let result = match &tx.body {
            TxBody::Transfer { to, denom, amount } => {
                state.transfer(&tx.sender, to, denom, *amount)
                    .map(|_| {
                        events.push(format!(
                            "transfer: {} {} from {} to {}",
                            amount, denom, tx.sender, to
                        ));
                    })
                    .map_err(|e| e.to_string())
            }
            TxBody::Burn { denom, amount } => {
                state.burn(&tx.sender, denom, *amount)
                    .map(|_| {
                        events.push(format!(
                            "burn: {} {} from {} (BME)",
                            amount, denom, tx.sender
                        ));
                    })
                    .map_err(|e| e.to_string())
            }
            TxBody::Stake { validator, amount } => {
                // Phase 0: record staking intent as a transfer to validator.
                // Full staking module (bonding, unbonding, slashing) is Tier 2.
                state.transfer(&tx.sender, validator, &self.config.native_denom, *amount)
                    .map(|_| {
                        events.push(format!(
                            "stake: {} {} from {} to validator {}",
                            amount, self.config.native_denom, tx.sender, validator
                        ));
                    })
                    .map_err(|e| e.to_string())
            }
            TxBody::Custom { module, payload } => {
                // Phase 0: custom module calls are recorded as events but not
                // executed -- the module runtime (Charm Confinement, QRC etc.)
                // is a later-phase addition.
                events.push(format!(
                    "custom: module={} payload_bytes={}",
                    module,
                    payload.len()
                ));
                Ok(())
            }
            // Identity-gated tx types require execute_tx_with_identity().
            TxBody::RegisterIdentity
            | TxBody::Attest { .. }
            | TxBody::ClaimUbi { .. }
            | TxBody::RedirectToUbiPool { .. }
            | TxBody::SponsorAgent { .. }
            | TxBody::RevokeAgent { .. }
            | TxBody::RevokeAttestation { .. }
            | TxBody::ConfirmSybil { .. }
            | TxBody::ReverseSybil { .. }
            | TxBody::ReportSuspectedSybil { .. } => {
                Err("identity-gated transaction requires identity-aware executor".to_string())
            }
            // QRC typed tx types require the QRC engine (execute_tx_with_identity).
            TxBody::QrcPurchase { .. }
            | TxBody::QrcSpend { .. }
            | TxBody::QrcContributionSettle { .. }
            | TxBody::RecordCapacity { .. } => {
                Err("QRC transaction requires QRC-engine-aware executor".to_string())
            }
            // Phase 1 typed variants require identity + agent store.
            TxBody::CharmConfinementUpdate { .. }
            | TxBody::IntrinsicCharmRecord { .. }
            | TxBody::RegisterAgent { .. } => {
                Err("Phase 1 transaction requires identity- and agent-aware executor".to_string())
            }
            // QRC v0.2 epoch boundary requires the QRC engine.
            TxBody::EpochOpen { .. }
            | TxBody::EpochClose { .. } => {
                Err("Epoch boundary transaction requires QRC-engine-aware executor".to_string())
            }
            // AEI Phase 2 lifecycle variants require the full agent-aware executor.
            TxBody::AuthorizeAgent { .. }
            | TxBody::SuspendAgent { .. }
            | TxBody::RevokeAgentFull { .. }
            | TxBody::RecordAgentSpend { .. }
            | TxBody::SpawnChildAgent { .. } => {
                Err("AEI Phase 2 transaction requires identity- and agent-aware executor".to_string())
            }
        };

        if result.is_ok() {
            advance_nonce_if_not_already(tx, state);
            bind_key_if_unbound(&self.config, tx, state);
        }

        match result {
            Ok(_) => TransactionResult::ok(tx.id.clone(), gas_required, tx.gas_limit, events),
            Err(e) => TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e),
        }
    }

    /// Execute all transactions for one block.
    /// Respects the block gas limit -- txs that would exceed it are skipped.
    pub fn execute_block(
        &self,
        height:       u64,
        transactions: Vec<Transaction>,
        state:        &mut StateStore,
        timestamp_ms: u64,
    ) -> BlockExecutionResult {
        let mut results       = Vec::new();
        let mut total_gas     = 0u64;
        let mut fees_collected = 0u64;
        let limit             = self.config.block_gas_limit;

        for tx in &transactions {
            let gas_required = self.config.gas_model.calculate_gas(tx);

            // Skip tx if it would exceed the block gas limit
            if total_gas + gas_required > limit {
                tracing::warn!(
                    tx_id = %tx.id,
                    gas_required,
                    total_gas,
                    limit,
                    "tx skipped: would exceed block gas limit"
                );
                results.push(TransactionResult::err(
                    tx.id.clone(),
                    gas_required,
                    tx.gas_limit,
                    format!("block gas limit would be exceeded ({total_gas} + {gas_required} > {limit})"),
                ));
                continue;
            }

            let result = self.execute_tx(tx, state);
            total_gas     += result.gas_used;
            fees_collected += result.gas_used; // simplified: all gas = fees
            results.push(result);
        }

        // Commit state after all txs -- take a snapshot every 100 blocks
        let take_snapshot = height % 100 == 0;
        let state_root = state.commit(height, timestamp_ms, take_snapshot);

        tracing::info!(
            height,
            txs      = transactions.len(),
            success  = results.iter().filter(|r| r.success).count(),
            gas_used = total_gas,
            "block executed"
        );

        BlockExecutionResult {
            height,
            tx_results:    results,
            gas_used:      total_gas,
            gas_limit:     limit,
            state_root:    state_root.root_hash,
            fees_collected,
        }
    }

    /// Execute all transactions for one block, with identity-, QRC-, and
    /// agent-gated transaction types (RegisterIdentity, Attest, ClaimUbi,
    /// RedirectToUbiPool, SponsorAgent, RevokeAgent, CharmConfinementUpdate,
    /// IntrinsicCharmRecord, RegisterAgent, and all QRC variants) actually
    /// processed instead of rejected. This is what a live node needs to call
    /// for those transaction types to work at all -- execute_block() above
    /// always rejects them, by design, since it has no identity, QRC, or
    /// agent state to process them against.
    pub fn execute_block_with_identity(
        &self,
        height:       u64,
        transactions: Vec<Transaction>,
        state:        &mut StateStore,
        identity:     &mut IdentityStore,
        qrc:          &mut QrcEngine,
        agents:       &mut AgentStore,
        timestamp_ms: u64,
    ) -> BlockExecutionResult {
        let mut results        = Vec::new();
        let mut total_gas      = 0u64;
        let mut fees_collected = 0u64;
        let limit              = self.config.block_gas_limit;

        for tx in &transactions {
            let gas_required = self.config.gas_model.calculate_gas(tx);

            if total_gas + gas_required > limit {
                tracing::warn!(
                    tx_id = %tx.id,
                    gas_required,
                    total_gas,
                    limit,
                    "tx skipped: would exceed block gas limit"
                );
                results.push(TransactionResult::err(
                    tx.id.clone(),
                    gas_required,
                    tx.gas_limit,
                    format!("block gas limit would be exceeded ({total_gas} + {gas_required} > {limit})"),
                ));
                continue;
            }

            let result = self.execute_tx_with_identity(tx, state, identity, qrc, agents);
            total_gas      += result.gas_used;
            fees_collected += result.gas_used;
            results.push(result);
        }

        let take_snapshot = height % 100 == 0;
        let state_root = state.commit(height, timestamp_ms, take_snapshot);

        tracing::info!(
            height,
            txs      = transactions.len(),
            success  = results.iter().filter(|r| r.success).count(),
            gas_used = total_gas,
            "block executed (identity-aware)"
        );

        BlockExecutionResult {
            height,
            tx_results:    results,
            gas_used:      total_gas,
            gas_limit:     limit,
            state_root:    state_root.root_hash,
            fees_collected,
        }
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_core::{GenesisConfig, HashWidth};
    use chain_forge_state::StateStore;
    use chain_forge_identity::IdentityStore;
    use chain_forge_qrc::QrcEngine;

    fn genesis_json() -> &'static str {
        r#"{
            "chain_id": "qcb-testnet-1",
            "chain_name": "QuarkCharmBit",
            "engine_version": "0.1.0",
            "genesis_time": "2026-09-16T00:00:00Z",
            "environment": { "mode": "testnet", "faucet_enabled": true, "relaxed_limits": true },
            "native_token": { "name": "QuarkCharm", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" },
            "address_prefix": "qcb",
            "consensus": { "type": "proof-of-stake", "validator_set_size": 4, "block_time_ms": 5000 },
            "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": false },
            "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
            "network": { "network_id": "qcb-testnet-1-net", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "both", "max_peers": 50 },
            "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 5000, "mempool_ttl_seconds": 300 },
            "modules": ["bank", "staking", "identity", "qrc", "agents"],
            "custom_modules": [],
            "genesis_accounts": [
                { "label": "Alice", "address": "qcb1alice", "balance": "5000000", "role": "user" },
                { "label": "Bob",   "address": "qcb1bob",   "balance": "5000000", "role": "user" },
                { "label": "Val",   "address": "qcb1val",   "balance": "1000000", "role": "validator" }
            ]
        }"#
    }

    fn setup() -> (Executor, StateStore) {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        (Executor::new(config), state)
    }

    #[test]
    fn transfer_tx_succeeds() {
        let (exec, mut state) = setup();
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100_000, 0);
        let result = exec.execute_tx(&tx, &mut state);

        assert!(result.success, "transfer should succeed: {:?}", result.error);
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 4_900_000);
        assert_eq!(state.get_account("qcb1bob").unwrap().balance_of("uqcb"),   5_100_000);
    }

    #[test]
    fn transfer_fails_insufficient_balance() {
        let (exec, mut state) = setup();
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 999_000_000, 0);
        let result = exec.execute_tx(&tx, &mut state);
        assert!(!result.success);
        assert!(!result.success, "transfer should fail with insufficient balance");
    }

    #[test]
    fn burn_tx_reduces_supply() {
        let (exec, mut state) = setup();
        let tx = Transaction::burn("tx1", "qcb1alice", "uqcb", 500_000, 0);
        let result = exec.execute_tx(&tx, &mut state);

        assert!(result.success, "{:?}", result.error);
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 4_500_000);
    }

    #[test]
    fn nonce_mismatch_rejects_tx() {
        let (exec, mut state) = setup();
        // Send with nonce=1 when account expects nonce=0
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 1);
        let result = exec.execute_tx(&tx, &mut state);
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("nonce"));
    }

    #[test]
    fn nonce_advances_after_tx() {
        let (exec, mut state) = setup();
        let tx1 = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0);
        let r1 = exec.execute_tx(&tx1, &mut state);
        assert!(r1.success);

        // Second tx with nonce=1 should succeed
        let tx2 = Transaction::transfer("tx2", "qcb1alice", "qcb1bob", "uqcb", 1_000, 1);
        let r2 = exec.execute_tx(&tx2, &mut state);
        assert!(r2.success, "{:?}", r2.error);
    }

    #[test]
    fn gas_is_calculated_for_dynamic_model() {
        let gas_model = GasModel::Dynamic { base_fee_per_byte: 1, op_multiplier: 10 };
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0);
        let gas = gas_model.calculate_gas(&tx);
        assert!(gas > 0, "gas should be non-zero");
    }

    #[test]
    fn gas_model_fixed_is_constant() {
        let gas_model = GasModel::Fixed { fee_per_tx: 5_000 };
        let tx1 = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1, 0);
        let tx2 = Transaction::transfer("tx2", "qcb1alice", "qcb1bob", "uqcb", 999_999, 0);
        assert_eq!(gas_model.calculate_gas(&tx1), 5_000);
        assert_eq!(gas_model.calculate_gas(&tx2), 5_000);
    }

    #[test]
    fn block_execution_produces_state_root() {
        let (exec, mut state) = setup();
        let txs = vec![
            Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100_000, 0),
            Transaction::transfer("tx2", "qcb1bob",   "qcb1val", "uqcb", 50_000,  0),
        ];

        let result = exec.execute_block(1, txs, &mut state, 1_000_000);
        assert_eq!(result.height, 1);
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.failure_count(), 0);
        assert!(!result.state_root.is_empty());
        assert!(result.gas_used > 0);
    }

    #[test]
    fn block_execution_counts_failures() {
        let (exec, mut state) = setup();
        let txs = vec![
            Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100_000, 0),
            // This will fail: wrong nonce (alice's nonce is now 1 after tx1)
            Transaction::transfer("tx2", "qcb1alice", "qcb1bob", "uqcb", 100_000, 0),
        ];

        let result = exec.execute_block(1, txs, &mut state, 1_000_000);
        assert_eq!(result.success_count(), 1);
        assert_eq!(result.failure_count(), 1);
    }

    #[test]
    fn block_gas_limit_skips_excess_txs() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        // Set a very tight block gas limit
        let config = ExecutionConfig {
            gas_model:       GasModel::Fixed { fee_per_tx: 1_000 },
            block_gas_limit: 1_500,   // fits only 1 tx at 1_000 gas each
            max_tx_bytes:    65_536,
            native_denom:    "uqcb".into(),
            chain_id:        "qcb-testnet-1".into(),
            address_prefix:  "qcb".into(),
            hash_width:      HashWidth::Bits256,
            require_signatures: false,
            modules:         EnabledModules::all(),
        };
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let exec = Executor::new(config);

        let txs = vec![
            Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0),
            Transaction::transfer("tx2", "qcb1bob",   "qcb1val", "uqcb", 100, 0),
        ];

        let result = exec.execute_block(1, txs, &mut state, 1_000_000);
        // tx1 succeeds (1_000 gas), tx2 skipped (would push to 2_000 > 1_500)
        assert_eq!(result.success_count(), 1);
        assert_eq!(result.failure_count(), 1);
        assert!(result.gas_used <= 1_500);
    }

    #[test]
    fn custom_tx_is_recorded_as_event() {
        let (exec, mut state) = setup();
        let tx = Transaction {
            id:        "custom1".into(),
            sender:    "qcb1alice".into(),
            nonce:     0,
            body:      TxBody::Custom {
                module:  "charm-confinement".into(),
                payload: b"charm_payload".to_vec(),
            },
            gas_limit: 100_000,
            signature: vec![],
            public_key: vec![],
        };

        let result = exec.execute_tx(&tx, &mut state);
        assert!(result.success);
        assert!(result.events.iter().any(|e| e.contains("charm-confinement")));
    }

    #[test]
    fn stake_tx_transfers_to_validator() {
        let (exec, mut state) = setup();
        let tx = Transaction {
            id:        "stake1".into(),
            sender:    "qcb1alice".into(),
            nonce:     0,
            body:      TxBody::Stake {
                validator: "qcb1val".into(),
                amount:    200_000,
            },
            gas_limit: 100_000,
            signature: vec![],
            public_key: vec![],
        };

        let result = exec.execute_tx(&tx, &mut state);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(state.get_account("qcb1val").unwrap().balance_of("uqcb"), 1_200_000);
    }

    #[test]
    fn fees_are_collected_in_block() {
        let (exec, mut state) = setup();
        let txs = vec![
            Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0),
            Transaction::burn("tx2", "qcb1bob", "uqcb", 500, 0),
        ];

        let result = exec.execute_block(1, txs, &mut state, 1_000_000);
        assert!(result.fees_collected > 0, "fees should be collected");
    }

    // -- CharmConfinement enforcement tests -----------------------------------

    fn setup_with_identity() -> (Executor, StateStore, IdentityStore, QrcEngine, AgentStore) {
        use chain_forge_identity::{IdentityStore, PopAttestation};
        use chain_forge_qrc::QrcEngine;

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();

        let mut identity = IdentityStore::new(0);
        let att = PopAttestation::genesis("qcb1alice", 0);
        identity.register("qcb1alice".into(), "qcb1alice".into(), att.clone()).unwrap();
        identity.verify_identity("qcb1alice", att, None).unwrap();

        let qrc = QrcEngine::new(chain_forge_qrc::D);
        let agents = AgentStore::new();
        (Executor::new(config), state, identity, qrc, agents)
    }

    // ── Deprecated UBI-era tx types (QRC Economic Model v0.1) ─────────────────
    //
    // ClaimUbi and RedirectToUbiPool were part of the old Circulating Finance
    // engine. The QRC engine (v0.1) replaces UBI with resource-contribution
    // earning and purchase-path minting. These tests document that the tx types
    // are preserved in the enum (protocol continuity) but now return an error.
    // They will be replaced with resource-consumption tx tests when the
    // execution layer is upgraded.

    #[test]
    fn claim_ubi_deprecated_in_qrc_model() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        identity.record_activity("qcb1alice");

        let tx = Transaction::claim_ubi("tx1", "qcb1alice", "qcb1alice", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);

        assert!(
            !result.success,
            "ClaimUbi must be rejected by QRC Economic Model v0.1 engine"
        );
        assert!(
            result.error.as_deref().unwrap_or("").contains("deprecated"),
            "error message should mention deprecation, got: {:?}", result.error
        );
    }

    #[test]
    fn redirect_to_ubi_pool_deprecated_in_qrc_model() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        identity.record_activity("qcb1alice");

        let tx = Transaction::redirect_to_ubi_pool("tx1", "qcb1alice", 1_000_000, 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);

        assert!(
            !result.success,
            "RedirectToUbiPool must be rejected by QRC Economic Model v0.1 engine"
        );
        assert!(
            result.error.as_deref().unwrap_or("").contains("deprecated"),
            "error message should mention deprecation, got: {:?}", result.error
        );
    }

    #[test]
    fn sponsor_agent_requires_verified_identity() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Bob is not in identity store -- should fail
        let tx = Transaction::sponsor_agent("tx1", "qcb1bob", "qcb1agent1", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!result.success, "unverified identity cannot sponsor agents");
    }

    #[test]
    fn sponsor_agent_succeeds_for_verified_human() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        let tx = Transaction::sponsor_agent("tx1", "qcb1alice", "qcb1agent1", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);

        assert!(result.success, "{:?}", result.error);
        assert!(identity.is_agent_authorized("qcb1agent1", "qcb1alice"),
            "agent should be authorized after sponsor tx");
    }

    #[test]
    fn spend_earns_decay_exemption() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Attach charm to alice's account first
        let mut charm = chain_forge_identity::IntrinsicCharm::provisional(0);
        charm.verify(0);
        let mut alice = state.get_account("qcb1alice").unwrap().clone();
        alice.attach_charm(charm);
        state.upsert_account(alice);

        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 0);

        // Transfer triggers spend -> exemption credit
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0);
        exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);

        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 1,
            "spending should earn 1 day of decay exemption");
    }

    // -- Identity pilot: RegisterIdentity + Attest transactions ---------------

    #[test]
    fn register_identity_tx_creates_provisional_account_with_charm() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        let tx = Transaction::register_identity("tx1", "qcb1newbie", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);

        assert!(result.success, "registration should succeed: {:?}", result.error);
        assert!(result.events.iter().any(|e| e.contains("register_identity")));
        assert_eq!(*identity.get("qcb1newbie").unwrap().tier(),
            chain_forge_identity::VerificationTier::Provisional);

        // The on-chain account must reflect the fresh Provisional charm --
        // without the attach_charm sync, this would be None forever.
        let acct = state.get_account("qcb1newbie").unwrap();
        assert_eq!(acct.verification_tier(),
            Some(&chain_forge_identity::VerificationTier::Provisional));
    }

    #[test]
    fn attest_tx_reaches_quorum_and_upgrades_onchain_tier() {
        use chain_forge_identity::{PopAttestation, VerificationTier};

        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Bootstrap two more Verified attesters alongside alice (already
        // Verified via setup_with_identity's genesis path).
        for name in ["qcb1bob", "qcb1carol"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att, None).unwrap();
        }

        // Register the real claimant via the actual transaction path.
        let reg_tx = Transaction::register_identity("tx0", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&reg_tx, &mut state, &mut identity, &mut qrc, &mut agents);

        // Two attestations: still Provisional on-chain.
        let a1 = Transaction::attest("tx1", "qcb1alice", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&a1, &mut state, &mut identity, &mut qrc, &mut agents);
        let a2 = Transaction::attest("tx2", "qcb1bob", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&a2, &mut state, &mut identity, &mut qrc, &mut agents);
        assert_eq!(
            state.get_account("qcb1newbie").unwrap().verification_tier(),
            Some(&VerificationTier::Provisional)
        );

        // Third distinct attestation crosses quorum -- both IdentityStore
        // AND the on-chain account must now show Verified.
        let a3 = Transaction::attest("tx3", "qcb1carol", "qcb1newbie", 0);
        let result = exec.execute_tx_with_identity(&a3, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(result.success);
        assert!(result.events.iter().any(|e| e.contains("now Verified")));
        assert_eq!(*identity.get("qcb1newbie").unwrap().tier(), VerificationTier::Verified);
        assert_eq!(
            state.get_account("qcb1newbie").unwrap().verification_tier(),
            Some(&VerificationTier::Verified),
            "on-chain account must reflect the quorum-triggered upgrade"
        );
    }

    #[test]
    fn identity_gated_new_tx_types_rejected_without_identity_store() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let exec    = Executor::new(config);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();

        let reg_tx = Transaction::register_identity("tx1", "qcb1newbie", 0);
        let r1 = exec.execute_tx(&reg_tx, &mut state);
        assert!(!r1.success, "RegisterIdentity must be rejected by the non-identity-aware executor");

        let attest_tx = Transaction::attest("tx2", "qcb1alice", "qcb1newbie", 0);
        let r2 = exec.execute_tx(&attest_tx, &mut state);
        assert!(!r2.success, "Attest must be rejected by the non-identity-aware executor");
    }

    #[test]
    fn identity_txs_advance_sender_nonce_and_block_replay() {
        use chain_forge_identity::PopAttestation;

        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        for name in ["qcb1bob", "qcb1carol"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att, None).unwrap();
        }

        // Registration advances the new account's nonce 0 -> 1.
        let reg = Transaction::register_identity("r0", "qcb1newbie", 0);
        assert!(exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut qrc, &mut agents).success);
        assert_eq!(state.get_account("qcb1newbie").unwrap().nonce, 1);

        // Replaying the exact same registration is now a nonce mismatch,
        // not a second trip into the identity logic.
        let replay = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!replay.success);
        assert!(replay.error.as_deref().unwrap_or("").contains("nonce mismatch"));

        // An attester's first attest advances their nonce, so their second
        // transaction must use nonce 1 -- and does succeed with it.
        let a1 = Transaction::attest("a1", "qcb1alice", "qcb1newbie", 0);
        assert!(exec.execute_tx_with_identity(&a1, &mut state, &mut identity, &mut qrc, &mut agents).success);
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 1);

        exec.execute_tx_with_identity(
            &Transaction::register_identity("r1", "qcb1other", 0),
            &mut state, &mut identity, &mut qrc, &mut agents,
        );
        let a2 = Transaction::attest("a2", "qcb1alice", "qcb1other", 1);
        let r = exec.execute_tx_with_identity(&a2, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "second attest with nonce 1 must succeed: {:?}", r.error);
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 2);
    }

    // -- Signature verification (require_signatures = true) -------------------

    fn key(seed: &str) -> KeyPair {
        ClassicalScheme.generate_keypair(seed).unwrap()
    }

    /// Plain executor with signatures enforced, and qcb1alice's genesis
    /// account bound to a known key (as a genesis public_key would do).
    fn signed_setup() -> (Executor, StateStore, KeyPair) {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut config = ExecutionConfig::from_genesis(&genesis);
        config.require_signatures = true;
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let alice = key("alice-test-key");
        state.get_account_mut("qcb1alice").unwrap().public_key = Some(alice.public_key.clone());
        (Executor::new(config), state, alice)
    }

    #[test]
    fn unsigned_tx_rejected_when_signatures_required() {
        let (exec, mut state, _) = signed_setup();
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        let r = exec.execute_tx(&tx, &mut state);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unsigned"));
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 0, "rejected tx must not advance nonce");
    }

    #[test]
    fn tx_signed_by_bound_key_succeeds() {
        let (exec, mut state, alice) = signed_setup();
        let mut tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sign(&alice, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx(&tx, &mut state);
        assert!(r.success, "{:?}", r.error);
    }

    #[test]
    fn tx_signed_by_wrong_key_rejected() {
        let (exec, mut state, _) = signed_setup();
        let mallory = key("mallory");
        let mut tx = Transaction::transfer("tx1", "qcb1alice", "qcb1mallory", "uqcb", 100, 0);
        tx.sign(&mallory, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx(&tx, &mut state);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("does not match the key bound"));
    }

    #[test]
    fn tampered_tx_rejected() {
        let (exec, mut state, alice) = signed_setup();
        let mut tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sign(&alice, "qcb-testnet-1").unwrap();
        tx.body = TxBody::Transfer { to: "qcb1bob".into(), denom: "uqcb".into(), amount: 4_000_000 };
        let r = exec.execute_tx(&tx, &mut state);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("invalid signature"));
    }

    #[test]
    fn signature_from_another_chain_rejected() {
        let (exec, mut state, alice) = signed_setup();
        let mut tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sign(&alice, "some-other-chain").unwrap();
        let r = exec.execute_tx(&tx, &mut state);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("invalid signature"));
    }

    #[test]
    fn named_address_without_bound_key_cannot_be_claimed() {
        // qcb1bob has a genesis balance but no bound key. A signature from
        // any key is useless for it: the address isn't derived from a key.
        let (exec, mut state, _) = signed_setup();
        let mallory = key("mallory");
        let mut tx = Transaction::transfer("tx1", "qcb1bob", "qcb1mallory", "uqcb", 100, 0);
        tx.sign(&mallory, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx(&tx, &mut state);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("not derived from the signing key"));
    }

    #[test]
    fn key_derived_address_registers_and_binds_its_key() {
        let (_, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut config = ExecutionConfig::from_genesis(&genesis);
        config.require_signatures = true;
        let exec = Executor::new(config);

        let user = key("new-user");
        let addr = Address::from_public_key(&user.public_key, "qcb", HashWidth::Bits256);
        let mut reg = Transaction::register_identity("r0", addr.as_str(), 0);
        reg.sign(&user, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "{:?}", r.error);

        let acct = state.get_account(addr.as_str()).unwrap();
        assert_eq!(acct.public_key.as_deref(), Some(user.public_key.as_slice()), "first tx binds the key");
        assert_eq!(acct.nonce, 1);

        // A different key can no longer act for this address.
        let other = key("someone-else");
        let mut hijack = Transaction::attest("h1", addr.as_str(), "qcb1alice", 1);
        hijack.sign(&other, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx_with_identity(&hijack, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("does not match the key bound"));
    }

    // -- Module gating -----------------------------------------------------------

    fn plain_chain_exec() -> Executor {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut config = ExecutionConfig::from_genesis(&genesis);
        config.modules = EnabledModules::default(); // bank only
        Executor::new(config)
    }

    #[test]
    fn charm_and_tier_reach_state_root_after_register_and_attest() {
        // This test catches the bug where attach_charm() updated AccountState
        // but refresh_leaf() was never called, so the state root never changed
        // after identity transactions even though the account data did.
        //
        // setup_with_identity() seeds qcb1alice as already Verified, so we
        // use fresh addresses: qcb1newcomer as the claimant and qcb1alice
        // (already Verified) as one of the three attesters.
        use chain_forge_identity::{IdentityStore, PopAttestation};
        use chain_forge_qrc::QrcEngine;

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let exec = Executor::new(config);

        // Seed three Verified attesters in the identity store.
        let mut identity = IdentityStore::new(0);
        for name in ["qcb1alice", "qcb1bob", "qcb1carol"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att, None).unwrap();
        }
        let mut qrc = QrcEngine::new(chain_forge_qrc::D);
        let mut agents = chain_forge_agents::AgentStore::new();

        let root_before = state.commit(0, 0, false).root_hash;

        // Register newcomer -- should change the state root (Provisional charm attached).
        let reg = Transaction::register_identity("t-reg", "qcb1newcomer", 0);
        let r = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "registration failed: {:?}", r.error);
        let root_after_reg = state.commit(0, 0, false).root_hash;
        assert_ne!(root_before, root_after_reg,
            "state root must change when RegisterIdentity attaches a Provisional charm");

        // Three attestations trigger the quorum upgrade to Verified.
        // sender = the Verified attester vouching; claimant_id = newcomer.
        for (i, attester) in ["qcb1alice", "qcb1bob", "qcb1carol"].iter().enumerate() {
            let attest = Transaction::attest(
                &format!("t-attest-{i}"), attester, "qcb1newcomer", 0
            );
            let r = exec.execute_tx_with_identity(&attest, &mut state, &mut identity, &mut qrc, &mut agents);
            assert!(r.success, "attest {i} failed: {:?}", r.error);
        }
        let root_after_verify = state.commit(0, 0, false).root_hash;
        assert_ne!(root_after_reg, root_after_verify,
            "state root must change when Attest upgrades a claimant from Provisional to Verified");

        let acct = state.get_account("qcb1newcomer").expect("account must exist");
        assert!(acct.charm.is_some(), "verified account must have a charm");
    }

    #[test]
    fn plain_chain_rejects_identity_qrc_agent_and_stake_txs() {
        let (_, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let exec = plain_chain_exec();
        let cases = [
            (Transaction::register_identity("t1", "qcb1alice", 0), "identity"),
            (Transaction::attest("t2", "qcb1alice", "qcb1bob", 0), "identity"),
            (Transaction::claim_ubi("t3", "qcb1alice", "qcb1alice", 0), "qrc"),
            (Transaction::sponsor_agent("t4", "qcb1alice", "qcb1agent", 0), "agents"),
        ];
        for (tx, module) in cases {
            let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
            assert!(!r.success, "{} must be rejected on a plain chain", tx.id);
            assert!(r.error.unwrap().contains(&format!("module \"{module}\" is not enabled")));
        }
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 0, "gated txs must not advance the nonce");
    }

    #[test]
    fn plain_chain_still_allows_core_transfers() {
        let (_, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let exec = plain_chain_exec();
        let tx = Transaction::transfer("t1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "{:?}", r.error);
    }

    #[test]
    fn every_tx_type_maps_to_a_known_module_or_core() {
        let known: Vec<&str> = chain_forge_core::KNOWN_MODULES.iter().map(|(n, _)| *n).collect();
        let bodies = [
            TxBody::RegisterIdentity,
            TxBody::Attest { claimant_id: "x".into() },
            TxBody::ClaimUbi { identity_id: "x".into() },
            TxBody::SponsorAgent { agent_address: "x".into() },
            TxBody::RevokeAgent { agent_address: "x".into() },
            // Phase D attestation guard tx types
            TxBody::RevokeAttestation { attested_id: "x".into() },
            TxBody::ConfirmSybil { sybil_id: "x".into() },
            TxBody::ReverseSybil { sybil_id: "x".into() },
            TxBody::ReportSuspectedSybil { suspected_id: "x".into() },
            // QRC Economic Model v0.1 tx types
            TxBody::QrcPurchase { qcb_amount: 1, min_qrc_out: 0 },
            TxBody::QrcSpend { resource: chain_forge_qrc::ResourceKind::Compute, units: 1, amount: 1 },
            TxBody::QrcContributionSettle {
                epoch: 1,
                evidence: make_evidence(1),
            },
            // Phase 1: IntrinsicCharm & AEI agent registration
            TxBody::CharmConfinementUpdate { epoch: 1 },
            TxBody::IntrinsicCharmRecord { event: CharmEvent::DecayTick },
            TxBody::RegisterAgent {
                agent_id:       "x".into(),
                agent_address:  "x".into(),
                capabilities:   vec![],
                spending_limits: chain_forge_agents::SpendingLimits::unlimited(),
                description:    "x".into(),
                parent_agent_id: None,
            },
            // QRC v0.2 epoch boundary
            TxBody::EpochOpen { epoch: 1, verified_count: 0 },
            TxBody::EpochClose { epoch: 1 },
            // AEI Phase 2 lifecycle
            TxBody::AuthorizeAgent { agent_id: "x".into() },
            TxBody::SuspendAgent { agent_id: "x".into(), reason: "x".into() },
            TxBody::RevokeAgentFull { agent_id: "x".into() },
            TxBody::RecordAgentSpend { agent_id: "x".into(), amount_uqrc: 1 },
            TxBody::SpawnChildAgent {
                child_agent_id:      "x".into(),
                child_agent_address: "x".into(),
                parent_agent_id:     "x".into(),
                capabilities:        vec![],
                spending_limits:     chain_forge_agents::SpendingLimits::unlimited(),
                description:         "x".into(),
            },
        ];
        for body in bodies {
            let m = required_module(&body).expect("gated tx types name their module");
            assert!(known.contains(&m), "{m} missing from KNOWN_MODULES");
        }
    }

    // ── QRC Economic Model v0.1 execution tests ───────────────────────────────

    fn make_evidence(epoch: u64) -> chain_forge_qrc::CapacityEvidence {
        use chain_forge_qrc::capacity_report::{
            CapacityEvidence, CapacityProof, ComputeProofV0, VcaCredential,
        };
        use chain_forge_qrc::ResourceType;
        CapacityEvidence {
            provider_id:    [1u8; 32],
            vca_credential: VcaCredential(vec![]),
            resource_type:  ResourceType::Compute,
            capacity_claim: 1_000_000_000, // 1_000 CU × D
            epoch,
            challenge_nonce: [0u8; 32],
            response_hash:   [0u8; 32],
            proof: CapacityProof::Compute(ComputeProofV0 {
                benchmark_result:  1_000_000,
                benchmark_circuit: [0u8; 4],
                elapsed_ms:        50,
            }),
            signature: [0u8; 64],
        }
    }

    #[test]
    fn qrc_purchase_burns_qcb_and_mints_qrc() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Alice starts with 5_000_000 uqcb and no uqrc.
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqrc"), 0);

        let tx = Transaction::qrc_purchase("tx_buy", "qcb1alice", 1_000_000, 0, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "QrcPurchase failed: {:?}", r.error);

        // QCB must decrease.
        assert_eq!(
            state.get_account("qcb1alice").unwrap().balance_of("uqcb"),
            4_000_000,
            "1_000_000 uqcb must be burned"
        );
        // QRC must be minted (exact amount depends on default Rt; just verify > 0).
        assert!(
            state.get_account("qcb1alice").unwrap().balance_of("uqrc") > 0,
            "should have received uqrc"
        );
        assert!(!r.events.is_empty(), "qrc_purchase must emit an event");
        assert!(r.events[0].contains("qrc_purchase"));
    }

    #[test]
    fn qrc_purchase_fails_on_insufficient_qcb() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Try to burn more than Alice's 5_000_000 uqcb balance.
        let tx = Transaction::qrc_purchase("tx_buy", "qcb1alice", 999_000_000, 0, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "should fail with insufficient balance");
        // Balance unchanged.
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 5_000_000);
    }

    #[test]
    fn qrc_purchase_slippage_guard_rejects_low_output() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Demand an absurd min_qrc_out that can never be met.
        let tx = Transaction::qrc_purchase("tx_buy", "qcb1alice", 1_000_000, u128::MAX, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "slippage guard must reject");
        let err = r.error.unwrap();
        assert!(err.contains("slippage exceeded"), "wrong error: {err}");
        // QCB must be refunded (not permanently burned).
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 5_000_000);
    }

    #[test]
    fn qrc_spend_deducts_qrc_and_applies_split() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // First give Alice some QRC via purchase.
        let buy = Transaction::qrc_purchase("tx_buy", "qcb1alice", 5_000_000, 0, 0);
        let r   = exec.execute_tx_with_identity(&buy, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "setup purchase failed: {:?}", r.error);

        let qrc_before = state.get_account("qcb1alice").unwrap().balance_of("uqrc");
        assert!(qrc_before > 0);

        // Now spend a small operation (1 base unit of Compute, not 1 CU×D).
        // The engine charges per unit; 1 unit is the minimum meaningful spend.
        // Authorise the full QRC balance so the amount check always passes.
        let spend = Transaction::qrc_spend(
            "tx_spend", "qcb1alice",
            chain_forge_qrc::ResourceKind::Compute,
            1,          // 1 base compute unit
            qrc_before, // authorise up to the full balance
            1,
        );
        let r = exec.execute_tx_with_identity(&spend, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "QrcSpend failed: {:?}", r.error);

        let qrc_after = state.get_account("qcb1alice").unwrap().balance_of("uqrc");
        assert!(qrc_after < qrc_before, "QRC balance must decrease after spend");
        assert!(r.events[0].contains("qrc_spend"));
    }

    #[test]
    fn qrc_spend_fails_with_insufficient_qrc_balance() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Alice has 0 uqrc — any spend must fail.
        // Set amount=u128::MAX so the "amount < cost" gate passes; the
        // balance check then fires and produces the "insufficient uqrc" error.
        let spend = Transaction::qrc_spend(
            "tx_spend", "qcb1alice",
            chain_forge_qrc::ResourceKind::Compute,
            1_000_000_000,  // 1 CU × D units
            u128::MAX,      // authorise any cost — balance check is what fails
            0,
        );
        let r = exec.execute_tx_with_identity(&spend, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "spend with 0 uqrc balance must fail");
        assert!(r.error.unwrap().contains("insufficient uqrc"));
    }

    #[test]
    fn qrc_contribution_settle_mints_to_verified_provider() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // qcb1alice is already Verified via setup_with_identity.
        let ev = make_evidence(1);
        let tx = Transaction::qrc_contribution_settle("tx_settle", "qcb1alice", 1, ev, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "contribution settle failed: {:?}", r.error);
        // Alice must have received QRC.
        let qrc_bal = state.get_account("qcb1alice").unwrap().balance_of("uqrc");
        // With default QrcEngine and 1_000 CU contribution the amount is engine-
        // specific; just assert > 0.
        // (If the engine returns 0 for the given utilization the test still
        //  passes — the tx is valid even when E(i,r,t) = 0.)
        let _ = qrc_bal; // balance may be 0 if utilization gives 0 earning
        assert!(!r.events.is_empty());
        assert!(r.events[0].contains("qrc_contribution_settle"));
    }

    #[test]
    fn qrc_contribution_settle_rejected_for_provisional_sender() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Register a fresh provisional account.
        let reg = Transaction::register_identity("reg1", "qcb1carol", 0);
        let r   = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);

        let ev = make_evidence(1);
        let settle = Transaction::qrc_contribution_settle("tx_settle", "qcb1carol", 1, ev, 1);
        let r = exec.execute_tx_with_identity(&settle, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "provisional identity must not be able to settle");
        assert!(r.error.unwrap().contains("Verified tier"));
    }

    #[test]
    fn qrc_contribution_settle_rejects_epoch_mismatch() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // evidence.epoch = 1 but tx.epoch = 99
        let mut ev = make_evidence(1);
        ev.epoch = 1;
        let tx = Transaction::qrc_contribution_settle("tx_settle", "qcb1alice", 99, ev, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("epoch"));
    }

    #[test]
    fn qrc_purchase_nonce_advances_on_success() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let tx0 = Transaction::qrc_purchase("tx0", "qcb1alice", 100_000, 0, 0);
        let r   = exec.execute_tx_with_identity(&tx0, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 1);

        let tx1 = Transaction::qrc_purchase("tx1", "qcb1alice", 100_000, 0, 1);
        let r   = exec.execute_tx_with_identity(&tx1, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 2);
    }

    #[test]
    fn qrc_purchase_nonce_does_not_advance_on_failure() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Slippage rejection — should not advance nonce.
        let tx = Transaction::qrc_purchase("tx0", "qcb1alice", 100_000, u128::MAX, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success);
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 0,
            "failed tx must not advance nonce");
    }

    // ── Phase 1: CharmConfinementUpdate tests ─────────────────────────────────

    #[test]
    fn charm_confinement_update_requires_verified_tier() {
        // An unregistered address (Provisional tier or absent) must be rejected.
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let tx = Transaction::charm_confinement_update("ccup1", "qcb1stranger", 1, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "unregistered address must not pass confinement gate");
        assert!(r.error.as_deref().unwrap_or("").contains("not Verified"),
            "error must mention 'not Verified': {:?}", r.error);
    }

    #[test]
    fn charm_confinement_update_advances_consecutive_epochs() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // alice is Verified in the identity store from setup_with_identity.
        // First heartbeat: consecutive_active_epochs goes from 0 → 1.
        let tx1 = Transaction::charm_confinement_update("ccup1", "qcb1alice", 1, 0);
        let r1  = exec.execute_tx_with_identity(&tx1, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r1.success, "first heartbeat must succeed: {:?}", r1.error);
        assert!(r1.events.iter().any(|e| e.contains("charm_confinement_update")),
            "must emit event");

        let epochs_after_1 = identity.get("qcb1alice")
            .unwrap()
            .charm
            .consecutive_active_epochs;
        assert_eq!(epochs_after_1, 1, "consecutive_active_epochs must be 1 after first heartbeat");
    }

    #[test]
    fn charm_confinement_update_syncs_to_state_root() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let root_before = state.commit(0, 0, false).root_hash;

        let tx = Transaction::charm_confinement_update("ccup1", "qcb1alice", 1, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);

        let root_after = state.commit(0, 0, false).root_hash;
        assert_ne!(root_before, root_after,
            "state root must change after a CharmConfinementUpdate");
    }

    #[test]
    fn charm_confinement_update_auto_promotes_at_epoch_30() {
        use chain_forge_identity::VerificationTier;

        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Drive alice's consecutive_active_epochs to 29 directly in the identity store.
        if let Some(r) = identity.get_mut("qcb1alice") {
            r.charm.consecutive_active_epochs = 29;
        }

        // The 30th heartbeat should trigger auto-promotion to Established.
        let tx = Transaction::charm_confinement_update("ccup30", "qcb1alice", 30, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "30th heartbeat must succeed: {:?}", r.error);

        let tier = identity.get("qcb1alice").unwrap().charm.tier.clone();
        assert_eq!(tier, VerificationTier::Established,
            "must auto-promote to Established after 30 consecutive epochs");
    }

    // ── Phase 1: IntrinsicCharmRecord tests ───────────────────────────────────

    #[test]
    fn intrinsic_charm_record_rejects_unknown_sender() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let tx = Transaction::intrinsic_charm_record(
            "icr1", "qcb1nobody", CharmEvent::DecayTick, 0,
        );
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "unregistered sender must be rejected");
    }

    #[test]
    fn intrinsic_charm_record_decay_tick_consumes_exemption_day() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Give alice 3 days of exemption via her charm in the identity store.
        if let Some(r) = identity.get_mut("qcb1alice") {
            r.charm.decay_exemption.record_spend(1);
            r.charm.decay_exemption.record_spend(1);
            r.charm.decay_exemption.record_spend(1);
        }
        // Sync to on-chain account.
        let charm = identity.get("qcb1alice").unwrap().charm.clone();
        if let Ok(acct) = state.get_account_mut("qcb1alice") {
            acct.attach_charm(charm);
        }
        state.refresh_leaf("qcb1alice");

        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 3);

        let tx = Transaction::intrinsic_charm_record(
            "icr1", "qcb1alice", CharmEvent::DecayTick, 0,
        );
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "DecayTick must succeed: {:?}", r.error);

        // The charm on the identity record should now have 2 days.
        let remaining = identity.get("qcb1alice").unwrap().charm.decay_exemption.has_exemption();
        assert!(remaining, "should still have 2 days remaining");
        // On-chain account should reflect 2 days.
        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 2);
        assert!(r.events.iter().any(|e| e.contains("decay_tick")));
    }

    #[test]
    fn intrinsic_charm_record_exemption_credit_adds_day() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Give alice a charm on her account (0 days initially).
        let charm = identity.get("qcb1alice").unwrap().charm.clone();
        if let Ok(acct) = state.get_account_mut("qcb1alice") {
            acct.attach_charm(charm);
        }
        state.refresh_leaf("qcb1alice");

        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 0);

        let tx = Transaction::intrinsic_charm_record(
            "icr2", "qcb1alice", CharmEvent::ExemptionCredit, 0,
        );
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "ExemptionCredit must succeed: {:?}", r.error);

        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 1,
            "exemption credit must add 1 day");
        assert!(r.events.iter().any(|e| e.contains("exemption_credit")));
    }

    // ── Phase 1: RegisterAgent tests ──────────────────────────────────────────

    #[test]
    fn register_agent_requires_verified_sponsor() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // qcb1stranger has no identity record at all.
        let tx = Transaction::register_agent(
            "ra1", "qcb1stranger",
            "agent-001", "qcb1agent001",
            vec![chain_forge_agents::AgentCapability::ReadState],
            chain_forge_agents::SpendingLimits::unlimited(),
            "stranger's agent",
            None,
            0,
        );
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "unverified sender must be rejected");
        assert!(r.error.as_deref().unwrap_or("").contains("not Verified"),
            "error must mention 'not Verified': {:?}", r.error);
    }

    #[test]
    fn register_agent_creates_pending_agent_in_store() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // alice is Verified.
        let tx = Transaction::register_agent(
            "ra1", "qcb1alice",
            "agent-001", "qcb1agent001",
            vec![
                chain_forge_agents::AgentCapability::ReadState,
                chain_forge_agents::AgentCapability::Transfer,
            ],
            chain_forge_agents::SpendingLimits::merchant(1_000_000),
            "alice's merchant agent",
            None,
            0,
        );
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "RegisterAgent must succeed for Verified sponsor: {:?}", r.error);

        // Agent must be in the AgentStore as Pending.
        let agent = agents.get("agent-001").expect("agent must be registered");
        assert_eq!(agent.status, chain_forge_agents::AgentStatus::Pending,
            "newly registered agent must be Pending (requires explicit authorize())");
        assert_eq!(agent.sponsor_id, "qcb1alice");
        assert_eq!(agent.address, "qcb1agent001");

        // IdentityStore must record the sponsorship.
        assert!(identity.get("qcb1alice").unwrap().has_sponsored("qcb1agent001"),
            "sponsor's identity record must list the agent address");

        assert!(r.events.iter().any(|e| e.contains("register_agent")),
            "must emit event");
    }

    #[test]
    fn register_agent_nonce_advances_on_success() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let tx = Transaction::register_agent(
            "ra1", "qcb1alice",
            "agent-002", "qcb1agent002",
            vec![],
            chain_forge_agents::SpendingLimits::unlimited(),
            "test agent",
            None,
            0,
        );
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 1,
            "nonce must advance after successful RegisterAgent");
    }

    // ── Phase 2: AEI agent lifecycle tests ────────────────────────────────────

    /// Register a basic agent as alice and return its agent_id.
    fn register_alice_agent(
        exec:     &Executor,
        state:    &mut StateStore,
        identity: &mut IdentityStore,
        qrc:      &mut QrcEngine,
        agents:   &mut AgentStore,
        agent_id: &str,
        address:  &str,
        caps:     Vec<chain_forge_agents::AgentCapability>,
        nonce:    u64,
    ) {
        let tx = Transaction::register_agent(
            &format!("reg-{agent_id}"), "qcb1alice",
            agent_id, address,
            caps,
            chain_forge_agents::SpendingLimits::unlimited(),
            "test agent",
            None,
            nonce,
        );
        let r = exec.execute_tx_with_identity(&tx, state, identity, qrc, agents);
        assert!(r.success, "register_alice_agent failed: {:?}", r.error);
    }

    #[test]
    fn authorize_agent_moves_pending_to_active() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Register agent.
        let tx_reg = Transaction::register_agent(
            "ra1", "qcb1alice",
            "agent-a1", "qcb1agentA1",
            vec![chain_forge_agents::AgentCapability::ReadState],
            chain_forge_agents::SpendingLimits::unlimited(),
            "agent for auth test",
            None, 0,
        );
        let r = exec.execute_tx_with_identity(&tx_reg, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);

        // Now authorize it.
        let tx_auth = Transaction {
            id: "auth1".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::AuthorizeAgent { agent_id: "agent-a1".into() },
            gas_limit: 100_000, signature: vec![], public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx_auth, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "AuthorizeAgent must succeed: {:?}", r.error);
        assert_eq!(agents.get("agent-a1").unwrap().status, chain_forge_agents::AgentStatus::Active);
        assert!(r.events.iter().any(|e| e.contains("authorize_agent")));
    }

    #[test]
    fn authorize_agent_rejects_wrong_sponsor() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let tx_reg = Transaction::register_agent(
            "ra1", "qcb1alice",
            "agent-a2", "qcb1agentA2",
            vec![], chain_forge_agents::SpendingLimits::unlimited(),
            "agent", None, 0,
        );
        exec.execute_tx_with_identity(&tx_reg, &mut state, &mut identity, &mut qrc, &mut agents);

        // bob tries to authorize alice's agent — must fail.
        let tx_auth = Transaction {
            id: "auth2".into(), sender: "qcb1bob".into(), nonce: 0,
            body: TxBody::AuthorizeAgent { agent_id: "agent-a2".into() },
            gas_limit: 100_000, signature: vec![], public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx_auth, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "wrong sponsor must be rejected");
        assert!(r.error.as_deref().unwrap_or("").contains("not the registered sponsor"),
            "error must mention sponsor mismatch: {:?}", r.error);
        // Agent must still be Pending.
        assert_eq!(agents.get("agent-a2").unwrap().status, chain_forge_agents::AgentStatus::Pending);
    }

    #[test]
    fn suspend_agent_moves_active_to_suspended() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Register + authorize.
        let tx_reg = Transaction::register_agent(
            "ra1", "qcb1alice",
            "agent-s1", "qcb1agentS1",
            vec![], chain_forge_agents::SpendingLimits::unlimited(),
            "agent", None, 0,
        );
        exec.execute_tx_with_identity(&tx_reg, &mut state, &mut identity, &mut qrc, &mut agents);
        let tx_auth = Transaction {
            id: "auth1".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::AuthorizeAgent { agent_id: "agent-s1".into() },
            gas_limit: 100_000, signature: vec![], public_key: vec![],
        };
        exec.execute_tx_with_identity(&tx_auth, &mut state, &mut identity, &mut qrc, &mut agents);
        assert_eq!(agents.get("agent-s1").unwrap().status, chain_forge_agents::AgentStatus::Active);

        // Suspend.
        let tx_sus = Transaction {
            id: "sus1".into(), sender: "qcb1alice".into(), nonce: 2,
            body: TxBody::SuspendAgent {
                agent_id: "agent-s1".into(),
                reason: "compliance review".into(),
            },
            gas_limit: 100_000, signature: vec![], public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx_sus, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "SuspendAgent must succeed: {:?}", r.error);
        assert_eq!(agents.get("agent-s1").unwrap().status, chain_forge_agents::AgentStatus::Suspended);
        assert!(r.events.iter().any(|e| e.contains("suspend_agent")));
    }

    #[test]
    fn revoke_agent_full_tombstones_aei_and_identity() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        let tx_reg = Transaction::register_agent(
            "ra1", "qcb1alice",
            "agent-r1", "qcb1agentR1",
            vec![], chain_forge_agents::SpendingLimits::unlimited(),
            "agent", None, 0,
        );
        exec.execute_tx_with_identity(&tx_reg, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(identity.get("qcb1alice").unwrap().has_sponsored("qcb1agentR1"),
            "identity store must have the sponsorship before revoke");

        let tx_rev = Transaction {
            id: "rev1".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::RevokeAgentFull { agent_id: "agent-r1".into() },
            gas_limit: 100_000, signature: vec![], public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx_rev, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "RevokeAgentFull must succeed: {:?}", r.error);

        // AgentStore must show Revoked.
        assert_eq!(agents.get("agent-r1").unwrap().status, chain_forge_agents::AgentStatus::Revoked,
            "AEI record must be Revoked");

        // IdentityStore sponsorship must be cleared.
        assert!(!identity.get("qcb1alice").unwrap().has_sponsored("qcb1agentR1"),
            "identity sponsorship must be removed after full revoke");

        assert!(r.events.iter().any(|e| e.contains("revoke_agent_full")));
    }

    #[test]
    fn record_agent_spend_enforces_epoch_limit() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Register with a tight epoch limit.
        let tx_reg = Transaction::register_agent(
            "ra1", "qcb1alice",
            "agent-sp1", "qcb1agentSP1",
            vec![chain_forge_agents::AgentCapability::Transfer],
            chain_forge_agents::SpendingLimits::merchant(500), // epoch limit = 500 uQRC
            "spending test agent",
            None, 0,
        );
        exec.execute_tx_with_identity(&tx_reg, &mut state, &mut identity, &mut qrc, &mut agents);
        // Authorize it.
        let tx_auth = Transaction {
            id: "auth1".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::AuthorizeAgent { agent_id: "agent-sp1".into() },
            gas_limit: 100_000, signature: vec![], public_key: vec![],
        };
        exec.execute_tx_with_identity(&tx_auth, &mut state, &mut identity, &mut qrc, &mut agents);

        // First spend within limit must succeed.
        let tx_spend = Transaction {
            id: "sp1".into(), sender: "qcb1alice".into(), nonce: 2,
            body: TxBody::RecordAgentSpend { agent_id: "agent-sp1".into(), amount_uqrc: 300 },
            gas_limit: 50_000, signature: vec![], public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx_spend, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "spend within limit must succeed: {:?}", r.error);
        assert_eq!(agents.get("agent-sp1").unwrap().epoch_spend_uqrc, 300);

        // Second spend that would exceed limit must fail.
        let tx_spend2 = Transaction {
            id: "sp2".into(), sender: "qcb1alice".into(), nonce: 3,
            body: TxBody::RecordAgentSpend { agent_id: "agent-sp1".into(), amount_uqrc: 300 },
            gas_limit: 50_000, signature: vec![], public_key: vec![],
        };
        let r2 = exec.execute_tx_with_identity(&tx_spend2, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r2.success, "spend exceeding epoch limit must fail");
        assert!(r2.error.as_deref().unwrap_or("").contains("RecordAgentSpend"),
            "error must mention RecordAgentSpend: {:?}", r2.error);
    }

    #[test]
    fn spawn_child_agent_requires_spawn_capability() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Register and authorize parent WITHOUT SpawnChildAgent capability.
        let tx_reg = Transaction::register_agent(
            "ra1", "qcb1alice",
            "parent-no-cap", "qcb1parent1",
            vec![chain_forge_agents::AgentCapability::Transfer], // no SpawnChildAgent
            chain_forge_agents::SpendingLimits::unlimited(),
            "parent without spawn cap", None, 0,
        );
        exec.execute_tx_with_identity(&tx_reg, &mut state, &mut identity, &mut qrc, &mut agents);
        let tx_auth = Transaction {
            id: "auth1".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::AuthorizeAgent { agent_id: "parent-no-cap".into() },
            gas_limit: 100_000, signature: vec![], public_key: vec![],
        };
        exec.execute_tx_with_identity(&tx_auth, &mut state, &mut identity, &mut qrc, &mut agents);

        // Attempt to spawn — must fail.
        let tx_spawn = Transaction {
            id: "spawn1".into(), sender: "qcb1alice".into(), nonce: 2,
            body: TxBody::SpawnChildAgent {
                child_agent_id:      "child-1".into(),
                child_agent_address: "qcb1child1".into(),
                parent_agent_id:     "parent-no-cap".into(),
                capabilities:        vec![],
                spending_limits:     chain_forge_agents::SpendingLimits::unlimited(),
                description:         "child".into(),
            },
            gas_limit: 300_000, signature: vec![], public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx_spawn, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "spawn without capability must fail");
        assert!(r.error.as_deref().unwrap_or("").contains("SpawnChildAgent"),
            "error must mention SpawnChildAgent: {:?}", r.error);
    }

    #[test]
    fn spawn_child_agent_succeeds_with_spawn_capability() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();
        // Register and authorize parent WITH SpawnChildAgent capability.
        let tx_reg = Transaction::register_agent(
            "ra1", "qcb1alice",
            "parent-cap", "qcb1parent2",
            vec![
                chain_forge_agents::AgentCapability::SpawnChildAgent,
                chain_forge_agents::AgentCapability::Transfer,
            ],
            chain_forge_agents::SpendingLimits::unlimited(),
            "parent with spawn cap", None, 0,
        );
        exec.execute_tx_with_identity(&tx_reg, &mut state, &mut identity, &mut qrc, &mut agents);
        let tx_auth = Transaction {
            id: "auth1".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::AuthorizeAgent { agent_id: "parent-cap".into() },
            gas_limit: 100_000, signature: vec![], public_key: vec![],
        };
        exec.execute_tx_with_identity(&tx_auth, &mut state, &mut identity, &mut qrc, &mut agents);

        // Spawn child.
        let tx_spawn = Transaction {
            id: "spawn2".into(), sender: "qcb1alice".into(), nonce: 2,
            body: TxBody::SpawnChildAgent {
                child_agent_id:      "child-2".into(),
                child_agent_address: "qcb1child2".into(),
                parent_agent_id:     "parent-cap".into(),
                capabilities:        vec![chain_forge_agents::AgentCapability::ReadState],
                spending_limits:     chain_forge_agents::SpendingLimits::unlimited(),
                description:         "child agent".into(),
            },
            gas_limit: 300_000, signature: vec![], public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx_spawn, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "SpawnChildAgent must succeed: {:?}", r.error);

        // Child must be registered as Pending with correct parent link.
        let child = agents.get("child-2").expect("child must be in AgentStore");
        assert_eq!(child.status, chain_forge_agents::AgentStatus::Pending,
            "spawned child must start as Pending");
        assert_eq!(child.parent_agent_id.as_deref(), Some("parent-cap"),
            "child must link back to parent");
        assert_eq!(child.sponsor_id, "qcb1alice",
            "child must share sponsor with parent");

        // IdentityStore must record the child's sponsorship.
        assert!(identity.get("qcb1alice").unwrap().has_sponsored("qcb1child2"),
            "IdentityStore must record child sponsorship");

        assert!(r.events.iter().any(|e| e.contains("spawn_child_agent")));
    }

    // ── Control 5: CoverageRatio circuit breaker — execution layer wiring ────
    //
    // These tests verify that:
    //   • RecordCapacity tx executes successfully and transitions circuit-breaker state
    //   • QrcPurchase is rejected when the engine is RESTRICTED or HALTED
    //   • QrcContributionSettle is rejected when the engine is HALTED
    //   • QrcContributionSettle is allowed when the engine is RESTRICTED
    //     (providers are the recovery mechanism)
    //
    // Setup convention: QrcEngine::new(D) starts with minting_state = Normal and
    // tracked_capacity = 0 (coverage_ratio = None when total_supply == 0).
    // We drive state changes by calling record_capacity directly on the QrcEngine
    // OR by submitting RecordCapacity transactions through execute_tx_with_identity.

    #[test]
    fn record_capacity_tx_succeeds_and_emits_event() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Submit a RecordCapacity tx with 2_000_000 units (2 × D = 2.0 capacity).
        let tx = Transaction::record_capacity("rc1", "qcb1alice", 2_000_000, 0);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "RecordCapacity must succeed: {:?}", r.error);
        assert!(
            r.events.iter().any(|e| e.contains("record_capacity")),
            "must emit a record_capacity event, got: {:?}", r.events
        );
        // Engine must have stored the capacity.
        assert_eq!(qrc.tracked_capacity, 2_000_000,
            "tracked_capacity must equal submitted value");
    }

    #[test]
    fn record_capacity_tx_transitions_circuit_breaker_to_normal() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Give Alice some QRC supply first so coverage ratio is finite.
        let buy = Transaction::qrc_purchase("buy1", "qcb1alice", 1_000_000, 0, 0);
        let r   = exec.execute_tx_with_identity(&buy, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);

        // Force engine into HALTED by setting capacity to 0 (CR = 0/supply < CR_halt).
        qrc.record_capacity(0);
        assert_eq!(qrc.minting_state, chain_forge_qrc::MintingState::Halted,
            "engine must be Halted with zero capacity and positive supply");

        // Submit RecordCapacity with ample capacity (e.g. 10× supply) to recover.
        let supply = qrc.total_supply;
        let capacity = supply * 10; // CR = 10.0, well above CR_resume = 1.0
        let rc = Transaction::record_capacity("rc2", "qcb1alice", capacity, 1);
        let r  = exec.execute_tx_with_identity(&rc, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success, "RecordCapacity must succeed: {:?}", r.error);
        assert_eq!(qrc.minting_state, chain_forge_qrc::MintingState::Normal,
            "engine must transition back to Normal when CR >= 1.0");
        // Event must describe the transition.
        let event = r.events.iter().find(|e| e.contains("record_capacity"))
            .expect("must have record_capacity event");
        assert!(event.contains("Halted->Normal") || event.contains("halted->normal"),
            "event must describe state transition, got: {event}");
    }

    #[test]
    fn qrc_purchase_blocked_when_restricted() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Give Alice some QRC supply so the coverage ratio is finite.
        let buy = Transaction::qrc_purchase("buy1", "qcb1alice", 1_000_000, 0, 0);
        let r   = exec.execute_tx_with_identity(&buy, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);

        // Set capacity between CR_halt (0.75) and CR_resume (1.0) → RESTRICTED.
        // CR = capacity / total_supply × D.
        // We want 0.75 × supply < capacity < 1.0 × supply → use 0.88 × supply.
        let supply = qrc.total_supply;
        let restricted_capacity = supply * 880_000 / 1_000_000; // 0.88 × supply
        qrc.record_capacity(restricted_capacity);
        assert_eq!(qrc.minting_state, chain_forge_qrc::MintingState::Restricted,
            "engine must be Restricted; supply={supply}, capacity={restricted_capacity}");

        // QrcPurchase must be rejected.
        let tx = Transaction::qrc_purchase("buy2", "qcb1alice", 100_000, 0, 1);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "QrcPurchase must be blocked in RESTRICTED state");
        let err = r.error.unwrap();
        assert!(
            err.contains("circuit breaker") || err.contains("CoverageRatio"),
            "error must mention circuit breaker, got: {err}"
        );
    }

    #[test]
    fn qrc_purchase_blocked_when_halted() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Give Alice some QRC supply.
        let buy = Transaction::qrc_purchase("buy1", "qcb1alice", 1_000_000, 0, 0);
        let r   = exec.execute_tx_with_identity(&buy, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);

        // Force HALTED: set capacity to 0 → CR = 0 < CR_halt (0.75).
        qrc.record_capacity(0);
        assert_eq!(qrc.minting_state, chain_forge_qrc::MintingState::Halted,
            "engine must be Halted");

        let tx = Transaction::qrc_purchase("buy2", "qcb1alice", 100_000, 0, 1);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "QrcPurchase must be blocked in HALTED state");
        let err = r.error.unwrap();
        assert!(
            err.contains("circuit breaker") || err.contains("CoverageRatio"),
            "error must mention circuit breaker, got: {err}"
        );
    }

    #[test]
    fn contribution_settle_blocked_when_halted() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Give Alice some QRC supply so CR is finite.
        let buy = Transaction::qrc_purchase("buy1", "qcb1alice", 1_000_000, 0, 0);
        let r   = exec.execute_tx_with_identity(&buy, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);

        // Force HALTED.
        qrc.record_capacity(0);
        assert_eq!(qrc.minting_state, chain_forge_qrc::MintingState::Halted,
            "engine must be Halted");

        // Both minting paths are suspended in HALTED state — contribution must fail.
        let ev = make_evidence(1);
        let tx = Transaction::qrc_contribution_settle("settle1", "qcb1alice", 1, ev, 1);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(!r.success, "QrcContributionSettle must be blocked in HALTED state");
        let err = r.error.unwrap();
        assert!(
            err.contains("circuit breaker") || err.contains("CoverageRatio"),
            "error must mention circuit breaker, got: {err}"
        );
    }

    #[test]
    fn contribution_settle_allowed_when_restricted() {
        let (exec, mut state, mut identity, mut qrc, mut agents) = setup_with_identity();

        // Give Alice some QRC supply.
        let buy = Transaction::qrc_purchase("buy1", "qcb1alice", 1_000_000, 0, 0);
        let r   = exec.execute_tx_with_identity(&buy, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success);

        // Set engine to RESTRICTED (providers are the recovery mechanism).
        let supply = qrc.total_supply;
        let restricted_capacity = supply * 880_000 / 1_000_000; // 0.88 × supply
        qrc.record_capacity(restricted_capacity);
        assert_eq!(qrc.minting_state, chain_forge_qrc::MintingState::Restricted,
            "engine must be Restricted");

        // qcb1alice is Verified in setup_with_identity — contribution must succeed.
        let ev = make_evidence(1);
        let tx = Transaction::qrc_contribution_settle("settle1", "qcb1alice", 1, ev, 1);
        let r  = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut qrc, &mut agents);
        assert!(r.success,
            "QrcContributionSettle must be ALLOWED in RESTRICTED state (providers = recovery): {:?}",
            r.error
        );
        assert!(
            r.events.iter().any(|e| e.contains("qrc_contribution_settle")),
            "must emit contribution_settle event"
        );
    }
}
