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
/// Single-token architecture (whitepaper, October 2026 revision): $QCB is
/// the sole active protocol token. The resource marketplace (LockQrcForJob,
/// ReleaseQrcForJob, RefundQrcForJob, VerifyJob, DepositToTreasury -- still
/// named for their QRC-prototype origin) escrows and settles in `uqcb`/
/// `locked_uqcb`, not a separate resource-credit denom. The `QrcPurchase`,
/// `QrcSpend`, `QrcContributionSettle`, `EpochOpen`/`EpochClose` handlers and
/// the `uqrc` denom they mint/spend are the earlier two-token prototype --
/// preserved and still functional, but dormant: nothing in the active
/// devnet lifecycle calls them, and new code should not build on `uqrc`.
/// See docs/QCB-Single-Token-Migration-Audit.md for the full audit.
///
/// Whitepaper refs:
///   - Section 6.2 (legacy $QRC transfers, demurrage -- prototype, dormant)
///   - Section 6.3 ($QCB burns via BME)
///   - Section 6.6 (gas fees -> staking yield)
///   - Section 8 (merchant payment flow)

use serde::{Deserialize, Serialize};
use chain_forge_core::{Address, EnabledModules, GenesisConfig, HashWidth};
use chain_forge_crypto::{
    ClassicalScheme, KeyPair, MlDsaScheme, SchemeId, Signature, SignatureScheme,
    mldsa_tx_prehash, ED25519_TX_DOMAIN_V1,
};
use chain_forge_state::{StateStore, StateError};
use chain_forge_identity::IdentityStore;
use chain_forge_agents::{AgentStore, AgentType, SpendingLimits};
use chain_forge_pocd::DiscoveryRegistry;

/// Validator Onboarding — Permissionless Entry via Stake Bond. See
/// ROADMAP.md, "Validator Onboarding" section.
pub mod validator_bond;

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
                    TxBody::BondValidator { .. }     => op_multiplier * 5,
                    TxBody::UnbondValidator          => op_multiplier * 5,
                    // Verifying a proof-of-possession signature is real
                    // crypto work, comparable to the other key/identity ops.
                    TxBody::RegisterValidatorKey { .. } => op_multiplier * 5,
                    TxBody::Custom  { .. }           => op_multiplier * 10,
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
                    // Spend: updates provider pool + burn + reserve — three writes.
                    // Settle: verifies evidence + mints QRC — most expensive.
                    // Phase 1 Charm Confinement / Agent typed variants.
                    // ConfinementUpdate: reads identity + writes charm + Merkle leaf.
                    TxBody::CharmConfinementUpdate { .. } => op_multiplier * 4,
                    // IntrinsicCharmRecord: single charm field update + leaf refresh.
                    TxBody::IntrinsicCharmRecord { .. }  => op_multiplier * 3,
                    // RegisterAgent: writes AgentRecord + identity sponsorship + account.
                    TxBody::RegisterAgent { .. }         => op_multiplier * 8,
                    // Epoch boundary: lightweight protocol signals.
                    // Control 5: capacity update + circuit breaker re-evaluation.
                    // AEI Phase 2 lifecycle ops.
                    TxBody::AuthorizeAgent { .. }        => op_multiplier * 4,
                    TxBody::SuspendAgent { .. }          => op_multiplier * 3,
                    TxBody::RevokeAgentFull { .. }       => op_multiplier * 6, // touches both stores
                    TxBody::RecordAgentSpend { .. }      => op_multiplier * 2,
                    TxBody::SpawnChildAgent { .. }       => op_multiplier * 8, // comparable to RegisterAgent
                    // Resource Network v0.2 marketplace tx types.
                    // PurchaseQrc: burns QCB + mints QRC + records job credit.
                    // CreditProvider: coordinator credit + mints QRC to provider.
                    // QRC Escrow: balance hold/release — moderate state writes.
                    // Agent Treasury: one debit + one credit + optional agent record update.
                    // Resource Network: Contribution layer.
                    // RegisterMachine: writes MachineRecord to state (similar to RegisterAgent).
                    // SubmitUsefulWork: verifies seal + writes receipt + updates contribution score.
                    // PQ-VAL-002 R1: ActivatePqConsensus governance tx — low gas,
                    // single epoch write.
                    TxBody::ActivatePqConsensus { .. } => op_multiplier * 4,
                    // EmergencyDeprecateAlgorithm (CS-001 P4): constitutional governance
                    // operation; high gas to deter frivolous calls.
                    TxBody::EmergencyDeprecateAlgorithm { .. } => op_multiplier * 20,
                    // ClaimResearchReward (Change Set L): settlement_operators check +
                    // replay-key write + treasury debit + recipient credit.
                    // Comparable to QrcContributionSettle (also 12×).
                    TxBody::ClaimResearchReward { .. }   => op_multiplier * 12,
                    // Resource Job Lifecycle: 4 state-machine tx types.
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
    /// Validator Onboarding (ROADMAP.md): bond uqcb as validator stake.
    /// Sender is the validator candidate; incremental bonding is allowed --
    /// whether the resulting total clears the minimum bond threshold only
    /// matters for active-set eligibility, not for this tx succeeding.
    /// See `validator_bond::ValidatorBondStore::bond()`.
    BondValidator {
        amount: u128,
    },
    /// Validator Onboarding (ROADMAP.md): begin unbonding the sender's
    /// entire current validator stake. Stops counting toward the active
    /// set immediately; funds remain locked (and slashable) for the
    /// unbonding cooldown before a later `UnbondValidator` call sweeps
    /// the matured amount back to the sender's balance. See
    /// `validator_bond::ValidatorBondStore::start_unbond()` /
    /// `sweep_matured()`.
    UnbondValidator,
    /// CF-VAL-KEY-002: register (or rotate) the sender's authenticated
    /// consensus public key -- the key that signs block proposals and
    /// votes, as distinct from the account key used to sign ordinary
    /// transactions (which may be the same key, but isn't required to be).
    ///
    /// `BondValidator` moves funds but has never carried any key material;
    /// this is the transaction that actually establishes the authenticated
    /// binding `consensus key -> validator identity` that mandatory
    /// signature verification depends on. Reusable across any Chain Forge
    /// chain -- there is nothing Qattice-specific here.
    ///
    /// Authentication (enforced unconditionally in the executor,
    /// independent of this chain's general `require_signatures` setting --
    /// see `verify_authorization_for`): the transaction's own signature
    /// must authenticate `sender` (so only the address that controls this
    /// validator's account can call this for itself), AND
    /// `proof_of_possession` must be a valid signature, made with the
    /// private key corresponding to `consensus_pubkey`, over
    /// `validator_key_registration_signing_bytes(chain_id, sender)` -- so
    /// the registrant has actually proven they hold the new key's private
    /// half, not merely asserted its public bytes. Both conditions must
    /// hold for every registration, including a later key rotation, which
    /// is what makes an unauthorized replacement impossible: nobody else's
    /// transaction can authenticate as `sender`, and nobody who doesn't
    /// hold the target private key can produce a valid proof of possession
    /// for it.
    RegisterValidatorKey {
        consensus_pubkey:     Vec<u8>,
        proof_of_possession:  Vec<u8>,
        /// Signature scheme used for this consensus key.
        /// Authorised values: "classical" | "ml-dsa-65".
        /// Required — absent or unrecognised values are rejected fail-closed.
        #[serde(default)]
        scheme:               String,
        /// PoP message version: 1 = legacy V1 (chain_id + sender),
        /// 2 = canonical V2 (chain_id + sender + pubkey).
        /// Defaults to 1 for backward-compat with pre-PQ-VAL-001 txs.
        #[serde(default = "default_pop_version")]
        pop_version:          u8,
    },
    /// Custom operation -- opaque payload for module-specific logic.
    /// Used by Charm Confinement, Intrinsic Charm, Charmed Agents.
    /// QRC operations now use typed variants below.
    Custom {
        module:  String,
        payload: Vec<u8>,
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
    /// charm record without going through the normal transfer paths.
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

    // ── AEI Phase 2 — Agent Lifecycle ────────────────────────────────────────

    /// Coordinator authorizes a Pending agent (moves it to Active status).
    AuthorizeAgent {
        agent_id: String,
    },
    /// Coordinator suspends an Active agent (moves it to Suspended status).
    SuspendAgent {
        agent_id: String,
        reason:   String,
    },
    /// Coordinator permanently revokes an agent (removes it from the store).
    RevokeAgentFull {
        agent_id: String,
    },
    /// Record that an agent spent `amount_uqrc` (updates spending limits).
    RecordAgentSpend {
        agent_id:    String,
        amount_uqrc: u128,
    },
    /// Spawn a child agent under an existing parent agent.
    SpawnChildAgent {
        child_agent_id:      String,
        child_agent_address: String,
        parent_agent_id:     String,
        capabilities:        Vec<chain_forge_agents::AgentCapability>,
        spending_limits:     SpendingLimits,
        description:         String,
    },

    // ── PoCD Research Reward Settlement (Change Set L) ────────────────────────
    //
    // Settlement operators (a recognized account set in genesis) submit this
    // transaction after the research DB records a canonical result with the
    // required verification quorum.  The execution layer enforces:
    //
    //   1. Sender must be in `settlement_operators` (DIS-backed; operator's
    //      ML-DSA-65 signature is checked by `verify_signature` on every tx).
    //   2. `claim:{claim_id}` state key must NOT exist (replay prevention).
    //   3. `recipient` is bound at claim-creation time; no substitution allowed.
    //   4. `treasury:pocd-research` is debited; `recipient` is credited.
    //
    // The claim_id is deterministic:
    //   hex( SHA-256( "qcb-claim-v1\x00" || chain_id || "\x00"
    //                 || objective_id || "\x00" || task_id || "\x00"
    //                 || reward_kind ) )
    // so a re-submission after a crash uses the same ID and hits the replay guard.
    //
    // Scientific constraints (preserved verbatim):
    //   "No result is automatically classified as a cryptographic breakthrough."
    //   "No experimental result is automatically classified as a cryptographic
    //    anomaly or scientific discovery."
    //   "Do not introduce AI inference, new token economics, or automatic
    //    scientific discovery claims."
    //   "Keep blockchain consensus unchanged."

    // ── CS-001 P4: Emergency Cryptographic Deprecation Governance Tx ─────────────
    //
    // When a cryptographic algorithm is believed to be compromised — either by
    // a credible CRQC report, a NIST advisory, or an operational anomaly —
    // authorized `crypto_governors` can submit this transaction to begin the
    // migration away from the affected scheme.
    //
    // Two-phase timeline (enforced by the executor):
    //   T₀ (this tx):   Algorithm marked deprecated; grace period opens.
    //                   All nodes MUST begin generating new keys in `replacement`
    //                   scheme from this epoch onward.
    //                   Old-scheme signatures remain valid during the grace window.
    //   T₀ + grace:     Hard cutoff epoch. Old-scheme signatures are REJECTED by
    //                   consensus. Any account that has not rotated its key before
    //                   this epoch cannot transact until it rotates.
    //
    // Semantics:
    //   - Sender must be in `config.crypto_governors`.
    //   - `deprecated_scheme` must be the currently active scheme (prevents
    //     deprecating an already-inactive scheme).
    //   - `replacement_scheme` must be distinct and must be a known SchemeId.
    //   - `grace_epochs` must be in [MIN_CRYPTO_GRACE_EPOCHS, MAX_CRYPTO_GRACE_EPOCHS].
    //   - On success: `crypto_migration:active` state key is written with the
    //     CryptoMigrationState struct; SchemeRegistry state is updated.
    //   - If a migration is already in progress, the tx is rejected (one
    //     active migration at a time).

    /// Emergency governance transaction to deprecate a cryptographic algorithm.
    ///
    /// Initiates a time-bounded migration window: existing signatures in the
    /// `deprecated_scheme` remain valid for `grace_epochs`, after which the
    /// scheme is hard-rejected by consensus.
    ///
    /// Authorization: sender must be in `config.crypto_governors` (a small set of
    /// constitutional keyholders, distinct from ordinary governance).
    /// Governance transaction that sets the epoch at which ML-DSA-65 consensus
    /// signature verification is activated (PQ-VAL-002 R1).
    ///
    /// - `activation_epoch` must be ≥ 1 (epoch 0 is the genesis sentinel and is rejected).
    ///   Any epoch ≥ 1, including epochs already passed, is valid (immediate activation).
    /// - A second `ActivatePqConsensus` tx before the first epoch is reached
    ///   replaces the stored epoch (last-writer-wins within the constraint).
    /// - After `EmergencyDeprecateAlgorithm("ml-dsa-65")`, a new tx is required
    ///   to re-enable; the deprecation clears the stored epoch.
    ///
    /// Authorization: initially open (any funded sender); a future change-set
    /// can narrow this to `crypto_governors` if needed.
    ActivatePqConsensus {
        /// Epoch at which ML-DSA-65 consensus signatures become accepted and
        /// the R3 power gate lifts for qualifying validators.
        activation_epoch: u64,
    },

    EmergencyDeprecateAlgorithm {
        /// Algorithm being deprecated (must be the current `active_scheme`).
        deprecated_scheme: String,
        /// Algorithm to migrate to.
        replacement_scheme: String,
        /// Number of epochs validators have to rotate keys and re-sign before
        /// the old scheme is hard-rejected. Enforced in [MIN, MAX] range.
        grace_epochs: u64,
        /// Reason for the emergency deprecation (audit trail; required, non-empty).
        rationale: String,
        /// Optional reference to a NIST/IETF advisory, vulnerability report,
        /// or internal security finding (e.g. "NIST-2026-CRQC-ALERT-001").
        advisory_ref: Option<String>,
        /// Which signature layer(s) this deprecation covers.
        ///
        /// Must be `DeprecationScope::TxSignatures` — consensus-signature
        /// migration is not yet implemented and is explicitly rejected at
        /// execution time to prevent an accidental network halt.
        scope: DeprecationScope,
    },

    /// Settle a verified PoCD research result as a uqcb reward payment.
    ///
    /// Only a `settlement_operators` address (from genesis) may submit this.
    /// The operator's ML-DSA-65 key must be registered in the DIS; chain-ID
    /// replay protection is enforced unconditionally by `verify_signature`.
    ///
    /// Enforced invariants:
    ///   - Sender must be in `config.settlement_operators`.
    ///   - `claim:{claim_id}` state key must not exist (replay / double-payment
    ///     prevention).
    ///   - `amount_uqcb` must be > 0.
    ///   - `treasury:pocd-research` must hold at least `amount_uqcb`.
    ///   - On success: `claim:{claim_id}` is written (idempotency key),
    ///     `treasury:pocd-research` is debited, `recipient` is credited.
    ClaimResearchReward {
        /// Deterministic claim identifier (prevents replay and enables idempotent
        /// re-submission after operator crash).
        claim_id: String,
        /// Parent research objective.
        objective_id: String,
        /// Task this result was produced for.
        task_id: String,
        /// UUID of the canonical experiment_results row.
        result_id: String,
        /// Content hash of the canonical result (denormalized; audit trail only).
        contribution_hash: String,
        /// Wallet address that will receive the reward.
        /// Bound to the canonical result's `miner_id` at claim creation;
        /// the execution layer does not re-verify this binding — the operator
        /// is responsible for deriving `recipient` from the authenticated machine
        /// owner recorded in the DIS.
        recipient: String,
        /// Reward amount in micro-QCB (uqcb). 1 QCB = 1_000_000 uqcb.
        amount_uqcb: u64,
        /// Policy version (e.g. `"QcbResearchRewardPolicy-v1"`).
        policy_version: String,
        /// Reward kind: `"primary"` | `"replication"`.
        reward_kind: String,
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
            TxBody::BondValidator { .. }          => "BondValidator",
            TxBody::UnbondValidator               => "UnbondValidator",
            TxBody::RegisterValidatorKey { .. }   => "RegisterValidatorKey",
            TxBody::Custom { .. }                 => "Custom",
            TxBody::SponsorAgent { .. }           => "SponsorAgent",
            TxBody::RevokeAgent { .. }            => "RevokeAgent",
            TxBody::RegisterIdentity             => "RegisterIdentity",
            TxBody::Attest { .. }                 => "Attest",
            TxBody::RevokeAttestation { .. }      => "RevokeAttestation",
            TxBody::ReportSuspectedSybil { .. }   => "ReportSuspectedSybil",
            TxBody::ConfirmSybil { .. }           => "ConfirmSybil",
            TxBody::ReverseSybil { .. }           => "ReverseSybil",
            TxBody::CharmConfinementUpdate { .. } => "CharmConfinementUpdate",
            TxBody::IntrinsicCharmRecord { .. }   => "IntrinsicCharmRecord",
            TxBody::RegisterAgent { .. }          => "RegisterAgent",
            TxBody::AuthorizeAgent { .. }         => "AuthorizeAgent",
            TxBody::SuspendAgent { .. }           => "SuspendAgent",
            TxBody::RevokeAgentFull { .. }        => "RevokeAgentFull",
            TxBody::RecordAgentSpend { .. }       => "RecordAgentSpend",
            TxBody::SpawnChildAgent { .. }        => "SpawnChildAgent",
            // PQ-VAL-002 R1: PQ consensus activation
            TxBody::ActivatePqConsensus { .. } => "ActivatePqConsensus",
            // CS-001 P4: Emergency Crypto Deprecation
            TxBody::EmergencyDeprecateAlgorithm { .. } => "EmergencyDeprecateAlgorithm",
            // Resource Network v0.2
            // Resource Marketplace — QRC Escrow
            // Agent Treasury
            // Contribution Layer
            // Resource Job Lifecycle
            // PoCD Research Reward Settlement (Change Set L)
            TxBody::ClaimResearchReward { .. }     => "ClaimResearchReward",
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
/// StateStore::burn. Every other body type previously advanced
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
            | TxBody::BondValidator { .. }
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

/// Debit the fee for a transaction from the sender's account and credit it
/// to the fee-collector account.
///
/// Called in `execute_tx` and `execute_tx_with_identity` after the gas-limit
/// and balance checks, before executing the tx body.  On failure the tx is
/// rejected with an insufficient-balance error (FS-03).
///
/// The fee-collector account is auto-created if it does not yet exist —
/// this handles the genesis case where `treasury:fees` is not pre-funded.
/// Both the sender and fee-collector state leaves are refreshed so the
/// Merkle tree stays consistent.
fn debit_fee(
    tx:        &Transaction,
    fee:       u64,
    denom:     &str,
    collector: &str,
    state:     &mut StateStore,
) -> Result<(), String> {
    let fee_u128 = fee as u128;

    // Verify sender has enough to cover the fee.
    let sender_bal = state.get_account(&tx.sender)
        .map(|a| a.balance_of(denom))
        .unwrap_or(0);
    if sender_bal < fee_u128 {
        return Err(format!(
            "insufficient balance for fee: sender {} has {} {denom}, need {fee}",
            tx.sender, sender_bal,
        ));
    }

    // Debit sender.
    if let Ok(acct) = state.get_account_mut(&tx.sender) {
        let _ = acct.debit(denom, fee_u128); // balance check above guarantees this succeeds
    }
    state.refresh_leaf(&tx.sender);

    // Credit fee collector (auto-create if absent).
    if state.get_account(collector).is_err() {
        let ca = chain_forge_state::AccountState::new(
            collector.to_string(),
            "treasury".to_string(),
        );
        state.upsert_account(ca);
    }
    if let Ok(ca) = state.get_account_mut(collector) {
        ca.credit(denom, fee_u128);
    }
    state.refresh_leaf(collector);

    tracing::debug!(
        tx_id     = %tx.id,
        sender    = %tx.sender,
        fee,
        denom,
        collector,
        "fee_debit"
    );
    Ok(())
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
    /// **Versioned signature scheme identifier (CS-001-H2).**
    ///
    /// Explicitly tags which cryptographic algorithm produced `signature` /
    /// `pq_signatures` so the verifier never has to guess.  This makes live
    /// algorithm migration possible without a hard fork: the executor reads
    /// this field first and dispatches to the correct verification path.
    ///
    /// - `None`  → legacy / unsigned tx (backward-compatible; verifier falls
    ///             back to the implicit `pq_signatures` prefix scan).
    /// - `Some(SchemeId::Classical)`          → Ed25519 in `signature`.
    /// - `Some(SchemeId::MlDsa)`              → ML-DSA-65 in `pq_signatures`.
    /// - `Some(SchemeId::HybridEd25519MlDsa)` → both fields must be present.
    ///
    /// New signers MUST set this field.  Verifiers accept `None` only for
    /// backward compatibility with pre-CS-001 transactions already on-chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_scheme: Option<SchemeId>,
    /// Ed25519 signature over signing_bytes(chain_id). Empty when unsigned.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Ed25519 public key (32 bytes) that produced `signature`. Must either
    /// match the key bound to `sender`, or -- for an account with no bound
    /// key yet -- be the key `sender` was derived from.
    #[serde(default)]
    pub public_key: Vec<u8>,
    /// Post-quantum signature tags.  Each entry is `"<scheme>:<hex>"`, e.g.
    /// `"mldsa65:<3293-byte-sig-hex>"`.  Empty for unsigned or Ed25519-only txs.
    ///
    /// When present the executor verifies the ML-DSA signature over
    /// SHA-256("chain-forge/pq-tx/v1\n" || chain_id || "\n" || body_json).
    /// This matches the signing path in chain-forge-wallet::sign_transaction()
    /// exactly, and binds the signature to the specific chain (B4).
    ///
    /// The `mldsa65:` tag is the only one enforced today; unknown tags are
    /// ignored (forward-compatibility).
    #[serde(default)]
    pub pq_signatures: Vec<String>,
    /// ML-DSA-65 public key (1952 bytes) supplied on the FIRST signed tx from a
    /// PQ wallet so the executor can bind it to the account and verify future txs.
    /// Ignored (and may be empty) once the account already has a bound PQ key.
    #[serde(default)]
    pub pq_public_key: Vec<u8>,
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
        out.extend_from_slice(ED25519_TX_DOMAIN_V1);  // CS-001-M1: "chain-forge/tx/v1\n"
        out.extend_from_slice(chain_id.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(&payload);
        out
    }

    /// Set public_key from `keypair` and sign. Clients call this last,
    /// after every other field is final.
    ///
    /// Sets `sig_scheme` from the keypair so verifiers know which algorithm
    /// to use without having to inspect signature byte lengths or tags
    /// (CS-001-H2: versioned signature envelope).
    pub fn sign(&mut self, keypair: &KeyPair, chain_id: &str) -> Result<(), String> {
        self.sig_scheme  = Some(keypair.scheme.clone());
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
            TxBody::BondValidator { .. }               => 16,
            TxBody::UnbondValidator                    => 8,
            TxBody::RegisterValidatorKey { consensus_pubkey, proof_of_possession, .. } =>
                consensus_pubkey.len() + proof_of_possession.len(),
            TxBody::Custom   { module, payload }      => module.len() + payload.len(),
            TxBody::RegisterIdentity                  => 8,
            TxBody::Attest   { claimant_id }          => claimant_id.len() + 8,
            TxBody::SponsorAgent { agent_address }    => agent_address.len() + 8,
            TxBody::RevokeAgent  { agent_address }    => agent_address.len() + 8,
            TxBody::RevokeAttestation { attested_id }    => attested_id.len() + 8,
            TxBody::ConfirmSybil { sybil_id }            => sybil_id.len() + 8,
            TxBody::ReverseSybil { sybil_id }            => sybil_id.len() + 8,
            TxBody::ReportSuspectedSybil { suspected_id }=> suspected_id.len() + 8,
            // QRC typed variants.
            // Evidence carries provider_id + proof bytes — treat as ~256 bytes.
            // Phase 1 typed variants.
            TxBody::CharmConfinementUpdate { .. }        => 16,
            TxBody::IntrinsicCharmRecord { .. }          => 16,
            // RegisterAgent carries description + capabilities list.
            TxBody::RegisterAgent { agent_id, agent_address, description, .. } => {
                agent_id.len() + agent_address.len() + description.len() + 64
            }
            // Epoch boundary signals: epoch number (u64) only.
            // Control 5: capacity value (u128).
            // AEI Phase 2 lifecycle ops.
            TxBody::AuthorizeAgent { agent_id }             => agent_id.len() + 8,
            TxBody::SuspendAgent { agent_id, reason }       => agent_id.len() + reason.len() + 8,
            TxBody::RevokeAgentFull { agent_id }            => agent_id.len() + 8,
            TxBody::RecordAgentSpend { agent_id, .. }       => agent_id.len() + 24,
            TxBody::SpawnChildAgent {
                child_agent_id, child_agent_address, parent_agent_id, description, ..
            } => child_agent_id.len() + child_agent_address.len()
                + parent_agent_id.len() + description.len() + 64,
            // ActivatePqConsensus: single u64 field.
            TxBody::ActivatePqConsensus { .. } => 8,
            // EmergencyDeprecateAlgorithm: two scheme names + rationale + optional advisory + scope.
            TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme, replacement_scheme, rationale, advisory_ref, ..
            } => {
                deprecated_scheme.len() + replacement_scheme.len() + rationale.len()
                    + advisory_ref.as_deref().map_or(0, str::len) + 32
            }
            // ClaimResearchReward: all string fields + 16 for amount/overhead.
            TxBody::ClaimResearchReward {
                claim_id, objective_id, task_id, result_id,
                contribution_hash, recipient, policy_version, reward_kind, ..
            } => {
                claim_id.len() + objective_id.len() + task_id.len() + result_id.len()
                    + contribution_hash.len() + recipient.len() + policy_version.len()
                    + reward_kind.len() + 16
            }
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        }
    }

    /// Validator Onboarding (ROADMAP.md): bond uqcb as validator stake.
    pub fn bond_validator(id: &str, sender: &str, amount: u128, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::BondValidator { amount },
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        }
    }

    /// Validator Onboarding (ROADMAP.md): begin/complete unbonding.
    pub fn unbond_validator(id: &str, sender: &str, nonce: u64) -> Self {
        Self {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::UnbondValidator,
            gas_limit: 50_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        }
    }

    // ── Resource Marketplace — QRC Escrow constructors ───────────────────────

    /// Lock `amount` uQRC in escrow for `job_id` (Resource Marketplace §5.1).
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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

// ── CS-001 P4: Crypto Migration State ────────────────────────────────────────

/// Minimum grace period (epochs) for an emergency algorithm deprecation.
/// Too short a window leaves accounts unable to rotate before the hard cutoff.
pub const MIN_CRYPTO_GRACE_EPOCHS: u64 = 10;

/// Maximum grace period (epochs) for an emergency algorithm deprecation.
/// Keeps the migration window bounded; if the threat is real, lingering
/// longer than this is operationally untenable.
pub const MAX_CRYPTO_GRACE_EPOCHS: u64 = 200;

/// Canonical scheme identifiers that the Chain Forge execution layer recognises.
///
/// These are the stable lowercase ids returned by `SchemeId::canonical_id()`.
/// Both `deprecated_scheme` and `replacement_scheme` in an
/// `EmergencyDeprecateAlgorithm` tx must resolve to one of these values
/// (case-insensitive) or the tx is rejected.
pub const KNOWN_CANONICAL_SCHEME_IDS: &[&str] = &[
    "ed25519",
    "ml-dsa",
    "ml-dsa-65",   // NIST alternate designation for the same scheme
    "slh-dsa",
    "fn-dsa",
    "hybrid-ed25519-ml-dsa",
];

/// State key used in the StateStore to persist the active migration window.
pub const CRYPTO_MIGRATION_STATE_KEY: &str = "crypto_migration:active";

/// Scope of an emergency cryptographic algorithm deprecation.
///
/// Transaction-signature migration and consensus-signature migration are
/// deliberately separate because an unsafe consensus migration can halt the
/// entire network.  `ConsensusSignatures` and `Both` are reserved for a
/// future release that includes a verified validator-key rotation procedure.
///
/// # Safety contract
/// `TxSignatures` is the only scope that the current executor implements.
/// Any attempt to deprecate `ConsensusSignatures` (directly or via `Both`) is
/// rejected at execution time with an unambiguous error, preventing an
/// accidental consensus-quorum failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeprecationScope {
    /// Deprecate the scheme only for wallet / transaction signatures.
    ///
    /// Safe to use today: the consensus layer hardcodes `SchemeId::Classical`
    /// and is entirely isolated from `CryptoMigrationState`.
    TxSignatures,
    /// Deprecate the scheme for consensus votes only.
    ///
    /// **NOT YET IMPLEMENTED** — rejected at execution time.
    /// Requires a verified validator-key rotation procedure and a replacement
    /// consensus signing path before it can be enabled.
    ConsensusSignatures,
    /// Deprecate the scheme for both transaction and consensus signatures.
    ///
    /// **NOT YET IMPLEMENTED** — rejected at execution time.
    /// Requires all pre-conditions of `ConsensusSignatures` to be met.
    Both,
}

/// On-chain record of an in-progress cryptographic algorithm migration.
///
/// Written to `StateStore` under `CRYPTO_MIGRATION_STATE_KEY` when an
/// `EmergencyDeprecateAlgorithm` tx is executed. Deleted by the scheduler
/// after the hard cutoff epoch passes and the migration is committed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoMigrationState {
    /// The scheme being deprecated.
    pub deprecated_scheme: String,
    /// The replacement scheme that all accounts must rotate to.
    pub replacement_scheme: String,
    /// Epoch the `EmergencyDeprecateAlgorithm` tx was included in.
    pub initiated_epoch: u64,
    /// Last epoch in which old-scheme signatures are still accepted.
    /// `hard_cutoff_epoch = initiated_epoch + grace_epochs - 1`
    pub hard_cutoff_epoch: u64,
    /// Reason for the deprecation.
    pub rationale: String,
    /// Optional advisory reference (NIST/IETF ID, internal finding ID, etc.).
    pub advisory_ref: Option<String>,
    /// Address that submitted the deprecation tx.
    pub initiated_by: String,
    /// Transaction ID of the `EmergencyDeprecateAlgorithm` tx.
    pub tx_id: String,
    /// Scope of this deprecation — which signature layers are covered.
    ///
    /// Defaults to `TxSignatures` when deserializing older records that
    /// pre-date the scope field, preserving backward compatibility.
    #[serde(default = "DeprecationScope::default_tx_signatures")]
    pub scope: DeprecationScope,
}

impl DeprecationScope {
    /// Serde default: deserialize old `CryptoMigrationState` records (before
    /// the scope field existed) as `TxSignatures`, preserving safe semantics.
    fn default_tx_signatures() -> Self {
        DeprecationScope::TxSignatures
    }
}

impl CryptoMigrationState {
    /// Returns true if `current_epoch` is past the hard cutoff — i.e. the old
    /// scheme MUST be rejected by consensus.
    pub fn hard_cutoff_passed(&self, current_epoch: u64) -> bool {
        current_epoch > self.hard_cutoff_epoch
    }

    /// Returns true if we are still in the grace window (old scheme accepted).
    pub fn in_grace_window(&self, current_epoch: u64) -> bool {
        current_epoch <= self.hard_cutoff_epoch
    }

    /// Remaining epochs in the grace window, or 0 if past the cutoff.
    pub fn grace_epochs_remaining(&self, current_epoch: u64) -> u64 {
        self.hard_cutoff_epoch.saturating_sub(current_epoch)
    }
}

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

    /// Addresses authorized to submit `ClaimResearchReward` (Change Set L).
    /// Derived from `GenesisConfig::settlement_operators`.
    pub settlement_operators: Vec<String>,

    /// Addresses authorized to submit `EmergencyDeprecateAlgorithm` (CS-001 P4).
    /// Constitutional keyholders — a small, distinct set from ordinary governance.
    /// Derived from `GenesisConfig::crypto_governors`.
    /// If empty, all `EmergencyDeprecateAlgorithm` txs are rejected (fail-closed).
    pub crypto_governors: Vec<String>,

    /// Address of the fee-collector account. All per-tx fees (in `native_denom`)
    /// are credited here after each transaction executes. Defaults to
    /// `"treasury:fees"` when not specified in genesis.
    pub fee_collector: String,
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
            settlement_operators: genesis.settlement_operators.clone(),
            crypto_governors:     genesis.crypto_governors.clone(),
            fee_collector: genesis.execution.fee_collector
                .clone()
                .unwrap_or_else(|| "treasury:fees".to_string()),
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
    verify_authorization_signed(config, tx, state)
}

/// CF-VAL-KEY-002: like `verify_authorization`, but used for transaction
/// types whose authentication must never be relaxed by this chain's general
/// `require_signatures` setting. `require_signatures = false` exists for
/// devnet/faucet convenience on ordinary transfers; it must never be read
/// as permission to bind an unauthenticated consensus key to a validator
/// identity. Callers pick this over `verify_authorization` for exactly
/// those tx types (currently: `RegisterValidatorKey`).
fn verify_authorization_for(config: &ExecutionConfig, tx: &Transaction, state: &StateStore) -> Result<(), String> {
    if matches!(tx.body, TxBody::RegisterValidatorKey { .. }) {
        return verify_authorization_signed(config, tx, state);
    }
    verify_authorization(config, tx, state)
}

/// The actual signature/key-binding check, unconditionally (no
/// `require_signatures` escape hatch). Factored out of `verify_authorization`
/// so `verify_authorization_for` can force it for specific tx types
/// regardless of chain config.
fn verify_authorization_signed(config: &ExecutionConfig, tx: &Transaction, state: &StateStore) -> Result<(), String> {

    // -- Scheme dispatch (CS-001-H2: versioned signature envelope) -------------
    //
    // Primary dispatch: use the explicit sig_scheme tag when present (set by
    // all signers post-CS-001).  Fall back to the legacy implicit detection
    // (pq_signatures prefix scan / presence of classical signature bytes) for
    // backward compatibility with pre-CS-001 transactions already on-chain.
    //
    // This allows live algorithm migration: adding a new SchemeId variant and
    // a new verify_* function is sufficient — no format change, no hard fork.
    match &tx.sig_scheme {
        Some(SchemeId::MlDsa)
        | Some(SchemeId::SlhDsa)
        | Some(SchemeId::FnDsa)
        | Some(SchemeId::HybridEd25519MlDsa) => {
            // Explicit PQ path: sig_scheme tag says a PQ algorithm is authoritative.
            // Currently only ML-DSA-65 has a live verifier; SLH-DSA and FN-DSA are
            // reserved for future activation and will fail cleanly here until wired.
            let sig_hex = tx.pq_signatures.iter()
                .find(|s| s.starts_with("mldsa65:"))
                .map(|s| s.trim_start_matches("mldsa65:"))
                .ok_or_else(|| format!(
                    "sig_scheme={:?} but no mldsa65: entry in pq_signatures for {}",
                    tx.sig_scheme, tx.sender
                ))?;
            return verify_mldsa_authorization(config, tx, state, sig_hex);
        }
        Some(SchemeId::Classical) => {
            // Explicit classical path: skip the pq_signatures scan entirely.
        }
        None => {
            // Legacy path: implicit detection for pre-CS-001 transactions.
            // ML-DSA: presence of "mldsa65:" tag in pq_signatures → PQ path.
            let mldsa_tag = tx.pq_signatures.iter()
                .find(|s| s.starts_with("mldsa65:"))
                .map(|s| s.trim_start_matches("mldsa65:"));
            if let Some(sig_hex) = mldsa_tag {
                return verify_mldsa_authorization(config, tx, state, sig_hex);
            }
            // Fall through to classical Ed25519 path below.
        }
    }

    // -- Classical Ed25519 path -----------------------------------------------
    if tx.signature.is_empty() && tx.public_key.is_empty() {
        return Err(format!(
            "transaction from {} has no signature and no pq_signature; \
             set require_signatures = false in genesis to allow unsigned txs",
            tx.sender
        ));
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

/// Default serde value for `TxBody::RegisterValidatorKey::pop_version`.
/// Returns 1 so that pre-PQ-VAL-001 txs (which have no pop_version field
/// in their JSON) deserialise as V1 and continue to verify against the
/// classical-legacy PoP format.
fn default_pop_version() -> u8 { 1 }

/// PQ-VAL-001: authorised signature schemes for validator key registration.
/// Fail-closed: any scheme not in this list is rejected before verification.
const VALIDATOR_AUTHORIZED_SCHEMES: &[&str] = &["classical", "ml-dsa-65"];

/// CF-VAL-KEY-002: domain-separated signing bytes for a validator
/// consensus-key registration proof-of-possession. Binds the registration
/// to a specific chain and a specific sender address, so a
/// proof-of-possession signature cannot be replayed against a different
/// chain, nor reused to register the same key under a different sender's
/// name. Reusable across any Chain Forge chain -- not Qattice-specific.
///
/// V1 — legacy format.  Does NOT bind the public key bytes.
/// Accepted for `scheme = "classical"` with `pop_version = 1` only.
/// New registrations SHOULD use V2.
pub fn validator_key_registration_signing_bytes(chain_id: &str, sender: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"CFVK|"); // Chain Forge Validator Key registration
    b.extend_from_slice(chain_id.as_bytes());
    b.push(b'|');
    b.extend_from_slice(sender.as_bytes());
    b
}

/// PQ-VAL-001: V2 PoP signing bytes — binds chain_id + sender + pubkey.
///
/// Prevents:
///   - Cross-chain replay  (chain_id bound)
///   - Cross-validator theft  (sender bound)
///   - Key substitution  (consensus_pubkey hex bound)
///
/// Required for all ML-DSA registrations and recommended for new
/// classical registrations going forward.
pub fn validator_key_registration_signing_bytes_v2(
    chain_id:       &str,
    sender:         &str,
    consensus_pubkey: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"CFVK-V2|");
    b.extend_from_slice(chain_id.as_bytes());
    b.push(b'|');
    b.extend_from_slice(sender.as_bytes());
    b.push(b'|');
    b.extend_from_slice(hex_encode_bytes(consensus_pubkey).as_bytes());
    b
}

/// PQ-VAL-002 R2: Domain-separated signing bytes for consensus precommit votes.
///
/// Format (spec §Precommit-signing-bytes):
///   `b"QATTICE-PRECOMMIT|" || chain_id || b"|" || height_le8 || b"|" || round_le4 || b"|" || hex(block_hash)`
///
/// Properties:
///   - Domain prefix prevents cross-protocol replay.
///   - `chain_id` prevents cross-chain replay.
///   - Little-endian fixed-width integers prevent length-extension ambiguity.
///   - `block_hash` hex-encoded to stay printable / loggable.
///
/// Used by both the classical (Ed25519) and ML-DSA-65 vote-signing paths;
/// the scheme tag lives in `Vote.scheme`, not in these bytes.
pub fn consensus_precommit_signing_bytes(
    chain_id:   &str,
    height:     u64,
    round:      u32,
    block_hash: &[u8],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(
        b"QATTICE-PRECOMMIT|".len()
            + chain_id.len()
            + 1  // '|'
            + 8  // height LE8
            + 1  // '|'
            + 4  // round LE4
            + 1  // '|'
            + block_hash.len() * 2, // hex
    );
    b.extend_from_slice(b"QATTICE-PRECOMMIT|");
    b.extend_from_slice(chain_id.as_bytes());
    b.push(b'|');
    b.extend_from_slice(&height.to_le_bytes());
    b.push(b'|');
    b.extend_from_slice(&round.to_le_bytes());
    b.push(b'|');
    b.extend_from_slice(hex_encode_bytes(block_hash).as_bytes());
    b
}

fn hex_encode_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Verify an ML-DSA-65 signature on a transaction.
///
/// Signing message (B4 chain-ID binding):
///   SHA-256("chain-forge/pq-tx/v1\n" || chain_id || "\n" || canonical_body_json)
///
/// This domain-separated construction binds the signature to the specific chain,
/// preventing cross-chain replay attacks.  It matches chain-forge-wallet::sign_transaction()
/// exactly (wallet must pass the same chain_id used at signing time).
///
/// Key lookup order:
///   1. Sender's account has a bound key → use it.
///   2. No bound key yet → use tx.pq_public_key (first-use registration).
///      The executor will bind this key via bind_pq_key_if_unbound() on success.
fn verify_mldsa_authorization(
    config:   &ExecutionConfig,
    tx:       &Transaction,
    state:    &StateStore,
    sig_hex:  &str,
) -> Result<(), String> {
    use chain_forge_crypto::Signature as CfSig;

    // Decode the signature
    let sig_bytes = hex_decode_str(sig_hex)
        .map_err(|e| format!("mldsa65 signature hex decode failed: {e}"))?;

    // Compute signing message via the canonical pre-hash helper (CS-001-M2).
    // Domain: MLDSA_TX_DOMAIN_V1 = "chain-forge/pq-tx/v1\n"; binds signature to chain_id.
    let body_json = serde_json::to_string(&tx.body)
        .map_err(|e| format!("cannot serialise tx.body for ML-DSA verification: {e}"))?;
    let message = mldsa_tx_prehash(&config.chain_id, body_json.as_bytes());

    // Resolve the public key: prefer the account's bound key, fall back to pq_public_key.
    let bound_key = state.get_account(&tx.sender).ok().and_then(|a| a.public_key.clone());
    let pub_key: Vec<u8> = match bound_key {
        Some(ref k) if !k.is_empty() => k.clone(),
        _ => {
            if tx.pq_public_key.is_empty() {
                return Err(format!(
                    "{} has no bound ML-DSA key and no pq_public_key was supplied; \
                     include the full ML-DSA public key in pq_public_key on first use",
                    tx.sender
                ));
            }
            tx.pq_public_key.clone()
        }
    };

    // Verify
    let sig = CfSig { scheme: SchemeId::MlDsa, bytes: sig_bytes };
    MlDsaScheme
        .verify(&message, &sig, &pub_key)
        .map_err(|e| format!("ML-DSA signature verification failed: {e}"))?;

    tracing::debug!(
        sender = %tx.sender,
        "ML-DSA-65 signature verified"
    );
    Ok(())
}

/// Decode a hex string without external crates (mirrors wallet's helper).
fn hex_decode_str(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length ({})", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| format!("at pos {i}: {e}")))
        .collect()
}

/// Which optional module a transaction type belongs to, if any. Transfer,
/// Burn and Custom are core and always allowed.
pub fn required_module(body: &TxBody) -> Option<&'static str> {
    match body {
        TxBody::Transfer { .. } | TxBody::Burn { .. } | TxBody::Custom { .. } => None,
        TxBody::Stake { .. } => Some("staking"),
        // Validator Onboarding (ROADMAP.md) reuses the "staking" module --
        // bonding/unbonding is the same economic gate as TxBody::Stake.
        TxBody::BondValidator { .. } | TxBody::UnbondValidator => Some("staking"),
        // Key registration is the authentication half of validator
        // onboarding, same module gate as bonding (the economic half).
        TxBody::RegisterValidatorKey { .. } => Some("staking"),
        TxBody::RegisterIdentity
        | TxBody::Attest { .. }
        | TxBody::RevokeAttestation { .. }
        | TxBody::ConfirmSybil { .. }
        | TxBody::ReverseSybil { .. }
        | TxBody::ReportSuspectedSybil { .. } => Some("identity"),
        // Legacy QRC-token ops (dormant in the single-token/$QCB-only
        // protocol -- see "market" and "pocd" below for the active,
        // uqcb-denominated paths that used to share this module).
        TxBody::SponsorAgent { .. } | TxBody::RevokeAgent { .. } => Some("agents"),
        // Phase 1 typed variants.
        TxBody::CharmConfinementUpdate { .. } | TxBody::IntrinsicCharmRecord { .. } => Some("identity"),
        TxBody::RegisterAgent { .. } => Some("agents"),
        // AEI Phase 2 lifecycle operations all require the agents module.
        TxBody::AuthorizeAgent { .. }
        | TxBody::SuspendAgent { .. }
        | TxBody::RevokeAgentFull { .. }
        | TxBody::RecordAgentSpend { .. }
        | TxBody::SpawnChildAgent { .. } => Some("agents"),
        // Resource Network v0.2 marketplace tx types: job-scoped QRC minting,
        // part of the resource marketplace, not the legacy standalone
        // QRC-token purchase path.
        // QRC Escrow is part of the Resource Marketplace.
        // Agent Treasury is part of the agents module (modifies agent records).
        // Contribution Layer (machine registration + useful-work submission)
        // belongs to PoCD / Grand Challenge research rewards -- active and
        // uqcb-denominated, distinct from the resource marketplace.
        // Resource Job Lifecycle belongs to the Resource Marketplace.
        // ClaimResearchReward (Change Set L): requires both the PoCD module
        // (treasury/balance ops) and identity module (settlement_operators
        // are DIS identities). Guard on PoCD since that also gates the
        // treasury and balance transfers for this reward path.
        TxBody::ClaimResearchReward { .. } => Some("pocd"),
        // PQ-VAL-002 R1: ActivatePqConsensus — no module gate.
        TxBody::ActivatePqConsensus { .. } => None,
        // CS-001 P4: EmergencyDeprecateAlgorithm is a core constitutional tx;
        // no optional module gate — governed exclusively by crypto_governors list.
        TxBody::EmergencyDeprecateAlgorithm { .. } => None,
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
        "market" => modules.market,
        "pocd"   => modules.pocd,
        _ => false,
    };
    if on { Ok(()) } else { Err(format!("module \"{name}\" is not enabled on this chain")) }
}

/// Stateless half of authorization: is `tx.signature` a valid Ed25519
/// signature by `tx.public_key` over this transaction on this chain?
/// Stateless mempool admission check — runs at POST /api/tx regardless of
/// `require_signatures`, before the tx enters the queue.
///
/// Checks that are always enforced (dev mode or not):
/// - sender non-empty
/// - gas_limit > 0 and <= block_gas_limit
/// - payload within max_tx_bytes
/// - Transfer body fields: amount > 0, `to` non-empty and qcb1-prefixed, denom non-empty
/// - Ed25519 signature, if present, is exactly 64 bytes
/// - ML-DSA-65 signature tag, if present, is exactly 6586 hex chars
///
/// What this does NOT check (needs state or crypto):
/// - nonce ordering / replay (state-dependent)
/// - balance sufficiency (state-dependent)
/// - unknown sender / recipient (state-dependent)
/// - crypto correctness of a 64-byte sig (that's `verify_signature`'s job)
pub fn check_tx(tx: &Transaction, max_tx_bytes: usize, block_gas_limit: u64) -> Result<(), String> {
    if tx.sender.is_empty() {
        return Err("sender must not be empty".into());
    }
    if tx.gas_limit == 0 {
        return Err("gas_limit must be > 0".into());
    }
    // F3: floor prevents dust-gas attacks; any real operation needs at least
    // this much gas to be worth including.
    const MIN_GAS_FLOOR: u64 = 1_000;
    if tx.gas_limit < MIN_GAS_FLOOR {
        return Err(format!("gas_limit {g} is below minimum {MIN_GAS_FLOOR}", g = tx.gas_limit));
    }
    if block_gas_limit > 0 && tx.gas_limit > block_gas_limit {
        return Err(format!(
            "gas_limit {g} exceeds block_gas_limit {b}",
            g = tx.gas_limit, b = block_gas_limit
        ));
    }
    // Re-serialise for the byte-size check so unicode-expanded content is
    // counted by its actual encoded byte length, not by char count.
    if max_tx_bytes > 0 {
        let approx = serde_json::to_vec(tx).map(|v| v.len()).unwrap_or(usize::MAX);
        if approx > max_tx_bytes {
            return Err(format!(
                "tx payload too large: ~{approx} bytes, limit {max_tx_bytes}"
            ));
        }
    }
    // Transfer-specific field validation.
    if let TxBody::Transfer { to, amount, denom } = &tx.body {
        if *amount == 0 {
            return Err("Transfer amount must be > 0".into());
        }
        if to.is_empty() {
            return Err("Transfer.to must not be empty".into());
        }
        if !to.starts_with("qcb1") {
            return Err(format!("Transfer.to has invalid address prefix (expected qcb1): {to}"));
        }
        // F2: self-send burns no value but wastes block space.
        if *to == tx.sender {
            return Err("Transfer.to must differ from sender (self-send not permitted)".into());
        }
        if denom.is_empty() {
            return Err("Transfer.denom must not be empty".into());
        }
        // F2: single-token chain — only uqcb is a valid transfer denom.
        if denom != "uqcb" {
            return Err(format!("Transfer.denom '{denom}' is not accepted; use 'uqcb'"));
        }
    }
    // Structural signature checks: wrong-length blobs are always invalid.
    // F5: all-zero public key is not a valid Ed25519 key.
    if !tx.public_key.is_empty() && tx.public_key.iter().all(|&b| b == 0) {
        return Err("public_key must not be all zeros".into());
    }
    if !tx.signature.is_empty() && tx.signature.len() != 64 {
        return Err(format!(
            "malformed Ed25519 signature: expected 64 bytes, got {}",
            tx.signature.len()
        ));
    }
    if !tx.pq_signatures.is_empty() {
        for tag in &tx.pq_signatures {
            if let Some(hex) = tag.strip_prefix("mldsa65:") {
                // ML-DSA-65 signatures are 3293 bytes = 6586 hex chars.
                if hex.len() != 6586 {
                    return Err(format!(
                        "malformed ML-DSA-65 signature: expected 6586 hex chars, got {}",
                        hex.len()
                    ));
                }
            }
        }
    }
    Ok(())
}

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
    // ML-DSA path: sig_scheme tag (CS-001-H2) or legacy prefix scan.
    let has_mldsa = matches!(tx.sig_scheme, Some(SchemeId::MlDsa) | Some(SchemeId::HybridEd25519MlDsa))
        || tx.pq_signatures.iter().any(|s| s.starts_with("mldsa65:"));
    if has_mldsa && !tx.pq_public_key.is_empty() {
        if let Ok(acct) = state.get_account_mut(&tx.sender) {
            if acct.public_key.is_none() {
                acct.public_key = Some(tx.pq_public_key.clone());
                tracing::info!(
                    sender = %tx.sender,
                    pk_len = tx.pq_public_key.len(),
                    "ML-DSA-65 public key bound to account"
                );
            }
        }
        state.refresh_leaf(&tx.sender);
        return;
    }
    // Classical Ed25519 path.
    if !tx.public_key.is_empty() {
        if let Ok(acct) = state.get_account_mut(&tx.sender) {
            if acct.public_key.is_none() {
                acct.public_key = Some(tx.public_key.clone());
            }
        }
        state.refresh_leaf(&tx.sender);
    }
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

    /// The chain's native fee/stake denom (e.g. `"uqcb"`). Exposed so
    /// callers outside this crate -- `chain-forge-node`'s epoch-boundary
    /// active-set recomputation, in particular -- can query
    /// `validator_bond::compute_stake_active_set` against the same denom
    /// the executor itself used to move bonded stake.
    pub fn native_denom(&self) -> &str {
        &self.config.native_denom
    }

    /// Execute a single transaction with CharmConfinement enforcement.
    /// Requires identity store, QRC engine, and agent store for identity-gated
    /// and agent-registered tx types.
    pub fn execute_tx_with_identity(
        &self,
        tx:       &Transaction,
        state:    &mut StateStore,
        identity: &mut IdentityStore,
        agents:   &mut AgentStore,
    ) -> TransactionResult {
        let gas_required = self.config.gas_model.calculate_gas(tx);

        if tx.gas_limit < gas_required {
            return TransactionResult::err(
                tx.id.clone(), gas_required, tx.gas_limit,
                format!("gas limit {} below required {}", tx.gas_limit, gas_required),
            );
        }

        // Reject a tx whose gas_limit exceeds the block gas cap — such a tx
        // can never be included in any block (B3: "absurd gas_limit rejected").
        let block_gas_cap = self.config.block_gas_limit;
        if tx.gas_limit > block_gas_cap {
            return TransactionResult::err(
                tx.id.clone(), gas_required, tx.gas_limit,
                format!("gas limit {} exceeds block gas cap {}", tx.gas_limit, block_gas_cap),
            );
        }

        if let Err(e) = module_check(tx, &self.config.modules) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }
        if let Err(e) = verify_authorization_for(&self.config, tx, state) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }

        // CS-001 P6 hard-cutoff enforcement (hardened).
        //
        // TODO(mempool): Chain Forge currently has no pre-execution mempool.
        // When a mempool is added, audit that any transaction admitted to the
        // mempool *before* the hard cutoff activates is re-checked against the
        // cutoff gate at execution time, not only at admission time.  The gate
        // here is the authoritative enforcement point; a mempool admission check
        // must not be treated as a substitute for it.
        //
        // Boundary semantics: `hard_cutoff_passed` uses `current_epoch > hard_cutoff_epoch`,
        // so the deprecated scheme is still accepted *at* hard_cutoff_epoch itself.
        // This is intentional: it gives the entire epoch in which the cutoff epoch begins
        // as a final grace period, protecting against block-timing races between the
        // EmergencyDeprecateAlgorithm tx inclusion and epoch advancement on other nodes.
        // The first epoch where classical is *refused* is hard_cutoff_epoch + 1.
        //
        // Fail-closed design (CS-001-P6-G1): if the migration key exists in state but
        // cannot be deserialized, the transaction is rejected rather than silently passing.
        // Malformed migration metadata is treated as an active (unknown) restriction
        // because allowing execution would bypass the migration intent.
        //
        // sig_scheme = None bypass closed (CS-001-P6-G2): the legacy path (sig_scheme
        // not set) falls through to classical Ed25519 verification.  A classical signer
        // could strip the sig_scheme tag to avoid this gate.  We close that gap by
        // treating None as SchemeId::Classical for cutoff purposes: any tx that reaches
        // this point via the classical Ed25519 verifier is subject to the same cutoff
        // as an explicitly-tagged Classical tx.
        if let Some(migration_json) = state.get_raw(CRYPTO_MIGRATION_STATE_KEY) {
            // Fail-closed: propagate deserialization failure as a hard rejection.
            let migration = match serde_json::from_str::<CryptoMigrationState>(&migration_json) {
                Ok(m) => m,
                Err(e) => {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "crypto migration state is present but could not be read \
                             (corrupt or schema mismatch); transaction rejected to \
                             protect migration integrity: {e}",
                        ),
                    );
                }
            };
            let current_epoch = identity.clock.current_epoch;
            if migration.hard_cutoff_passed(current_epoch) {
                // Resolve the effective scheme: tagged value if present, else Classical
                // (the only scheme that reaches this code path untagged).
                let effective_canonical = tx.sig_scheme.as_ref()
                    .map(|s| s.canonical_id())
                    .unwrap_or("ed25519");
                if effective_canonical == migration.deprecated_scheme.to_lowercase() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "sig_scheme {:?} was deprecated at epoch {} \
                             (hard cutoff passed at epoch {}); \
                             rotate to {} before submitting",
                            tx.sig_scheme,
                            migration.initiated_epoch,
                            migration.hard_cutoff_epoch,
                            migration.replacement_scheme,
                        ),
                    );
                }
            }
        }

        let expected_nonce = state.get_account(&tx.sender)
            .map(|a| a.nonce).unwrap_or(0);
        if tx.nonce != expected_nonce {
            return TransactionResult::err(
                tx.id.clone(), gas_required, tx.gas_limit,
                format!("nonce mismatch: expected {expected_nonce}, got {}", tx.nonce),
            );
        }

        // FS-03: Debit per-tx fee from sender before executing the body.
        // Failed txs still consume the fee (matching established EVM semantics).
        if let Err(e) = debit_fee(
            tx, gas_required, &self.config.native_denom,
            &self.config.fee_collector, state,
        ) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
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

            // Validator Onboarding (ROADMAP.md). Bonded stake and the
            // unbonding cooldown are tracked as on-chain balances of two
            // deterministic virtual accounts per validator -- no private
            // key ever controls them, same convention as `treasury:*`:
            //   `validator-bond:{address}`      balance["uqcb"] = currently bonded
            //   `validator-unbonding:{address}` balance["uqcb"] = amount cooling down
            //                                    balance["unlock_epoch"] = epoch it unlocks at
            // This keeps the rule set identical to what
            // `validator_bond::ValidatorBondStore` specifies and tests in
            // isolation, without threading a new store parameter through
            // every call site of this function. Computing the stake-ranked
            // active set (`validator_bond::ValidatorBondStore::active_set()`)
            // from these accounts, and swapping it into the live
            // ConsensusEngine's ValidatorSet at epoch boundaries, is the
            // remaining integration work -- see the module doc comment in
            // `validator_bond.rs` and ROADMAP.md.
            TxBody::BondValidator { amount } => {
                let bond_account = format!("validator-bond:{}", tx.sender);
                state.transfer(&tx.sender, &bond_account, &self.config.native_denom, *amount)
                    .map(|_| {
                        events.push(format!(
                            "bond_validator: {} {} bonded by {}",
                            amount, self.config.native_denom, tx.sender
                        ));
                        identity.record_activity_by_address(&tx.sender);
                    })
                    .map_err(|e| e.to_string())
            }

            TxBody::UnbondValidator => {
                let bond_account = format!("validator-bond:{}", tx.sender);
                let unbonding_account = format!("validator-unbonding:{}", tx.sender);
                let current_epoch = identity.clock.current_epoch;

                let currently_bonded = state.get_account(&bond_account)
                    .map(|a| a.balance_of(&self.config.native_denom))
                    .unwrap_or(0);

                if currently_bonded > 0 {
                    // New unbonding request: move the entire bonded amount
                    // into the cooldown-locked account and stamp its
                    // unlock_epoch. Only reachable when currently_bonded > 0,
                    // which is already false while a prior unbonding entry
                    // is outstanding (start_unbond zeroes the bond account),
                    // so this inherently forbids queuing a second cooldown
                    // on top of one already in flight.
                    let cooldown_epochs = validator_bond::DEFAULT_UNBONDING_COOLDOWN_EPOCHS;
                    let unlock_epoch = current_epoch.saturating_add(cooldown_epochs);
                    state.transfer(&bond_account, &unbonding_account, &self.config.native_denom, currently_bonded)
                        .map_err(|e| e.to_string())
                        .map(|_| {
                            if let Ok(acct) = state.get_account_mut(&unbonding_account) {
                                acct.balances.insert("unlock_epoch".to_string(), unlock_epoch as u128);
                            }
                            events.push(format!(
                                "unbond_validator: {} started unbonding {} {}, unlocks at epoch {}",
                                tx.sender, currently_bonded, self.config.native_denom, unlock_epoch
                            ));
                            identity.record_activity_by_address(&tx.sender);
                        })
                } else {
                    // No active bond -- either there's a matured cooldown to
                    // sweep back to the owner, or there's genuinely nothing
                    // bonded or unbonding at all.
                    let unlock_epoch = state.get_account(&unbonding_account)
                        .map(|a| a.balances.get("unlock_epoch").copied().unwrap_or(0))
                        .unwrap_or(0);
                    let unbonding_amount = state.get_account(&unbonding_account)
                        .map(|a| a.balance_of(&self.config.native_denom))
                        .unwrap_or(0);

                    if unbonding_amount == 0 {
                        return TransactionResult::err(
                            tx.id.clone(), gas_required, tx.gas_limit,
                            format!("{} has no bonded stake and no unbonding entry to sweep", tx.sender),
                        );
                    }
                    if (current_epoch as u128) < unlock_epoch {
                        return TransactionResult::err(
                            tx.id.clone(), gas_required, tx.gas_limit,
                            format!(
                                "{} unbonding cooldown not complete: unlocks at epoch {}, current epoch {}",
                                tx.sender, unlock_epoch, current_epoch
                            ),
                        );
                    }
                    // Matured: sweep back to the owner's own balance.
                    state.transfer(&unbonding_account, &tx.sender, &self.config.native_denom, unbonding_amount)
                        .map_err(|e| e.to_string())
                        .map(|_| {
                            if let Ok(acct) = state.get_account_mut(&unbonding_account) {
                                acct.balances.insert("unlock_epoch".to_string(), 0);
                            }
                            events.push(format!(
                                "unbond_validator: {} swept {} {} back to balance after cooldown",
                                tx.sender, unbonding_amount, self.config.native_denom
                            ));
                        })
                }
            }

            // CF-VAL-KEY-002: authenticate and register the sender's
            // consensus public key. Sender-authentication for this specific
            // transaction was already forced to run unconditionally (see
            // `verify_authorization_for`, called above instead of the
            // general `require_signatures`-gated `verify_authorization` --
            // a chain running devnet-permissive for ordinary transactions
            // must never extend that leniency to binding a validator's
            // consensus identity). What remains to check here is
            // proof-of-possession: that the sender actually holds the
            // *private* half of `consensus_pubkey`, not just its bytes.
            //
            // This only validates and emits an event; chain-forge-execution
            // has no dependency on chain-forge-validators (and must not
            // gain one -- ValidatorRegistry is a node-level concern, this
            // crate is the reusable, chain-agnostic execution engine). The
            // caller (`chain-forge-node`, after a successful commit) reads
            // this event back and mirrors the now-authenticated key into
            // `ValidatorRegistry::register_consensus_key()`.
            TxBody::RegisterValidatorKey {
                consensus_pubkey,
                proof_of_possession,
                scheme,
                pop_version,
            } => {
                // --- GAP-1 guard: reject empty key ---
                if consensus_pubkey.is_empty() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        "consensus_pubkey must not be empty".to_string(),
                    );
                }

                // --- R2: fail-closed scheme allowlist ---
                // Pre-PQ-VAL-001 txs have scheme = "" (serde default).
                // Treat empty scheme as "classical" for backward-compat
                // (they also have pop_version = 1 via the serde default).
                let effective_scheme: &str = if scheme.is_empty() {
                    "classical"
                } else {
                    scheme.as_str()
                };
                if !VALIDATOR_AUTHORIZED_SCHEMES.contains(&effective_scheme) {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "scheme '{effective_scheme}' is not authorized for \
                             validator registration; authorized: {}",
                            VALIDATOR_AUTHORIZED_SCHEMES.join(", ")
                        ),
                    );
                }

                // --- R2: key-length guard (fail before expensive crypto) ---
                let expected_key_len: Option<usize> = match effective_scheme {
                    "classical"  => Some(32),   // Ed25519 public key
                    "ml-dsa-65"  => Some(1952),  // ML-DSA-65 public key
                    _            => None,        // already gated above
                };
                if let Some(expected) = expected_key_len {
                    if consensus_pubkey.len() != expected {
                        return TransactionResult::err(
                            tx.id.clone(), gas_required, tx.gas_limit,
                            format!(
                                "consensus_pubkey length {} does not match expected \
                                 {} bytes for scheme '{effective_scheme}'",
                                consensus_pubkey.len(), expected
                            ),
                        );
                    }
                }

                // --- Build the PoP message for the declared pop_version ---
                let msg = match pop_version {
                    2 => validator_key_registration_signing_bytes_v2(
                        &self.config.chain_id, &tx.sender, consensus_pubkey,
                    ),
                    // V1 — legacy classical path; no pubkey binding.
                    _ => validator_key_registration_signing_bytes(
                        &self.config.chain_id, &tx.sender,
                    ),
                };

                // --- R2: scheme-aware PoP verification ---
                let verify_result = match effective_scheme {
                    "classical" => {
                        let sig = Signature {
                            scheme: SchemeId::Classical,
                            bytes: proof_of_possession.clone(),
                        };
                        ClassicalScheme.verify(&msg, &sig, consensus_pubkey)
                    }
                    "ml-dsa-65" => {
                        let sig = Signature {
                            scheme: SchemeId::MlDsa,
                            bytes: proof_of_possession.clone(),
                        };
                        MlDsaScheme.verify(&msg, &sig, consensus_pubkey)
                    }
                    _ => unreachable!("already gated by VALIDATOR_AUTHORIZED_SCHEMES"),
                };

                match verify_result {
                    Ok(()) => {
                        events.push(format!(
                            "register_validator_key: {} registered {} consensus key {} (pop_v{})",
                            tx.sender,
                            effective_scheme,
                            hex_encode_bytes(consensus_pubkey),
                            pop_version,
                        ));
                        identity.record_activity_by_address(&tx.sender);
                        Ok(())
                    }
                    Err(e) => Err(format!(
                        "proof-of-possession verification failed for {}: {e} -- the \
                         sender does not appear to hold the private key corresponding \
                         to the consensus_pubkey it is trying to register",
                        tx.sender
                    )),
                }
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

            // ── Phase 1: Charm Confinement ────────────────────────────────────
            TxBody::CharmConfinementUpdate { epoch } => {
                let tier_ok = identity.get(&tx.sender)
                    .map(|r| r.is_verified())
                    .unwrap_or(false);
                if !tier_ok {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "CharmConfinementUpdate: sender {} is not Verified tier",
                            tx.sender
                        ),
                    );
                }
                if let Some(rec) = identity.get_mut(&tx.sender) {
                    rec.charm.record_participation(*epoch);
                    // Sync updated charm to on-chain account state.
                    if let Ok(acct) = state.get_account_mut(&tx.sender) {
                        acct.attach_charm(rec.charm.clone());
                    }
                }
                state.refresh_leaf(&tx.sender);
                events.push(format!(
                    "charm_confinement_update: sender={} epoch={}",
                    tx.sender, epoch
                ));
                Ok(())
            }

            TxBody::IntrinsicCharmRecord { event } => {
                if identity.get(&tx.sender).is_err() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "IntrinsicCharmRecord: sender {} not registered in identity store",
                            tx.sender
                        ),
                    );
                }
                if let Some(rec) = identity.get_mut(&tx.sender) {
                    match event {
                        CharmEvent::DecayTick => {
                            // Consume one exemption day; lapse if exhausted.
                            if rec.charm.decay_exemption.consume(1) == 0 {
                                rec.charm.lapse();
                            }
                        }
                        CharmEvent::ExemptionCredit => {
                            // Credit one exemption day (spend activity reward).
                            rec.charm.decay_exemption.record_spend(
                                rec.charm.last_attested_epoch,
                            );
                        }
                    }
                    if let Ok(acct) = state.get_account_mut(&tx.sender) {
                        acct.attach_charm(rec.charm.clone());
                    }
                }
                state.refresh_leaf(&tx.sender);
                events.push(format!(
                    "intrinsic_charm_record: sender={} event={:?}",
                    tx.sender, event
                ));
                Ok(())
            }

            // ── AEI Phase 2 — Agent Lifecycle ─────────────────────────────────
            TxBody::AuthorizeAgent { agent_id } => {
                let current_epoch = identity.clock.current_epoch;
                match agents.authorize(agent_id, current_epoch) {
                    Ok(_) => {
                        events.push(format!(
                            "authorize_agent: agent_id={} authorized_by={}",
                            agent_id, tx.sender
                        ));
                        Ok(())
                    }
                    Err(e) => Err(format!("AuthorizeAgent: {e}")),
                }
            }

            TxBody::SuspendAgent { agent_id, reason } => {
                let current_epoch = identity.clock.current_epoch;
                match agents.suspend(agent_id, current_epoch) {
                    Ok(_) => {
                        events.push(format!(
                            "suspend_agent: agent_id={} reason={} suspended_by={}",
                            agent_id, reason, tx.sender
                        ));
                        Ok(())
                    }
                    Err(e) => Err(format!("SuspendAgent: {e}")),
                }
            }

            TxBody::RevokeAgentFull { agent_id } => {
                let current_epoch = identity.clock.current_epoch;
                // Capture agent address before revoking (for identity store cleanup).
                let agent_addr = agents.get(agent_id)
                    .map(|a| a.address.clone())
                    .unwrap_or_default();
                // Revoke from agent store.
                if let Err(e) = agents.revoke(agent_id, current_epoch) {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("RevokeAgentFull: {e}"),
                    );
                }
                // Also remove from identity store.
                if !agent_addr.is_empty() {
                    if let Some(rec) = identity.get_mut(&tx.sender) {
                        rec.revoke_agent(&agent_addr);
                    }
                }
                events.push(format!(
                    "revoke_agent_full: agent_id={} revoked_by={}",
                    agent_id, tx.sender
                ));
                Ok(())
            }

            TxBody::RecordAgentSpend { agent_id, amount_uqrc } => {
                match agents.record_spend(agent_id, *amount_uqrc) {
                    Ok(_) => {
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
                // Parent must exist and be Active.
                let parent_ok = agents.get(parent_agent_id)
                    .map(|r| r.status == chain_forge_agents::AgentStatus::Active)
                    .unwrap_or(false);
                if !parent_ok {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "SpawnChildAgent: parent agent '{}' does not exist or is not Active",
                            parent_agent_id
                        ),
                    );
                }
                let current_epoch = identity.clock.current_epoch;
                if let Err(e) = agents.register(
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
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("SpawnChildAgent: AgentStore.register failed: {e}"),
                    );
                }
                events.push(format!(
                    "spawn_child_agent: parent_id={} child_id={} address={} sponsor={}",
                    parent_agent_id, child_agent_id, child_agent_address, tx.sender
                ));
                Ok(())
            }

            // ── PQ-VAL-002 R1: Activate PQ Consensus ─────────────────────────
            TxBody::ActivatePqConsensus { activation_epoch } => {
                let current_epoch = identity.clock.current_epoch;
                // Epoch 0 is the genesis sentinel and is always rejected —
                // activation must refer to a named, post-genesis epoch.
                // Any epoch ≥ 1 is valid: if it has already passed, ML-DSA
                // consensus signatures are effective immediately.
                if *activation_epoch == 0 {
                    Err(format!(
                        "ActivatePqConsensus: activation_epoch must be ≥ 1 \
                         (epoch 0 is the genesis sentinel; current epoch is {})",
                        current_epoch
                    ))
                } else {
                    state.set_raw(
                        "pq_consensus_activation_epoch",
                        &activation_epoch.to_string(),
                    );
                    events.push(format!(
                        "activate_pq_consensus: activation_epoch={activation_epoch} \
                         set_by={} at_epoch={current_epoch}",
                        tx.sender
                    ));
                    Ok(())
                }
            }

            // ── CS-001 P4: Emergency Algorithm Deprecation ────────────────────
            TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme,
                replacement_scheme,
                grace_epochs,
                rationale,
                advisory_ref,
                scope,
            } => {
                // ── Guard 0: Scope check ───────────────────────────────────────
                // ConsensusSignatures scope is allowed only for "ml-dsa-65"
                // (PQ-VAL-002 R4 emergency rollback path).  All other schemes
                // and the Both scope still require the full validator-key
                // rotation path that does not yet exist.
                match scope {
                    DeprecationScope::TxSignatures => { /* always allowed */ }
                    DeprecationScope::ConsensusSignatures => {
                        // Allowed only for the PQ-VAL-002 ML-DSA rollback.
                        if deprecated_scheme != "ml-dsa-65" {
                            return TransactionResult::err(
                                tx.id.clone(), gas_required, tx.gas_limit,
                                format!(
                                    "EmergencyDeprecateAlgorithm: ConsensusSignatures \
                                     scope is only supported for deprecated_scheme \
                                     \"ml-dsa-65\"; got {:?}",
                                    deprecated_scheme,
                                ),
                            );
                        }
                        // Guard 5 (no in-progress migration) is checked below
                        // as usual; nothing else to gate here.
                    }
                    DeprecationScope::Both => {
                        return TransactionResult::err(
                            tx.id.clone(), gas_required, tx.gas_limit,
                            "EmergencyDeprecateAlgorithm: scope Both is not yet \
                             supported — use TxSignatures or ConsensusSignatures \
                             (ml-dsa-65 only) separately".to_string(),
                        );
                    }
                }

                // ── Guard 1: Sender must be a crypto governor ─────────────────
                // Fail-closed: empty crypto_governors denies all deprecation txs.
                if self.config.crypto_governors.is_empty() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        "EmergencyDeprecateAlgorithm: no crypto_governors configured \
                         in genesis — all deprecation txs denied".to_string(),
                    );
                }
                if !self.config.crypto_governors.contains(&tx.sender) {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "EmergencyDeprecateAlgorithm: sender {} is not a \
                             crypto governor", tx.sender
                        ),
                    );
                }

                // ── Guard 2: Schemes must be distinct ─────────────────────────
                if deprecated_scheme == replacement_scheme {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        "EmergencyDeprecateAlgorithm: deprecated_scheme and \
                         replacement_scheme must be different".to_string(),
                    );
                }

                // ── Guard 2b: Both schemes must be known canonical scheme ids ─
                // Do not pretend that a replacement algorithm is operational merely
                // because it appears as a string — it must be a scheme this
                // executor knows about.
                {
                    let dep_lower  = deprecated_scheme.to_lowercase();
                    let rep_lower  = replacement_scheme.to_lowercase();
                    if !KNOWN_CANONICAL_SCHEME_IDS.contains(&dep_lower.as_str()) {
                        return TransactionResult::err(
                            tx.id.clone(), gas_required, tx.gas_limit,
                            format!(
                                "EmergencyDeprecateAlgorithm: deprecated_scheme {:?} is \
                                 not a known scheme id; accepted values: {:?}",
                                deprecated_scheme, KNOWN_CANONICAL_SCHEME_IDS,
                            ),
                        );
                    }
                    if !KNOWN_CANONICAL_SCHEME_IDS.contains(&rep_lower.as_str()) {
                        return TransactionResult::err(
                            tx.id.clone(), gas_required, tx.gas_limit,
                            format!(
                                "EmergencyDeprecateAlgorithm: replacement_scheme {:?} is \
                                 not a known scheme id; accepted values: {:?}",
                                replacement_scheme, KNOWN_CANONICAL_SCHEME_IDS,
                            ),
                        );
                    }
                }

                // ── Guard 3: Grace period must be in valid range ──────────────
                if *grace_epochs < MIN_CRYPTO_GRACE_EPOCHS
                    || *grace_epochs > MAX_CRYPTO_GRACE_EPOCHS
                {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "EmergencyDeprecateAlgorithm: grace_epochs {} out of \
                             range [{}, {}]",
                            grace_epochs, MIN_CRYPTO_GRACE_EPOCHS, MAX_CRYPTO_GRACE_EPOCHS
                        ),
                    );
                }

                // ── Guard 4: Rationale must be non-empty ──────────────────────
                if rationale.trim().is_empty() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        "EmergencyDeprecateAlgorithm: rationale must not be empty".to_string(),
                    );
                }

                // ── Guard 5: No migration already in progress ─────────────────
                if state.get_raw(CRYPTO_MIGRATION_STATE_KEY).is_some() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        "EmergencyDeprecateAlgorithm: a crypto migration is already \
                         in progress — only one active migration is permitted".to_string(),
                    );
                }

                // ── Write migration state ─────────────────────────────────────
                let current_epoch = identity.clock.current_epoch;
                let hard_cutoff_epoch = current_epoch + grace_epochs - 1;
                let migration = CryptoMigrationState {
                    deprecated_scheme: deprecated_scheme.clone(),
                    replacement_scheme: replacement_scheme.clone(),
                    initiated_epoch: current_epoch,
                    hard_cutoff_epoch,
                    rationale: rationale.clone(),
                    advisory_ref: advisory_ref.clone(),
                    initiated_by: tx.sender.clone(),
                    tx_id: tx.id.clone(),
                    scope: scope.clone(),
                };

                // Persist migration state as a JSON sentinel in state store.
                // We use a named account slot; the "balance" is 0 but the
                // account's `data` carries the serialized CryptoMigrationState.
                let migration_json = serde_json::to_string(&migration)
                    .unwrap_or_else(|_| "{}".to_string());
                state.set_raw(CRYPTO_MIGRATION_STATE_KEY, &migration_json);

                // PQ-VAL-002 R4: When deprecating ML-DSA consensus signatures,
                // clear the activation epoch so verify_consensus_vote() in
                // chain-forge-node immediately rejects ML-DSA precommits.
                // A new ActivatePqConsensus tx is required to re-enable.
                if matches!(scope, DeprecationScope::ConsensusSignatures)
                    && deprecated_scheme == "ml-dsa-65"
                {
                    state.remove_raw("pq_consensus_activation_epoch");
                }

                tracing::warn!(
                    deprecated = %deprecated_scheme,
                    replacement = %replacement_scheme,
                    initiated_epoch = current_epoch,
                    hard_cutoff_epoch = hard_cutoff_epoch,
                    governor = %tx.sender,
                    rationale = %rationale,
                    "CS-001 P4: emergency algorithm deprecation initiated"
                );

                events.push(format!(
                    "emergency_deprecate_algorithm: deprecated={} replacement={} \
                     grace_epochs={} hard_cutoff_epoch={} governor={} tx_id={}",
                    deprecated_scheme, replacement_scheme,
                    grace_epochs, hard_cutoff_epoch,
                    tx.sender, tx.id,
                ));
                Ok(())
            }

            // ── PoCD Research Reward Settlement (Change Set L) ────────────────
            TxBody::ClaimResearchReward {
                claim_id,
                objective_id,
                task_id,
                result_id,
                contribution_hash,
                recipient,
                amount_uqcb,
                policy_version,
                reward_kind,
            } => {
                // ── Guard 1: Sender must be a settlement operator ─────────────
                // Settlement operators are a recognized account set in genesis,
                // analogous to the pilot-phase coordinator that gates ConfirmSybil.
                // Their ML-DSA-65 signatures are already verified unconditionally
                // by `verify_signature(tx, chain_id)` before this arm is reached.
                //
                // Fail-closed: an empty settlement_operators list denies all
                // ClaimResearchReward transactions. A misconfigured genesis cannot
                // accidentally open treasury-funded claims to any sender.
                if !self.config.settlement_operators.contains(&tx.sender) {
                    let reason = if self.config.settlement_operators.is_empty() {
                        format!(
                            "ClaimResearchReward: no settlement_operators configured in genesis \
                             — all claims denied (sender: {}, claim_id={}, objective_id={})",
                            tx.sender, claim_id, objective_id
                        )
                    } else {
                        format!(
                            "ClaimResearchReward: sender {} is not a recognized \
                             settlement operator (claim_id={}, objective_id={})",
                            tx.sender, claim_id, objective_id
                        )
                    };
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit, reason,
                    );
                }

                // ── Guard 2: Replay / double-payment prevention ───────────────
                // The claim_id is deterministic (hex-SHA-256 of domain-separated
                // fields), so a re-submission after an operator crash re-derives
                // the same ID and hits this guard — idempotent on the second call,
                // rejected as a replay attack on subsequent calls.
                let claim_key = format!("claim:{}", claim_id);
                if state.get_account(&claim_key).is_ok() {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "ClaimResearchReward: claim {} already settled (replay \
                             or duplicate submission); objective_id={} task_id={}",
                            claim_id, objective_id, task_id
                        ),
                    );
                }

                // ── Guard 3: Amount must be positive ──────────────────────────
                if *amount_uqcb == 0 {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "ClaimResearchReward: amount_uqcb must be > 0 \
                             (claim_id={}, reward_kind={})",
                            claim_id, reward_kind
                        ),
                    );
                }

                // ── Guard 4: Treasury must be solvent ─────────────────────────
                // Rewards are sourced from `treasury:pocd-research`.
                // This is a named account that governance must keep funded.
                let treasury = "treasury:pocd-research";
                let treasury_balance = state.get_account(treasury)
                    .map(|a| a.balance_of("uqcb"))
                    .unwrap_or(0);
                if treasury_balance < *amount_uqcb as u128 {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!(
                            "ClaimResearchReward: treasury {} has insufficient uqcb \
                             balance (have={}, need={}) for claim_id={} recipient={}",
                            treasury, treasury_balance, amount_uqcb, claim_id, recipient
                        ),
                    );
                }

                // ── Execute: debit treasury, credit recipient ─────────────────
                // Debit treasury:pocd-research
                if state.get_account(treasury).is_err() {
                    let ta = chain_forge_state::AccountState::new(
                        treasury.to_string(), "pocd-research-treasury".to_string(),
                    );
                    state.upsert_account(ta);
                }
                if let Ok(acct) = state.get_account_mut(treasury) {
                    let _ = acct.debit("uqcb", *amount_uqcb as u128);
                }
                state.refresh_leaf(treasury);

                // Credit recipient
                if state.get_account(recipient).is_err() {
                    let ra = chain_forge_state::AccountState::new(
                        recipient.clone(), "miner".to_string(),
                    );
                    state.upsert_account(ra);
                }
                if let Ok(acct) = state.get_account_mut(recipient) {
                    acct.credit("uqcb", *amount_uqcb as u128);
                }
                state.refresh_leaf(recipient);

                // ── Write idempotency key ─────────────────────────────────────
                // `claim:{claim_id}` is a write-once state key that prevents
                // any future re-execution of this claim (replay protection).
                // The stored JSON is an audit record; consensus only cares that
                // the key exists.
                let claim_record = serde_json::json!({
                    "claim_id":         claim_id,
                    "objective_id":     objective_id,
                    "task_id":          task_id,
                    "result_id":        result_id,
                    "contribution_hash": contribution_hash,
                    "recipient":        recipient,
                    "amount_uqcb":      amount_uqcb,
                    "policy_version":   policy_version,
                    "reward_kind":      reward_kind,
                    "settled_by":       &tx.sender,
                    "tx_id":            &tx.id,
                });
                let claim_record_json = serde_json::to_string(&claim_record)
                    .unwrap_or_else(|_| "{}".to_string());
                let mut claim_acct = chain_forge_state::AccountState::new(
                    claim_key.clone(), claim_record_json,
                );
                claim_acct.credit("settled", 1);
                state.upsert_account(claim_acct);
                state.refresh_leaf(&claim_key);

                events.push(format!(
                    "claim_research_reward: claim_id={} objective_id={} task_id={} \
                     result_id={} recipient={} amount_uqcb={} reward_kind={} \
                     policy_version={} settled_by={}",
                    claim_id, objective_id, task_id, result_id,
                    recipient, amount_uqcb, reward_kind, policy_version, tx.sender
                ));
                Ok(())
            }
        };

        if result.is_ok() {
            advance_nonce_if_not_already(tx, state);
            bind_key_if_unbound(&self.config, tx, state);
            // Every successfully committed transaction is on-chain activity.
            // Transfer and Stake already call this inside their match arms (so
            // the QRC yield comment lives next to the transfer logic), but
            // all other tx types — RegisterIdentity, Attest, SponsorAgent,
            // RevokeAgent — also count: submitting
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
        if let Err(e) = verify_authorization_for(&self.config, tx, state) {
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

        // FS-03: Debit per-tx fee from sender before executing the body.
        // Failed txs still consume the fee (matching established EVM semantics).
        if let Err(e) = debit_fee(
            tx, gas_required, &self.config.native_denom,
            &self.config.fee_collector, state,
        ) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
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
            | TxBody::SponsorAgent { .. }
            | TxBody::RevokeAgent { .. }
            | TxBody::RevokeAttestation { .. }
            | TxBody::ConfirmSybil { .. }
            | TxBody::ReverseSybil { .. }
            | TxBody::ReportSuspectedSybil { .. } => {
                Err("identity-gated transaction requires identity-aware executor".to_string())
            }
            // Validator Onboarding (ROADMAP.md): the unbonding cooldown is
            // tracked in epochs, so this needs identity.clock.current_epoch
            // -- execute_tx_with_identity() only.
            TxBody::BondValidator { .. } | TxBody::UnbondValidator
            | TxBody::RegisterValidatorKey { .. } => {
                Err("validator bonding transaction requires identity-aware executor".to_string())
            }
            // Phase 1 typed variants require identity + agent store.
            TxBody::CharmConfinementUpdate { .. }
            | TxBody::IntrinsicCharmRecord { .. }
            | TxBody::RegisterAgent { .. } => {
                Err("Phase 1 transaction requires identity- and agent-aware executor".to_string())
            }
            // AEI Phase 2 lifecycle variants require the full agent-aware executor.
            TxBody::AuthorizeAgent { .. }
            | TxBody::SuspendAgent { .. }
            | TxBody::RevokeAgentFull { .. }
            | TxBody::RecordAgentSpend { .. }
            | TxBody::SpawnChildAgent { .. } => {
                Err("AEI Phase 2 transaction requires identity- and agent-aware executor".to_string())
            }
            // ActivatePqConsensus requires the identity-aware executor
            // (needs current_epoch from identity.clock).
            TxBody::ActivatePqConsensus { .. } => {
                Err("ActivatePqConsensus requires the full identity- and state-aware executor".to_string())
            }
            // EmergencyDeprecateAlgorithm requires the identity-aware executor
            // (needs current_epoch from identity.clock).
            TxBody::EmergencyDeprecateAlgorithm { .. } => {
                Err("EmergencyDeprecateAlgorithm requires the full identity- and state-aware executor".to_string())
            }
            // ClaimResearchReward requires the full identity- and state-aware executor.
            TxBody::ClaimResearchReward { .. } => {
                Err("ClaimResearchReward requires the full identity- and state-aware executor".to_string())
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
            // FS-03: fee in uQCB == gas_used (GasModel returns uQCB directly).
            // debit_fee() already moved this amount sender → fee_collector.
            // Failed txs still consume the fee (EVM semantics); both success
            // and failure cases are counted in fees_collected.
            fees_collected += result.gas_used;
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
    /// agent-gated transaction types (RegisterIdentity, Attest,
    /// SponsorAgent, RevokeAgent, CharmConfinementUpdate,
    /// IntrinsicCharmRecord, RegisterAgent, and all QRC variants) actually
    /// processed instead of rejected. This is what a live node needs to call
    /// for those transaction types to work at all -- execute_block() above
    /// always rejects them, by design, since it has no identity, QRC, or
    /// agent state to process them against.
    pub fn execute_block_with_identity(
        &self,
        height:        u64,
        transactions:  Vec<Transaction>,
        state:         &mut StateStore,
        identity:      &mut IdentityStore,
        agents:        &mut AgentStore,
        timestamp_ms:  u64,
        pocd_registry: Option<&mut DiscoveryRegistry>,
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

            let result = self.execute_tx_with_identity(tx, state, identity, agents);
            total_gas      += result.gas_used;
            // FS-03: debit_fee() already moved fee amount sender → fee_collector.
            fees_collected += result.gas_used;
            results.push(result);
        }

        // ── PoCD epoch reward distribution ────────────────────────────────────
        // EpochClose tx has been removed (QRC epoch system retired).
        // PoCD rewards are now triggered via ClaimResearchReward instead.
        if let (true, Some(registry)) = (false, pocd_registry) {
            let closed_epoch: u64 = 0;
            let pending = registry.pending_reward_receipts(0, height);
            if !pending.is_empty() {
                use chain_forge_pocd::{RewardPolicy as _, FlatRewardPolicy};
                let policy = FlatRewardPolicy { amount_per_receipt: 1_000_000u64 };
                match policy.compute_rewards(&pending) {
                    Ok(grants) => {
                        let pocd_treasury = "treasury:pocd";
                        // Ensure treasury account exists (it should from genesis).
                        if state.get_account(pocd_treasury).is_err() {
                            let ta = chain_forge_state::AccountState::new(
                                pocd_treasury.to_string(), "treasury".to_string(),
                            );
                            state.upsert_account(ta);
                        }
                        let treasury_bal = state.get_account(pocd_treasury)
                            .map(|a| a.balance_of("uqcb"))
                            .unwrap_or(0);

                        let total_grant: u64 = grants.iter().map(|g| g.amount).sum();
                        // Never distribute more than what the treasury holds.
                        let disbursable = (total_grant as u128).min(treasury_bal);

                        let mut paid_total: u128 = 0;
                        let mut rewarded_ids: Vec<String> = Vec::new();

                        for grant in &grants {
                            let amt = grant.amount as u128;
                            if paid_total + amt > disbursable { break; }
                            // Ensure miner wallet exists.
                            if state.get_account(&grant.recipient_wallet).is_err() {
                                let wa = chain_forge_state::AccountState::new(
                                    grant.recipient_wallet.clone(), "machine_wallet".to_string(),
                                );
                                state.upsert_account(wa);
                            }
                            if let Ok(acct) = state.get_account_mut(&grant.recipient_wallet) {
                                acct.credit("uqcb", amt);
                            }
                            state.refresh_leaf(&grant.recipient_wallet);
                            paid_total += amt;
                            rewarded_ids.push(grant.receipt_id.clone());
                            tracing::info!(
                                epoch    = closed_epoch,
                                receipt  = %grant.receipt_id,
                                machine  = %grant.machine_id,
                                wallet   = %grant.recipient_wallet,
                                amount   = grant.amount,
                                "pocd_reward distributed"
                            );
                        }

                        // Debit treasury.
                        if paid_total > 0 {
                            if let Ok(ta) = state.get_account_mut(pocd_treasury) {
                                let _ = ta.debit("uqcb", paid_total);
                            }
                            state.refresh_leaf(pocd_treasury);
                        }

                        // Mark rewarded receipts in the registry.
                        for rid in &rewarded_ids {
                            let _ = registry.mark_reward_distributed(rid);
                        }

                        tracing::info!(
                            epoch         = closed_epoch,
                            receipts      = rewarded_ids.len(),
                            total_granted = total_grant,
                            disbursed     = paid_total,
                            "pocd_epoch_distribution complete"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            epoch = closed_epoch,
                            error = %e,
                            "PoCD reward computation failed; will retry next epoch"
                        );
                    }
                }
            }
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
            "modules": ["bank", "staking", "identity", "qrc", "agents", "market", "pocd"],
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

    /// Compute the gas cost for a tx under the test executor's gas model.
    /// Used to write balance assertions that stay correct after FS-03
    /// fee debit: `expected_balance = start - amount - gas_for(&exec, &tx)`.
    fn gas_for(exec: &Executor, tx: &Transaction) -> u128 {
        exec.config.gas_model.calculate_gas(tx) as u128
    }

    #[test]
    fn transfer_tx_succeeds() {
        let (exec, mut state) = setup();
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100_000, 0);
        let fee = gas_for(&exec, &tx);
        let result = exec.execute_tx(&tx, &mut state);

        assert!(result.success, "transfer should succeed: {:?}", result.error);
        // FS-03: alice pays transfer amount + fee; bob receives transfer amount only
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 5_000_000 - 100_000 - fee);
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
        let fee = gas_for(&exec, &tx);
        let result = exec.execute_tx(&tx, &mut state);

        assert!(result.success, "{:?}", result.error);
        // FS-03: alice pays burn amount + fee
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 5_000_000 - 500_000 - fee);
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
            settlement_operators: vec![],
            crypto_governors:     vec![],
            fee_collector:   "treasury:fees".into(),
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
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

    fn setup_with_identity() -> (Executor, StateStore, IdentityStore, AgentStore) {
        use chain_forge_identity::{IdentityStore, PopAttestation};

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();

        let mut identity = IdentityStore::new(0);
        let att = PopAttestation::genesis("qcb1alice", 0);
        identity.register("qcb1alice".into(), "qcb1alice".into(), att.clone()).unwrap();
        identity.verify_identity("qcb1alice", att, None).unwrap();

        let agents = AgentStore::new();
        (Executor::new(config), state, identity, agents)
    }

    // -- Validator Onboarding (ROADMAP.md): BondValidator / UnbondValidator --

    #[test]
    fn bond_validator_moves_funds_into_bond_account() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let tx = Transaction::bond_validator("bond1", "qcb1alice", 2_000_000, 0);
        let fee = gas_for(&exec, &tx);
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(r.success, "{:?}", r.error);
        // FS-03: alice pays bond amount + fee; bond account receives bond amount only
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 5_000_000 - 2_000_000 - fee);
        assert_eq!(state.get_account("validator-bond:qcb1alice").unwrap().balance_of("uqcb"), 2_000_000);
    }

    #[test]
    fn bonding_is_incremental_and_accumulates() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let tx1 = Transaction::bond_validator("bond1", "qcb1alice", 500_000, 0);
        let r1 = exec.execute_tx_with_identity(&tx1, &mut state, &mut identity, &mut agents);
        assert!(r1.success, "{:?}", r1.error);
        let tx2 = Transaction::bond_validator("bond2", "qcb1alice", 300_000, 1);
        let r2 = exec.execute_tx_with_identity(&tx2, &mut state, &mut identity, &mut agents);
        assert!(r2.success, "{:?}", r2.error);
        assert_eq!(state.get_account("validator-bond:qcb1alice").unwrap().balance_of("uqcb"), 800_000);
    }

    #[test]
    fn bond_fails_cleanly_on_insufficient_balance() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        // Alice only has 5_000_000 at genesis.
        let tx = Transaction::bond_validator("bond1", "qcb1alice", 50_000_000, 0);
        let fee = gas_for(&exec, &tx);
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(!r.success);
        // FS-03: the fee is consumed even on failure (EVM semantics).
        // The bond body is not executed, so no partial debit to the bond account.
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 5_000_000 - fee);
        assert!(state.get_account("validator-bond:qcb1alice").is_err());
    }

    #[test]
    fn unbond_without_any_bond_is_rejected() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let tx = Transaction::unbond_validator("unbond1", "qcb1alice", 0);
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("no bonded stake"));
    }

    #[test]
    fn unbond_starts_cooldown_and_removes_from_bond_account() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let bond = Transaction::bond_validator("bond1", "qcb1alice", 2_000_000, 0);
        let fee_bond = gas_for(&exec, &bond);
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents);

        let unbond = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        let fee_unbond = gas_for(&exec, &unbond);
        let r = exec.execute_tx_with_identity(&unbond, &mut state, &mut identity, &mut agents);
        assert!(r.success, "{:?}", r.error);
        // No longer counted as bonded -- stops counting toward the active set immediately.
        assert_eq!(state.get_account("validator-bond:qcb1alice").unwrap().balance_of("uqcb"), 0);
        // Funds are locked in the unbonding account, not back in Alice's spendable balance yet.
        assert_eq!(state.get_account("validator-unbonding:qcb1alice").unwrap().balance_of("uqcb"), 2_000_000);
        // FS-03: alice paid fees for both bond and unbond txs
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"),
            5_000_000 - 2_000_000 - fee_bond - fee_unbond);
    }

    #[test]
    fn claiming_unbonded_stake_before_cooldown_elapses_is_rejected() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let bond = Transaction::bond_validator("bond1", "qcb1alice", 2_000_000, 0);
        let fee_bond = gas_for(&exec, &bond);
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents);
        let unbond = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        let fee_unbond = gas_for(&exec, &unbond);
        exec.execute_tx_with_identity(&unbond, &mut state, &mut identity, &mut agents);

        // Still epoch 0 -- cooldown (21 epochs) has not elapsed. A second
        // UnbondValidator call (the only way to attempt a sweep) must be
        // rejected, and must NOT move any funds.
        let sweep_attempt = Transaction::unbond_validator("unbond2", "qcb1alice", 2);
        let fee_sweep = gas_for(&exec, &sweep_attempt);
        let r = exec.execute_tx_with_identity(&sweep_attempt, &mut state, &mut identity, &mut agents);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("cooldown not complete"));
        assert_eq!(state.get_account("validator-unbonding:qcb1alice").unwrap().balance_of("uqcb"), 2_000_000);
        // FS-03: alice paid fees for bond + unbond + failed sweep attempt
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"),
            5_000_000 - 2_000_000 - fee_bond - fee_unbond - fee_sweep);
    }

    #[test]
    fn claiming_unbonded_stake_after_cooldown_elapses_releases_funds_exactly_once() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let bond = Transaction::bond_validator("bond1", "qcb1alice", 2_000_000, 0);
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents);
        let unbond = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        exec.execute_tx_with_identity(&unbond, &mut state, &mut identity, &mut agents);

        // Advance past the 21-epoch cooldown.
        identity.clock.current_epoch = 21;

        let sweep = Transaction::unbond_validator("unbond2", "qcb1alice", 2);
        let fee_bond   = gas_for(&exec, &Transaction::bond_validator("x", "qcb1alice", 2_000_000, 0));
        let fee_unbond = gas_for(&exec, &Transaction::unbond_validator("x", "qcb1alice", 0));
        let fee_sweep  = gas_for(&exec, &sweep);
        let r = exec.execute_tx_with_identity(&sweep, &mut state, &mut identity, &mut agents);
        assert!(r.success, "{:?}", r.error);
        // FS-03: bond, unbond, and sweep all pay fees; but full principal returns via sweep
        let expected_after_sweep = 5_000_000 - fee_bond - fee_unbond - fee_sweep;
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), expected_after_sweep);
        assert_eq!(state.get_account("validator-unbonding:qcb1alice").unwrap().balance_of("uqcb"), 0);

        // Calling UnbondValidator again finds nothing bonded and nothing
        // matured left to sweep -- it must not double-release funds.
        let double_sweep = Transaction::unbond_validator("unbond3", "qcb1alice", 3);
        let fee_double = gas_for(&exec, &double_sweep);
        let r2 = exec.execute_tx_with_identity(&double_sweep, &mut state, &mut identity, &mut agents);
        assert!(!r2.success);
        assert!(r2.error.unwrap().contains("no bonded stake"));
        // FS-03: failed double-sweep still consumes fee
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"),
            expected_after_sweep - fee_double);
    }

    #[test]
    fn second_unbond_while_one_already_cooling_down_is_rejected() {
        // Exercises the "slash-and-run" guard: a validator cannot queue a
        // second, overlapping unbonding request while the first is still
        // locked -- there is nothing bonded left to start a new one from.
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let bond = Transaction::bond_validator("bond1", "qcb1alice", 2_000_000, 0);
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents);
        let unbond1 = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        exec.execute_tx_with_identity(&unbond1, &mut state, &mut identity, &mut agents);

        // Still cooling down (epoch 0 < unlock epoch 21); a second attempt
        // at the same nonce-advancing call correctly reports "not complete",
        // not a fresh, separately-tracked unbonding request.
        let unbond2 = Transaction::unbond_validator("unbond2", "qcb1alice", 2);
        let r = exec.execute_tx_with_identity(&unbond2, &mut state, &mut identity, &mut agents);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("cooldown not complete"));
    }

    #[test]
    fn bonding_by_different_validators_is_independent() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let a = Transaction::bond_validator("bondA", "qcb1alice", 2_000_000, 0);
        let b = Transaction::bond_validator("bondB", "qcb1bob", 4_000_000, 0);
        assert!(exec.execute_tx_with_identity(&a, &mut state, &mut identity, &mut agents).success);
        assert!(exec.execute_tx_with_identity(&b, &mut state, &mut identity, &mut agents).success);
        assert_eq!(state.get_account("validator-bond:qcb1alice").unwrap().balance_of("uqcb"), 2_000_000);
        assert_eq!(state.get_account("validator-bond:qcb1bob").unwrap().balance_of("uqcb"), 4_000_000);

        // Unbonding Alice must not touch Bob's independent bond.
        let unbond_a = Transaction::unbond_validator("unbondA", "qcb1alice", 1);
        assert!(exec.execute_tx_with_identity(&unbond_a, &mut state, &mut identity, &mut agents).success);
        assert_eq!(state.get_account("validator-bond:qcb1bob").unwrap().balance_of("uqcb"), 4_000_000);
    }

    #[test]
    fn compute_stake_active_set_ranks_live_bonded_stake() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let a = Transaction::bond_validator("bondA", "qcb1alice", 2_000_000, 0);
        let b = Transaction::bond_validator("bondB", "qcb1bob", 4_000_000, 0);
        let v = Transaction::bond_validator("bondV", "qcb1val", 500_000, 0); // below default min
        assert!(exec.execute_tx_with_identity(&a, &mut state, &mut identity, &mut agents).success);
        assert!(exec.execute_tx_with_identity(&b, &mut state, &mut identity, &mut agents).success);
        assert!(exec.execute_tx_with_identity(&v, &mut state, &mut identity, &mut agents).success);

        let active = validator_bond::compute_stake_active_set(
            &state, "uqcb", validator_bond::DEFAULT_MIN_BOND_UQCB, validator_bond::DEFAULT_MAX_ACTIVE_VALIDATORS,
        );
        // qcb1val's 500_000 is below the 1_000_000 minimum -- excluded.
        // Bob out-stakes Alice, so he ranks first.
        assert_eq!(active, vec![
            ("qcb1bob".to_string(), 4_000_000),
            ("qcb1alice".to_string(), 2_000_000),
        ]);
    }

    #[test]
    fn compute_stake_active_set_drops_validators_who_fully_unbond() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let bond = Transaction::bond_validator("bond1", "qcb1alice", 2_000_000, 0);
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents);
        let active_before = validator_bond::compute_stake_active_set(
            &state, "uqcb", validator_bond::DEFAULT_MIN_BOND_UQCB, validator_bond::DEFAULT_MAX_ACTIVE_VALIDATORS,
        );
        assert_eq!(active_before, vec![("qcb1alice".to_string(), 2_000_000)]);

        // UnbondValidator moves the bond out of validator-bond:qcb1alice
        // immediately (cooldown only gates when the *funds* return, not
        // when the validator stops counting toward the active set).
        let unbond = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        assert!(exec.execute_tx_with_identity(&unbond, &mut state, &mut identity, &mut agents).success);
        let active_after = validator_bond::compute_stake_active_set(
            &state, "uqcb", validator_bond::DEFAULT_MIN_BOND_UQCB, validator_bond::DEFAULT_MAX_ACTIVE_VALIDATORS,
        );
        assert!(active_after.is_empty());
    }

    #[test]
    fn compute_stake_active_set_respects_max_size_cap() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let a = Transaction::bond_validator("bondA", "qcb1alice", 2_000_000, 0);
        let b = Transaction::bond_validator("bondB", "qcb1bob", 4_000_000, 0);
        exec.execute_tx_with_identity(&a, &mut state, &mut identity, &mut agents);
        exec.execute_tx_with_identity(&b, &mut state, &mut identity, &mut agents);

        let active = validator_bond::compute_stake_active_set(&state, "uqcb", validator_bond::DEFAULT_MIN_BOND_UQCB, 1);
        // Capped to 1: only the higher-staked validator (Bob) makes it in.
        assert_eq!(active, vec![("qcb1bob".to_string(), 4_000_000)]);
    }

    #[test]
    fn simple_executor_rejects_bonding_tx_types() {
        // BondValidator/UnbondValidator need identity.clock.current_epoch
        // for the cooldown and are only supported via
        // execute_tx_with_identity(); the plain execute_tx() path must
        // reject them explicitly rather than silently no-op or panic.
        let (exec, mut state) = setup();
        let tx = Transaction::bond_validator("bond1", "qcb1alice", 1_000_000, 0);
        let r = exec.execute_tx(&tx, &mut state);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("identity-aware executor"));
    }

    #[test]
    fn sponsor_agent_requires_verified_identity() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        // Bob is not in identity store -- should fail
        let tx = Transaction::sponsor_agent("tx1", "qcb1bob", "qcb1agent1", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(!result.success, "unverified identity cannot sponsor agents");
    }

    #[test]
    fn sponsor_agent_succeeds_for_verified_human() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        let tx = Transaction::sponsor_agent("tx1", "qcb1alice", "qcb1agent1", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);

        assert!(result.success, "{:?}", result.error);
        assert!(identity.is_agent_authorized("qcb1agent1", "qcb1alice"),
            "agent should be authorized after sponsor tx");
    }

    #[test]
    fn spend_earns_decay_exemption() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        // Attach charm to alice's account first
        let mut charm = chain_forge_identity::IntrinsicCharm::provisional(0);
        charm.verify(0);
        let mut alice = state.get_account("qcb1alice").unwrap().clone();
        alice.attach_charm(charm);
        state.upsert_account(alice);

        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 0);

        // Transfer triggers spend -> exemption credit
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0);
        exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);

        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 1,
            "spending should earn 1 day of decay exemption");
    }

    // -- Identity pilot: RegisterIdentity + Attest transactions ---------------

    #[test]
    fn register_identity_tx_creates_provisional_account_with_charm() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        // FS-03: fund newbie so they can pay the registration fee
        {
            let mut acct = chain_forge_state::AccountState::new("qcb1newbie".into(), "user".into());
            acct.credit("uqcb", 10_000);
            state.upsert_account(acct);
        }

        let tx = Transaction::register_identity("tx1", "qcb1newbie", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);

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

        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        // Bootstrap two more Verified attesters alongside alice (already
        // Verified via setup_with_identity's genesis path).
        for name in ["qcb1bob", "qcb1carol"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att, None).unwrap();
        }

        // FS-03: fund newbie, bob, and carol so they can pay transaction fees
        for name in ["qcb1newbie", "qcb1bob", "qcb1carol"] {
            let mut acct = chain_forge_state::AccountState::new(name.into(), "user".into());
            acct.credit("uqcb", 10_000);
            state.upsert_account(acct);
        }

        // Register the real claimant via the actual transaction path.
        let reg_tx = Transaction::register_identity("tx0", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&reg_tx, &mut state, &mut identity, &mut agents);

        // Two attestations: still Provisional on-chain.
        let a1 = Transaction::attest("tx1", "qcb1alice", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&a1, &mut state, &mut identity, &mut agents);
        let a2 = Transaction::attest("tx2", "qcb1bob", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&a2, &mut state, &mut identity, &mut agents);
        assert_eq!(
            state.get_account("qcb1newbie").unwrap().verification_tier(),
            Some(&VerificationTier::Provisional)
        );

        // Third distinct attestation crosses quorum -- both IdentityStore
        // AND the on-chain account must now show Verified.
        let a3 = Transaction::attest("tx3", "qcb1carol", "qcb1newbie", 0);
        let result = exec.execute_tx_with_identity(&a3, &mut state, &mut identity, &mut agents);
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

        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        for name in ["qcb1bob", "qcb1carol"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att, None).unwrap();
        }

        // FS-03: fund new accounts so they can pay registration fees
        for name in ["qcb1newbie", "qcb1other"] {
            let mut acct = chain_forge_state::AccountState::new(name.into(), "user".into());
            acct.credit("uqcb", 10_000);
            state.upsert_account(acct);
        }

        // Registration advances the new account's nonce 0 -> 1.
        let reg = Transaction::register_identity("r0", "qcb1newbie", 0);
        assert!(exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut agents).success);
        assert_eq!(state.get_account("qcb1newbie").unwrap().nonce, 1);

        // Replaying the exact same registration is now a nonce mismatch,
        // not a second trip into the identity logic.
        let replay = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut agents);
        assert!(!replay.success);
        assert!(replay.error.as_deref().unwrap_or("").contains("nonce mismatch"));

        // An attester's first attest advances their nonce, so their second
        // transaction must use nonce 1 -- and does succeed with it.
        let a1 = Transaction::attest("a1", "qcb1alice", "qcb1newbie", 0);
        assert!(exec.execute_tx_with_identity(&a1, &mut state, &mut identity, &mut agents).success);
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 1);

        exec.execute_tx_with_identity(
            &Transaction::register_identity("r1", "qcb1other", 0),
            &mut state, &mut identity, &mut agents,
        );
        let a2 = Transaction::attest("a2", "qcb1alice", "qcb1other", 1);
        let r = exec.execute_tx_with_identity(&a2, &mut state, &mut identity, &mut agents);
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

    // -- CF-VAL-KEY-002: RegisterValidatorKey authentication ----------------

    fn register_key_tx(
        sender: &str, nonce: u64, consensus_kp: &KeyPair, pop_signer: &KeyPair, chain_id: &str,
    ) -> Transaction {
        let pop_msg = validator_key_registration_signing_bytes(chain_id, sender);
        let pop_sig = ClassicalScheme.sign(&pop_msg, pop_signer).unwrap();
        Transaction {
            id:        format!("regkey-{sender}-{nonce}"),
            sender:    sender.to_string(),
            nonce,
            body:      TxBody::RegisterValidatorKey {
                consensus_pubkey:    consensus_kp.public_key.clone(),
                proof_of_possession: pop_sig.bytes,
                scheme:              String::new(),
                pop_version:         1,
            },
            gas_limit: 10_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        }
    }

    #[test]
    fn register_validator_key_succeeds_with_valid_proof_of_possession() {
        let (exec, mut state, alice) = signed_setup();
        let consensus_kp = key("alice-consensus-key");
        let mut tx = register_key_tx("qcb1alice", 0, &consensus_kp, &consensus_kp, "qcb-testnet-1");
        tx.sign(&alice, "qcb-testnet-1").unwrap();

        let r = exec.execute_tx_with_identity(
            &tx, &mut state,
            &mut chain_forge_identity::IdentityStore::new(0),
            &mut AgentStore::new(),
        );
        assert!(r.success, "{:?}", r.error);
        assert!(r.events.iter().any(|e| e.starts_with("register_validator_key:")));
    }

    #[test]
    fn register_validator_key_rejects_forged_proof_of_possession() {
        // CF-VAL-KEY-002 Phase 4 test #3: "A forged key registration is
        // rejected." The sender authenticates itself correctly, but signs
        // the proof-of-possession with a DIFFERENT key than the one it is
        // trying to register as `consensus_pubkey` -- i.e. it does not
        // actually hold the private half of the key being registered.
        let (exec, mut state, alice) = signed_setup();
        let real_consensus_kp = key("alice-consensus-key");
        let attacker_kp       = key("not-alices-key-at-all");
        let mut tx = register_key_tx("qcb1alice", 0, &real_consensus_kp, &attacker_kp, "qcb-testnet-1");
        tx.sign(&alice, "qcb-testnet-1").unwrap();

        let r = exec.execute_tx_with_identity(
            &tx, &mut state,
            &mut chain_forge_identity::IdentityStore::new(0),
            &mut AgentStore::new(),
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("proof-of-possession"));
    }

    #[test]
    fn register_validator_key_requires_authentication_even_when_chain_allows_unsigned_txs() {
        // The general `require_signatures = false` devnet convenience must
        // never extend to binding an unauthenticated consensus key. Using
        // the permissive `setup()` fixture (require_signatures: false in
        // genesis) and submitting a completely unsigned RegisterValidatorKey
        // tx must still fail -- unlike an ordinary unsigned Transfer, which
        // `setup()`'s chain would accept.
        let (exec, mut state) = setup();
        let consensus_kp = key("some-consensus-key");
        // Unsigned: tx.signature and tx.public_key both left empty.
        let tx = register_key_tx("qcb1val", 0, &consensus_kp, &consensus_kp, "qcb-testnet-1");

        let r = exec.execute_tx_with_identity(
            &tx, &mut state,
            &mut chain_forge_identity::IdentityStore::new(0),
            &mut AgentStore::new(),
        );
        assert!(
            !r.success,
            "a RegisterValidatorKey tx must require real sender authentication \
             even on a chain configured with require_signatures = false"
        );

        // Sanity: the SAME chain really does accept an unsigned ordinary
        // transfer, confirming the rejection above is specific to
        // RegisterValidatorKey's unconditional check, not an accidental
        // side effect of some other change.
        let transfer = Transaction::transfer("t1", "qcb1val", "qcb1alice", "uqcb", 10, 0);
        let r2 = exec.execute_tx(&transfer, &mut state);
        assert!(r2.success, "{:?}", r2.error);
    }

    #[test]
    fn register_validator_key_rejects_empty_consensus_pubkey() {
        let (exec, mut state, alice) = signed_setup();
        let consensus_kp = key("alice-consensus-key");
        let mut tx = register_key_tx("qcb1alice", 0, &consensus_kp, &consensus_kp, "qcb-testnet-1");
        tx.body = TxBody::RegisterValidatorKey { consensus_pubkey: vec![], proof_of_possession: vec![1,2,3], scheme: String::new(), pop_version: 1 };
        tx.sign(&alice, "qcb-testnet-1").unwrap();

        let r = exec.execute_tx_with_identity(
            &tx, &mut state,
            &mut chain_forge_identity::IdentityStore::new(0),
            &mut AgentStore::new(),
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("must not be empty"));
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

    // ── CS-001-H2: versioned signature envelope tests ─────────────────────────

    /// sig_scheme = Classical is set by sign() and the verifier accepts it.
    #[test]
    fn cs001_h2_sign_sets_sig_scheme_classical() {
        let (exec, mut state, alice) = signed_setup();
        let mut tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sign(&alice, "qcb-testnet-1").unwrap();
        assert_eq!(tx.sig_scheme, Some(SchemeId::Classical),
            "sign() must set sig_scheme = Classical for a classical keypair");
        let r = exec.execute_tx(&tx, &mut state);
        assert!(r.success, "tx with explicit Classical scheme tag must succeed");
    }

    /// sig_scheme = Classical on a tx with no actual signature body → rejected.
    #[test]
    fn cs001_h2_explicit_classical_scheme_with_empty_sig_rejected() {
        let (exec, mut state, _) = signed_setup();
        let mut tx = Transaction::transfer("tx2", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sig_scheme = Some(SchemeId::Classical);  // claim classical but no sig bytes
        let r = exec.execute_tx(&tx, &mut state);
        assert!(!r.success, "Classical scheme tag with empty signature must fail");
    }

    /// Legacy tx (sig_scheme = None, pq_signatures prefix present) still routes
    /// to ML-DSA path — backward compatibility with pre-CS-001 transactions.
    #[test]
    fn cs001_h2_legacy_mldsa_prefix_still_accepted_when_scheme_absent() {
        // Build an ML-DSA tx the old way (no sig_scheme tag) and verify it routes correctly.
        let (tx, pk) = make_pq_tx_with_chain("qcb-testnet-1", "qcb1alice", 0, "alice-pq");
        // tx has sig_scheme = Some(MlDsa) from make_pq_tx_with_chain; strip it to test legacy path
        let mut legacy_tx = tx;
        legacy_tx.sig_scheme = None;  // simulate a pre-CS-001 tx

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut config = ExecutionConfig::from_genesis(&genesis);
        config.require_signatures = true;
        config.chain_id = "qcb-testnet-1".to_string();
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();

        // Derive alice's address from her ML-DSA pubkey and fund it.
        // CS-001-H1: ML-DSA keys use AddressScheme::PostQuantum → qcb1pq… namespace.
        let alice_addr = Address::from_public_key_schemed(
            &pk, "qcb", HashWidth::Bits256, chain_forge_core::AddressScheme::PostQuantum,
        );
        {
            let mut acct = chain_forge_state::AccountState::new(
                alice_addr.as_str().to_string(), "user".to_string()
            );
            acct.credit("uqcb", 1_000_000);
            state.upsert_account(acct);
        }
        legacy_tx.sender = alice_addr.as_str().to_string();

        let exec = Executor::new(config);
        let r = exec.execute_tx(&legacy_tx, &mut state);
        // Should succeed: verifier falls back to pq_signatures prefix scan
        assert!(r.success,
            "legacy ML-DSA tx without sig_scheme tag must still be accepted (backward compat): {:?}",
            r.error);
    }

    /// sig_scheme = MlDsa but pq_signatures is empty → verifier rejects cleanly.
    #[test]
    fn cs001_h2_explicit_mldsa_scheme_with_no_pq_signatures_rejected() {
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut config = ExecutionConfig::from_genesis(&genesis);
        config.require_signatures = true;
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let exec = Executor::new(config);

        let mut tx = Transaction::transfer("tx3", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sig_scheme = Some(SchemeId::MlDsa);  // claim ML-DSA but provide no pq_signatures
        let r = exec.execute_tx(&tx, &mut state);
        assert!(!r.success, "MlDsa scheme tag with empty pq_signatures must fail");
        let err = r.error.unwrap();
        assert!(err.contains("mldsa65") || err.contains("pq_signatures"),
            "error should mention missing pq_signatures, got: {err}");
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
        let (_, mut state, mut identity, mut agents) = setup_with_identity();
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut config = ExecutionConfig::from_genesis(&genesis);
        config.require_signatures = true;
        let exec = Executor::new(config);

        let user = key("new-user");
        let addr = Address::from_public_key(&user.public_key, "qcb", HashWidth::Bits256);

        // FS-03: fund the new address so it can pay the registration fee
        {
            let mut acct = chain_forge_state::AccountState::new(addr.as_str().into(), "user".into());
            acct.credit("uqcb", 10_000);
            state.upsert_account(acct);
        }

        let mut reg = Transaction::register_identity("r0", addr.as_str(), 0);
        reg.sign(&user, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut agents);
        assert!(r.success, "{:?}", r.error);

        let acct = state.get_account(addr.as_str()).unwrap();
        assert_eq!(acct.public_key.as_deref(), Some(user.public_key.as_slice()), "first tx binds the key");
        assert_eq!(acct.nonce, 1);

        // A different key can no longer act for this address.
        let other = key("someone-else");
        let mut hijack = Transaction::attest("h1", addr.as_str(), "qcb1alice", 1);
        hijack.sign(&other, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx_with_identity(&hijack, &mut state, &mut identity, &mut agents);
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
        let mut agents = chain_forge_agents::AgentStore::new();

        // FS-03: fund newcomer, bob, and carol so they can pay transaction fees
        for name in ["qcb1newcomer", "qcb1bob", "qcb1carol"] {
            let mut acct = chain_forge_state::AccountState::new(name.into(), "user".into());
            acct.credit("uqcb", 10_000);
            state.upsert_account(acct);
        }

        let root_before = state.commit(0, 0, false).root_hash;

        // Register newcomer -- should change the state root (Provisional charm attached).
        let reg = Transaction::register_identity("t-reg", "qcb1newcomer", 0);
        let r = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut agents);
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
            let r = exec.execute_tx_with_identity(&attest, &mut state, &mut identity, &mut agents);
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
        let (_, mut state, mut identity, mut agents) = setup_with_identity();
        let exec = plain_chain_exec();
        let cases = [
            (Transaction::register_identity("t1", "qcb1alice", 0), "identity"),
            (Transaction::attest("t2", "qcb1alice", "qcb1bob", 0), "identity"),
            (Transaction::bond_validator("t3", "qcb1alice", 1_000, 0), "staking"),
            (Transaction::sponsor_agent("t4", "qcb1alice", "qcb1agent", 0), "agents"),
        ];
        for (tx, module) in cases {
            let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
            assert!(!r.success, "{} must be rejected on a plain chain", tx.id);
            assert!(r.error.unwrap().contains(&format!("module \"{module}\" is not enabled")));
        }
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 0, "gated txs must not advance the nonce");
    }

    #[test]
    fn plain_chain_still_allows_core_transfers() {
        let (_, mut state, mut identity, mut agents) = setup_with_identity();
        let exec = plain_chain_exec();
        let tx = Transaction::transfer("t1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(r.success, "{:?}", r.error);
    }

    #[test]
    fn every_tx_type_maps_to_a_known_module_or_core() {
        let known: Vec<&str> = chain_forge_core::KNOWN_MODULES.iter().map(|(n, _)| *n).collect();
        let bodies = [
            TxBody::RegisterIdentity,
            TxBody::Attest { claimant_id: "x".into() },
            TxBody::SponsorAgent { agent_address: "x".into() },
            TxBody::RevokeAgent { agent_address: "x".into() },
            // Phase D attestation guard tx types
            TxBody::RevokeAttestation { attested_id: "x".into() },
            TxBody::ConfirmSybil { sybil_id: "x".into() },
            TxBody::ReverseSybil { sybil_id: "x".into() },
            TxBody::ReportSuspectedSybil { suspected_id: "x".into() },
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

    // ── B4: Chain-ID enforcement in ML-DSA signing path ──────────────────────
    //
    // chain-forge-execution always links chain-forge-crypto with real-pqc,
    // so ML-DSA is always the real implementation here.  These tests verify
    // that the execution layer binds chain_id into the ML-DSA signing message
    // (DIS-001 Phase B, criterion B4).

    /// Build a signed PQ transaction for testing.
    ///
    /// Constructs a TxBody::Transfer, serialises it to get the canonical JSON
    /// that verify_mldsa_authorization will also produce, then signs over
    /// SHA-256("chain-forge/pq-tx/v1\n{chain_id}\n{canonical_body_json}")
    /// using ML-DSA-65 (same construction as chain-forge-wallet::sign_transaction).
    ///
    /// The public key is returned separately and placed in tx.pq_public_key
    /// for first-use key registration (no pre-bound key in state needed).
    fn make_pq_tx_with_chain(
        chain_id: &str,
        sender:   &str,
        nonce:    u64,
        seed:     &str,
    ) -> (Transaction, Vec<u8>) {
        let kp = MlDsaScheme.generate_keypair(seed).expect("ML-DSA keygen");
        let pk = kp.public_key.clone();

        // Build canonical body and serialise exactly as the executor will.
        let body = TxBody::Transfer {
            to:     "qcb1recv".to_string(),
            denom:  "uqcb".to_string(),
            amount: 100,
        };
        let body_json = serde_json::to_string(&body).expect("body serialise");

        // CS-001-M2: use the canonical pre-hash helper (matches the verifier exactly).
        let message = mldsa_tx_prehash(chain_id, body_json.as_bytes());

        let sig = MlDsaScheme.sign(&message, &kp).expect("ML-DSA sign");
        let sig_hex = sig.bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

        let tx = Transaction {
            id:            format!("b4-tx-{nonce}"),
            sender:        sender.to_string(),
            nonce,
            body,
            gas_limit:     500_000,
            signature:     vec![],
            public_key:    vec![],
            pq_signatures: vec![format!("mldsa65:{sig_hex}")],
            sig_scheme:    Some(SchemeId::MlDsa),  // CS-001-H2
            pq_public_key: pk.clone(),
        };
        (tx, pk)
    }

    /// Set up an executor with require_signatures = true and a funded sender account.
    ///
    /// The sender's account has no pre-bound PQ key; the executor will accept
    /// tx.pq_public_key for first-use registration (documented in verify_mldsa_authorization).
    fn setup_signed(chain_id: &str, sender: &str) -> (Executor, StateStore) {
        let genesis_json = format!(r#"{{
            "chain_id": "{chain_id}",
            "chain_name": "B4 test chain",
            "engine_version": "0.1.0",
            "genesis_time": "2026-10-09T00:00:00Z",
            "environment": {{ "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true }},
            "native_token": {{ "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" }},
            "address_prefix": "qcb",
            "consensus": {{ "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 }},
            "execution": {{ "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": true }},
            "cryptography": {{ "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "classical-ed25519" }},
            "network": {{ "network_id": "b4-net", "p2p_port": 27000, "rpc_port": 27001, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 }},
            "limits": {{ "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 }},
            "modules": ["bank"],
            "custom_modules": [],
            "genesis_accounts": [
                {{ "label": "sender", "address": "{sender}", "balance": "5000000", "role": "user" }},
                {{ "label": "recv",   "address": "qcb1recv",  "balance": "0",       "role": "user" }}
            ]
        }}"#);

        let genesis = GenesisConfig::from_json(&genesis_json).expect("B4 genesis");
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();

        (Executor::new(config), state)
    }

    /// B4 — Correct chain_id: signed TX must be accepted.
    #[test]
    fn b4_mldsa_correct_chain_id_accepted() {
        const CHAIN: &str = "qcb-b4-test";
        let (tx, _pk) = make_pq_tx_with_chain(CHAIN, "qcb1sender", 0, "b4-alice-seed");
        let (exec, mut state) = setup_signed(CHAIN, "qcb1sender");
        let r = exec.execute_tx(&tx, &mut state);
        assert!(r.success,
            "valid ML-DSA tx with correct chain_id must be accepted; error: {:?}", r.error);
    }

    /// B4 — Wrong chain_id: the same signature submitted to a different chain must fail.
    #[test]
    fn b4_mldsa_wrong_chain_id_rejected() {
        const SIGNING_CHAIN: &str = "qcb-chain-A";
        const WRONG_CHAIN:   &str = "qcb-chain-B";  // attacker submits to a different chain

        // TX signed for chain A …
        let (tx, _pk) = make_pq_tx_with_chain(SIGNING_CHAIN, "qcb1sender", 0, "b4-bob-seed");
        // … but verified against chain B's executor (cross-chain replay attack)
        let (exec, mut state) = setup_signed(WRONG_CHAIN, "qcb1sender");
        let r = exec.execute_tx(&tx, &mut state);
        assert!(!r.success,
            "ML-DSA tx signed for chain '{SIGNING_CHAIN}' must be rejected on chain '{WRONG_CHAIN}'");
        let err = r.error.unwrap_or_default();
        assert!(
            err.contains("ML-DSA") || err.contains("signature") || err.contains("verif"),
            "error must indicate signature failure; got: {err}"
        );
    }

    /// B3 — gas_limit=0 must be rejected (floor check: gas_limit < gas_required).
    #[test]
    fn b3_gas_limit_zero_rejected() {
        const CHAIN: &str = "qcb-b3-test";
        const SENDER: &str = "qcb1b3sender";
        let genesis_json = format!(r#"{{
            "chain_id": "{CHAIN}",
            "chain_name": "B3 test",
            "engine_version": "0.1.0",
            "genesis_time": "2026-10-09T00:00:00Z",
            "environment": {{ "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true }},
            "native_token": {{ "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" }},
            "address_prefix": "qcb",
            "consensus": {{ "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 }},
            "execution": {{ "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": false }},
            "cryptography": {{ "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "classical-ed25519" }},
            "network": {{ "network_id": "b3-net", "p2p_port": 27000, "rpc_port": 27001, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 }},
            "limits": {{ "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 }},
            "modules": ["bank"],
            "custom_modules": [],
            "genesis_accounts": [
                {{ "label": "b3sender", "address": "{SENDER}", "balance": "5000000", "role": "user" }}
            ]
        }}"#);
        let genesis = GenesisConfig::from_json(&genesis_json).expect("B3 genesis");
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let exec = Executor::new(config);

        let tx = Transaction {
            id:            "b3-zero-gas-unit".to_string(),
            sender:        SENDER.to_string(),
            nonce:         0,
            body:          TxBody::Transfer { to: "qcb1carol".to_string(), denom: "uqcb".to_string(), amount: 100 },
            gas_limit:     0,
            signature:     vec![],
            public_key:    vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &tx, &mut state,
            &mut IdentityStore::new(0),
            &mut AgentStore::new(),
        );
        assert!(!r.success, "gas_limit=0 must be rejected; got success=true");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("gas limit") || err.contains("gas"),
            "error must mention gas; got: {err}");
    }

    /// B3 — gas_limit > block_gas_limit must be rejected (ceiling check).
    #[test]
    fn b3_gas_limit_huge_rejected() {
        const CHAIN: &str = "qcb-b3-huge-test";
        const SENDER: &str = "qcb1b3hugesender";
        let genesis_json = format!(r#"{{
            "chain_id": "{CHAIN}",
            "chain_name": "B3 huge test",
            "engine_version": "0.1.0",
            "genesis_time": "2026-10-09T00:00:00Z",
            "environment": {{ "mode": "devnet", "faucet_enabled": true, "relaxed_limits": true }},
            "native_token": {{ "name": "QC", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" }},
            "address_prefix": "qcb",
            "consensus": {{ "type": "proof-of-stake", "validator_set_size": 3, "block_time_ms": 500 }},
            "execution": {{ "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": false }},
            "cryptography": {{ "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "classical-ed25519" }},
            "network": {{ "network_id": "b3-net2", "p2p_port": 27002, "rpc_port": 27003, "bootstrap_nodes": [], "peer_discovery": "bootstrap", "max_peers": 10 }},
            "limits": {{ "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 100, "mempool_ttl_seconds": 60 }},
            "modules": ["bank"],
            "custom_modules": [],
            "genesis_accounts": [
                {{ "label": "b3hugesender", "address": "{SENDER}", "balance": "5000000", "role": "user" }}
            ]
        }}"#);
        let genesis = GenesisConfig::from_json(&genesis_json).expect("B3 huge genesis");
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let exec = Executor::new(config);

        let tx = Transaction {
            id:            "b3-huge-gas-unit".to_string(),
            sender:        SENDER.to_string(),
            nonce:         0,
            body:          TxBody::Transfer { to: "qcb1carol".to_string(), denom: "uqcb".to_string(), amount: 100 },
            gas_limit:     10_000_000_000,  // 10B — exceeds block_gas_limit of 10M
            signature:     vec![],
            public_key:    vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &tx, &mut state,
            &mut IdentityStore::new(0),
            &mut AgentStore::new(),
        );
        assert!(!r.success, "gas_limit=10B must be rejected; got success=true");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("gas limit") || err.contains("exceeds"),
            "error must mention gas cap; got: {err}");
    }

    // ── CS-001 P4: EmergencyDeprecateAlgorithm tests ──────────────────────────

    /// Helper: build a genesis JSON with a crypto_governor and return
    /// a ready (Executor, StateStore, IdentityStore, AgentStore).
    fn cs001_p4_setup(governor: &str) -> (Executor, StateStore, IdentityStore, chain_forge_agents::AgentStore) {
        let genesis_json = format!(r#"{{
            "chain_id": "qcb-cs001p4-test",
            "chain_name": "CS001P4Test",
            "engine_version": "0.1.0",
            "genesis_time": "2026-10-18T00:00:00Z",
            "environment": {{ "mode": "testnet", "faucet_enabled": false, "relaxed_limits": true }},
            "native_token": {{ "name": "QuarkCharm", "symbol": "QCB", "denom": "uqcb", "max_supply": "210000000" }},
            "address_prefix": "qcb",
            "consensus": {{ "type": "proof-of-stake", "validator_set_size": 4, "block_time_ms": 5000 }},
            "execution": {{ "state_model": "account", "parallel_execution": false, "gas_model": "dynamic", "require_signatures": false }},
            "cryptography": {{ "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" }},
            "network": {{ "network_id": "test-net", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "both", "max_peers": 50 }},
            "limits": {{ "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 5000, "mempool_ttl_seconds": 300 }},
            "modules": ["bank", "staking", "identity", "qrc", "agents", "market", "pocd"],
            "custom_modules": [],
            "crypto_governors": ["{governor}"],
            "genesis_accounts": [
                {{ "label": "Governor",  "address": "{governor}", "balance": "10000000", "role": "user" }},
                {{ "label": "Alice",     "address": "qcb1alice",  "balance": "5000000",  "role": "user" }},
                {{ "label": "Bob",       "address": "qcb1bob",    "balance": "5000000",  "role": "user" }}
            ]
        }}"#);
        let genesis = GenesisConfig::from_json(&genesis_json).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let mut identity = IdentityStore::new(0);
        identity.clock.current_epoch = 42;
        let agents = chain_forge_agents::AgentStore::new();
        (Executor::new(config), state, identity, agents)
    }

    fn emergency_deprecate_tx(
        id: &str, sender: &str, nonce: u64,
        from_scheme: &str, to_scheme: &str,
        grace: u64, rationale: &str,
    ) -> Transaction {
        Transaction {
            id: id.to_string(),
            sender: sender.to_string(),
            nonce,
            body: TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:  from_scheme.to_string(),
                replacement_scheme: to_scheme.to_string(),
                grace_epochs: grace,
                rationale: rationale.to_string(),
                advisory_ref: None,
                scope: DeprecationScope::TxSignatures,
            },
            gas_limit: 5_000_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
            sig_scheme: None,
        }
    }

    /// CS-001-P4-T1: Authorized governor can initiate a deprecation.
    /// After the tx succeeds, CryptoMigrationState is persisted in state.
    #[test]
    fn cs001_p4_governor_can_deprecate() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);
        let tx = emergency_deprecate_tx("eda1", gov, 0,
            "Ed25519", "ML-DSA-65", 30, "Credible CRQC report from NIST-2026");

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(r.success, "authorized governor should succeed: {:?}", r.error);

        // Migration state must now be persisted.
        let raw = state.get_raw(CRYPTO_MIGRATION_STATE_KEY)
            .expect("CryptoMigrationState should be stored after deprecation tx");
        let migration: CryptoMigrationState = serde_json::from_str(raw)
            .expect("persisted migration state must deserialize");

        assert_eq!(migration.deprecated_scheme,  "Ed25519");
        assert_eq!(migration.replacement_scheme, "ML-DSA-65");
        assert_eq!(migration.grace_epochs_remaining(42), 29,
            "initiated at epoch 42, grace=30 => cutoff=71, remaining=29");
        assert!(!migration.hard_cutoff_passed(42),  "should still be in grace window at epoch 42");
        assert!(!migration.hard_cutoff_passed(71),  "epoch 71 is the last valid epoch");
        assert!(migration.hard_cutoff_passed(72),   "epoch 72 is past hard cutoff");
        assert_eq!(migration.initiated_by, gov);
        assert_eq!(migration.tx_id, "eda1");
    }

    /// CS-001-P4-T2: Non-governor cannot initiate a deprecation.
    #[test]
    fn cs001_p4_non_governor_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);
        let tx = emergency_deprecate_tx("eda2", "qcb1alice", 0,
            "Ed25519", "ML-DSA-65", 30, "Unauthorized attempt");

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(!r.success, "non-governor must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("not a crypto governor"), "error: {err}");
        assert!(state.get_raw(CRYPTO_MIGRATION_STATE_KEY).is_none(),
            "no migration state should be written on rejection");
    }

    /// CS-001-P4-T3: Grace period below minimum is rejected.
    #[test]
    fn cs001_p4_grace_too_short_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);
        let tx = emergency_deprecate_tx("eda3", gov, 0,
            "Ed25519", "ML-DSA-65", MIN_CRYPTO_GRACE_EPOCHS - 1,
            "Short grace period test");

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(!r.success, "grace below minimum must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("grace_epochs") && err.contains("out of range"), "error: {err}");
    }

    /// CS-001-P4-T4: Grace period above maximum is rejected.
    #[test]
    fn cs001_p4_grace_too_long_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);
        let tx = emergency_deprecate_tx("eda4", gov, 0,
            "Ed25519", "ML-DSA-65", MAX_CRYPTO_GRACE_EPOCHS + 1,
            "Long grace period test");

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(!r.success, "grace above maximum must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("grace_epochs") && err.contains("out of range"), "error: {err}");
    }

    /// CS-001-P4-T5: Same deprecated and replacement scheme is rejected.
    #[test]
    fn cs001_p4_same_scheme_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);
        let tx = emergency_deprecate_tx("eda5", gov, 0,
            "Ed25519", "Ed25519", 30, "Noop migration test");

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(!r.success, "same deprecated/replacement must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("must be different"), "error: {err}");
    }

    /// CS-001-P4-T6: Empty rationale is rejected.
    #[test]
    fn cs001_p4_empty_rationale_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);
        let tx = emergency_deprecate_tx("eda6", gov, 0,
            "Ed25519", "ML-DSA-65", 30, "   ");

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(!r.success, "blank rationale must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("rationale must not be empty"), "error: {err}");
    }

    /// CS-001-P4-T7: A second deprecation while one is active is rejected.
    /// Enforces the "one active migration at a time" invariant.
    #[test]
    fn cs001_p4_double_migration_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // First deprecation — should succeed.
        let tx1 = emergency_deprecate_tx("eda7a", gov, 0,
            "Ed25519", "ML-DSA-65", 30, "First migration");
        let r1 = exec.execute_tx_with_identity(&tx1, &mut state, &mut identity, &mut agents);
        assert!(r1.success, "first deprecation must succeed: {:?}", r1.error);

        // Second deprecation while first is in progress — must be rejected.
        let tx2 = emergency_deprecate_tx("eda7b", gov, 1,
            "ML-DSA-65", "Hybrid-Ed25519-ML-DSA", 50, "Second migration");
        let r2 = exec.execute_tx_with_identity(&tx2, &mut state, &mut identity, &mut agents);
        assert!(!r2.success, "second deprecation while one is active must be rejected");
        let err = r2.error.unwrap_or_default();
        assert!(err.contains("already in progress"), "error: {err}");
    }

    /// CS-001-P4-T8 (Adversarial / Simulated Compromise): Simulate a scenario
    /// where the Ed25519 scheme is treated as "broken" and the network must
    /// migrate cleanly.
    ///
    /// Sequence:
    ///   1. Governor submits EmergencyDeprecateAlgorithm (Ed25519 → ML-DSA-65).
    ///   2. During grace window: verify CryptoMigrationState reports correct state.
    ///   3. At hard cutoff epoch: in_grace_window() is false.
    ///   4. After migration is accepted: clear migration state (simulating scheduler).
    ///   5. No further migration state exists — network is fully migrated.
    #[test]
    fn cs001_p4_simulated_compromise_migration_sequence() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // ── Step 1: Governor raises emergency — Ed25519 is compromised ────────
        let grace = 20u64;
        let tx = Transaction {
            id: "compromise-sim-1".to_string(),
            sender: gov.to_string(),
            nonce: 0,
            body: TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:  "Ed25519".to_string(),
                replacement_scheme: "ML-DSA-65".to_string(),
                grace_epochs: grace,
                rationale: "Simulated CRQC attack: Ed25519 private keys exposed by \
                            adversary with quantum oracle access".to_string(),
                advisory_ref: Some("SIMULATED-CRQC-2026-001".to_string()),
                scope: DeprecationScope::TxSignatures,
            },
            gas_limit: 5_000_000,
            signature: vec![], public_key: vec![], pq_signatures: vec![],
            pq_public_key: vec![], sig_scheme: None,
        };

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(r.success, "compromise simulation tx must succeed: {:?}", r.error);

        // ── Step 2: Check migration state during grace window ─────────────────
        let raw = state.get_raw(CRYPTO_MIGRATION_STATE_KEY).unwrap();
        let migration: CryptoMigrationState = serde_json::from_str(raw).unwrap();

        let initiated_epoch = 42u64; // from identity clock in cs001_p4_setup
        let expected_cutoff = initiated_epoch + grace - 1; // epoch 61

        assert_eq!(migration.initiated_epoch, initiated_epoch);
        assert_eq!(migration.hard_cutoff_epoch, expected_cutoff);
        assert_eq!(migration.advisory_ref.as_deref(), Some("SIMULATED-CRQC-2026-001"));

        // During grace window: old scheme still accepted
        for epoch in initiated_epoch..=expected_cutoff {
            assert!(migration.in_grace_window(epoch),
                "epoch {epoch} should still be in grace window (cutoff={expected_cutoff})");
            assert!(!migration.hard_cutoff_passed(epoch),
                "epoch {epoch}: hard cutoff should NOT have passed yet");
        }

        // ── Step 3: At and after hard cutoff epoch ────────────────────────────
        assert!(!migration.in_grace_window(expected_cutoff + 1),
            "epoch {} is past the grace window", expected_cutoff + 1);
        assert!(migration.hard_cutoff_passed(expected_cutoff + 1),
            "hard cutoff must have passed at epoch {}", expected_cutoff + 1);

        // Remaining epochs count down correctly
        assert_eq!(migration.grace_epochs_remaining(initiated_epoch), grace - 1);
        assert_eq!(migration.grace_epochs_remaining(expected_cutoff), 0);
        assert_eq!(migration.grace_epochs_remaining(expected_cutoff + 100), 0,
            "saturating_sub: never negative");

        // ── Step 4: Scheduler clears migration state after cutoff ─────────────
        // (In production this is done by the block-production scheduler once
        //  the hard cutoff epoch is confirmed committed. Here we simulate it.)
        state.remove_raw(CRYPTO_MIGRATION_STATE_KEY);
        assert!(state.get_raw(CRYPTO_MIGRATION_STATE_KEY).is_none(),
            "migration state must be cleared after scheduler sweep");

        // ── Step 5: Network can now initiate a new migration if needed ─────────
        // (No pending migration — a future deprecation tx would succeed.)
        assert!(state.get_raw(CRYPTO_MIGRATION_STATE_KEY).is_none(),
            "clean state: no active migration after completion");
    }

    /// CS-001-P4-T9: Empty crypto_governors list denies all deprecation txs.
    #[test]
    fn cs001_p4_no_governors_fail_closed() {
        // Build genesis WITHOUT crypto_governors (empty list = fail-closed).
        let genesis_json = genesis_json(); // standard test genesis, no crypto_governors
        let genesis = GenesisConfig::from_json(genesis_json).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let mut identity = IdentityStore::new(0);
        identity.clock.current_epoch = 1;
        let mut agents = chain_forge_agents::AgentStore::new();
        let exec = Executor::new(config);

        let tx = emergency_deprecate_tx("eda9", "qcb1alice", 0,
            "Ed25519", "ML-DSA-65", 30, "No governors configured");
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents);
        assert!(!r.success, "no crypto_governors must deny all deprecation txs");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("no crypto_governors configured"), "error: {err}");
    }

    /// CS-001-P4-T10: After the hard cutoff epoch passes, any transaction
    /// whose `sig_scheme` matches the deprecated algorithm is rejected by
    /// consensus.  Transactions using the replacement scheme are still accepted.
    ///
    /// This is the consensus-enforcement half of the migration: the governance
    /// tx (EmergencyDeprecateAlgorithm) sets the timeline; the executor enforces
    /// it here once `current_epoch > hard_cutoff_epoch`.
    #[test]
    fn cs001_p4_cutoff_rejects_deprecated_scheme_tx() {
        use chain_forge_crypto::SchemeId;

        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // Epoch 42: initiate deprecation of "ed25519" with grace = 10 epochs.
        // hard_cutoff_epoch = 42 + 10 - 1 = 51.
        let dep_tx = emergency_deprecate_tx("cutoff-dep", gov, 0,
            "ed25519", "ml-dsa", 10, "Simulated CRQC break");
        let r = exec.execute_tx_with_identity(&dep_tx, &mut state, &mut identity, &mut agents);
        assert!(r.success, "deprecation tx must succeed: {:?}", r.error);

        // Sanity: epoch 51 is the last grace epoch — transfer with Classical
        // sig_scheme should still be accepted.
        identity.clock.current_epoch = 51;
        let mut in_grace = Transaction::transfer(
            "t-grace", "qcb1alice", "qcb1bob", "uqcb", 1, 1
        );
        in_grace.sig_scheme = Some(SchemeId::Classical);
        let r = exec.execute_tx_with_identity(&in_grace, &mut state, &mut identity, &mut agents);
        // May fail for other reasons (balance, nonce) but must NOT fail with the
        // cutoff message while still in the grace window.
        if !r.success {
            let err = r.error.unwrap_or_default();
            assert!(!err.contains("was deprecated"),
                "Classical scheme must still be accepted at epoch 51 (in grace window); got: {err}");
        }

        // Epoch 52 = one past the hard cutoff — Classical scheme must be rejected.
        identity.clock.current_epoch = 52;
        let mut post_cutoff = Transaction::transfer(
            "t-post-cutoff", "qcb1alice", "qcb1bob", "uqcb", 1, 2
        );
        post_cutoff.sig_scheme = Some(SchemeId::Classical);
        let r = exec.execute_tx_with_identity(&post_cutoff, &mut state, &mut identity, &mut agents);
        assert!(!r.success, "Classical scheme must be rejected after hard cutoff");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("was deprecated"),
            "error must mention deprecation; got: {err}");
        assert!(err.contains("rotate to"),
            "error must hint at replacement scheme; got: {err}");

        // A transaction using the replacement scheme (ml-dsa) must NOT be
        // blocked by the cutoff check — the cutoff is scheme-specific.
        let mut pq_tx = Transaction::transfer(
            "t-pq-ok", "qcb1alice", "qcb1bob", "uqcb", 1, 2
        );
        pq_tx.sig_scheme = Some(SchemeId::MlDsa);
        let r = exec.execute_tx_with_identity(&pq_tx, &mut state, &mut identity, &mut agents);
        if !r.success {
            let err = r.error.unwrap_or_default();
            assert!(!err.contains("was deprecated"),
                "MlDsa scheme must not be blocked by Classical cutoff; got: {err}");
        }

        // CS-001-P6-G2: A transaction with sig_scheme = None (legacy classical path)
        // MUST be blocked by the cutoff after P6.  The untagged path reaches classical
        // Ed25519 verification, so it is treated as "ed25519" for cutoff purposes.
        // (This assertion was updated in P6; previously the gate did not cover None.)
        let untagged = Transaction::transfer(
            "t-untagged", "qcb1alice", "qcb1bob", "uqcb", 1, 2
        );
        assert!(untagged.sig_scheme.is_none());
        let r = exec.execute_tx_with_identity(&untagged, &mut state, &mut identity, &mut agents);
        assert!(!r.success, "Untagged classical tx must be blocked by cutoff after P6 (gap G2 closed)");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("was deprecated") || err.contains("deprecated"),
            "Untagged classical tx must fail with deprecation error; got: {err}");
    }

    /// CS-001 P5 — Guard 0: consensus-scope deprecations are explicitly rejected.
    ///
    /// `ConsensusSignatures` and `Both` scopes must be refused because
    /// consensus-signature migration has no verified replacement signing path.
    /// Only `TxSignatures` is permitted.
    #[test]
    fn cs001_p5_consensus_scope_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // ConsensusSignatures scope must be rejected.
        let consensus_tx = Transaction {
            id: "scope-cons".to_string(),
            sender: gov.to_string(),
            nonce: 0,
            body: TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme: "ed25519".to_string(),
                replacement_scheme: "ml-dsa".to_string(),
                grace_epochs: MIN_CRYPTO_GRACE_EPOCHS,
                rationale: "scope test".to_string(),
                advisory_ref: None,
                scope: DeprecationScope::ConsensusSignatures,
            },
            gas_limit: 5_000_000,
            signature: vec![],
            sig_scheme: None,
            public_key: vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &consensus_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success, "ConsensusSignatures scope must be rejected");
        let err = r.error.clone().unwrap_or_default();
        assert!(err.contains("not yet supported"),
            "error must say scope is not yet supported; got: {err}");
        assert!(err.contains("TxSignatures"),
            "error must hint at TxSignatures; got: {err}");

        // Both scope must also be rejected.
        let both_tx = Transaction {
            id: "scope-both".to_string(),
            sender: gov.to_string(),
            nonce: 0,
            body: TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme: "ed25519".to_string(),
                replacement_scheme: "ml-dsa".to_string(),
                grace_epochs: MIN_CRYPTO_GRACE_EPOCHS,
                rationale: "scope test both".to_string(),
                advisory_ref: None,
                scope: DeprecationScope::Both,
            },
            gas_limit: 5_000_000,
            signature: vec![],
            sig_scheme: None,
            public_key: vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &both_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success, "Both scope must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("not yet supported"),
            "error for Both scope must say not yet supported; got: {err}");

        // TxSignatures scope must succeed (sanity check the guard is scoped).
        let good_tx = emergency_deprecate_tx(
            "scope-ok", gov, 0, "ed25519", "ml-dsa",
            MIN_CRYPTO_GRACE_EPOCHS, "scope guard sanity",
        );
        let r = exec.execute_tx_with_identity(
            &good_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(r.success, "TxSignatures scope must succeed: {:?}", r.error);
        // Verify scope is persisted in migration state.
        let raw = state.get_raw(CRYPTO_MIGRATION_STATE_KEY)
            .expect("migration state must be written");
        let migration: CryptoMigrationState = serde_json::from_str(raw).unwrap();
        assert_eq!(migration.scope, DeprecationScope::TxSignatures,
            "persisted scope must be TxSignatures");
    }

    /// CS-001 P5 — Test 10: Restart cannot reactivate a deprecated algorithm.
    ///
    /// After deprecation is committed, a snapshot roundtrip (simulating restart)
    /// must preserve the migration state.  There is no code path that resets
    /// `CRYPTO_MIGRATION_STATE_KEY` — the test verifies this by confirming the
    /// key is present and identical after restore, and that the hard cutoff still
    /// fires post-restore.
    #[test]
    fn cs001_p5_restart_cannot_reactivate_deprecated_algorithm() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // 1. Submit deprecation tx.
        let dep_tx = emergency_deprecate_tx(
            "restart-dep", gov, 0, "ed25519", "ml-dsa",
            MIN_CRYPTO_GRACE_EPOCHS, "Restart survival test",
        );
        let r = exec.execute_tx_with_identity(
            &dep_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(r.success, "deprecation must succeed: {:?}", r.error);

        // 2. Record state root and migration JSON before snapshot.
        let pre_root   = state.commit(0, 0, false).root_hash;
        let pre_json   = state.get_raw(CRYPTO_MIGRATION_STATE_KEY)
            .expect("migration state must exist pre-snapshot")
            .to_string();
        let pre_migration: CryptoMigrationState =
            serde_json::from_str(&pre_json).unwrap();

        // 3. Export snapshot (simulates node shutdown / persistence).
        let snapshot = state.export_snapshot();
        assert!(snapshot.metadata.contains_key(CRYPTO_MIGRATION_STATE_KEY),
            "snapshot metadata must carry migration state");

        // 4. Restore snapshot (simulates node restart from disk).
        state.restore_snapshot(snapshot);

        // 5. Migration state must be identical post-restore.
        let post_json = state.get_raw(CRYPTO_MIGRATION_STATE_KEY)
            .expect("migration state must survive restart");
        let post_migration: CryptoMigrationState =
            serde_json::from_str(post_json).unwrap();
        assert_eq!(pre_migration, post_migration,
            "migration state must be bit-identical after restart");

        // 6. State root must be identical post-restore.
        let post_root = state.commit(0, 0, false).root_hash;
        assert_eq!(pre_root, post_root,
            "state root must be identical after restart — deterministic JMT");

        // 7. Hard cutoff still fires post-restore: advance past cutoff.
        use chain_forge_crypto::SchemeId;
        identity.clock.current_epoch = post_migration.hard_cutoff_epoch + 1;
        let mut cutoff_tx = Transaction::transfer(
            "restart-cutoff", "qcb1alice", "qcb1bob", "uqcb", 1, 1,
        );
        cutoff_tx.sig_scheme = Some(SchemeId::Classical);
        let r = exec.execute_tx_with_identity(
            &cutoff_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success,
            "deprecated scheme must still be rejected post-restart");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("was deprecated"),
            "post-restart cutoff error must mention deprecation; got: {err}");
    }

    /// CS-001 P5 — Test 11: Invalid / unsupported replacement scheme is rejected.
    ///
    /// An `EmergencyDeprecateAlgorithm` tx with a `replacement_scheme` that is
    /// not in the executor's `KNOWN_CANONICAL_SCHEME_IDS` list must be rejected.
    /// This prevents governance from accidentally migrating to a non-existent or
    /// unsupported algorithm.
    #[test]
    fn cs001_p5_invalid_replacement_scheme_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // Completely unknown replacement scheme.
        let bad_rep_tx = Transaction {
            id: "bad-rep-1".to_string(),
            sender: gov.to_string(),
            nonce: 0,
            body: TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:  "ed25519".to_string(),
                replacement_scheme: "rsa-4096".to_string(), // not in registry
                grace_epochs: MIN_CRYPTO_GRACE_EPOCHS,
                rationale: "invalid replacement test".to_string(),
                advisory_ref: None,
                scope: DeprecationScope::TxSignatures,
            },
            gas_limit: 5_000_000,
            signature: vec![],
            sig_scheme: None,
            public_key: vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &bad_rep_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success,
            "unknown replacement scheme must be rejected");
        let err = r.error.clone().unwrap_or_default();
        assert!(err.contains("not a known scheme id"),
            "error must name the guard; got: {err}");
        assert!(err.contains("rsa-4096"),
            "error must name the offending scheme; got: {err}");

        // Completely unknown deprecated scheme.
        let bad_dep_tx = Transaction {
            id: "bad-dep-1".to_string(),
            sender: gov.to_string(),
            nonce: 0,
            body: TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:  "secp256k1".to_string(), // not in registry
                replacement_scheme: "ml-dsa".to_string(),
                grace_epochs: MIN_CRYPTO_GRACE_EPOCHS,
                rationale: "invalid deprecated test".to_string(),
                advisory_ref: None,
                scope: DeprecationScope::TxSignatures,
            },
            gas_limit: 5_000_000,
            signature: vec![],
            sig_scheme: None,
            public_key: vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &bad_dep_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success,
            "unknown deprecated scheme must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("not a known scheme id"),
            "error must name the guard; got: {err}");

        // Valid tx must still succeed after the rejects.
        let good_tx = emergency_deprecate_tx(
            "good-scheme", gov, 0, "ed25519", "ml-dsa",
            MIN_CRYPTO_GRACE_EPOCHS, "valid schemes",
        );
        let r = exec.execute_tx_with_identity(
            &good_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(r.success, "valid scheme tx must succeed: {:?}", r.error);
    }

    /// CS-001 P5 — Test 12: Overlapping / conflicting migrations are rejected.
    ///
    /// Only one active migration is permitted at a time.  Submitting a second
    /// `EmergencyDeprecateAlgorithm` while one is in progress must be rejected,
    /// even if the deprecated scheme is different.
    #[test]
    fn cs001_p5_overlapping_migrations_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // 1. First migration: ed25519 → ml-dsa.
        let first_tx = emergency_deprecate_tx(
            "first-mig", gov, 0, "ed25519", "ml-dsa",
            MIN_CRYPTO_GRACE_EPOCHS, "First migration",
        );
        let r = exec.execute_tx_with_identity(
            &first_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(r.success, "first migration must succeed: {:?}", r.error);

        // 2. Duplicate — same scheme, same governor: must be rejected.
        let dup_tx = emergency_deprecate_tx(
            "dup-mig", gov, 1, "ed25519", "ml-dsa",
            MIN_CRYPTO_GRACE_EPOCHS, "Duplicate migration",
        );
        let r = exec.execute_tx_with_identity(
            &dup_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success, "duplicate migration must be rejected");
        let err = r.error.clone().unwrap_or_default();
        assert!(err.contains("already in progress"),
            "error must say a migration is already in progress; got: {err}");

        // 3. Conflicting — different scheme but migration still active: must be rejected.
        // Nonce 1 (same as dup_tx) since dup_tx failed and didn't advance the account nonce.
        let conflict_tx = Transaction {
            id: "conflict-mig".to_string(),
            sender: gov.to_string(),
            nonce: 1,
            body: TxBody::EmergencyDeprecateAlgorithm {
                deprecated_scheme:  "slh-dsa".to_string(),
                replacement_scheme: "ml-dsa".to_string(),
                grace_epochs: MIN_CRYPTO_GRACE_EPOCHS,
                rationale: "Conflicting migration".to_string(),
                advisory_ref: None,
                scope: DeprecationScope::TxSignatures,
            },
            gas_limit: 5_000_000,
            signature: vec![],
            sig_scheme: None,
            public_key: vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &conflict_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success, "conflicting migration must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("already in progress"),
            "error must say migration already in progress; got: {err}");
    }

    // ── CS-001 Phase 6 tests ────────────────────────────────────────────────

    /// CS-001-P6-G1: Malformed migration state in StateStore produces a hard
    /// rejection rather than silently passing through the cutoff gate.
    ///
    /// If `crypto_migration:active` exists but cannot be deserialised, the gate
    /// must reject the tx with a message indicating corrupt migration state.
    /// This closes the fail-open deserialization gap identified in the Phase 5
    /// security review.
    #[test]
    fn cs001_p6_corrupt_migration_state_rejected() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // Write deliberately malformed JSON into the migration key — simulates
        // a state corruption event or a schema mismatch after a partial upgrade.
        state.set_raw(CRYPTO_MIGRATION_STATE_KEY, "{ this is not valid json !!! }");

        // A routine transfer from any sender should now be hard-rejected because
        // the migration state cannot be read.
        let transfer_tx = Transaction {
            id:            "p6-corrupt-1".to_string(),
            sender:        gov.to_string(),
            nonce:         0,
            body:          TxBody::Transfer {
                to:     "qcb1recv".to_string(),
                denom:  "uqcb".to_string(),
                amount: 1,
            },
            gas_limit:     500_000,
            signature:     vec![],
            sig_scheme:    None,
            public_key:    vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &transfer_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success, "tx must be rejected when migration state is corrupt");
        let err = r.error.unwrap_or_default();
        assert!(
            err.contains("corrupt") || err.contains("could not be read"),
            "error must indicate migration state is unreadable; got: {err}",
        );
    }

    /// CS-001-P6-G2: A classical transaction with `sig_scheme = None` (legacy
    /// path) is subject to the same cutoff gate as an explicitly-tagged Classical
    /// tx after the hard cutoff passes.
    ///
    /// This closes the bypass gap: a signer who strips the `sig_scheme` field
    /// from a classical tx cannot circumvent the deprecation cutoff.
    #[test]
    fn cs001_p6_untagged_classical_tx_rejected_after_cutoff() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // Deprecate ed25519 with grace = 10 epochs (minimum allowed).
        // identity.clock.current_epoch = 42, so hard_cutoff_epoch = 52; rejected at 53.
        let eda = emergency_deprecate_tx(
            "eda-p6g2", gov, 0, "ed25519", "ml-dsa", 10,
            "P6 gate2 test — untagged classical bypass",
        );
        let r = exec.execute_tx_with_identity(&eda, &mut state, &mut identity, &mut agents);
        assert!(r.success, "EDA must succeed: {:?}", r.error);

        // Advance to epoch 53 — one past the hard cutoff (cutoff = 52, rejected at 53).
        identity.clock.current_epoch = 53;

        // Submit a tx with sig_scheme = None.  This is the legacy path that used to
        // bypass the cutoff gate; it should now be treated as Classical = ed25519.
        let untagged_tx = Transaction {
            id:            "p6-untagged-1".to_string(),
            sender:        gov.to_string(),
            nonce:         1,
            body:          TxBody::Transfer {
                to:     "qcb1recv".to_string(),
                denom:  "uqcb".to_string(),
                amount: 1,
            },
            gas_limit:     500_000,
            signature:     vec![],
            sig_scheme:    None,   // no explicit tag — legacy classical path
            public_key:    vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &untagged_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success, "untagged classical tx must be rejected after cutoff");
        let err = r.error.unwrap_or_default();
        assert!(
            err.contains("was deprecated") || err.contains("deprecated"),
            "error must indicate scheme was deprecated; got: {err}",
        );
    }

    /// CS-001-P6-BOUND: Documents and tests the exact cutoff boundary semantics.
    ///
    /// `hard_cutoff_passed(epoch)` returns `current_epoch > hard_cutoff_epoch`,
    /// which means:
    /// - At epoch == hard_cutoff_epoch: classical is still ACCEPTED (last grace epoch)
    /// - At epoch == hard_cutoff_epoch + 1: classical is REJECTED (first cutoff epoch)
    ///
    /// This is intentional: it prevents a scenario where the EDA tx is included at
    /// epoch N and the cutoff activates partway through the same epoch on another node,
    /// which could split consensus if block timing is tight.
    #[test]
    fn cs001_p6_cutoff_boundary_semantics() {
        let gov = "qcb1gov";
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // epoch=42, grace=10 (minimum) → hard_cutoff_epoch = 52.
        // Last accepted epoch: 52. First rejected epoch: 53.
        let eda = emergency_deprecate_tx(
            "eda-bound", gov, 0, "ed25519", "ml-dsa", 10,
            "P6 boundary test",
        );
        let r = exec.execute_tx_with_identity(&eda, &mut state, &mut identity, &mut agents);
        assert!(r.success, "EDA must succeed: {:?}", r.error);

        // hard_cutoff_epoch = initiated_epoch + grace_epochs - 1 = 42 + 10 - 1 = 51.
        // Last accepted epoch: 51. First rejected epoch: 52.
        let raw = state.get_raw(CRYPTO_MIGRATION_STATE_KEY).expect("migration state");
        let migration: CryptoMigrationState = serde_json::from_str(raw).expect("deserialise");
        assert_eq!(migration.hard_cutoff_epoch, 51,
            "initiated_epoch=42, grace=10 → cutoff must be 51 (= 42 + 10 - 1)");

        // Make a minimal valid tx to test through the executor.
        let make_transfer = |id: &str, nonce: u64| Transaction {
            id:            id.to_string(),
            sender:        gov.to_string(),
            nonce,
            body:          TxBody::Transfer {
                to:     "qcb1recv".to_string(),
                denom:  "uqcb".to_string(),
                amount: 1,
            },
            gas_limit:     500_000,
            signature:     vec![],
            sig_scheme:    Some(SchemeId::Classical),
            public_key:    vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        };

        // At epoch 51 (== hard_cutoff_epoch): classical still accepted.
        identity.clock.current_epoch = 51;
        let r51 = exec.execute_tx_with_identity(
            &make_transfer("p6-bound-51", 1), &mut state, &mut identity, &mut agents,
        );
        assert!(r51.success,
            "classical tx must be accepted AT hard_cutoff_epoch (51); got: {:?}", r51.error);

        // At epoch 52 (== hard_cutoff_epoch + 1): classical rejected.
        identity.clock.current_epoch = 52;
        let r52 = exec.execute_tx_with_identity(
            &make_transfer("p6-bound-52", 2), &mut state, &mut identity, &mut agents,
        );
        assert!(!r52.success,
            "classical tx must be REJECTED at hard_cutoff_epoch + 1 (52)");
        let err = r52.error.unwrap_or_default();
        assert!(err.contains("was deprecated") || err.contains("deprecated"),
            "error must indicate scheme deprecated; got: {err}");
    }

    /// CS-001-P6-MLDSA: A real ML-DSA-65 keypair can create, sign, and finalize
    /// a transaction after the classical cutoff has passed.
    ///
    /// This is the end-to-end proof that the replacement scheme is functional:
    /// the cutoff blocks classical but does not block the replacement.
    #[test]
    fn cs001_p6_mldsa_tx_accepted_after_classical_cutoff() {
        // Use the signed executor setup (require_signatures = true, funded sender).
        let sender = "qcb1senderabcdef";
        let chain_id = "b4-chain";
        let (exec, mut state) = setup_signed(chain_id, sender);
        let mut identity = IdentityStore::new(0);
        let mut agents   = chain_forge_agents::AgentStore::new();

        // Epoch 42; initiate ed25519 → ml-dsa with grace = 3 (cutoff at 45).
        identity.clock.current_epoch = 42;

        // We need a governor-enabled executor for the EDA tx.
        // For simplicity: use require_signatures = false for the governance tx,
        // then re-enable via the state directly by writing the migration record.
        let migration = CryptoMigrationState {
            deprecated_scheme:   "ed25519".to_string(),
            replacement_scheme:  "ml-dsa".to_string(),
            initiated_epoch:     42,
            hard_cutoff_epoch:   45,
            rationale:           "P6 end-to-end ML-DSA test".to_string(),
            advisory_ref:        None,
            initiated_by:        "qcb1gov".to_string(),
            tx_id:               "eda-p6mldsa".to_string(),
            scope:               DeprecationScope::TxSignatures,
        };
        let migration_json = serde_json::to_string(&migration).expect("serialize migration");
        state.set_raw(CRYPTO_MIGRATION_STATE_KEY, &migration_json);

        // Advance to epoch 46 — past the hard cutoff (45).
        identity.clock.current_epoch = 46;

        // Build a real ML-DSA-65 signed tx.
        let (mldsa_tx, _pk) = make_pq_tx_with_chain(chain_id, sender, 0, "p6-seed-unique");

        // Verify the tx is accepted — the deprecated classical scheme is blocked,
        // but ML-DSA is the replacement and must succeed.
        let r = exec.execute_tx_with_identity(
            &mldsa_tx, &mut state, &mut identity, &mut agents,
        );
        assert!(r.success,
            "ML-DSA-65 tx must be accepted after classical cutoff; got: {:?}", r.error);
    }

    /// CS-001-P6-CFG: The hard-cutoff gate is independent of the `require_signatures`
    /// chain configuration.  A chain with `require_signatures = false` (devnet mode)
    /// still enforces the migration cutoff — auth and cutoff are separate checks.
    ///
    /// This confirms the gate cannot be bypassed by node configuration.
    #[test]
    fn cs001_p6_cutoff_enforced_regardless_of_require_signatures() {
        let gov = "qcb1gov";
        // cs001_p4_setup builds a chain with require_signatures = false.
        let (exec, mut state, mut identity, mut agents) = cs001_p4_setup(gov);

        // Sanity: confirm require_signatures is false on this executor.
        assert!(!exec.config.require_signatures,
            "cs001_p4_setup must produce require_signatures = false");

        // Initiate deprecation (grace=10, cutoff at epoch 51).
        let eda = emergency_deprecate_tx(
            "eda-cfg", gov, 0, "ed25519", "ml-dsa", 10,
            "P6 config-independence test",
        );
        let r = exec.execute_tx_with_identity(&eda, &mut state, &mut identity, &mut agents);
        assert!(r.success, "EDA must succeed: {:?}", r.error);

        // Advance past hard cutoff (epoch 52 > cutoff 51).
        identity.clock.current_epoch = 52;

        // A tx with no signature and no sig_scheme — the kind that would pass
        // auth on a require_signatures=false chain.  After cutoff it should
        // still be rejected by the cutoff gate (which is after auth, not inside it).
        let unsigned_classical = Transaction {
            id:            "p6-cfg-unsigned".to_string(),
            sender:        gov.to_string(),
            nonce:         1,
            body:          TxBody::Transfer {
                to:     "qcb1recv".to_string(),
                denom:  "uqcb".to_string(),
                amount: 1,
            },
            gas_limit:     500_000,
            signature:     vec![],
            sig_scheme:    None,   // no tag — treated as classical by G2 fix
            public_key:    vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(
            &unsigned_classical, &mut state, &mut identity, &mut agents,
        );
        assert!(!r.success,
            "unsigned classical tx must be rejected by cutoff gate even with require_signatures=false");
        let err = r.error.unwrap_or_default();
        assert!(
            err.contains("was deprecated") || err.contains("deprecated"),
            "cutoff gate must fire despite require_signatures=false; got: {err}",
        );
    }

    /// PQ-VAL-003 diagnostic: confirm the executor accepts a second
    /// RegisterValidatorKey tx (rotation) from the same sender.
    #[test]
    fn mldsa_key_rotation_executor_accepts_second_registration() {
        use chain_forge_crypto::{ClassicalScheme, MlDsaScheme};
        use chain_forge_identity::IdentityStore;

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let exec = Executor::new(config.clone());
        let mut identity = IdentityStore::new(0);
        let mut agents   = chain_forge_agents::AgentStore::default();

        // Fund + bond the test validator via executor.
        let account_kp = ClassicalScheme.generate_keypair("pq003-exec-diag").unwrap();
        let addr = chain_forge_core::Address::from_public_key(
            &account_kp.public_key, "qcb", HashWidth::Bits256,
        ).to_string();

        // Fund from alice (nonce 0) — alice genesis balance ~5M; fund 4M to stay under
        let fund_tx = Transaction::transfer("fund-diag", "qcb1alice", &addr, "uqcb", 4_000_000, 0);
        let r = exec.execute_tx_with_identity(&fund_tx, &mut state, &mut identity, &mut agents);
        assert!(r.success, "fund: {:?}", r.error);

        // Bond (addr nonce 0)
        let bond_tx = Transaction::bond_validator("bond-diag", &addr, 2_000_000, 0);
        let r = exec.execute_tx_with_identity(&bond_tx, &mut state, &mut identity, &mut agents);
        assert!(r.success, "bond: {:?}", r.error);

        // Grant personhood in identity store
        let epoch = identity.clock.current_epoch;
        let att = chain_forge_identity::PopAttestation::genesis(&addr, epoch);
        let _ = identity.register(addr.clone(), addr.clone(), att.clone());
        identity.verify_identity(&addr, att, None).unwrap();

        // First ML-DSA key registration (addr nonce 1)
        let mldsa_kp1 = MlDsaScheme.generate_keypair("pq003-exec-mldsa1").unwrap();
        let pop_msg1 = validator_key_registration_signing_bytes_v2(
            &config.chain_id, &addr, &mldsa_kp1.public_key,
        );
        let pop_sig1 = MlDsaScheme.sign(&pop_msg1, &mldsa_kp1).unwrap();
        let mut reg1 = Transaction {
            id:        "regkey1-diag".to_string(),
            sender:    addr.clone(),
            nonce:     1,
            body:      TxBody::RegisterValidatorKey {
                consensus_pubkey:    mldsa_kp1.public_key.clone(),
                proof_of_possession: pop_sig1.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        reg1.sign(&account_kp, &config.chain_id).unwrap();

        let r1 = exec.execute_tx_with_identity(&reg1, &mut state, &mut identity, &mut agents);
        assert!(r1.success, "first registration must succeed: {:?}", r1.error);

        // Second ML-DSA key registration / rotation (addr nonce 2)
        let mldsa_kp2 = MlDsaScheme.generate_keypair("pq003-exec-mldsa2").unwrap();
        let pop_msg2 = validator_key_registration_signing_bytes_v2(
            &config.chain_id, &addr, &mldsa_kp2.public_key,
        );
        let pop_sig2 = MlDsaScheme.sign(&pop_msg2, &mldsa_kp2).unwrap();
        let mut reg2 = Transaction {
            id:        "regkey2-diag".to_string(),
            sender:    addr.clone(),
            nonce:     2,
            body:      TxBody::RegisterValidatorKey {
                consensus_pubkey:    mldsa_kp2.public_key.clone(),
                proof_of_possession: pop_sig2.bytes,
                scheme:              "ml-dsa-65".to_string(),
                pop_version:         2,
            },
            gas_limit: 20_000,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            sig_scheme:    None,
            pq_public_key: vec![],
        };
        reg2.sign(&account_kp, &config.chain_id).unwrap();

        let r2 = exec.execute_tx_with_identity(&reg2, &mut state, &mut identity, &mut agents);
        assert!(r2.success,
            "rotation (second RegisterValidatorKey) must be accepted by executor: {:?}", r2.error);
    }

    // -- check_tx (mempool ingress) -------------------------------------------

    fn minimal_tx(sender: &str, gas_limit: u64) -> Transaction {
        Transaction {
            id: "test-tx".into(),
            sender: sender.to_string(),
            nonce: 1,
            body: TxBody::Transfer { to: "qcb1bob".into(), denom: "uqcb".into(), amount: 1 },
            gas_limit,
            sig_scheme: None,
            signature: vec![],
            public_key: vec![],
            pq_signatures: vec![],
            pq_public_key: vec![],
        }
    }

    #[test]
    fn check_tx_rejects_empty_sender() {
        let tx = minimal_tx("", 100_000);
        assert!(check_tx(&tx, 0, 0).is_err(), "empty sender must be rejected");
    }

    #[test]
    fn check_tx_rejects_zero_gas() {
        let tx = minimal_tx("qcb1alice", 0);
        assert!(check_tx(&tx, 0, 0).is_err(), "zero gas_limit must be rejected");
    }

    #[test]
    fn check_tx_rejects_truncated_ed25519_signature() {
        let mut tx = minimal_tx("qcb1alice", 100_000);
        tx.signature = vec![0u8; 10]; // 10 bytes, not 64
        assert!(check_tx(&tx, 0, 0).is_err(), "truncated Ed25519 sig must be rejected");
    }

    #[test]
    fn check_tx_rejects_double_length_ed25519_signature() {
        let mut tx = minimal_tx("qcb1alice", 100_000);
        tx.signature = vec![0u8; 128]; // 128 bytes, not 64
        assert!(check_tx(&tx, 0, 0).is_err(), "double-length Ed25519 sig must be rejected");
    }

    #[test]
    fn check_tx_rejects_malformed_mldsa_signature() {
        let mut tx = minimal_tx("qcb1alice", 100_000);
        tx.pq_signatures = vec!["mldsa65:deadbeef".into()]; // 8 hex chars, not 6586
        assert!(check_tx(&tx, 0, 0).is_err(), "malformed ML-DSA-65 sig must be rejected");
    }

    #[test]
    fn check_tx_accepts_valid_unsigned_tx() {
        let tx = minimal_tx("qcb1alice", 100_000);
        assert!(check_tx(&tx, 0, 0).is_ok(), "valid unsigned dev tx must pass check_tx");
    }

    #[test]
    fn check_tx_accepts_correctly_sized_ed25519_sig_field() {
        let mut tx = minimal_tx("qcb1alice", 100_000);
        tx.signature = vec![0u8; 64]; // correct size (crypto validity is verify_signature's job)
        assert!(check_tx(&tx, 0, 0).is_ok(), "64-byte sig field must pass structural check");
    }

    #[test]
    fn check_tx_rejects_oversized_payload() {
        let tx = minimal_tx("qcb1alice", 100_000);
        // max_tx_bytes = 1 forces rejection of any real tx
        assert!(check_tx(&tx, 1, 0).is_err(), "oversized tx must be rejected");
    }

    #[test]
    fn check_tx_rejects_below_gas_floor() {
        let tx = minimal_tx("qcb1alice", 1);
        assert!(check_tx(&tx, 0, 0).is_err(), "gas_limit=1 must be rejected (below floor)");
    }

    #[test]
    fn check_tx_rejects_self_send() {
        let mut tx = minimal_tx("qcb1alice", 100_000);
        if let TxBody::Transfer { ref mut to, .. } = tx.body {
            *to = "qcb1alice".into();
        }
        assert!(check_tx(&tx, 0, 0).is_err(), "self-send must be rejected");
    }

    #[test]
    fn check_tx_rejects_unknown_denom() {
        let mut tx = minimal_tx("qcb1alice", 100_000);
        if let TxBody::Transfer { ref mut denom, .. } = tx.body {
            *denom = "notacoin".into();
        }
        assert!(check_tx(&tx, 0, 0).is_err(), "unknown denom must be rejected");
    }

    #[test]
    fn check_tx_rejects_zeroed_pubkey() {
        let mut tx = minimal_tx("qcb1alice", 100_000);
        tx.public_key = vec![0u8; 32];
        assert!(check_tx(&tx, 0, 0).is_err(), "all-zero public_key must be rejected");
    }
}
