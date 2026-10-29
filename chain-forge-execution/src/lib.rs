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

/// Deserialize a `Vec<u8>` from either a JSON byte-array `[0,1,2,…]` or a
/// lowercase hex string `"0102…"`.  Blockchain clients (Python, JS, Go) almost
/// universally encode byte fields as hex strings, but Rust's default serde
/// for `Vec<u8>` only accepts the integer-array form.  Using this deserializer
/// instead of `#[serde(default)]` means a hex-encoded zeroed public key such
/// as `"000…0"` is parsed as 32 zero bytes rather than silently falling back
/// to an empty Vec, which was the root cause of the F5 pubkey=zeroed bypass.
fn deser_hex_or_bytes<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where D: serde::Deserializer<'de>
{
    use serde::de::{self, SeqAccess, Visitor};
    struct HexOrBytes;
    impl<'de> Visitor<'de> for HexOrBytes {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "hex string or byte array")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
            if v.is_empty() { return Ok(Vec::new()); }
            if v.len() % 2 != 0 {
                return Err(de::Error::custom("hex string length must be even"));
            }
            (0..v.len()).step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16)
                    .map_err(|_| de::Error::custom(format!("invalid hex byte at position {i}"))))
                .collect()
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::new();
            while let Some(b) = seq.next_element::<u8>()? { bytes.push(b); }
            Ok(bytes)
        }
        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> { Ok(v.to_vec()) }
        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> { Ok(v) }
        fn visit_unit<E: de::Error>(self) -> Result<Vec<u8>, E> { Ok(Vec::new()) }
        fn visit_none<E: de::Error>(self) -> Result<Vec<u8>, E> { Ok(Vec::new()) }
        fn visit_some<D2: serde::Deserializer<'de>>(self, d: D2) -> Result<Vec<u8>, D2::Error> {
            d.deserialize_any(self)
        }
    }
    d.deserialize_any(HexOrBytes)
}

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

// -- Fee distribution ---------------------------------------------------------

/// How collected fees are split at each block close (basis points, sum = 10_000).
///
/// Default: 7000 validators / 2000 treasury / 1000 burn.
/// Any remainder from integer division stays in the validator pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeDistribution {
    pub validator_bps: u32,
    pub treasury_bps:  u32,
    pub burn_bps:      u32,
}

impl FeeDistribution {
    pub const DEFAULT_VALIDATOR_BPS: u32 = 7_000;
    pub const DEFAULT_TREASURY_BPS:  u32 = 2_000;
    pub const DEFAULT_BURN_BPS:      u32 = 1_000;

    pub fn default() -> Self {
        Self {
            validator_bps: Self::DEFAULT_VALIDATOR_BPS,
            treasury_bps:  Self::DEFAULT_TREASURY_BPS,
            burn_bps:      Self::DEFAULT_BURN_BPS,
        }
    }

    /// Construct from genesis config, validating the bps sum.
    pub fn from_genesis(genesis: &chain_forge_core::GenesisConfig) -> Result<Self, String> {
        if let Some(bps) = &genesis.execution.fee_distribution_bps {
            let sum = bps.validator_bps + bps.treasury_bps + bps.burn_bps;
            if sum != 10_000 {
                return Err(format!(
                    "fee_distribution_bps must sum to 10000; got {}+{}+{}={}",
                    bps.validator_bps, bps.treasury_bps, bps.burn_bps, sum,
                ));
            }
            Ok(Self {
                validator_bps: bps.validator_bps,
                treasury_bps:  bps.treasury_bps,
                burn_bps:      bps.burn_bps,
            })
        } else {
            Ok(Self::default())
        }
    }

    /// Split `amount` into (validator_share, treasury_share, burn_share).
    /// Integer floor division; any remainder accrues to the treasury share.
    pub fn split(&self, amount: u64) -> (u64, u64, u64) {
        let validator = (amount as u128 * self.validator_bps as u128 / 10_000) as u64;
        let treasury  = (amount as u128 * self.treasury_bps  as u128 / 10_000) as u64;
        let burn      = (amount as u128 * self.burn_bps       as u128 / 10_000) as u64;
        // Remainder (from floor division) accrues to treasury, not validators.
        let remainder = amount.saturating_sub(validator + treasury + burn);
        (validator, treasury + remainder, burn)
    }
}

/// Result of distributing one block's collected fees.
#[derive(Debug, Clone)]
pub struct FeeSettlementResult {
    pub fees_total:      u64,
    pub validator_share: u64,
    pub treasury_share:  u64,
    pub burn_share:      u64,
}

/// Distribute `fees_collected` from one block into the three destination accounts.
///
/// - `treasury:validator-pool` receives the validator share.
/// - `treasury:network`        receives the treasury share.
/// - The burn share is permanently removed via `StateStore::burn()`.
///
/// Only `fees_collected` (from the current block's `BlockExecutionResult`) is
/// moved — NOT the total balance of `treasury:fees`.  This prevents replay,
/// restart, or partial-commit errors from double-distributing prior epochs.
pub fn distribute_block_fees(
    fees_collected: u64,
    dist:           &FeeDistribution,
    native_denom:   &str,
    state:          &mut chain_forge_state::StateStore,
) -> FeeSettlementResult {
    distribute_block_fees_from("treasury:fees", fees_collected, dist, native_denom, state)
}

/// Distribute this block's fees out of `fee_src` (the chain's configured fee
/// collector). `fees_collected` must be the fees actually debited into
/// `fee_src` this block (H0-7), so every leg should succeed; a failed leg is an
/// invariant violation and is logged as an error rather than ignored.
pub fn distribute_block_fees_from(
    fee_src:        &str,
    fees_collected: u64,
    dist:           &FeeDistribution,
    native_denom:   &str,
    state:          &mut chain_forge_state::StateStore,
) -> FeeSettlementResult {
    if fees_collected == 0 {
        return FeeSettlementResult {
            fees_total: 0, validator_share: 0, treasury_share: 0, burn_share: 0,
        };
    }

    let (validator_share, treasury_share, burn_share) = dist.split(fees_collected);
    let report = |leg: &str, r: chain_forge_state::StateResult<()>| {
        if let Err(e) = r {
            tracing::error!(fee_src, leg, fees_collected, error = %e,
                "H0-7 fee conservation violated: fee distribution leg failed");
        }
    };

    // Helper: credit an account, auto-creating if absent.
    let credit_account = |state: &mut chain_forge_state::StateStore, addr: &str, amount: u64| {
        if state.get_account(addr).is_err() {
            let a = chain_forge_state::AccountState::new(addr.to_string(), "treasury".to_string());
            state.upsert_account(a);
        }
        if let Ok(a) = state.get_account_mut(addr) {
            a.credit(native_denom, amount as u128);
        }
        state.refresh_leaf(addr);
    };

    // Move validator share: treasury:fees → treasury:validator-pool
    if validator_share > 0 {
        report("validator", state.transfer(fee_src, "treasury:validator-pool", native_denom, validator_share as u128));
    }

    // Move treasury share: treasury:fees → treasury:network
    if treasury_share > 0 {
        // Ensure destination exists before transfer.
        credit_account(state, "treasury:network", 0);
        report("treasury", state.transfer(fee_src, "treasury:network", native_denom, treasury_share as u128));
    }

    // Burn the burn share permanently.
    if burn_share > 0 {
        report("burn", state.burn(fee_src, native_denom, burn_share as u128));
    }

    tracing::debug!(
        fees_total      = fees_collected,
        validator_share,
        treasury_share,
        burn_share,
        "block fee settlement"
    );

    FeeSettlementResult { fees_total: fees_collected, validator_share, treasury_share, burn_share }
}

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
                    // VerifyIdentityWithProof: Groth16 proof verification; higher gas than
                    // a plain attestation to reflect the ZK-VRC verification cost.
                    TxBody::VerifyIdentityWithProof { .. } => op_multiplier * 8,
                    // RotateAccountKey: two ML-DSA verifications (outer tx sig + PoP).
                    TxBody::RotateAccountKey { .. } => op_multiplier * 6,
                    // EnrollRecoveryPolicy: writes guardian set to state; moderate cost.
                    TxBody::EnrollRecoveryPolicy { .. } => op_multiplier * 5,
                    // RecoverAccountKey: N guardian ML-DSA verifications + PoP; high cost.
                    TxBody::RecoverAccountKey { .. } => op_multiplier * 10,
                    // RevokeRecoveryPolicy: simple state write.
                    TxBody::RevokeRecoveryPolicy => op_multiplier * 2,
                    // UpdateGuardianPolicy: same cost as EnrollRecoveryPolicy (writes guardian set).
                    TxBody::UpdateGuardianPolicy { .. } => op_multiplier * 5,
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
    ///
    /// QPC-CONS-001 Phase B: authenticated human-identity binding.
    ///
    /// `owner_identity_id` must be the address that holds an active, unfrozen
    /// personhood credential (i.e. `grants_consensus()` is true for that address
    /// in IdentityStore).  The executor enforces two authentication rules:
    ///   1. `tx.sender == owner_identity_id` — only the identity holder can
    ///      bind their own validators; prevents identity spoofing.
    ///   2. `owner_identity_id` must have `grants_consensus() == true` at
    ///      execution time — derived from authoritative IdentityStore state,
    ///      not a user-supplied claim.
    ///
    /// When `None` (backward-compat / genesis exemption): the validator is
    /// admitted with `pop_verified=false` and therefore `voting_power=0` via
    /// `gate_voting_power()`.  It can never gain consensus influence until an
    /// authenticated `owner_identity_id` is established (future rotation tx).
    /// This closes the QPC-GAP-001 omission-bypass: omitting the field is
    /// fail-closed, not fail-open.
    BondValidator {
        amount: u128,
        /// The verified human identity that owns this validator.
        /// See above for authentication rules and fail-closed semantics.
        #[serde(default)]
        owner_identity_id: Option<String>,
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

    /// Upgrade a Provisional identity to Verified via a ZK-VRC membership
    /// proof (QPC-GAP-002 — multi-issuer decentralized personhood verification).
    ///
    /// Replaces the single-coordinator bootstrap path for non-genesis validators:
    /// any identity holder with a valid Groth16 VRC proof from an approved issuer
    /// (registered in the node's IssuerRegistry) can self-promote to Verified
    /// without waiting for ATTESTATION_QUORUM human attestations.
    ///
    /// Effects:
    ///   - Calls `identity.verify_identity(sender, attestation, Some(verifier))`
    ///     where `verifier` is the node's configured `Groth16VrcVerifier`.
    ///   - On success, syncs the Verified charm to on-chain AccountState and
    ///     refreshes the Merkle leaf so `pop_verified` picks it up at the next
    ///     validator-set update.
    ///
    /// Enforced invariants:
    ///   - Sender must be registered (Provisional tier).
    ///   - Node must have a `pop_verifier` configured (fails closed otherwise).
    ///   - `proof_bytes` must be a valid compressed Groth16 proof.
    ///   - `public_inputs_bytes` must encode the IssuerRegistry Merkle root
    ///     matching the node's current approved-issuer set.
    /// DIS-002A: Replace the authorized signing key for the sender's account.
    ///
    /// Authorization: the transaction's outer pq_signature must be valid under
    /// the account's CURRENT bound key (enforced by verify_mldsa_authorization
    /// before execution reaches this handler).
    ///
    /// Guards (in order):
    ///   1. Sender must have a bound key (cannot rotate before first use).
    ///   2. key_version must be exactly current + 1 (prevents replay).
    ///   3. new_public_key must be valid ML-DSA-65 (2592 bytes).
    ///   4. new_public_key must differ from the current bound key.
    ///   5. pop_signature must verify under new_public_key over the
    ///      domain-separated message from account_key_rotation_signing_bytes().
    ///
    /// Effects on success:
    ///   account.public_key  = Some(new_public_key)
    ///   account.key_version += 1
    ///   account.nonce       += 1  (standard)
    ///   everything else:    unchanged (balance, identity record, permissions)
    RotateAccountKey {
        /// The replacement ML-DSA-65 public key (2592 bytes, hex-encoded in JSON).
        new_public_key: Vec<u8>,
        /// Must be "ml-dsa-65".
        new_key_scheme: String,
        /// Must equal account.key_version + 1.  Prevents replay of stale rotations.
        key_version: u32,
        /// Proof-of-possession: new key signs account_key_rotation_signing_bytes().
        pop_signature: Vec<u8>,
    },

    VerifyIdentityWithProof {
        /// Compressed canonical `ark_groth16::Proof<Bls12_381>` bytes.
        proof_bytes: Vec<u8>,
        /// Compressed canonical `Fr` public inputs (IssuerRegistry Merkle root).
        public_inputs_bytes: Vec<u8>,
    },

    /// DIS-002B Path 2 (R1): Enroll a threshold-guardian recovery policy.
    /// The sender must control the account (authorized tx) and must not
    /// already have an active policy (revoke first to replace).
    /// On success, `account.recovery_policy` is set to the enrolled policy.
    EnrollRecoveryPolicy {
        /// ML-DSA-65 public keys of authorized guardians (each 1952 bytes).
        guardians:  Vec<Vec<u8>>,
        /// How many distinct guardian signatures are required to recover.
        threshold:  u32,
    },

    /// DIS-002B Path 2 (R2): Replace a lost account key without the original
    /// signing key, using the enrolled recovery policy.
    /// The sender field must equal the account being recovered (the sender
    /// has no signing key to authenticate with; authentication comes entirely
    /// from the guardian signatures over the recovery domain message).
    RecoverAccountKey {
        /// The replacement ML-DSA-65 public key (1952 bytes).
        new_public_key:      Vec<u8>,
        /// Must be "ml-dsa-65".
        new_key_scheme:      String,
        /// Must equal account.key_version + 1.
        key_version:         u32,
        /// PoP: new key signs account_key_rotation_signing_bytes().
        pop_signature:       Vec<u8>,
        /// Guardian co-authorizations.
        guardian_signatures: Vec<GuardianAuth>,
        /// DIS-003A: must match the policy_id on the enrolled RecoveryPolicy.
        /// Prevents replay of guardian signatures under a re-enrolled policy.
        policy_id:           u64,
    },

    /// DIS-003A: Revoke the enrolled recovery policy for the sender's account.
    /// Signed by the current account key (same authorization path as
    /// EnrollRecoveryPolicy). Clears `recovery_policy`; does NOT reset
    /// `policy_generation` — the generation counter is monotone forever.
    RevokeRecoveryPolicy,

    /// DIS-003B: Replace the guardian set of an already-enrolled recovery policy.
    /// Signed by the current account key. Increments `policy_generation` so
    /// any guardian signatures collected under the old set are invalidated.
    /// Requires an active (enrolled) policy; rejected if none exists.
    UpdateGuardianPolicy {
        /// New guardian ML-DSA-65 public keys (replaces the old set entirely).
        new_guardians: Vec<Vec<u8>>,
        /// New threshold (must satisfy 1 ≤ threshold ≤ new_guardians.len()).
        new_threshold: u32,
    },
}

/// One guardian's authorization for a `RecoverAccountKey` transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianAuth {
    /// The guardian's ML-DSA-65 public key (1952 bytes).
    pub guardian_public_key: Vec<u8>,
    /// Signature over `recovery_domain_signing_bytes(chain_id, account, key_version, new_pk, policy_id, expires_at_height)`.
    pub signature:           Vec<u8>,
    /// DIS-003D: optional block-height expiry bound into the guardian's signature.
    /// If `Some(h)`, the authorization is valid only while `block_height <= h`.
    /// Rejected at height h+1 and beyond. `None` means no expiry.
    /// **Must be bound inside the signing bytes** so attackers cannot extend
    /// the lifetime of a captured signature by modifying this field.
    #[serde(default)]
    pub expires_at_height: Option<u64>,
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
            TxBody::VerifyIdentityWithProof { .. } => "VerifyIdentityWithProof",
            TxBody::RotateAccountKey { .. }         => "RotateAccountKey",
            TxBody::EnrollRecoveryPolicy { .. }     => "EnrollRecoveryPolicy",
            TxBody::RecoverAccountKey { .. }        => "RecoverAccountKey",
            TxBody::RevokeRecoveryPolicy            => "RevokeRecoveryPolicy",
            TxBody::UpdateGuardianPolicy { .. }     => "UpdateGuardianPolicy",
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

/// H0-5: finish an included tx (admitted, fee already debited) whose body ran
/// inside a `StateStore` checkpoint. Success keeps the body's writes; failure
/// rolls every one of them back and then consumes the sender's nonce, so the
/// same signed tx can never be included (and charged) again. Either way the
/// result records the fee that was charged.
fn settle_included_tx(tx: &Transaction, state: &mut StateStore, result: &mut TransactionResult, fee: u64) {
    if result.success {
        state.commit_checkpoint();
    } else {
        state.rollback_checkpoint();
        if let Ok(acct) = state.get_account_mut(&tx.sender) {
            acct.increment_nonce();
        }
        state.refresh_leaf(&tx.sender);
    }
    result.gas_used = fee;
    result.fee_charged = fee;
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
    #[serde(default, deserialize_with = "deser_hex_or_bytes")]
    pub signature: Vec<u8>,
    /// Ed25519 public key (32 bytes) that produced `signature`. Must either
    /// match the key bound to `sender`, or -- for an account with no bound
    /// key yet -- be the key `sender` was derived from.
    #[serde(default, deserialize_with = "deser_hex_or_bytes")]
    pub public_key: Vec<u8>,
    /// Post-quantum signature tags.  Each entry is `"<scheme>:<hex>"`, e.g.
    /// `"mldsa65:<3309-byte-sig-hex>"`.  Empty for unsigned or Ed25519-only txs.
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
    #[serde(default, deserialize_with = "deser_hex_or_bytes")]
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
            // VerifyIdentityWithProof: proof + public inputs bytes.
            TxBody::VerifyIdentityWithProof { proof_bytes, public_inputs_bytes } => {
                proof_bytes.len() + public_inputs_bytes.len()
            }
            // RotateAccountKey: new_public_key (2592) + pop_signature (4595) + overhead.
            TxBody::RotateAccountKey { new_public_key, pop_signature, new_key_scheme, .. } => {
                new_public_key.len() + pop_signature.len() + new_key_scheme.len() + 8
            }
            // EnrollRecoveryPolicy: guardian pubkeys (N × 1952) + threshold overhead.
            TxBody::EnrollRecoveryPolicy { guardians, .. } => {
                guardians.iter().map(|g| g.len()).sum::<usize>() + 16
            }
            // RecoverAccountKey: new pk + N guardian sigs (N × (1952+3309)) + PoP sig + scheme.
            TxBody::RecoverAccountKey {
                new_public_key, pop_signature, new_key_scheme, guardian_signatures, ..
            } => {
                new_public_key.len() + pop_signature.len() + new_key_scheme.len()
                    + guardian_signatures.iter().map(|g| g.guardian_public_key.len() + g.signature.len()).sum::<usize>()
                    + 16
            }
            TxBody::RevokeRecoveryPolicy => 8,
            TxBody::UpdateGuardianPolicy { new_guardians, .. } => {
                new_guardians.iter().map(|g| g.len()).sum::<usize>() + 16
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
            body: TxBody::BondValidator { amount, owner_identity_id: None },
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
    /// H0-7: fee actually debited from the sender for this tx. Non-zero only
    /// for included txs (successful or failed); 0 for rejected txs.
    #[serde(default)]
    pub fee_charged: u64,
}

impl TransactionResult {
    pub fn ok(tx_id: String, gas_used: u64, gas_limit: u64, events: Vec<String>) -> Self {
        Self { tx_id, success: true, gas_used, gas_limit, error: None, events, fee_charged: 0 }
    }

    pub fn err(tx_id: String, gas_used: u64, gas_limit: u64, error: String) -> Self {
        Self { tx_id, success: false, gas_used, gas_limit, error: Some(error), events: vec![], fee_charged: 0 }
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
#[derive(Clone)]
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

    /// How fees collected per block are split among validator pool, network
    /// treasury, and permanent burn.  Applied by `distribute_block_fees()`.
    pub fee_distribution: FeeDistribution,

    /// Optional ZK-VRC proof verifier (QPC-GAP-002).
    ///
    /// When set, `VerifyIdentityWithProof` transactions are accepted and the
    /// verifier is used to check the Groth16 membership proof against the
    /// node's IssuerRegistry root. When `None`, all `VerifyIdentityWithProof`
    /// transactions are rejected with "no pop_verifier configured" (fail-closed).
    pub pop_verifier: Option<std::sync::Arc<dyn chain_forge_identity::PopProofVerifier + Send + Sync>>,
    /// Web-of-trust attestation quorum from genesis (`identity.attestation_quorum`).
    /// Installed on the IdentityStore before every identity-aware tx, so the
    /// quorum always comes from genesis, never from persisted node state.
    pub attestation_quorum: usize,
    /// Per-attester rolling-window cap from genesis
    /// (`identity.attestation_cap_per_window`), installed alongside the quorum.
    pub attestation_cap_per_window: u32,
    /// `cryptography.validator_scheme = "ml-dsa-65"`: only ML-DSA-65
    /// consensus keys may register, and ML-DSA consensus cannot be
    /// deprecated (it is the only consensus scheme the chain has).
    pub mldsa_consensus_only: bool,
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
            fee_distribution: FeeDistribution::from_genesis(genesis)
                .unwrap_or_else(|_| FeeDistribution::default()),
            pop_verifier: None,
            // Fail closed: an invalid identity config gets the production
            // quorum. (The node refuses to start on one anyway.)
            attestation_quorum: genesis.attestation_quorum()
                .unwrap_or(chain_forge_core::DEFAULT_ATTESTATION_QUORUM),
            attestation_cap_per_window: genesis.attestation_cap_per_window()
                .unwrap_or(chain_forge_core::DEFAULT_ATTESTATION_CAP_PER_WINDOW),
            mldsa_consensus_only: genesis.mldsa_consensus_only(),
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
    // DIS-002B Path 2: RecoverAccountKey authenticates entirely through
    // guardian signatures verified inside execute_recover_account_key —
    // the account has no usable signing key by definition.
    if matches!(tx.body, TxBody::RecoverAccountKey { .. }) {
        return Ok(());
    }
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

/// DIS-002A: Domain-separated proof-of-possession message for account key rotation.
///
/// The new key signs this message to prove possession before being activated.
/// Binds to:
///   - chain_id       — prevents cross-chain replay
///   - sender_address — prevents registration under a different account
///   - key_version    — prevents replay of old rotation PoPs
///   - new_public_key — prevents key substitution
///
/// Format: `CFAR|<chain_id>|<sender_address>|<key_version_decimal>|<hex(new_public_key)>`
/// `CFAR` = "Chain Forge Account Rotation" domain tag.
pub fn account_key_rotation_signing_bytes(
    chain_id:       &str,
    sender_address: &str,
    key_version:    u32,
    new_public_key: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"CFAR|");
    b.extend_from_slice(chain_id.as_bytes());
    b.push(b'|');
    b.extend_from_slice(sender_address.as_bytes());
    b.push(b'|');
    b.extend_from_slice(key_version.to_string().as_bytes());
    b.push(b'|');
    b.extend_from_slice(hex_encode_bytes(new_public_key).as_bytes());
    b
}

/// DIS-002B Path 2 / DIS-003D: Domain-separated signing bytes for guardian
/// recovery authorization signatures.
///
/// Format: `b"CFREC|" || chain_id || b"|" || account_address || b"|" || key_version || b"|" || hex(new_public_key) || b"|" || expires_at_height`
///
/// `expires_at_height` is encoded as the decimal string of the height, or
/// `"none"` when `None`. Binding it inside the signed bytes prevents an attacker
/// from extending the lifetime of a captured signature by modifying the
/// `GuardianAuth.expires_at_height` field in the transaction.
pub fn recovery_domain_signing_bytes(
    chain_id:          &str,
    account:           &str,
    key_version:       u32,
    new_public_key:    &[u8],
    policy_id:         u64,
    expires_at_height: Option<u64>,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"CFREC|");
    b.extend_from_slice(chain_id.as_bytes());
    b.push(b'|');
    b.extend_from_slice(account.as_bytes());
    b.push(b'|');
    b.extend_from_slice(key_version.to_string().as_bytes());
    b.push(b'|');
    b.extend_from_slice(hex_encode_bytes(new_public_key).as_bytes());
    b.push(b'|');
    // DIS-003A: bind the policy generation so signatures collected under a
    // superseded policy cannot authorize recovery under a later one.
    b.extend_from_slice(b"pid");
    b.extend_from_slice(policy_id.to_string().as_bytes());
    b.push(b'|');
    match expires_at_height {
        Some(h) => b.extend_from_slice(h.to_string().as_bytes()),
        None    => b.extend_from_slice(b"none"),
    }
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
        // VerifyIdentityWithProof: requires identity module (ZK-VRC path).
        TxBody::VerifyIdentityWithProof { .. } => Some("identity"),
        // Key rotation is a core account right (always-on, like Transfer/Burn).
        TxBody::RotateAccountKey { .. }         => None,
        // Recovery policy enrollment and execution are core account rights.
        TxBody::EnrollRecoveryPolicy { .. }     => None,
        TxBody::RecoverAccountKey { .. }        => None,
        TxBody::RevokeRecoveryPolicy            => None,
        TxBody::UpdateGuardianPolicy { .. }     => None,
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
/// - ML-DSA-65 signature tag, if present, is exactly 6618 hex chars
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
    // nonce=u64::MAX is rejected to prevent overflow on the next increment.
    // nonce=0 is valid: it is what execution expects for a fresh account.
    if tx.nonce == u64::MAX {
        return Err("nonce u64::MAX is reserved and not permitted".into());
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
    // F3: hard ceiling — reject gas values that would overflow arithmetic
    // regardless of whether block_gas_limit is configured (0 = unconfigured).
    const ABSOLUTE_GAS_CAP: u64 = 100_000_000_000; // 100B gas units
    if tx.gas_limit > ABSOLUTE_GAS_CAP {
        return Err(format!(
            "gas_limit {g} exceeds absolute cap {ABSOLUTE_GAS_CAP}",
            g = tx.gas_limit
        ));
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
                // ML-DSA-65 signatures are 3309 bytes = 6618 hex chars (pqcrypto dilithium3 detached sig).
                if hex.len() != 6618 {
                    return Err(format!(
                        "malformed ML-DSA-65 signature: expected 6618 hex chars, got {}",
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
    if tx.public_key.iter().all(|&b| b == 0) {
        return Err("public_key must not be all zeros".into());
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

/// DIS-002A: Execute a RotateAccountKey transaction.
///
/// Called from both the simple and the full (identity-aware) executor.
/// Authorization (outer pq_signature checks) is already done by
/// verify_mldsa_authorization before this function is reached.
fn execute_rotate_account_key(
    config:         &ExecutionConfig,
    tx:             &Transaction,
    state:          &mut StateStore,
    new_public_key: &[u8],
    new_key_scheme: &str,
    key_version:    &u32,
    pop_signature:  &[u8],
) -> Result<(), String> {
    use chain_forge_crypto::Signature as CfSig;

    // Guard 1: sender must have a bound key.
    let current_key = state
        .get_account(&tx.sender)
        .ok()
        .and_then(|a| a.public_key.clone())
        .ok_or_else(|| format!(
            "RotateAccountKey: {} has no bound key; submit a regular transaction first",
            tx.sender
        ))?;
    if current_key.is_empty() {
        return Err(format!(
            "RotateAccountKey: {} has an empty bound key; internal state inconsistency",
            tx.sender
        ));
    }

    // Guard 2: key_version must be exactly current + 1.
    let current_version = state
        .get_account(&tx.sender)
        .map(|a| a.key_version)
        .unwrap_or(0);
    if *key_version != current_version + 1 {
        return Err(format!(
            "RotateAccountKey: key_version mismatch: expected {}, got {}",
            current_version + 1, key_version
        ));
    }

    // Guard 3: new_key_scheme must be "ml-dsa-65".
    if new_key_scheme != "ml-dsa-65" {
        return Err(format!(
            "RotateAccountKey: unsupported key scheme '{}'; only 'ml-dsa-65' is accepted",
            new_key_scheme
        ));
    }

    // Guard 4: new_public_key must be a valid ML-DSA-65 key (1952 bytes).
    // ML-DSA-65 (Dilithium3) pk = 1952 bytes; 2592 is ML-DSA-87.
    const MLDSA65_PK_BYTES: usize = 1952;
    if new_public_key.len() != MLDSA65_PK_BYTES {
        return Err(format!(
            "RotateAccountKey: new_public_key must be {} bytes (ML-DSA-65), got {}",
            MLDSA65_PK_BYTES, new_public_key.len()
        ));
    }

    // Guard 5: new_public_key must differ from the current bound key.
    if new_public_key == current_key.as_slice() {
        return Err(format!(
            "RotateAccountKey: new_public_key is identical to the current bound key for {}",
            tx.sender
        ));
    }

    // Guard 6: proof-of-possession — new key signs the domain-separated message.
    let pop_message = account_key_rotation_signing_bytes(
        &config.chain_id,
        &tx.sender,
        *key_version,
        new_public_key,
    );
    let pop_sig = CfSig { scheme: SchemeId::MlDsa, bytes: pop_signature.to_vec() };
    MlDsaScheme
        .verify(&pop_message, &pop_sig, new_public_key)
        .map_err(|e| format!("RotateAccountKey: proof-of-possession verification failed: {e}"))?;

    // All guards passed — commit the rotation.
    {
        let acct = state
            .get_account_mut(&tx.sender)
            .map_err(|e| format!("RotateAccountKey: account lookup failed: {e}"))?;
        acct.public_key  = Some(new_public_key.to_vec());
        acct.key_version = current_version + 1;
    }
    state.refresh_leaf(&tx.sender);

    tracing::info!(
        sender    = %tx.sender,
        new_ver   = current_version + 1,
        pk_len    = new_public_key.len(),
        "DIS-002A: account key rotated"
    );

    Ok(())
}

/// DIS-002B Path 2 (R1): Execute an EnrollRecoveryPolicy transaction.
///
/// Authorization (outer pq_signature checks) is already done before this is
/// called. Guards:
///  1. threshold >= 1 and <= guardians.len()
///  2. At least 1 guardian (and no more than 10 for Phase 0)
///  3. Each guardian key must be a valid-length ML-DSA-65 key (1952 bytes)
///  4. Guardian keys must be distinct (no duplicates in policy)
fn execute_enroll_recovery_policy(
    tx:         &Transaction,
    state:      &mut StateStore,
    guardians:  &[Vec<u8>],
    threshold:  u32,
) -> Result<(), String> {
    const MLDSA65_PK_BYTES: usize = 1952;
    const MAX_GUARDIANS: usize    = 10;

    if guardians.is_empty() {
        return Err("EnrollRecoveryPolicy: must specify at least 1 guardian".to_string());
    }
    if guardians.len() > MAX_GUARDIANS {
        return Err(format!(
            "EnrollRecoveryPolicy: too many guardians (max {MAX_GUARDIANS}, got {})",
            guardians.len()
        ));
    }
    if threshold == 0 || threshold as usize > guardians.len() {
        return Err(format!(
            "EnrollRecoveryPolicy: threshold {} out of range [1, {}]",
            threshold, guardians.len()
        ));
    }
    for (i, g) in guardians.iter().enumerate() {
        if g.len() != MLDSA65_PK_BYTES {
            return Err(format!(
                "EnrollRecoveryPolicy: guardian[{i}] key must be {MLDSA65_PK_BYTES} bytes, got {}",
                g.len()
            ));
        }
    }
    // Duplicate check.
    for i in 0..guardians.len() {
        for j in (i + 1)..guardians.len() {
            if guardians[i] == guardians[j] {
                return Err(format!(
                    "EnrollRecoveryPolicy: guardian[{i}] and guardian[{j}] are the same key"
                ));
            }
        }
    }

    let (current_version, next_generation) = state
        .get_account(&tx.sender)
        .map(|a| (a.key_version, a.policy_generation + 1))
        .unwrap_or((0, 1));

    {
        let acct = state
            .get_account_mut(&tx.sender)
            .map_err(|e| format!("EnrollRecoveryPolicy: account lookup failed: {e}"))?;
        acct.policy_generation = next_generation;
        acct.recovery_policy = Some(chain_forge_state::RecoveryPolicy {
            guardians:               guardians.to_vec(),
            threshold,
            enrolled_at_key_version: current_version,
            policy_id:               next_generation,
        });
    }
    state.refresh_leaf(&tx.sender);

    tracing::info!(
        sender    = %tx.sender,
        threshold,
        guardians = guardians.len(),
        policy_id = next_generation,
        "DIS-003A: recovery policy enrolled"
    );
    Ok(())
}

/// DIS-002B Path 2 (R2): Execute a RecoverAccountKey transaction.
///
/// Authorization does NOT use the normal pq_signature path (the account
/// has no usable signing key). Instead, authentication comes from the
/// guardian signatures in the tx body, verified here.
///
/// Guards:
///  1. Account must have an enrolled RecoveryPolicy.
///  2. enrolled_at_key_version == account.key_version (policy not stale).
///  3. key_version == current + 1.
///  4. new_key_scheme must be "ml-dsa-65".
///  5. new_public_key must be 1952 bytes.
///  6. At least `threshold` guardian_signatures are valid over recovery domain msg.
///  7. Each signing guardian key must be listed in the enrolled policy.
///  8. No duplicate guardian keys in the signatures.
///  9. PoP from new key verifies.
fn verify_recover_account_key(
    config:               &ExecutionConfig,
    tx:                   &Transaction,
    state:                &StateStore,
    new_public_key:       &[u8],
    new_key_scheme:       &str,
    key_version:          &u32,
    pop_signature:        &[u8],
    guardian_signatures:  &[GuardianAuth],
    policy_id:            u64,
    block_height:         u64,
) -> Result<u32, String> {
    use chain_forge_crypto::Signature as CfSig;

    const MLDSA65_PK_BYTES: usize = 1952;

    // Guard 1: policy must be enrolled.
    let policy = state
        .get_account(&tx.sender)
        .ok()
        .and_then(|a| a.recovery_policy.clone())
        .ok_or_else(|| format!(
            "RecoverAccountKey: {} has no enrolled recovery policy",
            tx.sender
        ))?;

    // Guard 2: policy must not be stale (no rotation since enrollment).
    let current_version = state
        .get_account(&tx.sender)
        .map(|a| a.key_version)
        .unwrap_or(0);
    if policy.enrolled_at_key_version != current_version {
        return Err(format!(
            "RecoverAccountKey: stale policy (enrolled at key_version {}, current {})",
            policy.enrolled_at_key_version, current_version
        ));
    }

    // Guard 2b (DIS-003A): policy_id must match the enrolled policy's generation.
    // This prevents replay of guardian signatures created for a previous (now
    // superseded or revoked) policy, even if the guardian set is identical.
    if policy_id != policy.policy_id {
        return Err(format!(
            "RecoverAccountKey: policy_id mismatch: tx carries {policy_id}, enrolled policy has {}",
            policy.policy_id
        ));
    }

    // Guard 3: key_version must be current + 1.
    if *key_version != current_version + 1 {
        return Err(format!(
            "RecoverAccountKey: key_version mismatch: expected {}, got {}",
            current_version + 1, key_version
        ));
    }

    // Guard 4: scheme.
    if new_key_scheme != "ml-dsa-65" {
        return Err(format!(
            "RecoverAccountKey: unsupported key scheme '{}'; only 'ml-dsa-65' is accepted",
            new_key_scheme
        ));
    }

    // Guard 5: new key size.
    if new_public_key.len() != MLDSA65_PK_BYTES {
        return Err(format!(
            "RecoverAccountKey: new_public_key must be {MLDSA65_PK_BYTES} bytes, got {}",
            new_public_key.len()
        ));
    }

    // Guard 6+7+8+10: verify guardian signatures, check policy membership, no duplicates,
    // and check per-guardian expiry (DIS-003D).
    let mut seen_guardian_keys: Vec<&[u8]> = Vec::new();
    let mut valid_count: u32 = 0;

    for (i, ga) in guardian_signatures.iter().enumerate() {
        // Must be listed in the policy.
        let in_policy = policy.guardians.iter().any(|g| g.as_slice() == ga.guardian_public_key.as_slice());
        if !in_policy {
            return Err(format!(
                "RecoverAccountKey: guardian_signatures[{i}] key is not in the enrolled policy"
            ));
        }
        // No duplicate signing keys.
        if seen_guardian_keys.iter().any(|&k| k == ga.guardian_public_key.as_slice()) {
            return Err(format!(
                "RecoverAccountKey: duplicate guardian key at index {i}"
            ));
        }
        seen_guardian_keys.push(&ga.guardian_public_key);

        // Guard 10 (DIS-003D): check block-height expiry.
        if let Some(exp) = ga.expires_at_height {
            if block_height > exp {
                return Err(format!(
                    "RecoverAccountKey: guardian_signatures[{i}] authorization expired at height {exp}, current height is {block_height}"
                ));
            }
        }

        // Verify signature — each guardian's message encodes their own expires_at_height.
        let recovery_msg = recovery_domain_signing_bytes(
            &config.chain_id,
            &tx.sender,
            *key_version,
            new_public_key,
            policy.policy_id,
            ga.expires_at_height,
        );
        let sig = CfSig { scheme: SchemeId::MlDsa, bytes: ga.signature.clone() };
        MlDsaScheme
            .verify(&recovery_msg, &sig, &ga.guardian_public_key)
            .map_err(|e| format!(
                "RecoverAccountKey: guardian_signatures[{i}] verification failed: {e}"
            ))?;
        valid_count += 1;
    }

    if valid_count < policy.threshold {
        return Err(format!(
            "RecoverAccountKey: only {valid_count} valid guardian signature(s), need {}",
            policy.threshold
        ));
    }

    // Guard 9: proof-of-possession from new key.
    let pop_message = account_key_rotation_signing_bytes(
        &config.chain_id,
        &tx.sender,
        *key_version,
        new_public_key,
    );
    let pop_sig = CfSig { scheme: SchemeId::MlDsa, bytes: pop_signature.to_vec() };
    MlDsaScheme
        .verify(&pop_message, &pop_sig, new_public_key)
        .map_err(|e| format!("RecoverAccountKey: proof-of-possession verification failed: {e}"))?;
    Ok(current_version)
}

/// DIS-003: guardian authorization is RecoverAccountKey's authorization,
/// because the account-key check is skipped for it. Run it before the fee
/// debit so a recovery attempt without valid guardian authorization is
/// rejected outright and costs the named account nothing.
fn precheck_recovery_authorization(
    config:       &ExecutionConfig,
    tx:           &Transaction,
    state:        &StateStore,
    block_height: u64,
) -> Result<(), String> {
    if let TxBody::RecoverAccountKey {
        new_public_key, new_key_scheme, key_version, pop_signature,
        guardian_signatures, policy_id,
    } = &tx.body {
        verify_recover_account_key(
            config, tx, state, new_public_key, new_key_scheme, key_version,
            pop_signature, guardian_signatures, *policy_id, block_height,
        )?;
    }
    Ok(())
}

/// Commit a RecoverAccountKey after `verify_recover_account_key` passes.
fn execute_recover_account_key(
    config:               &ExecutionConfig,
    tx:                   &Transaction,
    state:                &mut StateStore,
    new_public_key:       &[u8],
    new_key_scheme:       &str,
    key_version:          &u32,
    pop_signature:        &[u8],
    guardian_signatures:  &[GuardianAuth],
    policy_id:            u64,
    block_height:         u64,
) -> Result<(), String> {
    let current_version = verify_recover_account_key(
        config, tx, state, new_public_key, new_key_scheme, key_version,
        pop_signature, guardian_signatures, policy_id, block_height,
    )?;

    // All guards passed — commit the recovery.
    {
        let acct = state
            .get_account_mut(&tx.sender)
            .map_err(|e| format!("RecoverAccountKey: account lookup failed: {e}"))?;
        acct.public_key      = Some(new_public_key.to_vec());
        acct.key_version     = current_version + 1;
        // Policy is consumed — must re-enroll after recovery.
        acct.recovery_policy = None;
    }
    state.refresh_leaf(&tx.sender);

    tracing::info!(
        sender    = %tx.sender,
        new_ver   = current_version + 1,
        pk_len    = new_public_key.len(),
        "DIS-002B: account key recovered via guardian policy"
    );
    Ok(())
}

/// DIS-003A: Execute a RevokeRecoveryPolicy transaction.
///
/// Clears `recovery_policy` on the sender's account. Does NOT reset
/// `policy_generation` — the counter is monotone and survives revocation so
/// that old guardian signatures cannot be replayed if a policy with the same
/// guardian set is later re-enrolled.
fn execute_revoke_recovery_policy(
    tx:    &Transaction,
    state: &mut StateStore,
) -> Result<(), String> {
    {
        let acct = state
            .get_account_mut(&tx.sender)
            .map_err(|e| format!("RevokeRecoveryPolicy: account lookup failed: {e}"))?;
        if acct.recovery_policy.is_none() {
            return Err(format!(
                "RevokeRecoveryPolicy: {} has no enrolled recovery policy to revoke",
                tx.sender
            ));
        }
        acct.recovery_policy = None;
        // policy_generation is intentionally NOT touched.
    }
    state.refresh_leaf(&tx.sender);

    tracing::info!(sender = %tx.sender, "DIS-003A: recovery policy revoked");
    Ok(())
}

/// DIS-003B: Execute an UpdateGuardianPolicy transaction.
///
/// Replaces the guardian set of an **existing** enrolled recovery policy.
/// Authorization: signed by the current account key (same as EnrollRecoveryPolicy).
/// Effect: increments `policy_generation` and stamps a new `policy_id`, invalidating
/// any guardian signatures collected under the old set.
///
/// Guards (same as EnrollRecoveryPolicy):
///  1. An active policy must already be enrolled.
///  2. threshold >= 1 and <= new_guardians.len()
///  3. At least 1 guardian (and no more than 10 for Phase 0)
///  4. Each key must be a valid ML-DSA-65 key (1952 bytes)
///  5. Guardian keys must be distinct
fn execute_update_guardian_policy(
    tx:           &Transaction,
    state:        &mut StateStore,
    new_guardians: &[Vec<u8>],
    new_threshold: u32,
) -> Result<(), String> {
    const MLDSA65_PK_BYTES: usize = 1952;
    const MAX_GUARDIANS:    usize = 10;

    // Guard 1: must have an active policy to update.
    let has_policy = state.get_account(&tx.sender)
        .map(|a| a.recovery_policy.is_some())
        .unwrap_or(false);
    if !has_policy {
        return Err(format!(
            "UpdateGuardianPolicy: {} has no enrolled recovery policy to update",
            tx.sender
        ));
    }

    if new_guardians.is_empty() {
        return Err("UpdateGuardianPolicy: must specify at least 1 guardian".to_string());
    }
    if new_guardians.len() > MAX_GUARDIANS {
        return Err(format!(
            "UpdateGuardianPolicy: too many guardians (max {MAX_GUARDIANS}, got {})",
            new_guardians.len()
        ));
    }
    if new_threshold == 0 || new_threshold as usize > new_guardians.len() {
        return Err(format!(
            "UpdateGuardianPolicy: threshold {} out of range [1, {}]",
            new_threshold, new_guardians.len()
        ));
    }
    for (i, g) in new_guardians.iter().enumerate() {
        if g.len() != MLDSA65_PK_BYTES {
            return Err(format!(
                "UpdateGuardianPolicy: guardian[{i}] key must be {MLDSA65_PK_BYTES} bytes, got {}",
                g.len()
            ));
        }
    }
    for i in 0..new_guardians.len() {
        for j in (i + 1)..new_guardians.len() {
            if new_guardians[i] == new_guardians[j] {
                return Err(format!(
                    "UpdateGuardianPolicy: guardian[{i}] and guardian[{j}] are the same key"
                ));
            }
        }
    }

    let (current_version, next_generation) = state
        .get_account(&tx.sender)
        .map(|a| (a.key_version, a.policy_generation + 1))
        .unwrap_or((0, 1));

    {
        let acct = state
            .get_account_mut(&tx.sender)
            .map_err(|e| format!("UpdateGuardianPolicy: account lookup failed: {e}"))?;
        acct.policy_generation = next_generation;
        acct.recovery_policy = Some(chain_forge_state::RecoveryPolicy {
            guardians:               new_guardians.to_vec(),
            threshold:               new_threshold,
            enrolled_at_key_version: current_version,
            policy_id:               next_generation,
        });
    }
    state.refresh_leaf(&tx.sender);

    tracing::info!(
        sender    = %tx.sender,
        threshold = new_threshold,
        guardians = new_guardians.len(),
        policy_id = next_generation,
        "DIS-003B: guardian policy updated"
    );
    Ok(())
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

    /// Genesis attestation quorum this executor installs on the IdentityStore.
    pub fn attestation_quorum(&self) -> usize {
        self.config.attestation_quorum
    }

    /// Genesis per-attester cap this executor installs on the IdentityStore.
    pub fn attestation_cap_per_window(&self) -> u32 {
        self.config.attestation_cap_per_window
    }

    /// Execute a single transaction with CharmConfinement enforcement.
    /// Requires identity store, QRC engine, and agent store for identity-gated
    /// and agent-registered tx types.
    /// Execute one tx against state, identity and agents.
    ///
    /// H0-5/H0-7 semantics:
    /// - rejected at admission (gas, module, nonce, authorization, fee):
    ///   no state change, `gas_used = 0`, `fee_charged = 0`;
    /// - included but failed: fee charged, nonce consumed exactly once, every
    ///   other write rolled back;
    /// - included and successful: fee charged, body applied.
    pub fn execute_tx_with_identity(
        &self,
        tx:           &Transaction,
        state:        &mut StateStore,
        identity:     &mut IdentityStore,
        agents:       &mut AgentStore,
        block_height: u64,
    ) -> TransactionResult {
        let mut r = self.execute_tx_with_identity_inner(tx, state, identity, agents, block_height);
        if r.fee_charged == 0 {
            r.gas_used = 0;
        }
        r
    }

    fn execute_tx_with_identity_inner(
        &self,
        tx:           &Transaction,
        state:        &mut StateStore,
        identity:     &mut IdentityStore,
        agents:       &mut AgentStore,
        block_height: u64,
    ) -> TransactionResult {
        identity.set_attestation_quorum(self.config.attestation_quorum);
        identity.set_attestation_cap_per_window(self.config.attestation_cap_per_window);
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

        // Nonce check runs before signature verification: it is a cheap state
        // lookup that catches replays and out-of-sequence txs before any crypto.
        {
            let expected_nonce = state.get_account(&tx.sender)
                .map(|a| a.nonce).unwrap_or(0);
            if tx.nonce != expected_nonce {
                return TransactionResult::err(
                    tx.id.clone(), gas_required, tx.gas_limit,
                    format!("nonce mismatch: expected {expected_nonce}, got {}", tx.nonce),
                );
            }
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

        // FS-03: Debit per-tx fee from sender before executing the body.
        // Failed txs still consume the fee (matching established EVM semantics).
        if let Err(e) = precheck_recovery_authorization(&self.config, tx, state, block_height) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }
        if let Err(e) = debit_fee(
            tx, gas_required, &self.config.native_denom,
            &self.config.fee_collector, state,
        ) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }

        // H0-5: the tx is now included (admitted, fee paid). Everything the
        // body writes -- state, identity, agents -- is undone if it fails.
        state.begin_checkpoint();
        let identity_before = identity.clone();
        let agents_before = agents.clone();
        let mut result = self.execute_tx_with_identity_body(tx, state, identity, agents, gas_required, block_height);
        if !result.success {
            *identity = identity_before;
            *agents = agents_before;
        }
        settle_included_tx(tx, state, &mut result, gas_required);
        result
    }

    /// Body of `execute_tx_with_identity`, run inside a checkpoint. Early
    /// returns here are failures of an included tx and get rolled back.
    fn execute_tx_with_identity_body(
        &self,
        tx:           &Transaction,
        state:        &mut StateStore,
        identity:     &mut IdentityStore,
        agents:       &mut AgentStore,
        gas_required: u64,
        block_height: u64,
    ) -> TransactionResult {
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
            TxBody::BondValidator { amount, owner_identity_id } => {
                // QPC-CONS-001 Phase B: authenticate owner_identity_id before
                // moving funds.  Fail-closed: a missing binding means the bond
                // is accepted (stake moves) but the validator will receive no
                // consensus voting power.  A supplied binding that fails
                // authentication is rejected outright to prevent spoofing.
                let binding_key = format!("validator-owner:{}", tx.sender);
                if let Some(owner) = owner_identity_id {
                    // Rule 1: sender must equal owner (proves address control).
                    if tx.sender != *owner {
                        Err(format!(
                            "bond_validator: sender {} cannot bind to identity \
                             {}: tx.sender must equal owner_identity_id",
                            tx.sender, owner
                        ))
                    } else if let Some(existing_owner) = state.get_raw(&binding_key) {
                        // Rule 3: reject unauthorized ownership changes. Once a
                        // binding is established, it is immutable via this tx path.
                        // Rotation requires a separately authorized recovery process.
                        if existing_owner != owner.as_str() {
                            Err(format!(
                                "bond_validator: owner_identity_id cannot be changed \
                                 once set; unauthorized ownership change rejected \
                                 (current owner: {}, attempted: {})",
                                existing_owner, owner
                            ))
                        } else {
                            // Same owner re-bonding: re-check eligibility on every
                            // bond. An owner who was frozen or lost Verified tier
                            // after the initial binding must be blocked here;
                            // skipping this check would allow a revoked identity to
                            // keep accumulating stake without pop_verified revocation.
                            let owner_eligible = identity.get(owner)
                                .map(|r| !r.frozen && r.charm.tier.grants_consensus())
                                .unwrap_or(false);
                            if !owner_eligible {
                                Err(format!(
                                    "bond_validator: identity {} no longer holds an \
                                     active personhood credential (frozen or tier \
                                     insufficient); re-bond rejected",
                                    owner
                                ))
                            } else {
                            let bond_account = format!("validator-bond:{}", tx.sender);
                            state.transfer(&tx.sender, &bond_account, &self.config.native_denom, *amount)
                                .map(|_| {
                                    events.push(format!(
                                        "bond_validator: {} {} bonded by {}",
                                        amount, self.config.native_denom, tx.sender
                                    ));
                                    events.push(format!(
                                        "bond_validator_owner_binding:{}:{}",
                                        tx.sender, owner
                                    ));
                                    identity.record_activity_by_address(&tx.sender);
                                })
                                .map_err(|e| e.to_string())
                            }
                        }
                    } else {
                        // Rule 2: owner must have an active, unfrozen personhood
                        // credential — resolved from authoritative IdentityStore
                        // state, not from the tx payload.
                        let owner_eligible = identity.get(owner)
                            .map(|r| !r.frozen && r.charm.tier.grants_consensus())
                            .unwrap_or(false);
                        if !owner_eligible {
                            Err(format!(
                                "bond_validator: identity {} does not hold an active \
                                 personhood credential (frozen or tier insufficient); \
                                 binding rejected",
                                owner
                            ))
                        } else {
                            // All checks passed: move stake first, then persist binding.
                            // set_raw is only reachable after transfer returns Ok,
                            // preventing an orphaned binding from a failed bond.
                            let bond_account = format!("validator-bond:{}", tx.sender);
                            match state.transfer(&tx.sender, &bond_account, &self.config.native_denom, *amount) {
                                Ok(()) => {
                                    state.set_raw(&binding_key, owner);
                                    events.push(format!(
                                        "bond_validator: {} {} bonded by {}",
                                        amount, self.config.native_denom, tx.sender
                                    ));
                                    // Authenticated binding event consumed by node.rs
                                    // to record the human→validator association.
                                    events.push(format!(
                                        "bond_validator_owner_binding:{}:{}",
                                        tx.sender, owner
                                    ));
                                    identity.record_activity_by_address(&tx.sender);
                                    Ok(())
                                }
                                Err(e) => Err(e.to_string()),
                            }
                        }
                    }
                } else {
                    // No binding: stake moves but this validator is unbound.
                    // Fail-closed: pop_verified stays false, voting_power = 0.
                    // A future authenticated re-bond or rotation tx can establish
                    // the binding.
                    let bond_account = format!("validator-bond:{}", tx.sender);
                    state.transfer(&tx.sender, &bond_account, &self.config.native_denom, *amount)
                        .map(|_| {
                            events.push(format!(
                                "bond_validator: {} {} bonded by {} (unbound: no consensus voting power until owner_identity_id is authenticated)",
                                amount, self.config.native_denom, tx.sender
                            ));
                            identity.record_activity_by_address(&tx.sender);
                        })
                        .map_err(|e| e.to_string())
                }
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

                if self.config.mldsa_consensus_only && effective_scheme != "ml-dsa-65" {
                    return TransactionResult::err(
                        tx.id.clone(), gas_required, tx.gas_limit,
                        format!("this chain's consensus keys are ML-DSA-65 only; \
                                 scheme '{effective_scheme}' cannot register"),
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

            TxBody::VerifyIdentityWithProof { proof_bytes, public_inputs_bytes } => {
                // ZK-VRC direct verification path (QPC-GAP-002).
                // Fails closed if no verifier is configured.
                match self.config.pop_verifier.as_deref() {
                    None => Err("VerifyIdentityWithProof: no pop_verifier configured on this node".to_string()),
                    Some(verifier) => {
                        let epoch = identity.clock.current_epoch;
                        let attestation = chain_forge_identity::PopAttestation {
                            identity_id: tx.sender.clone(),
                            attester:    tx.sender.clone(),
                            epoch,
                            proof:       proof_bytes.clone(),
                            note:        Some("zkp-vrc".to_string()),
                        };
                        identity.verify_identity(&tx.sender, attestation, Some(verifier))
                            .map_err(|e| e.to_string())
                            .and_then(|_| {
                                // Atomic charm-sync: both lookups must succeed or the
                                // tx fails. Partial state (identity updated, account
                                // stale) would leave a mismatched tier in the Merkle
                                // tree, so we gate refresh_leaf on full sync.
                                let record = identity.get(&tx.sender)
                                    .map_err(|e| format!("charm-sync: identity lookup failed after ZK-VRC upgrade: {}", e))?;
                                let acct = state.get_account_mut(&tx.sender)
                                    .map_err(|e| format!("charm-sync: account lookup failed after ZK-VRC upgrade: {}", e))?;
                                acct.attach_charm(record.charm.clone());
                                state.refresh_leaf(&tx.sender);
                                events.push(format!(
                                    "verify_identity_with_proof: {} upgraded to Verified via ZK-VRC",
                                    tx.sender
                                ));
                                Ok(())
                            })
                    }
                }
            }

            // DIS-002A: key rotation does not touch identity store.
            TxBody::RotateAccountKey { new_public_key, new_key_scheme, key_version, pop_signature } => {
                execute_rotate_account_key(
                    &self.config, tx, state,
                    new_public_key, new_key_scheme, key_version, pop_signature,
                )
            }

            // DIS-002B: recovery policy enrollment and recovery.
            TxBody::EnrollRecoveryPolicy { guardians, threshold } => {
                execute_enroll_recovery_policy(tx, state, guardians, *threshold)
            }
            TxBody::RecoverAccountKey {
                new_public_key, new_key_scheme, key_version, pop_signature, guardian_signatures,
                policy_id,
            } => {
                execute_recover_account_key(
                    &self.config, tx, state,
                    new_public_key, new_key_scheme, key_version, pop_signature, guardian_signatures,
                    *policy_id, block_height,
                )
            }
            TxBody::RevokeRecoveryPolicy => {
                execute_revoke_recovery_policy(tx, state)
            }
            TxBody::UpdateGuardianPolicy { new_guardians, new_threshold } => {
                execute_update_guardian_policy(tx, state, new_guardians, *new_threshold)
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
                // Pre-flight: if the attested identity is currently Verified via WoT
                // and has fewer than quorum+1 active attesters, this
                // revocation will trigger a tier downgrade and require charm-sync.
                // Charm-sync needs the account to exist in StateStore. Every identity
                // that reached Verified via on-chain Attest txs must have an account
                // (RegisterIdentity creates it). A missing account is an invariant
                // violation — reject before mutating identity state so that a failed
                // tx leaves no partial mutation behind.
                {
                    let would_downgrade = identity.get(attested_id)
                        .map(|r| {
                            r.charm.verified_via_wot
                                && r.charm.tier.grants_consensus()
                                && r.attestation_ledger.count() <= identity.attestation_quorum()
                        })
                        .unwrap_or(false);
                    if would_downgrade && state.get_account(attested_id).is_err() {
                        return TransactionResult::err(
                            tx.id.clone(), gas_required, tx.gas_limit,
                            format!(
                                "revoke_attestation: attested identity {} would be downgraded \
                                 but has no on-chain account — state invariant violated; \
                                 tx rejected to prevent partial mutation",
                                attested_id
                            ),
                        );
                    }
                }
                // The identity crate enforces all rules (active record exists,
                // not already revoked) and returns the CS cost signal plus a
                // tier_downgraded flag (Phase C revocation propagation).
                identity.revoke_attestation(&tx.sender, attested_id)
                    .map_err(|e| e.to_string())
                    .and_then(|cost| {
                        // CS cost event. Full CS deduction from the state store
                        // is wired up when the CS ledger is on-chain; the event
                        // is the observable signal for now.
                        events.push(format!(
                            "revoke_attestation: {} revoked attestation of {} \
                             (cs_cost_bps={}, tier_downgraded={})",
                            cost.attester_id, cost.attested_id,
                            cost.cost_bps, cost.tier_downgraded
                        ));
                        // Phase C: if the revocation caused the attested identity
                        // to drop below quorum and be downgraded to Provisional,
                        // sync their updated charm to account state and refresh
                        // the Merkle leaf so light clients and verifiers see the
                        // correct tier and voting weight.
                        if cost.tier_downgraded {
                            // Atomic charm-sync: if either lookup fails the tx
                            // returns an error. The identity record was already
                            // mutated by revoke_attestation, so on retry the
                            // charm will be re-read from the updated record.
                            // Do NOT call refresh_leaf until sync succeeds —
                            // committing a stale Verified charm to the Merkle
                            // tree would leave a validator gate-eligible after
                            // revocation.
                            let record = identity.get(attested_id)
                                .map_err(|e| format!("charm-sync: identity lookup failed after tier downgrade: {}", e))?;
                            let acct = state.get_account_mut(attested_id)
                                .map_err(|e| format!("charm-sync: account lookup failed after tier downgrade: {}", e))?;
                            acct.attach_charm(record.charm.clone());
                            state.refresh_leaf(attested_id);
                        }
                        Ok(())
                    })
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
                        // On an ML-DSA-only chain there is nothing to roll
                        // back to: deprecating it would zero every validator.
                        if self.config.mldsa_consensus_only {
                            return TransactionResult::err(
                                tx.id.clone(), gas_required, tx.gas_limit,
                                "EmergencyDeprecateAlgorithm: ML-DSA-65 is this chain's only \
                                 consensus scheme; deprecating it would halt the chain"
                                    .to_string(),
                            );
                        }
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
    /// Returns the result regardless of success/failure. Same H0-5/H0-7
    /// semantics as `execute_tx_with_identity`: a rejected tx changes nothing
    /// and uses no gas; an included-but-failed tx pays the fee and consumes
    /// its nonce, and nothing else changes.
    pub fn execute_tx(
        &self,
        tx:           &Transaction,
        state:        &mut StateStore,
        block_height: u64,
    ) -> TransactionResult {
        let mut r = self.execute_tx_inner(tx, state, block_height);
        if r.fee_charged == 0 {
            r.gas_used = 0;
        }
        r
    }

    fn execute_tx_inner(
        &self,
        tx: &Transaction,
        state: &mut StateStore,
        block_height: u64,
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
        if let Err(e) = precheck_recovery_authorization(&self.config, tx, state, block_height) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }
        if let Err(e) = debit_fee(
            tx, gas_required, &self.config.native_denom,
            &self.config.fee_collector, state,
        ) {
            return TransactionResult::err(tx.id.clone(), gas_required, tx.gas_limit, e);
        }

        // H0-5: the tx is now included (admitted, fee paid); undo the body's
        // writes if it fails.
        state.begin_checkpoint();
        let mut result = self.execute_tx_body(tx, state, gas_required, block_height);
        settle_included_tx(tx, state, &mut result, gas_required);
        result
    }

    /// Body of `execute_tx`, run inside a checkpoint.
    fn execute_tx_body(
        &self,
        tx:           &Transaction,
        state:        &mut StateStore,
        gas_required: u64,
        block_height: u64,
    ) -> TransactionResult {
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
            // VerifyIdentityWithProof requires the full identity- and state-aware executor.
            TxBody::VerifyIdentityWithProof { .. } => {
                Err("VerifyIdentityWithProof requires the full identity- and state-aware executor".to_string())
            }
            // RotateAccountKey is handled in the simple executor (no identity store needed).
            TxBody::RotateAccountKey { new_public_key, new_key_scheme, key_version, pop_signature } => {
                execute_rotate_account_key(
                    &self.config, tx, state,
                    new_public_key, new_key_scheme, key_version, pop_signature,
                )
            }
            // DIS-002B: recovery policy enrollment and recovery (no identity store needed).
            TxBody::EnrollRecoveryPolicy { guardians, threshold } => {
                execute_enroll_recovery_policy(tx, state, guardians, *threshold)
            }
            TxBody::RecoverAccountKey {
                new_public_key, new_key_scheme, key_version, pop_signature, guardian_signatures,
                policy_id,
            } => {
                execute_recover_account_key(
                    &self.config, tx, state,
                    new_public_key, new_key_scheme, key_version, pop_signature, guardian_signatures,
                    *policy_id, block_height,
                )
            }
            TxBody::RevokeRecoveryPolicy => {
                execute_revoke_recovery_policy(tx, state)
            }
            TxBody::UpdateGuardianPolicy { new_guardians, new_threshold } => {
                execute_update_guardian_policy(tx, state, new_guardians, *new_threshold)
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
                    0,
                    tx.gas_limit,
                    format!("block gas limit would be exceeded ({total_gas} + {gas_required} > {limit})"),
                ));
                continue;
            }

            let result = self.execute_tx(tx, state, height);
            total_gas     += result.gas_used;
            // H0-7: count only fees actually debited (included txs, successful
            // or failed). Rejected txs report fee_charged = 0.
            fees_collected += result.fee_charged;
            results.push(result);
        }

        // Distribute this block's fees: 70% validator pool / 20% treasury / 10% burn.
        // Operates only on fees_collected (this block) — not the collector's
        // balance. Must run before commit so the reported root includes it.
        distribute_block_fees_from(&self.config.fee_collector, fees_collected,
            &self.config.fee_distribution, &self.config.native_denom, state);

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
                    0,
                    tx.gas_limit,
                    format!("block gas limit would be exceeded ({total_gas} + {gas_required} > {limit})"),
                ));
                continue;
            }

            let result = self.execute_tx_with_identity(tx, state, identity, agents, height);
            total_gas      += result.gas_used;
            // H0-7: count only fees actually debited (see execute_block).
            fees_collected += result.fee_charged;
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

        // Distribute this block's fees: 70% validator pool / 20% treasury / 10% burn.
        distribute_block_fees_from(&self.config.fee_collector, fees_collected,
            &self.config.fee_distribution, &self.config.native_denom, state);

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
        let result = exec.execute_tx(&tx, &mut state, 0);

        assert!(result.success, "transfer should succeed: {:?}", result.error);
        // FS-03: alice pays transfer amount + fee; bob receives transfer amount only
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 5_000_000 - 100_000 - fee);
        assert_eq!(state.get_account("qcb1bob").unwrap().balance_of("uqcb"),   5_100_000);
    }

    #[test]
    fn transfer_fails_insufficient_balance() {
        let (exec, mut state) = setup();
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 999_000_000, 0);
        let result = exec.execute_tx(&tx, &mut state, 0);
        assert!(!result.success);
        assert!(!result.success, "transfer should fail with insufficient balance");
    }

    #[test]
    fn burn_tx_reduces_supply() {
        let (exec, mut state) = setup();
        let tx = Transaction::burn("tx1", "qcb1alice", "uqcb", 500_000, 0);
        let fee = gas_for(&exec, &tx);
        let result = exec.execute_tx(&tx, &mut state, 0);

        assert!(result.success, "{:?}", result.error);
        // FS-03: alice pays burn amount + fee
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 5_000_000 - 500_000 - fee);
    }

    #[test]
    fn nonce_mismatch_rejects_tx() {
        let (exec, mut state) = setup();
        // Send with nonce=1 when account expects nonce=0
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 1);
        let result = exec.execute_tx(&tx, &mut state, 0);
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("nonce"));
    }

    #[test]
    fn nonce_advances_after_tx() {
        let (exec, mut state) = setup();
        let tx1 = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0);
        let r1 = exec.execute_tx(&tx1, &mut state, 0);
        assert!(r1.success);

        // Second tx with nonce=1 should succeed
        let tx2 = Transaction::transfer("tx2", "qcb1alice", "qcb1bob", "uqcb", 1_000, 1);
        let r2 = exec.execute_tx(&tx2, &mut state, 0);
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
            fee_collector:    "treasury:fees".into(),
            fee_distribution: FeeDistribution::default(),
            pop_verifier:     None,
            attestation_quorum: chain_forge_core::DEFAULT_ATTESTATION_QUORUM,
            attestation_cap_per_window: chain_forge_core::DEFAULT_ATTESTATION_CAP_PER_WINDOW,
            mldsa_consensus_only: false,
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

        let result = exec.execute_tx(&tx, &mut state, 0);
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

        let result = exec.execute_tx(&tx, &mut state, 0);
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
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "{:?}", r.error);
        // FS-03: alice pays bond amount + fee; bond account receives bond amount only
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), 5_000_000 - 2_000_000 - fee);
        assert_eq!(state.get_account("validator-bond:qcb1alice").unwrap().balance_of("uqcb"), 2_000_000);
    }

    #[test]
    fn bonding_is_incremental_and_accumulates() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let tx1 = Transaction::bond_validator("bond1", "qcb1alice", 500_000, 0);
        let r1 = exec.execute_tx_with_identity(&tx1, &mut state, &mut identity, &mut agents, 0);
        assert!(r1.success, "{:?}", r1.error);
        let tx2 = Transaction::bond_validator("bond2", "qcb1alice", 300_000, 1);
        let r2 = exec.execute_tx_with_identity(&tx2, &mut state, &mut identity, &mut agents, 0);
        assert!(r2.success, "{:?}", r2.error);
        assert_eq!(state.get_account("validator-bond:qcb1alice").unwrap().balance_of("uqcb"), 800_000);
    }

    #[test]
    fn bond_fails_cleanly_on_insufficient_balance() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        // Alice only has 5_000_000 at genesis.
        let tx = Transaction::bond_validator("bond1", "qcb1alice", 50_000_000, 0);
        let fee = gas_for(&exec, &tx);
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("no bonded stake"));
    }

    #[test]
    fn unbond_starts_cooldown_and_removes_from_bond_account() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let bond = Transaction::bond_validator("bond1", "qcb1alice", 2_000_000, 0);
        let fee_bond = gas_for(&exec, &bond);
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents, 0);

        let unbond = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        let fee_unbond = gas_for(&exec, &unbond);
        let r = exec.execute_tx_with_identity(&unbond, &mut state, &mut identity, &mut agents, 0);
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
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents, 0);
        let unbond = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        let fee_unbond = gas_for(&exec, &unbond);
        exec.execute_tx_with_identity(&unbond, &mut state, &mut identity, &mut agents, 0);

        // Still epoch 0 -- cooldown (21 epochs) has not elapsed. A second
        // UnbondValidator call (the only way to attempt a sweep) must be
        // rejected, and must NOT move any funds.
        let sweep_attempt = Transaction::unbond_validator("unbond2", "qcb1alice", 2);
        let fee_sweep = gas_for(&exec, &sweep_attempt);
        let r = exec.execute_tx_with_identity(&sweep_attempt, &mut state, &mut identity, &mut agents, 0);
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
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents, 0);
        let unbond = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        exec.execute_tx_with_identity(&unbond, &mut state, &mut identity, &mut agents, 0);

        // Advance past the 21-epoch cooldown.
        identity.clock.current_epoch = 21;

        let sweep = Transaction::unbond_validator("unbond2", "qcb1alice", 2);
        let fee_bond   = gas_for(&exec, &Transaction::bond_validator("x", "qcb1alice", 2_000_000, 0));
        let fee_unbond = gas_for(&exec, &Transaction::unbond_validator("x", "qcb1alice", 0));
        let fee_sweep  = gas_for(&exec, &sweep);
        let r = exec.execute_tx_with_identity(&sweep, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "{:?}", r.error);
        // FS-03: bond, unbond, and sweep all pay fees; but full principal returns via sweep
        let expected_after_sweep = 5_000_000 - fee_bond - fee_unbond - fee_sweep;
        assert_eq!(state.get_account("qcb1alice").unwrap().balance_of("uqcb"), expected_after_sweep);
        assert_eq!(state.get_account("validator-unbonding:qcb1alice").unwrap().balance_of("uqcb"), 0);

        // Calling UnbondValidator again finds nothing bonded and nothing
        // matured left to sweep -- it must not double-release funds.
        let double_sweep = Transaction::unbond_validator("unbond3", "qcb1alice", 3);
        let fee_double = gas_for(&exec, &double_sweep);
        let r2 = exec.execute_tx_with_identity(&double_sweep, &mut state, &mut identity, &mut agents, 0);
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
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents, 0);
        let unbond1 = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        exec.execute_tx_with_identity(&unbond1, &mut state, &mut identity, &mut agents, 0);

        // Still cooling down (epoch 0 < unlock epoch 21); a second attempt
        // at the same nonce-advancing call correctly reports "not complete",
        // not a fresh, separately-tracked unbonding request.
        let unbond2 = Transaction::unbond_validator("unbond2", "qcb1alice", 2);
        let r = exec.execute_tx_with_identity(&unbond2, &mut state, &mut identity, &mut agents, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("cooldown not complete"));
    }

    #[test]
    fn bonding_by_different_validators_is_independent() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let a = Transaction::bond_validator("bondA", "qcb1alice", 2_000_000, 0);
        let b = Transaction::bond_validator("bondB", "qcb1bob", 4_000_000, 0);
        assert!(exec.execute_tx_with_identity(&a, &mut state, &mut identity, &mut agents, 0).success);
        assert!(exec.execute_tx_with_identity(&b, &mut state, &mut identity, &mut agents, 0).success);
        assert_eq!(state.get_account("validator-bond:qcb1alice").unwrap().balance_of("uqcb"), 2_000_000);
        assert_eq!(state.get_account("validator-bond:qcb1bob").unwrap().balance_of("uqcb"), 4_000_000);

        // Unbonding Alice must not touch Bob's independent bond.
        let unbond_a = Transaction::unbond_validator("unbondA", "qcb1alice", 1);
        assert!(exec.execute_tx_with_identity(&unbond_a, &mut state, &mut identity, &mut agents, 0).success);
        assert_eq!(state.get_account("validator-bond:qcb1bob").unwrap().balance_of("uqcb"), 4_000_000);
    }

    #[test]
    fn compute_stake_active_set_ranks_live_bonded_stake() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();
        let a = Transaction::bond_validator("bondA", "qcb1alice", 2_000_000, 0);
        let b = Transaction::bond_validator("bondB", "qcb1bob", 4_000_000, 0);
        let v = Transaction::bond_validator("bondV", "qcb1val", 500_000, 0); // below default min
        assert!(exec.execute_tx_with_identity(&a, &mut state, &mut identity, &mut agents, 0).success);
        assert!(exec.execute_tx_with_identity(&b, &mut state, &mut identity, &mut agents, 0).success);
        assert!(exec.execute_tx_with_identity(&v, &mut state, &mut identity, &mut agents, 0).success);

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
        exec.execute_tx_with_identity(&bond, &mut state, &mut identity, &mut agents, 0);
        let active_before = validator_bond::compute_stake_active_set(
            &state, "uqcb", validator_bond::DEFAULT_MIN_BOND_UQCB, validator_bond::DEFAULT_MAX_ACTIVE_VALIDATORS,
        );
        assert_eq!(active_before, vec![("qcb1alice".to_string(), 2_000_000)]);

        // UnbondValidator moves the bond out of validator-bond:qcb1alice
        // immediately (cooldown only gates when the *funds* return, not
        // when the validator stops counting toward the active set).
        let unbond = Transaction::unbond_validator("unbond1", "qcb1alice", 1);
        assert!(exec.execute_tx_with_identity(&unbond, &mut state, &mut identity, &mut agents, 0).success);
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
        exec.execute_tx_with_identity(&a, &mut state, &mut identity, &mut agents, 0);
        exec.execute_tx_with_identity(&b, &mut state, &mut identity, &mut agents, 0);

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
        let r = exec.execute_tx(&tx, &mut state, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("identity-aware executor"));
    }

    #[test]
    fn sponsor_agent_requires_verified_identity() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        // Bob is not in identity store -- should fail
        let tx = Transaction::sponsor_agent("tx1", "qcb1bob", "qcb1agent1", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
        assert!(!result.success, "unverified identity cannot sponsor agents");
    }

    #[test]
    fn sponsor_agent_succeeds_for_verified_human() {
        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        let tx = Transaction::sponsor_agent("tx1", "qcb1alice", "qcb1agent1", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);

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
        exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);

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
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);

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

    /// H0 identity hardening: the quorum and per-attester cap come from the
    /// executor's genesis config on every identity-aware tx. A store that
    /// carries weaker values -- set in memory, or reloaded from a persisted
    /// identity.json after a restart -- cannot lower the bar.
    #[test]
    fn executor_enforces_genesis_identity_params_over_store_values() {
        use chain_forge_identity::VerificationTier;

        let (exec, mut state, identity, mut agents) = setup_with_identity();
        assert_eq!(exec.attestation_quorum(), 3);
        assert_eq!(exec.attestation_cap_per_window(), 3);

        // Simulate restart: persist, reload, and leave weak values in memory.
        let json = serde_json::to_string(&identity).unwrap();
        let mut identity: IdentityStore = serde_json::from_str(&json).unwrap();
        identity.set_attestation_quorum(1);
        identity.set_attestation_cap_per_window(10);

        let mut acct = chain_forge_state::AccountState::new("qcb1newbie".into(), "user".into());
        acct.credit("uqcb", 10_000);
        state.upsert_account(acct);
        let reg = Transaction::register_identity("tx0", "qcb1newbie", 0);
        assert!(exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut agents, 0).success);

        let a1 = Transaction::attest("tx1", "qcb1alice", "qcb1newbie", 0);
        let r = exec.execute_tx_with_identity(&a1, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "{:?}", r.error);
        assert_eq!(identity.attestation_quorum(), 3, "executor reinstalls the genesis quorum");
        assert_eq!(identity.attestation_cap_per_window(), 3, "executor reinstalls the genesis cap");
        assert_eq!(*identity.get("qcb1newbie").unwrap().tier(), VerificationTier::Provisional,
            "one attestation must not verify under the genesis quorum of 3");
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
        exec.execute_tx_with_identity(&reg_tx, &mut state, &mut identity, &mut agents, 0);

        // Two attestations: still Provisional on-chain.
        let a1 = Transaction::attest("tx1", "qcb1alice", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&a1, &mut state, &mut identity, &mut agents, 0);
        let a2 = Transaction::attest("tx2", "qcb1bob", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&a2, &mut state, &mut identity, &mut agents, 0);
        assert_eq!(
            state.get_account("qcb1newbie").unwrap().verification_tier(),
            Some(&VerificationTier::Provisional)
        );

        // Third distinct attestation crosses quorum -- both IdentityStore
        // AND the on-chain account must now show Verified.
        let a3 = Transaction::attest("tx3", "qcb1carol", "qcb1newbie", 0);
        let result = exec.execute_tx_with_identity(&a3, &mut state, &mut identity, &mut agents, 0);
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
        let r1 = exec.execute_tx(&reg_tx, &mut state, 0);
        assert!(!r1.success, "RegisterIdentity must be rejected by the non-identity-aware executor");

        let attest_tx = Transaction::attest("tx2", "qcb1alice", "qcb1newbie", 0);
        let r2 = exec.execute_tx(&attest_tx, &mut state, 0);
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
        assert!(exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut agents, 0).success);
        assert_eq!(state.get_account("qcb1newbie").unwrap().nonce, 1);

        // Replaying the exact same registration is now a nonce mismatch,
        // not a second trip into the identity logic.
        let replay = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut agents, 0);
        assert!(!replay.success);
        assert!(replay.error.as_deref().unwrap_or("").contains("nonce mismatch"));

        // An attester's first attest advances their nonce, so their second
        // transaction must use nonce 1 -- and does succeed with it.
        let a1 = Transaction::attest("a1", "qcb1alice", "qcb1newbie", 0);
        assert!(exec.execute_tx_with_identity(&a1, &mut state, &mut identity, &mut agents, 0).success);
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 1);

        exec.execute_tx_with_identity(
            &Transaction::register_identity("r1", "qcb1other", 0),
            &mut state, &mut identity, &mut agents, 0,
        );
        let a2 = Transaction::attest("a2", "qcb1alice", "qcb1other", 1);
        let r = exec.execute_tx_with_identity(&a2, &mut state, &mut identity, &mut agents, 0);
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
        let r = exec.execute_tx(&tx, &mut state, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unsigned"));
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 0, "rejected tx must not advance nonce");
    }

    #[test]
    fn tx_signed_by_bound_key_succeeds() {
        let (exec, mut state, alice) = signed_setup();
        let mut tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sign(&alice, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx(&tx, &mut state, 0);
        assert!(r.success, "{:?}", r.error);
    }

    #[test]
    fn tx_signed_by_wrong_key_rejected() {
        let (exec, mut state, _) = signed_setup();
        let mallory = key("mallory");
        let mut tx = Transaction::transfer("tx1", "qcb1alice", "qcb1mallory", "uqcb", 100, 0);
        tx.sign(&mallory, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx(&tx, &mut state, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("does not match the key bound"));
    }

    #[test]
    fn tampered_tx_rejected() {
        let (exec, mut state, alice) = signed_setup();
        let mut tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sign(&alice, "qcb-testnet-1").unwrap();
        tx.body = TxBody::Transfer { to: "qcb1bob".into(), denom: "uqcb".into(), amount: 4_000_000 };
        let r = exec.execute_tx(&tx, &mut state, 0);
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
            &mut AgentStore::new(), 0,
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
            &mut AgentStore::new(), 0,
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
            &mut AgentStore::new(), 0,
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
        let r2 = exec.execute_tx(&transfer, &mut state, 0);
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
            &mut AgentStore::new(), 0,
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("must not be empty"));
    }

    #[test]
    fn signature_from_another_chain_rejected() {
        let (exec, mut state, alice) = signed_setup();
        let mut tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sign(&alice, "some-other-chain").unwrap();
        let r = exec.execute_tx(&tx, &mut state, 0);
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
        let r = exec.execute_tx(&tx, &mut state, 0);
        assert!(r.success, "tx with explicit Classical scheme tag must succeed");
    }

    /// sig_scheme = Classical on a tx with no actual signature body → rejected.
    #[test]
    fn cs001_h2_explicit_classical_scheme_with_empty_sig_rejected() {
        let (exec, mut state, _) = signed_setup();
        let mut tx = Transaction::transfer("tx2", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        tx.sig_scheme = Some(SchemeId::Classical);  // claim classical but no sig bytes
        let r = exec.execute_tx(&tx, &mut state, 0);
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
        let r = exec.execute_tx(&legacy_tx, &mut state, 0);
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
        let r = exec.execute_tx(&tx, &mut state, 0);
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
        let r = exec.execute_tx(&tx, &mut state, 0);
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
        let r = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "{:?}", r.error);

        let acct = state.get_account(addr.as_str()).unwrap();
        assert_eq!(acct.public_key.as_deref(), Some(user.public_key.as_slice()), "first tx binds the key");
        assert_eq!(acct.nonce, 1);

        // A different key can no longer act for this address.
        let other = key("someone-else");
        let mut hijack = Transaction::attest("h1", addr.as_str(), "qcb1alice", 1);
        hijack.sign(&other, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx_with_identity(&hijack, &mut state, &mut identity, &mut agents, 0);
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
        let r = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut agents, 0);
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
            let r = exec.execute_tx_with_identity(&attest, &mut state, &mut identity, &mut agents, 0);
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
            let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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
        let r = exec.execute_tx(&tx, &mut state, 0);
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
        let r = exec.execute_tx(&tx, &mut state, 0);
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
            &mut AgentStore::new(), 0,
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
            &mut AgentStore::new(), 0,
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

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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
        let r1 = exec.execute_tx_with_identity(&tx1, &mut state, &mut identity, &mut agents, 0);
        assert!(r1.success, "first deprecation must succeed: {:?}", r1.error);

        // Second deprecation while first is in progress — must be rejected.
        let tx2 = emergency_deprecate_tx("eda7b", gov, 1,
            "ML-DSA-65", "Hybrid-Ed25519-ML-DSA", 50, "Second migration");
        let r2 = exec.execute_tx_with_identity(&tx2, &mut state, &mut identity, &mut agents, 0);
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

        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
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
        let r = exec.execute_tx_with_identity(&dep_tx, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "deprecation tx must succeed: {:?}", r.error);

        // Every tx below uses alice's current on-chain nonce, so a rejection
        // can only come from the gate under test, never from a nonce mismatch.
        let alice_nonce = |state: &StateStore| state.get_account("qcb1alice").unwrap().nonce;

        // Sanity: epoch 51 is the last grace epoch — transfer with Classical
        // sig_scheme should still be accepted.
        identity.clock.current_epoch = 51;
        let mut in_grace = Transaction::transfer(
            "t-grace", "qcb1alice", "qcb1bob", "uqcb", 1, alice_nonce(&state)
        );
        in_grace.sig_scheme = Some(SchemeId::Classical);
        let r = exec.execute_tx_with_identity(&in_grace, &mut state, &mut identity, &mut agents, 0);
        // May fail for other reasons (balance, nonce) but must NOT fail with the
        // cutoff message while still in the grace window.
        if !r.success {
            let err = r.error.unwrap_or_default();
            assert!(!err.contains("was deprecated"),
                "Classical scheme must still be accepted at epoch 51 (in grace window); got: {err}");
        }

        // Epoch 52 = one past the hard cutoff — Classical scheme must be rejected.
        identity.clock.current_epoch = 52;
        let nonce_before_cutoff = alice_nonce(&state);
        let mut post_cutoff = Transaction::transfer(
            "t-post-cutoff", "qcb1alice", "qcb1bob", "uqcb", 1, nonce_before_cutoff
        );
        post_cutoff.sig_scheme = Some(SchemeId::Classical);
        let r = exec.execute_tx_with_identity(&post_cutoff, &mut state, &mut identity, &mut agents, 0);
        assert!(!r.success, "Classical scheme must be rejected after hard cutoff");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("was deprecated"),
            "error must mention deprecation; got: {err}");
        assert!(err.contains("rotate to"),
            "error must hint at replacement scheme; got: {err}");
        assert_eq!(alice_nonce(&state), nonce_before_cutoff,
            "a deprecated-scheme rejection must not consume the nonce");

        // A transaction using the replacement scheme (ml-dsa) must NOT be
        // blocked by the cutoff check — the cutoff is scheme-specific.
        let mut pq_tx = Transaction::transfer(
            "t-pq-ok", "qcb1alice", "qcb1bob", "uqcb", 1, 2
        );
        pq_tx.sig_scheme = Some(SchemeId::MlDsa);
        let r = exec.execute_tx_with_identity(&pq_tx, &mut state, &mut identity, &mut agents, 0);
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
            "t-untagged", "qcb1alice", "qcb1bob", "uqcb", 1, nonce_before_cutoff
        );
        assert!(untagged.sig_scheme.is_none());
        let r = exec.execute_tx_with_identity(&untagged, &mut state, &mut identity, &mut agents, 0);
        assert!(!r.success, "Untagged classical tx must be blocked by cutoff after P6 (gap G2 closed)");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("was deprecated") || err.contains("deprecated"),
            "Untagged classical tx must fail with deprecation error; got: {err}");

        // Control: the replacement scheme (ml-dsa) at the SAME nonce is not
        // blocked -- the cutoff is scheme-specific, and the nonce was valid,
        // so the rejections above came from the deprecation gate.
        let mut pq_tx = Transaction::transfer(
            "t-pq-ok", "qcb1alice", "qcb1bob", "uqcb", 1, nonce_before_cutoff
        );
        pq_tx.sig_scheme = Some(SchemeId::MlDsa);
        let r = exec.execute_tx_with_identity(&pq_tx, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "MlDsa scheme must not be blocked by Classical cutoff; got: {:?}", r.error);
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
            &consensus_tx, &mut state, &mut identity, &mut agents, 0,
        );
        assert!(!r.success, "ConsensusSignatures scope must be rejected for non-ml-dsa-65 schemes");
        let err = r.error.clone().unwrap_or_default();
        // Guard 0 allows ConsensusSignatures only for "ml-dsa-65" (PQ-VAL-002 rollback path).
        // Any other deprecated_scheme with ConsensusSignatures scope must be rejected with a
        // message naming the only supported scheme.
        assert!(
            err.contains("ml-dsa-65") || err.contains("only supported"),
            "error must name the only permitted ConsensusSignatures scheme; got: {err}"
        );

        // Both scope must also be rejected.
        let both_tx = Transaction {
            id: "scope-both".to_string(),
            sender: gov.to_string(),
            nonce: 1, // H0-5: the rejected tx above was included and consumed nonce 0
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
            &both_tx, &mut state, &mut identity, &mut agents, 0,
        );
        assert!(!r.success, "Both scope must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("not yet supported"),
            "error for Both scope must say not yet supported; got: {err}");

        // TxSignatures scope must succeed (sanity check the guard is scoped).
        let good_tx = emergency_deprecate_tx(
            "scope-ok", gov, 2, "ed25519", "ml-dsa",
            MIN_CRYPTO_GRACE_EPOCHS, "scope guard sanity",
        );
        let r = exec.execute_tx_with_identity(
            &good_tx, &mut state, &mut identity, &mut agents, 0,
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
            &dep_tx, &mut state, &mut identity, &mut agents, 0,
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
        let alice_nonce = state.get_account("qcb1alice").unwrap().nonce;
        let mut cutoff_tx = Transaction::transfer(
            "restart-cutoff", "qcb1alice", "qcb1bob", "uqcb", 1, alice_nonce,
        );
        cutoff_tx.sig_scheme = Some(SchemeId::Classical);
        let r = exec.execute_tx_with_identity(
            &cutoff_tx, &mut state, &mut identity, &mut agents, 0,
        );
        assert!(!r.success,
            "deprecated scheme must still be rejected post-restart");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("was deprecated"),
            "post-restart cutoff error must mention deprecation; got: {err}");

        // Control: the replacement scheme at the same nonce is accepted, so
        // the rejection above came from the restored deprecation state.
        let mut pq_tx = Transaction::transfer(
            "restart-pq-ok", "qcb1alice", "qcb1bob", "uqcb", 1, alice_nonce,
        );
        pq_tx.sig_scheme = Some(SchemeId::MlDsa);
        let r = exec.execute_tx_with_identity(&pq_tx, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "replacement scheme must be accepted post-restart; got: {:?}", r.error);
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
            &bad_rep_tx, &mut state, &mut identity, &mut agents, 0,
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
            nonce: 1, // H0-5: the rejected tx above was included and consumed nonce 0
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
            &bad_dep_tx, &mut state, &mut identity, &mut agents, 0,
        );
        assert!(!r.success,
            "unknown deprecated scheme must be rejected");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("not a known scheme id"),
            "error must name the guard; got: {err}");

        // Valid tx must still succeed after the rejects.
        let good_tx = emergency_deprecate_tx(
            "good-scheme", gov, 2, "ed25519", "ml-dsa",
            MIN_CRYPTO_GRACE_EPOCHS, "valid schemes",
        );
        let r = exec.execute_tx_with_identity(
            &good_tx, &mut state, &mut identity, &mut agents, 0,
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
            &first_tx, &mut state, &mut identity, &mut agents, 0,
        );
        assert!(r.success, "first migration must succeed: {:?}", r.error);

        // 2. Duplicate — same scheme, same governor: must be rejected.
        let dup_tx = emergency_deprecate_tx(
            "dup-mig", gov, 1, "ed25519", "ml-dsa",
            MIN_CRYPTO_GRACE_EPOCHS, "Duplicate migration",
        );
        let r = exec.execute_tx_with_identity(
            &dup_tx, &mut state, &mut identity, &mut agents, 0,
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
            nonce: 2, // H0-5: the failed duplicate above consumed nonce 1
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
            &conflict_tx, &mut state, &mut identity, &mut agents, 0,
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
            &transfer_tx, &mut state, &mut identity, &mut agents, 0,
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
        let r = exec.execute_tx_with_identity(&eda, &mut state, &mut identity, &mut agents, 0);
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
            &untagged_tx, &mut state, &mut identity, &mut agents, 0,
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
        let r = exec.execute_tx_with_identity(&eda, &mut state, &mut identity, &mut agents, 0);
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
            &make_transfer("p6-bound-51", 1), &mut state, &mut identity, &mut agents, 0,
        );
        assert!(r51.success,
            "classical tx must be accepted AT hard_cutoff_epoch (51); got: {:?}", r51.error);

        // At epoch 52 (== hard_cutoff_epoch + 1): classical rejected.
        identity.clock.current_epoch = 52;
        let r52 = exec.execute_tx_with_identity(
            &make_transfer("p6-bound-52", 2), &mut state, &mut identity, &mut agents, 0,
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
            &mldsa_tx, &mut state, &mut identity, &mut agents, 0,
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
        let r = exec.execute_tx_with_identity(&eda, &mut state, &mut identity, &mut agents, 0);
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
            &unsigned_classical, &mut state, &mut identity, &mut agents, 0,
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
        let r = exec.execute_tx_with_identity(&fund_tx, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "fund: {:?}", r.error);

        // Bond (addr nonce 0)
        let bond_tx = Transaction::bond_validator("bond-diag", &addr, 2_000_000, 0);
        let r = exec.execute_tx_with_identity(&bond_tx, &mut state, &mut identity, &mut agents, 0);
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

        let r1 = exec.execute_tx_with_identity(&reg1, &mut state, &mut identity, &mut agents, 0);
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

        let r2 = exec.execute_tx_with_identity(&reg2, &mut state, &mut identity, &mut agents, 0);
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
        tx.pq_signatures = vec!["mldsa65:deadbeef".into()]; // 8 hex chars, not 6618
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
    fn check_tx_accepts_nonce_zero() {
        // nonce=0 is valid at the check_tx level: execution expects it for a fresh account.
        let mut tx = minimal_tx("qcb1alice", 100_000);
        tx.nonce = 0;
        assert!(check_tx(&tx, 0, 0).is_ok(), "nonce=0 must be accepted by check_tx");
    }

    #[test]
    fn check_tx_rejects_nonce_u64_max() {
        let mut tx = minimal_tx("qcb1alice", 100_000);
        tx.nonce = u64::MAX;
        assert!(check_tx(&tx, 0, 0).is_err(), "nonce=u64::MAX must be rejected");
    }

    #[test]
    fn check_tx_rejects_gas_above_absolute_cap() {
        let tx = minimal_tx("qcb1alice", u64::MAX);
        assert!(check_tx(&tx, 0, 0).is_err(), "gas=u64::MAX must be rejected by absolute cap");
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

    // -- Phase C: revocation propagation syncs charm to on-chain account ------

    #[test]
    fn revoke_attestation_below_quorum_downgrades_onchain_tier() {
        // End-to-end: attest newbie up to Verified via three attesters,
        // then revoke one attestation and verify the on-chain account charm
        // is synced back to Provisional (Phase C revocation propagation).
        use chain_forge_identity::{PopAttestation, VerificationTier};

        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        // Bootstrap two more Verified attesters alongside alice.
        for name in ["qcb1bob", "qcb1carol"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att, None).unwrap();
        }
        for name in ["qcb1newbie", "qcb1bob", "qcb1carol"] {
            let mut acct = chain_forge_state::AccountState::new(name.into(), "user".into());
            acct.credit("uqcb", 10_000);
            state.upsert_account(acct);
        }

        // Register and attest newbie up to quorum (Verified).
        exec.execute_tx_with_identity(
            &Transaction::register_identity("r0", "qcb1newbie", 0),
            &mut state, &mut identity, &mut agents, 0,
        );
        exec.execute_tx_with_identity(
            &Transaction::attest("a1", "qcb1alice", "qcb1newbie", 0),
            &mut state, &mut identity, &mut agents, 0,
        );
        exec.execute_tx_with_identity(
            &Transaction::attest("a2", "qcb1bob", "qcb1newbie", 0),
            &mut state, &mut identity, &mut agents, 0,
        );
        let r3 = exec.execute_tx_with_identity(
            &Transaction::attest("a3", "qcb1carol", "qcb1newbie", 0),
            &mut state, &mut identity, &mut agents, 0,
        );
        assert!(r3.success, "third attest should succeed and reach quorum");
        assert_eq!(
            state.get_account("qcb1newbie").unwrap().verification_tier(),
            Some(&VerificationTier::Verified),
            "on-chain account must be Verified after quorum"
        );

        // Phase C: revoke alice's attestation — count drops 3→2, below quorum.
        // alice nonce advanced to 1 after the attest tx.
        let rev = Transaction::revoke_attestation("rev1", "qcb1alice", "qcb1newbie", 1);
        let rr = exec.execute_tx_with_identity(&rev, &mut state, &mut identity, &mut agents, 0);
        assert!(rr.success, "revoke_attestation must succeed: {:?}", rr.error);
        assert!(
            rr.events.iter().any(|e| e.contains("tier_downgraded=true")),
            "revocation event must report tier_downgraded=true; events={:?}", rr.events
        );

        // Both the identity store and the on-chain account must now show Provisional.
        assert_eq!(
            *identity.get("qcb1newbie").unwrap().tier(),
            VerificationTier::Provisional,
            "identity store must show Provisional after revocation below quorum"
        );
        assert_eq!(
            state.get_account("qcb1newbie").unwrap().verification_tier(),
            Some(&VerificationTier::Provisional),
            "on-chain account charm must be synced to Provisional (Phase C)"
        );
    }

    // -- QPC-GAP-002: VerifyIdentityWithProof fail-closed ----------------------

    #[test]
    fn verify_identity_with_proof_fails_closed_when_no_verifier_configured() {
        // When pop_verifier is None (default), VerifyIdentityWithProof must
        // return a failure with the "no pop_verifier configured" sentinel.
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config = ExecutionConfig::from_genesis(&genesis);  // pop_verifier = None
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let mut identity = chain_forge_identity::IdentityStore::new(0);
        let att = chain_forge_identity::PopAttestation::genesis("qcb1alice", 0);
        identity.register("qcb1alice".into(), "qcb1alice".into(), att.clone()).unwrap();
        let mut agents = AgentStore::new();
        let exec = Executor::new(config);

        let tx = Transaction {
            id:           "vip1".into(),
            sender:       "qcb1alice".into(),
            nonce:        0,
            body:         TxBody::VerifyIdentityWithProof {
                proof_bytes: vec![0u8; 32],
                public_inputs_bytes: vec![],
            },
            gas_limit:    1_000_000,
            signature:    vec![],
            public_key:   vec![],
            pq_signatures: vec![],
            sig_scheme:   None,
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
        assert!(!r.success, "must fail when no pop_verifier is wired");
        let err = r.error.as_deref().unwrap_or("");
        assert!(
            err.contains("no pop_verifier configured"),
            "error must contain sentinel text; got: {err}"
        );
    }

    // -- QPC-GAP-002: VerifyIdentityWithProof upgrades Provisional → Verified --

    struct AlwaysOkVerifier;
    impl chain_forge_identity::PopProofVerifier for AlwaysOkVerifier {
        fn verify_pop_proof(&self, _proof_bytes: &[u8], _public_inputs: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn verify_identity_with_proof_upgrades_provisional_to_verified() {
        use std::sync::Arc;
        use chain_forge_identity::VerificationTier;
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut exec_config = ExecutionConfig::from_genesis(&genesis);
        exec_config.pop_verifier = Some(Arc::new(AlwaysOkVerifier));
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let mut identity = chain_forge_identity::IdentityStore::new(0);
        // Register qcb1bob as Provisional only (no verify_identity call).
        let reg_att = chain_forge_identity::PopAttestation::genesis("qcb1bob", 0);
        identity.register("qcb1bob".into(), "qcb1bob".into(), reg_att).unwrap();
        let mut agents = AgentStore::new();
        let exec = Executor::new(exec_config);

        assert_eq!(
            *identity.get("qcb1bob").unwrap().tier(),
            VerificationTier::Provisional,
            "precondition: bob must be Provisional before proof submission"
        );

        let tx = Transaction {
            id:           "vip2".into(),
            sender:       "qcb1bob".into(),
            nonce:        0,
            body:         TxBody::VerifyIdentityWithProof {
                proof_bytes: vec![1u8; 64],
                public_inputs_bytes: vec![2u8; 16],
            },
            gas_limit:    1_000_000,
            signature:    vec![],
            public_key:   vec![],
            pq_signatures: vec![],
            sig_scheme:   None,
            pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "VerifyIdentityWithProof must succeed with stub verifier: {:?}", r.error);
        assert_eq!(
            *identity.get("qcb1bob").unwrap().tier(),
            VerificationTier::Verified,
            "bob must be Verified after successful proof submission"
        );
    }

    // -- Security regression tests (PR #10 review findings) -------------------

    // Finding 2: re-bond after owner frozen must be rejected
    #[test]
    fn rebond_rejected_after_owner_frozen() {
        use chain_forge_identity::PopAttestation;

        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        // First authenticated bond succeeds — alice is Verified and unfrozen.
        let bond1 = Transaction {
            id: "bond1".into(), sender: "qcb1alice".into(), nonce: 0,
            body: TxBody::BondValidator { amount: 1_000_000, owner_identity_id: Some("qcb1alice".into()) },
            gas_limit: 50_000, signature: vec![], public_key: vec![],
            pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
        };
        let r1 = exec.execute_tx_with_identity(&bond1, &mut state, &mut identity, &mut agents, 0);
        assert!(r1.success, "initial authenticated bond must succeed: {:?}", r1.error);

        // Freeze alice's identity record directly (simulates sybil confirmation
        // or any other freeze path).
        identity.get_mut("qcb1alice").unwrap().frozen = true;

        // Re-bond attempt must be rejected — frozen owner fails eligibility.
        let bond2 = Transaction {
            id: "bond2".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::BondValidator { amount: 500_000, owner_identity_id: Some("qcb1alice".into()) },
            gas_limit: 50_000, signature: vec![], public_key: vec![],
            pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
        };
        let r2 = exec.execute_tx_with_identity(&bond2, &mut state, &mut identity, &mut agents, 0);
        assert!(!r2.success, "re-bond from frozen owner must be rejected");
        let err = r2.error.unwrap();
        assert!(err.contains("no longer holds") || err.contains("frozen") || err.contains("tier"),
            "error must name the eligibility check, got: {err}");
    }

    // Finding 2: re-bond after owner downgraded to Provisional must be rejected
    #[test]
    fn rebond_rejected_after_owner_downgraded_to_provisional() {
        use chain_forge_identity::{PopAttestation, VerificationTier};

        let (exec, mut state, mut identity, mut agents) = setup_with_identity();

        // First authenticated bond.
        let bond1 = Transaction {
            id: "bond1".into(), sender: "qcb1alice".into(), nonce: 0,
            body: TxBody::BondValidator { amount: 1_000_000, owner_identity_id: Some("qcb1alice".into()) },
            gas_limit: 50_000, signature: vec![], public_key: vec![],
            pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
        };
        assert!(exec.execute_tx_with_identity(&bond1, &mut state, &mut identity, &mut agents, 0).success);

        // Manually downgrade alice's charm tier to Provisional.
        {
            let rec = identity.get_mut("qcb1alice").unwrap();
            rec.charm.tier = VerificationTier::Provisional;
        }

        let bond2 = Transaction {
            id: "bond2".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::BondValidator { amount: 500_000, owner_identity_id: Some("qcb1alice".into()) },
            gas_limit: 50_000, signature: vec![], public_key: vec![],
            pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
        };
        let r2 = exec.execute_tx_with_identity(&bond2, &mut state, &mut identity, &mut agents, 0);
        assert!(!r2.success, "re-bond from Provisional owner must be rejected");
    }

    // Finding 1: revoke_attestation charm-sync: after tier downgrade the
    // on-chain account must reflect the new Provisional tier.
    #[test]
    fn revoke_attestation_syncs_charm_to_account_after_downgrade() {
        use chain_forge_identity::{PopAttestation, VerificationTier};

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let mut identity = chain_forge_identity::IdentityStore::new(0);
        let mut agents = AgentStore::new();
        let exec = Executor::new(config);

        // Register alice, bob, carol, dave all as Verified attesters.
        for name in ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att, None).unwrap();
            // Ensure each has an on-chain account with uqcb for fees.
            let mut acct = chain_forge_state::AccountState::new(name.into(), "user".into());
            acct.credit("uqcb", 100_000);
            state.upsert_account(acct);
        }

        // Register newbie as Provisional.
        {
            let att = PopAttestation::genesis("qcb1newbie", 0);
            identity.register("qcb1newbie".into(), "qcb1newbie".into(), att).unwrap();
            let mut acct = chain_forge_state::AccountState::new("qcb1newbie".into(), "user".into());
            acct.credit("uqcb", 100_000);
            state.upsert_account(acct);
        }

        // Attest newbie to Verified using 3 distinct attesters (ATTESTATION_QUORUM=3).
        // Each sender has its own nonce starting at 0.
        for (i, attester) in ["qcb1alice", "qcb1bob", "qcb1carol"].iter().enumerate() {
            let tx = Transaction {
                id: format!("att{i}"), sender: (*attester).into(), nonce: 0,
                body: TxBody::Attest { claimant_id: "qcb1newbie".into() },
                gas_limit: 50_000, signature: vec![], public_key: vec![],
                pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
            };
            let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
            assert!(r.success, "attest tx from {attester} must succeed: {:?}", r.error);
        }

        // Newbie should now be Verified.
        assert_eq!(
            *identity.get("qcb1newbie").unwrap().tier(),
            VerificationTier::Verified,
            "newbie must be Verified after 3 attestations"
        );

        // Advance epoch so the revoking attester is past the cooldown (epoch 0 → 2).
        identity.advance_epoch(1_000);
        identity.advance_epoch(2_000);

        // Alice revokes her attestation of newbie. With only 2 remaining
        // attesters (bob, carol) the quorum (3) is lost → tier_downgraded=true.
        // Alice's nonce: 1 (she sent attest at nonce 0 above).
        let revoke_tx = Transaction {
            id: "rev1".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::RevokeAttestation { attested_id: "qcb1newbie".into() },
            gas_limit: 50_000, signature: vec![], public_key: vec![],
            pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
        };
        let r_rev = exec.execute_tx_with_identity(&revoke_tx, &mut state, &mut identity, &mut agents, 0);
        assert!(r_rev.success, "revoke_attestation must succeed: {:?}", r_rev.error);

        // Identity store must show Provisional.
        assert_eq!(
            *identity.get("qcb1newbie").unwrap().tier(),
            VerificationTier::Provisional,
            "newbie identity tier must be Provisional after revocation-driven downgrade"
        );

        // On-chain account charm must also reflect Provisional — the sync cannot
        // have been skipped or silently failed.
        let acct = state.get_account("qcb1newbie").unwrap();
        assert_eq!(
            acct.verification_tier(),
            Some(&VerificationTier::Provisional),
            "on-chain account tier must match identity store tier after revocation downgrade"
        );
    }

    // Finding 3: ZK-VRC charm sync must be reflected in on-chain account.
    #[test]
    fn verify_identity_with_proof_syncs_charm_to_account() {
        use chain_forge_identity::VerificationTier;

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut config = ExecutionConfig::from_genesis(&genesis);
        config.pop_verifier = Some(std::sync::Arc::new(AlwaysOkVerifier));
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let mut identity = chain_forge_identity::IdentityStore::new(0);
        let mut agents = AgentStore::new();
        let exec = Executor::new(config);

        // Register bob as Provisional only.
        {
            use chain_forge_identity::PopAttestation;
            let att = PopAttestation::genesis("qcb1bob", 0);
            identity.register("qcb1bob".into(), "qcb1bob".into(), att).unwrap();
            let mut acct = chain_forge_state::AccountState::new("qcb1bob".into(), "user".into());
            acct.credit("uqcb", 100_000);
            state.upsert_account(acct);
        }

        let tx = Transaction {
            id: "vip1".into(), sender: "qcb1bob".into(), nonce: 0,
            body: TxBody::VerifyIdentityWithProof {
                proof_bytes: vec![1u8; 64],
                public_inputs_bytes: vec![2u8; 16],
            },
            gas_limit: 1_000_000, signature: vec![], public_key: vec![],
            pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "ZK-VRC upgrade must succeed: {:?}", r.error);

        // On-chain account must reflect Verified — charm sync must not have been skipped.
        let acct = state.get_account("qcb1bob").unwrap();
        assert_eq!(
            acct.verification_tier(),
            Some(&VerificationTier::Verified),
            "on-chain account must be Verified after ZK-VRC upgrade"
        );
    }

    // Atomicity check: after revoke_attestation the identity store is
    // always in a consistent state. The identity record mutation inside
    // revoke_attestation is eager; the important invariant is that on a
    // successful tx the identity tier, account charm, and Merkle leaf all
    // agree. This test verifies all three sources of truth are consistent
    // after a successful downgrade — the regression guard for the silent
    // charm-sync failure that was found in the review.
    #[test]
    fn revocation_three_state_sources_agree_after_downgrade() {
        use chain_forge_identity::{PopAttestation, VerificationTier};

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let mut identity = chain_forge_identity::IdentityStore::new(0);
        let mut agents = AgentStore::new();
        let exec = Executor::new(config);

        for name in ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1newbie"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            if name != "qcb1newbie" {
                identity.verify_identity(name, att, None).unwrap();
            }
            let mut acct = chain_forge_state::AccountState::new(name.into(), "user".into());
            acct.credit("uqcb", 100_000);
            state.upsert_account(acct);
        }

        // Attest newbie to Verified via alice, bob, carol.
        for (i, attester) in ["qcb1alice", "qcb1bob", "qcb1carol"].iter().enumerate() {
            let tx = Transaction {
                id: format!("att{i}"), sender: (*attester).into(), nonce: 0,
                body: TxBody::Attest { claimant_id: "qcb1newbie".into() },
                gas_limit: 50_000, signature: vec![], public_key: vec![],
                pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
            };
            assert!(exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0).success);
        }

        identity.advance_epoch(1_000);
        identity.advance_epoch(2_000);

        // Alice revokes → tier_downgraded=true (only 2 attesters remain).
        let revoke_tx = Transaction {
            id: "rev1".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::RevokeAttestation { attested_id: "qcb1newbie".into() },
            gas_limit: 50_000, signature: vec![], public_key: vec![],
            pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&revoke_tx, &mut state, &mut identity, &mut agents, 0);
        assert!(r.success, "revoke_attestation must succeed: {:?}", r.error);

        let identity_tier = identity.get("qcb1newbie").unwrap().charm.tier.clone();
        let account_tier  = state.get_account("qcb1newbie").unwrap().verification_tier().cloned();

        // Source 1: identity store.
        assert_eq!(identity_tier, VerificationTier::Provisional,
            "identity store must show Provisional after downgrade");
        // Source 2: on-chain account charm.
        assert_eq!(account_tier, Some(VerificationTier::Provisional),
            "account charm must match identity store after downgrade");
        // Sources 1 and 2 must agree (belt-and-suspenders).
        assert_eq!(Some(identity_tier), account_tier,
            "identity store and account charm must be consistent after downgrade");
    }

    // Atomicity gap test: revoke_attestation with missing account.
    //
    // This test deliberately omits newbie's StateStore account so that
    // get_account_mut() fails during the charm-sync step. It records what
    // actually happens to the identity record, attestation record, and
    // account state so the behaviour is explicit and observable in CI,
    // regardless of whether atomicity is guaranteed.
    //
    // The #[should_panic] attribute is NOT set here — the assertions document
    // the observed invariants. If a future commit introduces a rollback the
    // assertions should be updated to reflect the stronger guarantee.
    #[test]
    fn revoke_attestation_missing_account_documents_atomicity_behaviour() {
        use chain_forge_identity::{PopAttestation, VerificationTier};

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();
        let mut identity = chain_forge_identity::IdentityStore::new(0);
        let mut agents = AgentStore::new();
        let exec = Executor::new(config);

        // Register alice, bob, carol as Verified attesters (with accounts).
        for name in ["qcb1alice", "qcb1bob", "qcb1carol"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att, None).unwrap();
            let mut acct = chain_forge_state::AccountState::new(name.into(), "user".into());
            acct.credit("uqcb", 100_000);
            state.upsert_account(acct);
        }

        // Register newbie in IdentityStore but deliberately omit their
        // StateStore account — this is the partial-state scenario.
        {
            let att = PopAttestation::genesis("qcb1newbie", 0);
            identity.register("qcb1newbie".into(), "qcb1newbie".into(), att).unwrap();
            // No state.upsert_account for newbie.
        }

        // Attest newbie to Verified via three attesters.
        for (i, attester) in ["qcb1alice", "qcb1bob", "qcb1carol"].iter().enumerate() {
            let tx = Transaction {
                id: format!("att{i}"), sender: (*attester).into(), nonce: 0,
                body: TxBody::Attest { claimant_id: "qcb1newbie".into() },
                gas_limit: 50_000, signature: vec![], public_key: vec![],
                pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
            };
            assert!(exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0).success);
        }
        assert_eq!(*identity.get("qcb1newbie").unwrap().tier(), VerificationTier::Verified);

        identity.advance_epoch(1_000);
        identity.advance_epoch(2_000);

        // Snapshot pre-revocation state.
        let pre_attestation_count = identity
            .get("qcb1newbie").unwrap()
            .attestation_ledger.count();

        // Alice revokes → tier_downgraded=true. Newbie has no account, so
        // get_account_mut() will fail during charm-sync.
        let revoke_tx = Transaction {
            id: "rev1".into(), sender: "qcb1alice".into(), nonce: 1,
            body: TxBody::RevokeAttestation { attested_id: "qcb1newbie".into() },
            gas_limit: 50_000, signature: vec![], public_key: vec![],
            pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
        };
        let r = exec.execute_tx_with_identity(&revoke_tx, &mut state, &mut identity, &mut agents, 0);

        // The transaction MUST fail — the pre-flight check rejects the tx before
        // calling revoke_attestation(), so no identity mutation occurs.
        assert!(!r.success,
            "revoke_attestation must be rejected when the attested account is absent from StateStore");
        let err = r.error.unwrap_or_default();
        assert!(err.contains("state invariant violated") || err.contains("no on-chain account"),
            "error must name the invariant violation; got: {err}");

        // ATOMICITY INVARIANTS — the pre-flight fix guarantees these hold:

        // The identity tier must be UNCHANGED (still Verified) — the pre-flight
        // rejected the tx before revoke_attestation() was called.
        let post_tier = identity.get("qcb1newbie").unwrap().charm.tier.clone();
        assert_eq!(post_tier, VerificationTier::Verified,
            "identity tier must remain Verified after a pre-flight-rejected tx; \
             if this fails, revoke_attestation() was called before the pre-flight");

        // The attestation ledger count must be UNCHANGED (still 3).
        let post_count = identity.get("qcb1newbie").unwrap().attestation_ledger.count();
        assert_eq!(post_count, pre_attestation_count,
            "attestation ledger must be unchanged after a rejected tx");

        // The account must still not exist (we never created it — and no mutation
        // should have created it as a side effect).
        assert!(state.get_account("qcb1newbie").is_err(),
            "no account must exist for an identity that was never given one");
    }

    // ── FS-03 accounting acceptance tests ─────────────────────────────────────
    //
    // These tests verify the seven invariants identified in the FS-03 acceptance
    // review (2026-10-24):
    //   1. Fund conservation: validator + treasury + burn == fee charged (no dust lost)
    //   2. Remainder rule: integer-division dust accrues to treasury, not validators
    //   3. Double settlement: replaying distribute_block_fees with the same
    //      fees_collected value a second time cannot double-distribute
    //   4. Failed-tx fee: a tx that fails execution still charges a fee
    //   5. Supply accounting: burn reduces supply exactly once
    //   6. Zero-fee block: distribute_block_fees is a no-op when fees_collected == 0
    //   7. Custom split validated: genesis bps values that don't sum to 10 000
    //      are rejected

    fn seed_fee_collector(state: &mut StateStore, denom: &str, amount: u64) {
        if state.get_account("treasury:fees").is_err() {
            let a = chain_forge_state::AccountState::new(
                "treasury:fees".to_string(), "treasury".to_string());
            state.upsert_account(a);
        }
        if let Ok(a) = state.get_account_mut("treasury:fees") {
            a.credit(denom, amount as u128);
        }
        state.refresh_leaf("treasury:fees");
    }

    fn balance(state: &StateStore, addr: &str, denom: &str) -> u128 {
        state.get_account(addr).map(|a| a.balance_of(denom)).unwrap_or(0)
    }

    #[test]
    fn fs03_fee_split_conservation() {
        // validator_share + treasury_share + burn_share must equal the input amount
        // for a range of values including dust-producing amounts.
        let dist = FeeDistribution::default(); // 7000 / 2000 / 1000
        for amount in [0u64, 1, 9, 10, 99, 100, 1_000_001, 9_999_999, u64::MAX / 10_000] {
            let (v, t, b) = dist.split(amount);
            assert_eq!(v + t + b, amount,
                "conservation failed for amount={amount}: v={v} t={t} b={b}");
        }
    }

    #[test]
    fn fs03_remainder_goes_to_treasury() {
        // With 7000/2000/1000 bps on amount=9 (not divisible by 10_000):
        //   validator floor = 9 * 7000 / 10_000 = 6
        //   treasury  floor = 9 * 2000 / 10_000 = 1
        //   burn      floor = 9 * 1000 / 10_000 = 0
        //   sum = 7, remainder = 2  → treasury should get remainder
        let dist = FeeDistribution::default();
        let (v, t, b) = dist.split(9);
        assert_eq!(v, 6, "validator share");
        assert_eq!(t, 3, "treasury share (includes remainder of 2)");
        assert_eq!(b, 0, "burn share");
        assert_eq!(v + t + b, 9, "conservation");
    }

    #[test]
    fn fs03_distribute_block_fees_moves_correct_amounts() {
        let (_, mut state) = setup();
        let denom = "uqcb";
        let fees: u64 = 10_000;

        seed_fee_collector(&mut state, denom, fees as u64 + 50_000); // extra to test no-over-drain

        let dist = FeeDistribution::default();
        let result = distribute_block_fees(fees, &dist, denom, &mut state);

        assert_eq!(result.fees_total, fees);
        assert_eq!(result.validator_share + result.treasury_share + result.burn_share, fees,
            "settlement result must sum to fees_collected");

        // treasury:validator-pool got validator share
        assert_eq!(balance(&state, "treasury:validator-pool", denom), result.validator_share as u128);
        // treasury:network got treasury share
        assert_eq!(balance(&state, "treasury:network", denom), result.treasury_share as u128);
        // treasury:fees was debited fees (not all of its balance)
        let remaining_in_collector = balance(&state, "treasury:fees", denom);
        assert_eq!(remaining_in_collector, 50_000,
            "only fees_collected must leave treasury:fees, not its entire balance");
    }

    #[test]
    fn fs03_double_settlement_prevention() {
        // Calling distribute_block_fees twice with the same fees_collected value
        // should move an equal amount AGAIN from treasury:fees — but only if that
        // amount is still present.  When it is not (because the block already
        // settled), the transfer fails gracefully and does NOT double-credit.
        let (_, mut state) = setup();
        let denom = "uqcb";
        let fees: u64 = 1_000;

        // Seed exactly `fees` — simulates a block that collected exactly this amount.
        seed_fee_collector(&mut state, denom, fees);

        let dist = FeeDistribution::default();
        let r1 = distribute_block_fees(fees, &dist, denom, &mut state);
        assert_eq!(r1.fees_total, fees);

        // Second call with same fees_collected: treasury:fees is now empty (or
        // the burn share may have made it slightly under).  The function must not
        // panic and must not double-credit the pools.
        let pool_after_first = balance(&state, "treasury:validator-pool", denom);
        let net_after_first  = balance(&state, "treasury:network", denom);

        let _r2 = distribute_block_fees(fees, &dist, denom, &mut state);

        // Pools must NOT have grown again (second call finds no balance to drain).
        assert_eq!(balance(&state, "treasury:validator-pool", denom), pool_after_first,
            "validator-pool must not grow on second distribute call");
        assert_eq!(balance(&state, "treasury:network", denom), net_after_first,
            "treasury:network must not grow on second distribute call");
    }

    #[test]
    fn fs03_zero_fee_block_is_noop() {
        let (_, mut state) = setup();
        let denom = "uqcb";

        seed_fee_collector(&mut state, denom, 5_000);
        let dist = FeeDistribution::default();
        let result = distribute_block_fees(0, &dist, denom, &mut state);

        assert_eq!(result.fees_total,      0);
        assert_eq!(result.validator_share, 0);
        assert_eq!(result.treasury_share,  0);
        assert_eq!(result.burn_share,      0);

        // Nothing should have moved from the fee collector.
        assert_eq!(balance(&state, "treasury:fees", denom), 5_000);
        assert_eq!(balance(&state, "treasury:validator-pool", denom), 0);
        assert_eq!(balance(&state, "treasury:network", denom), 0);
    }

    #[test]
    fn fs03_failed_tx_still_charges_fee() {
        // A transfer that fails (insufficient balance for the transfer amount)
        // must still charge the gas fee — the sender loses the fee even if the
        // business logic is rolled back.
        let (exec, mut state) = setup();
        let alice_start = balance(&state, "qcb1alice", "uqcb");

        // Amount exceeds Alice's balance; transfer will fail.
        let tx = Transaction::transfer("tx-fail", "qcb1alice", "qcb1bob", "uqcb", alice_start * 2, 0);
        let fee = gas_for(&exec, &tx);
        let result = exec.execute_tx(&tx, &mut state, 0);

        assert!(!result.success, "transfer must fail when amount exceeds balance");

        let alice_after = balance(&state, "qcb1alice", "uqcb");
        // Alice should have paid the fee even though the transfer failed.
        assert_eq!(alice_after, alice_start - fee,
            "fee must be charged even on a failed tx (got alice={alice_after}, expected {})",
            alice_start - fee);
    }

    #[test]
    fn fs03_burn_reduces_supply_exactly_once() {
        // StateStore::burn() is the mechanism for the burn share.  Verify that
        // burning N tokens from an account exactly reduces that account's balance
        // by N and does not silently succeed on an empty account.
        let (_, mut state) = setup();
        let denom = "uqcb";

        seed_fee_collector(&mut state, denom, 1_000);
        let before = balance(&state, "treasury:fees", denom);
        let burn_amount: u128 = 100;

        let ok = state.burn("treasury:fees", denom, burn_amount);
        assert!(ok.is_ok(), "burn must succeed when funds are available: {ok:?}");
        let after = balance(&state, "treasury:fees", denom);
        assert_eq!(after, before - burn_amount, "burn must reduce balance by exactly the burn amount");

        // Burning more than available must fail — no partial burn, no overdraft.
        let over = state.burn("treasury:fees", denom, after + 1);
        assert!(over.is_err(), "burn must fail when amount exceeds balance");
        assert_eq!(balance(&state, "treasury:fees", denom), after,
            "balance must be unchanged after a failed burn");
    }

    #[test]
    fn fs03_custom_split_sum_validation() {
        // A genesis bps config that does not sum to 10 000 must be rejected.
        // We inject the bps into a genesis JSON string to exercise from_genesis().
        let bad_genesis = r#"{
            "chain_id": "qcb-testnet-fee", "chain_name": "Test", "engine_version": "0.1.0",
            "genesis_time": "2026-01-01T00:00:00Z",
            "environment": { "mode": "testnet", "faucet_enabled": false, "relaxed_limits": false },
            "native_token": { "name": "Q", "symbol": "QCB", "denom": "uqcb", "max_supply": "1000000" },
            "address_prefix": "qcb",
            "consensus": { "type": "proof-of-stake", "validator_set_size": 4, "block_time_ms": 5000 },
            "execution": {
                "state_model": "account", "parallel_execution": false,
                "gas_model": "dynamic", "require_signatures": false,
                "fee_distribution_bps": { "validator_bps": 7000, "treasury_bps": 2000, "burn_bps": 500 }
            },
            "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
            "network": { "network_id": "n1", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "both", "max_peers": 50 },
            "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 5000, "mempool_ttl_seconds": 300 },
            "modules": [], "custom_modules": [], "genesis_accounts": []
        }"#;
        let genesis = GenesisConfig::from_json(bad_genesis).unwrap();
        let result = FeeDistribution::from_genesis(&genesis);
        assert!(result.is_err(),
            "bps summing to 9500 must be rejected, got: {result:?}");

        // Valid custom split: 6000/3000/1000.
        let good_genesis = bad_genesis.replace(
            r#""fee_distribution_bps": { "validator_bps": 7000, "treasury_bps": 2000, "burn_bps": 500 }"#,
            r#""fee_distribution_bps": { "validator_bps": 6000, "treasury_bps": 3000, "burn_bps": 1000 }"#,
        );
        let genesis2 = GenesisConfig::from_json(&good_genesis).unwrap();
        let dist = FeeDistribution::from_genesis(&genesis2).expect("valid bps must be accepted");
        let (v, t, b) = dist.split(10_000);
        // 6000/3000/1000 on 10_000 → exact, no remainder
        assert_eq!((v, t, b), (6_000, 3_000, 1_000), "6000/3000/1000 split");
        assert_eq!(v + t + b, 10_000, "conservation");
    }

    // -- H0-5 execution atomicity / H0-7 fee conservation -------------------------
    //
    // Invariant 1 (included-but-failed): a tx that passes admission and is
    // included but fails during execution pays the fee, consumes its nonce
    // exactly once, and changes nothing else.
    // Invariant 2 (rejected): a tx rejected at admission changes nothing, uses
    // no block gas, and contributes zero to fees.
    // Invariant 3 (fee conservation, per block): fees debited == fees_collected
    // == validator share + treasury share + burned share.
    // Supply: S_after = S_before + I - B (no issuance in these blocks, so I = 0).

    mod h0_atomicity_fee_conservation {
        use super::*;

        const POOL: &str = "treasury:validator-pool";
        const NETWORK: &str = "treasury:network";
        const FEES: &str = "treasury:fees";
        /// Pre-existing balance in the fee collector, so that paying out fees
        /// nobody paid would be visible instead of silently failing.
        const FEE_RESERVE: u128 = 1_000_000;

        fn bal(state: &StateStore, addr: &str) -> u128 {
            state.get_account(addr).map(|a| a.balance_of("uqcb")).unwrap_or(0)
        }

        fn nonce(state: &StateStore, addr: &str) -> u64 {
            state.get_account(addr).map(|a| a.nonce).unwrap_or(0)
        }

        fn supply(state: &StateStore) -> u128 {
            state.all_accounts().map(|a| a.balance_of("uqcb")).sum()
        }

        fn fund_fee_reserve(state: &mut StateStore) {
            let mut acct = chain_forge_state::AccountState::new(FEES.into(), "treasury".into());
            acct.credit("uqcb", FEE_RESERVE);
            state.upsert_account(acct);
        }

        // -- Invariant 1: included-but-failed ---------------------------------

        #[test]
        fn failed_transfer_charges_fee_and_consumes_nonce_exactly_once() {
            let (exec, mut state) = setup();
            let alice0 = bal(&state, "qcb1alice");
            let bob0 = bal(&state, "qcb1bob");
            let tx = Transaction::transfer("fail1", "qcb1alice", "qcb1bob", "uqcb", 999_000_000, 0);
            let fee = gas_for(&exec, &tx);

            let r = exec.execute_tx(&tx, &mut state, 0);
            assert!(!r.success);
            assert_eq!(bal(&state, "qcb1alice"), alice0 - fee, "fee charged once");
            assert_eq!(bal(&state, "qcb1bob"), bob0, "no credit from a failed transfer");
            assert_eq!(nonce(&state, "qcb1alice"), 1, "included-but-failed tx consumes its nonce");

            // The same signed tx must not be includable again.
            let replay = exec.execute_tx(&tx, &mut state, 0);
            assert!(!replay.success);
            assert!(replay.error.as_deref().unwrap_or("").contains("nonce"), "{:?}", replay.error);
            assert_eq!(bal(&state, "qcb1alice"), alice0 - fee, "a replay must not charge again");
            assert_eq!(nonce(&state, "qcb1alice"), 1);
        }

        #[test]
        fn failed_transfer_identity_path_charges_fee_and_consumes_nonce_once() {
            let (exec, mut state, mut identity, mut agents) = setup_with_identity();
            let alice0 = bal(&state, "qcb1alice");
            let tx = Transaction::transfer("fail1", "qcb1alice", "qcb1bob", "uqcb", 999_000_000, 0);
            let fee = gas_for(&exec, &tx);

            let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
            assert!(!r.success);
            assert_eq!(bal(&state, "qcb1alice"), alice0 - fee);
            assert_eq!(nonce(&state, "qcb1alice"), 1);

            let replay = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
            assert!(!replay.success);
            assert_eq!(bal(&state, "qcb1alice"), alice0 - fee, "a replay must not charge again");
        }

        /// Handlers that bail out with an early `return` from inside the body
        /// (after the fee is charged) must follow the same rule.
        #[test]
        fn body_early_return_failure_consumes_nonce() {
            let (exec, mut state, mut identity, mut agents) = setup_with_identity();
            let tx = Transaction {
                id: "spawn-orphan".into(), sender: "qcb1alice".into(), nonce: 0,
                body: TxBody::SpawnChildAgent {
                    child_agent_id: "child".into(),
                    child_agent_address: "qcb1child".into(),
                    parent_agent_id: "no-such-parent".into(),
                    capabilities: vec![],
                    spending_limits: SpendingLimits::unlimited(),
                    description: "orphan".into(),
                },
                gas_limit: 1_000_000, signature: vec![], public_key: vec![],
                pq_signatures: vec![], sig_scheme: None, pq_public_key: vec![],
            };
            let alice0 = bal(&state, "qcb1alice");
            let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
            assert!(!r.success);
            assert!(r.error.as_deref().unwrap_or("").contains("parent agent"), "{:?}", r.error);
            assert_eq!(bal(&state, "qcb1alice"), alice0 - gas_for(&exec, &tx));
            assert_eq!(nonce(&state, "qcb1alice"), 1, "early-return failure must consume the nonce");
        }

        /// A human account's failed transfer must not change anything but the
        /// fee and nonce. The Transfer handler records a decay-exemption spend
        /// before attempting the transfer, so this needs a real rollback.
        #[test]
        fn failed_transfer_leaves_no_partial_account_mutation() {
            let (exec, mut state, mut identity, mut agents) = setup_with_identity();
            let mut alice = chain_forge_state::AccountState::new_human("qcb1alice".into(), "user".into(), 0);
            alice.credit("uqcb", 5_000_000);
            state.upsert_account(alice);
            identity.clock.current_epoch = 7;

            let charm_before = format!("{:?}", state.get_account("qcb1alice").unwrap().charm);
            let tx = Transaction::transfer("fail1", "qcb1alice", "qcb1bob", "uqcb", 999_000_000, 0);
            let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut agents, 0);
            assert!(!r.success);
            assert_eq!(format!("{:?}", state.get_account("qcb1alice").unwrap().charm), charm_before,
                "a failed transfer must not record a decay-exemption spend");
        }

        // -- Invariant 2: rejected --------------------------------------------

        fn bad_nonce_txs() -> Vec<Transaction> {
            (0..5).map(|i| Transaction::transfer(&format!("bad{i}"), "qcb1alice", "qcb1bob", "uqcb", 1, 77)).collect()
        }

        fn assert_rejected_block_changes_nothing(r: &BlockExecutionResult, before: &[(String, u128)], state: &StateStore, supply0: u128) {
            assert_eq!(r.fees_collected, 0, "rejected txs pay no fees");
            assert_eq!(r.gas_used, 0, "rejected txs use no block gas");
            assert!(r.tx_results.iter().all(|t| !t.success && t.gas_used == 0));
            for (addr, b) in before {
                assert_eq!(bal(state, addr), *b, "{addr} balance changed by a block of rejected txs");
            }
            assert_eq!(supply(state), supply0, "supply changed by a block of rejected txs");
            assert_eq!(nonce(state, "qcb1alice"), 0);
        }

        #[test]
        fn rejected_txs_pay_no_fees_and_move_no_treasury_funds() {
            let (exec, mut state) = setup();
            fund_fee_reserve(&mut state);
            let watch: Vec<String> = ["qcb1alice", FEES, POOL, NETWORK].iter().map(|s| s.to_string()).collect();
            let before: Vec<(String, u128)> = watch.iter().map(|a| (a.clone(), bal(&state, a))).collect();
            let supply0 = supply(&state);
            let r = exec.execute_block(1, bad_nonce_txs(), &mut state, 1_000);
            assert_rejected_block_changes_nothing(&r, &before, &state, supply0);
        }

        #[test]
        fn rejected_txs_pay_no_fees_identity_path() {
            let (exec, mut state, mut identity, mut agents) = setup_with_identity();
            fund_fee_reserve(&mut state);
            let watch: Vec<String> = ["qcb1alice", FEES, POOL, NETWORK].iter().map(|s| s.to_string()).collect();
            let before: Vec<(String, u128)> = watch.iter().map(|a| (a.clone(), bal(&state, a))).collect();
            let supply0 = supply(&state);
            let r = exec.execute_block_with_identity(
                1, bad_nonce_txs(), &mut state, &mut identity, &mut agents, 1_000, None);
            assert_rejected_block_changes_nothing(&r, &before, &state, supply0);
        }

        // -- Invariant 3: fee conservation + supply ---------------------------

        /// ok transfer, failed transfer, rejected tx, ok burn, ok transfer.
        fn mixed_block(exec: &Executor) -> (Vec<Transaction>, u128, u128) {
            let txs = vec![
                Transaction::transfer("ok1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0),
                Transaction::transfer("fail1", "qcb1alice", "qcb1bob", "uqcb", 999_000_000, 1),
                Transaction::transfer("rej1", "qcb1bob", "qcb1alice", "uqcb", 5, 9),
                Transaction::burn("burn1", "qcb1alice", "uqcb", 500, 2),
                Transaction::transfer("ok2", "qcb1bob", "qcb1val", "uqcb", 10, 0),
            ];
            let included: u128 = txs.iter().filter(|t| t.id != "rej1").map(|t| gas_for(exec, t)).sum();
            (txs, included, 500)
        }

        fn assert_conservation(r: &BlockExecutionResult, state: &StateStore, expected_fees: u128,
                               burned_by_txs: u128, supply0: u128, pool0: u128, net0: u128) {
            assert_eq!(r.fees_collected as u128, expected_fees,
                "fees_collected must equal fees actually debited from included txs");
            let to_pool = bal(state, POOL) - pool0;
            let to_net = bal(state, NETWORK) - net0;
            assert_eq!(bal(state, FEES), FEE_RESERVE, "collector must pass on exactly this block's fees");
            let fee_burn = expected_fees - to_pool - to_net;
            assert_eq!(supply(state), supply0 - burned_by_txs - fee_burn,
                "S_after = S_before - burns (no issuance)");
            assert_eq!(to_pool + to_net + fee_burn, expected_fees, "debited == collected == distributed");
            assert!(to_pool > 0 && fee_burn > 0, "fees were actually distributed");
        }

        #[test]
        fn block_fees_conserved_and_supply_follows_burns() {
            let (exec, mut state) = setup();
            fund_fee_reserve(&mut state);
            let (txs, expected, burned) = mixed_block(&exec);
            let (supply0, pool0, net0) = (supply(&state), bal(&state, POOL), bal(&state, NETWORK));
            let r = exec.execute_block(1, txs, &mut state, 1_000);
            assert_conservation(&r, &state, expected, burned, supply0, pool0, net0);
        }

        #[test]
        fn block_fees_conserved_identity_path() {
            let (exec, mut state, mut identity, mut agents) = setup_with_identity();
            fund_fee_reserve(&mut state);
            let (txs, expected, burned) = mixed_block(&exec);
            let (supply0, pool0, net0) = (supply(&state), bal(&state, POOL), bal(&state, NETWORK));
            let r = exec.execute_block_with_identity(1, txs, &mut state, &mut identity, &mut agents, 1_000, None);
            assert_conservation(&r, &state, expected, burned, supply0, pool0, net0);
        }

        /// The state root a block reports must include its fee distribution.
        #[test]
        fn reported_state_root_includes_fee_distribution() {
            let (exec, mut state) = setup();
            let txs = vec![Transaction::transfer("ok1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0)];
            let r = exec.execute_block(1, txs, &mut state, 1_000);
            assert!(r.fees_collected > 0);
            assert_eq!(Some(r.state_root.as_str()), state.current_root(),
                "execute_block must commit after distributing fees");
        }

        /// Two independent nodes executing the same adversarial block agree.
        #[test]
        fn independent_executions_of_adversarial_block_agree() {
            let run = || {
                let (exec, mut state, mut identity, mut agents) = setup_with_identity();
                fund_fee_reserve(&mut state);
                let (txs, _, _) = mixed_block(&exec);
                let r = exec.execute_block_with_identity(1, txs, &mut state, &mut identity, &mut agents, 1_000, None);
                (r.state_root, r.fees_collected,
                 r.tx_results.iter().map(|t| (t.success, t.gas_used)).collect::<Vec<_>>())
            };
            assert_eq!(run(), run());
        }
    }

    // -- DIS-003 recovery security: replay binding and unauthenticated fee drain --

    mod dis003_recovery_security {
        use super::*;
        use chain_forge_crypto::MlDsaScheme;

        const VICTIM: &str = "qcb1alice";

        fn mldsa(seed: &str) -> KeyPair {
            MlDsaScheme.generate_keypair(seed).expect("ML-DSA keygen")
        }

        fn unsigned(id: &str, sender: &str, nonce: u64, body: TxBody) -> Transaction {
            Transaction {
                id: id.into(), sender: sender.into(), nonce, body,
                gas_limit: 5_000_000,
                signature: vec![], public_key: vec![], pq_signatures: vec![],
                sig_scheme: Some(SchemeId::MlDsa), pq_public_key: vec![],
            }
        }

        fn enroll(exec: &Executor, state: &mut StateStore, id: &str, nonce: u64, guardians: &[&KeyPair]) {
            let body = TxBody::EnrollRecoveryPolicy {
                guardians: guardians.iter().map(|g| g.public_key.clone()).collect(),
                threshold: guardians.len() as u32,
            };
            let r = exec.execute_tx(&unsigned(id, VICTIM, nonce, body), state, 1);
            assert!(r.success, "enroll {id}: {:?}", r.error);
        }

        /// Guardian authorizations exactly as a guardian would produce them
        /// for the policy generation that was active when they signed.
        fn guardian_auths(exec: &Executor, key_version: u32, new_kp: &KeyPair,
                          policy_id: u64, guardians: &[&KeyPair]) -> Vec<GuardianAuth> {
            let msg = recovery_domain_signing_bytes(
                &exec.config.chain_id, VICTIM, key_version, &new_kp.public_key, policy_id, None);
            guardians.iter().map(|g| GuardianAuth {
                guardian_public_key: g.public_key.clone(),
                signature: MlDsaScheme.sign(&msg, g).unwrap().bytes,
                expires_at_height: None,
            }).collect()
        }

        fn recover_tx(exec: &Executor, id: &str, nonce: u64, key_version: u32, new_kp: &KeyPair,
                      policy_id: u64, auths: Vec<GuardianAuth>) -> Transaction {
            let pop_msg = account_key_rotation_signing_bytes(
                &exec.config.chain_id, VICTIM, key_version, &new_kp.public_key);
            let body = TxBody::RecoverAccountKey {
                new_public_key: new_kp.public_key.clone(),
                new_key_scheme: "ml-dsa-65".into(),
                key_version,
                pop_signature: MlDsaScheme.sign(&pop_msg, new_kp).unwrap().bytes,
                guardian_signatures: auths,
                policy_id,
            };
            unsigned(id, VICTIM, nonce, body)
        }

        /// Guardian signatures collected while policy generation 1 was active
        /// must not authorize recovery after the owner revokes and re-enrolls,
        /// even when the new policy keeps the same guardians.
        #[test]
        fn guardian_signatures_do_not_replay_across_policy_generations() {
            let (exec, mut state) = setup();
            let (g1, g2) = (mldsa("dis003-sec-g1"), mldsa("dis003-sec-g2"));
            let attacker = mldsa("dis003-sec-attacker");

            enroll(&exec, &mut state, "enroll1", 0, &[&g1, &g2]);
            let stockpiled = guardian_auths(&exec, 1, &attacker, 1, &[&g1, &g2]);

            let r = exec.execute_tx(&unsigned("revoke", VICTIM, 1, TxBody::RevokeRecoveryPolicy), &mut state, 2);
            assert!(r.success, "revoke: {:?}", r.error);
            enroll(&exec, &mut state, "enroll2", 2, &[&g1, &g2]);
            let current = state.get_account(VICTIM).unwrap().recovery_policy.clone().unwrap().policy_id;
            assert_eq!(current, 2);

            // The submitter copies the current policy_id into the tx field.
            let replay = recover_tx(&exec, "replay", 3, 1, &attacker, current, stockpiled);
            let r = exec.execute_tx(&replay, &mut state, 3);
            assert!(!r.success, "generation-1 guardian signatures must not authorize recovery under generation 2");
            assert_eq!(state.get_account(VICTIM).unwrap().key_version, 0, "key must not be replaced");

            // Control: fresh signatures for the current generation still work.
            let fresh = guardian_auths(&exec, 1, &attacker, current, &[&g1, &g2]);
            let ok = recover_tx(&exec, "fresh", 3, 1, &attacker, current, fresh);
            let r = exec.execute_tx(&ok, &mut state, 3);
            assert!(r.success, "fresh generation-2 recovery should succeed: {:?}", r.error);
        }

        /// A policy loaded from pre-DIS-003 state has policy_id 0. Signatures
        /// made for it must stop working once the owner re-enrolls.
        #[test]
        fn legacy_policy_signatures_do_not_replay_after_reenrollment() {
            let (exec, mut state) = setup();
            let (g1, g2) = (mldsa("dis003-legacy-g1"), mldsa("dis003-legacy-g2"));
            let attacker = mldsa("dis003-legacy-attacker");

            enroll(&exec, &mut state, "enroll1", 0, &[&g1, &g2]);
            // Simulate state loaded from a pre-DIS-003 snapshot.
            {
                let acct = state.get_account_mut(VICTIM).unwrap();
                acct.policy_generation = 0;
                acct.recovery_policy.as_mut().unwrap().policy_id = 0;
            }
            state.refresh_leaf(VICTIM);
            let stockpiled = guardian_auths(&exec, 1, &attacker, 0, &[&g1, &g2]);

            enroll(&exec, &mut state, "enroll2", 1, &[&g1, &g2]);
            let current = state.get_account(VICTIM).unwrap().recovery_policy.clone().unwrap().policy_id;
            assert_eq!(current, 1, "re-enrollment after legacy load starts a fresh generation");

            let replay = recover_tx(&exec, "replay", 2, 1, &attacker, current, stockpiled.clone());
            assert!(!exec.execute_tx(&replay, &mut state, 2).success,
                "legacy-policy signatures must not authorize recovery under the new generation");
            let replay0 = recover_tx(&exec, "replay0", 2, 1, &attacker, 0, stockpiled);
            assert!(!exec.execute_tx(&replay0, &mut state, 2).success,
                "a tx claiming the legacy policy_id must be rejected once it is superseded");
            assert_eq!(state.get_account(VICTIM).unwrap().key_version, 0);
        }

        /// RecoverAccountKey skips account-key authorization by design (the
        /// owner has lost the key), so guardian authorization IS its
        /// authorization. A recovery attempt with no valid guardian
        /// authorization is an unauthorized tx: it must cost the named
        /// account nothing, no matter how often a third party submits it.
        #[test]
        fn unauthorized_recovery_attempt_cannot_drain_account_fees() {
            for with_policy in [false, true] {
                let (exec, mut state) = setup();
                let mut nonce = 0;
                if with_policy {
                    let (g1, g2) = (mldsa("dis003-drain-g1"), mldsa("dis003-drain-g2"));
                    enroll(&exec, &mut state, "enroll", 0, &[&g1, &g2]);
                    nonce = 1;
                }
                let before = state.get_account(VICTIM).unwrap().clone();
                let junk_key = mldsa("dis003-drain-junk");

                for i in 0..5 {
                    let junk = recover_tx(&exec, &format!("junk{i}"), nonce, 1, &junk_key,
                        if with_policy { 1 } else { 0 }, vec![]);
                    let r = exec.execute_tx(&junk, &mut state, 10 + i);
                    assert!(!r.success, "junk recovery must fail");
                }

                let after = state.get_account(VICTIM).unwrap();
                assert_eq!(after.balance_of("uqcb"), before.balance_of("uqcb"),
                    "with_policy={with_policy}: unauthorized recovery attempts must not charge the account");
                assert_eq!(after.nonce, before.nonce,
                    "with_policy={with_policy}: unauthorized recovery attempts must not consume the account nonce");
            }
        }
    }
}
