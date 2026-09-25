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
///   - Section 6.2 ($CIRFI transfers, demurrage)
///   - Section 6.3 ($QCB burns via BME)
///   - Section 6.6 (gas fees -> staking yield)
///   - Section 8 (merchant payment flow)

use serde::{Deserialize, Serialize};
use chain_forge_core::{Address, EnabledModules, GenesisConfig, HashWidth};
use chain_forge_crypto::{ClassicalScheme, KeyPair, SchemeId, Signature, SignatureScheme};
use chain_forge_state::{StateStore, StateError};
use chain_forge_identity::IdentityStore;
use chain_forge_cirfi::CirfiEngine;

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
    /// Used by Charm Confinement, Intrinsic Charm, Charmed Agents, CirFi.
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
    /// Claim UBI for a verified identity (Section 6.2 / Charm Confinement 5.1).
    /// Enforces: one claim per epoch, verified tier, liveness.
    /// The sender must be the identity owner.
    ClaimUbi {
        identity_id: String,
    },
    /// Proactive redirect of $CIRFI balance to the UBI pool (Section 6.3 / Q25).
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
}

/// Advance the sender's nonce after a successful transaction, for the tx
/// types whose handlers don't already do it.
///
/// Transfer, Burn and Stake advance the nonce inside StateStore::transfer /
/// StateStore::burn, and ClaimUbi / RedirectToUbiPool advance it inside the
/// CirfiEngine calls they make. Every other body type previously advanced
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
        TxBody::RegisterIdentity | TxBody::Attest { .. } => Some("identity"),
        TxBody::ClaimUbi { .. } | TxBody::RedirectToUbiPool { .. } => Some("cirfi"),
        TxBody::SponsorAgent { .. } | TxBody::RevokeAgent { .. } => Some("agents"),
    }
}

/// Reject a transaction whose module this chain doesn't run. Stateless, so
/// the HTTP API applies it at submission as well as the executor.
pub fn module_check(tx: &Transaction, modules: &EnabledModules) -> Result<(), String> {
    let Some(name) = required_module(&tx.body) else { return Ok(()) };
    let on = match name {
        "staking"  => modules.staking,
        "identity" => modules.identity,
        "cirfi"    => modules.cirfi,
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
/// optional IdentityStore and CirfiEngine references.
pub struct Executor {
    config: ExecutionConfig,
}

impl Executor {
    pub fn new(config: ExecutionConfig) -> Self {
        Self { config }
    }

    /// Execute a single transaction with CharmConfinement enforcement.
    /// Requires identity store and CirFi engine for identity-gated tx types.
    pub fn execute_tx_with_identity(
        &self,
        tx:       &Transaction,
        state:    &mut StateStore,
        identity: &mut IdentityStore,
        cirfi:    &mut CirfiEngine,
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
                state.transfer(&tx.sender, to, denom, *amount)
                    .map(|_| events.push(format!("transfer: {} {} -> {}", amount, denom, to)))
                    .map_err(|e| e.to_string())
            }

            TxBody::Burn { denom, amount } => {
                state.burn(&tx.sender, denom, *amount)
                    .map(|_| events.push(format!("burn: {} {} (BME)", amount, denom)))
                    .map_err(|e| e.to_string())
            }

            TxBody::Stake { validator, amount } => {
                state.transfer(&tx.sender, validator, &self.config.native_denom, *amount)
                    .map(|_| events.push(format!("stake: {} -> {}", amount, validator)))
                    .map_err(|e| e.to_string())
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
                match state.get_account_mut(&tx.sender) {
                    Ok(account) => {
                        cirfi.distribute_ubi(identity_id, account, identity)
                            .map(|amount| {
                                events.push(format!(
                                    "ubi_claim: {} ucirfi -> {} (identity: {})",
                                    amount, tx.sender, identity_id
                                ));
                            })
                            .map_err(|e| e.to_string())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }

            TxBody::RedirectToUbiPool { amount } => {
                // Proactive redirect: triggers BME fee (Section 6.3 / Q25)
                let epoch = identity.clock.current_epoch;
                match state.get_account_mut(&tx.sender) {
                    Ok(account) => {
                        account.record_spend_for_exemption(epoch);
                        cirfi.redirect_to_ubi_pool(account, *amount)
                            .map(|to_pool| {
                                events.push(format!(
                                    "ubi_redirect: {} ucirfi to pool (BME triggered)",
                                    to_pool
                                ));
                            })
                            .map_err(|e| e.to_string())
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

        // TODO: verify signature once crypto layer is wired up.

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
                // executed -- the module runtime (Charm Confinement, CirFi etc.)
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
            | TxBody::RevokeAgent { .. } => {
                Err("identity-gated transaction requires identity-aware executor".to_string())
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

    /// Execute all transactions for one block, with identity- and
    /// CirFi-gated transaction types (RegisterIdentity, Attest, ClaimUbi,
    /// RedirectToUbiPool, SponsorAgent, RevokeAgent) actually processed
    /// instead of rejected. This is what a live node needs to call for
    /// those transaction types to work at all -- execute_block() above
    /// always rejects them, by design, since it has no identity or CirFi
    /// state to process them against.
    pub fn execute_block_with_identity(
        &self,
        height:       u64,
        transactions: Vec<Transaction>,
        state:        &mut StateStore,
        identity:     &mut IdentityStore,
        cirfi:        &mut CirfiEngine,
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

            let result = self.execute_tx_with_identity(tx, state, identity, cirfi);
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
    use chain_forge_cirfi::CirfiEngine;

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
            "modules": ["bank", "staking", "identity", "cirfi", "agents"],
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

    fn setup_with_identity() -> (Executor, StateStore, IdentityStore, CirfiEngine) {
        use chain_forge_identity::{IdentityStore, PopAttestation};
        use chain_forge_cirfi::CirfiEngine;

        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let config  = ExecutionConfig::from_genesis(&genesis);
        let mut state = StateStore::new(HashWidth::Bits256);
        state.apply_genesis(&genesis).unwrap();

        let mut identity = IdentityStore::new(0);
        let att = PopAttestation::genesis("qcb1alice", 0);
        identity.register("qcb1alice".into(), "qcb1alice".into(), att.clone()).unwrap();
        identity.verify_identity("qcb1alice", att).unwrap();

        let cirfi = CirfiEngine::new("ucirfi".into(), "uqcb".into());
        (Executor::new(config), state, identity, cirfi)
    }

    #[test]
    fn claim_ubi_credits_verified_human() {
        use chain_forge_identity::DAILY_UBI_RATE_UCIRFI;

        let (exec, mut state, mut identity, mut cirfi) = setup_with_identity();

        let tx = Transaction::claim_ubi("tx1", "qcb1alice", "qcb1alice", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut cirfi);

        assert!(result.success, "UBI claim should succeed: {:?}", result.error);
        assert!(result.events.iter().any(|e| e.contains("ubi_claim")));
        let balance = state.get_account("qcb1alice").unwrap().balance_of("ucirfi");
        assert_eq!(balance, DAILY_UBI_RATE_UCIRFI,
            "alice's ucirfi balance should equal one UBI claim (genesis balance is uqcb)");
    }

    #[test]
    fn charm_confinement_blocks_double_ubi_claim() {
        let (exec, mut state, mut identity, mut cirfi) = setup_with_identity();

        let tx1 = Transaction::claim_ubi("tx1", "qcb1alice", "qcb1alice", 0);
        let r1 = exec.execute_tx_with_identity(&tx1, &mut state, &mut identity, &mut cirfi);
        assert!(r1.success);

        let tx2 = Transaction::claim_ubi("tx2", "qcb1alice", "qcb1alice", 1);
        let r2 = exec.execute_tx_with_identity(&tx2, &mut state, &mut identity, &mut cirfi);
        assert!(!r2.success, "second UBI claim in same epoch must fail");
    }

    #[test]
    fn redirect_to_ubi_pool_triggers_bme() {
        let (exec, mut state, mut identity, mut cirfi) = setup_with_identity();

        // Claim UBI first so alice has ucirfi to redirect
        let claim = Transaction::claim_ubi("tx0", "qcb1alice", "qcb1alice", 0);
        let r0 = exec.execute_tx_with_identity(&claim, &mut state, &mut identity, &mut cirfi);
        assert!(r0.success, "{:?}", r0.error);

        let tx = Transaction::redirect_to_ubi_pool("tx1", "qcb1alice", 1_000_000, 1);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut cirfi);

        assert!(result.success, "{:?}", result.error);
        assert!(result.events.iter().any(|e| e.contains("ubi_redirect")));
        assert!(cirfi.bme.total_fees_collected_ucirfi > 0, "BME should collect fee");
    }

    #[test]
    fn sponsor_agent_requires_verified_identity() {
        let (exec, mut state, mut identity, mut cirfi) = setup_with_identity();

        // Bob is not in identity store -- should fail
        let tx = Transaction::sponsor_agent("tx1", "qcb1bob", "qcb1agent1", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut cirfi);
        assert!(!result.success, "unverified identity cannot sponsor agents");
    }

    #[test]
    fn sponsor_agent_succeeds_for_verified_human() {
        let (exec, mut state, mut identity, mut cirfi) = setup_with_identity();

        let tx = Transaction::sponsor_agent("tx1", "qcb1alice", "qcb1agent1", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut cirfi);

        assert!(result.success, "{:?}", result.error);
        assert!(identity.is_agent_authorized("qcb1agent1", "qcb1alice"),
            "agent should be authorized after sponsor tx");
    }

    #[test]
    fn spend_earns_decay_exemption() {
        let (exec, mut state, mut identity, mut cirfi) = setup_with_identity();

        // Attach charm to alice's account first
        let mut charm = chain_forge_identity::IntrinsicCharm::provisional(0);
        charm.verify(0);
        let mut alice = state.get_account("qcb1alice").unwrap().clone();
        alice.attach_charm(charm);
        state.upsert_account(alice);

        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 0);

        // Transfer triggers spend -> exemption credit
        let tx = Transaction::transfer("tx1", "qcb1alice", "qcb1bob", "uqcb", 1_000, 0);
        exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut cirfi);

        assert_eq!(state.get_account("qcb1alice").unwrap().exemption_days(), 1,
            "spending should earn 1 day of decay exemption");
    }

    // -- Identity pilot: RegisterIdentity + Attest transactions ---------------

    #[test]
    fn register_identity_tx_creates_provisional_account_with_charm() {
        let (exec, mut state, mut identity, mut cirfi) = setup_with_identity();

        let tx = Transaction::register_identity("tx1", "qcb1newbie", 0);
        let result = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut cirfi);

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

        let (exec, mut state, mut identity, mut cirfi) = setup_with_identity();

        // Bootstrap two more Verified attesters alongside alice (already
        // Verified via setup_with_identity's genesis path).
        for name in ["qcb1bob", "qcb1carol"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att).unwrap();
        }

        // Register the real claimant via the actual transaction path.
        let reg_tx = Transaction::register_identity("tx0", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&reg_tx, &mut state, &mut identity, &mut cirfi);

        // Two attestations: still Provisional on-chain.
        let a1 = Transaction::attest("tx1", "qcb1alice", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&a1, &mut state, &mut identity, &mut cirfi);
        let a2 = Transaction::attest("tx2", "qcb1bob", "qcb1newbie", 0);
        exec.execute_tx_with_identity(&a2, &mut state, &mut identity, &mut cirfi);
        assert_eq!(
            state.get_account("qcb1newbie").unwrap().verification_tier(),
            Some(&VerificationTier::Provisional)
        );

        // Third distinct attestation crosses quorum -- both IdentityStore
        // AND the on-chain account must now show Verified.
        let a3 = Transaction::attest("tx3", "qcb1carol", "qcb1newbie", 0);
        let result = exec.execute_tx_with_identity(&a3, &mut state, &mut identity, &mut cirfi);
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

        let (exec, mut state, mut identity, mut cirfi) = setup_with_identity();
        for name in ["qcb1bob", "qcb1carol"] {
            let att = PopAttestation::genesis(name, 0);
            identity.register(name.into(), name.into(), att.clone()).unwrap();
            identity.verify_identity(name, att).unwrap();
        }

        // Registration advances the new account's nonce 0 -> 1.
        let reg = Transaction::register_identity("r0", "qcb1newbie", 0);
        assert!(exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut cirfi).success);
        assert_eq!(state.get_account("qcb1newbie").unwrap().nonce, 1);

        // Replaying the exact same registration is now a nonce mismatch,
        // not a second trip into the identity logic.
        let replay = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut cirfi);
        assert!(!replay.success);
        assert!(replay.error.as_deref().unwrap_or("").contains("nonce mismatch"));

        // An attester's first attest advances their nonce, so their second
        // transaction must use nonce 1 -- and does succeed with it.
        let a1 = Transaction::attest("a1", "qcb1alice", "qcb1newbie", 0);
        assert!(exec.execute_tx_with_identity(&a1, &mut state, &mut identity, &mut cirfi).success);
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 1);

        exec.execute_tx_with_identity(
            &Transaction::register_identity("r1", "qcb1other", 0),
            &mut state, &mut identity, &mut cirfi,
        );
        let a2 = Transaction::attest("a2", "qcb1alice", "qcb1other", 1);
        let r = exec.execute_tx_with_identity(&a2, &mut state, &mut identity, &mut cirfi);
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
        let (_, mut state, mut identity, mut cirfi) = setup_with_identity();
        let genesis = GenesisConfig::from_json(genesis_json()).unwrap();
        let mut config = ExecutionConfig::from_genesis(&genesis);
        config.require_signatures = true;
        let exec = Executor::new(config);

        let user = key("new-user");
        let addr = Address::from_public_key(&user.public_key, "qcb", HashWidth::Bits256);
        let mut reg = Transaction::register_identity("r0", addr.as_str(), 0);
        reg.sign(&user, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut cirfi);
        assert!(r.success, "{:?}", r.error);

        let acct = state.get_account(addr.as_str()).unwrap();
        assert_eq!(acct.public_key.as_deref(), Some(user.public_key.as_slice()), "first tx binds the key");
        assert_eq!(acct.nonce, 1);

        // A different key can no longer act for this address.
        let other = key("someone-else");
        let mut hijack = Transaction::attest("h1", addr.as_str(), "qcb1alice", 1);
        hijack.sign(&other, "qcb-testnet-1").unwrap();
        let r = exec.execute_tx_with_identity(&hijack, &mut state, &mut identity, &mut cirfi);
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
        use chain_forge_cirfi::CirfiEngine;

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
            identity.verify_identity(name, att).unwrap();
        }
        let mut cirfi = CirfiEngine::new("ucirfi".into(), "uqcb".into());

        let root_before = state.commit(0, 0, false).root_hash;

        // Register newcomer -- should change the state root (Provisional charm attached).
        let reg = Transaction::register_identity("t-reg", "qcb1newcomer", 0);
        let r = exec.execute_tx_with_identity(&reg, &mut state, &mut identity, &mut cirfi);
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
            let r = exec.execute_tx_with_identity(&attest, &mut state, &mut identity, &mut cirfi);
            assert!(r.success, "attest {i} failed: {:?}", r.error);
        }
        let root_after_verify = state.commit(0, 0, false).root_hash;
        assert_ne!(root_after_reg, root_after_verify,
            "state root must change when Attest upgrades a claimant from Provisional to Verified");

        let acct = state.get_account("qcb1newcomer").expect("account must exist");
        assert!(acct.charm.is_some(), "verified account must have a charm");
    }

    #[test]
    fn plain_chain_rejects_identity_cirfi_agent_and_stake_txs() {
        let (_, mut state, mut identity, mut cirfi) = setup_with_identity();
        let exec = plain_chain_exec();
        let cases = [
            (Transaction::register_identity("t1", "qcb1alice", 0), "identity"),
            (Transaction::attest("t2", "qcb1alice", "qcb1bob", 0), "identity"),
            (Transaction::claim_ubi("t3", "qcb1alice", "qcb1alice", 0), "cirfi"),
            (Transaction::sponsor_agent("t4", "qcb1alice", "qcb1agent", 0), "agents"),
        ];
        for (tx, module) in cases {
            let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut cirfi);
            assert!(!r.success, "{} must be rejected on a plain chain", tx.id);
            assert!(r.error.unwrap().contains(&format!("module \"{module}\" is not enabled")));
        }
        assert_eq!(state.get_account("qcb1alice").unwrap().nonce, 0, "gated txs must not advance the nonce");
    }

    #[test]
    fn plain_chain_still_allows_core_transfers() {
        let (_, mut state, mut identity, mut cirfi) = setup_with_identity();
        let exec = plain_chain_exec();
        let tx = Transaction::transfer("t1", "qcb1alice", "qcb1bob", "uqcb", 100, 0);
        let r = exec.execute_tx_with_identity(&tx, &mut state, &mut identity, &mut cirfi);
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
        ];
        for body in bodies {
            let m = required_module(&body).expect("gated tx types name their module");
            assert!(known.contains(&m), "{m} missing from KNOWN_MODULES");
        }
    }
}
