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
use chain_forge_core::GenesisConfig;
use chain_forge_state::{StateStore, StateError};

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
                    TxBody::Transfer { .. } => op_multiplier * 2,
                    TxBody::Burn    { .. } => op_multiplier * 3,
                    TxBody::Stake   { .. } => op_multiplier * 5,
                    TxBody::Custom  { .. } => op_multiplier * 10,
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
    /// Sender's signature. Empty in Phase 0 -- crypto layer not wired.
    pub signature: Vec<u8>,
}

impl Transaction {
    /// Approximate serialised size in bytes (used for gas calculation).
    pub fn payload_size_bytes(&self) -> usize {
        let body_size = match &self.body {
            TxBody::Transfer { to, denom, .. } => to.len() + denom.len() + 16,
            TxBody::Burn     { denom, .. }      => denom.len() + 16,
            TxBody::Stake    { validator, .. }  => validator.len() + 16,
            TxBody::Custom   { module, payload } => module.len() + payload.len(),
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
}

impl ExecutionConfig {
    pub fn from_genesis(genesis: &GenesisConfig) -> Self {
        Self {
            gas_model:       GasModel::from_genesis(genesis),
            block_gas_limit: genesis.limits.block_gas_limit,
            max_tx_bytes:    genesis.limits.max_tx_bytes,
            native_denom:    genesis.native_token.denom.clone(),
        }
    }
}

// -- Executor -----------------------------------------------------------------

/// Applies transactions to a StateStore.
/// The node creates one Executor per block and calls execute_block().
pub struct Executor {
    config: ExecutionConfig,
}

impl Executor {
    pub fn new(config: ExecutionConfig) -> Self {
        Self { config }
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
        };

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
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chain_forge_core::{GenesisConfig, HashWidth};
    use chain_forge_state::StateStore;

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
            "execution": { "state_model": "account", "parallel_execution": false, "gas_model": "dynamic" },
            "cryptography": { "signature_scheme": "hybrid", "pqc_algorithm": "ml-dsa", "migration_trigger": "nist-guidance", "hash_width": 256, "validator_scheme": "pqc-native" },
            "network": { "network_id": "qcb-testnet-1-net", "p2p_port": 26656, "rpc_port": 26657, "bootstrap_nodes": [], "peer_discovery": "both", "max_peers": 50 },
            "limits": { "max_block_bytes": 1048576, "max_tx_bytes": 65536, "block_gas_limit": 10000000, "mempool_size": 5000, "mempool_ttl_seconds": 300 },
            "modules": ["bank", "staking"],
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
}
