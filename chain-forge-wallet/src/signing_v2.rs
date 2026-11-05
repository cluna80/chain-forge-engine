//! TEST-ONLY signing-v2 transaction signer (feature `signing-v2`). See docs/mldsa-tx-signing-v2/SPEC.md.
//! SCAFFOLD: not implemented yet (tests are written first).

use crate::{KeyPair, WalletError, WalletResult};
use chain_forge_execution::{Transaction, TxBody};

/// Inputs for one transaction. `sender: None` means "the address derived from the key".
pub struct V2TxParams {
    pub id: String,
    pub nonce: u64,
    pub gas_limit: u64,
    pub body: TxBody,
    pub sender: Option<String>,
    /// Put the public key in the transaction (required on first use; optional once the key is bound).
    pub carry_key: bool,
}

/// Sign one transaction under signing v2 (hedged: fresh OS randomness per signature).
pub fn sign_transaction_v2(_kp: &KeyPair, _chain_id: &str, _address_prefix: &str, _p: V2TxParams) -> WalletResult<Transaction> {
    Err(WalletError::SigningV2("not implemented".into()))
}
