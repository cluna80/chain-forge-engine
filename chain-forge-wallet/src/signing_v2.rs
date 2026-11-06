//! TEST-ONLY signing-v2 transaction signer (feature `signing-v2`). See docs/mldsa-tx-signing-v2/SPEC.md.
//!
//! The transaction is built from the node's own `Transaction` type so that the body JSON signed here is byte-for-byte the
//! body JSON the verifier recomputes. Signing is hedged (fresh OS randomness per signature, FIPS 204 default); deterministic
//! signing exists only for test vectors and is not reachable from this module.

use crate::{KeyPair, SchemeId, WalletError, WalletResult};
use chain_forge_core::{Address, AddressScheme, HashWidth};
use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use chain_forge_execution::signing_v2;
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

/// Submit a signed v2 transaction to a node's `POST /api/tx` and return the node's JSON answer.
pub fn submit_v2(host: &str, port: u16, tx: &Transaction) -> WalletResult<serde_json::Value> {
    let url = format!("http://{host}:{port}/api/tx");
    match ureq::post(&url).set("Content-Type", "application/json").send_json(tx) {
        Ok(resp) => resp.into_json().map_err(|e| WalletError::Network(format!("response parse: {e}"))),
        // The node answers a refusal with a 400 and a JSON body; hand that body back instead of hiding it.
        Err(ureq::Error::Status(_, resp)) => resp.into_json().map_err(|e| WalletError::Network(format!("response parse: {e}"))),
        Err(e) => Err(WalletError::Network(format!("{e}"))),
    }
}

/// Sign one transaction under signing v2 (hedged: fresh OS randomness per signature).
///
/// The key pair is validated first (a mismatched or malformed secret key is an error, never a panic). With `sender: None` the
/// sender is the address derived from the key (`address_prefix`, post-quantum scheme), which is what a first-use transaction
/// must name; an explicit sender is for accounts whose key is bound in genesis.
pub fn sign_transaction_v2(kp: &KeyPair, chain_id: &str, address_prefix: &str, p: V2TxParams) -> WalletResult<Transaction> {
    B::validate_keypair(&kp.public_key, &kp.private_key).map_err(|e| WalletError::SigningV2(format!("invalid key pair: {e}")))?;
    let sender = match p.sender {
        Some(s) => s,
        None => Address::from_public_key_schemed(&kp.public_key, address_prefix, HashWidth::Bits256, AddressScheme::PostQuantum)
            .as_str()
            .to_string(),
    };
    let mut tx = Transaction {
        id: p.id,
        sender,
        nonce: p.nonce,
        body: p.body,
        gas_limit: p.gas_limit,
        sig_scheme: Some(SchemeId::MlDsa),
        signature: vec![],
        public_key: vec![],
        pq_signatures: vec![],
        pq_public_key: if p.carry_key { kp.public_key.clone() } else { vec![] },
    };
    let preimage = signing_v2::tx_preimage(chain_id, &tx, &kp.public_key).map_err(WalletError::SigningV2)?;
    let sig = B::sign(&kp.private_key, &preimage, signing_v2::TX_CONTEXT).map_err(|e| WalletError::SigningV2(format!("signing failed: {e}")))?;
    let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    tx.pq_signatures = vec![format!("mldsa65:{hex}")];
    Ok(tx)
}
