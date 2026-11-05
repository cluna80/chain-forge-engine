//! Signing v2 for ML-DSA-65 transactions: FIPS 204 pure ML-DSA over the full canonical preimage, context
//! `qattice/tx/v2`, with the strict envelope rules E1-E5. Spec and vectors: `docs/mldsa-tx-signing-v2/` (PR #94).
//!
//! **TEST-ONLY.** Compiled only with the `signing-v2` cargo feature, and even then used only when
//! `ExecutionConfig::mldsa_signing_v2` is set; no genesis path sets it. The `commitment_profile` genesis field that will
//! activate it on a real chain is a separate change. With the switch off, every code path is the legacy one.
//!
//! What this fixes (H0-4): under the legacy ML-DSA digest the signature covers only (chain id, body), so a signed
//! transaction can be re-submitted under a new nonce. Here the signed message is
//! `U16(2) ‖ LP(chain_id) ‖ LP(id) ‖ LP(sender) ‖ U64(nonce) ‖ U64(gas_limit) ‖ LP(body_json) ‖ LP(pq_public_key)`.
//!
//! Not covered here: mempool/API ingress (`check_account_signature_policy` still runs there), signers (wallet, scheduler,
//! CLI), guardian/recovery signatures, validator and consensus signatures.

use crate::{ExecutionConfig, Transaction};
use chain_forge_core::{Address, AddressScheme};
use chain_forge_crypto::fips204_backend::{MlDsa65Fips204, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use chain_forge_crypto::SchemeId;
use chain_forge_state::StateStore;

/// FIPS 204 context string for transaction authorization.
pub const TX_CONTEXT: &[u8] = b"qattice/tx/v2";
/// Preimage version (first two bytes of the message).
pub const PREIMAGE_VERSION: u16 = 2;
const SIG_TAG: &str = "mldsa65:";

fn lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let n = u32::try_from(bytes.len()).map_err(|_| "field longer than 2^32-1 bytes".to_string())?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// The complete canonical preimage `M` that is handed to ML-DSA.Sign / Verify (no pre-hash).
/// `pq_public_key` is the key that verifies the signature (the bound key, or the first-use key).
pub fn tx_preimage(chain_id: &str, tx: &Transaction, pq_public_key: &[u8]) -> Result<Vec<u8>, String> {
    let body_json = serde_json::to_string(&tx.body).map_err(|e| format!("cannot serialise tx.body: {e}"))?;
    let mut m = Vec::with_capacity(64 + chain_id.len() + tx.id.len() + tx.sender.len() + body_json.len() + pq_public_key.len());
    m.extend_from_slice(&PREIMAGE_VERSION.to_be_bytes());
    lp(&mut m, chain_id.as_bytes())?;
    lp(&mut m, tx.id.as_bytes())?;
    lp(&mut m, tx.sender.as_bytes())?;
    m.extend_from_slice(&tx.nonce.to_be_bytes());
    m.extend_from_slice(&tx.gas_limit.to_be_bytes());
    lp(&mut m, body_json.as_bytes())?;
    lp(&mut m, pq_public_key)?;
    Ok(m)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Structural acceptance rules E1-E5 for a transaction on a signing-v2 chain. `bound_key` is the key already bound to the
/// sender, if any. Returns a stable reject code. No cryptography happens here.
pub fn check_envelope(tx: &Transaction, bound_key: Option<&[u8]>) -> Result<(), &'static str> {
    match tx.sig_scheme {
        None => return Err("E1_SCHEME_MISSING"),
        Some(SchemeId::MlDsa) => {}
        Some(_) => return Err("E1_SCHEME_NOT_MLDSA"),
    }
    if !tx.signature.is_empty() || !tx.public_key.is_empty() {
        return Err("E2_CLASSICAL_MATERIAL_PRESENT");
    }
    if tx.pq_signatures.len() != 1 {
        return Err("E3_NOT_EXACTLY_ONE_SIGNATURE");
    }
    let entry = &tx.pq_signatures[0];
    let Some(body) = entry.strip_prefix(SIG_TAG) else { return Err("E4_BAD_SIGNATURE_TAG") };
    if unhex(body).is_none() {
        return Err("E4_SIGNATURE_NOT_HEX");
    }
    if body.len() != 2 * SIGNATURE_BYTES {
        return Err("E4_SIGNATURE_WRONG_LENGTH");
    }
    match bound_key {
        None => {
            if tx.pq_public_key.len() != PUBLIC_KEY_BYTES {
                return Err("E5_FIRST_USE_KEY_MISSING_OR_WRONG_LENGTH");
            }
        }
        Some(b) => {
            if !tx.pq_public_key.is_empty() && tx.pq_public_key != b {
                return Err("E5_KEY_DIFFERS_FROM_BOUND_KEY");
            }
        }
    }
    Ok(())
}

/// Verify `signature` over the transaction's preimage. `preimage_key` is the key named inside the preimage and
/// `verify_key` the key used for verification (they are the same on a well-formed transaction; vectors use them separately).
pub fn verify_with_key(chain_id: &str, tx: &Transaction, preimage_key: &[u8], verify_key: &[u8], signature: &[u8], ctx: &[u8]) -> bool {
    match tx_preimage(chain_id, tx, preimage_key) {
        Ok(m) => MlDsa65Fips204::verify(verify_key, &m, signature, ctx).is_ok(),
        Err(_) => false,
    }
}

/// Stateless signature check for ingress that has no account state (the HTTP API): verify the signature against the key the
/// transaction carries. A well-formed envelope is assumed (`check_envelope`). It does not apply the bound-key or
/// derived-address rules; those need the sender's account and are applied by [`authorize`] at the mempool and at execution.
/// Returns Ok for a transaction that carries no key (it relies on a bound key the caller cannot see).
pub fn verify_carried_key(chain_id: &str, tx: &Transaction) -> Result<(), String> {
    if tx.pq_public_key.is_empty() {
        return Ok(());
    }
    let preimage = tx_preimage(chain_id, tx, &tx.pq_public_key)?;
    let sig_hex = tx.pq_signatures.first().and_then(|s| s.strip_prefix(SIG_TAG)).ok_or_else(|| "E4_BAD_SIGNATURE_TAG".to_string())?;
    let sig = unhex(sig_hex).ok_or_else(|| "E4_SIGNATURE_NOT_HEX".to_string())?;
    MlDsa65Fips204::verify(&tx.pq_public_key, &preimage, &sig, TX_CONTEXT)
        .map_err(|e| format!("ML-DSA signature verification failed (signing v2): {e}"))
}

/// Authorization of one transaction under signing v2. Rejections happen before any nonce check or fee debit, exactly like
/// the legacy authorization step, so a failed authorization changes no state.
pub(crate) fn authorize(config: &ExecutionConfig, tx: &Transaction, state: &StateStore) -> Result<(), String> {
    let bound: Option<Vec<u8>> = state.get_account(&tx.sender).ok().and_then(|a| a.public_key.clone()).filter(|k| !k.is_empty());
    check_envelope(tx, bound.as_deref()).map_err(|code| format!("{code}: transaction envelope rejected (signing v2)"))?;
    let key: Vec<u8> = match bound {
        Some(k) => k,
        None => {
            // First use: the sender must be the address derived from this key, so an unbound address can only be claimed
            // by its own key holder (named genesis accounts must have their key bound in genesis).
            let derived = Address::from_public_key_schemed(&tx.pq_public_key, &config.address_prefix, config.hash_width, AddressScheme::PostQuantum);
            if derived.as_str() != tx.sender {
                return Err(format!(
                    "{} has no bound key and is not derived from the signing key ({}); bind the account's ML-DSA key in genesis or send from the derived address",
                    tx.sender, derived.as_str()
                ));
            }
            tx.pq_public_key.clone()
        }
    };
    let preimage = tx_preimage(&config.chain_id, tx, &key)?;
    let sig_hex = &tx.pq_signatures[0][SIG_TAG.len()..];
    let sig = unhex(sig_hex).ok_or_else(|| "E4_SIGNATURE_NOT_HEX".to_string())?;
    MlDsa65Fips204::verify(&key, &preimage, &sig, TX_CONTEXT).map_err(|e| format!("ML-DSA signature verification failed (signing v2): {e}"))
}
