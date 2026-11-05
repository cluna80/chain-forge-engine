#[path = "../../common.rs"]
mod common;
use common::*;
use pqcrypto_mldsa::mldsa65 as m;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

struct B;
impl Backend for B {
    fn name() -> &'static str { "pqcrypto-mldsa 0.1.2 (PQClean)" }
    // PQClean ML-DSA signs with fresh randomness (hedged); no seeded keygen or caller-supplied rnd is exposed.
    fn deterministic_kat() -> bool { false }
    fn random_keypair() -> Option<(Vec<u8>, Vec<u8>)> { let (p, s) = m::keypair(); Some((p.as_bytes().to_vec(), s.as_bytes().to_vec())) }
    fn sign_pure(sk: &[u8], msg: &[u8], ctx: &[u8], _rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        Some(m::SecretKey::from_bytes(sk).map_err(|e| format!("{e:?}")).map(|k| m::detached_sign_ctx(msg, ctx, &k).as_bytes().to_vec()))
    }
    fn verify_pure(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<bool> {
        Some(match (m::PublicKey::from_bytes(pk), m::DetachedSignature::from_bytes(sig)) {
            (Ok(p), Ok(s)) => m::verify_detached_signature_ctx(&s, msg, ctx, &p).is_ok(),
            _ => false,
        })
    }
}
fn main() { main_for::<B>() }
