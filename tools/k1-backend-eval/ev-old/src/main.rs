#[path = "../../common.rs"]
mod common;
use common::*;
use pqcrypto_dilithium::dilithium3 as m;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
struct B;
fn mp(msg: &[u8], ctx: &[u8]) -> Option<Vec<u8>> { if ctx.len() > 255 { return None } let mut v = vec![0u8, ctx.len() as u8]; v.extend_from_slice(ctx); v.extend_from_slice(msg); Some(v) }
impl Backend for B {
    fn name() -> &'static str { "pqcrypto-dilithium 0.5.0 (CURRENT chain library)" }
    fn random_keypair() -> Option<(Vec<u8>, Vec<u8>)> { let (p, s) = m::keypair(); Some((p.as_bytes().to_vec(), s.as_bytes().to_vec())) }
    // Standard external-pure framing M' built by the caller, signing deterministically through the library's raw interface.
    fn sign_pure(sk: &[u8], msg: &[u8], ctx: &[u8], _rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        Some(m::SecretKey::from_bytes(sk).map_err(|e| format!("{e:?}")).and_then(|k| { let x = mp(msg, ctx).ok_or("ctx")?; Ok(m::detached_sign(&x, &k).as_bytes().to_vec()) }))
    }
    fn verify_pure(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<bool> {
        Some(match (m::PublicKey::from_bytes(pk), m::DetachedSignature::from_bytes(sig), mp(msg, ctx)) {
            (Ok(p), Ok(s), Some(x)) => m::verify_detached_signature(&s, &x, &p).is_ok(), _ => false })
    }
}
fn main() { main_for::<B>() }
