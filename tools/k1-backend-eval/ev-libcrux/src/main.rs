#[path = "../../common.rs"]
mod common;
use common::*;
use libcrux_ml_dsa::ml_dsa_65 as m;
use libcrux_ml_dsa::{MLDSASignature, MLDSASigningKey, MLDSAVerificationKey};

struct B;
fn sk_of(b: &[u8]) -> Result<m::MLDSA65SigningKey, String> {
    let a: [u8; 4032] = b.try_into().map_err(|_| "sk length".to_string())?;
    Ok(MLDSASigningKey::new(a))
}
fn pk_of(b: &[u8]) -> Option<m::MLDSA65VerificationKey> { let a: [u8; 1952] = b.try_into().ok()?; Some(MLDSAVerificationKey::new(a)) }
fn sig_of(b: &[u8]) -> Option<m::MLDSA65Signature> { let a: [u8; 3309] = b.try_into().ok()?; Some(MLDSASignature::new(a)) }

impl Backend for B {
    fn name() -> &'static str { "libcrux-ml-dsa 0.0.11" }
    fn keygen_from_seed(seed: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
        let kp = m::generate_key_pair(*seed);
        Some((kp.verification_key.as_slice().to_vec(), kp.signing_key.as_slice().to_vec()))
    }
    fn sign_internal(sk: &[u8], mp: &[u8], rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        Some(sk_of(sk).and_then(|k| m::sign_internal(&k, mp, *rnd).map(|s| s.as_slice().to_vec()).map_err(|e| format!("{e:?}"))))
    }
    fn sign_pure(sk: &[u8], msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        Some(sk_of(sk).and_then(|k| m::sign(&k, msg, ctx, *rnd).map(|s| s.as_slice().to_vec()).map_err(|e| format!("{e:?}"))))
    }
    // The crate exposes only the SHAKE-128 pre-hash variant natively.
    fn sign_prehash(sk: &[u8], msg: &[u8], ctx: &[u8], alg: &str, rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        if alg != "SHAKE-128" { return None; }
        Some(sk_of(sk).and_then(|k| m::sign_pre_hashed_shake128(&k, msg, ctx, *rnd).map(|s| s.as_slice().to_vec()).map_err(|e| format!("{e:?}"))))
    }
    fn verify_internal(pk: &[u8], mp: &[u8], sig: &[u8]) -> Option<bool> {
        Some(match (pk_of(pk), sig_of(sig)) { (Some(p), Some(s)) => m::verify_internal(&p, mp, &s).is_ok(), _ => false })
    }
    fn verify_pure(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<bool> {
        Some(match (pk_of(pk), sig_of(sig)) { (Some(p), Some(s)) => m::verify(&p, msg, ctx, &s).is_ok(), _ => false })
    }
    fn verify_prehash(pk: &[u8], msg: &[u8], ctx: &[u8], alg: &str, sig: &[u8]) -> Option<bool> {
        if alg != "SHAKE-128" { return None; }
        Some(match (pk_of(pk), sig_of(sig)) { (Some(p), Some(s)) => m::verify_pre_hashed_shake128(&p, msg, ctx, &s).is_ok(), _ => false })
    }
}
fn main() { main_for::<B>() }
