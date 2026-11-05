#[path = "../../common.rs"]
mod common;
use common::*;
use fips204::ml_dsa_65 as m;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use fips204::{CryptoRng, RngCore};

struct B;
struct Zero;
impl RngCore for Zero {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, d: &mut [u8]) { d.fill(0) }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), fips204::RngError> { d.fill(0); Ok(()) }
}
impl CryptoRng for Zero {}

fn sk_of(b: &[u8]) -> Result<m::PrivateKey, String> {
    let a: [u8; m::SK_LEN] = b.try_into().map_err(|_| "sk length".to_string())?;
    m::PrivateKey::try_from_bytes(a).map_err(|e| e.to_string())
}
fn pk_of(b: &[u8]) -> Option<m::PublicKey> {
    let a: [u8; m::PK_LEN] = b.try_into().ok()?;
    m::PublicKey::try_from_bytes(a).ok()
}
fn sig_of(b: &[u8]) -> Option<[u8; m::SIG_LEN]> { b.try_into().ok() }

impl Backend for B {
    fn name() -> &'static str { "fips204 0.5.0" }
    fn keygen_from_seed(seed: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
        let (pk, sk) = m::KG::keygen_from_seed(seed);
        Some((pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
    }
    #[allow(deprecated)]
    fn sign_internal(sk: &[u8], mp: &[u8], _rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        Some(sk_of(sk).and_then(|k| k.sign_internal(&mut Zero, mp, false).map(|s| s.to_vec()).map_err(|e| e.to_string())))
    }
    fn sign_pure(sk: &[u8], msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        Some(sk_of(sk).and_then(|k| k.try_sign_with_seed(rnd, msg, ctx).map(|s| s.to_vec()).map_err(|e| e.to_string())))
    }
    fn sign_prehash(sk: &[u8], msg: &[u8], ctx: &[u8], alg: &str, rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        let (oid, digest) = prehash(alg, msg);
        Some(sk_of(sk).and_then(|k| k.try_hash_sign_with_seed(rnd, &digest, ctx, &oid).map(|s| s.to_vec()).map_err(|e| e.to_string())))
    }
    #[allow(deprecated)]
    fn verify_internal(pk: &[u8], mp: &[u8], sig: &[u8]) -> Option<bool> {
        Some(match (pk_of(pk), sig_of(sig)) { (Some(p), Some(s)) => p.verify_internal(mp, &s), _ => false })
    }
    fn verify_pure(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<bool> {
        Some(match (pk_of(pk), sig_of(sig)) { (Some(p), Some(s)) => p.verify(msg, &s, ctx), _ => false })
    }
    fn verify_prehash(pk: &[u8], msg: &[u8], ctx: &[u8], alg: &str, sig: &[u8]) -> Option<bool> {
        let (oid, digest) = prehash(alg, msg);
        Some(match (pk_of(pk), sig_of(sig)) { (Some(p), Some(s)) => p.hash_verify(&digest, &s, ctx, &oid), _ => false })
    }
}
fn main() { main_for::<B>() }
