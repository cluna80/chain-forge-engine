#[path = "../../common.rs"]
mod common;
use common::*;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa65, Signature, SigningKey, VerifyingKey};

struct B;
type Seed = ml_dsa::B32;
fn sk_of(b: &[u8]) -> Result<ExpandedSigningKey<MlDsa65>, String> {
    let enc = ExpandedSigningKeyBytes::<MlDsa65>::try_from(b).map_err(|_| "sk length".to_string())?;
    #[allow(deprecated)]
    Ok(ExpandedSigningKey::<MlDsa65>::from_expanded(&enc))
}
fn pk_of(b: &[u8]) -> Option<VerifyingKey<MlDsa65>> {
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(b).ok()?;
    Some(VerifyingKey::<MlDsa65>::decode(&enc))
}
fn sig_of(b: &[u8]) -> Option<Signature<MlDsa65>> {
    let enc = EncodedSignature::<MlDsa65>::try_from(b).ok()?;
    Signature::<MlDsa65>::decode(&enc)
}
fn mprime_pure(msg: &[u8], ctx: &[u8]) -> Option<Vec<u8>> {
    if ctx.len() > 255 { return None; }
    let mut m = vec![0u8, ctx.len() as u8];
    m.extend_from_slice(ctx);
    m.extend_from_slice(msg);
    Some(m)
}

impl Backend for B {
    fn name() -> &'static str { "ml-dsa 0.1.2 (RustCrypto)" }
    fn keygen_from_seed(seed: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
        use ml_dsa::Keypair;
        let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(*seed));
        let pk = sk.verifying_key().encode();
        #[allow(deprecated)]
        let skb = sk.expanded_key().to_expanded();
        Some((pk.as_slice().to_vec(), skb.as_slice().to_vec()))
    }
    fn sign_internal(sk: &[u8], mp: &[u8], rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        Some(sk_of(sk).map(|k| k.sign_internal(&[mp], &Seed::from(*rnd)).encode().as_slice().to_vec()))
    }
    fn sign_pure(sk: &[u8], msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> {
        // pure ML-DSA with an explicit rnd is Sign_internal over M' = 0x00 || |ctx| || ctx || M
        Some(sk_of(sk).and_then(|k| {
            let mp = mprime_pure(msg, ctx).ok_or_else(|| "context longer than 255 bytes".to_string())?;
            Ok(k.sign_internal(&[&mp], &Seed::from(*rnd)).encode().as_slice().to_vec())
        }))
    }
    fn verify_internal(pk: &[u8], mp: &[u8], sig: &[u8]) -> Option<bool> {
        Some(match (pk_of(pk), sig_of(sig)) { (Some(p), Some(s)) => p.verify_internal(mp, &s), _ => false })
    }
    fn verify_pure(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<bool> {
        Some(match (pk_of(pk), sig_of(sig)) { (Some(p), Some(s)) => p.verify_with_context(msg, ctx, &s), _ => false })
    }
}
fn main() { main_for::<B>() }
