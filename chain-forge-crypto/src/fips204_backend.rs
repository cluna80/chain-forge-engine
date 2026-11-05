//! FIPS 204 ML-DSA-65 backend (crate `fips204`, pinned to 0.5.0).
//!
//! Standard FIPS 204 **pure** ML-DSA with a context string: `ML-DSA.Sign(sk, M, ctx)` / `ML-DSA.Verify(pk, M, sig, ctx)`.
//! `M` is the caller's complete message (for transactions: the whole canonical preimage, see
//! `docs/mldsa-tx-signing-v2/SPEC.md`); `ctx` is the Qattice protocol context (at most 255 bytes).
//!
//! Status: **isolated.** Behind the off-by-default `fips204-backend` feature, used by no caller, and independent of the
//! legacy [`crate::MlDsaScheme`] (`pqcrypto-dilithium`), whose behavior is unchanged. It is not a `SignatureScheme`
//! implementation on purpose: that trait has no context parameter, and a silent default context would defeat domain
//! separation.
//!
//! Strictness (all tested): keys and signatures must have exactly the FIPS 204 lengths (nothing is truncated or padded);
//! a context over 255 bytes is an error for signing and verification; a secret key with an invalid encoding is an error,
//! never a panic and never a signature; [`MlDsa65Fips204::validate_keypair`] rejects a public key that does not belong to
//! the secret key and a secret key whose embedded `rho`/`tr` or vectors are inconsistent (FIPS 204 itself does not
//! require that check, and the encoding of an inconsistent key is otherwise well-formed).
//!
//! Signing: [`MlDsa65Fips204::sign`] is **hedged** (FIPS 204 default; fresh randomness from the operating-system RNG).
//! [`MlDsa65Fips204::sign_with_randomness`] takes the randomness explicitly and exists for known-answer and reproducible
//! test vectors; production code must use `sign`.
//!
//! Secrets: the returned key and signature buffers are plain `Vec<u8>`; the `fips204` key objects are zeroized on drop,
//! but copies held by callers are the callers' responsibility.

use crate::{KeyPair, SchemeId};
use fips204::ml_dsa_65 as m;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use sha3::digest::{ExtendableOutput, Update, XofReader};

pub const PUBLIC_KEY_BYTES: usize = m::PK_LEN;
pub const SECRET_KEY_BYTES: usize = m::SK_LEN;
pub const SIGNATURE_BYTES: usize = m::SIG_LEN;
pub const SEED_BYTES: usize = 32;
pub const MAX_CONTEXT_BYTES: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    ContextTooLong,
    BadPublicKeyLength,
    BadSecretKeyLength,
    BadSignatureLength,
    MalformedPublicKey,
    MalformedSecretKey,
    KeyPairInconsistent,
    VerificationFailed,
    Rng,
    SigningFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Error::ContextTooLong => "context longer than 255 bytes",
            Error::BadPublicKeyLength => "ML-DSA-65 public key must be exactly 1952 bytes",
            Error::BadSecretKeyLength => "ML-DSA-65 secret key must be exactly 4032 bytes",
            Error::BadSignatureLength => "ML-DSA-65 signature must be exactly 3309 bytes",
            Error::MalformedPublicKey => "malformed ML-DSA-65 public key",
            Error::MalformedSecretKey => "malformed ML-DSA-65 secret key encoding",
            Error::KeyPairInconsistent => "public key does not match the secret key",
            Error::VerificationFailed => "ML-DSA-65 signature verification failed",
            Error::Rng => "operating-system random number generator failed",
            Error::SigningFailed => "ML-DSA-65 signing failed",
        };
        f.write_str(s)
    }
}
impl std::error::Error for Error {}

/// FIPS 204 ML-DSA-65 through the `fips204` crate. A unit type; all functions are associated functions.
pub struct MlDsa65Fips204;

fn check_ctx(ctx: &[u8]) -> Result<(), Error> {
    if ctx.len() > MAX_CONTEXT_BYTES { Err(Error::ContextTooLong) } else { Ok(()) }
}
fn parse_sk(sk: &[u8]) -> Result<m::PrivateKey, Error> {
    let a: [u8; SECRET_KEY_BYTES] = sk.try_into().map_err(|_| Error::BadSecretKeyLength)?;
    m::PrivateKey::try_from_bytes(a).map_err(|_| Error::MalformedSecretKey)
}
fn parse_pk(pk: &[u8]) -> Result<m::PublicKey, Error> {
    let a: [u8; PUBLIC_KEY_BYTES] = pk.try_into().map_err(|_| Error::BadPublicKeyLength)?;
    m::PublicKey::try_from_bytes(a).map_err(|_| Error::MalformedPublicKey)
}

impl MlDsa65Fips204 {
    pub const fn name() -> &'static str { "ML-DSA-65 (FIPS 204, fips204 0.5.0)" }

    /// FIPS 204 `KeyGen_internal(xi)`: the key pair for a 32-byte seed (public key 1952 B, expanded secret key 4032 B).
    #[must_use]
    pub fn keygen_from_seed(seed: &[u8; SEED_BYTES]) -> KeyPair {
        let (pk, sk) = m::KG::keygen_from_seed(seed);
        KeyPair { scheme: SchemeId::MlDsa, public_key: pk.into_bytes().to_vec(), private_key: sk.into_bytes().to_vec() }
    }

    /// A fresh key pair from the operating-system RNG. Returns the 32-byte seed so it can be stored instead of the
    /// 4,032-byte expanded key; `keygen_from_seed(&seed)` reproduces the pair.
    pub fn generate() -> Result<([u8; SEED_BYTES], KeyPair), Error> {
        let mut seed = [0u8; SEED_BYTES];
        getrandom::getrandom(&mut seed).map_err(|_| Error::Rng)?;
        let kp = Self::keygen_from_seed(&seed);
        Ok((seed, kp))
    }

    /// Check that `pk` belongs to `sk`, without ever panicking on a malformed or inconsistent key:
    /// exact lengths; a valid secret-key encoding; `rho` in the secret key equals `rho` in `pk`; the embedded `tr` equals
    /// `SHAKE256(pk, 64)`; and a deterministic sign/verify self-test passes (this catches a secret key whose vectors do
    /// not match the public key). It deliberately does **not** call `fips204`'s `get_public_key`, which asserts
    /// consistency internally and panics on an inconsistent key (observed with an all-zero key).
    pub fn validate_keypair(pk: &[u8], sk: &[u8]) -> Result<(), Error> {
        if pk.len() != PUBLIC_KEY_BYTES { return Err(Error::BadPublicKeyLength); }
        if sk.len() != SECRET_KEY_BYTES { return Err(Error::BadSecretKeyLength); }
        let key = parse_sk(sk)?;
        let public = parse_pk(pk)?;
        if sk[..32] != pk[..32] { return Err(Error::KeyPairInconsistent); }
        let mut h = sha3::Shake256::default();
        h.update(pk);
        let mut tr = [0u8; 64];
        h.finalize_xof().read(&mut tr);
        if sk[64..128] != tr { return Err(Error::KeyPairInconsistent); }
        const CTX: &[u8] = b"qattice/keypair-check/v1";
        const MSG: &[u8] = b"key pair self-test";
        let sig = key.try_sign_with_seed(&[0u8; 32], MSG, CTX).map_err(|_| Error::KeyPairInconsistent)?;
        if public.verify(MSG, &sig, CTX) { Ok(()) } else { Err(Error::KeyPairInconsistent) }
    }

    /// Hedged signature (fresh OS-RNG randomness) over `message` in context `ctx`.
    pub fn sign(sk: &[u8], message: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error> {
        check_ctx(ctx)?;
        let key = parse_sk(sk)?;
        key.try_sign(message, ctx).map(|s| s.to_vec()).map_err(|_| Error::SigningFailed)
    }

    /// Signature with caller-supplied randomness (`rnd = [0; 32]` is the FIPS 204 deterministic variant). **For known-answer
    /// and reproducible test vectors only**; production signing uses [`Self::sign`].
    pub fn sign_with_randomness(sk: &[u8], message: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, Error> {
        check_ctx(ctx)?;
        let key = parse_sk(sk)?;
        key.try_sign_with_seed(rnd, message, ctx).map(|s| s.to_vec()).map_err(|_| Error::SigningFailed)
    }

    /// Verify `signature` over `message` in context `ctx`. Every failure, including a wrong length, is an `Err`.
    pub fn verify(pk: &[u8], message: &[u8], signature: &[u8], ctx: &[u8]) -> Result<(), Error> {
        check_ctx(ctx)?;
        let key = parse_pk(pk)?;
        let sig: [u8; SIGNATURE_BYTES] = signature.try_into().map_err(|_| Error::BadSignatureLength)?;
        if key.verify(message, &sig, ctx) { Ok(()) } else { Err(Error::VerificationFailed) }
    }
}
