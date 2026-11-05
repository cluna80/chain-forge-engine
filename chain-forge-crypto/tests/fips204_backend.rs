//! Tests for the FIPS 204 ML-DSA-65 backend (`chain_forge_crypto::fips204_backend`, crate `fips204` 0.5.0).
//! Run with `--features fips204-backend` (add `real-pqc` to include the legacy-library comparisons).
//!
//! Fixtures: NIST ACVP FIPS 204 vectors (`vectors/fips204/mldsa65.json`, see K1 PR #95) and the Qattice signing-v2
//! vectors (`vectors/signing_v2/v2.json`, a verbatim copy of docs/mldsa-tx-signing-v2/vectors/v2.json from PR #94
//! at commit 8ba6516, sha256 e22cd494b2d1786b56db2c30a4f149ed08064ec17fa076b1518530954606e7c5).
#![cfg(feature = "fips204-backend")]

use chain_forge_crypto::fips204_backend::{Error, MlDsa65Fips204 as B, MAX_CONTEXT_BYTES, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hx(v: &Value, k: &str) -> Vec<u8> { unhex(v[k].as_str().unwrap_or_else(|| panic!("missing {k}"))) }
fn nist() -> Value { serde_json::from_str(include_str!("vectors/fips204/mldsa65.json")).unwrap() }
fn v2() -> Value { serde_json::from_str(include_str!("vectors/signing_v2/v2.json")).unwrap() }
const ZERO: [u8; 32] = [0u8; 32];

#[test]
fn sizes_are_the_fips204_ml_dsa_65_sizes() {
    assert_eq!((PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES, MAX_CONTEXT_BYTES), (1952, 4032, 3309, 255));
}

#[test]
fn nist_keygen_from_seed_matches_all_25() {
    for t in nist()["keygen"].as_array().unwrap() {
        let seed: [u8; 32] = hx(t, "seed").try_into().unwrap();
        let kp = B::keygen_from_seed(&seed);
        assert_eq!(kp.public_key, hx(t, "pk"), "pk tcId {}", t["tcId"]);
        assert_eq!(kp.private_key, hx(t, "sk"), "sk tcId {}", t["tcId"]);
    }
}

#[test]
fn nist_pure_interface_siggen_deterministic_matches_all_15() {
    let mut n = 0;
    for t in nist()["siggen"].as_array().unwrap().iter().filter(|t| t["group"] == "external-pure") {
        let sig = B::sign_with_randomness(&hx(t, "sk"), &hx(t, "message"), &hx(t, "context"), &ZERO).unwrap();
        assert_eq!(sig, hx(t, "signature"), "siggen tcId {}", t["tcId"]);
        n += 1;
    }
    assert_eq!(n, 15);
}

#[test]
fn nist_pure_interface_sigver_agrees_on_all_15_including_the_rejections() {
    let (mut n, mut rejected) = (0, 0);
    for t in nist()["sigver"].as_array().unwrap().iter().filter(|t| t["group"] == "external-pure") {
        let ok = B::verify(&hx(t, "pk"), &hx(t, "message"), &hx(t, "signature"), &hx(t, "context")).is_ok();
        assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "sigver tcId {} ({})", t["tcId"], t["reason"]);
        n += 1;
        rejected += (!ok) as u32;
    }
    assert_eq!((n, rejected), (15, 12));
}

#[test]
fn signing_v2_vectors_verify_or_fail_as_recorded() {
    let v = v2();
    assert_eq!(v["cases"].as_array().unwrap().len(), 29);
    for c in v["cases"].as_array().unwrap() {
        let r = B::verify(&hx(c, "verify_public_key_hex"), &hx(c, "preimage_hex"), &hx(c, "signature_hex"), c["context"].as_str().unwrap().as_bytes());
        assert_eq!(r.is_ok(), c["expect_valid"].as_bool().unwrap(), "case {} -> {:?}", c["name"], r);
    }
}

#[test]
fn signing_v2_valid_signatures_are_reproduced_byte_for_byte_by_this_backend() {
    let v = v2();
    let keys: Vec<(Vec<u8>, Vec<u8>)> = ["A", "B"].iter().map(|k| {
        let kp = B::keygen_from_seed(&unhex(v["keys"][k]["seed_hex"].as_str().unwrap()).try_into().unwrap());
        assert_eq!(kp.public_key, unhex(v["keys"][k]["pk_hex"].as_str().unwrap()), "key {k}");
        (kp.public_key, kp.private_key)
    }).collect();
    let mut n = 0;
    for c in v["cases"].as_array().unwrap().iter().filter(|c| c["expect_valid"].as_bool().unwrap()) {
        let signer_pk = hx(c, "pq_public_key_hex");
        let sk = &keys.iter().find(|(pk, _)| *pk == signer_pk).expect("signer key").1;
        let sig = B::sign_with_randomness(sk, &hx(c, "preimage_hex"), c["context"].as_str().unwrap().as_bytes(), &ZERO).unwrap();
        assert_eq!(sig, hx(c, "signature_hex"), "case {} differs from the Python reference signature", c["name"]);
        n += 1;
    }
    assert_eq!(n, 15);
}

#[test]
fn hedged_signing_is_randomised_and_every_signature_verifies() {
    let (_seed, kp) = B::generate().expect("OS RNG");
    let (msg, ctx) = (b"hedged".to_vec(), b"qattice/tx/v2".to_vec());
    let a = B::sign(&kp.private_key, &msg, &ctx).unwrap();
    let b = B::sign(&kp.private_key, &msg, &ctx).unwrap();
    assert_ne!(a, b, "two hedged signatures over the same input must differ");
    B::verify(&kp.public_key, &msg, &a, &ctx).unwrap();
    B::verify(&kp.public_key, &msg, &b, &ctx).unwrap();
    let d1 = B::sign_with_randomness(&kp.private_key, &msg, &ctx, &ZERO).unwrap();
    let d2 = B::sign_with_randomness(&kp.private_key, &msg, &ctx, &ZERO).unwrap();
    assert_eq!(d1, d2, "explicit randomness is reproducible (test vectors only)");
}

#[test]
fn generated_keys_come_from_the_returned_seed() {
    let (seed, kp) = B::generate().unwrap();
    assert_eq!(B::keygen_from_seed(&seed), kp);
    let (seed2, _) = B::generate().unwrap();
    assert_ne!(seed, seed2);
}

#[test]
fn context_limit_is_255_bytes_for_signing_and_verification() {
    let kp = B::keygen_from_seed(&[5u8; 32]);
    let ok = vec![0x41u8; 255];
    let sig = B::sign(&kp.private_key, b"m", &ok).unwrap();
    B::verify(&kp.public_key, b"m", &sig, &ok).unwrap();
    let long = vec![0x41u8; 256];
    assert_eq!(B::sign(&kp.private_key, b"m", &long), Err(Error::ContextTooLong));
    assert_eq!(B::sign_with_randomness(&kp.private_key, b"m", &long, &ZERO), Err(Error::ContextTooLong));
    assert_eq!(B::verify(&kp.public_key, b"m", &sig, &long), Err(Error::ContextTooLong));
}

#[test]
fn keys_and_signatures_must_have_exactly_the_right_length_nothing_is_truncated() {
    let kp = B::keygen_from_seed(&[6u8; 32]);
    let sig = B::sign(&kp.private_key, b"m", b"c").unwrap();
    for len in [0usize, 1, PUBLIC_KEY_BYTES - 1, PUBLIC_KEY_BYTES + 1] {
        let mut pk = kp.public_key.clone();
        pk.resize(len, 0xEE);
        assert_eq!(B::verify(&pk, b"m", &sig, b"c"), Err(Error::BadPublicKeyLength), "pk len {len}");
    }
    for len in [0usize, 1, SIGNATURE_BYTES - 1, SIGNATURE_BYTES + 1] {
        let mut s = sig.clone();
        s.resize(len, 0xA5);
        assert_eq!(B::verify(&kp.public_key, b"m", &s, b"c"), Err(Error::BadSignatureLength), "sig len {len}");
    }
    for len in [0usize, 1, SECRET_KEY_BYTES - 1, SECRET_KEY_BYTES + 1] {
        let mut sk = kp.private_key.clone();
        sk.resize(len, 0);
        assert_eq!(B::sign(&sk, b"m", b"c"), Err(Error::BadSecretKeyLength), "sk len {len}");
        assert_eq!(B::sign_with_randomness(&sk, b"m", b"c", &ZERO), Err(Error::BadSecretKeyLength), "sk len {len}");
    }
}

#[test]
fn a_malformed_secret_key_encoding_is_an_error_not_a_panic_and_not_a_signature() {
    let kp = B::keygen_from_seed(&[7u8; 32]);
    let mut bad = kp.private_key.clone();
    for x in &mut bad[128..160] { *x = 0xFF; }   // s1 coefficients outside [-eta, eta]
    let r = std::panic::catch_unwind(|| B::sign(&bad, b"m", b"c")).expect("must not panic");
    assert_eq!(r, Err(Error::MalformedSecretKey));
    assert_eq!(B::validate_keypair(&kp.public_key, &bad), Err(Error::MalformedSecretKey));
}

#[test]
fn validate_keypair_catches_inconsistent_and_mismatched_keys() {
    let kp = B::keygen_from_seed(&[8u8; 32]);
    let other = B::keygen_from_seed(&[9u8; 32]);
    B::validate_keypair(&kp.public_key, &kp.private_key).unwrap();
    assert_eq!(B::validate_keypair(&other.public_key, &kp.private_key), Err(Error::KeyPairInconsistent), "pk of another key");
    assert_eq!(B::validate_keypair(&vec![0u8; PUBLIC_KEY_BYTES], &vec![0u8; SECRET_KEY_BYTES]), Err(Error::KeyPairInconsistent), "all-zero pair");
    let mut bad_tr = kp.private_key.clone();
    bad_tr[64] ^= 1;   // tr must equal SHAKE256(pk)
    assert_eq!(B::validate_keypair(&kp.public_key, &bad_tr), Err(Error::KeyPairInconsistent), "wrong tr");
    let mut bad_rho = kp.private_key.clone();
    bad_rho[0] ^= 1;
    assert_eq!(B::validate_keypair(&kp.public_key, &bad_rho), Err(Error::KeyPairInconsistent), "wrong rho");
    assert_eq!(B::validate_keypair(&kp.public_key[..10], &kp.private_key), Err(Error::BadPublicKeyLength));
    assert_eq!(B::validate_keypair(&kp.public_key, &kp.private_key[..10]), Err(Error::BadSecretKeyLength));
}

#[test]
fn tampering_wrong_message_wrong_context_and_wrong_key_are_rejected() {
    let kp = B::keygen_from_seed(&[10u8; 32]);
    let other = B::keygen_from_seed(&[11u8; 32]);
    let sig = B::sign(&kp.private_key, b"message", b"qattice/tx/v2").unwrap();
    B::verify(&kp.public_key, b"message", &sig, b"qattice/tx/v2").unwrap();
    assert_eq!(B::verify(&kp.public_key, b"messagE", &sig, b"qattice/tx/v2"), Err(Error::VerificationFailed));
    assert_eq!(B::verify(&kp.public_key, b"message", &sig, b"qattice/consensus/vote/v1"), Err(Error::VerificationFailed));
    assert_eq!(B::verify(&kp.public_key, b"message", &sig, b""), Err(Error::VerificationFailed));
    assert_eq!(B::verify(&other.public_key, b"message", &sig, b"qattice/tx/v2"), Err(Error::VerificationFailed));
    for pos in [0usize, 47, 48, 1000, 3253, 3254, 3280, 3308] {
        let mut s = sig.clone();
        s[pos] ^= 1;
        assert_eq!(B::verify(&kp.public_key, b"message", &s, b"qattice/tx/v2"), Err(Error::VerificationFailed), "flip at {pos}");
    }
    assert_eq!(B::verify(&kp.public_key, b"message", &vec![0u8; SIGNATURE_BYTES], b"c"), Err(Error::VerificationFailed));
    assert_eq!(B::verify(&kp.public_key, b"message", &vec![0xFFu8; SIGNATURE_BYTES], b"c"), Err(Error::VerificationFailed));
}

// ---- comparisons with the legacy library (only when it is compiled in) -----------------------------------------

#[cfg(feature = "real-pqc")]
mod legacy {
    use super::*;
    use pqcrypto_dilithium::dilithium3;
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

    #[test]
    fn signatures_from_the_legacy_library_are_not_accepted() {
        let (pk, sk) = dilithium3::keypair();
        let ctx = b"qattice/tx/v2";
        let mut mp = vec![0u8, ctx.len() as u8];
        mp.extend_from_slice(ctx);
        mp.extend_from_slice(b"msg");
        let legacy_sig = dilithium3::detached_sign(&mp, &sk);          // standard framing, non-conformant challenge
        assert_eq!(B::verify(pk.as_bytes(), b"msg", legacy_sig.as_bytes(), ctx), Err(Error::VerificationFailed));
        let raw = dilithium3::detached_sign(b"msg", &sk);              // what the chain signs today
        assert_eq!(B::verify(pk.as_bytes(), b"msg", raw.as_bytes(), ctx), Err(Error::VerificationFailed));
    }

    #[test]
    fn key_pairs_made_by_the_legacy_library_remain_valid_keys() {
        for _ in 0..4 {
            let (pk, sk) = dilithium3::keypair();
            B::validate_keypair(pk.as_bytes(), sk.as_bytes()).expect("legacy key pairs are valid FIPS 204 keys");
            let sig = B::sign(sk.as_bytes(), b"reuse", b"qattice/tx/v2").unwrap();
            B::verify(pk.as_bytes(), b"reuse", &sig, b"qattice/tx/v2").unwrap();
        }
    }

    #[test]
    fn the_legacy_wrapper_still_truncates_an_overlong_key_but_the_new_backend_does_not() {
        let (pk, _) = dilithium3::keypair();
        let mut long = pk.as_bytes().to_vec();
        long.push(0xEE);
        let kp = B::keygen_from_seed(&[12u8; 32]);
        let sig = B::sign(&kp.private_key, b"m", b"c").unwrap();
        assert_eq!(B::verify(&long, b"m", &sig, b"c"), Err(Error::BadPublicKeyLength));
    }
}
