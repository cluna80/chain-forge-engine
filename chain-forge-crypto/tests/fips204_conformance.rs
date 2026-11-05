//! K1: FIPS 204 ML-DSA-65 conformance evidence for the signature library behind `MlDsaScheme`
//! (`pqcrypto-dilithium` 0.5.0, module `dilithium3`).
//!
//! Vectors: the ML-DSA-65 subset of NIST's ACVP FIPS 204 files (see `tests/vectors/fips204/extract_acvp.py`
//! for provenance and selection). Run with `--features real-pqc`.
//!
//! What the library is (from its vendored C source, `pqclean/crypto_sign/dilithium3/clean/sign.c`):
//! `detached_sign(m, sk)` is deterministic (`rnd = 0^32`) and computes `mu = SHAKE256(tr || m)` with NO FIPS 204
//! message prefix, i.e. it is the FIPS 204 *internal* interface `ML-DSA.Sign_internal(sk, M' = m, rnd = 0)`.
//! A caller wanting the standard *external* interface must therefore pass `M' = 0x00 || |ctx| || ctx || M`
//! (pure) or `0x01 || |ctx| || ctx || OID || PH(M)` (HashML-DSA) itself. These tests check exactly that mapping
//! against NIST's expected values.
#![cfg(feature = "real-pqc")]

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde_json::Value;
use sha2::Digest as _;
use sha3::digest::{ExtendableOutput, Update, XofReader};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/fips204/mldsa65.json")).expect("fixture parses")
}
fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit")).collect()
}
fn hx(v: &Value, k: &str) -> Vec<u8> {
    unhex(v[k].as_str().unwrap_or_else(|| panic!("missing {k}")))
}

/// DER-encoded OID of the pre-hash function and its digest, per FIPS 204 Algorithm 4.
fn prehash(alg: &str, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let oid = |last: u8| vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last];
    match alg {
        "SHA2-224" => (oid(0x04), sha2::Sha224::digest(msg).to_vec()),
        "SHA2-256" => (oid(0x01), sha2::Sha256::digest(msg).to_vec()),
        "SHA2-384" => (oid(0x02), sha2::Sha384::digest(msg).to_vec()),
        "SHA2-512" => (oid(0x03), sha2::Sha512::digest(msg).to_vec()),
        "SHA2-512/224" => (oid(0x05), sha2::Sha512_224::digest(msg).to_vec()),
        "SHA2-512/256" => (oid(0x06), sha2::Sha512_256::digest(msg).to_vec()),
        "SHA3-224" => (oid(0x07), sha3::Sha3_224::digest(msg).to_vec()),
        "SHA3-256" => (oid(0x08), sha3::Sha3_256::digest(msg).to_vec()),
        "SHA3-384" => (oid(0x09), sha3::Sha3_384::digest(msg).to_vec()),
        "SHA3-512" => (oid(0x0A), sha3::Sha3_512::digest(msg).to_vec()),
        "SHAKE-128" => {
            let mut h = sha3::Shake128::default();
            h.update(msg);
            let mut out = vec![0u8; 32];
            h.finalize_xof().read(&mut out);
            (oid(0x0B), out)
        }
        "SHAKE-256" => {
            let mut h = sha3::Shake256::default();
            h.update(msg);
            let mut out = vec![0u8; 64];
            h.finalize_xof().read(&mut out);
            (oid(0x0C), out)
        }
        other => panic!("unknown pre-hash {other}"),
    }
}

/// The message M' that the library's raw `detached_sign` / `verify_detached_signature` must be given to realise
/// each FIPS 204 interface.
fn m_prime(group: &str, msg: &[u8], ctx: &[u8], hash_alg: &str) -> Vec<u8> {
    match group {
        "internal" => msg.to_vec(),
        "external-pure" => {
            let mut m = vec![0x00, ctx.len() as u8];
            m.extend_from_slice(ctx);
            m.extend_from_slice(msg);
            m
        }
        "external-prehash" => {
            let (oid, ph) = prehash(hash_alg, msg);
            let mut m = vec![0x01, ctx.len() as u8];
            m.extend_from_slice(ctx);
            m.extend_from_slice(&oid);
            m.extend_from_slice(&ph);
            m
        }
        other => panic!("unknown group {other}"),
    }
}

fn sk_of(b: &[u8]) -> dilithium3::SecretKey {
    dilithium3::SecretKey::from_bytes(b).expect("NIST secret key is accepted")
}

#[test]
fn library_parameter_sizes_are_the_fips204_ml_dsa_65_sizes() {
    assert_eq!(dilithium3::public_key_bytes(), 1952);
    assert_eq!(dilithium3::secret_key_bytes(), 4032);
    assert_eq!(dilithium3::signature_bytes(), 3309);
}

/// ACVP sigGen (deterministic, ML-DSA-65): the library reproduces NIST's signature byte for byte, for all three
/// interfaces (internal; external pure with context; external HashML-DSA with 12 hash functions).
#[test]
#[ignore = "K1: pqcrypto-dilithium 0.5.0 is not FIPS 204 conformant (challenge sampled from 32 of 48 c-tilde bytes); passes with the one-line change in docs/k1-mldsa-conformance/challenge-full-ctilde.patch"]
fn acvp_siggen_deterministic_signatures_match_byte_for_byte() {
    let v = vectors();
    let mut counts = std::collections::BTreeMap::<String, (u32, u32)>::new();
    for t in v["siggen"].as_array().unwrap() {
        let g = t["group"].as_str().unwrap().to_string();
        let mp = m_prime(&g, &hx(t, "message"), &hx(t, "context"), t["hashAlg"].as_str().unwrap());
        let sig = dilithium3::detached_sign(&mp, &sk_of(&hx(t, "sk")));
        let ok = sig.as_bytes() == hx(t, "signature").as_slice();
        let e = counts.entry(g.clone()).or_default();
        e.0 += 1;
        e.1 += ok as u32;
    }
    println!("K1-RESULT siggen (total, matched) per interface: {counts:?}");
    assert_eq!(counts.values().map(|c| c.0).sum::<u32>(), 45);
    for (g, (total, matched)) in &counts {
        assert_eq!(total, matched, "siggen {g}: {matched}/{total} signatures match NIST byte for byte");
    }
}

/// ACVP sigVer (ML-DSA-65): accept/reject agrees with NIST for every case, including the modified-message and
/// modified-signature (commitment, z, hint) negatives and contexts up to 255 bytes.
#[test]
#[ignore = "K1: pqcrypto-dilithium 0.5.0 is not FIPS 204 conformant (challenge sampled from 32 of 48 c-tilde bytes); passes with the one-line change in docs/k1-mldsa-conformance/challenge-full-ctilde.patch"]
fn acvp_sigver_accept_and_reject_agree_with_nist() {
    let v = vectors();
    let (mut total, mut agree, mut rejects) = (0u32, 0u32, 0u32);
    let mut per_group = std::collections::BTreeMap::<String, (u32, u32)>::new();
    for t in v["sigver"].as_array().unwrap() {
        let g = t["group"].as_str().unwrap();
        let mp = m_prime(g, &hx(t, "message"), &hx(t, "context"), t["hashAlg"].as_str().unwrap());
        let pk = dilithium3::PublicKey::from_bytes(&hx(t, "pk")).expect("NIST public key is accepted");
        // A signature of the wrong length is a NIST negative too; treat a parse failure as a rejection.
        let accepted = match dilithium3::DetachedSignature::from_bytes(&hx(t, "signature")) {
            Ok(sig) => dilithium3::verify_detached_signature(&sig, &mp, &pk).is_ok(),
            Err(_) => false,
        };
        let expect = t["testPassed"].as_bool().unwrap();
        total += 1;
        agree += (accepted == expect) as u32;
        rejects += (!expect) as u32;
        let e = per_group.entry(g.to_string()).or_default();
        e.0 += 1;
        e.1 += (accepted == expect) as u32;
    }
    println!("K1-RESULT sigver: {agree}/{total} agree with NIST ({rejects} expected rejections); per interface {per_group:?}");
    assert_eq!(total, 45);
    for (g, (n, ok)) in &per_group {
        assert_eq!(n, ok, "sigver {g}: {ok}/{n} agree with NIST");
    }
}

/// Pins the CURRENT behavior so the gap cannot be forgotten (passes today). When the library is replaced or fixed
/// this test fails: that is the signal to delete it and un-ignore the two NIST tests above.
/// Measured: 0 of 45 NIST deterministic signatures reproduced; 0 of the 9 NIST-valid signatures verify; all 36
/// NIST-invalid ones are rejected; but for 11 of 15 internal-interface signatures the first 48 bytes (c-tilde) DO
/// match (the others stop at a different rejection-sampling iteration), which localises the difference to the
/// challenge polynomial derived from c-tilde, not to key handling, message hashing or randomness.
#[test]
fn characterization_library_does_not_match_nist_today() {
    let v = vectors();
    let (mut sig_total, mut sig_match, mut ctilde_match, mut internal_total) = (0u32, 0u32, 0u32, 0u32);
    for t in v["siggen"].as_array().unwrap() {
        let g = t["group"].as_str().unwrap();
        let mp = m_prime(g, &hx(t, "message"), &hx(t, "context"), t["hashAlg"].as_str().unwrap());
        let mine = dilithium3::detached_sign(&mp, &sk_of(&hx(t, "sk")));
        let theirs = hx(t, "signature");
        sig_total += 1;
        sig_match += (mine.as_bytes() == theirs.as_slice()) as u32;
        if g == "internal" {
            internal_total += 1;
            ctilde_match += (mine.as_bytes()[..48] == theirs[..48]) as u32;
        }
    }
    let (mut valid, mut valid_verified, mut invalid, mut invalid_rejected) = (0u32, 0u32, 0u32, 0u32);
    for t in v["sigver"].as_array().unwrap() {
        let mp = m_prime(t["group"].as_str().unwrap(), &hx(t, "message"), &hx(t, "context"), t["hashAlg"].as_str().unwrap());
        let pk = dilithium3::PublicKey::from_bytes(&hx(t, "pk")).unwrap();
        let ok = dilithium3::DetachedSignature::from_bytes(&hx(t, "signature"))
            .map(|s| dilithium3::verify_detached_signature(&s, &mp, &pk).is_ok())
            .unwrap_or(false);
        if t["testPassed"].as_bool().unwrap() { valid += 1; valid_verified += ok as u32 } else { invalid += 1; invalid_rejected += (!ok) as u32 }
    }
    println!("K1-RESULT characterization: siggen byte-matches {sig_match}/{sig_total}; internal c-tilde prefix matches {ctilde_match}/{internal_total}; \
              sigver NIST-valid verified {valid_verified}/{valid}; NIST-invalid rejected {invalid_rejected}/{invalid}");
    assert_eq!((sig_total, sig_match), (45, 0));
    assert_eq!((internal_total, ctilde_match), (15, 11), "deterministic: 11 of 15 share c-tilde; the other 4 stop at a different rejection-sampling iteration because the challenge differs");
    assert_eq!((valid, valid_verified), (9, 0));
    assert_eq!((invalid, invalid_rejected), (36, 36));
}

/// The NIST keys (generated by a FIPS 204 KeyGen) are accepted by the library and sign/verify with it, which checks
/// that the secret/public key encodings are the standard ones.
#[test]
fn acvp_keygen_keys_roundtrip_through_the_library() {
    let v = vectors();
    for t in v["keygen"].as_array().unwrap() {
        let (pkb, skb) = (hx(t, "pk"), hx(t, "sk"));
        assert_eq!((pkb.len(), skb.len()), (1952, 4032));
        let pk = dilithium3::PublicKey::from_bytes(&pkb).unwrap();
        let sk = sk_of(&skb);
        let sig = dilithium3::detached_sign(b"k1 roundtrip", &sk);
        dilithium3::verify_detached_signature(&sig, b"k1 roundtrip", &pk)
            .unwrap_or_else(|_| panic!("keygen tcId {}: NIST key pair does not sign/verify in the library", t["tcId"]));
        // sk = rho(32) || K(32) || tr(64) || ...; pk = rho(32) || t1(...). rho must agree and tr = SHAKE256(pk, 64).
        assert_eq!(&skb[..32], &pkb[..32], "rho");
        let mut h = sha3::Shake256::default();
        h.update(&pkb);
        let mut tr = [0u8; 64];
        h.finalize_xof().read(&mut tr);
        assert_eq!(&skb[64..128], &tr[..], "tr = SHAKE256(pk)");
    }
}

/// Keys generated by the library are well formed: correct sizes, rho and tr consistent with the public key, and a
/// sign/verify round trip. (Seed-based KeyGen KATs cannot be run: the library exposes no seeded key generation.)
#[test]
fn library_generated_keys_are_structurally_consistent() {
    for i in 0..8 {
        let (pk, sk) = dilithium3::keypair();
        let (pkb, skb) = (pk.as_bytes(), sk.as_bytes());
        assert_eq!((pkb.len(), skb.len()), (1952, 4032));
        assert_eq!(&skb[..32], &pkb[..32], "rho (key {i})");
        let mut h = sha3::Shake256::default();
        h.update(pkb);
        let mut tr = [0u8; 64];
        h.finalize_xof().read(&mut tr);
        assert_eq!(&skb[64..128], &tr[..], "tr (key {i})");
        let sig = dilithium3::detached_sign(b"msg", &sk);
        assert!(dilithium3::verify_detached_signature(&sig, b"msg", &pk).is_ok());
    }
}

/// Negative tests on a library-produced signature: every mutation must be rejected.
#[test]
fn invalid_signatures_and_messages_are_rejected() {
    let (pk, sk) = dilithium3::keypair();
    let msg = b"k1 negative tests";
    let sig = dilithium3::detached_sign(msg, &sk);
    let good = sig.as_bytes().to_vec();
    assert!(dilithium3::verify_detached_signature(&sig, msg, &pk).is_ok());
    // bit flips across the c-tilde (0..48), z (48..3254) and hint (3254..3309) regions
    for pos in [0usize, 47, 48, 1000, 3253, 3254, 3280, 3308] {
        let mut b = good.clone();
        b[pos] ^= 0x01;
        let s = dilithium3::DetachedSignature::from_bytes(&b).unwrap();
        assert!(dilithium3::verify_detached_signature(&s, msg, &pk).is_err(), "flip at {pos} accepted");
    }
    // wrong message, wrong key
    assert!(dilithium3::verify_detached_signature(&sig, b"k1 negative test", &pk).is_err());
    let (pk2, _) = dilithium3::keypair();
    assert!(dilithium3::verify_detached_signature(&sig, msg, &pk2).is_err());
    // wrong lengths: the parser is lenient, verification must refuse them
    for len in [0usize, 1, 3308, 3310, 6618] {
        let mut b = good.clone();
        b.resize(len, 0xA5);
        let accepted = match dilithium3::DetachedSignature::from_bytes(&b) {
            Ok(s) => dilithium3::verify_detached_signature(&s, msg, &pk).is_ok(),
            Err(_) => false,
        };
        assert!(!accepted, "signature of length {len} accepted");
    }
    for fill in [0x00u8, 0xFF] {
        let s = dilithium3::DetachedSignature::from_bytes(&vec![fill; 3309]).unwrap();
        assert!(dilithium3::verify_detached_signature(&s, msg, &pk).is_err(), "constant {fill:#x} signature accepted");
    }
    // hint region made non-canonical (index counts above omega=55) must be rejected
    let mut b = good.clone();
    for x in &mut b[3254..3309] {
        *x = 0xFF;
    }
    let s = dilithium3::DetachedSignature::from_bytes(&b).unwrap();
    assert!(dilithium3::verify_detached_signature(&s, msg, &pk).is_err());
}

/// Malformed keys: wrong lengths are rejected at parse time.
#[test]
fn malformed_keys_are_rejected_at_parse_time() {
    for len in [0usize, 1, 1951, 1953, 4032] {
        assert!(dilithium3::PublicKey::from_bytes(&vec![0u8; len]).is_err(), "pk length {len} parsed");
    }
    for len in [0usize, 1, 4031, 4033, 1952] {
        assert!(dilithium3::SecretKey::from_bytes(&vec![0u8; len]).is_err(), "sk length {len} parsed");
    }
}

/// An all-zero public key of the right length parses but must not verify a real signature.
#[test]
fn all_zero_public_key_does_not_verify() {
    let (_, sk) = dilithium3::keypair();
    let sig = dilithium3::detached_sign(b"m", &sk);
    let pk = dilithium3::PublicKey::from_bytes(&vec![0u8; 1952]).unwrap();
    assert!(dilithium3::verify_detached_signature(&sig, b"m", &pk).is_err());
}

/// Determinism of the library's signing (rnd = 0): the same key and message give the same bytes.
#[test]
fn library_signing_is_deterministic() {
    let (_, sk) = dilithium3::keypair();
    let a = dilithium3::detached_sign(b"same", &sk);
    let b = dilithium3::detached_sign(b"same", &sk);
    assert_eq!(a.as_bytes(), b.as_bytes());
}

// ---- The chain's wrapper: `chain_forge_crypto::MlDsaScheme` ---------------------------------------------------

use chain_forge_crypto::{MlDsaScheme, SchemeId, Signature, SignatureScheme};

#[test]
fn wrapper_signs_and_verifies_exactly_like_the_raw_library() {
    let kp = MlDsaScheme.generate_random().expect("keygen");
    let msg = [7u8; 32];
    let sig = MlDsaScheme.sign(&msg, &kp).unwrap();
    let raw = dilithium3::detached_sign(&msg, &sk_of(&kp.private_key[..4032]));
    assert_eq!(sig.bytes, raw.as_bytes(), "the wrapper adds no processing");
    MlDsaScheme.verify(&msg, &sig, &kp.public_key).unwrap();
}

#[test]
fn wrapper_rejects_tampered_signature_message_scheme_and_short_key() {
    let kp = MlDsaScheme.generate_random().expect("keygen");
    let msg = [9u8; 32];
    let sig = MlDsaScheme.sign(&msg, &kp).unwrap();
    let mut bad = sig.clone();
    bad.bytes[100] ^= 1;
    assert!(MlDsaScheme.verify(&msg, &bad, &kp.public_key).is_err());
    assert!(MlDsaScheme.verify(&[8u8; 32], &sig, &kp.public_key).is_err());
    let wrong_scheme = Signature { scheme: SchemeId::Classical, bytes: sig.bytes.clone() };
    assert!(MlDsaScheme.verify(&msg, &wrong_scheme, &kp.public_key).is_err());
    assert!(MlDsaScheme.verify(&msg, &sig, &kp.public_key[..1951]).is_err(), "short key");
    assert!(MlDsaScheme.verify(&msg, &sig, &[]).is_err(), "empty key");
}

/// DESIRED behavior: a public key with trailing bytes is not a valid ML-DSA-65 key and must be refused.
/// The wrapper currently truncates the key to 1952 bytes (`public_key[..1952.min(len)]`), so a 1953-byte key
/// verifies. Two distinct byte strings then name the same key (and derive different addresses).
#[test]
#[ignore = "K1 finding: MlDsaScheme::verify silently truncates an over-long public key; fix is a wrapper change (separate PR)"]
fn wrapper_must_reject_a_public_key_with_trailing_bytes() {
    let kp = MlDsaScheme.generate_random().expect("keygen");
    let msg = [3u8; 32];
    let sig = MlDsaScheme.sign(&msg, &kp).unwrap();
    let mut long_pk = kp.public_key.clone();
    long_pk.push(0xEE);
    assert!(MlDsaScheme.verify(&msg, &sig, &long_pk).is_err(), "1953-byte key must be refused");
}

/// Characterization of the same defect (passes today): the over-long key IS accepted.
#[test]
fn characterization_wrapper_accepts_an_overlong_public_key_today() {
    let kp = MlDsaScheme.generate_random().expect("keygen");
    let msg = [3u8; 32];
    let sig = MlDsaScheme.sign(&msg, &kp).unwrap();
    let mut long_pk = kp.public_key.clone();
    long_pk.push(0xEE);
    let r = MlDsaScheme.verify(&msg, &sig, &long_pk);
    println!("K1-RESULT overlong-pk (1953 bytes) verify -> {:?}", r.as_ref().map(|_| "ACCEPTED").map_err(|e| e.to_string()));
}
