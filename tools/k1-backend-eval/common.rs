//! Shared harness: runs the same NIST ACVP ML-DSA-65 vectors against any backend that implements `Backend`.
//! A method that returns `None` means the backend's public API does not expose that operation (reported as N/A,
//! never as a pass).
#![allow(dead_code)]
use serde_json::{json, Value};
use sha2::Digest as _;
use sha3::digest::{ExtendableOutput, Update, XofReader};

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
pub fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
pub fn hx(v: &Value, k: &str) -> Vec<u8> { unhex(v[k].as_str().unwrap_or_else(|| panic!("missing {k}"))) }

/// (DER OID, digest) of the FIPS 204 HashML-DSA pre-hash.
pub fn prehash(alg: &str, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
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
        "SHAKE-128" => { let mut h = sha3::Shake128::default(); h.update(msg); let mut o = vec![0u8; 32]; h.finalize_xof().read(&mut o); (oid(0x0B), o) }
        "SHAKE-256" => { let mut h = sha3::Shake256::default(); h.update(msg); let mut o = vec![0u8; 64]; h.finalize_xof().read(&mut o); (oid(0x0C), o) }
        other => panic!("unknown pre-hash {other}"),
    }
}

pub trait Backend {
    fn name() -> &'static str;
    /// a fresh random key pair (for backends without seeded keygen)
    fn random_keypair() -> Option<(Vec<u8>, Vec<u8>)> { None }
    /// false when the backend's signing is randomized-only, so byte-for-byte KATs cannot apply
    fn deterministic_kat() -> bool { true }
    /// FIPS 204 KeyGen_internal(xi) -> (pk, sk_expanded)
    fn keygen_from_seed(_seed: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> { None }
    /// Sign_internal(sk, M', rnd)
    fn sign_internal(_sk: &[u8], _mp: &[u8], _rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> { None }
    /// ML-DSA.Sign (pure, external) with context
    fn sign_pure(_sk: &[u8], _msg: &[u8], _ctx: &[u8], _rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> { None }
    /// HashML-DSA.Sign with the named pre-hash
    fn sign_prehash(_sk: &[u8], _msg: &[u8], _ctx: &[u8], _alg: &str, _rnd: &[u8; 32]) -> Option<Result<Vec<u8>, String>> { None }
    fn verify_internal(_pk: &[u8], _mp: &[u8], _sig: &[u8]) -> Option<bool> { None }
    fn verify_pure(_pk: &[u8], _msg: &[u8], _ctx: &[u8], _sig: &[u8]) -> Option<bool> { None }
    fn verify_prehash(_pk: &[u8], _msg: &[u8], _ctx: &[u8], _alg: &str, _sig: &[u8]) -> Option<bool> { None }
}

#[derive(Default)]
struct Tally { total: u32, pass: u32, na: u32 }
impl Tally {
    fn to_json(&self) -> Value { json!({"total": self.total, "pass": self.pass, "not_exposed": self.na}) }
}

/// Run every vector. Returns a JSON summary; failures are listed by tcId.
pub fn run_kat<B: Backend>(fixture: &Value) -> Value {
    let mut keygen = Tally::default();
    let mut keygen_fail = vec![];
    for t in fixture["keygen"].as_array().unwrap() {
        keygen.total += 1;
        let seed: [u8; 32] = hx(t, "seed").try_into().unwrap();
        match B::keygen_from_seed(&seed) {
            None => keygen.na += 1,
            Some((pk, sk)) => {
                if pk == hx(t, "pk") && sk == hx(t, "sk") { keygen.pass += 1 } else { keygen_fail.push(t["tcId"].clone()) }
            }
        }
    }
    let zero = [0u8; 32];
    let mut sg: std::collections::BTreeMap<String, Tally> = Default::default();
    let mut sg_fail: Vec<Value> = vec![];
    for t in fixture["siggen"].as_array().unwrap() {
        let g = t["group"].as_str().unwrap();
        let (sk, msg, ctx, alg, want) = (hx(t, "sk"), hx(t, "message"), hx(t, "context"), t["hashAlg"].as_str().unwrap(), hx(t, "signature"));
        let r = match g {
            "internal" => B::sign_internal(&sk, &msg, &zero),
            "external-pure" => B::sign_pure(&sk, &msg, &ctx, &zero),
            _ => B::sign_prehash(&sk, &msg, &ctx, alg, &zero),
        };
        let e = sg.entry(g.to_string()).or_default();
        e.total += 1;
        let r = if B::deterministic_kat() { r } else { None };
        match r {
            None => e.na += 1,
            Some(Ok(sig)) if sig == want => e.pass += 1,
            Some(other) => sg_fail.push(json!({"group": g, "tcId": t["tcId"], "hashAlg": alg, "err": other.err()})),
        }
    }
    let mut sv: std::collections::BTreeMap<String, Tally> = Default::default();
    let mut sv_fail: Vec<Value> = vec![];
    for t in fixture["sigver"].as_array().unwrap() {
        let g = t["group"].as_str().unwrap();
        let (pk, msg, ctx, alg, sig) = (hx(t, "pk"), hx(t, "message"), hx(t, "context"), t["hashAlg"].as_str().unwrap(), hx(t, "signature"));
        let want = t["testPassed"].as_bool().unwrap();
        let r = match g {
            "internal" => B::verify_internal(&pk, &msg, &sig),
            "external-pure" => B::verify_pure(&pk, &msg, &ctx, &sig),
            _ => B::verify_prehash(&pk, &msg, &ctx, alg, &sig),
        };
        let e = sv.entry(g.to_string()).or_default();
        e.total += 1;
        match r {
            None => e.na += 1,
            Some(got) if got == want => e.pass += 1,
            Some(got) => sv_fail.push(json!({"group": g, "tcId": t["tcId"], "hashAlg": alg, "expected": want, "got": got, "reason": t["reason"]})),
        }
    }
    json!({
        "backend": B::name(),
        "keygen_from_seed": keygen.to_json(), "keygen_failures": keygen_fail,
        "siggen_deterministic": sg.iter().map(|(k, v)| (k.clone(), v.to_json())).collect::<serde_json::Map<_, _>>(), "siggen_failures": sg_fail,
        "sigver": sv.iter().map(|(k, v)| (k.clone(), v.to_json())).collect::<serde_json::Map<_, _>>(), "sigver_failures": sv_fail,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Negative / malformed-input tests, interoperability files and a micro-benchmark, generic over `Backend`.
// ---------------------------------------------------------------------------------------------------------------
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Portable stand-in for fresh randomness (hedged-signing test inputs only; not a CSPRNG and not for production).
fn os_random32() -> [u8; 32] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, n.to_le_bytes());
    sha2::Digest::update(&mut h, CTR.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    sha2::Digest::update(&mut h, std::process::id().to_le_bytes());
    h.finalize().into()
}

/// Outcome of a call that must reject: "rejected", "ACCEPTED" (bad), or "PANIC" (bad).
fn outcome_verify<F: FnOnce() -> Option<bool>>(f: F) -> &'static str {
    match catch_unwind(AssertUnwindSafe(f)) {
        Err(_) => "PANIC",
        Ok(None) => "n/a",
        Ok(Some(true)) => "ACCEPTED",
        Ok(Some(false)) => "rejected",
    }
}

pub fn run_neg<B: Backend>() -> Value {
    std::panic::set_hook(Box::new(|_| {})); // silence expected panics; they are reported as PANIC
    let seed = [7u8; 32];
    let (pk, sk) = match B::keygen_from_seed(&seed) {
        Some(x) => x,
        None => {
            // no seeded keygen: borrow a fixed NIST key so the negatives still run
            let f: Value = serde_json::from_str(include_str!("../../chain-forge-crypto/tests/vectors/fips204/mldsa65.json")).unwrap();
            let t = &f["keygen"][0];
            (hx(t, "pk"), hx(t, "sk"))
        }
    };
    let (msg, ctx) = (b"qattice negative tests".to_vec(), b"ctx".to_vec());
    let sig = match B::sign_pure(&sk, &msg, &ctx, &[0u8; 32]) {
        Some(Ok(s)) => s,
        other => return json!({"backend": B::name(), "error": format!("cannot sign: {:?}", other.map(|r| r.err()))}),
    };
    let mut r = serde_json::Map::new();
    let mut put = |k: &str, v: String| { r.insert(k.to_string(), Value::String(v)); };
    put("valid_signature_verifies", format!("{}", outcome_verify(|| B::verify_pure(&pk, &msg, &ctx, &sig)) == "ACCEPTED"));
    // bit flips across c-tilde (0..48), z, hint (last 55 bytes)
    let n = sig.len();
    let mut flips = vec![];
    for pos in [0usize, 47, 48, 1000, n - 56, n - 55, n - 20, n - 1] {
        let mut b = sig.clone(); b[pos] ^= 1;
        flips.push(outcome_verify(|| B::verify_pure(&pk, &msg, &ctx, &b)));
    }
    put("bit_flips_8_positions", flips.join(","));
    put("wrong_message", outcome_verify(|| B::verify_pure(&pk, b"other", &ctx, &sig)).into());
    put("wrong_context", outcome_verify(|| B::verify_pure(&pk, &msg, b"other", &sig)).into());
    let mut pk2 = pk.clone(); pk2[100] ^= 1;
    put("wrong_public_key", outcome_verify(|| B::verify_pure(&pk2, &msg, &ctx, &sig)).into());
    let lens: Vec<&str> = [0usize, 1, n - 1, n + 1, 2 * n].iter().map(|&l| {
        let mut b = sig.clone(); b.resize(l, 0xA5);
        outcome_verify(|| B::verify_pure(&pk, &msg, &ctx, &b))
    }).collect();
    put("signature_wrong_lengths_0_1_n-1_n+1_2n", lens.join(","));
    put("signature_all_zero", outcome_verify(|| B::verify_pure(&pk, &msg, &ctx, &vec![0u8; n])).into());
    put("signature_all_ff", outcome_verify(|| B::verify_pure(&pk, &msg, &ctx, &vec![0xFFu8; n])).into());
    let mut hint_ff = sig.clone(); for x in &mut hint_ff[n - 55..] { *x = 0xFF; }
    put("hint_region_noncanonical_ff", outcome_verify(|| B::verify_pure(&pk, &msg, &ctx, &hint_ff)).into());
    let pk_lens: Vec<&str> = [0usize, 1, pk.len() - 1, pk.len() + 1].iter().map(|&l| {
        let mut b = pk.clone(); b.resize(l, 0xEE);
        outcome_verify(|| B::verify_pure(&b, &msg, &ctx, &sig))
    }).collect();
    put("public_key_wrong_lengths_0_1_n-1_n+1", pk_lens.join(","));
    put("public_key_all_zero", outcome_verify(|| B::verify_pure(&vec![0u8; pk.len()], &msg, &ctx, &sig)).into());
    // signing with malformed secret keys must return an error, not panic and not produce a signature
    let sign_outcome = |skb: &[u8]| -> &'static str {
        match catch_unwind(AssertUnwindSafe(|| B::sign_pure(skb, &msg, &ctx, &[0u8; 32]))) {
            Err(_) => "PANIC",
            Ok(None) => "n/a",
            Ok(Some(Err(_))) => "rejected",
            Ok(Some(Ok(_))) => "SIGNED",
        }
    };
    let sk_lens: Vec<&str> = [0usize, 1, sk.len() - 1, sk.len() + 1].iter().map(|&l| { let mut b = sk.clone(); b.resize(l, 0); sign_outcome(&b) }).collect();
    put("secret_key_wrong_lengths_0_1_n-1_n+1", sk_lens.join(","));
    let mut bad_eta = sk.clone(); for x in &mut bad_eta[128..160] { *x = 0xFF; } // s1 coefficients outside [-eta, eta]
    put("secret_key_invalid_eta_encoding", sign_outcome(&bad_eta).into());
    let mut bad_tr = sk.clone(); bad_tr[64] ^= 1; // tr no longer equals H(pk)
    put("secret_key_inconsistent_tr", sign_outcome(&bad_tr).into());
    put("secret_key_all_zero", sign_outcome(&vec![0u8; sk.len()]).into());
    // context longer than 255 bytes
    let long_ctx = vec![1u8; 256];
    let sc = match catch_unwind(AssertUnwindSafe(|| B::sign_pure(&sk, &msg, &long_ctx, &[0u8; 32]))) {
        Err(_) => "PANIC", Ok(None) => "n/a", Ok(Some(Err(_))) => "rejected", Ok(Some(Ok(_))) => "SIGNED(!)" };
    put("sign_with_256_byte_context", sc.into());
    put("verify_with_256_byte_context", outcome_verify(|| B::verify_pure(&pk, &msg, &long_ctx, &sig)).into());
    json!({"backend": B::name(), "negative_tests": r})
}

/// Interop file: for 6 seeds x 4 messages x contexts (empty, short, 255 bytes): deterministic signature
/// (rnd = 0) and, where the backend can, a hedged one (random rnd).
pub fn gen_interop<B: Backend>() -> Value {
    let mut out = vec![];
    let ctxs: Vec<Vec<u8>> = vec![vec![], b"qattice/tx/v2".to_vec(), vec![0xAB; 255]];
    let msgs: Vec<Vec<u8>> = vec![vec![], vec![0x42], (0..300u32).map(|i| (i * 7) as u8).collect(), vec![0xFF; 2000]];
    for s in 0..6u8 {
        let mut seed = [0u8; 32]; seed[0] = s; seed[31] = 0xA0 ^ s;
        let (pk, sk) = match B::keygen_from_seed(&seed) { Some(x) => x, None => {
            // backend has no seeded keygen: use the s-th NIST keyGen key pair instead
            let f: Value = serde_json::from_str(include_str!("../../chain-forge-crypto/tests/vectors/fips204/mldsa65.json")).unwrap();
            let t = &f["keygen"][s as usize]; (hx(t, "pk"), hx(t, "sk")) } };
        for ctx in &ctxs { for msg in &msgs {
            for hedged in [false, true] {
                let rnd = if hedged { os_random32() } else { [0u8; 32] };
                if let Some(Ok(sig)) = B::sign_pure(&sk, msg, ctx, &rnd) {
                    out.push(json!({"signer": B::name(), "hedged": hedged, "pk": hex(&pk), "msg": hex(msg), "ctx": hex(ctx), "sig": hex(&sig)}));
                }
            }
        }}
    }
    json!({"signer": B::name(), "cases": out})
}

pub fn verify_interop<B: Backend>(file: &Value) -> Value {
    let (mut total, mut ok, mut neg_total, mut neg_rejected) = (0u32, 0u32, 0u32, 0u32);
    for c in file["cases"].as_array().unwrap() {
        let (pk, msg, ctx, sig) = (hx(c, "pk"), hx(c, "msg"), hx(c, "ctx"), hx(c, "sig"));
        match B::verify_pure(&pk, &msg, &ctx, &sig) { None => return json!({"verifier": B::name(), "error": "no pure verify"}), Some(v) => { total += 1; ok += v as u32 } }
        // mutated copies must be rejected
        let mut bad = sig.clone(); let i = (total as usize * 37) % bad.len(); bad[i] ^= 0x10;
        neg_total += 1; neg_rejected += (B::verify_pure(&pk, &msg, &ctx, &bad) == Some(false)) as u32;
        let mut badm = msg.clone(); badm.push(1);
        neg_total += 1; neg_rejected += (B::verify_pure(&pk, &badm, &ctx, &sig) == Some(false)) as u32;
    }
    json!({"verifier": B::name(), "signer": file["signer"], "valid_total": total, "valid_accepted": ok, "mutated_total": neg_total, "mutated_rejected": neg_rejected})
}

pub fn bench<B: Backend>() -> Value {
    use std::time::Instant;
    let seed = [9u8; 32];
    let (pk, sk) = match B::keygen_from_seed(&seed) { Some(x) => x, None => {
        let f: Value = serde_json::from_str(include_str!("../../chain-forge-crypto/tests/vectors/fips204/mldsa65.json")).unwrap();
        let t = &f["keygen"][0]; (hx(t, "pk"), hx(t, "sk")) } };
    let msg = [0x5Au8; 32];
    let rnd = [0u8; 32];
    let time = |n: u32, f: &mut dyn FnMut()| -> f64 { for _ in 0..3 { f(); } let t = Instant::now(); for _ in 0..n { f(); } t.elapsed().as_secs_f64() * 1e6 / n as f64 };
    let kg = if B::keygen_from_seed(&seed).is_some() { Some(time(200, &mut || { let _ = B::keygen_from_seed(&seed); })) } else { None };
    // Vary the message so that rejection sampling averages out (a fixed message repeats one signing path).
    let mut ctr = 0u64;
    let sg = time(600, &mut || { ctr += 1; let mut m = [0x5Au8; 32]; m[..8].copy_from_slice(&ctr.to_le_bytes()); let _ = B::sign_pure(&sk, &m, b"", &rnd); });
    let sigs: Vec<(Vec<u8>, [u8; 32])> = (0..64u64).map(|i| { let mut m = [0x5Au8; 32]; m[..8].copy_from_slice(&i.to_le_bytes()); (B::sign_pure(&sk, &m, b"", &rnd).unwrap().unwrap(), m) }).collect();
    let mut j = 0usize;
    let vf = time(2000, &mut || { j = (j + 1) % sigs.len(); let _ = B::verify_pure(&pk, &sigs[j].1, b"", &sigs[j].0); });
    json!({"backend": B::name(), "keygen_us": kg, "sign_us": sg, "verify_us": vf})
}

pub fn gen_keys<B: Backend>() -> Value {
    let mut out = vec![];
    for s in 0..6u8 {
        let mut seed = [0u8; 32]; seed[0] = s; seed[31] = 0xC0 ^ s;
        let (kind, kp) = match B::keygen_from_seed(&seed) { Some(x) => ("seeded", Some(x)), None => ("random", B::random_keypair()) };
        if let Some((pk, sk)) = kp { out.push(json!({"kind": kind, "seed": hex(&seed), "pk": hex(&pk), "sk": hex(&sk)})); }
    }
    json!({"backend": B::name(), "keys": out})
}

/// Run keygen + sign + verify on a thread with the given stack size; exit code tells whether it survived.
pub fn stack_probe<B: Backend>(bytes: usize) {
    // Parse the fixture OUTSIDE the probed thread so only the cryptographic calls are measured.
    let f: Value = serde_json::from_str(include_str!("../../chain-forge-crypto/tests/vectors/fips204/mldsa65.json")).unwrap();
    let t = &f["keygen"][0];
    let (pk, sk) = (hx(t, "pk"), hx(t, "sk"));
    let h = std::thread::Builder::new().stack_size(bytes).spawn(move || {
        let _ = B::keygen_from_seed(&[1u8; 32]);
        let sig = B::sign_pure(&sk, b"m", b"", &[0u8; 32]).unwrap().unwrap();
        assert_eq!(B::verify_pure(&pk, b"m", b"", &sig), Some(true));
    }).unwrap();
    h.join().expect("thread failed");
    println!("ok");
}

/// Re-sign with key pairs supplied in a keys file (e.g. produced by the CURRENT chain library) to show key reuse.
pub fn sign_keys<B: Backend>(file: &Value) -> Value {
    let mut out = vec![];
    for k in file["keys"].as_array().unwrap() {
        let (pk, sk) = (hx(k, "pk"), hx(k, "sk"));
        for ctx in [&b""[..], &b"qattice/tx/v2"[..]] {
            let msg = b"re-signed with a conformant backend".to_vec();
            match B::sign_pure(&sk, &msg, ctx, &[0u8; 32]) {
                Some(Ok(sig)) => out.push(json!({"hedged": false, "pk": hex(&pk), "msg": hex(&msg), "ctx": hex(ctx), "sig": hex(&sig)})),
                other => out.push(json!({"error": format!("{:?}", other.map(|r| r.err())), "pk": hex(&pk), "msg": hex(&msg), "ctx": hex(ctx), "sig": ""})),
            }
        }
    }
    json!({"signer": B::name(), "cases": out})
}

pub fn main_for<B: Backend>() {
    let args: Vec<String> = std::env::args().collect();
    let fixture = || -> Value { serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap() };
    let v = match args.get(1).map(|s| s.as_str()) {
        Some("kat") => run_kat::<B>(&fixture()),
        Some("neg") => run_neg::<B>(),
        Some("gen-interop") => gen_interop::<B>(),
        Some("verify-interop") => verify_interop::<B>(&fixture()),
        Some("bench") => bench::<B>(),
        Some("keys") => gen_keys::<B>(),
        Some("sign-keys") => sign_keys::<B>(&fixture()),
        Some("stack") => { stack_probe::<B>(args[2].parse().unwrap()); return; }
        _ => { eprintln!("usage: <kat|verify-interop> <json> | neg | gen-interop | bench"); std::process::exit(2) }
    };
    println!("{}", serde_json::to_string(&v).unwrap());
}
