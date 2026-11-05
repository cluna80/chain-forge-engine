//! Encrypted key storage (issue #107; docs/key-storage/SPEC.md). Library-level tests, written before the implementation.
#![cfg(feature = "signing-v2")]

use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use chain_forge_crypto::{MlDsaScheme, SignatureScheme};
use chain_forge_keygen::fsperm::sddl_owner_only;
use chain_forge_keygen::keystore::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const PASS: &str = "correct horse battery";

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qcb-ks-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    #[cfg(unix)]
    { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap(); }
    d
}

fn fast() -> CreateOptions { CreateOptions { cost: KdfCost::FLOOR, harden_existing_dir: false, prefix: "qcb".into() } }

fn make(dir: &Path, name: &str) -> (PathBuf, Created) {
    let f = dir.join(name);
    let c = create_new(&f, "alice", PASS, &fast(), &OsPlatform).expect("create");
    (f, c)
}

fn read_json(p: &Path) -> Value { serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap() }

fn tamper(p: &Path, f: impl FnOnce(&mut Value)) {
    let mut v = read_json(p);
    f(&mut v);
    std::fs::write(p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

fn flip(s: &str, at: usize) -> String {
    let mut b = s.as_bytes().to_vec();
    b[at] = if b[at] == b'0' { b'1' } else { b'0' };
    String::from_utf8(b).unwrap()
}

/// A platform whose individual side effects can be made to fail.
#[derive(Default)]
struct Hook { random: bool, prepare: bool, restrict: bool, verify_file: bool }
impl Platform for Hook {
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), Error> {
        if self.random { Err(Error::Randomness("injected".into())) } else { OsPlatform.fill_random(buf) }
    }
    fn prepare_dir(&self, d: &Path, h: bool) -> Result<bool, Error> {
        if self.prepare { Err(Error::Permission("injected".into())) } else { OsPlatform.prepare_dir(d, h) }
    }
    fn restrict_file(&self, f: &Path) -> Result<(), Error> {
        if self.restrict { Err(Error::Permission("injected".into())) } else { OsPlatform.restrict_file(f) }
    }
    fn verify_file(&self, f: &Path) -> Result<(), Error> {
        if self.verify_file { Err(Error::Permission("injected".into())) } else { OsPlatform.verify_file(f) }
    }
    fn verify_dir(&self, d: &Path) -> Result<(), Error> { OsPlatform.verify_dir(d) }
}

// ── round trip and what is on disk ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_new_key_round_trips_and_signs_under_the_conforming_backend() {
    let d = tmpdir("rt");
    let (f, c) = make(&d, "k.json");
    assert_eq!(c.payload_kind, PayloadKind::Seed, "new keys store the seed only");
    let l = load(&f, PASS, &OsPlatform).expect("load");
    assert_eq!(l.public_key, c.public_key);
    assert_eq!(l.address, c.address);
    assert_eq!(l.label, "alice");
    assert_eq!(l.payload_kind, PayloadKind::Seed);
    let sig = B::sign(&l.keypair.private_key, b"msg", b"qattice/tx/v2").unwrap();
    B::verify(&c.public_key, b"msg", &sig, b"qattice/tx/v2").expect("a signature by the loaded key verifies");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_file_holds_no_plaintext_secret_and_only_the_seed_is_encrypted() {
    let d = tmpdir("plain"); let (f, _) = make(&d, "k.json");
    let text = std::fs::read_to_string(&f).unwrap();
    let l = load(&f, PASS, &OsPlatform).unwrap();
    let sk_hex: String = l.keypair.private_key.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!text.contains(&sk_hex[..64]) && !text.contains(PASS));
    let v = read_json(&f);
    for forbidden in ["private_key", "seed", "secret_key"] { assert!(v.get(forbidden).is_none(), "{forbidden} must not be a field"); }
    assert_eq!(v["ciphertext"].as_str().unwrap().len(), 2 * (32 + 16), "seed (32) + GCM tag (16) only, not the 4,032-byte expanded key");
    assert_eq!(v["format"], "qattice-key"); assert_eq!(v["version"], 1); assert_eq!(v["payload_kind"], "seed");
    assert_eq!(v["kdf"]["algorithm"], "argon2id"); assert_eq!(v["cipher"]["algorithm"], "aes-256-gcm");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn every_file_gets_a_fresh_salt_and_nonce() {
    let d = tmpdir("fresh"); let (a, _) = make(&d, "a.json"); let (b, _) = make(&d, "b.json");
    let (va, vb) = (read_json(&a), read_json(&b));
    assert_ne!(va["kdf"]["salt"], vb["kdf"]["salt"]); assert_ne!(va["cipher"]["nonce"], vb["cipher"]["nonce"]);
    assert_ne!(va["ciphertext"], vb["ciphertext"]);
    let _ = std::fs::remove_dir_all(&d);
}

// ── wrong passphrase and tampering ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_wrong_passphrase_fails_without_returning_anything() {
    let d = tmpdir("wrong"); let (f, _) = make(&d, "k.json");
    for p in ["wrong passphrase!", "", "correct horse battery "] {
        assert!(matches!(load(&f, p, &OsPlatform), Err(Error::Decrypt)), "{p:?}");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn every_authenticated_header_field_is_bound_to_the_ciphertext() {
    let d = tmpdir("aad");
    let (other, oc) = make(&d, "other.json"); let ov = read_json(&other);
    let other_pk = ov["public_key"].as_str().unwrap().to_string();
    let other_addr = oc.address.clone();
    type Edit = Box<dyn Fn(&mut Value)>;
    let edits: Vec<(&str, Edit)> = vec![
        ("label", Box::new(|v| v["label"] = json!("mallory"))),
        ("address", Box::new(move |v| v["address"] = json!(other_addr.clone()))),
        ("public_key", Box::new(move |v| v["public_key"] = json!(other_pk.clone()))),
        ("m_cost", Box::new(|v| v["kdf"]["m_cost_kib"] = json!(19_456 + 1))),
        ("t_cost", Box::new(|v| v["kdf"]["t_cost"] = json!(3))),
        ("p_cost", Box::new(|v| v["kdf"]["p_cost"] = json!(2))),
        ("salt", Box::new(|v| v["kdf"]["salt"] = json!(flip(v["kdf"]["salt"].as_str().unwrap(), 3)))),
        ("nonce", Box::new(|v| v["cipher"]["nonce"] = json!(flip(v["cipher"]["nonce"].as_str().unwrap(), 3)))),
        ("ciphertext first byte", Box::new(|v| v["ciphertext"] = json!(flip(v["ciphertext"].as_str().unwrap(), 0)))),
        ("ciphertext tag byte", Box::new(|v| { let c = v["ciphertext"].as_str().unwrap().to_string(); v["ciphertext"] = json!(flip(&c, c.len() - 1)); })),
    ];
    for (label, edit) in edits {
        let (f, _) = make(&d, &format!("t-{}.json", label.replace(' ', "-")));
        tamper(&f, |v| edit(v));
        assert!(matches!(load(&f, PASS, &OsPlatform), Err(Error::Decrypt)), "{label}: a change must fail authentication");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn structural_damage_is_refused() {
    let d = tmpdir("struct");
    type Edit = Box<dyn Fn(&mut Value)>;
    let edits: Vec<(&str, Edit)> = vec![
        ("version 2", Box::new(|v| v["version"] = json!(2))),
        ("version as string", Box::new(|v| v["version"] = json!("1"))),
        ("format", Box::new(|v| v["format"] = json!("wallet"))),
        ("scheme", Box::new(|v| v["scheme"] = json!("ml-dsa-44"))),
        ("kdf algorithm", Box::new(|v| v["kdf"]["algorithm"] = json!("scrypt"))),
        ("kdf version", Box::new(|v| v["kdf"]["version"] = json!(16))),
        ("cipher", Box::new(|v| v["cipher"]["algorithm"] = json!("chacha20-poly1305"))),
        ("payload kind", Box::new(|v| v["payload_kind"] = json!("expanded-secret-key"))),
        ("payload kind unknown", Box::new(|v| v["payload_kind"] = json!("plaintext"))),
        ("unknown field", Box::new(|v| v["extra"] = json!(1))),
        ("unknown kdf field", Box::new(|v| v["kdf"]["extra"] = json!(1))),
        ("missing label", Box::new(|v| { v.as_object_mut().unwrap().remove("label"); })),
        ("missing ciphertext", Box::new(|v| { v.as_object_mut().unwrap().remove("ciphertext"); })),
        ("ciphertext truncated", Box::new(|v| { let c = v["ciphertext"].as_str().unwrap().to_string(); v["ciphertext"] = json!(&c[..c.len() - 2]); })),
        ("ciphertext extended", Box::new(|v| { let c = v["ciphertext"].as_str().unwrap().to_string(); v["ciphertext"] = json!(format!("{c}00")); })),
        ("not hex", Box::new(|v| v["ciphertext"] = json!("zz".repeat(48)))),
        ("uppercase hex", Box::new(|v| v["ciphertext"] = json!(v["ciphertext"].as_str().unwrap().to_uppercase()))),
        ("short public key", Box::new(|v| v["public_key"] = json!("ab".repeat(100)))),
        ("short salt", Box::new(|v| v["kdf"]["salt"] = json!("ab".repeat(8)))),
        ("short nonce", Box::new(|v| v["cipher"]["nonce"] = json!("ab".repeat(8)))),
        ("label too long", Box::new(|v| v["label"] = json!("x".repeat(129)))),
    ];
    for (label, edit) in edits {
        let (f, _) = make(&d, &format!("s-{}.json", label.replace(' ', "-")));
        tamper(&f, |v| edit(v));
        let r = load(&f, PASS, &OsPlatform);
        assert!(matches!(r, Err(Error::Format(_)) | Err(Error::Decrypt)), "{label}: must be refused, got {:?}", r.map(|_| ()));
    }
    for (label, bytes) in [("empty", b"".to_vec()), ("not json", b"{ nope".to_vec()), ("array", b"[]".to_vec()), ("oversize", vec![b' '; 70_000])] {
        let f = d.join(format!("raw-{label}.json"));
        std::fs::write(&f, bytes).unwrap();
        #[cfg(unix)]
        { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap(); }
        assert!(load(&f, PASS, &OsPlatform).is_err(), "{label}");
    }
    let _ = std::fs::remove_dir_all(&d);
}

// ── KDF bounds, passphrase policy ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn kdf_cost_outside_the_bounds_is_refused_on_create() {
    let d = tmpdir("bounds");
    for (label, c) in [
        ("memory below floor", KdfCost { m_cost_kib: 1024, ..KdfCost::FLOOR }),
        ("iterations below floor", KdfCost { t_cost: 1, ..KdfCost::FLOOR }),
        ("parallelism zero", KdfCost { p_cost: 0, ..KdfCost::FLOOR }),
        ("memory above ceiling", KdfCost { m_cost_kib: 2_000_000, ..KdfCost::FLOOR }),
        ("iterations above ceiling", KdfCost { t_cost: 11, ..KdfCost::FLOOR }),
        ("parallelism above ceiling", KdfCost { p_cost: 17, ..KdfCost::FLOOR }),
    ] {
        let f = d.join(format!("{}.json", label.replace(' ', "-")));
        let o = CreateOptions { cost: c, ..fast() };
        assert!(matches!(create_new(&f, "a", PASS, &o, &OsPlatform), Err(Error::Kdf(_))), "{label}");
        assert!(!f.exists(), "{label}: no file may be left");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_file_asking_for_a_weak_or_enormous_kdf_is_refused_before_any_key_derivation() {
    let d = tmpdir("kdfload");
    for (label, field, val) in [("tiny memory", "m_cost_kib", 8u64), ("huge memory", "m_cost_kib", 4_194_304), ("huge time", "t_cost", 1000), ("zero lanes", "p_cost", 0)] {
        let (f, _) = make(&d, &format!("{}.json", label.replace(' ', "-")));
        tamper(&f, |v| v["kdf"][field] = json!(val));
        let t = std::time::Instant::now();
        let r = load(&f, PASS, &OsPlatform);
        assert!(matches!(r, Err(Error::Kdf(_)) | Err(Error::Format(_))), "{label}: {:?}", r.map(|_| ()));
        assert!(t.elapsed().as_secs() < 2, "{label}: must be refused without running the KDF");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn weak_passphrases_are_refused_and_leave_no_file() {
    let d = tmpdir("pass");
    for p in ["", "short", "elevenchars", "            "] {
        let f = d.join("k.json");
        assert!(matches!(create_new(&f, "a", p, &fast(), &OsPlatform), Err(Error::Passphrase(_))), "{p:?}");
        assert!(!f.exists());
    }
    let _ = std::fs::remove_dir_all(&d);
}

// ── fail closed ──────────────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn failures_of_randomness_permissions_or_directory_leave_no_file() {
    let d = tmpdir("failclosed");
    let cases: Vec<(&str, Hook)> = vec![
        ("randomness", Hook { random: true, ..Default::default() }),
        ("directory preparation", Hook { prepare: true, ..Default::default() }),
        ("restricting the file", Hook { restrict: true, ..Default::default() }),
        ("verifying the file's permissions", Hook { verify_file: true, ..Default::default() }),
    ];
    for (label, hook) in cases {
        let f = d.join(format!("{}.json", label.replace(' ', "-")));
        let r = create_new(&f, "a", PASS, &fast(), &hook);
        assert!(r.is_err(), "{label}: must fail closed");
        assert!(!f.exists(), "{label}: no key file (protected or not) may be left behind");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_existing_file_is_never_overwritten() {
    let d = tmpdir("exists"); let (f, _) = make(&d, "k.json");
    let before = std::fs::read(&f).unwrap();
    assert!(matches!(create_new(&f, "again", PASS, &fast(), &OsPlatform), Err(Error::Exists(_))));
    assert_eq!(std::fs::read(&f).unwrap(), before);
    let dir_as_target = d.join("sub"); std::fs::create_dir(&dir_as_target).unwrap();
    assert!(create_new(&dir_as_target, "a", PASS, &fast(), &OsPlatform).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_missing_grandparent_directory_is_an_error_not_a_silent_mkdir_p() {
    let d = tmpdir("deep");
    let f = d.join("a").join("b").join("k.json");
    assert!(create_new(&f, "a", PASS, &fast(), &OsPlatform).is_err());
    assert!(!d.join("a").exists(), "nothing may be created");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_new_storage_directory_is_created_restricted() {
    let d = tmpdir("newdir");
    let f = d.join("keys").join("k.json");
    create_new(&f, "a", PASS, &fast(), &OsPlatform).expect("create");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(d.join("keys")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    }
    load(&f, PASS, &OsPlatform).expect("a freshly created key loads");
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn an_existing_loose_directory_is_refused_unless_hardening_is_requested() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("loose");
    let keys = d.join("keys"); std::fs::create_dir(&keys).unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o775)).unwrap();
    let f = keys.join("k.json");
    assert!(matches!(create_new(&f, "a", PASS, &fast(), &OsPlatform), Err(Error::Permission(_))));
    assert!(!f.exists());
    assert_eq!(std::fs::metadata(&keys).unwrap().permissions().mode() & 0o777, 0o775, "an existing directory is not touched without the flag");
    let o = CreateOptions { harden_existing_dir: true, ..fast() };
    create_new(&f, "a", PASS, &o, &OsPlatform).expect("explicit hardening");
    assert_eq!(std::fs::metadata(&keys).unwrap().permissions().mode() & 0o777, 0o700);
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn loading_verifies_the_real_permissions_and_refuses_a_loosened_file_or_directory() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("loosen"); let (f, _) = make(&d, "k.json");
    load(&f, PASS, &OsPlatform).expect("baseline");
    for mode in [0o644, 0o640, 0o604, 0o660, 0o666, 0o700] {
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        let r = load(&f, PASS, &OsPlatform);
        if mode == 0o700 { continue; } // owner-only (executable bit aside) is not group/other exposure
        assert!(matches!(r, Err(Error::Permission(_))), "mode {mode:o} must be refused");
    }
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(load(&f, PASS, &OsPlatform), Err(Error::Permission(_))), "a world-writable directory must be refused");
    let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(&d);
}

// ── migration from the plaintext format (#106) ───────────────────────────────────────────────────────────────────────

fn write_plain_v2(dir: &Path, name: &str) -> (PathBuf, Vec<u8>) {
    let (seed, kp) = B::generate().unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let addr = chain_forge_core::Address::from_public_key_schemed(&kp.public_key, "qcb", chain_forge_core::HashWidth::Bits256, chain_forge_core::AddressScheme::PostQuantum);
    let v = json!({ "label": "old", "scheme": "ml-dsa-65", "address": addr.as_str(), "public_key": hex(&kp.public_key), "seed": hex(&seed), "private_key": hex(&kp.private_key) });
    let f = dir.join(name);
    std::fs::write(&f, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    (f, kp.public_key)
}

#[test]
fn migrating_a_plaintext_key_keeps_the_key_encrypts_the_seed_and_leaves_the_source_untouched() {
    let d = tmpdir("mig"); let (src, pk) = write_plain_v2(&d, "old.json");
    let before = std::fs::read(&src).unwrap();
    let out = d.join("new.json");
    let c = migrate_plaintext(&src, &out, PASS, &fast(), &OsPlatform).expect("migrate");
    assert_eq!(c.payload_kind, PayloadKind::Seed);
    assert_eq!(std::fs::read(&src).unwrap(), before, "the source file must be byte-identical");
    let l = load(&out, PASS, &OsPlatform).unwrap();
    assert_eq!(l.public_key, pk);
    let v = read_json(&out);
    assert!(v.get("private_key").is_none() && v.get("seed").is_none());
    assert_eq!(v["ciphertext"].as_str().unwrap().len(), 2 * 48, "the expanded key is dropped");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn migrating_a_legacy_library_key_without_a_seed_stores_the_expanded_key_encrypted() {
    let d = tmpdir("miglegacy");
    let kp = MlDsaScheme.generate_random().unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let src = d.join("legacy.json");
    std::fs::write(&src, serde_json::to_vec(&json!({ "label": "legacy", "scheme": "mldsa65", "public_key": hex(&kp.public_key), "private_key": hex(&kp.private_key) })).unwrap()).unwrap();
    let out = d.join("new.json");
    let c = migrate_plaintext(&src, &out, PASS, &fast(), &OsPlatform).expect("migrate legacy");
    assert_eq!(c.payload_kind, PayloadKind::ExpandedSecretKey);
    assert_eq!(read_json(&out)["ciphertext"].as_str().unwrap().len(), 2 * (4032 + 16));
    let l = load(&out, PASS, &OsPlatform).unwrap();
    assert_eq!(l.payload_kind, PayloadKind::ExpandedSecretKey);
    assert_eq!(l.keypair.private_key, kp.private_key);
    let sig = B::sign(&l.keypair.private_key, b"m", b"qattice/tx/v2").unwrap();
    B::verify(&kp.public_key, b"m", &sig, b"qattice/tx/v2").expect("the migrated legacy key signs under the conforming backend");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn migration_refuses_damaged_sources_existing_outputs_and_missing_files_and_creates_nothing() {
    let d = tmpdir("migbad");
    let (src, _) = write_plain_v2(&d, "old.json");
    let good: Value = read_json(&src);
    let (other, _) = write_plain_v2(&d, "other.json"); let ov = read_json(&other);
    let cases: Vec<(&str, Value)> = vec![
        ("secret key flipped", { let mut v = good.clone(); v["private_key"] = json!(flip(good["private_key"].as_str().unwrap(), 20)); v }),
        ("seed of another key", { let mut v = good.clone(); v["seed"] = ov["seed"].clone(); v }),
        ("address of another key", { let mut v = good.clone(); v["address"] = ov["address"].clone(); v }),
        ("public key of another key", { let mut v = good.clone(); v["public_key"] = ov["public_key"].clone(); v }),
        ("truncated secret key", { let mut v = good.clone(); v["private_key"] = json!(&good["private_key"].as_str().unwrap()[..100]); v }),
    ];
    for (label, v) in cases {
        let bad = d.join("bad.json"); std::fs::write(&bad, serde_json::to_vec(&v).unwrap()).unwrap();
        let out = d.join(format!("out-{}.json", label.replace(' ', "-")));
        assert!(matches!(migrate_plaintext(&bad, &out, PASS, &fast(), &OsPlatform), Err(Error::Key(_))), "{label}");
        assert!(!out.exists(), "{label}: nothing may be created from a damaged source");
    }
    let out = d.join("exists.json"); std::fs::write(&out, b"precious").unwrap();
    assert!(matches!(migrate_plaintext(&src, &out, PASS, &fast(), &OsPlatform), Err(Error::Exists(_))));
    assert_eq!(std::fs::read(&out).unwrap(), b"precious");
    let missing = d.join("nope.json"); let out2 = d.join("o2.json");
    assert!(matches!(migrate_plaintext(&missing, &out2, PASS, &fast(), &OsPlatform), Err(Error::Io(_))));
    assert!(!out2.exists());
    let _ = std::fs::remove_dir_all(&d);
}

// ── the Windows ACL verifier (pure, so it is tested everywhere) ──────────────────────────────────────────────────────

const SID: &str = "S-1-5-21-111-222-333-1001";

#[test]
fn the_sddl_verifier_accepts_exactly_one_protected_ace_for_the_current_user() {
    for s in [
        format!("D:P(A;;FA;;;{SID})"),
        format!("D:PAI(A;;FA;;;{SID})"),
        format!("D:PAR(A;;0x1f01ff;;;{SID})"),
        format!("O:{SID}G:{SID}D:PAI(A;;FA;;;{SID})"),
        format!("D:PAI(A;;FA;;;{SID})S:AI"),
    ] { sddl_owner_only(&s, SID, false).unwrap_or_else(|e| panic!("{s}: {e}")); }
    sddl_owner_only(&format!("D:PAI(A;OICI;FA;;;{SID})"), SID, true).expect("directory with inheritable ACE");
}

#[test]
fn the_sddl_verifier_rejects_everything_else() {
    let bad: Vec<(&str, String)> = vec![
        ("not protected", format!("D:AI(A;;FA;;;{SID})")),
        ("no flags", format!("D:(A;;FA;;;{SID})")),
        ("everyone", "D:P(A;;FA;;;WD)".into()),
        ("authenticated users", "D:P(A;;FA;;;AU)".into()),
        ("builtin users", "D:P(A;;FA;;;BU)".into()),
        ("user plus system", format!("D:P(A;;FA;;;{SID})(A;;FA;;;SY)")),
        ("user plus admins", format!("D:P(A;;FA;;;{SID})(A;;FA;;;BA)")),
        ("user plus everyone read", format!("D:P(A;;FA;;;{SID})(A;;FR;;;WD)")),
        ("inherited ace", format!("D:P(A;ID;FA;;;{SID})")),
        ("different user", "D:P(A;;FA;;;S-1-5-21-111-222-333-1002)".into()),
        ("read only", format!("D:P(A;;FR;;;{SID})")),
        ("deny ace", format!("D:P(D;;FA;;;{SID})")),
        ("deny plus allow", format!("D:P(D;;FA;;;WD)(A;;FA;;;{SID})")),
        ("no aces", "D:P".into()),
        ("empty", String::new()),
        ("garbage", "not sddl at all".into()),
        ("sid prefix only", format!("D:P(A;;FA;;;{}0)", SID)),
        ("object ace", format!("D:P(OA;;FA;;;{SID})")),
    ];
    for (label, s) in bad { assert!(sddl_owner_only(&s, SID, false).is_err(), "{label}: {s:?} must be rejected"); }
    assert!(sddl_owner_only(&format!("D:P(A;;FA;;;{SID})"), SID, true).is_err(), "a directory ACE must be inheritable (OICI)");
}
