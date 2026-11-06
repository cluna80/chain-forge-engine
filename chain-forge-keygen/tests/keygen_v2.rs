//! `qcb-keygen mldsa-v2` and `check-v2` (TEST-ONLY, feature `signing-v2`). Runs the real binary.
#![cfg(feature = "signing-v2")]

use chain_forge_core::{Address, AddressScheme, HashWidth};
use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use std::path::PathBuf;
use std::process::{Command, Output};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qcb-keygen-v2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qcb-keygen")).args(args).output().unwrap()
}

fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

fn gen(dir: &std::path::Path, name: &str) -> (PathBuf, serde_json::Value, Output) {
    let f = dir.join(name);
    let o = run(&["mldsa-v2", "alice", "--out", f.to_str().unwrap()]);
    assert!(o.status.success(), "mldsa-v2 failed: {}", String::from_utf8_lossy(&o.stderr));
    let j: serde_json::Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
    (f, j, o)
}

#[test]
fn mldsa_v2_writes_a_consistent_key_file() {
    let d = tmpdir("ok"); let (_f, j, _o) = gen(&d, "k.json");
    let (seed, pk, sk) = (unhex(j["seed"].as_str().unwrap()), unhex(j["public_key"].as_str().unwrap()), unhex(j["private_key"].as_str().unwrap()));
    assert_eq!((seed.len(), pk.len(), sk.len()), (32, 1952, 4032));
    let mut s = [0u8; 32]; s.copy_from_slice(&seed);
    assert_eq!(B::keygen_from_seed(&s).public_key, pk, "the seed regenerates the public key (FIPS 204 keygen)");
    B::validate_keypair(&pk, &sk).expect("the stored key pair is consistent");
    let addr = Address::from_public_key_schemed(&pk, "qcb", HashWidth::Bits256, AddressScheme::PostQuantum);
    assert_eq!(j["address"].as_str().unwrap(), addr.as_str());
    assert_eq!(j["scheme"], "ml-dsa-65");
    assert_eq!(j["label"], "alice");
    let sig = B::sign(&sk, b"msg", b"qattice/tx/v2").unwrap();
    B::verify(&pk, b"msg", &sig, b"qattice/tx/v2").expect("a signature by the stored key verifies");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn stdout_and_stderr_carry_no_secret_material() {
    let d = tmpdir("quiet"); let (_f, j, o) = gen(&d, "k.json");
    let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(!all.contains(&j["seed"].as_str().unwrap()[..32]) && !all.contains(&j["private_key"].as_str().unwrap()[..64]));
    assert!(all.contains(j["address"].as_str().unwrap()), "the public address is reported");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_output_file_is_required_so_secrets_never_go_to_a_terminal() {
    let o = run(&["mldsa-v2", "alice"]);
    assert!(!o.status.success());
    assert!(o.stdout.is_empty(), "nothing is printed without --out");
}

#[test]
fn an_existing_file_is_never_overwritten() {
    let d = tmpdir("clobber"); let (f, _j, _o) = gen(&d, "k.json");
    let before = std::fs::read(&f).unwrap();
    let o = run(&["mldsa-v2", "alice", "--out", f.to_str().unwrap()]);
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&f).unwrap(), before, "the existing key file is untouched");
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn the_key_file_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("perm"); let (f, _j, _o) = gen(&d, "k.json");
    assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn two_runs_give_different_keys() {
    let d = tmpdir("rng");
    let (_, a, _) = gen(&d, "a.json"); let (_, b, _) = gen(&d, "b.json");
    assert_ne!(a["seed"], b["seed"]); assert_ne!(a["public_key"], b["public_key"]);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn check_v2_accepts_its_own_files_and_prints_only_public_information() {
    let d = tmpdir("check"); let (f, j, _) = gen(&d, "k.json");
    let o = run(&["check-v2", f.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(out.contains(j["address"].as_str().unwrap()));
    assert!(!out.contains(&j["seed"].as_str().unwrap()[..32]) && !out.contains(&j["private_key"].as_str().unwrap()[..64]));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn check_v2_rejects_every_kind_of_damage() {
    let d = tmpdir("damage"); let (_f, j, _) = gen(&d, "k.json");
    let flip = |s: &str| { let mut b = s.as_bytes().to_vec(); b[10] = if b[10] == b'0' { b'1' } else { b'0' }; String::from_utf8(b).unwrap() };
    let other = { let (_, o, _) = gen(&d, "other.json"); o };
    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("public key flipped", { let mut v = j.clone(); v["public_key"] = flip(j["public_key"].as_str().unwrap()).into(); v }),
        ("seed flipped", { let mut v = j.clone(); v["seed"] = flip(j["seed"].as_str().unwrap()).into(); v }),
        ("secret key flipped", { let mut v = j.clone(); v["private_key"] = flip(j["private_key"].as_str().unwrap()).into(); v }),
        ("secret key of another key", { let mut v = j.clone(); v["private_key"] = other["private_key"].clone(); v }),
        ("address of another key", { let mut v = j.clone(); v["address"] = other["address"].clone(); v }),
        ("secret key truncated", { let mut v = j.clone(); v["private_key"] = j["private_key"].as_str().unwrap()[..100].into(); v }),
        ("not hex", { let mut v = j.clone(); v["public_key"] = "zz".repeat(1952).into(); v }),
    ];
    for (label, v) in cases {
        let f = d.join("bad.json");
        std::fs::write(&f, serde_json::to_vec(&v).unwrap()).unwrap();
        let o = run(&["check-v2", f.to_str().unwrap()]);
        assert!(!o.status.success(), "{label}: must be rejected");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// A key file made by the legacy `mldsa` command (no seed, library-generated) is usable under v2: check-v2 accepts it.
#[test]
fn check_v2_accepts_a_legacy_generated_key_file() {
    let d = tmpdir("legacy");
    let o = run(&["mldsa", "legacy-key"]);
    assert!(o.status.success());
    let f = d.join("legacy.json"); std::fs::write(&f, &o.stdout).unwrap();
    let c = run(&["check-v2", f.to_str().unwrap()]);
    assert!(c.status.success(), "{}", String::from_utf8_lossy(&c.stderr));
    let _ = std::fs::remove_dir_all(&d);
}

/// Control: the legacy command is unchanged (still prints a key as before).
#[test]
fn control_the_legacy_mldsa_command_is_unchanged() {
    let o = run(&["mldsa", "x"]);
    assert!(o.status.success());
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["scheme"], "mldsa65");
    assert!(j.get("private_key").is_some());
}
