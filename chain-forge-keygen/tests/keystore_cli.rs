//! `qcb-keygen key-new | key-check | key-migrate` (issue #107). Runs the real binary; written before the implementation.
#![cfg(feature = "signing-v2")]

use chain_forge_crypto::fips204_backend::MlDsa65Fips204 as B;
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PASS: &str = "correct horse battery";
const FAST: [&str; 6] = ["--kdf-memory-kib", "19456", "--kdf-iterations", "2", "--kdf-parallelism", "1"];

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qcb-ksc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    chain_forge_keygen::fsperm::prepare_dir(&d, true).expect("harden the test directory");
    d
}

fn passfile(d: &Path) -> PathBuf {
    let p = d.join("pass.txt");
    std::fs::write(&p, format!("{PASS}\n")).unwrap();
    p
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qcb-keygen")).args(args).env_remove("QCB_KEY_PASSPHRASE").output().unwrap()
}

fn text(o: &Output) -> String { format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)) }

fn new_key(d: &Path, name: &str) -> (PathBuf, Output) {
    let f = d.join(name);
    let pf = passfile(d);
    let mut a = vec!["key-new", "alice", "--out", f.to_str().unwrap(), "--passphrase-file", pf.to_str().unwrap()];
    a.extend(FAST);
    let o = run(&a);
    (f, o)
}

#[test]
fn key_new_then_key_check_round_trips_and_prints_only_public_information() {
    let d = tmpdir("rt"); let (f, o) = new_key(&d, "k.json");
    assert!(o.status.success(), "{}", text(&o));
    let v: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
    let addr = v["address"].as_str().unwrap();
    assert!(text(&o).contains(addr), "the public address is reported");
    let pf = passfile(&d);
    let c = run(&["key-check", f.to_str().unwrap(), "--passphrase-file", pf.to_str().unwrap()]);
    assert!(c.status.success(), "{}", text(&c));
    assert!(text(&c).contains(addr));
    // Nothing secret, neither the passphrase nor any key material, is ever printed.
    for t in [text(&o), text(&c)] {
        assert!(!t.contains(PASS));
        assert!(!t.contains(v["ciphertext"].as_str().unwrap()));
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_default_cost_is_the_production_cost() {
    let d = tmpdir("prod");
    let f = d.join("k.json"); let pf = passfile(&d);
    let o = run(&["key-new", "alice", "--out", f.to_str().unwrap(), "--passphrase-file", pf.to_str().unwrap()]);
    assert!(o.status.success(), "{}", text(&o));
    let v: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
    assert_eq!((v["kdf"]["m_cost_kib"].as_u64(), v["kdf"]["t_cost"].as_u64(), v["kdf"]["p_cost"].as_u64()), (Some(131_072), Some(3), Some(4)));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_passphrase_is_never_accepted_on_the_command_line() {
    let d = tmpdir("argv");
    let f = d.join("k.json");
    let mut a = vec!["key-new", "alice", "--out", f.to_str().unwrap(), "--passphrase", "correct horse battery"];
    a.extend(FAST);
    let o = run(&a);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(!f.exists());
    assert!(!text(&o).contains(PASS), "the rejected passphrase must not be echoed");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_passphrase_can_come_from_the_environment_or_stdin() {
    let d = tmpdir("env");
    let f = d.join("e.json");
    let mut a = vec!["key-new", "alice", "--out", f.to_str().unwrap()]; a.extend(FAST);
    let o = Command::new(env!("CARGO_BIN_EXE_qcb-keygen")).args(&a).env("QCB_KEY_PASSPHRASE", PASS).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let g = d.join("s.json");
    let mut a = vec!["key-new", "alice", "--out", g.to_str().unwrap()]; a.extend(FAST);
    let mut child = Command::new(env!("CARGO_BIN_EXE_qcb-keygen")).args(&a).env_remove("QCB_KEY_PASSPHRASE")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(format!("{PASS}\n").as_bytes()).unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_wrong_or_weak_passphrase_fails_and_creates_nothing() {
    let d = tmpdir("bad"); let (f, _) = new_key(&d, "k.json");
    let wrong = d.join("wrong.txt"); std::fs::write(&wrong, "not the passphrase!!\n").unwrap();
    let c = run(&["key-check", f.to_str().unwrap(), "--passphrase-file", wrong.to_str().unwrap()]);
    assert_eq!(c.status.code(), Some(1)); assert!(c.stdout.is_empty(), "no key information on failure");
    let weak = d.join("weak.txt"); std::fs::write(&weak, "short\n").unwrap();
    let g = d.join("g.json");
    let mut a = vec!["key-new", "x", "--out", g.to_str().unwrap(), "--passphrase-file", weak.to_str().unwrap()]; a.extend(FAST);
    let o = run(&a);
    assert_eq!(o.status.code(), Some(1)); assert!(!g.exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn kdf_flags_below_the_floor_or_above_the_ceiling_are_refused() {
    let d = tmpdir("kdf"); let pf = passfile(&d);
    for (m, t, p) in [("1024", "2", "1"), ("19456", "1", "1"), ("19456", "2", "0"), ("9999999", "2", "1")] {
        let f = d.join(format!("{m}-{t}-{p}.json"));
        let o = run(&["key-new", "x", "--out", f.to_str().unwrap(), "--passphrase-file", pf.to_str().unwrap(), "--kdf-memory-kib", m, "--kdf-iterations", t, "--kdf-parallelism", p]);
        assert_eq!(o.status.code(), Some(1), "{m}/{t}/{p}: {}", text(&o));
        assert!(!f.exists());
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn key_new_never_overwrites() {
    let d = tmpdir("clobber"); let (f, _) = new_key(&d, "k.json");
    let before = std::fs::read(&f).unwrap();
    let (_, o) = new_key(&d, "k.json");
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(std::fs::read(&f).unwrap(), before);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn key_migrate_encrypts_without_touching_or_printing_the_old_file() {
    let d = tmpdir("mig");
    let (seed, kp) = B::generate().unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let src = d.join("old.json");
    std::fs::write(&src, serde_json::to_vec_pretty(&json!({ "label": "old", "scheme": "ml-dsa-65", "public_key": hex(&kp.public_key), "seed": hex(&seed), "private_key": hex(&kp.private_key) })).unwrap()).unwrap();
    let before = std::fs::read(&src).unwrap();
    let out = d.join("new.json"); let pf = passfile(&d);
    let mut a = vec!["key-migrate", "--from", src.to_str().unwrap(), "--out", out.to_str().unwrap(), "--passphrase-file", pf.to_str().unwrap()]; a.extend(FAST);
    let o = run(&a);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(&src).unwrap(), before, "the plaintext source is untouched");
    let t = text(&o);
    assert!(!t.contains(&hex(&seed)[..32]) && !t.contains(&hex(&kp.private_key)[64..128]) && !t.contains(PASS));
    assert!(t.to_lowercase().contains("not deleted") || t.to_lowercase().contains("still exists"), "the operator is told the old file remains: {t}");
    let c = run(&["key-check", out.to_str().unwrap(), "--passphrase-file", pf.to_str().unwrap()]);
    assert!(c.status.success(), "{}", text(&c));
    // A second migration onto the same output is refused.
    let mut a2 = vec!["key-migrate", "--from", src.to_str().unwrap(), "--out", out.to_str().unwrap(), "--passphrase-file", pf.to_str().unwrap()]; a2.extend(FAST);
    assert_eq!(run(&a2).status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn usage_errors_exit_two() {
    for a in [&["key-new"][..], &["key-check"], &["key-migrate"], &["key-new", "x"], &["key-new", "x", "--bogus"]] {
        assert_eq!(run(a).status.code(), Some(2), "{a:?}");
    }
}

#[cfg(unix)]
#[test]
fn the_cli_creates_owner_only_files_and_directories() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("perm"); let pf = passfile(&d);
    let f = d.join("keys").join("k.json");
    let mut a = vec!["key-new", "x", "--out", f.to_str().unwrap(), "--passphrase-file", pf.to_str().unwrap()]; a.extend(FAST);
    assert!(run(&a).status.success());
    assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(d.join("keys")).unwrap().permissions().mode() & 0o777, 0o700);
    let _ = std::fs::remove_dir_all(&d);
}
