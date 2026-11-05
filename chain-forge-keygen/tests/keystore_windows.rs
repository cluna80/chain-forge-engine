//! Windows ACL tests for encrypted key storage (issue #107). They apply real ACLs through the real file system and read the
//! resulting DACL back; they do not trust the return value of the ACL-setting call. Run on Windows only.
#![cfg(all(windows, feature = "signing-v2"))]

use chain_forge_keygen::fsperm::{current_user_sid, read_sddl, sddl_owner_only};
use chain_forge_keygen::keystore::*;
use std::path::{Path, PathBuf};
use std::process::Command;

const PASS: &str = "correct horse battery";

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qcb-ksw-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn fast() -> CreateOptions { CreateOptions { cost: KdfCost::FLOOR, harden_existing_dir: false, prefix: "qcb".into() } }

fn icacls(args: &[&str]) {
    let o = Command::new("icacls").args(args).output().expect("icacls must be available");
    assert!(o.status.success(), "icacls {args:?}: {}", String::from_utf8_lossy(&o.stdout));
}

fn p(path: &Path) -> &str { path.to_str().unwrap() }

#[test]
fn the_current_user_sid_is_a_real_sid() {
    let sid = current_user_sid().expect("whoami must give the current SID");
    assert!(sid.starts_with("S-1-5-") && sid.len() > 10, "{sid}");
}

#[test]
fn a_new_key_file_and_its_new_directory_read_back_as_owner_only() {
    let sid = current_user_sid().unwrap();
    let d = tmpdir("new");
    let f = d.join("keys").join("k.json");
    create_new(&f, "a", PASS, &fast(), &OsPlatform).expect("create");
    let file_acl = read_sddl(&f).expect("read the file's DACL back");
    let dir_acl = read_sddl(&d.join("keys")).expect("read the directory's DACL back");
    sddl_owner_only(&file_acl, &sid, false).unwrap_or_else(|e| panic!("file DACL {file_acl:?}: {e}"));
    sddl_owner_only(&dir_acl, &sid, true).unwrap_or_else(|e| panic!("directory DACL {dir_acl:?}: {e}"));
    load(&f, PASS, &OsPlatform).expect("an owner-only key loads");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn loosening_the_file_acl_makes_load_refuse_the_key() {
    let d = tmpdir("loosen");
    let f = d.join("keys").join("k.json");
    create_new(&f, "a", PASS, &fast(), &OsPlatform).unwrap();
    icacls(&[p(&f), "/grant", "*S-1-1-0:(R)"]); // Everyone: read
    assert!(matches!(load(&f, PASS, &OsPlatform), Err(Error::Permission(_))), "a key readable by Everyone must be refused");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn loosening_the_directory_acl_makes_load_refuse_the_key() {
    let d = tmpdir("loosendir");
    let keys = d.join("keys"); let f = keys.join("k.json");
    create_new(&f, "a", PASS, &fast(), &OsPlatform).unwrap();
    icacls(&[p(&keys), "/grant", "*S-1-1-0:(OI)(CI)(M)"]); // Everyone: modify
    assert!(matches!(load(&f, PASS, &OsPlatform), Err(Error::Permission(_))));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn re_enabling_inheritance_makes_load_refuse_the_key() {
    let d = tmpdir("inherit");
    let f = d.join("keys").join("k.json");
    create_new(&f, "a", PASS, &fast(), &OsPlatform).unwrap();
    icacls(&[p(&f), "/inheritance:e"]);
    assert!(matches!(load(&f, PASS, &OsPlatform), Err(Error::Permission(_))), "inherited ACEs must be refused");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_existing_unhardened_directory_is_refused_unless_hardening_is_requested() {
    let sid = current_user_sid().unwrap();
    let d = tmpdir("existing");
    let keys = d.join("keys"); std::fs::create_dir(&keys).unwrap();
    let f = keys.join("k.json");
    assert!(matches!(create_new(&f, "a", PASS, &fast(), &OsPlatform), Err(Error::Permission(_))), "inherited default ACL is not owner-only");
    assert!(!f.exists());
    let o = CreateOptions { harden_existing_dir: true, ..fast() };
    create_new(&f, "a", PASS, &o, &OsPlatform).expect("explicit hardening");
    sddl_owner_only(&read_sddl(&keys).unwrap(), &sid, true).expect("the directory is now owner-only");
    load(&f, PASS, &OsPlatform).expect("loads");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_failed_creation_leaves_no_file_on_windows_either() {
    let d = tmpdir("fail");
    let f = d.join("keys").join("k.json");
    create_new(&f, "a", PASS, &fast(), &OsPlatform).unwrap();
    let before = std::fs::read(&f).unwrap();
    assert!(matches!(create_new(&f, "b", PASS, &fast(), &OsPlatform), Err(Error::Exists(_))));
    assert_eq!(std::fs::read(&f).unwrap(), before);
    let _ = std::fs::remove_dir_all(&d);
}
