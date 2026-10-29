//! qcb-keygen must produce a fresh random key on every run. The Ed25519
//! path used to derive the key from the label (SHA-256 of "<label>-ed25519"),
//! so anyone who knew the label could recompute the private key.

use std::process::Command;

fn run(scheme: &str, label: &str) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_qcb-keygen")).args([scheme, label]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn same_label_never_yields_the_same_key() {
    for scheme in ["ed25519", "mldsa"] {
        let a = run(scheme, "alice");
        let b = run(scheme, "alice");
        assert_ne!(a["private_key"], b["private_key"], "{scheme}: the key must not be derivable from the label");
        assert_ne!(a["public_key"], b["public_key"], "{scheme}");
    }
}
