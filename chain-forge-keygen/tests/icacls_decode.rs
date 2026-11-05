//! Parsing of `icacls <path> /save <file>` output. The first sample is the **real output captured on the owner's Windows
//! machine (BossKing, 2026-11-05)**: UTF-16LE with no byte-order mark.
#![cfg(feature = "signing-v2")]

use chain_forge_keygen::fsperm::{decode_icacls_save, sddl_line, sddl_owner_only};

const SID: &str = "S-1-5-21-2026880741-1893771558-4269005647-1001";

fn utf16le(s: &str, bom: bool) -> Vec<u8> {
    let mut v = if bom { vec![0xFF, 0xFE] } else { vec![] };
    for u in s.encode_utf16() { v.extend_from_slice(&u.to_le_bytes()); }
    v
}

fn real_output() -> String { format!("qcb-ks-kdfload-7436\r\nD:PAI(A;OICI;FA;;;{SID})\r\n") }

#[test]
fn the_real_windows_output_without_a_bom_is_decoded_and_verified() {
    let raw = utf16le(&real_output(), false);
    let text = decode_icacls_save(&raw);
    assert!(!text.contains('\0'), "NUL bytes mean the UTF-16 was read as UTF-8: {text:?}");
    let line = sddl_line(&text).expect("the SDDL line is found");
    assert_eq!(line, format!("D:PAI(A;OICI;FA;;;{SID})"));
    sddl_owner_only(&line, SID, true).expect("the real DACL is exactly one protected inheritable ACE for the owner");
}

#[test]
fn every_encoding_icacls_may_use_is_decoded() {
    let want = format!("D:PAI(A;;FA;;;{SID})");
    for (label, raw) in [
        ("utf-16le with bom", utf16le(&format!("name\r\n{want}\r\n"), true)),
        ("utf-16le without bom", utf16le(&format!("name\r\n{want}\r\n"), false)),
        ("utf-16be with bom", { let mut v = vec![0xFE, 0xFF]; for u in format!("name\r\n{want}\r\n").encode_utf16() { v.extend_from_slice(&u.to_be_bytes()); } v }),
        ("utf-8", format!("name\r\n{want}\r\n").into_bytes()),
        ("utf-8 with bom", { let mut v = vec![0xEF, 0xBB, 0xBF]; v.extend(format!("name\r\n{want}\r\n").bytes()); v }),
    ] {
        let line = sddl_line(&decode_icacls_save(&raw)).unwrap_or_else(|| panic!("{label}: no SDDL line"));
        assert_eq!(line.trim_start_matches('\u{feff}'), want, "{label}");
    }
}

#[test]
fn a_path_on_drive_d_is_not_mistaken_for_the_sddl_line() {
    let raw = utf16le(&format!("D:\\keys\\k.json\r\nD:PAI(A;;FA;;;{SID})\r\n"), false);
    let line = sddl_line(&decode_icacls_save(&raw)).expect("found");
    assert_eq!(line, format!("D:PAI(A;;FA;;;{SID})"));
}

#[test]
fn output_with_no_sddl_line_yields_nothing() {
    assert!(sddl_line(&decode_icacls_save(&utf16le("just a name\r\n", false))).is_none());
    assert!(sddl_line(&decode_icacls_save(b"")).is_none());
}
