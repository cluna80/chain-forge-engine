//! The Windows tools the key store runs (`whoami`, `icacls`) are launched by ABSOLUTE path under the system directory, never by a `PATH`
//! search. A directory earlier on `PATH` (or the current directory) must not be able to substitute a program that sees key file paths and
//! decides what the "current user" and "owner-only" mean. (TEST-ONLY, feature `signing-v2`.) The resolver is pure, so this runs on every OS.
#![cfg(feature = "signing-v2")]

use chain_forge_keygen::fsperm::system32_tool;
use std::ffi::OsStr;
use std::path::Path;

fn os(s: &str) -> Option<&OsStr> { Some(OsStr::new(s)) }

#[test]
fn the_tool_path_is_under_system_root_system32() {
    let p = system32_tool("icacls.exe", os("D:\\Win"), None).expect("resolves");
    assert!(p.starts_with(Path::new("D:\\Win")) || p.to_string_lossy().starts_with("D:\\Win"), "{p:?}");
    assert!(p.ends_with(Path::new("System32").join("icacls.exe")), "{p:?}");
}

#[test]
fn windir_is_used_when_system_root_is_missing_and_c_windows_when_both_are() {
    let p = system32_tool("whoami.exe", None, os("E:\\W")).expect("resolves");
    assert!(p.to_string_lossy().starts_with("E:\\W") && p.ends_with(Path::new("System32").join("whoami.exe")), "{p:?}");
    let p = system32_tool("whoami.exe", None, None).expect("resolves");
    assert!(p.to_string_lossy().starts_with("C:\\Windows") && p.ends_with(Path::new("System32").join("whoami.exe")), "{p:?}");
}

#[test]
fn a_relative_or_dotted_root_is_never_used() {
    for bad in ["Windows", "..\\evil", ".", "", "\\\\?\\", "C:", "C:evil", "x\\..\\y",
                    // drive-absolute but unsafe: a ".." / "." component, or a second ":" (alternate data stream / device syntax)
                    "C:\\Windows\\..\\evil", "C:/Windows/../evil", "C:\\a\\.\\b", "C:\\x:y"] {
        let p = system32_tool("icacls.exe", os(bad), None).expect("falls back instead of failing");
        assert!(p.to_string_lossy().starts_with("C:\\Windows"), "root {bad:?} must be ignored, got {p:?}");
    }
    // A bad SystemRoot falls through to a good windir, not straight to the default.
    let p = system32_tool("icacls.exe", os("..\\evil"), os("F:\\Good")).expect("resolves");
    assert!(p.to_string_lossy().starts_with("F:\\Good"), "{p:?}");
}

#[test]
fn only_a_bare_file_name_is_accepted() {
    for bad in ["", ".", "..", "a\\b.exe", "a/b.exe", "..\\x.exe", "C:\\x.exe", "x.exe "] {
        assert!(system32_tool(bad, os("C:\\Windows"), None).is_err(), "{bad:?} must be refused");
    }
}

/// The guard: no tool is launched by bare name. A `Command::new("icacls")` anywhere in the key store would search `PATH`.
#[test]
fn no_system_tool_is_launched_by_a_bare_name() {
    for (file, src) in [("fsperm.rs", include_str!("../src/fsperm.rs")), ("keystore.rs", include_str!("../src/keystore.rs")), ("main.rs", include_str!("../src/main.rs"))] {
        for bad in ["Command::new(\"icacls\")", "Command::new(\"whoami\")", "Command::new(\"icacls.exe\")", "Command::new(\"whoami.exe\")", "Command::new(\"cmd\")", "Command::new(\"powershell\")"] {
            assert!(!src.contains(bad), "{file} launches a tool by bare name: {bad}");
        }
    }
}
