//! File and directory permission hardening and *verification* for key storage (issue #107).
//!
//! The rule everywhere: after changing permissions, read the real state back and check it. The return value of a "set
//! permissions" call is never trusted. Unix: owner-only mode bits and ownership. Windows: a protected DACL with exactly one
//! allow ACE for the current user, read back as SDDL through `icacls /save` (locale independent) and checked by the pure
//! function [`sddl_owner_only`], which is unit-tested on every platform.

use std::path::Path;

// ── the pure SDDL verifier ───────────────────────────────────────────────────────────────────────────────────────────

/// Verify an SDDL string (as written by `icacls <path> /save`): the DACL must be **protected** (inheritance blocked) and contain
/// **exactly one** allow ACE, not inherited, with full-control rights, whose trustee is exactly `sid`. For a directory the ACE
/// must be inheritable by objects and containers (`OICI`). Anything else — another trustee, a deny ACE, an object ACE, a second
/// ACE, an unprotected DACL — is rejected.
pub fn sddl_owner_only(sddl: &str, sid: &str, is_dir: bool) -> Result<(), String> {
    let sddl = sddl.trim();
    let at = sddl.find("D:").ok_or("no DACL in the security descriptor")?;
    let rest = &sddl[at + 2..];

    // DACL flags, up to the first '(' (P = protected; AI/AR = auto-inherited/-required markers).
    let open = rest.find('(').ok_or("the DACL has no ACEs")?;
    let flags = &rest[..open];
    if !flags.chars().all(|c| matches!(c, 'P' | 'A' | 'I' | 'R')) {
        return Err(format!("unrecognised DACL flags {flags:?}"));
    }
    if !flags.contains('P') {
        return Err("the DACL is not protected: it inherits permissions from its parent".into());
    }

    // The ACE list: consecutive "(...)" groups; anything after (for example a SACL) is ignored.
    let mut aces: Vec<&str> = vec![];
    let mut tail = &rest[open..];
    while tail.starts_with('(') {
        let close = tail.find(')').ok_or("unterminated ACE")?;
        aces.push(&tail[1..close]);
        tail = &tail[close + 1..];
    }
    if aces.len() != 1 {
        return Err(format!("the DACL has {} ACEs; exactly one (the current user) is allowed", aces.len()));
    }

    let f: Vec<&str> = aces[0].split(';').collect();
    if f.len() != 6 {
        return Err(format!("malformed ACE {:?}", aces[0]));
    }
    if f[0] != "A" {
        return Err(format!("ACE type {:?} is not a plain allow ACE", f[0]));
    }
    // ACE flags: pairs from {OI, CI}; "ID" (inherited) and everything else is refused.
    if f[1].len() % 2 != 0 {
        return Err(format!("malformed ACE flags {:?}", f[1]));
    }
    let mut oi = false;
    let mut ci = false;
    for pair in f[1].as_bytes().chunks(2) {
        match pair {
            b"OI" => oi = true,
            b"CI" => ci = true,
            other => return Err(format!("ACE flag {:?} is not allowed (inherited or special ACE)", String::from_utf8_lossy(other))),
        }
    }
    if is_dir && !(oi && ci) {
        return Err("a directory ACE must be inheritable by objects and containers (OICI)".into());
    }
    if !f[2].eq_ignore_ascii_case("FA") && !f[2].eq_ignore_ascii_case("0x1f01ff") {
        return Err(format!("rights {:?} are not full control", f[2]));
    }
    if !f[3].is_empty() || !f[4].is_empty() {
        return Err("object ACEs are not allowed".into());
    }
    if f[5] != sid {
        return Err(format!("the only trustee is {:?}, not the current user", f[5]));
    }
    Ok(())
}

// ── parsing what `icacls <path> /save <file>` writes (pure, so it is tested on every platform) ──────────────────────

/// Decode the file written by `icacls /save`. On Windows it is **UTF-16LE with no byte-order mark** (observed on the owner's
/// machine); a BOM, UTF-16BE and UTF-8 are accepted too so a different Windows version cannot break verification.
pub fn decode_icacls_save(raw: &[u8]) -> String {
    let le = |b: &[u8]| String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<u16>>());
    let be = |b: &[u8]| String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect::<Vec<u16>>());
    if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(&raw[3..]).to_string()
    } else if raw.starts_with(&[0xFF, 0xFE]) {
        le(&raw[2..])
    } else if raw.starts_with(&[0xFE, 0xFF]) {
        be(&raw[2..])
    } else if raw.len() >= 2 && raw[0] == 0 && raw[1] != 0 {
        be(raw) // UTF-16BE without a BOM: ASCII text has a NUL in the first byte of every unit
    } else if raw.len() >= 2 && raw[1] == 0 {
        le(raw) // UTF-16LE without a BOM: ASCII text has a NUL in the second byte of every unit
    } else {
        String::from_utf8_lossy(raw).to_string()
    }
}

/// The SDDL line of an `icacls /save` file: the object's name comes first, then its SDDL. A path such as `D:\keys\k.json` also
/// contains "D:", but SDDL never contains a path separator, so select on that.
pub fn sddl_line(text: &str) -> Option<String> {
    text.lines().map(str::trim)
        .find(|l| l.contains("D:") && !l.contains('\\') && !l.contains('/'))
        .map(str::to_string)
}

// ── Unix ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
pub mod unix {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::Path;

    fn euid() -> u32 { unsafe { libc::geteuid() } }

    /// A key file: a regular file (not a symlink) owned by the current user with no group or other permission bits.
    pub fn verify_file(path: &Path) -> Result<(), String> {
        let m = std::fs::symlink_metadata(path).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        if !m.file_type().is_file() { return Err(format!("{} is not a regular file (symlinks are refused)", path.display())); }
        if m.uid() != euid() { return Err(format!("{} is not owned by the current user", path.display())); }
        let mode = m.permissions().mode() & 0o777;
        if mode & 0o077 != 0 { return Err(format!("{} has mode {mode:o}; group/other access is not allowed (expected 600)", path.display())); }
        Ok(())
    }

    /// A key directory: a real directory owned by the current user that is not group- or other-writable.
    pub fn verify_dir(path: &Path) -> Result<(), String> {
        let m = std::fs::symlink_metadata(path).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        if !m.file_type().is_dir() { return Err(format!("{} is not a directory (symlinks are refused)", path.display())); }
        if m.uid() != euid() { return Err(format!("{} is not owned by the current user", path.display())); }
        let mode = m.permissions().mode() & 0o777;
        if mode & 0o022 != 0 { return Err(format!("{} has mode {mode:o}; it must not be group- or other-writable", path.display())); }
        Ok(())
    }

    pub fn restrict_file(path: &Path) -> Result<(), String> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("chmod 600 failed: {e}"))?;
        verify_file(path)
    }

    pub fn harden_dir(path: &Path) -> Result<(), String> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("chmod 700 failed: {e}"))?;
        verify_dir(path)
    }

    /// Create a single directory level with mode 0700 and verify it.
    pub fn create_dir(path: &Path) -> Result<(), String> {
        std::fs::DirBuilder::new().mode(0o700).create(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        verify_dir(path)
    }
}

// ── Windows ──────────────────────────────────────────────────────────────────────────────────────────────────────────

/// The current user's SID, from `whoami /user` (locale independent: the SID is the last CSV field).
#[cfg(windows)]
pub fn current_user_sid() -> Result<String, String> {
    static SID: std::sync::OnceLock<Result<String, String>> = std::sync::OnceLock::new();
    SID.get_or_init(current_user_sid_uncached).clone()
}

#[cfg(windows)]
fn current_user_sid_uncached() -> Result<String, String> {
    let o = std::process::Command::new("whoami").args(["/user", "/fo", "csv", "/nh"]).output().map_err(|e| format!("whoami failed: {e}"))?;
    if !o.status.success() { return Err("whoami /user failed".into()); }
    let text = String::from_utf8_lossy(&o.stdout);
    let last = text.trim().rsplit(',').next().unwrap_or("").trim().trim_matches('"').to_string();
    if last.starts_with("S-1-") && last.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') { Ok(last) } else { Err(format!("unexpected whoami output {text:?}")) }
}

/// Read the DACL of `path` back from the file system as SDDL (`icacls <path> /save <file>`).
#[cfg(windows)]
pub fn read_sddl(path: &Path) -> Result<String, String> {
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("qcb-acl-{}-{}.txt", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));
    let o = std::process::Command::new("icacls").arg(path).arg("/save").arg(&tmp).output().map_err(|e| format!("icacls failed to start: {e}"))?;
    if !o.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("icacls /save failed: {}", String::from_utf8_lossy(&o.stdout)));
    }
    let raw = std::fs::read(&tmp).map_err(|e| format!("cannot read the saved ACL: {e}"));
    let _ = std::fs::remove_file(&tmp);
    let raw = raw?;
    let text = decode_icacls_save(&raw);
    sddl_line(&text).ok_or_else(|| format!("no SDDL line in icacls output {text:?}"))
}

#[cfg(windows)]
fn icacls(args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let o = std::process::Command::new("icacls").args(args).output().map_err(|e| format!("icacls failed to start: {e}"))?;
    if o.status.success() { Ok(()) } else { Err(format!("icacls failed: {}", String::from_utf8_lossy(&o.stdout).trim())) }
}

/// Make `path` owner-only (protected DACL, one ACE for the current user), then read it back and verify.
#[cfg(windows)]
fn windows_restrict(path: &Path, is_dir: bool) -> Result<(), String> {
    let sid = current_user_sid()?;
    let grant = if is_dir { format!("*{sid}:(OI)(CI)(F)") } else { format!("*{sid}:(F)") };
    icacls(&[path.as_os_str(), "/inheritance:r".as_ref()])?;
    icacls(&[path.as_os_str(), "/grant:r".as_ref(), grant.as_ref()])?;
    windows_verify(path, is_dir)
}

#[cfg(windows)]
fn windows_verify(path: &Path, is_dir: bool) -> Result<(), String> {
    let sid = current_user_sid()?;
    let sddl = read_sddl(path)?;
    sddl_owner_only(&sddl, &sid, is_dir).map_err(|e| format!("{} is not owner-only: {e}", path.display()))
}

// ── the platform-independent entry points used by the key store ──────────────────────────────────────────────────────

pub fn restrict_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)] { unix::restrict_file(path) }
    #[cfg(windows)] { windows_restrict(path, false) }
    #[cfg(not(any(unix, windows)))] { let _ = path; Err("no supported permission model on this platform: refusing".into()) }
}

pub fn verify_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)] { unix::verify_file(path) }
    #[cfg(windows)] { windows_verify(path, false) }
    #[cfg(not(any(unix, windows)))] { let _ = path; Err("no supported permission model on this platform: refusing".into()) }
}

pub fn verify_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)] { unix::verify_dir(path) }
    #[cfg(windows)] { windows_verify(path, true) }
    #[cfg(not(any(unix, windows)))] { let _ = path; Err("no supported permission model on this platform: refusing".into()) }
}

/// Create `dir` (one level; its parent must exist) restricted to the current user, or verify an existing one; an existing
/// directory is hardened only when `harden_existing` is true. Returns whether it was created.
pub fn prepare_dir(dir: &Path, harden_existing: bool) -> Result<bool, String> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => {
            if verify_dir(dir).is_ok() { return Ok(false); }
            if !harden_existing {
                return Err(format!("{} is not private to the current user; pass --harden-existing-dir to restrict it, or use a new directory", dir.display()));
            }
            #[cfg(unix)] { unix::harden_dir(dir)?; }
            #[cfg(windows)] { windows_restrict(dir, true)?; }
            #[cfg(not(any(unix, windows)))] { return Err("unsupported platform".into()); }
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)] { unix::create_dir(dir)?; }
            #[cfg(windows)] {
                std::fs::create_dir(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
                if let Err(e) = windows_restrict(dir, true) { let _ = std::fs::remove_dir(dir); return Err(e); }
            }
            #[cfg(not(any(unix, windows)))] { return Err("unsupported platform".into()); }
            Ok(true)
        }
        Err(e) => Err(format!("cannot inspect {}: {e}", dir.display())),
    }
}
