//! File and directory permission hardening and verification. SCAFFOLD (tests first).

/// Pure verifier for an SDDL DACL string (as written by `icacls <path> /save`): it must be protected (inheritance blocked) and
/// contain exactly one non-inherited allow ACE whose trustee is `sid`, with full-control rights, and nothing else.
pub fn sddl_owner_only(_sddl: &str, _sid: &str, _is_dir: bool) -> Result<(), String> {
    Err("not implemented".into())
}

/// The current user's SID (Windows). SCAFFOLD.
#[cfg(windows)]
pub fn current_user_sid() -> Result<String, String> { Err("not implemented".into()) }

/// The DACL of `path` as SDDL, read back from the file system (Windows). SCAFFOLD.
#[cfg(windows)]
pub fn read_sddl(_path: &std::path::Path) -> Result<String, String> { Err("not implemented".into()) }
