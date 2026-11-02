/// H0-3 — Generation-based atomic state persistence.
///
/// ## Layout on disk
///
/// ```text
/// <data_dir>/
///   CURRENT                        ← atomically updated pointer: "gen-000042\n"
///   persist/
///     consensus_signing.json       ← independently durable; written by
///                                    persist_sign_guard(), read by
///                                    restore_sign_guard() and the startup
///                                    compatibility check in load_persisted_state()
///   snapshots/
///     gen-000041/
///       manifest.json              ← written LAST; validates the generation
///       state.json
///       identity.json
///       validators.json
///       agents.json
///       slashing.json
///       chain_store.json
///       historical_validator_sets.json
///       live_validator_set.json
///     gen-000042/
///       ...                        ← in-progress write; CURRENT not yet updated
/// ```
///
/// ## Write protocol
///
/// 1. Choose next generation number = current + 1 (or 0 for the first).
/// 2. `mkdir snapshots/gen-NNNNNN`.
/// 3. Write each state file into the generation directory (atomic: tmp→rename).
/// 4. Compute SHA-256 of each file's final bytes; write `manifest.json` last.
/// 5. `fsync` the generation directory so all renames are durable.
/// 6. Atomically update `CURRENT` (tmp→rename in data_dir root).
/// 7. Delete the generation two steps back (keep N and N-1 for safety).
///
/// A crash at any step before step 6 leaves `CURRENT` pointing at the previous
/// generation. A crash during step 6 leaves a temp file that is ignored on
/// restart. The previous generation is always recoverable.
///
/// ## Load protocol
///
/// 1. Read `CURRENT`. If absent → fresh data directory.
/// 2. Enter `snapshots/<current>`.
/// 3. Read and validate `manifest.json`: all files must be present, sizes must
///    match, SHA-256 hashes must match.
/// 4. Parse each file; cross-check heights.
/// 5. On any error → `PersistError` (never silent genesis fallback).

use std::io::Write as IoWrite;
use std::path::Path;
use sha2::{Sha256, Digest};

// ── public error type ────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PersistError {
    /// A fresh data directory with no CURRENT pointer. Caller may initialize
    /// genesis. This is NOT an error condition.
    Fresh,
    /// CURRENT points to a generation directory that does not exist.
    MissingGeneration { gen: String },
    /// manifest.json is absent from the committed generation.
    MissingManifest { gen: String },
    /// manifest.json could not be parsed.
    CorruptManifest { gen: String, detail: String },
    /// A file listed in the manifest is absent.
    MissingFile { gen: String, file: String },
    /// A file's SHA-256 does not match the manifest.
    HashMismatch { gen: String, file: String },
    /// A file is present but cannot be parsed as valid JSON.
    CorruptFile { gen: String, file: String, detail: String },
    /// The heights recorded across different files are inconsistent.
    HeightMismatch { gen: String, detail: String },
    /// A signing history entry conflicts with the restored consensus state.
    /// Signing is blocked until an explicit recovery is performed.
    SigningHistoryConflict { detail: String },
    /// A low-level I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistError::Fresh =>
                write!(f, "fresh data directory — no committed snapshot"),
            PersistError::MissingGeneration { gen } =>
                write!(f, "CURRENT points to '{gen}' but that directory does not exist"),
            PersistError::MissingManifest { gen } =>
                write!(f, "generation '{gen}' has no manifest.json — incomplete write"),
            PersistError::CorruptManifest { gen, detail } =>
                write!(f, "generation '{gen}' manifest.json is corrupt: {detail}"),
            PersistError::MissingFile { gen, file } =>
                write!(f, "generation '{gen}' is missing required file '{file}'"),
            PersistError::HashMismatch { gen, file } =>
                write!(f, "generation '{gen}' file '{file}' SHA-256 does not match manifest"),
            PersistError::CorruptFile { gen, file, detail } =>
                write!(f, "generation '{gen}' file '{file}' cannot be parsed: {detail}"),
            PersistError::HeightMismatch { gen, detail } =>
                write!(f, "generation '{gen}' height inconsistency: {detail}"),
            PersistError::SigningHistoryConflict { detail } =>
                write!(f, "consensus signing history conflicts with restored state: {detail} \
                           — signing blocked; run with --force-unsafe-signing-recovery to override"),
            PersistError::Io(e) =>
                write!(f, "I/O error during persistence: {e}"),
        }
    }
}

impl std::error::Error for PersistError {}

impl From<std::io::Error> for PersistError {
    fn from(e: std::io::Error) -> Self { PersistError::Io(e) }
}

// ── manifest ─────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SnapshotManifest {
    /// The committed block height this snapshot captures.
    pub height: u64,
    /// Generation label, e.g. "gen-000042".
    pub generation: String,
    /// Per-file integrity records.
    pub files: Vec<FileEntry>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FileEntry {
    pub name: String,
    /// SHA-256 hex digest of the file's exact bytes on disk.
    pub sha256: String,
    /// Byte length of the file.
    pub size: u64,
}

// ── generation writer ────────────────────────────────────────────────────────

/// Names of all state files that belong to every snapshot (order matters for
/// the manifest; written in this order).
pub const SNAPSHOT_FILES: &[&str] = &[
    "state.json",
    "identity.json",
    "validators.json",
    "agents.json",
    "slashing.json",
    "chain_store.json",
    "historical_validator_sets.json",
    "live_validator_set.json",
];

/// Write `contents` to `path` atomically: temp file → fsync → rename.
/// On Windows `fs::rename` over an existing file succeeds (replaces).
/// On Linux it is atomic per POSIX.
fn write_atomic_bytes(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Compute the SHA-256 hex digest of `data`.
fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// fsync the directory itself so that rename operations within it are durable.
/// On Windows this is a no-op (directory fsyncs are not supported; atomic
/// renames provide the same guarantee via the NTFS journal).
fn fsync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let f = std::fs::File::open(path)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Format a generation label from a u64 counter.
pub fn gen_label(n: u64) -> String {
    format!("gen-{n:06}")
}

/// Read the current committed generation label from `<data_dir>/CURRENT`.
/// Returns `None` if the file does not exist (fresh directory).
pub fn read_current(data_dir: &Path) -> std::io::Result<Option<String>> {
    let current_path = data_dir.join("CURRENT");
    if !current_path.exists() { return Ok(None); }
    let raw = std::fs::read_to_string(&current_path)?;
    Ok(Some(raw.trim().to_string()))
}

/// Write `<data_dir>/CURRENT` atomically, pointing to `gen_label`.
///
/// After the atomic rename of the CURRENT tmp file, we fsync `data_dir`
/// itself so the rename is durable on Linux (POSIX requires an explicit
/// directory fsync to guarantee a rename survives a crash).  On Windows
/// the NTFS journal provides the same guarantee without an explicit fsync,
/// so the `fsync_dir` call is a no-op there.
pub fn write_current(data_dir: &Path, gen: &str) -> std::io::Result<()> {
    write_atomic_bytes(&data_dir.join("CURRENT"), gen.as_bytes())?;
    // Durability: flush the directory entry for the CURRENT rename.
    fsync_dir(data_dir)
}

/// Read the generation number from CURRENT (0 if fresh).
pub fn current_generation_number(data_dir: &Path) -> u64 {
    read_current(data_dir).ok().flatten()
        .as_deref()
        .and_then(|s| s.strip_prefix("gen-"))
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Write a complete snapshot for `height` with the provided file contents.
///
/// `contents`: slice of `(filename, bytes)` — must match `SNAPSHOT_FILES` order.
///
/// Returns the new generation label on success.
///
/// ## Durability contract
/// - All files written atomically within the generation directory.
/// - Generation directory fsynced before manifest is written.
/// - manifest.json written atomically last.
/// - Generation directory fsynced again.
/// - CURRENT pointer updated atomically.
/// - Previous-previous generation pruned.
pub fn write_snapshot(
    data_dir: &Path,
    height: u64,
    contents: &[(&str, Vec<u8>)],
) -> Result<String, PersistError> {
    let snaps = data_dir.join("snapshots");
    std::fs::create_dir_all(&snaps)?;

    let next_num = current_generation_number(data_dir) + 1;
    let gen = gen_label(next_num);
    let gen_dir = snaps.join(&gen);
    std::fs::create_dir_all(&gen_dir)?;

    let mut file_entries = Vec::with_capacity(contents.len());

    // Write each state file atomically.
    for (name, bytes) in contents {
        let path = gen_dir.join(name);
        write_atomic_bytes(&path, bytes)?;
        file_entries.push(FileEntry {
            name: name.to_string(),
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
        });
    }

    // Fsync the generation directory so all renames are durable before writing
    // the manifest.
    fsync_dir(&gen_dir)?;

    // Write manifest.json last — its presence is the commit signal.
    let manifest = SnapshotManifest { height, generation: gen.clone(), files: file_entries };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    write_atomic_bytes(&gen_dir.join("manifest.json"), &manifest_bytes)?;

    // Fsync the generation directory again so the manifest rename is durable.
    fsync_dir(&gen_dir)?;

    // Update CURRENT atomically.
    write_current(data_dir, &gen)?;

    // Prune the generation two steps back (keep N and N-1).
    if next_num >= 2 {
        let old = snaps.join(gen_label(next_num - 2));
        if old.exists() {
            let _ = std::fs::remove_dir_all(&old); // best-effort; not fatal
        }
    }

    Ok(gen)
}

// ── snapshot loader ──────────────────────────────────────────────────────────

/// Contents of a validated snapshot, ready to be restored into the node.
pub struct SnapshotContents {
    pub height: u64,
    pub generation: String,
    /// Raw JSON bytes for each file, indexed by filename.
    pub files: std::collections::HashMap<String, Vec<u8>>,
}

/// Load and validate the committed snapshot from `data_dir`.
///
/// Returns:
/// - `Ok(Some(contents))` — valid snapshot found and verified.
/// - `Ok(None)` — fresh directory (CURRENT absent).
/// - `Err(PersistError::*)` — corrupted/incomplete snapshot; node must NOT start.
pub fn load_snapshot(data_dir: &Path) -> Result<Option<SnapshotContents>, PersistError> {
    let gen_label_str = match read_current(data_dir)
        .map_err(PersistError::Io)? {
        None => {
            // CURRENT is absent.  If *any* generation directory exists under
            // snapshots/, CURRENT was lost mid-write (crash between the tmp
            // rename and the parent-dir fsync).  Treat this as Fatal rather
            // than silently starting from genesis — the operator must confirm
            // the intent.  A truly fresh directory has no snapshots/ at all,
            // or an empty one.
            let snaps = data_dir.join("snapshots");
            if snaps.exists() {
                let has_gens = std::fs::read_dir(&snaps)
                    .map_err(PersistError::Io)?
                    .filter_map(|e| e.ok())
                    .any(|e| {
                        e.file_name().to_string_lossy().starts_with("gen-")
                            && e.path().is_dir()
                    });
                if has_gens {
                    return Err(PersistError::CorruptManifest {
                        gen: "CURRENT".to_string(),
                        detail: "CURRENT pointer is absent but generation directories exist \
                                 under snapshots/ — CURRENT may have been lost in a crash. \
                                 Restore CURRENT from a backup or remove snapshots/ to start \
                                 from genesis."
                            .to_string(),
                    });
                }
            }
            return Ok(None); // genuinely fresh
        }
        Some(s) => s,
    };

    let gen_dir = data_dir.join("snapshots").join(&gen_label_str);
    if !gen_dir.exists() {
        return Err(PersistError::MissingGeneration { gen: gen_label_str });
    }

    // Validate manifest.
    let manifest_path = gen_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err(PersistError::MissingManifest { gen: gen_label_str });
    }
    let manifest_bytes = std::fs::read(&manifest_path).map_err(PersistError::Io)?;
    let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| PersistError::CorruptManifest {
            gen: gen_label_str.clone(),
            detail: e.to_string(),
        })?;

    // Verify each file.
    let mut file_map = std::collections::HashMap::new();
    for entry in &manifest.files {
        let path = gen_dir.join(&entry.name);
        if !path.exists() {
            return Err(PersistError::MissingFile {
                gen: gen_label_str.clone(),
                file: entry.name.clone(),
            });
        }
        let bytes = std::fs::read(&path).map_err(PersistError::Io)?;
        if bytes.len() as u64 != entry.size {
            return Err(PersistError::HashMismatch {
                gen: gen_label_str.clone(),
                file: entry.name.clone(),
            });
        }
        let actual_hash = sha256_hex(&bytes);
        if actual_hash != entry.sha256 {
            return Err(PersistError::HashMismatch {
                gen: gen_label_str.clone(),
                file: entry.name.clone(),
            });
        }
        file_map.insert(entry.name.clone(), bytes);
    }

    // Cross-check: state.json height must match manifest height.
    if let Some(state_bytes) = file_map.get("state.json") {
        let state: serde_json::Value = serde_json::from_slice(state_bytes)
            .map_err(|e| PersistError::CorruptFile {
                gen: gen_label_str.clone(),
                file: "state.json".to_string(),
                detail: e.to_string(),
            })?;
        let state_height = state["height"].as_u64().unwrap_or(u64::MAX);
        if state_height != manifest.height {
            return Err(PersistError::HeightMismatch {
                gen: gen_label_str.clone(),
                detail: format!(
                    "manifest.height={} but state.json height={}",
                    manifest.height, state_height
                ),
            });
        }
    }

    // Cross-check: chain_store.json max key must equal manifest height.
    if let Some(cs_bytes) = file_map.get("chain_store.json") {
        let cs: serde_json::Value = serde_json::from_slice(cs_bytes)
            .map_err(|e| PersistError::CorruptFile {
                gen: gen_label_str.clone(),
                file: "chain_store.json".to_string(),
                detail: e.to_string(),
            })?;
        if let Some(obj) = cs.as_object() {
            if !obj.is_empty() {
                let max_key = obj.keys()
                    .filter_map(|k| k.parse::<u64>().ok())
                    .max()
                    .unwrap_or(0);
                if max_key != manifest.height {
                    return Err(PersistError::HeightMismatch {
                        gen: gen_label_str.clone(),
                        detail: format!(
                            "manifest.height={} but chain_store.json max block height={}",
                            manifest.height, max_key
                        ),
                    });
                }
            }
        }
    }

    Ok(Some(SnapshotContents {
        height: manifest.height,
        generation: gen_label_str,
        files: file_map,
    }))
}

// ── legacy (pre-H0-3) data directory migration ───────────────────────────────

/// Subdirectory of `persist/` that receives the legacy files after a
/// successful migration. They are moved, never deleted.
pub const LEGACY_ARCHIVE_DIR: &str = "legacy-pre-h0-3";

/// True if `<data_dir>/persist/` holds any file of the pre-H0-3 layout.
fn has_legacy_files(data_dir: &Path) -> bool {
    let persist = data_dir.join("persist");
    SNAPSHOT_FILES.iter().any(|f| persist.join(f).exists())
}

/// Migrate a pre-H0-3 data directory (eight pretty-JSON files directly under
/// `persist/`, no `CURRENT`) into the generation layout.
///
/// Strict by design: a legacy directory is committed state, so it either
/// migrates completely or the node refuses to start. It never becomes a
/// fresh genesis start.
///   * every one of the eight files must exist (any absent file is
///     `MissingFile`, including `state.json`, and `live_validator_set.json`);
///   * every file must parse as JSON (`CorruptFile`);
///   * `state.json` must carry a numeric `height`.
/// The migrated generation is then verified by the ordinary `load_snapshot`
/// path (hashes, manifest, height cross-checks). On success the legacy files
/// are moved to `persist/legacy-pre-h0-3/`.
///
/// Returns `Ok(None)` when `CURRENT` already exists (nothing to migrate) or
/// when no legacy file is present (a genuinely fresh directory).
pub fn migrate_legacy(data_dir: &Path) -> Result<Option<String>, PersistError> {
    if read_current(data_dir).map_err(PersistError::Io)?.is_some() { return Ok(None); }
    if !has_legacy_files(data_dir) { return Ok(None); }

    let persist = data_dir.join("persist");
    let mut contents: Vec<(&str, Vec<u8>)> = Vec::with_capacity(SNAPSHOT_FILES.len());
    let mut height: Option<u64> = None;
    for &name in SNAPSHOT_FILES {
        let path = persist.join(name);
        if !path.exists() {
            return Err(PersistError::MissingFile { gen: "legacy".into(), file: name.into() });
        }
        let bytes = std::fs::read(&path).map_err(PersistError::Io)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            PersistError::CorruptFile { gen: "legacy".into(), file: name.into(), detail: e.to_string() }
        })?;
        if name == "state.json" {
            height = value["height"].as_u64();
        }
        contents.push((name, bytes));
    }
    let height = height.ok_or_else(|| PersistError::CorruptFile {
        gen: "legacy".into(),
        file: "state.json".into(),
        detail: "no numeric `height` field".into(),
    })?;

    let gen = write_snapshot(data_dir, height, &contents)?;

    // The new generation exists and CURRENT points at it. Archive (move) the
    // legacy files so a future start cannot mistake them for current state.
    let archive = persist.join(LEGACY_ARCHIVE_DIR);
    std::fs::create_dir_all(&archive).map_err(PersistError::Io)?;
    for &name in SNAPSHOT_FILES {
        std::fs::rename(persist.join(name), archive.join(name)).map_err(PersistError::Io)?;
    }
    Ok(Some(gen))
}

// ── signing history compatibility ─────────────────────────────────────────────

/// Validate that the consensus signing guard is compatible with the restored
/// state height. Does NOT advance the guard — that is the consensus engine's
/// responsibility.
///
/// Rules:
/// - `guard_height > state_height`: signing history is ahead of state — the
///   node may have voted on blocks that are not yet reflected in this snapshot.
///   This is the dangerous case: signing is blocked. The guard must be preserved
///   intact and the validator must not sign until it has caught up to
///   `guard_height` via block sync from peers.
/// - `guard_height == state_height`: consistent. Safe to resume.
/// - `guard_height < state_height`: the guard is behind the state — this can
///   happen if the signing file was lost but state was preserved. The node must
///   advance the guard to at least state_height before signing to prevent
///   re-signing at already-committed heights.
///
/// Returns Ok(SigningCompatibility) describing what action to take.
#[derive(Debug, PartialEq, Eq)]
pub enum SigningCompatibility {
    /// Guard and state are consistent. Normal startup.
    Consistent,
    /// Guard is behind state (guard_height < state_height). The consensus engine
    /// must advance the guard to state_height before allowing any new signatures.
    /// This is safe: the node cannot re-sign at heights it already committed
    /// because those heights are below the guard after advancement.
    GuardBehindState { guard_height: u64, state_height: u64 },
    /// Guard is ahead of state. Signing is blocked until the node syncs from
    /// peers and reaches guard_height. The guard must be preserved as-is.
    GuardAheadOfState { guard_height: u64, state_height: u64 },
}

pub fn check_signing_compatibility(
    guard_json: &serde_json::Value,
    state_height: u64,
) -> Result<SigningCompatibility, PersistError> {
    // `SignGuard` serializes as:
    //   { "last": [height, round, step] | null, "votes": [...], "lock": ... }
    //
    // `last` is `Option<(u64, u32, u8)>` — serde serialises the tuple as a
    // JSON array, so guard_json["last"][0] is the height.
    // If `last` is null or absent the guard has never signed; treat as height 0.
    let guard_height = match &guard_json["last"] {
        serde_json::Value::Array(arr) => {
            match arr.first().and_then(|v| v.as_u64()) {
                Some(h) => h,
                None => return Err(PersistError::SigningHistoryConflict {
                    detail: "consensus_signing.json: 'last' array is present but \
                             first element (height) is not a u64".to_string(),
                }),
            }
        }
        serde_json::Value::Null | serde_json::Value::Object(_) => {
            // Null last → guard has never signed; height 0 is consistent with
            // any state height (state may have been restored from a backup).
            // Object(_) branch should not occur but is safe to treat as 0.
            0
        }
        _ => {
            return Err(PersistError::SigningHistoryConflict {
                detail: format!(
                    "consensus_signing.json: unexpected type for 'last' field: {:?}",
                    guard_json["last"]
                ),
            })
        }
    };

    if guard_height > state_height {
        // Dangerous: guard is ahead. Block signing.
        // We return Ok(GuardAheadOfState) rather than Err so the caller can
        // make an informed decision (start as observer, or block signing).
        Ok(SigningCompatibility::GuardAheadOfState { guard_height, state_height })
    } else if guard_height < state_height {
        Ok(SigningCompatibility::GuardBehindState { guard_height, state_height })
    } else {
        Ok(SigningCompatibility::Consistent)
    }
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn make_valid_state_json(height: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "height": height,
            "accounts": {},
            "metadata": {},
        })).unwrap()
    }

    fn make_valid_chain_store_json(height: u64) -> Vec<u8> {
        let mut m = serde_json::Map::new();
        if height > 0 {
            m.insert(height.to_string(), serde_json::json!([null, {"height": height, "tx_data": ""}]));
        }
        serde_json::to_vec(&m).unwrap()
    }

    fn dummy_contents(height: u64) -> Vec<(&'static str, Vec<u8>)> {
        SNAPSHOT_FILES.iter().map(|&name| {
            let bytes = match name {
                "state.json"       => make_valid_state_json(height),
                "chain_store.json" => make_valid_chain_store_json(height),
                other              => format!("{{\"_file\":\"{other}\"}}").into_bytes(),
            };
            (name, bytes)
        }).collect()
    }

    // ── write_snapshot + load_snapshot round-trip ──────────────────────────

    #[test]
    fn round_trip_fresh_dir() {
        let dir = make_temp_dir();
        assert!(matches!(load_snapshot(dir.path()), Ok(None)), "fresh dir must return Ok(None)");
    }

    #[test]
    fn round_trip_single_generation() {
        let dir = make_temp_dir();
        let contents = dummy_contents(5);
        let gen = write_snapshot(dir.path(), 5, &contents).unwrap();
        assert_eq!(gen, "gen-000001");

        let snap = load_snapshot(dir.path()).unwrap().expect("should have snapshot");
        assert_eq!(snap.height, 5);
        assert_eq!(snap.generation, "gen-000001");
        assert!(snap.files.contains_key("state.json"));
    }

    #[test]
    fn second_write_increments_generation() {
        let dir = make_temp_dir();
        write_snapshot(dir.path(), 5, &dummy_contents(5)).unwrap();
        let gen2 = write_snapshot(dir.path(), 6, &dummy_contents(6)).unwrap();
        assert_eq!(gen2, "gen-000002");

        let snap = load_snapshot(dir.path()).unwrap().expect("snapshot");
        assert_eq!(snap.height, 6);
        assert_eq!(snap.generation, "gen-000002");
    }

    #[test]
    fn gen_minus_2_is_pruned() {
        let dir = make_temp_dir();
        write_snapshot(dir.path(), 1, &dummy_contents(1)).unwrap(); // gen-000001
        write_snapshot(dir.path(), 2, &dummy_contents(2)).unwrap(); // gen-000002
        write_snapshot(dir.path(), 3, &dummy_contents(3)).unwrap(); // gen-000003 → prunes gen-000001
        assert!(!dir.path().join("snapshots").join("gen-000001").exists(),
                "gen-000001 should have been pruned");
        assert!(dir.path().join("snapshots").join("gen-000002").exists(),
                "gen-000002 (N-1) should be retained");
    }

    // ── load errors ────────────────────────────────────────────────────────

    #[test]
    fn load_missing_generation_dir_is_error() {
        let dir = make_temp_dir();
        // Write CURRENT manually pointing at a non-existent dir.
        std::fs::write(dir.path().join("CURRENT"), "gen-000099").unwrap();
        assert!(matches!(
            load_snapshot(dir.path()),
            Err(PersistError::MissingGeneration { .. })
        ));
    }

    #[test]
    fn load_missing_manifest_is_error() {
        let dir = make_temp_dir();
        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::fs::write(dir.path().join("CURRENT"), "gen-000001").unwrap();
        // No manifest.json.
        assert!(matches!(
            load_snapshot(dir.path()),
            Err(PersistError::MissingManifest { .. })
        ));
    }

    #[test]
    fn load_corrupt_manifest_is_error() {
        let dir = make_temp_dir();
        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::fs::write(dir.path().join("CURRENT"), "gen-000001").unwrap();
        std::fs::write(gen_dir.join("manifest.json"), b"NOT_JSON").unwrap();
        assert!(matches!(
            load_snapshot(dir.path()),
            Err(PersistError::CorruptManifest { .. })
        ));
    }

    #[test]
    fn load_missing_file_is_error() {
        let dir = make_temp_dir();
        // Write a valid snapshot then delete one file from the generation dir.
        write_snapshot(dir.path(), 5, &dummy_contents(5)).unwrap();
        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        std::fs::remove_file(gen_dir.join("identity.json")).unwrap();
        assert!(matches!(
            load_snapshot(dir.path()),
            Err(PersistError::MissingFile { .. })
        ));
    }

    #[test]
    fn load_hash_mismatch_is_error() {
        let dir = make_temp_dir();
        write_snapshot(dir.path(), 5, &dummy_contents(5)).unwrap();
        // Corrupt identity.json after it was written.
        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        std::fs::write(gen_dir.join("identity.json"), b"CORRUPTED").unwrap();
        assert!(matches!(
            load_snapshot(dir.path()),
            Err(PersistError::HashMismatch { .. })
        ));
    }

    #[test]
    fn load_height_mismatch_state_vs_manifest_is_error() {
        let dir = make_temp_dir();
        // Craft contents where state.json height (3) != manifest height (5).
        let mut contents = dummy_contents(5);
        // Overwrite state.json with height=3.
        for (name, bytes) in contents.iter_mut() {
            if *name == "state.json" {
                *bytes = make_valid_state_json(3);
            }
        }
        // write_snapshot uses the height param for the manifest, but state.json
        // says 3 — this should be caught by load_snapshot's cross-check.
        write_snapshot(dir.path(), 5, &contents).unwrap();
        assert!(matches!(
            load_snapshot(dir.path()),
            Err(PersistError::HeightMismatch { .. })
        ));
    }

    #[test]
    fn load_height_mismatch_chain_store_vs_manifest_is_error() {
        let dir = make_temp_dir();
        let mut contents = dummy_contents(5);
        // chain_store at height 4, but manifest says 5.
        for (name, bytes) in contents.iter_mut() {
            if *name == "chain_store.json" {
                *bytes = make_valid_chain_store_json(4);
            }
            if *name == "state.json" {
                // Keep state.json consistent with manifest (height=5) so only
                // chain_store triggers the mismatch.
                *bytes = make_valid_state_json(5);
            }
        }
        write_snapshot(dir.path(), 5, &contents).unwrap();
        assert!(matches!(
            load_snapshot(dir.path()),
            Err(PersistError::HeightMismatch { .. })
        ));
    }

    // ── signing compatibility ───────────────────────────────────────────────
    //
    // SignGuard serialises as {"last": [height, round, step] | null, "votes": [...], "lock": ...}
    // check_signing_compatibility extracts the height from last[0].

    #[test]
    fn signing_guard_consistent() {
        // last = [10, 0, 2] → height 10, consistent with state at 10.
        let guard = serde_json::json!({"last": [10, 0, 2], "votes": [], "lock": null});
        assert_eq!(
            check_signing_compatibility(&guard, 10).unwrap(),
            SigningCompatibility::Consistent
        );
    }

    #[test]
    fn signing_guard_behind_state() {
        let guard = serde_json::json!({"last": [9, 0, 2], "votes": [], "lock": null});
        assert!(matches!(
            check_signing_compatibility(&guard, 10).unwrap(),
            SigningCompatibility::GuardBehindState { guard_height: 9, state_height: 10 }
        ));
    }

    #[test]
    fn signing_guard_ahead_of_state() {
        let guard = serde_json::json!({"last": [15, 0, 2], "votes": [], "lock": null});
        assert!(matches!(
            check_signing_compatibility(&guard, 10).unwrap(),
            SigningCompatibility::GuardAheadOfState { guard_height: 15, state_height: 10 }
        ));
    }

    #[test]
    fn signing_guard_null_last_at_genesis_is_consistent() {
        // Guard has never signed (null last) against state at height 0 → Consistent.
        let guard = serde_json::json!({"last": null, "votes": [], "lock": null});
        assert_eq!(
            check_signing_compatibility(&guard, 0).unwrap(),
            SigningCompatibility::Consistent
        );
    }

    #[test]
    fn signing_guard_null_last_behind_state_is_guard_behind() {
        // Guard has never signed (height 0) but state is at height 5 → GuardBehindState.
        // The consensus engine must advance the guard to 5 before allowing new signatures.
        let guard = serde_json::json!({"last": null, "votes": [], "lock": null});
        assert!(matches!(
            check_signing_compatibility(&guard, 5).unwrap(),
            SigningCompatibility::GuardBehindState { guard_height: 0, state_height: 5 }
        ));
    }

    #[test]
    fn signing_guard_missing_last_field_is_guard_behind() {
        // Missing `last` key → height 0; if state > 0, GuardBehindState.
        let guard = serde_json::json!({"votes": [], "lock": null});
        assert!(matches!(
            check_signing_compatibility(&guard, 5).unwrap(),
            SigningCompatibility::GuardBehindState { guard_height: 0, state_height: 5 }
        ));
    }

    #[test]
    fn signing_guard_malformed_last_array_is_error() {
        // Array present but first element is not a number.
        let guard = serde_json::json!({"last": ["bad", 0, 2], "votes": [], "lock": null});
        assert!(matches!(
            check_signing_compatibility(&guard, 10),
            Err(PersistError::SigningHistoryConflict { .. })
        ));
    }

    // ── F1 regression: data_dir fsynced after CURRENT rename ───────────────

    #[test]
    fn write_current_does_not_leave_tmp_file() {
        // write_current should atomically rename and leave no .tmp behind.
        let dir = make_temp_dir();
        write_current(dir.path(), "gen-000001").unwrap();
        assert!(!dir.path().join("CURRENT.tmp").exists(),
            "CURRENT.tmp must not survive after write_current");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("CURRENT")).unwrap().trim(),
            "gen-000001"
        );
    }

    // ── F3 regression: orphaned gen dirs without CURRENT are detected ───────

    #[test]
    fn orphaned_gen_dir_without_current_is_fatal() {
        // CURRENT absent but a gen-NNNNNN directory exists → CorruptManifest.
        let dir = make_temp_dir();
        let snaps = dir.path().join("snapshots");
        std::fs::create_dir_all(snaps.join("gen-000001")).unwrap();

        assert!(matches!(
            load_snapshot(dir.path()),
            Err(PersistError::CorruptManifest { .. })
        ), "orphaned gen dir without CURRENT must be detected as fatal");
    }

    #[test]
    fn empty_snapshots_dir_without_current_is_fresh() {
        // Empty snapshots/ with no CURRENT and no gen dirs → fresh install.
        let dir = make_temp_dir();
        std::fs::create_dir_all(dir.path().join("snapshots")).unwrap();
        assert!(load_snapshot(dir.path()).unwrap().is_none(),
            "empty snapshots/ with no CURRENT must be treated as fresh");
    }

    // ── crash-resilience: CURRENT not updated on incomplete write ──────────

    #[test]
    fn current_not_updated_on_interrupted_write() {
        let dir = make_temp_dir();
        // Write gen-000001 successfully.
        write_snapshot(dir.path(), 5, &dummy_contents(5)).unwrap();

        // Simulate crash during gen-000002 write: create the directory and write
        // some files, but do NOT call write_snapshot (so CURRENT stays on gen-000001).
        let partial = dir.path().join("snapshots").join("gen-000002");
        std::fs::create_dir_all(&partial).unwrap();
        std::fs::write(partial.join("state.json"), b"partial").unwrap();
        // CURRENT still points at gen-000001.

        // Load must return the committed gen-000001, not the partial gen-000002.
        let snap = load_snapshot(dir.path()).unwrap().expect("should have snapshot");
        assert_eq!(snap.generation, "gen-000001");
        assert_eq!(snap.height, 5);
    }
}
