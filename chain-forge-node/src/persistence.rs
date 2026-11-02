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
    /// The manifest is of a format, chain or genesis this node must not load
    /// (missing/unknown `format_version`, blank or mismatched `chain_id` /
    /// `genesis_hash`). `detail` is the operator-facing text.
    IncompatibleManifest { gen: String, detail: String },
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
            PersistError::MissingFile { gen, file } if gen == "legacy" =>
                write!(f, "{file} missing from the pre-H0-3 data directory — restore the file \
                           or start with a clean data directory"),
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
                           — restore the chain state from a peer or start with a clean data directory"),
            PersistError::IncompatibleManifest { gen, detail } =>
                write!(f, "generation '{gen}': {detail}"),
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
    /// Storage format of this generation. Written as `FORMAT_VERSION`. `None`
    /// only when parsing a manifest written by a pre-H0-3b node, which the
    /// loader refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_version: Option<u64>,
    /// `chain_id` of the genesis the writing node was running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    /// `chain_forge_core::genesis_hash_hex` of that genesis (64 hex chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_hash: Option<String>,
    /// The state root (64 hex; an empty tree is 64 zeros) of the live tree when
    /// this generation was written. The loader requires the restored state to
    /// reproduce it. `None` only when parsing a manifest that lacks it, which
    /// the loader refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    /// The committed block height this snapshot captures.
    pub height: u64,
    /// Generation label, e.g. "gen-000042".
    pub generation: String,
    /// Per-file integrity records.
    pub files: Vec<FileEntry>,
}

/// The storage format this node reads and writes. Bump on any incompatible
/// change; a node refuses every other version (no downgrade, no silent upgrade).
pub const FORMAT_VERSION: u64 = 1;

/// Who a snapshot belongs to. Always derived from the genesis the node is
/// RUNNING (`Node::snapshot_identity`) — never from a flag, file or environment
/// variable — so a mismatch at startup is caught by the loader's comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotIdentity {
    pub chain_id:     String,
    /// 64 lowercase hex characters.
    pub genesis_hash: String,
}

impl SnapshotIdentity {
    /// An identity that could match anything is not an identity.
    fn validate(&self) -> Result<(), String> {
        if self.chain_id.trim().is_empty() { return Err("chain_id is blank".into()); }
        if !is_hash_hex(&self.genesis_hash) { return Err("genesis_hash is not 64 hex characters".into()); }
        Ok(())
    }
}

/// The state root of an empty tree: 64 zeros. A root is never absent.
pub const EMPTY_STATE_ROOT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The manifest's `state_root`, validated: present, not blank, 64 hex.
fn manifest_state_root(m: &SnapshotManifest, gen: &str) -> Result<String, PersistError> {
    let bad = |detail: String| PersistError::IncompatibleManifest { gen: gen.to_string(), detail };
    match m.state_root.as_deref() {
        None => Err(bad("manifest state_root is missing — a manifest without a root offers no \
                         integrity guarantee; start with a clean data directory".into())),
        Some(r) if r.trim().is_empty() => Err(bad("manifest state_root is blank".into())),
        Some(r) if !is_hash_hex(r) => Err(bad(format!("manifest state_root '{r}' is not 64 hex characters"))),
        Some(r) => Ok(r.to_ascii_lowercase()),
    }
}

fn is_hash_hex(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) }

/// Refuse a manifest that is of another format, chain or genesis. Order:
/// format_version, chain_id, genesis_hash. Blank, whitespace-only or missing
/// identity fields are refused outright (never a wildcard).
fn check_manifest_identity(m: &SnapshotManifest, gen: &str, expected: &SnapshotIdentity)
    -> Result<(), PersistError>
{
    let bad = |detail: String| PersistError::IncompatibleManifest { gen: gen.to_string(), detail };
    match m.format_version {
        None => return Err(bad(
            "generation manifest missing format_version — written by a pre-H0-3b node; \
             start with a clean data directory".into())),
        Some(v) if v != FORMAT_VERSION => return Err(bad(format!(
            "manifest format_version {v} is not supported by this node (it reads format_version \
             {FORMAT_VERSION}); start with a clean data directory"))),
        Some(_) => {}
    }
    match m.chain_id.as_deref() {
        None => return Err(bad("manifest chain_id is missing".into())),
        Some(c) if c.trim().is_empty() => return Err(bad("manifest chain_id is blank".into())),
        Some(c) if c != expected.chain_id => return Err(bad(format!(
            "manifest chain_id '{c}' does not match this node's chain_id '{}' — this data \
             belongs to another chain", expected.chain_id))),
        Some(_) => {}
    }
    match m.genesis_hash.as_deref() {
        None => return Err(bad("manifest genesis_hash is missing".into())),
        Some(h) if h.trim().is_empty() => return Err(bad("manifest genesis_hash is blank".into())),
        Some(h) if !is_hash_hex(h) => return Err(bad(format!(
            "manifest genesis_hash '{h}' is not 64 hex characters"))),
        Some(h) if !h.eq_ignore_ascii_case(&expected.genesis_hash) => return Err(bad(format!(
            "manifest genesis_hash {h} does not match this node's genesis_hash {} — this data \
             was written under a different genesis", expected.genesis_hash))),
        Some(_) => {}
    }
    Ok(())
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

/// Flush a directory so that renames and creations inside it are durable.
/// Errors are REAL errors: a missing directory, a failed open or a failed flush
/// is returned, never swallowed, and the caller (`write_snapshot`,
/// `write_current`, the signing-guard write) propagates it so the commit fails
/// loudly and the node halts consensus rather than continuing on a snapshot or
/// guard it cannot prove durable.
///
/// * Unix: open the directory and `fsync` it.
/// * Windows: open the directory with `FILE_FLAG_BACKUP_SEMANTICS` (required to
///   open a directory handle) and `FlushFileBuffers` it (`File::sync_all`). The
///   handle is owned by a `File`, so it is closed when it drops, including on
///   the error path. NOT VERIFIED beyond "the call succeeds": whether this makes
///   a rename durable across power loss on NTFS is not something a test can
///   prove; the Windows validation run shows only that it does not fail.
///
/// KNOWN GAP — transient sharing violations. On Windows an antivirus or indexer
/// can briefly hold a file or directory open (ERROR_SHARING_VIOLATION), making a
/// create, rename or this flush fail. There is deliberately NO retry here: the
/// failure surfaces as an error. Adding a retry policy is a SEPARATE DECISION and
/// must be validated by a Windows run (see docs/persist-001-p02-design.md §15);
/// do not add one without going through that gate.
pub(crate) fn fsync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    fsync_probe::on_fsync(path)?; // test seam only: records the call, may inject a failure
    #[cfg(unix)]
    {
        std::fs::File::open(path)?.sync_all()
    }
    #[cfg(windows)]
    {
        flush_dir_windows(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

/// Windows directory flush: `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS)` +
/// `FlushFileBuffers`. `FlushFileBuffers` needs write access to the handle.
#[cfg(windows)]
fn flush_dir_windows(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    // The `File` owns the handle: it is closed on drop whether `sync_all`
    // succeeds or fails, so nothing leaks on the error path.
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    dir.sync_all()
}

/// TEST SEAM (compiled only for unit tests; changes no behaviour). Records every
/// directory fsync in order, and can make the one for a path ending in `suffix`
/// fail. Thread-local, so it is only meaningful on a current-thread runtime
/// (the default for `#[tokio::test]`).
#[cfg(test)]
pub(crate) mod fsync_probe {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    thread_local! {
        static LOG: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
        static FAIL: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    pub fn reset() {
        LOG.with(|l| l.borrow_mut().clear());
        FAIL.with(|f| *f.borrow_mut() = None);
    }
    /// Every directory fsync since `reset`, in call order.
    pub fn calls() -> Vec<PathBuf> { LOG.with(|l| l.borrow().clone()) }
    /// Make the directory fsync for any path ending in `suffix` fail with an I/O error.
    pub fn fail_on(suffix: &str) { FAIL.with(|f| *f.borrow_mut() = Some(suffix.to_string())); }

    pub(super) fn on_fsync(path: &Path) -> std::io::Result<()> {
        LOG.with(|l| l.borrow_mut().push(path.to_path_buf()));
        let hit = FAIL.with(|f| f.borrow().as_ref().map(|suf| path.ends_with(suf)).unwrap_or(false));
        if hit {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "injected directory fsync failure"));
        }
        Ok(())
    }
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
/// After the atomic rename of the CURRENT tmp file, `data_dir` itself is
/// flushed so the rename is durable (POSIX requires an explicit directory fsync
/// to guarantee a rename survives a crash; on Windows see `fsync_dir`).
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
    identity: &SnapshotIdentity,
    state_root: &str,
) -> Result<String, PersistError> {
    if !is_hash_hex(state_root) {
        return Err(PersistError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput,
            format!("snapshot state_root '{state_root}' is not 64 hex characters"))));
    }
    // Never write a wildcard identity: it would be accepted by any chain.
    identity.validate().map_err(|why| PersistError::Io(
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("snapshot identity: {why}"))))?;
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
    let manifest = SnapshotManifest {
        format_version: Some(FORMAT_VERSION),
        chain_id:       Some(identity.chain_id.clone()),
        genesis_hash:   Some(identity.genesis_hash.clone()),
        state_root:     Some(state_root.to_ascii_lowercase()),
        height,
        generation: gen.clone(),
        files: file_entries,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    write_atomic_bytes(&gen_dir.join("manifest.json"), &manifest_bytes)?;

    // Fsync the generation directory again so the manifest rename is durable.
    fsync_dir(&gen_dir)?;

    // Make the generation directory's own entry (in snapshots/) durable BEFORE
    // CURRENT is renamed to point at it. Without this, CURRENT could survive a
    // crash while the directory it names does not.
    fsync_dir(&snaps)?;

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
    /// The manifest's validated `state_root` (lowercase 64 hex). The CALLER must
    /// compare it with the root the restored state actually produces.
    pub state_root: String,
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
pub fn load_snapshot(data_dir: &Path, expected: &SnapshotIdentity)
    -> Result<Option<SnapshotContents>, PersistError>
{
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

    // Format, chain and genesis are checked BEFORE any file is trusted.
    check_manifest_identity(&manifest, &gen_label_str, expected)?;

    let state_root = manifest_state_root(&manifest, &gen_label_str)?;

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
        state_root,
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
pub fn migrate_legacy(
    data_dir: &Path,
    identity: &SnapshotIdentity,
    restored_root_of: impl FnOnce(&[u8]) -> Result<String, String>,
) -> Result<Option<String>, PersistError> {
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

    // ORDER MATTERS — do not reorder. `write_snapshot` writes `CURRENT` LAST, so
    // the generation is complete and verified before anything points at it.
    // A crash before that leaves the legacy files untouched and `CURRENT`
    // absent: the next start simply migrates again. A crash AFTER it but before
    // the archive move below leaves `CURRENT` on a valid generation: the next
    // start loads it (`migrate_legacy` returns early once `CURRENT` exists) and
    // the stale legacy files are ignored. Moving the files BEFORE `CURRENT`
    // exists would lose the only copy of the state on a crash.
    // The legacy layout recorded no root. Record the root the legacy state
    // REBUILDS to (what restore will produce), supplied by the caller from
    // `state.json`'s bytes.
    let state_bytes = &contents.iter().find(|(n, _)| *n == "state.json").expect("state.json present").1;
    let state_root = restored_root_of(state_bytes).map_err(|detail| PersistError::CorruptFile {
        gen: "legacy".into(), file: "state.json".into(), detail })?;
    let gen = write_snapshot(data_dir, height, &contents, identity, &state_root)?;

    // The new generation exists and CURRENT points at it. Archive (move) the
    // legacy files so a future start cannot mistake them for current state.
    let archive = persist.join(LEGACY_ARCHIVE_DIR);
    std::fs::create_dir_all(&archive).map_err(PersistError::Io)?;
    for &name in SNAPSHOT_FILES {
        std::fs::rename(persist.join(name), archive.join(name)).map_err(PersistError::Io)?;
    }
    Ok(Some(gen))
}

/// D6: does the consensus signing guard prove that chain state must exist?
///
/// Returns `Ok(Some(h))` when `persist/consensus_signing.json` exists and its
/// last signed height `h` is above the first decidable height (0): signing at
/// height >= 1 is only possible after height 0 was committed and persisted, so
/// a guard like that with NO chain state means the state was lost.
/// Returns `Ok(None)` when there is no guard, or the guard has never signed, or
/// it last signed at height 0 — a validator may legitimately vote on the first
/// block before its first commit writes any state. An unreadable guard is an
/// error (the guard cannot be proven empty).
pub fn guard_proves_missing_state(data_dir: &Path) -> Result<Option<u64>, PersistError> {
    let path = data_dir.join("persist").join("consensus_signing.json");
    if !path.exists() { return Ok(None); }
    let text = std::fs::read_to_string(&path).map_err(PersistError::Io)?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        PersistError::SigningHistoryConflict { detail: format!("consensus_signing.json unreadable: {e}") }
    })?;
    match &v["last"] {
        serde_json::Value::Array(a) => match a.first().and_then(|h| h.as_u64()) {
            Some(h) if h > 0 => Ok(Some(h)),
            Some(_) => Ok(None),
            None => Err(PersistError::SigningHistoryConflict {
                detail: "consensus_signing.json: 'last' has no numeric height".into() }),
        },
        _ => Ok(None),
    }
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

    fn test_root() -> String { "cd".repeat(32) }

    fn test_identity() -> SnapshotIdentity {
        SnapshotIdentity { chain_id: "test-chain".into(), genesis_hash: "ab".repeat(32) }
    }

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
        assert!(matches!(load_snapshot(dir.path(), &test_identity()), Ok(None)), "fresh dir must return Ok(None)");
    }

    #[test]
    fn round_trip_single_generation() {
        let dir = make_temp_dir();
        let contents = dummy_contents(5);
        let gen = write_snapshot(dir.path(), 5, &contents, &test_identity(), &test_root()).unwrap();
        assert_eq!(gen, "gen-000001");

        let snap = load_snapshot(dir.path(), &test_identity()).unwrap().expect("should have snapshot");
        assert_eq!(snap.height, 5);
        assert_eq!(snap.generation, "gen-000001");
        assert!(snap.files.contains_key("state.json"));
    }

    #[test]
    fn second_write_increments_generation() {
        let dir = make_temp_dir();
        write_snapshot(dir.path(), 5, &dummy_contents(5), &test_identity(), &test_root()).unwrap();
        let gen2 = write_snapshot(dir.path(), 6, &dummy_contents(6), &test_identity(), &test_root()).unwrap();
        assert_eq!(gen2, "gen-000002");

        let snap = load_snapshot(dir.path(), &test_identity()).unwrap().expect("snapshot");
        assert_eq!(snap.height, 6);
        assert_eq!(snap.generation, "gen-000002");
    }

    #[test]
    fn gen_minus_2_is_pruned() {
        let dir = make_temp_dir();
        write_snapshot(dir.path(), 1, &dummy_contents(1), &test_identity(), &test_root()).unwrap(); // gen-000001
        write_snapshot(dir.path(), 2, &dummy_contents(2), &test_identity(), &test_root()).unwrap(); // gen-000002
        write_snapshot(dir.path(), 3, &dummy_contents(3), &test_identity(), &test_root()).unwrap(); // gen-000003 → prunes gen-000001
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
            load_snapshot(dir.path(), &test_identity()),
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
            load_snapshot(dir.path(), &test_identity()),
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
            load_snapshot(dir.path(), &test_identity()),
            Err(PersistError::CorruptManifest { .. })
        ));
    }

    #[test]
    fn load_missing_file_is_error() {
        let dir = make_temp_dir();
        // Write a valid snapshot then delete one file from the generation dir.
        write_snapshot(dir.path(), 5, &dummy_contents(5), &test_identity(), &test_root()).unwrap();
        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        std::fs::remove_file(gen_dir.join("identity.json")).unwrap();
        assert!(matches!(
            load_snapshot(dir.path(), &test_identity()),
            Err(PersistError::MissingFile { .. })
        ));
    }

    #[test]
    fn load_hash_mismatch_is_error() {
        let dir = make_temp_dir();
        write_snapshot(dir.path(), 5, &dummy_contents(5), &test_identity(), &test_root()).unwrap();
        // Corrupt identity.json after it was written.
        let gen_dir = dir.path().join("snapshots").join("gen-000001");
        std::fs::write(gen_dir.join("identity.json"), b"CORRUPTED").unwrap();
        assert!(matches!(
            load_snapshot(dir.path(), &test_identity()),
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
        write_snapshot(dir.path(), 5, &contents, &test_identity(), &test_root()).unwrap();
        assert!(matches!(
            load_snapshot(dir.path(), &test_identity()),
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
        write_snapshot(dir.path(), 5, &contents, &test_identity(), &test_root()).unwrap();
        assert!(matches!(
            load_snapshot(dir.path(), &test_identity()),
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
            load_snapshot(dir.path(), &test_identity()),
            Err(PersistError::CorruptManifest { .. })
        ), "orphaned gen dir without CURRENT must be detected as fatal");
    }

    #[test]
    fn empty_snapshots_dir_without_current_is_fresh() {
        // Empty snapshots/ with no CURRENT and no gen dirs → fresh install.
        let dir = make_temp_dir();
        std::fs::create_dir_all(dir.path().join("snapshots")).unwrap();
        assert!(load_snapshot(dir.path(), &test_identity()).unwrap().is_none(),
            "empty snapshots/ with no CURRENT must be treated as fresh");
    }

    // ── Gap 5: directory fsync ordering and error propagation ───────────────
    //
    // Written FIRST. The probe records each directory fsync in order. Findings
    // that these tests pin on Linux: `snapshots/` is never fsynced after the new
    // generation directory is created, so CURRENT can become durable before the
    // directory entry it points at. Windows durability is NOT testable here; see
    // the notes at the end of this block.

    use super::fsync_probe;

    /// D1 — EXPECTED TO FAIL. The generation directory's entry (in `snapshots/`)
    /// must be durable BEFORE CURRENT is renamed to point at it, and the last
    /// directory fsync must be the data dir that holds CURRENT.
    #[test]
    fn d1_snapshots_dir_is_fsynced_before_current_and_data_dir_last() {
        let dir = make_temp_dir();
        fsync_probe::reset();
        write_snapshot(dir.path(), 5, &dummy_contents(5), &test_identity(), &test_root()).unwrap();
        let calls = fsync_probe::calls();
        let snaps = dir.path().join("snapshots");
        let gen = snaps.join("gen-000001");
        let pos = |p: &std::path::Path| calls.iter().position(|c| c == p);
        // existing guarantees (must keep holding)
        assert!(calls.iter().filter(|c| **c == gen).count() >= 2,
            "gen dir fsynced after the files and again after the manifest: {calls:?}");
        assert_eq!(calls.last(), Some(&dir.path().to_path_buf()),
            "the data dir (CURRENT's directory) must be fsynced last: {calls:?}");
        // the defect
        let s = pos(&snaps).unwrap_or_else(|| panic!("snapshots/ is never fsynced: {calls:?}"));
        let last_gen = calls.iter().rposition(|c| *c == gen).unwrap();
        assert!(s > last_gen && s < calls.len() - 1,
            "snapshots/ must be fsynced after the gen dir is complete and before CURRENT's \
             directory: {calls:?}");
    }

    /// D3 — SAFETY NET. A failed directory fsync of the generation is an ERROR
    /// from write_snapshot and CURRENT is not advanced: the commit did not happen.
    #[test]
    fn d3_a_failed_generation_fsync_is_an_error_and_current_is_not_advanced() {
        let dir = make_temp_dir();
        write_snapshot(dir.path(), 5, &dummy_contents(5), &test_identity(), &test_root()).unwrap();
        assert_eq!(read_current(dir.path()).unwrap().as_deref(), Some("gen-000001"));
        fsync_probe::reset();
        fsync_probe::fail_on("gen-000002");
        let err = write_snapshot(dir.path(), 6, &dummy_contents(6), &test_identity(), &test_root())
            .expect_err("a failed directory fsync must fail the snapshot write");
        assert!(matches!(err, PersistError::Io(_)), "{err}");
        assert_eq!(read_current(dir.path()).unwrap().as_deref(), Some("gen-000001"),
            "CURRENT must still point at the last committed generation");
    }

    /// D4 — SAFETY NET. A failure flushing the directory that holds CURRENT is
    /// also an error (the caller halts consensus), never silently dropped.
    #[test]
    fn d4_a_failed_current_directory_fsync_is_an_error() {
        let dir = make_temp_dir();
        fsync_probe::reset();
        let data_dir_name = dir.path().file_name().unwrap().to_string_lossy().to_string();
        fsync_probe::fail_on(&data_dir_name);
        let err = write_snapshot(dir.path(), 5, &dummy_contents(5), &test_identity(), &test_root())
            .expect_err("a failed fsync of CURRENT's directory must be reported");
        assert!(matches!(err, PersistError::Io(_)), "{err}");
    }

    /// D6 — fsync_dir on a directory that does not exist must be an ERROR on every
    /// platform. Passes on Linux today. On Windows `fsync_dir` is a no-op that
    /// returns Ok, so this FAILS there until the Windows branch really opens and
    /// flushes the directory. (Demonstrated on the Windows validation run.)
    #[test]
    fn d6_fsync_of_a_missing_directory_is_an_error_on_every_platform() {
        let dir = make_temp_dir();
        let missing = dir.path().join("does-not-exist");
        assert!(fsync_dir(&missing).is_err(), "fsync_dir must not swallow a missing directory");
        assert!(fsync_dir(dir.path()).is_ok(), "fsync of an existing directory succeeds");
    }

    // Not unit-testable (documented gap, to be exercised by the Windows run):
    //  * Windows durability. Whether FlushFileBuffers on a directory handle makes a
    //    rename durable on NTFS is not something a test can prove; the Windows run
    //    can show only that the call SUCCEEDS (no ACCESS_DENIED) and the node
    //    restarts correctly. A power-loss test is out of scope.
    //  * Transient sharing violations (ERROR_SHARING_VIOLATION, e.g. antivirus
    //    holding a file during rename or create). The persistence code does not
    //    retry; it fails the commit loudly and the node halts consensus. A retry
    //    policy would need its own decision and a Windows run to exercise.

    // ── crash-resilience: CURRENT not updated on incomplete write ──────────

    #[test]
    fn current_not_updated_on_interrupted_write() {
        let dir = make_temp_dir();
        // Write gen-000001 successfully.
        write_snapshot(dir.path(), 5, &dummy_contents(5), &test_identity(), &test_root()).unwrap();

        // Simulate crash during gen-000002 write: create the directory and write
        // some files, but do NOT call write_snapshot (so CURRENT stays on gen-000001).
        let partial = dir.path().join("snapshots").join("gen-000002");
        std::fs::create_dir_all(&partial).unwrap();
        std::fs::write(partial.join("state.json"), b"partial").unwrap();
        // CURRENT still points at gen-000001.

        // Load must return the committed gen-000001, not the partial gen-000002.
        let snap = load_snapshot(dir.path(), &test_identity()).unwrap().expect("should have snapshot");
        assert_eq!(snap.generation, "gen-000001");
        assert_eq!(snap.height, 5);
    }
}
