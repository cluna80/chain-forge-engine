//! Filesystem [`Storage`]: temporary file, `fsync`, rename, directory `fsync`.
use super::{Storage, StorageError};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Safety-state storage in one directory. The directory must already exist and should be private to the validator.
#[derive(Debug, Clone)]
pub struct FsStorage { dir: PathBuf }

fn io(e: std::io::Error) -> StorageError { StorageError(e.to_string()) }

impl FsStorage {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let dir = dir.into();
        if !dir.is_dir() { return Err(StorageError(format!("{} is not a directory", dir.display()))); }
        Ok(FsStorage { dir })
    }

    /// File names are plain names: no separators, no `..`, not empty, so nothing escapes the directory.
    fn path(&self, name: &str) -> Result<PathBuf, StorageError> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
            return Err(StorageError(format!("invalid file name {name:?}")));
        }
        Ok(self.dir.join(name))
    }
}

/// Directory flush. Unix: `fsync` on the directory. Windows: `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS)` + `FlushFileBuffers`
/// (`File::sync_all`). Same technique as `chain-forge-node`'s `persistence::fsync_dir`. NOT VERIFIED beyond "the call
/// succeeds": whether this makes a rename durable across power loss on NTFS is not something a test can prove.
fn fsync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    { std::fs::File::open(path)?.sync_all() }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new().read(true).write(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(path)?.sync_all()
    }
    #[cfg(not(any(unix, windows)))]
    { let _ = path; Ok(()) }
}

impl Storage for FsStorage {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
        match std::fs::read(self.path(name)?) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(e)),
        }
    }

    fn write_tmp(&mut self, name: &str, data: &[u8]) -> Result<(), StorageError> {
        let mut f = std::fs::File::create(self.path(name)?).map_err(io)?;
        f.write_all(data).map_err(io)
    }

    fn sync_file(&mut self, name: &str) -> Result<(), StorageError> {
        std::fs::OpenOptions::new().write(true).open(self.path(name)?).map_err(io)?.sync_all().map_err(io)
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), StorageError> {
        std::fs::rename(self.path(from)?, self.path(to)?).map_err(io)
    }

    fn sync_dir(&mut self) -> Result<(), StorageError> { fsync_dir(&self.dir).map_err(io) }

    fn remove(&mut self, name: &str) -> Result<(), StorageError> {
        match std::fs::remove_file(self.path(name)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e)),
        }
    }
}
