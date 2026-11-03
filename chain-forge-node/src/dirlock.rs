//! PERSIST-001 P-02b PR 1 — exclusive data-directory lock (UNWIRED).
//!
//! Owner decision (2026-11-03): an OS-backed exclusive lock, **not** lock-file existence. The lock is
//! held on an open file handle (`File::try_lock`: `flock` on Unix, `LockFileEx` on Windows), so the
//! operating system releases it when the process exits or is killed, and a stale `LOCK` file left behind
//! by a crash never blocks a restart. A second holder, in this or another process, fails fast with
//! [`LockError::Busy`]; there is no wait and no override.

#![allow(dead_code)]

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum LockError {
    /// Another process (or another handle in this process) holds the lock.
    Busy(PathBuf),
    Io(std::io::Error),
}
impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Busy(p) => write!(f, "data directory is in use by another process (lock {})", p.display()),
            LockError::Io(e) => write!(f, "cannot take the data-directory lock: {e}"),
        }
    }
}
impl std::error::Error for LockError {}

/// Holds the lock until dropped (or until the process dies).
#[derive(Debug)]
pub struct DataDirLock { _file: File, path: PathBuf }

impl DataDirLock {
    pub const FILE_NAME: &'static str = "LOCK";

    pub fn acquire(data_dir: &Path) -> Result<Self, LockError> {
        std::fs::create_dir_all(data_dir).map_err(LockError::Io)?;
        let path = data_dir.join(Self::FILE_NAME);
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path).map_err(LockError::Io)?;
        match file.try_lock() {
            Ok(()) => Ok(DataDirLock { _file: file, path }),
            Err(TryLockError::WouldBlock) => Err(LockError::Busy(path)),
            Err(TryLockError::Error(e)) => Err(LockError::Io(e)),
        }
    }
    pub fn path(&self) -> &Path { &self.path }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cf-dirlock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d); d
    }

    #[test]
    fn second_acquire_in_the_same_process_is_refused_then_allowed_after_drop() {
        let d = tmp("same");
        let a = DataDirLock::acquire(&d).unwrap();
        assert!(matches!(DataDirLock::acquire(&d), Err(LockError::Busy(_))));
        drop(a);
        let _b = DataDirLock::acquire(&d).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn existence_of_the_lock_file_alone_does_not_block() {
        let d = tmp("stale"); std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(DataDirLock::FILE_NAME), b"left behind by a crashed process").unwrap();
        let l = DataDirLock::acquire(&d).unwrap();
        drop(l);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Child-process half of the cross-process test: holds the lock until its stdin closes or it is killed.
    #[test]
    fn child_holder() {
        let Ok(dir) = std::env::var("CF_DIRLOCK_HOLD") else { return };
        let _l = DataDirLock::acquire(Path::new(&dir)).expect("child must get the lock");
        std::fs::write(Path::new(&dir).join("child-has-lock"), b"1").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(120));
    }

    /// A second PROCESS is refused while the first holds the lock; after the first is KILLED (no
    /// cleanup code runs), the stale LOCK file is still on disk and the lock is nevertheless free.
    #[test]
    fn another_process_is_refused_and_a_killed_holder_releases_the_lock() {
        let d = tmp("xproc"); std::fs::create_dir_all(&d).unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut child = Command::new(exe).args(["--exact", "dirlock::tests::child_holder", "--nocapture", "--test-threads=1"])
            .env("CF_DIRLOCK_HOLD", &d).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let marker = d.join("child-has-lock");
        let t = std::time::Instant::now();
        while !marker.exists() { assert!(t.elapsed().as_secs() < 60, "child never took the lock"); std::thread::sleep(std::time::Duration::from_millis(50)); }
        assert!(matches!(DataDirLock::acquire(&d), Err(LockError::Busy(_))), "a second process must be refused");
        child.kill().unwrap(); child.wait().unwrap();           // SIGKILL / TerminateProcess: no destructors run
        assert!(d.join(DataDirLock::FILE_NAME).exists(), "the stale lock file is still there");
        let l = DataDirLock::acquire(&d).expect("the OS released the lock when the holder died");
        drop(l);
        let _ = std::fs::remove_dir_all(&d);
    }
}
