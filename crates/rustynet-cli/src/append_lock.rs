#![forbid(unsafe_code)]

//! Shared exclusive-append lock for the committed live-lab ledgers.
//!
//! Extracted verbatim from the run-matrix append path, which was the only
//! consumer. Two ledgers now need the same guarantee, and a second, independently
//! written locking scheme is how two files end up with two different definitions
//! of "serialized" — so this is the one mechanism both use.
//!
//! Unix holds an exclusive advisory `flock` on a persistent lock file. The kernel
//! releases it when the descriptor closes, including on process death, so a
//! crashed holder never wedges the ledger. Non-unix falls back to an `O_EXCL`
//! lock file whose existence IS the lock (mirroring `rustynetd::resilience`);
//! auto-release on death is unix-only.
//!
//! Two properties worth preserving if this is ever edited:
//!
//! 1. The lock file is opened with `create(true)`, NOT `create_new`: a lock file
//!    may legitimately survive a crash, and mutual exclusion comes from the
//!    advisory lock, not from the file's existence.
//! 2. On unix the lock file is intentionally PERSISTENT — never unlinked on
//!    release. Removing it opens a split-inode race: with the name unlinked, two
//!    acquirers can each create a distinct inode, `flock` their own copy, and
//!    both enter the critical section.

use std::fs::{self, File, OpenOptions};
#[cfg(not(unix))]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg};

const MAX_WAIT: Duration = Duration::from_secs(10);
const WAIT_MS: u64 = 10;

/// RAII guard for a ledger's exclusive append lock. Dropping it releases.
pub struct AppendLock {
    // Only the non-unix (O_EXCL) path tracks the lock-file path for removal; the
    // unix path holds a persistent file and releases via the flock fd.
    #[cfg(not(unix))]
    path: PathBuf,
    #[cfg(unix)]
    _flock: Flock<File>,
    #[cfg(not(unix))]
    _handle: File,
}

impl Drop for AppendLock {
    fn drop(&mut self) {
        // Non-unix: the O_EXCL lock file's existence IS the lock, so remove it to
        // release. Unix: the advisory flock is released automatically when
        // `_flock`'s descriptor closes (including on process death), and the lock
        // file is intentionally persistent — see the module docs on the
        // split-inode race.
        #[cfg(not(unix))]
        let _ = fs::remove_file(&self.path);
    }
}

/// The lock-file path for a ledger: the ledger path plus `.lock`.
pub fn lock_path_for(path: &Path) -> PathBuf {
    let mut out = path.as_os_str().to_os_string();
    out.push(".lock");
    PathBuf::from(out)
}

/// Acquire the exclusive append lock for `lock_path`, failing closed on timeout
/// or a non-recoverable I/O error. `label` names the ledger in error messages so
/// a timeout says which ledger was contended.
#[cfg(unix)]
pub fn acquire_append_lock(lock_path: &Path, label: &str) -> Result<AppendLock, String> {
    let deadline = Instant::now() + MAX_WAIT;

    loop {
        // create(true) (NOT create_new): a lock file may legitimately survive a
        // crash; mutual exclusion comes from the advisory flock below.
        let mut options = OpenOptions::new();
        options.write(true).create(true).mode(0o600);
        match options.open(lock_path) {
            Ok(file) => match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
                Ok(flock) => {
                    return Ok(AppendLock { _flock: flock });
                }
                Err((_returned, _errno)) => {
                    // Held by another live descriptor (EWOULDBLOCK). A dead
                    // holder's flock is already released, so this loops only for
                    // genuine live contention.
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "acquire {label} append lock timed out ({})",
                            lock_path.display()
                        ));
                    }
                    sleep(Duration::from_millis(WAIT_MS));
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                // Wrong-owned lock file (e.g. left by a root-run op); we own the
                // directory, so unlink and recreate under our own UID.
                if fs::remove_file(lock_path).is_err() || Instant::now() >= deadline {
                    return Err(format!(
                        "acquire {label} append lock failed: wrong-owned lock ({})",
                        lock_path.display()
                    ));
                }
                sleep(Duration::from_millis(WAIT_MS));
            }
            Err(err) => {
                return Err(format!(
                    "open {label} append lock failed ({}): {err}",
                    lock_path.display()
                ));
            }
        }
    }
}

/// Non-unix fallback: `O_EXCL` lock file as a mutex (mirrors the
/// `rustynetd::resilience` non-unix path). Advisory-lock hardening (auto-release
/// on process death) is unix-only.
#[cfg(not(unix))]
pub fn acquire_append_lock(lock_path: &Path, label: &str) -> Result<AppendLock, String> {
    let deadline = Instant::now() + MAX_WAIT;

    loop {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        match options.open(lock_path) {
            Ok(mut handle) => {
                let stamp = format!("pid={}\n", std::process::id());
                let _ = handle.write_all(stamp.as_bytes());
                let _ = handle.sync_all();
                return Ok(AppendLock {
                    path: lock_path.to_path_buf(),
                    _handle: handle,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "acquire {label} append lock timed out ({})",
                        lock_path.display()
                    ));
                }
                sleep(Duration::from_millis(WAIT_MS));
            }
            Err(err) => {
                return Err(format!(
                    "open {label} append lock failed ({}): {err}",
                    lock_path.display()
                ));
            }
        }
    }
}
