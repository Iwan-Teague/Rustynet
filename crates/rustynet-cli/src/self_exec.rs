//! Stable re-execution target for flows that spawn `rustynet` self-ops.
//!
//! The CI gate flows (supply-chain integrity, security regression) re-execute
//! this binary for nested ops such as `ops sign-release-artifact`. On Linux,
//! `std::env::current_exe()` reports `<path> (deleted)` once another step
//! replaces the on-disk binary while the flow runs — exactly what the gates'
//! own `cargo test` stages do when they relink `target/debug/rustynet-cli` —
//! and exec'ing that path fails with ENOENT.
//!
//! [`pin_stable_self_executable`] snapshots the running image ONCE at flow
//! entry into a private 0700 directory under the temp dir (file mode 0500),
//! and [`stable_self_executable`] hands that immutable path to every nested
//! self-op. On Linux the snapshot is read from `/proc/self/exe`, i.e. the
//! inode the kernel itself associates with this process, so the code that is
//! executed downstream is by construction the code that is running — a path
//! that was replaced or deleted is never guessed at, and no " (deleted)"
//! suffix is ever stripped. [`cleanup_stable_self_executable`] removes the
//! copy when the process ends.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(unix)]
const COPY_FILE_NAME: &str = "rustynet-cli";
#[cfg(unix)]
const COPY_DIR_PREFIX: &str = "rustynet-self-exec-";
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o500;
#[cfg(unix)]
const MAX_DIR_ATTEMPTS: u32 = 8;

static STABLE_SELF: Mutex<Option<StableSelfBinary>> = Mutex::new(None);

struct StableSelfBinary {
    dir: Option<PathBuf>,
    file: PathBuf,
}

impl Drop for StableSelfBinary {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = fs::remove_file(&self.file);
            let _ = fs::remove_dir(dir);
        }
    }
}

fn lock_stable_self() -> MutexGuard<'static, Option<StableSelfBinary>> {
    match STABLE_SELF.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Eagerly snapshot the running image so nested self-ops can rely on it.
pub(crate) fn pin_stable_self_executable() -> Result<(), String> {
    let mut guard = lock_stable_self();
    if guard.is_none() {
        *guard = Some(acquire()?);
    }
    Ok(())
}

/// Path of the pinned copy of the running executable, creating it on first use.
pub(crate) fn stable_self_executable() -> Result<PathBuf, String> {
    let mut guard = lock_stable_self();
    if guard.is_none() {
        *guard = Some(acquire()?);
    }
    guard
        .as_ref()
        .map(|binary| binary.file.clone())
        .ok_or_else(|| "stable self-executable vanished while locked".to_owned())
}

/// Remove the pinned copy; a no-op when nothing was pinned.
pub(crate) fn cleanup_stable_self_executable() {
    *lock_stable_self() = None;
}

#[cfg(unix)]
fn acquire() -> Result<StableSelfBinary, String> {
    let source = source_executable()?;
    let dir = create_private_dir()?;
    let file = dir.join(COPY_FILE_NAME);
    copy_source_into_private_dir(&source, &file)?;
    Ok(StableSelfBinary {
        dir: Some(dir),
        file,
    })
}

#[cfg(not(unix))]
fn acquire() -> Result<StableSelfBinary, String> {
    let path = source_executable()?;
    Ok(StableSelfBinary {
        dir: None,
        file: path,
    })
}

/// The executable image this process is running, as the kernel sees it.
#[cfg(target_os = "linux")]
fn source_executable() -> Result<SourceBinary, String> {
    let path = Path::new("/proc/self/exe");
    let metadata =
        fs::metadata(path).map_err(|error| format!("resolve /proc/self/exe failed: {error}"))?;
    if !metadata.is_file() {
        return Err(
            "/proc/self/exe is not a regular file; refusing to pin a self-executable".to_owned(),
        );
    }
    Ok(SourceBinary {
        path: path.to_path_buf(),
        len: metadata.len(),
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn source_executable() -> Result<SourceBinary, String> {
    let path = std::env::current_exe()
        .map_err(|error| format!("resolve current executable failed: {error}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("stat current executable {} failed: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "current executable {} is not a regular file; refusing to pin a self-executable",
            path.display()
        ));
    }
    Ok(SourceBinary {
        path,
        len: metadata.len(),
    })
}

#[cfg(not(unix))]
fn source_executable() -> Result<PathBuf, String> {
    let path = std::env::current_exe()
        .map_err(|error| format!("resolve current executable failed: {error}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("stat current executable {} failed: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "current executable {} is not a regular file; refusing to pin a self-executable",
            path.display()
        ));
    }
    Ok(path)
}

#[cfg(unix)]
struct SourceBinary {
    path: PathBuf,
    len: u64,
}

#[cfg(unix)]
fn create_private_dir() -> Result<PathBuf, String> {
    let base = std::env::temp_dir();
    for attempt in 0..MAX_DIR_ATTEMPTS {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let candidate = base.join(format!(
            "{COPY_DIR_PREFIX}{}-{nanos}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                fs::set_permissions(&candidate, fs::Permissions::from_mode(DIR_MODE)).map_err(
                    |error| {
                        format!(
                            "restrict {} to mode {DIR_MODE:o} failed: {error}",
                            candidate.display()
                        )
                    },
                )?;
                assert_mode(&candidate, DIR_MODE)?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("create {} failed: {error}", candidate.display())),
        }
    }
    Err(format!(
        "no private directory for the stable self-executable after {MAX_DIR_ATTEMPTS} attempts"
    ))
}

#[cfg(unix)]
fn copy_source_into_private_dir(source: &SourceBinary, target: &Path) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(target)
        .map_err(|error| format!("create {} failed: {error}", target.display()))?;
    let mut input = fs::File::open(&source.path)
        .map_err(|error| format!("open {} failed: {error}", source.path.display()))?;
    std::io::copy(&mut input, &mut file).map_err(|error| {
        format!(
            "copy {} to {} failed: {error}",
            source.path.display(),
            target.display()
        )
    })?;
    drop(file);
    fs::set_permissions(target, fs::Permissions::from_mode(FILE_MODE)).map_err(|error| {
        format!(
            "restrict {} to mode {FILE_MODE:o} failed: {error}",
            target.display()
        )
    })?;
    assert_mode(target, FILE_MODE)?;
    let copied = fs::metadata(target)
        .map_err(|error| format!("stat {} failed: {error}", target.display()))?
        .len();
    if copied != source.len {
        return Err(format!(
            "copied {copied} bytes to {} but the running executable is {} bytes",
            target.display(),
            source.len
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn assert_mode(path: &Path, expected: u32) -> Result<(), String> {
    let mode = fs::metadata(path)
        .map_err(|error| format!("stat {} failed: {error}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != expected {
        return Err(format!(
            "{} has mode {mode:o}, expected {expected:o}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_executable_resolves_a_regular_file() {
        let resolved = source_executable().expect("source executable resolves");
        #[cfg(unix)]
        {
            assert!(resolved.path.is_file());
            assert!(resolved.len > 0);
        }
        #[cfg(not(unix))]
        assert!(resolved.is_file());
    }

    // One test on purpose: it drives the process-global pinned-copy slot and
    // the end-of-process cleanup, so it must not race parallel sibling tests.
    #[cfg(unix)]
    #[test]
    fn stable_self_executable_is_private_copy_of_running_image_and_cleans_up() {
        pin_stable_self_executable().expect("pin succeeds");
        let pinned = stable_self_executable().expect("pinned path available");
        assert!(pinned.is_file(), "pinned copy must exist");
        let metadata = fs::metadata(&pinned).expect("pinned copy is statable");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o500, "file mode");
        let dir = pinned
            .parent()
            .expect("pinned copy has a parent")
            .to_path_buf();
        assert_eq!(
            fs::metadata(&dir)
                .expect("private dir is statable")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "directory mode"
        );
        assert!(
            dir.file_name()
                .expect("private dir has a name")
                .to_string_lossy()
                .starts_with("rustynet-self-exec-"),
            "private dir lives under a namespaced temp path"
        );

        #[cfg(target_os = "linux")]
        let running = Path::new("/proc/self/exe").to_path_buf();
        #[cfg(not(target_os = "linux"))]
        let running = std::env::current_exe().expect("current executable resolves");
        let pinned_bytes = fs::read(&pinned).expect("pinned copy is readable");
        let running_bytes = fs::read(&running).expect("running image is readable");
        assert_eq!(pinned_bytes.len(), running_bytes.len(), "byte length");
        assert_eq!(
            pinned_bytes, running_bytes,
            "byte-identical to running image"
        );

        cleanup_stable_self_executable();
        assert!(!pinned.exists(), "pinned copy removed on cleanup");
        assert!(!dir.exists(), "private dir removed on cleanup");
        cleanup_stable_self_executable();
    }
}
