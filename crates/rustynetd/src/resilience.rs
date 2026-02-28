#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectPolicy {
    pub initial_backoff_ms: u64,
    pub multiplier: u32,
    pub max_backoff_ms: u64,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff_ms: 250,
            multiplier: 2,
            max_backoff_ms: 5_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStateSnapshot {
    pub timestamp_unix: u64,
    pub peer_ids: Vec<String>,
    pub selected_exit_node: Option<String>,
    pub lan_access_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResilienceError {
    Io,
    IntegrityMismatch,
    InvalidFormat,
}

impl fmt::Display for ResilienceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResilienceError::Io => f.write_str("i/o error"),
            ResilienceError::IntegrityMismatch => f.write_str("integrity mismatch"),
            ResilienceError::InvalidFormat => f.write_str("invalid format"),
        }
    }
}

impl std::error::Error for ResilienceError {}

pub fn next_reconnect_delay_ms(policy: ReconnectPolicy, attempt: u32) -> u64 {
    let factor = policy.multiplier.saturating_pow(attempt);
    let backoff = policy.initial_backoff_ms.saturating_mul(u64::from(factor));
    backoff.min(policy.max_backoff_ms)
}

pub fn persist_session_snapshot(
    snapshot: &SessionStateSnapshot,
    path: impl AsRef<Path>,
) -> Result<(), ResilienceError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| ResilienceError::Io)?;
    }

    let peers_csv = snapshot.peer_ids.join(",");
    let mut body = String::new();
    body.push_str(&format!("timestamp_unix={}\n", snapshot.timestamp_unix));
    body.push_str(&format!("peer_ids={peers_csv}\n"));
    body.push_str(&format!(
        "selected_exit_node={}\n",
        snapshot
            .selected_exit_node
            .clone()
            .unwrap_or_else(|| "none".to_string())
    ));
    body.push_str(&format!(
        "lan_access_enabled={}\n",
        if snapshot.lan_access_enabled {
            "true"
        } else {
            "false"
        }
    ));
    let digest = sha256_hex(body.as_bytes());
    body.push_str(&format!("digest={digest}\n"));

    write_atomic_locked(path, body.as_bytes())?;
    Ok(())
}

pub fn load_session_snapshot(
    path: impl AsRef<Path>,
) -> Result<SessionStateSnapshot, ResilienceError> {
    let content = fs::read_to_string(path).map_err(|_| ResilienceError::Io)?;
    if content.len() > 128 * 1024 {
        return Err(ResilienceError::InvalidFormat);
    }
    let mut timestamp: Option<u64> = None;
    let mut peer_ids: Option<Vec<String>> = None;
    let mut selected_exit_node: Option<Option<String>> = None;
    let mut lan_access_enabled: Option<bool> = None;
    let mut digest: Option<String> = None;
    let mut body_without_digest = String::new();

    for line in content.lines() {
        if let Some(value) = line.strip_prefix("timestamp_unix=") {
            timestamp = value.parse::<u64>().ok();
            body_without_digest.push_str(line);
            body_without_digest.push('\n');
            continue;
        }
        if let Some(value) = line.strip_prefix("peer_ids=") {
            let peers = if value.is_empty() {
                Vec::new()
            } else {
                value
                    .split(',')
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            };
            peer_ids = Some(peers);
            body_without_digest.push_str(line);
            body_without_digest.push('\n');
            continue;
        }
        if let Some(value) = line.strip_prefix("selected_exit_node=") {
            selected_exit_node = Some(if value == "none" {
                None
            } else {
                Some(value.to_string())
            });
            body_without_digest.push_str(line);
            body_without_digest.push('\n');
            continue;
        }
        if let Some(value) = line.strip_prefix("lan_access_enabled=") {
            lan_access_enabled = Some(match value {
                "true" => true,
                "false" => false,
                _ => return Err(ResilienceError::InvalidFormat),
            });
            body_without_digest.push_str(line);
            body_without_digest.push('\n');
            continue;
        }
        if let Some(value) = line.strip_prefix("digest=") {
            digest = Some(value.to_string());
            continue;
        }
        return Err(ResilienceError::InvalidFormat);
    }

    let expected = digest.ok_or(ResilienceError::InvalidFormat)?;
    let actual = sha256_hex(body_without_digest.as_bytes());
    if expected != actual {
        return Err(ResilienceError::IntegrityMismatch);
    }

    Ok(SessionStateSnapshot {
        timestamp_unix: timestamp.ok_or(ResilienceError::InvalidFormat)?,
        peer_ids: peer_ids.ok_or(ResilienceError::InvalidFormat)?,
        selected_exit_node: selected_exit_node.ok_or(ResilienceError::InvalidFormat)?,
        lan_access_enabled: lan_access_enabled.ok_or(ResilienceError::InvalidFormat)?,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn write_atomic_locked(path: &Path, bytes: &[u8]) -> Result<(), ResilienceError> {
    let lock_path = lock_path_for(path);
    let _lock_guard = acquire_lock(&lock_path)?;
    write_atomic(path, bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ResilienceError> {
    let parent = path.parent().ok_or(ResilienceError::Io)?;
    fs::create_dir_all(parent).map_err(|_| ResilienceError::Io)?;

    let temp_path = temp_path_for(path);
    let mut temp_file = create_restricted_file(&temp_path)?;
    temp_file
        .write_all(bytes)
        .map_err(|_| ResilienceError::Io)?;
    temp_file.sync_all().map_err(|_| ResilienceError::Io)?;
    fs::rename(&temp_path, path).map_err(|_| ResilienceError::Io)?;

    let parent_dir = File::open(parent).map_err(|_| ResilienceError::Io)?;
    parent_dir.sync_all().map_err(|_| ResilienceError::Io)?;
    Ok(())
}

fn create_restricted_file(path: &Path) -> Result<File, ResilienceError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options.open(path).map_err(|_| ResilienceError::Io)
}

fn acquire_lock(path: &Path) -> Result<StateLockGuard, ResilienceError> {
    const MAX_ATTEMPTS: usize = 50;
    const WAIT_MS: u64 = 10;

    for _ in 0..MAX_ATTEMPTS {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(mut handle) => {
                let stamp = format!("pid={} ts={}\n", std::process::id(), unix_now());
                let _ = handle.write_all(stamp.as_bytes());
                let _ = handle.sync_all();
                return Ok(StateLockGuard {
                    path: path.to_path_buf(),
                    _handle: handle,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                sleep(Duration::from_millis(WAIT_MS));
            }
            Err(_) => return Err(ResilienceError::Io),
        }
    }
    Err(ResilienceError::Io)
}

fn lock_path_for(path: &Path) -> PathBuf {
    let mut out = path.as_os_str().to_os_string();
    out.push(".lock");
    PathBuf::from(out)
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut out = path.as_os_str().to_os_string();
    out.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    PathBuf::from(out)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

struct StateLockGuard {
    path: PathBuf,
    _handle: File,
}

impl Drop for StateLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        ReconnectPolicy, ResilienceError, SessionStateSnapshot, load_session_snapshot,
        next_reconnect_delay_ms, persist_session_snapshot,
    };

    #[test]
    fn reconnect_policy_exponential_backoff_is_capped() {
        let policy = ReconnectPolicy {
            initial_backoff_ms: 200,
            multiplier: 2,
            max_backoff_ms: 1_000,
        };
        assert_eq!(next_reconnect_delay_ms(policy, 0), 200);
        assert_eq!(next_reconnect_delay_ms(policy, 1), 400);
        assert_eq!(next_reconnect_delay_ms(policy, 2), 800);
        assert_eq!(next_reconnect_delay_ms(policy, 3), 1_000);
    }

    #[test]
    fn session_snapshot_persist_restore_detects_tampering() {
        let snapshot = SessionStateSnapshot {
            timestamp_unix: 200,
            peer_ids: vec!["node-a".to_string(), "node-b".to_string()],
            selected_exit_node: Some("node-exit".to_string()),
            lan_access_enabled: true,
        };
        let unique = format!(
            "rustynet-session-snapshot-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);

        persist_session_snapshot(&snapshot, &path).expect("snapshot write should succeed");
        let restored = load_session_snapshot(&path).expect("snapshot read should succeed");
        assert_eq!(restored, snapshot);

        let mut tampered = std::fs::read_to_string(&path).expect("file should be readable");
        tampered = tampered.replace("lan_access_enabled=true", "lan_access_enabled=false");
        std::fs::write(&path, tampered).expect("tampered write should succeed");
        let err = load_session_snapshot(&path);
        assert_eq!(err.err(), Some(ResilienceError::IntegrityMismatch));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn concurrent_persist_keeps_snapshot_integrity() {
        let unique = format!(
            "rustynet-session-concurrency-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = Arc::new(std::env::temp_dir().join(unique));
        let mut joins = Vec::new();

        for index in 0..8 {
            let path = path.clone();
            joins.push(std::thread::spawn(move || {
                let snapshot = SessionStateSnapshot {
                    timestamp_unix: 1_000 + index,
                    peer_ids: vec![format!("node-{index}")],
                    selected_exit_node: Some(format!("exit-{index}")),
                    lan_access_enabled: index % 2 == 0,
                };
                persist_session_snapshot(&snapshot, &*path)
            }));
        }

        for join in joins {
            join.join()
                .expect("thread should not panic")
                .expect("write should succeed");
        }

        let restored = load_session_snapshot(&*path).expect("snapshot must remain readable");
        assert!(restored.timestamp_unix >= 1_000);
        assert!(!restored.peer_ids.is_empty());

        let _ = std::fs::remove_file(&*path);
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let _ = std::fs::remove_file(lock_path);
    }
}
