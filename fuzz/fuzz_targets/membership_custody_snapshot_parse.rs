#![no_main]

use libfuzzer_sys::fuzz_target;
use rustynet_control::membership::{
    load_membership_log, load_membership_snapshot, replay_membership_snapshot_and_log,
};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

// AQ-29: rustynet-control's public membership custody envelope — snapshot
// file, append-only log file, and snapshot+log replay — via the real
// `load_membership_snapshot`, `load_membership_log` and
// `replay_membership_snapshot_and_log` (crates/rustynet-control/src/
// membership.rs:1498/:2095/:2163).
//
// ATTACKER: anyone who can write or tamper with a node's membership snapshot
// or log on disk. The leading selector byte picks the path (0 = snapshot,
// 1 = log, 2 = snapshot+log replay split on a "\n\n---\n\n" separator).
// Staging uses 0600 because the real `validate_membership_file_security`
// gate rejects files with group/other permission bits; the loaders are
// called unchanged and their results ignored.
const REPLAY_NOW_UNIX: u64 = 1_700_000_000;
const SNAPSHOT_LOG_SEPARATOR: &[u8] = b"\n\n---\n\n";

static STAGE_SEQ: AtomicUsize = AtomicUsize::new(0);

struct Staged(PathBuf);

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn stage(bytes: &[u8]) -> Option<Staged> {
    let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "rustynet-fuzz-membership-custody-{}-{}",
        std::process::id(),
        seq
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&path).ok()?;
    file.write_all(bytes).ok()?;
    Some(Staged(path))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else {
        return;
    };
    match selector % 3 {
        0 => {
            if let Some(staged) = stage(body) {
                let _ = load_membership_snapshot(&staged.0);
            }
        }
        1 => {
            if let Some(staged) = stage(body) {
                let _ = load_membership_log(&staged.0);
            }
        }
        _ => {
            let Some(split_at) = find_subslice(body, SNAPSHOT_LOG_SEPARATOR) else {
                return;
            };
            let Some(snapshot) = stage(&body[..split_at]) else {
                return;
            };
            let Some(log) = stage(&body[split_at + SNAPSHOT_LOG_SEPARATOR.len()..]) else {
                return;
            };
            if let Ok(state) = load_membership_snapshot(&snapshot.0) {
                if let Ok(entries) = load_membership_log(&log.0) {
                    let _ = replay_membership_snapshot_and_log(&state, &entries, REPLAY_NOW_UNIX);
                }
            }
        }
    }
});
