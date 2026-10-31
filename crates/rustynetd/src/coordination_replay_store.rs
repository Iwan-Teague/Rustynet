//! RSA-0029 — durable store for the traversal coordination replay window.
//!
//! [`crate::traversal::CoordinationReplayWindow`] is in-memory only: every
//! daemon restart starts with an empty window, so a signed coordination
//! record captured before the restart can be replayed within its (up to
//! `MAX_COORDINATION_TTL_SECS` = 24 h) TTL. This module persists the
//! seen-nonce set beside the other trust-state artifacts, using the same
//! mechanics as the traversal watermark in `daemon.rs`: a strict `key=value`
//! text format, bounded read, unique temp file + fsync + atomic rename, and
//! 0600/0700 unix modes.
//!
//! Failure posture is FAIL CLOSED on the validation path: a corrupt or
//! unreadable store makes `validated_traversal_coordination_schedule` refuse
//! every coordination record until an operator repairs or removes the file.
//! Starting from an empty window instead would silently re-open exactly the
//! post-restart replay hole RSA-0029 describes.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of replay entries persisted. 256 lines × ~46 bytes ≈ 12 KiB,
/// comfortably below `MAX_BOOTSTRAP_ARTIFACT_BYTES` (16 KiB). 256 distinct
/// live coordination records inside one 24 h TTL is far above this mesh's
/// per-peer coordination volume (records are per peer-pair and delivered in
/// signed bundles).
pub const MAX_COORDINATION_REPLAY_STORE_ENTRIES: usize = 256;

/// Hex-encode a 16-byte coordination nonce (32 lowercase hex chars).
fn encode_nonce_hex(nonce: &[u8; 16]) -> String {
    let mut out = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        out.push(nibble_hex_char(byte >> 4));
        out.push(nibble_hex_char(byte & 0x0f));
    }
    out
}

/// Review rebase (rustynet-a115-r-b87): panic-family lints are crate-wide
/// `deny` in rustynetd since AQ-08 step 3 (Cargo.toml [lints.clippy]), so the
/// nibble conversion must be total instead of `expect`.
fn nibble_hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        _ => char::from(b'a' + (nibble - 10)),
    }
}

/// Decode a 32-lowercase-hex coordination nonce. Uppercase is rejected: the
/// store is written by this module only, so any other shape is tampering.
fn decode_nonce_hex(raw: &str) -> Result<[u8; 16], ()> {
    let bytes = raw.as_bytes();
    if bytes.len() != 32 {
        return Err(());
    }
    let mut nonce = [0u8; 16];
    for (slot, pair) in nonce.iter_mut().zip(bytes.chunks_exact(2)) {
        let &[hi, lo] = pair else { return Err(()) };
        let hi = decode_nonce_hex_nibble(hi)?;
        let lo = decode_nonce_hex_nibble(lo)?;
        *slot = (hi << 4) | lo;
    }
    Ok(nonce)
}

fn decode_nonce_hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

/// Load the persisted replay window. `Ok(None)` means the store does not exist
/// yet (fresh install / upgrade — identical to today's empty in-memory
/// window). Entries whose expiry has passed are pruned, mirroring the
/// in-memory `retain` in `CoordinationReplayWindow::verify_and_record`.
///
/// Errors (never silently ignored by callers): missing/corrupt header, any
/// line that is not `<32-lowercase-hex>=<unix-seconds>`, duplicate nonces,
/// more than [`MAX_COORDINATION_REPLAY_STORE_ENTRIES`] entries, or the read
/// exceeding the bootstrap-artifact byte bound.
pub fn load_coordination_replay_store(
    path: &Path,
    now_unix: u64,
) -> Result<Option<BTreeMap<[u8; 16], u64>>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let content = crate::daemon::read_text_artifact_bounded(
        path,
        "coordination replay store",
        crate::daemon::MAX_BOOTSTRAP_ARTIFACT_BYTES,
    )?;
    let mut lines = content.lines();
    match lines.next() {
        Some("version=1") => {}
        Some(other) => {
            return Err(format!(
                "unsupported coordination replay store header {other:?}; expected version=1"
            ));
        }
        None => {
            return Err("coordination replay store is empty; expected version=1 header".to_owned());
        }
    }
    let mut entries = BTreeMap::new();
    for (offset, line) in lines.enumerate() {
        let line_number = offset + 2;
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "coordination replay store line {line_number} missing key/value separator"
            ));
        };
        let nonce = decode_nonce_hex(key).map_err(|_| {
            format!(
                "coordination replay store line {line_number} nonce is not 32 lowercase hex characters"
            )
        })?;
        let expires_at_unix = value.parse::<u64>().map_err(|_| {
            format!("coordination replay store line {line_number} expiry is not a unix timestamp")
        })?;
        if entries.insert(nonce, expires_at_unix).is_some() {
            return Err(format!(
                "coordination replay store line {line_number} repeats nonce {key}"
            ));
        }
    }
    if entries.len() > MAX_COORDINATION_REPLAY_STORE_ENTRIES {
        return Err(format!(
            "coordination replay store holds {} entries; maximum is {}",
            entries.len(),
            MAX_COORDINATION_REPLAY_STORE_ENTRIES
        ));
    }
    entries.retain(|_, expires_at_unix| *expires_at_unix >= now_unix);
    Ok(Some(entries))
}

/// Persist the replay window atomically. Expired entries are dropped; if more
/// than [`MAX_COORDINATION_REPLAY_STORE_ENTRIES`] live entries remain, the
/// soonest-expiring are dropped first (they would age out of the window
/// soonest anyway). Writes through a unique temp file (0600) + `write_all` +
/// `sync_all` + `rename`, with the parent directory created 0700 — the exact
/// `persist_traversal_watermark` mechanics.
pub fn persist_coordination_replay_store(
    path: &Path,
    entries: &BTreeMap<[u8; 16], u64>,
    now_unix: u64,
) -> Result<(), String> {
    let live: BTreeMap<[u8; 16], u64> = entries
        .iter()
        .filter(|(_, expires_at_unix)| **expires_at_unix >= now_unix)
        .map(|(nonce, expires_at_unix)| (*nonce, *expires_at_unix))
        .collect();
    if live.len() <= MAX_COORDINATION_REPLAY_STORE_ENTRIES {
        return write_coordination_replay_payload(path, &live);
    }
    // Ascending (expiry, nonce): everything before the truncation point is the
    // soonest-expiring tail that gets dropped, deterministically.
    let mut by_expiry: Vec<(u64, [u8; 16])> = live
        .iter()
        .map(|(nonce, expires)| (*expires, *nonce))
        .collect();
    by_expiry.sort_unstable();
    let keep_start = live.len() - MAX_COORDINATION_REPLAY_STORE_ENTRIES;
    // Review rebase (rustynet-a115-r-b87): `by_expiry[keep_start..]` would
    // trip the crate-wide `clippy::indexing_slicing = deny`; iterator skip is
    // the same elements.
    let kept: BTreeMap<[u8; 16], u64> = by_expiry
        .iter()
        .skip(keep_start)
        .map(|(expires, nonce)| (*nonce, *expires))
        .collect();
    write_coordination_replay_payload(path, &kept)
}

fn write_coordination_replay_payload(
    path: &Path,
    entries: &BTreeMap<[u8; 16], u64>,
) -> Result<(), String> {
    use std::io::Write;
    let mut payload = String::from("version=1\n");
    for (nonce, expires_at_unix) in entries {
        payload.push_str(&encode_nonce_hex(nonce));
        payload.push('=');
        payload.push_str(&expires_at_unix.to_string());
        payload.push('\n');
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("coordination replay store parent create failed: {err}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(|err| format!("coordination replay store parent chmod failed: {err}"))?;
        }
    }
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| format!("coordination replay store temp create failed: {err}"))?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("coordination replay store write failed: {err}"));
    }
    if let Err(err) = temp.sync_all() {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("coordination replay store sync failed: {err}"));
    }
    if let Err(err) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("coordination replay store rename failed: {err}"));
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent_dir = std::fs::File::open(parent)
            .map_err(|err| format!("coordination replay store parent open failed: {err}"))?;
        parent_dir
            .sync_all()
            .map_err(|err| format!("coordination replay store parent sync failed: {err}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traversal::CoordinationReplayWindow;

    fn nonce(seed: u32) -> [u8; 16] {
        let mut nonce = [0u8; 16];
        nonce[0] = seed as u8;
        nonce[1] = (seed >> 8) as u8;
        nonce
    }

    fn store_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rsa0029-{}-{}-{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should create");
        dir.join("rustynetd.coordination-replay")
    }

    #[test]
    fn missing_store_loads_as_none_and_window_stays_empty() {
        let path = store_path("missing");
        let loaded =
            load_coordination_replay_store(&path, 1_000).expect("missing store must load as None");
        assert!(loaded.is_none());
        let mut window = CoordinationReplayWindow::default();
        window.restore_entries(loaded.unwrap_or_default(), 1_000);
        window
            .verify_and_record(nonce(1), 2_000, 1_000)
            .expect("fresh nonce must record");
    }

    #[test]
    fn recorded_nonce_survives_simulated_restart_and_replays_rejected() {
        let path = store_path("restart");
        let mut window = CoordinationReplayWindow::default();
        window
            .verify_and_record(nonce(7), 2_000, 1_000)
            .expect("fresh nonce must record");
        let entries: BTreeMap<[u8; 16], u64> = window.seen_entries().collect();
        persist_coordination_replay_store(&path, &entries, 1_000).expect("persist must succeed");

        // Post-restart: a fresh window restored from disk must reject the
        // replay of the same still-valid coordination record (RSA-0029).
        let loaded = load_coordination_replay_store(&path, 1_500)
            .expect("store must load")
            .expect("existing store must load as Some");
        let mut restarted = CoordinationReplayWindow::default();
        restarted.restore_entries(loaded, 1_500);
        let err = restarted
            .verify_and_record(nonce(7), 2_000, 1_500)
            .expect_err("replayed coordination nonce must be rejected after restart");
        assert!(matches!(
            err,
            crate::traversal::TraversalError::CoordinationReplayDetected
        ));
        restarted
            .verify_and_record(nonce(8), 2_000, 1_500)
            .expect("unrelated nonce must still record");
    }

    #[test]
    fn expired_entries_are_pruned_across_restart() {
        let path = store_path("prune");
        let mut entries = BTreeMap::new();
        entries.insert(nonce(1), 900u64);
        entries.insert(nonce(2), 1_100u64);
        persist_coordination_replay_store(&path, &entries, 900).expect("persist must succeed");
        let loaded = load_coordination_replay_store(&path, 900)
            .expect("store must load")
            .expect("existing store must load as Some");
        assert_eq!(loaded.len(), 2, "nothing expired yet at now=900");
        let loaded_later = load_coordination_replay_store(&path, 1_050)
            .expect("store must load")
            .expect("existing store must load as Some");
        assert_eq!(loaded_later.len(), 1, "expired entry must be pruned");
        assert_eq!(loaded_later.get(&nonce(2)), Some(&1_100));
    }

    #[test]
    fn corrupt_store_shapes_fail_closed() {
        let now = 1_000u64;
        let cases: [(&str, &str); 6] = [
            ("empty", ""),
            ("bad-header", "version=2\n"),
            ("no-header", "00000000000000000000000000000001=2000\n"),
            ("bad-nonce", "version=1\nZZZZ=2000\n"),
            (
                "uppercase-nonce",
                "version=1\n000000000000000000000000000000AB=2000\n",
            ),
            (
                "bad-expiry",
                "version=1\n00000000000000000000000000000001=soon\n",
            ),
        ];
        for (tag, payload) in cases {
            let path = store_path(tag);
            std::fs::write(&path, payload).expect("corrupt fixture should write");
            assert!(
                load_coordination_replay_store(&path, now).is_err(),
                "corrupt store shape {tag} must fail closed"
            );
        }
    }

    #[test]
    fn duplicate_nonce_in_store_fails_closed() {
        let path = store_path("dup");
        let line = "00000000000000000000000000000001=2000\n";
        std::fs::write(&path, format!("version=1\n{line}{line}")).expect("fixture should write");
        assert!(load_coordination_replay_store(&path, 1_000).is_err());
    }

    #[test]
    fn over_cap_store_fails_closed_on_load() {
        let path = store_path("overcap-load");
        let mut payload = String::from("version=1\n");
        for seed in 0..=MAX_COORDINATION_REPLAY_STORE_ENTRIES {
            payload.push_str(&format!(
                "{}={}\n",
                encode_nonce_hex(&nonce(seed as u32)),
                2_000u64 + seed as u64
            ));
        }
        std::fs::write(&path, payload).expect("over-cap fixture should write");
        assert!(load_coordination_replay_store(&path, 1_000).is_err());
    }

    #[test]
    fn persist_caps_at_max_entries_keeping_latest_expiring() {
        let path = store_path("cap");
        let mut entries = BTreeMap::new();
        for seed in 0..(MAX_COORDINATION_REPLAY_STORE_ENTRIES as u32 + 64) {
            entries.insert(nonce(seed), 2_000u64 + u64::from(seed));
        }
        persist_coordination_replay_store(&path, &entries, 1_000).expect("persist must succeed");
        let loaded = load_coordination_replay_store(&path, 1_000)
            .expect("capped store must still load")
            .expect("existing store must load as Some");
        assert_eq!(loaded.len(), MAX_COORDINATION_REPLAY_STORE_ENTRIES);
        // The dropped entries are the soonest-expiring ones.
        assert!(!loaded.contains_key(&nonce(0)));
        assert!(loaded.contains_key(&nonce(255)));
        assert!(loaded.contains_key(&nonce(MAX_COORDINATION_REPLAY_STORE_ENTRIES as u32 + 63)));
    }

    #[cfg(unix)]
    #[test]
    fn persisted_store_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = store_path("mode");
        let entries = BTreeMap::from([(nonce(3), 2_000u64)]);
        persist_coordination_replay_store(&path, &entries, 1_000).expect("persist must succeed");
        let mode = std::fs::metadata(&path)
            .expect("store file should exist")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "store file must be 0600");
        let parent_mode = std::fs::metadata(path.parent().expect("has parent"))
            .expect("parent should exist")
            .permissions()
            .mode();
        assert_eq!(parent_mode & 0o777, 0o700, "store parent must be 0700");
    }

    #[test]
    fn nonce_hex_round_trip() {
        let raw = nonce(0xab);
        let encoded = encode_nonce_hex(&raw);
        assert_eq!(encoded.len(), 32);
        assert_eq!(decode_nonce_hex(&encoded), Ok(raw));
        assert!(decode_nonce_hex(&encoded.to_uppercase()).is_err());
        assert!(decode_nonce_hex(&encoded[..30]).is_err());
    }
}
