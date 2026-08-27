#![forbid(unsafe_code)]

//! QH-40 — durable "the last shutdown left dataplane residue" marker.
//!
//! ## Why this module exists
//!
//! `Phase10Controller::shutdown` (`phase10.rs:6553`) accumulates every
//! teardown failure and returns `SystemError::RollbackFailed`. Until this
//! module landed, both shutdown call sites — the Unix SIGTERM/SIGINT gate
//! and the Windows SCM stop gate — logged that error as "best-effort" and
//! then fell through to a clean `Ok(())`, so the process exited **0**.
//!
//! On macOS that reporting hole is total: `KeepAlive` is unconditionally
//! `true` in both the reference plist (`scripts/launchd/com.rustynet.daemon.plist`)
//! and the rendered one (`scripts/bootstrap/macos/Install-RustyNetMacosService.sh`),
//! so launchd restarts the job on *any* exit and never inspects the code.
//! A failed rollback therefore leaves firewall/DNS/exit-NAT state installed
//! and `net.inet.ip.forwarding` enabled (`phase10.rs:3601` is what restores
//! it) with **no signal anywhere** — the daemon said it stopped cleanly, no
//! orchestrator stage observed it, and the run matrix stayed green.
//!
//! ## The channel this module provides
//!
//! A process exit code is a channel only something has to read. Under
//! `KeepAlive = true` nothing does. So the loud channel is a **durable file**
//! written next to the daemon state file at the instant the rollback failure
//! is known:
//!
//! * it survives the process, the restart, and the reboot;
//! * it is machine-readable with its own `schema_version`, so it costs no
//!   change to the daemon's persisted-state schema (`persist_state` writes
//!   only `{timestamp_unix, peer_ids, selected_exit_node, lan_access_enabled}`);
//! * it is never cleared automatically — only an explicit operator
//!   acknowledgement (`rustynetd shutdown-residue-check --acknowledge`)
//!   removes it, so the evidence pipeline cannot race past it;
//! * a marker that exists but cannot be read or parsed counts as residue
//!   **present** ([`ResidueScan::is_residue`]), never as clean. Fail closed
//!   (AGENTS.md §3) means an unreadable marker is not an absent marker.
//!
//! The nonzero exit is retained on the Unix path as a second, independent
//! signal for wrappers and shells that *do* read exit codes; see the design
//! doc for why it cannot create a restart loop launchd was not already going
//! to run.
//!
//! Wired through the CLI as `rustynetd shutdown-residue-check`.
//!
//! See `documents/operations/active/MacOsHelperShutdownOrderingDesign_2026-08-27.md`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Reviewed schema version for the on-disk marker. Bump only with a paired
/// update to the reader below and to the operator runbook.
pub const SHUTDOWN_RESIDUE_MARKER_SCHEMA_VERSION: u32 = 1;

/// Suffix appended to the daemon state file name to derive the marker path.
/// Deliberately a sibling of the state file rather than a new directory: the
/// state file's parent is already created and permission-checked at startup.
pub const SHUTDOWN_RESIDUE_MARKER_SUFFIX: &str = ".shutdown-residue.json";

/// Stable substring embedded in every operator-facing residue message.
///
/// Two consumers depend on it, and both are pinned by tests:
/// * `main.rs` selects the "shutdown" banner instead of the "startup" banner;
/// * `classify_top_level_error` maps it to [`crate::exit_codes::ExitCode::PolicyReject`]
///   (78) because it contains `fail-closed`.
pub const SHUTDOWN_RESIDUE_FAIL_CLOSED_TOKEN: &str = "shutdown rollback failed (fail-closed)";

/// Stable grep token for the startup-side detection log line. Live-lab log
/// scrapes key off this exact string; do not reword it without updating the
/// evidence pipeline.
pub const SHUTDOWN_RESIDUE_DETECTED_LOG_TOKEN: &str = "shutdown_rollback_residue_detected";

/// Trigger label recorded when the Unix SIGTERM/SIGINT gate observed the
/// failed rollback.
pub const TRIGGER_UNIX_SHUTDOWN_SIGNAL: &str = "unix_shutdown_signal";

/// Trigger label recorded when the Windows SCM stop gate observed the
/// failed rollback.
pub const TRIGGER_WINDOWS_SERVICE_STOP: &str = "windows_service_stop";

/// Durable record of a shutdown whose dataplane rollback did not complete.
///
/// Presence of this file means: firewall / DNS / exit-NAT / interface state
/// from the previous run may still be installed on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownResidueMarker {
    /// Schema version of this record.
    pub schema_version: u32,
    /// Unix timestamp at which the failed rollback was observed.
    pub recorded_unix: u64,
    /// `std::env::consts::OS` of the host that recorded the marker.
    pub platform: String,
    /// Node id of the daemon that failed to roll back.
    pub node_id: String,
    /// Which shutdown gate observed the failure. One of
    /// [`TRIGGER_UNIX_SHUTDOWN_SIGNAL`] / [`TRIGGER_WINDOWS_SERVICE_STOP`].
    pub trigger: String,
    /// The accumulated rollback error, verbatim.
    pub rollback_error: String,
}

impl ShutdownResidueMarker {
    /// Build a marker at the current schema version.
    pub fn new(
        recorded_unix: u64,
        node_id: impl Into<String>,
        trigger: impl Into<String>,
        rollback_error: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SHUTDOWN_RESIDUE_MARKER_SCHEMA_VERSION,
            recorded_unix,
            platform: std::env::consts::OS.to_owned(),
            node_id: node_id.into(),
            trigger: trigger.into(),
            rollback_error: rollback_error.into(),
        }
    }

    /// Single-line operator-facing summary. Always contains
    /// [`SHUTDOWN_RESIDUE_FAIL_CLOSED_TOKEN`].
    pub fn fail_closed_message(&self) -> String {
        format!(
            "{SHUTDOWN_RESIDUE_FAIL_CLOSED_TOKEN}: node_id={} trigger={} platform={} recorded_unix={} error={}",
            self.node_id, self.trigger, self.platform, self.recorded_unix, self.rollback_error
        )
    }
}

/// Outcome of scanning for a residue marker.
///
/// `Unreadable` is deliberately a distinct variant rather than an error the
/// caller may discard: a marker that exists but cannot be parsed is residue
/// evidence we failed to decode, and treating it as "clean" would reintroduce
/// exactly the silent-success defect this module exists to close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResidueScan {
    /// No marker file present — the previous shutdown rolled back cleanly
    /// (or never ran).
    Clean,
    /// A marker was present and parsed.
    Present(Box<ShutdownResidueMarker>),
    /// A marker path exists but could not be read or parsed. Counts as
    /// residue.
    Unreadable {
        /// Marker path that could not be decoded.
        path: PathBuf,
        /// Why it could not be decoded.
        reason: String,
    },
}

impl ResidueScan {
    /// Does this scan mean the host may be carrying dataplane residue?
    ///
    /// `Unreadable` answers `true` — see the type-level note.
    pub fn is_residue(&self) -> bool {
        !matches!(self, ResidueScan::Clean)
    }

    /// Operator-facing summary, or `None` when clean. Always contains
    /// [`SHUTDOWN_RESIDUE_FAIL_CLOSED_TOKEN`] when residue is present.
    pub fn fail_closed_message(&self) -> Option<String> {
        match self {
            ResidueScan::Clean => None,
            ResidueScan::Present(marker) => Some(marker.fail_closed_message()),
            ResidueScan::Unreadable { path, reason } => Some(format!(
                "{SHUTDOWN_RESIDUE_FAIL_CLOSED_TOKEN}: marker present but undecodable at {} ({reason}); treated as residue",
                path.display()
            )),
        }
    }
}

/// Derive the marker path from the daemon state path.
///
/// The marker is a sibling of the state file so it inherits the state
/// directory's ownership and permissions. A state path with no file name
/// (`/`, `..`) falls back to a fixed name inside that directory rather than
/// silently producing a path that would collide with the directory itself.
pub fn marker_path(state_path: &Path) -> PathBuf {
    match state_path.file_name().and_then(|name| name.to_str()) {
        Some(name) if !name.is_empty() => {
            state_path.with_file_name(format!("{name}{SHUTDOWN_RESIDUE_MARKER_SUFFIX}"))
        }
        _ => state_path.join(format!("rustynetd{SHUTDOWN_RESIDUE_MARKER_SUFFIX}")),
    }
}

/// Write the marker durably next to the state file.
///
/// Written to a temporary sibling and renamed, so a crash mid-write cannot
/// leave a truncated marker that a later scan would report as `Unreadable`
/// for the wrong reason. On Unix the file is chmod 0600 before the rename:
/// the rollback error text can name interfaces and addresses, and the state
/// directory is group-readable by `rustynetd` on macOS.
pub fn record_marker(state_path: &Path, marker: &ShutdownResidueMarker) -> Result<PathBuf, String> {
    let path = marker_path(state_path);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create residue marker parent failed: {err}"))?;
    }
    let body = serde_json::to_string_pretty(marker)
        .map_err(|err| format!("serialize residue marker failed: {err}"))?;
    let temp_path = path.with_extension("json.tmp");
    std::fs::write(&temp_path, body.as_bytes())
        .map_err(|err| format!("write residue marker failed: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("chmod residue marker failed: {err}"))?;
    }
    std::fs::rename(&temp_path, &path)
        .map_err(|err| format!("rename residue marker failed: {err}"))?;
    Ok(path)
}

/// Scan for a residue marker beside the given state path.
///
/// Never returns an error: an unreadable marker is a *finding*, not a
/// caller-discardable failure, so it is reported as
/// [`ResidueScan::Unreadable`].
pub fn scan(state_path: &Path) -> ResidueScan {
    let path = marker_path(state_path);
    let body = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return ResidueScan::Clean,
        Err(err) => {
            return ResidueScan::Unreadable {
                path,
                reason: format!("read failed: {err}"),
            };
        }
    };
    match serde_json::from_str::<ShutdownResidueMarker>(&body) {
        Ok(marker) if marker.schema_version == SHUTDOWN_RESIDUE_MARKER_SCHEMA_VERSION => {
            ResidueScan::Present(Box::new(marker))
        }
        Ok(marker) => ResidueScan::Unreadable {
            path,
            reason: format!(
                "unsupported schema_version {} (expected {SHUTDOWN_RESIDUE_MARKER_SCHEMA_VERSION})",
                marker.schema_version
            ),
        },
        Err(err) => ResidueScan::Unreadable {
            path,
            reason: format!("parse failed: {err}"),
        },
    }
}

/// Remove the marker. Only ever called from the explicit operator
/// acknowledgement path — never automatically on daemon start, because an
/// automatic clear would let a restart erase the only durable evidence that
/// the host is carrying residue.
///
/// Returns `Ok(true)` when a marker was removed, `Ok(false)` when there was
/// none.
pub fn acknowledge_marker(state_path: &Path) -> Result<bool, String> {
    let path = marker_path(state_path);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "remove residue marker {} failed: {err}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker() -> ShutdownResidueMarker {
        ShutdownResidueMarker::new(
            1_756_000_000,
            "node-a",
            TRIGGER_UNIX_SHUTDOWN_SIGNAL,
            "rollback dns protection: rollback failed: privileged helper connect failed",
        )
    }

    #[test]
    fn marker_path_is_a_sibling_of_the_state_file() {
        let derived = marker_path(Path::new("/usr/local/var/rustynet/rustynetd.state"));
        assert_eq!(
            derived,
            PathBuf::from("/usr/local/var/rustynet/rustynetd.state.shutdown-residue.json")
        );
    }

    #[test]
    fn marker_path_falls_back_when_state_path_has_no_file_name() {
        // Mutation guard: a naive `with_file_name` on `/` would produce a
        // path outside the intended directory.
        let derived = marker_path(Path::new("/"));
        assert_eq!(derived, PathBuf::from("/rustynetd.shutdown-residue.json"));
    }

    #[test]
    fn scan_reports_clean_when_no_marker_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("rustynetd.state");
        let scan = scan(&state);
        assert_eq!(scan, ResidueScan::Clean);
        assert!(!scan.is_residue());
        assert_eq!(scan.fail_closed_message(), None);
    }

    #[test]
    fn recorded_marker_round_trips_and_reports_residue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("rustynetd.state");
        let written = record_marker(&state, &marker()).expect("record");
        assert!(written.exists(), "marker file must exist after record");
        match scan(&state) {
            ResidueScan::Present(found) => assert_eq!(*found, marker()),
            other => panic!("expected Present, got {other:?}"),
        }
        assert!(scan(&state).is_residue());
    }

    #[test]
    fn recorded_marker_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("rustynetd.state");
        record_marker(&state, &marker()).expect("record");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn recorded_marker_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("rustynetd.state");
        let written = record_marker(&state, &marker()).expect("record");
        let mode = std::fs::metadata(&written)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "residue marker must not be group/world readable"
        );
    }

    /// NEGATIVE TEST: a marker we cannot decode must count as residue.
    /// Mutation: returning `Clean` on a parse failure makes this fail.
    #[test]
    fn undecodable_marker_counts_as_residue_not_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("rustynetd.state");
        std::fs::write(marker_path(&state), b"{ this is not json").expect("write garbage");
        let scan = scan(&state);
        assert!(
            scan.is_residue(),
            "an undecodable marker must fail closed, got {scan:?}"
        );
        assert!(matches!(scan, ResidueScan::Unreadable { .. }));
        assert!(
            scan.fail_closed_message()
                .expect("message")
                .contains(SHUTDOWN_RESIDUE_FAIL_CLOSED_TOKEN)
        );
    }

    /// NEGATIVE TEST: an unknown future schema version must not be read as
    /// a clean host either.
    #[test]
    fn unsupported_schema_version_counts_as_residue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("rustynetd.state");
        let mut future = marker();
        future.schema_version = SHUTDOWN_RESIDUE_MARKER_SCHEMA_VERSION + 1;
        std::fs::write(
            marker_path(&state),
            serde_json::to_vec(&future).expect("serialize"),
        )
        .expect("write");
        let scan = scan(&state);
        assert!(
            scan.is_residue(),
            "future schema must fail closed: {scan:?}"
        );
        match scan {
            ResidueScan::Unreadable { reason, .. } => {
                assert!(reason.contains("unsupported schema_version"), "{reason}");
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn fail_closed_message_carries_the_pinned_token_and_the_error() {
        let message = marker().fail_closed_message();
        assert!(
            message.contains(SHUTDOWN_RESIDUE_FAIL_CLOSED_TOKEN),
            "{message}"
        );
        assert!(message.contains("node-a"), "{message}");
        assert!(message.contains(TRIGGER_UNIX_SHUTDOWN_SIGNAL), "{message}");
        assert!(
            message.contains("privileged helper connect failed"),
            "the verbatim rollback error must survive into the message: {message}"
        );
    }

    #[test]
    fn fail_closed_token_maps_to_policy_reject_exit_code() {
        // Pin the coupling `main.rs` relies on: the token contains
        // "fail-closed", which `classify_top_level_error` buckets as
        // PolicyReject (78) — "DO NOT retry without operator review".
        assert!(
            SHUTDOWN_RESIDUE_FAIL_CLOSED_TOKEN.contains("fail-closed"),
            "token must keep the substring the exit-code classifier matches on"
        );
        assert_eq!(crate::exit_codes::ExitCode::PolicyReject.as_i32(), 78);
    }

    #[test]
    fn acknowledge_removes_the_marker_and_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("rustynetd.state");
        record_marker(&state, &marker()).expect("record");
        assert!(acknowledge_marker(&state).expect("first acknowledge"));
        assert_eq!(scan(&state), ResidueScan::Clean);
        assert!(
            !acknowledge_marker(&state).expect("second acknowledge"),
            "acknowledging a clean host must report that nothing was cleared"
        );
    }

    /// The marker must survive a restart, i.e. nothing in this module clears
    /// it except the explicit acknowledgement. Mutation: making `scan` remove
    /// the file after reading makes this fail.
    #[test]
    fn scanning_does_not_clear_the_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("rustynetd.state");
        record_marker(&state, &marker()).expect("record");
        for _ in 0..3 {
            assert!(scan(&state).is_residue());
        }
        assert!(marker_path(&state).exists(), "scan must be non-destructive");
    }
}
