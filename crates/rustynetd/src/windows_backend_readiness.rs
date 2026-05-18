#![allow(clippy::result_large_err)]

//! Windows backend readiness verifier.
//!
//! Confirms the prerequisites the `windows-wireguard-nt` data-plane
//! backend depends on are present on the Windows host before the
//! daemon attempts to bring up tunnels:
//!
//! * `wireguard.exe` from the official `WireGuard` for Windows installer
//!   (`https://www.wireguard.com/install/`) at the canonical path
//!   `C:\Program Files\WireGuard\wireguard.exe`. The daemon's
//!   `WindowsWireguardBackend` shells out to this binary for every
//!   `installtunnelservice` / `uninstalltunnelservice` call.
//! * `wg.exe` from the same installer at
//!   `C:\Program Files\WireGuard\wg.exe`. Used for low-level peer
//!   sync + transfer-stat queries.
//! * `netsh.exe` from the OS at `C:\Windows\System32\netsh.exe`.
//!   Used for route / DNS lifecycle. Always present on Windows but
//!   recorded for forensic completeness.
//!
//! When any required binary is missing the report's `overall_ok`
//! is false and the daemon-side install helper / orchestrator can
//! surface a precise blocker reason ("install `WireGuard` for Windows
//! before switching the env file to `--backend windows-wireguard-nt`").
//!
//! The collector is cross-platform: off-Windows hosts get an
//! explicit "not supported on this host" entry rather than a
//! fabricated absent / present answer.

use serde::{Deserialize, Serialize};

pub const REVIEWED_WIREGUARD_EXE_PATH: &str = r"C:\Program Files\WireGuard\wireguard.exe";
pub const REVIEWED_WG_EXE_PATH: &str = r"C:\Program Files\WireGuard\wg.exe";
pub const REVIEWED_NETSH_EXE_PATH: &str = r"C:\Windows\System32\netsh.exe";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsBackendReadinessEntry {
    pub label: String,
    pub path: String,
    pub present: bool,
    /// When false (off-Windows or on a host that cannot probe), the
    /// `present` field is meaningless and the collector publishes a
    /// blocker reason instead.
    pub probed: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsBackendReadinessReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub entries: Vec<WindowsBackendReadinessEntry>,
    pub drift_reasons: Vec<String>,
}

/// Pure evaluator: walk the entries, aggregate every drift reason
/// in one pass, return `Ok(())` when every required binary is
/// present and probed.
pub fn evaluate_windows_backend_readiness(
    entries: &[WindowsBackendReadinessEntry],
) -> Result<(), Vec<String>> {
    let mut reasons = Vec::new();
    if entries.is_empty() {
        reasons.push("backend readiness report contains no entries".to_owned());
        return Err(reasons);
    }
    for entry in entries {
        if !entry.probed {
            reasons.push(format!(
                "{} could not be probed (off-Windows host or runtime probe failed): {}",
                entry.label,
                entry.reason.as_deref().unwrap_or("(no reason recorded)")
            ));
            continue;
        }
        if !entry.present {
            reasons.push(format!(
                "{} not present at reviewed path {}",
                entry.label, entry.path
            ));
        }
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

pub fn build_windows_backend_readiness_report(
    entries: Vec<WindowsBackendReadinessEntry>,
) -> WindowsBackendReadinessReport {
    let drift_reasons = match evaluate_windows_backend_readiness(&entries) {
        Ok(()) => Vec::new(),
        Err(reasons) => reasons,
    };
    let overall_ok = drift_reasons.is_empty();
    WindowsBackendReadinessReport {
        schema_version: 1,
        overall_ok,
        entries,
        drift_reasons,
    }
}

/// Cross-platform collector. On Windows hosts probes the canonical
/// install paths via `std::fs::symlink_metadata`; off-Windows the
/// per-entry `probed=false` so the evaluator surfaces a clear
/// blocker rather than a fabricated answer.
pub fn collect_windows_backend_readiness_report() -> WindowsBackendReadinessReport {
    let entries = vec![
        probe_canonical_binary(
            "wireguard.exe (from WireGuard for Windows)",
            REVIEWED_WIREGUARD_EXE_PATH,
        ),
        probe_canonical_binary("wg.exe (from WireGuard for Windows)", REVIEWED_WG_EXE_PATH),
        probe_canonical_binary("netsh.exe", REVIEWED_NETSH_EXE_PATH),
    ];
    build_windows_backend_readiness_report(entries)
}

#[cfg(windows)]
fn probe_canonical_binary(label: &str, path: &str) -> WindowsBackendReadinessEntry {
    let probe_path = std::path::Path::new(path);
    match std::fs::symlink_metadata(probe_path) {
        Ok(meta) if meta.is_file() => WindowsBackendReadinessEntry {
            label: label.to_string(),
            path: path.to_string(),
            present: true,
            probed: true,
            reason: None,
        },
        Ok(_) => WindowsBackendReadinessEntry {
            label: label.to_string(),
            path: path.to_string(),
            present: false,
            probed: true,
            reason: Some(format!("path exists at {path} but is not a regular file")),
        },
        Err(err) => WindowsBackendReadinessEntry {
            label: label.to_string(),
            path: path.to_string(),
            present: false,
            probed: true,
            reason: Some(format!("path probe failed: {err}")),
        },
    }
}

#[cfg(not(windows))]
fn probe_canonical_binary(label: &str, path: &str) -> WindowsBackendReadinessEntry {
    WindowsBackendReadinessEntry {
        label: label.to_owned(),
        path: path.to_owned(),
        present: false,
        probed: false,
        reason: Some("windows-backend-readiness-check requires a Windows runtime host".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed_present_entries() -> Vec<WindowsBackendReadinessEntry> {
        vec![
            WindowsBackendReadinessEntry {
                label: "wireguard.exe".to_owned(),
                path: REVIEWED_WIREGUARD_EXE_PATH.to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
            WindowsBackendReadinessEntry {
                label: "wg.exe".to_owned(),
                path: REVIEWED_WG_EXE_PATH.to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
            WindowsBackendReadinessEntry {
                label: "netsh.exe".to_owned(),
                path: REVIEWED_NETSH_EXE_PATH.to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
        ]
    }

    #[test]
    fn evaluator_accepts_all_present_entries() {
        evaluate_windows_backend_readiness(&reviewed_present_entries())
            .expect("all-present must validate");
    }

    #[test]
    fn evaluator_rejects_empty_entries() {
        let reasons =
            evaluate_windows_backend_readiness(&[]).expect_err("empty entries must reject");
        assert!(reasons.iter().any(|r| r.contains("no entries")));
    }

    #[test]
    fn evaluator_rejects_missing_binary() {
        let mut entries = reviewed_present_entries();
        entries[0].present = false;
        let reasons =
            evaluate_windows_backend_readiness(&entries).expect_err("missing binary must reject");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("not present at reviewed path")
                    && r.contains(REVIEWED_WIREGUARD_EXE_PATH)),
            "rejection must cite path: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_unprobed_entry() {
        let mut entries = reviewed_present_entries();
        entries[1].probed = false;
        entries[1].reason = Some("off-Windows host".to_owned());
        let reasons =
            evaluate_windows_backend_readiness(&entries).expect_err("unprobed entry must reject");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("could not be probed") && r.contains("off-Windows host")),
            "rejection must surface probe failure: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_aggregates_multiple_drift_reasons() {
        let mut entries = reviewed_present_entries();
        entries[0].present = false;
        entries[1].probed = false;
        entries[1].reason = Some("probe error".to_owned());
        let reasons =
            evaluate_windows_backend_readiness(&entries).expect_err("multi-drift must aggregate");
        assert!(reasons.len() >= 2, "expected multiple reasons: {reasons:?}");
    }

    #[test]
    fn build_report_marks_overall_ok_for_clean_entries() {
        let report = build_windows_backend_readiness_report(reviewed_present_entries());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
        assert_eq!(report.entries.len(), 3);
    }

    #[test]
    fn build_report_surfaces_drift_for_missing_binary() {
        let mut entries = reviewed_present_entries();
        entries[0].present = false;
        let report = build_windows_backend_readiness_report(entries);
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("not present at reviewed path"))
        );
    }

    #[test]
    fn report_serde_round_trips() {
        let report = build_windows_backend_readiness_report(reviewed_present_entries());
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: WindowsBackendReadinessReport =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    #[cfg(not(windows))]
    fn collector_off_windows_marks_every_entry_unprobed() {
        let report = collect_windows_backend_readiness_report();
        assert!(!report.overall_ok);
        // Every entry should be unprobed with a "requires a Windows
        // runtime host" reason.
        for entry in &report.entries {
            assert!(!entry.probed, "off-Windows must mark probed=false");
            assert!(
                entry
                    .reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("requires a Windows runtime host"),
                "expected runtime-host blocker: {:?}",
                entry.reason
            );
        }
        assert_eq!(report.entries.len(), 3);
    }
}
