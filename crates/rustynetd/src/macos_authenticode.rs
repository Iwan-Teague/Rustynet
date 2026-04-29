#![allow(clippy::result_large_err)]

//! macOS authenticode-equivalent stub.
//!
//! Authenticode is a Windows-specific mechanism. macOS uses Gatekeeper
//! (code signing + notarization) as the nearest equivalent, but Gatekeeper
//! verification is performed at first-launch time by the OS, not by the
//! running daemon at runtime. The macOS runtime verifier does not
//! re-evaluate code signatures on already-running binaries.
//!
//! Rather than reject the `Authenticode` op on macOS, the daemon exposes
//! a `macos-authenticode-check` subcommand that always emits a typed
//! `applicable: false` report. This keeps the `MacosDaemonProbe::build_argv`
//! shape uniform with Linux and Windows — every op resolves to argv — and
//! gives the orchestrator a consistent JSON structure to consume.
//!
//! A future slice could wire `codesign --verify` here, at which point
//! `applicable` would flip to `true`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosAuthenticodeReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    /// Always `false` today: macOS Gatekeeper operates at launch time,
    /// not as a runtime binary attestation mechanism.
    pub applicable: bool,
    pub reason: String,
}

pub fn collect_macos_authenticode_report() -> MacosAuthenticodeReport {
    MacosAuthenticodeReport {
        schema_version: 1,
        overall_ok: true,
        applicable: false,
        reason: "macOS does not enforce binary signatures at runtime via a mechanism \
                 analogous to Windows Authenticode. Gatekeeper verification runs at \
                 first-launch time. A runtime codesign --verify probe is not part of \
                 the reviewed macOS posture today."
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_marks_overall_ok_with_applicable_false() {
        let report = collect_macos_authenticode_report();
        assert!(
            report.overall_ok,
            "applicable=false must not fail overall_ok"
        );
        assert!(!report.applicable);
        assert!(!report.reason.is_empty());
    }

    #[test]
    fn report_serde_round_trips() {
        let report = collect_macos_authenticode_report();
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: MacosAuthenticodeReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }
}
