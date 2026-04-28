#![allow(clippy::result_large_err)]

//! Linux authenticode-equivalent stub.
//!
//! Authenticode is a Windows-specific binary signature mechanism
//! (`WinVerifyTrust` + the WINTRUST_ACTION_GENERIC_VERIFY_V2 chain).
//! Linux does not enforce binary signatures at runtime — package
//! signature verification happens at install time via dpkg / rpm /
//! apt-secure / dnf-gpgcheck, not as a runtime binary attestation.
//!
//! Rather than reject the `Authenticode` op on Linux, the daemon
//! exposes a `linux-authenticode-check` subcommand that always emits
//! a typed `applicable: false` report. This keeps the
//! `LinuxDaemonProbe::build_argv` shape uniform — every op resolves
//! to argv — and gives the orchestrator a consistent JSON structure
//! to consume regardless of platform. The `applicable` field signals
//! the orchestrator that the runtime did not enforce a binary
//! signature on this host; a future Linux slice could swap this stub
//! for an actual dpkg/rpm signature lookup, at which point the
//! report's `applicable` would flip to `true` and the existing
//! Windows-style `valid` field would carry the verdict.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxAuthenticodeReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    /// Always `false` on Linux today: there is no runtime binary
    /// signature attestation equivalent to Windows `WinVerifyTrust`.
    /// Reserved for a future slice that wires dpkg/rpm signature
    /// verification.
    pub applicable: bool,
    pub reason: String,
}

pub fn collect_linux_authenticode_report() -> LinuxAuthenticodeReport {
    LinuxAuthenticodeReport {
        schema_version: 1,
        // overall_ok=true because the verifier did not find drift;
        // it found the op is not applicable on this platform. The
        // orchestrator threads this differently from Windows where
        // `valid: false` is a hard fail.
        overall_ok: true,
        applicable: false,
        reason: "Linux does not enforce binary signatures at runtime; package \
             signature verification happens at install time via dpkg/rpm. \
             A runtime authenticode-equivalent is not part of the reviewed \
             Linux posture today."
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_marks_overall_ok_with_applicable_false() {
        let report = collect_linux_authenticode_report();
        assert!(report.overall_ok);
        assert!(!report.applicable);
        assert!(
            report.reason.contains("dpkg/rpm"),
            "reason must cite the install-time mechanism: {}",
            report.reason
        );
    }

    #[test]
    fn report_serde_round_trips() {
        let report = collect_linux_authenticode_report();
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: LinuxAuthenticodeReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn report_schema_pins_version_one() {
        let report = collect_linux_authenticode_report();
        assert_eq!(report.schema_version, 1);
    }
}
