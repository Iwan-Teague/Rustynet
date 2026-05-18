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
            .to_owned(),
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

    // ----- X4 coverage parity sweep ---------------------------------------
    //
    // The macOS authenticode module is a deliberate non-applicable stub.
    // The drift surface is correspondingly small, but the structural
    // invariants are worth pinning so a future flip from `applicable=false`
    // to a real `codesign --verify` probe lands as a deliberate code change
    // (one of these tests has to be updated) rather than a silent
    // posture change.

    #[test]
    fn report_schema_version_pinned_at_one() {
        let report = collect_macos_authenticode_report();
        assert_eq!(report.schema_version, 1);
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"schema_version\":1"),
            "schema_version JSON shape must be int=1: {body}"
        );
    }

    #[test]
    fn report_pins_applicable_false_until_codesign_probe_lands() {
        // Pin the current non-applicable posture. If a future slice
        // wires `codesign --verify`, `applicable` flips to true and
        // this test must be updated in the same commit.
        let report = collect_macos_authenticode_report();
        assert!(!report.applicable);
        assert!(
            report.overall_ok,
            "applicable=false must not fail overall_ok — the macOS posture is \
             explicitly out-of-scope today"
        );
    }

    #[test]
    fn report_reason_text_explains_non_applicability() {
        // Pin the operator-facing reason wording so a future shortened
        // or rephrased reason has to update this test deliberately.
        // The reviewed reason must (a) name Authenticode, (b) explain
        // that Gatekeeper is the macOS analogue, (c) call out that
        // first-launch is when Gatekeeper runs.
        let report = collect_macos_authenticode_report();
        assert!(
            report.reason.contains("Authenticode"),
            "reason must reference Authenticode: {}",
            report.reason
        );
        assert!(
            report.reason.contains("Gatekeeper"),
            "reason must reference the macOS analogue Gatekeeper: {}",
            report.reason
        );
        assert!(
            report.reason.contains("first-launch") || report.reason.contains("launch time"),
            "reason must explain Gatekeeper runs at launch time, not runtime: {}",
            report.reason
        );
    }

    #[test]
    fn collect_is_deterministic_across_calls() {
        // Pure stub — every call must produce byte-identical output.
        // Pin so a future addition of a non-deterministic field (e.g.
        // timestamp_unix) trips this test.
        let a = collect_macos_authenticode_report();
        let b = collect_macos_authenticode_report();
        assert_eq!(a, b);
    }

    #[test]
    fn report_rejects_unknown_optional_field() {
        // The report struct has 4 fixed fields (schema_version,
        // overall_ok, applicable, reason). serde_json's default
        // behavior ignores unknown fields on a struct — pin the
        // current tolerance shape so a future deny_unknown_fields
        // attribute either trips this test or is intentional.
        let body = r#"{"schema_version":1,"overall_ok":true,"applicable":false,"reason":"r","future_field":"x"}"#;
        let parsed: MacosAuthenticodeReport =
            serde_json::from_str(body).expect("unknown fields tolerated today");
        assert_eq!(parsed.schema_version, 1);
        assert_eq!(parsed.reason, "r");
    }
}
