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
            .to_owned(),
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

    // -- X4 parity expansion: drift / shape / forward-compat tests ----------
    //
    // The Linux authenticode collector is a typed-stub today: it always
    // returns `applicable=false, overall_ok=true` because Linux has no
    // runtime equivalent to `WinVerifyTrust`. These tests pin the
    // reviewed-clean shape so that any silent mutation of the report
    // (schema bump, applicable flipped, reason rewritten, overall_ok
    // flipped) trips a named failure rather than slipping through into
    // the orchestrator's downstream contract.
    //
    // Mirrors the test-shape conventions in `windows_authenticode` and
    // `linux_key_custody` (descriptive names, single-invariant tests,
    // negative tests for drift shapes, serde round-trips, snapshot pins).

    /// Canonical reviewed-clean report. Centralized so drift tests
    /// have a single source of truth to mutate.
    fn canonical_reviewed_report() -> LinuxAuthenticodeReport {
        collect_linux_authenticode_report()
    }

    #[test]
    fn evaluator_accepts_reviewed_clean_snapshot_as_overall_ok() {
        let report = canonical_reviewed_report();
        assert!(
            report.overall_ok,
            "reviewed-clean Linux authenticode report must be overall_ok=true; \
             on Linux there is no runtime binary attestation to fail, so the \
             collector reports non-applicability as a non-drift outcome"
        );
    }

    #[test]
    fn evaluator_marks_applicable_false_signaling_no_runtime_binary_attestation() {
        let report = canonical_reviewed_report();
        assert!(
            !report.applicable,
            "Linux has no `WinVerifyTrust` equivalent; `applicable` must be \
             false so the orchestrator threads this differently from a \
             Windows `valid: false` hard fail"
        );
    }

    #[test]
    fn evaluator_reason_cites_install_time_mechanism_not_runtime() {
        let report = canonical_reviewed_report();
        let reason = report.reason.to_lowercase();
        assert!(
            reason.contains("install time") || reason.contains("install-time"),
            "reason must explicitly cite install-time semantics so operators \
             do not misread the report as a runtime attestation pass: {}",
            report.reason
        );
    }

    #[test]
    fn evaluator_reason_documents_both_dpkg_and_rpm_package_paths() {
        let report = canonical_reviewed_report();
        assert!(
            report.reason.contains("dpkg") && report.reason.contains("rpm"),
            "reason must name both dpkg and rpm so the report is honest \
             about which Linux package families are covered at install \
             time: {}",
            report.reason
        );
    }

    #[test]
    fn evaluator_reason_is_non_empty_to_avoid_silent_report_in_orchestrator() {
        let report = canonical_reviewed_report();
        assert!(
            !report.reason.trim().is_empty(),
            "an empty reason would render a confusing applicable=false \
             report with no explanation; reject that shape"
        );
    }

    #[test]
    fn report_schema_version_pinned_to_one_for_forward_compat_drift_detection() {
        let report = canonical_reviewed_report();
        // If this assertion ever needs to change, the producer side must
        // bump schema_version intentionally and every downstream consumer
        // must be audited for the new shape. Pinning here forces that
        // review rather than silently riding through.
        assert_eq!(
            report.schema_version, 1,
            "schema_version is part of the cross-platform health contract; \
             a silent bump would let consumers parse a stale shape"
        );
    }

    #[test]
    fn report_two_independent_collections_are_byte_identical_for_determinism() {
        let a = collect_linux_authenticode_report();
        let b = collect_linux_authenticode_report();
        assert_eq!(
            a, b,
            "collector must be deterministic: two back-to-back calls on \
             the same host must produce equal reports so health diffs \
             reflect real drift, not collector nondeterminism"
        );
    }

    #[test]
    fn report_clone_equals_original_preserving_all_fields() {
        let report = canonical_reviewed_report();
        let cloned = report.clone();
        assert_eq!(cloned, report);
        assert_eq!(cloned.schema_version, report.schema_version);
        assert_eq!(cloned.overall_ok, report.overall_ok);
        assert_eq!(cloned.applicable, report.applicable);
        assert_eq!(cloned.reason, report.reason);
    }

    #[test]
    fn report_debug_formatting_includes_all_field_names_for_operator_triage() {
        let report = canonical_reviewed_report();
        let debug = format!("{report:?}");
        for field in ["schema_version", "overall_ok", "applicable", "reason"] {
            assert!(
                debug.contains(field),
                "Debug impl must surface field `{field}` so operators can \
                 read the report in logs without re-serializing: {debug}"
            );
        }
    }

    #[test]
    fn report_serde_json_value_round_trip_preserves_every_field() {
        let report = canonical_reviewed_report();
        let value = serde_json::to_value(&report).expect("serialize to Value");
        // Confirm each field is present and the right shape at the
        // Value level (catches serde rename / skip drift that a
        // string-based round trip might mask if both sides drift).
        assert_eq!(value["schema_version"], serde_json::json!(1));
        assert_eq!(value["overall_ok"], serde_json::json!(true));
        assert_eq!(value["applicable"], serde_json::json!(false));
        assert!(value["reason"].is_string());
        let parsed: LinuxAuthenticodeReport =
            serde_json::from_value(value).expect("deserialize from Value");
        assert_eq!(parsed, report);
    }

    #[test]
    fn report_serialized_json_exposes_only_the_expected_top_level_keys() {
        let report = canonical_reviewed_report();
        let value = serde_json::to_value(&report).expect("serialize");
        let obj = value.as_object().expect("report serializes as object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["applicable", "overall_ok", "reason", "schema_version"],
            "top-level JSON keys are part of the cross-platform health \
             contract; an extra or missing key would break downstream \
             parsers without a schema bump"
        );
    }

    #[test]
    fn report_deserialize_rejects_empty_input_string() {
        let err = serde_json::from_str::<LinuxAuthenticodeReport>("");
        assert!(
            err.is_err(),
            "empty input must not deserialize into a default report; \
             that would silently mask a missing-collection failure"
        );
    }

    #[test]
    fn report_deserialize_rejects_object_missing_required_schema_version_field() {
        let json = r#"{"overall_ok":true,"applicable":false,"reason":"x"}"#;
        let err = serde_json::from_str::<LinuxAuthenticodeReport>(json);
        assert!(
            err.is_err(),
            "deserializer must reject reports missing schema_version; \
             a default-filled version would silently pin downstream \
             consumers to a stale shape"
        );
    }

    #[test]
    fn report_with_mutated_schema_version_breaks_equality_with_canonical() {
        let canonical = canonical_reviewed_report();
        let mut mutated = canonical.clone();
        mutated.schema_version = 2;
        assert_ne!(
            mutated, canonical,
            "schema_version is part of the report identity; a drift on \
             that field must not compare equal to the canonical shape"
        );
    }

    #[test]
    fn report_with_mutated_applicable_flag_breaks_equality_with_canonical() {
        let canonical = canonical_reviewed_report();
        let mut mutated = canonical.clone();
        mutated.applicable = true;
        assert_ne!(
            mutated, canonical,
            "flipping `applicable` to true would falsely claim Linux \
             enforces a runtime binary signature; that drift must be \
             detectable via PartialEq"
        );
    }

    #[test]
    fn report_with_mutated_overall_ok_breaks_equality_with_canonical() {
        let canonical = canonical_reviewed_report();
        let mut mutated = canonical.clone();
        mutated.overall_ok = false;
        assert_ne!(
            mutated, canonical,
            "an overall_ok=false drift would falsely surface a hard fail \
             on a platform where the op is non-applicable; that shape \
             must not compare equal to the canonical reviewed report"
        );
    }

    #[test]
    fn report_with_mutated_reason_breaks_equality_with_canonical() {
        let canonical = canonical_reviewed_report();
        let mut mutated = canonical.clone();
        mutated.reason = "different reason".to_owned();
        assert_ne!(
            mutated, canonical,
            "reason is operator-facing; a silent rewrite must be \
             detectable via PartialEq for snapshot-style pinning"
        );
    }

    #[test]
    fn report_pins_canonical_serialized_snapshot_to_detect_silent_shape_drift() {
        // Full snapshot pin. If the collector's output ever changes —
        // schema bump, reason rewrite, new field — this test forces an
        // explicit, reviewed update rather than letting the new shape
        // ride through into orchestrator consumers.
        let report = canonical_reviewed_report();
        let value = serde_json::to_value(&report).expect("serialize");
        let expected = serde_json::json!({
            "schema_version": 1,
            "overall_ok": true,
            "applicable": false,
            "reason": "Linux does not enforce binary signatures at runtime; package \
             signature verification happens at install time via dpkg/rpm. \
             A runtime authenticode-equivalent is not part of the reviewed \
             Linux posture today."
        });
        assert_eq!(
            value, expected,
            "canonical Linux authenticode report shape drifted; if this is \
             intentional, bump schema_version and update this snapshot in \
             the same commit"
        );
    }

    #[test]
    fn collector_returns_non_applicable_report_on_every_supported_host_today() {
        // Linux-side analog of the "off-platform collector" test on the
        // Windows side: today the Linux collector is a typed stub that
        // never reports `applicable=true`. This pins that contract so a
        // future slice that wires real dpkg/rpm signature verification
        // has to flip this assertion (and the snapshot above) deliberately.
        for _ in 0..4 {
            let report = collect_linux_authenticode_report();
            assert!(
                !report.applicable,
                "until a runtime dpkg/rpm verifier lands, every collection \
                 must report applicable=false; flipping this assertion is \
                 the explicit signal that runtime attestation went live"
            );
            assert!(
                report.overall_ok,
                "non-applicable must not surface as overall_ok=false; that \
                 would be a hard fail on a platform where the op is N/A"
            );
        }
    }
}
