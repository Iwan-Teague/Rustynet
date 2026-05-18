//! X6 — shared CLI exit-code taxonomy.
//!
//! Every `rustynet*` binary returns one of these codes so operators
//! and CI can branch on the failure kind without parsing error text.
//! The taxonomy follows BSD `sysexits.h` conventions closely so that
//! shell wrappers, `systemd` `RestartPreventExitStatus=`, and CI
//! retry policies that already understand `64/65/70/78` work without
//! Rustynet-specific knowledge.
//!
//! Reviewed contract:
//!
//! | Code | Variant            | Meaning                                                        |
//! |------|--------------------|----------------------------------------------------------------|
//! |   0  | `Success`          | the command did what was asked                                 |
//! |  64  | `BadArgs`          | invalid CLI argv / missing required flag / unknown subcommand  |
//! |  65  | `ConfigError`      | configuration on disk failed validation (bad path, bad schema) |
//! |  70  | `TransientFailure` | IO, network, or other retry-safe failure                       |
//! |  78  | `PolicyReject`     | policy or fail-closed gate rejected the operation              |
//! |   1  | `GenericFailure`   | last-resort fallback when no narrower code fits                |
//!
//! Rules:
//!
//! * Bad CLI args (typos, missing required flags, unknown subcommand)
//!   must return `BadArgs`. A clap-style usage error is `BadArgs`.
//! * Configuration that parsed but failed schema or path validation
//!   is `ConfigError`. A signed bundle that fails verification is a
//!   `PolicyReject` instead.
//! * Failures that a retry might fix (TCP RST, sudden EOF, transient
//!   DNS lookup failure) are `TransientFailure`. CI loops can retry
//!   only this code without risking masking a real fault.
//! * Anything that surfaced a fail-closed contract (signature
//!   verification rejected, reviewed-root check rejected, runtime
//!   ACL drift) is `PolicyReject`. Operators must NOT retry these.
//! * `GenericFailure` is `1` so existing `if !cmd; then …` checks
//!   keep working. New code should prefer a narrower variant.
//!
//! See `documents/operations/CliExitCodeTaxonomy.md` for the
//! operator-facing summary, and ADR-003 for the design rationale.

/// CLI exit-code taxonomy. See module docs for the reviewed contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitCode {
    /// 0 — the command did what was asked.
    Success,
    /// 1 — last-resort fallback. Existing call-sites that just want
    /// "non-zero" map to this. New code should choose a narrower code.
    GenericFailure,
    /// 64 — invalid argv / missing required flag / unknown subcommand.
    BadArgs,
    /// 65 — configuration on disk failed validation (bad path, bad
    /// schema, missing required key).
    ConfigError,
    /// 70 — IO / network / transient failure where a retry is sane.
    TransientFailure,
    /// 78 — policy or fail-closed gate rejected the operation. Do NOT
    /// retry; operator intervention required.
    PolicyReject,
}

impl ExitCode {
    /// Numeric exit code as a 32-bit signed integer suitable for
    /// passing to `std::process::exit`.
    pub const fn as_i32(self) -> i32 {
        match self {
            ExitCode::Success => 0,
            ExitCode::GenericFailure => 1,
            ExitCode::BadArgs => 64,
            ExitCode::ConfigError => 65,
            ExitCode::TransientFailure => 70,
            ExitCode::PolicyReject => 78,
        }
    }

    /// Short identifier used in logs and JSON output so operators can
    /// see which taxonomy bucket fired even when the numeric code is
    /// suppressed by an outer shell wrapper.
    pub const fn label(self) -> &'static str {
        match self {
            ExitCode::Success => "success",
            ExitCode::GenericFailure => "generic_failure",
            ExitCode::BadArgs => "bad_args",
            ExitCode::ConfigError => "config_error",
            ExitCode::TransientFailure => "transient_failure",
            ExitCode::PolicyReject => "policy_reject",
        }
    }

    /// Hint string the CLI's top-level error reporter can append to
    /// the message it prints just before `std::process::exit`. Helps
    /// operators tell at a glance whether a retry is sane.
    pub const fn operator_hint(self) -> &'static str {
        match self {
            ExitCode::Success => "",
            ExitCode::GenericFailure => "unclassified failure; check the error message above",
            ExitCode::BadArgs => "invalid CLI arguments; re-run with --help",
            ExitCode::ConfigError => {
                "configuration validation failed; check the path/schema named above"
            }
            ExitCode::TransientFailure => "transient failure (IO/network); retry is likely safe",
            ExitCode::PolicyReject => {
                "fail-closed policy gate rejected the operation; DO NOT retry without operator review"
            }
        }
    }

    /// Convenience for `if let Err(ec) = … { std::process::exit(ec.as_i32()) }`
    /// patterns common across the CLI binaries. Returns the numeric
    /// code without ever returning to the caller.
    pub fn exit(self) -> ! {
        std::process::exit(self.as_i32())
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code.as_i32()
    }
}

impl std::fmt::Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.label(), self.as_i32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_values_match_reviewed_contract() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::GenericFailure.as_i32(), 1);
        assert_eq!(ExitCode::BadArgs.as_i32(), 64);
        assert_eq!(ExitCode::ConfigError.as_i32(), 65);
        assert_eq!(ExitCode::TransientFailure.as_i32(), 70);
        assert_eq!(ExitCode::PolicyReject.as_i32(), 78);
    }

    #[test]
    fn labels_are_stable_snake_case_strings() {
        // Pin so a future Rename refactor (e.g. PolicyReject ->
        // PolicyFailClosed) trips a named test, since downstream
        // log-grepping CI may depend on these.
        assert_eq!(ExitCode::Success.label(), "success");
        assert_eq!(ExitCode::GenericFailure.label(), "generic_failure");
        assert_eq!(ExitCode::BadArgs.label(), "bad_args");
        assert_eq!(ExitCode::ConfigError.label(), "config_error");
        assert_eq!(ExitCode::TransientFailure.label(), "transient_failure");
        assert_eq!(ExitCode::PolicyReject.label(), "policy_reject");
    }

    #[test]
    fn operator_hint_marks_policy_reject_as_no_retry() {
        // Pin the explicit no-retry instruction so a retry loop that
        // does `grep -q "retry is likely safe"` only ever retries on
        // TransientFailure.
        assert!(
            ExitCode::TransientFailure
                .operator_hint()
                .contains("retry is likely safe"),
            "transient hint must mention retry safety"
        );
        assert!(
            ExitCode::PolicyReject
                .operator_hint()
                .contains("DO NOT retry"),
            "policy-reject hint must explicitly forbid retry"
        );
    }

    #[test]
    fn operator_hint_for_success_is_empty() {
        // Success path: nothing to surface to the operator.
        assert_eq!(ExitCode::Success.operator_hint(), "");
    }

    #[test]
    fn display_renders_label_and_numeric_code() {
        assert_eq!(format!("{}", ExitCode::BadArgs), "bad_args (64)");
        assert_eq!(format!("{}", ExitCode::PolicyReject), "policy_reject (78)");
    }

    #[test]
    fn from_exit_code_into_i32_round_trips_against_as_i32() {
        // Every variant must satisfy `i32::from(ec) == ec.as_i32()`
        // so the From impl is consistent with the inherent method.
        for ec in [
            ExitCode::Success,
            ExitCode::GenericFailure,
            ExitCode::BadArgs,
            ExitCode::ConfigError,
            ExitCode::TransientFailure,
            ExitCode::PolicyReject,
        ] {
            assert_eq!(i32::from(ec), ec.as_i32(), "From inconsistency for {ec:?}");
        }
    }

    /// Snapshot test: pin the exact reviewed taxonomy as a single
    /// array so a future addition (or, worse, a silent removal) shows
    /// up as a named test failure.
    #[test]
    fn reviewed_taxonomy_pinned_at_six_variants() {
        const REVIEWED: &[(ExitCode, i32, &str)] = &[
            (ExitCode::Success, 0, "success"),
            (ExitCode::GenericFailure, 1, "generic_failure"),
            (ExitCode::BadArgs, 64, "bad_args"),
            (ExitCode::ConfigError, 65, "config_error"),
            (ExitCode::TransientFailure, 70, "transient_failure"),
            (ExitCode::PolicyReject, 78, "policy_reject"),
        ];
        assert_eq!(REVIEWED.len(), 6);
        for (ec, code, label) in REVIEWED {
            assert_eq!(ec.as_i32(), *code, "{ec:?} numeric drift");
            assert_eq!(ec.label(), *label, "{ec:?} label drift");
        }
    }

    /// Numeric codes must NOT collide with each other — a future
    /// refactor that accidentally maps BadArgs and ConfigError to the
    /// same number must trip a named failure.
    #[test]
    fn numeric_codes_are_pairwise_distinct() {
        let codes = [
            ExitCode::Success.as_i32(),
            ExitCode::GenericFailure.as_i32(),
            ExitCode::BadArgs.as_i32(),
            ExitCode::ConfigError.as_i32(),
            ExitCode::TransientFailure.as_i32(),
            ExitCode::PolicyReject.as_i32(),
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            codes.len(),
            "exit codes must be pairwise distinct: {codes:?}"
        );
    }

    /// Pin sysexits.h alignment: 64/65/70/78 are the canonical BSD
    /// sysexits codes. Any future refactor that drifts away from
    /// those must be a deliberate act with a paired runbook update.
    #[test]
    fn taxonomy_aligns_with_sysexits_h() {
        // sysexits.h: EX_USAGE=64, EX_DATAERR=65, EX_SOFTWARE=70,
        //             EX_CONFIG=78
        assert_eq!(ExitCode::BadArgs.as_i32(), 64, "EX_USAGE drift");
        assert_eq!(ExitCode::ConfigError.as_i32(), 65, "EX_DATAERR drift");
        assert_eq!(ExitCode::TransientFailure.as_i32(), 70, "EX_SOFTWARE drift");
        assert_eq!(ExitCode::PolicyReject.as_i32(), 78, "EX_CONFIG drift");
    }
}
