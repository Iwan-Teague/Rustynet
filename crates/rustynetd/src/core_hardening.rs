#![forbid(unsafe_code)]

//! Linux core-dump / debugger hygiene at daemon startup (AQ-40, B8 / R-SEC-15).
//!
//! `rustynetd` holds long-lived key material in process memory (WireGuard
//! private keys, membership signing keys, enrollment secrets). `rustynet-crypto`
//! already zeroizes that material on drop (CRY-11), but zeroing-on-drop cannot
//! stop two post-compromise disclosure channels that happen while the process
//! is still alive:
//!
//! * a **core dump** — an unexpected crash lets the kernel write the whole
//!   address space, key material included, to disk;
//! * a **privileged debugger** — with `dumpable` left at the default, the
//!   process's own `/proc/<pid>/mem` surface stays attached-friendly and
//!   `/proc/<pid>/*` stays owned by the daemon uid.
//!
//! This module closes both channels at startup, before any key material is
//! loaded, by calling `prctl(PR_SET_DUMPABLE, 0)` and
//! `setrlimit(RLIMIT_CORE, {0, 0})` through the SAFE `nix` wrappers
//! (`nix::sys::prctl::set_dumpable`, `nix::sys::resource::setrlimit`) — no
//! `unsafe` is introduced (the crate keeps `#![deny(unsafe_code)]` at the root
//! and this module re-asserts `#![forbid(unsafe_code)]`).
//!
//! Disposition on failure is FAIL-CLOSED (§3): both calls are self-targeted
//! and cannot legitimately fail on a healthy kernel, so a failure means the
//! runtime is interfering with the process's own security posture (seccomp
//! profile, LSM, broken kernel) and the daemon refuses to start rather than
//! holding key material in a dumpable process.
//!
//! Lab escape hatch: setting `RUSTYNET_ALLOW_CORE_DUMPS=1` (exactly; the
//! parser is fail-closed on any other value) skips the hardening and logs a
//! loud warning, so live-lab debugging can still collect core dumps. The
//! opt-out is env-only on purpose: the daemon's `DaemonConfig` has no
//! file-backed field for it, and a value that only exists on the command
//! line / unit environment cannot silently drift into a reviewed config
//! schema.
//!
//! The control is Linux-only by design (`PR_SET_DUMPABLE` is a Linux prctl;
//! macOS `launchd` and the Windows SCM enforce their own core/crash-dump
//! policies outside the process). On every other platform the apply call is a
//! logged no-op that reports `skipped_reason: Some("not linux")`.

/// Environment variable that opts a deployment OUT of core-dump hardening.
///
/// Recognized values, case-insensitive and whitespace-trimmed:
/// `1`, `true`, `yes`, `on` — hardening is SKIPPED (core dumps stay
/// available for lab debugging). `0`, `false`, `no`, `off`, unset, and the
/// empty string — hardening is ENFORCED. ANY other value is a hard startup
/// error: an operator typo must fail loudly, never silently disable (or
/// silently enable) the disclosure control.
pub const ALLOW_CORE_DUMPS_ENV: &str = "RUSTYNET_ALLOW_CORE_DUMPS";

/// What [`apply_startup_hardening`] actually did, so callers (and tests) can
/// verify the enforcement point instead of trusting a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryHygieneOutcome {
    /// `true` only when `prctl(PR_SET_DUMPABLE, 0)` was applied successfully.
    pub dumpable_disabled: bool,
    /// `true` only when `setrlimit(RLIMIT_CORE, {0, 0})` was applied
    /// successfully.
    pub core_limit_zeroed: bool,
    /// `Some(reason)` when the hardening was skipped entirely (operator
    /// opt-out, or the control is not applicable on this platform).
    pub skipped_reason: Option<&'static str>,
}

/// Fail-closed parser for the [`ALLOW_CORE_DUMPS_ENV`] opt-out.
///
/// Returns `Ok(true)` only for an explicit opt-in to core dumps (`1`, `true`,
/// `yes`, `on`, case-insensitive, trimmed). `Ok(false)` means "enforce the
/// hardening" — including unset, empty, and the explicit negative spellings.
/// Any unrecognized value is `Err`, which the daemon turns into a fatal
/// startup error.
pub fn parse_allow_core_dumps(raw: Option<&str>) -> Result<bool, String> {
    let value = match raw {
        None => return Ok(false),
        Some(value) => value.trim().to_ascii_lowercase(),
    };
    match value.as_str() {
        "" => Ok(false),
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!(
            "invalid {ALLOW_CORE_DUMPS_ENV} value {other:?}: expected \
             1/true/yes/on (allow core dumps) or 0/false/no/off (enforce hardening)"
        )),
    }
}

/// Apply the startup memory-hygiene posture.
///
/// Reads [`ALLOW_CORE_DUMPS_ENV`], parses it fail-closed, and either applies
/// `PR_SET_DUMPABLE=0` + `RLIMIT_CORE={0,0}` (Linux) or logs why it was
/// skipped. Call once, right after logging is initialized and BEFORE any key
/// material is loaded into the process.
///
/// Errors (unrecognized opt-out value, or a failed self-targeted syscall on
/// Linux) are fatal for daemon startup — callers must propagate them.
pub fn apply_startup_hardening() -> Result<MemoryHygieneOutcome, String> {
    let raw = std::env::var(ALLOW_CORE_DUMPS_ENV).ok();
    let allow_core_dumps = parse_allow_core_dumps(raw.as_deref())?;
    apply_parsed(allow_core_dumps)
}

/// Apply a pre-parsed decision. Split from [`apply_startup_hardening`] so the
/// enforcement branch is unit-testable without mutating process env state.
pub fn apply_parsed(allow_core_dumps: bool) -> Result<MemoryHygieneOutcome, String> {
    if allow_core_dumps {
        log::warn!(
            "rustynetd startup: memory hygiene SKIPPED: {ALLOW_CORE_DUMPS_ENV} requests core \
             dumps; a crash may write key material to disk (lab debugging only)"
        );
        return Ok(MemoryHygieneOutcome {
            dumpable_disabled: false,
            core_limit_zeroed: false,
            skipped_reason: Some("operator opt-out"),
        });
    }
    apply_core_dump_hardening()
}

#[cfg(target_os = "linux")]
fn apply_core_dump_hardening() -> Result<MemoryHygieneOutcome, String> {
    // PR_SET_DUMPABLE=0: the kernel marks the process non-dumpable, flips
    // /proc/<pid>/* ownership to root, and blocks the attach-friendly default.
    // Self-targeted; cannot legitimately fail on a healthy kernel.
    if let Err(err) = nix::sys::prctl::set_dumpable(false) {
        let message = format!("prctl(PR_SET_DUMPABLE, 0) failed: {err}");
        log::error!("rustynetd startup: memory hygiene FAILED: {message}");
        return Err(message);
    }
    // RLIMIT_CORE={0,0}: even if dumpable were flipped back, the kernel will
    // not write a core image. Self-targeted; lowering a limit needs no
    // privilege.
    if let Err(err) = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)
    {
        let message = format!("setrlimit(RLIMIT_CORE, 0, 0) failed: {err}");
        log::error!("rustynetd startup: memory hygiene FAILED: {message}");
        return Err(message);
    }
    log::info!(
        "rustynetd startup: memory hygiene applied (PR_SET_DUMPABLE=0, RLIMIT_CORE=0:0); \
         core dumps disabled"
    );
    Ok(MemoryHygieneOutcome {
        dumpable_disabled: true,
        core_limit_zeroed: true,
        skipped_reason: None,
    })
}

#[cfg(not(target_os = "linux"))]
fn apply_core_dump_hardening() -> Result<MemoryHygieneOutcome, String> {
    log::info!(
        "rustynetd startup: memory hygiene not applicable on this platform \
         (PR_SET_DUMPABLE/RLIMIT_CORE are Linux-only controls)"
    );
    Ok(MemoryHygieneOutcome {
        dumpable_disabled: false,
        core_limit_zeroed: false,
        skipped_reason: Some("not linux"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── opt-out parsing (AQ-40 unit-test requirement) ───────────────────────

    #[test]
    fn parse_unset_enforces_hardening() {
        assert_eq!(parse_allow_core_dumps(None), Ok(false));
    }

    #[test]
    fn parse_empty_value_enforces_hardening() {
        assert_eq!(parse_allow_core_dumps(Some("")), Ok(false));
        assert_eq!(parse_allow_core_dumps(Some("   ")), Ok(false));
    }

    #[test]
    fn parse_explicit_opt_out_enables_core_dumps() {
        for value in ["1", "true", "TRUE", "Yes", "on", "  true  "] {
            assert_eq!(
                parse_allow_core_dumps(Some(value)),
                Ok(true),
                "value: {value}"
            );
        }
    }

    #[test]
    fn parse_explicit_negative_enforces_hardening() {
        for value in ["0", "false", "FALSE", "No", "OFF"] {
            assert_eq!(
                parse_allow_core_dumps(Some(value)),
                Ok(false),
                "value: {value}"
            );
        }
    }

    #[test]
    fn parse_unknown_value_fails_closed() {
        // Fail-closed: an operator typo ("ture", "2", "enabled") must be a
        // loud startup error, never a silent disable OR a silent enable.
        for value in ["banana", "2", "tRue!", "enable", "-1"] {
            let err = parse_allow_core_dumps(Some(value)).expect_err(value);
            assert!(
                err.contains(ALLOW_CORE_DUMPS_ENV),
                "error must name the env var: {err}"
            );
        }
    }

    // ── enforcement decisions ────────────────────────────────────────────────

    #[test]
    fn opt_out_decision_skips_hardening_on_every_platform() {
        let outcome = apply_parsed(true).expect("opt-out must never fail startup");
        assert_eq!(outcome.skipped_reason, Some("operator opt-out"));
        assert!(!outcome.dumpable_disabled);
        assert!(!outcome.core_limit_zeroed);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enforce_decision_applies_both_controls_on_linux() {
        // Runs in the Linux CI legs (and any Linux host). Both controls are
        // self-targeted and idempotent; PR_SET_DUMPABLE=0 is process-wide, so
        // this test intentionally leaves the test process non-dumpable —
        // harmless under the CI runner and exactly the posture the daemon
        // ships with.
        let outcome = apply_parsed(false).expect("self-targeted hardening must succeed");
        assert_eq!(outcome.skipped_reason, None);
        assert!(outcome.dumpable_disabled);
        assert!(outcome.core_limit_zeroed);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn enforce_decision_reports_not_applicable_off_linux() {
        let outcome = apply_parsed(false).expect("off-Linux enforce is a logged no-op");
        assert_eq!(outcome.skipped_reason, Some("not linux"));
        assert!(!outcome.dumpable_disabled);
        assert!(!outcome.core_limit_zeroed);
    }
}
