#![allow(dead_code)]
use std::time::Duration;

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const MAX_LAB_CLOCK_SKEW_SECS: u64 = 90;

/// Clock-probe retry budget. The probe is the first SSH command a run issues
/// against a guest, so it eats first-connection transients (control-master
/// warm-up, ARP/route settle after a network reconfig). A single transient
/// `Operation timed out` used to hard-fail the whole run (cascade to skip-all +
/// cleanup fail); retry a few times before giving up (ledger 2026-07-11,
/// observed on `debian-headless-4`). The underlying `ssh::run_remote` already
/// bounds each attempt with `ConnectTimeout=15`, so this only adds retries, not
/// an unbounded wait.
const CLOCK_PROBE_ATTEMPTS: u32 = 3;
const CLOCK_PROBE_RETRY_BACKOFF: Duration = Duration::from_millis(750);

/// Run `op` up to `attempts` times (clamped to at least one), sleeping `backoff`
/// between tries, returning the first `Ok`. Route ONLY transient transport
/// failures here — a deterministic remote error (non-zero exit, unparseable
/// output) is handled by the caller without retry.
fn retry_transient<T, E>(
    attempts: u32,
    backoff: Duration,
    mut op: impl FnMut() -> Result<T, E>,
) -> Result<T, E> {
    let attempts = attempts.max(1);
    let mut last_err: Option<E> = None;
    for attempt in 1..=attempts {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_err = Some(err);
                if attempt < attempts {
                    std::thread::sleep(backoff);
                }
            }
        }
    }
    Err(last_err.expect("attempts >= 1 guarantees at least one captured error"))
}

fn parse_remote_unix_time(output: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(output)
        .map_err(|err| format!("remote clock output is not UTF-8: {err}"))?
        .trim();
    text.parse::<u64>()
        .map_err(|err| format!("remote clock output is not a Unix timestamp ({text:?}): {err}"))
}

fn validate_clock_skew(host_unix: u64, guest_unix: u64, max_skew_secs: u64) -> Result<(), String> {
    let skew = host_unix.abs_diff(guest_unix);
    if skew > max_skew_secs {
        Err(format!(
            "guest clock skew is {skew}s (maximum {max_skew_secs}s; host={host_unix}, guest={guest_unix})"
        ))
    } else {
        Ok(())
    }
}

/// Classification of a measured host/guest clock difference beyond the
/// preflight tolerance. Pure diagnosis only — this type never mutates
/// anything and the gate (`validate_clock_skew`) remains the sole arbiter of
/// pass/fail; classification only enriches the failure with a verdict
/// (WindowsClockSkewHardeningPlan_2026-09-02 §3, as amended by the
/// adversarial review A-1/A-2).
///
/// There is deliberately no `Unparseable` variant (review A-2): the
/// classifier receives already-parsed u64 timestamps, and a guest clock
/// string that fails to parse stays an `execute()`-level failure via
/// `parse_remote_unix_time` — never a classifier verdict.
///
/// Sign convention (review A-3): the skew is `s = host_unix - guest_unix`;
/// `s > 0` means the guest clock is BEHIND the host. `HourOffset::
/// offset_hours` carries this sign (e.g. the observed 3602 s case —
/// host ahead of guest by one hour plus two seconds — is `HourOffset
/// { offset_hours: 1 }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClockVerdict {
    /// |host_unix - guest_unix| <= max_skew_secs; the gate passes, no remedy
    /// is needed.
    WithinTolerance,
    /// Beyond tolerance, but within the inclusive ±30 s band of a nonzero
    /// whole-hour quantum — the RTC-localtime / TZ-convention signature.
    /// `offset_hours` is signed per the convention above.
    HourOffset { offset_hours: i64 },
    /// Beyond tolerance with no hour quantum — an uncharacterized drift
    /// (free-running clock, pause/restore lag). Diagnose-only (review A-1):
    /// never remediated.
    GenericDrift { skew_secs: i64 },
}

/// The inclusive ±30 s residual band around a whole-hour quantum that still
/// classifies as an `HourOffset` (review A-7: inclusive; 3630 s → 1 h,
/// 3631 s → not quantized).
const HOUR_QUANTUM_RESIDUAL_BAND_SECS: u64 = 30;
const SECS_PER_HOUR: u64 = 3600;

/// Pure classifier for a measured clock skew. Side-effect-free; never panics;
/// never returns a verdict that contradicts the gate: whenever
/// `classify_clock_skew` returns anything, `validate_clock_skew` with the
/// same inputs returns `Ok` iff the verdict is `WithinTolerance` (pinned by
/// `clock_verdict_negative_never_ok_when_skew_exceeds_max`).
///
/// Hour-quantization rule (plan §3, band amended inclusive by review A-7):
/// with `m = |s|` and `round(m/3600)` the nearest whole hour, the skew is
/// hour-quantized iff `|m - round(m/3600)·3600| <= 30` and
/// `round(m/3600) >= 1`.
pub(crate) fn classify_clock_skew(
    host_unix: u64,
    guest_unix: u64,
    max_skew_secs: u64,
) -> ClockVerdict {
    let magnitude = host_unix.abs_diff(guest_unix);
    if magnitude <= max_skew_secs {
        return ClockVerdict::WithinTolerance;
    }
    // Beyond tolerance: the gate has already failed (or will), regardless of
    // which verdict is produced below. Classification can never upgrade a
    // failing skew to a pass because the WithinTolerance branch is decided
    // by exactly the same comparison the gate uses.
    debug_assert!(
        magnitude > 0,
        "magnitude > max_skew_secs >= 0 implies a nonzero magnitude"
    );
    let sign: i64 = if host_unix >= guest_unix { 1 } else { -1 };

    // Signed skew s = host - guest (review A-3). The magnitude can exceed
    // i64::MAX only for |s| > i64::MAX seconds (~2.9e11 years), which no
    // real Unix timestamp can produce; saturate instead of wrapping so the
    // classifier stays total and panic-free. The conversion is therefore
    // error-free for every physically possible input and the saturation is
    // documented, not silent.
    let skew_secs = i64::try_from(magnitude).unwrap_or(if sign > 0 { i64::MAX } else { i64::MIN });

    // Nearest whole hour to magnitude/3600, computed with integer arithmetic:
    // `magnitude % 3600 >= 3300` means the residual to the NEXT hour
    // (`3600 - residual`) is within the 30 s band, so round up; otherwise
    // round down.
    let hours_down = magnitude / SECS_PER_HOUR;
    let residual_down = magnitude % SECS_PER_HOUR;
    let (hours, residual) = if residual_down >= SECS_PER_HOUR - HOUR_QUANTUM_RESIDUAL_BAND_SECS {
        (hours_down + 1, SECS_PER_HOUR - residual_down)
    } else {
        (hours_down, residual_down)
    };
    // `round(m/3600) >= 1` guard (plan §3): a sub-hour skew that rounds to
    // zero hours is generic drift, not a whole-hour offset. `hours` is bounded
    // by u64::MAX/3600 + 1 (~5.1e15), so this i64 conversion cannot overflow.
    if residual <= HOUR_QUANTUM_RESIDUAL_BAND_SECS && hours >= 1 {
        let hours = i64::try_from(hours).unwrap_or(i64::MAX);
        ClockVerdict::HourOffset {
            offset_hours: sign * hours,
        }
    } else {
        ClockVerdict::GenericDrift { skew_secs }
    }
}

/// Whether the guarded self-heal (a later, flag-gated step) may attempt a
/// remedy for this verdict. Only `HourOffset` qualifies (review A-1): its
/// cause is characterized (RTC-localtime / TZ convention). `GenericDrift` is
/// an unknown-cause signature — diagnose-only, never mutated.
/// `WithinTolerance` needs no remedy. This predicate is the single place
/// that policy is expressed.
pub(crate) fn remediation_allowed(verdict: &ClockVerdict) -> bool {
    matches!(verdict, ClockVerdict::HourOffset { .. })
}

use crate::vm_lab::orchestrator::adapter::validated_args::ValidatedArg;

/// Build the validated, seam-rendered remedy argv for ONE clock-skew
/// remediation attempt (plan §4; review A-9). The remedy target is a
/// [`ValidatedArg::UnixSeconds`] — it reaches this builder only after the
/// `unix_seconds` class validator accepted it, and it is embedded as inert
/// ASCII digits (`@<secs>` / a digits-only PowerShell expression), never via
/// a shell string assembled from unvalidated input. The live exec against a
/// real guest is deliberately NOT wired here: `execute` drives this argv
/// through an `apply` closure so the ordering and the fail-closed re-measure
/// are unit-testable offline without a live Windows/Linux guest.
pub(crate) fn build_clock_remediation_argv(
    platform: crate::vm_lab::VmGuestPlatform,
    target_unix: &ValidatedArg,
) -> Vec<String> {
    match platform {
        crate::vm_lab::VmGuestPlatform::Windows => vec![
            "powershell.exe".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            format!(
                "Set-Date -Date ([DateTimeOffset]::FromUnixTimeSeconds({}).UtcDateTime)",
                target_unix.value()
            ),
        ],
        _ => vec![
            "sudo".to_owned(),
            "timedatectl".to_owned(),
            "set-time".to_owned(),
            format!("@{}", target_unix.value()),
        ],
    }
}

fn fresh_unix_seconds() -> Result<u64, String> {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => Ok(duration.as_secs()),
        Err(err) => Err(format!(
            "orchestrator host clock precedes Unix epoch: {err}"
        )),
    }
}

/// ONE bounded remediation attempt followed by a re-measure through the SAME
/// [`validate_clock_skew`] gate (plan §4; review A-4). Only an
/// `HourOffset`-classified drift is remediable (`remediation_allowed`); every
/// other class, every remediation failure, and every residual skew fails
/// closed. Every `Err` carries the ORIGINAL gate text (`skew_err`) plus an
/// enriched suffix; the caller prefixes the node alias.
pub(crate) fn attempt_clock_remediation(
    platform: crate::vm_lab::VmGuestPlatform,
    probe_host_unix: u64,
    probe_guest_unix: u64,
    max_skew_secs: u64,
    skew_err: &str,
    apply: &mut dyn FnMut(&[String]) -> Result<(), String>,
    remeasure_guest_unix: &mut dyn FnMut() -> Result<u64, String>,
) -> Result<(), String> {
    let verdict = classify_clock_skew(probe_host_unix, probe_guest_unix, max_skew_secs);
    if !remediation_allowed(&verdict) {
        return Err(format!(
            "{skew_err}; clock remediation is enabled but this drift class has no \
             automatic remedy; failing closed"
        ));
    }
    // A-4: the remedy target is captured FRESH inside the attempt — never the
    // probe-time reading, which is already stale by the time a fix would land.
    let fresh_host_unix = fresh_unix_seconds()?;
    let target = ValidatedArg::unix_seconds(&fresh_host_unix.to_string())
        .map_err(|err| format!("fresh remediation timestamp rejected: {err}"))?;
    let argv = build_clock_remediation_argv(platform, &target);
    apply(&argv).map_err(|err| {
        format!("{skew_err}; clock remediation attempt failed: {err}; failing closed")
    })?;
    let remeasured_guest_unix = remeasure_guest_unix().map_err(|err| {
        format!("{skew_err}; clock remediation re-measure failed: {err}; failing closed")
    })?;
    let remeasured_host_unix = fresh_unix_seconds()?;
    if let Err(recheck_err) =
        validate_clock_skew(remeasured_host_unix, remeasured_guest_unix, max_skew_secs)
    {
        return Err(format!(
            "{skew_err}; clock remediation did not resolve the skew ({recheck_err}); \
             failing closed"
        ));
    }
    Ok(())
}

/// The stage's decision on a skew-gate failure, factored out so the OFF
/// path's byte-identity (review A-6) and the ON path's fail-closed behaviour
/// are testable offline without a live guest.
#[allow(clippy::too_many_arguments)]
fn clock_skew_failure_outcome(
    alias: &str,
    skew_err: &str,
    remediation_enabled: bool,
    platform: crate::vm_lab::VmGuestPlatform,
    probe_host_unix: u64,
    probe_guest_unix: u64,
    max_skew_secs: u64,
    apply: &mut dyn FnMut(&[String]) -> Result<(), String>,
    remeasure_guest_unix: &mut dyn FnMut() -> Result<u64, String>,
) -> StageOutcome {
    if !remediation_enabled {
        // Flag OFF: byte-identical to the pre-flag behaviour (A-6).
        return StageOutcome::Failed(format!("{alias}: {skew_err}"));
    }
    match attempt_clock_remediation(
        platform,
        probe_host_unix,
        probe_guest_unix,
        max_skew_secs,
        skew_err,
        apply,
        remeasure_guest_unix,
    ) {
        Ok(()) => StageOutcome::Passed,
        Err(remediation_err) => StageOutcome::Failed(format!("{alias}: {remediation_err}")),
    }
}

pub struct PreflightStage {
    /// `--enable-clock-remediation`: arms the ONE-SHOT self-heal below. OFF
    /// (the default) keeps every failure text byte-identical to the
    /// pre-flag behaviour (review A-6).
    pub clock_remediation_enabled: bool,
}

impl OrchestrationStage for PreflightStage {
    fn id(&self) -> StageId {
        StageId::Preflight
    }
    fn name(&self) -> &str {
        "preflight"
    }
    fn dependencies(&self) -> &[StageId] {
        &[]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // 1. report_dir writable
        if !ctx.report_dir.exists()
            && let Err(e) = std::fs::create_dir_all(&ctx.report_dir)
        {
            return StageOutcome::Failed(format!(
                "cannot create report dir '{}': {e}",
                ctx.report_dir.display()
            ));
        }
        let probe = ctx.report_dir.join(".preflight_write_test");
        if std::fs::write(&probe, b"ok").is_err() {
            return StageOutcome::Failed(format!(
                "report dir '{}' is not writable",
                ctx.report_dir.display()
            ));
        }
        let _ = std::fs::remove_file(&probe);

        // 1b. network-profile immutability: the record written at launch must
        // still verify against the on-repo manifests. Drift after launch
        // fails closed (connectivity rulebook §15.4). Legacy report dirs
        // without a record skip the check; the launch path always writes one.
        let network_profile_record = ctx.report_dir.join("orchestration/network_profile.json");
        if network_profile_record.is_file() {
            let verified = std::fs::read_to_string(&network_profile_record)
                .map_err(|err| format!("read network profile record failed: {err}"))
                .and_then(|raw| {
                    serde_json::from_str::<
                        crate::vm_lab::network_profile::OrchestrationNetworkProfileRecord,
                    >(&raw)
                    .map_err(|err| format!("parse network profile record failed: {err}"))
                })
                .and_then(|record| {
                    record.verify_against_manifests(std::path::Path::new(
                        crate::vm_lab::network_profile::DEFAULT_NETWORK_PROFILE_DIR,
                    ))
                });
            if let Err(err) = verified {
                return StageOutcome::Failed(format!("network profile drift check failed: {err}"));
            }
        }

        // 2. ssh binary
        if std::process::Command::new("ssh")
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_err()
        {
            return StageOutcome::Failed("ssh binary not found in PATH".to_owned());
        }

        // 3. exactly one exit node
        let exit_count = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Exit)
            .count();
        if exit_count != 1 {
            return StageOutcome::Failed(format!(
                "lab requires exactly 1 Exit node, found {exit_count}"
            ));
        }

        // 4. signed-state freshness depends on synchronized clocks. A paused
        // VM can be hours behind while SSH/readiness still look healthy; issuing
        // bundles then makes the daemon reject them as future-dated. Detect the
        // condition before bootstrap or signed-state mutation.
        for (alias, adapter) in &ctx.adapters {
            let host = match adapter.shell_host() {
                Ok(host) => host,
                Err(err) => {
                    return StageOutcome::Failed(format!(
                        "{alias}: cannot construct clock probe: {err}"
                    ));
                }
            };
            let platform = adapter.platform();
            let argv: &[&str] = match platform {
                crate::vm_lab::VmGuestPlatform::Windows => &[
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()",
                ],
                _ => &["date", "+%s"],
            };
            // Retry only the transport: a first-connection SSH transient must
            // not decide the whole run. A non-zero exit / unparseable output
            // below is deterministic and is NOT retried.
            let status = match retry_transient(
                CLOCK_PROBE_ATTEMPTS,
                CLOCK_PROBE_RETRY_BACKOFF,
                || host.run_argv(argv, &[], &[]),
            ) {
                Ok(status) => status,
                Err(err) => {
                    return StageOutcome::Failed(format!(
                        "{alias}: remote clock probe failed after {CLOCK_PROBE_ATTEMPTS} attempts: {err}"
                    ));
                }
            };
            if !status.is_success() {
                return StageOutcome::Failed(format!(
                    "{alias}: remote clock probe exited {}: {}",
                    status.code,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
            let guest_unix = match parse_remote_unix_time(&status.stdout) {
                Ok(value) => value,
                Err(err) => return StageOutcome::Failed(format!("{alias}: {err}")),
            };
            let host_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            {
                Ok(duration) => duration.as_secs(),
                Err(err) => {
                    return StageOutcome::Failed(format!(
                        "orchestrator host clock precedes Unix epoch: {err}"
                    ));
                }
            };
            if let Err(err) = validate_clock_skew(host_unix, guest_unix, MAX_LAB_CLOCK_SKEW_SECS) {
                // The flag-gated seam: OFF = today's failure exactly (A-6);
                // ON = one bounded remediation attempt through validated argv
                // + a re-measure through the SAME gate (still fail-closed).
                // The live exec against the guest is intentionally not wired:
                // the production closure refuses, so a flag-ON run can never
                // silently "succeed" without a real fix landing on the guest.
                let mut apply = |_attempted: &[String]| -> Result<(), String> {
                    Err("live clock-remediation exec is not wired (offline seam); \
                         the live-guest step supplies the exec closure"
                        .to_owned())
                };
                let mut remeasure = || -> Result<u64, String> {
                    let status = retry_transient(
                        CLOCK_PROBE_ATTEMPTS,
                        CLOCK_PROBE_RETRY_BACKOFF,
                        || host.run_argv(argv, &[], &[]),
                    )
                    .map_err(|err| {
                        format!(
                            "remote clock probe failed after {CLOCK_PROBE_ATTEMPTS} attempts: {err}"
                        )
                    })?;
                    if !status.is_success() {
                        return Err(format!(
                            "remote clock probe exited {}: {}",
                            status.code,
                            String::from_utf8_lossy(&status.stderr).trim()
                        ));
                    }
                    parse_remote_unix_time(&status.stdout)
                };
                return clock_skew_failure_outcome(
                    alias,
                    &err,
                    self.clock_remediation_enabled,
                    platform,
                    host_unix,
                    guest_unix,
                    MAX_LAB_CLOCK_SKEW_SECS,
                    &mut apply,
                    &mut remeasure,
                );
            }
        }

        StageOutcome::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use std::collections::HashMap;

    fn make_ctx_with_exit(tmp_dir: &std::path::Path) -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "exit-1".to_owned(),
                role: NodeRole::Exit,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: tmp_dir.to_path_buf(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
        }
    }

    #[test]
    fn preflight_passes_with_exit_node_and_writable_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = make_ctx_with_exit(tmp.path());
        let outcome = PreflightStage {
            clock_remediation_enabled: false,
        }
        .execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Passed | StageOutcome::Failed(_)),
            "must produce a terminal outcome: {outcome:?}"
        );
    }

    #[test]
    fn preflight_fails_with_no_exit_node() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "client-1".to_owned(),
                role: NodeRole::Client,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: tmp.path().to_path_buf(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
        };
        let outcome = PreflightStage {
            clock_remediation_enabled: false,
        }
        .execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Failed(_)),
            "must fail with no exit node: {outcome:?}"
        );
    }

    #[test]
    fn remote_clock_parser_and_skew_check_fail_closed() {
        assert_eq!(parse_remote_unix_time(b"123\n"), Ok(123));
        assert!(parse_remote_unix_time(b"").is_err());
        assert!(parse_remote_unix_time(b"not-a-time").is_err());
        assert!(validate_clock_skew(1_000, 910, 90).is_ok());
        assert!(validate_clock_skew(1_000, 909, 90).is_err());
        assert!(validate_clock_skew(909, 1_000, 90).is_err());
    }

    #[test]
    fn preflight_failure_text_unchanged_by_classifier() {
        // The classifier is additive diagnosis; the gate's failure text is
        // the exact string live-lab triage greps for and must not move
        // (review A-6's OFF-path byte-identity, pinned pre-flag).
        assert_eq!(
            validate_clock_skew(1_785_005_541, 1_785_001_939, 90),
            Err(
                "guest clock skew is 3602s (maximum 90s; host=1785005541, guest=1785001939)"
                    .to_owned()
            )
        );
    }

    #[test]
    fn clock_verdict_passes_within_max() {
        // skew == max is inside tolerance (extends the 90-pass edge in
        // remote_clock_parser_and_skew_check_fail_closed).
        assert!(matches!(
            classify_clock_skew(1_000, 910, 90),
            ClockVerdict::WithinTolerance
        ));
        assert!(matches!(
            classify_clock_skew(910, 1_000, 90),
            ClockVerdict::WithinTolerance
        ));
        assert!(matches!(
            classify_clock_skew(5, 5, 0),
            ClockVerdict::WithinTolerance
        ));
    }

    #[test]
    fn clock_verdict_fails_beyond_max() {
        // skew == max+1 is beyond tolerance: the classifier must NOT say
        // WithinTolerance (and the gate must still reject).
        assert!(!matches!(
            classify_clock_skew(1_000, 909, 90),
            ClockVerdict::WithinTolerance
        ));
        assert!(validate_clock_skew(1_000, 909, 90).is_err());
    }

    #[test]
    fn clock_verdict_classifies_hour_offset() {
        // 3602 s: the observed signature (host ahead — guest BEHIND, sign +).
        assert_eq!(
            classify_clock_skew(1_785_005_541, 1_785_001_939, 90),
            ClockVerdict::HourOffset { offset_hours: 1 }
        );
        // Mirrored input pair: guest ahead by one hour (sign -).
        assert_eq!(
            classify_clock_skew(1_785_001_939, 1_785_005_541, 90),
            ClockVerdict::HourOffset { offset_hours: -1 }
        );
        // 7195 s: |7195 - 2*3600| = 5 <= 30 → rounds up to 2 hours.
        assert_eq!(
            classify_clock_skew(7_200, 5, 90),
            ClockVerdict::HourOffset { offset_hours: 2 }
        );
    }

    #[test]
    fn clock_verdict_rejects_non_hour_quantum() {
        // 1800: exactly between quanta. 7240: |7240 - 7200| = 40 > 30
        // (review A-5 replaced the plan's contradictory 7205 example).
        assert_eq!(
            classify_clock_skew(1_800, 0, 90),
            ClockVerdict::GenericDrift { skew_secs: 1_800 }
        );
        assert_eq!(
            classify_clock_skew(7_240, 0, 90),
            ClockVerdict::GenericDrift { skew_secs: 7_240 }
        );
    }

    #[test]
    fn clock_verdict_band_boundary_is_inclusive() {
        // Review A-7: the ±30 s residual band is inclusive.
        assert_eq!(
            classify_clock_skew(3_630, 0, 90),
            ClockVerdict::HourOffset { offset_hours: 1 }
        );
        assert_eq!(
            classify_clock_skew(3_631, 0, 90),
            ClockVerdict::GenericDrift { skew_secs: 3_631 }
        );
    }

    #[test]
    fn clock_verdict_generic_drift_gets_no_remedy() {
        // Review A-1: only the hour-quantized signature may ever be
        // remediated; generic drift is diagnose-only and within-tolerance
        // needs nothing.
        assert!(remediation_allowed(&ClockVerdict::HourOffset {
            offset_hours: 1
        }));
        assert!(!remediation_allowed(&ClockVerdict::GenericDrift {
            skew_secs: 1_800
        }));
        assert!(!remediation_allowed(&ClockVerdict::WithinTolerance));
    }

    #[test]
    fn clock_verdict_negative_never_ok_when_skew_exceeds_max() {
        // For EVERY skew beyond the maximum the verdict is never
        // WithinTolerance AND the gate still errors — classification can
        // never upgrade a failing skew to a pass.
        let max: u64 = 90;
        for skew in (max + 1)..=7_200 {
            let (host, guest) = (1_000_000, 1_000_000 - skew);
            assert!(
                !matches!(
                    classify_clock_skew(host, guest, max),
                    ClockVerdict::WithinTolerance
                ),
                "skew {skew} classified WithinTolerance"
            );
            assert!(
                validate_clock_skew(host, guest, max).is_err(),
                "gate accepted skew {skew}"
            );
        }
    }

    // ── Clock-skew self-heal (flag-gated; plan §4, review A-4/A-6/A-9) ──────

    const A6_SKEW_ERR: &str =
        "guest clock skew is 3602s (maximum 90s; host=1785005541, guest=1785001939)";

    fn hour_offset_pair() -> (u64, u64) {
        (1785005541, 1785001939) // exactly 3602s ≈ 1h behind
    }

    #[test]
    fn preflight_failure_text_identical_with_flag_off() {
        // The gate text is verbatim today's (A-6).
        let err = validate_clock_skew(1785005541, 1785001939, 90)
            .expect_err("a 3602s skew must fail the gate");
        assert_eq!(err, A6_SKEW_ERR);
        let mut apply_calls = 0usize;
        {
            let mut apply = |_argv: &[String]| -> Result<(), String> {
                apply_calls += 1;
                Ok(())
            };
            let mut remeasure = || -> Result<u64, String> { Ok(1785005541) };
            let (host, guest) = hour_offset_pair();
            let outcome = clock_skew_failure_outcome(
                "win-guest",
                &err,
                false,
                crate::vm_lab::VmGuestPlatform::Windows,
                host,
                guest,
                90,
                &mut apply,
                &mut remeasure,
            );
            match outcome {
                StageOutcome::Failed(text) => assert_eq!(
                    text,
                    "win-guest: guest clock skew is 3602s (maximum 90s; host=1785005541, guest=1785001939)"
                ),
                other => panic!("flag OFF must fail exactly as today: {other:?}"),
            }
        }
        assert_eq!(apply_calls, 0, "flag OFF: no clock_remediation may happen");
    }

    #[test]
    fn clock_remediation_builds_validated_set_date_argv_only_for_hour_offset() {
        let (host, guest) = hour_offset_pair();
        let verdict = classify_clock_skew(host, guest, 90);
        assert!(remediation_allowed(&verdict), "hour quantum is remediable");
        let target = ValidatedArg::unix_seconds("1788381043").expect("plausible timestamp");
        let win_argv =
            build_clock_remediation_argv(crate::vm_lab::VmGuestPlatform::Windows, &target);
        assert_eq!(win_argv[0], "powershell.exe");
        assert!(
            win_argv
                .last()
                .expect("argv")
                .contains("Set-Date -Date ([DateTimeOffset]::FromUnixTimeSeconds(1788381043)"),
            "Set-Date remedy embeds the validated timestamp: {:?}",
            win_argv.last()
        );
        let linux_argv =
            build_clock_remediation_argv(crate::vm_lab::VmGuestPlatform::Linux, &target);
        assert_eq!(
            linux_argv,
            vec![
                "sudo".to_owned(),
                "timedatectl".to_owned(),
                "set-time".to_owned(),
                "@1788381043".to_owned(),
            ]
        );

        // GenericDrift (over max, not an hour quantum): remediation is
        // refused outright and nothing is applied.
        let drift_guest = host - 600;
        let skew_err = validate_clock_skew(host, drift_guest, 90).expect_err("skewed");
        let mut apply_calls = 0usize;
        {
            let mut apply = |_argv: &[String]| -> Result<(), String> {
                apply_calls += 1;
                Ok(())
            };
            let mut remeasure = || -> Result<u64, String> { Ok(host) };
            let outcome = attempt_clock_remediation(
                crate::vm_lab::VmGuestPlatform::Linux,
                host,
                drift_guest,
                90,
                &skew_err,
                &mut apply,
                &mut remeasure,
            );
            match outcome {
                Err(msg) => {
                    assert!(msg.contains(&skew_err), "keeps the original gate text");
                    assert!(msg.contains("no automatic remedy"), "{msg}");
                }
                Ok(()) => panic!("GenericDrift must not be remediated"),
            }
        }
        assert_eq!(apply_calls, 0, "no argv may be applied for GenericDrift");
    }

    #[test]
    fn clock_remediation_uses_a_fresh_timestamp_not_the_probe_value() {
        let (probe_host, probe_guest) = hour_offset_pair();
        let test_start = fresh_unix_seconds().expect("host clock reads");
        let captured: std::cell::RefCell<Option<Vec<String>>> = std::cell::RefCell::new(None);
        {
            let mut apply = |argv: &[String]| -> Result<(), String> {
                *captured.borrow_mut() = Some(argv.to_vec());
                Ok(())
            };
            let mut remeasure = || -> Result<u64, String> { fresh_unix_seconds() };
            let skew_err = validate_clock_skew(probe_host, probe_guest, 90)
                .expect_err("a 3602s skew must fail the gate");
            attempt_clock_remediation(
                crate::vm_lab::VmGuestPlatform::Windows,
                probe_host,
                probe_guest,
                90,
                &skew_err,
                &mut apply,
                &mut remeasure,
            )
            .expect("a fresh-target remediation with a synced re-measure resolves");
        }
        let argv = captured
            .into_inner()
            .expect("the apply closure captured the argv");
        let digits: String = argv
            .last()
            .expect("argv")
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        let applied_secs: u64 = digits.parse().expect("digits-only timestamp");
        assert!(
            applied_secs >= test_start,
            "the remedy target must be a FRESH host reading (A-4), got {applied_secs} < {test_start}"
        );
        assert_ne!(
            applied_secs, probe_host,
            "the remedy target must never be the probe-time host value"
        );
    }

    #[test]
    fn clock_remediation_still_fails_closed_when_remeasure_is_still_skewed() {
        let (host, guest) = hour_offset_pair();
        let skew_err =
            validate_clock_skew(host, guest, 90).expect_err("a 3602s skew must fail the gate");
        let mut apply_calls = 0usize;
        {
            let mut apply = |_argv: &[String]| -> Result<(), String> {
                apply_calls += 1;
                Ok(())
            };
            // The guest is still 3602s behind after the attempt.
            let mut remeasure = || -> Result<u64, String> { Ok(guest) };
            let outcome = attempt_clock_remediation(
                crate::vm_lab::VmGuestPlatform::Linux,
                host,
                guest,
                90,
                &skew_err,
                &mut apply,
                &mut remeasure,
            );
            match outcome {
                Err(msg) => {
                    assert!(msg.contains(&skew_err), "keeps the original gate text");
                    assert!(msg.contains("did not resolve the skew"), "{msg}");
                    assert!(msg.contains("failing closed"), "{msg}");
                }
                Ok(()) => panic!("a still-skewed re-measure must fail closed"),
            }
        }
        assert_eq!(apply_calls, 1, "exactly ONE bounded attempt");
    }

    #[test]
    fn clock_remediation_apply_failure_fails_closed() {
        let (host, guest) = hour_offset_pair();
        let skew_err =
            validate_clock_skew(host, guest, 90).expect_err("a 3602s skew must fail the gate");
        let mut remeasure_calls = 0usize;
        {
            let mut apply = |_argv: &[String]| -> Result<(), String> { Err("boom".to_owned()) };
            let mut remeasure = || -> Result<u64, String> {
                remeasure_calls += 1;
                Ok(host)
            };
            let outcome = attempt_clock_remediation(
                crate::vm_lab::VmGuestPlatform::Linux,
                host,
                guest,
                90,
                &skew_err,
                &mut apply,
                &mut remeasure,
            );
            match outcome {
                Err(msg) => {
                    assert!(msg.contains(&skew_err), "keeps the original gate text");
                    assert!(
                        msg.contains("clock remediation attempt failed: boom"),
                        "{msg}"
                    );
                    assert!(msg.contains("failing closed"), "{msg}");
                }
                Ok(()) => panic!("a failed apply must fail closed"),
            }
        }
        assert_eq!(remeasure_calls, 0, "no re-measure after a failed apply");
    }

    #[test]
    fn retry_transient_recovers_after_transient_failures() {
        // Regression (ledger 2026-07-11): a first-connection SSH transient must
        // not decide the clock probe. Fail twice, then succeed on the third
        // attempt — the value from the successful try is returned.
        let calls = std::cell::Cell::new(0u32);
        let result: Result<&str, &str> =
            retry_transient(CLOCK_PROBE_ATTEMPTS, Duration::ZERO, || {
                let n = calls.get() + 1;
                calls.set(n);
                if n < 3 {
                    Err("Operation timed out")
                } else {
                    Ok("ok")
                }
            });
        assert_eq!(result, Ok("ok"));
        assert_eq!(calls.get(), 3, "must retry until the probe succeeds");
    }

    #[test]
    fn retry_transient_returns_last_error_after_exhausting_attempts() {
        let calls = std::cell::Cell::new(0u32);
        let result: Result<&str, String> =
            retry_transient(CLOCK_PROBE_ATTEMPTS, Duration::ZERO, || {
                let n = calls.get() + 1;
                calls.set(n);
                Err(format!("timeout #{n}"))
            });
        assert_eq!(result, Err("timeout #3".to_owned()));
        assert_eq!(
            calls.get(),
            CLOCK_PROBE_ATTEMPTS,
            "must attempt exactly the configured budget before failing"
        );
    }

    #[test]
    fn retry_transient_clamps_zero_attempts_to_one() {
        let calls = std::cell::Cell::new(0u32);
        let result: Result<&str, &str> = retry_transient(0, Duration::ZERO, || {
            calls.set(calls.get() + 1);
            Err("nope")
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 1, "zero attempts clamps to exactly one try");
    }
}
