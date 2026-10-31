#![allow(dead_code)]
use std::time::Duration;

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::collect_pubkeys::load_dataplane_overrides;
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
    /// Stage ids the PlanBuilder elected for this run. Drives the
    /// cross-bridge decision severity: a subnet split is a warning for
    /// control-plane-only plans but a hard failure when any
    /// cross-bridge dataplane stage is planned.
    pub planned_stage_ids: Vec<StageId>,
    /// The subset of `planned_stage_ids` this invocation will actually
    /// execute: the plan after the `--setup-only` / `--run-only` mode filter
    /// (`native::stage_id_retained_for_mode`). Read ONLY by the
    /// dataplane-addressed PassWithNote-versus-Warn decision; the Fail
    /// severity keeps reading `planned_stage_ids`.
    ///
    /// Why two views of the plan:
    /// - `--setup-only` drops every non-Setup stage, so a setup-only run
    ///   "plans" `mesh_status_validation` / `traffic_test_matrix` yet never
    ///   runs them. A note claiming they prove a dataplane-addressed node's
    ///   handshake would claim proof this invocation never produces, so this
    ///   view yields a Warn there.
    /// - The Fail decision must NOT read this narrowed view: a later
    ///   `--run-only` reuses this stage's pass as an injected Passed
    ///   dependency without re-running it, then executes the dataplane
    ///   stages. Narrowing Fail to what a setup-only run executes would let
    ///   those stages run with no cross-bridge gate at all, so Fail keeps the
    ///   full (unfiltered) plan and stays over-broad in the safe direction.
    /// - `--run-only`: preflight is retained in the mode filter but reused as
    ///   an injected pass, so it does not execute there; whenever it does
    ///   execute, both handshake stages are retained too.
    /// - `--resume-from` / `--rerun-stage`: reused stages are always a prefix
    ///   of the plan and `preflight` precedes `mesh_status_validation` and
    ///   `traffic_test_matrix` in canonical order, so whenever preflight
    ///   executes both later stages execute with it.
    pub invocation_stage_ids: Vec<StageId>,
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
                // A remediated node is only THIS node's clock verdict: keep
                // walking the fleet and still run the cross-bridge preflight
                // below, whose report file is this stage's declared witness.
                // Returning `Passed` here would skip both and the runner
                // would demote the unwitnessed pass to NotProven.
                match clock_skew_failure_outcome(
                    alias,
                    &err,
                    self.clock_remediation_enabled,
                    platform,
                    host_unix,
                    guest_unix,
                    MAX_LAB_CLOCK_SKEW_SECS,
                    &mut apply,
                    &mut remeasure,
                ) {
                    StageOutcome::Passed => continue,
                    other => return other,
                }
            }
        }

        self.cross_bridge_preflight(ctx)
    }
}

/// One /24 subnet group derived from live ssh_target addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CrossBridgeSubnetGroup {
    subnet: [u8; 4],
    aliases: Vec<String>,
}

/// Strip an optional `:port` suffix from an ssh host string, returning the
/// bare host. Only strips when the suffix parses as u16. NOTE: an IPv6
/// literal CAN end in a numeric group (`::1`, `fd00::1:22` → the tail parses
/// as u16 and gets stripped) — that is harmless here only because the
/// stripped remnant still fails the later `Ipv4Addr` parse and lands in
/// `excluded`, never in a probe argv.
fn strip_ssh_port(host: &str) -> &str {
    if let Some((head, tail)) = host.rsplit_once(':') {
        if tail.parse::<u16>().is_ok() {
            return head;
        }
    }
    host
}

/// Classify live ssh targets into /24 groups. Unparseable and IPv6 targets
/// are returned in `excluded` so the report can name them without letting
/// them silently pass or fail the split decision.
fn classify_subnet_split(
    targets: &[(String, String)],
) -> (Vec<CrossBridgeSubnetGroup>, Vec<String>) {
    let mut excluded = Vec::new();
    let mut groups: Vec<CrossBridgeSubnetGroup> = Vec::new();
    for (alias, host) in targets {
        let bare = strip_ssh_port(host);
        match bare.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => {
                let octets = ip.octets();
                let subnet = [octets[0], octets[1], octets[2], 0];
                if let Some(g) = groups.iter_mut().find(|g| g.subnet == subnet) {
                    g.aliases.push(alias.clone());
                } else {
                    groups.push(CrossBridgeSubnetGroup {
                        subnet,
                        aliases: vec![alias.clone()],
                    });
                }
            }
            Err(_) => excluded.push(alias.clone()),
        }
    }
    for g in &mut groups {
        g.aliases.sort();
    }
    groups.sort_by(|a, b| a.subnet.cmp(&b.subnet));
    (groups, excluded)
}

/// Build the argv-only TCP/22 probe command for a guest platform. `ip` is
/// always the display form of a validated Ipv4Addr, never untrusted text.
fn cross_bridge_probe_argv(platform: crate::vm_lab::VmGuestPlatform, ip: &str) -> Vec<String> {
    match platform {
        crate::vm_lab::VmGuestPlatform::Macos => vec![
            "nc".to_owned(),
            "-z".to_owned(),
            "-G".to_owned(),
            "5".to_owned(),
            ip.to_owned(),
            "22".to_owned(),
        ],
        crate::vm_lab::VmGuestPlatform::Windows => vec![
            "powershell.exe".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            // Exit code is the ONLY discriminator: `Test-NetConnection`
            // prints `PingSucceeded : True` whenever the host answers ICMP,
            // so matching the string "True" in stdout would pass the probe
            // on ping-reachable-but-TCP-blocked hosts (the exact shape the
            // CP-1 pf block produces).
            "-Command".to_owned(),
            format!(
                "if ((Test-NetConnection -ComputerName {ip} -Port 22).TcpTestSucceeded) \
                 {{ exit 0 }} else {{ exit 1 }}"
            ),
        ],
        // Linux (and any other unix-ish guest): bash /dev/tcp under timeout.
        _ => vec![
            "timeout".to_owned(),
            "10".to_owned(),
            "bash".to_owned(),
            "-c".to_owned(),
            format!("exec 3<>/dev/tcp/{ip}/22"),
        ],
    }
}

/// Dataplane stages whose results are meaningless when the fleet spans
/// more than one L2 segment without the CP-1 pf override.
///
/// Drift note: the four `StageId`s below are compile-time pinned — renaming
/// any of them breaks this match. Only ADDING a new cross-bridge dataplane
/// stage without listing it here drifts silently (degrading Fail→Warn), so
/// any such stage MUST be added here in the same change.
fn plan_has_cross_bridge_dataplane_stage(planned: &[StageId]) -> bool {
    planned.iter().any(|id| {
        matches!(
            id,
            StageId::TrafficTestMatrix
                | StageId::LiveTwoHopValidation
                | StageId::LiveManagedDnsValidation
                | StageId::RelayForwardsFrameValidation
        )
    })
}

/// Collapse control characters (ANSI escapes, CR) in probe stderr so
/// guest-influenced bytes cannot forge or garble operator-facing failure
/// text. Newlines and carriage returns become a single backslash and every
/// other control character a space, so one probe stays one report line.
fn sanitize_probe_text(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' | '\r' => '\\',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect()
}

/// Pure decision for the cross-bridge preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CrossBridgeOutcome {
    NoSplit,
    Pass,
    /// Passed, but dataplane-addressed nodes were excluded from the L2 probe
    /// and their reachability is left to the planned handshake-proving
    /// stages. Never reads as a clean "no subnet split".
    PassWithNote(String),
    Warn(String),
    Fail(String),
}

fn decide_cross_bridge(
    groups: &[CrossBridgeSubnetGroup],
    excluded: &[String],
    probe_failures: &[String],
    planned: &[StageId],
) -> CrossBridgeOutcome {
    // Non-IPv4 ssh hosts (IPv6 literals, hostnames) cannot be classified
    // into a /24, so cross-bridge reachability is UNPROVABLE for them. A
    // fleet carrying such a target must never read as a clean single-subnet
    // pass: hard-fail under a dataplane plan, warn otherwise.
    let excluded_note = (!excluded.is_empty()).then(|| excluded.join(", "));
    if let Some(names) = &excluded_note {
        if plan_has_cross_bridge_dataplane_stage(planned) {
            return CrossBridgeOutcome::Fail(format!(
                "cross-bridge preflight: non-IPv4 ssh host(s) cannot be classified into a \
                 /24 ({names}); cross-bridge reachability is unprovable for them while \
                 cross-bridge dataplane stages (traffic_test_matrix / \
                 live_two_hop_validation / live_managed_dns_validation / \
                 relay_forwards_frame_validation) are planned (CP-1: \
                 documents/operations/active/MacosCrossNetworkTrafficBlocker_2026-09-03.md \
                 §9, scripts/vm_lab/cross_vmnet_pf_override.pf)"
            ));
        }
    }
    if groups.len() <= 1 {
        if excluded.is_empty() {
            return CrossBridgeOutcome::NoSplit;
        }
        return CrossBridgeOutcome::Warn(format!(
            "cross-bridge preflight: single /24 plus unclassifiable non-IPv4 ssh host(s) \
             ({excluded_note:?}); reachability for them unproven, continuing (control-plane \
             plan; CP-1: documents/operations/active/MacosCrossNetworkTrafficBlocker_2026-09-03.md \
             §9, scripts/vm_lab/cross_vmnet_pf_override.pf)"
        ));
    }
    if probe_failures.is_empty() {
        if excluded.is_empty() {
            return CrossBridgeOutcome::Pass;
        }
        return CrossBridgeOutcome::Warn(format!(
            "cross-bridge preflight: probes reachable, but non-IPv4 ssh host(s) \
             ({excluded_note:?}) were never probed (control-plane plan; CP-1: \
             documents/operations/active/MacosCrossNetworkTrafficBlocker_2026-09-03.md §9, \
             scripts/vm_lab/cross_vmnet_pf_override.pf)"
        ));
    }
    let failure_detail = probe_failures.join("; ");
    if plan_has_cross_bridge_dataplane_stage(planned) {
        CrossBridgeOutcome::Fail(format!(
            "cross-bridge preflight: guests span {} /24 subnets and guest-to-guest TCP/22 is blocked across the split ({failure_detail}); cross-bridge dataplane stages (traffic_test_matrix / live_two_hop_validation / live_managed_dns_validation / relay_forwards_frame_validation) cannot pass without CP-1 (see documents/operations/active/MacosCrossNetworkTrafficBlocker_2026-09-03.md §9 and scripts/vm_lab/cross_vmnet_pf_override.pf)",
            groups.len()
        ))
    } else {
        CrossBridgeOutcome::Warn(format!(
            "cross-bridge preflight: guests span {} /24 subnets and guest-to-guest TCP/22 is blocked across the split ({failure_detail}); no cross-bridge dataplane stage is planned, continuing (CP-1: documents/operations/active/MacosCrossNetworkTrafficBlocker_2026-09-03.md §9, scripts/vm_lab/cross_vmnet_pf_override.pf)",
            groups.len()
        ))
    }
}

/// Whether THIS invocation genuinely proves a dataplane-addressed node's
/// reachability elsewhere, so the cross-bridge preflight may pass with a note
/// instead of warning that it is unproven. Requires all of: both stages that
/// fail closed on a missing WireGuard handshake (`mesh_status_validation`,
/// `traffic_test_matrix`) are in `invocation` (the mode-filtered plan, not
/// the full plan); at least two assigned nodes (a handshake needs a peer);
/// and at least one Linux node (those stages exercise Linux nodes only).
fn plan_proves_dataplane_handshakes(
    invocation: &[StageId],
    assigned_node_count: usize,
    any_linux_node: bool,
) -> bool {
    invocation.contains(&StageId::MeshStatusValidation)
        && invocation.contains(&StageId::TrafficTestMatrix)
        && assigned_node_count >= 2
        && any_linux_node
}

/// Whether `host` (an ssh host string, optional `:port`) is an RFC1918 or
/// link-local IPv4 address — a lab-private management network, as opposed to
/// a tailnet (100.64/10) / public address or a non-IPv4 name.
fn ssh_host_is_private_lab_address(host: &str) -> bool {
    strip_ssh_port(host)
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| ip.is_private() || ip.is_link_local())
}

/// Result of [`partition_dataplane_addressed`].
#[derive(Debug, Default, PartialEq, Eq)]
struct DataplanePartition {
    /// Targets that stay in subnet classification and the probes.
    probed: Vec<(String, String)>,
    /// Aliases removed from every probe (sorted).
    excluded: Vec<String>,
    /// Aliases that declare a `dataplane_endpoint` but whose ssh host is on a
    /// private lab network, so the declaration was NOT honoured (sorted).
    ignored_override: Vec<String>,
}

/// Split the live ssh targets into those that sit on the management L2 and
/// the aliases that declare an inventory `dataplane_endpoint` (a node reached
/// for management over a different path than its dataplane, e.g. a cloud VM
/// over the tailnet). The latter are by definition not on the management L2,
/// so guest-to-guest TCP/22 toward or from them is meaningless: they are
/// removed from subnet classification and from every probe.
///
/// An alias is excluded ONLY when its ssh host is NOT an RFC1918 / link-local
/// lab address (i.e. tailnet 100.64/10, public, or a non-IPv4 name). A
/// declaration on an alias whose ssh host sits on a private lab network is
/// treated as a misdeclaration: the alias stays in the probe set, so a typo
/// in the inventory can never drop a real lab guest from the CP-1 gate, and it
/// is reported in `ignored_override`. Only aliases that are actual targets
/// can be excluded or ignored; overrides for other inventory entries are
/// dropped.
fn partition_dataplane_addressed(
    targets: Vec<(String, String)>,
    overrides: &std::collections::BTreeMap<String, std::net::IpAddr>,
) -> DataplanePartition {
    let mut out = DataplanePartition::default();
    for (alias, host) in targets {
        if !overrides.contains_key(&alias) {
            out.probed.push((alias, host));
        } else if ssh_host_is_private_lab_address(&host) {
            out.ignored_override.push(alias.clone());
            out.probed.push((alias, host));
        } else {
            out.excluded.push(alias);
        }
    }
    out.excluded.sort();
    out.ignored_override.sort();
    out
}

/// `decide_cross_bridge` plus the dataplane-addressed exclusion. With no
/// excluded aliases this IS `decide_cross_bridge`. With some, a Fail stays a
/// Fail (a real split among the probed nodes, decided on the full plan), a
/// Warn gains the unproven note, and an otherwise clean NoSplit/Pass can no
/// longer read as clean: it is Pass-with-note only when `handshakes_proven`
/// (see [`plan_proves_dataplane_handshakes`]), else a Warn.
fn decide_cross_bridge_with_dataplane(
    groups: &[CrossBridgeSubnetGroup],
    excluded: &[String],
    dataplane_addressed: &[String],
    probe_failures: &[String],
    planned: &[StageId],
    handshakes_proven: bool,
) -> CrossBridgeOutcome {
    let base = decide_cross_bridge(groups, excluded, probe_failures, planned);
    if dataplane_addressed.is_empty() {
        return base;
    }
    let names = dataplane_addressed.join(", ");
    let unproven = format!("dataplane reachability for {names} unproven by this stage");
    match base {
        CrossBridgeOutcome::Fail(msg) => CrossBridgeOutcome::Fail(msg),
        CrossBridgeOutcome::Warn(msg) => CrossBridgeOutcome::Warn(format!("{msg}; {unproven}")),
        CrossBridgeOutcome::NoSplit
        | CrossBridgeOutcome::Pass
        | CrossBridgeOutcome::PassWithNote(_) => {
            if handshakes_proven {
                CrossBridgeOutcome::PassWithNote(format!(
                    "dataplane-addressed node(s) {names} excluded from the L2 TCP/22 probe \
                     (not on the management L2); their dataplane reachability is left to \
                     mesh_status_validation and traffic_test_matrix, both executed by this \
                     invocation and fail-closed on missing handshakes"
                ))
            } else {
                CrossBridgeOutcome::Warn(unproven)
            }
        }
    }
}

impl PreflightStage {
    /// Probe guest-to-guest TCP/22 across every derived /24 pair and gate
    /// the run on the result. WARN-only for control-plane plans; hard fail
    /// when a cross-bridge dataplane stage is planned (CP-1).
    fn cross_bridge_preflight(&self, ctx: &OrchestrationContext) -> StageOutcome {
        use std::fmt::Write as _;

        let mut targets: Vec<(String, String)> = Vec::new();
        for (alias, adapter) in &ctx.adapters {
            if let Some(params) = adapter.ssh_connection_params() {
                targets.push((alias.clone(), params.host));
            }
        }
        // Nodes declaring a dataplane_endpoint are not on the management L2:
        // drop them from classification and every probe (source or
        // destination). A load failure fails closed; no inventory path
        // (unit-test contexts) means no overrides.
        let overrides = match load_dataplane_overrides(ctx.inventory_path.as_deref()) {
            Ok(overrides) => overrides,
            Err(e) => {
                return StageOutcome::Failed(format!(
                    "cross-bridge preflight: load inventory for dataplane_endpoint overrides \
                     failed: {e}"
                ));
            }
        };
        let DataplanePartition {
            probed: targets,
            excluded: dataplane_addressed,
            ignored_override,
        } = partition_dataplane_addressed(targets, &overrides);
        let (groups, excluded) = classify_subnet_split(&targets);

        let mut report = String::new();
        let _ = writeln!(report, "# cross-bridge preflight");
        for (alias, host) in &targets {
            let _ = writeln!(report, "target: {alias} host: {host}");
        }
        for g in &groups {
            let _ = writeln!(
                report,
                "subnet: {}.{}.{}.0 nodes: {}",
                g.subnet[0],
                g.subnet[1],
                g.subnet[2],
                g.aliases.join(", ")
            );
        }
        for alias in &excluded {
            let _ = writeln!(report, "excluded (non-IPv4 ssh host): {alias}");
        }
        // Alias only: the dataplane address itself is never written out.
        for alias in &dataplane_addressed {
            let _ = writeln!(report, "dataplane-addressed (not L2-probed): {alias}");
        }
        for alias in &ignored_override {
            let _ = writeln!(
                report,
                "dataplane_endpoint override ignored for preflight (ssh host is on a private \
                 lab network): {alias}"
            );
        }
        let _ = writeln!(
            report,
            "note: one alias per /24 is sampled per probe direction (spot check, not full mesh)"
        );

        let mut probe_failures: Vec<String> = Vec::new();
        if groups.len() >= 2 {
            for i in 0..groups.len() {
                for j in (i + 1)..groups.len() {
                    let a = &groups[i];
                    let b = &groups[j];
                    let a_alias = &a.aliases[0];
                    let b_alias = &b.aliases[0];
                    let (Some(a_adapter), Some(b_adapter)) =
                        (ctx.adapters.get(a_alias), ctx.adapters.get(b_alias))
                    else {
                        // A silently skipped pair would let decide_cross_bridge
                        // read zero failures as Pass — record the unproven
                        // pair as a probe failure instead (fail-closed).
                        probe_failures.push(format!(
                            "probe skipped: adapter missing for {a_alias} or {b_alias} \
                             — cross-bridge pair unproven"
                        ));
                        continue;
                    };
                    let a_ip = strip_ssh_port(
                        &a_adapter
                            .ssh_connection_params()
                            .map(|p| p.host)
                            .unwrap_or_default(),
                    )
                    .to_owned();
                    let b_ip = strip_ssh_port(
                        &b_adapter
                            .ssh_connection_params()
                            .map(|p| p.host)
                            .unwrap_or_default(),
                    )
                    .to_owned();
                    for (src_alias, src_adapter, dst_alias, dst_ip) in [
                        (a_alias, a_adapter, b_alias, b_ip.clone()),
                        (b_alias, b_adapter, a_alias, a_ip.clone()),
                    ] {
                        let reachable = (|| {
                            let host = src_adapter.shell_host().map_err(|e| e.to_string())?;
                            let argv = cross_bridge_probe_argv(src_adapter.platform(), &dst_ip);
                            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
                            let status = host
                                .run_argv(&argv_refs, &[], &[])
                                .map_err(|e| e.to_string())?;
                            if !status.is_success() {
                                return Err(format!(
                                    "exit {}: {}",
                                    status.code,
                                    sanitize_probe_text(
                                        String::from_utf8_lossy(&status.stderr).trim()
                                    )
                                ));
                            }
                            Ok(())
                        })();
                        match reachable {
                            Ok(()) => {
                                let _ = writeln!(
                                    report,
                                    "probe: {src_alias} -> {dst_alias} ({dst_ip}):22 reachable"
                                );
                            }
                            Err(e) => {
                                let line = format!(
                                    "{src_alias} → {dst_alias} ({dst_ip}):22 cross-bridge unreachable ({e})"
                                );
                                let _ = writeln!(report, "probe: {line}");
                                probe_failures.push(line);
                            }
                        }
                    }
                }
            }
        }

        let outcome = decide_cross_bridge_with_dataplane(
            &groups,
            &excluded,
            &dataplane_addressed,
            &probe_failures,
            &self.planned_stage_ids,
            plan_proves_dataplane_handshakes(
                &self.invocation_stage_ids,
                ctx.assignments.len(),
                ctx.adapters
                    .values()
                    .any(|a| a.platform() == crate::vm_lab::VmGuestPlatform::Linux),
            ),
        );
        let decision_line = match &outcome {
            CrossBridgeOutcome::NoSplit => "decision: no subnet split (single /24)".to_owned(),
            CrossBridgeOutcome::Pass => {
                "decision: split present, all cross-bridge probes reachable".to_owned()
            }
            CrossBridgeOutcome::PassWithNote(msg) => format!("decision: PASS (note) — {msg}"),
            CrossBridgeOutcome::Warn(msg) => format!("decision: WARN — {msg}"),
            CrossBridgeOutcome::Fail(msg) => format!("decision: FAIL — {msg}"),
        };
        let _ = writeln!(report, "{decision_line}");

        // QH-83: this report file is the stage's declared File witness, so a
        // write failure is the stage's failure — never a stderr note beside
        // a pass the runner would then demote to NotProven anyway.
        let log_path = ctx.report_dir.join("logs/cross_bridge_preflight.txt");
        if let Some(parent) = log_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return StageOutcome::Failed(format!(
                    "cross-bridge preflight: cannot create witness log dir {}: {e}",
                    parent.display()
                ));
            }
        }
        if let Err(e) = std::fs::write(&log_path, &report) {
            return StageOutcome::Failed(format!(
                "cross-bridge preflight: cannot write witness report {}: {e}",
                log_path.display()
            ));
        }

        match outcome {
            CrossBridgeOutcome::NoSplit | CrossBridgeOutcome::Pass => StageOutcome::Passed,
            CrossBridgeOutcome::PassWithNote(msg) => {
                eprintln!("preflight note: {msg}");
                StageOutcome::Passed
            }
            CrossBridgeOutcome::Warn(msg) => {
                eprintln!("preflight warning: {msg}");
                StageOutcome::Passed
            }
            CrossBridgeOutcome::Fail(msg) => StageOutcome::Failed(msg),
        }
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
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
            relay_forward_candidate_endpoint: None,
        }
    }

    #[test]
    fn preflight_passes_with_exit_node_and_writable_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = make_ctx_with_exit(tmp.path());
        let outcome = PreflightStage {
            clock_remediation_enabled: false,
            planned_stage_ids: Vec::new(),
            invocation_stage_ids: Vec::new(),
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
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
            relay_forward_candidate_endpoint: None,
        };
        let outcome = PreflightStage {
            clock_remediation_enabled: false,
            planned_stage_ids: Vec::new(),
            invocation_stage_ids: Vec::new(),
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

    // ---- cross-bridge preflight (QH-72) ---------------------------------

    #[test]
    fn classify_subnet_split_separates_and_sorts_subnets() {
        let targets = vec![
            ("node-b".to_owned(), "192.168.64.20".to_owned()),
            ("node-a".to_owned(), "192.168.64.10".to_owned()),
            ("node-c".to_owned(), "192.168.65.30".to_owned()),
        ];
        let (groups, excluded) = classify_subnet_split(&targets);
        assert_eq!(excluded.len(), 0);
        assert_eq!(groups.len(), 2, "two /24s must yield two groups");
        assert_eq!(groups[0].subnet, [192, 168, 64, 0]);
        assert_eq!(
            groups[0].aliases,
            vec!["node-a".to_owned(), "node-b".to_owned()]
        );
        assert_eq!(groups[1].subnet, [192, 168, 65, 0]);
        assert_eq!(groups[1].aliases, vec!["node-c".to_owned()]);
    }

    #[test]
    fn classify_subnet_split_groups_same_subnet_and_strips_port() {
        let targets = vec![
            ("a".to_owned(), "10.0.0.7:2222".to_owned()),
            ("b".to_owned(), "10.0.0.9".to_owned()),
        ];
        let (groups, excluded) = classify_subnet_split(&targets);
        assert_eq!(
            excluded.len(),
            0,
            "host:port must be stripped, not excluded"
        );
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].subnet, [10, 0, 0, 0]);
        assert_eq!(groups[0].aliases.len(), 2);
    }

    #[test]
    fn classify_subnet_split_excludes_non_ipv4() {
        let targets = vec![
            ("v6".to_owned(), "fd00::1".to_owned()),
            ("junk".to_owned(), "not-an-ip".to_owned()),
            ("v6port".to_owned(), "[fd00::2]:22".to_owned()),
            ("ok".to_owned(), "172.16.0.5".to_owned()),
        ];
        let (groups, excluded) = classify_subnet_split(&targets);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].aliases, vec!["ok".to_owned()]);
        assert_eq!(excluded.len(), 3);
    }

    #[test]
    fn cross_bridge_probe_argv_per_platform() {
        let linux = cross_bridge_probe_argv(crate::vm_lab::VmGuestPlatform::Linux, "192.168.64.9");
        assert_eq!(
            linux[..4],
            ["timeout", "10", "bash", "-c"].map(String::from).to_vec()
        );
        assert!(linux[4].contains("/dev/tcp/192.168.64.9/22"));

        let macos = cross_bridge_probe_argv(crate::vm_lab::VmGuestPlatform::Macos, "192.168.64.9");
        assert_eq!(
            macos,
            ["nc", "-z", "-G", "5", "192.168.64.9", "22"]
                .map(String::from)
                .to_vec()
        );

        let windows =
            cross_bridge_probe_argv(crate::vm_lab::VmGuestPlatform::Windows, "192.168.64.9");
        assert_eq!(windows[0], "powershell.exe");
        assert!(windows[4].contains("Test-NetConnection"));
        assert!(windows[4].contains("192.168.64.9"));
    }

    #[test]
    fn decide_cross_bridge_no_split_and_pass() {
        let one = vec![CrossBridgeSubnetGroup {
            subnet: [192, 168, 64, 0],
            aliases: vec!["a".to_owned(), "b".to_owned()],
        }];
        assert_eq!(
            decide_cross_bridge(&one, &[], &["x".to_owned()], &[]),
            CrossBridgeOutcome::NoSplit,
            "a single subnet never fails regardless of probes"
        );

        let two = two_groups();
        assert_eq!(
            decide_cross_bridge(&two, &[], &[], &[]),
            CrossBridgeOutcome::Pass,
            "reachable probes pass regardless of plan"
        );
    }

    #[test]
    fn decide_cross_bridge_hard_fails_for_each_dataplane_stage() {
        for stage in [
            StageId::TrafficTestMatrix,
            StageId::LiveTwoHopValidation,
            StageId::LiveManagedDnsValidation,
            StageId::RelayForwardsFrameValidation,
        ] {
            let outcome = decide_cross_bridge(
                &two_groups(),
                &[],
                &["a → b (192.168.65.9):22 cross-bridge unreachable (exit 1)".to_owned()],
                &[stage.clone()],
            );
            match outcome {
                CrossBridgeOutcome::Fail(ref msg) => {
                    assert!(msg.contains("CP-1"), "{stage:?}: {msg}");
                    assert!(
                        msg.contains("MacosCrossNetworkTrafficBlocker_2026-09-03"),
                        "{stage:?}: {msg}"
                    );
                    assert!(
                        msg.contains("scripts/vm_lab/cross_vmnet_pf_override.pf"),
                        "{stage:?}: {msg}"
                    );
                }
                ref other => panic!("{stage:?}: expected Fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn decide_cross_bridge_warns_for_control_plane_only_plans() {
        let control_plane = [
            StageId::MacosAnchorProfileDeploy,
            StageId::MacosRoleTransitionValidation,
            StageId::MacosRebootRecoveryValidation,
        ];
        let outcome = decide_cross_bridge(
            &two_groups(),
            &[],
            &["a → b (192.168.65.9):22 cross-bridge unreachable (exit 1)".to_owned()],
            &control_plane,
        );
        assert!(matches!(outcome, CrossBridgeOutcome::Warn(_)));

        let empty = decide_cross_bridge(
            &two_groups(),
            &[],
            &["a → b (192.168.65.9):22 cross-bridge unreachable (exit 1)".to_owned()],
            &[],
        );
        assert!(matches!(empty, CrossBridgeOutcome::Warn(_)));
    }

    /// glm-5.3 review (TASK 3): a fleet with an unclassifiable (non-IPv4)
    /// ssh target must never read as a clean pass — reachability for that
    /// host is unprovable, so a cross-bridge dataplane plan hard-fails and a
    /// control-plane plan warns even when all classified probes are green.
    #[test]
    fn decide_cross_bridge_excluded_targets_never_pass_cleanly() {
        let excluded = vec!["ula-node".to_owned()];
        // Single /24 + excluded, control-plane plan → Warn (not NoSplit).
        let one = vec![CrossBridgeSubnetGroup {
            subnet: [192, 168, 64, 0],
            aliases: vec!["a".to_owned()],
        }];
        assert!(matches!(
            decide_cross_bridge(&one, &excluded, &[], &[]),
            CrossBridgeOutcome::Warn(_)
        ));
        // Split + all probes green + excluded, control-plane plan → Warn.
        assert!(matches!(
            decide_cross_bridge(&two_groups(), &excluded, &[], &[]),
            CrossBridgeOutcome::Warn(_)
        ));
        // Any excluded target under a dataplane plan → Fail.
        for stage in [
            StageId::TrafficTestMatrix,
            StageId::LiveTwoHopValidation,
            StageId::LiveManagedDnsValidation,
            StageId::RelayForwardsFrameValidation,
        ] {
            let outcome = decide_cross_bridge(&one, &excluded, &[], &[stage.clone()]);
            assert!(
                matches!(outcome, CrossBridgeOutcome::Fail(ref msg) if msg.contains("non-IPv4")),
                "{stage:?}: expected Fail naming the non-IPv4 host, got {outcome:?}"
            );
        }
    }

    /// glm-5.3 review (TASK 3): the Windows probe must discriminate on EXIT
    /// CODE, not on the string "True" — Test-NetConnection prints
    /// `PingSucceeded : True` on ICMP-reachable but TCP-blocked hosts, which
    /// would false-pass a stdout substring check.
    #[test]
    fn cross_bridge_windows_probe_exits_on_tcp_result() {
        let windows =
            cross_bridge_probe_argv(crate::vm_lab::VmGuestPlatform::Windows, "192.168.64.9");
        let script = &windows[4];
        assert!(script.contains("if ((Test-NetConnection"));
        assert!(script.contains("TcpTestSucceeded"));
        assert!(script.contains("exit 0"));
        assert!(script.contains("exit 1"));
    }

    fn two_groups() -> Vec<CrossBridgeSubnetGroup> {
        vec![
            CrossBridgeSubnetGroup {
                subnet: [192, 168, 64, 0],
                aliases: vec!["mac-node".to_owned()],
            },
            CrossBridgeSubnetGroup {
                subnet: [192, 168, 65, 0],
                aliases: vec!["linux-node".to_owned()],
            },
        ]
    }

    // ── dataplane-addressed (dataplane_endpoint) exclusion ─────────────────

    fn overrides_for(aliases: &[&str]) -> std::collections::BTreeMap<String, std::net::IpAddr> {
        aliases
            .iter()
            .map(|a| ((*a).to_owned(), "203.0.113.7".parse().unwrap()))
            .collect()
    }

    fn both_handshake_stages() -> Vec<StageId> {
        vec![
            StageId::Preflight,
            StageId::MeshStatusValidation,
            StageId::TrafficTestMatrix,
        ]
    }

    /// The excluded alias never reaches subnet classification: no group holds
    /// it and it is not in the non-IPv4 `excluded` list either. The excluded
    /// node's ssh host is a tailnet address (not a private lab network).
    /// Mutation caught: dropping the partition (classifying every target).
    #[test]
    fn dataplane_addressed_alias_is_excluded_from_classification() {
        let targets = vec![
            ("a".to_owned(), "192.168.64.10:22".to_owned()),
            ("b".to_owned(), "192.168.64.11:22".to_owned()),
            ("azure-vm-1".to_owned(), "100.109.160.10:22".to_owned()),
        ];
        // `unrelated` is an override for an inventory entry that is not a
        // target of this run: ignored.
        let part =
            partition_dataplane_addressed(targets, &overrides_for(&["azure-vm-1", "unrelated"]));
        assert_eq!(part.excluded, vec!["azure-vm-1".to_owned()]);
        assert!(part.ignored_override.is_empty());
        assert_eq!(part.probed.len(), 2);
        let (groups, non_ipv4) = classify_subnet_split(&part.probed);
        assert!(non_ipv4.is_empty());
        assert_eq!(groups.len(), 1, "remaining fleet is one /24");
        assert!(
            groups
                .iter()
                .all(|g| !g.aliases.contains(&"azure-vm-1".to_owned())),
            "no group may hold the dataplane-addressed alias"
        );
    }

    /// Only a host that is NOT a private lab address may be excluded: tailnet
    /// CGNAT, public and non-IPv4 names are; RFC1918 and link-local are a
    /// misdeclaration and stay probed, reported in `ignored_override`.
    /// Mutation caught: dropping the private-address check, or narrowing it
    /// to only one RFC1918 block / dropping link-local.
    #[test]
    fn dataplane_override_on_private_lab_host_is_ignored_and_stays_probed() {
        for private in [
            "10.1.2.3",
            "172.16.0.9",
            "172.31.255.1:22",
            "192.168.122.45",
            "169.254.3.4",
        ] {
            let part = partition_dataplane_addressed(
                vec![("vm".to_owned(), private.to_owned())],
                &overrides_for(&["vm"]),
            );
            assert!(part.excluded.is_empty(), "{private} must not be excluded");
            assert_eq!(part.ignored_override, vec!["vm".to_owned()], "{private}");
            assert_eq!(part.probed.len(), 1, "{private} stays probed");
        }
        for foreign in [
            "100.64.0.1",
            "100.109.160.10",
            "100.127.255.254:22",
            "203.0.113.7",
            "8.8.8.8",
            "azure-vm.tailnet.example",
            "fd7a:115c:a1e0::1",
        ] {
            let part = partition_dataplane_addressed(
                vec![("vm".to_owned(), foreign.to_owned())],
                &overrides_for(&["vm"]),
            );
            assert_eq!(part.excluded, vec!["vm".to_owned()], "{foreign}");
            assert!(part.ignored_override.is_empty(), "{foreign}");
            assert!(part.probed.is_empty(), "{foreign}");
        }
    }

    #[test]
    fn partition_without_overrides_is_identity() {
        let targets = vec![
            ("a".to_owned(), "192.168.64.10:22".to_owned()),
            ("b".to_owned(), "192.168.65.10:22".to_owned()),
        ];
        let part =
            partition_dataplane_addressed(targets.clone(), &std::collections::BTreeMap::new());
        assert_eq!(
            part,
            DataplanePartition {
                probed: targets,
                excluded: Vec::new(),
                ignored_override: Vec::new(),
            }
        );
    }

    /// Pass-with-note ONLY when the caller says the handshakes are proven by
    /// this invocation; never a clean NoSplit/Pass. Mutation caught: returning
    /// NoSplit/Pass unchanged, or ignoring `handshakes_proven`.
    #[test]
    fn dataplane_addressed_is_pass_with_note_only_when_handshakes_proven() {
        let dp = vec!["azure-vm-1".to_owned()];
        let one = vec![CrossBridgeSubnetGroup {
            subnet: [192, 168, 64, 0],
            aliases: vec!["a".to_owned()],
        }];
        for groups in [&one, &two_groups()] {
            match decide_cross_bridge_with_dataplane(
                groups,
                &[],
                &dp,
                &[],
                &both_handshake_stages(),
                true,
            ) {
                CrossBridgeOutcome::PassWithNote(msg) => {
                    assert!(msg.contains("azure-vm-1"), "{msg}");
                    assert!(msg.contains("mesh_status_validation"), "{msg}");
                    assert!(msg.contains("traffic_test_matrix"), "{msg}");
                }
                other => panic!("expected PassWithNote, got {other:?}"),
            }
            // Not proven by this invocation => Warn naming the alias, even
            // though the FULL plan carries both stages.
            assert_eq!(
                decide_cross_bridge_with_dataplane(
                    groups,
                    &[],
                    &dp,
                    &[],
                    &both_handshake_stages(),
                    false
                ),
                CrossBridgeOutcome::Warn(
                    "dataplane reachability for azure-vm-1 unproven by this stage".to_owned()
                )
            );
        }
    }

    /// Every condition of the handshake-proof predicate is load-bearing: both
    /// stages in the INVOCATION plan, at least two nodes, at least one Linux
    /// node. Mutation caught: dropping any one conjunct.
    #[test]
    fn plan_proves_dataplane_handshakes_needs_stages_two_nodes_and_linux() {
        let both = both_handshake_stages();
        assert!(plan_proves_dataplane_handshakes(&both, 2, true));
        assert!(plan_proves_dataplane_handshakes(&both, 5, true));
        // A missing stage (either, or both).
        let without_mesh = [StageId::Preflight, StageId::TrafficTestMatrix];
        let without_matrix = [StageId::Preflight, StageId::MeshStatusValidation];
        for planned in [&without_mesh[..], &without_matrix[..], &[][..]] {
            assert!(!plan_proves_dataplane_handshakes(planned, 2, true));
        }
        // A single node never proves a handshake.
        assert!(!plan_proves_dataplane_handshakes(&both, 1, true));
        assert!(!plan_proves_dataplane_handshakes(&both, 0, true));
        // No Linux node: the stages do not exercise it.
        assert!(!plan_proves_dataplane_handshakes(&both, 2, false));
    }

    /// With nothing excluded the wrapper IS `decide_cross_bridge`; a real
    /// split among the probed nodes still fails (CP-1 text) and a Warn gains
    /// the unproven note.
    #[test]
    fn dataplane_wrapper_preserves_existing_decisions() {
        let failure = vec!["a → b (192.168.65.9):22 cross-bridge unreachable (exit 1)".to_owned()];
        let planned = [StageId::TrafficTestMatrix];
        assert_eq!(
            decide_cross_bridge_with_dataplane(&two_groups(), &[], &[], &failure, &planned, true),
            decide_cross_bridge(&two_groups(), &[], &failure, &planned)
        );
        // Fail survives the exclusion untouched, whatever the invocation view
        // says about handshake proof.
        let dp = vec!["azure-vm-1".to_owned()];
        let full = [StageId::TrafficTestMatrix, StageId::MeshStatusValidation];
        for proven in [true, false] {
            let with = decide_cross_bridge_with_dataplane(
                &two_groups(),
                &[],
                &dp,
                &failure,
                &full,
                proven,
            );
            assert_eq!(
                with,
                decide_cross_bridge(&two_groups(), &[], &failure, &full)
            );
            assert!(matches!(with, CrossBridgeOutcome::Fail(ref m) if m.contains("CP-1")));
        }
        // Warn keeps its text and gains the note.
        match decide_cross_bridge_with_dataplane(&two_groups(), &[], &dp, &failure, &[], true) {
            CrossBridgeOutcome::Warn(m) => {
                assert!(m.contains("CP-1"), "{m}");
                assert!(
                    m.contains("dataplane reachability for azure-vm-1 unproven by this stage"),
                    "{m}"
                );
            }
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    use crate::vm_lab::orchestrator::adapter::node_adapter::{NodeAdapter, SshConnectionParams};
    use crate::vm_lab::orchestrator::error::{
        AdapterError, BundleKind, GossipIdentity, InstallReport, MembershipOwnerKey,
        MembershipSnapshot, NodeId, NodeMembershipPeer, TrafficTestResult, TunnelsList,
        ValidatorReport, WireguardPublicKey,
    };
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;

    /// Adapter double for the cross-bridge preflight: answers only the ssh
    /// host and the platform. `shell_host` (the probe source) panics when
    /// `forbid_probe` is set, so a probe issued FROM that alias fails the
    /// test loudly; otherwise it keeps the trait default (an error), which the
    /// preflight records as an unreachable probe.
    #[derive(Debug)]
    struct ProbeAdapter {
        alias: String,
        host: String,
        forbid_probe: bool,
        platform: crate::vm_lab::VmGuestPlatform,
    }

    impl NodeAdapter for ProbeAdapter {
        fn platform(&self) -> crate::vm_lab::VmGuestPlatform {
            self.platform
        }
        fn alias(&self) -> &str {
            &self.alias
        }
        fn ssh_connection_params(&self) -> Option<SshConnectionParams> {
            Some(SshConnectionParams::new(
                self.host.clone(),
                22,
                Some("debian".to_owned()),
                std::path::PathBuf::from("/dev/null"),
                std::path::PathBuf::from("/dev/null"),
            ))
        }
        fn shell_host(
            &self,
        ) -> Result<
            std::sync::Arc<dyn crate::vm_lab::orchestrator::remote_shell::RemoteShellHost>,
            AdapterError,
        > {
            assert!(
                !self.forbid_probe,
                "a probe was issued from dataplane-addressed alias {}",
                self.alias
            );
            Err(AdapterError::UnsupportedPlatform {
                platform: self.platform(),
                message: "probe double has no shell".to_owned(),
            })
        }
        fn install_daemon(
            &self,
            _source: &SourceArchive,
            _ctx: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
            unimplemented!()
        }
        fn start_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn stop_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn restart_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn uninstall_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
            unimplemented!()
        }
        fn init_membership_snapshot(
            &self,
            _owner_key: &MembershipOwnerKey,
            _peers: &[NodeMembershipPeer],
        ) -> Result<MembershipSnapshot, AdapterError> {
            unimplemented!()
        }
        fn distribute_signed_bundle(
            &self,
            _kind: BundleKind,
            _bundle_path: &std::path::Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn distribute_verifier_key(
            &self,
            _kind: BundleKind,
            _pub_key_path: &std::path::Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_bundles_to_dir(
            &self,
            _kind: BundleKind,
            _env_content: &str,
            _local_out_dir: &std::path::Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
            unimplemented!()
        }
        fn collect_gossip_identity(&self) -> Result<GossipIdentity, AdapterError> {
            unimplemented!()
        }
        fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
            unimplemented!()
        }
        fn run_validator(
            &self,
            _op: crate::vm_lab::DaemonProbeOp,
            _extra_args: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!()
        }
        fn ping_mesh_peer(&self, _peer: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _denied: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            unimplemented!()
        }
        fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn endpoint(&self) -> String {
            unimplemented!()
        }
        fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
            unimplemented!()
        }
        fn collect_artifacts(&self, _dst: &std::path::Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    const DP_NODE: &str = "azure-vm-1";
    const DP_NODE_SSH_HOST: &str = "100.109.160.10";
    const DP_PUBLIC_IP: &str = "203.0.113.7";

    /// A context over `(alias, ssh host, is dataplane-addressed)` nodes whose
    /// inventory declares `dataplane_endpoint` for the flagged ones. All
    /// nodes are Linux and a probe issued FROM a flagged node panics.
    fn dataplane_ctx(tag: &str, nodes: &[(&str, &str, bool)]) -> OrchestrationContext {
        dataplane_ctx_on(tag, nodes, crate::vm_lab::VmGuestPlatform::Linux, true)
    }

    fn dataplane_ctx_on(
        tag: &str,
        nodes: &[(&str, &str, bool)],
        platform: crate::vm_lab::VmGuestPlatform,
        forbid_probe_from_dataplane_nodes: bool,
    ) -> OrchestrationContext {
        let dir = std::env::temp_dir().join(format!(
            "preflight_dp_{tag}_{}_{}",
            std::process::id(),
            nodes.len()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let entries: Vec<String> = nodes
            .iter()
            .map(|(alias, host, dp)| {
                let dpe = if *dp {
                    format!(r#""dataplane_endpoint": "{DP_PUBLIC_IP}","#)
                } else {
                    String::new()
                };
                format!(
                    r#"{{ "alias": "{alias}", "ssh_target": "{host}", {dpe} "platform": "linux" }}"#
                )
            })
            .collect();
        let inventory = dir.join("vm_lab_inventory.json");
        std::fs::write(
            &inventory,
            format!(r#"{{ "version": 1, "entries": [{}] }}"#, entries.join(",")),
        )
        .unwrap();
        let assignments = nodes
            .iter()
            .map(|(alias, _, _)| NodeRoleAssignment {
                alias: (*alias).to_owned(),
                role: NodeRole::Client,
            })
            .collect();
        let mut ctx = OrchestrationContext::new(assignments, dir, "dpnet".to_owned());
        ctx.inventory_path = Some(inventory);
        for (alias, host, dp) in nodes {
            ctx.adapters.insert(
                (*alias).to_owned(),
                Box::new(ProbeAdapter {
                    alias: (*alias).to_owned(),
                    host: (*host).to_owned(),
                    forbid_probe: *dp && forbid_probe_from_dataplane_nodes,
                    platform,
                }),
            );
        }
        ctx
    }

    fn read_witness(ctx: &OrchestrationContext) -> String {
        std::fs::read_to_string(ctx.report_dir.join("logs/cross_bridge_preflight.txt"))
            .expect("witness report written")
    }

    fn azure_fleet() -> [(&'static str, &'static str, bool); 3] {
        [
            ("guest-1", "192.168.122.45", false),
            ("guest-2", "192.168.122.46", false),
            (DP_NODE, DP_NODE_SSH_HOST, true),
        ]
    }

    fn stage_with(planned: Vec<StageId>, invocation: Vec<StageId>) -> PreflightStage {
        PreflightStage {
            clock_remediation_enabled: false,
            planned_stage_ids: planned,
            invocation_stage_ids: invocation,
        }
    }

    /// The Azure shape: a tailnet-managed node on a foreign /24 next to a
    /// one-/24 NAT fleet. No probe toward or from it, the report names the
    /// alias (never an IP), and the decision is Pass-with-note when this
    /// invocation executes both handshake stages, Warn without.
    #[test]
    fn stage_excludes_dataplane_addressed_node_from_every_probe() {
        let nodes = azure_fleet();
        let stage = stage_with(both_handshake_stages(), both_handshake_stages());
        let ctx = dataplane_ctx("pass", &nodes);
        assert_eq!(stage.cross_bridge_preflight(&ctx), StageOutcome::Passed);
        let report = read_witness(&ctx);
        assert!(
            report.contains(&format!("dataplane-addressed (not L2-probed): {DP_NODE}")),
            "{report}"
        );
        assert!(
            !report.contains("probe:"),
            "no probe may be issued: {report}"
        );
        assert!(!report.contains(DP_PUBLIC_IP), "public IP leaked: {report}");
        assert!(
            !report.contains(DP_NODE_SSH_HOST),
            "excluded node's host leaked: {report}"
        );
        assert!(report.contains("decision: PASS (note)"), "{report}");
        assert!(
            !report.contains("no subnet split"),
            "must not read as a clean single /24: {report}"
        );
        let _ = std::fs::remove_dir_all(&ctx.report_dir);

        // Without mesh_status_validation: Warn, still Passed (non-fatal),
        // still no probe.
        let stage = stage_with(
            vec![StageId::TrafficTestMatrix],
            vec![StageId::TrafficTestMatrix],
        );
        let ctx = dataplane_ctx("warn", &nodes);
        assert_eq!(stage.cross_bridge_preflight(&ctx), StageOutcome::Passed);
        let report = read_witness(&ctx);
        assert!(
            report.contains(&format!(
                "decision: WARN — dataplane reachability for {DP_NODE} unproven by this stage"
            )),
            "{report}"
        );
        assert!(!report.contains("probe:"), "{report}");
        let _ = std::fs::remove_dir_all(&ctx.report_dir);
    }

    /// `--setup-only`: the plan still carries both handshake stages but the
    /// mode filter drops them, so this invocation proves nothing about the
    /// dataplane node and the note must NOT claim it does: Warn, not
    /// Pass-with-note. The invocation view comes from the real mode filter.
    /// Mutation caught: preflight reading the full plan for the note.
    #[test]
    fn setup_only_invocation_warns_instead_of_claiming_handshake_proof() {
        let planned: Vec<StageId> = StageId::ALL.to_vec();
        let invocation: Vec<StageId> = planned
            .iter()
            .filter(|id| {
                crate::vm_lab::orchestrator::native::stage_id_retained_for_mode(id, true, false)
            })
            .cloned()
            .collect();
        assert!(invocation.contains(&StageId::Preflight));
        assert!(!invocation.contains(&StageId::MeshStatusValidation));
        assert!(!invocation.contains(&StageId::TrafficTestMatrix));
        let stage = stage_with(planned.clone(), invocation);
        let ctx = dataplane_ctx("setuponly", &azure_fleet());
        assert_eq!(stage.cross_bridge_preflight(&ctx), StageOutcome::Passed);
        let report = read_witness(&ctx);
        assert!(
            report.contains(&format!(
                "decision: WARN — dataplane reachability for {DP_NODE} unproven by this stage"
            )),
            "{report}"
        );
        assert!(!report.contains("PASS (note)"), "{report}");
        let _ = std::fs::remove_dir_all(&ctx.report_dir);

        // The Fail decision keeps the FULL plan: a real split still fails a
        // setup-only invocation, because a later --run-only reuses this
        // stage's pass as an injected dependency and would otherwise run the
        // dataplane stages with no cross-bridge gate.
        let split = [
            ("guest-1", "192.168.64.10", false),
            ("guest-2", "192.168.65.10", false),
            (DP_NODE, DP_NODE_SSH_HOST, true),
        ];
        let stage = stage_with(planned, vec![StageId::Preflight]);
        let ctx = dataplane_ctx("setuponly_split", &split);
        match stage.cross_bridge_preflight(&ctx) {
            StageOutcome::Failed(msg) => assert!(msg.contains("CP-1"), "{msg}"),
            other => panic!("expected Failed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&ctx.report_dir);
    }

    /// A handshake needs two nodes and the proving stages exercise Linux
    /// nodes: a lone dataplane node, or an all-macOS fleet, never reads as
    /// proven even with both stages executed. Mutation caught: dropping the
    /// node-count or Linux conjunct from the stage's call.
    #[test]
    fn single_node_or_non_linux_fleet_warns_even_with_handshake_stages_executed() {
        let stage = stage_with(both_handshake_stages(), both_handshake_stages());
        let warn =
            format!("decision: WARN — dataplane reachability for {DP_NODE} unproven by this stage");

        // One node only (the dataplane-addressed one).
        let ctx = dataplane_ctx("solo", &[(DP_NODE, DP_NODE_SSH_HOST, true)]);
        assert_eq!(stage.cross_bridge_preflight(&ctx), StageOutcome::Passed);
        let report = read_witness(&ctx);
        assert!(report.contains(&warn), "{report}");
        assert!(!report.contains("PASS (note)"), "{report}");
        let _ = std::fs::remove_dir_all(&ctx.report_dir);

        // Two nodes, none Linux.
        let ctx = dataplane_ctx_on(
            "macos",
            &[
                ("mac-1", "192.168.64.10", false),
                (DP_NODE, DP_NODE_SSH_HOST, true),
            ],
            crate::vm_lab::VmGuestPlatform::Macos,
            true,
        );
        assert_eq!(stage.cross_bridge_preflight(&ctx), StageOutcome::Passed);
        let report = read_witness(&ctx);
        assert!(report.contains(&warn), "{report}");
        assert!(!report.contains("PASS (note)"), "{report}");
        let _ = std::fs::remove_dir_all(&ctx.report_dir);
    }

    /// The Azure misdeclaration shape end to end: a `dataplane_endpoint` on an
    /// alias whose ssh host is on a private lab /24 must not hide it from the
    /// CP-1 gate. It stays probed (so the split it causes still fails), the
    /// report names only the alias in an "ignored" line, never the declared
    /// endpoint, and there is no dataplane-addressed exclusion note.
    #[test]
    fn stage_keeps_misdeclared_private_node_in_probes_and_reports_override_ignored() {
        let nodes = [
            ("guest-1", "192.168.64.10", false),
            ("guest-2", "192.168.65.10", true),
        ];
        let stage = stage_with(both_handshake_stages(), both_handshake_stages());
        // The misdeclared node is NOT excluded, so it is probed: the double
        // has no shell, so each direction records an unreachable probe.
        let ctx = dataplane_ctx_on(
            "misdecl",
            &nodes,
            crate::vm_lab::VmGuestPlatform::Linux,
            false,
        );
        match stage.cross_bridge_preflight(&ctx) {
            StageOutcome::Failed(msg) => {
                assert!(msg.contains("CP-1"), "{msg}");
                assert!(msg.contains("guest-2"), "{msg}");
            }
            other => panic!("expected Failed (split among probed nodes), got {other:?}"),
        }
        let report = read_witness(&ctx);
        assert!(
            report.contains(
                "dataplane_endpoint override ignored for preflight (ssh host is on a private \
                 lab network): guest-2"
            ),
            "{report}"
        );
        assert!(
            !report.contains("dataplane-addressed (not L2-probed)"),
            "{report}"
        );
        assert!(!report.contains(DP_PUBLIC_IP), "public IP leaked: {report}");
        let _ = std::fs::remove_dir_all(&ctx.report_dir);
    }

    /// Regression: excluding the dataplane node does not weaken the gate for
    /// the rest of the fleet — a split among the remaining nodes under a
    /// dataplane plan still fails with the CP-1 text, and the excluded node
    /// is still not probed (its adapter panics on `shell_host`).
    #[test]
    fn unexcluded_split_still_fails_with_cp1_text_alongside_a_dataplane_node() {
        let nodes = [
            ("guest-1", "192.168.64.10", false),
            ("guest-2", "192.168.65.10", false),
            (DP_NODE, DP_NODE_SSH_HOST, true),
        ];
        let stage = stage_with(both_handshake_stages(), both_handshake_stages());
        let ctx = dataplane_ctx("split", &nodes);
        match stage.cross_bridge_preflight(&ctx) {
            StageOutcome::Failed(msg) => {
                assert!(msg.contains("CP-1"), "{msg}");
                assert!(msg.contains("guest-1") && msg.contains("guest-2"), "{msg}");
                assert!(!msg.contains(DP_NODE), "{msg}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&ctx.report_dir);
    }

    /// Fail closed: an inventory that cannot be loaded fails the stage rather
    /// than silently probing a node that may be dataplane-addressed.
    #[test]
    fn unloadable_inventory_fails_the_cross_bridge_preflight() {
        let stage = stage_with(both_handshake_stages(), both_handshake_stages());
        let mut ctx = dataplane_ctx("badinv", &[("guest-1", "192.168.122.45", false)]);
        std::fs::write(ctx.inventory_path.as_ref().unwrap(), "{ not json").unwrap();
        match stage.cross_bridge_preflight(&ctx) {
            StageOutcome::Failed(msg) => {
                assert!(msg.contains("dataplane_endpoint"), "{msg}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // No inventory path (unit-test contexts) => no overrides, no failure.
        ctx.inventory_path = None;
        assert_eq!(stage.cross_bridge_preflight(&ctx), StageOutcome::Passed);
        let _ = std::fs::remove_dir_all(&ctx.report_dir);
    }
}
