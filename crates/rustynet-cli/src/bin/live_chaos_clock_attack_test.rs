#![forbid(unsafe_code)]
// Track B Phase 28 transition: still calls the deprecated `capture_root`
// shim (via `live_lab_bin_support`). Phase 29 rewrites onto the new
// `RemoteShellHost` trait. Allow until then so `-D warnings` passes — this
// mirrors `live_chaos_daemon_fault_test.rs`, the live-injection template.
#![allow(deprecated)]

//! Live-lab chaos stage: per-process clock-attack adversarial sweep.
//!
//! Converts the former `chaos_clock_attack` scaffold (which called the inert
//! `live_chaos_support::run_category` and touched no host) into a real proof of
//! SecurityMinimumBar §4 ("Enforce anti-replay and rollback protection where
//! state freshness matters") against a running daemon whose **wall clock is
//! surgically manipulated per-process** via `libfaketime`
//! (`LD_PRELOAD=<libfaketime.so.1>` + `FAKETIME=...`). Only the daemon process
//! sees the faked clock — there is no global VM clock change, so SSH, systemd,
//! and the orchestrator clock are untouched (research F15).
//!
//! Stages (TUF freeze/rollback/skew-tolerance defenses):
//!   * `chaos_clock_jump_forward_past_max_age` — jump the daemon clock PAST a
//!     signed bundle's max-age (Phase A): a +90-day faked clock puts the
//!     on-disk state BEHIND the daemon's clock, so the daemon correctly
//!     classifies it STALE/expired — never future-dated — and fails closed:
//!     `restricted_safe_mode=true`, `state=FailClosed`, a bootstrap error
//!     naming staleness, or a refused start. The future-dated rejection
//!     counters must stay at baseline (any rise would be a misclassification
//!     defect). Phase B: after the faketime drop-in is removed and the clock
//!     resyncs, the daemon must clear the restriction, recover within the
//!     deadline, and hold `membership_epoch >= ` the real-clock baseline
//!     (freeze defense, F10).
//!   * `chaos_clock_jump_backward_past_replay_window` — jump the daemon clock
//!     BACKWARD beyond the replay watermark window. Under a backward jump the
//!     daemon clock sits BEHIND the on-disk artifacts, so future-dated
//!     rejection IS the primary assertion; a stale (superseded-epoch) bundle
//!     must also be rejected, and the replay watermark (`membership_epoch`)
//!     must NOT regress when measured POST-RECOVERY against the real-clock
//!     baseline (rollback defense, F8).
//!   * `chaos_clock_skew_slow_drift` — drift within accepted skew is tolerated
//!     (no spurious rejection, daemon stays proven); out-of-window drift fails
//!     closed (F16).
//!
//! Methodology + report shape mirror `live_chaos_daemon_fault_test.rs` (the
//! closest real live-injection template): SSH host seam via
//! `live_lab_bin_support`, a `key=value` remote-script protocol parsed into an
//! observation struct, a pure per-stage verdict evaluator, and the same JSON
//! report shape the run-matrix tooling ingests. `--dry-run` keeps the inert
//! scaffold path (`run_category`) so the orchestrator's scaffold-validation
//! call is byte-for-byte unchanged.

mod live_chaos_support;
mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_chaos_support::{ChaosConfig, ChaosStage, git_head_commit, repo_root, run_category};
use live_lab_bin_support::{
    Logger, REMOTE_RUSTYNET_BIN, capture_root, ensure_pinned_known_hosts_file, ensure_safe_token,
    load_home_known_hosts_path, shell_quote, unix_now, verify_sudo, wait_for_daemon_socket,
    write_file,
};
use serde_json::{Value, json};

const CATEGORY: &str = "chaos_clock_attack";
const DEFAULT_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
const DEFAULT_SERVICE_NAME: &str = "rustynetd.service";
const DEFAULT_RECOVERY_DEADLINE_SECS: u64 = 180;
const MAX_RECOVERY_DEADLINE_SECS: u64 = 900;

/// Guest-side wall-clock bound for ONE `rustynet status` round trip inside
/// the remote script — the same bound as the host-side shared readiness
/// probe (`live_lab_bin_support::DAEMON_STATUS_PROBE_TIMEOUT_SECS`, guest
/// coreutils `timeout`): a daemon that accepts but never answers must
/// consume one attempt (`timeout` kills it with exit 124) instead of
/// hanging the whole stage on the CLI's unbounded Unix IPC read.
const REMOTE_STATUS_PROBE_TIMEOUT_SECS: &str = "15";

// REVIEW(W5-A): default libfaketime shared-object path. On Debian/Ubuntu lab
// guests the package `libfaketime` installs the preload object at
// `/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1`. This is overridable
// via `--faketime-lib <path>` so the operator can point at the actual location
// on a given guest (e.g. `/usr/lib/faketime/libfaketime.so.1` on some distros,
// or an aarch64 multiarch dir). The remote script ALSO refuses to inject if the
// path is not a readable file on the guest, so a wrong default fails closed
// (never silently runs the daemon with a real clock and reports a fake pass).
const DEFAULT_FAKETIME_LIB: &str = "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1";

/// Default forward jump (seconds) for the freeze-defense stage. 90 days is far
/// past any signed-state max-age / TTL the daemon enforces, so the live state
/// is unambiguously future-dated/expired under the faked clock.
const DEFAULT_FORWARD_JUMP_SECS: u64 = 90 * 24 * 60 * 60;
/// Default backward jump (seconds) for the rollback-defense stage. 90 days back
/// is well beyond the replay watermark window.
const DEFAULT_BACKWARD_JUMP_SECS: u64 = 90 * 24 * 60 * 60;
/// Default within-window skew (seconds) for the tolerated leg of the drift
/// stage. Must stay under the daemon's accepted clock-skew tolerance.
const DEFAULT_TOLERATED_SKEW_SECS: u64 = 30;
/// Default out-of-window skew (seconds) for the fail-closed leg of the drift
/// stage. Must exceed the accepted clock-skew tolerance.
const DEFAULT_EXCESS_SKEW_SECS: u64 = 24 * 60 * 60;

/// Which declared stage this invocation injects. The orchestrator selects one
/// stage per live run (mirroring `--fault-mode` in the daemon-fault template);
/// the other two stay `skipped` in the report. Defaults to `JumpForward`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ClockStage {
    #[default]
    JumpForward,
    JumpBackward,
    SlowDrift,
}

impl ClockStage {
    /// Index into [`clock_attack_stages`] for this stage.
    fn stage_index(self) -> usize {
        match self {
            ClockStage::JumpForward => 0,
            ClockStage::JumpBackward => 1,
            ClockStage::SlowDrift => 2,
        }
    }
}

fn clock_attack_stages() -> Vec<ChaosStage> {
    vec![
        ChaosStage {
            name: "chaos_clock_jump_forward_past_max_age",
            fault: "jump host clock beyond signed-state max age",
            pass_criterion: "Phase A: under the forward jump the daemon fails closed (restricted_safe_mode + FailClosed + stale-naming bootstrap error, or refuses to start) with no future-dated misclassification; Phase B: recovers within the deadline, restriction cleared, epoch holds post-recovery",
            recovery_deadline_secs: 180,
        },
        ChaosStage {
            name: "chaos_clock_jump_backward_past_replay_window",
            fault: "jump clock backward beyond replay watermark window",
            pass_criterion: "future-dated bundles are rejected (primary), stale state is rejected, and the replay watermark holds post-recovery",
            recovery_deadline_secs: 180,
        },
        ChaosStage {
            name: "chaos_clock_skew_slow_drift",
            fault: "slowly drift clock past accepted skew",
            pass_criterion: "within-window drift is tolerated; out-of-window drift fails closed",
            recovery_deadline_secs: 900,
        },
    ]
}

#[derive(Clone, Debug)]
struct Config {
    report_path: PathBuf,
    log_path: PathBuf,
    git_commit: String,
    dry_run: bool,
    target_host: Option<String>,
    ssh_identity_file: Option<PathBuf>,
    known_hosts_file: Option<PathBuf>,
    socket_path: String,
    service_name: String,
    faketime_lib: String,
    stage: ClockStage,
    forward_jump_secs: u64,
    backward_jump_secs: u64,
    tolerated_skew_secs: u64,
    excess_skew_secs: u64,
    recovery_deadline_secs: u64,
}

impl Config {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let root = repo_root()?;
        let mut config = Self {
            report_path: root.join(format!("artifacts/phase10/{CATEGORY}_report.json")),
            log_path: root.join(format!("artifacts/phase10/source/{CATEGORY}.log")),
            git_commit: env::var("RUSTYNET_EXPECTED_GIT_COMMIT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| git_head_commit(&root)),
            dry_run: false,
            target_host: None,
            ssh_identity_file: None,
            known_hosts_file: None,
            socket_path: DEFAULT_SOCKET_PATH.to_owned(),
            service_name: DEFAULT_SERVICE_NAME.to_owned(),
            faketime_lib: DEFAULT_FAKETIME_LIB.to_owned(),
            stage: ClockStage::default(),
            forward_jump_secs: DEFAULT_FORWARD_JUMP_SECS,
            backward_jump_secs: DEFAULT_BACKWARD_JUMP_SECS,
            tolerated_skew_secs: DEFAULT_TOLERATED_SKEW_SECS,
            excess_skew_secs: DEFAULT_EXCESS_SKEW_SECS,
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
        };

        let args = args.into_iter().collect::<Vec<_>>();
        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--dry-run" => config.dry_run = true,
                "--report-path" => {
                    idx += 1;
                    config.report_path =
                        PathBuf::from(required_value(&args, idx, "--report-path")?);
                }
                "--log-path" => {
                    idx += 1;
                    config.log_path = PathBuf::from(required_value(&args, idx, "--log-path")?);
                }
                "--git-commit" => {
                    idx += 1;
                    config.git_commit = required_value(&args, idx, "--git-commit")?;
                }
                "--target-host" => {
                    idx += 1;
                    config.target_host = Some(required_value(&args, idx, "--target-host")?);
                }
                "--ssh-identity-file" => {
                    idx += 1;
                    config.ssh_identity_file = Some(PathBuf::from(required_value(
                        &args,
                        idx,
                        "--ssh-identity-file",
                    )?));
                }
                "--known-hosts-file" | "--known-hosts" => {
                    idx += 1;
                    config.known_hosts_file = Some(PathBuf::from(required_value(
                        &args,
                        idx,
                        "--known-hosts-file",
                    )?));
                }
                "--socket-path" => {
                    idx += 1;
                    config.socket_path = required_value(&args, idx, "--socket-path")?;
                }
                "--service-name" => {
                    idx += 1;
                    config.service_name = required_value(&args, idx, "--service-name")?;
                }
                "--faketime-lib" => {
                    idx += 1;
                    config.faketime_lib = required_value(&args, idx, "--faketime-lib")?;
                }
                "--stage" => {
                    idx += 1;
                    config.stage = parse_stage(&required_value(&args, idx, "--stage")?)?;
                }
                "--forward-jump-secs" => {
                    idx += 1;
                    config.forward_jump_secs = parse_u64(&args, idx, "--forward-jump-secs")?;
                }
                "--backward-jump-secs" => {
                    idx += 1;
                    config.backward_jump_secs = parse_u64(&args, idx, "--backward-jump-secs")?;
                }
                "--tolerated-skew-secs" => {
                    idx += 1;
                    config.tolerated_skew_secs = parse_u64(&args, idx, "--tolerated-skew-secs")?;
                }
                "--excess-skew-secs" => {
                    idx += 1;
                    config.excess_skew_secs = parse_u64(&args, idx, "--excess-skew-secs")?;
                }
                "--recovery-deadline-secs" => {
                    idx += 1;
                    config.recovery_deadline_secs =
                        parse_u64(&args, idx, "--recovery-deadline-secs")?;
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    print_usage();
                    return Err(format!("unknown argument: {other}"));
                }
            }
            idx += 1;
        }

        config.validate()?;
        Ok(config)
    }

    fn validate(&mut self) -> Result<(), String> {
        ensure_safe_token("socket path", &self.socket_path)?;
        ensure_safe_token("service name", &self.service_name)?;
        ensure_safe_token("faketime lib", &self.faketime_lib)?;
        if self.recovery_deadline_secs == 0
            || self.recovery_deadline_secs > MAX_RECOVERY_DEADLINE_SECS
        {
            return Err(format!(
                "recovery deadline must be 1..={MAX_RECOVERY_DEADLINE_SECS} seconds"
            ));
        }
        if self.forward_jump_secs == 0 {
            return Err("--forward-jump-secs must be greater than zero".to_owned());
        }
        if self.backward_jump_secs == 0 {
            return Err("--backward-jump-secs must be greater than zero".to_owned());
        }
        if self.tolerated_skew_secs == 0 {
            return Err("--tolerated-skew-secs must be greater than zero".to_owned());
        }
        if self.excess_skew_secs <= self.tolerated_skew_secs {
            return Err(
                "--excess-skew-secs must exceed --tolerated-skew-secs so the out-of-window leg \
                 is genuinely past the accepted skew"
                    .to_owned(),
            );
        }
        if self.dry_run {
            return Ok(());
        }
        let Some(target_host) = self.target_host.as_deref() else {
            return Err("--target-host is required unless --dry-run is set".to_owned());
        };
        ensure_safe_token("target host", target_host)?;
        let Some(identity) = self.ssh_identity_file.as_deref() else {
            return Err("--ssh-identity-file is required unless --dry-run is set".to_owned());
        };
        if !identity.is_file() {
            return Err(format!("identity file not found: {}", identity.display()));
        }
        if self.known_hosts_file.is_none() {
            self.known_hosts_file = Some(load_home_known_hosts_path()?);
        }
        let known_hosts = self
            .known_hosts_file
            .as_deref()
            .ok_or_else(|| "known_hosts file is required".to_owned())?;
        ensure_pinned_known_hosts_file(known_hosts)?;
        Ok(())
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse(env::args().skip(1))?;
    if config.dry_run {
        // Preserve the orchestrator's scaffold-validation contract exactly:
        // the inert `run_category` dry-run path writes the standard report
        // with overall_status "skipped" and mutates no host.
        return run_category(ChaosConfig {
            category: CATEGORY,
            report_path: config.report_path,
            log_path: config.log_path,
            dry_run: true,
            git_commit: config.git_commit,
            stages: clock_attack_stages(),
        });
    }

    let mut logger = Logger::new(&config.log_path)?;
    logger.line("[chaos-clock-attack] starting live per-process clock-attack injection")?;
    let report = run_live_clock_attack(&config, &mut logger)?;
    write_file(
        &config.report_path,
        &serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialise clock attack report failed: {err}"))?,
    )?;
    logger.line(
        format!(
            "[chaos-clock-attack] report written to {}",
            config.report_path.display()
        )
        .as_str(),
    )?;

    let overall_status = report
        .get("overall_status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if overall_status == "pass" || overall_status == "skipped" {
        // b30: a declared precondition skip (overall_status "skipped" with
        // a recorded skip_reason) is an acceptable outcome: nothing ran on
        // the host and the report is the evidence. Anything else that is
        // not a pass fails the stage.
        Ok(())
    } else {
        Err("clock attack chaos stage failed".to_owned())
    }
}

fn run_live_clock_attack(config: &Config, logger: &mut Logger) -> Result<Value, String> {
    let target = required_option(config.target_host.as_deref(), "--target-host")?;
    let identity = required_path(config.ssh_identity_file.as_deref(), "--ssh-identity-file")?;
    let known_hosts = required_path(config.known_hosts_file.as_deref(), "--known-hosts-file")?;

    logger.line("[chaos-clock-attack] verifying sudo and baseline daemon socket")?;
    verify_sudo(identity, known_hosts, target)?;
    wait_for_daemon_socket(identity, known_hosts, target, &config.socket_path, 10, 2)?;

    let fault_script = render_remote_clock_script(config);
    logger.line(
        format!(
            "[chaos-clock-attack] injecting stage {:?} via libfaketime drop-in on {}",
            config.stage, config.service_name
        )
        .as_str(),
    )?;
    let output = capture_root(identity, known_hosts, target, &fault_script)?;
    logger.block(output.as_str())?;

    let observation = ClockStageObservation::parse(&output)?;
    Ok(render_live_report(config, &observation))
}

/// Build the `FAKETIME` value for a relative jump. libfaketime accepts a signed
/// relative offset of the form `+<secs>s` / `-<secs>s`, interpreted against the
/// real clock. We pin to whole seconds so the value is deterministic and
/// parser-safe. Pure so it is unit-testable.
fn faketime_offset_spec(forward: bool, secs: u64) -> String {
    if forward {
        format!("+{secs}s")
    } else {
        format!("-{secs}s")
    }
}

/// Render the per-stage remote script. ARGV-only host invocation is preserved
/// by `capture_root` (it wraps the body in `sudo -n sh -lc <single-quoted>`);
/// every interpolated value is either an integer constant or passed through
/// `shell_quote`, and no untrusted value reaches the shell unquoted. The script
/// registers teardown (drop-in removal + daemon restart) via `trap cleanup
/// EXIT` BEFORE the fault, so the daemon is never left running under a faked
/// clock on any abort path.
fn render_remote_clock_script(config: &Config) -> String {
    let remote_rustynet_bin = shell_quote(REMOTE_RUSTYNET_BIN);
    let probe_timeout = REMOTE_STATUS_PROBE_TIMEOUT_SECS;
    let service = shell_quote(&config.service_name);
    let socket_path = shell_quote(&config.socket_path);
    let faketime_lib = shell_quote(&config.faketime_lib);
    let deadline = config.recovery_deadline_secs;

    // Per-stage FAKETIME spec(s) and the stage marker emitted in the output.
    let (stage_marker, primary_spec, secondary_spec) = match config.stage {
        ClockStage::JumpForward => (
            "chaos_clock_jump_forward_past_max_age",
            faketime_offset_spec(true, config.forward_jump_secs),
            None,
        ),
        ClockStage::JumpBackward => (
            "chaos_clock_jump_backward_past_replay_window",
            faketime_offset_spec(false, config.backward_jump_secs),
            None,
        ),
        ClockStage::SlowDrift => (
            "chaos_clock_skew_slow_drift",
            faketime_offset_spec(true, config.tolerated_skew_secs),
            Some(faketime_offset_spec(true, config.excess_skew_secs)),
        ),
    };
    let stage_marker_q = shell_quote(stage_marker);
    let primary_spec_q = shell_quote(&primary_spec);

    // The common preamble: validate the faketime object, register teardown,
    // capture the baseline epoch + rejection counters. `status_field` reads a
    // single `key=value` token out of the canonical daemon status line.
    let preamble = format!(
        r#"set -eu
# RSA-0080: a non-login shell omits the sbin directories where tc/ip/systemctl live.
PATH="/usr/local/sbin:/usr/sbin:/sbin:${{PATH:-/usr/local/bin:/usr/bin:/bin}}"; export PATH
service={service}
socket_path={socket_path}
faketime_lib={faketime_lib}
deadline={deadline}
stage_marker={stage_marker_q}
drop_in_dir="/run/systemd/system/${{service}}.d"
drop_in_file="$drop_in_dir/zz-chaos-clock-attack.conf"
# Diagnostics channel for the bounded status probes: the LAST `rustynet
# status` attempt's exit status + stderr, folded to one line. Written by
# status_field (command substitutions run in subshells, so variables do not
# propagate) and printed into the stage log at the points where an
# unsampleable status decides a verdict. Report-only evidence — never a
# verdict input.
status_diag_file=""
printf 'stage=%s\n' "$stage_marker"
command -v systemctl >/dev/null 2>&1 || {{ printf 'missing_systemctl=true\n'; exit 1; }}
# b30 (live 2026-09-27, EL lab guest): libfaketime is OPTIONAL on EL
# bootstrap (EPEL deliberately not enabled), so a guest without it is a
# supported state. The injection must then be a declared precondition skip:
# print the marker + precise reason and exit ZERO, BEFORE any teardown
# registration or service mutation. The pre-fix `exit 1` made capture_root
# error out and the bin crashed without writing any report at all.
if ! test -r "$faketime_lib"; then
  printf 'faketime_lib_present=false\n'
  printf 'precondition_skip=libfaketime shared object not readable at %s on this guest; the lab bootstrap treats libfaketime as optional on EL (EPEL not enabled, ADR-027), so the chaos clock-attack stage cannot inject a clock fault here\n' "$faketime_lib"
  exit 0
fi
printf 'faketime_lib_present=true\n'
cleanup() {{
  rm -f "$drop_in_file" >/dev/null 2>&1 || true
  rmdir "$drop_in_dir" >/dev/null 2>&1 || true
  rm -f "$status_diag_file" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  # A daemon that refused to start under the fault has tripped the unit's
  # start limit; clear it or this restart is refused and the exit stays
  # down for every later stage (live 2026-09-10, lenovo-bot).
  systemctl reset-failed "$service" >/dev/null 2>&1 || true
  systemctl restart "$service" >/dev/null 2>&1 || true
}}
trap cleanup EXIT HUP INT TERM
printf 'teardown_registered_before_fault=true\n'
systemctl is-active --quiet "$service" || {{ printf 'baseline_service_active=false\n'; exit 1; }}
test -S "$socket_path" || {{ printf 'baseline_socket_present=false\n'; exit 1; }}
# Diagnostics file for the status probes (created after the skip/refusal
# exits so a skipped run leaves nothing behind; removed by the EXIT trap).
status_diag_file="$(mktemp /tmp/rustynet-clock-status-diag.XXXXXX)"
# One `key=value` token out of the canonical daemon status line, read via a
# TIMEOUT-BOUNDED IPC round trip with the attempt's exit status + stderr
# folded into "$status_diag_file" for the stage log. The old form piped an
# UNBOUNDED `rustynet status 2>/dev/null`: a refused endpoint, a wedged
# daemon and a token-less answer were indistinguishable (all empty), a
# wedged daemon could hang the whole stage on the CLI's unbounded IPC read,
# and 180 s of empty samples were unexplainable after the fact
# (katana-xnet-403/-703/-709/-733/-734, fingerprint 9044e3ed661a). The
# `timeout` bound matches the host-side shared probe
# (live_lab_bin_support::DAEMON_STATUS_PROBE_TIMEOUT_SECS); exit 124 = the
# daemon accepted but never answered. `status_field` always exits 0 — the
# field value is EMPTY when the sample failed (fail-closed at the verdict),
# and the WHY lives in the diagnostics line.
status_field() {{
  status_raw="$(timeout {probe_timeout} env RUSTYNET_DAEMON_SOCKET="$socket_path" {remote_rustynet_bin} status 2>"$status_diag_file")" && probe_rc=0 || probe_rc=$?
  printf 'rc=%s stderr=%s\n' "$probe_rc" "$(tr '\n' '|' <"$status_diag_file" | cut -c1-300)" > "$status_diag_file"
  printf '%s' "$status_raw" | tr ' ' '\n' \
    | awk -F= -v k="$1" '$1==k {{ print $2; exit }}'
}}
baseline_epoch="$(status_field membership_epoch)"
# An unsampleable baseline stays EMPTY (never 0): the daemon never emits 0,
# and the post-recovery non-regression check must fail on an unverifiable
# baseline rather than degrade to `recovered >= 0`.
case "$baseline_epoch" in *[!0-9]*) baseline_epoch="" ;; esac
baseline_future_rej="$(status_field traversal_future_dated_rejections)"
case "$baseline_future_rej" in ''|*[!0-9]*) baseline_future_rej=0 ;; esac
baseline_stale_rej="$(status_field traversal_stale_rejections)"
case "$baseline_stale_rej" in ''|*[!0-9]*) baseline_stale_rej=0 ;; esac
baseline_dns_future_rej="$(status_field dns_future_dated_rejections)"
case "$baseline_dns_future_rej" in ''|*[!0-9]*) baseline_dns_future_rej=0 ;; esac
baseline_dns_stale_rej="$(status_field dns_stale_rejections)"
case "$baseline_dns_stale_rej" in ''|*[!0-9]*) baseline_dns_stale_rej=0 ;; esac
baseline_replay_rej="$(status_field traversal_replay_rejections)"
case "$baseline_replay_rej" in ''|*[!0-9]*) baseline_replay_rej=0 ;; esac
printf 'baseline_epoch=%s\n' "$baseline_epoch"
printf 'baseline_future_rej=%s\n' "$baseline_future_rej"
printf 'baseline_stale_rej=%s\n' "$baseline_stale_rej"
printf 'baseline_dns_future_rej=%s\n' "$baseline_dns_future_rej"
printf 'baseline_dns_stale_rej=%s\n' "$baseline_dns_stale_rej"
printf 'baseline_replay_rej=%s\n' "$baseline_replay_rej"
install_faketime() {{
  mkdir -p "$drop_in_dir"
  {{
    printf '[Service]\n'
    printf 'Environment=LD_PRELOAD=%s\n' "$faketime_lib"
    printf 'Environment=FAKETIME=%s\n' "$1"
    printf 'Environment=FAKETIME_DONT_FAKE_MONOTONIC=1\n'
  }} > "$drop_in_file"
  systemctl daemon-reload
  systemctl reset-failed "$service" >/dev/null 2>&1 || true
  # The restart may legitimately FAIL: a daemon that refuses to come up
  # under the injected clock is an observation (fail-closed at start),
  # not a script error — record it instead of aborting under `set -e`.
  # `systemctl restart` returning 0 only means the start job was queued;
  # a daemon that refuses the injected clock exits a moment later (live
  # 2026-09-11: "trust preflight failed: trust evidence is stale", exit 65).
  # Judge the unit's state after a settle, not the restart's exit code.
  restart_rc=0
  systemctl restart "$service" 2>"$status_diag_file" || restart_rc=$?
  printf 'started_restart_diag=rc=%s stderr=%s\n' "$restart_rc" "$(tr '\n' '|' <"$status_diag_file" | cut -c1-300)"
  sleep 5
  # Started means "answers ONE bounded status IPC under the fault" — the same
  # oracle as recovery (fingerprint 9044e3ed661a; katana-xnet-843: is-active +
  # the lingering socket FILE read started=true at 5 s while every IPC call in
  # the same run hit rc=70, forcing the started-form of the verdict onto
  # evidence that could never be sampled). The attempt's rc+stderr land in the
  # diagnostics channel so the WHY survives the later status_field overwrites.
  started_probe_rc=0
  timeout {probe_timeout} env RUSTYNET_DAEMON_SOCKET="$socket_path" {remote_rustynet_bin} status 2>"$status_diag_file" >/dev/null || started_probe_rc=$?
  if [ "$started_probe_rc" -eq 0 ]; then
    printf 'daemon_started_under_fault=true\n'
  else
    printf 'daemon_started_under_fault=false\n'
  fi
  printf 'started_diag=rc=%s stderr=%s\n' "$started_probe_rc" "$(tr '\n' '|' <"$status_diag_file" | cut -c1-300)"
}}
remove_faketime() {{
  rm -f "$drop_in_file" >/dev/null 2>&1 || true
  rmdir "$drop_in_dir" >/dev/null 2>&1 || true
  systemctl daemon-reload
  systemctl reset-failed "$service" >/dev/null 2>&1 || true
  remove_restart_rc=0
  systemctl restart "$service" 2>"$status_diag_file" || remove_restart_rc=$?
  printf 'remove_restart_diag=rc=%s stderr=%s\n' "$remove_restart_rc" "$(tr '\n' '|' <"$status_diag_file" | cut -c1-300)"
}}
# Recovery readiness is ONE completed IPC round trip against the daemon
# socket — the same criterion as the host-side shared readiness probe
# (live_lab_bin_support::daemon_status_probe_body / wait_for_daemon_socket,
# which the pre-injection baseline wait already uses) — never
# `systemctl is-active` + `test -S`: the OLD socket file lingers on disk
# after a restart until the new daemon binds, so the unit+file check
# declared recovered=true at 0 s while every IPC call still hit
# `connect … refused` for the whole 180 s window (katana-xnet-148 first
# observed the lingering file; xnet-403/-703/-709/-733/-734 fingerprint
# 9044e3ed661a turned it into 7 stage failures). The guest coreutils
# `timeout` bounds one attempt (exit 124 = accepted but never answered) so
# a wedged daemon consumes attempts instead of hanging the stage. Called
# directly (not in a subshell), so its probe_* variables propagate.
daemon_answers_status() {{
  probe_stderr="$(timeout {probe_timeout} env RUSTYNET_DAEMON_SOCKET="$socket_path" {remote_rustynet_bin} status 2>&1 >/dev/null)" && probe_rc=0 || probe_rc=$?
  probe_diag="rc=$probe_rc stderr=$(printf '%s' "$probe_stderr" | tr '\n' '|' | cut -c1-300)"
  [ "$probe_rc" -eq 0 ]
}}
# Fold a refused/failed start's WHY into ONE line: the unit's StatusText
# plus its last 20 journal lines. The status IPC is empty exactly when the
# daemon is down (katana-xnet-1068: recovered_diag_probe rc=70 with empty
# stderr for the whole window), so this is the only evidence channel left
# for a bootstrap-staleness naming. Report-only — never a verdict input.
refusal_text() {{
  rt_status="$(systemctl show "$service" -p StatusText --value 2>/dev/null || true)"
  rt_journal="$(journalctl -u "$service" -n 20 --no-pager 2>/dev/null || true)"
  printf '%s\n%s\n' "$rt_status" "$rt_journal" | tr '\n' '|' | cut -c1-600
}}
# Does a refusal text NAME staleness? Same vocabulary the live daemon emits
# (2026-09-11: "trust preflight failed: trust evidence is stale";
# rustynetd windows_mesh_status: "state snapshot is stale: age=...s exceeds
# max_age=...s").
staleness_named() {{
  case "$1" in
    *"stale"*|*"expired"*|*"max_age"*|*"max-age"*) return 0 ;;
    *) return 1 ;;
  esac
}}
wait_recovered() {{
  # start_unix is set by the CALLER at the true fault-clear instant —
  # immediately BEFORE remove_faketime's daemon-reload+restart latency —
  # and must never be reset here (katana-xnet-1068: resetting inside the
  # function started the measured window AFTER the restart latency, so a
  # recovery landing within the deadline was structurally recorded at
  # deadline+1). The := default only keeps the function standalone-safe.
  : "${{start_unix:=$(date +%s)}}"
  recovered=false
  end_unix="$((start_unix + deadline))"
  while [ "$(date +%s)" -le "$end_unix" ]; do
    if daemon_answers_status; then
      recovered=true
      break
    fi
    sleep 1
  done
  printf 'measured_recovery_secs=%s\n' "$(( $(date +%s) - start_unix ))"
  printf 'recovered=%s\n' "$recovered"
  # Report-only: names the structural expiry of the wait window — when
  # recovered=false the loop ran to end_unix and measured_recovery_secs
  # lands at deadline+1 BY LOOP STRUCTURE, not because recovery was one
  # second slow. Never a verdict input.
  if [ "$recovered" = true ]; then
    printf 'recovery_wait_expired=false\n'
  else
    printf 'recovery_wait_expired=true\n'
  fi
  # Evidence for the stage log — why the last readiness attempt concluded
  # what it did, plus the unit state and the socket FILE presence at that
  # moment. Report-only: a probe failure here means recovered=false (the
  # verdict stays fail-closed), it never gates anything by itself.
  printf 'recovered_diag_probe=%s\n' "$probe_diag"
  printf 'recovered_diag_unit=%s\n' "$(systemctl is-active "$service" 2>/dev/null || true)/$(systemctl show "$service" -p SubState --value 2>/dev/null || true)"
  printf 'recovered_diag_socket_file=%s\n' "$([ -S "$socket_path" ] && echo present || echo absent)"
  # Report-only WHY for a recovery failure (katana-xnet-849/-853: 181 s of
  # rc=70 stderr= with the refusal text left unread in the unit journal).
  if [ "$recovered" != true ]; then
    printf 'recovery_journal_tail=%s\n' "$(journalctl -u "$service" -n 40 --no-pager 2>/dev/null | tr '\n' '|' | cut -c1-2000)"
  fi
}}
"#
    );

    // Per-stage fault body. Each emits the verdict-relevant `key=value` lines
    // the Rust evaluator parses.
    let body = match config.stage {
        // Freeze defense, Phase A: jump the daemon clock far forward. A +90-day
        // faked clock puts the on-disk signed state BEHIND the daemon's clock,
        // so the FutureDated arms (generated_at > now + skew) can never fire;
        // what fires is Stale/Expired and the snapshot load is REFUSED. The
        // verdict therefore asserts the daemon's own fail-closed posture —
        // restricted_safe_mode, state, the staleness-naming bootstrap error —
        // plus that the future-dated counters do NOT move (a rise would be a
        // misclassification defect), never the future-dated counter itself.
        // Under the fault membership_epoch renders `none` (snapshot refused),
        // so it is reported raw and the anti-rollback comparison is made
        // POST-RECOVERY against the real-clock baseline (Phase B).
        ClockStage::JumpForward => format!(
            r#"printf 'fault_spec=%s\n' {primary_spec_q}
install_faketime {primary_spec_q}
# Give the daemon a reconcile cycle under the faked clock.
sleep 20
post_epoch="$(status_field membership_epoch)"
printf 'post_epoch=%s\n' "$post_epoch"
post_future_rej="$(status_field traversal_future_dated_rejections)"
case "$post_future_rej" in ''|*[!0-9]*) post_future_rej="$baseline_future_rej" ;; esac
post_dns_future_rej="$(status_field dns_future_dated_rejections)"
case "$post_dns_future_rej" in ''|*[!0-9]*) post_dns_future_rej="$baseline_dns_future_rej" ;; esac
post_stale_rej="$(status_field traversal_stale_rejections)"
case "$post_stale_rej" in ''|*[!0-9]*) post_stale_rej="$baseline_stale_rej" ;; esac
post_dns_stale_rej="$(status_field dns_stale_rejections)"
case "$post_dns_stale_rej" in ''|*[!0-9]*) post_dns_stale_rej="$baseline_dns_stale_rej" ;; esac
printf 'post_future_rej=%s\n' "$post_future_rej"
printf 'post_dns_future_rej=%s\n' "$post_dns_future_rej"
printf 'post_stale_rej=%s\n' "$post_stale_rej"
printf 'post_dns_stale_rej=%s\n' "$post_dns_stale_rej"
post_restricted="$(status_field restricted_safe_mode)"
post_state="$(status_field state)"
printf 'post_restricted=%s\n' "$post_restricted"
printf 'post_state=%s\n' "$post_state"
# status_field's awk truncates each token at the first space, so the
# multi-word bootstrap_error text can only be matched against the full
# status line. The round trip is the same timeout-bounded, stderr-capturing
# form as status_field (a daemon wedged accept-but-never-answer consumes the
# attempt with exit 124 instead of hanging the stage on the CLI's unbounded
# IPC read): an unsampleable status (refused start, timeout) leaves
# full_status empty and this false — fail-closed at the verdict, with the
# refused-start case accepted via daemon_started_under_fault=false. The
# attempt's rc+stderr land in the diagnostics channel and are printed
# immediately as bootstrap_status_diag so the WHY survives the later
# status_field overwrites of the channel. Report-only evidence, never a
# verdict input.
full_status="$(timeout {probe_timeout} env RUSTYNET_DAEMON_SOCKET="$socket_path" {remote_rustynet_bin} status 2>"$status_diag_file")" && bootstrap_probe_rc=0 || bootstrap_probe_rc=$?
printf 'rc=%s stderr=%s\n' "$bootstrap_probe_rc" "$(tr '\n' '|' <"$status_diag_file" | cut -c1-300)" > "$status_diag_file"
printf 'bootstrap_status_diag=%s\n' "$(cat "$status_diag_file")"
bootstrap_error_names_staleness=false
case "$full_status" in *"is stale"*|*"expired"*) bootstrap_error_names_staleness=true ;; esac
# When the daemon refused to start under the fault the status IPC is EMPTY
# and the case above saw no text at all: the flag would stay false purely
# from absence of evidence (katana-xnet-1068: bootstrap_status_diag
# rc=70 stderr= empty for the whole window). Consult the unit itself
# (StatusText + journal via refusal_text) and re-derive the flag from that
# text. fault_refusal_text is report-only evidence; the FLAG is printed
# ONCE, after recovery, so the parser sees a single line.
if [ "$bootstrap_error_names_staleness" = false ] && [ -z "$full_status" ]; then
  fault_refusal_text="$(refusal_text)"
  if staleness_named "$fault_refusal_text"; then
    bootstrap_error_names_staleness=true
  fi
  if [ -n "$fault_refusal_text" ]; then
    printf 'fault_refusal_text=%s\n' "$fault_refusal_text"
  fi
fi
snapshot_refused=false
if [ "$post_restricted" = "true" ] || ! systemctl is-active --quiet "$service"; then
  snapshot_refused=true
fi
printf 'snapshot_refused_under_fault=%s\n' "$snapshot_refused"
# Unsampleable counters (refused start) cannot have moved, so they compare
# equal to baseline: "unchanged" is vacuously true when the daemon never
# came up, and strictly compared when it did.
future_rejections_unchanged=false
if [ "$post_future_rej" = "$baseline_future_rej" ] && [ "$post_dns_future_rej" = "$baseline_dns_future_rej" ]; then
  future_rejections_unchanged=true
fi
printf 'future_rejections_unchanged=%s\n' "$future_rejections_unchanged"
# REPORT-ONLY (live f760df74: the stale counters stayed flat even though the
# code should increment them on the first status poll) — never gated.
stale_rejection_observed=false
if [ "$post_stale_rej" -gt "$baseline_stale_rej" ] || [ "$post_dns_stale_rej" -gt "$baseline_dns_stale_rej" ]; then
  stale_rejection_observed=true
fi
printf 'stale_rejection_observed=%s\n' "$stale_rejection_observed"
# Evidence that no dataplane ran under the fault (FailClosed posture). An
# unsampleable status is UNKNOWN, never "live": the verdict then rests on
# the refused-start form alone.
case "$post_state" in
  '') path_live_proven=none ;;
  FailClosed) path_live_proven=false ;;
  *) path_live_proven=true ;;
esac
printf 'path_live_proven=%s\n' "$path_live_proven"
# t0 = the true fault-clear instant: BEFORE remove_faketime's
# daemon-reload+restart latency, so the measured window is pure recovery
# time (katana-xnet-1068: the reset inside wait_recovered recorded the
# restart latency against the deadline, structurally measuring deadline+1).
start_unix="$(date +%s)"
remove_faketime
wait_recovered
# Recovery window expired without ONE completed IPC round trip: capture the
# unit's WHY now (the daemon may be refusing the RE-start for a staleness
# reason) and, if the Phase-A flag never got evidence, derive it from this
# text too. The flag prints ONCE here so the parser sees a single line.
if [ "$recovered" = false ]; then
  deadline_refusal_text="$(refusal_text)"
  if [ "$bootstrap_error_names_staleness" = false ]; then
    if staleness_named "$deadline_refusal_text"; then
      bootstrap_error_names_staleness=true
    fi
  fi
  if [ -n "$deadline_refusal_text" ]; then
    printf 'deadline_refusal_text=%s\n' "$deadline_refusal_text"
  fi
fi
printf 'bootstrap_error_names_staleness=%s\n' "$bootstrap_error_names_staleness"
# Socket-up precedes bootstrap-complete by seconds (live 2026-09-11: the
# epoch read `none` when sampled at the instant the socket appeared). Poll
# until the daemon reports a numeric epoch and an unrestricted posture, or
# the deadline, before judging recovery.
recovered_epoch=none
recovered_restricted=""
sample_end_unix="$((start_unix + deadline))"
while :; do
  recovered_epoch="$(status_field membership_epoch)"
  case "$recovered_epoch" in ''|*[!0-9]*) recovered_epoch=none ;; esac
  recovered_restricted="$(status_field restricted_safe_mode)"
  if [ "$recovered_epoch" != none ] && [ "$recovered_restricted" = "false" ]; then break; fi
  [ "$(date +%s)" -ge "$sample_end_unix" ] && break
  sleep 2
done
# The LAST status sample's exit status + stderr — the WHY behind an
# unsampleable recovery (refused vs wedged vs token-less answer).
# Report-only evidence, printed unconditionally so a pass carries it too.
printf 'status_diag=%s\n' "$(cat "$status_diag_file" 2>/dev/null || true)"
printf 'recovered_epoch=%s\n' "$recovered_epoch"
printf 'recovered_restricted=%s\n' "$recovered_restricted"
if [ "$recovered_restricted" = "false" ]; then
  printf 'recovered_proven=true\n'
else
  printf 'recovered_proven=false\n'
fi
# Phase B epoch non-regression, measured POST-RECOVERY: a non-numeric
# recovered epoch is a FAIL (never coerced to 0), and a genuine watermark
# downgrade surfaces as recovered_epoch < baseline_epoch.
epoch_not_regressed=false
case "$recovered_epoch" in
  ''|*[!0-9]*|none) : ;;
  *)
    case "$baseline_epoch" in
      ''|*[!0-9]*) : ;;   # unverifiable baseline must FAIL, never degrade to 0
      *) [ "$recovered_epoch" -ge "$baseline_epoch" ] && epoch_not_regressed=true ;;
    esac
    ;;
esac
printf 'epoch_not_regressed=%s\n' "$epoch_not_regressed"
"#
        ),
        // Rollback defense: jump the daemon clock far backward. Unlike the
        // forward leg, a backward jump puts the daemon clock BEHIND the
        // on-disk signed artifacts, so the FutureDated classification fires
        // correctly: the future-dated rejection counters are the PRIMARY
        // assertion here. A stale (superseded-epoch) bundle must also be
        // rejected, and the replay watermark must not regress when measured
        // POST-RECOVERY against the real-clock baseline.
        ClockStage::JumpBackward => format!(
            r#"printf 'fault_spec=%s\n' {primary_spec_q}
install_faketime {primary_spec_q}
sleep 20
post_epoch="$(status_field membership_epoch)"
printf 'post_epoch=%s\n' "$post_epoch"
post_future_rej="$(status_field traversal_future_dated_rejections)"
case "$post_future_rej" in ''|*[!0-9]*) post_future_rej=0 ;; esac
post_dns_future_rej="$(status_field dns_future_dated_rejections)"
case "$post_dns_future_rej" in ''|*[!0-9]*) post_dns_future_rej=0 ;; esac
post_stale_rej="$(status_field traversal_stale_rejections)"
case "$post_stale_rej" in ''|*[!0-9]*) post_stale_rej=0 ;; esac
post_replay_rej="$(status_field traversal_replay_rejections)"
case "$post_replay_rej" in ''|*[!0-9]*) post_replay_rej=0 ;; esac
printf 'post_future_rej=%s\n' "$post_future_rej"
printf 'post_dns_future_rej=%s\n' "$post_dns_future_rej"
printf 'post_stale_rej=%s\n' "$post_stale_rej"
printf 'post_replay_rej=%s\n' "$post_replay_rej"
if [ "$post_future_rej" -gt "$baseline_future_rej" ] || [ "$post_dns_future_rej" -gt "$baseline_dns_future_rej" ]; then
  printf 'future_dated_rejected=true\n'
else
  printf 'future_dated_rejected=false\n'
fi
if [ "$post_stale_rej" -gt "$baseline_stale_rej" ] || [ "$post_replay_rej" -gt "$baseline_replay_rej" ]; then
  printf 'stale_state_rejected=true\n'
else
  printf 'stale_state_rejected=false\n'
fi
# t0 = the true fault-clear instant (see the jump-forward hoist; the
# measured window must exclude the remove_faketime restart latency).
start_unix="$(date +%s)"
remove_faketime
wait_recovered
recovered_epoch="$(status_field membership_epoch)"
case "$recovered_epoch" in ''|*[!0-9]*) recovered_epoch=none ;; esac
printf 'status_diag=%s\n' "$(cat "$status_diag_file" 2>/dev/null || true)"
printf 'recovered_epoch=%s\n' "$recovered_epoch"
epoch_not_regressed=false
case "$recovered_epoch" in
  ''|*[!0-9]*|none) : ;;
  *)
    case "$baseline_epoch" in
      ''|*[!0-9]*) : ;;   # unverifiable baseline must FAIL, never degrade to 0
      *) [ "$recovered_epoch" -ge "$baseline_epoch" ] && epoch_not_regressed=true ;;
    esac
    ;;
esac
printf 'epoch_not_regressed=%s\n' "$epoch_not_regressed"
"#
        ),
        // Skew tolerance: within-window drift must be tolerated (no spurious
        // rejection, daemon stays active + socket present), then out-of-window
        // drift must fail closed (rejections rise / state not accepted). The
        // `secondary_spec` is the excess (out-of-window) FAKETIME value.
        ClockStage::SlowDrift => {
            let secondary_spec = secondary_spec.expect("slow-drift stage has a secondary spec");
            let secondary_spec_q = shell_quote(&secondary_spec);
            format!(
                r#"printf 'fault_spec=%s\n' {primary_spec_q}
printf 'excess_spec=%s\n' {secondary_spec_q}
# Leg 1: within accepted skew -- must be tolerated.
install_faketime {primary_spec_q}
sleep 20
tol_future_rej="$(status_field traversal_future_dated_rejections)"
case "$tol_future_rej" in ''|*[!0-9]*) tol_future_rej=0 ;; esac
if systemctl is-active --quiet "$service" && [ -S "$socket_path" ] && [ "$tol_future_rej" -le "$baseline_future_rej" ]; then
  printf 'within_window_tolerated=true\n'
else
  printf 'within_window_tolerated=false\n'
fi
printf 'tolerated_future_rej=%s\n' "$tol_future_rej"
# Leg 2: out of accepted skew -- must fail closed.
install_faketime {secondary_spec_q}
sleep 20
excess_future_rej="$(status_field traversal_future_dated_rejections)"
case "$excess_future_rej" in ''|*[!0-9]*) excess_future_rej=0 ;; esac
excess_stale_rej="$(status_field traversal_stale_rejections)"
case "$excess_stale_rej" in ''|*[!0-9]*) excess_stale_rej=0 ;; esac
printf 'excess_future_rej=%s\n' "$excess_future_rej"
printf 'excess_stale_rej=%s\n' "$excess_stale_rej"
if [ "$excess_future_rej" -gt "$tol_future_rej" ] || [ "$excess_stale_rej" -gt "$baseline_stale_rej" ]; then
  printf 'out_of_window_failed_closed=true\n'
else
  printf 'out_of_window_failed_closed=false\n'
fi
post_epoch="$(status_field membership_epoch)"
case "$post_epoch" in ''|*[!0-9]*) post_epoch=0 ;; esac
printf 'post_epoch=%s\n' "$post_epoch"
printf 'status_diag=%s\n' "$(cat "$status_diag_file" 2>/dev/null || true)"
if [ "$post_epoch" -ge "$baseline_epoch" ]; then
  printf 'epoch_not_regressed=true\n'
else
  printf 'epoch_not_regressed=false\n'
fi
# t0 = the true fault-clear instant (see the jump-forward hoist; the
# measured window must exclude the remove_faketime restart latency).
start_unix="$(date +%s)"
remove_faketime
wait_recovered
"#
            )
        }
    };

    format!("{preamble}{body}")
}

/// Parsed `key=value` observation emitted by the per-stage remote script. All
/// verdict fields are `Option` because the stages emit disjoint subsets; the
/// per-stage verdict evaluators require exactly the fields their stage emits,
/// so a missing field for the active stage is a FAIL (never-run / unverifiable
/// injection), never a fake-pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ClockStageObservation {
    stage: Option<String>,
    teardown_registered_before_fault: bool,
    faketime_lib_present: bool,
    /// b30: precise reason printed by the remote script when the injection
    /// is skipped as a precondition failure (e.g. libfaketime absent on an
    /// EL guest whose bootstrap treats it as optional). When set, the fault
    /// fields below were never produced: nothing ran on the host.
    precondition_skip: Option<String>,
    recovered: bool,
    measured_recovery_secs: Option<u64>,
    /// Did `rustynetd` come up at all under the injected clock? `false` is
    /// a fail-closed-at-start observation, distinct from "came up and
    /// rejected stale state" (live 2026-09-10: +90 days → refused to start).
    daemon_started_under_fault: Option<bool>,
    /// Backward leg only: did the future-dated rejection counters rise under
    /// the backward jump (primary assertion — a backward clock sits BEHIND the
    /// on-disk artifacts, so FutureDated fires correctly)?
    future_dated_rejected: Option<bool>,
    /// Forward leg, Phase A: did the daemon fail closed under the fault —
    /// `restricted_safe_mode=true` or the service inactive (refused start)?
    snapshot_refused_under_fault: Option<bool>,
    /// Forward leg, Phase A: does the daemon's bootstrap error name staleness
    /// ("is stale" / "expired")? Accepted in place of the refused-start form.
    bootstrap_error_names_staleness: Option<bool>,
    /// Forward leg, Phase A: did the future-dated counters stay at baseline
    /// (a rise would mean the daemon MISCLASSIFIED stale state as future)?
    future_rejections_unchanged: Option<bool>,
    /// Forward leg, Phase A, REPORT-ONLY (never gated; live f760df74 showed
    /// the stale counters flat despite the code intending otherwise).
    stale_rejection_observed: Option<bool>,
    /// Forward leg, Phase A, evidence that no dataplane ran under the fault
    /// (`state=FailClosed` ⇒ false).
    path_live_proven: Option<bool>,
    /// Phase B: is the post-recovery restriction cleared
    /// (`restricted_safe_mode=false`)?
    recovered_proven: Option<bool>,
    /// Post-recovery `membership_epoch` (`none` while refused ⇒ `None`).
    recovered_epoch: Option<u64>,
    stale_state_rejected: Option<bool>,
    epoch_not_regressed: Option<bool>,
    within_window_tolerated: Option<bool>,
    out_of_window_failed_closed: Option<bool>,
    /// REPORT-ONLY recovery diagnostics (fingerprint 9044e3ed661a: the old
    /// oracle left a 180 s unsampleable window unexplainable): the last
    /// readiness round trip's `rc=<n> stderr=<folded>` line, the unit state
    /// and the socket FILE presence at the moment `wait_recovered` ended,
    /// and the last status sample's `rc=<n> stderr=<folded>` line. Evidence
    /// only — never a verdict input.
    recovered_diag_probe: Option<String>,
    recovered_diag_unit: Option<String>,
    recovered_diag_socket_file: Option<String>,
    status_diag: Option<String>,
    /// REPORT-ONLY (glm-review-chaos-clock-oracle-2-1 MEDIUM-1): the Phase-A
    /// bootstrap-staleness probe's `rc=<n> stderr=<folded>` line, printed at
    /// the probe site so it survives the later `status_field` overwrites of
    /// the diagnostics channel. Evidence only — never a verdict input.
    bootstrap_status_diag: Option<String>,
    /// REPORT-ONLY (katana-xnet-1068 near-miss): true when `wait_recovered`
    /// ran to the end of its window without one completed IPC round trip
    /// (recovered=false ⇒ measured_recovery_secs lands at deadline+1 by
    /// loop structure). Names the expiry instead of disguising it as
    /// latency. Never a verdict input.
    recovery_wait_expired: Option<bool>,
    /// REPORT-ONLY WHY captured UNDER the fault when the status IPC was
    /// empty (refused start): the unit's StatusText + last journal lines,
    /// folded to one line via `refusal_text`. When this text names
    /// staleness it re-derives `bootstrap_error_names_staleness` (the old
    /// code left the flag false purely from absence of evidence).
    fault_refusal_text: Option<String>,
    /// REPORT-ONLY WHY captured after the recovery window expired without
    /// recovery (recovered=false): the same channel, re-deriving the flag
    /// the same way when it never got evidence. Never a verdict input.
    deadline_refusal_text: Option<String>,
}

impl ClockStageObservation {
    fn parse(output: &str) -> Result<Self, String> {
        let value = |key: &str| -> Option<&str> {
            output.lines().find_map(|line| {
                line.split_once('=')
                    .and_then(|(found, value)| (found.trim() == key).then_some(value.trim()))
            })
        };
        let opt_bool = |key: &str| -> Result<Option<bool>, String> {
            match value(key) {
                Some("true") => Ok(Some(true)),
                Some("false") => Ok(Some(false)),
                // The script writes `none` when the datum could not be sampled
                // (e.g. status unanswerable under the fault): unknown, never a
                // verdict either way.
                Some("none") => Ok(None),
                Some(other) => Err(format!("invalid boolean for {key}: {other}")),
                None => Ok(None),
            }
        };
        let req_bool = |key: &str| -> Result<bool, String> {
            match value(key) {
                Some("true") => Ok(true),
                Some("false") => Ok(false),
                Some(other) => Err(format!("invalid boolean for {key}: {other}")),
                None => Err(format!("missing {key} in clock attack output")),
            }
        };
        let opt_u64 = |key: &str| -> Result<Option<u64>, String> {
            match value(key) {
                Some(raw) => raw
                    .parse::<u64>()
                    .map(Some)
                    .map_err(|err| format!("invalid integer for {key}: {err}")),
                None => Ok(None),
            }
        };
        let opt_string = |key: &str| -> Option<String> { value(key).map(str::to_owned) };
        // b30: a declared precondition skip exits the remote script before
        // the fault fields exist. Only stage, faketime_lib_present and the
        // skip reason are guaranteed; demanding the required fault booleans
        // here would crash the bin on a parse error instead of reporting
        // the skip (the pre-fix behaviour).
        let precondition_skip = value("precondition_skip").map(str::to_owned);
        if let Some(reason) = precondition_skip {
            return Ok(Self {
                stage: value("stage").map(str::to_owned),
                faketime_lib_present: req_bool("faketime_lib_present")?,
                precondition_skip: Some(reason),
                ..Self::default()
            });
        }
        Ok(Self {
            stage: value("stage").map(str::to_owned),
            teardown_registered_before_fault: req_bool("teardown_registered_before_fault")?,
            faketime_lib_present: req_bool("faketime_lib_present")?,
            precondition_skip: None,
            recovered: req_bool("recovered")?,
            measured_recovery_secs: opt_u64("measured_recovery_secs")?,
            daemon_started_under_fault: opt_bool("daemon_started_under_fault")?,
            future_dated_rejected: opt_bool("future_dated_rejected")?,
            snapshot_refused_under_fault: opt_bool("snapshot_refused_under_fault")?,
            bootstrap_error_names_staleness: opt_bool("bootstrap_error_names_staleness")?,
            future_rejections_unchanged: opt_bool("future_rejections_unchanged")?,
            stale_rejection_observed: opt_bool("stale_rejection_observed")?,
            path_live_proven: opt_bool("path_live_proven")?,
            recovered_proven: opt_bool("recovered_proven")?,
            // `none` is the daemon's own rendering of a refused snapshot
            // (membership_state absent) — parsed as absent, never coerced to 0.
            recovered_epoch: match value("recovered_epoch") {
                Some(raw) if raw != "none" && !raw.is_empty() => Some(
                    raw.parse::<u64>()
                        .map_err(|err| format!("invalid integer for recovered_epoch: {err}"))?,
                ),
                _ => None,
            },
            stale_state_rejected: opt_bool("stale_state_rejected")?,
            epoch_not_regressed: opt_bool("epoch_not_regressed")?,
            within_window_tolerated: opt_bool("within_window_tolerated")?,
            out_of_window_failed_closed: opt_bool("out_of_window_failed_closed")?,
            recovered_diag_probe: opt_string("recovered_diag_probe"),
            recovered_diag_unit: opt_string("recovered_diag_unit"),
            recovered_diag_socket_file: opt_string("recovered_diag_socket_file"),
            status_diag: opt_string("status_diag"),
            bootstrap_status_diag: opt_string("bootstrap_status_diag"),
            recovery_wait_expired: opt_bool("recovery_wait_expired")?,
            fault_refusal_text: opt_string("fault_refusal_text"),
            deadline_refusal_text: opt_string("deadline_refusal_text"),
        })
    }

    /// Shared preconditions for every stage: teardown registered before the
    /// fault, the faketime object actually present (so the injection ran), and
    /// the daemon recovered within the deadline after clock resync.
    fn common_ok(&self, deadline_secs: u64) -> bool {
        self.teardown_registered_before_fault
            && self.faketime_lib_present
            && self.recovered
            && self
                .measured_recovery_secs
                .is_some_and(|secs| secs <= deadline_secs)
    }

    /// `chaos_clock_jump_forward_past_max_age` verdict (TUF freeze defense).
    ///
    /// Phase A (under the +90-day fault): the daemon must fail closed — either
    /// it started with `restricted_safe_mode=true` AND a bootstrap error that
    /// names staleness, or it refused to start outright — and it must NOT
    /// misclassify the stale state as future-dated (counters stay at
    /// baseline). Phase B (post-recovery): the restriction must be cleared and
    /// the replay watermark must hold against the real-clock baseline.
    /// `stale_rejection_observed` is deliberately NOT gated (report-only;
    /// live f760df74 showed the counters flat despite the code intending
    /// otherwise).
    fn passed_jump_forward(&self, deadline_secs: u64) -> bool {
        self.common_ok(deadline_secs)
            && self.snapshot_refused_under_fault == Some(true)
            && self.future_rejections_unchanged == Some(true)
            && (self.bootstrap_error_names_staleness == Some(true)
                || self.daemon_started_under_fault == Some(false))
            // Started form: the dataplane must be FailClosed under the fault
            // (`path_live_proven=false` is the status-line reading of it).
            && (self.daemon_started_under_fault == Some(false)
                || self.path_live_proven == Some(false))
            && self.epoch_not_regressed == Some(true)
            && self.recovered_proven == Some(true)
    }

    /// `chaos_clock_jump_backward_past_replay_window` verdict (rollback
    /// defense). Future-dated rejection is the primary assertion (a backward
    /// clock sits BEHIND the on-disk artifacts, so FutureDated fires
    /// correctly); stale-state rejection stays as the secondary gate and the
    /// replay watermark is compared POST-RECOVERY.
    fn passed_jump_backward(&self, deadline_secs: u64) -> bool {
        self.common_ok(deadline_secs)
            && self.future_dated_rejected == Some(true)
            && self.epoch_not_regressed == Some(true)
            && self.stale_state_rejected == Some(true)
    }

    /// `chaos_clock_skew_slow_drift` verdict (skew tolerance).
    fn passed_slow_drift(&self, deadline_secs: u64) -> bool {
        self.common_ok(deadline_secs)
            && self.within_window_tolerated == Some(true)
            && self.out_of_window_failed_closed == Some(true)
            && self.epoch_not_regressed == Some(true)
    }

    fn passed(&self, stage: ClockStage, deadline_secs: u64) -> bool {
        match stage {
            ClockStage::JumpForward => self.passed_jump_forward(deadline_secs),
            ClockStage::JumpBackward => self.passed_jump_backward(deadline_secs),
            ClockStage::SlowDrift => self.passed_slow_drift(deadline_secs),
        }
    }
}

fn render_live_report(config: &Config, observation: &ClockStageObservation) -> Value {
    let implemented_index = config.stage.stage_index();
    let implemented_status = if observation.precondition_skip.is_some() {
        // b30: a declared precondition skip (e.g. libfaketime absent on an
        // EL guest) is neither a pass nor a fail: nothing ran on the host.
        "skipped"
    } else if observation.passed(config.stage, config.recovery_deadline_secs) {
        "pass"
    } else {
        "fail"
    };
    let stages = clock_attack_stages()
        .into_iter()
        .enumerate()
        .map(|(idx, stage)| {
            if idx == implemented_index {
                json!({
                    "name": stage.name,
                    "status": implemented_status,
                    "fault": stage.fault,
                    "pass_criterion": stage.pass_criterion,
                    "recovery_deadline_secs": config.recovery_deadline_secs,
                    "measured_recovery_secs": observation.measured_recovery_secs,
                    "plaintext_leak_check": "not-applicable-clock-attack",
                    "faketime_lib": config.faketime_lib,
                    "faketime_lib_present": observation.faketime_lib_present,
                    "skip_reason": observation.precondition_skip,
                    "teardown_registered_before_fault": observation.teardown_registered_before_fault,
                    "recovered": observation.recovered,
                    "daemon_started_under_fault": observation.daemon_started_under_fault,
                    "future_dated_rejected": observation.future_dated_rejected,
                    "snapshot_refused_under_fault": observation.snapshot_refused_under_fault,
                    "bootstrap_error_names_staleness": observation.bootstrap_error_names_staleness,
                    "future_rejections_unchanged": observation.future_rejections_unchanged,
                    "stale_rejection_observed": observation.stale_rejection_observed,
                    "path_live_proven": observation.path_live_proven,
                    "recovered_proven": observation.recovered_proven,
                    "recovered_epoch": observation.recovered_epoch,
                    "stale_state_rejected": observation.stale_state_rejected,
                    "epoch_not_regressed": observation.epoch_not_regressed,
                    "within_window_tolerated": observation.within_window_tolerated,
                    "out_of_window_failed_closed": observation.out_of_window_failed_closed,
                    "recovered_diag_probe": observation.recovered_diag_probe,
                    "recovered_diag_unit": observation.recovered_diag_unit,
                    "recovered_diag_socket_file": observation.recovered_diag_socket_file,
                    "status_diag": observation.status_diag,
                    "bootstrap_status_diag": observation.bootstrap_status_diag,
                    "recovery_wait_expired": observation.recovery_wait_expired,
                    "fault_refusal_text": observation.fault_refusal_text,
                    "deadline_refusal_text": observation.deadline_refusal_text,
                })
            } else {
                json!({
                    "name": stage.name,
                    "status": "skipped",
                    "fault": stage.fault,
                    "pass_criterion": stage.pass_criterion,
                    "recovery_deadline_secs": stage.recovery_deadline_secs,
                    "measured_recovery_secs": null,
                    "plaintext_leak_check": "not-run",
                    "summary": "not selected in this clock-attack live slice",
                })
            }
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": CATEGORY,
        "overall_status": implemented_status,
        // b30r2: the orchestrator's stage runner (stage/chaos.rs
        // chaos_report_precondition_skip) reads the skip verdict + reason at
        // the TOP level of this report. A skip carried only inside
        // stages[0] would fall through to verify_chaos_report_shape (which
        // accepts exactly "pass") and fail the stage despite the declared
        // skip, so the reason must live here too.
        "skip_reason": observation.precondition_skip,
        "summary": "per-process clock-attack fault injected via libfaketime against the live daemon",
        "dry_run": false,
        "generated_at_unix": unix_now(),
        "git_commit": config.git_commit,
        "implemented_stage_count": 1,
        "remaining_stage_count": 2,
        "stages": stages,
        "security_invariants": {
            "requires_explicit_enable_chaos_suite": true,
            "requires_teardown_registration_before_injection": true,
            "requires_plaintext_leak_capture_for_live_faults": false,
            "production_state_mutation": false,
            "per_process_clock_only": true,
            "teardown_registered_before_fault": observation.teardown_registered_before_fault,
            "faketime_lib_present": observation.faketime_lib_present,
            "recovered_within_deadline": observation.recovered
                && observation
                    .measured_recovery_secs
                    .is_some_and(|secs| secs <= config.recovery_deadline_secs)
        }
    })
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn parse_u64(args: &[String], idx: usize, flag: &str) -> Result<u64, String> {
    required_value(args, idx, flag)?
        .parse::<u64>()
        .map_err(|err| format!("invalid {flag}: {err}"))
}

fn required_option<'a>(value: Option<&'a str>, flag: &str) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("{flag} is required"))
}

fn required_path<'a>(value: Option<&'a Path>, flag: &str) -> Result<&'a Path, String> {
    value.ok_or_else(|| format!("{flag} is required"))
}

/// Map the `--stage` argument onto [`ClockStage`], rejecting any unknown value
/// so a typo can never silently fall back to a different stage. Accepts both
/// the short alias and the canonical stage name.
fn parse_stage(value: &str) -> Result<ClockStage, String> {
    match value {
        "jump-forward" | "chaos_clock_jump_forward_past_max_age" => Ok(ClockStage::JumpForward),
        "jump-backward" | "chaos_clock_jump_backward_past_replay_window" => {
            Ok(ClockStage::JumpBackward)
        }
        "slow-drift" | "chaos_clock_skew_slow_drift" => Ok(ClockStage::SlowDrift),
        other => Err(format!(
            "invalid --stage: {other} (expected one of: jump-forward, jump-backward, slow-drift)"
        )),
    }
}

fn print_usage() {
    eprintln!(
        "usage: {CATEGORY} [--dry-run] [--target-host <user@host>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--socket-path <path>] [--service-name <name>] [--faketime-lib <path>] [--stage <jump-forward|jump-backward|slow-drift>] [--forward-jump-secs <secs>] [--backward-jump-secs <secs>] [--tolerated-skew-secs <secs>] [--excess-skew-secs <secs>] [--recovery-deadline-secs <secs>] [--report-path <path>] [--log-path <path>] [--git-commit <sha>]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, String> {
        Config::parse(args.iter().map(|value| (*value).to_owned()))
    }

    // Live 2026-09-10 (lenovo-bot): the guest's non-login PATH omits the sbin
    // directories, so `tc`/`ip`/`systemctl` lookups can fail with an opaque
    // status 1. The script pins an sbin-bearing PATH before any lookup.
    #[test]
    fn remote_script_pins_an_sbin_bearing_path_before_any_lookup() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        let path_pos = script
            .find("PATH=\"/usr/local/sbin:/usr/sbin:/sbin:")
            .expect("sbin PATH line present");
        let first_lookup = script
            .find("command -v ")
            .expect("a command -v preflight exists");
        assert!(
            path_pos < first_lookup,
            "PATH must precede the first lookup:\n{script}"
        );
    }

    // Live 2026-09-10 (lenovo-bot): the +90-day jump made rustynetd refuse
    // to start, the failed starts tripped StartLimitBurst, and the teardown's
    // restart was refused — the exit stayed down for every later chaos
    // stage. The script must reset the limit before every restart and
    // record a non-starting daemon instead of aborting.
    #[test]
    fn remote_script_resets_start_limit_and_records_a_daemon_that_will_not_start() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        assert!(
            script
                .matches("systemctl reset-failed \"$service\"")
                .count()
                >= 3,
            "{script}"
        );
        assert!(
            script.contains("printf 'daemon_started_under_fault=false\\n'"),
            "{script}"
        );
        let cleanup = script.find("cleanup() {").expect("cleanup fn");
        let reset_in_cleanup = script[cleanup..]
            .find("systemctl reset-failed")
            .expect("reset in cleanup");
        let restart_in_cleanup = script[cleanup..]
            .find("systemctl restart")
            .expect("restart in cleanup");
        assert!(
            reset_in_cleanup < restart_in_cleanup,
            "reset-failed must precede the teardown restart"
        );
    }

    // katana-xnet-843: install_faketime declared daemon_started_under_fault=true from
    // `systemctl is-active` + the lingering socket FILE at 5 s while every
    // bounded status IPC in the same run hit rc=70 (fingerprint 9044e3ed661a),
    // forcing the started-form of the verdict onto unsampleable evidence. The
    // started oracle must be the same bounded IPC round trip as recovery, and
    // its rc+stderr must reach the diagnostics channel.
    #[test]
    fn remote_script_started_oracle_is_ipc_backed_not_unit_and_socket_file() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        let start = script
            .find("install_faketime() {")
            .expect("install_faketime fn");
        let end = script
            .find("remove_faketime() {")
            .expect("remove_faketime fn");
        let install = &script[start..end];
        assert!(
            !install
                .lines()
                .any(|l| !l.trim_start().starts_with('#') && l.contains("is-active")),
            "started oracle must not rest on the unit-state + lingering socket FILE check (katana-xnet-843): {install}"
        );
        let started_true = install
            .find("daemon_started_under_fault=true")
            .expect("started=true verdict line must remain");
        let probe = install
            .find("status 2>\"$status_diag_file\"")
            .expect("bounded status IPC probe inside install_faketime");
        assert!(
            probe < started_true,
            "started=true must be decided by a completed bounded IPC round trip"
        );
        assert!(
            install.contains("started_diag=rc="),
            "the started attempt's rc+stderr must reach the diagnostics channel: {install}"
        );
    }

    // katana-xnet-843..853: the only artifact that names the bootstrap error is
    // the failed start's own stderr (the daemon never binds, so no status IPC
    // can sample it) and the old `>/dev/null 2>&1` discarded it —
    // bootstrap_error_names_staleness was structurally unsatisfiable. Restart
    // stderr must be captured in both fault windows, and a recovery failure
    // must fold the unit journal into the stage log.
    #[test]
    fn remote_script_captures_restart_and_journal_failure_text() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        for function in ["install_faketime() {", "remove_faketime() {"] {
            let start = script.find(function).expect(function);
            let body = &script[start..start + 1600];
            assert!(
                !body.contains("restart \"$service\" >/dev/null 2>&1"),
                "restart stderr must be captured, not discarded, in {function}: {body}"
            );
        }
        assert!(
            script.contains("recovery_journal_tail="),
            "a recovery failure must fold the unit journal into the stage log"
        );
        assert!(
            script.contains("journalctl -u \"$service\""),
            "the unit journal is the only source of the bootstrap error text"
        );
    }

    #[test]
    fn dry_run_allows_no_live_targets() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        assert!(config.dry_run);
        assert!(config.target_host.is_none());
        assert_eq!(config.stage, ClockStage::JumpForward);
    }

    #[test]
    fn live_mode_requires_target_and_identity() {
        let err = parse(&[]).expect_err("live mode should require target host");
        assert!(err.contains("--target-host"), "got: {err}");
        let err = parse(&["--target-host", "debian@192.0.2.10"])
            .expect_err("live mode should require identity");
        assert!(err.contains("--ssh-identity-file"), "got: {err}");
    }

    #[test]
    fn parser_rejects_shell_metacharacters() {
        let err = parse(&["--dry-run", "--service-name", "rustynetd.service;reboot"])
            .expect_err("service shell metacharacter must reject");
        assert!(err.contains("service name"), "got: {err}");
        let err = parse(&["--dry-run", "--faketime-lib", "/lib/x.so $(id)"])
            .expect_err("faketime lib shell metacharacter must reject");
        assert!(err.contains("faketime lib"), "got: {err}");
    }

    #[test]
    fn parser_bounds_recovery_deadline() {
        let err = parse(&[
            "--dry-run",
            "--recovery-deadline-secs",
            &(MAX_RECOVERY_DEADLINE_SECS + 1).to_string(),
        ])
        .expect_err("deadline above max must reject");
        assert!(err.contains("recovery deadline"), "got: {err}");
        let err = parse(&["--dry-run", "--recovery-deadline-secs", "0"])
            .expect_err("zero deadline must reject");
        assert!(err.contains("recovery deadline"), "got: {err}");
    }

    #[test]
    fn parser_requires_excess_skew_to_exceed_tolerated() {
        let err = parse(&[
            "--dry-run",
            "--tolerated-skew-secs",
            "100",
            "--excess-skew-secs",
            "100",
        ])
        .expect_err("excess skew must strictly exceed tolerated skew");
        assert!(err.contains("excess-skew-secs"), "got: {err}");
    }

    #[test]
    fn parser_rejects_zero_jumps() {
        let err = parse(&["--dry-run", "--forward-jump-secs", "0"])
            .expect_err("zero forward jump must reject");
        assert!(err.contains("forward-jump-secs"), "got: {err}");
        let err = parse(&["--dry-run", "--backward-jump-secs", "0"])
            .expect_err("zero backward jump must reject");
        assert!(err.contains("backward-jump-secs"), "got: {err}");
    }

    #[test]
    fn parse_stage_maps_aliases_and_canonical_names() {
        assert_eq!(
            parse_stage("jump-forward").unwrap(),
            ClockStage::JumpForward
        );
        assert_eq!(
            parse_stage("chaos_clock_jump_forward_past_max_age").unwrap(),
            ClockStage::JumpForward
        );
        assert_eq!(
            parse_stage("jump-backward").unwrap(),
            ClockStage::JumpBackward
        );
        assert_eq!(
            parse_stage("chaos_clock_jump_backward_past_replay_window").unwrap(),
            ClockStage::JumpBackward
        );
        assert_eq!(parse_stage("slow-drift").unwrap(), ClockStage::SlowDrift);
        assert_eq!(
            parse_stage("chaos_clock_skew_slow_drift").unwrap(),
            ClockStage::SlowDrift
        );
    }

    #[test]
    fn parse_stage_rejects_unknown() {
        let err = parse_stage("rewind-the-tape").expect_err("unknown stage must reject");
        assert!(err.contains("invalid --stage"), "got: {err}");
    }

    #[test]
    fn faketime_offset_spec_signs_correctly() {
        assert_eq!(faketime_offset_spec(true, 7_776_000), "+7776000s");
        assert_eq!(faketime_offset_spec(false, 7_776_000), "-7776000s");
        assert_eq!(faketime_offset_spec(true, 30), "+30s");
    }

    // --- jump-forward (freeze defense) verdict ---

    /// Passing Phase A + Phase B observation: under the fault the daemon
    /// started, failed closed (`restricted_safe_mode=true`, a bootstrap error
    /// naming staleness, `state=FailClosed`), kept the future-dated counters
    /// at baseline, then recovered, cleared the restriction, and held the
    /// epoch at the real-clock baseline.
    fn forward_pass_output() -> &'static str {
        "stage=chaos_clock_jump_forward_past_max_age\n\
         teardown_registered_before_fault=true\n\
         faketime_lib_present=true\n\
         baseline_epoch=4\n\
         post_epoch=none\n\
         daemon_started_under_fault=true\n\
         snapshot_refused_under_fault=true\n\
         bootstrap_error_names_staleness=true\n\
         future_rejections_unchanged=true\n\
         stale_rejection_observed=false\n\
         path_live_proven=false\n\
         measured_recovery_secs=12\n\
         recovered=true\n\
         recovery_wait_expired=false\n\
         recovered_epoch=4\n\
         recovered_proven=true\n\
         epoch_not_regressed=true\n"
    }

    #[test]
    fn jump_forward_passes_when_fail_closed_posture_and_recovered() {
        let observation = ClockStageObservation::parse(forward_pass_output()).expect("parse");
        assert!(observation.passed(ClockStage::JumpForward, 180));
    }

    // Review 2026-09-11 blocker: an unsampleable baseline used to coerce to 0,
    // which turned the post-recovery anti-rollback gate into `>= 0`.
    // Live 2026-09-11: `systemctl restart` returned 0 while the daemon exited
    // a second later refusing the clock; and the post-recovery epoch was
    // sampled before bootstrap finished. Both are observation bugs.
    // katana-xnet-843 (fingerprint 9044e3ed661a) showed the t+5 s unit-state +
    // socket-FILE start oracle itself lies: the old socket FILE lingers after
    // a restart, so the started decision must be the same bounded IPC round
    // trip as recovery. This test was updated from the unit-state oracle to
    // the IPC oracle with the fix; the verdict functions are untouched.
    #[test]
    fn remote_script_judges_fault_start_by_ipc_and_polls_post_recovery() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        let install = script.find("install_faketime() {").expect("install fn");
        let end = script[install..]
            .find("remove_faketime() {")
            .expect("remove fn")
            + install;
        let body = &script[install..end];
        assert!(body.contains("sleep 5"), "{body}");
        let probe = body
            .lines()
            .find(|l| l.contains("timeout 15 env RUSTYNET_DAEMON_SOCKET=\"$socket_path\""))
            .expect("the start decision must be a timeout-bounded status IPC round trip");
        assert!(
            probe.contains("status 2>\"$status_diag_file\""),
            "the start probe's stderr must be captured, not discarded:\n{probe}"
        );
        assert!(
            body.find("timeout 15 env RUSTYNET_DAEMON_SOCKET=\"$socket_path\"")
                < body.find("daemon_started_under_fault="),
            "started must be decided by the completed bounded IPC round trip, not unit state + socket FILE:\n{body}"
        );
        assert!(
            script.contains("sample_end_unix=\"$((start_unix + deadline))\""),
            "{script}"
        );
        assert!(script.contains("'') path_live_proven=none ;;"), "{script}");
    }

    // Fingerprint 9044e3ed661a (xnet-403/-703/-709/-733/-734, 7 live runs):
    // wait_recovered declared recovery from `systemctl is-active` + the
    // socket FILE — but the old file lingers on disk after a restart until
    // the new daemon binds (katana-xnet-148), so `recovered=true` at 0 s
    // coexisted with 180 s of `connect … refused` and the stage failed with
    // an unexplainable empty window. Readiness must be ONE completed IPC
    // round trip — the same criterion as the host-side shared probe
    // (live_lab_bin_support::daemon_status_probe_body) — and the attempt's
    // outcome must land in the stage log as evidence. On the pre-fix code
    // the first assertion fails (the unit+file check IS the wait body) and
    // no probe/diagnostic lines exist.
    #[test]
    fn remote_script_recovery_readiness_requires_an_ipc_round_trip() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        let wait = script.find("wait_recovered() {").expect("wait fn");
        let end = script[wait..].find("\n}\n").expect("wait fn end") + wait;
        let body = &script[wait..end];
        assert!(
            !body.contains("systemctl is-active --quiet \"$service\" && [ -S \"$socket_path\" ]"),
            "recovery must not be declared from unit state + socket FILE existence (the old file lingers after a restart):\n{body}"
        );
        assert!(
            script.contains("daemon_answers_status() {"),
            "the readiness probe must be a named function:\n{script}"
        );
        assert!(
            body.contains("if daemon_answers_status; then"),
            "wait_recovered must poll the IPC round trip:\n{body}"
        );
        let probe_start = script
            .find("daemon_answers_status() {")
            .expect("readiness probe fn");
        let probe_end = script[probe_start..].find("\n}\n").expect("probe fn end") + probe_start;
        let probe_body = &script[probe_start..probe_end];
        assert!(
            probe_body.contains("timeout 15 env RUSTYNET_DAEMON_SOCKET=\"$socket_path\""),
            "each readiness attempt must be the timeout-bounded round trip (a wedged daemon must consume the attempt, exit 124, not hang the stage):\n{probe_body}"
        );
        assert!(
            body.contains("printf 'recovered_diag_probe=%s\\n' \"$probe_diag\""),
            "the last probe attempt's rc+stderr must be recorded for the stage log:\n{body}"
        );
        assert!(
            body.contains("recovered_diag_unit=") && body.contains("recovered_diag_socket_file="),
            "unit state + socket file presence must be recorded as evidence:\n{body}"
        );
    }

    // The status oracle: an UNBOUNDED `rustynet status 2>/dev/null` could
    // hang the whole stage on the CLI's unbounded IPC read and discarded the
    // one stderr that explained 180 s of empty samples (fingerprint
    // 9044e3ed661a). On the pre-fix code both assertions fail (no timeout,
    // stderr piped to /dev/null).
    #[test]
    fn remote_script_status_field_is_timeout_bounded_and_captures_stderr() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        let start = script.find("status_field() {").expect("status_field fn");
        let end = script[start..].find("\n}\n").expect("status_field fn end") + start;
        let body = &script[start..end];
        assert!(
            body.contains("timeout 15 env RUSTYNET_DAEMON_SOCKET=\"$socket_path\""),
            "status_field must bound one round trip at 15 s (exit 124 = accepted but never answered):\n{body}"
        );
        assert!(
            !body.contains("2>/dev/null"),
            "stderr must be captured into the stage-log diagnostics file, not discarded:\n{body}"
        );
        assert!(
            body.contains("2>\"$status_diag_file\""),
            "the attempt's stderr must land in the diagnostics file:\n{body}"
        );
    }

    // glm-review-chaos-clock-oracle-2-1 MEDIUM-1: the JumpForward Phase-A
    // bootstrap-staleness probe was the LAST unbounded, stderr-discarding
    // `rustynet status 2>/dev/null || true` in the remote script — a daemon
    // wedged accept-but-never-answer at that instant hung the whole stage on
    // the CLI's unbounded IPC read and the stderr was lost. It must be the
    // same timeout-bounded, stderr-capturing form as status_field, and its
    // rc+stderr must be printed into the stage log AT THE PROBE SITE (the
    // shared diagnostics channel is overwritten by the later status_field
    // calls, so a phase-end print would usually never carry it). On the
    // pre-fix code the first three assertions fail (no timeout, stderr to
    // /dev/null) and the bootstrap_status_diag print does not exist.
    #[test]
    fn remote_script_bootstrap_status_probe_is_timeout_bounded_and_captures_stderr() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        let offender = script
            .lines()
            .find(|l| !l.trim_start().starts_with('#') && l.contains("status 2>/dev/null"));
        assert!(
            offender.is_none(),
            "no non-comment line of the remote script may still be an unbounded, stderr-discarding status probe:\n{offender:?}"
        );
        let line = script
            .lines()
            .find(|l| l.starts_with("full_status=\"$("))
            .expect("the bootstrap staleness probe line");
        assert!(
            line.contains("timeout 15 env RUSTYNET_DAEMON_SOCKET=\"$socket_path\""),
            "the bootstrap staleness probe must bound one round trip at 15 s (exit 124 = accepted but never answered, not a stage hang):\n{line}"
        );
        assert!(
            !line.contains("2>/dev/null"),
            "the probe's stderr must be captured, not discarded:\n{line}"
        );
        assert!(
            line.contains("2>\"$status_diag_file\""),
            "the probe's stderr must land in the diagnostics file:\n{line}"
        );
        assert!(
            script
                .contains("printf 'bootstrap_status_diag=%s\\n' \"$(cat \"$status_diag_file\")\""),
            "the probe's rc+stderr must be printed into the stage log at the probe site, before the later status_field calls overwrite the channel:\n{script}"
        );
    }

    // The Phase-B poll must print the last status sample's rc+stderr into
    // the stage log, so the WHY behind an unsampleable recovery (refused vs
    // wedged vs token-less answer) is evidence, not a mystery.
    #[test]
    fn remote_script_records_last_status_sample_diagnostics() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        let sample = script
            .find("sample_end_unix=\"$((start_unix + deadline))\"")
            .expect("phase-B poll loop");
        let body = &script[sample..];
        assert!(
            body.contains(
                "printf 'status_diag=%s\\n' \"$(cat \"$status_diag_file\" 2>/dev/null || true)\""
            ),
            "the last status sample's rc+stderr must be printed into the stage log:\n{body}"
        );
    }

    // The diagnostics are report-only strings: they must PARSE (the pre-fix
    // code silently dropped unknown keys, leaving the 180 s window
    // unexplainable) and must never change the verdict inputs they
    // accompany.
    #[test]
    fn recovery_and_status_diagnostics_parse_as_report_only_strings() {
        let output = format!(
            "{}\nrecovered_diag_probe=rc=124 stderr=Error: connect to /run/rustynet/rustynetd.sock failed: Connection refused\nrecovered_diag_unit=active/running\nrecovered_diag_socket_file=present\nstatus_diag=rc=7 stderr=Connection refused\nbootstrap_status_diag=rc=124 stderr=timed out\n",
            forward_pass_output()
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert_eq!(
            observation.recovered_diag_probe.as_deref(),
            Some(
                "rc=124 stderr=Error: connect to /run/rustynet/rustynetd.sock failed: \
                 Connection refused"
            )
        );
        assert_eq!(
            observation.recovered_diag_unit.as_deref(),
            Some("active/running")
        );
        assert_eq!(
            observation.recovered_diag_socket_file.as_deref(),
            Some("present")
        );
        assert_eq!(
            observation.status_diag.as_deref(),
            Some("rc=7 stderr=Connection refused")
        );
        assert_eq!(
            observation.bootstrap_status_diag.as_deref(),
            Some("rc=124 stderr=timed out")
        );
        assert!(
            observation.passed(ClockStage::JumpForward, 180),
            "report-only diagnostics must never change the verdict of the observation they accompany"
        );
    }

    #[test]
    fn live_report_carries_recovery_and_status_diagnostics() {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let output = format!(
            "{}\nrecovered_diag_probe=rc=0 stderr=\nrecovered_diag_unit=active/running\nrecovered_diag_socket_file=present\nstatus_diag=rc=0 stderr=\nbootstrap_status_diag=rc=0 stderr=\n",
            forward_pass_output()
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        let report = render_live_report(&config, &observation);
        let stage = &report["stages"][0];
        assert_eq!(stage["recovered_diag_probe"], "rc=0 stderr=");
        assert_eq!(stage["recovered_diag_unit"], "active/running");
        assert_eq!(stage["recovered_diag_socket_file"], "present");
        assert_eq!(stage["status_diag"], "rc=0 stderr=");
        assert_eq!(stage["bootstrap_status_diag"], "rc=0 stderr=");
    }

    // The tightened oracle must never turn a failure into a pass: if the
    // daemon never completes one IPC round trip inside the window,
    // recovered=false and common_ok fails the stage (with the diagnostics
    // naming the rc/stderr of the last attempt).
    #[test]
    fn jump_forward_fails_when_no_ipc_round_trip_ever_succeeds() {
        let output = forward_pass_output().replace("recovered=true", "recovered=false");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.recovered);
        assert!(!observation.passed(ClockStage::JumpForward, 180));
    }

    // An unsampleable dataplane state is unknown: with the daemon reported
    // as started, the leg cannot claim FailClosed and must fail.
    #[test]
    fn jump_forward_fails_when_dataplane_state_is_unknown_but_daemon_started() {
        let output =
            forward_pass_output().replace("path_live_proven=false", "path_live_proven=none");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert_eq!(observation.path_live_proven, None);
        assert!(!observation.passed_jump_forward(180));
    }

    #[test]
    fn remote_script_never_coerces_an_epoch_comparison_to_zero() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        assert!(!script.contains("post_epoch=0"), "{script}");
        assert!(!script.contains("recovered_epoch=0"), "{script}");
        assert!(!script.contains("baseline_epoch=0"), "{script}");
        assert!(
            script.contains("''|*[!0-9]*) : ;;   # unverifiable baseline must FAIL"),
            "{script}"
        );
        assert!(script.contains("*[!0-9]*|none) : ;;"), "{script}");
    }

    // Started form must also prove the dataplane stayed FailClosed under
    // the fault (path_live_proven=false); a live path under a +90d clock
    // is the fail-open this leg exists to catch.
    #[test]
    fn jump_forward_fails_when_dataplane_is_live_under_fault() {
        let output =
            forward_pass_output().replace("path_live_proven=false", "path_live_proven=true");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed_jump_forward(180));
    }

    #[test]
    fn jump_forward_fails_when_restriction_not_raised_under_fault() {
        // restricted_safe_mode stayed false under the fault (no fail-closed
        // posture) — the exact regression the Phase A gate exists to catch.
        let output = forward_pass_output().replace(
            "snapshot_refused_under_fault=true",
            "snapshot_refused_under_fault=false",
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpForward, 180));
    }

    #[test]
    fn jump_forward_fails_when_future_counters_misclassified() {
        // The old gate demanded future_state_rejected=true; the NEW gate is
        // the inverse: the future-dated counters must NOT move. A daemon that
        // misclassifies stale state as future-dated must FAIL.
        let output = forward_pass_output().replace(
            "future_rejections_unchanged=true",
            "future_rejections_unchanged=false",
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpForward, 180));
    }

    #[test]
    fn jump_forward_accepts_refused_start_without_stale_bootstrap_error() {
        // D6 is open: a daemon that refuses to start outright satisfies the
        // fail-closed posture via daemon_started_under_fault=false, even
        // though no status (and so no bootstrap error) was sampleable.
        let output = forward_pass_output()
            .replace(
                "daemon_started_under_fault=true",
                "daemon_started_under_fault=false",
            )
            .replace(
                "bootstrap_error_names_staleness=true",
                "bootstrap_error_names_staleness=false",
            );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(observation.passed(ClockStage::JumpForward, 180));
    }

    #[test]
    fn jump_forward_fails_when_started_without_stale_naming_error() {
        // Started but neither restricted-with-staleness-error nor refused:
        // neither disjunct holds, so the fail-closed posture is unproven.
        let output = forward_pass_output().replace(
            "bootstrap_error_names_staleness=true",
            "bootstrap_error_names_staleness=false",
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpForward, 180));
    }

    #[test]
    fn jump_forward_does_not_gate_on_stale_rejection_observed() {
        // REPORT-ONLY: a flat stale counter (live f760df74) must not fail the
        // leg, and an observed rise must not be required.
        let output = forward_pass_output().replace(
            "stale_rejection_observed=false",
            "stale_rejection_observed=true",
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(observation.passed(ClockStage::JumpForward, 180));
    }

    #[test]
    fn jump_forward_fails_when_epoch_regressed_post_recovery() {
        // A genuine watermark downgrade (recovered epoch < real-clock
        // baseline) is the rollback the leg must catch.
        let output =
            forward_pass_output().replace("epoch_not_regressed=true", "epoch_not_regressed=false");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpForward, 180));
    }

    #[test]
    fn jump_forward_fails_when_restriction_not_cleared_post_recovery() {
        // Phase B: restricted_safe_mode must be false after recovery.
        let output =
            forward_pass_output().replace("recovered_proven=true", "recovered_proven=false");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpForward, 180));
    }

    #[test]
    fn jump_forward_parses_refused_epoch_as_absent_not_zero() {
        // `none` (the daemon's rendering of a refused snapshot) must parse as
        // absent — never coerced to 0, the artifact that broke the old gate.
        let output = forward_pass_output().replace("recovered_epoch=4", "recovered_epoch=none");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert_eq!(observation.recovered_epoch, None);
    }

    #[test]
    fn jump_forward_fails_when_not_recovered_in_deadline() {
        let output = forward_pass_output()
            .replace("measured_recovery_secs=12", "measured_recovery_secs=999");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpForward, 180));
    }

    #[test]
    fn jump_forward_fails_when_faketime_absent() {
        // A never-run / unverifiable injection (no faketime object present) must
        // be a FAIL, never a fake-pass.
        let output = forward_pass_output()
            .replace("faketime_lib_present=true", "faketime_lib_present=false");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpForward, 180));
    }

    #[test]
    fn jump_forward_fails_when_verdict_fields_missing() {
        // Missing the stage-specific verdict fields => unverifiable => FAIL.
        let output = "stage=chaos_clock_jump_forward_past_max_age\n\
             teardown_registered_before_fault=true\n\
             faketime_lib_present=true\n\
             measured_recovery_secs=12\n\
             recovered=true\n";
        let observation = ClockStageObservation::parse(output).expect("parse");
        assert_eq!(observation.snapshot_refused_under_fault, None);
        assert_eq!(observation.future_rejections_unchanged, None);
        assert_eq!(observation.recovered_proven, None);
        assert!(!observation.passed(ClockStage::JumpForward, 180));
    }

    // --- jump-backward (rollback defense) verdict ---

    fn backward_pass_output() -> &'static str {
        "stage=chaos_clock_jump_backward_past_replay_window\n\
         teardown_registered_before_fault=true\n\
         faketime_lib_present=true\n\
         baseline_epoch=9\n\
         post_epoch=none\n\
         future_dated_rejected=true\n\
         stale_state_rejected=true\n\
         measured_recovery_secs=20\n\
         recovered=true\n\
         recovered_epoch=9\n\
         epoch_not_regressed=true\n"
    }

    #[test]
    fn jump_backward_passes_when_future_dated_rejected_epoch_held_and_stale_rejected() {
        let observation = ClockStageObservation::parse(backward_pass_output()).expect("parse");
        assert!(observation.passed(ClockStage::JumpBackward, 180));
    }

    #[test]
    fn jump_backward_fails_when_future_dated_accepted() {
        // Primary assertion: under a backward jump the FutureDated arms fire
        // correctly, so a daemon that fails to reject future-dated state is a
        // real defect.
        let output = backward_pass_output()
            .replace("future_dated_rejected=true", "future_dated_rejected=false");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpBackward, 180));
    }

    #[test]
    fn jump_backward_fails_when_epoch_regressed() {
        // A regressed replay watermark is the rollback the test must catch.
        let output =
            backward_pass_output().replace("epoch_not_regressed=true", "epoch_not_regressed=false");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpBackward, 180));
    }

    #[test]
    fn jump_backward_fails_when_stale_state_accepted() {
        let output = backward_pass_output()
            .replace("stale_state_rejected=true", "stale_state_rejected=false");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::JumpBackward, 180));
    }

    // --- slow-drift (skew tolerance) verdict ---

    fn drift_pass_output() -> &'static str {
        "stage=chaos_clock_skew_slow_drift\n\
         teardown_registered_before_fault=true\n\
         faketime_lib_present=true\n\
         within_window_tolerated=true\n\
         out_of_window_failed_closed=true\n\
         epoch_not_regressed=true\n\
         measured_recovery_secs=30\n\
         recovered=true\n"
    }

    #[test]
    fn slow_drift_passes_when_within_tolerated_and_excess_fails_closed() {
        let observation = ClockStageObservation::parse(drift_pass_output()).expect("parse");
        assert!(observation.passed(ClockStage::SlowDrift, 900));
    }

    #[test]
    fn slow_drift_fails_when_within_window_spuriously_rejected() {
        let output = drift_pass_output().replace(
            "within_window_tolerated=true",
            "within_window_tolerated=false",
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::SlowDrift, 900));
    }

    #[test]
    fn slow_drift_fails_when_out_of_window_accepted() {
        let output = drift_pass_output().replace(
            "out_of_window_failed_closed=true",
            "out_of_window_failed_closed=false",
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(ClockStage::SlowDrift, 900));
    }

    #[test]
    fn observation_parse_rejects_non_boolean_required_field() {
        let output =
            "teardown_registered_before_fault=maybe\nfaketime_lib_present=true\nrecovered=true\n";
        let err = ClockStageObservation::parse(output).expect_err("non-boolean must reject");
        assert!(
            err.contains("teardown_registered_before_fault"),
            "got: {err}"
        );
    }

    #[test]
    fn observation_parse_rejects_missing_required_field() {
        let output = "faketime_lib_present=true\nrecovered=true\n";
        let err =
            ClockStageObservation::parse(output).expect_err("missing required boolean must reject");
        assert!(
            err.contains("teardown_registered_before_fault"),
            "got: {err}"
        );
    }

    // --- report rendering ---

    #[test]
    fn live_report_marks_selected_stage_and_skips_others() {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let observation = ClockStageObservation::parse(forward_pass_output()).expect("parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "pass");
        assert_eq!(report["implemented_stage_count"], 1);
        assert_eq!(report["remaining_stage_count"], 2);
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages.len(), 3);
        assert_eq!(stages[0]["name"], "chaos_clock_jump_forward_past_max_age");
        assert_eq!(stages[0]["status"], "pass");
        assert_eq!(stages[1]["status"], "skipped");
        assert_eq!(stages[2]["status"], "skipped");
    }

    #[test]
    fn live_report_carries_new_jump_forward_verdict_fields() {
        // Every new key=value the remote script prints must land in the JSON
        // report — including the report-only stale counter and the raw
        // post-recovery epoch.
        let config = parse(&["--dry-run"]).expect("config should parse");
        let observation = ClockStageObservation::parse(forward_pass_output()).expect("parse");
        let report = render_live_report(&config, &observation);
        let stage = &report["stages"][0];
        assert_eq!(stage["snapshot_refused_under_fault"], true);
        assert_eq!(stage["bootstrap_error_names_staleness"], true);
        assert_eq!(stage["future_rejections_unchanged"], true);
        assert_eq!(stage["stale_rejection_observed"], false);
        assert_eq!(stage["path_live_proven"], false);
        assert_eq!(stage["recovered_proven"], true);
        assert_eq!(stage["recovered_epoch"], 4);
        assert_eq!(stage["recovery_wait_expired"], false);
    }

    #[test]
    fn live_report_marks_failed_when_state_accepted() {
        let config =
            parse(&["--dry-run", "--stage", "jump-backward"]).expect("config should parse");
        let output =
            backward_pass_output().replace("epoch_not_regressed=true", "epoch_not_regressed=false");
        let observation = ClockStageObservation::parse(&output).expect("parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "fail");
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(
            stages[1]["name"],
            "chaos_clock_jump_backward_past_replay_window"
        );
        assert_eq!(stages[1]["status"], "fail");
        assert_eq!(stages[0]["status"], "skipped");
        assert_eq!(stages[2]["status"], "skipped");
    }

    // --- b30: an EL guest without libfaketime must be a declared
    // --- precondition skip — never a crash (the pre-fix remote script's
    // --- `exit 1` made capture_root fail and the bin died without writing
    // --- any report), and never a pass.

    /// Exactly what the remote script prints on a guest whose bootstrap
    /// treated libfaketime as optional (EL): the fault fields
    /// (teardown/baseline/recovery) are legitimately absent because nothing
    /// ran.
    fn precondition_skip_output() -> &'static str {
        "stage=chaos_clock_jump_forward_past_max_age\n\
         faketime_lib_present=false\n\
         precondition_skip=libfaketime shared object not readable at \
         /usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 on this guest; \
         the lab bootstrap treats libfaketime as optional on EL, so the chaos \
         clock-attack stage cannot inject a clock fault here\n"
    }

    #[test]
    fn precondition_skip_output_parses_without_the_fault_fields() {
        // On the pre-fix code this parse ERRED ("missing
        // teardown_registered_before_fault in clock attack output") — the
        // hard parse failure on top of the remote exit-1 crash is what b30
        // removes.
        let observation = ClockStageObservation::parse(precondition_skip_output()).expect("parse");
        assert!(!observation.faketime_lib_present);
        assert!(
            observation.precondition_skip.is_some(),
            "the skip reason must be carried on the observation"
        );
        assert!(!observation.teardown_registered_before_fault);
        assert!(!observation.recovered);
    }

    #[test]
    fn precondition_skip_never_counts_as_a_pass() {
        let observation = ClockStageObservation::parse(precondition_skip_output()).expect("parse");
        assert!(
            !observation.passed(ClockStage::JumpForward, 180),
            "a skipped injection must never satisfy the jump-forward verdict"
        );
    }

    #[test]
    fn live_report_marks_precondition_skip_with_precise_reason() {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let observation = ClockStageObservation::parse(precondition_skip_output()).expect("parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "skipped");
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages[0]["status"], "skipped");
        assert_eq!(stages[0]["faketime_lib_present"], false);
        let reason = stages[0]["skip_reason"].as_str().expect("skip_reason");
        assert!(
            reason.contains("faketime"),
            "the reason must name the missing faketime object: {reason}"
        );
        // b30r2: the orchestrator stage runner (stage/chaos.rs
        // chaos_report_precondition_skip) reads skip_reason at the TOP level
        // of the report; without it a declared skip falls through to
        // verify_chaos_report_shape (which accepts exactly "pass") and FAILS
        // the stage. Mutation: drop the top-level "skip_reason" key from
        // render_live_report — this assertion goes red.
        assert_eq!(
            report["skip_reason"].as_str(),
            Some(reason),
            "the skip reason must be carried at the report TOP level for the stage runner"
        );
        assert_eq!(
            report["security_invariants"]["faketime_lib_present"], false,
            "the security invariant must keep recording the absent object"
        );
    }

    #[test]
    fn remote_script_skips_cleanly_when_faketime_lib_missing() {
        let config = parse(&[
            "--dry-run",
            "--stage",
            "jump-forward",
            "--service-name",
            "rustynetd.service",
        ])
        .expect("config should parse");
        let script = render_remote_clock_script(&config);
        let skip_pos = script
            .find("faketime_lib_present=false")
            .expect("skip marker present");
        let trap_pos = script
            .find("trap cleanup EXIT HUP INT TERM")
            .expect("trap present");
        assert!(
            skip_pos < trap_pos,
            "the faketime precondition must be decided BEFORE teardown registration: a skip must never register a trap or touch the service"
        );
        let window = &script[skip_pos..(skip_pos + 600).min(script.len())];
        assert!(
            window.contains("precondition_skip="),
            "the skip must carry a precise reason: {window}"
        );
        assert!(
            window.contains("exit 0"),
            "the skip path must exit ZERO — the pre-fix `exit 1` made capture_root error out and the bin crashed with no report at all: {window}"
        );
    }

    #[test]
    fn remote_script_quotes_values_and_registers_teardown_before_fault() {
        let config = parse(&[
            "--dry-run",
            "--stage",
            "jump-forward",
            "--service-name",
            "rustynetd.service",
            "--faketime-lib",
            "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
        ])
        .expect("config should parse");
        let script = render_remote_clock_script(&config);
        // Teardown trap is registered before the fault is installed, and it
        // names HUP/INT/TERM explicitly: the SSH session dying (orchestrator
        // SIGKILL) may not run an EXIT-only trap, which would leave the
        // faketime drop-in installed.
        let trap_pos = script
            .find("trap cleanup EXIT HUP INT TERM")
            .expect("trap present");
        let install_pos = script
            .find("install_faketime '+7776000s'")
            .expect("install present");
        assert!(
            trap_pos < install_pos,
            "teardown must be registered before the fault"
        );
        // Values flow through shell_quote (single-quoted).
        assert!(script.contains("service='rustynetd.service'"));
        assert!(
            script.contains("faketime_lib='/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1'")
        );
        // The faketime object is verified readable before injection.
        assert!(script.contains("test -r \"$faketime_lib\""));
    }

    #[test]
    fn remote_script_slow_drift_uses_both_legs() {
        let config = parse(&[
            "--dry-run",
            "--stage",
            "slow-drift",
            "--tolerated-skew-secs",
            "30",
            "--excess-skew-secs",
            "86400",
        ])
        .expect("config should parse");
        let script = render_remote_clock_script(&config);
        assert!(script.contains("install_faketime '+30s'"), "tolerated leg");
        assert!(script.contains("install_faketime '+86400s'"), "excess leg");
        assert!(script.contains("within_window_tolerated="));
        assert!(script.contains("out_of_window_failed_closed="));
    }

    // --- katana-xnet-1068: the deadline+1 near-miss ---

    /// Run the RENDERED `wait_recovered` body under a virtual clock: `date`
    /// and `sleep` are stubs around one integer `NOW`, the readiness probe is
    /// a stub that starts answering at a controllable instant. The harness
    /// presets the variables the body's `set -u` expects but the caller
    /// normally supplies.
    fn run_wait_recovered(recover_at: u64) -> (String, String, String) {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let script = render_remote_clock_script(&config);
        let wait = script.find("wait_recovered() {").expect("wait fn");
        let end = script[wait..].find("\n}\n").expect("wait fn end") + wait;
        let wait_fn = &script[wait..end];
        assert!(
            !wait_fn.contains("start_unix=\"$(date +%s)\""),
            "wait_recovered must never RESET the caller's t0 (katana-xnet-1068: the reset recorded the remove_faketime restart latency against the deadline):\n{wait_fn}"
        );
        let harness = format!(
            "#!/usr/bin/env bash\n\
             set -eu\n\
             deadline=5\n\
             service='stub.service'\n\
             socket_path='/tmp/rustynet-wait-stub-absent.sock'\n\
             NOW=1000\n\
             recover_at={recover_at}\n\
             date() {{ printf '%s' \"$NOW\"; }}\n\
             sleep() {{ NOW=$((NOW + ${{1:-0}})); }}\n\
             systemctl() {{ printf 'inactive\\n'; }}\n\
             daemon_answers_status() {{\n\
               if [ \"$NOW\" -ge \"$recover_at\" ]; then\n\
                 probe_diag='rc=0 stderr='\n\
                 return 0\n\
               fi\n\
               probe_diag='rc=70 stderr=connection refused'\n\
               return 1\n\
             }}\n\
             {wait_fn}\n\
             }}\n\
             wait_recovered\n"
        );
        let dir = std::env::temp_dir().join(format!(
            "rn-clock-wait-{}-{recover_at}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("harness.sh");
        std::fs::write(&path, harness).expect("write harness");
        let output = std::process::Command::new("/bin/bash")
            .arg(&path)
            .output()
            .expect("run harness");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            output.status.success(),
            "harness exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).to_owned();
        let field = |key: &str| -> String {
            stdout
                .lines()
                .find_map(|line| {
                    line.split_once('=')
                        .and_then(|(found, value)| {
                            (found.trim() == key).then(|| value.trim().to_owned())
                        })
                })
                .unwrap_or_else(|| panic!("{key} missing in:\n{stdout}"))
        };
        (
            field("measured_recovery_secs"),
            field("recovered"),
            field("recovery_wait_expired"),
        )
    }

    // Behavioral: with the t0 hoisted to the caller, a recovery that lands on
    // the LAST in-window poll measures exactly the deadline (never +1), and a
    // daemon that never answers measures deadline+1 BY LOOP STRUCTURE — which
    // the report now names with recovery_wait_expired=true instead of
    // disguising it as one second of latency.
    #[test]
    fn wait_recovered_honors_caller_t0_and_names_structural_expiry() {
        let (measured, recovered, expired) = run_wait_recovered(1005);
        assert_eq!(
            measured, "5",
            "recovery on the last in-window poll must measure the deadline exactly"
        );
        assert_eq!(recovered, "true");
        assert_eq!(expired, "false");
        let (measured, recovered, expired) = run_wait_recovered(9_999_999);
        assert_eq!(
            measured, "6",
            "a never-recovering daemon runs the loop to end_unix and exits one tick later: deadline+1 is STRUCTURAL"
        );
        assert_eq!(recovered, "false");
        assert_eq!(expired, "true");
    }

    // The t0 must be hoisted into EVERY stage body, immediately before
    // remove_faketime, exactly once per rendered script.
    #[test]
    fn remote_script_starts_recovery_clock_before_faketime_removal_in_every_stage() {
        let configs = [
            parse(&["--dry-run"]).expect("config should parse"),
            parse(&["--dry-run", "--stage", "jump-backward"]).expect("config should parse"),
            parse(&[
                "--dry-run",
                "--stage",
                "slow-drift",
                "--tolerated-skew-secs",
                "30",
                "--excess-skew-secs",
                "86400",
            ])
            .expect("config should parse"),
        ];
        for config in &configs {
            let script = render_remote_clock_script(config);
            assert_eq!(
                script.matches("start_unix=\"$(date +%s)\"").count(),
                1,
                "t0 must be hoisted exactly once per stage script:\n{script}"
            );
            assert!(
                script.contains("start_unix=\"$(date +%s)\"\nremove_faketime\nwait_recovered"),
                "t0 must sit immediately BEFORE remove_faketime (the measured window must exclude the restart latency):\n{script}"
            );
        }
    }

    /// Run the rendered `staleness_named` body against one refusal text.
    fn staleness_named_judges(text: &str) -> bool {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let script = render_remote_clock_script(&config);
        let start = script
            .find("staleness_named() {")
            .expect("staleness_named fn");
        let end = script[start..].find("\n}\n").expect("fn end") + start;
        let harness = format!(
            "#!/usr/bin/env bash\nset -eu\n{}\n}}\nif staleness_named \"$1\"; then echo yes; else echo no; fi\n",
            &script[start..end]
        );
        let dir = std::env::temp_dir().join(format!("rn-clock-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("judge.sh");
        std::fs::write(&path, harness).expect("write harness");
        let output = std::process::Command::new("/bin/bash")
            .arg(&path)
            .arg(text)
            .output()
            .expect("run harness");
        assert!(
            output.status.success(),
            "harness exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim() == "yes"
    }

    // Behavioral: the vocabulary must cover what the live daemon actually
    // emits (2026-09-11: "trust preflight failed: trust evidence is stale";
    // rustynetd windows_mesh_status: "state snapshot is stale: age=...s
    // exceeds max_age=...s") and reject unrelated refusals.
    #[test]
    fn staleness_named_matches_live_daemon_vocabulary() {
        for text in [
            "trust preflight failed: trust evidence is stale",
            "state snapshot is stale: age=200s exceeds max_age=180s",
            "start-up aborted: trust bundle expired",
            "snapshot age 200s exceeds max-age=180s",
        ] {
            assert!(
                staleness_named_judges(text),
                "must NAME staleness: {text}"
            );
        }
        for text in ["start request repeated too quickly", ""] {
            assert!(
                !staleness_named_judges(text),
                "unrelated refusal must not name staleness: {text}"
            );
        }
    }

    // Jump-forward must capture the refusal WHY (a) under the fault when the
    // status IPC was empty (refused start) and (b) after an expired recovery
    // wait — and the staleness FLAG must print exactly ONCE, after both
    // derivations (the parser takes the FIRST line of a key). The other two
    // stages never sampled the flag and must stay that way.
    #[test]
    fn remote_script_captures_refusal_evidence_for_the_staleness_flag() {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let script = render_remote_clock_script(&config);
        assert!(
            script.contains("refusal_text() {") && script.contains("staleness_named() {"),
            "the refusal/staleness helpers must exist:\n{script}"
        );
        let body = &script[script.find("printf 'fault_spec=").expect("stage body")..];
        let fault_cap = body
            .find("fault_refusal_text=\"$(refusal_text)\"")
            .expect("the under-fault refusal capture must exist");
        let wait_call = body
            .find("\nwait_recovered\n")
            .expect("the recovery wait call");
        assert!(
            fault_cap < wait_call,
            "the refusal capture must run UNDER the fault, before recovery:\n{body}"
        );
        let deadline_cap = body
            .find("if [ \"$recovered\" = false ]; then")
            .expect("the deadline-cross capture must exist");
        assert!(
            deadline_cap > wait_call,
            "the deadline refusal capture must run only after the wait ended:\n{body}"
        );
        let flag_print = "printf 'bootstrap_error_names_staleness=%s\\n'";
        assert_eq!(
            body.matches(flag_print).count(),
            1,
            "the staleness flag must print exactly ONCE (the parser takes the first line of a key):\n{body}"
        );
        assert!(
            body.find(flag_print).expect("flag print") > deadline_cap,
            "the flag must print after the deadline-cross re-derivation:\n{body}"
        );
        for (args, name) in [
            (
                vec!["--dry-run", "--stage", "jump-backward"],
                "jump-backward",
            ),
            (
                vec![
                    "--dry-run",
                    "--stage",
                    "slow-drift",
                    "--tolerated-skew-secs",
                    "30",
                    "--excess-skew-secs",
                    "86400",
                ],
                "slow-drift",
            ),
        ] {
            let other = render_remote_clock_script(&parse(&args).expect("config should parse"));
            // The refusal helpers live in the shared preamble; the flag and
            // its captures must stay out of the other stages' BODIES.
            let other_body =
                &other[other.find("printf 'fault_spec=").expect("stage body")..];
            assert!(
                !other_body.contains("bootstrap_error_names_staleness"),
                "{name} must not reference the staleness flag:\n{other_body}"
            );
            assert!(
                !other_body.contains("refusal_text"),
                "{name} must not capture refusal text:\n{other_body}"
            );
        }
    }

    // katana-xnet-1068 exactly: recovered=false, measured=181 (one tick past
    // the 180 s deadline — the loop's structural expiry), status channel
    // empty the whole window. The observation must carry the expiry + both
    // refusal texts, and none of them may move the verdict.
    #[test]
    fn recovery_expiry_and_refusal_texts_are_report_only() {
        let output = format!(
            "{}\nrecovery_wait_expired=true\n\
             fault_refusal_text=trust preflight failed: trust evidence is stale|journal line kept for the record\n\
             deadline_refusal_text=start request repeated too quickly\n",
            forward_pass_output()
                .replace("recovered=true", "recovered=false")
                .replace("recovery_wait_expired=false", "recovery_wait_expired=true")
                .replace("measured_recovery_secs=12", "measured_recovery_secs=181")
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        assert_eq!(observation.recovery_wait_expired, Some(true));
        assert_eq!(
            observation.fault_refusal_text.as_deref(),
            Some("trust preflight failed: trust evidence is stale|journal line kept for the record")
        );
        assert_eq!(
            observation.deadline_refusal_text.as_deref(),
            Some("start request repeated too quickly")
        );
        assert!(
            !observation.passed(ClockStage::JumpForward, 180),
            "the expiry flag + refusal texts must never change the verdict"
        );
    }

    #[test]
    fn live_report_carries_expiry_and_refusal_texts() {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let output = format!(
            "{}\nrecovery_wait_expired=true\n\
             fault_refusal_text=trust preflight failed: trust evidence is stale\n\
             deadline_refusal_text=state snapshot is stale: age=200s exceeds max_age=180s\n",
            forward_pass_output()
                .replace("recovered=true", "recovered=false")
                .replace("recovery_wait_expired=false", "recovery_wait_expired=true")
                .replace("measured_recovery_secs=12", "measured_recovery_secs=181")
        );
        let observation = ClockStageObservation::parse(&output).expect("parse");
        let report = render_live_report(&config, &observation);
        let stage = &report["stages"][0];
        assert_eq!(stage["recovery_wait_expired"], true);
        assert_eq!(
            stage["fault_refusal_text"],
            "trust preflight failed: trust evidence is stale"
        );
        assert_eq!(
            stage["deadline_refusal_text"],
            "state snapshot is stale: age=200s exceeds max_age=180s"
        );
        // Absent keys must render null, never a fake default.
        let plain =
            ClockStageObservation::parse(forward_pass_output()).expect("parse");
        let plain_report = render_live_report(&config, &plain);
        let plain_stage = &plain_report["stages"][0];
        assert_eq!(plain_stage["recovery_wait_expired"], false);
        assert!(plain_stage["fault_refusal_text"].is_null());
        assert!(plain_stage["deadline_refusal_text"].is_null());
    }
}
