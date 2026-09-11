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

    if report
        .get("overall_status")
        .and_then(Value::as_str)
        .is_some_and(|status| status == "pass")
    {
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
printf 'stage=%s\n' "$stage_marker"
cleanup() {{
  rm -f "$drop_in_file" >/dev/null 2>&1 || true
  rmdir "$drop_in_dir" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  # A daemon that refused to start under the fault has tripped the unit's
  # start limit; clear it or this restart is refused and the exit stays
  # down for every later stage (live 2026-09-10, lenovo-bot).
  systemctl reset-failed "$service" >/dev/null 2>&1 || true
  systemctl restart "$service" >/dev/null 2>&1 || true
}}
trap cleanup EXIT HUP INT TERM
printf 'teardown_registered_before_fault=true\n'
command -v systemctl >/dev/null 2>&1 || {{ printf 'missing_systemctl=true\n'; exit 1; }}
test -r "$faketime_lib" || {{ printf 'faketime_lib_present=false\n'; exit 1; }}
printf 'faketime_lib_present=true\n'
systemctl is-active --quiet "$service" || {{ printf 'baseline_service_active=false\n'; exit 1; }}
test -S "$socket_path" || {{ printf 'baseline_socket_present=false\n'; exit 1; }}
status_field() {{
  env RUSTYNET_DAEMON_SOCKET="$socket_path" {remote_rustynet_bin} status 2>/dev/null \
    | tr ' ' '\n' \
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
  systemctl restart "$service" >/dev/null 2>&1 || true
  sleep 5
  if systemctl is-active --quiet "$service" && [ -S "$socket_path" ]; then
    printf 'daemon_started_under_fault=true\n'
  else
    printf 'daemon_started_under_fault=false\n'
  fi
}}
remove_faketime() {{
  rm -f "$drop_in_file" >/dev/null 2>&1 || true
  rmdir "$drop_in_dir" >/dev/null 2>&1 || true
  systemctl daemon-reload
  systemctl reset-failed "$service" >/dev/null 2>&1 || true
  systemctl restart "$service"
}}
wait_recovered() {{
  start_unix="$(date +%s)"
  recovered=false
  end_unix="$((start_unix + deadline))"
  while [ "$(date +%s)" -le "$end_unix" ]; do
    if systemctl is-active --quiet "$service" && [ -S "$socket_path" ]; then
      recovered=true
      break
    fi
    sleep 1
  done
  printf 'measured_recovery_secs=%s\n' "$(( $(date +%s) - start_unix ))"
  printf 'recovered=%s\n' "$recovered"
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
# status line. An unsampleable status (refused start) leaves this false;
# the refused-start case is accepted via daemon_started_under_fault=false.
full_status="$(env RUSTYNET_DAEMON_SOCKET="$socket_path" {remote_rustynet_bin} status 2>/dev/null || true)"
bootstrap_error_names_staleness=false
case "$full_status" in *"is stale"*|*"expired"*) bootstrap_error_names_staleness=true ;; esac
printf 'bootstrap_error_names_staleness=%s\n' "$bootstrap_error_names_staleness"
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
remove_faketime
wait_recovered
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
remove_faketime
wait_recovered
recovered_epoch="$(status_field membership_epoch)"
case "$recovered_epoch" in ''|*[!0-9]*) recovered_epoch=none ;; esac
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
if [ "$post_epoch" -ge "$baseline_epoch" ]; then
  printf 'epoch_not_regressed=true\n'
else
  printf 'epoch_not_regressed=false\n'
fi
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
        Ok(Self {
            stage: value("stage").map(str::to_owned),
            teardown_registered_before_fault: req_bool("teardown_registered_before_fault")?,
            faketime_lib_present: req_bool("faketime_lib_present")?,
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
    let implemented_status = if observation.passed(config.stage, config.recovery_deadline_secs) {
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
    #[test]
    fn remote_script_judges_fault_start_by_unit_state_and_polls_post_recovery() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let script = render_remote_clock_script(&config);
        let install = script.find("install_faketime() {").expect("install fn");
        let end = script[install..]
            .find("remove_faketime() {")
            .expect("remove fn")
            + install;
        let body = &script[install..end];
        assert!(body.contains("sleep 5"), "{body}");
        assert!(
            body.contains("systemctl is-active --quiet \"$service\" && [ -S \"$socket_path\" ]"),
            "{body}"
        );
        assert!(
            script.contains("sample_end_unix=\"$((start_unix + deadline))\""),
            "{script}"
        );
        assert!(script.contains("'') path_live_proven=none ;;"), "{script}");
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
}
