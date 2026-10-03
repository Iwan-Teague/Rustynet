#![forbid(unsafe_code)]
// Track B Phase 28 transition: this binary still drives the deprecated
// `capture_root` shim (mirroring the daemon-fault template). Phase 29
// rewrites every chaos bin onto the new `RemoteShellHost` trait. Allow
// the deprecation lint until then so `-D warnings` stays green.
#![allow(deprecated)]

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

const CATEGORY: &str = "chaos_crash_recovery";
const DEFAULT_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
const DEFAULT_SERVICE_NAME: &str = "rustynetd.service";
// REVIEW(W5-B): These daemon-state paths are the Linux defaults taken
// from `live_lab_bin_support::assignment_bundle_path_for_platform` /
// `assignment_watermark_path_for_platform` and `crates/rustynetd/src/
// fetcher.rs` (WatermarkStore line format `assignment=<u64>`). The
// keystore directory `/var/lib/rustynet/keys` is taken from
// `collect_pubkey_hex` in the shared support module. All three are
// overridable on the CLI so a relocated lab layout can still run; flag
// for the reviewer to confirm against the live install layout.
const DEFAULT_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.assignment";
const DEFAULT_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.assignment.watermark";
const DEFAULT_KEYSTORE_DIR: &str = "/var/lib/rustynet/keys";
// The OS-managed WireGuard interface the daemon programs (crates/rustynetd/
// src/daemon.rs DEFAULT_WG_INTERFACE; same constant as the LAN-toggle stage's
// TUNNEL_IFACE). Overridable with --wg-interface for a relocated layout.
const DEFAULT_WG_INTERFACE: &str = "rustynet0";
const DEFAULT_RECOVERY_DEADLINE_SECS: u64 = 90;
const MAX_RECOVERY_DEADLINE_SECS: u64 = 90;
const DEFAULT_CRASH_ITERATIONS: u64 = 12;
const MAX_CRASH_ITERATIONS: u64 = 50;
// The watermark store keys persistence per bundle type (fetcher.rs). The
// assignment line is the release-blocking one: a torn bundle apply must
// never roll this number backward.
const WATERMARK_BUNDLE_TYPE: &str = "assignment";

fn crash_recovery_stages() -> Vec<ChaosStage> {
    vec![
        ChaosStage {
            name: "chaos_crash_during_membership_apply",
            fault: "crash daemon between verified update and membership apply",
            pass_criterion: "snapshot rolls back to prior valid state or completes atomically",
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
        },
        ChaosStage {
            name: "chaos_crash_during_tunnel_setup",
            fault: "crash after tunnel interface creation before route install",
            pass_criterion: "next reconcile cleans partial interface and killswitch holds during gap",
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
        },
        ChaosStage {
            name: "chaos_crash_during_bundle_write",
            fault: "crash during signed bundle atomic publish",
            pass_criterion: "atomic rename leaves pre-write or post-write state only",
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
        },
    ]
}

/// Which trust-state PERSISTENCE boundary the harness injects the
/// `kill -9` against. Each maps onto one declared `ChaosStage` (the
/// orchestrator selects the boundary per live invocation; the template's
/// `--fault-mode` selector is the precedent). All three drive the SAME
/// kill-on-fsync loop and the SAME atomic-recovery assertion — only the
/// file under inspection and the implemented stage index differ. Defaults
/// to `BundleWrite` (the release-blocking torn-bundle / watermark-
/// downgrade boundary) so a caller that omits `--persistence-boundary`
/// exercises the most dangerous case.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum PersistenceBoundary {
    /// Crash between a verified membership update and its on-disk apply
    /// (stages[0]). Inspects the bundle file for atomic old-or-new.
    MembershipApply,
    /// Crash after tunnel-interface creation, before route install
    /// (stages[1]). Inspects the bundle file the reconcile re-derives
    /// from; killswitch must hold across the gap.
    TunnelSetup,
    /// Crash during the signed-bundle atomic publish (stages[2]). The
    /// release-blocking boundary: the watermark must NEVER regress and a
    /// truncated/partial bundle must be rejected on restart.
    #[default]
    BundleWrite,
}

impl PersistenceBoundary {
    /// Index into [`crash_recovery_stages`] that this boundary proves.
    fn stage_index(self) -> usize {
        match self {
            PersistenceBoundary::MembershipApply => 0,
            PersistenceBoundary::TunnelSetup => 1,
            PersistenceBoundary::BundleWrite => 2,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            PersistenceBoundary::MembershipApply => "membership-apply",
            PersistenceBoundary::TunnelSetup => "tunnel-setup",
            PersistenceBoundary::BundleWrite => "bundle-write",
        }
    }
}

/// Map the `--persistence-boundary` argument onto [`PersistenceBoundary`],
/// rejecting any unknown value so a typo can never silently fall back to
/// a different (less dangerous) boundary.
fn parse_persistence_boundary(value: &str) -> Result<PersistenceBoundary, String> {
    match value {
        "membership-apply" => Ok(PersistenceBoundary::MembershipApply),
        "tunnel-setup" => Ok(PersistenceBoundary::TunnelSetup),
        "bundle-write" => Ok(PersistenceBoundary::BundleWrite),
        other => Err(format!(
            "invalid --persistence-boundary: {other} (expected one of: membership-apply, tunnel-setup, bundle-write)"
        )),
    }
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
    bundle_path: String,
    watermark_path: String,
    keystore_dir: String,
    wg_interface: String,
    recovery_deadline_secs: u64,
    crash_iterations: u64,
    boundary: PersistenceBoundary,
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
            bundle_path: DEFAULT_BUNDLE_PATH.to_owned(),
            watermark_path: DEFAULT_WATERMARK_PATH.to_owned(),
            keystore_dir: DEFAULT_KEYSTORE_DIR.to_owned(),
            wg_interface: DEFAULT_WG_INTERFACE.to_owned(),
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
            crash_iterations: DEFAULT_CRASH_ITERATIONS,
            boundary: PersistenceBoundary::default(),
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
                "--target-host" | "--exit-host" => {
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
                "--bundle-path" => {
                    idx += 1;
                    config.bundle_path = required_value(&args, idx, "--bundle-path")?;
                }
                "--watermark-path" => {
                    idx += 1;
                    config.watermark_path = required_value(&args, idx, "--watermark-path")?;
                }
                "--keystore-dir" => {
                    idx += 1;
                    config.keystore_dir = required_value(&args, idx, "--keystore-dir")?;
                }
                "--wg-interface" => {
                    idx += 1;
                    config.wg_interface = required_value(&args, idx, "--wg-interface")?;
                }
                "--recovery-deadline-secs" => {
                    idx += 1;
                    config.recovery_deadline_secs =
                        required_value(&args, idx, "--recovery-deadline-secs")?
                            .parse::<u64>()
                            .map_err(|err| format!("invalid --recovery-deadline-secs: {err}"))?;
                }
                "--crash-iterations" => {
                    idx += 1;
                    config.crash_iterations = required_value(&args, idx, "--crash-iterations")?
                        .parse::<u64>()
                        .map_err(|err| format!("invalid --crash-iterations: {err}"))?;
                }
                "--persistence-boundary" => {
                    idx += 1;
                    config.boundary = parse_persistence_boundary(&required_value(
                        &args,
                        idx,
                        "--persistence-boundary",
                    )?)?;
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
        ensure_safe_token("bundle path", &self.bundle_path)?;
        ensure_safe_token("watermark path", &self.watermark_path)?;
        ensure_safe_token("keystore dir", &self.keystore_dir)?;
        ensure_safe_token("wg interface", &self.wg_interface)?;
        if self.recovery_deadline_secs == 0
            || self.recovery_deadline_secs > MAX_RECOVERY_DEADLINE_SECS
        {
            return Err(format!(
                "recovery deadline must be 1..={MAX_RECOVERY_DEADLINE_SECS} seconds"
            ));
        }
        if self.crash_iterations == 0 || self.crash_iterations > MAX_CRASH_ITERATIONS {
            return Err(format!(
                "crash iterations must be 1..={MAX_CRASH_ITERATIONS}"
            ));
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
        return run_category(ChaosConfig {
            category: CATEGORY,
            report_path: config.report_path,
            log_path: config.log_path,
            dry_run: true,
            git_commit: config.git_commit,
            stages: crash_recovery_stages(),
        });
    }

    let mut logger = Logger::new(&config.log_path)?;
    logger.line("[chaos-crash-recovery] starting live crash-recovery fault injection")?;
    let report = run_live_crash_recovery(&config, &mut logger)?;
    write_file(
        &config.report_path,
        &serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialise crash recovery report failed: {err}"))?,
    )?;
    logger.line(
        format!(
            "[chaos-crash-recovery] report written to {}",
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
        Err("crash recovery chaos stage failed".to_owned())
    }
}

fn run_live_crash_recovery(config: &Config, logger: &mut Logger) -> Result<Value, String> {
    let target = required_option(config.target_host.as_deref(), "--target-host")?;
    let identity = required_path(config.ssh_identity_file.as_deref(), "--ssh-identity-file")?;
    let known_hosts = required_path(config.known_hosts_file.as_deref(), "--known-hosts-file")?;

    logger.line("[chaos-crash-recovery] verifying sudo and baseline daemon socket")?;
    verify_sudo(identity, known_hosts, target)?;
    wait_for_daemon_socket(identity, known_hosts, target, &config.socket_path, 10, 2)?;

    logger.line(
        format!(
            "[chaos-crash-recovery] injecting kill -9 at persistence boundary {}",
            config.boundary.as_str()
        )
        .as_str(),
    )?;
    let fault_script = render_remote_crash_script(config);
    let output = capture_root(identity, known_hosts, target, &fault_script)?;
    logger.block(output.as_str())?;

    let observation = CrashStageObservation::parse(&output)?;
    Ok(render_live_report(config, &observation))
}

/// Remote kill-on-fsync injection script. Mirrors the daemon-fault
/// template's prologue (mktemp work_dir, `trap cleanup EXIT HUP INT TERM`
/// registered BEFORE the fault so the daemon is never left dead on any
/// abort path — including the SSH session dying, where a POSIX shell may
/// not run an EXIT-only trap; `teardown_registered_before_fault` marker,
/// preflight that the service is active + socket present). Divergences vs the daemon-fault path:
///   * NO tcpdump leak capture — this boundary asserts on-disk trust-state
///     atomicity, not plaintext egress; the leak check is not-applicable.
///   * The fault is a TIGHT `kill -9` LOOP (kill -> bounded restart-wait ->
///     re-kill) timed to land mid trust-state write (kill-on-fsync style,
///     research F17/F18), driving an assignment refresh between kills so a
///     bundle/watermark write is in flight when SIGKILL arrives.
///   * It records the watermark BEFORE the loop and AFTER recovery, and
///     records whether the on-disk bundle is present / parseable / non-empty
///     so the Rust side can prove atomic old-or-new and no watermark
///     downgrade.
fn render_remote_crash_script(config: &Config) -> String {
    let remote_rustynet_bin = shell_quote(REMOTE_RUSTYNET_BIN);
    let service = shell_quote(&config.service_name);
    let socket_path = shell_quote(&config.socket_path);
    let bundle_path = shell_quote(&config.bundle_path);
    let watermark_path = shell_quote(&config.watermark_path);
    let keystore_dir = shell_quote(&config.keystore_dir);
    let wg_interface = shell_quote(&config.wg_interface);
    let watermark_key = shell_quote(WATERMARK_BUNDLE_TYPE);
    let deadline = config.recovery_deadline_secs;
    let iterations = config.crash_iterations;
    let boundary = shell_quote(config.boundary.as_str());

    // The remote helper emits `key=value` lines parsed by
    // CrashStageObservation::parse. read_watermark prints the numeric
    // assignment watermark (or `absent`) for the well-known bundle key;
    // classify_bundle classifies the bundle file as absent|empty|present;
    // bundle_parse_ok proves it still parses as a signed bundle (a torn
    // write would leave a half-line that fails the `version=1` + trailing
    // `signature=` shape check) — a truncated bundle MUST be rejected, not
    // silently treated as valid.
    format!(
        r#"set -eu
# RSA-0080: a non-login shell omits the sbin directories where ip/systemctl live.
PATH="/usr/local/sbin:/usr/sbin:/sbin:${{PATH:-/usr/local/bin:/usr/bin:/bin}}"; export PATH
service={service}
socket_path={socket_path}
bundle_path={bundle_path}
watermark_path={watermark_path}
keystore_dir={keystore_dir}
wg_interface={wg_interface}
watermark_key={watermark_key}
boundary={boundary}
deadline={deadline}
iterations={iterations}
work_dir="$(mktemp -d /tmp/rustynet-chaos-crash-recovery.XXXXXX)"
cleanup() {{
  # The kill loop trips the unit's start limiter once >= StartLimitBurst
  # kills accumulate; clear it or this teardown start is refused and the
  # exit stays down for every later stage (live 2026-09-10, lenovo-bot).
  systemctl reset-failed "$service" >/dev/null 2>&1 || true
  systemctl start "$service" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}}
trap cleanup EXIT HUP INT TERM
printf 'teardown_registered_before_fault=true\n'
command -v systemctl >/dev/null 2>&1 || {{ printf 'missing_systemctl=true\n'; exit 1; }}
systemctl is-active --quiet "$service" || {{ printf 'baseline_service_active=false\n'; exit 1; }}
test -S "$socket_path" || {{ printf 'baseline_socket_present=false\n'; exit 1; }}

read_watermark() {{
  if [ -f "$watermark_path" ]; then
    value="$(awk -F= -v k="$watermark_key" '$1==k {{ print $2; found=1 }} END {{ if (!found) print "absent" }}' "$watermark_path" 2>/dev/null || true)"
    case "$value" in ''|*[!0-9]*) printf 'absent' ;; *) printf '%s' "$value" ;; esac
  else
    printf 'absent'
  fi
}}

classify_bundle() {{
  if [ ! -e "$bundle_path" ]; then
    printf 'absent'
  elif [ ! -s "$bundle_path" ]; then
    printf 'empty'
  else
    printf 'present'
  fi
}}

# A signed bundle persisted by the daemon starts with `version=1` and ends
# with a `signature=` line (see crates/rustynetd/src/fetcher.rs bundle
# parse). A torn atomic publish leaves either a missing header or a missing
# trailing signature line; either MUST be rejected on restart. `absent` is
# a valid (pre-write) atomic state, so it parses-ok by definition.
bundle_parse_ok() {{
  if [ ! -e "$bundle_path" ]; then
    printf 'true'
    return
  fi
  if [ ! -s "$bundle_path" ]; then
    printf 'false'
    return
  fi
  head_ok=false
  sig_ok=false
  if head -n 1 "$bundle_path" 2>/dev/null | grep -q '^version=1$'; then head_ok=true; fi
  if grep -q '^signature=' "$bundle_path" 2>/dev/null; then sig_ok=true; fi
  if [ "$head_ok" = true ] && [ "$sig_ok" = true ]; then
    printf 'true'
  else
    printf 'false'
  fi
}}

# Keystore residue check: a crash mid keystore write must never leave a
# zero-length private key file (that would be a torn key write). Report the
# count of empty regular files under the keystore dir.
keystore_empty_files() {{
  if [ -d "$keystore_dir" ]; then
    find "$keystore_dir" -maxdepth 1 -type f -empty 2>/dev/null | wc -l | tr -d '[:space:]'
  else
    printf '0'
  fi
}}

watermark_before="$(read_watermark)"
bundle_before="$(classify_bundle)"
printf 'persistence_boundary=%s\n' "$boundary"
printf 'watermark_before=%s\n' "$watermark_before"
printf 'bundle_before=%s\n' "$bundle_before"

start_unix="$(date +%s)"
printf 'fault_signal=KILL\n'
printf 'crash_iterations=%s\n' "$iterations"
# Tight kill-on-fsync loop: nudge the daemon into a trust-state write
# (systemctl reload re-reads signed state / triggers a reconcile+refresh),
# then SIGKILL it almost immediately so the write is interrupted in flight.
i=0
killed=0
resets=0
while [ "$i" -lt "$iterations" ]; do
  # The unit carries StartLimitBurst=5/60s (pinned by service_hardening);
  # a tight kill loop trips systemd's rate limiter, which would otherwise
  # be what this stage measures instead of the daemon's own recovery. Clear
  # it per iteration and report how often it would have engaged.
  if systemctl reset-failed "$service" >/dev/null 2>&1; then resets="$(( resets + 1 ))"; fi
  systemctl start "$service" >/dev/null 2>&1 || true
  # Best-effort kick to drive a fresh trust-state apply; ignore failure so
  # the loop still SIGKILLs even if reload is unsupported.
  systemctl reload "$service" >/dev/null 2>&1 || systemctl kill -s HUP "$service" >/dev/null 2>&1 || true
  systemctl kill -s KILL "$service" >/dev/null 2>&1 || true
  killed="$(( killed + 1 ))"
  i="$(( i + 1 ))"
done
printf 'observed_kill_count=%s\n' "$killed"

# Restart and wait for atomic recovery within the deadline (clear the
# start-limit state left by the final kill first, same rationale as above).
if systemctl reset-failed "$service" >/dev/null 2>&1; then resets="$(( resets + 1 ))"; fi
printf 'start_limit_resets=%s\n' "$resets"
systemctl start "$service" >/dev/null 2>&1 || true
recovered=false
end_unix="$((start_unix + deadline))"
while [ "$(date +%s)" -le "$end_unix" ]; do
  if systemctl is-active --quiet "$service" && [ -S "$socket_path" ]; then
    recovered=true
    break
  fi
  sleep 1
done
measured_recovery_secs="$(( $(date +%s) - start_unix ))"

watermark_after="$(read_watermark)"
bundle_after="$(classify_bundle)"
bundle_parse_after="$(bundle_parse_ok)"
keystore_empty_after="$(keystore_empty_files)"

# Capture the daemon's single-line status AND the OS WireGuard interface's
# per-peer latest-handshake timestamps (`wg show <iface> latest-handshakes`;
# the whole script runs as root via capture_root's `sudo -n sh -lc`). The
# Rust side then applies a deterministic per-peer criterion: EVERY peer on
# the interface must show a handshake at or after recovery_start_unix (a
# post-crash rekey), AND the status line must report bootstrap_error=none,
# restricted_safe_mode=false and at least one live peer. The old
# path_live_proven=true requirement was a phase lottery — it demands every
# peer be fresh within a 30 s window at ONE sampling instant while peers
# only rekey every ~120 s (triage: out/rustynet-b76-u32-crash-recovery-
# triage/REPORT.md) — and the old early-break glob listed the status
# fields in an order that never occurs in the real line (the real line
# puts restricted_safe_mode/bootstrap_error BEFORE the path_* fields), so
# every run burned the full window. Per-token greps are order-independent,
# and the wg rekey condition is monotone (timestamps only advance), so the
# loop breaks as soon as the full criterion first holds.
# wg_peer_handshakes format: "<count> <peer>:<epoch> ..." (count first so
# a silently-dropped or duplicated line is detectable = fail closed).
mesh_status_line=""
mesh_poll_secs=0
recovery_start_unix="$start_unix"
wg_interface_present=false
wg_peer_handshakes="0 "
if [ "$recovered" = true ]; then
  # Recovery (active unit + socket) precedes mesh convergence by seconds:
  # re-handshake, signed-state apply, path proof. Poll the status line and
  # the wg per-peer handshakes until every peer has rekeyed since
  # recovery_start_unix, bounded by the same deadline, instead of sampling
  # the instant the socket appears (live 2026-09-11: recovered in 8 s,
  # sampled unconverged, stage failed). Peers rekey every ~120 s
  # (REKEY_AFTER_TIME) and the OS interface preserves pre-crash rekey
  # phase across the daemon restart, so within three deadlines (270 s at
  # the 90 s default) a healthy mesh rekeys every peer deterministically
  # while a dead peer never does (fail closed at the deadline).
  mesh_end_unix="$((start_unix + deadline * 3))"
  while :; do
    mesh_status_line="$(env RUSTYNET_DAEMON_SOCKET="$socket_path" {remote_rustynet_bin} status 2>/dev/null | tr '\n' ' ' | head -c 8192 || true)"
    if [ -d "/sys/class/net/$wg_interface" ]; then wg_interface_present=true; fi
    wg_raw="$(wg show "$wg_interface" latest-handshakes 2>/dev/null || true)"
    wg_peer_handshakes="$(printf '%s\n' "$wg_raw" | awk '{{ if (NF == 0) next; gsub(/\t/, ":"); n++; if (n > 1) pairs = pairs " "; pairs = pairs $0 }} END {{ printf "%d %s", n, pairs }}')"
    wg_rekeyed="$(printf '%s\n' "$wg_raw" | awk -v start="$start_unix" '{{ if (NF == 0) next; n++; line = $0; gsub(/\t/, ":", line); split(line, p, ":"); if (p[1] == "" || p[3] != "" || p[2] !~ /^[0-9]+$/) bad = 1; else if (p[2] + 0 < start + 0) stale = 1 }} END {{ if (n > 0 && !bad && !stale) printf "true"; else printf "false" }}')"
    if [ "$wg_interface_present" = true ] \
       && [ "$wg_rekeyed" = true ] \
       && printf '%s\n' "$mesh_status_line" | grep -q 'restricted_safe_mode=false' \
       && printf '%s\n' "$mesh_status_line" | grep -q 'bootstrap_error=none' \
       && printf '%s\n' "$mesh_status_line" | grep -Eq 'path_live_peer_count=[1-9]'
    then
      break
    fi
    [ "$(date +%s)" -ge "$mesh_end_unix" ] && break
    sleep 2
  done
  mesh_poll_secs="$(( $(date +%s) - start_unix ))"
fi
printf 'mesh_poll_secs=%s\n' "$mesh_poll_secs"
printf 'recovered=%s\n' "$recovered"
printf 'measured_recovery_secs=%s\n' "$measured_recovery_secs"
printf 'watermark_after=%s\n' "$watermark_after"
printf 'bundle_after=%s\n' "$bundle_after"
printf 'bundle_parse_after=%s\n' "$bundle_parse_after"
printf 'keystore_empty_files_after=%s\n' "$keystore_empty_after"
printf 'mesh_status_line=%s\n' "$mesh_status_line"
printf 'recovery_start_unix=%s\n' "$recovery_start_unix"
printf 'wg_interface_present=%s\n' "$wg_interface_present"
printf 'wg_peer_handshakes=%s\n' "$wg_peer_handshakes"
"#
    )
}

/// On-disk watermark value observed before/after the crash loop. `absent`
/// (no watermark file / no assignment line yet) is a legitimate atomic
/// pre-write state and is treated as the additive identity (0) for the
/// regression check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WatermarkSample {
    Absent,
    Value(u64),
}

impl WatermarkSample {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "absent" => Ok(WatermarkSample::Absent),
            other => other
                .parse::<u64>()
                .map(WatermarkSample::Value)
                .map_err(|err| format!("invalid watermark sample {other:?}: {err}")),
        }
    }

    fn as_u64(self) -> u64 {
        match self {
            WatermarkSample::Absent => 0,
            WatermarkSample::Value(value) => value,
        }
    }
}

/// Classification of the on-disk bundle file after the crash loop. A
/// signed bundle is atomically published, so only `Absent` (pre-write) or
/// a fully `Present` (post-write) file is acceptable; an `Empty` file is a
/// torn write and MUST fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BundleState {
    Absent,
    Empty,
    Present,
}

impl BundleState {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "absent" => Ok(BundleState::Absent),
            "empty" => Ok(BundleState::Empty),
            "present" => Ok(BundleState::Present),
            other => Err(format!("invalid bundle state {other:?}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            BundleState::Absent => "absent",
            BundleState::Empty => "empty",
            BundleState::Present => "present",
        }
    }
}

/// PURE EVALUATOR (1/3): replay-watermark regression detector. Returns
/// true when the post-crash on-disk watermark is STRICTLY LOWER than the
/// pre-crash watermark — the release-blocking failure: a torn bundle apply
/// that downgrades the anti-replay watermark. `absent` collapses to 0, so
/// a watermark that goes from a real value back to `absent` is a
/// regression too.
fn watermark_regressed(before: WatermarkSample, after: WatermarkSample) -> bool {
    after.as_u64() < before.as_u64()
}

/// PURE EVALUATOR (2/3): atomic-state verdict. The on-disk trust state is
/// atomic old-or-new iff:
///   * the watermark did NOT regress, AND
///   * the bundle file is Absent (pre-write) or Present-and-parseable
///     (post-write) — never Empty/torn, never present-but-unparseable
///     (truncated/partial bundle that must be rejected), AND
///   * the keystore left no zero-length (torn) key file behind.
///
/// Returns true only when ALL hold (fail-closed: any unmet condition =
/// not-atomic = fail).
fn atomic_state_verdict(
    watermark_before: WatermarkSample,
    watermark_after: WatermarkSample,
    bundle_after: BundleState,
    bundle_parse_ok: bool,
    keystore_empty_files: u64,
) -> bool {
    if watermark_regressed(watermark_before, watermark_after) {
        return false;
    }
    let bundle_atomic = match bundle_after {
        BundleState::Absent => true,
        BundleState::Present => bundle_parse_ok,
        BundleState::Empty => false,
    };
    bundle_atomic && keystore_empty_files == 0
}

/// PURE EVALUATOR (3/3), status half: reads the daemon's single-line
/// `node_id=... state=... restricted_safe_mode=... bootstrap_error=...
/// path_mode=... path_live_proven=... path_live_peer_count=...` status
/// (crates/rustynetd/src/daemon.rs) and returns true iff the status half
/// of the recovery criterion holds: `path_live_peer_count` >= 1 AND
/// `bootstrap_error=none` AND `restricted_safe_mode=false`.
/// `path_live_proven` is deliberately NOT required here: it demands every
/// programmed peer hold a handshake fresher than the daemon's 30 s
/// freshness window at ONE sampling instant, while WireGuard peers only
/// rekey every ~120 s — the per-peer, deterministic half of the criterion
/// is [`wg_mesh_rekeyed`] over the OS interface's handshakes instead
/// (triage: out/rustynet-b76-u32-crash-recovery-triage/REPORT.md).
/// Missing / malformed status => not healthy (fail-closed).
fn parse_mesh_converged(status_line: &str) -> bool {
    let field = |key: &str| -> Option<&str> {
        status_line.split_whitespace().find_map(|token| {
            token
                .split_once('=')
                .and_then(|(found, value)| (found == key).then_some(value))
        })
    };
    let live_peers = field("path_live_peer_count")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    // bootstrap_error / restricted_safe_mode may be absent on very old
    // status formats; treat absence as fail-closed for those fields.
    let bootstrap_clean = field("bootstrap_error") == Some("none");
    let not_restricted = field("restricted_safe_mode") == Some("false");
    live_peers >= 1 && bootstrap_clean && not_restricted
}

/// PURE EVALUATOR (4/5): parse the remote script's flattened
/// `wg show <iface> latest-handshakes` sample. The script emits
/// `"<count> <peer-key>:<epoch-seconds> ..."` — count first, each wg
/// output line flattened by replacing its TAB with `:`. Returns the
/// per-peer `(peer key, latest handshake unix)` pairs, or Err on ANY
/// malformation (missing/invalid count, token without a colon, empty
/// peer key, extra colon-separated field, non-numeric epoch, or a pair
/// count that disagrees with the declared count). An Err is fail-closed
/// at the call site; an empty peer list is Ok(vec![]) and fails the
/// criterion downstream (no peers listed => no proof => fail).
fn parse_wg_peer_handshakes(raw: &str) -> Result<Vec<(String, u64)>, String> {
    let mut tokens = raw.split_whitespace();
    let count = tokens
        .next()
        .ok_or_else(|| "empty wg handshake sample".to_owned())?
        .parse::<usize>()
        .map_err(|err| format!("invalid wg handshake count: {err}"))?;
    let peers = tokens
        .map(|token| {
            let (key, ts) = token.split_once(':').ok_or_else(|| {
                format!("malformed wg handshake token {token:?}: expected <peer>:<epoch>")
            })?;
            if key.is_empty() {
                return Err(format!(
                    "malformed wg handshake token {token:?}: empty peer key"
                ));
            }
            let ts = ts.parse::<u64>().map_err(|err| {
                format!("malformed wg handshake token {token:?}: invalid epoch: {err}")
            })?;
            Ok((key.to_owned(), ts))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if peers.len() != count {
        return Err(format!(
            "wg handshake sample declared {count} peers but carried {}",
            peers.len()
        ));
    }
    Ok(peers)
}

/// PURE EVALUATOR (5/5), wg half: true iff at least one peer is listed and
/// EVERY peer's latest handshake is at or after `recovery_start_unix` — a
/// post-crash rekey per peer. `>=` semantics: a handshake stamped exactly
/// at recovery start counts (the poll samples whole seconds).
fn all_peers_rekeyed_since(peers: &[(String, u64)], recovery_start_unix: u64) -> bool {
    !peers.is_empty() && peers.iter().all(|(_, ts)| *ts >= recovery_start_unix)
}

/// Fail-closed wrapper over [`parse_wg_peer_handshakes`] +
/// [`all_peers_rekeyed_since`]: malformed output, an unknown recovery
/// start (0) or no peers all fail closed.
fn wg_mesh_rekeyed(wg_peer_handshakes: &str, recovery_start_unix: u64) -> bool {
    recovery_start_unix > 0
        && parse_wg_peer_handshakes(wg_peer_handshakes)
            .map(|peers| all_peers_rekeyed_since(&peers, recovery_start_unix))
            .unwrap_or(false)
}

/// The full mesh-recovery criterion (PURE). True iff:
///   * `recovery_start_unix` is a real timestamp (0 = unknown => fail
///     closed), AND
///   * the OS WireGuard interface was present on the target (missing
///     interface => no handshake evidence => fail closed), AND
///   * the status half holds ([`parse_mesh_converged`]), AND
///   * every peer listed by `wg show <iface> latest-handshakes` rekeyed
///     at/after recovery start ([`wg_mesh_rekeyed`]).
fn mesh_recovered(
    status_line: &str,
    wg_interface_present: bool,
    wg_peer_handshakes: &str,
    recovery_start_unix: u64,
) -> bool {
    recovery_start_unix > 0
        && wg_interface_present
        && parse_mesh_converged(status_line)
        && wg_mesh_rekeyed(wg_peer_handshakes, recovery_start_unix)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CrashStageObservation {
    teardown_registered_before_fault: bool,
    persistence_boundary: String,
    observed_kill_count: u64,
    /// Seconds from the start of the recovery window (the same origin as
    /// `measured_recovery_secs`) until the mesh status reported a live-proven,
    /// unrestricted path — or the deadline — so the report shows convergence
    /// time, not just socket-recovery time.
    mesh_poll_secs: u64,
    /// How many times the loop cleared systemd's start-limit state
    /// (`systemctl reset-failed`); reviewers read it to see how often the
    /// unit's own rate limiter would have engaged.
    start_limit_resets: u64,
    recovered: bool,
    measured_recovery_secs: u64,
    watermark_before: WatermarkSample,
    watermark_after: WatermarkSample,
    bundle_before: BundleState,
    bundle_after: BundleState,
    bundle_parse_ok: bool,
    keystore_empty_files: u64,
    /// Daemon `rustynet status` single line captured after recovery (empty
    /// when recovery failed / status was unavailable). Fed to
    /// [`parse_mesh_converged`] as the status half of the criterion.
    mesh_status_line: String,
    /// Unix second the fault loop started (the origin of the recovery
    /// window). Every peer's post-crash handshake must be at/after this
    /// instant. 0 = unknown => fail closed.
    recovery_start_unix: u64,
    /// Whether the OS WireGuard interface existed at the final poll
    /// (checked per poll via /sys/class/net). False => fail closed.
    wg_interface_present: bool,
    /// Flattened `wg show <iface> latest-handshakes` sample at the final
    /// poll: `"<count> <peer>:<epoch> ..."`. Parsed by
    /// [`parse_wg_peer_handshakes`]; malformed/empty fails closed.
    wg_peer_handshakes: String,
}

impl CrashStageObservation {
    fn parse(output: &str) -> Result<Self, String> {
        let value = |key: &str| -> Option<&str> {
            output.lines().find_map(|line| {
                line.split_once('=')
                    .and_then(|(found, raw)| (found == key).then_some(raw.trim()))
            })
        };
        let parse_bool = |key: &str| -> Result<bool, String> {
            match value(key) {
                Some("true") => Ok(true),
                Some("false") => Ok(false),
                Some(other) => Err(format!("invalid boolean for {key}: {other}")),
                None => Err(format!("missing {key} in crash recovery output")),
            }
        };
        let parse_u64 = |key: &str| -> Result<u64, String> {
            value(key)
                .ok_or_else(|| format!("missing {key} in crash recovery output"))?
                .parse::<u64>()
                .map_err(|err| format!("invalid integer for {key}: {err}"))
        };
        let parse_str = |key: &str| -> Result<String, String> {
            value(key)
                .map(str::to_owned)
                .ok_or_else(|| format!("missing {key} in crash recovery output"))
        };

        Ok(Self {
            teardown_registered_before_fault: parse_bool("teardown_registered_before_fault")?,
            persistence_boundary: parse_str("persistence_boundary")?,
            observed_kill_count: parse_u64("observed_kill_count")?,
            start_limit_resets: parse_u64("start_limit_resets")?,
            mesh_poll_secs: parse_u64("mesh_poll_secs")?,
            recovered: parse_bool("recovered")?,
            measured_recovery_secs: parse_u64("measured_recovery_secs")?,
            watermark_before: WatermarkSample::parse(&parse_str("watermark_before")?)?,
            watermark_after: WatermarkSample::parse(&parse_str("watermark_after")?)?,
            bundle_before: BundleState::parse(&parse_str("bundle_before")?)?,
            bundle_after: BundleState::parse(&parse_str("bundle_after")?)?,
            bundle_parse_ok: parse_bool("bundle_parse_after")?,
            keystore_empty_files: parse_u64("keystore_empty_files_after")?,
            // A missing/empty mesh status line is treated as not-converged
            // (fail-closed), so it is not a hard parse error.
            mesh_status_line: value("mesh_status_line").unwrap_or("").to_owned(),
            // Script and bin ship together (the bin renders the script), so
            // these are hard-required: absence means an old/corrupted
            // remote output and must fail the stage at parse, not silently
            // skip the per-peer criterion.
            recovery_start_unix: parse_u64("recovery_start_unix")?,
            wg_interface_present: parse_bool("wg_interface_present")?,
            wg_peer_handshakes: parse_str("wg_peer_handshakes")?,
        })
    }

    /// Whether the daemon converged to a healthy, fully-rekeyed mesh after
    /// recovery. Pure delegation to [`mesh_recovered`] over the captured
    /// status line, wg interface presence, per-peer handshake sample and
    /// recovery start.
    fn mesh_converged(&self) -> bool {
        mesh_recovered(
            &self.mesh_status_line,
            self.wg_interface_present,
            &self.wg_peer_handshakes,
            self.recovery_start_unix,
        )
    }

    /// Stage pass-check. Fail-closed conjunction: teardown was registered
    /// before the fault, at least one SIGKILL actually landed (a never-run
    /// injection is a FAIL, not a pass), the daemon recovered within the
    /// deadline, the on-disk trust state is atomic old-or-new with no
    /// watermark downgrade and no torn bundle/keystore residue, AND the
    /// daemon re-handshook + re-applied signed state to a healthy mesh.
    fn passed(&self, deadline_secs: u64) -> bool {
        self.teardown_registered_before_fault
            && self.observed_kill_count >= 1
            && self.recovered
            && self.measured_recovery_secs <= deadline_secs
            && atomic_state_verdict(
                self.watermark_before,
                self.watermark_after,
                self.bundle_after,
                self.bundle_parse_ok,
                self.keystore_empty_files,
            )
            && self.mesh_converged()
    }
}

fn render_live_report(config: &Config, observation: &CrashStageObservation) -> Value {
    let implemented_index = config.boundary.stage_index();
    let watermark_regressed_flag =
        watermark_regressed(observation.watermark_before, observation.watermark_after);
    let implemented_status = if observation.passed(config.recovery_deadline_secs) {
        "pass"
    } else {
        "fail"
    };
    let stages = crash_recovery_stages()
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
                    "start_limit_resets": observation.start_limit_resets,
                    "mesh_poll_secs": observation.mesh_poll_secs,
                    "plaintext_leak_check": "not-applicable-persistence-boundary",
                    "persistence_boundary": observation.persistence_boundary,
                    "observed_kill_count": observation.observed_kill_count,
                    "teardown_registered_before_fault": observation.teardown_registered_before_fault,
                    "recovered": observation.recovered,
                    "watermark_before": watermark_sample_json(observation.watermark_before),
                    "watermark_after": watermark_sample_json(observation.watermark_after),
                    "watermark_regressed": watermark_regressed_flag,
                    "bundle_before": observation.bundle_before.as_str(),
                    "bundle_after": observation.bundle_after.as_str(),
                    "bundle_parse_ok": observation.bundle_parse_ok,
                    "keystore_empty_files": observation.keystore_empty_files,
                    "atomic_state": atomic_state_verdict(
                        observation.watermark_before,
                        observation.watermark_after,
                        observation.bundle_after,
                        observation.bundle_parse_ok,
                        observation.keystore_empty_files,
                    ),
                    "mesh_converged": observation.mesh_converged(),
                    "recovery_start_unix": observation.recovery_start_unix,
                    "wg_interface": config.wg_interface,
                    "wg_interface_present": observation.wg_interface_present,
                    "wg_peer_handshakes_raw": observation.wg_peer_handshakes,
                    "wg_peers": wg_peers_evidence_json(observation),
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
                    "summary": "not implemented in this crash-recovery live slice",
                })
            }
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": CATEGORY,
        "overall_status": implemented_status,
        "summary": format!(
            "kill -9 injected at the {} trust-state persistence boundary; on-restart state asserted atomic old-or-new with no watermark downgrade",
            config.boundary.as_str()
        ),
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
            "production_state_mutation": true,
            "teardown_registered_before_fault": observation.teardown_registered_before_fault,
            "watermark_regressed": watermark_regressed_flag,
            "torn_bundle_rejected": observation.bundle_after != BundleState::Empty
                && (observation.bundle_after != BundleState::Present || observation.bundle_parse_ok),
            "recovered_within_deadline": observation.recovered
                && observation.measured_recovery_secs <= config.recovery_deadline_secs,
            "mesh_converged": observation.mesh_converged(),
            "wg_all_peers_rekeyed_since_recovery": wg_mesh_rekeyed(
                &observation.wg_peer_handshakes,
                observation.recovery_start_unix,
            ),
        }
    })
}

/// Per-peer handshake evidence for the report JSON: one row per peer with
/// its latest-handshake timestamp and whether it rekeyed at/after the
/// recovery start. A malformed sample is reported as a parse error (the
/// stage verdict already failed closed via [`wg_mesh_rekeyed`]).
fn wg_peers_evidence_json(observation: &CrashStageObservation) -> Value {
    match parse_wg_peer_handshakes(&observation.wg_peer_handshakes) {
        Ok(peers) => json!(peers
            .iter()
            .map(|(peer, ts)| json!({
                "peer": peer,
                "latest_handshake_unix": ts,
                "rekeyed_since_recovery":
                    observation.recovery_start_unix > 0 && *ts >= observation.recovery_start_unix,
            }))
            .collect::<Vec<_>>()),
        Err(err) => json!({ "parse_error": err }),
    }
}

fn watermark_sample_json(sample: WatermarkSample) -> Value {
    match sample {
        WatermarkSample::Absent => json!("absent"),
        WatermarkSample::Value(value) => json!(value),
    }
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn required_option<'a>(value: Option<&'a str>, flag: &str) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("{flag} is required"))
}

fn required_path<'a>(value: Option<&'a Path>, flag: &str) -> Result<&'a Path, String> {
    value.ok_or_else(|| format!("{flag} is required"))
}

fn print_usage() {
    eprintln!(
        "usage: {CATEGORY} [--dry-run] [--target-host <user@host>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--socket-path <path>] [--service-name <name>] [--bundle-path <path>] [--watermark-path <path>] [--keystore-dir <path>] [--wg-interface <name>] [--recovery-deadline-secs <secs>] [--crash-iterations <n>] [--persistence-boundary <membership-apply|tunnel-setup|bundle-write>] [--report-path <path>] [--log-path <path>] [--git-commit <sha>]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, String> {
        Config::parse(args.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn dry_run_allows_no_live_targets() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        assert!(config.dry_run);
        assert!(config.target_host.is_none());
        assert_eq!(config.boundary, PersistenceBoundary::BundleWrite);
    }

    #[test]
    fn live_mode_requires_target_and_identity() {
        let err = parse(&[]).expect_err("live mode should require target host");
        assert!(err.contains("--target-host"));
        let err = parse(&["--target-host", "debian@192.0.2.10"])
            .expect_err("live mode should require identity");
        assert!(err.contains("--ssh-identity-file"));
    }

    #[test]
    fn parser_rejects_shell_metacharacters() {
        let err = parse(&["--dry-run", "--service-name", "rustynetd.service;reboot"])
            .expect_err("service shell metacharacter must reject");
        assert!(err.contains("service name"));
        let err = parse(&["--dry-run", "--bundle-path", "/var/lib/rustynet/b $(id)"])
            .expect_err("bundle path shell metacharacter must reject");
        assert!(err.contains("bundle path"));
    }

    #[test]
    fn parser_bounds_recovery_deadline_to_transport_timeout() {
        let err = parse(&["--dry-run", "--recovery-deadline-secs", "91"])
            .expect_err("deadline above max must reject");
        assert!(err.contains("recovery deadline"));
    }

    #[test]
    fn parser_bounds_crash_iterations() {
        let err = parse(&["--dry-run", "--crash-iterations", "0"])
            .expect_err("zero iterations must reject");
        assert!(err.contains("crash iterations"));
        let err = parse(&["--dry-run", "--crash-iterations", "51"])
            .expect_err("iterations above max must reject");
        assert!(err.contains("crash iterations"));
    }

    #[test]
    fn parse_accepts_each_persistence_boundary() {
        assert_eq!(
            parse(&["--dry-run", "--persistence-boundary", "membership-apply"])
                .expect("membership-apply parses")
                .boundary,
            PersistenceBoundary::MembershipApply
        );
        assert_eq!(
            parse(&["--dry-run", "--persistence-boundary", "tunnel-setup"])
                .expect("tunnel-setup parses")
                .boundary,
            PersistenceBoundary::TunnelSetup
        );
        assert_eq!(
            parse(&["--dry-run", "--persistence-boundary", "bundle-write"])
                .expect("bundle-write parses")
                .boundary,
            PersistenceBoundary::BundleWrite
        );
    }

    #[test]
    fn parse_rejects_unknown_persistence_boundary() {
        let err = parse(&["--dry-run", "--persistence-boundary", "sigsegv"])
            .expect_err("unknown boundary must reject");
        assert!(err.contains("invalid --persistence-boundary"));
    }

    #[test]
    fn persistence_boundary_stage_indices_are_distinct() {
        assert_eq!(PersistenceBoundary::MembershipApply.stage_index(), 0);
        assert_eq!(PersistenceBoundary::TunnelSetup.stage_index(), 1);
        assert_eq!(PersistenceBoundary::BundleWrite.stage_index(), 2);
    }

    // ----- PURE EVALUATOR (1/3): watermark_regressed -----

    #[test]
    fn watermark_regressed_detects_downgrade() {
        assert!(watermark_regressed(
            WatermarkSample::Value(200),
            WatermarkSample::Value(199)
        ));
        // Real value rolling back to absent (== 0) is a regression.
        assert!(watermark_regressed(
            WatermarkSample::Value(1),
            WatermarkSample::Absent
        ));
    }

    #[test]
    fn watermark_regressed_allows_hold_or_advance() {
        // Equal (atomic old) is NOT a regression.
        assert!(!watermark_regressed(
            WatermarkSample::Value(200),
            WatermarkSample::Value(200)
        ));
        // Advance (atomic new) is NOT a regression.
        assert!(!watermark_regressed(
            WatermarkSample::Value(200),
            WatermarkSample::Value(201)
        ));
        // Absent -> Absent (both 0) is NOT a regression.
        assert!(!watermark_regressed(
            WatermarkSample::Absent,
            WatermarkSample::Absent
        ));
    }

    #[test]
    fn watermark_sample_parses_value_and_absent_and_rejects_garbage() {
        assert_eq!(
            WatermarkSample::parse("absent").unwrap(),
            WatermarkSample::Absent
        );
        assert_eq!(
            WatermarkSample::parse(" 42 ").unwrap(),
            WatermarkSample::Value(42)
        );
        assert!(WatermarkSample::parse("nope").is_err());
    }

    // ----- PURE EVALUATOR (2/3): atomic_state_verdict -----

    #[test]
    fn atomic_state_verdict_accepts_old_state_present_parseable() {
        // Atomic OLD: watermark held, bundle present + parseable, no torn keys.
        assert!(atomic_state_verdict(
            WatermarkSample::Value(200),
            WatermarkSample::Value(200),
            BundleState::Present,
            true,
            0
        ));
    }

    #[test]
    fn atomic_state_verdict_accepts_new_state_advanced() {
        // Atomic NEW: watermark advanced, bundle present + parseable.
        assert!(atomic_state_verdict(
            WatermarkSample::Value(200),
            WatermarkSample::Value(201),
            BundleState::Present,
            true,
            0
        ));
    }

    #[test]
    fn atomic_state_verdict_accepts_absent_bundle_pre_write() {
        assert!(atomic_state_verdict(
            WatermarkSample::Absent,
            WatermarkSample::Absent,
            BundleState::Absent,
            true,
            0
        ));
    }

    #[test]
    fn atomic_state_verdict_rejects_watermark_downgrade() {
        // Release-blocking: torn apply downgraded the watermark.
        assert!(!atomic_state_verdict(
            WatermarkSample::Value(200),
            WatermarkSample::Value(199),
            BundleState::Present,
            true,
            0
        ));
    }

    #[test]
    fn atomic_state_verdict_rejects_truncated_bundle() {
        // Present-but-unparseable = truncated/partial bundle must fail closed.
        assert!(!atomic_state_verdict(
            WatermarkSample::Value(200),
            WatermarkSample::Value(200),
            BundleState::Present,
            false,
            0
        ));
    }

    #[test]
    fn atomic_state_verdict_rejects_empty_bundle() {
        // Zero-length bundle file = torn write.
        assert!(!atomic_state_verdict(
            WatermarkSample::Value(200),
            WatermarkSample::Value(200),
            BundleState::Empty,
            false,
            0
        ));
    }

    #[test]
    fn atomic_state_verdict_rejects_torn_keystore_file() {
        // Zero-length key file = torn keystore write.
        assert!(!atomic_state_verdict(
            WatermarkSample::Value(200),
            WatermarkSample::Value(200),
            BundleState::Present,
            true,
            1
        ));
    }

    // ----- PURE EVALUATOR (3/3): parse_mesh_converged -----

    #[test]
    fn parse_mesh_converged_accepts_healthy_status() {
        let line = "node_id=node-a node_role=client state=Ready path_live_proven=true path_live_peer_count=2 bootstrap_error=none restricted_safe_mode=false";
        assert!(parse_mesh_converged(line));
    }

    #[test]
    fn parse_mesh_converged_accepts_unproven_path_when_other_fields_healthy() {
        // b78 criterion change: path_live_proven is the 30 s simultaneity
        // lottery (peers rekey every ~120 s), so the status half no longer
        // requires it — the per-peer rekey evidence carries that proof.
        let line = "node_id=node-a path_live_proven=false path_live_peer_count=2 bootstrap_error=none restricted_safe_mode=false";
        assert!(parse_mesh_converged(line));
    }

    #[test]
    fn parse_mesh_converged_rejects_zero_peers() {
        let line = "node_id=node-a path_live_proven=true path_live_peer_count=0 bootstrap_error=none restricted_safe_mode=false";
        assert!(!parse_mesh_converged(line));
    }

    #[test]
    fn parse_mesh_converged_rejects_bootstrap_error_or_restricted() {
        let with_error = "path_live_proven=true path_live_peer_count=1 bootstrap_error=cannot_load restricted_safe_mode=false";
        assert!(!parse_mesh_converged(with_error));
        let restricted = "path_live_proven=true path_live_peer_count=1 bootstrap_error=none restricted_safe_mode=true";
        assert!(!parse_mesh_converged(restricted));
    }

    #[test]
    fn parse_mesh_converged_fails_closed_on_missing_fields() {
        // Empty / malformed status => not converged.
        assert!(!parse_mesh_converged(""));
        assert!(!parse_mesh_converged("garbage without fields"));
    }

    // ----- Observation parsing + stage pass-check -----

    fn passing_output() -> String {
        [
            "teardown_registered_before_fault=true",
            "persistence_boundary=bundle-write",
            "watermark_before=200",
            "bundle_before=present",
            "fault_signal=KILL",
            "crash_iterations=12",
            "observed_kill_count=12",
            "start_limit_resets=13",
            "mesh_poll_secs=21",
            "recovered=true",
            "measured_recovery_secs=7",
            "watermark_after=201",
            "bundle_after=present",
            "bundle_parse_after=true",
            "keystore_empty_files_after=0",
            "mesh_status_line=node_id=node-a node_role=client state=Ready path_live_proven=true path_live_peer_count=2 bootstrap_error=none restricted_safe_mode=false",
            "recovery_start_unix=1790995300",
            "wg_interface_present=true",
            "wg_peer_handshakes=2 katana-client-peer-key:1790995400 katana-entry-peer-key:1790995450",
        ]
        .join("\n")
    }

    // Live 2026-09-10 (lenovo-bot): 12 kills tripped StartLimitBurst=5/60s and
    // the daemon never came back inside the deadline — systemd's limiter, not
    // the daemon, decided the verdict. The script must clear it per kill and
    // account for it in the observation.
    #[test]
    fn remote_script_resets_start_limit_per_kill_and_reports_the_count() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
        assert!(
            script
                .matches("systemctl reset-failed \"$service\"")
                .count()
                >= 2,
            "reset-failed must precede both the per-iteration start and the final restart:\n{script}"
        );
        assert!(
            script.contains("printf 'start_limit_resets=%s\\n' \"$resets\""),
            "{script}"
        );
        let observation = CrashStageObservation::parse(&passing_output()).expect("parse");
        assert_eq!(observation.start_limit_resets, 13);
        let missing = passing_output().replace("start_limit_resets=13\n", "");
        assert!(
            CrashStageObservation::parse(&missing).is_err(),
            "the field is required"
        );
    }

    // The abort-path cleanup must clear the start limiter before its start:
    // an abort after >= StartLimitBurst kills leaves the limiter armed, and a
    // bare `systemctl start` is refused ("Start request repeated too
    // quickly"), inheriting a dead daemon into every later stage.
    #[test]
    fn remote_script_cleanup_resets_start_limit_before_teardown_start() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
        let cleanup = script.find("cleanup() {").expect("cleanup fn");
        let body_end = script[cleanup..].find("\n}").expect("cleanup body end");
        let cleanup_body = &script[cleanup..cleanup + body_end];
        let reset = cleanup_body
            .find("systemctl reset-failed \"$service\"")
            .expect("reset-failed inside cleanup");
        let start = cleanup_body
            .find("systemctl start \"$service\"")
            .expect("start inside cleanup");
        assert!(
            reset < start,
            "cleanup must reset-failed before the teardown start:\n{script}"
        );
    }

    // The teardown trap must survive the SSH session dying (orchestrator
    // SIGKILL/timeout): a POSIX shell may not run an EXIT-only trap on
    // SIGHUP, so the registration has to name the signals explicitly.
    #[test]
    fn remote_script_arms_teardown_against_session_death() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
        assert!(
            script.contains("trap cleanup EXIT HUP INT TERM"),
            "{script}"
        );
    }

    // RSA-0080: the guest's non-login PATH omits the sbin directories where
    // ip/systemctl live; the script pins an sbin-bearing PATH before any
    // lookup.
    #[test]
    fn remote_script_pins_an_sbin_bearing_path_before_any_lookup() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
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

    // Live 2026-09-11: socket recovery in 8 s but the mesh had not re-proven a
    // path at that instant; the script must poll to the deadline. b78: the
    // poll breaks early only when EVERY peer has rekeyed since recovery
    // start AND the status fields hold — as per-token greps, since the real
    // status line puts restricted_safe_mode/bootstrap_error BEFORE the
    // path_* fields and the old break glob therefore never matched.
    #[test]
    fn remote_script_polls_mesh_convergence_after_recovery() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
        assert!(
            script.contains("wg show \"$wg_interface\" latest-handshakes"),
            "{script}"
        );
        assert!(
            script.contains("grep -Eq 'path_live_peer_count=[1-9]'"),
            "{script}"
        );
        assert!(
            script.contains("printf 'mesh_poll_secs=%s\\n' \"$mesh_poll_secs\""),
            "{script}"
        );
        let observation = CrashStageObservation::parse(&passing_output()).expect("parse");
        assert_eq!(observation.mesh_poll_secs, 21);
    }

    // The early-break arm must be evaluated BEFORE the deadline check so a
    // healthy mesh exits the loop at the first satisfying sample instead of
    // burning the full 3x window (the old never-matching glob always did).
    #[test]
    fn remote_script_early_break_arm_precedes_deadline_check() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
        let break_arm = script
            .find("[ \"$wg_rekeyed\" = true ]")
            .expect("wg rekey break arm");
        let deadline_check = script
            .find("[ \"$(date +%s)\" -ge \"$mesh_end_unix\" ] && break")
            .expect("deadline check");
        assert!(
            break_arm < deadline_check,
            "break arm must precede the deadline check:\n{script}"
        );
    }

    // The awk ready-check must treat a handshake stamped EXACTLY at
    // recovery start as rekeyed (>= semantics, mirroring
    // all_peers_rekeyed_since): only a strictly-older timestamp is stale.
    #[test]
    fn remote_script_rekey_check_uses_ge_semantics() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
        assert!(
            script.contains("p[2] + 0 < start + 0) stale = 1"),
            "{script}"
        );
    }

    // The evidence fields must be printed on EVERY path (initialized before
    // the recovered branch) so the Rust parser always sees them and a
    // not-recovered run fails closed on the wg half instead of erroring.
    #[test]
    fn remote_script_emits_wg_evidence_fields_even_when_not_recovered() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
        let init = script
            .find("wg_interface_present=false")
            .expect("pre-branch initialization");
        let branch = script
            .find("if [ \"$recovered\" = true ]; then")
            .expect("branch");
        let print = script
            .find("printf 'recovery_start_unix=%s\\n' \"$recovery_start_unix\"")
            .expect("evidence print");
        assert!(init < branch, "{script}");
        assert!(branch < print, "{script}");
        assert!(
            script.contains("printf 'wg_interface_present=%s\\n' \"$wg_interface_present\""),
            "{script}"
        );
        assert!(
            script.contains("printf 'wg_peer_handshakes=%s\\n' \"$wg_peer_handshakes\""),
            "{script}"
        );
    }

    #[test]
    fn observation_parses_passing_output() {
        let observation = CrashStageObservation::parse(&passing_output()).expect("parse");
        assert!(observation.passed(90));
        assert_eq!(observation.observed_kill_count, 12);
        assert_eq!(observation.watermark_after, WatermarkSample::Value(201));
        assert_eq!(observation.bundle_after, BundleState::Present);
    }

    #[test]
    fn observation_parses_embedded_mesh_status_line() {
        // The mesh_status_line value embeds spaces and `=` chars; the
        // per-line key parser must keep the whole status line intact and
        // must NOT let its inner `bootstrap_error=` token shadow other keys.
        let observation = CrashStageObservation::parse(&passing_output()).expect("parse");
        assert!(
            observation
                .mesh_status_line
                .contains("path_live_proven=true")
        );
        assert!(observation.mesh_converged());
        // The inner token does not get mis-parsed as a top-level key.
        assert_eq!(observation.observed_kill_count, 12);
    }

    #[test]
    fn observation_fails_when_no_kill_landed() {
        // A never-run injection (zero kills) must FAIL, not silently pass.
        let output = passing_output().replace("observed_kill_count=12", "observed_kill_count=0");
        let observation = CrashStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(90));
    }

    #[test]
    fn observation_fails_when_mesh_not_converged() {
        // Daemon came back but never re-handshook to a healthy mesh.
        let output = passing_output().replace(
            "path_live_proven=true path_live_peer_count=2",
            "path_live_proven=false path_live_peer_count=0",
        );
        let observation = CrashStageObservation::parse(&output).expect("parse");
        assert!(!observation.mesh_converged());
        assert!(!observation.passed(90));
    }

    #[test]
    fn observation_fails_when_mesh_status_absent() {
        // Empty mesh status line (recovery captured nothing) => not converged.
        let output = passing_output().replace(
            "mesh_status_line=node_id=node-a node_role=client state=Ready path_live_proven=true path_live_peer_count=2 bootstrap_error=none restricted_safe_mode=false",
            "mesh_status_line=",
        );
        let observation = CrashStageObservation::parse(&output).expect("parse");
        assert!(observation.mesh_status_line.is_empty());
        assert!(!observation.passed(90));
    }

    #[test]
    fn observation_fails_on_watermark_downgrade() {
        let output = passing_output().replace("watermark_after=201", "watermark_after=199");
        let observation = CrashStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(90));
    }

    #[test]
    fn observation_fails_on_truncated_bundle() {
        let output =
            passing_output().replace("bundle_parse_after=true", "bundle_parse_after=false");
        let observation = CrashStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(90));
    }

    #[test]
    fn observation_fails_when_not_recovered_in_deadline() {
        let output =
            passing_output().replace("measured_recovery_secs=7", "measured_recovery_secs=91");
        let observation = CrashStageObservation::parse(&output).expect("parse");
        assert!(!observation.passed(90));
    }

    #[test]
    fn observation_parse_rejects_missing_key() {
        let output = passing_output().replace("watermark_after=201\n", "");
        let err = CrashStageObservation::parse(&output).expect_err("missing key must error");
        assert!(err.contains("watermark_after"));
    }

    #[test]
    fn live_report_marks_selected_boundary_stage_and_others_skipped() {
        let config = parse(&["--dry-run", "--persistence-boundary", "bundle-write"])
            .expect("dry-run config should parse");
        let observation = CrashStageObservation::parse(&passing_output()).expect("parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "pass");
        assert_eq!(report["implemented_stage_count"], 1);
        assert_eq!(report["remaining_stage_count"], 2);
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages[2]["name"], "chaos_crash_during_bundle_write");
        assert_eq!(stages[2]["status"], "pass");
        assert_eq!(stages[2]["watermark_regressed"], false);
        assert_eq!(stages[2]["atomic_state"], true);
        assert_eq!(stages[0]["status"], "skipped");
        assert_eq!(stages[1]["status"], "skipped");
    }

    #[test]
    fn live_report_membership_boundary_targets_stage_zero() {
        let config = parse(&["--dry-run", "--persistence-boundary", "membership-apply"])
            .expect("dry-run config should parse");
        let output = passing_output().replace(
            "persistence_boundary=bundle-write",
            "persistence_boundary=membership-apply",
        );
        let observation = CrashStageObservation::parse(&output).expect("parse");
        let report = render_live_report(&config, &observation);
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages[0]["name"], "chaos_crash_during_membership_apply");
        assert_eq!(stages[0]["status"], "pass");
        assert_eq!(stages[1]["status"], "skipped");
        assert_eq!(stages[2]["status"], "skipped");
    }

    #[test]
    fn live_report_surfaces_watermark_downgrade_as_fail() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let output = passing_output().replace("watermark_after=201", "watermark_after=199");
        let observation = CrashStageObservation::parse(&output).expect("parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "fail");
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages[2]["status"], "fail");
        assert_eq!(stages[2]["watermark_regressed"], true);
        assert_eq!(report["security_invariants"]["watermark_regressed"], true);
    }

    // ----- b78 WITNESSES: per-peer post-crash rekey criterion -----
    // These four tests FAIL against the pre-b78 harness: (1) the old
    // criterion demanded path_live_proven=true (the 30 s simultaneity
    // lottery) even when every peer provably rekeyed after the crash, and
    // (2) the old criterion let a peer with NO post-crash handshake slip
    // through when the other peer happened to be fresh at the sample
    // instant. (3)/(4) pin the wg evidence read and the field-order-
    // corrected early break in the remote script.

    #[test]
    fn observation_passes_when_path_live_proven_false_but_every_peer_rekeyed_since_recovery() {
        let output = passing_output().replace("path_live_proven=true", "path_live_proven=false");
        let observation = CrashStageObservation::parse(&output).expect("parse");
        assert!(
            observation.passed(90),
            "every peer rekeyed post-crash must pass even when the daemon's 30 s \
             simultaneity window was not sampled"
        );
    }

    #[test]
    fn observation_fails_when_one_peer_never_rekeyed_since_recovery() {
        let output = passing_output().replace(
            "wg_peer_handshakes=2 katana-client-peer-key:1790995400 katana-entry-peer-key:1790995450",
            "wg_peer_handshakes=2 katana-client-peer-key:1790995400 katana-entry-peer-key:900",
        );
        let observation = CrashStageObservation::parse(&output).expect("parse");
        assert!(
            !observation.passed(90),
            "a peer with no post-crash handshake must fail the stage, not hide \
             behind the other peer's fresh sample"
        );
    }

    #[test]
    fn remote_script_reads_wg_latest_handshakes_for_every_peer() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
        assert!(
            script.contains("wg show \"$wg_interface\" latest-handshakes"),
            "the mesh poll must read per-peer handshakes from the OS WireGuard \
             interface directly:\n{script}"
        );
        assert!(
            script.contains("printf 'wg_peer_handshakes=%s\\n' \"$wg_peer_handshakes\""),
            "the report evidence must carry the per-peer handshake sample:\n{script}"
        );
    }

    #[test]
    fn remote_script_breaks_early_on_corrected_field_order_and_all_peer_rekey() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run"]).expect("dry-run config should parse"),
        );
        // The real status line puts restricted_safe_mode/bootstrap_error
        // BEFORE the path_* fields (katana-u32 mesh_status_line), so the old
        // glob could never match and every run burned the full 3x window.
        assert!(
            !script.contains(
                "*path_live_proven=true*path_live_peer_count=[1-9]*bootstrap_error=none*restricted_safe_mode=false*) break ;;"
            ),
            "the impossible-order glob must be gone:\n{script}"
        );
        assert!(
            script.contains("grep -q 'restricted_safe_mode=false'"),
            "{script}"
        );
        assert!(
            script.contains("grep -q 'bootstrap_error=none'"),
            "{script}"
        );
        assert!(
            script.contains("grep -Eq 'path_live_peer_count=[1-9]'"),
            "{script}"
        );
    }

    // ----- PURE EVALUATOR (4/5): parse_wg_peer_handshakes -----

    #[test]
    fn wg_sample_parses_two_peers() {
        let peers = parse_wg_peer_handshakes(
            "2 katana-client-peer-key:1790995400 katana-entry-peer-key:1790995450",
        )
        .expect("valid sample");
        assert_eq!(
            peers,
            vec![
                ("katana-client-peer-key".to_owned(), 1790995400),
                ("katana-entry-peer-key".to_owned(), 1790995450),
            ]
        );
    }

    #[test]
    fn wg_sample_parses_zero_peers_as_empty() {
        // The script prints "0 " when the interface listed no peers; that
        // is a WELL-FORMED but FAILING sample (no peers => no proof), not a
        // parse error.
        assert_eq!(
            parse_wg_peer_handshakes("0 ").expect("empty sample"),
            vec![]
        );
    }

    #[test]
    fn wg_sample_fails_closed_on_count_mismatch() {
        // Two tokens after a declared count of 3: wg output was truncated
        // or mangled => unusable evidence.
        let err =
            parse_wg_peer_handshakes("3 k1:1 k2:2").expect_err("count mismatch must fail closed");
        assert!(err.contains("declared 3"), "{err}");
    }

    #[test]
    fn wg_sample_fails_closed_on_invalid_count() {
        assert!(parse_wg_peer_handshakes("").is_err(), "empty sample");
        assert!(parse_wg_peer_handshakes("x k:1").is_err(), "garbage count");
        assert!(
            parse_wg_peer_handshakes("-1 k:1").is_err(),
            "negative count"
        );
    }

    #[test]
    fn wg_sample_fails_closed_on_malformed_tokens() {
        // No colon: the tab separator was lost.
        assert!(parse_wg_peer_handshakes("1 justakey").is_err());
        // Extra field: a third tab-separated column.
        assert!(parse_wg_peer_handshakes("1 a:b:5").is_err());
        // Non-numeric epoch.
        assert!(parse_wg_peer_handshakes("1 key:later").is_err());
        // Empty peer key.
        assert!(parse_wg_peer_handshakes("1 :5").is_err());
    }

    // ----- PURE EVALUATOR (5/5): all_peers_rekeyed_since / wg_mesh_rekeyed -----

    #[test]
    fn all_peers_rekeyed_requires_every_peer_at_or_after_start() {
        let fresh = vec![("a".to_owned(), 1100), ("b".to_owned(), 1200)];
        assert!(all_peers_rekeyed_since(&fresh, 1000));
        // Equal to recovery start counts (>= semantics).
        assert!(all_peers_rekeyed_since(&fresh, 1100));
        let one_stale = vec![("a".to_owned(), 1100), ("b".to_owned(), 900)];
        assert!(!all_peers_rekeyed_since(&one_stale, 1000));
    }

    #[test]
    fn all_peers_rekeyed_fails_closed_on_no_peers() {
        assert!(!all_peers_rekeyed_since(&[], 1000));
    }

    #[test]
    fn wg_mesh_rekeyed_fails_closed_on_malformed_or_unknown_start() {
        // Malformed output never passes.
        assert!(!wg_mesh_rekeyed("2 k1:1100", 1000));
        assert!(!wg_mesh_rekeyed("1 bad-token", 1000));
        // No peers listed: fail closed.
        assert!(!wg_mesh_rekeyed("0 ", 1000));
        // Unknown recovery start (0): fail closed.
        assert!(!wg_mesh_rekeyed("1 k:1100", 0));
        // Well-formed and all fresh: passes.
        assert!(wg_mesh_rekeyed("1 k:1100", 1000));
    }

    // ----- PURE: mesh_recovered (the full criterion) -----

    fn healthy_status_line() -> String {
        "node_id=node-a node_role=client state=Ready path_live_proven=true path_live_peer_count=2 bootstrap_error=none restricted_safe_mode=false".to_owned()
    }

    #[test]
    fn mesh_recovered_accepts_all_peers_rekeyed() {
        assert!(mesh_recovered(
            &healthy_status_line(),
            true,
            "2 a:1100 b:1200",
            1000
        ));
    }

    #[test]
    fn mesh_recovered_accepts_live_proven_false_when_peers_rekeyed() {
        // THE criterion change: the daemon's 30 s simultaneity window not
        // being sampled no longer fails a mesh whose every peer rekeyed
        // after the crash.
        let line = healthy_status_line().replace("path_live_proven=true", "path_live_proven=false");
        assert!(mesh_recovered(&line, true, "2 a:1100 b:1200", 1000));
    }

    #[test]
    fn mesh_recovered_fails_when_one_peer_stale() {
        assert!(!mesh_recovered(
            &healthy_status_line(),
            true,
            "2 a:1100 b:900",
            1000
        ));
    }

    #[test]
    fn mesh_recovered_fails_when_no_peers_listed() {
        assert!(!mesh_recovered(&healthy_status_line(), true, "0 ", 1000));
    }

    #[test]
    fn mesh_recovered_fails_on_malformed_wg_output() {
        assert!(!mesh_recovered(
            &healthy_status_line(),
            true,
            "2 a:1100",
            1000
        ));
    }

    #[test]
    fn mesh_recovered_fails_when_interface_missing() {
        assert!(!mesh_recovered(
            &healthy_status_line(),
            false,
            "2 a:1100 b:1200",
            1000
        ));
    }

    #[test]
    fn mesh_recovered_fails_on_unhealthy_status() {
        let bootstrap_error =
            healthy_status_line().replace("bootstrap_error=none", "bootstrap_error=cannot_load");
        assert!(!mesh_recovered(
            &bootstrap_error,
            true,
            "2 a:1100 b:1200",
            1000
        ));
        let restricted = healthy_status_line()
            .replace("restricted_safe_mode=false", "restricted_safe_mode=true");
        assert!(!mesh_recovered(&restricted, true, "2 a:1100 b:1200", 1000));
        let zero_peers =
            healthy_status_line().replace("path_live_peer_count=2", "path_live_peer_count=0");
        assert!(!mesh_recovered(&zero_peers, true, "2 a:1100 b:1200", 1000));
        assert!(!mesh_recovered("", true, "2 a:1100 b:1200", 1000));
    }

    #[test]
    fn mesh_recovered_fails_on_unknown_recovery_start() {
        assert!(!mesh_recovered(
            &healthy_status_line(),
            true,
            "2 a:1100 b:1200",
            0
        ));
    }

    // ----- Observation parsing + stage pass-check over the wg evidence -----

    #[test]
    fn observation_fails_when_wg_interface_absent() {
        let output =
            passing_output().replace("wg_interface_present=true", "wg_interface_present=false");
        let observation = CrashStageObservation::parse(&output).expect("parse");
        assert!(!observation.mesh_converged());
        assert!(!observation.passed(90));
    }

    #[test]
    fn observation_parse_requires_recovery_start_unix() {
        // Script and bin ship together; a remote output without the
        // recovery start must fail at parse (fail closed), not skip the
        // per-peer criterion.
        let output = passing_output().replace("recovery_start_unix=1790995300\n", "");
        let err = CrashStageObservation::parse(&output).expect_err("missing recovery start");
        assert!(err.contains("recovery_start_unix"), "{err}");
    }

    #[test]
    fn observation_parse_requires_wg_sample_line() {
        let output = passing_output().replace("wg_peer_handshakes=2 katana-client-peer-key:1790995400 katana-entry-peer-key:1790995450", "");
        let err = CrashStageObservation::parse(&output).expect_err("missing wg sample");
        assert!(err.contains("wg_peer_handshakes"), "{err}");
    }

    // ----- --wg-interface config surface -----

    #[test]
    fn wg_interface_defaults_to_rustynet0_and_overrides() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        assert_eq!(config.wg_interface, "rustynet0");
        let config =
            parse(&["--dry-run", "--wg-interface", "wg-node7"]).expect("override should parse");
        assert_eq!(config.wg_interface, "wg-node7");
    }

    #[test]
    fn wg_interface_rejects_shell_metacharacters() {
        let err = parse(&["--dry-run", "--wg-interface", "rustynet0; reboot"])
            .expect_err("interface shell metacharacter must reject");
        assert!(err.contains("wg interface"));
        let err = parse(&["--dry-run", "--wg-interface", "wg0 $(id)"])
            .expect_err("interface command substitution must reject");
        assert!(err.contains("wg interface"));
    }

    #[test]
    fn remote_script_pins_the_configured_wg_interface() {
        let script = render_remote_crash_script(
            &parse(&["--dry-run", "--wg-interface", "wg-node7"])
                .expect("dry-run config should parse"),
        );
        assert!(script.contains("wg_interface='wg-node7'"), "{script}");
    }

    // ----- Report evidence -----

    #[test]
    fn live_report_carries_wg_rekey_evidence() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let observation = CrashStageObservation::parse(&passing_output()).expect("parse");
        let report = render_live_report(&config, &observation);
        let stage = &report["stages"][2];
        assert_eq!(stage["recovery_start_unix"], 1790995300);
        assert_eq!(stage["wg_interface"], "rustynet0");
        assert_eq!(stage["wg_interface_present"], true);
        let peers = stage["wg_peers"].as_array().expect("per-peer evidence");
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0]["peer"], "katana-client-peer-key");
        assert_eq!(peers[0]["latest_handshake_unix"], 1790995400);
        assert_eq!(peers[0]["rekeyed_since_recovery"], true);
        assert_eq!(peers[1]["latest_handshake_unix"], 1790995450);
        assert_eq!(
            report["security_invariants"]["wg_all_peers_rekeyed_since_recovery"],
            true
        );
    }

    #[test]
    fn live_report_marks_stale_peer_as_not_rekeyed_and_stage_failed() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let output = passing_output().replace(
            "wg_peer_handshakes=2 katana-client-peer-key:1790995400 katana-entry-peer-key:1790995450",
            "wg_peer_handshakes=2 katana-client-peer-key:1790995400 katana-entry-peer-key:900",
        );
        let observation = CrashStageObservation::parse(&output).expect("parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "fail");
        let peers = report["stages"][2]["wg_peers"].as_array().expect("peers");
        assert_eq!(peers[1]["rekeyed_since_recovery"], false);
        assert_eq!(
            report["security_invariants"]["wg_all_peers_rekeyed_since_recovery"],
            false
        );
    }
}
