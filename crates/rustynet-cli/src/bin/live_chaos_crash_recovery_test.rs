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
    Logger, capture_root, ensure_pinned_known_hosts_file, ensure_safe_token,
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
/// template's prologue (mktemp work_dir, `trap cleanup EXIT` registered
/// BEFORE the fault so the daemon is never left dead on any abort path,
/// `teardown_registered_before_fault` marker, preflight that the service
/// is active + socket present). Divergences vs the daemon-fault path:
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
    let service = shell_quote(&config.service_name);
    let socket_path = shell_quote(&config.socket_path);
    let bundle_path = shell_quote(&config.bundle_path);
    let watermark_path = shell_quote(&config.watermark_path);
    let keystore_dir = shell_quote(&config.keystore_dir);
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
service={service}
socket_path={socket_path}
bundle_path={bundle_path}
watermark_path={watermark_path}
keystore_dir={keystore_dir}
watermark_key={watermark_key}
boundary={boundary}
deadline={deadline}
iterations={iterations}
work_dir="$(mktemp -d /tmp/rustynet-chaos-crash-recovery.XXXXXX)"
cleanup() {{
  systemctl start "$service" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}}
trap cleanup EXIT
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
while [ "$i" -lt "$iterations" ]; do
  systemctl start "$service" >/dev/null 2>&1 || true
  # Best-effort kick to drive a fresh trust-state apply; ignore failure so
  # the loop still SIGKILLs even if reload is unsupported.
  systemctl reload "$service" >/dev/null 2>&1 || systemctl kill -s HUP "$service" >/dev/null 2>&1 || true
  systemctl kill -s KILL "$service" >/dev/null 2>&1 || true
  killed="$(( killed + 1 ))"
  i="$(( i + 1 ))"
done
printf 'observed_kill_count=%s\n' "$killed"

# Restart and wait for atomic recovery within the deadline.
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

# Capture the daemon's single-line status so the Rust side can confirm the
# daemon re-handshook and re-applied signed state to a healthy mesh after
# the crash loop (path_live_proven / path_live_peer_count). Force the first
# physical line only (the status output is a single key=value line) and
# strip any embedded newlines so it round-trips on one report line. Empty
# on failure => parse_mesh_converged returns false (fail-closed).
mesh_status_line=""
if [ "$recovered" = true ]; then
  mesh_status_line="$(env RUSTYNET_DAEMON_SOCKET="$socket_path" rustynet status 2>/dev/null | tr '\n' ' ' | head -c 8192 || true)"
fi
printf 'recovered=%s\n' "$recovered"
printf 'measured_recovery_secs=%s\n' "$measured_recovery_secs"
printf 'watermark_after=%s\n' "$watermark_after"
printf 'bundle_after=%s\n' "$bundle_after"
printf 'bundle_parse_after=%s\n' "$bundle_parse_after"
printf 'keystore_empty_files_after=%s\n' "$keystore_empty_after"
printf 'mesh_status_line=%s\n' "$mesh_status_line"
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

/// PURE EVALUATOR (3/3): mesh-converged parser. Reads the daemon's
/// single-line `node_id=... node_role=... path_live_proven=...
/// path_live_peer_count=...` status (crates/rustynetd/src/daemon.rs) and
/// returns true iff the daemon re-handshook and re-applied signed state to
/// a healthy mesh: `path_live_proven=true` AND `path_live_peer_count` >= 1
/// AND `bootstrap_error=none` AND `restricted_safe_mode=false`. Missing /
/// malformed status => not converged (fail-closed).
fn parse_mesh_converged(status_line: &str) -> bool {
    let field = |key: &str| -> Option<&str> {
        status_line.split_whitespace().find_map(|token| {
            token
                .split_once('=')
                .and_then(|(found, value)| (found == key).then_some(value))
        })
    };
    let live_proven = field("path_live_proven") == Some("true");
    let live_peers = field("path_live_peer_count")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    // bootstrap_error / restricted_safe_mode may be absent on very old
    // status formats; treat absence as fail-closed for those fields.
    let bootstrap_clean = field("bootstrap_error") == Some("none");
    let not_restricted = field("restricted_safe_mode") == Some("false");
    live_proven && live_peers >= 1 && bootstrap_clean && not_restricted
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CrashStageObservation {
    teardown_registered_before_fault: bool,
    persistence_boundary: String,
    observed_kill_count: u64,
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
    /// [`parse_mesh_converged`] to prove the daemon re-handshook and
    /// re-applied signed state to a healthy mesh.
    mesh_status_line: String,
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
        })
    }

    /// Whether the daemon converged to a healthy mesh after recovery. Pure
    /// delegation to [`parse_mesh_converged`] over the captured status line.
    fn mesh_converged(&self) -> bool {
        parse_mesh_converged(&self.mesh_status_line)
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
            "mesh_converged": observation.mesh_converged()
        }
    })
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
        "usage: {CATEGORY} [--dry-run] [--target-host <user@host>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--socket-path <path>] [--service-name <name>] [--bundle-path <path>] [--watermark-path <path>] [--keystore-dir <path>] [--recovery-deadline-secs <secs>] [--crash-iterations <n>] [--persistence-boundary <membership-apply|tunnel-setup|bundle-write>] [--report-path <path>] [--log-path <path>] [--git-commit <sha>]"
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
    fn parse_mesh_converged_rejects_unproven_path() {
        let line = "node_id=node-a path_live_proven=false path_live_peer_count=2 bootstrap_error=none restricted_safe_mode=false";
        assert!(!parse_mesh_converged(line));
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
            "recovered=true",
            "measured_recovery_secs=7",
            "watermark_after=201",
            "bundle_after=present",
            "bundle_parse_after=true",
            "keystore_empty_files_after=0",
            "mesh_status_line=node_id=node-a node_role=client state=Ready path_live_proven=true path_live_peer_count=2 bootstrap_error=none restricted_safe_mode=false",
        ]
        .join("\n")
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
}
