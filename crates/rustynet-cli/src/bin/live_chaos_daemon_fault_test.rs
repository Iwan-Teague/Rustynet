#![forbid(unsafe_code)]
// Track B Phase 28 transition: still calls the deprecated
// `capture_root` shim. Phase 29 rewrites on the new
// `RemoteShellHost` trait. Allow until then so `-D warnings` passes.
#![allow(deprecated)]

mod live_chaos_support;
mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_chaos_support::{ChaosConfig, ChaosStage, git_head_commit, repo_root, run_category};
use live_lab_bin_support::{
    Logger, capture_root, ensure_pinned_known_hosts_file, ensure_safe_token,
    load_home_known_hosts_path, run_root, shell_quote, unix_now, verify_sudo,
    wait_for_daemon_socket, write_file,
};
use serde_json::{Value, json};

const CATEGORY: &str = "chaos_daemon_fault";
const DEFAULT_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
const DEFAULT_SERVICE_NAME: &str = "rustynetd.service";
const DEFAULT_CAPTURE_INTERFACE: &str = "default-route";
const DEFAULT_MESH_CIDR: &str = "100.64.0.0/10";
const DEFAULT_RECOVERY_DEADLINE_SECS: u64 = 90;
const MAX_RECOVERY_DEADLINE_SECS: u64 = 90;
const CLIENT_TRAFFIC_PID_FILE: &str = "/tmp/rustynet-chaos-daemon-fault-client.pid";
const CLIENT_TCPDUMP_PID_FILE: &str = "/tmp/rustynet-chaos-daemon-fault-client-tcpdump.pid";
const CLIENT_TCPDUMP_CAPTURE_FILE: &str = "/tmp/rustynet-chaos-daemon-fault-client-tcpdump.txt";
const CLIENT_TCPDUMP_ERROR_FILE: &str = "/tmp/rustynet-chaos-daemon-fault-client-tcpdump.err";
const CLIENT_PROBE_TARGET: &str = "1.1.1.1";

fn daemon_fault_stages() -> Vec<ChaosStage> {
    vec![
        ChaosStage {
            name: "chaos_daemon_kill_during_reconcile",
            fault: "kill rustynetd while baseline traffic is in flight",
            pass_criterion: "daemon restarts, killswitch holds, zero plaintext egress during fault window",
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
        },
        ChaosStage {
            name: "chaos_daemon_oom_during_bundle_write",
            fault: "clip daemon address space during assignment refresh",
            pass_criterion: "signed-state file is valid or absent, never partial; next reconcile recovers",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_daemon_sigstop_sigcont",
            fault: "SIGSTOP daemon beyond reconcile interval, then SIGCONT",
            pass_criterion: "peers fail closed during stop window and recover after daemon resumes",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: "chaos_helper_socket_race",
            fault: "race privileged-helper socket with malformed argv frames",
            pass_criterion: "argv-only boundary rejects malformed input without panic or shell construction",
            recovery_deadline_secs: 60,
        },
    ]
}

/// Which live fault the harness injects. `Kill` is the original, proven
/// `systemctl kill -s KILL` path (orchestrator stage `chaos_daemon_fault`);
/// `StopCont` adds the SIGSTOP/SIGCONT freeze-then-resume sub-stage
/// (`chaos_daemon_sigstop_sigcont`). Defaults to `Kill` so callers that do
/// not pass `--fault-mode` keep byte-for-byte-identical kill behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum FaultMode {
    #[default]
    Kill,
    StopCont,
}

#[derive(Clone, Debug)]
struct Config {
    report_path: PathBuf,
    log_path: PathBuf,
    git_commit: String,
    dry_run: bool,
    target_host: Option<String>,
    client_host: Option<String>,
    ssh_identity_file: Option<PathBuf>,
    known_hosts_file: Option<PathBuf>,
    socket_path: String,
    service_name: String,
    capture_interface: String,
    mesh_cidr: String,
    recovery_deadline_secs: u64,
    fault_mode: FaultMode,
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
            client_host: None,
            ssh_identity_file: None,
            known_hosts_file: None,
            socket_path: DEFAULT_SOCKET_PATH.to_owned(),
            service_name: DEFAULT_SERVICE_NAME.to_owned(),
            capture_interface: DEFAULT_CAPTURE_INTERFACE.to_owned(),
            mesh_cidr: DEFAULT_MESH_CIDR.to_owned(),
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
            fault_mode: FaultMode::default(),
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
                "--client-host" => {
                    idx += 1;
                    config.client_host = Some(required_value(&args, idx, "--client-host")?);
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
                "--capture-interface" => {
                    idx += 1;
                    config.capture_interface = required_value(&args, idx, "--capture-interface")?;
                }
                "--mesh-cidr" => {
                    idx += 1;
                    config.mesh_cidr = required_value(&args, idx, "--mesh-cidr")?;
                }
                "--recovery-deadline-secs" => {
                    idx += 1;
                    config.recovery_deadline_secs =
                        required_value(&args, idx, "--recovery-deadline-secs")?
                            .parse::<u64>()
                            .map_err(|err| format!("invalid --recovery-deadline-secs: {err}"))?;
                }
                "--fault-mode" => {
                    idx += 1;
                    config.fault_mode =
                        parse_fault_mode(&required_value(&args, idx, "--fault-mode")?)?;
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
        ensure_safe_token("capture interface", &self.capture_interface)?;
        ensure_safe_token("mesh cidr", &self.mesh_cidr)?;
        if self.recovery_deadline_secs == 0
            || self.recovery_deadline_secs > MAX_RECOVERY_DEADLINE_SECS
        {
            return Err(format!(
                "recovery deadline must be 1..={MAX_RECOVERY_DEADLINE_SECS} seconds"
            ));
        }
        if self.dry_run {
            return Ok(());
        }
        let Some(target_host) = self.target_host.as_deref() else {
            return Err("--target-host is required unless --dry-run is set".to_owned());
        };
        let Some(client_host) = self.client_host.as_deref() else {
            return Err("--client-host is required unless --dry-run is set".to_owned());
        };
        ensure_safe_token("target host", target_host)?;
        ensure_safe_token("client host", client_host)?;
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
            stages: daemon_fault_stages(),
        });
    }

    let mut logger = Logger::new(&config.log_path)?;
    logger.line("[chaos-daemon-fault] starting live daemon fault injection")?;
    let report = run_live_daemon_kill(&config, &mut logger)?;
    write_file(
        &config.report_path,
        &serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialise daemon fault report failed: {err}"))?,
    )?;
    logger.line(
        format!(
            "[chaos-daemon-fault] report written to {}",
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
        Err("daemon fault chaos stage failed".to_owned())
    }
}

fn run_live_daemon_kill(config: &Config, logger: &mut Logger) -> Result<Value, String> {
    let target = required_option(config.target_host.as_deref(), "--target-host")?;
    let client = required_option(config.client_host.as_deref(), "--client-host")?;
    let identity = required_path(config.ssh_identity_file.as_deref(), "--ssh-identity-file")?;
    let known_hosts = required_path(config.known_hosts_file.as_deref(), "--known-hosts-file")?;

    logger.line("[chaos-daemon-fault] verifying sudo and baseline daemon socket")?;
    verify_sudo(identity, known_hosts, target)?;
    verify_sudo(identity, known_hosts, client)?;
    wait_for_daemon_socket(identity, known_hosts, target, &config.socket_path, 10, 2)?;

    let traffic_guard = ClientTrafficGuard::start(config, identity, known_hosts, client)?;
    logger.line("[chaos-daemon-fault] client exit-path traffic started")?;

    // ClientTrafficGuard is reused verbatim for both fault modes; only the
    // remote fault script differs (kill vs SIGSTOP/SIGCONT).
    let fault_script = match config.fault_mode {
        FaultMode::Kill => render_remote_kill_script(config),
        FaultMode::StopCont => render_remote_sigstop_script(config),
    };
    let output = capture_root(identity, known_hosts, target, &fault_script);

    let cleanup_result = traffic_guard.stop();
    let output = output?;
    let client_output = cleanup_result.map_err(|err| {
        format!(
            "client leak-check guard failed fail-closed; a broken or missing capture can never pass the plaintext check: {err}"
        )
    })?;

    logger.block(output.as_str())?;
    logger.block(client_output.as_str())?;
    let observation = KillStageObservation::parse(&output, &client_output)?;
    Ok(render_live_report(config, &observation))
}

struct ClientTrafficGuard<'a> {
    identity: &'a Path,
    known_hosts: &'a Path,
    client: &'a str,
}

impl<'a> ClientTrafficGuard<'a> {
    fn start(
        config: &'a Config,
        identity: &'a Path,
        known_hosts: &'a Path,
        client: &'a str,
    ) -> Result<Self, String> {
        let duration = config.recovery_deadline_secs + 60;
        let script = render_client_traffic_start_script(duration);
        run_root(identity, known_hosts, client, &script)?;
        Ok(Self {
            identity,
            known_hosts,
            client,
        })
    }

    fn stop(self) -> Result<String, String> {
        let script = render_client_traffic_stop_script();
        capture_root(self.identity, self.known_hosts, self.client, &script)
    }
}

/// Shared fail-closed capture tally for every tcpdump leak check in this bin
/// (audit I2 finding 2, 2026-09-11). A capture that is missing, empty,
/// unproven (no provenance marker, or tcpdump never printed its "listening on"
/// banner into the error file), or backed by a tcpdump stderr containing
/// anything but the known-benign startup/summary lines is an ERROR. Those lines
/// include the `tcpdump: verbose output suppressed, …` notice that tcpdump
/// 4.99 prints on every non-verbose capture; before it was listed, every live
/// run failed this check on Debian 13 guests (2026-09-27). Without the
/// whitelist entry the zero-plaintext claim would be unmeasured, and an
/// unmeasured claim fails the stage instead of passing it. On the error path
/// the script prints
/// `<check_var>=error` plus the reason and exits 3 (capture_root surfaces a
/// non-zero exit as a hard error); the observation parser additionally treats
/// an in-band `<check_var>=error` as a stage failure naming the reason.
fn render_capture_leak_tally_sh(
    capture_path: &str,
    error_path: &str,
    lines_var: &str,
    check_var: &str,
    reason_var: &str,
) -> String {
    format!(
        r#"{reason_var}=""
if [ ! -f {capture_path} ]; then
  {reason_var}=capture_missing
elif [ ! -s {capture_path} ]; then
  {reason_var}=capture_empty
elif ! grep -q '^capture_provenance=' {capture_path} 2>/dev/null; then
  {reason_var}=capture_provenance_missing
elif ! grep -q '^listening on ' {error_path} 2>/dev/null; then
  {reason_var}=tcpdump_did_not_start
else
  {lines_var}="$(grep -Evc '^(tcpdump:|listening on|capture_provenance=|$)' {capture_path} 2>/dev/null || true)"
  case "${lines_var}" in ''|*[!0-9]*) {lines_var}=0; {reason_var}=unparseable_capture_tally ;; esac
fi
if [ -z "${reason_var}" ]; then
  tcpdump_err_lines="$(grep -Evc '^(dropped privs to |listening on |tcpdump: verbose output suppressed, use -v\[v\]\.\.\. for full protocol decode$|[0-9]+ packets (captured|received by filter|dropped by kernel))' {error_path} 2>/dev/null || true)"
  case "$tcpdump_err_lines" in ''|*[!0-9]*) tcpdump_err_lines=0 ;; esac
  if [ "$tcpdump_err_lines" != "0" ]; then
    {reason_var}=tcpdump_error_file_nonempty
  fi
fi
if [ -n "${reason_var}" ]; then
  printf '{lines_var}=0\n'
  printf '{check_var}=error\n'
  printf '{reason_var}=%s\n' "${reason_var}"
  # 2026-09-30 katana-u26: the work_dir (holding tcpdump.err) is rm -rf'ed by
  # the cleanup trap, so an error verdict used to leave NO evidence of why the
  # capture failed. Surface a bounded single-line excerpt of tcpdump's stderr
  # in the k=v stream (the observation parser ignores unknown keys) before the
  # fail-closed exit.
  tcpdump_error_snippet="$(tr '\n' ' ' 2>/dev/null < {error_path} | cut -c1-240)"
  printf 'tcpdump_error_snippet=%s\n' "$tcpdump_error_snippet"
  exit 3
fi
if [ "${lines_var}" = "0" ]; then
  {check_var}=pass
else
  {check_var}=fail
fi
"#
    )
}

/// Bounded readiness wait for a backgrounded tcpdump: a real readiness signal
/// (`listening on ` in tcpdump's stderr file) instead of a blind `sleep 2`.
/// 2026-09-30 katana-u26: the daemon-fault kill path declared recovery on the
/// first recovery-poll iteration, tore tcpdump down ~1.5s after spawning it,
/// and the kernel log proves the device was never opened (no `promiscuous
/// mode` line), so the stderr file never received the banner and the leak
/// tally failed closed with `tcpdump_did_not_start`. Waiting for the banner
/// (bounded, 1s polls) makes the fault window start from a PROVEN capture and
/// still fails closed: on timeout this prints `tcpdump_ready=false` plus a
/// bounded excerpt of tcpdump's stderr for diagnosability, then emits
/// `plaintext_leak_check=error` / `plaintext_error=tcpdump_not_ready` (verdict
/// keys first, the stderr excerpt LAST, because the orchestrator keeps only
/// the first 500 chars of stderr) and exits 3 BEFORE any fault is injected (the caller's EXIT trap restores the
/// service), so no pass is possible without a proven working capture.
/// `error_path_expr` is inserted verbatim (callers pass a quoted runtime path
/// such as `"$work_dir/tcpdump.err"`), mirroring [`render_capture_leak_tally_sh`].
fn render_tcpdump_readiness_wait_sh(error_path_expr: &str, timeout_secs: u64) -> String {
    format!(
        r#"tcpdump_ready=false
readiness_i=0
while [ "$readiness_i" -lt {timeout_secs} ]; do
  if grep -q '^listening on ' {error_path_expr} 2>/dev/null; then
    tcpdump_ready=true
    break
  fi
  readiness_i=$((readiness_i + 1))
  sleep 1
done
printf 'tcpdump_ready=%s\n' "$tcpdump_ready"
if [ "$tcpdump_ready" = "false" ]; then
  # Fail closed BEFORE the fault is injected: a fault window without a proven
  # capture proves nothing. The caller's EXIT trap tears down and restores.
  # The verdict keys print FIRST and the free-text stderr excerpt LAST: the
  # orchestrator keeps only the first 500 chars of stderr/output, so the
  # excerpt must never be able to push the verdict out of the kept window.
  printf 'tcpdump_lines=0\n'
  printf 'plaintext_leak_check=error\n'
  printf 'plaintext_error=tcpdump_not_ready\n'
  tcpdump_error_snippet="$(tr '\n' ' ' 2>/dev/null < {error_path_expr} | cut -c1-240)"
  printf 'tcpdump_error_snippet=%s\n' "$tcpdump_error_snippet"
  exit 3
fi
"#
    )
}

/// The kill-mode fault window: inject the KILL fault, PROVE the fault landed,
/// then poll for recovery. 2026-09-30 katana-u26 root cause: the old inline
/// block polled `systemctl is-active && [ -S socket ]` immediately after
/// `systemctl kill -s KILL`, and the first iteration raced systemd's SIGKILL
/// reaping (the guest journal shows the kill at 08:00:42 and the exit
/// processed at 08:00:44) while the SIGKILLed daemon could not unlink its
/// socket file — so `recovered=true` fired instantly, the fault window
/// collapsed from 90s to ~1s, and tcpdump was killed before it ever opened
/// the device. Now the fault must be OBSERVED first (`is-active` flipping
/// false, or the socket inode changing — a restart faster than one poll is
/// still caught by the inode), and recovery requires a FRESH socket inode,
/// so a stale pre-fault socket can never stand in for a restarted daemon.
/// `stat` absence or an unchanged inode fail closed (`recovered=false` →
/// `.passed()` refuses the stage), never fail open. The pre-fault inode is a
/// precondition: if it is empty or non-numeric (unreadable socket, `stat`
/// failure) the fragment prints `fault_precondition=socket_inode_unreadable`
/// and exits 1 BEFORE `systemctl kill` — with an empty baseline ANY later
/// readable inode, including the unchanged stale one, would read as a "fresh"
/// socket and fake both the fault observation and the recovery. `service` and
/// `socket_path` are shell-quoted literals; both are parameters so tests can
/// run this fragment under `sh` with fake `systemctl`/`stat` binaries on
/// PATH, replaying the exact katana-u26 race.
fn render_kill_fault_window_sh(
    service: &str,
    socket_path: &str,
    deadline_secs: u64,
    observe_timeout_secs: u64,
) -> String {
    let service = shell_quote(service);
    let socket_path = shell_quote(socket_path);
    format!(
        r#"start_unix="$(date +%s)"
socket_ino_before="$(stat -c %i {socket_path} 2>/dev/null || true)"
case "$socket_ino_before" in
  ''|*[!0-9]*) printf 'fault_precondition=socket_inode_unreadable\n'; exit 1 ;;
esac
printf 'fault_signal=KILL\n'
systemctl kill -s KILL {service}
fault_observed=false
observe_i=0
while [ "$observe_i" -lt {observe_timeout_secs} ]; do
  if ! systemctl is-active --quiet {service} 2>/dev/null; then
    fault_observed=true
    break
  fi
  socket_ino_now="$(stat -c %i {socket_path} 2>/dev/null || true)"
  if [ -n "$socket_ino_now" ] && [ "$socket_ino_now" != "$socket_ino_before" ]; then
    fault_observed=true
    break
  fi
  observe_i=$((observe_i + 1))
  sleep 1
done
printf 'fault_observed=%s\n' "$fault_observed"
recovered=false
if [ "$fault_observed" = "true" ]; then
  end_unix="$((start_unix + {deadline_secs}))"
  while [ "$(date +%s)" -le "$end_unix" ]; do
    socket_ino_now="$(stat -c %i {socket_path} 2>/dev/null || true)"
    if systemctl is-active --quiet {service} && [ -S {socket_path} ] && [ -n "$socket_ino_now" ] && [ "$socket_ino_now" != "$socket_ino_before" ]; then
      recovered=true
      break
    fi
    sleep 1
  done
fi
measured_recovery_secs="$(( $(date +%s) - start_unix ))"
"#
    )
}

/// Teardown for the client traffic guard: stop the pinger and tcpdump, then
/// tally the plaintext capture fail-closed via
/// [`render_capture_leak_tally_sh`]. A missing or empty capture exits 3 with
/// `client_plaintext_leak_check=error` — it can never be read as a pass.
fn render_client_traffic_stop_script() -> String {
    let traffic_pid_file = shell_quote(CLIENT_TRAFFIC_PID_FILE);
    let tcpdump_pid_file = shell_quote(CLIENT_TCPDUMP_PID_FILE);
    let capture_file = shell_quote(CLIENT_TCPDUMP_CAPTURE_FILE);
    let error_file = shell_quote(CLIENT_TCPDUMP_ERROR_FILE);
    let leak_tally = render_capture_leak_tally_sh(
        &capture_file,
        &error_file,
        "client_plaintext_lines",
        "client_plaintext_leak_check",
        "client_plaintext_error",
    );
    format!(
        r#"set -eu
traffic_pid_file={traffic_pid_file}
tcpdump_pid_file={tcpdump_pid_file}
capture_file={capture_file}
error_file={error_file}
stop_pid_file() {{
  pid_file="$1"
  if [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file")"
    case "$pid" in ''|*[!0-9]*) : ;; *) kill "$pid" >/dev/null 2>&1 || true; wait "$pid" >/dev/null 2>&1 || true ;; esac
    rm -f "$pid_file"
  fi
}}
stop_pid_file "$traffic_pid_file"
stop_pid_file "$tcpdump_pid_file"
{leak_tally}
rm -f "$capture_file" "$error_file"
printf 'client_plaintext_lines=%s\n' "$client_plaintext_lines"
printf 'client_plaintext_leak_check=%s\n' "$client_plaintext_leak_check"
"#
    )
}

fn render_client_traffic_start_script(duration_secs: u64) -> String {
    let traffic_pid_file = shell_quote(CLIENT_TRAFFIC_PID_FILE);
    let tcpdump_pid_file = shell_quote(CLIENT_TCPDUMP_PID_FILE);
    let capture_file = shell_quote(CLIENT_TCPDUMP_CAPTURE_FILE);
    let error_file = shell_quote(CLIENT_TCPDUMP_ERROR_FILE);
    let probe_target = shell_quote(CLIENT_PROBE_TARGET);
    format!(
        r#"set -eu
# RSA-0080: a non-login shell omits the sbin directories where ip/tcpdump live.
PATH="/usr/local/sbin:/usr/sbin:/sbin:${{PATH:-/usr/local/bin:/usr/bin:/bin}}"; export PATH
traffic_pid_file={traffic_pid_file}
tcpdump_pid_file={tcpdump_pid_file}
capture_file={capture_file}
error_file={error_file}
probe_target={probe_target}
rm -f "$traffic_pid_file" "$tcpdump_pid_file" "$capture_file" "$error_file"
# Named precheck markers: an opaque exit 1 tells the operator nothing about
# which tool was absent on the guest (live 2026-09-10 class).
command -v tcpdump >/dev/null 2>&1 || {{ printf 'missing_tcpdump=true\n'; exit 1; }}
command -v timeout >/dev/null 2>&1 || {{ printf 'missing_timeout=true\n'; exit 1; }}
command -v ip >/dev/null 2>&1 || {{ printf 'missing_ip=true\n'; exit 1; }}
capture_interface="$(ip route show default 0.0.0.0/0 | awk 'NR==1 {{ for (i=1; i<=NF; i++) if ($i == "dev") {{ print $(i+1); exit }} }}')"
case "$capture_interface" in ""|*[!A-Za-z0-9_.:-]*|rustynet0) exit 1 ;; esac
# Provenance marker: the capture is pre-seeded so a missing or empty capture
# downstream can only mean tcpdump never ran or truncated the file (fail
# closed); a healthy zero-packet window still yields a provable capture.
printf 'capture_provenance=started_unix=%s\n' "$(date +%s)" > "$capture_file"
timeout {duration_secs} tcpdump -i "$capture_interface" -nn -l "icmp and dst host $probe_target" >> "$capture_file" 2> "$error_file" &
printf '%s\n' "$!" > "$tcpdump_pid_file"
sleep 2
# Unpredictable sink path: root must not write a fixed /tmp name.
traffic_log="$(mktemp /tmp/rustynet-chaos-daemon-fault-client-log.XXXXXX)"
(
  end="$(( $(date +%s) + {duration_secs} ))"
  while [ "$(date +%s)" -lt "$end" ]; do
    ping -n -c 1 -W 1 "$probe_target" >/dev/null 2>&1 || true
    sleep 1
  done
) > "$traffic_log" 2>&1 &
printf '%s\n' "$!" > "$traffic_pid_file"
"#
    )
}

fn render_remote_kill_script(config: &Config) -> String {
    let service = shell_quote(&config.service_name);
    let socket_path = shell_quote(&config.socket_path);
    let capture_interface = shell_quote(&config.capture_interface);
    let mesh_cidr = shell_quote(&config.mesh_cidr);
    let deadline = config.recovery_deadline_secs;
    let leak_tally = render_capture_leak_tally_sh(
        "\"$work_dir/tcpdump.txt\"",
        "\"$work_dir/tcpdump.err\"",
        "tcpdump_lines",
        "plaintext_leak_check",
        "plaintext_error",
    );
    let readiness = render_tcpdump_readiness_wait_sh("\"$work_dir/tcpdump.err\"", 15);
    let fault_window =
        render_kill_fault_window_sh(&config.service_name, &config.socket_path, deadline, 15);

    format!(
        r#"set -eu
# RSA-0080: a non-login shell omits the sbin directories where ip/tcpdump/systemctl live.
PATH="/usr/local/sbin:/usr/sbin:/sbin:${{PATH:-/usr/local/bin:/usr/bin:/bin}}"; export PATH
service={service}
socket_path={socket_path}
capture_interface={capture_interface}
mesh_cidr={mesh_cidr}
deadline={deadline}
work_dir="$(mktemp -d /tmp/rustynet-chaos-daemon-fault.XXXXXX)"
tcpdump_pid=""
cleanup() {{
  if [ -n "$tcpdump_pid" ]; then
    kill "$tcpdump_pid" >/dev/null 2>&1 || true
    wait "$tcpdump_pid" >/dev/null 2>&1 || true
  fi
  # A fault window with failed auto-restarts arms the unit's start limit;
  # clear it or this teardown start is refused and the exit stays down.
  systemctl reset-failed "$service" >/dev/null 2>&1 || true
  systemctl start "$service" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}}
trap cleanup EXIT HUP INT TERM
printf 'teardown_registered_before_fault=true\n'
command -v tcpdump >/dev/null 2>&1 || {{ printf 'missing_tcpdump=true\n'; exit 1; }}
command -v timeout >/dev/null 2>&1 || {{ printf 'missing_timeout=true\n'; exit 1; }}
command -v ip >/dev/null 2>&1 || {{ printf 'missing_ip=true\n'; exit 1; }}
systemctl is-active --quiet "$service" || {{ printf 'baseline_service_active=false\n'; exit 1; }}
test -S "$socket_path" || {{ printf 'baseline_socket_present=false\n'; exit 1; }}
if [ "$capture_interface" = "default-route" ]; then
  capture_interface="$(ip route show default 0.0.0.0/0 | awk 'NR==1 {{ for (i=1; i<=NF; i++) if ($i == "dev") {{ print $(i+1); exit }} }}')"
fi
case "$capture_interface" in
  ""|*[!A-Za-z0-9_.:-]*) printf 'invalid_capture_interface=%s\n' "$capture_interface"; exit 1 ;;
esac
if [ "$capture_interface" = "rustynet0" ]; then
  printf 'invalid_capture_interface=rustynet0\n'
  exit 1
fi
printf 'capture_interface=%s\n' "$capture_interface"
# The CIDR is spliced into a BPF string; charset-validate it first.
case "$mesh_cidr" in ''|*[!A-Za-z0-9.:/]*) printf 'invalid_mesh_cidr=true\n'; exit 1 ;; esac
filter="ip and src net $mesh_cidr and not dst net $mesh_cidr"
# Provenance marker + append: a missing or empty capture downstream fails
# closed (audit I2 finding 2) instead of tallying as zero plaintext.
printf 'capture_provenance=started_unix=%s\n' "$(date +%s)" > "$work_dir/tcpdump.txt"
timeout "$((deadline + 45))" tcpdump -i "$capture_interface" -nn -l "$filter" >> "$work_dir/tcpdump.txt" 2> "$work_dir/tcpdump.err" &
tcpdump_pid="$!"
{readiness}
{fault_window}
kill "$tcpdump_pid" >/dev/null 2>&1 || true
wait "$tcpdump_pid" >/dev/null 2>&1 || true
tcpdump_pid=""
{leak_tally}
printf 'recovered=%s\n' "$recovered"
printf 'measured_recovery_secs=%s\n' "$measured_recovery_secs"
printf 'tcpdump_lines=%s\n' "$tcpdump_lines"
printf 'plaintext_leak_check=%s\n' "$plaintext_leak_check"
"#
    )
}

/// SIGSTOP/SIGCONT variant of [`render_remote_kill_script`]. The prologue is
/// IDENTICAL (mirrors render_remote_kill_script ~395-440): same mktemp, same
/// `trap cleanup EXIT HUP INT TERM` registered BEFORE the fault, same
/// teardown_registered_before_fault marker, same tcpdump/timeout/active/socket
/// preflight, same default-route capture iface that REFUSES rustynet0, and the
/// same `timeout $((deadline+15))` tcpdump with the same BPF mesh-egress
/// filter. Divergences vs the kill path:
///   * the cleanup trap issues `systemctl kill -s CONT` BEFORE `systemctl start`
///     so the daemon is never left frozen on any abort path,
///   * the fault block STOPs the daemon, then POLLS `/proc/$pid/stat` for the
///     `T` (stopped, or `t` tracing-stop) kernel state within a bounded window
///     ([`STOP_POLL_WINDOW_SECS`]) instead of sampling one instant, records the
///     distinct state sequence, holds past the reconcile interval, CONTs, and
///     polls for a resumed (`S`/`R`/`D`) state within [`RESUME_POLL_WINDOW_SECS`].
///
/// Why poll instead of one sample: a task in uninterruptible sleep (`D`) holds
/// SIGSTOP pending until it returns from the wait, so a single first-instant
/// sample can legitimately read `D` on a healthy freeze (live
/// katana-u37-anchor-b78, 2026-10-03: observed_stopped_state=D with
/// recovered=true and all leak checks passing). An empty stop sequence or a
/// resume sequence that never reaches `S`/`R` still fails the stage closed.
///
/// The bounded recovery poll and leak tally tail are identical to the kill path.
fn render_remote_sigstop_script(config: &Config) -> String {
    let service = shell_quote(&config.service_name);
    let socket_path = shell_quote(&config.socket_path);
    let capture_interface = shell_quote(&config.capture_interface);
    let mesh_cidr = shell_quote(&config.mesh_cidr);
    let deadline = config.recovery_deadline_secs;
    let leak_tally = render_capture_leak_tally_sh(
        "\"$work_dir/tcpdump.txt\"",
        "\"$work_dir/tcpdump.err\"",
        "tcpdump_lines",
        "plaintext_leak_check",
        "plaintext_error",
    );
    let readiness = render_tcpdump_readiness_wait_sh("\"$work_dir/tcpdump.err\"", 15);

    format!(
        r#"set -eu
# RSA-0080: a non-login shell omits the sbin directories where ip/tcpdump/systemctl live.
PATH="/usr/local/sbin:/usr/sbin:/sbin:${{PATH:-/usr/local/bin:/usr/bin:/bin}}"; export PATH
service={service}
socket_path={socket_path}
capture_interface={capture_interface}
mesh_cidr={mesh_cidr}
deadline={deadline}
work_dir="$(mktemp -d /tmp/rustynet-chaos-daemon-sigstop.XXXXXX)"
tcpdump_pid=""
cleanup() {{
  if [ -n "$tcpdump_pid" ]; then
    kill "$tcpdump_pid" >/dev/null 2>&1 || true
    wait "$tcpdump_pid" >/dev/null 2>&1 || true
  fi
  systemctl kill -s CONT "$service" >/dev/null 2>&1 || true
  # A fault window with failed auto-restarts arms the unit's start limit;
  # clear it or this teardown start is refused and the exit stays down.
  systemctl reset-failed "$service" >/dev/null 2>&1 || true
  systemctl start "$service" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}}
trap cleanup EXIT HUP INT TERM
printf 'teardown_registered_before_fault=true\n'
command -v tcpdump >/dev/null 2>&1 || {{ printf 'missing_tcpdump=true\n'; exit 1; }}
command -v timeout >/dev/null 2>&1 || {{ printf 'missing_timeout=true\n'; exit 1; }}
command -v ip >/dev/null 2>&1 || {{ printf 'missing_ip=true\n'; exit 1; }}
systemctl is-active --quiet "$service" || {{ printf 'baseline_service_active=false\n'; exit 1; }}
test -S "$socket_path" || {{ printf 'baseline_socket_present=false\n'; exit 1; }}
if [ "$capture_interface" = "default-route" ]; then
  capture_interface="$(ip route show default 0.0.0.0/0 | awk 'NR==1 {{ for (i=1; i<=NF; i++) if ($i == "dev") {{ print $(i+1); exit }} }}')"
fi
case "$capture_interface" in
  ""|*[!A-Za-z0-9_.:-]*) printf 'invalid_capture_interface=%s\n' "$capture_interface"; exit 1 ;;
esac
if [ "$capture_interface" = "rustynet0" ]; then
  printf 'invalid_capture_interface=rustynet0\n'
  exit 1
fi
printf 'capture_interface=%s\n' "$capture_interface"
# The CIDR is spliced into a BPF string; charset-validate it first.
case "$mesh_cidr" in ''|*[!A-Za-z0-9.:/]*) printf 'invalid_mesh_cidr=true\n'; exit 1 ;; esac
filter="ip and src net $mesh_cidr and not dst net $mesh_cidr"
# Provenance marker + append: a missing or empty capture downstream fails
# closed (audit I2 finding 2) instead of tallying as zero plaintext.
printf 'capture_provenance=started_unix=%s\n' "$(date +%s)" > "$work_dir/tcpdump.txt"
timeout "$((deadline + 45))" tcpdump -i "$capture_interface" -nn -l "$filter" >> "$work_dir/tcpdump.txt" 2> "$work_dir/tcpdump.err" &
tcpdump_pid="$!"
{readiness}
start_unix="$(date +%s)"
printf 'fault_signal=STOP\n'
systemctl kill -s STOP "$service"
main_pid="$(systemctl show -p MainPID --value "$service" 2>/dev/null || true)"
case "$main_pid" in ""|*[!0-9]*|0) main_pid="" ;; esac
observed_stopped_state=unknown
observed_stopped_states=
if [ -n "$main_pid" ]; then
  stop_poll_deadline=$(( $(date +%s) + {STOP_POLL_WINDOW_SECS} ))
  while :; do
    state="$(awk '{{ print $3 }}' "/proc/$main_pid/stat" 2>/dev/null || true)"
    case "$state" in ""|*[!A-Za-z]*) state=unknown ;; esac
    if [ "$observed_stopped_state" = unknown ]; then
      observed_stopped_state="$state"
    fi
    case "$observed_stopped_states" in
      "$state"|*",$state") : ;;
      *) observed_stopped_states="${{observed_stopped_states:+$observed_stopped_states,}}$state" ;;
    esac
    case "$state" in
      T|t) break ;;
    esac
    if [ "$(date +%s)" -ge "$stop_poll_deadline" ]; then break; fi
    sleep 0.2
  done
fi
printf 'observed_stopped_state=%s\n' "$observed_stopped_state"
printf 'observed_stopped_states=%s\n' "$observed_stopped_states"
sleep 3
printf 'fault_signal_resume=CONT\n'
systemctl kill -s CONT "$service"
# Fail closed on an unfinished resume too: poll for a state that proves the
# task left the stopped state (S sleeping, R running or D waiting on I/O; a
# daemon that just resumed commonly writes and fsyncs state, which reads D)
# within a bounded window right after CONT, and
# record every distinct state seen so the report shows the whole sequence.
observed_resumed_states=
resumed_state=unknown
if [ -n "$main_pid" ]; then
  resume_poll_deadline=$(( $(date +%s) + {RESUME_POLL_WINDOW_SECS} ))
  while :; do
    state="$(awk '{{ print $3 }}' "/proc/$main_pid/stat" 2>/dev/null || true)"
    case "$state" in ""|*[!A-Za-z]*) state=unknown ;; esac
    resumed_state="$state"
    case "$observed_resumed_states" in
      "$state"|*",$state") : ;;
      *) observed_resumed_states="${{observed_resumed_states:+$observed_resumed_states,}}$state" ;;
    esac
    case "$state" in
      S|R|D) break ;;
    esac
    if [ "$(date +%s)" -ge "$resume_poll_deadline" ]; then break; fi
    sleep 0.2
  done
fi
printf 'resumed_state=%s\n' "$resumed_state"
printf 'observed_resumed_states=%s\n' "$observed_resumed_states"
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
kill "$tcpdump_pid" >/dev/null 2>&1 || true
wait "$tcpdump_pid" >/dev/null 2>&1 || true
tcpdump_pid=""
{leak_tally}
printf 'recovered=%s\n' "$recovered"
printf 'measured_recovery_secs=%s\n' "$measured_recovery_secs"
printf 'tcpdump_lines=%s\n' "$tcpdump_lines"
printf 'plaintext_leak_check=%s\n' "$plaintext_leak_check"
"#
    )
}

/// Bounded window (seconds) the guest script polls `/proc/<MainPID>/stat` for
/// a stopped state after SIGSTOP before giving up. A task in uninterruptible
/// sleep (`D`) holds SIGSTOP pending until it returns from the wait, so the
/// stop can land later than the first instant sample (live
/// katana-u37-anchor-b78, 2026-10-03).
const STOP_POLL_WINDOW_SECS: u64 = 10;

/// Bounded window (seconds) the guest script polls for a state that proves the
/// task left the stopped state (`S`/`R`/`D`) right after SIGCONT, so a
/// still-stopped (`T`) sample cannot pass.
const RESUME_POLL_WINDOW_SECS: u64 = 2;

/// Pass input for the SIGSTOP/SIGCONT stage: true when the bounded stop-poll
/// sequence proves the kernel actually parked the task — it contains `T`
/// (job-control stop) or `t` (tracing stop). Decided purely from the contents:
/// `["D","D","T"]` is true (the u37 race — `D` before the stop landed, `T`
/// once it did), `["T"]` alone is true, while `["D","D","D"]`, `["R"]`, `["S"]`
/// and `[]` are false (never stopped).
fn stop_sequence_proves_stopped(states: &[String]) -> bool {
    states.iter().any(|state| state == "T" || state == "t")
}

/// Pass input for the SIGSTOP/SIGCONT stage: true when the bounded post-SIGCONT
/// sequence proves the task left the stopped state — it contains `S`
/// (interruptible sleep), `R` (running) or `D` (uninterruptible sleep: a
/// freshly resumed daemon writing and fsyncing state reads `D`, as in
/// katana-u39; a task that is still stopped reads `T`, never `D`). A sequence
/// that stays `T` (SIGCONT never took), is `unknown` or is empty is false.
fn resume_sequence_proves_resumed(states: &[String]) -> bool {
    states
        .iter()
        .any(|state| state == "S" || state == "R" || state == "D")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct KillStageObservation {
    teardown_registered_before_fault: bool,
    recovered: bool,
    measured_recovery_secs: u64,
    tcpdump_lines: u64,
    plaintext_leak_check: String,
    client_plaintext_lines: u64,
    client_plaintext_leak_check: String,
    capture_interface: Option<String>,
    /// Field-3 (`state`) read from `/proc/<MainPID>/stat` at the FIRST sample
    /// instant after SIGSTOP (the legacy single-instant key, kept for the
    /// report; the pass decision no longer rests on it). `None` for kill-mode
    /// output (the key is never emitted there), so it never affects the
    /// existing `.passed()` kill check.
    observed_stopped_state: Option<String>,
    /// Every distinct consecutive `/proc/<MainPID>/stat` state sampled while
    /// polling for the stop within [`STOP_POLL_WINDOW_SECS`] after SIGSTOP, in
    /// order. Containing `T`/`t` — not any single instant — is what
    /// `passed_stopcont` requires: a task in uninterruptible sleep (`D`) holds
    /// SIGSTOP pending until it leaves the wait, so a first-instant sample
    /// alone can read `D` (live katana-u37-anchor-b78, 2026-10-03). Empty
    /// fails the stage closed.
    observed_stopped_states: Vec<String>,
    /// Every distinct consecutive state sampled while polling right after
    /// SIGCONT for a resumed (`S`/`R`/`D`) state within
    /// [`RESUME_POLL_WINDOW_SECS`]. Empty, or a sequence that never reaches
    /// `S`/`R` (e.g. the task still reads `T`), fails the stage closed.
    observed_resumed_states: Vec<String>,
    /// Last state observed in the post-SIGCONT resume window (`unknown` when
    /// `/proc` was unreadable). Informational; the pass criterion is
    /// [`KillStageObservation::observed_resumed_states`].
    resumed_state: Option<String>,
    /// Kill-mode proof that the fault actually landed (`is-active` flipped
    /// false or the socket inode changed) before recovery was measured.
    /// `None` when the key is absent (SIGSTOP output never emits it, and an
    /// old/broken guest script would not either); `.passed()` requires
    /// `Some(true)` so a missing or false observation can never pass kill mode.
    fault_observed: Option<bool>,
}

impl KillStageObservation {
    fn parse(exit_output: &str, client_output: &str) -> Result<Self, String> {
        let exit_value = |key: &str| -> Option<&str> {
            exit_output.lines().find_map(|line| {
                line.split_once('=')
                    .and_then(|(found, value)| (found == key).then_some(value.trim()))
            })
        };
        let client_value = |key: &str| -> Option<&str> {
            client_output.lines().find_map(|line| {
                line.split_once('=')
                    .and_then(|(found, value)| (found == key).then_some(value.trim()))
            })
        };
        // Audit I2 finding 2 (2026-09-11): a broken capture is reported by the
        // guest as `<check>=error` plus a named reason (the script also exits
        // 3, which capture_root surfaces as a hard error before this parser
        // runs). Treat an in-band error verdict as a stage failure naming the
        // reason — never as a zero-count pass.
        if exit_value("plaintext_leak_check") == Some("error") {
            return Err(format!(
                "target tcpdump leak check errored: {}",
                exit_value("plaintext_error").unwrap_or("reason not reported")
            ));
        }
        if client_value("client_plaintext_leak_check") == Some("error") {
            return Err(format!(
                "client tcpdump leak check errored: {}",
                client_value("client_plaintext_error").unwrap_or("reason not reported")
            ));
        }
        let parse_exit_bool = |key: &str| -> Result<bool, String> {
            match exit_value(key) {
                Some("true") => Ok(true),
                Some("false") => Ok(false),
                Some(other) => Err(format!("invalid boolean for {key}: {other}")),
                None => Err(format!("missing {key} in daemon fault output")),
            }
        };
        let parse_exit_u64 = |key: &str| -> Result<u64, String> {
            exit_value(key)
                .ok_or_else(|| format!("missing {key} in daemon fault output"))?
                .parse::<u64>()
                .map_err(|err| format!("invalid integer for {key}: {err}"))
        };
        let parse_client_u64 = |key: &str| -> Result<u64, String> {
            client_value(key)
                .ok_or_else(|| format!("missing {key} in client leak output"))?
                .parse::<u64>()
                .map_err(|err| format!("invalid integer for {key}: {err}"))
        };
        let fault_observed = match exit_value("fault_observed") {
            None => None,
            Some("true") => Some(true),
            Some("false") => Some(false),
            Some(other) => return Err(format!("invalid boolean for fault_observed: {other}")),
        };
        // Bounded poll sequences are comma-joined lists of `/proc` states as
        // the guest script emitted them ("D,D,T"). An absent key parses to an
        // empty sequence, which `passed_stopcont` treats as fail-closed.
        let parse_state_list = |key: &str| -> Vec<String> {
            exit_value(key)
                .map(|raw| {
                    raw.split(',')
                        .map(|state| state.trim().to_owned())
                        .filter(|state| !state.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        let observed_stopped_states = parse_state_list("observed_stopped_states");
        let observed_resumed_states = parse_state_list("observed_resumed_states");
        let resumed_state = observed_resumed_states.last().cloned();
        Ok(Self {
            teardown_registered_before_fault: parse_exit_bool("teardown_registered_before_fault")?,
            recovered: parse_exit_bool("recovered")?,
            measured_recovery_secs: parse_exit_u64("measured_recovery_secs")?,
            tcpdump_lines: parse_exit_u64("tcpdump_lines")?,
            plaintext_leak_check: exit_value("plaintext_leak_check")
                .ok_or_else(|| "missing plaintext_leak_check in daemon fault output".to_owned())?
                .to_owned(),
            client_plaintext_lines: parse_client_u64("client_plaintext_lines")?,
            client_plaintext_leak_check: client_value("client_plaintext_leak_check")
                .ok_or_else(|| "missing client_plaintext_leak_check in client output".to_owned())?
                .to_owned(),
            capture_interface: exit_value("capture_interface").map(str::to_owned),
            observed_stopped_state: exit_value("observed_stopped_state").map(str::to_owned),
            observed_stopped_states,
            observed_resumed_states,
            resumed_state,
            fault_observed,
        })
    }

    fn passed(&self, deadline_secs: u64) -> bool {
        self.teardown_registered_before_fault
            && self.fault_observed == Some(true)
            && self.recovered
            && self.measured_recovery_secs <= deadline_secs
            && self.tcpdump_lines == 0
            && self.plaintext_leak_check == "pass"
            && self.client_plaintext_lines == 0
            && self.client_plaintext_leak_check == "pass"
    }

    /// Pass-check for the SIGSTOP/SIGCONT sub-stage. ANDs: teardown was
    /// registered before the fault, the bounded stop-poll sequence proves the
    /// daemon actually reached the stopped (`T`/`t`) state, the bounded
    /// resume-poll sequence proves it left the stopped state (`S`/`R`) after
    /// SIGCONT, it recovered within the deadline, and ALL FOUR zero-plaintext
    /// leak checks (target tcpdump + client tcpdump) held during the fault
    /// window. Fails closed when either sequence is absent (an old guest
    /// script sampling one instant proves nothing about the stop or the
    /// resume) or never reaches the required states.
    fn passed_stopcont(&self, deadline_secs: u64) -> bool {
        self.teardown_registered_before_fault
            && stop_sequence_proves_stopped(&self.observed_stopped_states)
            && resume_sequence_proves_resumed(&self.observed_resumed_states)
            && self.recovered
            && self.measured_recovery_secs <= deadline_secs
            && self.tcpdump_lines == 0
            && self.plaintext_leak_check == "pass"
            && self.client_plaintext_lines == 0
            && self.client_plaintext_leak_check == "pass"
    }
}

fn render_live_report(config: &Config, observation: &KillStageObservation) -> Value {
    // The implemented stage index depends on the fault mode: kill mode proves
    // stages[0] (chaos_daemon_kill_during_reconcile), SIGSTOP/SIGCONT mode
    // proves stages[2] (chaos_daemon_sigstop_sigcont). Every other stage stays
    // "skipped" in both modes, so the implemented/remaining counts are constant.
    let implemented_index = match config.fault_mode {
        FaultMode::Kill => 0usize,
        FaultMode::StopCont => 2usize,
    };
    let implemented_status = match config.fault_mode {
        FaultMode::Kill => {
            if observation.passed(config.recovery_deadline_secs) {
                "pass"
            } else {
                "fail"
            }
        }
        FaultMode::StopCont => {
            if observation.passed_stopcont(config.recovery_deadline_secs) {
                "pass"
            } else {
                "fail"
            }
        }
    };
    let stages = daemon_fault_stages()
        .into_iter()
        .enumerate()
        .map(|(idx, stage)| {
            if idx == implemented_index {
                let mut implemented = json!({
                    "name": stage.name,
                    "status": implemented_status,
                    "fault": stage.fault,
                    "pass_criterion": stage.pass_criterion,
                    "recovery_deadline_secs": config.recovery_deadline_secs,
                    "measured_recovery_secs": observation.measured_recovery_secs,
                    "plaintext_leak_check": observation.plaintext_leak_check,
                    "tcpdump_lines": observation.tcpdump_lines,
                    "client_plaintext_leak_check": observation.client_plaintext_leak_check,
                    "client_plaintext_lines": observation.client_plaintext_lines,
                    "capture_interface": observation.capture_interface,
                    "teardown_registered_before_fault": observation.teardown_registered_before_fault,
                    "recovered": observation.recovered,
                });
                if config.fault_mode == FaultMode::Kill {
                    // Surface the proof that the KILL fault actually landed.
                    implemented["fault_observed"] = json!(observation.fault_observed);
                }
                if config.fault_mode == FaultMode::StopCont {
                    // Surface the proof that the daemon was actually frozen:
                    // the first-instant sample (legacy key, often `D` during
                    // the u37 race) plus the bounded stop/resume poll
                    // sequences that actually decide the stage.
                    implemented["observed_stopped_state"] =
                        json!(observation.observed_stopped_state);
                    implemented["observed_stopped_states"] =
                        json!(observation.observed_stopped_states);
                    implemented["stop_poll_window_secs"] = json!(STOP_POLL_WINDOW_SECS);
                    implemented["resumed_state"] = json!(observation.resumed_state);
                    implemented["observed_resumed_states"] =
                        json!(observation.observed_resumed_states);
                    implemented["resume_poll_window_secs"] = json!(RESUME_POLL_WINDOW_SECS);
                }
                implemented
            } else {
                json!({
                    "name": stage.name,
                    "status": "skipped",
                    "fault": stage.fault,
                    "pass_criterion": stage.pass_criterion,
                    "recovery_deadline_secs": stage.recovery_deadline_secs,
                    "measured_recovery_secs": null,
                    "plaintext_leak_check": "not-run",
                    "summary": "not implemented in this daemon-fault live slice",
                })
            }
        })
        .collect::<Vec<_>>();
    let summary = match config.fault_mode {
        FaultMode::Kill => {
            "daemon KILL fault was injected under live client traffic with tcpdump plaintext-leak proof"
        }
        FaultMode::StopCont => {
            "daemon SIGSTOP/SIGCONT fault was injected under live client traffic with tcpdump plaintext-leak proof"
        }
    };
    json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": CATEGORY,
        "overall_status": implemented_status,
        "summary": summary,
        "dry_run": false,
        "generated_at_unix": unix_now(),
        "git_commit": config.git_commit,
        "implemented_stage_count": 1,
        "remaining_stage_count": 3,
        "stages": stages,
        "security_invariants": {
            "requires_explicit_enable_chaos_suite": true,
            "requires_teardown_registration_before_injection": true,
            "requires_plaintext_leak_capture_for_live_faults": true,
            "production_state_mutation": true,
            "teardown_registered_before_fault": observation.teardown_registered_before_fault,
            "plaintext_leak_check": observation.plaintext_leak_check,
            "client_plaintext_leak_check": observation.client_plaintext_leak_check,
            "recovered_within_deadline": observation.recovered
                && observation.measured_recovery_secs <= config.recovery_deadline_secs
        }
    })
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

/// Map the `--fault-mode` argument onto [`FaultMode`], rejecting any unknown
/// value so a typo can never silently fall back to the kill path. `kill` keeps
/// the original behavior; `sigstop-cont` selects the freeze-then-resume fault.
fn parse_fault_mode(value: &str) -> Result<FaultMode, String> {
    match value {
        "kill" => Ok(FaultMode::Kill),
        "sigstop-cont" => Ok(FaultMode::StopCont),
        other => Err(format!(
            "invalid --fault-mode: {other} (expected one of: kill, sigstop-cont)"
        )),
    }
}

fn print_usage() {
    eprintln!(
        "usage: {CATEGORY} [--dry-run] [--target-host <user@host>] [--client-host <user@host>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--socket-path <path>] [--service-name <name>] [--capture-interface <name|default-route>] [--mesh-cidr <cidr>] [--recovery-deadline-secs <secs>] [--fault-mode <kill|sigstop-cont>] [--report-path <path>] [--log-path <path>] [--git-commit <sha>]"
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
        assert!(config.client_host.is_none());
    }

    #[test]
    fn live_mode_requires_target_client_and_identity() {
        let err = parse(&[]).expect_err("live mode should require target host");
        assert!(err.contains("--target-host"));
        let err = parse(&["--target-host", "debian@192.0.2.10"])
            .expect_err("live mode should require client host");
        assert!(err.contains("--client-host"));
        let err = parse(&[
            "--target-host",
            "debian@192.0.2.10",
            "--client-host",
            "debian@192.0.2.11",
        ])
        .expect_err("live mode should require identity");
        assert!(err.contains("--ssh-identity-file"));
    }

    #[test]
    fn parser_rejects_shell_metacharacters() {
        let err = parse(&["--dry-run", "--service-name", "rustynetd.service;reboot"])
            .expect_err("service shell metacharacter must reject");
        assert!(err.contains("service name"));
        let err = parse(&["--dry-run", "--capture-interface", "eth0 $(id)"])
            .expect_err("interface shell metacharacter must reject");
        assert!(err.contains("capture interface"));
    }

    #[test]
    fn parser_bounds_recovery_deadline_to_transport_timeout() {
        let err = parse(&["--dry-run", "--recovery-deadline-secs", "91"])
            .expect_err("deadline above max must reject");
        assert!(err.contains("recovery deadline"));
    }

    #[test]
    fn kill_observation_parses_passing_output() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nfault_observed=true\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=0\nplaintext_leak_check=pass\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(observation.passed(90));
        assert_eq!(observation.capture_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn kill_observation_fails_on_plaintext_lines() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\nfault_observed=true\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=1\nplaintext_leak_check=fail\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed(90));
    }

    #[test]
    fn kill_observation_fails_on_client_plaintext_lines() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\nfault_observed=true\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=0\nplaintext_leak_check=pass\n",
            "client_plaintext_lines=1\nclient_plaintext_leak_check=fail\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed(90));
    }

    // The fault-landed proof is mandatory in kill mode: a guest that reports
    // recovered=true without ever proving the fault landed (key missing, or
    // fault_observed=false) must not pass, and the stage report must be fail.
    #[test]
    fn kill_observation_requires_fault_observed() {
        let client = "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n";
        let base = "teardown_registered_before_fault=true\ncapture_interface=eth0\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=0\nplaintext_leak_check=pass\n";
        let missing = KillStageObservation::parse(base, client).expect("missing key parses");
        assert_eq!(missing.fault_observed, None);
        assert!(!missing.passed(90), "missing fault_observed must not pass");
        let denied = KillStageObservation::parse(&format!("fault_observed=false\n{base}"), client)
            .expect("false parses");
        assert_eq!(denied.fault_observed, Some(false));
        assert!(!denied.passed(90), "fault_observed=false must not pass");
        let proven = KillStageObservation::parse(&format!("fault_observed=true\n{base}"), client)
            .expect("true parses");
        assert_eq!(proven.fault_observed, Some(true));
        assert!(proven.passed(90));
        let err = KillStageObservation::parse(&format!("fault_observed=maybe\n{base}"), client)
            .expect_err("garbage boolean must reject");
        assert!(err.contains("fault_observed"), "{err}");
        // The report must say fail, not pass, for the unproven observation.
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let report = render_live_report(&config, &missing);
        assert_eq!(report["overall_status"], "fail");
        assert_eq!(report["stages"][0]["status"], "fail");
    }

    #[test]
    fn live_report_marks_first_stage_pass_and_remaining_skipped() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nfault_observed=true\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=0\nplaintext_leak_check=pass\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "pass");
        assert_eq!(report["implemented_stage_count"], 1);
        assert_eq!(report["remaining_stage_count"], 3);
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages[0]["name"], "chaos_daemon_kill_during_reconcile");
        assert_eq!(stages[0]["status"], "pass");
        assert_eq!(stages[0]["fault_observed"], true);
        assert_eq!(stages[1]["status"], "skipped");
        assert_eq!(stages[2]["status"], "skipped");
        assert_eq!(stages[3]["status"], "skipped");
    }

    #[test]
    fn parse_accepts_fault_mode_sigstop() {
        let config = parse(&["--dry-run", "--fault-mode", "sigstop-cont"])
            .expect("sigstop-cont fault mode should parse");
        assert_eq!(config.fault_mode, FaultMode::StopCont);
        let default_config = parse(&["--dry-run"]).expect("dry-run config should parse");
        assert_eq!(default_config.fault_mode, FaultMode::Kill);
        let kill_config =
            parse(&["--dry-run", "--fault-mode", "kill"]).expect("kill fault mode should parse");
        assert_eq!(kill_config.fault_mode, FaultMode::Kill);
    }

    #[test]
    fn parse_rejects_unknown_fault_mode() {
        let err = parse(&["--dry-run", "--fault-mode", "sigsegv"])
            .expect_err("unknown fault mode must reject");
        assert!(err.contains("invalid --fault-mode"));
    }

    #[test]
    fn sigstop_observation_parses_passing_output() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nobserved_stopped_state=T\nobserved_stopped_states=T\nrecovered=true\nmeasured_recovery_secs=9\ntcpdump_lines=0\nplaintext_leak_check=pass\nresumed_state=S\nobserved_resumed_states=S\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert_eq!(observation.observed_stopped_state.as_deref(), Some("T"));
        assert_eq!(observation.observed_stopped_states, ["T"]);
        assert_eq!(observation.resumed_state.as_deref(), Some("S"));
        assert_eq!(observation.observed_resumed_states, ["S"]);
        assert!(observation.passed_stopcont(90));
    }

    #[test]
    fn sigstop_observation_fails_when_not_stopped() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nobserved_stopped_state=R\nobserved_stopped_states=R\nrecovered=true\nmeasured_recovery_secs=9\ntcpdump_lines=0\nplaintext_leak_check=pass\nresumed_state=R\nobserved_resumed_states=R\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed_stopcont(90));
    }

    #[test]
    fn sigstop_observation_fails_on_plaintext_lines() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nobserved_stopped_state=T\nobserved_stopped_states=T\nrecovered=true\nmeasured_recovery_secs=9\ntcpdump_lines=1\nplaintext_leak_check=fail\nresumed_state=S\nobserved_resumed_states=S\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed_stopcont(90));
    }

    #[test]
    fn sigstop_observation_fails_on_client_plaintext_lines() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nobserved_stopped_state=T\nobserved_stopped_states=T\nrecovered=true\nmeasured_recovery_secs=9\ntcpdump_lines=0\nplaintext_leak_check=pass\nresumed_state=S\nobserved_resumed_states=S\n",
            "client_plaintext_lines=1\nclient_plaintext_leak_check=fail\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed_stopcont(90));
    }

    // The daemon ran the whole bounded stop window without ever reaching the
    // stopped state (D forever): fail closed even though it recovered.
    #[test]
    fn sigstop_fails_closed_when_daemon_never_reaches_stopped_state() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nobserved_stopped_state=D\nobserved_stopped_states=D,D,D,D,D\nrecovered=true\nmeasured_recovery_secs=9\ntcpdump_lines=0\nplaintext_leak_check=pass\nresumed_state=R\nobserved_resumed_states=R\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed_stopcont(90));
    }

    // Witness for the live katana-u37-anchor-b78 D-state flake (2026-10-03):
    // the first-instant sample read `D` because the daemon sat in
    // uninterruptible sleep when SIGSTOP landed, every substantive check
    // passed, and the stage still failed. The bounded poll sequence is the
    // proof of the stop, not any single instant.
    #[test]
    fn sigstop_ddt_sequence_passes_where_first_instant_sample_read_d() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=ens3\nfault_signal=STOP\nobserved_stopped_state=D\nobserved_stopped_states=D,D,T\nfault_signal_resume=CONT\nresumed_state=R\nobserved_resumed_states=T,R\nrecovered=true\nmeasured_recovery_secs=3\ntcpdump_lines=0\nplaintext_leak_check=pass\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(observation.passed_stopcont(90));
    }

    // Fail closed on an unfinished resume: the stop was proven, but the
    // bounded post-SIGCONT poll still reads `T`, so SIGCONT never took.
    #[test]
    fn sigstop_fails_when_daemon_still_stopped_after_sigcont() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nobserved_stopped_state=T\nobserved_stopped_states=T\nrecovered=true\nmeasured_recovery_secs=9\ntcpdump_lines=0\nplaintext_leak_check=pass\nresumed_state=T\nobserved_resumed_states=T,T\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed_stopcont(90));
    }

    // Fail closed when the guest emitted no poll sequences at all (an old
    // single-instant script proves nothing about the stop or the resume).
    #[test]
    fn sigstop_fails_closed_when_state_sequences_absent() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nobserved_stopped_state=T\nrecovered=true\nmeasured_recovery_secs=9\ntcpdump_lines=0\nplaintext_leak_check=pass\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed_stopcont(90));
    }

    #[test]
    fn live_report_marks_sigstop_stage_pass_and_others_skipped() {
        let config = parse(&["--dry-run", "--fault-mode", "sigstop-cont"])
            .expect("sigstop dry-run config should parse");
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nobserved_stopped_state=T\nobserved_stopped_states=T\nrecovered=true\nmeasured_recovery_secs=9\ntcpdump_lines=0\nplaintext_leak_check=pass\nresumed_state=S\nobserved_resumed_states=S\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "pass");
        assert_eq!(report["implemented_stage_count"], 1);
        assert_eq!(report["remaining_stage_count"], 3);
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages[2]["name"], "chaos_daemon_sigstop_sigcont");
        assert_eq!(stages[2]["status"], "pass");
        assert_eq!(stages[2]["observed_stopped_state"], "T");
        assert_eq!(stages[2]["observed_stopped_states"], json!(["T"]));
        assert_eq!(stages[2]["stop_poll_window_secs"], STOP_POLL_WINDOW_SECS);
        assert_eq!(stages[2]["resumed_state"], "S");
        assert_eq!(stages[2]["observed_resumed_states"], json!(["S"]));
        assert_eq!(
            stages[2]["resume_poll_window_secs"],
            RESUME_POLL_WINDOW_SECS
        );
        assert_eq!(stages[0]["status"], "skipped");
        assert_eq!(stages[1]["status"], "skipped");
        assert_eq!(stages[3]["status"], "skipped");
    }

    #[test]
    fn stop_sequence_proves_stopped_decides_purely_on_contents() {
        // D,D,T: the u37 race — D at the first instant, T once the stop landed.
        assert!(stop_sequence_proves_stopped(&[
            "D".to_owned(),
            "D".to_owned(),
            "T".to_owned()
        ]));
        // T immediately.
        assert!(stop_sequence_proves_stopped(&["T".to_owned()]));
        // t: tracing stop counts too.
        assert!(stop_sequence_proves_stopped(&[
            "D".to_owned(),
            "t".to_owned()
        ]));
        // D forever never proves the stop.
        assert!(!stop_sequence_proves_stopped(&[
            "D".to_owned(),
            "D".to_owned(),
            "D".to_owned()
        ]));
        // R: running is not stopped.
        assert!(!stop_sequence_proves_stopped(&["R".to_owned()]));
        // S: sleeping is not stopped.
        assert!(!stop_sequence_proves_stopped(&["S".to_owned()]));
        // Empty (sequence key absent): fail closed.
        assert!(!stop_sequence_proves_stopped(&[]));
    }

    #[test]
    fn resume_sequence_proves_resumed_accepts_s_r_and_d() {
        assert!(resume_sequence_proves_resumed(&["S".to_owned()]));
        assert!(resume_sequence_proves_resumed(&["R".to_owned()]));
        // T then R: the first sample raced the CONT, it did resume.
        assert!(resume_sequence_proves_resumed(&[
            "T".to_owned(),
            "R".to_owned()
        ]));
        // Still stopped after SIGCONT.
        assert!(!resume_sequence_proves_resumed(&[
            "T".to_owned(),
            "T".to_owned()
        ]));
        // Uninterruptible I/O right after CONT (katana-u39: the resumed daemon
        // fsyncing state): the task left the stopped state, so it resumed.
        assert!(resume_sequence_proves_resumed(&[
            "D".to_owned(),
            "D".to_owned()
        ]));
        assert!(resume_sequence_proves_resumed(&["D".to_owned()]));
        // Unreadable state (process gone or malformed): fail closed.
        assert!(!resume_sequence_proves_resumed(&["unknown".to_owned()]));
        // Empty (sequence key absent): fail closed.
        assert!(!resume_sequence_proves_resumed(&[]));
    }

    #[test]
    fn sigstop_script_polls_for_stopped_state_within_bounded_window() {
        let script = sigstop_script();
        assert!(script.contains(&format!(
            "stop_poll_deadline=$(( $(date +%s) + {STOP_POLL_WINDOW_SECS} ))"
        )));
        assert!(script.contains("T|t) break ;;"));
        assert!(script.contains("printf 'observed_stopped_state=%s\\n'"));
        assert!(script.contains("printf 'observed_stopped_states=%s\\n'"));
    }

    #[test]
    fn sigstop_script_polls_for_resume_and_records_state_sequence() {
        let script = sigstop_script();
        assert!(script.contains(&format!(
            "resume_poll_deadline=$(( $(date +%s) + {RESUME_POLL_WINDOW_SECS} ))"
        )));
        assert!(script.contains("S|R|D) break ;;"));
        assert!(script.contains("printf 'resumed_state=%s\\n'"));
        assert!(script.contains("printf 'observed_resumed_states=%s\\n'"));
    }

    // The kill stage (fixed in cef3ecde2) must keep its fault_observed proof
    // and must gain none of the SIGSTOP poll keys.
    #[test]
    fn kill_script_keeps_fault_observed_and_gains_no_sigstop_poll_keys() {
        let script = kill_script();
        assert!(script.contains("fault_observed"));
        assert!(!script.contains("observed_stopped_states"));
        assert!(!script.contains("observed_resumed_states"));
    }

    fn kill_script() -> String {
        render_remote_kill_script(&parse(&["--dry-run"]).expect("dry-run config should parse"))
    }

    fn sigstop_script() -> String {
        render_remote_sigstop_script(
            &parse(&["--dry-run", "--fault-mode", "sigstop-cont"])
                .expect("sigstop dry-run config should parse"),
        )
    }

    // Live 2026-09-10 cascade class: the teardown start must clear the unit's
    // start limiter first, or a fault window with failed auto-restarts leaves
    // the exit dead for every later stage.
    #[test]
    fn fault_scripts_reset_start_limit_before_teardown_start() {
        for (name, script) in [("kill", kill_script()), ("sigstop", sigstop_script())] {
            let cleanup = script
                .find("cleanup() {")
                .unwrap_or_else(|| panic!("{name}: cleanup fn"));
            let body_end = script[cleanup..]
                .find("\n}")
                .unwrap_or_else(|| panic!("{name}: cleanup body end"));
            let cleanup_body = &script[cleanup..cleanup + body_end];
            let reset = cleanup_body
                .find("systemctl reset-failed \"$service\"")
                .unwrap_or_else(|| panic!("{name}: reset-failed inside cleanup"));
            let start = cleanup_body
                .find("systemctl start \"$service\"")
                .unwrap_or_else(|| panic!("{name}: start inside cleanup"));
            assert!(
                reset < start,
                "{name}: cleanup must reset-failed before the teardown start:\n{script}"
            );
        }
    }

    // The teardown trap must survive the SSH session dying (orchestrator
    // SIGKILL/timeout): a POSIX shell may not run an EXIT-only trap on SIGHUP.
    #[test]
    fn fault_scripts_arm_teardown_against_session_death() {
        for (name, script) in [("kill", kill_script()), ("sigstop", sigstop_script())] {
            assert!(
                script.contains("trap cleanup EXIT HUP INT TERM"),
                "{name}: teardown trap must name the signals:\n{script}"
            );
        }
    }

    // RSA-0080: the guest's non-login PATH omits the sbin directories where
    // ip/tcpdump/systemctl live; pin it before any lookup.
    #[test]
    fn fault_scripts_pin_an_sbin_bearing_path_before_any_lookup() {
        for (name, script) in [("kill", kill_script()), ("sigstop", sigstop_script())] {
            let path_pos = script
                .find("PATH=\"/usr/local/sbin:/usr/sbin:/sbin:")
                .unwrap_or_else(|| panic!("{name}: sbin PATH line present"));
            let first_lookup = script
                .find("command -v ")
                .unwrap_or_else(|| panic!("{name}: a command -v preflight exists"));
            assert!(
                path_pos < first_lookup,
                "{name}: PATH must precede the first lookup:\n{script}"
            );
        }
    }

    // A preflight that exits 1 without a named marker is the "opaque status 1"
    // class from live 2026-09-10: the operator cannot tell which tool or
    // lookup failed.
    #[test]
    fn fault_scripts_preflight_ip_with_a_named_marker() {
        for (name, script) in [("kill", kill_script()), ("sigstop", sigstop_script())] {
            assert!(
                script.contains("printf 'missing_ip=true\\n'; exit 1"),
                "{name}: ip preflight must print a named marker:\n{script}"
            );
        }
    }

    // The CIDR reaches a BPF string; it must be charset-validated first so no
    // metacharacter survives into tcpdump's filter.
    #[test]
    fn fault_scripts_validate_mesh_cidr_before_bpf_splice() {
        for (name, script) in [("kill", kill_script()), ("sigstop", sigstop_script())] {
            let cidr = script.find("mesh_cidr=").expect("cidr assignment");
            let validate = script
                .find("case \"$mesh_cidr\" in ''|*[!A-Za-z0-9.:/]*) printf 'invalid_mesh_cidr=true\\n'")
                .unwrap_or_else(|| panic!("{name}: mesh_cidr charset validation present"));
            let filter = script
                .find("filter=\"ip and src net $mesh_cidr")
                .expect("filter build");
            assert!(
                validate < filter,
                "{name}: validate before splice:\n{script}"
            );
            assert!(cidr < validate);
        }
    }

    // The client guard's start script must print named markers for its
    // tcpdump/timeout/ip preflights and must not write a fixed /tmp log name.
    #[test]
    fn client_start_script_prints_named_precheck_markers() {
        let script = render_client_traffic_start_script(35);
        assert!(
            script.contains("printf 'missing_tcpdump=true\\n'; exit 1"),
            "{script}"
        );
        assert!(
            script.contains("printf 'missing_timeout=true\\n'; exit 1"),
            "{script}"
        );
        assert!(
            script.contains("printf 'missing_ip=true\\n'; exit 1"),
            "{script}"
        );
        let path_pos = script
            .find("PATH=\"/usr/local/sbin:/usr/sbin:/sbin:")
            .expect("sbin PATH line present");
        let first_lookup = script.find("command -v ").expect("preflight exists");
        assert!(
            path_pos < first_lookup,
            "PATH must precede the first lookup:\n{script}"
        );
        assert!(
            script.contains(
                "traffic_log=\"$(mktemp /tmp/rustynet-chaos-daemon-fault-client-log.XXXXXX)\""
            ),
            "the ping sink must use mktemp, not a fixed /tmp name:\n{script}"
        );
        assert!(!script.contains("/tmp/rustynet-chaos-daemon-fault-client.log"));
    }

    fn client_stop_script() -> String {
        render_client_traffic_stop_script()
    }

    // Audit I2 finding 2 (2026-09-11): the old stop script mapped a missing or
    // empty capture to client_plaintext_lines=0 => leak_check=pass. That
    // fail-open must be gone in every leak-tally site.
    #[test]
    fn leak_tallies_fail_closed_on_broken_captures() {
        let tally_markers = [
            "capture_missing",
            "capture_empty",
            "capture_provenance_missing",
            "tcpdump_did_not_start",
            "tcpdump_error_file_nonempty",
            "unparseable_capture_tally",
        ];
        for (name, script) in [
            ("kill", kill_script()),
            ("sigstop", sigstop_script()),
            ("client-stop", client_stop_script()),
        ] {
            for marker in tally_markers {
                assert!(
                    script.contains(marker),
                    "{name}: missing {marker}:\n{script}"
                );
            }
            assert!(
                script.contains("leak_check=error"),
                "{name}: error verdict must be emitted:\n{script}"
            );
            assert!(
                script.contains("exit 3"),
                "{name}: error must exit 3:\n{script}"
            );
            // The provenance marker must be excluded from the packet tally.
            assert!(
                script.contains("^(tcpdump:|listening on|capture_provenance=|$)"),
                "{name}: tally must exclude the provenance marker:\n{script}"
            );
        }
    }

    /// Run the rendered tally fragment under `sh` against a real capture and a
    /// given tcpdump stderr, returning its stdout (and whether it exited 3).
    fn run_tally(error_file_body: &str) -> (String, bool) {
        let dir = std::env::temp_dir().join(format!(
            "rn-tally-{}-{}",
            std::process::id(),
            error_file_body.len()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let capture = dir.join("capture");
        let error = dir.join("error");
        std::fs::write(&capture, "capture_provenance=test\n").expect("capture");
        std::fs::write(&error, error_file_body).expect("error file");
        let tally = render_capture_leak_tally_sh(
            &shell_quote(capture.to_str().expect("utf8")),
            &shell_quote(error.to_str().expect("utf8")),
            "lines",
            "leak_check",
            "reason",
        );
        let script = format!("{tally}printf 'leak_check=%s\\n' \"$leak_check\"\n");
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("run sh");
        let _ = std::fs::remove_dir_all(&dir);
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            out.status.code() == Some(3),
        )
    }

    // 2026-09-27 live lab (UTM Debian 13 and lenovo KVM guests): tcpdump 4.99.5
    // prints this exact stderr on every non-verbose capture, and the tally
    // called it an error, so chaos_daemon_fault failed on every node while
    // capturing zero plaintext. It must pass; a real tcpdump error must not.
    #[test]
    fn tally_accepts_tcpdump_499_banner_and_still_rejects_real_errors() {
        let benign = "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\n\
                      listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n\
                      0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n";
        let (out, exited_3) = run_tally(benign);
        assert!(
            !exited_3,
            "benign tcpdump stderr must not be an error: {out}"
        );
        assert!(out.contains("leak_check=pass"), "{out}");

        let broken = "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\n\
                      listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n\
                      tcpdump: pcap_loop: The interface disappeared\n";
        let (out, exited_3) = run_tally(broken);
        assert!(exited_3, "a real tcpdump error must fail closed: {out}");
        assert!(out.contains("reason=tcpdump_error_file_nonempty"), "{out}");
    }

    #[test]
    fn client_start_script_seeds_capture_provenance_marker_before_appending_tcpdump() {
        let script = render_client_traffic_start_script(35);
        let marker = script
            .find("capture_provenance=started_unix=")
            .unwrap_or_else(|| panic!("provenance marker present:\n{script}"));
        let launch = script
            .find("tcpdump -i \"$capture_interface\"")
            .unwrap_or_else(|| panic!("tcpdump launch present:\n{script}"));
        let launch_line = script[launch..]
            .lines()
            .next()
            .unwrap_or_else(|| panic!("tcpdump launch line:\n{script}"));
        assert!(
            launch_line.contains(">> \"$capture_file\""),
            "tcpdump must append to the seeded capture:\n{script}"
        );
        assert!(
            marker < launch,
            "marker must be written before tcpdump:\n{script}"
        );
    }

    #[test]
    fn fault_scripts_seed_capture_provenance_marker_before_appending_tcpdump() {
        for (name, script) in [("kill", kill_script()), ("sigstop", sigstop_script())] {
            let marker = script
                .find("capture_provenance=started_unix=")
                .unwrap_or_else(|| panic!("{name}: provenance marker present:\n{script}"));
            let launch = script
                .find("tcpdump -i \"$capture_interface\"")
                .unwrap_or_else(|| panic!("{name}: tcpdump launch present:\n{script}"));
            let launch_line = script[launch..]
                .lines()
                .next()
                .unwrap_or_else(|| panic!("{name}: tcpdump launch line:\n{script}"));
            assert!(
                launch_line.contains(">> \"$work_dir/tcpdump.txt\""),
                "{name}: tcpdump must append to the seeded capture:\n{script}"
            );
            assert!(
                marker < launch,
                "{name}: marker must be written before tcpdump:\n{script}"
            );
        }
    }

    // The mutation the audit worried about: the old guest script turned "no
    // capture" into leak_check=pass. The parser must now turn an in-band
    // error verdict into a stage failure naming the reason.
    #[test]
    fn empty_client_capture_is_a_stage_failure_not_a_pass() {
        let err = KillStageObservation::parse(
            "teardown_registered_before_fault=true\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=0\nplaintext_leak_check=pass\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=error\nclient_plaintext_error=capture_empty\n",
        )
        .expect_err("an empty capture must fail the stage, not pass");
        assert!(err.contains("capture_empty"), "{err}");
        assert!(err.contains("client tcpdump leak check"), "{err}");
    }

    #[test]
    fn missing_target_capture_is_a_stage_failure_not_a_pass() {
        let err = KillStageObservation::parse(
            "teardown_registered_before_fault=true\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=0\nplaintext_leak_check=error\nplaintext_error=capture_missing\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect_err("a missing capture must fail the stage, not pass");
        assert!(err.contains("capture_missing"), "{err}");
        assert!(err.contains("target tcpdump leak check"), "{err}");
    }

    // 2026-09-30 katana-u26: on the error path the work_dir (holding
    // tcpdump.err) is deleted by the cleanup trap, so the failure output named
    // `tcpdump_did_not_start` with zero evidence of WHY. The error branch must
    // carry a bounded single-line excerpt of tcpdump's stderr. Old behaviour:
    // no snippet line — this test fails against it.
    #[test]
    fn tally_error_carries_tcpdump_stderr_snippet_for_diagnosis() {
        let body = "tcpdump: boom: permission denied\n";
        let (out, exited_3) = run_tally(body);
        assert!(exited_3, "a bannerless capture must fail closed: {out}");
        assert!(out.contains("reason=tcpdump_did_not_start"), "{out}");
        assert!(
            out.contains("tcpdump_error_snippet=tcpdump: boom: permission denied"),
            "the stderr excerpt must reach the failure output: {out}"
        );

        // A healthy capture path must NOT grow a snippet line.
        let healthy = "listening on ens3, link-type EN10MB (Ethernet)\n0 packets captured\n";
        let (out, exited_3) = run_tally(healthy);
        assert!(!exited_3, "healthy stderr must pass: {out}");
        assert!(!out.contains("tcpdump_error_snippet="), "{out}");
    }

    /// Run the readiness fragment against a temp stderr file, optionally with
    /// a backgrounded late writer, and return its stdout.
    fn run_readiness(prelude: &str, timeout_secs: u64) -> (String, Option<i32>) {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rn-ready-{}-{}-{}-{}",
            std::process::id(),
            timeout_secs,
            prelude.len(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let error = dir.join("tcpdump.err");
        std::fs::write(&error, "").expect("empty stderr file");
        let frag = render_tcpdump_readiness_wait_sh(
            &shell_quote(error.to_str().expect("utf8")),
            timeout_secs,
        );
        let script = format!(
            "RDY_ERR={}\n{prelude}\n{frag}\nprintf 'READY_DONE\\n'\nprintf 'FAULT_INJECTED\\n'\n",
            shell_quote(error.to_str().expect("utf8")),
        );
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run sh");
        let _ = std::fs::remove_dir_all(&dir);
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            out.status.code(),
        )
    }

    // The banner may arrive AFTER the blind `sleep 2` the old scripts used:
    // katana-u26's kernel log proves tcpdump was killed ~1.5s after spawn
    // without ever opening ens3. The readiness wait must accept a banner that
    // lands late (1s), and still time out bounded with `tcpdump_ready=false`
    // plus a stderr excerpt when it never lands.
    #[test]
    fn readiness_wait_accepts_late_banner() {
        // Banner at 3s: later than the old blind `sleep 2`, inside a 6s wait.
        let (out, code) = run_readiness(
            "( sleep 3; printf 'listening on ens3, link-type EN10MB (Ethernet)\\n' >> \"$RDY_ERR\" ) &",
            6,
        );
        assert_eq!(code, Some(0), "{out}");
        assert!(out.contains("tcpdump_ready=true"), "{out}");
        assert!(out.contains("FAULT_INJECTED"), "{out}");
        assert!(out.contains("READY_DONE"), "{out}");
        assert!(!out.contains("tcpdump_ready=false"), "{out}");
    }

    #[test]
    fn readiness_wait_times_out_bounded_with_stderr_snippet() {
        let started = std::time::Instant::now();
        let (out, code) = run_readiness("RDY_ERR_UNUSED=0", 1);
        let elapsed = started.elapsed();
        assert!(out.contains("tcpdump_ready=false"), "{out}");
        assert!(out.contains("tcpdump_error_snippet="), "{out}");
        // The orchestrator keeps only the first 500 chars of stderr/output:
        // the verdict keys must precede the free-text excerpt, which is LAST.
        let pos = |needle: &str| {
            out.find(needle)
                .unwrap_or_else(|| panic!("{needle}: {out}"))
        };
        let snippet_at = pos("tcpdump_error_snippet=");
        assert!(pos("tcpdump_lines=0") < snippet_at, "{out}");
        assert!(pos("plaintext_leak_check=error") < snippet_at, "{out}");
        assert!(
            pos("plaintext_error=tcpdump_not_ready") < snippet_at,
            "{out}"
        );
        assert_eq!(
            out.trim_end()
                .lines()
                .last()
                .map(|l| l.starts_with("tcpdump_error_snippet=")),
            Some(true),
            "the snippet must be the LAST line: {out}"
        );
        // Fail closed: exit 3 with the not-ready verdict, and the code after
        // the fragment (standing in for the fault injection) never runs.
        assert_eq!(code, Some(3), "{out}");
        assert!(out.contains("tcpdump_lines=0"), "{out}");
        assert!(out.contains("plaintext_leak_check=error"), "{out}");
        assert!(out.contains("plaintext_error=tcpdump_not_ready"), "{out}");
        assert!(
            !out.contains("FAULT_INJECTED"),
            "fault must not be injected: {out}"
        );
        assert!(!out.contains("READY_DONE"), "{out}");
        // Bounded: one poll + margin, never the old unbounded wait.
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "readiness wait must be bounded, took {elapsed:?}"
        );
    }

    /// Run the kill fault-window fragment with fake `systemctl`/`stat`
    /// binaries on PATH. `systemctl_body`/`stat_body` are full fake scripts;
    /// `prelude` runs before the fragment (for background simulators).
    fn run_kill_fault_window(
        systemctl_body: &str,
        stat_body: &str,
        prelude: &str,
        deadline: u64,
        observe_timeout: u64,
    ) -> (String, std::path::PathBuf) {
        let (out, dir, _code) = run_kill_fault_window_status(
            systemctl_body,
            stat_body,
            prelude,
            deadline,
            observe_timeout,
        );
        (out, dir)
    }

    /// As [`run_kill_fault_window`], also returning the script's exit code.
    fn run_kill_fault_window_status(
        systemctl_body: &str,
        stat_body: &str,
        prelude: &str,
        deadline: u64,
        observe_timeout: u64,
    ) -> (String, std::path::PathBuf, Option<i32>) {
        // Unique per call: parallel tests may share (deadline, observe) pairs
        // and each call now wipes its own dir first.
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rn-killfw-{}-{}-{}-{}",
            std::process::id(),
            deadline,
            observe_timeout,
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let bin = dir.join("bin");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&bin).expect("bin dir");
        let sock = dir.join("rustynetd.sock");
        let _ = std::os::unix::net::UnixListener::bind(&sock).expect("bind fake socket");
        let ino_state = dir.join("ino");
        std::fs::write(&ino_state, "424242\n").expect("ino");
        let systemctl = bin.join("systemctl");
        std::fs::write(&systemctl, systemctl_body).expect("systemctl");
        let stat = bin.join("stat");
        std::fs::write(&stat, stat_body).expect("stat");
        for tool in [&systemctl, &stat] {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(tool).expect("stat tool").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(tool, perms).expect("chmod");
        }
        let frag = render_kill_fault_window_sh(
            "rustynetd.service",
            sock.to_str().expect("utf8"),
            deadline,
            observe_timeout,
        );
        let script = format!(
            "RDY_KILLFW_DIR={}\nRDY_INO={}\nPATH={}:\"$PATH\"\nexport PATH RDY_KILLFW_DIR RDY_INO\n{prelude}\n{frag}\nprintf 'recovered=%s\\n' \"$recovered\"\nprintf 'KILLFW_DONE\\n'\n",
            shell_quote(dir.to_str().expect("utf8")),
            shell_quote(ino_state.to_str().expect("utf8")),
            shell_quote(bin.to_str().expect("utf8")),
        );
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run sh");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            dir,
            out.status.code(),
        )
    }

    // THE katana-u26 witness: `systemctl kill -s KILL` raced systemd's
    // reaping — the guest journal shows the kill at 08:00:42 and the exit
    // processed at 08:00:44 — while the SIGKILLed daemon could not unlink its
    // socket file. The old inline recovery poll treated `is-active` (still
    // active) + the stale socket as instant recovery, collapsing the 90s
    // fault window to ~1s and killing tcpdump before it opened the device.
    // Replay: is-active NEVER flips, inode NEVER changes. The old logic
    // printed `recovered=true` here; the new fragment must print
    // `fault_observed=false` / `recovered=false` (fail closed), bounded.
    #[test]
    fn kill_fault_window_stale_active_and_stale_socket_never_recovers() {
        let systemctl = "#!/bin/sh\ncase \"$1\" in\n  is-active) exit 0 ;;\n  kill) exit 0 ;;\n  *) exit 0 ;;\nesac\n";
        let stat = "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    %i) shift; cat \"$RDY_INO\"; exit 0 ;;\n    *) shift ;;\n  esac\ndone\nexit 1\n";
        let started = std::time::Instant::now();
        let (out, dir) = run_kill_fault_window(systemctl, stat, "", 1, 1);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(out.contains("fault_observed=false"), "{out}");
        assert!(out.contains("recovered=false"), "{out}");
        assert!(
            !out.contains("recovered=true"),
            "a never-reaped daemon with a stale socket must NOT read as recovered: {out}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "observation must be bounded"
        );
    }

    // The healthy path: the fault lands (is-active flips false), the daemon
    // restarts (active again) and binds a FRESH socket (inode changes).
    // Recovery must be observed as true within the deadline.
    #[test]
    fn kill_fault_window_observes_fault_and_recovers_on_fresh_socket() {
        // Fake systemctl: `kill -s KILL <svc>` deactivates, a background
        // restart reactivates after 1s. Fake stat returns the CURRENT inode
        // from a state file the restart bumps.
        let systemctl = "#!/bin/sh\nif [ \"$1\" = \"kill\" ]; then\n  printf '0\\n' > \"$RDY_KILLFW_DIR/active\"\n  printf '777777\\n' > \"$RDY_INO\"\n  ( sleep 1; printf '1\\n' > \"$RDY_KILLFW_DIR/active\" ) &\n  exit 0\nfi\nif [ \"$1\" = \"is-active\" ]; then\n  if [ -f \"$RDY_KILLFW_DIR/active\" ] && [ \"$(cat \"$RDY_KILLFW_DIR/active\")\" = \"1\" ]; then exit 0; fi\n  exit 1\nfi\nexit 0\n";
        let stat = "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    %i) shift; cat \"$RDY_INO\"; exit 0 ;;\n    *) shift ;;\n  esac\ndone\nexit 1\n";
        let (out, dir) = run_kill_fault_window(
            systemctl,
            stat,
            "printf '1\\n' > \"$RDY_KILLFW_DIR/active\"",
            5,
            3,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(out.contains("fault_observed=true"), "{out}");
        assert!(out.contains("recovered=true"), "{out}");
        assert!(out.contains("KILLFW_DONE"), "{out}");
    }

    const FAKE_STAT: &str = "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    %i) shift; cat \"$RDY_INO\"; exit 0 ;;\n    *) shift ;;\n  esac\ndone\nexit 1\n";

    // Fault observed via is-active flipping, daemon comes back active, but the
    // socket inode NEVER changes (stale socket). Recovery requires a fresh
    // inode, so this must read fault_observed=true, recovered=false. A weaker
    // recovery condition (active + socket present) would print recovered=true.
    #[test]
    fn kill_fault_window_active_again_but_stale_inode_not_recovered() {
        let systemctl = "#!/bin/sh\nif [ \"$1\" = \"kill\" ]; then\n  printf '0\\n' > \"$RDY_KILLFW_DIR/active\"\n  ( sleep 1; printf '1\\n' > \"$RDY_KILLFW_DIR/active\" ) &\n  exit 0\nfi\nif [ \"$1\" = \"is-active\" ]; then\n  if [ -f \"$RDY_KILLFW_DIR/active\" ] && [ \"$(cat \"$RDY_KILLFW_DIR/active\")\" = \"1\" ]; then exit 0; fi\n  exit 1\nfi\nexit 0\n";
        let (out, dir) = run_kill_fault_window(
            systemctl,
            FAKE_STAT,
            "printf '1\\n' > \"$RDY_KILLFW_DIR/active\"",
            3,
            3,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(out.contains("fault_observed=true"), "{out}");
        assert!(out.contains("recovered=false"), "{out}");
        assert!(!out.contains("recovered=true"), "{out}");
    }

    // A restart faster than one poll: `kill` bumps the inode while is-active
    // exits 0 throughout. The inode alone must prove the fault landed
    // (fault_observed=true) and the fresh inode proves recovery. An
    // is-active-only observation would print fault_observed=false here.
    #[test]
    fn kill_fault_window_fast_restart_observed_by_inode_only() {
        let systemctl = "#!/bin/sh\nif [ \"$1\" = \"kill\" ]; then\n  printf '777777\\n' > \"$RDY_INO\"\n  exit 0\nfi\nexit 0\n";
        let (out, dir) = run_kill_fault_window(systemctl, FAKE_STAT, "", 5, 3);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(out.contains("fault_observed=true"), "{out}");
        assert!(out.contains("recovered=true"), "{out}");
    }

    // Review MUST-fix: if the pre-fault `stat` fails, socket_ino_before is
    // empty and ANY later readable inode -- including the unchanged stale one --
    // differs from "", so the fragment used to declare fault_observed=true and
    // then recovered=true against a daemon that was never verified to restart.
    // Replay: the FIRST stat fails, every later stat returns the same stale
    // inode, systemctl always reports active. The precondition guard must abort
    // BEFORE the kill: no fault_signal, no recovered=true, nonzero exit.
    #[test]
    fn kill_fault_window_unreadable_pre_fault_inode_aborts_before_kill() {
        let systemctl = "#!/bin/sh\ncase \"$1\" in\n  kill) printf 'KILLED\\n' >> \"$RDY_KILLFW_DIR/killed\"; exit 0 ;;\n  *) exit 0 ;;\nesac\n";
        let stat = "#!/bin/sh\nn=0\n[ -f \"$RDY_KILLFW_DIR/statn\" ] && n=\"$(cat \"$RDY_KILLFW_DIR/statn\")\"\nn=$((n + 1))\nprintf '%s\\n' \"$n\" > \"$RDY_KILLFW_DIR/statn\"\nif [ \"$n\" -eq 1 ]; then exit 1; fi\ncat \"$RDY_INO\"\nexit 0\n";
        let (out, dir, code) = run_kill_fault_window_status(systemctl, stat, "", 3, 2);
        let killed = dir.join("killed").exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            out.contains("fault_precondition=socket_inode_unreadable"),
            "{out}"
        );
        assert!(
            !out.contains("fault_signal="),
            "no fault may be signalled: {out}"
        );
        assert!(!killed, "systemctl kill must never run: {out}");
        assert!(!out.contains("recovered=true"), "{out}");
        assert!(!out.contains("KILLFW_DONE"), "{out}");
        assert!(
            matches!(code, Some(c) if c != 0),
            "the precondition failure must exit nonzero: {code:?} {out}"
        );
    }

    // The redirect order matters under dash: `< file 2>/dev/null` opens the
    // file BEFORE stderr is silenced, so a missing file printed an open error.
    #[test]
    fn snippet_pipelines_silence_stderr_before_opening_the_file() {
        for frag in [
            render_tcpdump_readiness_wait_sh("\"$E\"", 1),
            render_capture_leak_tally_sh("\"$C\"", "\"$E\"", "L", "K", "R"),
        ] {
            assert!(frag.contains("2>/dev/null < "), "{frag}");
            assert!(!frag.contains("< \"$E\" 2>/dev/null"), "{frag}");
        }
    }

    // Both live fault scripts must wire the fragments in: the readiness wait
    // replaces the blind `sleep 2` after the tcpdump spawn, and the kill
    // script must carry the observation guard + socket-inode freshness.
    #[test]
    fn fault_scripts_use_readiness_wait_and_kill_observation_guard() {
        let kill = kill_script();
        let sigstop = sigstop_script();
        for (name, script) in [("kill", &kill), ("sigstop", &sigstop)] {
            assert!(
                script.contains("tcpdump_ready="),
                "{name}: readiness wait must be wired in:\n{script}"
            );
            assert!(
                !script.contains("\nsleep 2\nstart_unix="),
                "{name}: blind sleep 2 must be gone:\n{script}"
            );
        }
        // Readiness must precede fault injection in both scripts.
        for (name, script, fault) in [
            ("kill", &kill, "fault_signal=KILL"),
            ("sigstop", &sigstop, "fault_signal=STOP"),
        ] {
            let ready = script.find("tcpdump_ready=").expect("readiness present");
            let fault_at = script.find(fault).expect("fault signal present");
            assert!(
                ready < fault_at,
                "{name}: tcpdump_ready= must appear before {fault}"
            );
            assert!(
                script.contains("timeout \"$((deadline + 45))\" tcpdump"),
                "{name}: target tcpdump timeout must be deadline + 45"
            );
        }
        assert!(
            kill.contains("fault_observed=false") && kill.contains("socket_ino_before"),
            "kill script must observe the fault and pin the pre-fault socket inode:\n{kill}"
        );
        let guard = kill
            .find("fault_precondition=socket_inode_unreadable")
            .expect("precondition guard present");
        let kill_at = kill.find("systemctl kill").expect("kill present");
        assert!(
            guard < kill_at,
            "guard must precede systemctl kill:\n{kill}"
        );
    }
}
