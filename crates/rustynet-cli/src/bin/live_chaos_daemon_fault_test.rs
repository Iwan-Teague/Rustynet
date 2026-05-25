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

    let output = capture_root(
        identity,
        known_hosts,
        target,
        &render_remote_kill_script(config),
    );

    let cleanup_result = traffic_guard.stop();
    let output = output?;
    let client_output = cleanup_result?;

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
        let duration = config.recovery_deadline_secs + 20;
        let traffic_pid_file = shell_quote(CLIENT_TRAFFIC_PID_FILE);
        let tcpdump_pid_file = shell_quote(CLIENT_TCPDUMP_PID_FILE);
        let capture_file = shell_quote(CLIENT_TCPDUMP_CAPTURE_FILE);
        let error_file = shell_quote(CLIENT_TCPDUMP_ERROR_FILE);
        let probe_target = shell_quote(CLIENT_PROBE_TARGET);
        let script = format!(
            r#"set -eu
traffic_pid_file={traffic_pid_file}
tcpdump_pid_file={tcpdump_pid_file}
capture_file={capture_file}
error_file={error_file}
probe_target={probe_target}
rm -f "$traffic_pid_file" "$tcpdump_pid_file" "$capture_file" "$error_file"
command -v tcpdump >/dev/null 2>&1
command -v timeout >/dev/null 2>&1
capture_interface="$(ip route show default 0.0.0.0/0 | awk 'NR==1 {{ for (i=1; i<=NF; i++) if ($i == "dev") {{ print $(i+1); exit }} }}')"
case "$capture_interface" in ""|*[!A-Za-z0-9_.:-]*|rustynet0) exit 1 ;; esac
timeout {duration} tcpdump -i "$capture_interface" -nn -l "icmp and dst host $probe_target" > "$capture_file" 2> "$error_file" &
printf '%s\n' "$!" > "$tcpdump_pid_file"
sleep 2
(
  end="$(( $(date +%s) + {duration} ))"
  while [ "$(date +%s)" -lt "$end" ]; do
    ping -n -c 1 -W 1 "$probe_target" >/dev/null 2>&1 || true
    sleep 1
  done
) >/tmp/rustynet-chaos-daemon-fault-client.log 2>&1 &
printf '%s\n' "$!" > "$traffic_pid_file"
"#
        );
        run_root(identity, known_hosts, client, &script)?;
        Ok(Self {
            identity,
            known_hosts,
            client,
        })
    }

    fn stop(self) -> Result<String, String> {
        let traffic_pid_file = shell_quote(CLIENT_TRAFFIC_PID_FILE);
        let tcpdump_pid_file = shell_quote(CLIENT_TCPDUMP_PID_FILE);
        let capture_file = shell_quote(CLIENT_TCPDUMP_CAPTURE_FILE);
        let error_file = shell_quote(CLIENT_TCPDUMP_ERROR_FILE);
        let script = format!(
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
if [ -f "$capture_file" ]; then
  client_plaintext_lines="$(grep -Evc '^(tcpdump:|listening on|$)' "$capture_file" 2>/dev/null || true)"
else
  client_plaintext_lines=0
fi
case "$client_plaintext_lines" in ""|*[!0-9]*) client_plaintext_lines=0 ;; esac
if [ "$client_plaintext_lines" = "0" ]; then
  client_plaintext_leak_check=pass
else
  client_plaintext_leak_check=fail
fi
rm -f "$capture_file" "$error_file"
printf 'client_plaintext_lines=%s\n' "$client_plaintext_lines"
printf 'client_plaintext_leak_check=%s\n' "$client_plaintext_leak_check"
"#
        );
        capture_root(self.identity, self.known_hosts, self.client, &script)
    }
}

fn render_remote_kill_script(config: &Config) -> String {
    let service = shell_quote(&config.service_name);
    let socket_path = shell_quote(&config.socket_path);
    let capture_interface = shell_quote(&config.capture_interface);
    let mesh_cidr = shell_quote(&config.mesh_cidr);
    let deadline = config.recovery_deadline_secs;

    format!(
        r#"set -eu
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
  systemctl start "$service" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}}
trap cleanup EXIT
printf 'teardown_registered_before_fault=true\n'
command -v tcpdump >/dev/null 2>&1 || {{ printf 'missing_tcpdump=true\n'; exit 1; }}
command -v timeout >/dev/null 2>&1 || {{ printf 'missing_timeout=true\n'; exit 1; }}
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
filter="ip and src net $mesh_cidr and not dst net $mesh_cidr"
timeout "$((deadline + 15))" tcpdump -i "$capture_interface" -nn -l "$filter" > "$work_dir/tcpdump.txt" 2> "$work_dir/tcpdump.err" &
tcpdump_pid="$!"
sleep 2
start_unix="$(date +%s)"
printf 'fault_signal=KILL\n'
systemctl kill -s KILL "$service"
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
if [ -f "$work_dir/tcpdump.txt" ]; then
  tcpdump_lines="$(grep -Evc '^(tcpdump:|listening on|$)' "$work_dir/tcpdump.txt" 2>/dev/null || true)"
else
  tcpdump_lines=0
fi
case "$tcpdump_lines" in ""|*[!0-9]*) tcpdump_lines=0 ;; esac
if [ "$tcpdump_lines" = "0" ]; then
  plaintext_leak_check=pass
else
  plaintext_leak_check=fail
fi
printf 'recovered=%s\n' "$recovered"
printf 'measured_recovery_secs=%s\n' "$measured_recovery_secs"
printf 'tcpdump_lines=%s\n' "$tcpdump_lines"
printf 'plaintext_leak_check=%s\n' "$plaintext_leak_check"
"#
    )
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
        })
    }

    fn passed(&self, deadline_secs: u64) -> bool {
        self.teardown_registered_before_fault
            && self.recovered
            && self.measured_recovery_secs <= deadline_secs
            && self.tcpdump_lines == 0
            && self.plaintext_leak_check == "pass"
            && self.client_plaintext_lines == 0
            && self.client_plaintext_leak_check == "pass"
    }
}

fn render_live_report(config: &Config, observation: &KillStageObservation) -> Value {
    let implemented_status = if observation.passed(config.recovery_deadline_secs) {
        "pass"
    } else {
        "fail"
    };
    let stages = daemon_fault_stages()
        .into_iter()
        .enumerate()
        .map(|(idx, stage)| {
            if idx == 0 {
                json!({
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
                    "summary": "not implemented in this daemon-fault live slice",
                })
            }
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": CATEGORY,
        "overall_status": implemented_status,
        "summary": "daemon KILL fault was injected under live client traffic with tcpdump plaintext-leak proof",
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

fn print_usage() {
    eprintln!(
        "usage: {CATEGORY} [--dry-run] [--target-host <user@host>] [--client-host <user@host>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--socket-path <path>] [--service-name <name>] [--capture-interface <name|default-route>] [--mesh-cidr <cidr>] [--recovery-deadline-secs <secs>] [--report-path <path>] [--log-path <path>] [--git-commit <sha>]"
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
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=0\nplaintext_leak_check=pass\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(observation.passed(90));
        assert_eq!(observation.capture_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn kill_observation_fails_on_plaintext_lines() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=1\nplaintext_leak_check=fail\n",
            "client_plaintext_lines=0\nclient_plaintext_leak_check=pass\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed(90));
    }

    #[test]
    fn kill_observation_fails_on_client_plaintext_lines() {
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=0\nplaintext_leak_check=pass\n",
            "client_plaintext_lines=1\nclient_plaintext_leak_check=fail\n",
        )
        .expect("observation should parse");
        assert!(!observation.passed(90));
    }

    #[test]
    fn live_report_marks_first_stage_pass_and_remaining_skipped() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let observation = KillStageObservation::parse(
            "teardown_registered_before_fault=true\ncapture_interface=eth0\nrecovered=true\nmeasured_recovery_secs=7\ntcpdump_lines=0\nplaintext_leak_check=pass\n",
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
        assert_eq!(stages[1]["status"], "skipped");
        assert_eq!(stages[2]["status"], "skipped");
        assert_eq!(stages[3]["status"], "skipped");
    }
}
