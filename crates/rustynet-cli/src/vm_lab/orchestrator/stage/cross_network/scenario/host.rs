//! The *local* side of a scenario: the commands a validator runs on the
//! orchestrator host rather than on a lab guest.
//!
//! Remote work goes through [`NetLeafRunner`](super::super::substrate::NetLeafRunner);
//! this trait covers the three things the bash validators did locally:
//!
//! 1. run a required-test gate (`scripts/ci/run_required_test.sh`),
//! 2. invoke a **sibling** validator that is already its own Rust binary,
//! 3. read named check fields back out of the report that sibling emitted.
//!
//! It is a trait so scenarios are unit-testable without a lab: the tests drive
//! [`RecordingHost`] and assert on the recorded invocations, which is also how
//! the argv-only property is pinned.
//!
//! # Why the sibling validators are still separate processes
//!
//! `live_linux_endpoint_hijack_test`, `live_linux_control_surface_exposure_test`,
//! `live_linux_server_ip_bypass_test` and `live_linux_managed_dns_test` were
//! ported to Rust ahead of CN-3 and each is a `[[bin]]` whose logic lives in
//! `main()`. They are explicitly NOT in CN-3's deletion scope, and their bash
//! wrappers are already retired to two-line `exec cargo run --bin …` shims. So
//! a scenario that composes one keeps invoking it as a process. That is one
//! documented seam rather than the eight-way `cargo run` fan CN-3 removes, and
//! collapsing it further means lifting four `main()`s into library functions —
//! a separate, larger change with its own review surface.
//!
//! What did change: the *evidence* is no longer read by shelling out to
//! `cargo run … ops read-cross-network-report-fields` and parsing stdout. It is
//! read in-process through [`execute_ops_read_cross_network_report_fields`], so
//! a scenario can no longer be defeated by the subprocess having been built
//! without the `vm-lab` feature — the failure mode that made the endpoint-hijack
//! bin record FAIL after its assertions had already passed.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::ops_cross_network_reports::{
    GenerateCrossNetworkRemoteExitReportConfig, ReadCrossNetworkReportFieldsConfig,
    WriteCrossNetworkSoakMonitorSummaryConfig,
    execute_ops_generate_cross_network_remote_exit_report,
    execute_ops_read_cross_network_report_fields,
    execute_ops_write_cross_network_soak_monitor_summary,
};

/// The orchestrator-host command surface a scenario needs.
pub trait ScenarioHost {
    /// Run one required-test gate, appending its combined output to `log_path`.
    /// `Ok(true)` means the gate passed; `Ok(false)` means it ran and failed.
    /// `Err` is reserved for not being able to run it at all — a distinction the
    /// shell collapsed into a single non-zero status.
    ///
    /// The log is not optional: the cross-network report validator lists the
    /// gate log in `required_pass_log_artifacts`, so a scenario that ran its
    /// gates without recording their output cannot emit a passing report. The
    /// shell got this from `… | tee -a "$log_path"`.
    fn run_required_test(
        &self,
        crate_name: &str,
        test_name: &str,
        log_path: &Path,
    ) -> Result<bool, String>;

    /// Invoke a sibling validator binary with `args`. As above, `Ok(false)` is
    /// "it ran and reported failure", `Err` is "it could not be run".
    fn run_validator_bin(&self, bin: &str, args: &[&str]) -> Result<bool, String>;

    /// True when `report_path` exists. The validators distinguish "the sibling
    /// failed but left evidence" (readable, still assertable) from "it failed
    /// before emitting evidence" (fail closed, nothing to assert on).
    fn report_exists(&self, report_path: &Path) -> bool;

    /// Read the `status` field of the report at `report_path`.
    ///
    /// The shell got this from the same reader call as the checks, by passing
    /// `--include-status`, which prepended it to the results and left every
    /// subsequent index shifted by one. Splitting it out means a scenario
    /// indexes its checks from zero and cannot silently read the status as a
    /// check — the off-by-one that shift invites.
    fn read_report_status(&self, report_path: &Path) -> Result<String, String>;

    /// Read `checks` out of the report at `report_path`, in order. A missing
    /// check reads as `"fail"`, never as absent — the shell's
    /// `"${results[0]:-fail}"` default, made structural.
    fn read_report_checks(
        &self,
        report_path: &Path,
        checks: &[&str],
    ) -> Result<Vec<String>, String>;

    /// Write one of the scenario's own text artifacts to `path`, creating its
    /// parent directory. The shell wrote these with `printf … > "$path"` from
    /// inside the validator; they are part of the evidence the report declares,
    /// so a scenario that cannot write one has not produced its evidence and
    /// the failure is propagated rather than swallowed.
    fn write_artifact(&self, path: &Path, contents: &str) -> Result<(), String>;

    /// Write a cross-network report for a scenario this one *composed*.
    ///
    /// Five of the eight validators establish their baseline by running another
    /// scenario. The shell did that by executing the baseline's script, which
    /// wrote its own report as a side effect; the composing script then named
    /// that file in its own `source_artifacts`. Composition is now a Rust
    /// function call, so no report appears by itself — and the report validator
    /// lists those baseline reports in `required_pass_source_artifacts`, so a
    /// composing scenario that skipped writing one could not emit a passing
    /// report at all.
    ///
    /// It is on the trait rather than called directly so a scenario unit test
    /// can assert on the report that *would* be written without touching the
    /// filesystem, exactly as it does for every other local effect here.
    fn write_report(
        &self,
        config: GenerateCrossNetworkRemoteExitReportConfig,
    ) -> Result<(), String>;

    /// Write the soak scenario's monitor summary.
    ///
    /// Its own writer rather than a plain [`Self::write_artifact`] because the
    /// cross-network report validator does not merely require this file to
    /// exist — it parses it and checks its fields. Rendering the JSON by hand
    /// here would put the schema in two places; the ops writer is the one that
    /// already agrees with the validator.
    fn write_soak_monitor_summary(
        &self,
        config: WriteCrossNetworkSoakMonitorSummaryConfig,
    ) -> Result<(), String>;

    /// The orchestrator's pinned `known_hosts` file and its SHA-256, for the
    /// SSH trust summary the report validator requires. `Err` when this host
    /// has no pin (the summary then cannot be produced, and a scenario that
    /// cannot write its evidence fails closed).
    fn pinned_known_hosts(&self) -> Result<PinnedKnownHosts, String> {
        Err("this scenario host has no pinned known_hosts file".to_owned())
    }

    /// Probe one SSH target for the trust summary: is its host key present in
    /// the pinned file, and does `sudo -n true` succeed over the pinned,
    /// strict-host-key-checked connection. Measured, never assumed.
    fn probe_ssh_target(&self, _target: &str) -> Result<SshTrustProbe, String> {
        Err("this scenario host cannot probe ssh targets".to_owned())
    }

    /// Capture the client's `rustynet status` (bounded, through this host's
    /// ssh transport, daemon at `socket_path`) so the traversal-adversarial
    /// scenario can refuse an already-unhealthy client BEFORE its sibling
    /// validator mutates the lab — with the status text in the refusal, not
    /// an empty validator log. `Err` only when the host cannot ask at all;
    /// parsing the captured text (fail closed on ambiguity) is the caller's
    /// job via `baseline_status_is_fail_closed`.
    fn capture_node_status(&self, _target: &str, _socket_path: &str) -> Result<String, String> {
        Err("this scenario host cannot capture remote status".to_owned())
    }
}

/// The pinned `known_hosts` file the orchestrator trusts, with its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedKnownHosts {
    pub path: String,
    pub sha256: String,
}

/// What a probe of one SSH target measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTrustProbe {
    pub checked_candidates: Vec<String>,
    pub matched_candidate: Option<String>,
    pub passwordless_sudo: bool,
}

/// `[user@]host[:port]` split into its parts. IPv6 literals are refused (the
/// lab targets are IPv4 or names; a bracketed form would need its own
/// known_hosts spelling).
pub fn parse_ssh_target(target: &str) -> Result<(Option<String>, String, u16), String> {
    let (user, rest) = match target.split_once('@') {
        Some((user, rest)) if !user.is_empty() => (Some(user.to_owned()), rest),
        Some(_) => return Err(format!("ssh target {target:?} has an empty user")),
        None => (None, target),
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .map_err(|_| format!("ssh target {target:?} has an invalid port"))?,
        ),
        None => (rest, 22),
    };
    if host.is_empty()
        || host.starts_with('-')
        || host.contains(':')
        || !host
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return Err(format!("ssh target {target:?} has an unsupported host"));
    }
    if let Some(user) = &user
        && (user.starts_with('-')
            || !user
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')))
    {
        return Err(format!("ssh target {target:?} has an unsupported user"));
    }
    Ok((user, host.to_owned(), port))
}

/// The `known_hosts` spelling of `host` on `port`.
pub fn known_hosts_candidate(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

/// The production [`ScenarioHost`]: real subprocesses, real filesystem, and the
/// in-process report reader.
pub struct LocalScenarioHost {
    repo_root: PathBuf,
    /// Forwarded to a sibling validator as `LIVE_LAB_PINNED_KNOWN_HOSTS_FILE`.
    /// The siblings drive their own ssh transport and read the pin from the
    /// environment, exactly as the shell exported it before invoking them.
    known_hosts_file: Option<PathBuf>,
    /// The identity the trust-summary probe connects with.
    ssh_identity_file: Option<PathBuf>,
    /// Forwarded as `RUSTYNET_EXPECTED_GIT_COMMIT`; the siblings stamp it into
    /// the reports the cross-network report validator later checks.
    expected_git_commit: Option<String>,
    /// The stage log (`logs/<stage>.log`) sibling validator output is teed
    /// into. Without it the validator's stdout/stderr inherit the
    /// orchestrator's stdio and never reach the stage's declared evidence —
    /// katana-xnet-1271's `traversal_adversarial` failed with an empty stage
    /// log while the sibling had printed its `policy_reject` reason.
    stage_log: Option<PathBuf>,
}

impl LocalScenarioHost {
    pub fn new(repo_root: PathBuf) -> Self {
        Self {
            repo_root,
            known_hosts_file: None,
            ssh_identity_file: None,
            expected_git_commit: None,
            stage_log: None,
        }
    }

    /// Tee sibling validator output into the stage log (see [`Self::stage_log`]).
    pub fn with_stage_log(mut self, stage_log: Option<PathBuf>) -> Self {
        self.stage_log = stage_log;
        self
    }

    pub fn with_ssh_identity_file(mut self, ssh_identity_file: Option<PathBuf>) -> Self {
        self.ssh_identity_file = ssh_identity_file;
        self
    }

    pub fn with_known_hosts_file(mut self, known_hosts_file: Option<PathBuf>) -> Self {
        self.known_hosts_file = known_hosts_file;
        self
    }

    pub fn with_expected_git_commit(mut self, expected_git_commit: Option<String>) -> Self {
        self.expected_git_commit = expected_git_commit;
        self
    }

    /// Run `command`, mapping a spawn failure to `Err` and the process's own
    /// exit status to `Ok(bool)`.
    fn status_of(&self, mut command: Command, label: &str) -> Result<bool, String> {
        command
            .current_dir(&self.repo_root)
            .status()
            .map(|status| status.success())
            .map_err(|err| format!("failed to run {label}: {err}"))
    }
}

impl ScenarioHost for LocalScenarioHost {
    fn run_required_test(
        &self,
        crate_name: &str,
        test_name: &str,
        log_path: &Path,
    ) -> Result<bool, String> {
        // Append rather than truncate: the caller runs several gates in a row
        // into one log, which is what made the shell's `tee -a` the right
        // primitive and a per-gate truncation the wrong one.
        let log = append_log(log_path)?;
        let errors = log
            .try_clone()
            .map_err(|err| format!("failed to open gate log {}: {err}", log_path.display()))?;
        let mut command = Command::new("bash");
        command
            .arg("scripts/ci/run_required_test.sh")
            .arg(crate_name)
            .arg(test_name)
            .arg("--all-features")
            .stdout(log)
            .stderr(errors);
        self.status_of(command, &format!("required test {crate_name}::{test_name}"))
    }

    fn write_report(
        &self,
        config: GenerateCrossNetworkRemoteExitReportConfig,
    ) -> Result<(), String> {
        execute_ops_generate_cross_network_remote_exit_report(config).map(|_| ())
    }

    fn write_soak_monitor_summary(
        &self,
        config: WriteCrossNetworkSoakMonitorSummaryConfig,
    ) -> Result<(), String> {
        execute_ops_write_cross_network_soak_monitor_summary(config).map(|_| ())
    }

    fn pinned_known_hosts(&self) -> Result<PinnedKnownHosts, String> {
        use sha2::{Digest, Sha256};
        let path = self
            .known_hosts_file
            .as_deref()
            .ok_or_else(|| "no pinned known_hosts file is configured".to_owned())?;
        let bytes = std::fs::read(path).map_err(|err| {
            format!(
                "reading pinned known_hosts {} failed: {err}",
                path.display()
            )
        })?;
        Ok(PinnedKnownHosts {
            path: path.display().to_string(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        })
    }

    fn probe_ssh_target(&self, target: &str) -> Result<SshTrustProbe, String> {
        let known_hosts = self
            .known_hosts_file
            .as_deref()
            .ok_or_else(|| "no pinned known_hosts file is configured".to_owned())?;
        let identity = self
            .ssh_identity_file
            .as_deref()
            .ok_or_else(|| "no ssh identity file is configured".to_owned())?;
        let (user, host, port) = parse_ssh_target(target)?;
        let candidate = known_hosts_candidate(&host, port);
        let pinned = Command::new("ssh-keygen")
            .arg("-F")
            .arg(&candidate)
            .arg("-f")
            .arg(known_hosts)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|err| format!("ssh-keygen lookup failed for {candidate}: {err}"))?
            .success();
        // The sudo probe runs over the same pinned, strict connection every
        // scenario command uses; a host that is not pinned never gets probed.
        let passwordless_sudo = pinned && {
            let mut command = Command::new("ssh");
            command
                .args([
                    "-n",
                    "-F",
                    "/dev/null",
                    "-o",
                    "LogLevel=ERROR",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    "-o",
                    "ConnectTimeout=15",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-p",
                ])
                .arg(port.to_string())
                .arg("-i")
                .arg(identity)
                .arg("-o")
                .arg(format!("UserKnownHostsFile={}", known_hosts.display()));
            if let Some(user) = &user {
                command.arg("-l").arg(user);
            }
            command
                .args(["--", host.as_str(), "sudo", "-n", "true"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|status| status.success())
                .map_err(|err| format!("ssh sudo probe to {target} failed to start: {err}"))?
        };
        Ok(SshTrustProbe {
            checked_candidates: vec![candidate.clone()],
            matched_candidate: pinned.then_some(candidate),
            passwordless_sudo,
        })
    }

    fn capture_node_status(&self, target: &str, socket_path: &str) -> Result<String, String> {
        let identity = self
            .ssh_identity_file
            .as_deref()
            .ok_or_else(|| "no ssh identity file is configured".to_owned())?;
        let (user, host, port) = parse_ssh_target(target)?;
        // Same pinned, strict connection the sudo probe uses; only the remote
        // command differs. `rustynet status` may exit non-zero on a fail-closed
        // daemon while still printing its status — the captured stdout is the
        // evidence, so any exit status is accepted here and parsed upstream.
        let mut command = Command::new("ssh");
        command
            .args([
                "-n",
                "-F",
                "/dev/null",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=15",
                "-o",
                "IdentitiesOnly=yes",
                "-p",
            ])
            .arg(port.to_string())
            .arg("-i")
            .arg(identity);
        if let Some(known_hosts) = &self.known_hosts_file {
            command
                .arg("-o")
                .arg(format!("UserKnownHostsFile={}", known_hosts.display()));
        }
        if let Some(user) = &user {
            command.arg("-l").arg(user);
        }
        command
            .args([
                "--",
                host.as_str(),
                "timeout",
                "15",
                "env",
                &format!("RUSTYNET_DAEMON_SOCKET={socket_path}"),
                super::REMOTE_RUSTYNET_BIN,
                "status",
            ])
            .output()
            .map_err(|err| format!("ssh status capture from {target} failed to start: {err}"))
            .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn run_validator_bin(&self, bin: &str, args: &[&str]) -> Result<bool, String> {
        let mut command = Command::new("cargo");
        command
            .args([
                "run",
                "--quiet",
                "-p",
                "rustynet-cli",
                "--features",
                "vm-lab",
                "--bin",
                bin,
                "--",
            ])
            .args(args);
        if let Some(known_hosts) = self.known_hosts_file.as_deref() {
            command.env("LIVE_LAB_PINNED_KNOWN_HOSTS_FILE", known_hosts);
        }
        if let Some(commit) = self.expected_git_commit.as_deref() {
            command.env("RUSTYNET_EXPECTED_GIT_COMMIT", commit);
        }
        // Capture the sibling's output into the stage log WITHOUT touching the
        // pass criterion: the exit status alone still decides Ok(bool). The
        // sibling usually writes its own --log-path artifact, but everything it
        // prints BEFORE that (cargo failures, panics, early refusals) used to
        // vanish into the orchestrator's inherited stdio.
        if let Some(stage_log) = self.stage_log.as_deref() {
            tee_validator_output(&mut command, stage_log, bin)?;
        }
        self.status_of(command, bin)
    }

    fn report_exists(&self, report_path: &Path) -> bool {
        report_path.is_file()
    }

    fn write_artifact(&self, path: &Path, contents: &str) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "failed to create artifact directory {}: {err}",
                    parent.display()
                )
            })?;
        }
        std::fs::write(path, contents)
            .map_err(|err| format!("failed to write artifact {}: {err}", path.display()))
    }

    fn read_report_status(&self, report_path: &Path) -> Result<String, String> {
        let rendered =
            execute_ops_read_cross_network_report_fields(ReadCrossNetworkReportFieldsConfig {
                report_path: report_path.to_path_buf(),
                include_status: true,
                checks: Vec::new(),
                network_fields: Vec::new(),
                default_value: CHECK_FAIL.to_owned(),
            })?;
        Ok(split_report_lines(&rendered, 1)
            .into_iter()
            .next()
            .unwrap_or_else(|| CHECK_FAIL.to_owned()))
    }

    fn read_report_checks(
        &self,
        report_path: &Path,
        checks: &[&str],
    ) -> Result<Vec<String>, String> {
        let rendered =
            execute_ops_read_cross_network_report_fields(ReadCrossNetworkReportFieldsConfig {
                report_path: report_path.to_path_buf(),
                include_status: false,
                checks: checks.iter().map(|check| (*check).to_owned()).collect(),
                network_fields: Vec::new(),
                // A check the report does not carry reads as "fail", never as
                // absent — the shell's `"${results[N]:-fail}"`, pushed down
                // into the reader so every caller inherits it.
                default_value: CHECK_FAIL.to_owned(),
            })?;
        Ok(split_report_lines(&rendered, checks.len()))
    }
}

/// Open `path` for appending, creating its parent directory and the file
/// itself. Failing here is a hard error rather than a silent fallback to
/// discarding the output: the gate log is declared evidence, and a gate whose
/// output went nowhere has not produced it.
fn append_log(path: &Path) -> Result<std::fs::File, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create log directory {}: {err}", parent.display()))?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("failed to open gate log {}: {err}", path.display()))
}

/// Wire `command`'s stdout and stderr into `stage_log` under a header naming
/// the validator, so sibling output lands in the stage's declared evidence.
///
/// Append, never truncate: a stage log collects several validators (the
/// adversarial suite runs two) plus the scenario's own remote-command
/// transcripts. Failing to open the log is a hard error, same contract as
/// [`append_log`]: a validator whose output went nowhere has not produced its
/// evidence. The pass criterion is untouched — this only redirects streams.
fn tee_validator_output(command: &mut Command, stage_log: &Path, bin: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut log = append_log(stage_log)?;
    let errors = log
        .try_clone()
        .map_err(|err| format!("failed to clone stage log {}: {err}", stage_log.display()))?;
    writeln!(log, "-- validator {bin} --")
        .map_err(|err| format!("failed to write stage log {}: {err}", stage_log.display()))?;
    command.stdout(log).stderr(errors);
    Ok(())
}

/// Split the reader's newline-delimited output into exactly `expected` values,
/// padding any short answer with `"fail"`.
///
/// Padding rather than erroring is deliberate and matches the shell's
/// `"${results[N]:-fail}"`: a report that omits a check has not passed it. The
/// alternative — treating a short read as a hard error — would turn a
/// legitimately-failing report into an unassertable one.
fn split_report_lines(rendered: &str, expected: usize) -> Vec<String> {
    let mut values: Vec<String> = rendered
        .lines()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect();
    values.resize(expected, CHECK_FAIL.to_owned());
    values
}

/// The passing spelling in a report's check fields.
pub const CHECK_PASS: &str = "pass";
/// The failing spelling, and the fail-closed default for an absent check.
pub const CHECK_FAIL: &str = "fail";

/// True only when every value in `values` is exactly `"pass"`.
///
/// The shell wrote this as a chain of `[[ "${a[0]}" == 'pass' && … ]]`. Folding
/// it into one helper means a scenario that adds a check to the list cannot
/// forget to add it to the conjunction.
pub fn all_pass(values: &[String]) -> bool {
    !values.is_empty() && values.iter().all(|value| value == CHECK_PASS)
}

#[cfg(test)]
pub(crate) mod recording {
    use super::{
        CHECK_FAIL, GenerateCrossNetworkRemoteExitReportConfig, PinnedKnownHosts, ScenarioHost,
        SshTrustProbe, WriteCrossNetworkSoakMonitorSummaryConfig,
    };
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// One recorded local invocation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum HostCall {
        RequiredTest {
            crate_name: String,
            test_name: String,
            log_path: PathBuf,
        },
        /// A report a composed baseline scenario asked to have written. Kept as
        /// the whole config so a test can assert on the suite, the status and
        /// the artifact lists the composing scenario declared.
        WriteReport(Box<GenerateCrossNetworkRemoteExitReportConfig>),
        /// A soak monitor summary the scenario asked to have written, kept
        /// whole so a test can assert on every counter it reported.
        WriteSoakMonitorSummary(Box<WriteCrossNetworkSoakMonitorSummaryConfig>),
        ValidatorBin {
            bin: String,
            args: Vec<String>,
        },
        ReadReport {
            report_path: PathBuf,
            checks: Vec<String>,
        },
        ReadReportStatus {
            report_path: PathBuf,
        },
        WriteArtifact {
            path: PathBuf,
            contents: String,
        },
    }

    /// Scriptable in-memory [`ScenarioHost`] for scenario unit tests.
    #[derive(Default)]
    pub struct RecordingHost {
        pub calls: Mutex<Vec<HostCall>>,
        /// Required-test outcomes by test name; absent = pass.
        pub required_test_results: BTreeMap<String, bool>,
        /// Required tests that cannot be run at all.
        pub required_test_errors: Vec<String>,
        /// Validator-bin outcomes by bin name; absent = pass.
        pub validator_results: BTreeMap<String, bool>,
        /// Validator bins that cannot be run at all.
        pub validator_errors: Vec<String>,
        /// Report paths that exist; anything else does not.
        pub existing_reports: Vec<PathBuf>,
        /// Check values by report path, in the order the scenario asks.
        pub report_checks: BTreeMap<PathBuf, Vec<String>>,
        /// Report `status` by path; absent = `"pass"`.
        pub report_status: BTreeMap<PathBuf, String>,
        /// Report paths whose read fails outright.
        pub report_read_errors: Vec<PathBuf>,
        /// Artifact paths whose write fails outright.
        pub artifact_write_errors: Vec<PathBuf>,
        /// Report paths whose generation fails outright.
        pub report_write_errors: Vec<PathBuf>,
        /// `rustynet status` captures by ssh target for
        /// [`ScenarioHost::capture_node_status`]; absent = the host cannot
        /// answer (Err, fail closed).
        pub node_status_by_target: BTreeMap<String, String>,
    }

    impl RecordingHost {
        pub fn recorded(&self) -> Vec<HostCall> {
            self.calls.lock().expect("recording host lock").clone()
        }

        fn record(&self, call: HostCall) {
            self.calls.lock().expect("recording host lock").push(call);
        }
    }

    impl ScenarioHost for RecordingHost {
        fn run_required_test(
            &self,
            crate_name: &str,
            test_name: &str,
            log_path: &Path,
        ) -> Result<bool, String> {
            self.record(HostCall::RequiredTest {
                crate_name: crate_name.to_owned(),
                test_name: test_name.to_owned(),
                log_path: log_path.to_path_buf(),
            });
            if self
                .required_test_errors
                .iter()
                .any(|name| name == test_name)
            {
                return Err(format!("mock: cannot run required test {test_name}"));
            }
            Ok(*self.required_test_results.get(test_name).unwrap_or(&true))
        }

        fn run_validator_bin(&self, bin: &str, args: &[&str]) -> Result<bool, String> {
            self.record(HostCall::ValidatorBin {
                bin: bin.to_owned(),
                args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            });
            if self.validator_errors.iter().any(|name| name == bin) {
                return Err(format!("mock: cannot run validator {bin}"));
            }
            Ok(*self.validator_results.get(bin).unwrap_or(&true))
        }

        fn report_exists(&self, report_path: &Path) -> bool {
            self.existing_reports.iter().any(|path| path == report_path)
        }

        fn read_report_status(&self, report_path: &Path) -> Result<String, String> {
            self.record(HostCall::ReadReportStatus {
                report_path: report_path.to_path_buf(),
            });
            if self.report_read_errors.iter().any(|p| p == report_path) {
                return Err(format!("mock: cannot read {}", report_path.display()));
            }
            Ok(self
                .report_status
                .get(report_path)
                .cloned()
                .unwrap_or_else(|| super::CHECK_PASS.to_owned()))
        }

        fn read_report_checks(
            &self,
            report_path: &Path,
            checks: &[&str],
        ) -> Result<Vec<String>, String> {
            self.record(HostCall::ReadReport {
                report_path: report_path.to_path_buf(),
                checks: checks.iter().map(|check| (*check).to_owned()).collect(),
            });
            if self.report_read_errors.iter().any(|p| p == report_path) {
                return Err(format!("mock: cannot read {}", report_path.display()));
            }
            let mut values = self
                .report_checks
                .get(report_path)
                .cloned()
                .unwrap_or_default();
            values.resize(checks.len(), CHECK_FAIL.to_owned());
            Ok(values)
        }

        fn write_artifact(&self, path: &Path, contents: &str) -> Result<(), String> {
            self.record(HostCall::WriteArtifact {
                path: path.to_path_buf(),
                contents: contents.to_owned(),
            });
            if self.artifact_write_errors.iter().any(|p| p == path) {
                return Err(format!("mock: cannot write {}", path.display()));
            }
            Ok(())
        }

        fn write_soak_monitor_summary(
            &self,
            config: WriteCrossNetworkSoakMonitorSummaryConfig,
        ) -> Result<(), String> {
            let path = config.path.clone();
            self.record(HostCall::WriteSoakMonitorSummary(Box::new(config)));
            if self.artifact_write_errors.contains(&path) {
                return Err(format!("mock: cannot write {}", path.display()));
            }
            Ok(())
        }

        fn pinned_known_hosts(&self) -> Result<PinnedKnownHosts, String> {
            Ok(PinnedKnownHosts {
                path: "/tmp/mock-known_hosts".to_owned(),
                sha256: "0".repeat(64),
            })
        }

        fn probe_ssh_target(&self, target: &str) -> Result<SshTrustProbe, String> {
            Ok(SshTrustProbe {
                checked_candidates: vec![target.to_owned()],
                matched_candidate: Some(target.to_owned()),
                passwordless_sudo: true,
            })
        }

        fn capture_node_status(&self, target: &str, _socket_path: &str) -> Result<String, String> {
            self.node_status_by_target
                .get(target)
                .cloned()
                .ok_or_else(|| format!("no scripted node status for {target}"))
        }

        fn write_report(
            &self,
            config: GenerateCrossNetworkRemoteExitReportConfig,
        ) -> Result<(), String> {
            let report_path = config.report_path.clone();
            self.record(HostCall::WriteReport(Box::new(config)));
            if self.report_write_errors.contains(&report_path) {
                return Err(format!(
                    "mock: cannot write report {}",
                    report_path.display()
                ));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod ssh_target_tests {
    use super::{known_hosts_candidate, parse_ssh_target};

    #[test]
    fn parses_user_host_and_port() {
        assert_eq!(
            parse_ssh_target("debian@192.168.122.45:22"),
            Ok((Some("debian".to_owned()), "192.168.122.45".to_owned(), 22))
        );
        assert_eq!(
            parse_ssh_target("lab-1:2222"),
            Ok((None, "lab-1".to_owned(), 2222))
        );
        assert_eq!(
            parse_ssh_target("debian@host"),
            Ok((Some("debian".to_owned()), "host".to_owned(), 22))
        );
    }

    #[test]
    fn refuses_what_it_cannot_spell_safely() {
        for bad in [
            "",
            "@host",
            "debian@",
            "debian@::1",
            "debian@h:99999",
            "a b@h",
            "-oProxy@h",
            "debian@-oProxy",
        ] {
            assert!(parse_ssh_target(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn known_hosts_spelling_brackets_a_non_default_port() {
        assert_eq!(known_hosts_candidate("h", 22), "h");
        assert_eq!(known_hosts_candidate("h", 2222), "[h]:2222");
    }
}

#[cfg(test)]
mod validator_stage_log_tests {
    use super::tee_validator_output;
    use std::path::PathBuf;
    use std::process::Command;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-validator-stage-log-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// The tee must land BOTH streams plus the naming header in the stage log,
    /// appending (never truncating) what earlier evidence wrote.
    #[test]
    fn tee_captures_both_streams_under_a_header_without_truncating() {
        let dir = temp_dir("capture");
        let log = dir.join("stage.log");
        std::fs::write(&log, "prior evidence\n").expect("seed log");

        let mut first = Command::new("sh");
        first.arg("-c").arg("echo out-line; echo err-line 1>&2");
        tee_validator_output(&mut first, &log, "endpoint-hijack").expect("tee first");
        let status = first.status().expect("run first");
        assert!(status.success(), "the fixture command itself succeeds");

        let mut second = Command::new("sh");
        second.arg("-c").arg("echo second-out");
        tee_validator_output(&mut second, &log, "control-surface").expect("tee second");
        second.status().expect("run second");

        let content = std::fs::read_to_string(&log).expect("read log");
        assert!(
            content.starts_with("prior evidence\n"),
            "append, not truncate"
        );
        assert!(content.contains("-- validator endpoint-hijack --"));
        assert!(content.contains("out-line"));
        assert!(content.contains("err-line"));
        assert!(content.contains("-- validator control-surface --"));
        assert!(content.contains("second-out"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The tee creates the log's parent directory, matching the gate-log
    /// contract: missing directories are made, not fatal.
    #[test]
    fn tee_creates_missing_parent_directories() {
        let dir = temp_dir("parents");
        let log = dir.join("logs").join("nested").join("stage.log");
        let mut command = Command::new("true");
        tee_validator_output(&mut command, &log, "bin").expect("tee creates parents");
        command.status().expect("run");
        assert!(log.is_file(), "the stage log must exist afterwards");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A validator that exits non-zero still writes its output — the capture
    /// must not change the exit status the caller reads (pass criterion
    /// untouched), and a failing sibling is exactly the case the log exists
    /// for (katana-xnet-1271's policy_reject).
    #[test]
    fn tee_keeps_the_exit_status_and_logs_failing_validators_too() {
        let dir = temp_dir("failing");
        let log = dir.join("stage.log");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("echo 'error [policy_reject (78)]' 1>&2; exit 78");
        tee_validator_output(&mut command, &log, "endpoint-hijack").expect("tee");
        let status = command.status().expect("run");
        assert_eq!(status.code(), Some(78), "the exit status passes through");
        let content = std::fs::read_to_string(&log).expect("read log");
        assert!(content.contains("policy_reject"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
