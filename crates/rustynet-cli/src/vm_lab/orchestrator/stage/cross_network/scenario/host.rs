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
    ReadCrossNetworkReportFieldsConfig, execute_ops_read_cross_network_report_fields,
};

/// The orchestrator-host command surface a scenario needs.
pub trait ScenarioHost {
    /// Run one required-test gate. `Ok(true)` means the gate passed;
    /// `Ok(false)` means it ran and failed. `Err` is reserved for not being
    /// able to run it at all — a distinction the shell collapsed into a single
    /// non-zero status.
    fn run_required_test(&self, crate_name: &str, test_name: &str) -> Result<bool, String>;

    /// Invoke a sibling validator binary with `args`. As above, `Ok(false)` is
    /// "it ran and reported failure", `Err` is "it could not be run".
    fn run_validator_bin(&self, bin: &str, args: &[&str]) -> Result<bool, String>;

    /// True when `report_path` exists. The validators distinguish "the sibling
    /// failed but left evidence" (readable, still assertable) from "it failed
    /// before emitting evidence" (fail closed, nothing to assert on).
    fn report_exists(&self, report_path: &Path) -> bool;

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
}

/// The production [`ScenarioHost`]: real subprocesses, real filesystem, and the
/// in-process report reader.
pub struct LocalScenarioHost {
    repo_root: PathBuf,
    /// Forwarded to a sibling validator as `LIVE_LAB_PINNED_KNOWN_HOSTS_FILE`.
    /// The siblings drive their own ssh transport and read the pin from the
    /// environment, exactly as the shell exported it before invoking them.
    known_hosts_file: Option<PathBuf>,
    /// Forwarded as `RUSTYNET_EXPECTED_GIT_COMMIT`; the siblings stamp it into
    /// the reports the cross-network report validator later checks.
    expected_git_commit: Option<String>,
}

impl LocalScenarioHost {
    pub fn new(repo_root: PathBuf) -> Self {
        Self {
            repo_root,
            known_hosts_file: None,
            expected_git_commit: None,
        }
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
    fn run_required_test(&self, crate_name: &str, test_name: &str) -> Result<bool, String> {
        let mut command = Command::new("bash");
        command
            .arg("scripts/ci/run_required_test.sh")
            .arg(crate_name)
            .arg(test_name)
            .arg("--all-features");
        self.status_of(command, &format!("required test {crate_name}::{test_name}"))
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
    use super::{CHECK_FAIL, ScenarioHost};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// One recorded local invocation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum HostCall {
        RequiredTest {
            crate_name: String,
            test_name: String,
        },
        ValidatorBin {
            bin: String,
            args: Vec<String>,
        },
        ReadReport {
            report_path: PathBuf,
            checks: Vec<String>,
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
        /// Report paths whose read fails outright.
        pub report_read_errors: Vec<PathBuf>,
        /// Artifact paths whose write fails outright.
        pub artifact_write_errors: Vec<PathBuf>,
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
        fn run_required_test(&self, crate_name: &str, test_name: &str) -> Result<bool, String> {
            self.record(HostCall::RequiredTest {
                crate_name: crate_name.to_owned(),
                test_name: test_name.to_owned(),
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
    }
}
