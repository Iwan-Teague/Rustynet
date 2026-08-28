//! Running one scenario as another's baseline.
//!
//! Five of the eight cross-network validators do not start from a bare lab: they
//! first establish a working remote-exit path and only then perturb it. In bash
//! that was literally `bash live_linux_cross_network_direct_remote_exit_test.sh
//! …` (or the relay one), and it cost three things:
//!
//! * a whole extra process, re-doing argument parsing and ssh setup;
//! * a **report round trip** — the baseline wrote JSON, the composing script
//!   shelled out to `ops read-cross-network-report-fields` to read four values
//!   back out, and a report the baseline failed to write read as four `fail`s
//!   indistinguishable from four real failures;
//! * a second copy of every check name, spelled as a string in the reader call.
//!
//! Both baselines are Rust functions now, so composition is a call and the
//! [`ScenarioOutcome`] comes back directly — no serialisation, no re-parse, and
//! a baseline that could not run is an `Err` rather than a `fail` verdict.
//!
//! # Why the baseline report is still written
//!
//! It is no longer *read*, but it is still required to **exist**: the
//! cross-network report validator lists the baseline's report file (and log) in
//! the composing suite's `required_pass_source_artifacts` /
//! `required_pass_log_artifacts`, and `execute_ops_generate_…` filters
//! `source_artifacts` down to files that are actually on disk. So a composing
//! scenario that only called the function would emit a report that fails its own
//! schema validation. Writing it also keeps the evidence trail the operator had
//! before: the baseline's own verdict, per check, in its own file.

use std::path::Path;

use crate::ops_cross_network_reports::GenerateCrossNetworkRemoteExitReportConfig;

use super::host::ScenarioHost;
use super::provisioning::{self, LabContext, during};
use super::{ScenarioInputs, ScenarioOutcome};

/// Which scenario is being composed as a baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineScenario {
    /// [`super::direct_remote_exit`] — a two-node direct path.
    Direct,
    /// [`super::relay_remote_exit`] — a three-node relayed chain.
    Relay,
}

impl BaselineScenario {
    /// The suite name the baseline's own report carries.
    pub fn suite(self) -> &'static str {
        match self {
            Self::Direct => super::direct_remote_exit::SUITE,
            Self::Relay => super::relay_remote_exit::SUITE,
        }
    }

    /// The aggregate check the baseline's report leads with.
    pub fn success_check(self) -> &'static str {
        match self {
            Self::Direct => "direct_remote_exit_success",
            Self::Relay => "relay_remote_exit_success",
        }
    }

    fn run(
        self,
        host: &dyn ScenarioHost,
        inputs: &ScenarioInputs<'_>,
        lab: &LabContext,
    ) -> ScenarioOutcome {
        match self {
            Self::Direct => super::direct_remote_exit::run(host, inputs, lab),
            Self::Relay => super::relay_remote_exit::run(host, inputs, lab),
        }
    }
}

/// Where a composed baseline's own evidence goes. Both paths are named by the
/// *composing* scenario — the shell passed them as `--report-path` / `--log-path`
/// — and both appear in the composing report's artifact lists.
pub struct BaselinePaths<'a> {
    pub report_path: &'a Path,
    pub log_path: &'a Path,
}

/// What a composed baseline proved.
pub struct BaselineResult {
    /// The baseline's full outcome, so the composing scenario reads check
    /// verdicts directly instead of re-parsing them out of a report.
    pub outcome: ScenarioOutcome,
}

impl BaselineResult {
    /// The baseline ran end to end and its own aggregate passed.
    ///
    /// This is the shell's `direct_rc == 0 && results[0] == 'pass'` pair, which
    /// were never independent: the baseline script wrote `status` from the exit
    /// status of the same `main` the shell was checking, so one implies the
    /// other. Collapsing them here loses nothing and removes the possibility of
    /// checking one and forgetting the other.
    pub fn succeeded(&self) -> bool {
        self.outcome.is_pass()
    }

    /// The baseline's verdict for one of its own named checks.
    pub fn passed(&self, check: &str) -> bool {
        self.outcome.checks.passed(check)
    }
}

/// Run `scenario` as a baseline and write its report at `paths`.
///
/// The baseline's report is written on **every** path including failure, for the
/// same reason the composing scenario's is: a failing baseline that left
/// evidence is diagnosable, and one that left none is not.
pub fn compose(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    scenario: BaselineScenario,
    paths: &BaselinePaths<'_>,
    phase: &str,
) -> Result<BaselineResult, String> {
    let outcome = scenario.run(host, inputs, lab);

    // The baseline's log would otherwise be an empty file the report generator
    // created just to satisfy the schema. Its real remote-command transcript
    // lives in the stage log, because in-process composition shares the stage's
    // one runner per node — so the honest thing for this file to hold is a
    // pointer to that fact plus the baseline's own verdict.
    let mut log = format!(
        "suite: {}\n\
         composition: run in process by the composing cross-network scenario\n\
         remote-command transcript: the stage log for this run\n\
         status: {}\n",
        scenario.suite(),
        outcome.status
    );
    if !outcome.failure_summary.is_empty() {
        log.push_str(&format!("failure_summary: {}\n", outcome.failure_summary));
    }
    for (name, verdict) in outcome.checks.iter() {
        log.push_str(&format!("check {name}={verdict}\n"));
    }
    during(phase, host.write_artifact(paths.log_path, &log))?;

    let relay_host = matches!(scenario, BaselineScenario::Relay)
        .then(|| lab.require_relay_ssh_target(scenario.suite()))
        .transpose()?
        .map(str::to_owned);
    let relay_network_id = matches!(scenario, BaselineScenario::Relay)
        .then(|| lab.require_relay_network_id(scenario.suite()))
        .transpose()?
        .map(str::to_owned);

    let config = GenerateCrossNetworkRemoteExitReportConfig {
        suite: scenario.suite().to_owned(),
        report_path: paths.report_path.to_path_buf(),
        log_path: paths.log_path.to_path_buf(),
        status: outcome.status.as_str().to_owned(),
        failure_summary: outcome.failure_summary.clone(),
        environment: BASELINE_ENVIRONMENT.to_owned(),
        implementation_state: BASELINE_IMPLEMENTATION_STATE.to_owned(),
        source_artifacts: outcome
            .source_artifacts
            .iter()
            .map(std::path::PathBuf::from)
            .collect(),
        log_artifacts: outcome
            .log_artifacts
            .iter()
            .map(std::path::PathBuf::from)
            .collect(),
        client_host: Some(lab.client_ssh_target.clone()),
        exit_host: Some(lab.exit_ssh_target.clone()),
        relay_host,
        probe_host: None,
        client_network_id: Some(lab.client_network_id.clone()),
        exit_network_id: Some(lab.exit_network_id.clone()),
        relay_network_id,
        nat_profile: inputs.nat_profile.as_str().to_owned(),
        impairment_profile: inputs.impairment_profile.clone(),
        check_overrides: outcome.checks.as_report_args(),
        path_status_line: outcome.path_status_line.clone(),
        path_evidence_report: None,
    };
    during(phase, host.write_report(config))?;
    Ok(BaselineResult { outcome })
}

/// The `environment` field every ported scenario's report carries.
pub const BASELINE_ENVIRONMENT: &str = "live_linux_skeleton";
/// The `implementation_state` field every ported scenario's report carries.
pub const BASELINE_IMPLEMENTATION_STATE: &str = "live_measured_validator";

/// Render a path for a report artifact list. See [`provisioning::path_arg`].
pub fn path_arg(path: &Path) -> String {
    provisioning::path_arg(path)
}
