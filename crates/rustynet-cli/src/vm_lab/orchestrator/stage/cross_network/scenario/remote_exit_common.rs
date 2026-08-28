//! What the direct and relay remote-exit scenarios prove identically.
//!
//! Both bash validators ended with the same two steps, spelled out twice: run
//! `live_linux_server_ip_bypass_test` against the client and the final exit,
//! then fold its four checks into the same two conclusions. They also wrote the
//! same ssh trust summary under different filenames. Duplicating that here
//! would mean two copies of the conjunction that decides whether a leak was
//! proven — the exact thing a reader has to trust — so it lives once.
//!
//! What is deliberately NOT shared: the steady-state evidence. The direct
//! scenario proves a two-node direct path, the relay scenario a three-node
//! relayed one, and their check names, node roles and aggregates differ. Folding
//! those together would need a parameter for every difference and would hide
//! which assertions each scenario actually makes.

use std::path::Path;

use super::host::{CHECK_PASS, ScenarioHost};
use super::provisioning::{self, LabContext, during};

/// The checks the server-IP bypass report is read for, in the shell's order.
/// [`bypass_verdicts`] indexes into this list, so the two cannot drift.
pub const BYPASS_CHECKS: &[&str] = &[
    "internet_route_via_rustynet0",
    "probe_service_blocked_from_client",
    "probe_endpoint_route_direct_not_tunnelled",
    "no_unexpected_bypass_routes",
];

/// The two conclusions a remote-exit scenario draws from the bypass report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BypassVerdicts {
    pub no_underlay_leak: bool,
    pub bypass_is_narrow: bool,
}

/// Fold the four bypass checks into those two conclusions, reproducing the
/// shell's two `[[ … == 'pass' ]]` conjunctions exactly.
///
/// The overlap on `probe_service_blocked_from_client` (index 1, in both) is
/// intentional and load-bearing: it is the single observation that separates
/// "the tunnel carries traffic" from "the tunnel is the only thing that carries
/// traffic". A `results` slice shorter than [`BYPASS_CHECKS`] reads every
/// missing index as fail, so a truncated report cannot produce a pass.
pub fn bypass_verdicts(results: &[String]) -> BypassVerdicts {
    let verdict = |index: usize| results.get(index).is_some_and(|value| value == CHECK_PASS);
    BypassVerdicts {
        no_underlay_leak: verdict(0) && verdict(1),
        bypass_is_narrow: verdict(1) && verdict(2) && verdict(3),
    }
}

/// One scenario's invocation of the server-IP bypass validator.
pub struct BypassRun<'a> {
    /// Where the sibling is told to write its report.
    pub report_path: &'a Path,
    /// Where the sibling is told to write its log.
    pub log_path: &'a Path,
    /// The node whose underlay address the client must NOT be able to reach
    /// around the tunnel — the final exit in both scenarios.
    pub probe_ssh_target: &'a str,
    /// `--probe-bind-ip`: which of the probe's addresses it should serve on.
    ///
    /// `None` lets the sibling pick, which is what the two remote-exit
    /// scenarios do. The failback scenario pins it to the exit's freshly added
    /// roam alias, because the question there is specifically whether the
    /// client can reach the exit at its NEW address around the tunnel — probing
    /// the old one would test a path the roam was supposed to abandon.
    pub probe_bind_ip: Option<&'a str>,
    /// The `FAILURE_SUMMARY` for "the validator failed before emitting
    /// evidence". Each scenario spelled this differently and the operator-facing
    /// text is preserved verbatim.
    pub missing_evidence_summary: &'a str,
    /// The phase label for everything in this step.
    pub phase: &'a str,
}

/// Run the bypass validator and read its verdicts.
///
/// The shell's split between "the validator failed" and "the validator could
/// not produce evidence" is preserved, because only the second is fatal: a
/// failing validator that still wrote a report is assertable, and asserting on
/// it is how the scenario reports WHICH leak occurred rather than just that the
/// step exited non-zero.
pub fn run_bypass_validator(
    host: &dyn ScenarioHost,
    lab: &LabContext,
    run: &BypassRun<'_>,
) -> Result<BypassVerdicts, String> {
    let identity = provisioning::path_arg(&lab.ssh_identity_file);
    let report_arg = provisioning::path_arg(run.report_path);
    let log_arg = provisioning::path_arg(run.log_path);
    let mut args: Vec<&str> = vec![
        "--ssh-identity-file",
        identity.as_str(),
        "--client-host",
        lab.client_ssh_target.as_str(),
        "--probe-host",
        run.probe_ssh_target,
    ];
    // Positioned here, between the probe host and the allow-cidrs, exactly
    // where the shell spelled it.
    if let Some(bind_ip) = run.probe_bind_ip {
        args.push("--probe-bind-ip");
        args.push(bind_ip);
    }
    args.extend_from_slice(&[
        "--ssh-allow-cidrs",
        lab.ssh_allow_cidrs.as_str(),
        "--report-path",
        report_arg.as_str(),
        "--log-path",
        log_arg.as_str(),
    ]);

    let succeeded = during(
        run.phase,
        host.run_validator_bin(provisioning::BIN_SERVER_IP_BYPASS, &args),
    )?;
    if !succeeded && !host.report_exists(run.report_path) {
        return Err(run.missing_evidence_summary.to_owned());
    }

    let results = during(
        run.phase,
        host.read_report_checks(run.report_path, BYPASS_CHECKS),
    )?;
    Ok(bypass_verdicts(&results))
}

/// Write the ssh trust summary the report spec requires as a pass artifact.
///
/// The shell's `live_lab_write_ssh_trust_summary` dumped the host keys its own
/// ad-hoc ssh setup had pinned. That setup is gone — the orchestrator owns
/// host-key pinning for every stage — so the summary records what is actually
/// true of this run: which targets took part, and that their keys were pinned by
/// the orchestrator rather than accepted on first use. Dropping the artifact was
/// not an option: the report validator lists it in
/// `required_pass_source_artifacts`, so a report without it cannot pass.
pub fn write_trust_summary(
    host: &dyn ScenarioHost,
    path: &Path,
    suite: &str,
    participants: &[(&str, &str)],
) -> Result<(), String> {
    let mut contents = format!(
        "suite: {suite}\n\
         host-key-policy: orchestrator-pinned known_hosts (no trust-on-first-use)\n"
    );
    for (role, target) in participants {
        contents.push_str(&format!("{role}: {target}\n"));
    }
    during(
        "writing ssh trust summary",
        host.write_artifact(path, &contents),
    )
}
