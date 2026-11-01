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

use super::host::{CHECK_PASS, PinnedKnownHosts, ScenarioHost, SshTrustProbe};
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
/// The report validator (`validate_ssh_trust_summary_artifact`) parses this as
/// `key=value` lines and checks MEASURED facts: the pinned known_hosts file and
/// its digest, and per target whether the host key is in that file and whether
/// `sudo -n` works. The shell's `live_lab_write_ssh_trust_summary` measured
/// them; the first Rust port wrote free-text `key: value` lines that the
/// validator rejects as `malformed key/value line 1`, so no suite could ever
/// pass (katana-xnet-64). This writes the validator's format and takes every
/// status from a probe through the host seam. A probe that finds a host
/// unpinned or without passwordless sudo is recorded as `fail` and the
/// validator then refuses the pass report; only a host that cannot produce the
/// evidence at all returns `Err`.
pub fn write_trust_summary(
    host: &dyn ScenarioHost,
    path: &Path,
    suite: &str,
    participants: &[(&str, &str)],
) -> Result<(), String> {
    let pinned = during(
        "reading the pinned known_hosts file",
        host.pinned_known_hosts(),
    )?;
    let mut probes = Vec::with_capacity(participants.len());
    for (role, target) in participants {
        let probe = during(
            "probing ssh trust",
            host.probe_ssh_target(target)
                .map_err(|err| format!("{suite} {role} {target}: {err}")),
        )?;
        probes.push(((*target).to_owned(), probe));
    }
    let generated_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let contents = render_trust_summary(&pinned, &probes, generated_at_unix);
    during(
        "writing ssh trust summary",
        host.write_artifact(path, &contents),
    )
}

/// The validator's `key=value` layout. `transport` is `ssh`: every scenario
/// target is reached over the pinned ssh connection.
fn render_trust_summary(
    pinned: &PinnedKnownHosts,
    probes: &[(String, SshTrustProbe)],
    generated_at_unix: u64,
) -> String {
    let all_pinned = probes
        .iter()
        .all(|(_, probe)| probe.matched_candidate.is_some());
    let all_sudo = probes.iter().all(|(_, probe)| probe.passwordless_sudo);
    let mut out = format!(
        "schema_version=1\n\
         generated_at_unix={generated_at_unix}\n\
         pinned_known_hosts_file={}\n\
         pinned_known_hosts_sha256={}\n\
         target_count={}\n",
        pinned.path,
        pinned.sha256,
        probes.len()
    );
    for (index, (target, probe)) in probes.iter().enumerate() {
        out.push_str(&format!(
            "target[{index}].target={target}\n\
             target[{index}].configured_transport=ssh\n\
             target[{index}].checked_candidates={}\n\
             target[{index}].matched_candidate={}\n\
             target[{index}].host_key_status={}\n\
             target[{index}].passwordless_sudo_status={}\n",
            probe.checked_candidates.join(","),
            probe.matched_candidate.as_deref().unwrap_or(""),
            if probe.matched_candidate.is_some() {
                CHECK_PASS
            } else {
                "fail"
            },
            if probe.passwordless_sudo {
                CHECK_PASS
            } else {
                "fail"
            },
        ));
    }
    out.push_str(&format!(
        "all_targets_pinned={all_pinned}\nall_targets_passwordless_sudo={all_sudo}\n"
    ));
    out
}

#[cfg(test)]
mod trust_summary_tests {
    use super::*;

    fn pinned() -> PinnedKnownHosts {
        PinnedKnownHosts {
            path: "/tmp/pinned_known_hosts".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn probe(pinned_ok: bool, sudo: bool) -> SshTrustProbe {
        SshTrustProbe {
            checked_candidates: vec!["192.168.122.45".to_owned()],
            matched_candidate: pinned_ok.then(|| "192.168.122.45".to_owned()),
            passwordless_sudo: sudo,
        }
    }

    fn problems_for(probes: &[(String, SshTrustProbe)]) -> Vec<String> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x_ssh_trust_summary.txt");
        std::fs::write(
            &path,
            render_trust_summary(&pinned(), probes, 1_700_000_000),
        )
        .expect("write summary");
        crate::ops_cross_network_reports::validate_ssh_trust_summary_for_tests(&path)
    }

    /// The summary the scenarios write must satisfy the validator that grades
    /// pass reports, byte for byte, when the probes are clean.
    #[test]
    fn a_clean_summary_satisfies_the_real_validator() {
        let probes = vec![
            ("debian@192.168.122.45:22".to_owned(), probe(true, true)),
            ("debian@192.168.123.222:22".to_owned(), probe(true, true)),
        ];
        assert_eq!(problems_for(&probes), Vec::<String>::new());
    }

    /// An unpinned host or a failed sudo probe is recorded honestly and the
    /// validator refuses it: the writer never turns a failed probe into a pass.
    #[test]
    fn failed_probes_are_recorded_and_refused() {
        let unpinned = vec![("debian@192.168.122.45:22".to_owned(), probe(false, true))];
        let problems = problems_for(&unpinned);
        assert!(
            problems.iter().any(|p| p.contains("all_targets_pinned")),
            "{problems:?}"
        );
        let no_sudo = vec![("debian@192.168.122.45:22".to_owned(), probe(true, false))];
        let problems = problems_for(&no_sudo);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("all_targets_passwordless_sudo")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_host_that_cannot_produce_the_evidence_fails_closed() {
        struct NoPin;
        impl ScenarioHost for NoPin {
            fn run_required_test(&self, _: &str, _: &str, _: &Path) -> Result<bool, String> {
                unreachable!()
            }
            fn run_validator_bin(&self, _: &str, _: &[&str]) -> Result<bool, String> {
                unreachable!()
            }
            fn report_exists(&self, _: &Path) -> bool {
                unreachable!()
            }
            fn read_report_status(&self, _: &Path) -> Result<String, String> {
                unreachable!()
            }
            fn read_report_checks(&self, _: &Path, _: &[&str]) -> Result<Vec<String>, String> {
                unreachable!()
            }
            fn write_artifact(&self, _: &Path, _: &str) -> Result<(), String> {
                panic!("nothing may be written without evidence")
            }
            fn write_report(
                &self,
                _: crate::ops_cross_network_reports::GenerateCrossNetworkRemoteExitReportConfig,
            ) -> Result<(), String> {
                unreachable!()
            }
            fn write_soak_monitor_summary(
                &self,
                _: crate::ops_cross_network_reports::WriteCrossNetworkSoakMonitorSummaryConfig,
            ) -> Result<(), String> {
                unreachable!()
            }
        }
        let err = write_trust_summary(
            &NoPin,
            Path::new("/tmp/never"),
            "suite",
            &[("client-host", "debian@192.168.122.45:22")],
        )
        .expect_err("no pinned known_hosts means no evidence");
        assert!(err.contains("known_hosts"), "{err}");
    }
}
