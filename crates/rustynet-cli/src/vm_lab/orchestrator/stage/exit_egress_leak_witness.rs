#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::exit_egress_leak_witness::{
    LeakWitnessReport, exit_egress_leak_witness_runtime_implemented,
    run_linux_exit_egress_leak_witness,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "exit_egress_leak_witness.reported_skips.json";
const VERDICT_FILENAME: &str = "exit_egress_leak_witness.verdict.json";
const WITNESS_ICMP_TARGET: &str = "192.0.2.1";

/// AQ-46: live pcap witness for the scoped exit killswitch egress ruleset
/// (commit `5093ac97`). Code-fixed + Fable-reviewed is NOT PROVEN until
/// lab-witnessed: while the assigned Linux exit is active (NAT on,
/// `protected_dns` on), this stage captures the egress NIC during a bounded
/// window and asserts it carries **zero host-origin udp/53, tcp/53, tcp/853,
/// or IPv6**, while masqueraded client ICMP to 192.0.2.1 (positive control
/// fired from the assigned client) and WireGuard udp on the listen port stay
/// present. Runs right after `exit_dns_failclosed_validation`, while the
/// scoped ruleset is still active and before destructive lifecycle proofs —
/// any leak class, a vacuous capture (no control traffic), a failed posture
/// precondition, or an unusable capture fails closed.
///
/// A macOS / Windows exit node is **reported-skipped** — named in
/// `exit_egress_leak_witness.reported_skips.json`, never a silent pass.
pub struct ExitEgressLeakWitnessStage;

impl OrchestrationStage for ExitEgressLeakWitnessStage {
    fn id(&self) -> StageId {
        StageId::ExitEgressLeakWitness
    }
    fn name(&self) -> &str {
        "exit_egress_leak_witness"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ActiveExit]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Exit]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Exit) {
            Some(assignment) => assignment.alias.clone(),
            None => {
                return StageOutcome::Failed(
                    "exit-egress-leak-witness: no Exit node in assignments".to_owned(),
                );
            }
        };
        // The masqueraded-ICMP positive control must be fired from the
        // assigned client; without one the witness could only ever be
        // vacuous, so a missing client fails closed instead of passing on a
        // capture that proves nothing.
        let client_alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Client) {
            Some(assignment) => assignment.alias.clone(),
            None => {
                return StageOutcome::Failed(
                    "exit-egress-leak-witness: no Client node in assignments — the masqueraded \
                     ICMP positive control is unfireable and the witness would be vacuous; \
                     failing closed"
                        .to_owned(),
                );
            }
        };
        let adapter = match ctx.adapters.get(alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no adapter for exit-egress-leak-witness node"
                ));
            }
        };
        let platform = adapter.platform();
        if !exit_egress_leak_witness_runtime_implemented(platform) {
            let reported_skips = vec![(alias, format!("{platform:?}"))];
            write_reported_skips_note(ctx, &reported_skips);
            return StageOutcome::Skipped(format!(
                "exit egress leak witness is not implemented for {platform:?}"
            ));
        }
        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(e) => {
                return StageOutcome::Failed(format!("{alias}: shell host unavailable: {e}"));
            }
        };
        let client_adapter = match ctx.adapters.get(client_alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{client_alias}: no adapter for the positive-control client"
                ));
            }
        };
        let client_shell = match client_adapter.shell_host() {
            Ok(shell) => shell,
            Err(e) => {
                return StageOutcome::Failed(format!(
                    "{client_alias}: shell host unavailable for positive control: {e}"
                ));
            }
        };
        let client_ping_argv = client_positive_control_ping_argv(client_adapter.platform());

        let mut report = match run_linux_exit_egress_leak_witness(
            shell,
            &alias,
            Some((client_shell, client_ping_argv)),
            crate::vm_lab::orchestrator::role_validation::exit_egress_leak_witness::CAPTURE_WINDOW_SECS,
            crate::vm_lab::orchestrator::role_validation::exit_egress_leak_witness::CAPTURE_SETTLE_SECS,
        ) {
            Ok(report) => report,
            Err(e) => return StageOutcome::Failed(format!("{alias}: {e}")),
        };

        // The verdict artifact lands on every completed run — pass AND fail —
        // so the counts and the raw capture text are always inspectable. A
        // write failure fails the stage: an unwitnessed verdict must never be
        // recorded.
        if let Err(e) = write_verdict_artifact(&ctx.report_dir, &report, &client_alias) {
            return StageOutcome::Failed(format!(
                "exit egress leak witness verdict write failed: {e}"
            ));
        }

        if report.failures.is_empty() {
            match write_pass_witness(&ctx.report_dir, &report, &client_alias) {
                Ok(()) => StageOutcome::Passed,
                Err(e) => {
                    StageOutcome::Failed(format!("exit egress leak witness write failed: {e}"))
                }
            }
        } else {
            report.failures.insert(
                0,
                format!("exit egress leak witness FAILED on exit {alias}:"),
            );
            StageOutcome::Failed(report.failures.join(" "))
        }
    }
}

/// The masqueraded-ICMP positive control the assigned client fires at
/// 192.0.2.1 through its exit route, per client platform. The capture on the
/// exit — not this exit code — is the assertion; the code is recorded as
/// auxiliary evidence.
fn client_positive_control_ping_argv(platform: VmGuestPlatform) -> Vec<String> {
    match platform {
        VmGuestPlatform::Windows => vec![
            "ping".to_owned(),
            "-n".to_owned(),
            "4".to_owned(),
            WITNESS_ICMP_TARGET.to_owned(),
        ],
        VmGuestPlatform::Linux => vec![
            "ping".to_owned(),
            "-c".to_owned(),
            "4".to_owned(),
            "-W".to_owned(),
            "2".to_owned(),
            WITNESS_ICMP_TARGET.to_owned(),
        ],
        VmGuestPlatform::Macos | VmGuestPlatform::Ios | VmGuestPlatform::Android => vec![
            "ping".to_owned(),
            "-c".to_owned(),
            "4".to_owned(),
            WITNESS_ICMP_TARGET.to_owned(),
        ],
    }
}

/// The per-run verdict artifact: posture context, per-class counts, probe
/// exit codes, verdict reasons, and the raw capture text.
fn verdict_json_bytes(report: &LeakWitnessReport, client_alias: &str) -> Vec<u8> {
    let probes: Vec<serde_json::Value> = report
        .probe_exit_codes
        .iter()
        .map(|(probe, code)| serde_json::json!({ "probe": probe, "exit_code": code }))
        .collect();
    let body = serde_json::json!({
        "stage": "exit_egress_leak_witness",
        "exit_alias": report.exit_alias,
        "client_alias": client_alias,
        "egress_iface": report.egress_iface,
        "egress_addr": report.egress_addr,
        "killswitch_table": report.killswitch_table,
        "wg_listen_port": report.wg_listen_port,
        "capture_filter": report.capture_filter,
        "probe_exit_codes": probes,
        "counts": {
            "host_dns_udp": report.counts.host_dns_udp,
            "host_dns_tcp": report.counts.host_dns_tcp,
            "host_dot": report.counts.host_dot,
            "ipv6": report.counts.ipv6,
            "forwarded_icmp": report.counts.forwarded_icmp,
            "wireguard": report.counts.wireguard,
        },
        "leak_free": report.failures.is_empty(),
        "failures": report.failures,
        "capture_stdout": report.capture_stdout,
        "capture_stderr": report.capture_stderr,
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_verdict_artifact(
    report_dir: &std::path::Path,
    report: &LeakWitnessReport,
    client_alias: &str,
) -> Result<(), String> {
    let path = report_dir.join(VERDICT_FILENAME);
    std::fs::write(&path, verdict_json_bytes(report, client_alias))
        .map_err(|err| format!("write {} failed: {err}", path.display()))
}

/// QH-83-style pass witness: names the exit, the client, and the control
/// counts, so a bare PASS can never be recorded without the evidence behind
/// it. An unwritable witness fails the stage — fail closed.
fn write_pass_witness(
    report_dir: &std::path::Path,
    report: &LeakWitnessReport,
    client_alias: &str,
) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::ExitEgressLeakWitness.as_str(),
        &format!(
            "exit_egress_leak=clean exit={} client={} iface={} {}",
            report.exit_alias,
            client_alias,
            report.egress_iface,
            report.counts.as_json_fields()
        ),
    )
}

fn reported_skips_json_bytes(reported_skips: &[(String, String)]) -> Vec<u8> {
    let skipped: Vec<serde_json::Value> = reported_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "exit_egress_leak_witness",
        "reported_skipped_exit_egress_leak_witness": skipped,
        "reason": "The exit egress leak witness runs live on Linux through the Rust engine; \
                   non-Linux exit nodes are reported-skipped (named, never a silent pass)",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_reported_skips_note(ctx: &OrchestrationContext, reported_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(reported_skips));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_evidence_is_scoped_to_assigned_exit() {
        assert_eq!(
            ExitEgressLeakWitnessStage.applies_to_roles(),
            &[NodeRole::Exit]
        );
        assert_eq!(
            ExitEgressLeakWitnessStage.dependencies(),
            &[StageId::ActiveExit]
        );
        assert_eq!(
            ExitEgressLeakWitnessStage.name(),
            "exit_egress_leak_witness"
        );
    }

    #[test]
    fn client_ping_argv_per_platform() {
        assert_eq!(
            client_positive_control_ping_argv(VmGuestPlatform::Linux),
            vec![
                "ping".to_owned(),
                "-c".to_owned(),
                "4".to_owned(),
                "-W".to_owned(),
                "2".to_owned(),
                "192.0.2.1".to_owned()
            ]
        );
        assert_eq!(
            client_positive_control_ping_argv(VmGuestPlatform::Windows),
            vec![
                "ping".to_owned(),
                "-n".to_owned(),
                "4".to_owned(),
                "192.0.2.1".to_owned()
            ]
        );
        assert_eq!(
            client_positive_control_ping_argv(VmGuestPlatform::Macos),
            vec![
                "ping".to_owned(),
                "-c".to_owned(),
                "4".to_owned(),
                "192.0.2.1".to_owned()
            ]
        );
    }

    #[test]
    fn reported_skip_note_names_every_skipped_node() {
        let bytes = reported_skips_json_bytes(&[
            ("mac-1".into(), "Macos".into()),
            ("win-1".into(), "Windows".into()),
        ]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("mac-1") && s.contains("win-1"));
        assert!(s.contains("exit_egress_leak_witness"));
        assert!(s.contains("reported_skipped_exit_egress_leak_witness"));
    }

    fn sample_report(failures: Vec<String>) -> LeakWitnessReport {
        LeakWitnessReport {
            exit_alias: "exit-1".to_owned(),
            egress_iface: "enp0s9".to_owned(),
            egress_addr: "192.0.2.240".to_owned(),
            killswitch_table: "rustynet_g7".to_owned(),
            wg_listen_port: 51820,
            capture_filter: "udp port 53 or icmp".to_owned(),
            counts: crate::vm_lab::orchestrator::role_validation::exit_egress_leak_witness::LeakWitnessCounts {
                host_dns_udp: 0,
                host_dns_tcp: 0,
                host_dot: 0,
                ipv6: 0,
                forwarded_icmp: 4,
                wireguard: 9,
            },
            probe_exit_codes: vec![
                ("host_dns_udp_dig".to_owned(), 1),
                ("client_icmp_positive_control".to_owned(), 0),
            ],
            capture_stdout: "12:00:00.000000 IP 192.0.2.240 > 192.0.2.1: ICMP echo request\n"
                .to_owned(),
            capture_stderr: "tcpdump: listening on 'enp0s9'\n4 packets captured\n".to_owned(),
            failures,
        }
    }

    #[test]
    fn verdict_json_names_counts_and_controls() {
        let bytes = verdict_json_bytes(&sample_report(Vec::new()), "client-1");
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("\"leak_free\": true"), "{s}");
        assert!(s.contains("\"forwarded_icmp\": 4"), "{s}");
        assert!(s.contains("\"wireguard\": 9"), "{s}");
        assert!(s.contains("\"client_alias\": \"client-1\""), "{s}");
        assert!(s.contains("\"exit_alias\": \"exit-1\""), "{s}");
        assert!(s.contains("\"wg_listen_port\": 51820"), "{s}");
        assert!(s.contains("host_dns_udp_dig"), "{s}");
        assert!(s.contains("ICMP echo request"), "{s}");
    }

    #[test]
    fn failing_verdict_json_is_marked_not_leak_free() {
        let bytes = verdict_json_bytes(&sample_report(vec!["leak".to_owned()]), "client-1");
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("\"leak_free\": false"), "{s}");
        assert!(s.contains("\"leak\""), "{s}");
    }

    // QH-83: the pass witness must name the exit, the client, and the control
    // counts — a bare "pass" line would be appeasement, not evidence.
    #[test]
    fn pass_witness_line_names_exit_client_and_counts() {
        let dir = std::env::temp_dir().join(format!(
            "exegress_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_pass_witness(&dir, &sample_report(Vec::new()), "client-1").expect("witness write");
        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::ExitEgressLeakWitness.as_str(),
            ),
        )
        .expect("stage log");
        assert!(log.contains("exit_egress_leak=clean"), "{log}");
        assert!(log.contains("exit=exit-1"), "{log}");
        assert!(log.contains("client=client-1"), "{log}");
        assert!(log.contains("forwarded_icmp=4"), "{log}");
        assert!(log.contains("wireguard=9"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as an
    /// error the execute path turns into `Failed` — never a silent pass.
    #[test]
    fn pass_witness_write_failure_is_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "exegress_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        std::fs::write(dir.join("logs"), b"not a directory").expect("blocker file");
        let err = write_pass_witness(&dir, &sample_report(Vec::new()), "client-1")
            .expect_err("witness write must fail when the logs path is a regular file");
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verdict_artifact_write_failure_is_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "exegress_verdict_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        std::fs::write(dir.join(VERDICT_FILENAME), b"placeholder").expect("pre-write");
        std::fs::set_permissions(
            dir.join(VERDICT_FILENAME),
            std::os::unix::fs::PermissionsExt::from_mode(0o444),
        )
        .expect("chmod");
        let err = write_verdict_artifact(&dir, &sample_report(Vec::new()), "client-1");
        // A read-only verdict file must fail the write on this lab host.
        let _ = std::fs::set_permissions(
            dir.join(VERDICT_FILENAME),
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        );
        match err {
            Err(msg) => {
                assert!(msg.contains("failed:"), "{msg}");
                assert!(msg.contains("Permission denied"), "{msg}");
            }
            Ok(()) => {
                // Running as root would overwrite the read-only file; that
                // environment cannot exercise this guard.
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
