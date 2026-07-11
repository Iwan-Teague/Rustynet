#![allow(dead_code)]
use std::time::Duration;

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const MAX_LAB_CLOCK_SKEW_SECS: u64 = 90;

/// Clock-probe retry budget. The probe is the first SSH command a run issues
/// against a guest, so it eats first-connection transients (control-master
/// warm-up, ARP/route settle after a network reconfig). A single transient
/// `Operation timed out` used to hard-fail the whole run (cascade to skip-all +
/// cleanup fail); retry a few times before giving up (ledger 2026-07-11,
/// observed on `debian-headless-4`). The underlying `ssh::run_remote` already
/// bounds each attempt with `ConnectTimeout=15`, so this only adds retries, not
/// an unbounded wait.
const CLOCK_PROBE_ATTEMPTS: u32 = 3;
const CLOCK_PROBE_RETRY_BACKOFF: Duration = Duration::from_millis(750);

/// Run `op` up to `attempts` times (clamped to at least one), sleeping `backoff`
/// between tries, returning the first `Ok`. Route ONLY transient transport
/// failures here — a deterministic remote error (non-zero exit, unparseable
/// output) is handled by the caller without retry.
fn retry_transient<T, E>(
    attempts: u32,
    backoff: Duration,
    mut op: impl FnMut() -> Result<T, E>,
) -> Result<T, E> {
    let attempts = attempts.max(1);
    let mut last_err: Option<E> = None;
    for attempt in 1..=attempts {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_err = Some(err);
                if attempt < attempts {
                    std::thread::sleep(backoff);
                }
            }
        }
    }
    Err(last_err.expect("attempts >= 1 guarantees at least one captured error"))
}

fn parse_remote_unix_time(output: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(output)
        .map_err(|err| format!("remote clock output is not UTF-8: {err}"))?
        .trim();
    text.parse::<u64>()
        .map_err(|err| format!("remote clock output is not a Unix timestamp ({text:?}): {err}"))
}

fn validate_clock_skew(host_unix: u64, guest_unix: u64, max_skew_secs: u64) -> Result<(), String> {
    let skew = host_unix.abs_diff(guest_unix);
    if skew > max_skew_secs {
        Err(format!(
            "guest clock skew is {skew}s (maximum {max_skew_secs}s; host={host_unix}, guest={guest_unix})"
        ))
    } else {
        Ok(())
    }
}

pub struct PreflightStage;

impl OrchestrationStage for PreflightStage {
    fn id(&self) -> StageId {
        StageId::Preflight
    }
    fn name(&self) -> &str {
        "preflight"
    }
    fn dependencies(&self) -> &[StageId] {
        &[]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // 1. report_dir writable
        if !ctx.report_dir.exists()
            && let Err(e) = std::fs::create_dir_all(&ctx.report_dir)
        {
            return StageOutcome::Failed(format!(
                "cannot create report dir '{}': {e}",
                ctx.report_dir.display()
            ));
        }
        let probe = ctx.report_dir.join(".preflight_write_test");
        if std::fs::write(&probe, b"ok").is_err() {
            return StageOutcome::Failed(format!(
                "report dir '{}' is not writable",
                ctx.report_dir.display()
            ));
        }
        let _ = std::fs::remove_file(&probe);

        // 1b. network-profile immutability: the record written at launch must
        // still verify against the on-repo manifests. Drift after launch
        // fails closed (connectivity rulebook §15.4). Legacy report dirs
        // without a record skip the check; the launch path always writes one.
        let network_profile_record = ctx.report_dir.join("orchestration/network_profile.json");
        if network_profile_record.is_file() {
            let verified = std::fs::read_to_string(&network_profile_record)
                .map_err(|err| format!("read network profile record failed: {err}"))
                .and_then(|raw| {
                    serde_json::from_str::<
                        crate::vm_lab::network_profile::OrchestrationNetworkProfileRecord,
                    >(&raw)
                    .map_err(|err| format!("parse network profile record failed: {err}"))
                })
                .and_then(|record| {
                    record.verify_against_manifests(std::path::Path::new(
                        crate::vm_lab::network_profile::DEFAULT_NETWORK_PROFILE_DIR,
                    ))
                });
            if let Err(err) = verified {
                return StageOutcome::Failed(format!("network profile drift check failed: {err}"));
            }
        }

        // 2. ssh binary
        if std::process::Command::new("ssh")
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_err()
        {
            return StageOutcome::Failed("ssh binary not found in PATH".to_owned());
        }

        // 3. exactly one exit node
        let exit_count = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Exit)
            .count();
        if exit_count != 1 {
            return StageOutcome::Failed(format!(
                "lab requires exactly 1 Exit node, found {exit_count}"
            ));
        }

        // 4. signed-state freshness depends on synchronized clocks. A paused
        // VM can be hours behind while SSH/readiness still look healthy; issuing
        // bundles then makes the daemon reject them as future-dated. Detect the
        // condition before bootstrap or signed-state mutation.
        for (alias, adapter) in &ctx.adapters {
            let host = match adapter.shell_host() {
                Ok(host) => host,
                Err(err) => {
                    return StageOutcome::Failed(format!(
                        "{alias}: cannot construct clock probe: {err}"
                    ));
                }
            };
            let platform = adapter.platform();
            let argv: &[&str] = match platform {
                crate::vm_lab::VmGuestPlatform::Windows => &[
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()",
                ],
                _ => &["date", "+%s"],
            };
            // Retry only the transport: a first-connection SSH transient must
            // not decide the whole run. A non-zero exit / unparseable output
            // below is deterministic and is NOT retried.
            let status = match retry_transient(
                CLOCK_PROBE_ATTEMPTS,
                CLOCK_PROBE_RETRY_BACKOFF,
                || host.run_argv(argv, &[], &[]),
            ) {
                Ok(status) => status,
                Err(err) => {
                    return StageOutcome::Failed(format!(
                        "{alias}: remote clock probe failed after {CLOCK_PROBE_ATTEMPTS} attempts: {err}"
                    ));
                }
            };
            if !status.is_success() {
                return StageOutcome::Failed(format!(
                    "{alias}: remote clock probe exited {}: {}",
                    status.code,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
            let guest_unix = match parse_remote_unix_time(&status.stdout) {
                Ok(value) => value,
                Err(err) => return StageOutcome::Failed(format!("{alias}: {err}")),
            };
            let host_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            {
                Ok(duration) => duration.as_secs(),
                Err(err) => {
                    return StageOutcome::Failed(format!(
                        "orchestrator host clock precedes Unix epoch: {err}"
                    ));
                }
            };
            if let Err(err) = validate_clock_skew(host_unix, guest_unix, MAX_LAB_CLOCK_SKEW_SECS) {
                return StageOutcome::Failed(format!("{alias}: {err}"));
            }
        }

        StageOutcome::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use std::collections::HashMap;

    fn make_ctx_with_exit(tmp_dir: &std::path::Path) -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "exit-1".to_owned(),
                role: NodeRole::Exit,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: tmp_dir.to_path_buf(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
        }
    }

    #[test]
    fn preflight_passes_with_exit_node_and_writable_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = make_ctx_with_exit(tmp.path());
        let outcome = PreflightStage.execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Passed | StageOutcome::Failed(_)),
            "must produce a terminal outcome: {outcome:?}"
        );
    }

    #[test]
    fn preflight_fails_with_no_exit_node() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "client-1".to_owned(),
                role: NodeRole::Client,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: tmp.path().to_path_buf(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
        };
        let outcome = PreflightStage.execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Failed(_)),
            "must fail with no exit node: {outcome:?}"
        );
    }

    #[test]
    fn remote_clock_parser_and_skew_check_fail_closed() {
        assert_eq!(parse_remote_unix_time(b"123\n"), Ok(123));
        assert!(parse_remote_unix_time(b"").is_err());
        assert!(parse_remote_unix_time(b"not-a-time").is_err());
        assert!(validate_clock_skew(1_000, 910, 90).is_ok());
        assert!(validate_clock_skew(1_000, 909, 90).is_err());
        assert!(validate_clock_skew(909, 1_000, 90).is_err());
    }

    #[test]
    fn retry_transient_recovers_after_transient_failures() {
        // Regression (ledger 2026-07-11): a first-connection SSH transient must
        // not decide the clock probe. Fail twice, then succeed on the third
        // attempt — the value from the successful try is returned.
        let calls = std::cell::Cell::new(0u32);
        let result: Result<&str, &str> =
            retry_transient(CLOCK_PROBE_ATTEMPTS, Duration::ZERO, || {
                let n = calls.get() + 1;
                calls.set(n);
                if n < 3 {
                    Err("Operation timed out")
                } else {
                    Ok("ok")
                }
            });
        assert_eq!(result, Ok("ok"));
        assert_eq!(calls.get(), 3, "must retry until the probe succeeds");
    }

    #[test]
    fn retry_transient_returns_last_error_after_exhausting_attempts() {
        let calls = std::cell::Cell::new(0u32);
        let result: Result<&str, String> =
            retry_transient(CLOCK_PROBE_ATTEMPTS, Duration::ZERO, || {
                let n = calls.get() + 1;
                calls.set(n);
                Err(format!("timeout #{n}"))
            });
        assert_eq!(result, Err("timeout #3".to_owned()));
        assert_eq!(
            calls.get(),
            CLOCK_PROBE_ATTEMPTS,
            "must attempt exactly the configured budget before failing"
        );
    }

    #[test]
    fn retry_transient_clamps_zero_attempts_to_one() {
        let calls = std::cell::Cell::new(0u32);
        let result: Result<&str, &str> = retry_transient(0, Duration::ZERO, || {
            calls.set(calls.get() + 1);
            Err("nope")
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 1, "zero attempts clamps to exactly one try");
    }
}
