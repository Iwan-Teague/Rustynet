#![allow(dead_code)]
//! Gossip peer-convergence validation for the standard orchestrator.
//!
//! Proves the thing the producer-alignment work exists to achieve: that a node
//! publishing its derived gossip verifying key into signed membership actually
//! ends up in a converged gossip mesh — registered as a peer, accepting its
//! peers' signed bundles, and rejecting nothing as an unknown source.
//!
//! Reads the daemon's own status surface rather than the journal. That is a
//! deliberate choice and it removes a real hazard: `gossip_accepted_total` and
//! `gossip_reject_reasons` are counters on the in-process `GossipNode`, so they
//! are scoped to the current daemon lifetime **by construction**. A journal grep
//! is not — during this work an unbounded `journalctl` grep reported 87
//! `gossip_reject_unknown_source` lines that were all emitted by earlier daemon
//! instances running the pre-fix code, which reads as a failure when the node is
//! in fact clean.
//!
//! Fail-closed: every field must be present and parseable, and a missing field
//! fails rather than skips.

use std::time::{Duration, Instant};

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// Where gossip convergence can be validated live.
///
/// Linux only, and that is a property of the product rather than of the lab:
/// the daemon refuses a configured gossip secret on non-unix because the gossip
/// transport is unix-only, and the lab macOS bootstrap never mints a secret. A
/// non-Linux node is reported-skipped by the stage, never silently passed.
pub fn gossip_convergence_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Gossip re-mint heartbeat is 30 s, so a node that has just joined may
/// legitimately not have accepted a bundle yet. Wait across several intervals
/// before calling it a failure; a stage that fails on the first poll is a flaky
/// stage, and a flaky stage gets ignored.
const CONVERGENCE_DEADLINE: Duration = Duration::from_secs(150);
const POLL_INTERVAL: Duration = Duration::from_secs(10);

const DAEMON_SOCKET_ENV: &str = "RUSTYNET_DAEMON_SOCKET";
const DAEMON_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";

/// Run the Linux gossip-convergence check through the shell seam.
///
/// `cli_path` is the `rustynet` CLI (not the daemon binary): the gossip fields
/// ride on the daemon's IPC `status` response, which the CLI is what surfaces.
pub fn validate_linux_gossip_convergence(
    shell: &dyn RemoteShellHost,
    cli_path: &str,
    alias: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + CONVERGENCE_DEADLINE;
    loop {
        let attempt = read_and_evaluate(shell, cli_path, alias);
        match attempt {
            Ok(()) => return Ok(()),
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(format!("{err} (after {}s)", CONVERGENCE_DEADLINE.as_secs()));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

fn read_and_evaluate(
    shell: &dyn RemoteShellHost,
    cli_path: &str,
    alias: &str,
) -> Result<(), String> {
    let argv = [cli_path, "status"];
    let out = shell
        .run_argv(&argv, &[(DAEMON_SOCKET_ENV, DAEMON_SOCKET_PATH)], &[])
        .map_err(|err| format!("dispatch of `rustynet status` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    evaluate_gossip_convergence_status(alias, &stdout)
}

/// Split a `key=value` status line into pairs.
///
/// `splitn(2, '=')` is load-bearing: `gossip_reject_reasons` carries a value
/// that itself contains `=` (`unknown_source=3,stale=1`), so a naive `split('=')`
/// silently truncates exactly the field this check depends on.
fn status_tokens(line: &str) -> Vec<(&str, &str)> {
    line.split_whitespace()
        .filter_map(|token| {
            let mut parts = token.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => Some((key, value)),
                _ => None,
            }
        })
        .collect()
}

fn field<'a>(tokens: &[(&'a str, &'a str)], key: &str) -> Result<&'a str, String> {
    tokens
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
        .ok_or_else(|| format!("status output has no `{key}` field"))
}

fn count_field(tokens: &[(&str, &str)], key: &str) -> Result<u64, String> {
    let raw = field(tokens, key)?;
    raw.parse::<u64>()
        .map_err(|err| format!("`{key}` is not a count: {raw:?} ({err})"))
}

/// Evaluate the gossip half of a `rustynet status` line. Pure, so the contract
/// is testable without a node.
///
/// Every criterion fails closed, and each one is here because its absence would
/// admit a specific false green:
///
/// * `gossip_identity_mismatch` is compared for LITERAL equality with `"false"`.
///   It returns `"unknown"` for a node with no gossip node at all, so the
///   tempting `!= "true"` would pass the most broken node there is.
/// * `gossip_peers_registered >= 1` — a node that registered nobody is not in a
///   mesh, however healthy it looks otherwise.
/// * `gossip_accepted_total >= 1` — registration alone proves only that the
///   local view was built. Accepting a bundle proves a peer's signature verified
///   under the key membership published, which is the property under test.
/// * no `unknown_source` in `gossip_reject_reasons` — the exact signature of the
///   defect this work removes.
pub fn evaluate_gossip_convergence_status(alias: &str, stdout: &str) -> Result<(), String> {
    let tokens = status_tokens(stdout);
    if tokens.is_empty() {
        return Err(format!("{alias}: gossip convergence: empty status output"));
    }
    let fail = |detail: String| Err(format!("{alias}: gossip convergence: {detail}"));

    let mismatch = match field(&tokens, "gossip_identity_mismatch") {
        Ok(value) => value,
        Err(err) => return fail(err),
    };
    if mismatch != "false" {
        return fail(format!(
            "gossip_identity_mismatch={mismatch} (must be exactly \"false\"; \
             \"unknown\" means this node has no gossip identity at all)"
        ));
    }

    let peers = match count_field(&tokens, "gossip_peers_registered") {
        Ok(value) => value,
        Err(err) => return fail(err),
    };
    if peers < 1 {
        return fail("gossip_peers_registered=0 (node is in no gossip mesh)".to_owned());
    }

    let accepted = match count_field(&tokens, "gossip_accepted_total") {
        Ok(value) => value,
        Err(err) => return fail(err),
    };
    if accepted < 1 {
        return fail(
            "gossip_accepted_total=0 (registered peers, but never verified a bundle \
             from one)"
                .to_owned(),
        );
    }

    let reasons = match field(&tokens, "gossip_reject_reasons") {
        Ok(value) => value,
        Err(err) => return fail(err),
    };
    if reasons.contains("unknown_source") {
        return fail(format!(
            "gossip_reject_reasons={reasons} — a peer is publishing a key it cannot \
             sign with, which is the producer-alignment defect"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape taken from a real `rustynet status` line on a converged node.
    const CONVERGED: &str = "node_id=client-1 path_mode=direct gossip_state=active \
         gossip_accepted_total=5 gossip_minted_total=9 gossip_push_failures_total=0 \
         gossip_recv_errors_total=0 gossip_rejected_total=0 gossip_reject_reasons=none \
         gossip_peers_registered=1 gossip_local_epoch=2 gossip_identity_mismatch=false \
         gossip_transport_error=none";

    fn with(field: &str, value: &str) -> String {
        CONVERGED
            .split_whitespace()
            .map(|token| {
                if token.starts_with(&format!("{field}=")) {
                    format!("{field}={value}")
                } else {
                    token.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn a_converged_node_passes() {
        assert!(evaluate_gossip_convergence_status("n1", CONVERGED).is_ok());
    }

    #[test]
    fn identity_mismatch_unknown_fails() {
        // The single most important case: "unknown" is what a node with NO
        // gossip identity reports, so a `!= "true"` check would pass it.
        let err =
            evaluate_gossip_convergence_status("n1", &with("gossip_identity_mismatch", "unknown"))
                .expect_err("unknown identity mismatch must fail");
        assert!(err.contains("must be exactly"), "got: {err}");
    }

    #[test]
    fn identity_mismatch_true_fails() {
        assert!(
            evaluate_gossip_convergence_status("n1", &with("gossip_identity_mismatch", "true"))
                .is_err()
        );
    }

    #[test]
    fn zero_registered_peers_fails() {
        let err = evaluate_gossip_convergence_status("n1", &with("gossip_peers_registered", "0"))
            .expect_err("a node in no mesh must fail");
        assert!(err.contains("no gossip mesh"), "got: {err}");
    }

    #[test]
    fn zero_accepted_fails_even_with_a_registered_peer() {
        // Registration is local bookkeeping; acceptance is the property that
        // proves the published key actually verifies a peer's signature.
        let err = evaluate_gossip_convergence_status("n1", &with("gossip_accepted_total", "0"))
            .expect_err("registered-but-never-accepted must fail");
        assert!(err.contains("never verified a bundle"), "got: {err}");
    }

    #[test]
    fn an_unknown_source_rejection_fails() {
        let err = evaluate_gossip_convergence_status(
            "n1",
            &with("gossip_reject_reasons", "unknown_source=3"),
        )
        .expect_err("unknown_source rejections are the defect signature");
        assert!(err.contains("cannot sign with"), "got: {err}");
    }

    #[test]
    fn other_rejection_kinds_do_not_fail() {
        // Only `unknown_source` indicates the producer-alignment defect; a stale
        // bundle is a different (and expected) condition.
        assert!(
            evaluate_gossip_convergence_status("n1", &with("gossip_reject_reasons", "stale=2"))
                .is_ok()
        );
    }

    #[test]
    fn a_missing_field_fails_rather_than_skips() {
        let stripped = CONVERGED
            .split_whitespace()
            .filter(|t| !t.starts_with("gossip_peers_registered="))
            .collect::<Vec<_>>()
            .join(" ");
        let err = evaluate_gossip_convergence_status("n1", &stripped)
            .expect_err("a missing field must fail closed");
        assert!(
            err.contains("no `gossip_peers_registered` field"),
            "got: {err}"
        );
    }

    #[test]
    fn empty_output_fails() {
        assert!(evaluate_gossip_convergence_status("n1", "").is_err());
    }

    #[test]
    fn reject_reasons_value_containing_equals_is_not_truncated() {
        // `splitn(2, '=')` guard: the value itself contains '='. A naive
        // `split('=')` would drop the payload and silently pass this node.
        let tokens = status_tokens("a=1 gossip_reject_reasons=unknown_source=3,stale=1 b=2");
        let reasons = field(&tokens, "gossip_reject_reasons").expect("field present");
        assert_eq!(reasons, "unknown_source=3,stale=1");
    }

    #[test]
    fn runtime_is_linux_only() {
        assert!(gossip_convergence_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(!gossip_convergence_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(!gossip_convergence_runtime_implemented(
            VmGuestPlatform::Windows
        ));
    }
}
