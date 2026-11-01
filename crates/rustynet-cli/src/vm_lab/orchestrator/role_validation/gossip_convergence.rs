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
/// Linux and macOS: the gossip transport is unix-only (the daemon refuses a
/// configured gossip secret on non-unix), and the lab macOS bootstrap now mints
/// a gossip signing secret, so a macOS node is a real gossip participant and is
/// held to the same four-criterion contract as Linux. A Windows node is
/// reported-skipped by the stage, never silently passed.
pub fn gossip_convergence_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux | VmGuestPlatform::Macos)
}

/// Gossip re-mint heartbeat is 30 s, so a node that has just joined may
/// legitimately not have accepted a bundle yet. Wait across several intervals
/// before calling it a failure; a stage that fails on the first poll is a flaky
/// stage, and a flaky stage gets ignored.
const CONVERGENCE_DEADLINE: Duration = Duration::from_secs(150);
const POLL_INTERVAL: Duration = Duration::from_secs(10);

const DAEMON_SOCKET_ENV: &str = "RUSTYNET_DAEMON_SOCKET";
const DAEMON_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
/// macOS keeps the daemon socket under `/private/var/run/rustynet`, root-owned,
/// so the status query runs through `sudo -n` with the socket pinned by `env`.
const MACOS_DAEMON_SOCKET_PATH: &str = "/private/var/run/rustynet/rustynetd.sock";

/// How the `rustynet status` query is dispatched on a given platform.
#[derive(Clone, Copy)]
enum StatusDispatch {
    /// Socket readable by the ssh user: pass the socket through the env seam.
    Direct,
    /// Root-owned socket: `sudo -n env <SOCKET_ENV>=<path> <cli> status`.
    SudoEnv,
}

/// Run the Linux gossip-convergence check through the shell seam.
///
/// `cli_path` is the `rustynet` CLI (not the daemon binary): the gossip fields
/// ride on the daemon's IPC `status` response, which the CLI is what surfaces.
pub fn validate_linux_gossip_convergence(
    shell: &dyn RemoteShellHost,
    cli_path: &str,
    alias: &str,
) -> Result<(), String> {
    validate_gossip_convergence(shell, cli_path, alias, StatusDispatch::Direct)
}

/// Run the macOS gossip-convergence check: same contract as Linux, status
/// queried through `sudo -n` against the root-owned macOS daemon socket.
pub fn validate_macos_gossip_convergence(
    shell: &dyn RemoteShellHost,
    cli_path: &str,
    alias: &str,
) -> Result<(), String> {
    validate_gossip_convergence(shell, cli_path, alias, StatusDispatch::SudoEnv)
}

fn validate_gossip_convergence(
    shell: &dyn RemoteShellHost,
    cli_path: &str,
    alias: &str,
    dispatch: StatusDispatch,
) -> Result<(), String> {
    let deadline = Instant::now() + CONVERGENCE_DEADLINE;
    loop {
        let attempt = read_and_evaluate(shell, cli_path, alias, dispatch);
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

fn status_argv(cli_path: &str, dispatch: StatusDispatch) -> Vec<String> {
    match dispatch {
        StatusDispatch::Direct => vec![cli_path.to_owned(), "status".to_owned()],
        StatusDispatch::SudoEnv => vec![
            "sudo".to_owned(),
            "-n".to_owned(),
            "env".to_owned(),
            format!("{DAEMON_SOCKET_ENV}={MACOS_DAEMON_SOCKET_PATH}"),
            cli_path.to_owned(),
            "status".to_owned(),
        ],
    }
}

fn read_and_evaluate(
    shell: &dyn RemoteShellHost,
    cli_path: &str,
    alias: &str,
    dispatch: StatusDispatch,
) -> Result<(), String> {
    let owned = status_argv(cli_path, dispatch);
    let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
    let env: &[(&str, &str)] = match dispatch {
        StatusDispatch::Direct => &[(DAEMON_SOCKET_ENV, DAEMON_SOCKET_PATH)],
        StatusDispatch::SudoEnv => &[],
    };
    let out = shell
        .run_argv(&argv, env, &[])
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

    // A node that only LISTENS can register peers and accept bundles pushed to it
    // while its own mint/push is dead; that is receive-only participation, not
    // membership of a mesh. It must have minted at least one bundle of its own.
    let minted = match count_field(&tokens, "gossip_minted_total") {
        Ok(value) => value,
        Err(err) => return fail(err),
    };
    if minted < 1 {
        return fail(
            "gossip_minted_total=0 (receive-only: this node never minted a bundle of \
             its own)"
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
    fn receive_only_node_does_not_pass() {
        let receive_only = CONVERGED.replace("gossip_minted_total=9", "gossip_minted_total=0");
        let err = evaluate_gossip_convergence_status("n1", receive_only.as_str())
            .expect_err("a node that never minted must not pass");
        assert!(err.contains("gossip_minted_total=0"), "got: {err}");
        let missing = CONVERGED.replace("gossip_minted_total=9", "");
        assert!(
            evaluate_gossip_convergence_status("n1", missing.as_str()).is_err(),
            "a missing minted counter must fail closed"
        );
    }

    #[test]
    fn runtime_is_unix_only_linux_and_macos() {
        assert!(gossip_convergence_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(gossip_convergence_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(!gossip_convergence_runtime_implemented(
            VmGuestPlatform::Windows
        ));
    }

    #[test]
    fn macos_status_is_queried_through_sudo_with_the_macos_socket() {
        let argv = status_argv("/usr/local/bin/rustynet", StatusDispatch::SudoEnv);
        assert_eq!(
            argv,
            vec![
                "sudo",
                "-n",
                "env",
                "RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock",
                "/usr/local/bin/rustynet",
                "status",
            ]
        );
        let linux = status_argv("/usr/local/bin/rustynet", StatusDispatch::Direct);
        assert_eq!(linux, vec!["/usr/local/bin/rustynet", "status"]);
    }
}
