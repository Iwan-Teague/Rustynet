#![allow(dead_code)]
//! Cross-OS anchor capability-advertisement validation.
//!
//! This is the orchestrator-native port of the
//! capability-advertisement surface of the Linux-only
//! `live_linux_anchor_test` bin, refitted to drive the single probe it
//! needs (`rustynet anchor list`) through the hardened
//! [`RemoteShellHost`] seam instead of the bin's raw
//! `capture_anchor_list_from_host` shell-out. The bin built a shell body
//! string per probe; here the one probe is an explicit argv +
//! Rust-side parsing of [`RemoteExitStatus::stdout`], so no shell string
//! is ever constructed from a non-constant value.
//!
//! Scope: the anchor CAPABILITY-ADVERTISEMENT surface, which works
//! cross-OS today (the same six [`anchor.*`] capabilities are advertised
//! on every OS — see
//! [`NodeRole::product_capabilities_for_platform`](crate::vm_lab::orchestrator::role::NodeRole)).
//! The two checks here are PURE PARSERS over the text the daemon prints
//! for `rustynet anchor list`:
//!
//! 1. [`validate_anchor_capabilities`] — assert the anchor's own row
//!    carries ALL required anchor capabilities.
//! 2. [`validate_anchor_gossip_seed`] — assert the primary anchor
//!    carries `anchor.gossip_seed` and at least one node advertises it.
//!
//! Neither parser needs a listener, an enrollment token, or a
//! membership-mutation: they only read the `anchor list` stdout + the
//! anchor's node-id. The runtime-dependent substages (bundle-pull
//! loopback, invalid-token, log-redaction, enrollment-endpoint) and the
//! mutation substages (gossip-priority, downgrade-revocation) from the
//! bin are NOT ported here — they require anchor bundle-pull /
//! enrollment runtime setup in the orchestrator install path and the
//! Windows membership-mutation backend, and are reported as explicit
//! skips by the owning stage rather than silently dropped.
//!
//! Security posture (per `CLAUDE.md` / `documents/SecurityMinimumBar.md`):
//!
//! * Argv-only: the single probe is a fixed argument vector with no
//!   untrusted interpolation. The POSIX backend wraps argv in `sudo -n`;
//!   the Windows backend forwards it via PowerShell `-EncodedCommand`.
//! * Read-only: `anchor list` only reads the daemon's membership view;
//!   nothing is mutated.
//! * Fail closed: a transport error or a non-zero `anchor list` exit is
//!   surfaced as `Err`, never a silent pass.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// Capabilities the daemon must advertise for an anchor node, exactly
/// mirroring the bin's `REQUIRED_ANCHOR_CAPS`. These are the six
/// composable anchor capabilities plus the `anchor` marker and the
/// `relay_host` capability anchors co-advertise. The set matches
/// [`NodeRole::Anchor`](crate::vm_lab::orchestrator::role::NodeRole)'s
/// product capabilities plus `relay_host` (anchors run as relay hosts).
const REQUIRED_ANCHOR_CAPS: &[&str] = &[
    "anchor",
    "relay_host",
    "anchor.gossip_seed",
    "anchor.bundle_pull",
    "anchor.enrollment_endpoint",
    "anchor.relay_colocation",
    "anchor.port_mapping_authoritative",
];

// ── Per-OS membership snapshot/log paths ──────────────────────────────
//
// `rustynet anchor list` reconstructs the anchor view from the on-disk
// signed membership snapshot + append log. The canonical per-OS paths
// match the orchestrator's install + daemon defaults:
//
//   * Linux:   /var/lib/rustynet/membership.{snapshot,log}
//              (rustynetd::daemon::DEFAULT_MEMBERSHIP_{SNAPSHOT,LOG}_PATH
//               on a non-Windows daemon build; pinned as literals here so
//               the path is host-build-independent — the build host may
//               be macOS, where those cfg-gated constants would resolve
//               to the macOS-build values).
//   * macOS:   /usr/local/var/rustynet/membership/membership.{snapshot,log}
//              (vm_lab::orchestrator::adapter::macos_install::
//               MACOS_MEMBERSHIP_SNAPSHOT_PATH and the sibling log path).
//   * Windows: C:\ProgramData\RustyNet\membership\membership.{snapshot,log}
//              (rustynetd::windows_paths::DEFAULT_WINDOWS_MEMBERSHIP_
//               {SNAPSHOT,LOG}_PATH).

const LINUX_MEMBERSHIP_SNAPSHOT_PATH: &str = "/var/lib/rustynet/membership.snapshot";
const LINUX_MEMBERSHIP_LOG_PATH: &str = "/var/lib/rustynet/membership.log";
const MACOS_MEMBERSHIP_SNAPSHOT_PATH: &str =
    "/usr/local/var/rustynet/membership/membership.snapshot";
const MACOS_MEMBERSHIP_LOG_PATH: &str = "/usr/local/var/rustynet/membership/membership.log";

/// Per-OS `(rustynet program, snapshot path, log path)` for the
/// `anchor list` probe. The Windows row references the reviewed
/// `rustynetd::windows_paths` constants so a canonical-layout rename
/// surfaces at compile time; Linux + macOS use module constants pinned
/// to the orchestrator install defaults (and host-build-independent).
fn anchor_list_invocation(
    platform: VmGuestPlatform,
) -> Result<(&'static str, String, String), String> {
    match platform {
        VmGuestPlatform::Linux => Ok((
            "rustynet",
            LINUX_MEMBERSHIP_SNAPSHOT_PATH.to_owned(),
            LINUX_MEMBERSHIP_LOG_PATH.to_owned(),
        )),
        VmGuestPlatform::Macos => Ok((
            "rustynet",
            MACOS_MEMBERSHIP_SNAPSHOT_PATH.to_owned(),
            MACOS_MEMBERSHIP_LOG_PATH.to_owned(),
        )),
        VmGuestPlatform::Windows => Ok((
            "rustynet.exe",
            rustynetd::windows_paths::DEFAULT_WINDOWS_MEMBERSHIP_SNAPSHOT_PATH.to_owned(),
            rustynetd::windows_paths::DEFAULT_WINDOWS_MEMBERSHIP_LOG_PATH.to_owned(),
        )),
        VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
            "anchor capability advertisement validation is only implemented for Linux, macOS, and Windows (got {platform:?})"
        )),
    }
}

/// Drive the anchor capability-advertisement proof for `platform`:
/// capture `rustynet anchor list` over the shell, then feed the output
/// to both pure parsers. Returns the gossip-seed summary string on
/// success.
///
/// Fail-closed contract: a transport error OR a non-zero `anchor list`
/// exit returns `Err` (never a silent pass — an unreadable membership
/// view must surface as a failure, not be treated as "no capabilities").
pub fn validate_anchor_capability_advertisement(
    shell: &dyn RemoteShellHost,
    platform: VmGuestPlatform,
    anchor_node_id: &str,
) -> Result<String, String> {
    let (program, snapshot, log) = anchor_list_invocation(platform)?;
    // Argv-only: a fixed argument vector. The POSIX backend wraps this in
    // `sudo -n`; the Windows backend forwards it via `-EncodedCommand`.
    // The only non-constant elements are the reviewed per-OS path
    // strings — never any untrusted value.
    let argv = [
        program,
        "anchor",
        "list",
        "--snapshot",
        snapshot.as_str(),
        "--log",
        log.as_str(),
    ];
    let status = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("anchor list run_argv failed: {err}"))?;
    if status.code != 0 {
        return Err(format!(
            "anchor list exited {} (stderr: {})",
            status.code,
            stderr_snippet(&status.stderr)
        ));
    }
    let anchor_list = String::from_utf8_lossy(&status.stdout).into_owned();

    validate_anchor_capabilities(&anchor_list, anchor_node_id)?;
    let gossip_summary = validate_anchor_gossip_seed(&anchor_list, anchor_node_id)?;
    Ok(gossip_summary)
}

/// First 200 bytes of a stderr blob, single-lined, for embedding in a
/// failure string without flooding the report.
fn stderr_snippet(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .chars()
        .take(200)
        .collect::<String>()
        .replace('\n', " ")
        .trim()
        .to_owned()
}

// ── Pure parsers (copied verbatim from `live_linux_anchor_test`) ──────

/// Assert the anchor's row in `rustynet anchor list` output carries ALL
/// required anchor capabilities. Copied verbatim from the bin's
/// `validate_anchor_capabilities`.
fn validate_anchor_capabilities(anchor_list: &str, anchor_node_id: &str) -> Result<(), String> {
    let row = anchor_list
        .lines()
        .find(|line| line.starts_with(anchor_node_id))
        .ok_or_else(|| format!("anchor node {anchor_node_id} missing from anchor list"))?;
    for capability in REQUIRED_ANCHOR_CAPS {
        // Word-boundary match — a substring check would accept a
        // hypothetical future cap like `anchor.gossip_seed_v2` and
        // hide a real drop of `anchor.gossip_seed`.
        if !row_has_capability(row, capability) {
            return Err(format!(
                "anchor capability {capability} missing for {anchor_node_id}: {row}"
            ));
        }
    }
    Ok(())
}

/// Dedicated gossip-seed advertisement check. Reads the `rustynet anchor
/// list` output that the running daemon derived from its in-memory
/// membership snapshot and asserts:
///   * the primary anchor carries `anchor.gossip_seed`
///   * at least one node total advertises `anchor.gossip_seed`
///
/// Copied from the bin's `validate_anchor_gossip_seed`; the only change
/// is the parameter — the bin took the whole `Config` but used only
/// `config.anchor_node_id`, so this takes that `anchor_node_id: &str`
/// directly.
///
/// The daemon hashes this same view into the runtime
/// `anchor_gossip_seed_peer_ids` set used by gossip re-broadcast
/// targeting, so an advertisement-side regression would also break
/// runtime targeting. The check is intentionally parser-only (no host
/// mutation) so it is cheap to run on every live-lab pass.
fn validate_anchor_gossip_seed(anchor_list: &str, anchor_node_id: &str) -> Result<String, String> {
    let seed_rows: Vec<&str> = anchor_list
        .lines()
        .filter(|line| row_has_capability(line, "anchor.gossip_seed"))
        .collect();
    if seed_rows.is_empty() {
        return Err(
            "no node in anchor list advertises anchor.gossip_seed — daemon membership view is missing the capability"
                .to_owned(),
        );
    }
    let primary_row = anchor_list
        .lines()
        .find(|line| line.starts_with(anchor_node_id))
        .ok_or_else(|| {
            format!("primary anchor {anchor_node_id} missing from anchor list while checking gossip_seed")
        })?;
    if !row_has_capability(primary_row, "anchor.gossip_seed") {
        return Err(format!(
            "primary anchor {anchor_node_id} is missing anchor.gossip_seed capability: {primary_row}"
        ));
    }
    let seed_node_ids: Vec<String> = seed_rows
        .iter()
        .filter_map(|line| line.split_once(' ').map(|(node_id, _)| node_id.to_owned()))
        .collect();
    Ok(format!(
        "primary={} seed_count={} seeds={}",
        anchor_node_id,
        seed_node_ids.len(),
        seed_node_ids.join(",")
    ))
}

/// Word-boundary capability match. The daemon emits anchor rows as
/// `<node_id> capabilities=<csv>` with CSV entries separated by `,`
/// (see `crates/rustynet-cli/src/main.rs::render_anchor_list`). A
/// naive `line.contains("anchor.gossip_seed")` would also match a
/// hypothetical future capability `anchor.gossip_seed_v2` and let a
/// drift pass silently. Anchor here on the explicit CSV separators
/// so a future capability rename surfaces as a test break instead.
fn row_has_capability(line: &str, capability: &str) -> bool {
    let Some((_, csv)) = line.split_once("capabilities=") else {
        return false;
    };
    // Strip a trailing newline / whitespace so the terminator
    // boundary check works for the last entry.
    let csv = csv.trim();
    csv.split(',').any(|entry| entry.trim() == capability)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    fn ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    // ── validate_anchor_capabilities (copied) ──

    #[test]
    fn validate_anchor_capabilities_requires_all_anchor_caps() {
        let output = "anchor nodes:\nexit-1 capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\n";
        validate_anchor_capabilities(output, "exit-1").expect("all caps present");
        let err = validate_anchor_capabilities(output, "missing").expect_err("missing node");
        assert!(err.contains("missing"));
    }

    #[test]
    fn validate_anchor_capabilities_rejects_partial_cap_set() {
        // A row missing one required capability must fail closed,
        // naming the absent capability.
        let output = "anchor nodes:\nexit-1 capabilities=anchor,relay_host,anchor.gossip_seed\n";
        let err =
            validate_anchor_capabilities(output, "exit-1").expect_err("partial caps must fail");
        assert!(err.contains("anchor.bundle_pull"), "got: {err}");
    }

    // ── validate_anchor_gossip_seed (copied; config param → node_id) ──

    #[test]
    fn validate_anchor_gossip_seed_accepts_primary_carrying_capability() {
        let anchor_list = "anchor nodes:\n\
                           exit-1 capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\n\
                           entry-2 capabilities=anchor,relay_host,anchor.gossip_seed\n";
        let summary = validate_anchor_gossip_seed(anchor_list, "exit-1").expect("must pass");
        assert!(
            summary.contains("seed_count=2"),
            "expected 2 seed nodes: {summary}"
        );
        assert!(summary.contains("primary=exit-1"));
        assert!(summary.contains("exit-1"));
        assert!(summary.contains("entry-2"));
    }

    #[test]
    fn validate_anchor_gossip_seed_rejects_when_no_node_carries_capability() {
        // A snapshot that has lost the anchor.gossip_seed capability
        // entirely must fail closed — gossip re-broadcast targeting
        // would otherwise silently degrade to no targeted seeds.
        let anchor_list = "anchor nodes:\n\
                           exit-1 capabilities=anchor,relay_host\n";
        let err = validate_anchor_gossip_seed(anchor_list, "exit-1").expect_err("must fail closed");
        assert!(
            err.contains("no node in anchor list advertises anchor.gossip_seed"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_anchor_gossip_seed_rejects_when_primary_missing_capability() {
        // The primary anchor must always carry gossip_seed. A
        // snapshot where a SECONDARY anchor carries it but the
        // primary does not is a configuration drift that must
        // surface as a failure rather than be silently accepted.
        let anchor_list = "anchor nodes:\n\
                           exit-1 capabilities=anchor,relay_host\n\
                           entry-2 capabilities=anchor,relay_host,anchor.gossip_seed\n";
        let err = validate_anchor_gossip_seed(anchor_list, "exit-1").expect_err("must fail closed");
        assert!(
            err.contains("primary anchor exit-1 is missing anchor.gossip_seed"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_anchor_gossip_seed_rejects_when_primary_absent_from_list() {
        let anchor_list = "anchor nodes:\n\
                           other-node capabilities=anchor,relay_host,anchor.gossip_seed\n";
        let err = validate_anchor_gossip_seed(anchor_list, "exit-1").expect_err("must fail closed");
        assert!(
            err.contains("primary anchor exit-1 missing from anchor list"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_anchor_gossip_seed_rejects_prefix_collision_capability() {
        // Concrete end-to-end regression — a node carrying only
        // anchor.gossip_seed_v2 must NOT satisfy the substage.
        let anchor_list = "anchor nodes:\n\
                           exit-1 capabilities=anchor,relay_host,anchor.gossip_seed_v2,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\n";
        let err = validate_anchor_gossip_seed(anchor_list, "exit-1")
            .expect_err("must fail closed on prefix-collision");
        assert!(
            err.contains("no node in anchor list advertises anchor.gossip_seed"),
            "got: {err}"
        );
    }

    // ── row_has_capability (copied) ──

    #[test]
    fn row_has_capability_matches_exact_csv_entry() {
        let row = "exit-1 capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull";
        assert!(row_has_capability(row, "anchor"));
        assert!(row_has_capability(row, "relay_host"));
        assert!(row_has_capability(row, "anchor.gossip_seed"));
        assert!(row_has_capability(row, "anchor.bundle_pull"));
    }

    #[test]
    fn row_has_capability_rejects_prefix_only_match() {
        // A future capability named `anchor.gossip_seed_v2` must NOT
        // satisfy a `anchor.gossip_seed` check — that would mask a
        // real loss of the original capability. Pre-fix the matcher
        // used `line.contains(capability)` which accepted this.
        let row = "exit-1 capabilities=anchor,relay_host,anchor.gossip_seed_v2";
        assert!(
            !row_has_capability(row, "anchor.gossip_seed"),
            "substring-only matcher would accept anchor.gossip_seed_v2"
        );
    }

    #[test]
    fn row_has_capability_rejects_suffix_only_match() {
        let row = "exit-1 capabilities=anchor,relay_host,extra.anchor.gossip_seed";
        assert!(
            !row_has_capability(row, "anchor.gossip_seed"),
            "substring-only matcher would accept extra.anchor.gossip_seed"
        );
    }

    #[test]
    fn row_has_capability_returns_false_when_capabilities_column_missing() {
        let row = "anchor nodes:";
        assert!(!row_has_capability(row, "anchor.gossip_seed"));
    }

    #[test]
    fn row_has_capability_handles_trailing_whitespace_after_csv() {
        let row = "exit-1 capabilities=anchor,anchor.gossip_seed\t\n";
        assert!(row_has_capability(row, "anchor.gossip_seed"));
    }

    // ── Per-OS invocation pins ──

    #[test]
    fn anchor_list_invocation_uses_per_os_paths_and_program() {
        let (prog, snap, log) = anchor_list_invocation(VmGuestPlatform::Linux).unwrap();
        assert_eq!(prog, "rustynet");
        assert_eq!(snap, "/var/lib/rustynet/membership.snapshot");
        assert_eq!(log, "/var/lib/rustynet/membership.log");

        let (prog, snap, log) = anchor_list_invocation(VmGuestPlatform::Macos).unwrap();
        assert_eq!(prog, "rustynet");
        assert_eq!(
            snap,
            "/usr/local/var/rustynet/membership/membership.snapshot"
        );
        assert_eq!(log, "/usr/local/var/rustynet/membership/membership.log");

        let (prog, snap, log) = anchor_list_invocation(VmGuestPlatform::Windows).unwrap();
        assert_eq!(prog, "rustynet.exe");
        assert_eq!(
            snap,
            rustynetd::windows_paths::DEFAULT_WINDOWS_MEMBERSHIP_SNAPSHOT_PATH
        );
        assert_eq!(
            log,
            rustynetd::windows_paths::DEFAULT_WINDOWS_MEMBERSHIP_LOG_PATH
        );

        assert!(anchor_list_invocation(VmGuestPlatform::Ios).is_err());
        assert!(anchor_list_invocation(VmGuestPlatform::Android).is_err());
    }

    // ── End-to-end advertisement check over the in-process mock shell ──

    /// Program the `anchor list` argv response for `platform` on `mock`.
    fn program_anchor_list(
        mock: &MockShellHost,
        platform: VmGuestPlatform,
        response: RemoteExitStatus,
    ) {
        let (prog, snap, log) = anchor_list_invocation(platform).unwrap();
        let argv = [
            prog,
            "anchor",
            "list",
            "--snapshot",
            snap.as_str(),
            "--log",
            log.as_str(),
        ];
        mock.program_run_response(&argv, response);
    }

    #[test]
    fn advertisement_passes_when_anchor_row_is_complete() {
        let mock = MockShellHost::new();
        let anchor_list = "anchor nodes:\n\
                           exit-1 capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\n";
        program_anchor_list(&mock, VmGuestPlatform::Linux, ok(anchor_list));
        let summary =
            validate_anchor_capability_advertisement(&mock, VmGuestPlatform::Linux, "exit-1")
                .expect("complete anchor row must pass");
        assert!(summary.contains("primary=exit-1"), "got: {summary}");
        assert!(summary.contains("seed_count=1"), "got: {summary}");
    }

    #[test]
    fn advertisement_fails_closed_on_nonzero_anchor_list_exit() {
        // A non-zero `anchor list` exit (e.g. unreadable membership
        // snapshot) must surface as a failure, not a silent pass.
        let mock = MockShellHost::new();
        program_anchor_list(
            &mock,
            VmGuestPlatform::Linux,
            RemoteExitStatus {
                code: 1,
                stdout: Vec::new(),
                stderr: b"membership snapshot unreadable".to_vec(),
            },
        );
        let err = validate_anchor_capability_advertisement(&mock, VmGuestPlatform::Linux, "exit-1")
            .expect_err("non-zero anchor list exit must fail closed");
        assert!(err.contains("anchor list exited 1"), "got: {err}");
        assert!(err.contains("membership snapshot unreadable"), "got: {err}");
    }

    #[test]
    fn advertisement_fails_closed_on_transport_error() {
        // No programmed response → the mock returns a Transport error;
        // the validator must surface it rather than swallow it.
        let mock = MockShellHost::new();
        let err = validate_anchor_capability_advertisement(&mock, VmGuestPlatform::Linux, "exit-1")
            .expect_err("transport error must fail closed");
        assert!(err.contains("anchor list run_argv failed"), "got: {err}");
    }

    #[test]
    fn advertisement_fails_when_required_capability_absent() {
        // Transport + exit are fine but the row is missing a required
        // capability → the parser must fail.
        let mock = MockShellHost::new();
        let anchor_list =
            "anchor nodes:\nexit-1 capabilities=anchor,relay_host,anchor.gossip_seed\n";
        program_anchor_list(&mock, VmGuestPlatform::Linux, ok(anchor_list));
        let err = validate_anchor_capability_advertisement(&mock, VmGuestPlatform::Linux, "exit-1")
            .expect_err("incomplete capability set must fail");
        assert!(err.contains("anchor.bundle_pull"), "got: {err}");
    }

    #[test]
    fn advertisement_fails_closed_on_mobile_platform() {
        let mock = MockShellHost::new();
        assert!(
            validate_anchor_capability_advertisement(&mock, VmGuestPlatform::Ios, "exit-1")
                .is_err()
        );
        assert!(
            validate_anchor_capability_advertisement(&mock, VmGuestPlatform::Android, "exit-1")
                .is_err()
        );
    }
}
