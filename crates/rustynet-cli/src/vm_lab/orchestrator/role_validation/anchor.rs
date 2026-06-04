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

use std::time::Duration;

use sha2::{Digest, Sha256};

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

// ── Runtime-dependent bundle-pull substages (cross-OS, gated) ─────────
//
// Ported from the formerly Linux-only `live_linux_anchor_test` bin's
// Phase-29 RemoteShellHost-driven substages. They prove the daemon's
// anchor bundle-pull listener actually serves the signed membership
// snapshot to an authorised token, rejects an unauthorised one, and
// (Linux) redacts the raw token from the journal. Every probe is an
// explicit RemoteShellHost call (read_file / tcp_send_recv / run_argv)
// with Rust-side parsing — no shell string is built from a non-constant
// value. The owning stage runs these only where
// `NodeRole::Anchor::is_supported_for_platform` holds (Linux today) and
// reported-skips macOS/Windows, since their bundle-pull token/listener
// provisioning is not yet wired (cross-OS Phase 8).

/// Linux anchor bundle-pull token path — seeded by `ops install-systemd`
/// for admin-role nodes (mirrors `ops_install_systemd`'s
/// `ANCHOR_BUNDLE_PULL_TOKEN_PATH`).
const LINUX_ANCHOR_BUNDLE_PULL_TOKEN_PATH: &str = "/var/lib/rustynet/anchor-bundle-pull.token";
/// macOS/Windows token paths: best-effort install-layout analogues. The
/// substages are gated to Linux until Phase 8 wires + evidences the
/// macOS/Windows bundle-pull token provisioning, so these are not yet
/// exercised on a live run.
const MACOS_ANCHOR_BUNDLE_PULL_TOKEN_PATH: &str =
    "/usr/local/var/rustynet/anchor-bundle-pull.token";
const WINDOWS_ANCHOR_BUNDLE_PULL_TOKEN_PATH: &str =
    "C:\\ProgramData\\RustyNet\\anchor-bundle-pull.token";
/// Loopback address the daemon binds its bundle-pull listener on (the
/// `RUSTYNET_ANCHOR_BUNDLE_PULL_ADDR` default in the unit template).
/// Loopback-only, identical on every OS.
const ANCHOR_BUNDLE_PULL_ADDR: &str = "127.0.0.1:51822";

/// Per-anchor runtime parameters for the bundle-pull substages, lifted
/// from the bin's `Config` but carrying only the orchestrator's per-OS
/// install-path defaults (the SSH transport is the `RemoteShellHost` the
/// stage already builds). The enrollment-endpoint substage is NOT driven
/// from here yet: it needs the membership owner signing key + passphrase
/// credential, which the orchestrator provisions only on the Exit
/// (membership owner), so it stays a reported-skip pending a trust-model
/// decision.
pub struct AnchorRuntimeParams {
    pub platform: VmGuestPlatform,
    pub anchor_bundle_pull_addr: String,
    pub anchor_token_path: String,
    pub membership_snapshot_path: String,
}

impl AnchorRuntimeParams {
    /// Build from the orchestrator's per-OS install-path defaults. The
    /// membership snapshot path reuses [`anchor_list_invocation`] so it
    /// stays in lock-step with the capability-advertisement probe.
    pub fn for_platform(platform: VmGuestPlatform) -> Result<Self, String> {
        let (_, snapshot, _log) = anchor_list_invocation(platform)?;
        let anchor_token_path = match platform {
            VmGuestPlatform::Linux => LINUX_ANCHOR_BUNDLE_PULL_TOKEN_PATH.to_owned(),
            VmGuestPlatform::Macos => MACOS_ANCHOR_BUNDLE_PULL_TOKEN_PATH.to_owned(),
            VmGuestPlatform::Windows => WINDOWS_ANCHOR_BUNDLE_PULL_TOKEN_PATH.to_owned(),
            VmGuestPlatform::Ios | VmGuestPlatform::Android => {
                return Err(format!(
                    "anchor runtime validation is only implemented for Linux, macOS, and Windows (got {platform:?})"
                ));
            }
        };
        Ok(Self {
            platform,
            anchor_bundle_pull_addr: ANCHOR_BUNDLE_PULL_ADDR.to_owned(),
            anchor_token_path,
            membership_snapshot_path: snapshot,
        })
    }
}

/// Prove the anchor bundle-pull listener returns the signed membership
/// snapshot byte-for-byte for an authorised token. Copied from the bin's
/// `validate_bundle_pull_loopback`, re-keyed onto `AnchorRuntimeParams`.
pub fn validate_bundle_pull_loopback(
    shell: &dyn RemoteShellHost,
    params: &AnchorRuntimeParams,
) -> Result<String, String> {
    let _ = parse_nc_addr(&params.anchor_bundle_pull_addr)?;
    let token = read_anchor_token(shell, params)?;
    let snapshot = shell
        .read_file(params.membership_snapshot_path.as_str())
        .map_err(|err| {
            format!(
                "anchor bundle-pull loopback: read snapshot {} failed: {err}",
                params.membership_snapshot_path
            )
        })?;
    let mut request = token.clone();
    request.push(b'\n');
    // Retry the TCP probe up to 3 times with a 2s sleep between attempts.
    // An empty response means the listener wasn't ready (port not yet
    // bound or daemon briefly between restart cycles) — not a hard failure.
    let max_attempts = 3u32;
    let sleep_secs = 2u64;
    let mut attempt = 0u32;
    let (header_vec, body_vec) = loop {
        attempt += 1;
        let response = shell
            .tcp_send_recv(
                &params.anchor_bundle_pull_addr,
                &request,
                Duration::from_secs(5),
            )
            .map_err(|err| format!("anchor bundle-pull loopback: tcp probe failed: {err}"))?;
        match split_bundle_pull_response(&response) {
            Ok((header, body)) => break (header.to_vec(), body.to_vec()),
            Err(err) => {
                if attempt >= max_attempts {
                    return Err(err);
                }
                std::thread::sleep(Duration::from_secs(sleep_secs));
            }
        }
    };
    if !header_vec.starts_with(b"OK ") {
        return Err(format!(
            "anchor bundle-pull loopback: unexpected header {:?}",
            String::from_utf8_lossy(&header_vec)
        ));
    }
    if body_vec != snapshot.as_slice() {
        return Err(format!(
            "anchor bundle-pull loopback: response body ({} bytes) does not match snapshot ({} bytes) byte-for-byte",
            body_vec.len(),
            snapshot.len()
        ));
    }
    let digest = sha256_hex(&snapshot);
    Ok(format!(
        "bundle_digest={digest} bundle_bytes={}",
        body_vec.len()
    ))
}

/// Prove the listener rejects a syntactically well-shaped but
/// unauthenticated token. Fixed 32-byte printable payload (deterministic,
/// no RNG). Copied from the bin's `validate_invalid_token_rejected`.
pub fn validate_invalid_token_rejected(
    shell: &dyn RemoteShellHost,
    params: &AnchorRuntimeParams,
) -> Result<String, String> {
    let _ = parse_nc_addr(&params.anchor_bundle_pull_addr)?;
    let payload: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n";
    let response = shell
        .tcp_send_recv(
            &params.anchor_bundle_pull_addr,
            payload,
            Duration::from_secs(5),
        )
        .map_err(|err| format!("invalid token rejection: tcp probe failed: {err}"))?;
    let header = first_line_bytes(&response);
    if header != b"ERR unauthorized" {
        return Err(format!(
            "invalid token was not rejected: header={:?}",
            String::from_utf8_lossy(header)
        ));
    }
    Ok("invalid_token_rejected=true".to_owned())
}

/// Linux-only assertion that the daemon's journal contains only the
/// token's SHA-256 thumbprint, never the raw token bytes. macOS/Windows
/// return a `log_redaction_check=skipped` summary (journalctl is
/// Linux-only; the per-OS log surface is a separate substage). Copied from
/// the bin's `validate_bundle_pull_log_redaction`.
pub fn validate_bundle_pull_log_redaction(
    shell: &dyn RemoteShellHost,
    params: &AnchorRuntimeParams,
) -> Result<String, String> {
    if params.platform != VmGuestPlatform::Linux {
        return Ok(format!(
            "log_redaction_check=skipped platform={:?} reason=journalctl-linux-only",
            params.platform
        ));
    }
    let token = read_anchor_token(shell, params)?;
    let thumbprint = anchor_token_thumbprint(&token);
    let token_str = std::str::from_utf8(&token)
        .map_err(|err| format!("anchor token bytes not utf-8: {err}"))?;
    let thumbprint_marker = format!("token_thumbprint={thumbprint}");
    // journald indexes entries asynchronously after the daemon writes
    // them; retry up to 3 times with a 1s sleep. Token-leak detection runs
    // on every attempt (no retry for leaks).
    let max_attempts: u8 = 3;
    for attempt in 1..=max_attempts {
        let logs = shell
            .run_argv(
                &[
                    "journalctl",
                    "-u",
                    "rustynetd",
                    "--since",
                    "10 minutes ago",
                    "--no-pager",
                ],
                &[],
                &[],
            )
            .map_err(|err| format!("journalctl run failed: {err}"))?;
        if !logs.is_success() {
            return Err(format!(
                "journalctl exited {}: {}",
                logs.code,
                String::from_utf8_lossy(&logs.stderr).trim()
            ));
        }
        let body = String::from_utf8_lossy(&logs.stdout);
        let filtered: Vec<&str> = body
            .lines()
            .filter(|line| line.contains("anchor_bundle_pull:"))
            .collect();
        if filtered.iter().any(|line| line.contains(token_str)) {
            return Err("anchor bundle-pull journal leaked raw token material".to_owned());
        }
        if filtered
            .iter()
            .any(|line| line.contains(&thumbprint_marker))
        {
            return Ok(format!(
                "token_thumbprint={thumbprint} raw_token_leaked=false"
            ));
        }
        if attempt < max_attempts {
            let _ = shell.run_argv(&["sleep", "1"], &[], &[]);
        }
    }
    Err(format!(
        "anchor bundle-pull journal missing token thumbprint {thumbprint}"
    ))
}

// ── Bundle-pull helpers (copied verbatim from `live_linux_anchor_test`) ─

/// Read + shape-validate the anchor bundle-pull token from disk
/// (printable ASCII, >= 32 bytes, trailing CR/LF stripped).
fn read_anchor_token(
    shell: &dyn RemoteShellHost,
    params: &AnchorRuntimeParams,
) -> Result<Vec<u8>, String> {
    let raw = shell
        .read_file(params.anchor_token_path.as_str())
        .map_err(|err| {
            format!(
                "read anchor token at {} failed: {err}",
                params.anchor_token_path
            )
        })?;
    let trimmed: Vec<u8> = raw
        .into_iter()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect();
    if trimmed.is_empty() {
        return Err("invalid token material shape: empty token".to_owned());
    }
    if !trimmed.iter().all(|b| matches!(b, 0x20..=0x7e)) {
        return Err("invalid token material shape: contains non-printable bytes".to_owned());
    }
    if trimmed.len() < 32 {
        return Err("invalid token material length".to_owned());
    }
    Ok(trimmed)
}

/// SHA-256 thumbprint (first 16 hex chars) of the anchor token — the
/// daemon emits this in its `anchor_bundle_pull:` journal lines.
fn anchor_token_thumbprint(token: &[u8]) -> String {
    let digest = sha256_hex(token);
    digest[..16].to_owned()
}

/// Hex-encode the SHA-256 digest of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Split a bundle-pull response into the header line and body bytes. The
/// server emits `OK <…>\n<bytes>` for success and `ERR <…>\n` for failure.
fn split_bundle_pull_response(response: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if response.is_empty() {
        return Err("bundle-pull response was empty".to_owned());
    }
    let header = first_line_bytes(response);
    let body = if response.len() > header.len() {
        let mut body_start = header.len();
        if body_start < response.len() && response[body_start] == b'\r' {
            body_start += 1;
        }
        if body_start < response.len() && response[body_start] == b'\n' {
            body_start += 1;
        }
        &response[body_start..]
    } else {
        &[][..]
    };
    Ok((header, body))
}

/// Bytes of the first line (excluding trailing `\r\n` / `\n`).
fn first_line_bytes(bytes: &[u8]) -> &[u8] {
    if let Some(idx) = bytes.iter().position(|b| *b == b'\n') {
        let end = if idx > 0 && bytes[idx - 1] == b'\r' {
            idx - 1
        } else {
            idx
        };
        &bytes[..end]
    } else {
        bytes
    }
}

/// host:port validation for the bundle-pull address. The fields are kept
/// for parity with the bin (and future use); the substages only need the
/// format check.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NcAddr {
    host: String,
    port: String,
}

fn parse_nc_addr(value: &str) -> Result<NcAddr, String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| "anchor-bundle-pull-addr must be host:port".to_owned())?;
    if host.is_empty()
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err("anchor-bundle-pull-addr must be host:port".to_owned());
    }
    Ok(NcAddr {
        host: host.to_owned(),
        port: port.to_owned(),
    })
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

    // ── Bundle-pull substage + helper coverage (Phase 29 port) ──

    fn linux_params() -> AnchorRuntimeParams {
        AnchorRuntimeParams::for_platform(VmGuestPlatform::Linux).unwrap()
    }

    #[test]
    fn parse_nc_addr_accepts_host_port_and_rejects_malformed() {
        assert!(parse_nc_addr("127.0.0.1:51822").is_ok());
        assert!(parse_nc_addr("anchor-host.local:4500").is_ok());
        assert!(parse_nc_addr("no-port").is_err());
        assert!(parse_nc_addr("127.0.0.1:").is_err());
        assert!(parse_nc_addr(":51822").is_err());
        assert!(parse_nc_addr("127.0.0.1:port").is_err());
    }

    #[test]
    fn split_bundle_pull_response_separates_header_body_and_crlf() {
        let mut resp = b"OK 5\n".to_vec();
        resp.extend_from_slice(b"hello");
        let (header, body) = split_bundle_pull_response(&resp).unwrap();
        assert_eq!(header, b"OK 5");
        assert_eq!(body, b"hello");

        let mut crlf = b"OK 3\r\n".to_vec();
        crlf.extend_from_slice(b"abc");
        let (header, body) = split_bundle_pull_response(&crlf).unwrap();
        assert_eq!(header, b"OK 3");
        assert_eq!(body, b"abc");

        assert!(split_bundle_pull_response(b"").is_err());
    }

    #[test]
    fn first_line_bytes_strips_terminators() {
        assert_eq!(first_line_bytes(b"ERR unauthorized\n"), b"ERR unauthorized");
        assert_eq!(
            first_line_bytes(b"ERR unauthorized\r\n"),
            b"ERR unauthorized"
        );
        assert_eq!(first_line_bytes(b"no-newline"), b"no-newline");
    }

    #[test]
    fn sha256_hex_and_thumbprint_match_known_vector() {
        // SHA-256("") known digest.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let tp = anchor_token_thumbprint(b"");
        assert_eq!(tp, "e3b0c44298fc1c14");
        assert_eq!(tp.len(), 16);
    }

    #[test]
    fn for_platform_uses_per_os_token_paths() {
        assert_eq!(
            linux_params().anchor_token_path,
            "/var/lib/rustynet/anchor-bundle-pull.token"
        );
        assert_eq!(linux_params().anchor_bundle_pull_addr, "127.0.0.1:51822");
        assert_eq!(
            AnchorRuntimeParams::for_platform(VmGuestPlatform::Macos)
                .unwrap()
                .anchor_token_path,
            "/usr/local/var/rustynet/anchor-bundle-pull.token"
        );
        assert!(AnchorRuntimeParams::for_platform(VmGuestPlatform::Ios).is_err());
    }

    #[test]
    fn read_anchor_token_validates_shape() {
        let params = linux_params();
        let mock = MockShellHost::new();
        mock.write_file(&params.anchor_token_path, &[b'a'; 64], 0o600)
            .unwrap();
        assert_eq!(read_anchor_token(&mock, &params).unwrap().len(), 64);

        // Too short → fail closed.
        let short = MockShellHost::new();
        short
            .write_file(&params.anchor_token_path, b"short", 0o600)
            .unwrap();
        assert!(
            read_anchor_token(&short, &params)
                .unwrap_err()
                .contains("length")
        );

        // Non-printable → fail closed.
        let binv = MockShellHost::new();
        binv.write_file(&params.anchor_token_path, &[0u8; 64], 0o600)
            .unwrap();
        assert!(
            read_anchor_token(&binv, &params)
                .unwrap_err()
                .contains("non-printable")
        );
    }

    #[test]
    fn validate_bundle_pull_loopback_passes_when_body_matches_snapshot() {
        let params = linux_params();
        let mock = MockShellHost::new();
        mock.write_file(&params.anchor_token_path, &[b'a'; 64], 0o600)
            .unwrap();
        let snapshot = b"signed-membership-snapshot-bytes";
        mock.write_file(&params.membership_snapshot_path, snapshot, 0o600)
            .unwrap();
        let mut resp = b"OK 32\n".to_vec();
        resp.extend_from_slice(snapshot);
        mock.program_tcp_response(&params.anchor_bundle_pull_addr, resp);
        let summary = validate_bundle_pull_loopback(&mock, &params).expect("loopback must pass");
        assert!(summary.contains("bundle_digest="), "got: {summary}");
        assert!(
            summary.contains(&format!("bundle_bytes={}", snapshot.len())),
            "got: {summary}"
        );
    }

    #[test]
    fn validate_bundle_pull_loopback_fails_when_body_mismatches_snapshot() {
        let params = linux_params();
        let mock = MockShellHost::new();
        mock.write_file(&params.anchor_token_path, &[b'a'; 64], 0o600)
            .unwrap();
        mock.write_file(&params.membership_snapshot_path, b"real-snapshot", 0o600)
            .unwrap();
        let mut resp = b"OK 5\n".to_vec();
        resp.extend_from_slice(b"WRONG");
        mock.program_tcp_response(&params.anchor_bundle_pull_addr, resp);
        let err =
            validate_bundle_pull_loopback(&mock, &params).expect_err("body mismatch must fail");
        assert!(err.contains("does not match snapshot"), "got: {err}");
    }

    #[test]
    fn validate_invalid_token_rejected_passes_on_err_unauthorized() {
        let params = linux_params();
        let mock = MockShellHost::new();
        mock.program_tcp_response(
            &params.anchor_bundle_pull_addr,
            b"ERR unauthorized\n".to_vec(),
        );
        assert!(validate_invalid_token_rejected(&mock, &params).is_ok());
    }

    #[test]
    fn validate_invalid_token_rejected_fails_when_listener_accepts() {
        // A listener that returns OK for the fixed fake token must fail closed.
        let params = linux_params();
        let mock = MockShellHost::new();
        mock.program_tcp_response(&params.anchor_bundle_pull_addr, b"OK 0\n".to_vec());
        let err = validate_invalid_token_rejected(&mock, &params)
            .expect_err("listener accepting a bad token must fail");
        assert!(err.contains("not rejected"), "got: {err}");
    }

    #[test]
    fn log_redaction_skips_on_non_linux() {
        let params = AnchorRuntimeParams::for_platform(VmGuestPlatform::Macos).unwrap();
        let mock = MockShellHost::new();
        let summary = validate_bundle_pull_log_redaction(&mock, &params).unwrap();
        assert!(summary.contains("skipped"), "got: {summary}");
        assert!(summary.contains("journalctl-linux-only"), "got: {summary}");
    }

    #[test]
    fn log_redaction_passes_when_journal_carries_thumbprint_only() {
        let params = linux_params();
        let mock = MockShellHost::new();
        let token = [b'a'; 64];
        mock.write_file(&params.anchor_token_path, &token, 0o600)
            .unwrap();
        let thumbprint = anchor_token_thumbprint(&token);
        let journal =
            format!("Jun 04 anchor_bundle_pull: served bundle token_thumbprint={thumbprint}\n");
        mock.program_run_response(
            &[
                "journalctl",
                "-u",
                "rustynetd",
                "--since",
                "10 minutes ago",
                "--no-pager",
            ],
            ok(&journal),
        );
        let summary = validate_bundle_pull_log_redaction(&mock, &params).expect("must pass");
        assert!(summary.contains("raw_token_leaked=false"), "got: {summary}");
    }

    #[test]
    fn log_redaction_fails_when_journal_leaks_raw_token() {
        let params = linux_params();
        let mock = MockShellHost::new();
        let token = [b'a'; 64];
        mock.write_file(&params.anchor_token_path, &token, 0o600)
            .unwrap();
        let token_str = std::str::from_utf8(&token).unwrap();
        let journal = format!("Jun 04 anchor_bundle_pull: raw token {token_str} served\n");
        mock.program_run_response(
            &[
                "journalctl",
                "-u",
                "rustynetd",
                "--since",
                "10 minutes ago",
                "--no-pager",
            ],
            ok(&journal),
        );
        let err = validate_bundle_pull_log_redaction(&mock, &params)
            .expect_err("raw token leak must fail");
        assert!(err.contains("leaked raw token"), "got: {err}");
    }
}
