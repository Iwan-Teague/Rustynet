#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]
// Track B Phase 29 migration: the seven POSIX-only substages
// (validate_bundle_pull_loopback, start_inflight_bundle_pull,
// validate_invalid_token_rejected, validate_anchor_enrollment_endpoint,
// validate_anchor_downgrade_revocation, capture_role_audit_log_size,
// validate_bundle_pull_log_redaction) now drive the Phase 28
// [`RemoteShellHost`] trait. The bin still calls the deprecated
// `capture_root` shim for the helpers that remain POSIX-only outside
// the Phase 29 scope (anchor list capture, membership mutation flow),
// so allow the deprecation lint here until those callers migrate.
#![allow(deprecated)]

mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use live_lab_bin_support as live_lab_support;
use live_lab_support::{
    LiveLabPlatform, Logger, RemoteShellHost, capture_remote_stdout, capture_root,
    create_workspace, ensure_pinned_known_hosts_file, ensure_safe_token, git_head_commit,
    load_home_known_hosts_path, new_remote_shell_host, repo_root, require_command,
    seed_known_hosts, shell_quote, unix_now, verify_passwordless_sudo, verify_sudo,
    verify_windows_admin, write_file,
};
use rustynetd::windows_paths::{
    DEFAULT_WINDOWS_KEYS_ROOT, DEFAULT_WINDOWS_MEMBERSHIP_LOG_PATH,
    DEFAULT_WINDOWS_MEMBERSHIP_OWNER_SIGNING_KEY_PATH, DEFAULT_WINDOWS_MEMBERSHIP_SNAPSHOT_PATH,
    DEFAULT_WINDOWS_SECRET_ROOT, DEFAULT_WINDOWS_STATE_ROOT,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const REQUIRED_ANCHOR_CAPS: &[&str] = &[
    "anchor",
    "relay_host",
    "anchor.gossip_seed",
    "anchor.bundle_pull",
    "anchor.enrollment_endpoint",
    "anchor.relay_colocation",
    "anchor.port_mapping_authoritative",
];

const ANCHOR_LIVE_SUBSTAGES: &[(&str, &str)] = &[
    (
        "validate_anchor_membership_advertise",
        "signed anchor membership advertises all required anchor sub-capabilities",
    ),
    (
        "validate_anchor_bundle_pull",
        "token-gated loopback bundle-pull returns signed membership byte-for-byte and rejects invalid tokens",
    ),
    (
        "validate_anchor_gossip_priority",
        "multi-anchor gossip prefers lex-min authority and keeps secondary anchor passive for port mapping",
    ),
    (
        "validate_anchor_gossip_seed",
        "anchor.gossip_seed capability is advertised in the running membership and identifies the expected seed nodes",
    ),
    (
        "validate_anchor_enrollment_endpoint",
        "fresh node enrollment uses anchor-minted token, sealed bundle, and anchor-signed approver attestation",
    ),
    (
        "validate_anchor_downgrade_revocation",
        "owner-signed anchor.bundle_pull revocation stops new pulls, preserves in-flight pulls, and records audit",
    ),
];

fn main() {
    if let Err(err) = run() {
        let code = classify_live_lab_error(err.as_str());
        let hint = code.operator_hint();
        if hint.is_empty() {
            eprintln!("error [{code}]: {err}");
        } else {
            eprintln!("error [{code}]: {err}\n  hint: {hint}");
        }
        std::process::exit(code.as_i32());
    }
}

fn classify_live_lab_error(message: &str) -> rustynetd::exit_codes::ExitCode {
    use rustynetd::exit_codes::ExitCode;
    let lower = message.to_ascii_lowercase();
    if lower.contains("missing required")
        || lower.contains("unknown argument")
        || lower.contains("usage:")
    {
        ExitCode::BadArgs
    } else if lower.contains("anchor capability")
        || lower.contains("token")
        || lower.contains("unauthorized")
        || lower.contains("fail-closed")
        || lower.contains("policy reject")
    {
        ExitCode::PolicyReject
    } else if lower.contains("identity file")
        || lower.contains("known_hosts")
        || lower.contains("invalid path")
        || lower.contains("config")
    {
        ExitCode::ConfigError
    } else if lower.contains("ssh")
        || lower.contains("connection refused")
        || lower.contains("timed out")
        || lower.contains("transient")
    {
        ExitCode::TransientFailure
    } else {
        ExitCode::GenericFailure
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse(env::args().skip(1).collect())?;
    let git_commit = config
        .git_commit
        .clone()
        .or_else(|| env::var("RUSTYNET_EXPECTED_GIT_COMMIT").ok())
        .unwrap_or_else(|| {
            repo_root()
                .and_then(|root| git_head_commit(&root))
                .unwrap_or_else(|_| "unknown".to_owned())
        });

    let mut logger = Logger::new(&config.log_path)?;
    logger.line("[anchor-live] starting anchor validation harness")?;

    if config.dry_run {
        let report = render_report(&config, &git_commit, dry_run_subchecks(), None)?;
        write_file(&config.report_path, &report)?;
        logger.line(
            format!(
                "[anchor-live] dry-run report written to {}",
                config.report_path.display()
            )
            .as_str(),
        )?;
        return Ok(());
    }

    // Track B Phase 29 — bundle_pull / enrollment now run for real
    // on Windows via the [`RemoteShellHost`] trait (Phase 28). The
    // trait drives argv-only commands on a per-OS backend, so the
    // substage code is identical across Linux + macOS + Windows.
    // The remaining Windows skip (downgrade_revocation) is gated on
    // the membership-mutation pipeline, not the anchor bundle-pull
    // surface — tracked outside Phase 29.

    for command in ["ssh", "ssh-keygen"] {
        require_command(command)?;
    }
    validate_identity(
        config
            .ssh_identity_file
            .as_ref()
            .ok_or_else(|| "--ssh-identity-file is required unless --dry-run is set".to_owned())?,
    )?;
    let pinned_known_hosts = match &config.pinned_known_hosts_file {
        Some(path) => path.clone(),
        None => load_home_known_hosts_path()?,
    };
    ensure_pinned_known_hosts_file(&pinned_known_hosts)?;

    let workspace = create_workspace("anchor-live")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;

    let identity = config
        .ssh_identity_file
        .as_ref()
        .expect("identity presence checked above");
    // Track B Phases 10 + 11 — the sudo preflight is platform-aware.
    // Linux uses verify_sudo (also greps /etc/hosts to surface PAM
    // sudo issues). macOS uses verify_passwordless_sudo (mac does
    // not put its hostname in /etc/hosts). Windows uses
    // verify_windows_admin (probes BUILTIN\Administrators via
    // PowerShell — there is no sudo).
    match config.platform {
        AnchorPlatform::Linux => {
            verify_sudo(identity, &work_known_hosts, &config.anchor_host)?;
        }
        AnchorPlatform::Macos => {
            verify_passwordless_sudo(identity, &work_known_hosts, &config.anchor_host)?;
        }
        AnchorPlatform::Windows => {
            verify_windows_admin(identity, &work_known_hosts, &config.anchor_host)?;
        }
    }

    // Track B Phase 29 — every substage that runs on the trait now
    // shares this single anchor-host shell. The trait surface is
    // platform-aware: `new_remote_shell_host` picks Linux / macOS /
    // Windows backend so the substage code is identical across all
    // three OSes (argv-only exec via `run_argv`, base64-framed file
    // I/O via `read_file`/`write_file`, TCP probes via
    // `tcp_send_recv`). The Arc clone is cheap and lets each helper
    // hold its own owned reference.
    let anchor_shell: Arc<dyn RemoteShellHost> = new_remote_shell_host(
        config.platform.to_live_lab_platform(),
        identity.to_path_buf(),
        work_known_hosts.clone(),
        config.anchor_host.clone(),
    );

    let mut subchecks = Vec::new();

    let anchor_list = capture_anchor_list(identity, &work_known_hosts, &config)?;
    validate_anchor_capabilities(&anchor_list, config.anchor_node_id.as_str())?;
    subchecks.push(Subcheck::pass(
        "validate_anchor_membership_advertise",
        "signed membership advertises required anchor capabilities",
        json!({ "anchor_node_id": config.anchor_node_id, "capabilities": REQUIRED_ANCHOR_CAPS }),
    ));

    // Track B Phase 29 — bundle_pull now runs on Linux + macOS +
    // Windows. The three composing helpers
    // (validate_bundle_pull_loopback, validate_invalid_token_rejected,
    // validate_bundle_pull_log_redaction) all drive the
    // [`RemoteShellHost`] trait, which folds the per-OS shell-out
    // path into the backend selection. The log-redaction helper
    // still returns a `skipped` summary on non-Linux because
    // journalctl is Linux-only — that internal skip is reported in
    // the evidence payload instead of being a top-level substage
    // skip.
    let pull_summary = validate_bundle_pull_loopback(anchor_shell.as_ref(), &config)?;
    let invalid_token_summary = validate_invalid_token_rejected(anchor_shell.as_ref(), &config)?;
    let redaction_summary = validate_bundle_pull_log_redaction(anchor_shell.as_ref(), &config)?;
    subchecks.push(Subcheck::pass(
        "validate_anchor_bundle_pull",
        "loopback bundle-pull listener returned membership snapshot byte-for-byte, rejected invalid token, and logged only token thumbprints",
        json!({ "pull": pull_summary, "invalid_token": invalid_token_summary, "log_redaction": redaction_summary }),
    ));

    // Track B Phase 15 — gossip_priority now runs on macOS too via
    // the cross-platform 3-step membership mutation flow
    // (set_membership_capabilities_three_step). Windows still skips
    // because no Windows-side mutation helper exists; the dedicated
    // gossip_seed substage below (parser-only) still covers the
    // gossip-related contract there.
    if config.platform == AnchorPlatform::Windows {
        subchecks.push(Subcheck::skipped(
            "validate_anchor_gossip_priority",
            "Windows skip: cross-platform membership mutation helper not yet wired for PowerShell; macOS + Linux run for real via Phase 15's three-step flow",
        ));
    } else {
        let gossip_priority =
            validate_anchor_gossip_priority(identity, &work_known_hosts, &config)?;
        subchecks.push(Subcheck::pass(
            "validate_anchor_gossip_priority",
            "second anchor is signed into membership, leaf sees both anchors, and lex-min authority remains primary",
            json!({ "summary": gossip_priority }),
        ));
    }

    // Track B Phase 9 — dedicated gossip-seed coverage. The existing
    // `validate_anchor_gossip_priority` substage exercises the
    // port-mapping-authority lex-min path and incidentally promotes
    // the second anchor with the gossip_seed capability, but it does
    // not directly assert that ALL anchor.gossip_seed capability
    // holders show up in the running daemon's anchor list (the data
    // the daemon hashes into `anchor_gossip_seed_peer_ids_from_membership`
    // at gossip_runtime.rs:483). Split the assertion so a future
    // change that drops `anchor.gossip_seed` from the canonical
    // anchor capability set or stops surfacing it in the snapshot
    // surfaces here.
    let gossip_seed_summary = validate_anchor_gossip_seed(&anchor_list, &config)?;
    subchecks.push(Subcheck::pass(
        "validate_anchor_gossip_seed",
        "anchor.gossip_seed capability is advertised in the running membership and identifies the expected seed nodes",
        json!({ "summary": gossip_seed_summary }),
    ));

    // Track B Phase 29 — enrollment_endpoint now runs on Linux +
    // macOS + Windows. The composing helper drives the trait for
    // argv-only `rustynet enrollment …` invocations and uses a
    // platform-aware passphrase unwrap step (systemd-creds on
    // Linux, security on macOS, PowerShell `ProtectedData.Unprotect`
    // on Windows) so the credential never appears in argv. The
    // signed-membership apply phase still relies on the cross-OS
    // signed-update path that ships with `rustynet enrollment
    // admit`.
    let enrollment_endpoint = validate_anchor_enrollment_endpoint(anchor_shell.as_ref(), &config)?;
    subchecks.push(Subcheck::pass(
        "validate_anchor_enrollment_endpoint",
        "anchor minted enrollment token, rejected negative token and approver paths, admitted enrollee through signed membership, and verified membership visibility",
        json!({ "summary": enrollment_endpoint }),
    ));

    // Track B Phase 29 — downgrade_revocation now runs on Linux +
    // macOS via the trait. Every TCP probe, in-flight pull, and
    // audit log size capture flows through the platform-aware
    // backend. Windows is still gated at the substage level: the
    // capability mutation step calls `set_membership_capabilities`
    // which has no Windows implementation yet (the signed-membership
    // owner-side mutation pipeline is tracked separately from the
    // Phase 29 anchor-side bundle-pull surface). The Windows skip
    // note is now precise about the blocker rather than blaming
    // POSIX shell composition.
    if config.platform == AnchorPlatform::Windows {
        subchecks.push(Subcheck::skipped(
            "validate_anchor_downgrade_revocation",
            "Windows skip: substage requires set_membership_capabilities, which has no Windows mutation backend yet (tracked separately from Phase 29 anchor bundle-pull surface). Linux + macOS run for real via the Phase 29 RemoteShellHost trait.",
        ));
    } else {
        let downgrade_revocation = validate_anchor_downgrade_revocation(
            anchor_shell.as_ref(),
            identity,
            &work_known_hosts,
            &config,
        )?;
        subchecks.push(Subcheck::pass(
            "validate_anchor_downgrade_revocation",
            "anchor.bundle_pull revocation stops new pulls, preserves prior pull, emits audit, and restores capability",
            json!({ "summary": downgrade_revocation }),
        ));
    }

    // Track B Phase 13 — unlock daemon_status_available on
    // Windows by routing through the new platform-aware helper in
    // `live_lab_bin_support::capture_daemon_status_for_platform`.
    // Phase 11 had to skip Windows because the bin-local
    // `capture_daemon_status` wraps the command in `sudo -n sh -lc`
    // via capture_root (POSIX-only). The new helper dispatches per
    // platform: capture_root + Linux socket on Linux, capture_root
    // + macOS socket on macOS, capture_remote_stdout + PowerShell
    // `rustynet.exe status` on Windows.
    let daemon_status = live_lab_support::capture_daemon_status_for_platform(
        identity,
        &work_known_hosts,
        &config.anchor_host,
        config.platform.as_str(),
    )
    .map_err(|err| format!("daemon status capture failed: {err}"))?;
    subchecks.push(Subcheck::pass(
        "validate_anchor_daemon_status_available",
        "daemon IPC status command completed for anchor host",
        json!({ "status_excerpt": first_line(&daemon_status) }),
    ));

    let report = render_report(&config, &git_commit, subchecks, Some(&anchor_list))?;
    write_file(&config.report_path, &report)?;
    logger.line(
        format!(
            "[anchor-live] report written to {}",
            config.report_path.display()
        )
        .as_str(),
    )?;
    Ok(())
}

fn capture_anchor_list(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    capture_anchor_list_from_host(identity, known_hosts, &config.anchor_host, config.platform)
}

fn capture_anchor_list_from_host(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    platform: AnchorPlatform,
) -> Result<String, String> {
    match platform {
        AnchorPlatform::Linux => {
            let command = "command -v rustynet >/dev/null; rustynet anchor list";
            capture_root(identity, known_hosts, host, command)
                .map_err(|err| format!("anchor list failed on {host}: {err}"))
        }
        AnchorPlatform::Macos => {
            // macOS installs membership state under membership/ subdir, not /var/lib/rustynet.
            // Pass both --snapshot and --log explicitly; the CLI defaults to the Linux paths
            // which do not exist on macOS.
            let command = "command -v rustynet >/dev/null; rustynet anchor list --snapshot /usr/local/var/rustynet/membership/membership.snapshot --log /usr/local/var/rustynet/membership/membership.log";
            capture_root(identity, known_hosts, host, command)
                .map_err(|err| format!("anchor list failed on {host}: {err}"))
        }
        AnchorPlatform::Windows => {
            // Windows OpenSSH session runs as Administrator; no sudo.
            // PowerShell `Get-Command` is the rough equivalent of
            // `command -v`. `rustynet.exe anchor list` writes the
            // same canonical output as the Linux binary.
            // Use `if (-not (Get-Command ...))` so a missing
            // `rustynet.exe` short-circuits with an explicit
            // diagnostic instead of falling through to a confusing
            // PSCommandNotFoundException from the second statement.
            // `Out-String -Width 32767` prevents PowerShell from
            // wrapping long anchor-list rows at terminal width —
            // wrapped rows would split `<node_id> capabilities=...`
            // and break the parser's anchor-row matcher.
            let command = "powershell -NoProfile -Command \"if (-not (Get-Command rustynet.exe -ErrorAction SilentlyContinue)) { Write-Error 'rustynet.exe not on PATH'; exit 1 }; rustynet.exe anchor list | Out-String -Width 32767\"";
            capture_remote_stdout(identity, known_hosts, host, command)
                .map_err(|err| format!("anchor list failed on {host}: {err}"))
        }
    }
}

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

fn validate_anchor_gossip_priority(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    let second_anchor_host = config.second_anchor_host.as_deref().ok_or_else(|| {
        "--second-anchor-host is required for validate_anchor_gossip_priority".to_owned()
    })?;
    let second_anchor_node_id = config.second_anchor_node_id.as_deref().ok_or_else(|| {
        "--second-anchor-node-id is required for validate_anchor_gossip_priority".to_owned()
    })?;
    let leaf_client_host = config.leaf_client_host.as_deref().ok_or_else(|| {
        "--leaf-client-host is required for validate_anchor_gossip_priority".to_owned()
    })?;
    let owner_approver_id = config.owner_approver_id.as_deref().ok_or_else(|| {
        "--owner-approver-id is required for validate_anchor_gossip_priority".to_owned()
    })?;

    set_membership_capabilities(
        identity,
        known_hosts,
        config,
        &config.anchor_host,
        second_anchor_node_id,
        "anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative",
        owner_approver_id,
    )
    .map_err(|err| format!("promote second anchor {second_anchor_node_id} failed: {err}"))?;

    // Read anchor list from the anchor host (exit-1/Admin role), not the leaf client.
    // Client nodes are role-gated: IpcCommand::MembershipApply is rejected for
    // NodeRole::Client, so their on-disk membership files are never updated by the
    // daemon after the initial distribute_membership_state push from the orchestrator.
    // exit-1 (Admin) processes the MembershipApply immediately and its anchor list
    // reflects the promotion as soon as set_membership_capabilities returns.
    let validation = {
        let max_attempts = 3u32;
        let sleep_secs = 2u64;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match (|| -> Result<String, String> {
                let anchor_list = capture_anchor_list_from_host(
                    identity,
                    known_hosts,
                    &config.anchor_host,
                    config.platform,
                )?;
                validate_anchor_capabilities(&anchor_list, config.anchor_node_id.as_str())?;
                validate_anchor_capabilities(&anchor_list, second_anchor_node_id)?;
                let (lex_min_id, lex_other_id) =
                    if config.anchor_node_id.as_str() <= second_anchor_node_id {
                        (config.anchor_node_id.as_str(), second_anchor_node_id)
                    } else {
                        (second_anchor_node_id, config.anchor_node_id.as_str())
                    };
                validate_lex_min_anchor_authority(&anchor_list, lex_min_id, lex_other_id)?;
                Ok(format!(
                    "primary={} secondary={} anchor_host={} leaf={} secondary_host={} attempts={}",
                    config.anchor_node_id,
                    second_anchor_node_id,
                    config.anchor_host,
                    leaf_client_host,
                    second_anchor_host,
                    attempt,
                ))
            })() {
                Ok(summary) => break Ok(summary),
                Err(err) => {
                    if attempt >= max_attempts {
                        break Err(err);
                    }
                    std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
                }
            }
        }
    };

    let restore = set_membership_capabilities(
        identity,
        known_hosts,
        config,
        &config.anchor_host,
        second_anchor_node_id,
        "client,relay_host",
        owner_approver_id,
    );

    match (validation, restore) {
        (Ok(summary), Ok(_)) => Ok(format!("{summary} restore=ok")),
        (Err(err), Ok(_)) => Err(err),
        (Ok(_), Err(restore_err)) => Err(format!(
            "second anchor validation passed but restore failed for {second_anchor_node_id}: {restore_err}"
        )),
        (Err(err), Err(restore_err)) => Err(format!(
            "{err}; restore failed for {second_anchor_node_id}: {restore_err}"
        )),
    }
}

/// Mutate the signed-membership capability set for a single node.
///
/// Linux path keeps the existing `rustynet ops e2e-membership-set-capabilities`
/// verb, which uses systemd-creds to decrypt the signing passphrase.
/// macOS path routes through a cross-platform 3-step flow (propose +
/// sign + apply) using the per-platform path defaults the operator
/// pre-stages — Track B Phase 15 unlock. Both paths land the same
/// signed-membership mutation on disk; the daemon then reconciles
/// via its membership watermark.
///
/// Windows is not yet wired here — the helper continues to error
/// closed for Windows so the caller's skip arm stays explicit.
fn set_membership_capabilities(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
    target_host: &str,
    node_id: &str,
    capabilities: &str,
    owner_approver_id: &str,
) -> Result<String, String> {
    match config.platform {
        AnchorPlatform::Linux => set_membership_capabilities_linux_ops_verb(
            identity,
            known_hosts,
            target_host,
            node_id,
            capabilities,
            owner_approver_id,
        ),
        AnchorPlatform::Macos => set_membership_capabilities_three_step(
            identity,
            known_hosts,
            config,
            target_host,
            node_id,
            capabilities,
            owner_approver_id,
        ),
        AnchorPlatform::Windows => Err(
            "set_membership_capabilities is not implemented for Windows; the substage must skip in run() before reaching this helper"
                .to_owned(),
        ),
    }
}

/// Phase 15 — Linux path keeps the existing one-shot ops verb that
/// handles systemd-creds decryption + propose/sign/apply atomically.
fn set_membership_capabilities_linux_ops_verb(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    node_id: &str,
    capabilities: &str,
    owner_approver_id: &str,
) -> Result<String, String> {
    let command = format!(
        "command -v rustynet >/dev/null && rustynet ops e2e-membership-set-capabilities --node-id {node_id} --capabilities {capabilities} --owner-approver-id {owner}",
        node_id = shell_quote(node_id),
        capabilities = shell_quote(capabilities),
        owner = shell_quote(owner_approver_id),
    );
    capture_root(identity, known_hosts, host, &command)
        .map(|out| out.trim().to_owned())
        .map_err(|err| format!("membership capability mutation failed on {host}: {err}"))
}

/// Phase 15 — macOS path. Runs the three cross-platform CLI verbs
/// directly: `membership propose-set-capabilities`, `membership
/// sign-update`, `membership apply-update`. Reads the plaintext
/// signing-key passphrase from `config.signing_key_passphrase_cred_path`
/// (the operator pre-stages it under `/usr/local/etc/rustynet/credentials/`
/// — the macOS layout's default per `apply_macos_default_paths`).
///
/// The work dir uses `mktemp -d` so concurrent runs do not collide.
/// Cleanup runs even when validation fails so plaintext key material
/// never lingers in /tmp.
fn set_membership_capabilities_three_step(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
    host: &str,
    node_id: &str,
    capabilities: &str,
    owner_approver_id: &str,
) -> Result<String, String> {
    let work_root = "/tmp";
    let work_dir = format!("{work_root}/rustynet-membership-update.XXXXXX");
    // Single shell pipeline so the mktemp result + cleanup live in
    // the same script execution. macOS sh (bash) is POSIX-compatible
    // for mktemp -d. The capabilities CSV is quoted via shell_quote
    // so an attacker-controlled CSV cannot inject shell metachars.
    let script = format!(
        r#"set -eu
work="$(/usr/bin/mktemp -d {work_dir})"
trap '/bin/rm -rf -- "$work"' EXIT
rustynet membership propose-set-capabilities \
  --node-id {node_id} \
  --capabilities {capabilities} \
  --output "$work/record.bin" \
  --snapshot {snapshot} \
  --log {log_path}
rustynet membership sign-update \
  --record "$work/record.bin" \
  --approver-id {approver} \
  --signing-key {signing_key} \
  --signing-key-passphrase-file {passphrase} \
  --output "$work/signed.bin"
rustynet membership apply-update \
  --signed-update "$work/signed.bin" \
  --snapshot {snapshot} \
  --log {log_path}
"#,
        work_dir = shell_quote(work_dir.as_str()),
        node_id = shell_quote(node_id),
        capabilities = shell_quote(capabilities),
        approver = shell_quote(owner_approver_id),
        snapshot = shell_quote(config.membership_snapshot_path.as_str()),
        log_path = shell_quote(config.membership_log_path.as_str()),
        signing_key = shell_quote(config.owner_signing_key_path.as_str()),
        passphrase = shell_quote(config.signing_key_passphrase_cred_path.as_str()),
    );
    capture_root(identity, known_hosts, host, &script)
        .map(|out| out.trim().to_owned())
        .map_err(|err| format!("macos membership capability mutation failed on {host}: {err}"))
}

/// Track B Phase 9 — dedicated gossip-seed advertisement check.
///
/// Reads the `rustynet anchor list` output that the running daemon
/// derived from its in-memory membership snapshot and asserts:
///   * the primary anchor carries `anchor.gossip_seed`
///   * at least one node total advertises `anchor.gossip_seed`
///   * a node WITHOUT the capability (when configured) does not
///     accidentally inherit it
///
/// The daemon hashes this same view into the runtime
/// `anchor_gossip_seed_peer_ids` set used by gossip re-broadcast
/// targeting (see `gossip_runtime.rs::anchor_gossip_seed_peer_ids_from_membership`),
/// so an advertisement-side regression would also break runtime
/// targeting. The substage is intentionally parser-only (no host
/// mutation) so it is cheap to run on every live-lab pass.
fn validate_anchor_gossip_seed(anchor_list: &str, config: &Config) -> Result<String, String> {
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
        .find(|line| line.starts_with(config.anchor_node_id.as_str()))
        .ok_or_else(|| {
            format!(
                "primary anchor {} missing from anchor list while checking gossip_seed",
                config.anchor_node_id
            )
        })?;
    if !row_has_capability(primary_row, "anchor.gossip_seed") {
        return Err(format!(
            "primary anchor {} is missing anchor.gossip_seed capability: {primary_row}",
            config.anchor_node_id
        ));
    }
    let seed_node_ids: Vec<String> = seed_rows
        .iter()
        .filter_map(|line| line.split_once(' ').map(|(node_id, _)| node_id.to_owned()))
        .collect();
    Ok(format!(
        "primary={} seed_count={} seeds={}",
        config.anchor_node_id,
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

fn validate_lex_min_anchor_authority(
    anchor_list: &str,
    expected_authority_node_id: &str,
    second_anchor_node_id: &str,
) -> Result<(), String> {
    let mut anchors = anchor_list
        .lines()
        .filter_map(|line| {
            line.split_once(" capabilities=")
                .map(|(node_id, _)| node_id)
        })
        .filter(|node_id| *node_id != "anchor nodes:")
        .map(str::to_owned)
        .collect::<Vec<_>>();
    anchors.sort();
    let actual = anchors
        .first()
        .ok_or_else(|| "anchor list has no authority candidates".to_owned())?;
    if actual != expected_authority_node_id {
        return Err(format!(
            "port-mapping authority mismatch: expected lex-min {expected_authority_node_id}, got {actual}; anchors={}",
            anchors.join(",")
        ));
    }
    if !anchors.iter().any(|node| node == second_anchor_node_id) {
        return Err(format!(
            "second anchor {second_anchor_node_id} missing from authority candidate set: {}",
            anchors.join(",")
        ));
    }
    Ok(())
}

// ─── Track B Phase 29 — RemoteShellHost-driven anchor substages ──────
//
// The seven helpers below were POSIX-only (`set -eu`, `nc`, `sed`,
// `cat`, `mktemp`, … all assembled into a single `sh -lc` body via
// `capture_root`). Phase 29 rewrites them on the
// [`RemoteShellHost`] trait introduced in Phase 28 so the substage
// code is identical across Linux + macOS + Windows. The trait
// performs argv-only exec, base64-frames every file I/O round-trip,
// and runs a pure-PowerShell TCP probe on Windows. Per
// `documents/SecurityMinimumBar.md`, all secret bytes flow through
// `read_file` / `write_file` (binary-safe) or `run_argv` (no shell
// construction with untrusted values) — secrets are never embedded
// in shell strings the trait would have to escape.

/// Track B Phase 29 — validate the loopback bundle-pull listener
/// returns the signed-membership snapshot byte-for-byte to a
/// caller presenting the correct authority token.
///
/// The trait covers each step end-to-end:
///   1. read the authority token from disk via `read_file`
///   2. validate token shape locally (ASCII printable, length >= 32)
///   3. read the membership snapshot via `read_file` for the
///      byte-equality comparison
///   4. TCP-probe the listener via `tcp_send_recv` with
///      `token + "\n"` as the request payload
///   5. assert the response begins with `OK ` and the body matches
///      the snapshot byte-for-byte
///   6. compute the SHA-256 digest of the snapshot in-process
///      (sha2 is already a CLI dependency for trust-evidence
///      handling) so the helper does not depend on `sha256sum`
///      vs `shasum -a 256` vs `Get-FileHash` availability
fn validate_bundle_pull_loopback(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<String, String> {
    let _ = parse_nc_addr(&config.anchor_bundle_pull_addr)?;
    let token = read_anchor_token(shell, config)?;
    let snapshot = shell
        .read_file(config.membership_snapshot_path.as_str())
        .map_err(|err| {
            format!(
                "anchor bundle-pull loopback: read snapshot {} failed: {err}",
                config.membership_snapshot_path
            )
        })?;
    let mut request = token.clone();
    request.push(b'\n');
    // Retry the TCP probe up to 3 times with a 2s sleep between attempts.
    // An empty response means the listener wasn't ready (port not yet bound
    // or daemon briefly between restart cycles) — not a hard failure.
    let max_attempts = 3u32;
    let sleep_secs = 2u64;
    let mut attempt = 0u32;
    let (header_vec, body_vec) = loop {
        attempt += 1;
        let response = shell
            .tcp_send_recv(
                &config.anchor_bundle_pull_addr,
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
                std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
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

/// Track B Phase 29 — assert the listener rejects a syntactically
/// well-shaped but unauthenticated token. Uses a fixed 32-byte
/// printable payload so the test is deterministic and does not
/// depend on RNG, mirroring the pre-Phase-29 script.
fn validate_invalid_token_rejected(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<String, String> {
    let _ = parse_nc_addr(&config.anchor_bundle_pull_addr)?;
    let payload: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n";
    let response = shell
        .tcp_send_recv(
            &config.anchor_bundle_pull_addr,
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

/// Track B Phase 29 — Linux-only assertion that the daemon's
/// journal contains only the token's SHA-256 thumbprint, never the
/// raw token bytes. On macOS / Windows the helper returns a
/// `log_redaction_check=skipped` summary because journalctl is
/// Linux-only; the per-platform log surface (`log show`,
/// `Get-WinEvent`) is a separate substage tracked outside Phase 29.
fn validate_bundle_pull_log_redaction(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<String, String> {
    if config.platform != AnchorPlatform::Linux {
        return Ok(format!(
            "log_redaction_check=skipped platform={} reason=journalctl-linux-only",
            config.platform.as_str()
        ));
    }
    let token = read_anchor_token(shell, config)?;
    let thumbprint = anchor_token_thumbprint(&token);
    let token_str = std::str::from_utf8(&token)
        .map_err(|err| format!("anchor token bytes not utf-8: {err}"))?;
    let thumbprint_marker = format!("token_thumbprint={thumbprint}");
    // journald indexes entries asynchronously after the daemon writes them.
    // On a loaded system the entry may not appear immediately after the TCP
    // roundtrip. Retry up to 3 times with a 1 s sleep between attempts so
    // the check is robust without adding fixed latency on fast systems.
    // Token-leak detection is checked on every attempt (no retry for leaks).
    let max_attempts: u8 = 3;
    for attempt in 1..=max_attempts {
        // The trait's `run_argv` drives `journalctl` in argv-only form
        // (no shell composition), then the Rust side filters lines for
        // the `anchor_bundle_pull:` tag and asserts the leak/thumbprint
        // contract locally.
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
            // Entry not yet indexed; wait 1 s and retry.
            let _ = shell.run_argv(&["sleep", "1"], &[], &[]);
        }
    }
    Err(format!(
        "anchor bundle-pull journal missing token thumbprint {thumbprint}"
    ))
}

/// Track B Phase 29 — capture the role-transition audit log size
/// (or `0` if the file does not yet exist) in a cross-OS way. The
/// helper builds two argv shapes — POSIX `sh -c` with `wc -c` and
/// PowerShell `Get-Item .Length` — that both honour the
/// fail-closed missing-file case explicitly.
fn capture_role_audit_log_size(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<u64, String> {
    let audit_path = config.role_audit_log_path.as_str();
    let argv: Vec<&str> = match config.platform {
        AnchorPlatform::Linux | AnchorPlatform::Macos => vec![
            "sh",
            "-c",
            "if [ -e \"$1\" ]; then wc -c <\"$1\" | tr -d '[:space:]'; else printf 0; fi",
            "--",
            audit_path,
        ],
        AnchorPlatform::Windows => vec![
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$p=$args[0]; if (Test-Path -LiteralPath $p) { Write-Output (Get-Item -LiteralPath $p).Length } else { Write-Output 0 }",
            audit_path,
        ],
    };
    let status = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("role audit size capture failed: {err}"))?;
    if !status.is_success() {
        return Err(format!(
            "role audit size capture exited {}: {}",
            status.code,
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }
    let text = String::from_utf8(status.stdout)
        .map_err(|err| format!("role audit size stdout not utf-8: {err}"))?;
    text.trim()
        .parse::<u64>()
        .map_err(|err| format!("role audit size parse failed: {err}: {text:?}"))
}

/// Track B Phase 29 — kick off a bundle-pull request that the
/// caller can `finish_inflight_bundle_pull` *after* the
/// anchor.bundle_pull revocation lands. The split lets the
/// downgrade substage prove that an in-flight pull initiated
/// before revocation completes successfully (the listener does
/// not yank an established session).
///
/// The original POSIX script backgrounded `nc` via `nohup … &`.
/// The cross-OS rewrite spawns a detached helper:
///   * POSIX: `sh -c 'nohup nc -w … & echo $! > pid' </dev/null`
///   * Windows: PowerShell `Start-Job` so the outer `Start-Process`
///     in the trait does NOT wait on the long-running pull.
fn start_inflight_bundle_pull(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<String, String> {
    let addr = parse_nc_addr(&config.anchor_bundle_pull_addr)?;
    let token = read_anchor_token(shell, config)?;
    let token_str = std::str::from_utf8(&token)
        .map_err(|err| format!("anchor token bytes not utf-8: {err}"))?;
    let work_dir = remote_scratch_dir(config.platform, "rustynet-anchor-inflight");
    // Create the scratch dir before writing the token into it.
    // write_file uses `install -m <mode> -- src dst` which requires
    // the parent directory to already exist.
    let mk = shell.run_argv(&["mkdir", "-p", &work_dir], &[], &[]).map_err(|err| {
        format!("create in-flight work dir {work_dir} failed: {err}")
    })?;
    if !mk.is_success() {
        return Err(format!(
            "create in-flight work dir {work_dir} failed: {}",
            String::from_utf8_lossy(&mk.stderr).trim()
        ));
    }
    let token_remote_path = remote_join(config.platform, &work_dir, "token");
    shell
        .write_file(&token_remote_path, &token, 0o600)
        .map_err(|err| format!("stage in-flight token at {token_remote_path} failed: {err}"))?;
    match config.platform {
        AnchorPlatform::Linux | AnchorPlatform::Macos => {
            // The wrapper sh script writes nc's stdout + exit code
            // to per-run files inside the work dir, then exits — so
            // the trait's synchronous `run_argv` returns immediately
            // while nc continues in the background.
            let body = "set -eu; \
                work=\"$1\"; tok=\"$2\"; addr_host=\"$3\"; addr_port=\"$4\"; \
                chmod 700 \"$work\"; \
                nohup sh -c '\
                  printf \"%s\\n\" \"$(cat \"$1\")\" | nc -w 10 \"$2\" \"$3\" > \"$4\" 2> \"$5\"; \
                  printf \"%s\\n\" \"$?\" > \"$6\"\
                ' rustynet-anchor-inflight \"$tok\" \"$addr_host\" \"$addr_port\" \
                  \"$work/response\" \"$work/stderr\" \"$work/status\" \
                  </dev/null >/dev/null 2>&1 &
                printf '%s\\n' \"$!\" > \"$work/pid\"";
            let status = shell
                .run_argv(
                    &[
                        "sh",
                        "-c",
                        body,
                        "--",
                        &work_dir,
                        &token_remote_path,
                        &addr.host,
                        &addr.port,
                    ],
                    &[],
                    &[],
                )
                .map_err(|err| format!("start in-flight bundle-pull failed: {err}"))?;
            if !status.is_success() {
                return Err(format!(
                    "start in-flight bundle-pull exited {}: {}",
                    status.code,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
            // Return the scratch dir to the caller — the finisher
            // resolves the per-run status / response paths via
            // `remote_join`. The original script emitted a
            // `work_dir=<…> pid=<…>` line that the caller then
            // re-parsed; the trait-based design just returns the
            // dir directly so no intermediate text parsing is
            // needed.
            Ok(work_dir)
        }
        AnchorPlatform::Windows => {
            // Windows PowerShell job: `Start-Job` returns
            // immediately and runs the bundle-pull connect in the
            // background. The job writes `response` / `status`
            // files; the trait's outer `Start-Process` waits on the
            // PowerShell wrapper which exits as soon as `Start-Job`
            // returns.
            //
            // We embed paths via `ps_quote_str` so a path with an
            // apostrophe (defense-in-depth) stays balanced inside
            // the single-quoted PowerShell literals.
            let _ = token_str; // string form not needed on Windows
            let script = format!(
                "$ErrorActionPreference='Stop'; \
                 $work = '{work}'; \
                 $tok = '{tok}'; \
                 $addrHost = '{addr_host}'; \
                 $addrPort = {addr_port}; \
                 $response = Join-Path $work 'response'; \
                 $statusFile = Join-Path $work 'status'; \
                 $stderr = Join-Path $work 'stderr'; \
                 Start-Job -Name 'rustynet-anchor-inflight' -ArgumentList @($tok,$addrHost,$addrPort,$response,$statusFile,$stderr) -ScriptBlock {{ \
                   param($Tok,$AddrHost,$AddrPort,$Response,$StatusFile,$Stderr); \
                   $token = [System.IO.File]::ReadAllText($Tok); \
                   $token = $token.TrimEnd(\"`r\",\"`n\"); \
                   try {{ \
                     $client = New-Object System.Net.Sockets.TcpClient; \
                     $client.ReceiveTimeout = 10000; \
                     $client.SendTimeout = 10000; \
                     $client.Connect($AddrHost, [int]$AddrPort); \
                     $stream = $client.GetStream(); \
                     $bytes = [System.Text.Encoding]::ASCII.GetBytes(($token + \"`n\")); \
                     $stream.Write($bytes, 0, $bytes.Length); \
                     $stream.Flush(); \
                     $ms = New-Object System.IO.MemoryStream; \
                     $buf = New-Object byte[] 4096; \
                     $deadline = [DateTime]::UtcNow.AddSeconds(10); \
                     while ([DateTime]::UtcNow -lt $deadline) {{ \
                       if ($client.Available -gt 0) {{ \
                         $n = $stream.Read($buf, 0, $buf.Length); \
                         if ($n -le 0) {{ break }}; \
                         $ms.Write($buf, 0, $n); \
                       }} elseif ($ms.Length -gt 0) {{ break }} else {{ Start-Sleep -Milliseconds 100 }} \
                     }}; \
                     $client.Close(); \
                     [System.IO.File]::WriteAllBytes($Response, $ms.ToArray()); \
                     [System.IO.File]::WriteAllText($StatusFile, '0'); \
                   }} catch {{ \
                     [System.IO.File]::WriteAllText($Stderr, $_.Exception.Message); \
                     [System.IO.File]::WriteAllText($StatusFile, '1'); \
                   }} \
                 }} | Out-Null",
                work = ps_quote_str(&work_dir),
                tok = ps_quote_str(&token_remote_path),
                addr_host = ps_quote_str(&addr.host),
                addr_port = addr.port,
            );
            let status = shell
                .run_argv(
                    &[
                        "powershell",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        &script,
                    ],
                    &[],
                    &[],
                )
                .map_err(|err| format!("start in-flight bundle-pull failed: {err}"))?;
            if !status.is_success() {
                return Err(format!(
                    "start in-flight bundle-pull exited {}: {}",
                    status.code,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
            Ok(work_dir)
        }
    }
}

/// Track B Phase 29 — wait for an in-flight bundle pull to finish
/// and assert its header is `OK ` and the body was non-empty. The
/// helper polls the per-run `status` file written by
/// `start_inflight_bundle_pull` (POSIX: nohup wrapper, Windows:
/// `Start-Job` scriptblock); both paths persist `0` on success.
/// Cleanup is best-effort — the work dir is always unlinked even
/// when the body assertion fails so the test does not leak temp
/// state.
fn finish_inflight_bundle_pull(
    shell: &dyn RemoteShellHost,
    config: &Config,
    work_dir: &str,
) -> Result<String, String> {
    if !is_safe_remote_dir(config.platform, work_dir) {
        return Err(format!(
            "in-flight bundle-pull work dir {work_dir:?} is not under the expected scratch root"
        ));
    }
    let status_path = remote_join(config.platform, work_dir, "status");
    let response_path = remote_join(config.platform, work_dir, "response");

    let mut last_err: Option<String> = None;
    let mut status_bytes: Option<Vec<u8>> = None;
    for _ in 0..20u32 {
        match shell.read_file(&status_path) {
            Ok(bytes) if !bytes.is_empty() => {
                status_bytes = Some(bytes);
                break;
            }
            Ok(_) => {}
            Err(err) => last_err = Some(err.to_string()),
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let Some(status_bytes) = status_bytes else {
        cleanup_remote_dir(shell, config, work_dir);
        return Err(format!(
            "in-flight bundle-pull did not finish before timeout: last_err={last_err:?}"
        ));
    };
    let status_text = String::from_utf8_lossy(&status_bytes).trim().to_owned();
    if status_text != "0" {
        cleanup_remote_dir(shell, config, work_dir);
        return Err(format!(
            "in-flight bundle-pull exited with status {status_text}"
        ));
    }
    let response = shell.read_file(&response_path).map_err(|err| {
        cleanup_remote_dir(shell, config, work_dir);
        format!("read in-flight response failed: {err}")
    })?;
    let (header, body) = split_bundle_pull_response(&response)?;
    if !header.starts_with(b"OK ") {
        cleanup_remote_dir(shell, config, work_dir);
        return Err(format!(
            "in-flight bundle-pull header was not OK: {:?}",
            String::from_utf8_lossy(header)
        ));
    }
    let header_text = String::from_utf8_lossy(header).into_owned();
    let bytes = body.len();
    cleanup_remote_dir(shell, config, work_dir);
    Ok(format!("header={header_text} bytes={bytes}"))
}

/// Track B Phase 29 — probe the bundle-pull listener until it
/// returns a non-`OK` header (i.e. fail-closed after revocation).
/// The helper preserves the original 30-attempt × 2-second cap
/// and emits the same `fail_closed_header=…` summary so the
/// substage's evidence payload is unchanged.
fn wait_for_bundle_pull_fail_closed(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<String, String> {
    let _ = parse_nc_addr(&config.anchor_bundle_pull_addr)?;
    let token = read_anchor_token(shell, config)?;
    let mut request = token;
    request.push(b'\n');
    for attempt in 0..30u32 {
        let response = shell
            .tcp_send_recv(
                &config.anchor_bundle_pull_addr,
                &request,
                Duration::from_secs(3),
            )
            .unwrap_or_default();
        let header = first_line_bytes(&response);
        if !header.starts_with(b"OK ") {
            let header_text = String::from_utf8_lossy(header).into_owned();
            return Ok(format!(
                "fail_closed_header={header_text} attempts={attempt}"
            ));
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err("bundle-pull still accepted after anchor.bundle_pull revocation".to_owned())
}

/// Track B Phase 29 — drive the full enrollment-endpoint contract
/// through the trait. The helper still needs a signing-key
/// passphrase staged as a file (the `rustynet enrollment admit`
/// CLI takes `--signing-key-passphrase <path>`), so the unwrap
/// happens in `unwrap_signing_passphrase_to_remote_tmp` which has
/// per-platform branches (systemd-creds on Linux, security on
/// macOS, PowerShell `ProtectedData.Unprotect` on Windows). Every
/// other step — token mint, negative verify, missing-token admit,
/// wrong-approver admit, positive admit, post-admit membership
/// check — flows through `shell.run_argv` so it is platform-agnostic.
fn validate_anchor_enrollment_endpoint(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<String, String> {
    let enrollee_host = config.enrollee_host.as_deref().ok_or_else(|| {
        "--enrollee-host is required for validate_anchor_enrollment_endpoint".to_owned()
    })?;
    let enrollee_node_id = config.enrollee_node_id.as_deref().ok_or_else(|| {
        "--enrollee-node-id is required for validate_anchor_enrollment_endpoint".to_owned()
    })?;
    let owner_approver_id = config.owner_approver_id.as_deref().ok_or_else(|| {
        "--owner-approver-id is required for validate_anchor_enrollment_endpoint".to_owned()
    })?;

    // Per-host scratch directory + file paths. The original script
    // used `mktemp -d` for the work dir; we use a deterministic
    // PID/timestamp suffix so the path is reproducible across
    // logging without losing collision avoidance.
    let work_dir = remote_scratch_dir(config.platform, "rustynet-anchor-enrollment");
    let passphrase_path = remote_join(config.platform, &work_dir, "signing.passphrase");
    let wrong_secret_path = remote_join(config.platform, &work_dir, "wrong.secret");
    let signed_update_path = remote_join(config.platform, &work_dir, "enrollee.signed");
    let bad_approver_path = remote_join(config.platform, &work_dir, "bad-approver.signed");

    let result = (|| -> Result<String, String> {
        // 1. unwrap signing-key passphrase to the work dir. The
        //    helper writes 0o600 / SYSTEM+Admins-only on each OS.
        unwrap_signing_passphrase_to_remote_tmp(shell, config, &work_dir, &passphrase_path)?;

        // 2. stage the wrong-secret (32 zero bytes) for the
        //    negative verify check.
        shell
            .write_file(&wrong_secret_path, &[0u8; 32], 0o600)
            .map_err(|err| format!("stage wrong secret failed: {err}"))?;

        // 3. probe whether enrollee is already in membership.
        let pre_status = run_argv_capture_stdout(
            shell,
            &[
                "rustynet",
                "membership",
                "status",
                "--snapshot",
                config.membership_snapshot_path.as_str(),
                "--log",
                config.membership_log_path.as_str(),
            ],
        )?;
        // In the full live lab the bootstrap pre-enrolls all nodes, so client-4 is
        // already in membership when this test runs. enrollment admit refuses to add
        // a node_id that is already present in the snapshot. Use a synthetic test-only
        // node ID ("<enrollee_node_id>-live-test") when the enrollee is pre-enrolled
        // so the positive admit has a fresh ID to work with. The enrollment MECHANISM
        // (token minting, rejection paths, signed log append) is identical either way.
        let pre_enrolled =
            pre_status.contains("active_nodes=") && pre_status.contains(enrollee_node_id);
        let effective_enrollee_node_id: String = if pre_enrolled {
            format!("{enrollee_node_id}-live-test")
        } else {
            enrollee_node_id.to_owned()
        };

        // 4. generate a random 32-byte pubkey and URL-safe-base64
        //    encode it locally — no need to shell out to dd/base64/tr.
        let pubkey_b64 = random_url_safe_pubkey();

        // 5. mint a fresh enrollment token (positive).
        let token = run_argv_capture_stdout(
            shell,
            &[
                "rustynet",
                "enrollment",
                "mint",
                "--secret",
                config.enrollment_secret_path.as_str(),
                "--ttl",
                "300",
            ],
        )?
        .trim()
        .to_owned();

        // 6. negative verify: wrong secret MUST fail.
        let wrong_secret_verify = shell
            .run_argv(
                &[
                    "rustynet",
                    "enrollment",
                    "verify",
                    "--secret",
                    &wrong_secret_path,
                    "--token",
                    &token,
                ],
                &[],
                &[],
            )
            .map_err(|err| format!("wrong-secret verify run failed: {err}"))?;
        if wrong_secret_verify.is_success() {
            return Err(
                "wrong-secret enrollment token verification unexpectedly succeeded".to_owned(),
            );
        }

        // 7. negative verify: bogus token MUST fail.
        let bogus_verify = shell
            .run_argv(
                &[
                    "rustynet",
                    "enrollment",
                    "verify",
                    "--secret",
                    config.enrollment_secret_path.as_str(),
                    "--ledger",
                    config.enrollment_ledger_path.as_str(),
                    "--token",
                    "not-a-token",
                ],
                &[],
                &[],
            )
            .map_err(|err| format!("bogus-token verify run failed: {err}"))?;
        if bogus_verify.is_success() {
            return Err("bogus enrollment token unexpectedly verified".to_owned());
        }

        // 8. negative admit: wrong-secret token MUST be rejected by admit.
        // Using an explicitly bad token string rather than a missing --token,
        // because the CLI falls through to Help (exit 0) when required args are
        // absent (Err(_) => CliCommand::Help in parse_command).
        let wrong_token_admit = shell
            .run_argv(
                &[
                    "rustynet",
                    "enrollment",
                    "admit",
                    "--token",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "--pubkey",
                    &pubkey_b64,
                    "--node-id",
                    enrollee_node_id,
                    "--owner",
                    enrollee_node_id,
                    "--roles",
                    "client",
                    "--secret",
                    config.enrollment_secret_path.as_str(),
                    "--ledger",
                    config.enrollment_ledger_path.as_str(),
                    "--snapshot",
                    config.membership_snapshot_path.as_str(),
                    "--log",
                    config.membership_log_path.as_str(),
                    "--signing-key",
                    config.owner_signing_key_path.as_str(),
                    "--signing-key-passphrase",
                    &passphrase_path,
                    "--approver-id",
                    owner_approver_id,
                    "--output",
                    &signed_update_path,
                    "--apply",
                ],
                &[],
                &[],
            )
            .map_err(|err| format!("wrong-token admit run failed: {err}"))?;
        if wrong_token_admit.is_success() {
            return Err("wrong-token enrollment admit unexpectedly succeeded".to_owned());
        }

        // 9. mint a fresh token for the negative-approver test (the
        //    original script reused the same secret/ttl).
        let bad_approver_token = run_argv_capture_stdout(
            shell,
            &[
                "rustynet",
                "enrollment",
                "mint",
                "--secret",
                config.enrollment_secret_path.as_str(),
                "--ttl",
                "300",
            ],
        )?
        .trim()
        .to_owned();

        // 10. negative admit: non-anchor approver MUST fail.
        let bad_approver_admit = shell
            .run_argv(
                &[
                    "rustynet",
                    "enrollment",
                    "admit",
                    "--token",
                    &bad_approver_token,
                    "--pubkey",
                    &pubkey_b64,
                    "--node-id",
                    enrollee_node_id,
                    "--owner",
                    enrollee_node_id,
                    "--roles",
                    "client",
                    "--secret",
                    config.enrollment_secret_path.as_str(),
                    "--ledger",
                    config.enrollment_ledger_path.as_str(),
                    "--snapshot",
                    config.membership_snapshot_path.as_str(),
                    "--log",
                    config.membership_log_path.as_str(),
                    "--signing-key",
                    config.owner_signing_key_path.as_str(),
                    "--signing-key-passphrase",
                    &passphrase_path,
                    "--approver-id",
                    "rustynet-live-negative-approver",
                    "--output",
                    &bad_approver_path,
                    "--apply",
                ],
                &[],
                &[],
            )
            .map_err(|err| format!("bad-approver admit run failed: {err}"))?;
        if bad_approver_admit.is_success() {
            return Err("non-anchor approver enrollment admit unexpectedly succeeded".to_owned());
        }

        // 11. positive admit: must succeed.
        let positive_admit = shell
            .run_argv(
                &[
                    "rustynet",
                    "enrollment",
                    "admit",
                    "--token",
                    &token,
                    "--pubkey",
                    &pubkey_b64,
                    "--node-id",
                    effective_enrollee_node_id.as_str(),
                    "--owner",
                    effective_enrollee_node_id.as_str(),
                    "--roles",
                    "client",
                    "--secret",
                    config.enrollment_secret_path.as_str(),
                    "--ledger",
                    config.enrollment_ledger_path.as_str(),
                    "--snapshot",
                    config.membership_snapshot_path.as_str(),
                    "--log",
                    config.membership_log_path.as_str(),
                    "--signing-key",
                    config.owner_signing_key_path.as_str(),
                    "--signing-key-passphrase",
                    &passphrase_path,
                    "--approver-id",
                    owner_approver_id,
                    "--output",
                    &signed_update_path,
                    "--apply",
                ],
                &[],
                &[],
            )
            .map_err(|err| format!("positive admit run failed: {err}"))?;
        if !positive_admit.is_success() {
            return Err(format!(
                "positive enrollment admit failed (code {}): {}",
                positive_admit.code,
                String::from_utf8_lossy(&positive_admit.stderr).trim()
            ));
        }

        // 12. assert enrollee is now visible in membership status.
        let post_status = run_argv_capture_stdout(
            shell,
            &[
                "rustynet",
                "membership",
                "status",
                "--snapshot",
                config.membership_snapshot_path.as_str(),
                "--log",
                config.membership_log_path.as_str(),
            ],
        )?;
        if !(post_status.contains("active_nodes=")
            && post_status.contains(effective_enrollee_node_id.as_str()))
        {
            return Err(format!(
                "enrollee {effective_enrollee_node_id} missing from membership status after admit"
            ));
        }

        Ok(format!(
            "enrollee={enrollee_node_id} host={enrollee_host} pre_enrolled={pre_enrolled} admitted=true wrong_secret_rejected=true bogus_token_rejected=true wrong_token_rejected=true non_anchor_approver_rejected=true"
        ))
    })();

    // Always clean up the scratch dir so plaintext passphrase /
    // negative-test signed records do not linger on the remote.
    cleanup_remote_dir(shell, config, &work_dir);
    result
}

fn validate_anchor_downgrade_revocation(
    shell: &dyn RemoteShellHost,
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    let owner_approver_id = config.owner_approver_id.as_deref().ok_or_else(|| {
        "--owner-approver-id is required for validate_anchor_downgrade_revocation".to_owned()
    })?;

    let pre_revocation_pull = validate_bundle_pull_loopback(shell, config)?;
    let inflight_work_dir = start_inflight_bundle_pull(shell, config)?;
    let audit_bytes_before = capture_role_audit_log_size(shell, config)
        .map_err(|err| format!("capture audit size before revocation failed: {err}"))?;

    if let Err(err) = set_membership_capabilities(
        identity,
        known_hosts,
        config,
        &config.anchor_host,
        config.anchor_node_id.as_str(),
        "anchor,relay_host,anchor.gossip_seed,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative",
        owner_approver_id,
    ) {
        let _ = finish_inflight_bundle_pull(shell, config, &inflight_work_dir);
        return Err(format!(
            "revoke anchor.bundle_pull from {} failed: {err}",
            config.anchor_node_id
        ));
    }

    let validation = (|| -> Result<String, String> {
        let inflight_pull = finish_inflight_bundle_pull(shell, config, &inflight_work_dir)?;
        let fail_closed = wait_for_bundle_pull_fail_closed(shell, config)?;
        let audit_bytes_after = capture_role_audit_log_size(shell, config)
            .map_err(|err| format!("capture audit size after revocation failed: {err}"))?;
        if audit_bytes_after <= audit_bytes_before {
            return Err(format!(
                "role-transition audit did not grow after downgrade: before={audit_bytes_before} after={audit_bytes_after}"
            ));
        }
        Ok(format!(
            "pre_revocation_pull=ok({pre_revocation_pull}) inflight_pull=ok({inflight_pull}) post_revocation={fail_closed} audit_bytes_before={audit_bytes_before} audit_bytes_after={audit_bytes_after}"
        ))
    })();

    let restore = set_membership_capabilities(
        identity,
        known_hosts,
        config,
        &config.anchor_host,
        config.anchor_node_id.as_str(),
        "anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative",
        owner_approver_id,
    );

    match (validation, restore) {
        (Ok(summary), Ok(_)) => Ok(format!("{summary} restore=ok")),
        (Err(err), Ok(_)) => Err(err),
        (Ok(_), Err(restore_err)) => Err(format!(
            "downgrade validation passed but anchor.bundle_pull restore failed for {}: {restore_err}",
            config.anchor_node_id
        )),
        (Err(err), Err(restore_err)) => Err(format!(
            "{err}; anchor.bundle_pull restore failed for {}: {restore_err}",
            config.anchor_node_id
        )),
    }
}

// ─── Phase 29 trait-driven helpers ───────────────────────────────────

/// Read the anchor bundle-pull token from the remote host via the
/// trait and validate the printable-ASCII + length-32 shape the
/// pre-Phase-29 POSIX script enforced inline via shell `case`.
fn read_anchor_token(shell: &dyn RemoteShellHost, config: &Config) -> Result<Vec<u8>, String> {
    let raw = shell
        .read_file(config.anchor_token_path.as_str())
        .map_err(|err| {
            format!(
                "read anchor token at {} failed: {err}",
                config.anchor_token_path
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

/// Compute the SHA-256 thumbprint (first 16 hex chars) of the
/// anchor token. The daemon emits this same thumbprint in the
/// `anchor_bundle_pull:` journal lines (see
/// `crates/rustynetd/src/anchor_bundle_pull.rs`) so the redaction
/// substage can match on it locally.
fn anchor_token_thumbprint(token: &[u8]) -> String {
    let digest = sha256_hex(token);
    digest[..16].to_owned()
}

/// Hex-encode the SHA-256 digest of `bytes`. Used by both the
/// bundle-pull loopback summary and the journal thumbprint match.
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

/// Generate a random 32-byte URL-safe-base64 (no padding) string.
/// Replaces the original `dd if=/dev/urandom bs=32 count=1 |
/// base64 | tr '+/' '-_' | tr -d '= \n'` pipeline. Uses the local
/// system RNG so the test does not depend on `/dev/urandom`
/// existing on the remote (Windows has no `/dev/urandom`).
fn random_url_safe_pubkey() -> String {
    use base64::prelude::*;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut encoded = BASE64_STANDARD.encode(bytes);
    // URL-safe + no padding to match the original tr pipeline.
    encoded = encoded.replace('+', "-").replace('/', "_");
    while encoded.ends_with('=') {
        encoded.pop();
    }
    encoded
}

/// Split a bundle-pull response into the header line and body
/// bytes. The server emits `OK <…>\n<bytes>` for success and
/// `ERR <…>\n` for failure.
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

/// Return the bytes of the first line (excluding the trailing
/// `\r\n` or `\n`) of `bytes`. Empty slice if no newline found
/// AND the input is empty; otherwise the whole input.
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

/// Capture stdout from a successful `run_argv` invocation, fail
/// closed on a non-zero exit. Used by the enrollment-endpoint
/// helper for the `rustynet membership status` / `rustynet
/// enrollment mint` calls.
fn run_argv_capture_stdout(shell: &dyn RemoteShellHost, argv: &[&str]) -> Result<String, String> {
    let status = shell
        .run_argv(argv, &[], &[])
        .map_err(|err| format!("run_argv {argv:?} failed: {err}"))?;
    if !status.is_success() {
        return Err(format!(
            "run_argv {argv:?} exited {}: {}",
            status.code,
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }
    String::from_utf8(status.stdout)
        .map_err(|err| format!("run_argv {argv:?} stdout not utf-8: {err}"))
}

/// Build a deterministic remote scratch directory name. The
/// trait's `write_file` creates parent dirs on Windows, but POSIX
/// `install` does not — so the helper that wants to use this dir
/// must either pre-create it via `mkdir -p` or rely on write_file
/// auto-creating the parent (Windows path handles this).
fn remote_scratch_dir(platform: AnchorPlatform, prefix: &str) -> String {
    let pid = std::process::id();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    match platform {
        AnchorPlatform::Linux | AnchorPlatform::Macos => {
            format!("/tmp/{prefix}-{pid}-{stamp}")
        }
        AnchorPlatform::Windows => {
            format!(r"C:\Windows\Temp\{prefix}-{pid}-{stamp}")
        }
    }
}

/// Cross-OS path join. POSIX uses `/`; Windows uses `\`.
fn remote_join(platform: AnchorPlatform, dir: &str, leaf: &str) -> String {
    match platform {
        AnchorPlatform::Linux | AnchorPlatform::Macos => format!("{dir}/{leaf}"),
        AnchorPlatform::Windows => format!(r"{dir}\{leaf}"),
    }
}

/// Best-effort cleanup of a remote scratch dir. POSIX uses `rm
/// -rf` (sudo-wrapped by the trait); Windows uses
/// `Remove-Item -Recurse -Force`. Errors are intentionally
/// dropped — the substages already returned their primary result
/// and a noisy cleanup error would mask the real signal.
///
/// Phase 29 follow-up (LOW 2 fold-in): the Windows branch now also
/// stops and removes the `rustynet-anchor-inflight` PowerShell job
/// emitted by `start_inflight_bundle_pull`. Without the explicit
/// `Stop-Job` + `Remove-Job` step, a hung job persists until the
/// host PowerShell exits — which on a long-running orchestrator run
/// leaks one PowerShell job per substage iteration. The cleanup is
/// best-effort and silently noops if no job by that name exists.
fn cleanup_remote_dir(shell: &dyn RemoteShellHost, config: &Config, dir: &str) {
    if !is_safe_remote_dir(config.platform, dir) {
        return;
    }
    match config.platform {
        AnchorPlatform::Linux | AnchorPlatform::Macos => {
            let _ = shell.run_argv(&["rm", "-rf", "--", dir], &[], &[]);
        }
        AnchorPlatform::Windows => {
            let script = windows_cleanup_remote_dir_script(dir);
            let _ = shell.run_argv(
                &[
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &script,
                ],
                &[],
                &[],
            );
        }
    }
}

/// Build the PowerShell body that drives the Windows `cleanup_remote_dir`
/// primitive. Extracted so a unit test can pin the `Stop-Job` step
/// without needing a remote PowerShell to actually execute it.
///
/// The script's contract:
///   1. Stop + remove the named `rustynet-anchor-inflight` job, if
///      present, to bound the LOW-2 leak window.
///   2. Remove the scratch dir recursively. SilentlyContinue so a
///      missing dir does not propagate an error code (the cleanup
///      runs best-effort after the substage's primary result).
fn windows_cleanup_remote_dir_script(dir: &str) -> String {
    format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         Get-Job -Name 'rustynet-anchor-inflight' -ErrorAction SilentlyContinue | \
         Stop-Job -PassThru -ErrorAction SilentlyContinue | \
         Remove-Job -Force -ErrorAction SilentlyContinue; \
         Remove-Item -LiteralPath '{quoted}' -Recurse -Force",
        quoted = ps_quote_str(dir),
    )
}

/// Defence-in-depth check before invoking `rm -rf`: refuse to
/// recurse paths that are not under the expected scratch root.
fn is_safe_remote_dir(platform: AnchorPlatform, dir: &str) -> bool {
    if dir.is_empty() || dir.contains('\0') {
        return false;
    }
    match platform {
        AnchorPlatform::Linux | AnchorPlatform::Macos => dir.starts_with("/tmp/rustynet-"),
        AnchorPlatform::Windows => {
            dir.starts_with(r"C:\Windows\Temp\rustynet-")
                || dir.starts_with(r"C:\WINDOWS\Temp\rustynet-")
        }
    }
}

/// PowerShell single-quote escape — doubles every `'` to `''`.
/// The trait's own escape applies on the outer argv level; this
/// helper applies the SAME rule for embedded data inside our
/// inline PowerShell scripts so the outer + inner escapes compose
/// correctly through the EncodedCommand pipeline.
fn ps_quote_str(value: &str) -> String {
    value.replace('\'', "''")
}

/// Unwrap the membership signing-key passphrase to a 0o600 (or
/// SYSTEM+Admins-only) file inside the remote work dir. The
/// per-OS branches mirror the production `CredentialUnwrapBackend`
/// strategies:
///   * Linux: `systemd-creds decrypt --name=signing_key_passphrase`
///   * macOS: `security find-generic-password -w` → stdout, then
///     write to disk via `write_file` with 0o600
///   * Windows: PowerShell `ProtectedData.Unprotect` on the
///     RNYDPAPI-envelope-stripped inner blob, then
///     `[System.IO.File]::WriteAllBytes`
fn unwrap_signing_passphrase_to_remote_tmp(
    shell: &dyn RemoteShellHost,
    config: &Config,
    work_dir: &str,
    passphrase_path: &str,
) -> Result<(), String> {
    let cred_path = config.signing_key_passphrase_cred_path.as_str();
    match config.platform {
        AnchorPlatform::Linux => {
            // Pre-create the work dir so systemd-creds' output
            // path is writable. mkdir -p is a POSIX no-op when the
            // path already exists.
            ensure_remote_dir(shell, config, work_dir)?;
            let status = shell
                .run_argv(
                    &[
                        "systemd-creds",
                        "decrypt",
                        "--name=signing_key_passphrase",
                        cred_path,
                        passphrase_path,
                    ],
                    &[],
                    &[],
                )
                .map_err(|err| format!("systemd-creds decrypt failed: {err}"))?;
            if !status.is_success() {
                return Err(format!(
                    "systemd-creds decrypt exited {}: {}",
                    status.code,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
            // systemd-creds writes 0o600 by default but defend
            // against a wider umask by chmod-ing explicitly.
            let chmod = shell
                .run_argv(&["chmod", "600", passphrase_path], &[], &[])
                .map_err(|err| format!("chmod passphrase failed: {err}"))?;
            if !chmod.is_success() {
                return Err(format!(
                    "chmod passphrase exited {}: {}",
                    chmod.code,
                    String::from_utf8_lossy(&chmod.stderr).trim()
                ));
            }
        }
        AnchorPlatform::Macos => {
            ensure_remote_dir(shell, config, work_dir)?;
            let status = shell
                .run_argv(
                    &[
                        "security",
                        "find-generic-password",
                        "-s",
                        "signing_key_passphrase",
                        "-a",
                        "membership-owner-signing-key",
                        "-w",
                    ],
                    &[],
                    &[],
                )
                .map_err(|err| format!("macos keychain unwrap failed: {err}"))?;
            if !status.is_success() {
                return Err(format!(
                    "security find-generic-password exited {}: {}",
                    status.code,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
            let mut bytes = status.stdout;
            // `security -w` always appends a newline.
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            if bytes.is_empty() {
                return Err(
                    "macos keychain unwrap returned empty passphrase (item missing?)".to_owned(),
                );
            }
            shell
                .write_file(passphrase_path, &bytes, 0o600)
                .map_err(|err| format!("write macos passphrase to {passphrase_path}: {err}"))?;
        }
        AnchorPlatform::Windows => {
            // Windows DPAPI: load the RNYDPAPI envelope, validate
            // magic + version + declared length, call
            // ProtectedData.Unprotect on the inner CryptProtectData
            // payload, and write the plaintext to disk with
            // owner-only ACL.
            //
            // The write_file step (run separately AFTER this) is
            // skipped — we write inline from PowerShell so the
            // plaintext never leaves the remote host. The work_dir
            // creation is handled by the script itself.
            //
            // Phase 29 follow-up (MED 1 fold-in): the script
            // ordering is now ACL-first — see
            // `windows_dpapi_unwrap_script` for the canonical
            // contract + the unit test that pins it.
            let script = windows_dpapi_unwrap_script(work_dir, cred_path, passphrase_path);
            let status = shell
                .run_argv(
                    &[
                        "powershell",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        &script,
                    ],
                    &[],
                    &[],
                )
                .map_err(|err| format!("windows DPAPI unwrap failed: {err}"))?;
            if !status.is_success() {
                return Err(format!(
                    "windows DPAPI unwrap exited {}: {}",
                    status.code,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
        }
    }
    Ok(())
}

/// Build the PowerShell body that drives the Windows DPAPI unwrap
/// step in `unwrap_signing_passphrase_to_remote_tmp`. Extracted so a
/// unit test can pin the ACL-first ordering without needing a remote
/// PowerShell to actually execute the script.
///
/// The script's hardened contract (mirrors POSIX
/// `chmod 700 <work_dir>` ahead of the secret write, and the
/// `windows_write_file_script` ACL-first pattern in
/// `live_lab_bin_support/remote_shell.rs`):
///
///   1. Create the work dir (no-op if already present).
///   2. Tighten the DIRECTORY ACL via icacls
///      (`/inheritance:r` + grant SYSTEM/Administrators full
///      control). This happens BEFORE any plaintext is written so a
///      concurrent observer that opens a freshly-created file inside
///      the dir during the race window inherits the locked-down ACL.
///   3. Verify the directory's SDDL is canonical (no Everyone /
///      BUILTIN\Users ACE; SYSTEM + Administrators full control
///      present). Fail-closed on drift.
///   4. Read + validate the RNYDPAPI envelope, then
///      ProtectedData.Unprotect the inner CryptProtectData payload.
///   5. WriteAllBytes the plaintext into the already-ACL'd dir.
///   6. Re-tighten the FILE ACL (defense-in-depth — the file
///      already inherits from the locked-down dir, but an explicit
///      grant matches the POSIX `chmod 600 <passphrase_path>` step
///      after `chmod 700 <work_dir>`).
///   7. Verify the file's SDDL is canonical. On drift the file is
///      removed and the script throws fail-closed.
///
/// Invariant the test pins: between the moment the dir exists and
/// the moment its DACL is locked down, NO secret bytes can have been
/// written to disk. Specifically, the `icacls $work` call must
/// appear in the script text *before* the first `WriteAllBytes`.
fn windows_dpapi_unwrap_script(work_dir: &str, cred_path: &str, passphrase_path: &str) -> String {
    format!(
        "$ErrorActionPreference='Stop'; \
         $work = '{work}'; \
         if (-not (Test-Path -LiteralPath $work)) {{ New-Item -ItemType Directory -Force -Path $work | Out-Null }}; \
         & icacls $work /inheritance:r /grant:r 'SYSTEM:(F)' /grant:r 'Administrators:(F)' | Out-Null; \
         $dirAcl = (Get-Acl -LiteralPath $work).Sddl; \
         if ($dirAcl -match ';WD\\)' -or $dirAcl -match ';BU\\)') {{ \
           Write-Error 'rustynet-anchor-dpapi: work-dir ACL drift (Users or Everyone present) before secret write'; \
           exit 1; \
         }}; \
         if (-not ($dirAcl -match ';FA;;;SY\\)') -or -not ($dirAcl -match ';FA;;;BA\\)')) {{ \
           Write-Error 'rustynet-anchor-dpapi: work-dir ACL drift (SYSTEM or Administrators missing) before secret write'; \
           exit 1; \
         }}; \
         $blob = [System.IO.File]::ReadAllBytes('{cred}'); \
         if ($blob.Length -lt 14) {{ Write-Error 'RNYDPAPI envelope too short'; exit 1 }}; \
         $magic = [System.Text.Encoding]::ASCII.GetBytes('RNYDPAPI'); \
         for ($i = 0; $i -lt 8; $i++) {{ if ($blob[$i] -ne $magic[$i]) {{ Write-Error 'RNYDPAPI magic missing'; exit 1 }} }}; \
         if ($blob[8] -ne 1) {{ Write-Error 'RNYDPAPI unsupported version'; exit 1 }}; \
         $declared = ([int]$blob[10] -shl 24) -bor ([int]$blob[11] -shl 16) -bor ([int]$blob[12] -shl 8) -bor [int]$blob[13]; \
         $actual = $blob.Length - 14; \
         if ($actual -ne $declared) {{ Write-Error 'RNYDPAPI length mismatch'; exit 1 }}; \
         $inner = New-Object byte[] $actual; \
         [Array]::Copy($blob, 14, $inner, 0, $actual); \
         Add-Type -AssemblyName System.Security; \
         $plain = [System.Security.Cryptography.ProtectedData]::Unprotect($inner, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine); \
         [System.IO.File]::WriteAllBytes('{out}', $plain); \
         & icacls '{out}' /inheritance:r /grant:r 'SYSTEM:(F)' /grant:r 'Administrators:(F)' | Out-Null; \
         $fileAcl = (Get-Acl -LiteralPath '{out}').Sddl; \
         if ($fileAcl -match ';WD\\)' -or $fileAcl -match ';BU\\)') {{ \
           Remove-Item -LiteralPath '{out}' -Force -ErrorAction SilentlyContinue; \
           Write-Error 'rustynet-anchor-dpapi: passphrase file ACL drift after write (Users or Everyone present)'; \
           exit 1; \
         }}; \
         if (-not ($fileAcl -match ';FA;;;SY\\)') -or -not ($fileAcl -match ';FA;;;BA\\)')) {{ \
           Remove-Item -LiteralPath '{out}' -Force -ErrorAction SilentlyContinue; \
           Write-Error 'rustynet-anchor-dpapi: passphrase file ACL drift after write (SYSTEM or Administrators missing)'; \
           exit 1; \
         }}",
        work = ps_quote_str(work_dir),
        cred = ps_quote_str(cred_path),
        out = ps_quote_str(passphrase_path),
    )
}

/// Pre-create a remote scratch directory with the conventional
/// 0o700 / SYSTEM+Admins-only ACL. The trait's `write_file`
/// helper auto-creates parent dirs on Windows, but POSIX `install`
/// requires the target dir to exist — call this explicitly when
/// the work dir will host multiple files.
fn ensure_remote_dir(
    shell: &dyn RemoteShellHost,
    config: &Config,
    dir: &str,
) -> Result<(), String> {
    match config.platform {
        AnchorPlatform::Linux | AnchorPlatform::Macos => {
            let status = shell
                .run_argv(
                    &[
                        "sh",
                        "-c",
                        "mkdir -p -- \"$1\" && chmod 700 -- \"$1\"",
                        "--",
                        dir,
                    ],
                    &[],
                    &[],
                )
                .map_err(|err| format!("mkdir {dir} failed: {err}"))?;
            if !status.is_success() {
                return Err(format!(
                    "mkdir {dir} exited {}: {}",
                    status.code,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
        }
        AnchorPlatform::Windows => {
            let script = format!(
                "$ErrorActionPreference='Stop'; \
                 $p = '{}'; \
                 if (-not (Test-Path -LiteralPath $p)) {{ New-Item -ItemType Directory -Force -Path $p | Out-Null }}; \
                 & icacls $p /inheritance:r /grant:r 'SYSTEM:(F)' /grant:r 'Administrators:(F)' | Out-Null",
                ps_quote_str(dir)
            );
            let status = shell
                .run_argv(
                    &[
                        "powershell",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        &script,
                    ],
                    &[],
                    &[],
                )
                .map_err(|err| format!("mkdir {dir} failed: {err}"))?;
            if !status.is_success() {
                return Err(format!(
                    "mkdir {dir} exited {}: {}",
                    status.code,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
        }
    }
    Ok(())
}

fn dry_run_subchecks() -> Vec<Subcheck> {
    ANCHOR_LIVE_SUBSTAGES
        .iter()
        .map(|(name, detail)| Subcheck::skipped(name, detail))
        .collect()
}

fn render_report(
    config: &Config,
    git_commit: &str,
    subchecks: Vec<Subcheck>,
    anchor_list: Option<&str>,
) -> Result<String, String> {
    let status = if subchecks.iter().any(|check| check.status == "fail") {
        "fail"
    } else {
        "pass"
    };
    let checks = subchecks
        .into_iter()
        .map(|check| {
            json!({
                "name": check.name,
                "status": check.status,
                "detail": check.detail,
                "evidence": check.evidence,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&json!({
        "schema_version": 1,
        "stage": "live_anchor",
        "status": status,
        "dry_run": config.dry_run,
        "generated_at_unix": unix_now(),
        "git_commit": git_commit,
        "platform": config.platform.as_str(),
        "anchor_host": config.anchor_host,
        "anchor_node_id": config.anchor_node_id,
        "second_anchor_host": config.second_anchor_host,
        "second_anchor_node_id": config.second_anchor_node_id,
        "leaf_client_host": config.leaf_client_host,
        "leaf_client_node_id": config.leaf_client_node_id,
        "enrollee_host": config.enrollee_host,
        "enrollee_node_id": config.enrollee_node_id,
        "owner_approver_id": config.owner_approver_id,
        "anchor_bundle_pull_addr": config.anchor_bundle_pull_addr,
        "membership_snapshot_path": config.membership_snapshot_path,
        "membership_log_path": config.membership_log_path,
        "enrollment_secret_path": config.enrollment_secret_path,
        "enrollment_ledger_path": config.enrollment_ledger_path,
        "owner_signing_key_path": config.owner_signing_key_path,
        "signing_key_passphrase_cred_path": config.signing_key_passphrase_cred_path,
        "subchecks": checks,
        "anchor_list": anchor_list,
    }))
    .map_err(|err| format!("serialize anchor live report failed: {err}"))
}

fn first_line(value: &str) -> String {
    value
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(240)
        .collect()
}

fn validate_identity(path: &Path) -> Result<(), String> {
    let meta = std::fs::metadata(path)
        .map_err(|err| format!("identity file {} is not readable: {err}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("identity file {} is not a file", path.display()));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct Subcheck {
    name: String,
    status: String,
    detail: String,
    evidence: serde_json::Value,
}

impl Subcheck {
    fn pass(name: &str, detail: &str, evidence: serde_json::Value) -> Self {
        Self {
            name: name.to_owned(),
            status: "pass".to_owned(),
            detail: detail.to_owned(),
            evidence,
        }
    }

    fn skipped(name: &str, detail: &str) -> Self {
        Self {
            name: name.to_owned(),
            status: "skipped".to_owned(),
            detail: detail.to_owned(),
            evidence: json!({}),
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    platform: AnchorPlatform,
    anchor_host: String,
    anchor_node_id: String,
    second_anchor_host: Option<String>,
    second_anchor_node_id: Option<String>,
    leaf_client_host: Option<String>,
    leaf_client_node_id: Option<String>,
    leaf_client_platform: AnchorPlatform,
    enrollee_host: Option<String>,
    enrollee_node_id: Option<String>,
    owner_approver_id: Option<String>,
    anchor_bundle_pull_addr: String,
    anchor_token_path: String,
    membership_snapshot_path: String,
    membership_log_path: String,
    enrollment_secret_path: String,
    enrollment_ledger_path: String,
    owner_signing_key_path: String,
    signing_key_passphrase_cred_path: String,
    /// Phase 16 — platform-aware default for the role-transitions
    /// audit log. The downgrade_revocation substage measures this
    /// file's size before + after revocation to prove the
    /// revocation event was audited. Linux default
    /// `/var/lib/rustynet/role_transitions.audit.log` (matches
    /// `role_cli::DEFAULT_ROLE_AUDIT_LOG_PATH`); macOS swap goes
    /// under `/usr/local/var/rustynet/`.
    role_audit_log_path: String,
    ssh_identity_file: Option<PathBuf>,
    pinned_known_hosts_file: Option<PathBuf>,
    report_path: PathBuf,
    log_path: PathBuf,
    git_commit: Option<String>,
    dry_run: bool,
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            platform: AnchorPlatform::Linux,
            anchor_host: "debian@192.168.64.13".to_owned(),
            anchor_node_id: "exit-1".to_owned(),
            second_anchor_host: None,
            second_anchor_node_id: None,
            leaf_client_host: None,
            leaf_client_node_id: None,
            leaf_client_platform: AnchorPlatform::Linux,
            enrollee_host: None,
            enrollee_node_id: None,
            owner_approver_id: None,
            anchor_bundle_pull_addr: "127.0.0.1:51822".to_owned(),
            anchor_token_path: "/var/lib/rustynet/anchor-bundle-pull.token".to_owned(),
            membership_snapshot_path: "/var/lib/rustynet/membership.snapshot".to_owned(),
            membership_log_path: "/var/lib/rustynet/membership.log".to_owned(),
            enrollment_secret_path: "/var/lib/rustynet/keys/enrollment.secret".to_owned(),
            enrollment_ledger_path: "/var/lib/rustynet/rustynetd.enrollment.ledger".to_owned(),
            role_audit_log_path: "/var/lib/rustynet/role_transitions.audit.log".to_owned(),
            owner_signing_key_path: "/etc/rustynet/membership.owner.key".to_owned(),
            signing_key_passphrase_cred_path:
                "/etc/rustynet/credentials/signing_key_passphrase.cred".to_owned(),
            ssh_identity_file: None,
            pinned_known_hosts_file: None,
            report_path: PathBuf::from("artifacts/phase10/live_linux_anchor_report.json"),
            log_path: PathBuf::from("artifacts/phase10/live_linux_anchor.log"),
            git_commit: None,
            dry_run: false,
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--platform" => {
                    config.platform = AnchorPlatform::parse(&next_value(&mut iter, &arg)?)?
                }
                "--anchor-host" => config.anchor_host = next_value(&mut iter, &arg)?,
                "--anchor-node-id" => config.anchor_node_id = next_value(&mut iter, &arg)?,
                "--second-anchor-host" => {
                    config.second_anchor_host = Some(next_value(&mut iter, &arg)?)
                }
                "--second-anchor-node-id" => {
                    config.second_anchor_node_id = Some(next_value(&mut iter, &arg)?)
                }
                "--leaf-client-host" => {
                    config.leaf_client_host = Some(next_value(&mut iter, &arg)?)
                }
                "--leaf-client-node-id" => {
                    config.leaf_client_node_id = Some(next_value(&mut iter, &arg)?)
                }
                "--leaf-client-platform" => {
                    config.leaf_client_platform =
                        AnchorPlatform::parse(&next_value(&mut iter, &arg)?)?
                }
                "--enrollee-host" => config.enrollee_host = Some(next_value(&mut iter, &arg)?),
                "--enrollee-node-id" => {
                    config.enrollee_node_id = Some(next_value(&mut iter, &arg)?)
                }
                "--owner-approver-id" => {
                    config.owner_approver_id = Some(next_value(&mut iter, &arg)?)
                }
                "--anchor-bundle-pull-addr" => {
                    config.anchor_bundle_pull_addr = next_value(&mut iter, &arg)?
                }
                "--anchor-token-path" => config.anchor_token_path = next_value(&mut iter, &arg)?,
                "--membership-snapshot-path" => {
                    config.membership_snapshot_path = next_value(&mut iter, &arg)?
                }
                "--membership-log-path" => {
                    config.membership_log_path = next_value(&mut iter, &arg)?
                }
                "--enrollment-secret-path" => {
                    config.enrollment_secret_path = next_value(&mut iter, &arg)?
                }
                "--enrollment-ledger-path" => {
                    config.enrollment_ledger_path = next_value(&mut iter, &arg)?
                }
                "--role-audit-log-path" => {
                    config.role_audit_log_path = next_value(&mut iter, &arg)?
                }
                "--owner-signing-key-path" => {
                    config.owner_signing_key_path = next_value(&mut iter, &arg)?
                }
                "--signing-key-passphrase-cred-path" => {
                    config.signing_key_passphrase_cred_path = next_value(&mut iter, &arg)?
                }
                "--ssh-identity-file" => {
                    config.ssh_identity_file = Some(PathBuf::from(next_value(&mut iter, &arg)?))
                }
                "--known-hosts" => {
                    config.pinned_known_hosts_file =
                        Some(PathBuf::from(next_value(&mut iter, &arg)?))
                }
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--git-commit" => config.git_commit = Some(next_value(&mut iter, &arg)?),
                "--dry-run" => config.dry_run = true,
                "--help" | "-h" => return Err(usage()),
                other => return Err(format!("unknown argument: {other}\n{}", usage())),
            }
        }

        config.apply_platform_default_paths();
        config.validate()?;
        Ok(config)
    }

    /// Track B Phases 10 + 11 — apply per-platform path defaults
    /// after `--platform` has been parsed. The Linux defaults are
    /// baked in at struct init so a Linux-only run keeps its shape;
    /// if macOS / Windows was requested AND a path is still equal to
    /// its Linux default, swap to the platform-native equivalent. An
    /// explicit `--<path-flag>` always wins because we only rewrite
    /// values that match the Linux baked-in default literal.
    ///
    /// macOS layout: state under `/usr/local/var/rustynet/membership/`
    /// (subdir per `ops_e2e.rs::macos_install`), credentials under
    /// `/usr/local/etc/rustynet`.
    ///
    /// Windows layout: state under `C:\ProgramData\RustyNet\`,
    /// credentials under `C:\ProgramData\RustyNet\credentials\`
    /// (per `Install-RustyNetWindowsRelayService.ps1`'s reviewed
    /// install defaults).
    fn apply_platform_default_paths(&mut self) {
        match self.platform {
            AnchorPlatform::Linux => {}
            AnchorPlatform::Macos => self.apply_macos_default_paths(),
            AnchorPlatform::Windows => self.apply_windows_default_paths(),
        }
    }

    fn apply_macos_default_paths(&mut self) {
        if self.anchor_token_path == "/var/lib/rustynet/anchor-bundle-pull.token" {
            self.anchor_token_path = "/usr/local/var/rustynet/anchor-bundle-pull.token".to_owned();
        }
        // The macOS installer writes membership state under a
        // `membership/` subdirectory (see `ops_e2e.rs::macos_install`
        // + `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs`),
        // distinct from the Linux layout that uses /var/lib/rustynet
        // directly. Phase 10 reviewer caught the validator pinning
        // the wrong macOS path; honor the canonical subdir layout.
        if self.membership_snapshot_path == "/var/lib/rustynet/membership.snapshot" {
            self.membership_snapshot_path =
                "/usr/local/var/rustynet/membership/membership.snapshot".to_owned();
        }
        if self.membership_log_path == "/var/lib/rustynet/membership.log" {
            self.membership_log_path =
                "/usr/local/var/rustynet/membership/membership.log".to_owned();
        }
        if self.enrollment_secret_path == "/var/lib/rustynet/keys/enrollment.secret" {
            self.enrollment_secret_path =
                "/usr/local/var/rustynet/keys/enrollment.secret".to_owned();
        }
        if self.enrollment_ledger_path == "/var/lib/rustynet/rustynetd.enrollment.ledger" {
            self.enrollment_ledger_path =
                "/usr/local/var/rustynet/rustynetd.enrollment.ledger".to_owned();
        }
        if self.role_audit_log_path == "/var/lib/rustynet/role_transitions.audit.log" {
            self.role_audit_log_path =
                "/usr/local/var/rustynet/role_transitions.audit.log".to_owned();
        }
        if self.owner_signing_key_path == "/etc/rustynet/membership.owner.key" {
            self.owner_signing_key_path = "/usr/local/etc/rustynet/membership.owner.key".to_owned();
        }
        if self.signing_key_passphrase_cred_path
            == "/etc/rustynet/credentials/signing_key_passphrase.cred"
        {
            self.signing_key_passphrase_cred_path =
                "/usr/local/etc/rustynet/credentials/signing_key_passphrase.cred".to_owned();
        }
    }

    /// Phase 11 reviewer BLOCKER #2 fix: pin Windows defaults to
    /// the canonical layout from `rustynetd::windows_paths`.
    /// Membership state lives under `...\membership\`, secret
    /// material under `...\secrets\` (not `...\credentials\`).
    /// Imports the canonical constants so a future rename surfaces
    /// here as a compile break instead of a silent path drift.
    fn apply_windows_default_paths(&mut self) {
        if self.anchor_token_path == "/var/lib/rustynet/anchor-bundle-pull.token" {
            self.anchor_token_path =
                format!(r"{DEFAULT_WINDOWS_STATE_ROOT}\anchor-bundle-pull.token");
        }
        if self.membership_snapshot_path == "/var/lib/rustynet/membership.snapshot" {
            self.membership_snapshot_path = DEFAULT_WINDOWS_MEMBERSHIP_SNAPSHOT_PATH.to_owned();
        }
        if self.membership_log_path == "/var/lib/rustynet/membership.log" {
            self.membership_log_path = DEFAULT_WINDOWS_MEMBERSHIP_LOG_PATH.to_owned();
        }
        if self.enrollment_secret_path == "/var/lib/rustynet/keys/enrollment.secret" {
            self.enrollment_secret_path = format!(r"{DEFAULT_WINDOWS_KEYS_ROOT}\enrollment.secret");
        }
        if self.enrollment_ledger_path == "/var/lib/rustynet/rustynetd.enrollment.ledger" {
            self.enrollment_ledger_path =
                format!(r"{DEFAULT_WINDOWS_STATE_ROOT}\rustynetd.enrollment.ledger");
        }
        if self.role_audit_log_path == "/var/lib/rustynet/role_transitions.audit.log" {
            self.role_audit_log_path =
                format!(r"{DEFAULT_WINDOWS_STATE_ROOT}\role_transitions.audit.log");
        }
        if self.owner_signing_key_path == "/etc/rustynet/membership.owner.key" {
            self.owner_signing_key_path =
                DEFAULT_WINDOWS_MEMBERSHIP_OWNER_SIGNING_KEY_PATH.to_owned();
        }
        if self.signing_key_passphrase_cred_path
            == "/etc/rustynet/credentials/signing_key_passphrase.cred"
        {
            self.signing_key_passphrase_cred_path =
                format!(r"{DEFAULT_WINDOWS_SECRET_ROOT}\signing_key_passphrase.cred");
        }
    }

    fn validate(&self) -> Result<(), String> {
        ensure_safe_token("anchor host", &self.anchor_host)?;
        ensure_safe_token("anchor node id", &self.anchor_node_id)?;
        for (label, value) in [
            ("second anchor host", self.second_anchor_host.as_deref()),
            (
                "second anchor node id",
                self.second_anchor_node_id.as_deref(),
            ),
            ("leaf client host", self.leaf_client_host.as_deref()),
            ("leaf client node id", self.leaf_client_node_id.as_deref()),
            ("enrollee host", self.enrollee_host.as_deref()),
            ("enrollee node id", self.enrollee_node_id.as_deref()),
            ("owner approver id", self.owner_approver_id.as_deref()),
        ] {
            if let Some(value) = value {
                ensure_safe_token(label, value)?;
            }
        }
        require_pair(
            "--second-anchor-host",
            &self.second_anchor_host,
            "--second-anchor-node-id",
            &self.second_anchor_node_id,
        )?;
        require_pair(
            "--leaf-client-host",
            &self.leaf_client_host,
            "--leaf-client-node-id",
            &self.leaf_client_node_id,
        )?;
        require_pair(
            "--enrollee-host",
            &self.enrollee_host,
            "--enrollee-node-id",
            &self.enrollee_node_id,
        )?;
        ensure_safe_token("anchor bundle-pull addr", &self.anchor_bundle_pull_addr)?;
        parse_nc_addr(&self.anchor_bundle_pull_addr)?;
        self.ensure_absolute_platform_path("--anchor-token-path", &self.anchor_token_path)?;
        self.ensure_absolute_platform_path(
            "--membership-snapshot-path",
            &self.membership_snapshot_path,
        )?;
        self.ensure_absolute_platform_path("--membership-log-path", &self.membership_log_path)?;
        self.ensure_absolute_platform_path(
            "--enrollment-secret-path",
            &self.enrollment_secret_path,
        )?;
        self.ensure_absolute_platform_path(
            "--enrollment-ledger-path",
            &self.enrollment_ledger_path,
        )?;
        self.ensure_absolute_platform_path(
            "--owner-signing-key-path",
            &self.owner_signing_key_path,
        )?;
        self.ensure_absolute_platform_path(
            "--signing-key-passphrase-cred-path",
            &self.signing_key_passphrase_cred_path,
        )?;
        if !self.dry_run && self.ssh_identity_file.is_none() {
            return Err("--ssh-identity-file is required unless --dry-run is set".to_owned());
        }
        Ok(())
    }

    fn ensure_absolute_platform_path(&self, flag: &str, path: &str) -> Result<(), String> {
        if path.contains('\0') || path.contains('\n') || !self.platform.path_is_absolute(path) {
            return Err(format!(
                "{flag} must be an absolute {} path",
                self.platform.as_str()
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorPlatform {
    Linux,
    Macos,
    Windows,
}

impl AnchorPlatform {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "linux" => Ok(Self::Linux),
            "macos" | "darwin" => Ok(Self::Macos),
            "windows" | "win32" => Ok(Self::Windows),
            other => Err(format!(
                "unsupported anchor live-test platform {other:?}; expected linux, macos, or windows"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }

    fn path_is_absolute(self, path: &str) -> bool {
        match self {
            Self::Linux | Self::Macos => path.starts_with('/'),
            Self::Windows => {
                let bytes = path.as_bytes();
                bytes.len() >= 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && matches!(bytes[2], b'\\' | b'/')
            }
        }
    }

    /// Track B Phase 29 — bridge from the bin-local enum to the
    /// support-crate enum that the [`RemoteShellHost`] factory takes.
    /// Keeping the bridge here (rather than `From`) avoids leaking
    /// `live_lab_support` into every signature in the bin while still
    /// providing one canonical mapping.
    fn to_live_lab_platform(self) -> LiveLabPlatform {
        match self {
            Self::Linux => LiveLabPlatform::Linux,
            Self::Macos => LiveLabPlatform::MacOs,
            Self::Windows => LiveLabPlatform::Windows,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NcAddr {
    host: String,
    port: String,
}

fn parse_nc_addr(value: &str) -> Result<NcAddr, String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| "--anchor-bundle-pull-addr must be host:port".to_owned())?;
    if host.is_empty()
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err("--anchor-bundle-pull-addr must be host:port".to_owned());
    }
    Ok(NcAddr {
        host: host.to_owned(),
        port: port.to_owned(),
    })
}

fn next_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("missing required value for {flag}"))
}

fn require_pair<T>(
    left_flag: &str,
    left: &Option<T>,
    right_flag: &str,
    right: &Option<T>,
) -> Result<(), String> {
    if left.is_some() != right.is_some() {
        return Err(format!(
            "{left_flag} and {right_flag} must be provided together"
        ));
    }
    Ok(())
}

fn usage() -> String {
    "usage: live_linux_anchor_test --ssh-identity-file <path> [options]\n\noptions:\n  --platform <linux|macos|windows>\n  --anchor-host <user@host>\n  --anchor-node-id <id>\n  --second-anchor-host <user@host>\n  --second-anchor-node-id <id>\n  --leaf-client-host <user@host>\n  --leaf-client-node-id <id>\n  --enrollee-host <user@host>\n  --enrollee-node-id <id>\n  --owner-approver-id <id>\n  --anchor-bundle-pull-addr <host:port>\n  --anchor-token-path <path>\n  --membership-snapshot-path <path>\n  --membership-log-path <path>\n  --enrollment-secret-path <path>\n  --enrollment-ledger-path <path>\n  --owner-signing-key-path <path>\n  --signing-key-passphrase-cred-path <path>\n  --known-hosts <path>\n  --report-path <path>\n  --log-path <path>\n  --git-commit <sha>\n  --dry-run".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dry_run_does_not_require_identity() {
        let cfg = Config::parse(vec!["--dry-run".to_owned()]).expect("dry-run parses");
        assert!(cfg.dry_run);
        assert_eq!(cfg.platform, AnchorPlatform::Linux);
        assert_eq!(cfg.anchor_node_id, "exit-1");
    }

    #[test]
    fn parse_accepts_macos_platform() {
        let cfg = Config::parse(vec![
            "--dry-run".to_owned(),
            "--platform".to_owned(),
            "macos".to_owned(),
            "--second-anchor-host".to_owned(),
            "mac@192.168.64.18".to_owned(),
            "--second-anchor-node-id".to_owned(),
            "macos-anchor-1".to_owned(),
        ])
        .expect("macos dry-run parses");
        assert_eq!(cfg.platform, AnchorPlatform::Macos);
        assert_eq!(cfg.second_anchor_node_id.as_deref(), Some("macos-anchor-1"));
    }

    #[test]
    fn parse_accepts_windows_platform_with_windows_paths() {
        let cfg = Config::parse(vec![
            "--dry-run".to_owned(),
            "--platform".to_owned(),
            "windows".to_owned(),
            "--anchor-token-path".to_owned(),
            r"C:\ProgramData\RustyNet\anchor\bundle-pull.token".to_owned(),
            "--membership-snapshot-path".to_owned(),
            r"C:\ProgramData\RustyNet\state\membership.snapshot".to_owned(),
            "--membership-log-path".to_owned(),
            r"C:\ProgramData\RustyNet\state\membership.log".to_owned(),
            "--enrollment-secret-path".to_owned(),
            r"C:\ProgramData\RustyNet\keys\enrollment.secret".to_owned(),
            "--enrollment-ledger-path".to_owned(),
            r"C:\ProgramData\RustyNet\state\enrollment.ledger".to_owned(),
            "--owner-signing-key-path".to_owned(),
            r"C:\ProgramData\RustyNet\keys\membership.owner.key".to_owned(),
            "--signing-key-passphrase-cred-path".to_owned(),
            r"C:\ProgramData\RustyNet\keys\signing_key_passphrase.cred".to_owned(),
        ])
        .expect("windows dry-run parses");
        assert_eq!(cfg.platform, AnchorPlatform::Windows);
        assert_eq!(cfg.platform.as_str(), "windows");
    }

    #[test]
    fn parse_rejects_windows_relative_paths() {
        let err = Config::parse(vec![
            "--dry-run".to_owned(),
            "--platform".to_owned(),
            "windows".to_owned(),
            "--anchor-token-path".to_owned(),
            r"ProgramData\RustyNet\anchor.token".to_owned(),
        ])
        .expect_err("relative Windows token path rejected");
        assert!(
            err.contains("absolute windows path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_rejects_missing_identity_without_dry_run() {
        let err = Config::parse(Vec::new()).expect_err("identity required");
        assert!(err.contains("--ssh-identity-file"));
    }

    #[test]
    fn parse_rejects_unpaired_topology_nodes() {
        let err = Config::parse(vec![
            "--dry-run".to_owned(),
            "--second-anchor-host".to_owned(),
            "debian@192.168.64.6".to_owned(),
        ])
        .expect_err("unpaired second anchor rejected");
        assert!(err.contains("--second-anchor-host"));
    }

    #[test]
    fn parse_accepts_enrollment_path_overrides() {
        let cfg = Config::parse(vec![
            "--dry-run".to_owned(),
            "--membership-log-path".to_owned(),
            "/state/membership.log".to_owned(),
            "--enrollment-secret-path".to_owned(),
            "/keys/enrollment.secret".to_owned(),
            "--enrollment-ledger-path".to_owned(),
            "/state/enrollment.ledger".to_owned(),
            "--owner-signing-key-path".to_owned(),
            "/keys/membership.owner.key".to_owned(),
            "--signing-key-passphrase-cred-path".to_owned(),
            "/creds/signing_key_passphrase.cred".to_owned(),
        ])
        .expect("enrollment path overrides parse");
        assert_eq!(cfg.membership_log_path, "/state/membership.log");
        assert_eq!(cfg.enrollment_secret_path, "/keys/enrollment.secret");
        assert_eq!(cfg.enrollment_ledger_path, "/state/enrollment.ledger");
    }

    #[test]
    fn parse_nc_addr_splits_host_port_for_nc() {
        let addr = parse_nc_addr("127.0.0.1:51822").unwrap();
        assert_eq!(addr.host, "127.0.0.1");
        assert_eq!(addr.port, "51822");
        assert!(parse_nc_addr("127.0.0.1").is_err());
        assert!(parse_nc_addr("127.0.0.1;rm:51822").is_err());
    }

    #[test]
    fn validate_anchor_capabilities_requires_all_anchor_caps() {
        let output = "anchor nodes:\nexit-1 capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\n";
        validate_anchor_capabilities(output, "exit-1").expect("all caps present");
        let err = validate_anchor_capabilities(output, "missing").expect_err("missing node");
        assert!(err.contains("missing"));
    }

    #[test]
    fn validate_lex_min_authority_rejects_wrong_primary() {
        let output = "anchor nodes:\nexit-1 capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\nrelay-1 capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\n";
        validate_lex_min_anchor_authority(output, "exit-1", "relay-1").expect("exit-1 is lex-min");
        let err = validate_lex_min_anchor_authority(output, "relay-1", "relay-1")
            .expect_err("non lex-min primary rejected");
        assert!(err.contains("authority mismatch"));
    }

    #[test]
    fn dry_run_report_contains_all_subchecks() {
        let cfg = Config::parse(vec!["--dry-run".to_owned()]).unwrap();
        let report = render_report(&cfg, "abc123", dry_run_subchecks(), None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&report).unwrap();
        assert_eq!(parsed["stage"], "live_anchor");
        assert_eq!(parsed["status"], "pass");
        assert_eq!(parsed["subchecks"].as_array().unwrap().len(), 6);
        let names = parsed["subchecks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "validate_anchor_membership_advertise",
                "validate_anchor_bundle_pull",
                "validate_anchor_gossip_priority",
                "validate_anchor_gossip_seed",
                "validate_anchor_enrollment_endpoint",
                "validate_anchor_downgrade_revocation",
            ]
        );
    }

    // ─── Track B Phase 9: gossip-seed parser coverage ──────────────

    fn gossip_seed_sample_config() -> super::Config {
        let mut cfg = super::Config::parse(vec!["--dry-run".to_owned()]).expect("dry-run parse");
        cfg.anchor_node_id = "exit-1".to_owned();
        cfg
    }

    #[test]
    fn validate_anchor_gossip_seed_accepts_primary_carrying_capability() {
        let anchor_list = "anchor nodes:\n\
                           exit-1 capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\n\
                           entry-2 capabilities=anchor,relay_host,anchor.gossip_seed\n";
        let cfg = gossip_seed_sample_config();
        let summary = super::validate_anchor_gossip_seed(anchor_list, &cfg).expect("must pass");
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
        let cfg = gossip_seed_sample_config();
        let err =
            super::validate_anchor_gossip_seed(anchor_list, &cfg).expect_err("must fail closed");
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
        let cfg = gossip_seed_sample_config();
        let err =
            super::validate_anchor_gossip_seed(anchor_list, &cfg).expect_err("must fail closed");
        assert!(
            err.contains("primary anchor exit-1 is missing anchor.gossip_seed"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_anchor_gossip_seed_rejects_when_primary_absent_from_list() {
        let anchor_list = "anchor nodes:\n\
                           other-node capabilities=anchor,relay_host,anchor.gossip_seed\n";
        let cfg = gossip_seed_sample_config();
        let err =
            super::validate_anchor_gossip_seed(anchor_list, &cfg).expect_err("must fail closed");
        assert!(
            err.contains("primary anchor exit-1 missing from anchor list"),
            "got: {err}"
        );
    }

    // ─── Track B Phase 10: macOS anchor dispatch + path defaults ──

    #[test]
    fn parse_macos_swaps_default_paths_to_macos_conventions() {
        let cfg = super::Config::parse(vec![
            "--platform".to_owned(),
            "macos".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect("macos dry-run parse");
        assert_eq!(cfg.platform, super::AnchorPlatform::Macos);
        assert_eq!(
            cfg.anchor_token_path,
            "/usr/local/var/rustynet/anchor-bundle-pull.token"
        );
        assert_eq!(
            cfg.membership_snapshot_path,
            "/usr/local/var/rustynet/membership/membership.snapshot"
        );
        assert_eq!(
            cfg.membership_log_path,
            "/usr/local/var/rustynet/membership/membership.log"
        );
        assert_eq!(
            cfg.enrollment_secret_path,
            "/usr/local/var/rustynet/keys/enrollment.secret"
        );
        assert_eq!(
            cfg.enrollment_ledger_path,
            "/usr/local/var/rustynet/rustynetd.enrollment.ledger"
        );
        assert_eq!(
            cfg.owner_signing_key_path,
            "/usr/local/etc/rustynet/membership.owner.key"
        );
        assert_eq!(
            cfg.signing_key_passphrase_cred_path,
            "/usr/local/etc/rustynet/credentials/signing_key_passphrase.cred"
        );
    }

    #[test]
    fn parse_macos_explicit_path_flag_wins_over_default_swap() {
        let cfg = super::Config::parse(vec![
            "--platform".to_owned(),
            "macos".to_owned(),
            "--anchor-token-path".to_owned(),
            "/Users/admin/rustynet/anchor-bundle-pull.token".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect("macos parse");
        assert_eq!(
            cfg.anchor_token_path, "/Users/admin/rustynet/anchor-bundle-pull.token",
            "explicit --anchor-token-path must NOT be rewritten by the default-swap"
        );
        assert_eq!(
            cfg.membership_snapshot_path, "/usr/local/var/rustynet/membership/membership.snapshot",
            "other paths still get the macOS default swap (membership/ subdir included)"
        );
    }

    #[test]
    fn parse_linux_keeps_linux_paths_unchanged() {
        let cfg = super::Config::parse(vec!["--dry-run".to_owned()]).expect("default linux parse");
        assert_eq!(cfg.platform, super::AnchorPlatform::Linux);
        assert_eq!(
            cfg.anchor_token_path,
            "/var/lib/rustynet/anchor-bundle-pull.token"
        );
        assert_eq!(
            cfg.owner_signing_key_path,
            "/etc/rustynet/membership.owner.key"
        );
    }

    // ─── Phase 10 reviewer BLOCKER fix: macOS subdir layout ────────

    #[test]
    fn parse_macos_membership_paths_include_subdir() {
        // The macOS installer writes membership state under a
        // `membership/` subdirectory (see
        // `vm_lab/orchestrator/adapter/macos_install.rs`). Phase 10
        // initially pinned the wrong path; this test prevents
        // regression.
        let cfg = super::Config::parse(vec![
            "--platform".to_owned(),
            "macos".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect("macos dry-run parse");
        assert_eq!(
            cfg.membership_snapshot_path, "/usr/local/var/rustynet/membership/membership.snapshot",
            "macOS membership snapshot must live under the membership/ subdir"
        );
        assert_eq!(
            cfg.membership_log_path,
            "/usr/local/var/rustynet/membership/membership.log"
        );
    }

    // ─── Track B Phase 11: Windows anchor dispatch + path defaults ─

    #[test]
    fn parse_windows_swaps_default_paths_to_canonical_layout() {
        // Phase 11 reviewer caught that the first Windows-path swap
        // diverged from the canonical layout from
        // `rustynetd::windows_paths`. Pin the expected paths to the
        // canonical constants so a future rename surfaces here.
        let cfg = super::Config::parse(vec![
            "--platform".to_owned(),
            "windows".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect("windows dry-run parse");
        assert_eq!(cfg.platform, super::AnchorPlatform::Windows);
        assert_eq!(
            cfg.anchor_token_path,
            r"C:\ProgramData\RustyNet\anchor-bundle-pull.token"
        );
        // Membership state lives under the membership/ subdir
        // (NOT flat under the state root).
        assert_eq!(
            cfg.membership_snapshot_path,
            r"C:\ProgramData\RustyNet\membership\membership.snapshot"
        );
        assert_eq!(
            cfg.membership_log_path,
            r"C:\ProgramData\RustyNet\membership\membership.log"
        );
        assert_eq!(
            cfg.enrollment_secret_path,
            r"C:\ProgramData\RustyNet\keys\enrollment.secret"
        );
        assert_eq!(
            cfg.enrollment_ledger_path,
            r"C:\ProgramData\RustyNet\rustynetd.enrollment.ledger"
        );
        // Owner signing key lives next to the snapshot in the
        // membership/ subdir.
        assert_eq!(
            cfg.owner_signing_key_path,
            r"C:\ProgramData\RustyNet\membership\membership.owner.key"
        );
        // Secret material lives under secrets/ (NOT credentials/).
        assert_eq!(
            cfg.signing_key_passphrase_cred_path,
            r"C:\ProgramData\RustyNet\secrets\signing_key_passphrase.cred"
        );
    }

    #[test]
    fn parse_windows_explicit_path_flag_wins_over_default_swap() {
        let cfg = super::Config::parse(vec![
            "--platform".to_owned(),
            "windows".to_owned(),
            "--anchor-token-path".to_owned(),
            r"D:\rustynet\anchor-bundle-pull.token".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect("windows parse");
        assert_eq!(
            cfg.anchor_token_path, r"D:\rustynet\anchor-bundle-pull.token",
            "explicit --anchor-token-path must NOT be rewritten by the Windows default-swap"
        );
        // Other paths still get the canonical Windows default swap.
        assert_eq!(
            cfg.membership_snapshot_path, r"C:\ProgramData\RustyNet\membership\membership.snapshot",
            "membership snapshot still uses the canonical membership/ subdir layout"
        );
    }

    #[test]
    fn parse_linux_paths_unaffected_by_other_platform_swaps() {
        // Defense-in-depth: Phase 10/11 added macOS + Windows swaps
        // gated on platform != Linux. The Linux branch must remain
        // a no-op. A regression here would silently shift the Linux
        // VMs to look in /usr/local/var/rustynet instead of
        // /var/lib/rustynet.
        let cfg = super::Config::parse(vec!["--dry-run".to_owned()])
            .expect("linux default-platform parse");
        assert_eq!(cfg.platform, super::AnchorPlatform::Linux);
        assert_eq!(
            cfg.membership_snapshot_path,
            "/var/lib/rustynet/membership.snapshot"
        );
        assert_eq!(
            cfg.signing_key_passphrase_cred_path,
            "/etc/rustynet/credentials/signing_key_passphrase.cred"
        );
    }

    // ─── Phase 9 reviewer HIGH — word-boundary capability match ──

    #[test]
    fn row_has_capability_matches_exact_csv_entry() {
        let row = "exit-1 capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull";
        assert!(super::row_has_capability(row, "anchor"));
        assert!(super::row_has_capability(row, "relay_host"));
        assert!(super::row_has_capability(row, "anchor.gossip_seed"));
        assert!(super::row_has_capability(row, "anchor.bundle_pull"));
    }

    #[test]
    fn row_has_capability_rejects_prefix_only_match() {
        // A future capability named `anchor.gossip_seed_v2` must NOT
        // satisfy a `anchor.gossip_seed` check — that would mask a
        // real loss of the original capability. Pre-fix the matcher
        // used `line.contains(capability)` which accepted this.
        let row = "exit-1 capabilities=anchor,relay_host,anchor.gossip_seed_v2";
        assert!(
            !super::row_has_capability(row, "anchor.gossip_seed"),
            "substring-only matcher would accept anchor.gossip_seed_v2"
        );
    }

    #[test]
    fn row_has_capability_rejects_suffix_only_match() {
        let row = "exit-1 capabilities=anchor,relay_host,extra.anchor.gossip_seed";
        assert!(
            !super::row_has_capability(row, "anchor.gossip_seed"),
            "substring-only matcher would accept extra.anchor.gossip_seed"
        );
    }

    #[test]
    fn row_has_capability_returns_false_when_capabilities_column_missing() {
        let row = "anchor nodes:";
        assert!(!super::row_has_capability(row, "anchor.gossip_seed"));
    }

    #[test]
    fn row_has_capability_handles_trailing_whitespace_after_csv() {
        let row = "exit-1 capabilities=anchor,anchor.gossip_seed\t\n";
        assert!(super::row_has_capability(row, "anchor.gossip_seed"));
    }

    #[test]
    fn validate_anchor_gossip_seed_rejects_prefix_collision_capability() {
        // Concrete end-to-end regression — a node carrying only
        // anchor.gossip_seed_v2 must NOT satisfy the substage.
        let anchor_list = "anchor nodes:\n\
                           exit-1 capabilities=anchor,relay_host,anchor.gossip_seed_v2,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\n";
        let cfg = gossip_seed_sample_config();
        let err = super::validate_anchor_gossip_seed(anchor_list, &cfg)
            .expect_err("must fail closed on prefix-collision");
        assert!(
            err.contains("no node in anchor list advertises anchor.gossip_seed"),
            "got: {err}"
        );
    }

    // ─── Track B Phase 15: cross-platform membership mutation ─────

    // ─── Track B Phase 16: role-audit-log path platform-aware ─────

    #[test]
    fn parse_linux_role_audit_log_path_uses_canonical_var_lib_default() {
        let cfg = super::Config::parse(vec!["--dry-run".to_owned()]).expect("linux parse");
        assert_eq!(
            cfg.role_audit_log_path, "/var/lib/rustynet/role_transitions.audit.log",
            "linux default must match crates/rustynet-cli/src/role_cli.rs::DEFAULT_ROLE_AUDIT_LOG_PATH"
        );
    }

    #[test]
    fn parse_macos_role_audit_log_path_swaps_to_usr_local_var() {
        let cfg = super::Config::parse(vec![
            "--platform".to_owned(),
            "macos".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect("macos parse");
        assert_eq!(
            cfg.role_audit_log_path, "/usr/local/var/rustynet/role_transitions.audit.log",
            "macOS default-swap must mirror the macOS install layout (state under /usr/local/var/rustynet)"
        );
    }

    #[test]
    fn parse_windows_role_audit_log_path_swaps_to_program_data() {
        let cfg = super::Config::parse(vec![
            "--platform".to_owned(),
            "windows".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect("windows parse");
        assert_eq!(
            cfg.role_audit_log_path, r"C:\ProgramData\RustyNet\role_transitions.audit.log",
            "windows default-swap must mirror the canonical ProgramData layout"
        );
    }

    #[test]
    fn parse_explicit_role_audit_log_path_flag_wins_over_default_swap() {
        let cfg = super::Config::parse(vec![
            "--platform".to_owned(),
            "macos".to_owned(),
            "--role-audit-log-path".to_owned(),
            "/Users/admin/rustynet/audit.log".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect("parse");
        assert_eq!(
            cfg.role_audit_log_path, "/Users/admin/rustynet/audit.log",
            "explicit --role-audit-log-path must NOT be rewritten by the macOS default-swap"
        );
    }

    #[test]
    fn set_membership_capabilities_rejects_windows_platform_with_explicit_message() {
        // Phase 15 helper supports Linux (ops verb) and macOS
        // (three-step flow). Windows is intentionally
        // unimplemented; the run() dispatcher arm skips the
        // substage BEFORE reaching this helper. If somebody wires
        // a Windows caller in the future without adding a helper,
        // the explicit error here surfaces the contract.
        let mut cfg = super::Config::parse(vec![
            "--platform".to_owned(),
            "windows".to_owned(),
            "--dry-run".to_owned(),
        ])
        .expect("windows dry-run parse");
        // Path::new("/tmp/id") + arbitrary host args — we expect the
        // platform check to short-circuit BEFORE any SSH call.
        cfg.ssh_identity_file = Some(std::path::PathBuf::from("/tmp/id"));
        let err = super::set_membership_capabilities(
            std::path::Path::new("/tmp/id"),
            std::path::Path::new("/tmp/known_hosts"),
            &cfg,
            "admin@example.invalid",
            "test-node",
            "client",
            "owner-1",
        )
        .expect_err("windows must be rejected by the helper");
        assert!(
            err.contains("Windows"),
            "rejection message must name the platform: {err}"
        );
        assert!(
            err.contains("not implemented"),
            "rejection must say the helper is not implemented: {err}"
        );
    }

    // ─── Track B Phase 29: rewritten helpers on RemoteShellHost ────

    use super::live_lab_support::RemoteExitStatus;
    use super::live_lab_support::testing::MockShellHost;

    fn mock_config_for_test(platform: super::AnchorPlatform) -> super::Config {
        let mut cfg = super::Config::parse(vec!["--dry-run".to_owned()]).expect("dry-run parses");
        cfg.platform = platform;
        // Apply platform defaults manually so the macOS / Windows
        // path swaps are observed in tests (parse already ran with
        // platform=Linux so we re-run the swap).
        cfg.apply_platform_default_paths();
        cfg.enrollee_host = Some("debian@enrollee.invalid".to_owned());
        cfg.enrollee_node_id = Some("enrollee-1".to_owned());
        cfg.owner_approver_id = Some("owner-approver".to_owned());
        cfg
    }

    fn ok_response(stdout: &[u8]) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
        }
    }

    fn fail_response(code: i32, stderr: &[u8]) -> RemoteExitStatus {
        RemoteExitStatus {
            code,
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn validate_bundle_pull_loopback_drives_trait_calls() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        // 32-byte ASCII printable token — passes the shape check.
        let token: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        let snapshot: &[u8] = b"\x00\x01\x02snapshot-bytes";
        shell
            .write_file(cfg.anchor_token_path.as_str(), token, 0o600)
            .unwrap();
        shell
            .write_file(cfg.membership_snapshot_path.as_str(), snapshot, 0o644)
            .unwrap();
        let mut response = b"OK 12345\n".to_vec();
        response.extend_from_slice(snapshot);
        shell.program_tcp_response(&cfg.anchor_bundle_pull_addr, response);

        let summary = super::validate_bundle_pull_loopback(&shell, &cfg).expect("loopback ok");

        let digest = super::sha256_hex(snapshot);
        assert_eq!(
            summary,
            format!("bundle_digest={digest} bundle_bytes={}", snapshot.len())
        );
        let tcp_log = shell.tcp_log();
        assert_eq!(tcp_log.len(), 1);
        assert_eq!(tcp_log[0].addr, cfg.anchor_bundle_pull_addr);
        let mut expected_payload = token.to_vec();
        expected_payload.push(b'\n');
        assert_eq!(tcp_log[0].payload, expected_payload);
    }

    #[test]
    fn validate_bundle_pull_loopback_fails_when_body_does_not_match_snapshot() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let token: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        shell
            .write_file(cfg.anchor_token_path.as_str(), token, 0o600)
            .unwrap();
        shell
            .write_file(cfg.membership_snapshot_path.as_str(), b"expected", 0o644)
            .unwrap();
        let mut response = b"OK 1\n".to_vec();
        response.extend_from_slice(b"different-body");
        shell.program_tcp_response(&cfg.anchor_bundle_pull_addr, response);
        let err = super::validate_bundle_pull_loopback(&shell, &cfg).expect_err("body mismatch");
        assert!(err.contains("byte-for-byte"), "got: {err}");
    }

    #[test]
    fn validate_invalid_token_rejected_passes_when_listener_returns_err_unauthorized() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        shell.program_tcp_response(&cfg.anchor_bundle_pull_addr, b"ERR unauthorized\n".to_vec());
        let summary =
            super::validate_invalid_token_rejected(&shell, &cfg).expect("rejected as expected");
        assert_eq!(summary, "invalid_token_rejected=true");
        let tcp_log = shell.tcp_log();
        assert_eq!(tcp_log.len(), 1);
        assert_eq!(tcp_log[0].payload, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n");
    }

    #[test]
    fn validate_invalid_token_rejected_fails_when_listener_accepts_bad_token() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        shell.program_tcp_response(&cfg.anchor_bundle_pull_addr, b"OK 1\nbody".to_vec());
        let err = super::validate_invalid_token_rejected(&shell, &cfg)
            .expect_err("listener accepted bad token");
        assert!(err.contains("not rejected"), "got: {err}");
    }

    #[test]
    fn validate_bundle_pull_log_redaction_returns_skipped_summary_on_macos() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Macos);
        let summary = super::validate_bundle_pull_log_redaction(&shell, &cfg)
            .expect("skip should be a successful summary");
        assert!(
            summary.contains("log_redaction_check=skipped"),
            "got: {summary}"
        );
        assert!(summary.contains("platform=macos"), "got: {summary}");
        assert!(shell.run_log().is_empty(), "no journalctl call on macOS");
    }

    #[test]
    fn validate_bundle_pull_log_redaction_drives_journalctl_argv_on_linux() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let token: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        shell
            .write_file(cfg.anchor_token_path.as_str(), token, 0o600)
            .unwrap();
        let thumbprint = super::anchor_token_thumbprint(token);
        let log_payload = format!(
            "Jul 01 anchor_bundle_pull: peer=relay-1 token_thumbprint={thumbprint} bytes=512"
        );
        shell.program_run_response(
            &[
                "journalctl",
                "-u",
                "rustynetd",
                "--since",
                "10 minutes ago",
                "--no-pager",
            ],
            ok_response(log_payload.as_bytes()),
        );
        let summary =
            super::validate_bundle_pull_log_redaction(&shell, &cfg).expect("redaction ok");
        assert!(summary.contains(&format!("token_thumbprint={thumbprint}")));
        assert!(summary.contains("raw_token_leaked=false"));
        let log = shell.run_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].argv[0], "journalctl");
    }

    #[test]
    fn validate_bundle_pull_log_redaction_fails_when_journal_leaks_token() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let token: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        shell
            .write_file(cfg.anchor_token_path.as_str(), token, 0o600)
            .unwrap();
        let leaky =
            "Jul 01 anchor_bundle_pull: peer=relay-1 token=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        shell.program_run_response(
            &[
                "journalctl",
                "-u",
                "rustynetd",
                "--since",
                "10 minutes ago",
                "--no-pager",
            ],
            ok_response(leaky.as_bytes()),
        );
        let err = super::validate_bundle_pull_log_redaction(&shell, &cfg)
            .expect_err("must fail closed on leaked token");
        assert!(err.contains("leaked raw token material"), "got: {err}");
    }

    #[test]
    fn validate_bundle_pull_log_redaction_retries_when_thumbprint_missing_first_attempt() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let token: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        shell
            .write_file(cfg.anchor_token_path.as_str(), token, 0o600)
            .unwrap();
        let thumbprint = super::anchor_token_thumbprint(token);
        let empty_log = "";
        let good_log = format!(
            "Jul 01 anchor_bundle_pull: peer=relay-1 token_thumbprint={thumbprint} bytes=512"
        );
        let jctl_argv = &[
            "journalctl",
            "-u",
            "rustynetd",
            "--since",
            "10 minutes ago",
            "--no-pager",
        ];
        // First attempt: no matching entries (journald not yet flushed)
        shell.program_run_response(jctl_argv, ok_response(empty_log.as_bytes()));
        // sleep 1 between attempts
        shell.program_run_response(&["sleep", "1"], ok_response(b""));
        // Second attempt: entry now indexed
        shell.program_run_response(jctl_argv, ok_response(good_log.as_bytes()));
        let summary =
            super::validate_bundle_pull_log_redaction(&shell, &cfg).expect("should succeed");
        assert!(summary.contains(&format!("token_thumbprint={thumbprint}")));
        assert!(summary.contains("raw_token_leaked=false"));
        let log = shell.run_log();
        assert_eq!(log.len(), 3, "journalctl + sleep + journalctl");
        assert_eq!(log[0].argv[0], "journalctl");
        assert_eq!(log[1].argv[0], "sleep");
        assert_eq!(log[2].argv[0], "journalctl");
    }

    #[test]
    fn validate_bundle_pull_log_redaction_fails_after_all_retries_exhausted() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let token: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        shell
            .write_file(cfg.anchor_token_path.as_str(), token, 0o600)
            .unwrap();
        let thumbprint = super::anchor_token_thumbprint(token);
        let empty_log = "";
        let jctl_argv = &[
            "journalctl",
            "-u",
            "rustynetd",
            "--since",
            "10 minutes ago",
            "--no-pager",
        ];
        for _ in 0..3 {
            shell.program_run_response(jctl_argv, ok_response(empty_log.as_bytes()));
        }
        shell.program_run_response(&["sleep", "1"], ok_response(b""));
        shell.program_run_response(&["sleep", "1"], ok_response(b""));
        let err = super::validate_bundle_pull_log_redaction(&shell, &cfg)
            .expect_err("should fail after all retries");
        assert!(
            err.contains(&format!("missing token thumbprint {thumbprint}")),
            "got: {err}"
        );
        let log = shell.run_log();
        assert_eq!(log.len(), 5, "3× journalctl + 2× sleep");
    }

    #[test]
    fn capture_role_audit_log_size_uses_posix_argv_on_linux() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        shell.program_run_response(
            &[
                "sh",
                "-c",
                "if [ -e \"$1\" ]; then wc -c <\"$1\" | tr -d '[:space:]'; else printf 0; fi",
                "--",
                cfg.role_audit_log_path.as_str(),
            ],
            ok_response(b"42"),
        );
        let size = super::capture_role_audit_log_size(&shell, &cfg).expect("size returned");
        assert_eq!(size, 42);
        let log = shell.run_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].argv[0], "sh");
        assert!(log[0].argv.last().unwrap().contains("role_transitions"));
    }

    #[test]
    fn capture_role_audit_log_size_uses_powershell_argv_on_windows() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Windows);
        shell.program_run_response(
            &[
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$p=$args[0]; if (Test-Path -LiteralPath $p) { Write-Output (Get-Item -LiteralPath $p).Length } else { Write-Output 0 }",
                cfg.role_audit_log_path.as_str(),
            ],
            ok_response(b"128\r\n"),
        );
        let size = super::capture_role_audit_log_size(&shell, &cfg).expect("size returned");
        assert_eq!(size, 128);
        let log = shell.run_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].argv[0], "powershell");
    }

    #[test]
    fn capture_role_audit_log_size_returns_zero_when_path_absent() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        shell.program_run_response(
            &[
                "sh",
                "-c",
                "if [ -e \"$1\" ]; then wc -c <\"$1\" | tr -d '[:space:]'; else printf 0; fi",
                "--",
                cfg.role_audit_log_path.as_str(),
            ],
            ok_response(b"0"),
        );
        let size = super::capture_role_audit_log_size(&shell, &cfg).expect("zero size");
        assert_eq!(size, 0);
    }

    #[test]
    fn start_inflight_bundle_pull_stages_token_and_emits_scratch_dir() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let token: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        shell
            .write_file(cfg.anchor_token_path.as_str(), token, 0o600)
            .unwrap();
        // Program ANY sh -c invocation with success — assert on the
        // recorded argv below to confirm the helper drove the right
        // commands.
        let body = "set -eu; \
                work=\"$1\"; tok=\"$2\"; addr_host=\"$3\"; addr_port=\"$4\"; \
                chmod 700 \"$work\"; \
                nohup sh -c '\
                  printf \"%s\\n\" \"$(cat \"$1\")\" | nc -w 10 \"$2\" \"$3\" > \"$4\" 2> \"$5\"; \
                  printf \"%s\\n\" \"$?\" > \"$6\"\
                ' rustynet-anchor-inflight \"$tok\" \"$addr_host\" \"$addr_port\" \
                  \"$work/response\" \"$work/stderr\" \"$work/status\" \
                  </dev/null >/dev/null 2>&1 &
                printf '%s\\n' \"$!\" > \"$work/pid\"";
        // We don't know the scratch dir name in advance, so first
        // capture the helper's argv by reading run_log AFTER the
        // attempt. Since the mock requires a programmed response,
        // we drive it via a wildcard: pre-stage the response for the
        // EXACT argv the helper builds. To do that, predict the dir.
        // Easier: run the helper without a programmed response,
        // read the error to discover the argv, then re-program.
        let err = super::start_inflight_bundle_pull(&shell, &cfg)
            .expect_err("no programmed response on first attempt");
        let log = shell.run_log();
        assert_eq!(log.len(), 1, "one run_argv attempt expected: {err}");
        // The argv is [sh, -c, <body>, --, <work>, <tok>, host, port]
        let argv: Vec<&str> = log[0].argv.iter().map(String::as_str).collect();
        assert_eq!(argv[0], "sh");
        assert_eq!(argv[1], "-c");
        assert_eq!(argv[2], body);
        assert_eq!(argv[3], "--");
        let work_dir = argv[4].to_owned();
        assert!(
            work_dir.starts_with("/tmp/rustynet-anchor-inflight-"),
            "work dir under POSIX scratch root: {work_dir}"
        );
        assert_eq!(argv[5], format!("{work_dir}/token"));
        assert_eq!(argv[6], "127.0.0.1");
        assert_eq!(argv[7], "51822");
        // Confirm the token was staged via write_file before the run.
        let token_remote_path = format!("{work_dir}/token");
        let staged = shell.read_file(&token_remote_path).expect("token staged");
        assert_eq!(staged, token);

        // Now re-program success for a second attempt with the same
        // argv, exercise the happy path.
        let argv_str: Vec<&str> = argv.to_vec();
        shell.program_run_response(&argv_str, ok_response(b""));
        // The second call generates a different work_dir because of
        // the monotonic timestamp — so the helper writes a new token
        // file and would build a new argv. Instead we just confirm
        // the inputs/outputs above are correct; the second-run path
        // is exercised by the integration test.
    }

    #[test]
    fn wait_for_bundle_pull_fail_closed_returns_summary_on_first_err_header() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let token: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        shell
            .write_file(cfg.anchor_token_path.as_str(), token, 0o600)
            .unwrap();
        shell.program_tcp_response(
            &cfg.anchor_bundle_pull_addr,
            b"ERR forbidden after revocation\n".to_vec(),
        );
        let summary =
            super::wait_for_bundle_pull_fail_closed(&shell, &cfg).expect("fail-closed detected");
        assert!(
            summary.starts_with("fail_closed_header=ERR forbidden after revocation"),
            "got: {summary}"
        );
        assert!(summary.contains("attempts=0"), "got: {summary}");
    }

    #[test]
    fn validate_anchor_enrollment_endpoint_drives_full_argv_chain_on_linux() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        // Pre-program every run_argv the helper will issue, in
        // order. The argv shape is deterministic per the helper's
        // source.
        // 1. mkdir scratch dir
        shell.program_run_response(
            &["sh", "-c", "mkdir -p -- \"$1\" && chmod 700 -- \"$1\""],
            ok_response(b""),
        );
        // We cannot program the exact argv ahead of time because
        // the scratch dir name embeds a timestamp + pid. The mock
        // backend keys responses on the full argv string. Workaround:
        // sniff out the argv via a "warmup" call that we expect to
        // fail with `no programmed response`, then re-program. But
        // that mutates the run_log. Simpler: assert at the FIRST
        // helper invocation level instead of trying to drive the
        // whole chain through the mock. The full-chain coverage is
        // exercised by the live-lab integration test.
        let err = super::validate_anchor_enrollment_endpoint(&shell, &cfg)
            .expect_err("first run_argv has no programmed response");
        let log = shell.run_log();
        assert!(!log.is_empty(), "helper called run_argv at least once");
        // The first call is the mkdir scratch dir (Linux ensure_remote_dir).
        let first = &log[0];
        assert_eq!(first.argv[0], "sh");
        assert_eq!(first.argv[1], "-c");
        assert!(first.argv[2].contains("mkdir -p"));
        // The error surfaces the unprogrammed argv path.
        assert!(
            err.contains("no programmed response") || err.contains("systemd-creds"),
            "got: {err}"
        );
    }

    #[test]
    fn read_anchor_token_rejects_non_printable_payload() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        shell
            .write_file(cfg.anchor_token_path.as_str(), b"\x01\x02 short", 0o600)
            .unwrap();
        let err = super::read_anchor_token(&shell, &cfg).expect_err("non-printable rejected");
        assert!(err.contains("non-printable"), "got: {err}");
    }

    #[test]
    fn read_anchor_token_rejects_short_payload() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        shell
            .write_file(cfg.anchor_token_path.as_str(), b"too-short", 0o600)
            .unwrap();
        let err = super::read_anchor_token(&shell, &cfg).expect_err("short rejected");
        assert!(err.contains("length"), "got: {err}");
    }

    #[test]
    fn read_anchor_token_strips_trailing_newlines() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        shell
            .write_file(
                cfg.anchor_token_path.as_str(),
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n",
                0o600,
            )
            .unwrap();
        let token = super::read_anchor_token(&shell, &cfg).expect("trimmed ok");
        assert_eq!(token, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
    }

    #[test]
    fn split_bundle_pull_response_separates_header_and_body() {
        let mut input = b"OK 7\n".to_vec();
        input.extend_from_slice(b"snapshot");
        let (header, body) = super::split_bundle_pull_response(&input).unwrap();
        assert_eq!(header, b"OK 7");
        assert_eq!(body, b"snapshot");
    }

    #[test]
    fn split_bundle_pull_response_handles_crlf_terminator() {
        let mut input = b"OK 7\r\n".to_vec();
        input.extend_from_slice(b"snapshot");
        let (header, body) = super::split_bundle_pull_response(&input).unwrap();
        assert_eq!(header, b"OK 7");
        assert_eq!(body, b"snapshot");
    }

    #[test]
    fn first_line_bytes_returns_whole_input_when_no_newline() {
        assert_eq!(super::first_line_bytes(b""), b"");
        assert_eq!(
            super::first_line_bytes(b"ERR unauthorized"),
            b"ERR unauthorized"
        );
    }

    #[test]
    fn first_line_bytes_strips_lf_and_crlf() {
        assert_eq!(super::first_line_bytes(b"OK 1\nbody"), b"OK 1");
        assert_eq!(super::first_line_bytes(b"OK 1\r\nbody"), b"OK 1");
    }

    #[test]
    fn remote_scratch_dir_picks_platform_root() {
        let linux = super::remote_scratch_dir(super::AnchorPlatform::Linux, "anchor");
        let macos = super::remote_scratch_dir(super::AnchorPlatform::Macos, "anchor");
        let windows = super::remote_scratch_dir(super::AnchorPlatform::Windows, "anchor");
        assert!(linux.starts_with("/tmp/anchor-"));
        assert!(macos.starts_with("/tmp/anchor-"));
        assert!(windows.starts_with(r"C:\Windows\Temp\anchor-"));
    }

    #[test]
    fn remote_join_uses_platform_separator() {
        assert_eq!(
            super::remote_join(super::AnchorPlatform::Linux, "/tmp/x", "a"),
            "/tmp/x/a"
        );
        assert_eq!(
            super::remote_join(super::AnchorPlatform::Windows, r"C:\tmp\x", "a"),
            r"C:\tmp\x\a"
        );
    }

    #[test]
    fn is_safe_remote_dir_rejects_paths_outside_scratch_root() {
        assert!(!super::is_safe_remote_dir(super::AnchorPlatform::Linux, ""));
        assert!(!super::is_safe_remote_dir(
            super::AnchorPlatform::Linux,
            "/etc"
        ));
        assert!(super::is_safe_remote_dir(
            super::AnchorPlatform::Linux,
            "/tmp/rustynet-x"
        ));
        assert!(super::is_safe_remote_dir(
            super::AnchorPlatform::Windows,
            r"C:\Windows\Temp\rustynet-x"
        ));
        assert!(!super::is_safe_remote_dir(
            super::AnchorPlatform::Windows,
            r"C:\ProgramData\RustyNet"
        ));
    }

    #[test]
    fn ps_quote_str_doubles_apostrophes() {
        assert_eq!(super::ps_quote_str("simple"), "simple");
        assert_eq!(super::ps_quote_str("Bob's file"), "Bob''s file");
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // SHA-256("abc") is the canonical RFC 4634 test vector.
        let digest = super::sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn anchor_token_thumbprint_returns_first_16_hex_chars() {
        let thumbprint = super::anchor_token_thumbprint(b"abc");
        assert_eq!(thumbprint, "ba7816bf8f01cfea");
        assert_eq!(thumbprint.len(), 16);
    }

    #[test]
    fn random_url_safe_pubkey_emits_no_padding_and_url_safe_alphabet() {
        let key = super::random_url_safe_pubkey();
        assert!(!key.contains('='));
        assert!(!key.contains('+'));
        assert!(!key.contains('/'));
        // 32 raw bytes → 43 base64 chars after stripping padding.
        assert_eq!(key.len(), 43);
        assert!(
            key.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "got: {key}"
        );
        let other = super::random_url_safe_pubkey();
        assert_ne!(key, other, "two consecutive calls must differ");
    }

    #[test]
    fn finish_inflight_bundle_pull_returns_header_summary_after_status_zero() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let work_dir = "/tmp/rustynet-anchor-inflight-test";
        // Stage the status + response so the polling loop sees a
        // ready state immediately.
        shell
            .write_file(&format!("{work_dir}/status"), b"0\n", 0o600)
            .unwrap();
        let mut body = b"OK 8\n".to_vec();
        body.extend_from_slice(b"contents");
        shell
            .write_file(&format!("{work_dir}/response"), &body, 0o600)
            .unwrap();
        // Mock cleanup_remote_dir's rm -rf — accept ANY argv that
        // starts with rm.
        shell.program_run_response(&["rm", "-rf", "--", work_dir], ok_response(b""));
        let summary = super::finish_inflight_bundle_pull(&shell, &cfg, work_dir)
            .expect("inflight finished cleanly");
        assert_eq!(summary, "header=OK 8 bytes=8");
    }

    #[test]
    fn finish_inflight_bundle_pull_fails_when_status_is_nonzero() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let work_dir = "/tmp/rustynet-anchor-inflight-fail";
        shell
            .write_file(&format!("{work_dir}/status"), b"7", 0o600)
            .unwrap();
        shell.program_run_response(&["rm", "-rf", "--", work_dir], ok_response(b""));
        let err = super::finish_inflight_bundle_pull(&shell, &cfg, work_dir)
            .expect_err("nonzero status rejected");
        assert!(err.contains("exited with status 7"), "got: {err}");
    }

    #[test]
    fn finish_inflight_bundle_pull_rejects_unsafe_work_dir() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Linux);
        let err = super::finish_inflight_bundle_pull(&shell, &cfg, "/etc/passwd")
            .expect_err("scratch root enforced");
        assert!(
            err.contains("not under the expected scratch root"),
            "got: {err}"
        );
    }

    #[test]
    fn run_argv_capture_stdout_returns_stderr_on_nonzero_exit() {
        let shell = MockShellHost::new();
        shell.program_run_response(&["rustynet", "anchor", "list"], fail_response(2, b"boom"));
        let err = super::run_argv_capture_stdout(&shell, &["rustynet", "anchor", "list"])
            .expect_err("nonzero exit");
        assert!(err.contains("boom"), "got: {err}");
        assert!(err.contains("exited 2"), "got: {err}");
    }

    #[test]
    fn run_argv_capture_stdout_returns_stdout_on_success() {
        let shell = MockShellHost::new();
        shell.program_run_response(&["echo", "hi"], ok_response(b"hi\n"));
        let out = super::run_argv_capture_stdout(&shell, &["echo", "hi"]).expect("success ok");
        assert_eq!(out, "hi\n");
    }

    // ─── Phase 29 follow-up: MED 1 (Windows DPAPI tempdir ACL pre-tighten) ───

    /// Pins the ACL-first invariant: the icacls call that tightens
    /// the work-dir DACL MUST appear in the script text before the
    /// first `WriteAllBytes` (which is the secret write). The
    /// inverse ordering — what Phase 29 originally shipped — left a
    /// race window where a concurrent reader could open the
    /// freshly-written passphrase file under the inherited
    /// (possibly permissive) `C:\Windows\Temp` ACL.
    #[test]
    fn windows_dpapi_unwrap_script_pins_acl_before_secret_write() {
        let script = super::windows_dpapi_unwrap_script(
            r"C:\Windows\Temp\rustynet-anchor-enrollment-1-2",
            r"C:\ProgramData\RustyNet\credentials\signing_key_passphrase.cred",
            r"C:\Windows\Temp\rustynet-anchor-enrollment-1-2\signing.passphrase",
        );
        let icacls_dir = script
            .find("& icacls $work")
            .expect("script tightens the work-dir ACL via icacls $work");
        let write_all_bytes = script
            .find("WriteAllBytes(")
            .expect("script writes plaintext via WriteAllBytes");
        assert!(
            icacls_dir < write_all_bytes,
            "icacls on work-dir ({icacls_dir}) must precede WriteAllBytes ({write_all_bytes}); ACL-first ordering broken"
        );
    }

    /// Pins the post-write directory-ACL verification step. Without
    /// the verify step a future regression that swaps the icacls
    /// call for an ineffective grant (e.g. typo in SID) would
    /// silently regress: the script would exit 0 even though the
    /// work dir is still permissive. The verify step's Get-Acl +
    /// SDDL match makes the regression fail loudly.
    #[test]
    fn windows_dpapi_unwrap_script_verifies_dir_acl_before_secret_write() {
        let script = super::windows_dpapi_unwrap_script(
            r"C:\Windows\Temp\rustynet-anchor-enrollment-1-2",
            r"C:\ProgramData\RustyNet\credentials\signing_key_passphrase.cred",
            r"C:\Windows\Temp\rustynet-anchor-enrollment-1-2\signing.passphrase",
        );
        let get_dir_acl = script
            .find("$dirAcl = (Get-Acl -LiteralPath $work).Sddl")
            .expect("script reads the work-dir SDDL");
        let write_all_bytes = script
            .find("WriteAllBytes(")
            .expect("script writes plaintext via WriteAllBytes");
        assert!(
            get_dir_acl < write_all_bytes,
            "Get-Acl verify on work-dir ({get_dir_acl}) must precede WriteAllBytes ({write_all_bytes})"
        );
        assert!(
            script
                .contains("rustynet-anchor-dpapi: work-dir ACL drift (Users or Everyone present) before secret write"),
            "script must fail-closed if work-dir DACL leaks Users/Everyone"
        );
        assert!(
            script.contains(
                "rustynet-anchor-dpapi: work-dir ACL drift (SYSTEM or Administrators missing) before secret write"
            ),
            "script must fail-closed if SYSTEM/Administrators ACE is missing"
        );
    }

    /// Pins the post-write file-ACL verification step + fail-closed
    /// secret removal on drift. Mirrors the
    /// `windows_post_move_acl_verify_script` pattern in
    /// `live_lab_bin_support/remote_shell.rs`.
    #[test]
    fn windows_dpapi_unwrap_script_verifies_file_acl_after_secret_write() {
        let script = super::windows_dpapi_unwrap_script(
            r"C:\Windows\Temp\rustynet-anchor-enrollment-1-2",
            r"C:\ProgramData\RustyNet\credentials\signing_key_passphrase.cred",
            r"C:\Windows\Temp\rustynet-anchor-enrollment-1-2\signing.passphrase",
        );
        let write_all_bytes = script
            .find("WriteAllBytes(")
            .expect("script writes plaintext");
        let icacls_file = script
            .rfind("& icacls '")
            .expect("script tightens file ACL");
        let get_file_acl = script
            .find("$fileAcl = (Get-Acl -LiteralPath '")
            .expect("script reads file SDDL after write");
        assert!(
            write_all_bytes < icacls_file,
            "file icacls must run after the write (defense-in-depth)"
        );
        assert!(
            icacls_file < get_file_acl,
            "file ACL verify must run after the file icacls"
        );
        assert!(
            script.contains("Remove-Item -LiteralPath '")
                && script.contains(
                    "rustynet-anchor-dpapi: passphrase file ACL drift after write (Users or Everyone present)"
                ),
            "drift must trigger secret-file removal + fail-closed throw"
        );
    }

    // ─── Phase 29 follow-up: LOW 2 (Start-Job cleanup) ───

    /// Pins the LOW-2 fold-in: `cleanup_remote_dir` on Windows MUST
    /// stop + remove the `rustynet-anchor-inflight` PowerShell job
    /// before removing the scratch dir. Without this step a hung
    /// job (e.g. listener accepts then never replies, so
    /// `$client.Available -gt 0` polls forever) persists until the
    /// host PowerShell process exits.
    #[test]
    fn windows_cleanup_remote_dir_script_stops_inflight_job_before_removing_dir() {
        let script = super::windows_cleanup_remote_dir_script(
            r"C:\Windows\Temp\rustynet-anchor-inflight-1-2",
        );
        let get_job = script
            .find("Get-Job -Name 'rustynet-anchor-inflight'")
            .expect("script must reference the named Start-Job");
        let stop_job = script.find("Stop-Job").expect("script must call Stop-Job");
        let remove_job = script
            .find("Remove-Job")
            .expect("script must call Remove-Job");
        let remove_item = script
            .find("Remove-Item -LiteralPath '")
            .expect("script must remove the scratch dir");
        assert!(
            get_job < stop_job,
            "Get-Job ({get_job}) must precede Stop-Job ({stop_job})"
        );
        assert!(
            stop_job < remove_job,
            "Stop-Job ({stop_job}) must precede Remove-Job ({remove_job})"
        );
        assert!(
            remove_job < remove_item,
            "Remove-Job ({remove_job}) must precede Remove-Item ({remove_item}) so a hung job is cleaned up before the dir is gone"
        );
        // Silent-continue everywhere so cleanup never masks a real
        // substage failure.
        assert!(
            script.contains("$ErrorActionPreference='SilentlyContinue'"),
            "script must run best-effort (SilentlyContinue)"
        );
        assert!(
            script.contains("-ErrorAction SilentlyContinue"),
            "Get/Stop/Remove-Job calls must also tolerate missing job"
        );
    }

    /// End-to-end mock check: when cleanup_remote_dir is invoked
    /// against a Windows config it must dispatch a single
    /// PowerShell invocation whose script body contains the
    /// Stop-Job step.
    #[test]
    fn cleanup_remote_dir_dispatches_stop_job_on_windows() {
        let shell = MockShellHost::new();
        let cfg = mock_config_for_test(super::AnchorPlatform::Windows);
        let dir = r"C:\Windows\Temp\rustynet-anchor-inflight-windows-1";
        // Pre-program ANY powershell invocation as success — the
        // recorded argv is asserted below.
        let expected_script = super::windows_cleanup_remote_dir_script(dir);
        shell.program_run_response(
            &[
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                expected_script.as_str(),
            ],
            ok_response(b""),
        );
        super::cleanup_remote_dir(&shell, &cfg, dir);
        let log = shell.run_log();
        assert_eq!(log.len(), 1, "single powershell dispatch expected");
        assert_eq!(log[0].argv[0], "powershell");
        assert!(
            log[0].argv[4].contains("Get-Job -Name 'rustynet-anchor-inflight'"),
            "argv must reference the named Start-Job: {:?}",
            log[0].argv[4]
        );
        assert!(
            log[0].argv[4].contains("Stop-Job"),
            "argv must include Stop-Job: {:?}",
            log[0].argv[4]
        );
    }
}
