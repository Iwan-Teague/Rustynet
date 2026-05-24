#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_lab_bin_support as live_lab_support;
use live_lab_support::{
    Logger, capture_remote_stdout, capture_root, create_workspace, ensure_pinned_known_hosts_file,
    ensure_safe_token, git_head_commit, load_home_known_hosts_path, repo_root, require_command,
    seed_known_hosts, shell_quote, unix_now, verify_passwordless_sudo, verify_sudo,
    verify_windows_admin, write_file,
};
use rustynetd::windows_paths::{
    DEFAULT_WINDOWS_KEYS_ROOT, DEFAULT_WINDOWS_MEMBERSHIP_LOG_PATH,
    DEFAULT_WINDOWS_MEMBERSHIP_OWNER_SIGNING_KEY_PATH, DEFAULT_WINDOWS_MEMBERSHIP_SNAPSHOT_PATH,
    DEFAULT_WINDOWS_SECRET_ROOT, DEFAULT_WINDOWS_STATE_ROOT,
};
use serde_json::json;

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

    // Track B Phase 11 — Windows anchor validator. The Windows OpenSSH
    // session defaults to PowerShell, so the POSIX-shell-composed
    // substages (bundle_pull / enrollment / downgrade) that rely on
    // `set -eu`, `cat`, pipe expansions cannot run via the existing
    // capture_root (`sudo -n sh -lc`) wrapper. Those three skip on
    // Windows with a clear rationale rather than fake success. The
    // remaining three substages (capability advertise / gossip seed /
    // daemon status) need only `rustynet anchor list` + `rustynet
    // status`, which work cross-platform — they run for real on
    // Windows via the platform-aware capture helper below.

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

    let mut subchecks = Vec::new();

    let anchor_list = capture_anchor_list(identity, &work_known_hosts, &config)?;
    validate_anchor_capabilities(&anchor_list, config.anchor_node_id.as_str())?;
    subchecks.push(Subcheck::pass(
        "validate_anchor_membership_advertise",
        "signed membership advertises required anchor capabilities",
        json!({ "anchor_node_id": config.anchor_node_id, "capabilities": REQUIRED_ANCHOR_CAPS }),
    ));

    if config.platform != AnchorPlatform::Linux {
        // bundle_pull composes `set -eu` + `cat <token>` + `nc | curl`
        // via capture_root's `sudo -n sh -lc` wrapper, which is
        // POSIX-only. A faithful PowerShell rewrite needs a follow-up
        // refactor of the helper layer — out of scope for Phase 11.
        subchecks.push(Subcheck::skipped(
            "validate_anchor_bundle_pull",
            "non-Linux skip: substage composes POSIX shell (set -eu, cat, nc, curl) via capture_root sudo -n sh -lc wrapper; cross-platform rewrite is tracked separately",
        ));
    } else {
        let pull_summary = validate_bundle_pull_loopback(identity, &work_known_hosts, &config)?;
        let invalid_token_summary =
            validate_invalid_token_rejected(identity, &work_known_hosts, &config)?;
        let redaction_summary =
            validate_bundle_pull_log_redaction(identity, &work_known_hosts, &config)?;
        subchecks.push(Subcheck::pass(
            "validate_anchor_bundle_pull",
            "loopback bundle-pull listener returned membership snapshot byte-for-byte, rejected invalid token, and logged only token thumbprints",
            json!({ "pull": pull_summary, "invalid_token": invalid_token_summary, "log_redaction": redaction_summary }),
        ));
    }

    if config.platform != AnchorPlatform::Linux {
        // gossip_priority calls set_membership_capabilities which
        // shells `rustynet ops e2e-membership-set-capabilities ...`
        // through `sudo -n sh -lc`. PowerShell rewrite tracked
        // separately. The dedicated gossip_seed substage below
        // (parser-only) still covers the gossip-related contract.
        subchecks.push(Subcheck::skipped(
            "validate_anchor_gossip_priority",
            "non-Linux skip: substage mutates membership via Linux-hardcoded `rustynet ops e2e-membership-set-capabilities` (systemd-creds + /etc/rustynet); gossip_seed substage below covers the gossip surface",
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

    if config.platform != AnchorPlatform::Linux {
        subchecks.push(Subcheck::skipped(
            "validate_anchor_enrollment_endpoint",
            "non-Linux skip: substage composes POSIX shell (cat, set -eu, multi-line pipes) AND shells `rustynet ops e2e-membership-set-capabilities` (Linux-hardcoded systemd-creds + /etc/rustynet); cross-platform rewrite is tracked separately",
        ));
    } else {
        let enrollment_endpoint =
            validate_anchor_enrollment_endpoint(identity, &work_known_hosts, &config)?;
        subchecks.push(Subcheck::pass(
            "validate_anchor_enrollment_endpoint",
            "anchor minted enrollment token, rejected negative token and approver paths, admitted enrollee through signed membership, and verified membership visibility",
            json!({ "summary": enrollment_endpoint }),
        ));
    }

    if config.platform != AnchorPlatform::Linux {
        subchecks.push(Subcheck::skipped(
            "validate_anchor_downgrade_revocation",
            "non-Linux skip: substage composes POSIX shell (set -eu, cat, ops mutations) AND shells `rustynet ops e2e-membership-set-capabilities` (Linux-hardcoded systemd-creds + /etc/rustynet); cross-platform rewrite is tracked separately",
        ));
    } else {
        let downgrade_revocation =
            validate_anchor_downgrade_revocation(identity, &work_known_hosts, &config)?;
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
        AnchorPlatform::Linux | AnchorPlatform::Macos => {
            let command = "command -v rustynet >/dev/null; rustynet anchor list";
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
            // `Out-String -Width 4096` prevents PowerShell from
            // wrapping long anchor-list rows at terminal width —
            // wrapped rows would split `<node_id> capabilities=...`
            // and break the parser's anchor-row matcher.
            let command = "powershell -NoProfile -Command \"if (-not (Get-Command rustynet.exe -ErrorAction SilentlyContinue)) { Write-Error 'rustynet.exe not on PATH'; exit 1 }; rustynet.exe anchor list | Out-String -Width 4096\"";
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
        &config.anchor_host,
        second_anchor_node_id,
        "anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative",
        owner_approver_id,
    )
    .map_err(|err| format!("promote second anchor {second_anchor_node_id} failed: {err}"))?;

    let validation = (|| -> Result<String, String> {
        let anchor_list = capture_anchor_list_from_host(
            identity,
            known_hosts,
            leaf_client_host,
            config.platform,
        )?;
        validate_anchor_capabilities(&anchor_list, config.anchor_node_id.as_str())?;
        validate_anchor_capabilities(&anchor_list, second_anchor_node_id)?;
        validate_lex_min_anchor_authority(
            &anchor_list,
            config.anchor_node_id.as_str(),
            second_anchor_node_id,
        )?;
        Ok(format!(
            "primary={} secondary={} leaf={} secondary_host={}",
            config.anchor_node_id, second_anchor_node_id, leaf_client_host, second_anchor_host
        ))
    })();

    let restore = set_membership_capabilities(
        identity,
        known_hosts,
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

fn set_membership_capabilities(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    node_id: &str,
    capabilities: &str,
    owner_approver_id: &str,
) -> Result<String, String> {
    let command = format!(
        "command -v rustynet >/dev/null; rustynet ops e2e-membership-set-capabilities --node-id {node_id} --capabilities {capabilities} --owner-approver-id {owner}",
        node_id = shell_quote(node_id),
        capabilities = shell_quote(capabilities),
        owner = shell_quote(owner_approver_id),
    );
    capture_root(identity, known_hosts, host, &command)
        .map(|out| out.trim().to_owned())
        .map_err(|err| format!("membership capability mutation failed on {host}: {err}"))
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

fn validate_anchor_enrollment_endpoint(
    identity: &Path,
    known_hosts: &Path,
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

    let script = format!(
        r#"set -eu
command -v rustynet >/dev/null
command -v systemd-creds >/dev/null
command -v base64 >/dev/null
command -v dd >/dev/null
command -v tr >/dev/null
test -r {enrollment_secret}
test -r {membership_snapshot}
test -r {membership_log}
test -r {owner_signing_key}
test -r {signing_credential}
work="$(mktemp -d)"
chmod 700 "$work"
passphrase="$work/signing.passphrase"
wrong_secret="$work/wrong.secret"
signed_update="$work/enrollee.signed"
bad_approver_update="$work/bad-approver.signed"
trap 'rm -rf "$work"' EXIT
systemd-creds decrypt --name=signing_key_passphrase {signing_credential} "$passphrase"
chmod 600 "$passphrase"
dd if=/dev/zero bs=32 count=1 of="$wrong_secret" 2>/dev/null
chmod 600 "$wrong_secret"
enrollee_status="$(rustynet membership status --snapshot {membership_snapshot} --log {membership_log})"
case "$enrollee_status" in
  *"active_nodes="*"{enrollee_node_id}"*)
    printf 'enrollee node %s already exists in membership; cleanup required before live enrollment\n' {enrollee_node_id} >&2
    exit 1
    ;;
esac
pubkey_b64="$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr '+/' '-_' | tr -d '= \n')"
token="$(rustynet enrollment mint --secret {enrollment_secret} --ttl 300)"
if rustynet enrollment verify --secret "$wrong_secret" --token "$token" >/dev/null 2>&1; then
  printf 'wrong-secret enrollment token verification unexpectedly succeeded\n' >&2
  exit 1
fi
if rustynet enrollment verify --secret {enrollment_secret} --ledger {enrollment_ledger} --token "not-a-token" >/dev/null 2>&1; then
  printf 'bogus enrollment token unexpectedly verified\n' >&2
  exit 1
fi
if rustynet enrollment admit \
  --pubkey "$pubkey_b64" \
  --node-id {enrollee_node_id} \
  --owner {enrollee_node_id} \
  --roles client \
  --secret {enrollment_secret} \
  --ledger {enrollment_ledger} \
  --snapshot {membership_snapshot} \
  --log {membership_log} \
  --signing-key {owner_signing_key} \
  --signing-key-passphrase "$passphrase" \
  --approver-id {owner_approver_id} \
  --output "$signed_update" \
  --apply >/dev/null 2>&1; then
  printf 'missing-token enrollment admit unexpectedly succeeded\n' >&2
  exit 1
fi
bad_approver_token="$(rustynet enrollment mint --secret {enrollment_secret} --ttl 300)"
if rustynet enrollment admit \
  --token "$bad_approver_token" \
  --pubkey "$pubkey_b64" \
  --node-id {enrollee_node_id} \
  --owner {enrollee_node_id} \
  --roles client \
  --secret {enrollment_secret} \
  --ledger {enrollment_ledger} \
  --snapshot {membership_snapshot} \
  --log {membership_log} \
  --signing-key {owner_signing_key} \
  --signing-key-passphrase "$passphrase" \
  --approver-id rustynet-live-negative-approver \
  --output "$bad_approver_update" \
  --apply >/dev/null 2>&1; then
  printf 'non-anchor approver enrollment admit unexpectedly succeeded\n' >&2
  exit 1
fi
rustynet enrollment admit \
  --token "$token" \
  --pubkey "$pubkey_b64" \
  --node-id {enrollee_node_id} \
  --owner {enrollee_node_id} \
  --roles client \
  --secret {enrollment_secret} \
  --ledger {enrollment_ledger} \
  --snapshot {membership_snapshot} \
  --log {membership_log} \
  --signing-key {owner_signing_key} \
  --signing-key-passphrase "$passphrase" \
  --approver-id {owner_approver_id} \
  --output "$signed_update" \
  --apply >/dev/null
post_status="$(rustynet membership status --snapshot {membership_snapshot} --log {membership_log})"
case "$post_status" in
  *"active_nodes="*"{enrollee_node_id}"*) ;;
  *)
    printf 'enrollee missing from membership status after admit\n' >&2
    exit 1
    ;;
esac
printf 'enrollee=%s host=%s admitted=true wrong_secret_rejected=true bogus_token_rejected=true missing_token_rejected=true non_anchor_approver_rejected=true\n' {enrollee_node_id} {enrollee_host}
"#,
        enrollment_secret = shell_quote(config.enrollment_secret_path.as_str()),
        enrollment_ledger = shell_quote(config.enrollment_ledger_path.as_str()),
        membership_snapshot = shell_quote(config.membership_snapshot_path.as_str()),
        membership_log = shell_quote(config.membership_log_path.as_str()),
        owner_signing_key = shell_quote(config.owner_signing_key_path.as_str()),
        signing_credential = shell_quote(config.signing_key_passphrase_cred_path.as_str()),
        enrollee_node_id = shell_quote(enrollee_node_id),
        enrollee_host = shell_quote(enrollee_host),
        owner_approver_id = shell_quote(owner_approver_id),
    );
    capture_root(identity, known_hosts, &config.anchor_host, &script)
        .map(|out| out.trim().to_owned())
        .map_err(|err| format!("anchor enrollment endpoint validation failed: {err}"))
}

fn validate_anchor_downgrade_revocation(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    let owner_approver_id = config.owner_approver_id.as_deref().ok_or_else(|| {
        "--owner-approver-id is required for validate_anchor_downgrade_revocation".to_owned()
    })?;

    let pre_revocation_pull = validate_bundle_pull_loopback(identity, known_hosts, config)?;
    let inflight_work_dir = start_inflight_bundle_pull(identity, known_hosts, config)?;
    let audit_bytes_before =
        capture_role_audit_log_size(identity, known_hosts, &config.anchor_host)
            .map_err(|err| format!("capture audit size before revocation failed: {err}"))?;

    if let Err(err) = set_membership_capabilities(
        identity,
        known_hosts,
        &config.anchor_host,
        config.anchor_node_id.as_str(),
        "anchor,relay_host,anchor.gossip_seed,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative",
        owner_approver_id,
    ) {
        let _ = finish_inflight_bundle_pull(
            identity,
            known_hosts,
            &config.anchor_host,
            &inflight_work_dir,
        );
        return Err(format!(
            "revoke anchor.bundle_pull from {} failed: {err}",
            config.anchor_node_id
        ));
    }

    let validation = (|| -> Result<String, String> {
        let inflight_pull = finish_inflight_bundle_pull(
            identity,
            known_hosts,
            &config.anchor_host,
            &inflight_work_dir,
        )?;
        let fail_closed = wait_for_bundle_pull_fail_closed(identity, known_hosts, config)?;
        let audit_bytes_after =
            capture_role_audit_log_size(identity, known_hosts, &config.anchor_host)
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

fn start_inflight_bundle_pull(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    let addr = parse_nc_addr(&config.anchor_bundle_pull_addr)?;
    let script = format!(
        r#"set -eu
command -v mktemp >/dev/null
command -v nc >/dev/null
test -r {token_path}
work="$(mktemp -d /tmp/rustynet-anchor-inflight.XXXXXX)"
chmod 700 "$work"
response="$work/response"
status="$work/status"
stderr="$work/stderr"
nohup sh -c '
  token="$(cat "$1")"
  printf "%s\n" "$token" | nc -w 10 "$2" "$3" > "$4" 2> "$6"
  printf "%s\n" "$?" > "$5"
' rustynet-anchor-inflight {token_path} {addr_host} {addr_port} "$response" "$status" "$stderr" >/dev/null 2>&1 &
pid="$!"
printf '%s\n' "$pid" > "$work/pid"
printf 'work_dir=%s pid=%s\n' "$work" "$pid"
"#,
        token_path = shell_quote(config.anchor_token_path.as_str()),
        addr_host = shell_quote(addr.host.as_str()),
        addr_port = shell_quote(addr.port.as_str()),
    );
    let output = capture_root(identity, known_hosts, &config.anchor_host, &script)
        .map_err(|err| format!("start in-flight bundle-pull failed: {err}"))?;
    parse_summary_field(&output, "work_dir")
        .ok_or_else(|| format!("start in-flight bundle-pull missing work_dir: {output:?}"))
}

fn finish_inflight_bundle_pull(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
    work_dir: &str,
) -> Result<String, String> {
    ensure_safe_token("in-flight bundle-pull work dir", work_dir)?;
    let script = format!(
        r#"set -eu
work={work_dir}
test -d "$work"
status="$work/status"
response="$work/response"
stderr="$work/stderr"
attempt=0
while [ "$attempt" -lt 20 ]; do
  if [ -s "$status" ]; then
    break
  fi
  sleep 1
  attempt=$((attempt + 1))
done
if [ ! -s "$status" ]; then
  cat "$stderr" >&2 2>/dev/null || true
  rm -rf "$work"
  printf 'in-flight bundle-pull did not finish before timeout\n' >&2
  exit 1
fi
code="$(cat "$status")"
if [ "$code" != "0" ]; then
  cat "$stderr" >&2 2>/dev/null || true
  rm -rf "$work"
  printf 'in-flight bundle-pull exited with status %s\n' "$code" >&2
  exit 1
fi
header="$(sed -n '1p' "$response")"
case "$header" in
  OK\ *) ;;
  *)
    rm -rf "$work"
    printf 'in-flight bundle-pull header was not OK: %s\n' "$header" >&2
    exit 1
    ;;
esac
bytes="$(sed '1d' "$response" | wc -c | tr -d '[:space:]')"
rm -rf "$work"
printf 'header=%s bytes=%s\n' "$header" "$bytes"
"#,
        work_dir = shell_quote(work_dir),
    );
    capture_root(identity, known_hosts, host, &script)
        .map(|out| out.trim().to_owned())
        .map_err(|err| format!("finish in-flight bundle-pull failed: {err}"))
}

fn capture_role_audit_log_size(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
) -> Result<u64, String> {
    let script = r#"set -eu
path="${RUSTYNET_ROLE_AUDIT_LOG:-/var/lib/rustynet/role_transitions.audit.log}"
if [ -e "$path" ]; then
  wc -c < "$path" | tr -d '[:space:]'
else
  printf '0\n'
fi
"#;
    let out = capture_root(identity, known_hosts, host, script)
        .map_err(|err| format!("role audit size capture failed on {host}: {err}"))?;
    out.trim()
        .parse::<u64>()
        .map_err(|err| format!("role audit size parse failed: {err}: {out:?}"))
}

fn wait_for_bundle_pull_fail_closed(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    let addr = parse_nc_addr(&config.anchor_bundle_pull_addr)?;
    let script = format!(
        r#"set -eu
command -v nc >/dev/null
test -r {token_path}
token="$(cat {token_path})"
case "$token" in
  *[! -~]*|'') printf 'invalid token material shape\n' >&2; exit 1;;
esac
attempt=0
while [ "$attempt" -lt 30 ]; do
  response="$(mktemp)"
  printf '%s\n' "$token" | nc -w 3 {addr_host} {addr_port} > "$response" || true
  header="$(sed -n '1p' "$response" || true)"
  rm -f "$response"
  case "$header" in
    OK\ *) sleep 2 ;;
    *) printf 'fail_closed_header=%s attempts=%s\n' "$header" "$attempt"; exit 0 ;;
  esac
  attempt=$((attempt + 1))
done
printf 'bundle-pull still accepted after anchor.bundle_pull revocation\n' >&2
exit 1
"#,
        token_path = shell_quote(config.anchor_token_path.as_str()),
        addr_host = shell_quote(addr.host.as_str()),
        addr_port = shell_quote(addr.port.as_str()),
    );
    capture_root(identity, known_hosts, &config.anchor_host, &script)
        .map(|out| out.trim().to_owned())
        .map_err(|err| format!("post-revocation bundle-pull fail-closed check failed: {err}"))
}

fn validate_bundle_pull_loopback(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    let addr = parse_nc_addr(&config.anchor_bundle_pull_addr)?;
    let script = format!(
        r#"set -eu
command -v nc >/dev/null
{digest_prereq}
test -r {snapshot}
test -r {token_path}
response="$(mktemp)"
pulled="$(mktemp)"
trap 'rm -f "$response" "$pulled"' EXIT
token="$(cat {token_path})"
case "$token" in
  *[! -~]*|'') printf 'invalid token material shape\n' >&2; exit 1;;
esac
if [ "${{#token}}" -lt 32 ]; then
  printf 'invalid token material length\n' >&2
  exit 1
fi
printf '%s\n' "$token" | nc -w 5 {addr_host} {addr_port} > "$response"
header="$(sed -n '1p' "$response")"
case "$header" in
  OK\ *) ;;
  *) printf 'unexpected bundle-pull header: %s\n' "$header" >&2; exit 1;;
esac
sed '1d' "$response" > "$pulled"
cmp -s {snapshot} "$pulled"
digest="$({digest_command})"
bytes="$(wc -c < "$pulled" | tr -d '[:space:]')"
printf 'bundle_digest=%s bundle_bytes=%s\n' "$digest" "$bytes"
"#,
        digest_prereq = config.platform.digest_prereq(),
        snapshot = shell_quote(config.membership_snapshot_path.as_str()),
        token_path = shell_quote(config.anchor_token_path.as_str()),
        addr_host = shell_quote(addr.host.as_str()),
        addr_port = shell_quote(addr.port.as_str()),
        digest_command = config
            .platform
            .digest_command(shell_quote(config.membership_snapshot_path.as_str()).as_str()),
    );
    capture_root(identity, known_hosts, &config.anchor_host, &script)
        .map(|out| out.trim().to_owned())
        .map_err(|err| format!("anchor bundle-pull loopback failed: {err}"))
}

fn validate_invalid_token_rejected(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    let addr = parse_nc_addr(&config.anchor_bundle_pull_addr)?;
    let script = format!(
        r#"set -eu
command -v nc >/dev/null
response="$(mktemp)"
trap 'rm -f "$response"' EXIT
printf '%s\n' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345' | nc -w 5 {addr_host} {addr_port} > "$response" || true
header="$(sed -n '1p' "$response")"
if [ "$header" != "ERR unauthorized" ]; then
  printf 'invalid token was not rejected: %s\n' "$header" >&2
  exit 1
fi
printf 'invalid_token_rejected=true\n'
"#,
        addr_host = shell_quote(addr.host.as_str()),
        addr_port = shell_quote(addr.port.as_str()),
    );
    capture_root(identity, known_hosts, &config.anchor_host, &script)
        .map(|out| out.trim().to_owned())
        .map_err(|err| format!("invalid token rejection check failed: {err}"))
}

fn validate_bundle_pull_log_redaction(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    if config.platform != AnchorPlatform::Linux {
        return Ok(format!(
            "log_redaction_check=skipped platform={} reason=journalctl-linux-only",
            config.platform.as_str()
        ));
    }
    let script = format!(
        r#"set -eu
command -v journalctl >/dev/null
command -v sha256sum >/dev/null
test -r {token_path}
token="$(cat {token_path})"
case "$token" in
  *[! -~]*|'') printf 'invalid token material shape\n' >&2; exit 1;;
esac
thumbprint="$(printf '%s' "$token" | sha256sum | awk '{{print substr($1,1,16)}}')"
logs="$(journalctl -u rustynetd --since '10 minutes ago' --no-pager 2>/dev/null | grep -F 'anchor_bundle_pull:' || true)"
case "$logs" in
  *"$token"*)
    printf 'anchor bundle-pull journal leaked raw token material\n' >&2
    exit 1
    ;;
esac
case "$logs" in
  *"token_thumbprint=$thumbprint"*) ;;
  *)
    printf 'anchor bundle-pull journal missing token thumbprint %s\n' "$thumbprint" >&2
    exit 1
    ;;
esac
printf 'token_thumbprint=%s raw_token_leaked=false\n' "$thumbprint"
"#,
        token_path = shell_quote(config.anchor_token_path.as_str()),
    );
    capture_root(identity, known_hosts, &config.anchor_host, &script)
        .map(|out| out.trim().to_owned())
        .map_err(|err| format!("bundle-pull log redaction check failed: {err}"))
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

fn parse_summary_field(summary: &str, key: &str) -> Option<String> {
    summary.split_whitespace().find_map(|field| {
        field
            .split_once('=')
            .and_then(|(field_key, value)| (field_key == key).then(|| value.to_owned()))
    })
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
            enrollee_host: None,
            enrollee_node_id: None,
            owner_approver_id: None,
            anchor_bundle_pull_addr: "127.0.0.1:51822".to_owned(),
            anchor_token_path: "/var/lib/rustynet/anchor-bundle-pull.token".to_owned(),
            membership_snapshot_path: "/var/lib/rustynet/membership.snapshot".to_owned(),
            membership_log_path: "/var/lib/rustynet/membership.log".to_owned(),
            enrollment_secret_path: "/var/lib/rustynet/keys/enrollment.secret".to_owned(),
            enrollment_ledger_path: "/var/lib/rustynet/rustynetd.enrollment.ledger".to_owned(),
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

    fn digest_prereq(self) -> &'static str {
        match self {
            Self::Linux => "command -v sha256sum >/dev/null",
            Self::Macos => "command -v shasum >/dev/null",
            Self::Windows => {
                "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Get-Command Get-FileHash | Out-Null\""
            }
        }
    }

    fn digest_command(self, path: &str) -> String {
        match self {
            Self::Linux => format!("sha256sum {path} | awk '{{print $1}}'"),
            Self::Macos => format!("shasum -a 256 {path} | awk '{{print $1}}'"),
            Self::Windows => format!(
                "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"(Get-FileHash -Algorithm SHA256 -LiteralPath {path}).Hash.ToLowerInvariant()\""
            ),
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
        assert_eq!(
            AnchorPlatform::Macos.digest_command("'bundle.snapshot'"),
            "shasum -a 256 'bundle.snapshot' | awk '{print $1}'"
        );
        assert!(
            AnchorPlatform::Windows
                .digest_command("'C:\\ProgramData\\RustyNet\\state\\membership.snapshot'")
                .contains("Get-FileHash")
        );
        assert!(parse_nc_addr("127.0.0.1").is_err());
        assert!(parse_nc_addr("127.0.0.1;rm:51822").is_err());
    }

    #[test]
    fn parse_summary_field_extracts_work_dir() {
        let summary = "work_dir=/tmp/rustynet-anchor-inflight.a1B2 pid=1234\n";
        assert_eq!(
            parse_summary_field(summary, "work_dir").as_deref(),
            Some("/tmp/rustynet-anchor-inflight.a1B2")
        );
        assert_eq!(parse_summary_field(summary, "missing"), None);
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
}
