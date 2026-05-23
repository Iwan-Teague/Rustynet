#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_lab_bin_support as live_lab_support;
use live_lab_support::{
    Logger, capture_root, create_workspace, ensure_pinned_known_hosts_file, ensure_safe_token,
    git_head_commit, load_home_known_hosts_path, repo_root, require_command, seed_known_hosts,
    shell_quote, unix_now, verify_sudo, write_file,
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

    if config.platform == AnchorPlatform::Windows {
        return Err(
            "Windows anchor live execution is not enabled yet; use --platform windows --dry-run"
                .to_owned(),
        );
    }

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
    verify_sudo(identity, &work_known_hosts, &config.anchor_host)?;

    let mut subchecks = Vec::new();

    let anchor_list = capture_anchor_list(identity, &work_known_hosts, &config)?;
    validate_anchor_capabilities(&anchor_list, config.anchor_node_id.as_str())?;
    subchecks.push(Subcheck::pass(
        "validate_anchor_membership_advertise",
        "signed membership advertises required anchor capabilities",
        json!({ "anchor_node_id": config.anchor_node_id, "capabilities": REQUIRED_ANCHOR_CAPS }),
    ));

    let pull_summary = validate_bundle_pull_loopback(identity, &work_known_hosts, &config)?;
    subchecks.push(Subcheck::pass(
        "validate_anchor_bundle_pull",
        "loopback bundle-pull listener returned membership snapshot byte-for-byte and rejected invalid token",
        json!({ "pull": pull_summary, "invalid_token": validate_invalid_token_rejected(identity, &work_known_hosts, &config)? }),
    ));

    let gossip_priority = validate_anchor_gossip_priority(identity, &work_known_hosts, &config)?;
    subchecks.push(Subcheck::pass(
        "validate_anchor_gossip_priority",
        "second anchor is signed into membership, leaf sees both anchors, and lex-min authority remains primary",
        json!({ "summary": gossip_priority }),
    ));

    let daemon_status = capture_daemon_status(identity, &work_known_hosts, &config)?;
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
    capture_anchor_list_from_host(identity, known_hosts, &config.anchor_host)
}

fn capture_anchor_list_from_host(
    identity: &Path,
    known_hosts: &Path,
    host: &str,
) -> Result<String, String> {
    let command = "command -v rustynet >/dev/null; rustynet anchor list";
    capture_root(identity, known_hosts, host, command)
        .map_err(|err| format!("anchor list failed on {host}: {err}"))
}

fn validate_anchor_capabilities(anchor_list: &str, anchor_node_id: &str) -> Result<(), String> {
    let row = anchor_list
        .lines()
        .find(|line| line.starts_with(anchor_node_id))
        .ok_or_else(|| format!("anchor node {anchor_node_id} missing from anchor list"))?;
    for capability in REQUIRED_ANCHOR_CAPS {
        if !row.contains(capability) {
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
        let anchor_list = capture_anchor_list_from_host(identity, known_hosts, leaf_client_host)?;
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

fn capture_daemon_status(
    identity: &Path,
    known_hosts: &Path,
    config: &Config,
) -> Result<String, String> {
    capture_root(
        identity,
        known_hosts,
        &config.anchor_host,
        "command -v rustynet >/dev/null; rustynet status",
    )
    .map_err(|err| format!("daemon status failed on {}: {err}", config.anchor_host))
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
    enrollee_host: Option<String>,
    enrollee_node_id: Option<String>,
    owner_approver_id: Option<String>,
    anchor_bundle_pull_addr: String,
    anchor_token_path: String,
    membership_snapshot_path: String,
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

        config.validate()?;
        Ok(config)
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
        if self.anchor_token_path.contains('\0')
            || self.anchor_token_path.contains('\n')
            || !self.platform.path_is_absolute(&self.anchor_token_path)
        {
            return Err(format!(
                "--anchor-token-path must be an absolute {} path",
                self.platform.as_str()
            ));
        }
        if self.membership_snapshot_path.contains('\0')
            || self.membership_snapshot_path.contains('\n')
            || !self
                .platform
                .path_is_absolute(&self.membership_snapshot_path)
        {
            return Err(format!(
                "--membership-snapshot-path must be an absolute {} path",
                self.platform.as_str()
            ));
        }
        if !self.dry_run && self.ssh_identity_file.is_none() {
            return Err("--ssh-identity-file is required unless --dry-run is set".to_owned());
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
    "usage: live_linux_anchor_test --ssh-identity-file <path> [options]\n\noptions:\n  --platform <linux|macos|windows>\n  --anchor-host <user@host>\n  --anchor-node-id <id>\n  --second-anchor-host <user@host>\n  --second-anchor-node-id <id>\n  --leaf-client-host <user@host>\n  --leaf-client-node-id <id>\n  --enrollee-host <user@host>\n  --enrollee-node-id <id>\n  --owner-approver-id <id>\n  --anchor-bundle-pull-addr <host:port>\n  --anchor-token-path <path>\n  --membership-snapshot-path <path>\n  --known-hosts <path>\n  --report-path <path>\n  --log-path <path>\n  --git-commit <sha>\n  --dry-run".to_owned()
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
        assert_eq!(parsed["subchecks"].as_array().unwrap().len(), 5);
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
                "validate_anchor_enrollment_endpoint",
                "validate_anchor_downgrade_revocation",
            ]
        );
    }
}
