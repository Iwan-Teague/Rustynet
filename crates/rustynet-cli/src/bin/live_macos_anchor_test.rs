#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]
//! Live macOS anchor bundle-pull validator (sub-test A1.2 parity).
//!
//! This is the macOS-focused sibling of `live_linux_anchor_test`'s
//! `validate_anchor_bundle_pull` substage. It proves — against a real
//! macOS anchor host running the `com.rustynet.anchor` launchd profile —
//! that the loopback bundle-pull listener serves the signed membership
//! snapshot byte-for-byte to a peer presenting the authority token, and
//! that every fail-closed control holds live:
//!
//!   1. loopback pull byte-for-byte: token + "\n" over the
//!      SSH-tunnelled 127.0.0.1:51822 listener returns `OK <len>\n` +
//!      the membership snapshot bytes, and the body digest matches the
//!      on-disk snapshot digest exactly (verify-before-serve).
//!   2. token gate: a syntactically valid but wrong 32-byte token is
//!      rejected with `ERR unauthorized` (default-deny).
//!   3. short-token gate: a <32-byte token is rejected (the daemon's
//!      `load_anchor_bundle_pull_token` minimum-length rule, asserted
//!      from the request side).
//!   4. LAN-bind refusal: `rustynetd` started with a non-loopback
//!      bundle-pull addr and no `--anchor-bundle-pull-allow-lan` exits
//!      non-zero with the loopback-only diagnostic (the
//!      `validate_anchor_bundle_pull_addr` enforcement point).
//!   5. secrets hygiene: the served `OK <len>\n` header + bundle bytes
//!      never contain the raw token, and the response carries only the
//!      framed length — the daemon logs the token as a thumbprint only
//!      (enforcement in `daemon.rs`; the request-side proof here asserts
//!      the token never round-trips in the served bytes).
//!
//! All network + file I/O flows through the [`RemoteShellHost`] trait so
//! the bundle-pull probe is argv-only / base64-framed and never embeds
//! the token in a shell string. The bin emits a typed JSON report the
//! `validate_macos_anchor_bundle_pull` vm_lab stage consumes.

mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use live_lab_bin_support as live_lab_support;
use live_lab_support::{
    LiveLabPlatform, Logger, RemoteShellHost, create_workspace, ensure_pinned_known_hosts_file,
    ensure_safe_token, git_head_commit, load_home_known_hosts_path, new_remote_shell_host,
    repo_root, require_command, seed_known_hosts, unix_now, verify_passwordless_sudo, write_file,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const ANCHOR_BUNDLE_PULL_SUBSTAGES: &[(&str, &str)] = &[
    (
        "validate_macos_anchor_bundle_pull_loopback",
        "token-gated loopback bundle-pull returns the signed membership snapshot byte-for-byte",
    ),
    (
        "validate_macos_anchor_bundle_pull_token_gate",
        "wrong and short authority tokens are rejected fail-closed",
    ),
    (
        "validate_macos_anchor_bundle_pull_lan_refused",
        "non-loopback bundle-pull bind is refused without --anchor-bundle-pull-allow-lan",
    ),
    (
        "validate_macos_anchor_bundle_pull_secrets_hygiene",
        "served bytes never contain the raw token (thumbprint-only logging upstream)",
    ),
];

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
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
    logger.line("[macos-anchor-live] starting macОS anchor bundle-pull validation harness")?;

    if config.dry_run {
        let report = render_report(&config, &git_commit, dry_run_subchecks(), None)?;
        write_file(&config.report_path, &report)?;
        logger.line(
            format!(
                "[macos-anchor-live] dry-run report written to {}",
                config.report_path.display()
            )
            .as_str(),
        )?;
        return Ok(());
    }

    for command in ["ssh", "ssh-keygen"] {
        require_command(command)?;
    }
    let identity = config
        .ssh_identity_file
        .as_ref()
        .ok_or_else(|| "--ssh-identity-file is required unless --dry-run is set".to_owned())?;
    validate_identity(identity)?;

    let pinned_known_hosts = match &config.pinned_known_hosts_file {
        Some(path) => path.clone(),
        None => load_home_known_hosts_path()?,
    };
    ensure_pinned_known_hosts_file(&pinned_known_hosts)?;

    let workspace = create_workspace("macos-anchor-live")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;

    // macOS uses passwordless sudo (no /etc/hosts hostname requirement).
    verify_passwordless_sudo(identity, &work_known_hosts, &config.anchor_host)?;

    let anchor_shell: Arc<dyn RemoteShellHost> = new_remote_shell_host(
        LiveLabPlatform::MacOs,
        identity.to_path_buf(),
        work_known_hosts.clone(),
        config.anchor_host.clone(),
    );

    let mut subchecks = Vec::new();

    let loopback = validate_bundle_pull_loopback(anchor_shell.as_ref(), &config)?;
    subchecks.push(Subcheck::pass(
        "validate_macos_anchor_bundle_pull_loopback",
        "loopback bundle-pull returned the membership snapshot byte-for-byte",
        json!({ "summary": loopback }),
    ));

    let token_gate = validate_token_gate(anchor_shell.as_ref(), &config)?;
    subchecks.push(Subcheck::pass(
        "validate_macos_anchor_bundle_pull_token_gate",
        "wrong and short authority tokens were rejected fail-closed",
        json!({ "summary": token_gate }),
    ));

    let lan_refused = validate_lan_bind_refused(anchor_shell.as_ref(), &config)?;
    subchecks.push(Subcheck::pass(
        "validate_macos_anchor_bundle_pull_lan_refused",
        "non-loopback bundle-pull bind was refused without --anchor-bundle-pull-allow-lan",
        json!({ "summary": lan_refused }),
    ));

    let hygiene = validate_secrets_hygiene(anchor_shell.as_ref(), &config)?;
    subchecks.push(Subcheck::pass(
        "validate_macos_anchor_bundle_pull_secrets_hygiene",
        "served bundle-pull bytes never contained the raw token",
        json!({ "summary": hygiene }),
    ));

    let report = render_report(&config, &git_commit, subchecks, None)?;
    write_file(&config.report_path, &report)?;
    logger.line(
        format!(
            "[macos-anchor-live] report written to {}",
            config.report_path.display()
        )
        .as_str(),
    )?;
    Ok(())
}

/// Control 1 + verify-before-serve: pull the bundle with the correct
/// token and assert the served body equals the on-disk membership
/// snapshot byte-for-byte (digest-checked).
fn validate_bundle_pull_loopback(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<String, String> {
    let _ = parse_addr(&config.anchor_bundle_pull_addr)?;
    let token = read_anchor_token(shell, config)?;
    let snapshot = shell
        .read_file(config.membership_snapshot_path.as_str())
        .map_err(|err| {
            format!(
                "read snapshot {} failed: {err}",
                config.membership_snapshot_path
            )
        })?;
    let mut request = token.clone();
    request.push(b'\n');
    let (header, body) = pull_with_retry(shell, &config.anchor_bundle_pull_addr, &request)?;
    if !header.starts_with(b"OK ") {
        return Err(format!(
            "unexpected bundle-pull header: {:?}",
            String::from_utf8_lossy(&header)
        ));
    }
    if body != snapshot {
        return Err(format!(
            "bundle-pull body ({} bytes) does not match snapshot ({} bytes) byte-for-byte",
            body.len(),
            snapshot.len()
        ));
    }
    let digest = sha256_hex(&snapshot);
    Ok(format!(
        "bundle_digest={digest} bundle_bytes={} header={}",
        body.len(),
        String::from_utf8_lossy(&header)
    ))
}

/// Control 2 + 3: a wrong (valid-shape) token and a too-short token are
/// both rejected with `ERR unauthorized` / a non-OK header.
fn validate_token_gate(shell: &dyn RemoteShellHost, config: &Config) -> Result<String, String> {
    let _ = parse_addr(&config.anchor_bundle_pull_addr)?;
    // Wrong but well-shaped 32-byte token.
    let wrong: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n";
    let wrong_response = shell
        .tcp_send_recv(
            &config.anchor_bundle_pull_addr,
            wrong,
            Duration::from_secs(5),
        )
        .map_err(|err| format!("wrong-token probe failed: {err}"))?;
    let wrong_header = first_line_bytes(&wrong_response);
    if wrong_header != b"ERR unauthorized" {
        return Err(format!(
            "wrong token was not rejected: header={:?}",
            String::from_utf8_lossy(wrong_header)
        ));
    }
    // Too-short token (< 32 bytes). The daemon refuses to serve.
    let short: &[u8] = b"tooshort\n";
    let short_response = shell
        .tcp_send_recv(
            &config.anchor_bundle_pull_addr,
            short,
            Duration::from_secs(5),
        )
        .map_err(|err| format!("short-token probe failed: {err}"))?;
    let short_header = first_line_bytes(&short_response);
    if short_header.starts_with(b"OK ") {
        return Err(format!(
            "short token was unexpectedly served: header={:?}",
            String::from_utf8_lossy(short_header)
        ));
    }
    Ok(format!(
        "wrong_token_rejected=true wrong_header={} short_token_rejected=true short_header={}",
        String::from_utf8_lossy(wrong_header),
        String::from_utf8_lossy(short_header)
    ))
}

/// Control 4: invoke `rustynetd daemon` with a non-loopback bundle-pull
/// addr and no `--anchor-bundle-pull-allow-lan`. `validate_daemon_config`
/// runs at the very start of `run_daemon`, BEFORE any socket / listener
/// bind or key-material preparation, and rejects a non-loopback addr via
/// the `validate_anchor_bundle_pull_addr` enforcement point. The process
/// therefore exits non-zero with the loopback-only diagnostic and never
/// mutates host state (it returns before the unix-socket bind).
///
/// The invocation mirrors the installed anchor plist's canonical flags
/// (so every other config check passes against the genesis-seeded
/// state) and changes ONLY the bind addr to the LAN probe addr — so the
/// first and only failure is the loopback-only rule. Runs argv-only via
/// the trait; the token path is referenced, not read, so no secret bytes
/// enter argv.
fn validate_lan_bind_refused(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<String, String> {
    let status = shell
        .run_argv(
            &[
                "rustynetd",
                "daemon",
                "--node-id",
                config.anchor_node_id.as_str(),
                "--node-role",
                "admin",
                "--backend",
                "macos-wireguard-userspace-shared",
                "--membership-snapshot",
                config.membership_snapshot_path.as_str(),
                "--anchor-bundle-pull-addr",
                config.lan_probe_addr.as_str(),
                "--anchor-bundle-pull-token-path",
                config.anchor_token_path.as_str(),
                "--anchor-bundle-pull-allow-lan",
                "false",
            ],
            &[],
            &[],
        )
        .map_err(|err| format!("LAN-bind probe run failed: {err}"))?;
    if status.is_success() {
        return Err(format!(
            "LAN bind {} was unexpectedly accepted without --anchor-bundle-pull-allow-lan",
            config.lan_probe_addr
        ));
    }
    let stderr = String::from_utf8_lossy(&status.stderr);
    let stdout = String::from_utf8_lossy(&status.stdout);
    let combined = format!("{stderr}{stdout}");
    if !combined.contains("loopback") {
        return Err(format!(
            "LAN bind rejection did not mention the loopback-only rule (exit={}): {combined}",
            status.code
        ));
    }
    Ok(format!(
        "lan_bind_refused=true probe_addr={} exit={}",
        config.lan_probe_addr, status.code
    ))
}

/// Control 5: re-pull with the correct token and assert the served
/// bytes (header + body) never contain the raw token. The daemon logs
/// only the token thumbprint (enforced in `daemon.rs`); this is the
/// request-side proof that the secret never round-trips in the served
/// payload.
fn validate_secrets_hygiene(
    shell: &dyn RemoteShellHost,
    config: &Config,
) -> Result<String, String> {
    let token = read_anchor_token(shell, config)?;
    let mut request = token.clone();
    request.push(b'\n');
    let (header, body) = pull_with_retry(shell, &config.anchor_bundle_pull_addr, &request)?;
    if contains_subslice(&header, &token) {
        return Err("served bundle-pull header leaked the raw token".to_owned());
    }
    if contains_subslice(&body, &token) {
        return Err("served bundle-pull body leaked the raw token".to_owned());
    }
    let thumbprint = anchor_token_thumbprint(&token);
    Ok(format!(
        "raw_token_in_served_bytes=false token_thumbprint={thumbprint}"
    ))
}

// ── helpers ──────────────────────────────────────────────────────────

/// Read the anchor bundle-pull token from the remote host and validate
/// the printable-ASCII + length>=32 shape the daemon enforces.
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

/// Probe the bundle-pull listener up to 3 times (2s between attempts) to
/// tolerate the daemon being briefly between restart cycles, then split
/// the response into header + body.
fn pull_with_retry(
    shell: &dyn RemoteShellHost,
    addr: &str,
    request: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let max_attempts = 3u32;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let response = shell
            .tcp_send_recv(addr, request, Duration::from_secs(5))
            .map_err(|err| format!("bundle-pull tcp probe failed: {err}"))?;
        match split_response(&response) {
            Ok((header, body)) => return Ok((header.to_vec(), body.to_vec())),
            Err(err) => {
                if attempt >= max_attempts {
                    return Err(err);
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn split_response(response: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if response.is_empty() {
        return Err("bundle-pull response was empty".to_owned());
    }
    let header = first_line_bytes(response);
    let body = if response.len() > header.len() {
        let mut start = header.len();
        if start < response.len() && response[start] == b'\r' {
            start += 1;
        }
        if start < response.len() && response[start] == b'\n' {
            start += 1;
        }
        &response[start..]
    } else {
        &[][..]
    };
    Ok((header, body))
}

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

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

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

fn anchor_token_thumbprint(token: &[u8]) -> String {
    sha256_hex(token)[..16].to_owned()
}

fn dry_run_subchecks() -> Vec<Subcheck> {
    ANCHOR_BUNDLE_PULL_SUBSTAGES
        .iter()
        .map(|(name, detail)| Subcheck::skipped(name, detail))
        .collect()
}

fn render_report(
    config: &Config,
    git_commit: &str,
    subchecks: Vec<Subcheck>,
    note: Option<&str>,
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
        "stage": "live_macos_anchor_bundle_pull",
        "status": status,
        "dry_run": config.dry_run,
        "generated_at_unix": unix_now(),
        "git_commit": git_commit,
        "platform": "macos",
        "anchor_host": config.anchor_host,
        "anchor_node_id": config.anchor_node_id,
        "anchor_bundle_pull_addr": config.anchor_bundle_pull_addr,
        "lan_probe_addr": config.lan_probe_addr,
        "anchor_token_path": config.anchor_token_path,
        "membership_snapshot_path": config.membership_snapshot_path,
        "subchecks": checks,
        "note": note,
    }))
    .map_err(|err| format!("serialize macОS anchor bundle-pull report failed: {err}"))
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
    anchor_host: String,
    anchor_node_id: String,
    anchor_bundle_pull_addr: String,
    lan_probe_addr: String,
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
            anchor_host: "admin@192.168.64.10".to_owned(),
            anchor_node_id: "macos-anchor-1".to_owned(),
            anchor_bundle_pull_addr: "127.0.0.1:51822".to_owned(),
            lan_probe_addr: "0.0.0.0:51822".to_owned(),
            anchor_token_path: "/usr/local/var/rustynet/anchor-bundle-pull.token".to_owned(),
            membership_snapshot_path: "/usr/local/var/rustynet/membership/membership.snapshot"
                .to_owned(),
            ssh_identity_file: None,
            pinned_known_hosts_file: None,
            report_path: PathBuf::from(
                "artifacts/phase10/live_macos_anchor_bundle_pull_report.json",
            ),
            log_path: PathBuf::from("artifacts/phase10/live_macos_anchor_bundle_pull.log"),
            git_commit: None,
            dry_run: false,
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--anchor-host" => config.anchor_host = next_value(&mut iter, &arg)?,
                "--anchor-node-id" => config.anchor_node_id = next_value(&mut iter, &arg)?,
                "--anchor-bundle-pull-addr" => {
                    config.anchor_bundle_pull_addr = next_value(&mut iter, &arg)?
                }
                "--lan-probe-addr" => config.lan_probe_addr = next_value(&mut iter, &arg)?,
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
        ensure_safe_token("anchor bundle-pull addr", &self.anchor_bundle_pull_addr)?;
        ensure_safe_token("lan probe addr", &self.lan_probe_addr)?;
        parse_addr(&self.anchor_bundle_pull_addr)?;
        let lan = parse_addr(&self.lan_probe_addr)?;
        // Defence-in-depth: the LAN-probe addr MUST be non-loopback so
        // the refusal assertion is meaningful. A loopback probe addr
        // would always be accepted and silently pass the test.
        if lan.host == "127.0.0.1" || lan.host == "::1" || lan.host == "localhost" {
            return Err(
                "--lan-probe-addr must be a non-loopback address so the refusal proof is meaningful"
                    .to_owned(),
            );
        }
        if !self.anchor_token_path.starts_with('/') {
            return Err("--anchor-token-path must be absolute".to_owned());
        }
        if !self.membership_snapshot_path.starts_with('/') {
            return Err("--membership-snapshot-path must be absolute".to_owned());
        }
        if !self.dry_run && self.ssh_identity_file.is_none() {
            return Err("--ssh-identity-file is required unless --dry-run is set".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAddr {
    host: String,
    port: String,
}

fn parse_addr(value: &str) -> Result<ParsedAddr, String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| "bundle-pull addr must be host:port".to_owned())?;
    if host.is_empty()
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        return Err("bundle-pull addr must be host:port".to_owned());
    }
    Ok(ParsedAddr {
        host: host.to_owned(),
        port: port.to_owned(),
    })
}

fn next_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("missing required value for {flag}"))
}

fn usage() -> String {
    "usage: live_macos_anchor_test --ssh-identity-file <path> [options]\n\noptions:\n  --anchor-host <user@host>\n  --anchor-node-id <id>\n  --anchor-bundle-pull-addr <host:port>\n  --lan-probe-addr <host:port>\n  --anchor-token-path <path>\n  --membership-snapshot-path <path>\n  --known-hosts <path>\n  --report-path <path>\n  --log-path <path>\n  --git-commit <sha>\n  --dry-run".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use live_lab_support::RemoteExitStatus;
    use live_lab_support::testing::MockShellHost;

    fn base_config() -> Config {
        Config::parse(vec!["--dry-run".to_owned()]).expect("dry-run config parses")
    }

    #[test]
    fn parse_dry_run_does_not_require_identity() {
        let cfg = base_config();
        assert!(cfg.dry_run);
        assert_eq!(cfg.anchor_node_id, "macos-anchor-1");
        assert_eq!(cfg.anchor_bundle_pull_addr, "127.0.0.1:51822");
        assert_eq!(cfg.lan_probe_addr, "0.0.0.0:51822");
    }

    #[test]
    fn parse_rejects_missing_identity_without_dry_run() {
        let err = Config::parse(Vec::new()).expect_err("identity required");
        assert!(err.contains("--ssh-identity-file"));
    }

    #[test]
    fn parse_rejects_loopback_lan_probe_addr() {
        let err = Config::parse(vec![
            "--dry-run".to_owned(),
            "--lan-probe-addr".to_owned(),
            "127.0.0.1:51822".to_owned(),
        ])
        .expect_err("loopback lan probe addr must be rejected");
        assert!(err.contains("non-loopback"), "unexpected error: {err}");
    }

    #[test]
    fn dry_run_report_lists_all_substages() {
        let cfg = base_config();
        let report = render_report(&cfg, "abc123", dry_run_subchecks(), None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&report).unwrap();
        assert_eq!(parsed["stage"], "live_macos_anchor_bundle_pull");
        assert_eq!(parsed["platform"], "macos");
        assert_eq!(parsed["status"], "pass");
        let names = parsed["subchecks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "validate_macos_anchor_bundle_pull_loopback",
                "validate_macos_anchor_bundle_pull_token_gate",
                "validate_macos_anchor_bundle_pull_lan_refused",
                "validate_macos_anchor_bundle_pull_secrets_hygiene",
            ]
        );
    }

    fn ok_status(stdout: &[u8]) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
        }
    }

    fn fail_status(stderr: &[u8]) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 1,
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
        }
    }

    fn programmed_host(token: &[u8], snapshot: &[u8]) -> (MockShellHost, Config) {
        let mut cfg = base_config();
        cfg.dry_run = false;
        let host = MockShellHost::new();
        host.write_file(cfg.anchor_token_path.as_str(), token, 0o600)
            .unwrap();
        host.write_file(cfg.membership_snapshot_path.as_str(), snapshot, 0o600)
            .unwrap();
        (host, cfg)
    }

    #[test]
    fn loopback_pull_matches_snapshot_byte_for_byte() {
        let token = b"0123456789abcdef0123456789abcdef".to_vec();
        let snapshot = b"\x00\x01SIGNED-MEMBERSHIP-SNAPSHOT-BYTES\xff".to_vec();
        let (host, cfg) = programmed_host(&token, &snapshot);
        let mut framed = format!("OK {}\n", snapshot.len()).into_bytes();
        framed.extend_from_slice(&snapshot);
        host.program_tcp_response(&cfg.anchor_bundle_pull_addr, framed);

        let summary = validate_bundle_pull_loopback(&host, &cfg).expect("loopback pull passes");
        assert!(
            summary.contains(&sha256_hex(&snapshot)),
            "summary: {summary}"
        );
    }

    #[test]
    fn loopback_pull_fails_on_body_mismatch() {
        let token = b"0123456789abcdef0123456789abcdef".to_vec();
        let snapshot = b"REAL-SNAPSHOT".to_vec();
        let (host, cfg) = programmed_host(&token, &snapshot);
        let mut framed = b"OK 7\n".to_vec();
        framed.extend_from_slice(b"TAMPERD"); // 7 bytes, wrong content
        host.program_tcp_response(&cfg.anchor_bundle_pull_addr, framed);

        let err =
            validate_bundle_pull_loopback(&host, &cfg).expect_err("body mismatch must fail closed");
        assert!(err.contains("byte-for-byte"), "unexpected error: {err}");
    }

    #[test]
    fn token_gate_rejects_wrong_and_short_tokens() {
        let token = b"0123456789abcdef0123456789abcdef".to_vec();
        let snapshot = b"snap".to_vec();
        let (host, cfg) = programmed_host(&token, &snapshot);
        // Both the wrong-token and short-token probes hit the same addr;
        // queue ERR responses for each.
        host.program_tcp_response(&cfg.anchor_bundle_pull_addr, b"ERR unauthorized\n".to_vec());
        host.program_tcp_response(&cfg.anchor_bundle_pull_addr, b"ERR unauthorized\n".to_vec());

        let summary = validate_token_gate(&host, &cfg).expect("token gate passes");
        assert!(summary.contains("wrong_token_rejected=true"));
        assert!(summary.contains("short_token_rejected=true"));
    }

    #[test]
    fn token_gate_fails_if_wrong_token_served() {
        let token = b"0123456789abcdef0123456789abcdef".to_vec();
        let snapshot = b"snap".to_vec();
        let (host, cfg) = programmed_host(&token, &snapshot);
        // Wrong token erroneously served an OK header → must fail.
        host.program_tcp_response(&cfg.anchor_bundle_pull_addr, b"OK 4\nsnap".to_vec());
        let err =
            validate_token_gate(&host, &cfg).expect_err("served wrong token must fail closed");
        assert!(err.contains("not rejected"), "unexpected error: {err}");
    }

    #[test]
    fn lan_bind_refusal_passes_when_daemon_exits_nonzero_with_loopback_diagnostic() {
        let token = b"0123456789abcdef0123456789abcdef".to_vec();
        let snapshot = b"snap".to_vec();
        let (host, cfg) = programmed_host(&token, &snapshot);
        host.program_default_run_response(fail_status(
            b"anchor bundle-pull listener must bind loopback only; set --anchor-bundle-pull-allow-lan to permit LAN bind",
        ));
        let summary = validate_lan_bind_refused(&host, &cfg).expect("lan refusal passes");
        assert!(
            summary.contains("lan_bind_refused=true"),
            "summary: {summary}"
        );
    }

    #[test]
    fn lan_bind_refusal_fails_if_daemon_accepts_lan_bind() {
        let token = b"0123456789abcdef0123456789abcdef".to_vec();
        let snapshot = b"snap".to_vec();
        let (host, cfg) = programmed_host(&token, &snapshot);
        host.program_default_run_response(ok_status(b"config ok"));
        let err =
            validate_lan_bind_refused(&host, &cfg).expect_err("accepted LAN bind must fail closed");
        assert!(
            err.contains("unexpectedly accepted"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn secrets_hygiene_passes_when_token_absent_from_served_bytes() {
        let token = b"0123456789abcdef0123456789abcdef".to_vec();
        let snapshot = b"SIGNED-SNAPSHOT-NO-TOKEN".to_vec();
        let (host, cfg) = programmed_host(&token, &snapshot);
        let mut framed = format!("OK {}\n", snapshot.len()).into_bytes();
        framed.extend_from_slice(&snapshot);
        host.program_tcp_response(&cfg.anchor_bundle_pull_addr, framed);
        let summary = validate_secrets_hygiene(&host, &cfg).expect("hygiene passes");
        assert!(summary.contains("raw_token_in_served_bytes=false"));
        assert!(summary.contains(&anchor_token_thumbprint(&token)));
    }

    #[test]
    fn secrets_hygiene_fails_if_served_body_leaks_token() {
        let token = b"0123456789abcdef0123456789abcdef".to_vec();
        // Pathological server that echoes the token into the body.
        let mut snapshot = b"LEAK:".to_vec();
        snapshot.extend_from_slice(&token);
        let (host, cfg) = programmed_host(&token, &snapshot);
        let mut framed = format!("OK {}\n", snapshot.len()).into_bytes();
        framed.extend_from_slice(&snapshot);
        host.program_tcp_response(&cfg.anchor_bundle_pull_addr, framed);
        let err =
            validate_secrets_hygiene(&host, &cfg).expect_err("token leak in body must fail closed");
        assert!(
            err.contains("leaked the raw token"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn contains_subslice_finds_embedded_token() {
        assert!(contains_subslice(b"abcTOKENdef", b"TOKEN"));
        assert!(!contains_subslice(b"abcdef", b"TOKEN"));
        assert!(!contains_subslice(b"short", b"longneedle"));
    }

    #[test]
    fn split_response_separates_header_and_body() {
        let (header, body) = split_response(b"OK 5\nhello").unwrap();
        assert_eq!(header, b"OK 5");
        assert_eq!(body, b"hello");
        assert!(split_response(b"").is_err());
    }
}
