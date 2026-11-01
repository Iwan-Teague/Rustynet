#![allow(dead_code)]
//! Linux side of the preissued relay session token spool (HP-3 provisioning
//! design, patch 3).
//!
//! The daemon builds a relay client only when a token source is configured. The
//! lab uses the preissued SPOOL (`RUSTYNET_RELAY_SESSION_TOKEN_SPOOL_DIR`) and
//! never the daemon-local issuer: the daemon verifies each spooled token under
//! the traversal verifier key and never holds a signing key for it. Tokens are
//! minted OUTSIDE the peers, on the node that already holds the assignment
//! signing secret (the exit guest, through the same adapter seam that issues the
//! signed bundles), and delivered here.
//!
//! Spool semantics this module is built around (all from
//! `rustynetd/src/relay_client.rs`, `PreissuedRelaySessionTokenIssuer`):
//!
//! * the daemon scans the directory sorted by file name and, for each
//!   `*.relay-token` file, FIRST verifies the signature (a bad signature or a
//!   malformed file aborts the whole issue call, for every triple) and only
//!   then skips files bound to another `(node, peer, relay id)`;
//! * the first matching file is validated and, if expired, the call fails and
//!   the file STAYS -- an expired matching token blocks issuance until removed;
//! * a consumed token is deleted (one use), so the daemon needs write access to
//!   the directory;
//! * more than 128 `*.relay-token` files is a hard error.
//!
//! So every install purges expired and unparseable files first, names sort
//! chronologically, and the directory is owned by the daemon user, mode 0700.
//!
//! Daemon environment: a systemd DROP-IN (`rustynetd.service.d/`), not an edit
//! of `/etc/default/rustynetd`. That file is also the `EnvironmentFile` of the
//! privileged helper, the refresh timers, the managed-DNS and anchor units, and
//! a regenerated artifact of `ops install-systemd`; a drop-in touches only the
//! daemon unit and is removed by deleting one file.
//!
//! Every remote command here is built from [`ValidatedArg`]s (no shell, no
//! interpolation), which is what keeps the QH-01 raw-sink ratchet from growing.
//!
//! Custody: token files are bearer credentials for at most 120 s. They travel
//! by scp (never argv or stdout), are mode 0600 everywhere, and no function
//! here logs or returns token contents.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::node_adapter::RelayTokenSpoolReport;
use crate::vm_lab::orchestrator::adapter::ssh::{self, RemoteCommand};
use crate::vm_lab::orchestrator::adapter::validated_args::ValidatedArg;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::AdapterError;

/// The daemon-owned spool directory. Under `/var/lib/rustynet`, which the
/// daemon unit already makes writable (`ReadWritePaths`) and owns
/// (`StateDirectory=rustynet`).
pub const RELAY_TOKEN_SPOOL_DIR: &str = "/var/lib/rustynet/relay-token-spool";
/// Staging directory INSIDE the spool: the daemon only reads `*.relay-token`
/// entries, and a directory without that extension is ignored, so a token is
/// renamed out of here into the spool only once it is fully written.
const SPOOL_INCOMING_DIR: &str = "/var/lib/rustynet/relay-token-spool/.incoming";
/// The daemon unit and its drop-in directory/file.
const DAEMON_UNIT: &str = "rustynetd.service";
const DROPIN_DIR: &str = "/etc/systemd/system/rustynetd.service.d";
const DROPIN_FILE: &str = "/etc/systemd/system/rustynetd.service.d/hp3-relay-token-spool.conf";
/// The daemon's spool variable (`RELAY_SESSION_TOKEN_SPOOL_DIR_ENV`).
pub const SPOOL_ENV_KEY: &str = "RUSTYNET_RELAY_SESSION_TOKEN_SPOOL_DIR";
/// The daemon's hard cap on spool entries (`PREISSUED_RELAY_TOKEN_MAX_FILES`).
pub const MAX_SPOOL_FILES: usize = 128;
/// Seconds of remaining life below which the purge drops a token: the daemon
/// would reject it, and an expired matching token blocks the spool.
const PURGE_MARGIN_SECS: u64 = 10;
/// The extension the daemon's spool reader accepts.
const TOKEN_SUFFIX: &str = ".relay-token";

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

/// Content of the daemon unit drop-in: one `Environment=` line, constant.
fn dropin_content() -> String {
    format!("[Service]\nEnvironment={SPOOL_ENV_KEY}={RELAY_TOKEN_SPOOL_DIR}\n")
}

fn argv(label: &str, args: &[&str]) -> Result<RemoteCommand, AdapterError> {
    let validated = args
        .iter()
        .map(|arg| {
            if arg.starts_with('/') {
                ValidatedArg::path(arg)
            } else {
                ValidatedArg::cli_token(arg)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    RemoteCommand::from_args(label, &validated)
}

fn path_arg(value: &str) -> Result<ValidatedArg, AdapterError> {
    Ok(ValidatedArg::path(value)?)
}

// ── pure parsing ─────────────────────────────────────────────────────────────

/// Names in an `ls -1` listing that are spool tokens. Any other entry that is
/// not the staging dir, or a name outside the bundle-filename alphabet, is
/// refused: a surprise in the spool must not be silently interpolated anywhere.
pub(crate) fn parse_spool_listing(listing: &str) -> Result<Vec<String>, AdapterError> {
    let mut tokens = Vec::new();
    for name in listing.lines().map(str::trim).filter(|l| !l.is_empty()) {
        ValidatedArg::bundle_filename(name)?;
        if name.ends_with(TOKEN_SUFFIX) {
            tokens.push(name.to_owned());
        }
    }
    Ok(tokens)
}

/// `grep -F -H expires_at_unix=` output lines (`<path>:expires_at_unix=<n>`) as
/// `(file name, expiry)`. A file with no parseable expiry is simply absent, and
/// [`select_purge`] deletes absentees.
pub(crate) fn parse_expiry_listing(output: &str) -> Vec<(String, u64)> {
    output
        .lines()
        .filter_map(|line| {
            let (path, expiry) = line.trim().rsplit_once(":expires_at_unix=")?;
            let name = path.rsplit('/').next()?;
            Some((name.to_owned(), expiry.parse::<u64>().ok()?))
        })
        .collect()
}

/// Which spool tokens to delete: expired (or expiring within `margin_secs`) and
/// those whose expiry could not be read.
pub(crate) fn select_purge(
    present: &[String],
    expiries: &[(String, u64)],
    now_unix: u64,
    margin_secs: u64,
) -> Vec<String> {
    let keep_after = now_unix.saturating_add(margin_secs);
    present
        .iter()
        .filter(|name| {
            !expiries
                .iter()
                .any(|(n, expiry)| n == *name && *expiry > keep_after)
        })
        .cloned()
        .collect()
}

/// Which spool tokens a fresh batch supersedes: every `*.relay-token` present
/// that is NOT in the batch just published. The daemon scans oldest-first and an
/// expired matching token that stays on disk blocks every later one, and a
/// 90 s refill against a 120 s lifetime would leave the previous generation's
/// unconsumed tokens expired for part of every cycle. Removing the whole
/// previous generation as the new one lands means the spool only ever holds the
/// newest batch (plus anything consumed in between is simply gone).
pub(crate) fn select_superseded(present: &[String], batch: &[String]) -> Vec<String> {
    present
        .iter()
        .filter(|name| !batch.contains(*name))
        .cloned()
        .collect()
}

/// Unix seconds from `date -u --rfc-3339=seconds` (`2026-10-09 10:31:44+00:00`).
/// The node clock is read through argv (no `+%s` format string, whose `%` and
/// `+` are outside the validated alphabet), so the civil date is converted here.
/// Only UTC offsets of `+00:00` are accepted.
pub(crate) fn parse_rfc3339_utc_secs(output: &str) -> Result<u64, AdapterError> {
    let bad = || AdapterError::Protocol {
        message: "node clock reply was not an RFC 3339 UTC timestamp".to_owned(),
    };
    let text = output.trim();
    let text = text.strip_suffix("+00:00").ok_or_else(bad)?;
    let (date, time) = text.split_once(' ').ok_or_else(bad)?;
    let mut d = date.split('-').map(|p| p.parse::<i64>());
    let (Some(Ok(year)), Some(Ok(month)), Some(Ok(day)), None) =
        (d.next(), d.next(), d.next(), d.next())
    else {
        return Err(bad());
    };
    let mut t = time.split(':').map(|p| p.parse::<i64>());
    let (Some(Ok(hour)), Some(Ok(minute)), Some(Ok(second)), None) =
        (t.next(), t.next(), t.next(), t.next())
    else {
        return Err(bad());
    };
    if !(1970..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..61).contains(&second)
    {
        return Err(bad());
    }
    // Howard Hinnant's days-from-civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).map_err(|_| bad())
}

// ── command builders (pure, unit-tested) ─────────────────────────────────────

fn cmd_install_dropin(tmp_remote: &str) -> Result<RemoteCommand, AdapterError> {
    let args = [
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("install")?,
        ValidatedArg::cli_token("-o")?,
        ValidatedArg::cli_token("root")?,
        ValidatedArg::cli_token("-g")?,
        ValidatedArg::cli_token("root")?,
        ValidatedArg::cli_token("-m")?,
        ValidatedArg::cli_token("0644")?,
        path_arg(tmp_remote)?,
        path_arg(DROPIN_FILE)?,
    ];
    RemoteCommand::from_args("linux relay token spool drop-in install", &args)
}

fn cmd_make_spool_dir(dir: &str) -> Result<RemoteCommand, AdapterError> {
    let args = [
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("install")?,
        ValidatedArg::cli_token("-d")?,
        ValidatedArg::cli_token("-o")?,
        ValidatedArg::cli_token("rustynetd")?,
        ValidatedArg::cli_token("-g")?,
        ValidatedArg::cli_token("rustynetd")?,
        ValidatedArg::cli_token("-m")?,
        ValidatedArg::cli_token("0700")?,
        path_arg(dir)?,
    ];
    RemoteCommand::from_args("linux relay token spool dir", &args)
}

fn cmd_install_tokens(stage_dir: &str, names: &[String]) -> Result<RemoteCommand, AdapterError> {
    let mut args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("install")?,
        ValidatedArg::cli_token("-o")?,
        ValidatedArg::cli_token("rustynetd")?,
        ValidatedArg::cli_token("-g")?,
        ValidatedArg::cli_token("rustynetd")?,
        ValidatedArg::cli_token("-m")?,
        ValidatedArg::cli_token("0600")?,
        ValidatedArg::cli_token("-t")?,
        path_arg(SPOOL_INCOMING_DIR)?,
    ];
    for name in names {
        ValidatedArg::bundle_filename(name)?;
        args.push(path_arg(&format!("{stage_dir}/{name}"))?);
    }
    RemoteCommand::from_args("linux relay token install", &args)
}

fn cmd_publish_tokens(names: &[String]) -> Result<RemoteCommand, AdapterError> {
    let mut args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("mv")?,
        ValidatedArg::cli_token("-f")?,
        ValidatedArg::cli_token("-t")?,
        path_arg(RELAY_TOKEN_SPOOL_DIR)?,
    ];
    for name in names {
        ValidatedArg::bundle_filename(name)?;
        args.push(path_arg(&format!("{SPOOL_INCOMING_DIR}/{name}"))?);
    }
    RemoteCommand::from_args("linux relay token publish", &args)
}

fn cmd_read_expiries(names: &[String]) -> Result<RemoteCommand, AdapterError> {
    let mut args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("grep")?,
        ValidatedArg::cli_token("-F")?,
        ValidatedArg::cli_token("-H")?,
        ValidatedArg::cli_token("expires_at_unix=")?,
    ];
    for name in names {
        ValidatedArg::bundle_filename(name)?;
        args.push(path_arg(&format!("{RELAY_TOKEN_SPOOL_DIR}/{name}"))?);
    }
    RemoteCommand::from_args("linux relay token expiries", &args)
}

fn cmd_remove_tokens(names: &[String]) -> Result<RemoteCommand, AdapterError> {
    let mut args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("rm")?,
        ValidatedArg::cli_token("-f")?,
        ValidatedArg::cli_token("--")?,
    ];
    for name in names {
        ValidatedArg::bundle_filename(name)?;
        args.push(path_arg(&format!("{RELAY_TOKEN_SPOOL_DIR}/{name}"))?);
    }
    RemoteCommand::from_args("linux relay token purge", &args)
}

fn cmd_list_spool() -> Result<RemoteCommand, AdapterError> {
    argv(
        "linux relay token spool listing",
        &["sudo", "-n", "ls", "-1", "--", RELAY_TOKEN_SPOOL_DIR],
    )
}

fn cmd_node_clock() -> Result<RemoteCommand, AdapterError> {
    argv("linux node clock", &["date", "-u", "--rfc-3339=seconds"])
}

fn cmd_daemon_environment() -> Result<RemoteCommand, AdapterError> {
    argv(
        "linux daemon unit environment",
        &[
            "sudo",
            "-n",
            "systemctl",
            "show",
            "-p",
            "Environment",
            DAEMON_UNIT,
        ],
    )
}

fn cmd_daemon_reload() -> Result<RemoteCommand, AdapterError> {
    argv(
        "linux systemd reload",
        &["sudo", "-n", "systemctl", "daemon-reload"],
    )
}

// ── remote operations ────────────────────────────────────────────────────────

/// Mint tokens on this node and bring the files back to `local_out_dir`.
pub fn issue_relay_tokens_to_dir(
    conn: &NodeConnection,
    rustynet_path: &str,
    env_content: &str,
    local_out_dir: &Path,
) -> Result<(), AdapterError> {
    use std::io::Write as IoWrite;
    let uniq = super::unique_temp_token();
    let remote_env = format!("/tmp/rn_relay_tok_env_{uniq}.env");
    let remote_issue_dir = format!("/tmp/rn_relay_tok_issue_{uniq}");

    // Validate every remote path before any command exists. This relies on the
    // custody posture of /etc/rustynet (0750 root:rustynetd) that the
    // `issue_bundles_to_dir` calls of the stage's declared dependency
    // (`refresh_signed_bundles`) re-assert immediately beforehand.
    let env_arg = ValidatedArg::path(&remote_env)?;
    let dir_arg = ValidatedArg::path(&remote_issue_dir)?;

    let mut env_tmp = std::env::temp_dir();
    env_tmp.push(format!("rn_relay_tok_env_{uniq}.env"));
    {
        let mut file = std::fs::File::create(&env_tmp).map_err(|e| AdapterError::Io {
            message: format!("create relay token env tmp: {e}"),
        })?;
        file.write_all(env_content.as_bytes())
            .map_err(|e| AdapterError::Io {
                message: format!("write relay token env tmp: {e}"),
            })?;
    }
    let shipped = ssh::scp_to(conn, &env_tmp, &remote_env, MEDIUM_TIMEOUT);
    let _ = std::fs::remove_file(&env_tmp);
    shipped?;

    let result = (|| -> Result<(), AdapterError> {
        let issue_args = [
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("env")?,
            ValidatedArg::cli_token("RUSTYNET_NODE_ROLE=admin")?,
            ValidatedArg::path(rustynet_path)?,
            ValidatedArg::cli_token("ops")?,
            ValidatedArg::cli_token("e2e-issue-relay-session-tokens-from-env")?,
            ValidatedArg::cli_token("--env-file")?,
            env_arg.clone(),
            ValidatedArg::cli_token("--issue-dir")?,
            dir_arg.clone(),
        ];
        let issue_cmd = RemoteCommand::from_args("linux issue relay tokens", &issue_args)?;
        ssh::run_remote(conn, issue_cmd.as_str(), MEDIUM_TIMEOUT)?;

        // The issuer leaves a root:root 0700 dir of 0600 files. Hand it to the
        // ssh user, keeping 0700/0600: the tokens are never group- or
        // world-readable, not even for the seconds this copy takes. `id` runs in
        // the ssh user's shell BEFORE sudo, so it names the ssh user.
        let id_cmd = argv("linux ssh user id", &["id", "-u"])?;
        let owner = ssh::run_remote(conn, id_cmd.as_str(), SHORT_TIMEOUT)?;
        let owner = owner.trim();
        if owner.is_empty() || !owner.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AdapterError::Protocol {
                message: "ssh user id reply was not numeric".to_owned(),
            });
        }
        let chown_args = [
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("chown")?,
            ValidatedArg::cli_token("-R")?,
            ValidatedArg::cli_token(owner)?,
            dir_arg.clone(),
        ];
        // `chown -R <uid> dir` keeps the group; the 0600/0700 modes are what
        // protect the files, and the uid is the ssh user's.
        let chown_cmd = RemoteCommand::from_args("linux relay token handoff", &chown_args)?;
        ssh::run_remote(conn, chown_cmd.as_str(), SHORT_TIMEOUT)?;

        let ls_args = [
            ValidatedArg::cli_token("ls")?,
            ValidatedArg::cli_token("-1")?,
            dir_arg.clone(),
        ];
        let ls_cmd = RemoteCommand::from_args("linux relay token listing", &ls_args)?;
        let listing = ssh::run_remote(conn, ls_cmd.as_str(), SHORT_TIMEOUT)?;
        let names = listing
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        let token_names = names.iter().filter(|n| n.ends_with(TOKEN_SUFFIX)).count();
        let has_verifier = names.contains(&"rn-relay-token.pub");
        if token_names == 0 || !has_verifier {
            return Err(AdapterError::Protocol {
                message: format!(
                    "relay token issuer produced {token_names} token file(s) and verifier={has_verifier}; \
                     refusing to distribute a partial or empty mint"
                ),
            });
        }
        std::fs::create_dir_all(local_out_dir).map_err(|e| AdapterError::Io {
            message: format!("create local relay token dir: {e}"),
        })?;
        for name in &names {
            // Single path component from a fixed alphabet; anything else from
            // the guest is refused rather than interpolated into a path.
            ValidatedArg::bundle_filename(name)?;
            let remote_path = format!("{remote_issue_dir}/{name}");
            let local_path = local_out_dir.join(name);
            ssh::scp_from(conn, &remote_path, &local_path, MEDIUM_TIMEOUT)?;
            set_owner_only(&local_path)?;
        }
        Ok(())
    })();
    // Best effort on every path: remove the env file and the guest-side copies.
    let cleanup_args = [
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("rm")?,
        ValidatedArg::cli_token("-rf")?,
        ValidatedArg::cli_token("--")?,
        env_arg,
        dir_arg,
    ];
    if let Ok(cleanup_cmd) = RemoteCommand::from_args("linux relay token cleanup", &cleanup_args) {
        let _ = ssh::run_remote(conn, cleanup_cmd.as_str(), SHORT_TIMEOUT);
    }
    result
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), AdapterError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        AdapterError::Io {
            message: format!("restrict relay token file: {e}"),
        }
    })
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), AdapterError> {
    Ok(())
}

/// Create the spool, add the daemon drop-in, reload systemd, and confirm systemd
/// now resolves the variable for the daemon unit. No restart.
pub fn prepare_relay_token_spool(conn: &NodeConnection) -> Result<(), AdapterError> {
    let uniq = super::unique_temp_token();
    let tmp_remote = format!("/tmp/rn_hp3_spool_{uniq}.conf");
    let mut tmp_local = std::env::temp_dir();
    tmp_local.push(format!("rn_hp3_spool_{uniq}.conf"));
    std::fs::write(&tmp_local, dropin_content()).map_err(|e| AdapterError::Io {
        message: format!("write drop-in tmp: {e}"),
    })?;
    let shipped = ssh::scp_to(conn, &tmp_local, &tmp_remote, SHORT_TIMEOUT);
    let _ = std::fs::remove_file(&tmp_local);
    shipped?;

    let steps = (|| -> Result<(), AdapterError> {
        let spool_cmd = cmd_make_spool_dir(RELAY_TOKEN_SPOOL_DIR)?;
        ssh::run_remote(conn, spool_cmd.as_str(), SHORT_TIMEOUT)?;
        let incoming_cmd = cmd_make_spool_dir(SPOOL_INCOMING_DIR)?;
        ssh::run_remote(conn, incoming_cmd.as_str(), SHORT_TIMEOUT)?;
        let dir_cmd = {
            let args = [
                ValidatedArg::cli_token("sudo")?,
                ValidatedArg::cli_token("-n")?,
                ValidatedArg::cli_token("install")?,
                ValidatedArg::cli_token("-d")?,
                ValidatedArg::cli_token("-o")?,
                ValidatedArg::cli_token("root")?,
                ValidatedArg::cli_token("-g")?,
                ValidatedArg::cli_token("root")?,
                ValidatedArg::cli_token("-m")?,
                ValidatedArg::cli_token("0755")?,
                path_arg(DROPIN_DIR)?,
            ];
            RemoteCommand::from_args("linux daemon drop-in dir", &args)?
        };
        ssh::run_remote(conn, dir_cmd.as_str(), SHORT_TIMEOUT)?;
        let install_cmd = cmd_install_dropin(&tmp_remote)?;
        ssh::run_remote(conn, install_cmd.as_str(), SHORT_TIMEOUT)?;
        let reload_cmd = cmd_daemon_reload()?;
        ssh::run_remote(conn, reload_cmd.as_str(), SHORT_TIMEOUT)?;
        let env_cmd = cmd_daemon_environment()?;
        let environment = ssh::run_remote(conn, env_cmd.as_str(), SHORT_TIMEOUT)?;
        if !environment_has_spool(&environment) {
            return Err(AdapterError::Protocol {
                message: "systemd does not resolve the relay token spool variable for the daemon \
                          unit after the drop-in was installed"
                    .to_owned(),
            });
        }
        Ok(())
    })();
    if let Ok(rm_cmd) = argv("linux drop-in tmp cleanup", &["rm", "-f", &tmp_remote]) {
        let _ = ssh::run_remote(conn, rm_cmd.as_str(), SHORT_TIMEOUT);
    }
    steps
}

/// True when `systemctl show -p Environment` output carries the spool variable
/// pointing at [`RELAY_TOKEN_SPOOL_DIR`] (exactly, as a whole word).
pub(crate) fn environment_has_spool(show_output: &str) -> bool {
    let needle = format!("{SPOOL_ENV_KEY}={RELAY_TOKEN_SPOOL_DIR}");
    show_output
        .trim()
        .strip_prefix("Environment=")
        .is_some_and(|rest| rest.split_whitespace().any(|word| word == needle))
}

/// The node's own clock (unix seconds), read through argv.
pub fn node_clock_unix(conn: &NodeConnection) -> Result<u64, AdapterError> {
    let clock_cmd = cmd_node_clock()?;
    parse_rfc3339_utc_secs(&ssh::run_remote(conn, clock_cmd.as_str(), SHORT_TIMEOUT)?)
}

/// Purge expired tokens and install `token_files` into the spool.
pub fn install_relay_token_spool(
    conn: &NodeConnection,
    token_files: &[PathBuf],
) -> Result<RelayTokenSpoolReport, AdapterError> {
    let names = token_files
        .iter()
        .map(|local| {
            let name = local
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| AdapterError::Protocol {
                    message: "relay token file has no usable name".to_owned(),
                })?;
            ValidatedArg::bundle_filename(name)?;
            if !name.ends_with(TOKEN_SUFFIX) {
                return Err(AdapterError::Protocol {
                    message: format!("refusing to install {name:?}: not a {TOKEN_SUFFIX} file"),
                });
            }
            Ok(name.to_owned())
        })
        .collect::<Result<Vec<_>, AdapterError>>()?;

    // 1. Node clock first: the purge decision must use the clock the daemon
    //    judges expiry on.
    let clock_cmd = cmd_node_clock()?;
    let node_now_unix =
        parse_rfc3339_utc_secs(&ssh::run_remote(conn, clock_cmd.as_str(), SHORT_TIMEOUT)?)?;

    // 2. Purge expired/unreadable tokens BEFORE new ones land (so a failed
    //    install below cannot leave an expired matching token blocking the
    //    daemon). The daemon may consume a file between the listing and the
    //    grep (grep then exits 2): re-list once before giving up.
    let mut relisted = false;
    loop {
        let list_cmd = cmd_list_spool()?;
        let present =
            parse_spool_listing(&ssh::run_remote(conn, list_cmd.as_str(), SHORT_TIMEOUT)?)?;
        if present.is_empty() {
            break;
        }
        let read_cmd = cmd_read_expiries(&present)?;
        // grep exits 1 when NO file has an expiry line; that is "purge them
        // all", not a transport failure.
        let expiries = match ssh::run_remote(conn, read_cmd.as_str(), SHORT_TIMEOUT) {
            Ok(output) => parse_expiry_listing(&output),
            Err(AdapterError::Command {
                exit_code: Some(1), ..
            }) => Vec::new(),
            Err(AdapterError::Command {
                exit_code: Some(2), ..
            }) if !relisted => {
                relisted = true;
                continue;
            }
            Err(other) => return Err(other),
        };
        let expired = select_purge(&present, &expiries, node_now_unix, PURGE_MARGIN_SECS);
        if !expired.is_empty() {
            let rm_cmd = cmd_remove_tokens(&expired)?;
            ssh::run_remote(conn, rm_cmd.as_str(), SHORT_TIMEOUT)?;
        }
        break;
    }

    // 3. Stage, install into the staging dir, publish by rename.
    let stage_dir = format!("/tmp/rn_relay_tok_stage_{}", super::unique_temp_token());
    let mkdir_cmd = argv(
        "linux relay token stage dir",
        &["mkdir", "-m", "0700", "-p", &stage_dir],
    )?;
    ssh::run_remote(conn, mkdir_cmd.as_str(), SHORT_TIMEOUT)?;
    let published = (|| -> Result<(), AdapterError> {
        for (local, name) in token_files.iter().zip(&names) {
            ssh::scp_to(conn, local, &format!("{stage_dir}/{name}"), MEDIUM_TIMEOUT)?;
        }
        let install_cmd = cmd_install_tokens(&stage_dir, &names)?;
        ssh::run_remote(conn, install_cmd.as_str(), MEDIUM_TIMEOUT)?;
        let publish_cmd = cmd_publish_tokens(&names)?;
        ssh::run_remote(conn, publish_cmd.as_str(), SHORT_TIMEOUT)?;
        Ok(())
    })();
    if let Ok(rm_cmd) = argv(
        "linux relay token stage cleanup",
        &["rm", "-rf", "--", &stage_dir],
    ) {
        let _ = ssh::run_remote(conn, rm_cmd.as_str(), SHORT_TIMEOUT);
    }
    published?;

    // 4. Supersede: drop every token that is not in the batch just published
    //    (the previous generation's unconsumed leftovers), then report the
    //    resulting spool size (the daemon's hard cap is 128).
    let after_cmd = cmd_list_spool()?;
    let after = parse_spool_listing(&ssh::run_remote(conn, after_cmd.as_str(), SHORT_TIMEOUT)?)?;
    let superseded = select_superseded(&after, &names);
    if !superseded.is_empty() {
        let rm_cmd = cmd_remove_tokens(&superseded)?;
        ssh::run_remote(conn, rm_cmd.as_str(), SHORT_TIMEOUT)?;
    }
    report_for(node_now_unix, after.len() - superseded.len())
}

fn report_for(
    node_now_unix: u64,
    spool_files: usize,
) -> Result<RelayTokenSpoolReport, AdapterError> {
    if spool_files > MAX_SPOOL_FILES {
        return Err(AdapterError::Protocol {
            message: format!(
                "relay token spool holds {spool_files} files, over the daemon's hard cap of \
                 {MAX_SPOOL_FILES}"
            ),
        });
    }
    Ok(RelayTokenSpoolReport {
        node_now_unix,
        spool_files,
    })
}

/// Remove the drop-in FIRST, reload, then the spool directory, so a failure
/// between the steps can never leave the daemon unit pointing at a missing
/// directory (the daemon refuses to start in that state). Verifies systemd no
/// longer resolves the variable.
pub fn teardown_relay_token_spool(conn: &NodeConnection) -> Result<(), AdapterError> {
    let rm_dropin = argv(
        "linux relay token drop-in removal",
        &["sudo", "-n", "rm", "-f", "--", DROPIN_FILE],
    )?;
    ssh::run_remote(conn, rm_dropin.as_str(), SHORT_TIMEOUT)?;
    let reload_cmd = cmd_daemon_reload()?;
    ssh::run_remote(conn, reload_cmd.as_str(), SHORT_TIMEOUT)?;
    let env_cmd = cmd_daemon_environment()?;
    let environment = ssh::run_remote(conn, env_cmd.as_str(), SHORT_TIMEOUT)?;
    if environment.contains(SPOOL_ENV_KEY) {
        // Leave the directory in place: the daemon still points at it.
        return Err(AdapterError::Protocol {
            message: "systemd still resolves the relay token spool variable after the drop-in \
                      was removed; the spool directory was left in place"
                .to_owned(),
        });
    }
    let rm_spool = argv(
        "linux relay token spool removal",
        &["sudo", "-n", "rm", "-rf", "--", RELAY_TOKEN_SPOOL_DIR],
    )?;
    ssh::run_remote(conn, rm_spool.as_str(), SHORT_TIMEOUT)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_daemon_contract() {
        let daemon = include_str!("../../../../../rustynetd/src/daemon.rs");
        assert!(
            daemon.contains(&format!(
                "const RELAY_SESSION_TOKEN_SPOOL_DIR_ENV: &str = \"{SPOOL_ENV_KEY}\";"
            )),
            "the spool env key must be the daemon's"
        );
        let client = include_str!("../../../../../rustynetd/src/relay_client.rs");
        assert!(client.contains(&format!(
            "const PREISSUED_RELAY_TOKEN_MAX_FILES: usize = {MAX_SPOOL_FILES};"
        )));
        assert!(
            client.contains(&format!(
                "const PREISSUED_RELAY_TOKEN_EXTENSION: &str = \"{}\";",
                TOKEN_SUFFIX.trim_start_matches('.')
            )),
            "the spool reader's extension"
        );
        // The spool lives where the daemon unit can write, under its state dir.
        let unit = include_str!("../../../../../../scripts/systemd/rustynetd.service");
        assert!(unit.contains("ReadWritePaths=-/run/rustynet /var/lib/rustynet /etc/rustynet"));
        assert!(RELAY_TOKEN_SPOOL_DIR.starts_with("/var/lib/rustynet/"));
        assert!(SPOOL_INCOMING_DIR.starts_with(RELAY_TOKEN_SPOOL_DIR));
        assert!(DROPIN_FILE.starts_with(DROPIN_DIR));
        assert_eq!(DROPIN_DIR, format!("/etc/systemd/system/{DAEMON_UNIT}.d"));
    }

    #[test]
    fn dropin_sets_exactly_the_spool_variable() {
        assert_eq!(
            dropin_content(),
            "[Service]\nEnvironment=RUSTYNET_RELAY_SESSION_TOKEN_SPOOL_DIR=/var/lib/rustynet/relay-token-spool\n"
        );
        // The daemon refuses a spool combined with daemon-local signing; the
        // drop-in must never also hand it a signing secret.
        let content = dropin_content();
        assert!(!content.contains("SIGNING") && !content.contains("LOCAL_TOKEN_ISSUER"));
    }

    #[test]
    fn spool_dirs_are_daemon_owned_and_private_and_the_dropin_is_root_owned() {
        let spool = cmd_make_spool_dir(RELAY_TOKEN_SPOOL_DIR).expect("cmd");
        assert_eq!(
            spool.as_str(),
            "'sudo' '-n' 'install' '-d' '-o' 'rustynetd' '-g' 'rustynetd' '-m' '0700' \
             '/var/lib/rustynet/relay-token-spool'"
        );
        let dropin = cmd_install_dropin("/tmp/x.conf").expect("cmd");
        assert_eq!(
            dropin.as_str(),
            "'sudo' '-n' 'install' '-o' 'root' '-g' 'root' '-m' '0644' '/tmp/x.conf' \
             '/etc/systemd/system/rustynetd.service.d/hp3-relay-token-spool.conf'"
        );
    }

    #[test]
    fn tokens_install_into_the_staging_dir_then_publish_by_rename() {
        let names = vec![
            "1791000000-00-00.relay-token".to_owned(),
            "1791000000-00-01.relay-token".to_owned(),
        ];
        let install = cmd_install_tokens("/tmp/stage", &names).expect("cmd");
        assert_eq!(
            install.as_str(),
            "'sudo' '-n' 'install' '-o' 'rustynetd' '-g' 'rustynetd' '-m' '0600' '-t' \
             '/var/lib/rustynet/relay-token-spool/.incoming' \
             '/tmp/stage/1791000000-00-00.relay-token' '/tmp/stage/1791000000-00-01.relay-token'"
        );
        let publish = cmd_publish_tokens(&names).expect("cmd");
        assert_eq!(
            publish.as_str(),
            "'sudo' '-n' 'mv' '-f' '-t' '/var/lib/rustynet/relay-token-spool' \
             '/var/lib/rustynet/relay-token-spool/.incoming/1791000000-00-00.relay-token' \
             '/var/lib/rustynet/relay-token-spool/.incoming/1791000000-00-01.relay-token'"
        );
        // The staging dir has no `.relay-token` extension, so the daemon's
        // *.relay-token scan never sees a half-written token.
        assert!(!SPOOL_INCOMING_DIR.ends_with(TOKEN_SUFFIX));
        assert_eq!(
            std::path::Path::new(SPOOL_INCOMING_DIR)
                .extension()
                .and_then(|e| e.to_str()),
            None
        );
    }

    #[test]
    fn hostile_file_names_never_reach_a_command() {
        for bad in [
            "a b.relay-token",
            "../x.relay-token",
            "a/b.relay-token",
            "a;rm -rf.relay-token",
            "$(id).relay-token",
            "",
        ] {
            let names = vec![bad.to_owned()];
            assert!(cmd_install_tokens("/tmp/stage", &names).is_err(), "{bad:?}");
            assert!(cmd_publish_tokens(&names).is_err(), "{bad:?}");
            assert!(cmd_read_expiries(&names).is_err(), "{bad:?}");
            assert!(cmd_remove_tokens(&names).is_err(), "{bad:?}");
            assert!(
                parse_spool_listing(bad).is_err() || bad.is_empty(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn listing_keeps_tokens_and_ignores_the_staging_dir() {
        let names = parse_spool_listing(".incoming\n1791000000-00-00.relay-token\nsurprise.txt\n")
            .expect("alphabet-clean listing");
        assert_eq!(names, vec!["1791000000-00-00.relay-token".to_owned()]);
        assert!(parse_spool_listing("evil name.relay-token\n").is_err());
        assert_eq!(
            parse_spool_listing("").expect("empty"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn purge_removes_expired_expiring_and_unreadable_tokens_only() {
        let present: Vec<String> = ["old", "expiring", "fresh", "unreadable"]
            .iter()
            .map(|n| format!("{n}.relay-token"))
            .collect();
        let output = "\
/var/lib/rustynet/relay-token-spool/old.relay-token:expires_at_unix=1790999000\n\
/var/lib/rustynet/relay-token-spool/expiring.relay-token:expires_at_unix=1791000005\n\
/var/lib/rustynet/relay-token-spool/fresh.relay-token:expires_at_unix=1791000100\n";
        let expiries = parse_expiry_listing(output);
        assert_eq!(expiries.len(), 3);
        let purge = select_purge(&present, &expiries, 1_791_000_000, 10);
        assert_eq!(
            purge,
            vec![
                "old.relay-token".to_owned(),
                "expiring.relay-token".to_owned(),
                "unreadable.relay-token".to_owned()
            ]
        );
        // Everything unreadable (grep found nothing) is purged.
        assert_eq!(select_purge(&present, &[], 1_791_000_000, 10).len(), 4);
        // A token exactly at the margin is dropped (daemon needs expiry > now).
        let edge = vec![("e.relay-token".to_owned(), 1_791_000_010)];
        assert_eq!(
            select_purge(&["e.relay-token".to_owned()], &edge, 1_791_000_000, 10).len(),
            1
        );
    }

    #[test]
    fn a_new_generation_supersedes_every_leftover_of_the_previous_one() {
        // Spool as seen after publishing generation 2 at t+90 while generation 1
        // (minted at t, 4 tokens, 1 consumed) is still on disk: at t+130 the
        // leftovers are expired and, scanned oldest-first, would block the
        // daemon. All of them must be selected for removal; the new batch must
        // not be.
        let gen1: Vec<String> = (1..4)
            .map(|i| format!("1791000000-00-{i:02}.relay-token"))
            .collect();
        let gen2: Vec<String> = (0..4)
            .map(|i| format!("1791000090-00-{i:02}.relay-token"))
            .collect();
        let present: Vec<String> = gen1.iter().chain(&gen2).cloned().collect();
        let superseded = select_superseded(&present, &gen2);
        assert_eq!(superseded, gen1);
        // Nothing to do when the spool already holds only the batch (consumed
        // tokens are simply absent).
        assert!(select_superseded(&gen2[1..], &gen2).is_empty());
        // A leftover from an even older generation goes too.
        let mut with_gen0 = present.clone();
        with_gen0.push("1790999900-00-00.relay-token".to_owned());
        assert_eq!(select_superseded(&with_gen0, &gen2).len(), gen1.len() + 1);
    }

    #[test]
    fn install_supersedes_after_publishing_and_relists_once_on_a_grep_race() {
        let source =
            crate::vm_lab::implementation_source_slice(include_str!("linux_relay_tokens.rs"))
                .expect("implementation slice must parse");
        let start = source
            .find("pub fn install_relay_token_spool(")
            .expect("install fn");
        let body = &source[start..];
        let publish = body.find("cmd_publish_tokens(&names)").expect("publish");
        let supersede = body.find("select_superseded(&after").expect("supersede");
        assert!(
            publish < supersede,
            "supersede only after the new batch is in place"
        );
        assert!(body.contains("exit_code: Some(2)") && body.contains("!relisted"));
    }

    #[test]
    fn expiry_parsing_ignores_garbage_lines() {
        assert!(parse_expiry_listing("grep: x: No such file\nnot a line\n").is_empty());
        assert!(parse_expiry_listing("/p/a.relay-token:expires_at_unix=abc\n").is_empty());
    }

    #[test]
    fn rfc3339_clock_parses_known_instants_and_rejects_everything_else() {
        assert_eq!(
            parse_rfc3339_utc_secs("1970-01-01 00:00:00+00:00").expect("epoch"),
            0
        );
        assert_eq!(
            parse_rfc3339_utc_secs("2000-03-01 00:00:00+00:00").expect("y2k"),
            951_868_800
        );
        assert_eq!(
            parse_rfc3339_utc_secs("2026-10-09 10:31:44+00:00\n").expect("lab date"),
            1_791_541_904
        );
        // Leap day.
        assert_eq!(
            parse_rfc3339_utc_secs("2024-02-29 12:00:00+00:00").expect("leap"),
            1_709_208_000
        );
        for bad in [
            "",
            "2026-10-09 10:31:44",
            "2026-10-09 10:31:44+01:00",
            "2026-10-09T10:31:44+00:00",
            "2026-13-09 10:31:44+00:00",
            "2026-10-09 25:31:44+00:00",
            "1969-12-31 23:59:59+00:00",
            "garbage",
        ] {
            assert!(parse_rfc3339_utc_secs(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn node_clock_is_read_through_argv_without_a_format_string() {
        assert_eq!(
            cmd_node_clock().expect("cmd").as_str(),
            "'date' '-u' '--rfc-3339=seconds'"
        );
    }

    #[test]
    fn environment_check_matches_the_whole_variable_only() {
        let ok = "Environment=RUSTYNET_NODE_ID=daemon-local RUSTYNET_RELAY_SESSION_TOKEN_SPOOL_DIR=/var/lib/rustynet/relay-token-spool RUSTYNET_BACKEND=linux-wireguard\n";
        assert!(environment_has_spool(ok));
        assert!(!environment_has_spool("Environment=RUSTYNET_NODE_ID=x\n"));
        assert!(!environment_has_spool("Environment=\n"));
        assert!(!environment_has_spool(
            "Environment=RUSTYNET_RELAY_SESSION_TOKEN_SPOOL_DIR=/elsewhere\n"
        ));
        assert!(!environment_has_spool(
            "Environment=XRUSTYNET_RELAY_SESSION_TOKEN_SPOOL_DIR=/var/lib/rustynet/relay-token-spool\n"
        ));
    }

    #[test]
    fn report_enforces_the_daemon_file_cap() {
        assert!(report_for(1, MAX_SPOOL_FILES).is_ok());
        let err = report_for(1, MAX_SPOOL_FILES + 1).expect_err("over cap");
        assert!(err.to_string().contains("hard cap"), "{err}");
    }

    #[test]
    fn teardown_removes_the_dropin_before_the_directory() {
        let source =
            crate::vm_lab::implementation_source_slice(include_str!("linux_relay_tokens.rs"))
                .expect("implementation slice must parse");
        let start = source
            .find("pub fn teardown_relay_token_spool(")
            .expect("teardown fn");
        let body = &source[start..];
        let dropin = body.find("DROPIN_FILE").expect("drop-in removal");
        let reload = body.find("cmd_daemon_reload").expect("reload");
        let verify = body
            .find("environment.contains(SPOOL_ENV_KEY)")
            .expect("verify");
        let dir = body.find("RELAY_TOKEN_SPOOL_DIR]").expect("dir removal");
        assert!(dropin < reload && reload < verify && verify < dir);
    }

    #[test]
    fn token_material_never_reaches_a_command_line_or_a_log() {
        let source =
            crate::vm_lab::implementation_source_slice(include_str!("linux_relay_tokens.rs"))
                .expect("implementation slice must parse");
        for forbidden in [
            "relay_session_token_to_wire",
            "parse_relay_session_token_wire",
            "read_to_string(&local",
            "println!",
            "eprintln!",
            "log::",
        ] {
            assert!(
                !source.contains(forbidden),
                "{forbidden} must not appear in the adapter transport"
            );
        }
    }
}
