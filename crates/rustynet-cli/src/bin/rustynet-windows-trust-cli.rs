#![forbid(unsafe_code)]

//! The Windows-side `rustynet` CLI.
//!
//! Historically this binary was a purely offline crypto tool (`trust
//! keygen`/`export-verifier-key`/`issue`) — deliberately kept minimal
//! because the full Unix-oriented `rustynet-cli` binary (`src/main.rs`)
//! is not Windows-buildable (it unconditionally depends on the `nix`
//! crate for uid/gid handling). It now also carries the daemon-control
//! verbs (`role status`/`role set`/`state refresh`) over the Windows
//! named-pipe control channel, reusing:
//!
//! - the exact wire protocol Linux/macOS already use
//!   (`rustynetd::ipc::{IpcCommand, IpcResponse}` +
//!   `rustynetd::windows_ipc::call_windows_daemon_control_raw`), and
//! - the same pure role-transition planner Linux/macOS use
//!   (`rustynet_cli::role_cli`, exposed via the package's `[lib]`
//!   target so this binary and `main.rs` share one planner instead of
//!   forking a second copy — CLAUDE.md §3).
//!
//! Only the `LocalOnly` transition kind (e.g. admin<->client) is wired
//! up end-to-end today; any other `ConcreteAction` fails closed with an
//! explicit "not yet implemented" error rather than silently no-op'ing
//! or guessing (`SignedMembership`/`Irreversible` transitions remain
//! design-only for Windows, matching the current Linux/macOS scope —
//! see `documents/operations/active/CrossOsRoleSwitchPlan_2026-06-24.md`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rand::{TryRngCore, rngs::OsRng};
use rustynet_cli::role_cli;
use rustynet_control::role_audit::{RoleTransitionEvent, RoleTransitionOutcome};
use rustynet_control::role_presets::composition_for;
use rustynet_crypto::{
    KeyCustodyPermissionPolicy, read_encrypted_key_file, write_encrypted_key_file,
};
use rustynetd::exit_codes::ExitCode;
use rustynetd::ipc::{IpcCommand, IpcResponse};
use rustynetd::key_material::read_passphrase_file_explicit;
use rustynetd::windows_ipc::{
    DEFAULT_WINDOWS_DAEMON_PIPE_PATH, WindowsLocalIpcRole, call_windows_daemon_control_raw,
    validate_windows_pipe_path,
};
use zeroize::{Zeroize, Zeroizing};

fn main() {
    match run() {
        Ok(message) => {
            println!("{message}");
        }
        Err(err) => {
            let code = classify_local_error(err.as_str());
            let hint = code.operator_hint();
            if hint.is_empty() {
                eprintln!("error [{code}]: {err}");
            } else {
                eprintln!("error [{code}]: {err}\n  hint: {hint}");
            }
            std::process::exit(code.as_i32());
        }
    }
}

fn classify_local_error(message: &str) -> ExitCode {
    let lower = message.to_ascii_lowercase();
    if lower.starts_with("usage:")
        || lower.contains("unexpected positional argument")
        || lower.contains("missing value for option")
        || lower.contains("missing required option")
        || lower.contains("invalid --")
    {
        ExitCode::BadArgs
    } else if lower.contains("passphrase file path must be absolute")
        || lower.contains("path must not be a symlink")
        || lower.contains("path must reference a regular file")
        || lower.contains("path has no parent")
        || lower.contains("already exists")
        || lower.contains("inspect ")
        || lower.contains("remove old ")
        || lower.contains("create parent failed")
        || lower.contains("write file failed")
        || lower.contains("os randomness unavailable")
    {
        ExitCode::ConfigError
    } else if lower.contains("passphrase source invalid")
        || lower.contains("decrypt ")
        || lower.contains("persist encrypted ")
        || lower.contains("decrypted signing key must be exactly 32 bytes")
    {
        // Trust-key custody / signing-key decryption failures are
        // fail-closed verdicts: corrupted or unauthorized key material
        // must not be retried.
        ExitCode::PolicyReject
    } else {
        ExitCode::GenericFailure
    }
}

fn run() -> Result<String, String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [scope, action, rest @ ..] if scope == "trust" && action == "keygen" => {
            let parser = OptionParser::parse(rest)?;
            trust_keygen(
                parser.required_path("--signing-key-output")?,
                parser.required_path("--signing-key-passphrase-file")?,
                parser.required_path("--verifier-key-output")?,
                parser.has_flag("--force"),
            )
        }
        [scope, action, rest @ ..] if scope == "trust" && action == "export-verifier-key" => {
            let parser = OptionParser::parse(rest)?;
            trust_export_verifier_key(
                parser.required_path("--signing-key")?,
                parser.required_path("--signing-key-passphrase-file")?,
                parser.required_path("--output")?,
            )
        }
        [scope, action, rest @ ..] if scope == "trust" && action == "issue" => {
            let parser = OptionParser::parse(rest)?;
            trust_issue(
                parser.required_path("--signing-key")?,
                parser.required_path("--signing-key-passphrase-file")?,
                parser.required_path("--output")?,
                parser.parse_u64_or_default("--updated-at-unix", unix_now())?,
                parser.parse_u64_or_default("--nonce", generate_nonce())?,
            )
        }
        [scope, action] if scope == "role" && (action == "status" || action == "show") => {
            execute_role_status()
        }
        [scope] if scope == "role" => execute_role_status(),
        [scope, action] if scope == "role" && action == "list" => Ok(role_cli::render_role_list()),
        [scope, action, raw_target] if scope == "role" && action == "set" => {
            execute_role_set(raw_target)
        }
        [scope, action] if scope == "state" && action == "refresh" => execute_state_refresh(),
        _ => Err(
            "usage: rustynet <trust <keygen|export-verifier-key|issue>|role <status|list|set <preset>>|state refresh> [options]"
                .to_owned(),
        ),
    }
}

#[derive(Debug)]
struct OptionParser<'a> {
    args: &'a [String],
}

impl<'a> OptionParser<'a> {
    fn parse(args: &'a [String]) -> Result<Self, String> {
        let parser = Self { args };
        let mut index = 0usize;
        while index < args.len() {
            if !args[index].starts_with("--") {
                return Err(format!("unexpected positional argument: {}", args[index]));
            }
            if parser.is_flag(args[index].as_str()) {
                index += 1;
            } else {
                if index + 1 >= args.len() || args[index + 1].starts_with("--") {
                    return Err(format!("missing value for option {}", args[index]));
                }
                index += 2;
            }
        }
        Ok(parser)
    }

    fn is_flag(&self, key: &str) -> bool {
        key == "--force"
    }

    fn has_flag(&self, key: &str) -> bool {
        self.args.iter().any(|arg| arg == key)
    }

    fn required_path(&self, key: &str) -> Result<PathBuf, String> {
        self.required_value(key).map(PathBuf::from)
    }

    fn required_value(&self, key: &str) -> Result<String, String> {
        let mut index = 0usize;
        while index < self.args.len() {
            if self.args[index] == key {
                if index + 1 >= self.args.len() || self.args[index + 1].starts_with("--") {
                    return Err(format!("missing value for option {key}"));
                }
                return Ok(self.args[index + 1].clone());
            }
            index += 1;
        }
        Err(format!("missing required option {key}"))
    }

    fn parse_u64_or_default(&self, key: &str, default: u64) -> Result<u64, String> {
        let mut index = 0usize;
        while index < self.args.len() {
            if self.args[index] == key {
                if index + 1 >= self.args.len() || self.args[index + 1].starts_with("--") {
                    return Err(format!("missing value for option {key}"));
                }
                return self.args[index + 1]
                    .parse::<u64>()
                    .map_err(|err| format!("invalid {key} value: {err}"));
            }
            index += 1;
        }
        Ok(default)
    }
}

fn trust_keygen(
    signing_key_path: PathBuf,
    signing_key_passphrase_path: PathBuf,
    verifier_key_output_path: PathBuf,
    force: bool,
) -> Result<String, String> {
    let mut seed = [0u8; 32];
    fill_os_random_bytes(&mut seed, "trust signing key")?;
    persist_encrypted_secret_material(
        &signing_key_path,
        &seed,
        &signing_key_passphrase_path,
        "trust signing key",
        force,
    )?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    write_text_file(
        &verifier_key_output_path,
        &format!("{}\n", hex_bytes(signing_key.verifying_key().as_bytes())),
    )?;
    Ok(format!(
        "trust signing key initialized: signing_key={} verifier_key_output={}",
        signing_key_path.display(),
        verifier_key_output_path.display()
    ))
}

fn trust_export_verifier_key(
    signing_key_path: PathBuf,
    signing_key_passphrase_path: PathBuf,
    output_path: PathBuf,
) -> Result<String, String> {
    let signing_key = load_signing_key(&signing_key_path, &signing_key_passphrase_path)?;
    write_text_file(
        &output_path,
        &format!("{}\n", hex_bytes(signing_key.verifying_key().as_bytes())),
    )?;
    Ok(format!(
        "trust verifier key exported: signing_key={} output={}",
        signing_key_path.display(),
        output_path.display()
    ))
}

fn trust_issue(
    signing_key_path: PathBuf,
    signing_key_passphrase_path: PathBuf,
    output_path: PathBuf,
    updated_at_unix: u64,
    nonce: u64,
) -> Result<String, String> {
    let signing_key = load_signing_key(&signing_key_path, &signing_key_passphrase_path)?;
    let payload = format!(
        "version=3\nsigned_control_valid=true\nsigned_data_age_secs=0\nclock_skew_secs=0\nupdated_at_unix={updated_at_unix}\nnonce={nonce}\n"
    );
    let signature = signing_key.sign(payload.as_bytes());
    write_text_file(
        &output_path,
        &format!("{payload}signature={}\n", hex_bytes(&signature.to_bytes())),
    )?;
    Ok(format!(
        "trust evidence issued: output={} updated_at_unix={} nonce={}",
        output_path.display(),
        updated_at_unix,
        nonce
    ))
}

fn persist_encrypted_secret_material(
    path: &Path,
    secret: &[u8],
    passphrase_path: &Path,
    label: &str,
    force: bool,
) -> Result<(), String> {
    if !passphrase_path.is_absolute() {
        return Err(format!(
            "{label} passphrase file path must be absolute: {}",
            passphrase_path.display()
        ));
    }
    if path.exists() {
        let metadata =
            fs::symlink_metadata(path).map_err(|err| format!("inspect {label} failed: {err}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("{label} path must not be a symlink"));
        }
        if !metadata.file_type().is_file() {
            return Err(format!("{label} path must reference a regular file"));
        }
        if !force {
            return Err(format!(
                "{label} already exists at {}; use --force to overwrite",
                path.display()
            ));
        }
        fs::remove_file(path).map_err(|err| format!("remove old {label} failed: {err}"))?;
    }
    let passphrase = read_passphrase_file_explicit(passphrase_path).map_err(|err| {
        format!(
            "{label} passphrase source invalid ({}): {err}",
            passphrase_path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent: {}", path.display()))?;
    write_encrypted_key_file(
        parent,
        path,
        secret,
        passphrase.as_str(),
        encrypted_secret_permission_policy(path),
    )
    .map_err(|err| {
        format!(
            "persist encrypted {label} failed ({}): {err}",
            path.display()
        )
    })
}

fn load_signing_key(path: &Path, passphrase_path: &Path) -> Result<SigningKey, String> {
    let secret = load_encrypted_secret_material(path, passphrase_path, "signing key")?;
    if secret.len() != 32 {
        return Err("decrypted signing key must be exactly 32 bytes".to_owned());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(secret.as_slice());
    let key = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    Ok(key)
}

fn load_encrypted_secret_material(
    path: &Path,
    passphrase_path: &Path,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if !passphrase_path.is_absolute() {
        return Err(format!(
            "{label} passphrase file path must be absolute: {}",
            passphrase_path.display()
        ));
    }
    if !path.is_file() {
        return Err(format!("{label} path must reference a regular file"));
    }
    let passphrase = read_passphrase_file_explicit(passphrase_path).map_err(|err| {
        format!(
            "{label} passphrase source invalid ({}): {err}",
            passphrase_path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent: {}", path.display()))?;
    let secret = read_encrypted_key_file(
        parent,
        path,
        passphrase.as_str(),
        encrypted_secret_permission_policy(path),
    )
    .map_err(|err| format!("decrypt {label} failed ({}): {err}", path.display()))?;
    Ok(Zeroizing::new(secret))
}

fn encrypted_secret_permission_policy(_path: &Path) -> KeyCustodyPermissionPolicy {
    KeyCustodyPermissionPolicy::default()
}

fn write_text_file(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create parent failed: {err}"))?;
    }
    fs::write(path, body).map_err(|err| format!("write file failed: {err}"))
}

fn fill_os_random_bytes(bytes: &mut [u8], label: &str) -> Result<(), String> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|err| format!("os randomness unavailable for {label}: {err}"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn generate_nonce() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    (nanos & u128::from(u64::MAX)) as u64
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ─── daemon-control (named-pipe IPC) ────────────────────────────────────────

fn daemon_pipe_path() -> PathBuf {
    std::env::var("RUSTYNET_DAEMON_SOCKET").map_or_else(
        |_| PathBuf::from(DEFAULT_WINDOWS_DAEMON_PIPE_PATH),
        PathBuf::from,
    )
}

/// Send one daemon-control command over the Windows named pipe. This is
/// the Windows-CLI counterpart of `rustynet-cli`'s `send_command`
/// (`main.rs`, `#[cfg(windows)]` branch) — same wire protocol
/// (`IpcCommand::as_wire`/`IpcResponse::from_wire`), same pipe-path
/// hardening (`validate_windows_pipe_path`), same underlying transport
/// (`call_windows_daemon_control_raw`). The two call sites are small,
/// non-semantic glue; the actual authorization/hardening logic they both
/// call into lives once in `rustynetd::windows_ipc`.
fn send_command(command: IpcCommand) -> Result<IpcResponse, String> {
    let pipe_path = daemon_pipe_path();
    validate_windows_pipe_path(pipe_path.as_path(), WindowsLocalIpcRole::DaemonControl)
        .map_err(|err| format!("daemon named-pipe path failed validation: {err}"))?;
    let line = call_windows_daemon_control_raw(
        pipe_path.as_path(),
        &command.as_wire(),
        Duration::from_secs(5),
    )?;
    Ok(IpcResponse::from_wire(&line))
}

fn execute_role_status() -> Result<String, String> {
    let response = send_command(IpcCommand::Status)?;
    if !response.ok {
        return Err(format!("daemon error: {}", response.message));
    }
    let preset = role_cli::resolve_preset_from_status(response.message.as_str())
        .map_err(|err| err.user_message())?;
    let comp = composition_for(preset);
    let mut out = format!(
        "current role: {preset} (primary={}, capabilities={})\n",
        comp.primary,
        if comp.capabilities.is_empty() {
            "none".to_owned()
        } else {
            comp.capabilities
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    out.push_str(&format!("description: {}\n", preset.description()));
    Ok(out)
}

fn execute_state_refresh() -> Result<String, String> {
    let response = send_command(IpcCommand::StateRefresh)?;
    if !response.ok {
        return Err(response.message);
    }
    Ok(response.message)
}

fn execute_role_set(raw_target: &str) -> Result<String, String> {
    let target = role_cli::parse_preset_arg(raw_target).map_err(|err| err.user_message())?;
    let response = send_command(IpcCommand::Status)?;
    if !response.ok {
        return Err(format!("daemon error: {}", response.message));
    }
    let current = role_cli::resolve_preset_from_status(response.message.as_str())
        .map_err(|err| err.user_message())?;
    let plan = role_cli::plan_concrete_actions(
        current,
        target,
        false,
        PathBuf::from(role_cli::platform_default_daemon_env_path()),
    );
    execute_role_plan(plan)
}

/// Windows-CLI counterpart of `rustynet-cli`'s `execute_role_plan`
/// (`main.rs`). Same audit-emission contract (RSA-0014: a durable audit
/// record is mandatory for `SignedMembership`/`Irreversible`
/// transitions, best-effort for `Identity`/`LocalOnly`) applied to
/// whichever `ConcreteAction`s this binary actually knows how to
/// execute (see [`execute_windows_role_action`]).
fn execute_role_plan(plan: role_cli::RoleSetPlan) -> Result<String, String> {
    match plan {
        role_cli::RoleSetPlan::Blocked { from, to, error } => {
            if let Err(audit_err) = emit_role_audit(&RoleTransitionEvent::PresetTransition {
                from,
                to,
                outcome: RoleTransitionOutcome::Blocked,
                error_category: Some(role_cli::role_cli_error_category(&error)),
            }) {
                eprintln!("[warn] {audit_err}");
            }
            Err(format!(
                "transition {from} → {to} blocked: {}",
                error.user_message()
            ))
        }
        role_cli::RoleSetPlan::Allowed {
            from,
            to,
            kind,
            actions,
            followup_instructions,
        } => {
            let mut summary = format!("transition planned: {from} → {to}\n");
            for action in &actions {
                match execute_windows_role_action(action) {
                    Ok(action_summary) => {
                        summary.push_str(&format!("  applied: {action_summary}\n"));
                    }
                    Err(err) => {
                        if let Err(audit_err) =
                            emit_role_audit(&RoleTransitionEvent::PresetTransition {
                                from,
                                to,
                                outcome: RoleTransitionOutcome::Failed,
                                error_category: Some("side_effect_failed"),
                            })
                        {
                            eprintln!("[warn] {audit_err}");
                        }
                        return Err(err);
                    }
                }
            }
            if !followup_instructions.is_empty() {
                summary.push_str("follow-up:\n");
                for instruction in &followup_instructions {
                    summary.push_str(&format!("  - {instruction}\n"));
                }
            }
            let audit_result = emit_role_audit(&RoleTransitionEvent::PresetTransition {
                from,
                to,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            });
            finalize_role_audit(&kind, audit_result)?;
            Ok(summary)
        }
    }
}

/// Execute one [`role_cli::ConcreteAction`]. Only `NoOp` and
/// `WriteNodeRoleEnv` are implemented today — the two side-effects the
/// `LocalOnly` transition kind (e.g. admin<->client) needs. Every other
/// action (route advertise/retract, sibling-service deploy/undeploy)
/// backs a `SignedMembership` transition, which remains design-only for
/// Windows (see the module doc comment); failing closed here rather than
/// silently no-op'ing means an operator who tries e.g. `role set exit`
/// gets an honest error instead of a half-applied transition.
fn execute_windows_role_action(action: &role_cli::ConcreteAction) -> Result<String, String> {
    match action {
        role_cli::ConcreteAction::NoOp => Ok("no change required".to_owned()),
        role_cli::ConcreteAction::WriteNodeRoleEnv {
            new_primary,
            env_path,
            restart_required: _,
        } => {
            update_node_role_windows_env_file(env_path, new_primary.as_str())?;
            Ok(format!(
                "set --node-role {} in {} (service restart applies it)",
                new_primary,
                env_path.display()
            ))
        }
        other => Err(format!(
            "{other:?} is not yet implemented by the Windows CLI (fail-closed; only LocalOnly \
             admin<->client transitions are supported on Windows today — see \
             CrossOsRoleSwitchPlan_2026-06-24.md)"
        )),
    }
}

/// Windows counterpart of `rustynet-cli`'s `update_node_role_windows_env_file`
/// (`main.rs`). Both call the same pure rewrite
/// (`role_cli::rewrite_windows_daemon_env_node_role`); only the small,
/// non-semantic file-I/O glue (read/atomic-write) is duplicated across
/// the two binaries.
fn update_node_role_windows_env_file(env_path: &Path, new_role: &str) -> Result<(), String> {
    let existing = fs::read_to_string(env_path).map_err(|err| {
        format!(
            "read {} failed (daemon not installed on this host?): {err}",
            env_path.display()
        )
    })?;

    let (updated, node_role_replaced) =
        role_cli::rewrite_windows_daemon_env_node_role(&existing, new_role);
    if !node_role_replaced {
        return Err(format!(
            "{}: RUSTYNETD_DAEMON_ARGS_JSON has no `--node-role` entry to update; \
             refusing to persist a role the daemon will not read",
            env_path.display()
        ));
    }

    let parent = env_path
        .parent()
        .ok_or_else(|| format!("env path {} has no parent directory", env_path.display()))?;
    let tmp = parent.join(format!(
        ".{}.role-update.tmp",
        env_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rustynetd.env")
    ));
    fs::write(&tmp, updated.as_bytes())
        .map_err(|err| format!("write {} failed: {err}", tmp.display()))?;
    fs::rename(&tmp, env_path).map_err(|err| {
        format!(
            "rename {} → {} failed: {err}",
            tmp.display(),
            env_path.display()
        )
    })?;
    Ok(())
}

fn audit_timestamp_unix() -> u64 {
    unix_now()
}

fn emit_role_audit(event: &RoleTransitionEvent) -> Result<(), String> {
    let path = role_cli::resolve_audit_log_path();
    rustynet_control::role_audit::append_role_audit_entry(&path, audit_timestamp_unix(), event)
        .map(|_entry| ())
        .map_err(|err| {
            format!(
                "role-transition audit log append failed (path={}): {err}",
                path.display()
            )
        })
}

/// RSA-0014 — mirrors `rustynet-cli`'s `finalize_role_audit` (`main.rs`):
/// an un-writable audit log is fail-closed for security-sensitive
/// (`SignedMembership`/`Irreversible`) transitions, best-effort for
/// lower-sensitivity ones.
fn finalize_role_audit(
    kind: &rustynet_control::role_presets::TransitionKind,
    append_result: Result<(), String>,
) -> Result<(), String> {
    match append_result {
        Ok(()) => Ok(()),
        Err(err) => {
            if kind.requires_owner_signature() {
                Err(format!(
                    "fail-closed: durable audit record could not be written for a \
                     security-sensitive role transition; refusing to report success — {err}"
                ))
            } else {
                eprintln!("[warn] {err}");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Windows role-set env-file persistence (update_node_role_windows_env_file) -----

    #[test]
    fn update_node_role_windows_env_file_rewrites_json_array_and_preserves_other_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = dir.path().join("rustynetd.env");
        std::fs::write(
            &env,
            concat!(
                "# reviewed Windows service config\n",
                "RUSTYNETD_DAEMON_ARGS_JSON=[\"--backend\",\"windows-wireguard-nt\",\"--node-id\",\"windows-client-1\",\"--node-role\",\"client\"]\n",
            ),
        )
        .expect("write env");
        update_node_role_windows_env_file(&env, "admin").expect("update should succeed");
        let out = std::fs::read_to_string(&env).expect("read back");
        assert!(
            out.contains(r#""--node-role","admin""#),
            "role updated in JSON array: {out}"
        );
        assert!(!out.contains(r#""client""#), "no stale role: {out}");
        assert!(
            out.contains(r#""--node-id","windows-client-1""#),
            "unrelated array entries preserved: {out}"
        );
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.contains("role-update.tmp"))
            .collect();
        assert!(
            strays.is_empty(),
            "atomic rename must leave no temp: {strays:?}"
        );
    }

    #[test]
    fn update_node_role_windows_env_file_fails_closed_without_node_role_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = dir.path().join("rustynetd.env");
        let body = "RUSTYNETD_DAEMON_ARGS_JSON=[\"--backend\",\"windows-wireguard-nt\"]\n";
        std::fs::write(&env, body).expect("write env");
        let err = update_node_role_windows_env_file(&env, "admin").expect_err("must fail closed");
        assert!(
            err.contains("--node-role"),
            "error must name the missing entry: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&env).unwrap(),
            body,
            "the env file must be left unchanged on fail-closed"
        );
    }

    #[test]
    fn update_node_role_windows_env_file_fails_closed_on_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = dir.path().join("rustynetd.env");
        let err = update_node_role_windows_env_file(&env, "admin").expect_err("must fail closed");
        assert!(err.contains("read"), "error names the read failure: {err}");
    }

    // ----- role-set plan execution: fail-closed on unimplemented actions -----

    #[test]
    fn execute_windows_role_action_fails_closed_for_unimplemented_actions() {
        let err = execute_windows_role_action(&role_cli::ConcreteAction::AdvertiseDefaultRoute)
            .expect_err("must fail closed on an unimplemented action");
        assert!(
            err.contains("not yet implemented"),
            "error must explain the gap: {err}"
        );
    }

    #[test]
    fn execute_windows_role_action_handles_noop() {
        let out = execute_windows_role_action(&role_cli::ConcreteAction::NoOp)
            .expect("NoOp must always succeed");
        assert_eq!(out, "no change required");
    }

    // ----- send_command: daemon pipe path resolution -----

    #[test]
    fn daemon_pipe_path_defaults_to_the_reviewed_rustynet_pipe() {
        // Only assert the fallback when the env override isn't set by an
        // outer harness, matching role_cli's own env-fallback test style.
        if std::env::var_os("RUSTYNET_DAEMON_SOCKET").is_none() {
            assert_eq!(
                daemon_pipe_path(),
                PathBuf::from(DEFAULT_WINDOWS_DAEMON_PIPE_PATH)
            );
        }
    }
}
