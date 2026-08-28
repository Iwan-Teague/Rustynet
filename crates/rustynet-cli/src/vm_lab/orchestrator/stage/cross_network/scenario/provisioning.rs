//! Shared live-lab provisioning primitives for the ported cross-network
//! scenarios, from `scripts/e2e/live_lab_common.sh`.
//!
//! Only the parts the four ported scenarios actually use are here. The shell
//! library is platform-generic (`linux` / `macos` / `windows` arms on every
//! path helper); every cross-network scenario host is a Linux guest, so the
//! Linux arm is the only one ported and the platform parameter is gone.
//!
//! # How bytes cross the argv seam
//!
//! The shell moved files between guests with `scp`: read a file on the issuing
//! host into a local temporary, then copy it out to each peer. A
//! [`NetLeafRunner`] has no file channel — it runs argv and returns output —
//! and [`substrate::validate_argv`] rejects control characters in argv, so a
//! multi-line bundle cannot be passed as a raw argument.
//!
//! So opaque bytes cross as single-line base64: [`read_remote_base64`] reads a
//! file with `base64 -w 0`, [`write_remote_base64`] writes it back through a
//! **fixed** shell script whose path, mode and payload arrive as positional
//! parameters. No value is ever substituted into a command string: the script
//! text is a compile-time constant and `$1`/`$2`/`$3` are argv elements the
//! runner quotes once, centrally. That is the same guarantee the rest of CN-3
//! makes, expressed for the one operation that needs a byte payload.
//!
//! # What is validated before anything reaches argv
//!
//! [`validate_argv_value`] rejects empty values, control characters and
//! leading `-` (which would be read as an option by whatever binary receives
//! it). [`validate_node_id`] narrows further to an allowlist, because node ids
//! are pasted into staging *filenames*. Spec fields additionally reject the
//! `;` and `|` delimiters — the shell concatenated them unchecked, so a node id
//! containing `;` could forge an extra entry in a signed-assignment spec.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;

use super::super::substrate::NetLeafRunner;
use super::{DAEMON_SOCKET, REMOTE_RUSTYNET_BIN, capture_root, run_root, run_root_allow_failure};

// ───────────────────────────── remote paths ─────────────────────────────

/// `rustynet_wg_pub_key_path linux`.
pub const WG_PUB_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.pub";
/// Where `e2e-issue-assignment-bundles-from-env` leaves its output.
pub const ASSIGNMENT_ISSUE_DIR: &str = "/run/rustynet/assignment-issue";
/// Where `e2e-issue-traversal-bundles-from-env` leaves its output.
pub const TRAVERSAL_ISSUE_DIR: &str = "/run/rustynet/traversal-issue";
/// `rustynet_config_dir linux`.
pub const CONFIG_DIR: &str = "/etc/rustynet";
/// `rustynet_state_root linux`.
pub const STATE_ROOT: &str = "/var/lib/rustynet";
/// `rustynet_assignment_pub_path linux`.
pub const ASSIGNMENT_PUB_PATH: &str = "/etc/rustynet/assignment.pub";
/// `rustynet_assignment_bundle_path linux`.
pub const ASSIGNMENT_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.assignment";
/// `rustynet_assignment_watermark_path linux`.
pub const ASSIGNMENT_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.assignment.watermark";
/// `rustynet_assignment_refresh_env_path linux`.
pub const ASSIGNMENT_REFRESH_ENV_PATH: &str = "/etc/rustynet/assignment-refresh.env";
/// Traversal verifying key, installed beside the assignment one.
pub const TRAVERSAL_PUB_PATH: &str = "/etc/rustynet/traversal.pub";
/// Signed traversal bundle.
pub const TRAVERSAL_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.traversal";
/// Traversal anti-replay watermark, cleared whenever a fresh bundle lands.
pub const TRAVERSAL_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.traversal.watermark";
/// Staging directory for files being installed into place.
pub const STAGING_DIR: &str = "/tmp";

/// The signing secret the assignment-refresh unit reads.
pub const ASSIGNMENT_SIGNING_SECRET: &str = "/etc/rustynet/assignment.signing.secret";
/// The systemd credential the refresh unit unlocks that secret with.
pub const ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE: &str =
    "/run/credentials/rustynetd-assignment-refresh.service/signing_key_passphrase";
/// `RUSTYNET_ASSIGNMENT_TTL_SECS` as the shell wrote it.
pub const ASSIGNMENT_TTL_SECS: &str = "3600";
/// `RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS` as the shell wrote it.
pub const ASSIGNMENT_MIN_REMAINING_SECS: &str = "300";

/// The unix group the daemon runs as; trust artifacts are group-readable to it.
const RUSTYNETD_GROUP: &str = "rustynetd";

// ───────────────────────────── phase labelling ─────────────────────────────

/// Tag a fallible step with the phase it belongs to.
///
/// The shell set `FAILURE_SUMMARY="<phase>"` before each block, so an
/// unhandled error under `set -e` reported the phase and nothing else. This
/// keeps the phase as the prefix — the operator-facing "what stopped this" is
/// unchanged — and appends the underlying error, which the shell only ever
/// wrote to its log file. Explicit `FAILURE_SUMMARY="…"; return 1` failures are
/// reproduced verbatim and do not go through here.
pub fn during<T>(phase: &str, result: Result<T, String>) -> Result<T, String> {
    result.map_err(|err| format!("{phase}: {err}"))
}

// ───────────────────────────── value validation ─────────────────────────────

/// Reject a value that must not reach argv: empty, control characters, or a
/// leading `-` that the receiving binary would parse as an option.
///
/// The shell had no equivalent — every value went through `printf %q` or a
/// hand-written `'…'` and an id beginning with `-` reached the CLI as a flag.
pub fn validate_argv_value(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!(
            "{label} must not contain control characters: {value:?}"
        ));
    }
    if value.starts_with('-') {
        return Err(format!("{label} must not look like an option: {value:?}"));
    }
    Ok(())
}

/// As [`validate_argv_value`], and additionally reject the `;` and `|`
/// characters that delimit the assignment/allow/traversal specs. A node id
/// carrying one would silently forge an extra spec entry.
pub fn validate_spec_field(label: &str, value: &str) -> Result<(), String> {
    validate_argv_value(label, value)?;
    if value.contains(';') || value.contains('|') {
        return Err(format!(
            "{label} must not contain the spec delimiters ';' or '|': {value:?}"
        ));
    }
    Ok(())
}

/// A node id becomes part of a staging *filename*, so it is held to an
/// allowlist rather than a denylist: ASCII letters, digits, `.`, `_`, `-`, and
/// never a relative-path component.
pub fn validate_node_id(node_id: &str) -> Result<(), String> {
    validate_spec_field("node id", node_id)?;
    if node_id == "." || node_id == ".." {
        return Err(format!("node id must not be a path component: {node_id:?}"));
    }
    if !node_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(format!(
            "node id must contain only ASCII letters, digits, '.', '_' or '-': {node_id:?}"
        ));
    }
    Ok(())
}

/// Validate a base64 payload before it is handed to a remote `base64 -d`:
/// non-empty and standard-alphabet only. A payload that fails here never
/// reaches the guest.
fn validate_base64(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
    {
        return Err(format!("{label} is not standard base64"));
    }
    Ok(())
}

// ───────────────────────────── remote file I/O ─────────────────────────────

/// Read a remote file as one line of base64. `capture_root` fails closed on a
/// non-zero exit, so a missing or unreadable file is an error, never an empty
/// payload that later writes an empty bundle.
pub fn read_remote_base64(runner: &dyn NetLeafRunner, path: &str) -> Result<String, String> {
    validate_argv_value("remote path", path)?;
    let encoded = capture_root(runner, &["base64", "-w", "0", path])?;
    validate_base64(&format!("contents of {path}"), &encoded)?;
    Ok(encoded)
}

/// The fixed script [`write_remote_base64`] runs. `$0` is the script name and
/// `$1`/`$2`/`$3` are the path, mode and base64 payload — all argv, never
/// interpolated. `umask 077` keeps the file private between creation and the
/// explicit `chmod`.
const WRITE_BASE64_SCRIPT: &str =
    "set -eu; umask 077; printf '%s' \"$3\" | base64 -d > \"$1\"; chmod \"$2\" \"$1\"";

/// Write `payload` (base64) to `path` on the guest with mode `mode`.
pub fn write_remote_base64(
    runner: &dyn NetLeafRunner,
    path: &str,
    mode: &str,
    payload: &str,
) -> Result<(), String> {
    validate_argv_value("remote path", path)?;
    validate_argv_value("file mode", mode)?;
    validate_base64("file payload", payload)?;
    run_root(
        runner,
        &["sh", "-c", WRITE_BASE64_SCRIPT, "sh", path, mode, payload],
    )
}

/// Write UTF-8 text to `path` on the guest, encoding it for transit.
pub fn write_remote_text(
    runner: &dyn NetLeafRunner,
    path: &str,
    mode: &str,
    contents: &str,
) -> Result<(), String> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(contents.as_bytes());
    write_remote_base64(runner, path, mode, &encoded)
}

/// Remove remote paths, tolerating absence — the shell's `rm -f`.
pub fn remove_remote(runner: &dyn NetLeafRunner, paths: &[&str]) -> Result<(), String> {
    let mut argv: Vec<&str> = vec!["rm", "-f"];
    for path in paths {
        validate_argv_value("remote path", path)?;
        argv.push(path);
    }
    run_root(runner, &argv)
}

/// Run `argv` unprivileged and return trimmed stdout, treating a non-zero exit
/// as empty output — the shell's `live_lab_capture "<cmd> || true"`. A
/// transport failure still fails closed.
pub fn capture_allow_failure(runner: &dyn NetLeafRunner, argv: &[&str]) -> Result<String, String> {
    let output = runner
        .run(argv)
        .map_err(|err| format!("{argv:?}: transport failure: {err}"))?;
    Ok(output.stdout.trim().to_owned())
}

// ───────────────────────────── WireGuard identity ─────────────────────────────

/// Read a guest's WireGuard public key and return it as lowercase hex.
///
/// `live_lab_collect_pubkey_hex`: `cat <path> | tr -d '[:space:]'`, base64
/// decode, then require `^[0-9a-f]{64}$`. Whitespace stripping happens here
/// rather than in a remote `tr` so the pipeline is one argv, and the length
/// check is what makes a partial read fail closed instead of producing a short
/// key that would later be rejected far from its cause.
pub fn collect_pubkey_hex(runner: &dyn NetLeafRunner) -> Result<String, String> {
    let raw = capture_root(runner, &["cat", WG_PUB_KEY_PATH])?;
    let stripped: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(stripped.as_bytes())
        .map_err(|err| format!("failed to decode wireguard pubkey: {err}"))?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    if hex.len() != 64 {
        return Err(format!(
            "failed to decode wireguard pubkey: expected 32 key bytes, decoded {}",
            bytes.len()
        ));
    }
    Ok(hex)
}

// ───────────────────────────── spec builders ─────────────────────────────

/// One entry of `RUSTYNET_ASSIGNMENT_NODES`: `<node-id>|<addr>:<port>|<pubkey-hex>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpec {
    node_id: String,
    endpoint: String,
    pubkey_hex: String,
}

impl NodeSpec {
    pub fn new(
        node_id: impl Into<String>,
        address: &str,
        port: u16,
        pubkey_hex: impl Into<String>,
    ) -> Result<Self, String> {
        let node_id = node_id.into();
        let pubkey_hex = pubkey_hex.into();
        validate_node_id(&node_id)?;
        validate_spec_field("node address", address)?;
        validate_spec_field("node public key", &pubkey_hex)?;
        Ok(Self {
            node_id,
            endpoint: format!("{address}:{port}"),
            pubkey_hex,
        })
    }

    fn render(&self) -> String {
        format!("{}|{}|{}", self.node_id, self.endpoint, self.pubkey_hex)
    }
}

/// `RUSTYNET_ASSIGNMENT_NODES`: node entries joined by `;`, in the order the
/// shell wrote them (exit first, then relay, then client).
pub fn nodes_spec(nodes: &[NodeSpec]) -> Result<String, String> {
    if nodes.is_empty() {
        return Err("nodes spec must name at least one node".to_owned());
    }
    Ok(nodes
        .iter()
        .map(NodeSpec::render)
        .collect::<Vec<_>>()
        .join(";"))
}

/// `RUSTYNET_ASSIGNMENT_ALLOW`: directed `from|to` pairs joined by `;`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowSpec {
    pairs: Vec<(String, String)>,
}

impl AllowSpec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one directed pair. Both halves must be added for a bidirectional
    /// allow — the shell wrote both explicitly and so does this.
    pub fn allow(mut self, from: &str, to: &str) -> Result<Self, String> {
        validate_spec_field("allow source node id", from)?;
        validate_spec_field("allow destination node id", to)?;
        self.pairs.push((from.to_owned(), to.to_owned()));
        Ok(self)
    }

    pub fn render(&self) -> Result<String, String> {
        if self.pairs.is_empty() {
            return Err("allow spec must contain at least one pair".to_owned());
        }
        Ok(self
            .pairs
            .iter()
            .map(|(from, to)| format!("{from}|{to}"))
            .collect::<Vec<_>>()
            .join(";"))
    }
}

/// `ASSIGNMENTS_SPEC`: `<node-id>|<exit-node-id>` pairs joined by `;`, with `-`
/// meaning "this node has no exit of its own".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssignmentsSpec {
    entries: Vec<(String, Option<String>)>,
}

impl AssignmentsSpec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn assign(mut self, node_id: &str, exit_node_id: Option<&str>) -> Result<Self, String> {
        validate_spec_field("assignment node id", node_id)?;
        if let Some(exit) = exit_node_id {
            validate_spec_field("assignment exit node id", exit)?;
        }
        self.entries
            .push((node_id.to_owned(), exit_node_id.map(str::to_owned)));
        Ok(self)
    }

    pub fn render(&self) -> Result<String, String> {
        if self.entries.is_empty() {
            return Err("assignments spec must contain at least one entry".to_owned());
        }
        Ok(self
            .entries
            .iter()
            .map(|(node, exit)| format!("{node}|{}", exit.as_deref().unwrap_or("-")))
            .collect::<Vec<_>>()
            .join(";"))
    }
}

// ───────────────────────────── env files ─────────────────────────────

/// A `KEY="value"` env file, in insertion order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvFile {
    entries: Vec<(String, String)>,
}

impl EnvFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(mut self, key: &str, value: &str) -> Result<Self, String> {
        validate_argv_value("env key", key)?;
        if value.contains('\n') || value.contains('\r') {
            return Err("env value contains newline characters".to_owned());
        }
        self.entries.push((key.to_owned(), value.to_owned()));
        Ok(self)
    }

    /// Render the file exactly as `live_lab_append_env_assignment` did:
    /// double-quoted, with `\`, `"`, `$` and backtick escaped so the value
    /// survives the shell that sources it.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (key, value) in &self.entries {
            let escaped = value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('$', "\\$")
                .replace('`', "\\`");
            out.push_str(key);
            out.push_str("=\"");
            out.push_str(&escaped);
            out.push_str("\"\n");
        }
        out
    }
}

/// The `assignment-refresh.env` key set, in the shell's order.
///
/// `RUSTYNET_ASSIGNMENT_EXIT_NODE_ID` is present only when the node routes
/// through an exit — the shell omitted the key entirely for the exit itself.
pub fn assignment_refresh_env(
    target_node_id: &str,
    nodes_spec: &str,
    allow_spec: &str,
    exit_node_id: Option<&str>,
) -> Result<EnvFile, String> {
    validate_node_id(target_node_id)?;
    let mut env = EnvFile::new()
        .set("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID", target_node_id)?
        .set("RUSTYNET_ASSIGNMENT_NODES", nodes_spec)?
        .set("RUSTYNET_ASSIGNMENT_ALLOW", allow_spec)?
        .set(
            "RUSTYNET_ASSIGNMENT_SIGNING_SECRET",
            ASSIGNMENT_SIGNING_SECRET,
        )?
        .set(
            "RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE",
            ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE,
        )?
        .set("RUSTYNET_ASSIGNMENT_TTL_SECS", ASSIGNMENT_TTL_SECS)?
        .set(
            "RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS",
            ASSIGNMENT_MIN_REMAINING_SECS,
        )?;
    if let Some(exit) = exit_node_id {
        validate_node_id(exit)?;
        env = env.set("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID", exit)?;
    }
    Ok(env)
}

// ───────────────────────────── bundle issuance ─────────────────────────────

/// Write `env` to `remote_env_path`, run `subcommand`, then remove the file.
///
/// The shell's ordering is preserved exactly, because it is the security-
/// relevant part: on failure the env file (which names the signing secret) is
/// removed on a best-effort basis and the *issuance* error is what the caller
/// sees; on success the removal is required, so a signing-secret reference left
/// behind on the guest fails the step rather than passing quietly.
fn issue_bundles_from_env(
    runner: &dyn NetLeafRunner,
    subcommand: &str,
    env: &EnvFile,
    remote_env_path: &str,
) -> Result<(), String> {
    validate_argv_value("remote env path", remote_env_path)?;
    write_remote_text(runner, remote_env_path, "0600", &env.render())?;
    let issued = run_root(
        runner,
        &[
            REMOTE_RUSTYNET_BIN,
            "ops",
            subcommand,
            "--env-file",
            remote_env_path,
        ],
    );
    if let Err(err) = issued {
        let _ = run_root_allow_failure(runner, &["rm", "-f", remote_env_path]);
        return Err(err);
    }
    remove_remote(runner, &[remote_env_path])
}

/// `rustynet ops e2e-issue-assignment-bundles-from-env`.
pub fn issue_assignment_bundles_from_env(
    runner: &dyn NetLeafRunner,
    env: &EnvFile,
    remote_env_path: &str,
) -> Result<(), String> {
    issue_bundles_from_env(
        runner,
        "e2e-issue-assignment-bundles-from-env",
        env,
        remote_env_path,
    )
}

/// `rustynet ops e2e-issue-traversal-bundles-from-env`.
pub fn issue_traversal_bundles_from_env(
    runner: &dyn NetLeafRunner,
    env: &EnvFile,
    remote_env_path: &str,
) -> Result<(), String> {
    issue_bundles_from_env(
        runner,
        "e2e-issue-traversal-bundles-from-env",
        env,
        remote_env_path,
    )
}

/// Path of an issued assignment bundle on the issuing host.
pub fn issued_assignment_path(node_id: &str) -> Result<String, String> {
    validate_node_id(node_id)?;
    Ok(format!(
        "{ASSIGNMENT_ISSUE_DIR}/rn-assignment-{node_id}.assignment"
    ))
}

/// Path of the assignment verifying key on the issuing host.
pub fn issued_assignment_pub_path() -> String {
    format!("{ASSIGNMENT_ISSUE_DIR}/rn-assignment.pub")
}

/// Path of an issued traversal bundle on the issuing host.
pub fn issued_traversal_path(node_id: &str) -> Result<String, String> {
    validate_node_id(node_id)?;
    Ok(format!(
        "{TRAVERSAL_ISSUE_DIR}/rn-traversal-{node_id}.traversal"
    ))
}

/// Path of the traversal verifying key on the issuing host.
pub fn issued_traversal_pub_path() -> String {
    format!("{TRAVERSAL_ISSUE_DIR}/rn-traversal.pub")
}

// ───────────────────────────── installation ─────────────────────────────

/// `live_lab_ensure_rustynetd_group`: create the system group if absent.
///
/// The probe is allowed to fail (absence is the answer); creating the group is
/// not.
pub fn ensure_rustynetd_group(runner: &dyn NetLeafRunner) -> Result<(), String> {
    if run_root_allow_failure(runner, &["getent", "group", RUSTYNETD_GROUP])? {
        return Ok(());
    }
    run_root(runner, &["groupadd", "--system", RUSTYNETD_GROUP])
}

/// `live_lab_install_assignment_bundle` (Linux arm): stage the verifying key
/// and the signed bundle, install both with the exact modes and owners the
/// daemon's startup permission check requires, clear the anti-replay watermark
/// so the fresh bundle is accepted, and remove the staging copies.
pub fn install_assignment_bundle(
    runner: &dyn NetLeafRunner,
    node_id: &str,
    assignment_pub_b64: &str,
    assignment_bundle_b64: &str,
) -> Result<(), String> {
    validate_node_id(node_id)?;
    ensure_rustynetd_group(runner)?;
    let staged_pub = format!("{STAGING_DIR}/rn-assignment-{node_id}.pub");
    let staged_bundle = format!("{STAGING_DIR}/rn-assignment-{node_id}.bundle");
    write_remote_base64(runner, &staged_pub, "0600", assignment_pub_b64)?;
    write_remote_base64(runner, &staged_bundle, "0600", assignment_bundle_b64)?;

    run_root(
        runner,
        &[
            "install",
            "-d",
            "-m",
            "0750",
            "-o",
            "root",
            "-g",
            RUSTYNETD_GROUP,
            CONFIG_DIR,
        ],
    )?;
    run_root(
        runner,
        &[
            "install",
            "-d",
            "-m",
            "0700",
            "-o",
            RUSTYNETD_GROUP,
            "-g",
            RUSTYNETD_GROUP,
            STATE_ROOT,
        ],
    )?;
    run_root(
        runner,
        &[
            "install",
            "-m",
            "0644",
            "-o",
            "root",
            "-g",
            "root",
            &staged_pub,
            ASSIGNMENT_PUB_PATH,
        ],
    )?;
    run_root(
        runner,
        &[
            "install",
            "-m",
            "0640",
            "-o",
            "root",
            "-g",
            RUSTYNETD_GROUP,
            &staged_bundle,
            ASSIGNMENT_BUNDLE_PATH,
        ],
    )?;
    remove_remote(
        runner,
        &[ASSIGNMENT_WATERMARK_PATH, &staged_pub, &staged_bundle],
    )
}

/// `live_lab_install_assignment_refresh_env` (Linux arm). Mode `0600`,
/// `root:root`: the file names the signing secret, so it is readable by root
/// only even though the config directory is group-readable to the daemon.
pub fn install_assignment_refresh_env(
    runner: &dyn NetLeafRunner,
    node_id: &str,
    env: &EnvFile,
) -> Result<(), String> {
    validate_node_id(node_id)?;
    let staged = format!("{STAGING_DIR}/rn-assignment-refresh-{node_id}.env");
    write_remote_text(runner, &staged, "0600", &env.render())?;
    run_root(
        runner,
        &[
            "install",
            "-d",
            "-m",
            "0750",
            "-o",
            "root",
            "-g",
            RUSTYNETD_GROUP,
            CONFIG_DIR,
        ],
    )?;
    run_root(
        runner,
        &[
            "install",
            "-m",
            "0600",
            "-o",
            "root",
            "-g",
            "root",
            &staged,
            ASSIGNMENT_REFRESH_ENV_PATH,
        ],
    )?;
    remove_remote(runner, &[&staged])
}

/// The `install_traversal_bundle` helper the remote-exit validators defined
/// inline. Same shape as the assignment install, against the traversal paths.
pub fn install_traversal_bundle(
    runner: &dyn NetLeafRunner,
    traversal_pub_b64: &str,
    traversal_bundle_b64: &str,
) -> Result<(), String> {
    let staged_pub = format!("{STAGING_DIR}/rn-traversal.pub");
    let staged_bundle = format!("{STAGING_DIR}/rn-traversal.bundle");
    write_remote_base64(runner, &staged_pub, "0600", traversal_pub_b64)?;
    write_remote_base64(runner, &staged_bundle, "0600", traversal_bundle_b64)?;
    run_root(
        runner,
        &[
            "install",
            "-m",
            "0644",
            "-o",
            "root",
            "-g",
            "root",
            &staged_pub,
            TRAVERSAL_PUB_PATH,
        ],
    )?;
    run_root(
        runner,
        &[
            "install",
            "-m",
            "0640",
            "-o",
            "root",
            "-g",
            RUSTYNETD_GROUP,
            &staged_bundle,
            TRAVERSAL_BUNDLE_PATH,
        ],
    )?;
    remove_remote(
        runner,
        &[TRAVERSAL_WATERMARK_PATH, &staged_pub, &staged_bundle],
    )
}

// ───────────────────────────── role enforcement ─────────────────────────────

/// `live_lab_enforce_host`: `rustynet ops e2e-enforce-host`.
///
/// The shell prefixed `env RUSTYNET_BACKEND=…` when that variable was set in
/// the caller's environment; that pass-through is preserved, with the value
/// validated before it reaches argv.
pub fn enforce_host(
    runner: &dyn NetLeafRunner,
    role: &str,
    node_id: &str,
    src_dir: &str,
    ssh_allow_cidrs: &str,
) -> Result<(), String> {
    validate_argv_value("role", role)?;
    validate_node_id(node_id)?;
    validate_argv_value("src dir", src_dir)?;
    validate_argv_value("ssh allow cidrs", ssh_allow_cidrs)?;

    let backend = std::env::var("RUSTYNET_BACKEND")
        .ok()
        .filter(|value| !value.is_empty());
    let backend_assignment = match backend {
        Some(value) => {
            validate_argv_value("RUSTYNET_BACKEND", &value)?;
            Some(format!("RUSTYNET_BACKEND={value}"))
        }
        None => None,
    };

    let mut argv: Vec<&str> = Vec::new();
    if let Some(assignment) = backend_assignment.as_deref() {
        argv.push("env");
        argv.push(assignment);
    }
    argv.extend_from_slice(&[
        REMOTE_RUSTYNET_BIN,
        "ops",
        "e2e-enforce-host",
        "--role",
        role,
        "--node-id",
        node_id,
        "--src-dir",
        src_dir,
        "--ssh-allow-cidrs",
        ssh_allow_cidrs,
    ]);
    run_root(runner, &argv)
}

/// `live_lab_apply_role_coupling` (Linux arm): `rustynet ops
/// apply-role-coupling` under the daemon socket and auto-tunnel bundle paths.
pub fn apply_role_coupling(
    runner: &dyn NetLeafRunner,
    target_role: &str,
    preferred_exit_node_id: Option<&str>,
    enable_exit_advertise: bool,
    env_path: Option<&str>,
    skip_client_exit_route_wait: bool,
) -> Result<(), String> {
    validate_argv_value("target role", target_role)?;
    let env_path = env_path.unwrap_or(ASSIGNMENT_REFRESH_ENV_PATH);
    validate_argv_value("env path", env_path)?;
    if let Some(exit) = preferred_exit_node_id {
        validate_node_id(exit)?;
    }

    let socket_assignment = format!("RUSTYNET_SOCKET={DAEMON_SOCKET}");
    let bundle_assignment = format!("RUSTYNET_AUTO_TUNNEL_BUNDLE={ASSIGNMENT_BUNDLE_PATH}");
    let watermark_assignment =
        format!("RUSTYNET_AUTO_TUNNEL_WATERMARK={ASSIGNMENT_WATERMARK_PATH}");
    let advertise = if enable_exit_advertise {
        "true"
    } else {
        "false"
    };

    let mut argv: Vec<&str> = vec![
        "env",
        socket_assignment.as_str(),
        bundle_assignment.as_str(),
        watermark_assignment.as_str(),
        REMOTE_RUSTYNET_BIN,
        "ops",
        "apply-role-coupling",
        "--target-role",
        target_role,
        "--enable-exit-advertise",
        advertise,
        "--env-path",
        env_path,
    ];
    if let Some(exit) = preferred_exit_node_id {
        argv.push("--preferred-exit-node-id");
        argv.push(exit);
    }
    if skip_client_exit_route_wait {
        argv.push("--skip-client-exit-route-convergence-wait");
    }
    run_root(runner, &argv)
}

// ───────────────────────────── netcheck parsing ─────────────────────────────

/// The value of `key=` in a `netcheck` line, or `None`.
///
/// The shell split on spaces and took the first match (`awk … { print; exit }`).
/// Splitting on all ASCII whitespace here is equivalent, because `netcheck`
/// output is one token per field and the shell had already turned newlines into
/// separators. "First wins" is preserved deliberately: a later duplicate key
/// must not be able to override the daemon's first answer.
pub fn extract_netcheck_value(netcheck: &str, key: &str) -> Option<String> {
    netcheck.split_whitespace().find_map(|token| {
        token
            .split_once('=')
            .filter(|(name, _)| *name == key)
            .map(|(_, value)| value.to_owned())
    })
}

/// `extract_netcheck_value` parsed as a counter, defaulting to 0 for a missing
/// or non-numeric field — the shell's `[[ ! =~ ^[0-9]+$ ]] && =0`.
pub fn netcheck_counter(netcheck: &str, key: &str) -> u64 {
    extract_netcheck_value(netcheck, key)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

// ───────────────────────────── lab context ─────────────────────────────

/// How the scenarios spend wall-clock time.
///
/// The shell's sleeps and retry cadences are load-bearing in the lab: they are
/// how long convergence is actually allowed to take. [`TimeScale::Collapsed`]
/// keeps every *attempt count* and every loop bound identical while making the
/// waits zero-length, so tests exercise the same control flow without spending
/// the same minutes. Only tests construct it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeScale {
    /// Wait for the durations the shell waited.
    Real,
    /// Waits are zero-length. Attempt counts and loop bounds are unchanged.
    Collapsed,
}

impl TimeScale {
    /// The duration to actually wait for a nominal `duration`.
    pub fn scale(self, duration: Duration) -> Duration {
        match self {
            Self::Real => duration,
            Self::Collapsed => Duration::ZERO,
        }
    }

    pub fn sleep(self, duration: Duration) {
        let scaled = self.scale(duration);
        if !scaled.is_zero() {
            std::thread::sleep(scaled);
        }
    }
}

/// Everything a scenario needs that is *not* reachable through a
/// [`NetLeafRunner`]: host-level identity for the sibling validator bins, the
/// role-enforcement inputs, and where artifacts go.
///
/// `ScenarioInputs` carries the per-node runner/id/address triple; this carries
/// the lab-wide facts the shell read from its own argv.
#[derive(Debug, Clone)]
pub struct LabContext {
    /// `--ssh-identity-file`, forwarded to the sibling validators.
    ///
    /// The host-key pin that accompanied it (`LIVE_LAB_PINNED_KNOWN_HOSTS_FILE`)
    /// and `RUSTYNET_EXPECTED_GIT_COMMIT` are *environment* for the sibling
    /// processes rather than scenario inputs, so they live on
    /// [`LocalScenarioHost`](super::host::LocalScenarioHost) instead of here.
    pub ssh_identity_file: PathBuf,
    /// `--ssh-allow-cidrs`, passed to `e2e-enforce-host`.
    pub ssh_allow_cidrs: String,
    /// Directory the scenario writes its own artifacts into, and where the
    /// sibling validators are told to write theirs.
    pub artifact_dir: PathBuf,
    /// `user@host` for the client, as the sibling validators expect it.
    pub client_ssh_target: String,
    /// `user@host` for the exit.
    pub exit_ssh_target: String,
    /// `user@host` for the relay, when the scenario has one.
    pub relay_ssh_target: Option<String>,
    /// `user@host` for the probe, when the scenario has one.
    pub probe_ssh_target: Option<String>,
    /// `live_lab_remote_src_dir` for the client.
    pub client_src_dir: String,
    /// `live_lab_remote_src_dir` for the exit.
    pub exit_src_dir: String,
    /// `live_lab_remote_src_dir` for the relay, when present.
    pub relay_src_dir: Option<String>,
    /// See [`TimeScale`].
    pub time_scale: TimeScale,
}

impl LabContext {
    pub fn sleep(&self, duration: Duration) {
        self.time_scale.sleep(duration);
    }

    /// The duration to pass to a retry helper, scaled for the current mode.
    pub fn pace(&self, duration: Duration) -> Duration {
        self.time_scale.scale(duration)
    }

    /// An artifact path inside [`Self::artifact_dir`].
    pub fn artifact(&self, name: &str) -> PathBuf {
        self.artifact_dir.join(name)
    }

    /// The relay ssh target, or a fail-closed error.
    pub fn require_relay_ssh_target(&self, scenario: &str) -> Result<&str, String> {
        self.relay_ssh_target
            .as_deref()
            .ok_or_else(|| format!("{scenario} requires a relay ssh target but none was resolved"))
    }

    /// The probe ssh target, or a fail-closed error.
    pub fn require_probe_ssh_target(&self, scenario: &str) -> Result<&str, String> {
        self.probe_ssh_target
            .as_deref()
            .ok_or_else(|| format!("{scenario} requires a probe ssh target but none was resolved"))
    }
}

// ───────────────────── in-process ops helpers ─────────────────────

/// `ops classify-cross-network-topology`, in process.
///
/// True when the two underlay addresses sit on *different* prefixes, i.e. the
/// topology really is cross-network. The CLI's `--ipv4-prefix` / `--ipv6-prefix`
/// defaults (24 / 64) are reproduced here because the shell never overrode them.
pub fn classify_cross_network_topology(ip_a: &str, ip_b: &str) -> Result<bool, String> {
    let verdict = crate::ops_cross_network_reports::execute_ops_classify_cross_network_topology(
        crate::ops_cross_network_reports::ClassifyCrossNetworkTopologyConfig {
            ip_a: ip_a.to_owned(),
            ip_b: ip_b.to_owned(),
            ipv4_prefix: DEFAULT_IPV4_PREFIX,
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
        },
    )?;
    Ok(verdict.trim() == "pass")
}

/// The CLI default for `--ipv4-prefix`.
pub const DEFAULT_IPV4_PREFIX: u8 = 24;
/// The CLI default for `--ipv6-prefix`.
pub const DEFAULT_IPV6_PREFIX: u8 = 64;

/// `ops choose-cross-network-roam-alias`, in process. Returns `(alias, prefix)`.
pub fn choose_cross_network_roam_alias(
    exit_ip: &str,
    used_ips: &[&str],
) -> Result<(String, u8), String> {
    let raw = crate::ops_cross_network_reports::execute_ops_choose_cross_network_roam_alias(
        crate::ops_cross_network_reports::ChooseCrossNetworkRoamAliasConfig {
            exit_ip: exit_ip.to_owned(),
            used_ips: used_ips.iter().map(|value| (*value).to_owned()).collect(),
            ipv4_prefix: DEFAULT_IPV4_PREFIX,
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
        },
    )?;
    let mut lines = raw.lines();
    let alias = lines
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "failed to choose roam alias for client endpoint switch".to_owned())?;
    let prefix = lines
        .next()
        .map(str::trim)
        .and_then(|value| value.parse::<u8>().ok())
        .ok_or_else(|| "failed to choose roam alias for client endpoint switch".to_owned())?;
    Ok((alias.to_owned(), prefix))
}

// ───────────────────── the sibling-validator seam ─────────────────────
//
// Reading a sibling's report and invoking a sibling bin both live on
// [`ScenarioHost`](super::host::ScenarioHost), not here. An earlier draft of
// this module carried its own copies; two seams to the same four binaries is
// one seam too many, and only the trait version is mockable, so the duplicates
// were removed rather than kept in parallel.

/// `live_linux_server_ip_bypass_test` — leak resistance and bypass narrowness.
pub const BIN_SERVER_IP_BYPASS: &str = "live_linux_server_ip_bypass_test";
/// `live_linux_managed_dns_test` — managed-DNS behaviour.
pub const BIN_MANAGED_DNS: &str = "live_linux_managed_dns_test";
/// `live_linux_endpoint_hijack_test` — rogue-endpoint adoption denial.
pub const BIN_ENDPOINT_HIJACK: &str = "live_linux_endpoint_hijack_test";
/// `live_linux_control_surface_exposure_test` — control-surface exposure.
pub const BIN_CONTROL_SURFACE_EXPOSURE: &str = "live_linux_control_surface_exposure_test";

/// `live_lab_remote_src_dir`: where the deployed source tree lives on a guest.
///
/// A pure function of the ssh *username*, exactly as the shell had it — `root`
/// gets `/root/Rustynet`, everyone else `/home/<user>/Rustynet`. It is
/// deliberately not a remote `echo $HOME`: the value is passed to
/// `e2e-enforce-host` as `--src-dir`, and deriving it locally means the path
/// cannot be influenced by the guest's own environment.
pub fn remote_src_dir(ssh_user: &str) -> Result<String, String> {
    validate_argv_value("ssh user", ssh_user)?;
    if ssh_user.contains('/') {
        return Err(format!(
            "ssh user must not contain a path separator: {ssh_user:?}"
        ));
    }
    if ssh_user == "root" {
        return Ok("/root/Rustynet".to_owned());
    }
    Ok(format!("/home/{ssh_user}/Rustynet"))
}

/// Render a path for argv.
///
/// Lossy conversion is acceptable for these paths and nowhere else: every one
/// is orchestrator-derived (an artifact directory joined with a fixed literal,
/// or an ssh identity path from the inventory), never guest-supplied, so there
/// is no untrusted content for the conversion to mangle.
pub fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
