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
use rustynet_control::roles::{RoleCapability, role_capability_csv};

use super::super::substrate::NetLeafRunner;
use super::{
    DAEMON_SOCKET, REMOTE_RUSTYNET_BIN, capture_root, capture_root_allow_failure, run_root,
    run_root_allow_failure,
};

// ───────────────────────────── remote paths ─────────────────────────────

/// `rustynet_wg_pub_key_path linux`.
pub const WG_PUB_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.pub";
/// Where `e2e-issue-assignment-bundles-from-env` leaves its output.
pub const ASSIGNMENT_ISSUE_DIR: &str = "/run/rustynet/assignment-issue";
/// Where `e2e-issue-traversal-bundles-from-env` leaves its output.
pub const TRAVERSAL_ISSUE_DIR: &str = "/run/rustynet/traversal-issue";
/// Where `e2e-issue-dns-zone-bundles-from-env` leaves its output (the
/// subcommand's own default `--issue-dir`).
pub const DNS_ZONE_ISSUE_DIR: &str = "/run/rustynet/dns-zone-issue";
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
/// DNS-zone verifying key (matches `adapter::linux_membership`).
pub const DNS_ZONE_PUB_PATH: &str = "/etc/rustynet/dns-zone.pub";
/// Signed DNS-zone bundle (matches `adapter::linux_membership`).
pub const DNS_ZONE_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.dns-zone";
/// Remote path of the dns-zone issuance env file.
pub const DNS_ZONE_ISSUE_ENV_PATH: &str = "/tmp/rn_issue_cross_network_dns_zone.env";
/// Lifetime of a freshly issued dns-zone bundle. The signed-zone builder
/// hard-caps it at 300 s (`ops_e2e.rs`), and the daemon rejects a bundle once
/// `now > expires_at_unix` whatever `RUSTYNET_DNS_ZONE_MAX_AGE_SECS` says.
pub const DNS_ZONE_TTL_SECS: &str = "300";
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

/// Read a remote file as TEXT with `cat` — the module's existing text-capture
/// path ([`collect_pubkey_hex`] reads the WireGuard public key the same way).
///
/// `capture_root` fails closed on a non-zero exit and returns trimmed stdout,
/// so a missing or unreadable file is an error, never an empty string that
/// flows on as if it were the file's contents. Use this for files whose bytes
/// are consumed as text (hex keys, config); [`read_remote_base64`] returns the
/// base64 TRANSPORT of the file, which is the right shape only when the bytes
/// are re-transmitted unexamined.
pub fn read_remote_text(runner: &dyn NetLeafRunner, path: &str) -> Result<String, String> {
    validate_argv_value("remote path", path)?;
    capture_root(runner, &["cat", path])
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

/// Lab-role → wire capability for a scenario exit node: it must advertise
/// `exit_server` or the issuer refuses every remote-exit assignment naming it
/// (`validate_assignment_exit_provider`: "exit node {id} lacks exit_server
/// capability" — katana-xnet-1 root cause A, seven stage failures). Client and
/// entry nodes carry no extra capability: their [`NodeSpec`] stays
/// capability-free, keeps the issuer's `[Client]` default, and therefore
/// renders byte-identical to the old three-field entry.
///
/// The exit node also carries `Anchor`: the cross-network scenarios enforce it
/// as `admin` (the only role that can advertise the default route,
/// `daemon.rs:11398` `route_advertise_requires_exit_serving_activation`), and
/// `admin` requires the `anchor` capability in the signed assignment bundle
/// (`daemon.rs:2301` `required_membership_capabilities`). Without `anchor`,
/// the daemon fail-closes the assignment refresh with "assignment target
/// intent lacks required local capability anchor" (katana-xnet-14/16/37).
pub const EXIT_NODE_CAPABILITIES: [RoleCapability; 2] =
    [RoleCapability::Anchor, RoleCapability::ExitServer];

/// One entry of `NODES_SPEC`:
/// `<node-id>|<addr>:<port>|<pubkey-hex>[|<capabilities-csv>]`.
///
/// The optional fourth field carries the node's role capabilities. It is
/// rendered only from the closed [`RoleCapability`] enum via
/// `role_capability_csv`, never from caller text, so nothing can inject `|`,
/// `;` or an unknown token into the spec line; the guest-side issuer re-parses
/// it with `parse_role_capability_csv` and refuses unknown tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpec {
    node_id: String,
    endpoint: String,
    pubkey_hex: String,
    capabilities: Vec<RoleCapability>,
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
            capabilities: Vec::new(),
        })
    }

    /// Tag the node with the capabilities its lab role carries. The wire value
    /// is produced from the closed [`RoleCapability`] enum only; see
    /// [`EXIT_NODE_CAPABILITIES`] for the one mapping the scenarios need.
    pub fn with_capabilities(mut self, capabilities: &[RoleCapability]) -> Self {
        self.capabilities = capabilities.to_vec();
        self
    }

    fn render(&self) -> String {
        if self.capabilities.is_empty() {
            return format!("{}|{}|{}", self.node_id, self.endpoint, self.pubkey_hex);
        }
        format!(
            "{}|{}|{}|{}",
            self.node_id,
            self.endpoint,
            self.pubkey_hex,
            role_capability_csv(&self.capabilities),
        )
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

/// Re-spell an issuer-grammar `NODES_SPEC` for `assignment-refresh.env`.
///
/// ONE string is read by TWO parsers inside `rustynet ops refresh-assignment`
/// (`main.rs::execute_ops_refresh_assignment`):
///
/// The traversal re-sign (`local_traversal_refresh_env_body` ->
/// `ops_e2e::parse_generic_nodes`) reads `node|endpoint|key[|capabilities_csv]`:
/// the 4th field is the capabilities and any further fields are ignored;
///
/// The assignment re-issue (`parse_assignment_nodes`) reads
/// `node|endpoint|key[|owner|hostname|os|tags_csv|capabilities_csv]`: the 4th
/// field is the OWNER, the 8th the capabilities, and an absent 8th defaults to
/// `[client]`.
/// Handing it the issuer spelling `...|anchor,exit_server` makes the assignment
/// side take the capabilities as an owner and mint a `[client]` bundle (the exit
/// then refuses it: "lacks required local capability anchor"; katana-xnet-69).
/// The first fix here (`id|id|linux||caps`, katana-xnet-71) satisfied the
/// assignment parser but the traversal parser then rejected the node id sitting
/// in its capabilities slot ("unknown role capability <node-id>"). The spelling
/// both accept is the project convention every other lab writer already uses
/// (`vm_lab/mod.rs`, `live_linux_exit_handoff_test`, `live_linux_two_hop_test`,
/// `live_linux_lan_toggle_test`): `node|endpoint|key|caps||||caps`, i.e. the
/// capabilities in BOTH slots; hostname/os/tags stay empty so they default to the
/// node id / `linux` / none. (The assignment parser therefore records the
/// capability text as the node's owner label, as it already does for those
/// writers.) Entries without capabilities are left untouched (both parsers
/// default them to `[client]`). Capability tokens go through the closed
/// `RoleCapability` parser and are written canonically; other arities, unknown
/// tokens or an empty spec are errors, never silent defaults.
pub fn refresh_nodes_spec(generic: &str) -> Result<String, String> {
    let mut entries = Vec::new();
    for entry in generic.split(';').filter(|entry| !entry.is_empty()) {
        let fields: Vec<&str> = entry.split('|').collect();
        match fields.as_slice() {
            [_, _, _] => entries.push(entry.to_owned()),
            [id, endpoint, key, caps] => {
                let parsed = rustynet_control::roles::parse_role_capability_csv(caps)
                    .map_err(|err| format!("node {id}: invalid capabilities {caps:?}: {err}"))?;
                if parsed.is_empty() {
                    entries.push(format!("{id}|{endpoint}|{key}"));
                } else {
                    let caps = rustynet_control::roles::role_capability_csv(&parsed);
                    entries.push(format!("{id}|{endpoint}|{key}|{caps}||||{caps}"));
                }
            }
            other => {
                return Err(format!(
                    "unexpected NODES_SPEC entry with {} fields: {entry:?}",
                    other.len()
                ));
            }
        }
    }
    if entries.is_empty() {
        return Err("NODES_SPEC is empty".to_owned());
    }
    Ok(entries.join(";"))
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
    let refresh_nodes = refresh_nodes_spec(nodes_spec)?;
    let mut env = EnvFile::new()
        .set("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID", target_node_id)?
        .set("RUSTYNET_ASSIGNMENT_NODES", &refresh_nodes)?
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

/// `rustynet ops e2e-issue-dns-zone-bundles-from-env`.
pub fn issue_dns_zone_bundles_from_env(
    runner: &dyn NetLeafRunner,
    env: &EnvFile,
    remote_env_path: &str,
) -> Result<(), String> {
    issue_bundles_from_env(
        runner,
        "e2e-issue-dns-zone-bundles-from-env",
        env,
        remote_env_path,
    )
}

/// Path of an issued dns-zone bundle on the issuing host.
pub fn issued_dns_zone_path(node_id: &str) -> Result<String, String> {
    validate_node_id(node_id)?;
    Ok(format!(
        "{DNS_ZONE_ISSUE_DIR}/rn-dns-zone-{node_id}.dns-zone"
    ))
}

/// Path of the dns-zone verifying key on the issuing host.
pub fn issued_dns_zone_pub_path() -> String {
    format!("{DNS_ZONE_ISSUE_DIR}/rn-dns-zone.pub")
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

/// Install a signed dns-zone bundle and its verifying key, same shape as the
/// traversal install. The anti-replay watermark is deliberately NOT cleared: a
/// freshly issued bundle carries a later `generated_at`, which the daemon
/// accepts against the existing watermark, so replay protection stays intact.
pub fn install_dns_zone_bundle(
    runner: &dyn NetLeafRunner,
    dns_zone_pub_b64: &str,
    dns_zone_bundle_b64: &str,
) -> Result<(), String> {
    let staged_pub = format!("{STAGING_DIR}/rn-dns-zone.pub");
    let staged_bundle = format!("{STAGING_DIR}/rn-dns-zone.bundle");
    write_remote_base64(runner, &staged_pub, "0600", dns_zone_pub_b64)?;
    write_remote_base64(runner, &staged_bundle, "0600", dns_zone_bundle_b64)?;
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
            DNS_ZONE_PUB_PATH,
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
            DNS_ZONE_BUNDLE_PATH,
        ],
    )?;
    remove_remote(runner, &[&staged_pub, &staged_bundle])
}

/// Re-issue the signed dns-zone bundles on `issuer` for the topology named by
/// `nodes_spec`/`allow_spec` and install each node's own bundle.
///
/// The baseline `distribute_dns_zone` stage mints one bundle minutes before the
/// cross-network scenarios run, and the bundle cannot outlive 300 s, so a
/// scenario that re-installs the daemons and then asserts `dns_alarm_state`
/// healthy would read `dns_zone_bundle_is_stale` (katana-xnet-62). This is the
/// same mint-and-install the setup stage and `refresh_signed_bundles` perform
/// (the existing `e2e-issue-dns-zone-bundles-from-env` verb), scoped to the
/// scenario's nodes. Call it after the other bundles are installed and before
/// the `enforce_host` pass that makes the daemon re-read its state.
pub fn reissue_dns_zone(
    issuer: &dyn NetLeafRunner,
    nodes_spec: &str,
    allow_spec: &str,
    targets: &[(&dyn NetLeafRunner, &str)],
) -> Result<(), String> {
    let env = EnvFile::new()
        .set("NODES_SPEC", nodes_spec)?
        .set("ALLOW_SPEC", allow_spec)?
        .set("DNS_ZONE_TTL_SECS", DNS_ZONE_TTL_SECS)?;
    issue_dns_zone_bundles_from_env(issuer, &env, DNS_ZONE_ISSUE_ENV_PATH)?;
    let pub_b64 = read_remote_base64(issuer, &issued_dns_zone_pub_path())?;
    for (runner, node_id) in targets {
        let bundle = read_remote_base64(issuer, &issued_dns_zone_path(node_id)?)?;
        install_dns_zone_bundle(*runner, &pub_b64, &bundle)?;
    }
    Ok(())
}

// ───────────────────────────── role enforcement ─────────────────────────────

/// Lab-only freshness-window overrides forwarded to `e2e-enforce-host`; the
/// same three values `adapter::linux_install::build_enforce_script` sets for
/// every other lab enforce pass.
const LAB_FRESHNESS_ENV: [&str; 3] = [
    "RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400",
    "RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400",
    "RUSTYNET_DNS_ZONE_MAX_AGE_SECS=86400",
];

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

    // The standard orchestrator's enforce script (`build_enforce_script`) passes
    // the lab freshness windows to `e2e-enforce-host`, which bakes them into the
    // unit via install-systemd. This path re-installs the units on a node many
    // minutes after the baseline distributed its dns-zone bundle (TTL <= 300 s)
    // and nothing here re-issues that bundle, so without the same lab window
    // the daemon reports `dns_alarm_state=error` /
    // `dns_zone_bundle_is_stale` and `signed_state_healthy` fails the stage
    // (katana-xnet-61). Production leaves these unset (300 s / 120 s defaults).
    let mut argv: Vec<&str> = vec!["env"];
    argv.extend_from_slice(&LAB_FRESHNESS_ENV);
    if let Some(assignment) = backend_assignment.as_deref() {
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
    /// `--client-network-id`. Carried because a composing scenario writes its
    /// baseline's report itself, and the report schema requires the network
    /// context; the shell passed these straight through to the baseline script.
    pub client_network_id: String,
    /// `--exit-network-id`.
    pub exit_network_id: String,
    /// `--relay-network-id`, when the scenario has a relay.
    pub relay_network_id: Option<String>,
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

    /// The relay network id, or a fail-closed error.
    pub fn require_relay_network_id(&self, scenario: &str) -> Result<&str, String> {
        self.relay_network_id
            .as_deref()
            .ok_or_else(|| format!("{scenario} requires a relay network id but none was resolved"))
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

// ───────────────── relay service + token spool (DESIGN-XNET-RELAY S3) ─────────────────
//
// The relay_remote_exit scenario needs the same relay machinery the HP-3
// adapter builds for its own topology, but over the scenario `NetLeafRunner`
// seam (argv + sudo -n), not the adapter's ssh `NodeConnection`. These helpers
// mirror `adapter::linux_relay_tokens` and `adapter::linux_install` step for
// step — same paths, modes, ordering and failure discipline — and reuse the
// adapter's `pub(crate)` pure parsers so the semantics cannot drift. Only the
// transport differs: files cross as single-line base64 through
// [`write_remote_base64`], commands run through [`run_root`].

/// Where `e2e-issue-relay-session-tokens-from-env` leaves its output. Passed
/// explicitly (`--issue-dir`); it is also the verb's own default, so an
/// operator replaying the mint by hand lands in the same directory.
pub const RELAY_TOKEN_ISSUE_DIR: &str = "/run/rustynet/relay-token-issue";
/// Remote path of the relay token issuance env file (the scenario's /tmp, in
/// the pattern of the other issuance env paths).
pub const RELAY_TOKEN_ISSUE_ENV_PATH: &str = "/tmp/rn_issue_cross_network_relay_tokens.env";
/// The relay id label this scenario mints tokens for. Matches the
/// `rustynet-relay.service` default and the HP-3 test relay id.
pub const RELAY_ID_LABEL: &str = "relay-local";
/// TCP port the relay service binds (the unit's default, made explicit here).
pub const RELAY_SERVICE_BIND_PORT: &str = "4500";
/// The relay service's bind override: the unit reads it via
/// `EnvironmentFile=-/etc/default/rustynet-relay`, and a STALE file from an
/// earlier topology crash-loops the unit (EADDRNOTAVAIL), which is why deploy
/// rewrites it unconditionally.
pub const RELAY_DEFAULT_ENV_PATH: &str = "/etc/default/rustynet-relay";
/// Where the relay's token-verifying key is installed (mirrors
/// `adapter::linux_install`).
pub const RELAY_VERIFIER_PATH: &str = "/etc/rustynet/relay-verifier.pub";
/// The systemd unit `ops install-systemd-relay` installs.
const RELAY_SERVICE_UNIT: &str = "rustynet-relay.service";

// Mirrors of the adapter-private spool paths. Values are pinned by unit tests
// against the imported constants where those are public.
const SPOOL_INCOMING_DIR: &str = "/var/lib/rustynet/relay-token-spool/.incoming";
const DROPIN_DIR: &str = "/etc/systemd/system/rustynetd.service.d";
const DROPIN_FILE: &str = "/etc/systemd/system/rustynetd.service.d/hp3-relay-token-spool.conf";
/// Seconds of remaining life below which the purge drops a token (the adapter's
/// [`linux_relay_tokens::PURGE_MARGIN_SECS`] value).
const PURGE_MARGIN_SECS: u64 = 10;
/// The extension the daemon's spool reader accepts.
const TOKEN_SUFFIX: &str = ".relay-token";
/// The non-token file the mint also leaves in the issue dir (the verifying
/// key), skipped when splitting the listing.
const RELAY_TOKEN_ISSUE_VERIFIER_FILE: &str = "rn-relay-token.pub";

/// Content of the daemon unit drop-in: one `Environment=` line, constant.
///
/// Byte-equivalent to the adapter's `linux_relay_tokens::dropin_content`.
fn relay_spool_dropin_content() -> String {
    format!("[Service]\nEnvironment={SPOOL_ENV_KEY}={RELAY_TOKEN_SPOOL_DIR}\n")
}

use crate::vm_lab::orchestrator::adapter::linux_relay_tokens::{
    MAX_SPOOL_FILES, RELAY_TOKEN_SPOOL_DIR, SPOOL_ENV_KEY, environment_has_spool,
    parse_expiry_listing, parse_rfc3339_utc_secs, parse_spool_listing, select_purge,
    select_superseded,
};

/// `install -d` arguments for the spool directories (adapter's
/// `cmd_make_spool_dir`): owned by the daemon, private.
const MAKE_SPOOL_DIR_ARGV: [&str; 8] = [
    "install",
    "-d",
    "-o",
    "rustynetd",
    "-g",
    "rustynetd",
    "-m",
    "0700",
];

/// Read expiries from every spool token with ONE fixed script.
///
/// The adapter runs one `grep -F -H expires_at_unix=` over the listed paths and
/// distinguishes exit 1 (no file has an expiry: purge all) from exit 2 (a file
/// vanished between list and grep: re-list). Over the scenario seam the same
/// fail-safe outcome falls out of a per-file `|| true` loop: a consumed file
/// simply contributes no expiry line and is purged as an absentee, exactly what
/// the adapter's re-list would decide. `$1` is the spool dir; nothing is
/// interpolated.
const READ_SPOOL_EXPIRIES_SCRIPT: &str = "set -eu; for f in \"$1\"/*.relay-token; do \
[ -f \"$f\" ] || continue; grep -H -F expires_at_unix= \"$f\" || true; done";

/// Create the spool, add the daemon drop-in, reload systemd, and confirm
/// systemd now resolves the variable for the daemon unit. No restart — the
/// scenario restarts the daemon itself right after (drop-in first, daemon
/// second, so the first start already sees the spool).
pub fn prepare_relay_token_spool(runner: &dyn NetLeafRunner) -> Result<(), String> {
    let uniq = crate::vm_lab::orchestrator::adapter::unique_temp_token();
    let tmp_remote = format!("/tmp/rn_hp3_spool_{uniq}.conf");
    write_remote_text(
        runner,
        tmp_remote.as_str(),
        "0644",
        &relay_spool_dropin_content(),
    )?;
    let steps = (|| -> Result<(), String> {
        for dir in [RELAY_TOKEN_SPOOL_DIR, SPOOL_INCOMING_DIR] {
            let mut argv: Vec<&str> = MAKE_SPOOL_DIR_ARGV.to_vec();
            argv.push(dir);
            run_root(runner, &argv)?;
        }
        run_root(
            runner,
            &[
                "install", "-d", "-o", "root", "-g", "root", "-m", "0755", DROPIN_DIR,
            ],
        )?;
        run_root(
            runner,
            &[
                "install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0644",
                tmp_remote.as_str(),
                DROPIN_FILE,
            ],
        )?;
        run_root(runner, &["systemctl", "daemon-reload"])?;
        let environment = capture_root(
            runner,
            &[
                "systemctl",
                "show",
                "-p",
                "Environment",
                "rustynetd.service",
            ],
        )?;
        if !environment_has_spool(&environment) {
            return Err(
                "systemd does not resolve the relay token spool variable for the daemon \
                 unit after the drop-in was installed"
                    .to_owned(),
            );
        }
        Ok(())
    })();
    let _ = remove_remote(runner, &[tmp_remote.as_str()]);
    steps
}

/// `rustynet ops e2e-issue-relay-session-tokens-from-env`, with an explicit
/// `--issue-dir`: same security ordering as [`issue_bundles_from_env`] (the env
/// file names the signing secret, so it is removed best-effort on failure and
/// its removal is REQUIRED on success).
pub fn issue_relay_session_tokens_from_env(
    runner: &dyn NetLeafRunner,
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
            "e2e-issue-relay-session-tokens-from-env",
            "--env-file",
            remote_env_path,
            "--issue-dir",
            RELAY_TOKEN_ISSUE_DIR,
        ],
    );
    if let Err(err) = issued {
        let _ = remove_remote(runner, &[remote_env_path]);
        return Err(err);
    }
    remove_remote(runner, &[remote_env_path])
}

/// One issued relay session token: its spool name and base64 payload.
///
/// The payload is bearer material, so this type deliberately derives no
/// `Debug` and is listed in rustynetd's `FORBIDDEN_DEBUG_SECRET_TYPES` to
/// guard against a future re-introduction.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayTokenFile {
    pub name: String,
    pub payload_b64: String,
}

/// `{issued_at:010}-{pair:02}-{seq:02}.relay-token` as its three numbers.
///
/// Everything else is refused: the name is the only thing that routes a token
/// to the right peer's spool, so a malformed name must not be silently
/// interpolated into a filename.
pub fn parse_relay_token_name(name: &str) -> Option<(u32, u32, u32)> {
    let stem = name.strip_suffix(TOKEN_SUFFIX)?;
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    let mut parts = stem.split('-');
    let issued = parts.next()?.parse::<u32>().ok()?;
    let pair = parts.next()?.parse::<u32>().ok()?;
    let seq = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    // Shape, not range: 10-2-2 digits as the mint writes them.
    let widths = (
        stem.split('-').next()?.len(),
        stem.split('-').nth(1)?.len(),
        stem.split('-').nth(2)?.len(),
    );
    if widths != (10, 2, 2) {
        return None;
    }
    Some((issued, pair, seq))
}

/// Read the relay session tokens the mint left in [`RELAY_TOKEN_ISSUE_DIR`].
///
/// Only `*.relay-token` files with the exact mint name shape are returned; the
/// verifying key and any surprise entry are skipped, never installed.
pub fn read_issued_relay_token_files(
    runner: &dyn NetLeafRunner,
) -> Result<Vec<RelayTokenFile>, String> {
    let listing = capture_root(runner, &["ls", "-1", "--", RELAY_TOKEN_ISSUE_DIR])?;
    let mut files = Vec::new();
    for name in listing.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if name == RELAY_TOKEN_ISSUE_VERIFIER_FILE {
            continue;
        }
        if parse_relay_token_name(name).is_none() {
            return Err(format!(
                "unexpected entry in {RELAY_TOKEN_ISSUE_DIR}: {name:?} is not a relay token name"
            ));
        }
        let payload_b64 = read_remote_base64(runner, &format!("{RELAY_TOKEN_ISSUE_DIR}/{name}"))?;
        files.push(RelayTokenFile {
            name: name.to_owned(),
            payload_b64,
        });
    }
    if files.is_empty() {
        return Err(format!(
            "no relay session tokens were issued into {RELAY_TOKEN_ISSUE_DIR}"
        ));
    }
    Ok(files)
}

/// Purge expired tokens and install `files` into the spool; then drop every
/// token that is not in the batch just published.
///
/// Ordering mirrors the adapter's `install_relay_token_spool`: clock first (the
/// purge decision must use the clock the daemon judges expiry on), purge BEFORE
/// the new batch lands (a failed install must not leave an expired matching
/// token blocking the daemon), stage → install into `.incoming` → publish by
/// rename (a token appears in the spool only once fully written), supersede,
/// and finally the daemon's hard cap of [`MAX_SPOOL_FILES`] entries.
pub fn install_relay_token_spool(
    runner: &dyn NetLeafRunner,
    files: &[RelayTokenFile],
) -> Result<(), String> {
    if files.is_empty() {
        return Err("refusing to install an empty relay token batch".to_owned());
    }
    let names = files
        .iter()
        .map(|file| {
            if parse_relay_token_name(&file.name).is_none() {
                return Err(format!(
                    "refusing to install {:?}: not a relay token name",
                    file.name
                ));
            }
            Ok(file.name.clone())
        })
        .collect::<Result<Vec<_>, String>>()?;

    // 1. The node's own clock, read the same way the adapter reads it.
    let clock = capture_root(runner, &["date", "-u", "--rfc-3339=seconds"])?;
    let node_now_unix = parse_rfc3339_utc_secs(&clock).map_err(|e| e.to_string())?;

    // 2. Purge expired/unreadable tokens BEFORE new ones land.
    let listing = capture_root(runner, &["ls", "-1", "--", RELAY_TOKEN_SPOOL_DIR])?;
    let present = parse_spool_listing(&listing).map_err(|err| err.to_string())?;
    if !present.is_empty() {
        let expiry_listing = capture_root(
            runner,
            &[
                "sh",
                "-c",
                READ_SPOOL_EXPIRIES_SCRIPT,
                "sh",
                RELAY_TOKEN_SPOOL_DIR,
            ],
        )?;
        let expiries = parse_expiry_listing(&expiry_listing);
        let expired = select_purge(&present, &expiries, node_now_unix, PURGE_MARGIN_SECS);
        if !expired.is_empty() {
            let mut argv = vec!["rm", "-f", "--"];
            let mut paths = Vec::new();
            for name in &expired {
                paths.push(format!("{RELAY_TOKEN_SPOOL_DIR}/{name}"));
            }
            for path in &paths {
                argv.push(path.as_str());
            }
            run_root(runner, &argv)?;
        }
    }

    // 3. Stage, install into the staging dir, publish by rename.
    let stage_dir = format!(
        "/tmp/rn_relay_tok_stage_{}",
        crate::vm_lab::orchestrator::adapter::unique_temp_token()
    );
    run_root(runner, &["mkdir", "-m", "0700", "-p", stage_dir.as_str()])?;
    let published = (|| -> Result<(), String> {
        for file in files {
            write_remote_base64(
                runner,
                &format!("{stage_dir}/{}", file.name),
                "0600",
                &file.payload_b64,
            )?;
            run_root(
                runner,
                &[
                    "install",
                    "-o",
                    "rustynetd",
                    "-g",
                    "rustynetd",
                    "-m",
                    "0600",
                    &format!("{stage_dir}/{}", file.name),
                    &format!("{SPOOL_INCOMING_DIR}/{}", file.name),
                ],
            )?;
            run_root(
                runner,
                &[
                    "mv",
                    "-f",
                    &format!("{SPOOL_INCOMING_DIR}/{}", file.name),
                    &format!("{RELAY_TOKEN_SPOOL_DIR}/{}", file.name),
                ],
            )?;
        }
        Ok(())
    })();
    let _ = remove_remote(runner, &[stage_dir.as_str()]);
    published?;

    // 4. Supersede: only the batch just published stays; then the hard cap.
    let after_listing = capture_root(runner, &["ls", "-1", "--", RELAY_TOKEN_SPOOL_DIR])?;
    let after = parse_spool_listing(&after_listing).map_err(|err| err.to_string())?;
    let superseded = select_superseded(&after, &names);
    if !superseded.is_empty() {
        let mut argv = vec!["rm", "-f", "--"];
        let mut paths = Vec::new();
        for name in &superseded {
            paths.push(format!("{RELAY_TOKEN_SPOOL_DIR}/{name}"));
        }
        for path in &paths {
            argv.push(path.as_str());
        }
        run_root(runner, &argv)?;
    }
    let spool_files = after.len() - superseded.len();
    if spool_files > MAX_SPOOL_FILES {
        return Err(format!(
            "relay token spool holds {spool_files} files, over the daemon's hard cap of \
             {MAX_SPOOL_FILES}"
        ));
    }
    Ok(())
}

/// Decode the traversal verifying key (64 hex chars + newline on the guest) into
/// the 32 raw bytes the relay service expects, as base64 for transit.
fn relay_verifier_raw_b64(hex_text: &str) -> Result<String, String> {
    let hex = hex_text.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "traversal verifying key is not 64 hex characters (got {} characters)",
            hex.len()
        ));
    }
    let mut raw = [0u8; 32];
    for (index, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|err| format!("traversal verifying key hex is malformed: {err}"))?;
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(raw))
}

/// The `/etc/default/rustynet-relay` bind/id override for this scenario.
fn relay_default_env_content(relay_label: &str, relay_bind: &str) -> String {
    format!("RUSTYNET_RELAY_ID={relay_label}\nRUSTYNET_RELAY_BIND={relay_bind}\n")
}

/// Install + enable + start the relay service, then point it at this scenario's
/// topology: verifier key from the already-distributed traversal bundle, bind
/// override in `/etc/default`, restart, and a fail-closed `is-active` gate with
/// the unit's journal tail on failure.
///
/// `src_dir` is the guest's Rustynet source root — `ops install-systemd-relay`
/// reads the unit template relative to the process cwd (the adapter documents
/// the same requirement), so the verb runs under `cd "$1"`.
pub fn deploy_relay_service(
    runner: &dyn NetLeafRunner,
    src_dir: &str,
    relay_bind: &str,
    relay_label: &str,
) -> Result<(), String> {
    validate_argv_value("relay src dir", src_dir)?;
    validate_argv_value("relay bind", relay_bind)?;
    if relay_label != RELAY_ID_LABEL {
        return Err(format!(
            "relay label must be {RELAY_ID_LABEL} for this scenario (got: {relay_label:?})"
        ));
    }

    // 1+2+3. Verifier key: the traversal pub the distribute stage already put
    // on THIS guest (the exit mints, the relay verifies), decoded hex → raw →
    // installed 0644. The file is TEXT (64 hex chars + newline), so it is read
    // through the `cat` text-capture path: reading it with
    // `read_remote_base64` returned the base64 TRANSPORT of the file — 88
    // characters — which the hex check refused ("traversal verifying key is
    // not 64 hex characters (got 88 characters)", katana-xnet-1280,
    // cross_network_relay_remote_exit.log:187).
    let verifier_hex = read_remote_text(runner, &format!("{CONFIG_DIR}/traversal.pub"))?;
    let raw_b64 = relay_verifier_raw_b64(&verifier_hex)?;
    write_remote_base64(runner, RELAY_VERIFIER_PATH, "0644", &raw_b64)?;

    // 4. A stale /etc/default from an earlier topology crash-loops the unit
    // (EADDRNOTAVAIL); rewrite it unconditionally instead of trusting it.
    remove_remote(runner, &[RELAY_DEFAULT_ENV_PATH])?;

    // 5. Install + enable + start, from the source root (cwd-relative unit).
    run_root(
        runner,
        &[
            "sh",
            "-c",
            "set -eu; cd \"$1\"; rustynet ops install-systemd-relay",
            "sh",
            src_dir,
        ],
    )?;
    write_remote_text(
        runner,
        RELAY_DEFAULT_ENV_PATH,
        "0644",
        &relay_default_env_content(relay_label, relay_bind),
    )?;
    run_root(runner, &["systemctl", "restart", RELAY_SERVICE_UNIT])?;

    // 6. Fail closed unless the unit is active; carry the journal tail.
    let active = capture_root(runner, &["systemctl", "is-active", RELAY_SERVICE_UNIT])?;
    if active != "active" {
        let journal = capture_root_allow_failure(
            runner,
            &[
                "journalctl",
                "-u",
                RELAY_SERVICE_UNIT,
                "-n",
                "12",
                "--no-pager",
            ],
        )
        .unwrap_or_default();
        return Err(format!(
            "rustynet-relay service is not active after deploy (is-active: {active:?}): {journal}"
        ));
    }
    Ok(())
}

/// The unique 198.18.0.0/15 address in `ip -o -4 addr show` output.
///
/// The relay transport address is READ from the relay guest (owner decision:
/// no new CLI flag, no inventory change). Zero or multiple candidates is a hard
/// error — deploying the relay on a guessed address would mint bundles no peer
/// can use.
pub fn unique_ipv4_in_benchmark_prefix(output: &str) -> Result<String, String> {
    let mut found: Option<String> = None;
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(position) = fields.iter().position(|f| *f == "inet") else {
            continue;
        };
        let Some(cidr) = fields.get(position + 1) else {
            continue;
        };
        let addr = cidr.split('/').next().unwrap_or(cidr);
        let Ok(parsed) = addr.parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        let octets = parsed.octets();
        let in_prefix = octets[0] == 198 && (octets[1] == 18 || octets[1] == 19);
        if !in_prefix {
            continue;
        }
        if let Some(previous) = &found {
            if previous != addr {
                return Err(format!(
                    "multiple 198.18.0.0/15 addresses on the relay guest: {previous} and {addr}"
                ));
            }
            continue;
        }
        found = Some(addr.to_owned());
    }
    found.ok_or_else(|| {
        "no 198.18.0.0/15 address found on the relay guest: the relay transport address \
         cannot be determined"
            .to_owned()
    })
}

/// The relay's transport endpoint, read live from the relay guest.
pub fn relay_transport_endpoint(runner: &dyn NetLeafRunner) -> Result<String, String> {
    let addresses = capture_root_allow_failure(runner, &["ip", "-o", "-4", "addr", "show"])?;
    Ok(format!(
        "{}:{RELAY_SERVICE_BIND_PORT}",
        unique_ipv4_in_benchmark_prefix(&addresses)?
    ))
}

#[cfg(test)]
mod tests {
    use super::{EXIT_NODE_CAPABILITIES, NodeSpec, nodes_spec};

    const EXIT_PUB: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ENTRY_PUB: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const CLIENT_PUB: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn exit_node() -> NodeSpec {
        NodeSpec::new(
            "katana-exit-1-bootstrap",
            "192.168.123.222",
            51820,
            EXIT_PUB,
        )
        .expect("exit spec")
        .with_capabilities(&EXIT_NODE_CAPABILITIES)
    }

    fn entry_node() -> NodeSpec {
        NodeSpec::new(
            "katana-entry-1-bootstrap",
            "192.168.122.57",
            51820,
            ENTRY_PUB,
        )
        .expect("entry spec")
    }

    fn client_node() -> NodeSpec {
        NodeSpec::new(
            "katana-client-1-bootstrap",
            "192.168.122.45",
            51820,
            CLIENT_PUB,
        )
        .expect("client spec")
    }

    /// Client and entry keep the issuer's `[Client]` default: their entries
    /// stay byte-identical to the old three-field wire form (no fourth field,
    /// no capability token anywhere) — the "identical output" pin.
    #[test]
    fn client_and_entry_spec_stays_three_fields() {
        let spec = nodes_spec(&[entry_node(), client_node()]).expect("spec");
        assert_eq!(
            spec,
            format!(
                "katana-entry-1-bootstrap|192.168.122.57:51820|{ENTRY_PUB};\
                 katana-client-1-bootstrap|192.168.122.45:51820|{CLIENT_PUB}"
            )
        );
        assert!(!spec.contains("exit_server"));
        for entry in spec.split(';') {
            assert_eq!(
                entry.split('|').count(),
                3,
                "entry {entry:?} must stay three-field"
            );
        }
    }

    /// Golden wire form for the direct remote-exit topology: the exit entry
    /// grows exactly `|anchor,exit_server`. The `anchor` capability is required
    /// because the exit is enforced as `admin` and `admin` requires `anchor`
    /// in the signed assignment bundle.
    #[test]
    fn exit_spec_carries_anchor_and_exit_server_capabilities() {
        let spec = nodes_spec(&[exit_node(), client_node()]).expect("spec");
        assert_eq!(
            spec,
            format!(
                "katana-exit-1-bootstrap|192.168.123.222:51820|{EXIT_PUB}|anchor,exit_server;\
                 katana-client-1-bootstrap|192.168.122.45:51820|{CLIENT_PUB}"
            )
        );
    }

    /// Golden wire form for the relay-chain / failback topologies (exit,
    /// entry, client — the shell's order): only the exit's entry is four-field.
    #[test]
    fn relay_chain_spec_carries_capability_only_on_exit() {
        let spec = nodes_spec(&[exit_node(), entry_node(), client_node()]).expect("spec");
        assert_eq!(
            spec,
            format!(
                "katana-exit-1-bootstrap|192.168.123.222:51820|{EXIT_PUB}|anchor,exit_server;\
                 katana-entry-1-bootstrap|192.168.122.57:51820|{ENTRY_PUB};\
                 katana-client-1-bootstrap|192.168.122.45:51820|{CLIENT_PUB}"
            )
        );
    }

    /// Capability values come only from the closed `RoleCapability` enum and
    /// are rendered in canonical form: caller order is normalized and no free
    /// text can reach the spec line.
    #[test]
    fn capabilities_render_canonically_from_closed_enum() {
        let spec = nodes_spec(&[NodeSpec::new(
            "katana-exit-1-bootstrap",
            "192.168.123.222",
            51820,
            EXIT_PUB,
        )
        .expect("exit spec")
        .with_capabilities(&[RoleCapability::ExitServer, RoleCapability::Client])])
        .expect("spec");
        assert_eq!(
            spec,
            format!("katana-exit-1-bootstrap|192.168.123.222:51820|{EXIT_PUB}|client,exit_server")
        );
    }

    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;

    use super::{
        DNS_ZONE_BUNDLE_PATH, DNS_ZONE_PUB_PATH, install_dns_zone_bundle, reissue_dns_zone,
    };

    fn joined(runner: &MockLeafRunner) -> Vec<String> {
        runner
            .recorded()
            .iter()
            .map(|argv| argv.join(" "))
            .collect()
    }

    fn issuer_with_bundles() -> MockLeafRunner {
        MockLeafRunner {
            // `base64 -w 0 <path>` answers; any valid base64 payload will do.
            stdout_by_match: vec![("base64 -w 0".to_owned(), "QUJD".to_owned())],
            ..MockLeafRunner::default()
        }
    }

    /// The re-issue mints on the issuer through the EXISTING dns-zone verb with
    /// the scenario's own specs and the 300 s cap, reads each node's own
    /// bundle, and installs verifier key + bundle on that node, without
    /// touching the anti-replay watermark.
    #[test]
    fn reissue_dns_zone_mints_on_the_issuer_and_installs_each_nodes_own_bundle() {
        let issuer = issuer_with_bundles();
        let exit = MockLeafRunner::default();
        let client = MockLeafRunner::default();
        reissue_dns_zone(
            &issuer,
            "NODES",
            "ALLOW",
            &[
                (&exit, "katana-exit-1-bootstrap"),
                (&client, "katana-client-1-bootstrap"),
            ],
        )
        .expect("reissue");

        let issued = joined(&issuer);
        assert!(
            issued
                .iter()
                .any(|c| c.contains("rustynet ops e2e-issue-dns-zone-bundles-from-env --env-file")),
            "{issued:#?}"
        );
        // The env file travels as a base64 argument of the write script.
        use base64::Engine as _;
        let env_text = issuer
            .recorded()
            .iter()
            .filter_map(|argv| argv.last())
            .filter_map(|arg| {
                base64::engine::general_purpose::STANDARD
                    .decode(arg)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
            })
            .find(|text| text.contains("NODES_SPEC"))
            .expect("env file is written");
        assert!(env_text.contains("NODES_SPEC=\"NODES\""), "{env_text}");
        assert!(env_text.contains("ALLOW_SPEC=\"ALLOW\""), "{env_text}");
        assert!(env_text.contains("DNS_ZONE_TTL_SECS=\"300\""), "{env_text}");
        for node in ["katana-exit-1-bootstrap", "katana-client-1-bootstrap"] {
            assert!(
                issued.iter().any(|c| c.contains(&format!(
                    "base64 -w 0 /run/rustynet/dns-zone-issue/rn-dns-zone-{node}.dns-zone"
                ))),
                "{node}: {issued:#?}"
            );
        }
        for target in [&exit, &client] {
            let calls = joined(target);
            assert!(
                calls.iter().any(|c| c.contains(DNS_ZONE_PUB_PATH)),
                "{calls:#?}"
            );
            assert!(
                calls.iter().any(|c| c.contains(DNS_ZONE_BUNDLE_PATH)),
                "{calls:#?}"
            );
            assert!(
                !calls.iter().any(|c| c.contains("watermark")),
                "the replay watermark must stay: {calls:#?}"
            );
        }
        // Each node only ever receives its own bundle: the issuer is read once
        // per target, so the two reads name different files.
        let reads: Vec<_> = issued
            .iter()
            .filter(|c| c.contains("rn-dns-zone-") && c.contains("base64 -w 0"))
            .collect();
        assert_eq!(reads.len(), 2, "{reads:#?}");
    }

    #[test]
    fn reissue_dns_zone_fails_closed_when_the_issuer_refuses() {
        let issuer = MockLeafRunner {
            fail_on: (0..8).collect(),
            failure_stderr: "issue failed".to_owned(),
            ..MockLeafRunner::default()
        };
        let exit = MockLeafRunner::default();
        let err = reissue_dns_zone(
            &issuer,
            "NODES",
            "ALLOW",
            &[(&exit, "katana-exit-1-bootstrap")],
        )
        .expect_err("a failed issuance must not install anything");
        assert!(!err.is_empty());
        assert!(
            exit.recorded().is_empty(),
            "nothing is installed on failure"
        );
    }

    #[test]
    fn install_dns_zone_bundle_uses_the_daemon_paths_and_modes() {
        let node = MockLeafRunner::default();
        install_dns_zone_bundle(&node, "QUJD", "QUJD").expect("install");
        let calls = joined(&node);
        assert!(
            calls
                .iter()
                .any(|c| c.contains("install -m 0644 -o root -g root")
                    && c.ends_with(DNS_ZONE_PUB_PATH)),
            "{calls:#?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c.contains("install -m 0640 -o root -g rustynetd")
                    && c.ends_with(DNS_ZONE_BUNDLE_PATH)),
            "{calls:#?}"
        );
    }

    use super::refresh_nodes_spec;

    /// The refresher must see the node's capabilities in ITS field position.
    #[test]
    fn refresh_spec_carries_capabilities_in_both_parsers_slots() {
        let generic = format!(
            "katana-exit-1-bootstrap|192.168.123.222:51820|{EXIT_PUB}|anchor,exit_server;\
             katana-client-1-bootstrap|192.168.122.45:51820|{CLIENT_PUB}"
        );
        assert_eq!(
            refresh_nodes_spec(&generic).expect("convert"),
            format!(
                "katana-exit-1-bootstrap|192.168.123.222:51820|{EXIT_PUB}|anchor,exit_server||||\
                 anchor,exit_server;\
                 katana-client-1-bootstrap|192.168.122.45:51820|{CLIENT_PUB}"
            )
        );
    }

    #[test]
    fn refresh_spec_canonicalises_and_refuses_unknown_or_malformed_input() {
        let spec = |tail: &str| format!("n1|192.0.2.1:51820|{EXIT_PUB}{tail}");
        let converted = refresh_nodes_spec(&spec("|exit_server,client")).expect("convert");
        assert!(
            converted.ends_with("|client,exit_server||||client,exit_server"),
            "{converted}"
        );
        assert_eq!(
            refresh_nodes_spec(&spec("|")).expect("empty caps stay 3-field"),
            spec("")
        );
        assert!(refresh_nodes_spec(&spec("|not_a_capability")).is_err());
        assert!(
            refresh_nodes_spec(&spec("|a|b|c|d")).is_err(),
            "5 fields are not issuer grammar"
        );
        assert!(refresh_nodes_spec("").is_err());
        assert!(refresh_nodes_spec(";").is_err());
    }

    /// The refresh env a scenario installs must carry the dual-slot spelling.
    #[test]
    fn assignment_refresh_env_uses_the_dual_slot_spelling() {
        let generic =
            format!("katana-exit-1-bootstrap|192.168.123.222:51820|{EXIT_PUB}|anchor,exit_server");
        let env = super::assignment_refresh_env("katana-exit-1-bootstrap", &generic, "a|b", None)
            .expect("env")
            .render();
        assert!(
            env.contains("|anchor,exit_server||||anchor,exit_server"),
            "{env}"
        );
        // Exactly the capabilities-in-both-slots entry, nothing after it.
        assert!(
            env.contains(&format!(
                "{EXIT_PUB}|anchor,exit_server||||anchor,exit_server\"\n"
            )),
            "{env}"
        );
    }

    // ── relay service + spool helpers (DESIGN-XNET-RELAY S3) ──

    /// The drop-in must set exactly the variable the adapter sets, pointing at
    /// exactly the directory the daemon and adapter agree on.
    #[test]
    fn relay_spool_dropin_matches_adapter_contract() {
        let content = super::relay_spool_dropin_content();
        assert_eq!(
            content,
            format!(
                "[Service]\nEnvironment={}={}\n",
                crate::vm_lab::orchestrator::adapter::linux_relay_tokens::SPOOL_ENV_KEY,
                crate::vm_lab::orchestrator::adapter::linux_relay_tokens::RELAY_TOKEN_SPOOL_DIR
            )
        );
        // The adapter's own verifier accepts this output verbatim.
        assert!(
            crate::vm_lab::orchestrator::adapter::linux_relay_tokens::environment_has_spool(
                &format!(
                    "Environment={}",
                    content
                        .lines()
                        .find_map(|l| l.strip_prefix("Environment="))
                        .expect("Environment line")
                )
            )
        );
    }

    /// Only exact mint names parse; anything else must be refused before it is
    /// interpolated into a spool filename (pair-split off-by-one guard).
    #[test]
    fn parse_relay_token_name_accepts_only_mint_shape() {
        let ok = "1700000000-01-02.relay-token";
        assert_eq!(
            super::parse_relay_token_name(ok),
            Some((1_700_000_000_u32, 1, 2)),
            "issued/pair/seq order matters: the pair index routes the file"
        );
        assert_eq!(
            super::parse_relay_token_name("1700000000-00-01.relay-token"),
            Some((1_700_000_000, 0, 1))
        );
        for bad in [
            "rn-relay-token.pub",
            "0001700000000-00-01.relay-token", // exactly 10 digits required
            "170000000-1-01.relay-token",      // issued must be 10 digits
            "1700000000-1-01.relay-token",     // pair must be 2 digits
            "1700000000-00.relay-token",       // missing seq
            "1700000000-00-01-99.relay-token", // extra field
            "1700000000-00-01.relay-token.backup",
            "../escape.relay-token",
            "",
        ] {
            assert_eq!(
                super::parse_relay_token_name(bad),
                None,
                "{bad:?} must not parse"
            );
        }
    }

    #[test]
    fn relay_verifier_raw_b64_decodes_exactly_32_bytes() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let encoded = super::relay_verifier_raw_b64(&format!("{hex}\n")).expect("decodes");
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("valid base64");
        assert_eq!(raw.len(), 32);
        assert_eq!(&raw[..4], &[0x00, 0x01, 0x02, 0x03]);
        assert_eq!(&raw[28..], &[0x1c, 0x1d, 0x1e, 0x1f]);
        for bad in ["", "00", "zz", &"a".repeat(63), &format!("{hex}00")] {
            assert!(super::relay_verifier_raw_b64(bad).is_err(), "{bad:?}");
        }
    }

    // ── D4: traversal.pub is TEXT, not a base64 transport ──

    /// REAL (katana-xnet-1280, cross_network_relay_remote_exit.log:187-190):
    /// `sudo -n base64 -w 0 /etc/rustynet/traversal.pub` on the relay guest
    /// returned exactly this — the base64 TRANSPORT of the file bytes (64 hex
    /// chars + LF = 65 bytes = 88 base64 chars), the string that the old
    /// `read_remote_base64` read fed to the hex check.
    const REAL_TRAVERSAL_PUB_TRANSPORT_B64: &str =
        "NGRkNDI2ZGQ2NTE5MDIxNzljMjdlMmZmM2RkMjJkZGVjZmU5MjI0MDkxZDU2NWQyMDFmY2E0Y2RjNzY4MTY0Mwo=";

    /// REAL: the transport above decoded (base64 of the 65 file bytes) — the
    /// file TEXT a real `cat /etc/rustynet/traversal.pub` returns, trimmed by
    /// [`capture_root`] the same way.
    const REAL_TRAVERSAL_PUB_HEX_TEXT: &str =
        "4dd426dd651902179c27e2ff3dd22ddecfe9224091d565d201fca4cdc7681643";

    /// base64 of the 32 raw verifier bytes the fixed pipeline must install
    /// 0644 (hex-decode of the key above, re-encoded for transit).
    const EXPECTED_VERIFIER_RAW_B64: &str = "TdQm3WUZAhecJ+L/PdIt3s/pIkCR1WXSAfykzcdoFkM=";

    /// A fake that answers the way the REAL guest answers: `cat` yields the
    /// file text, `base64 -w 0` yields base64 of the file bytes — never the
    /// author's belief about either.
    fn relay_deploy_runner() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![
                (
                    "cat /etc/rustynet/traversal.pub".to_owned(),
                    format!("{REAL_TRAVERSAL_PUB_HEX_TEXT}\n"),
                ),
                (
                    "base64 -w 0 /etc/rustynet/traversal.pub".to_owned(),
                    REAL_TRAVERSAL_PUB_TRANSPORT_B64.to_owned(),
                ),
                ("systemctl is-active".to_owned(), "active".to_owned()),
            ],
            ..MockLeafRunner::default()
        }
    }

    /// D4, fixed: the deploy reads traversal.pub as TEXT via `cat`, decodes it
    /// to the 32 raw bytes, and installs them 0644 as base64 of exactly those
    /// bytes. Against the old `read_remote_base64` read this is red: the fake
    /// answers `base64 -w 0` with the REAL 88-char transport, the hex check
    /// refuses it, and no verifier write ever happens.
    #[test]
    fn deploy_relay_service_installs_real_verifier_bytes_read_as_text() {
        let runner = relay_deploy_runner();
        super::deploy_relay_service(
            &runner,
            "/srv/rustynet-relay",
            "198.18.64.5:4500",
            super::RELAY_ID_LABEL,
        )
        .expect("deploy succeeds against the real capture");

        let recorded = runner.recorded();
        assert!(
            recorded
                .iter()
                .any(|call| call.join(" ").contains("cat /etc/rustynet/traversal.pub")),
            "traversal.pub must be read as text via cat: {recorded:?}"
        );
        assert!(
            !recorded.iter().any(|call| call
                .join(" ")
                .contains("base64 -w 0 /etc/rustynet/traversal.pub")),
            "the base64 transport read must not be used for traversal.pub: {recorded:?}"
        );
        let verifier_write = recorded
            .iter()
            .find(|call| {
                let joined = call.join(" ");
                joined.contains(super::RELAY_VERIFIER_PATH) && joined.contains("0644")
            })
            .unwrap_or_else(|| panic!("no verifier write in transcript: {recorded:?}"));
        assert_eq!(
            verifier_write.last(),
            Some(&EXPECTED_VERIFIER_RAW_B64.to_owned()),
            "verifier payload must be base64 of the 32 raw key bytes: {verifier_write:?}"
        );
    }

    /// The old misread stays refused forever: the REAL transport string fed to
    /// the hex check is exactly the katana-xnet-1280 failure ("traversal
    /// verifying key is not 64 hex characters (got 88 characters)") and must
    /// remain an error, never a lenient decode.
    #[test]
    fn relay_verifier_rejects_the_real_base64_transport_misread() {
        let err = super::relay_verifier_raw_b64(REAL_TRAVERSAL_PUB_TRANSPORT_B64)
            .expect_err("the transport string is not hex text");
        assert!(err.contains("not 64 hex characters"), "{err}");
        assert!(err.contains("88 characters"), "{err}");
    }

    /// A traversal.pub whose content is not 64 hex chars fails the deploy
    /// BEFORE any write: no verifier file is touched on the guest.
    #[test]
    fn deploy_relay_service_fails_closed_when_the_pub_is_not_hex_text() {
        let runner = MockLeafRunner {
            stdout_by_match: vec![(
                "cat /etc/rustynet/traversal.pub".to_owned(),
                REAL_TRAVERSAL_PUB_TRANSPORT_B64.to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        let err = super::deploy_relay_service(
            &runner,
            "/srv/rustynet-relay",
            "198.18.64.5:4500",
            super::RELAY_ID_LABEL,
        )
        .expect_err("non-hex traversal.pub must fail the deploy");
        assert!(err.contains("not 64 hex characters"), "{err}");
        assert!(err.contains("88 characters"), "{err}");
        assert!(
            !runner
                .recorded()
                .iter()
                .any(|call| call.join(" ").contains(super::RELAY_VERIFIER_PATH)),
            "no verifier write may happen on a refused key: {:?}",
            runner.recorded()
        );
    }

    /// The bind override must carry the id AND the bind, newline-terminated —
    /// this is the file whose staleness crash-loops the unit.
    #[test]
    fn relay_default_env_content_pins_id_and_bind() {
        let content = super::relay_default_env_content("relay-local", "198.18.64.5:4500");
        assert_eq!(
            content,
            "RUSTYNET_RELAY_ID=relay-local\nRUSTYNET_RELAY_BIND=198.18.64.5:4500\n"
        );
    }

    /// Exactly one 198.18.0.0/15 address wins; zero or two is refused.
    #[test]
    fn unique_ipv4_in_benchmark_prefix_picks_the_single_relay_address() {
        let output = "\
2: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
3: enp0s2    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s2\\       valid_lft 86189sec preferred_lft 86189sec
4: wg0    inet 198.18.64.5/24 brd 198.18.64.255 scope global wg0\\       valid_lft forever preferred_lft forever
";
        assert_eq!(
            super::unique_ipv4_in_benchmark_prefix(output).expect("unique"),
            "198.18.64.5"
        );
        assert!(
            super::unique_ipv4_in_benchmark_prefix("2: lo    inet 127.0.0.1/8 scope host lo")
                .is_err()
        );
        let two = "\
3: a    inet 198.18.64.5/24 scope global a
4: b    inet 198.19.1.1/24 scope global b
";
        assert!(
            super::unique_ipv4_in_benchmark_prefix(two).is_err(),
            "two candidate addresses must fail closed"
        );
        // Whole /15: 198.18.x and 198.19.x both qualify, nothing else.
        assert_eq!(
            super::unique_ipv4_in_benchmark_prefix(
                "4: wg0    inet 198.19.255.254/24 scope global wg0"
            )
            .as_deref(),
            Ok("198.19.255.254")
        );
        assert!(
            super::unique_ipv4_in_benchmark_prefix("4: wg0    inet 198.20.0.1/24 scope global wg0")
                .is_err()
        );
    }

    use rustynet_control::roles::RoleCapability;
}
