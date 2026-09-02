//! QH-01 validated-argument seam — the ONE home for per-class orchestrator
//! argument validators.
//!
//! Every value that reaches a remote command sink must pass through a validator
//! in this module BEFORE any command string is built (`orchestrator_arg_safety_
//! is_the_injection_boundary` in `vm_lab/mod.rs`). A validator rejects with a
//! [`ValidationError`] naming the class and the violated rule; it never echoes
//! the full offending value back (secrets hygiene — values may be user data).
//!
//! Hoisted here (single source of truth, re-exported from the original file so
//! existing callers and tests are unchanged):
//! - [`validate_ip_arg`] — was duplicated in `linux_traffic.rs` and
//!   `windows_traffic.rs` (identical charset allowlist).
//! - [`validate_utun_name`] — was `macos_install.rs`.
//! - [`validate_windows_path`] — was `windows_install.rs`.
//!
//! Deliberately NOT hoisted: `macos_traffic.rs::validate_ip_arg` parses the
//! value as an [`std::net::IpAddr`] and rejects unspecified/multicast/broadcast
//! addresses — a different validation class (address semantics, not charset).
//! It keeps its own home; its tests require CIDR rejection, which the charset
//! class intentionally permits.
//!
//! Confinement note: [`posix_path`] checks shape (absolute, no traversal
//! segment, no control characters). It does NOT enforce a filesystem
//! confinement root — that is a separate concern handled where the path is
//! consumed.

use std::fmt;
use std::net::IpAddr;

use crate::vm_lab::orchestrator::error::AdapterError;
use crate::vm_lab::shell_quote;

/// A rejected orchestrator argument: names the argument class and the rule it
/// violated. The offending value is never fully echoed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidationError {
    class: &'static str,
    rule: String,
}

impl ValidationError {
    fn new(class: &'static str, rule: impl Into<String>) -> Self {
        Self {
            class,
            rule: rule.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {} argument: {}", self.class, self.rule)
    }
}

impl std::error::Error for ValidationError {}

impl From<ValidationError> for AdapterError {
    fn from(err: ValidationError) -> Self {
        AdapterError::Protocol {
            message: err.to_string(),
        }
    }
}

/// Reject `value` unless every character satisfies `allowed`.
fn ensure_charset(
    value: &str,
    class: &'static str,
    allowed: impl Fn(char) -> bool,
) -> Result<(), ValidationError> {
    if let Some(bad) = value.chars().find(|ch| !allowed(*ch)) {
        return Err(ValidationError::new(
            class,
            format!(
                "must match the class alphabet but contains {bad:?} \
                 (offset {})",
                value.chars().take_while(|ch| *ch != bad).count()
            ),
        ));
    }
    Ok(())
}

const ARG_ALPHABET: &str = "alphanumeric, '.', '_', '-'";

/// A node identifier: the same alphabet a `script_template` bare binding
/// permits (`[A-Za-z0-9._-]+`, non-empty).
pub(crate) fn node_id(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("node id", "must not be empty"));
    }
    ensure_charset(value, "node id", |ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')
    })
    .map_err(|err| {
        ValidationError::new(
            "node id",
            format!("must match [{ARG_ALPHABET}]+, {}", err.rule),
        )
    })
}

/// An SSH connection user: must not start with `-` (option injection into
/// `ssh_config`/argv), must contain no newline/CR/NUL, and must stay inside
/// `[A-Za-z0-9._-]+`.
pub(crate) fn connection_user(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("connection user", "must not be empty"));
    }
    if value.starts_with('-') {
        return Err(ValidationError::new(
            "connection user",
            "must not start with '-' (option injection)",
        ));
    }
    if value.chars().any(|ch| matches!(ch, '\n' | '\r' | '\0')) {
        return Err(ValidationError::new(
            "connection user",
            "must not contain newline, carriage return, or NUL",
        ));
    }
    ensure_charset(value, "connection user", |ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')
    })
    .map_err(|err| {
        ValidationError::new(
            "connection user",
            format!("must match [{ARG_ALPHABET}]+, {}", err.rule),
        )
    })
}

/// A POSIX path argument: absolute, no NUL/newline/CR, and no `..` segment.
/// This is a shape check, not a filesystem confinement guarantee.
pub(crate) fn posix_path(value: &str) -> Result<(), ValidationError> {
    if !value.starts_with('/') {
        return Err(ValidationError::new(
            "posix path",
            "must be absolute (start with '/')",
        ));
    }
    if value.chars().any(|ch| matches!(ch, '\n' | '\r' | '\0')) {
        return Err(ValidationError::new(
            "posix path",
            "must not contain newline, carriage return, or NUL",
        ));
    }
    if value.split('/').any(|segment| segment == "..") {
        return Err(ValidationError::new(
            "posix path",
            "must not contain a '..' segment",
        ));
    }
    Ok(())
}

/// A CIDR argument: `<address>/<prefix>` with a parseable IP address and a
/// prefix that fits the address family.
pub(crate) fn cidr(value: &str) -> Result<(), ValidationError> {
    let Some((addr, prefix)) = value.split_once('/') else {
        return Err(ValidationError::new("CIDR", "must be <address>/<prefix>"));
    };
    let max_prefix: u32 = if addr.contains(':') { 128 } else { 32 };
    let parsed: IpAddr = addr
        .parse()
        .map_err(|_| ValidationError::new("CIDR", "address part is not a parseable IP address"))?;
    let prefix_num: u32 = prefix
        .parse()
        .map_err(|_| ValidationError::new("CIDR", "prefix part is not a decimal number"))?;
    if prefix_num > max_prefix {
        return Err(ValidationError::new(
            "CIDR",
            format!("prefix exceeds the {max_prefix}-bit maximum for this family"),
        ));
    }
    let _ = parsed;
    Ok(())
}

/// A service (unit) name: non-empty, `[A-Za-z0-9._-]+` — no separators that
/// could escape the unit-name slot it is embedded into.
pub(crate) fn service_name(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("service name", "must not be empty"));
    }
    ensure_charset(value, "service name", |ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')
    })
    .map_err(|err| {
        ValidationError::new(
            "service name",
            format!("must match [{ARG_ALPHABET}]+, {}", err.rule),
        )
    })
}

/// A bundle filename: a single path component, non-empty, `[A-Za-z0-9._-]+`,
/// never `..` and never containing a separator.
pub(crate) fn bundle_filename(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("bundle filename", "must not be empty"));
    }
    if value.contains('/') || value.contains('\\') {
        return Err(ValidationError::new(
            "bundle filename",
            "must be a single filename without path separators",
        ));
    }
    if value == ".." {
        return Err(ValidationError::new("bundle filename", "must not be '..'"));
    }
    ensure_charset(value, "bundle filename", |ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')
    })
    .map_err(|err| {
        ValidationError::new(
            "bundle filename",
            format!("must match [{ARG_ALPHABET}]+, {}", err.rule),
        )
    })
}

/// A TCP port: must parse as `u16`.
pub(crate) fn port(value: &str) -> Result<(), ValidationError> {
    value
        .parse::<u16>()
        .map(|_| ())
        .map_err(|_| ValidationError::new("port", "must be a decimal number in the u16 range"))
}

/// An interface name: delegates to the reviewed checker in
/// `recover_guest_network.rs` (single source of truth — not copied).
pub(crate) fn interface_name(value: &str) -> Result<(), ValidationError> {
    if !crate::vm_lab::recover_guest_network::is_safe_interface_name(value) {
        return Err(ValidationError::new(
            "interface name",
            "must be non-empty, at most 32 characters, and match \
             [A-Za-z0-9._-]+",
        ));
    }
    Ok(())
}

/// A utun interface name: `utun` + non-empty decimal digits, at most
/// 15 characters (IFNAMSIZ).
pub(crate) fn utun_name(value: &str) -> Result<(), ValidationError> {
    let Some(suffix) = value.strip_prefix("utun") else {
        return Err(ValidationError::new(
            "utun interface name",
            "must start with utun",
        ));
    };
    if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return Err(ValidationError::new(
            "utun interface name",
            "must be utun followed by digits",
        ));
    }
    if value.len() > 15 {
        return Err(ValidationError::new(
            "utun interface name",
            "exceeds 15-char IFNAMSIZ",
        ));
    }
    Ok(())
}

/// A Windows path argument: reject NUL/CR/LF that could escape PowerShell
/// quoting; must not be empty.
pub(crate) fn windows_path(value: &str) -> Result<(), ValidationError> {
    if value.chars().any(|ch| matches!(ch, '\0' | '\r' | '\n')) {
        return Err(ValidationError::new(
            "Windows path",
            "contains control characters not safe for shell embedding",
        ));
    }
    if value.is_empty() {
        return Err(ValidationError::new("Windows path", "must not be empty"));
    }
    Ok(())
}

/// An IP-address-shaped argument: a charset allowlist safe for shell
/// embedding. Hoisted from `linux_traffic.rs` / `windows_traffic.rs` (the two
/// identical copies). Note this class intentionally accepts CIDR notation;
/// address-semantics validation is a different class (see module docs).
pub(crate) fn ip_charset(value: &str) -> Result<(), ValidationError> {
    ensure_charset(value, "IP argument", |ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '/')
    })
    .map_err(|err| {
        ValidationError::new(
            "IP argument",
            format!(
                "contains characters not safe for shell embedding \
                 (allowed: alphanumeric, '.', ':', '/'); {}",
                err.rule
            ),
        )
    })
}

// ── Hoisted entry points (original signatures, re-exported from old homes) ──

/// Validate that an IP address argument contains no shell-dangerous characters.
/// Hoisted from `linux_traffic.rs` / `windows_traffic.rs`.
pub(crate) fn validate_ip_arg(ip: &str) -> Result<(), AdapterError> {
    ip_charset(ip).map_err(AdapterError::from)
}

/// Validate that a utun name is safe for use as an interface name.
/// Hoisted from `macos_install.rs`.
pub(crate) fn validate_utun_name(name: &str) -> Result<(), AdapterError> {
    utun_name(name).map_err(AdapterError::from)
}

/// Validate a Windows path argument: reject NUL/CR/LF that could escape PS
/// quoting. Hoisted from `windows_install.rs`.
pub(crate) fn validate_windows_path(path: &str) -> Result<(), AdapterError> {
    windows_path(path).map_err(AdapterError::from)
}

// ── Validated argument values ────────────────────────────────────────────────

/// A value that has already passed its class validator. Construction is the
/// only way in — there is no way to wrap an unvalidated string, so a
/// [`ValidatedArg`] reaching a command builder is proof the validator ran.
#[derive(Clone)]
pub(crate) enum ValidatedArg {
    Ip(String),
    NodeId(String),
    Path(String),
    Service(String),
    Cidr(String),
    Utun(String),
    ConnectionUser(String),
    InterfaceName(String),
    BundleFilename(String),
    Port(String),
}

impl ValidatedArg {
    fn value(&self) -> &str {
        match self {
            Self::Ip(v)
            | Self::NodeId(v)
            | Self::Path(v)
            | Self::Service(v)
            | Self::Cidr(v)
            | Self::Utun(v)
            | Self::ConnectionUser(v)
            | Self::InterfaceName(v)
            | Self::BundleFilename(v)
            | Self::Port(v) => v,
        }
    }

    /// Shell-quoted form for embedding into a remote command. The only way a
    /// caller observes the value; it is always quoted by `shell_quote`.
    pub(crate) fn quoted(&self) -> String {
        shell_quote(self.value())
    }

    pub(crate) fn ip(value: &str) -> Result<Self, ValidationError> {
        ip_charset(value)?;
        Ok(Self::Ip(value.to_owned()))
    }

    pub(crate) fn node_id(value: &str) -> Result<Self, ValidationError> {
        node_id(value)?;
        Ok(Self::NodeId(value.to_owned()))
    }

    pub(crate) fn path(value: &str) -> Result<Self, ValidationError> {
        posix_path(value)?;
        Ok(Self::Path(value.to_owned()))
    }

    pub(crate) fn service(value: &str) -> Result<Self, ValidationError> {
        service_name(value)?;
        Ok(Self::Service(value.to_owned()))
    }

    pub(crate) fn cidr(value: &str) -> Result<Self, ValidationError> {
        cidr(value)?;
        Ok(Self::Cidr(value.to_owned()))
    }

    pub(crate) fn utun(value: &str) -> Result<Self, ValidationError> {
        utun_name(value)?;
        Ok(Self::Utun(value.to_owned()))
    }

    pub(crate) fn connection_user(value: &str) -> Result<Self, ValidationError> {
        connection_user(value)?;
        Ok(Self::ConnectionUser(value.to_owned()))
    }

    pub(crate) fn interface_name(value: &str) -> Result<Self, ValidationError> {
        interface_name(value)?;
        Ok(Self::InterfaceName(value.to_owned()))
    }

    pub(crate) fn bundle_filename(value: &str) -> Result<Self, ValidationError> {
        bundle_filename(value)?;
        Ok(Self::BundleFilename(value.to_owned()))
    }

    pub(crate) fn port(value: &str) -> Result<Self, ValidationError> {
        port(value)?;
        Ok(Self::Port(value.to_owned()))
    }
}

impl fmt::Debug for ValidatedArg {
    /// Redacted to the variant name and value length: validated argument
    /// values are operator-controlled, but they have no business in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Ip(_) => "Ip",
            Self::NodeId(_) => "NodeId",
            Self::Path(_) => "Path",
            Self::Service(_) => "Service",
            Self::Cidr(_) => "Cidr",
            Self::Utun(_) => "Utun",
            Self::ConnectionUser(_) => "ConnectionUser",
            Self::InterfaceName(_) => "InterfaceName",
            Self::BundleFilename(_) => "BundleFilename",
            Self::Port(_) => "Port",
        };
        write!(f, "ValidatedArg::{variant}(len={})", self.value().len())
    }
}

// ── Step 5 pin: structural invariants over the adapter source tree ──────────

/// The measured count of raw sink-call sites in the adapter tree at the time
/// this seam landed: lines matching `run_remote[a-z_]*(` (the whole remote
/// sink family) that are not `fn` definitions, with `#[cfg(test)]` regions
/// skipped. MUST ONLY GO DOWN — Step 4 migrates these call sites onto
/// `RemoteCommand`; an increase reintroduces raw string interpolation at a
/// sink and fails this test.
#[cfg(test)]
pub(crate) const BASELINE_RAW_SINK_CALL_SITES: usize = 160;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn adapter_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vm_lab/orchestrator/adapter")
    }

    /// Remove `#[cfg(test)] mod <name> { ... }` regions (brace-depth matched)
    /// so the structural scan only sees production code (review A7).
    fn strip_test_regions(source: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.contains("#[cfg(test)]") {
                // Find the `mod` line that follows, then skip to its matching
                // close brace. If no mod appears nearby, skip only the
                // attribute line.
                let mut j = i + 1;
                let mut found_mod = None;
                while j < lines.len() && j <= i + 5 {
                    if lines[j].contains("mod ") && lines[j].contains('{') {
                        found_mod = Some(j);
                        break;
                    }
                    j += 1;
                }
                match found_mod {
                    Some(start) => {
                        let mut depth = 0usize;
                        let mut k = start;
                        loop {
                            depth += lines[k].matches('{').count();
                            depth = depth.saturating_sub(lines[k].matches('}').count());
                            if depth == 0 && k > start {
                                i = k + 1;
                                break;
                            }
                            if k >= lines.len() - 1 {
                                i = k + 1;
                                break;
                            }
                            k += 1;
                        }
                        continue;
                    }
                    None => {
                        i += 1;
                        continue;
                    }
                }
            }
            out.push_str(line);
            out.push('\n');
            i += 1;
        }
        out
    }

    fn adapter_sources() -> Vec<(String, String)> {
        let dir = adapter_dir();
        let mut files = Vec::new();
        let entries = std::fs::read_dir(&dir).expect("adapter dir must be readable");
        for entry in entries {
            let entry = entry.expect("adapter dir entry must be readable");
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                let name = path
                    .file_name()
                    .expect("file name must exist")
                    .to_string_lossy()
                    .to_string();
                let source =
                    std::fs::read_to_string(&path).expect("adapter source must be readable");
                files.push((name, strip_test_regions(&source)));
            }
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        files
    }

    /// Count occurrences of `run_remote[a-z_]*(` in non-fn-definition lines.
    fn count_raw_sink_call_sites(source: &str) -> usize {
        let mut count = 0usize;
        for line in source.lines() {
            if line.contains("fn run_remote") {
                continue;
            }
            let bytes = line.as_bytes();
            let mut search_from = 0usize;
            while let Some(rel) = line[search_from..].find("run_remote") {
                let idx = search_from + rel;
                let mut end = idx + "run_remote".len();
                while end < bytes.len() && (bytes[end].is_ascii_lowercase() || bytes[end] == b'_') {
                    end += 1;
                }
                if end < bytes.len() && bytes[end] == b'(' {
                    count += 1;
                }
                search_from = end;
            }
        }
        count
    }

    #[test]
    fn remote_command_field_stays_private_outside_its_defining_module() {
        for (name, source) in adapter_sources() {
            if name == "ssh.rs" {
                continue;
            }
            assert!(
                !source.contains("RemoteCommand("),
                "{name} constructs RemoteCommand directly; only ssh.rs may \
                 build one — route new values through ValidatedArg instead"
            );
        }
    }

    #[test]
    fn raw_sink_call_site_count_must_only_go_down() {
        let total: usize = adapter_sources()
            .iter()
            .map(|(_, source)| count_raw_sink_call_sites(source))
            .sum();
        // Step 4 migrates these call sites; the count must never grow back.
        assert!(
            total <= BASELINE_RAW_SINK_CALL_SITES,
            "raw sink-call sites grew to {total} (baseline {}): a new call \
             site is interpolating an unvalidated string at a remote sink; \
             route it through RemoteCommand + ValidatedArg instead",
            BASELINE_RAW_SINK_CALL_SITES
        );
    }

    #[test]
    fn scan_helpers_skip_cfg_test_regions() {
        let source = "fn a() {}\n#[cfg(test)]\nmod tests {\n    run_remote_x(conn);\n}\nfn b() { ssh::run_remote(conn); }\n";
        let stripped = strip_test_regions(source);
        assert!(!stripped.contains("run_remote_x"));
        assert_eq!(count_raw_sink_call_sites(&stripped), 1);
    }

    // ── Per-class validators: one rejection + one acceptance each ───────────

    #[test]
    fn node_id_rejects_shell_metacharacters_and_accepts_the_bare_alphabet() {
        assert!(node_id("edge-1.en0_x").is_ok());
        let err = node_id("edge;rm -rf").expect_err("semicolon is outside the alphabet");
        assert!(err.to_string().contains("node id"));
        assert!(!err.to_string().contains("rm -rf"), "no payload echo");
        assert!(node_id("").is_err());
        assert!(node_id("edge$1").is_err());
        assert!(node_id("edge 1").is_err());
    }

    #[test]
    fn connection_user_rejects_option_injection_and_newlines() {
        assert!(connection_user("iwan.teague_1").is_ok());
        assert!(connection_user("-oProxyCommand=evil").is_err());
        assert!(connection_user("user\nhost").is_err());
        assert!(connection_user("user\0").is_err());
        assert!(connection_user("user;id").is_err());
        assert!(connection_user("").is_err());
    }

    #[test]
    fn posix_path_rejects_relative_traversal_and_controls() {
        assert!(posix_path("/opt/rustynet/bin").is_ok());
        assert!(posix_path("opt/rustynet").is_err());
        assert!(posix_path("/opt/../etc").is_err());
        assert!(posix_path("/opt/rus\0tynet").is_err());
        assert!(posix_path("/opt/rus\ntynet").is_err());
    }

    #[test]
    fn cidr_rejects_malformed_input_and_accepts_both_families() {
        assert!(cidr("10.0.0.0/8").is_ok());
        assert!(cidr("fd00::/64").is_ok());
        assert!(cidr("10.0.0.0").is_err());
        assert!(cidr("10.0.0.0/33").is_err());
        assert!(cidr("fd00::/129").is_err());
        assert!(cidr("nohost/8").is_err());
        assert!(cidr("10.0.0.0/x").is_err());
    }

    #[test]
    fn service_name_rejects_separators_and_accepts_unit_names() {
        assert!(service_name("rustynet-relay.service_x").is_ok());
        assert!(service_name("svc/systemd-escape").is_err());
        assert!(service_name("svc name").is_err());
        assert!(service_name("").is_err());
    }

    #[test]
    fn bundle_filename_rejects_path_separators_and_traversal() {
        assert!(bundle_filename("membership_bundle_1.tar").is_ok());
        assert!(bundle_filename("a/b").is_err());
        assert!(bundle_filename("a\\b").is_err());
        assert!(bundle_filename("..").is_err());
        assert!(bundle_filename("").is_err());
    }

    #[test]
    fn port_rejects_out_of_range_and_non_numeric() {
        assert!(port("4242").is_ok());
        assert!(port("0").is_ok());
        assert!(port("65536").is_err());
        assert!(port("4242;").is_err());
        assert!(port("").is_err());
    }

    #[test]
    fn interface_name_rejects_metacharacters_and_spaces_via_the_reviewed_checker() {
        assert!(interface_name("en0").is_ok());
        assert!(interface_name("utun7").is_ok());
        assert!(interface_name("a;rm -rf").is_err());
        assert!(interface_name("en p0").is_err());
        assert!(interface_name("").is_err());
    }

    #[test]
    fn utun_name_rejects_non_numeric_suffix_and_oversized_names() {
        assert!(utun_name("utun7").is_ok());
        assert!(utun_name("").is_err());
        assert!(utun_name("utun").is_err());
        assert!(utun_name("utunX").is_err());
        assert!(utun_name("utun;rm -rf /").is_err());
        assert!(utun_name("utun\n0").is_err());
        assert!(utun_name("utun12345678901234").is_err());
        assert!(utun_name("wg0").is_err());
    }

    #[test]
    fn windows_path_rejects_control_characters_and_empty() {
        assert!(windows_path("C:\\ProgramData\\Rustynet\\vm-lab").is_ok());
        assert!(windows_path("C:\\foo\0bar").is_err());
        assert!(windows_path("C:\r\nfoo").is_err());
        assert!(windows_path("").is_err());
    }

    #[test]
    fn ip_charset_rejects_metacharacters_and_accepts_address_shapes() {
        assert!(ip_charset("10.0.0.5").is_ok());
        assert!(ip_charset("fd00::5").is_ok());
        assert!(ip_charset("10.0.0.0/8").is_ok());
        assert!(ip_charset("10.0.0.5;id").is_err());
        assert!(ip_charset("$(id)").is_err());
        // Original charset rule accepted the empty string vacuously; the
        // hoisted rule preserves that behavior byte-for-byte (empty is
        // rejected downstream by the remote, not by a changed rule here).
        assert!(ip_charset("").is_ok());
    }

    #[test]
    fn hoisted_wrappers_still_error_as_adapter_protocol_failures() {
        assert!(validate_ip_arg("10.0.0.5;id").is_err());
        assert!(validate_ip_arg("10.0.0.5").is_ok());
        assert!(validate_utun_name("utunABC").is_err());
        assert!(validate_utun_name("utun9").is_ok());
        assert!(validate_windows_path("bad\0path").is_err());
        assert!(validate_windows_path("C:\\ok").is_ok());
    }

    #[test]
    fn validated_arg_constructors_reject_before_a_value_is_stored() {
        assert!(ValidatedArg::ip("10.0.0.5;id").is_err());
        assert!(ValidatedArg::node_id("no;node").is_err());
        assert!(ValidatedArg::path("relative/path").is_err());
        assert!(ValidatedArg::service("bad name").is_err());
        assert!(ValidatedArg::cidr("10.0.0.0/33").is_err());
        assert!(ValidatedArg::utun("utunX").is_err());
        assert!(ValidatedArg::connection_user("-bad").is_err());
        assert!(ValidatedArg::interface_name("bad;name").is_err());
        assert!(ValidatedArg::bundle_filename("a/b").is_err());
        assert!(ValidatedArg::port("99999").is_err());
        assert!(ValidatedArg::port("4242").is_ok());
    }
}
