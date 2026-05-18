#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

const PUBLIC_KEY_KEYS: [&str; 4] = [
    "assignment_verifier_key_b64",
    "traversal_verifier_key_b64",
    "dns_zone_verifier_key_b64",
    "trust_evidence_verifier_key_b64",
];
const FORBIDDEN_KEY_NAME_TOKENS: [&str; 4] =
    ["private_key", "signing_secret", "passphrase", "secret"];
const FORBIDDEN_STRING_TOKENS: [&str; 3] = [
    "BEGIN PRIVATE KEY",
    "PRIVATE KEY-----",
    "OPENSSH PRIVATE KEY",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateNetworkDiscoveryBundleConfig {
    pub bundles: Vec<PathBuf>,
    pub max_age_seconds: u64,
    pub require_verifier_keys: bool,
    pub require_daemon_active: bool,
    pub require_socket_present: bool,
    pub output: Option<PathBuf>,
}

struct ValidationConfig {
    max_age_seconds: u64,
    require_verifier_keys: bool,
    require_daemon_active: bool,
    require_socket_present: bool,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn resolve_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    Ok(cwd.join(path))
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    const TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut reverse = BTreeMap::new();
    for (index, ch) in TABLE.chars().enumerate() {
        reverse.insert(ch, index as u8);
    }
    let clean = value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if clean.is_empty() || clean.len() % 4 != 0 {
        return Err("invalid base64".to_string());
    }
    let mut output = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let mut sextets = [0u8; 4];
        let mut padding = 0usize;
        for (index, ch) in chunk.iter().enumerate() {
            if *ch == '=' {
                sextets[index] = 0;
                padding += 1;
            } else if let Some(value) = reverse.get(ch) {
                sextets[index] = *value;
            } else {
                return Err("invalid base64".to_string());
            }
        }
        let b0 = (sextets[0] << 2) | (sextets[1] >> 4);
        let b1 = ((sextets[1] & 0x0f) << 4) | (sextets[2] >> 2);
        let b2 = ((sextets[2] & 0x03) << 6) | sextets[3];
        output.push(b0);
        if padding < 2 {
            output.push(b1);
        }
        if padding < 1 {
            output.push(b2);
        }
    }
    Ok(output)
}

fn decode_b64_32(value: &str) -> bool {
    match decode_base64(value) {
        Ok(decoded) => decoded.len() == 32,
        Err(_) => false,
    }
}

fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_host_like(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn validate_host_endpoint(endpoint: &str) -> bool {
    let Some((host, raw_port)) = endpoint.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || raw_port.is_empty() || !raw_port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(port) = raw_port.parse::<u16>() else {
        return false;
    };
    if port == 0 {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    valid_host_like(host)
}

fn validate_absolute_path(raw: Option<&Value>) -> bool {
    matches!(raw, Some(Value::String(value)) if value.starts_with('/'))
}

fn validate_no_secrets(payload: &Value, problems: &mut Vec<String>, path: &str) {
    match payload {
        Value::Object(object) => {
            for (key, value) in object {
                let lowered = key.to_ascii_lowercase();
                if FORBIDDEN_KEY_NAME_TOKENS
                    .iter()
                    .any(|token| lowered.contains(token))
                {
                    problems.push(format!("{path}.{key}: forbidden secret-like key name"));
                }
                validate_no_secrets(value, problems, format!("{path}.{key}").as_str());
            }
        }
        Value::Array(array) => {
            for (index, item) in array.iter().enumerate() {
                validate_no_secrets(item, problems, format!("{path}[{index}]").as_str());
            }
        }
        Value::String(value) => {
            for token in FORBIDDEN_STRING_TOKENS {
                if value.contains(token) {
                    problems.push(format!(
                        "{path}: contains forbidden secret-like token {token:?}"
                    ));
                }
            }
        }
        _ => {}
    }
}

/// X2: Phase A typed view for the top-level shape of a network
/// discovery bundle. The reviewed contract pins three fields with
/// serde required-field semantics:
///
/// - `schema_version: u64` — must deserialize as an unsigned integer;
///   the downstream check still enforces the value (`== 1`).
/// - `purpose: String` — must deserialize as a string; the downstream
///   check still enforces the value
///   (`"cross_network_discovery_bundle"`).
/// - `collected_at_unix: u64` — must deserialize as an unsigned
///   integer; the downstream check still enforces positivity and
///   freshness against `config.max_age_seconds`.
///
/// Everything else flows through `#[serde(flatten)] extra:
/// Map<String, Value>` so the downstream Map-walking validation logic
/// (NAT profile, wireguard, endpoint candidates, etc.) keeps working
/// unchanged. `into_value_map` re-injects the typed fields so the
/// caller sees the full bundle shape.
///
/// `validate_no_secrets` STAYS a generic `Value` walk — it must be
/// generic to catch arbitrary nested forbidden keys/strings.
#[derive(Debug, Clone, serde::Deserialize)]
struct NetworkDiscoveryBundleView {
    schema_version: u64,
    purpose: String,
    collected_at_unix: u64,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl NetworkDiscoveryBundleView {
    /// Bridge the typed view back to a `Map<String, Value>` for
    /// downstream code that still walks the bundle generically. Adds
    /// the typed fields back into the map so callers see the full
    /// bundle shape.
    fn into_value_map(self) -> Map<String, Value> {
        let mut m = self.extra;
        m.insert(
            "schema_version".to_string(),
            Value::Number(self.schema_version.into()),
        );
        m.insert("purpose".to_string(), Value::String(self.purpose));
        m.insert(
            "collected_at_unix".to_string(),
            Value::Number(self.collected_at_unix.into()),
        );
        m
    }
}

/// X2: typed view over the `node_identity` sub-block. 5 typed
/// `Option<String>` slots match every `.get("...")` call the
/// validator makes; `extra` flatten preserves any future fields.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct NodeIdentityView {
    pub node_id: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub arch: Option<String>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// X2: typed view over the `wireguard` sub-block. 4 typed slots —
/// 3 strings + `listen_port: Option<u64>`. Wrong-type slots fail
/// at the typed deserialize instead of slipping past the silent
/// `.and_then(Value::as_*)` walks.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct WireguardView {
    pub interface: Option<String>,
    pub public_key: Option<String>,
    pub listen_port: Option<u64>,
    pub peer_stanza_template: Option<String>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// X2: typed view over the `nat_profile` sub-block. 5 typed slots
/// — `behind_nat: Option<bool>` + 4 strings. Wrong-type slots
/// fail at deserialize.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct NatProfileView {
    pub behind_nat: Option<bool>,
    pub first_lan_ip: Option<String>,
    pub detected_public_ip: Option<String>,
    pub port_forwarded_hint: Option<String>,
    pub recommended_traversal_strategy: Option<String>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// X2: typed view over a single entry inside the
/// `endpoint_candidates` array.
///
/// * `kind` is the JSON `type` field (renamed because `type` is a
///   Rust keyword). The validator still applies the
///   `host` / `server_reflexive` / `relay` value-level check
///   downstream.
/// * `endpoint: Option<String>` lets the validator distinguish
///   absent-endpoint (`None` → "must be a string") from
///   present-empty-string (`Some("")` → fails the host:port check
///   downstream). A wrong-type slot fails at the typed deserialise.
/// * `priority: Option<i64>` was previously silent via
///   `.and_then(Value::as_i64) -> None`, conflating missing with
///   wrong-type. Typed view now distinguishes.
///
/// Per-entry deserialise (rather than `Vec<EndpointCandidateView>`)
/// preserves the legacy per-entry granular error messages —
/// `endpoint_candidates[{index}]` keeps pointing at the exact
/// offending row instead of the whole array short-circuiting.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct EndpointCandidateView {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub endpoint: Option<String>,
    pub priority: Option<i64>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// X2: typed view over a single entry inside the
/// `rustynet_artifacts` keyed map. The 4 typed slots correspond to
/// every `.get("...")` call the walker makes per artifact entry.
///
/// * `path: Option<Value>` stays `Value` because the downstream
///   `validate_absolute_path(&Option<&Value>)` helper accepts any
///   `Value` and rejects non-string/non-absolute at the helper
///   level — the same boundary used by `daemon_status.socket_path`.
/// * `exists: Option<bool>` — wrong-type slot now rejected at
///   deserialise instead of slipping past
///   `.and_then(Value::as_bool) -> None`.
/// * `size_bytes` / `mtime_unix: Option<i64>` — likewise distinguish
///   wrong-type from missing.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct RustynetArtifactEntryView {
    pub path: Option<Value>,
    pub exists: Option<bool>,
    pub size_bytes: Option<i64>,
    pub mtime_unix: Option<i64>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// X2: typed view over a single entry inside the `known_peers`
/// array. The 2 typed slots correspond to every `.get("...")` call
/// the walker makes per known-peer entry.
///
/// Per-entry deserialise (same pattern as `EndpointCandidateView`)
/// preserves the legacy `known_peers[{index}]` per-index error
/// granularity. The validator preserves the existing "must be a
/// string" vs host:port-shape error split via the
/// `view.endpoint.is_none()` check at the call site.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct KnownPeerView {
    pub public_key: Option<String>,
    pub endpoint: Option<String>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// X2: typed view over the `verifier_keys` sub-block. The 4 typed
/// slots line up 1:1 with `PUBLIC_KEY_KEYS`. Wrong-type slots
/// (e.g. an integer in any of the base64 fields) fail at the typed
/// deserialise instead of slipping past the silent
/// `.and_then(Value::as_str)` walk.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct VerifierKeysView {
    pub assignment_verifier_key_b64: Option<String>,
    pub traversal_verifier_key_b64: Option<String>,
    pub dns_zone_verifier_key_b64: Option<String>,
    pub trust_evidence_verifier_key_b64: Option<String>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl VerifierKeysView {
    /// Map a `PUBLIC_KEY_KEYS` entry to its typed slot. Returns
    /// `None` when the slot was absent on the wire (parity with the
    /// legacy `verifier_keys.get(key).and_then(Value::as_str)` walk).
    fn slot(&self, key: &str) -> Option<&str> {
        match key {
            "assignment_verifier_key_b64" => self.assignment_verifier_key_b64.as_deref(),
            "traversal_verifier_key_b64" => self.traversal_verifier_key_b64.as_deref(),
            "dns_zone_verifier_key_b64" => self.dns_zone_verifier_key_b64.as_deref(),
            "trust_evidence_verifier_key_b64" => self.trust_evidence_verifier_key_b64.as_deref(),
            _ => None,
        }
    }
}

/// X2: typed view over the `daemon_status` sub-block.
///
/// * `active: Option<String>` — the legacy walker used
///   `.unwrap_or_default()`, so a wrong-type slot silently became
///   `""` and triggered "must be one of …". Typed view rejects
///   wrong-type at deserialise.
/// * `socket_present: Option<bool>` — the legacy walker used a
///   `match` against `.and_then(Value::as_bool)`, so wrong-type
///   was silent → "must be boolean" (same as missing). Typed view
///   distinguishes.
/// * `socket_path: Option<Value>` — kept as `Value` because the
///   downstream `validate_absolute_path` helper accepts the raw
///   `Option<&Value>` to also reject non-string values cleanly.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct DaemonStatusView {
    pub active: Option<String>,
    pub socket_present: Option<bool>,
    pub socket_path: Option<Value>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Deserialise a sub-block from `object[key]` into a typed view.
/// Returns:
/// * `Ok(Some(view))` when the key is present and deserialises.
/// * `Ok(None)` when the key is missing (caller decides whether to
///   emit "must be an object" or treat as optional).
/// * `Err(msg)` when the key is present but the typed deserialise
///   fails (wrong-type slot, wrong outer shape, etc.). The error
///   string is prefixed with `key has invalid field shape:` so the
///   reviewer sees which sub-block is at fault.
fn deserialize_sub_block<T>(object: &Map<String, Value>, key: &str) -> Result<Option<T>, String>
where
    T: serde::de::DeserializeOwned,
{
    match object.get(key).cloned() {
        Some(v) => serde_json::from_value::<T>(v)
            .map(Some)
            .map_err(|err| format!("{key} has invalid field shape: {err}")),
        None => Ok(None),
    }
}

fn validate_bundle(path: &Path, payload: &Value, config: &ValidationConfig) -> Vec<String> {
    let mut problems = Vec::new();

    // Recursive secret-leak scan STAYS a generic Value walk — it must
    // be generic to catch arbitrary nested forbidden keys and strings.
    validate_no_secrets(payload, &mut problems, "$");

    // X2: Phase A typed view migration. The top-level shape now goes
    // through `NetworkDiscoveryBundleView`, which pins `schema_version`,
    // `purpose`, and `collected_at_unix` with serde required-field
    // semantics. A missing or wrong-type required field fails at
    // deserialize with a precise error rather than falling through to
    // `as_i64`/`as_str`/`as_u64` returning `None`.
    let typed: NetworkDiscoveryBundleView = match serde_json::from_value(payload.clone()) {
        Ok(view) => view,
        Err(err) => {
            problems.push(format!("bundle top-level shape invalid: {err}"));
            return problems
                .into_iter()
                .map(|problem| format!("{}: {problem}", path.display()))
                .collect();
        }
    };

    if typed.schema_version != 1 {
        problems.push("schema_version must equal 1".to_string());
    }
    if typed.purpose != "cross_network_discovery_bundle" {
        problems.push("purpose must equal 'cross_network_discovery_bundle'".to_string());
    }

    let now_unix = unix_now();
    let collected_at_unix = typed.collected_at_unix;
    if collected_at_unix == 0 {
        problems.push("collected_at_unix must be a positive integer".to_string());
    } else {
        if collected_at_unix > now_unix.saturating_add(300) {
            problems.push("collected_at_unix is too far in the future".to_string());
        }
        if now_unix.saturating_sub(collected_at_unix) > config.max_age_seconds {
            problems.push("collected_at_unix is stale".to_string());
        }
    }

    let object = typed.into_value_map();
    let object = &object;

    match deserialize_sub_block::<NodeIdentityView>(object, "node_identity") {
        Ok(Some(view)) => {
            if !matches!(view.node_id.as_deref(), Some(value) if valid_node_id(value)) {
                problems.push("node_identity.node_id must match [A-Za-z0-9._-]+".to_string());
            }
            for (field, slot) in [
                ("hostname", &view.hostname),
                ("os", &view.os),
                ("kernel", &view.kernel),
                ("arch", &view.arch),
            ] {
                let valid = slot
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_some();
                if !valid {
                    problems.push(format!("node_identity.{field} must be a non-empty string"));
                }
            }
        }
        Ok(None) => problems.push("node_identity must be an object".to_string()),
        Err(err) => problems.push(err),
    }

    match deserialize_sub_block::<WireguardView>(object, "wireguard") {
        Ok(Some(view)) => {
            let interface = view
                .interface
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some();
            if !interface {
                problems.push("wireguard.interface must be a non-empty string".to_string());
            }

            let pubkey_ok = view
                .public_key
                .as_deref()
                .map(str::trim)
                .map(decode_b64_32)
                .unwrap_or(false);
            if !pubkey_ok {
                problems
                    .push("wireguard.public_key must be valid base64 for 32-byte key".to_string());
            }

            if !matches!(view.listen_port, Some(value) if (1..=65535).contains(&value)) {
                problems.push("wireguard.listen_port must be an integer in [1, 65535]".to_string());
            }

            let stanza = view
                .peer_stanza_template
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some();
            if !stanza {
                problems
                    .push("wireguard.peer_stanza_template must be a non-empty string".to_string());
            }
        }
        Ok(None) => problems.push("wireguard must be an object".to_string()),
        Err(err) => problems.push(err),
    }

    match object.get("endpoint_candidates").and_then(Value::as_array) {
        Some(candidates) if !candidates.is_empty() => {
            let mut seen = HashSet::new();
            for (index, candidate) in candidates.iter().enumerate() {
                // X2: per-entry typed deserialise. Object-shape and
                // each typed slot are checked here; the
                // value-level checks (allowed `kind`, host:port
                // shape, duplicate detection) stay below as
                // domain-specific validation.
                let view = match serde_json::from_value::<EndpointCandidateView>(candidate.clone())
                {
                    Ok(view) => view,
                    Err(err) => {
                        let msg = err.to_string();
                        if msg.contains("expected a") && msg.contains("map") {
                            // serde error for non-object entries — preserve the
                            // legacy "must be an object" message so the existing
                            // contract reads cleanly.
                            problems
                                .push(format!("endpoint_candidates[{index}] must be an object"));
                        } else {
                            problems.push(format!(
                                "endpoint_candidates[{index}] has invalid field shape: {err}"
                            ));
                        }
                        continue;
                    }
                };
                let candidate_type = view.kind.as_deref().unwrap_or_default();
                let endpoint = view.endpoint.as_deref().unwrap_or_default();
                if !matches!(candidate_type, "host" | "server_reflexive" | "relay") {
                    problems.push(format!(
                        "endpoint_candidates[{index}].type must be host/server_reflexive/relay"
                    ));
                    continue;
                }
                if view.endpoint.is_none() {
                    problems.push(format!(
                        "endpoint_candidates[{index}].endpoint must be a string"
                    ));
                    continue;
                }
                if matches!(candidate_type, "host" | "server_reflexive") {
                    if endpoint.is_empty() || !validate_host_endpoint(endpoint) {
                        problems.push(format!(
                            "endpoint_candidates[{index}].endpoint must be host:port for {candidate_type}"
                        ));
                    }
                } else if !endpoint.is_empty() && !validate_host_endpoint(endpoint) {
                    problems.push(format!(
                        "endpoint_candidates[{index}].endpoint must be empty or host:port for relay"
                    ));
                }
                if view.priority.is_none() {
                    problems.push(format!(
                        "endpoint_candidates[{index}].priority must be an integer"
                    ));
                }
                let candidate_key = (candidate_type.to_string(), endpoint.to_string());
                if seen.contains(&candidate_key) {
                    problems.push(format!(
                        "endpoint_candidates[{index}] duplicates candidate type/endpoint pair"
                    ));
                }
                seen.insert(candidate_key);
            }
        }
        _ => problems.push("endpoint_candidates must be a non-empty list".to_string()),
    }

    match deserialize_sub_block::<NatProfileView>(object, "nat_profile") {
        Ok(Some(view)) => {
            if view.behind_nat.is_none() {
                problems.push("nat_profile.behind_nat must be boolean".to_string());
            }
            for (field, slot) in [
                ("first_lan_ip", &view.first_lan_ip),
                ("detected_public_ip", &view.detected_public_ip),
                ("port_forwarded_hint", &view.port_forwarded_hint),
                (
                    "recommended_traversal_strategy",
                    &view.recommended_traversal_strategy,
                ),
            ] {
                if slot.is_none() {
                    problems.push(format!("nat_profile.{field} must be a string"));
                }
            }
        }
        Ok(None) => problems.push("nat_profile must be an object".to_string()),
        Err(err) => problems.push(err),
    }

    match deserialize_sub_block::<VerifierKeysView>(object, "verifier_keys") {
        Ok(Some(view)) => {
            for key in PUBLIC_KEY_KEYS {
                let Some(value) = view.slot(key) else {
                    problems.push(format!("verifier_keys.{key} must be a string"));
                    continue;
                };
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    if config.require_verifier_keys {
                        problems.push(format!(
                            "verifier_keys.{key} must be non-empty in strict mode"
                        ));
                    }
                    continue;
                }
                if !decode_b64_32(trimmed) {
                    problems.push(format!("verifier_keys.{key} must decode to 32 bytes"));
                }
            }
        }
        Ok(None) => problems.push("verifier_keys must be an object".to_string()),
        Err(err) => problems.push(err),
    }

    match object.get("rustynet_artifacts").and_then(Value::as_object) {
        Some(rustynet_artifacts) => {
            for name in [
                "assignment_bundle",
                "traversal_bundle",
                "membership_snapshot",
                "membership_log",
                "dns_zone_bundle",
                "trust_evidence",
            ] {
                let Some(raw_entry) = rustynet_artifacts.get(name) else {
                    problems.push(format!("rustynet_artifacts.{name} must be an object"));
                    continue;
                };
                let view =
                    match serde_json::from_value::<RustynetArtifactEntryView>(raw_entry.clone()) {
                        Ok(view) => view,
                        Err(err) => {
                            let msg = err.to_string();
                            if msg.contains("expected a") && msg.contains("map") {
                                problems
                                    .push(format!("rustynet_artifacts.{name} must be an object"));
                            } else {
                                problems.push(format!(
                                    "rustynet_artifacts.{name} has invalid field shape: {err}"
                                ));
                            }
                            continue;
                        }
                    };
                if !validate_absolute_path(view.path.as_ref()) {
                    problems.push(format!("rustynet_artifacts.{name}.path must be absolute"));
                }
                let exists = view.exists;
                if exists.is_none() {
                    problems.push(format!("rustynet_artifacts.{name}.exists must be boolean"));
                    continue;
                }
                let size = view.size_bytes;
                let mtime = view.mtime_unix;
                if !matches!(size, Some(value) if value >= 0) {
                    problems.push(format!("rustynet_artifacts.{name}.size_bytes must be >= 0"));
                }
                if !matches!(mtime, Some(value) if value >= 0) {
                    problems.push(format!("rustynet_artifacts.{name}.mtime_unix must be >= 0"));
                }
                if exists == Some(true) {
                    if !matches!(size, Some(value) if value > 0) {
                        problems.push(format!(
                            "rustynet_artifacts.{name}.size_bytes must be > 0 when exists=true"
                        ));
                    }
                    if !matches!(mtime, Some(value) if value > 0) {
                        problems.push(format!(
                            "rustynet_artifacts.{name}.mtime_unix must be > 0 when exists=true"
                        ));
                    }
                }
            }
        }
        None => problems.push("rustynet_artifacts must be an object".to_string()),
    }

    match deserialize_sub_block::<DaemonStatusView>(object, "daemon_status") {
        Ok(Some(view)) => {
            let active = view.active.as_deref().unwrap_or_default();
            if !matches!(active, "active" | "inactive" | "socket_present" | "unknown") {
                problems.push(
                    "daemon_status.active must be one of active/inactive/socket_present/unknown"
                        .to_string(),
                );
            }
            if config.require_daemon_active && !matches!(active, "active" | "socket_present") {
                problems.push("daemon_status.active must indicate active runtime".to_string());
            }
            match view.socket_present {
                Some(socket_present) => {
                    if config.require_socket_present && !socket_present {
                        problems.push(
                            "daemon_status.socket_present must be true in strict mode".to_string(),
                        );
                    }
                }
                None => problems.push("daemon_status.socket_present must be boolean".to_string()),
            }
            if !validate_absolute_path(view.socket_path.as_ref()) {
                problems.push("daemon_status.socket_path must be absolute".to_string());
            }
        }
        Ok(None) => problems.push("daemon_status must be an object".to_string()),
        Err(err) => problems.push(err),
    }

    match object.get("known_peers").and_then(Value::as_array) {
        Some(known_peers) => {
            for (index, peer) in known_peers.iter().enumerate() {
                let view = match serde_json::from_value::<KnownPeerView>(peer.clone()) {
                    Ok(view) => view,
                    Err(err) => {
                        let msg = err.to_string();
                        if msg.contains("expected a") && msg.contains("map") {
                            problems.push(format!("known_peers[{index}] must be an object"));
                        } else {
                            problems.push(format!(
                                "known_peers[{index}] has invalid field shape: {err}"
                            ));
                        }
                        continue;
                    }
                };
                let pubkey_ok = view
                    .public_key
                    .as_deref()
                    .map(str::trim)
                    .map(decode_b64_32)
                    .unwrap_or(false);
                if !pubkey_ok {
                    problems.push(format!(
                        "known_peers[{index}].public_key must decode to 32 bytes"
                    ));
                }
                let endpoint = view.endpoint.as_deref().unwrap_or_default();
                if view.endpoint.is_none() {
                    problems.push(format!("known_peers[{index}].endpoint must be a string"));
                } else if !endpoint.is_empty() && !validate_host_endpoint(endpoint) {
                    problems.push(format!("known_peers[{index}].endpoint must be host:port"));
                }
            }
        }
        None => problems.push("known_peers must be a list".to_string()),
    }

    match object
        .get("remote_network_checklist")
        .and_then(Value::as_array)
    {
        Some(checklist) if !checklist.is_empty() => {
            for (index, item) in checklist.iter().enumerate() {
                let valid = item
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_some();
                if !valid {
                    problems.push(format!(
                        "remote_network_checklist[{index}] must be a non-empty string"
                    ));
                }
            }
        }
        _ => problems.push("remote_network_checklist must be a non-empty list".to_string()),
    }

    problems
        .into_iter()
        .map(|problem| format!("{}: {problem}", path.display()))
        .collect()
}

fn render_markdown(results: &[(PathBuf, Vec<String>)]) -> String {
    let mut lines = vec![
        "# Network Discovery Bundle Validation".to_string(),
        String::new(),
    ];
    for (bundle_path, errors) in results {
        lines.push(format!("## `{}`", bundle_path.display()));
        lines.push(String::new());
        if errors.is_empty() {
            lines.push("- Validation passed.".to_string());
        } else {
            for error in errors {
                lines.push(format!("- {error}"));
            }
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

fn write_markdown(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create output parent directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    fs::write(path, body).map_err(|err| format!("write output failed ({}): {err}", path.display()))
}

pub fn execute_ops_validate_network_discovery_bundle(
    config: ValidateNetworkDiscoveryBundleConfig,
) -> Result<String, String> {
    if config.max_age_seconds == 0 {
        return Err("--max-age-seconds must be > 0".to_string());
    }
    if config.bundles.is_empty() {
        return Err("at least one bundle path is required (--bundle or --bundles)".to_string());
    }

    let validation_config = ValidationConfig {
        max_age_seconds: config.max_age_seconds,
        require_verifier_keys: config.require_verifier_keys,
        require_daemon_active: config.require_daemon_active,
        require_socket_present: config.require_socket_present,
    };

    let mut results = Vec::new();
    let mut overall_errors = Vec::new();
    for bundle in &config.bundles {
        let bundle_path = resolve_path(bundle)?;
        if !bundle_path.is_file() {
            let errors = vec![format!(
                "{}: bundle file does not exist",
                bundle_path.display()
            )];
            overall_errors.extend(errors.iter().cloned());
            results.push((bundle_path, errors));
            continue;
        }
        let body = fs::read_to_string(&bundle_path)
            .map_err(|err| format!("{}: read bundle failed: {err}", bundle_path.display()))?;
        let payload: Value = match serde_json::from_str(&body) {
            Ok(payload) => payload,
            Err(err) => {
                let errors = vec![format!("{}: invalid JSON ({err})", bundle_path.display())];
                overall_errors.extend(errors.iter().cloned());
                results.push((bundle_path, errors));
                continue;
            }
        };
        let errors = validate_bundle(&bundle_path, &payload, &validation_config);
        overall_errors.extend(errors.iter().cloned());
        results.push((bundle_path, errors));
    }

    if let Some(output) = config.output {
        let output_path = resolve_path(&output)?;
        write_markdown(output_path.as_path(), render_markdown(&results).as_str())?;
    }

    if overall_errors.is_empty() {
        Ok("network discovery bundle validation passed".to_string())
    } else {
        Err(overall_errors.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DaemonStatusView, EndpointCandidateView, KnownPeerView, NatProfileView,
        NetworkDiscoveryBundleView, NodeIdentityView, RustynetArtifactEntryView, VerifierKeysView,
        WireguardView, deserialize_sub_block,
    };
    use serde_json::{Map, Value, json};

    /// Clean fixture: a well-formed top-level shape deserializes into
    /// the typed view, the typed fields land in their slots, and the
    /// remaining keys ride through `#[serde(flatten)] extra`.
    #[test]
    fn network_discovery_bundle_view_accepts_clean_top_level() {
        let payload = json!({
            "schema_version": 1,
            "purpose": "cross_network_discovery_bundle",
            "collected_at_unix": 1_700_000_000u64,
            "node_identity": { "node_id": "node-a" },
            "extra_field": "ride-through",
        });
        let view: NetworkDiscoveryBundleView =
            serde_json::from_value(payload).expect("typed view accepts clean top-level shape");
        assert_eq!(view.schema_version, 1);
        assert_eq!(view.purpose, "cross_network_discovery_bundle");
        assert_eq!(view.collected_at_unix, 1_700_000_000);
        assert!(view.extra.contains_key("node_identity"));
        assert_eq!(
            view.extra.get("extra_field").and_then(Value::as_str),
            Some("ride-through")
        );
    }

    /// Missing required field rejected with a precise error naming the
    /// field. The serde error message must mention `purpose` so the
    /// failure points to the source field.
    #[test]
    fn network_discovery_bundle_view_rejects_missing_required_field() {
        let payload = json!({
            "schema_version": 1,
            "collected_at_unix": 1_700_000_000u64,
        });
        let err = serde_json::from_value::<NetworkDiscoveryBundleView>(payload)
            .expect_err("missing purpose must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("purpose"),
            "error must name the missing required field: {message}"
        );
    }

    /// Wrong-type required field rejected at deserialize.
    /// `schema_version` is typed `u64`; supplying a string must fail
    /// at parse, not later via `as_u64()` returning `None`.
    #[test]
    fn network_discovery_bundle_view_rejects_wrong_type_required_field() {
        let payload = json!({
            "schema_version": "one",
            "purpose": "cross_network_discovery_bundle",
            "collected_at_unix": 1_700_000_000u64,
        });
        let err = serde_json::from_value::<NetworkDiscoveryBundleView>(payload)
            .expect_err("string schema_version must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("schema_version") || message.contains("u64"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// `into_value_map` round-trips: typed fields are re-injected and
    /// flattened extras are preserved verbatim.
    #[test]
    fn network_discovery_bundle_view_into_value_map_round_trips() {
        let payload = json!({
            "schema_version": 1,
            "purpose": "cross_network_discovery_bundle",
            "collected_at_unix": 1_700_000_000u64,
            "node_identity": { "node_id": "node-a" },
            "extra_field": "ride-through",
        });
        let view: NetworkDiscoveryBundleView =
            serde_json::from_value(payload).expect("typed view parses");
        let map = view.into_value_map();
        assert_eq!(
            map.get("schema_version").and_then(Value::as_u64),
            Some(1),
            "schema_version must round-trip"
        );
        assert_eq!(
            map.get("purpose").and_then(Value::as_str),
            Some("cross_network_discovery_bundle"),
            "purpose must round-trip"
        );
        assert_eq!(
            map.get("collected_at_unix").and_then(Value::as_u64),
            Some(1_700_000_000),
            "collected_at_unix must round-trip"
        );
        assert!(
            map.contains_key("node_identity"),
            "flattened extras must be preserved"
        );
        assert_eq!(
            map.get("extra_field").and_then(Value::as_str),
            Some("ride-through"),
            "scalar extras must be preserved"
        );
    }

    // ---- X2: sub-block typed views (node_identity / wireguard /
    // nat_profile) --------------------------------------------------

    /// Clean fixture: `NodeIdentityView` accepts a well-formed
    /// sub-block; every typed slot populates; extra fields ride
    /// through.
    #[test]
    fn node_identity_view_accepts_clean_block() {
        let block = json!({
            "node_id": "node-a",
            "hostname": "host",
            "os": "linux",
            "kernel": "6.5",
            "arch": "x86_64",
            "extra": "ride",
        });
        let view: NodeIdentityView = serde_json::from_value(block).expect("clean parse");
        assert_eq!(view.node_id.as_deref(), Some("node-a"));
        assert_eq!(view.hostname.as_deref(), Some("host"));
        assert_eq!(view.os.as_deref(), Some("linux"));
        assert_eq!(view.kernel.as_deref(), Some("6.5"));
        assert_eq!(view.arch.as_deref(), Some("x86_64"));
        assert_eq!(
            view.extra.get("extra").and_then(Value::as_str),
            Some("ride")
        );
    }

    /// Wrong-type `node_id` slot rejected at deserialize. Was
    /// previously silent via `.and_then(Value::as_str)`.
    #[test]
    fn node_identity_view_rejects_wrong_type_slot() {
        let block = json!({ "node_id": 42 });
        let err = serde_json::from_value::<NodeIdentityView>(block)
            .expect_err("integer node_id must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("node_id") || message.contains("string"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Clean fixture: `WireguardView` populates all 4 typed slots;
    /// `listen_port: u64` accepts a positive integer.
    #[test]
    fn wireguard_view_accepts_clean_block() {
        let block = json!({
            "interface": "wg0",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "listen_port": 51820u64,
            "peer_stanza_template": "[Peer]",
        });
        let view: WireguardView = serde_json::from_value(block).expect("clean parse");
        assert_eq!(view.interface.as_deref(), Some("wg0"));
        assert_eq!(view.listen_port, Some(51820));
        assert_eq!(view.peer_stanza_template.as_deref(), Some("[Peer]"));
    }

    /// Wrong-type `listen_port` slot rejected. Previously silent
    /// via `.and_then(Value::as_u64) -> None`.
    #[test]
    fn wireguard_view_rejects_wrong_type_listen_port() {
        let block = json!({ "listen_port": "51820" });
        let err = serde_json::from_value::<WireguardView>(block)
            .expect_err("string listen_port must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("listen_port") || message.contains("u64"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Clean fixture: `NatProfileView` populates `behind_nat: bool`
    /// plus 4 string slots.
    #[test]
    fn nat_profile_view_accepts_clean_block() {
        let block = json!({
            "behind_nat": true,
            "first_lan_ip": "192.168.1.10",
            "detected_public_ip": "203.0.113.5",
            "port_forwarded_hint": "none",
            "recommended_traversal_strategy": "direct_first",
        });
        let view: NatProfileView = serde_json::from_value(block).expect("clean parse");
        assert_eq!(view.behind_nat, Some(true));
        assert_eq!(view.first_lan_ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(view.detected_public_ip.as_deref(), Some("203.0.113.5"));
    }

    /// Wrong-type `behind_nat` slot rejected. Previously silent via
    /// `.and_then(Value::as_bool) -> None`.
    #[test]
    fn nat_profile_view_rejects_wrong_type_behind_nat() {
        let block = json!({ "behind_nat": "yes" });
        let err = serde_json::from_value::<NatProfileView>(block)
            .expect_err("string behind_nat must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("behind_nat") || message.contains("bool"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// `deserialize_sub_block` distinguishes missing (Ok(None)) from
    /// wrong-type-top (Err) from valid (Ok(Some(view))). Each
    /// branch produces the correct validator-facing message.
    #[test]
    fn deserialize_sub_block_distinguishes_missing_wrong_type_and_present() {
        let mut object = Map::new();
        let missing: Result<Option<NatProfileView>, String> =
            deserialize_sub_block(&object, "nat_profile");
        assert!(matches!(missing, Ok(None)));

        object.insert("nat_profile".to_string(), Value::String("oops".to_string()));
        let wrong: Result<Option<NatProfileView>, String> =
            deserialize_sub_block(&object, "nat_profile");
        let err = wrong.expect_err("string sub-block must surface invalid field shape");
        assert!(
            err.contains("nat_profile has invalid field shape"),
            "error must prefix with sub-block key: {err}"
        );

        object.insert("nat_profile".to_string(), json!({ "behind_nat": false }));
        let present: Result<Option<NatProfileView>, String> =
            deserialize_sub_block(&object, "nat_profile");
        let view = present
            .expect("valid sub-block must succeed")
            .expect("Ok(None) only for missing");
        assert_eq!(view.behind_nat, Some(false));
    }

    /// Clean fixture: `VerifierKeysView` accepts the 4
    /// `PUBLIC_KEY_KEYS` slots; every typed slot populates and the
    /// `slot()` helper resolves each key correctly. The lookup
    /// helper is the bridge between the legacy
    /// `PUBLIC_KEY_KEYS.iter().for_each(|key| ...)` loop and the
    /// typed fields.
    #[test]
    fn verifier_keys_view_accepts_clean_block_and_slot_resolves() {
        let block = json!({
            "assignment_verifier_key_b64": "AAA",
            "traversal_verifier_key_b64": "BBB",
            "dns_zone_verifier_key_b64": "CCC",
            "trust_evidence_verifier_key_b64": "DDD",
        });
        let view: VerifierKeysView = serde_json::from_value(block).expect("clean parse");
        assert_eq!(view.slot("assignment_verifier_key_b64"), Some("AAA"));
        assert_eq!(view.slot("traversal_verifier_key_b64"), Some("BBB"));
        assert_eq!(view.slot("dns_zone_verifier_key_b64"), Some("CCC"));
        assert_eq!(view.slot("trust_evidence_verifier_key_b64"), Some("DDD"));
        assert!(
            view.slot("unknown_key").is_none(),
            "unknown keys must return None"
        );
    }

    /// Wrong-type slot inside `verifier_keys` rejected at deserialise.
    /// Previously silent via `.and_then(Value::as_str) -> None`,
    /// surfacing as "must be a string" (same as missing). Typed view
    /// distinguishes them.
    #[test]
    fn verifier_keys_view_rejects_wrong_type_slot() {
        let block = json!({ "assignment_verifier_key_b64": 42 });
        let err = serde_json::from_value::<VerifierKeysView>(block)
            .expect_err("integer slot must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("assignment_verifier_key_b64") || message.contains("string"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Clean fixture: `DaemonStatusView` populates `active` string,
    /// `socket_present` bool, and `socket_path` as the raw Value
    /// (so the existing `validate_absolute_path(&Option<&Value>)`
    /// helper keeps working unchanged).
    #[test]
    fn daemon_status_view_accepts_clean_block() {
        let block = json!({
            "active": "active",
            "socket_present": true,
            "socket_path": "/var/run/rustynetd.sock",
        });
        let view: DaemonStatusView = serde_json::from_value(block).expect("clean parse");
        assert_eq!(view.active.as_deref(), Some("active"));
        assert_eq!(view.socket_present, Some(true));
        assert!(matches!(view.socket_path, Some(Value::String(_))));
    }

    /// Wrong-type `socket_present` slot rejected. Previously silent
    /// via `.and_then(Value::as_bool) -> None`, surfacing as
    /// "must be boolean" (same as missing). Typed view distinguishes
    /// the shape error.
    #[test]
    fn daemon_status_view_rejects_wrong_type_socket_present() {
        let block = json!({ "socket_present": "true" });
        let err = serde_json::from_value::<DaemonStatusView>(block)
            .expect_err("string socket_present must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("socket_present") || message.contains("bool"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Clean fixture: `EndpointCandidateView` accepts a well-formed
    /// per-entry payload. The JSON `type` key renames to `kind` via
    /// `#[serde(rename = "type")]` because `type` is a Rust keyword.
    #[test]
    fn endpoint_candidate_view_accepts_clean_entry() {
        let entry = json!({
            "type": "host",
            "endpoint": "192.0.2.10:51820",
            "priority": 100,
            "extra": "ride",
        });
        let view: EndpointCandidateView = serde_json::from_value(entry).expect("clean parse");
        assert_eq!(view.kind.as_deref(), Some("host"));
        assert_eq!(view.endpoint.as_deref(), Some("192.0.2.10:51820"));
        assert_eq!(view.priority, Some(100));
        assert_eq!(
            view.extra.get("extra").and_then(Value::as_str),
            Some("ride")
        );
    }

    /// Wrong-type `priority` slot rejected at the typed layer.
    /// Previously silent via `.and_then(Value::as_i64) -> None`,
    /// surfacing as "must be an integer" (same as missing). Typed
    /// view now distinguishes them.
    #[test]
    fn endpoint_candidate_view_rejects_wrong_type_priority() {
        let entry = json!({
            "type": "host",
            "endpoint": "192.0.2.10:51820",
            "priority": "high",
        });
        let err = serde_json::from_value::<EndpointCandidateView>(entry)
            .expect_err("string priority must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("priority") || message.contains("i64") || message.contains("integer"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Wrong-type `type` slot rejected. Previously the silent
    /// `.unwrap_or_default()` returned empty string, surfacing as
    /// "type must be host/server_reflexive/relay" — conflated with
    /// missing or wrong-type. Typed view catches wrong-type first.
    #[test]
    fn endpoint_candidate_view_rejects_wrong_type_kind() {
        let entry = json!({ "type": 42 });
        let err = serde_json::from_value::<EndpointCandidateView>(entry)
            .expect_err("integer type must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("type") || message.contains("string"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Missing optional slots deserialise to `None`. The validator
    /// keeps emitting the legacy per-field errors (e.g.
    /// "endpoint_candidates[i].endpoint must be a string") via the
    /// downstream check on `view.endpoint.is_none()`.
    #[test]
    fn endpoint_candidate_view_accepts_missing_optional_slots() {
        let entry = json!({ "type": "host" });
        let view: EndpointCandidateView =
            serde_json::from_value(entry).expect("typed view tolerates missing slots");
        assert_eq!(view.kind.as_deref(), Some("host"));
        assert!(view.endpoint.is_none());
        assert!(view.priority.is_none());
    }

    /// Clean fixture: `RustynetArtifactEntryView` populates the 4
    /// typed slots from a well-formed artifact entry.
    #[test]
    fn rustynet_artifact_entry_view_accepts_clean_entry() {
        let entry = json!({
            "path": "/var/lib/rustynet/assignment.json",
            "exists": true,
            "size_bytes": 4096,
            "mtime_unix": 1_700_000_000,
        });
        let view: RustynetArtifactEntryView = serde_json::from_value(entry).expect("clean parse");
        assert!(matches!(view.path, Some(Value::String(_))));
        assert_eq!(view.exists, Some(true));
        assert_eq!(view.size_bytes, Some(4096));
        assert_eq!(view.mtime_unix, Some(1_700_000_000));
    }

    /// Wrong-type `exists` slot rejected at the typed layer.
    /// Previously silent via `.and_then(Value::as_bool) -> None`,
    /// surfacing as "must be boolean" (same as missing). Typed view
    /// distinguishes the shape error.
    #[test]
    fn rustynet_artifact_entry_view_rejects_wrong_type_exists() {
        let entry = json!({ "exists": "true" });
        let err = serde_json::from_value::<RustynetArtifactEntryView>(entry)
            .expect_err("string exists must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("exists") || message.contains("bool"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Wrong-type `size_bytes` slot rejected. Previously silent
    /// via `.and_then(Value::as_i64) -> None`, surfacing as
    /// "must be >= 0" (same as missing or negative).
    #[test]
    fn rustynet_artifact_entry_view_rejects_wrong_type_size_bytes() {
        let entry = json!({ "size_bytes": "4096" });
        let err = serde_json::from_value::<RustynetArtifactEntryView>(entry)
            .expect_err("string size_bytes must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("size_bytes")
                || message.contains("i64")
                || message.contains("integer"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Clean fixture: `KnownPeerView` populates the 2 typed slots.
    /// Per-entry deserialise preserves per-index error granularity.
    #[test]
    fn known_peer_view_accepts_clean_entry() {
        let entry = json!({
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "endpoint": "192.0.2.10:51820",
            "extra": "ride",
        });
        let view: KnownPeerView = serde_json::from_value(entry).expect("clean parse");
        assert!(view.public_key.is_some());
        assert_eq!(view.endpoint.as_deref(), Some("192.0.2.10:51820"));
        assert_eq!(
            view.extra.get("extra").and_then(Value::as_str),
            Some("ride")
        );
    }

    /// Wrong-type `public_key` slot rejected. Previously silent via
    /// `.and_then(Value::as_str) -> None`, surfacing as "must decode
    /// to 32 bytes" — conflating wrong-type with empty / malformed
    /// base64.
    #[test]
    fn known_peer_view_rejects_wrong_type_public_key() {
        let entry = json!({ "public_key": 42 });
        let err = serde_json::from_value::<KnownPeerView>(entry)
            .expect_err("integer public_key must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("public_key") || message.contains("string"),
            "error must point to the offending field or type: {message}"
        );
    }
}
