#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

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

fn validate_bundle(path: &Path, payload: &Value, config: &ValidationConfig) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(object) = payload.as_object() else {
        return vec![format!("{}: payload must be a JSON object", path.display())];
    };

    validate_no_secrets(payload, &mut problems, "$");

    if object.get("schema_version").and_then(Value::as_i64) != Some(1) {
        problems.push("schema_version must equal 1".to_string());
    }
    if object.get("purpose").and_then(Value::as_str) != Some("cross_network_discovery_bundle") {
        problems.push("purpose must equal 'cross_network_discovery_bundle'".to_string());
    }

    let now_unix = unix_now();
    match object.get("collected_at_unix").and_then(Value::as_u64) {
        Some(collected_at_unix) if collected_at_unix > 0 => {
            if collected_at_unix > now_unix.saturating_add(300) {
                problems.push("collected_at_unix is too far in the future".to_string());
            }
            if now_unix.saturating_sub(collected_at_unix) > config.max_age_seconds {
                problems.push("collected_at_unix is stale".to_string());
            }
        }
        _ => problems.push("collected_at_unix must be a positive integer".to_string()),
    }

    match object.get("node_identity").and_then(Value::as_object) {
        Some(node_identity) => {
            let node_id = node_identity.get("node_id").and_then(Value::as_str);
            if !matches!(node_id, Some(value) if valid_node_id(value)) {
                problems.push("node_identity.node_id must match [A-Za-z0-9._-]+".to_string());
            }
            for field in ["hostname", "os", "kernel", "arch"] {
                let valid = node_identity
                    .get(field)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_some();
                if !valid {
                    problems.push(format!("node_identity.{field} must be a non-empty string"));
                }
            }
        }
        None => problems.push("node_identity must be an object".to_string()),
    }

    match object.get("wireguard").and_then(Value::as_object) {
        Some(wireguard) => {
            let interface = wireguard
                .get("interface")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some();
            if !interface {
                problems.push("wireguard.interface must be a non-empty string".to_string());
            }

            let pubkey_ok = wireguard
                .get("public_key")
                .and_then(Value::as_str)
                .map(str::trim)
                .map(decode_b64_32)
                .unwrap_or(false);
            if !pubkey_ok {
                problems
                    .push("wireguard.public_key must be valid base64 for 32-byte key".to_string());
            }

            let listen_port = wireguard.get("listen_port").and_then(Value::as_u64);
            if !matches!(listen_port, Some(value) if (1..=65535).contains(&value)) {
                problems.push("wireguard.listen_port must be an integer in [1, 65535]".to_string());
            }

            let stanza = wireguard
                .get("peer_stanza_template")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some();
            if !stanza {
                problems
                    .push("wireguard.peer_stanza_template must be a non-empty string".to_string());
            }
        }
        None => problems.push("wireguard must be an object".to_string()),
    }

    match object.get("endpoint_candidates").and_then(Value::as_array) {
        Some(candidates) if !candidates.is_empty() => {
            let mut seen = HashSet::new();
            for (index, candidate) in candidates.iter().enumerate() {
                let Some(candidate_object) = candidate.as_object() else {
                    problems.push(format!("endpoint_candidates[{index}] must be an object"));
                    continue;
                };
                let candidate_type = candidate_object
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let endpoint = candidate_object
                    .get("endpoint")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !matches!(candidate_type, "host" | "server_reflexive" | "relay") {
                    problems.push(format!(
                        "endpoint_candidates[{index}].type must be host/server_reflexive/relay"
                    ));
                    continue;
                }
                if candidate_object
                    .get("endpoint")
                    .and_then(Value::as_str)
                    .is_none()
                {
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
                if candidate_object
                    .get("priority")
                    .and_then(Value::as_i64)
                    .is_none()
                {
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

    match object.get("nat_profile").and_then(Value::as_object) {
        Some(nat_profile) => {
            if nat_profile
                .get("behind_nat")
                .and_then(Value::as_bool)
                .is_none()
            {
                problems.push("nat_profile.behind_nat must be boolean".to_string());
            }
            for field in [
                "first_lan_ip",
                "detected_public_ip",
                "port_forwarded_hint",
                "recommended_traversal_strategy",
            ] {
                if nat_profile.get(field).and_then(Value::as_str).is_none() {
                    problems.push(format!("nat_profile.{field} must be a string"));
                }
            }
        }
        None => problems.push("nat_profile must be an object".to_string()),
    }

    match object.get("verifier_keys").and_then(Value::as_object) {
        Some(verifier_keys) => {
            for key in PUBLIC_KEY_KEYS {
                let Some(value) = verifier_keys.get(key).and_then(Value::as_str) else {
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
        None => problems.push("verifier_keys must be an object".to_string()),
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
                let Some(entry) = rustynet_artifacts.get(name).and_then(Value::as_object) else {
                    problems.push(format!("rustynet_artifacts.{name} must be an object"));
                    continue;
                };
                if !validate_absolute_path(entry.get("path")) {
                    problems.push(format!("rustynet_artifacts.{name}.path must be absolute"));
                }
                let exists = entry.get("exists").and_then(Value::as_bool);
                if exists.is_none() {
                    problems.push(format!("rustynet_artifacts.{name}.exists must be boolean"));
                    continue;
                }
                let size = entry.get("size_bytes").and_then(Value::as_i64);
                let mtime = entry.get("mtime_unix").and_then(Value::as_i64);
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

    match object.get("daemon_status").and_then(Value::as_object) {
        Some(daemon_status) => {
            let active = daemon_status
                .get("active")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !matches!(active, "active" | "inactive" | "socket_present" | "unknown") {
                problems.push(
                    "daemon_status.active must be one of active/inactive/socket_present/unknown"
                        .to_string(),
                );
            }
            if config.require_daemon_active && !matches!(active, "active" | "socket_present") {
                problems.push("daemon_status.active must indicate active runtime".to_string());
            }
            match daemon_status.get("socket_present").and_then(Value::as_bool) {
                Some(socket_present) => {
                    if config.require_socket_present && !socket_present {
                        problems.push(
                            "daemon_status.socket_present must be true in strict mode".to_string(),
                        );
                    }
                }
                None => problems.push("daemon_status.socket_present must be boolean".to_string()),
            }
            if !validate_absolute_path(daemon_status.get("socket_path")) {
                problems.push("daemon_status.socket_path must be absolute".to_string());
            }
        }
        None => problems.push("daemon_status must be an object".to_string()),
    }

    match object.get("known_peers").and_then(Value::as_array) {
        Some(known_peers) => {
            for (index, peer) in known_peers.iter().enumerate() {
                let Some(peer_object) = peer.as_object() else {
                    problems.push(format!("known_peers[{index}] must be an object"));
                    continue;
                };
                let pubkey_ok = peer_object
                    .get("public_key")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .map(decode_b64_32)
                    .unwrap_or(false);
                if !pubkey_ok {
                    problems.push(format!(
                        "known_peers[{index}].public_key must decode to 32 bytes"
                    ));
                }
                let endpoint = peer_object
                    .get("endpoint")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if peer_object
                    .get("endpoint")
                    .and_then(Value::as_str)
                    .is_none()
                {
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
