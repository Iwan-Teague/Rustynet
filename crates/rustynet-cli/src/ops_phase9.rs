#![forbid(unsafe_code)]

use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const DEFAULT_PHASE9_SOURCE_DIR: &str = "artifacts/operations/source";
const DEFAULT_PHASE9_RAW_DIR: &str = "artifacts/operations/raw";
const DEFAULT_PHASE9_OUT_DIR: &str = "artifacts/operations";
const DEFAULT_PHASE10_SOURCE_DIR: &str = "artifacts/phase10/source";
const DEFAULT_PHASE10_OUT_DIR: &str = "artifacts/phase10";
const DEFAULT_PHASE10_PROVENANCE_DIR: &str = "artifacts/phase10/provenance";
const DEFAULT_PHASE10_PROVENANCE_SIGNING_KEY_FILENAME: &str = "signing_seed.hex";
const DEFAULT_PHASE10_PROVENANCE_VERIFIER_KEY_FILENAME: &str = "verifier_key.hex";
const DEFAULT_PHASE10_PROVENANCE_HOST_ID: &str = "ci-localhost";
const DEFAULT_PHASE10_MAX_SOURCE_AGE_SECONDS: u64 = 2_678_400;
const DEFAULT_PHASE9_MAX_SOURCE_AGE_SECONDS: i64 = 2_678_400;
const DEFAULT_PHASE10_MAX_PROVENANCE_AGE_SECONDS: u64 = 2_678_400;
const PHASE10_PROVENANCE_FILENAME: &str = "phase10_provenance.attestation.json";
const PHASE10_PROVENANCE_SIGNING_KEY_PATH_ENV: &str =
    "RUSTYNET_PHASE10_PROVENANCE_SIGNING_KEY_PATH";
const PHASE10_PROVENANCE_VERIFIER_KEY_PATH_ENV: &str =
    "RUSTYNET_PHASE10_PROVENANCE_VERIFIER_KEY_PATH";
const PHASE10_PROVENANCE_HOST_ID_ENV: &str = "RUSTYNET_PHASE10_PROVENANCE_HOST_ID";
const PHASE10_PROVENANCE_SCHEMA_VERSION: u64 = 1;
const PHASE10_PROVENANCE_COMMAND_LITERAL: &str = "rustynet ops generate-phase10-artifacts";

const PHASE9_REQUIRED_SOURCES: &[&str] = &[
    "compatibility_policy.json",
    "crypto_deprecation_schedule.json",
    "slo_windows.ndjson",
    "performance_samples.ndjson",
    "incident_drills.ndjson",
    "dr_drills.ndjson",
    "backend_security_review.json",
];

const PHASE9_REQUIRED_ARTIFACTS: &[&str] = &[
    "compatibility_policy.json",
    "slo_error_budget_report.json",
    "performance_budget_report.json",
    "incident_drill_report.json",
    "dr_failover_report.json",
    "backend_agility_report.json",
    "crypto_deprecation_schedule.json",
];

const PHASE9_BACKEND_SCAN_TARGETS: &[&str] = &[
    "crates/rustynet-control/src",
    "crates/rustynet-policy/src",
    "crates/rustynet-crypto/src",
    "crates/rustynet-backend-api/src",
    "crates/rustynet-relay/src",
];

fn env_optional_string(key: &str) -> Result<Option<String>, String> {
    match std::env::var(key) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} contains non-utf8 data"))
        }
    }
}

fn required_env_string(key: &str) -> Result<String, String> {
    env_optional_string(key)?.ok_or_else(|| format!("missing required environment variable: {key}"))
}

fn resolve_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("path must not be empty".to_string());
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    Ok(cwd.join(path))
}

fn path_from_env_or_default(key: &str, default: &str) -> Result<PathBuf, String> {
    let raw = env_optional_string(key)?.unwrap_or_else(|| default.to_string());
    resolve_path(raw.as_str())
}

fn phase10_artifact_dir_from_env() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string("RUSTYNET_PHASE10_ARTIFACT_DIR")? {
        return resolve_path(value.as_str());
    }
    path_from_env_or_default("RUSTYNET_PHASE10_OUT_DIR", DEFAULT_PHASE10_OUT_DIR)
}

fn env_u64_with_default(key: &str, default: u64) -> Result<u64, String> {
    match env_optional_string(key)? {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|err| format!("invalid integer value for {key}: {err}")),
        None => Ok(default),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_hex_to_fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let normalized = value.trim();
    if normalized.len() != N * 2 {
        return Err(format!("expected {} hex characters", N * 2));
    }
    let mut out = [0u8; N];
    let bytes = normalized.as_bytes();
    for (index, slot) in out.iter_mut().enumerate().take(N) {
        let offset = index * 2;
        let hi = (bytes[offset] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex character".to_string())?;
        let lo = (bytes[offset + 1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex character".to_string())?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
}

fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let body = fs::read(path).map_err(|err| format!("read {} failed: {err}", path.display()))?;
    Ok(sha256_hex(&body))
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("missing required {label}: {} ({err})", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn enforce_owner_only_mode(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{label} must not be group/world accessible (expected <= 0600): {}",
            path.display()
        ));
    }
    Ok(())
}

fn ensure_secure_parent_directory(path: &Path, label: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} has no parent directory: {}", path.display()))?;
    let metadata = fs::symlink_metadata(parent).map_err(|err| {
        format!(
            "inspect {label} parent failed ({}): {err}",
            parent.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} parent must not be a symlink: {}",
            parent.display()
        ));
    }
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "{label} parent must be a directory: {}",
            parent.display()
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{label} parent must not be group/world accessible (expected <= 0700): {}",
            parent.display()
        ));
    }
    Ok(())
}

fn ensure_secure_directory(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("{label} must not be a symlink: {}", path.display()));
        }
        if !metadata.file_type().is_dir() {
            return Err(format!("{label} must be a directory: {}", path.display()));
        }
    } else {
        fs::create_dir_all(path)
            .map_err(|err| format!("create {label} failed ({}): {err}", path.display()))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("set {label} mode failed ({}): {err}", path.display()))?;
    let mode = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{label} must not be group/world accessible (expected <= 0700): {}",
            path.display()
        ));
    }
    Ok(())
}

fn secure_regular_file_exists(path: &Path, label: &str) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!("{label} must not be a symlink: {}", path.display()));
            }
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "{label} must be a regular file: {}",
                    path.display()
                ));
            }
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "inspect {label} failed ({}): {err}",
            path.display()
        )),
    }
}

fn load_key_hex_from_secure_path(path: &Path, label: &str) -> Result<String, String> {
    ensure_secure_parent_directory(path, label)?;
    ensure_regular_file(path, label)?;
    enforce_owner_only_mode(path, label)?;
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("read {label} failed ({}): {err}", path.display()))?;
    let normalized = raw.trim();
    if normalized.is_empty() {
        return Err(format!("{label} must not be empty: {}", path.display()));
    }
    Ok(normalized.to_string())
}

fn phase10_provenance_dir_from_env_or_default() -> Result<PathBuf, String> {
    path_from_env_or_default(
        "RUSTYNET_PHASE10_PROVENANCE_DIR",
        DEFAULT_PHASE10_PROVENANCE_DIR,
    )
}

fn phase10_signing_key_path_from_env_or_default() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string(PHASE10_PROVENANCE_SIGNING_KEY_PATH_ENV)? {
        return resolve_path(value.as_str());
    }
    Ok(phase10_provenance_dir_from_env_or_default()?
        .join(DEFAULT_PHASE10_PROVENANCE_SIGNING_KEY_FILENAME))
}

fn phase10_verifier_key_path_from_env_or_default() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string(PHASE10_PROVENANCE_VERIFIER_KEY_PATH_ENV)? {
        return resolve_path(value.as_str());
    }
    Ok(phase10_provenance_dir_from_env_or_default()?
        .join(DEFAULT_PHASE10_PROVENANCE_VERIFIER_KEY_FILENAME))
}

fn write_phase10_provenance_keypair(
    signing_key_path: &Path,
    verifier_key_path: &Path,
) -> Result<(), String> {
    let signing_parent = signing_key_path.parent().ok_or_else(|| {
        format!(
            "phase10 provenance signing key path has no parent: {}",
            signing_key_path.display()
        )
    })?;
    ensure_secure_directory(signing_parent, "phase10 provenance key directory")?;

    let verifier_parent = verifier_key_path.parent().ok_or_else(|| {
        format!(
            "phase10 provenance verifier key path has no parent: {}",
            verifier_key_path.display()
        )
    })?;
    if verifier_parent != signing_parent {
        ensure_secure_directory(verifier_parent, "phase10 provenance key directory")?;
    }

    let mut signing_seed = [0u8; 32];
    OsRng.fill_bytes(&mut signing_seed);
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifier_key = signing_key.verifying_key();
    let mut signing_key_hex = hex_encode(&signing_seed);
    let mut signing_key_body = signing_key_hex.clone();
    signing_key_body.push('\n');
    let verifier_key_body = format!("{}\n", hex_encode(verifier_key.as_bytes()));
    let write_result = (|| {
        write_secure_bytes(signing_key_path, signing_key_body.as_bytes())?;
        write_secure_bytes(verifier_key_path, verifier_key_body.as_bytes())?;
        Ok(())
    })();
    signing_seed.zeroize();
    signing_key_hex.zeroize();
    signing_key_body.zeroize();
    write_result
}

fn ensure_phase10_provenance_keypair_exists() -> Result<(), String> {
    let signing_key_path = phase10_signing_key_path_from_env_or_default()?;
    let verifier_key_path = phase10_verifier_key_path_from_env_or_default()?;
    if !signing_key_path.is_absolute() {
        return Err(format!(
            "{PHASE10_PROVENANCE_SIGNING_KEY_PATH_ENV} must resolve to an absolute path"
        ));
    }
    if !verifier_key_path.is_absolute() {
        return Err(format!(
            "{PHASE10_PROVENANCE_VERIFIER_KEY_PATH_ENV} must resolve to an absolute path"
        ));
    }

    let signing_exists =
        secure_regular_file_exists(signing_key_path.as_path(), "phase10 provenance signing key")?;
    let verifier_exists = secure_regular_file_exists(
        verifier_key_path.as_path(),
        "phase10 provenance verifier key",
    )?;

    match (signing_exists, verifier_exists) {
        (true, true) => Ok(()),
        (false, false) => {
            write_phase10_provenance_keypair(signing_key_path.as_path(), verifier_key_path.as_path())
        }
        _ => Err(
            "phase10 provenance key material is incomplete: signing and verifier keys must either both exist or both be absent".to_string(),
        ),
    }
}

fn load_phase10_signing_key() -> Result<SigningKey, String> {
    let key_path = phase10_signing_key_path_from_env_or_default()?;
    if !key_path.is_absolute() {
        return Err(format!(
            "{PHASE10_PROVENANCE_SIGNING_KEY_PATH_ENV} must resolve to an absolute path"
        ));
    }
    let key_hex =
        load_key_hex_from_secure_path(key_path.as_path(), "phase10 provenance signing key")?;
    let seed = decode_hex_to_fixed::<32>(key_hex.as_str())
        .map_err(|err| format!("invalid phase10 provenance signing key hex: {err}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn load_phase10_verifier_key() -> Result<VerifyingKey, String> {
    let key_path = phase10_verifier_key_path_from_env_or_default()?;
    if !key_path.is_absolute() {
        return Err(format!(
            "{PHASE10_PROVENANCE_VERIFIER_KEY_PATH_ENV} must resolve to an absolute path"
        ));
    }
    let key_hex =
        load_key_hex_from_secure_path(key_path.as_path(), "phase10 provenance verifier key")?;
    let key_bytes = decode_hex_to_fixed::<32>(key_hex.as_str())
        .map_err(|err| format!("invalid phase10 provenance verifier key hex: {err}"))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|err| format!("parse phase10 provenance verifier key failed: {err}"))
}

fn validate_phase10_host_identity(host_identity: &str) -> Result<String, String> {
    if host_identity.len() > 128 {
        return Err("phase10 provenance host identity must be <= 128 characters".to_string());
    }
    if !host_identity
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '/'))
    {
        return Err("phase10 provenance host identity contains unsupported characters".to_string());
    }
    Ok(host_identity.to_string())
}

fn phase10_host_identity_from_env_or_default() -> Result<String, String> {
    match env_optional_string(PHASE10_PROVENANCE_HOST_ID_ENV)? {
        Some(value) => validate_phase10_host_identity(value.as_str()),
        None => Ok(DEFAULT_PHASE10_PROVENANCE_HOST_ID.to_string()),
    }
}

fn read_json_object(path: &Path, label: &str) -> Result<Map<String, Value>, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read {label} failed ({}): {err}", path.display()))?;
    let value: Value = serde_json::from_str(body.as_str())
        .map_err(|err| format!("parse {label} failed ({}): {err}", path.display()))?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| format!("{label} must be a JSON object: {}", path.display()))
}

fn create_secure_temp_file(dir: &Path, prefix: &str) -> Result<PathBuf, String> {
    fs::create_dir_all(dir)
        .map_err(|err| format!("create directory {} failed: {err}", dir.display()))?;
    let pid = std::process::id();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system time before unix epoch: {err}"))?
        .as_nanos();
    for counter in 0..32u32 {
        let candidate = dir.join(format!("{prefix}{pid}-{nonce}-{counter}"));
        match OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "create secure temporary file failed ({}): {err}",
                    candidate.display()
                ));
            }
        }
    }
    Err(format!(
        "unable to allocate secure temporary file in {}",
        dir.display()
    ))
}

fn write_secure_bytes(path: &Path, body: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create output directory failed ({}): {err}",
            parent.display()
        )
    })?;

    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| format!("inspect output path failed ({}): {err}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "output path must not be a symlink: {}",
                path.display()
            ));
        }
        if !metadata.file_type().is_file() {
            return Err(format!("output path must be a file: {}", path.display()));
        }
    }

    let temp_path = create_secure_temp_file(parent, "ops-evidence.")?;
    {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(temp_path.as_path())
            .map_err(|err| format!("open temp output failed ({}): {err}", temp_path.display()))?;
        file.write_all(body)
            .map_err(|err| format!("write temp output failed ({}): {err}", temp_path.display()))?;
        file.sync_all()
            .map_err(|err| format!("sync temp output failed ({}): {err}", temp_path.display()))?;
    }
    fs::set_permissions(temp_path.as_path(), fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "set temp output mode failed ({}): {err}",
            temp_path.display()
        )
    })?;
    fs::rename(temp_path.as_path(), path)
        .map_err(|err| format!("publish output failed ({}): {err}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("set output mode failed ({}): {err}", path.display()))?;
    Ok(())
}

fn write_json_secure(path: &Path, payload: &Value) -> Result<(), String> {
    let mut body = serde_json::to_string_pretty(payload)
        .map_err(|err| format!("serialize json failed ({}): {err}", path.display()))?;
    body.push('\n');
    write_secure_bytes(path, body.as_bytes())
}

fn run_check_script(script_path: &str, label: &str) -> Result<(), String> {
    let status = Command::new(script_path)
        .status()
        .map_err(|err| format!("invoke {label} failed ({script_path}): {err}"))?;
    if !status.success() {
        return Err(format!(
            "{label} failed with status {status} ({script_path})"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Phase9BackendProbeStatus {
    conformance_wireguard: bool,
    conformance_backend_api: bool,
    protocol_leakage_detected: bool,
}

fn env_flag_equals_one_with_default(key: &str, default: bool) -> Result<bool, String> {
    match env_optional_string(key)? {
        Some(raw) => Ok(raw == "1"),
        None => Ok(default),
    }
}

fn ensure_directory(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("{label} must not be a symlink: {}", path.display()));
        }
        if !metadata.file_type().is_dir() {
            return Err(format!("{label} must be a directory: {}", path.display()));
        }
        return Ok(());
    }
    fs::create_dir_all(path)
        .map_err(|err| format!("create {label} failed ({}): {err}", path.display()))
}

fn read_ndjson_objects(path: &Path, label: &str) -> Result<Vec<Map<String, Value>>, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read {label} failed ({}): {err}", path.display()))?;
    let mut entries = Vec::new();
    for (line_number, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).map_err(|err| {
            format!(
                "invalid ndjson at {}:{} ({label}): {err}",
                path.display(),
                line_number + 1
            )
        })?;
        let object = value.as_object().ok_or_else(|| {
            format!(
                "invalid ndjson object at {}:{} ({label})",
                path.display(),
                line_number + 1
            )
        })?;
        entries.push(object.clone());
    }
    if entries.is_empty() {
        return Err(format!("no entries in ndjson source: {}", path.display()));
    }
    Ok(entries)
}

fn open_secure_log_file(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("open log file failed ({}): {err}", path.display()))
}

fn run_logged_command(
    mut command: Command,
    log_path: &Path,
    label: &str,
) -> Result<std::process::ExitStatus, String> {
    let stdout = open_secure_log_file(log_path)?;
    let stderr = stdout
        .try_clone()
        .map_err(|err| format!("clone log file failed ({}): {err}", log_path.display()))?;
    let status = command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .map_err(|err| format!("invoke {label} failed: {err}"))?;
    fs::set_permissions(log_path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("set log mode failed ({}): {err}", log_path.display()))?;
    Ok(status)
}

fn phase9_backend_leakage_pattern() -> String {
    "(wireguard|wg[-_]|wgctrl)".to_string()
}

fn run_phase9_backend_probes(
    source_dir: &Path,
    run_backend_probes: bool,
) -> Result<Phase9BackendProbeStatus, String> {
    let mut status = Phase9BackendProbeStatus {
        conformance_wireguard: false,
        conformance_backend_api: false,
        protocol_leakage_detected: true,
    };
    if !run_backend_probes {
        return Ok(status);
    }

    let wireguard_log = source_dir.join("backend_conformance_wireguard.log");
    let backend_wireguard = run_logged_command(
        {
            let mut command = Command::new("cargo");
            command.args([
                "test",
                "-p",
                "rustynet-backend-wireguard",
                "--test",
                "conformance",
                "--all-features",
            ]);
            command
        },
        wireguard_log.as_path(),
        "phase9 wireguard backend conformance",
    )?;
    status.conformance_wireguard = backend_wireguard.success();

    let backend_api_log = source_dir.join("backend_conformance_api.log");
    let backend_api = run_logged_command(
        {
            let mut command = Command::new("cargo");
            command.args([
                "test",
                "-p",
                "rustynet-backend-api",
                "--all-targets",
                "--all-features",
            ]);
            command
        },
        backend_api_log.as_path(),
        "phase9 backend api conformance",
    )?;
    status.conformance_backend_api = backend_api.success();

    let leakage_log = source_dir.join("backend_leakage_scan.log");
    let leakage_scan = run_logged_command(
        {
            let mut command = Command::new("rg");
            command.arg("-n");
            command.arg("-i");
            command.arg(phase9_backend_leakage_pattern());
            for target in PHASE9_BACKEND_SCAN_TARGETS {
                command.arg(target);
            }
            command
        },
        leakage_log.as_path(),
        "phase9 backend leakage scan",
    )?;
    match leakage_scan.code() {
        Some(0) => status.protocol_leakage_detected = true,
        Some(1) => status.protocol_leakage_detected = false,
        Some(code) => {
            return Err(format!(
                "backend leakage scan failed unexpectedly (status {code}); see {}",
                leakage_log.display()
            ));
        }
        None => {
            return Err(format!(
                "backend leakage scan terminated unexpectedly; see {}",
                leakage_log.display()
            ));
        }
    }

    Ok(status)
}

fn phase9_require_measured_mode(payload: &Map<String, Value>, label: &str) -> Result<(), String> {
    if let Some(mode) = payload.get("evidence_mode")
        && mode.as_str() != Some("measured")
    {
        return Err(format!(
            "{label} must be measured evidence when evidence_mode is present; got {mode:?}"
        ));
    }
    Ok(())
}

fn parse_two_digits(value: &str, field: &str) -> Result<u32, String> {
    if value.len() != 2 || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("invalid numeric field for {field}: {value}"));
    }
    value
        .parse::<u32>()
        .map_err(|err| format!("invalid numeric field for {field}: {err}"))
}

fn parse_four_digits(value: &str, field: &str) -> Result<i32, String> {
    if value.len() != 4 || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("invalid numeric field for {field}: {value}"));
    }
    value
        .parse::<i32>()
        .map_err(|err| format!("invalid numeric field for {field}: {err}"))
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    };
    Some(days)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut y = i64::from(year);
    let m = i64::from(month);
    let d = i64::from(day);
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_utc_to_unix(value: &str, field: &str) -> Result<i64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("missing or invalid UTC field: {field}"));
    }

    let (datetime_part, offset_seconds) = if let Some(stripped) = trimmed.strip_suffix('Z') {
        (stripped, 0i64)
    } else {
        let tz_start = trimmed
            .char_indices()
            .rev()
            .find_map(|(index, ch)| {
                if index > 10 && (ch == '+' || ch == '-') {
                    Some(index)
                } else {
                    None
                }
            })
            .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
        let (base, zone) = trimmed.split_at(tz_start);
        if zone.len() != 6 {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }
        if &zone[3..4] != ":" {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }
        let sign = if &zone[0..1] == "+" { 1i64 } else { -1i64 };
        let offset_hour = parse_two_digits(&zone[1..3], field)?;
        let offset_minute = parse_two_digits(&zone[4..6], field)?;
        if offset_hour > 23 || offset_minute > 59 {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }
        let total = i64::from(offset_hour) * 3600 + i64::from(offset_minute) * 60;
        (base, sign * total)
    };

    let (date_part, time_part) = datetime_part
        .split_once('T')
        .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
    let date_fields = date_part.split('-').collect::<Vec<_>>();
    if date_fields.len() != 3 {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    }
    let year = parse_four_digits(date_fields[0], field)?;
    let month = parse_two_digits(date_fields[1], field)?;
    let day = parse_two_digits(date_fields[2], field)?;
    let max_day = days_in_month(year, month)
        .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
    if day == 0 || day > max_day {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    }

    let (time_core, fraction) = match time_part.split_once('.') {
        Some((core, frac)) => (core, Some(frac)),
        None => (time_part, None),
    };
    if let Some(frac) = fraction
        && (frac.is_empty() || !frac.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    }
    let time_fields = time_core.split(':').collect::<Vec<_>>();
    if time_fields.len() != 3 {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    }
    let hour = parse_two_digits(time_fields[0], field)?;
    let minute = parse_two_digits(time_fields[1], field)?;
    let second = parse_two_digits(time_fields[2], field)?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    }

    let date_seconds = days_from_civil(year, month, day)
        .checked_mul(86_400)
        .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
    let time_seconds = i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
    date_seconds
        .checked_add(time_seconds)
        .and_then(|value| value.checked_sub(offset_seconds))
        .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))
}

fn phase9_entry_numeric(
    entry: &Map<String, Value>,
    keys: &[&str],
    label: &str,
) -> Result<f64, String> {
    for key in keys {
        if let Some(value) = entry.get(*key).and_then(Value::as_f64) {
            return Ok(value);
        }
    }
    Err(format!(
        "missing numeric field for {label}; expected one of {}",
        keys.join(",")
    ))
}

fn phase9_value_or_null(entry: &Map<String, Value>, key: &str) -> Value {
    entry.get(key).cloned().unwrap_or(Value::Null)
}

fn phase9_bool_or_default(entry: &Map<String, Value>, key: &str) -> bool {
    entry.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn phase9_enforce_timestamp_freshness(
    timestamp_unix: i64,
    label: &str,
    now_unix: i64,
) -> Result<(), String> {
    if timestamp_unix > now_unix + 300 {
        return Err(format!("{label} timestamp is too far in the future"));
    }
    if now_unix - timestamp_unix > DEFAULT_PHASE9_MAX_SOURCE_AGE_SECONDS {
        return Err(format!(
            "{label} evidence is stale; recollect measured source data"
        ));
    }
    Ok(())
}

pub fn execute_ops_collect_phase9_raw_evidence() -> Result<String, String> {
    let source_dir =
        path_from_env_or_default("RUSTYNET_PHASE9_SOURCE_DIR", DEFAULT_PHASE9_SOURCE_DIR)?;
    let raw_dir = path_from_env_or_default("RUSTYNET_PHASE9_RAW_DIR", DEFAULT_PHASE9_RAW_DIR)?;
    let run_backend_probes =
        env_flag_equals_one_with_default("RUSTYNET_PHASE9_RUN_BACKEND_PROBES", true)?;
    let strict_mode = env_flag_equals_one_with_default("RUSTYNET_PHASE9_COLLECT_STRICT", true)?;

    ensure_directory(source_dir.as_path(), "phase9 source directory")?;
    ensure_directory(raw_dir.as_path(), "phase9 raw directory")?;

    for source_name in PHASE9_REQUIRED_SOURCES {
        ensure_regular_file(
            source_dir.join(source_name).as_path(),
            "phase9 evidence source",
        )?;
    }

    let backend_probe_status = run_phase9_backend_probes(source_dir.as_path(), run_backend_probes)?;
    let now_unix =
        i64::try_from(unix_now()).map_err(|_| "current unix time out of range".to_string())?;

    let compatibility_source = source_dir.join("compatibility_policy.json");
    let compatibility_policy =
        read_json_object(compatibility_source.as_path(), "compatibility_policy.json")?;
    phase9_require_measured_mode(&compatibility_policy, "compatibility_policy.json")?;
    for required in [
        "policy_version",
        "minimum_supported_client",
        "latest_server",
        "deprecation_window_days",
        "insecure_compatibility_mode",
    ] {
        if !compatibility_policy.contains_key(required) {
            return Err(format!("compatibility policy missing field: {required}"));
        }
    }

    let crypto_source = source_dir.join("crypto_deprecation_schedule.json");
    let crypto_schedule =
        read_json_object(crypto_source.as_path(), "crypto_deprecation_schedule.json")?;
    phase9_require_measured_mode(&crypto_schedule, "crypto_deprecation_schedule.json")?;
    if crypto_schedule
        .get("entries")
        .and_then(Value::as_array)
        .map(|entries| entries.is_empty())
        .unwrap_or(true)
    {
        return Err("crypto deprecation schedule requires non-empty entries".to_string());
    }

    let slo_entries = read_ndjson_objects(
        source_dir.join("slo_windows.ndjson").as_path(),
        "slo_windows.ndjson",
    )?;
    let mut latest_slo: Option<(i64, Map<String, Value>)> = None;
    for (index, entry) in slo_entries.iter().enumerate() {
        phase9_require_measured_mode(entry, format!("slo_windows.ndjson entry {index}").as_str())?;
        let window_end = entry
            .get("window_end_utc")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing or invalid UTC field: slo latest window_end_utc".to_string())?;
        let timestamp = parse_utc_to_unix(window_end, "slo latest window_end_utc")?;
        if latest_slo
            .as_ref()
            .map(|(latest, _)| timestamp > *latest)
            .unwrap_or(true)
        {
            latest_slo = Some((timestamp, entry.clone()));
        }
    }
    let (slo_latest_timestamp, slo_latest) =
        latest_slo.ok_or_else(|| "no entries in ndjson source: slo_windows.ndjson".to_string())?;
    phase9_enforce_timestamp_freshness(slo_latest_timestamp, "latest slo window", now_unix)?;

    let performance_entries = read_ndjson_objects(
        source_dir.join("performance_samples.ndjson").as_path(),
        "performance_samples.ndjson",
    )?;
    let mut performance_entries_sorted = Vec::new();
    for (index, entry) in performance_entries.into_iter().enumerate() {
        phase9_require_measured_mode(
            &entry,
            format!("performance_samples.ndjson entry {index}").as_str(),
        )?;
        let timestamp_raw = entry
            .get("measured_at_utc")
            .and_then(Value::as_str)
            .or_else(|| entry.get("timestamp_utc").and_then(Value::as_str))
            .ok_or_else(|| "missing or invalid UTC field: performance timestamp".to_string())?;
        let timestamp = parse_utc_to_unix(timestamp_raw, "performance timestamp")?;
        performance_entries_sorted.push((timestamp, entry));
    }
    performance_entries_sorted.sort_by_key(|(timestamp, _)| *timestamp);
    let (performance_start, _) = performance_entries_sorted
        .first()
        .ok_or_else(|| "no entries in ndjson source: performance_samples.ndjson".to_string())?;
    let (performance_end, performance_latest) = performance_entries_sorted
        .last()
        .ok_or_else(|| "no entries in ndjson source: performance_samples.ndjson".to_string())?;
    phase9_enforce_timestamp_freshness(*performance_end, "latest performance sample", now_unix)?;
    let soak_test_hours = ((*performance_end - *performance_start) as f64) / 3600.0;
    let soak_test_hours = (soak_test_hours * 1000.0).round() / 1000.0;

    let mut idle_cpu_percent = f64::MIN;
    let mut idle_memory_mb = f64::MIN;
    let mut reconnect_seconds = f64::MIN;
    let mut route_apply_p95_seconds = f64::MIN;
    let mut throughput_overhead_percent = f64::MIN;
    for (_, entry) in &performance_entries_sorted {
        idle_cpu_percent = idle_cpu_percent.max(phase9_entry_numeric(
            entry,
            &["idle_cpu_percent"],
            "idle_cpu_percent",
        )?);
        idle_memory_mb = idle_memory_mb.max(phase9_entry_numeric(
            entry,
            &["idle_memory_mb"],
            "idle_memory_mb",
        )?);
        reconnect_seconds = reconnect_seconds.max(phase9_entry_numeric(
            entry,
            &["reconnect_seconds", "reconnect_p95_seconds"],
            "reconnect_seconds",
        )?);
        route_apply_p95_seconds = route_apply_p95_seconds.max(phase9_entry_numeric(
            entry,
            &["route_apply_p95_seconds", "route_apply_seconds_p95"],
            "route_apply_p95_seconds",
        )?);
        throughput_overhead_percent = throughput_overhead_percent.max(phase9_entry_numeric(
            entry,
            &[
                "throughput_overhead_percent",
                "throughput_overhead_vs_wireguard_percent",
            ],
            "throughput_overhead_percent",
        )?);
    }

    let incident_entries = read_ndjson_objects(
        source_dir.join("incident_drills.ndjson").as_path(),
        "incident_drills.ndjson",
    )?;
    let mut latest_incident: Option<(i64, Map<String, Value>)> = None;
    for (index, entry) in incident_entries.iter().enumerate() {
        phase9_require_measured_mode(
            entry,
            format!("incident_drills.ndjson entry {index}").as_str(),
        )?;
        let executed_at = entry
            .get("executed_at_utc")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "missing or invalid UTC field: incident latest executed_at_utc".to_string()
            })?;
        let timestamp = parse_utc_to_unix(executed_at, "incident latest executed_at_utc")?;
        if latest_incident
            .as_ref()
            .map(|(latest, _)| timestamp > *latest)
            .unwrap_or(true)
        {
            latest_incident = Some((timestamp, entry.clone()));
        }
    }
    let (incident_latest_timestamp, incident_latest) = latest_incident
        .ok_or_else(|| "no entries in ndjson source: incident_drills.ndjson".to_string())?;
    phase9_enforce_timestamp_freshness(
        incident_latest_timestamp,
        "latest incident drill",
        now_unix,
    )?;

    let dr_entries = read_ndjson_objects(
        source_dir.join("dr_drills.ndjson").as_path(),
        "dr_drills.ndjson",
    )?;
    let mut latest_dr: Option<(i64, Map<String, Value>)> = None;
    for (index, entry) in dr_entries.iter().enumerate() {
        phase9_require_measured_mode(entry, format!("dr_drills.ndjson entry {index}").as_str())?;
        let executed_at = entry
            .get("executed_at_utc")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing or invalid UTC field: dr latest executed_at_utc".to_string())?;
        let timestamp = parse_utc_to_unix(executed_at, "dr latest executed_at_utc")?;
        if latest_dr
            .as_ref()
            .map(|(latest, _)| timestamp > *latest)
            .unwrap_or(true)
        {
            latest_dr = Some((timestamp, entry.clone()));
        }
    }
    let (dr_latest_timestamp, dr_latest) =
        latest_dr.ok_or_else(|| "no entries in ndjson source: dr_drills.ndjson".to_string())?;
    phase9_enforce_timestamp_freshness(dr_latest_timestamp, "latest dr drill", now_unix)?;

    let backend_review_source = source_dir.join("backend_security_review.json");
    let backend_review = read_json_object(
        backend_review_source.as_path(),
        "backend_security_review.json",
    )?;
    phase9_require_measured_mode(&backend_review, "backend_security_review.json")?;
    let additional_paths_values = backend_review
        .get("additional_backend_paths")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "backend_security_review.json requires non-empty additional_backend_paths".to_string()
        })?;
    if additional_paths_values.is_empty() {
        return Err(
            "backend_security_review.json requires non-empty additional_backend_paths".to_string(),
        );
    }
    let mut additional_paths = Vec::with_capacity(additional_paths_values.len());
    for path in additional_paths_values {
        let path_value = path
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "backend additional path must be non-empty string".to_string())?;
        additional_paths.push(path_value.to_string());
    }

    let backend_leakage_pattern = phase9_backend_leakage_pattern();
    let backend_leakage_command = format!(
        "rg -n '{}' {}",
        backend_leakage_pattern,
        PHASE9_BACKEND_SCAN_TARGETS.join(" ")
    );

    let raw_payloads: [(&str, Value); 7] = [
        (
            "compatibility_policy.json",
            Value::Object(compatibility_policy),
        ),
        (
            "slo_error_budget_report.json",
            json!({
                "window_start_utc": phase9_value_or_null(&slo_latest, "window_start_utc"),
                "window_end_utc": phase9_value_or_null(&slo_latest, "window_end_utc"),
                "availability_slo_percent": phase9_entry_numeric(&slo_latest, &["availability_slo_percent"], "availability_slo_percent")?,
                "measured_availability_percent": phase9_entry_numeric(&slo_latest, &["measured_availability_percent"], "measured_availability_percent")?,
                "max_error_budget_consumed_percent": phase9_entry_numeric(&slo_latest, &["max_error_budget_consumed_percent"], "max_error_budget_consumed_percent")?,
                "measured_error_budget_consumed_percent": phase9_entry_numeric(&slo_latest, &["measured_error_budget_consumed_percent"], "measured_error_budget_consumed_percent")?,
            }),
        ),
        (
            "performance_budget_report.json",
            json!({
                "benchmark_matrix": performance_latest.get("benchmark_matrix").cloned().unwrap_or_else(|| json!({})),
                "idle_cpu_percent": idle_cpu_percent,
                "idle_memory_mb": idle_memory_mb,
                "reconnect_seconds": reconnect_seconds,
                "route_apply_p95_seconds": route_apply_p95_seconds,
                "throughput_overhead_percent": throughput_overhead_percent,
                "soak_test_hours": soak_test_hours,
            }),
        ),
        (
            "incident_drill_report.json",
            json!({
                "drill_id": phase9_value_or_null(&incident_latest, "drill_id"),
                "executed_at_utc": phase9_value_or_null(&incident_latest, "executed_at_utc"),
                "scenario": phase9_value_or_null(&incident_latest, "scenario"),
                "detection_minutes": phase9_entry_numeric(&incident_latest, &["detection_minutes"], "incident detection_minutes")?,
                "containment_minutes": phase9_entry_numeric(&incident_latest, &["containment_minutes"], "incident containment_minutes")?,
                "recovery_minutes": phase9_entry_numeric(&incident_latest, &["recovery_minutes"], "incident recovery_minutes")?,
                "postmortem_completed": phase9_bool_or_default(&incident_latest, "postmortem_completed"),
                "action_items_closed": phase9_bool_or_default(&incident_latest, "action_items_closed"),
                "oncall_readiness_confirmed": phase9_bool_or_default(&incident_latest, "oncall_readiness_confirmed"),
            }),
        ),
        (
            "dr_failover_report.json",
            json!({
                "drill_id": phase9_value_or_null(&dr_latest, "drill_id"),
                "executed_at_utc": phase9_value_or_null(&dr_latest, "executed_at_utc"),
                "regions_tested": dr_latest.get("regions_tested").cloned().unwrap_or_else(|| json!([])),
                "region_count": phase9_entry_numeric(&dr_latest, &["region_count"], "dr region_count")? as i64,
                "rpo_target_minutes": phase9_entry_numeric(&dr_latest, &["rpo_target_minutes"], "dr rpo_target_minutes")? as i64,
                "rto_target_minutes": phase9_entry_numeric(&dr_latest, &["rto_target_minutes"], "dr rto_target_minutes")? as i64,
                "measured_rpo_minutes": phase9_entry_numeric(&dr_latest, &["measured_rpo_minutes"], "dr measured_rpo_minutes")? as i64,
                "measured_rto_minutes": phase9_entry_numeric(&dr_latest, &["measured_rto_minutes"], "dr measured_rto_minutes")? as i64,
                "restore_integrity_verified": phase9_bool_or_default(&dr_latest, "restore_integrity_verified"),
            }),
        ),
        (
            "backend_agility_report.json",
            json!({
                "default_backend": backend_review.get("default_backend").and_then(Value::as_str).unwrap_or("wireguard"),
                "additional_backend_paths": additional_paths,
                "conformance_passed": backend_probe_status.conformance_wireguard && backend_probe_status.conformance_backend_api,
                "security_review_complete": phase9_bool_or_default(&backend_review, "security_review_complete"),
                "wireguard_is_adapter_boundary": phase9_bool_or_default(&backend_review, "wireguard_is_adapter_boundary"),
                "protocol_leakage_detected": backend_probe_status.protocol_leakage_detected,
                "evidence_commands": [
                    "cargo test -p rustynet-backend-wireguard --test conformance --all-features",
                    "cargo test -p rustynet-backend-api --all-targets --all-features",
                    backend_leakage_command,
                ],
            }),
        ),
        (
            "crypto_deprecation_schedule.json",
            Value::Object(crypto_schedule),
        ),
    ];

    for (filename, payload) in raw_payloads {
        write_json_secure(raw_dir.join(filename).as_path(), &payload)?;
    }

    if strict_mode
        && (!backend_probe_status.conformance_wireguard
            || !backend_probe_status.conformance_backend_api
            || backend_probe_status.protocol_leakage_detected)
    {
        return Err(
            "backend agility probe controls failed; raw evidence written but collection is failing closed"
                .to_string(),
        );
    }

    Ok(format!(
        "wrote {} raw phase9 evidence files to {}\nphase9 raw evidence collected from source logs/config and command probes",
        PHASE9_REQUIRED_ARTIFACTS.len(),
        raw_dir.display()
    ))
}

fn phase10_require_measured_source(
    payload: &Map<String, Value>,
    source_path: &Path,
    label: &str,
) -> Result<(), String> {
    let evidence_mode = payload
        .get("evidence_mode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "{label} source must set evidence_mode=measured: {}",
                source_path.display()
            )
        })?;
    if evidence_mode != "measured" {
        return Err(format!(
            "{label} source must set evidence_mode=measured: {}",
            source_path.display()
        ));
    }
    Ok(())
}

fn phase10_require_positive_unix_timestamp(
    payload: &Map<String, Value>,
    source_path: &Path,
    label: &str,
) -> Result<i64, String> {
    let value = payload.get("captured_at_unix").ok_or_else(|| {
        format!(
            "{label} source requires captured_at_unix: {}",
            source_path.display()
        )
    })?;
    let parsed = if let Some(v) = value.as_i64() {
        v
    } else if let Some(v) = value.as_u64() {
        i64::try_from(v).map_err(|_| {
            format!(
                "{label} source has out-of-range captured_at_unix: {}",
                source_path.display()
            )
        })?
    } else {
        return Err(format!(
            "{label} source requires integer captured_at_unix: {}",
            source_path.display()
        ));
    };
    if parsed <= 0 {
        return Err(format!(
            "{label} source requires positive captured_at_unix: {}",
            source_path.display()
        ));
    }
    Ok(parsed)
}

fn phase10_validate_source_freshness(
    source_captured_at_unix: i64,
    source_path: &Path,
    label: &str,
    now_unix: i64,
    max_source_age_seconds: i64,
) -> Result<(), String> {
    if source_captured_at_unix > now_unix + 300 {
        return Err(format!(
            "{label} source timestamp is too far in the future: {}",
            source_path.display()
        ));
    }
    if now_unix - source_captured_at_unix > max_source_age_seconds {
        return Err(format!(
            "{label} source evidence is stale; recollect measured data: {}",
            source_path.display()
        ));
    }
    Ok(())
}

fn phase10_require_status_pass(
    payload: &Map<String, Value>,
    source_path: &Path,
    label: &str,
) -> Result<(), String> {
    if payload.get("status").and_then(Value::as_str) != Some("pass") {
        return Err(format!(
            "{label} source must report status=pass: {}",
            source_path.display()
        ));
    }
    Ok(())
}

fn phase10_validate_checks_all_pass(
    payload: &Map<String, Value>,
    source_path: &Path,
    label: &str,
) -> Result<(), String> {
    let checks = payload
        .get("checks")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            format!(
                "{label} source must include non-empty checks object: {}",
                source_path.display()
            )
        })?;
    if checks.is_empty() {
        return Err(format!(
            "{label} source must include non-empty checks object: {}",
            source_path.display()
        ));
    }
    for (key, value) in checks {
        if value.as_str() != Some("pass") {
            return Err(format!(
                "{label} source check must pass ({key}) in {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn phase10_validate_perf_budget(
    payload: &Map<String, Value>,
    source_path: &Path,
) -> Result<(), String> {
    if payload.get("soak_status").and_then(Value::as_str) != Some("pass") {
        return Err(format!(
            "perf_budget_report source must report soak_status=pass: {}",
            source_path.display()
        ));
    }
    let metrics = payload
        .get("metrics")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            format!(
                "perf_budget_report source must include non-empty metrics list: {}",
                source_path.display()
            )
        })?;
    if metrics.is_empty() {
        return Err(format!(
            "perf_budget_report source must include non-empty metrics list: {}",
            source_path.display()
        ));
    }
    for metric in metrics {
        let metric_object = metric.as_object().ok_or_else(|| {
            format!(
                "perf_budget_report metrics entries must be objects: {}",
                source_path.display()
            )
        })?;
        if metric_object.get("status").and_then(Value::as_str) != Some("pass") {
            return Err(format!(
                "perf_budget_report source must not contain failing metrics: {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn contains_generation_marker(log_body: &str) -> bool {
    for token in log_body.split(|ch: char| ch.is_ascii_whitespace() || ch == ',' || ch == ';') {
        let Some(rest) = token.strip_prefix("generation=") else {
            continue;
        };
        if !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit()) {
            return true;
        }
    }
    false
}

fn phase10_provenance_path(out_dir: &Path) -> PathBuf {
    out_dir.join(PHASE10_PROVENANCE_FILENAME)
}

fn phase10_expected_provenance_entries(
    source_dir: &Path,
    out_dir: &Path,
) -> Vec<(&'static str, &'static str, PathBuf, bool)> {
    vec![
        (
            "source_netns_e2e_report",
            "source",
            source_dir.join("netns_e2e_report.json"),
            true,
        ),
        (
            "source_leak_test_report",
            "source",
            source_dir.join("leak_test_report.json"),
            true,
        ),
        (
            "source_perf_budget_report",
            "source",
            source_dir.join("perf_budget_report.json"),
            true,
        ),
        (
            "source_direct_relay_failover_report",
            "source",
            source_dir.join("direct_relay_failover_report.json"),
            true,
        ),
        (
            "source_state_transition_audit_log",
            "source",
            source_dir.join("state_transition_audit.log"),
            false,
        ),
        (
            "derived_netns_e2e_report",
            "derived",
            out_dir.join("netns_e2e_report.json"),
            true,
        ),
        (
            "derived_leak_test_report",
            "derived",
            out_dir.join("leak_test_report.json"),
            true,
        ),
        (
            "derived_perf_budget_report",
            "derived",
            out_dir.join("perf_budget_report.json"),
            true,
        ),
        (
            "derived_direct_relay_failover_report",
            "derived",
            out_dir.join("direct_relay_failover_report.json"),
            true,
        ),
        (
            "derived_state_transition_audit_log",
            "derived",
            out_dir.join("state_transition_audit.log"),
            false,
        ),
    ]
}

fn canonical_file_display(path: &Path, label: &str) -> Result<String, String> {
    ensure_regular_file(path, label)?;
    let canonical = fs::canonicalize(path)
        .map_err(|err| format!("canonicalize {label} failed ({}): {err}", path.display()))?;
    Ok(canonical.display().to_string())
}

fn phase10_json_captured_at_unix(path: &Path, label: &str) -> Result<u64, String> {
    let payload = read_json_object(path, label)?;
    let captured = phase10_require_positive_unix_timestamp(&payload, path, label)?;
    u64::try_from(captured).map_err(|_| {
        format!(
            "{label} captured_at_unix out of range for u64: {}",
            path.display()
        )
    })
}

struct Phase10ProvenancePayload<'a> {
    generated_at_unix: u64,
    host_identity: &'a str,
    command_digest_sha256: &'a str,
    signer_key_id: &'a str,
    verifier_key_hex: &'a str,
    label: &'a str,
    role: &'a str,
    artifact_path: &'a str,
    artifact_sha256: &'a str,
    captured_at_unix: u64,
}

fn phase10_provenance_payload(fields: &Phase10ProvenancePayload<'_>) -> String {
    format!(
        "version={PHASE10_PROVENANCE_SCHEMA_VERSION}\nphase=phase10\ngenerated_at_unix={generated_at_unix}\nhost_identity={host_identity}\ncommand_digest_sha256={command_digest_sha256}\nsigner_key_id={signer_key_id}\nverifier_key_hex={verifier_key_hex}\nlabel={label}\nrole={role}\nartifact_path={artifact_path}\nartifact_sha256={artifact_sha256}\ncaptured_at_unix={captured_at_unix}\n",
        generated_at_unix = fields.generated_at_unix,
        host_identity = fields.host_identity,
        command_digest_sha256 = fields.command_digest_sha256,
        signer_key_id = fields.signer_key_id,
        verifier_key_hex = fields.verifier_key_hex,
        label = fields.label,
        role = fields.role,
        artifact_path = fields.artifact_path,
        artifact_sha256 = fields.artifact_sha256,
        captured_at_unix = fields.captured_at_unix,
    )
}

fn build_phase10_provenance_document(
    source_dir: &Path,
    out_dir: &Path,
    generated_at_unix: u64,
    host_identity: &str,
    signing_key: &SigningKey,
    verifier_key: &VerifyingKey,
) -> Result<Value, String> {
    let command_digest_sha256 = sha256_hex(PHASE10_PROVENANCE_COMMAND_LITERAL.as_bytes());
    let verifier_key_hex = hex_encode(verifier_key.as_bytes());
    let signer_fingerprint = sha256_hex(verifier_key.as_bytes());
    let signer_key_id = format!("ed25519:{}", &signer_fingerprint[..16]);

    let mut entries = Vec::new();
    for (label, role, path, is_json) in phase10_expected_provenance_entries(source_dir, out_dir) {
        let canonical_path = canonical_file_display(path.as_path(), label)?;
        let artifact_sha256 = sha256_file_hex(Path::new(canonical_path.as_str()))?;
        let captured_at_unix = if is_json {
            phase10_json_captured_at_unix(Path::new(canonical_path.as_str()), label)?
        } else {
            generated_at_unix
        };
        let payload = phase10_provenance_payload(&Phase10ProvenancePayload {
            generated_at_unix,
            host_identity,
            command_digest_sha256: command_digest_sha256.as_str(),
            signer_key_id: signer_key_id.as_str(),
            verifier_key_hex: verifier_key_hex.as_str(),
            label,
            role,
            artifact_path: canonical_path.as_str(),
            artifact_sha256: artifact_sha256.as_str(),
            captured_at_unix,
        });
        let signature = signing_key.sign(payload.as_bytes());
        entries.push(json!({
            "label": label,
            "role": role,
            "artifact_path": canonical_path,
            "artifact_sha256": artifact_sha256,
            "captured_at_unix": captured_at_unix,
            "signature_hex": hex_encode(&signature.to_bytes()),
        }));
    }

    Ok(json!({
        "schema_version": PHASE10_PROVENANCE_SCHEMA_VERSION,
        "phase": "phase10",
        "generated_at_unix": generated_at_unix,
        "host_identity": host_identity,
        "command_digest_sha256": command_digest_sha256,
        "signer_key_id": signer_key_id,
        "verifier_key_hex": verifier_key_hex,
        "entries": entries,
    }))
}

fn object_string_field(
    object: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("{label} missing non-empty string field: {key}"))
}

fn object_u64_field(object: &Map<String, Value>, key: &str, label: &str) -> Result<u64, String> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label} missing positive integer field: {key}"))
}

fn verify_phase10_provenance_document(
    source_dir: &Path,
    out_dir: &Path,
    expected_host_identity: &str,
    verifier_key: &VerifyingKey,
    max_provenance_age_seconds: i64,
) -> Result<(), String> {
    let provenance_path = phase10_provenance_path(out_dir);
    let document = read_json_object(provenance_path.as_path(), "phase10 provenance attestation")?;
    if object_u64_field(
        &document,
        "schema_version",
        "phase10 provenance attestation",
    )? != PHASE10_PROVENANCE_SCHEMA_VERSION
    {
        return Err("phase10 provenance attestation schema_version mismatch".to_string());
    }
    if object_string_field(&document, "phase", "phase10 provenance attestation")? != "phase10" {
        return Err("phase10 provenance attestation must set phase=phase10".to_string());
    }
    let generated_at_unix = object_u64_field(
        &document,
        "generated_at_unix",
        "phase10 provenance attestation",
    )?;
    let now_unix =
        i64::try_from(unix_now()).map_err(|_| "current unix time out of range".to_string())?;
    let generated_at = i64::try_from(generated_at_unix)
        .map_err(|_| "generated_at_unix out of range".to_string())?;
    if generated_at > now_unix + 300 {
        return Err(
            "phase10 provenance attestation generated_at_unix is in the future".to_string(),
        );
    }
    if now_unix - generated_at > max_provenance_age_seconds {
        return Err("phase10 provenance attestation is stale".to_string());
    }

    let host_identity =
        object_string_field(&document, "host_identity", "phase10 provenance attestation")?;
    if host_identity != expected_host_identity {
        return Err("phase10 provenance host identity mismatch".to_string());
    }
    let command_digest = object_string_field(
        &document,
        "command_digest_sha256",
        "phase10 provenance attestation",
    )?;
    let expected_command_digest = sha256_hex(PHASE10_PROVENANCE_COMMAND_LITERAL.as_bytes());
    if command_digest != expected_command_digest {
        return Err("phase10 provenance command digest mismatch".to_string());
    }
    let signer_key_id =
        object_string_field(&document, "signer_key_id", "phase10 provenance attestation")?;
    let verifier_key_hex = object_string_field(
        &document,
        "verifier_key_hex",
        "phase10 provenance attestation",
    )?;
    if verifier_key_hex != hex_encode(verifier_key.as_bytes()) {
        return Err("phase10 provenance verifier key mismatch".to_string());
    }

    let mut expected = std::collections::BTreeMap::new();
    for (label, role, path, is_json) in phase10_expected_provenance_entries(source_dir, out_dir) {
        let canonical = canonical_file_display(path.as_path(), label)?;
        expected.insert(label.to_string(), (role.to_string(), canonical, is_json));
    }

    let entries = document
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "phase10 provenance attestation missing entries array".to_string())?;
    if entries.len() != expected.len() {
        return Err("phase10 provenance attestation entry count mismatch".to_string());
    }

    let mut seen = std::collections::BTreeSet::new();
    for entry in entries {
        let entry_obj = entry
            .as_object()
            .ok_or_else(|| "phase10 provenance entry must be a JSON object".to_string())?;
        let label = object_string_field(entry_obj, "label", "phase10 provenance entry")?;
        if !seen.insert(label.clone()) {
            return Err(format!(
                "phase10 provenance contains duplicate label: {label}"
            ));
        }
        let (expected_role, expected_path, is_json) = expected
            .get(label.as_str())
            .ok_or_else(|| format!("phase10 provenance contains unexpected label: {label}"))?
            .clone();

        let role = object_string_field(entry_obj, "role", "phase10 provenance entry")?;
        if role != expected_role {
            return Err(format!("phase10 provenance role mismatch for {label}"));
        }

        let artifact_path =
            object_string_field(entry_obj, "artifact_path", "phase10 provenance entry")?;
        if artifact_path != expected_path {
            return Err(format!("phase10 provenance path mismatch for {label}"));
        }
        let artifact_sha256 =
            object_string_field(entry_obj, "artifact_sha256", "phase10 provenance entry")?;
        let actual_sha256 = sha256_file_hex(Path::new(artifact_path.as_str()))?;
        if artifact_sha256 != actual_sha256 {
            return Err(format!("phase10 provenance digest mismatch for {label}"));
        }

        let captured_at_unix =
            object_u64_field(entry_obj, "captured_at_unix", "phase10 provenance entry")?;
        let captured_at = i64::try_from(captured_at_unix)
            .map_err(|_| format!("phase10 provenance captured_at_unix out of range for {label}"))?;
        if captured_at > now_unix + 300 {
            return Err(format!(
                "phase10 provenance captured_at_unix is in the future for {label}"
            ));
        }
        if now_unix - captured_at > max_provenance_age_seconds {
            return Err(format!(
                "phase10 provenance captured_at_unix is stale for {label}"
            ));
        }
        if is_json {
            let observed =
                phase10_json_captured_at_unix(Path::new(artifact_path.as_str()), label.as_str())?;
            if observed != captured_at_unix {
                return Err(format!(
                    "phase10 provenance captured_at_unix mismatch for {label}"
                ));
            }
        } else if captured_at_unix != generated_at_unix {
            return Err(format!(
                "phase10 provenance log captured_at_unix must match generated_at_unix for {label}"
            ));
        }

        let signature_hex =
            object_string_field(entry_obj, "signature_hex", "phase10 provenance entry")?;
        let signature_bytes = decode_hex_to_fixed::<64>(signature_hex.as_str()).map_err(|err| {
            format!("phase10 provenance signature parse failed for {label}: {err}")
        })?;
        let payload = phase10_provenance_payload(&Phase10ProvenancePayload {
            generated_at_unix,
            host_identity: host_identity.as_str(),
            command_digest_sha256: command_digest.as_str(),
            signer_key_id: signer_key_id.as_str(),
            verifier_key_hex: verifier_key_hex.as_str(),
            label: label.as_str(),
            role: role.as_str(),
            artifact_path: artifact_path.as_str(),
            artifact_sha256: artifact_sha256.as_str(),
            captured_at_unix,
        });
        let signature = Signature::from_bytes(&signature_bytes);
        verifier_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|_| format!("phase10 provenance signature verification failed for {label}"))?;
    }

    if seen.len() != expected.len() {
        return Err("phase10 provenance attestation missing required entries".to_string());
    }
    Ok(())
}

pub fn execute_ops_generate_phase9_artifacts() -> Result<String, String> {
    let raw_dir = path_from_env_or_default("RUSTYNET_PHASE9_RAW_DIR", DEFAULT_PHASE9_RAW_DIR)?;
    let out_dir = path_from_env_or_default("RUSTYNET_PHASE9_OUT_DIR", DEFAULT_PHASE9_OUT_DIR)?;
    let environment = required_env_string("RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT")?;
    fs::create_dir_all(out_dir.as_path()).map_err(|err| {
        format!(
            "create phase9 output directory failed ({}): {err}",
            out_dir.display()
        )
    })?;

    let captured_at_unix = unix_now();
    for filename in PHASE9_REQUIRED_ARTIFACTS {
        let source = raw_dir.join(filename);
        ensure_regular_file(source.as_path(), "raw phase9 evidence input")?;
        let mut document = read_json_object(source.as_path(), "raw phase9 evidence")?;
        document.remove("gate_passed");
        document.insert("evidence_mode".to_string(), json!("measured"));
        document.insert("captured_at_unix".to_string(), json!(captured_at_unix));
        document.insert("environment".to_string(), json!(environment.as_str()));
        document.insert(
            "source_artifacts".to_string(),
            json!([source.display().to_string()]),
        );

        let target = out_dir.join(filename);
        write_json_secure(target.as_path(), &Value::Object(document))?;
    }

    run_check_script(
        "./scripts/ci/check_phase9_readiness.sh",
        "phase9 readiness check",
    )?;
    Ok(format!(
        "phase9 artifacts generated and validated under: {}",
        out_dir.display()
    ))
}

pub fn execute_ops_generate_phase10_artifacts() -> Result<String, String> {
    let source_dir =
        path_from_env_or_default("RUSTYNET_PHASE10_SOURCE_DIR", DEFAULT_PHASE10_SOURCE_DIR)?;
    let out_dir = phase10_artifact_dir_from_env()?;
    let environment = required_env_string("RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT")?;
    let max_source_age_seconds = env_u64_with_default(
        "RUSTYNET_PHASE10_MAX_SOURCE_AGE_SECONDS",
        DEFAULT_PHASE10_MAX_SOURCE_AGE_SECONDS,
    )?;
    let max_source_age_seconds = i64::try_from(max_source_age_seconds)
        .map_err(|_| "RUSTYNET_PHASE10_MAX_SOURCE_AGE_SECONDS is too large".to_string())?;
    let max_provenance_age_seconds = env_u64_with_default(
        "RUSTYNET_PHASE10_MAX_PROVENANCE_AGE_SECONDS",
        DEFAULT_PHASE10_MAX_PROVENANCE_AGE_SECONDS,
    )?;
    let max_provenance_age_seconds = i64::try_from(max_provenance_age_seconds)
        .map_err(|_| "RUSTYNET_PHASE10_MAX_PROVENANCE_AGE_SECONDS is too large".to_string())?;
    ensure_phase10_provenance_keypair_exists()?;
    let provenance_host_identity = phase10_host_identity_from_env_or_default()?;
    let provenance_signing_key = load_phase10_signing_key()?;
    let provenance_verifier_key = load_phase10_verifier_key()?;
    let derived_verifier_key = provenance_signing_key.verifying_key();
    if derived_verifier_key.as_bytes() != provenance_verifier_key.as_bytes() {
        return Err(
            "phase10 provenance key mismatch: signing key does not match verifier key".to_string(),
        );
    }

    fs::create_dir_all(out_dir.as_path()).map_err(|err| {
        format!(
            "create phase10 output directory failed ({}): {err}",
            out_dir.display()
        )
    })?;

    let now_unix =
        i64::try_from(unix_now()).map_err(|_| "current unix time out of range".to_string())?;
    let captured_at_unix = now_unix;
    let captured_at_unix_u64 =
        u64::try_from(captured_at_unix).map_err(|_| "captured_at_unix out of range".to_string())?;

    let mut netns_payload = read_json_object(
        source_dir.join("netns_e2e_report.json").as_path(),
        "netns_e2e_report source",
    )?;
    let mut leak_payload = read_json_object(
        source_dir.join("leak_test_report.json").as_path(),
        "leak_test_report source",
    )?;
    let mut perf_payload = read_json_object(
        source_dir.join("perf_budget_report.json").as_path(),
        "perf_budget_report source",
    )?;
    let mut direct_payload = read_json_object(
        source_dir
            .join("direct_relay_failover_report.json")
            .as_path(),
        "direct_relay_failover_report source",
    )?;

    let netns_source = source_dir.join("netns_e2e_report.json");
    let leak_source = source_dir.join("leak_test_report.json");
    let perf_source = source_dir.join("perf_budget_report.json");
    let direct_source = source_dir.join("direct_relay_failover_report.json");

    ensure_regular_file(netns_source.as_path(), "raw phase10 evidence source")?;
    ensure_regular_file(leak_source.as_path(), "raw phase10 evidence source")?;
    ensure_regular_file(perf_source.as_path(), "raw phase10 evidence source")?;
    ensure_regular_file(direct_source.as_path(), "raw phase10 evidence source")?;

    for (payload, source, label) in [
        (&netns_payload, netns_source.as_path(), "netns_e2e_report"),
        (&leak_payload, leak_source.as_path(), "leak_test_report"),
        (&perf_payload, perf_source.as_path(), "perf_budget_report"),
        (
            &direct_payload,
            direct_source.as_path(),
            "direct_relay_failover_report",
        ),
    ] {
        phase10_require_measured_source(payload, source, label)?;
        let source_captured = phase10_require_positive_unix_timestamp(payload, source, label)?;
        phase10_validate_source_freshness(
            source_captured,
            source,
            label,
            now_unix,
            max_source_age_seconds,
        )?;
    }

    phase10_require_status_pass(&netns_payload, netns_source.as_path(), "netns_e2e_report")?;
    phase10_validate_checks_all_pass(&netns_payload, netns_source.as_path(), "netns_e2e_report")?;

    phase10_require_status_pass(&leak_payload, leak_source.as_path(), "leak_test_report")?;

    phase10_require_status_pass(
        &direct_payload,
        direct_source.as_path(),
        "direct_relay_failover_report",
    )?;
    phase10_validate_checks_all_pass(
        &direct_payload,
        direct_source.as_path(),
        "direct_relay_failover_report",
    )?;

    phase10_validate_perf_budget(&perf_payload, perf_source.as_path())?;

    for (payload, source, filename) in [
        (
            &mut netns_payload,
            netns_source.as_path(),
            "netns_e2e_report.json",
        ),
        (
            &mut leak_payload,
            leak_source.as_path(),
            "leak_test_report.json",
        ),
        (
            &mut perf_payload,
            perf_source.as_path(),
            "perf_budget_report.json",
        ),
        (
            &mut direct_payload,
            direct_source.as_path(),
            "direct_relay_failover_report.json",
        ),
    ] {
        payload.remove("gate_passed");
        payload.insert("phase".to_string(), json!("phase10"));
        payload.insert("evidence_mode".to_string(), json!("measured"));
        payload.insert("environment".to_string(), json!(environment.as_str()));
        payload.insert("captured_at_unix".to_string(), json!(captured_at_unix));
        payload.insert(
            "source_artifacts".to_string(),
            json!([source.display().to_string()]),
        );
        let target = out_dir.join(filename);
        write_json_secure(target.as_path(), &Value::Object(payload.clone()))?;
    }

    let state_source = source_dir.join("state_transition_audit.log");
    ensure_regular_file(state_source.as_path(), "raw phase10 evidence source")?;
    let state_body = fs::read_to_string(state_source.as_path()).map_err(|err| {
        format!(
            "read phase10 state transition source failed ({}): {err}",
            state_source.display()
        )
    })?;
    if !contains_generation_marker(state_body.as_str()) {
        return Err(format!(
            "state_transition_audit.log source missing generation entries: {}",
            state_source.display()
        ));
    }
    let state_target = out_dir.join("state_transition_audit.log");
    write_secure_bytes(state_target.as_path(), state_body.as_bytes())?;

    let provenance_document = build_phase10_provenance_document(
        source_dir.as_path(),
        out_dir.as_path(),
        captured_at_unix_u64,
        provenance_host_identity.as_str(),
        &provenance_signing_key,
        &provenance_verifier_key,
    )?;
    write_json_secure(
        phase10_provenance_path(out_dir.as_path()).as_path(),
        &provenance_document,
    )?;
    verify_phase10_provenance_document(
        source_dir.as_path(),
        out_dir.as_path(),
        provenance_host_identity.as_str(),
        &provenance_verifier_key,
        max_provenance_age_seconds,
    )?;
    run_check_script(
        "./scripts/ci/check_phase10_readiness.sh",
        "phase10 readiness check",
    )?;
    Ok(format!(
        "phase10 artifacts generated and validated under: {}",
        out_dir.display()
    ))
}

pub fn execute_ops_verify_phase10_provenance() -> Result<String, String> {
    let source_dir =
        path_from_env_or_default("RUSTYNET_PHASE10_SOURCE_DIR", DEFAULT_PHASE10_SOURCE_DIR)?;
    let out_dir = phase10_artifact_dir_from_env()?;
    let max_provenance_age_seconds = env_u64_with_default(
        "RUSTYNET_PHASE10_MAX_PROVENANCE_AGE_SECONDS",
        DEFAULT_PHASE10_MAX_PROVENANCE_AGE_SECONDS,
    )?;
    let max_provenance_age_seconds = i64::try_from(max_provenance_age_seconds)
        .map_err(|_| "RUSTYNET_PHASE10_MAX_PROVENANCE_AGE_SECONDS is too large".to_string())?;
    let host_identity = phase10_host_identity_from_env_or_default()?;
    let verifier_key = load_phase10_verifier_key()?;
    verify_phase10_provenance_document(
        source_dir.as_path(),
        out_dir.as_path(),
        host_identity.as_str(),
        &verifier_key,
        max_provenance_age_seconds,
    )?;
    Ok(format!(
        "phase10 provenance verification passed: {}",
        phase10_provenance_path(out_dir.as_path()).display()
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::SigningKey;

    use super::{
        contains_generation_marker, decode_hex_to_fixed, hex_encode, load_key_hex_from_secure_path,
        validate_phase10_host_identity, write_phase10_provenance_keypair,
    };

    #[test]
    fn generation_marker_parser_accepts_valid_tokens() {
        let body = "ts=1 generation=7 action=apply";
        assert!(contains_generation_marker(body));
    }

    #[test]
    fn generation_marker_parser_rejects_missing_or_non_numeric_tokens() {
        assert!(!contains_generation_marker("ts=1 generation= action=apply"));
        assert!(!contains_generation_marker(
            "ts=1 generation=abc action=apply"
        ));
        assert!(!contains_generation_marker("ts=1 action=apply"));
    }

    #[test]
    fn phase10_host_identity_validation_rejects_invalid_values() {
        assert!(validate_phase10_host_identity("prod-host-01").is_ok());
        assert!(validate_phase10_host_identity("prod host 01").is_err());
        assert!(validate_phase10_host_identity("prod#host").is_err());
        let oversized = "a".repeat(129);
        assert!(validate_phase10_host_identity(oversized.as_str()).is_err());
    }

    #[test]
    fn phase10_provenance_keypair_writer_sets_secure_permissions_and_matching_keys() {
        let unique = format!(
            "ops-phase10-provenance-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let key_dir = std::env::temp_dir().join(unique);
        let signing_path = key_dir.join("signing_seed.hex");
        let verifier_path = key_dir.join("verifier_key.hex");
        write_phase10_provenance_keypair(signing_path.as_path(), verifier_path.as_path())
            .expect("phase10 provenance keypair writer should succeed");

        let dir_mode = fs::metadata(key_dir.as_path())
            .expect("key directory metadata should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode & 0o077, 0);

        let signing_mode = fs::metadata(signing_path.as_path())
            .expect("signing key metadata should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(signing_mode & 0o077, 0);

        let verifier_mode = fs::metadata(verifier_path.as_path())
            .expect("verifier key metadata should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(verifier_mode & 0o077, 0);

        let signing_seed_hex =
            load_key_hex_from_secure_path(signing_path.as_path(), "test signing seed")
                .expect("signing seed should load");
        let verifier_key_hex =
            load_key_hex_from_secure_path(verifier_path.as_path(), "test verifier key")
                .expect("verifier key should load");
        let signing_seed =
            decode_hex_to_fixed::<32>(signing_seed_hex.as_str()).expect("seed hex should parse");
        let signing_key = SigningKey::from_bytes(&signing_seed);
        assert_eq!(
            hex_encode(signing_key.verifying_key().as_bytes()),
            verifier_key_hex
        );

        fs::remove_file(signing_path.as_path()).expect("remove signing key file");
        fs::remove_file(verifier_path.as_path()).expect("remove verifier key file");
        fs::remove_dir(key_dir.as_path()).expect("remove key directory");
    }
}
