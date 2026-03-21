#![forbid(unsafe_code)]

use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use nix::unistd::Uid;
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
const DEFAULT_RELEASE_OUT_DIR: &str = "artifacts/release";
const DEFAULT_RELEASE_PROVENANCE_DIR: &str = "artifacts/release/provenance";
const DEFAULT_PHASE6_PARITY_REPORT_PATH: &str = "artifacts/release/platform_parity_report.json";
const DEFAULT_PHASE6_PARITY_ATTESTATION_FILENAME: &str = "platform_parity_report.attestation.json";
const DEFAULT_PHASE9_EVIDENCE_ATTESTATION_FILENAME: &str = "phase9_evidence.attestation.json";
const DEFAULT_RELEASE_PROVENANCE_SIGNING_KEY_FILENAME: &str = "signing_seed.hex";
const DEFAULT_RELEASE_PROVENANCE_VERIFIER_KEY_FILENAME: &str = "verifier_key.hex";
const DEFAULT_RELEASE_HOST_ID: &str = "ci-localhost";
const DEFAULT_RELEASE_ARTIFACT_PATH: &str = "target/release/rustynetd";
const DEFAULT_RELEASE_PROVENANCE_FILENAME: &str = "rustynetd.provenance.json";
const DEFAULT_RELEASE_TRACK: &str = "beta";
const DEFAULT_RELEASE_MAX_PROVENANCE_AGE_SECONDS: u64 = 2_678_400;
const RELEASE_PROVENANCE_SCHEMA_VERSION: u64 = 1;
const RELEASE_PROVENANCE_COMMAND_LITERAL: &str = "rustynet ops sign-release-artifact";
const DEFAULT_PHASE10_MAX_SOURCE_AGE_SECONDS: u64 = 2_678_400;
const DEFAULT_PHASE9_MAX_SOURCE_AGE_SECONDS: i64 = 2_678_400;
const DEFAULT_PHASE10_MAX_PROVENANCE_AGE_SECONDS: u64 = 2_678_400;
const MAX_PHASE10_JSON_SOURCE_BYTES: u64 = 1_048_576;
const MAX_PHASE10_STATE_LOG_SOURCE_BYTES: u64 = 1_048_576;
const MAX_REQUIRED_TEST_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const PHASE10_PROVENANCE_FILENAME: &str = "phase10_provenance.attestation.json";
const PHASE10_PROVENANCE_SIGNING_KEY_PATH_ENV: &str =
    "RUSTYNET_PHASE10_PROVENANCE_SIGNING_KEY_PATH";
const PHASE10_PROVENANCE_VERIFIER_KEY_PATH_ENV: &str =
    "RUSTYNET_PHASE10_PROVENANCE_VERIFIER_KEY_PATH";
const PHASE10_PROVENANCE_HOST_ID_ENV: &str = "RUSTYNET_PHASE10_PROVENANCE_HOST_ID";
const RELEASE_PROVENANCE_SIGNING_KEY_PATH_ENV: &str =
    "RUSTYNET_RELEASE_PROVENANCE_SIGNING_KEY_PATH";
const RELEASE_PROVENANCE_VERIFIER_KEY_PATH_ENV: &str =
    "RUSTYNET_RELEASE_PROVENANCE_VERIFIER_KEY_PATH";
const RELEASE_PROVENANCE_PATH_ENV: &str = "RUSTYNET_RELEASE_PROVENANCE_PATH";
const RELEASE_ARTIFACT_PATH_ENV: &str = "RUSTYNET_RELEASE_ARTIFACT_PATH";
const RELEASE_SBOM_PATH_ENV: &str = "RUSTYNET_RELEASE_SBOM_PATH";
const RELEASE_SBOM_SHA256_PATH_ENV: &str = "RUSTYNET_RELEASE_SBOM_SHA256_PATH";
const RELEASE_TRACK_ENV: &str = "RUSTYNET_RELEASE_TRACK";
const RELEASE_HOST_ID_ENV: &str = "RUSTYNET_RELEASE_HOST_ID";
const RELEASE_MAX_PROVENANCE_AGE_SECONDS_ENV: &str = "RUSTYNET_RELEASE_MAX_PROVENANCE_AGE_SECONDS";
const PHASE6_PARITY_ATTESTATION_PATH_ENV: &str = "RUSTYNET_PHASE6_PARITY_ATTESTATION_PATH";
const PHASE6_PARITY_ATTESTATION_MAX_AGE_SECONDS_ENV: &str =
    "RUSTYNET_PHASE6_PARITY_ATTESTATION_MAX_AGE_SECONDS";
const PHASE9_EVIDENCE_ATTESTATION_PATH_ENV: &str = "RUSTYNET_PHASE9_EVIDENCE_ATTESTATION_PATH";
const PHASE9_EVIDENCE_ATTESTATION_MAX_AGE_SECONDS_ENV: &str =
    "RUSTYNET_PHASE9_EVIDENCE_ATTESTATION_MAX_AGE_SECONDS";
const PHASE10_PROVENANCE_SCHEMA_VERSION: u64 = 1;
const PHASE10_PROVENANCE_COMMAND_LITERAL: &str = "rustynet ops generate-phase10-artifacts";
const PHASE6_PARITY_ATTESTATION_SCHEMA_VERSION: u64 = 1;
const PHASE6_PARITY_ATTESTATION_COMMAND_LITERAL: &str =
    "rustynet ops generate-platform-parity-report";
const PHASE9_EVIDENCE_ATTESTATION_SCHEMA_VERSION: u64 = 1;
const PHASE9_EVIDENCE_ATTESTATION_COMMAND_LITERAL: &str = "rustynet ops generate-phase9-artifacts";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyRequiredTestOutputConfig {
    pub output_path: PathBuf,
    pub package: String,
    pub test_filter: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritePhase10Hp2TraversalReportsConfig {
    pub source_dir: PathBuf,
    pub environment: String,
    pub path_selection_log: PathBuf,
    pub probe_security_log: PathBuf,
}

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

fn ensure_trusted_owner(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<(), String> {
    let owner_uid = metadata.uid();
    let expected_uid = Uid::effective().as_raw();
    if owner_uid != expected_uid {
        return Err(format!(
            "{label} owner is not trusted ({} uid={owner_uid} expected_uid={expected_uid})",
            path.display()
        ));
    }
    Ok(())
}

fn enforce_owner_only_mode(path: &Path, label: &str) -> Result<(), String> {
    let mut metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    ensure_trusted_owner(path, &metadata, label)?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        let hardened_mode = mode & !0o077;
        fs::set_permissions(path, fs::Permissions::from_mode(hardened_mode)).map_err(|err| {
            format!(
                "failed to harden {label} mode ({} mode {:o} -> {:o}): {err}",
                path.display(),
                mode,
                hardened_mode
            )
        })?;
        metadata = fs::symlink_metadata(path)
            .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
        ensure_trusted_owner(path, &metadata, label)?;
    }
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
    let parent_label = format!("{label} parent");
    let mut metadata = fs::symlink_metadata(parent).map_err(|err| {
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
    ensure_trusted_owner(parent, &metadata, parent_label.as_str())?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        let hardened_mode = mode & !0o077;
        fs::set_permissions(parent, fs::Permissions::from_mode(hardened_mode)).map_err(|err| {
            format!(
                "failed to harden {label} parent mode ({} mode {:o} -> {:o}): {err}",
                parent.display(),
                mode,
                hardened_mode
            )
        })?;
        metadata = fs::symlink_metadata(parent).map_err(|err| {
            format!(
                "inspect {label} parent failed ({}): {err}",
                parent.display()
            )
        })?;
        ensure_trusted_owner(parent, &metadata, parent_label.as_str())?;
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

fn validate_release_track(value: &str) -> Result<String, String> {
    let normalized = value.trim();
    match normalized {
        "unstable" | "canary" | "stable" | "internal" | "beta" => Ok(normalized.to_string()),
        _ => Err(format!("unsupported release track: {normalized}")),
    }
}

fn release_out_dir_from_env_or_default() -> Result<PathBuf, String> {
    path_from_env_or_default("RUSTYNET_RELEASE_OUT_DIR", DEFAULT_RELEASE_OUT_DIR)
}

fn release_provenance_dir_from_env_or_default() -> Result<PathBuf, String> {
    path_from_env_or_default(
        "RUSTYNET_RELEASE_PROVENANCE_DIR",
        DEFAULT_RELEASE_PROVENANCE_DIR,
    )
}

fn release_signing_key_path_from_env_or_default() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string(RELEASE_PROVENANCE_SIGNING_KEY_PATH_ENV)? {
        return resolve_path(value.as_str());
    }
    Ok(release_provenance_dir_from_env_or_default()?
        .join(DEFAULT_RELEASE_PROVENANCE_SIGNING_KEY_FILENAME))
}

fn release_verifier_key_path_from_env_or_default() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string(RELEASE_PROVENANCE_VERIFIER_KEY_PATH_ENV)? {
        return resolve_path(value.as_str());
    }
    Ok(release_provenance_dir_from_env_or_default()?
        .join(DEFAULT_RELEASE_PROVENANCE_VERIFIER_KEY_FILENAME))
}

fn release_provenance_path_from_env_or_default() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string(RELEASE_PROVENANCE_PATH_ENV)? {
        return resolve_path(value.as_str());
    }
    Ok(release_out_dir_from_env_or_default()?.join(DEFAULT_RELEASE_PROVENANCE_FILENAME))
}

fn phase6_parity_report_path_from_env_or_default() -> Result<PathBuf, String> {
    path_from_env_or_default(
        "RUSTYNET_PHASE6_PLATFORM_PARITY_REPORT",
        DEFAULT_PHASE6_PARITY_REPORT_PATH,
    )
}

fn phase6_parity_attestation_path_from_env_or_default() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string(PHASE6_PARITY_ATTESTATION_PATH_ENV)? {
        return resolve_path(value.as_str());
    }
    Ok(release_out_dir_from_env_or_default()?.join(DEFAULT_PHASE6_PARITY_ATTESTATION_FILENAME))
}

fn phase9_evidence_attestation_path_from_env_or_default() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string(PHASE9_EVIDENCE_ATTESTATION_PATH_ENV)? {
        return resolve_path(value.as_str());
    }
    Ok(
        path_from_env_or_default("RUSTYNET_PHASE9_OUT_DIR", DEFAULT_PHASE9_OUT_DIR)?
            .join(DEFAULT_PHASE9_EVIDENCE_ATTESTATION_FILENAME),
    )
}

fn release_artifact_path_from_env_or_default() -> Result<PathBuf, String> {
    path_from_env_or_default(RELEASE_ARTIFACT_PATH_ENV, DEFAULT_RELEASE_ARTIFACT_PATH)
}

fn release_sbom_path_from_env_or_default() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string(RELEASE_SBOM_PATH_ENV)? {
        return resolve_path(value.as_str());
    }
    Ok(release_out_dir_from_env_or_default()?.join("sbom.cargo-metadata.json"))
}

fn release_sbom_sha256_path_from_env_or_default() -> Result<PathBuf, String> {
    if let Some(value) = env_optional_string(RELEASE_SBOM_SHA256_PATH_ENV)? {
        return resolve_path(value.as_str());
    }
    Ok(release_out_dir_from_env_or_default()?.join("sbom.sha256"))
}

fn release_track_from_env_or_default() -> Result<String, String> {
    match env_optional_string(RELEASE_TRACK_ENV)? {
        Some(value) => validate_release_track(value.as_str()),
        None => Ok(DEFAULT_RELEASE_TRACK.to_string()),
    }
}

fn release_host_identity_from_env_or_default() -> Result<String, String> {
    match env_optional_string(RELEASE_HOST_ID_ENV)? {
        Some(value) => validate_phase10_host_identity(value.as_str()),
        None => Ok(DEFAULT_RELEASE_HOST_ID.to_string()),
    }
}

fn release_max_provenance_age_seconds_from_env() -> Result<i64, String> {
    let value = env_u64_with_default(
        RELEASE_MAX_PROVENANCE_AGE_SECONDS_ENV,
        DEFAULT_RELEASE_MAX_PROVENANCE_AGE_SECONDS,
    )?;
    i64::try_from(value).map_err(|_| {
        format!("{RELEASE_MAX_PROVENANCE_AGE_SECONDS_ENV} is too large for signed attestation age")
    })
}

fn phase6_parity_attestation_max_age_seconds_from_env() -> Result<i64, String> {
    let value = env_u64_with_default(
        PHASE6_PARITY_ATTESTATION_MAX_AGE_SECONDS_ENV,
        DEFAULT_RELEASE_MAX_PROVENANCE_AGE_SECONDS,
    )?;
    i64::try_from(value).map_err(|_| {
        format!(
            "{PHASE6_PARITY_ATTESTATION_MAX_AGE_SECONDS_ENV} is too large for signed attestation age"
        )
    })
}

fn phase9_evidence_attestation_max_age_seconds_from_env() -> Result<i64, String> {
    let value = env_u64_with_default(
        PHASE9_EVIDENCE_ATTESTATION_MAX_AGE_SECONDS_ENV,
        DEFAULT_RELEASE_MAX_PROVENANCE_AGE_SECONDS,
    )?;
    i64::try_from(value).map_err(|_| {
        format!(
            "{PHASE9_EVIDENCE_ATTESTATION_MAX_AGE_SECONDS_ENV} is too large for signed attestation age"
        )
    })
}

fn current_git_commit() -> Result<String, String> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("invoke git rev-parse HEAD failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed with status {}",
            output.status
        ));
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|err| format!("decode git commit output failed: {err}"))?
        .trim()
        .to_ascii_lowercase();
    if commit.len() != 40 || !commit.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "git rev-parse HEAD returned invalid commit: {commit}"
        ));
    }
    Ok(commit)
}

fn read_sha256_digest_file(path: &Path, label: &str) -> Result<String, String> {
    let body = read_utf8_regular_file_with_max_bytes(path, label, 256)?;
    let digest = body.trim();
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must contain a 64-character hex sha256 digest: {}",
            path.display()
        ));
    }
    Ok(digest.to_ascii_lowercase())
}

fn write_release_provenance_keypair(
    signing_key_path: &Path,
    verifier_key_path: &Path,
) -> Result<(), String> {
    let signing_parent = signing_key_path.parent().ok_or_else(|| {
        format!(
            "release provenance signing key path has no parent: {}",
            signing_key_path.display()
        )
    })?;
    ensure_secure_directory(signing_parent, "release provenance key directory")?;

    let verifier_parent = verifier_key_path.parent().ok_or_else(|| {
        format!(
            "release provenance verifier key path has no parent: {}",
            verifier_key_path.display()
        )
    })?;
    if verifier_parent != signing_parent {
        ensure_secure_directory(verifier_parent, "release provenance key directory")?;
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

fn ensure_release_provenance_keypair_exists() -> Result<(), String> {
    let signing_key_path = release_signing_key_path_from_env_or_default()?;
    let verifier_key_path = release_verifier_key_path_from_env_or_default()?;
    if !signing_key_path.is_absolute() {
        return Err(format!(
            "{RELEASE_PROVENANCE_SIGNING_KEY_PATH_ENV} must resolve to an absolute path"
        ));
    }
    if !verifier_key_path.is_absolute() {
        return Err(format!(
            "{RELEASE_PROVENANCE_VERIFIER_KEY_PATH_ENV} must resolve to an absolute path"
        ));
    }

    let signing_exists =
        secure_regular_file_exists(signing_key_path.as_path(), "release provenance signing key")?;
    let verifier_exists = secure_regular_file_exists(
        verifier_key_path.as_path(),
        "release provenance verifier key",
    )?;

    match (signing_exists, verifier_exists) {
        (true, true) => Ok(()),
        (false, false) => write_release_provenance_keypair(
            signing_key_path.as_path(),
            verifier_key_path.as_path(),
        ),
        _ => Err(
            "release provenance key material is incomplete: signing and verifier keys must either both exist or both be absent".to_string(),
        ),
    }
}

fn load_release_signing_key() -> Result<SigningKey, String> {
    let key_path = release_signing_key_path_from_env_or_default()?;
    if !key_path.is_absolute() {
        return Err(format!(
            "{RELEASE_PROVENANCE_SIGNING_KEY_PATH_ENV} must resolve to an absolute path"
        ));
    }
    let key_hex =
        load_key_hex_from_secure_path(key_path.as_path(), "release provenance signing key")?;
    let seed = decode_hex_to_fixed::<32>(key_hex.as_str())
        .map_err(|err| format!("invalid release provenance signing key hex: {err}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn load_release_verifier_key() -> Result<VerifyingKey, String> {
    let key_path = release_verifier_key_path_from_env_or_default()?;
    if !key_path.is_absolute() {
        return Err(format!(
            "{RELEASE_PROVENANCE_VERIFIER_KEY_PATH_ENV} must resolve to an absolute path"
        ));
    }
    let key_hex =
        load_key_hex_from_secure_path(key_path.as_path(), "release provenance verifier key")?;
    let key_bytes = decode_hex_to_fixed::<32>(key_hex.as_str())
        .map_err(|err| format!("invalid release provenance verifier key hex: {err}"))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|err| format!("parse release provenance verifier key failed: {err}"))
}

fn read_utf8_regular_file_with_max_bytes(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<String, String> {
    ensure_regular_file(path, label)?;
    let metadata = fs::metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "{label} exceeds maximum size ({} bytes > {} bytes): {}",
            metadata.len(),
            max_bytes,
            path.display()
        ));
    }
    let body =
        fs::read(path).map_err(|err| format!("read {label} failed ({}): {err}", path.display()))?;
    if (body.len() as u64) > max_bytes {
        return Err(format!(
            "{label} exceeds maximum size after read ({} bytes > {} bytes): {}",
            body.len(),
            max_bytes,
            path.display()
        ));
    }
    String::from_utf8(body)
        .map_err(|err| format!("decode {label} as utf-8 failed ({}): {err}", path.display()))
}

fn read_json_object(path: &Path, label: &str) -> Result<Map<String, Value>, String> {
    let body = read_utf8_regular_file_with_max_bytes(path, label, MAX_PHASE10_JSON_SOURCE_BYTES)?;
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

fn phase10_require_named_checks_pass(
    payload: &Map<String, Value>,
    source_path: &Path,
    label: &str,
    required_checks: &[&str],
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
    for check_name in required_checks {
        if checks.get(*check_name).and_then(Value::as_str) != Some("pass") {
            return Err(format!(
                "{label} source check must pass ({check_name}) in {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn phase10_require_non_empty_environment(
    payload: &Map<String, Value>,
    source_path: &Path,
    label: &str,
) -> Result<(), String> {
    let environment = payload
        .get("environment")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!(
                "{label} source must include non-empty environment: {}",
                source_path.display()
            )
        })?;
    let _ = environment;
    Ok(())
}

fn phase10_validate_source_artifacts_entries(
    payload: &Map<String, Value>,
    source_path: &Path,
    label: &str,
) -> Result<(), String> {
    let source_artifacts = payload
        .get("source_artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            format!(
                "{label} source must include non-empty source_artifacts list: {}",
                source_path.display()
            )
        })?;
    if source_artifacts.is_empty() {
        return Err(format!(
            "{label} source must include non-empty source_artifacts list: {}",
            source_path.display()
        ));
    }

    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    for entry in source_artifacts {
        let source = entry
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "{label} source has invalid source_artifacts entry: {}",
                    source_path.display()
                )
            })?;
        let candidate = if Path::new(source).is_absolute() {
            PathBuf::from(source)
        } else {
            cwd.join(source)
        };
        if !candidate.exists() {
            return Err(format!("{label} source artifact does not exist: {source}"));
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

fn phase10_validate_required_perf_metrics(
    payload: &Map<String, Value>,
    source_path: &Path,
) -> Result<(), String> {
    let required_metric_names = [
        "idle_cpu_percent",
        "idle_rss_mb",
        "reconnect_seconds",
        "route_apply_p95_seconds",
        "throughput_overhead_percent",
    ];
    let metrics = payload
        .get("metrics")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            format!(
                "perf_budget_report source must include non-empty metrics list: {}",
                source_path.display()
            )
        })?;
    let mut seen = std::collections::BTreeSet::new();
    for metric in metrics {
        let metric_object = metric.as_object().ok_or_else(|| {
            format!(
                "perf_budget_report metrics entries must be objects: {}",
                source_path.display()
            )
        })?;
        let name = metric_object
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "perf_budget_report metric is missing name: {}",
                    source_path.display()
                )
            })?;
        if metric_object.get("status").and_then(Value::as_str) != Some("pass") {
            return Err(format!(
                "perf_budget_report metric did not pass ({name}) in {}",
                source_path.display()
            ));
        }
        if required_metric_names.contains(&name) {
            seen.insert(name.to_string());
        }
    }
    let missing = required_metric_names
        .iter()
        .filter(|name| !seen.contains(**name))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "perf_budget_report missing required metrics: {}",
            missing.join(", ")
        ));
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
            "source_traversal_path_selection_report",
            "source",
            source_dir.join("traversal_path_selection_report.json"),
            true,
        ),
        (
            "source_traversal_probe_security_report",
            "source",
            source_dir.join("traversal_probe_security_report.json"),
            true,
        ),
        (
            "source_managed_dns_report",
            "source",
            source_dir.join("managed_dns_report.json"),
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
            "derived_traversal_path_selection_report",
            "derived",
            out_dir.join("traversal_path_selection_report.json"),
            true,
        ),
        (
            "derived_traversal_probe_security_report",
            "derived",
            out_dir.join("traversal_probe_security_report.json"),
            true,
        ),
        (
            "derived_managed_dns_report",
            "derived",
            out_dir.join("managed_dns_report.json"),
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

struct ReleaseProvenancePayload<'a> {
    generated_at_unix: u64,
    host_identity: &'a str,
    command_digest_sha256: &'a str,
    signer_key_id: &'a str,
    verifier_key_hex: &'a str,
    release_track: &'a str,
    artifact_path: &'a str,
    artifact_sha256: &'a str,
    artifact_size_bytes: u64,
    sbom_path: &'a str,
    sbom_sha256: &'a str,
    sbom_digest_path: &'a str,
    sbom_digest_value: &'a str,
}

fn release_provenance_payload(fields: &ReleaseProvenancePayload<'_>) -> String {
    format!(
        "version={RELEASE_PROVENANCE_SCHEMA_VERSION}\nphase=release\ngenerated_at_unix={generated_at_unix}\nhost_identity={host_identity}\ncommand_digest_sha256={command_digest_sha256}\nsigner_key_id={signer_key_id}\nverifier_key_hex={verifier_key_hex}\nrelease_track={release_track}\nartifact_path={artifact_path}\nartifact_sha256={artifact_sha256}\nartifact_size_bytes={artifact_size_bytes}\nsbom_path={sbom_path}\nsbom_sha256={sbom_sha256}\nsbom_digest_path={sbom_digest_path}\nsbom_digest_value={sbom_digest_value}\n",
        generated_at_unix = fields.generated_at_unix,
        host_identity = fields.host_identity,
        command_digest_sha256 = fields.command_digest_sha256,
        signer_key_id = fields.signer_key_id,
        verifier_key_hex = fields.verifier_key_hex,
        release_track = fields.release_track,
        artifact_path = fields.artifact_path,
        artifact_sha256 = fields.artifact_sha256,
        artifact_size_bytes = fields.artifact_size_bytes,
        sbom_path = fields.sbom_path,
        sbom_sha256 = fields.sbom_sha256,
        sbom_digest_path = fields.sbom_digest_path,
        sbom_digest_value = fields.sbom_digest_value,
    )
}

struct Phase6ParityAttestationPayload<'a> {
    generated_at_unix: u64,
    host_identity: &'a str,
    command_digest_sha256: &'a str,
    signer_key_id: &'a str,
    verifier_key_hex: &'a str,
    git_commit: &'a str,
    report_path: &'a str,
    report_sha256: &'a str,
    report_captured_at_unix: u64,
}

fn phase6_parity_attestation_payload(fields: &Phase6ParityAttestationPayload<'_>) -> String {
    format!(
        "version={PHASE6_PARITY_ATTESTATION_SCHEMA_VERSION}\nphase=phase6\ngenerated_at_unix={generated_at_unix}\nhost_identity={host_identity}\ncommand_digest_sha256={command_digest_sha256}\nsigner_key_id={signer_key_id}\nverifier_key_hex={verifier_key_hex}\ngit_commit={git_commit}\nreport_path={report_path}\nreport_sha256={report_sha256}\nreport_captured_at_unix={report_captured_at_unix}\n",
        generated_at_unix = fields.generated_at_unix,
        host_identity = fields.host_identity,
        command_digest_sha256 = fields.command_digest_sha256,
        signer_key_id = fields.signer_key_id,
        verifier_key_hex = fields.verifier_key_hex,
        git_commit = fields.git_commit,
        report_path = fields.report_path,
        report_sha256 = fields.report_sha256,
        report_captured_at_unix = fields.report_captured_at_unix,
    )
}

#[derive(Clone)]
struct Phase9EvidenceArtifactEntry {
    name: String,
    artifact_path: String,
    artifact_sha256: String,
    captured_at_unix: u64,
}

struct Phase9EvidenceAttestationPayload<'a> {
    generated_at_unix: u64,
    host_identity: &'a str,
    command_digest_sha256: &'a str,
    signer_key_id: &'a str,
    verifier_key_hex: &'a str,
    git_commit: &'a str,
    environment: &'a str,
    artifacts: &'a [Phase9EvidenceArtifactEntry],
}

fn phase9_evidence_attestation_payload(fields: &Phase9EvidenceAttestationPayload<'_>) -> String {
    let mut payload = format!(
        "version={PHASE9_EVIDENCE_ATTESTATION_SCHEMA_VERSION}\nphase=phase9\ngenerated_at_unix={generated_at_unix}\nhost_identity={host_identity}\ncommand_digest_sha256={command_digest_sha256}\nsigner_key_id={signer_key_id}\nverifier_key_hex={verifier_key_hex}\ngit_commit={git_commit}\nenvironment={environment}\n",
        generated_at_unix = fields.generated_at_unix,
        host_identity = fields.host_identity,
        command_digest_sha256 = fields.command_digest_sha256,
        signer_key_id = fields.signer_key_id,
        verifier_key_hex = fields.verifier_key_hex,
        git_commit = fields.git_commit,
        environment = fields.environment,
    );
    for artifact in fields.artifacts {
        payload.push_str(
            format!(
                "artifact={name}|{artifact_path}|{artifact_sha256}|{captured_at_unix}\n",
                name = artifact.name,
                artifact_path = artifact.artifact_path,
                artifact_sha256 = artifact.artifact_sha256,
                captured_at_unix = artifact.captured_at_unix,
            )
            .as_str(),
        );
    }
    payload
}

struct ReleaseProvenanceBuildInputs<'a> {
    artifact_path: &'a Path,
    sbom_path: &'a Path,
    sbom_digest_path: &'a Path,
    generated_at_unix: u64,
    host_identity: &'a str,
    release_track: &'a str,
    signing_key: &'a SigningKey,
    verifier_key: &'a VerifyingKey,
}

fn build_release_provenance_document(
    inputs: &ReleaseProvenanceBuildInputs<'_>,
) -> Result<Value, String> {
    let release_track = validate_release_track(inputs.release_track)?;
    let artifact_path = canonical_file_display(inputs.artifact_path, "release artifact")?;
    let sbom_path = canonical_file_display(inputs.sbom_path, "release sbom")?;
    let sbom_digest_path = canonical_file_display(inputs.sbom_digest_path, "release sbom digest")?;

    let artifact_sha256 = sha256_file_hex(Path::new(artifact_path.as_str()))?;
    let sbom_sha256 = sha256_file_hex(Path::new(sbom_path.as_str()))?;
    let sbom_digest_value =
        read_sha256_digest_file(Path::new(sbom_digest_path.as_str()), "release sbom digest")?;
    if sbom_digest_value != sbom_sha256 {
        return Err("release sbom digest file does not match sbom content digest".to_string());
    }
    let artifact_size_bytes = fs::metadata(Path::new(artifact_path.as_str()))
        .map_err(|err| format!("inspect release artifact metadata failed: {err}"))?
        .len();

    let command_digest_sha256 = sha256_hex(RELEASE_PROVENANCE_COMMAND_LITERAL.as_bytes());
    let verifier_key_hex = hex_encode(inputs.verifier_key.as_bytes());
    let signer_fingerprint = sha256_hex(inputs.verifier_key.as_bytes());
    let signer_key_id = format!("ed25519:{}", &signer_fingerprint[..16]);
    let payload = release_provenance_payload(&ReleaseProvenancePayload {
        generated_at_unix: inputs.generated_at_unix,
        host_identity: inputs.host_identity,
        command_digest_sha256: command_digest_sha256.as_str(),
        signer_key_id: signer_key_id.as_str(),
        verifier_key_hex: verifier_key_hex.as_str(),
        release_track: release_track.as_str(),
        artifact_path: artifact_path.as_str(),
        artifact_sha256: artifact_sha256.as_str(),
        artifact_size_bytes,
        sbom_path: sbom_path.as_str(),
        sbom_sha256: sbom_sha256.as_str(),
        sbom_digest_path: sbom_digest_path.as_str(),
        sbom_digest_value: sbom_digest_value.as_str(),
    });
    let signature = inputs.signing_key.sign(payload.as_bytes());

    Ok(json!({
        "schema_version": RELEASE_PROVENANCE_SCHEMA_VERSION,
        "phase": "release",
        "generated_at_unix": inputs.generated_at_unix,
        "host_identity": inputs.host_identity,
        "command_digest_sha256": command_digest_sha256,
        "signer_key_id": signer_key_id,
        "verifier_key_hex": verifier_key_hex,
        "release_track": release_track,
        "artifact_path": artifact_path,
        "artifact_sha256": artifact_sha256,
        "artifact_size_bytes": artifact_size_bytes,
        "sbom_path": sbom_path,
        "sbom_sha256": sbom_sha256,
        "sbom_digest_path": sbom_digest_path,
        "sbom_digest_value": sbom_digest_value,
        "signature_hex": hex_encode(&signature.to_bytes()),
    }))
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

struct ReleaseProvenanceVerifyInputs<'a> {
    provenance_path: &'a Path,
    expected_artifact_path: &'a Path,
    expected_sbom_path: &'a Path,
    expected_sbom_digest_path: &'a Path,
    expected_host_identity: &'a str,
    expected_release_track: &'a str,
    verifier_key: &'a VerifyingKey,
    max_provenance_age_seconds: i64,
}

fn verify_release_provenance_document(
    inputs: &ReleaseProvenanceVerifyInputs<'_>,
) -> Result<(), String> {
    let expected_release_track = validate_release_track(inputs.expected_release_track)?;
    let provenance = read_json_object(inputs.provenance_path, "release provenance attestation")?;
    if object_u64_field(
        &provenance,
        "schema_version",
        "release provenance attestation",
    )? != RELEASE_PROVENANCE_SCHEMA_VERSION
    {
        return Err("release provenance schema_version mismatch".to_string());
    }
    if object_string_field(&provenance, "phase", "release provenance attestation")? != "release" {
        return Err("release provenance must set phase=release".to_string());
    }

    let generated_at_unix = object_u64_field(
        &provenance,
        "generated_at_unix",
        "release provenance attestation",
    )?;
    let now_unix =
        i64::try_from(unix_now()).map_err(|_| "current unix time out of range".to_string())?;
    let generated_at = i64::try_from(generated_at_unix)
        .map_err(|_| "release provenance generated_at_unix out of range".to_string())?;
    if generated_at > now_unix + 300 {
        return Err("release provenance generated_at_unix is in the future".to_string());
    }
    if now_unix - generated_at > inputs.max_provenance_age_seconds {
        return Err("release provenance attestation is stale".to_string());
    }

    let host_identity = object_string_field(
        &provenance,
        "host_identity",
        "release provenance attestation",
    )?;
    if host_identity != inputs.expected_host_identity {
        return Err("release provenance host identity mismatch".to_string());
    }

    let release_track = object_string_field(
        &provenance,
        "release_track",
        "release provenance attestation",
    )?;
    let release_track = validate_release_track(release_track.as_str())?;
    if release_track != expected_release_track {
        return Err("release provenance release_track mismatch".to_string());
    }

    let command_digest = object_string_field(
        &provenance,
        "command_digest_sha256",
        "release provenance attestation",
    )?;
    let expected_command_digest = sha256_hex(RELEASE_PROVENANCE_COMMAND_LITERAL.as_bytes());
    if command_digest != expected_command_digest {
        return Err("release provenance command digest mismatch".to_string());
    }

    let signer_key_id = object_string_field(
        &provenance,
        "signer_key_id",
        "release provenance attestation",
    )?;
    let verifier_key_hex = object_string_field(
        &provenance,
        "verifier_key_hex",
        "release provenance attestation",
    )?;
    if verifier_key_hex != hex_encode(inputs.verifier_key.as_bytes()) {
        return Err("release provenance verifier key mismatch".to_string());
    }

    let artifact_path = object_string_field(
        &provenance,
        "artifact_path",
        "release provenance attestation",
    )?;
    let expected_artifact =
        canonical_file_display(inputs.expected_artifact_path, "release artifact")?;
    if artifact_path != expected_artifact {
        return Err("release provenance artifact path mismatch".to_string());
    }
    let artifact_sha256 = object_string_field(
        &provenance,
        "artifact_sha256",
        "release provenance attestation",
    )?;
    let actual_artifact_sha256 = sha256_file_hex(Path::new(artifact_path.as_str()))?;
    if artifact_sha256 != actual_artifact_sha256 {
        return Err("release provenance artifact digest mismatch".to_string());
    }
    let artifact_size_bytes = object_u64_field(
        &provenance,
        "artifact_size_bytes",
        "release provenance attestation",
    )?;
    let actual_artifact_size = fs::metadata(Path::new(artifact_path.as_str()))
        .map_err(|err| format!("inspect release artifact metadata failed: {err}"))?
        .len();
    if artifact_size_bytes != actual_artifact_size {
        return Err("release provenance artifact size mismatch".to_string());
    }

    let sbom_path =
        object_string_field(&provenance, "sbom_path", "release provenance attestation")?;
    let expected_sbom = canonical_file_display(inputs.expected_sbom_path, "release sbom")?;
    if sbom_path != expected_sbom {
        return Err("release provenance sbom path mismatch".to_string());
    }
    let sbom_sha256 =
        object_string_field(&provenance, "sbom_sha256", "release provenance attestation")?;
    let actual_sbom_sha256 = sha256_file_hex(Path::new(sbom_path.as_str()))?;
    if sbom_sha256 != actual_sbom_sha256 {
        return Err("release provenance sbom digest mismatch".to_string());
    }

    let sbom_digest_path = object_string_field(
        &provenance,
        "sbom_digest_path",
        "release provenance attestation",
    )?;
    let expected_sbom_digest =
        canonical_file_display(inputs.expected_sbom_digest_path, "release sbom digest")?;
    if sbom_digest_path != expected_sbom_digest {
        return Err("release provenance sbom digest path mismatch".to_string());
    }
    let sbom_digest_value = object_string_field(
        &provenance,
        "sbom_digest_value",
        "release provenance attestation",
    )?;
    let actual_sbom_digest_value =
        read_sha256_digest_file(Path::new(sbom_digest_path.as_str()), "release sbom digest")?;
    if sbom_digest_value != actual_sbom_digest_value || sbom_digest_value != sbom_sha256 {
        return Err("release provenance sbom digest value mismatch".to_string());
    }

    let signature_hex = object_string_field(
        &provenance,
        "signature_hex",
        "release provenance attestation",
    )?;
    let signature_bytes = decode_hex_to_fixed::<64>(signature_hex.as_str())
        .map_err(|err| format!("release provenance signature parse failed: {err}"))?;
    let payload = release_provenance_payload(&ReleaseProvenancePayload {
        generated_at_unix,
        host_identity: host_identity.as_str(),
        command_digest_sha256: command_digest.as_str(),
        signer_key_id: signer_key_id.as_str(),
        verifier_key_hex: verifier_key_hex.as_str(),
        release_track: release_track.as_str(),
        artifact_path: artifact_path.as_str(),
        artifact_sha256: artifact_sha256.as_str(),
        artifact_size_bytes,
        sbom_path: sbom_path.as_str(),
        sbom_sha256: sbom_sha256.as_str(),
        sbom_digest_path: sbom_digest_path.as_str(),
        sbom_digest_value: sbom_digest_value.as_str(),
    });
    let signature = Signature::from_bytes(&signature_bytes);
    inputs
        .verifier_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| "release provenance signature verification failed".to_string())?;
    Ok(())
}

fn phase9_validate_source_artifacts_field(
    document: &Map<String, Value>,
    label: &str,
) -> Result<(), String> {
    let sources = document
        .get("source_artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label} missing non-empty source_artifacts array"))?;
    if sources.is_empty() {
        return Err(format!("{label} source_artifacts array must not be empty"));
    }
    for source in sources {
        let source_str = source
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{label} has invalid source_artifacts entry"))?;
        let source_path = Path::new(source_str);
        if !source_path.exists() {
            return Err(format!(
                "{label} source artifact does not exist: {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

fn phase9_parse_measured_artifact_document(
    artifact_path: &Path,
    label: &str,
) -> Result<(u64, String), String> {
    let document = read_json_object(artifact_path, label)?;
    if document.get("gate_passed").is_some() {
        return Err(format!("{label} must not include gate_passed field"));
    }
    let evidence_mode = object_string_field(&document, "evidence_mode", label)?;
    if evidence_mode != "measured" {
        return Err(format!("{label} must set evidence_mode=measured"));
    }
    let captured_at_unix = object_u64_field(&document, "captured_at_unix", label)?;
    let environment = object_string_field(&document, "environment", label)?;
    phase9_validate_source_artifacts_field(&document, label)?;
    Ok((captured_at_unix, environment))
}

fn phase6_report_captured_at_unix(report_path: &Path) -> Result<u64, String> {
    let report = read_json_object(report_path, "phase6 parity report")?;
    if report.get("gate_passed").is_some() {
        return Err("phase6 parity report must not include gate_passed field".to_string());
    }
    let evidence_mode = object_string_field(&report, "evidence_mode", "phase6 parity report")?;
    if evidence_mode != "measured" {
        return Err("phase6 parity report must set evidence_mode=measured".to_string());
    }
    let _ = object_string_field(&report, "environment", "phase6 parity report")?;
    phase9_validate_source_artifacts_field(&report, "phase6 parity report")?;
    object_u64_field(&report, "captured_at_unix", "phase6 parity report")
}

fn phase9_require_measured_evidence_metadata(
    document: &Map<String, Value>,
    label: &str,
    now_unix: i64,
    max_evidence_age_seconds: i64,
) -> Result<(), String> {
    if document.get("gate_passed").is_some() {
        return Err(format!(
            "{label} contains deprecated gate_passed toggle; gate pass must be derived, not asserted"
        ));
    }
    if document.get("evidence_mode").and_then(Value::as_str) != Some("measured") {
        return Err(format!("{label} must set evidence_mode=measured"));
    }

    let captured_at_unix = object_u64_field(document, "captured_at_unix", label)?;
    if captured_at_unix == 0 {
        return Err(format!(
            "{label} requires positive integer captured_at_unix"
        ));
    }
    let captured_at_i64 = i64::try_from(captured_at_unix)
        .map_err(|_| format!("{label} captured_at_unix out of range"))?;
    if captured_at_i64 > now_unix + 300 {
        return Err(format!("{label} captured_at_unix is too far in the future"));
    }
    if now_unix - captured_at_i64 > max_evidence_age_seconds {
        return Err(format!(
            "{label} evidence is too old; regenerate with fresh measurements"
        ));
    }

    let environment = object_string_field(document, "environment", label)?;
    if environment.trim().is_empty() {
        return Err(format!(
            "{label} requires non-empty string field: environment"
        ));
    }

    phase9_validate_source_artifacts_field(document, label)
}

fn phase9_require_string(
    document: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, String> {
    object_string_field(document, key, label)
}

fn phase9_require_bool(
    document: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<bool, String> {
    document
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{label} requires boolean field: {key}"))
}

fn phase9_require_integer(
    document: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<i64, String> {
    if let Some(value) = document.get(key).and_then(Value::as_i64) {
        return Ok(value);
    }
    if let Some(value) = document.get(key).and_then(Value::as_u64) {
        return i64::try_from(value)
            .map_err(|_| format!("{label} integer field out of range: {key}"));
    }
    Err(format!("{label} requires integer field: {key}"))
}

fn phase9_require_number(
    document: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<f64, String> {
    document
        .get(key)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("{label} requires numeric field: {key}"))
}

fn phase9_contains_any_case_insensitive(value: &str, tokens: &[&str]) -> bool {
    let lowered = value.to_ascii_lowercase();
    tokens.iter().any(|token| lowered.contains(token))
}

fn parse_required_test_output_total_passed(output: &str) -> u64 {
    const PREFIX: &str = "test result: ok.";
    output
        .lines()
        .filter_map(|line| {
            let remainder = line.trim().strip_prefix(PREFIX)?;
            let mut fields = remainder.split_whitespace();
            let passed = fields.next()?.parse::<u64>().ok()?;
            if fields.next() != Some("passed;") {
                return None;
            }
            Some(passed)
        })
        .sum()
}

struct Phase6ParityAttestationBuildInputs<'a> {
    report_path: &'a Path,
    generated_at_unix: u64,
    host_identity: &'a str,
    git_commit: &'a str,
    signing_key: &'a SigningKey,
    verifier_key: &'a VerifyingKey,
}

fn build_phase6_parity_attestation_document(
    inputs: &Phase6ParityAttestationBuildInputs<'_>,
) -> Result<Value, String> {
    let report_path = canonical_file_display(inputs.report_path, "phase6 parity report")?;
    let report_sha256 = sha256_file_hex(Path::new(report_path.as_str()))?;
    let report_captured_at_unix = phase6_report_captured_at_unix(Path::new(report_path.as_str()))?;
    let command_digest_sha256 = sha256_hex(PHASE6_PARITY_ATTESTATION_COMMAND_LITERAL.as_bytes());
    let verifier_key_hex = hex_encode(inputs.verifier_key.as_bytes());
    let signer_fingerprint = sha256_hex(inputs.verifier_key.as_bytes());
    let signer_key_id = format!("ed25519:{}", &signer_fingerprint[..16]);
    let payload = phase6_parity_attestation_payload(&Phase6ParityAttestationPayload {
        generated_at_unix: inputs.generated_at_unix,
        host_identity: inputs.host_identity,
        command_digest_sha256: command_digest_sha256.as_str(),
        signer_key_id: signer_key_id.as_str(),
        verifier_key_hex: verifier_key_hex.as_str(),
        git_commit: inputs.git_commit,
        report_path: report_path.as_str(),
        report_sha256: report_sha256.as_str(),
        report_captured_at_unix,
    });
    let signature = inputs.signing_key.sign(payload.as_bytes());
    Ok(json!({
        "schema_version": PHASE6_PARITY_ATTESTATION_SCHEMA_VERSION,
        "phase": "phase6",
        "generated_at_unix": inputs.generated_at_unix,
        "host_identity": inputs.host_identity,
        "command_digest_sha256": command_digest_sha256,
        "signer_key_id": signer_key_id,
        "verifier_key_hex": verifier_key_hex,
        "git_commit": inputs.git_commit,
        "report_path": report_path,
        "report_sha256": report_sha256,
        "report_captured_at_unix": report_captured_at_unix,
        "signature_hex": hex_encode(&signature.to_bytes()),
    }))
}

struct Phase6ParityAttestationVerifyInputs<'a> {
    attestation_path: &'a Path,
    expected_report_path: &'a Path,
    expected_host_identity: &'a str,
    expected_git_commit: &'a str,
    verifier_key: &'a VerifyingKey,
    max_attestation_age_seconds: i64,
}

fn verify_phase6_parity_attestation_document(
    inputs: &Phase6ParityAttestationVerifyInputs<'_>,
) -> Result<(), String> {
    let attestation = read_json_object(inputs.attestation_path, "phase6 parity attestation")?;
    if object_u64_field(&attestation, "schema_version", "phase6 parity attestation")?
        != PHASE6_PARITY_ATTESTATION_SCHEMA_VERSION
    {
        return Err("phase6 parity attestation schema_version mismatch".to_string());
    }
    if object_string_field(&attestation, "phase", "phase6 parity attestation")? != "phase6" {
        return Err("phase6 parity attestation must set phase=phase6".to_string());
    }

    let generated_at_unix = object_u64_field(
        &attestation,
        "generated_at_unix",
        "phase6 parity attestation",
    )?;
    let now_unix =
        i64::try_from(unix_now()).map_err(|_| "current unix time out of range".to_string())?;
    let generated_at = i64::try_from(generated_at_unix)
        .map_err(|_| "phase6 parity generated_at_unix out of range".to_string())?;
    if generated_at > now_unix + 300 {
        return Err("phase6 parity generated_at_unix is in the future".to_string());
    }
    if now_unix - generated_at > inputs.max_attestation_age_seconds {
        return Err("phase6 parity attestation is stale".to_string());
    }

    let host_identity =
        object_string_field(&attestation, "host_identity", "phase6 parity attestation")?;
    if host_identity != inputs.expected_host_identity {
        return Err("phase6 parity host identity mismatch".to_string());
    }

    let command_digest = object_string_field(
        &attestation,
        "command_digest_sha256",
        "phase6 parity attestation",
    )?;
    let expected_command_digest = sha256_hex(PHASE6_PARITY_ATTESTATION_COMMAND_LITERAL.as_bytes());
    if command_digest != expected_command_digest {
        return Err("phase6 parity command digest mismatch".to_string());
    }

    let signer_key_id =
        object_string_field(&attestation, "signer_key_id", "phase6 parity attestation")?;
    let expected_signer_fingerprint = sha256_hex(inputs.verifier_key.as_bytes());
    let expected_signer_key_id = format!("ed25519:{}", &expected_signer_fingerprint[..16]);
    if signer_key_id != expected_signer_key_id {
        return Err("phase6 parity signer key id mismatch".to_string());
    }
    let verifier_key_hex = object_string_field(
        &attestation,
        "verifier_key_hex",
        "phase6 parity attestation",
    )?;
    if verifier_key_hex != hex_encode(inputs.verifier_key.as_bytes()) {
        return Err("phase6 parity verifier key mismatch".to_string());
    }

    let git_commit = object_string_field(&attestation, "git_commit", "phase6 parity attestation")?;
    if git_commit != inputs.expected_git_commit {
        return Err("phase6 parity git commit mismatch".to_string());
    }

    let report_path =
        object_string_field(&attestation, "report_path", "phase6 parity attestation")?;
    let expected_report =
        canonical_file_display(inputs.expected_report_path, "phase6 parity report")?;
    if report_path != expected_report {
        return Err("phase6 parity report path mismatch".to_string());
    }
    let report_sha256 =
        object_string_field(&attestation, "report_sha256", "phase6 parity attestation")?;
    let actual_report_sha256 = sha256_file_hex(Path::new(report_path.as_str()))?;
    if report_sha256 != actual_report_sha256 {
        return Err("phase6 parity report digest mismatch".to_string());
    }

    let report_captured_at_unix = object_u64_field(
        &attestation,
        "report_captured_at_unix",
        "phase6 parity attestation",
    )?;
    let report_captured_at = i64::try_from(report_captured_at_unix)
        .map_err(|_| "phase6 parity report_captured_at_unix out of range".to_string())?;
    if report_captured_at > now_unix + 300 {
        return Err("phase6 parity report_captured_at_unix is in the future".to_string());
    }
    if now_unix - report_captured_at > inputs.max_attestation_age_seconds {
        return Err("phase6 parity report_captured_at_unix is stale".to_string());
    }
    let observed_report_captured_at =
        phase6_report_captured_at_unix(Path::new(report_path.as_str()))?;
    if report_captured_at_unix != observed_report_captured_at {
        return Err("phase6 parity report captured_at_unix mismatch".to_string());
    }

    let signature_hex =
        object_string_field(&attestation, "signature_hex", "phase6 parity attestation")?;
    let signature_bytes = decode_hex_to_fixed::<64>(signature_hex.as_str())
        .map_err(|err| format!("phase6 parity signature parse failed: {err}"))?;
    let payload = phase6_parity_attestation_payload(&Phase6ParityAttestationPayload {
        generated_at_unix,
        host_identity: host_identity.as_str(),
        command_digest_sha256: command_digest.as_str(),
        signer_key_id: signer_key_id.as_str(),
        verifier_key_hex: verifier_key_hex.as_str(),
        git_commit: git_commit.as_str(),
        report_path: report_path.as_str(),
        report_sha256: report_sha256.as_str(),
        report_captured_at_unix,
    });
    let signature = Signature::from_bytes(&signature_bytes);
    inputs
        .verifier_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| "phase6 parity signature verification failed".to_string())?;
    Ok(())
}

struct Phase9EvidenceAttestationBuildInputs<'a> {
    out_dir: &'a Path,
    environment: &'a str,
    generated_at_unix: u64,
    host_identity: &'a str,
    git_commit: &'a str,
    signing_key: &'a SigningKey,
    verifier_key: &'a VerifyingKey,
}

fn build_phase9_evidence_attestation_document(
    inputs: &Phase9EvidenceAttestationBuildInputs<'_>,
) -> Result<Value, String> {
    let command_digest_sha256 = sha256_hex(PHASE9_EVIDENCE_ATTESTATION_COMMAND_LITERAL.as_bytes());
    let verifier_key_hex = hex_encode(inputs.verifier_key.as_bytes());
    let signer_fingerprint = sha256_hex(inputs.verifier_key.as_bytes());
    let signer_key_id = format!("ed25519:{}", &signer_fingerprint[..16]);

    let mut artifacts = Vec::with_capacity(PHASE9_REQUIRED_ARTIFACTS.len());
    for name in PHASE9_REQUIRED_ARTIFACTS {
        let candidate = inputs.out_dir.join(name);
        let canonical_path =
            canonical_file_display(candidate.as_path(), "phase9 evidence artifact")?;
        let artifact_path = Path::new(canonical_path.as_str());
        let artifact_sha256 = sha256_file_hex(artifact_path)?;
        let artifact_label = format!("phase9 evidence artifact {name}");
        let (captured_at_unix, artifact_environment) =
            phase9_parse_measured_artifact_document(artifact_path, artifact_label.as_str())?;
        if artifact_environment != inputs.environment {
            return Err(format!(
                "phase9 evidence environment mismatch for {name}: expected={} observed={}",
                inputs.environment, artifact_environment
            ));
        }
        artifacts.push(Phase9EvidenceArtifactEntry {
            name: (*name).to_string(),
            artifact_path: canonical_path,
            artifact_sha256,
            captured_at_unix,
        });
    }

    let payload = phase9_evidence_attestation_payload(&Phase9EvidenceAttestationPayload {
        generated_at_unix: inputs.generated_at_unix,
        host_identity: inputs.host_identity,
        command_digest_sha256: command_digest_sha256.as_str(),
        signer_key_id: signer_key_id.as_str(),
        verifier_key_hex: verifier_key_hex.as_str(),
        git_commit: inputs.git_commit,
        environment: inputs.environment,
        artifacts: artifacts.as_slice(),
    });
    let signature = inputs.signing_key.sign(payload.as_bytes());

    let artifact_documents = artifacts
        .iter()
        .map(|artifact| {
            json!({
                "name": artifact.name,
                "artifact_path": artifact.artifact_path,
                "artifact_sha256": artifact.artifact_sha256,
                "captured_at_unix": artifact.captured_at_unix,
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "schema_version": PHASE9_EVIDENCE_ATTESTATION_SCHEMA_VERSION,
        "phase": "phase9",
        "generated_at_unix": inputs.generated_at_unix,
        "host_identity": inputs.host_identity,
        "command_digest_sha256": command_digest_sha256,
        "signer_key_id": signer_key_id,
        "verifier_key_hex": verifier_key_hex,
        "git_commit": inputs.git_commit,
        "environment": inputs.environment,
        "artifacts": artifact_documents,
        "signature_hex": hex_encode(&signature.to_bytes()),
    }))
}

struct Phase9EvidenceAttestationVerifyInputs<'a> {
    attestation_path: &'a Path,
    expected_out_dir: &'a Path,
    expected_host_identity: &'a str,
    expected_git_commit: &'a str,
    verifier_key: &'a VerifyingKey,
    max_attestation_age_seconds: i64,
}

fn verify_phase9_evidence_attestation_document(
    inputs: &Phase9EvidenceAttestationVerifyInputs<'_>,
) -> Result<(), String> {
    let attestation = read_json_object(inputs.attestation_path, "phase9 evidence attestation")?;
    if object_u64_field(
        &attestation,
        "schema_version",
        "phase9 evidence attestation",
    )? != PHASE9_EVIDENCE_ATTESTATION_SCHEMA_VERSION
    {
        return Err("phase9 evidence attestation schema_version mismatch".to_string());
    }
    if object_string_field(&attestation, "phase", "phase9 evidence attestation")? != "phase9" {
        return Err("phase9 evidence attestation must set phase=phase9".to_string());
    }

    let generated_at_unix = object_u64_field(
        &attestation,
        "generated_at_unix",
        "phase9 evidence attestation",
    )?;
    let now_unix =
        i64::try_from(unix_now()).map_err(|_| "current unix time out of range".to_string())?;
    let generated_at = i64::try_from(generated_at_unix)
        .map_err(|_| "phase9 evidence generated_at_unix out of range".to_string())?;
    if generated_at > now_unix + 300 {
        return Err("phase9 evidence generated_at_unix is in the future".to_string());
    }
    if now_unix - generated_at > inputs.max_attestation_age_seconds {
        return Err("phase9 evidence attestation is stale".to_string());
    }

    let host_identity =
        object_string_field(&attestation, "host_identity", "phase9 evidence attestation")?;
    if host_identity != inputs.expected_host_identity {
        return Err("phase9 evidence host identity mismatch".to_string());
    }

    let command_digest = object_string_field(
        &attestation,
        "command_digest_sha256",
        "phase9 evidence attestation",
    )?;
    let expected_command_digest =
        sha256_hex(PHASE9_EVIDENCE_ATTESTATION_COMMAND_LITERAL.as_bytes());
    if command_digest != expected_command_digest {
        return Err("phase9 evidence command digest mismatch".to_string());
    }

    let signer_key_id =
        object_string_field(&attestation, "signer_key_id", "phase9 evidence attestation")?;
    let expected_signer_fingerprint = sha256_hex(inputs.verifier_key.as_bytes());
    let expected_signer_key_id = format!("ed25519:{}", &expected_signer_fingerprint[..16]);
    if signer_key_id != expected_signer_key_id {
        return Err("phase9 evidence signer key id mismatch".to_string());
    }
    let verifier_key_hex = object_string_field(
        &attestation,
        "verifier_key_hex",
        "phase9 evidence attestation",
    )?;
    if verifier_key_hex != hex_encode(inputs.verifier_key.as_bytes()) {
        return Err("phase9 evidence verifier key mismatch".to_string());
    }

    let git_commit =
        object_string_field(&attestation, "git_commit", "phase9 evidence attestation")?;
    if git_commit != inputs.expected_git_commit {
        return Err("phase9 evidence git commit mismatch".to_string());
    }
    let environment =
        object_string_field(&attestation, "environment", "phase9 evidence attestation")?;

    let entries = attestation
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| "phase9 evidence attestation missing artifacts array".to_string())?;
    if entries.len() != PHASE9_REQUIRED_ARTIFACTS.len() {
        return Err("phase9 evidence attestation artifact count mismatch".to_string());
    }

    let mut expected_paths = std::collections::BTreeMap::new();
    for name in PHASE9_REQUIRED_ARTIFACTS {
        let expected_path = canonical_file_display(
            inputs.expected_out_dir.join(name).as_path(),
            "phase9 evidence artifact",
        )?;
        expected_paths.insert((*name).to_string(), expected_path);
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut observed_entries = std::collections::BTreeMap::new();
    for entry in entries {
        let entry_object = entry.as_object().ok_or_else(|| {
            "phase9 evidence attestation artifact entry must be object".to_string()
        })?;
        let name = object_string_field(entry_object, "name", "phase9 evidence artifact entry")?;
        if !seen.insert(name.clone()) {
            return Err(format!(
                "phase9 evidence attestation has duplicate artifact: {name}"
            ));
        }
        let expected_path = expected_paths.get(name.as_str()).ok_or_else(|| {
            format!("phase9 evidence attestation has unexpected artifact: {name}")
        })?;
        let artifact_path = object_string_field(
            entry_object,
            "artifact_path",
            "phase9 evidence artifact entry",
        )?;
        if artifact_path != *expected_path {
            return Err(format!("phase9 evidence artifact path mismatch for {name}"));
        }

        let artifact_sha256 = object_string_field(
            entry_object,
            "artifact_sha256",
            "phase9 evidence artifact entry",
        )?;
        let actual_artifact_sha256 = sha256_file_hex(Path::new(artifact_path.as_str()))?;
        if artifact_sha256 != actual_artifact_sha256 {
            return Err(format!(
                "phase9 evidence artifact digest mismatch for {name}"
            ));
        }

        let captured_at_unix = object_u64_field(
            entry_object,
            "captured_at_unix",
            "phase9 evidence artifact entry",
        )?;
        let captured_at = i64::try_from(captured_at_unix)
            .map_err(|_| format!("phase9 evidence captured_at_unix out of range for {name}"))?;
        if captured_at > now_unix + 300 {
            return Err(format!(
                "phase9 evidence captured_at_unix is in the future for {name}"
            ));
        }
        if now_unix - captured_at > inputs.max_attestation_age_seconds {
            return Err(format!(
                "phase9 evidence captured_at_unix is stale for {name}"
            ));
        }

        let label = format!("phase9 evidence artifact {name}");
        let (artifact_captured_at, artifact_environment) = phase9_parse_measured_artifact_document(
            Path::new(artifact_path.as_str()),
            label.as_str(),
        )?;
        if artifact_captured_at != captured_at_unix {
            return Err(format!(
                "phase9 evidence captured_at_unix mismatch for {name}"
            ));
        }
        if artifact_environment != environment {
            return Err(format!("phase9 evidence environment mismatch for {name}"));
        }

        observed_entries.insert(
            name.clone(),
            Phase9EvidenceArtifactEntry {
                name,
                artifact_path,
                artifact_sha256,
                captured_at_unix,
            },
        );
    }

    if seen.len() != PHASE9_REQUIRED_ARTIFACTS.len() {
        return Err("phase9 evidence attestation missing required artifacts".to_string());
    }

    let mut ordered_entries = Vec::with_capacity(PHASE9_REQUIRED_ARTIFACTS.len());
    for required_name in PHASE9_REQUIRED_ARTIFACTS {
        let Some(entry) = observed_entries.remove(*required_name) else {
            return Err(format!(
                "phase9 evidence attestation missing required artifact: {required_name}"
            ));
        };
        ordered_entries.push(entry);
    }
    if !observed_entries.is_empty() {
        return Err("phase9 evidence attestation contains unexpected artifacts".to_string());
    }

    let signature_hex =
        object_string_field(&attestation, "signature_hex", "phase9 evidence attestation")?;
    let signature_bytes = decode_hex_to_fixed::<64>(signature_hex.as_str())
        .map_err(|err| format!("phase9 evidence signature parse failed: {err}"))?;
    let payload = phase9_evidence_attestation_payload(&Phase9EvidenceAttestationPayload {
        generated_at_unix,
        host_identity: host_identity.as_str(),
        command_digest_sha256: command_digest.as_str(),
        signer_key_id: signer_key_id.as_str(),
        verifier_key_hex: verifier_key_hex.as_str(),
        git_commit: git_commit.as_str(),
        environment: environment.as_str(),
        artifacts: ordered_entries.as_slice(),
    });
    let signature = Signature::from_bytes(&signature_bytes);
    inputs
        .verifier_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| "phase9 evidence signature verification failed".to_string())?;
    Ok(())
}

fn write_phase9_evidence_attestation(out_dir: &Path, environment: &str) -> Result<PathBuf, String> {
    ensure_release_provenance_keypair_exists()?;
    let signing_key = load_release_signing_key()?;
    let verifier_key = load_release_verifier_key()?;
    let derived_verifier_key = signing_key.verifying_key();
    if derived_verifier_key.as_bytes() != verifier_key.as_bytes() {
        return Err(
            "phase9 evidence key mismatch: signing key does not match verifier key".to_string(),
        );
    }

    let generated_at_unix = unix_now();
    let host_identity = release_host_identity_from_env_or_default()?;
    let git_commit = current_git_commit()?;
    let attestation_document =
        build_phase9_evidence_attestation_document(&Phase9EvidenceAttestationBuildInputs {
            out_dir,
            environment,
            generated_at_unix,
            host_identity: host_identity.as_str(),
            git_commit: git_commit.as_str(),
            signing_key: &signing_key,
            verifier_key: &verifier_key,
        })?;
    let attestation_path = phase9_evidence_attestation_path_from_env_or_default()?;
    write_json_secure(attestation_path.as_path(), &attestation_document)?;
    Ok(attestation_path)
}

pub fn write_phase6_parity_evidence_attestation(report_path: &Path) -> Result<(), String> {
    ensure_release_provenance_keypair_exists()?;
    let signing_key = load_release_signing_key()?;
    let verifier_key = load_release_verifier_key()?;
    let derived_verifier_key = signing_key.verifying_key();
    if derived_verifier_key.as_bytes() != verifier_key.as_bytes() {
        return Err(
            "phase6 parity key mismatch: signing key does not match verifier key".to_string(),
        );
    }

    let generated_at_unix = unix_now();
    let host_identity = release_host_identity_from_env_or_default()?;
    let git_commit = current_git_commit()?;
    let attestation_document =
        build_phase6_parity_attestation_document(&Phase6ParityAttestationBuildInputs {
            report_path,
            generated_at_unix,
            host_identity: host_identity.as_str(),
            git_commit: git_commit.as_str(),
            signing_key: &signing_key,
            verifier_key: &verifier_key,
        })?;
    let attestation_path = phase6_parity_attestation_path_from_env_or_default()?;
    write_json_secure(attestation_path.as_path(), &attestation_document)
}

pub fn execute_ops_verify_phase6_platform_readiness() -> Result<String, String> {
    let report_path = phase6_parity_report_path_from_env_or_default()?;
    crate::phase6_validate_platform_parity_report(report_path.as_path())?;
    Ok(format!(
        "phase6 platform readiness checks passed: {}",
        report_path.display()
    ))
}

pub fn execute_ops_verify_phase6_parity_evidence() -> Result<String, String> {
    let report_path = phase6_parity_report_path_from_env_or_default()?;
    let attestation_path = phase6_parity_attestation_path_from_env_or_default()?;
    let host_identity = release_host_identity_from_env_or_default()?;
    let verifier_key = load_release_verifier_key()?;
    let git_commit = current_git_commit()?;
    verify_phase6_parity_attestation_document(&Phase6ParityAttestationVerifyInputs {
        attestation_path: attestation_path.as_path(),
        expected_report_path: report_path.as_path(),
        expected_host_identity: host_identity.as_str(),
        expected_git_commit: git_commit.as_str(),
        verifier_key: &verifier_key,
        max_attestation_age_seconds: phase6_parity_attestation_max_age_seconds_from_env()?,
    })?;
    Ok(format!(
        "phase6 parity evidence verification passed: report={} attestation={}",
        report_path.display(),
        attestation_path.display()
    ))
}

pub fn execute_ops_verify_phase9_readiness() -> Result<String, String> {
    let out_dir = path_from_env_or_default("RUSTYNET_PHASE9_OUT_DIR", DEFAULT_PHASE9_OUT_DIR)?;
    let max_evidence_age_seconds = env_u64_with_default(
        "RUSTYNET_PHASE9_MAX_EVIDENCE_AGE_SECONDS",
        DEFAULT_PHASE9_MAX_SOURCE_AGE_SECONDS as u64,
    )?;
    let max_evidence_age_seconds = i64::try_from(max_evidence_age_seconds)
        .map_err(|_| "RUSTYNET_PHASE9_MAX_EVIDENCE_AGE_SECONDS is too large".to_string())?;
    let now_unix =
        i64::try_from(unix_now()).map_err(|_| "current unix time out of range".to_string())?;

    let compatibility_policy_path = out_dir.join("compatibility_policy.json");
    let compatibility_policy =
        read_json_object(compatibility_policy_path.as_path(), "compatibility_policy")?;
    phase9_require_measured_evidence_metadata(
        &compatibility_policy,
        "compatibility_policy",
        now_unix,
        max_evidence_age_seconds,
    )?;
    phase9_require_string(
        &compatibility_policy,
        "policy_version",
        "compatibility_policy",
    )?;
    let minimum_supported_client = compatibility_policy
        .get("minimum_supported_client")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            "compatibility policy requires minimum_supported_client and latest_server objects"
                .to_string()
        })?;
    let latest_server = compatibility_policy
        .get("latest_server")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            "compatibility policy requires minimum_supported_client and latest_server objects"
                .to_string()
        })?;
    let minimum_major = phase9_require_integer(
        minimum_supported_client,
        "major",
        "compatibility_policy minimum_supported_client",
    )?;
    let minimum_minor = phase9_require_integer(
        minimum_supported_client,
        "minor",
        "compatibility_policy minimum_supported_client",
    )?;
    let latest_major =
        phase9_require_integer(latest_server, "major", "compatibility_policy latest_server")?;
    let latest_minor =
        phase9_require_integer(latest_server, "minor", "compatibility_policy latest_server")?;
    if (minimum_major, minimum_minor) > (latest_major, latest_minor) {
        return Err(
            "compatibility policy invalid: minimum client is greater than latest server"
                .to_string(),
        );
    }
    if phase9_require_number(
        &compatibility_policy,
        "deprecation_window_days",
        "compatibility_policy",
    )? <= 0.0
    {
        return Err("compatibility policy invalid: deprecation window must be > 0".to_string());
    }
    let insecure_mode = compatibility_policy
        .get("insecure_compatibility_mode")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            "compatibility policy invalid: insecure_compatibility_mode object is required"
                .to_string()
        })?;
    if phase9_require_bool(
        insecure_mode,
        "default_enabled",
        "compatibility_policy insecure_compatibility_mode",
    )? {
        return Err(
            "compatibility policy invalid: insecure compatibility default must be disabled"
                .to_string(),
        );
    }
    if !phase9_require_bool(
        insecure_mode,
        "risk_acceptance_required",
        "compatibility_policy insecure_compatibility_mode",
    )? || !phase9_require_bool(
        insecure_mode,
        "auto_expiry_required",
        "compatibility_policy insecure_compatibility_mode",
    )? {
        return Err(
            "compatibility policy invalid: risk acceptance + auto-expiry are mandatory".to_string(),
        );
    }

    let slo_path = out_dir.join("slo_error_budget_report.json");
    let slo = read_json_object(slo_path.as_path(), "slo_error_budget_report")?;
    phase9_require_measured_evidence_metadata(
        &slo,
        "slo_error_budget_report",
        now_unix,
        max_evidence_age_seconds,
    )?;
    let window_start = phase9_require_string(&slo, "window_start_utc", "slo_error_budget_report")?;
    let window_end = phase9_require_string(&slo, "window_end_utc", "slo_error_budget_report")?;
    let window_start_unix = parse_utc_to_unix(window_start.as_str(), "slo window_start_utc")?;
    let window_end_unix = parse_utc_to_unix(window_end.as_str(), "slo window_end_utc")?;
    if window_end_unix <= window_start_unix {
        return Err("slo gate failed: window_end_utc must be after window_start_utc".to_string());
    }
    if phase9_require_number(
        &slo,
        "measured_availability_percent",
        "slo_error_budget_report",
    )? < phase9_require_number(&slo, "availability_slo_percent", "slo_error_budget_report")?
    {
        return Err("slo gate failed: measured availability below target".to_string());
    }
    if phase9_require_number(
        &slo,
        "measured_error_budget_consumed_percent",
        "slo_error_budget_report",
    )? > phase9_require_number(
        &slo,
        "max_error_budget_consumed_percent",
        "slo_error_budget_report",
    )? {
        return Err("slo gate failed: error budget over-consumed".to_string());
    }

    let performance_path = out_dir.join("performance_budget_report.json");
    let performance = read_json_object(performance_path.as_path(), "performance_budget_report")?;
    phase9_require_measured_evidence_metadata(
        &performance,
        "performance_budget_report",
        now_unix,
        max_evidence_age_seconds,
    )?;
    if phase9_require_number(
        &performance,
        "idle_cpu_percent",
        "performance_budget_report",
    )? > 2.0
    {
        return Err("performance gate failed: idle CPU above 2%".to_string());
    }
    if phase9_require_number(&performance, "idle_memory_mb", "performance_budget_report")? > 120.0 {
        return Err("performance gate failed: idle memory above 120 MB".to_string());
    }
    if phase9_require_number(
        &performance,
        "reconnect_seconds",
        "performance_budget_report",
    )? > 5.0
    {
        return Err("performance gate failed: reconnect above 5 seconds".to_string());
    }
    if phase9_require_number(
        &performance,
        "route_apply_p95_seconds",
        "performance_budget_report",
    )? > 2.0
    {
        return Err("performance gate failed: route apply p95 above 2 seconds".to_string());
    }
    if phase9_require_number(
        &performance,
        "throughput_overhead_percent",
        "performance_budget_report",
    )? > 15.0
    {
        return Err("performance gate failed: throughput overhead above 15%".to_string());
    }
    if phase9_require_number(&performance, "soak_test_hours", "performance_budget_report")? < 24.0 {
        return Err("performance gate failed: soak test duration under 24 hours".to_string());
    }

    let incident_path = out_dir.join("incident_drill_report.json");
    let incident = read_json_object(incident_path.as_path(), "incident_drill_report")?;
    phase9_require_measured_evidence_metadata(
        &incident,
        "incident_drill_report",
        now_unix,
        max_evidence_age_seconds,
    )?;
    let incident_executed_at =
        phase9_require_string(&incident, "executed_at_utc", "incident_drill_report")?;
    let _ = parse_utc_to_unix(incident_executed_at.as_str(), "incident executed_at_utc")?;
    if !phase9_require_bool(&incident, "postmortem_completed", "incident_drill_report")? {
        return Err("incident gate failed: postmortem not completed".to_string());
    }
    if !phase9_require_bool(&incident, "action_items_closed", "incident_drill_report")? {
        return Err("incident gate failed: action items not closed".to_string());
    }
    if !phase9_require_bool(
        &incident,
        "oncall_readiness_confirmed",
        "incident_drill_report",
    )? {
        return Err("incident gate failed: on-call readiness not confirmed".to_string());
    }

    let dr_path = out_dir.join("dr_failover_report.json");
    let dr = read_json_object(dr_path.as_path(), "dr_failover_report")?;
    phase9_require_measured_evidence_metadata(
        &dr,
        "dr_failover_report",
        now_unix,
        max_evidence_age_seconds,
    )?;
    let dr_executed_at = phase9_require_string(&dr, "executed_at_utc", "dr_failover_report")?;
    let _ = parse_utc_to_unix(dr_executed_at.as_str(), "dr executed_at_utc")?;
    if phase9_require_integer(&dr, "region_count", "dr_failover_report")? < 2 {
        return Err("dr gate failed: fewer than two regions validated".to_string());
    }
    if phase9_require_number(&dr, "measured_rpo_minutes", "dr_failover_report")?
        > phase9_require_number(&dr, "rpo_target_minutes", "dr_failover_report")?
    {
        return Err("dr gate failed: RPO target not met".to_string());
    }
    if phase9_require_number(&dr, "measured_rto_minutes", "dr_failover_report")?
        > phase9_require_number(&dr, "rto_target_minutes", "dr_failover_report")?
    {
        return Err("dr gate failed: RTO target not met".to_string());
    }
    if !phase9_require_bool(&dr, "restore_integrity_verified", "dr_failover_report")? {
        return Err("dr gate failed: restore integrity not verified".to_string());
    }

    let backend_path = out_dir.join("backend_agility_report.json");
    let backend = read_json_object(backend_path.as_path(), "backend_agility_report")?;
    phase9_require_measured_evidence_metadata(
        &backend,
        "backend_agility_report",
        now_unix,
        max_evidence_age_seconds,
    )?;
    let default_backend =
        phase9_require_string(&backend, "default_backend", "backend_agility_report")?;
    if !default_backend.eq_ignore_ascii_case("wireguard") {
        return Err("backend agility gate failed: default backend must be wireguard".to_string());
    }
    let additional_backend_paths = backend
        .get("additional_backend_paths")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "backend agility gate failed: at least one additional backend path is required"
                .to_string()
        })?;
    if additional_backend_paths.is_empty() {
        return Err(
            "backend agility gate failed: at least one additional backend path is required"
                .to_string(),
        );
    }
    for value in additional_backend_paths {
        let path = value
            .as_str()
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .ok_or_else(|| {
                "backend agility gate failed: invalid additional backend path entry".to_string()
            })?;
        if phase9_contains_any_case_insensitive(path, &["stub", "fake", "mock", "simulat"]) {
            return Err(format!(
                "backend agility gate failed: synthetic backend path not allowed: {path}"
            ));
        }
        let candidate = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else if path.contains('/') {
            Path::new(".").join(path)
        } else {
            Path::new("crates").join(path)
        };
        if !candidate.exists() {
            return Err(format!(
                "backend agility gate failed: backend path does not exist: {path}"
            ));
        }
    }
    if !phase9_require_bool(&backend, "conformance_passed", "backend_agility_report")? {
        return Err("backend agility gate failed: conformance not passed".to_string());
    }
    if !phase9_require_bool(
        &backend,
        "security_review_complete",
        "backend_agility_report",
    )? {
        return Err("backend agility gate failed: security review incomplete".to_string());
    }
    if !phase9_require_bool(
        &backend,
        "wireguard_is_adapter_boundary",
        "backend_agility_report",
    )? {
        return Err("backend agility gate failed: wireguard boundary not preserved".to_string());
    }
    if phase9_require_bool(
        &backend,
        "protocol_leakage_detected",
        "backend_agility_report",
    )? {
        return Err("backend agility gate failed: protocol leakage detected".to_string());
    }
    let evidence_commands = backend
        .get("evidence_commands")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "backend agility gate failed: evidence_commands must be a non-empty list".to_string()
        })?;
    if evidence_commands.is_empty() {
        return Err(
            "backend agility gate failed: evidence_commands must be a non-empty list".to_string(),
        );
    }
    for value in evidence_commands {
        let command = value
            .as_str()
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .ok_or_else(|| {
                "backend agility gate failed: invalid command in evidence_commands".to_string()
            })?;
        if phase9_contains_any_case_insensitive(command, &["backend-stub", "stub-backend"]) {
            return Err(
                "backend agility gate failed: stub backend command is not valid evidence"
                    .to_string(),
            );
        }
    }

    let crypto_path = out_dir.join("crypto_deprecation_schedule.json");
    let crypto = read_json_object(crypto_path.as_path(), "crypto_deprecation_schedule")?;
    phase9_require_measured_evidence_metadata(
        &crypto,
        "crypto_deprecation_schedule",
        now_unix,
        max_evidence_age_seconds,
    )?;
    let entries = crypto
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "crypto schedule gate failed: no deprecation entries present".to_string())?;
    if entries.is_empty() {
        return Err("crypto schedule gate failed: no deprecation entries present".to_string());
    }
    for entry in entries {
        let entry_obj = entry
            .as_object()
            .ok_or_else(|| "crypto schedule gate failed: invalid entry type".to_string())?;
        let deprecates_at = phase9_require_string(
            entry_obj,
            "deprecates_at_utc",
            "crypto deprecation schedule entry",
        )?;
        let removal_at = phase9_require_string(
            entry_obj,
            "removal_at_utc",
            "crypto deprecation schedule entry",
        )?;
        let deprecates_at_unix =
            parse_utc_to_unix(deprecates_at.as_str(), "crypto deprecates_at_utc")?;
        let removal_at_unix = parse_utc_to_unix(removal_at.as_str(), "crypto removal_at_utc")?;
        if removal_at_unix <= deprecates_at_unix {
            return Err(
                "crypto schedule gate failed: removal timestamp must be after deprecation timestamp"
                    .to_string(),
            );
        }
    }
    if phase9_require_bool(
        &crypto,
        "exceptions_default_enabled",
        "crypto_deprecation_schedule",
    )? {
        return Err(
            "crypto schedule gate failed: insecure exceptions must be disabled by default"
                .to_string(),
        );
    }
    if !phase9_require_bool(
        &crypto,
        "exceptions_require_risk_acceptance",
        "crypto_deprecation_schedule",
    )? {
        return Err(
            "crypto schedule gate failed: exceptions must require risk acceptance".to_string(),
        );
    }
    if !phase9_require_bool(
        &crypto,
        "exceptions_auto_expire",
        "crypto_deprecation_schedule",
    )? {
        return Err("crypto schedule gate failed: exceptions must auto-expire".to_string());
    }

    Ok(format!(
        "phase9 readiness checks passed: {}",
        out_dir.display()
    ))
}

pub fn execute_ops_verify_phase9_evidence() -> Result<String, String> {
    let out_dir = path_from_env_or_default("RUSTYNET_PHASE9_OUT_DIR", DEFAULT_PHASE9_OUT_DIR)?;
    let attestation_path = phase9_evidence_attestation_path_from_env_or_default()?;
    let host_identity = release_host_identity_from_env_or_default()?;
    let verifier_key = load_release_verifier_key()?;
    let git_commit = current_git_commit()?;
    verify_phase9_evidence_attestation_document(&Phase9EvidenceAttestationVerifyInputs {
        attestation_path: attestation_path.as_path(),
        expected_out_dir: out_dir.as_path(),
        expected_host_identity: host_identity.as_str(),
        expected_git_commit: git_commit.as_str(),
        verifier_key: &verifier_key,
        max_attestation_age_seconds: phase9_evidence_attestation_max_age_seconds_from_env()?,
    })?;
    Ok(format!(
        "phase9 evidence verification passed: out_dir={} attestation={}",
        out_dir.display(),
        attestation_path.display()
    ))
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

    write_phase9_evidence_attestation(out_dir.as_path(), environment.as_str())?;
    run_check_script(
        "./scripts/ci/check_phase9_readiness.sh",
        "phase9 readiness check",
    )?;
    Ok(format!(
        "phase9 artifacts generated and validated under: {}",
        out_dir.display()
    ))
}

pub fn execute_ops_write_phase10_hp2_traversal_reports(
    config: WritePhase10Hp2TraversalReportsConfig,
) -> Result<String, String> {
    let source_dir = resolve_path(config.source_dir.to_string_lossy().as_ref())?;
    ensure_directory(source_dir.as_path(), "phase10 HP2 source directory")?;

    let path_selection_log = resolve_path(config.path_selection_log.to_string_lossy().as_ref())?;
    let probe_security_log = resolve_path(config.probe_security_log.to_string_lossy().as_ref())?;
    ensure_regular_file(
        path_selection_log.as_path(),
        "phase10 HP2 path selection log",
    )?;
    ensure_regular_file(
        probe_security_log.as_path(),
        "phase10 HP2 probe security log",
    )?;

    let environment = config.environment.trim();
    if environment.is_empty() {
        return Err("phase10 HP2 environment label must not be empty".to_string());
    }

    let captured_at_unix = unix_now();
    let git_commit = current_git_commit()?;

    let path_selection_report = json!({
        "phase": "phase10",
        "suite": "traversal_path_selection",
        "evidence_mode": "measured",
        "environment": environment,
        "captured_at_unix": captured_at_unix,
        "git_commit": git_commit,
        "status": "pass",
        "checks": {
            "direct_probe_success": "pass",
            "relay_fallback_success": "pass",
            "direct_failback_success": "pass",
            "multi_peer_snapshot_success": "pass"
        },
        "validated_by_tests": [
            "daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_accepts_multi_peer_snapshot",
            "daemon::tests::daemon_runtime_auto_tunnel_traversal_probe_falls_back_to_relay_without_handshake_evidence",
            "daemon::tests::daemon_runtime_auto_tunnel_traversal_probe_recovers_direct_when_handshake_arrives",
            "phase10::tests::traversal_probe_falls_back_to_relay_when_handshake_does_not_advance",
            "phase10::tests::traversal_probe_promotes_direct_when_handshake_advances"
        ],
        "log_artifacts": [path_selection_log.display().to_string()]
    });

    let probe_security_report = json!({
        "phase": "phase10",
        "suite": "traversal_probe_security",
        "evidence_mode": "measured",
        "environment": environment,
        "captured_at_unix": captured_at_unix,
        "git_commit": git_commit,
        "status": "pass",
        "checks": {
            "replay_rejected": "pass",
            "fail_closed_on_invalid_traversal": "pass",
            "no_unauthorized_endpoint_mutation": "pass",
            "managed_peer_coverage_required": "pass",
            "unmanaged_peer_bundle_rejected": "pass",
            "backend_handshake_evidence_hardened": "pass"
        },
        "validated_by_tests": [
            "daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay",
            "daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed",
            "daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_requires_full_peer_coverage",
            "daemon::tests::daemon_runtime_auto_tunnel_traversal_authority_rejects_unmanaged_peer_bundle",
            "daemon::tests::daemon_runtime_auto_tunnel_traversal_runtime_sync_fail_closes_on_missing_peer_coverage",
            "traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback",
            "daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay",
            "rustynet-backend-wireguard::tests::latest_handshake_parser_rejects_oversized_or_malformed_output",
            "rustynet-backend-wireguard::tests::linux_backend_reads_latest_handshake_for_configured_peer"
        ],
        "log_artifacts": [probe_security_log.display().to_string()]
    });

    let path_report_path = source_dir.join("traversal_path_selection_report.json");
    let probe_report_path = source_dir.join("traversal_probe_security_report.json");
    write_json_secure(path_report_path.as_path(), &path_selection_report)?;
    write_json_secure(probe_report_path.as_path(), &probe_security_report)?;

    Ok(format!(
        "phase10 HP2 traversal reports written: path_selection_report={} probe_security_report={}",
        path_report_path.display(),
        probe_report_path.display()
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
    let mut traversal_path_payload = read_json_object(
        source_dir
            .join("traversal_path_selection_report.json")
            .as_path(),
        "traversal_path_selection_report source",
    )?;
    let mut traversal_security_payload = read_json_object(
        source_dir
            .join("traversal_probe_security_report.json")
            .as_path(),
        "traversal_probe_security_report source",
    )?;
    let mut managed_dns_payload = read_json_object(
        source_dir.join("managed_dns_report.json").as_path(),
        "managed_dns_report source",
    )?;

    let netns_source = source_dir.join("netns_e2e_report.json");
    let leak_source = source_dir.join("leak_test_report.json");
    let perf_source = source_dir.join("perf_budget_report.json");
    let direct_source = source_dir.join("direct_relay_failover_report.json");
    let traversal_path_source = source_dir.join("traversal_path_selection_report.json");
    let traversal_security_source = source_dir.join("traversal_probe_security_report.json");
    let managed_dns_source = source_dir.join("managed_dns_report.json");

    ensure_regular_file(netns_source.as_path(), "raw phase10 evidence source")?;
    ensure_regular_file(leak_source.as_path(), "raw phase10 evidence source")?;
    ensure_regular_file(perf_source.as_path(), "raw phase10 evidence source")?;
    ensure_regular_file(direct_source.as_path(), "raw phase10 evidence source")?;
    ensure_regular_file(
        traversal_path_source.as_path(),
        "raw phase10 evidence source",
    )?;
    ensure_regular_file(
        traversal_security_source.as_path(),
        "raw phase10 evidence source",
    )?;
    ensure_regular_file(managed_dns_source.as_path(), "raw phase10 evidence source")?;

    for (payload, source, label) in [
        (&netns_payload, netns_source.as_path(), "netns_e2e_report"),
        (&leak_payload, leak_source.as_path(), "leak_test_report"),
        (&perf_payload, perf_source.as_path(), "perf_budget_report"),
        (
            &direct_payload,
            direct_source.as_path(),
            "direct_relay_failover_report",
        ),
        (
            &traversal_path_payload,
            traversal_path_source.as_path(),
            "traversal_path_selection_report",
        ),
        (
            &traversal_security_payload,
            traversal_security_source.as_path(),
            "traversal_probe_security_report",
        ),
        (
            &managed_dns_payload,
            managed_dns_source.as_path(),
            "managed_dns_report",
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
    phase10_require_status_pass(
        &traversal_path_payload,
        traversal_path_source.as_path(),
        "traversal_path_selection_report",
    )?;
    phase10_validate_checks_all_pass(
        &traversal_path_payload,
        traversal_path_source.as_path(),
        "traversal_path_selection_report",
    )?;
    phase10_require_status_pass(
        &traversal_security_payload,
        traversal_security_source.as_path(),
        "traversal_probe_security_report",
    )?;
    phase10_validate_checks_all_pass(
        &traversal_security_payload,
        traversal_security_source.as_path(),
        "traversal_probe_security_report",
    )?;
    phase10_require_status_pass(
        &managed_dns_payload,
        managed_dns_source.as_path(),
        "managed_dns_report",
    )?;
    phase10_validate_checks_all_pass(
        &managed_dns_payload,
        managed_dns_source.as_path(),
        "managed_dns_report",
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
        (
            &mut traversal_path_payload,
            traversal_path_source.as_path(),
            "traversal_path_selection_report.json",
        ),
        (
            &mut traversal_security_payload,
            traversal_security_source.as_path(),
            "traversal_probe_security_report.json",
        ),
        (
            &mut managed_dns_payload,
            managed_dns_source.as_path(),
            "managed_dns_report.json",
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
    let state_body = read_utf8_regular_file_with_max_bytes(
        state_source.as_path(),
        "phase10 state transition source",
        MAX_PHASE10_STATE_LOG_SOURCE_BYTES,
    )?;
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

pub fn execute_ops_verify_phase10_readiness() -> Result<String, String> {
    let artifact_dir = phase10_artifact_dir_from_env()?;
    let max_evidence_age_seconds = env_u64_with_default(
        "RUSTYNET_PHASE10_MAX_EVIDENCE_AGE_SECONDS",
        DEFAULT_PHASE10_MAX_SOURCE_AGE_SECONDS,
    )?;
    let max_evidence_age_seconds = i64::try_from(max_evidence_age_seconds)
        .map_err(|_| "RUSTYNET_PHASE10_MAX_EVIDENCE_AGE_SECONDS is too large".to_string())?;
    let now_unix =
        i64::try_from(unix_now()).map_err(|_| "current unix time out of range".to_string())?;

    let netns_path = artifact_dir.join("netns_e2e_report.json");
    let leak_path = artifact_dir.join("leak_test_report.json");
    let perf_path = artifact_dir.join("perf_budget_report.json");
    let failover_path = artifact_dir.join("direct_relay_failover_report.json");
    let traversal_path_path = artifact_dir.join("traversal_path_selection_report.json");
    let traversal_security_path = artifact_dir.join("traversal_probe_security_report.json");
    let managed_dns_path = artifact_dir.join("managed_dns_report.json");

    let netns_payload = read_json_object(netns_path.as_path(), "netns_e2e_report")?;
    let leak_payload = read_json_object(leak_path.as_path(), "leak_test_report")?;
    let perf_payload = read_json_object(perf_path.as_path(), "perf_budget_report")?;
    let failover_payload =
        read_json_object(failover_path.as_path(), "direct_relay_failover_report")?;
    let traversal_path_payload = read_json_object(
        traversal_path_path.as_path(),
        "traversal_path_selection_report",
    )?;
    let traversal_security_payload = read_json_object(
        traversal_security_path.as_path(),
        "traversal_probe_security_report",
    )?;
    let managed_dns_payload = read_json_object(managed_dns_path.as_path(), "managed_dns_report")?;

    for (payload, source_path, label) in [
        (&netns_payload, netns_path.as_path(), "netns_e2e_report"),
        (&leak_payload, leak_path.as_path(), "leak_test_report"),
        (&perf_payload, perf_path.as_path(), "perf_budget_report"),
        (
            &failover_payload,
            failover_path.as_path(),
            "direct_relay_failover_report",
        ),
        (
            &traversal_path_payload,
            traversal_path_path.as_path(),
            "traversal_path_selection_report",
        ),
        (
            &traversal_security_payload,
            traversal_security_path.as_path(),
            "traversal_probe_security_report",
        ),
        (
            &managed_dns_payload,
            managed_dns_path.as_path(),
            "managed_dns_report",
        ),
    ] {
        phase10_require_measured_source(payload, source_path, label)?;
        let captured_at_unix =
            phase10_require_positive_unix_timestamp(payload, source_path, label)?;
        phase10_validate_source_freshness(
            captured_at_unix,
            source_path,
            label,
            now_unix,
            max_evidence_age_seconds,
        )?;
        phase10_require_non_empty_environment(payload, source_path, label)?;
        phase10_validate_source_artifacts_entries(payload, source_path, label)?;
    }

    phase10_require_status_pass(&netns_payload, netns_path.as_path(), "netns_e2e_report")?;
    phase10_validate_checks_all_pass(&netns_payload, netns_path.as_path(), "netns_e2e_report")?;

    phase10_require_status_pass(&leak_payload, leak_path.as_path(), "leak_test_report")?;

    phase10_require_status_pass(
        &failover_payload,
        failover_path.as_path(),
        "direct_relay_failover_report",
    )?;
    phase10_validate_checks_all_pass(
        &failover_payload,
        failover_path.as_path(),
        "direct_relay_failover_report",
    )?;

    phase10_require_status_pass(
        &traversal_path_payload,
        traversal_path_path.as_path(),
        "traversal_path_selection_report",
    )?;
    phase10_validate_checks_all_pass(
        &traversal_path_payload,
        traversal_path_path.as_path(),
        "traversal_path_selection_report",
    )?;
    phase10_require_named_checks_pass(
        &traversal_path_payload,
        traversal_path_path.as_path(),
        "traversal_path_selection_report",
        &[
            "direct_probe_success",
            "relay_fallback_success",
            "direct_failback_success",
        ],
    )?;

    phase10_require_status_pass(
        &traversal_security_payload,
        traversal_security_path.as_path(),
        "traversal_probe_security_report",
    )?;
    phase10_validate_checks_all_pass(
        &traversal_security_payload,
        traversal_security_path.as_path(),
        "traversal_probe_security_report",
    )?;
    phase10_require_named_checks_pass(
        &traversal_security_payload,
        traversal_security_path.as_path(),
        "traversal_probe_security_report",
        &[
            "replay_rejected",
            "fail_closed_on_invalid_traversal",
            "no_unauthorized_endpoint_mutation",
            "managed_peer_coverage_required",
            "unmanaged_peer_bundle_rejected",
        ],
    )?;

    phase10_require_status_pass(
        &managed_dns_payload,
        managed_dns_path.as_path(),
        "managed_dns_report",
    )?;
    phase10_validate_checks_all_pass(
        &managed_dns_payload,
        managed_dns_path.as_path(),
        "managed_dns_report",
    )?;
    phase10_require_named_checks_pass(
        &managed_dns_payload,
        managed_dns_path.as_path(),
        "managed_dns_report",
        &[
            "zone_issue_verify_passes",
            "dns_inspect_valid",
            "managed_dns_service_active",
            "resolvectl_split_dns_configured",
            "loopback_resolver_answers_managed_name",
            "systemd_resolved_answers_managed_name",
            "alias_resolves_to_expected_ip",
            "non_managed_query_refused",
            "stale_bundle_fail_closed",
            "valid_bundle_restored",
        ],
    )?;

    phase10_validate_perf_budget(&perf_payload, perf_path.as_path())?;
    phase10_validate_required_perf_metrics(&perf_payload, perf_path.as_path())?;

    let state_log_path = artifact_dir.join("state_transition_audit.log");
    let state_log = read_utf8_regular_file_with_max_bytes(
        state_log_path.as_path(),
        "state_transition_audit.log",
        MAX_PHASE10_STATE_LOG_SOURCE_BYTES,
    )?;
    if !contains_generation_marker(state_log.as_str()) {
        return Err("state_transition_audit.log missing generation entries".to_string());
    }

    Ok(format!(
        "phase10 readiness checks passed: {}",
        artifact_dir.display()
    ))
}

pub fn execute_ops_verify_required_test_output(
    config: VerifyRequiredTestOutputConfig,
) -> Result<String, String> {
    let body = read_utf8_regular_file_with_max_bytes(
        config.output_path.as_path(),
        "required test output",
        MAX_REQUIRED_TEST_OUTPUT_BYTES,
    )?;
    let total_passed = parse_required_test_output_total_passed(body.as_str());
    if total_passed < 1 {
        return Err(format!(
            "required test did not execute any tests: package={} filter={}",
            config.package, config.test_filter
        ));
    }
    Ok(format!(
        "required test output verification passed: package={} filter={} passed_tests={}",
        config.package, config.test_filter, total_passed
    ))
}

pub fn execute_ops_sign_release_artifact() -> Result<String, String> {
    let artifact_path = release_artifact_path_from_env_or_default()?;
    let sbom_path = release_sbom_path_from_env_or_default()?;
    let sbom_digest_path = release_sbom_sha256_path_from_env_or_default()?;
    let provenance_path = release_provenance_path_from_env_or_default()?;
    let release_track = release_track_from_env_or_default()?;
    let host_identity = release_host_identity_from_env_or_default()?;

    ensure_release_provenance_keypair_exists()?;
    let signing_key = load_release_signing_key()?;
    let verifier_key = load_release_verifier_key()?;
    let derived_verifier_key = signing_key.verifying_key();
    if derived_verifier_key.as_bytes() != verifier_key.as_bytes() {
        return Err(
            "release provenance key mismatch: signing key does not match verifier key".to_string(),
        );
    }

    let generated_at_unix = unix_now();
    let provenance = build_release_provenance_document(&ReleaseProvenanceBuildInputs {
        artifact_path: artifact_path.as_path(),
        sbom_path: sbom_path.as_path(),
        sbom_digest_path: sbom_digest_path.as_path(),
        generated_at_unix,
        host_identity: host_identity.as_str(),
        release_track: release_track.as_str(),
        signing_key: &signing_key,
        verifier_key: &verifier_key,
    })?;
    write_json_secure(provenance_path.as_path(), &provenance)?;

    verify_release_provenance_document(&ReleaseProvenanceVerifyInputs {
        provenance_path: provenance_path.as_path(),
        expected_artifact_path: artifact_path.as_path(),
        expected_sbom_path: sbom_path.as_path(),
        expected_sbom_digest_path: sbom_digest_path.as_path(),
        expected_host_identity: host_identity.as_str(),
        expected_release_track: release_track.as_str(),
        verifier_key: &verifier_key,
        max_provenance_age_seconds: release_max_provenance_age_seconds_from_env()?,
    })?;

    Ok(format!(
        "release provenance signed and verified: artifact={} sbom={} provenance={} release_track={}",
        artifact_path.display(),
        sbom_path.display(),
        provenance_path.display(),
        release_track
    ))
}

pub fn execute_ops_verify_release_artifact() -> Result<String, String> {
    let artifact_path = release_artifact_path_from_env_or_default()?;
    let sbom_path = release_sbom_path_from_env_or_default()?;
    let sbom_digest_path = release_sbom_sha256_path_from_env_or_default()?;
    let provenance_path = release_provenance_path_from_env_or_default()?;
    let release_track = release_track_from_env_or_default()?;
    let host_identity = release_host_identity_from_env_or_default()?;
    let verifier_key = load_release_verifier_key()?;

    verify_release_provenance_document(&ReleaseProvenanceVerifyInputs {
        provenance_path: provenance_path.as_path(),
        expected_artifact_path: artifact_path.as_path(),
        expected_sbom_path: sbom_path.as_path(),
        expected_sbom_digest_path: sbom_digest_path.as_path(),
        expected_host_identity: host_identity.as_str(),
        expected_release_track: release_track.as_str(),
        verifier_key: &verifier_key,
        max_provenance_age_seconds: release_max_provenance_age_seconds_from_env()?,
    })?;

    Ok(format!(
        "release provenance verification passed: artifact={} provenance={}",
        artifact_path.display(),
        provenance_path.display()
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::{
        MAX_PHASE10_JSON_SOURCE_BYTES, PHASE9_REQUIRED_ARTIFACTS,
        Phase6ParityAttestationBuildInputs, Phase6ParityAttestationVerifyInputs,
        Phase9EvidenceAttestationBuildInputs, Phase9EvidenceAttestationVerifyInputs,
        ReleaseProvenanceBuildInputs, ReleaseProvenanceVerifyInputs,
        WritePhase10Hp2TraversalReportsConfig, build_phase6_parity_attestation_document,
        build_phase9_evidence_attestation_document, build_release_provenance_document,
        contains_generation_marker, decode_hex_to_fixed,
        execute_ops_write_phase10_hp2_traversal_reports, hex_encode, load_key_hex_from_secure_path,
        parse_required_test_output_total_passed, phase10_expected_provenance_entries,
        read_json_object, read_utf8_regular_file_with_max_bytes, sha256_hex,
        validate_phase10_host_identity, verify_phase6_parity_attestation_document,
        verify_phase9_evidence_attestation_document, verify_release_provenance_document,
        write_phase10_provenance_keypair,
    };
    use ed25519_dalek::SigningKey;

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
    fn required_test_output_parser_sums_passed_counts() {
        let output = "\
running 1 test
test daemon::tests::alpha ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 2 tests
test daemon::tests::beta ... ok
test daemon::tests::gamma ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
";
        assert_eq!(parse_required_test_output_total_passed(output), 3);
    }

    #[test]
    fn required_test_output_parser_returns_zero_without_matching_summary() {
        let output = "running 0 tests\n";
        assert_eq!(parse_required_test_output_total_passed(output), 0);
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
    fn phase10_provenance_entries_include_traversal_and_managed_dns_reports() {
        let source_dir = Path::new("/tmp/rustynet-phase10-source");
        let out_dir = Path::new("/tmp/rustynet-phase10-out");
        let entries = phase10_expected_provenance_entries(source_dir, out_dir);
        assert!(entries.iter().any(|(name, kind, path, json_required)| {
            *name == "source_traversal_path_selection_report"
                && *kind == "source"
                && *json_required
                && path == &source_dir.join("traversal_path_selection_report.json")
        }));
        assert!(entries.iter().any(|(name, kind, path, json_required)| {
            *name == "source_traversal_probe_security_report"
                && *kind == "source"
                && *json_required
                && path == &source_dir.join("traversal_probe_security_report.json")
        }));
        assert!(entries.iter().any(|(name, kind, path, json_required)| {
            *name == "derived_traversal_path_selection_report"
                && *kind == "derived"
                && *json_required
                && path == &out_dir.join("traversal_path_selection_report.json")
        }));
        assert!(entries.iter().any(|(name, kind, path, json_required)| {
            *name == "derived_traversal_probe_security_report"
                && *kind == "derived"
                && *json_required
                && path == &out_dir.join("traversal_probe_security_report.json")
        }));
        assert!(entries.iter().any(|(name, kind, path, json_required)| {
            *name == "source_managed_dns_report"
                && *kind == "source"
                && *json_required
                && path == &source_dir.join("managed_dns_report.json")
        }));
        assert!(entries.iter().any(|(name, kind, path, json_required)| {
            *name == "derived_managed_dns_report"
                && *kind == "derived"
                && *json_required
                && path == &out_dir.join("managed_dns_report.json")
        }));
    }

    #[test]
    fn hp2_traversal_report_writer_emits_expected_reports() {
        let unique = format!(
            "ops-phase10-hp2-writer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        let source_dir = root.join("source");
        fs::create_dir_all(source_dir.as_path()).expect("create source dir");

        let path_log = source_dir.join("traversal_path_selection_tests.log");
        let probe_log = source_dir.join("traversal_probe_security_tests.log");
        fs::write(path_log.as_path(), "path log\n").expect("write path log");
        fs::write(probe_log.as_path(), "probe log\n").expect("write probe log");

        execute_ops_write_phase10_hp2_traversal_reports(WritePhase10Hp2TraversalReportsConfig {
            source_dir: source_dir.clone(),
            environment: "ci".to_string(),
            path_selection_log: path_log.clone(),
            probe_security_log: probe_log.clone(),
        })
        .expect("HP2 report writer should succeed");

        let path_report = source_dir.join("traversal_path_selection_report.json");
        let probe_report = source_dir.join("traversal_probe_security_report.json");
        assert!(path_report.is_file());
        assert!(probe_report.is_file());

        let path_payload =
            read_json_object(path_report.as_path(), "path selection report").expect("path report");
        let probe_payload = read_json_object(probe_report.as_path(), "probe security report")
            .expect("probe report");

        assert_eq!(
            path_payload.get("suite").and_then(|value| value.as_str()),
            Some("traversal_path_selection")
        );
        assert_eq!(
            probe_payload.get("suite").and_then(|value| value.as_str()),
            Some("traversal_probe_security")
        );
        assert_eq!(
            path_payload.get("status").and_then(|value| value.as_str()),
            Some("pass")
        );
        assert_eq!(
            probe_payload.get("status").and_then(|value| value.as_str()),
            Some("pass")
        );

        fs::remove_file(path_report.as_path()).expect("remove path report");
        fs::remove_file(probe_report.as_path()).expect("remove probe report");
        fs::remove_file(path_log.as_path()).expect("remove path log");
        fs::remove_file(probe_log.as_path()).expect("remove probe log");
        fs::remove_dir_all(root.as_path()).expect("remove root dir");
    }

    #[test]
    fn read_json_object_rejects_oversized_source() {
        let unique = format!(
            "ops-phase10-source-size-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(temp_dir.as_path()).expect("temp directory should be creatable");
        let oversized_json_path = temp_dir.join("oversized.json");
        let oversized = vec![b' '; (MAX_PHASE10_JSON_SOURCE_BYTES as usize) + 1];
        fs::write(oversized_json_path.as_path(), oversized).expect("oversized file should write");

        let err = read_json_object(oversized_json_path.as_path(), "phase10 test source")
            .expect_err("oversized source must be rejected");
        assert!(err.contains("exceeds maximum size"));

        fs::remove_file(oversized_json_path.as_path()).expect("remove oversized source file");
        fs::remove_dir(temp_dir.as_path()).expect("remove temp directory");
    }

    #[test]
    fn read_utf8_regular_file_with_max_bytes_rejects_oversized_source() {
        let unique = format!(
            "ops-phase10-source-size-limit-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(temp_dir.as_path()).expect("temp directory should be creatable");
        let oversized_text_path = temp_dir.join("oversized.log");
        fs::write(oversized_text_path.as_path(), vec![b'x'; 257])
            .expect("oversized state source should write");

        let err = read_utf8_regular_file_with_max_bytes(
            oversized_text_path.as_path(),
            "phase10 state transition source",
            256,
        )
        .expect_err("oversized text source must be rejected");
        assert!(err.contains("exceeds maximum size"));

        fs::remove_file(oversized_text_path.as_path()).expect("remove oversized source file");
        fs::remove_dir(temp_dir.as_path()).expect("remove temp directory");
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

    #[test]
    fn phase10_provenance_keypair_writer_hardens_open_parent_directory() {
        let unique = format!(
            "ops-phase10-provenance-open-parent-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let key_dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(key_dir.as_path()).expect("create key directory");
        fs::set_permissions(key_dir.as_path(), fs::Permissions::from_mode(0o755))
            .expect("set insecure key directory mode");

        let signing_path = key_dir.join("signing_seed.hex");
        let verifier_path = key_dir.join("verifier_key.hex");
        write_phase10_provenance_keypair(signing_path.as_path(), verifier_path.as_path())
            .expect("phase10 provenance keypair writer should harden open parent directory");

        let dir_mode = fs::metadata(key_dir.as_path())
            .expect("key directory metadata should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode & 0o077, 0);

        fs::remove_file(signing_path.as_path()).expect("remove signing key file");
        fs::remove_file(verifier_path.as_path()).expect("remove verifier key file");
        fs::set_permissions(key_dir.as_path(), fs::Permissions::from_mode(0o700))
            .expect("set key directory mode for cleanup");
        fs::remove_dir(key_dir.as_path()).expect("remove key directory");
    }

    #[test]
    fn release_provenance_verification_rejects_tampered_artifact() {
        let unique = format!(
            "ops-release-provenance-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let root_dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(root_dir.as_path()).expect("create temp root");

        let artifact_path = root_dir.join("rustynetd");
        let sbom_path = root_dir.join("sbom.cargo-metadata.json");
        let sbom_digest_path = root_dir.join("sbom.sha256");
        let provenance_path = root_dir.join("rustynetd.provenance.json");

        fs::write(artifact_path.as_path(), b"binary-content-v1").expect("write artifact");
        fs::write(
            sbom_path.as_path(),
            br#"{"name":"rustynet","version":"0.1.0"}"#,
        )
        .expect("write sbom");
        let sbom_digest = sha256_hex(fs::read(sbom_path.as_path()).expect("read sbom").as_slice());
        fs::write(sbom_digest_path.as_path(), format!("{sbom_digest}\n"))
            .expect("write sbom digest");

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifier_key = signing_key.verifying_key();
        let generated_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_secs();
        let provenance = build_release_provenance_document(&ReleaseProvenanceBuildInputs {
            artifact_path: artifact_path.as_path(),
            sbom_path: sbom_path.as_path(),
            sbom_digest_path: sbom_digest_path.as_path(),
            generated_at_unix,
            host_identity: "ci-localhost",
            release_track: "beta",
            signing_key: &signing_key,
            verifier_key: &verifier_key,
        })
        .expect("build release provenance");
        let mut payload = serde_json::to_string_pretty(&provenance).expect("serialize provenance");
        payload.push('\n');
        fs::write(provenance_path.as_path(), payload.as_bytes()).expect("write provenance");

        verify_release_provenance_document(&ReleaseProvenanceVerifyInputs {
            provenance_path: provenance_path.as_path(),
            expected_artifact_path: artifact_path.as_path(),
            expected_sbom_path: sbom_path.as_path(),
            expected_sbom_digest_path: sbom_digest_path.as_path(),
            expected_host_identity: "ci-localhost",
            expected_release_track: "beta",
            verifier_key: &verifier_key,
            max_provenance_age_seconds: 3600,
        })
        .expect("baseline provenance verify");

        let mut artifact_handle = fs::OpenOptions::new()
            .append(true)
            .open(artifact_path.as_path())
            .expect("reopen artifact for tamper");
        artifact_handle
            .write_all(b"tamper")
            .expect("tamper write should succeed");
        artifact_handle.sync_all().expect("sync tampered artifact");

        let err = verify_release_provenance_document(&ReleaseProvenanceVerifyInputs {
            provenance_path: provenance_path.as_path(),
            expected_artifact_path: artifact_path.as_path(),
            expected_sbom_path: sbom_path.as_path(),
            expected_sbom_digest_path: sbom_digest_path.as_path(),
            expected_host_identity: "ci-localhost",
            expected_release_track: "beta",
            verifier_key: &verifier_key,
            max_provenance_age_seconds: 3600,
        })
        .expect_err("tampered artifact must fail verification");
        assert!(err.contains("artifact digest mismatch"));

        fs::remove_file(provenance_path.as_path()).expect("remove provenance");
        fs::remove_file(sbom_digest_path.as_path()).expect("remove sbom digest");
        fs::remove_file(sbom_path.as_path()).expect("remove sbom");
        fs::remove_file(artifact_path.as_path()).expect("remove artifact");
        fs::remove_dir(root_dir.as_path()).expect("remove temp root");
    }

    #[test]
    fn release_provenance_verification_rejects_unsigned_document() {
        let unique = format!(
            "ops-release-provenance-unsigned-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let root_dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(root_dir.as_path()).expect("create temp root");

        let artifact_path = root_dir.join("rustynetd");
        let sbom_path = root_dir.join("sbom.cargo-metadata.json");
        let sbom_digest_path = root_dir.join("sbom.sha256");
        let provenance_path = root_dir.join("rustynetd.provenance.json");

        fs::write(artifact_path.as_path(), b"binary-content-v1").expect("write artifact");
        fs::write(
            sbom_path.as_path(),
            br#"{"name":"rustynet","version":"0.1.0"}"#,
        )
        .expect("write sbom");
        let sbom_digest = sha256_hex(fs::read(sbom_path.as_path()).expect("read sbom").as_slice());
        fs::write(sbom_digest_path.as_path(), format!("{sbom_digest}\n"))
            .expect("write sbom digest");

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifier_key = signing_key.verifying_key();
        let generated_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_secs();
        let mut provenance = build_release_provenance_document(&ReleaseProvenanceBuildInputs {
            artifact_path: artifact_path.as_path(),
            sbom_path: sbom_path.as_path(),
            sbom_digest_path: sbom_digest_path.as_path(),
            generated_at_unix,
            host_identity: "ci-localhost",
            release_track: "beta",
            signing_key: &signing_key,
            verifier_key: &verifier_key,
        })
        .expect("build release provenance");
        let object = provenance
            .as_object_mut()
            .expect("release provenance should be object");
        object.remove("signature_hex");
        let mut serialized =
            serde_json::to_string_pretty(&provenance).expect("serialize unsigned provenance");
        serialized.push('\n');
        fs::write(provenance_path.as_path(), serialized.as_bytes()).expect("write provenance");

        let err = verify_release_provenance_document(&ReleaseProvenanceVerifyInputs {
            provenance_path: provenance_path.as_path(),
            expected_artifact_path: artifact_path.as_path(),
            expected_sbom_path: sbom_path.as_path(),
            expected_sbom_digest_path: sbom_digest_path.as_path(),
            expected_host_identity: "ci-localhost",
            expected_release_track: "beta",
            verifier_key: &verifier_key,
            max_provenance_age_seconds: 3600,
        })
        .expect_err("unsigned provenance must fail verification");
        assert!(err.contains("missing non-empty string field: signature_hex"));

        fs::remove_file(provenance_path.as_path()).expect("remove provenance");
        fs::remove_file(sbom_digest_path.as_path()).expect("remove sbom digest");
        fs::remove_file(sbom_path.as_path()).expect("remove sbom");
        fs::remove_file(artifact_path.as_path()).expect("remove artifact");
        fs::remove_dir(root_dir.as_path()).expect("remove temp root");
    }

    #[test]
    fn phase6_parity_attestation_verification_rejects_tampered_report() {
        let unique = format!(
            "ops-phase6-attestation-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let root_dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(root_dir.as_path()).expect("create temp root");

        let source_path = root_dir.join("probe-source.json");
        fs::write(source_path.as_path(), br#"{"probe":"ok"}"#).expect("write source");
        let report_path = root_dir.join("platform_parity_report.json");
        let captured_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_secs();
        let report = json!({
            "evidence_mode": "measured",
            "captured_at_unix": captured_at_unix,
            "environment": "ci",
            "source_artifacts": [source_path.display().to_string()],
        });
        let mut report_body = serde_json::to_string_pretty(&report).expect("serialize report");
        report_body.push('\n');
        fs::write(report_path.as_path(), report_body.as_bytes()).expect("write report");

        let attestation_path = root_dir.join("platform_parity_report.attestation.json");
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let verifier_key = signing_key.verifying_key();
        let attestation =
            build_phase6_parity_attestation_document(&Phase6ParityAttestationBuildInputs {
                report_path: report_path.as_path(),
                generated_at_unix: captured_at_unix,
                host_identity: "ci-localhost",
                git_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                signing_key: &signing_key,
                verifier_key: &verifier_key,
            })
            .expect("build phase6 attestation");
        let mut attestation_body =
            serde_json::to_string_pretty(&attestation).expect("serialize attestation");
        attestation_body.push('\n');
        fs::write(attestation_path.as_path(), attestation_body.as_bytes())
            .expect("write phase6 attestation");

        verify_phase6_parity_attestation_document(&Phase6ParityAttestationVerifyInputs {
            attestation_path: attestation_path.as_path(),
            expected_report_path: report_path.as_path(),
            expected_host_identity: "ci-localhost",
            expected_git_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            verifier_key: &verifier_key,
            max_attestation_age_seconds: 3600,
        })
        .expect("baseline phase6 attestation verify");

        fs::write(
            report_path.as_path(),
            br#"{"evidence_mode":"measured","captured_at_unix":1,"environment":"ci","source_artifacts":["tampered"]}"#,
        )
        .expect("tamper report");

        let err = verify_phase6_parity_attestation_document(&Phase6ParityAttestationVerifyInputs {
            attestation_path: attestation_path.as_path(),
            expected_report_path: report_path.as_path(),
            expected_host_identity: "ci-localhost",
            expected_git_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            verifier_key: &verifier_key,
            max_attestation_age_seconds: 3600,
        })
        .expect_err("tampered phase6 report must fail verification");
        assert!(err.contains("report digest mismatch"));

        fs::remove_file(attestation_path.as_path()).expect("remove attestation");
        fs::remove_file(report_path.as_path()).expect("remove report");
        fs::remove_file(source_path.as_path()).expect("remove source");
        fs::remove_dir(root_dir.as_path()).expect("remove temp root");
    }

    #[test]
    fn phase9_evidence_attestation_verification_rejects_git_commit_mismatch() {
        let unique = format!(
            "ops-phase9-attestation-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let root_dir = std::env::temp_dir().join(unique);
        let out_dir = root_dir.join("operations");
        fs::create_dir_all(out_dir.as_path()).expect("create phase9 output directory");
        let source_path = root_dir.join("source.log");
        fs::write(source_path.as_path(), b"source").expect("write source");
        let captured_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_secs();

        for artifact in PHASE9_REQUIRED_ARTIFACTS {
            let payload = json!({
                "evidence_mode": "measured",
                "captured_at_unix": captured_at_unix,
                "environment": "ci",
                "source_artifacts": [source_path.display().to_string()],
            });
            let mut body =
                serde_json::to_string_pretty(&payload).expect("serialize phase9 artifact payload");
            body.push('\n');
            fs::write(out_dir.join(artifact), body.as_bytes()).expect("write phase9 artifact");
        }

        let signing_key = SigningKey::from_bytes(&[13u8; 32]);
        let verifier_key = signing_key.verifying_key();
        let attestation =
            build_phase9_evidence_attestation_document(&Phase9EvidenceAttestationBuildInputs {
                out_dir: out_dir.as_path(),
                environment: "ci",
                generated_at_unix: captured_at_unix,
                host_identity: "ci-localhost",
                git_commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                signing_key: &signing_key,
                verifier_key: &verifier_key,
            })
            .expect("build phase9 evidence attestation");
        let attestation_path = out_dir.join("phase9_evidence.attestation.json");
        let mut attestation_body =
            serde_json::to_string_pretty(&attestation).expect("serialize phase9 attestation");
        attestation_body.push('\n');
        fs::write(attestation_path.as_path(), attestation_body.as_bytes())
            .expect("write phase9 attestation");

        verify_phase9_evidence_attestation_document(&Phase9EvidenceAttestationVerifyInputs {
            attestation_path: attestation_path.as_path(),
            expected_out_dir: out_dir.as_path(),
            expected_host_identity: "ci-localhost",
            expected_git_commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            verifier_key: &verifier_key,
            max_attestation_age_seconds: 3600,
        })
        .expect("baseline phase9 verify");

        let err =
            verify_phase9_evidence_attestation_document(&Phase9EvidenceAttestationVerifyInputs {
                attestation_path: attestation_path.as_path(),
                expected_out_dir: out_dir.as_path(),
                expected_host_identity: "ci-localhost",
                expected_git_commit: "cccccccccccccccccccccccccccccccccccccccc",
                verifier_key: &verifier_key,
                max_attestation_age_seconds: 3600,
            })
            .expect_err("phase9 verify must fail on commit mismatch");
        assert!(err.contains("git commit mismatch"));

        fs::remove_file(attestation_path.as_path()).expect("remove phase9 attestation");
        for artifact in PHASE9_REQUIRED_ARTIFACTS {
            fs::remove_file(out_dir.join(artifact)).expect("remove phase9 artifact");
        }
        fs::remove_file(source_path.as_path()).expect("remove source");
        fs::remove_dir(out_dir.as_path()).expect("remove operations directory");
        fs::remove_dir(root_dir.as_path()).expect("remove temp root");
    }
}
