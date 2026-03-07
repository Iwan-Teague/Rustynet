#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use nix::unistd::Uid;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use rustynet_crypto::{
    KeyCustodyManager, KeyCustodyPermissionPolicy, PlatformOsSecureStore, write_encrypted_key_file,
};
#[cfg(target_os = "macos")]
use rustynet_crypto::{
    OsStoreFallbackPolicy, load_macos_generic_password, store_macos_generic_password,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const PASSPHRASE_CREDENTIAL_PATH_ENV: &str = "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH";
const SYSTEMD_CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";
#[cfg(not(target_os = "macos"))]
const DEFAULT_PASSPHRASE_CREDENTIAL_NAME: &str = "wg_key_passphrase";
#[cfg(target_os = "macos")]
const PASSPHRASE_KEYCHAIN_ACCOUNT_ENV: &str = "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT";
#[cfg(target_os = "macos")]
const MACOS_PASSPHRASE_KEYCHAIN_SERVICE: &str = "rustynet.wg_passphrase";
const MAX_PASSPHRASE_BYTES: usize = 4096;
const WG_BINARY_PATH_ENV: &str = "RUSTYNET_WG_BINARY_PATH";
#[cfg(not(target_os = "macos"))]
const IP_BINARY_PATH_ENV: &str = "RUSTYNET_IP_BINARY_PATH";
#[cfg(target_os = "macos")]
const IFCONFIG_BINARY_PATH_ENV: &str = "RUSTYNET_IFCONFIG_BINARY_PATH";
const DEFAULT_WG_BINARY_PATH: &str = "/usr/bin/wg";
#[cfg(not(target_os = "macos"))]
const DEFAULT_IP_BINARY_PATH: &str = "/usr/sbin/ip";
#[cfg(target_os = "macos")]
const DEFAULT_IFCONFIG_BINARY_PATH: &str = "/sbin/ifconfig";

pub fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>, String> {
    #[cfg(target_os = "macos")]
    if let Some(account) = resolve_macos_keychain_account_from_env()? {
        return read_passphrase_from_macos_keychain(&account);
    }
    let source_path = resolve_passphrase_source(path)?;
    read_passphrase_from_source(&source_path)
}

pub fn read_passphrase_file_explicit(path: &Path) -> Result<Zeroizing<String>, String> {
    read_passphrase_from_source(path)
}

pub fn store_passphrase_in_os_secure_store(
    passphrase_path: &Path,
    keychain_account: Option<&str>,
) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let account = match keychain_account {
            Some(value) => normalize_macos_keychain_account(value)?,
            None => resolve_macos_keychain_account_from_env()?.ok_or_else(|| {
                format!(
                    "missing {PASSPHRASE_KEYCHAIN_ACCOUNT_ENV}; configure a macOS keychain account for passphrase custody"
                )
            })?,
        };
        let passphrase = read_passphrase_file_explicit(passphrase_path)?;
        store_macos_generic_password(
            MACOS_PASSPHRASE_KEYCHAIN_SERVICE,
            account.as_str(),
            passphrase.as_bytes(),
        )
        .map_err(|err| format!("store macOS keychain passphrase failed: {err}"))?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (passphrase_path, keychain_account);
        Err("passphrase secure-store provisioning is only supported on macOS".to_string())
    }
}

fn read_passphrase_from_source(source_path: &Path) -> Result<Zeroizing<String>, String> {
    let allow_root_owner = is_systemd_credential_path(source_path);
    validate_secret_file_security(source_path, "passphrase file", allow_root_owner)?;

    let raw = fs::read(source_path).map_err(|err| format!("read passphrase file failed: {err}"))?;
    parse_passphrase_bytes(raw, "passphrase file")
}

fn parse_passphrase_bytes(
    mut raw: Vec<u8>,
    source_label: &str,
) -> Result<Zeroizing<String>, String> {
    if raw.len() > MAX_PASSPHRASE_BYTES {
        raw.zeroize();
        return Err("passphrase exceeds maximum allowed size".to_string());
    }
    let decoded = match std::str::from_utf8(&raw) {
        Ok(value) => value,
        Err(_) => {
            raw.zeroize();
            return Err(format!("{source_label} contains non-utf8 bytes"));
        }
    };
    let trimmed = decoded.trim();
    if trimmed.len() < 16 {
        raw.zeroize();
        return Err("passphrase must be at least 16 characters".to_string());
    }
    let value = Zeroizing::new(trimmed.to_string());
    raw.zeroize();
    Ok(value)
}

#[cfg(target_os = "macos")]
fn read_passphrase_from_macos_keychain(account: &str) -> Result<Zeroizing<String>, String> {
    let value =
        load_macos_generic_password(MACOS_PASSPHRASE_KEYCHAIN_SERVICE, account).map_err(|err| {
            format!(
                "load macOS keychain passphrase failed for service '{MACOS_PASSPHRASE_KEYCHAIN_SERVICE}' account '{account}': {err}",
            )
        })?;
    parse_passphrase_bytes(value, "macOS keychain passphrase")
}

#[cfg(target_os = "macos")]
fn resolve_macos_keychain_account_from_env() -> Result<Option<String>, String> {
    let account = match std::env::var(PASSPHRASE_KEYCHAIN_ACCOUNT_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!(
                "{PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} must be valid utf-8",
            ));
        }
    };
    Ok(Some(normalize_macos_keychain_account(&account)?))
}

#[cfg(target_os = "macos")]
fn normalize_macos_keychain_account(raw: &str) -> Result<String, String> {
    let account = raw.trim();
    if account.is_empty() {
        return Err(format!(
            "{PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} must not be empty",
        ));
    }
    if account.len() > 128 {
        return Err(format!(
            "{PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} exceeds max length (128)",
        ));
    }
    if !account
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    {
        return Err(format!(
            "{PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} contains invalid characters; allowed: [A-Za-z0-9._-]",
        ));
    }
    Ok(account.to_string())
}

pub fn decrypt_private_key(
    encrypted_key_path: &Path,
    passphrase_path: &Path,
) -> Result<Vec<u8>, String> {
    let passphrase = read_passphrase_file(passphrase_path)?;
    let manager = key_custody_manager(encrypted_key_path, passphrase)?;
    let key_id = key_custody_key_id(encrypted_key_path);
    let mut key = manager
        .load_private_key(&key_id)
        .map_err(|err| format!("decrypt encrypted key failed: {err}"))?;
    if key.is_empty() {
        return Err("decrypted key is empty".to_string());
    }
    if !key.ends_with(b"\n") {
        key.push(b'\n');
    }
    Ok(key)
}

pub fn encrypt_private_key(
    private_key: &[u8],
    encrypted_key_path: &Path,
    passphrase_path: &Path,
) -> Result<(), String> {
    encrypt_private_key_with_passphrase(private_key, encrypted_key_path, passphrase_path, None)
}

pub fn encrypt_private_key_with_passphrase(
    private_key: &[u8],
    encrypted_key_path: &Path,
    passphrase_path: &Path,
    explicit_passphrase_path: Option<&Path>,
) -> Result<(), String> {
    let passphrase = match explicit_passphrase_path {
        Some(path) => read_passphrase_file_explicit(path)?,
        None => read_passphrase_file(passphrase_path)?,
    };
    let manager = key_custody_manager(encrypted_key_path, passphrase.clone())?;
    let key_id = key_custody_key_id(encrypted_key_path);
    let _backend = manager
        .store_private_key(&key_id, private_key)
        .map_err(|err| format!("encrypt key failed: {err}"))?;
    let parent = encrypted_key_path
        .parent()
        .ok_or_else(|| "encrypted key path must include parent directory".to_string())?;
    // Keep the configured encrypted-key path materialized on disk for service prechecks and
    // deterministic bootstrap across hosts, even when the custody backend also stores by key-id.
    write_encrypted_key_file(
        parent,
        encrypted_key_path,
        private_key,
        &passphrase,
        KeyCustodyPermissionPolicy::default(),
    )
    .map_err(|err| format!("encrypt key backup failed: {err}"))?;
    Ok(())
}

fn key_custody_manager(
    encrypted_key_path: &Path,
    passphrase: Zeroizing<String>,
) -> Result<KeyCustodyManager<PlatformOsSecureStore>, String> {
    let parent = encrypted_key_path
        .parent()
        .ok_or_else(|| "encrypted key path must include parent directory".to_string())?;
    let manager = KeyCustodyManager::new_zeroizing(
        PlatformOsSecureStore,
        parent.to_path_buf(),
        passphrase,
        KeyCustodyPermissionPolicy::default(),
    );
    #[cfg(target_os = "macos")]
    let manager = manager.with_fallback_policy(OsStoreFallbackPolicy::RequireOsSecureStore);
    Ok(manager)
}

fn validate_secret_file_security(
    path: &Path,
    label: &str,
    allow_root_owner: bool,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| format!("{label} metadata read failed: {err}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("{label} must not be a symlink"));
        }
        if !metadata.file_type().is_file() {
            return Err(format!("{label} must be a regular file"));
        }
        let mode = metadata.mode() & 0o777;
        let disallowed_mode_mask = if allow_root_owner { 0o037 } else { 0o077 };
        if mode & disallowed_mode_mask != 0 {
            let expected = if allow_root_owner {
                "owner-only or root-owned credential with group-read only"
            } else {
                "owner-only"
            };
            return Err(format!(
                "{label} permissions are too broad: expected {expected}, found {mode:03o}",
            ));
        }
        let owner_uid = metadata.uid();
        let expected_uid = Uid::effective().as_raw();
        if owner_uid != expected_uid && !(allow_root_owner && owner_uid == 0) {
            return Err(format!(
                "{label} owner uid mismatch: expected {expected_uid}, found {owner_uid}"
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let metadata =
            fs::metadata(path).map_err(|err| format!("{label} metadata read failed: {err}"))?;
        if !metadata.is_file() {
            return Err(format!("{label} must be a regular file"));
        }
    }
    Ok(())
}

fn resolve_passphrase_source(configured_path: &Path) -> Result<PathBuf, String> {
    let explicit = std::env::var(PASSPHRASE_CREDENTIAL_PATH_ENV).ok();
    let directory = std::env::var(SYSTEMD_CREDENTIALS_DIRECTORY_ENV).ok();
    resolve_passphrase_source_from_env(configured_path, explicit.as_deref(), directory.as_deref())
}

fn resolve_passphrase_source_from_env(
    configured_path: &Path,
    explicit_credential_path: Option<&str>,
    credentials_directory: Option<&str>,
) -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = (
            configured_path,
            explicit_credential_path,
            credentials_directory,
        );
        Err(format!(
            "macOS passphrase file custody is disabled; set {PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} and provision the passphrase in keychain",
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(explicit) = explicit_credential_path {
            let explicit_path = PathBuf::from(explicit);
            if explicit_path.exists() {
                return Ok(explicit_path);
            }
            return Err(format!(
                "passphrase credential path not found ({}={})",
                PASSPHRASE_CREDENTIAL_PATH_ENV,
                explicit_path.display()
            ));
        }

        if let Some(directory) = credentials_directory {
            let candidate = Path::new(directory).join(DEFAULT_PASSPHRASE_CREDENTIAL_NAME);
            if candidate.exists() {
                return Ok(candidate);
            }
            return Err(format!(
                "passphrase credential not found in {} (expected {})",
                SYSTEMD_CREDENTIALS_DIRECTORY_ENV,
                candidate.display()
            ));
        }

        if configured_path.exists() {
            return Err(format!(
                "passphrase credential source must be explicitly configured via {} or {}; direct fallback to {} is disallowed",
                PASSPHRASE_CREDENTIAL_PATH_ENV,
                SYSTEMD_CREDENTIALS_DIRECTORY_ENV,
                configured_path.display()
            ));
        }

        return Err(format!(
            "passphrase credential source is not configured; set {} or {}",
            PASSPHRASE_CREDENTIAL_PATH_ENV, SYSTEMD_CREDENTIALS_DIRECTORY_ENV
        ));
    }
}

fn is_systemd_credential_path(path: &Path) -> bool {
    path.starts_with("/run/credentials/")
}

fn key_custody_key_id(encrypted_key_path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(encrypted_key_path.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut suffix = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        suffix.push_str(&format!("{byte:02x}"));
    }
    format!("wg-private-{suffix}")
}

pub fn write_runtime_private_key(path: &Path, private_key: &[u8]) -> Result<(), String> {
    if private_key.is_empty() {
        return Err("private key must not be empty".to_string());
    }
    write_atomic(path, private_key, 0o600)
}

pub fn write_public_key(path: &Path, public_key: &str) -> Result<(), String> {
    if public_key.trim().is_empty() {
        return Err("public key must not be empty".to_string());
    }
    let value = format!("{}\n", public_key.trim());
    write_atomic(path, value.as_bytes(), 0o644)
}

pub fn generate_wireguard_keypair() -> Result<(Vec<u8>, String), String> {
    let wg_binary = resolve_wireguard_binary_path()?;
    let private = Command::new(&wg_binary)
        .arg("genkey")
        .output()
        .map_err(|err| format!("wg genkey spawn failed ({}): {err}", wg_binary.display()))?;
    if !private.status.success() {
        return Err(format!("wg genkey failed: {}", private.status));
    }
    let mut private_key = private.stdout;
    if private_key.is_empty() {
        return Err("wg genkey produced empty key".to_string());
    }
    if !private_key.ends_with(b"\n") {
        private_key.push(b'\n');
    }

    let public_key = match derive_public_key_from_private_key(&private_key) {
        Ok(value) => value,
        Err(err) => {
            private_key.fill(0);
            return Err(err);
        }
    };
    Ok((private_key, public_key))
}

pub fn apply_interface_private_key(
    interface_name: &str,
    runtime_key_path: &Path,
) -> Result<(), String> {
    validate_interface_name(interface_name)?;
    let wg_binary = resolve_wireguard_binary_path()?;
    let status = Command::new(&wg_binary)
        .arg("set")
        .arg(interface_name)
        .arg("private-key")
        .arg(runtime_key_path)
        .status()
        .map_err(|err| {
            format!(
                "wg set private-key spawn failed ({}): {err}",
                wg_binary.display()
            )
        })?;
    if status.success() {
        return Ok(());
    }
    Err(format!(
        "wg set private-key failed for {interface_name}: {status}",
    ))
}

pub fn set_interface_down(interface_name: &str) -> Result<(), String> {
    validate_interface_name(interface_name)?;
    #[cfg(target_os = "macos")]
    let status = {
        let ifconfig_binary = resolve_ifconfig_binary_path()?;
        Command::new(&ifconfig_binary)
            .arg(interface_name)
            .arg("down")
            .status()
            .map_err(|err| {
                format!(
                    "ifconfig down spawn failed ({}): {err}",
                    ifconfig_binary.display()
                )
            })?
    };
    #[cfg(not(target_os = "macos"))]
    let status = {
        let ip_binary = resolve_ip_binary_path()?;
        Command::new(&ip_binary)
            .arg("link")
            .arg("set")
            .arg("down")
            .arg("dev")
            .arg(interface_name)
            .status()
            .map_err(|err| {
                format!(
                    "ip link set down spawn failed ({}): {err}",
                    ip_binary.display()
                )
            })?
    };
    if status.success() {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    return Err(format!(
        "ifconfig down failed for {interface_name}: {status}",
    ));
    #[cfg(not(target_os = "macos"))]
    Err(format!(
        "ip link set down failed for {}: {}",
        interface_name, status
    ))
}

pub fn remove_file_if_present(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("inspect {} failed: {err}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        return fs::remove_file(path)
            .map_err(|err| format!("remove symlink {} failed: {err}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "secure remove requires a regular file: {}",
            path.display()
        ));
    }
    scrub_file_contents(path)?;
    fs::remove_file(path).map_err(|err| format!("remove {} failed: {err}", path.display()))
}

fn scrub_file_contents(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|err| format!("inspect file {} failed: {err}", path.display()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|err| format!("open {} failed: {err}", path.display()))?;
    let mut remaining = metadata.len();
    let zero_block = [0u8; 8192];
    while remaining > 0 {
        let chunk_len = std::cmp::min(remaining, zero_block.len() as u64) as usize;
        file.write_all(&zero_block[..chunk_len])
            .map_err(|err| format!("scrub write {} failed: {err}", path.display()))?;
        remaining -= chunk_len as u64;
    }
    file.sync_all()
        .map_err(|err| format!("sync {} failed: {err}", path.display()))?;
    file.set_len(0)
        .map_err(|err| format!("truncate {} failed: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("sync {} after truncate failed: {err}", path.display()))?;
    Ok(())
}

pub fn initialize_encrypted_key_material(
    runtime_private_key_path: &Path,
    encrypted_key_path: &Path,
    public_key_path: &Path,
    passphrase_path: &Path,
    explicit_passphrase_path: Option<&Path>,
    force: bool,
) -> Result<String, String> {
    if !force
        && (runtime_private_key_path.exists()
            || encrypted_key_path.exists()
            || public_key_path.exists())
    {
        return Err(
            "key material already exists; use --force to overwrite existing files".to_string(),
        );
    }

    let (mut private_key, public_key) = generate_wireguard_keypair()?;
    let result = (|| -> Result<String, String> {
        encrypt_private_key_with_passphrase(
            &private_key,
            encrypted_key_path,
            passphrase_path,
            explicit_passphrase_path,
        )?;
        if let Err(err) = write_runtime_private_key(runtime_private_key_path, &private_key) {
            let _ = remove_file_if_present(runtime_private_key_path);
            return Err(err);
        }
        if let Err(err) = write_public_key(public_key_path, &public_key) {
            let _ = remove_file_if_present(public_key_path);
            return Err(err);
        }
        Ok(public_key.clone())
    })();
    private_key.fill(0);
    result
}

pub fn migrate_existing_private_key_material(
    existing_private_key_path: &Path,
    runtime_private_key_path: &Path,
    encrypted_key_path: &Path,
    public_key_path: &Path,
    passphrase_path: &Path,
    explicit_passphrase_path: Option<&Path>,
    force: bool,
) -> Result<String, String> {
    if !existing_private_key_path.exists() {
        return Err(format!(
            "existing private key file not found: {}",
            existing_private_key_path.display()
        ));
    }
    if !force && (encrypted_key_path.exists() || public_key_path.exists()) {
        return Err(
            "target key material already exists; use --force to overwrite existing files"
                .to_string(),
        );
    }

    let mut private_key = fs::read(existing_private_key_path).map_err(|err| {
        format!(
            "read existing private key {} failed: {err}",
            existing_private_key_path.display()
        )
    })?;
    if private_key.is_empty() {
        return Err("existing private key is empty".to_string());
    }
    if !private_key.ends_with(b"\n") {
        private_key.push(b'\n');
    }

    let result = (|| -> Result<String, String> {
        let public_key = derive_public_key_from_private_key(&private_key)?;
        encrypt_private_key_with_passphrase(
            &private_key,
            encrypted_key_path,
            passphrase_path,
            explicit_passphrase_path,
        )?;
        if let Err(err) = write_runtime_private_key(runtime_private_key_path, &private_key) {
            let _ = remove_file_if_present(runtime_private_key_path);
            return Err(err);
        }
        if let Err(err) = write_public_key(public_key_path, &public_key) {
            let _ = remove_file_if_present(public_key_path);
            return Err(err);
        }
        Ok(public_key)
    })();
    private_key.fill(0);
    result
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path {} has no parent", path.display()))?;
    if parent.exists() {
        let parent_meta = fs::symlink_metadata(parent).map_err(|err| {
            format!(
                "inspect parent directory {} failed: {err}",
                parent.display()
            )
        })?;
        if parent_meta.file_type().is_symlink() || !parent_meta.file_type().is_dir() {
            return Err(format!(
                "parent path {} must be a real directory, not a symlink",
                parent.display()
            ));
        }
    }
    fs::create_dir_all(parent)
        .map_err(|err| format!("create parent directory {} failed: {err}", parent.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        match fs::set_permissions(parent, fs::Permissions::from_mode(0o700)) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                let metadata = fs::metadata(parent).map_err(|meta_err| {
                    format!(
                        "inspect parent permissions {} failed after chmod denial: {meta_err}",
                        parent.display()
                    )
                })?;
                let mode = metadata.permissions().mode() & 0o777;
                let owner_uid = metadata.uid();
                let expected_uid = Uid::effective().as_raw();
                // Privilege-separated deployments keep /run/rustynet root-owned and group-writable
                // for helper + daemon cooperation; accept that hardened shared parent shape.
                let root_managed_shared_runtime = owner_uid == 0 && mode == 0o770;
                if !root_managed_shared_runtime {
                    return Err(format!(
                        "set parent permissions {} failed: {err}",
                        parent.display()
                    ));
                }
                if owner_uid == expected_uid {
                    return Err(format!(
                        "set parent permissions {} failed despite owner match: {err}",
                        parent.display()
                    ));
                }
            }
            Err(err) => {
                return Err(format!(
                    "set parent permissions {} failed: {err}",
                    parent.display()
                ));
            }
        }
    }

    let temp = temp_path_for(path);
    if path.exists() {
        let target_meta = fs::symlink_metadata(path)
            .map_err(|err| format!("inspect target {} failed: {err}", path.display()))?;
        if target_meta.file_type().is_symlink() {
            return Err(format!("target {} must not be a symlink", path.display()));
        }
        if !target_meta.file_type().is_file() {
            return Err(format!("target {} must be a regular file", path.display()));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    let mut file = options
        .open(&temp)
        .map_err(|err| format!("create temp key file {} failed: {err}", temp.display()))?;
    if let Err(err) = file.write_all(bytes) {
        let _ = fs::remove_file(&temp);
        return Err(format!(
            "write temp key file {} failed: {err}",
            temp.display()
        ));
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&temp);
        return Err(format!(
            "sync temp key file {} failed: {err}",
            temp.display()
        ));
    }
    if let Err(err) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(format!(
            "rename temp key file {} to {} failed: {err}",
            temp.display(),
            path.display()
        ));
    }
    let parent_dir = fs::File::open(parent)
        .map_err(|err| format!("open parent directory {} failed: {err}", parent.display()))?;
    parent_dir
        .sync_all()
        .map_err(|err| format!("sync parent directory {} failed: {err}", parent.display()))?;
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut out = path.as_os_str().to_os_string();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    out.push(format!(".tmp.{}.{}", std::process::id(), stamp));
    PathBuf::from(out)
}

fn validate_interface_name(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("interface name must not be empty".to_string());
    }
    if value.len() > 15 {
        return Err("interface name must be <= 15 characters".to_string());
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    {
        return Ok(());
    }
    Err("interface name contains invalid characters".to_string())
}

fn resolve_wireguard_binary_path() -> Result<PathBuf, String> {
    resolve_binary_path(WG_BINARY_PATH_ENV, DEFAULT_WG_BINARY_PATH, "wg")
}

#[cfg(not(target_os = "macos"))]
fn resolve_ip_binary_path() -> Result<PathBuf, String> {
    resolve_binary_path(IP_BINARY_PATH_ENV, DEFAULT_IP_BINARY_PATH, "ip")
}

#[cfg(target_os = "macos")]
fn resolve_ifconfig_binary_path() -> Result<PathBuf, String> {
    resolve_binary_path(
        IFCONFIG_BINARY_PATH_ENV,
        DEFAULT_IFCONFIG_BINARY_PATH,
        "ifconfig",
    )
}

fn resolve_binary_path(env_var: &str, default_path: &str, label: &str) -> Result<PathBuf, String> {
    let configured = std::env::var(env_var).ok();
    let candidate = configured
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_path);
    validate_binary_path(candidate, label)?;
    Ok(PathBuf::from(candidate))
}

fn validate_binary_path(raw_path: &str, label: &str) -> Result<(), String> {
    let path = Path::new(raw_path);
    if !path.is_absolute() {
        return Err(format!("{label} binary path must be absolute: {raw_path}"));
    }
    let canonical = fs::canonicalize(path).map_err(|err| {
        format!(
            "{label} binary canonicalization failed for {}: {err}",
            path.display()
        )
    })?;
    let metadata =
        fs::metadata(&canonical).map_err(|err| format!("{label} binary metadata failed: {err}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} binary path must be a regular file: {}",
            canonical.display()
        ));
    }
    #[cfg(unix)]
    {
        let mode = metadata.mode() & 0o777;
        if mode & 0o111 == 0 {
            return Err(format!(
                "{label} binary is not executable: {} ({:03o})",
                canonical.display(),
                mode
            ));
        }
        if mode & 0o022 != 0 {
            return Err(format!(
                "{label} binary must not be group/other writable: {} ({:03o})",
                canonical.display(),
                mode
            ));
        }
        let owner_uid = metadata.uid();
        if owner_uid != 0 {
            return Err(format!(
                "{label} binary must be root-owned: {} (uid={owner_uid})",
                canonical.display()
            ));
        }
    }
    Ok(())
}

fn derive_public_key_from_private_key(private_key: &[u8]) -> Result<String, String> {
    let wg_binary = resolve_wireguard_binary_path()?;
    let mut child = Command::new(&wg_binary)
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| format!("wg pubkey spawn failed ({}): {err}", wg_binary.display()))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "wg pubkey stdin unavailable".to_string())?;
        stdin
            .write_all(private_key)
            .map_err(|err| format!("wg pubkey stdin write failed: {err}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("wg pubkey wait failed: {err}"))?;
    if !output.status.success() {
        return Err(format!("wg pubkey failed: {}", output.status));
    }
    let public_key = String::from_utf8(output.stdout)
        .map_err(|err| format!("wg pubkey produced non-utf8 output: {err}"))?
        .trim()
        .to_string();
    if public_key.is_empty() {
        return Err("wg pubkey produced empty key".to_string());
    }
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "macos"))]
    use super::DEFAULT_PASSPHRASE_CREDENTIAL_NAME;
    use super::{remove_file_if_present, resolve_passphrase_source_from_env, validate_binary_path};

    fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{stamp}"));
        std::fs::create_dir_all(&dir).expect("test directory should be creatable");
        dir
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn resolve_passphrase_source_prefers_explicit_credential_path_env() {
        let test_dir = unique_test_dir("rustynet-passphrase-source-explicit");
        let configured = test_dir.join("configured.passphrase");
        let explicit = test_dir.join("explicit.passphrase");
        std::fs::write(&configured, "configured").expect("configured path should be writable");
        std::fs::write(&explicit, "explicit").expect("explicit path should be writable");

        let resolved = resolve_passphrase_source_from_env(
            &configured,
            Some(&explicit.to_string_lossy()),
            None,
        )
        .expect("explicit credential path should resolve");
        assert_eq!(resolved, explicit);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn resolve_passphrase_source_uses_credentials_directory_when_present() {
        let test_dir = unique_test_dir("rustynet-passphrase-source-credentials-dir");
        let configured = test_dir.join("configured.passphrase");
        let credentials_dir = test_dir.join("credentials");
        std::fs::create_dir_all(&credentials_dir).expect("credentials dir should be creatable");
        let credential = credentials_dir.join(DEFAULT_PASSPHRASE_CREDENTIAL_NAME);
        std::fs::write(&configured, "configured").expect("configured path should be writable");
        std::fs::write(&credential, "credential").expect("credential path should be writable");

        let resolved = resolve_passphrase_source_from_env(
            &configured,
            None,
            Some(&credentials_dir.to_string_lossy()),
        )
        .expect("credential directory path should resolve");
        assert_eq!(resolved, credential);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn resolve_passphrase_source_rejects_direct_configured_path_fallback() {
        let test_dir = unique_test_dir("rustynet-passphrase-source-fallback");
        let configured = test_dir.join("configured.passphrase");
        std::fs::write(&configured, "configured").expect("configured path should be writable");

        let err = resolve_passphrase_source_from_env(&configured, None, None)
            .expect_err("direct configured path fallback must be rejected");
        assert!(err.contains("disallowed"));

        let _ = std::fs::remove_file(&configured);
        let err = resolve_passphrase_source_from_env(&configured, None, None)
            .expect_err("missing credential source must be rejected");
        assert!(err.contains("not configured"));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn resolve_passphrase_source_rejects_file_custody_on_macos() {
        let test_dir = unique_test_dir("rustynet-passphrase-source-macos");
        let configured = test_dir.join("configured.passphrase");
        let err = resolve_passphrase_source_from_env(&configured, None, None)
            .expect_err("macOS must reject passphrase file custody");
        assert!(err.contains("disabled"));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn remove_file_if_present_removes_target_file() {
        let test_dir = unique_test_dir("rustynet-remove-file");
        let target = test_dir.join("secret.key");
        std::fs::write(&target, b"wireguard-private-key").expect("test target should be writable");
        remove_file_if_present(&target).expect("remove should succeed");
        assert!(!target.exists());
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn validate_binary_path_rejects_relative_paths() {
        let err = validate_binary_path("wg", "wg").expect_err("relative paths should be rejected");
        assert!(err.contains("must be absolute"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_binary_path_rejects_symlink_to_untrusted_target() {
        let test_dir = unique_test_dir("rustynet-binary-symlink");
        let target = test_dir.join("wg-real");
        let symlink = test_dir.join("wg-link");
        std::fs::write(&target, "#!/bin/sh\n").expect("target should be writable");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
            .expect("target should be executable");
        std::os::unix::fs::symlink(&target, &symlink).expect("symlink should be creatable");

        let err =
            validate_binary_path(symlink.to_str().expect("symlink path should be utf8"), "wg")
                .expect_err("untrusted symlink target should be rejected");
        assert!(err.contains("must be root-owned"));

        let _ = std::fs::remove_dir_all(test_dir);
    }
}
