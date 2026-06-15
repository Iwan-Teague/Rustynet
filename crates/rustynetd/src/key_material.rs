#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use crate::windows_paths::{
    validate_windows_local_secret_acl, validate_windows_local_secret_input_path,
    validate_windows_runtime_acl, validate_windows_runtime_file_path,
    validate_windows_secret_blob_path,
};
#[cfg(unix)]
use nix::unistd::Uid;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(any(target_os = "macos", windows))]
use rustynet_crypto::OsStoreFallbackPolicy;
use rustynet_crypto::{
    KeyCustodyManager, KeyCustodyPermissionPolicy, PlatformOsSecureStore, write_encrypted_key_file,
};
#[cfg(target_os = "macos")]
use rustynet_crypto::{
    load_macos_generic_password, store_macos_generic_password_system_keychain_owned,
};
#[cfg(windows)]
use rustynet_windows_native::{WindowsDpapiScope, dpapi_protect, dpapi_unprotect};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const PASSPHRASE_CREDENTIAL_PATH_ENV: &str = "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH";
const SYSTEMD_CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";
#[cfg(not(target_os = "macos"))]
const DEFAULT_PASSPHRASE_CREDENTIAL_NAME: &str = "wg_key_passphrase";
#[cfg(target_os = "macos")]
const PASSPHRASE_KEYCHAIN_ACCOUNT_ENV: &str = "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT";
#[cfg(target_os = "macos")]
const MACOS_PASSPHRASE_KEYCHAIN_SERVICE: &str = "net.rustynet.wg-key-passphrase";
const MAX_PASSPHRASE_BYTES: usize = 4096;
const WG_BINARY_PATH_ENV: &str = "RUSTYNET_WG_BINARY_PATH";
#[cfg(not(target_os = "macos"))]
const IP_BINARY_PATH_ENV: &str = "RUSTYNET_IP_BINARY_PATH";
#[cfg(target_os = "macos")]
const IFCONFIG_BINARY_PATH_ENV: &str = "RUSTYNET_IFCONFIG_BINARY_PATH";
#[cfg(not(windows))]
const DEFAULT_WG_BINARY_PATH: &str = "/usr/bin/wg";
#[cfg(windows)]
const DEFAULT_WG_BINARY_PATH: &str = r"C:\Program Files\WireGuard\wg.exe";
#[cfg(not(target_os = "macos"))]
const DEFAULT_IP_BINARY_PATH: &str = "/usr/sbin/ip";
#[cfg(target_os = "macos")]
const DEFAULT_IFCONFIG_BINARY_PATH: &str = "/sbin/ifconfig";
#[cfg(windows)]
const WINDOWS_DPAPI_PASSPHRASE_BLOB_MAGIC: &[u8; 8] = b"RNYDPAPI";
#[cfg(windows)]
const WINDOWS_DPAPI_PASSPHRASE_BLOB_VERSION: u8 = 1;
#[cfg(windows)]
const WINDOWS_DPAPI_PASSPHRASE_DESCRIPTION: &str = "RustyNet WireGuard passphrase";
#[cfg(windows)]
const WINDOWS_DPAPI_STARTUP_SELF_TEST_PLAINTEXT: &[u8] = b"RustyNet DPAPI startup self-test v1";
#[cfg(windows)]
static WINDOWS_DPAPI_STARTUP_SELF_TEST: OnceLock<Result<(), String>> = OnceLock::new();

pub fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>, String> {
    #[cfg(target_os = "macos")]
    if let Some(account) = resolve_macos_keychain_account_from_env()? {
        return read_passphrase_from_macos_keychain(&account);
    }
    #[cfg(windows)]
    {
        return read_windows_runtime_passphrase_source(path);
    }
    #[cfg(not(windows))]
    {
        let source_path = resolve_passphrase_source(path)?;
        read_passphrase_from_source(&source_path)
    }
}

pub fn read_passphrase_file_explicit(path: &Path) -> Result<Zeroizing<String>, String> {
    #[cfg(windows)]
    {
        read_windows_explicit_passphrase_source(path)
    }
    #[cfg(not(windows))]
    {
        read_passphrase_from_source(path)
    }
}

pub fn store_passphrase_in_os_secure_store(
    passphrase_path: &Path,
    keychain_account: Option<&str>,
    keychain_service: Option<&str>,
    allow_any_app: bool,
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
        // Default to the WireGuard passphrase service for back-compat; callers
        // that custody a different secret (e.g. the trust signing-key
        // passphrase) pass their own service explicitly.
        let service = match keychain_service {
            Some(value) => normalize_macos_keychain_service(value)?,
            None => MACOS_PASSPHRASE_KEYCHAIN_SERVICE.to_owned(),
        };
        let passphrase = read_passphrase_file_explicit(passphrase_path)?;
        // `allow_any_app` forces the allow-any-application (`-A`) ACL, required
        // only when a *different* binary reads the secret back: the trust
        // signing-key passphrase is stored by rustynetd but read by `rustynet
        // ops refresh-signed-trust`. Otherwise (the default, e.g. the WireGuard
        // key passphrase) the secret is both stored and read by rustynetd, so we
        // use the owned-identity System-keychain path (`SecItemAdd`), which binds
        // read access to rustynetd's own code-signing identity. That is strictly
        // tighter than `-A` and — unlike `-A` — is actually readable by the
        // launchd daemon across the login-session boundary on macOS 26 (the `-A`
        // CLI path stores an item the daemon cannot read; see the rustynet-crypto
        // rationale on `store_macos_generic_password_system_keychain_owned`).
        if allow_any_app {
            rustynet_crypto::store_macos_generic_password_allow_any_app(
                service.as_str(),
                account.as_str(),
                passphrase.as_bytes(),
            )
        } else {
            store_macos_generic_password_system_keychain_owned(
                service.as_str(),
                account.as_str(),
                passphrase.as_bytes(),
            )
        }
        .map_err(|err| format!("store macOS keychain passphrase failed: {err}"))?;
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = allow_any_app;
        if keychain_account.is_some() || keychain_service.is_some() {
            return Err(
                "Windows passphrase secure-store provisioning does not accept --keychain-account or --keychain-service"
                    .to_string(),
            );
        }
        let passphrase = read_passphrase_file_explicit(passphrase_path)?;
        store_windows_dpapi_passphrase_blob(passphrase_path, passphrase.as_bytes())
    }
    #[cfg(not(target_os = "macos"))]
    #[cfg(not(windows))]
    {
        let _ = (
            passphrase_path,
            keychain_account,
            keychain_service,
            allow_any_app,
        );
        Err("passphrase secure-store provisioning is only supported on macOS".to_string())
    }
}

#[cfg(not(windows))]
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
        return Err("passphrase exceeds maximum allowed size".to_owned());
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
        return Err("passphrase must be at least 16 characters".to_owned());
    }
    let value = Zeroizing::new(trimmed.to_owned());
    raw.zeroize();
    Ok(value)
}

#[cfg(windows)]
fn read_windows_runtime_passphrase_source(path: &Path) -> Result<Zeroizing<String>, String> {
    validate_windows_secret_blob_path(path, "passphrase file")?;
    validate_secret_file_security(path, "passphrase file", false)?;
    // Use local-secret ACL here: the blob may be created by an SSH bootstrap session
    // (admin user, not SYSTEM), so the file owner is the SSH user's SID rather than
    // BA/SY. Security is provided by DPAPI LocalMachine encryption + NTFS DACL
    // (SY/BA/service only); file-owner identity is not a meaningful invariant.
    validate_windows_local_secret_acl(path, "passphrase file")?;
    let raw = fs::read(path).map_err(|err| format!("read passphrase file failed: {err}"))?;
    decode_windows_dpapi_passphrase_blob(raw, "passphrase file")
}

#[cfg(windows)]
fn read_windows_explicit_passphrase_source(path: &Path) -> Result<Zeroizing<String>, String> {
    validate_windows_local_secret_input_path(path, "passphrase file")?;
    validate_secret_file_security(path, "passphrase file", false)?;
    let raw = fs::read(path).map_err(|err| format!("read passphrase file failed: {err}"))?;
    if looks_like_windows_dpapi_passphrase_blob(raw.as_slice()) {
        decode_windows_dpapi_passphrase_blob(raw, "passphrase file")
    } else {
        parse_passphrase_bytes(raw, "passphrase file")
    }
}

#[cfg(windows)]
fn store_windows_dpapi_passphrase_blob(path: &Path, plaintext: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;

    validate_windows_secret_blob_path(path, "passphrase file")?;
    let parent = path.parent().ok_or_else(|| {
        format!(
            "passphrase file path must include a parent directory: {}",
            path.display()
        )
    })?;
    validate_windows_runtime_file_path(parent, "passphrase file parent directory")?;
    validate_windows_runtime_acl(parent, "passphrase file parent directory")?;
    if path.exists() {
        validate_secret_file_security(path, "passphrase file", false)?;
    }

    let mut protected = dpapi_protect(
        plaintext,
        // LocalMachine scope allows the service account (NT SERVICE\RustyNet) to
        // decrypt a passphrase blob provisioned by the Administrator bootstrap
        // session via SSH. NTFS ACLs on C:\ProgramData\RustyNet\secrets\ restrict
        // which local identities can read the file at all; DPAPI provides an
        // additional layer that ties the blob to this machine.
        WindowsDpapiScope::LocalMachine,
        WINDOWS_DPAPI_PASSPHRASE_DESCRIPTION,
    )
    .map_err(|err| format!("protect Windows DPAPI passphrase blob failed: {err}"))?;
    let mut blob = encode_windows_dpapi_passphrase_blob(protected.as_slice())?;
    protected.zeroize();

    let candidate = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("passphrase"),
        std::process::id()
    ));
    if candidate.exists() {
        remove_file_if_present(candidate.as_path())?;
    }

    let write_result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(candidate.as_path())
            .map_err(|err| {
                format!(
                    "create Windows DPAPI passphrase blob failed ({}): {err}",
                    candidate.display()
                )
            })?;
        file.write_all(blob.as_slice()).map_err(|err| {
            format!(
                "write Windows DPAPI passphrase blob failed ({}): {err}",
                candidate.display()
            )
        })?;
        file.flush().map_err(|err| {
            format!(
                "flush Windows DPAPI passphrase blob failed ({}): {err}",
                candidate.display()
            )
        })?;
        if path.exists() {
            remove_file_if_present(path)?;
        }
        fs::rename(candidate.as_path(), path).map_err(|err| {
            format!(
                "persist Windows DPAPI passphrase blob failed ({} -> {}): {err}",
                candidate.display(),
                path.display()
            )
        })?;
        validate_secret_file_security(path, "passphrase file", false)?;
        // Use local-secret ACL (not runtime ACL) for the post-write check: the blob
        // may be created during SSH bootstrap where the creating process runs under
        // the admin user's SSH token (not SYSTEM), so the file owner is the SSH user
        // rather than BA/SY. DPAPI LocalMachine encryption + NTFS DACL are the
        // enforced security guarantees; owner identity is checked at startup
        // by validate_windows_runtime_startup_acls on the containing directories.
        validate_windows_local_secret_acl(path, "passphrase file")
    })();
    if write_result.is_err() {
        let _ = remove_file_if_present(candidate.as_path());
    }
    blob.zeroize();
    write_result
}

#[cfg(windows)]
fn encode_windows_dpapi_passphrase_blob(protected: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let blob_len = u32::try_from(protected.len())
        .map_err(|_| "Windows DPAPI passphrase blob exceeds u32".to_string())?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        WINDOWS_DPAPI_PASSPHRASE_BLOB_MAGIC.len() + 1 + 1 + 4 + protected.len(),
    ));
    encoded.extend_from_slice(WINDOWS_DPAPI_PASSPHRASE_BLOB_MAGIC);
    encoded.push(WINDOWS_DPAPI_PASSPHRASE_BLOB_VERSION);
    encoded.push(0);
    encoded.extend_from_slice(&blob_len.to_be_bytes());
    encoded.extend_from_slice(protected);
    Ok(encoded)
}

#[cfg(windows)]
fn decode_windows_dpapi_passphrase_blob(
    mut blob: Vec<u8>,
    source_label: &str,
) -> Result<Zeroizing<String>, String> {
    if !looks_like_windows_dpapi_passphrase_blob(blob.as_slice()) {
        blob.zeroize();
        return Err(format!(
            "{source_label} is not a reviewed Windows DPAPI passphrase blob",
        ));
    }
    let version = blob[WINDOWS_DPAPI_PASSPHRASE_BLOB_MAGIC.len()];
    if version != WINDOWS_DPAPI_PASSPHRASE_BLOB_VERSION {
        blob.zeroize();
        return Err(format!(
            "{source_label} uses unsupported Windows DPAPI blob version {version}",
        ));
    }
    let length_offset = WINDOWS_DPAPI_PASSPHRASE_BLOB_MAGIC.len() + 2;
    let protected_len = u32::from_be_bytes([
        blob[length_offset],
        blob[length_offset + 1],
        blob[length_offset + 2],
        blob[length_offset + 3],
    ]) as usize;
    let data_offset = length_offset + 4;
    let actual_len = match blob.len().checked_sub(data_offset) {
        Some(value) => value,
        None => {
            blob.zeroize();
            return Err(format!("truncated {source_label} Windows DPAPI blob"));
        }
    };
    if actual_len != protected_len {
        blob.zeroize();
        return Err(format!(
            "{source_label} Windows DPAPI blob length mismatch (declared {protected_len}, actual {})",
            actual_len
        ));
    }
    let mut protected = Zeroizing::new(blob.split_off(data_offset));
    blob.zeroize();
    let mut plaintext = dpapi_unprotect(protected.as_slice())
        .map_err(|err| format!("unprotect Windows DPAPI passphrase blob failed: {err}"))?;
    let result = parse_passphrase_bytes(std::mem::take(&mut plaintext), source_label);
    plaintext.zeroize();
    result
}

#[cfg(windows)]
fn looks_like_windows_dpapi_passphrase_blob(blob: &[u8]) -> bool {
    let header_len = WINDOWS_DPAPI_PASSPHRASE_BLOB_MAGIC.len() + 1 + 1 + 4;
    blob.len() >= header_len && blob.starts_with(WINDOWS_DPAPI_PASSPHRASE_BLOB_MAGIC)
}

#[cfg(windows)]
fn verify_dpapi_startup_self_test() -> Result<(), String> {
    WINDOWS_DPAPI_STARTUP_SELF_TEST
        .get_or_init(run_dpapi_startup_self_test)
        .clone()
}

#[cfg(windows)]
fn run_dpapi_startup_self_test() -> Result<(), String> {
    let mut protected = dpapi_protect(
        WINDOWS_DPAPI_STARTUP_SELF_TEST_PLAINTEXT,
        WindowsDpapiScope::LocalMachine,
        "RustyNet DPAPI startup self-test",
    )
    .map_err(|err| format!("DPAPI startup self-test protect failed: {err}"))?;
    // Keep the decrypted self-test copy in a Zeroizing buffer so even the
    // non-secret probe bytes follow the same cleanup discipline as secret
    // material. Fail closed on any DPAPI error or mismatch.
    let roundtrip = match dpapi_unprotect(protected.as_slice()) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(err) => {
            protected.zeroize();
            return Err(format!("DPAPI startup self-test unprotect failed: {err}"));
        }
    };
    protected.zeroize();
    if roundtrip.as_slice() != WINDOWS_DPAPI_STARTUP_SELF_TEST_PLAINTEXT {
        return Err(
            "DPAPI startup self-test: round-trip bytes do not match original - fail closed"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_dpapi_startup_self_test() -> Result<(), String> {
    Ok(())
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
fn normalize_macos_keychain_service(raw: &str) -> Result<String, String> {
    let service = raw.trim();
    if service.is_empty() {
        return Err("macOS keychain service must not be empty".to_owned());
    }
    if service != raw {
        return Err(
            "macOS keychain service must not contain leading or trailing whitespace".to_owned(),
        );
    }
    if service.len() > 128 {
        return Err("macOS keychain service exceeds max length (128)".to_owned());
    }
    if !service
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err(
            "macOS keychain service contains invalid characters; allowed: [A-Za-z0-9._:-]"
                .to_owned(),
        );
    }
    Ok(service.to_owned())
}

#[cfg(target_os = "macos")]
fn normalize_macos_keychain_account(raw: &str) -> Result<String, String> {
    let account = raw.trim();
    if account.is_empty() {
        return Err(format!(
            "{PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} must not be empty",
        ));
    }
    if account != raw {
        return Err(format!(
            "{PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} must not contain leading or trailing whitespace",
        ));
    }
    if account.len() > 128 {
        return Err(format!(
            "{PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} exceeds max length (128)",
        ));
    }
    if !account
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
    {
        return Err(format!(
            "{PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} contains invalid characters; allowed: [A-Za-z0-9._:-]",
        ));
    }
    Ok(account.to_owned())
}

pub fn decrypt_private_key(
    encrypted_key_path: &Path,
    passphrase_path: &Path,
) -> Result<Vec<u8>, String> {
    let passphrase = read_passphrase_file(passphrase_path)?;
    // Fail closed on Windows if process startup cannot prove LocalMachine DPAPI
    // protect/unprotect works. The check is cached so repeated key loads do not
    // repeatedly round-trip live passphrase bytes.
    verify_dpapi_startup_self_test()?;
    let manager = key_custody_manager(encrypted_key_path, passphrase)?;
    let key_id = key_custody_key_id(encrypted_key_path);
    let mut key = manager
        .load_private_key(&key_id)
        .map_err(|err| format!("decrypt encrypted key failed: {err}"))?;
    if key.is_empty() {
        return Err("decrypted key is empty".to_owned());
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
        .ok_or_else(|| "encrypted key path must include parent directory".to_owned())?;
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
        .ok_or_else(|| "encrypted key path must include parent directory".to_owned())?;
    let manager = KeyCustodyManager::new_zeroizing(
        PlatformOsSecureStore,
        parent.to_path_buf(),
        passphrase,
        KeyCustodyPermissionPolicy::default(),
    );
    #[cfg(target_os = "macos")]
    let manager = manager.with_fallback_policy(OsStoreFallbackPolicy::RequireOsSecureStore);
    #[cfg(target_os = "windows")]
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
        // When the credential source is a systemd-loaded credential
        // (allow_root_owner=true), also validate the parent directory.
        // systemd mounts /run/credentials/ as a tmpfs; if the directory
        // is group- or world-accessible, any local process can read the
        // credential file regardless of its own permissions.
        if allow_root_owner && let Some(parent) = path.parent() {
            let parent_meta = fs::symlink_metadata(parent)
                .map_err(|err| format!("inspect {label} parent directory failed: {err}"))?;
            if parent_meta.file_type().is_symlink() {
                return Err(format!("{label} parent directory must not be a symlink"));
            }
            let parent_mode = parent_meta.mode() & 0o777;
            if parent_mode & 0o077 != 0 {
                return Err(format!(
                    "{label} parent directory permissions are too broad: \
                     must be owner-only (0o700), found {parent_mode:03o}",
                ));
            }
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
        #[cfg(windows)]
        {
            validate_windows_local_secret_input_path(path, label)?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|err| format!("{label} metadata read failed: {err}"))?;
            if metadata.file_type().is_symlink() {
                return Err(format!("{label} must not be a symlink"));
            }
            if !metadata.file_type().is_file() {
                return Err(format!("{label} must be a regular file"));
            }
            validate_windows_local_secret_acl(path, label)?;
            fs::File::open(path)
                .map_err(|err| format!("{label} is not readable by the current identity: {err}"))?;
            return Ok(());
        }

        #[cfg(not(windows))]
        {
            let metadata =
                fs::metadata(path).map_err(|err| format!("{label} metadata read failed: {err}"))?;
            if !metadata.is_file() {
                return Err(format!("{label} must be a regular file"));
            }
        }
    }
    Ok(())
}

fn resolve_passphrase_source(configured_path: &Path) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        validate_windows_secret_blob_path(configured_path, "passphrase file")?;
        if configured_path.exists() {
            return Ok(configured_path.to_path_buf());
        }
        return Err(format!(
            "Windows passphrase source must be a reviewed DPAPI blob at {}",
            configured_path.display()
        ));
    }
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

        Err(format!(
            "passphrase credential source is not configured; set {PASSPHRASE_CREDENTIAL_PATH_ENV} or {SYSTEMD_CREDENTIALS_DIRECTORY_ENV}",
        ))
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
        return Err("private key must not be empty".to_owned());
    }
    write_atomic(path, private_key, 0o600)
}

pub fn write_public_key(path: &Path, public_key: &str) -> Result<(), String> {
    if public_key.trim().is_empty() {
        return Err("public key must not be empty".to_owned());
    }
    let value = format!("{}\n", public_key.trim());
    // 0o640 (owner rw, group r, no world): the reviewed key-custody posture for
    // the WireGuard public key (linux_key_custody expects 0o640). World-read is
    // unnecessary even for a public key and is flagged as drift.
    write_atomic(path, value.as_bytes(), 0o640)
}

/// Self-heal an existing WireGuard public-key file to the reviewed `0o640`
/// custody posture (owner rw, group r, no world).
///
/// Older builds wrote the public key world-readable (`0o644`). On rebuild the
/// keypair is preserved rather than regenerated (see
/// [`initialize_encrypted_key_material`], which refuses to overwrite existing
/// key material), so a stale loose mode persists indefinitely and trips the
/// Linux key-custody validator. New writes already use `0o640`; this repairs
/// pre-existing files at daemon startup. No-op when the file is absent or
/// already `0o640`; refuses to follow a symlink. World-read is unnecessary even
/// for a public key, so removing it is always the secure default.
#[cfg(unix)]
pub fn tighten_public_key_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect public key {} failed: {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "public key {} must not be a symlink",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "public key {} must be a regular file",
            path.display()
        ));
    }
    if metadata.permissions().mode() & 0o777 == 0o640 {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o640)).map_err(|err| {
        format!(
            "tighten public key {} to 0o640 failed: {err}",
            path.display()
        )
    })
}

/// Windows lacks Unix file modes; the custody posture is enforced via ACLs
/// elsewhere, so this is a no-op on non-Unix targets.
#[cfg(not(unix))]
pub fn tighten_public_key_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
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
        return Err("wg genkey produced empty key".to_owned());
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
        "ip link set down failed for {interface_name}: {status}"
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
            "key material already exists; use --force to overwrite existing files".to_owned(),
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
                .to_owned(),
        );
    }

    let mut private_key = fs::read(existing_private_key_path).map_err(|err| {
        format!(
            "read existing private key {} failed: {err}",
            existing_private_key_path.display()
        )
    })?;
    if private_key.is_empty() {
        return Err("existing private key is empty".to_owned());
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
    options.mode(mode);
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
    // Directory fsync is a no-op on Windows: FlushFileBuffers on a directory
    // handle requires special access that read-open does not provide.
    #[cfg(unix)]
    {
        let parent_dir = fs::File::open(parent)
            .map_err(|err| format!("open parent directory {} failed: {err}", parent.display()))?;
        parent_dir
            .sync_all()
            .map_err(|err| format!("sync parent directory {} failed: {err}", parent.display()))?
    };
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
        return Err("interface name must not be empty".to_owned());
    }
    if value.len() > 15 {
        return Err("interface name must be <= 15 characters".to_owned());
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    {
        return Ok(());
    }
    Err("interface name contains invalid characters".to_owned())
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
            .ok_or_else(|| "wg pubkey stdin unavailable".to_owned())?;
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
        .to_owned();
    if public_key.is_empty() {
        return Err("wg pubkey produced empty key".to_owned());
    }
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "macos"))]
    use super::DEFAULT_PASSPHRASE_CREDENTIAL_NAME;
    #[cfg(target_os = "macos")]
    use super::{MACOS_PASSPHRASE_KEYCHAIN_SERVICE, normalize_macos_keychain_account};
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

    /// Verification for the public-key custody self-heal: a stale world-readable
    /// (`0o644`) `wireguard.pub` is tightened to the reviewed `0o640` posture,
    /// the operation is idempotent on an already-`0o640` file and a no-op when
    /// absent, and a symlinked path is refused (never chmod through a symlink).
    #[test]
    #[cfg(unix)]
    fn tighten_public_key_permissions_self_heals_world_readable_pub() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_test_dir("rn-pubkey-perms");
        let pub_path = dir.join("wireguard.pub");

        // Absent file is a no-op (not an error).
        super::tighten_public_key_permissions(&pub_path)
            .expect("absent public key should be a no-op");

        // The stale legacy world-readable mode is tightened to 0o640.
        std::fs::write(&pub_path, b"deadbeef\n").expect("write pub");
        std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))
            .expect("set 0o644");
        super::tighten_public_key_permissions(&pub_path).expect("tighten should succeed");
        let mode = std::fs::metadata(&pub_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "world-readable pub must be tightened to 0o640");

        // Idempotent on an already-0o640 file.
        super::tighten_public_key_permissions(&pub_path).expect("idempotent tighten");
        let mode = std::fs::metadata(&pub_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640);

        // A symlinked path must be refused.
        let link_path = dir.join("wireguard.pub.link");
        std::os::unix::fs::symlink(&pub_path, &link_path).expect("symlink");
        assert!(
            super::tighten_public_key_permissions(&link_path).is_err(),
            "symlinked public key path must be refused"
        );

        let _ = remove_file_if_present(&pub_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pin the macOS passphrase custody routing: the cross-binary case
    /// (`allow_any_app == true`, e.g. the trust signing passphrase read by the
    /// `rustynet` CLI) uses the `-A` allow-any-app path, while the same-binary
    /// case (`allow_any_app == false`, e.g. the WireGuard passphrase stored and
    /// read by rustynetd) uses the owned-identity `SecItemAdd` path — NOT the
    /// legacy default-keychain `store_macos_generic_password`, whose `-A` CLI
    /// fallback produces an item the launchd daemon cannot read cross-session on
    /// macOS 26. A regression here re-opens the daemon crash-loop.
    #[cfg(target_os = "macos")]
    #[test]
    fn store_passphrase_routes_owned_identity_for_same_binary_custody() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body = std::fs::read_to_string(crate_root.join("src/key_material.rs"))
            .expect("key_material source readable");
        let start = body
            .find("pub fn store_passphrase_in_os_secure_store(")
            .expect("store_passphrase_in_os_secure_store must remain present");
        let rel_end = body[start..]
            .find("\n}\n")
            .expect("store_passphrase_in_os_secure_store must have a closing brace");
        let window = &body[start..start + rel_end + 3];
        assert!(
            window.contains("store_macos_generic_password_allow_any_app("),
            "cross-binary custody must keep the -A allow-any-app path"
        );
        assert!(
            window.contains("store_macos_generic_password_system_keychain_owned("),
            "same-binary custody (WG passphrase) must use the owned-identity SecItemAdd path"
        );
        assert!(
            !window.contains("store_macos_generic_password(service.as_str()"),
            "WG passphrase must NOT route through the legacy default-keychain store \
             (its -A CLI fallback is unreadable by the launchd daemon on macOS 26)"
        );
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
    #[cfg(target_os = "macos")]
    fn macos_keychain_service_matches_reviewed_launchd_contract() {
        assert_eq!(
            MACOS_PASSPHRASE_KEYCHAIN_SERVICE,
            "net.rustynet.wg-key-passphrase"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_keychain_account_accepts_bootstrap_node_id_shape() {
        let account = normalize_macos_keychain_account("wg-passphrase-node:exit_1.alpha")
            .expect("bootstrap account shape should be accepted");
        assert_eq!(account, "wg-passphrase-node:exit_1.alpha");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_keychain_account_rejects_shell_and_plist_metacharacters() {
        for raw in [
            "",
            " wg-passphrase-node ",
            "wg passphrase",
            "wg/passphrase",
            "wg<script>",
            "wg&passphrase",
            "wg\"passphrase",
            "wg\npassphrase",
        ] {
            assert!(
                normalize_macos_keychain_account(raw).is_err(),
                "unsafe account must reject: {raw:?}"
            );
        }
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
    fn remove_file_if_present_rejects_directory() {
        let test_dir = unique_test_dir("rustynet-remove-dir-reject");
        let err = remove_file_if_present(&test_dir)
            .expect_err("secure remove must reject directory inputs");
        assert!(err.contains("regular file"));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[cfg(unix)]
    #[test]
    fn remove_file_if_present_removes_symlink_without_following_target() {
        let test_dir = unique_test_dir("rustynet-remove-symlink");
        let target = test_dir.join("target.key");
        let link = test_dir.join("target.link");
        std::fs::write(&target, b"wireguard-private-key").expect("target file should be writable");
        std::os::unix::fs::symlink(&target, &link).expect("symlink should be writable");

        remove_file_if_present(&link).expect("symlink remove should succeed");
        assert!(!link.exists(), "symlink path should be removed");
        assert!(target.exists(), "symlink target must remain untouched");

        let _ = std::fs::remove_dir_all(test_dir);
    }

    // W2.4-followup: DPAPI startup self-test unit coverage.
    //
    // On non-Windows: the function is a no-op and must return Ok,
    // confirming the cfg gate keeps DPAPI logic off non-Windows production paths.
    // On Windows: the real DPAPI is used once per process and must succeed.

    #[test]
    fn dpapi_startup_self_test_returns_ok() {
        // Positive test: startup self-test must succeed.
        // On non-Windows this exercises the no-op path; on Windows it uses real DPAPI.
        let result = super::verify_dpapi_startup_self_test();
        assert!(
            result.is_ok(),
            "DPAPI startup self-test should succeed: {result:?}"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn dpapi_startup_self_test_noop_on_non_windows_never_errors() {
        // On non-Windows the function must be a no-op, confirming
        // it does not call into the Windows DPAPI stubs (which always return Err).
        for _ in 0..3 {
            let result = super::verify_dpapi_startup_self_test();
            assert!(
                result.is_ok(),
                "non-Windows no-op must not return Err: {result:?}",
            );
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn dpapi_protect_stub_returns_err_on_non_windows() {
        // Verify the non-Windows stub always returns Err so the cfg(windows) branch
        // cannot silently appear on non-Windows builds and mask a missing guard.
        use rustynet_windows_native::{WindowsDpapiScope, dpapi_protect};
        let result = dpapi_protect(
            b"test-value",
            WindowsDpapiScope::LocalMachine,
            "test-description",
        );
        assert!(
            result.is_err(),
            "dpapi_protect must return Err on non-Windows; got Ok"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("Windows"),
            "error message should mention Windows: {err_msg}"
        );
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

    // -----------------------------------------------------------------
    // Windows DPAPI key custody — fail-closed regression tests.
    //
    // These tests pin the documented contract for the Windows DPAPI
    // passphrase paths.  Mirrors the Windows assert_killswitch defense-
    // in-depth audit: every security-sensitive path must either query
    // live OS state OR fail closed; no in-process flag may stand in
    // for OS verification.  On non-Windows hosts the cfg-gated
    // production paths are no-ops and we exercise the cross-platform
    // pieces (passphrase parser, DPAPI stub contract, blob magic).
    // -----------------------------------------------------------------

    #[test]
    fn parse_passphrase_bytes_rejects_short_passphrase_fails_closed() {
        // Pins the minimum-length contract: a passphrase below 16 chars
        // must be rejected so callers cannot pass a trivially-guessable
        // string into key encryption.
        let raw = b"too-short".to_vec();
        let err = super::parse_passphrase_bytes(raw, "passphrase file")
            .expect_err("short passphrase must be rejected");
        assert!(err.contains("at least 16 characters"), "unexpected: {err}");
    }

    #[test]
    fn parse_passphrase_bytes_rejects_oversize_input_fails_closed() {
        // Pins the upper-bound: oversized input must be rejected so a
        // hostile passphrase file cannot exhaust memory or smuggle
        // structured data through the passphrase channel.
        let raw = vec![b'A'; super::MAX_PASSPHRASE_BYTES + 1];
        let err = super::parse_passphrase_bytes(raw, "passphrase file")
            .expect_err("oversize passphrase must be rejected");
        assert!(err.contains("maximum allowed size"), "unexpected: {err}");
    }

    #[test]
    fn parse_passphrase_bytes_rejects_non_utf8_fails_closed() {
        // Pins the encoding contract: invalid utf-8 must fail closed,
        // not silently lossy-decode (which could let an attacker forge
        // the trimmed passphrase via mojibake collisions).
        let raw = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8];
        let err = super::parse_passphrase_bytes(raw, "passphrase file")
            .expect_err("non-utf8 passphrase must be rejected");
        assert!(err.contains("non-utf8 bytes"), "unexpected: {err}");
    }

    #[test]
    fn parse_passphrase_bytes_accepts_minimum_length_passphrase() {
        // Positive control: exactly 16 characters must succeed so the
        // boundary on the rejection test is not off-by-one.  Trims
        // surrounding whitespace before the length check.
        let raw = b"  sixteen-charsXYZ  ".to_vec();
        let value = super::parse_passphrase_bytes(raw, "passphrase file")
            .expect("16-char trimmed passphrase must be accepted");
        assert_eq!(value.as_str(), "sixteen-charsXYZ");
        assert_eq!(value.len(), 16);
    }

    #[cfg(windows)]
    #[test]
    fn looks_like_windows_dpapi_passphrase_blob_rejects_short_or_wrong_magic() {
        // Pins the magic-byte gate: explicit-passphrase reads only
        // attempt DPAPI unprotect when the input starts with the
        // reviewed magic.  Without this gate, an attacker who places a
        // plaintext passphrase at the runtime DPAPI path could make the
        // daemon read it as a passphrase, bypassing the encrypted-at-
        // rest contract.  This test pins the gate so a regression
        // (e.g. checking only a prefix or returning true on empty
        // input) cannot silently weaken the contract.
        assert!(!super::looks_like_windows_dpapi_passphrase_blob(b""));
        assert!(!super::looks_like_windows_dpapi_passphrase_blob(
            b"plaintext-passphrase-not-a-blob"
        ));
        assert!(!super::looks_like_windows_dpapi_passphrase_blob(b"RNYDPAP"));
        // header_len = 8 (magic) + 1 (version) + 1 (reserved) + 4 (length) = 14
        let too_short = b"RNYDPAPI\x01\x00\x00\x00\x00";
        assert_eq!(too_short.len(), 13);
        assert!(!super::looks_like_windows_dpapi_passphrase_blob(too_short));
        let well_formed_header = b"RNYDPAPI\x01\x00\x00\x00\x00\x00\xff";
        assert_eq!(well_formed_header.len(), 15);
        assert!(super::looks_like_windows_dpapi_passphrase_blob(
            well_formed_header
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn looks_like_windows_dpapi_blob_module_only_compiled_on_windows() {
        // Sentinel test: pin that the magic-gate function is cfg-gated
        // to Windows only.  If a refactor accidentally compiles the
        // function on non-Windows hosts (e.g. by removing the cfg),
        // this test will fail to compile because there will be no
        // collision with the always-Err DPAPI stubs to keep the
        // contract honest.  Today on non-Windows the cfg(windows)
        // function does not exist; this assertion is a marker for
        // grep/code-review.
        let dpapi_protect_is_stub = !cfg!(windows);
        assert!(
            dpapi_protect_is_stub,
            "non-Windows builds must use the always-Err DPAPI stub so the\
             cfg(windows) blob magic + DPAPI paths cannot be reached"
        );
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_startup_self_test_uses_once_lock() {
        // Pins the E.4 contract: key decrypts call the startup verifier, but
        // the actual DPAPI protect/unprotect self-test runs once per process.
        super::verify_dpapi_startup_self_test().expect("DPAPI must round-trip on a Windows host");
        assert!(
            super::WINDOWS_DPAPI_STARTUP_SELF_TEST.get().is_some(),
            "startup self-test result must be cached"
        );
        super::verify_dpapi_startup_self_test()
            .expect("cached DPAPI startup self-test must remain usable");
    }
}
