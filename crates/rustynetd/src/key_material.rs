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
    KeyCustodyBackend, KeyCustodyManager, KeyCustodyPermissionPolicy, PlatformOsSecureStore,
    write_encrypted_key_file,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const PASSPHRASE_CREDENTIAL_PATH_ENV: &str = "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH";
const SYSTEMD_CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";
const DEFAULT_PASSPHRASE_CREDENTIAL_NAME: &str = "wg_key_passphrase";
const MAX_PASSPHRASE_BYTES: usize = 4096;

pub fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let source_path = resolve_passphrase_source(path);
    let allow_root_owner = is_systemd_credential_path(&source_path);
    validate_secret_file_security(&source_path, "passphrase file", allow_root_owner)?;

    let mut raw =
        fs::read(&source_path).map_err(|err| format!("read passphrase file failed: {err}"))?;
    if raw.len() > MAX_PASSPHRASE_BYTES {
        raw.zeroize();
        return Err("passphrase exceeds maximum allowed size".to_string());
    }
    let decoded = match std::str::from_utf8(&raw) {
        Ok(value) => value,
        Err(_) => {
            raw.zeroize();
            return Err("passphrase file contains non-utf8 bytes".to_string());
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
    let passphrase = read_passphrase_file(passphrase_path)?;
    let manager = key_custody_manager(encrypted_key_path, passphrase.clone())?;
    let key_id = key_custody_key_id(encrypted_key_path);
    let backend = manager
        .store_private_key(&key_id, private_key)
        .map_err(|err| format!("encrypt key failed: {err}"))?;
    if backend == KeyCustodyBackend::OsSecureStore {
        let parent = encrypted_key_path
            .parent()
            .ok_or_else(|| "encrypted key path must include parent directory".to_string())?;
        write_encrypted_key_file(
            parent,
            encrypted_key_path,
            private_key,
            &passphrase,
            KeyCustodyPermissionPolicy::default(),
        )
        .map_err(|err| format!("encrypt key backup failed: {err}"))?;
    }
    Ok(())
}

fn key_custody_manager(
    encrypted_key_path: &Path,
    passphrase: Zeroizing<String>,
) -> Result<KeyCustodyManager<PlatformOsSecureStore>, String> {
    let parent = encrypted_key_path
        .parent()
        .ok_or_else(|| "encrypted key path must include parent directory".to_string())?;
    Ok(KeyCustodyManager::new_zeroizing(
        PlatformOsSecureStore,
        parent.to_path_buf(),
        passphrase,
        KeyCustodyPermissionPolicy::default(),
    ))
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
                "{label} permissions are too broad: expected {expected}, found {:03o}",
                mode,
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

fn resolve_passphrase_source(configured_path: &Path) -> PathBuf {
    let explicit = std::env::var(PASSPHRASE_CREDENTIAL_PATH_ENV).ok();
    let directory = std::env::var(SYSTEMD_CREDENTIALS_DIRECTORY_ENV).ok();
    resolve_passphrase_source_from_env(configured_path, explicit.as_deref(), directory.as_deref())
}

fn resolve_passphrase_source_from_env(
    configured_path: &Path,
    explicit_credential_path: Option<&str>,
    credentials_directory: Option<&str>,
) -> PathBuf {
    if let Some(explicit) = explicit_credential_path {
        let explicit_path = PathBuf::from(explicit);
        if explicit_path.exists() {
            return explicit_path;
        }
    }

    if let Some(directory) = credentials_directory {
        let candidate = Path::new(directory).join(DEFAULT_PASSPHRASE_CREDENTIAL_NAME);
        if candidate.exists() {
            return candidate;
        }
    }

    configured_path.to_path_buf()
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
    let private = Command::new("wg")
        .arg("genkey")
        .output()
        .map_err(|err| format!("wg genkey spawn failed: {err}"))?;
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
    let status = Command::new("wg")
        .arg("set")
        .arg(interface_name)
        .arg("private-key")
        .arg(runtime_key_path)
        .status()
        .map_err(|err| format!("wg set private-key spawn failed: {err}"))?;
    if status.success() {
        return Ok(());
    }
    Err(format!(
        "wg set private-key failed for {}: {}",
        interface_name, status
    ))
}

pub fn set_interface_down(interface_name: &str) -> Result<(), String> {
    validate_interface_name(interface_name)?;
    let status = Command::new("ip")
        .arg("link")
        .arg("set")
        .arg("down")
        .arg("dev")
        .arg(interface_name)
        .status()
        .map_err(|err| format!("ip link set down spawn failed: {err}"))?;
    if status.success() {
        return Ok(());
    }
    Err(format!(
        "ip link set down failed for {}: {}",
        interface_name, status
    ))
}

pub fn remove_file_if_present(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    best_effort_scrub_file_contents(path);
    fs::remove_file(path).map_err(|err| format!("remove {} failed: {err}", path.display()))
}

fn best_effort_scrub_file_contents(path: &Path) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };
    if !metadata.is_file() {
        return;
    }
    let mut file = match OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(_) => return,
    };
    let mut remaining = metadata.len();
    if remaining == 0 {
        return;
    }
    let zero_block = [0u8; 8192];
    while remaining > 0 {
        let chunk_len = std::cmp::min(remaining, zero_block.len() as u64) as usize;
        if file.write_all(&zero_block[..chunk_len]).is_err() {
            return;
        }
        remaining -= chunk_len as u64;
    }
    let _ = file.sync_all();
}

pub fn initialize_encrypted_key_material(
    runtime_private_key_path: &Path,
    encrypted_key_path: &Path,
    public_key_path: &Path,
    passphrase_path: &Path,
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
        encrypt_private_key(&private_key, encrypted_key_path, passphrase_path)?;
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
        encrypt_private_key(&private_key, encrypted_key_path, passphrase_path)?;
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

fn derive_public_key_from_private_key(private_key: &[u8]) -> Result<String, String> {
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| format!("wg pubkey spawn failed: {err}"))?;
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
    use super::{
        DEFAULT_PASSPHRASE_CREDENTIAL_NAME, remove_file_if_present,
        resolve_passphrase_source_from_env,
    };

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
        );
        assert_eq!(resolved, explicit);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
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
        );
        assert_eq!(resolved, credential);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn resolve_passphrase_source_falls_back_to_configured_path() {
        let test_dir = unique_test_dir("rustynet-passphrase-source-fallback");
        let configured = test_dir.join("configured.passphrase");
        std::fs::write(&configured, "configured").expect("configured path should be writable");

        let resolved = resolve_passphrase_source_from_env(&configured, None, None);
        assert_eq!(resolved, configured);

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
}
