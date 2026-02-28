#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use rustynet_crypto::{
    KeyCustodyPermissionPolicy, read_encrypted_key_file, write_encrypted_key_file,
};

pub fn read_passphrase_file(path: &Path) -> Result<String, String> {
    let raw =
        fs::read_to_string(path).map_err(|err| format!("read passphrase file failed: {err}"))?;
    let value = raw.trim().to_string();
    if value.len() < 16 {
        return Err("passphrase must be at least 16 characters".to_string());
    }
    Ok(value)
}

pub fn decrypt_private_key(
    encrypted_key_path: &Path,
    passphrase_path: &Path,
) -> Result<Vec<u8>, String> {
    let passphrase = read_passphrase_file(passphrase_path)?;
    let parent = encrypted_key_path
        .parent()
        .ok_or_else(|| "encrypted key path must include parent directory".to_string())?;
    let mut key = read_encrypted_key_file(
        parent,
        encrypted_key_path,
        &passphrase,
        KeyCustodyPermissionPolicy::default(),
    )
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
    .map_err(|err| format!("encrypt key failed: {err}"))
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

    let public_key = derive_public_key_from_private_key(&private_key)?;
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
    fs::remove_file(path).map_err(|err| format!("remove {} failed: {err}", path.display()))
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
    encrypt_private_key(&private_key, encrypted_key_path, passphrase_path)?;
    write_runtime_private_key(runtime_private_key_path, &private_key)?;
    write_public_key(public_key_path, &public_key)?;
    private_key.fill(0);
    Ok(public_key)
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

    let public_key = derive_public_key_from_private_key(&private_key)?;
    encrypt_private_key(&private_key, encrypted_key_path, passphrase_path)?;
    write_runtime_private_key(runtime_private_key_path, &private_key)?;
    write_public_key(public_key_path, &public_key)?;
    private_key.fill(0);
    Ok(public_key)
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path {} has no parent", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("create parent directory {} failed: {err}", parent.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("set parent permissions {} failed: {err}", parent.display()))?;
    }

    let temp = temp_path_for(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    let mut file = options
        .open(&temp)
        .map_err(|err| format!("create temp key file {} failed: {err}", temp.display()))?;
    file.write_all(bytes)
        .map_err(|err| format!("write temp key file {} failed: {err}", temp.display()))?;
    file.sync_all()
        .map_err(|err| format!("sync temp key file {} failed: {err}", temp.display()))?;
    fs::rename(&temp, path).map_err(|err| {
        format!(
            "rename temp key file {} to {} failed: {err}",
            temp.display(),
            path.display()
        )
    })?;
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
