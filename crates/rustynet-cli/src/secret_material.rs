//! Shared encrypted-secret-material loading + nonce/time helpers.
//!
//! These helpers were historically private items of `main.rs`. They moved
//! into this module (verbatim — RNQ-17 is a structure-only change) because
//! `ops_e2e.rs` calls them and, under the `vm-lab` feature, the crate
//! LIBRARY also compiles `ops_e2e` (the lab orchestrator tree needs it), so
//! the definitions must live in a module both crate roots can declare.
//!
//! Security posture is unchanged: fail-closed validation of file type,
//! permissions, and ownership before any decrypt; decrypted material is
//! returned wrapped in [`Zeroizing`] where the call shape allows it; no
//! secret bytes are ever logged.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::unistd::Uid;
use rustynet_crypto::{KeyCustodyPermissionPolicy, read_encrypted_key_file};
use rustynetd::key_material::read_passphrase_file_explicit;
use zeroize::Zeroizing;

pub(crate) fn encrypted_secret_permission_policy(path: &Path) -> KeyCustodyPermissionPolicy {
    let mut policy = KeyCustodyPermissionPolicy::default();
    if matches!(
        path.parent(),
        Some(parent)
            if parent == Path::new("/etc/rustynet")
                || parent == Path::new("/usr/local/etc/rustynet")
    ) {
        // Encrypted signing artifacts coexist with daemon-readable verifier
        // material under the config root (/etc/rustynet on Linux,
        // /usr/local/etc/rustynet on macOS), which is 0750 root:rustynetd.
        policy.required_directory_mode = 0o750;
    }
    policy
}

pub(crate) fn validate_encrypted_secret_file_security(
    path: &Path,
    label: &str,
) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|err| format!("inspect {label} failed: {err}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} path must not be a symlink"));
    }
    if !metadata.file_type().is_file() {
        return Err(format!("{label} path must reference a regular file"));
    }

    let mode = metadata.mode() & 0o777;
    if (mode & 0o077) != 0 {
        return Err(format!(
            "{label} file permissions must be owner-only (0600); found {mode:03o}",
        ));
    }

    let expected_uid = Uid::effective().as_raw();
    let owner_uid = metadata.uid();
    if owner_uid != expected_uid {
        return Err(format!(
            "{label} file owner mismatch: expected uid {expected_uid}, found {owner_uid}"
        ));
    }
    Ok(())
}

pub(crate) fn load_encrypted_secret_material(
    path: &Path,
    passphrase_path: &Path,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if !passphrase_path.is_absolute() {
        return Err(format!(
            "{label} passphrase file path must be absolute: {}",
            passphrase_path.display()
        ));
    }
    validate_encrypted_secret_file_security(path, label)?;
    let passphrase = read_passphrase_file_explicit(passphrase_path).map_err(|err| {
        format!(
            "{label} passphrase source invalid ({}): {err}",
            passphrase_path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent: {}", path.display()))?;
    let permission_policy = encrypted_secret_permission_policy(path);
    let secret = read_encrypted_key_file(parent, path, passphrase.as_str(), permission_policy)
        .map_err(|err| format!("decrypt {label} failed ({}): {err}", path.display()))?;
    Ok(Zeroizing::new(secret))
}

pub(crate) fn load_assignment_signing_secret(
    path: &Path,
    passphrase_path: &Path,
) -> Result<Vec<u8>, String> {
    let secret =
        load_encrypted_secret_material(path, passphrase_path, "assignment signing secret")?;
    if secret.len() < 32 {
        return Err("assignment signing secret must be at least 32 bytes".to_owned());
    }
    Ok(secret.to_vec())
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn generate_assignment_nonce() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    (nanos & u128::from(u64::MAX)) as u64
}
