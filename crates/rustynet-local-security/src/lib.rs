#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;

fn validate_socket_basics(path: &Path, label: &str) -> Result<fs::Metadata, String> {
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute: {}", path.display()));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_socket() {
        return Err(format!("{label} must be a Unix socket: {}", path.display()));
    }
    Ok(metadata)
}

fn validate_parent_basics(path: &Path, label: &str) -> Result<fs::Metadata, String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "{label} path must include a parent directory: {}",
            path.display()
        )
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(|err| {
        format!(
            "{label} parent directory metadata read failed for {}: {err}",
            parent.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(format!(
            "{label} parent directory must be a non-symlink directory: {}",
            parent.display()
        ));
    }
    Ok(metadata)
}

fn owner_allowed(owner_uid: u32, allowed_owner_uids: &[u32]) -> bool {
    allowed_owner_uids.contains(&owner_uid)
}

pub fn validate_owner_only_socket(
    path: &Path,
    label: &str,
    allowed_socket_owner_uids: &[u32],
    allowed_parent_owner_uids: &[u32],
) -> Result<(), String> {
    let socket = validate_socket_basics(path, label)?;
    let socket_mode = socket.permissions().mode() & 0o777;
    if socket_mode & 0o077 != 0 {
        return Err(format!(
            "{label} permissions too broad ({socket_mode:03o}); expected owner-only socket permissions: {}",
            path.display()
        ));
    }
    let socket_owner = socket.uid();
    if !owner_allowed(socket_owner, allowed_socket_owner_uids) {
        return Err(format!(
            "{label} owner uid mismatch: allowed {:?}, found {} ({})",
            allowed_socket_owner_uids,
            socket_owner,
            path.display()
        ));
    }

    let parent = validate_parent_basics(path, label)?;
    let parent_mode = parent.permissions().mode() & 0o777;
    if parent_mode & 0o022 != 0 {
        return Err(format!(
            "{label} parent directory has insecure permissions: mode {parent_mode:o}"
        ));
    }
    let parent_owner = parent.uid();
    if !owner_allowed(parent_owner, allowed_parent_owner_uids) {
        return Err(format!(
            "{label} parent directory owner uid mismatch: allowed {:?}, found {}",
            allowed_parent_owner_uids, parent_owner
        ));
    }
    Ok(())
}

pub fn validate_root_managed_shared_runtime_socket(
    path: &Path,
    label: &str,
    allowed_socket_owner_uids: &[u32],
    allowed_parent_owner_uids: &[u32],
    expected_gid: u32,
) -> Result<(), String> {
    let socket = validate_socket_basics(path, label)?;
    let socket_mode = socket.permissions().mode() & 0o777;
    if socket_mode & 0o007 != 0 {
        return Err(format!(
            "{label} permissions too broad ({socket_mode:03o}); world access is forbidden: {}",
            path.display()
        ));
    }
    let socket_owner = socket.uid();
    let socket_gid = socket.gid();
    let root_managed_group_socket =
        socket_owner == 0 && socket_gid == expected_gid && socket_mode == 0o660;
    if !owner_allowed(socket_owner, allowed_socket_owner_uids) && !root_managed_group_socket {
        return Err(format!(
            "{label} owner uid mismatch: allowed {:?}, found {} ({})",
            allowed_socket_owner_uids,
            socket_owner,
            path.display()
        ));
    }
    if socket_mode & 0o070 != 0 && !root_managed_group_socket && socket_gid != expected_gid {
        return Err(format!(
            "{label} group mismatch: expected gid {expected_gid}, found {} ({})",
            socket_gid,
            path.display()
        ));
    }

    let parent = validate_parent_basics(path, label)?;
    let parent_mode = parent.permissions().mode() & 0o777;
    if parent_mode & 0o002 != 0 {
        return Err(format!(
            "{label} parent directory has insecure permissions: mode {parent_mode:o}"
        ));
    }
    let parent_owner = parent.uid();
    let parent_gid = parent.gid();
    let root_managed_shared_runtime =
        parent_owner == 0 && parent_gid == expected_gid && parent_mode == 0o770;
    if !owner_allowed(parent_owner, allowed_parent_owner_uids) && !root_managed_shared_runtime {
        return Err(format!(
            "{label} parent directory owner uid mismatch: allowed {:?}, found {}",
            allowed_parent_owner_uids, parent_owner
        ));
    }
    if parent_mode & 0o020 != 0 && !root_managed_shared_runtime && parent_gid != expected_gid {
        return Err(format!(
            "{label} parent directory group mismatch: expected gid {expected_gid}, found {parent_gid}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_owner_only_socket, validate_root_managed_shared_runtime_socket};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(prefix: &str) -> PathBuf {
        let unique = format!(
            "{prefix}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        PathBuf::from("/tmp").join(unique)
    }

    #[test]
    fn owner_only_socket_validator_accepts_owner_only_socket() {
        let dir = unique_dir("rn-local-sec-ok");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let dir_metadata = std::fs::symlink_metadata(&dir).expect("dir metadata should exist");
        let socket = dir.join("rustynetd.sock");
        let listener = UnixListener::bind(&socket).expect("socket should bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode should be owner-only");
        let uid = dir_metadata.uid();

        let result = validate_owner_only_socket(&socket, "daemon socket", &[uid], &[uid]);
        assert!(result.is_ok(), "owner-only socket should validate");

        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn owner_only_socket_validator_rejects_group_writable_parent_directory() {
        let dir = unique_dir("rn-local-sec-parent");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770))
            .expect("test dir permissions should be set");
        let dir_metadata = std::fs::symlink_metadata(&dir).expect("dir metadata should exist");
        let socket = dir.join("rustynetd.sock");
        let listener = UnixListener::bind(&socket).expect("socket should bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode should be owner-only");
        let uid = dir_metadata.uid();

        let err = validate_owner_only_socket(&socket, "daemon socket", &[uid], &[uid])
            .expect_err("group-writable parent must fail");
        assert!(err.contains("parent directory has insecure permissions"));

        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn owner_only_socket_validator_rejects_symlink_socket_path() {
        let dir = unique_dir("rn-local-sec-link");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let dir_metadata = std::fs::symlink_metadata(&dir).expect("dir metadata should exist");
        let socket = dir.join("rustynetd.sock");
        let symlink_path = dir.join("rustynetd.sock.link");
        let listener = UnixListener::bind(&socket).expect("socket should bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode should be owner-only");
        symlink(&socket, &symlink_path).expect("symlink should be created");
        let uid = dir_metadata.uid();

        let err = validate_owner_only_socket(&symlink_path, "daemon socket", &[uid], &[uid])
            .expect_err("symlink socket path must fail");
        assert!(err.contains("must not be a symlink"));

        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn shared_runtime_socket_validator_accepts_owner_only_socket() {
        let dir = unique_dir("rn-local-sec-shared-ok");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let dir_metadata = std::fs::symlink_metadata(&dir).expect("dir metadata should exist");
        let socket = dir.join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("socket should bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode should be owner-only");
        let uid = dir_metadata.uid();
        let gid = dir_metadata.gid();

        let result = validate_root_managed_shared_runtime_socket(
            &socket,
            "privileged helper socket",
            &[uid],
            &[uid],
            gid,
        );
        assert!(
            result.is_ok(),
            "owner-only helper socket should validate under shared-runtime policy"
        );

        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }
}
