#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketSecurityFacts {
    socket_mode: u32,
    socket_uid: u32,
    socket_gid: u32,
    parent_mode: u32,
    parent_uid: u32,
    parent_gid: u32,
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn inspect_socket_security_facts(path: &Path, label: &str) -> Result<SocketSecurityFacts, String> {
    let socket = validate_socket_basics(path, label)?;
    let parent = validate_parent_basics(path, label)?;
    Ok(SocketSecurityFacts {
        socket_mode: socket.permissions().mode() & 0o777,
        socket_uid: socket.uid(),
        socket_gid: socket.gid(),
        parent_mode: parent.permissions().mode() & 0o777,
        parent_uid: parent.uid(),
        parent_gid: parent.gid(),
    })
}

fn validate_owner_only_socket_facts(
    path: &Path,
    label: &str,
    facts: SocketSecurityFacts,
    allowed_socket_owner_uids: &[u32],
    allowed_parent_owner_uids: &[u32],
) -> Result<(), String> {
    if facts.socket_mode & 0o077 != 0 {
        return Err(format!(
            "{label} permissions too broad ({:03o}); expected owner-only socket permissions: {}",
            facts.socket_mode,
            path.display()
        ));
    }
    if !owner_allowed(facts.socket_uid, allowed_socket_owner_uids) {
        return Err(format!(
            "{label} owner uid mismatch: allowed {:?}, found {} ({})",
            allowed_socket_owner_uids,
            facts.socket_uid,
            path.display()
        ));
    }
    if facts.parent_mode & 0o022 != 0 {
        return Err(format!(
            "{label} parent directory has insecure permissions: mode {:o}",
            facts.parent_mode
        ));
    }
    if !owner_allowed(facts.parent_uid, allowed_parent_owner_uids) {
        return Err(format!(
            "{label} parent directory owner uid mismatch: allowed {allowed_parent_owner_uids:?}, found {}",
            facts.parent_uid,
        ));
    }
    Ok(())
}

pub fn validate_owner_only_socket(
    path: &Path,
    label: &str,
    allowed_socket_owner_uids: &[u32],
    allowed_parent_owner_uids: &[u32],
) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (
            path,
            label,
            allowed_socket_owner_uids,
            allowed_parent_owner_uids,
        );
        return Err(
            "owner-only socket validation is available only on Unix sockets; Windows must use named-pipe IPC validation"
                .to_string(),
        );
    }

    #[cfg(unix)]
    {
        let facts = inspect_socket_security_facts(path, label)?;
        validate_owner_only_socket_facts(
            path,
            label,
            facts,
            allowed_socket_owner_uids,
            allowed_parent_owner_uids,
        )
    }
}

fn validate_root_managed_shared_runtime_socket_facts(
    path: &Path,
    label: &str,
    facts: SocketSecurityFacts,
    allowed_socket_owner_uids: &[u32],
    allowed_parent_owner_uids: &[u32],
    expected_gid: u32,
) -> Result<(), String> {
    if facts.socket_mode & 0o007 != 0 {
        return Err(format!(
            "{label} permissions too broad ({:03o}); world access is forbidden: {}",
            facts.socket_mode,
            path.display()
        ));
    }
    let root_managed_group_socket =
        facts.socket_uid == 0 && facts.socket_gid == expected_gid && facts.socket_mode == 0o660;
    if !owner_allowed(facts.socket_uid, allowed_socket_owner_uids) && !root_managed_group_socket {
        return Err(format!(
            "{label} owner uid mismatch: allowed {:?}, found {} ({})",
            allowed_socket_owner_uids,
            facts.socket_uid,
            path.display()
        ));
    }
    if facts.socket_mode & 0o070 != 0
        && !root_managed_group_socket
        && facts.socket_gid != expected_gid
    {
        return Err(format!(
            "{label} group mismatch: expected gid {expected_gid}, found {} ({})",
            facts.socket_gid,
            path.display()
        ));
    }

    if facts.parent_mode & 0o002 != 0 {
        return Err(format!(
            "{label} parent directory has insecure permissions: mode {:o}",
            facts.parent_mode
        ));
    }
    let root_managed_shared_runtime =
        facts.parent_uid == 0 && facts.parent_gid == expected_gid && facts.parent_mode == 0o770;
    if !owner_allowed(facts.parent_uid, allowed_parent_owner_uids) && !root_managed_shared_runtime {
        return Err(format!(
            "{label} parent directory owner uid mismatch: allowed {allowed_parent_owner_uids:?}, found {}",
            facts.parent_uid,
        ));
    }
    if facts.parent_mode & 0o020 != 0
        && !root_managed_shared_runtime
        && facts.parent_gid != expected_gid
    {
        return Err(format!(
            "{label} parent directory group mismatch: expected gid {expected_gid}, found {}",
            facts.parent_gid
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
    #[cfg(not(unix))]
    {
        let _ = (
            path,
            label,
            allowed_socket_owner_uids,
            allowed_parent_owner_uids,
            expected_gid,
        );
        return Err(
            "root-managed shared runtime socket validation is available only on Unix sockets; Windows must use named-pipe IPC validation"
                .to_string(),
        );
    }

    #[cfg(unix)]
    {
        let facts = inspect_socket_security_facts(path, label)?;
        validate_root_managed_shared_runtime_socket_facts(
            path,
            label,
            facts,
            allowed_socket_owner_uids,
            allowed_parent_owner_uids,
            expected_gid,
        )
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        SocketSecurityFacts, validate_owner_only_socket, validate_owner_only_socket_facts,
        validate_root_managed_shared_runtime_socket_facts,
    };
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
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
    fn owner_only_socket_facts_accept_owner_only_socket() {
        let path = Path::new("/tmp/rustynetd.sock");
        let facts = SocketSecurityFacts {
            socket_mode: 0o600,
            socket_uid: 501,
            socket_gid: 20,
            parent_mode: 0o700,
            parent_uid: 501,
            parent_gid: 20,
        };

        let result = validate_owner_only_socket_facts(path, "daemon socket", facts, &[501], &[501]);
        assert!(result.is_ok(), "owner-only socket should validate");
    }

    #[test]
    fn owner_only_socket_facts_reject_group_writable_parent_directory() {
        let path = Path::new("/tmp/rustynetd.sock");
        let facts = SocketSecurityFacts {
            socket_mode: 0o600,
            socket_uid: 501,
            socket_gid: 20,
            parent_mode: 0o770,
            parent_uid: 501,
            parent_gid: 20,
        };

        let err = validate_owner_only_socket_facts(path, "daemon socket", facts, &[501], &[501])
            .expect_err("group-writable parent must fail");
        assert!(err.contains("parent directory has insecure permissions"));
    }

    #[test]
    fn owner_only_socket_validator_rejects_symlink_socket_path() {
        let dir = unique_dir("rn-local-sec-link");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let socket = dir.join("rustynetd.sock.target");
        let symlink_path = dir.join("rustynetd.sock.link");
        std::fs::write(&socket, b"not-a-socket").expect("target file should exist");
        symlink(&socket, &symlink_path).expect("symlink should be created");

        let err = validate_owner_only_socket(&symlink_path, "daemon socket", &[501], &[501])
            .expect_err("symlink socket path must fail");
        assert!(err.contains("must not be a symlink"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn shared_runtime_socket_facts_accept_owner_only_socket() {
        let path = Path::new("/run/rustynet/helper.sock");
        let facts = SocketSecurityFacts {
            socket_mode: 0o600,
            socket_uid: 501,
            socket_gid: 20,
            parent_mode: 0o700,
            parent_uid: 501,
            parent_gid: 20,
        };

        let result = validate_root_managed_shared_runtime_socket_facts(
            path,
            "privileged helper socket",
            facts,
            &[501],
            &[501],
            20,
        );
        assert!(
            result.is_ok(),
            "owner-only helper socket should validate under shared-runtime policy"
        );
    }

    #[test]
    fn shared_runtime_socket_validator_accepts_root_managed_group_socket_facts() {
        let path = Path::new("/run/rustynet/helper.sock");
        let facts = SocketSecurityFacts {
            socket_mode: 0o660,
            socket_uid: 0,
            socket_gid: 998,
            parent_mode: 0o770,
            parent_uid: 0,
            parent_gid: 998,
        };

        let result = validate_root_managed_shared_runtime_socket_facts(
            path,
            "privileged helper socket",
            facts,
            &[501],
            &[501],
            998,
        );
        assert!(
            result.is_ok(),
            "root-managed shared-runtime socket should validate"
        );
    }

    #[test]
    fn owner_only_socket_validator_rejects_regular_file_path() {
        let dir = unique_dir("rn-local-sec-regular");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let path = dir.join("rustynetd.sock");
        std::fs::write(&path, b"not-a-socket").expect("regular file should exist");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("regular file permissions should be owner-only");

        let err = validate_owner_only_socket(&path, "daemon socket", &[501], &[501])
            .expect_err("regular file path must fail");
        assert!(err.contains("must be a Unix socket"));

        let _ = std::fs::remove_dir_all(dir);
    }
}
