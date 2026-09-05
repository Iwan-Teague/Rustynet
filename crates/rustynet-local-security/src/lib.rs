#![forbid(unsafe_code)]

use std::path::Path;

#[cfg(unix)]
use std::fs;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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
        Err(
            "owner-only socket validation is available only on Unix sockets; Windows must use named-pipe IPC validation"
                .to_string(),
        )
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

#[cfg(unix)]
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
        Err(
            "root-managed shared runtime socket validation is available only on Unix sockets; Windows must use named-pipe IPC validation"
                .to_string(),
        )
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
        validate_root_managed_shared_runtime_socket,
        validate_root_managed_shared_runtime_socket_facts,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
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

    // ---- owner-only validator: reject-branch coverage (pure, no IO) ----
    //
    // A valid owner-only fact set against allowed uid 501; each test below
    // flips exactly one field so the asserted rejection is unambiguous.
    fn owner_only_valid_facts() -> SocketSecurityFacts {
        SocketSecurityFacts {
            socket_mode: 0o600,
            socket_uid: 501,
            socket_gid: 20,
            parent_mode: 0o700,
            parent_uid: 501,
            parent_gid: 20,
        }
    }

    #[test]
    fn owner_only_socket_facts_reject_group_or_world_accessible_socket() {
        let path = Path::new("/tmp/rustynetd.sock");
        for broad_mode in [0o660, 0o604, 0o660 | 0o006] {
            let mut facts = owner_only_valid_facts();
            facts.socket_mode = broad_mode;
            let err =
                validate_owner_only_socket_facts(path, "daemon socket", facts, &[501], &[501])
                    .expect_err("non-owner-only socket mode must fail");
            assert!(
                err.contains("permissions too broad"),
                "mode {broad_mode:03o} expected too-broad rejection, got: {err}"
            );
        }
    }

    #[test]
    fn owner_only_socket_facts_reject_socket_owner_uid_mismatch() {
        let path = Path::new("/tmp/rustynetd.sock");
        let mut facts = owner_only_valid_facts();
        facts.socket_uid = 1000;
        let err = validate_owner_only_socket_facts(path, "daemon socket", facts, &[501], &[501])
            .expect_err("foreign socket owner must fail");
        assert!(err.contains("owner uid mismatch"), "got: {err}");
    }

    #[test]
    fn owner_only_socket_facts_reject_parent_owner_uid_mismatch() {
        let path = Path::new("/tmp/rustynetd.sock");
        let mut facts = owner_only_valid_facts();
        facts.parent_uid = 1000;
        let err = validate_owner_only_socket_facts(path, "daemon socket", facts, &[501], &[501])
            .expect_err("foreign parent owner must fail");
        assert!(
            err.contains("parent directory owner uid mismatch"),
            "got: {err}"
        );
    }

    // ---- root-managed shared-runtime validator: reject-branch coverage ----
    //
    // Validated against allowed socket/parent uid 501 and expected gid 20,
    // starting from the owner-only-valid accept case.
    fn shared_runtime_valid_facts() -> SocketSecurityFacts {
        SocketSecurityFacts {
            socket_mode: 0o600,
            socket_uid: 501,
            socket_gid: 20,
            parent_mode: 0o700,
            parent_uid: 501,
            parent_gid: 20,
        }
    }

    fn assert_shared_runtime_rejects(facts: SocketSecurityFacts, needle: &str) {
        let path = Path::new("/run/rustynet/helper.sock");
        let err = validate_root_managed_shared_runtime_socket_facts(
            path,
            "privileged helper socket",
            facts,
            &[501],
            &[501],
            20,
        )
        .expect_err("insecure facts must be rejected");
        assert!(
            err.contains(needle),
            "expected rejection containing {needle:?}, got: {err}"
        );
    }

    #[test]
    fn shared_runtime_socket_facts_reject_world_accessible_socket() {
        let mut facts = shared_runtime_valid_facts();
        facts.socket_mode = 0o604; // world-readable
        assert_shared_runtime_rejects(facts, "world access is forbidden");
    }

    #[test]
    fn shared_runtime_world_access_check_precedes_root_managed_allowance() {
        // A root-owned, correctly-grouped socket must STILL be rejected if it
        // grants any world access — the root-managed allowance never bypasses
        // the world-access ban (defense-in-depth, fail-closed).
        let facts = SocketSecurityFacts {
            socket_mode: 0o666,
            socket_uid: 0,
            socket_gid: 20,
            parent_mode: 0o770,
            parent_uid: 0,
            parent_gid: 20,
        };
        assert_shared_runtime_rejects(facts, "world access is forbidden");
    }

    #[test]
    fn shared_runtime_socket_facts_reject_foreign_socket_owner() {
        let mut facts = shared_runtime_valid_facts();
        facts.socket_uid = 1000; // not allowed and not root-managed
        assert_shared_runtime_rejects(facts, "owner uid mismatch");
    }

    #[test]
    fn shared_runtime_socket_facts_reject_group_gid_mismatch() {
        let mut facts = shared_runtime_valid_facts();
        facts.socket_mode = 0o640; // group-readable
        facts.socket_gid = 99; // not the expected gid
        assert_shared_runtime_rejects(facts, "group mismatch");
    }

    #[test]
    fn shared_runtime_socket_facts_reject_world_writable_parent() {
        let mut facts = shared_runtime_valid_facts();
        facts.parent_mode = 0o702; // world-writable parent
        assert_shared_runtime_rejects(facts, "parent directory has insecure permissions");
    }

    #[test]
    fn shared_runtime_socket_facts_reject_foreign_parent_owner() {
        let mut facts = shared_runtime_valid_facts();
        facts.parent_uid = 1000; // not allowed and not root-managed
        assert_shared_runtime_rejects(facts, "parent directory owner uid mismatch");
    }

    #[test]
    fn shared_runtime_socket_facts_reject_parent_group_gid_mismatch() {
        let mut facts = shared_runtime_valid_facts();
        facts.parent_mode = 0o770; // group-writable parent
        facts.parent_gid = 99; // not the expected gid
        assert_shared_runtime_rejects(facts, "parent directory group mismatch");
    }

    // ---- owner-only validator: path-level fail-closed coverage ----

    #[test]
    fn socket_validator_rejects_relative_path() {
        let err =
            validate_owner_only_socket(Path::new("relative.sock"), "daemon socket", &[501], &[501])
                .expect_err("relative path must fail closed");
        assert!(err.contains("must be absolute"), "got: {err}");
    }

    #[test]
    fn owner_only_socket_validator_rejects_missing_socket_path() {
        let err = validate_owner_only_socket(
            Path::new("/tmp/rn-local-sec-does-not-exist.sock"),
            "daemon socket",
            &[501],
            &[501],
        )
        .expect_err("missing socket path must fail closed");
        assert!(err.contains("inspect daemon socket failed"), "got: {err}");
    }

    #[test]
    fn owner_only_socket_validator_rejects_symlinked_parent_directory() {
        let dir = unique_dir("rn-local-sec-link-parent");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let socket = dir.join("rustynetd.sock");
        let _listener = UnixListener::bind(&socket).expect("socket should bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket permissions should be owner-only");
        let link = dir.join("parent-link");
        symlink(&dir, &link).expect("symlink should be created");

        let err = validate_owner_only_socket(
            &link.join("rustynetd.sock"),
            "daemon socket",
            &[501],
            &[501],
        )
        .expect_err("symlinked parent directory must fail closed");
        assert!(
            err.contains("parent directory must be a non-symlink directory"),
            "got: {err}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    // ---- owner-only validator: allowlist + precedence (pure, no IO) ----

    #[test]
    fn owner_only_socket_facts_deny_empty_allowed_owner_lists() {
        let path = Path::new("/tmp/rustynetd.sock");
        let err = validate_owner_only_socket_facts(
            path,
            "daemon socket",
            owner_only_valid_facts(),
            &[],
            &[],
        )
        .expect_err("empty allowlist must deny");
        assert!(err.contains("owner uid mismatch"), "got: {err}");
    }

    #[test]
    fn owner_only_socket_facts_reject_broad_mode_before_owner_mismatch() {
        let path = Path::new("/tmp/rustynetd.sock");
        let mut facts = owner_only_valid_facts();
        facts.socket_mode = 0o666;
        facts.socket_uid = 1000;
        let err = validate_owner_only_socket_facts(path, "daemon socket", facts, &[501], &[501])
            .expect_err("broad mode with foreign owner must fail");
        assert!(
            err.contains("permissions too broad") && !err.contains("owner uid mismatch"),
            "mode check must precede owner check, got: {err}"
        );
    }

    #[test]
    fn owner_only_socket_facts_reject_socket_owner_before_parent_owner() {
        let path = Path::new("/tmp/rustynetd.sock");
        let mut facts = owner_only_valid_facts();
        facts.socket_uid = 1000;
        facts.parent_uid = 1000;
        let err = validate_owner_only_socket_facts(path, "daemon socket", facts, &[501], &[501])
            .expect_err("foreign socket and parent owner must fail");
        assert!(
            err.contains("owner uid mismatch")
                && !err.contains("parent directory owner uid mismatch"),
            "socket owner check must precede parent owner check, got: {err}"
        );
    }

    #[test]
    fn owner_only_socket_facts_reject_world_writable_parent() {
        let path = Path::new("/tmp/rustynetd.sock");
        let mut facts = owner_only_valid_facts();
        facts.parent_mode = 0o702; // world-writable parent
        let err = validate_owner_only_socket_facts(path, "daemon socket", facts, &[501], &[501])
            .expect_err("world-writable parent must fail");
        assert!(
            err.contains("parent directory has insecure permissions"),
            "got: {err}"
        );
    }

    // ---- shared-runtime validator: allowlist + bypass strictness ----

    #[test]
    fn shared_runtime_socket_facts_deny_empty_allowed_owner_lists_for_non_root_socket() {
        let path = Path::new("/run/rustynet/helper.sock");
        let err = validate_root_managed_shared_runtime_socket_facts(
            path,
            "privileged helper socket",
            shared_runtime_valid_facts(),
            &[],
            &[],
            20,
        )
        .expect_err("empty allowlist must deny a non-root socket");
        assert!(err.contains("owner uid mismatch"), "got: {err}");
    }

    // NOTE: the root-managed bypass ignores the allowed-owner lists entirely —
    // an exact uid=0/gid/mode match is the gate. This pins the current design.
    #[test]
    fn shared_runtime_root_managed_bypass_accepts_with_empty_allowed_lists() {
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
            &[],
            &[],
            998,
        );
        assert!(
            result.is_ok(),
            "root-managed facts should bypass allowlists, got: {result:?}"
        );
    }

    // NOTE: a root-owned socket with the correct group but mode 0o600 is
    // REJECTED — the bypass requires exactly 0o660 and uid 0 is outside the
    // allowlist. This is stricter than strictly necessary (fail-closed), so the
    // current behavior is pinned rather than treated as a defect.
    #[test]
    fn shared_runtime_root_managed_bypass_requires_exact_socket_mode() {
        let facts = SocketSecurityFacts {
            socket_mode: 0o600,
            socket_uid: 0,
            socket_gid: 20,
            parent_mode: 0o700,
            parent_uid: 501,
            parent_gid: 20,
        };
        assert_shared_runtime_rejects(facts, "owner uid mismatch");
    }

    #[test]
    fn shared_runtime_root_managed_bypass_requires_exact_parent_mode() {
        let facts = SocketSecurityFacts {
            socket_mode: 0o600,
            socket_uid: 501,
            socket_gid: 20,
            parent_mode: 0o775, // root-owned, grouped, but not exactly 0o770
            parent_uid: 0,
            parent_gid: 20,
        };
        assert_shared_runtime_rejects(facts, "parent directory owner uid mismatch");
    }

    #[test]
    fn shared_runtime_insecure_parent_check_precedes_root_managed_allowance() {
        // A root-owned, correctly-grouped parent must STILL be rejected if it
        // is world-writable — the insecure-permission check runs before the
        // root-managed bypass (defense-in-depth, fail-closed).
        let facts = SocketSecurityFacts {
            socket_mode: 0o600,
            socket_uid: 501,
            socket_gid: 20,
            parent_mode: 0o777,
            parent_uid: 0,
            parent_gid: 20,
        };
        assert_shared_runtime_rejects(facts, "parent directory has insecure permissions");
    }

    #[test]
    fn shared_runtime_socket_facts_reject_owner_mismatch_before_group_mismatch() {
        let mut facts = shared_runtime_valid_facts();
        facts.socket_uid = 1000; // foreign owner
        facts.socket_mode = 0o640; // group bits set...
        facts.socket_gid = 99; // ...with the wrong gid
        assert_shared_runtime_rejects(facts, "owner uid mismatch");
    }

    #[test]
    fn shared_runtime_socket_facts_accept_group_readable_socket_with_expected_gid() {
        let mut facts = shared_runtime_valid_facts();
        facts.socket_mode = 0o640; // group-readable, gid matches expected
        let path = Path::new("/run/rustynet/helper.sock");
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
            "group-readable socket with expected gid should validate, got: {result:?}"
        );
    }

    #[test]
    fn shared_runtime_parent_facts_accept_group_writable_parent_with_expected_gid() {
        let mut facts = shared_runtime_valid_facts();
        facts.parent_mode = 0o750; // group-writable parent, gid matches expected
        let path = Path::new("/run/rustynet/helper.sock");
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
            "group-writable parent with expected gid should validate, got: {result:?}"
        );
    }

    #[test]
    fn shared_runtime_socket_facts_accept_multi_uid_allowlists() {
        let path = Path::new("/run/rustynet/helper.sock");
        let mut facts = shared_runtime_valid_facts();
        facts.socket_uid = 1002; // second member of the socket allowlist
        facts.parent_uid = 1000; // first member of the parent allowlist
        let result = validate_root_managed_shared_runtime_socket_facts(
            path,
            "privileged helper socket",
            facts,
            &[1000, 1002],
            &[1000, 1002],
            20,
        );
        assert!(
            result.is_ok(),
            "any allowlisted uid should validate, got: {result:?}"
        );
    }

    // ---- full public validators against a REAL Unix socket (end-to-end) ----

    #[test]
    fn owner_only_socket_validator_accepts_real_owner_only_socket() {
        let dir = unique_dir("rn-local-sec-e2e-ok");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let path = dir.join("rustynetd.sock");
        let _listener = UnixListener::bind(&path).expect("socket should bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("socket permissions should be owner-only");
        let uid = std::fs::metadata(&path).expect("socket should stat").uid();

        validate_owner_only_socket(&path, "daemon socket", &[uid], &[uid])
            .expect("real owner-only socket should validate");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn owner_only_socket_validator_rejects_group_accessible_real_socket() {
        let dir = unique_dir("rn-local-sec-e2e-broad");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let path = dir.join("rustynetd.sock");
        let _listener = UnixListener::bind(&path).expect("socket should bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .expect("socket permissions should be group-accessible");
        let uid = std::fs::metadata(&path).expect("socket should stat").uid();

        let err = validate_owner_only_socket(&path, "daemon socket", &[uid], &[uid])
            .expect_err("group-accessible socket must fail closed");
        assert!(err.contains("permissions too broad"), "got: {err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn shared_runtime_socket_validator_accepts_real_socket_with_matching_gid() {
        let dir = unique_dir("rn-local-sec-e2e-shared");
        std::fs::create_dir_all(&dir).expect("test dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("test dir permissions should be strict");
        let path = dir.join("helper.sock");
        let _listener = UnixListener::bind(&path).expect("socket should bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("socket permissions should be owner-only");
        let metadata = std::fs::metadata(&path).expect("socket should stat");

        validate_root_managed_shared_runtime_socket(
            &path,
            "privileged helper socket",
            &[metadata.uid()],
            &[metadata.uid()],
            metadata.gid(),
        )
        .expect("real socket with matching gid should validate under shared-runtime policy");
        let _ = std::fs::remove_dir_all(dir);
    }
}
